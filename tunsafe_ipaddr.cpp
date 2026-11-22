#include "stdafx.h"
#include <string.h>
#include "tunsafe_ipaddr.h"
#include "tunsafe_dnsresolve.h"

#if defined(OS_WIN)
#include "network_win32_dnsblock.h"
#include <malloc.h>
// MSVC 没有 POSIX 的 popen/pclose/WEXITSTATUS，这里做兼容。
// https 目前仍用 curl -k 回退，保证和旧版本行为一致。
#ifndef popen
#define popen _popen
#endif
#ifndef pclose
#define pclose _pclose
#endif
#ifndef WEXITSTATUS
#define WEXITSTATUS(status) (status)
#endif
#else
#include <sys/wait.h>
#endif

#if defined(OS_POSIX)
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netdb.h>
#include <fcntl.h>
#include <errno.h>
#endif  // defined(OS_POSIX)
#ifdef _WIN32
#include <windows.h>
#define sleep(x) Sleep((x) * 1000)  // 将秒转换为毫秒
#else
#include <unistd.h>
#endif
#include <stdlib.h>
#include "util.h"

const char *print_ip_prefix(char buf[kSizeOfAddress], int family, const void *ip, int prefixlen) {
  // cast to void* to work on VS2015
  if (!inet_ntop(family, (void*)ip, buf, kSizeOfAddress - 8)) {
    memcpy(buf, "unknown", 8);
  }
  if (prefixlen >= 0)
    snprintf(buf + strlen(buf), 8, "/%d", prefixlen);
  return buf;
}

char *PrintIpAddr(const IpAddr &addr, char buf[kSizeOfAddress]) {
  if (addr.sin.sin_family == AF_INET) {
    print_ip_prefix(buf, addr.sin.sin_family, &addr.sin.sin_addr, -1);
  } else if (addr.sin.sin_family == AF_INET6) {
    print_ip_prefix(buf, addr.sin.sin_family, &addr.sin6.sin6_addr, -1);
  } else {
    buf[0] = 0;
  }
  return buf;
}


char *PrintWgCidrAddr(const WgCidrAddr &addr, char buf[kSizeOfAddress]) {
  if (addr.size == 32) {
    print_ip_prefix(buf, AF_INET, addr.addr, addr.cidr);
  } else if (addr.size == 128) {
    print_ip_prefix(buf, AF_INET6, addr.addr, addr.cidr);
  } else {
    buf[0] = 0;
  }
  return buf;
}

struct Addr {
  byte addr[4];
  uint8 cidr;
};

bool ParseCidrAddr(const char *s, WgCidrAddr *out) {
  const char *slash = strchr(s, '/');
  if (!slash)
    return false;

  size_t len = slash - s;
  char *tmp = (char*)alloca(len + 1);
  tmp[len] = 0;
  memcpy(tmp, s, len);

  int e = atoi(slash + 1);
  if (e < 0) return false;

  if (inet_pton(AF_INET, tmp, out->addr) == 1) {
    if (e > 32) return false;
    out->cidr = e;
    out->size = 32;
    return true;
  }
  if (inet_pton(AF_INET6, tmp, out->addr) == 1) {
    if (e > 128) return false;
    out->cidr = e;
    out->size = 128;
    return true;
  }
  return false;
}

static inline bool CheckFirstNbitsEquals(const byte *a, const byte *b, size_t n) {
  return memcmp(a, b, n >> 3) == 0 && ((n & 7) == 0 || !((a[n >> 3] ^ b[n >> 3]) & (0xff << (8 - (n & 7)))));
}

static bool IsWgCidrAddrSubsetOf(const WgCidrAddr &inner, const WgCidrAddr &outer) {
  return inner.size == outer.size && inner.cidr >= outer.cidr &&
    CheckFirstNbitsEquals(inner.addr, outer.addr, outer.cidr);
}

bool IsWgCidrAddrSubsetOfAny(const WgCidrAddr &inner, const std::vector<WgCidrAddr> &addr) {
  for (auto &a : addr)
    if (IsWgCidrAddrSubsetOf(inner, a))
      return true;
  return false;
}

// Returns nonzero if two endpoints are different.
uint32 CompareIpAddr(const IpAddr *a, const IpAddr *b) {
  uint32 rv = b->sin.sin_family ^ a->sin.sin_family;
  if (b->sin.sin_family != AF_INET6) {
    rv |= b->sin.sin_addr.s_addr ^ a->sin.sin_addr.s_addr;
    rv |= b->sin.sin_port ^ a->sin.sin_port;
  } else {
    uint64 rx = ((uint64*)&b->sin6.sin6_addr)[0] ^ ((uint64*)&a->sin6.sin6_addr)[0];
    rx |= ((uint64*)&b->sin6.sin6_addr)[1] ^ ((uint64*)&a->sin6.sin6_addr)[1];
    rv |= rx | (rx >> 32);
    rv |= b->sin6.sin6_port ^ a->sin6.sin6_port;
  }
  return rv;
}


static Mutex g_dns_mutex;

// This starts a background thread for running DNS resolving.
class DnsResolverThread : private Thread::Runner {
public:
  DnsResolverThread();
  ~DnsResolverThread();

  // Resolve the hostname and store the result in |result|.
  // The function will block until it's resolved. If the cancellation
  // token or becomes signalled, the call will fail.
  bool Resolve(const char *hostname, IpAddr *result, DnsResolverCanceller *token);

private:
  virtual void ThreadMain();
  void StartThread();

  struct Entry {
    enum {
      // Set when it's been posted to the job queue
      POSTED = 0,
      // Set when the thread has finished and original thread should delete
      COMPLETE = 1,
      // Set when the original thread has cancelled and worker thread should delete
      CANCELLED = 2,
    };

    Entry() : hostname(NULL) {}
    ~Entry() { free(hostname); }

    char *hostname;
    IpAddr *result;
    Entry *next;
    uint32 state;
    ConditionVariable *condvar;
  };
  Entry *entry_;
  Thread thread_;
  bool thread_active_;
};

DnsResolverThread::DnsResolverThread() {
  thread_active_ = false;
  entry_ = NULL;
}

DnsResolverThread::~DnsResolverThread() {
  assert(entry_ == NULL);
  thread_.StopThread();
}

void DnsResolverCanceller::Cancel() {
  g_dns_mutex.Acquire();
  cancel_ = true;
  condvar_.Wake();
  g_dns_mutex.Release();
}

void DnsResolverCanceller::CancelSleepOnce() {
  g_dns_mutex.Acquire();
  cancel_sleep_once_ = true;
  condvar_.Wake();
  g_dns_mutex.Release();
}



bool DnsResolverThread::Resolve(const char *hostname, IpAddr *result, DnsResolverCanceller *token) {
  if (token->cancel_)
    return false;

  Entry *e = new Entry;
  e->hostname = _strdup(hostname);
  e->result = result;
  e->next = NULL;
  e->state = Entry::POSTED;
  e->condvar = &token->condvar_;
  result->sin.sin_family = 0;

  // Push it to the queue and start thread
  g_dns_mutex.Acquire();
  Entry **p = &entry_;
  while (*p) p = &(*p)->next;
  *p = e;
  if (!thread_active_)
    StartThread();
  // Wait for something to happen with it.
  while (!token->cancel_ && e->state == Entry::POSTED)
    token->condvar_.Wait(&g_dns_mutex);
  if (e->state == Entry::COMPLETE) {
    delete e;
  } else {
    e->state = Entry::CANCELLED;
  }
  g_dns_mutex.Release();
  return result->sin.sin_family != 0;
}

void DnsResolverThread::StartThread() {
  thread_.StopThread();
  thread_active_ = true;
  thread_.StartThread(this);
}

void DnsResolverThread::ThreadMain() {
  Entry *e;
  struct addrinfo *ai;
  g_dns_mutex.Acquire();
  while ((e = entry_) != NULL) {
    entry_ = e->next;
    g_dns_mutex.Release();

    struct addrinfo hints = {0};
    hints.ai_family = PF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    // AI_V4MAPPED doesn't work on Android?!
#if defined(OS_IOS)
    hints.ai_flags = AI_DEFAULT;
#else
    hints.ai_flags = AI_ADDRCONFIG ;
#endif
    ai = NULL;
    int r =  getaddrinfo(e->hostname, NULL, &hints, &ai);
    if (r != 0)
      ai = NULL;
//    RINFO("r=%d errno=%d, %s", r, errno, gai_strerror(r));
    //    he = gethostbyname(e->hostname);
    g_dns_mutex.Acquire();
    if (e->state == Entry::CANCELLED) {
      delete e;
    } else {
//      RINFO("ai=%p, family=%d", ai, ai ? ai->ai_family : -1);
      if (ai) {
        e->result->sin.sin_family = ai->ai_family;
        e->result->sin.sin_port = 0;
        if (ai->ai_family == AF_INET)
          memcpy(&e->result->sin.sin_addr, &((sockaddr_in*)ai->ai_addr)->sin_addr, 4);
        else
          memcpy(&e->result->sin6.sin6_addr, &((sockaddr_in6*)ai->ai_addr)->sin6_addr, 16);
      }
/*      if (he) {
        e->result->sin.sin_family = AF_INET;
        e->result->sin.sin_port = 0;
        memcpy(&e->result->sin.sin_addr, he->h_addr_list[0], 4);
      }*/
      
      e->state = Entry::COMPLETE;
      e->condvar->Wake();
    }
    
    if (ai)
      freeaddrinfo(ai);
  }
  thread_active_ = false;
  g_dns_mutex.Release();
}

static DnsResolverThread g_dnsresolver_thread;

static bool InterruptibleSleep(int delay, DnsResolverCanceller *token) {
  g_dns_mutex.Acquire();
  uint32 time_at_start = (uint32)OsGetMilliseconds();
  while (delay > 0 && !token->cancel_) {
    if (token->cancel_sleep_once_) {
      token->cancel_sleep_once_ = false;
      delay = 0;
      break;
    }
    token->condvar_.WaitTimed(&g_dns_mutex, delay);
    uint32 now = (uint32)OsGetMilliseconds();
    delay -= (now - time_at_start);
    time_at_start = now;
  }
  g_dns_mutex.Release();
  return (delay <= 0);
}

DnsResolver::DnsResolver(DnsBlocker *dns_blocker) {
  dns_blocker_ = dns_blocker;
}

DnsResolver::~DnsResolver() {
}

void DnsResolver::ClearCache() {
  cache_.clear();
}

void DnsResolver::ClearCacheEntry(const char *hostname) {
  // 只删除当前域名的缓存，避免断线重连时把其他 peer 的解析结果一并清空，造成不必要的重复 DNS 查询。
  for (auto it = cache_.begin(); it != cache_.end(); ) {
    if (it->name == hostname)
      it = cache_.erase(it);
    else
      ++it;
  }
}

bool DnsResolver::Resolve(const char *hostname, IpAddr *result, int max_retries) {
  static const uint8 retry_delays[] = {1, 2, 3, 5, 10, 20, 40, 60, 120, 180, 255};
  char buf[kSizeOfAddress];

  retry_attempt_ = 0;

  memset(result, 0, sizeof(IpAddr));

  // First check cache
  for (auto it = cache_.begin(); it != cache_.end(); ++it) {
    if (it->name == hostname) {

      *result = it->ip;
      RINFO("已将 %s 解析为 %s:%s", hostname, PrintIpAddr(*result, buf), " (来自缓存)");
      return true;
    }
  }

#if defined(OS_WIN)
  // Then disable dns blocker (otherwise the windows dns client service can't resolve)
  if (dns_blocker_ && dns_blocker_->IsActive()) {
    RINFO("禁用 DNS 拦截器即可解决 %s", hostname);
    dns_blocker_->RestoreDns();
  }
#endif  // defined(OS_WIN)

  for (int attempt = 0; ; attempt++) {
    if (g_dnsresolver_thread.Resolve(hostname, result, &token_)) {
      // add to cache
      cache_.emplace_back(hostname, *result);
      RINFO("已将 %s 解析为 %s%s", hostname, PrintIpAddr(*result, buf), "");
      return true;
    }
    if (token_.is_cancelled())
      return false;
    // 断线重连时 DNS 可能已经被默认路由带进未建立的隧道，
    // 这里允许调用方限制重试次数，避免主线程卡在 255 秒的退避循环里。
    if (max_retries >= 0 && attempt >= max_retries)
      return false;

    RINFO("无法解析 %s 等待 %d 秒后重试", hostname, retry_delays[retry_attempt_]);
    if (!InterruptibleSleep(retry_delays[retry_attempt_] * 1000, &token_))
      return false;

    if (retry_attempt_ != ARRAY_SIZE(retry_delays) - 1)
      retry_attempt_++;
  }
}

void DnsResolver::RetryNow() {
  retry_attempt_ = 0;
  token_.CancelSleepOnce();
}

// Parse an IPV4 address into sin, doing NAT64 translation if applicable (on IOS)
static bool ParseIpv4WithNAT64Translation(const char *s, IpAddr *sin, int flags) {
  // First verify it's actually a valid ipv4 address to prevent getaddrinfo from doing a slow resolve
  if (inet_pton(AF_INET, s, &sin->sin.sin_addr) != 1)
    return false;
  sin->sin.sin_family = AF_INET;

#if defined(OS_IOS)
  if (!(flags & kParseSockaddrDontDoNAT64)) {
    struct addrinfo hints = {0};
    hints.ai_family = PF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_DEFAULT;
    struct addrinfo* ai = NULL;
    // When NAT64 is enabled, I don't get an IPv4 address back.
    if (getaddrinfo(s, NULL, &hints, &ai) == 0) {
      // check so we have an AF_INET6 and no AF_INET
      struct sockaddr_in6 *found = NULL;
      for(struct addrinfo *t = ai; t; t = t->ai_next) {
        if (t->ai_family == AF_INET) { found = NULL; break; }
        if (t->ai_family == AF_INET6) found = (sockaddr_in6*)t->ai_addr;
      }
      if (found) {
        memset(&sin->sin.sin_addr, 0, 4); // clear out ipv4 address already written
        memcpy(&sin->sin6.sin6_addr, &found->sin6_addr, 16);
        sin->sin.sin_family = AF_INET6;
      }
      freeaddrinfo(ai);
    }
  }
#endif  // defined(OS_IOS)
  return true;
}

// 执行 curl 命令并获取输出。仅在未启用 WITH_MBEDTLS 时作为 https 回退；
// 正常构建使用 mbedTLS，http 使用下面的内置轻量客户端。
std::string executeCurlCommand(const std::string &url, int timeout, int max_retries) {
    std::string command = "curl -iks --max-time " + std::to_string(timeout) + " \"" + url + "\" 2>&1";
    char buffer[1280];
    std::string result = "";
    FILE *fp = nullptr;
    // 重试逻辑
    int retries = 0;
    while (retries < max_retries) {
        fp = popen(command.c_str(), "r");
        if (fp != nullptr) {
            while (fgets(buffer, sizeof(buffer), fp) != nullptr) {
                result += buffer;
            }
           int status = pclose(fp);
	   int exit_code = WEXITSTATUS(status); 
	   if (exit_code != 0) {                             
    		RINFO("错误：curl 退出码【%d】，可能 AllowedIPs 被设置了 0.0.0.0/0 导致的无网。 ", exit_code);         
	   }
            // 检查输出中的Location字段
            if (result.find("Location:") != std::string::npos || result.find("location:") != std::string::npos) {
                break;  // 如果获取到重定向地址，退出重试循环
            }
        }
        retries++;
        if (retries < max_retries) {
            sleep(1);  // 如果失败，等待1秒后重试
        }
    }

    return result;
}

// 内置轻量 HTTP 客户端，替代 curl 外部进程处理 http://。
// 目的：不依赖 popen/system，Windows 可编译，嵌入式设备体积更小。
// 只实现明文 http://；https 需要真正的 TLS，会显著增加体积，暂不支持。
#if defined(OS_WIN)
typedef SOCKET HttpSocket;
#define kInvalidHttpSocket INVALID_SOCKET
static void CloseHttpSocket(HttpSocket s) { closesocket(s); }
#else
typedef int HttpSocket;
#define kInvalidHttpSocket (-1)
static void CloseHttpSocket(HttpSocket s) { close(s); }
#endif

static bool HttpSetNonBlocking(HttpSocket s, bool enable) {
#if defined(OS_WIN)
  u_long mode = enable ? 1 : 0;
  return ioctlsocket(s, FIONBIO, &mode) == 0;
#else
  int flags = fcntl(s, F_GETFL, 0);
  if (flags < 0) return false;
  if (enable) flags |= O_NONBLOCK; else flags &= ~O_NONBLOCK;
  return fcntl(s, F_SETFL, flags) == 0;
#endif
}

static bool HttpWaitSocket(HttpSocket s, bool for_write, int timeout_ms) {
  fd_set set;
  FD_ZERO(&set);
  FD_SET(s, &set);
  struct timeval tv;
  tv.tv_sec = timeout_ms / 1000;
  tv.tv_usec = (timeout_ms % 1000) * 1000;
#if defined(OS_WIN)
  int r = select(0, for_write ? NULL : &set, for_write ? &set : NULL, NULL, &tv);
#else
  int r = select(s + 1, for_write ? NULL : &set, for_write ? &set : NULL, NULL, &tv);
#endif
  return r > 0;
}

static HttpSocket HttpConnect(const std::string &host, const std::string &port, int timeout_ms) {
#if defined(OS_WIN)
  // 内置 HTTP 客户端也依赖 Winsock；主程序未显式初始化时这里兜底。
  static bool winsock_ready = false;
  if (!winsock_ready) {
    WSADATA wsa_data;
    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0)
      return kInvalidHttpSocket;
    winsock_ready = true;
  }
#endif
  struct addrinfo hints;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  struct addrinfo *res = NULL;
  if (getaddrinfo(host.c_str(), port.c_str(), &hints, &res) != 0)
    return kInvalidHttpSocket;

  HttpSocket fd = kInvalidHttpSocket;
  for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
    HttpSocket s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (s == kInvalidHttpSocket)
      continue;
    if (!HttpSetNonBlocking(s, true)) {
      CloseHttpSocket(s);
      continue;
    }
    bool connected = false;
    if (connect(s, ai->ai_addr, (int)ai->ai_addrlen) == 0) {
      connected = true;
    } else {
#if defined(OS_WIN)
      int err = WSAGetLastError();
      bool in_progress = (err == WSAEWOULDBLOCK || err == WSAEINPROGRESS);
#else
      int err = errno;
      bool in_progress = (err == EINPROGRESS);
#endif
      if (in_progress && HttpWaitSocket(s, true, timeout_ms)) {
        int so_error = 0;
#if defined(OS_WIN)
        int len = sizeof(so_error);
        getsockopt(s, SOL_SOCKET, SO_ERROR, (char*)&so_error, &len);
#else
        socklen_t len = sizeof(so_error);
        getsockopt(s, SOL_SOCKET, SO_ERROR, (char*)&so_error, &len);
#endif
        connected = (so_error == 0);
      }
    }
    if (connected) {
      HttpSetNonBlocking(s, false);
      fd = s;
      break;
    }
    CloseHttpSocket(s);
  }
  freeaddrinfo(res);
  return fd;
}

static bool HttpSendAll(HttpSocket s, const std::string &data, int timeout_ms) {
  size_t off = 0;
  while (off < data.size()) {
    if (!HttpWaitSocket(s, true, timeout_ms)) return false;
    int n = send(s, data.c_str() + off, (int)(data.size() - off), 0);
    if (n <= 0) {
#if defined(OS_WIN)
      if (n < 0 && WSAGetLastError() == WSAEWOULDBLOCK) continue;
#else
      if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) continue;
#endif
      return false;
    }
    off += n;
  }
  return true;
}

static bool HttpRecvHeaders(HttpSocket s, std::string *headers, int timeout_ms) {
  char buf[1024];
  // 只读取响应头，限制 16KB，避免恶意服务器无限发送。
  while (headers->size() < 16 * 1024) {
    if (!HttpWaitSocket(s, false, timeout_ms)) return false;
    int n = recv(s, buf, sizeof(buf), 0);
    if (n <= 0) {
#if defined(OS_WIN)
      if (n < 0 && WSAGetLastError() == WSAEWOULDBLOCK) continue;
#else
      if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) continue;
#endif
      break;  // 连接关闭，已收到的头仍然可以解析
    }
    headers->append(buf, n);
    if (headers->find("\r\n\r\n") != std::string::npos)
      return true;
  }
  return !headers->empty();
}

static bool HttpHeaderEquals(const char *a, const char *b, size_t n) {
  for (size_t i = 0; i < n; i++) {
    char ca = a[i], cb = b[i];
    if (ca >= 'A' && ca <= 'Z') ca = (char)(ca + ('a' - 'A'));
    if (cb >= 'A' && cb <= 'Z') cb = (char)(cb + ('a' - 'A'));
    if (ca != cb) return false;
  }
  return true;
}

// 从响应头取出 Location。没有 Location 时返回原 host:port，
// 这样调用方可以直接把结果当成最终端点使用。
std::string ParseHttpRedirectHostPort(const std::string &url, const std::string &headers,
                                     const std::string &host, const std::string &port) {
  std::string location;
  size_t pos = 0;
  while (pos < headers.size()) {
    size_t end = headers.find("\r\n", pos);
    if (end == std::string::npos) break;
    const char *line = headers.c_str() + pos;
    size_t line_len = end - pos;
    const char kLocation[] = "location";
    if (line_len > sizeof(kLocation) - 1 &&
        HttpHeaderEquals(line, kLocation, sizeof(kLocation) - 1) &&
        line[sizeof(kLocation) - 1] == ':') {
      size_t value_start = sizeof(kLocation);
      while (value_start < line_len && (line[value_start] == ' ' || line[value_start] == '\t'))
        value_start++;
      location.assign(line + value_start, line_len - value_start);
      // HTTP 头允许尾部空格，去掉后再解析 host:port。
      size_t loc_end = location.find_last_not_of(" \t");
      if (loc_end == std::string::npos)
        location.clear();
      else
        location.erase(loc_end + 1);
      break;
    }
    pos = end + 2;
  }

  if (location.empty())
    return host + ":" + port;

  // 协议相对地址 //host/path：沿用原 URL 的 scheme，端口缺省时补该 scheme 默认端口。
  if (location.rfind("//", 0) == 0) {
    location = location.substr(2);
    size_t slash = location.find('/');
    if (slash != std::string::npos)
      location = location.substr(0, slash);
    size_t q = location.find('?');
    if (q != std::string::npos)
      location = location.substr(0, q);
    if (location.empty())
      return "";
    bool has_port;
    if (location[0] == '[') {
      size_t end = location.find(']');
      has_port = end != std::string::npos && end + 1 < location.size() &&
                 location[end + 1] == ':';
    } else {
      has_port = location.find(':') != std::string::npos;
    }
    if (!has_port)
      location += (url.rfind("https://", 0) == 0) ? ":443" : ":80";
    return location;
  }

  // 查询或片段引用：沿用原 host:port。
  if (location[0] == '?' || location[0] == '#')
    return host + ":" + port;

  // 绝对路径：沿用原 host:port。
  if (location[0] == '/')
    return host + ":" + port;

  std::string default_port;
  if (location.rfind("http://", 0) == 0) {
    location = location.substr(7);
    default_port = "80";
  } else if (location.rfind("https://", 0) == 0) {
    location = location.substr(8);
    default_port = "443";
  } else {
    // 没有 scheme 的绝对地址，端口缺省时沿用原端口。
    default_port = port;
  }

  size_t slash = location.find('/');
  if (slash != std::string::npos)
    location = location.substr(0, slash);
  size_t q = location.find('?');
  if (q != std::string::npos)
    location = location.substr(0, q);
  size_t frag = location.find('#');
  if (frag != std::string::npos)
    location = location.substr(0, frag);
  if (location.empty())
    return "";

  bool has_port;
  if (location[0] == '[') {
    size_t end = location.find(']');
    has_port = end != std::string::npos && end + 1 < location.size() &&
               location[end + 1] == ':';
  } else {
    has_port = location.find(':') != std::string::npos;
  }
  if (!has_port) {
    if (default_port.empty())
      default_port = (url.rfind("https://", 0) == 0) ? "443" : "80";
    location += ":";
    location += default_port;
  }
  return location;
}

std::string FetchHttpRedirectHostPort(const std::string &url, int timeout_sec) {
  if (url.rfind("https://", 0) == 0) {
#if defined(WITH_MBEDTLS)
    // 使用 mbedTLS 完成 TLS 握手，不再依赖 curl。
    return FetchHttpsRedirectHostPortMbedTls(url, timeout_sec);
#else
    // 未启用 mbedTLS 时保留 curl -k 回退。
    std::string output = executeCurlCommand(url, timeout_sec, 3);
    size_t loc_pos = output.find("Location:");
    if (loc_pos == std::string::npos)
      loc_pos = output.find("location:");
    if (loc_pos == std::string::npos) {
      RERROR("无法从 https 响应中获取重定向地址: %s", url.c_str());
      return "";
    }
    std::string location = output.substr(loc_pos + 9);
    location.erase(0, location.find_first_not_of(" \t\r\n"));
    size_t endline = location.find('\n');
    if (endline != std::string::npos)
      location = location.substr(0, endline);
    location.erase(location.find_last_not_of(" \t\r\n") + 1);
    if (location.rfind("http://", 0) == 0)
      location = location.substr(7);
    else if (location.rfind("https://", 0) == 0)
      location = location.substr(8);
    else {
      RERROR("重定向地址格式不正确: %s", location.c_str());
      return "";
    }
    size_t slash = location.find('/');
    if (slash != std::string::npos)
      location = location.substr(0, slash);
    return location;
#endif
  }
  if (url.rfind("http://", 0) != 0) {
    RERROR("不支持的 URL: %s", url.c_str());
    return "";
  }

  const char *p = url.c_str() + 7;
  const char *slash = strchr(p, '/');
  const char *query = strchr(p, '?');
  const char *frag = strchr(p, '#');
  const char *hostport_end = slash;
  if (!hostport_end || (query && query < hostport_end)) hostport_end = query;
  if (!hostport_end || (frag && frag < hostport_end)) hostport_end = frag;
  std::string hostport = hostport_end ? std::string(p, hostport_end - p) : std::string(p);
  std::string path = slash ? std::string(slash) : std::string("/");
  // fragment 不应发送给服务器。
  size_t frag_pos = path.find('#');
  if (frag_pos != std::string::npos)
    path = path.substr(0, frag_pos);
  if (hostport.empty()) return "";

  std::string host, port;
  if (hostport[0] == '[') {
    size_t end = hostport.find(']');
    if (end == std::string::npos) return "";
    host = hostport.substr(1, end - 1);
    if (end + 1 < hostport.size() && hostport[end + 1] == ':')
      port = hostport.substr(end + 2);
    else
      port = "80";
  } else {
    size_t colon = hostport.rfind(':');
    if (colon != std::string::npos) {
      host = hostport.substr(0, colon);
      port = hostport.substr(colon + 1);
    } else {
      host = hostport;
      port = "80";
    }
  }
  if (host.empty() || port.empty()) return "";

  int timeout_ms = (timeout_sec > 0 ? timeout_sec : 10) * 1000;
  HttpSocket s = HttpConnect(host, port, timeout_ms);
  if (s == kInvalidHttpSocket) {
    RERROR("无法连接 %s:%s", host.c_str(), port.c_str());
    return "";
  }

  std::string request;
  request.reserve(256);
  request += "GET ";
  request += path;
  request += " HTTP/1.0\r\nHost: ";
  // IPv6 的 Host 头必须加方括号。
  if (host.find(':') != std::string::npos) {
    request += "[";
    request += host;
    request += "]";
  } else {
    request += host;
  }
  if (port != "80") {
    request += ":";
    request += port;
  }
  request += "\r\nUser-Agent: TunSafe\r\nConnection: close\r\n\r\n";

  std::string headers;
  bool ok = HttpSendAll(s, request, timeout_ms) && HttpRecvHeaders(s, &headers, timeout_ms);
  CloseHttpSocket(s);
  if (!ok) {
    RERROR("读取 %s 的 HTTP 响应失败", url.c_str());
    return "";
  }
  return ParseHttpRedirectHostPort(url, headers, host, port);
}

bool ParsePortNumber(const char *s, uint16 *port) {
  if (!s || !*s)
    return false;
  char *end = NULL;
  long v = strtol(s, &end, 10);
  if (end == s || *end != '\0' || v < 1 || v > 65535)
    return false;
  *port = (uint16)v;
  return true;
}

bool ParseSockaddrInWithPort(const char *si, IpAddr *sin, DnsResolver *resolver, int flags) {
  std::string hostport = si;
  // 检查是否为 http 或 https 开头
  if (hostport.rfind("http:", 0) == 0 || hostport.rfind("https:", 0) == 0) {
    if (hostport.rfind("http:", 0) == 0 && hostport.substr(5, 2) != "//") {
      hostport.insert(5, "//");
    } else if (hostport.rfind("https:", 0) == 0 && hostport.substr(6, 2) != "//") {
      hostport.insert(6, "//");
    }

    // 调用 curl 获取 HTTP 响应头
#if 0  // 旧的 curl 解析逻辑，已由内置 HTTP 客户端替代。
    std::string output = executeCurlCommand(hostport);
    size_t loc_pos = output.find("Location:");
    if (loc_pos == std::string::npos)
      loc_pos = output.find("location:");

    if (loc_pos != std::string::npos) {
      std::string location = output.substr(loc_pos + 9);
      // 去除前导空格和换行
      location.erase(0, location.find_first_not_of(" \t\r\n"));
  
      // 截取到行尾
      size_t endline = location.find('\n');
      if (endline != std::string::npos) location = location.substr(0, endline);

      // 去除尾部空白
     location.erase(location.find_last_not_of(" \t\r\n") + 1);

     //RINFO("获取到重定向地址(原始): %s", location.c_str());

     // 验证是 http 或 https 开头
     if (location.rfind("http://", 0) == 0) 
     	location = location.substr(7);
     else if (location.rfind("https://", 0) == 0) 
     	location = location.substr(8);
     else {
       RERROR("重定向地址格式不正确: %s", location.c_str());
       return false;
     }

     // 去除路径（只保留 host:port）
     size_t slash = location.find('/');
     if (slash != std::string::npos) 
     	location = location.substr(0, slash);

     // 更新最终 hostport
     hostport = location;

#endif
    // 用内置 HTTP 客户端获取最终端点；https 由 mbedTLS 处理。
    std::string location = FetchHttpRedirectHostPort(hostport, 10);
    if (location.empty()) {
      RERROR("无法获取重定向地址: %s", hostport.c_str());
      return false;
    }
    hostport = location;
    RINFO("获取到重定向地址: %s", hostport.c_str());
  }
  
  // 用 vector 代替 alloca，避免超长配置（最大 1MB）撑爆线程栈。
  std::vector<char> hostport_buf(hostport.begin(), hostport.end());
  hostport_buf.push_back('\0');
  char *s = &hostport_buf[0];
  
  memset(sin, 0, sizeof(IpAddr));
  if (*s == '[') {
    char *end = strchr(s, ']');
    if (end == NULL)
      return false;
    *end = 0;
    if (inet_pton(AF_INET6, s + 1, &sin->sin6.sin6_addr) != 1)
      return false;
    char *x = strchr(end + 1, ':');
    if (!x)
      return false;
    uint16 port;
    if (!ParsePortNumber(x + 1, &port))
      return false;
    sin->sin6.sin6_family = AF_INET6;
    sin->sin6.sin6_port = htons(port);
    return true;
  }
  char *x = strchr(s, ':');
  if (!x) return false;
  *x = 0;
  uint16 port;
  if (!ParsePortNumber(x + 1, &port)) {
    RERROR("端口无效: %s", x + 1);
    return false;
  }
  if (!ParseIpv4WithNAT64Translation(s, sin, flags)) {
    if (!resolver) {
      return false;
    } else if (!resolver->Resolve(s, sin)) {
      RERROR("无法解析 %s", s);
      return false;
    }
  }
  sin->sin.sin_port = htons(port);
  return true;
}

bool ParseSockaddrInWithoutPort(char *s, IpAddr *sin, DnsResolver *resolver, int flags) {
  memset(sin, 0, sizeof(IpAddr));

  if (inet_pton(AF_INET6, s, &sin->sin6.sin6_addr) == 1) {
    sin->sin.sin_family = AF_INET6;
    return true;
  } else if (ParseIpv4WithNAT64Translation(s, sin, flags)) {
    return true;
  } else if (!resolver) {
    return false;
  } else if (!resolver->Resolve(s, sin)) {
    RERROR("无法解析 %s", s);
    return false;
  }
  return true;
}

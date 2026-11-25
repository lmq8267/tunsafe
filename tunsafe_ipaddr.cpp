#include "stdafx.h"
#include <string.h>
#include "tunsafe_ipaddr.h"
#include "tunsafe_dnsresolve.h"
#include "util.h"

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
    bool used_configured_dns = false;
    bool resolved = false;
    // 配置了 DNS = 时优先使用它解析 Endpoint 域名；失败后仍回退系统 DNS，
    // 保证配置 DNS 未覆盖的公网域名（如 HTTP 跳转服务）也能解析。
    if (HasConfiguredDnsServers()) {
      std::vector<IpAddr> addresses;
      if (ResolveHostWithConfiguredDns(hostname, &addresses, 2000) && !addresses.empty()) {
        *result = addresses[0];
        used_configured_dns = true;
        resolved = true;
      }
    }
    if (!resolved)
      resolved = g_dnsresolver_thread.Resolve(hostname, result, &token_);
    if (resolved) {
      // add to cache
      cache_.emplace_back(hostname, *result);
      RINFO("已将 %s 解析为 %s%s", hostname, PrintIpAddr(*result, buf),
            used_configured_dns ? " (配置 DNS)" : "");
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
  std::vector<std::string> hosts;
  GetHostAddressStrings(host, timeout_ms, &hosts);
  bool numeric_hosts = !hosts.empty();
  if (!numeric_hosts)
    hosts.push_back(host);

  HttpSocket fd = kInvalidHttpSocket;
  uint64 start_ms = OsGetMilliseconds();
  for (size_t hi = 0; hi < hosts.size(); hi++) {
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (numeric_hosts)
      hints.ai_flags = AI_NUMERICHOST;
    struct addrinfo *res = NULL;
    if (getaddrinfo(hosts[hi].c_str(), port.c_str(), &hints, &res) != 0)
      continue;

    for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
    int remaining_ms = timeout_ms - (int)(OsGetMilliseconds() - start_ms);
    if (remaining_ms <= 0)
      break;
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
      if (in_progress && HttpWaitSocket(s, true, remaining_ms)) {
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
    if (fd != kInvalidHttpSocket)
      break;
  }
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

static bool HttpHeaderEquals(const char *a, const char *b, size_t n) {
  for (size_t i = 0; i < n; i++) {
    char ca = a[i], cb = b[i];
    if (ca >= 'A' && ca <= 'Z') ca = (char)(ca + ('a' - 'A'));
    if (cb >= 'A' && cb <= 'Z') cb = (char)(cb + ('a' - 'A'));
    if (ca != cb) return false;
  }
  return true;
}

int ParseHttpStatusCode(const std::string &headers) {
  size_t line_end = headers.find("\r\n");
  std::string line = line_end == std::string::npos ? headers : headers.substr(0, line_end);
  if (line.size() < 10 || line.compare(0, 5, "HTTP/") != 0)
    return 0;
  size_t space = line.find(' ');
  if (space == std::string::npos || space + 3 >= line.size())
    return 0;
  int code = 0;
  for (size_t i = space + 1; i <= space + 3; i++) {
    if (line[i] < '0' || line[i] > '9')
      return 0;
    code = code * 10 + (line[i] - '0');
  }
  return code;
}

bool HttpGetHeaderValue(const std::string &headers, const char *name, std::string *value) {
  size_t name_len = strlen(name);
  // 第一行是状态行，从它后面的 \r\n 开始找字段。
  size_t pos = headers.find("\r\n");
  if (pos == std::string::npos)
    return false;
  pos += 2;
  while (pos < headers.size()) {
    size_t end = headers.find("\r\n", pos);
    if (end == std::string::npos)
      break;
    const char *line = headers.c_str() + pos;
    size_t line_len = end - pos;
    if (line_len > name_len && HttpHeaderEquals(line, name, name_len) &&
        line[name_len] == ':') {
      size_t value_start = name_len + 1;
      while (value_start < line_len && (line[value_start] == ' ' || line[value_start] == '\t'))
        value_start++;
      *value = headers.substr(pos + value_start, line_len - value_start);
      size_t value_end = value->find_last_not_of(" \t");
      if (value_end == std::string::npos)
        value->clear();
      else
        value->erase(value_end + 1);
      return true;
    }
    pos = end + 2;
  }
  return false;
}

std::string HttpDecodeChunkedBody(const std::string &body) {
  std::string out;
  size_t pos = 0;
  while (pos < body.size()) {
    size_t line_end = body.find("\r\n", pos);
    if (line_end == std::string::npos)
      break;
    const char *size_start = body.c_str() + pos;
    char *endptr = NULL;
    long len = strtol(size_start, &endptr, 16);
    if (endptr == size_start || len <= 0)
      break;
    size_t data_start = line_end + 2;
    size_t available = body.size() - data_start;
    size_t take = (size_t)len < available ? (size_t)len : available;
    out.append(body, data_start, take);
    if ((size_t)len > available)
      break;
    pos = data_start + (size_t)len;
    if (body.compare(pos, 2, "\r\n") == 0)
      pos += 2;
  }
  return out;
}

// 判断 chunked 响应体是否已经读到结束块。这里按块长度逐个跳过，
// 避免把块数据里的 "0\r\n" 误当成结束标记；允许 0 块后面带 trailer。
bool HttpChunkedBodyComplete(const std::string &body) {
  size_t pos = 0;
  while (pos < body.size()) {
    size_t line_end = body.find("\r\n", pos);
    if (line_end == std::string::npos)
      return false;
    const char *size_start = body.c_str() + pos;
    char *endptr = NULL;
    long len = strtol(size_start, &endptr, 16);
    if (endptr == size_start || len < 0)
      return false;
    if (len == 0) {
      size_t rest = line_end + 2;
      if (rest >= body.size())
        return false;
      if (body.compare(rest, 2, "\r\n") == 0)
        return true;
      // 0 块后可以有 trailer，直到空行结束。
      return body.find("\r\n\r\n", rest) != std::string::npos;
    }
    size_t data_start = line_end + 2;
    if ((size_t)len > body.size() - data_start)
      return false;
    pos = data_start + (size_t)len;
    if (body.compare(pos, 2, "\r\n") != 0)
      return false;
    pos += 2;
  }
  return false;
}

bool StringStartsWithNoCase(const std::string &s, const char *prefix) {
  size_t n = strlen(prefix);
  if (s.size() < n)
    return false;
  for (size_t i = 0; i < n; i++) {
    char c = s[i];
    if (c >= 'A' && c <= 'Z') c = (char)(c + ('a' - 'A'));
    if (c != prefix[i]) return false;
  }
  return true;
}

bool HttpTextContainsNoCase(const std::string &s, const char *needle) {
  size_t n = strlen(needle);
  if (n == 0 || s.size() < n)
    return false;
  for (size_t i = 0; i + n <= s.size(); i++) {
    bool match = true;
    for (size_t j = 0; j < n; j++) {
      char c = s[i + j];
      if (c >= 'A' && c <= 'Z') c = (char)(c + ('a' - 'A'));
      if (c != needle[j]) { match = false; break; }
    }
    if (match) return true;
  }
  return false;
}

// 200 响应文本或 scheme-less Location 里只取主机和端口。
// 只接受 IPv4 或带方括号的 IPv6，避免把普通网页内容误当成 Endpoint。
std::string ExtractEndpointHostPort(const std::string &text, bool allow_hostname) {
  size_t start = text.find_first_not_of(" \t\r\n");
  if (start == std::string::npos)
    return "";
  size_t text_end = text.find_last_not_of(" \t\r\n");
  std::string value = text.substr(start, text_end - start + 1);
  // 只看第一个空白分隔的片段，防止多行文本干扰。
  size_t whitespace = value.find_first_of(" \t\r\n");
  if (whitespace != std::string::npos)
    value.resize(whitespace);
  if (StringStartsWithNoCase(value, "http://"))
    value = value.substr(7);
  else if (StringStartsWithNoCase(value, "https://"))
    value = value.substr(8);
  // 去掉路径、查询和片段，只保留主机和端口。
  size_t cut = value.find_first_of("/?#");
  if (cut != std::string::npos)
    value.resize(cut);
  if (value.empty())
    return "";

  std::string host, port_text;
  if (value[0] == '[') {
    size_t close = value.find(']');
    if (close == std::string::npos || close + 1 >= value.size() || value[close + 1] != ':')
      return "";
    host = value.substr(1, close - 1);
    port_text = value.substr(close + 2);
    struct in6_addr addr6;
    if (inet_pton(AF_INET6, host.c_str(), &addr6) != 1)
      return "";
    uint16 port;
    if (!ParsePortNumber(port_text.c_str(), &port))
      return "";
    return "[" + host + "]:" + port_text;
  }

  size_t colon = value.rfind(':');
  if (colon == std::string::npos)
    return "";
  host = value.substr(0, colon);
  port_text = value.substr(colon + 1);
  struct in_addr addr4;
  if (inet_pton(AF_INET, host.c_str(), &addr4) != 1) {
    // 域名只在 scheme-less Location 场景允许；未加方括号的 IPv6 仍然拒绝。
    if (!allow_hostname || host.empty() || host.find(':') != std::string::npos)
      return "";
  }
  uint16 port;
  if (!ParsePortNumber(port_text.c_str(), &port))
    return "";
  return host + ":" + port_text;
}

// 配置里允许 http:host/path 这种省略 // 的写法，统一补成完整 URL；
// 同时把大写 scheme 规范成小写，后续解析只认小写。
static std::string NormalizeHttpUrl(const std::string &url) {
  bool is_https = StringStartsWithNoCase(url, "https:");
  bool is_http = !is_https && StringStartsWithNoCase(url, "http:");
  if (!is_http && !is_https)
    return "";
  std::string rest = url.substr(is_https ? 6 : 5);
  if (rest.rfind("//", 0) != 0)
    rest = "//" + rest;
  return std::string(is_https ? "https" : "http") + ":" + rest;
}

static bool HttpLocationIsUrl(const std::string &location) {
  if (!NormalizeHttpUrl(location).empty())
    return true;
  if (location.empty())
    return false;
  return location[0] == '/' || location[0] == '?' || location[0] == '#';
}

// 归一化路径中的 . 和 .. 段（RFC 3986 的 remove_dot_segments），
// 避免相对 Location（如 ../endpoint）拼出服务端不认的路径。
static std::string NormalizeUrlPath(const std::string &path) {
  size_t suffix_pos = path.find_first_of("?#");
  std::string suffix = suffix_pos == std::string::npos ? "" : path.substr(suffix_pos);
  std::string body = suffix_pos == std::string::npos ? path : path.substr(0, suffix_pos);
  bool trailing_slash = !body.empty() && body[body.size() - 1] == '/';
  // 以 . 或 .. 结尾时，归一化后按 RFC 3986 保留尾斜杠。
  if (body == ".." || body == "." ||
      (body.size() >= 3 && body.compare(body.size() - 3, 3, "/..") == 0) ||
      (body.size() >= 2 && body.compare(body.size() - 2, 2, "/.") == 0))
    trailing_slash = true;
  std::vector<std::string> segments;
  size_t pos = 0;
  while (pos < body.size()) {
    while (pos < body.size() && body[pos] == '/')
      pos++;
    size_t next = body.find('/', pos);
    if (next == std::string::npos)
      next = body.size();
    std::string segment = body.substr(pos, next - pos);
    if (segment == "..") {
      if (!segments.empty())
        segments.pop_back();
    } else if (!segment.empty() && segment != ".") {
      segments.push_back(segment);
    }
    pos = next;
  }
  std::string out;
  for (size_t i = 0; i < segments.size(); i++) {
    out += "/";
    out += segments[i];
  }
  if (out.empty())
    out = "/";
  else if (trailing_slash)
    out += "/";
  return out + suffix;
}

// 把 Location 相对地址补成完整 URL，支持 //host、/path、?query 和相对路径。
static std::string HttpResolveRedirectUrl(const std::string &base, const std::string &location) {
  std::string absolute = NormalizeHttpUrl(location);
  if (!absolute.empty())
    return absolute;
  size_t scheme_end = base.find("://");
  if (scheme_end == std::string::npos || location.empty())
    return "";
  std::string scheme = base.substr(0, scheme_end);
  std::string rest = base.substr(scheme_end + 3);
  size_t authority_end = rest.find_first_of("/?#");
  std::string authority = authority_end == std::string::npos ? rest : rest.substr(0, authority_end);
  std::string path = authority_end == std::string::npos ? std::string("/") : rest.substr(authority_end);
  size_t clean_end = path.find_first_of("?#");
  if (clean_end != std::string::npos)
    path.resize(clean_end);
  if (authority.empty())
    return "";
  if (location.rfind("//", 0) == 0)
    return scheme + ":" + location;
  if (location[0] == '/')
    return scheme + "://" + authority + NormalizeUrlPath(location);
  if (location[0] == '?' || location[0] == '#')
    return scheme + "://" + authority + path + location;
  size_t slash = path.rfind('/');
  std::string dir = slash == std::string::npos ? std::string("/") : path.substr(0, slash + 1);
  return scheme + "://" + authority + NormalizeUrlPath(dir + location);
}

// 从完整 URL 里取出 host:port，作为“跟随 Location 失败时的最终端点”。
// 只接受地址字面量：域名 URL 更可能是另一个 HTTP(S) 重定向服务，
// 失败时不能把它的 443/80 端口当成 WireGuard 端点。
static std::string ExtractUrlHostPort(const std::string &url) {
  std::string normalized = NormalizeHttpUrl(url);
  size_t scheme_end = normalized.find("://");
  if (scheme_end == std::string::npos)
    return "";
  std::string default_port = normalized.rfind("https://", 0) == 0 ? "443" : "80";
  std::string rest = normalized.substr(scheme_end + 3);
  size_t authority_end = rest.find_first_of("/?#");
  std::string authority = authority_end == std::string::npos ? rest : rest.substr(0, authority_end);
  if (authority.empty())
    return "";

  std::string host, port_text;
  if (authority[0] == '[') {
    size_t close = authority.find(']');
    if (close == std::string::npos)
      return "";
    host = authority.substr(1, close - 1);
    if (close + 1 < authority.size()) {
      if (authority[close + 1] != ':')
        return "";
      port_text = authority.substr(close + 2);
    }
    struct in6_addr addr6;
    if (inet_pton(AF_INET6, host.c_str(), &addr6) != 1)
      return "";
    if (port_text.empty())
      port_text = default_port;
    uint16 port;
    if (!ParsePortNumber(port_text.c_str(), &port))
      return "";
    return "[" + host + "]:" + port_text;
  }

  size_t colon = authority.rfind(':');
  if (colon != std::string::npos) {
    host = authority.substr(0, colon);
    port_text = authority.substr(colon + 1);
  } else {
    host = authority;
    port_text = default_port;
  }
  struct in_addr addr4;
  if (inet_pton(AF_INET, host.c_str(), &addr4) != 1)
    return "";
  uint16 port;
  if (!ParsePortNumber(port_text.c_str(), &port))
    return "";
  return host + ":" + port_text;
}

static bool HttpRecvResponse(HttpSocket s, int timeout_ms, HttpResponseData *resp) {
  const size_t kMaxHeaderBytes = 16 * 1024;
  const size_t kMaxBodyBytes = 8 * 1024;
  std::string raw;
  size_t header_end = std::string::npos;
  char buf[1024];
  // 先读到响应头结束；限制 16KB，避免恶意服务器无限发送。
  while (raw.size() < kMaxHeaderBytes) {
    if (!HttpWaitSocket(s, false, timeout_ms))
      break;
    int n = recv(s, buf, sizeof(buf), 0);
    if (n <= 0) {
#if defined(OS_WIN)
      if (n < 0 && WSAGetLastError() == WSAEWOULDBLOCK) continue;
#else
      if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) continue;
#endif
      break;
    }
    raw.append(buf, n);
    header_end = raw.find("\r\n\r\n");
    if (header_end != std::string::npos) {
      header_end += 4;
      break;
    }
  }
  if (header_end == std::string::npos)
    return false;

  resp->headers = raw.substr(0, header_end);
  resp->status_code = ParseHttpStatusCode(resp->headers);
  resp->body = raw.substr(header_end);
  if (resp->status_code != 200)
    return true;

  std::string value;
  long long content_length = -1;
  if (HttpGetHeaderValue(resp->headers, "content-length", &value)) {
    bool valid = !value.empty();
    long long parsed = 0;
    for (size_t i = 0; valid && i < value.size(); i++) {
      if (value[i] < '0' || value[i] > '9') {
        valid = false;
        break;
      }
      parsed = parsed * 10 + (value[i] - '0');
      if (parsed > (long long)kMaxBodyBytes)
        parsed = kMaxBodyBytes;
    }
    if (valid)
      content_length = parsed;
  }
  bool chunked = false;
  if (HttpGetHeaderValue(resp->headers, "transfer-encoding", &value))
    chunked = HttpTextContainsNoCase(value, "chunked");

  while (resp->body.size() < kMaxBodyBytes) {
    if (!chunked && content_length >= 0 && resp->body.size() >= (size_t)content_length)
      break;
    if (chunked && HttpChunkedBodyComplete(resp->body))
      break;
    // 长度未知且非 chunked 时只等 1 秒，避免服务器保持连接导致卡满超时。
    int wait_ms = (!chunked && content_length < 0) ? 1000 : timeout_ms;
    if (!HttpWaitSocket(s, false, wait_ms))
      break;
    int n = recv(s, buf, sizeof(buf), 0);
    if (n <= 0) {
#if defined(OS_WIN)
      if (n < 0 && WSAGetLastError() == WSAEWOULDBLOCK) continue;
#else
      if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) continue;
#endif
      break;
    }
    resp->body.append(buf, n);
  }
  if (resp->body.size() > kMaxBodyBytes)
    resp->body.resize(kMaxBodyBytes);
  if (chunked) {
    // 分块没收完不能拿半截数据去解析，否则可能把 1.2.3.4:518 当成 518 端口。
    if (!HttpChunkedBodyComplete(resp->body))
      return false;
    resp->body = HttpDecodeChunkedBody(resp->body);
  } else if (content_length >= 0 && resp->body.size() < (size_t)content_length) {
    // Content-Length 声明了更多字节但连接提前结束，响应不完整。
    return false;
  }
  return true;
}

static bool ParseHttpUrl(const std::string &url, std::string *host,
                         std::string *port, std::string *path) {
  if (url.rfind("http://", 0) != 0)
    return false;
  const char *p = url.c_str() + 7;
  // authority 到 /、?、# 为止；只带 query 没有路径时，请求行必须是 "/?query"。
  const char *hostport_end = p;
  while (*hostport_end && *hostport_end != '/' && *hostport_end != '?' && *hostport_end != '#')
    hostport_end++;
  std::string hostport(p, hostport_end - p);
  if (*hostport_end == '?')
    *path = "/" + std::string(hostport_end);
  else if (*hostport_end == '/')
    *path = hostport_end;
  else
    *path = "/";
  // fragment 不应发送给服务器。
  size_t frag_pos = path->find('#');
  if (frag_pos != std::string::npos)
    *path = path->substr(0, frag_pos);
  if (hostport.empty())
    return false;

  if (hostport[0] == '[') {
    size_t end = hostport.find(']');
    if (end == std::string::npos)
      return false;
    *host = hostport.substr(1, end - 1);
    if (end + 1 < hostport.size() && hostport[end + 1] == ':')
      *port = hostport.substr(end + 2);
    else
      *port = "80";
  } else {
    size_t colon = hostport.rfind(':');
    if (colon != std::string::npos) {
      *host = hostport.substr(0, colon);
      *port = hostport.substr(colon + 1);
    } else {
      *host = hostport;
      *port = "80";
    }
  }
  return !host->empty() && !port->empty();
}

bool FetchHttpResponseOnce(const std::string &url, int timeout_sec, HttpResponseData *resp) {
  std::string host, port, path;
  if (!ParseHttpUrl(url, &host, &port, &path)) {
    RERROR("HTTP 地址格式不正确: %s", url.c_str());
    return false;
  }

  int timeout_ms = (timeout_sec > 0 ? timeout_sec : 10) * 1000;
  HttpSocket s = HttpConnect(host, port, timeout_ms);
  if (s == kInvalidHttpSocket) {
    RERROR("无法连接 %s:%s", host.c_str(), port.c_str());
    return false;
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

  bool ok = HttpSendAll(s, request, timeout_ms) && HttpRecvResponse(s, timeout_ms, resp);
  CloseHttpSocket(s);
  if (!ok)
    RERROR("读取 %s 的 HTTP 响应失败", url.c_str());
  return ok;
}

#if !defined(WITH_MBEDTLS)
// 未启用 mbedTLS 时保留 curl 回退，但仍按同一套 3xx/200 规则解析。
static bool FetchHttpsResponseOnceCurl(const std::string &url, int timeout_sec, HttpResponseData *resp) {
  std::string output = executeCurlCommand(url, timeout_sec, 1);
  size_t header_end = output.find("\r\n\r\n");
  if (header_end == std::string::npos)
    return false;
  header_end += 4;
  resp->headers = output.substr(0, header_end);
  resp->status_code = ParseHttpStatusCode(resp->headers);
  resp->body = output.substr(header_end, 8 * 1024);
  std::string value;
  if (HttpGetHeaderValue(resp->headers, "transfer-encoding", &value) &&
      HttpTextContainsNoCase(value, "chunked"))
    resp->body = HttpDecodeChunkedBody(resp->body);
  return true;
}
#endif

static const int kMaxHttpRedirects = 3;

std::string FetchHttpRedirectHostPort(const std::string &url, int timeout_sec) {
  std::string current = NormalizeHttpUrl(url);
  if (current.empty()) {
    RERROR("不支持的 URL: %s", url.c_str());
    return "";
  }

  int total_timeout = timeout_sec > 0 ? timeout_sec : 10;
  // 整条重定向链共用一个超时预算，避免多次重定向把主线程阻塞数倍时间。
  uint64 deadline = OsGetMilliseconds() + (uint64)total_timeout * 1000;

  // 跟随 Location 时记录它的 host:port。下一跳如果不是 HTTP(S) 服务
  //（例如 Location 直接就是 WireGuard 的 TCP 端点），回落到这个地址。
  // 只记录地址字面量；域名 URL 失败时保留上次可用地址，避免把
  // 重定向服务的 443/80 端口误当成 Endpoint。
  std::string fallback_endpoint;

  for (int redirects = 0; redirects <= kMaxHttpRedirects; redirects++) {
    uint64 now = OsGetMilliseconds();
    if (now >= deadline) {
      RERROR("解析 %s 超过 %d 秒，停止", url.c_str(), total_timeout);
      return fallback_endpoint;
    }
    int remaining_sec = (int)((deadline - now + 999) / 1000);
    if (remaining_sec < 1)
      remaining_sec = 1;

    HttpResponseData resp;
#if defined(WITH_MBEDTLS)
    bool ok = current.rfind("https://", 0) == 0
                  ? FetchHttpsResponseOnce(current, remaining_sec, &resp)
                  : FetchHttpResponseOnce(current, remaining_sec, &resp);
#else
    bool ok = current.rfind("https://", 0) == 0
                  ? FetchHttpsResponseOnceCurl(current, remaining_sec, &resp)
                  : FetchHttpResponseOnce(current, remaining_sec, &resp);
#endif
    if (!ok || resp.status_code == 0) {
      if (!fallback_endpoint.empty()) {
        RINFO("无法作为 HTTP(S) 获取 %s，直接使用其地址: %s",
              current.c_str(), fallback_endpoint.c_str());
        return fallback_endpoint;
      }
      if (!ok)
        return "";
      RERROR("无法解析 %s 的 HTTP 状态行", current.c_str());
      return "";
    }

    if (resp.status_code == 200) {
      std::string endpoint = ExtractEndpointHostPort(resp.body);
      if (endpoint.empty()) {
        RERROR("HTTP 200 响应中没有有效的 IPv4/IPv6 地址和端口: %s", current.c_str());
        return "";
      }
      return endpoint;
    }

    if (resp.status_code >= 300 && resp.status_code < 400) {
      std::string location;
      if (!HttpGetHeaderValue(resp.headers, "location", &location) || location.empty()) {
        RERROR("%s 返回 HTTP %d 但没有 Location", current.c_str(), resp.status_code);
        return "";
      }

      // Location 可能是完整 URL、相对引用（/x、?x、#x、next、../x），
      // 也可能直接写 ip:port/域名:port。只有最后一种直接当 Endpoint 返回，
      // 其余都继续请求下一跳，由状态码决定是再重定向还是 200 文本。
      std::string endpoint;
      if (!HttpLocationIsUrl(location))
        endpoint = ExtractEndpointHostPort(location, true);
      if (!endpoint.empty())
        return endpoint;

      if (redirects == kMaxHttpRedirects) {
        RERROR("重定向次数超过 %d 次，停止解析: %s", kMaxHttpRedirects, current.c_str());
        return "";
      }
      std::string next = HttpResolveRedirectUrl(current, location);
      if (next.empty()) {
        RERROR("无法解析重定向地址: %s", location.c_str());
        return "";
      }
      RINFO("HTTP %d 重定向(%d/%d): %s -> %s", resp.status_code,
            redirects + 1, kMaxHttpRedirects, current.c_str(), next.c_str());
      fallback_endpoint = ExtractUrlHostPort(next);
      current = next;
      continue;
    }

    RERROR("%s 返回 HTTP %d，无法获取 Endpoint", current.c_str(), resp.status_code);
    return "";
  }
  return "";
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
  // 先处理 txt:域名 / TXT:域名，把 TXT 记录里的 ip:port 当作最终地址。
  if (StringStartsWithNoCase(hostport, "txt:")) {
    std::string endpoint = FetchTxtRecordHostPort(hostport.substr(4), 10);
    if (endpoint.empty()) {
      RERROR("无法从 TXT 记录获取地址: %s", si);
      return false;
    }
    hostport = endpoint;
    RINFO("从 TXT 记录获取到地址: %s", hostport.c_str());
  } else if (hostport.rfind("http:", 0) == 0 || hostport.rfind("https:", 0) == 0) {
    // 检查是否为 http 或 https 开头
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

bool ParseSockaddrInWithoutPort(char *s, IpAddr *sin, DnsResolver *resolver, int flags, int max_retries) {
  memset(sin, 0, sizeof(IpAddr));

  if (inet_pton(AF_INET6, s, &sin->sin6.sin6_addr) == 1) {
    sin->sin.sin_family = AF_INET6;
    return true;
  } else if (ParseIpv4WithNAT64Translation(s, sin, flags)) {
    return true;
  } else if (!resolver) {
    return false;
  } else if (!resolver->Resolve(s, sin, max_retries)) {
    RERROR("无法解析 %s", s);
    return false;
  }
  return true;
}

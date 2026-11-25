// SPDX-License-Identifier: AGPL-1.0-only
// 使用 mbedTLS 实现 HTTPS 重定向/200 文本解析，替代 curl -k 外部进程。
// 只读取响应头和 200 响应体，不做证书校验（与旧 curl -k 行为一致）。
#include "stdafx.h"
#include <string.h>
#if defined(OS_WIN)
#include <winsock2.h>
#else
#include <sys/socket.h>
#include <sys/select.h>
#include <netdb.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#endif
#include "tunsafe_types.h"
#include "tunsafe_ipaddr.h"
#include "tunsafe_dnsresolve.h"
#include "util.h"

#if defined(WITH_MBEDTLS)

#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/error.h"

static void LogMbedtlsError(const char *what, int ret) {
  char buf[128];
  mbedtls_strerror(ret, buf, sizeof(buf));
  RERROR("%s: %s (0x%04x)", what, buf, (unsigned)(0u - (unsigned)ret));
}

static bool ParseHttpsUrl(const std::string &url, std::string *host,
                          std::string *port, std::string *path) {
  if (url.rfind("https://", 0) != 0)
    return false;
  const char *p = url.c_str() + 8;
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
      *port = "443";
  } else {
    size_t colon = hostport.rfind(':');
    if (colon != std::string::npos) {
      *host = hostport.substr(0, colon);
      *port = hostport.substr(colon + 1);
    } else {
      *host = hostport;
      *port = "443";
    }
  }
  return !host->empty() && !port->empty();
}

#if defined(OS_WIN)
typedef SOCKET NetSocket;
#define kInvalidNetSocket INVALID_SOCKET
static void CloseNetSocket(NetSocket s) { closesocket(s); }
#else
typedef int NetSocket;
#define kInvalidNetSocket (-1)
static void CloseNetSocket(NetSocket s) { close(s); }
#endif

static bool NetSetNonBlocking(NetSocket s, bool enable) {
#if defined(OS_WIN)
  u_long mode = enable ? 1 : 0;
  return ioctlsocket(s, FIONBIO, &mode) == 0;
#else
  int flags = fcntl(s, F_GETFL, 0);
  if (flags < 0)
    return false;
  if (enable) flags |= O_NONBLOCK; else flags &= ~O_NONBLOCK;
  return fcntl(s, F_SETFL, flags) == 0;
#endif
}

static bool NetWaitWritable(NetSocket s, int timeout_ms) {
  fd_set set;
  FD_ZERO(&set);
  FD_SET(s, &set);
  struct timeval tv;
  tv.tv_sec = timeout_ms / 1000;
  tv.tv_usec = (timeout_ms % 1000) * 1000;
#if defined(OS_WIN)
  int r = select(0, NULL, &set, NULL, &tv);
#else
  int r = select(s + 1, NULL, &set, NULL, &tv);
#endif
  return r > 0;
}

// mbedtls_net_connect 是阻塞 connect，被防火墙丢包时要等系统默认的超时
//（通常 2 分钟以上）。这里用非阻塞 connect + select 加上调用方超时，
// 避免断线重连时把主线程卡住。
static bool ConnectTcpWithTimeout(mbedtls_net_context *ctx, const char *host,
                                  const char *port, int timeout_ms) {
  struct addrinfo hints;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  struct addrinfo *res = NULL;
  if (getaddrinfo(host, port, &hints, &res) != 0)
    return false;

  bool connected = false;
  uint64 start_ms = OsGetMilliseconds();
  for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
    int remaining_ms = timeout_ms - (int)(OsGetMilliseconds() - start_ms);
    if (remaining_ms <= 0)
      break;
    NetSocket s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (s == kInvalidNetSocket)
      continue;
    if (!NetSetNonBlocking(s, true)) {
      CloseNetSocket(s);
      continue;
    }
    bool in_progress = false;
    if (connect(s, ai->ai_addr, (int)ai->ai_addrlen) == 0) {
      connected = true;
    } else {
#if defined(OS_WIN)
      int err = WSAGetLastError();
      in_progress = (err == WSAEWOULDBLOCK || err == WSAEINPROGRESS);
#else
      int err = errno;
      in_progress = (err == EINPROGRESS || err == EINTR);
#endif
    }
    if (!connected && in_progress && NetWaitWritable(s, remaining_ms)) {
      int so_error = 0;
#if defined(OS_WIN)
      int len = sizeof(so_error);
      getsockopt(s, SOL_SOCKET, SO_ERROR, (char*)&so_error, &len);
#else
      socklen_t len = sizeof(so_error);
      getsockopt(s, SOL_SOCKET, SO_ERROR, &so_error, &len);
#endif
      connected = (so_error == 0);
    }
    if (connected) {
      NetSetNonBlocking(s, false);
      // 与 mbedtls_net_connect 保持一致：net_context 里保存的就是 int。
      ctx->fd = (int)s;
      break;
    }
    CloseNetSocket(s);
  }
  freeaddrinfo(res);
  return connected;
}

// 读取一次 HTTPS 响应头；200 时继续读取响应体（最多 8KB）。
static bool ReadHttpsResponse(mbedtls_ssl_context *ssl, mbedtls_ssl_config *conf,
                              HttpResponseData *resp) {
  const size_t kMaxHeaderBytes = 16 * 1024;
  const size_t kMaxBodyBytes = 8 * 1024;
  std::string raw;
  size_t header_end = std::string::npos;
  char buf[1024];

  while (raw.size() < kMaxHeaderBytes) {
    int ret = mbedtls_ssl_read(ssl, (unsigned char*)buf, sizeof(buf));
    if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE)
      continue;
    if (ret <= 0)
      break;
    raw.append(buf, ret);
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
  resp->body = raw.substr(header_end, kMaxBodyBytes);
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

  // 长度未知时只再等 1 秒，避免服务器保持连接导致卡满整个超时。
  if (!chunked && content_length < 0)
    mbedtls_ssl_conf_read_timeout(conf, 1000);

  while (resp->body.size() < kMaxBodyBytes) {
    if (!chunked && content_length >= 0 && resp->body.size() >= (size_t)content_length)
      break;
    if (chunked && HttpChunkedBodyComplete(resp->body))
      break;
    int ret = mbedtls_ssl_read(ssl, (unsigned char*)buf, sizeof(buf));
    if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE)
      continue;
    if (ret <= 0)
      break;
    resp->body.append(buf, ret);
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

bool FetchHttpsResponseOnce(const std::string &url, int timeout_sec, HttpResponseData *resp) {
#if defined(OS_WIN)
  // mbedTLS 的 net_sockets 依赖 Winsock 已初始化；主程序未显式调用时这里兜底。
  static bool winsock_ready = false;
  if (!winsock_ready) {
    WSADATA wsa_data;
    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
      RERROR("WSAStartup 失败");
      return false;
    }
    winsock_ready = true;
  }
#endif
  std::string host, port, path;
  if (!ParseHttpsUrl(url, &host, &port, &path)) {
    RERROR("HTTPS 地址格式不正确: %s", url.c_str());
    return false;
  }

  mbedtls_net_context server_fd;
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;
  mbedtls_ssl_context ssl;
  mbedtls_ssl_config conf;
  mbedtls_net_init(&server_fd);
  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&ctr_drbg);
  mbedtls_ssl_init(&ssl);
  mbedtls_ssl_config_init(&conf);

  int ret;
  const char *pers = "tunsafe_https";
  std::string request;
  size_t off = 0;
  bool ok = false;

  if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                   (const unsigned char*)pers, strlen(pers))) != 0) {
    LogMbedtlsError("mbedtls_ctr_drbg_seed", ret);
    goto cleanup;
  }
  if (!ConnectTcpWithTimeout(&server_fd, host.c_str(), port.c_str(),
                             (timeout_sec > 0 ? timeout_sec : 10) * 1000)) {
    RERROR("无法连接 %s:%s", host.c_str(), port.c_str());
    goto cleanup;
  }
  if ((ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT,
                                         MBEDTLS_SSL_TRANSPORT_STREAM,
                                         MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
    LogMbedtlsError("mbedtls_ssl_config_defaults", ret);
    goto cleanup;
  }
  // 与旧 curl -k 行为一致：只读取重定向地址或 200 文本，不校验证书链。
  mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);
  mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
  mbedtls_ssl_conf_read_timeout(&conf,
      (uint32_t)(timeout_sec > 0 ? timeout_sec : 10) * 1000);

  if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0) {
    LogMbedtlsError("mbedtls_ssl_setup", ret);
    goto cleanup;
  }
  if ((ret = mbedtls_ssl_set_hostname(&ssl, host.c_str())) != 0) {
    LogMbedtlsError("mbedtls_ssl_set_hostname", ret);
    goto cleanup;
  }
  mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv,
                      mbedtls_net_recv_timeout);

  while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
    if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
      LogMbedtlsError("mbedtls_ssl_handshake", ret);
      goto cleanup;
    }
  }

  request.reserve(256);
  request += "GET ";
  request += path;
  request += " HTTP/1.0\r\nHost: ";
  if (host.find(':') != std::string::npos) {
    request += "[";
    request += host;
    request += "]";
  } else {
    request += host;
  }
  if (port != "443") {
    request += ":";
    request += port;
  }
  request += "\r\nUser-Agent: TunSafe\r\nConnection: close\r\n\r\n";

  while (off < request.size()) {
    ret = mbedtls_ssl_write(&ssl, (const unsigned char*)request.data() + off,
                            request.size() - off);
    if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE)
      continue;
    if (ret <= 0) {
      LogMbedtlsError("mbedtls_ssl_write", ret);
      goto cleanup;
    }
    off += ret;
  }

  ok = ReadHttpsResponse(&ssl, &conf, resp);
  if (!ok)
    RERROR("读取 %s 的 HTTPS 响应失败", url.c_str());

cleanup:
  mbedtls_ssl_close_notify(&ssl);
  mbedtls_net_free(&server_fd);
  mbedtls_ssl_free(&ssl);
  mbedtls_ssl_config_free(&conf);
  mbedtls_ctr_drbg_free(&ctr_drbg);
  mbedtls_entropy_free(&entropy);
  return ok;
}

std::string FetchHttpsRedirectHostPortMbedTls(const std::string &url, int timeout_sec) {
  // 重定向和 200 文本解析统一由 FetchHttpRedirectHostPort 处理，
  // 保证配置加载和断线重连走完全相同的规则。
  return FetchHttpRedirectHostPort(url, timeout_sec);
}

#endif  // defined(WITH_MBEDTLS)

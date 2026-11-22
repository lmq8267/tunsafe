// SPDX-License-Identifier: AGPL-1.0-only
// 使用 mbedTLS 实现 HTTPS 重定向解析，替代 curl -k 外部进程。
// 只用于读取 HTTP 响应头里的 Location，不做证书校验（与旧 curl -k 行为一致）。
#include "stdafx.h"
#include <string.h>
#if defined(OS_WIN)
#include <winsock2.h>
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
  const char *slash = strchr(p, '/');
  const char *query = strchr(p, '?');
  const char *frag = strchr(p, '#');
  const char *hostport_end = slash;
  if (!hostport_end || (query && query < hostport_end)) hostport_end = query;
  if (!hostport_end || (frag && frag < hostport_end)) hostport_end = frag;
  std::string hostport = hostport_end ? std::string(p, hostport_end - p) : std::string(p);
  *path = slash ? std::string(slash) : std::string("/");
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

std::string FetchHttpsRedirectHostPortMbedTls(const std::string &url, int timeout_sec) {
#if defined(OS_WIN)
  // mbedTLS 的 net_sockets 依赖 Winsock 已初始化；主程序未显式调用时这里兜底。
  static bool winsock_ready = false;
  if (!winsock_ready) {
    WSADATA wsa_data;
    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
      RERROR("WSAStartup 失败");
      return "";
    }
    winsock_ready = true;
  }
#endif
  std::string host, port, path;
  if (!ParseHttpsUrl(url, &host, &port, &path)) {
    RERROR("HTTPS 地址格式不正确: %s", url.c_str());
    return "";
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
  std::string headers;
  std::string request;
  char buf[1024];
  size_t off = 0;
  bool ok = false;

  if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                   (const unsigned char*)pers, strlen(pers))) != 0) {
    LogMbedtlsError("mbedtls_ctr_drbg_seed", ret);
    goto cleanup;
  }
  if ((ret = mbedtls_net_connect(&server_fd, host.c_str(), port.c_str(),
                                 MBEDTLS_NET_PROTO_TCP)) != 0) {
    LogMbedtlsError("mbedtls_net_connect", ret);
    goto cleanup;
  }
  if ((ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT,
                                         MBEDTLS_SSL_TRANSPORT_STREAM,
                                         MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
    LogMbedtlsError("mbedtls_ssl_config_defaults", ret);
    goto cleanup;
  }
  // 与旧 curl -k 行为一致：只读取重定向地址，不校验证书链。
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

  while (headers.size() < 16 * 1024) {
    ret = mbedtls_ssl_read(&ssl, (unsigned char*)buf, sizeof(buf));
    if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE)
      continue;
    if (ret <= 0)
      break;
    headers.append(buf, ret);
    if (headers.find("\r\n\r\n") != std::string::npos) {
      ok = true;
      break;
    }
  }
  if (headers.empty()) {
    RERROR("读取 %s 的 HTTPS 响应失败", url.c_str());
    goto cleanup;
  }
  ok = true;

cleanup:
  mbedtls_ssl_close_notify(&ssl);
  mbedtls_net_free(&server_fd);
  mbedtls_ssl_free(&ssl);
  mbedtls_ssl_config_free(&conf);
  mbedtls_ctr_drbg_free(&ctr_drbg);
  mbedtls_entropy_free(&entropy);
  if (!ok)
    return "";
  return ParseHttpRedirectHostPort(url, headers, host, port);
}

#endif  // defined(WITH_MBEDTLS)

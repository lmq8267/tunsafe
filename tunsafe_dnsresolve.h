#ifndef TUNSAFE_DNSRESOLVE_H_
#define TUNSAFE_DNSRESOLVE_H_

#include <string>
#include "tunsafe_threading.h"
#include "tunsafe_ipaddr.h"

class DnsBlocker;

class DnsResolverCanceller {
public:
  DnsResolverCanceller() : cancel_(false), cancel_sleep_once_(false) {}
  void Cancel();
  void CancelSleepOnce();
  void Reset() { cancel_ = false; }
  bool is_cancelled() { return cancel_; }
public:
  bool cancel_;
  bool cancel_sleep_once_;
  ConditionVariable condvar_;
};

class DnsResolver {
public:
  explicit DnsResolver(DnsBlocker *dns_blocker);
  ~DnsResolver();

  // max_retries < 0 表示无限重试；>=0 表示最多尝试 max_retries + 1 次。
  bool Resolve(const char *hostname, IpAddr *result, int max_retries = -1);
  void ClearCache();
  // 只清理指定域名的缓存，断线重连时不要影响其他 peer 的解析结果。
  void ClearCacheEntry(const char *hostname);

  void RetryNow();
  void Cancel() { token_.Cancel(); }
  void ResetCancel() { token_.Reset(); }
private:
  struct Entry {
    std::string name;
    IpAddr ip;
    Entry(const std::string &name, const IpAddr &ip) : name(name), ip(ip) {}
  };
  std::vector<Entry> cache_;
  DnsBlocker *dns_blocker_;
  DnsResolverCanceller token_;
  int retry_attempt_;
};

std::string executeCurlCommand(const std::string &url, int timeout = 10, int max_retries = 3);

// 单次 HTTP(S) 请求的结果。headers 含状态行，body 只对 200 响应读取且最多 8KB。
struct HttpResponseData {
  int status_code;
  std::string headers;
  std::string body;
  HttpResponseData() : status_code(0) {}
};

// 单次请求，不跟随重定向；拿到完整响应头返回 true。
bool FetchHttpResponseOnce(const std::string &url, int timeout_sec, HttpResponseData *resp);
bool FetchHttpsResponseOnce(const std::string &url, int timeout_sec, HttpResponseData *resp);

// 解析状态行（如 “HTTP/1.1 302 Found”），失败返回 0。
int ParseHttpStatusCode(const std::string &headers);

// 大小写不敏感地取响应头字段值，并去掉首尾空白。
bool HttpGetHeaderValue(const std::string &headers, const char *name, std::string *value);

// 解码 Transfer-Encoding: chunked 的响应体。
std::string HttpDecodeChunkedBody(const std::string &body);

// 判断 chunked 响应体是否已经读到结束块（允许带 trailer）。
bool HttpChunkedBodyComplete(const std::string &body);

// 大小写不敏感地判断 text 是否包含 needle。
bool HttpTextContainsNoCase(const std::string &text, const char *needle);

// 从 200 文本或 scheme-less 的 Location 中提取 host:port。
// 默认只接受 IPv4 / [IPv6] 加端口（200 响应体按此规则）；
// allow_hostname 用于 scheme-less 的 Location，兼容服务直接返回域名:端口。
std::string ExtractEndpointHostPort(const std::string &text, bool allow_hostname = false);

// http:// 使用内置轻量 HTTP 客户端，https:// 在启用 WITH_MBEDTLS 时使用 mbedTLS。
// 仅 3xx 跟随 Location（最多 3 次），200 取响应文本中的地址；其他状态码视为失败。
std::string FetchHttpRedirectHostPort(const std::string &url, int timeout_sec = 10);
std::string FetchHttpsRedirectHostPortMbedTls(const std::string &url, int timeout_sec = 10);

#endif  // TUNSAFE_DNSRESOLVE_H_

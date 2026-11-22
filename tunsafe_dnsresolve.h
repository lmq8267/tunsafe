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

// http:// 使用内置轻量 HTTP 客户端，不依赖外部命令；
// https:// 在启用 WITH_MBEDTLS 时使用 mbedTLS，否则保留 curl -k 回退。
std::string FetchHttpRedirectHostPort(const std::string &url, int timeout_sec = 10);
std::string FetchHttpsRedirectHostPortMbedTls(const std::string &url, int timeout_sec = 10);

// 从 HTTP(S) 响应头中解析 Location，返回 host:port。
std::string ParseHttpRedirectHostPort(const std::string &url, const std::string &headers,
                                      const std::string &host, const std::string &port);

#endif  // TUNSAFE_DNSRESOLVE_H_

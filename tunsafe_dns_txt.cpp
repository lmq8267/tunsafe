// SPDX-License-Identifier: AGPL-1.0-only
// 内置轻量 DNS 查询，用于 Endpoint 的 TXT/A/AAAA 解析。
// OpenWrt 使用的 musl 没有 res_query，所以这里自己构造 DNS 报文，
// 避免依赖平台 resolver 接口。未配置 DNS 时 Windows 使用系统 DnsQuery/TXT。
#include "stdafx.h"
#include <string.h>
#include <vector>
#if defined(OS_WIN)
#include <winsock2.h>
#include <windows.h>
#include <windns.h>
#if defined(_MSC_VER)
#pragma comment(lib, "dnsapi.lib")
#endif
#else
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#endif
#include "tunsafe_types.h"
#include "tunsafe_ipaddr.h"
#include "tunsafe_dnsresolve.h"
#include "tunsafe_threading.h"
#include "util.h"

// 从 TXT 文本里取出 ipv4:port 或 ipv6:port。
// 一条 TXT 里可能用空白/逗号分隔多个地址，只取第一个有效的。
std::string ExtractTxtEndpointHostPort(const std::string &text) {
  size_t pos = 0;
  while (pos < text.size()) {
    size_t start = text.find_first_not_of(" \t\r\n,;", pos);
    if (start == std::string::npos)
      break;
    size_t end = text.find_first_of(" \t\r\n,;", start);
    if (end == std::string::npos)
      end = text.size();
    std::string value = text.substr(start, end - start);

    // TXT 可以包含任意二进制，只接受可打印 ASCII，避免 NUL 截断影响端口解析。
    bool printable = true;
    for (size_t i = 0; i < value.size(); i++) {
      unsigned char c = (unsigned char)value[i];
      if (c <= 0x20 || c >= 0x7f) {
        printable = false;
        break;
      }
    }
    if (!printable) {
      pos = end + 1;
      continue;
    }

    // 先按 IPv4:port / [IPv6]:port 解析。
    std::string endpoint = ExtractEndpointHostPort(value, false);
    if (!endpoint.empty())
      return endpoint;

    // 兼容未加方括号的 IPv6:port，按最后一个冒号拆分端口。
    size_t colon = value.rfind(':');
    if (colon != std::string::npos && colon + 1 < value.size()) {
      std::string host = value.substr(0, colon);
      std::string port_text = value.substr(colon + 1);
      struct in6_addr addr6;
      uint16 port;
      if (inet_pton(AF_INET6, host.c_str(), &addr6) == 1 &&
          ParsePortNumber(port_text.c_str(), &port))
        return "[" + host + "]:" + port_text;
    }
    pos = end + 1;
  }
  return "";
}

// 配置里 [Interface] 的 DNS = 指定的服务器。TXT 查询只使用它们；
// Endpoint 的 A/AAAA 查询优先使用它们，失败后回退系统 DNS。
static std::vector<std::string> g_configured_dns_servers;
static Mutex g_dns_servers_mutex;

void SetConfiguredDnsServers(const std::vector<std::string> &servers) {
  g_dns_servers_mutex.Acquire();
  g_configured_dns_servers = servers;
  g_dns_servers_mutex.Release();
}

static std::vector<std::string> GetConfiguredDnsServers() {
  g_dns_servers_mutex.Acquire();
  std::vector<std::string> result = g_configured_dns_servers;
  g_dns_servers_mutex.Release();
  return result;
}

bool HasConfiguredDnsServers() {
  g_dns_servers_mutex.Acquire();
  bool result = !g_configured_dns_servers.empty();
  g_dns_servers_mutex.Release();
  return result;
}

#if defined(OS_WIN)
// 没有指定 DNS 时沿用系统 DNS 客户端，它已经处理了各类网络适配器。
static bool QueryTxtRecordsSystem(const std::string &domain, int timeout_sec,
                                  std::vector<std::string> *values) {
  (void)timeout_sec;  // DnsQuery 的超时由系统 DNS 客户端控制
  PDNS_RECORDA record = NULL;
  DNS_STATUS status = DnsQuery_A(domain.c_str(), DNS_TYPE_TEXT, DNS_QUERY_STANDARD,
                                 NULL, &record, NULL);
  if (status != ERROR_SUCCESS || record == NULL) {
    RERROR("TXT 查询失败: %s (code=%ld)", domain.c_str(), (long)status);
    return false;
  }
  for (PDNS_RECORDA r = record; r != NULL; r = r->pNext) {
    if (r->wType != DNS_TYPE_TEXT)
      continue;
    std::string value;
    for (DWORD i = 0; i < r->Data.TXT.dwStringCount; i++) {
      if (r->Data.TXT.pStringArray[i])
        value += r->Data.TXT.pStringArray[i];
    }
    if (!value.empty())
      values->push_back(value);
  }
  DnsRecordListFree(record, DnsFreeRecordList);
  return !values->empty();
}
#endif  // defined(OS_WIN)

#if defined(OS_WIN)
typedef SOCKET DnsSocket;
typedef int DnsSockLen;
#define kInvalidDnsSocket INVALID_SOCKET
static void CloseDnsSocket(DnsSocket s) { closesocket(s); }
#else
typedef int DnsSocket;
typedef socklen_t DnsSockLen;
#define kInvalidDnsSocket (-1)
static void CloseDnsSocket(DnsSocket s) { close(s); }
#endif

struct DnsServerAddr {
  int family;
  sockaddr_storage storage;
  DnsSockLen length;
};

// 一条解析出来的 DNS 记录，rdata 保留原始字节，由调用方按类型解释。
struct DnsRecord {
  uint16 type;
  uint16 klass;
  std::string rdata;
};

static bool InitDnsSockets() {
#if defined(OS_WIN)
  // 主程序没有统一初始化 Winsock，这里在第一次发送 UDP 前兜底。
  static bool ready = false;
  if (!ready) {
    WSADATA wsa_data;
    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0)
      return false;
    ready = true;
  }
#endif
  return true;
}

static void AppendU16(std::vector<uint8> *out, uint16 v) {
  out->push_back((uint8)(v >> 8));
  out->push_back((uint8)(v & 0xff));
}

static uint16 ReadU16(const uint8 *p) {
  return (uint16)(((uint16)p[0] << 8) | p[1]);
}

static bool EncodeDnsName(const std::string &name, std::vector<uint8> *out) {
  size_t name_len = name.size();
  while (name_len > 0 && name[name_len - 1] == '.')
    name_len--;
  if (name_len == 0 || name_len > 253)
    return false;
  size_t start = 0;
  size_t encoded_len = 1;  // 末尾的根标签
  while (start < name_len) {
    size_t dot = name.find('.', start);
    if (dot == std::string::npos || dot > name_len)
      dot = name_len;
    size_t label_len = dot - start;
    if (label_len == 0 || label_len > 63)
      return false;
    encoded_len += 1 + label_len;
    if (encoded_len > 255)
      return false;
    out->push_back((uint8)label_len);
    out->insert(out->end(), name.begin() + start, name.begin() + dot);
    start = dot + 1;
  }
  out->push_back(0);
  return true;
}

// 只跳过域名，不关心内容；压缩指针只跳 2 字节。
static bool SkipDnsName(const uint8 *msg, size_t len, size_t *pos) {
  size_t p = *pos;
  while (p < len) {
    uint8 c = msg[p];
    if (c == 0) {
      *pos = p + 1;
      return true;
    }
    if ((c & 0xc0) == 0xc0) {
      if (p + 1 >= len)
        return false;
      *pos = p + 2;
      return true;
    }
    if (c & 0xc0)
      return false;
    p += 1 + c;
  }
  return false;
}

// 解析 DNS 响应中的问题区和答案区。整包边界检查通过后才交给调用方，
// 避免半截响应里的记录被后续查询误用。
static bool ParseDnsResponse(const uint8 *data, size_t len, uint16 id,
                             std::vector<DnsRecord> *records, bool *truncated) {
  *truncated = false;
  if (len < 12)
    return false;
  if (ReadU16(data) != id || (ReadU16(data + 2) & 0x8000) == 0)
    return false;
  uint16 flags = ReadU16(data + 2);
  *truncated = (flags & 0x0200) != 0;
  int rcode = flags & 0x000f;
  if (rcode != 0) {
    RINFO("DNS 查询返回 RCODE=%d", rcode);
    return false;
  }
  uint16 qdcount = ReadU16(data + 4);
  uint16 ancount = ReadU16(data + 6);
  size_t pos = 12;
  std::vector<DnsRecord> found;

  for (uint16 i = 0; i < qdcount; i++) {
    if (!SkipDnsName(data, len, &pos) || pos + 4 > len)
      return false;
    pos += 4;
  }
  for (uint16 i = 0; i < ancount; i++) {
    if (!SkipDnsName(data, len, &pos) || pos + 10 > len)
      return false;
    DnsRecord record;
    record.type = ReadU16(data + pos);
    record.klass = ReadU16(data + pos + 2);
    uint16 rdlen = ReadU16(data + pos + 8);
    size_t rdata = pos + 10;
    if (rdata + rdlen > len)
      return false;
    record.rdata.assign((const char*)data + rdata, rdlen);
    found.push_back(record);
    pos = rdata + rdlen;
  }
  records->swap(found);
  return true;
}

static bool ParseDnsServerAddr(const std::string &text, DnsServerAddr *out) {
  // 去掉 IPv6 的 %scope（作用域 ID 对普通域名查询用不到）。
  std::string host = text;
  size_t scope = host.find('%');
  if (scope != std::string::npos)
    host.resize(scope);
  memset(out, 0, sizeof(*out));
  sockaddr_in *v4 = (sockaddr_in*)&out->storage;
  if (inet_pton(AF_INET, host.c_str(), &v4->sin_addr) == 1) {
    v4->sin_family = AF_INET;
    v4->sin_port = htons(53);
#if defined(OS_MACOSX) || defined(OS_IOS) || defined(OS_FREEBSD) || defined(OS_OPENBSD)
    v4->sin_len = (uint8)sizeof(sockaddr_in);
#endif
    out->family = AF_INET;
    out->length = (DnsSockLen)sizeof(sockaddr_in);
    return true;
  }
  sockaddr_in6 *v6 = (sockaddr_in6*)&out->storage;
  if (inet_pton(AF_INET6, host.c_str(), &v6->sin6_addr) == 1) {
    v6->sin6_family = AF_INET6;
    v6->sin6_port = htons(53);
#if defined(OS_MACOSX) || defined(OS_IOS) || defined(OS_FREEBSD) || defined(OS_OPENBSD)
    v6->sin6_len = (uint8)sizeof(sockaddr_in6);
#endif
    out->family = AF_INET6;
    out->length = (DnsSockLen)sizeof(sockaddr_in6);
    return true;
  }
  return false;
}

#if !defined(OS_WIN)
static bool ReadResolvConfServers(std::vector<std::string> *servers) {
  FILE *fp = fopen("/etc/resolv.conf", "r");
  if (!fp)
    return false;
  char line[512];
  while (fgets(line, sizeof(line), fp) != NULL && servers->size() < 4) {
    char *p = line;
    while (*p == ' ' || *p == '\t')
      p++;
    if (strncmp(p, "nameserver", 10) != 0)
      continue;
    p += 10;
    if (*p != ' ' && *p != '\t')
      continue;
    while (*p == ' ' || *p == '\t')
      p++;
    char *end = p;
    while (*end && *end != ' ' && *end != '\t' && *end != '\r' &&
           *end != '\n' && *end != '#')
      end++;
    if (end > p)
      servers->push_back(std::string(p, end - p));
  }
  fclose(fp);
  return !servers->empty();
}
#endif  // !defined(OS_WIN)

static bool BuildDnsQuery(const std::string &domain, uint16 type, uint16 id,
                          std::vector<uint8> *query) {
  query->clear();
  AppendU16(query, id);
  AppendU16(query, 0x0100);  // RD
  AppendU16(query, 1);       // QDCOUNT
  AppendU16(query, 0);       // ANCOUNT
  AppendU16(query, 0);       // NSCOUNT
  AppendU16(query, 1);       // ARCOUNT: EDNS0
  if (!EncodeDnsName(domain, query))
    return false;
  AppendU16(query, type);
  AppendU16(query, 1);   // IN
  // EDNS0 OPT，声明 1232 字节，减少响应被截断的概率。
  query->push_back(0);
  AppendU16(query, 41);
  AppendU16(query, 1232);
  AppendU16(query, 0);
  AppendU16(query, 0);
  AppendU16(query, 0);
  return true;
}

static bool SendDnsQueryUdp(const DnsServerAddr &server,
                            const std::vector<uint8> &query, uint16 id,
                            int timeout_ms, std::vector<DnsRecord> *records,
                            bool *truncated) {
  DnsSocket fd = socket(server.family, SOCK_DGRAM, 0);
  if (fd == kInvalidDnsSocket)
    return false;
  int sent = (int)sendto(fd, (const char*)query.data(), (int)query.size(), 0,
                         (const sockaddr*)&server.storage, server.length);
  if (sent != (int)query.size()) {
    CloseDnsSocket(fd);
    return false;
  }

  uint8 buf[4096];
  bool ok = false;
  fd_set set;
  FD_ZERO(&set);
  FD_SET(fd, &set);
  struct timeval tv;
  tv.tv_sec = timeout_ms / 1000;
  tv.tv_usec = (timeout_ms % 1000) * 1000;
#if defined(OS_WIN)
  int r = select(0, &set, NULL, NULL, &tv);
#else
  int r = select(fd + 1, &set, NULL, NULL, &tv);
#endif
  if (r > 0) {
    int n = (int)recvfrom(fd, (char*)buf, (int)sizeof(buf), 0, NULL, NULL);
    if (n > 0) {
      std::vector<DnsRecord> response;
      bool tr = false;
      if (ParseDnsResponse(buf, (size_t)n, id, &response, &tr)) {
        *truncated = tr;
        records->swap(response);
        ok = true;
      }
    }
  }
  CloseDnsSocket(fd);
  return ok;
}

// 判断响应里是否有可用的指定类型记录。A/AAAA 同时校验 RDATA 长度。
static bool HasRecordType(const std::vector<DnsRecord> &records, uint16 type) {
  size_t want = 0;
  if (type == 1) want = 4;
  else if (type == 28) want = 16;
  for (size_t i = 0; i < records.size(); i++) {
    if (records[i].type != type || records[i].klass != 1)
      continue;
    if (want != 0 && records[i].rdata.size() != want)
      continue;
    return true;
  }
  return false;
}

// 在 deadline 前依次尝试各 DNS 服务器，直到某个响应里出现 type 记录。
static bool CollectRecords(const std::string &domain, uint16 type, uint64 deadline,
                           const std::vector<std::string> &servers,
                           std::vector<DnsRecord> *records) {
  records->clear();
  if (servers.empty() || OsGetMilliseconds() >= deadline)
    return false;

  uint16 id = (uint16)OsGetMilliseconds();
  std::vector<uint8> query;
  if (!BuildDnsQuery(domain, type, id, &query)) {
    RERROR("DNS 域名格式不正确: %s", domain.c_str());
    return false;
  }

  for (size_t i = 0; i < servers.size(); i++) {
    uint64 now = OsGetMilliseconds();
    if (now >= deadline)
      break;
    int remaining = (int)(deadline - now);
    if (remaining <= 0)
      break;
    int per_server = remaining / (int)(servers.size() - i);
    if (per_server < 500) per_server = 500;
    if (per_server > 2000) per_server = 2000;
    if (per_server > remaining) per_server = remaining;

    DnsServerAddr addr;
    if (!ParseDnsServerAddr(servers[i], &addr)) {
      RINFO("忽略无法解析的 DNS 服务器: %s", servers[i].c_str());
      continue;
    }
    std::vector<DnsRecord> response;
    bool truncated = false;
    if (SendDnsQueryUdp(addr, query, id, per_server, &response, &truncated)) {
      if (HasRecordType(response, type)) {
        records->swap(response);
        return true;
      }
      // 服务器返回了 NOERROR 但没有该类型，继续试下一个（拆分 DNS）。
    }
    if (truncated)
      RERROR("DNS 响应被截断: %s", domain.c_str());
  }
  return false;
}

static bool ExtractTxtValues(const std::vector<DnsRecord> &records,
                             std::vector<std::string> *values) {
  for (size_t i = 0; i < records.size(); i++) {
    if (records[i].type != 16 || records[i].klass != 1)
      continue;
    std::string value;
    size_t p = 0;
    bool bad = false;
    while (p < records[i].rdata.size()) {
      uint8 slen = (uint8)records[i].rdata[p++];
      if (p + slen > records[i].rdata.size()) {
        bad = true;  // TXT 字符串长度超出 RDATA，丢弃该记录
        break;
      }
      value.append(records[i].rdata.data() + p, slen);
      p += slen;
    }
    if (!bad && !value.empty())
      values->push_back(value);
  }
  return !values->empty();
}

static bool ExtractAddresses(const std::vector<DnsRecord> &records, uint16 type,
                             std::vector<IpAddr> *addresses) {
  size_t want = type == 1 ? 4 : 16;
  for (size_t i = 0; i < records.size(); i++) {
    if (records[i].type != type || records[i].klass != 1 ||
        records[i].rdata.size() != want)
      continue;
    IpAddr addr;
    memset(&addr, 0, sizeof(addr));
    if (type == 1) {
      addr.sin.sin_family = AF_INET;
      memcpy(&addr.sin.sin_addr, records[i].rdata.data(), 4);
    } else {
      addr.sin.sin_family = AF_INET6;
      memcpy(&addr.sin6.sin6_addr, records[i].rdata.data(), 16);
    }
    addr.sin.sin_port = 0;
    addresses->push_back(addr);
  }
  return !addresses->empty();
}

static bool HostIsIpLiteral(const std::string &host) {
  struct in_addr a4;
  struct in6_addr a6;
  return inet_pton(AF_INET, host.c_str(), &a4) == 1 ||
         inet_pton(AF_INET6, host.c_str(), &a6) == 1;
}

static bool QueryTxtRecords(const std::string &domain, int timeout_sec,
                            std::vector<std::string> *values) {
  std::vector<std::string> servers = GetConfiguredDnsServers();
#if defined(OS_WIN)
  if (servers.empty())
    return QueryTxtRecordsSystem(domain, timeout_sec, values);
#else
  if (servers.empty() && !ReadResolvConfServers(&servers)) {
    // Android 等系统没有 resolv.conf，使用中国可访问的公共 DNS 兜底。
    RINFO("未找到 /etc/resolv.conf 的 nameserver，使用 223.5.5.5/119.29.29.29");
    servers.push_back("223.5.5.5");
    servers.push_back("119.29.29.29");
  }
#endif
  if (!InitDnsSockets())
    return false;

  int timeout_ms = (timeout_sec > 0 ? timeout_sec : 10) * 1000;
  uint64 deadline = OsGetMilliseconds() + timeout_ms;
  std::vector<DnsRecord> records;
  if (!CollectRecords(domain, 16, deadline, servers, &records))
    return false;
  return ExtractTxtValues(records, values);
}

bool ResolveHostWithConfiguredDns(const std::string &hostname,
                                  std::vector<IpAddr> *addresses,
                                  int timeout_ms) {
  addresses->clear();
  if (hostname.empty() || HostIsIpLiteral(hostname))
    return false;
  std::vector<std::string> servers = GetConfiguredDnsServers();
  if (servers.empty())
    return false;
  if (!InitDnsSockets())
    return false;

  int timeout = timeout_ms > 0 ? timeout_ms : 1;
  uint64 deadline = OsGetMilliseconds() + (uint64)timeout;
  std::vector<DnsRecord> records;
  if (CollectRecords(hostname, 1, deadline, servers, &records))
    ExtractAddresses(records, 1, addresses);
  if (addresses->empty()) {
    records.clear();
    if (CollectRecords(hostname, 28, deadline, servers, &records))
      ExtractAddresses(records, 28, addresses);
  }
  if (addresses->empty()) {
    RINFO("配置 DNS 未解析到 %s，回退系统 DNS", hostname.c_str());
    return false;
  }
  return true;
}

void GetHostAddressStrings(const std::string &hostname, int timeout_ms,
                           std::vector<std::string> *ips) {
  ips->clear();
  if (hostname.empty() || HostIsIpLiteral(hostname))
    return;
  // 给调用方保留系统 DNS 回退和连接的时间。
  int dns_timeout = timeout_ms > 2000 ? 2000 : timeout_ms;
  std::vector<IpAddr> addresses;
  if (!ResolveHostWithConfiguredDns(hostname, &addresses, dns_timeout))
    return;
  for (size_t i = 0; i < addresses.size(); i++) {
    char buf[kSizeOfAddress];
    PrintIpAddr(addresses[i], buf);
    if (buf[0])
      ips->push_back(buf);
  }
}

std::string FetchTxtRecordHostPort(const std::string &domain, int timeout_sec) {
  // 配置里可能写成 "txt: abc.com"，这里统一去掉首尾空白。
  size_t begin = domain.find_first_not_of(" \t\r\n");
  size_t end = domain.find_last_not_of(" \t\r\n");
  std::string name = begin == std::string::npos ? "" : domain.substr(begin, end - begin + 1);
  if (name.empty())
    return "";
  std::vector<std::string> values;
  if (!QueryTxtRecords(name, timeout_sec, &values)) {
    RERROR("查询 TXT 记录失败: %s", name.c_str());
    return "";
  }
  for (size_t i = 0; i < values.size(); i++) {
    std::string endpoint = ExtractTxtEndpointHostPort(values[i]);
    if (!endpoint.empty()) {
      RINFO("TXT %s -> %s", name.c_str(), endpoint.c_str());
      return endpoint;
    }
  }
  RERROR("TXT 记录中没有有效的 ip:port: %s", name.c_str());
  return "";
}

<p align="center">
  <img src="icons/green-bg-icon.ico" alt="TunSafe" width="96" height="96">
</p>

<h1 align="center">TunSafe</h1>

<p align="center">高性能、用户态 WireGuard 客户端，支持 TCP、重定向和头部混淆。</p>

<p align="center">
<a href="https://deepwiki.com/lmq8267/tunsafe"><img src="https://devin.ai/assets/askdeepwiki.png" alt="Ask DeepWiki"></a>
  <img alt="GitHub Created At" src="https://img.shields.io/github/created-at/lmq8267/tunsafe?logo=github&label=%E5%88%9B%E5%BB%BA%E6%97%A5%E6%9C%9F">
<a href="https://github.com/lmq8267/tunsafe/releases"><img src="https://img.shields.io/github/downloads/lmq8267/tunsafe/total?logo=github&label=%E4%B8%8B%E8%BD%BD%E9%87%8F"></a>
<a href="https://github.com/lmq8267/tunsafe/releases/"><img src="https://img.shields.io/github/release/lmq8267/tunsafe?logo=github&label=%E6%9C%80%E6%96%B0%E7%89%88%E6%9C%AC"></a>
<a href="https://github.com/lmq8267/tunsafe/issues"><img src="https://img.shields.io/github/issues-raw/lmq8267/tunsafe?logo=github&label=%E9%97%AE%E9%A2%98"></a>
<a href="GitHub repo size"><img src="https://img.shields.io/github/repo-size/lmq8267/tunsafe?logo=github&label=%E4%BB%93%E5%BA%93%E5%A4%A7%E5%B0%8F"></a>
</p>

原项目地址：https://github.com/TunSafe/TunSafe

liaohcai 大佬的相关教程：
https://www.right.com.cn/forum/thread-8348737-1-1.html

## 功能

- 用户态 WireGuard 客户端，不依赖内核模块
- 支持 Linux、OpenWrt、Windows、macOS、FreeBSD
- 支持 UDP、TCP、HTTP/HTTPS 重定向
- 支持头部混淆和自定义加密套件
- 断线重连时自动重新解析域名和重定向地址
- HTTPS 重定向使用内置 mbedTLS，不依赖外部 `curl`

## 编译

### Linux

```sh
make
```

静态链接：

```sh
make ENABLE_STATIC=1
```

### OpenWrt

`openwrt/Makefile` 可使用当前仓库源码，依赖 `libmbedtls`：

```sh
make package/tunsafe/compile V=s
```

## 使用说明

### 启动

```sh
TZ=utc-8 ./tunsafe start -d -n wg0 ./wg.conf
```

- `start`：启动接口
- `-d` / `--daemon`：后台运行
- `-n wg0`：指定网卡名为 `wg0`
- `./wg.conf`：WireGuard 配置文件路径

也可以直接传入配置文件：

```sh
./tunsafe ./wg.conf
```

### 停止

```sh
./tunsafe stop wg0
```

### OpenWrt 时区

如果日志时区不对，可在启动命令前加 `TZ=utc-8` 指定中国时区：

```sh
TZ=utc-8 ./tunsafe start -d -n wg0 ./wg.conf
```

如果是 procd 服务，可在启动脚本中加：

```sh
procd_set_param env TZ="utc-8"
```

## 参数介绍

用法：

```text
tunsafe <命令> [<参数>]
```

| 命令 | 说明 |
| --- | --- |
| `start [-d/--daemon] [-n <接口名>] [<文件名>]` | 启动接口 |
| `stop <接口名>` | 停止接口 |
| `show { <接口> \| all \| interfaces }` | 显示接口配置和状态 |
| `set <接口名> ...` | 修改接口配置或 Peer 列表 |
| `genkey` | 生成新的私钥 |
| `genpsk` | 生成新的预共享密钥 |
| `pubkey` | 从私钥生成公钥 |
| `--help` | 显示帮助 |

## 配置文件介绍

TunSafe 使用 WireGuard 的 INI 格式，包含 `[Interface]` 和 `[Peer]` 两部分。

### [Interface]

| 字段 | 说明 |
| --- | --- |
| `PrivateKey` | 本机私钥，必填 |
| `Address` | 本机地址，例如 `192.168.2.2/24` |
| `ListenPort` | UDP 监听端口 |
| `ListenPortTCP` | TCP 监听端口 |
| `DNS` | Endpoint 域名解析和连接后使用的 DNS 服务器，多个用逗号分隔 |
| `MTU` | 接口 MTU |
| `Table` | `auto` 或 `off`，是否自动添加路由 |
| `BlockDNS` | 是否阻止 DNS 泄漏 |
| `BlockInternet` | 断网时阻止流量，支持 `route`、`firewall`、`on`、`off`、`persist`、`allow_local` |
| `ExcludedIPs` | 不经过 VPN 的地址，支持 CIDR 和域名（域名解析为 IPv4） |
| `PreUp` / `PostUp` / `PreDown` / `PostDown` | 连接前后执行的命令 |
| `ObfuscateKey` / `ObfuscateTCP` | 头部混淆相关配置 |
| `Ciphers` / `Ciphers!` | 自定义加密套件 |

### [Peer]

| 字段 | 说明 |
| --- | --- |
| `PublicKey` | 对端公钥，必填 |
| `PresharedKey` | 预共享密钥，可选 |
| `AllowedIPs` | 允许走该 Peer 的网段，多个用逗号分隔，例如 `192.168.2.0/24` |
| `Endpoint` | 对端地址，支持 UDP、TCP、HTTP/HTTPS 重定向、TXT 记录 |
| `PersistentKeepalive` | NAT 保活间隔，单位秒 |
| `AllowMulticast` | 是否允许组播 |
| `Features` | 可选特性 |
| `Ciphers` | 自定义加密套件 |

### 配置示例

```ini
[Interface]
PrivateKey = 本机私钥
Address = 192.168.2.2/24
DNS = 223.5.5.5, 119.29.29.29
MTU = 1420

[Peer]
PublicKey = 对端公钥
PresharedKey = 预共享密钥
AllowedIPs = 192.168.2.0/24
Endpoint = 1.2.3.4:8040
PersistentKeepalive = 25
```

## Endpoint 写法

| 写法 | 说明 |
| --- | --- |
| `Endpoint = 1.2.3.4:8040` | 直连 UDP |
| `Endpoint = tcp://abc.com:8040` | 通过 TCP 连接 |
| `Endpoint = http://abc.com:8040` | 先请求 HTTP 重定向，再连接最终地址 |
| `Endpoint = https://abc.com:8040` | 先请求 HTTPS 重定向（mbedTLS），再连接最终地址 |
| `Endpoint = tcp://http://abc.com:8040` | TCP + HTTP 重定向 |
| `Endpoint = tcp://https://abc.com:8040` | TCP + HTTPS 重定向 |
| `Endpoint = txt:abc.com` | 查询 abc.com 的 TXT 记录，内容为 ipv4:port 或 ipv6:port |
| `Endpoint = TXT:abc.com` | 同上，`txt:` 大小写不敏感 |
| `Endpoint = tcp://txt:abc.com` | TCP + TXT 记录解析 |

断线重连时，TunSafe 会重新解析域名、重新请求 HTTP/HTTPS 重定向地址，也会重新查询 TXT 记录。

TXT 记录内容示例：

```dns
abc.com. 60 IN TXT "203.0.113.10:51820"
abc.com. 60 IN TXT "[2001:db8::10]:51820"
```

如果 `[Interface]` 里配置了 `DNS = 8.8.8.8, 1.1.1.1`，TXT 查询会使用这里指定的 DNS；没有配置时使用系统 DNS（Linux/OpenWrt 读取 `/etc/resolv.conf`，Windows 使用系统 DNS 客户端）。TXT 记录未加方括号的 IPv6 也支持，按最后一个冒号拆分端口。

配置里的 DNS 也会优先用于普通域名 Endpoint 和 HTTP/HTTPS 跳转主机的 A/AAAA 查询；这些查询失败时会回退系统 DNS，TXT 查询不回退。

## 常见问题

### 日志时间不对

在启动命令前加 `TZ=utc-8`，或在 procd 服务中设置：

```sh
procd_set_param env TZ="utc-8"
```

### 使用全局路由时排除 Endpoint 或 DNS

TunSafe 会自动把 IPv4 `Endpoint` 加入排除路由。DNS 服务器或额外地址可以这样写：

```ini
ExcludedIPs = 223.5.5.5/32, dns.example.com
```

`ExcludedIPs` 支持 CIDR 和域名，域名会在配置加载时解析为 IPv4。

### 使用全局路由后域名解析失败

VPN 启动后系统 DNS 可能被接管，导致重定向域名无法解析。可以：

- 保留可用的原 DNS
- 使用 IP 形式的 `Endpoint`
- 先确认域名在 VPN 启动前可以解析

### 配置文件权限

配置文件中包含私钥，建议限制权限：

```sh
chmod 600 wg.conf
```

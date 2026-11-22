# mbedTLS 集成说明（TunSafe）

本目录是 mbedTLS 3.6.2 源码，用于 HTTPS 重定向解析，替代外部 `curl` 进程。

## 版本

- 来源：https://github.com/Mbed-TLS/mbedtls
- 版本：`mbedtls-3.6.2`（LTS）
- 仅保留 `include/`、`library/`、`scripts/`、`configs/`、`cmake/` 等构建必需内容，
  已删除 tests/programs/docs 等非必要文件。

## Linux / macOS / FreeBSD

项目根目录的 `Makefile`、`build_linux.sh`、`build_osx.sh`、`build_freebsd.sh`
会自动执行：

```sh
make -C third_party/mbedtls lib
```

并链接：

```text
third_party/mbedtls/library/libmbedtls.a
third_party/mbedtls/library/libmbedx509.a
third_party/mbedtls/library/libmbedcrypto.a
```

## Windows (Visual Studio)

`TunSafe.vcxproj` 已配置：

- 预处理宏：`WITH_MBEDTLS=1`
- 头文件目录：`third_party\mbedtls\include`
- 链接库：`mbedtls.lib;mbedx509.lib;mbedcrypto.lib`
- 库目录：`third_party\mbedtls\build\library\$(Configuration)` 和
  `third_party\mbedtls\library\$(Configuration)`

需要先构建 mbedTLS 静态库（二选一）：

### 方式一：CMake（推荐）

在项目根目录执行：

```bat
cmake -S third_party\mbedtls -B third_party\mbedtls\build ^
      -G "Visual Studio 17 2022" -A x64 ^
      -DENABLE_PROGRAMS=OFF -DENABLE_TESTING=OFF
cmake --build third_party\mbedtls\build --config Release
```

生成的库位于 `third_party\mbedtls\build\library\Release`。
如果使用 Win32 配置，把 `-A x64` 改成 `-A Win32`。

### 方式二：Visual Studio 打开 CMake 工程

用 Visual Studio 直接打开 `third_party/mbedtls/CMakeLists.txt`，构建
`mbedtls`、`mbedx509`、`mbedcrypto` 三个静态库，然后按上面的库目录放好。

## OpenWrt

`openwrt/Makefile` 通过 `DEPENDS:=...+libmbedtls` 使用 OpenWrt 自带的
mbedTLS 包，不需要在本目录编译源码。编译命令已加：

```text
-DWITH_MBEDTLS=1 -lmbedtls -lmbedx509 -lmbedcrypto
```

## 证书校验

与旧 `curl -k` 行为一致，HTTPS 客户端使用 `MBEDTLS_SSL_VERIFY_NONE`，
只读取 `Location` 重定向地址，不校验证书链。仅用于端点发现，不传输业务数据。

## 体积

`include/mbedtls/mbedtls_config.h` 已按 TunSafe 需求裁剪：关闭服务器、DTLS、
调试、文件 IO、证书写入、旧算法和不常用曲线，只保留 TLS 1.2/1.3 客户端。
Linux x86_64 动态链接实测约 519KB（原 283KB，增加约 236KB），静态 musl
交叉编译后体积更小。升级 mbedTLS 时需要重新应用这些裁剪。

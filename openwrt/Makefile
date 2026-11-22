# SPDX-License-Identifier: GPL-2.0-only

include $(TOPDIR)/rules.mk

PKG_NAME:=tunsafe
PKG_VERSION:=1.5rc2
PKG_REV:=main
PKG_RELEASE:=1

# 使用当前仓库 main 分支源码，跳过哈希校验。
PKG_SOURCE_URL:=https://github.com/lmq8267/tunsafe
PKG_SOURCE_PROTO:=git
PKG_SOURCE_VERSION:=$(PKG_REV)
PKG_MIRROR_HASH:=skip


PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/package.mk

define Package/tunsafe
	SECTION:=net
	CATEGORY:=Network
	SUBMENU:=VPN
	DEPENDS:=+librt +libstdcpp +libmbedtls +(TARGET_armv5_3_2||TARGET_x86_2_6||TARGET_mips_3_4||TARGET_mipsel_3_4):libatomic
	TITLE:=TunSafe
	URL:=https://www.tunsafe.com/
	MAINTAINER:=
endef

define Package/tunsafe/description
 A high performance and secure VPN client that uses the WireGuard protocol.
 TunSafe makes it extremely simple to setup blazingly fast and secure VPN
 tunnels between Windows and Linux. This is a user-mode implementation that
 also supports non-standard obfuscation and TCP mode.
endef

ifeq ($(ARCH),arm)
TUNSAFE_EXTRA_FILES+= \
	crypto/chacha20/chacha20-arm-linux.S \
	crypto/poly1305/poly1305-arm-linux.S
else ifeq ($(ARCH),aarch64)
TUNSAFE_EXTRA_FILES+= \
	crypto/chacha20/chacha20-arm64-linux.S \
	crypto/poly1305/poly1305-arm64-linux.S
else ifeq ($(ARCH),x86_64)
TUNSAFE_EXTRA_FILES+= \
	crypto/aesgcm/aesni_gcm-x64-linux.s \
	crypto/aesgcm/aesni-x64-linux.s \
	crypto/aesgcm/ghash-x64-linux.s \
	crypto/poly1305/poly1305-x64-linux.s \
	crypto/chacha20/chacha20-x64-linux.s
else
# 32 位 MIPS 的汇编路径当前未在 chacha20poly1305.cpp 中启用，
# 其他架构也没有对应汇编，统一走可移植的 C 实现。
TUNSAFE_EXTRA_CFLAGS+=-DCHACHA20_WITH_ASM=0 -DBLAKE2S_WITH_ASM=0
endif

ifneq ($(findstring xarmv5,x$(BOARD)),)
TUNSAFE_REQUIRES_LIBATOMIC:=1
endif

ifeq ($(ARCH),i386)
TUNSAFE_REQUIRES_LIBATOMIC:=1
endif

ifeq ($(ARCH),mips)
TUNSAFE_REQUIRES_LIBATOMIC:=1
endif

ifeq ($(ARCH),mipsel)
TUNSAFE_REQUIRES_LIBATOMIC:=1
endif

ifdef TUNSAFE_REQUIRES_LIBATOMIC
TUNSAFE_EXTRA_LDFLAGS+=-latomic
endif

define Build/Compile
	cd $(PKG_BUILD_DIR) && $(TARGET_CXX) -I. -DNDEBUG -DWITH_NETWORK_BSD=1 -DWITH_MBEDTLS=1 \
	    $(TUNSAFE_EXTRA_CFLAGS) $(TARGET_CPPFLAGS) -pthread -lrt -std=c++11 \
	    $(TUNSAFE_EXTRA_LDFLAGS) $(TARGET_LDFLAGS) $(TUNSAFE_EXTRA_FILES) \
	    tunsafe_amalgam.cpp -o tunsafe -lmbedtls -lmbedx509 -lmbedcrypto;
endef

define Package/tunsafe/conffiles
/etc/tunsafe/tunsafe.conf
endef

define Package/tunsafe/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/tunsafe $(1)/usr/sbin
	$(INSTALL_DIR) $(1)/etc/tunsafe
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/installer/TunSafe.conf \
		$(1)/etc/tunsafe/tunsafe.conf
endef

$(eval $(call BuildPackage,tunsafe))

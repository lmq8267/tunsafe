PROJECT=tunsafe

CROSS_PREFIX :=
CXX=$(CROSS_PREFIX)g++
STRIP=$(CROSS_PREFIX)strip
MBEDTLS_DIR = third_party/mbedtls
MBEDTLS_LIBS = $(MBEDTLS_DIR)/library/libmbedtls.a \
               $(MBEDTLS_DIR)/library/libmbedx509.a \
               $(MBEDTLS_DIR)/library/libmbedcrypto.a
MBEDTLS_CONFIG_FLAGS =
MBEDTLS_BUILD_CFLAGS = -Os -ffunction-sections -fdata-sections
MBEDTLS_STAMP = $(MBEDTLS_DIR)/library/.tunsafe_config
CCFLAGS = -O3 -DNDEBUG -I . -I$(MBEDTLS_DIR)/include $(MBEDTLS_CONFIG_FLAGS) $(CFLAGS) -DWITH_NETWORK_BSD=1 -DWITH_MBEDTLS=1 -std=c++11
LLDFLAGS = $(LDFLAGS) $(MBEDTLS_LIBS)

TARGET ?= Linux
ifeq ($(TARGET), Linux)
    CCFLAGS += -ffunction-sections -fdata-sections
    LLDFLAGS += -Wl,--gc-sections -lrt -pthread -latomic
else ifeq ($(TARGET), FreeBSD)
    CCFLAGS += -mssse3
    LLDFLAGS += -lrt -pthread
else ifeq ($(TARGET), Darwin)
    CCFLAGS += -Wno-deprecated-declarations -fno-exceptions -fno-rtti -ffunction-sections
    LLDFLAGS += 
else ifeq ($(TARGET), Windows)
    CCFLAGS += 
    LLDFLAGS += 
else
    $(error 未知的系统: $(TARGET))
endif
	
# 默认使用当前最常见的 x86_64 目标，避免直接 make 时进入“未知架构”。
ARCH ?= x86

BUILDMSG="\e[1;31mBUILD\e[0m %s\n"
LINKMSG="\e[1;34mLINK\e[0m  \e[1;32m%s\e[0m\n"
STRIPMSG="\e[1;34mSTRIP\e[0m \e[1;32m%s\e[0m\n"
CLEANMSG="\e[1;34mCLEAN\e[0m %s\n"

ENABLE_STATIC :=
ifeq ($(ENABLE_STATIC),1)
	CCFLAGS+=-static
endif

V :=
ECHO_PREFIX := @
ifeq ($(V),1)
	undefine ECHO_PREFIX
endif

all: tunsafe

$(MBEDTLS_STAMP): $(MBEDTLS_DIR)/include/mbedtls/mbedtls_config.h
	rm -f $(MBEDTLS_DIR)/library/*.o $(MBEDTLS_DIR)/library/*.a
	$(ECHO_PREFIX) $(MAKE) -C $(MBEDTLS_DIR) lib CFLAGS="$(MBEDTLS_BUILD_CFLAGS)"
	touch $@

tunsafe: clean $(MBEDTLS_STAMP)
	@printf $(BUILDMSG) tunsafe
	$(ECHO_PREFIX) $(MAKE) -C $(MBEDTLS_DIR) lib CFLAGS="$(MBEDTLS_BUILD_CFLAGS)"
	$(ECHO_PREFIX) if [ "$(TARGET)" != "Linux" ]; then \
		echo "当前 Makefile 只支持 TARGET=Linux，请使用 build_osx.sh / build_freebsd.sh"; \
		exit 1; \
	fi
	$(ECHO_PREFIX) if [ "$(TARGET)" = "Linux" ]; then \
		if [ "$(ARCH)" = "x86" ]; then \
			$(CXX) $(CCFLAGS) -o tunsafe tunsafe_amalgam.cpp $(LLDFLAGS) crypto/aesgcm/aesni_gcm-x64-linux.s crypto/aesgcm/aesni-x64-linux.s crypto/aesgcm/ghash-x64-linux.s crypto/poly1305/poly1305-x64-linux.s crypto/chacha20/chacha20-x64-linux.s ; \
		elif [ "$(ARCH)" = "arm" ]; then \
			$(CXX) $(CCFLAGS) -o tunsafe tunsafe_amalgam.cpp $(LLDFLAGS) crypto/poly1305/poly1305-arm-linux.S crypto/chacha20/chacha20-arm-linux.S ; \
		elif [ "$(ARCH)" = "arm64" ]; then \
			$(CXX) $(CCFLAGS) -o tunsafe tunsafe_amalgam.cpp $(LLDFLAGS) crypto/poly1305/poly1305-arm64-linux.S crypto/chacha20/chacha20-arm64-linux.S ; \
		elif [ "$(ARCH)" = "mips" ]; then \
			$(CXX) $(CCFLAGS) -march=mips32r2 -o tunsafe tunsafe_amalgam.cpp $(LLDFLAGS) crypto/poly1305/poly1305-mips32.S crypto/chacha20/chacha20-mips.S ; \
		else \
			echo "未知的CPU架构: $(ARCH)" ; \
			exit 1 ; \
		fi ; \
	fi
	@printf $(STRIPMSG) tunsafe
	$(ECHO_PREFIX) $(STRIP) tunsafe
	$(ECHO_PREFIX) file tunsafe
clean:
	$(ECHO_PREFIX) rm -f tunsafe *.o
	@printf $(CLEANMSG) $(PROJECT)


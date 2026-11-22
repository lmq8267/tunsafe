make -C third_party/mbedtls lib CFLAGS="-Os -ffunction-sections -fdata-sections"
g++7 -I . -Ithird_party/mbedtls/include -O2 -DNDEBUG -DWITH_NETWORK_BSD=1 -DWITH_MBEDTLS=1 -ffunction-sections -fdata-sections -Wl,--gc-sections -static -mssse3 -o tunsafe \
tunsafe_amalgam.cpp \
third_party/mbedtls/library/libmbedtls.a \
third_party/mbedtls/library/libmbedx509.a \
third_party/mbedtls/library/libmbedcrypto.a \
crypto/chacha20/chacha20-x64-linux.s \
crypto/poly1305/poly1305-x64-linux.s \
-lrt -pthread

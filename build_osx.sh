set -e

clang++ -c -mavx512f -mavx512vl crypto/poly1305/poly1305-x64-osx.s crypto/chacha20/chacha20-x64-osx.s 

make -C third_party/mbedtls lib CFLAGS="-Os -ffunction-sections -fdata-sections"
clang++ -g -O3 -I . -Ithird_party/mbedtls/include -std=c++11 -DWITH_NETWORK_BSD=1 -DWITH_MBEDTLS=1 -DNDEBUG=1 -Wno-deprecated-declarations -fno-exceptions -fno-rtti -ffunction-sections -fdata-sections -Wl,-dead_strip -o tunsafe \
tunsafe_amalgam.cpp \
third_party/mbedtls/library/libmbedtls.a \
third_party/mbedtls/library/libmbedx509.a \
third_party/mbedtls/library/libmbedcrypto.a \
crypto/aesgcm/aesni_gcm-x64-osx.s \
crypto/aesgcm/aesni-x64-osx.s \
crypto/aesgcm/ghash-x64-osx.s \
chacha20-x64-osx.o \
poly1305-x64-osx.o

cp tunsafe tunsafe.unstripped
strip tunsafe
rm -f tunsafe_osx.zip
zip tunsafe_osx.zip tunsafe readme_osx.txt


#!/bin/sh
set -e

#RELARGS="-O3 -DNDEBUG"
#DBGARGS="-g -D_DEBUG"
#CURARGS="$RELARGS -L/lib/x86_64-linux-gnu"
rm -f tunsafe *.o
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/lib/x86_64-linux-gnu
#g++ -c -march=skylake-avx512 crypto/poly1305/poly1305-x64-linux.s crypto/chacha20/chacha20-x64-linux.s
#g++ -I . $CURARGS -DWITH_NETWORK_BSD=1 -mssse3 -pthread -lrt -o tunsafe \
#tunsafe_amalgam.cpp \
#crypto/aesgcm/aesni_gcm-x64-linux.s \
#crypto/aesgcm/aesni-x64-linux.s \
#crypto/aesgcm/ghash-x64-linux.s \
#chacha20-x64-linux.o \
#poly1305-x64-linux.o \

CXXFLAGS="-I . -Ithird_party/mbedtls/include -O2 -DNDEBUG -DWITH_NETWORK_BSD=1 -DWITH_MBEDTLS=1 -std=c++11 -ffunction-sections -fdata-sections"
LDFLAGS=" -Wl,--gc-sections -static -lrt -lpthread -Wl,-Bstatic -latomic third_party/mbedtls/library/libmbedtls.a third_party/mbedtls/library/libmbedx509.a third_party/mbedtls/library/libmbedcrypto.a"
CXX=g++
make -C third_party/mbedtls lib CFLAGS="-Os -ffunction-sections -fdata-sections"
#$CXX -c crypto/poly1305/poly1305-x64-linux.s crypto/chacha20/chacha20-x64-linux.s
$CXX $CXXFLAGS -c tunsafe_amalgam.cpp 
$CXX -o tunsafe tunsafe_amalgam.o $LDFLAGS crypto/aesgcm/aesni_gcm-x64-linux.s crypto/aesgcm/aesni-x64-linux.s crypto/aesgcm/ghash-x64-linux.s crypto/poly1305/poly1305-x64-linux.s crypto/chacha20/chacha20-x64-linux.s 

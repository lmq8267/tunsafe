// SPDX-License-Identifier: AGPL-1.0-only
// Copyright (C) 2018 Ludvig Strigeus <info@tunsafe.com>. All Rights Reserved.
#include "stdafx.h"
#include "tunsafe_cpu.h"
#include "tunsafe_types.h"

#if defined(COMPILER_MSVC)
#include <intrin.h>
#endif

#include <string.h>

// 32 位 ARM Linux/Android 需要读取内核 HWCAP 判断是否支持 NEON，不能因为编译时链接了 NEON 汇编就假设 CPU 一定支持。
#if (defined(OS_LINUX) || defined(OS_ANDROID)) && !defined(ARCH_CPU_ARM64)
#include <sys/auxv.h>
#endif

static char *strcpy_e(char *dst, char *end, const char *copy) {
  size_t len = strlen(copy);
  if (len >= (size_t)(end - dst)) return end;
  memcpy(dst, copy, len + 1);
  return dst + len;
}


#if defined(ARCH_CPU_X86_FAMILY)

uint32 x86_pcap[3];

#if !defined(COMPILER_MSVC)
static inline void __cpuid(int info[4], int func) {
  __asm__ __volatile__(
    "cpuid"
    : "=a"(info[0]), "=b"(info[1]), "=c"(info[2]), "=d"(info[3])
    : "a"(func), "c"(0)
  );
}
#endif


void InitCpuFeatures() {
  unsigned nIds, nExIds;

  {
    int info[4];
    __cpuid(info, 0);
    nIds = info[0];
    __cpuid(info, 0x80000000);
    nExIds = info[0];
  }
  if (nIds >= 0x00000001) {
    int info[4];
    __cpuid(info, 0x00000001);
    x86_pcap[0] = info[3];
    x86_pcap[1] = info[2];
  }
  if (nIds >= 0x00000007) {
    int info[4];
    __cpuid(info, 0x00000007);
    x86_pcap[2] = info[1];
  }
}

void PrintCpuFeatures() {
  char capbuf[2048], *end = capbuf + 2048, *s = capbuf;

  if (X86_PCAP_AVX) s = strcpy_e(s, end, " avx");
  if (X86_PCAP_SSSE3) s = strcpy_e(s, end, " ssse3");
  if (X86_PCAP_AVX2) s = strcpy_e(s, end, " avx2");
  if (X86_PCAP_MOVBE) s = strcpy_e(s, end, " movbe");
  if (X86_PCAP_AES) s = strcpy_e(s, end, " aes");
  if (X86_PCAP_PCLMULQDQ) s = strcpy_e(s, end, " pclmuldqd");
  if (X86_PCAP_AVX512F) s = strcpy_e(s, end, " avx512f");
  if (X86_PCAP_AVX512VL) s = strcpy_e(s, end, " avx512vl");

  RINFO("\n\033[1;31m使用： \033[0m %s", capbuf);
}

#elif defined(ARCH_CPU_ARM_FAMILY)  // defined(ARCH_CPU_X86_FAMILY)

uint32 arm_pcap[1];

void InitCpuFeatures() {
#if defined(ARCH_CPU_ARM64)
  // AArch64 强制包含 NEON/ASIMD，不存在无 NEON 的 AArch64 CPU。
  arm_pcap[0] = 0xffffffff;
#elif defined(OS_LINUX) || defined(OS_ANDROID)
#if defined(OS_ANDROID) && defined(__ANDROID_API__) && __ANDROID_API__ < 18
  // 旧 Android NDK 没有 getauxval，无法安全检测，禁用 NEON 走通用实现。
  arm_pcap[0] = 0;
#else
  // ARM 32 位 Linux 的 HWCAP_NEON 是 bit 12。
  unsigned long hwcap = getauxval(AT_HWCAP);
  arm_pcap[0] = (hwcap & (1UL << 12)) ? 0xffffffff : 0;
#endif
#else
  // iOS/macOS 的 ARM 设备均支持 NEON。
  arm_pcap[0] = 0xffffffff;
#endif
}

void PrintCpuFeatures() {
  char capbuf[2048], *end = capbuf + 2048, *s = capbuf;

  if (ARM_PCAP_NEON) s = strcpy_e(s, end, " neon");

  RINFO("\n\033[1;31m使用： \033[0m %s", capbuf);
}
#else  // defined(ARCH_CPU_ARM_FAMILY)

void InitCpuFeatures() { }

void PrintCpuFeatures() {
  RINFO("\n\033[1;31m使用： \033[0m generic");
}

#endif  // else

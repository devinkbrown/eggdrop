/*
 * opssl/crypto/cpuid.c — runtime CPU feature detection.
 *
 * Detects hardware crypto capabilities at runtime. Even if the compiler
 * supports -maes/-mpclmul, the running CPU may lack the feature.
 * Set once at opssl_init(), read-only thereafter (no atomics needed).
 *
 * x86-64: CPUID + XCR0
 * aarch64: getauxval(AT_HWCAP)
 *
 * Copyright (C) 2026 ophion development team
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <opssl/platform.h>
#include <stdint.h>
#include <stdbool.h>

#if defined(__x86_64__) || defined(_M_X64)
#include <cpuid.h>
#include <immintrin.h>
#elif defined(__aarch64__)
#include <sys/auxv.h>
#include <asm/hwcap.h>
#endif

struct opssl_cpu_features {
    bool aesni;
    bool pclmul;
    bool avx2;
    bool sha_ni;
    bool sse41;
    bool bmi2;
    bool adx;
    bool arm_aes;
    bool arm_sha2;
    bool arm_sha3;
    bool arm_pmull;
};

static struct opssl_cpu_features cpu_features;

#if defined(__x86_64__) || defined(_M_X64)

static inline void
cpuid(uint32_t leaf, uint32_t sub, uint32_t *eax, uint32_t *ebx,
      uint32_t *ecx, uint32_t *edx)
{
    __cpuid_count(leaf, sub, *eax, *ebx, *ecx, *edx);
}

static bool
xsave_enabled(void)
{
    uint32_t eax, ebx, ecx, edx;
    cpuid(1, 0, &eax, &ebx, &ecx, &edx);
    if (!(ecx & (1u << 27)))
        return false;
    uint64_t xcr0 = _xgetbv(0);
    return (xcr0 & 0x6) == 0x6;
}

static void
detect_x86(void)
{
    uint32_t eax, ebx, ecx, edx;
    uint32_t max_leaf;

    cpuid(0, 0, &max_leaf, &ebx, &ecx, &edx);
    if (max_leaf < 1)
        return;

    cpuid(1, 0, &eax, &ebx, &ecx, &edx);

    cpu_features.aesni  = (ecx >> 25) & 1;
    cpu_features.pclmul = (ecx >> 1) & 1;
    cpu_features.sse41  = (ecx >> 19) & 1;

    bool have_xsave = xsave_enabled();

    if (max_leaf >= 7) {
        cpuid(7, 0, &eax, &ebx, &ecx, &edx);
        cpu_features.avx2  = have_xsave && ((ebx >> 5) & 1);
        cpu_features.bmi2  = (ebx >> 8) & 1;
        cpu_features.adx   = (ebx >> 19) & 1;
        cpu_features.sha_ni = (ebx >> 29) & 1;
    }
}

#elif defined(__aarch64__)

static void
detect_arm(void)
{
    unsigned long hwcap = getauxval(AT_HWCAP);

    cpu_features.arm_aes   = !!(hwcap & HWCAP_AES);
    cpu_features.arm_sha2  = !!(hwcap & HWCAP_SHA2);
    cpu_features.arm_pmull = !!(hwcap & HWCAP_PMULL);

#ifdef HWCAP_SHA3
    cpu_features.arm_sha3 = !!(hwcap & HWCAP_SHA3);
#endif
}

#endif

void
opssl_cpu_detect(void)
{
#if defined(__x86_64__) || defined(_M_X64)
    detect_x86();
#elif defined(__aarch64__)
    detect_arm();
#endif
}

bool opssl_has_aesni(void)  { return cpu_features.aesni; }
bool opssl_has_pclmul(void) { return cpu_features.pclmul; }
bool opssl_has_avx2(void)   { return cpu_features.avx2; }
bool opssl_has_sha_ni(void) { return cpu_features.sha_ni; }
bool opssl_has_sse41(void)  { return cpu_features.sse41; }
bool opssl_has_bmi2(void)   { return cpu_features.bmi2; }
bool opssl_has_adx(void)    { return cpu_features.adx; }

bool opssl_has_arm_aes(void)   { return cpu_features.arm_aes; }
bool opssl_has_arm_sha2(void)  { return cpu_features.arm_sha2; }
bool opssl_has_arm_sha3(void)  { return cpu_features.arm_sha3; }
bool opssl_has_arm_pmull(void) { return cpu_features.arm_pmull; }

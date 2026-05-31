/*
 * opssl/crypto/cpuid.c — runtime CPU feature detection.
 *
 * Detects hardware crypto capabilities at runtime.  Even if the compiler
 * supports -maes/-mpclmul, the running CPU may lack the feature.  Detection
 * is performed at most once; the resulting struct is read-only thereafter,
 * so no atomics or locks are required.
 *
 * x86-64 : CPUID + XGETBV (XSAVE) for AVX state
 * aarch64: getauxval(AT_HWCAP / AT_HWCAP2)
 *
 * Copyright (C) 2026 ophion development team
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <opssl/platform.h>
#include <stdint.h>
#include <stdbool.h>

#if defined(__x86_64__) || defined(_M_X64)
# include <cpuid.h>
# include <immintrin.h>
#elif defined(__aarch64__)
# include <sys/auxv.h>
# if __has_include(<asm/hwcap.h>)
#  include <asm/hwcap.h>
# endif
#endif

struct opssl_cpu_features {
    bool initialised;
    /* x86 */
    bool aesni;
    bool pclmul;
    bool avx2;
    bool avx512f;
    bool avx512vl;
    bool avx512bw;
    bool avx512dq;
    bool sha_ni;
    bool sse41;
    bool bmi2;
    bool adx;
    /* arm */
    bool arm_aes;
    bool arm_sha1;
    bool arm_sha2;
    bool arm_sha3;
    bool arm_pmull;
};

static struct opssl_cpu_features cpu_features;

#if defined(__x86_64__) || defined(_M_X64)

static inline void
cpuid_count(uint32_t leaf, uint32_t sub,
            uint32_t *eax, uint32_t *ebx, uint32_t *ecx, uint32_t *edx)
{
    __cpuid_count(leaf, sub, *eax, *ebx, *ecx, *edx);
}

/*
 * xsave_state — returns the XCR0 register if OS-managed XSAVE is enabled,
 * or 0 if XSAVE/OSXSAVE is unavailable (callers must then treat all
 * vector-state-dependent features as absent).
 */
static uint64_t
xsave_state(void)
{
    uint32_t eax, ebx, ecx, edx;
    cpuid_count(1, 0, &eax, &ebx, &ecx, &edx);

    const uint32_t XSAVE_BIT  = 1u << 26;
    const uint32_t OSXSAVE_BIT = 1u << 27;
    if ((ecx & (XSAVE_BIT | OSXSAVE_BIT)) != (XSAVE_BIT | OSXSAVE_BIT))
        return 0;

    return (uint64_t)_xgetbv(0);
}

static void
detect_x86(void)
{
    uint32_t eax, ebx, ecx, edx;
    uint32_t max_leaf;

    cpuid_count(0, 0, &max_leaf, &ebx, &ecx, &edx);
    if (max_leaf < 1)
        return;

    cpuid_count(1, 0, &eax, &ebx, &ecx, &edx);

    cpu_features.aesni  = !!((ecx >> 25) & 1u);
    cpu_features.pclmul = !!((ecx >>  1) & 1u);
    cpu_features.sse41  = !!((ecx >> 19) & 1u);

    /*
     * AVX/AVX2/AVX-512 require OS-managed XSAVE state.
     *   bit 1 (SSE)      : XMM
     *   bit 2 (AVX)      : YMM
     *   bits 5-7 (AVX-512): opmask + ZMM_Hi256 + Hi16_ZMM
     */
    const uint64_t xcr0 = xsave_state();
    const bool ymm_ok  = (xcr0 & 0x6) == 0x6;
    const bool zmm_ok  = (xcr0 & 0xE6) == 0xE6;

    if (max_leaf >= 7) {
        cpuid_count(7, 0, &eax, &ebx, &ecx, &edx);

        cpu_features.bmi2     = !!((ebx >>  8) & 1u);
        cpu_features.adx      = !!((ebx >> 19) & 1u);
        cpu_features.sha_ni   = !!((ebx >> 29) & 1u);
        cpu_features.avx2     = ymm_ok && ((ebx >>  5) & 1u);
        cpu_features.avx512f  = zmm_ok && ((ebx >> 16) & 1u);
        cpu_features.avx512dq = zmm_ok && ((ebx >> 17) & 1u);
        cpu_features.avx512bw = zmm_ok && ((ebx >> 30) & 1u);
        cpu_features.avx512vl = zmm_ok && ((ebx >> 31) & 1u);
    }
}

#elif defined(__aarch64__)

/* Some headers omit individual HWCAP_* constants on older toolchains.
 * Provide the canonical Linux values as fallbacks. */
# ifndef HWCAP_AES
#  define HWCAP_AES   (1u << 3)
# endif
# ifndef HWCAP_PMULL
#  define HWCAP_PMULL (1u << 4)
# endif
# ifndef HWCAP_SHA1
#  define HWCAP_SHA1  (1u << 5)
# endif
# ifndef HWCAP_SHA2
#  define HWCAP_SHA2  (1u << 6)
# endif

static void
detect_arm(void)
{
    unsigned long hwcap = getauxval(AT_HWCAP);

    cpu_features.arm_aes   = !!(hwcap & HWCAP_AES);
    cpu_features.arm_pmull = !!(hwcap & HWCAP_PMULL);
    cpu_features.arm_sha1  = !!(hwcap & HWCAP_SHA1);
    cpu_features.arm_sha2  = !!(hwcap & HWCAP_SHA2);

# ifdef HWCAP_SHA3
    cpu_features.arm_sha3  = !!(hwcap & HWCAP_SHA3);
# endif
}

#endif

void
opssl_cpu_detect(void)
{
    if (cpu_features.initialised)
        return;

#if defined(__x86_64__) || defined(_M_X64)
    detect_x86();
#elif defined(__aarch64__)
    detect_arm();
#endif

    cpu_features.initialised = true;
}

/* Ensure the feature struct is populated even if a caller forgets to call
 * opssl_cpu_detect() explicitly.  First query triggers detection. */
static inline void
ensure_detected(void)
{
    if (!cpu_features.initialised)
        opssl_cpu_detect();
}

bool opssl_has_aesni(void)    { ensure_detected(); return cpu_features.aesni; }
bool opssl_has_pclmul(void)   { ensure_detected(); return cpu_features.pclmul; }
bool opssl_has_avx2(void)     { ensure_detected(); return cpu_features.avx2; }
bool opssl_has_avx512f(void)  { ensure_detected(); return cpu_features.avx512f; }
bool opssl_has_avx512vl(void) { ensure_detected(); return cpu_features.avx512vl; }
bool opssl_has_avx512bw(void) { ensure_detected(); return cpu_features.avx512bw; }
bool opssl_has_avx512dq(void) { ensure_detected(); return cpu_features.avx512dq; }
bool opssl_has_sha_ni(void)   { ensure_detected(); return cpu_features.sha_ni; }
bool opssl_has_sse41(void)    { ensure_detected(); return cpu_features.sse41; }
bool opssl_has_bmi2(void)     { ensure_detected(); return cpu_features.bmi2; }
bool opssl_has_adx(void)      { ensure_detected(); return cpu_features.adx; }

bool opssl_has_arm_aes(void)   { ensure_detected(); return cpu_features.arm_aes; }
bool opssl_has_arm_sha1(void)  { ensure_detected(); return cpu_features.arm_sha1; }
bool opssl_has_arm_sha2(void)  { ensure_detected(); return cpu_features.arm_sha2; }
bool opssl_has_arm_sha3(void)  { ensure_detected(); return cpu_features.arm_sha3; }
bool opssl_has_arm_pmull(void) { ensure_detected(); return cpu_features.arm_pmull; }

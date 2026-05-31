/*
 * opssl/crypto/constant_time.c — constant-time operations.
 *
 * These routines must NEVER be optimised into branching code; any branch
 * predicated on secret data leaks information through timing.  We use a
 * combination of `volatile` qualifiers on pointers/accumulators and inline
 * assembly memory barriers to prevent the compiler from:
 *   - hoisting loads out of the loop,
 *   - replacing the loop with a branch-based memcmp,
 *   - short-circuiting the accumulator on a non-zero byte,
 *   - dead-store-eliminating writes to dst.
 *
 * Used for MAC verification, padding checks, key comparison.
 *
 * Copyright (C) 2026 ophion development team
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <opssl/platform.h>
#include <string.h>

/*
 * opssl_ct_barrier — compiler memory barrier.
 * Forces the compiler to commit pending stores and re-read memory; cheaper
 * than asm volatile("" ::: "memory") because no clobber list is needed.
 */
#define opssl_ct_barrier()  __asm__ __volatile__("" ::: "memory")

/*
 * opssl_ct_eq — byte-buffer constant-time equality.
 *
 * Return value: 1 if the buffers are equal, 0 otherwise.
 *
 * Implementation note: `diff` is a volatile uint8_t accumulator.  After
 * the loop it is non-zero iff any byte differed.  We convert that to a
 * 0/1 result via ((diff - 1) >> 8) & 1 — when diff == 0 the subtraction
 * underflows to (int)-1 which shifts to all-ones; otherwise the value is
 * non-negative and shifts to zero.  No branch on secret data.
 */
int
opssl_ct_eq(const void *a, const void *b, size_t len)
{
    const volatile uint8_t *x = (const volatile uint8_t *)a;
    const volatile uint8_t *y = (const volatile uint8_t *)b;
    volatile uint8_t diff = 0;

    for (size_t i = 0; i < len; i++)
        diff |= (uint8_t)(x[i] ^ y[i]);

    opssl_ct_barrier();

    /* Promote through unsigned int so the shift behaviour is well-defined. */
    unsigned int d = diff;
    return (int)((d - 1u) >> 8) & 1;
}

/*
 * opssl_ct_is_zero — byte-buffer constant-time all-zeros test.
 *
 * Return value: 1 if every byte in buf[0..len-1] is zero, 0 otherwise.
 */
int
opssl_ct_is_zero(const void *buf, size_t len)
{
    const volatile uint8_t *p = (const volatile uint8_t *)buf;
    volatile uint8_t acc = 0;

    for (size_t i = 0; i < len; i++)
        acc |= p[i];

    opssl_ct_barrier();

    unsigned int a = acc;
    return (int)((a - 1u) >> 8) & 1;
}

/*
 * opssl_ct_word_is_zero — single 64-bit word constant-time zero test.
 *
 * Uses only arithmetic and bitwise ops; no branches.  Suitable for use
 * inside bignum / field-arithmetic routines where the byte-buffer variant
 * would be unnecessarily heavy.
 *
 * Return value: 1 if x == 0, 0 otherwise.
 *
 * Method: (x | -x) has bit 63 set for every non-zero x and is 0 only for
 * x == 0.  We use unsigned two's-complement negation to avoid relying on
 * implementation-defined signed overflow.
 */
int
opssl_ct_word_is_zero(uint64_t x)
{
    volatile uint64_t v = x;
    uint64_t neg = (uint64_t)0 - v;     /* well-defined unsigned wrap */
    uint64_t bit = (v | neg) >> 63;     /* 1 if v != 0, else 0 */
    opssl_ct_barrier();
    return (int)(bit ^ 1u);
}

/*
 * opssl_ct_mask — branchless all-ones / all-zeros mask from a boolean.
 *
 * Returns (uint64_t)-1 when condition != 0, otherwise 0.
 *
 *   result = (opssl_ct_mask(cond) & a) | (opssl_ct_mask(!cond) & b);
 *
 * Method: normalise condition to {0,1} via `!!`, then negate as unsigned
 * (0 → 0, 1 → all-ones).  The double-negation lowers to a branch-free
 * setne/cmov on every supported target.
 */
uint64_t
opssl_ct_mask(int condition)
{
    volatile uint64_t bit = (uint64_t)(!!(unsigned int)condition);
    uint64_t mask = (uint64_t)0 - bit;
    opssl_ct_barrier();
    return mask;
}

/*
 * opssl_ct_select — constant-time byte-buffer conditional copy.
 *
 * Writes a[0..len-1] to dst when select_a != 0, b[0..len-1] otherwise.
 * Both source pointers must remain valid for the full length regardless
 * of selection; both buffers are always touched.
 */
void
opssl_ct_select(void *dst, const void *a, const void *b,
                size_t len, int select_a)
{
    const volatile uint8_t *pa = (const volatile uint8_t *)a;
    const volatile uint8_t *pb = (const volatile uint8_t *)b;
    volatile uint8_t       *pd = (volatile uint8_t *)dst;

    /* mask = 0xFF if select_a is set, else 0x00. */
    volatile uint8_t mask = (uint8_t)(0u - (unsigned int)(!!select_a));

    for (size_t i = 0; i < len; i++) {
        uint8_t va = pa[i];
        uint8_t vb = pb[i];
        pd[i] = (uint8_t)((va & mask) | (vb & (uint8_t)~mask));
    }

    opssl_ct_barrier();
}

/*
 * opssl_ct_min — branchless size_t minimum.
 *
 * The arithmetic sign-propagation trick requires the signed type whose
 * width matches size_t (ptrdiff_t), NOT a fixed-width int64_t.  On a
 * 32-bit target size_t is 32 bits; casting diff to int64_t would extend
 * 0xFFFFFFFF to a positive value, producing the wrong mask.  ptrdiff_t
 * matches size_t width on every conforming platform.
 */
size_t
opssl_ct_min(size_t a, size_t b)
{
    size_t diff = a - b;                                       /* wraps on underflow */
    size_t mask = (size_t)((ptrdiff_t)diff >>                  /* arithmetic shift  */
                           (sizeof(size_t) * 8 - 1));          /* fills with borrow */
    return b + (diff & mask);                                  /* b if a>=b, a if a<b */
}

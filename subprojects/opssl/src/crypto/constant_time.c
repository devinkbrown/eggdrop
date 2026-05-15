/*
 * opssl/crypto/constant_time.c — constant-time operations.
 *
 * These must NEVER be optimized into branching code.
 * Used for MAC verification, padding checks, key comparison.
 *
 * Copyright (C) 2026 ophion development team
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <opssl/platform.h>
#include <string.h>

/*
 * opssl_ct_eq — byte-buffer constant-time equality.
 *
 * All three pointers are volatile so the compiler cannot eliminate any
 * load, hoist a read outside the loop, or replace the loop with a
 * branch-based memcmp.  The accumulator is volatile to prevent the
 * compiler short-circuiting once a non-zero byte is found.
 *
 * Return value: 1 if the buffers are equal, 0 otherwise.
 */
int
opssl_ct_eq(const void *a, const void *b, size_t len)
{
    const volatile uint8_t *x = a;
    const volatile uint8_t *y = b;
    volatile uint8_t diff = 0;

    for (size_t i = 0; i < len; i++)
        diff |= x[i] ^ y[i];

    return (1 & ((diff - 1) >> 8));
}

/*
 * opssl_ct_is_zero — byte-buffer constant-time all-zeros test.
 *
 * Return value: 1 if every byte in buf[0..len-1] is zero, 0 otherwise.
 */
int
opssl_ct_is_zero(const void *buf, size_t len)
{
    const volatile uint8_t *p = buf;
    volatile uint8_t acc = 0;

    for (size_t i = 0; i < len; i++)
        acc |= p[i];

    return (1 & ((acc - 1) >> 8));
}

/*
 * opssl_ct_word_is_zero — single 64-bit word constant-time zero test.
 *
 * Uses only arithmetic and bitwise ops; no branches.  Suitable for use
 * inside bignum / field-arithmetic routines where the byte-buffer
 * variant would be unnecessarily heavy.
 *
 * Return value: 1 if x == 0, 0 otherwise.
 */
int
opssl_ct_word_is_zero(uint64_t x)
{
    /*
     * If x != 0 then at least one bit is set.  (x | -x) therefore has
     * bit 63 set for any non-zero x, and is 0 for x == 0.
     * Shifting right 63 extracts that flag, then XOR 1 inverts it.
     */
    return (int)(1 ^ ((x | (uint64_t)(-(int64_t)x)) >> 63));
}

/*
 * opssl_ct_mask — branchless all-ones / all-zeros mask from a boolean.
 *
 * Returns (uint64_t)-1  (all bits set)  when condition != 0.
 * Returns (uint64_t)0   (all bits clear) when condition == 0.
 *
 * Callers use this to build constant-time conditional assignments:
 *   result = (opssl_ct_mask(cond) & a) | (opssl_ct_mask(!cond) & b);
 */
uint64_t
opssl_ct_mask(int condition)
{
    /*
     * Normalise condition to exactly 0 or 1 without a branch, then
     * negate: -(uint64_t)1 == 0xFFFFFFFFFFFFFFFF.
     *
     * The double-negation (!!) trick is defined by the C standard and
     * produces 0 or 1 without a conditional branch on all common targets
     * because compilers lower it to a setne/cmovne or equivalent.
     */
    return (uint64_t)(-(uint64_t)(!!(unsigned int)condition));
}

/*
 * opssl_ct_select — constant-time byte-buffer conditional copy.
 *
 * Writes a[0..len-1] to dst when select_a != 0, b[0..len-1] otherwise.
 * All three data pointers are volatile to prevent the compiler from
 * dead-store-eliminating the dst writes or hoisting the src reads.
 * The mask is volatile for the same reason.
 */
void
opssl_ct_select(void *dst, const void *a, const void *b, size_t len, int select_a)
{
    const volatile uint8_t *pa = a;
    const volatile uint8_t *pb = b;
    volatile uint8_t *pd = dst;

    /* mask is 0xFF if select_a is set, 0x00 otherwise — no branch */
    volatile uint8_t mask = (uint8_t)(-(select_a & 1));

    for (size_t i = 0; i < len; i++)
        pd[i] = (pa[i] & mask) | (pb[i] & ~mask);
}

/*
 * opssl_ct_min — branchless size_t minimum.
 *
 * The arithmetic sign-propagation trick requires that we use the signed
 * type whose width exactly matches size_t (ptrdiff_t), NOT a fixed-width
 * int64_t.  On a 32-bit target size_t is 32 bits; casting diff to int64_t
 * would extend 0xFFFFFFFF to a positive value, producing a wrong mask.
 * ptrdiff_t is defined to match size_t width on every conforming platform.
 */
size_t
opssl_ct_min(size_t a, size_t b)
{
    size_t diff = a - b;                                    /* wraps on underflow */
    size_t mask = (size_t)((ptrdiff_t)diff >>               /* arithmetic shift   */
                           (sizeof(size_t) * 8 - 1));      /* fills with borrow  */
    return b + (diff & mask);                               /* b if a>=b, a if a<b */
}

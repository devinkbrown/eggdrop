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
 * Volatile qualifier prevents the compiler from optimizing away
 * the loop or replacing it with a branch-based memcmp.
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

int
opssl_ct_is_zero(const void *buf, size_t len)
{
    const volatile uint8_t *p = buf;
    volatile uint8_t acc = 0;

    for (size_t i = 0; i < len; i++)
        acc |= p[i];

    return (1 & ((acc - 1) >> 8));
}

void
opssl_ct_select(void *dst, const void *a, const void *b, size_t len, int select_a)
{
    const uint8_t *pa = a;
    const uint8_t *pb = b;
    uint8_t *pd = dst;

    /* mask is all-ones if select_a, all-zeros otherwise */
    volatile uint8_t mask = (uint8_t)(-(select_a & 1));

    for (size_t i = 0; i < len; i++)
        pd[i] = (pa[i] & mask) | (pb[i] & ~mask);
}

size_t
opssl_ct_min(size_t a, size_t b)
{
    /* branchless min */
    size_t diff = a - b;
    size_t mask = (size_t)((int64_t)diff >> 63);
    return b + (diff & mask);
}

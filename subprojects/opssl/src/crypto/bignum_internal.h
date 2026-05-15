/*
 * bignum_internal.h — internal bignum types for opssl.
 *
 * Shared between bignum.c and rsa.c. Not part of the public API.
 *
 * Copyright (C) 2026 ophion development team
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef OPSSL_BIGNUM_INTERNAL_H
#define OPSSL_BIGNUM_INTERNAL_H

#include <stdint.h>
#include <stddef.h>

#define OPSSL_BN_MAX_LIMBS 64  /* supports up to 4096-bit */

typedef struct {
    uint64_t d[OPSSL_BN_MAX_LIMBS];
    int width;  /* number of active limbs — public, never shrinks */
} opssl_bn_t;

typedef struct {
    opssl_bn_t n;       /* modulus */
    opssl_bn_t r_squared; /* R^2 mod n, precomputed for to_mont */
    uint64_t   n0_inv;  /* -n^(-1) mod 2^64 (Montgomery constant) */
    int        width;
} opssl_bn_mont_ctx_t;

/* Function declarations (implemented in bignum.c) */
void opssl_bn_zero(opssl_bn_t *bn, int width);
void opssl_bn_from_bytes(opssl_bn_t *bn, const uint8_t *buf, size_t len);
void opssl_bn_to_bytes(uint8_t *buf, size_t len, const opssl_bn_t *bn);
void opssl_bn_mont_ctx_init(opssl_bn_mont_ctx_t *ctx, const opssl_bn_t *modulus, int width);
void opssl_bn_mont_mul(opssl_bn_t *r, const opssl_bn_t *a, const opssl_bn_t *b, const opssl_bn_mont_ctx_t *mont);
void opssl_bn_mont_sqr(opssl_bn_t *r, const opssl_bn_t *a, const opssl_bn_mont_ctx_t *mont);
void opssl_bn_to_mont(opssl_bn_t *r, const opssl_bn_t *a, const opssl_bn_mont_ctx_t *mont);
void opssl_bn_from_mont(opssl_bn_t *r, const opssl_bn_t *a, const opssl_bn_mont_ctx_t *mont);
void opssl_bn_mod_mul(opssl_bn_t *r, const opssl_bn_t *a, const opssl_bn_t *b, const opssl_bn_mont_ctx_t *mont);
void opssl_bn_mod_exp_ct(opssl_bn_t *r, const opssl_bn_t *base, const opssl_bn_t *exp,
                         int exp_width, const opssl_bn_mont_ctx_t *mont);
uint64_t opssl_bn_add(opssl_bn_t *r, const opssl_bn_t *a, const opssl_bn_t *b, int width);
uint64_t opssl_bn_sub(opssl_bn_t *r, const opssl_bn_t *a, const opssl_bn_t *b, int width);
int opssl_bn_cmp(const opssl_bn_t *a, const opssl_bn_t *b, int width);
void opssl_bn_ct_select(opssl_bn_t *r, const opssl_bn_t *a, const opssl_bn_t *b, int width, uint64_t sel);
void opssl_bn_copy(opssl_bn_t *dst, const opssl_bn_t *src, int width);
uint64_t opssl_bn_reduce_once(opssl_bn_t *r, const opssl_bn_t *n, int width);
int opssl_bn_mod_inv(opssl_bn_t *r, const opssl_bn_t *a, const opssl_bn_t *prime,
                     const opssl_bn_mont_ctx_t *mont);

#endif /* OPSSL_BIGNUM_INTERNAL_H */

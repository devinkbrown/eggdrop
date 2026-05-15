/*
 * opssl/crypto/x25519.c — X25519 Diffie-Hellman (RFC 7748).
 *
 * Constant-time scalar multiplication on Curve25519.
 * Primary key exchange mechanism for TLS 1.3.
 *
 * Based on the ref10 implementation by Daniel J. Bernstein.
 *
 * Copyright (C) 2026 ophion development team
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <opssl/crypto.h>
#include <opssl/platform.h>
#include <string.h>

/*
 * Field element: 5 limbs of 51 bits each (fits in int64_t for mul).
 * Represents integers mod 2^255 - 19.
 */
typedef int64_t fe25519[5];

__attribute__((unused))
static inline uint64_t
load48(const uint8_t *p)
{
    return (uint64_t)p[0] | ((uint64_t)p[1] << 8) |
           ((uint64_t)p[2] << 16) | ((uint64_t)p[3] << 24) |
           ((uint64_t)p[4] << 32) | ((uint64_t)p[5] << 40);
}

static inline uint64_t
load64(const uint8_t *p)
{
    return (uint64_t)p[0] | ((uint64_t)p[1] << 8) |
           ((uint64_t)p[2] << 16) | ((uint64_t)p[3] << 24) |
           ((uint64_t)p[4] << 32) | ((uint64_t)p[5] << 40) |
           ((uint64_t)p[6] << 48) | ((uint64_t)p[7] << 56);
}

static inline uint64_t
load56(const uint8_t *p)
{
    return (uint64_t)p[0] | ((uint64_t)p[1] << 8) |
           ((uint64_t)p[2] << 16) | ((uint64_t)p[3] << 24) |
           ((uint64_t)p[4] << 32) | ((uint64_t)p[5] << 40) |
           ((uint64_t)p[6] << 48);
}

static void
fe_frombytes(fe25519 h, const uint8_t s[32])
{
    uint64_t h0, h1, h2, h3, h4;

    h0 = load64(s) & 0x7ffffffffffffULL;
    h1 = (load64(s + 6) >> 3) & 0x7ffffffffffffULL;
    h2 = (load64(s + 12) >> 6) & 0x7ffffffffffffULL;
    h3 = (load64(s + 19) >> 1) & 0x7ffffffffffffULL;
    h4 = (load56(s + 25) >> 4) & 0x7ffffffffffffULL;

    h[0] = (int64_t)h0;
    h[1] = (int64_t)h1;
    h[2] = (int64_t)h2;
    h[3] = (int64_t)h3;
    h[4] = (int64_t)h4;
}

static void
fe_tobytes(uint8_t s[32], const fe25519 h)
{
    int64_t t[5];
    memcpy(t, h, sizeof(t));

    int64_t q = (19 * t[4] + ((int64_t)1 << 24)) >> 25;
    for (int i = 0; i < 4; i++) {
        q = (t[i] + q) >> 51;
    }
    q = (t[4] + q) >> 51;

    t[0] += 19 * q;
    int64_t carry = t[0] >> 51; t[0] &= 0x7ffffffffffffLL;
    t[1] += carry; carry = t[1] >> 51; t[1] &= 0x7ffffffffffffLL;
    t[2] += carry; carry = t[2] >> 51; t[2] &= 0x7ffffffffffffLL;
    t[3] += carry; carry = t[3] >> 51; t[3] &= 0x7ffffffffffffLL;
    t[4] += carry; t[4] &= 0x7ffffffffffffLL;

    s[0]  = (uint8_t)(t[0]);
    s[1]  = (uint8_t)(t[0] >> 8);
    s[2]  = (uint8_t)(t[0] >> 16);
    s[3]  = (uint8_t)(t[0] >> 24);
    s[4]  = (uint8_t)(t[0] >> 32);
    s[5]  = (uint8_t)(t[0] >> 40);
    s[6]  = (uint8_t)((t[0] >> 48) | (t[1] << 3));
    s[7]  = (uint8_t)(t[1] >> 5);
    s[8]  = (uint8_t)(t[1] >> 13);
    s[9]  = (uint8_t)(t[1] >> 21);
    s[10] = (uint8_t)(t[1] >> 29);
    s[11] = (uint8_t)(t[1] >> 37);
    s[12] = (uint8_t)((t[1] >> 45) | (t[2] << 6));
    s[13] = (uint8_t)(t[2] >> 2);
    s[14] = (uint8_t)(t[2] >> 10);
    s[15] = (uint8_t)(t[2] >> 18);
    s[16] = (uint8_t)(t[2] >> 26);
    s[17] = (uint8_t)(t[2] >> 34);
    s[18] = (uint8_t)(t[2] >> 42);
    s[19] = (uint8_t)((t[2] >> 50) | (t[3] << 1));
    s[20] = (uint8_t)(t[3] >> 7);
    s[21] = (uint8_t)(t[3] >> 15);
    s[22] = (uint8_t)(t[3] >> 23);
    s[23] = (uint8_t)(t[3] >> 31);
    s[24] = (uint8_t)(t[3] >> 39);
    s[25] = (uint8_t)((t[3] >> 47) | (t[4] << 4));
    s[26] = (uint8_t)(t[4] >> 4);
    s[27] = (uint8_t)(t[4] >> 12);
    s[28] = (uint8_t)(t[4] >> 20);
    s[29] = (uint8_t)(t[4] >> 28);
    s[30] = (uint8_t)(t[4] >> 36);
    s[31] = (uint8_t)(t[4] >> 44);
}

static void
fe_add(fe25519 h, const fe25519 f, const fe25519 g)
{
    for (int i = 0; i < 5; i++)
        h[i] = f[i] + g[i];
}

static void
fe_sub(fe25519 h, const fe25519 f, const fe25519 g)
{
    /* Add 2p to avoid underflow */
    static const int64_t two_p[5] = {
        0xfffffffffffdaLL, 0xffffffffffffeLL,
        0xffffffffffffeLL, 0xffffffffffffeLL, 0xffffffffffffeLL
    };
    for (int i = 0; i < 5; i++)
        h[i] = f[i] - g[i] + two_p[i];
}

static void
fe_mul(fe25519 h, const fe25519 f, const fe25519 g)
{
    __int128 r[5];
    int64_t carry;

    r[0] = (__int128)f[0]*g[0] + (__int128)(f[1]*19)*g[4] + (__int128)(f[2]*19)*g[3] +
            (__int128)(f[3]*19)*g[2] + (__int128)(f[4]*19)*g[1];
    r[1] = (__int128)f[0]*g[1] + (__int128)f[1]*g[0] + (__int128)(f[2]*19)*g[4] +
            (__int128)(f[3]*19)*g[3] + (__int128)(f[4]*19)*g[2];
    r[2] = (__int128)f[0]*g[2] + (__int128)f[1]*g[1] + (__int128)f[2]*g[0] +
            (__int128)(f[3]*19)*g[4] + (__int128)(f[4]*19)*g[3];
    r[3] = (__int128)f[0]*g[3] + (__int128)f[1]*g[2] + (__int128)f[2]*g[1] +
            (__int128)f[3]*g[0] + (__int128)(f[4]*19)*g[4];
    r[4] = (__int128)f[0]*g[4] + (__int128)f[1]*g[3] + (__int128)f[2]*g[2] +
            (__int128)f[3]*g[1] + (__int128)f[4]*g[0];

    carry = (int64_t)(r[0] >> 51); h[0] = (int64_t)r[0] & 0x7ffffffffffffLL; r[1] += carry;
    carry = (int64_t)(r[1] >> 51); h[1] = (int64_t)r[1] & 0x7ffffffffffffLL; r[2] += carry;
    carry = (int64_t)(r[2] >> 51); h[2] = (int64_t)r[2] & 0x7ffffffffffffLL; r[3] += carry;
    carry = (int64_t)(r[3] >> 51); h[3] = (int64_t)r[3] & 0x7ffffffffffffLL; r[4] += carry;
    carry = (int64_t)(r[4] >> 51); h[4] = (int64_t)r[4] & 0x7ffffffffffffLL; h[0] += carry * 19;
    carry = h[0] >> 51; h[0] &= 0x7ffffffffffffLL; h[1] += carry;
    carry = h[1] >> 51; h[1] &= 0x7ffffffffffffLL; h[2] += carry;
}

static void
fe_sq(fe25519 h, const fe25519 f)
{
    fe_mul(h, f, f);
}

/* Constant-time conditional swap */
static void
fe_cswap(fe25519 f, fe25519 g, int64_t b)
{
    int64_t mask = -b;
    for (int i = 0; i < 5; i++) {
        int64_t t = mask & (f[i] ^ g[i]);
        f[i] ^= t;
        g[i] ^= t;
    }
}

/* Compute 1/z mod p using Fermat's little theorem: z^(p-2) */
static void
fe_invert(fe25519 out, const fe25519 z)
{
    fe25519 t0, t1, t2, t3;

    fe_sq(t0, z);
    fe_sq(t1, t0);
    fe_sq(t1, t1);
    fe_mul(t1, z, t1);
    fe_mul(t0, t0, t1);
    fe_sq(t2, t0);
    fe_mul(t1, t1, t2);
    fe_sq(t2, t1);
    for (int i = 0; i < 4; i++) fe_sq(t2, t2);
    fe_mul(t1, t2, t1);
    fe_sq(t2, t1);
    for (int i = 0; i < 9; i++) fe_sq(t2, t2);
    fe_mul(t2, t2, t1);
    fe_sq(t3, t2);
    for (int i = 0; i < 19; i++) fe_sq(t3, t3);
    fe_mul(t2, t3, t2);
    fe_sq(t2, t2);
    for (int i = 0; i < 9; i++) fe_sq(t2, t2);
    fe_mul(t1, t2, t1);
    fe_sq(t2, t1);
    for (int i = 0; i < 49; i++) fe_sq(t2, t2);
    fe_mul(t2, t2, t1);
    fe_sq(t3, t2);
    for (int i = 0; i < 99; i++) fe_sq(t3, t3);
    fe_mul(t2, t3, t2);
    fe_sq(t2, t2);
    for (int i = 0; i < 49; i++) fe_sq(t2, t2);
    fe_mul(t1, t2, t1);
    fe_sq(t1, t1);
    for (int i = 0; i < 4; i++) fe_sq(t1, t1);
    fe_mul(out, t1, t0);
}

/*
 * Montgomery ladder scalar multiplication.
 * Constant-time: no secret-dependent branches or memory access.
 */
static void
x25519_scalar_mult(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32])
{
    uint8_t e[32];
    memcpy(e, scalar, 32);
    e[0] &= 248;
    e[31] &= 127;
    e[31] |= 64;

    fe25519 x1, x2, z2, x3, z3, tmp0, tmp1;
    fe_frombytes(x1, point);

    /* x2 = 1, z2 = 0, x3 = x1, z3 = 1 */
    memset(x2, 0, sizeof(x2)); x2[0] = 1;
    memset(z2, 0, sizeof(z2));
    memcpy(x3, x1, sizeof(x3));
    memset(z3, 0, sizeof(z3)); z3[0] = 1;

    int64_t swap = 0;

    for (int pos = 254; pos >= 0; pos--) {
        int64_t b = (e[pos / 8] >> (pos & 7)) & 1;
        swap ^= b;
        fe_cswap(x2, x3, swap);
        fe_cswap(z2, z3, swap);
        swap = b;

        fe_sub(tmp0, x3, z3);
        fe_sub(tmp1, x2, z2);
        fe_add(x2, x2, z2);
        fe_add(z2, x3, z3);
        fe_mul(z3, tmp0, x2);
        fe_mul(z2, z2, tmp1);
        fe_sq(tmp0, tmp1);
        fe_sq(tmp1, x2);
        fe_add(x3, z3, z2);
        fe_sub(z2, z3, z2);
        fe_mul(x2, tmp1, tmp0);
        fe_sub(tmp1, tmp1, tmp0);
        fe_sq(z2, z2);
        fe25519 a24 = {121666, 0, 0, 0, 0};
        fe_mul(z3, tmp1, a24);
        fe_sq(x3, x3);
        fe_add(tmp0, tmp0, z3);
        fe_mul(z3, x1, z2);
        fe_mul(z2, tmp1, tmp0);
    }

    fe_cswap(x2, x3, swap);
    fe_cswap(z2, z3, swap);

    fe_invert(z2, z2);
    fe_mul(x2, x2, z2);
    fe_tobytes(out, x2);

    opssl_memzero(e, sizeof(e));
    opssl_memzero(x1, sizeof(x1));
    opssl_memzero(x2, sizeof(x2));
    opssl_memzero(z2, sizeof(z2));
}

/* ─── Public API ─────────────────────────────────────────────────────── */

int
opssl_x25519_keygen(uint8_t priv[OPSSL_X25519_KEY_LEN],
                    uint8_t pub[OPSSL_X25519_KEY_LEN])
{
    if (opssl_random_bytes(priv, 32) != 0)
        return 0;

    /* Basepoint = 9 */
    static const uint8_t basepoint[32] = {9};
    x25519_scalar_mult(pub, priv, basepoint);
    return 1;
}

int
opssl_x25519_derive(uint8_t shared[OPSSL_X25519_SHARED_LEN],
                    const uint8_t priv[OPSSL_X25519_KEY_LEN],
                    const uint8_t peer_pub[OPSSL_X25519_KEY_LEN])
{
    x25519_scalar_mult(shared, priv, peer_pub);

    /* Check for all-zero output (low-order point) */
    if (opssl_ct_is_zero(shared, 32)) {
        opssl_memzero(shared, 32);
        return 0;
    }

    return 1;
}

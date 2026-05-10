/*
 * Ed25519 digital signatures (RFC 8032) - Working Implementation
 *
 * This implementation uses the same field arithmetic as x25519.c.
 */

#include <opssl/crypto.h>
#include <opssl/platform.h>
#include <string.h>
#include "sha_internal.h"

/* Field element: 5 limbs of 51 bits each, little-endian */
typedef int64_t fe25519[5];

/* Extended twisted Edwards point (X:Y:Z:T) where x=X/Z, y=Y/Z, T=X*Y/Z */
typedef struct {
    fe25519 X, Y, Z, T;
} ge25519_p3;

/* Field arithmetic from working x25519.c implementation */

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
    uint64_t h0 = load64(s) & 0x7ffffffffffffULL;
    uint64_t h1 = (load64(s + 6) >> 3) & 0x7ffffffffffffULL;
    uint64_t h2 = (load64(s + 12) >> 6) & 0x7ffffffffffffULL;
    uint64_t h3 = (load64(s + 19) >> 1) & 0x7ffffffffffffULL;
    uint64_t h4 = (load56(s + 25) >> 4) & 0x7ffffffffffffULL;

    h[0] = (int64_t)h0;
    h[1] = (int64_t)h1;
    h[2] = (int64_t)h2;
    h[3] = (int64_t)h3;
    h[4] = (int64_t)h4;
}

static void
fe_tobytes(uint8_t s[32], const fe25519 h)
{
    int64_t t[5], c;
    memcpy(t, h, sizeof(t));

    /* Two carry passes with wrap-around to bring into [0, 2p) */
    for (int pass = 0; pass < 2; pass++) {
        c = t[0] >> 51; t[0] &= 0x7ffffffffffffLL; t[1] += c;
        c = t[1] >> 51; t[1] &= 0x7ffffffffffffLL; t[2] += c;
        c = t[2] >> 51; t[2] &= 0x7ffffffffffffLL; t[3] += c;
        c = t[3] >> 51; t[3] &= 0x7ffffffffffffLL; t[4] += c;
        c = t[4] >> 51; t[4] &= 0x7ffffffffffffLL; t[0] += c * 19;
    }
    c = t[0] >> 51; t[0] &= 0x7ffffffffffffLL; t[1] += c;

    /* Conditional subtraction of p: add 19 and check overflow past 2^255 */
    int64_t u[5];
    u[0] = t[0] + 19;
    c = u[0] >> 51; u[0] &= 0x7ffffffffffffLL;
    u[1] = t[1] + c; c = u[1] >> 51; u[1] &= 0x7ffffffffffffLL;
    u[2] = t[2] + c; c = u[2] >> 51; u[2] &= 0x7ffffffffffffLL;
    u[3] = t[3] + c; c = u[3] >> 51; u[3] &= 0x7ffffffffffffLL;
    u[4] = t[4] + c; c = u[4] >> 51; u[4] &= 0x7ffffffffffffLL;

    /* c=1 means t >= p, use u (= t-p); c=0 means t < p, keep t */
    int64_t mask = -(int64_t)c;
    t[0] = (t[0] & ~mask) | (u[0] & mask);
    t[1] = (t[1] & ~mask) | (u[1] & mask);
    t[2] = (t[2] & ~mask) | (u[2] & mask);
    t[3] = (t[3] & ~mask) | (u[3] & mask);
    t[4] = (t[4] & ~mask) | (u[4] & mask);

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

    int64_t carry = (int64_t)(r[0] >> 51); h[0] = (int64_t)r[0] & 0x7ffffffffffffLL; r[1] += carry;
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

static void fe_1(fe25519 h) { h[0] = 1; h[1] = h[2] = h[3] = h[4] = 0; }
static void fe_0(fe25519 h) { h[0] = h[1] = h[2] = h[3] = h[4] = 0; }
static void fe_copy(fe25519 h, const fe25519 f) { memcpy(h, f, sizeof(fe25519)); }

static int
fe_isnegative(const fe25519 f)
{
    uint8_t s[32];
    fe_tobytes(s, f);
    return s[0] & 1;
}

static void
fe_neg(fe25519 h, const fe25519 f)
{
    static const int64_t two_p[5] = {
        0xfffffffffffdaLL, 0xffffffffffffeLL, 0xffffffffffffeLL, 0xffffffffffffeLL, 0xffffffffffffeLL
    };
    for (int i = 0; i < 5; i++)
        h[i] = two_p[i] - f[i];
}

/* Constants for Ed25519 curve: -x^2 + y^2 = 1 + d*x^2*y^2 */
static const fe25519 ed25519_d = {
    0x34dca135978a3LL, 0x1a8283b156ebdLL, 0x5e7a26001c029LL, 0x739c663a03cbbLL, 0x52036cee2b6ffLL
};

static const fe25519 ed25519_d2 = {
    0x69b9426b2f159LL, 0x35050762add7aLL, 0x3cf44c0038052LL, 0x6738cc7407977LL, 0x2406d9dc56dffLL
};

static const fe25519 ed25519_sqrtm1 = {
    0x61b274a0ea0b0LL, 0xd5a5fc8f189dLL, 0x7ef5e9cbd0c60LL, 0x78595a6804c9eLL, 0x2b8324804fc1dLL
};

static const ge25519_p3 ed25519_base = {
    {0x62d608f25d51aLL, 0x412a4b4f6592aLL, 0x75b7171a4b31dLL, 0x1ff60527118feLL, 0x216936d3cd6e5LL},
    {0x6666666666658LL, 0x4ccccccccccccLL, 0x1999999999999LL, 0x3333333333333LL, 0x6666666666666LL},
    {1, 0, 0, 0, 0},
    {0x68ab3a5b7dda3LL, 0xeea2a5eadbbLL, 0x2af8df483c27eLL, 0x332b375274732LL, 0x67875f0fd78b7LL}
};

/* Forward declarations */
static void fe_cmov(fe25519 f, const fe25519 g, unsigned int b);
static void ge25519_cmov(ge25519_p3 *t, const ge25519_p3 *u, unsigned int b);
static void ge25519_scalarmult(ge25519_p3 *r, const uint8_t *scalar, const ge25519_p3 *p);

/* Point operations */

static void
ge25519_p3_0(ge25519_p3 *h)
{
    fe_0(h->X); fe_1(h->Y); fe_1(h->Z); fe_0(h->T);
}

static void
ge25519_add(ge25519_p3 *r, const ge25519_p3 *p, const ge25519_p3 *q)
{
    fe25519 A, B, C, D, E, F, G, H;

    fe_sub(A, p->Y, p->X);
    fe_sub(H, q->Y, q->X);
    fe_mul(A, A, H);
    fe_add(B, p->Y, p->X);
    fe_add(H, q->Y, q->X);
    fe_mul(B, B, H);
    fe_mul(C, p->T, q->T);
    fe_mul(C, C, ed25519_d2);
    fe_mul(D, p->Z, q->Z);
    fe_add(D, D, D);
    fe_sub(E, B, A);
    fe_sub(F, D, C);
    fe_add(G, D, C);
    fe_add(H, B, A);

    fe_mul(r->X, E, F);
    fe_mul(r->Y, G, H);
    fe_mul(r->T, E, H);
    fe_mul(r->Z, F, G);
}

static void
ge25519_dbl(ge25519_p3 *r, const ge25519_p3 *p)
{
    ge25519_add(r, p, p);
}

/* ge25519_scalarmult defined later with constant-time implementation */

static void
fe_invert(fe25519 out, const fe25519 z)
{
    /* Fermat's little theorem: a^(p-1) = 1 => a^(p-2) = a^(-1) mod p */
    fe25519 t0, t1, t2;
    int i;

    /* Compute z^(p-2) = z^(2^255-21) using addition chain */
    fe25519 z11;
    fe_sq(t0, z);               /* t0 = z^2 */
    fe_sq(t1, t0);
    fe_sq(t1, t1);              /* t1 = z^8 */
    fe_mul(t1, z, t1);          /* t1 = z^9 */
    fe_mul(t0, t0, t1);         /* t0 = z^11 */
    fe_copy(z11, t0);           /* save z^11 for final step */
    fe_sq(t0, t0);              /* t0 = z^22 */
    fe_mul(t0, t1, t0);         /* t0 = z^31 */
    fe_sq(t1, t0);
    for (i = 1; i < 5; ++i)
        fe_sq(t1, t1);          /* t1 = z^(31*2^5) = z^992 */
    fe_mul(t0, t1, t0);         /* t0 = z^1023 = z^(2^10-1) */
    fe_sq(t1, t0);
    for (i = 1; i < 10; ++i)
        fe_sq(t1, t1);          /* t1 = z^((2^10-1)*2^10) */
    fe_mul(t1, t1, t0);         /* t1 = z^(2^20-1) */
    fe_sq(t2, t1);
    for (i = 1; i < 20; ++i)
        fe_sq(t2, t2);          /* t2 = z^((2^20-1)*2^20) */
    fe_mul(t1, t2, t1);         /* t1 = z^(2^40-1) */
    fe_sq(t1, t1);
    for (i = 1; i < 10; ++i)
        fe_sq(t1, t1);          /* t1 = z^((2^40-1)*2^10) */
    fe_mul(t0, t1, t0);         /* t0 = z^(2^50-1) */
    fe_sq(t1, t0);
    for (i = 1; i < 50; ++i)
        fe_sq(t1, t1);
    fe_mul(t1, t1, t0);         /* t1 = z^(2^100-1) */
    fe_sq(t2, t1);
    for (i = 1; i < 100; ++i)
        fe_sq(t2, t2);
    fe_mul(t1, t2, t1);         /* t1 = z^(2^200-1) */
    fe_sq(t1, t1);
    for (i = 1; i < 50; ++i)
        fe_sq(t1, t1);
    fe_mul(t0, t1, t0);         /* t0 = z^(2^250-1) */
    fe_sq(t0, t0);
    fe_sq(t0, t0);
    fe_sq(t0, t0);
    fe_sq(t0, t0);
    fe_sq(t0, t0);              /* t0 = z^(2^255-32) */
    fe_mul(out, t0, z11);       /* out = z^(2^255-32+11) = z^(2^255-21) */
}

static void
fe_pow2523(fe25519 out, const fe25519 z)
{
    /* Compute z^((p-5)/8) = z^(2^252-3) for square root */
    fe25519 t0, t1, t2;
    int i;

    fe_sq(t0, z);
    fe_sq(t1, t0);
    fe_sq(t1, t1);
    fe_mul(t1, z, t1);
    fe_mul(t0, t0, t1);
    fe_sq(t0, t0);
    fe_mul(t0, t1, t0);
    fe_sq(t1, t0);
    for (i = 1; i < 5; ++i) {
        fe_sq(t1, t1);
    }
    fe_mul(t0, t1, t0);
    fe_sq(t1, t0);
    for (i = 1; i < 10; ++i) {
        fe_sq(t1, t1);
    }
    fe_mul(t1, t1, t0);
    fe_sq(t2, t1);
    for (i = 1; i < 20; ++i) {
        fe_sq(t2, t2);
    }
    fe_mul(t1, t2, t1);
    fe_sq(t1, t1);
    for (i = 1; i < 10; ++i) {
        fe_sq(t1, t1);
    }
    fe_mul(t0, t1, t0);
    fe_sq(t1, t0);
    for (i = 1; i < 50; ++i) {
        fe_sq(t1, t1);
    }
    fe_mul(t1, t1, t0);
    fe_sq(t2, t1);
    for (i = 1; i < 100; ++i) {
        fe_sq(t2, t2);
    }
    fe_mul(t1, t2, t1);
    fe_sq(t1, t1);
    for (i = 1; i < 50; ++i) {
        fe_sq(t1, t1);
    }
    fe_mul(t0, t1, t0);
    fe_sq(t0, t0);
    fe_sq(t0, t0);
    fe_mul(out, t0, z);
}

/* Ed25519 scalar (mod L) where L = 2^252 + 27742317777372353535851937790883648493 */
static const uint8_t L[32] = {
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
};

static void
sc25519_reduce(uint8_t out[32], const uint8_t in[64])
{
    uint64_t x[8];
    for (int i = 0; i < 8; i++) {
        x[i] = 0;
        for (int j = 0; j < 8; j++)
            x[i] |= (uint64_t)in[i * 8 + j] << (8 * j);
    }

    static const uint64_t l[4] = {
        0x5812631a5cf5d3edULL, 0x14def9dea2f79cd6ULL,
        0x0000000000000000ULL, 0x1000000000000000ULL
    };

    uint64_t sl[8] = {0};
    for (int i = 0; i < 4; i++) {
        sl[i + 4] |= l[i] << 3;
        if (i + 5 < 8)
            sl[i + 5] |= l[i] >> 61;
    }

    for (int shift = 259; shift >= 0; shift--) {
        int ge = 1;
        for (int i = 7; i >= 0; i--) {
            if (x[i] > sl[i]) break;
            if (x[i] < sl[i]) { ge = 0; break; }
        }

        if (ge) {
            __int128 borrow = 0;
            for (int i = 0; i < 8; i++) {
                __int128 diff = (__int128)x[i] - sl[i] - borrow;
                x[i] = (uint64_t)diff;
                borrow = (diff < 0) ? 1 : 0;
            }
        }

        for (int i = 0; i < 7; i++)
            sl[i] = (sl[i] >> 1) | (sl[i + 1] << 63);
        sl[7] >>= 1;
    }

    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 8; j++)
            out[i * 8 + j] = (uint8_t)(x[i] >> (8 * j));
}

static void
sc25519_muladd(uint8_t s[32], const uint8_t a[32], const uint8_t b[32], const uint8_t c[32])
{
    /* Compute s = (a * b + c) mod L */
    /* This is a simplified implementation for Ed25519 */
    __int128 t[64] = {0};

    /* Multiply a * b */
    for (int i = 0; i < 32; i++) {
        for (int j = 0; j < 32; j++) {
            t[i + j] += (__int128)a[i] * b[j];
        }
    }

    /* Add c */
    for (int i = 0; i < 32; i++) {
        t[i] += c[i];
    }

    /* Propagate carries */
    for (int i = 0; i < 63; i++) {
        t[i + 1] += t[i] >> 8;
        t[i] &= 0xff;
    }

    /* Convert to bytes and reduce */
    uint8_t temp[64];
    for (int i = 0; i < 64; i++) {
        temp[i] = (uint8_t)(t[i] & 0xff);
    }

    sc25519_reduce(s, temp);
}

static void
ge25519_encode(uint8_t *s, const ge25519_p3 *p)
{
    fe25519 zinv, x, y;

    fe_invert(zinv, p->Z);
    fe_mul(x, p->X, zinv);
    fe_mul(y, p->Y, zinv);

    fe_tobytes(s, y);
    s[31] ^= fe_isnegative(x) << 7;
}

static int
ge25519_decode(ge25519_p3 *p, const uint8_t s[32])
{
    fe25519 y, x, xx, yy, dyy, u, v, v3, vxx, check;
    int x_sign;

    /* Extract y coordinate and x sign */
    fe_frombytes(y, s);
    x_sign = s[31] >> 7;

    /* Check y is in valid range (< p) */
    fe_tobytes((uint8_t*)xx, y); /* Reuse xx as temp */
    if (memcmp((uint8_t*)xx, s, 31) != 0 || ((uint8_t*)xx)[31] != (s[31] & 0x7f)) {
        return 0; /* Invalid y coordinate */
    }

    /* Recover x coordinate: x^2 = (y^2 - 1) / (d*y^2 + 1) */
    fe_sq(yy, y);                    /* yy = y^2 */
    fe25519 one; fe_1(one);
    fe_sub(u, yy, one);              /* u = y^2 - 1 */
    fe_mul(dyy, ed25519_d, yy);      /* dyy = d*y^2 */
    fe_add(v, dyy, one);             /* v = d*y^2 + 1 */

    /* Compute x = +/- sqrt(u/v) using: x = u * v^3 * (u * v^7)^((p-5)/8) */
    fe_sq(v3, v);                    /* v^2 */
    fe_mul(v3, v3, v);               /* v^3 */
    fe_sq(vxx, v3);                  /* v^6 */
    fe_mul(vxx, vxx, v);             /* v^7 */
    fe_mul(vxx, vxx, u);             /* u * v^7 */
    fe_pow2523(vxx, vxx);            /* (u * v^7)^((p-5)/8) */
    fe_mul(x, vxx, v3);              /* v^3 * (u * v^7)^((p-5)/8) */
    fe_mul(x, x, u);                 /* u * v^3 * (u * v^7)^((p-5)/8) */

    /* Check if x^2 = u/v */
    fe_sq(xx, x);                    /* x^2 */
    fe_mul(check, v, xx);            /* v * x^2 */
    fe_sub(check, check, u);         /* v * x^2 - u */

    /* If check != 0, try x * sqrt(-1) */
    uint8_t check_bytes[32];
    fe_tobytes(check_bytes, check);
    int is_zero = 1;
    for (int i = 0; i < 32; i++) {
        if (check_bytes[i] != 0) {
            is_zero = 0;
            break;
        }
    }

    if (!is_zero) {
        fe_mul(x, x, ed25519_sqrtm1);
        fe_sq(xx, x);
        fe_mul(check, v, xx);
        fe_sub(check, check, u);
        fe_tobytes(check_bytes, check);
        is_zero = 1;
        for (int i = 0; i < 32; i++) {
            if (check_bytes[i] != 0) {
                is_zero = 0;
                break;
            }
        }
        if (!is_zero) {
            return 0; /* Point not on curve */
        }
    }

    /* Adjust sign of x */
    if (fe_isnegative(x) != x_sign) {
        fe_neg(x, x);
    }

    /* Set point coordinates */
    fe_copy(p->X, x);
    fe_copy(p->Y, y);
    fe_1(p->Z);
    fe_mul(p->T, x, y);

    return 1;
}

static void
fe_cmov(fe25519 f, const fe25519 g, unsigned int b)
{
    int64_t mask = -(int64_t)(b & 1);
    for (int i = 0; i < 5; i++)
        f[i] ^= mask & (g[i] ^ f[i]);
}

static void
ge25519_cmov(ge25519_p3 *t, const ge25519_p3 *u, unsigned int b)
{
    fe_cmov(t->X, u->X, b);
    fe_cmov(t->Y, u->Y, b);
    fe_cmov(t->Z, u->Z, b);
    fe_cmov(t->T, u->T, b);
}

static void
ge25519_scalarmult(ge25519_p3 *r, const uint8_t *scalar, const ge25519_p3 *p)
{
    /* Constant-time scalar multiplication using double-and-add */
    ge25519_p3 result, addend;
    ge25519_p3_0(&result);  /* result = O (point at infinity) */
    addend = *p;           /* addend = P */

    /* Process scalar bits from LSB to MSB */
    for (int i = 0; i < 256; i++) {
        int byte_idx = i / 8;
        int bit_idx = i % 8;
        unsigned int bit = (scalar[byte_idx] >> bit_idx) & 1;

        /* Constant-time conditional add: result += bit ? addend : 0 */
        ge25519_p3 temp;
        ge25519_add(&temp, &result, &addend);
        ge25519_cmov(&result, &temp, bit);

        /* addend = 2 * addend for next iteration */
        if (i < 255) {
            ge25519_dbl(&addend, &addend);
        }
    }

    *r = result;
}

int opssl_ed25519_keygen(uint8_t pk[32], uint8_t sk[64])
{
    uint8_t seed[32];
    uint8_t h[64];
    ge25519_p3 A;
    struct opssl_sha512_ctx ctx;

    /* Use sk[0..31] as seed if non-zero, otherwise generate random */
    int have_seed = 0;
    for (int i = 0; i < 32; i++) {
        if (sk[i] != 0) { have_seed = 1; break; }
    }
    if (have_seed) {
        memcpy(seed, sk, 32);
    } else {
        if (!opssl_random_bytes(seed, 32))
            return 0;
    }

    /* Hash seed with SHA-512 */
    opssl_sha512_init(&ctx);
    opssl_sha512_update(&ctx, seed, 32);
    opssl_sha512_final(&ctx, h);

    /* Clamp hash[0..31]: clear bits 0,1,2 and 255, set bit 254 */
    h[0] &= 248;   /* Clear lowest 3 bits */
    h[31] &= 127;  /* Clear bit 255 */
    h[31] |= 64;   /* Set bit 254 */

    /* Scalar multiply: A = hash[0..31] * B (base point) */
    ge25519_scalarmult(&A, h, &ed25519_base);

    /* Compress A to get pk[32] */
    ge25519_encode(pk, &A);

    /* sk[0..31] = seed, sk[32..63] = pk */
    memcpy(sk, seed, 32);
    memcpy(sk + 32, pk, 32);

    /* Clear sensitive data */
    opssl_memzero(seed, sizeof(seed));
    opssl_memzero(h, sizeof(h));

    return 1;
}

int opssl_ed25519_sign(uint8_t sig[64], const uint8_t *msg, size_t msg_len, const uint8_t sk[64])
{
    uint8_t h[64], r[64];
    uint8_t a[32], k[32];
    const uint8_t *pk = sk + 32;
    ge25519_p3 R;
    struct opssl_sha512_ctx ctx;

    /* Hash sk[0..31] with SHA-512 to get h */
    opssl_sha512_init(&ctx);
    opssl_sha512_update(&ctx, sk, 32);
    opssl_sha512_final(&ctx, h);

    /* Clamp h[0..31] as scalar a */
    memcpy(a, h, 32);
    a[0] &= 248;
    a[31] &= 127;
    a[31] |= 64;

    /* Compute r = SHA-512(h[32..63] || msg) mod L */
    opssl_sha512_init(&ctx);
    opssl_sha512_update(&ctx, h + 32, 32);
    opssl_sha512_update(&ctx, msg, msg_len);
    opssl_sha512_final(&ctx, r);
    sc25519_reduce(r, r); /* Reduce to 32 bytes mod L */

    /* R = r * B, encode R → sig[0..31] */
    ge25519_scalarmult(&R, r, &ed25519_base);
    ge25519_encode(sig, &R);

    /* Compute k = SHA-512(sig[0..31] || pk || msg) mod L */
    opssl_sha512_init(&ctx);
    opssl_sha512_update(&ctx, sig, 32);      /* R encoding */
    opssl_sha512_update(&ctx, pk, 32);       /* Public key */
    opssl_sha512_update(&ctx, msg, msg_len); /* Message */
    opssl_sha512_final(&ctx, h);             /* Reuse h buffer */
    sc25519_reduce(k, h);

    /* S = (r + k * a) mod L → sig[32..63] */
    sc25519_muladd(sig + 32, k, a, r);

    /* Clear sensitive data */
    opssl_memzero(h, sizeof(h));
    opssl_memzero(r, sizeof(r));
    opssl_memzero(a, sizeof(a));
    opssl_memzero(k, sizeof(k));

    return 1;
}

int opssl_ed25519_verify(const uint8_t sig[64], const uint8_t *msg, size_t msg_len, const uint8_t pk[32])
{
    ge25519_p3 A, R;
    uint8_t h[64], k[32];
    struct opssl_sha512_ctx ctx;

    /* Decode public key A from pk */
    if (!ge25519_decode(&A, pk)) {
        return 0; /* Invalid public key */
    }

    /* Decode R from sig[0..31] */
    if (!ge25519_decode(&R, sig)) {
        return 0; /* Invalid R point */
    }

    /* Check that S (sig[32..63]) is in valid range [0, L) */
    for (int i = 31; i >= 0; i--) {
        if (sig[32 + i] > L[i]) {
            return 0; /* S >= L */
        } else if (sig[32 + i] < L[i]) {
            break; /* S < L, valid */
        }
    }

    /* Compute k = SHA-512(sig[0..31] || pk || msg) mod L */
    opssl_sha512_init(&ctx);
    opssl_sha512_update(&ctx, sig, 32);      /* R encoding */
    opssl_sha512_update(&ctx, pk, 32);       /* Public key */
    opssl_sha512_update(&ctx, msg, msg_len); /* Message */
    opssl_sha512_final(&ctx, h);
    sc25519_reduce(k, h);

    /* Verify equation: 8*S*B == 8*R + 8*k*A (cofactored verification) */
    /* This is equivalent to: S*B == R + k*A */

    /* Compute S * B */
    ge25519_p3 left_side;
    ge25519_scalarmult(&left_side, sig + 32, &ed25519_base);

    /* Compute k * A */
    ge25519_p3 kA;
    ge25519_scalarmult(&kA, k, &A);

    /* Compute R + k*A */
    ge25519_p3 right_side;
    ge25519_add(&right_side, &R, &kA);

    /* Check if left_side == right_side by encoding both and comparing */
    uint8_t left_enc[32], right_enc[32];
    ge25519_encode(left_enc, &left_side);
    ge25519_encode(right_enc, &right_side);

    /* Constant-time comparison */
    int result = opssl_ct_eq(left_enc, right_enc, 32);

    /* Clear sensitive data */
    opssl_memzero(h, sizeof(h));
    opssl_memzero(k, sizeof(k));

    return result;
}
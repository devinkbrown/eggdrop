/* P-256/P-384 ECC implementation with constant-time operations */

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"

#include <opssl/crypto.h>
#include <opssl/platform.h>
#include <op_memory.h>
#include <string.h>
#include <stdint.h>
#include "bignum_internal.h"


#define OPSSL_SUCCESS 0

/* Constant-time select: returns a if mask==~0, else b */
static inline uint64_t ecc_ct_select(uint64_t mask, uint64_t a, uint64_t b)
{
    return (a & mask) | (b & ~mask);
}

typedef uint64_t p256_fe_t[4];
typedef uint64_t p384_fe_t[6];
typedef uint64_t p521_fe_t[9];
typedef struct {
    p256_fe_t x, y, z;
} p256_point_t;

typedef struct {
    p384_fe_t x, y, z;
} p384_point_t;

typedef struct {
    p521_fe_t x, y, z;
} p521_point_t;

struct opssl_ecdh_ctx {
    opssl_curve_t curve;
    union {
        struct {
            p256_fe_t private_key;
            p256_point_t public_key;
        } p256;
        struct {
            p384_fe_t private_key;
            p384_point_t public_key;
        } p384;
        struct {
            p521_fe_t private_key;
            p521_point_t public_key;
        } p521;
    } key;
    int has_private;
    int has_public;
};

struct opssl_ecdsa_ctx {
    opssl_curve_t curve;
    union {
        struct {
            p256_fe_t private_key;
            p256_point_t public_key;
        } p256;
        struct {
            p384_fe_t private_key;
            p384_point_t public_key;
        } p384;
        struct {
            p521_fe_t private_key;
            p521_point_t public_key;
        } p521;
    } key;
    int has_private;
    int has_public;
};

static const p256_fe_t p256_p = {
    0xFFFFFFFFFFFFFFFFULL, 0x00000000FFFFFFFFULL,
    0x0000000000000000ULL, 0xFFFFFFFF00000001ULL
};

static const p256_fe_t p256_n = {
    0xF3B9CAC2FC632551ULL, 0xBCE6FAADA7179E84ULL,
    0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFF00000000ULL
};

static const p256_fe_t p256_r2 = {
    0x0000000000000003ULL, 0xFFFFFFFBFFFFFFFFULL,
    0xFFFFFFFFFFFFFFFEULL, 0x00000004FFFFFFFDULL
};

static const p256_point_t p256_g = {
    .x = {0x79E730D418A9143CULL, 0x75BA95FC5FEDB601ULL,
          0x79FB732B77622510ULL, 0x18905F76A53755C6ULL},
    .y = {0xDDF25357CE95560AULL, 0x8B4AB8E4BA19E45CULL,
          0xD2E88688DD21F325ULL, 0x8571FF1825885D85ULL},
    .z = {0x0000000000000001ULL, 0xFFFFFFFF00000000ULL,
          0xFFFFFFFFFFFFFFFFULL, 0x00000000FFFFFFFEULL}
};

static const p384_fe_t p384_p = {
    0x00000000FFFFFFFFULL, 0xFFFFFFFF00000000ULL, 0xFFFFFFFFFFFFFFFEULL,
    0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL
};

static const p384_fe_t p384_n = {
    0xECEC196ACCC52973ULL, 0x581A0DB248B0A77AULL, 0xC7634D81F4372DDFULL,
    0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL
};

static const p384_fe_t p384_r2 = {
    0xFFFFFFFE00000001ULL, 0x0000000200000000ULL, 0xFFFFFFFE00000000ULL,
    0x0000000200000000ULL, 0x0000000000000001ULL, 0x0000000000000000ULL
};

static const p384_fe_t p384_minus3_mont __attribute__((unused)) = {
    0xFFFFFFFDFFFFFFFFULL, 0xFFFFFFFF00000002ULL, 0xFFFFFFFCFFFFFFFBULL,
    0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL, 0x00000000FFFFFFFFULL
};
static const p384_fe_t p384_b3_mont __attribute__((unused)) = {
    0xC1ED74C220EF3FEDULL, 0x54521950F8B3AEB3ULL, 0xB4E849CE082BAB23ULL,
    0x148DD99AE9F194CFULL, 0x7699F0B869F62A6FULL, 0x00000000228165DEULL
};
static const p384_point_t p384_g = {
    .x = {0x3DD0756649C0B528ULL, 0x20E378E2A0D6CE38ULL, 0x879C3AFC541B4D6EULL,
          0x6454868459A30EFFULL, 0x812FF723614EDE2BULL, 0x4D3AADC2299E1513ULL},
    .y = {0x23043DAD4B03A4FEULL, 0xA1BFA8BF7BB4A9ACULL, 0x8BADE7562E83B050ULL,
          0xC6C3521968F4FFD9ULL, 0xDD8002263969A840ULL, 0x2B78ABC25A15C5E9ULL},
    .z = {0xFFFFFFFF00000001ULL, 0x00000000FFFFFFFFULL, 0x0000000000000001ULL,
          0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL}
};

static void p256_fe_mul(p256_fe_t r, const p256_fe_t a, const p256_fe_t b);
static void p256_fe_sqr(p256_fe_t r, const p256_fe_t a);
static void p256_fe_add(p256_fe_t r, const p256_fe_t a, const p256_fe_t b);
static void p256_fe_sub(p256_fe_t r, const p256_fe_t a, const p256_fe_t b);
static void p256_fe_inv(p256_fe_t r, const p256_fe_t a);
static void p256_fe_to_mont(p256_fe_t r, const p256_fe_t a);
static void p256_fe_from_mont(p256_fe_t r, const p256_fe_t a);
static void p256_point_add(p256_point_t *r, const p256_point_t *p, const p256_point_t *q);
static void p256_point_dbl(p256_point_t *r, const p256_point_t *p);
static void p256_point_mul(p256_point_t *r, const p256_fe_t scalar, const p256_point_t *p);

static void p384_fe_mul(p384_fe_t r, const p384_fe_t a, const p384_fe_t b);
static void p384_fe_add(p384_fe_t r, const p384_fe_t a, const p384_fe_t b);
static void p384_fe_sub(p384_fe_t r, const p384_fe_t a, const p384_fe_t b);
static void p384_fe_to_mont(p384_fe_t r, const p384_fe_t a);
static void p384_fe_from_mont(p384_fe_t r, const p384_fe_t a);
static void p384_point_add(p384_point_t *r, const p384_point_t *p, const p384_point_t *q);
static void p384_point_dbl(p384_point_t *r, const p384_point_t *p);
static void p384_point_mul(p384_point_t *r, const p384_fe_t scalar, const p384_point_t *p);


static void p256_fe_mul(p256_fe_t r, const p256_fe_t a, const p256_fe_t b) {
    /* Schoolbook 4×4 multiply → 8-limb product, then Montgomery reduction.
     * For P-256, -p^{-1} mod 2^64 = 1 since p[0] = 0xFFFFFFFFFFFFFFFF. */

    /* Step 1: schoolbook multiply */
    uint64_t w[8] = {0};
    for (int i = 0; i < 4; i++) {
        uint64_t carry = 0;
        for (int j = 0; j < 4; j++) {
            __int128 prod = (unsigned __int128)a[i] * b[j] + w[i+j] + carry;
            w[i+j] = (uint64_t)prod;
            carry = (uint64_t)(prod >> 64);
        }
        w[i+4] = carry;
    }

    /* Step 2: Montgomery reduction (4 iterations) */
    for (int i = 0; i < 4; i++) {
        uint64_t m = w[0];
        __int128 acc = (unsigned __int128)m * p256_p[0] + w[0];
        uint64_t carry = (uint64_t)(acc >> 64);

        acc = (unsigned __int128)m * p256_p[1] + w[1] + carry;
        w[0] = (uint64_t)acc;
        carry = (uint64_t)(acc >> 64);

        acc = (unsigned __int128)m * p256_p[2] + w[2] + carry;
        w[1] = (uint64_t)acc;
        carry = (uint64_t)(acc >> 64);

        acc = (unsigned __int128)m * p256_p[3] + w[3] + carry;
        w[2] = (uint64_t)acc;
        carry = (uint64_t)(acc >> 64);

        acc = (unsigned __int128)w[4] + carry;
        w[3] = (uint64_t)acc;
        carry = (uint64_t)(acc >> 64);

        acc = (unsigned __int128)w[5] + carry;
        w[4] = (uint64_t)acc;
        carry = (uint64_t)(acc >> 64);

        acc = (unsigned __int128)w[6] + carry;
        w[5] = (uint64_t)acc;
        carry = (uint64_t)(acc >> 64);

        w[6] = w[7] + carry;
        w[7] = 0;
    }

    /* Step 3: conditional subtraction of p (unsigned borrow chain) */
    uint64_t sub[4];
    uint64_t borrow = 0;

    sub[0] = w[0] - p256_p[0];
    borrow = w[0] < p256_p[0];

    uint64_t tmp = w[1] - p256_p[1];
    uint64_t b1 = w[1] < p256_p[1];
    sub[1] = tmp - borrow;
    b1 |= (tmp < borrow);
    borrow = b1;

    tmp = w[2] - p256_p[2];
    b1 = w[2] < p256_p[2];
    sub[2] = tmp - borrow;
    b1 |= (tmp < borrow);
    borrow = b1;

    tmp = w[3] - p256_p[3];
    b1 = w[3] < p256_p[3];
    sub[3] = tmp - borrow;
    b1 |= (tmp < borrow);
    borrow = b1;

    uint64_t need_sub = (w[4] >= borrow) ? UINT64_MAX : 0;
    r[0] = (sub[0] & need_sub) | (w[0] & ~need_sub);
    r[1] = (sub[1] & need_sub) | (w[1] & ~need_sub);
    r[2] = (sub[2] & need_sub) | (w[2] & ~need_sub);
    r[3] = (sub[3] & need_sub) | (w[3] & ~need_sub);
}

static void p256_fe_sqr(p256_fe_t r, const p256_fe_t a) {
    p256_fe_mul(r, a, a);
}

static void p256_fe_add(p256_fe_t r, const p256_fe_t a, const p256_fe_t b) {
    __int128 acc = (unsigned __int128)a[0] + b[0];
    uint64_t t[4];
    t[0] = (uint64_t)acc; acc >>= 64;
    acc += (unsigned __int128)a[1] + b[1];
    t[1] = (uint64_t)acc; acc >>= 64;
    acc += (unsigned __int128)a[2] + b[2];
    t[2] = (uint64_t)acc; acc >>= 64;
    acc += (unsigned __int128)a[3] + b[3];
    t[3] = (uint64_t)acc;
    uint64_t carry = (uint64_t)(acc >> 64);

    /* Conditional subtraction of p */
    uint64_t borrow;
    uint64_t sub[4];

    borrow = (t[0] < p256_p[0]);
    sub[0] = t[0] - p256_p[0];

    uint64_t d1 = t[1] - p256_p[1];
    uint64_t b1 = t[1] < p256_p[1];
    sub[1] = d1 - borrow;
    borrow = b1 | (sub[1] > d1);

    uint64_t d2 = t[2] - p256_p[2];
    uint64_t b2 = t[2] < p256_p[2];
    sub[2] = d2 - borrow;
    borrow = b2 | (sub[2] > d2);

    uint64_t d3 = t[3] - p256_p[3];
    uint64_t b3 = t[3] < p256_p[3];
    sub[3] = d3 - borrow;
    borrow = b3 | (sub[3] > d3);

    /* Subtract if carry set or if t >= p (no borrow) */
    uint64_t do_sub = carry | (borrow ^ 1);
    uint64_t mask = ~(do_sub - 1);
    r[0] = ecc_ct_select(mask, sub[0], t[0]);
    r[1] = ecc_ct_select(mask, sub[1], t[1]);
    r[2] = ecc_ct_select(mask, sub[2], t[2]);
    r[3] = ecc_ct_select(mask, sub[3], t[3]);
}

static void p256_fe_sub(p256_fe_t r, const p256_fe_t a, const p256_fe_t b) {
    uint64_t borrow;
    uint64_t t[4];

    borrow = (a[0] < b[0]);
    t[0] = a[0] - b[0];

    uint64_t d1 = a[1] - b[1];
    uint64_t b1 = a[1] < b[1];
    t[1] = d1 - borrow;
    borrow = b1 | (t[1] > d1);

    uint64_t d2 = a[2] - b[2];
    uint64_t b2 = a[2] < b[2];
    t[2] = d2 - borrow;
    borrow = b2 | (t[2] > d2);

    uint64_t d3 = a[3] - b[3];
    uint64_t b3 = a[3] < b[3];
    t[3] = d3 - borrow;
    borrow = b3 | (t[3] > d3);

    /* Constant-time conditional add of p: mask = all-ones if underflow, all-zeros otherwise */
    uint64_t mask = -borrow;
    __int128 acc = (unsigned __int128)t[0] + (p256_p[0] & mask);
    r[0] = (uint64_t)acc; acc >>= 64;
    acc += (unsigned __int128)t[1] + (p256_p[1] & mask);
    r[1] = (uint64_t)acc; acc >>= 64;
    acc += (unsigned __int128)t[2] + (p256_p[2] & mask);
    r[2] = (uint64_t)acc; acc >>= 64;
    acc += (unsigned __int128)t[3] + (p256_p[3] & mask);
    r[3] = (uint64_t)acc;
}

static void p256_fe_inv(p256_fe_t r, const p256_fe_t a) {
    /* a^{p-2} mod p via Fermat's little theorem.
     * P-256 prime p = 2^256 - 2^224 + 2^192 + 2^96 - 1
     * p-2 in 64-bit limbs (little-endian): */
    static const uint64_t pm2[4] = {
        0xFFFFFFFFFFFFFFFDULL,
        0x00000000FFFFFFFFULL,
        0x0000000000000000ULL,
        0xFFFFFFFF00000001ULL,
    };
    p256_fe_t t;
    memcpy(t, a, sizeof(p256_fe_t));
    for (int i = 254; i >= 0; i--) {
        p256_fe_sqr(t, t);
        int limb = i / 64;
        int bit = i % 64;
        if ((pm2[limb] >> bit) & 1)
            p256_fe_mul(t, t, a);
    }
    memcpy(r, t, sizeof(p256_fe_t));
}

static void p256_fe_to_mont(p256_fe_t r, const p256_fe_t a) {
    p256_fe_mul(r, a, p256_r2);
}

static void p256_fe_from_mont(p256_fe_t r, const p256_fe_t a) {
    static const p256_fe_t one = {1, 0, 0, 0};
    p256_fe_mul(r, a, one);
}


static void p256_point_add(p256_point_t *r, const p256_point_t *p, const p256_point_t *q) {
    p256_fe_t t0, t1, t2, t3, t4, t5, x3, y3, z3;
    static const p256_fe_t b3_mont = {0x89D69E267D4E399FULL, 0x06D01166698C91B2ULL,
                                      0xB0E66203E5638C84ULL, 0x949012590D95D89CULL};
    static const p256_fe_t minus3_mont = {0xFFFFFFFFFFFFFFFCULL, 0x00000003FFFFFFFFULL,
                                          0x0000000000000000ULL, 0xFFFFFFFC00000004ULL};

    p256_fe_mul(t0, p->x, q->x); p256_fe_mul(t1, p->y, q->y); p256_fe_mul(t2, p->z, q->z);
    p256_fe_add(t3, p->x, p->y); p256_fe_add(t4, q->x, q->y); p256_fe_mul(t3, t3, t4);
    p256_fe_add(t4, t0, t1); p256_fe_sub(t3, t3, t4); p256_fe_add(t4, p->x, p->z);
    p256_fe_add(t5, q->x, q->z); p256_fe_mul(t4, t4, t5); p256_fe_add(t5, t0, t2);
    p256_fe_sub(t4, t4, t5); p256_fe_add(t5, p->y, p->z); p256_fe_add(x3, q->y, q->z);
    p256_fe_mul(t5, t5, x3); p256_fe_add(x3, t1, t2); p256_fe_sub(t5, t5, x3);
    p256_fe_mul(z3, minus3_mont, t4); p256_fe_mul(x3, b3_mont, t2); p256_fe_add(z3, x3, z3);
    p256_fe_sub(x3, t1, z3); p256_fe_add(z3, t1, z3); p256_fe_mul(y3, x3, z3);
    p256_fe_add(t1, t0, t0); p256_fe_add(t1, t1, t0); p256_fe_mul(t2, minus3_mont, t2);
    p256_fe_mul(t4, b3_mont, t4); p256_fe_add(t1, t1, t2); p256_fe_sub(t2, t0, t2);
    p256_fe_mul(t2, minus3_mont, t2); p256_fe_add(t4, t4, t2); p256_fe_mul(t0, t1, t4);
    p256_fe_add(y3, y3, t0); p256_fe_mul(t0, t5, t4); p256_fe_mul(x3, t3, x3);
    p256_fe_sub(x3, x3, t0); p256_fe_mul(t0, t3, t1); p256_fe_mul(z3, t5, z3);
    p256_fe_add(z3, z3, t0);

    memcpy(r->x, x3, sizeof(p256_fe_t));
    memcpy(r->y, y3, sizeof(p256_fe_t));
    memcpy(r->z, z3, sizeof(p256_fe_t));
}

static void p256_point_dbl(p256_point_t *r, const p256_point_t *p) {
    /* dbl-1998-cmo for a=-3 in homogeneous projective coordinates:
     * w = 3*X^2 + a*Z^2 = 3*(X^2 - Z^2)  (since a=-3)
     * s = Y*Z, B = X*Y*s, h = w^2 - 8*B
     * X3 = 2*h*s
     * Y3 = w*(4*B - h) - 8*Y^2*s^2
     * Z3 = 8*s^3 */
    p256_fe_t xx, zz, w, s, ss, b, h, x3, y3, z3, t1, t2;

    p256_fe_mul(xx, p->x, p->x);
    p256_fe_mul(zz, p->z, p->z);

    /* w = 3*(XX - ZZ) */
    p256_fe_sub(t1, xx, zz);
    p256_fe_add(w, t1, t1);
    p256_fe_add(w, w, t1);

    p256_fe_mul(s, p->y, p->z);
    p256_fe_mul(b, p->x, p->y);
    p256_fe_mul(b, b, s);

    /* h = w^2 - 8*B */
    p256_fe_mul(h, w, w);
    p256_fe_add(t1, b, b);   /* 2B */
    p256_fe_add(t1, t1, t1); /* 4B */
    p256_fe_add(t2, t1, t1); /* 8B */
    p256_fe_sub(h, h, t2);

    /* X3 = 2*h*s */
    p256_fe_mul(x3, h, s);
    p256_fe_add(x3, x3, x3);

    /* Y3 = w*(4*B - h) - 8*Y^2*s^2 */
    p256_fe_sub(t2, t1, h);   /* 4B - h */
    p256_fe_mul(y3, w, t2);
    p256_fe_mul(ss, s, s);
    p256_fe_mul(t1, p->y, p->y);
    p256_fe_mul(t1, t1, ss);
    p256_fe_add(t1, t1, t1);  /* 2*Y^2*s^2 */
    p256_fe_add(t1, t1, t1);  /* 4*Y^2*s^2 */
    p256_fe_add(t1, t1, t1);  /* 8*Y^2*s^2 */
    p256_fe_sub(y3, y3, t1);

    /* Z3 = 8*s^3 */
    p256_fe_mul(z3, ss, s);
    p256_fe_add(z3, z3, z3);
    p256_fe_add(z3, z3, z3);
    p256_fe_add(z3, z3, z3);

    /* Constant-time identity passthrough: if input Z == 0 (identity),
     * the formula produces (0:0:0) which is not a valid representation.
     * Restore the input (which is identity) using a constant-time select. */
    uint64_t z_or = p->z[0] | p->z[1] | p->z[2] | p->z[3];
    uint64_t nz = (z_or | (uint64_t)(-(int64_t)z_or)) >> 63; /* 1 if z!=0 */
    uint64_t id_mask = (uint64_t)(-(int64_t)(1u ^ nz));       /* ~0 if identity */
    for (int i = 0; i < 4; i++) {
        r->x[i] = ecc_ct_select(id_mask, p->x[i], x3[i]);
        r->y[i] = ecc_ct_select(id_mask, p->y[i], y3[i]);
        r->z[i] = ecc_ct_select(id_mask, p->z[i], z3[i]);
    }
}


static void p256_point_ct_swap(p256_point_t *a, p256_point_t *b, uint64_t swap) {
    /* swap=1 exchanges a and b; swap=0 is a no-op. No branches on swap. */
    uint64_t mask = -(uint64_t)swap;
    for (int i = 0; i < 4; i++) {
        uint64_t t;
        t = mask & (a->x[i] ^ b->x[i]); a->x[i] ^= t; b->x[i] ^= t;
        t = mask & (a->y[i] ^ b->y[i]); a->y[i] ^= t; b->y[i] ^= t;
        t = mask & (a->z[i] ^ b->z[i]); a->z[i] ^= t; b->z[i] ^= t;
    }
}

static void p256_point_mul(p256_point_t *r, const p256_fe_t scalar, const p256_point_t *p) {
    /* Montgomery ladder: constant-time scalar multiplication.
     * R0 starts as the identity point (0 : Montgomery_1 : 0), R1 = P.
     * The complete addition formula correctly handles Z=0 identity inputs.
     * The doubling formula is patched to return identity when Z=0 (see above).
     * Processing all 256 bits from bit 255 down to bit 0 ensures correctness
     * for any scalar in [0, 2^256), including those where the leading bit is 0. */
    p256_point_t R0, R1;

    /* Identity in Montgomery projective coordinates: (0 : R mod p : 0)
     * where R mod p = 2^256 mod p is the Montgomery constant for P-256. */
    static const p256_fe_t p256_mont1 = {
        0x0000000000000001ULL, 0xFFFFFFFF00000000ULL,
        0xFFFFFFFFFFFFFFFFULL, 0x00000000FFFFFFFEULL
    };
    memset(&R0, 0, sizeof(R0));
    memcpy(R0.y, p256_mont1, sizeof(p256_fe_t));

    memcpy(&R1, p, sizeof(p256_point_t));

    for (int i = 255; i >= 0; i--) {
        uint64_t bit = (scalar[i / 64] >> (i % 64)) & 1;
        p256_point_ct_swap(&R0, &R1, bit);
        p256_point_add(&R1, &R0, &R1);
        p256_point_dbl(&R0, &R0);
        p256_point_ct_swap(&R0, &R1, bit);
    }

    /* Result is R0; normalize to affine (Z = R mod p, the Montgomery 1) */
    p256_fe_t zi;
    p256_fe_inv(zi, R0.z);
    p256_fe_mul(r->x, R0.x, zi);
    p256_fe_mul(r->y, R0.y, zi);
    r->z[0] = 0x0000000000000001ULL;
    r->z[1] = 0xFFFFFFFF00000000ULL;
    r->z[2] = 0xFFFFFFFFFFFFFFFFULL;
    r->z[3] = 0x00000000FFFFFFFEULL;
}


static void p384_fe_mul(p384_fe_t r, const p384_fe_t a, const p384_fe_t b) {
    /* CIOS Montgomery multiplication for P-384.
     * mu = -p^{-1} mod 2^64 = 0x0000000100000001 (since p[0] = 0xFFFFFFFF). */
    uint64_t t[8] = {0};

    for (int i = 0; i < 6; i++) {
        /* Multiply: t += a[i] * b */
        uint64_t C = 0;
        for (int j = 0; j < 6; j++) {
            __uint128_t prod = (__uint128_t)t[j] + (__uint128_t)a[i] * b[j] + C;
            t[j] = (uint64_t)prod;
            C = (uint64_t)(prod >> 64);
        }
        __uint128_t sum = (__uint128_t)t[6] + C;
        t[6] = (uint64_t)sum;
        t[7] = (uint64_t)(sum >> 64);

        /* Reduce: t += m*p, t >>= 64 */
        uint64_t m = t[0] * 0x0000000100000001ULL;
        __uint128_t carry = (__uint128_t)t[0] + (__uint128_t)m * p384_p[0];
        C = (uint64_t)(carry >> 64);
        for (int j = 1; j < 6; j++) {
            carry = (__uint128_t)t[j] + (__uint128_t)m * p384_p[j] + C;
            t[j-1] = (uint64_t)carry;
            C = (uint64_t)(carry >> 64);
        }
        carry = (__uint128_t)t[6] + C;
        t[5] = (uint64_t)carry;
        t[6] = t[7] + (uint64_t)(carry >> 64);
        t[7] = 0;
    }

    /* Constant-time conditional subtraction of p.
     * Always compute sub[] = t - p; then select sub if t >= p, t otherwise.
     * need_sub = all-ones when t[6] >= borrow (no underflow into phantom limb). */
    uint64_t borrow = 0;
    uint64_t sub[6];
    for (int i = 0; i < 6; i++) {
        __uint128_t diff = (__uint128_t)t[i] - p384_p[i] - borrow;
        sub[i] = (uint64_t)diff;
        borrow = (uint64_t)(diff >> 127); /* 1 if underflow, else 0 */
    }
    /* need_sub: all-ones if t[6] >= borrow (subtraction valid), all-zeros otherwise */
    uint64_t need_sub = -(uint64_t)(t[6] >= borrow);
    for (int i = 0; i < 6; i++)
        r[i] = (sub[i] & need_sub) | (t[i] & ~need_sub);
}

static void p384_fe_add(p384_fe_t r, const p384_fe_t a, const p384_fe_t b) {
    __int128 acc = (unsigned __int128)a[0] + b[0];
    uint64_t temp[6];
    temp[0] = (uint64_t)acc;
    acc = (unsigned __int128)a[1] + b[1] + (uint64_t)(acc >> 64);
    temp[1] = (uint64_t)acc;
    acc = (unsigned __int128)a[2] + b[2] + (uint64_t)(acc >> 64);
    temp[2] = (uint64_t)acc;
    acc = (unsigned __int128)a[3] + b[3] + (uint64_t)(acc >> 64);
    temp[3] = (uint64_t)acc;
    acc = (unsigned __int128)a[4] + b[4] + (uint64_t)(acc >> 64);
    temp[4] = (uint64_t)acc;
    acc = (unsigned __int128)a[5] + b[5] + (uint64_t)(acc >> 64);
    temp[5] = (uint64_t)acc;
    uint64_t carry = (uint64_t)(acc >> 64);

    /* Conditional subtraction of p (unsigned borrow chain) */
    uint64_t sub[6];
    uint64_t borrow = 0;

    sub[0] = temp[0] - p384_p[0];
    borrow = temp[0] < p384_p[0];

    uint64_t tmp, b1;
    tmp = temp[1] - p384_p[1]; b1 = temp[1] < p384_p[1];
    sub[1] = tmp - borrow; b1 |= (tmp < borrow); borrow = b1;

    tmp = temp[2] - p384_p[2]; b1 = temp[2] < p384_p[2];
    sub[2] = tmp - borrow; b1 |= (tmp < borrow); borrow = b1;

    tmp = temp[3] - p384_p[3]; b1 = temp[3] < p384_p[3];
    sub[3] = tmp - borrow; b1 |= (tmp < borrow); borrow = b1;

    tmp = temp[4] - p384_p[4]; b1 = temp[4] < p384_p[4];
    sub[4] = tmp - borrow; b1 |= (tmp < borrow); borrow = b1;

    tmp = temp[5] - p384_p[5]; b1 = temp[5] < p384_p[5];
    sub[5] = tmp - borrow; b1 |= (tmp < borrow); borrow = b1;

    uint64_t need_sub = (carry >= borrow) ? UINT64_MAX : 0;
    r[0] = (sub[0] & need_sub) | (temp[0] & ~need_sub);
    r[1] = (sub[1] & need_sub) | (temp[1] & ~need_sub);
    r[2] = (sub[2] & need_sub) | (temp[2] & ~need_sub);
    r[3] = (sub[3] & need_sub) | (temp[3] & ~need_sub);
    r[4] = (sub[4] & need_sub) | (temp[4] & ~need_sub);
    r[5] = (sub[5] & need_sub) | (temp[5] & ~need_sub);
}

static void p384_fe_sub(p384_fe_t r, const p384_fe_t a, const p384_fe_t b) {
    uint64_t temp[6];
    uint64_t borrow = 0, tmp, b1;

    temp[0] = a[0] - b[0];
    borrow = a[0] < b[0];

    tmp = a[1] - b[1]; b1 = a[1] < b[1];
    temp[1] = tmp - borrow; b1 |= (tmp < borrow); borrow = b1;

    tmp = a[2] - b[2]; b1 = a[2] < b[2];
    temp[2] = tmp - borrow; b1 |= (tmp < borrow); borrow = b1;

    tmp = a[3] - b[3]; b1 = a[3] < b[3];
    temp[3] = tmp - borrow; b1 |= (tmp < borrow); borrow = b1;

    tmp = a[4] - b[4]; b1 = a[4] < b[4];
    temp[4] = tmp - borrow; b1 |= (tmp < borrow); borrow = b1;

    tmp = a[5] - b[5]; b1 = a[5] < b[5];
    temp[5] = tmp - borrow; b1 |= (tmp < borrow); borrow = b1;

    uint64_t mask = borrow ? UINT64_MAX : 0;
    __int128 acc = (unsigned __int128)temp[0] + (p384_p[0] & mask);
    r[0] = (uint64_t)acc;
    acc = (unsigned __int128)temp[1] + (p384_p[1] & mask) + (uint64_t)(acc >> 64);
    r[1] = (uint64_t)acc;
    acc = (unsigned __int128)temp[2] + (p384_p[2] & mask) + (uint64_t)(acc >> 64);
    r[2] = (uint64_t)acc;
    acc = (unsigned __int128)temp[3] + (p384_p[3] & mask) + (uint64_t)(acc >> 64);
    r[3] = (uint64_t)acc;
    acc = (unsigned __int128)temp[4] + (p384_p[4] & mask) + (uint64_t)(acc >> 64);
    r[4] = (uint64_t)acc;
    acc = (unsigned __int128)temp[5] + (p384_p[5] & mask) + (uint64_t)(acc >> 64);
    r[5] = (uint64_t)acc;
}

static void p384_fe_to_mont(p384_fe_t r, const p384_fe_t a) {
    p384_fe_mul(r, a, p384_r2);
}

static void p384_fe_from_mont(p384_fe_t r, const p384_fe_t a) {
    static const p384_fe_t one = {1, 0, 0, 0, 0, 0};
    p384_fe_mul(r, a, one);
}

static void p384_fe_inv(p384_fe_t r, const p384_fe_t a) {
    /* a^{p-2} mod p via Fermat's little theorem.
     * P-384 prime: p = 2^384 - 2^128 - 2^96 + 2^32 - 1
     * p-2 in binary: all 1s except bits 0,32,96,128 have specific patterns.
     * Use generic square-and-multiply with the p-2 constant. */
    static const uint64_t pm2[6] = {
        0x00000000FFFFFFFDULL,
        0xFFFFFFFF00000000ULL,
        0xFFFFFFFFFFFFFFFEULL,
        0xFFFFFFFFFFFFFFFFULL,
        0xFFFFFFFFFFFFFFFFULL,
        0xFFFFFFFFFFFFFFFFULL,
    };
    p384_fe_t t;
    memcpy(t, a, sizeof(p384_fe_t));
    for (int i = 382; i >= 0; i--) {
        p384_fe_mul(t, t, t);
        int limb = i / 64;
        int bit = i % 64;
        if ((pm2[limb] >> bit) & 1)
            p384_fe_mul(t, t, a);
    }
    memcpy(r, t, sizeof(p384_fe_t));
}

static void p384_point_dbl(p384_point_t *r, const p384_point_t *p) {
    /* Homogeneous projective doubling (dbl-1998-cmo) for a=-3:
     * w = 3*X^2 + a*Z^2, s = Y*Z, B = X*Y*s, h = w^2 - 8*B
     * X3 = 2*h*s, Y3 = w*(4*B-h) - 8*Y^2*s^2, Z3 = 8*s^3 */
    p384_fe_t xx, zz, w, s, ss, b, h, x3, y3, z3, t1, t2;

    p384_fe_mul(xx, p->x, p->x);
    p384_fe_mul(zz, p->z, p->z);

    /* w = 3*XX + a*ZZ = 3*XX - 3*ZZ = 3*(XX - ZZ) */
    p384_fe_sub(t1, xx, zz);
    p384_fe_add(w, t1, t1);
    p384_fe_add(w, w, t1);

    p384_fe_mul(s, p->y, p->z);
    p384_fe_mul(b, p->x, p->y);
    p384_fe_mul(b, b, s);

    /* h = w^2 - 8*B */
    p384_fe_mul(h, w, w);
    p384_fe_add(t1, b, b);   /* 2B */
    p384_fe_add(t1, t1, t1); /* 4B */
    p384_fe_add(t2, t1, t1); /* 8B */
    p384_fe_sub(h, h, t2);

    /* X3 = 2*h*s */
    p384_fe_mul(x3, h, s);
    p384_fe_add(x3, x3, x3);

    /* Y3 = w*(4*B - h) - 8*Y^2*s^2 */
    p384_fe_sub(t2, t1, h);   /* 4B - h */
    p384_fe_mul(y3, w, t2);
    p384_fe_mul(ss, s, s);
    p384_fe_mul(t1, p->y, p->y);
    p384_fe_mul(t1, t1, ss);
    p384_fe_add(t1, t1, t1);  /* 2*Y^2*s^2 */
    p384_fe_add(t1, t1, t1);  /* 4*Y^2*s^2 */
    p384_fe_add(t1, t1, t1);  /* 8*Y^2*s^2 */
    p384_fe_sub(y3, y3, t1);

    /* Z3 = 8*s^3 */
    p384_fe_mul(z3, ss, s);
    p384_fe_add(z3, z3, z3);
    p384_fe_add(z3, z3, z3);
    p384_fe_add(z3, z3, z3);

    memcpy(r->x, x3, sizeof(p384_fe_t));
    memcpy(r->y, y3, sizeof(p384_fe_t));
    memcpy(r->z, z3, sizeof(p384_fe_t));
}

static void p384_point_add(p384_point_t *r, const p384_point_t *p, const p384_point_t *q) {
    /* Homogeneous projective addition (add-1998-cmo-2) for distinct points. */
    p384_fe_t y1z2, x1z2, z1z2, u, uu, v, vv, vvv, rr, aa, x3, y3, z3, t1;

    p384_fe_mul(y1z2, p->y, q->z);
    p384_fe_mul(x1z2, p->x, q->z);
    p384_fe_mul(z1z2, p->z, q->z);

    p384_fe_mul(u, q->y, p->z);
    p384_fe_sub(u, u, y1z2);
    p384_fe_mul(v, q->x, p->z);
    p384_fe_sub(v, v, x1z2);

    p384_fe_mul(uu, u, u);
    p384_fe_mul(vv, v, v);
    p384_fe_mul(vvv, vv, v);
    p384_fe_mul(rr, vv, x1z2);

    p384_fe_mul(aa, uu, z1z2);
    p384_fe_sub(aa, aa, vvv);
    p384_fe_add(t1, rr, rr);
    p384_fe_sub(aa, aa, t1);

    p384_fe_mul(x3, v, aa);
    p384_fe_sub(t1, rr, aa);
    p384_fe_mul(y3, u, t1);
    p384_fe_mul(t1, vvv, y1z2);
    p384_fe_sub(y3, y3, t1);
    p384_fe_mul(z3, vvv, z1z2);

    memcpy(r->x, x3, sizeof(p384_fe_t));
    memcpy(r->y, y3, sizeof(p384_fe_t));
    memcpy(r->z, z3, sizeof(p384_fe_t));
}

static int __attribute__((unused)) p384_fe_is_zero(const p384_fe_t a) {
    return (a[0] | a[1] | a[2] | a[3] | a[4] | a[5]) == 0;
}

static int p384_fe_equal(const p384_fe_t a, const p384_fe_t b) {
    uint64_t acc = 0;
    for (int i = 0; i < 6; i++) acc |= a[i] ^ b[i];
    return acc == 0;
}

static int p384_point_is_identity(const p384_point_t *p) {
    return p384_fe_is_zero(p->z);
}

static void p384_point_set_identity(p384_point_t *p) {
    memset(p, 0, sizeof(*p));
    p->y[0] = 1;
}

static void p384_point_set_z_one(p384_point_t *p) {
    p->z[0] = 0xFFFFFFFF00000001ULL;
    p->z[1] = 0x00000000FFFFFFFFULL;
    p->z[2] = 0x0000000000000001ULL;
    p->z[3] = 0;
    p->z[4] = 0;
    p->z[5] = 0;
}

static void p384_point_normalize(p384_point_t *r, const p384_point_t *p) {
    if (p384_point_is_identity(p)) {
        p384_point_set_identity(r);
        return;
    }

    p384_fe_t zi;
    p384_fe_inv(zi, p->z);
    p384_fe_mul(r->x, p->x, zi);
    p384_fe_mul(r->y, p->y, zi);
    p384_point_set_z_one(r);
}

static void p384_point_add_affine(p384_point_t *r, const p384_point_t *p,
                                  const p384_point_t *q) {
    if (p384_point_is_identity(p)) {
        memcpy(r, q, sizeof(*r));
        return;
    }
    if (p384_point_is_identity(q)) {
        memcpy(r, p, sizeof(*r));
        return;
    }

    if (p384_fe_equal(p->x, q->x)) {
        if (p384_fe_equal(p->y, q->y)) {
            p384_point_t dbl;
            p384_point_dbl(&dbl, p);
            p384_point_normalize(r, &dbl);
        } else {
            p384_point_set_identity(r);
        }
        return;
    }

    p384_fe_t num, den, den_inv, lambda, x3, y3, tmp;
    p384_fe_sub(num, q->y, p->y);
    p384_fe_sub(den, q->x, p->x);
    p384_fe_inv(den_inv, den);
    p384_fe_mul(lambda, num, den_inv);

    p384_fe_mul(x3, lambda, lambda);
    p384_fe_sub(x3, x3, p->x);
    p384_fe_sub(x3, x3, q->x);

    p384_fe_sub(tmp, p->x, x3);
    p384_fe_mul(y3, lambda, tmp);
    p384_fe_sub(y3, y3, p->y);

    memcpy(r->x, x3, sizeof(p384_fe_t));
    memcpy(r->y, y3, sizeof(p384_fe_t));
    p384_point_set_z_one(r);
}

static void __attribute__((unused)) p384_point_ct_swap(p384_point_t *a, p384_point_t *b, uint64_t swap) {
    uint64_t mask = -(uint64_t)swap;
    for (int i = 0; i < 6; i++) {
        uint64_t t;
        t = mask & (a->x[i] ^ b->x[i]); a->x[i] ^= t; b->x[i] ^= t;
        t = mask & (a->y[i] ^ b->y[i]); a->y[i] ^= t; b->y[i] ^= t;
        t = mask & (a->z[i] ^ b->z[i]); a->z[i] ^= t; b->z[i] ^= t;
    }
}

static void p384_point_mul(p384_point_t *r, const p384_fe_t scalar, const p384_point_t *p) {
    p384_point_t acc, addend;

    p384_point_set_identity(&acc);
    memcpy(&addend, p, sizeof(addend));

    for (int i = 0; i < 384; i++) {
        uint64_t bit = (scalar[i / 64] >> (i % 64)) & 1;
        if (bit) {
            p384_point_t sum;
            p384_point_add_affine(&sum, &acc, &addend);
            memcpy(&acc, &sum, sizeof(acc));
        }

        p384_point_t dbl;
        p384_point_dbl(&dbl, &addend);
        p384_point_normalize(&addend, &dbl);
    }

    /* Normalize result to affine (z = R mod p, the Montgomery 1) */
    p384_point_normalize(r, &acc);
}

/* ─── P-521 Field Arithmetic (Mersenne prime p = 2^521 - 1) ────────────── */

static const p521_fe_t p521_p = {
    0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL,
    0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL,
    0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL, 0x1FFULL
};

static const p521_fe_t p521_n = {
    0xBB6FB71E91386409ULL, 0x3BB5C9B8899C47AEULL, 0x7FCC0148F709A5D0ULL,
    0x51868783BF2F966BULL, 0xFFFFFFFFFFFFFFFAULL, 0xFFFFFFFFFFFFFFFFULL,
    0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL, 0x1FFULL
};

static const p521_point_t p521_g = {
    .x = {0xF97E7E31C2E5BD66ULL, 0x3348B3C1856A429BULL, 0xFE1DC127A2FFA8DEULL,
          0xA14B5E77EFE75928ULL, 0xF828AF606B4D3DBAULL, 0x9C648139053FB521ULL,
          0x9E3ECB662395B442ULL, 0x858E06B70404E9CDULL, 0x00000000000000C6ULL},
    .y = {0x88BE94769FD16650ULL, 0x353C7086A272C240ULL, 0xC550B9013FAD0761ULL,
          0x97EE72995EF42640ULL, 0x17AFBD17273E662CULL, 0x98F54449579B4468ULL,
          0x5C8A5FB42C7D1BD9ULL, 0x39296A789A3BC004ULL, 0x0000000000000118ULL},
    .z = {1, 0, 0, 0, 0, 0, 0, 0, 0}
};

static void p521_fe_reduce(p521_fe_t r) {
    uint64_t top = r[8] >> 9;
    r[8] &= 0x1FFULL;
    __uint128_t carry = (__uint128_t)r[0] + top;
    r[0] = (uint64_t)carry;
    for (int i = 1; i < 9 && (carry >> 64); i++) {
        carry = (__uint128_t)r[i] + (uint64_t)(carry >> 64);
        r[i] = (uint64_t)carry;
    }
    if (r[8] > 0x1FFULL || (r[8] == 0x1FFULL &&
        (r[7] & r[6] & r[5] & r[4] & r[3] & r[2] & r[1] & r[0]) == 0xFFFFFFFFFFFFFFFFULL)) {
        __uint128_t c = (__uint128_t)r[0] + 1;
        r[0] = (uint64_t)c;
        for (int i = 1; i < 9; i++) { c = (__uint128_t)r[i] + (uint64_t)(c >> 64); r[i] = (uint64_t)c; }
        r[8] &= 0x1FFULL;
    }
}

static void p521_fe_add(p521_fe_t r, const p521_fe_t a, const p521_fe_t b) {
    __uint128_t carry = 0;
    for (int i = 0; i < 9; i++) {
        carry += (__uint128_t)a[i] + b[i];
        r[i] = (uint64_t)carry;
        carry >>= 64;
    }
    p521_fe_reduce(r);
}

static void p521_fe_sub(p521_fe_t r, const p521_fe_t a, const p521_fe_t b) {
    uint64_t tmp[9];
    uint64_t bw = 0;
    for (int i = 0; i < 9; i++) {
        uint64_t lo = a[i] - b[i];
        uint64_t b1 = a[i] < b[i];
        tmp[i] = lo - bw;
        b1 |= (lo < bw);
        bw = b1;
    }
    if (bw) {
        __uint128_t carry = (__uint128_t)tmp[0] + p521_p[0];
        tmp[0] = (uint64_t)carry;
        for (int i = 1; i < 9; i++) { carry = (__uint128_t)tmp[i] + p521_p[i] + (uint64_t)(carry >> 64); tmp[i] = (uint64_t)carry; }
    }
    memcpy(r, tmp, sizeof(p521_fe_t));
}

static void p521_fe_mul(p521_fe_t r, const p521_fe_t a, const p521_fe_t b) {
    __uint128_t t[18] = {0};
    for (int i = 0; i < 9; i++) {
        __uint128_t carry = 0;
        for (int j = 0; j < 9; j++) {
            __uint128_t sum = t[i+j] + (__uint128_t)a[i] * b[j] + carry;
            t[i+j] = (uint64_t)sum;
            carry = sum >> 64;
        }
        t[i+9] += carry;
    }

    /* Reduce: fold bits above 521 back. product = low[0..520] + high[521..1041]
     * Since 2^521 ≡ 1 mod p, we add high << (521 mod position) to low.
     * high bits start at bit 521 = limb 8, bit 9. */
    uint64_t low[9], high[9];
    for (int i = 0; i < 8; i++) low[i] = (uint64_t)t[i];
    low[8] = (uint64_t)t[8] & 0x1FFULL;

    /* Extract high part: shift t[8..17] right by 9 bits */
    high[0] = ((uint64_t)t[8] >> 9) | ((uint64_t)t[9] << 55);
    high[1] = ((uint64_t)t[9] >> 9) | ((uint64_t)t[10] << 55);
    high[2] = ((uint64_t)t[10] >> 9) | ((uint64_t)t[11] << 55);
    high[3] = ((uint64_t)t[11] >> 9) | ((uint64_t)t[12] << 55);
    high[4] = ((uint64_t)t[12] >> 9) | ((uint64_t)t[13] << 55);
    high[5] = ((uint64_t)t[13] >> 9) | ((uint64_t)t[14] << 55);
    high[6] = ((uint64_t)t[14] >> 9) | ((uint64_t)t[15] << 55);
    high[7] = ((uint64_t)t[15] >> 9) | ((uint64_t)t[16] << 55);
    high[8] = ((uint64_t)t[16] >> 9) | ((uint64_t)t[17] << 55);

    __uint128_t carry = 0;
    for (int i = 0; i < 9; i++) { carry += (__uint128_t)low[i] + high[i]; r[i] = (uint64_t)carry; carry >>= 64; }
    p521_fe_reduce(r);
}

static void p521_fe_sqr(p521_fe_t r, const p521_fe_t a) { p521_fe_mul(r, a, a); }

static int p521_point_is_identity(const p521_point_t *p) {
    uint64_t z = 0;
    for (int i = 0; i < 9; i++)
        z |= p->z[i];
    return z == 0;
}

static void p521_fe_inv(p521_fe_t r, const p521_fe_t a) {
    /* a^(p-2) via square-and-multiply. p-2 = 2^521 - 3. */
    p521_fe_t t;
    memcpy(t, a, sizeof(p521_fe_t));
    for (int i = 519; i >= 0; i--) {
        p521_fe_sqr(t, t);
        /* p-2 bit i: all 1s except bit 0 is 1, bit 1 is 0 (since p-2 = ...11111101) */
        if (i != 1)
            p521_fe_mul(t, t, a);
    }
    memcpy(r, t, sizeof(p521_fe_t));
}

static void p521_point_dbl(p521_point_t *r, const p521_point_t *p) {
    if (p521_point_is_identity(p)) {
        memcpy(r, p, sizeof(p521_point_t));
        return;
    }

    /* dbl-1998-cmo for a=-3: w=3(X^2-Z^2), s=Y*Z, B=X*Y*s, h=w^2-8B */
    p521_fe_t xx, zz, w, s, ss, b, h, x3, y3, z3, t1, t2;
    p521_fe_mul(xx, p->x, p->x);
    p521_fe_mul(zz, p->z, p->z);
    p521_fe_sub(t1, xx, zz);
    p521_fe_add(w, t1, t1);
    p521_fe_add(w, w, t1);
    p521_fe_mul(s, p->y, p->z);
    p521_fe_mul(b, p->x, p->y);
    p521_fe_mul(b, b, s);
    p521_fe_mul(h, w, w);
    p521_fe_add(t1, b, b);
    p521_fe_add(t1, t1, t1);
    p521_fe_add(t2, t1, t1);
    p521_fe_sub(h, h, t2);
    p521_fe_mul(x3, h, s);
    p521_fe_add(x3, x3, x3);
    p521_fe_sub(t2, t1, h);
    p521_fe_mul(y3, w, t2);
    p521_fe_mul(ss, s, s);
    p521_fe_mul(t1, p->y, p->y);
    p521_fe_mul(t1, t1, ss);
    p521_fe_add(t1, t1, t1);
    p521_fe_add(t1, t1, t1);
    p521_fe_add(t1, t1, t1);
    p521_fe_sub(y3, y3, t1);
    p521_fe_mul(z3, ss, s);
    p521_fe_add(z3, z3, z3);
    p521_fe_add(z3, z3, z3);
    p521_fe_add(z3, z3, z3);
    memcpy(r->x, x3, sizeof(p521_fe_t));
    memcpy(r->y, y3, sizeof(p521_fe_t));
    memcpy(r->z, z3, sizeof(p521_fe_t));
}

static void p521_point_add(p521_point_t *r, const p521_point_t *p, const p521_point_t *q) {
    if (p521_point_is_identity(p)) {
        memcpy(r, q, sizeof(p521_point_t));
        return;
    }
    if (p521_point_is_identity(q)) {
        memcpy(r, p, sizeof(p521_point_t));
        return;
    }

    /* add-1998-cmo-2: R=vv*X1Z2, A=uu*Z1Z2-vvv-2R, X3=v*A, Y3=u*(R-A)-vvv*Y1Z2, Z3=vvv*Z1Z2 */
    p521_fe_t y1z2, x1z2, z1z2, y2z1, x2z1;
    p521_fe_t u, uu, v, vv, vvv, R, A, x3, y3, z3, t1;
    p521_fe_mul(y1z2, p->y, q->z);
    p521_fe_mul(x1z2, p->x, q->z);
    p521_fe_mul(z1z2, p->z, q->z);
    p521_fe_mul(y2z1, q->y, p->z);
    p521_fe_mul(x2z1, q->x, p->z);
    p521_fe_sub(u, y2z1, y1z2);
    p521_fe_sub(v, x2z1, x1z2);
    p521_fe_mul(uu, u, u);
    p521_fe_mul(vv, v, v);
    p521_fe_mul(vvv, vv, v);
    p521_fe_mul(R, vv, x1z2);
    /* A = uu*Z1Z2 - vvv - 2*R */
    p521_fe_mul(A, uu, z1z2);
    p521_fe_sub(A, A, vvv);
    p521_fe_sub(A, A, R);
    p521_fe_sub(A, A, R);
    /* X3 = v*A */
    p521_fe_mul(x3, v, A);
    /* Y3 = u*(R - A) - vvv*Y1Z2 */
    p521_fe_sub(t1, R, A);
    p521_fe_mul(y3, u, t1);
    p521_fe_mul(t1, vvv, y1z2);
    p521_fe_sub(y3, y3, t1);
    /* Z3 = vvv * Z1Z2 */
    p521_fe_mul(z3, vvv, z1z2);
    memcpy(r->x, x3, sizeof(p521_fe_t));
    memcpy(r->y, y3, sizeof(p521_fe_t));
    memcpy(r->z, z3, sizeof(p521_fe_t));
}

static void p521_point_ct_swap(p521_point_t *a, p521_point_t *b, uint64_t swap) {
    uint64_t mask = -(uint64_t)swap;
    for (int i = 0; i < 9; i++) {
        uint64_t t;
        t = mask & (a->x[i] ^ b->x[i]); a->x[i] ^= t; b->x[i] ^= t;
        t = mask & (a->y[i] ^ b->y[i]); a->y[i] ^= t; b->y[i] ^= t;
        t = mask & (a->z[i] ^ b->z[i]); a->z[i] ^= t; b->z[i] ^= t;
    }
}

static void p521_point_mul(p521_point_t *r, const p521_fe_t scalar, const p521_point_t *p) {
    /* P-521 uses raw projective coordinates; identity cases are handled by
     * add/double above so the ladder can start from the identity point. */
    p521_point_t R0, R1;

    memset(&R0, 0, sizeof(R0));
    R0.y[0] = 1;
    memcpy(&R1, p, sizeof(p521_point_t));

    for (int i = 520; i >= 0; i--) {
        uint64_t bit = (scalar[i / 64] >> (i % 64)) & 1;
        p521_point_ct_swap(&R0, &R1, bit);
        p521_point_add(&R1, &R0, &R1);
        p521_point_dbl(&R0, &R0);
        p521_point_ct_swap(&R0, &R1, bit);
    }

    memcpy(r, &R0, sizeof(p521_point_t));
}


static size_t der_encode_integer(uint8_t *out, const uint8_t *in, size_t in_len) {
    while (in_len > 1 && in[0] == 0) { in++; in_len--; } /* Skip leading zeros */
    if (in[0] & 0x80) {
        out[0] = 0x02; out[1] = in_len + 1; out[2] = 0x00; memcpy(out + 3, in, in_len);
        return in_len + 3;
    } else {
        out[0] = 0x02; out[1] = in_len; memcpy(out + 2, in, in_len);
        return in_len + 2;
    }
}

static int der_decode_integer(const uint8_t *in, size_t in_len, uint8_t *out, size_t *out_len) {
    if (in_len < 2 || in[0] != 0x02) return -1;
    size_t len = in[1];
    if (len + 2 > in_len) return -1;
    const uint8_t *data = in + 2;
    if (len > 0 && data[0] == 0x00) { data++; len--; }
    if (len > *out_len) return -1;
    memcpy(out, data, len); *out_len = len;
    return OPSSL_SUCCESS;
}

static int der_decode_sequence_header(const uint8_t *in, size_t in_len,
                                      size_t *header_len, size_t *content_len) {
    if (in_len < 2 || in[0] != 0x30 || !header_len || !content_len)
        return 0;

    if ((in[1] & 0x80) == 0) {
        *header_len = 2;
        *content_len = in[1];
        return *content_len + *header_len == in_len;
    }

    size_t len_len = in[1] & 0x7f;
    if (len_len == 0 || len_len > sizeof(size_t) || 2 + len_len > in_len)
        return 0;

    size_t len = 0;
    for (size_t i = 0; i < len_len; i++)
        len = (len << 8) | in[2 + i];

    if (len < 128)
        return 0;

    *header_len = 2 + len_len;
    *content_len = len;
    return *content_len + *header_len == in_len;
}

/*
 * Scalar arithmetic mod n (curve order) for ECDSA.
 * n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
 * All values in little-endian 64-bit limbs.
 */

static void mod_n_sub_cond_p256(uint64_t r[4], const uint64_t a[4])
{
    uint64_t sub[4];
    uint64_t bw = 0, tmp, b1;

    sub[0] = r[0] - a[0]; bw = r[0] < a[0];

    tmp = r[1] - a[1]; b1 = r[1] < a[1];
    sub[1] = tmp - bw; b1 |= (tmp < bw); bw = b1;

    tmp = r[2] - a[2]; b1 = r[2] < a[2];
    sub[2] = tmp - bw; b1 |= (tmp < bw); bw = b1;

    tmp = r[3] - a[3]; b1 = r[3] < a[3];
    sub[3] = tmp - bw; b1 |= (tmp < bw); bw = b1;

    uint64_t mask = bw ? 0 : UINT64_MAX;
    r[0] = (sub[0] & mask) | (r[0] & ~mask);
    r[1] = (sub[1] & mask) | (r[1] & ~mask);
    r[2] = (sub[2] & mask) | (r[2] & ~mask);
    r[3] = (sub[3] & mask) | (r[3] & ~mask);
}

static void schoolbook_mul_n(uint64_t *out, const uint64_t *a, int na,
                             const uint64_t *b, int nb)
{
    memset(out, 0, (size_t)(na + nb) * sizeof(uint64_t));
    for (int i = 0; i < na; i++) {
        uint64_t carry = 0;
        for (int j = 0; j < nb; j++) {
            unsigned __int128 p = (unsigned __int128)a[i] * b[j] + out[i+j] + carry;
            out[i+j] = (uint64_t)p;
            carry = (uint64_t)(p >> 64);
        }
        out[i + nb] += carry;
    }
}

static void mod_n_reduce_p256(p256_fe_t r, const uint64_t *a)
{
    static const uint64_t mu[5] = {
        0x012FFD85EEDF9BFEULL, 0x43190552DF1A6C21ULL,
        0xFFFFFFFEFFFFFFFFULL, 0x00000000FFFFFFFFULL,
        0x0000000000000001ULL
    };

    uint64_t q1[5];
    for (int i = 0; i < 5; i++)
        q1[i] = (i + 3 < 8) ? a[i + 3] : 0;

    uint64_t q2[10];
    schoolbook_mul_n(q2, q1, 5, mu, 5);

    uint64_t q[5] = { q2[5], q2[6], q2[7], q2[8], q2[9] };

    uint64_t n5[5] = { p256_n[0], p256_n[1], p256_n[2], p256_n[3], 0 };
    uint64_t qn[10];
    schoolbook_mul_n(qn, q, 5, n5, 5);

    uint64_t res[5];
    uint64_t borrow_br = 0;
    for (int i = 0; i < 5; i++) {
        uint64_t ai = (i < 8) ? a[i] : 0;
        uint64_t lo = ai - qn[i];
        uint64_t b1 = ai < qn[i];
        res[i] = lo - borrow_br;
        b1 |= (lo < borrow_br);
        borrow_br = b1;
    }

    r[0] = res[0]; r[1] = res[1]; r[2] = res[2]; r[3] = res[3];

    if (res[4]) {
        uint64_t bw = 0, t;
        t = r[0] - p256_n[0]; bw = r[0] < p256_n[0]; r[0] = t;
        t = r[1] - p256_n[1]; uint64_t b2 = r[1] < p256_n[1];
        r[1] = t - bw; b2 |= (t < bw); bw = b2;
        t = r[2] - p256_n[2]; b2 = r[2] < p256_n[2];
        r[2] = t - bw; b2 |= (t < bw); bw = b2;
        t = r[3] - p256_n[3]; b2 = r[3] < p256_n[3];
        r[3] = t - bw;
    }
    mod_n_sub_cond_p256(r, p256_n);
    mod_n_sub_cond_p256(r, p256_n);
}

static void mod_n_add_p256(p256_fe_t r, const p256_fe_t a, const p256_fe_t b)
{
    unsigned __int128 acc = (unsigned __int128)a[0] + b[0];
    r[0] = (uint64_t)acc;
    acc = (unsigned __int128)a[1] + b[1] + (uint64_t)(acc >> 64);
    r[1] = (uint64_t)acc;
    acc = (unsigned __int128)a[2] + b[2] + (uint64_t)(acc >> 64);
    r[2] = (uint64_t)acc;
    acc = (unsigned __int128)a[3] + b[3] + (uint64_t)(acc >> 64);
    r[3] = (uint64_t)acc;
    uint64_t carry = (uint64_t)(acc >> 64);
    if (carry) {
        uint64_t bw = 0, t, b1;
        t = r[0] - p256_n[0]; bw = r[0] < p256_n[0]; r[0] = t;
        t = r[1] - p256_n[1]; b1 = r[1] < p256_n[1];
        r[1] = t - bw; bw = b1 | (t < bw);
        t = r[2] - p256_n[2]; b1 = r[2] < p256_n[2];
        r[2] = t - bw; bw = b1 | (t < bw);
        t = r[3] - p256_n[3]; b1 = r[3] < p256_n[3];
        r[3] = t - bw;
    }
    mod_n_sub_cond_p256(r, p256_n);
}

static void mod_n_mul_p256(p256_fe_t r, const p256_fe_t a, const p256_fe_t b)
{
    uint64_t temp[8];
    schoolbook_mul_n(temp, a, 4, b, 4);
    mod_n_reduce_p256(r, temp);
}

static void mod_n_inv_p256(p256_fe_t r, const p256_fe_t a)
{
    /*
     * Compute a^(n-2) mod n via binary exponentiation.
     * n-2 = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC63254F
     */
    static const uint64_t n_minus_2[4] = {
        0xF3B9CAC2FC63254FULL, 0xBCE6FAADA7179E84ULL,
        0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFF00000000ULL
    };
    p256_fe_t base, result = {1, 0, 0, 0};
    memcpy(base, a, sizeof(p256_fe_t));
    for (int i = 0; i < 256; i++) {
        uint64_t bit = (n_minus_2[i / 64] >> (i % 64)) & 1;
        if (bit) mod_n_mul_p256(result, result, base);
        mod_n_mul_p256(base, base, base);
    }
    memcpy(r, result, sizeof(p256_fe_t));
}

/* RFC 6979 deterministic nonce generation */
static int rfc6979_generate_k(p256_fe_t k, const p256_fe_t private_key, const uint8_t *digest) {
    uint8_t v[32], K[32], temp[97], priv_bytes[32];
    size_t len = 32;

    memset(v, 0x01, 32);
    memset(K, 0x00, 32);

    /* Convert private key to bytes */
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 8; j++) {
            priv_bytes[i * 8 + j] = (private_key[3 - i] >> (56 - j * 8)) & 0xFF;
        }
    }

    /* RFC 6979 HMAC steps */
    memcpy(temp, v, 32); temp[32] = 0x00; memcpy(temp + 33, priv_bytes, 32); memcpy(temp + 65, digest, 32);
    opssl_hmac(OPSSL_HMAC_SHA256, K, 32, temp, 97, K, &len);
    len = 32; opssl_hmac(OPSSL_HMAC_SHA256, K, 32, v, 32, v, &len);

    memcpy(temp, v, 32); temp[32] = 0x01; memcpy(temp + 33, priv_bytes, 32); memcpy(temp + 65, digest, 32);
    len = 32; opssl_hmac(OPSSL_HMAC_SHA256, K, 32, temp, 97, K, &len);
    len = 32; opssl_hmac(OPSSL_HMAC_SHA256, K, 32, v, 32, v, &len);
    len = 32; opssl_hmac(OPSSL_HMAC_SHA256, K, 32, v, 32, temp, &len);

    for (int i = 0; i < 4; i++) {
        k[i] = 0;
        for (int j = 0; j < 8; j++)
            k[i] |= ((uint64_t)temp[(3 - i) * 8 + j]) << (56 - j * 8);
    }

    opssl_memzero(K, 32); opssl_memzero(v, 32); opssl_memzero(priv_bytes, 32);
    return OPSSL_SUCCESS;
}


/* ─── Point-on-curve validation ────────────────────────────────────────── */
/*
 * Verify that an affine point (x, y) lies on the curve y^2 = x^3 + ax + b
 * where a = -3 for all three NIST primes.
 * All inputs are in raw (non-Montgomery) form.
 * Returns 1 if the point is valid and on the curve, 0 otherwise.
 */

static int p256_point_on_curve(const p256_fe_t x_raw, const p256_fe_t y_raw) {
    /* P-256 b (raw little-endian limbs) */
    static const p256_fe_t b_raw = {
        0x3BCE3C3E27D2604BULL, 0x651D06B0CC53B0F6ULL,
        0xB3EBBD55769886BCULL, 0x5AC635D8AA3A93E7ULL
    };
    /* minus3 raw = p - 3 */
    static const p256_fe_t minus3_raw = {
        0xFFFFFFFFFFFFFFFCULL, 0x00000000FFFFFFFFULL,
        0x0000000000000000ULL, 0xFFFFFFFF00000001ULL
    };

    p256_fe_t x, y, b, m3;
    p256_fe_t lhs, rhs, t1, t2;

    /* Convert inputs to Montgomery form */
    p256_fe_to_mont(x, x_raw);
    p256_fe_to_mont(y, y_raw);
    p256_fe_to_mont(b, b_raw);
    p256_fe_to_mont(m3, minus3_raw);

    /* lhs = y^2 */
    p256_fe_sqr(lhs, y);

    /* rhs = x^3 + a*x + b = x^3 - 3*x + b */
    p256_fe_sqr(t1, x);             /* x^2 */
    p256_fe_mul(rhs, t1, x);        /* x^3 */
    p256_fe_mul(t2, m3, x);         /* -3*x */
    p256_fe_add(rhs, rhs, t2);      /* x^3 - 3*x */
    p256_fe_add(rhs, rhs, b);       /* x^3 - 3*x + b */

    /* Constant-time comparison: lhs == rhs */
    uint64_t diff = (lhs[0] ^ rhs[0]) | (lhs[1] ^ rhs[1]) |
                    (lhs[2] ^ rhs[2]) | (lhs[3] ^ rhs[3]);
    return diff == 0;
}

static int p384_point_on_curve(const p384_fe_t x_raw, const p384_fe_t y_raw) {
    /* P-384 b (raw little-endian limbs) */
    static const p384_fe_t b_raw = {
        0x2A85C8EDD3EC2AEFULL, 0xC656398D8A2ED19DULL,
        0x0314088F5013875AULL, 0x181D9C6EFE814112ULL,
        0x988E056BE3F82D19ULL, 0xB3312FA7E23EE7E4ULL
    };
    /* minus3 raw = p - 3 */
    static const p384_fe_t minus3_raw = {
        0x00000000FFFFFFFCULL, 0xFFFFFFFF00000000ULL,
        0xFFFFFFFFFFFFFFFEULL, 0xFFFFFFFFFFFFFFFFULL,
        0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL
    };

    p384_fe_t x, y, b, m3;
    p384_fe_t lhs, rhs, t1, t2;

    p384_fe_to_mont(x, x_raw);
    p384_fe_to_mont(y, y_raw);
    p384_fe_to_mont(b, b_raw);
    p384_fe_to_mont(m3, minus3_raw);

    p384_fe_mul(lhs, y, y);

    p384_fe_mul(t1, x, x);
    p384_fe_mul(rhs, t1, x);
    p384_fe_mul(t2, m3, x);
    p384_fe_add(rhs, rhs, t2);
    p384_fe_add(rhs, rhs, b);

    uint64_t diff = (lhs[0] ^ rhs[0]) | (lhs[1] ^ rhs[1]) | (lhs[2] ^ rhs[2]) |
                    (lhs[3] ^ rhs[3]) | (lhs[4] ^ rhs[4]) | (lhs[5] ^ rhs[5]);
    return diff == 0;
}

static int p521_point_on_curve(const p521_fe_t x_raw, const p521_fe_t y_raw) {
    /* P-521 b (raw little-endian limbs, 521 bits) */
    static const p521_fe_t b_raw = {
        0xEF451FD46B503F00ULL, 0x3573DF883D2C34F1ULL,
        0x1652C0BD3BB1BF07ULL, 0x56193951EC7E937BULL,
        0xB8B489918EF109E1ULL, 0xA2DA725B99B315F3ULL,
        0x929A21A0B68540EEULL, 0x953EB9618E1C9A1FULL,
        0x0000000000000051ULL
    };
    /* minus3 = p - 3: limb[0] -= 3 from all-ones, rest unchanged */
    static const p521_fe_t minus3_raw = {
        0xFFFFFFFFFFFFFFFCULL, 0xFFFFFFFFFFFFFFFFULL,
        0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL,
        0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL,
        0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL,
        0x00000000000001FFULL
    };
    /* P-521 uses raw (non-Montgomery) field arithmetic */
    p521_fe_t lhs, rhs, t1, t2;

    p521_fe_mul(lhs, y_raw, y_raw);

    p521_fe_mul(t1, x_raw, x_raw);
    p521_fe_mul(rhs, t1, x_raw);
    p521_fe_mul(t2, minus3_raw, x_raw);
    p521_fe_add(rhs, rhs, t2);
    p521_fe_add(rhs, rhs, b_raw);

    uint64_t diff = 0;
    for (int i = 0; i < 9; i++)
        diff |= (lhs[i] ^ rhs[i]);
    return diff == 0;
}

static int encode_point_uncompressed(uint8_t *out, size_t *out_len,
                                    const void *point, opssl_curve_t curve) {
    if (curve == OPSSL_CURVE_P256) {
        const p256_point_t *p = (const p256_point_t *)point;
        if (*out_len < 65) return 0;

        /* Convert from projective to affine: x = X/Z, y = Y/Z */
        p256_fe_t z_inv, x, y;
        p256_fe_inv(z_inv, p->z);
        p256_fe_mul(x, p->x, z_inv);
        p256_fe_mul(y, p->y, z_inv);
        p256_fe_from_mont(x, x);
        p256_fe_from_mont(y, y);

        out[0] = 0x04;
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 8; j++) {
                out[1 + i * 8 + j] = (x[3 - i] >> (56 - j * 8)) & 0xFF;
                out[33 + i * 8 + j] = (y[3 - i] >> (56 - j * 8)) & 0xFF;
            }
        }
        *out_len = 65;
        return 1;

    } else if (curve == OPSSL_CURVE_P384) {
        const p384_point_t *p = (const p384_point_t *)point;
        if (*out_len < 97) return 0;

        p384_fe_t z_inv, x, y;
        p384_fe_inv(z_inv, p->z);
        p384_fe_mul(x, p->x, z_inv);
        p384_fe_mul(y, p->y, z_inv);
        p384_fe_from_mont(x, x);
        p384_fe_from_mont(y, y);

        out[0] = 0x04;
        for (int i = 0; i < 6; i++) {
            for (int j = 0; j < 8; j++) {
                out[1 + i * 8 + j] = (x[5 - i] >> (56 - j * 8)) & 0xFF;
                out[49 + i * 8 + j] = (y[5 - i] >> (56 - j * 8)) & 0xFF;
            }
        }
        *out_len = 97;
        return 1;

    } else if (curve == OPSSL_CURVE_P521) {
        const p521_point_t *p = (const p521_point_t *)point;
        if (*out_len < 133) return 0;

        p521_fe_t z_inv, x, y;
        p521_fe_inv(z_inv, p->z);
        p521_fe_mul(x, p->x, z_inv);
        p521_fe_mul(y, p->y, z_inv);

        out[0] = 0x04;
        /* 66 big-endian bytes from 9 little-endian 64-bit limbs (521 bits) */
        for (int coord = 0; coord < 2; coord++) {
            const uint64_t *fe = coord == 0 ? x : y;
            uint8_t *dst = out + 1 + coord * 66;
            memset(dst, 0, 66);
            /* Limbs 0..7 → bytes. Byte 65 is lowest byte of limb[0]. */
            for (int i = 0; i < 8; i++) {
                for (int j = 0; j < 8; j++)
                    dst[65 - i * 8 - j] = (fe[i] >> (j * 8)) & 0xFF;
            }
            /* Limb 8 has at most 9 bits → byte 1 = low 8 bits, byte 0 = bit 8 */
            dst[1] = fe[8] & 0xFF;
            dst[0] = (fe[8] >> 8) & 0xFF;
        }
        *out_len = 133;
        return 1;
    }

    return 0;
}


opssl_ecdh_ctx_t *opssl_ecdh_new(opssl_curve_t curve) {
    opssl_ecdh_ctx_t *ctx = op_malloc(sizeof(opssl_ecdh_ctx_t));
    if (!ctx) return NULL;

    opssl_memzero(ctx, sizeof(opssl_ecdh_ctx_t));
    ctx->curve = curve;
    return ctx;
}

int opssl_ecdh_keygen(opssl_ecdh_ctx_t *ctx) {
    if (!ctx) return 0;

    if (ctx->curve == OPSSL_CURVE_P256) {
        uint8_t key_bytes[32];
        if (opssl_random_bytes(key_bytes, 32) != 0) return 0;

        for (int i = 0; i < 4; i++) {
            ctx->key.p256.private_key[i] = 0;
            for (int j = 0; j < 8; j++)
                ctx->key.p256.private_key[i] |=
                    ((uint64_t)key_bytes[(3 - i) * 8 + j]) << (56 - j * 8);
        }

        p256_point_mul(&ctx->key.p256.public_key, ctx->key.p256.private_key, &p256_g);

        ctx->has_private = 1;
        ctx->has_public = 1;
        return 1;

    } else if (ctx->curve == OPSSL_CURVE_P384) {
        uint8_t key_bytes[48];
        if (opssl_random_bytes(key_bytes, 48) != 0) return 0;

        for (int i = 0; i < 6; i++) {
            ctx->key.p384.private_key[i] = 0;
            for (int j = 0; j < 8; j++)
                ctx->key.p384.private_key[i] |=
                    ((uint64_t)key_bytes[(5 - i) * 8 + j]) << (56 - j * 8);
        }

        p384_point_mul(&ctx->key.p384.public_key, ctx->key.p384.private_key, &p384_g);

        ctx->has_private = 1;
        ctx->has_public = 1;
        return 1;

    } else if (ctx->curve == OPSSL_CURVE_P521) {
        uint8_t key_bytes[66];
        if (opssl_random_bytes(key_bytes, 66) != 0) return 0;
        key_bytes[0] &= 0x01;

        for (int i = 0; i < 8; i++) {
            ctx->key.p521.private_key[i] = 0;
            for (int j = 0; j < 8; j++)
                ctx->key.p521.private_key[i] |=
                    ((uint64_t)key_bytes[(7 - i) * 8 + 2 + j]) << (56 - j * 8);
        }
        ctx->key.p521.private_key[8] = ((uint64_t)key_bytes[0] << 8) | key_bytes[1];
        ctx->key.p521.private_key[8] &= 0x1FFULL;

        p521_point_mul(&ctx->key.p521.public_key, ctx->key.p521.private_key, &p521_g);

        ctx->has_private = 1;
        ctx->has_public = 1;
        return 1;
    }

    return 0;
}

int opssl_ecdh_get_public(opssl_ecdh_ctx_t *ctx, uint8_t *pub, size_t *pub_len) {
    if (!ctx || !pub || !pub_len || !ctx->has_public) return 0;

    if (ctx->curve == OPSSL_CURVE_P256) {
        return encode_point_uncompressed(pub, pub_len, &ctx->key.p256.public_key, ctx->curve);
    } else if (ctx->curve == OPSSL_CURVE_P384) {
        return encode_point_uncompressed(pub, pub_len, &ctx->key.p384.public_key, ctx->curve);
    } else if (ctx->curve == OPSSL_CURVE_P521) {
        return encode_point_uncompressed(pub, pub_len, &ctx->key.p521.public_key, ctx->curve);
    }

    return 0;
}

int opssl_ecdh_derive(opssl_ecdh_ctx_t *ctx, const uint8_t *peer_pub, size_t peer_pub_len,
                      uint8_t *shared, size_t *shared_len) {
    if (!ctx || !peer_pub || !shared || !shared_len || !ctx->has_private)
        return 0;

    if (ctx->curve == OPSSL_CURVE_P256 && peer_pub_len == 65 && peer_pub[0] == 0x04) {
        if (*shared_len < 32) return 0;

        /* Decode peer public key (big-endian bytes → little-endian limbs) */
        p256_point_t peer_point;
        p256_fe_t x_coord, y_coord;
        for (int i = 0; i < 4; i++) {
            x_coord[i] = 0;
            y_coord[i] = 0;
            for (int j = 0; j < 8; j++) {
                x_coord[i] |= ((uint64_t)peer_pub[1 + (3 - i) * 8 + j]) << (56 - j * 8);
                y_coord[i] |= ((uint64_t)peer_pub[33 + (3 - i) * 8 + j]) << (56 - j * 8);
            }
        }

        /* Reject points not on the curve (invalid-curve attack defense) */
        if (!p256_point_on_curve(x_coord, y_coord))
            return 0;

        /* Convert to Montgomery form */
        p256_fe_to_mont(peer_point.x, x_coord);
        p256_fe_to_mont(peer_point.y, y_coord);
        /* Set Z = 1 in Montgomery form */
        peer_point.z[0] = 1;
        peer_point.z[1] = 0xFFFFFFFF00000000ULL;
        peer_point.z[2] = 0xFFFFFFFFFFFFFFFFULL;
        peer_point.z[3] = 0x00000000FFFFFFFEULL;

        /* Shared secret = private_key * peer_public_point */
        p256_point_t shared_point;
        p256_point_mul(&shared_point, ctx->key.p256.private_key, &peer_point);

        /* Convert from projective to affine: x = X / Z */
        p256_fe_t z_inv, shared_x;
        p256_fe_inv(z_inv, shared_point.z);
        p256_fe_mul(shared_x, shared_point.x, z_inv);
        p256_fe_from_mont(shared_x, shared_x);

        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 8; j++) {
                shared[i * 8 + j] = (shared_x[3 - i] >> (56 - j * 8)) & 0xFF;
            }
        }

        *shared_len = 32;
        return 1;
    }

    if (ctx->curve == OPSSL_CURVE_P384 && peer_pub_len == 97 && peer_pub[0] == 0x04) {
        if (*shared_len < 48) return 0;

        /* Decode peer public key (big-endian bytes → limbs) */
        p384_point_t peer_point;
        p384_fe_t x_coord, y_coord;
        for (int i = 0; i < 6; i++) {
            x_coord[i] = 0;
            y_coord[i] = 0;
            for (int j = 0; j < 8; j++) {
                x_coord[i] |= ((uint64_t)peer_pub[1 + (5 - i) * 8 + j]) << (56 - j * 8);
                y_coord[i] |= ((uint64_t)peer_pub[49 + (5 - i) * 8 + j]) << (56 - j * 8);
            }
        }

        /* Reject points not on the curve (invalid-curve attack defense) */
        if (!p384_point_on_curve(x_coord, y_coord))
            return 0;

        /* Convert to Montgomery form */
        p384_fe_to_mont(peer_point.x, x_coord);
        p384_fe_to_mont(peer_point.y, y_coord);
        /* Z = R mod p (Montgomery representation of 1) */
        peer_point.z[0] = 0xFFFFFFFF00000001ULL;
        peer_point.z[1] = 0x00000000FFFFFFFFULL;
        peer_point.z[2] = 0x0000000000000001ULL;
        peer_point.z[3] = 0;
        peer_point.z[4] = 0;
        peer_point.z[5] = 0;

        /* Shared secret = private_key * peer_public_point */
        p384_point_t shared_point;
        p384_point_mul(&shared_point, ctx->key.p384.private_key, &peer_point);

        /* Convert from projective to affine: x = X / Z */
        p384_fe_t z_inv, shared_x;
        p384_fe_inv(z_inv, shared_point.z);
        p384_fe_mul(shared_x, shared_point.x, z_inv);
        p384_fe_from_mont(shared_x, shared_x);

        for (int i = 0; i < 6; i++) {
            for (int j = 0; j < 8; j++) {
                shared[i * 8 + j] = (shared_x[5 - i] >> (56 - j * 8)) & 0xFF;
            }
        }

        *shared_len = 48;
        return 1;
    }

    if (ctx->curve == OPSSL_CURVE_P521 && peer_pub_len == 133 && peer_pub[0] == 0x04) {
        if (*shared_len < 66) return 0;

        /* Decode 66 big-endian bytes → 9 little-endian 64-bit limbs */
        p521_point_t peer_point;
        for (int coord = 0; coord < 2; coord++) {
            const uint8_t *src = peer_pub + 1 + coord * 66;
            uint64_t *fe = coord == 0 ? peer_point.x : peer_point.y;
            memset(fe, 0, 9 * sizeof(uint64_t));
            for (int i = 0; i < 8; i++)
                for (int j = 0; j < 8; j++)
                    fe[i] |= ((uint64_t)src[65 - i * 8 - j]) << (j * 8);
            fe[8] = ((uint64_t)src[0] << 8) | src[1];
        }

        /* Reject points not on the curve (invalid-curve attack defense) */
        if (!p521_point_on_curve(peer_point.x, peer_point.y))
            return 0;

        peer_point.z[0] = 1;
        for (int i = 1; i < 9; i++) peer_point.z[i] = 0;

        p521_point_t shared_point;
        p521_point_mul(&shared_point, ctx->key.p521.private_key, &peer_point);

        p521_fe_t z_inv, shared_x;
        p521_fe_inv(z_inv, shared_point.z);
        p521_fe_mul(shared_x, shared_point.x, z_inv);

        /* Serialize affine x to 66 big-endian bytes */
        memset(shared, 0, 66);
        for (int i = 0; i < 8; i++)
            for (int j = 0; j < 8; j++)
                shared[65 - i * 8 - j] = (shared_x[i] >> (j * 8)) & 0xFF;
        shared[1] = shared_x[8] & 0xFF;
        shared[0] = (shared_x[8] >> 8) & 0xFF;

        *shared_len = 66;
        return 1;
    }

    return 0;
}

void opssl_ecdh_free(opssl_ecdh_ctx_t *ctx) {
    if (ctx) {
        opssl_memzero(ctx, sizeof(opssl_ecdh_ctx_t));
        op_free(ctx);
    }
}


opssl_ecdsa_ctx_t *opssl_ecdsa_new(opssl_curve_t curve) {
    opssl_ecdsa_ctx_t *ctx = op_malloc(sizeof(opssl_ecdsa_ctx_t));
    if (!ctx) return NULL;

    opssl_memzero(ctx, sizeof(opssl_ecdsa_ctx_t));
    ctx->curve = curve;
    return ctx;
}

int opssl_ecdsa_keygen(opssl_ecdsa_ctx_t *ctx) {
    if (!ctx) return 0;

    if (ctx->curve == OPSSL_CURVE_P256) {
        uint8_t key_bytes[32];
        if (opssl_random_bytes(key_bytes, 32) != 0) return 0;

        for (int i = 0; i < 4; i++) {
            ctx->key.p256.private_key[i] = 0;
            for (int j = 0; j < 8; j++)
                ctx->key.p256.private_key[i] |=
                    ((uint64_t)key_bytes[(3 - i) * 8 + j]) << (56 - j * 8);
        }

        p256_point_mul(&ctx->key.p256.public_key, ctx->key.p256.private_key, &p256_g);

        ctx->has_private = 1;
        ctx->has_public = 1;
        return 1;

    } else if (ctx->curve == OPSSL_CURVE_P384) {
        uint8_t key_bytes[48];
        if (opssl_random_bytes(key_bytes, 48) != 0) return 0;

        for (int i = 0; i < 6; i++) {
            ctx->key.p384.private_key[i] = 0;
            for (int j = 0; j < 8; j++)
                ctx->key.p384.private_key[i] |=
                    ((uint64_t)key_bytes[(5 - i) * 8 + j]) << (56 - j * 8);
        }

        p384_point_mul(&ctx->key.p384.public_key, ctx->key.p384.private_key, &p384_g);

        ctx->has_private = 1;
        ctx->has_public = 1;
        return 1;
    } else if (ctx->curve == OPSSL_CURVE_P521) {
        uint8_t key_bytes[66];
        if (opssl_random_bytes(key_bytes, 66) != 0) return 0;
        key_bytes[0] &= 0x01;

        for (int i = 0; i < 8; i++) {
            ctx->key.p521.private_key[i] = 0;
            for (int j = 0; j < 8; j++)
                ctx->key.p521.private_key[i] |=
                    ((uint64_t)key_bytes[65 - i * 8 - j]) << (j * 8);
        }
        ctx->key.p521.private_key[8] = ((uint64_t)key_bytes[0] << 8) | key_bytes[1];
        ctx->key.p521.private_key[8] &= 0x1FFULL;

        p521_point_mul(&ctx->key.p521.public_key, ctx->key.p521.private_key, &p521_g);

        ctx->has_private = 1;
        ctx->has_public = 1;
        return 1;
    }

    return 0;
}

int opssl_ecdsa_sign(opssl_ecdsa_ctx_t *ctx, const uint8_t *digest, size_t digest_len,
                     uint8_t *sig, size_t *sig_len) {
    if (!ctx || !digest || !sig || !sig_len || !ctx->has_private)
        return 0;

    if (ctx->curve == OPSSL_CURVE_P256 && digest_len == 32) {
        if (*sig_len < 72) return 0; /* Max DER size */

        /* RFC 6979 deterministic k generation */
        p256_fe_t k;
        if (rfc6979_generate_k(k, ctx->key.p256.private_key, digest) != OPSSL_SUCCESS) {
            return 0;
        }

        /* Compute R = k * G */
        p256_point_t R;
        p256_point_mul(&R, k, &p256_g);

        /* Extract r = R.x mod n (convert from projective to affine first) */
        p256_fe_t r, r_affine, z_inv;
        p256_fe_inv(z_inv, R.z);
        p256_fe_mul(r_affine, R.x, z_inv);
        p256_fe_from_mont(r_affine, r_affine);
        uint64_t r_ext[8] = {r_affine[0], r_affine[1], r_affine[2], r_affine[3], 0, 0, 0, 0};
        mod_n_reduce_p256(r, r_ext);

        /* Check r != 0 (simplified) */
        if ((r[0] | r[1] | r[2] | r[3]) == 0) return 0;

        /* Convert digest to field element (big-endian bytes → little-endian limbs) */
        p256_fe_t h;
        for (int i = 0; i < 4; i++) {
            h[i] = 0;
            for (int j = 0; j < 8; j++)
                h[i] |= ((uint64_t)digest[(3 - i) * 8 + j]) << (56 - j * 8);
        }

        /* Compute s = k^(-1) * (h + r * private_key) mod n */
        p256_fe_t k_inv, r_sk, h_plus_r_sk, s;
        mod_n_inv_p256(k_inv, k);
        mod_n_mul_p256(r_sk, r, ctx->key.p256.private_key);
        mod_n_add_p256(h_plus_r_sk, h, r_sk);
        mod_n_mul_p256(s, k_inv, h_plus_r_sk);

        /* Check s != 0 */
        if ((s[0] | s[1] | s[2] | s[3]) == 0) return 0;

        /* Convert r and s to bytes */
        uint8_t r_bytes[32], s_bytes[32];
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 8; j++) {
                r_bytes[i * 8 + j] = (r[3 - i] >> (56 - j * 8)) & 0xFF;
                s_bytes[i * 8 + j] = (s[3 - i] >> (56 - j * 8)) & 0xFF;
            }
        }

        /* DER encode signature */
        uint8_t r_der[34], s_der[34];
        size_t r_der_len = der_encode_integer(r_der, r_bytes, 32);
        size_t s_der_len = der_encode_integer(s_der, s_bytes, 32);

        size_t total_len = 2 + r_der_len + s_der_len;
        if (*sig_len < total_len) return 0;

        sig[0] = 0x30;
        sig[1] = r_der_len + s_der_len;
        memcpy(sig + 2, r_der, r_der_len);
        memcpy(sig + 2 + r_der_len, s_der, s_der_len);

        *sig_len = total_len;

        /* Clear sensitive data */
        opssl_memzero(k, sizeof(k));
        opssl_memzero(k_inv, sizeof(k_inv));

        return 1; /* Success */
    }

    if (ctx->curve == OPSSL_CURVE_P384 && digest_len == 48) {
        if (*sig_len < 104) return 0;

        opssl_bn_t n, k_bn, sk_bn, r_bn, s_bn, h_bn, kinv_bn, tmp_bn;
        opssl_bn_zero(&n, 6);
        for (int i = 0; i < 6; i++) n.d[i] = p384_n[i];
        n.width = 6;

        uint8_t k_bytes[48];
        int attempts = 0;
        do {
            if (opssl_random_bytes(k_bytes, 48) != 0) return 0;
            opssl_bn_from_bytes(&k_bn, k_bytes, 48);
            k_bn.width = 6;
            if (attempts++ > 100) return 0;
        } while (opssl_bn_is_zero(&k_bn, 6) || opssl_bn_cmp(&k_bn, &n, 6) >= 0);

        p384_fe_t k;
        for (int i = 0; i < 6; i++) k[i] = k_bn.d[i];

        p384_point_t R;
        p384_point_mul(&R, k, &p384_g);

        p384_fe_t z_inv, r_affine;
        p384_fe_inv(z_inv, R.z);
        p384_fe_mul(r_affine, R.x, z_inv);
        p384_fe_from_mont(r_affine, r_affine);

        opssl_bn_zero(&r_bn, 6);
        for (int i = 0; i < 6; i++) r_bn.d[i] = r_affine[i];
        r_bn.width = 6;
        while (opssl_bn_cmp(&r_bn, &n, 6) >= 0)
            opssl_bn_sub(&r_bn, &r_bn, &n, 6);
        if (opssl_bn_is_zero(&r_bn, 6))
            return opssl_ecdsa_sign(ctx, digest, digest_len, sig, sig_len);

        opssl_bn_mont_ctx_t mont_n;
        opssl_bn_mont_ctx_init(&mont_n, &n, 6);

        opssl_bn_zero(&sk_bn, 6);
        for (int i = 0; i < 6; i++) sk_bn.d[i] = ctx->key.p384.private_key[i];
        sk_bn.width = 6;

        opssl_bn_from_bytes(&h_bn, digest, 48);
        h_bn.width = 6;
        while (opssl_bn_cmp(&h_bn, &n, 6) >= 0)
            opssl_bn_sub(&h_bn, &h_bn, &n, 6);

        if (!opssl_bn_mod_inv(&kinv_bn, &k_bn, &n, &mont_n)) return 0;
        opssl_bn_mod_mul(&tmp_bn, &r_bn, &sk_bn, &mont_n);

        uint64_t carry = opssl_bn_add(&tmp_bn, &tmp_bn, &h_bn, 6);
        if (carry || opssl_bn_cmp(&tmp_bn, &n, 6) >= 0)
            opssl_bn_sub(&tmp_bn, &tmp_bn, &n, 6);

        opssl_bn_mod_mul(&s_bn, &kinv_bn, &tmp_bn, &mont_n);
        if (opssl_bn_is_zero(&s_bn, 6))
            return opssl_ecdsa_sign(ctx, digest, digest_len, sig, sig_len);

        uint8_t rb[48], sb[48];
        opssl_bn_to_bytes(rb, 48, &r_bn);
        opssl_bn_to_bytes(sb, 48, &s_bn);

        uint8_t r_der[52], s_der[52];
        size_t r_der_len = der_encode_integer(r_der, rb, 48);
        size_t s_der_len = der_encode_integer(s_der, sb, 48);
        size_t seq_len = r_der_len + s_der_len;
        size_t header_len = (seq_len >= 128) ? 3 : 2;
        size_t total_len = header_len + seq_len;
        if (*sig_len < total_len) return 0;

        sig[0] = 0x30;
        if (seq_len >= 128) {
            sig[1] = 0x81;
            sig[2] = (uint8_t)seq_len;
        } else {
            sig[1] = (uint8_t)seq_len;
        }
        memcpy(sig + header_len, r_der, r_der_len);
        memcpy(sig + header_len + r_der_len, s_der, s_der_len);
        *sig_len = total_len;

        opssl_memzero(&k_bn, sizeof(k_bn));
        opssl_memzero(&kinv_bn, sizeof(kinv_bn));
        return 1;
    }

    if (ctx->curve == OPSSL_CURVE_P521 && digest_len == 64) {
        if (*sig_len < 142) return 0;

        opssl_bn_t n, k_bn, sk_bn, r_bn, s_bn, h_bn, kinv_bn, tmp_bn;
        opssl_bn_zero(&n, 9);
        for (int i = 0; i < 9; i++) n.d[i] = p521_n[i];
        n.width = 9;

        uint8_t k_bytes[66];
        int attempts = 0;
        do {
            if (opssl_random_bytes(k_bytes, 66) != 0) return 0;
            k_bytes[0] &= 0x01;
            opssl_bn_from_bytes(&k_bn, k_bytes, 66);
            k_bn.width = 9;
            if (attempts++ > 100) return 0;
        } while (opssl_bn_is_zero(&k_bn, 9) || opssl_bn_cmp(&k_bn, &n, 9) >= 0);

        p521_fe_t k;
        for (int i = 0; i < 9; i++) k[i] = k_bn.d[i];

        p521_point_t R;
        p521_point_mul(&R, k, &p521_g);

        p521_fe_t z_inv, r_affine;
        p521_fe_inv(z_inv, R.z);
        p521_fe_mul(r_affine, R.x, z_inv);

        opssl_bn_zero(&r_bn, 9);
        for (int i = 0; i < 9; i++) r_bn.d[i] = r_affine[i];
        r_bn.width = 9;
        while (opssl_bn_cmp(&r_bn, &n, 9) >= 0)
            opssl_bn_sub(&r_bn, &r_bn, &n, 9);
        if (opssl_bn_is_zero(&r_bn, 9))
            return opssl_ecdsa_sign(ctx, digest, digest_len, sig, sig_len);

        opssl_bn_mont_ctx_t mont_n;
        opssl_bn_mont_ctx_init(&mont_n, &n, 9);

        opssl_bn_zero(&sk_bn, 9);
        for (int i = 0; i < 9; i++) sk_bn.d[i] = ctx->key.p521.private_key[i];
        sk_bn.width = 9;

        opssl_bn_from_bytes(&h_bn, digest, 64);
        h_bn.width = 9;
        while (opssl_bn_cmp(&h_bn, &n, 9) >= 0)
            opssl_bn_sub(&h_bn, &h_bn, &n, 9);

        if (!opssl_bn_mod_inv(&kinv_bn, &k_bn, &n, &mont_n)) return 0;
        opssl_bn_mod_mul(&tmp_bn, &r_bn, &sk_bn, &mont_n);

        uint64_t carry = opssl_bn_add(&tmp_bn, &tmp_bn, &h_bn, 9);
        if (carry || opssl_bn_cmp(&tmp_bn, &n, 9) >= 0)
            opssl_bn_sub(&tmp_bn, &tmp_bn, &n, 9);

        opssl_bn_mod_mul(&s_bn, &kinv_bn, &tmp_bn, &mont_n);
        if (opssl_bn_is_zero(&s_bn, 9))
            return opssl_ecdsa_sign(ctx, digest, digest_len, sig, sig_len);

        uint8_t rb[66], sb[66];
        opssl_bn_to_bytes(rb, 66, &r_bn);
        opssl_bn_to_bytes(sb, 66, &s_bn);

        uint8_t r_der[70], s_der[70];
        size_t r_der_len = der_encode_integer(r_der, rb, 66);
        size_t s_der_len = der_encode_integer(s_der, sb, 66);
        size_t seq_len = r_der_len + s_der_len;
        size_t header_len = (seq_len >= 128) ? 3 : 2;
        size_t total_len = header_len + seq_len;
        if (*sig_len < total_len) return 0;

        sig[0] = 0x30;
        if (seq_len >= 128) {
            sig[1] = 0x81;
            sig[2] = (uint8_t)seq_len;
        } else {
            sig[1] = (uint8_t)seq_len;
        }
        memcpy(sig + header_len, r_der, r_der_len);
        memcpy(sig + header_len + r_der_len, s_der, s_der_len);
        *sig_len = total_len;

        opssl_memzero(&k_bn, sizeof(k_bn));
        opssl_memzero(&kinv_bn, sizeof(kinv_bn));
        return 1;
    }

    return 0;
}

int opssl_ecdsa_verify(opssl_ecdsa_ctx_t *ctx, const uint8_t *digest, size_t digest_len,
                       const uint8_t *sig, size_t sig_len) {
    if (!ctx || !digest || !sig || !ctx->has_public)
        return 0;

    if (ctx->curve == OPSSL_CURVE_P256 && digest_len == 32) {
        /* Parse DER signature */
        if (sig_len < 6 || sig[0] != 0x30) return 0;

        size_t seq_len = sig[1];
        if (seq_len + 2 != sig_len) return 0;

        /* Parse r */
        uint8_t r_bytes[32] = {0};
        size_t r_len = 32;
        const uint8_t *r_der = sig + 2;
        if (der_decode_integer(r_der, seq_len, r_bytes, &r_len) != OPSSL_SUCCESS) {
            return 0;
        }

        /* Parse s */
        uint8_t s_bytes[32] = {0};
        size_t s_len = 32;
        size_t r_der_len = r_der[1] + 2;
        const uint8_t *s_der = r_der + r_der_len;
        size_t s_der_remaining = seq_len - r_der_len;
        if (der_decode_integer(s_der, s_der_remaining, s_bytes, &s_len) != OPSSL_SUCCESS) {
            return 0;
        }

        /* Convert to field elements */
        p256_fe_t r, s;
        for (int i = 0; i < 4; i++) {
            r[i] = 0;
            s[i] = 0;
            for (int j = 0; j < 8; j++) {
                size_t off = (size_t)(i * 8 + j);
                if (off < r_len) {
                    r[i] |= ((uint64_t)r_bytes[r_len - 1 - off]) << (j * 8);
                }
                if (off < s_len) {
                    s[i] |= ((uint64_t)s_bytes[s_len - 1 - off]) << (j * 8);
                }
            }
        }

        /* Check r and s are valid (non-zero) */
        if ((r[0] | r[1] | r[2] | r[3]) == 0 || (s[0] | s[1] | s[2] | s[3]) == 0) return 0;

        /* Convert digest to field element (big-endian bytes → little-endian limbs) */
        p256_fe_t h;
        for (int i = 0; i < 4; i++) {
            h[i] = 0;
            for (int j = 0; j < 8; j++)
                h[i] |= ((uint64_t)digest[(3 - i) * 8 + j]) << (56 - j * 8);
        }

        /* Compute w = s^(-1) mod n */
        p256_fe_t w;
        mod_n_inv_p256(w, s);

        /* Compute u1 = h * w mod n and u2 = r * w mod n */
        p256_fe_t u1, u2;
        mod_n_mul_p256(u1, h, w);
        mod_n_mul_p256(u2, r, w);

        /* Compute R = u1*G + u2*Q */
        p256_point_t u1G, u2Q, R;
        p256_point_mul(&u1G, u1, &p256_g);
        p256_point_mul(&u2Q, u2, &ctx->key.p256.public_key);
        p256_point_add(&R, &u1G, &u2Q);

        /* Convert to affine coordinates and get x coordinate */
        p256_fe_t z_inv, x_affine;
        p256_fe_inv(z_inv, R.z);
        p256_fe_mul(x_affine, R.x, z_inv);
        p256_fe_from_mont(x_affine, x_affine);

        /* Reduce x coordinate mod n */
        p256_fe_t x_mod_n;
        uint64_t x_ext[8] = {x_affine[0], x_affine[1], x_affine[2], x_affine[3], 0, 0, 0, 0};
        mod_n_reduce_p256(x_mod_n, x_ext);

        uint64_t diff_check = (x_mod_n[0] ^ r[0]) | (x_mod_n[1] ^ r[1]) | (x_mod_n[2] ^ r[2]) | (x_mod_n[3] ^ r[3]);
        return diff_check == 0 ? 1 : 0;
    }

    if (ctx->curve == OPSSL_CURVE_P384 && digest_len == 48) {
        if (sig_len < 8) return 0;

        size_t seq_hdr_len, seq_len;
        if (!der_decode_sequence_header(sig, sig_len, &seq_hdr_len, &seq_len))
            return 0;

        uint8_t r_bytes[48] = {0};
        size_t r_len = sizeof(r_bytes);
        const uint8_t *r_der = sig + seq_hdr_len;
        if (der_decode_integer(r_der, seq_len, r_bytes, &r_len) != OPSSL_SUCCESS)
            return 0;

        size_t r_der_len = r_der[1] + 2;
        if (r_der_len >= seq_len) return 0;
        const uint8_t *s_der = r_der + r_der_len;
        size_t s_der_remaining = seq_len - r_der_len;
        uint8_t s_bytes[48] = {0};
        size_t s_len = sizeof(s_bytes);
        if (der_decode_integer(s_der, s_der_remaining, s_bytes, &s_len) != OPSSL_SUCCESS)
            return 0;

        opssl_bn_t n, r_bn, s_bn, h_bn, w_bn, u1_bn, u2_bn, x_bn, sk_bn, tmp_bn, k_bn;
        opssl_bn_zero(&n, 6);
        for (int i = 0; i < 6; i++) n.d[i] = p384_n[i];
        n.width = 6;

        opssl_bn_from_bytes(&r_bn, r_bytes, r_len);
        opssl_bn_from_bytes(&s_bn, s_bytes, s_len);
        opssl_bn_from_bytes(&h_bn, digest, digest_len);
        r_bn.width = s_bn.width = h_bn.width = 6;
        while (opssl_bn_cmp(&h_bn, &n, 6) >= 0)
            opssl_bn_sub(&h_bn, &h_bn, &n, 6);

        if (opssl_bn_is_zero(&r_bn, 6) || opssl_bn_is_zero(&s_bn, 6) ||
            opssl_bn_cmp(&r_bn, &n, 6) >= 0 || opssl_bn_cmp(&s_bn, &n, 6) >= 0)
            return 0;

        opssl_bn_mont_ctx_t mont_n;
        opssl_bn_mont_ctx_init(&mont_n, &n, 6);
        if (!opssl_bn_mod_inv(&w_bn, &s_bn, &n, &mont_n))
            return 0;

        if (ctx->has_private) {
            opssl_bn_zero(&sk_bn, 6);
            for (int i = 0; i < 6; i++) sk_bn.d[i] = ctx->key.p384.private_key[i];
            sk_bn.width = 6;

            opssl_bn_mod_mul(&tmp_bn, &r_bn, &sk_bn, &mont_n);
            uint64_t carry = opssl_bn_add(&tmp_bn, &tmp_bn, &h_bn, 6);
            if (carry || opssl_bn_cmp(&tmp_bn, &n, 6) >= 0)
                opssl_bn_sub(&tmp_bn, &tmp_bn, &n, 6);
            opssl_bn_mod_mul(&k_bn, &tmp_bn, &w_bn, &mont_n);

            p384_fe_t k;
            for (int i = 0; i < 6; i++) k[i] = k_bn.d[i];

            p384_point_t Rk;
            p384_point_mul(&Rk, k, &p384_g);

            p384_fe_t z_inv_k, x_affine_k;
            p384_fe_inv(z_inv_k, Rk.z);
            p384_fe_mul(x_affine_k, Rk.x, z_inv_k);
            p384_fe_from_mont(x_affine_k, x_affine_k);

            opssl_bn_zero(&x_bn, 6);
            for (int i = 0; i < 6; i++) x_bn.d[i] = x_affine_k[i];
            x_bn.width = 6;
            while (opssl_bn_cmp(&x_bn, &n, 6) >= 0)
                opssl_bn_sub(&x_bn, &x_bn, &n, 6);

            return opssl_bn_cmp(&x_bn, &r_bn, 6) == 0 ? 1 : 0;
        }

        opssl_bn_mod_mul(&u1_bn, &h_bn, &w_bn, &mont_n);
        opssl_bn_mod_mul(&u2_bn, &r_bn, &w_bn, &mont_n);

        p384_fe_t u1, u2;
        for (int i = 0; i < 6; i++) {
            u1[i] = u1_bn.d[i];
            u2[i] = u2_bn.d[i];
        }

        p384_point_t u1G, u2Q, R;
        p384_point_mul(&u1G, u1, &p384_g);
        p384_point_mul(&u2Q, u2, &ctx->key.p384.public_key);
        p384_point_add(&R, &u1G, &u2Q);

        p384_fe_t z_inv, x_affine;
        p384_fe_inv(z_inv, R.z);
        p384_fe_mul(x_affine, R.x, z_inv);
        p384_fe_from_mont(x_affine, x_affine);

        opssl_bn_zero(&x_bn, 6);
        for (int i = 0; i < 6; i++) x_bn.d[i] = x_affine[i];
        x_bn.width = 6;
        while (opssl_bn_cmp(&x_bn, &n, 6) >= 0)
            opssl_bn_sub(&x_bn, &x_bn, &n, 6);

        return opssl_bn_cmp(&x_bn, &r_bn, 6) == 0 ? 1 : 0;
    }

    if (ctx->curve == OPSSL_CURVE_P521 && digest_len == 64) {
        if (sig_len < 8) return 0;

        size_t seq_hdr_len, seq_len;
        if (!der_decode_sequence_header(sig, sig_len, &seq_hdr_len, &seq_len))
            return 0;

        uint8_t r_bytes[66] = {0};
        size_t r_len = sizeof(r_bytes);
        const uint8_t *r_der = sig + seq_hdr_len;
        if (der_decode_integer(r_der, seq_len, r_bytes, &r_len) != OPSSL_SUCCESS)
            return 0;

        size_t r_der_len = r_der[1] + 2;
        if (r_der_len >= seq_len) return 0;
        const uint8_t *s_der = r_der + r_der_len;
        size_t s_der_remaining = seq_len - r_der_len;
        uint8_t s_bytes[66] = {0};
        size_t s_len = sizeof(s_bytes);
        if (der_decode_integer(s_der, s_der_remaining, s_bytes, &s_len) != OPSSL_SUCCESS)
            return 0;

        opssl_bn_t n, r_bn, s_bn, h_bn, w_bn, u1_bn, u2_bn, x_bn;
        opssl_bn_zero(&n, 9);
        for (int i = 0; i < 9; i++) n.d[i] = p521_n[i];
        n.width = 9;

        opssl_bn_from_bytes(&r_bn, r_bytes, r_len);
        opssl_bn_from_bytes(&s_bn, s_bytes, s_len);
        opssl_bn_from_bytes(&h_bn, digest, digest_len);
        r_bn.width = s_bn.width = h_bn.width = 9;
        while (opssl_bn_cmp(&h_bn, &n, 9) >= 0)
            opssl_bn_sub(&h_bn, &h_bn, &n, 9);

        if (opssl_bn_is_zero(&r_bn, 9) || opssl_bn_is_zero(&s_bn, 9) ||
            opssl_bn_cmp(&r_bn, &n, 9) >= 0 || opssl_bn_cmp(&s_bn, &n, 9) >= 0)
            return 0;

        opssl_bn_mont_ctx_t mont_n;
        opssl_bn_mont_ctx_init(&mont_n, &n, 9);
        if (!opssl_bn_mod_inv(&w_bn, &s_bn, &n, &mont_n))
            return 0;
        opssl_bn_mod_mul(&u1_bn, &h_bn, &w_bn, &mont_n);
        opssl_bn_mod_mul(&u2_bn, &r_bn, &w_bn, &mont_n);

        p521_fe_t u1, u2;
        for (int i = 0; i < 9; i++) {
            u1[i] = u1_bn.d[i];
            u2[i] = u2_bn.d[i];
        }

        p521_point_t u1G, u2Q, R;
        p521_point_mul(&u1G, u1, &p521_g);
        p521_point_mul(&u2Q, u2, &ctx->key.p521.public_key);
        p521_point_add(&R, &u1G, &u2Q);

        p521_fe_t z_inv, x_affine;
        p521_fe_inv(z_inv, R.z);
        p521_fe_mul(x_affine, R.x, z_inv);

        opssl_bn_zero(&x_bn, 9);
        for (int i = 0; i < 9; i++) x_bn.d[i] = x_affine[i];
        x_bn.width = 9;
        while (opssl_bn_cmp(&x_bn, &n, 9) >= 0)
            opssl_bn_sub(&x_bn, &x_bn, &n, 9);

        return opssl_bn_cmp(&x_bn, &r_bn, 9) == 0 ? 1 : 0;
    }

    return 0;
}

int opssl_ecdsa_set_public(opssl_ecdsa_ctx_t *ctx, const uint8_t *pub, size_t pub_len) {
    if (!ctx || !pub) return 0;

    if (ctx->curve == OPSSL_CURVE_P256 && pub_len == 65 && pub[0] == 0x04) {
        p256_fe_t x_coord, y_coord;

        for (int i = 0; i < 4; i++) {
            x_coord[i] = 0;
            y_coord[i] = 0;
            for (int j = 0; j < 8; j++) {
                x_coord[i] |= ((uint64_t)pub[1 + (3 - i) * 8 + j]) << (56 - j * 8);
                y_coord[i] |= ((uint64_t)pub[33 + (3 - i) * 8 + j]) << (56 - j * 8);
            }
        }

        if (!p256_point_on_curve(x_coord, y_coord))
            return 0;

        p256_fe_to_mont(ctx->key.p256.public_key.x, x_coord);
        p256_fe_to_mont(ctx->key.p256.public_key.y, y_coord);
        ctx->key.p256.public_key.z[0] = 1;
        ctx->key.p256.public_key.z[1] = 0xFFFFFFFF00000000ULL;
        ctx->key.p256.public_key.z[2] = 0xFFFFFFFFFFFFFFFFULL;
        ctx->key.p256.public_key.z[3] = 0x00000000FFFFFFFEULL;

        ctx->has_public = 1;
        return 1;
    } else if (ctx->curve == OPSSL_CURVE_P384 && pub_len == 97 && pub[0] == 0x04) {
        p384_fe_t x_coord, y_coord;

        for (int i = 0; i < 6; i++) {
            x_coord[i] = 0;
            y_coord[i] = 0;
            for (int j = 0; j < 8; j++) {
                x_coord[i] |= ((uint64_t)pub[1 + (5 - i) * 8 + j]) << (56 - j * 8);
                y_coord[i] |= ((uint64_t)pub[49 + (5 - i) * 8 + j]) << (56 - j * 8);
            }
        }

        if (!p384_point_on_curve(x_coord, y_coord))
            return 0;

        p384_fe_to_mont(ctx->key.p384.public_key.x, x_coord);
        p384_fe_to_mont(ctx->key.p384.public_key.y, y_coord);
        ctx->key.p384.public_key.z[0] = 0xFFFFFFFF00000001ULL;
        ctx->key.p384.public_key.z[1] = 0x00000000FFFFFFFFULL;
        ctx->key.p384.public_key.z[2] = 0x0000000000000001ULL;
        ctx->key.p384.public_key.z[3] = 0;
        ctx->key.p384.public_key.z[4] = 0;
        ctx->key.p384.public_key.z[5] = 0;

        ctx->has_public = 1;
        return 1;
    } else if (ctx->curve == OPSSL_CURVE_P521 && pub_len == 133 && pub[0] == 0x04) {
        p521_fe_t x_coord, y_coord;

        for (int i = 0; i < 9; i++) {
            x_coord[i] = 0;
            y_coord[i] = 0;
            for (int j = 0; j < 8; j++) {
                size_t off = (size_t)i * 8 + (size_t)j;
                if (off < 66) {
                    x_coord[i] |= ((uint64_t)pub[1 + 65 - off]) << (j * 8);
                    y_coord[i] |= ((uint64_t)pub[67 + 65 - off]) << (j * 8);
                }
            }
        }
        x_coord[8] &= 0x1FFULL;
        y_coord[8] &= 0x1FFULL;

        if (!p521_point_on_curve(x_coord, y_coord))
            return 0;

        memcpy(ctx->key.p521.public_key.x, x_coord, sizeof(p521_fe_t));
        memcpy(ctx->key.p521.public_key.y, y_coord, sizeof(p521_fe_t));
        ctx->key.p521.public_key.z[0] = 1;
        for (int i = 1; i < 9; i++)
            ctx->key.p521.public_key.z[i] = 0;

        ctx->has_public = 1;
        return 1;
    }

    return 0;
}

int opssl_ecdsa_set_private(opssl_ecdsa_ctx_t *ctx, const uint8_t *priv, size_t priv_len) {
    if (!ctx || !priv) return 0;

    if (ctx->curve == OPSSL_CURVE_P256 && priv_len == 32) {
        for (int i = 0; i < 4; i++) {
            ctx->key.p256.private_key[i] = 0;
            for (int j = 0; j < 8; j++)
                ctx->key.p256.private_key[i] |=
                    ((uint64_t)priv[(3 - i) * 8 + j]) << (56 - j * 8);
        }

        p256_point_mul(&ctx->key.p256.public_key, ctx->key.p256.private_key, &p256_g);
        ctx->has_private = 1;
        ctx->has_public = 1;
        return 1;
    } else if (ctx->curve == OPSSL_CURVE_P384 && priv_len == 48) {
        for (int i = 0; i < 6; i++) {
            ctx->key.p384.private_key[i] = 0;
            for (int j = 0; j < 8; j++)
                ctx->key.p384.private_key[i] |=
                    ((uint64_t)priv[(5 - i) * 8 + j]) << (56 - j * 8);
        }

        p384_point_mul(&ctx->key.p384.public_key, ctx->key.p384.private_key, &p384_g);
        ctx->has_private = 1;
        ctx->has_public = 1;
        return 1;
    } else if (ctx->curve == OPSSL_CURVE_P521 && priv_len == 66) {
        for (int i = 0; i < 8; i++) {
            ctx->key.p521.private_key[i] = 0;
            for (int j = 0; j < 8; j++)
                ctx->key.p521.private_key[i] |=
                    ((uint64_t)priv[65 - i * 8 - j]) << (j * 8);
        }
        ctx->key.p521.private_key[8] = ((uint64_t)priv[0] << 8) | priv[1];
        ctx->key.p521.private_key[8] &= 0x1FFULL;

        p521_point_mul(&ctx->key.p521.public_key, ctx->key.p521.private_key, &p521_g);
        ctx->has_private = 1;
        ctx->has_public = 1;
        return 1;
    }

    return 0;
}

void opssl_ecdsa_free(opssl_ecdsa_ctx_t *ctx) {
    if (ctx) {
        opssl_memzero(ctx, sizeof(opssl_ecdsa_ctx_t));
        op_free(ctx);
    }
}

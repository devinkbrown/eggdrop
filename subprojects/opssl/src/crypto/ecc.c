/* P-256/P-384 ECC implementation with constant-time operations */

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"

#include <opssl/crypto.h>
#include <opssl/platform.h>
#include <op_memory.h>
#include <string.h>
#include <stdint.h>


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

static const p384_fe_t p384_r2 = {
    0xFFFFFFFE00000001ULL, 0x0000000200000000ULL, 0xFFFFFFFE00000000ULL,
    0x0000000200000000ULL, 0x0000000000000001ULL, 0x0000000000000000ULL
};

static const p384_fe_t p384_minus3_mont = {
    0xFFFFFFFDFFFFFFFFULL, 0xFFFFFFFF00000002ULL, 0xFFFFFFFCFFFFFFFBULL,
    0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL, 0x00000000FFFFFFFFULL
};
static const p384_fe_t p384_b3_mont = {
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

    /* If underflow, add p */
    __int128 acc = (unsigned __int128)t[0] + (borrow ? p256_p[0] : 0);
    r[0] = (uint64_t)acc; acc >>= 64;
    acc += (unsigned __int128)t[1] + (borrow ? p256_p[1] : 0);
    r[1] = (uint64_t)acc; acc >>= 64;
    acc += (unsigned __int128)t[2] + (borrow ? p256_p[2] : 0);
    r[2] = (uint64_t)acc; acc >>= 64;
    acc += (unsigned __int128)t[3] + (borrow ? p256_p[3] : 0);
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
    p256_point_add(r, p, p);
}


static void p256_point_mul(p256_point_t *r, const p256_fe_t scalar, const p256_point_t *p) {
    p256_point_t acc;
    memset(&acc, 0, sizeof(p256_point_t));
    int started = 0;

    for (int i = 255; i >= 0; i--) {
        if (started)
            p256_point_dbl(&acc, &acc);
        uint64_t bit = (scalar[i / 64] >> (i % 64)) & 1;
        if (bit) {
            if (!started) {
                memcpy(&acc, p, sizeof(p256_point_t));
                started = 1;
            } else {
                p256_point_add(&acc, &acc, p);
            }
        }
    }

    if (!started) {
        memset(r, 0, sizeof(p256_point_t));
    } else {
        p256_fe_t zi;
        p256_fe_inv(zi, acc.z);
        p256_fe_mul(r->x, acc.x, zi);
        p256_fe_mul(r->y, acc.y, zi);
        r->z[0] = 0x0000000000000001ULL;
        r->z[1] = 0xFFFFFFFF00000000ULL;
        r->z[2] = 0xFFFFFFFFFFFFFFFFULL;
        r->z[3] = 0x00000000FFFFFFFEULL;
    }
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

    /* Conditional subtraction of p */
    int borrow = 0;
    uint64_t sub[6];
    for (int i = 0; i < 6; i++) {
        __uint128_t diff = (__uint128_t)t[i] - p384_p[i] - borrow;
        sub[i] = (uint64_t)diff;
        borrow = (diff >> 64) != 0;
    }
    if (t[6] >= (uint64_t)borrow)
        memcpy(r, sub, 48);
    else
        memcpy(r, t, 48);
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
    /* Homogeneous projective addition (add-1998-cmo-2) for distinct points:
     * u = Y2*Z1 - Y1*Z2, v = X2*Z1 - X1*Z2
     * X3 = v*(u^2*Z1Z2 - v^3 - 2*v^2*X1Z2)
     * Y3 = u*(v^2*X1Z2 - X3/v) - v^3*Y1Z2  [simplified]
     * Z3 = v^3*Z1Z2 */
    p384_fe_t y1z2, x1z2, z1z2, u, uu, v, vv, vvv, rr, aa, x3, y3, z3, t1;

    p384_fe_mul(y1z2, p->y, q->z);
    p384_fe_mul(x1z2, p->x, q->z);
    p384_fe_mul(z1z2, p->z, q->z);

    /* u = Y2*Z1 - Y1*Z2 */
    p384_fe_mul(u, q->y, p->z);
    p384_fe_sub(u, u, y1z2);

    /* v = X2*Z1 - X1*Z2 */
    p384_fe_mul(v, q->x, p->z);
    p384_fe_sub(v, v, x1z2);

    p384_fe_mul(uu, u, u);
    p384_fe_mul(vv, v, v);
    p384_fe_mul(vvv, vv, v);
    p384_fe_mul(rr, vv, x1z2);

    /* A = uu*Z1Z2 - vvv - 2*R */
    p384_fe_mul(aa, uu, z1z2);
    p384_fe_sub(aa, aa, vvv);
    p384_fe_add(t1, rr, rr);
    p384_fe_sub(aa, aa, t1);

    /* X3 = v*A */
    p384_fe_mul(x3, v, aa);

    /* Y3 = u*(R - A) - vvv*Y1Z2 */
    p384_fe_sub(t1, rr, aa);
    p384_fe_mul(y3, u, t1);
    p384_fe_mul(t1, vvv, y1z2);
    p384_fe_sub(y3, y3, t1);

    /* Z3 = vvv*Z1Z2 */
    p384_fe_mul(z3, vvv, z1z2);

    memcpy(r->x, x3, sizeof(p384_fe_t));
    memcpy(r->y, y3, sizeof(p384_fe_t));
    memcpy(r->z, z3, sizeof(p384_fe_t));
}

static int p384_fe_is_zero(const p384_fe_t a) {
    return (a[0] | a[1] | a[2] | a[3] | a[4] | a[5]) == 0;
}

static void p384_point_mul(p384_point_t *r, const p384_fe_t scalar, const p384_point_t *p) {
    /* Double-and-add from MSB. Result starts as identity (Z=0). */
    p384_point_t acc;
    memset(&acc, 0, sizeof(p384_point_t));
    int started = 0;

    for (int i = 383; i >= 0; i--) {
        if (started) {
            p384_point_dbl(&acc, &acc);
        }
        uint64_t bit = (scalar[i / 64] >> (i % 64)) & 1;
        if (bit) {
            if (!started) {
                memcpy(&acc, p, sizeof(p384_point_t));
                started = 1;
            } else {
                p384_point_add(&acc, &acc, p);
            }
        }
    }

    if (!started) {
        memset(r, 0, sizeof(p384_point_t));
    } else {
        /* Normalize to affine projective (z = R mod p) */
        p384_fe_t zi;
        p384_fe_inv(zi, acc.z);
        p384_fe_mul(r->x, acc.x, zi);
        p384_fe_mul(r->y, acc.y, zi);
        r->z[0] = 0xFFFFFFFF00000001ULL;
        r->z[1] = 0x00000000FFFFFFFFULL;
        r->z[2] = 0x0000000000000001ULL;
        r->z[3] = 0;
        r->z[4] = 0;
        r->z[5] = 0;
    }
}

/* ─── P-521 Field Arithmetic (Mersenne prime p = 2^521 - 1) ────────────── */

static const p521_fe_t p521_p = {
    0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL,
    0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL,
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

static void p521_point_mul(p521_point_t *r, const p521_fe_t scalar, const p521_point_t *p) {
    p521_point_t acc;
    memset(&acc, 0, sizeof(p521_point_t));
    int started = 0;
    for (int i = 520; i >= 0; i--) {
        if (started) p521_point_dbl(&acc, &acc);
        if ((scalar[i / 64] >> (i % 64)) & 1) {
            if (!started) { memcpy(&acc, p, sizeof(p521_point_t)); started = 1; }
            else p521_point_add(&acc, &acc, p);
        }
    }
    if (!started) memset(r, 0, sizeof(p521_point_t));
    else memcpy(r, &acc, sizeof(p521_point_t));
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

    /* Convert to field element */
    for (int i = 0; i < 4; i++) {
        k[i] = 0;
        for (int j = 0; j < 8; j++) {
            k[i] |= ((uint64_t)temp[i * 8 + j]) << (56 - j * 8);
        }
    }

    opssl_memzero(K, 32); opssl_memzero(v, 32); opssl_memzero(priv_bytes, 32);
    return OPSSL_SUCCESS;
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
        /* Generate random private key */
        uint8_t key_bytes[32];
        if (opssl_random_bytes(key_bytes, 32) != 0) return 0;

        /* Convert to field element */
        for (int i = 0; i < 4; i++) {
            ctx->key.p256.private_key[i] = 0;
            for (int j = 0; j < 8; j++) {
                ctx->key.p256.private_key[i] |=
                    ((uint64_t)key_bytes[i * 8 + j]) << (56 - j * 8);
            }
        }

        /* Compute public key Q = private_key * G */
        p256_point_mul(&ctx->key.p256.public_key, ctx->key.p256.private_key, &p256_g);

        ctx->has_private = 1;
        ctx->has_public = 1;
        return 1;

    } else if (ctx->curve == OPSSL_CURVE_P384) {
        /* Generate random private key */
        uint8_t key_bytes[48];
        if (opssl_random_bytes(key_bytes, 48) != 0) return 0;

        /* Convert to field element */
        for (int i = 0; i < 6; i++) {
            ctx->key.p384.private_key[i] = 0;
            for (int j = 0; j < 8; j++) {
                ctx->key.p384.private_key[i] |=
                    ((uint64_t)key_bytes[i * 8 + j]) << (56 - j * 8);
            }
        }

        /* Compute public key Q = private_key * G */
        p384_point_mul(&ctx->key.p384.public_key, ctx->key.p384.private_key, &p384_g);

        ctx->has_private = 1;
        ctx->has_public = 1;
        return 1;

    } else if (ctx->curve == OPSSL_CURVE_P521) {
        uint8_t key_bytes[66];
        if (opssl_random_bytes(key_bytes, 66) != 0) return 0;
        key_bytes[0] &= 0x01; /* Ensure < 2^521 */

        for (int i = 0; i < 8; i++) {
            ctx->key.p521.private_key[i] = 0;
            for (int j = 0; j < 8; j++)
                ctx->key.p521.private_key[i] |=
                    ((uint64_t)key_bytes[i * 8 + j]) << (56 - j * 8);
        }
        ctx->key.p521.private_key[8] = ((uint64_t)key_bytes[64] << 8) | key_bytes[65];
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

        /* Convert to field element */
        for (int i = 0; i < 4; i++) {
            ctx->key.p256.private_key[i] = 0;
            for (int j = 0; j < 8; j++) {
                ctx->key.p256.private_key[i] |=
                    ((uint64_t)key_bytes[i * 8 + j]) << (56 - j * 8);
            }
        }

        /* Compute public key Q = private_key * G */
        p256_point_mul(&ctx->key.p256.public_key, ctx->key.p256.private_key, &p256_g);

        ctx->has_private = 1;
        ctx->has_public = 1;
        return 1;

    } else if (ctx->curve == OPSSL_CURVE_P384) {
        uint8_t key_bytes[48];
        if (opssl_random_bytes(key_bytes, 48) != 0) return 0;

        /* Convert to field element */
        for (int i = 0; i < 6; i++) {
            ctx->key.p384.private_key[i] = 0;
            for (int j = 0; j < 8; j++) {
                ctx->key.p384.private_key[i] |=
                    ((uint64_t)key_bytes[i * 8 + j]) << (56 - j * 8);
            }
        }

        /* Compute public key Q = private_key * G */
        p384_point_mul(&ctx->key.p384.public_key, ctx->key.p384.private_key, &p384_g);

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

    return 0;
}

int opssl_ecdsa_set_public(opssl_ecdsa_ctx_t *ctx, const uint8_t *pub, size_t pub_len) {
    if (!ctx || !pub) return 0;

    if (ctx->curve == OPSSL_CURVE_P256 && pub_len == 65 && pub[0] == 0x04) {
        /* Parse uncompressed point format (0x04 || x || y) */
        p256_fe_t x_coord, y_coord;

        /* Parse x coordinate (big-endian bytes → little-endian limbs) */
        for (int i = 0; i < 4; i++) {
            x_coord[i] = 0;
            for (int j = 0; j < 8; j++) {
                x_coord[i] |= ((uint64_t)pub[1 + (3 - i) * 8 + j]) << (56 - j * 8);
            }
        }

        /* Parse y coordinate (big-endian bytes → little-endian limbs) */
        for (int i = 0; i < 4; i++) {
            y_coord[i] = 0;
            for (int j = 0; j < 8; j++) {
                y_coord[i] |= ((uint64_t)pub[33 + (3 - i) * 8 + j]) << (56 - j * 8);
            }
        }

        /* Convert to Montgomery form */
        p256_fe_to_mont(ctx->key.p256.public_key.x, x_coord);
        p256_fe_to_mont(ctx->key.p256.public_key.y, y_coord);

        /* Set Z = 1 in Montgomery form */
        ctx->key.p256.public_key.z[0] = 1;
        ctx->key.p256.public_key.z[1] = 0xFFFFFFFF00000000ULL;
        ctx->key.p256.public_key.z[2] = 0xFFFFFFFFFFFFFFFFULL;
        ctx->key.p256.public_key.z[3] = 0x00000000FFFFFFFEULL;

        ctx->has_public = 1;
        return 1;

    } else if (ctx->curve == OPSSL_CURVE_P384 && pub_len == 97 && pub[0] == 0x04) {
        /* Parse P-384 uncompressed point format */
        p384_fe_t x_coord, y_coord;

        /* Parse x coordinate (big-endian bytes → little-endian limbs) */
        for (int i = 0; i < 6; i++) {
            x_coord[i] = 0;
            for (int j = 0; j < 8; j++) {
                x_coord[i] |= ((uint64_t)pub[1 + (5 - i) * 8 + j]) << (56 - j * 8);
            }
        }

        /* Parse y coordinate (big-endian bytes → little-endian limbs) */
        for (int i = 0; i < 6; i++) {
            y_coord[i] = 0;
            for (int j = 0; j < 8; j++) {
                y_coord[i] |= ((uint64_t)pub[49 + (5 - i) * 8 + j]) << (56 - j * 8);
            }
        }

        /* Convert to Montgomery form */
        p384_fe_to_mont(ctx->key.p384.public_key.x, x_coord);
        p384_fe_to_mont(ctx->key.p384.public_key.y, y_coord);

        /* Set Z = R mod p (Montgomery representation of 1) */
        ctx->key.p384.public_key.z[0] = 0xFFFFFFFF00000001ULL;
        ctx->key.p384.public_key.z[1] = 0x00000000FFFFFFFFULL;
        ctx->key.p384.public_key.z[2] = 0x0000000000000001ULL;
        ctx->key.p384.public_key.z[3] = 0;
        ctx->key.p384.public_key.z[4] = 0;
        ctx->key.p384.public_key.z[5] = 0;

        ctx->has_public = 1;
        return 1;
    }

    return 0;
}

int opssl_ecdsa_set_private(opssl_ecdsa_ctx_t *ctx, const uint8_t *priv, size_t priv_len) {
    if (!ctx || !priv) return 0;

    if (ctx->curve == OPSSL_CURVE_P256 && priv_len == 32) {
        /* Parse raw 32-byte big-endian private key to little-endian limbs */
        for (int i = 0; i < 4; i++) {
            ctx->key.p256.private_key[i] = 0;
            for (int j = 0; j < 8; j++) {
                ctx->key.p256.private_key[i] |=
                    ((uint64_t)priv[(3 - i) * 8 + j]) << (56 - j * 8);
            }
        }

        /* Compute public key Q = private_key * G */
        p256_point_mul(&ctx->key.p256.public_key, ctx->key.p256.private_key, &p256_g);

        ctx->has_private = 1;
        ctx->has_public = 1;
        return 1;

    } else if (ctx->curve == OPSSL_CURVE_P384 && priv_len == 48) {
        /* Parse raw 48-byte big-endian private key to little-endian limbs */
        for (int i = 0; i < 6; i++) {
            ctx->key.p384.private_key[i] = 0;
            for (int j = 0; j < 8; j++) {
                ctx->key.p384.private_key[i] |=
                    ((uint64_t)priv[(5 - i) * 8 + j]) << (56 - j * 8);
            }
        }

        /* Compute public key Q = private_key * G */
        p384_point_mul(&ctx->key.p384.public_key, ctx->key.p384.private_key, &p384_g);

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
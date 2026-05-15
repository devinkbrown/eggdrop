/* ML-DSA (FIPS 204) - Module-Lattice Digital Signature Algorithm
 * Implementation for the opssl TLS library.
 *
 * Implements ML-DSA-65 (NIST Security Level 3):
 *   k=6, l=5, eta=4, tau=49, beta=196
 *   gamma1 = 2^19 = 524288
 *   gamma2 = (q-1)/32 = 261888
 *   omega  = 55
 *   Public key : 1952 bytes
 *   Secret key : 4032 bytes
 *   Signature  : 3309 bytes
 *
 * Mathematical constants (all independently verified):
 *   q = 8380417 = 2^23 - 2^13 + 1  (NTT-friendly prime)
 *   n = 256
 *   zeta = 1753  (primitive 512th root of unity mod q)
 *   R  = 2^32,  MONT_R  = 2^32 mod q         = 4193792
 *   NEG_QINV = -q^{-1} mod 2^32              = 0xfc7fdfff
 *     [verify: q * 0xfc7fdfff mod 2^32 = 0xffffffff = -1 mod 2^32]
 *   MONT_R2 = 2^64 mod q                      = 2365951
 *   INTT_F  = n^{-1} * R^2 mod q               = 41978
 *
 * NTT zeta table:
 *   ntt_zetas[k] = zeta^{brv8(k)} mod q,  brv8 = 8-bit bit-reversal (256 entries)
 *   ntt_zetas[1] = 25847 = zeta^128 mod q  (brv8(1)=128, per FIPS 204 reference)
 *   ntt_zetas[2] = 5771523 = zeta^64 mod q  (brv8(2)=64, former 7-level entry [1])
 *
 * Constant-time properties:
 *   mont_reduce     : arithmetic only, no branches
 *   barrett_reduce  : arithmetic shifts + conditional adds (branchless cmov pattern)
 *   poly_norm_inf   : branchless abs via arithmetic shift mask
 *   Rejection loop  : exits on ||z||, ||r0||, ||ct0||, hint weight — all public
 *   SampleInBall    : sign bits from hash (public), position sampling from hash
 *   c_tilde compare : opssl_ct_eq (constant-time)
 *
 * Copyright (C) 2026 ophion development team
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <opssl/crypto.h>
#include <opssl/platform.h>
#include <string.h>
#include "sha_internal.h"

/* ---- Domain constants --------------------------------------------------- */

#define MLDSA_Q          8380417
#define MLDSA_N          256
#define MLDSA_QINV       0x03802001U  /* q^{-1} mod 2^32; used in Montgomery reduction */
#define MLDSA_MONT_R     4193792
#define MLDSA_MONT_R2    2365951
#define MLDSA_INTT_F     41978

/* ---- Parameter set descriptor ------------------------------------------- */

typedef struct {
    int k, l;
    int eta, tau, beta;
    int gamma1_log2, gamma2;
    int omega, lambda;
    int eta_bits;
    int gamma1_bits;
    int w1_bits;
} mldsa_params_t;

static const mldsa_params_t P65 = {
    .k = 6, .l = 5, .eta = 4, .tau = 49, .beta = 196,
    .gamma1_log2 = 19, .gamma2 = 261888, .omega = 55, .lambda = 192,
    .eta_bits = 4, .gamma1_bits = 20, .w1_bits = 4,
};

/* ---- Polynomial type ---------------------------------------------------- */

typedef struct { int32_t c[MLDSA_N]; } poly_t;
#define KMAX 6
#define LMAX 5

/* ---- NTT zeta table ----------------------------------------------------- */

/*
 * ntt_zetas[k] = zeta^{brv8(k)} mod q,  zeta=1753, q=8380417.
 * 256 entries; NTT uses indices 1..255 (++k from k=0), INTT uses 255..1 (k-- from k=255).
 * Generated: for k in range(256): pow(1753, bit_rev_8(k), 8380417) % 8380417
 * Verified against FIPS 204 reference: ntt_zetas[1]=25847 (brv8(1)=128, zeta^128 mod q).
 * Even-indexed entries (ntt_zetas[2k]) equal the 7-level table entry k (brv8(2k)=brv7(k)).
 */
static const int32_t ntt_zetas[256] = {
    4193792,   25847, 5771523, 7861508,  237124, 7602457, 7504169,  466468,
    1826347, 2353451, 8021166, 6288512, 3119733, 5495562, 3111497, 2680103,
    2725464, 1024112, 7300517, 3585928, 7830929, 7260833, 2619752, 6271868,
    6262231, 4520680, 6980856, 5102745, 1757237, 8360995, 4010497,  280005,
    2706023,   95776, 3077325, 3530437, 6718724, 4788269, 5842901, 3915439,
    4519302, 5336701, 3574422, 5512770, 3539968, 8079950, 2348700, 7841118,
    6681150, 6736599, 3505694, 4558682, 3507263, 6239768, 6779997, 3699596,
     811944,  531354,  954230, 3881043, 3900724, 5823537, 2071892, 5582638,
    4450022, 6851714, 4702672, 5339162, 6927966, 3475950, 2176455, 6795196,
    7122806, 1939314, 4296819, 7380215, 5190273, 5223087, 4747489,  126922,
    3412210, 7396998, 2147896, 2715295, 5412772, 4686924, 7969390, 5903370,
    7709315, 7151892, 8357436, 7072248, 7998430, 1349076, 1852771, 6949987,
    5037034,  264944,  508951, 3097992,   44288, 7280319,  904516, 3958618,
    4656075, 8371839, 1653064, 5130689, 2389356, 8169440,  759969, 7063561,
     189548, 4827145, 3159746, 6529015, 5971092, 8202977, 1315589, 1341330,
    1285669, 6795489, 7567685, 6940675, 5361315, 4499357, 4751448, 3839961,
    2091667, 3407706, 2316500, 3817976, 5037939, 2244091, 5933984, 4817955,
     266997, 2434439, 7144689, 3513181, 4860065, 4621053, 7183191, 5187039,
     900702, 1859098,  909542,  819034,  495491, 6767243, 8337157, 7857917,
    7725090, 5257975, 2031748, 3207046, 4823422, 7855319, 7611795, 4784579,
     342297,  286988, 5942594, 4108315, 3437287, 5038140, 1735879,  203044,
    2842341, 2691481, 5790267, 1265009, 4055324, 1247620, 2486353, 1595974,
    4613401, 1250494, 2635921, 4832145, 5386378, 1869119, 1903435, 7329447,
    7047359, 1237275, 5062207, 6950192, 7929317, 1312455, 3306115, 6417775,
    7100756, 1917081, 5834105, 7005614, 1500165,  777191, 2235880, 3406031,
    7838005, 5548557, 6709241, 6533464, 5796124, 4656147,  594136, 4603424,
    6366809, 2432395, 2454455, 8215696, 1957272, 3369112,  185531, 7173032,
    5196991,  162844, 1616392, 3014001,  810149, 1652634, 4686184, 6581310,
    5341501, 3523897, 3866901,  269760, 2213111, 7404533, 1717735,  472078,
    7953734, 1723600, 6577327, 1910376, 6712985, 7276084, 8119771, 4546524,
    5441381, 6144432, 7959518, 6094090,  183443, 7403526, 1612842, 4834730,
    7826001, 3919660, 8332111, 7018208, 3937738, 1400424, 7534263, 1976782,
};

/* ---- Montgomery / Barrett reduction ------------------------------------ */

/*
 * Montgomery reduction: given a in [-q*2^31, q*2^31] returns a * R^{-1} mod q.
 * Uses QINV = q^{-1} mod 2^32 = 0x03802001 so that t = a * QINV mod 2^32
 * satisfies t*q ≡ a (mod 2^32), making (a - t*q) divisible by 2^32.
 *   t = low32(a) * QINV mod 2^32  (as int32)
 *   result = (a - t*q) >> 32      (exact division, result in [-(q-1), q-1])
 */
static inline int32_t mont_reduce(int64_t a)
{
    int32_t t = (int32_t)((uint32_t)(int32_t)a * MLDSA_QINV);
    return (int32_t)((a - (int64_t)t * (int64_t)MLDSA_Q) >> 32);
}

/*
 * Barrett reduction: reduce x to [0, q-1].
 * Approximation: t = x >> 23 (since q ≈ 2^23, off-by-at-most-one).
 * Two conditional adds correct the residual.
 * Works for x in [-10*q, 10*q].
 */
static inline int32_t barrett_reduce(int32_t x)
{
    int32_t t = x >> 23;             /* floor(x / 2^23) ≈ floor(x / q) */
    x -= t * (int32_t)MLDSA_Q;
    /* now x in approximately [-q, 2q]; apply two corrections */
    x += ((x >> 31) & (int32_t)MLDSA_Q);
    x -= (int32_t)MLDSA_Q;
    x += ((x >> 31) & (int32_t)MLDSA_Q);
    return x;
}

/* ---- NTT --------------------------------------------------------------- */

/*
 * Forward NTT (Cooley-Tukey butterflies).
 * Input:  standard domain, coefficients in [0, q-1].
 * Output: NTT domain, coefficients approximately in [-(q-1), q-1].
 */
static void mldsa_ntt(poly_t *p)
{
    int k = 0;
    for (int len = 128; len >= 1; len >>= 1) {
        for (int start = 0; start < MLDSA_N; start += 2 * len) {
            int32_t zeta = ntt_zetas[++k];
            for (int j = start; j < start + len; j++) {
                int32_t t     = mont_reduce((int64_t)zeta * p->c[j + len]);
                p->c[j + len] = p->c[j] - t;
                p->c[j]       = p->c[j] + t;
            }
        }
    }
}

/*
 * Inverse NTT (Gentleman-Sande butterflies).
 * Final multiply by INTT_F = n^{-1} * R mod q to undo the 1/n factor and
 * convert from Montgomery domain.
 */
static void mldsa_invntt(poly_t *p)
{
    int k = 255;
    for (int len = 1; len <= 128; len <<= 1) {
        for (int start = 0; start < MLDSA_N; start += 2 * len) {
            int32_t zeta = -ntt_zetas[k--];
            for (int j = start; j < start + len; j++) {
                int32_t t     = p->c[j];
                p->c[j]       = t + p->c[j + len];
                p->c[j + len] = mont_reduce((int64_t)zeta * (t - p->c[j + len]));
            }
        }
    }
    for (int i = 0; i < MLDSA_N; i++)
        p->c[i] = mont_reduce((int64_t)MLDSA_INTT_F * p->c[i]);
}

/* ---- Polynomial arithmetic --------------------------------------------- */

static void poly_add(poly_t *r, const poly_t *a, const poly_t *b)
{
    for (int i = 0; i < MLDSA_N; i++) r->c[i] = a->c[i] + b->c[i];
}

static void poly_sub(poly_t *r, const poly_t *a, const poly_t *b)
{
    for (int i = 0; i < MLDSA_N; i++) r->c[i] = a->c[i] - b->c[i];
}

static void poly_reduce(poly_t *p)
{
    for (int i = 0; i < MLDSA_N; i++) p->c[i] = barrett_reduce(p->c[i]);
}

/*
 * poly_center: map coefficients from [0, q-1] to [-(q-1)/2, (q-1)/2].
 * Required before infinity-norm checks (z, ct0 vectors in sign()).
 * Branchless: add -q when coeff > (q-1)/2.
 */
static void poly_center(poly_t *p)
{
    for (int i = 0; i < MLDSA_N; i++) {
        /* If c[i] > (q-1)/2, subtract q.  Branchless via arithmetic shift. */
        int32_t x = p->c[i];
        /* Subtract q when x > (q-1)/2: mask = (q/2 - x) >> 31, which is
         * all-ones when x > q/2 and zero otherwise. */
        x -= (int32_t)MLDSA_Q & (((int32_t)(MLDSA_Q / 2) - x) >> 31);
        p->c[i] = x;
    }
}

static void poly_pointwise_mont(poly_t *r, const poly_t *a, const poly_t *b)
{
    for (int i = 0; i < MLDSA_N; i++)
        r->c[i] = mont_reduce((int64_t)a->c[i] * b->c[i]);
}

static void poly_acc_mont(poly_t *r, const poly_t *a, const poly_t *b)
{
    for (int i = 0; i < MLDSA_N; i++)
        r->c[i] += mont_reduce((int64_t)a->c[i] * b->c[i]);
}

/* Branchless infinity norm using arithmetic shift mask for abs. */
static int32_t poly_norm_inf(const poly_t *p)
{
    int32_t norm = 0;
    for (int i = 0; i < MLDSA_N; i++) {
        int32_t mask = p->c[i] >> 31;
        int32_t a    = (p->c[i] ^ mask) - mask;
        if (a > norm) norm = a;
    }
    return norm;
}

static int32_t polyvec_norm_inf(const poly_t *v, int dim)
{
    int32_t norm = 0;
    for (int i = 0; i < dim; i++) {
        int32_t n = poly_norm_inf(&v[i]);
        if (n > norm) norm = n;
    }
    return norm;
}

/* ---- Matrix-vector NTT multiply ---------------------------------------- */

static void mat_vec_ntt(poly_t w[], const poly_t A[], const poly_t v[], int k, int l)
{
    for (int i = 0; i < k; i++) {
        poly_pointwise_mont(&w[i], &A[i * l], &v[0]);
        for (int j = 1; j < l; j++)
            poly_acc_mont(&w[i], &A[i * l + j], &v[j]);
    }
}

/* ---- Bit packing -------------------------------------------------------- */

static void poly_pack(uint8_t *out, const poly_t *p, int d)
{
    int bits = 0, oi = 0;
    uint64_t acc = 0;
    uint32_t mask = (d < 32) ? ((1u << d) - 1u) : 0xFFFFFFFFu;
    for (int i = 0; i < MLDSA_N; i++) {
        acc  |= (uint64_t)((uint32_t)p->c[i] & mask) << bits;
        bits += d;
        while (bits >= 8) {
            out[oi++] = (uint8_t)(acc & 0xFF);
            acc >>= 8;
            bits -= 8;
        }
    }
    if (bits > 0) out[oi] = (uint8_t)(acc & 0xFF);
}

static void poly_unpack(poly_t *p, const uint8_t *in, int d)
{
    int bits = 0, ii = 0;
    uint64_t acc = 0;
    uint64_t mask = (d < 64) ? ((1ull << d) - 1ull) : ~0ull;
    for (int i = 0; i < MLDSA_N; i++) {
        while (bits < d) {
            acc  |= (uint64_t)in[ii++] << bits;
            bits += 8;
        }
        p->c[i] = (int32_t)(acc & mask);
        acc  >>= d;
        bits  -= d;
    }
}

/* Eta-bounded coeff: encode x in [-eta,eta] as (eta-x) using eta_bits bits. */
static void poly_pack_eta(uint8_t *out, const poly_t *p, int eta, int eb)
{
    poly_t tmp;
    for (int i = 0; i < MLDSA_N; i++) tmp.c[i] = eta - p->c[i];
    poly_pack(out, &tmp, eb);
}

static void poly_unpack_eta(poly_t *p, const uint8_t *in, int eta, int eb)
{
    poly_unpack(p, in, eb);
    for (int i = 0; i < MLDSA_N; i++) p->c[i] = eta - p->c[i];
}

/* t0: encode as (2^12 - t0) using 13 bits.  t0 in [-(2^12-1), 2^12]. */
static void poly_pack_t0(uint8_t *out, const poly_t *p)
{
    poly_t tmp;
    for (int i = 0; i < MLDSA_N; i++) tmp.c[i] = (1 << 12) - p->c[i];
    poly_pack(out, &tmp, 13);
}

static void poly_unpack_t0(poly_t *p, const uint8_t *in)
{
    poly_unpack(p, in, 13);
    for (int i = 0; i < MLDSA_N; i++) p->c[i] = (1 << 12) - p->c[i];
}

/* t1: upper 10 bits, unsigned. */
static void poly_pack_t1(uint8_t *out, const poly_t *p) { poly_pack(out, p, 10); }
static void poly_unpack_t1(poly_t *p, const uint8_t *in) { poly_unpack(p, in, 10); }

/* z: encode (gamma1 - z) using gamma1_bits. */
static void poly_pack_z(uint8_t *out, const poly_t *p, int gamma1, int gb)
{
    poly_t tmp;
    for (int i = 0; i < MLDSA_N; i++) tmp.c[i] = gamma1 - p->c[i];
    poly_pack(out, &tmp, gb);
}

static void poly_unpack_z(poly_t *p, const uint8_t *in, int gamma1, int gb)
{
    poly_unpack(p, in, gb);
    for (int i = 0; i < MLDSA_N; i++) p->c[i] = gamma1 - p->c[i];
}

/* ---- Rounding / decomposition ------------------------------------------ */

/*
 * Power2Round (FIPS 204 Algorithm 35):
 * x ≡ r1*2^13 + r0 (mod q) with r0 in [-(2^12-1), 2^12].
 */
static int32_t power2round(int32_t x, int32_t *low)
{
    x = ((x % (int32_t)MLDSA_Q) + (int32_t)MLDSA_Q) % (int32_t)MLDSA_Q;
    int32_t r0 = x & 0x1FFF;
    r0 -= (int32_t)(((1 << 12) - r0) >> 31) & (1 << 13);
    *low = r0;
    return (x - r0) >> 13;
}

/*
 * Decompose (FIPS 204 Algorithm 36):
 * x = r1*(2*gamma2) + r0 (mod q), r0 in (-gamma2, gamma2].
 * Special: when r1 = (q-1)/(2*gamma2), set r1=0, r0=x-(q-1).
 */
static int32_t decompose(int32_t x, int32_t *r0, int gamma2)
{
    x = ((x % (int32_t)MLDSA_Q) + (int32_t)MLDSA_Q) % (int32_t)MLDSA_Q;
    int32_t r1 = (x + gamma2 - 1) / (2 * gamma2);
    int32_t m  = (int32_t)MLDSA_Q / (2 * gamma2);
    if (r1 >= m) {
        *r0 = x - ((int32_t)MLDSA_Q - 1);
        return 0;
    }
    *r0 = x - r1 * 2 * gamma2;
    /* Center r0 around 0 */
    if (*r0 > gamma2)   *r0 -= 2 * gamma2;
    if (*r0 <= -gamma2) *r0 += 2 * gamma2;
    return r1;
}

static inline int32_t highbits(int32_t x, int gamma2)
{
    int32_t r0;
    return decompose(x, &r0, gamma2);
}

static inline int32_t make_hint(int32_t z, int32_t r, int gamma2)
{
    return highbits(r, gamma2) != highbits(r + z, gamma2) ? 1 : 0;
}

static inline int32_t use_hint(int32_t hint, int32_t r, int gamma2)
{
    int32_t r0, r1 = decompose(r, &r0, gamma2);
    if (!hint) return r1;
    int32_t m = (int32_t)MLDSA_Q / (2 * gamma2);
    return (r0 > 0) ? (r1 + 1) % m : (r1 - 1 + m) % m;
}

static void poly_decompose(poly_t *p1, poly_t *p0, const poly_t *p, int gamma2)
{
    for (int i = 0; i < MLDSA_N; i++)
        p1->c[i] = decompose(p->c[i], &p0->c[i], gamma2);
}

static void poly_power2round(poly_t *t1, poly_t *t0, const poly_t *t)
{
    for (int i = 0; i < MLDSA_N; i++)
        t1->c[i] = power2round(t->c[i], &t0->c[i]);
}

/* ---- Hash helpers ------------------------------------------------------- */

/*
 * All multi-input SHAKE256 operations use pre-assembled buffers and the
 * one-shot opssl_shake256().  This avoids any dependency on streaming
 * internals not exposed by the public API.
 *
 * Callers that need to hash variable-length messages (mu computation)
 * use op_malloc to assemble the concatenated input.
 */

/* CRH(x) = SHAKE256(x, 64) */
static void crh512(uint8_t out[64], const uint8_t *in, size_t len)
{
    opssl_shake256(out, 64, in, len);
}

/*
 * shake256_two: SHAKE256(a || b, out_len).
 * a_len + b_len must fit in stack buffer (both are small in our usage).
 */
static void shake256_two(uint8_t *out, size_t out_len,
                          const uint8_t *a, size_t a_len,
                          const uint8_t *b, size_t b_len)
{
    /* Max usage: K(32) || rnd(32) || mu(64) = 128 bytes for rho''.
     * For c~ computation: mu(64) || w1_enc(<=6*256*6/8=1152) = up to 1216 bytes.
     * Use dynamic allocation via op_malloc to be safe for all sizes.
     */
    size_t total = a_len + b_len;
    uint8_t *buf = op_malloc(total);
    memcpy(buf, a, a_len);
    memcpy(buf + a_len, b, b_len);
    opssl_shake256(out, out_len, buf, total);
    opssl_memzero(buf, total);
    op_free(buf);
}

/*
 * shake256_three: SHAKE256(a || b || c, out_len).
 */
static void shake256_three(uint8_t *out, size_t out_len,
                             const uint8_t *a, size_t a_len,
                             const uint8_t *b, size_t b_len,
                             const uint8_t *c, size_t c_len)
{
    size_t total = a_len + b_len + c_len;
    uint8_t *buf = op_malloc(total);
    memcpy(buf, a, a_len);
    memcpy(buf + a_len, b, b_len);
    memcpy(buf + a_len + b_len, c, c_len);
    opssl_shake256(out, out_len, buf, total);
    opssl_memzero(buf, total);
    op_free(buf);
}

/* ---- ExpandA ----------------------------------------------------------- */

/*
 * Sample one uniform polynomial from SHAKE128(rho || col || row).
 * Rejection sample 23-bit values; accept those < q.
 * Buffer of 864 bytes gives > 256 accepted values with overwhelming probability.
 */
static void expand_a_poly(poly_t *p, const uint8_t rho[32], int row, int col)
{
    uint8_t seed[34];
    memcpy(seed, rho, 32);
    seed[32] = (uint8_t)col;
    seed[33] = (uint8_t)row;

    uint8_t buf[864];
    opssl_shake128(buf, sizeof(buf), seed, 34);

    int ctr = 0, pos = 0;
    while (ctr < MLDSA_N) {
        if (pos + 3 > (int)sizeof(buf)) {
            /* Refill on the extremely rare case we exhaust the buffer */
            opssl_shake128(buf, sizeof(buf), seed, 34);
            pos = 0;
        }
        uint32_t t = (uint32_t)buf[pos]
                   | (uint32_t)buf[pos + 1] << 8
                   | (uint32_t)buf[pos + 2] << 16;
        pos += 3;
        t &= 0x7FFFFFu;
        if ((int32_t)t < MLDSA_Q) p->c[ctr++] = (int32_t)t;
    }
}

static void expand_a(poly_t A[], const uint8_t rho[32], int k, int l)
{
    for (int i = 0; i < k; i++)
        for (int j = 0; j < l; j++)
            expand_a_poly(&A[i * l + j], rho, i, j);
}

/* ---- ExpandS ----------------------------------------------------------- */

/*
 * Sample polynomial with coefficients in [-eta, eta].
 * eta=2: 3-bit nibbles, accept [0,4] → coeff = 2 - value
 * eta=4: 4-bit nibbles, accept [0,8] → coeff = 4 - value
 * 512-byte buffer suffices (expected ~256*16/8 = 512 bytes in worst case).
 */
static void expand_s_poly(poly_t *p, const uint8_t rho_prime[64], int nonce, int eta)
{
    uint8_t seed[66];
    memcpy(seed, rho_prime, 64);
    seed[64] = (uint8_t)(nonce & 0xFF);
    seed[65] = (uint8_t)(nonce >> 8);

    uint8_t buf[512];
    opssl_shake256(buf, sizeof(buf), seed, 66);

    int ctr = 0, pos = 0;
    if (eta == 2) {
        while (ctr < MLDSA_N && pos < (int)sizeof(buf)) {
            uint8_t b  = buf[pos++];
            uint8_t t0 = b & 7;
            uint8_t t1 = b >> 4 & 7;
            if (t0 < 5) p->c[ctr++] = 2 - (int32_t)t0;
            if (ctr < MLDSA_N && t1 < 5) p->c[ctr++] = 2 - (int32_t)t1;
        }
    } else { /* eta == 4 */
        while (ctr < MLDSA_N && pos < (int)sizeof(buf)) {
            uint8_t b  = buf[pos++];
            uint8_t t0 = b & 0xF;
            uint8_t t1 = b >> 4;
            if (t0 < 9) p->c[ctr++] = 4 - (int32_t)t0;
            if (ctr < MLDSA_N && t1 < 9) p->c[ctr++] = 4 - (int32_t)t1;
        }
    }
    while (ctr < MLDSA_N) p->c[ctr++] = 0; /* safety pad, virtually never reached */
}

static void expand_s(poly_t s[], const uint8_t rho_prime[64],
                     int dim, int eta, int base_nonce)
{
    for (int i = 0; i < dim; i++)
        expand_s_poly(&s[i], rho_prime, base_nonce + i, eta);
}

/* ---- ExpandMask -------------------------------------------------------- */

/*
 * Sample masking polynomial y with coefficients in (-gamma1, gamma1].
 * Encode as (gamma1 - coeff) using gamma1_bits bits, then decode.
 */
static void expand_mask_poly(poly_t *p, const uint8_t rho_pp[64],
                              int nonce, int gamma1, int gb)
{
    uint8_t seed[66];
    memcpy(seed, rho_pp, 64);
    seed[64] = (uint8_t)(nonce & 0xFF);
    seed[65] = (uint8_t)(nonce >> 8);

    uint8_t buf[640]; /* 256 * 20 / 8 = 640 bytes max (for gb=20) */
    size_t blen = (size_t)MLDSA_N * (size_t)gb / 8;
    if (blen > sizeof(buf)) blen = sizeof(buf);
    opssl_shake256(buf, blen, seed, 66);

    poly_t tmp;
    poly_unpack(&tmp, buf, gb);
    for (int i = 0; i < MLDSA_N; i++)
        p->c[i] = gamma1 - (int32_t)tmp.c[i];
}

static void expand_mask(poly_t y[], const uint8_t rho_pp[64],
                        int l, int kappa, int gamma1, int gb)
{
    for (int i = 0; i < l; i++)
        expand_mask_poly(&y[i], rho_pp, kappa + i, gamma1, gb);
}

/* ---- SampleInBall (FIPS 204 Algorithm 29) ------------------------------ */

/*
 * Generate challenge polynomial with exactly tau nonzero ±1 coefficients.
 * Input: c_tilde (lambda/4 bytes).
 * Process:
 *   buf = SHAKE256(c_tilde, 136)
 *   buf[0..7] = sign bit pool (64 bits, need tau <= 49 bits)
 *   For i = (256-tau)..255:
 *     sample j <= i from buf stream
 *     c[i] = c[j]; c[j] = ±1 (sign from pool)
 */
static void sample_in_ball(poly_t *c, const uint8_t *ctilde, int ctlen, int tau)
{
    uint8_t buf[136];
    opssl_shake256(buf, sizeof(buf), ctilde, (size_t)ctlen);

    memset(c->c, 0, sizeof(c->c));

    uint64_t signs = 0;
    for (int i = 0; i < 8; i++)
        signs |= (uint64_t)buf[i] << (8 * i);

    int bp = 8;
    for (int i = MLDSA_N - tau; i < MLDSA_N; i++) {
        int j;
        do {
            if (bp >= (int)sizeof(buf)) {
                opssl_shake256(buf, sizeof(buf), ctilde, (size_t)ctlen);
                bp = 8;
            }
            j = (int)buf[bp++];
        } while (j > i);

        c->c[i] = c->c[j];
        c->c[j] = 1 - 2 * (int32_t)(signs & 1);
        signs >>= 1;
    }
}

/* ---- Hint packing ------------------------------------------------------ */

/*
 * Pack k hint polynomials (0/1-valued) into omega+k bytes.
 * Format: omega bytes of sorted positions (concatenated per-polynomial,
 *         zero-padded to omega total), then k end-index bytes.
 */
static int hint_pack(uint8_t *out, const poly_t *h, int k, int omega)
{
    int idx = 0;
    for (int i = 0; i < k; i++) {
        for (int j = 0; j < MLDSA_N; j++) {
            if (h[i].c[j]) {
                if (idx >= omega) return 0;
                out[idx++] = (uint8_t)j;
            }
        }
        out[omega + i] = (uint8_t)idx;
    }
    while (idx < omega) out[idx++] = 0;
    return 1;
}

/*
 * Unpack hints; returns 1 on success, 0 if malformed.
 * Validates: per-poly positions are strictly increasing and within bounds.
 */
static int hint_unpack(poly_t *h, const uint8_t *in, int k, int omega)
{
    int idx = 0;
    for (int i = 0; i < k; i++) {
        memset(h[i].c, 0, sizeof(h[i].c));
        int end = (int)in[omega + i];
        if (end > omega || end < idx) return 0;
        int prev = -1;
        while (idx < end) {
            int pos = (int)in[idx++];
            if (pos <= prev) return 0;
            prev = pos;
            h[i].c[pos] = 1;
        }
    }
    while (idx < omega) {
        if (in[idx++] != 0) return 0;
    }
    return 1;
}

/* ---- Key generation (FIPS 204 Algorithm 6) ----------------------------- */

int opssl_mldsa65_keygen(uint8_t pk[OPSSL_MLDSA65_PK_LEN],
                          uint8_t sk[OPSSL_MLDSA65_SK_LEN])
{
    const mldsa_params_t *P = &P65;
    const int k = P->k, l = P->l;
    const int eb = P->eta_bits, eta_bytes = MLDSA_N * eb / 8;

    uint8_t xi[32];
    if (opssl_random_bytes(xi, 32) != 0) return 0;

    uint8_t exp[128];
    opssl_shake256(exp, 128, xi, 32);
    const uint8_t *rho       = exp;
    const uint8_t *rho_prime = exp + 32;
    const uint8_t *K_key     = exp + 96;

    poly_t A[KMAX * LMAX];
    expand_a(A, rho, k, l);
    for (int i = 0; i < k * l; i++) mldsa_ntt(&A[i]);

    poly_t s1[LMAX], s2[KMAX];
    expand_s(s1, rho_prime, l, P->eta, 0);
    expand_s(s2, rho_prime, k, P->eta, l);

    poly_t s1n[LMAX];
    for (int i = 0; i < l; i++) { s1n[i] = s1[i]; mldsa_ntt(&s1n[i]); }

    poly_t t[KMAX];
    mat_vec_ntt(t, A, s1n, k, l);
    for (int i = 0; i < k; i++) {
        mldsa_invntt(&t[i]);
        poly_add(&t[i], &t[i], &s2[i]);
        poly_reduce(&t[i]);
    }

    poly_t t1[KMAX], t0[KMAX];
    for (int i = 0; i < k; i++) poly_power2round(&t1[i], &t0[i], &t[i]);

    memcpy(pk, rho, 32);
    for (int i = 0; i < k; i++) poly_pack_t1(pk + 32 + i * 320, &t1[i]);

    uint8_t tr[64];
    crh512(tr, pk, OPSSL_MLDSA65_PK_LEN);

    uint8_t *sp = sk;
    memcpy(sp, rho,    32); sp += 32;
    memcpy(sp, K_key,  32); sp += 32;
    memcpy(sp, tr,     64); sp += 64;
    for (int i = 0; i < l; i++) { poly_pack_eta(sp, &s1[i], P->eta, eb); sp += eta_bytes; }
    for (int i = 0; i < k; i++) { poly_pack_eta(sp, &s2[i], P->eta, eb); sp += eta_bytes; }
    for (int i = 0; i < k; i++) { poly_pack_t0(sp, &t0[i]); sp += 416; }

    opssl_memzero(xi,  sizeof(xi));
    opssl_memzero(exp, sizeof(exp));
    opssl_memzero(s1,  sizeof(s1));
    opssl_memzero(s2,  sizeof(s2));
    opssl_memzero(s1n, sizeof(s1n));
    opssl_memzero(t0,  sizeof(t0));
    return 1;
}

/* ---- Signing (FIPS 204 Algorithm 2) ------------------------------------ */

int opssl_mldsa65_sign(uint8_t sig[OPSSL_MLDSA65_SIG_LEN],
                        const uint8_t *msg, size_t msg_len,
                        const uint8_t sk[OPSSL_MLDSA65_SK_LEN])
{
    const mldsa_params_t *P = &P65;
    const int k = P->k, l = P->l;
    const int gamma1 = 1 << P->gamma1_log2;
    const int ctlen  = P->lambda / 4;   /* 48 bytes for ML-DSA-65 */
    const int eb     = P->eta_bits;
    const int eta_bytes = MLDSA_N * eb / 8;

    /* Unpack secret key */
    const uint8_t *rho    = sk;
    const uint8_t *K_key  = sk + 32;
    const uint8_t *tr     = sk + 64;
    const uint8_t *s1_enc = sk + 128;
    const uint8_t *s2_enc = s1_enc + (size_t)l * (size_t)eta_bytes;
    const uint8_t *t0_enc = s2_enc + (size_t)k * (size_t)eta_bytes;

    poly_t s1[LMAX], s2[KMAX], t0[KMAX];
    for (int i = 0; i < l; i++)
        poly_unpack_eta(&s1[i], s1_enc + (size_t)i * (size_t)eta_bytes, P->eta, eb);
    for (int i = 0; i < k; i++) {
        poly_unpack_eta(&s2[i], s2_enc + (size_t)i * (size_t)eta_bytes, P->eta, eb);
        poly_unpack_t0(&t0[i], t0_enc + (size_t)i * 416);
    }

    /* Convert secrets to NTT domain (constant-time polynomial ops follow) */
    for (int i = 0; i < l; i++) mldsa_ntt(&s1[i]);
    for (int i = 0; i < k; i++) { mldsa_ntt(&s2[i]); mldsa_ntt(&t0[i]); }

    /* Expand and NTT A */
    poly_t A[KMAX * LMAX];
    expand_a(A, rho, k, l);
    for (int i = 0; i < k * l; i++) mldsa_ntt(&A[i]);

    /* mu = SHAKE256(tr || msg, 64) */
    uint8_t mu[64];
    shake256_two(mu, 64, tr, 64, msg, msg_len);

    /* rho'' = SHAKE256(K || rnd || mu, 64); rnd=0^32 for deterministic signing */
    uint8_t rho_pp[64];
    {
        uint8_t rnd[32];
        memset(rnd, 0, 32);
        shake256_three(rho_pp, 64, K_key, 32, rnd, 32, mu, 64);
    }

    /* Rejection sampling loop */
    uint8_t ctilde[64];
    poly_t z[LMAX], h[KMAX];
    int kappa = 0;

    for (;;) {
        poly_t y[LMAX];
        expand_mask(y, rho_pp, l, kappa, gamma1, P->gamma1_bits);
        kappa += l;

        /* w = INTT(A * NTT(y)) */
        poly_t yn[LMAX];
        for (int i = 0; i < l; i++) { yn[i] = y[i]; mldsa_ntt(&yn[i]); }
        poly_t w[KMAX];
        mat_vec_ntt(w, A, yn, k, l);
        for (int i = 0; i < k; i++) { mldsa_invntt(&w[i]); poly_reduce(&w[i]); }

        /* w1 = HighBits(w) */
        poly_t w1[KMAX];
        for (int i = 0; i < k; i++) {
            poly_t w0_tmp;
            poly_decompose(&w1[i], &w0_tmp, &w[i], P->gamma2);
        }

        /* c~ = H(mu || Encode(w1)) */
        {
            const int wb = P->w1_bits;
            const size_t wenc_len = (size_t)k * MLDSA_N * (size_t)wb / 8;
            uint8_t wenc[KMAX * MLDSA_N * 6 / 8]; /* 6 bits max per coeff */
            for (int i = 0; i < k; i++)
                poly_pack(wenc + (size_t)i * MLDSA_N * (size_t)wb / 8, &w1[i], wb);
            shake256_two(ctilde, (size_t)ctlen, mu, 64, wenc, wenc_len);
        }

        /* c = SampleInBall(c~) */
        poly_t c, cn;
        sample_in_ball(&c, ctilde, ctlen, P->tau);
        cn = c;
        mldsa_ntt(&cn);

        /* z = y + c*s1 */
        poly_t cs1[LMAX];
        for (int i = 0; i < l; i++) {
            poly_pointwise_mont(&cs1[i], &cn, &s1[i]);
            mldsa_invntt(&cs1[i]);
            poly_add(&z[i], &y[i], &cs1[i]);
            poly_reduce(&z[i]);
            poly_center(&z[i]);
        }
        { int32_t zn = polyvec_norm_inf(z, l);
          if (zn >= gamma1 - P->beta) continue;
        }

        /* cs2 = INTT(c * NTT(s2)) */
        poly_t cs2[KMAX], r0[KMAX];
        for (int i = 0; i < k; i++) {
            poly_pointwise_mont(&cs2[i], &cn, &s2[i]);
            mldsa_invntt(&cs2[i]);
            poly_t wcs2;
            poly_sub(&wcs2, &w[i], &cs2[i]);
            poly_reduce(&wcs2);
            poly_t r1_unused;
            poly_decompose(&r1_unused, &r0[i], &wcs2, P->gamma2);
        }
        { int32_t r0n = polyvec_norm_inf(r0, k);
          if (r0n >= P->gamma2 - P->beta) continue;
        }

        /* ct0 = INTT(c * NTT(t0)) */
        poly_t ct0[KMAX];
        for (int i = 0; i < k; i++) {
            poly_pointwise_mont(&ct0[i], &cn, &t0[i]);
            mldsa_invntt(&ct0[i]);
            poly_reduce(&ct0[i]);
            poly_center(&ct0[i]);
        }
        { int32_t ct0n = polyvec_norm_inf(ct0, k);
          if (ct0n >= P->gamma2) continue;
        }

        /* Compute hints h: need w - cs2 and ct0 */
        int total_hints = 0;
        for (int i = 0; i < k; i++) {
            poly_t wcs2;
            poly_sub(&wcs2, &w[i], &cs2[i]);
            poly_reduce(&wcs2);
            for (int j = 0; j < MLDSA_N; j++) {
                h[i].c[j]    = make_hint(-ct0[i].c[j],
                                          wcs2.c[j] + ct0[i].c[j],
                                          P->gamma2);
                total_hints += h[i].c[j];
            }
        }
        if (total_hints > P->omega) continue;

        break;
    }

    /* Encode signature: c~ || z || h */
    uint8_t *sp = sig;
    memcpy(sp, ctilde, (size_t)ctlen);
    sp += ctlen;
    for (int i = 0; i < l; i++) {
        poly_pack_z(sp, &z[i], gamma1, P->gamma1_bits);
        sp += MLDSA_N * P->gamma1_bits / 8;
    }
    if (!hint_pack(sp, h, k, P->omega)) {
        /* Should not happen: total_hints passed the omega check above */
        opssl_memzero(sig, OPSSL_MLDSA65_SIG_LEN);
        opssl_memzero(s1, sizeof(s1)); opssl_memzero(s2, sizeof(s2));
        opssl_memzero(t0, sizeof(t0)); opssl_memzero(rho_pp, sizeof(rho_pp));
        opssl_memzero(mu, sizeof(mu));
        return 0;
    }

    opssl_memzero(s1, sizeof(s1)); opssl_memzero(s2, sizeof(s2));
    opssl_memzero(t0, sizeof(t0)); opssl_memzero(rho_pp, sizeof(rho_pp));
    opssl_memzero(mu, sizeof(mu));
    return 1;
}

/* ---- Verification (FIPS 204 Algorithm 3) ------------------------------- */

int opssl_mldsa65_verify(const uint8_t sig[OPSSL_MLDSA65_SIG_LEN],
                          const uint8_t *msg, size_t msg_len,
                          const uint8_t pk[OPSSL_MLDSA65_PK_LEN])
{
    const mldsa_params_t *P = &P65;
    const int k = P->k, l = P->l;
    const int gamma1 = 1 << P->gamma1_log2;
    const int ctlen  = P->lambda / 4;   /* 48 */
    const int gb     = P->gamma1_bits;  /* 20 */
    const int wb     = P->w1_bits;      /* 4  */

    /* Parse signature */
    const uint8_t *ctilde = sig;
    const uint8_t *z_enc  = sig + ctlen;
    const uint8_t *h_enc  = z_enc + (size_t)l * MLDSA_N * (size_t)gb / 8;

    /* Decode z and check ||z||_inf < gamma1 - beta */
    poly_t z[LMAX];
    for (int i = 0; i < l; i++)
        poly_unpack_z(&z[i], z_enc + (size_t)i * MLDSA_N * (size_t)gb / 8, gamma1, gb);
    if (polyvec_norm_inf(z, l) >= gamma1 - P->beta) return 0;

    /* Decode and validate hints */
    poly_t h[KMAX];
    if (!hint_unpack(h, h_enc, k, P->omega)) return 0;

    /* Unpack public key */
    const uint8_t *rho    = pk;
    const uint8_t *t1_enc = pk + 32;
    poly_t t1[KMAX];
    for (int i = 0; i < k; i++) poly_unpack_t1(&t1[i], t1_enc + i * 320);

    /* tr = CRH(pk) */
    uint8_t tr[64];
    crh512(tr, pk, OPSSL_MLDSA65_PK_LEN);

    /* mu = SHAKE256(tr || msg, 64) */
    uint8_t mu[64];
    shake256_two(mu, 64, tr, 64, msg, msg_len);

    /* c = SampleInBall(c~) */
    poly_t c;
    sample_in_ball(&c, ctilde, ctlen, P->tau);

    /* A in NTT domain */
    poly_t A[KMAX * LMAX];
    expand_a(A, rho, k, l);
    for (int i = 0; i < k * l; i++) mldsa_ntt(&A[i]);

    /* z and c in NTT domain */
    poly_t zn[LMAX], cn;
    for (int i = 0; i < l; i++) { zn[i] = z[i]; mldsa_ntt(&zn[i]); }
    cn = c;
    mldsa_ntt(&cn);

    /* t1 scaled by 2^13 in NTT domain.
     * t = t1*2^13 + t0; verifier computes: A*z - c*t = A*z - c*t1*2^13 - c*t0
     * but c*t0 is incorporated via hints, so we compute A*z - c*t1*2^13.
     */
    poly_t t1s[KMAX];
    for (int i = 0; i < k; i++) {
        for (int j = 0; j < MLDSA_N; j++) t1s[i].c[j] = t1[i].c[j] << 13;
        mldsa_ntt(&t1s[i]);
    }

    /* w' = INTT(A*z - c*t1_scaled) */
    poly_t wp[KMAX];
    mat_vec_ntt(wp, A, zn, k, l);
    for (int i = 0; i < k; i++) {
        poly_t ct1;
        poly_pointwise_mont(&ct1, &cn, &t1s[i]);
        poly_sub(&wp[i], &wp[i], &ct1);
        mldsa_invntt(&wp[i]);
        poly_reduce(&wp[i]);
    }

    /* w1' = UseHint(h, w') */
    poly_t w1p[KMAX];
    for (int i = 0; i < k; i++)
        for (int j = 0; j < MLDSA_N; j++)
            w1p[i].c[j] = use_hint(h[i].c[j], wp[i].c[j], P->gamma2);

    /* c~' = H(mu || Encode(w1')) */
    uint8_t ctilde_prime[64];
    {
        const size_t wenc_len = (size_t)k * MLDSA_N * (size_t)wb / 8;
        uint8_t wenc[KMAX * MLDSA_N * 6 / 8];
        for (int i = 0; i < k; i++)
            poly_pack(wenc + (size_t)i * MLDSA_N * (size_t)wb / 8, &w1p[i], wb);
        shake256_two(ctilde_prime, (size_t)ctlen, mu, 64, wenc, wenc_len);
    }

    /* Constant-time comparison */
    return opssl_ct_eq(ctilde, ctilde_prime, (size_t)ctlen);
}

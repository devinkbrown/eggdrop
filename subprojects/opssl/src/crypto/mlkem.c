/* ML-KEM (FIPS 203) - Post-quantum key encapsulation mechanism
 * Implementation for opssl TLS library
 * Parameters: q=3329, n=256, ML-KEM-768 (k=3), ML-KEM-1024 (k=4)
 */

#include <opssl/crypto.h>
#include <opssl/platform.h>
#include <string.h>

/* ML-KEM parameters */
#define MLKEM_Q         3329
#define MLKEM_N         256
#define MLKEM_SYMBYTES  32

/* Montgomery arithmetic constants */
#define MLKEM_MONT_R    2285    /* 2^16 mod q */
#define MLKEM_QINV      62209   /* q^(-1) mod 2^16, such that q * qinv = -1 mod 2^16 */

/* NTT constants */
#define MLKEM_ZETA      17      /* primitive 256th root of unity mod q */

/* Parameter sets */
typedef struct {
    int k;          /* vector dimension */
    int eta1, eta2; /* CBD parameters */
    int du, dv;     /* compression parameters */
    size_t pk_len, sk_len, ct_len;
} mlkem_params_t;

static const mlkem_params_t mlkem_params[] = {
    [OPSSL_MLKEM_768] = {
        .k = 3, .eta1 = 2, .eta2 = 2, .du = 10, .dv = 4,
        .pk_len = OPSSL_MLKEM768_PK_LEN, .sk_len = OPSSL_MLKEM768_SK_LEN, .ct_len = OPSSL_MLKEM768_CT_LEN
    },
    [OPSSL_MLKEM_1024] = {
        .k = 4, .eta1 = 2, .eta2 = 2, .du = 11, .dv = 5,
        .pk_len = OPSSL_MLKEM1024_PK_LEN, .sk_len = OPSSL_MLKEM1024_SK_LEN, .ct_len = OPSSL_MLKEM1024_CT_LEN
    }
};

/* Polynomial representation */
typedef struct {
    int16_t coeffs[MLKEM_N];
} poly_t;

/* Vector of polynomials */
typedef struct {
    poly_t vec[4];  /* max k=4 for ML-KEM-1024 */
} polyvec_t;

/* ML-KEM context */
struct opssl_mlkem_ctx {
    opssl_mlkem_level_t level;
    const mlkem_params_t *params;
    uint8_t *pk, *sk;           /* public/secret keys */
    bool keys_generated;
};

/* Precomputed zetas for NTT (Montgomery form) */
static const int16_t zetas[128] = {
    2285, 2571, 2970, 1812, 1493, 1422, 287, 202, 3158, 622, 1577, 182, 962,
    2127, 1855, 1468, 573, 2004, 264, 383, 2500, 1458, 1727, 3199, 2648, 1017,
    732, 608, 1787, 411, 3124, 1758, 1223, 652, 2777, 1015, 2036, 1491, 3047,
    1785, 516, 3321, 3009, 2663, 1711, 2167, 126, 1469, 2476, 3239, 3058, 830,
    107, 1908, 3082, 2378, 2931, 961, 1821, 2604, 448, 2264, 677, 2054, 2226,
    430, 555, 843, 2078, 871, 1550, 105, 422, 587, 177, 3094, 3038, 2869, 1574,
    1653, 3083, 778, 1159, 3182, 2552, 1483, 2727, 1119, 1739, 644, 2457, 349,
    418, 329, 3173, 3254, 817, 1097, 603, 610, 1322, 2044, 1864, 384, 2114, 3193,
    1218, 1994, 2455, 220, 2142, 1670, 2144, 1799, 2051, 794, 1819, 2475, 2459,
    478, 3221, 3021, 996, 991, 958, 1869, 1522, 1628
};

/* Barrett reduction: reduce x mod q */
static int16_t barrett_reduce(int16_t x) {
    int16_t t = ((int32_t)x * 20159) >> 26;
    return x - t * MLKEM_Q;
}

/* Montgomery reduction: compute aR^(-1) mod q where R = 2^16 */
static int16_t montgomery_reduce(int32_t a) {
    int16_t t = (int16_t)(a * MLKEM_QINV);
    t = (a - (int32_t)t * MLKEM_Q) >> 16;
    return t;
}

/* Conditional subtraction: subtract q if x >= q */
static int16_t csubq(int16_t x) {
    x -= MLKEM_Q;
    x += (x >> 15) & MLKEM_Q;
    return x;
}

/* Forward NTT */
static void ntt(poly_t *p) {
    int len = 128;
    for (int k = 0; k < 7; k++) {
        for (int start = 0; start < MLKEM_N; start += 2 * len) {
            int16_t zeta = zetas[k];
            for (int j = start; j < start + len; j++) {
                int16_t t = montgomery_reduce((int32_t)zeta * p->coeffs[j + len]);
                p->coeffs[j + len] = p->coeffs[j] - t;
                p->coeffs[j] = p->coeffs[j] + t;
            }
        }
        len >>= 1;
    }
}

/* Inverse NTT */
static void invntt(poly_t *p) {
    int len = 2;
    for (int k = 0; k < 7; k++) {
        for (int start = 0; start < MLKEM_N; start += 2 * len) {
            int16_t zeta = zetas[127 - k];
            for (int j = start; j < start + len; j++) {
                int16_t t = p->coeffs[j];
                p->coeffs[j] = barrett_reduce(t + p->coeffs[j + len]);
                p->coeffs[j + len] = montgomery_reduce((int32_t)zeta * (t - p->coeffs[j + len]));
            }
        }
        len <<= 1;
    }

    /* Multiply by n^(-1) = 3303 in Montgomery form */
    for (int i = 0; i < MLKEM_N; i++) {
        p->coeffs[i] = montgomery_reduce((int32_t)p->coeffs[i] * 3303);
    }
}

/* Pointwise multiplication in NTT domain */
static void poly_basemul(poly_t *r, const poly_t *a, const poly_t *b) {
    for (int i = 0; i < MLKEM_N / 4; i++) {
        int16_t zeta = zetas[64 + i];

        /* Basemul for 4 coefficients using zeta */
        int16_t a0 = a->coeffs[4*i], a1 = a->coeffs[4*i+1];
        int16_t a2 = a->coeffs[4*i+2], a3 = a->coeffs[4*i+3];
        int16_t b0 = b->coeffs[4*i], b1 = b->coeffs[4*i+1];
        int16_t b2 = b->coeffs[4*i+2], b3 = b->coeffs[4*i+3];

        r->coeffs[4*i] = montgomery_reduce((int32_t)a0 * b0 + (int32_t)a1 * b1 * zeta);
        r->coeffs[4*i+1] = montgomery_reduce((int32_t)a0 * b1 + (int32_t)a1 * b0);
        r->coeffs[4*i+2] = montgomery_reduce((int32_t)a2 * b2 + (int32_t)a3 * b3 * zeta);
        r->coeffs[4*i+3] = montgomery_reduce((int32_t)a2 * b3 + (int32_t)a3 * b2);
    }
}

/* Polynomial addition */
static void poly_add(poly_t *r, const poly_t *a, const poly_t *b) {
    for (int i = 0; i < MLKEM_N; i++) {
        r->coeffs[i] = a->coeffs[i] + b->coeffs[i];
    }
}

/* Polynomial subtraction */
static void poly_sub(poly_t *r, const poly_t *a, const poly_t *b) {
    for (int i = 0; i < MLKEM_N; i++) {
        r->coeffs[i] = a->coeffs[i] - b->coeffs[i];
    }
}

/* Reduce all coefficients modulo q */
static void poly_reduce(poly_t *p) {
    for (int i = 0; i < MLKEM_N; i++) {
        p->coeffs[i] = barrett_reduce(p->coeffs[i]);
    }
}

/* Compress polynomial coefficients */
static void poly_compress(uint8_t *out, const poly_t *p, int d) {
    if (d == 1) {
        /* Special case for d=1 (message compression) */
        for (int i = 0; i < MLKEM_N / 8; i++) {
            uint8_t t = 0;
            for (int j = 0; j < 8; j++) {
                int16_t c = csubq(p->coeffs[8*i + j]);
                t |= ((((uint32_t)c << 1) + MLKEM_Q/2) / MLKEM_Q) << j;
            }
            out[i] = t;
        }
    } else {
        /* General compression for d > 1 */
        uint32_t mask = (1 << d) - 1;
        int bits = 0;
        uint32_t acc = 0;
        int out_idx = 0;

        for (int i = 0; i < MLKEM_N; i++) {
            int16_t c = csubq(p->coeffs[i]);
            uint32_t compressed = (((uint32_t)c << d) + MLKEM_Q/2) / MLKEM_Q;
            compressed &= mask;

            acc |= compressed << bits;
            bits += d;

            while (bits >= 8) {
                out[out_idx++] = acc & 0xFF;
                acc >>= 8;
                bits -= 8;
            }
        }

        if (bits > 0) {
            out[out_idx] = acc;
        }
    }
}

/* Decompress polynomial coefficients */
static void poly_decompress(poly_t *p, const uint8_t *in, int d) {
    if (d == 1) {
        /* Special case for d=1 */
        for (int i = 0; i < MLKEM_N / 8; i++) {
            uint8_t t = in[i];
            for (int j = 0; j < 8; j++) {
                p->coeffs[8*i + j] = ((t >> j) & 1) ? (MLKEM_Q + 1) / 2 : 0;
            }
        }
    } else {
        /* General decompression */
        uint32_t mask = (1 << d) - 1;
        int bits = 0;
        uint32_t acc = 0;
        int in_idx = 0;

        for (int i = 0; i < MLKEM_N; i++) {
            while (bits < d) {
                acc |= (uint32_t)in[in_idx++] << bits;
                bits += 8;
            }

            uint32_t compressed = acc & mask;
            p->coeffs[i] = ((compressed * MLKEM_Q) + (1 << (d-1))) >> d;

            acc >>= d;
            bits -= d;
        }
    }
}

/* Centered Binomial Distribution sampling for η=2 */
static void cbd2(poly_t *r, const uint8_t *buf) {
    for (int i = 0; i < MLKEM_N / 2; i++) {
        uint32_t t = buf[2*i] | ((uint32_t)buf[2*i+1] << 8);
        uint32_t d = t & 0x5555;
        d += (t >> 1) & 0x5555;

        for (int j = 0; j < 2; j++) {
            int16_t a = (d >> (2*j)) & 3;
            int16_t b = (d >> (2*j+8)) & 3;
            r->coeffs[2*i + j] = a - b;
        }
    }
}

/* XOF for matrix generation */
static void gen_matrix_row(polyvec_t *a, const uint8_t rho[32], int row, int k) {
    for (int col = 0; col < k; col++) {
        uint8_t seed[34];
        memcpy(seed, rho, 32);
        seed[32] = col;
        seed[33] = row;

        uint8_t buf[672];  /* 256 * 13 / 8 rounded up */
        opssl_shake128(buf, sizeof(buf), seed, 34);

        int pos = 0, ctr = 0;
        while (ctr < MLKEM_N && pos < sizeof(buf) - 2) {
            uint16_t val = buf[pos] | ((uint16_t)buf[pos+1] << 8);
            pos += 2;
            val &= 0x1FFF;  /* 13 bits */

            if (val < MLKEM_Q) {
                a->vec[col].coeffs[ctr++] = val;
            }
        }
    }
}

/* PRF for sampling noise */
static void prf(uint8_t *out, size_t outlen, const uint8_t key[32], uint8_t nonce) {
    uint8_t seed[33];
    memcpy(seed, key, 32);
    seed[32] = nonce;
    opssl_shake256(out, outlen, seed, 33);
}

/* G function: SHA3-512 */
static void kdf_g(uint8_t out[64], const uint8_t *in, size_t inlen) {
    opssl_sha3_512(in, inlen, out);
}

/* H function: SHA3-256 */
static void kdf_h(uint8_t out[32], const uint8_t *in, size_t inlen) {
    opssl_sha3_256(in, inlen, out);
}

/* Encode/decode functions */
static void encode_polyvec(uint8_t *out, const polyvec_t *v, int k, int d) {
    for (int i = 0; i < k; i++) {
        poly_compress(out, &v->vec[i], d);
        out += (MLKEM_N * d + 7) / 8;
    }
}

static void decode_polyvec(polyvec_t *v, const uint8_t *in, int k, int d) {
    for (int i = 0; i < k; i++) {
        poly_decompress(&v->vec[i], in, d);
        in += (MLKEM_N * d + 7) / 8;
    }
}

/* Constant-time conditional move */
static void cmov(uint8_t *r, const uint8_t *a, size_t len, int b) {
    uint8_t mask = -b;
    for (size_t i = 0; i < len; i++) {
        r[i] ^= mask & (r[i] ^ a[i]);
    }
}

/* Constant-time comparison */
static int verify(const uint8_t *a, const uint8_t *b, size_t len) {
    uint8_t r = 0;
    for (size_t i = 0; i < len; i++) {
        r |= a[i] ^ b[i];
    }
    return (-(uint32_t)r) >> 31;
}

opssl_mlkem_ctx_t *opssl_mlkem_new(opssl_mlkem_level_t level) {
    if (level != OPSSL_MLKEM_768 && level != OPSSL_MLKEM_1024) {
        return NULL;
    }

    opssl_mlkem_ctx_t *ctx = op_malloc(sizeof(*ctx));
    if (!ctx) return NULL;

    ctx->level = level;
    ctx->params = &mlkem_params[level];
    ctx->pk = op_malloc(ctx->params->pk_len);
    ctx->sk = op_malloc(ctx->params->sk_len);
    ctx->keys_generated = false;

    if (!ctx->pk || !ctx->sk) {
        opssl_mlkem_free(ctx);
        return NULL;
    }

    return ctx;
}

int opssl_mlkem_keygen(opssl_mlkem_ctx_t *ctx) {
    if (!ctx) return -1;

    const mlkem_params_t *p = ctx->params;
    uint8_t d[32], z[32];
    uint8_t rho[32], sigma[32];

    /* Generate random seeds */
    if (opssl_random_bytes(d, 32) != 0 || opssl_random_bytes(z, 32) != 0) {
        return -1;
    }

    /* (rho, sigma) = G(d) */
    uint8_t g_out[64];
    kdf_g(g_out, d, 32);
    memcpy(rho, g_out, 32);
    memcpy(sigma, g_out + 32, 32);

    /* Generate matrix A */
    polyvec_t a[4];  /* max k=4 */
    for (int i = 0; i < p->k; i++) {
        gen_matrix_row(&a[i], rho, i, p->k);
        for (int j = 0; j < p->k; j++) {
            ntt(&a[i].vec[j]);
        }
    }

    /* Sample secret s and error e */
    polyvec_t s, e;
    uint8_t noise_seed[128];
    for (int i = 0; i < p->k; i++) {
        prf(noise_seed, 128, sigma, i);
        cbd2(&s.vec[i], noise_seed);

        prf(noise_seed, 128, sigma, i + p->k);
        cbd2(&e.vec[i], noise_seed);

        ntt(&s.vec[i]);
        ntt(&e.vec[i]);
    }

    /* Compute t = As + e */
    polyvec_t t;
    for (int i = 0; i < p->k; i++) {
        poly_t temp;
        poly_basemul(&temp, &a[i].vec[0], &s.vec[0]);
        for (int j = 1; j < p->k; j++) {
            poly_t prod;
            poly_basemul(&prod, &a[i].vec[j], &s.vec[j]);
            poly_add(&temp, &temp, &prod);
        }
        poly_add(&t.vec[i], &temp, &e.vec[i]);
        poly_reduce(&t.vec[i]);
    }

    /* Encode keys */
    uint8_t *pk_ptr = ctx->pk;
    uint8_t *sk_ptr = ctx->sk;

    /* Public key: pk = (t_encoded || rho) */
    encode_polyvec(pk_ptr, &t, p->k, 12);
    pk_ptr += p->k * 384;  /* 256 * 12 / 8 = 384 bytes per poly */
    memcpy(pk_ptr, rho, 32);

    /* Secret key: dk = (s_encoded || pk || H(pk) || z) */
    for (int i = 0; i < p->k; i++) {
        invntt(&s.vec[i]);
        poly_compress(sk_ptr, &s.vec[i], 12);
        sk_ptr += 384;
    }
    memcpy(sk_ptr, ctx->pk, ctx->params->pk_len);
    sk_ptr += ctx->params->pk_len;
    kdf_h(sk_ptr, ctx->pk, ctx->params->pk_len);
    sk_ptr += 32;
    memcpy(sk_ptr, z, 32);

    opssl_memzero(d, sizeof(d));
    opssl_memzero(z, sizeof(z));
    opssl_memzero(sigma, sizeof(sigma));

    ctx->keys_generated = true;
    return 0;
}

int opssl_mlkem_encaps(opssl_mlkem_ctx_t *ctx, const uint8_t *pk, size_t pk_len,
                       uint8_t *ct, size_t *ct_len, uint8_t *ss, size_t *ss_len) {
    if (!ctx || !pk || !ct || !ct_len || !ss || !ss_len) return -1;
    if (pk_len != ctx->params->pk_len) return -1;

    const mlkem_params_t *p = ctx->params;
    uint8_t m[32], kr[64], h_pk[32];

    /* Generate random message */
    if (opssl_random_bytes(m, 32) != 0) return -1;

    /* H(pk) */
    kdf_h(h_pk, pk, pk_len);

    /* (K || r) = G(m || H(pk)) */
    uint8_t m_h[64];
    memcpy(m_h, m, 32);
    memcpy(m_h + 32, h_pk, 32);
    kdf_g(kr, m_h, 64);

    /* Encrypt: ct = K-PKE.Encrypt(pk, m, r) */
    uint8_t *r = kr + 32;

    /* Decode public key */
    polyvec_t t;
    uint8_t rho[32];
    decode_polyvec(&t, pk, p->k, 12);
    memcpy(rho, pk + p->k * 384, 32);

    /* Transform t to NTT domain */
    for (int i = 0; i < p->k; i++) {
        ntt(&t.vec[i]);
    }

    /* Generate matrix A */
    polyvec_t a[4];
    for (int i = 0; i < p->k; i++) {
        gen_matrix_row(&a[i], rho, i, p->k);
        for (int j = 0; j < p->k; j++) {
            ntt(&a[i].vec[j]);
        }
    }

    /* Sample r, e1, e2 from r */
    polyvec_t r_vec, e1;
    poly_t e2;
    uint8_t noise[128];

    for (int i = 0; i < p->k; i++) {
        prf(noise, 128, r, i);
        cbd2(&r_vec.vec[i], noise);
        ntt(&r_vec.vec[i]);
    }

    for (int i = 0; i < p->k; i++) {
        prf(noise, 128, r, i + p->k);
        cbd2(&e1.vec[i], noise);
    }

    prf(noise, 128, r, 2 * p->k);
    cbd2(&e2, noise);

    /* u = A^T * r + e1 */
    polyvec_t u;
    for (int i = 0; i < p->k; i++) {
        poly_t temp;
        poly_basemul(&temp, &a[0].vec[i], &r_vec.vec[0]);
        for (int j = 1; j < p->k; j++) {
            poly_t prod;
            poly_basemul(&prod, &a[j].vec[i], &r_vec.vec[j]);
            poly_add(&temp, &temp, &prod);
        }
        invntt(&temp);
        poly_add(&u.vec[i], &temp, &e1.vec[i]);
        poly_reduce(&u.vec[i]);
    }

    /* v = t^T * r + e2 + decompress(m, 1) */
    poly_t v, mu;
    poly_decompress(&mu, m, 1);

    poly_t temp;
    poly_basemul(&temp, &t.vec[0], &r_vec.vec[0]);
    for (int j = 1; j < p->k; j++) {
        poly_t prod;
        poly_basemul(&prod, &t.vec[j], &r_vec.vec[j]);
        poly_add(&temp, &temp, &prod);
    }
    invntt(&temp);
    poly_add(&v, &temp, &e2);
    poly_add(&v, &v, &mu);
    poly_reduce(&v);

    /* Encode ciphertext */
    uint8_t *ct_ptr = ct;
    encode_polyvec(ct_ptr, &u, p->k, p->du);
    ct_ptr += p->k * ((MLKEM_N * p->du + 7) / 8);
    poly_compress(ct_ptr, &v, p->dv);

    *ct_len = ctx->params->ct_len;
    memcpy(ss, kr, 32);  /* K */
    *ss_len = 32;

    /* Clear sensitive data */
    opssl_memzero(m, sizeof(m));
    opssl_memzero(kr, sizeof(kr));
    opssl_memzero(r, 32);

    return 0;
}

int opssl_mlkem_decaps(opssl_mlkem_ctx_t *ctx, const uint8_t *ct, size_t ct_len,
                       uint8_t *ss, size_t *ss_len) {
    if (!ctx || !ct || !ss || !ss_len || !ctx->keys_generated) return -1;
    if (ct_len != ctx->params->ct_len) return -1;

    const mlkem_params_t *p = ctx->params;

    /* Extract components from secret key */
    const uint8_t *s_enc = ctx->sk;
    const uint8_t *pk = ctx->sk + p->k * 384;
    const uint8_t *h_pk = pk + ctx->params->pk_len;
    const uint8_t *z = h_pk + 32;

    /* Decode secret key */
    polyvec_t s;
    for (int i = 0; i < p->k; i++) {
        poly_decompress(&s.vec[i], s_enc + i * 384, 12);
        ntt(&s.vec[i]);
    }

    /* Decode ciphertext */
    polyvec_t u;
    poly_t v;
    const uint8_t *ct_ptr = ct;
    decode_polyvec(&u, ct_ptr, p->k, p->du);
    ct_ptr += p->k * ((MLKEM_N * p->du + 7) / 8);
    poly_decompress(&v, ct_ptr, p->dv);

    /* Transform u to NTT domain */
    for (int i = 0; i < p->k; i++) {
        ntt(&u.vec[i]);
    }

    /* m' = v - s^T * u */
    poly_t temp;
    poly_basemul(&temp, &s.vec[0], &u.vec[0]);
    for (int j = 1; j < p->k; j++) {
        poly_t prod;
        poly_basemul(&prod, &s.vec[j], &u.vec[j]);
        poly_add(&temp, &temp, &prod);
    }
    invntt(&temp);
    poly_sub(&v, &v, &temp);
    poly_reduce(&v);

    uint8_t m_prime[32];
    poly_compress(m_prime, &v, 1);

    /* (K' || r') = G(m' || H(pk)) */
    uint8_t m_h[64], kr_prime[64];
    memcpy(m_h, m_prime, 32);
    memcpy(m_h + 32, h_pk, 32);
    kdf_g(kr_prime, m_h, 64);

    /* Re-encrypt to verify */
    uint8_t ct_prime[OPSSL_MLKEM1024_CT_LEN];  /* max size */
    size_t ct_prime_len;
    uint8_t ss_prime[32];
    size_t ss_prime_len;

    int enc_result = opssl_mlkem_encaps(ctx, pk, ctx->params->pk_len,
                                        ct_prime, &ct_prime_len, ss_prime, &ss_prime_len);
    if (enc_result != 0) return -1;

    /* Constant-time comparison */
    int equal = verify(ct, ct_prime, ct_len);

    /* Compute rejection key: KDF(z || H(ct)) */
    uint8_t z_h_ct[64], reject_key[32];
    memcpy(z_h_ct, z, 32);
    kdf_h(z_h_ct + 32, ct, ct_len);
    kdf_h(reject_key, z_h_ct, 64);

    /* Constant-time select: ss = equal ? K' : reject_key */
    cmov(ss, reject_key, 32, 1 - equal);
    cmov(ss, kr_prime, 32, equal);
    *ss_len = 32;

    /* Clear sensitive data */
    opssl_memzero(m_prime, sizeof(m_prime));
    opssl_memzero(kr_prime, sizeof(kr_prime));
    opssl_memzero(reject_key, sizeof(reject_key));

    return 0;
}

int opssl_mlkem_get_public(opssl_mlkem_ctx_t *ctx, uint8_t *pk, size_t *pk_len) {
    if (!ctx || !pk || !pk_len || !ctx->keys_generated) return -1;
    if (*pk_len < ctx->params->pk_len) return -1;

    memcpy(pk, ctx->pk, ctx->params->pk_len);
    *pk_len = ctx->params->pk_len;
    return 0;
}

void opssl_mlkem_free(opssl_mlkem_ctx_t *ctx) {
    if (!ctx) return;

    if (ctx->pk) {
        opssl_memzero(ctx->pk, ctx->params->pk_len);
        op_free(ctx->pk);
    }
    if (ctx->sk) {
        opssl_memzero(ctx->sk, ctx->params->sk_len);
        op_free(ctx->sk);
    }

    opssl_memzero(ctx, sizeof(*ctx));
    op_free(ctx);
}
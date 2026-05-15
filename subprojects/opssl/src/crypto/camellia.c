/*
 * opssl/crypto/camellia.c — Camellia block cipher (RFC 3713) + GCM mode.
 *
 * 128-bit block cipher with 128/256-bit keys.
 * Feistel network with SP-function, FL/FLINV layers every 6 rounds.
 * 18 rounds for 128-bit keys, 24 rounds for 256-bit keys.
 *
 * GCM mode reuses the same GHASH (GF(2^128)) construction as AES-GCM
 * with Camellia as the underlying block cipher.
 *
 * Copyright (C) 2026 ophion development team
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <opssl/crypto.h>
#include <opssl/platform.h>
#include <string.h>

/* ─── S-box (RFC 3713 §2.4.1) ──────────────────────────────────────── */

static const uint8_t SBOX1[256] = {
    112,130, 44,236,179, 39,192,229,228,133, 87, 53,234, 12,174, 65,
     35,239,107,147, 69, 25,165, 33,237, 14, 79, 78, 29,101,146,189,
    134,184,175,143,124,235, 31,206, 62, 48,220, 95, 94,197, 11, 26,
    166,225, 57,202,213, 71, 93, 61,217,  1, 90,214, 81, 86,108, 77,
    139, 13,154,102,251,204,176, 45,116, 18, 43, 32,240,177,132,153,
    223, 76,203,194, 52,126,118,  5,109,183,169, 49,209, 23,  4,215,
     20, 88, 58, 97,222, 27, 17, 28, 50, 15,156, 22, 83, 24,242, 34,
    254, 68,207,178,195,181,122,145, 36,  8,232,168, 96,252,105, 80,
    170,208,160,125,161,137, 98,151, 84, 91, 30,149,224,255,100,210,
     16,196,  0, 72,163,247,117,219,138,  3,230,218,  9, 63,221,148,
    135, 92,131,  2,205, 74,144, 51,115,103,246,243,157,127,191,226,
     82,155,216, 38,200, 55,198, 59,129,150,111, 75, 19,190, 99, 46,
    233,121,167,140,159,110,188,142, 41,245,249,182, 47,253,180, 89,
    120,152,  6,106,231, 70,113,186,212, 37,171, 66,136,162,141,250,
    114,  7,185, 85,248,238,172, 10, 54, 73, 42,104, 60, 56,241,164,
     64, 40,211,123,187,201, 67,193, 21,227,173,244,119,199,128,158,
};

#define ROL8(x, n)  ((uint8_t)(((x) << (n)) | ((x) >> (8 - (n)))))
#define S1(x)       (SBOX1[(x)])
#define S2(x)       ROL8(SBOX1[(x)], 1)
#define S3(x)       ROL8(SBOX1[(x)], 7)
#define S4(x)       SBOX1[ROL8((x), 1)]

/* ─── Sigma constants (√2, √3 fractional digits) ───────────────────── */

static const uint64_t SIGMA[6] = {
    UINT64_C(0xA09E667F3BCC908B), UINT64_C(0xB67AE8584CAA73B2),
    UINT64_C(0xC6EF372FE94F82BE), UINT64_C(0x54FF53A5F1D36F1C),
    UINT64_C(0x10E527FADE682D1D), UINT64_C(0xB05688C2B3E6C1FD),
};

/* ─── Core operations ───────────────────────────────────────────────── */

/* SP-function: S-box substitution + P-function diffusion (RFC 3713 §2.4.1) */
static uint64_t
camellia_sp(uint64_t x)
{
    uint8_t t1 = S1((x >> 56) & 0xFF);
    uint8_t t2 = S2((x >> 48) & 0xFF);
    uint8_t t3 = S3((x >> 40) & 0xFF);
    uint8_t t4 = S4((x >> 32) & 0xFF);
    uint8_t t5 = S2((x >> 24) & 0xFF);
    uint8_t t6 = S3((x >> 16) & 0xFF);
    uint8_t t7 = S4((x >>  8) & 0xFF);
    uint8_t t8 = S1( x        & 0xFF);

    uint8_t z1 = t1 ^ t3 ^ t4 ^ t6 ^ t7 ^ t8;
    uint8_t z2 = t1 ^ t2 ^ t4 ^ t5 ^ t7 ^ t8;
    uint8_t z3 = t1 ^ t2 ^ t3 ^ t5 ^ t6 ^ t8;
    uint8_t z4 = t2 ^ t3 ^ t4 ^ t5 ^ t6 ^ t7;
    uint8_t z5 = t1 ^ t2 ^ t6 ^ t7 ^ t8;
    uint8_t z6 = t2 ^ t3 ^ t5 ^ t7 ^ t8;
    uint8_t z7 = t3 ^ t4 ^ t5 ^ t6 ^ t8;
    uint8_t z8 = t1 ^ t4 ^ t5 ^ t6 ^ t7;

    return ((uint64_t)z1 << 56) | ((uint64_t)z2 << 48) |
           ((uint64_t)z3 << 40) | ((uint64_t)z4 << 32) |
           ((uint64_t)z5 << 24) | ((uint64_t)z6 << 16) |
           ((uint64_t)z7 <<  8) | (uint64_t)z8;
}

static inline uint64_t
camellia_f(uint64_t d, uint64_t k)
{
    return camellia_sp(d ^ k);
}

static uint64_t
camellia_fl(uint64_t x, uint64_t k)
{
    uint32_t x1 = (uint32_t)(x >> 32), x2 = (uint32_t)x;
    uint32_t k1 = (uint32_t)(k >> 32), k2 = (uint32_t)k;
    uint32_t t = x1 & k1;
    x2 ^= (t << 1) | (t >> 31);
    x1 ^= (x2 | k2);
    return ((uint64_t)x1 << 32) | (uint64_t)x2;
}

static uint64_t
camellia_flinv(uint64_t y, uint64_t k)
{
    uint32_t y1 = (uint32_t)(y >> 32), y2 = (uint32_t)y;
    uint32_t k1 = (uint32_t)(k >> 32), k2 = (uint32_t)k;
    y1 ^= (y2 | k2);
    uint32_t t = y1 & k1;
    y2 ^= (t << 1) | (t >> 31);
    return ((uint64_t)y1 << 32) | (uint64_t)y2;
}

/* 128-bit left rotation of (hi, lo) by n bits */
static void
rot128(uint64_t *hi, uint64_t *lo, int n)
{
    uint64_t h = *hi, l = *lo;
    if (n < 64) {
        *hi = (h << n) | (l >> (64 - n));
        *lo = (l << n) | (h >> (64 - n));
    } else if (n == 64) {
        *hi = l; *lo = h;
    } else {
        n -= 64;
        *hi = (l << n) | (h >> (64 - n));
        *lo = (h << n) | (l >> (64 - n));
    }
}

/* ─── Key Schedule ──────────────────────────────────────────────────── */

typedef struct {
    uint64_t kw[4];
    uint64_t k[24];
    uint64_t ke[6];
    int      nr;
} camellia_ctx_t;

static void
camellia_keygen_128(camellia_ctx_t *ctx, const uint8_t *key)
{
    uint64_t KLh = opssl_be64(key), KLl = opssl_be64(key + 8);
    uint64_t D1, D2, KAh, KAl, rh, rl;

    D1 = KLh; D2 = KLl;
    D2 ^= camellia_f(D1, SIGMA[0]);
    D1 ^= camellia_f(D2, SIGMA[1]);
    D1 ^= KLh; D2 ^= KLl;
    D2 ^= camellia_f(D1, SIGMA[2]);
    D1 ^= camellia_f(D2, SIGMA[3]);
    KAh = D1; KAl = D2;

    ctx->nr = 18;
    ctx->kw[0] = KLh;              ctx->kw[1] = KLl;
    ctx->k[0]  = KAh;              ctx->k[1]  = KAl;

    rh = KLh; rl = KLl; rot128(&rh, &rl, 15);
    ctx->k[2] = rh;                ctx->k[3] = rl;
    rh = KAh; rl = KAl; rot128(&rh, &rl, 15);
    ctx->k[4] = rh;                ctx->k[5] = rl;
    rh = KAh; rl = KAl; rot128(&rh, &rl, 30);
    ctx->ke[0] = rh;               ctx->ke[1] = rl;
    rh = KLh; rl = KLl; rot128(&rh, &rl, 45);
    ctx->k[6] = rh;                ctx->k[7] = rl;
    rh = KAh; rl = KAl; rot128(&rh, &rl, 45);
    ctx->k[8] = rh;
    rh = KLh; rl = KLl; rot128(&rh, &rl, 60);
    ctx->k[9] = rl;                /* k10 = (KL<<<60)_R, not (KA<<<45)_R */
    rh = KAh; rl = KAl; rot128(&rh, &rl, 60);
    ctx->k[10] = rh;               ctx->k[11] = rl;
    rh = KLh; rl = KLl; rot128(&rh, &rl, 77);
    ctx->ke[2] = rh;               ctx->ke[3] = rl;
    rh = KLh; rl = KLl; rot128(&rh, &rl, 94);
    ctx->k[12] = rh;               ctx->k[13] = rl;
    rh = KAh; rl = KAl; rot128(&rh, &rl, 94);
    ctx->k[14] = rh;               ctx->k[15] = rl;
    rh = KLh; rl = KLl; rot128(&rh, &rl, 111);
    ctx->k[16] = rh;               ctx->k[17] = rl;
    rh = KAh; rl = KAl; rot128(&rh, &rl, 111);
    ctx->kw[2] = rh;               ctx->kw[3] = rl;
}

static void
camellia_keygen_256(camellia_ctx_t *ctx, const uint8_t *key)
{
    uint64_t KLh = opssl_be64(key),      KLl = opssl_be64(key + 8);
    uint64_t KRh = opssl_be64(key + 16), KRl = opssl_be64(key + 24);
    uint64_t D1, D2, KAh, KAl, KBh, KBl, rh, rl;

    D1 = KLh ^ KRh; D2 = KLl ^ KRl;
    D2 ^= camellia_f(D1, SIGMA[0]);
    D1 ^= camellia_f(D2, SIGMA[1]);
    D1 ^= KLh; D2 ^= KLl;
    D2 ^= camellia_f(D1, SIGMA[2]);
    D1 ^= camellia_f(D2, SIGMA[3]);
    KAh = D1; KAl = D2;

    D1 = KAh ^ KRh; D2 = KAl ^ KRl;
    D2 ^= camellia_f(D1, SIGMA[4]);
    D1 ^= camellia_f(D2, SIGMA[5]);
    KBh = D1; KBl = D2;

    ctx->nr = 24;
    ctx->kw[0] = KLh;              ctx->kw[1] = KLl;
    ctx->k[0]  = KBh;              ctx->k[1]  = KBl;

    rh = KRh; rl = KRl; rot128(&rh, &rl, 15);
    ctx->k[2] = rh;                ctx->k[3] = rl;
    rh = KAh; rl = KAl; rot128(&rh, &rl, 15);
    ctx->k[4] = rh;                ctx->k[5] = rl;
    rh = KRh; rl = KRl; rot128(&rh, &rl, 30);
    ctx->ke[0] = rh;               ctx->ke[1] = rl;
    rh = KBh; rl = KBl; rot128(&rh, &rl, 30);
    ctx->k[6] = rh;                ctx->k[7] = rl;
    rh = KLh; rl = KLl; rot128(&rh, &rl, 45);
    ctx->k[8] = rh;                ctx->k[9] = rl;
    rh = KAh; rl = KAl; rot128(&rh, &rl, 45);
    ctx->k[10] = rh;               ctx->k[11] = rl;
    rh = KLh; rl = KLl; rot128(&rh, &rl, 60);
    ctx->ke[2] = rh;               ctx->ke[3] = rl;
    rh = KRh; rl = KRl; rot128(&rh, &rl, 60);
    ctx->k[12] = rh;               ctx->k[13] = rl;
    rh = KBh; rl = KBl; rot128(&rh, &rl, 60);
    ctx->k[14] = rh;               ctx->k[15] = rl;
    rh = KLh; rl = KLl; rot128(&rh, &rl, 77);
    ctx->k[16] = rh;               ctx->k[17] = rl;
    rh = KAh; rl = KAl; rot128(&rh, &rl, 77);
    ctx->ke[4] = rh;               ctx->ke[5] = rl;
    rh = KRh; rl = KRl; rot128(&rh, &rl, 94);
    ctx->k[18] = rh;               ctx->k[19] = rl;
    rh = KAh; rl = KAl; rot128(&rh, &rl, 94);
    ctx->k[20] = rh;               ctx->k[21] = rl;
    rh = KLh; rl = KLl; rot128(&rh, &rl, 111);
    ctx->k[22] = rh;               ctx->k[23] = rl;
    rh = KBh; rl = KBl; rot128(&rh, &rl, 111);
    ctx->kw[2] = rh;               ctx->kw[3] = rl;
}

/* ─── Block Encryption ──────────────────────────────────────────────── */

static void
camellia_encrypt_block(const camellia_ctx_t *ctx, uint8_t out[16], const uint8_t in[16])
{
    uint64_t D1 = opssl_be64(in);
    uint64_t D2 = opssl_be64(in + 8);

    D1 ^= ctx->kw[0]; D2 ^= ctx->kw[1];

    D2 ^= camellia_f(D1, ctx->k[0]);
    D1 ^= camellia_f(D2, ctx->k[1]);
    D2 ^= camellia_f(D1, ctx->k[2]);
    D1 ^= camellia_f(D2, ctx->k[3]);
    D2 ^= camellia_f(D1, ctx->k[4]);
    D1 ^= camellia_f(D2, ctx->k[5]);

    D1 = camellia_fl(D1, ctx->ke[0]);
    D2 = camellia_flinv(D2, ctx->ke[1]);

    D2 ^= camellia_f(D1, ctx->k[6]);
    D1 ^= camellia_f(D2, ctx->k[7]);
    D2 ^= camellia_f(D1, ctx->k[8]);
    D1 ^= camellia_f(D2, ctx->k[9]);
    D2 ^= camellia_f(D1, ctx->k[10]);
    D1 ^= camellia_f(D2, ctx->k[11]);

    D1 = camellia_fl(D1, ctx->ke[2]);
    D2 = camellia_flinv(D2, ctx->ke[3]);

    D2 ^= camellia_f(D1, ctx->k[12]);
    D1 ^= camellia_f(D2, ctx->k[13]);
    D2 ^= camellia_f(D1, ctx->k[14]);
    D1 ^= camellia_f(D2, ctx->k[15]);
    D2 ^= camellia_f(D1, ctx->k[16]);
    D1 ^= camellia_f(D2, ctx->k[17]);

    if (ctx->nr == 24) {
        D1 = camellia_fl(D1, ctx->ke[4]);
        D2 = camellia_flinv(D2, ctx->ke[5]);

        D2 ^= camellia_f(D1, ctx->k[18]);
        D1 ^= camellia_f(D2, ctx->k[19]);
        D2 ^= camellia_f(D1, ctx->k[20]);
        D1 ^= camellia_f(D2, ctx->k[21]);
        D2 ^= camellia_f(D1, ctx->k[22]);
        D1 ^= camellia_f(D2, ctx->k[23]);
    }

    D2 ^= ctx->kw[2]; D1 ^= ctx->kw[3];
    opssl_put_be64(out, D2);
    opssl_put_be64(out + 8, D1);
}

static int
camellia_set_key(camellia_ctx_t *ctx, const uint8_t *key, size_t key_len)
{
    memset(ctx, 0, sizeof(*ctx));
    if (key_len == 16)
        camellia_keygen_128(ctx, key);
    else if (key_len == 32)
        camellia_keygen_256(ctx, key);
    else
        return 0;
    return 1;
}

/* ─── Camellia-GCM (GF(2^128) GHASH + CTR) ─────────────────────────── */

typedef struct {
    camellia_ctx_t cam;
    uint8_t  H[16];
    uint8_t  J0[16];
    uint8_t  ghash[16];
    uint64_t aad_len;
    uint64_t ct_len;
} cam_gcm_t;

static void
cam_ghash_mult(uint8_t out[16], const uint8_t x[16], const uint8_t h[16])
{
    uint8_t v[16], z[16] = {0};
    memcpy(v, h, 16);

    for (int i = 0; i < 128; i++) {
        uint8_t xi = (x[i / 8] >> (7 - (i % 8))) & 1;
        uint8_t mask = (uint8_t)(-(int8_t)xi);
        for (int j = 0; j < 16; j++)
            z[j] ^= v[j] & mask;

        uint8_t carry = v[15] & 1;
        for (int j = 15; j > 0; j--)
            v[j] = (v[j] >> 1) | (v[j-1] << 7);
        v[0] >>= 1;
        v[0] ^= 0xE1 & (uint8_t)(-(int8_t)carry);
    }

    memcpy(out, z, 16);
}

static void
cam_ghash_update(cam_gcm_t *ctx, const uint8_t *data, size_t len)
{
    while (len >= 16) {
        for (int i = 0; i < 16; i++)
            ctx->ghash[i] ^= data[i];
        cam_ghash_mult(ctx->ghash, ctx->ghash, ctx->H);
        data += 16; len -= 16;
    }
    if (len > 0) {
        for (size_t i = 0; i < len; i++)
            ctx->ghash[i] ^= data[i];
        cam_ghash_mult(ctx->ghash, ctx->ghash, ctx->H);
    }
}

static void
cam_gcm_init(cam_gcm_t *g, const uint8_t *key, size_t key_len, const uint8_t nonce[12])
{
    memset(g, 0, sizeof(*g));
    camellia_set_key(&g->cam, key, key_len);

    uint8_t zeros[16] = {0};
    camellia_encrypt_block(&g->cam, g->H, zeros);

    memcpy(g->J0, nonce, 12);
    g->J0[12] = 0; g->J0[13] = 0; g->J0[14] = 0; g->J0[15] = 1;
}

static void
cam_gcm_ctr(cam_gcm_t *g, uint8_t *out, const uint8_t *in, size_t len)
{
    uint8_t counter[16], ks[16];
    memcpy(counter, g->J0, 16);
    uint32_t ctr = opssl_be32(counter + 12) + 1;

    while (len > 0) {
        opssl_put_be32(counter + 12, ctr);
        camellia_encrypt_block(&g->cam, ks, counter);
        size_t chunk = len < 16 ? len : 16;
        for (size_t i = 0; i < chunk; i++)
            out[i] = in[i] ^ ks[i];
        out += chunk; in += chunk; len -= chunk; ctr++;
    }
    opssl_memzero(ks, 16);
    opssl_memzero(counter, 16);
}

/* ─── Public API ────────────────────────────────────────────────────── */

int
opssl_camellia_gcm_seal(uint8_t *out, size_t *out_len, size_t max_out,
                        const uint8_t *key, size_t key_len,
                        const uint8_t nonce[12],
                        const uint8_t *plaintext, size_t pt_len,
                        const uint8_t *aad, size_t aad_len)
{
    size_t needed = pt_len + 16;
    if (max_out < needed || (key_len != 16 && key_len != 32))
        return 0;

    cam_gcm_t g;
    cam_gcm_init(&g, key, key_len, nonce);

    g.aad_len = aad_len;
    if (aad_len > 0) cam_ghash_update(&g, aad, aad_len);
    size_t aad_pad = (16 - (aad_len % 16)) % 16;
    if (aad_pad > 0) { uint8_t z[16] = {0}; cam_ghash_update(&g, z, aad_pad); }

    cam_gcm_ctr(&g, out, plaintext, pt_len);
    g.ct_len = pt_len;

    cam_ghash_update(&g, out, pt_len);
    size_t ct_pad = (16 - (pt_len % 16)) % 16;
    if (ct_pad > 0) { uint8_t z[16] = {0}; cam_ghash_update(&g, z, ct_pad); }

    uint8_t lengths[16];
    opssl_put_be64(lengths, aad_len * 8);
    opssl_put_be64(lengths + 8, pt_len * 8);
    cam_ghash_update(&g, lengths, 16);

    uint8_t tag_mask[16];
    camellia_encrypt_block(&g.cam, tag_mask, g.J0);
    for (int i = 0; i < 16; i++)
        out[pt_len + i] = g.ghash[i] ^ tag_mask[i];

    *out_len = needed;
    opssl_memzero(&g, sizeof(g));
    opssl_memzero(tag_mask, 16);
    return 1;
}

int
opssl_camellia_gcm_open(uint8_t *out, size_t *out_len, size_t max_out,
                        const uint8_t *key, size_t key_len,
                        const uint8_t nonce[12],
                        const uint8_t *ciphertext, size_t ct_len,
                        const uint8_t *aad, size_t aad_len)
{
    if (ct_len < 16) return 0;
    size_t pt_len = ct_len - 16;
    if (max_out < pt_len || (key_len != 16 && key_len != 32))
        return 0;

    cam_gcm_t g;
    cam_gcm_init(&g, key, key_len, nonce);

    g.aad_len = aad_len;
    if (aad_len > 0) cam_ghash_update(&g, aad, aad_len);
    size_t aad_pad = (16 - (aad_len % 16)) % 16;
    if (aad_pad > 0) { uint8_t z[16] = {0}; cam_ghash_update(&g, z, aad_pad); }

    g.ct_len = pt_len;
    cam_ghash_update(&g, ciphertext, pt_len);
    size_t ct_pad = (16 - (pt_len % 16)) % 16;
    if (ct_pad > 0) { uint8_t z[16] = {0}; cam_ghash_update(&g, z, ct_pad); }

    uint8_t lengths[16];
    opssl_put_be64(lengths, aad_len * 8);
    opssl_put_be64(lengths + 8, pt_len * 8);
    cam_ghash_update(&g, lengths, 16);

    uint8_t expected[16], tag_mask[16];
    camellia_encrypt_block(&g.cam, tag_mask, g.J0);
    for (int i = 0; i < 16; i++)
        expected[i] = g.ghash[i] ^ tag_mask[i];

    if (!opssl_ct_eq(expected, ciphertext + pt_len, 16)) {
        opssl_memzero(&g, sizeof(g));
        opssl_memzero(expected, 16);
        return 0;
    }

    cam_gcm_ctr(&g, out, ciphertext, pt_len);
    *out_len = pt_len;

    opssl_memzero(&g, sizeof(g));
    opssl_memzero(expected, 16);
    opssl_memzero(tag_mask, 16);
    return 1;
}

/*
 * opssl/crypto/aes_gcm.c — AES-GCM authenticated encryption (NIST SP 800-38D).
 *
 * The dominant AEAD for TLS and kTLS offload.
 * Supports AES-128-GCM and AES-256-GCM.
 *
 * GCM = CTR mode encryption + GHASH authentication.
 *
 * Copyright (C) 2026 ophion development team
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <opssl/crypto.h>
#include <opssl/platform.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

/* AES-NI hardware acceleration dispatch */
extern bool opssl_has_aesni(void);
extern bool opssl_has_pclmul(void);
extern int opssl_aesni_gcm_seal(uint8_t *out, size_t *out_len, size_t max_out,
                                const uint8_t *key, size_t key_len,
                                const uint8_t nonce[12],
                                const uint8_t *plaintext, size_t pt_len,
                                const uint8_t *aad, size_t aad_len);
extern int opssl_aesni_gcm_open(uint8_t *out, size_t *out_len, size_t max_out,
                                const uint8_t *key, size_t key_len,
                                const uint8_t nonce[12],
                                const uint8_t *ciphertext, size_t ct_len,
                                const uint8_t *aad, size_t aad_len);

/* ChaCha20-Poly1305 dispatch */
extern int opssl_chacha20_poly1305_seal(uint8_t *out, size_t *out_len, size_t max_out,
                                        const uint8_t key[32],
                                        const uint8_t nonce[12],
                                        const uint8_t *plaintext, size_t pt_len,
                                        const uint8_t *aad, size_t aad_len);
extern int opssl_chacha20_poly1305_open(uint8_t *out, size_t *out_len, size_t max_out,
                                        const uint8_t key[32],
                                        const uint8_t nonce[12],
                                        const uint8_t *ciphertext, size_t ct_len,
                                        const uint8_t *aad, size_t aad_len);

/* AES-CCM dispatch */
extern int opssl_aes_ccm_seal(uint8_t *out, size_t *out_len, size_t max_out,
                               const uint8_t *key, size_t key_len,
                               const uint8_t nonce[12], size_t tag_len,
                               const uint8_t *plaintext, size_t pt_len,
                               const uint8_t *aad, size_t aad_len);
extern int opssl_aes_ccm_open(uint8_t *out, size_t *out_len, size_t max_out,
                               const uint8_t *key, size_t key_len,
                               const uint8_t nonce[12], size_t tag_len,
                               const uint8_t *ciphertext, size_t ct_len,
                               const uint8_t *aad, size_t aad_len);

/* Camellia-GCM dispatch */
extern int opssl_camellia_gcm_seal(uint8_t *out, size_t *out_len, size_t max_out,
                                    const uint8_t *key, size_t key_len,
                                    const uint8_t nonce[12],
                                    const uint8_t *plaintext, size_t pt_len,
                                    const uint8_t *aad, size_t aad_len);
extern int opssl_camellia_gcm_open(uint8_t *out, size_t *out_len, size_t max_out,
                                    const uint8_t *key, size_t key_len,
                                    const uint8_t nonce[12],
                                    const uint8_t *ciphertext, size_t ct_len,
                                    const uint8_t *aad, size_t aad_len);

/* Defined in aes.c — layout MUST match aes.c::opssl_aes_ctx_t exactly. */
typedef struct {
    uint32_t rk[60];
    int      nr;
    void     *hw_ctx;
    bool     use_hw;
} opssl_aes_ctx_t;

extern int  opssl_aes_set_encrypt_key(opssl_aes_ctx_t *ctx, const uint8_t *key, int bits);
extern void opssl_aes_encrypt_block(const opssl_aes_ctx_t *ctx, uint8_t out[16], const uint8_t in[16]);

/* Free any hardware-allocated context held by an AES context. */
static void
gcm_aes_cleanup(opssl_aes_ctx_t *aes)
{
    if (aes->hw_ctx) {
        free(aes->hw_ctx);
        aes->hw_ctx = NULL;
    }
    opssl_memzero(aes, sizeof(*aes));
}

/* GCM state */
typedef struct {
    opssl_aes_ctx_t aes;
    uint8_t  H[16];      /* Hash subkey: AES_K(0^128) */
    uint8_t  J0[16];     /* Pre-counter block */
    uint8_t  ghash[16];  /* Running GHASH state */
    uint64_t aad_len;
    uint64_t ct_len;
} gcm_ctx_t;

/*
 * GF(2^128) multiplication (GHASH).
 * Schoolbook implementation — correct and constant-time.
 * PCLMULQDQ acceleration dispatched at the seal/open level via aes_ni.c.
 */
static void
ghash_mult(uint8_t out[16], const uint8_t x[16], const uint8_t h[16])
{
    uint8_t v[16];
    uint8_t z[16] = {0};

    memcpy(v, h, 16);

    for (int i = 0; i < 128; i++) {
        /* If bit i of x is set, Z ^= V */
        uint8_t xi = (x[i / 8] >> (7 - (i % 8))) & 1;
        uint8_t mask = (uint8_t)(-(int8_t)xi);
        for (int j = 0; j < 16; j++)
            z[j] ^= v[j] & mask;

        /* V = V * x (multiply by the polynomial x in GF(2^128)) */
        uint8_t carry = v[15] & 1;
        for (int j = 15; j > 0; j--)
            v[j] = (v[j] >> 1) | (v[j-1] << 7);
        v[0] >>= 1;

        /* If carry, XOR with R = 0xE1000...0 */
        v[0] ^= 0xE1 & (uint8_t)(-(int8_t)carry);
    }

    memcpy(out, z, 16);
}

static void
ghash_update(gcm_ctx_t *ctx, const uint8_t *data, size_t len)
{
    while (len >= 16) {
        for (int i = 0; i < 16; i++)
            ctx->ghash[i] ^= data[i];
        ghash_mult(ctx->ghash, ctx->ghash, ctx->H);
        data += 16;
        len -= 16;
    }

    if (len > 0) {
        for (size_t i = 0; i < len; i++)
            ctx->ghash[i] ^= data[i];
        ghash_mult(ctx->ghash, ctx->ghash, ctx->H);
    }
}

static void
gcm_init(gcm_ctx_t *ctx, const uint8_t *key, size_t key_len, const uint8_t nonce[12])
{
    memset(ctx, 0, sizeof(*ctx));

    int bits = (key_len == 16) ? 128 : 256;
    opssl_aes_set_encrypt_key(&ctx->aes, key, bits);

    /* H = AES_K(0^128) */
    uint8_t zeros[16] = {0};
    opssl_aes_encrypt_block(&ctx->aes, ctx->H, zeros);

    /* J0 = nonce || 0x00000001 (for 96-bit nonce) */
    memcpy(ctx->J0, nonce, 12);
    ctx->J0[12] = 0;
    ctx->J0[13] = 0;
    ctx->J0[14] = 0;
    ctx->J0[15] = 1;
}

static void
gcm_ctr32_encrypt(gcm_ctx_t *ctx, uint8_t *out, const uint8_t *in, size_t len)
{
    uint8_t counter[16];
    uint8_t keystream[16];

    memcpy(counter, ctx->J0, 16);
    /* Start at counter = J0 + 1 (J0 is reserved for final tag) */
    uint32_t ctr = opssl_be32(counter + 12) + 1;

    while (len > 0) {
        opssl_put_be32(counter + 12, ctr);
        opssl_aes_encrypt_block(&ctx->aes, keystream, counter);

        size_t chunk = len < 16 ? len : 16;
        for (size_t i = 0; i < chunk; i++)
            out[i] = in[i] ^ keystream[i];

        out += chunk;
        in += chunk;
        len -= chunk;
        ctr++;
    }

    opssl_memzero(keystream, sizeof(keystream));
    opssl_memzero(counter, sizeof(counter));
}

/* ─── Public API ─────────────────────────────────────────────────────── */

int
opssl_aes_gcm_seal(uint8_t *out, size_t *out_len, size_t max_out,
                   const uint8_t *key, size_t key_len,
                   const uint8_t nonce[12],
                   const uint8_t *plaintext, size_t pt_len,
                   const uint8_t *aad, size_t aad_len)
{
    if (pt_len > SIZE_MAX - 16)
        return 0;
    /*
     * NIST SP 800-38D §5.2.1.1 (Input Data) — for a 96-bit IV the CTR
     * mode counter field is 32 bits, so the maximum plaintext per
     * invocation is 2^39 - 256 bits = 2^36 - 32 bytes. Exceeding this
     * causes the 32-bit counter to wrap and reuse keystream, which
     * catastrophically breaks GCM confidentiality (and trivially
     * recovers the authentication subkey H).
     */
    if (pt_len > ((uint64_t)1 << 36) - 32)
        return 0;
    size_t needed = pt_len + 16;
    if (max_out < needed)
        return 0;
    if (key_len != 16 && key_len != 32)
        return 0;

    if (opssl_has_aesni() && opssl_has_pclmul())
        return opssl_aesni_gcm_seal(out, out_len, max_out, key, key_len,
                                    nonce, plaintext, pt_len, aad, aad_len);

    gcm_ctx_t ctx;
    gcm_init(&ctx, key, key_len, nonce);

    /* Authenticate AAD */
    ctx.aad_len = aad_len;
    if (aad_len > 0)
        ghash_update(&ctx, aad, aad_len);

    /* Pad AAD to 16-byte boundary in GHASH */
    size_t aad_pad = (16 - (aad_len % 16)) % 16;
    if (aad_pad > 0) {
        uint8_t zeros[16] = {0};
        ghash_update(&ctx, zeros, aad_pad);
    }

    /* Encrypt */
    gcm_ctr32_encrypt(&ctx, out, plaintext, pt_len);
    ctx.ct_len = pt_len;

    /* Authenticate ciphertext */
    ghash_update(&ctx, out, pt_len);
    size_t ct_pad = (16 - (pt_len % 16)) % 16;
    if (ct_pad > 0) {
        uint8_t zeros[16] = {0};
        ghash_update(&ctx, zeros, ct_pad);
    }

    /* Final GHASH block: len(AAD) || len(CT) in bits */
    uint8_t lengths[16];
    opssl_put_be64(lengths, aad_len * 8);
    opssl_put_be64(lengths + 8, pt_len * 8);
    ghash_update(&ctx, lengths, 16);

    /* Tag = GHASH ^ AES_K(J0) */
    uint8_t tag_mask[16];
    opssl_aes_encrypt_block(&ctx.aes, tag_mask, ctx.J0);
    for (int i = 0; i < 16; i++)
        out[pt_len + i] = ctx.ghash[i] ^ tag_mask[i];

    *out_len = needed;
    gcm_aes_cleanup(&ctx.aes);
    opssl_memzero(&ctx, sizeof(ctx));
    opssl_memzero(tag_mask, sizeof(tag_mask));
    return 1;
}

int
opssl_aes_gcm_open(uint8_t *out, size_t *out_len, size_t max_out,
                   const uint8_t *key, size_t key_len,
                   const uint8_t nonce[12],
                   const uint8_t *ciphertext, size_t ct_len,
                   const uint8_t *aad, size_t aad_len)
{
    if (ct_len < 16)
        return 0;

    size_t pt_len = ct_len - 16;
    if (max_out < pt_len)
        return 0;
    /*
     * NIST SP 800-38D §5.2.1.1 (Input Data) — symmetric upper bound to
     * the seal path. A 32-bit CTR field over a 96-bit IV caps the
     * payload at 2^36 - 32 bytes; honour the same limit on decrypt so
     * we never derive keystream past a counter wrap.
     */
    if (pt_len > ((uint64_t)1 << 36) - 32)
        return 0;
    if (key_len != 16 && key_len != 32)
        return 0;

    if (opssl_has_aesni() && opssl_has_pclmul())
        return opssl_aesni_gcm_open(out, out_len, max_out, key, key_len,
                                    nonce, ciphertext, ct_len, aad, aad_len);

    gcm_ctx_t ctx;
    gcm_init(&ctx, key, key_len, nonce);

    /* Authenticate AAD */
    ctx.aad_len = aad_len;
    if (aad_len > 0)
        ghash_update(&ctx, aad, aad_len);
    size_t aad_pad = (16 - (aad_len % 16)) % 16;
    if (aad_pad > 0) {
        uint8_t zeros[16] = {0};
        ghash_update(&ctx, zeros, aad_pad);
    }

    /* Authenticate ciphertext (NOT the tag) */
    ctx.ct_len = pt_len;
    ghash_update(&ctx, ciphertext, pt_len);
    size_t ct_pad = (16 - (pt_len % 16)) % 16;
    if (ct_pad > 0) {
        uint8_t zeros[16] = {0};
        ghash_update(&ctx, zeros, ct_pad);
    }

    /* Lengths block */
    uint8_t lengths[16];
    opssl_put_be64(lengths, aad_len * 8);
    opssl_put_be64(lengths + 8, pt_len * 8);
    ghash_update(&ctx, lengths, 16);

    /* Compute expected tag */
    uint8_t expected_tag[16];
    uint8_t tag_mask[16];
    opssl_aes_encrypt_block(&ctx.aes, tag_mask, ctx.J0);
    for (int i = 0; i < 16; i++)
        expected_tag[i] = ctx.ghash[i] ^ tag_mask[i];

    /* Constant-time tag verification */
    const uint8_t *received_tag = ciphertext + pt_len;
    if (!opssl_ct_eq(expected_tag, received_tag, 16)) {
        gcm_aes_cleanup(&ctx.aes);
        opssl_memzero(&ctx, sizeof(ctx));
        opssl_memzero(expected_tag, sizeof(expected_tag));
        opssl_memzero(tag_mask, sizeof(tag_mask));
        return 0;
    }

    /* Decrypt */
    gcm_ctr32_encrypt(&ctx, out, ciphertext, pt_len);
    *out_len = pt_len;

    gcm_aes_cleanup(&ctx.aes);
    opssl_memzero(&ctx, sizeof(ctx));
    opssl_memzero(expected_tag, sizeof(expected_tag));
    opssl_memzero(tag_mask, sizeof(tag_mask));
    return 1;
}

/* ─── AEAD Context API ───────────────────────────────────────────────── */

struct opssl_aead_ctx {
    opssl_aead_algo_t algo;
    uint8_t key[32];
    size_t  key_len;
};

opssl_aead_ctx_t *opssl_aead_new(opssl_aead_algo_t algo)
{
    opssl_aead_ctx_t *ctx = calloc(1, sizeof(opssl_aead_ctx_t));
    if (!ctx)
        return NULL;
    ctx->algo = algo;
    return ctx;
}

int opssl_aead_set_key(opssl_aead_ctx_t *ctx, const uint8_t *key, size_t key_len)
{
    if (!ctx || !key)
        return 0;
    if (key_len != 16 && key_len != 32)
        return 0;
    memcpy(ctx->key, key, key_len);
    ctx->key_len = key_len;
    return 1;
}

void opssl_aead_free(opssl_aead_ctx_t *ctx)
{
    if (ctx) {
        opssl_memzero(ctx, sizeof(*ctx));
        free(ctx);
    }
}

int opssl_aead_seal(opssl_aead_ctx_t *ctx,
                    uint8_t *out, size_t *out_len, size_t max_out,
                    const uint8_t *nonce, size_t nonce_len,
                    const uint8_t *plaintext, size_t plaintext_len,
                    const uint8_t *aad, size_t aad_len)
{
    if (!ctx || !out || !out_len || nonce_len != 12)
        return 0;

    if (ctx->algo == OPSSL_AEAD_CHACHA20_POLY1305) {
        return opssl_chacha20_poly1305_seal(out, out_len, max_out,
                                           ctx->key, nonce,
                                           plaintext, plaintext_len,
                                           aad, aad_len);
    }

    if (ctx->algo == OPSSL_AEAD_AES_128_CCM || ctx->algo == OPSSL_AEAD_AES_256_CCM) {
        return opssl_aes_ccm_seal(out, out_len, max_out,
                                  ctx->key, ctx->key_len, nonce, 16,
                                  plaintext, plaintext_len, aad, aad_len);
    }

    if (ctx->algo == OPSSL_AEAD_AES_128_CCM_8 || ctx->algo == OPSSL_AEAD_AES_256_CCM_8) {
        return opssl_aes_ccm_seal(out, out_len, max_out,
                                  ctx->key, ctx->key_len, nonce, 8,
                                  plaintext, plaintext_len, aad, aad_len);
    }

    if (ctx->algo == OPSSL_AEAD_CAMELLIA_128_GCM || ctx->algo == OPSSL_AEAD_CAMELLIA_256_GCM) {
        return opssl_camellia_gcm_seal(out, out_len, max_out,
                                       ctx->key, ctx->key_len, nonce,
                                       plaintext, plaintext_len, aad, aad_len);
    }

    return opssl_aes_gcm_seal(out, out_len, max_out,
                              ctx->key, ctx->key_len,
                              nonce, plaintext, plaintext_len,
                              aad, aad_len);
}

int opssl_aead_open(opssl_aead_ctx_t *ctx,
                    uint8_t *out, size_t *out_len, size_t max_out,
                    const uint8_t *nonce, size_t nonce_len,
                    const uint8_t *ciphertext, size_t ciphertext_len,
                    const uint8_t *aad, size_t aad_len)
{
    if (!ctx || !out || !out_len || nonce_len != 12)
        return 0;

    if (ctx->algo == OPSSL_AEAD_CHACHA20_POLY1305) {
        return opssl_chacha20_poly1305_open(out, out_len, max_out,
                                           ctx->key, nonce,
                                           ciphertext, ciphertext_len,
                                           aad, aad_len);
    }

    if (ctx->algo == OPSSL_AEAD_AES_128_CCM || ctx->algo == OPSSL_AEAD_AES_256_CCM) {
        return opssl_aes_ccm_open(out, out_len, max_out,
                                  ctx->key, ctx->key_len, nonce, 16,
                                  ciphertext, ciphertext_len, aad, aad_len);
    }

    if (ctx->algo == OPSSL_AEAD_AES_128_CCM_8 || ctx->algo == OPSSL_AEAD_AES_256_CCM_8) {
        return opssl_aes_ccm_open(out, out_len, max_out,
                                  ctx->key, ctx->key_len, nonce, 8,
                                  ciphertext, ciphertext_len, aad, aad_len);
    }

    if (ctx->algo == OPSSL_AEAD_CAMELLIA_128_GCM || ctx->algo == OPSSL_AEAD_CAMELLIA_256_GCM) {
        return opssl_camellia_gcm_open(out, out_len, max_out,
                                       ctx->key, ctx->key_len, nonce,
                                       ciphertext, ciphertext_len, aad, aad_len);
    }

    return opssl_aes_gcm_open(out, out_len, max_out,
                              ctx->key, ctx->key_len,
                              nonce, ciphertext, ciphertext_len,
                              aad, aad_len);
}

size_t opssl_aead_key_len(opssl_aead_algo_t algo)
{
    switch (algo) {
        case OPSSL_AEAD_AES_128_GCM:
        case OPSSL_AEAD_AES_128_CCM:
        case OPSSL_AEAD_AES_128_CCM_8:
        case OPSSL_AEAD_CAMELLIA_128_GCM: return 16;
        default:                          return 32;
    }
}

size_t opssl_aead_nonce_len(opssl_aead_algo_t algo)
{
    (void)algo;
    return 12;
}

size_t opssl_aead_tag_len(opssl_aead_algo_t algo)
{
    switch (algo) {
        case OPSSL_AEAD_AES_128_CCM_8:
        case OPSSL_AEAD_AES_256_CCM_8: return 8;
        default:                       return 16;
    }
}

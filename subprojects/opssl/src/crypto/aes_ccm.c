/*
 * opssl/crypto/aes_ccm.c — AES-CCM authenticated encryption (NIST SP 800-38C).
 *
 * Counter with CBC-MAC. Supports AES-128-CCM and AES-256-CCM with
 * 16-byte (CCM) or 8-byte (CCM_8) authentication tags.
 *
 * For TLS: 12-byte nonce, q=3, max message size 2^24-1 bytes.
 *
 * Copyright (C) 2026 ophion development team
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <opssl/crypto.h>
#include <opssl/platform.h>
#include <string.h>
#include <stdlib.h>

/* Full AES context — must match aes.c definition */
typedef struct {
    uint32_t rk[60];
    int      nr;
    void     *hw_ctx;
    bool     use_hw;
} opssl_aes_ctx_t;

extern int  opssl_aes_set_encrypt_key(opssl_aes_ctx_t *ctx, const uint8_t *key, int bits);
extern void opssl_aes_encrypt_block(const opssl_aes_ctx_t *ctx, uint8_t out[16], const uint8_t in[16]);

static void
aes_cleanup(opssl_aes_ctx_t *ctx)
{
    if (ctx->hw_ctx)
        free(ctx->hw_ctx);
    opssl_memzero(ctx, sizeof(*ctx));
}

/*
 * B_0: flags(1) | nonce(12) | Q(3)
 * flags = 64*(Adata?1:0) | ((t-2)/2)<<3 | (q-1)
 * q = 15 - nonce_len = 3
 */
static void
ccm_format_b0(uint8_t b0[16], const uint8_t nonce[12],
              size_t pt_len, size_t aad_len, size_t tag_len)
{
    b0[0] = (aad_len > 0 ? 64 : 0)
          | (uint8_t)(((tag_len - 2) / 2) << 3)
          | 2;
    memcpy(b0 + 1, nonce, 12);
    b0[13] = (uint8_t)(pt_len >> 16);
    b0[14] = (uint8_t)(pt_len >> 8);
    b0[15] = (uint8_t)(pt_len);
}

/* A_i: flags_ctr(1) | nonce(12) | counter(3) */
static void
ccm_format_ctr(uint8_t a[16], const uint8_t nonce[12], uint32_t i)
{
    a[0] = 2; /* q-1 */
    memcpy(a + 1, nonce, 12);
    a[13] = (uint8_t)(i >> 16);
    a[14] = (uint8_t)(i >> 8);
    a[15] = (uint8_t)(i);
}

static void
cbc_mac_block(const opssl_aes_ctx_t *aes, uint8_t state[16], const uint8_t block[16])
{
    for (int j = 0; j < 16; j++)
        state[j] ^= block[j];
    opssl_aes_encrypt_block(aes, state, state);
}

/* AAD: 2-byte length prefix (for aad_len < 0xFF00), then data, zero-padded to block boundary */
static void
cbc_mac_aad(const opssl_aes_ctx_t *aes, uint8_t state[16],
            const uint8_t *aad, size_t aad_len)
{
    if (aad_len == 0)
        return;

    uint8_t block[16] = {0};
    block[0] = (uint8_t)(aad_len >> 8);
    block[1] = (uint8_t)(aad_len);

    size_t first = aad_len < 14 ? aad_len : 14;
    memcpy(block + 2, aad, first);
    cbc_mac_block(aes, state, block);

    size_t off = first;
    while (off < aad_len) {
        memset(block, 0, 16);
        size_t chunk = aad_len - off;
        if (chunk > 16) chunk = 16;
        memcpy(block, aad + off, chunk);
        cbc_mac_block(aes, state, block);
        off += chunk;
    }
}

static void
cbc_mac_msg(const opssl_aes_ctx_t *aes, uint8_t state[16],
            const uint8_t *msg, size_t msg_len)
{
    uint8_t block[16];
    size_t off = 0;

    while (off < msg_len) {
        memset(block, 0, 16);
        size_t chunk = msg_len - off;
        if (chunk > 16) chunk = 16;
        memcpy(block, msg + off, chunk);
        cbc_mac_block(aes, state, block);
        off += chunk;
    }
}

/* CTR mode starting at A_1 (A_0 reserved for tag encryption) */
static void
ccm_ctr_crypt(const opssl_aes_ctx_t *aes, uint8_t *out, const uint8_t *in,
              size_t len, const uint8_t nonce[12])
{
    uint8_t a[16], ks[16];
    uint32_t ctr = 1;
    size_t off = 0;

    while (off < len) {
        ccm_format_ctr(a, nonce, ctr);
        opssl_aes_encrypt_block(aes, ks, a);

        size_t chunk = len - off;
        if (chunk > 16) chunk = 16;
        for (size_t j = 0; j < chunk; j++)
            out[off + j] = in[off + j] ^ ks[j];

        off += chunk;
        ctr++;
    }

    opssl_memzero(ks, sizeof(ks));
    opssl_memzero(a, sizeof(a));
}

/* ─── Public API ─────────────────────────────────────────────────────── */

int
opssl_aes_ccm_seal(uint8_t *out, size_t *out_len, size_t max_out,
                   const uint8_t *key, size_t key_len,
                   const uint8_t nonce[12], size_t tag_len,
                   const uint8_t *plaintext, size_t pt_len,
                   const uint8_t *aad, size_t aad_len)
{
    size_t needed = pt_len + tag_len;
    if (max_out < needed)
        return 0;
    if (key_len != 16 && key_len != 32)
        return 0;
    if (tag_len != 8 && tag_len != 16)
        return 0;
    if (pt_len > 0xFFFFFF)
        return 0;
    if (aad_len >= 0xFF00)
        return 0;

    opssl_aes_ctx_t aes;
    memset(&aes, 0, sizeof(aes));
    opssl_aes_set_encrypt_key(&aes, key, (key_len == 16) ? 128 : 256);

    /* CBC-MAC over B_0 || AAD || plaintext */
    uint8_t b0[16];
    ccm_format_b0(b0, nonce, pt_len, aad_len, tag_len);

    uint8_t mac[16] = {0};
    opssl_aes_encrypt_block(&aes, mac, b0);
    cbc_mac_aad(&aes, mac, aad, aad_len);
    cbc_mac_msg(&aes, mac, plaintext, pt_len);

    /* CTR encrypt plaintext (counter starts at 1) */
    ccm_ctr_crypt(&aes, out, plaintext, pt_len, nonce);

    /* Encrypt tag with S_0 = AES_K(A_0) */
    uint8_t a0[16], s0[16];
    ccm_format_ctr(a0, nonce, 0);
    opssl_aes_encrypt_block(&aes, s0, a0);
    for (size_t i = 0; i < tag_len; i++)
        out[pt_len + i] = mac[i] ^ s0[i];

    *out_len = needed;
    aes_cleanup(&aes);
    opssl_memzero(mac, sizeof(mac));
    opssl_memzero(s0, sizeof(s0));
    return 1;
}

int
opssl_aes_ccm_open(uint8_t *out, size_t *out_len, size_t max_out,
                   const uint8_t *key, size_t key_len,
                   const uint8_t nonce[12], size_t tag_len,
                   const uint8_t *ciphertext, size_t ct_len,
                   const uint8_t *aad, size_t aad_len)
{
    if (ct_len < tag_len)
        return 0;
    size_t pt_len = ct_len - tag_len;
    if (max_out < pt_len)
        return 0;
    if (key_len != 16 && key_len != 32)
        return 0;
    if (tag_len != 8 && tag_len != 16)
        return 0;
    if (pt_len > 0xFFFFFF)
        return 0;
    if (aad_len >= 0xFF00)
        return 0;

    opssl_aes_ctx_t aes;
    memset(&aes, 0, sizeof(aes));
    opssl_aes_set_encrypt_key(&aes, key, (key_len == 16) ? 128 : 256);

    /* Decrypt ciphertext with CTR */
    ccm_ctr_crypt(&aes, out, ciphertext, pt_len, nonce);

    /* Decrypt received tag with S_0 */
    uint8_t a0[16], s0[16];
    ccm_format_ctr(a0, nonce, 0);
    opssl_aes_encrypt_block(&aes, s0, a0);

    uint8_t recv_tag[16] = {0};
    for (size_t i = 0; i < tag_len; i++)
        recv_tag[i] = ciphertext[pt_len + i] ^ s0[i];

    /* Recompute CBC-MAC over decrypted plaintext */
    uint8_t b0[16];
    ccm_format_b0(b0, nonce, pt_len, aad_len, tag_len);

    uint8_t mac[16] = {0};
    opssl_aes_encrypt_block(&aes, mac, b0);
    cbc_mac_aad(&aes, mac, aad, aad_len);
    cbc_mac_msg(&aes, mac, out, pt_len);

    /* Constant-time tag verification */
    if (!opssl_ct_eq(mac, recv_tag, tag_len)) {
        opssl_memzero(out, pt_len);
        aes_cleanup(&aes);
        opssl_memzero(mac, sizeof(mac));
        opssl_memzero(recv_tag, sizeof(recv_tag));
        return 0;
    }

    *out_len = pt_len;
    aes_cleanup(&aes);
    opssl_memzero(mac, sizeof(mac));
    opssl_memzero(s0, sizeof(s0));
    opssl_memzero(recv_tag, sizeof(recv_tag));
    return 1;
}

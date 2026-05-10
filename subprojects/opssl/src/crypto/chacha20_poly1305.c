/*
 * opssl/crypto/chacha20_poly1305.c — ChaCha20-Poly1305 AEAD (RFC 8439).
 *
 * Combined authenticated encryption. The primary AEAD for TLS when
 * hardware AES is unavailable, and preferred for kTLS on mobile.
 *
 * Construction:
 *   1. Generate Poly1305 key: ChaCha20(key, nonce, counter=0)[0..31]
 *   2. Encrypt plaintext: ChaCha20(key, nonce, counter=1)
 *   3. Authenticate: Poly1305(AAD || pad || ciphertext || pad || lengths)
 *
 * Copyright (C) 2026 ophion development team
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <opssl/crypto.h>
#include <opssl/platform.h>
#include <string.h>

/* Defined in chacha20.c */
extern void opssl_chacha20(uint8_t *out, const uint8_t *in, size_t len,
                           const uint8_t key[32], const uint8_t nonce[12],
                           uint32_t counter);

/* Defined in poly1305.c */
extern void opssl_poly1305(uint8_t tag[16], const uint8_t *msg, size_t len,
                           const uint8_t key[32]);

static inline void
store64_le(uint8_t *p, uint64_t v)
{
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
    p[4] = (uint8_t)(v >> 32);
    p[5] = (uint8_t)(v >> 40);
    p[6] = (uint8_t)(v >> 48);
    p[7] = (uint8_t)(v >> 56);
}

static size_t
pad16(size_t len)
{
    size_t rem = len & 0xf;
    return rem ? 16 - rem : 0;
}

/*
 * Compute Poly1305 tag over the AEAD construction:
 *   AAD || pad(AAD) || ciphertext || pad(ciphertext) || len(AAD) || len(CT)
 */
static void
compute_tag(uint8_t tag[16],
            const uint8_t poly_key[32],
            const uint8_t *aad, size_t aad_len,
            const uint8_t *ct, size_t ct_len)
{
    /* Build the authenticated message in a buffer.
     * For large messages this would need streaming, but TLS records
     * are bounded at 16KB + overhead so this is fine. */
    size_t msg_len = aad_len + pad16(aad_len) +
                     ct_len + pad16(ct_len) + 16;

    uint8_t *msg = op_malloc(msg_len);
    size_t off = 0;

    memcpy(msg + off, aad, aad_len);
    off += aad_len;
    memset(msg + off, 0, pad16(aad_len));
    off += pad16(aad_len);

    memcpy(msg + off, ct, ct_len);
    off += ct_len;
    memset(msg + off, 0, pad16(ct_len));
    off += pad16(ct_len);

    store64_le(msg + off, (uint64_t)aad_len);
    off += 8;
    store64_le(msg + off, (uint64_t)ct_len);
    off += 8;

    opssl_poly1305(tag, msg, off, poly_key);

    opssl_memzero(msg, msg_len);
    free(msg);
}

int
opssl_chacha20_poly1305_seal(uint8_t *out, size_t *out_len, size_t max_out,
                             const uint8_t key[32],
                             const uint8_t nonce[12],
                             const uint8_t *plaintext, size_t pt_len,
                             const uint8_t *aad, size_t aad_len)
{
    size_t needed = pt_len + 16; /* ciphertext + tag */
    if (max_out < needed)
        return 0;

    /* Step 1: Generate Poly1305 one-time key */
    uint8_t poly_key[32];
    uint8_t zeros[32] = {0};
    opssl_chacha20(poly_key, zeros, 32, key, nonce, 0);

    /* Step 2: Encrypt with counter starting at 1 */
    opssl_chacha20(out, plaintext, pt_len, key, nonce, 1);

    /* Step 3: Compute authentication tag */
    uint8_t tag[16];
    compute_tag(tag, poly_key, aad, aad_len, out, pt_len);
    memcpy(out + pt_len, tag, 16);

    *out_len = needed;

    opssl_memzero(poly_key, sizeof(poly_key));
    opssl_memzero(tag, sizeof(tag));
    return 1;
}

int
opssl_chacha20_poly1305_open(uint8_t *out, size_t *out_len, size_t max_out,
                             const uint8_t key[32],
                             const uint8_t nonce[12],
                             const uint8_t *ciphertext, size_t ct_len,
                             const uint8_t *aad, size_t aad_len)
{
    if (ct_len < 16)
        return 0;

    size_t pt_len = ct_len - 16;
    if (max_out < pt_len)
        return 0;

    /* Step 1: Generate Poly1305 one-time key */
    uint8_t poly_key[32];
    uint8_t zeros[32] = {0};
    opssl_chacha20(poly_key, zeros, 32, key, nonce, 0);

    /* Step 2: Verify tag (constant-time) */
    uint8_t expected_tag[16];
    compute_tag(expected_tag, poly_key, aad, aad_len, ciphertext, pt_len);

    const uint8_t *received_tag = ciphertext + pt_len;
    if (!opssl_ct_eq(expected_tag, received_tag, 16)) {
        opssl_memzero(poly_key, sizeof(poly_key));
        opssl_memzero(expected_tag, sizeof(expected_tag));
        return 0;
    }

    /* Step 3: Decrypt */
    opssl_chacha20(out, ciphertext, pt_len, key, nonce, 1);
    *out_len = pt_len;

    opssl_memzero(poly_key, sizeof(poly_key));
    opssl_memzero(expected_tag, sizeof(expected_tag));
    return 1;
}

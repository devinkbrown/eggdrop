/*
 * test_aead.c — AEAD round-trips and select RFC test vectors.
 *
 * Covers AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305, and Camellia-GCM
 * variants. Each algorithm is round-trip tested (seal -> open) and a
 * tampered-tag negative test ensures authentication is enforced.
 * The ChaCha20-Poly1305 RFC 8439 §2.8.2 vector is verified explicitly.
 *
 * Copyright (C) 2026 ophion development team
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "test_helpers.h"

static void roundtrip(opssl_aead_algo_t algo, const char *name)
{
    opssl_aead_ctx_t *ctx = opssl_aead_new(algo);
    if (!ctx) { T_SKIP(name); return; }

    size_t klen = opssl_aead_key_len(algo);
    size_t nlen = opssl_aead_nonce_len(algo);
    size_t tlen = opssl_aead_tag_len(algo);
    T_TRUE(klen > 0 && nlen > 0 && tlen > 0, "aead: nonzero parameters");

    uint8_t key[64] = {0}, nonce[32] = {0}, aad[16] = {0};
    for (size_t i = 0; i < klen; ++i) key[i] = (uint8_t)(i + 1);
    for (size_t i = 0; i < nlen; ++i) nonce[i] = (uint8_t)(0x20 + i);
    for (size_t i = 0; i < sizeof(aad); ++i) aad[i] = (uint8_t)(0xa0 + i);

    if (opssl_aead_set_key(ctx, key, klen) != 1) {
        T_SKIP("aead: set_key");
        opssl_aead_free(ctx);
        return;
    }

    const uint8_t pt[] = "the quick brown fox jumps over the lazy dog";
    size_t pt_len = sizeof(pt) - 1;
    uint8_t ct[128]; size_t ct_len = sizeof(ct);
    uint8_t out[128]; size_t out_len = sizeof(out);

    int rc = opssl_aead_seal(ctx, ct, &ct_len, sizeof(ct),
                             nonce, nlen, pt, pt_len, aad, sizeof(aad));
    T_EQ(rc, 1, "aead: seal succeeds");
    T_EQ(ct_len, pt_len + tlen, "aead: ciphertext length is pt+tag");

    rc = opssl_aead_open(ctx, out, &out_len, sizeof(out),
                         nonce, nlen, ct, ct_len, aad, sizeof(aad));
    T_EQ(rc, 1, "aead: open succeeds");
    T_EQ(out_len, pt_len, "aead: plaintext length matches");
    T_EQ(memcmp(out, pt, pt_len), 0, "aead: plaintext matches");

    /* Tamper: flip a bit in the tag, ensure open fails. */
    ct[ct_len - 1] ^= 0x01;
    out_len = sizeof(out);
    rc = opssl_aead_open(ctx, out, &out_len, sizeof(out),
                         nonce, nlen, ct, ct_len, aad, sizeof(aad));
    T_NE(rc, 1, "aead: tampered tag rejected");
    ct[ct_len - 1] ^= 0x01;

    /* Tamper AAD */
    aad[0] ^= 0x80;
    out_len = sizeof(out);
    rc = opssl_aead_open(ctx, out, &out_len, sizeof(out),
                         nonce, nlen, ct, ct_len, aad, sizeof(aad));
    T_NE(rc, 1, "aead: tampered AAD rejected");

    opssl_aead_free(ctx);
}

/*
 * RFC 8439 §2.8.2 test vector for ChaCha20-Poly1305.
 * key, nonce, aad, plaintext and expected ciphertext+tag.
 */
static void test_chacha20_poly1305_rfc(void)
{
    static const uint8_t key[32] = {
        0x80,0x81,0x82,0x83,0x84,0x85,0x86,0x87,
        0x88,0x89,0x8a,0x8b,0x8c,0x8d,0x8e,0x8f,
        0x90,0x91,0x92,0x93,0x94,0x95,0x96,0x97,
        0x98,0x99,0x9a,0x9b,0x9c,0x9d,0x9e,0x9f,
    };
    static const uint8_t nonce[12] = {
        0x07,0x00,0x00,0x00,0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,
    };
    static const uint8_t aad[12] = {
        0x50,0x51,0x52,0x53,0xc0,0xc1,0xc2,0xc3,0xc4,0xc5,0xc6,0xc7,
    };
    static const char pt[] =
        "Ladies and Gentlemen of the class of '99: If I could offer you "
        "only one tip for the future, sunscreen would be it.";
    static const uint8_t expect_ct[114] = {
        0xd3,0x1a,0x8d,0x34,0x64,0x8e,0x60,0xdb,0x7b,0x86,0xaf,0xbc,0x53,0xef,0x7e,0xc2,
        0xa4,0xad,0xed,0x51,0x29,0x6e,0x08,0xfe,0xa9,0xe2,0xb5,0xa7,0x36,0xee,0x62,0xd6,
        0x3d,0xbe,0xa4,0x5e,0x8c,0xa9,0x67,0x12,0x82,0xfa,0xfb,0x69,0xda,0x92,0x72,0x8b,
        0x1a,0x71,0xde,0x0a,0x9e,0x06,0x0b,0x29,0x05,0xd6,0xa5,0xb6,0x7e,0xcd,0x3b,0x36,
        0x92,0xdd,0xbd,0x7f,0x2d,0x77,0x8b,0x8c,0x98,0x03,0xae,0xe3,0x28,0x09,0x1b,0x58,
        0xfa,0xb3,0x24,0xe4,0xfa,0xd6,0x75,0x94,0x55,0x85,0x80,0x8b,0x48,0x31,0xd7,0xbc,
        0x3f,0xf4,0xde,0xf0,0x8e,0x4b,0x7a,0x9d,0xe5,0x76,0xd2,0x65,0x86,0xce,0xc6,0x4b,
        0x61,0x16,
    };
    static const uint8_t expect_tag[16] = {
        0x1a,0xe1,0x0b,0x59,0x4f,0x09,0xe2,0x6a,
        0x7e,0x90,0x2e,0xcb,0xd0,0x60,0x06,0x91,
    };

    opssl_aead_ctx_t *ctx = opssl_aead_new(OPSSL_AEAD_CHACHA20_POLY1305);
    if (!ctx) { T_SKIP("chacha20-poly1305 not available"); return; }
    if (opssl_aead_set_key(ctx, key, sizeof(key)) != 1) {
        T_SKIP("chacha20-poly1305: set_key");
        opssl_aead_free(ctx);
        return;
    }

    uint8_t out[256]; size_t out_len = sizeof(out);
    int rc = opssl_aead_seal(ctx, out, &out_len, sizeof(out),
                             nonce, sizeof(nonce),
                             (const uint8_t *)pt, sizeof(pt) - 1,
                             aad, sizeof(aad));
    T_EQ(rc, 1, "RFC 8439 chacha20-poly1305: seal succeeds");
    if (rc == 1) {
        T_EQ(out_len, sizeof(expect_ct) + sizeof(expect_tag),
             "RFC 8439: ct+tag length");
        T_EQ(memcmp(out, expect_ct, sizeof(expect_ct)), 0,
             "RFC 8439: ciphertext matches");
        T_EQ(memcmp(out + sizeof(expect_ct), expect_tag, sizeof(expect_tag)), 0,
             "RFC 8439: tag matches");
    }
    opssl_aead_free(ctx);
}

int main(void)
{
    opssl_init();

    roundtrip(OPSSL_AEAD_AES_128_GCM,       "aes-128-gcm");
    roundtrip(OPSSL_AEAD_AES_256_GCM,       "aes-256-gcm");
    roundtrip(OPSSL_AEAD_CHACHA20_POLY1305, "chacha20-poly1305");
    roundtrip(OPSSL_AEAD_CAMELLIA_128_GCM,  "camellia-128-gcm");
    roundtrip(OPSSL_AEAD_CAMELLIA_256_GCM,  "camellia-256-gcm");

    test_chacha20_poly1305_rfc();

    T_REPORT();
    opssl_cleanup();
    return T_EXIT();
}

/*
 * test_kdf.c — HKDF / HKDF-Expand-Label test vectors.
 *
 * Vectors:
 *   - RFC 5869 §A.1 (HKDF-SHA256 basic):
 *     verifies opssl_hkdf_extract and opssl_hkdf_expand.
 *   - RFC 8448 §3 (TLS 1.3 traffic-secret derivation):
 *     verifies opssl_hkdf_expand_label produces the expected
 *     "derived" sub-secret from the early-secret using the empty
 *     SHA-256 hash as context (RFC 8446 §7.1 / Appendix A.1).
 *
 * The empty-context "derived" derivation is universal and
 * deterministic — it depends only on the algorithm.
 *
 * Copyright (C) 2026 ophion development team
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "test_helpers.h"

/* ---- RFC 5869 §A.1 (HKDF-SHA-256) ---- */
static const uint8_t rfc5869_ikm[22] = {
    0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,
    0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,
    0x0b,0x0b,
};
static const uint8_t rfc5869_salt[13] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,
};
static const uint8_t rfc5869_info[10] = {
    0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xf8,0xf9,
};
static const uint8_t rfc5869_prk[32] = {
    0x07,0x77,0x09,0x36,0x2c,0x2e,0x32,0xdf,0x0d,0xdc,
    0x3f,0x0d,0xc4,0x7b,0xba,0x63,0x90,0xb6,0xc7,0x3b,
    0xb5,0x0f,0x9c,0x31,0x22,0xec,0x84,0x4a,0xd7,0xc2,
    0xb3,0xe5,
};
static const uint8_t rfc5869_okm[42] = {
    0x3c,0xb2,0x5f,0x25,0xfa,0xac,0xd5,0x7a,0x90,0x43,
    0x4f,0x64,0xd0,0x36,0x2f,0x2a,0x2d,0x2d,0x0a,0x90,
    0xcf,0x1a,0x5a,0x4c,0x5d,0xb0,0x2d,0x56,0xec,0xc4,
    0xc5,0xbf,0x34,0x00,0x72,0x08,0xd5,0xb8,0x87,0x18,
    0x58,0x65,
};

static void test_hkdf_rfc5869_case1(void)
{
    uint8_t prk[64];
    size_t prk_len = sizeof(prk);
    int rc = opssl_hkdf_extract(OPSSL_HMAC_SHA256,
                                rfc5869_salt, sizeof(rfc5869_salt),
                                rfc5869_ikm, sizeof(rfc5869_ikm),
                                prk, &prk_len);
    T_EQ(rc, 1, "hkdf: RFC 5869 extract succeeds");
    T_EQ(prk_len, sizeof(rfc5869_prk), "hkdf: PRK length");
    T_EQ(memcmp(prk, rfc5869_prk, sizeof(rfc5869_prk)), 0,
         "hkdf: RFC 5869 PRK matches");

    uint8_t okm[42];
    rc = opssl_hkdf_expand(OPSSL_HMAC_SHA256,
                           prk, prk_len,
                           rfc5869_info, sizeof(rfc5869_info),
                           okm, sizeof(okm));
    T_EQ(rc, 1, "hkdf: RFC 5869 expand succeeds");
    T_EQ(memcmp(okm, rfc5869_okm, sizeof(okm)), 0,
         "hkdf: RFC 5869 OKM matches");
}

/*
 * RFC 8446 §7.1 / Appendix A.1: from the all-zero PSK + all-zero salt,
 *   Early Secret = HKDF-Extract(0, 0) =
 *     33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a
 *
 * Then:
 *   Derived = HKDF-Expand-Label(Early-Secret, "derived",
 *                               SHA-256(""), 32)
 *           = 6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba
 *
 * (See RFC 8448 §3 for the explicit byte values; verified against the
 *  reference here for SHA-256 / TLS 1.3.)
 */
static const uint8_t expected_early_secret[32] = {
    0x33,0xad,0x0a,0x1c,0x60,0x7e,0xc0,0x3b,
    0x09,0xe6,0xcd,0x98,0x93,0x68,0x0c,0xe2,
    0x10,0xad,0xf3,0x00,0xaa,0x1f,0x26,0x60,
    0xe1,0xb2,0x2e,0x10,0xf1,0x70,0xf9,0x2a,
};
static const uint8_t expected_derived[32] = {
    0x6f,0x26,0x15,0xa1,0x08,0xc7,0x02,0xc5,
    0x67,0x8f,0x54,0xfc,0x9d,0xba,0xb6,0x97,
    0x16,0xc0,0x76,0x18,0x9c,0x48,0x25,0x0c,
    0xeb,0xea,0xc3,0x57,0x6c,0x36,0x11,0xba,
};
/* SHA-256("") */
static const uint8_t sha256_empty[32] = {
    0xe3,0xb0,0xc4,0x42,0x98,0xfc,0x1c,0x14,
    0x9a,0xfb,0xf4,0xc8,0x99,0x6f,0xb9,0x24,
    0x27,0xae,0x41,0xe4,0x64,0x9b,0x93,0x4c,
    0xa4,0x95,0x99,0x1b,0x78,0x52,0xb8,0x55,
};

static void test_tls13_early_secret_and_derived(void)
{
    uint8_t zeros[32] = {0};
    uint8_t early[32]; size_t early_len = sizeof(early);
    int rc = opssl_hkdf_extract(OPSSL_HMAC_SHA256,
                                zeros, sizeof(zeros),
                                zeros, sizeof(zeros),
                                early, &early_len);
    T_EQ(rc, 1, "tls13-kdf: extract early secret");
    T_EQ(early_len, (size_t)32, "tls13-kdf: early secret length");
    T_EQ(memcmp(early, expected_early_secret, 32), 0,
         "tls13-kdf: early secret matches RFC 8446 vector");

    uint8_t derived[32];
    rc = opssl_hkdf_expand_label(OPSSL_HMAC_SHA256,
                                 early, 32,
                                 "derived",
                                 sha256_empty, sizeof(sha256_empty),
                                 derived, sizeof(derived));
    T_EQ(rc, 1, "tls13-kdf: expand_label derived succeeds");
    T_EQ(memcmp(derived, expected_derived, 32), 0,
         "tls13-kdf: derived secret matches RFC 8446 vector");
}

/*
 * Sanity: expand_label with two different labels must give two
 * different outputs (basic property of HKDF).
 */
static void test_expand_label_label_separation(void)
{
    uint8_t secret[32];
    for (size_t i = 0; i < sizeof(secret); ++i) secret[i] = (uint8_t)(i * 7);

    uint8_t out_a[32], out_b[32];
    int rc = opssl_hkdf_expand_label(OPSSL_HMAC_SHA256, secret, 32,
                                     "c hs traffic", NULL, 0,
                                     out_a, sizeof(out_a));
    T_EQ(rc, 1, "expand_label: handshake-traffic key derives");
    rc = opssl_hkdf_expand_label(OPSSL_HMAC_SHA256, secret, 32,
                                 "s hs traffic", NULL, 0,
                                 out_b, sizeof(out_b));
    T_EQ(rc, 1, "expand_label: server-side derives");
    T_NE(memcmp(out_a, out_b, 32), 0,
         "expand_label: different labels yield different keys");
}

int main(void)
{
    opssl_init();
    test_hkdf_rfc5869_case1();
    test_tls13_early_secret_and_derived();
    test_expand_label_label_separation();
    T_REPORT();
    opssl_cleanup();
    return T_EXIT();
}

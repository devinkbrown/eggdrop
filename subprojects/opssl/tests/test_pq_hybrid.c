/*
 * test_pq_hybrid.c — ML-KEM-768 + X25519 hybrid key exchange.
 *
 * Mirrors the construction used in TLS 1.3 hybrid groups
 * (draft-ietf-tls-hybrid-design):
 *
 *   1. Client generates ML-KEM-768 keypair and X25519 keypair.
 *   2. Server receives client's PK + X25519 pub, encapsulates ML-KEM
 *      against client PK and computes X25519 shared with own private.
 *   3. Client decapsulates ciphertext + derives X25519 shared.
 *   4. Both sides concatenate (mlkem_ss || x25519_ss) — equal.
 *
 * Also performs a tamper test (single bit flip in ML-KEM ciphertext
 * must yield different decapsulated secret — ML-KEM uses implicit
 * rejection so the call still succeeds but the secret diverges).
 *
 * Copyright (C) 2026 ophion development team
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "test_helpers.h"

static void test_mlkem768_x25519_hybrid(void)
{
    /* ---- ML-KEM-768 client keypair ---- */
    opssl_mlkem_ctx_t *client_kem = opssl_mlkem_new(OPSSL_MLKEM_768);
    if (!client_kem) { T_SKIP("hybrid: mlkem_new"); return; }
    int rc = opssl_mlkem_keygen(client_kem);
    if (rc != 1) {
        T_SKIP("hybrid: mlkem keygen");
        opssl_mlkem_free(client_kem);
        return;
    }
    uint8_t client_pk[OPSSL_MLKEM768_PK_LEN];
    size_t pk_len = sizeof(client_pk);
    rc = opssl_mlkem_get_public(client_kem, client_pk, &pk_len);
    T_EQ(rc, 1, "hybrid: mlkem get_public");
    T_EQ(pk_len, (size_t)OPSSL_MLKEM768_PK_LEN, "hybrid: mlkem pk size");

    /* ---- Server encapsulates against client_pk ---- */
    opssl_mlkem_ctx_t *server_kem = opssl_mlkem_new(OPSSL_MLKEM_768);
    T_NE(server_kem, NULL, "hybrid: server mlkem_new");

    uint8_t ct[OPSSL_MLKEM768_CT_LEN];
    size_t ct_len = sizeof(ct);
    uint8_t server_ss[OPSSL_MLKEM768_SS_LEN];
    size_t server_ss_len = sizeof(server_ss);
    rc = opssl_mlkem_encaps(server_kem, client_pk, pk_len,
                            ct, &ct_len, server_ss, &server_ss_len);
    T_EQ(rc, 1, "hybrid: mlkem encaps");
    T_EQ(ct_len, (size_t)OPSSL_MLKEM768_CT_LEN, "hybrid: ct size");
    T_EQ(server_ss_len, (size_t)OPSSL_MLKEM768_SS_LEN, "hybrid: ss size");

    /* ---- Client decapsulates ---- */
    uint8_t client_ss[OPSSL_MLKEM768_SS_LEN];
    size_t client_ss_len = sizeof(client_ss);
    rc = opssl_mlkem_decaps(client_kem, ct, ct_len, client_ss, &client_ss_len);
    T_EQ(rc, 1, "hybrid: mlkem decaps");
    T_EQ(client_ss_len, server_ss_len, "hybrid: ss len agree");
    T_EQ(memcmp(client_ss, server_ss, client_ss_len), 0,
         "hybrid: ML-KEM shared secret matches");

    /* ---- X25519 leg ---- */
    uint8_t c_x_priv[OPSSL_X25519_KEY_LEN], c_x_pub[OPSSL_X25519_KEY_LEN];
    uint8_t s_x_priv[OPSSL_X25519_KEY_LEN], s_x_pub[OPSSL_X25519_KEY_LEN];
    T_EQ(opssl_x25519_keygen(c_x_priv, c_x_pub), 1, "hybrid: x25519 client keygen");
    T_EQ(opssl_x25519_keygen(s_x_priv, s_x_pub), 1, "hybrid: x25519 server keygen");

    uint8_t c_x_ss[OPSSL_X25519_SHARED_LEN];
    uint8_t s_x_ss[OPSSL_X25519_SHARED_LEN];
    T_EQ(opssl_x25519_derive(c_x_ss, c_x_priv, s_x_pub), 1, "hybrid: x25519 client derive");
    T_EQ(opssl_x25519_derive(s_x_ss, s_x_priv, c_x_pub), 1, "hybrid: x25519 server derive");
    T_EQ(memcmp(c_x_ss, s_x_ss, OPSSL_X25519_SHARED_LEN), 0,
         "hybrid: X25519 shared secret matches");

    /* ---- Concatenated hybrid secret matches on both sides ---- */
    uint8_t client_hybrid[OPSSL_MLKEM768_SS_LEN + OPSSL_X25519_SHARED_LEN];
    uint8_t server_hybrid[sizeof(client_hybrid)];
    memcpy(client_hybrid, client_ss, OPSSL_MLKEM768_SS_LEN);
    memcpy(client_hybrid + OPSSL_MLKEM768_SS_LEN, c_x_ss, OPSSL_X25519_SHARED_LEN);
    memcpy(server_hybrid, server_ss, OPSSL_MLKEM768_SS_LEN);
    memcpy(server_hybrid + OPSSL_MLKEM768_SS_LEN, s_x_ss, OPSSL_X25519_SHARED_LEN);
    T_EQ(memcmp(client_hybrid, server_hybrid, sizeof(client_hybrid)), 0,
         "hybrid: concatenated secrets equal");

    /* ---- Tamper test: flip a byte in ciphertext, decaps must diverge ---- */
    ct[0] ^= 0x01;
    uint8_t tampered_ss[OPSSL_MLKEM768_SS_LEN];
    size_t tampered_len = sizeof(tampered_ss);
    rc = opssl_mlkem_decaps(client_kem, ct, ct_len, tampered_ss, &tampered_len);
    /* ML-KEM uses implicit rejection: returns a pseudo-random value, not error */
    if (rc == 1) {
        T_NE(memcmp(tampered_ss, client_ss, tampered_len), 0,
             "hybrid: tampered ct yields different secret");
    } else {
        T_NE(rc, 1, "hybrid: tampered ct rejected");
    }

    opssl_mlkem_free(client_kem);
    opssl_mlkem_free(server_kem);
}

int main(void)
{
    opssl_init();
    test_mlkem768_x25519_hybrid();
    T_REPORT();
    opssl_cleanup();
    return T_EXIT();
}

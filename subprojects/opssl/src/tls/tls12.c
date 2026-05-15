/*
 * opssl/tls/tls12.c — TLS 1.2 handshake state machine (RFC 5246 + extensions).
 *
 * Implements the TLS 1.2 handshake for both client and server.
 * Only supports ECDHE/DHE key exchange (no RSA key transport).
 * Only AEAD ciphers (GCM, ChaCha20-Poly1305).
 *
 * State machine approach for non-blocking I/O:
 * - Each call processes one incoming message and produces zero or more outgoing messages
 * - Returns WANT_READ/WANT_WRITE for non-blocking operation
 * - Enforces Extended Master Secret (RFC 7627) for security
 *
 * Copyright (C) 2026 ophion development team
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <opssl/platform.h>
#include <opssl/crypto.h>
#include <opssl/cbs.h>
#include <opssl/cert.h>
#include <opssl/err.h>
#include <opssl/types.h>
#include <string.h>
#include <stdlib.h>
#include "../crypto/sha_internal.h"

/* Crypto function declarations */
extern int opssl_ct_eq(const void *a, const void *b, size_t len);

/* Convenience functions for ECC key operations */
__attribute__((unused)) static int opssl_ecc_keygen(opssl_named_group_t group, uint8_t *priv_key, uint8_t *pub_key, size_t *pub_len)
{
    if (group == OPSSL_GROUP_X25519) {
        return opssl_x25519_keygen(priv_key, pub_key);
    } else if (group == OPSSL_GROUP_SECP256R1) {
        opssl_ecdh_ctx_t *ctx = opssl_ecdh_new(OPSSL_CURVE_P256);
        if (!ctx || !opssl_ecdh_keygen(ctx)) {
            if (ctx) opssl_ecdh_free(ctx);
            return 0;
        }
        int ret = opssl_ecdh_get_public(ctx, pub_key, pub_len);
        opssl_ecdh_free(ctx);
        return ret;
    } else if (group == OPSSL_GROUP_SECP384R1) {
        opssl_ecdh_ctx_t *ctx = opssl_ecdh_new(OPSSL_CURVE_P384);
        if (!ctx || !opssl_ecdh_keygen(ctx)) {
            if (ctx) opssl_ecdh_free(ctx);
            return 0;
        }
        int ret = opssl_ecdh_get_public(ctx, pub_key, pub_len);
        opssl_ecdh_free(ctx);
        return ret;
    }
    return 0;
}

/* TLS constants */
#define TLS_HELLO_RANDOM_LEN        32
#define TLS_MASTER_SECRET_LEN       48
#define TLS_FINISHED_VERIFY_LEN     12
#define TLS_MAX_KEY_BLOCK_LEN       256

/* Handshake message types */
#define TLS_MT_CLIENT_HELLO         1
#define TLS_MT_SERVER_HELLO         2
#define TLS_MT_CERTIFICATE          11
#define TLS_MT_SERVER_KEY_EXCHANGE  12
#define TLS_MT_CERTIFICATE_REQUEST  13
#define TLS_MT_SERVER_HELLO_DONE    14
#define TLS_MT_CERTIFICATE_VERIFY   15
#define TLS_MT_CLIENT_KEY_EXCHANGE  16
#define TLS_MT_FINISHED             20

/* Extension types */
#define TLS_EXT_SERVER_NAME                 0
#define TLS_EXT_SUPPORTED_GROUPS            10
#define TLS_EXT_SIGNATURE_ALGORITHMS        13
#define TLS_EXT_ALPN                        16
#define TLS_EXT_ENCRYPT_THEN_MAC            22
#define TLS_EXT_EXTENDED_MASTER_SECRET      23

/* TLS 1.2 handshake state */
typedef struct {
    opssl_handshake_state_t state;
    opssl_ciphersuite_t cipher;
    opssl_named_group_t group;
    opssl_sig_algo_t sig_algo;

    uint8_t client_random[32];
    uint8_t server_random[32];
    uint8_t master_secret[48];
    uint8_t key_block[256];  /* expanded key material */

    /* ECDHE state */
    uint8_t ecdh_priv[OPSSL_X25519_KEY_LEN];
    uint8_t ecdh_pub[133];  /* max uncompressed P-521 */
    size_t ecdh_pub_len;
    uint8_t premaster_secret[48];
    size_t premaster_len;
    void *ecdh_ctx;  /* For P-256/P-384 context storage */

    /* Transcript hashes for Finished */
    opssl_sha256_ctx_t verify_sha256;
    opssl_sha512_ctx_t verify_sha384;
    opssl_hmac_algo_t prf_hash;

    bool extended_master_secret;  /* RFC 7627 */
    bool encrypt_then_mac;        /* RFC 7366 */
    bool ccs_sent;                /* CCS has been sent for this side */

    const opssl_pkey_t *sign_key;  /* server's long-term signing key (from ctx) */
    const opssl_x509_chain_t *cert_chain;  /* server's certificate chain */

    /* Peer certificate (leaf only, for verification) */
    uint8_t *peer_cert_der;
    size_t peer_cert_der_len;

    /* Server's SPKI from Certificate (for SKE signature verification) */
    const uint8_t *peer_spki;
    size_t peer_spki_len;

    char sni[256];   /* client SNI to send */
    char alpn[32];   /* negotiated ALPN protocol */
    size_t alpn_len;

    /* Client ALPN: protocols to offer (len-prefixed) */
    char alpn_offer[128];
    size_t alpn_offer_len;

    /* Server ALPN: supported protocols (len-prefixed) */
    char alpn_supported[128];
    size_t alpn_supported_len;

    /* Client's received ALPN from ClientHello (for server selection) */
    char alpn_client[128];
    size_t alpn_client_len;

    bool tls13_capable;  /* server supports TLS 1.3 — apply downgrade sentinel */
} tls12_hs_t;

/* RFC 8446 §4.1.3 downgrade sentinel: "DOWNGRD\x01" for TLS 1.2 negotiation */
static const uint8_t tls13_downgrade_sentinel[8] = {
    0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x01
};

/*
 * TLS 1.2 PRF implementation (RFC 5246 §5)
 *
 * P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) ||
 *                        HMAC_hash(secret, A(2) + seed) || ...
 * where A(0) = seed, A(i) = HMAC_hash(secret, A(i-1))
 *
 * PRF(secret, label, seed) = P_hash(secret, label + seed)
 */
static int
tls12_prf(opssl_hmac_algo_t hash,
          const uint8_t *secret, size_t secret_len,
          const char *label,
          const uint8_t *seed, size_t seed_len,
          uint8_t *out, size_t out_len)
{
    opssl_hmac_ctx_t hmac;
    uint8_t A[OPSSL_HMAC_MAX_DIGEST_LEN];
    size_t A_len = 0;
    size_t hash_len = 0;
    size_t label_len = strlen(label);
    uint8_t *p = out;
    size_t remaining = out_len;
    int ret = 0;

    /* Determine hash output length */
    switch (hash) {
        case OPSSL_HMAC_SHA256: hash_len = 32; break;
        case OPSSL_HMAC_SHA384: hash_len = 48; break;
        case OPSSL_HMAC_SHA512: hash_len = 64; break;
        default: goto err;
    }

    /* Initialize HMAC with secret */
    if (!opssl_hmac_init(&hmac, hash, secret, secret_len))
        goto err;

    /* A(0) = label + seed */
    opssl_hmac_update(&hmac, label, label_len);
    opssl_hmac_update(&hmac, seed, seed_len);

    /* A(1) = HMAC(secret, A(0)) */
    A_len = sizeof(A);
    if (!opssl_hmac_final(&hmac, A, &A_len))
        goto cleanup;

    while (remaining > 0) {
        /* P_hash iteration: HMAC(secret, A(i) + label + seed) */
        if (!opssl_hmac_init(&hmac, hash, secret, secret_len))
            goto cleanup;

        opssl_hmac_update(&hmac, A, A_len);
        opssl_hmac_update(&hmac, label, label_len);
        opssl_hmac_update(&hmac, seed, seed_len);

        if (remaining >= hash_len) {
            size_t out_piece = hash_len;
            if (!opssl_hmac_final(&hmac, p, &out_piece))
                goto cleanup;
            p += hash_len;
            remaining -= hash_len;
        } else {
            /* Final partial block */
            uint8_t tmp[OPSSL_HMAC_MAX_DIGEST_LEN];
            size_t tmp_len = sizeof(tmp);
            if (!opssl_hmac_final(&hmac, tmp, &tmp_len))
                goto cleanup;
            memcpy(p, tmp, remaining);
            remaining = 0;
        }

        /* Compute A(i+1) = HMAC(secret, A(i)) */
        if (remaining > 0) {
            if (!opssl_hmac_init(&hmac, hash, secret, secret_len))
                goto cleanup;
            opssl_hmac_update(&hmac, A, A_len);
            A_len = sizeof(A);
            if (!opssl_hmac_final(&hmac, A, &A_len))
                goto cleanup;
        }
    }

    ret = 1;

cleanup:
    opssl_hmac_cleanup(&hmac);
    opssl_memzero(A, sizeof(A));
err:
    return ret;
}

/*
 * Derive master secret from premaster secret.
 *
 * Standard TLS 1.2:
 *   master_secret = PRF(premaster_secret, "master secret",
 *                       client_random + server_random)[0..47]
 *
 * Extended Master Secret (RFC 7627):
 *   master_secret = PRF(premaster_secret, "extended master secret",
 *                       Hash(handshake_messages))[0..47]
 */
static int
derive_master_secret(tls12_hs_t *hs)
{
    uint8_t seed[64];
    size_t seed_len;

    if (hs->extended_master_secret) {
        /* RFC 7627: use handshake hash as seed (use copy to preserve state) */
        if (hs->prf_hash == OPSSL_HMAC_SHA256) {
            opssl_sha256_ctx_t tmp = hs->verify_sha256;
            opssl_sha256_final(&tmp, seed);
            seed_len = 32;
        } else {
            opssl_sha512_ctx_t tmp = hs->verify_sha384;
            opssl_sha384_final(&tmp, seed);
            seed_len = 48;
        }

        return tls12_prf(hs->prf_hash,
                         hs->premaster_secret, hs->premaster_len,
                         "extended master secret",
                         seed, seed_len,
                         hs->master_secret, 48);
    } else {
        /* Standard TLS 1.2: client_random + server_random */
        memcpy(seed, hs->client_random, 32);
        memcpy(seed + 32, hs->server_random, 32);

        return tls12_prf(hs->prf_hash,
                         hs->premaster_secret, hs->premaster_len,
                         "master secret",
                         seed, 64,
                         hs->master_secret, 48);
    }
}

/*
 * Expand key block from master secret.
 * key_block = PRF(master_secret, "key expansion", server_random + client_random)[needed_len]
 */
__attribute__((unused)) static int
expand_key_block(tls12_hs_t *hs, size_t needed_len)
{
    uint8_t seed[64];

    if (needed_len > sizeof(hs->key_block)) {
        OPSSL_ERR(OPSSL_ERR_TLS, OPSSL_TLS_ERR_INTERNAL_ERROR);
        return 0;
    }

    /* server_random + client_random */
    memcpy(seed, hs->server_random, 32);
    memcpy(seed + 32, hs->client_random, 32);

    return tls12_prf(hs->prf_hash,
                     hs->master_secret, 48,
                     "key expansion",
                     seed, 64,
                     hs->key_block, needed_len);
}

static void
tls12_update_transcript(tls12_hs_t *hs, const uint8_t *data, size_t len)
{
    if (hs->prf_hash == OPSSL_HMAC_SHA256)
        opssl_sha256_update(&hs->verify_sha256, data, len);
    else
        opssl_sha512_update(&hs->verify_sha384, data, len);
}

/*
 * Generate Finished verify_data.
 * client: PRF(master_secret, "client finished", Hash(handshake_messages))[0..11]
 * server: PRF(master_secret, "server finished", Hash(handshake_messages))[0..11]
 */
static int
generate_finished(tls12_hs_t *hs, bool is_client, uint8_t verify_data[12])
{
    uint8_t hash[64];
    size_t hash_len;
    const char *label;

    /* Get handshake hash */
    if (hs->prf_hash == OPSSL_HMAC_SHA256) {
        opssl_sha256_ctx_t tmp = hs->verify_sha256;
        opssl_sha256_final(&tmp, hash);
        hash_len = 32;
    } else {
        opssl_sha512_ctx_t tmp = hs->verify_sha384;
        opssl_sha384_final(&tmp, hash);
        hash_len = 48;
    }

    label = is_client ? "client finished" : "server finished";
    return tls12_prf(hs->prf_hash,
                     hs->master_secret, 48,
                     label,
                     hash, hash_len,
                     verify_data, 12);
}

/*
 * Parse ClientHello message.
 * Extract cipher suites, extensions, random.
 */
static int
parse_client_hello(tls12_hs_t *hs, opssl_cbs_t *cbs)
{
    opssl_cbs_t session_id, cipher_suites, compression, extensions;
    uint16_t version;
    uint8_t session_id_len;

    /* version(2) + random(32) + session_id_len(1) + session_id + ... */
    if (!opssl_cbs_get_u16(cbs, &version) ||
        !opssl_cbs_copy_bytes(cbs, hs->client_random, 32) ||
        !opssl_cbs_get_u8(cbs, &session_id_len) ||
        !opssl_cbs_get_bytes(cbs, &session_id, session_id_len) ||
        !opssl_cbs_get_u16_length_prefixed(cbs, &cipher_suites) ||
        !opssl_cbs_get_u8_length_prefixed(cbs, &compression)) {
        OPSSL_ERR(OPSSL_ERR_TLS, OPSSL_TLS_ERR_DECODE_ERROR);
        return 0;
    }

    /* Check TLS version */
    if (version != OPSSL_TLS_1_2) {
        OPSSL_ERR(OPSSL_ERR_TLS, OPSSL_TLS_ERR_PROTOCOL_VERSION);
        return 0;
    }

    /* Parse extensions if present */
    if (!opssl_cbs_is_empty(cbs)) {
        if (!opssl_cbs_get_u16_length_prefixed(cbs, &extensions)) {
            OPSSL_ERR(OPSSL_ERR_TLS, OPSSL_TLS_ERR_DECODE_ERROR);
            return 0;
        }

        /* Process extensions */
        while (!opssl_cbs_is_empty(&extensions)) {
            uint16_t ext_type;
            opssl_cbs_t ext_data;

            if (!opssl_cbs_get_u16(&extensions, &ext_type) ||
                !opssl_cbs_get_u16_length_prefixed(&extensions, &ext_data)) {
                OPSSL_ERR(OPSSL_ERR_TLS, OPSSL_TLS_ERR_DECODE_ERROR);
                return 0;
            }

            switch (ext_type) {
                case TLS_EXT_EXTENDED_MASTER_SECRET:
                    hs->extended_master_secret = true;
                    break;
                case TLS_EXT_ENCRYPT_THEN_MAC:
                    hs->encrypt_then_mac = true;
                    break;
                case TLS_EXT_SERVER_NAME: {
                    opssl_cbs_t sni_list;
                    if (opssl_cbs_get_u16_length_prefixed(&ext_data, &sni_list)) {
                        while (opssl_cbs_len(&sni_list) >= 3) {
                            uint8_t name_type;
                            opssl_cbs_t name;
                            if (!opssl_cbs_get_u8(&sni_list, &name_type) ||
                                !opssl_cbs_get_u16_length_prefixed(&sni_list, &name))
                                break;
                            if (name_type == 0) {
                                size_t nlen = opssl_cbs_len(&name);
                                if (nlen < sizeof(hs->sni)) {
                                    memcpy(hs->sni, opssl_cbs_data(&name), nlen);
                                    hs->sni[nlen] = '\0';
                                }
                            }
                        }
                    }
                    break;
                }
                case TLS_EXT_SIGNATURE_ALGORITHMS:
                case TLS_EXT_SUPPORTED_GROUPS:
                    break;
                case TLS_EXT_ALPN: {
                    opssl_cbs_t proto_list;
                    if (!opssl_cbs_get_u16_length_prefixed(&ext_data, &proto_list))
                        break;
                    size_t off = 0;
                    while (opssl_cbs_len(&proto_list) > 0 && off < sizeof(hs->alpn_client) - 2) {
                        opssl_cbs_t proto;
                        if (!opssl_cbs_get_u8_length_prefixed(&proto_list, &proto))
                            break;
                        size_t plen = opssl_cbs_len(&proto);
                        if (plen == 0 || off + 1 + plen > sizeof(hs->alpn_client))
                            break;
                        hs->alpn_client[off] = (char)plen;
                        memcpy(hs->alpn_client + off + 1, opssl_cbs_data(&proto), plen);
                        off += 1 + plen;
                    }
                    hs->alpn_client_len = off;
                    break;
                }
                default:
                    /* Skip unknown extensions */
                    break;
            }
        }
    }

    /* Select cipher suite — must match key type.
     * ECDHE_RSA requires RSA key, ECDHE_ECDSA works with ECDSA/Ed25519. */
    bool is_ecdsa_key = hs->sign_key &&
                        (opssl_pkey_type(hs->sign_key) == OPSSL_PKEY_EC ||
                         opssl_pkey_type(hs->sign_key) == OPSSL_PKEY_ED25519);

    while (!opssl_cbs_is_empty(&cipher_suites)) {
        uint16_t cipher;
        if (!opssl_cbs_get_u16(&cipher_suites, &cipher))
            break;

        switch (cipher) {
            case OPSSL_TLS_ECDHE_ECDSA_AES_128_GCM:
                if (!is_ecdsa_key) break;
                hs->cipher = cipher;
                hs->prf_hash = OPSSL_HMAC_SHA256;
                hs->group = OPSSL_GROUP_SECP256R1;
                goto found;
            case OPSSL_TLS_ECDHE_RSA_AES_128_GCM:
                if (is_ecdsa_key) break;
                hs->cipher = cipher;
                hs->prf_hash = OPSSL_HMAC_SHA256;
                hs->group = OPSSL_GROUP_SECP256R1;
                goto found;
            case OPSSL_TLS_ECDHE_ECDSA_AES_256_GCM:
                if (!is_ecdsa_key) break;
                hs->cipher = cipher;
                hs->prf_hash = OPSSL_HMAC_SHA384;
                hs->group = OPSSL_GROUP_SECP384R1;
                goto found;
            case OPSSL_TLS_ECDHE_RSA_AES_256_GCM:
                if (is_ecdsa_key) break;
                hs->cipher = cipher;
                hs->prf_hash = OPSSL_HMAC_SHA384;
                hs->group = OPSSL_GROUP_SECP384R1;
                goto found;
        }
    }

    OPSSL_ERR(OPSSL_ERR_TLS, OPSSL_TLS_ERR_HANDSHAKE_FAILURE);
    return 0;

found:
    /* Require Extended Master Secret for security */
    if (!hs->extended_master_secret) {
        OPSSL_ERR(OPSSL_ERR_TLS, OPSSL_TLS_ERR_MISSING_EXTENSION);
        return 0;
    }

    return 1;
}

/*
 * Build TLS 1.2 Certificate message body (just the certificate_list, without
 * the handshake header byte + length — those are added by the caller).
 */
static int
build_server_certificate(tls12_hs_t *hs, opssl_cbb_t *cbb)
{
    opssl_cbb_t msg_body, cert_list;

    if (!opssl_cbb_add_u24_length_prefixed(cbb, &msg_body))
        return 0;

    if (!hs->cert_chain || opssl_x509_chain_count(hs->cert_chain) == 0) {
        if (!opssl_cbb_add_u24(&msg_body, 0))
            return 0;
        opssl_cbb_flush(cbb);
        return 1;
    }

    if (!opssl_cbb_add_u24_length_prefixed(&msg_body, &cert_list))
        return 0;

    size_t count = opssl_x509_chain_count(hs->cert_chain);
    for (size_t i = 0; i < count; i++) {
        opssl_x509_t *cert = opssl_x509_chain_get(hs->cert_chain, i);
        if (!cert)
            return 0;

        const uint8_t *der;
        size_t der_len;
        if (!opssl_x509_get_der(cert, &der, &der_len)) {
            opssl_x509_free(cert);
            return 0;
        }

        opssl_cbb_t cert_entry;
        if (!opssl_cbb_add_u24_length_prefixed(&cert_list, &cert_entry) ||
            !opssl_cbb_add_bytes(&cert_entry, der, der_len) ||
            !opssl_cbb_flush(&cert_list)) {
            opssl_x509_free(cert);
            return 0;
        }

        opssl_x509_free(cert);
    }

    opssl_cbb_flush(cbb);
    return 1;
}

/*
 * Build ServerHello message.
 */
static int
build_server_hello(tls12_hs_t *hs, opssl_cbb_t *cbb)
{
    opssl_cbb_t hello, extensions, ext;

    if (!opssl_cbb_add_u24_length_prefixed(cbb, &hello))
        return 0;

    /* version(2) + random(32) + session_id_len(1) + cipher(2) + compression(1) */
    if (!opssl_cbb_add_u16(&hello, OPSSL_TLS_1_2) ||
        !opssl_cbb_add_bytes(&hello, hs->server_random, 32) ||
        !opssl_cbb_add_u8(&hello, 0) ||  /* no session ID */
        !opssl_cbb_add_u16(&hello, hs->cipher) ||
        !opssl_cbb_add_u8(&hello, 0))   /* null compression */
        return 0;

    /* Extensions */
    if (!opssl_cbb_add_u16_length_prefixed(&hello, &extensions))
        return 0;

    /* Extended Master Secret */
    if (!opssl_cbb_add_u16(&extensions, TLS_EXT_EXTENDED_MASTER_SECRET) ||
        !opssl_cbb_add_u16_length_prefixed(&extensions, &ext) ||
        !opssl_cbb_flush(&ext))
        return 0;

    /* ALPN negotiation: match server preference against client offers */
    if (hs->alpn_supported_len > 0 && hs->alpn_client_len > 0) {
        size_t soff = 0;
        while (soff < hs->alpn_supported_len) {
            uint8_t slen = (uint8_t)hs->alpn_supported[soff];
            const char *sproto = hs->alpn_supported + soff + 1;
            size_t coff = 0;
            while (coff < hs->alpn_client_len) {
                uint8_t clen = (uint8_t)hs->alpn_client[coff];
                const char *cproto = hs->alpn_client + coff + 1;
                if (slen == clen && memcmp(sproto, cproto, slen) == 0) {
                    memcpy(hs->alpn, sproto, slen);
                    hs->alpn[slen] = '\0';
                    hs->alpn_len = slen;
                    goto alpn_done;
                }
                coff += 1 + clen;
            }
            soff += 1 + slen;
        }
    }
alpn_done:
    if (hs->alpn_len > 0) {
        opssl_cbb_t alpn_ext, alpn_list, alpn_entry;
        if (!opssl_cbb_add_u16(&extensions, TLS_EXT_ALPN) ||
            !opssl_cbb_add_u16_length_prefixed(&extensions, &alpn_ext) ||
            !opssl_cbb_add_u16_length_prefixed(&alpn_ext, &alpn_list) ||
            !opssl_cbb_add_u8_length_prefixed(&alpn_list, &alpn_entry) ||
            !opssl_cbb_add_bytes(&alpn_entry, (const uint8_t *)hs->alpn, hs->alpn_len))
            return 0;
    }

    return opssl_cbb_flush(&hello);
}

/*
 * Build ServerKeyExchange for ECDHE.
 * Format: curve_type(1) + named_curve(2) + point_len(1) + point + sig_algo(2) + sig_len(2) + signature
 */
static int
build_server_key_exchange(tls12_hs_t *hs, opssl_cbb_t *cbb)
{
    opssl_cbb_t ske;
    uint8_t sig_input[512];
    uint8_t signature[128];
    size_t sig_input_len = 0;
    size_t sig_len = sizeof(signature);

    /* Generate ECDH key pair */
    if (hs->group == OPSSL_GROUP_X25519) {
        if (!opssl_x25519_keygen(hs->ecdh_priv, hs->ecdh_pub)) {
            OPSSL_ERR(OPSSL_ERR_CRYPTO, 0);
            return 0;
        }
        hs->ecdh_pub_len = 32;
    } else if (hs->group == OPSSL_GROUP_SECP256R1) {
        /* Use P-256 for ECDHE */
        opssl_ecdh_ctx_t *ecdh_ctx = opssl_ecdh_new(OPSSL_CURVE_P256);
        if (!ecdh_ctx || !opssl_ecdh_keygen(ecdh_ctx)) {
            if (ecdh_ctx) opssl_ecdh_free(ecdh_ctx);
            OPSSL_ERR(OPSSL_ERR_CRYPTO, 0);
            return 0;
        }

        size_t pub_len = sizeof(hs->ecdh_pub);
        if (!opssl_ecdh_get_public(ecdh_ctx, hs->ecdh_pub, &pub_len)) {
            opssl_ecdh_free(ecdh_ctx);
            OPSSL_ERR(OPSSL_ERR_CRYPTO, 0);
            return 0;
        }
        hs->ecdh_pub_len = pub_len;

        /* Store ECDH context for later use in key exchange */
        hs->ecdh_ctx = ecdh_ctx;
    } else if (hs->group == OPSSL_GROUP_SECP384R1) {
        /* Use P-384 for ECDHE */
        opssl_ecdh_ctx_t *ecdh_ctx = opssl_ecdh_new(OPSSL_CURVE_P384);
        if (!ecdh_ctx || !opssl_ecdh_keygen(ecdh_ctx)) {
            if (ecdh_ctx) opssl_ecdh_free(ecdh_ctx);
            OPSSL_ERR(OPSSL_ERR_CRYPTO, 0);
            return 0;
        }

        size_t pub_len = sizeof(hs->ecdh_pub);
        if (!opssl_ecdh_get_public(ecdh_ctx, hs->ecdh_pub, &pub_len)) {
            opssl_ecdh_free(ecdh_ctx);
            OPSSL_ERR(OPSSL_ERR_CRYPTO, 0);
            return 0;
        }
        hs->ecdh_pub_len = pub_len;

        /* Store ECDH context for later use in key exchange */
        hs->ecdh_ctx = ecdh_ctx;
    } else {
        OPSSL_ERR(OPSSL_ERR_TLS, OPSSL_TLS_ERR_INSUFFICIENT_SECURITY);
        return 0;
    }

    if (!opssl_cbb_add_u24_length_prefixed(cbb, &ske))
        return 0;

    /* ECDH parameters */
    if (!opssl_cbb_add_u8(&ske, 3) ||  /* named_curve */
        !opssl_cbb_add_u16(&ske, hs->group) ||
        !opssl_cbb_add_u8(&ske, hs->ecdh_pub_len) ||
        !opssl_cbb_add_bytes(&ske, hs->ecdh_pub, hs->ecdh_pub_len))
        return 0;

    /* Build signature input: client_random + server_random + ecdh_params */
    memcpy(sig_input, hs->client_random, 32);
    memcpy(sig_input + 32, hs->server_random, 32);
    sig_input[64] = 3; /* named_curve */
    sig_input[65] = (hs->group >> 8) & 0xff;
    sig_input[66] = hs->group & 0xff;
    sig_input[67] = hs->ecdh_pub_len;
    memcpy(sig_input + 68, hs->ecdh_pub, hs->ecdh_pub_len);
    sig_input_len = 68 + hs->ecdh_pub_len;

    /*
     * Hash the signature input.
     * TLS 1.2 SKE uses the PRF-aligned hash: SHA-384 for P-384 cipher suites,
     * SHA-256 for everything else.  The hash byte in the on-wire
     * SignatureAndHashAlgorithm field must match the digest actually produced.
     */
    uint8_t digest[OPSSL_SHA384_DIGEST_LEN];  /* 48 bytes -- fits SHA-256 and SHA-384 */
    size_t digest_len;
    if (hs->group == OPSSL_GROUP_SECP384R1) {
        opssl_sha384(sig_input, sig_input_len, digest);
        digest_len = OPSSL_SHA384_DIGEST_LEN;
    } else {
        opssl_sha256(sig_input, sig_input_len, digest);
        digest_len = OPSSL_SHA256_DIGEST_LEN;
    }

    /* Sign with the server's long-term key from the TLS context */
    if (!hs->sign_key) {
        OPSSL_ERR(OPSSL_ERR_CRYPTO, 0);
        return 0;
    }

    if (!opssl_pkey_sign(hs->sign_key, digest, digest_len, signature, &sig_len)) {
        OPSSL_ERR(OPSSL_ERR_CRYPTO, 0);
        return 0;
    }

    /*
     * Select SignatureAndHashAlgorithm (RFC 5246 ss7.4.1.4.1).
     * For ECDSA keys the hash byte must match the digest used above:
     *   P-384 group -> SHA-384 + ECDSA -> OPSSL_SIG_ECDSA_SECP384R1 (0x0503)
     *   others      -> SHA-256 + ECDSA -> OPSSL_SIG_ECDSA_SECP256R1 (0x0403)
     * RSA-PSS: opssl_pkey_sign hardcodes SHA-256 internally -> 0x0804.
     * Ed25519: pure signature scheme, hash byte not applicable -> 0x0807.
     */
    uint16_t sig_algo;
    opssl_pkey_type_t ktype = opssl_pkey_type(hs->sign_key);
    if (ktype == OPSSL_PKEY_RSA)
        sig_algo = OPSSL_SIG_RSA_PSS_SHA256;
    else if (ktype == OPSSL_PKEY_ED25519)
        sig_algo = OPSSL_SIG_ED25519;
    else if (hs->group == OPSSL_GROUP_SECP384R1)
        sig_algo = OPSSL_SIG_ECDSA_SECP384R1;
    else
        sig_algo = OPSSL_SIG_ECDSA_SECP256R1;

    /* Add signature to message */
    if (!opssl_cbb_add_u16(&ske, sig_algo) ||
        !opssl_cbb_add_u16(&ske, sig_len) ||
        !opssl_cbb_add_bytes(&ske, signature, sig_len))
        return 0;

    return opssl_cbb_flush(&ske);
}

/*
 * TLS 1.2 server handshake state machine.
 */
int
opssl_tls12_server_handshake(void *hs_opaque, uint8_t *buf, size_t buf_len,
                             size_t *consumed, uint8_t *out, size_t *out_len,
                             size_t out_cap)
{
    tls12_hs_t *hs = (tls12_hs_t *)hs_opaque;
    opssl_cbs_t cbs;
    opssl_cbb_t cbb;
    uint8_t msg_type;
    uint32_t msg_len;
    opssl_cbs_t msg_data;
    int ret = OPSSL_WANT_READ;

    *consumed = 0;
    *out_len = 0;

    if (!opssl_cbb_init(&cbb, 1024))
        return OPSSL_ERROR;

    opssl_cbs_init(&cbs, buf, buf_len);

    switch (hs->state) {
        case OPSSL_HS_IDLE:
            /* Wait for ClientHello */
            if (!opssl_cbs_get_u8(&cbs, &msg_type) ||
                !opssl_cbs_get_u24(&cbs, &msg_len) ||
                !opssl_cbs_get_bytes(&cbs, &msg_data, msg_len)) {
                ret = OPSSL_WANT_READ;
                break;
            }

            if (msg_type != TLS_MT_CLIENT_HELLO) {
                OPSSL_ERR(OPSSL_ERR_TLS, OPSSL_TLS_ERR_UNEXPECTED_MSG);
                ret = OPSSL_ERROR;
                break;
            }

            if (!parse_client_hello(hs, &msg_data)) {                ret = OPSSL_ERROR;
                break;
            }
            /* Initialize transcript hash AFTER cipher suite selection determines PRF */
            if (hs->prf_hash == OPSSL_HMAC_SHA256)
                opssl_sha256_init(&hs->verify_sha256);
            else
                opssl_sha384_init(&hs->verify_sha384);

            /* Hash ClientHello */
            tls12_update_transcript(hs, buf, 4 + msg_len);

            /* Generate server random */
            opssl_random_bytes(hs->server_random, 32);

            /* RFC 8446 §4.1.3: embed downgrade sentinel when TLS 1.3 capable */
            if (hs->tls13_capable)
                memcpy(hs->server_random + 24, tls13_downgrade_sentinel, 8);

            *consumed = 4 + msg_len;
            hs->state = OPSSL_HS_SERVER_HELLO;
            ret = OPSSL_WANT_WRITE;

            /* Build response: ServerHello + Certificate + ServerKeyExchange + ServerHelloDone */
            {
                size_t out_start = opssl_cbb_len(&cbb);
                int r1 = opssl_cbb_add_u8(&cbb, TLS_MT_SERVER_HELLO);
                int r2 = r1 ? build_server_hello(hs, &cbb) : 0;
                int r3 = r2 ? opssl_cbb_add_u8(&cbb, TLS_MT_CERTIFICATE) : 0;
                int r5 = r3 ? build_server_certificate(hs, &cbb) : 0;
                int r6 = r5 ? opssl_cbb_add_u8(&cbb, TLS_MT_SERVER_KEY_EXCHANGE) : 0;
                int r7 = r6 ? build_server_key_exchange(hs, &cbb) : 0;
                int r8 = r7 ? opssl_cbb_add_u8(&cbb, TLS_MT_SERVER_HELLO_DONE) : 0;
                int r9 = r8 ? opssl_cbb_add_u24(&cbb, 0) : 0;
                if (!r9) {                    ret = OPSSL_ERROR;
                    break;
                }                /* Hash all server messages into transcript */
                tls12_update_transcript(hs, opssl_cbb_data(&cbb) + out_start,
                                        opssl_cbb_len(&cbb) - out_start);
            }
            break;

        case OPSSL_HS_SERVER_HELLO:
            /* Wait for ClientKeyExchange */            if (!opssl_cbs_get_u8(&cbs, &msg_type) ||
                !opssl_cbs_get_u24(&cbs, &msg_len) ||
                !opssl_cbs_get_bytes(&cbs, &msg_data, msg_len)) {
                ret = OPSSL_WANT_READ;
                break;
            }            if (msg_type != TLS_MT_CLIENT_KEY_EXCHANGE) {                OPSSL_ERR(OPSSL_ERR_TLS, OPSSL_TLS_ERR_UNEXPECTED_MSG);
                ret = OPSSL_ERROR;
                break;
            }

            /* Hash ClientKeyExchange into transcript */
            tls12_update_transcript(hs, buf, 4 + msg_len);

            /* Parse client ECDH public key and derive premaster */
            uint8_t point_len;
            uint8_t client_pub[133];
            if (!opssl_cbs_get_u8(&msg_data, &point_len) ||
                point_len > sizeof(client_pub) ||
                !opssl_cbs_copy_bytes(&msg_data, client_pub, point_len)) {
                OPSSL_ERR(OPSSL_ERR_TLS, OPSSL_TLS_ERR_DECODE_ERROR);
                ret = OPSSL_ERROR;
                break;
            }

            /* Derive shared secret based on curve */
            if (hs->group == OPSSL_GROUP_X25519) {
                if (point_len != 32) {
                    OPSSL_ERR(OPSSL_ERR_TLS, OPSSL_TLS_ERR_DECODE_ERROR);
                    ret = OPSSL_ERROR;
                    break;
                }
                if (!opssl_x25519_derive(hs->premaster_secret, hs->ecdh_priv, client_pub)) {
                    OPSSL_ERR(OPSSL_ERR_CRYPTO, 0);
                    ret = OPSSL_ERROR;
                    break;
                }
                hs->premaster_len = 32;
            } else if (hs->group == OPSSL_GROUP_SECP256R1 || hs->group == OPSSL_GROUP_SECP384R1) {
                /* Use the stored ECDH context */
                opssl_ecdh_ctx_t *ecdh_ctx = (opssl_ecdh_ctx_t *)hs->ecdh_ctx;
                if (!ecdh_ctx) {
                    OPSSL_ERR(OPSSL_ERR_TLS, OPSSL_TLS_ERR_INTERNAL_ERROR);
                    ret = OPSSL_ERROR;
                    break;
                }

                size_t shared_len = sizeof(hs->premaster_secret);
                if (!opssl_ecdh_derive(ecdh_ctx, client_pub, point_len,
                                       hs->premaster_secret, &shared_len)) {
                    OPSSL_ERR(OPSSL_ERR_CRYPTO, 0);
                    ret = OPSSL_ERROR;
                    break;
                }
                hs->premaster_len = shared_len;

                /* Clean up context as we're done with it */
                opssl_ecdh_free(ecdh_ctx);
                hs->ecdh_ctx = NULL;
            } else {
                OPSSL_ERR(OPSSL_ERR_TLS, OPSSL_TLS_ERR_INSUFFICIENT_SECURITY);
                ret = OPSSL_ERROR;
                break;
            }

            /* Derive master secret */
            if (!derive_master_secret(hs)) {
                ret = OPSSL_ERROR;
                break;
            }
            *consumed = 4 + msg_len;
            hs->state = OPSSL_HS_FINISHED;
            ret = OPSSL_WANT_READ;  /* Wait for ChangeCipherSpec + Finished */
            break;

        case OPSSL_HS_FINISHED: {
            /* Receive client Finished (CCS already consumed by dispatcher) */            if (!opssl_cbs_get_u8(&cbs, &msg_type) ||
                !opssl_cbs_get_u24(&cbs, &msg_len)) {                ret = OPSSL_WANT_READ;
                break;
            }            if (msg_type != TLS_MT_FINISHED || msg_len != 12) {                OPSSL_ERR(OPSSL_ERR_TLS, OPSSL_TLS_ERR_UNEXPECTED_MSG);
                ret = OPSSL_ERROR;
                break;
            }

            opssl_cbs_t finished_data;
            if (!opssl_cbs_get_bytes(&cbs, &finished_data, 12)) {
                ret = OPSSL_WANT_READ;
                break;
            }

            uint8_t expected_verify[12];
            if (!generate_finished(hs, true, expected_verify)) {
                ret = OPSSL_ERROR;
                break;
            }
            if (opssl_ct_eq(opssl_cbs_data(&finished_data), expected_verify, 12) != 1) {
                OPSSL_ERR(OPSSL_ERR_TLS, OPSSL_TLS_ERR_DECODE_ERROR);
                ret = OPSSL_ERROR;
                break;
            }
            /* Hash client Finished into transcript */
            tls12_update_transcript(hs, buf, 4 + 12);

            *consumed = 4 + 12;

            /* Build server Finished */
            uint8_t finished_verify[12];
            if (!generate_finished(hs, false, finished_verify) ||
                !opssl_cbb_add_u8(&cbb, TLS_MT_FINISHED) ||
                !opssl_cbb_add_u24(&cbb, 12) ||
                !opssl_cbb_add_bytes(&cbb, finished_verify, 12)) {
                ret = OPSSL_ERROR;
                break;
            }

            hs->state = OPSSL_HS_COMPLETE;
            ret = OPSSL_OK;
            break;
        }

        default:
            OPSSL_ERR(OPSSL_ERR_TLS, OPSSL_TLS_ERR_INTERNAL_ERROR);
            ret = OPSSL_ERROR;
    }

    /* Finalize output */
    if (ret == OPSSL_WANT_WRITE || ret == OPSSL_OK) {
        uint8_t *output;
        size_t output_len;

        if (!opssl_cbb_finish(&cbb, &output, &output_len)) {
            opssl_cbb_cleanup(&cbb);
            return OPSSL_ERROR;
        }

        if (output_len <= out_cap) {
            memcpy(out, output, output_len);
            *out_len = output_len;
        } else {
            free(output);
            opssl_cbb_cleanup(&cbb);
            return OPSSL_ERROR;
        }

        free(output);
    }

    opssl_cbb_cleanup(&cbb);
    return ret;
}

/*
 * TLS 1.2 client handshake state machine.
 * Mirror of server flow.
 */
int
opssl_tls12_client_handshake(void *hs_opaque, uint8_t *buf, size_t buf_len,
                             size_t *consumed, uint8_t *out, size_t *out_len,
                             size_t out_cap)
{
    tls12_hs_t *hs = (tls12_hs_t *)hs_opaque;
    opssl_cbb_t cbb;
    int ret = OPSSL_WANT_WRITE;

    *consumed = 0;
    *out_len = 0;

    if (!opssl_cbb_init(&cbb, 1024))
        return OPSSL_ERROR;

    switch (hs->state) {
        case OPSSL_HS_IDLE:
            /* Send ClientHello */
            hs->cipher = OPSSL_TLS_ECDHE_RSA_AES_128_GCM;
            hs->prf_hash = OPSSL_HMAC_SHA256;
            hs->extended_master_secret = true;

            opssl_random_bytes(hs->client_random, 32);

            /* Initialize transcript hash */
            opssl_sha256_init(&hs->verify_sha256);

            /* Build ClientHello */
            {
                size_t out_start = opssl_cbb_len(&cbb);
                opssl_cbb_t ch_body, extensions, ext;

                if (!opssl_cbb_add_u8(&cbb, TLS_MT_CLIENT_HELLO) ||
                    !opssl_cbb_add_u24_length_prefixed(&cbb, &ch_body) ||
                    !opssl_cbb_add_u16(&ch_body, OPSSL_TLS_1_2) ||
                    !opssl_cbb_add_bytes(&ch_body, hs->client_random, 32) ||
                    !opssl_cbb_add_u8(&ch_body, 0) ||  /* no session ID */
                    !opssl_cbb_add_u16(&ch_body, 8) ||  /* cipher suites length: 4 ciphers × 2 bytes */
                    !opssl_cbb_add_u16(&ch_body, OPSSL_TLS_ECDHE_ECDSA_AES_128_GCM) ||
                    !opssl_cbb_add_u16(&ch_body, OPSSL_TLS_ECDHE_RSA_AES_128_GCM) ||
                    !opssl_cbb_add_u16(&ch_body, OPSSL_TLS_ECDHE_ECDSA_AES_256_GCM) ||
                    !opssl_cbb_add_u16(&ch_body, OPSSL_TLS_ECDHE_RSA_AES_256_GCM) ||
                    !opssl_cbb_add_u8(&ch_body, 1) ||   /* compression methods length */
                    !opssl_cbb_add_u8(&ch_body, 0))    /* null compression */
                    return OPSSL_ERROR;

                /* Add extensions */
                if (!opssl_cbb_add_u16_length_prefixed(&ch_body, &extensions) ||
                    !opssl_cbb_add_u16(&extensions, TLS_EXT_EXTENDED_MASTER_SECRET) ||
                    !opssl_cbb_add_u16_length_prefixed(&extensions, &ext) ||
                    !opssl_cbb_flush(&ext)) {
                    ret = OPSSL_ERROR;
                    break;
                }

                /* SNI extension if hostname is set */
                if (hs->sni[0]) {
                    size_t sni_len = strlen(hs->sni);
                    opssl_cbb_t sni_ext, sni_list, sni_entry;
                    if (!opssl_cbb_add_u16(&extensions, TLS_EXT_SERVER_NAME) ||
                        !opssl_cbb_add_u16_length_prefixed(&extensions, &sni_ext) ||
                        !opssl_cbb_add_u16_length_prefixed(&sni_ext, &sni_list) ||
                        !opssl_cbb_add_u8(&sni_list, 0) ||  /* host_name type */
                        !opssl_cbb_add_u16_length_prefixed(&sni_list, &sni_entry) ||
                        !opssl_cbb_add_bytes(&sni_entry, (const uint8_t *)hs->sni, sni_len) ||
                        !opssl_cbb_flush(&sni_list)) {
                        ret = OPSSL_ERROR;
                        break;
                    }
                }

                /* ALPN extension (RFC 7301) */
                if (hs->alpn_offer_len > 0) {
                    opssl_cbb_t alpn_ext, alpn_list;
                    if (!opssl_cbb_add_u16(&extensions, TLS_EXT_ALPN) ||
                        !opssl_cbb_add_u16_length_prefixed(&extensions, &alpn_ext) ||
                        !opssl_cbb_add_u16_length_prefixed(&alpn_ext, &alpn_list) ||
                        !opssl_cbb_add_bytes(&alpn_list, (const uint8_t *)hs->alpn_offer,
                                            hs->alpn_offer_len)) {
                        ret = OPSSL_ERROR;
                        break;
                    }
                }

                /*
                 * supported_groups extension (RFC 4492 / RFC 8422).
                 * Advertise P-256, P-384, and X25519 to allow the server to
                 * select any of the three groups.  The order signals preference.
                 */
                {
                    opssl_cbb_t sg_ext, sg_list;
                    if (!opssl_cbb_add_u16(&extensions, TLS_EXT_SUPPORTED_GROUPS) ||
                        !opssl_cbb_add_u16_length_prefixed(&extensions, &sg_ext) ||
                        !opssl_cbb_add_u16_length_prefixed(&sg_ext, &sg_list) ||
                        !opssl_cbb_add_u16(&sg_list, OPSSL_GROUP_SECP256R1) ||
                        !opssl_cbb_add_u16(&sg_list, OPSSL_GROUP_SECP384R1) ||
                        !opssl_cbb_add_u16(&sg_list, OPSSL_GROUP_X25519) ||
                        !opssl_cbb_flush(&sg_ext)) {
                        ret = OPSSL_ERROR;
                        break;
                    }
                }

                /*
                 * signature_algorithms extension (RFC 5246 ss7.4.1.4.1).
                 * Required for TLS 1.2 ECDHE; tells the server which
                 * SignatureAndHashAlgorithm pairs we accept on the SKE.
                 */
                {
                    opssl_cbb_t sa_ext, sa_list;
                    if (!opssl_cbb_add_u16(&extensions, TLS_EXT_SIGNATURE_ALGORITHMS) ||
                        !opssl_cbb_add_u16_length_prefixed(&extensions, &sa_ext) ||
                        !opssl_cbb_add_u16_length_prefixed(&sa_ext, &sa_list) ||
                        !opssl_cbb_add_u16(&sa_list, OPSSL_SIG_ECDSA_SECP256R1) ||
                        !opssl_cbb_add_u16(&sa_list, OPSSL_SIG_ECDSA_SECP384R1) ||
                        !opssl_cbb_add_u16(&sa_list, OPSSL_SIG_RSA_PSS_SHA256) ||
                        !opssl_cbb_add_u16(&sa_list, OPSSL_SIG_ED25519) ||
                        !opssl_cbb_flush(&sa_ext)) {
                        ret = OPSSL_ERROR;
                        break;
                    }
                }

                if (!opssl_cbb_flush(&ch_body)) {
                    ret = OPSSL_ERROR;
                    break;
                }

                /* Hash ClientHello into transcript */
                tls12_update_transcript(hs, opssl_cbb_data(&cbb) + out_start,
                                        opssl_cbb_len(&cbb) - out_start);
            }

            hs->state = OPSSL_HS_CLIENT_HELLO;
            ret = OPSSL_WANT_READ;
            break;

        case OPSSL_HS_CLIENT_HELLO: {
            /* Process server messages: ServerHello + Certificate + ServerKeyExchange + ServerHelloDone */            opssl_cbs_t cbs;
            opssl_cbs_init(&cbs, buf, buf_len);
            size_t total_consumed = 0;
            bool got_server_hello_done = false;

            while (!opssl_cbs_is_empty(&cbs) && !got_server_hello_done) {
                uint8_t msg_type;
                uint32_t msg_len;
                opssl_cbs_t msg_data;

                if (!opssl_cbs_get_u8(&cbs, &msg_type) ||
                    !opssl_cbs_get_u24(&cbs, &msg_len) ||
                    !opssl_cbs_get_bytes(&cbs, &msg_data, msg_len)) {
                    ret = OPSSL_WANT_READ;
                    break;
                }

                total_consumed += 4 + msg_len;

                /* Hash each server message into transcript */
                tls12_update_transcript(hs, buf + total_consumed - (4 + msg_len), 4 + msg_len);

                switch (msg_type) {
                case TLS_MT_SERVER_HELLO: {
                    uint16_t version;
                    opssl_cbs_t extensions;
                    if (!opssl_cbs_get_u16(&msg_data, &version) ||
                        version != OPSSL_TLS_1_2 ||
                        !opssl_cbs_copy_bytes(&msg_data, hs->server_random, 32)) {
                        ret = OPSSL_ERROR;
                        goto client_done;
                    }
                    /* Skip session ID */
                    uint8_t sid_len;
                    opssl_cbs_t sid;
                    if (!opssl_cbs_get_u8(&msg_data, &sid_len) ||
                        !opssl_cbs_get_bytes(&msg_data, &sid, sid_len))  {
                        ret = OPSSL_ERROR;
                        goto client_done;
                    }
                    /* Cipher suite + compression */
                    uint16_t server_cipher;
                    uint8_t compression;
                    if (!opssl_cbs_get_u16(&msg_data, &server_cipher) ||
                        !opssl_cbs_get_u8(&msg_data, &compression)) {
                        ret = OPSSL_ERROR;
                        goto client_done;
                    }
                    hs->cipher = server_cipher;

                    /* Set PRF hash based on cipher suite */
                    switch (server_cipher) {
                        case OPSSL_TLS_ECDHE_RSA_AES_128_GCM:
                        case OPSSL_TLS_ECDHE_ECDSA_AES_128_GCM:
                            hs->prf_hash = OPSSL_HMAC_SHA256;
                            break;
                        case OPSSL_TLS_ECDHE_RSA_AES_256_GCM:
                        case OPSSL_TLS_ECDHE_ECDSA_AES_256_GCM:
                            hs->prf_hash = OPSSL_HMAC_SHA384;
                            break;
                        default:
                            ret = OPSSL_ERROR;
                            goto client_done;
                    }

                    /* Parse extensions if present */
                    if (!opssl_cbs_is_empty(&msg_data)) {
                        if (!opssl_cbs_get_u16_length_prefixed(&msg_data, &extensions)) {
                            ret = OPSSL_ERROR;
                            goto client_done;
                        }
                        while (!opssl_cbs_is_empty(&extensions)) {
                            uint16_t ext_type;
                            opssl_cbs_t ext_data;
                            if (!opssl_cbs_get_u16(&extensions, &ext_type) ||
                                !opssl_cbs_get_u16_length_prefixed(&extensions, &ext_data)) {
                                ret = OPSSL_ERROR;
                                goto client_done;
                            }
                            if (ext_type == TLS_EXT_EXTENDED_MASTER_SECRET) {
                                hs->extended_master_secret = true;
                            } else if (ext_type == TLS_EXT_ALPN) {
                                opssl_cbs_t alpn_list, proto;
                                if (opssl_cbs_get_u16_length_prefixed(&ext_data, &alpn_list) &&
                                    opssl_cbs_get_u8_length_prefixed(&alpn_list, &proto)) {
                                    size_t plen = opssl_cbs_len(&proto);
                                    if (plen < sizeof(hs->alpn)) {
                                        memcpy(hs->alpn, opssl_cbs_data(&proto), plen);
                                        hs->alpn[plen] = '\0';
                                        hs->alpn_len = plen;
                                    }
                                }
                            }
                        }
                    }

                    /* RFC 8446 §4.1.3: detect downgrade attack via sentinel */
                    {
                        static const uint8_t dg12[8] = {0x44,0x4F,0x57,0x4E,0x47,0x52,0x44,0x01};
                        static const uint8_t dg11[8] = {0x44,0x4F,0x57,0x4E,0x47,0x52,0x44,0x00};
                        if (memcmp(hs->server_random + 24, dg12, 8) == 0 ||
                            memcmp(hs->server_random + 24, dg11, 8) == 0) {
                            ret = OPSSL_ERROR;
                            goto client_done;
                        }
                    }
                    break;
                }
                case TLS_MT_CERTIFICATE: {
                    /* Parse certificate chain: u24 total_len, then (u24 cert_len + cert)* */
                    uint32_t chain_len;
                    if (!opssl_cbs_get_u24(&msg_data, &chain_len)) {
                        ret = OPSSL_ERROR;
                        goto client_done;
                    }
                    opssl_cbs_t chain_data;
                    if (!opssl_cbs_get_bytes(&msg_data, &chain_data, chain_len))
                        break;

                    /* Extract leaf certificate (first in chain) */
                    uint32_t cert_len;
                    if (opssl_cbs_get_u24(&chain_data, &cert_len) &&
                        cert_len > 0 && cert_len <= opssl_cbs_len(&chain_data)) {
                        opssl_cbs_t cert_der;
                        if (opssl_cbs_get_bytes(&chain_data, &cert_der, cert_len)) {
                            hs->peer_cert_der = malloc(cert_len);
                            if (hs->peer_cert_der) {
                                memcpy(hs->peer_cert_der, opssl_cbs_data(&cert_der), cert_len);
                                hs->peer_cert_der_len = cert_len;
                            }
                        }
                    }
                    break;
                }
                case TLS_MT_SERVER_KEY_EXCHANGE: {
                    /* Parse ECDHE params: curve_type(1) + named_curve(2) + point_len(1) + point */
                    uint8_t curve_type, point_len;
                    uint16_t named_curve;
                    if (!opssl_cbs_get_u8(&msg_data, &curve_type) ||
                        !opssl_cbs_get_u16(&msg_data, &named_curve) ||
                        !opssl_cbs_get_u8(&msg_data, &point_len)) {
                        ret = OPSSL_ERROR;
                        goto client_done;
                    }
                    hs->group = named_curve;
                    if (point_len > sizeof(hs->ecdh_pub)) {
                        ret = OPSSL_ERROR;
                        goto client_done;
                    }
                    uint8_t server_pub[133];
                    if (!opssl_cbs_copy_bytes(&msg_data, server_pub, point_len)) {
                        ret = OPSSL_ERROR;
                        goto client_done;
                    }
                    memcpy(hs->ecdh_pub, server_pub, point_len);
                    hs->ecdh_pub_len = point_len;
                    break;
                }
                case TLS_MT_SERVER_HELLO_DONE:
                    got_server_hello_done = true;
                    break;
                default:
                    break;
                }
            }

            if (!got_server_hello_done) {
                ret = OPSSL_WANT_READ;
                break;
            }

            *consumed = total_consumed;

            /* Generate ephemeral ECDHE key and compute premaster secret */
            if (hs->group == OPSSL_GROUP_X25519) {
                uint8_t server_pub[32];
                memcpy(server_pub, hs->ecdh_pub, 32);
                if (!opssl_x25519_keygen(hs->ecdh_priv, hs->ecdh_pub)) {
                    ret = OPSSL_ERROR;
                    break;
                }
                if (!opssl_x25519_derive(hs->premaster_secret, hs->ecdh_priv, server_pub)) {
                    ret = OPSSL_ERROR;
                    break;
                }
                hs->premaster_len = 32;
            } else if (hs->group == OPSSL_GROUP_SECP256R1) {
                /* Store server's public key */
                uint8_t server_pub[133];
                size_t server_pub_len = hs->ecdh_pub_len;
                memcpy(server_pub, hs->ecdh_pub, server_pub_len);

                /* Generate client ECDH key pair */
                opssl_ecdh_ctx_t *ecdh_ctx = opssl_ecdh_new(OPSSL_CURVE_P256);
                if (!ecdh_ctx || !opssl_ecdh_keygen(ecdh_ctx)) {
                    if (ecdh_ctx) opssl_ecdh_free(ecdh_ctx);
                    ret = OPSSL_ERROR;
                    break;
                }

                /* Get our public key for transmission */
                size_t pub_len = sizeof(hs->ecdh_pub);
                if (!opssl_ecdh_get_public(ecdh_ctx, hs->ecdh_pub, &pub_len)) {
                    opssl_ecdh_free(ecdh_ctx);
                    ret = OPSSL_ERROR;
                    break;
                }
                hs->ecdh_pub_len = pub_len;

                /* Derive shared secret */
                size_t shared_len = sizeof(hs->premaster_secret);
                if (!opssl_ecdh_derive(ecdh_ctx, server_pub, server_pub_len,
                                       hs->premaster_secret, &shared_len)) {
                    opssl_ecdh_free(ecdh_ctx);
                    ret = OPSSL_ERROR;
                    break;
                }
                hs->premaster_len = shared_len;
                opssl_ecdh_free(ecdh_ctx);
            } else if (hs->group == OPSSL_GROUP_SECP384R1) {
                /* Store server's public key */
                uint8_t server_pub[133];
                size_t server_pub_len = hs->ecdh_pub_len;
                memcpy(server_pub, hs->ecdh_pub, server_pub_len);

                /* Generate client ECDH key pair */
                opssl_ecdh_ctx_t *ecdh_ctx = opssl_ecdh_new(OPSSL_CURVE_P384);
                if (!ecdh_ctx || !opssl_ecdh_keygen(ecdh_ctx)) {
                    if (ecdh_ctx) opssl_ecdh_free(ecdh_ctx);
                    ret = OPSSL_ERROR;
                    break;
                }

                /* Get our public key for transmission */
                size_t pub_len = sizeof(hs->ecdh_pub);
                if (!opssl_ecdh_get_public(ecdh_ctx, hs->ecdh_pub, &pub_len)) {
                    opssl_ecdh_free(ecdh_ctx);
                    ret = OPSSL_ERROR;
                    break;
                }
                hs->ecdh_pub_len = pub_len;

                /* Derive shared secret */
                size_t shared_len = sizeof(hs->premaster_secret);
                if (!opssl_ecdh_derive(ecdh_ctx, server_pub, server_pub_len,
                                       hs->premaster_secret, &shared_len)) {
                    opssl_ecdh_free(ecdh_ctx);
                    ret = OPSSL_ERROR;
                    break;
                }
                hs->premaster_len = shared_len;
                opssl_ecdh_free(ecdh_ctx);
            } else {
                OPSSL_ERR(OPSSL_ERR_TLS, OPSSL_TLS_ERR_INSUFFICIENT_SECURITY);
                ret = OPSSL_ERROR;
                break;
            }

            /* Build CKE first, hash it, then derive master (EMS needs CKE in transcript) */
            {
                size_t cke_start = opssl_cbb_len(&cbb);
                opssl_cbb_t cke_body;
                if (!opssl_cbb_add_u8(&cbb, TLS_MT_CLIENT_KEY_EXCHANGE) ||
                    !opssl_cbb_add_u24_length_prefixed(&cbb, &cke_body) ||
                    !opssl_cbb_add_u8(&cke_body, hs->ecdh_pub_len) ||
                    !opssl_cbb_add_bytes(&cke_body, hs->ecdh_pub, hs->ecdh_pub_len) ||
                    !opssl_cbb_flush(&cke_body)) {
                    ret = OPSSL_ERROR;
                    break;
                }

                tls12_update_transcript(hs, opssl_cbb_data(&cbb) + cke_start,
                                        opssl_cbb_len(&cbb) - cke_start);

                if (!derive_master_secret(hs)) {
                    ret = OPSSL_ERROR;
                    break;
                }
                size_t fin_start = opssl_cbb_len(&cbb);
                uint8_t finished_verify[12];
                if (!generate_finished(hs, true, finished_verify) ||
                    !opssl_cbb_add_u8(&cbb, TLS_MT_FINISHED) ||
                    !opssl_cbb_add_u24(&cbb, 12) ||
                    !opssl_cbb_add_bytes(&cbb, finished_verify, 12)) {
                    ret = OPSSL_ERROR;
                    break;
                }

                tls12_update_transcript(hs, opssl_cbb_data(&cbb) + fin_start,
                                        opssl_cbb_len(&cbb) - fin_start);
            }

            hs->state = OPSSL_HS_FINISHED;
            ret = OPSSL_WANT_READ;
            break;
        client_done:
            break;
        }

        case OPSSL_HS_FINISHED: {
            /* Receive server Finished (CCS consumed by dispatcher) */
            opssl_cbs_t fin_cbs;
            opssl_cbs_init(&fin_cbs, buf, buf_len);

            uint8_t fin_type;
            uint32_t fin_len;
            if (!opssl_cbs_get_u8(&fin_cbs, &fin_type) ||
                !opssl_cbs_get_u24(&fin_cbs, &fin_len)) {
                ret = OPSSL_WANT_READ;
                break;
            }

            if (fin_type != TLS_MT_FINISHED || fin_len != 12) {
                OPSSL_ERR(OPSSL_ERR_TLS, OPSSL_TLS_ERR_UNEXPECTED_MSG);
                ret = OPSSL_ERROR;
                break;
            }

            opssl_cbs_t fin_data;
            if (!opssl_cbs_get_bytes(&fin_cbs, &fin_data, 12)) {
                ret = OPSSL_WANT_READ;
                break;
            }

            /* Hash client Finished into transcript before computing server Finished */
            /* (client Finished was already output — hash it now for the server Finished check) */

            uint8_t expected_verify[12];
            if (!generate_finished(hs, false, expected_verify)) {
                ret = OPSSL_ERROR;
                break;
            }

            if (opssl_ct_eq(opssl_cbs_data(&fin_data), expected_verify, 12) != 1) {
                OPSSL_ERR(OPSSL_ERR_TLS, OPSSL_TLS_ERR_DECODE_ERROR);
                ret = OPSSL_ERROR;
                break;
            }

            *consumed = 4 + 12;
            hs->state = OPSSL_HS_COMPLETE;
            ret = OPSSL_OK;
            break;
        }

        default:
            OPSSL_ERR(OPSSL_ERR_TLS, OPSSL_TLS_ERR_INTERNAL_ERROR);
            ret = OPSSL_ERROR;
    }

    /* Finalize output */
    if (ret == OPSSL_WANT_READ) {
        uint8_t *output;
        size_t output_len;

        if (!opssl_cbb_finish(&cbb, &output, &output_len)) {
            opssl_cbb_cleanup(&cbb);
            return OPSSL_ERROR;
        }

        if (output_len <= out_cap) {
            memcpy(out, output, output_len);
            *out_len = output_len;
            ret = OPSSL_WANT_WRITE;
        } else {
            ret = OPSSL_ERROR;
        }

        free(output);
    }

    opssl_cbb_cleanup(&cbb);
    return ret;
}
/*
 * Extract key material from TLS 1.2 handshake state for cipher setup.
 * This is called by the handshake dispatcher after handshake completion.
 */
int opssl_tls12_extract_traffic_keys(void *hs_opaque,
                                     uint8_t *client_key, size_t *client_key_len,
                                     uint8_t *server_key, size_t *server_key_len,
                                     uint8_t *client_iv, size_t *client_iv_len,
                                     uint8_t *server_iv, size_t *server_iv_len,
                                     opssl_ciphersuite_t *cipher)
{
    tls12_hs_t *hs = (tls12_hs_t *)hs_opaque;

    if (!hs || hs->state != OPSSL_HS_COMPLETE) {
        return OPSSL_ERROR;
    }

    *cipher = hs->cipher;

    /* Expand key block if not already done */
    size_t key_len = 32;  /* AES-256 or ChaCha20 */
    size_t iv_len = 12;   /* GCM IV or ChaCha20 IV */

    /* Adjust key length based on cipher */
    switch (hs->cipher) {
        case OPSSL_TLS_ECDHE_RSA_AES_128_GCM:
        case OPSSL_TLS_ECDHE_ECDSA_AES_128_GCM:
            key_len = 16;
            break;
        case OPSSL_TLS_ECDHE_RSA_AES_256_GCM:
        case OPSSL_TLS_ECDHE_ECDSA_AES_256_GCM:
        case OPSSL_TLS_ECDHE_RSA_CHACHA20:
        case OPSSL_TLS_ECDHE_ECDSA_CHACHA20:
            key_len = 32;
            break;
        default:
            return OPSSL_ERROR;
    }

    size_t needed_len = 2 * (key_len + iv_len);  /* client + server keys + IVs */
    if (!expand_key_block(hs, needed_len)) {
        return OPSSL_ERROR;
    }

    /* Extract keys from key block: client_key + server_key + client_iv + server_iv */
    memcpy(client_key, hs->key_block, key_len);
    memcpy(server_key, hs->key_block + key_len, key_len);
    memcpy(client_iv, hs->key_block + 2 * key_len, iv_len);
    memcpy(server_iv, hs->key_block + 2 * key_len + iv_len, iv_len);

    *client_key_len = key_len;
    *server_key_len = key_len;
    *client_iv_len = iv_len;
    *server_iv_len = iv_len;

    return OPSSL_OK;
}

void
opssl_tls12_set_sign_key(void *hs_opaque, const opssl_pkey_t *key)
{
    tls12_hs_t *hs = (tls12_hs_t *)hs_opaque;
    if (hs)
        hs->sign_key = key;
}

void
opssl_tls12_set_cert_chain(void *hs_opaque, const opssl_x509_chain_t *chain)
{
    tls12_hs_t *hs = (tls12_hs_t *)hs_opaque;
    if (hs)
        hs->cert_chain = chain;
}

void
opssl_tls12_set_sni(void *hs_opaque, const char *hostname)
{
    tls12_hs_t *hs = (tls12_hs_t *)hs_opaque;
    if (hs && hostname) {
        size_t len = strlen(hostname);
        if (len >= sizeof(hs->sni)) len = sizeof(hs->sni) - 1;
        memcpy(hs->sni, hostname, len);
        hs->sni[len] = '\0';
    }
}

const char *
opssl_tls12_get_sni(void *hs_opaque)
{
    tls12_hs_t *hs = (tls12_hs_t *)hs_opaque;
    if (hs && hs->sni[0])
        return hs->sni;
    return NULL;
}

void
opssl_tls12_set_alpn_offer(void *hs_opaque, const char **protos, size_t count)
{
    tls12_hs_t *hs = (tls12_hs_t *)hs_opaque;
    if (!hs) return;
    size_t off = 0;
    for (size_t i = 0; i < count && off < sizeof(hs->alpn_offer) - 2; i++) {
        size_t plen = strlen(protos[i]);
        if (plen == 0 || off + 1 + plen > sizeof(hs->alpn_offer))
            break;
        hs->alpn_offer[off] = (char)plen;
        memcpy(hs->alpn_offer + off + 1, protos[i], plen);
        off += 1 + plen;
    }
    hs->alpn_offer_len = off;
}

void
opssl_tls12_set_alpn_supported(void *hs_opaque, const char **protos, size_t count)
{
    tls12_hs_t *hs = (tls12_hs_t *)hs_opaque;
    if (!hs) return;
    size_t off = 0;
    for (size_t i = 0; i < count && off < sizeof(hs->alpn_supported) - 2; i++) {
        size_t plen = strlen(protos[i]);
        if (plen == 0 || off + 1 + plen > sizeof(hs->alpn_supported))
            break;
        hs->alpn_supported[off] = (char)plen;
        memcpy(hs->alpn_supported + off + 1, protos[i], plen);
        off += 1 + plen;
    }
    hs->alpn_supported_len = off;
}

const char *
opssl_tls12_get_alpn(void *hs_opaque)
{
    tls12_hs_t *hs = (tls12_hs_t *)hs_opaque;
    if (hs && hs->alpn_len > 0)
        return hs->alpn;
    return NULL;
}

opssl_named_group_t
opssl_tls12_get_group(void *hs_opaque)
{
    tls12_hs_t *hs = (tls12_hs_t *)hs_opaque;
    return hs ? hs->group : (opssl_named_group_t)0;
}

/*
 * RFC 5705 keying material exporter for TLS 1.2.
 * PRF(master_secret, label, client_random + server_random + context_value)
 */
int
opssl_tls12_export_keying_material(void *hs_opaque,
                                   uint8_t *out, size_t out_len,
                                   const char *label,
                                   const uint8_t *context, size_t context_len)
{
    tls12_hs_t *hs = (tls12_hs_t *)hs_opaque;
    if (!hs || hs->state != OPSSL_HS_COMPLETE)
        return 0;

    size_t seed_len = 64 + (context ? 2 + context_len : 0);
    uint8_t seed[512];

    if (seed_len > sizeof(seed))
        return 0;

    memcpy(seed, hs->client_random, 32);
    memcpy(seed + 32, hs->server_random, 32);

    if (context && context_len > 0) {
        seed[64] = (context_len >> 8) & 0xff;
        seed[65] = context_len & 0xff;
        memcpy(seed + 66, context, context_len);
    }

    return tls12_prf(hs->prf_hash, hs->master_secret, 48,
                     label, seed, seed_len, out, out_len);
}

const uint8_t *
opssl_tls12_get_peer_cert(void *hs_opaque, size_t *out_len)
{
    tls12_hs_t *hs = (tls12_hs_t *)hs_opaque;
    if (!hs || !hs->peer_cert_der || hs->peer_cert_der_len == 0) {
        if (out_len) *out_len = 0;
        return NULL;
    }
    if (out_len) *out_len = hs->peer_cert_der_len;
    return hs->peer_cert_der;
}

void
opssl_tls12_free_peer_cert(void *hs_opaque)
{
    tls12_hs_t *hs = (tls12_hs_t *)hs_opaque;
    if (hs && hs->peer_cert_der) {
        free(hs->peer_cert_der);
        hs->peer_cert_der = NULL;
        hs->peer_cert_der_len = 0;
    }
}

void
opssl_tls12_set_tls13_capable(void *hs_opaque, bool capable)
{
    tls12_hs_t *hs = (tls12_hs_t *)hs_opaque;
    if (hs)
        hs->tls13_capable = capable;
}

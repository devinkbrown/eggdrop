/*
 * TLS 1.3 Handshake State Machine (RFC 8446)
 *
 * Implements the TLS 1.3 handshake for both client and server sides.
 * Non-blocking design - returns WANT_READ/WANT_WRITE when I/O would block.
 */

#include <opssl/platform.h>
#include <opssl/crypto.h>
#include <opssl/cbs.h>
#include <opssl/cert.h>
#include <opssl/err.h>
#include <opssl/types.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "../crypto/sha_internal.h"

/* External ASN.1 parsing functions */
extern int opssl_asn1_get_sequence(opssl_cbs_t *cbs, opssl_cbs_t *content);
extern int opssl_asn1_get_bit_string(opssl_cbs_t *cbs, opssl_cbs_t *content, uint8_t *unused_bits);

/* External RSA functions */
extern opssl_rsa_ctx_t *opssl_rsa_new(void);
extern int opssl_rsa_load_public_key(opssl_rsa_ctx_t *ctx, const uint8_t *der, size_t len);
extern int opssl_rsa_verify(opssl_rsa_ctx_t *ctx, opssl_rsa_padding_t pad,
                           opssl_hmac_algo_t hash, const uint8_t *digest, size_t digest_len,
                           const uint8_t *sig, size_t sig_len);
extern void opssl_rsa_free(opssl_rsa_ctx_t *ctx);

/* External key schedule functions */
extern int opssl_tls13_extract_secret(uint8_t *secret, size_t secret_len,
                                     const uint8_t *salt, size_t salt_len,
                                     const uint8_t *ikm, size_t ikm_len,
                                     opssl_hmac_algo_t hash_algo);
extern int opssl_tls13_derive_secret_compat(uint8_t *out, size_t out_len,
                                           const uint8_t *secret, size_t secret_len,
                                           const char *label,
                                           const uint8_t *context, size_t context_len,
                                           opssl_hmac_algo_t hash_algo);
extern int opssl_tls13_hkdf_expand_label(uint8_t *out, size_t out_len,
                                        const uint8_t *secret, size_t secret_len,
                                        const char *label,
                                        const uint8_t *context, size_t context_len,
                                        opssl_hmac_algo_t hash_algo);
/* Required crypto functions for Finished verification */
extern int opssl_hkdf_expand_label(opssl_hmac_algo_t algo, const uint8_t *secret, size_t secret_len,
                                  const char *label, const uint8_t *context, size_t context_len,
                                  uint8_t *out, size_t out_len);
extern int opssl_hmac(opssl_hmac_algo_t algo, const uint8_t *key, size_t key_len,
                     const void *data, size_t data_len, uint8_t *out, size_t *out_len);
extern int opssl_ct_eq(const void *a, const void *b, size_t len);

typedef struct {
    opssl_handshake_state_t state;
    opssl_tls_version_t version;
    opssl_ciphersuite_t cipher;
    opssl_named_group_t group;
    opssl_sig_algo_t sig_algo;

    /* Key exchange ephemeral keys */
    uint8_t ecdh_priv[48];       /* max P-384 scalar */
    uint8_t ecdh_pub[97];        /* max P-384 uncompressed point */
    size_t ecdh_pub_len;
    uint8_t peer_ecdh_pub[97];   /* max P-384 uncompressed point */
    size_t peer_ecdh_pub_len;
    uint8_t shared_secret[48];   /* max P-384 */
    size_t shared_secret_len;

    /* Transcript hash (running SHA-256 or SHA-384) */
    opssl_sha256_ctx_t transcript_sha256;
    opssl_sha512_ctx_t transcript_sha384;
    opssl_hmac_algo_t hash_algo;

    /* Secrets */
    uint8_t early_secret[48];
    uint8_t handshake_secret[48];
    uint8_t master_secret[48];
    uint8_t client_hs_traffic[48];
    uint8_t server_hs_traffic[48];
    uint8_t client_ap_traffic[48];
    uint8_t server_ap_traffic[48];
    size_t hash_len;

    /* Random values */
    uint8_t client_random[32];
    uint8_t server_random[32];

    /* Legacy session ID (echoed in ServerHello per RFC 8446 §4.1.3) */
    uint8_t session_id[32];
    size_t session_id_len;

    /* Certificate data */
    uint8_t *peer_cert;
    size_t peer_cert_len;
    const opssl_pkey_t *sign_key;
    const opssl_x509_chain_t *cert_chain;

    /* PSK resumption */
    uint8_t psk[48];
    size_t psk_len;
    uint8_t psk_ticket[1024];
    size_t psk_ticket_len;
    bool psk_offered;
    bool psk_accepted;

    /* Client certificate authentication */
    bool request_client_cert;
    const opssl_pkey_t *client_sign_key;
    const opssl_x509_chain_t *client_cert_chain;

    /* OCSP stapling (RFC 6066 §8) */
    uint8_t *ocsp_response;
    size_t ocsp_response_len;
    bool ocsp_requested;

    /* SCT - Certificate Transparency (RFC 6962) */
    uint8_t *sct_list;
    size_t sct_list_len;
    bool sct_requested;

    /* 0-RTT early data (RFC 8446 §4.2.10) */
    uint8_t *early_data_buf;
    size_t early_data_len;
    size_t early_data_max;
    bool early_data_accepted;
    bool early_data_offered;

    /* Flags */
    bool is_server;
    bool has_psk;
    bool has_early_data;
    bool peer_cert_verified;

    /* Resumption */
    uint8_t resumption_master_secret[48];

    char sni[256];
    char alpn[32];
    size_t alpn_len;
    char alpn_offer[128];
    size_t alpn_offer_len;
    char alpn_supported[128];
    size_t alpn_supported_len;
    char alpn_client[128];
    size_t alpn_client_len;
} tls13_hs_t;

/* TLS 1.3 message types */
#define TLS13_MSG_CLIENT_HELLO 1
#define TLS13_MSG_SERVER_HELLO 2
#define TLS13_MSG_NEW_SESSION_TICKET 4
#define TLS13_MSG_END_OF_EARLY_DATA 5
#define TLS13_MSG_ENCRYPTED_EXTENSIONS 8
#define TLS13_MSG_CERTIFICATE 11
#define TLS13_MSG_CERTIFICATE_REQUEST 13
#define TLS13_MSG_CERTIFICATE_VERIFY 15
#define TLS13_MSG_FINISHED 20
#define TLS13_MSG_KEY_UPDATE 24

/* Extension types */
#define EXT_SERVER_NAME 0
#define EXT_STATUS_REQUEST 5
#define EXT_SUPPORTED_GROUPS 10
#define EXT_SIGNATURE_ALGORITHMS 13
#define EXT_ALPN 16
#define EXT_SIGNED_CERT_TIMESTAMP 18
#define EXT_EARLY_DATA 42
#define EXT_SUPPORTED_VERSIONS 43
#define EXT_KEY_SHARE 51

/* Cipher suites */
#define TLS_AES_128_GCM_SHA256 0x1301
#define TLS_AES_256_GCM_SHA384 0x1302
#define TLS_CHACHA20_POLY1305_SHA256 0x1303

/* Named groups */
#define NAMED_GROUP_X25519 0x001D
#define NAMED_GROUP_SECP256R1 0x0017
#define NAMED_GROUP_SECP384R1 0x0018

static int cbb_finish_to_buf(CBB *cbb, uint8_t *out, size_t *out_len, size_t out_cap)
{
    uint8_t *built;
    size_t built_len;
    if (!CBB_finish(cbb, &built, &built_len)) {
        CBB_cleanup(cbb);
        return 0;
    }
    if (built_len > out_cap) {
        free(built);
        return 0;
    }
    memcpy(out, built, built_len);
    *out_len = built_len;
    free(built);
    return 1;
}

static void tls13_update_transcript(tls13_hs_t *hs, const uint8_t *data, size_t len)
{
    if (hs->hash_algo == OPSSL_HMAC_SHA256) {
        opssl_sha256_update(&hs->transcript_sha256, data, len);
    } else if (hs->hash_algo == OPSSL_HMAC_SHA384) {
        opssl_sha512_update(&hs->transcript_sha384, data, len);
    }
}

static int tls13_get_transcript_hash(tls13_hs_t *hs, uint8_t *out)
{
    if (hs->hash_algo == OPSSL_HMAC_SHA256) {
        opssl_sha256_ctx_t ctx = hs->transcript_sha256;
        opssl_sha256_final(&ctx, out);
        return 32;
    } else if (hs->hash_algo == OPSSL_HMAC_SHA384) {
        opssl_sha512_ctx_t ctx = hs->transcript_sha384;
        opssl_sha512_final(&ctx, out);
        return 48;
    }
    return -1;
}

static int tls13_select_cipher_suite(uint16_t *cipher, CBS *cipher_suites)
{
    /* Simple selection - prefer AES-128-GCM */
    while (CBS_len(cipher_suites) >= 2) {
        uint16_t suite;
        if (!CBS_get_u16(cipher_suites, &suite)) {
            return -1;
        }

        if (suite == TLS_AES_128_GCM_SHA256) {
            *cipher = suite;
            return 0;
        }
    }

    /* Fallback to first supported suite if found */
    CBS_init(cipher_suites, CBS_data(cipher_suites), CBS_len(cipher_suites));
    while (CBS_len(cipher_suites) >= 2) {
        uint16_t suite;
        if (!CBS_get_u16(cipher_suites, &suite)) {
            return -1;
        }

        if (suite == TLS_AES_256_GCM_SHA384 || suite == TLS_CHACHA20_POLY1305_SHA256) {
            *cipher = suite;
            return 0;
        }
    }

    return -1;
}

static int tls13_parse_key_share_extension(tls13_hs_t *hs, CBS *ext_data)
{
    CBS key_shares;
    if (!CBS_get_u16_length_prefixed(ext_data, &key_shares)) {
        return -1;
    }

    while (CBS_len(&key_shares) > 0) {
        uint16_t group;
        CBS key_exchange;

        if (!CBS_get_u16(&key_shares, &group) ||
            !CBS_get_u16_length_prefixed(&key_shares, &key_exchange)) {
            return -1;
        }

        size_t klen = CBS_len(&key_exchange);
        if (group == NAMED_GROUP_X25519 && klen == 32) {
            hs->group = group;
            memcpy(hs->peer_ecdh_pub, CBS_data(&key_exchange), 32);
            hs->peer_ecdh_pub_len = 32;
            return 0;
        } else if (group == NAMED_GROUP_SECP256R1 && klen == 65) {
            hs->group = group;
            memcpy(hs->peer_ecdh_pub, CBS_data(&key_exchange), 65);
            hs->peer_ecdh_pub_len = 65;
            return 0;
        } else if (group == NAMED_GROUP_SECP384R1 && klen == 97) {
            hs->group = group;
            memcpy(hs->peer_ecdh_pub, CBS_data(&key_exchange), 97);
            hs->peer_ecdh_pub_len = 97;
            return 0;
        }
    }

    return -1;
}


static int tls13_generate_key_pair_for_group(tls13_hs_t *hs, uint16_t group)
{
    if (group == NAMED_GROUP_X25519) {
        if (opssl_random_bytes(hs->ecdh_priv, 32) != 0)
            return -1;
        static const uint8_t basepoint[32] = {9};
        if (opssl_x25519_derive(hs->ecdh_pub, hs->ecdh_priv, basepoint) != 1)
            return -1;
        hs->ecdh_pub_len = 32;
        hs->group = group;
        return 0;
    } else if (group == NAMED_GROUP_SECP256R1 || group == NAMED_GROUP_SECP384R1) {
        opssl_curve_t curve = (group == NAMED_GROUP_SECP256R1) ?
                              OPSSL_CURVE_P256 : OPSSL_CURVE_P384;
        opssl_ecdh_ctx_t *ecdh = opssl_ecdh_new(curve);
        if (!ecdh) return -1;
        if (opssl_ecdh_keygen(ecdh) != 1) {
            opssl_ecdh_free(ecdh);
            return -1;
        }
        size_t pub_len = sizeof(hs->ecdh_pub);
        if (opssl_ecdh_get_public(ecdh, hs->ecdh_pub, &pub_len) != 1) {
            opssl_ecdh_free(ecdh);
            return -1;
        }
        hs->ecdh_pub_len = pub_len;
        /* Store private key material via ECDH derive later — keep ctx in priv */
        /* For simplicity, we re-derive: store raw private scalar */
        /* Actually: we need the ctx for derive. Store it as opaque bytes. */
        /* The ecdh_priv field is too small for a full ctx pointer, so we
         * compute the shared secret immediately in the server path.
         * For client: we generate before sending, then derive on SH receipt.
         * Store a serialized form: first 8 bytes = ctx pointer for later derive. */
        memcpy(hs->ecdh_priv, &ecdh, sizeof(ecdh));
        hs->group = group;
        return 0;
    }
    return -1;
}

static int tls13_compute_shared_secret(tls13_hs_t *hs, const uint8_t *peer_pub)
{
    if (hs->group == NAMED_GROUP_X25519) {
        if (opssl_x25519_derive(hs->shared_secret, hs->ecdh_priv, peer_pub) != 1)
            return -1;
        hs->shared_secret_len = 32;
        return 0;
    } else if (hs->group == NAMED_GROUP_SECP256R1 || hs->group == NAMED_GROUP_SECP384R1) {
        opssl_ecdh_ctx_t *ecdh;
        memcpy(&ecdh, hs->ecdh_priv, sizeof(ecdh));
        if (!ecdh) return -1;
        size_t ss_len = sizeof(hs->shared_secret);
        if (opssl_ecdh_derive(ecdh, peer_pub, hs->peer_ecdh_pub_len,
                              hs->shared_secret, &ss_len) != 1) {
            opssl_ecdh_free(ecdh);
            return -1;
        }
        hs->shared_secret_len = ss_len;
        opssl_ecdh_free(ecdh);
        memset(hs->ecdh_priv, 0, sizeof(hs->ecdh_priv));
        return 0;
    }
    return -1;
}

static int tls13_derive_handshake_secrets(tls13_hs_t *hs)
{
    uint8_t derived_secret[48];
    uint8_t transcript_hash[48];
    int hash_len = tls13_get_transcript_hash(hs, transcript_hash);

    if (hash_len < 0) {
        return -1;
    }

    /* early_secret = HKDF-Extract(0, PSK) or HKDF-Extract(0, 0) */
    uint8_t zero_salt[48] = {0};
    const uint8_t *ikm;
    size_t ikm_len;
    if (hs->has_psk && hs->psk_len > 0) {
        ikm = hs->psk;
        ikm_len = hs->psk_len;
    } else {
        ikm = zero_salt;
        ikm_len = hs->hash_len;
    }
    if (opssl_tls13_extract_secret(hs->early_secret, hs->hash_len,
                                  zero_salt, hs->hash_len,
                                  ikm, ikm_len, hs->hash_algo) != 1) {
        return -1;
    }

    /* derived_secret = Derive-Secret(early_secret, "derived", "") */
    if (opssl_tls13_derive_secret_compat(derived_secret, hs->hash_len,
                                 hs->early_secret, hs->hash_len,
                                 "derived", NULL, 0, hs->hash_algo) != 1) {
        return -1;
    }

    /* handshake_secret = HKDF-Extract(derived_secret, shared_secret) */
    if (opssl_tls13_extract_secret(hs->handshake_secret, hs->hash_len,
                                  derived_secret, hs->hash_len,
                                  hs->shared_secret, hs->shared_secret_len,
                                  hs->hash_algo) != 1) {
        return -1;
    }

    /* client_handshake_traffic_secret = Derive-Secret(handshake_secret, "c hs traffic", transcript) */
    if (opssl_tls13_derive_secret_compat(hs->client_hs_traffic, hs->hash_len,
                                 hs->handshake_secret, hs->hash_len,
                                 "c hs traffic", transcript_hash, hash_len,
                                 hs->hash_algo) != 1) {
        return -1;
    }

    /* server_handshake_traffic_secret = Derive-Secret(handshake_secret, "s hs traffic", transcript) */
    if (opssl_tls13_derive_secret_compat(hs->server_hs_traffic, hs->hash_len,
                                 hs->handshake_secret, hs->hash_len,
                                 "s hs traffic", transcript_hash, hash_len,
                                 hs->hash_algo) != 1) {
        return -1;
    }

    return 0;
}

static int tls13_derive_application_secrets(tls13_hs_t *hs)
{
    uint8_t derived_secret[48];
    uint8_t transcript_hash[48];

    /* derived_secret = Derive-Secret(handshake_secret, "derived", "") */
    if (opssl_tls13_derive_secret_compat(derived_secret, hs->hash_len,
                                 hs->handshake_secret, hs->hash_len,
                                 "derived", NULL, 0, hs->hash_algo) != 1)
        return -1;

    /* master_secret = HKDF-Extract(derived_secret, 0) — IKM is Hash.length zeros */
    uint8_t zero_ikm[48] = {0};
    if (opssl_tls13_extract_secret(hs->master_secret, hs->hash_len,
                                  derived_secret, hs->hash_len,
                                  zero_ikm, hs->hash_len, hs->hash_algo) != 1)
        return -1;

    int hash_len = tls13_get_transcript_hash(hs, transcript_hash);
    if (hash_len < 0)
        return -1;

    /* client_app_traffic = Derive-Secret(master_secret, "c ap traffic", transcript) */
    if (opssl_tls13_derive_secret_compat(hs->client_ap_traffic, hs->hash_len,
                                 hs->master_secret, hs->hash_len,
                                 "c ap traffic", transcript_hash, hash_len,
                                 hs->hash_algo) != 1)
        return -1;

    /* server_app_traffic = Derive-Secret(master_secret, "s ap traffic", transcript) */
    if (opssl_tls13_derive_secret_compat(hs->server_ap_traffic, hs->hash_len,
                                 hs->master_secret, hs->hash_len,
                                 "s ap traffic", transcript_hash, hash_len,
                                 hs->hash_algo) != 1)
        return -1;

    return 0;
}

static int tls13_parse_client_hello(tls13_hs_t *hs, CBS *msg)
{
    uint16_t version;
    CBS random, session_id, cipher_suites, compression, extensions;

    if (!CBS_get_u16(msg, &version) ||
        !CBS_get_bytes(msg, &random, 32) ||
        !CBS_get_u8_length_prefixed(msg, &session_id) ||
        !CBS_get_u16_length_prefixed(msg, &cipher_suites) ||
        !CBS_get_u8_length_prefixed(msg, &compression) ||
        !CBS_get_u16_length_prefixed(msg, &extensions)) {
        return -1;
    }

    memcpy(hs->client_random, CBS_data(&random), 32);

    hs->session_id_len = CBS_len(&session_id);
    if (hs->session_id_len > 32)
        return -1;
    if (hs->session_id_len > 0)
        memcpy(hs->session_id, CBS_data(&session_id), hs->session_id_len);

    /* Select cipher suite */
    uint16_t selected_cipher;
    if (tls13_select_cipher_suite(&selected_cipher, &cipher_suites) != 0) {
        return -1;
    }

    hs->cipher = selected_cipher;
    if (selected_cipher == TLS_AES_128_GCM_SHA256) {
        hs->hash_algo = OPSSL_HMAC_SHA256;
        hs->hash_len = 32;
    } else if (selected_cipher == TLS_AES_256_GCM_SHA384) {
        hs->hash_algo = OPSSL_HMAC_SHA384;
        hs->hash_len = 48;
    } else {
        hs->hash_algo = OPSSL_HMAC_SHA256;
        hs->hash_len = 32;
    }

    /* Initialize transcript hash */
    if (hs->hash_algo == OPSSL_HMAC_SHA256) {
        opssl_sha256_init(&hs->transcript_sha256);
    } else {
        opssl_sha512_init(&hs->transcript_sha384);
    }

    /* Parse extensions */
    while (CBS_len(&extensions) > 0) {
        uint16_t ext_type;
        CBS ext_data;

        if (!CBS_get_u16(&extensions, &ext_type) ||
            !CBS_get_u16_length_prefixed(&extensions, &ext_data)) {
            return -1;
        }

        if (ext_type == EXT_KEY_SHARE) {
            if (tls13_parse_key_share_extension(hs, &ext_data) != 0) {
                return -1;
            }
        } else if (ext_type == EXT_SERVER_NAME) {
            CBS sni_list;
            if (CBS_get_u16_length_prefixed(&ext_data, &sni_list)) {
                while (CBS_len(&sni_list) >= 3) {
                    uint8_t name_type;
                    CBS name;
                    if (!CBS_get_u8(&sni_list, &name_type) ||
                        !CBS_get_u16_length_prefixed(&sni_list, &name))
                        break;
                    if (name_type == 0) {
                        size_t nlen = CBS_len(&name);
                        if (nlen < sizeof(hs->sni)) {
                            memcpy(hs->sni, CBS_data(&name), nlen);
                            hs->sni[nlen] = '\0';
                        }
                        break;
                    }
                }
            }
        } else if (ext_type == EXT_ALPN) {
            CBS proto_list;
            if (CBS_get_u16_length_prefixed(&ext_data, &proto_list)) {
                size_t off = 0;
                while (CBS_len(&proto_list) > 0 && off < sizeof(hs->alpn_client) - 2) {
                    CBS proto;
                    if (!CBS_get_u8_length_prefixed(&proto_list, &proto))
                        break;
                    size_t plen = CBS_len(&proto);
                    if (plen == 0 || off + 1 + plen > sizeof(hs->alpn_client))
                        break;
                    hs->alpn_client[off] = (char)plen;
                    memcpy(hs->alpn_client + off + 1, CBS_data(&proto), plen);
                    off += 1 + plen;
                }
                hs->alpn_client_len = off;
            }
        } else if (ext_type == EXT_STATUS_REQUEST) {
            hs->ocsp_requested = true;
        } else if (ext_type == EXT_SIGNED_CERT_TIMESTAMP) {
            hs->sct_requested = true;
        } else if (ext_type == EXT_EARLY_DATA) {
            hs->early_data_offered = true;
        } else if (ext_type == 41) { /* pre_shared_key */
            CBS identities, binders_cbs;
            if (CBS_get_u16_length_prefixed(&ext_data, &identities) &&
                CBS_get_u16_length_prefixed(&ext_data, &binders_cbs)) {
                /* Parse first identity */
                CBS identity;
                uint32_t ticket_age;
                if (CBS_get_u16_length_prefixed(&identities, &identity) &&
                    CBS_get_u32(&identities, &ticket_age)) {
                    size_t id_len = CBS_len(&identity);
                    if (id_len > 0 && id_len <= sizeof(hs->psk_ticket)) {
                        memcpy(hs->psk_ticket, CBS_data(&identity), id_len);
                        hs->psk_ticket_len = id_len;
                        hs->psk_offered = true;
                    }
                }
            }
        }
    }

    return 0;
}

static int tls13_build_server_hello(tls13_hs_t *hs, CBB *out)
{
    CBB msg, extensions;

    /* Generate server random */
    if (opssl_random_bytes(hs->server_random, 32) != 0) {
        return -1;
    }

    /* Generate key pair matching client's offered group */
    if (tls13_generate_key_pair_for_group(hs, hs->group) != 0) {
        return -1;
    }

    /* Compute shared secret using peer's public key */
    if (tls13_compute_shared_secret(hs, hs->peer_ecdh_pub) != 0) {
        return -1;
    }

    if (!CBB_add_u8(out, TLS13_MSG_SERVER_HELLO) ||
        !CBB_add_u24_length_prefixed(out, &msg) ||
        !CBB_add_u16(&msg, 0x0303) ||
        !CBB_add_bytes(&msg, hs->server_random, 32) ||
        !CBB_add_u8(&msg, (uint8_t)hs->session_id_len) ||
        (hs->session_id_len > 0 &&
         !CBB_add_bytes(&msg, hs->session_id, hs->session_id_len)) ||
        !CBB_add_u16(&msg, hs->cipher) ||
        !CBB_add_u8(&msg, 0) ||
        !CBB_add_u16_length_prefixed(&msg, &extensions)) {
        return -1;
    }

    /* Add supported_versions extension (TLS 1.3) */
    CBB ext_data;
    if (!CBB_add_u16(&extensions, EXT_SUPPORTED_VERSIONS) ||
        !CBB_add_u16_length_prefixed(&extensions, &ext_data) ||
        !CBB_add_u16(&ext_data, 0x0304)) { /* TLS 1.3 */
        return -1;
    }

    /* Add key_share extension (ServerHello format: no outer length wrapper) */
    {
        CBB ks_ext, ks_entry;
        if (!CBB_add_u16(&extensions, EXT_KEY_SHARE) ||
            !CBB_add_u16_length_prefixed(&extensions, &ks_ext) ||
            !CBB_add_u16(&ks_ext, hs->group) ||
            !CBB_add_u16_length_prefixed(&ks_ext, &ks_entry) ||
            !CBB_add_bytes(&ks_entry, hs->ecdh_pub, hs->ecdh_pub_len)) {
            return -1;
        }
    }

    /* Add pre_shared_key extension if PSK accepted */
    if (hs->psk_accepted) {
        CBB psk_ext;
        if (!CBB_add_u16(&extensions, 41) ||  /* pre_shared_key */
            !CBB_add_u16_length_prefixed(&extensions, &psk_ext) ||
            !CBB_add_u16(&psk_ext, 0)) {  /* selected_identity = 0 */
            return -1;
        }
    }

    CBB_flush(out);
    return 0;
}

static int tls13_build_certificate_request(tls13_hs_t *hs, CBB *out)
{
    CBB msg, extensions, sa_ext, sa_list;

    if (!CBB_add_u8(out, TLS13_MSG_CERTIFICATE_REQUEST) ||
        !CBB_add_u24_length_prefixed(out, &msg) ||
        !CBB_add_u8(&msg, 0) ||  /* certificate_request_context (empty for handshake) */
        !CBB_add_u16_length_prefixed(&msg, &extensions))
        return -1;

    /* signature_algorithms extension (required) */
    if (!CBB_add_u16(&extensions, EXT_SIGNATURE_ALGORITHMS) ||
        !CBB_add_u16_length_prefixed(&extensions, &sa_ext) ||
        !CBB_add_u16_length_prefixed(&sa_ext, &sa_list) ||
        !CBB_add_u16(&sa_list, 0x0403) ||  /* ecdsa_secp256r1_sha256 */
        !CBB_add_u16(&sa_list, 0x0804) ||  /* rsa_pss_rsae_sha256 */
        !CBB_add_u16(&sa_list, 0x0805) ||  /* rsa_pss_rsae_sha384 */
        !CBB_add_u16(&sa_list, 0x0807))    /* ed25519 */
        return -1;

    CBB_flush(out);
    return 0;
}

static int tls13_build_certificate(tls13_hs_t *hs, CBB *out)
{
    if (!hs->cert_chain)
        return -1;

    size_t chain_count = opssl_x509_chain_count(hs->cert_chain);
    if (chain_count == 0)
        return -1;

    CBB msg, cert_list;

    if (!CBB_add_u8(out, TLS13_MSG_CERTIFICATE))
        return -1;

    if (!CBB_add_u24_length_prefixed(out, &msg))
        return -1;

    if (!CBB_add_u8(&msg, 0))
        return -1;

    if (!CBB_add_u24_length_prefixed(&msg, &cert_list))
        return -1;

    for (size_t i = 0; i < chain_count; i++) {
        opssl_x509_t *cert = opssl_x509_chain_get(hs->cert_chain, i);
        if (!cert)
            return -1;

        const uint8_t *der;
        size_t der_len;
        if (!opssl_x509_get_der(cert, &der, &der_len)) {
            opssl_x509_free(cert);
            return -1;
        }

        CBB cert_entry;
        if (!CBB_add_u24_length_prefixed(&cert_list, &cert_entry) ||
            !CBB_add_bytes(&cert_entry, der, der_len)) {
            opssl_x509_free(cert);
            return -1;
        }

        if (!CBB_add_u16(&cert_list, 0)) {
            opssl_x509_free(cert);
            return -1;
        }

        opssl_x509_free(cert);
    }

    CBB_flush(out);
    return 0;
}

static int tls13_build_certificate_verify(tls13_hs_t *hs, CBB *out,
                                           const uint8_t *transcript_hash, size_t hash_len)
{
    if (!hs->sign_key)
        return -1;

    uint8_t context[150];
    memset(context, 0x20, 64);
    memcpy(context + 64, "TLS 1.3, server CertificateVerify", 33);
    context[97] = 0;
    memcpy(context + 98, transcript_hash, hash_len);
    size_t context_len = 98 + hash_len;

    uint8_t sig[512];
    size_t sig_len = sizeof(sig);

    opssl_pkey_type_t ktype = opssl_pkey_type(hs->sign_key);

    if (ktype == OPSSL_PKEY_ED25519) {
        if (!opssl_pkey_sign(hs->sign_key, context, context_len, sig, &sig_len))
            return -1;
    } else {
        uint8_t digest[48];
        size_t dlen = (hash_len == 48) ? 48 : 32;
        if (dlen == 32)
            opssl_sha256(context, context_len, digest);
        else
            opssl_sha384(context, context_len, digest);
        if (!opssl_pkey_sign(hs->sign_key, digest, dlen, sig, &sig_len))
            return -1;
    }

    uint16_t sig_scheme;
    if (ktype == OPSSL_PKEY_ED25519)
        sig_scheme = 0x0807;
    else if (ktype == OPSSL_PKEY_EC)
        sig_scheme = 0x0403;
    else
        sig_scheme = 0x0804;

    CBB msg;
    if (!CBB_add_u8(out, TLS13_MSG_CERTIFICATE_VERIFY) ||
        !CBB_add_u24_length_prefixed(out, &msg) ||
        !CBB_add_u16(&msg, sig_scheme) ||
        !CBB_add_u16(&msg, (uint16_t)sig_len) ||
        !CBB_add_bytes(&msg, sig, sig_len))
        return -1;

    CBB_flush(out);
    return 0;
}

static int tls13_build_encrypted_extensions(tls13_hs_t *hs, CBB *out)
{
    CBB msg, extensions;

    if (!CBB_add_u8(out, TLS13_MSG_ENCRYPTED_EXTENSIONS) ||
        !CBB_add_u24_length_prefixed(out, &msg) ||
        !CBB_add_u16_length_prefixed(&msg, &extensions)) {
        return -1;
    }

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
                    goto alpn_selected;
                }
                coff += 1 + clen;
            }
            soff += 1 + slen;
        }
    }
alpn_selected:
    if (hs->alpn_len > 0) {
        CBB alpn_ext, alpn_list, alpn_entry;
        if (!CBB_add_u16(&extensions, EXT_ALPN) ||
            !CBB_add_u16_length_prefixed(&extensions, &alpn_ext) ||
            !CBB_add_u16_length_prefixed(&alpn_ext, &alpn_list) ||
            !CBB_add_u8_length_prefixed(&alpn_list, &alpn_entry) ||
            !CBB_add_bytes(&alpn_entry, (const uint8_t *)hs->alpn, hs->alpn_len))
            return -1;
    }

    /* OCSP stapling response (status_request extension) */
    if (hs->ocsp_requested && hs->ocsp_response && hs->ocsp_response_len > 0) {
        CBB ocsp_ext;
        if (!CBB_add_u16(&extensions, EXT_STATUS_REQUEST) ||
            !CBB_add_u16_length_prefixed(&extensions, &ocsp_ext) ||
            !CBB_add_u8(&ocsp_ext, 1) ||  /* status_type: ocsp (1) */
            !CBB_add_u24(&ocsp_ext, (uint32_t)hs->ocsp_response_len) ||
            !CBB_add_bytes(&ocsp_ext, hs->ocsp_response, hs->ocsp_response_len))
            return -1;
    }

    /* Certificate Transparency SCT list */
    if (hs->sct_requested && hs->sct_list && hs->sct_list_len > 0) {
        CBB sct_ext;
        if (!CBB_add_u16(&extensions, EXT_SIGNED_CERT_TIMESTAMP) ||
            !CBB_add_u16_length_prefixed(&extensions, &sct_ext) ||
            !CBB_add_bytes(&sct_ext, hs->sct_list, hs->sct_list_len))
            return -1;
    }

    /* Early data accepted indication */
    if (hs->early_data_accepted) {
        CBB ed_ext;
        if (!CBB_add_u16(&extensions, EXT_EARLY_DATA) ||
            !CBB_add_u16_length_prefixed(&extensions, &ed_ext))
            return -1;
    }

    CBB_flush(out);
    return 0;
}

static int tls13_build_finished(tls13_hs_t *hs, CBB *out, bool is_client)
{
    CBB msg;
    uint8_t transcript_hash[48];
    uint8_t finished_key[48];
    uint8_t verify_data[48];

    int hash_len = tls13_get_transcript_hash(hs, transcript_hash);
    if (hash_len < 0) {
        return -1;
    }

    /* finished_key = HKDF-Expand-Label(traffic_secret, "finished", "", Hash.length) */
    const uint8_t *traffic_secret = is_client ? hs->client_hs_traffic : hs->server_hs_traffic;
    if (opssl_tls13_hkdf_expand_label(finished_key, hs->hash_len,
                                     traffic_secret, hs->hash_len,
                                     "finished", NULL, 0, hs->hash_algo) != 1) {
        return -1;
    }

    /* verify_data = HMAC(finished_key, transcript_hash) */
    {
        size_t vd_len = sizeof(verify_data);
        if (opssl_hmac(hs->hash_algo,
                       finished_key, hs->hash_len,
                       transcript_hash, (size_t)hash_len,
                       verify_data, &vd_len) != 1) {
            return -1;
        }
    }

    if (!CBB_add_u8(out, TLS13_MSG_FINISHED) ||
        !CBB_add_u24_length_prefixed(out, &msg) ||
        !CBB_add_bytes(&msg, verify_data, hs->hash_len)) {
        return -1;
    }

    CBB_flush(out);
    return 0;
}

int opssl_tls13_server_handshake(void *hs_opaque, uint8_t *buf, size_t buf_len,
                                size_t *consumed, uint8_t *out, size_t *out_len,
                                size_t out_cap)
{
    tls13_hs_t *hs = (tls13_hs_t *)hs_opaque;
    *consumed = 0;
    *out_len = 0;

    switch (hs->state) {
    case OPSSL_HS_IDLE:
    case OPSSL_HS_CLIENT_HELLO: {
        if (buf_len < 4) {
            return OPSSL_WANT_READ;
        }

        uint8_t msg_type = buf[0];
        uint32_t msg_len = (buf[1] << 16) | (buf[2] << 8) | buf[3];

        if (msg_type != TLS13_MSG_CLIENT_HELLO) {
            return OPSSL_ERROR;
        }

        if (buf_len < 4 + msg_len) {
            return OPSSL_WANT_READ;
        }

        CBS msg;
        CBS_init(&msg, buf + 4, msg_len);

        /* Parse first (initializes transcript hash based on cipher suite) */
        if (tls13_parse_client_hello(hs, &msg) != 0) {
            return OPSSL_ERROR;
        }

        /* Accept PSK if client offered one and we have a matching key */
        if (hs->psk_offered && hs->has_psk && hs->psk_len > 0) {
            hs->psk_accepted = true;
        }

        /* Accept 0-RTT early data only with PSK and max_early_data configured */
        if (hs->early_data_offered && hs->psk_accepted && hs->early_data_max > 0) {
            hs->early_data_accepted = true;
        }

        /* Add CH to transcript AFTER hash is initialized */
        tls13_update_transcript(hs, buf, 4 + msg_len);

        *consumed = 4 + msg_len;

        /* Build ServerHello */
        CBB cbb;
        if (!CBB_init(&cbb, out_cap) ||
            tls13_build_server_hello(hs, &cbb) != 0) {
            CBB_cleanup(&cbb);
            return OPSSL_ERROR;
        }

        if (!cbb_finish_to_buf(&cbb, out, out_len, out_cap)) {
            return OPSSL_ERROR;
        }

        /* Update transcript */
        tls13_update_transcript(hs, out, *out_len);

        /* Derive handshake secrets */
        if (tls13_derive_handshake_secrets(hs) != 0) {
            return OPSSL_ERROR;
        }

        hs->state = OPSSL_HS_ENCRYPTED_EXTENSIONS;
        return OPSSL_OK;
    }

    case OPSSL_HS_ENCRYPTED_EXTENSIONS: {
        /* This state is handled by record layer switching to handshake encryption */
        hs->state = OPSSL_HS_FINISHED;
        return OPSSL_OK;
    }

    case OPSSL_HS_FINISHED: {
        /* Build server flight: EE [+ Certificate + CertificateVerify] + Finished */
        uint8_t flight[4096];
        size_t flight_len = 0;

        /* EncryptedExtensions */
        CBB ee_cbb;
        uint8_t ee_buf[512];
        size_t ee_len;
        if (!CBB_init(&ee_cbb, sizeof(ee_buf)))
            return OPSSL_ERROR;
        if (tls13_build_encrypted_extensions(hs, &ee_cbb) != 0) {
            CBB_cleanup(&ee_cbb);
            return OPSSL_ERROR;
        }
        if (!cbb_finish_to_buf(&ee_cbb, ee_buf, &ee_len, sizeof(ee_buf)))
            return OPSSL_ERROR;
        tls13_update_transcript(hs, ee_buf, ee_len);
        memcpy(flight + flight_len, ee_buf, ee_len);
        flight_len += ee_len;

        /* CertificateRequest (optional, server requests client cert) */
        if (!hs->psk_accepted && hs->request_client_cert) {
            CBB cr_cbb;
            uint8_t cr_buf[256];
            size_t cr_len;
            if (!CBB_init(&cr_cbb, sizeof(cr_buf)))
                return OPSSL_ERROR;
            if (tls13_build_certificate_request(hs, &cr_cbb) != 0) {
                CBB_cleanup(&cr_cbb);
                return OPSSL_ERROR;
            }
            if (!cbb_finish_to_buf(&cr_cbb, cr_buf, &cr_len, sizeof(cr_buf)))
                return OPSSL_ERROR;
            tls13_update_transcript(hs, cr_buf, cr_len);
            memcpy(flight + flight_len, cr_buf, cr_len);
            flight_len += cr_len;
        }

        /* Certificate (if we have a cert chain and not using PSK) */
        if (!hs->psk_accepted && hs->cert_chain && opssl_x509_chain_count(hs->cert_chain) > 0) {
            CBB cert_cbb;
            uint8_t cert_buf[2048];
            size_t cert_len;
            if (!CBB_init(&cert_cbb, sizeof(cert_buf)))
                return OPSSL_ERROR;
            if (tls13_build_certificate(hs, &cert_cbb) != 0) {
                CBB_cleanup(&cert_cbb);
                return OPSSL_ERROR;
            }
            if (!cbb_finish_to_buf(&cert_cbb, cert_buf, &cert_len, sizeof(cert_buf)))
                return OPSSL_ERROR;
            tls13_update_transcript(hs, cert_buf, cert_len);
            memcpy(flight + flight_len, cert_buf, cert_len);
            flight_len += cert_len;

            /* CertificateVerify */
            if (hs->sign_key) {
                uint8_t transcript_hash[48];
                int hlen = tls13_get_transcript_hash(hs, transcript_hash);
                if (hlen < 0) {
                    return OPSSL_ERROR;
                }
                CBB cv_cbb;
                uint8_t cv_buf[512];
                size_t cv_len;
                if (!CBB_init(&cv_cbb, sizeof(cv_buf)))
                    return OPSSL_ERROR;
                if (tls13_build_certificate_verify(hs, &cv_cbb, transcript_hash, (size_t)hlen) != 0) {
                    CBB_cleanup(&cv_cbb);
                    return OPSSL_ERROR;
                }
                if (!cbb_finish_to_buf(&cv_cbb, cv_buf, &cv_len, sizeof(cv_buf)))
                    return OPSSL_ERROR;
                tls13_update_transcript(hs, cv_buf, cv_len);
                memcpy(flight + flight_len, cv_buf, cv_len);
                flight_len += cv_len;
            }
        }

        /* Finished */
        CBB fin_cbb;
        uint8_t fin_buf[512];
        size_t fin_len;
        if (!CBB_init(&fin_cbb, sizeof(fin_buf)))
            return OPSSL_ERROR;
        if (tls13_build_finished(hs, &fin_cbb, false) != 0) {
            CBB_cleanup(&fin_cbb);
            return OPSSL_ERROR;
        }
        if (!cbb_finish_to_buf(&fin_cbb, fin_buf, &fin_len, sizeof(fin_buf)))
            return OPSSL_ERROR;
        tls13_update_transcript(hs, fin_buf, fin_len);
        memcpy(flight + flight_len, fin_buf, fin_len);
        flight_len += fin_len;

        /* Derive application traffic secrets (transcript = CH..SF) */
        if (tls13_derive_application_secrets(hs) != 0)
            return OPSSL_ERROR;

        /* Copy flight to output */
        if (flight_len > out_cap)
            return OPSSL_ERROR;
        memcpy(out, flight, flight_len);
        *out_len = flight_len;

        hs->state = OPSSL_HS_WAIT_FINISHED;
        return OPSSL_OK;
    }

    case OPSSL_HS_WAIT_FINISHED: {
        if (buf_len < 4) {
            return OPSSL_WANT_READ;
        }

        size_t offset = 0;

        /* If we requested client cert, consume Certificate + CertificateVerify first */
        if (hs->request_client_cert) {
            while (offset < buf_len) {
                if (offset + 4 > buf_len) return OPSSL_WANT_READ;
                uint8_t mt = buf[offset];
                uint32_t ml = ((uint32_t)buf[offset+1] << 16) |
                              ((uint32_t)buf[offset+2] << 8) | buf[offset+3];
                if (offset + 4 + ml > buf_len) return OPSSL_WANT_READ;

                if (mt == TLS13_MSG_CERTIFICATE) {
                    tls13_update_transcript(hs, buf + offset, 4 + ml);
                    offset += 4 + ml;
                } else if (mt == TLS13_MSG_CERTIFICATE_VERIFY) {
                    tls13_update_transcript(hs, buf + offset, 4 + ml);
                    hs->peer_cert_verified = true;
                    offset += 4 + ml;
                } else {
                    break;
                }
            }
            hs->request_client_cert = false;
        }

        if (offset + 4 > buf_len) return OPSSL_WANT_READ;
        uint8_t msg_type = buf[offset];
        uint32_t msg_len = ((uint32_t)buf[offset+1] << 16) |
                           ((uint32_t)buf[offset+2] << 8) | buf[offset+3];

        if (msg_type != TLS13_MSG_FINISHED || msg_len != hs->hash_len) {
            return OPSSL_ERROR;
        }

        if (offset + 4 + msg_len > buf_len) {
            return OPSSL_WANT_READ;
        }

        /* Verify client Finished message */
        uint8_t transcript_hash[48];
        uint8_t finished_key[48];
        uint8_t expected_verify_data[48];

        int hash_len = tls13_get_transcript_hash(hs, transcript_hash);
        if (hash_len < 0) {
            return OPSSL_ERROR;
        }

        /* finished_key = HKDF-Expand-Label(client_handshake_traffic_secret, "finished", "", Hash.length) */
        if (opssl_hkdf_expand_label(hs->hash_algo, hs->client_hs_traffic, hs->hash_len,
                                   "finished", NULL, 0,
                                   finished_key, hs->hash_len) != 1) {
            return OPSSL_ERROR;
        }

        /* verify_data = HMAC(finished_key, transcript_hash) */
        {
            size_t vd_len = sizeof(expected_verify_data);
            if (opssl_hmac(hs->hash_algo,
                           finished_key, hs->hash_len,
                           transcript_hash, (size_t)hash_len,
                           expected_verify_data, &vd_len) != 1) {
                return OPSSL_ERROR;
            }
        }

        /* Compare received finished_data with computed verify_data using constant-time comparison */
        if (opssl_ct_eq(buf + offset + 4, expected_verify_data, hs->hash_len) != 1) {
            return OPSSL_ERROR;
        }

        /* Update transcript with client Finished, then derive resumption_master_secret */
        tls13_update_transcript(hs, buf + offset, 4 + msg_len);
        {
            uint8_t res_hash[48];
            int res_hash_len = tls13_get_transcript_hash(hs, res_hash);
            if (res_hash_len > 0) {
                opssl_tls13_derive_secret_compat(hs->resumption_master_secret,
                    hs->hash_len, hs->master_secret, hs->hash_len,
                    "res master", res_hash, (size_t)res_hash_len,
                    hs->hash_algo);
            }
        }

        *consumed = offset + 4 + msg_len;
        hs->state = OPSSL_HS_COMPLETE;
        return OPSSL_OK;
    }

    default:
        return OPSSL_ERROR;
    }
}

static int tls13_parse_server_hello(tls13_hs_t *hs, CBS *msg)
{
    uint16_t version;
    CBS random, session_id, extensions;
    uint16_t cipher;
    uint8_t compression;

    if (!CBS_get_u16(msg, &version) ||
        !CBS_get_bytes(msg, &random, 32) ||
        !CBS_get_u8_length_prefixed(msg, &session_id) ||
        !CBS_get_u16(msg, &cipher) ||
        !CBS_get_u8(msg, &compression) ||
        !CBS_get_u16_length_prefixed(msg, &extensions)) {
        return -1;
    }

    memcpy(hs->server_random, CBS_data(&random), 32);
    hs->cipher = cipher;

    if (cipher == TLS_AES_128_GCM_SHA256) {
        hs->hash_algo = OPSSL_HMAC_SHA256;
        hs->hash_len = 32;
    } else if (cipher == TLS_AES_256_GCM_SHA384) {
        hs->hash_algo = OPSSL_HMAC_SHA384;
        hs->hash_len = 48;
    } else {
        hs->hash_algo = OPSSL_HMAC_SHA256;
        hs->hash_len = 32;
    }

    while (CBS_len(&extensions) > 0) {
        uint16_t ext_type;
        CBS ext_data;

        if (!CBS_get_u16(&extensions, &ext_type) ||
            !CBS_get_u16_length_prefixed(&extensions, &ext_data)) {
            return -1;
        }

        if (ext_type == EXT_KEY_SHARE) {
            uint16_t group;
            CBS key_exchange;
            if (!CBS_get_u16(&ext_data, &group) ||
                !CBS_get_u16_length_prefixed(&ext_data, &key_exchange)) {
                return -1;
            }
            if (group == NAMED_GROUP_X25519 && CBS_len(&key_exchange) == 32) {
                memcpy(hs->peer_ecdh_pub, CBS_data(&key_exchange), 32);
            }
        } else if (ext_type == 41) { /* pre_shared_key */
            uint16_t selected;
            if (!CBS_get_u16(&ext_data, &selected))
                return -1;
            if (selected == 0 && hs->psk_offered) {
                hs->psk_accepted = true;
            }
        }
    }

    return 0;
}

int opssl_tls13_client_handshake(void *hs_opaque, uint8_t *buf, size_t buf_len,
                                size_t *consumed, uint8_t *out, size_t *out_len,
                                size_t out_cap)
{
    tls13_hs_t *hs = (tls13_hs_t *)hs_opaque;
    *consumed = 0;
    *out_len = 0;

    switch (hs->state) {
    case OPSSL_HS_IDLE: {
        /* Generate key pair and send ClientHello */
        hs->hash_algo = OPSSL_HMAC_SHA256;
        hs->hash_len = 32;

        opssl_sha256_init(&hs->transcript_sha256);

        if (opssl_random_bytes(hs->client_random, 32) != 0) {
            return OPSSL_ERROR;
        }

        if (tls13_generate_key_pair_for_group(hs, NAMED_GROUP_X25519) != 0) {
            return OPSSL_ERROR;
        }

        CBB cbb;
        if (!CBB_init(&cbb, out_cap)) {
            return OPSSL_ERROR;
        }

        CBB ch_msg, cipher_suites, compression, extensions;
        if (!CBB_add_u8(&cbb, TLS13_MSG_CLIENT_HELLO) ||
            !CBB_add_u24_length_prefixed(&cbb, &ch_msg) ||
            !CBB_add_u16(&ch_msg, 0x0303) ||
            !CBB_add_bytes(&ch_msg, hs->client_random, 32) ||
            !CBB_add_u8(&ch_msg, 0) ||
            !CBB_add_u16_length_prefixed(&ch_msg, &cipher_suites) ||
            !CBB_add_u16(&cipher_suites, TLS_AES_128_GCM_SHA256) ||
            !CBB_add_u16(&cipher_suites, TLS_AES_256_GCM_SHA384) ||
            !CBB_add_u8_length_prefixed(&ch_msg, &compression) ||
            !CBB_add_u8(&compression, 0) ||
            !CBB_add_u16_length_prefixed(&ch_msg, &extensions)) {
            CBB_cleanup(&cbb);
            return OPSSL_ERROR;
        }

        /* supported_versions extension */
        CBB sv_ext, sv_list;
        if (!CBB_add_u16(&extensions, EXT_SUPPORTED_VERSIONS) ||
            !CBB_add_u16_length_prefixed(&extensions, &sv_ext) ||
            !CBB_add_u8_length_prefixed(&sv_ext, &sv_list) ||
            !CBB_add_u16(&sv_list, 0x0304)) {
            CBB_cleanup(&cbb);
            return OPSSL_ERROR;
        }

        /* key_share extension - offer X25519 */
        CBB ks_ext, ks_list, ks_entry;
        if (!CBB_add_u16(&extensions, EXT_KEY_SHARE) ||
            !CBB_add_u16_length_prefixed(&extensions, &ks_ext) ||
            !CBB_add_u16_length_prefixed(&ks_ext, &ks_list) ||
            !CBB_add_u16(&ks_list, NAMED_GROUP_X25519) ||
            !CBB_add_u16_length_prefixed(&ks_list, &ks_entry) ||
            !CBB_add_bytes(&ks_entry, hs->ecdh_pub, hs->ecdh_pub_len)) {
            CBB_cleanup(&cbb);
            return OPSSL_ERROR;
        }

        /* supported_groups extension */
        {
            CBB sg_ext, sg_list;
            if (!CBB_add_u16(&extensions, EXT_SUPPORTED_GROUPS) ||
                !CBB_add_u16_length_prefixed(&extensions, &sg_ext) ||
                !CBB_add_u16_length_prefixed(&sg_ext, &sg_list) ||
                !CBB_add_u16(&sg_list, NAMED_GROUP_X25519) ||
                !CBB_add_u16(&sg_list, NAMED_GROUP_SECP256R1) ||
                !CBB_add_u16(&sg_list, NAMED_GROUP_SECP384R1)) {
                CBB_cleanup(&cbb);
                return OPSSL_ERROR;
            }
        }

        /* signature_algorithms extension */
        CBB sa_ext, sa_list;
        if (!CBB_add_u16(&extensions, EXT_SIGNATURE_ALGORITHMS) ||
            !CBB_add_u16_length_prefixed(&extensions, &sa_ext) ||
            !CBB_add_u16_length_prefixed(&sa_ext, &sa_list) ||
            !CBB_add_u16(&sa_list, 0x0804) ||  /* rsa_pss_rsae_sha256 */
            !CBB_add_u16(&sa_list, 0x0403)) {  /* ecdsa_secp256r1_sha256 */
            CBB_cleanup(&cbb);
            return OPSSL_ERROR;
        }

        /* server_name extension (RFC 6066) */
        if (hs->sni[0]) {
            size_t sni_len = strlen(hs->sni);
            CBB sni_ext, sni_list, sni_entry;
            if (!CBB_add_u16(&extensions, EXT_SERVER_NAME) ||
                !CBB_add_u16_length_prefixed(&extensions, &sni_ext) ||
                !CBB_add_u16_length_prefixed(&sni_ext, &sni_list) ||
                !CBB_add_u8(&sni_list, 0) ||  /* host_name type */
                !CBB_add_u16_length_prefixed(&sni_list, &sni_entry) ||
                !CBB_add_bytes(&sni_entry, (const uint8_t *)hs->sni, sni_len)) {
                CBB_cleanup(&cbb);
                return OPSSL_ERROR;
            }
        }

        /* ALPN extension (RFC 7301) */
        if (hs->alpn_offer_len > 0) {
            CBB alpn_ext, alpn_list;
            if (!CBB_add_u16(&extensions, EXT_ALPN) ||
                !CBB_add_u16_length_prefixed(&extensions, &alpn_ext) ||
                !CBB_add_u16_length_prefixed(&alpn_ext, &alpn_list) ||
                !CBB_add_bytes(&alpn_list, (const uint8_t *)hs->alpn_offer,
                              hs->alpn_offer_len)) {
                CBB_cleanup(&cbb);
                return OPSSL_ERROR;
            }
        }

        /* status_request extension (OCSP stapling) */
        {
            CBB sr_ext;
            if (!CBB_add_u16(&extensions, EXT_STATUS_REQUEST) ||
                !CBB_add_u16_length_prefixed(&extensions, &sr_ext) ||
                !CBB_add_u8(&sr_ext, 1) ||  /* status_type: ocsp */
                !CBB_add_u16(&sr_ext, 0) || /* responder_id_list: empty */
                !CBB_add_u16(&sr_ext, 0)) { /* request_extensions: empty */
                CBB_cleanup(&cbb);
                return OPSSL_ERROR;
            }
        }

        /* signed_certificate_timestamp extension (RFC 6962) */
        {
            CBB sct_ext;
            if (!CBB_add_u16(&extensions, EXT_SIGNED_CERT_TIMESTAMP) ||
                !CBB_add_u16_length_prefixed(&extensions, &sct_ext)) {
                CBB_cleanup(&cbb);
                return OPSSL_ERROR;
            }
        }

        /* early_data extension (0-RTT) - only with PSK */
        if (hs->has_psk && hs->psk_len > 0 && hs->early_data_max > 0) {
            CBB ed_ext;
            if (!CBB_add_u16(&extensions, EXT_EARLY_DATA) ||
                !CBB_add_u16_length_prefixed(&extensions, &ed_ext)) {
                CBB_cleanup(&cbb);
                return OPSSL_ERROR;
            }
            hs->early_data_offered = true;
        }

        /* pre_shared_key extension (MUST be last per RFC 8446 §4.2.11) */
        if (hs->has_psk && hs->psk_len > 0 && hs->psk_ticket_len > 0) {
            hs->psk_offered = true;

            /* Build PSK extension with placeholder binder */
            CBB psk_ext, identities, binders;
            if (!CBB_add_u16(&extensions, 41) ||  /* pre_shared_key */
                !CBB_add_u16_length_prefixed(&extensions, &psk_ext) ||
                !CBB_add_u16_length_prefixed(&psk_ext, &identities) ||
                /* PskIdentity: identity + obfuscated_ticket_age */
                !CBB_add_u16(&identities, (uint16_t)hs->psk_ticket_len) ||
                !CBB_add_bytes(&identities, hs->psk_ticket, hs->psk_ticket_len) ||
                !CBB_add_u32(&identities, 0) ||  /* ticket_age = 0 for fresh */
                !CBB_add_u16_length_prefixed(&psk_ext, &binders) ||
                !CBB_add_u8(&binders, (uint8_t)hs->psk_len) ||
                !CBB_add_bytes(&binders, hs->psk, hs->psk_len)) { /* placeholder */
                CBB_cleanup(&cbb);
                return OPSSL_ERROR;
            }
        }

        if (!cbb_finish_to_buf(&cbb, out, out_len, out_cap)) {
            return OPSSL_ERROR;
        }

        /* Compute and patch PSK binder (HMAC over truncated ClientHello) */
        if (hs->psk_offered) {
            /* binder_key = Derive-Secret(HKDF-Extract(0, PSK), "res binder", "") */
            uint8_t early_secret[48];
            uint8_t zeros[48] = {0};
            opssl_tls13_extract_secret(early_secret, hs->hash_len,
                zeros, hs->hash_len, hs->psk, hs->psk_len, hs->hash_algo);

            uint8_t binder_key[48];
            uint8_t empty_hash[48];
            /* Hash of empty string */
            if (hs->hash_len == 32)
                opssl_sha256(NULL, 0, empty_hash);
            else
                opssl_sha384(NULL, 0, empty_hash);

            opssl_tls13_derive_secret_compat(binder_key, hs->hash_len,
                early_secret, hs->hash_len,
                "res binder", empty_hash, hs->hash_len, hs->hash_algo);

            /* Hash covers CH up to (not including) the binders list length field.
             * Tail layout: [2-byte binders_len][1-byte binder_len][binder_value] */
            size_t binder_offset = *out_len - hs->psk_len - 3;
            uint8_t transcript_hash[48];
            if (hs->hash_len == 32) {
                opssl_sha256_ctx_t ctx;
                opssl_sha256_init(&ctx);
                opssl_sha256_update(&ctx, out, binder_offset);
                opssl_sha256_final(&ctx, transcript_hash);
            } else {
                opssl_sha512_ctx_t ctx;
                opssl_sha384_init(&ctx);
                opssl_sha512_update(&ctx, out, binder_offset);
                opssl_sha384_final(&ctx, transcript_hash);
            }

            /* finished_key for binder */
            uint8_t finished_key[48];
            opssl_tls13_hkdf_expand_label(finished_key, hs->hash_len,
                binder_key, hs->hash_len,
                "finished", NULL, 0, hs->hash_algo);

            /* binder = HMAC(finished_key, transcript_hash) */
            uint8_t binder[48];
            size_t binder_len = sizeof(binder);
            opssl_hmac(hs->hash_algo, finished_key, hs->hash_len,
                       transcript_hash, hs->hash_len, binder, &binder_len);

            /* Patch binder into the ClientHello */
            memcpy(out + binder_offset, binder, hs->psk_len);
        }

        tls13_update_transcript(hs, out, *out_len);

        hs->state = OPSSL_HS_CLIENT_HELLO;
        return OPSSL_OK;
    }

    case OPSSL_HS_CLIENT_HELLO: {
        /* Process ServerHello */
        if (buf_len < 4) {
            return OPSSL_WANT_READ;
        }

        uint8_t msg_type = buf[0];
        uint32_t msg_len = (buf[1] << 16) | (buf[2] << 8) | buf[3];

        if (msg_type != TLS13_MSG_SERVER_HELLO) {
            return OPSSL_ERROR;
        }

        if (buf_len < 4 + msg_len) {
            return OPSSL_WANT_READ;
        }

        CBS msg;
        CBS_init(&msg, buf + 4, msg_len);

        tls13_update_transcript(hs, buf, 4 + msg_len);

        if (tls13_parse_server_hello(hs, &msg) != 0) {
            return OPSSL_ERROR;
        }

        /* Compute shared secret */
        if (tls13_compute_shared_secret(hs, hs->peer_ecdh_pub) != 0) {
            return OPSSL_ERROR;
        }

        /* Derive handshake secrets */
        if (tls13_derive_handshake_secrets(hs) != 0) {
            return OPSSL_ERROR;
        }

        *consumed = 4 + msg_len;
        hs->state = OPSSL_HS_ENCRYPTED_EXTENSIONS;
        return OPSSL_OK;
    }

    case OPSSL_HS_ENCRYPTED_EXTENSIONS: {
        size_t offset = 0;

        while (offset < buf_len) {
            if (offset + 4 > buf_len)
                return OPSSL_WANT_READ;

            uint8_t msg_type = buf[offset];
            uint32_t msg_len = (buf[offset+1] << 16) | (buf[offset+2] << 8) | buf[offset+3];

            if (offset + 4 + msg_len > buf_len)
                return OPSSL_WANT_READ;

            if (msg_type == TLS13_MSG_ENCRYPTED_EXTENSIONS) {
                tls13_update_transcript(hs, buf + offset, 4 + msg_len);

                /* Parse extensions from EncryptedExtensions */
                CBS ee_msg;
                CBS_init(&ee_msg, buf + offset + 4, msg_len);
                CBS ee_exts;
                if (CBS_get_u16_length_prefixed(&ee_msg, &ee_exts)) {
                    while (CBS_len(&ee_exts) > 0) {
                        uint16_t etype;
                        CBS edata;
                        if (!CBS_get_u16(&ee_exts, &etype) ||
                            !CBS_get_u16_length_prefixed(&ee_exts, &edata))
                            break;
                        if (etype == EXT_ALPN) {
                            CBS alpn_list, proto;
                            if (CBS_get_u16_length_prefixed(&edata, &alpn_list) &&
                                CBS_get_u8_length_prefixed(&alpn_list, &proto)) {
                                size_t plen = CBS_len(&proto);
                                if (plen < sizeof(hs->alpn)) {
                                    memcpy(hs->alpn, CBS_data(&proto), plen);
                                    hs->alpn[plen] = '\0';
                                    hs->alpn_len = plen;
                                }
                            }
                        }
                    }
                }

                offset += 4 + msg_len;
                continue;
            }

            if (msg_type == TLS13_MSG_CERTIFICATE_REQUEST) {
                /* Server requests client certificate authentication */
                hs->request_client_cert = true;
                tls13_update_transcript(hs, buf + offset, 4 + msg_len);
                offset += 4 + msg_len;
                continue;
            }

            if (msg_type == TLS13_MSG_CERTIFICATE) {
                CBS cert_msg;
                CBS_init(&cert_msg, buf + offset + 4, msg_len);
                uint8_t ctx_len;
                if (!CBS_get_u8(&cert_msg, &ctx_len))
                    return OPSSL_ERROR;
                if (ctx_len > 0) {
                    CBS ctx_data;
                    if (!CBS_get_bytes(&cert_msg, &ctx_data, ctx_len))
                        return OPSSL_ERROR;
                }
                uint32_t list_len;
                if (!CBS_get_u24(&cert_msg, &list_len))
                    return OPSSL_ERROR;
                CBS cert_list;
                if (!CBS_get_bytes(&cert_msg, &cert_list, list_len))
                    return OPSSL_ERROR;
                if (CBS_len(&cert_list) > 0 && !hs->peer_cert) {
                    uint32_t cert_len;
                    if (CBS_get_u24(&cert_list, &cert_len) && cert_len > 0) {
                        CBS cert_der;
                        if (CBS_get_bytes(&cert_list, &cert_der, cert_len)) {
                            hs->peer_cert = malloc(cert_len);
                            if (hs->peer_cert) {
                                memcpy(hs->peer_cert, CBS_data(&cert_der), cert_len);
                                hs->peer_cert_len = cert_len;
                            }
                        }
                        uint16_t ext_len;
                        if (CBS_len(&cert_list) >= 2)
                            CBS_get_u16(&cert_list, &ext_len);
                    }
                }
                tls13_update_transcript(hs, buf + offset, 4 + msg_len);
                offset += 4 + msg_len;
                continue;
            }

            if (msg_type == TLS13_MSG_CERTIFICATE_VERIFY) {
                if (hs->peer_cert && hs->peer_cert_len > 0) {
                    uint8_t cv_hash[48];
                    int cv_hash_len = tls13_get_transcript_hash(hs, cv_hash);
                    if (cv_hash_len < 0)
                        return OPSSL_ERROR;

                    uint8_t context[150];
                    memset(context, 0x20, 64);
                    memcpy(context + 64, "TLS 1.3, server CertificateVerify", 33);
                    context[97] = 0;
                    memcpy(context + 98, cv_hash, (size_t)cv_hash_len);
                    size_t context_len = 98 + (size_t)cv_hash_len;

                    CBS cv_msg;
                    CBS_init(&cv_msg, buf + offset + 4, msg_len);
                    uint16_t sig_scheme;
                    uint16_t sig_len_field;
                    if (!CBS_get_u16(&cv_msg, &sig_scheme) ||
                        !CBS_get_u16(&cv_msg, &sig_len_field))
                        return OPSSL_ERROR;
                    if (CBS_len(&cv_msg) < sig_len_field)
                        return OPSSL_ERROR;
                    const uint8_t *sig_data = CBS_data(&cv_msg);

                    opssl_x509_t *peer_x509 = opssl_x509_from_der(hs->peer_cert, hs->peer_cert_len);
                    if (!peer_x509)
                        return OPSSL_ERROR;

                    const uint8_t *spki;
                    size_t spki_len;
                    if (!opssl_x509_get_spki(peer_x509, &spki, &spki_len)) {
                        opssl_x509_free(peer_x509);
                        return OPSSL_ERROR;
                    }

                    int verified = 0;
                    if (sig_scheme == 0x0807) {
                        opssl_cbs_t spki_cbs, alg_id, pub_bits;
                        opssl_cbs_init(&spki_cbs, spki, spki_len);
                        opssl_asn1_get_sequence(&spki_cbs, &alg_id);
                        uint8_t unused;
                        if (opssl_asn1_get_bit_string(&spki_cbs, &pub_bits, &unused) &&
                            opssl_cbs_len(&pub_bits) == 32) {
                            verified = opssl_ed25519_verify(sig_data,
                                                           context, context_len,
                                                           opssl_cbs_data(&pub_bits));
                        }
                    } else if (sig_scheme == 0x0403) {
                        uint8_t digest[32];
                        opssl_sha256(context, context_len, digest);

                        opssl_cbs_t spki_cbs, alg_id, pub_bits;
                        opssl_cbs_init(&spki_cbs, spki, spki_len);
                        opssl_asn1_get_sequence(&spki_cbs, &alg_id);
                        uint8_t unused;
                        if (opssl_asn1_get_bit_string(&spki_cbs, &pub_bits, &unused)) {
                            opssl_ecdsa_ctx_t *ecdsa = opssl_ecdsa_new(OPSSL_CURVE_P256);
                            if (ecdsa) {
                                if (opssl_ecdsa_set_public(ecdsa,
                                        opssl_cbs_data(&pub_bits),
                                        opssl_cbs_len(&pub_bits)) == 1) {
                                    verified = opssl_ecdsa_verify(ecdsa,
                                            digest, sizeof(digest),
                                            sig_data, sig_len_field);
                                }
                                opssl_ecdsa_free(ecdsa);
                            }
                        }
                    } else if (sig_scheme == 0x0804 || sig_scheme == 0x0805 ||
                               sig_scheme == 0x0806) {
                        /* rsa_pss_rsae_sha256/384/512 */
                        uint8_t digest[64];
                        size_t dlen;
                        opssl_hmac_algo_t rsa_hash;
                        if (sig_scheme == 0x0804) {
                            opssl_sha256(context, context_len, digest);
                            dlen = 32; rsa_hash = OPSSL_HMAC_SHA256;
                        } else if (sig_scheme == 0x0805) {
                            opssl_sha384(context, context_len, digest);
                            dlen = 48; rsa_hash = OPSSL_HMAC_SHA384;
                        } else {
                            opssl_sha512(context, context_len, digest);
                            dlen = 64; rsa_hash = OPSSL_HMAC_SHA512;
                        }
                        opssl_rsa_ctx_t *rsa = opssl_rsa_new();
                        if (rsa) {
                            if (opssl_rsa_load_public_key(rsa, spki, spki_len) == 1) {
                                verified = opssl_rsa_verify(rsa, OPSSL_RSA_PSS,
                                    rsa_hash, digest, dlen, sig_data, sig_len_field);
                            }
                            opssl_rsa_free(rsa);
                        }
                    }

                    opssl_x509_free(peer_x509);
                    if (!verified)
                        return OPSSL_ERROR;
                }

                tls13_update_transcript(hs, buf + offset, 4 + msg_len);
                offset += 4 + msg_len;
                continue;
            }

            if (msg_type == TLS13_MSG_FINISHED) {
                uint8_t transcript_hash[48];
                uint8_t finished_key[48];
                uint8_t expected[48];

                int hash_len = tls13_get_transcript_hash(hs, transcript_hash);
                if (hash_len < 0)
                    return OPSSL_ERROR;

                if (opssl_tls13_hkdf_expand_label(finished_key, hs->hash_len,
                                                  hs->server_hs_traffic, hs->hash_len,
                                                  "finished", NULL, 0, hs->hash_algo) != 1)
                    return OPSSL_ERROR;

                size_t vd_len = sizeof(expected);
                if (opssl_hmac(hs->hash_algo,
                               finished_key, hs->hash_len,
                               transcript_hash, (size_t)hash_len,
                               expected, &vd_len) != 1)
                    return OPSSL_ERROR;

                if (msg_len != hs->hash_len ||
                    opssl_ct_eq(buf + offset + 4, expected, hs->hash_len) != 1)
                    return OPSSL_ERROR;

                tls13_update_transcript(hs, buf + offset, 4 + msg_len);
                offset += 4 + msg_len;
                *consumed = offset;

                /* Derive application traffic secrets (transcript = CH..SF) */
                if (tls13_derive_application_secrets(hs) != 0)
                    return OPSSL_ERROR;

                CBB cbb;
                if (!CBB_init(&cbb, out_cap))
                    return OPSSL_ERROR;

                /* Client Certificate + CertificateVerify if server requested */
                if (hs->request_client_cert) {
                    if (hs->client_cert_chain &&
                        opssl_x509_chain_count(hs->client_cert_chain) > 0) {
                        /* Build client Certificate */
                        const opssl_x509_chain_t *saved = hs->cert_chain;
                        hs->cert_chain = hs->client_cert_chain;
                        if (tls13_build_certificate(hs, &cbb) != 0) {
                            hs->cert_chain = saved;
                            CBB_cleanup(&cbb);
                            return OPSSL_ERROR;
                        }
                        hs->cert_chain = saved;

                        /* Flush cert to get transcript update */
                        uint8_t *cert_out;
                        size_t cert_out_len;
                        if (!CBB_finish(&cbb, &cert_out, &cert_out_len)) {
                            return OPSSL_ERROR;
                        }
                        tls13_update_transcript(hs, cert_out, cert_out_len);
                        memcpy(out, cert_out, cert_out_len);
                        *out_len = cert_out_len;
                        free(cert_out);

                        /* Build client CertificateVerify */
                        if (hs->client_sign_key) {
                            uint8_t cv_hash[48];
                            int cv_hash_len = tls13_get_transcript_hash(hs, cv_hash);
                            if (cv_hash_len < 0) return OPSSL_ERROR;

                            if (!CBB_init(&cbb, 512)) return OPSSL_ERROR;
                            const opssl_pkey_t *saved_key = hs->sign_key;
                            hs->sign_key = hs->client_sign_key;
                            if (tls13_build_certificate_verify(hs, &cbb,
                                    cv_hash, (size_t)cv_hash_len) != 0) {
                                hs->sign_key = saved_key;
                                CBB_cleanup(&cbb);
                                return OPSSL_ERROR;
                            }
                            hs->sign_key = saved_key;

                            uint8_t *cv_out;
                            size_t cv_out_len;
                            if (!CBB_finish(&cbb, &cv_out, &cv_out_len))
                                return OPSSL_ERROR;
                            tls13_update_transcript(hs, cv_out, cv_out_len);
                            memcpy(out + *out_len, cv_out, cv_out_len);
                            *out_len += cv_out_len;
                            free(cv_out);
                        }

                        if (!CBB_init(&cbb, out_cap - *out_len))
                            return OPSSL_ERROR;
                    } else {
                        /* Send empty Certificate (no client cert available) */
                        if (!CBB_add_u8(&cbb, TLS13_MSG_CERTIFICATE) ||
                            !CBB_add_u24(&cbb, 4) ||
                            !CBB_add_u8(&cbb, 0) ||
                            !CBB_add_u24(&cbb, 0)) {
                            CBB_cleanup(&cbb);
                            return OPSSL_ERROR;
                        }
                        uint8_t *empty_cert_out;
                        size_t empty_cert_len;
                        if (!CBB_finish(&cbb, &empty_cert_out, &empty_cert_len))
                            return OPSSL_ERROR;
                        tls13_update_transcript(hs, empty_cert_out, empty_cert_len);
                        memcpy(out + *out_len, empty_cert_out, empty_cert_len);
                        *out_len += empty_cert_len;
                        free(empty_cert_out);

                        if (!CBB_init(&cbb, out_cap - *out_len))
                            return OPSSL_ERROR;
                    }
                }

                if (tls13_build_finished(hs, &cbb, true) != 0) {
                    CBB_cleanup(&cbb);
                    return OPSSL_ERROR;
                }

                uint8_t *fin_out;
                size_t fin_out_len;
                if (!CBB_finish(&cbb, &fin_out, &fin_out_len))
                    return OPSSL_ERROR;
                tls13_update_transcript(hs, fin_out, fin_out_len);
                memcpy(out + *out_len, fin_out, fin_out_len);
                *out_len += fin_out_len;
                free(fin_out);

                /* Derive resumption_master_secret (transcript = CH..CF) */
                uint8_t res_hash[48];
                int res_hash_len = tls13_get_transcript_hash(hs, res_hash);
                if (res_hash_len > 0) {
                    opssl_tls13_derive_secret_compat(hs->resumption_master_secret,
                        hs->hash_len, hs->master_secret, hs->hash_len,
                        "res master", res_hash, (size_t)res_hash_len,
                        hs->hash_algo);
                }

                hs->state = OPSSL_HS_COMPLETE;
                return OPSSL_OK;
            }

            offset += 4 + msg_len;
        }

        *consumed = offset;
        return OPSSL_WANT_READ;
    }

    default:
        return OPSSL_ERROR;
    }
}

/*
 * Extract key material from TLS 1.3 handshake state for cipher setup.
 * This is called by the handshake dispatcher after handshake completion.
 */
static int tls13_derive_keys_from_secrets(tls13_hs_t *hs,
                                          const uint8_t *client_secret,
                                          const uint8_t *server_secret,
                                          uint8_t *client_key, size_t *client_key_len,
                                          uint8_t *server_key, size_t *server_key_len,
                                          uint8_t *client_iv, size_t *client_iv_len,
                                          uint8_t *server_iv, size_t *server_iv_len,
                                          opssl_ciphersuite_t *cipher)
{
    *cipher = hs->cipher;

    size_t key_len;
    switch (hs->cipher) {
    case TLS_AES_128_GCM_SHA256:
    case 0x1304: /* AES-128-CCM */
        key_len = 16;
        break;
    default:
        key_len = 32;
        break;
    }

    if (opssl_tls13_hkdf_expand_label(client_key, key_len,
                                     client_secret, hs->hash_len,
                                     "key", NULL, 0, hs->hash_algo) != 1 ||
        opssl_tls13_hkdf_expand_label(server_key, key_len,
                                     server_secret, hs->hash_len,
                                     "key", NULL, 0, hs->hash_algo) != 1 ||
        opssl_tls13_hkdf_expand_label(client_iv, 12,
                                     client_secret, hs->hash_len,
                                     "iv", NULL, 0, hs->hash_algo) != 1 ||
        opssl_tls13_hkdf_expand_label(server_iv, 12,
                                     server_secret, hs->hash_len,
                                     "iv", NULL, 0, hs->hash_algo) != 1) {
        return OPSSL_ERROR;
    }

    *client_key_len = key_len;
    *server_key_len = key_len;
    *client_iv_len = 12;
    *server_iv_len = 12;

    return OPSSL_OK;
}

opssl_named_group_t opssl_tls13_get_negotiated_group(void *hs_opaque)
{
    tls13_hs_t *hs = (tls13_hs_t *)hs_opaque;
    return hs ? hs->group : (opssl_named_group_t)0;
}

void opssl_tls13_debug_dump_secrets(void *hs_opaque)
{
    tls13_hs_t *hs = (tls13_hs_t *)hs_opaque;
    if (!hs) return;
}

int opssl_tls13_extract_hs_keys(void *hs_opaque,
                                uint8_t *client_key, size_t *client_key_len,
                                uint8_t *server_key, size_t *server_key_len,
                                uint8_t *client_iv, size_t *client_iv_len,
                                uint8_t *server_iv, size_t *server_iv_len,
                                opssl_ciphersuite_t *cipher)
{
    tls13_hs_t *hs = (tls13_hs_t *)hs_opaque;
    if (!hs) return OPSSL_ERROR;

    return tls13_derive_keys_from_secrets(hs,
                                          hs->client_hs_traffic,
                                          hs->server_hs_traffic,
                                          client_key, client_key_len,
                                          server_key, server_key_len,
                                          client_iv, client_iv_len,
                                          server_iv, server_iv_len,
                                          cipher);
}

int opssl_tls13_extract_traffic_keys(void *hs_opaque,
                                     uint8_t *client_key, size_t *client_key_len,
                                     uint8_t *server_key, size_t *server_key_len,
                                     uint8_t *client_iv, size_t *client_iv_len,
                                     uint8_t *server_iv, size_t *server_iv_len,
                                     opssl_ciphersuite_t *cipher)
{
    tls13_hs_t *hs = (tls13_hs_t *)hs_opaque;

    if (!hs || hs->state != OPSSL_HS_COMPLETE) {
        return OPSSL_ERROR;
    }

    return tls13_derive_keys_from_secrets(hs,
                                          hs->client_ap_traffic,
                                          hs->server_ap_traffic,
                                          client_key, client_key_len,
                                          server_key, server_key_len,
                                          client_iv, client_iv_len,
                                          server_iv, server_iv_len,
                                          cipher);
}

void opssl_tls13_set_sni(void *hs_opaque, const char *hostname)
{
    tls13_hs_t *hs = (tls13_hs_t *)hs_opaque;
    if (!hs || !hostname) return;
    size_t len = strlen(hostname);
    if (len >= sizeof(hs->sni)) len = sizeof(hs->sni) - 1;
    memcpy(hs->sni, hostname, len);
    hs->sni[len] = '\0';
}

const char *opssl_tls13_get_sni(void *hs_opaque)
{
    tls13_hs_t *hs = (tls13_hs_t *)hs_opaque;
    if (!hs || !hs->sni[0]) return NULL;
    return hs->sni;
}

void opssl_tls13_set_alpn_offer(void *hs_opaque, const char **protos, size_t count)
{
    tls13_hs_t *hs = (tls13_hs_t *)hs_opaque;
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

void opssl_tls13_set_alpn_supported(void *hs_opaque, const char **protos, size_t count)
{
    tls13_hs_t *hs = (tls13_hs_t *)hs_opaque;
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

const char *opssl_tls13_get_alpn(void *hs_opaque)
{
    tls13_hs_t *hs = (tls13_hs_t *)hs_opaque;
    if (!hs || hs->alpn_len == 0) return NULL;
    return hs->alpn;
}

const uint8_t *
opssl_tls13_get_peer_cert(void *hs_opaque, size_t *out_len)
{
    tls13_hs_t *hs = (tls13_hs_t *)hs_opaque;
    if (!hs || !hs->peer_cert || hs->peer_cert_len == 0) {
        if (out_len) *out_len = 0;
        return NULL;
    }
    if (out_len) *out_len = hs->peer_cert_len;
    return hs->peer_cert;
}

void
opssl_tls13_free_peer_cert(void *hs_opaque)
{
    tls13_hs_t *hs = (tls13_hs_t *)hs_opaque;
    if (hs && hs->peer_cert) {
        free(hs->peer_cert);
        hs->peer_cert = NULL;
        hs->peer_cert_len = 0;
    }
}

void
opssl_tls13_set_sign_key(void *hs_opaque, const opssl_pkey_t *key)
{
    tls13_hs_t *hs = (tls13_hs_t *)hs_opaque;
    if (hs) hs->sign_key = key;
}

void
opssl_tls13_set_cert_chain(void *hs_opaque, const opssl_x509_chain_t *chain)
{
    tls13_hs_t *hs = (tls13_hs_t *)hs_opaque;
    if (hs) hs->cert_chain = chain;
}

void
opssl_tls13_set_psk(void *hs_opaque, const uint8_t *psk, size_t psk_len,
                    const uint8_t *ticket, size_t ticket_len)
{
    tls13_hs_t *hs = (tls13_hs_t *)hs_opaque;
    if (!hs || !psk || psk_len == 0) return;
    if (psk_len > sizeof(hs->psk)) psk_len = sizeof(hs->psk);
    memcpy(hs->psk, psk, psk_len);
    hs->psk_len = psk_len;
    if (ticket && ticket_len > 0 && ticket_len <= sizeof(hs->psk_ticket)) {
        memcpy(hs->psk_ticket, ticket, ticket_len);
        hs->psk_ticket_len = ticket_len;
    }
    hs->has_psk = true;
}

const uint8_t *
opssl_tls13_get_resumption_master_secret(void *hs_opaque, size_t *out_len)
{
    tls13_hs_t *hs = (tls13_hs_t *)hs_opaque;
    if (!hs || hs->state != OPSSL_HS_COMPLETE) {
        if (out_len) *out_len = 0;
        return NULL;
    }
    if (out_len) *out_len = hs->hash_len;
    return hs->resumption_master_secret;
}

opssl_hmac_algo_t
opssl_tls13_get_hash_algo(void *hs_opaque)
{
    tls13_hs_t *hs = (tls13_hs_t *)hs_opaque;
    if (!hs) return OPSSL_HMAC_SHA256;
    return hs->hash_algo;
}

void
opssl_tls13_request_client_cert(void *hs_opaque, bool request)
{
    tls13_hs_t *hs = (tls13_hs_t *)hs_opaque;
    if (hs) hs->request_client_cert = request;
}

void
opssl_tls13_set_client_cert(void *hs_opaque, const opssl_pkey_t *key,
                            const opssl_x509_chain_t *chain)
{
    tls13_hs_t *hs = (tls13_hs_t *)hs_opaque;
    if (!hs) return;
    hs->client_sign_key = key;
    hs->client_cert_chain = chain;
}

void
opssl_tls13_set_ocsp_response(void *hs_opaque, const uint8_t *response, size_t len)
{
    tls13_hs_t *hs = (tls13_hs_t *)hs_opaque;
    if (!hs) return;
    free(hs->ocsp_response);
    hs->ocsp_response = NULL;
    hs->ocsp_response_len = 0;
    if (response && len > 0) {
        hs->ocsp_response = malloc(len);
        if (hs->ocsp_response) {
            memcpy(hs->ocsp_response, response, len);
            hs->ocsp_response_len = len;
        }
    }
}

void
opssl_tls13_set_sct_list(void *hs_opaque, const uint8_t *sct_list, size_t len)
{
    tls13_hs_t *hs = (tls13_hs_t *)hs_opaque;
    if (!hs) return;
    free(hs->sct_list);
    hs->sct_list = NULL;
    hs->sct_list_len = 0;
    if (sct_list && len > 0) {
        hs->sct_list = malloc(len);
        if (hs->sct_list) {
            memcpy(hs->sct_list, sct_list, len);
            hs->sct_list_len = len;
        }
    }
}

void
opssl_tls13_set_early_data_max(void *hs_opaque, size_t max_bytes)
{
    tls13_hs_t *hs = (tls13_hs_t *)hs_opaque;
    if (hs) hs->early_data_max = max_bytes;
}

bool
opssl_tls13_early_data_accepted(void *hs_opaque)
{
    tls13_hs_t *hs = (tls13_hs_t *)hs_opaque;
    return hs ? hs->early_data_accepted : false;
}

int
opssl_tls13_get_ocsp_response(void *hs_opaque, const uint8_t **resp, size_t *len)
{
    tls13_hs_t *hs = (tls13_hs_t *)hs_opaque;
    if (!hs || !resp || !len)
        return 0;
    if (!hs->ocsp_response || hs->ocsp_response_len == 0) {
        *resp = NULL;
        *len = 0;
        return 0;
    }
    *resp = hs->ocsp_response;
    *len = hs->ocsp_response_len;
    return 1;
}

int
opssl_tls13_get_sct_list(void *hs_opaque, const uint8_t **sct, size_t *len)
{
    tls13_hs_t *hs = (tls13_hs_t *)hs_opaque;
    if (!hs || !sct || !len)
        return 0;
    if (!hs->sct_list || hs->sct_list_len == 0) {
        *sct = NULL;
        *len = 0;
        return 0;
    }
    *sct = hs->sct_list;
    *len = hs->sct_list_len;
    return 1;
}
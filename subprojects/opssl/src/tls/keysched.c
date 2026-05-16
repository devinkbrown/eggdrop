/*
 * opssl/tls/keysched.c — TLS 1.3 key schedule (RFC 8446 §7.1).
 *
 * Derives all handshake and application traffic secrets using HKDF.
 * Implements the TLS 1.3 key schedule phases:
 *   Early Secret → Handshake Secret → Master Secret
 *
 * Each phase derives traffic secrets via Derive-Secret with transcript hashes.
 * Traffic keys derived via HKDF-Expand-Label for encryption/decryption.
 *
 * Copyright (C) 2026 ophion development team
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <opssl/crypto.h>
#include <opssl/platform.h>
#include <opssl/types.h>
#include <string.h>

/* TLS 1.3 labels defined in RFC 8446 */
#define TLS13_LABEL_DERIVED     "derived"
#define TLS13_LABEL_C_HS_TRAFFIC "c hs traffic"
#define TLS13_LABEL_S_HS_TRAFFIC "s hs traffic"
#define TLS13_LABEL_C_AP_TRAFFIC "c ap traffic"
#define TLS13_LABEL_S_AP_TRAFFIC "s ap traffic"
#define TLS13_LABEL_KEY         "key"
#define TLS13_LABEL_IV          "iv"
#define TLS13_LABEL_FINISHED    "finished"

/* Maximum hash output length */
#define MAX_HASH_LEN            64

/* Zero-filled input for HKDF-Extract with no salt/IKM */
static const uint8_t zero_ikm[MAX_HASH_LEN] = {0};

/* SHA-256("") — used as Transcript-Hash("") in Derive-Secret */
static const uint8_t empty_hash_sha256[32] = {
    0xe3,0xb0,0xc4,0x42,0x98,0xfc,0x1c,0x14,
    0x9a,0xfb,0xf4,0xc8,0x99,0x6f,0xb9,0x24,
    0x27,0xae,0x41,0xe4,0x64,0x9b,0x93,0x4c,
    0xa4,0x95,0x99,0x1b,0x78,0x52,0xb8,0x55,
};

/* SHA-384("") */
static const uint8_t empty_hash_sha384[48] = {
    0x38,0xb0,0x60,0xa7,0x51,0xac,0x96,0x38,
    0x4c,0xd9,0x32,0x7e,0xb1,0xb1,0xe3,0x6a,
    0x21,0xfd,0xb7,0x11,0x14,0xbe,0x07,0x43,
    0x4c,0x0c,0xc7,0xbf,0x63,0xf6,0xe1,0xda,
    0x27,0x4e,0xde,0xbf,0xe7,0x6f,0x65,0xfb,
    0xd5,0x1a,0xd2,0xf1,0x48,0x98,0xb9,0x5b,
};

/*
 * Get hash output length for HMAC algorithm.
 */
static size_t
hmac_hash_len(opssl_hmac_algo_t hash)
{
    switch (hash) {
    case OPSSL_HMAC_SHA1: return 0;
    case OPSSL_HMAC_SHA256: return OPSSL_SHA256_DIGEST_LEN;
    case OPSSL_HMAC_SHA384: return OPSSL_SHA384_DIGEST_LEN;
    case OPSSL_HMAC_SHA512: return OPSSL_SHA512_DIGEST_LEN;
    }
    return 0;
}

/*
 * Derive-Secret(Secret, Label, Messages) = HKDF-Expand-Label(Secret, Label,
 *                                          Transcript-Hash(Messages), Hash.length)
 *
 * RFC 8446 §7.1
 */
int
opssl_tls13_derive_secret(opssl_hmac_algo_t hash,
                          const uint8_t *secret, size_t secret_len,
                          const char *label,
                          const uint8_t *transcript_hash, size_t hash_len,
                          uint8_t *out, size_t out_len)
{
    if (!secret || !label || !out) {
        return OPSSL_ERROR;
    }

    /* Validate hash length matches algorithm */
    size_t expected_hash_len = hmac_hash_len(hash);
    if (expected_hash_len == 0 || out_len != expected_hash_len) {
        return OPSSL_ERROR;
    }

    /* Use Hash("") if transcript_hash is NULL (RFC 8446 §7.1) */
    const uint8_t *context;
    size_t context_len;
    if (transcript_hash) {
        context = transcript_hash;
        context_len = hash_len;
    } else {
        context = (hash == OPSSL_HMAC_SHA384) ? empty_hash_sha384
                                               : empty_hash_sha256;
        context_len = expected_hash_len;
    }

    return opssl_hkdf_expand_label(hash, secret, secret_len, label,
                                   context, context_len, out, out_len);
}

/*
 * HKDF-Extract operation for TLS 1.3 key schedule.
 * Extract(salt, IKM) -> PRK
 */
int
opssl_tls13_extract(opssl_hmac_algo_t hash,
                    const uint8_t *salt, size_t salt_len,
                    const uint8_t *ikm, size_t ikm_len,
                    uint8_t *out, size_t *out_len)
{
    if (!out || !out_len) {
        return OPSSL_ERROR;
    }

    /* Use zero-filled salt if NULL */
    size_t hash_len = hmac_hash_len(hash);
    if (hash_len == 0) {
        return OPSSL_ERROR;
    }

    const uint8_t *actual_salt = salt;
    size_t actual_salt_len = salt_len;

    if (!salt) {
        actual_salt = zero_ikm;
        actual_salt_len = hash_len;
    }

    /* Use zero-filled IKM if NULL */
    const uint8_t *actual_ikm = ikm;
    size_t actual_ikm_len = ikm_len;

    if (!ikm) {
        actual_ikm = zero_ikm;
        actual_ikm_len = hash_len;
    }

    return opssl_hkdf_extract(hash, actual_salt, actual_salt_len,
                              actual_ikm, actual_ikm_len, out, out_len);
}

/*
 * Derive traffic keys and IV from traffic secret.
 * key = HKDF-Expand-Label(Secret, "key", "", key_len)
 * iv = HKDF-Expand-Label(Secret, "iv", "", iv_len)
 */
int
opssl_tls13_derive_traffic_keys(opssl_hmac_algo_t hash,
                                const uint8_t *secret, size_t secret_len,
                                uint8_t *key, size_t key_len,
                                uint8_t *iv, size_t iv_len)
{
    if (!secret || !key || !iv) {
        return OPSSL_ERROR;
    }

    /* Derive key */
    if (opssl_hkdf_expand_label(hash, secret, secret_len, TLS13_LABEL_KEY,
                                NULL, 0, key, key_len) != OPSSL_OK) {
        return OPSSL_ERROR;
    }

    /* Derive IV */
    if (opssl_hkdf_expand_label(hash, secret, secret_len, TLS13_LABEL_IV,
                                NULL, 0, iv, iv_len) != OPSSL_OK) {
        /* Zero key on failure */
        opssl_memzero(key, key_len);
        return OPSSL_ERROR;
    }

    return OPSSL_OK;
}

/*
 * TLS 1.3 Early Secret derivation.
 * Early-Secret = HKDF-Extract(0, PSK)
 *
 * If PSK is NULL, uses zero-filled input.
 */
int
opssl_tls13_early_secret(opssl_hmac_algo_t hash,
                         const uint8_t *psk, size_t psk_len,
                         uint8_t *out, size_t *out_len)
{
    if (!out || !out_len) {
        return OPSSL_ERROR;
    }

    size_t hash_len = hmac_hash_len(hash);
    if (hash_len == 0) {
        return OPSSL_ERROR;
    }

    *out_len = hash_len;

    /* Extract with zero salt */
    return opssl_tls13_extract(hash, NULL, 0, psk, psk_len, out, out_len);
}

/*
 * TLS 1.3 Handshake Secret derivation.
 * Derive-Secret(Early-Secret, "derived", "") -> derived_secret
 * Handshake-Secret = HKDF-Extract(derived_secret, ECDHE)
 */
int
opssl_tls13_handshake_secret(opssl_hmac_algo_t hash,
                             const uint8_t *early_secret, size_t es_len,
                             const uint8_t *shared_secret, size_t ss_len,
                             uint8_t *out, size_t *out_len)
{
    if (!early_secret || !out || !out_len) {
        return OPSSL_ERROR;
    }

    size_t hash_len = hmac_hash_len(hash);
    if (hash_len == 0 || es_len != hash_len) {
        return OPSSL_ERROR;
    }

    *out_len = hash_len;

    /* Derive salt from early secret */
    uint8_t derived_secret[MAX_HASH_LEN];
    if (opssl_tls13_derive_secret(hash, early_secret, es_len, TLS13_LABEL_DERIVED,
                                  NULL, 0, derived_secret, hash_len) != OPSSL_OK) {
        return OPSSL_ERROR;
    }

    /* Extract with derived secret as salt */
    int ret = opssl_tls13_extract(hash, derived_secret, hash_len,
                                  shared_secret, ss_len, out, out_len);

    /* Clear derived secret */
    opssl_memzero(derived_secret, hash_len);
    return ret;
}

/*
 * TLS 1.3 Master Secret derivation.
 * Derive-Secret(Handshake-Secret, "derived", "") -> derived_secret
 * Master-Secret = HKDF-Extract(derived_secret, 0)
 */
int
opssl_tls13_master_secret(opssl_hmac_algo_t hash,
                          const uint8_t *handshake_secret, size_t hs_len,
                          uint8_t *out, size_t *out_len)
{
    if (!handshake_secret || !out || !out_len) {
        return OPSSL_ERROR;
    }

    size_t hash_len = hmac_hash_len(hash);
    if (hash_len == 0 || hs_len != hash_len) {
        return OPSSL_ERROR;
    }

    *out_len = hash_len;

    /* Derive salt from handshake secret */
    uint8_t derived_secret[MAX_HASH_LEN];
    if (opssl_tls13_derive_secret(hash, handshake_secret, hs_len, TLS13_LABEL_DERIVED,
                                  NULL, 0, derived_secret, hash_len) != OPSSL_OK) {
        return OPSSL_ERROR;
    }

    /* Extract with zero IKM */
    int ret = opssl_tls13_extract(hash, derived_secret, hash_len,
                                  NULL, 0, out, out_len);

    /* Clear derived secret */
    opssl_memzero(derived_secret, hash_len);
    return ret;
}

/*
 * TLS 1.3 key update (RFC 8446 §7.2).
 * application_traffic_secret_N+1 =
 *   HKDF-Expand-Label(application_traffic_secret_N, "traffic upd", "", Hash.length)
 */
int
opssl_tls13_update_traffic_secret(opssl_hmac_algo_t hash,
                                  const uint8_t *current, size_t len,
                                  uint8_t *next)
{
    if (!current || !next) {
        return OPSSL_ERROR;
    }

    size_t hash_len = hmac_hash_len(hash);
    if (hash_len == 0 || len != hash_len) {
        return OPSSL_ERROR;
    }

    return opssl_hkdf_expand_label(hash, current, len, "traffic upd",
                                   NULL, 0, next, hash_len);
}

/*
 * TLS 1.3 finished key derivation.
 * finished_key = HKDF-Expand-Label(BaseKey, "finished", "", Hash.length)
 */
int
opssl_tls13_finished_key(opssl_hmac_algo_t hash,
                         const uint8_t *base_key, size_t key_len,
                         uint8_t *finished_key)
{
    if (!base_key || !finished_key) {
        return OPSSL_ERROR;
    }

    size_t hash_len = hmac_hash_len(hash);
    if (hash_len == 0 || key_len != hash_len) {
        return OPSSL_ERROR;
    }

    return opssl_hkdf_expand_label(hash, base_key, key_len, TLS13_LABEL_FINISHED,
                                   NULL, 0, finished_key, hash_len);
}

/*
 * TLS 1.3 verify data computation.
 * verify_data = HMAC(finished_key, Transcript-Hash(Handshake Context))
 */
int
opssl_tls13_verify_data(opssl_hmac_algo_t hash,
                        const uint8_t *finished_key, size_t key_len,
                        const uint8_t *transcript_hash, size_t hash_len,
                        uint8_t *out, size_t *out_len)
{
    if (!finished_key || !transcript_hash || !out || !out_len) {
        return OPSSL_ERROR;
    }

    size_t expected_hash_len = hmac_hash_len(hash);
    if (expected_hash_len == 0 || key_len != expected_hash_len ||
        hash_len != expected_hash_len) {
        return OPSSL_ERROR;
    }

    return opssl_hmac(hash, finished_key, key_len,
                      transcript_hash, hash_len, out, out_len);
}

/*
 * Compat wrappers with the calling convention expected by tls13.c.
 */
int opssl_tls13_extract_secret(uint8_t *secret, size_t secret_len,
                               const uint8_t *salt, size_t salt_len,
                               const uint8_t *ikm, size_t ikm_len,
                               opssl_hmac_algo_t hash_algo)
{
    size_t out_len = secret_len;
    return opssl_tls13_extract(hash_algo, salt, salt_len, ikm, ikm_len,
                               secret, &out_len);
}

int opssl_tls13_derive_secret_compat(uint8_t *out, size_t out_len,
                                    const uint8_t *secret, size_t secret_len,
                                    const char *label,
                                    const uint8_t *context, size_t context_len,
                                    opssl_hmac_algo_t hash_algo)
{
    return opssl_tls13_derive_secret(hash_algo, secret, secret_len,
                                     label, context, context_len,
                                     out, out_len);
}

int opssl_tls13_hkdf_expand_label(uint8_t *out, size_t out_len,
                                  const uint8_t *secret, size_t secret_len,
                                  const char *label,
                                  const uint8_t *context, size_t context_len,
                                  opssl_hmac_algo_t hash_algo)
{
    return opssl_hkdf_expand_label(hash_algo, secret, secret_len,
                                   label, context, context_len,
                                   out, out_len);
}

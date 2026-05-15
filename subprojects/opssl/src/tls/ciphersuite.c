/*
 * opssl/tls/ciphersuite.c — cipher suite registry.
 *
 * Maps cipher suite IDs to their cryptographic parameters.
 * Supports TLS 1.3 AEAD cipher suites and TLS 1.2 ECDHE/DHE suites.
 *
 * Each cipher suite defines:
 * - AEAD algorithm (AES-GCM, ChaCha20-Poly1305, AES-CCM)
 * - Hash algorithm for PRF/HKDF
 * - Key, IV, and authentication tag lengths
 * - TLS version compatibility
 *
 * Copyright (C) 2026 ophion development team
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <opssl/crypto.h>
#include <opssl/platform.h>
#include <opssl/types.h>
#include <string.h>

typedef struct {
    opssl_ciphersuite_t id;
    const char *name;
    opssl_aead_algo_t aead;
    opssl_hmac_algo_t hash;
    size_t key_len;
    size_t iv_len;
    size_t tag_len;
    bool is_tls13;
} opssl_ciphersuite_info_t;

/* Cipher suite registry - ordered by preference (strongest first) */
static const opssl_ciphersuite_info_t cipher_suites[] = {
    /* TLS 1.3 cipher suites */
    {
        OPSSL_TLS_AES_256_GCM_SHA384,
        "TLS_AES_256_GCM_SHA384",
        OPSSL_AEAD_AES_256_GCM,
        OPSSL_HMAC_SHA384,
        32, 12, 16,
        true
    },
    {
        OPSSL_TLS_CHACHA20_POLY1305_SHA256,
        "TLS_CHACHA20_POLY1305_SHA256",
        OPSSL_AEAD_CHACHA20_POLY1305,
        OPSSL_HMAC_SHA256,
        32, 12, 16,
        true
    },
    {
        OPSSL_TLS_AES_128_GCM_SHA256,
        "TLS_AES_128_GCM_SHA256",
        OPSSL_AEAD_AES_128_GCM,
        OPSSL_HMAC_SHA256,
        16, 12, 16,
        true
    },
    {
        OPSSL_TLS_AES_128_CCM_SHA256,
        "TLS_AES_128_CCM_SHA256",
        OPSSL_AEAD_AES_128_CCM,
        OPSSL_HMAC_SHA256,
        16, 12, 16,
        true
    },
    {
        OPSSL_TLS_AES_128_CCM_8_SHA256,
        "TLS_AES_128_CCM_8_SHA256",
        OPSSL_AEAD_AES_128_CCM_8,
        OPSSL_HMAC_SHA256,
        16, 12, 8,
        true
    },
    {
        OPSSL_TLS_AES_256_CCM_SHA384,
        "TLS_AES_256_CCM_SHA384",
        OPSSL_AEAD_AES_256_CCM,
        OPSSL_HMAC_SHA384,
        32, 12, 16,
        true
    },
    {
        OPSSL_TLS_AES_256_CCM_8_SHA384,
        "TLS_AES_256_CCM_8_SHA384",
        OPSSL_AEAD_AES_256_CCM_8,
        OPSSL_HMAC_SHA384,
        32, 12, 8,
        true
    },
    {
        OPSSL_TLS_CAMELLIA_256_GCM_SHA384,
        "TLS_CAMELLIA_256_GCM_SHA384",
        OPSSL_AEAD_CAMELLIA_256_GCM,
        OPSSL_HMAC_SHA384,
        32, 12, 16,
        true
    },
    {
        OPSSL_TLS_CAMELLIA_128_GCM_SHA256,
        "TLS_CAMELLIA_128_GCM_SHA256",
        OPSSL_AEAD_CAMELLIA_128_GCM,
        OPSSL_HMAC_SHA256,
        16, 12, 16,
        true
    },

    /* TLS 1.2 ECDHE cipher suites */
    {
        OPSSL_TLS_ECDHE_ECDSA_AES_256_GCM,
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        OPSSL_AEAD_AES_256_GCM,
        OPSSL_HMAC_SHA384,
        32, 12, 16,
        false
    },
    {
        OPSSL_TLS_ECDHE_RSA_AES_256_GCM,
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        OPSSL_AEAD_AES_256_GCM,
        OPSSL_HMAC_SHA384,
        32, 12, 16,
        false
    },
    {
        OPSSL_TLS_ECDHE_ECDSA_CHACHA20,
        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        OPSSL_AEAD_CHACHA20_POLY1305,
        OPSSL_HMAC_SHA256,
        32, 12, 16,
        false
    },
    {
        OPSSL_TLS_ECDHE_RSA_CHACHA20,
        "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        OPSSL_AEAD_CHACHA20_POLY1305,
        OPSSL_HMAC_SHA256,
        32, 12, 16,
        false
    },
    {
        OPSSL_TLS_ECDHE_ECDSA_AES_128_GCM,
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        OPSSL_AEAD_AES_128_GCM,
        OPSSL_HMAC_SHA256,
        16, 12, 16,
        false
    },
    {
        OPSSL_TLS_ECDHE_RSA_AES_128_GCM,
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        OPSSL_AEAD_AES_128_GCM,
        OPSSL_HMAC_SHA256,
        16, 12, 16,
        false
    },
    {
        OPSSL_TLS_ECDHE_ECDSA_AES_256_CCM,
        "TLS_ECDHE_ECDSA_WITH_AES_256_CCM",
        OPSSL_AEAD_AES_256_CCM,
        OPSSL_HMAC_SHA256,
        32, 12, 16,
        false
    },
    {
        OPSSL_TLS_ECDHE_ECDSA_AES_128_CCM,
        "TLS_ECDHE_ECDSA_WITH_AES_128_CCM",
        OPSSL_AEAD_AES_128_CCM,
        OPSSL_HMAC_SHA256,
        16, 12, 16,
        false
    },

    /* TLS 1.2 DHE AES-CCM cipher suites */
    {
        OPSSL_TLS_DHE_RSA_AES_256_CCM,
        "TLS_DHE_RSA_WITH_AES_256_CCM",
        OPSSL_AEAD_AES_256_CCM,
        OPSSL_HMAC_SHA256,
        32, 12, 16,
        false
    },
    {
        OPSSL_TLS_DHE_RSA_AES_128_CCM,
        "TLS_DHE_RSA_WITH_AES_128_CCM",
        OPSSL_AEAD_AES_128_CCM,
        OPSSL_HMAC_SHA256,
        16, 12, 16,
        false
    },

    /* TLS 1.2 DHE AES-CCM_8 cipher suites (8-byte tag) */
    {
        OPSSL_TLS_DHE_RSA_AES_256_CCM_8,
        "TLS_DHE_RSA_WITH_AES_256_CCM_8",
        OPSSL_AEAD_AES_256_CCM_8,
        OPSSL_HMAC_SHA256,
        32, 12, 8,
        false
    },
    {
        OPSSL_TLS_DHE_RSA_AES_128_CCM_8,
        "TLS_DHE_RSA_WITH_AES_128_CCM_8",
        OPSSL_AEAD_AES_128_CCM_8,
        OPSSL_HMAC_SHA256,
        16, 12, 8,
        false
    },

    /* TLS 1.2 DHE cipher suites */
    {
        OPSSL_TLS_DHE_RSA_AES_256_GCM,
        "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
        OPSSL_AEAD_AES_256_GCM,
        OPSSL_HMAC_SHA384,
        32, 12, 16,
        false
    },
    {
        OPSSL_TLS_DHE_RSA_CHACHA20,
        "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        OPSSL_AEAD_CHACHA20_POLY1305,
        OPSSL_HMAC_SHA256,
        32, 12, 16,
        false
    },
    {
        OPSSL_TLS_DHE_RSA_AES_128_GCM,
        "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
        OPSSL_AEAD_AES_128_GCM,
        OPSSL_HMAC_SHA256,
        16, 12, 16,
        false
    },

    /* TLS 1.2 ECDHE AES-CCM_8 cipher suites (8-byte tag) */
    {
        OPSSL_TLS_ECDHE_ECDSA_AES_256_CCM_8,
        "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8",
        OPSSL_AEAD_AES_256_CCM_8,
        OPSSL_HMAC_SHA256,
        32, 12, 8,
        false
    },
    {
        OPSSL_TLS_ECDHE_ECDSA_AES_128_CCM_8,
        "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8",
        OPSSL_AEAD_AES_128_CCM_8,
        OPSSL_HMAC_SHA256,
        16, 12, 8,
        false
    },

    /* TLS 1.2 Camellia-GCM cipher suites (RFC 6367) */
    {
        OPSSL_TLS_ECDHE_ECDSA_CAMELLIA_256_GCM,
        "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384",
        OPSSL_AEAD_CAMELLIA_256_GCM,
        OPSSL_HMAC_SHA384,
        32, 12, 16,
        false
    },
    {
        OPSSL_TLS_ECDHE_RSA_CAMELLIA_256_GCM,
        "TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384",
        OPSSL_AEAD_CAMELLIA_256_GCM,
        OPSSL_HMAC_SHA384,
        32, 12, 16,
        false
    },
    {
        OPSSL_TLS_ECDHE_ECDSA_CAMELLIA_128_GCM,
        "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256",
        OPSSL_AEAD_CAMELLIA_128_GCM,
        OPSSL_HMAC_SHA256,
        16, 12, 16,
        false
    },
    {
        OPSSL_TLS_ECDHE_RSA_CAMELLIA_128_GCM,
        "TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256",
        OPSSL_AEAD_CAMELLIA_128_GCM,
        OPSSL_HMAC_SHA256,
        16, 12, 16,
        false
    },
    {
        OPSSL_TLS_DHE_RSA_CAMELLIA_256_GCM,
        "TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384",
        OPSSL_AEAD_CAMELLIA_256_GCM,
        OPSSL_HMAC_SHA384,
        32, 12, 16,
        false
    },
    {
        OPSSL_TLS_DHE_RSA_CAMELLIA_128_GCM,
        "TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256",
        OPSSL_AEAD_CAMELLIA_128_GCM,
        OPSSL_HMAC_SHA256,
        16, 12, 16,
        false
    },
};

static const size_t num_cipher_suites = sizeof(cipher_suites) / sizeof(cipher_suites[0]);

/*
 * Find cipher suite by ID.
 * Returns NULL if not found.
 */
const opssl_ciphersuite_info_t *
opssl_ciphersuite_find(opssl_ciphersuite_t id)
{
    for (size_t i = 0; i < num_cipher_suites; i++) {
        if (cipher_suites[i].id == id) {
            return &cipher_suites[i];
        }
    }
    return NULL;
}

/*
 * Find cipher suite by name.
 * Returns NULL if not found.
 */
const opssl_ciphersuite_info_t *
opssl_ciphersuite_find_by_name(const char *name)
{
    if (!name) {
        return NULL;
    }

    for (size_t i = 0; i < num_cipher_suites; i++) {
        if (strcmp(cipher_suites[i].name, name) == 0) {
            return &cipher_suites[i];
        }
    }
    return NULL;
}

/*
 * Parse a colon-separated cipher list string.
 * Example: "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256"
 *
 * Returns number of parsed cipher suites, or -1 on error.
 * Updates *count with actual number parsed.
 */
int
opssl_ciphersuite_parse_list(const char *list, opssl_ciphersuite_t *out,
                             size_t *count, size_t max)
{
    if (!list || !out || !count || max == 0) {
        return -1;
    }

    size_t parsed = 0;
    const char *start = list;
    const char *end;

    while (*start && parsed < max) {
        /* Skip whitespace */
        while (*start == ' ' || *start == '\t') {
            start++;
        }

        if (!*start) {
            break;
        }

        /* Find end of current cipher name */
        end = start;
        while (*end && *end != ':' && *end != ' ' && *end != '\t') {
            end++;
        }

        /* Extract cipher name */
        size_t name_len = end - start;
        if (name_len == 0) {
            break;
        }

        /* Copy name to null-terminated buffer */
        char name[256];
        if (name_len >= sizeof(name)) {
            /* Name too long - skip this cipher */
            start = (*end == ':') ? end + 1 : end;
            continue;
        }

        memcpy(name, start, name_len);
        name[name_len] = '\0';

        /* Look up cipher suite */
        const opssl_ciphersuite_info_t *info = opssl_ciphersuite_find_by_name(name);
        if (info) {
            out[parsed] = info->id;
            parsed++;
        }

        /* Move to next cipher */
        start = (*end == ':') ? end + 1 : end;
    }

    *count = parsed;
    return (parsed > 0) ? (int)parsed : -1;
}

/*
 * Get default TLS 1.3 cipher suite list.
 * Returns preferred order for TLS 1.3 connections.
 */
int
opssl_ciphersuite_tls13_default(opssl_ciphersuite_t *out, size_t *count, size_t max)
{
    if (!out || !count || max == 0) {
        return -1;
    }

    size_t filled = 0;

    for (size_t i = 0; i < num_cipher_suites && filled < max; i++) {
        if (cipher_suites[i].is_tls13) {
            out[filled] = cipher_suites[i].id;
            filled++;
        }
    }

    *count = filled;
    return (filled > 0) ? (int)filled : -1;
}

/*
 * Get default TLS 1.2 cipher suite list.
 * Returns preferred order for TLS 1.2 connections.
 */
int
opssl_ciphersuite_tls12_default(opssl_ciphersuite_t *out, size_t *count, size_t max)
{
    if (!out || !count || max == 0) {
        return -1;
    }

    size_t filled = 0;

    for (size_t i = 0; i < num_cipher_suites && filled < max; i++) {
        if (!cipher_suites[i].is_tls13) {
            out[filled] = cipher_suites[i].id;
            filled++;
        }
    }

    *count = filled;
    return (filled > 0) ? (int)filled : -1;
}

/*
 * Check if cipher suite is supported for given TLS version.
 */
bool
opssl_ciphersuite_is_supported(opssl_ciphersuite_t id, opssl_tls_version_t version)
{
    const opssl_ciphersuite_info_t *info = opssl_ciphersuite_find(id);
    if (!info) {
        return false;
    }

    if (version == OPSSL_TLS_1_3) {
        return info->is_tls13;
    } else if (version == OPSSL_TLS_1_2) {
        return !info->is_tls13;
    }

    return false;
}

/*
 * Get cipher suite name by ID.
 * Returns NULL if not found.
 */
const char *
opssl_ciphersuite_name(opssl_ciphersuite_t id)
{
    const opssl_ciphersuite_info_t *info = opssl_ciphersuite_find(id);
    return info ? info->name : NULL;
}

/*
 * Get cipher suite cryptographic parameters.
 */
bool
opssl_ciphersuite_get_params(opssl_ciphersuite_t id,
                             opssl_aead_algo_t *aead,
                             opssl_hmac_algo_t *hash,
                             size_t *key_len,
                             size_t *iv_len,
                             size_t *tag_len)
{
    const opssl_ciphersuite_info_t *info = opssl_ciphersuite_find(id);
    if (!info) {
        return false;
    }

    if (aead) *aead = info->aead;
    if (hash) *hash = info->hash;
    if (key_len) *key_len = info->key_len;
    if (iv_len) *iv_len = info->iv_len;
    if (tag_len) *tag_len = info->tag_len;

    return true;
}
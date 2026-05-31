/*
 * OpenSSL - X.509 Certificate Fingerprinting
 * Copyright (c) 2024 OpenSSL contributors
 */

#include <opssl/cert.h>
#include <opssl/crypto.h>
#include <opssl/platform.h>
#include <opssl/err.h>
#include <string.h>
#include <stdio.h>

/* Local compat: map OPSSL_FINGERPRINT_* names to OPSSL_FP_* */
#define OPSSL_FINGERPRINT_SHA1          OPSSL_FP_SHA1
#define OPSSL_FINGERPRINT_SHA256        OPSSL_FP_SHA256
#define OPSSL_FINGERPRINT_SHA512        OPSSL_FP_SHA512
#define OPSSL_FINGERPRINT_SHA3_256      OPSSL_FP_SHA3_256
#define OPSSL_FINGERPRINT_SHA3_512      OPSSL_FP_SHA3_512
#define OPSSL_FINGERPRINT_SPKI_SHA256   OPSSL_FP_SPKI_SHA256
#define OPSSL_FINGERPRINT_SPKI_SHA512   OPSSL_FP_SPKI_SHA512
#define OPSSL_FINGERPRINT_SPKI_SHA3_256 OPSSL_FP_SPKI_SHA3_256
#define OPSSL_FINGERPRINT_SPKI_SHA3_512 OPSSL_FP_SPKI_SHA3_512
#define OPSSL_ERR_CERT_PARSE            OPSSL_ERR_INVALID_ARGUMENT

/* Get hash function parameters */
static int get_hash_params(opssl_fingerprint_method_t method, size_t *hash_len,
                          void (**hash_func)(const void *, size_t, uint8_t *)) {
    switch (method) {
        case OPSSL_FINGERPRINT_SHA1:
            *hash_len = 20;
            *hash_func = (void (*)(const void *, size_t, uint8_t *))opssl_sha1;
            return 1;

        case OPSSL_FINGERPRINT_SHA256:
        case OPSSL_FINGERPRINT_SPKI_SHA256:
            *hash_len = 32;
            *hash_func = (void (*)(const void *, size_t, uint8_t *))opssl_sha256;
            return 1;

        case OPSSL_FINGERPRINT_SHA512:
        case OPSSL_FINGERPRINT_SPKI_SHA512:
            *hash_len = 64;
            *hash_func = (void (*)(const void *, size_t, uint8_t *))opssl_sha512;
            return 1;

        case OPSSL_FINGERPRINT_SHA3_256:
        case OPSSL_FINGERPRINT_SPKI_SHA3_256:
            *hash_len = 32;
            *hash_func = (void (*)(const void *, size_t, uint8_t *))opssl_sha3_256;
            return 1;

        case OPSSL_FINGERPRINT_SHA3_512:
        case OPSSL_FINGERPRINT_SPKI_SHA3_512:
            *hash_len = 64;
            *hash_func = (void (*)(const void *, size_t, uint8_t *))opssl_sha3_512;
            return 1;

        default:
            return 0;
    }
}

/* Check if method is SPKI-based */
static int is_spki_method(opssl_fingerprint_method_t method) {
    return (method == OPSSL_FINGERPRINT_SPKI_SHA256 ||
            method == OPSSL_FINGERPRINT_SPKI_SHA512 ||
            method == OPSSL_FINGERPRINT_SPKI_SHA3_256 ||
            method == OPSSL_FINGERPRINT_SPKI_SHA3_512);
}

/* Convert binary hash to hex string with colons */
static void hash_to_hex_string(const uint8_t *hash, size_t hash_len,
                               char *hex_out, size_t hex_len) {
    if (hex_len < (hash_len * 3)) { /* Need 2 chars + 1 colon per byte, minus last colon */
        hex_out[0] = '\0';
        return;
    }

    size_t pos = 0;
    for (size_t i = 0; i < hash_len; i++) {
        if (i > 0 && pos < hex_len - 1) {
            hex_out[pos++] = ':';
        }

        if (pos < hex_len - 2) {
            snprintf(hex_out + pos, hex_len - pos, "%02x", hash[i]);
            pos += 2;
        }
    }

    hex_out[pos] = '\0';
}

/* Validate fingerprint method */
static int validate_fingerprint_method(opssl_fingerprint_method_t method) {
    switch (method) {
        case OPSSL_FINGERPRINT_SHA1:
        case OPSSL_FINGERPRINT_SHA256:
        case OPSSL_FINGERPRINT_SHA512:
        case OPSSL_FINGERPRINT_SHA3_256:
        case OPSSL_FINGERPRINT_SHA3_512:
        case OPSSL_FINGERPRINT_SPKI_SHA256:
        case OPSSL_FINGERPRINT_SPKI_SHA512:
        case OPSSL_FINGERPRINT_SPKI_SHA3_256:
        case OPSSL_FINGERPRINT_SPKI_SHA3_512:
            return 1;
        default:
            return 0;
    }
}

/* Get required hex string buffer size for a hash length */
static size_t get_hex_buffer_size(size_t hash_len) {
    if (hash_len == 0)
        return 1; /* At least null terminator */

    /* Each byte becomes "xx:" except the last byte which becomes "xx\0" */
    return (hash_len * 3); /* 2 hex chars + 1 colon per byte, last colon becomes null terminator */
}

/* Public API functions */

int opssl_x509_fingerprint(const opssl_x509_t *cert, opssl_fingerprint_method_t method,
                           uint8_t *out, size_t *out_len) {
    if (!cert || !out || !out_len) {
        opssl_set_error(OPSSL_ERR_INVALID_ARGUMENT, "Invalid arguments");
        return 0;
    }

    if (!validate_fingerprint_method(method)) {
        opssl_set_error(OPSSL_ERR_INVALID_ARGUMENT, "Invalid fingerprint method");
        return 0;
    }

    size_t required_hash_len;
    void (*hash_func)(const void *, size_t, uint8_t *);

    if (!get_hash_params(method, &required_hash_len, &hash_func)) {
        opssl_set_error(OPSSL_ERR_INVALID_ARGUMENT, "Unsupported fingerprint method");
        return 0;
    }

    if (*out_len < required_hash_len) {
        *out_len = required_hash_len;
        opssl_set_error(OPSSL_ERR_BUFFER_TOO_SMALL, "Output buffer too small");
        return 0;
    }

    const uint8_t *data_to_hash;
    size_t data_len;

    if (is_spki_method(method)) {
        /* Hash the full DER-encoded SubjectPublicKeyInfo (including
         * the SEQUENCE tag+length) to match openssl's output. */
        extern int opssl_x509_get_spki_der(const opssl_x509_t *, const uint8_t **, size_t *);
        if (!opssl_x509_get_spki_der(cert, &data_to_hash, &data_len)) {
            opssl_set_error(OPSSL_ERR_CERT_PARSE, "Failed to get SPKI");
            return 0;
        }
    } else {
        /* Hash the full DER-encoded certificate */
        if (!opssl_x509_get_der(cert, &data_to_hash, &data_len)) {
            opssl_set_error(OPSSL_ERR_CERT_PARSE, "Failed to get DER encoding");
            return 0;
        }
    }

    /* Compute hash (SHA functions return void, always succeed) */
    hash_func(data_to_hash, data_len, out);

    *out_len = required_hash_len;
    return 1;
}

int opssl_x509_fingerprint_hex(const opssl_x509_t *cert, opssl_fingerprint_method_t method,
                               char *out, size_t out_len) {
    if (!cert || !out || out_len == 0) {
        opssl_set_error(OPSSL_ERR_INVALID_ARGUMENT, "Invalid arguments");
        return 0;
    }

    if (!validate_fingerprint_method(method)) {
        opssl_set_error(OPSSL_ERR_INVALID_ARGUMENT, "Invalid fingerprint method");
        return 0;
    }

    size_t hash_len;
    void (*hash_func)(const void *, size_t, uint8_t *);

    if (!get_hash_params(method, &hash_len, &hash_func)) {
        opssl_set_error(OPSSL_ERR_INVALID_ARGUMENT, "Unsupported fingerprint method");
        return 0;
    }

    size_t required_hex_len = get_hex_buffer_size(hash_len);
    if (out_len < required_hex_len) {
        opssl_set_error(OPSSL_ERR_BUFFER_TOO_SMALL, "Output buffer too small for hex string");
        return 0;
    }

    uint8_t hash[64]; /* Maximum hash size */
    size_t actual_hash_len = sizeof(hash);

    if (!opssl_x509_fingerprint(cert, method, hash, &actual_hash_len)) {
        /* Error already set by opssl_x509_fingerprint */
        return 0;
    }

    /* Convert binary hash to hex string with colons */
    hash_to_hex_string(hash, actual_hash_len, out, out_len);

    /* Verify the conversion was successful */
    if (strlen(out) == 0) {
        opssl_set_error(OPSSL_ERR_INTERNAL, "Hex conversion failed");
        return 0;
    }

    return 1;
}

/* Convenience function to get fingerprint size for a method */
int opssl_fingerprint_size(opssl_fingerprint_method_t method, size_t *size) {
    if (!size) {
        opssl_set_error(OPSSL_ERR_INVALID_ARGUMENT, "Invalid size pointer");
        return 0;
    }

    if (!validate_fingerprint_method(method)) {
        opssl_set_error(OPSSL_ERR_INVALID_ARGUMENT, "Invalid fingerprint method");
        return 0;
    }

    void (*hash_func)(const void *, size_t, uint8_t *);
    return get_hash_params(method, size, &hash_func);
}

/* Convenience function to get hex string size for a method */
int opssl_fingerprint_hex_size(opssl_fingerprint_method_t method, size_t *size) {
    if (!size) {
        opssl_set_error(OPSSL_ERR_INVALID_ARGUMENT, "Invalid size pointer");
        return 0;
    }

    if (!validate_fingerprint_method(method)) {
        opssl_set_error(OPSSL_ERR_INVALID_ARGUMENT, "Invalid fingerprint method");
        return 0;
    }

    size_t hash_len;
    void (*hash_func)(const void *, size_t, uint8_t *);

    if (!get_hash_params(method, &hash_len, &hash_func)) {
        return 0;
    }

    *size = get_hex_buffer_size(hash_len);
    return 1;
}

/* Compare two fingerprints for equality */
int opssl_fingerprint_compare(const uint8_t *fp1, const uint8_t *fp2,
                              opssl_fingerprint_method_t method) {
    if (!fp1 || !fp2) {
        opssl_set_error(OPSSL_ERR_INVALID_ARGUMENT, "Invalid fingerprint pointers");
        return -1;
    }

    if (!validate_fingerprint_method(method)) {
        opssl_set_error(OPSSL_ERR_INVALID_ARGUMENT, "Invalid fingerprint method");
        return -1;
    }

    size_t hash_len;
    void (*hash_func)(const void *, size_t, uint8_t *);

    if (!get_hash_params(method, &hash_len, &hash_func)) {
        return -1;
    }

    /* Constant-time equality: return 0 if equal, non-zero otherwise,
     * to retain memcmp-style semantics for existing callers. */
    return opssl_ct_eq(fp1, fp2, hash_len) ? 0 : 1;
}

/* Compare two hex fingerprints for equality (constant-time, case-insensitive). */
int opssl_fingerprint_hex_compare(const char *fp1, const char *fp2) {
    if (!fp1 || !fp2) {
        opssl_set_error(OPSSL_ERR_INVALID_ARGUMENT, "Invalid fingerprint strings");
        return -1;
    }

    size_t len1 = strlen(fp1);
    size_t len2 = strlen(fp2);
    if (len1 != len2) {
        return 1;
    }

    /* Case-insensitive constant-time compare: fold to lowercase per byte
     * and OR the differences so we always scan the full buffer. */
    unsigned diff = 0;
    for (size_t i = 0; i < len1; i++) {
        unsigned char a = (unsigned char)fp1[i];
        unsigned char b = (unsigned char)fp2[i];
        if (a >= 'A' && a <= 'Z') a = (unsigned char)(a + 32);
        if (b >= 'A' && b <= 'Z') b = (unsigned char)(b + 32);
        diff |= (unsigned)(a ^ b);
    }
    return diff == 0 ? 0 : 1;
}

/* Validate fingerprint format (hex string with colons) */
int opssl_fingerprint_hex_validate(const char *hex_fp, opssl_fingerprint_method_t method) {
    if (!hex_fp) {
        opssl_set_error(OPSSL_ERR_INVALID_ARGUMENT, "Invalid fingerprint string");
        return 0;
    }

    if (!validate_fingerprint_method(method)) {
        opssl_set_error(OPSSL_ERR_INVALID_ARGUMENT, "Invalid fingerprint method");
        return 0;
    }

    size_t hash_len;
    void (*hash_func)(const void *, size_t, uint8_t *);

    if (!get_hash_params(method, &hash_len, &hash_func)) {
        return 0;
    }

    size_t expected_len = get_hex_buffer_size(hash_len) - 1; /* Exclude null terminator */
    size_t actual_len = strlen(hex_fp);

    if (actual_len != expected_len) {
        opssl_set_error(OPSSL_ERR_INVALID_ARGUMENT, "Invalid fingerprint length");
        return 0;
    }

    /* Validate format: hex digits separated by colons */
    for (size_t i = 0; i < actual_len; i++) {
        char c = hex_fp[i];

        if (i % 3 == 2) {
            /* Should be colon (except for the last character) */
            if (i < actual_len - 1 && c != ':') {
                opssl_set_error(OPSSL_ERR_INVALID_ARGUMENT, "Invalid fingerprint format");
                return 0;
            }
        } else {
            /* Should be hex digit */
            if (!((c >= '0' && c <= '9') ||
                  (c >= 'a' && c <= 'f') ||
                  (c >= 'A' && c <= 'F'))) {
                opssl_set_error(OPSSL_ERR_INVALID_ARGUMENT, "Invalid hex character in fingerprint");
                return 0;
            }
        }
    }

    return 1;
}
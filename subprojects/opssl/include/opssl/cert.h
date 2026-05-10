/*
 * opssl/cert.h — X.509 certificate operations.
 *
 * Zero-copy certificate parsing using CRYPTO_BUFFER pools (BoringSSL idea).
 * Fingerprinting supports SHA1/256/512, SHA3, and SPKI variants.
 *
 * Copyright (C) 2026 ophion development team
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef OPSSL_CERT_H
#define OPSSL_CERT_H

#include <opssl/types.h>

/* ─── Certificate Loading ───────────────���────────────────────────────── */

/* Parse a PEM or DER certificate */
opssl_x509_t *opssl_x509_from_pem(const char *pem, size_t len);
opssl_x509_t *opssl_x509_from_der(const uint8_t *der, size_t len);
opssl_x509_t *opssl_x509_from_file(const char *path);

/* Certificate chain */
typedef struct opssl_x509_chain opssl_x509_chain_t;

opssl_x509_chain_t *opssl_x509_chain_from_file(const char *path);
opssl_x509_chain_t *opssl_x509_chain_from_leaf(const uint8_t *der, size_t der_len);
size_t              opssl_x509_chain_count(const opssl_x509_chain_t *chain);
opssl_x509_t      *opssl_x509_chain_get(const opssl_x509_chain_t *chain, size_t idx);
void               opssl_x509_chain_free(opssl_x509_chain_t *chain);

/* Reference counting */
opssl_x509_t *opssl_x509_ref(opssl_x509_t *cert);
void          opssl_x509_free(opssl_x509_t *cert);

/* ─── Certificate Information ────────────────────────────────────────── */

/* Subject / Issuer as RFC 2253 string */
int opssl_x509_get_subject(const opssl_x509_t *cert, char *buf, size_t len);
int opssl_x509_get_issuer(const opssl_x509_t *cert, char *buf, size_t len);

/* Subject Alternative Names */
int opssl_x509_get_san_count(const opssl_x509_t *cert);
int opssl_x509_get_san(const opssl_x509_t *cert, int idx, char *buf, size_t len);

/* Validity period */
int opssl_x509_get_not_before(const opssl_x509_t *cert, int64_t *epoch);
int opssl_x509_get_not_after(const opssl_x509_t *cert, int64_t *epoch);
int opssl_x509_is_expired(const opssl_x509_t *cert);

/* Serial number */
int opssl_x509_get_serial(const opssl_x509_t *cert, uint8_t *buf, size_t *len);

/* Raw DER encoding */
int opssl_x509_get_der(const opssl_x509_t *cert, const uint8_t **der, size_t *len);

/* SubjectPublicKeyInfo DER (for SPKI fingerprints) */
int opssl_x509_get_spki(const opssl_x509_t *cert, const uint8_t **spki, size_t *len);

/* ─── Fingerprinting ���────────────────────────────────────────────────── */

/*
 * Compute certificate fingerprint.
 * Supports: SHA1, SHA256, SHA512, SHA3-256, SHA3-512
 * SPKI variants hash SubjectPublicKeyInfo instead of full cert.
 */
int opssl_x509_fingerprint(const opssl_x509_t *cert,
                           opssl_fingerprint_method_t method,
                           uint8_t *out, size_t *out_len);

/* Fingerprint to hex string (null-terminated) */
int opssl_x509_fingerprint_hex(const opssl_x509_t *cert,
                               opssl_fingerprint_method_t method,
                               char *out, size_t out_len);

/* ─── Verification ──────────────────────────────────────────��────────── */

/* Certificate store (trusted CA certificates) */
typedef struct opssl_x509_store opssl_x509_store_t;

opssl_x509_store_t *opssl_x509_store_new(void);
int  opssl_x509_store_add_cert(opssl_x509_store_t *store, opssl_x509_t *cert);
int  opssl_x509_store_load_file(opssl_x509_store_t *store, const char *path);
int  opssl_x509_store_load_dir(opssl_x509_store_t *store, const char *path);
void opssl_x509_store_free(opssl_x509_store_t *store);

/* Verify a certificate chain against a store */
typedef struct {
    int  depth;           /* depth where error occurred */
    int  error_code;      /* verification error */
    const char *error_string;
    size_t chain_length;           /* number of certificates in chain */
    uint8_t leaf_fingerprint[32];  /* SHA-256 fingerprint of leaf cert */
} opssl_x509_verify_result_t;

int opssl_x509_verify(const opssl_x509_chain_t *chain,
                      const opssl_x509_store_t *store,
                      const char *hostname,
                      opssl_x509_verify_result_t *result);

/* ─��─ Private Key ───────────────��────────────────────────────────────── */

opssl_pkey_t *opssl_pkey_from_pem(const char *pem, size_t len);
opssl_pkey_t *opssl_pkey_from_der(const uint8_t *der, size_t len);
opssl_pkey_t *opssl_pkey_from_file(const char *path);
opssl_pkey_t *opssl_pkey_from_ed25519_raw(const uint8_t priv[32], const uint8_t pub[32]);
void          opssl_pkey_free(opssl_pkey_t *key);

/* Check that a private key matches a certificate */
int opssl_pkey_matches_cert(const opssl_pkey_t *key, const opssl_x509_t *cert);

/* Key type introspection */
typedef enum {
    OPSSL_PKEY_RSA,
    OPSSL_PKEY_EC,
    OPSSL_PKEY_ED25519,
    OPSSL_PKEY_ED448,
} opssl_pkey_type_t;

opssl_pkey_type_t opssl_pkey_type(const opssl_pkey_t *key);
size_t            opssl_pkey_bits(const opssl_pkey_t *key);
int               opssl_pkey_sign(const opssl_pkey_t *key, const uint8_t *digest,
                                  size_t digest_len, uint8_t *sig, size_t *sig_len);

#endif /* OPSSL_CERT_H */

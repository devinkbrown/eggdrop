/*
 * opssl/cert.h - X.509 certificate operations.
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
#include <opssl/crypto.h>

/* --- Certificate Loading ------------------------------------------------- */

opssl_x509_t *opssl_x509_from_pem(const char *pem, size_t len);
opssl_x509_t *opssl_x509_from_der(const uint8_t *der, size_t len);
opssl_x509_t *opssl_x509_from_file(const char *path);

typedef struct opssl_x509_chain opssl_x509_chain_t;

opssl_x509_chain_t *opssl_x509_chain_from_file(const char *path);
opssl_x509_chain_t *opssl_x509_chain_from_leaf(const uint8_t *der, size_t der_len);
opssl_x509_chain_t *opssl_x509_chain_from_ders(const uint8_t *der, size_t der_len,
                                                const uint8_t * const *intermediates,
                                                const size_t *ilens, size_t n_intermediates);
size_t              opssl_x509_chain_count(const opssl_x509_chain_t *chain);
opssl_x509_t       *opssl_x509_chain_get(const opssl_x509_chain_t *chain, size_t idx);
void                opssl_x509_chain_free(opssl_x509_chain_t *chain);

opssl_x509_t *opssl_x509_ref(opssl_x509_t *cert);
void          opssl_x509_free(opssl_x509_t *cert);

/* --- Certificate Information ------------------------------------------- */

int opssl_x509_get_subject(const opssl_x509_t *cert, char *buf, size_t len);
int opssl_x509_get_issuer(const opssl_x509_t *cert, char *buf, size_t len);

int opssl_x509_get_san_count(const opssl_x509_t *cert);
int opssl_x509_get_san(const opssl_x509_t *cert, int idx, char *buf, size_t len);

int opssl_x509_get_not_before(const opssl_x509_t *cert, int64_t *epoch);
int opssl_x509_get_not_after(const opssl_x509_t *cert, int64_t *epoch);
int opssl_x509_is_expired(const opssl_x509_t *cert);

int opssl_x509_get_serial(const opssl_x509_t *cert, uint8_t *buf, size_t *len);

int opssl_x509_get_der(const opssl_x509_t *cert, const uint8_t **der, size_t *len);

int opssl_x509_get_spki(const opssl_x509_t *cert, const uint8_t **spki, size_t *len);
int opssl_x509_get_spki_der(const opssl_x509_t *cert, const uint8_t **spki, size_t *len);

/* --- Fingerprinting ---------------------------------------------------- */

int opssl_x509_fingerprint(const opssl_x509_t *cert,
                           opssl_fingerprint_method_t method,
                           uint8_t *out, size_t *out_len);

int opssl_x509_fingerprint_hex(const opssl_x509_t *cert,
                               opssl_fingerprint_method_t method,
                               char *out, size_t out_len);

/* --- Verification ------------------------------------------------------- */

/* Certificate store (trusted CA certificates with CRL support) */
typedef struct opssl_x509_store opssl_x509_store_t;

opssl_x509_store_t *opssl_x509_store_new(void);
int  opssl_x509_store_add_cert(opssl_x509_store_t *store, opssl_x509_t *cert);
int  opssl_x509_store_load_file(opssl_x509_store_t *store, const char *path);
int  opssl_x509_store_load_dir(opssl_x509_store_t *store, const char *path);
void opssl_x509_store_free(opssl_x509_store_t *store);

/*
 * Trust Store - fast hash set of trusted root CA certs.
 *
 * Keyed by SHA-256(SubjectDN_raw || SPKI_DER) for O(1) lookup.
 * A chain is only accepted if its root is present here.
 */
typedef struct opssl_trust_store opssl_trust_store_t;

opssl_trust_store_t *opssl_trust_store_new(void);
void opssl_trust_store_free(opssl_trust_store_t *store);

int opssl_trust_store_load_default(opssl_trust_store_t *store);
int opssl_trust_store_load_file(opssl_trust_store_t *store, const char *path);
int opssl_trust_store_load_dir(opssl_trust_store_t *store, const char *path);
int opssl_trust_store_add_cert(opssl_trust_store_t *store,
                               const uint8_t *der, size_t len);
int opssl_trust_store_contains(const opssl_trust_store_t *store,
                               const uint8_t *cert_der, size_t cert_len);

/* Verify a certificate chain against a store */
typedef struct {
    int  depth;
    int  error_code;
    const char *error_string;
    size_t chain_length;
    uint8_t leaf_fingerprint[32];
} opssl_x509_verify_result_t;

int opssl_x509_verify(const opssl_x509_chain_t *chain,
                      const opssl_x509_store_t *store,
                      const char *hostname,
                      opssl_x509_verify_result_t *result);

/* --- CRL (Certificate Revocation List) ---------------------------------- */

typedef struct opssl_crl opssl_crl_t;

opssl_crl_t *opssl_crl_from_der(const uint8_t *der, size_t len);
opssl_crl_t *opssl_crl_from_pem(const char *pem, size_t len);
void          opssl_crl_free(opssl_crl_t *crl);

int opssl_x509_store_add_crl(opssl_x509_store_t *store, opssl_crl_t *crl);
int opssl_x509_store_load_crl(opssl_x509_store_t *store, const char *path);

/* Load a CRL from a local file path (PEM or DER auto-detected).
 * URI/HTTP fetch is intentionally not supported. Caller owns *crl_out. */
int opssl_trust_store_load_crl(const char *path, opssl_crl_t **crl_out);

int opssl_x509_check_revocation(const opssl_x509_t *cert,
                                const opssl_x509_store_t *store);

/* --- OCSP Response Verification (RFC 6960) ----------------------------- */

typedef enum {
    OPSSL_OCSP_GOOD    = 0,
    OPSSL_OCSP_REVOKED = 1,
    OPSSL_OCSP_UNKNOWN = 2,
} opssl_ocsp_status_t;

opssl_ocsp_status_t opssl_ocsp_verify_response(const uint8_t *response, size_t len,
                                               const opssl_x509_t *cert,
                                               const opssl_x509_store_t *store);

/* --- Private Key --------------------------------------------------------- */

opssl_pkey_t *opssl_pkey_from_pem(const char *pem, size_t len);
opssl_pkey_t *opssl_pkey_from_der(const uint8_t *der, size_t len);
opssl_pkey_t *opssl_pkey_from_file(const char *path);
opssl_pkey_t *opssl_pkey_from_ed25519_raw(const uint8_t priv[32], const uint8_t pub[32]);
opssl_pkey_t *opssl_pkey_from_raw_bytes(const uint8_t *bytes, size_t len);
void          opssl_pkey_free(opssl_pkey_t *key);

int opssl_pkey_matches_cert(const opssl_pkey_t *key, const opssl_x509_t *cert);

typedef enum {
    OPSSL_PKEY_RSA,
    OPSSL_PKEY_EC,
    OPSSL_PKEY_ED25519,
    OPSSL_PKEY_ED448,
} opssl_pkey_type_t;

opssl_pkey_type_t opssl_pkey_type(const opssl_pkey_t *key);
opssl_curve_t     opssl_pkey_ec_curve(const opssl_pkey_t *key);
size_t            opssl_pkey_bits(const opssl_pkey_t *key);
int               opssl_pkey_sign(const opssl_pkey_t *key, const uint8_t *digest,
                                  size_t digest_len, uint8_t *sig, size_t *sig_len);

#endif /* OPSSL_CERT_H */

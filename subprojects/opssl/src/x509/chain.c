/*
 * opssl/x509/chain.c - X.509 certificate chain loading and verification.
 *
 * Includes fixes for:
 *   - CVE-class: self-signed CA bypass in is_ca_certificate()
 *   - CVE-class: root not checked against trust store
 *   - pathLenConstraint enforcement (RFC 5280 s4.2.1.9)
 *   - keyCertSign / digitalSignature key usage enforcement
 *
 * Copyright (C) 2026 ophion development team
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <opssl/cert.h>
#include <opssl/cbs.h>
#include <opssl/crypto.h>
#include <opssl/platform.h>
#include <opssl/err.h>
#include "asn1_internal.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <dirent.h>
#include <sys/stat.h>
#include <time.h>
#include <fnmatch.h>

#define OPSSL_MAX_CERT_CHAIN 10

/* Local compat: undefined error codes and verify result constants */
#define OPSSL_ERR_STORE_FULL                 OPSSL_ERR_INVALID_ARGUMENT
#define OPSSL_VERIFY_OK                      0
#define OPSSL_VERIFY_ERROR_EMPTY_CHAIN       1
#define OPSSL_VERIFY_ERROR_HOSTNAME_MISMATCH 2
#define OPSSL_VERIFY_ERROR_INVALID_TIME      3
#define OPSSL_VERIFY_ERROR_EXPIRED           4
#define OPSSL_VERIFY_ERROR_NOT_YET_VALID     5
#define OPSSL_VERIFY_ERROR_ISSUER_NOT_FOUND  6
#define OPSSL_VERIFY_ERROR_INVALID_SIGNATURE 7
#define OPSSL_VERIFY_ERROR_UNTRUSTED_ROOT    8
#define OPSSL_VERIFY_ERROR_INVALID_CA        9
#define OPSSL_VERIFY_ERROR_REVOKED          10
#define OPSSL_VERIFY_ERROR_PATHLEN_EXCEEDED 11
#define OPSSL_VERIFY_ERROR_KEY_USAGE        12

/* Signature algorithm OIDs */
static const uint8_t oid_rsa_pss[] = {
    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0A
};
static const uint8_t oid_rsa_pkcs1_sha256[] = {
    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B
};
static const uint8_t oid_ecdsa_sha256[] = {
    0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02
};
static const uint8_t oid_ed25519[] = {
    0x2B, 0x65, 0x70
};

static int opssl_verify_signature(const uint8_t *tbs, size_t tbs_len,
                                  const uint8_t *algo, size_t algo_len,
                                  const uint8_t *sig, size_t sig_len,
                                  const uint8_t *spki, size_t spki_len)
{
    if (!tbs || !algo || !sig || !spki)
        return 0;

    uint8_t hash[32];
    opssl_sha256(tbs, tbs_len, hash);

    if (algo_len == sizeof(oid_rsa_pkcs1_sha256) &&
        opssl_ct_eq(algo, oid_rsa_pkcs1_sha256, sizeof(oid_rsa_pkcs1_sha256))) {
        opssl_rsa_ctx_t *rsa = opssl_rsa_new();
        if (!rsa) return 0;
        if (opssl_rsa_load_public_key(rsa, spki, spki_len) != 1) {
            opssl_rsa_free(rsa); return 0;
        }
        int result = opssl_rsa_verify(rsa, OPSSL_RSA_PKCS1_V15, OPSSL_HMAC_SHA256,
                                      hash, sizeof(hash), sig, sig_len);
        opssl_rsa_free(rsa);
        return result;

    } else if (algo_len == sizeof(oid_rsa_pss) &&
               opssl_ct_eq(algo, oid_rsa_pss, sizeof(oid_rsa_pss))) {
        opssl_rsa_ctx_t *rsa = opssl_rsa_new();
        if (!rsa) return 0;
        if (opssl_rsa_load_public_key(rsa, spki, spki_len) != 1) {
            opssl_rsa_free(rsa); return 0;
        }
        int result = opssl_rsa_verify(rsa, OPSSL_RSA_PSS, OPSSL_HMAC_SHA256,
                                      hash, sizeof(hash), sig, sig_len);
        opssl_rsa_free(rsa);
        return result;

    } else if (algo_len == sizeof(oid_ecdsa_sha256) &&
               opssl_ct_eq(algo, oid_ecdsa_sha256, sizeof(oid_ecdsa_sha256))) {
        opssl_cbs_t spki_cbs, alg_id, pub_bits;
        opssl_cbs_init(&spki_cbs, spki, spki_len);
        if (!opssl_asn1_get_sequence(&spki_cbs, &alg_id)) return 0;
        uint8_t pub_unused;
        if (!opssl_asn1_get_bit_string(&spki_cbs, &pub_bits, &pub_unused)) return 0;
        const uint8_t *pub_key = opssl_cbs_data(&pub_bits);
        size_t pub_key_len = opssl_cbs_len(&pub_bits);
        opssl_ecdsa_ctx_t *ecdsa = opssl_ecdsa_new(OPSSL_CURVE_P256);
        if (!ecdsa) return 0;
        if (opssl_ecdsa_set_public(ecdsa, pub_key, pub_key_len) != 1) {
            opssl_ecdsa_free(ecdsa); return 0;
        }
        int result = opssl_ecdsa_verify(ecdsa, hash, sizeof(hash), sig, sig_len);
        opssl_ecdsa_free(ecdsa);
        return result;

    } else if (algo_len == sizeof(oid_ed25519) &&
               opssl_ct_eq(algo, oid_ed25519, sizeof(oid_ed25519))) {
        if (spki_len < 32) return 0;
        return opssl_ed25519_verify(sig, tbs, tbs_len, spki + (spki_len - 32));
    }

    return 0; /* unknown algorithm */
}

/* Certificate chain structure */
struct opssl_x509_chain {
    opssl_x509_t *certs[OPSSL_MAX_CERT_CHAIN];
    size_t count;
};

/* CRL entry: one revoked serial number */
typedef struct {
    uint8_t serial[20];
    size_t  serial_len;
} opssl_crl_entry_t;

/* CRL structure */
struct opssl_crl {
    uint8_t          *der;
    size_t            der_len;
    uint8_t           issuer_hash[32];
    opssl_crl_entry_t entries[1024];
    size_t            entry_count;
    int64_t           this_update;
    int64_t           next_update;
};

#define OPSSL_MAX_CRLS 64

/* Certificate store structure */
struct opssl_x509_store {
    opssl_x509_t *trusted[256];
    size_t count;
    opssl_crl_t *crls[OPSSL_MAX_CRLS];
    size_t crl_count;
};

/* External PEM functions */
extern int opssl_pem_read_file(const char *path, uint8_t **der_out, size_t *der_len, char *label_out, size_t label_max);
extern int opssl_pem_decode_multi(const char *pem, size_t pem_len, uint8_t **ders, size_t *der_lens, size_t *count, size_t max_count);

/* Helper to check if hostname matches a pattern (with wildcard support) */
static int hostname_matches_pattern(const char *hostname, const char *pattern) {
    if (!hostname || !pattern) return 0;
    if (strcmp(hostname, pattern) == 0) return 1;
    if (pattern[0] == '*' && pattern[1] == '.') {
        const char *dot = strchr(hostname, '.');
        if (dot && strcmp(dot, pattern + 1) == 0) {
            const char *hostname_part = hostname;
            while (hostname_part < dot) {
                if (*hostname_part == '.') return 0;
                hostname_part++;
            }
            return 1;
        }
    }
    return 0;
}

static int check_hostname_match(const opssl_x509_t *cert, const char *hostname) {
    if (!cert || !hostname) return 0;
    int san_count = opssl_x509_get_san_count(cert);
    for (int i = 0; i < san_count; i++) {
        char san_buf[256];
        if (opssl_x509_get_san(cert, i, san_buf, sizeof(san_buf)) &&
            hostname_matches_pattern(hostname, san_buf))
            return 1;
    }
    char subject[512];
    if (opssl_x509_get_subject(cert, subject, sizeof(subject))) {
        char *cn_start = strstr(subject, "CN=");
        if (cn_start) {
            cn_start += 3;
            char *cn_end = strchr(cn_start, ',');
            if (cn_end) {
                char cn[256];
                size_t cn_len = cn_end - cn_start;
                if (cn_len < sizeof(cn)) {
                    memcpy(cn, cn_start, cn_len);
                    cn[cn_len] = '\0';
                    return hostname_matches_pattern(hostname, cn);
                }
            } else {
                return hostname_matches_pattern(hostname, cn_start);
            }
        }
    }
    return 0;
}

/*
 * is_ca_certificate - check if cert has BasicConstraints with cA=TRUE.
 *
 * SECURITY: RFC 5280 s4.2.1.9 requires cA=TRUE in BasicConstraints for CA
 * certificates. We DO NOT accept self-signed certs without this extension as
 * CAs. The old fallback (self-signed => CA) allowed an attacker to bypass the
 * CA check with a crafted leaf certificate.
 */
static int is_ca_certificate(const opssl_x509_t *cert) {
    const uint8_t *der;
    size_t der_len;

    if (opssl_x509_get_der(cert, &der, &der_len) != 1)
        return 0;

    opssl_cbs_t cbs, cert_seq, tbs_cert, extensions_seq, extension_seq;
    opssl_cbs_init(&cbs, der, der_len);

    if (!opssl_asn1_get_sequence(&cbs, &cert_seq)) return 0;
    if (!opssl_asn1_get_sequence(&cert_seq, &tbs_cert)) return 0;

    uint8_t tag;
    if (opssl_cbs_peek_u8(&tbs_cert, &tag) && tag == 0xA0) {
        opssl_cbs_t version;
        opssl_asn1_get_element(&tbs_cert, 0xA0, &version);
    }

    for (int i = 0; i < 6; i++) {
        if (!opssl_asn1_skip_element(&tbs_cert)) return 0;
    }

    if (!opssl_cbs_peek_u8(&tbs_cert, &tag) || tag != 0xA3)
        return 0; /* No extensions => not a CA */

    opssl_cbs_t ext_wrapper;
    if (!opssl_asn1_get_element(&tbs_cert, 0xA3, &ext_wrapper)) return 0;
    if (!opssl_asn1_get_sequence(&ext_wrapper, &extensions_seq)) return 0;

    static const uint8_t basic_constraints_oid[] = {0x55, 0x1D, 0x13};

    while (opssl_cbs_len(&extensions_seq) > 0) {
        opssl_cbs_t oid, ext_value;

        if (!opssl_asn1_get_sequence(&extensions_seq, &extension_seq)) break;
        if (!opssl_asn1_get_oid(&extension_seq, &oid)) break;

        if (opssl_cbs_peek_u8(&extension_seq, &tag) && tag == 0x01)
            opssl_asn1_skip_element(&extension_seq);

        if (!opssl_asn1_get_element(&extension_seq, 0x04, &ext_value)) break;

        if (opssl_cbs_len(&oid) == sizeof(basic_constraints_oid) &&
            opssl_ct_eq(opssl_cbs_data(&oid), basic_constraints_oid,
                        sizeof(basic_constraints_oid))) {
            opssl_cbs_t basic_constraints;
            if (opssl_asn1_get_sequence(&ext_value, &basic_constraints)) {
                if (opssl_cbs_peek_u8(&basic_constraints, &tag) && tag == 0x01) {
                    opssl_cbs_t ca_bool;
                    if (opssl_asn1_get_element(&basic_constraints, 0x01, &ca_bool)) {
                        if (opssl_cbs_len(&ca_bool) == 1 &&
                            opssl_cbs_data(&ca_bool)[0] == 0xFF)
                            return 1; /* cA = TRUE */
                    }
                }
            }
            return 0; /* cA = FALSE or absent */
        }
    }

    /*
     * BasicConstraints extension not present => not a CA.
     * NOTE: We intentionally do NOT fall back to checking whether the cert is
     * self-signed. A self-signed leaf without BasicConstraints is NOT a CA per
     * RFC 5280. The old fallback was a security vulnerability.
     */
    return 0;
}

/*
 * get_pathlen_constraint - return the pathLenConstraint value from
 * BasicConstraints, or -1 if absent or cert is not a CA.
 *
 * RFC 5280 s4.2.1.9: pathLenConstraint gives the maximum number of
 * non-self-issued intermediate CA certs that may follow this cert in the chain.
 */
static int
get_pathlen_constraint(const opssl_x509_t *cert)
{
    const uint8_t *der;
    size_t der_len;

    if (opssl_x509_get_der(cert, &der, &der_len) != 1)
        return -1;

    opssl_cbs_t cbs, cert_seq, tbs_cert, extensions_seq, extension_seq;
    opssl_cbs_init(&cbs, der, der_len);

    if (!opssl_asn1_get_sequence(&cbs, &cert_seq)) return -1;
    if (!opssl_asn1_get_sequence(&cert_seq, &tbs_cert)) return -1;

    uint8_t tag;
    if (opssl_cbs_peek_u8(&tbs_cert, &tag) && tag == 0xA0) {
        opssl_cbs_t version;
        opssl_asn1_get_element(&tbs_cert, 0xA0, &version);
    }

    for (int i = 0; i < 6; i++) {
        if (!opssl_asn1_skip_element(&tbs_cert)) return -1;
    }

    if (!opssl_cbs_peek_u8(&tbs_cert, &tag) || tag != 0xA3) return -1;

    opssl_cbs_t ext_wrapper;
    if (!opssl_asn1_get_element(&tbs_cert, 0xA3, &ext_wrapper)) return -1;
    if (!opssl_asn1_get_sequence(&ext_wrapper, &extensions_seq)) return -1;

    static const uint8_t basic_constraints_oid[] = {0x55, 0x1D, 0x13};

    while (opssl_cbs_len(&extensions_seq) > 0) {
        opssl_cbs_t oid, ext_value;

        if (!opssl_asn1_get_sequence(&extensions_seq, &extension_seq)) break;
        if (!opssl_asn1_get_oid(&extension_seq, &oid)) break;

        if (opssl_cbs_peek_u8(&extension_seq, &tag) && tag == 0x01)
            opssl_asn1_skip_element(&extension_seq);

        if (!opssl_asn1_get_element(&extension_seq, 0x04, &ext_value)) break;

        if (opssl_cbs_len(&oid) == sizeof(basic_constraints_oid) &&
            opssl_ct_eq(opssl_cbs_data(&oid), basic_constraints_oid,
                        sizeof(basic_constraints_oid))) {
            opssl_cbs_t bc;
            if (!opssl_asn1_get_sequence(&ext_value, &bc)) return -1;

            /* Skip cA BOOLEAN if present */
            if (opssl_cbs_peek_u8(&bc, &tag) && tag == 0x01)
                opssl_asn1_skip_element(&bc);

            /* pathLenConstraint INTEGER (optional) */
            if (opssl_cbs_len(&bc) > 0 &&
                opssl_cbs_peek_u8(&bc, &tag) && tag == 0x02) {
                opssl_cbs_t pathlen_int;
                if (!opssl_asn1_get_integer(&bc, &pathlen_int)) return -1;

                const uint8_t *p = opssl_cbs_data(&pathlen_int);
                size_t plen = opssl_cbs_len(&pathlen_int);

                /* Decode as non-negative integer (max fits in int for sane values) */
                if (plen == 0 || plen > 4) return -1;
                int val = 0;
                for (size_t j = 0; j < plen; j++)
                    val = (val << 8) | p[j];
                return val;
            }
            return -1; /* no pathLenConstraint */
        }
    }
    return -1;
}

/*
 * check_key_usage - verify KeyUsage bits for a certificate.
 *
 * RFC 5280 s4.2.1.3: KeyUsage extension.
 *   bit 0 (0x80): digitalSignature
 *   bit 5 (0x04): keyCertSign
 *
 * CA certs MUST have keyCertSign set.
 * End-entity TLS server certs SHOULD have digitalSignature set.
 *
 * Returns 1 if usage is consistent, 0 if KeyUsage is present and wrong.
 * Returns 1 (permissive) when KeyUsage extension is absent (optional per RFC).
 */
#define KEY_USAGE_DIGITAL_SIGNATURE 0x80  /* bit 0 of first octet */
#define KEY_USAGE_CERT_SIGN         0x04  /* bit 5 of first octet */

static int
check_key_usage(const opssl_x509_t *cert, int require_cert_sign)
{
    const uint8_t *der;
    size_t der_len;

    if (opssl_x509_get_der(cert, &der, &der_len) != 1)
        return 1; /* cannot parse => be permissive, signature will catch issues */

    opssl_cbs_t cbs, cert_seq, tbs_cert, extensions_seq, extension_seq;
    opssl_cbs_init(&cbs, der, der_len);

    if (!opssl_asn1_get_sequence(&cbs, &cert_seq)) return 1;
    if (!opssl_asn1_get_sequence(&cert_seq, &tbs_cert)) return 1;

    uint8_t tag;
    if (opssl_cbs_peek_u8(&tbs_cert, &tag) && tag == 0xA0) {
        opssl_cbs_t version;
        opssl_asn1_get_element(&tbs_cert, 0xA0, &version);
    }

    for (int i = 0; i < 6; i++) {
        if (!opssl_asn1_skip_element(&tbs_cert)) return 1;
    }

    if (!opssl_cbs_peek_u8(&tbs_cert, &tag) || tag != 0xA3)
        return 1; /* No extensions => KeyUsage absent => permissive */

    opssl_cbs_t ext_wrapper;
    if (!opssl_asn1_get_element(&tbs_cert, 0xA3, &ext_wrapper)) return 1;
    if (!opssl_asn1_get_sequence(&ext_wrapper, &extensions_seq)) return 1;

    /* KeyUsage OID: 2.5.29.15 */
    static const uint8_t key_usage_oid[] = {0x55, 0x1D, 0x0F};

    while (opssl_cbs_len(&extensions_seq) > 0) {
        opssl_cbs_t oid, ext_value;

        if (!opssl_asn1_get_sequence(&extensions_seq, &extension_seq)) break;
        if (!opssl_asn1_get_oid(&extension_seq, &oid)) break;

        if (opssl_cbs_peek_u8(&extension_seq, &tag) && tag == 0x01)
            opssl_asn1_skip_element(&extension_seq);

        if (!opssl_asn1_get_element(&extension_seq, 0x04, &ext_value)) break;

        if (opssl_cbs_len(&oid) == sizeof(key_usage_oid) &&
            opssl_ct_eq(opssl_cbs_data(&oid), key_usage_oid,
                        sizeof(key_usage_oid))) {
            /* KeyUsage is a BIT STRING */
            opssl_cbs_t ku_bits;
            uint8_t unused_bits;
            if (!opssl_asn1_get_bit_string(&ext_value, &ku_bits, &unused_bits))
                return 0;

            if (opssl_cbs_len(&ku_bits) == 0)
                return 0;

            uint8_t ku_byte = opssl_cbs_data(&ku_bits)[0];

            if (require_cert_sign) {
                /* CA cert must have keyCertSign (bit 5) */
                return (ku_byte & KEY_USAGE_CERT_SIGN) != 0 ? 1 : 0;
            } else {
                /* End-entity: digitalSignature (bit 0) */
                return (ku_byte & KEY_USAGE_DIGITAL_SIGNATURE) != 0 ? 1 : 0;
            }
        }
    }

    return 1; /* KeyUsage absent => permissive (RFC 5280 s4.2.1.3) */
}

/* Find issuer certificate in store by subject name match */
static opssl_x509_t *find_issuer(const opssl_x509_t *cert, const opssl_x509_store_t *store) {
    if (!cert || !store)
        return NULL;

    char cert_issuer[512];
    if (!opssl_x509_get_issuer(cert, cert_issuer, sizeof(cert_issuer)))
        return NULL;

    for (size_t i = 0; i < store->count; i++) {
        char ca_subject[512];
        if (opssl_x509_get_subject(store->trusted[i], ca_subject, sizeof(ca_subject))) {
            if (strcmp(cert_issuer, ca_subject) == 0)
                return store->trusted[i];
        }
    }

    return NULL;
}

/* --- Public API --- */

opssl_x509_chain_t *opssl_x509_chain_from_file(const char *path) {
    if (!path) {
        opssl_set_error(OPSSL_ERR_INVALID_ARGUMENT, "Invalid file path");
        return NULL;
    }

    FILE *file = fopen(path, "r");
    if (!file) {
        opssl_set_error(OPSSL_ERR_FILE_READ, "Cannot open certificate chain file");
        return NULL;
    }

    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    if (file_size <= 0 || file_size > 1024 * 1024) {
        fclose(file);
        opssl_set_error(OPSSL_ERR_FILE_READ, "Invalid file size");
        return NULL;
    }

    char *pem_data = malloc(file_size + 1);
    if (!pem_data) {
        fclose(file);
        opssl_set_error(OPSSL_ERR_MEMORY, "Memory allocation failed");
        return NULL;
    }

    size_t read_size = fread(pem_data, 1, file_size, file);
    pem_data[read_size] = 0;
    fclose(file);

    uint8_t *der_list[OPSSL_MAX_CERT_CHAIN];
    size_t der_lens[OPSSL_MAX_CERT_CHAIN];
    size_t count = 0;

    if (!opssl_pem_decode_multi(pem_data, read_size, der_list, der_lens, &count, OPSSL_MAX_CERT_CHAIN)) {
        free(pem_data);
        opssl_set_error(OPSSL_ERR_PEM_DECODE, "Failed to decode PEM chain");
        return NULL;
    }

    free(pem_data);

    if (count == 0 || count > OPSSL_MAX_CERT_CHAIN) {
        for (size_t i = 0; i < count; i++) free(der_list[i]);
        opssl_set_error(OPSSL_ERR_INVALID_ARGUMENT, "Invalid certificate count");
        return NULL;
    }

    opssl_x509_chain_t *chain = calloc(1, sizeof(opssl_x509_chain_t));
    if (!chain) {
        for (size_t i = 0; i < count; i++) free(der_list[i]);
        opssl_set_error(OPSSL_ERR_MEMORY, "Memory allocation failed");
        return NULL;
    }

    for (size_t i = 0; i < count; i++) {
        chain->certs[i] = opssl_x509_from_der(der_list[i], der_lens[i]);
        if (!chain->certs[i]) {
            opssl_x509_chain_free(chain);
            for (size_t j = i; j < count; j++) free(der_list[j]);
            return NULL;
        }
        chain->count++;
        free(der_list[i]);
    }

    return chain;
}

size_t opssl_x509_chain_count(const opssl_x509_chain_t *chain) {
    return chain ? chain->count : 0;
}

opssl_x509_t *opssl_x509_chain_get(const opssl_x509_chain_t *chain, size_t idx) {
    if (!chain || idx >= chain->count) {
        opssl_set_error(OPSSL_ERR_INVALID_ARGUMENT, "Invalid chain or index");
        return NULL;
    }
    return opssl_x509_ref(chain->certs[idx]);
}

opssl_x509_chain_t *opssl_x509_chain_from_leaf(const uint8_t *der, size_t der_len) {
    if (!der || der_len == 0) return NULL;
    opssl_x509_t *cert = opssl_x509_from_der(der, der_len);
    if (!cert) return NULL;
    opssl_x509_chain_t *chain = calloc(1, sizeof(opssl_x509_chain_t));
    if (!chain) { opssl_x509_free(cert); return NULL; }
    chain->certs[0] = cert;
    chain->count = 1;
    return chain;
}

void opssl_x509_chain_free(opssl_x509_chain_t *chain) {
    if (!chain) return;
    for (size_t i = 0; i < chain->count; i++)
        opssl_x509_free(chain->certs[i]);
    free(chain);
}

opssl_x509_store_t *opssl_x509_store_new(void) {
    opssl_x509_store_t *store = calloc(1, sizeof(opssl_x509_store_t));
    if (!store) {
        opssl_set_error(OPSSL_ERR_MEMORY, "Memory allocation failed");
        return NULL;
    }
    return store;
}

int opssl_x509_store_add_cert(opssl_x509_store_t *store, opssl_x509_t *cert) {
    if (!store || !cert) {
        opssl_set_error(OPSSL_ERR_INVALID_ARGUMENT, "Invalid store or certificate");
        return 0;
    }
    if (store->count >= 256) {
        opssl_set_error(OPSSL_ERR_STORE_FULL, "Certificate store is full");
        return 0;
    }
    store->trusted[store->count] = opssl_x509_ref(cert);
    store->count++;
    return 1;
}

int opssl_x509_store_load_file(opssl_x509_store_t *store, const char *path) {
    if (!store || !path) {
        opssl_set_error(OPSSL_ERR_INVALID_ARGUMENT, "Invalid store or path");
        return 0;
    }
    opssl_x509_t *cert = opssl_x509_from_file(path);
    if (!cert) return 0;
    int result = opssl_x509_store_add_cert(store, cert);
    opssl_x509_free(cert);
    return result;
}

int opssl_x509_store_load_dir(opssl_x509_store_t *store, const char *path) {
    if (!store || !path) {
        opssl_set_error(OPSSL_ERR_INVALID_ARGUMENT, "Invalid store or path");
        return 0;
    }
    DIR *dir = opendir(path);
    if (!dir) {
        opssl_set_error(OPSSL_ERR_FILE_READ, "Cannot open directory");
        return 0;
    }
    int loaded = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') continue;
        const char *ext = strrchr(entry->d_name, '.');
        if (!ext || (strcmp(ext, ".pem") != 0 && strcmp(ext, ".crt") != 0 &&
                     strcmp(ext, ".cer") != 0))
            continue;
        char full_path[1024];
        snprintf(full_path, sizeof(full_path), "%s/%s", path, entry->d_name);
        struct stat st;
        if (stat(full_path, &st) == 0 && S_ISREG(st.st_mode)) {
            if (opssl_x509_store_load_file(store, full_path))
                loaded++;
        }
    }
    closedir(dir);
    return loaded;
}

void opssl_x509_store_free(opssl_x509_store_t *store) {
    if (!store) return;
    for (size_t i = 0; i < store->count; i++)
        opssl_x509_free(store->trusted[i]);
    free(store);
}

int opssl_x509_verify(const opssl_x509_chain_t *chain, const opssl_x509_store_t *store,
                      const char *hostname, opssl_x509_verify_result_t *result) {
    if (!chain || !store || !result) {
        opssl_set_error(OPSSL_ERR_INVALID_ARGUMENT, "Invalid arguments");
        return 0;
    }

    memset(result, 0, sizeof(*result));

    if (chain->count == 0) {
        result->error_code = OPSSL_VERIFY_ERROR_EMPTY_CHAIN;
        return 0;
    }

    opssl_x509_t *leaf = chain->certs[0];

    /* 1. Hostname check */
    if (hostname && !check_hostname_match(leaf, hostname)) {
        result->error_code = OPSSL_VERIFY_ERROR_HOSTNAME_MISMATCH;
        return 0;
    }

    /* 2. Validity period for all certs in chain */
    int64_t now = time(NULL);
    for (size_t i = 0; i < chain->count; i++) {
        int64_t not_before, not_after;
        if (!opssl_x509_get_not_before(chain->certs[i], &not_before) ||
            !opssl_x509_get_not_after(chain->certs[i], &not_after)) {
            result->error_code = OPSSL_VERIFY_ERROR_INVALID_TIME;
            return 0;
        }
        if (now < not_before || now > not_after) {
            result->error_code = (now > not_after) ?
                OPSSL_VERIFY_ERROR_EXPIRED : OPSSL_VERIFY_ERROR_NOT_YET_VALID;
            return 0;
        }
    }

    /* 3. Verify chain signatures */
    opssl_x509_t *current = leaf;
    opssl_x509_t *issuer = NULL;

    for (size_t i = 0; i < chain->count; i++) {
        if (i + 1 < chain->count) {
            issuer = chain->certs[i + 1];
        } else {
            issuer = find_issuer(current, store);
            if (!issuer) {
                result->error_code = OPSSL_VERIFY_ERROR_ISSUER_NOT_FOUND;
                return 0;
            }
        }

        const uint8_t *spki;
        size_t spki_len;
        if (!opssl_x509_get_spki_der(issuer, &spki, &spki_len)) {
            result->error_code = OPSSL_VERIFY_ERROR_INVALID_SIGNATURE;
            return 0;
        }

        const uint8_t *cert_der;
        size_t cert_der_len;
        if (!opssl_x509_get_der(current, &cert_der, &cert_der_len)) {
            result->error_code = OPSSL_VERIFY_ERROR_INVALID_SIGNATURE;
            return 0;
        }

        opssl_cbs_t cert_cbs, cert_seq, tbs_cert, sig_alg_seq, sig_bits;
        opssl_cbs_init(&cert_cbs, cert_der, cert_der_len);

        if (!opssl_asn1_get_sequence(&cert_cbs, &cert_seq)) {
            result->error_code = OPSSL_VERIFY_ERROR_INVALID_SIGNATURE;
            return 0;
        }

        const uint8_t *tbs_start = opssl_cbs_data(&cert_seq);
        if (!opssl_asn1_get_sequence(&cert_seq, &tbs_cert)) {
            result->error_code = OPSSL_VERIFY_ERROR_INVALID_SIGNATURE;
            return 0;
        }
        size_t tbs_len = opssl_cbs_data(&cert_seq) - tbs_start;

        opssl_cbs_t sig_alg_oid;
        if (!opssl_asn1_get_sequence(&cert_seq, &sig_alg_seq) ||
            !opssl_asn1_get_oid(&sig_alg_seq, &sig_alg_oid)) {
            result->error_code = OPSSL_VERIFY_ERROR_INVALID_SIGNATURE;
            return 0;
        }

        uint8_t sig_unused;
        if (!opssl_asn1_get_bit_string(&cert_seq, &sig_bits, &sig_unused)) {
            result->error_code = OPSSL_VERIFY_ERROR_INVALID_SIGNATURE;
            return 0;
        }

        if (!opssl_verify_signature(tbs_start, tbs_len,
                                    opssl_cbs_data(&sig_alg_oid), opssl_cbs_len(&sig_alg_oid),
                                    opssl_cbs_data(&sig_bits), opssl_cbs_len(&sig_bits),
                                    spki, spki_len)) {
            result->error_code = OPSSL_VERIFY_ERROR_INVALID_SIGNATURE;
            return 0;
        }

        current = issuer;
    }

    /*
     * 4. Trust anchor check.
     *
     * After the signature loop, current == the cert returned by find_issuer()
     * on the final iteration, which is a member of store->trusted[].  However
     * we explicitly re-verify trust store membership here to guard against any
     * future refactoring of the loop logic above.
     *
     * SECURITY: We require that the root is explicitly in the trust store AND
     * that it is a proper CA cert (BasicConstraints cA=TRUE per RFC 5280).
     * Self-signed status alone is NOT sufficient.
     */
    const uint8_t *root_der;
    size_t root_der_len;
    if (!opssl_x509_get_der(current, &root_der, &root_der_len)) {
        result->error_code = OPSSL_VERIFY_ERROR_UNTRUSTED_ROOT;
        return 0;
    }

    /* Verify root is explicitly in store->trusted[] (not just subject-matched) */
    bool root_in_store = false;
    for (size_t i = 0; i < store->count; i++) {
        const uint8_t *tder;
        size_t tder_len;
        if (opssl_x509_get_der(store->trusted[i], &tder, &tder_len) &&
            tder_len == root_der_len &&
            memcmp(tder, root_der, root_der_len) == 0) {
            root_in_store = true;
            break;
        }
    }
    if (!root_in_store) {
        result->error_code = OPSSL_VERIFY_ERROR_UNTRUSTED_ROOT;
        return 0;
    }

    /* Root must be a proper CA (BasicConstraints cA=TRUE) */
    if (!is_ca_certificate(current)) {
        result->error_code = OPSSL_VERIFY_ERROR_UNTRUSTED_ROOT;
        return 0;
    }

    /* Root must have keyCertSign in KeyUsage if the extension is present */
    if (!check_key_usage(current, 1)) {
        result->error_code = OPSSL_VERIFY_ERROR_KEY_USAGE;
        return 0;
    }

    /* 5. Intermediate CA validity checks */
    for (size_t i = 1; i < chain->count; i++) {
        /* Must have BasicConstraints cA=TRUE */
        if (!is_ca_certificate(chain->certs[i])) {
            result->error_code = OPSSL_VERIFY_ERROR_INVALID_CA;
            return 0;
        }
        /* Must have keyCertSign in KeyUsage if present */
        if (!check_key_usage(chain->certs[i], 1)) {
            result->error_code = OPSSL_VERIFY_ERROR_KEY_USAGE;
            return 0;
        }
    }

    /* 6. pathLenConstraint enforcement (RFC 5280 s4.2.1.9).
     *
     * pathLenConstraint on a CA cert at depth D limits the number of
     * non-self-issued intermediate CAs below it to at most pathLen.
     * Depth 0 = leaf, depth N = root.
     *
     * chain->certs[] is ordered [leaf, ..., root-or-intermediate].
     * Intermediates are at indices 1..chain->count-1.
     * For each intermediate at index i, the CA that issued it is at i+1
     * (or the store root for the last intermediate).
     * The number of additional intermediates below the issuer is (i-1).
     */
    for (size_t i = 1; i < chain->count; i++) {
        int pathlen = get_pathlen_constraint(chain->certs[i]);
        if (pathlen < 0) continue; /* no constraint */

        /* Number of non-self-issued intermediates below certs[i] = i-1 */
        if ((int)(i - 1) > pathlen) {
            result->error_code = OPSSL_VERIFY_ERROR_PATHLEN_EXCEEDED;
            return 0;
        }
    }
    /* Also enforce pathLenConstraint on the root */
    {
        int pathlen = get_pathlen_constraint(current);
        if (pathlen >= 0 && (int)(chain->count - 1) > pathlen) {
            result->error_code = OPSSL_VERIFY_ERROR_PATHLEN_EXCEEDED;
            return 0;
        }
    }

    /* 7. Leaf key usage: digitalSignature for TLS server auth */
    if (!check_key_usage(leaf, 0)) {
        result->error_code = OPSSL_VERIFY_ERROR_KEY_USAGE;
        return 0;
    }

    /* 8. CRL revocation check */
    if (store->crl_count > 0) {
        if (!opssl_x509_check_revocation(leaf, store)) {
            result->error_code = OPSSL_VERIFY_ERROR_REVOKED;
            return 0;
        }
    }

    result->error_code = OPSSL_VERIFY_OK;
    result->chain_length = chain->count;

    const uint8_t *der;
    size_t der_len;
    if (opssl_x509_get_der(leaf, &der, &der_len))
        opssl_sha256(der, der_len, result->leaf_fingerprint);

    return 1;
}

/* --- CRL Implementation --- */

opssl_crl_t *
opssl_crl_from_der(const uint8_t *der, size_t len)
{
    if (!der || len == 0) return NULL;

    opssl_crl_t *crl = op_calloc(1, sizeof(*crl));

    crl->der = op_malloc(len);
    memcpy(crl->der, der, len);
    crl->der_len = len;

    opssl_cbs_t cbs, crl_seq, tbs_seq;
    opssl_cbs_init(&cbs, der, len);

    if (!opssl_asn1_get_sequence(&cbs, &crl_seq) ||
        !opssl_asn1_get_sequence(&crl_seq, &tbs_seq))
        goto parse_done;

    if (opssl_cbs_len(&tbs_seq) > 0 &&
        opssl_cbs_data(&tbs_seq)[0] == 0x02) {
        opssl_cbs_t ver;
        opssl_asn1_get_integer(&tbs_seq, &ver);
    }

    opssl_cbs_t sig_alg;
    if (!opssl_asn1_get_sequence(&tbs_seq, &sig_alg)) goto parse_done;

    const uint8_t *issuer_start = opssl_cbs_data(&tbs_seq);
    opssl_cbs_t issuer_name;
    if (!opssl_asn1_get_sequence(&tbs_seq, &issuer_name)) goto parse_done;
    size_t issuer_len = opssl_cbs_data(&tbs_seq) - issuer_start;
    opssl_sha256(issuer_start, issuer_len, crl->issuer_hash);

    if (!opssl_asn1_get_time(&tbs_seq, &crl->this_update)) goto parse_done;

    if (opssl_cbs_len(&tbs_seq) > 0) {
        uint8_t peek = opssl_cbs_data(&tbs_seq)[0];
        if (peek == 0x17 || peek == 0x18)
            opssl_asn1_get_time(&tbs_seq, &crl->next_update);
    }

    if (opssl_cbs_len(&tbs_seq) > 0 &&
        opssl_cbs_data(&tbs_seq)[0] == 0x30) {
        opssl_cbs_t revoked_seq;
        if (opssl_asn1_get_sequence(&tbs_seq, &revoked_seq)) {
            while (opssl_cbs_len(&revoked_seq) > 0 &&
                   crl->entry_count < 1024) {
                opssl_cbs_t entry;
                if (!opssl_asn1_get_sequence(&revoked_seq, &entry)) break;
                opssl_cbs_t serial_int;
                if (!opssl_asn1_get_integer(&entry, &serial_int)) break;
                size_t slen = opssl_cbs_len(&serial_int);
                if (slen > 20) slen = 20;
                opssl_crl_entry_t *e = &crl->entries[crl->entry_count];
                memcpy(e->serial, opssl_cbs_data(&serial_int), slen);
                e->serial_len = slen;
                crl->entry_count++;
            }
        }
    }

parse_done:
    return crl;
}

opssl_crl_t *
opssl_crl_from_pem(const char *pem, size_t len)
{
    if (!pem || len == 0) return NULL;
    size_t count = 0;
    uint8_t *ders[1];
    size_t lens[1];
    if (!opssl_pem_decode_multi(pem, len, ders, lens, &count, 1) || count == 0)
        return NULL;
    opssl_crl_t *crl = opssl_crl_from_der(ders[0], lens[0]);
    op_free(ders[0]);
    return crl;
}

void
opssl_crl_free(opssl_crl_t *crl)
{
    if (!crl) return;
    op_free(crl->der);
    op_free(crl);
}

int
opssl_x509_store_add_crl(opssl_x509_store_t *store, opssl_crl_t *crl)
{
    if (!store || !crl || store->crl_count >= OPSSL_MAX_CRLS) return 0;
    store->crls[store->crl_count++] = crl;
    return 1;
}

int
opssl_x509_store_load_crl(opssl_x509_store_t *store, const char *path)
{
    if (!store || !path) return 0;
    uint8_t *der = NULL;
    size_t der_len = 0;
    char label[64] = {0};
    if (!opssl_pem_read_file(path, &der, &der_len, label, sizeof(label)))
        return 0;
    opssl_crl_t *crl = opssl_crl_from_der(der, der_len);
    op_free(der);
    if (!crl) return 0;
    if (!opssl_x509_store_add_crl(store, crl)) {
        opssl_crl_free(crl);
        return 0;
    }
    return 1;
}

int
opssl_x509_check_revocation(const opssl_x509_t *cert,
                            const opssl_x509_store_t *store)
{
    if (!cert || !store) return 0;

    uint8_t cert_serial[20];
    size_t cert_serial_len = sizeof(cert_serial);
    if (!opssl_x509_get_serial(cert, cert_serial, &cert_serial_len))
        return 1;

    const uint8_t *cert_der;
    size_t cert_der_len;
    if (!opssl_x509_get_der(cert, &cert_der, &cert_der_len))
        return 1;

    opssl_cbs_t cbs, cert_seq, tbs;
    opssl_cbs_init(&cbs, cert_der, cert_der_len);
    if (!opssl_asn1_get_sequence(&cbs, &cert_seq) ||
        !opssl_asn1_get_sequence(&cert_seq, &tbs))
        return 1;

    if (opssl_cbs_len(&tbs) > 0 &&
        opssl_cbs_data(&tbs)[0] == 0xA0) {
        opssl_cbs_t ver_ctx;
        opssl_asn1_get_element(&tbs, 0xA0, &ver_ctx);
    }

    opssl_cbs_t serial_skip;
    if (!opssl_asn1_get_integer(&tbs, &serial_skip)) return 1;

    opssl_cbs_t sig_skip;
    if (!opssl_asn1_get_sequence(&tbs, &sig_skip)) return 1;

    const uint8_t *issuer_start = opssl_cbs_data(&tbs);
    opssl_cbs_t issuer_name;
    if (!opssl_asn1_get_sequence(&tbs, &issuer_name)) return 1;
    size_t issuer_len = opssl_cbs_data(&tbs) - issuer_start;

    uint8_t issuer_hash[32];
    opssl_sha256(issuer_start, issuer_len, issuer_hash);

    int64_t now = time(NULL);

    for (size_t c = 0; c < store->crl_count; c++) {
        const opssl_crl_t *crl = store->crls[c];
        if (memcmp(crl->issuer_hash, issuer_hash, 32) != 0) continue;
        if (crl->next_update > 0 && now > crl->next_update) continue;
        for (size_t e = 0; e < crl->entry_count; e++) {
            const opssl_crl_entry_t *entry = &crl->entries[e];
            if (entry->serial_len == cert_serial_len &&
                memcmp(entry->serial, cert_serial, cert_serial_len) == 0)
                return 0;
        }
    }

    return 1;
}

/* --- OCSP Response Verification (RFC 6960) --- */

static const uint8_t oid_ocsp_basic[] = {
    0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01
};

opssl_ocsp_status_t
opssl_ocsp_verify_response(const uint8_t *response, size_t len,
                           const opssl_x509_t *cert,
                           const opssl_x509_store_t *store)
{
    if (!response || len == 0 || !cert)
        return OPSSL_OCSP_UNKNOWN;

    opssl_cbs_t cbs, resp_seq;
    opssl_cbs_init(&cbs, response, len);
    if (!opssl_asn1_get_sequence(&cbs, &resp_seq))
        return OPSSL_OCSP_UNKNOWN;

    opssl_cbs_t status_enum;
    if (!opssl_asn1_get_element(&resp_seq, 0x0A, &status_enum) ||
        opssl_cbs_len(&status_enum) != 1 ||
        opssl_cbs_data(&status_enum)[0] != 0)
        return OPSSL_OCSP_UNKNOWN;

    opssl_cbs_t resp_bytes_ctx, resp_bytes;
    if (!opssl_asn1_get_element(&resp_seq, 0xA0, &resp_bytes_ctx) ||
        !opssl_asn1_get_sequence(&resp_bytes_ctx, &resp_bytes))
        return OPSSL_OCSP_UNKNOWN;

    opssl_cbs_t resp_type_oid;
    if (!opssl_asn1_get_oid(&resp_bytes, &resp_type_oid) ||
        !opssl_asn1_oid_equal(&resp_type_oid, oid_ocsp_basic, sizeof(oid_ocsp_basic)))
        return OPSSL_OCSP_UNKNOWN;

    opssl_cbs_t basic_octet;
    if (!opssl_asn1_get_octet_string(&resp_bytes, &basic_octet))
        return OPSSL_OCSP_UNKNOWN;

    opssl_cbs_t basic_inner, basic_seq;
    opssl_cbs_init(&basic_inner, opssl_cbs_data(&basic_octet), opssl_cbs_len(&basic_octet));
    if (!opssl_asn1_get_sequence(&basic_inner, &basic_seq))
        return OPSSL_OCSP_UNKNOWN;

    const uint8_t *tbs_start = opssl_cbs_data(&basic_seq);
    opssl_cbs_t tbs_resp;
    if (!opssl_asn1_get_sequence(&basic_seq, &tbs_resp))
        return OPSSL_OCSP_UNKNOWN;
    size_t tbs_len = opssl_cbs_data(&basic_seq) - tbs_start;

    opssl_cbs_t sig_alg_seq, sig_alg_oid, sig_bits;
    uint8_t sig_unused;
    if (!opssl_asn1_get_sequence(&basic_seq, &sig_alg_seq) ||
        !opssl_asn1_get_oid(&sig_alg_seq, &sig_alg_oid) ||
        !opssl_asn1_get_bit_string(&basic_seq, &sig_bits, &sig_unused))
        return OPSSL_OCSP_UNKNOWN;

    if (opssl_cbs_len(&tbs_resp) > 0 &&
        opssl_cbs_data(&tbs_resp)[0] == 0xA0) {
        opssl_cbs_t ver;
        opssl_asn1_get_element(&tbs_resp, 0xA0, &ver);
    }

    if (opssl_cbs_len(&tbs_resp) == 0) return OPSSL_OCSP_UNKNOWN;
    uint8_t rid_tag = opssl_cbs_data(&tbs_resp)[0];
    if (rid_tag == 0xA1 || rid_tag == 0xA2) {
        opssl_cbs_t rid;
        opssl_asn1_get_element(&tbs_resp, rid_tag, &rid);
    } else {
        return OPSSL_OCSP_UNKNOWN;
    }

    int64_t produced_at;
    if (!opssl_asn1_get_time(&tbs_resp, &produced_at))
        return OPSSL_OCSP_UNKNOWN;

    opssl_cbs_t responses;
    if (!opssl_asn1_get_sequence(&tbs_resp, &responses))
        return OPSSL_OCSP_UNKNOWN;

    uint8_t target_serial[20];
    size_t target_serial_len = sizeof(target_serial);
    if (!opssl_x509_get_serial(cert, target_serial, &target_serial_len))
        return OPSSL_OCSP_UNKNOWN;

    opssl_ocsp_status_t result = OPSSL_OCSP_UNKNOWN;

    while (opssl_cbs_len(&responses) > 0) {
        opssl_cbs_t single_resp;
        if (!opssl_asn1_get_sequence(&responses, &single_resp)) break;

        opssl_cbs_t cert_id;
        if (!opssl_asn1_get_sequence(&single_resp, &cert_id)) break;

        opssl_cbs_t hash_alg, name_hash, key_hash, resp_serial;
        if (!opssl_asn1_get_sequence(&cert_id, &hash_alg) ||
            !opssl_asn1_get_octet_string(&cert_id, &name_hash) ||
            !opssl_asn1_get_octet_string(&cert_id, &key_hash) ||
            !opssl_asn1_get_integer(&cert_id, &resp_serial))
            break;

        if (opssl_cbs_len(&resp_serial) != target_serial_len ||
            memcmp(opssl_cbs_data(&resp_serial), target_serial, target_serial_len) != 0)
            continue;

        if (opssl_cbs_len(&single_resp) == 0) break;
        uint8_t status_tag = opssl_cbs_data(&single_resp)[0] & 0x1F;
        if (status_tag == 0) result = OPSSL_OCSP_GOOD;
        else if (status_tag == 1) result = OPSSL_OCSP_REVOKED;
        else result = OPSSL_OCSP_UNKNOWN;
        break;
    }

    if (result == OPSSL_OCSP_GOOD && store) {
        bool sig_verified = false;

        if (opssl_cbs_len(&basic_seq) > 0 &&
            opssl_cbs_data(&basic_seq)[0] == 0xA0) {
            opssl_cbs_t certs_ctx, certs_seq;
            if (opssl_asn1_get_element(&basic_seq, 0xA0, &certs_ctx) &&
                opssl_asn1_get_sequence(&certs_ctx, &certs_seq) &&
                opssl_cbs_len(&certs_seq) > 0) {
                const uint8_t *rc_start = opssl_cbs_data(&certs_seq);
                opssl_cbs_t rc_seq;
                if (opssl_asn1_get_sequence(&certs_seq, &rc_seq)) {
                    size_t rc_len = opssl_cbs_data(&certs_seq) - rc_start;
                    opssl_x509_t *rc = opssl_x509_from_der(rc_start, rc_len);
                    if (rc) {
                        const uint8_t *spki;
                        size_t spki_len;
                        if (opssl_x509_get_spki_der(rc, &spki, &spki_len)) {
                            sig_verified = opssl_verify_signature(
                                tbs_start, tbs_len,
                                opssl_cbs_data(&sig_alg_oid), opssl_cbs_len(&sig_alg_oid),
                                opssl_cbs_data(&sig_bits), opssl_cbs_len(&sig_bits),
                                spki, spki_len);
                        }
                        opssl_x509_free(rc);
                    }
                }
            }
        }

        if (!sig_verified) {
            for (size_t i = 0; i < store->count; i++) {
                const uint8_t *spki;
                size_t spki_len;
                if (opssl_x509_get_spki_der(store->trusted[i], &spki, &spki_len) &&
                    opssl_verify_signature(tbs_start, tbs_len,
                                           opssl_cbs_data(&sig_alg_oid), opssl_cbs_len(&sig_alg_oid),
                                           opssl_cbs_data(&sig_bits), opssl_cbs_len(&sig_bits),
                                           spki, spki_len)) {
                    sig_verified = true;
                    break;
                }
            }
        }

        if (!sig_verified) result = OPSSL_OCSP_UNKNOWN;
    }

    return result;
}

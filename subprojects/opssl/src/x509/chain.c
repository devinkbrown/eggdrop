/*
 * OpenSSL - X.509 Certificate Chain Loading and Verification
 * Copyright (c) 2024 OpenSSL contributors
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

/* Signature algorithm OIDs */
static const uint8_t oid_rsa_pss[] = {
    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0A  /* 1.2.840.113549.1.1.10 */
};
static const uint8_t oid_rsa_pkcs1_sha256[] = {
    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B  /* 1.2.840.113549.1.1.11 */
};
static const uint8_t oid_ecdsa_sha256[] = {
    0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02  /* 1.2.840.10045.4.3.2 */
};
static const uint8_t oid_ed25519[] = {
    0x2B, 0x65, 0x70  /* 1.3.101.112 */
};

/* opssl_verify_signature is not in the public API; implement it here */
static int opssl_verify_signature(const uint8_t *tbs, size_t tbs_len,
                                  const uint8_t *algo, size_t algo_len,
                                  const uint8_t *sig, size_t sig_len,
                                  const uint8_t *spki, size_t spki_len)
{
    if (!tbs || !algo || !sig || !spki) {
        return 0;
    }

    /* Hash TBSCertificate with SHA-256 (most common) */
    uint8_t hash[32];
    opssl_sha256(tbs, tbs_len, hash);

    /* Determine signature algorithm and verify */
    if (algo_len == sizeof(oid_rsa_pkcs1_sha256) &&
        opssl_ct_eq(algo, oid_rsa_pkcs1_sha256, sizeof(oid_rsa_pkcs1_sha256))) {
        /* RSA PKCS#1 v1.5 with SHA-256 */
        opssl_rsa_ctx_t *rsa = opssl_rsa_new();
        if (!rsa) return 0;

        if (opssl_rsa_load_public_key(rsa, spki, spki_len) != 1) {
            opssl_rsa_free(rsa);
            return 0;
        }

        int result = opssl_rsa_verify(rsa, OPSSL_RSA_PKCS1_V15, OPSSL_HMAC_SHA256,
                                      hash, sizeof(hash), sig, sig_len);
        opssl_rsa_free(rsa);
        return result;

    } else if (algo_len == sizeof(oid_rsa_pss) &&
               opssl_ct_eq(algo, oid_rsa_pss, sizeof(oid_rsa_pss))) {
        /* RSA-PSS */
        opssl_rsa_ctx_t *rsa = opssl_rsa_new();
        if (!rsa) return 0;

        if (opssl_rsa_load_public_key(rsa, spki, spki_len) != 1) {
            opssl_rsa_free(rsa);
            return 0;
        }

        int result = opssl_rsa_verify(rsa, OPSSL_RSA_PSS, OPSSL_HMAC_SHA256,
                                      hash, sizeof(hash), sig, sig_len);
        opssl_rsa_free(rsa);
        return result;

    } else if (algo_len == sizeof(oid_ecdsa_sha256) &&
               opssl_ct_eq(algo, oid_ecdsa_sha256, sizeof(oid_ecdsa_sha256))) {
        /* ECDSA with SHA-256 — extract raw public key from SPKI content */
        opssl_cbs_t spki_cbs, alg_id, pub_bits;
        opssl_cbs_init(&spki_cbs, spki, spki_len);

        /* Skip AlgorithmIdentifier SEQUENCE */
        if (!opssl_asn1_get_sequence(&spki_cbs, &alg_id))
            return 0;

        /* Parse BIT STRING containing the public key */
        uint8_t pub_unused;
        if (!opssl_asn1_get_bit_string(&spki_cbs, &pub_bits, &pub_unused))
            return 0;

        const uint8_t *pub_key = opssl_cbs_data(&pub_bits);
        size_t pub_key_len = opssl_cbs_len(&pub_bits);

        opssl_ecdsa_ctx_t *ecdsa = opssl_ecdsa_new(OPSSL_CURVE_P256);
        if (!ecdsa) return 0;

        if (opssl_ecdsa_set_public(ecdsa, pub_key, pub_key_len) != 1) {
            opssl_ecdsa_free(ecdsa);
            return 0;
        }

        int result = opssl_ecdsa_verify(ecdsa, hash, sizeof(hash), sig, sig_len);
        opssl_ecdsa_free(ecdsa);
        return result;

    } else if (algo_len == sizeof(oid_ed25519) &&
               opssl_ct_eq(algo, oid_ed25519, sizeof(oid_ed25519))) {
        /* Ed25519 - no pre-hashing needed */
        if (spki_len < 32) return 0;
        return opssl_ed25519_verify(sig, tbs, tbs_len, spki + (spki_len - 32));

    } else {
        /* Unknown signature algorithm */
        return 0;
    }
}

/* Certificate chain structure */
struct opssl_x509_chain {
    opssl_x509_t *certs[OPSSL_MAX_CERT_CHAIN]; /* 10 max */
    size_t count;
};

/* Certificate store structure */
struct opssl_x509_store {
    opssl_x509_t *trusted[256];  /* trusted CA certs */
    size_t count;
};

/* External PEM functions */
extern int opssl_pem_read_file(const char *path, uint8_t **der_out, size_t *der_len, char *label_out, size_t label_max);
extern int opssl_pem_decode_multi(const char *pem, size_t pem_len, uint8_t **ders, size_t *der_lens, size_t *count, size_t max_count);


/* Helper to check if hostname matches a pattern (with wildcard support) */
static int hostname_matches_pattern(const char *hostname, const char *pattern) {
    if (!hostname || !pattern)
        return 0;

    /* Exact match */
    if (strcmp(hostname, pattern) == 0)
        return 1;

    /* Wildcard match - only support *.domain.com format */
    if (pattern[0] == '*' && pattern[1] == '.') {
        const char *dot = strchr(hostname, '.');
        if (dot && strcmp(dot, pattern + 1) == 0) {
            /* Ensure there's no additional dot before the matched portion */
            const char *hostname_part = hostname;
            while (hostname_part < dot) {
                if (*hostname_part == '.')
                    return 0; /* Multiple subdomains not allowed */
                hostname_part++;
            }
            return 1;
        }
    }

    return 0;
}

/* Check if certificate hostname matches */
static int check_hostname_match(const opssl_x509_t *cert, const char *hostname) {
    if (!cert || !hostname)
        return 0;

    /* Check Subject Alternative Names first */
    int san_count = opssl_x509_get_san_count(cert);
    for (int i = 0; i < san_count; i++) {
        char san_buf[256];
        if (opssl_x509_get_san(cert, i, san_buf, sizeof(san_buf)) &&
            hostname_matches_pattern(hostname, san_buf))
            return 1;
    }

    /* If no SANs, check Common Name in subject
     * This is a simplified implementation - would need full DN parsing */
    char subject[512];
    if (opssl_x509_get_subject(cert, subject, sizeof(subject))) {
        /* Look for CN= in subject string */
        char *cn_start = strstr(subject, "CN=");
        if (cn_start) {
            cn_start += 3; /* Skip "CN=" */
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
                /* CN is at the end */
                return hostname_matches_pattern(hostname, cn_start);
            }
        }
    }

    return 0;
}

/* Check if certificate is a CA certificate */
static int is_ca_certificate(const opssl_x509_t *cert) {
    const uint8_t *der;
    size_t der_len;

    if (opssl_x509_get_der(cert, &der, &der_len) != 1) {
        return 0;
    }

    /* Parse certificate to find Basic Constraints extension */
    opssl_cbs_t cbs, cert_seq, tbs_cert, extensions_seq, extension_seq;
    opssl_cbs_init(&cbs, der, der_len);

    if (!opssl_asn1_get_sequence(&cbs, &cert_seq)) return 0;
    if (!opssl_asn1_get_sequence(&cert_seq, &tbs_cert)) return 0;

    /* Skip version [0], serial number, signature algorithm, issuer, validity, subject, SPKI */
    uint8_t tag;
    if (opssl_cbs_peek_u8(&tbs_cert, &tag) && tag == 0xA0) {
        opssl_cbs_t version;
        opssl_asn1_get_element(&tbs_cert, 0xA0, &version);
    }

    /* Skip serial, signature algorithm, issuer, validity, subject, SPKI */
    for (int i = 0; i < 6; i++) {
        if (!opssl_asn1_skip_element(&tbs_cert)) return 0;
    }

    /* Look for extensions [3] */
    if (!opssl_cbs_peek_u8(&tbs_cert, &tag) || tag != 0xA3) {
        return 0; /* No extensions */
    }

    opssl_cbs_t ext_wrapper;
    if (!opssl_asn1_get_element(&tbs_cert, 0xA3, &ext_wrapper)) return 0;
    if (!opssl_asn1_get_sequence(&ext_wrapper, &extensions_seq)) return 0;

    /* Basic Constraints OID: 2.5.29.19 */
    static const uint8_t basic_constraints_oid[] = {0x55, 0x1D, 0x13};

    while (opssl_cbs_len(&extensions_seq) > 0) {
        opssl_cbs_t oid, ext_value;

        if (!opssl_asn1_get_sequence(&extensions_seq, &extension_seq)) break;
        if (!opssl_asn1_get_oid(&extension_seq, &oid)) break;

        /* Skip critical flag if present */
        if (opssl_cbs_peek_u8(&extension_seq, &tag) && tag == 0x01) {
            opssl_asn1_skip_element(&extension_seq);
        }

        if (!opssl_asn1_get_element(&extension_seq, 0x04, &ext_value)) break;

        /* Check if this is Basic Constraints */
        if (opssl_cbs_len(&oid) == sizeof(basic_constraints_oid) &&
            opssl_ct_eq(opssl_cbs_data(&oid), basic_constraints_oid, sizeof(basic_constraints_oid))) {

            /* Parse Basic Constraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE, ... } */
            opssl_cbs_t basic_constraints;
            if (opssl_asn1_get_sequence(&ext_value, &basic_constraints)) {
                /* Check if cA boolean is present and TRUE */
                if (opssl_cbs_peek_u8(&basic_constraints, &tag) && tag == 0x01) {
                    opssl_cbs_t ca_bool;
                    if (opssl_asn1_get_element(&basic_constraints, 0x01, &ca_bool)) {
                        if (opssl_cbs_len(&ca_bool) == 1 && opssl_cbs_data(&ca_bool)[0] == 0xFF) {
                            return 1; /* cA = TRUE */
                        }
                    }
                }
            }
            return 0; /* cA = FALSE or absent */
        }
    }

    /* Fallback: self-signed certificates are typically CAs */
    char subject[512], issuer[512];
    if (opssl_x509_get_subject(cert, subject, sizeof(subject)) &&
        opssl_x509_get_issuer(cert, issuer, sizeof(issuer))) {
        return strcmp(subject, issuer) == 0;
    }

    return 0;
}

/* Find issuer certificate in store */
static opssl_x509_t *find_issuer(const opssl_x509_t *cert, const opssl_x509_store_t *store) {
    if (!cert || !store)
        return NULL;

    char cert_issuer[512];
    if (!opssl_x509_get_issuer(cert, cert_issuer, sizeof(cert_issuer)))
        return NULL;

    for (size_t i = 0; i < store->count; i++) {
        char ca_subject[512];
        if (opssl_x509_get_subject(store->trusted[i], ca_subject, sizeof(ca_subject))) {
            if (strcmp(cert_issuer, ca_subject) == 0) {
                return store->trusted[i];
            }
        }
    }

    return NULL;
}

/* Public API functions */

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

    /* Read entire file */
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    if (file_size <= 0 || file_size > 1024 * 1024) { /* 1MB max */
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
    pem_data[read_size] = '\0';
    fclose(file);

    /* Parse multiple certificates from PEM data */
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
        /* Clean up */
        for (size_t i = 0; i < count; i++)
            free(der_list[i]);
        opssl_set_error(OPSSL_ERR_INVALID_ARGUMENT, "Invalid certificate count");
        return NULL;
    }

    opssl_x509_chain_t *chain = calloc(1, sizeof(opssl_x509_chain_t));
    if (!chain) {
        /* Clean up */
        for (size_t i = 0; i < count; i++)
            free(der_list[i]);
        opssl_set_error(OPSSL_ERR_MEMORY, "Memory allocation failed");
        return NULL;
    }

    /* Convert DER data to certificate objects */
    for (size_t i = 0; i < count; i++) {
        chain->certs[i] = opssl_x509_from_der(der_list[i], der_lens[i]);
        if (!chain->certs[i]) {
            /* Clean up on failure */
            opssl_x509_chain_free(chain);
            for (size_t j = i; j < count; j++)
                free(der_list[j]);
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
    if (!der || der_len == 0)
        return NULL;

    opssl_x509_t *cert = opssl_x509_from_der(der, der_len);
    if (!cert)
        return NULL;

    opssl_x509_chain_t *chain = calloc(1, sizeof(opssl_x509_chain_t));
    if (!chain) {
        opssl_x509_free(cert);
        return NULL;
    }

    chain->certs[0] = cert;
    chain->count = 1;
    return chain;
}

void opssl_x509_chain_free(opssl_x509_chain_t *chain) {
    if (!chain)
        return;

    for (size_t i = 0; i < chain->count; i++) {
        opssl_x509_free(chain->certs[i]);
    }

    free(chain);
}

opssl_x509_store_t *opssl_x509_store_new(void) {
    return calloc(1, sizeof(opssl_x509_store_t));
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
    if (!cert)
        return 0;

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
        if (entry->d_name[0] == '.') /* Skip hidden files */
            continue;

        /* Check for certificate file extensions */
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
    if (!store)
        return;

    for (size_t i = 0; i < store->count; i++) {
        opssl_x509_free(store->trusted[i]);
    }

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

    /* Get leaf certificate (first in chain) */
    opssl_x509_t *leaf = chain->certs[0];

    /* 1. Check hostname match */
    if (hostname && !check_hostname_match(leaf, hostname)) {
        result->error_code = OPSSL_VERIFY_ERROR_HOSTNAME_MISMATCH;
        return 0;
    }

    /* 2. Check time validity for all certificates in chain */
    int64_t now = time(NULL);
    for (size_t i = 0; i < chain->count; i++) {
        int64_t not_before, not_after;
        if (!opssl_x509_get_not_before(chain->certs[i], &not_before) ||
            !opssl_x509_get_not_after(chain->certs[i], &not_after)) {
            result->error_code = OPSSL_VERIFY_ERROR_INVALID_TIME;
            return 0;
        }

        if (now < not_before || now > not_after) {
            result->error_code = (now > not_after) ? OPSSL_VERIFY_ERROR_EXPIRED : OPSSL_VERIFY_ERROR_NOT_YET_VALID;
            return 0;
        }
    }

    /* 3. Verify certificate chain signatures */
    opssl_x509_t *current = leaf;
    opssl_x509_t *issuer = NULL;

    for (size_t i = 0; i < chain->count; i++) {
        /* Find issuer - either next in chain or in trusted store */
        if (i + 1 < chain->count) {
            issuer = chain->certs[i + 1];
        } else {
            issuer = find_issuer(current, store);
            if (!issuer) {
                result->error_code = OPSSL_VERIFY_ERROR_ISSUER_NOT_FOUND;
                return 0;
            }
        }

        /* Verify signature of current certificate using issuer's public key */
        const uint8_t *spki;
        size_t spki_len;
        if (!opssl_x509_get_spki(issuer, &spki, &spki_len)) {
            result->error_code = OPSSL_VERIFY_ERROR_INVALID_SIGNATURE;
            return 0;
        }

        /* Get the certificate DER to extract TBS, algorithm, and signature */
        const uint8_t *cert_der;
        size_t cert_der_len;
        if (!opssl_x509_get_der(current, &cert_der, &cert_der_len)) {
            result->error_code = OPSSL_VERIFY_ERROR_INVALID_SIGNATURE;
            return 0;
        }

        /* Parse certificate structure to extract components */
        opssl_cbs_t cert_cbs, cert_seq, tbs_cert, sig_alg_seq, sig_bits;
        opssl_cbs_init(&cert_cbs, cert_der, cert_der_len);

        if (!opssl_asn1_get_sequence(&cert_cbs, &cert_seq)) {
            result->error_code = OPSSL_VERIFY_ERROR_INVALID_SIGNATURE;
            return 0;
        }

        /* Extract TBSCertificate */
        const uint8_t *tbs_start = opssl_cbs_data(&cert_seq);
        if (!opssl_asn1_get_sequence(&cert_seq, &tbs_cert)) {
            result->error_code = OPSSL_VERIFY_ERROR_INVALID_SIGNATURE;
            return 0;
        }
        size_t tbs_len = opssl_cbs_data(&cert_seq) - tbs_start;

        /* Extract signature algorithm */
        opssl_cbs_t sig_alg_oid;
        if (!opssl_asn1_get_sequence(&cert_seq, &sig_alg_seq) ||
            !opssl_asn1_get_oid(&sig_alg_seq, &sig_alg_oid)) {
            result->error_code = OPSSL_VERIFY_ERROR_INVALID_SIGNATURE;
            return 0;
        }

        /* Extract signature bits */
        uint8_t sig_unused;
        if (!opssl_asn1_get_bit_string(&cert_seq, &sig_bits, &sig_unused)) {
            result->error_code = OPSSL_VERIFY_ERROR_INVALID_SIGNATURE;
            return 0;
        }

        /* Verify the signature */
        if (!opssl_verify_signature(tbs_start, tbs_len,
                                    opssl_cbs_data(&sig_alg_oid), opssl_cbs_len(&sig_alg_oid),
                                    opssl_cbs_data(&sig_bits), opssl_cbs_len(&sig_bits),
                                    spki, spki_len)) {
            result->error_code = OPSSL_VERIFY_ERROR_INVALID_SIGNATURE;
            return 0;
        }

        current = issuer;
    }

    /* 4. Check that root/final issuer is self-signed and trusted */
    if (!is_ca_certificate(current)) {
        result->error_code = OPSSL_VERIFY_ERROR_UNTRUSTED_ROOT;
        return 0;
    }

    /* 5. Check basic constraints for intermediate certificates */
    for (size_t i = 1; i < chain->count; i++) {
        if (!is_ca_certificate(chain->certs[i])) {
            result->error_code = OPSSL_VERIFY_ERROR_INVALID_CA;
            return 0;
        }
    }

    result->error_code = OPSSL_VERIFY_OK;
    result->chain_length = chain->count;

    /* Store certificate fingerprints for reference */
    const uint8_t *der;
    size_t der_len;
    if (opssl_x509_get_der(leaf, &der, &der_len)) {
        /* Calculate SHA-256 fingerprint of leaf certificate */
        opssl_sha256(der, der_len, result->leaf_fingerprint);
    }

    return 1;
}
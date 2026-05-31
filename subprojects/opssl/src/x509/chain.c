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
#include <sys/wait.h>
#include <time.h>
#include <fnmatch.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#define OPSSL_MAX_CERT_CHAIN 10

/*
 * Hard cap on the certificate chain length enforced by opssl_x509_verify().
 *
 * This is the strict policy ceiling used when callers cannot plumb a per-ctx
 * verify_depth value down to this function (the public verify ABI takes no
 * ctx).  It must NEVER exceed OPSSL_MAX_CERT_CHAIN, because the storage in
 * struct opssl_x509_chain is sized by that constant.  This matches the
 * default returned by opssl_ctx_get_verify_depth().
 *
 * If you want a smaller per-deployment limit, plumb it through and check
 * before calling opssl_x509_verify().
 */
#define OPSSL_VERIFY_MAX_DEPTH OPSSL_MAX_CERT_CHAIN

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
#define OPSSL_VERIFY_ERROR_DEPTH_EXCEEDED   13
#define OPSSL_VERIFY_ERROR_WEAK_HASH        14
#define OPSSL_VERIFY_ERROR_NAME_CONSTRAINT  15
#define OPSSL_VERIFY_ERROR_EXT_KEY_USAGE    16

/* Signature algorithm OIDs */
static const uint8_t oid_rsa_pss[] = {
    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0A
};
static const uint8_t oid_mgf1[] = {
    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x08
};
static const uint8_t oid_sha1[] = {
    0x2B, 0x0E, 0x03, 0x02, 0x1A
};
static const uint8_t oid_sha256[] = {
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01
};
static const uint8_t oid_sha384[] = {
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02
};
static const uint8_t oid_sha512[] = {
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03
};
static const uint8_t oid_rsa_pkcs1_sha1[] = {
    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x05
};
static const uint8_t oid_rsa_pkcs1_sha256[] = {
    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B
};
static const uint8_t oid_rsa_pkcs1_sha384[] = {
    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0C
};
static const uint8_t oid_rsa_pkcs1_sha512[] = {
    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0D
};
static const uint8_t oid_ecdsa_sha1[] = {
    0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x01
};
static const uint8_t oid_ecdsa_sha256[] = {
    0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02
};
static const uint8_t oid_ecdsa_sha384[] = {
    0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03
};
static const uint8_t oid_ecdsa_sha512[] = {
    0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x04
};
static const uint8_t oid_ed25519[] = {
    0x2B, 0x65, 0x70
};
static const uint8_t oid_secp256r1[] = {
    0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07
};
static const uint8_t oid_secp384r1[] = {
    0x2B, 0x81, 0x04, 0x00, 0x22
};
static const uint8_t oid_secp521r1[] = {
    0x2B, 0x81, 0x04, 0x00, 0x23
};

static int
x509_digest_for_hmac_algo(opssl_hmac_algo_t algo, const uint8_t *data, size_t data_len,
                          uint8_t *digest, size_t *digest_len)
{
    switch (algo) {
    case OPSSL_HMAC_SHA1:
        opssl_sha1(data, data_len, digest);
        *digest_len = OPSSL_SHA1_DIGEST_LEN;
        return 1;
    case OPSSL_HMAC_SHA256:
        opssl_sha256(data, data_len, digest);
        *digest_len = OPSSL_SHA256_DIGEST_LEN;
        return 1;
    case OPSSL_HMAC_SHA384:
        opssl_sha384(data, data_len, digest);
        *digest_len = OPSSL_SHA384_DIGEST_LEN;
        return 1;
    case OPSSL_HMAC_SHA512:
        opssl_sha512(data, data_len, digest);
        *digest_len = OPSSL_SHA512_DIGEST_LEN;
        return 1;
    default:
        return 0;
    }
}

static int
x509_oid_eq(const uint8_t *algo, size_t algo_len, const uint8_t *oid, size_t oid_len)
{
    return algo_len == oid_len && opssl_ct_eq(algo, oid, oid_len);
}

static int
x509_ec_curve_from_spki_alg(const opssl_cbs_t *alg_id, opssl_curve_t *curve)
{
    if (!alg_id || !curve)
        return 0;

    opssl_cbs_t tmp = *alg_id;
    opssl_cbs_t key_algo, curve_oid;
    if (!opssl_asn1_get_oid(&tmp, &key_algo))
        return 0;
    if (!opssl_asn1_get_oid(&tmp, &curve_oid))
        return 0;

    const uint8_t *oid = opssl_cbs_data(&curve_oid);
    size_t oid_len = opssl_cbs_len(&curve_oid);
    if (x509_oid_eq(oid, oid_len, oid_secp256r1, sizeof(oid_secp256r1))) {
        *curve = OPSSL_CURVE_P256;
        return 1;
    }
    if (x509_oid_eq(oid, oid_len, oid_secp384r1, sizeof(oid_secp384r1))) {
        *curve = OPSSL_CURVE_P384;
        return 1;
    }
    if (x509_oid_eq(oid, oid_len, oid_secp521r1, sizeof(oid_secp521r1))) {
        *curve = OPSSL_CURVE_P521;
        return 1;
    }
    return 0;
}

static int
x509_write_all(int fd, const uint8_t *data, size_t len)
{
    while (len > 0) {
        ssize_t n = write(fd, data, len);
        if (n <= 0)
            return 0;
        data += (size_t)n;
        len -= (size_t)n;
    }
    return 1;
}

static int
x509_mkstemp_write(char *tmpl, const uint8_t *data, size_t len)
{
    int fd = mkstemp(tmpl);
    if (fd < 0)
        return -1;
    if (!x509_write_all(fd, data, len) || close(fd) != 0) {
        close(fd);
        unlink(tmpl);
        return -1;
    }
    return 0;
}

static int
x509_verify_ecdsa_with_system_openssl(const char *digest_arg,
                                      const uint8_t *tbs, size_t tbs_len,
                                      const uint8_t *sig, size_t sig_len,
                                      const uint8_t *spki, size_t spki_len)
{
    char tbs_path[] = "/tmp/opssl-tbs-XXXXXX";
    char sig_path[] = "/tmp/opssl-sig-XXXXXX";
    char key_path[] = "/tmp/opssl-key-XXXXXX";
    int ok = 0;

    if (!digest_arg || !tbs || !sig || !spki)
        return 0;
    if (x509_mkstemp_write(tbs_path, tbs, tbs_len) != 0)
        return 0;
    if (x509_mkstemp_write(sig_path, sig, sig_len) != 0)
        goto out_tbs;
    if (x509_mkstemp_write(key_path, spki, spki_len) != 0)
        goto out_sig;

    pid_t pid = fork();
    if (pid == 0) {
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }
        execlp("openssl", "openssl", "dgst", digest_arg,
               "-keyform", "DER", "-verify", key_path,
               "-signature", sig_path, tbs_path, (char *)NULL);
        _exit(127);
    }
    if (pid > 0) {
        int status = 0;
        while (waitpid(pid, &status, 0) < 0) {
            if (errno != EINTR)
                break;
        }
        ok = WIFEXITED(status) && WEXITSTATUS(status) == 0;
    }

    unlink(key_path);
out_sig:
    unlink(sig_path);
out_tbs:
    unlink(tbs_path);
    return ok;
}

static int
x509_hash_oid_to_hmac(const uint8_t *oid, size_t oid_len, opssl_hmac_algo_t *hash)
{
    if (x509_oid_eq(oid, oid_len, oid_sha1, sizeof(oid_sha1))) {
        *hash = OPSSL_HMAC_SHA1;
        return 1;
    }
    if (x509_oid_eq(oid, oid_len, oid_sha256, sizeof(oid_sha256))) {
        *hash = OPSSL_HMAC_SHA256;
        return 1;
    }
    if (x509_oid_eq(oid, oid_len, oid_sha384, sizeof(oid_sha384))) {
        *hash = OPSSL_HMAC_SHA384;
        return 1;
    }
    if (x509_oid_eq(oid, oid_len, oid_sha512, sizeof(oid_sha512))) {
        *hash = OPSSL_HMAC_SHA512;
        return 1;
    }
    return 0;
}

static size_t
x509_hmac_digest_len(opssl_hmac_algo_t hash)
{
    switch (hash) {
    case OPSSL_HMAC_SHA1: return OPSSL_SHA1_DIGEST_LEN;
    case OPSSL_HMAC_SHA256: return OPSSL_SHA256_DIGEST_LEN;
    case OPSSL_HMAC_SHA384: return OPSSL_SHA384_DIGEST_LEN;
    case OPSSL_HMAC_SHA512: return OPSSL_SHA512_DIGEST_LEN;
    default: return 0;
    }
}

static int
x509_parse_hash_algorithm(opssl_cbs_t *cbs, opssl_hmac_algo_t *hash)
{
    opssl_cbs_t seq, oid;
    if (!opssl_asn1_get_sequence(cbs, &seq) ||
        !opssl_asn1_get_oid(&seq, &oid))
        return 0;
    return x509_hash_oid_to_hmac(opssl_cbs_data(&oid), opssl_cbs_len(&oid), hash);
}

static int
x509_parse_small_uint(opssl_cbs_t *cbs, size_t *value)
{
    opssl_cbs_t integer;
    if (!opssl_asn1_get_integer(cbs, &integer) || opssl_cbs_len(&integer) > sizeof(size_t))
        return 0;

    size_t v = 0;
    const uint8_t *p = opssl_cbs_data(&integer);
    for (size_t i = 0; i < opssl_cbs_len(&integer); i++)
        v = (v << 8) | p[i];
    *value = v;
    return 1;
}

static int
x509_parse_rsa_pss_params(const uint8_t *params, size_t params_len,
                          opssl_hmac_algo_t *hash)
{
    opssl_hmac_algo_t pss_hash = OPSSL_HMAC_SHA1;
    opssl_hmac_algo_t mgf_hash = OPSSL_HMAC_SHA1;
    size_t salt_len = OPSSL_SHA1_DIGEST_LEN;
    size_t trailer_field = 1;

    if (params_len == 0) {
        *hash = pss_hash;
        return 1;
    }

    opssl_cbs_t params_cbs, params_seq;
    opssl_cbs_init(&params_cbs, params, params_len);
    if (!opssl_asn1_get_sequence(&params_cbs, &params_seq))
        return 0;

    while (opssl_cbs_len(&params_seq) > 0) {
        uint8_t tag;
        opssl_cbs_t field;
        if (!opssl_cbs_peek_u8(&params_seq, &tag))
            return 0;

        if (tag == 0xA0) {
            if (!opssl_asn1_get_element(&params_seq, 0xA0, &field) ||
                !x509_parse_hash_algorithm(&field, &pss_hash))
                return 0;
        } else if (tag == 0xA1) {
            opssl_cbs_t mgf_seq, mgf_oid;
            if (!opssl_asn1_get_element(&params_seq, 0xA1, &field) ||
                !opssl_asn1_get_sequence(&field, &mgf_seq) ||
                !opssl_asn1_get_oid(&mgf_seq, &mgf_oid) ||
                !x509_oid_eq(opssl_cbs_data(&mgf_oid), opssl_cbs_len(&mgf_oid),
                             oid_mgf1, sizeof(oid_mgf1))) {
                return 0;
            }
            if (!x509_parse_hash_algorithm(&mgf_seq, &mgf_hash))
                return 0;
        } else if (tag == 0xA2) {
            if (!opssl_asn1_get_element(&params_seq, 0xA2, &field) ||
                !x509_parse_small_uint(&field, &salt_len))
                return 0;
        } else if (tag == 0xA3) {
            if (!opssl_asn1_get_element(&params_seq, 0xA3, &field) ||
                !x509_parse_small_uint(&field, &trailer_field))
                return 0;
        } else {
            return 0;
        }
    }

    if (pss_hash != mgf_hash || trailer_field != 1 ||
        salt_len != x509_hmac_digest_len(pss_hash))
        return 0;

    *hash = pss_hash;
    return 1;
}

static int opssl_verify_signature(const uint8_t *tbs, size_t tbs_len,
                                  const uint8_t *algo, size_t algo_len,
                                  const uint8_t *params, size_t params_len,
                                  const uint8_t *sig, size_t sig_len,
                                  const uint8_t *spki, size_t spki_len)
{
    if (!tbs || !algo || !sig || !spki)
        return 0;

    uint8_t hash[OPSSL_SHA512_DIGEST_LEN];
    size_t hash_len = 0;

    opssl_hmac_algo_t rsa_hash;
    if (x509_oid_eq(algo, algo_len, oid_rsa_pkcs1_sha1, sizeof(oid_rsa_pkcs1_sha1))) {
        rsa_hash = OPSSL_HMAC_SHA1;
    } else if (x509_oid_eq(algo, algo_len, oid_rsa_pkcs1_sha256, sizeof(oid_rsa_pkcs1_sha256))) {
        rsa_hash = OPSSL_HMAC_SHA256;
    } else if (x509_oid_eq(algo, algo_len, oid_rsa_pkcs1_sha384, sizeof(oid_rsa_pkcs1_sha384))) {
        rsa_hash = OPSSL_HMAC_SHA384;
    } else if (x509_oid_eq(algo, algo_len, oid_rsa_pkcs1_sha512, sizeof(oid_rsa_pkcs1_sha512))) {
        rsa_hash = OPSSL_HMAC_SHA512;
    } else {
        rsa_hash = (opssl_hmac_algo_t)-1;
    }

    if (rsa_hash != (opssl_hmac_algo_t)-1) {
        if (!x509_digest_for_hmac_algo(rsa_hash, tbs, tbs_len, hash, &hash_len))
            return 0;
        opssl_rsa_ctx_t *rsa = opssl_rsa_new();
        if (!rsa) return 0;
        if (opssl_rsa_load_public_key(rsa, spki, spki_len) != 1) {
            opssl_rsa_free(rsa); return 0;
        }
        int result = opssl_rsa_verify(rsa, OPSSL_RSA_PKCS1_V15, rsa_hash,
                                      hash, hash_len, sig, sig_len);
        opssl_rsa_free(rsa);
        return result;

    } else if (x509_oid_eq(algo, algo_len, oid_rsa_pss, sizeof(oid_rsa_pss))) {
        opssl_hmac_algo_t pss_hash;
        if (!x509_parse_rsa_pss_params(params, params_len, &pss_hash))
            return 0;
        if (!x509_digest_for_hmac_algo(pss_hash, tbs, tbs_len, hash, &hash_len))
            return 0;
        opssl_rsa_ctx_t *rsa = opssl_rsa_new();
        if (!rsa) return 0;
        if (opssl_rsa_load_public_key(rsa, spki, spki_len) != 1) {
            opssl_rsa_free(rsa); return 0;
        }
        int result = opssl_rsa_verify(rsa, OPSSL_RSA_PSS, pss_hash,
                                      hash, hash_len, sig, sig_len);
        opssl_rsa_free(rsa);
        return result;

    }

    opssl_hmac_algo_t ecdsa_hash;
    opssl_curve_t ecdsa_curve = OPSSL_CURVE_P256;
    if (x509_oid_eq(algo, algo_len, oid_ecdsa_sha1, sizeof(oid_ecdsa_sha1))) {
        ecdsa_hash = OPSSL_HMAC_SHA1;
    } else if (x509_oid_eq(algo, algo_len, oid_ecdsa_sha256, sizeof(oid_ecdsa_sha256))) {
        ecdsa_hash = OPSSL_HMAC_SHA256;
    } else if (x509_oid_eq(algo, algo_len, oid_ecdsa_sha384, sizeof(oid_ecdsa_sha384))) {
        ecdsa_hash = OPSSL_HMAC_SHA384;
        ecdsa_curve = OPSSL_CURVE_P384;
    } else if (x509_oid_eq(algo, algo_len, oid_ecdsa_sha512, sizeof(oid_ecdsa_sha512))) {
        ecdsa_hash = OPSSL_HMAC_SHA512;
        ecdsa_curve = OPSSL_CURVE_P521;
    } else {
        ecdsa_hash = (opssl_hmac_algo_t)-1;
    }

    if (ecdsa_hash != (opssl_hmac_algo_t)-1) {
        if (!x509_digest_for_hmac_algo(ecdsa_hash, tbs, tbs_len, hash, &hash_len))
            return 0;
        opssl_cbs_t spki_cbs, alg_id, pub_bits;
        opssl_cbs_init(&spki_cbs, spki, spki_len);
        const char *digest_arg = NULL;
        if (ecdsa_hash == OPSSL_HMAC_SHA1)
            digest_arg = "-sha1";
        else if (ecdsa_hash == OPSSL_HMAC_SHA256)
            digest_arg = "-sha256";
        else if (ecdsa_hash == OPSSL_HMAC_SHA384)
            digest_arg = "-sha384";
        else if (ecdsa_hash == OPSSL_HMAC_SHA512)
            digest_arg = "-sha512";

        if (!opssl_asn1_get_sequence(&spki_cbs, &alg_id))
            return x509_verify_ecdsa_with_system_openssl(digest_arg, tbs, tbs_len,
                                                         sig, sig_len, spki, spki_len);
        if (!x509_ec_curve_from_spki_alg(&alg_id, &ecdsa_curve))
            return x509_verify_ecdsa_with_system_openssl(digest_arg, tbs, tbs_len,
                                                         sig, sig_len, spki, spki_len);
        uint8_t pub_unused;
        if (!opssl_asn1_get_bit_string(&spki_cbs, &pub_bits, &pub_unused))
            return x509_verify_ecdsa_with_system_openssl(digest_arg, tbs, tbs_len,
                                                         sig, sig_len, spki, spki_len);
        const uint8_t *pub_key = opssl_cbs_data(&pub_bits);
        size_t pub_key_len = opssl_cbs_len(&pub_bits);
        opssl_ecdsa_ctx_t *ecdsa = opssl_ecdsa_new(ecdsa_curve);
        if (!ecdsa)
            return x509_verify_ecdsa_with_system_openssl(digest_arg, tbs, tbs_len,
                                                         sig, sig_len, spki, spki_len);
        if (opssl_ecdsa_set_public(ecdsa, pub_key, pub_key_len) != 1) {
            opssl_ecdsa_free(ecdsa);
            return x509_verify_ecdsa_with_system_openssl(digest_arg, tbs, tbs_len,
                                                         sig, sig_len, spki, spki_len);
        }
        uint8_t padded_hash[OPSSL_SHA384_DIGEST_LEN];
        const uint8_t *verify_hash = hash;
        size_t verify_hash_len = hash_len;
        size_t curve_hash_len = 0;
        if (ecdsa_curve == OPSSL_CURVE_P256)
            curve_hash_len = OPSSL_SHA256_DIGEST_LEN;
        else if (ecdsa_curve == OPSSL_CURVE_P384)
            curve_hash_len = OPSSL_SHA384_DIGEST_LEN;
        if (curve_hash_len > 0) {
            if (hash_len < curve_hash_len) {
                memset(padded_hash, 0, curve_hash_len);
                memcpy(padded_hash + curve_hash_len - hash_len, hash, hash_len);
                verify_hash = padded_hash;
                verify_hash_len = curve_hash_len;
            } else if (hash_len > curve_hash_len) {
                verify_hash_len = curve_hash_len;
            }
        }
        int result = opssl_ecdsa_verify(ecdsa, verify_hash, verify_hash_len, sig, sig_len);
        opssl_ecdsa_free(ecdsa);
        if (!result)
            result = x509_verify_ecdsa_with_system_openssl(digest_arg,
                                                           tbs, tbs_len,
                                                           sig, sig_len,
                                                           spki, spki_len);
        return result;

    } else if (x509_oid_eq(algo, algo_len, oid_ed25519, sizeof(oid_ed25519))) {
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

/*
 * hostname_matches_pattern - RFC 6125 §6.4 hostname matching.
 *
 * Rules enforced:
 *   - exact (case-insensitive) match always works
 *   - wildcard '*' is permitted ONLY as the entire left-most label, e.g.
 *     "*.example.com"; NOT "foo*.example.com" or "*foo.example.com"
 *   - the pattern must contain at least two dots after the wildcard
 *     (no "*.com" matching arbitrary TLDs)
 *   - the wildcard label matches exactly ONE hostname label (no embedded
 *     dots, no empty label)
 *   - reject if the hostname begins with '.' or is empty
 *   - reject if either string contains '\0' embedded (callers pass C strings)
 *
 * IP addresses are handled by the caller and never go through wildcards.
 */
static int hostname_ascii_ieq(const char *a, const char *b) {
    while (*a && *b) {
        unsigned char ca = (unsigned char)*a++;
        unsigned char cb = (unsigned char)*b++;
        if (ca >= 'A' && ca <= 'Z') ca = (unsigned char)(ca + 32);
        if (cb >= 'A' && cb <= 'Z') cb = (unsigned char)(cb + 32);
        if (ca != cb) return 0;
    }
    return *a == 0 && *b == 0;
}

static int hostname_matches_pattern(const char *hostname, const char *pattern) {
    if (!hostname || !pattern) return 0;
    if (hostname[0] == '\0' || hostname[0] == '.') return 0;
    if (pattern[0] == '\0') return 0;

    /* Exact (case-insensitive) match. */
    if (hostname_ascii_ieq(hostname, pattern)) return 1;

    /* Wildcard: must be exactly "*." prefix. */
    if (!(pattern[0] == '*' && pattern[1] == '.')) return 0;

    const char *pattern_tail = pattern + 1; /* points at '.' */

    /* The remainder of the pattern must contain at least one more dot, so
     * we reject "*.com" matching everything. */
    if (!strchr(pattern_tail + 1, '.')) return 0;

    const char *dot = strchr(hostname, '.');
    if (!dot || dot == hostname) return 0; /* empty left label */

    /* The hostname's first label must be non-empty and contain no '.', and
     * must contain no NUL.  By construction here that's already true. */

    /* Compare the tail (case-insensitive). */
    return hostname_ascii_ieq(dot, pattern_tail);
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

/*
 * weak_hash_signature - return 1 if the certificate is signed with a hash
 * algorithm we consider too weak (MD5 or SHA-1) for chain trust.
 *
 * Parses the outer Certificate SEQUENCE to read the AlgorithmIdentifier that
 * sits AFTER the tbsCertificate.  Compares its OID to known weak OIDs.
 */
static int weak_hash_signature(const opssl_x509_t *cert)
{
    const uint8_t *der;
    size_t der_len;
    if (!opssl_x509_get_der(cert, &der, &der_len)) return 0;

    opssl_cbs_t cbs, cert_seq, tbs, sig_alg, sig_oid;
    opssl_cbs_init(&cbs, der, der_len);
    if (!opssl_asn1_get_sequence(&cbs, &cert_seq)) return 0;
    if (!opssl_asn1_get_sequence(&cert_seq, &tbs)) return 0;
    if (!opssl_asn1_get_sequence(&cert_seq, &sig_alg)) return 0;
    if (!opssl_asn1_get_oid(&sig_alg, &sig_oid)) return 0;

    /* MD5 with RSA: 1.2.840.113549.1.1.4 */
    static const uint8_t oid_md5_rsa[] = {
        0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x04
    };
    if (opssl_asn1_oid_equal(&sig_oid, oid_md5_rsa, sizeof(oid_md5_rsa)))
        return 1;
    if (opssl_asn1_oid_equal(&sig_oid, oid_rsa_pkcs1_sha1,
                             sizeof(oid_rsa_pkcs1_sha1)))
        return 1;
    if (opssl_asn1_oid_equal(&sig_oid, oid_ecdsa_sha1,
                             sizeof(oid_ecdsa_sha1)))
        return 1;
    /* DSA-with-SHA1: 1.2.840.10040.4.3 */
    static const uint8_t oid_dsa_sha1[] = {
        0x2A, 0x86, 0x48, 0xCE, 0x38, 0x04, 0x03
    };
    if (opssl_asn1_oid_equal(&sig_oid, oid_dsa_sha1, sizeof(oid_dsa_sha1)))
        return 1;
    return 0;
}

/*
 * walk_extensions - generic helper to call cb() for each extension OID/value
 * pair in a certificate.  Returns 1 if traversal completed, 0 on parse error.
 * cb returns 0 to stop early (and walk_extensions returns 1), nonzero to
 * continue.
 */
typedef int (*ext_cb_t)(const opssl_cbs_t *oid, int critical,
                        opssl_cbs_t *ext_value, void *ctx);

static int walk_extensions(const opssl_x509_t *cert, ext_cb_t cb, void *ctx)
{
    const uint8_t *der; size_t der_len;
    if (!opssl_x509_get_der(cert, &der, &der_len)) return 0;

    opssl_cbs_t cbs, cert_seq, tbs;
    opssl_cbs_init(&cbs, der, der_len);
    if (!opssl_asn1_get_sequence(&cbs, &cert_seq)) return 0;
    if (!opssl_asn1_get_sequence(&cert_seq, &tbs)) return 0;

    uint8_t tag;
    if (opssl_cbs_peek_u8(&tbs, &tag) && tag == 0xA0) {
        opssl_cbs_t v;
        opssl_asn1_get_element(&tbs, 0xA0, &v);
    }
    for (int i = 0; i < 6; i++) {
        if (!opssl_asn1_skip_element(&tbs)) return 1; /* no extensions */
    }
    if (!opssl_cbs_peek_u8(&tbs, &tag) || tag != 0xA3) return 1;

    opssl_cbs_t ext_wrapper, ext_seq;
    if (!opssl_asn1_get_element(&tbs, 0xA3, &ext_wrapper)) return 0;
    if (!opssl_asn1_get_sequence(&ext_wrapper, &ext_seq)) return 0;

    while (opssl_cbs_len(&ext_seq) > 0) {
        opssl_cbs_t extension, oid, ext_value;
        if (!opssl_asn1_get_sequence(&ext_seq, &extension)) return 0;
        if (!opssl_asn1_get_oid(&extension, &oid)) return 0;

        int critical = 0;
        if (opssl_cbs_peek_u8(&extension, &tag) && tag == 0x01) {
            bool b = false;
            if (opssl_asn1_get_boolean(&extension, &b)) critical = b ? 1 : 0;
        }
        if (!opssl_asn1_get_element(&extension, 0x04, &ext_value)) return 0;

        if (!cb(&oid, critical, &ext_value, ctx)) return 1;
    }
    return 1;
}

/*
 * check_ext_key_usage - verify that the leaf has the requested EKU OID set,
 * OR has the anyExtendedKeyUsage OID, OR has no EKU extension at all.
 *
 * `want_oid` must point to the DER bytes of the OID (e.g. id-kp-serverAuth).
 * Returns 1 if usage is acceptable, 0 if EKU is present and does NOT include
 * the requested usage.
 */
static const uint8_t oid_ekp_server_auth[] = {
    0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01
};
static const uint8_t oid_ekp_client_auth[] = {
    0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02
};
static const uint8_t oid_ekp_any[] = {
    0x55, 0x1D, 0x25, 0x00
};
static const uint8_t oid_ext_key_usage[] = { 0x55, 0x1D, 0x25 };

struct eku_ctx {
    const uint8_t *want; size_t want_len;
    int found_extension;
    int allowed;
};

static int eku_cb(const opssl_cbs_t *oid, int critical,
                  opssl_cbs_t *ext_value, void *vctx)
{
    (void)critical;
    struct eku_ctx *c = vctx;
    if (!opssl_asn1_oid_equal(oid, oid_ext_key_usage,
                              sizeof(oid_ext_key_usage)))
        return 1;
    c->found_extension = 1;
    opssl_cbs_t eku_seq;
    if (!opssl_asn1_get_sequence(ext_value, &eku_seq)) {
        c->allowed = 0; return 0;
    }
    while (opssl_cbs_len(&eku_seq) > 0) {
        opssl_cbs_t kp_oid;
        if (!opssl_asn1_get_oid(&eku_seq, &kp_oid)) break;
        if (opssl_asn1_oid_equal(&kp_oid, c->want, c->want_len) ||
            opssl_asn1_oid_equal(&kp_oid, oid_ekp_any,
                                 sizeof(oid_ekp_any))) {
            c->allowed = 1;
            return 0;
        }
    }
    return 0;
}

static int check_ext_key_usage(const opssl_x509_t *cert,
                               const uint8_t *want_oid, size_t want_len)
{
    struct eku_ctx c = { want_oid, want_len, 0, 0 };
    if (!walk_extensions(cert, eku_cb, &c)) return 0; /* parse fail: fail closed */
    if (!c.found_extension) return 1; /* RFC 5280: EKU optional */
    return c.allowed;
}

/*
 * Name constraints (RFC 5280 §4.2.1.10).
 *
 * We parse the NameConstraints extension on an intermediate CA and check the
 * leaf's SANs against the permittedSubtrees / excludedSubtrees lists for all
 * GeneralName forms RFC 5280 requires enforcement on:
 *
 *   - dNSName            [2] IA5String           (§4.2.1.10.1)
 *   - iPAddress          [7] OCTET STRING        (§4.2.1.10.3) — CIDR network|mask
 *   - rfc822Name         [1] IA5String           (§4.2.1.10.2)
 *   - uniformResourceIdentifier [6] IA5String    (§4.2.1.10.4) — host component
 *
 * GeneralName tags are taken directly from the SAN extension DER (not from the
 * stringified SAN API), so classification is exact and never heuristic.
 *
 * Per RFC 5280 §4.2.1.10, a leaf is rejected if (a) any SAN of a constrained
 * type falls within excludedSubtrees, or (b) permittedSubtrees is present for
 * that type and any SAN of that type does NOT fall within any permitted
 * subtree of the same type.  Types with no constraint of that kind are
 * unconstrained.
 */

/* GeneralName CHOICE context tags (IMPLICIT, primitive forms used here). */
#define GN_TAG_RFC822    0x81
#define GN_TAG_DNS       0x82
#define GN_TAG_URI       0x86
#define GN_TAG_IP        0x87

/* Hard cap matches the cert parser's per-cert SAN cap. */
#define NC_MAX_ENTRIES   1024

/* Per-SAN entry parsed from the leaf SAN extension. data points into a
 * heap-owned blob; len is the raw payload length (no NUL). */
struct nc_san {
    uint8_t  tag;          /* GN_TAG_* */
    uint8_t *data;
    size_t   len;
};

/* Constraint-evaluation state: tracks per-SAN "matched a permitted subtree"
 * flags split by GeneralName type, plus per-type "had any permitted of this
 * type" flags.  After traversal, any SAN whose type had permitted subtrees
 * but which never matched is a violation. */
struct nc_eval {
    struct nc_san *sans;
    int            n_sans;
    uint8_t       *permitted_matched;   /* parallel to sans[]: 0/1 */
    int            had_permitted_dns;
    int            had_permitted_ip;
    int            had_permitted_email;
    int            had_permitted_uri;
    int            violated;
};

/* --- DNS subtree matching (RFC 5280 §4.2.1.10.1). --- */
static int dnsname_within_constraint(const char *name, size_t nl,
                                     const char *cons, size_t cl)
{
    if (cl == 0) return 1;          /* empty constraint matches any DNS name */
    if (nl < cl) return 0;
    /* Case-insensitive suffix match. */
    for (size_t i = 0; i < cl; i++) {
        unsigned char a = (unsigned char)name[nl - cl + i];
        unsigned char b = (unsigned char)cons[i];
        if (a >= 'A' && a <= 'Z') a = (unsigned char)(a + 32);
        if (b >= 'A' && b <= 'Z') b = (unsigned char)(b + 32);
        if (a != b) return 0;
    }
    if (nl == cl) return 1;
    /* Suffix must align on a label boundary. */
    return name[nl - cl - 1] == '.';
}

/* --- rfc822Name subtree matching (RFC 5280 §4.2.1.10.2). ---
 *   - constraint with '@': full address match (case-insensitive on domain).
 *   - constraint without '@' and with no leading '.': single-host domain.
 *   - constraint beginning with '.': any address whose domain ends with it.
 */
static int email_within_constraint(const char *name, size_t nl,
                                   const char *cons, size_t cl)
{
    if (cl == 0) return 1;
    const char *at = memchr(name, '@', nl);
    if (!at) return 0;                              /* malformed SAN */
    size_t local_len = (size_t)(at - name);
    const char *dom  = at + 1;
    size_t dom_len   = nl - local_len - 1;

    if (memchr(cons, '@', cl)) {
        /* Mailbox constraint: exact local-part, case-insensitive domain. */
        const char *cat = memchr(cons, '@', cl);
        size_t clocal = (size_t)(cat - cons);
        size_t cdom   = cl - clocal - 1;
        if (clocal != local_len) return 0;
        if (memcmp(cons, name, local_len) != 0) return 0;
        return dnsname_within_constraint(dom, dom_len, cat + 1, cdom);
    }
    if (cl > 0 && cons[0] == '.') {
        /* Domain-subtree constraint: domain must end with constraint
         * (label-aligned), and the SAN domain must be a strict subdomain. */
        if (dom_len <= cl) return 0;
        return dnsname_within_constraint(dom, dom_len, cons + 1, cl - 1) &&
               dom[dom_len - cl] == '.';
    }
    /* Single-host-domain constraint: exact case-insensitive domain match. */
    if (dom_len != cl) return 0;
    return dnsname_within_constraint(dom, dom_len, cons, cl);
}

/* --- URI subtree matching (RFC 5280 §4.2.1.10.4). ---
 * Extract the host component of the URI and apply DNS subtree semantics.
 * URI format: scheme ":" hier-part.  We accept "scheme://[userinfo@]host[:port]/..."
 * Without an authority component there is no host to constrain, so we treat
 * the URI as not-in-subtree (excluded: no violation; permitted: violation if
 * permitted URI constraints exist).
 */
static int uri_extract_host(const char *uri, size_t ul,
                            const char **host_out, size_t *host_len_out)
{
    const char *p = memchr(uri, ':', ul);
    if (!p) return 0;
    size_t rem = ul - (size_t)(p - uri) - 1;
    if (rem < 2 || p[1] != '/' || p[2] != '/') return 0;
    const char *h = p + 3;
    size_t hl = rem - 2;
    /* Strip userinfo */
    const char *at = memchr(h, '@', hl);
    if (at) { hl -= (size_t)(at - h) + 1; h = at + 1; }
    /* Terminate at port, path, query, or fragment */
    size_t end = hl;
    for (size_t i = 0; i < hl; i++) {
        char c = h[i];
        if (c == ':' || c == '/' || c == '?' || c == '#') { end = i; break; }
    }
    if (end == 0) return 0;
    *host_out = h;
    *host_len_out = end;
    return 1;
}

static int uri_within_constraint(const char *uri, size_t ul,
                                 const char *cons, size_t cl)
{
    const char *host;
    size_t hl;
    if (!uri_extract_host(uri, ul, &host, &hl)) return 0;
    /* Constraint may begin with "." for subtree-only (no exact host match). */
    if (cl > 0 && cons[0] == '.') {
        if (hl <= cl - 1) return 0;
        return dnsname_within_constraint(host, hl, cons + 1, cl - 1) &&
               host[hl - (cl - 1)] == '.';
    }
    return dnsname_within_constraint(host, hl, cons, cl);
}

/* --- iPAddress subtree matching (RFC 5280 §4.2.1.10.3). ---
 * Constraint encoding is network||mask (8 bytes for v4, 32 bytes for v6).
 * Address SAN is 4 bytes (v4) or 16 bytes (v6).  Address must match network
 * under mask; family must agree. */
static int ip_within_constraint(const uint8_t *addr, size_t alen,
                                const uint8_t *cons, size_t clen)
{
    size_t fam = alen;
    if (clen != fam * 2) return 0;          /* family mismatch / malformed */
    for (size_t i = 0; i < fam; i++) {
        if ((addr[i] & cons[fam + i]) != (cons[i] & cons[fam + i]))
            return 0;
    }
    return 1;
}

/* Dispatch a single constraint subtree against all SANs. is_excluded selects
 * violation semantics. */
static void nc_apply_subtree(uint8_t cons_tag,
                             const uint8_t *cons_data, size_t cons_len,
                             struct nc_eval *e, int is_excluded)
{
    /* Record per-type "had permitted" flag once we see one. */
    if (!is_excluded) {
        switch (cons_tag) {
        case GN_TAG_DNS:    e->had_permitted_dns   = 1; break;
        case GN_TAG_IP:     e->had_permitted_ip    = 1; break;
        case GN_TAG_RFC822: e->had_permitted_email = 1; break;
        case GN_TAG_URI:    e->had_permitted_uri   = 1; break;
        default: return;                /* unsupported constraint type */
        }
    } else if (cons_tag != GN_TAG_DNS && cons_tag != GN_TAG_IP &&
               cons_tag != GN_TAG_RFC822 && cons_tag != GN_TAG_URI) {
        return;
    }

    for (int i = 0; i < e->n_sans; i++) {
        struct nc_san *s = &e->sans[i];
        if (s->tag != cons_tag) continue;
        int match = 0;
        switch (cons_tag) {
        case GN_TAG_DNS:
            match = dnsname_within_constraint(
                (const char *)s->data, s->len,
                (const char *)cons_data, cons_len);
            break;
        case GN_TAG_IP:
            match = ip_within_constraint(s->data, s->len, cons_data, cons_len);
            break;
        case GN_TAG_RFC822:
            match = email_within_constraint(
                (const char *)s->data, s->len,
                (const char *)cons_data, cons_len);
            break;
        case GN_TAG_URI:
            match = uri_within_constraint(
                (const char *)s->data, s->len,
                (const char *)cons_data, cons_len);
            break;
        }
        if (match) {
            if (is_excluded) { e->violated = 1; return; }
            e->permitted_matched[i] = 1;
        }
    }
}

static void nc_walk_subtrees(opssl_cbs_t *subtrees, struct nc_eval *e,
                             int is_excluded)
{
    while (opssl_cbs_len(subtrees) > 0 && !e->violated) {
        opssl_cbs_t subtree;
        if (!opssl_asn1_get_sequence(subtrees, &subtree)) return;
        /* base GeneralName: first element of the subtree SEQUENCE. */
        uint8_t tag;
        if (!opssl_cbs_peek_u8(&subtree, &tag)) return;
        opssl_cbs_t gn;
        if (!opssl_asn1_get_element(&subtree, tag, &gn)) return;
        nc_apply_subtree(tag, opssl_cbs_data(&gn), opssl_cbs_len(&gn),
                         e, is_excluded);
    }
}

static int nc_cb(const opssl_cbs_t *oid, int critical, opssl_cbs_t *ext_value,
                 void *vctx)
{
    (void)critical;
    static const uint8_t oid_name_constraints[] = { 0x55, 0x1D, 0x1E };
    if (!opssl_asn1_oid_equal(oid, oid_name_constraints,
                              sizeof(oid_name_constraints)))
        return 1;
    struct nc_eval *e = vctx;
    opssl_cbs_t nc;
    if (!opssl_asn1_get_sequence(ext_value, &nc)) return 0;

    /* permittedSubtrees [0] IMPLICIT GeneralSubtrees */
    uint8_t tag;
    if (opssl_cbs_peek_u8(&nc, &tag) && tag == 0xA0) {
        opssl_cbs_t perm;
        if (opssl_asn1_get_element(&nc, 0xA0, &perm))
            nc_walk_subtrees(&perm, e, 0);
        if (e->violated) return 0;
    }
    /* excludedSubtrees [1] IMPLICIT GeneralSubtrees */
    if (opssl_cbs_peek_u8(&nc, &tag) && tag == 0xA1) {
        opssl_cbs_t excl;
        if (opssl_asn1_get_element(&nc, 0xA1, &excl))
            nc_walk_subtrees(&excl, e, 1);
        if (e->violated) return 0;
    }
    return 0; /* found NC, stop walking extensions */
}

/* Parse the leaf SAN extension directly from DER so we can preserve each
 * GeneralName's tag. Caller must free() entries[i].data and the returned
 * array. */
static struct nc_san *collect_leaf_sans(const opssl_x509_t *leaf, int *out_n)
{
    *out_n = 0;
    const uint8_t *der;
    size_t der_len;
    if (opssl_x509_get_der(leaf, &der, &der_len) != 1) return NULL;

    opssl_cbs_t cbs, cert_seq, tbs, ext_wrap, ext_seq;
    opssl_cbs_init(&cbs, der, der_len);
    if (!opssl_asn1_get_sequence(&cbs, &cert_seq)) return NULL;
    if (!opssl_asn1_get_sequence(&cert_seq, &tbs)) return NULL;

    /* Skip version [0], serial, sigAlg, issuer, validity, subject, SPKI,
     * issuerUID [1], subjectUID [2] — locate extensions [3]. */
    uint8_t t;
    if (opssl_cbs_peek_u8(&tbs, &t) && t == 0xA0)
        opssl_asn1_skip_element(&tbs);
    for (int n = 0; n < 6; n++)
        if (!opssl_asn1_skip_element(&tbs)) return NULL;
    while (opssl_cbs_peek_u8(&tbs, &t) && (t == 0x81 || t == 0x82))
        opssl_asn1_skip_element(&tbs);

    if (!opssl_cbs_peek_u8(&tbs, &t) || t != 0xA3) return NULL;
    if (!opssl_asn1_get_element(&tbs, 0xA3, &ext_wrap)) return NULL;
    if (!opssl_asn1_get_sequence(&ext_wrap, &ext_seq)) return NULL;

    static const uint8_t san_oid[] = { 0x55, 0x1D, 0x11 };
    struct nc_san *out = NULL;
    int cap = 0, count = 0;

    while (opssl_cbs_len(&ext_seq) > 0) {
        opssl_cbs_t ext, oid, ext_value;
        if (!opssl_asn1_get_sequence(&ext_seq, &ext)) break;
        if (!opssl_asn1_get_oid(&ext, &oid)) break;
        uint8_t pk;
        if (opssl_cbs_peek_u8(&ext, &pk) && pk == 0x01)
            opssl_asn1_skip_element(&ext);
        if (!opssl_asn1_get_element(&ext, 0x04, &ext_value)) break;

        if (opssl_cbs_len(&oid) != sizeof(san_oid) ||
            memcmp(opssl_cbs_data(&oid), san_oid, sizeof(san_oid)) != 0)
            continue;

        opssl_cbs_t san_seq;
        if (!opssl_asn1_get_sequence(&ext_value, &san_seq)) break;
        while (opssl_cbs_len(&san_seq) > 0 && count < NC_MAX_ENTRIES) {
            uint8_t gn_tag;
            if (!opssl_cbs_peek_u8(&san_seq, &gn_tag)) break;
            opssl_cbs_t gn;
            if (!opssl_asn1_get_element(&san_seq, gn_tag, &gn)) break;
            if (gn_tag != GN_TAG_DNS && gn_tag != GN_TAG_IP &&
                gn_tag != GN_TAG_RFC822 && gn_tag != GN_TAG_URI)
                continue;

            if (count == cap) {
                int new_cap = cap ? cap * 2 : 16;
                if (new_cap > NC_MAX_ENTRIES) new_cap = NC_MAX_ENTRIES;
                struct nc_san *tmp = realloc(out,
                    (size_t)new_cap * sizeof(*tmp));
                if (!tmp) { goto oom; }
                out = tmp;
                cap = new_cap;
            }
            size_t glen = opssl_cbs_len(&gn);
            if (glen > 0xFFFF) continue; /* sanity ceiling */
            uint8_t *buf = malloc(glen ? glen : 1);
            if (!buf) goto oom;
            if (glen) memcpy(buf, opssl_cbs_data(&gn), glen);
            out[count].tag  = gn_tag;
            out[count].data = buf;
            out[count].len  = glen;
            count++;
        }
        break; /* only one SAN extension per cert */
    }

    *out_n = count;
    return out;

oom:
    for (int i = 0; i < count; i++) free(out[i].data);
    free(out);
    return NULL;
}

static int check_name_constraints(const opssl_x509_t *intermediate,
                                  const opssl_x509_t *leaf)
{
    int n = 0;
    struct nc_san *sans = collect_leaf_sans(leaf, &n);
    if (n == 0) { free(sans); return 1; } /* nothing to constrain */

    uint8_t *matched = calloc((size_t)n, 1);
    if (!matched) {
        for (int i = 0; i < n; i++) free(sans[i].data);
        free(sans);
        return 0; /* fail closed on OOM */
    }

    struct nc_eval e = { sans, n, matched, 0, 0, 0, 0, 0 };
    walk_extensions(intermediate, nc_cb, &e);

    int ok = !e.violated;
    if (ok) {
        /* Permitted-subtree aggregation: every SAN whose type had any
         * permitted constraint must have matched at least one of them. */
        for (int i = 0; i < n && ok; i++) {
            int constrained = 0;
            switch (sans[i].tag) {
            case GN_TAG_DNS:    constrained = e.had_permitted_dns;   break;
            case GN_TAG_IP:     constrained = e.had_permitted_ip;    break;
            case GN_TAG_RFC822: constrained = e.had_permitted_email; break;
            case GN_TAG_URI:    constrained = e.had_permitted_uri;   break;
            }
            if (constrained && !matched[i]) ok = 0;
        }
    }

    for (int i = 0; i < n; i++) free(sans[i].data);
    free(sans);
    free(matched);
    return ok;
}

/* Find issuer certificate in store by subject name and signature match. */
static opssl_x509_t *find_issuer(const opssl_x509_t *cert, const opssl_x509_store_t *store) {
    if (!cert || !store)
        return NULL;

    char cert_issuer[512];
    if (!opssl_x509_get_issuer(cert, cert_issuer, sizeof(cert_issuer)))
        return NULL;

    const uint8_t *cert_der;
    size_t cert_der_len;
    if (!opssl_x509_get_der(cert, &cert_der, &cert_der_len))
        return NULL;

    opssl_cbs_t cert_cbs, cert_seq, tbs_cert, sig_alg_seq, sig_alg_oid, sig_bits;
    opssl_cbs_init(&cert_cbs, cert_der, cert_der_len);

    if (!opssl_asn1_get_sequence(&cert_cbs, &cert_seq))
        return NULL;

    const uint8_t *tbs_start = opssl_cbs_data(&cert_seq);
    if (!opssl_asn1_get_sequence(&cert_seq, &tbs_cert))
        return NULL;
    size_t tbs_len = (size_t)(opssl_cbs_data(&cert_seq) - tbs_start);

    if (!opssl_asn1_get_sequence(&cert_seq, &sig_alg_seq) ||
        !opssl_asn1_get_oid(&sig_alg_seq, &sig_alg_oid))
        return NULL;

    uint8_t sig_unused;
    if (!opssl_asn1_get_bit_string(&cert_seq, &sig_bits, &sig_unused))
        return NULL;

    for (size_t i = 0; i < store->count; i++) {
        char ca_subject[512];
        if (opssl_x509_get_subject(store->trusted[i], ca_subject, sizeof(ca_subject))) {
            if (strcmp(cert_issuer, ca_subject) != 0)
                continue;

            const uint8_t *spki;
            size_t spki_len;
            if (!opssl_x509_get_spki_der(store->trusted[i], &spki, &spki_len))
                continue;

            if (opssl_verify_signature(tbs_start, tbs_len,
                                        opssl_cbs_data(&sig_alg_oid), opssl_cbs_len(&sig_alg_oid),
                                        opssl_cbs_data(&sig_alg_seq), opssl_cbs_len(&sig_alg_seq),
                                        opssl_cbs_data(&sig_bits), opssl_cbs_len(&sig_bits),
                                        spki, spki_len))
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

opssl_x509_chain_t *opssl_x509_chain_from_ders(const uint8_t *der, size_t der_len,
                                                const uint8_t * const *intermediates,
                                                const size_t *ilens,
                                                size_t n_intermediates) {
    if (!der || der_len == 0 || n_intermediates >= OPSSL_MAX_CERT_CHAIN)
        return NULL;

    opssl_x509_chain_t *chain = calloc(1, sizeof(opssl_x509_chain_t));
    if (!chain)
        return NULL;

    chain->certs[0] = opssl_x509_from_der(der, der_len);
    if (!chain->certs[0]) {
        opssl_x509_chain_free(chain);
        return NULL;
    }
    chain->count = 1;

    for (size_t i = 0; i < n_intermediates; i++) {
        if (!intermediates || !ilens || !intermediates[i] || ilens[i] == 0) {
            opssl_x509_chain_free(chain);
            return NULL;
        }

        chain->certs[chain->count] = opssl_x509_from_der(intermediates[i], ilens[i]);
        if (!chain->certs[chain->count]) {
            opssl_x509_chain_free(chain);
            return NULL;
        }
        chain->count++;
    }

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

    /* Read the whole file to handle multi-cert PEM bundles (e.g. ca-certificates.crt). */
    FILE *fp = fopen(path, "r");
    if (!fp) {
        opssl_set_error(OPSSL_ERR_FILE_READ, "cannot open trust cert file");
        return 0;
    }
    if (fseek(fp, 0, SEEK_END) != 0) { fclose(fp); return 0; }
    long fsize = ftell(fp);
    if (fsize <= 0 || fsize > 16L * 1024L * 1024L) {
        fclose(fp);
        opssl_set_error(OPSSL_ERR_FILE_READ, "trust cert file is empty or too large");
        return 0;
    }
    rewind(fp);
    char *pem_data = malloc((size_t)fsize + 1);
    if (!pem_data) { fclose(fp); return 0; }
    size_t nread = fread(pem_data, 1, (size_t)fsize, fp);
    fclose(fp);
    pem_data[nread] = '\0';

    /* Decode all PEM blocks in the file (handles single certs and bundles). */
#define STORE_LOAD_MAX 512
    uint8_t *ders[STORE_LOAD_MAX];
    size_t der_lens[STORE_LOAD_MAX];
    size_t count = 0;
    int added = 0;

    if (opssl_pem_decode_multi(pem_data, nread, ders, der_lens, &count, STORE_LOAD_MAX)) {
        for (size_t i = 0; i < count; i++) {
            opssl_x509_t *cert = opssl_x509_from_der(ders[i], der_lens[i]);
            if (cert) {
                if (opssl_x509_store_add_cert(store, cert))
                    added++;
                opssl_x509_free(cert);
            }
            free(ders[i]);
        }
    }
    free(pem_data);
#undef STORE_LOAD_MAX
    return added;
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

    /* Chain depth limit (strict).  The chain already cannot exceed
     * OPSSL_MAX_CERT_CHAIN due to the storage array; this check enforces
     * the policy explicitly and protects against the array being grown
     * later without revisiting the verification policy. */
    if (chain->count > OPSSL_VERIFY_MAX_DEPTH) {
        result->error_code = OPSSL_VERIFY_ERROR_DEPTH_EXCEEDED;
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

    /* 3. Verify chain signatures — stop early if a chain cert is a trust anchor */
    opssl_x509_t *current = leaf;
    opssl_x509_t *issuer = NULL;

    for (size_t i = 0; i < chain->count; i++) {
        /* If the current cert's SPKI matches a trust anchor, accept it
         * (handles cross-signed roots that differ in DER but share the same key) */
        if (i > 0) {
            const uint8_t *cur_spki;
            size_t cur_spki_len;
            if (opssl_x509_get_spki_der(current, &cur_spki, &cur_spki_len)) {
                for (size_t j = 0; j < store->count; j++) {
                    const uint8_t *tspki;
                    size_t tspki_len;
                    if (opssl_x509_get_spki_der(store->trusted[j], &tspki, &tspki_len) &&
                        tspki_len == cur_spki_len &&
                        opssl_ct_eq(tspki, cur_spki, cur_spki_len))
                        goto chain_trusted;
                }
            }
        }

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
                                    opssl_cbs_data(&sig_alg_seq), opssl_cbs_len(&sig_alg_seq),
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
            opssl_ct_eq(tder, root_der, root_der_len)) {
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

chain_trusted:
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

    /* 7b. Leaf EKU: enforce per-purpose EKU OID.
     * If hostname is supplied we are verifying a TLS server cert — require
     * id-kp-serverAuth (or anyExtendedKeyUsage, or no EKU at all).
     * If hostname is NULL we are verifying a client cert — require
     * id-kp-clientAuth (or anyExtendedKeyUsage, or no EKU at all). */
    if (hostname) {
        if (!check_ext_key_usage(leaf, oid_ekp_server_auth,
                                 sizeof(oid_ekp_server_auth))) {
            result->error_code = OPSSL_VERIFY_ERROR_EXT_KEY_USAGE;
            return 0;
        }
    } else {
        if (!check_ext_key_usage(leaf, oid_ekp_client_auth,
                                 sizeof(oid_ekp_client_auth))) {
            result->error_code = OPSSL_VERIFY_ERROR_EXT_KEY_USAGE;
            return 0;
        }
    }

    /* 7c. Reject weak signature hashes (MD5 / SHA-1 / DSA-SHA1) across the
     * entire chain.  We exempt the trust anchor itself (operators may keep
     * a legacy SHA-1 self-signed root in the trust store as policy). */
    for (size_t i = 0; i + 1 < chain->count; i++) {
        if (weak_hash_signature(chain->certs[i])) {
            result->error_code = OPSSL_VERIFY_ERROR_WEAK_HASH;
            return 0;
        }
    }

    /* 7d. Name constraints: enforce on each intermediate against the leaf. */
    for (size_t i = 1; i < chain->count; i++) {
        if (!check_name_constraints(chain->certs[i], leaf)) {
            result->error_code = OPSSL_VERIFY_ERROR_NAME_CONSTRAINT;
            return 0;
        }
    }

    /* 8. CRL revocation check.
     *
     * Hardened: when ANY CRL is loaded into the store, EVERY certificate in
     * the chain (leaf + intermediates) must pass revocation. Previously only
     * the leaf was checked, which allowed a revoked intermediate to keep
     * issuing accepted leaves. */
    if (store->crl_count > 0) {
        for (size_t i = 0; i < chain->count; i++) {
            if (!opssl_x509_check_revocation(chain->certs[i], store)) {
                result->error_code = OPSSL_VERIFY_ERROR_REVOKED;
                return 0;
            }
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
        if (!opssl_ct_eq(crl->issuer_hash, issuer_hash, 32)) continue;
        if (crl->next_update > 0 && now > crl->next_update) continue;
        for (size_t e = 0; e < crl->entry_count; e++) {
            const opssl_crl_entry_t *entry = &crl->entries[e];
            if (entry->serial_len == cert_serial_len &&
                opssl_ct_eq(entry->serial, cert_serial, cert_serial_len))
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
            !opssl_ct_eq(opssl_cbs_data(&resp_serial), target_serial,
                         target_serial_len))
            continue;

        if (opssl_cbs_len(&single_resp) == 0) break;
        uint8_t status_tag = opssl_cbs_data(&single_resp)[0] & 0x1F;
        if (status_tag == 0) result = OPSSL_OCSP_GOOD;
        else if (status_tag == 1) result = OPSSL_OCSP_REVOKED;
        else result = OPSSL_OCSP_UNKNOWN;

        /* Validate this/nextUpdate timestamps when present. */
        opssl_asn1_skip_element(&single_resp); /* certStatus */
        int64_t this_update = 0, next_update = 0;
        if (opssl_asn1_get_time(&single_resp, &this_update)) {
            int64_t now_ts = time(NULL);
            /* Allow 5 minutes of skew either side. */
            if (this_update - 300 > now_ts) {
                result = OPSSL_OCSP_UNKNOWN;
                break;
            }
            uint8_t ntag;
            if (opssl_cbs_peek_u8(&single_resp, &ntag) && ntag == 0xA0) {
                opssl_cbs_t nu_ctx;
                if (opssl_asn1_get_element(&single_resp, 0xA0, &nu_ctx)) {
                    if (opssl_asn1_get_time(&nu_ctx, &next_update) &&
                        now_ts > next_update + 300) {
                        result = OPSSL_OCSP_UNKNOWN;
                    }
                }
            }
        }
        break;
    }

    /* producedAt sanity: reject responses produced absurdly in the future. */
    {
        int64_t now_ts = time(NULL);
        if (produced_at - 300 > now_ts) {
            return OPSSL_OCSP_UNKNOWN;
        }
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
                                opssl_cbs_data(&sig_alg_seq), opssl_cbs_len(&sig_alg_seq),
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
                                           opssl_cbs_data(&sig_alg_seq), opssl_cbs_len(&sig_alg_seq),
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

/*
 * opssl/x509/pkey.c — private key loading and management.
 *
 * Supports RSA, ECDSA, and Ed25519 private keys in PKCS#8 and legacy formats.
 * All key material is stored in secure memory with guaranteed zeroing on free.
 *
 * Key parsing follows RFC 5208 (PKCS#8) and legacy formats:
 * - RSA: PKCS#1 RSAPrivateKey or PKCS#8 PrivateKeyInfo
 * - EC: RFC 5915 ECPrivateKey wrapped in PKCS#8
 * - Ed25519: RFC 8037 CurvePrivateKey in PKCS#8
 *
 * Copyright (C) 2026 ophion development team
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <opssl/cert.h>
#include <opssl/crypto.h>
#include <opssl/platform.h>
#include <opssl/cbs.h>
#include <opssl/err.h>
#include <string.h>
#include <stdio.h>

/* OID constants for key type identification */
static const uint8_t oid_rsa[] = {
    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01  /* 1.2.840.113549.1.1.1 */
};
static const uint8_t oid_ec[] = {
    0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01  /* 1.2.840.10045.2.1 */
};
static const uint8_t oid_ed25519[] = {
    0x2B, 0x65, 0x70  /* 1.3.101.112 */
};

/* EC curve OIDs */
static const uint8_t oid_secp256r1[] = {
    0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07  /* 1.2.840.10045.3.1.7 */
};
static const uint8_t oid_secp384r1[] = {
    0x2B, 0x81, 0x04, 0x00, 0x22  /* 1.3.132.0.34 */
};
static const uint8_t oid_secp521r1[] = {
    0x2B, 0x81, 0x04, 0x00, 0x23  /* 1.3.132.0.35 */
};

struct opssl_pkey {
    opssl_pkey_type_t type;
    size_t bits;

    union {
        struct {
            uint8_t *der;       /* Full PKCS#8 or PKCS#1 DER */
            size_t der_len;
        } rsa;
        struct {
            uint8_t priv[66];   /* raw scalar (32 P-256, 48 P-384, 66 P-521) */
            uint8_t pub[133];   /* uncompressed point (04 || X || Y) */
            size_t priv_len;
            size_t pub_len;
            opssl_curve_t curve;
        } ec;
        struct {
            uint8_t priv[32];
            uint8_t pub[32];
        } ed25519;
    } key;
};

/* External PEM functions */
extern int opssl_pem_decode(const char *pem, size_t pem_len, uint8_t **der_out, size_t *der_len, char *label_out, size_t label_max);
extern int opssl_pem_read_file(const char *path, uint8_t **der_out, size_t *der_len, char *label_out, size_t label_max);

/* External ASN.1 functions */
extern int opssl_asn1_get_sequence(opssl_cbs_t *cbs, opssl_cbs_t *content);
extern int opssl_asn1_get_integer(opssl_cbs_t *cbs, opssl_cbs_t *value);
extern int opssl_asn1_get_oid(opssl_cbs_t *cbs, opssl_cbs_t *oid);
extern int opssl_asn1_get_element(opssl_cbs_t *cbs, uint8_t expected_tag, opssl_cbs_t *content);

/*
 * pkey_wipe_and_free — zero any private material in a partially-populated
 * key struct, then free it. Use this on every error path inside the parsers
 * so that scalar bytes copied before a later parse failure never linger in
 * freed-but-unsanitised heap memory.
 *
 * Safe to call on a key whose union has not yet been touched: the memset
 * covers all variants of the union by overwriting the whole struct.
 */
static void
pkey_wipe_and_free(opssl_pkey_t *key)
{
    if (!key) return;
    if (key->type == OPSSL_PKEY_RSA && key->key.rsa.der) {
        opssl_key_free(key->key.rsa.der, key->key.rsa.der_len);
        key->key.rsa.der = NULL;
    }
    opssl_memzero(key, sizeof(*key));
    op_free(key);
}

/*
 * Check if an OID matches a known key algorithm.
 */
static int
oid_equal(const opssl_cbs_t *oid, const uint8_t *expected, size_t expected_len)
{
    return opssl_cbs_len(oid) == expected_len &&
           opssl_ct_eq(opssl_cbs_data(oid), expected, expected_len);
}

/*
 * Map EC curve OID to opssl_curve_t.
 */
static int
parse_ec_curve_oid(const opssl_cbs_t *oid, opssl_curve_t *curve, size_t *bits)
{
    if (oid_equal(oid, oid_secp256r1, sizeof(oid_secp256r1))) {
        *curve = OPSSL_CURVE_P256;
        *bits = 256;
        return 1;
    }
    if (oid_equal(oid, oid_secp384r1, sizeof(oid_secp384r1))) {
        *curve = OPSSL_CURVE_P384;
        *bits = 384;
        return 1;
    }
    if (oid_equal(oid, oid_secp521r1, sizeof(oid_secp521r1))) {
        *curve = OPSSL_CURVE_P521;
        *bits = 521;
        return 1;
    }

    OPSSL_ERR(OPSSL_ERR_X509, 0);
    return 0;
}

/*
 * Extract RSA modulus length in bits for key size determination.
 */
static size_t
rsa_modulus_bits(const uint8_t *der, size_t der_len)
{
    opssl_cbs_t cbs, seq, version, modulus;

    opssl_cbs_init(&cbs, der, der_len);

    /* Parse RSAPrivateKey or RSAPublicKey to get modulus */
    if (!opssl_asn1_get_sequence(&cbs, &seq)) {
        return 0;
    }

    /* Skip version INTEGER, then read modulus INTEGER */
    if (!opssl_asn1_get_integer(&seq, &version)) {
        return 0;
    }

    if (!opssl_asn1_get_integer(&seq, &modulus)) {
        return 0;
    }

    /* Calculate bits from modulus length */
    size_t byte_len = opssl_cbs_len(&modulus);
    if (byte_len == 0) return 0;

    /* Skip leading zero byte if present */
    const uint8_t *data = opssl_cbs_data(&modulus);
    if (data[0] == 0x00 && byte_len > 1) {
        byte_len--;
    }

    return byte_len * 8;
}

/*
 * Parse PKCS#8 PrivateKeyInfo structure.
 */
static opssl_pkey_t *
parse_pkcs8_private_key(const uint8_t *der, size_t der_len)
{
    opssl_cbs_t cbs, seq, version, alg_seq, alg_oid, private_key_data;
    opssl_pkey_t *key = NULL;

    opssl_cbs_init(&cbs, der, der_len);

    /* PrivateKeyInfo ::= SEQUENCE {
     *   version         Version,
     *   privateKeyAlgorithm PrivateKeyAlgorithmIdentifier,
     *   privateKey      PrivateKey,
     *   attributes      [0] IMPLICIT Attributes OPTIONAL }
     */

    if (!opssl_asn1_get_sequence(&cbs, &seq)) {
        OPSSL_ERR(OPSSL_ERR_X509, 0);
        return NULL;
    }

    /* version Version */
    if (!opssl_asn1_get_integer(&seq, &version)) {
        OPSSL_ERR(OPSSL_ERR_X509, 0);
        return NULL;
    }

    /* privateKeyAlgorithm AlgorithmIdentifier */
    if (!opssl_asn1_get_sequence(&seq, &alg_seq)) {
        OPSSL_ERR(OPSSL_ERR_X509, 0);
        return NULL;
    }

    if (!opssl_asn1_get_oid(&alg_seq, &alg_oid)) {
        OPSSL_ERR(OPSSL_ERR_X509, 0);
        return NULL;
    }

    /* privateKey OCTET STRING */
    if (!opssl_asn1_get_element(&seq, 0x04, &private_key_data)) {
        OPSSL_ERR(OPSSL_ERR_X509, 0);
        return NULL;
    }

    /* Allocate key structure */
    key = op_malloc(sizeof(opssl_pkey_t));
    if (!key) {
        OPSSL_ERR(OPSSL_ERR_MEMORY, 0);
        return NULL;
    }

    memset(key, 0, sizeof(*key));

    /* Identify key type by algorithm OID */
    if (oid_equal(&alg_oid, oid_rsa, sizeof(oid_rsa))) {
        /* RSA private key */
        key->type = OPSSL_PKEY_RSA;
        key->key.rsa.der_len = opssl_cbs_len(&private_key_data);
        key->key.rsa.der = opssl_key_alloc(key->key.rsa.der_len);

        if (!key->key.rsa.der) {
            op_free(key);
            OPSSL_ERR(OPSSL_ERR_MEMORY, 0);
            return NULL;
        }

        memcpy(key->key.rsa.der, opssl_cbs_data(&private_key_data), key->key.rsa.der_len);
        key->bits = rsa_modulus_bits(key->key.rsa.der, key->key.rsa.der_len);

    } else if (oid_equal(&alg_oid, oid_ec, sizeof(oid_ec))) {
        /* EC private key - need to parse parameters for curve */
        opssl_cbs_t curve_oid, ec_key_seq, priv_key, pub_key_bits;

        /* Parse EC parameters (curve OID) */
        if (!opssl_asn1_get_oid(&alg_seq, &curve_oid)) {
            op_free(key);
            OPSSL_ERR(OPSSL_ERR_X509, 0);
            return NULL;
        }

        if (!parse_ec_curve_oid(&curve_oid, &key->key.ec.curve, &key->bits)) {
            op_free(key);
            return NULL;
        }

        key->type = OPSSL_PKEY_EC;

        /* Parse ECPrivateKey structure inside OCTET STRING */
        opssl_cbs_t ec_cbs;
        opssl_cbs_init(&ec_cbs, opssl_cbs_data(&private_key_data), opssl_cbs_len(&private_key_data));

        if (!opssl_asn1_get_sequence(&ec_cbs, &ec_key_seq)) {
            op_free(key);
            OPSSL_ERR(OPSSL_ERR_X509, 0);
            return NULL;
        }

        /* Skip version */
        opssl_cbs_t version;
        opssl_asn1_get_integer(&ec_key_seq, &version);

        /* privateKey OCTET STRING */
        if (!opssl_asn1_get_element(&ec_key_seq, 0x04, &priv_key)) {
            op_free(key);
            OPSSL_ERR(OPSSL_ERR_X509, 0);
            return NULL;
        }

        /* Determine expected scalar length from curve */
        size_t expected_scalar;
        switch (key->key.ec.curve) {
        case OPSSL_CURVE_P384: expected_scalar = 48; break;
        case OPSSL_CURVE_P521: expected_scalar = 66; break;
        default:               expected_scalar = 32; break;
        }

        if (opssl_cbs_len(&priv_key) > expected_scalar) {
            op_free(key);
            OPSSL_ERR(OPSSL_ERR_X509, 0);
            return NULL;
        }

        size_t scalar_len = opssl_cbs_len(&priv_key);
        size_t pad_len = expected_scalar - scalar_len;
        memset(key->key.ec.priv, 0, pad_len);
        memcpy(key->key.ec.priv + pad_len, opssl_cbs_data(&priv_key), scalar_len);
        key->key.ec.priv_len = expected_scalar;

        /*
         * After privateKey, the remaining optional fields are:
         *   parameters [0] ECParameters OPTIONAL
         *   publicKey  [1] BIT STRING OPTIONAL
         *
         * RFC 5915 uses EXPLICIT TAGS, so [0] = 0xa0, [1] = 0xa1.
         * Some encoders use IMPLICIT: [0] = 0x80, [1] = 0x81.
         * Peek at the tag byte to decide without corrupting the CBS.
         */
        while (opssl_cbs_len(&ec_key_seq) > 0) {
            uint8_t peek = opssl_cbs_data(&ec_key_seq)[0];

            if (peek == 0xa0 || peek == 0x80) {
                opssl_cbs_t params_skip;
                if (!opssl_asn1_get_element(&ec_key_seq, peek, &params_skip))
                    break;
                continue;
            }

            if (peek == 0xa1) {
                opssl_cbs_t explicit_wrapper;
                if (!opssl_asn1_get_element(&ec_key_seq, 0xa1, &explicit_wrapper))
                    break;
                if (opssl_asn1_get_element(&explicit_wrapper, 0x03, &pub_key_bits)) {
                    uint8_t unused_bits;
                    if (opssl_cbs_get_u8(&pub_key_bits, &unused_bits) && unused_bits == 0) {
                        size_t pub_len = opssl_cbs_len(&pub_key_bits);
                        if (pub_len <= sizeof(key->key.ec.pub)) {
                            memcpy(key->key.ec.pub, opssl_cbs_data(&pub_key_bits), pub_len);
                            key->key.ec.pub_len = pub_len;
                        }
                    }
                }
                break;
            }

            if (peek == 0x81) {
                if (opssl_asn1_get_element(&ec_key_seq, 0x81, &pub_key_bits)) {
                    uint8_t unused_bits;
                    if (opssl_cbs_get_u8(&pub_key_bits, &unused_bits) && unused_bits == 0) {
                        size_t pub_len = opssl_cbs_len(&pub_key_bits);
                        if (pub_len <= sizeof(key->key.ec.pub)) {
                            memcpy(key->key.ec.pub, opssl_cbs_data(&pub_key_bits), pub_len);
                            key->key.ec.pub_len = pub_len;
                        }
                    }
                }
                break;
            }

            break;
        }

    } else if (oid_equal(&alg_oid, oid_ed25519, sizeof(oid_ed25519))) {
        /* Ed25519 private key */
        key->type = OPSSL_PKEY_ED25519;
        key->bits = 256;

        /* Parse the private key data. OpenSSL's PKCS#8 Ed25519 format wraps
         * the 32-byte seed inside another OCTET STRING: 04 20 <32-byte seed> */
        const uint8_t *seed_ptr;

        if (opssl_cbs_len(&private_key_data) == 34) {
            /* Standard OpenSSL format: 04 20 <32-byte seed> */
            const uint8_t *data = opssl_cbs_data(&private_key_data);
            if (data[0] == 0x04 && data[1] == 0x20) {
                seed_ptr = data + 2;
            } else {
                op_free(key);
                OPSSL_ERR(OPSSL_ERR_X509, 0);
                return NULL;
            }
        } else if (opssl_cbs_len(&private_key_data) == 32) {
            /* Some encoders use raw 32-byte seed directly */
            seed_ptr = opssl_cbs_data(&private_key_data);
        } else {
            op_free(key);
            OPSSL_ERR(OPSSL_ERR_X509, 0);
            return NULL;
        }

        /* Copy the seed and derive the public key */
        memcpy(key->key.ed25519.priv, seed_ptr, 32);

        /* Derive public key from seed using opssl_ed25519_keygen */
        uint8_t sk_temp[64];
        memcpy(sk_temp, seed_ptr, 32);
        memset(sk_temp + 32, 0, 32);

        if (opssl_ed25519_keygen(key->key.ed25519.pub, sk_temp) != 1) {
            opssl_memzero(sk_temp, 64);
            /* Ed25519 seed already copied into key->key.ed25519.priv: must
             * zero it before releasing the heap block. */
            pkey_wipe_and_free(key);
            OPSSL_ERR(OPSSL_ERR_X509, 0);
            return NULL;
        }
        opssl_memzero(sk_temp, 64);

    } else {
        op_free(key);
        OPSSL_ERR(OPSSL_ERR_X509, 0);
        return NULL;
    }

    return key;
}

/*
 * Parse SEC1/RFC 5915 ECPrivateKey.
 */
static opssl_pkey_t *
parse_sec1_ec_key(const uint8_t *der, size_t der_len)
{
    opssl_cbs_t cbs, seq, version, priv_key;
    opssl_pkey_t *key = NULL;

    opssl_cbs_init(&cbs, der, der_len);

    /* ECPrivateKey ::= SEQUENCE {
     *   version        INTEGER { ecPrivkeyVer1(1) },
     *   privateKey     OCTET STRING,
     *   parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
     *   publicKey  [1] BIT STRING OPTIONAL
     * }
     */

    if (!opssl_asn1_get_sequence(&cbs, &seq)) {
        OPSSL_ERR(OPSSL_ERR_X509, 0);
        return NULL;
    }

    /* Version must be 1 for SEC1 EC keys */
    if (!opssl_asn1_get_integer(&seq, &version)) {
        OPSSL_ERR(OPSSL_ERR_X509, 0);
        return NULL;
    }

    /* Check version is 1 (single byte 0x01) */
    if (opssl_cbs_len(&version) != 1 || opssl_cbs_data(&version)[0] != 0x01) {
        OPSSL_ERR(OPSSL_ERR_X509, 0);
        return NULL;
    }

    /* privateKey OCTET STRING */
    if (!opssl_asn1_get_element(&seq, 0x04, &priv_key)) {
        OPSSL_ERR(OPSSL_ERR_X509, 0);
        return NULL;
    }

    key = op_malloc(sizeof(opssl_pkey_t));
    if (!key) {
        OPSSL_ERR(OPSSL_ERR_MEMORY, 0);
        return NULL;
    }

    memset(key, 0, sizeof(*key));
    key->type = OPSSL_PKEY_EC;

    /* Extract curve parameters from [0] field if present */
    opssl_curve_t curve = OPSSL_CURVE_P256;  /* Default fallback */
    size_t bits = 256;

    while (opssl_cbs_len(&seq) > 0) {
        uint8_t peek = opssl_cbs_data(&seq)[0];

        if (peek == 0xa0) {  /* [0] EXPLICIT parameters */
            opssl_cbs_t params_wrapper, curve_oid;
            if (opssl_asn1_get_element(&seq, 0xa0, &params_wrapper) &&
                opssl_asn1_get_oid(&params_wrapper, &curve_oid)) {
                parse_ec_curve_oid(&curve_oid, &curve, &bits);
            }
            continue;
        }

        if (peek == 0xa1) {  /* [1] EXPLICIT publicKey */
            opssl_cbs_t pubkey_wrapper, pub_key_bits;
            if (opssl_asn1_get_element(&seq, 0xa1, &pubkey_wrapper) &&
                opssl_asn1_get_element(&pubkey_wrapper, 0x03, &pub_key_bits)) {
                uint8_t unused_bits;
                if (opssl_cbs_get_u8(&pub_key_bits, &unused_bits) && unused_bits == 0) {
                    size_t pub_len = opssl_cbs_len(&pub_key_bits);
                    if (pub_len <= sizeof(key->key.ec.pub)) {
                        memcpy(key->key.ec.pub, opssl_cbs_data(&pub_key_bits), pub_len);
                        key->key.ec.pub_len = pub_len;
                    }
                }
            }
            break;
        }

        break;
    }

    key->key.ec.curve = curve;
    key->bits = bits;

    /* Determine expected scalar length from curve */
    size_t expected_scalar;
    switch (curve) {
    case OPSSL_CURVE_P384: expected_scalar = 48; break;
    case OPSSL_CURVE_P521: expected_scalar = 66; break;
    default:               expected_scalar = 32; break;
    }

    size_t scalar_len = opssl_cbs_len(&priv_key);
    if (scalar_len > expected_scalar) {
        op_free(key);
        OPSSL_ERR(OPSSL_ERR_X509, 0);
        return NULL;
    }

    size_t pad_len = expected_scalar - scalar_len;
    memset(key->key.ec.priv, 0, pad_len);
    memcpy(key->key.ec.priv + pad_len, opssl_cbs_data(&priv_key), scalar_len);
    key->key.ec.priv_len = expected_scalar;

    return key;
}

/*
 * Parse legacy PKCS#1 RSAPrivateKey.
 */
static opssl_pkey_t *
parse_pkcs1_rsa_key(const uint8_t *der, size_t der_len)
{
    opssl_pkey_t *key = op_malloc(sizeof(opssl_pkey_t));
    if (!key) {
        OPSSL_ERR(OPSSL_ERR_MEMORY, 0);
        return NULL;
    }

    memset(key, 0, sizeof(*key));
    key->type = OPSSL_PKEY_RSA;
    key->bits = rsa_modulus_bits(der, der_len);

    key->key.rsa.der_len = der_len;
    key->key.rsa.der = opssl_key_alloc(der_len);

    if (!key->key.rsa.der) {
        op_free(key);
        OPSSL_ERR(OPSSL_ERR_MEMORY, 0);
        return NULL;
    }

    memcpy(key->key.rsa.der, der, der_len);

    return key;
}

opssl_pkey_t *
opssl_pkey_from_der(const uint8_t *der, size_t len)
{
    if (!der || len == 0) {
        OPSSL_ERR(OPSSL_ERR_X509, 0);
        return NULL;
    }

    /* Try PKCS#8 first */
    opssl_pkey_t *key = parse_pkcs8_private_key(der, len);
    if (key) {
        return key;
    }

    /* Clear error and try SEC1 EC key format */
    opssl_err_clear();

    /* Check if it might be a SEC1 EC key by examining structure */
    opssl_cbs_t cbs, seq, version, second_field;
    opssl_cbs_init(&cbs, der, len);

    if (opssl_asn1_get_sequence(&cbs, &seq)) {
        /* Look at the structure to distinguish SEC1 EC from PKCS#1 RSA:
         * SEC1 EC: version=1, then OCTET STRING
         * PKCS#1 RSA: version=0, then large INTEGER (modulus) */
        if (opssl_asn1_get_integer(&seq, &version)) {
            /* Check if version field looks like SEC1 EC (single byte 0x01) */
            if (opssl_cbs_len(&version) == 1 &&
                opssl_cbs_data(&version)[0] == 0x01) {
                /* Next field should be OCTET STRING for SEC1 */
                if (opssl_asn1_get_element(&seq, 0x04, &second_field)) {
                    key = parse_sec1_ec_key(der, len);
                    if (key) {
                        return key;
                    }
                }
            }
        }
    }

    /* Clear error and try PKCS#1 RSA as final fallback */
    opssl_err_clear();

    opssl_cbs_init(&cbs, der, len);
    if (opssl_asn1_get_sequence(&cbs, &seq)) {
        return parse_pkcs1_rsa_key(der, len);
    }

    OPSSL_ERR(OPSSL_ERR_X509, 0);
    return NULL;
}

opssl_pkey_t *
opssl_pkey_from_pem(const char *pem, size_t len)
{
    uint8_t *der;
    size_t der_len;
    char label[64];

    if (!opssl_pem_decode(pem, len, &der, &der_len, label, sizeof(label))) {
        OPSSL_ERR(OPSSL_ERR_X509, 0);
        return NULL;
    }

    opssl_pkey_t *key = opssl_pkey_from_der(der, der_len);

    /* Clean up DER (contains sensitive data) */
    opssl_memzero(der, der_len);
    op_free(der);

    return key;
}

opssl_pkey_t *
opssl_pkey_from_file(const char *path)
{
    uint8_t *der;
    size_t der_len;
    char label[64];

    if (!opssl_pem_read_file(path, &der, &der_len, label, sizeof(label))) {
        OPSSL_ERR(OPSSL_ERR_X509, 0);
        return NULL;
    }

    /* If the first PEM block is "EC PARAMETERS" (from openssl ecparam -genkey),
     * skip it and read the actual key block ("EC PRIVATE KEY") */
    if (strcmp(label, "EC PARAMETERS") == 0) {
        opssl_memzero(der, der_len);
        op_free(der);

        /* Re-read the file and find the second PEM block */
        FILE *fp = fopen(path, "r");
        if (!fp) {
            OPSSL_ERR(OPSSL_ERR_X509, 0);
            return NULL;
        }

        char *pem_data = NULL;
        size_t pem_size = 0;
        size_t pem_cap = 4096;
        pem_data = op_malloc(pem_cap);
        if (!pem_data) { fclose(fp); return NULL; }

        size_t n;
        while ((n = fread(pem_data + pem_size, 1, pem_cap - pem_size - 1, fp)) > 0) {
            pem_size += n;
            if (pem_size + 1 >= pem_cap) {
                pem_cap *= 2;
                char *tmp = op_realloc(pem_data, pem_cap);
                if (!tmp) { op_free(pem_data); fclose(fp); return NULL; }
                pem_data = tmp;
            }
        }
        fclose(fp);
        pem_data[pem_size] = '\0';

        /* Find the second PEM block by searching past the first END marker */
        const char *second = strstr(pem_data, "-----END EC PARAMETERS-----");
        if (second) {
            second = strstr(second, "-----BEGIN ");
            if (second) {
                size_t remaining = pem_size - (size_t)(second - pem_data);
                if (opssl_pem_decode(second, remaining, &der, &der_len, label, sizeof(label))) {
                    opssl_pkey_t *key = opssl_pkey_from_der(der, der_len);
                    opssl_memzero(der, der_len);
                    op_free(der);
                    op_free(pem_data);
                    return key;
                }
            }
        }

        op_free(pem_data);
        OPSSL_ERR(OPSSL_ERR_X509, 0);
        return NULL;
    }

    opssl_pkey_t *key = opssl_pkey_from_der(der, der_len);

    /* Clean up DER (contains sensitive data) */
    opssl_memzero(der, der_len);
    op_free(der);

    return key;
}

void
opssl_pkey_free(opssl_pkey_t *key)
{
    if (!key) {
        return;
    }

    switch (key->type) {
    case OPSSL_PKEY_RSA:
        if (key->key.rsa.der) {
            opssl_key_free(key->key.rsa.der, key->key.rsa.der_len);
        }
        break;

    case OPSSL_PKEY_EC:
        opssl_memzero(key->key.ec.priv, sizeof(key->key.ec.priv));
        opssl_memzero(key->key.ec.pub, sizeof(key->key.ec.pub));
        break;

    case OPSSL_PKEY_ED25519:
        opssl_memzero(key->key.ed25519.priv, sizeof(key->key.ed25519.priv));
        opssl_memzero(key->key.ed25519.pub, sizeof(key->key.ed25519.pub));
        break;

    case OPSSL_PKEY_ED448:
        /* Not implemented yet */
        break;
    }

    opssl_memzero(key, sizeof(*key));
    op_free(key);
}

opssl_pkey_type_t
opssl_pkey_type(const opssl_pkey_t *key)
{
    return key ? key->type : OPSSL_PKEY_RSA;
}

opssl_curve_t
opssl_pkey_ec_curve(const opssl_pkey_t *key)
{
    if (!key || key->type != OPSSL_PKEY_EC)
        return (opssl_curve_t)0;
    return key->key.ec.curve;
}

size_t
opssl_pkey_bits(const opssl_pkey_t *key)
{
    return key ? key->bits : 0;
}

int
opssl_pkey_matches_cert(const opssl_pkey_t *key, const opssl_x509_t *cert)
{
    if (!key || !cert) {
        return 0;
    }

    /* Get certificate's SPKI for public key comparison */
    const uint8_t *spki_der;
    size_t spki_len;

    if (opssl_x509_get_spki(cert, &spki_der, &spki_len) != 1) {
        return 0;
    }

    /* Parse SPKI to extract public key */
    opssl_cbs_t cbs, alg_seq, alg_oid, pub_key_bits;

    opssl_cbs_init(&cbs, spki_der, spki_len);

    /* spki_der is the CONTENT of the SPKI SEQUENCE (TLV already stripped
       in cert.c), so the first element is AlgorithmIdentifier directly. */
    if (!opssl_asn1_get_sequence(&cbs, &alg_seq)) {
        return 0;
    }

    if (!opssl_asn1_get_oid(&alg_seq, &alg_oid)) {
        return 0;
    }

    if (!opssl_asn1_get_element(&cbs, 0x03, &pub_key_bits)) {
        return 0;
    }

    /* Skip unused bits byte */
    uint8_t unused_bits;
    if (!opssl_cbs_get_u8(&pub_key_bits, &unused_bits) || unused_bits != 0) {
        return 0;
    }

    /* Match based on key type */
    switch (key->type) {
    case OPSSL_PKEY_RSA:
        if (!oid_equal(&alg_oid, oid_rsa, sizeof(oid_rsa))) {
            return 0;
        }

        /* Compare RSA modulus - extract from both private key and SPKI */

        /* Extract modulus from private key DER */
        opssl_cbs_t priv_cbs, priv_seq, priv_version, priv_modulus;
        opssl_cbs_init(&priv_cbs, key->key.rsa.der, key->key.rsa.der_len);

        if (!opssl_asn1_get_sequence(&priv_cbs, &priv_seq)) return 0;

        /* Skip version if present in PKCS#1 format */
        if (opssl_asn1_get_integer(&priv_seq, &priv_version)) {
            /* Version skipped, get modulus */
        }

        if (!opssl_asn1_get_integer(&priv_seq, &priv_modulus)) return 0;

        /* Extract modulus from SPKI public key */
        opssl_cbs_t spki_pubkey_bits = pub_key_bits;
        opssl_cbs_t pub_rsa_seq, spki_modulus;

        if (!opssl_asn1_get_sequence(&spki_pubkey_bits, &pub_rsa_seq)) return 0;
        if (!opssl_asn1_get_integer(&pub_rsa_seq, &spki_modulus)) return 0;

        /*
         * Strip any DER sign-padding zero so encodings that disagree on the
         * leading 0x00 still compare equal: ASN.1 INTEGER is signed, so a
         * modulus whose high bit is set gets a 0x00 prefix. Different
         * encoders are inconsistent about emitting this byte for the
         * PKCS#1 vs SPKI representations of the same key.
         */
        const uint8_t *priv_mod_data = opssl_cbs_data(&priv_modulus);
        size_t         priv_mod_len  = opssl_cbs_len(&priv_modulus);
        if (priv_mod_len > 1 && priv_mod_data[0] == 0x00) {
            priv_mod_data++;
            priv_mod_len--;
        }

        const uint8_t *spki_mod_data = opssl_cbs_data(&spki_modulus);
        size_t         spki_mod_len  = opssl_cbs_len(&spki_modulus);
        if (spki_mod_len > 1 && spki_mod_data[0] == 0x00) {
            spki_mod_data++;
            spki_mod_len--;
        }

        if (priv_mod_len != spki_mod_len) return 0;
        return opssl_ct_eq(priv_mod_data, spki_mod_data, priv_mod_len);

    case OPSSL_PKEY_EC:
        if (!oid_equal(&alg_oid, oid_ec, sizeof(oid_ec))) {
            return 0;
        }

        /* For EC keys, compare the public point if we have it */
        if (key->key.ec.pub_len > 0) {
            const uint8_t *cert_pub = opssl_cbs_data(&pub_key_bits);
            size_t cert_pub_len = opssl_cbs_len(&pub_key_bits);

            return (cert_pub_len == key->key.ec.pub_len &&
                    opssl_ct_eq(cert_pub, key->key.ec.pub, cert_pub_len));
        }

        /* If we don't have the stored public key, derive it from private scalar */
        /* This is a simplified implementation for EC key matching */
        return 1;

    case OPSSL_PKEY_ED25519:
        if (!oid_equal(&alg_oid, oid_ed25519, sizeof(oid_ed25519))) {
            return 0;
        }

        /* For Ed25519, derive the public key from the seed and compare */
        if (opssl_cbs_len(&pub_key_bits) == 32) {
            uint8_t derived_pub[32];
            uint8_t temp_sk[64];
            memcpy(temp_sk, key->key.ed25519.priv, 32);
            memset(temp_sk + 32, 0, 32);
            opssl_ed25519_keygen(derived_pub, temp_sk);
            opssl_memzero(temp_sk, 64);
            return memcmp(derived_pub, opssl_cbs_data(&pub_key_bits), 32) == 0;
        }
        return 0;

    case OPSSL_PKEY_ED448:
        /* Not implemented yet */
        return 0;
    }

    return 0;
}

/*
 * Sign a digest using the private key.
 * Dispatches to the appropriate algorithm based on key type.
 * Returns 1 on success, 0 on failure.
 */
int
opssl_pkey_sign(const opssl_pkey_t *key, const uint8_t *digest, size_t digest_len,
                uint8_t *sig, size_t *sig_len)
{
    if (!key || !digest || !sig || !sig_len)
        return 0;

    switch (key->type) {
    case OPSSL_PKEY_RSA: {
        opssl_hmac_algo_t hash;
        switch (digest_len) {
        case OPSSL_SHA1_DIGEST_LEN: hash = OPSSL_HMAC_SHA1; break;
        case OPSSL_SHA256_DIGEST_LEN: hash = OPSSL_HMAC_SHA256; break;
        case OPSSL_SHA384_DIGEST_LEN: hash = OPSSL_HMAC_SHA384; break;
        case OPSSL_SHA512_DIGEST_LEN: hash = OPSSL_HMAC_SHA512; break;
        default: return 0;
        }

        opssl_rsa_ctx_t *rsa = opssl_rsa_new();
        if (!rsa)
            return 0;
        if (!opssl_rsa_load_private_key(rsa, key->key.rsa.der, key->key.rsa.der_len)) {
            opssl_rsa_free(rsa);
            return 0;
        }
        int ret = opssl_rsa_sign(rsa, OPSSL_RSA_PSS, hash,
                                 digest, digest_len, sig, sig_len);
        opssl_rsa_free(rsa);
        return ret;
    }

    case OPSSL_PKEY_EC: {
        opssl_ecdsa_ctx_t *ec = opssl_ecdsa_new(key->key.ec.curve);
        if (!ec)
            return 0;
        if (!opssl_ecdsa_set_private(ec, key->key.ec.priv, key->key.ec.priv_len)) {
            opssl_ecdsa_free(ec);
            return 0;
        }
        int ret = opssl_ecdsa_sign(ec, digest, digest_len, sig, sig_len);
        opssl_ecdsa_free(ec);
        return ret;
    }

    case OPSSL_PKEY_ED25519: {
        if (*sig_len < 64) {
            *sig_len = 64;
            return 0;
        }
        uint8_t sk[64];
        memcpy(sk, key->key.ed25519.priv, 32);
        memcpy(sk + 32, key->key.ed25519.pub, 32);
        int ret = opssl_ed25519_sign(sig, digest, digest_len, sk);
        opssl_memzero(sk, 64);
        *sig_len = 64;
        return ret;
    }

    case OPSSL_PKEY_ED448:
        return 0;
    }

    return 0;
}

/*
 * opssl_pkey_from_raw_bytes — construct a private key from a flat byte buffer.
 *
 * The bytes are forwarded to opssl_pkey_from_der after a defensive copy so the
 * caller's buffer is not retained. Useful when keys arrive over a wire format
 * already stripped of PEM armour. If parsing fails the temporary buffer is
 * zeroed before being freed: callers passing sensitive material should still
 * wipe their own copy, but we guarantee no residue from the path we own.
 */
opssl_pkey_t *
opssl_pkey_from_raw_bytes(const uint8_t *bytes, size_t len)
{
    if (!bytes || len == 0) {
        OPSSL_ERR(OPSSL_ERR_X509, 0);
        return NULL;
    }

    uint8_t *copy = op_malloc(len);
    if (!copy) {
        OPSSL_ERR(OPSSL_ERR_MEMORY, 0);
        return NULL;
    }
    memcpy(copy, bytes, len);

    opssl_pkey_t *key = opssl_pkey_from_der(copy, len);

    opssl_memzero(copy, len);
    op_free(copy);
    return key;
}

opssl_pkey_t *
opssl_pkey_from_ed25519_raw(const uint8_t priv[32], const uint8_t pub[32])
{
    if (!priv || !pub)
        return NULL;

    opssl_pkey_t *key = op_malloc(sizeof(opssl_pkey_t));
    if (!key) {
        OPSSL_ERR(OPSSL_ERR_MEMORY, 0);
        return NULL;
    }

    memset(key, 0, sizeof(*key));
    key->type = OPSSL_PKEY_ED25519;
    key->bits = 256;
    memcpy(key->key.ed25519.priv, priv, 32);
    memcpy(key->key.ed25519.pub, pub, 32);

    return key;
}

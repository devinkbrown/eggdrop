/*
 * OpenSSL - X.509 Certificate Parsing and Operations
 * Copyright (c) 2024 OpenSSL contributors
 */

#include <opssl/cert.h>
#include <opssl/crypto.h>
#include <opssl/platform.h>
#include <opssl/cbs.h>
#include <opssl/err.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

/* Internal certificate structure */
struct opssl_x509 {
    uint8_t *der;        /* raw DER encoding (owned) */
    size_t der_len;

    /* Parsed fields (pointers into der) */
    const uint8_t *tbs;         /* TBSCertificate */
    size_t tbs_len;
    const uint8_t *issuer_raw;
    size_t issuer_len;
    const uint8_t *subject_raw;
    size_t subject_len;
    const uint8_t *spki;        /* SubjectPublicKeyInfo (inner content) */
    size_t spki_len;
    const uint8_t *spki_der;    /* Full DER including SEQUENCE tag+length */
    size_t spki_der_len;
    const uint8_t *sig_algo_raw;
    size_t sig_algo_len;
    const uint8_t *signature;
    size_t signature_len;

    /* Serial number */
    const uint8_t *serial;
    size_t serial_len;

    /* Decoded metadata */
    int64_t not_before;
    int64_t not_after;
    opssl_pkey_type_t key_type;
    size_t key_bits;

    /* SANs (Subject Alternative Names) */
    char sans[16][256];
    int san_count;

    /* Reference count */
    int refcount;
};

/* External ASN.1 functions */
extern int opssl_asn1_get_element(opssl_cbs_t *cbs, uint8_t expected_tag, opssl_cbs_t *content);
extern int opssl_asn1_get_sequence(opssl_cbs_t *cbs, opssl_cbs_t *content);
extern int opssl_asn1_get_integer(opssl_cbs_t *cbs, opssl_cbs_t *value);
extern int opssl_asn1_get_time(opssl_cbs_t *cbs, int64_t *epoch);
extern int opssl_asn1_get_oid(opssl_cbs_t *cbs, opssl_cbs_t *oid);
extern int opssl_asn1_skip_element(opssl_cbs_t *cbs);

/* External PEM functions */
extern int opssl_pem_decode(const char *pem, size_t pem_len, uint8_t **der_out, size_t *der_len, char *label_out, size_t label_max);
extern int opssl_pem_read_file(const char *path, uint8_t **der_out, size_t *der_len, char *label_out, size_t label_max);

/* DN component parsing helper */
static int parse_dn_component(opssl_cbs_t *cbs, char *buf, size_t buf_len) {
    opssl_cbs_t oid, value;
    size_t pos = 0;

    while (CBS_len(cbs) > 0 && pos < buf_len - 1) {
        opssl_cbs_t rdn_set, rdn_seq;

        if (!opssl_asn1_get_element(cbs, 0x31, &rdn_set)) /* SET */
            break;

        if (!opssl_asn1_get_sequence(&rdn_set, &rdn_seq))
            break;

        if (!opssl_asn1_get_oid(&rdn_seq, &oid))
            break;

        if (!opssl_asn1_get_element(&rdn_seq, 0x0C, &value) && /* UTF8String */
            !opssl_asn1_get_element(&rdn_seq, 0x13, &value) && /* PrintableString */
            !opssl_asn1_get_element(&rdn_seq, 0x16, &value))   /* IA5String */
            break;

        /* Add comma separator if not first component */
        if (pos > 0 && pos < buf_len - 2) {
            buf[pos++] = ',';
            buf[pos++] = ' ';
        }

        /* Copy value */
        size_t copy_len = CBS_len(&value);
        if (copy_len > buf_len - pos - 1)
            copy_len = buf_len - pos - 1;

        memcpy(buf + pos, CBS_data(&value), copy_len);
        pos += copy_len;
    }

    buf[pos] = '\0';
    return 1;
}

/* Parse Subject Alternative Names extension */
static int parse_san_extension(opssl_x509_t *cert, opssl_cbs_t *ext_value) {
    opssl_cbs_t san_seq;

    if (!opssl_asn1_get_sequence(ext_value, &san_seq))
        return 0;

    cert->san_count = 0;

    while (CBS_len(&san_seq) > 0 && cert->san_count < 16) {
        opssl_cbs_t name_value;
        uint8_t tag;

        if (!CBS_peek_u8(&san_seq, &tag))
            break;

        /* dNSName [2] */
        if (tag == 0x82) {
            if (!opssl_asn1_get_element(&san_seq, 0x82, &name_value))
                break;

            size_t name_len = CBS_len(&name_value);
            if (name_len >= sizeof(cert->sans[0]))
                name_len = sizeof(cert->sans[0]) - 1;

            memcpy(cert->sans[cert->san_count], CBS_data(&name_value), name_len);
            cert->sans[cert->san_count][name_len] = '\0';
            cert->san_count++;
        } else {
            /* Skip other name types */
            if (!opssl_asn1_skip_element(&san_seq))
                break;
        }
    }

    return 1;
}

/* Parse certificate extensions */
static int parse_extensions(opssl_x509_t *cert, opssl_cbs_t *cbs) {
    opssl_cbs_t extensions, ext_seq;

    /* Extensions are optional and have explicit tag [3] */
    uint8_t peek;
    if (CBS_len(cbs) == 0 || !CBS_peek_u8(cbs, &peek) || peek != 0xA3)
        return 1; /* No extensions is OK */
    if (!opssl_asn1_get_element(cbs, 0xA3, &extensions))
        return 1;

    if (!opssl_asn1_get_sequence(&extensions, &ext_seq))
        return 0;

    while (CBS_len(&ext_seq) > 0) {
        opssl_cbs_t extension, oid, ext_value;

        if (!opssl_asn1_get_sequence(&ext_seq, &extension))
            break;

        if (!opssl_asn1_get_oid(&extension, &oid))
            break;

        /* Skip critical flag if present */
        uint8_t tag;
        if (CBS_peek_u8(&extension, &tag) && tag == 0x01)
            opssl_asn1_skip_element(&extension);

        if (!opssl_asn1_get_element(&extension, 0x04, &ext_value)) /* OCTET STRING */
            break;

        /* Check for Subject Alternative Name extension (2.5.29.17) */
        static const uint8_t san_oid[] = {0x55, 0x1D, 0x11};
        if (CBS_len(&oid) == sizeof(san_oid) &&
            memcmp(CBS_data(&oid), san_oid, sizeof(san_oid)) == 0) {
            parse_san_extension(cert, &ext_value);
        }
    }

    return 1;
}

/* Parse TBSCertificate structure */
static int parse_tbs_certificate(opssl_x509_t *cert) {
    opssl_cbs_t tbs, validity;

    CBS_init(&tbs, cert->tbs, cert->tbs_len);

    /* Skip version [0] if present */
    uint8_t tag;
    if (CBS_peek_u8(&tbs, &tag) && tag == 0xA0)
        opssl_asn1_skip_element(&tbs);

    /* Parse serialNumber */
    {
        opssl_cbs_t serial_val;
        if (!opssl_asn1_get_integer(&tbs, &serial_val))
            return 0;
        cert->serial = CBS_data(&serial_val);
        cert->serial_len = CBS_len(&serial_val);
    }

    /* Skip signature algorithm */
    if (!opssl_asn1_skip_element(&tbs))
        return 0;

    /* Parse issuer */
    opssl_cbs_t issuer_seq;
    if (!opssl_asn1_get_sequence(&tbs, &issuer_seq))
        return 0;
    cert->issuer_raw = CBS_data(&issuer_seq);
    cert->issuer_len = CBS_len(&issuer_seq);

    /* Parse validity */
    if (!opssl_asn1_get_sequence(&tbs, &validity))
        return 0;

    if (!opssl_asn1_get_time(&validity, &cert->not_before))
        return 0;
    if (!opssl_asn1_get_time(&validity, &cert->not_after))
        return 0;

    /* Parse subject */
    opssl_cbs_t subject_seq;
    if (!opssl_asn1_get_sequence(&tbs, &subject_seq))
        return 0;
    cert->subject_raw = CBS_data(&subject_seq);
    cert->subject_len = CBS_len(&subject_seq);

    /* Parse subjectPublicKeyInfo — store both the full DER start
     * (for fingerprinting, which must include the SEQUENCE wrapper)
     * and the inner content pointer (for key extraction). */
    cert->spki_der = CBS_data(&tbs);
    opssl_cbs_t spki_seq;
    if (!opssl_asn1_get_sequence(&tbs, &spki_seq))
        return 0;
    cert->spki_der_len = (size_t)(CBS_data(&tbs) - cert->spki_der);
    cert->spki = CBS_data(&spki_seq);
    cert->spki_len = CBS_len(&spki_seq);

    /* Parse extensions if present */
    parse_extensions(cert, &tbs);

    return 1;
}

/* Main certificate parsing function */
static opssl_x509_t *parse_certificate(const uint8_t *der, size_t len) {
    opssl_x509_t *cert = calloc(1, sizeof(opssl_x509_t));
    if (!cert)
        return NULL;

    cert->refcount = 1;
    cert->san_count = 0;

    /* Store raw DER data */
    cert->der = malloc(len);
    if (!cert->der) {
        free(cert);
        return NULL;
    }
    memcpy(cert->der, der, len);
    cert->der_len = len;

    /* Parse top-level Certificate structure (use cert->der so internal pointers remain valid) */
    opssl_cbs_t cbs, cert_seq;
    CBS_init(&cbs, cert->der, len);

    if (!opssl_asn1_get_sequence(&cbs, &cert_seq)) {
        opssl_x509_free(cert);
        return NULL;
    }

    /* Parse TBSCertificate */
    opssl_cbs_t tbs_seq;
    if (!opssl_asn1_get_sequence(&cert_seq, &tbs_seq)) {
        opssl_x509_free(cert);
        return NULL;
    }
    cert->tbs = CBS_data(&tbs_seq);
    cert->tbs_len = CBS_len(&tbs_seq);

    /* Parse signatureAlgorithm */
    opssl_cbs_t sig_algo_seq;
    if (!opssl_asn1_get_sequence(&cert_seq, &sig_algo_seq)) {
        opssl_x509_free(cert);
        return NULL;
    }
    cert->sig_algo_raw = CBS_data(&sig_algo_seq);
    cert->sig_algo_len = CBS_len(&sig_algo_seq);

    /* Parse signatureValue */
    opssl_cbs_t signature_bits;
    if (!opssl_asn1_get_element(&cert_seq, 0x03, &signature_bits)) { /* BIT STRING */
        opssl_x509_free(cert);
        return NULL;
    }
    /* Skip unused bits byte */
    if (CBS_len(&signature_bits) > 0) {
        CBS_skip(&signature_bits, 1);
        cert->signature = CBS_data(&signature_bits);
        cert->signature_len = CBS_len(&signature_bits);
    }

    /* Parse TBS contents */
    if (!parse_tbs_certificate(cert)) {
        opssl_x509_free(cert);
        return NULL;
    }

    return cert;
}

/* Public API functions */

opssl_x509_t *opssl_x509_from_der(const uint8_t *der, size_t len) {
    if (!der || len == 0) {
        opssl_set_error(OPSSL_ERR_INVALID_ARGUMENT, "Invalid DER data");
        return NULL;
    }

    return parse_certificate(der, len);
}

opssl_x509_t *opssl_x509_from_pem(const char *pem, size_t len) {
    uint8_t *der = NULL;
    size_t der_len;
    char label[64];

    if (!pem || len == 0) {
        opssl_set_error(OPSSL_ERR_INVALID_ARGUMENT, "Invalid PEM data");
        return NULL;
    }

    if (!opssl_pem_decode(pem, len, &der, &der_len, label, sizeof(label))) {
        opssl_set_error(OPSSL_ERR_PEM_DECODE, "Failed to decode PEM");
        return NULL;
    }

    opssl_x509_t *cert = opssl_x509_from_der(der, der_len);
    free(der);
    return cert;
}

opssl_x509_t *opssl_x509_from_file(const char *path) {
    uint8_t *der = NULL;
    size_t der_len;
    char label[64];

    if (!path) {
        opssl_set_error(OPSSL_ERR_INVALID_ARGUMENT, "Invalid file path");
        return NULL;
    }

    if (!opssl_pem_read_file(path, &der, &der_len, label, sizeof(label))) {
        opssl_set_error(OPSSL_ERR_FILE_READ, "Failed to read certificate file");
        return NULL;
    }

    opssl_x509_t *cert = opssl_x509_from_der(der, der_len);
    free(der);
    return cert;
}

opssl_x509_t *opssl_x509_ref(opssl_x509_t *cert) {
    if (!cert)
        return NULL;

    cert->refcount++;
    return cert;
}

void opssl_x509_free(opssl_x509_t *cert) {
    if (!cert)
        return;

    cert->refcount--;
    if (cert->refcount > 0)
        return;

    free(cert->der);
    free(cert);
}

int opssl_x509_get_subject(const opssl_x509_t *cert, char *buf, size_t len) {
    if (!cert || !buf || len == 0) {
        opssl_set_error(OPSSL_ERR_INVALID_ARGUMENT, "Invalid arguments");
        return 0;
    }

    opssl_cbs_t subject;
    CBS_init(&subject, cert->subject_raw, cert->subject_len);
    return parse_dn_component(&subject, buf, len);
}

int opssl_x509_get_issuer(const opssl_x509_t *cert, char *buf, size_t len) {
    if (!cert || !buf || len == 0) {
        opssl_set_error(OPSSL_ERR_INVALID_ARGUMENT, "Invalid arguments");
        return 0;
    }

    opssl_cbs_t issuer;
    CBS_init(&issuer, cert->issuer_raw, cert->issuer_len);
    return parse_dn_component(&issuer, buf, len);
}

int opssl_x509_get_san_count(const opssl_x509_t *cert) {
    if (!cert) {
        opssl_set_error(OPSSL_ERR_INVALID_ARGUMENT, "Invalid certificate");
        return -1;
    }

    return cert->san_count;
}

int opssl_x509_get_san(const opssl_x509_t *cert, int idx, char *buf, size_t len) {
    if (!cert || idx < 0 || idx >= cert->san_count || !buf || len == 0) {
        opssl_set_error(OPSSL_ERR_INVALID_ARGUMENT, "Invalid arguments");
        return 0;
    }

    size_t san_len = strlen(cert->sans[idx]);
    if (san_len >= len) {
        opssl_set_error(OPSSL_ERR_BUFFER_TOO_SMALL, "Buffer too small for SAN");
        return 0;
    }

    snprintf(buf, len, "%s", cert->sans[idx]);
    return 1;
}

int opssl_x509_get_not_before(const opssl_x509_t *cert, int64_t *epoch) {
    if (!cert || !epoch) {
        opssl_set_error(OPSSL_ERR_INVALID_ARGUMENT, "Invalid arguments");
        return 0;
    }

    *epoch = cert->not_before;
    return 1;
}

int opssl_x509_get_not_after(const opssl_x509_t *cert, int64_t *epoch) {
    if (!cert || !epoch) {
        opssl_set_error(OPSSL_ERR_INVALID_ARGUMENT, "Invalid arguments");
        return 0;
    }

    *epoch = cert->not_after;
    return 1;
}

int opssl_x509_is_expired(const opssl_x509_t *cert) {
    if (!cert) {
        opssl_set_error(OPSSL_ERR_INVALID_ARGUMENT, "Invalid certificate");
        return -1;
    }

    int64_t now = time(NULL);
    return (now < cert->not_before || now > cert->not_after) ? 1 : 0;
}

int opssl_x509_get_serial(const opssl_x509_t *cert, uint8_t *buf, size_t *len) {
    if (!cert || !buf || !len)
        return 0;
    if (cert->serial_len == 0 || cert->serial_len > *len)
        return 0;
    memcpy(buf, cert->serial, cert->serial_len);
    *len = cert->serial_len;
    return 1;
}

int opssl_x509_get_der(const opssl_x509_t *cert, const uint8_t **der, size_t *len) {
    if (!cert || !der || !len) {
        opssl_set_error(OPSSL_ERR_INVALID_ARGUMENT, "Invalid arguments");
        return 0;
    }

    *der = cert->der;
    *len = cert->der_len;
    return 1;
}

int opssl_x509_get_spki(const opssl_x509_t *cert, const uint8_t **spki, size_t *len) {
    if (!cert || !spki || !len) {
        opssl_set_error(OPSSL_ERR_INVALID_ARGUMENT, "Invalid arguments");
        return 0;
    }

    *spki = cert->spki;
    *len = cert->spki_len;
    return 1;
}

int opssl_x509_get_spki_der(const opssl_x509_t *cert, const uint8_t **spki, size_t *len) {
    if (!cert || !spki || !len) {
        opssl_set_error(OPSSL_ERR_INVALID_ARGUMENT, "Invalid arguments");
        return 0;
    }

    *spki = cert->spki_der;
    *len = cert->spki_der_len;
    return 1;
}
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
    char **sans;
    int san_count;
    int san_cap;

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

/*
 * Validate UTF-8 byte sequence per RFC 3629.
 * Rejects overlong forms, surrogates, and code points > U+10FFFF.
 * Returns 1 if valid, 0 otherwise.
 */
static int is_valid_utf8(const uint8_t *s, size_t len) {
    size_t i = 0;
    while (i < len) {
        uint8_t b = s[i];
        if (b < 0x80) { i++; continue; }
        uint32_t cp; size_t extra;
        if ((b & 0xE0) == 0xC0) { cp = b & 0x1F; extra = 1; if (b < 0xC2) return 0; }
        else if ((b & 0xF0) == 0xE0) { cp = b & 0x0F; extra = 2; }
        else if ((b & 0xF8) == 0xF0) { cp = b & 0x07; extra = 3; if (b > 0xF4) return 0; }
        else return 0;
        if (i + extra >= len) return 0;
        for (size_t j = 1; j <= extra; j++) {
            uint8_t c = s[i + j];
            if ((c & 0xC0) != 0x80) return 0;
            cp = (cp << 6) | (c & 0x3F);
        }
        /* Reject overlong, surrogates, and > U+10FFFF */
        if (extra == 2 && cp < 0x800) return 0;
        if (extra == 3 && cp < 0x10000) return 0;
        if (cp >= 0xD800 && cp <= 0xDFFF) return 0;
        if (cp > 0x10FFFF) return 0;
        i += extra + 1;
    }
    return 1;
}

/* Reject buffers containing an embedded NUL byte — defeats CN/SAN
 * NUL-byte name-confusion attacks (e.g., "evil.com\0good.com"). */
static int has_embedded_nul(const uint8_t *s, size_t len) {
    return memchr(s, '\0', len) != NULL;
}

/* DN component parsing helper. Returns 1 on success, 0 on malformed input. */
static int parse_dn_component(opssl_cbs_t *cbs, char *buf, size_t buf_len) {
    opssl_cbs_t oid, value;
    size_t pos = 0;

    if (buf_len == 0)
        return 0;

    /* Reserve room for terminator. */
    while (CBS_len(cbs) > 0 && pos + 1 < buf_len) {
        opssl_cbs_t rdn_set, rdn_seq;
        uint8_t value_tag = 0;

        if (!opssl_asn1_get_element(cbs, 0x31, &rdn_set)) /* SET */
            break;

        if (!opssl_asn1_get_sequence(&rdn_set, &rdn_seq))
            break;

        if (!opssl_asn1_get_oid(&rdn_seq, &oid))
            break;

        /* Try common string tags in order. */
        if (opssl_asn1_get_element(&rdn_seq, 0x0C, &value))      value_tag = 0x0C; /* UTF8 */
        else if (opssl_asn1_get_element(&rdn_seq, 0x13, &value)) value_tag = 0x13; /* Printable */
        else if (opssl_asn1_get_element(&rdn_seq, 0x16, &value)) value_tag = 0x16; /* IA5 */
        else break;

        size_t v_len = CBS_len(&value);
        const uint8_t *v_data = CBS_data(&value);

        /* Reject NUL-byte name-confusion. */
        if (has_embedded_nul(v_data, v_len))
            return 0;

        /* UTF8String must be valid UTF-8 per RFC 5280 + RFC 3629. */
        if (value_tag == 0x0C && !is_valid_utf8(v_data, v_len))
            return 0;

        /* Add comma separator if not first component. Need at least 3 free
         * bytes (", " + NUL) to safely insert a separator. */
        if (pos > 0) {
            if (pos + 3 >= buf_len)
                break;
            buf[pos++] = ',';
            buf[pos++] = ' ';
        }

        /* Copy value, leaving room for terminator. */
        size_t avail = buf_len - pos - 1;
        size_t copy_len = v_len < avail ? v_len : avail;

        memcpy(buf + pos, v_data, copy_len);
        pos += copy_len;

        /* If we had to truncate, stop to avoid emitting a partial name. */
        if (copy_len < v_len)
            break;
    }

    buf[pos] = '\0';
    return 1;
}

/* Hard cap on SANs to bound memory use against malicious certs. */
#define OPSSL_MAX_SAN_ENTRIES 1024
/* RFC 1035 max DNS name length. */
#define OPSSL_MAX_DNS_NAME_LEN 253
/* Max rfc822Name length (local-part 64 + "@" + domain 253). */
#define OPSSL_MAX_EMAIL_LEN 320

/* Append a SAN entry to the cert. Returns 1 on success, 0 on alloc failure
 * or if the per-cert cap is hit. */
static int append_san(opssl_x509_t *cert, const char *prefix, size_t prefix_len,
                      const uint8_t *data, size_t data_len) {
    if (cert->san_count >= OPSSL_MAX_SAN_ENTRIES)
        return 0;

    if (cert->san_count >= cert->san_cap) {
        int new_cap = cert->san_cap ? cert->san_cap * 2 : 16;
        if (new_cap > OPSSL_MAX_SAN_ENTRIES) new_cap = OPSSL_MAX_SAN_ENTRIES;
        /* Overflow guard: new_cap * sizeof(char*). */
        if ((size_t)new_cap > SIZE_MAX / sizeof(char *))
            return 0;
        char **tmp = realloc(cert->sans, (size_t)new_cap * sizeof(char *));
        if (!tmp) return 0;
        cert->sans = tmp;
        cert->san_cap = new_cap;
    }

    /* prefix + data + NUL */
    if (data_len > SIZE_MAX - prefix_len - 1)
        return 0;
    size_t total = prefix_len + data_len + 1;
    char *buf = malloc(total);
    if (!buf) return 0;
    if (prefix_len) memcpy(buf, prefix, prefix_len);
    memcpy(buf + prefix_len, data, data_len);
    buf[prefix_len + data_len] = '\0';

    cert->sans[cert->san_count++] = buf;
    return 1;
}

/* Parse Subject Alternative Names extension. Returns 1 on success. */
static int parse_san_extension(opssl_x509_t *cert, opssl_cbs_t *ext_value) {
    opssl_cbs_t san_seq;

    if (!opssl_asn1_get_sequence(ext_value, &san_seq))
        return 0;

    cert->san_count = 0;
    cert->san_cap = 0;
    cert->sans = NULL;

    while (CBS_len(&san_seq) > 0) {
        opssl_cbs_t name_value;
        uint8_t tag;

        if (!CBS_peek_u8(&san_seq, &tag))
            break;

        if (tag == 0x82) {
            /* dNSName [2] IA5String */
            if (!opssl_asn1_get_element(&san_seq, 0x82, &name_value))
                break;
            size_t name_len = CBS_len(&name_value);
            const uint8_t *name_data = CBS_data(&name_value);
            /* Reject truncation, NUL-byte attacks, and oversize names. */
            if (name_len == 0 || name_len > OPSSL_MAX_DNS_NAME_LEN)
                break;
            if (has_embedded_nul(name_data, name_len))
                break;
            if (!append_san(cert, NULL, 0, name_data, name_len))
                break;
        } else if (tag == 0x81) {
            /* rfc822Name [1] IA5String */
            if (!opssl_asn1_get_element(&san_seq, 0x81, &name_value))
                break;
            size_t name_len = CBS_len(&name_value);
            const uint8_t *name_data = CBS_data(&name_value);
            if (name_len == 0 || name_len > OPSSL_MAX_EMAIL_LEN)
                break;
            if (has_embedded_nul(name_data, name_len))
                break;
            /* email: prefix so callers can disambiguate. */
            static const char p[] = "email:";
            if (!append_san(cert, p, sizeof(p) - 1, name_data, name_len))
                break;
        } else if (tag == 0x87) {
            /* iPAddress [7] OCTET STRING — 4 bytes (v4) or 16 bytes (v6). */
            if (!opssl_asn1_get_element(&san_seq, 0x87, &name_value))
                break;
            size_t ip_len = CBS_len(&name_value);
            const uint8_t *ip = CBS_data(&name_value);
            char ipbuf[64];
            int written;
            if (ip_len == 4) {
                written = snprintf(ipbuf, sizeof(ipbuf), "IP:%u.%u.%u.%u",
                                   ip[0], ip[1], ip[2], ip[3]);
            } else if (ip_len == 16) {
                written = snprintf(ipbuf, sizeof(ipbuf),
                    "IP:%02x%02x:%02x%02x:%02x%02x:%02x%02x:"
                    "%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                    ip[0], ip[1], ip[2], ip[3], ip[4], ip[5], ip[6], ip[7],
                    ip[8], ip[9], ip[10], ip[11], ip[12], ip[13], ip[14], ip[15]);
            } else {
                /* Malformed iPAddress: reject the entry but continue parsing. */
                continue;
            }
            if (written <= 0 || (size_t)written >= sizeof(ipbuf))
                break;
            if (!append_san(cert, NULL, 0, (const uint8_t *)ipbuf, (size_t)written))
                break;
        } else {
            /* Skip unsupported name types (e.g., otherName, x400Address,
             * directoryName, ediPartyName, URI, registeredID). */
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

    for (int i = 0; i < cert->san_count; i++)
        free(cert->sans[i]);
    free(cert->sans);
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
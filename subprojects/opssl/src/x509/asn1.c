/*
 * opssl/x509/asn1.c — minimal ASN.1 DER parser for X.509 certificate processing.
 *
 * Implements essential ASN.1 BER/DER parsing operations for certificate
 * validation. Follows ITU-T X.690 encoding rules with strict DER validation.
 *
 * Copyright (C) 2026 ophion development team
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <opssl/platform.h>
#include <opssl/cbs.h>
#include <opssl/err.h>
#include <string.h>

/* ASN.1 universal tags */
#define ASN1_BOOLEAN           0x01
#define ASN1_INTEGER           0x02
#define ASN1_BIT_STRING        0x03
#define ASN1_OCTET_STRING      0x04
#define ASN1_NULL              0x05
#define ASN1_OID               0x06
#define ASN1_UTF8STRING        0x0C
#define ASN1_PRINTABLESTRING   0x13
#define ASN1_T61STRING         0x14
#define ASN1_IA5STRING         0x16
#define ASN1_UTCTIME           0x17
#define ASN1_GENERALIZEDTIME   0x18
#define ASN1_SEQUENCE          0x30
#define ASN1_SET               0x31
#define ASN1_CONTEXT_0         0xA0
#define ASN1_CONTEXT_3         0xA3

/* Length encoding limits */
#define ASN1_LONG_FORM_MASK    0x80
#define ASN1_LENGTH_INDEFINITE 0x80

/*
 * Parse a single ASN.1 tag from CBS.
 * Returns 1 on success, 0 on failure.
 */
int
opssl_asn1_get_tag(opssl_cbs_t *cbs, uint8_t *tag)
{
    if (!cbs || !tag) {
        OPSSL_ERR(OPSSL_ERR_INTERNAL, 0);
        return 0;
    }

    return opssl_cbs_get_u8(cbs, tag);
}

/*
 * Parse ASN.1 length encoding from CBS.
 * DER uses definite length encoding only.
 */
int
opssl_asn1_get_length(opssl_cbs_t *cbs, size_t *len)
{
    uint8_t initial;

    if (!cbs || !len) {
        OPSSL_ERR(OPSSL_ERR_INTERNAL, 0);
        return 0;
    }

    if (!opssl_cbs_get_u8(cbs, &initial)) {
        OPSSL_ERR(OPSSL_ERR_X509, 1);
        return 0;
    }

    /* Short form: length < 128 */
    if ((initial & ASN1_LONG_FORM_MASK) == 0) {
        *len = initial;
        return 1;
    }

    /* Long form: high bit set, bottom 7 bits = num octets */
    uint8_t num_octets = initial & 0x7F;

    /* DER forbids indefinite length */
    if (num_octets == 0) {
        OPSSL_ERR(OPSSL_ERR_X509, 2);
        return 0;
    }

    /* Prevent integer overflow */
    if (num_octets > sizeof(size_t)) {
        OPSSL_ERR(OPSSL_ERR_X509, 3);
        return 0;
    }

    *len = 0;
    for (uint8_t i = 0; i < num_octets; i++) {
        uint8_t byte;
        if (!opssl_cbs_get_u8(cbs, &byte)) {
            OPSSL_ERR(OPSSL_ERR_X509, 4);
            return 0;
        }

        /* Check for overflow */
        if (*len > (SIZE_MAX >> 8)) {
            OPSSL_ERR(OPSSL_ERR_X509, 5);
            return 0;
        }

        *len = (*len << 8) | byte;
    }

    /* DER canonical encoding: no leading zeros in length */
    if (num_octets > 1 && *len < (1ULL << (8 * (num_octets - 1)))) {
        OPSSL_ERR(OPSSL_ERR_X509, 6);
        return 0;
    }

    return 1;
}

/*
 * Parse a complete TLV element with expected tag.
 * Content CBS points to the value portion.
 */
int
opssl_asn1_get_element(opssl_cbs_t *cbs, uint8_t expected_tag, opssl_cbs_t *content)
{
    uint8_t tag;
    size_t len;

    if (!cbs || !content) {
        OPSSL_ERR(OPSSL_ERR_INTERNAL, 0);
        return 0;
    }

    if (!opssl_asn1_get_tag(cbs, &tag) ||
        !opssl_asn1_get_length(cbs, &len)) {
        return 0;
    }

    if (tag != expected_tag) {
        OPSSL_ERR(OPSSL_ERR_X509, 7);
        return 0;
    }

    return opssl_cbs_get_bytes(cbs, content, len);
}

/*
 * Parse ASN.1 INTEGER.
 * Value CBS contains the integer content (including sign bit).
 */
int
opssl_asn1_get_integer(opssl_cbs_t *cbs, opssl_cbs_t *value)
{
    opssl_cbs_t content;

    if (!opssl_asn1_get_element(cbs, ASN1_INTEGER, &content)) {
        return 0;
    }

    /* DER: INTEGER must have at least one octet */
    if (opssl_cbs_is_empty(&content)) {
        OPSSL_ERR(OPSSL_ERR_X509, 8);
        return 0;
    }

    *value = content;
    return 1;
}

/*
 * Parse ASN.1 SEQUENCE.
 */
int
opssl_asn1_get_sequence(opssl_cbs_t *cbs, opssl_cbs_t *content)
{
    return opssl_asn1_get_element(cbs, ASN1_SEQUENCE, content);
}

/*
 * Parse ASN.1 SET.
 */
int
opssl_asn1_get_set(opssl_cbs_t *cbs, opssl_cbs_t *content)
{
    return opssl_asn1_get_element(cbs, ASN1_SET, content);
}

/*
 * Parse ASN.1 BIT STRING.
 * Returns the content and number of unused bits in the last octet.
 */
int
opssl_asn1_get_bit_string(opssl_cbs_t *cbs, opssl_cbs_t *content, uint8_t *unused_bits)
{
    opssl_cbs_t raw_content;
    uint8_t unused;

    if (!unused_bits) {
        OPSSL_ERR(OPSSL_ERR_INTERNAL, 0);
        return 0;
    }

    if (!opssl_asn1_get_element(cbs, ASN1_BIT_STRING, &raw_content)) {
        return 0;
    }

    /* First octet is unused bits count */
    if (!opssl_cbs_get_u8(&raw_content, &unused)) {
        OPSSL_ERR(OPSSL_ERR_X509, 9);
        return 0;
    }

    /* Unused bits must be 0-7 */
    if (unused > 7) {
        OPSSL_ERR(OPSSL_ERR_X509, 10);
        return 0;
    }

    /* If empty, unused must be 0 */
    if (opssl_cbs_is_empty(&raw_content) && unused != 0) {
        OPSSL_ERR(OPSSL_ERR_X509, 11);
        return 0;
    }

    *unused_bits = unused;
    *content = raw_content;
    return 1;
}

/*
 * Parse ASN.1 OCTET STRING.
 */
int
opssl_asn1_get_octet_string(opssl_cbs_t *cbs, opssl_cbs_t *content)
{
    return opssl_asn1_get_element(cbs, ASN1_OCTET_STRING, content);
}

/*
 * Parse ASN.1 OBJECT IDENTIFIER.
 */
int
opssl_asn1_get_oid(opssl_cbs_t *cbs, opssl_cbs_t *oid)
{
    opssl_cbs_t content;

    if (!opssl_asn1_get_element(cbs, ASN1_OID, &content)) {
        return 0;
    }

    /* OID must have at least one octet */
    if (opssl_cbs_is_empty(&content)) {
        OPSSL_ERR(OPSSL_ERR_X509, 12);
        return 0;
    }

    *oid = content;
    return 1;
}

/*
 * Parse ASN.1 BOOLEAN.
 */
int
opssl_asn1_get_boolean(opssl_cbs_t *cbs, bool *value)
{
    opssl_cbs_t content;
    uint8_t byte;

    if (!value) {
        OPSSL_ERR(OPSSL_ERR_INTERNAL, 0);
        return 0;
    }

    if (!opssl_asn1_get_element(cbs, ASN1_BOOLEAN, &content)) {
        return 0;
    }

    /* BOOLEAN must be exactly one octet */
    if (opssl_cbs_len(&content) != 1) {
        OPSSL_ERR(OPSSL_ERR_X509, 13);
        return 0;
    }

    if (!opssl_cbs_get_u8(&content, &byte)) {
        OPSSL_ERR(OPSSL_ERR_X509, 14);
        return 0;
    }

    /* DER: TRUE must be 0xFF, FALSE must be 0x00 */
    if (byte != 0x00 && byte != 0xFF) {
        OPSSL_ERR(OPSSL_ERR_X509, 15);
        return 0;
    }

    *value = (byte != 0x00);
    return 1;
}

/*
 * Compare OID with expected byte sequence.
 */
int
opssl_asn1_oid_equal(const opssl_cbs_t *oid, const uint8_t *expected, size_t len)
{
    if (!oid || !expected) {
        return 0;
    }

    if (opssl_cbs_len(oid) != len) {
        return 0;
    }

    return opssl_ct_eq(opssl_cbs_data(oid), expected, len);
}

/*
 * Parse ASN.1 time (UTCTime or GeneralizedTime) to Unix epoch.
 * UTCTime: YYMMDDHHMMSSZ (13 chars)
 * GeneralizedTime: YYYYMMDDHHMMSSZ (15 chars)
 */
int
opssl_asn1_get_time(opssl_cbs_t *cbs, int64_t *epoch)
{
    uint8_t tag;
    opssl_cbs_t content;
    const uint8_t *time_str;
    size_t time_len;
    int year, month, day, hour, min, sec;

    if (!epoch) {
        OPSSL_ERR(OPSSL_ERR_INTERNAL, 0);
        return 0;
    }

    /* Peek at tag to determine time format */
    if (!opssl_cbs_peek_u8(cbs, &tag)) {
        OPSSL_ERR(OPSSL_ERR_X509, 16);
        return 0;
    }

    if (tag == ASN1_UTCTIME) {
        if (!opssl_asn1_get_element(cbs, ASN1_UTCTIME, &content)) {
            return 0;
        }
    } else if (tag == ASN1_GENERALIZEDTIME) {
        if (!opssl_asn1_get_element(cbs, ASN1_GENERALIZEDTIME, &content)) {
            return 0;
        }
    } else {
        OPSSL_ERR(OPSSL_ERR_X509, 17);
        return 0;
    }

    time_str = opssl_cbs_data(&content);
    time_len = opssl_cbs_len(&content);

    /* Validate format and parse */
    if (tag == ASN1_UTCTIME) {
        /* YYMMDDHHMMSSZ */
        if (time_len != 13 || time_str[12] != 'Z') {
            OPSSL_ERR(OPSSL_ERR_X509, 18);
            return 0;
        }

        year = (time_str[0] - '0') * 10 + (time_str[1] - '0');
        /* RFC 5280: if YY >= 50, then 19YY; else 20YY */
        year += (year >= 50) ? 1900 : 2000;

        month = (time_str[2] - '0') * 10 + (time_str[3] - '0');
        day = (time_str[4] - '0') * 10 + (time_str[5] - '0');
        hour = (time_str[6] - '0') * 10 + (time_str[7] - '0');
        min = (time_str[8] - '0') * 10 + (time_str[9] - '0');
        sec = (time_str[10] - '0') * 10 + (time_str[11] - '0');
    } else {
        /* YYYYMMDDHHMMSSZ */
        if (time_len != 15 || time_str[14] != 'Z') {
            OPSSL_ERR(OPSSL_ERR_X509, 19);
            return 0;
        }

        year = (time_str[0] - '0') * 1000 + (time_str[1] - '0') * 100 +
               (time_str[2] - '0') * 10 + (time_str[3] - '0');
        month = (time_str[4] - '0') * 10 + (time_str[5] - '0');
        day = (time_str[6] - '0') * 10 + (time_str[7] - '0');
        hour = (time_str[8] - '0') * 10 + (time_str[9] - '0');
        min = (time_str[10] - '0') * 10 + (time_str[11] - '0');
        sec = (time_str[12] - '0') * 10 + (time_str[13] - '0');
    }

    /* Basic range validation */
    if (month < 1 || month > 12 ||
        day < 1 || day > 31 ||
        hour > 23 || min > 59 || sec > 59) {
        OPSSL_ERR(OPSSL_ERR_X509, 20);
        return 0;
    }

    /* Convert to Unix timestamp (simplified, no leap seconds) */
    static const int days_in_month[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    int64_t days = 0;

    /* Count days from 1970 */
    for (int y = 1970; y < year; y++) {
        days += 365;
        /* Leap year */
        if ((y % 4 == 0 && y % 100 != 0) || (y % 400 == 0)) {
            days++;
        }
    }

    /* Add days for completed months in current year */
    for (int m = 1; m < month; m++) {
        days += days_in_month[m - 1];
        /* February in leap year */
        if (m == 2 && ((year % 4 == 0 && year % 100 != 0) || (year % 400 == 0))) {
            days++;
        }
    }

    days += day - 1; /* Zero-based day */

    *epoch = days * 86400 + hour * 3600 + min * 60 + sec;
    return 1;
}

/*
 * Extract string from ASN.1 string types to C string.
 * Handles UTF8String, PrintableString, IA5String, T61String.
 */
int
opssl_asn1_get_string(opssl_cbs_t *cbs, char *out, size_t out_len)
{
    uint8_t tag;
    opssl_cbs_t content;
    size_t str_len;

    if (!out || out_len == 0) {
        OPSSL_ERR(OPSSL_ERR_INTERNAL, 0);
        return 0;
    }

    if (!opssl_cbs_peek_u8(cbs, &tag)) {
        OPSSL_ERR(OPSSL_ERR_X509, 21);
        return 0;
    }

    /* Accept common string types */
    if (tag != ASN1_UTF8STRING && tag != ASN1_PRINTABLESTRING &&
        tag != ASN1_IA5STRING && tag != ASN1_T61STRING) {
        OPSSL_ERR(OPSSL_ERR_X509, 22);
        return 0;
    }

    if (!opssl_asn1_get_element(cbs, tag, &content)) {
        return 0;
    }

    str_len = opssl_cbs_len(&content);

    /* Ensure space for null terminator */
    if (str_len >= out_len) {
        OPSSL_ERR(OPSSL_ERR_X509, 23);
        return 0;
    }

    if (!opssl_cbs_copy_bytes(&content, (uint8_t *)out, str_len)) {
        return 0;
    }

    out[str_len] = '\0';
    return 1;
}

/*
 * Skip an ASN.1 element regardless of its type.
 */
int
opssl_asn1_skip_element(opssl_cbs_t *cbs)
{
    uint8_t tag;
    size_t len;

    if (!opssl_asn1_get_tag(cbs, &tag) ||
        !opssl_asn1_get_length(cbs, &len)) {
        return 0;
    }

    return opssl_cbs_skip(cbs, len);
}
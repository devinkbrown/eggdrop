/*
 * opssl/x509/pem.c — PEM encoding/decoding (RFC 7468).
 *
 * Handles base64 encoding/decoding and PEM format parsing for certificates
 * and private keys. Supports both single and multiple PEM blocks.
 *
 * PEM format:
 * -----BEGIN CERTIFICATE-----
 * <base64 encoded DER data>
 * -----END CERTIFICATE-----
 *
 * Copyright (C) 2026 ophion development team
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <opssl/platform.h>
#include <opssl/cert.h>
#include <opssl/err.h>
#include <string.h>

/* PEM constants */
#define PEM_BEGIN_PREFIX "-----BEGIN "
#define PEM_END_PREFIX   "-----END "
#define PEM_SUFFIX       "-----"

/* Base64 alphabet */
static const char base64_chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* Base64 decode table (256 entries, invalid = 0xFF) */
static const uint8_t base64_decode_table[256] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, /* 0x00-0x07 */
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, /* 0x08-0x0F */
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, /* 0x10-0x17 */
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, /* 0x18-0x1F */
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, /* 0x20-0x27 */
    0xFF, 0xFF, 0xFF, 0x3E, 0xFF, 0xFF, 0xFF, 0x3F, /* 0x28-0x2F */
    0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, /* 0x30-0x37 */
    0x3C, 0x3D, 0xFF, 0xFF, 0xFF, 0x00, 0xFF, 0xFF, /* 0x38-0x3F */
    0xFF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, /* 0x40-0x47 */
    0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, /* 0x48-0x4F */
    0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, /* 0x50-0x57 */
    0x17, 0x18, 0x19, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, /* 0x58-0x5F */
    0xFF, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, /* 0x60-0x67 */
    0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, /* 0x68-0x6F */
    0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, /* 0x70-0x77 */
    0x31, 0x32, 0x33, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, /* 0x78-0x7F */
    [0x80 ... 0xFF] = 0xFF /* All high bytes invalid */
};

/*
 * Skip whitespace and line breaks in PEM data.
 */
static const char *
skip_whitespace(const char *p, const char *end)
{
    while (p < end && (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')) {
        p++;
    }
    return p;
}

/*
 * Find next line in PEM data.
 */
static const char *
find_line_end(const char *p, const char *end)
{
    while (p < end && *p != '\r' && *p != '\n') {
        p++;
    }
    return p;
}

/*
 * Find PEM begin marker and extract label.
 */
static const char *
find_pem_begin(const char *pem, const char *end, char *label, size_t label_max)
{
    const char *p = pem;

    while (p < end) {
        p = skip_whitespace(p, end);
        if (p >= end) break;

        /* Look for "-----BEGIN ". Use <= so a marker that sits flush against
         * the end of the buffer is still recognised. */
        if ((size_t)(end - p) >= strlen(PEM_BEGIN_PREFIX) &&
            memcmp(p, PEM_BEGIN_PREFIX, strlen(PEM_BEGIN_PREFIX)) == 0) {

            p += strlen(PEM_BEGIN_PREFIX);
            const char *label_start = p;

            /* Find "-----" suffix. memcmp would over-read past `end` when
             * fewer than strlen(SUFFIX) bytes remain; bound the comparison. */
            size_t suf_len = strlen(PEM_SUFFIX);
            while ((size_t)(end - p) >= suf_len &&
                   memcmp(p, PEM_SUFFIX, suf_len) != 0) {
                p++;
            }

            if ((size_t)(end - p) < suf_len) {
                OPSSL_ERR(OPSSL_ERR_X509, 50);
                return NULL;
            }

            size_t label_len = p - label_start;
            if (label_len >= label_max) {
                OPSSL_ERR(OPSSL_ERR_X509, 51);
                return NULL;
            }

            memcpy(label, label_start, label_len);
            label[label_len] = '\0';

            p += strlen(PEM_SUFFIX);
            p = skip_whitespace(p, end);
            return p; /* Return start of base64 data */
        }

        p = find_line_end(p, end);
        if (p < end) p++; /* Skip newline */
    }

    return NULL; /* No BEGIN marker found */
}

/*
 * Find PEM end marker matching the given label.
 */
static const char *
find_pem_end(const char *data, const char *end, const char *label)
{
    const char *p = data;
    size_t label_len = strlen(label);

    while (p < end) {
        const char *line_start = p;
        p = skip_whitespace(p, end);
        if (p >= end) break;

        /* Look for "-----END <label>-----" with strict bounds checks. */
        size_t pre = strlen(PEM_END_PREFIX);
        size_t suf = strlen(PEM_SUFFIX);
        if ((size_t)(end - p) >= pre + label_len + suf &&
            memcmp(p, PEM_END_PREFIX, pre) == 0 &&
            memcmp(p + pre, label, label_len) == 0 &&
            memcmp(p + pre + label_len, PEM_SUFFIX, suf) == 0) {
            return line_start;
        }

        p = find_line_end(p, end);
        if (p < end) p++;
    }

    OPSSL_ERR(OPSSL_ERR_X509, 52);
    return NULL;
}

/*
 * Base64 decode implementation.
 */
int
opssl_base64_decode(const char *in, size_t in_len, uint8_t *out, size_t *out_len)
{
    const char *in_end = in + in_len;
    const char *p = in;
    uint8_t *out_p = out;
    size_t max_out = *out_len;
    uint32_t accum = 0;
    int accum_bits = 0;
    int padding = 0;

    if (!in || !out || !out_len) {
        OPSSL_ERR(OPSSL_ERR_INTERNAL, 0);
        return 0;
    }

    while (p < in_end) {
        char c = *p++;

        /* Skip whitespace */
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
            continue;
        }

        /* Handle padding */
        if (c == '=') {
            padding++;
            continue;
        }

        /* No more data after padding */
        if (padding > 0) {
            OPSSL_ERR(OPSSL_ERR_X509, 53);
            return 0;
        }

        /* Decode character */
        uint8_t val = base64_decode_table[(uint8_t)c];
        if (val == 0xFF) {
            OPSSL_ERR(OPSSL_ERR_X509, 54);
            return 0;
        }

        accum = (accum << 6) | val;
        accum_bits += 6;

        /* Extract complete bytes */
        if (accum_bits >= 8) {
            if ((size_t)(out_p - out) >= max_out) {
                OPSSL_ERR(OPSSL_ERR_X509, 55);
                return 0;
            }

            *out_p++ = (uint8_t)(accum >> (accum_bits - 8));
            accum_bits -= 8;
        }
    }

    /* Validate padding */
    if (padding > 2) {
        OPSSL_ERR(OPSSL_ERR_X509, 56);
        return 0;
    }

    /* Check for leftover bits */
    if (accum_bits > 0 && (accum & ((1 << accum_bits) - 1)) != 0) {
        OPSSL_ERR(OPSSL_ERR_X509, 57);
        return 0;
    }

    *out_len = out_p - out;
    return 1;
}

/*
 * Base64 encode implementation.
 */
int
opssl_base64_encode(const uint8_t *in, size_t in_len, char *out, size_t *out_len)
{
    size_t max_out = *out_len;
    size_t encoded_len = ((in_len + 2) / 3) * 4;
    size_t lines = (encoded_len + 63) / 64; /* 64 chars per line */
    size_t total_len = encoded_len + lines; /* Add newlines */

    if (!in || !out || !out_len) {
        OPSSL_ERR(OPSSL_ERR_INTERNAL, 0);
        return 0;
    }

    if (total_len >= max_out) {
        OPSSL_ERR(OPSSL_ERR_X509, 58);
        return 0;
    }

    const uint8_t *in_p = in;
    char *out_p = out;
    size_t line_pos = 0;

    while (in_len > 0) {
        uint32_t triple = 0;
        int triple_bytes = 0;

        /* Read up to 3 input bytes */
        for (int i = 0; i < 3 && in_len > 0; i++) {
            triple = (triple << 8) | *in_p++;
            triple_bytes++;
            in_len--;
        }

        /* Pad to complete triple */
        triple <<= (3 - triple_bytes) * 8;

        /* Extract 4 base64 characters: triple_bytes+1 real chars, rest '=' */
        int real_chars = triple_bytes + 1;
        for (int i = 3; i >= 0; i--) {
            int char_idx = 3 - i;
            if (char_idx < real_chars) {
                *out_p++ = base64_chars[(triple >> (i * 6)) & 0x3F];
            } else {
                *out_p++ = '=';
            }
            line_pos++;
        }

        /* Add newline every 64 characters */
        if (line_pos >= 64) {
            *out_p++ = '\n';
            line_pos = 0;
        }
    }

    /* Final newline if needed */
    if (line_pos > 0) {
        *out_p++ = '\n';
    }

    *out_len = out_p - out;
    return 1;
}

/*
 * Decode a single PEM block to DER.
 */
int
opssl_pem_decode(const char *pem, size_t pem_len,
                 uint8_t **der_out, size_t *der_len,
                 char *label_out, size_t label_max)
{
    const char *pem_end = pem + pem_len;
    char label[64];

    if (!pem || !der_out || !der_len) {
        OPSSL_ERR(OPSSL_ERR_INTERNAL, 0);
        return 0;
    }

    /* Find BEGIN marker */
    const char *data_start = find_pem_begin(pem, pem_end, label, sizeof(label));
    if (!data_start) {
        return 0;
    }

    /* Find matching END marker */
    const char *data_end = find_pem_end(data_start, pem_end, label);
    if (!data_end) {
        return 0;
    }

    /* Calculate maximum decoded size with overflow check. */
    size_t b64_len = (size_t)(data_end - data_start);
    if (b64_len > (SIZE_MAX - 3) / 3) {
        OPSSL_ERR(OPSSL_ERR_X509, 60);
        return 0;
    }
    size_t max_der_len = (b64_len * 3) / 4 + 3; /* Overestimate */

    /* Allocate output buffer */
    uint8_t *der_buf = op_malloc(max_der_len);
    if (!der_buf) {
        OPSSL_ERR(OPSSL_ERR_MEMORY, 0);
        return 0;
    }

    /* Decode base64 */
    size_t actual_der_len = max_der_len;
    if (!opssl_base64_decode(data_start, b64_len, der_buf, &actual_der_len)) {
        op_free(der_buf);
        return 0;
    }

    /* Copy label if requested */
    if (label_out && label_max > 0) {
        size_t label_len = strlen(label);
        if (label_len < label_max) {
            memcpy(label_out, label, label_len + 1);
        } else {
            OPSSL_ERR(OPSSL_ERR_X509, 59);
            op_free(der_buf);
            return 0;
        }
    }

    *der_out = der_buf;
    *der_len = actual_der_len;
    return 1;
}

/*
 * Decode multiple PEM blocks (certificate chain).
 */
int
opssl_pem_decode_multi(const char *pem, size_t pem_len,
                       uint8_t **ders, size_t *der_lens, size_t *count, size_t max_count)
{
    const char *p = pem;
    const char *pem_end = pem + pem_len;
    size_t found = 0;

    if (!pem || !ders || !der_lens || !count || max_count == 0) {
        OPSSL_ERR(OPSSL_ERR_INTERNAL, 0);
        return 0;
    }

    while (p < pem_end && found < max_count) {
        char label[64];

        /* Find next BEGIN marker */
        const char *data_start = find_pem_begin(p, pem_end, label, sizeof(label));
        if (!data_start) {
            break; /* No more PEM blocks */
        }

        /* Find matching END marker */
        const char *data_end = find_pem_end(data_start, pem_end, label);
        if (!data_end) {
            /* Cleanup already allocated blocks */
            for (size_t i = 0; i < found; i++) {
                op_free(ders[i]);
            }
            return 0;
        }

        /* Decode this block with overflow guard. */
        size_t b64_len = (size_t)(data_end - data_start);
        if (b64_len > (SIZE_MAX - 3) / 3) {
            for (size_t i = 0; i < found; i++) op_free(ders[i]);
            OPSSL_ERR(OPSSL_ERR_X509, 60);
            return 0;
        }
        size_t max_der_len = (b64_len * 3) / 4 + 3;

        uint8_t *der_buf = op_malloc(max_der_len);
        if (!der_buf) {
            /* Cleanup */
            for (size_t i = 0; i < found; i++) {
                op_free(ders[i]);
            }
            OPSSL_ERR(OPSSL_ERR_MEMORY, 0);
            return 0;
        }

        size_t actual_der_len = max_der_len;
        if (!opssl_base64_decode(data_start, b64_len, der_buf, &actual_der_len)) {
            op_free(der_buf);
            /* Cleanup */
            for (size_t i = 0; i < found; i++) {
                op_free(ders[i]);
            }
            return 0;
        }

        ders[found] = der_buf;
        der_lens[found] = actual_der_len;
        found++;

        /* Continue after this block */
        p = data_end;
    }

    *count = found;
    return found > 0 ? 1 : 0;
}

/*
 * Read PEM file from disk.
 */
int
opssl_pem_read_file(const char *path, uint8_t **der_out, size_t *der_len,
                    char *label_out, size_t label_max)
{
    FILE *fp;
    char *pem_data = NULL;
    size_t pem_size = 0;
    size_t pem_capacity = 4096;
    int result = 0;

    if (!path || !der_out || !der_len) {
        OPSSL_ERR(OPSSL_ERR_INTERNAL, 0);
        return 0;
    }

    fp = fopen(path, "r");
    if (!fp) {
        OPSSL_ERR(OPSSL_ERR_IO, 1);
        return 0;
    }

    /* Allocate initial buffer */
    pem_data = op_malloc(pem_capacity);
    if (!pem_data) {
        fclose(fp);
        OPSSL_ERR(OPSSL_ERR_MEMORY, 0);
        return 0;
    }

    /* Read file in chunks */
    size_t bytes_read;
    while ((bytes_read = fread(pem_data + pem_size, 1, pem_capacity - pem_size - 1, fp)) > 0) {
        pem_size += bytes_read;

        /* Expand buffer if needed */
        if (pem_size + 1 >= pem_capacity) {
            pem_capacity *= 2;
            char *new_data = op_realloc(pem_data, pem_capacity);
            if (!new_data) {
                op_free(pem_data);
                fclose(fp);
                OPSSL_ERR(OPSSL_ERR_MEMORY, 0);
                return 0;
            }
            pem_data = new_data;
        }
    }

    fclose(fp);

    if (pem_size == 0) {
        op_free(pem_data);
        OPSSL_ERR(OPSSL_ERR_IO, 2);
        return 0;
    }

    /* Null terminate */
    pem_data[pem_size] = '\0';

    /* Decode PEM */
    result = opssl_pem_decode(pem_data, pem_size, der_out, der_len, label_out, label_max);

    op_free(pem_data);
    return result;
}
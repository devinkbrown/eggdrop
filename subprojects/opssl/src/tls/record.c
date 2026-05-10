/*
 * opssl/tls/record.c — TLS record layer.
 *
 * Handles framing, encryption/decryption of TLS records.
 * Supports both TLS 1.2 and TLS 1.3 record formats.
 *
 * TLS 1.2: type(1) + version(2) + length(2) + [payload]
 * TLS 1.3: type=0x17(1) + version=0x0303(2) + length(2) + [encrypted payload + type(1)]
 *
 * Copyright (C) 2026 ophion development team
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <opssl/platform.h>
#include <opssl/crypto.h>
#include <opssl/cbs.h>
#include <opssl/err.h>
#include <string.h>

/* Record content types */
#define TLS_CT_CHANGE_CIPHER_SPEC 20
#define TLS_CT_ALERT              21
#define TLS_CT_HANDSHAKE          22
#define TLS_CT_APPLICATION_DATA   23

/* Record header size */
#define TLS_RECORD_HEADER_LEN     5

/* Max plaintext per record (RFC 8446 §5.1) */
#define TLS_MAX_PLAINTEXT         16384
#define TLS_MAX_CIPHERTEXT        (TLS_MAX_PLAINTEXT + 256)

/* Internal record state */
typedef struct {
    opssl_aead_ctx_t *cipher;
    uint8_t          iv[12];
    uint64_t         seq;
    bool             is_tls13;
} record_cipher_state_t;

/*
 * Construct per-record nonce.
 *
 * TLS 1.2: nonce = explicit_iv(4) || implicit_iv(8)
 * TLS 1.3: nonce = iv XOR seq (RFC 8446 §5.3)
 */
static void
record_make_nonce(uint8_t nonce[12], const record_cipher_state_t *st)
{
    memcpy(nonce, st->iv, 12);

    if (st->is_tls13) {
        /* XOR the sequence number into the rightmost bytes */
        uint8_t seq_bytes[8];
        opssl_put_be64(seq_bytes, st->seq);
        for (int i = 0; i < 8; i++)
            nonce[4 + i] ^= seq_bytes[i];
    }
}

/*
 * Construct additional authenticated data (AAD).
 *
 * TLS 1.2: seq(8) + type(1) + version(2) + length(2)
 * TLS 1.3: type(1) + version(2) + length(2)  (record header as-is)
 */
static size_t
record_make_aad(uint8_t *aad, const record_cipher_state_t *st,
                uint8_t content_type, uint16_t version, uint16_t length)
{
    size_t offset = 0;

    if (!st->is_tls13) {
        opssl_put_be64(aad, st->seq);
        offset = 8;
    }

    aad[offset++] = content_type;
    opssl_put_be16(aad + offset, version);
    offset += 2;
    opssl_put_be16(aad + offset, length);
    offset += 2;

    return offset;
}

/*
 * Encrypt a TLS record in place.
 *
 * Input: plaintext in buf[TLS_RECORD_HEADER_LEN .. TLS_RECORD_HEADER_LEN + plain_len]
 * Output: ciphertext replaces plaintext, tag appended.
 * Returns total record length (header + ciphertext + tag), or -1 on error.
 */
int
opssl_record_encrypt(record_cipher_state_t *st,
                     uint8_t *buf, size_t buf_cap,
                     uint8_t content_type, size_t plain_len)
{
    if (!st->cipher)
        return -1;

    size_t tag_len = 16;
    size_t cipher_len = plain_len + tag_len;

    /* TLS 1.3: append real content type inside encryption boundary */
    if (st->is_tls13)
        cipher_len += 1;

    if (TLS_RECORD_HEADER_LEN + cipher_len > buf_cap)
        return -1;

    /* Build nonce */
    uint8_t nonce[12];
    record_make_nonce(nonce, st);

    /* Write record header */
    uint8_t ct_wire = st->is_tls13 ? TLS_CT_APPLICATION_DATA : content_type;
    uint16_t ver_wire = 0x0303; /* Always TLS 1.2 on wire (even for 1.3) */

    buf[0] = ct_wire;
    opssl_put_be16(buf + 1, ver_wire);
    opssl_put_be16(buf + 3, (uint16_t)cipher_len);

    /* Plaintext starts after header */
    uint8_t *payload = buf + TLS_RECORD_HEADER_LEN;

    /* TLS 1.3: append real content type to plaintext before encryption */
    if (st->is_tls13)
        payload[plain_len] = content_type;

    /* AAD */
    uint8_t aad[13];
    size_t aad_len = record_make_aad(aad, st, ct_wire, ver_wire,
                                     (uint16_t)cipher_len);

    /* Encrypt in place */
    size_t out_len = 0;
    size_t encrypt_input_len = st->is_tls13 ? plain_len + 1 : plain_len;

    if (!opssl_aead_seal(st->cipher,
                         payload, &out_len, cipher_len,
                         nonce, 12,
                         payload, encrypt_input_len,
                         aad, aad_len)) {
        opssl_memzero(nonce, sizeof(nonce));
        return -1;
    }

    st->seq++;
    opssl_memzero(nonce, sizeof(nonce));

    return (int)(TLS_RECORD_HEADER_LEN + cipher_len);
}

/*
 * Decrypt a TLS record in place.
 *
 * Input: complete record in buf[0 .. record_len]
 * Output: plaintext replaces ciphertext (after header).
 * Returns plaintext length, or -1 on MAC failure / error.
 * On TLS 1.3, *real_content_type is set from the decrypted inner type.
 */
int
opssl_record_decrypt(record_cipher_state_t *st,
                     uint8_t *buf, size_t record_len,
                     uint8_t *real_content_type)
{
    if (!st->cipher || record_len < TLS_RECORD_HEADER_LEN)
        return -1;

    uint8_t ct_wire = buf[0];
    uint16_t ver_wire = opssl_be16(buf + 1);
    uint16_t cipher_len = opssl_be16(buf + 3);

    if ((size_t)(TLS_RECORD_HEADER_LEN + cipher_len) > record_len)
        return -1;

    if (cipher_len < 16) /* at minimum: tag */
        return -1;

    /* Nonce */
    uint8_t nonce[12];
    record_make_nonce(nonce, st);

    /* AAD */
    uint8_t aad[13];
    size_t aad_len = record_make_aad(aad, st, ct_wire, ver_wire, cipher_len);

    /* Decrypt in place */
    uint8_t *payload = buf + TLS_RECORD_HEADER_LEN;
    size_t out_len = 0;

    if (!opssl_aead_open(st->cipher,
                         payload, &out_len, cipher_len,
                         nonce, 12,
                         payload, cipher_len,
                         aad, aad_len)) {
        opssl_memzero(nonce, sizeof(nonce));
        OPSSL_ERR(OPSSL_ERR_TLS, OPSSL_TLS_ERR_BAD_RECORD_MAC);
        return -1;
    }

    st->seq++;
    opssl_memzero(nonce, sizeof(nonce));

    /* TLS 1.3: strip content type from end, skip padding zeros */
    if (st->is_tls13) {
        while (out_len > 0 && payload[out_len - 1] == 0)
            out_len--;

        if (out_len == 0) {
            OPSSL_ERR(OPSSL_ERR_TLS, OPSSL_TLS_ERR_UNEXPECTED_MSG);
            return -1;
        }

        *real_content_type = payload[out_len - 1];
        out_len--;
    } else {
        *real_content_type = ct_wire;
    }

    return (int)out_len;
}

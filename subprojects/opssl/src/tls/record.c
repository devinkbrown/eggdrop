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
 * TLS 1.2 AEAD (RFC 5116 / RFC 5246 §6.3):
 *   nonce = implicit_iv(4) || explicit_seq(8)
 *   iv[0..3] is the 4-byte implicit part from the key block.
 *   Bytes 4-11 are the explicit nonce = sequence number (BE64) written to wire.
 *
 * TLS 1.3 (RFC 8446 §5.3):
 *   nonce = iv[0..11] XOR (0x00000000 || seq_be64)
 *
 * Note: for TLS 1.2, the decrypt path overrides nonce[4..11] with the
 * explicit nonce read from the wire rather than using st->seq directly.
 */
static void
record_make_nonce(uint8_t nonce[12], const record_cipher_state_t *st)
{
    if (st->is_tls13) {
        /* TLS 1.3: XOR full 12-byte IV with right-padded sequence number */
        memcpy(nonce, st->iv, 12);
        uint8_t seq_bytes[8];
        opssl_put_be64(seq_bytes, st->seq);
        for (int i = 0; i < 8; i++)
            nonce[4 + i] ^= seq_bytes[i];
    } else {
        /*
         * TLS 1.2: implicit(4) || explicit_seq(8).
         * Only iv[0..3] is the implicit part; iv[4..11] is unused.
         * The explicit seq is the sequence number; it is also written to the
         * wire before the ciphertext.
         */
        memcpy(nonce, st->iv, 4);
        opssl_put_be64(nonce + 4, st->seq);
    }
}

/*
 * Construct additional authenticated data (AAD).
 *
 * TLS 1.2: seq(8) + type(1) + version(2) + length(2)  — length = plaintext length
 * TLS 1.3: type(1) + version(2) + length(2)            — length = ciphertext length
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
 * TLS 1.3:
 *   Input plaintext at buf[TLS_RECORD_HEADER_LEN .. + plain_len].
 *   The inner content type is appended, then the whole thing is encrypted.
 *   Record wire payload = ciphertext(plain_len + 1) + tag(16).
 *   AAD = 5-byte record header (length = ciphertext payload length).
 *
 * TLS 1.2:
 *   Input plaintext at buf[TLS_RECORD_HEADER_LEN + 8 .. + 8 + plain_len].
 *   Caller must provide 8 bytes of headroom after the record header.
 *   Wire payload = explicit_nonce(8) | ciphertext(plain_len) | tag(16).
 *   AAD length field = plaintext length (RFC 5246 §6.2.3.3).
 *
 * Returns total record length (header + wire payload) on success, -1 on error.
 */
int
opssl_record_encrypt(record_cipher_state_t *st,
                     uint8_t *buf, size_t buf_cap,
                     uint8_t content_type, size_t plain_len)
{
    if (!st->cipher)
        return -1;

    if (st->seq == UINT64_MAX) {
        OPSSL_ERR(OPSSL_ERR_TLS, OPSSL_TLS_ERR_RECORD_OVERFLOW);
        return -1;
    }

    uint8_t ct_wire = st->is_tls13 ? TLS_CT_APPLICATION_DATA : content_type;
    uint16_t ver_wire = 0x0303; /* Always TLS 1.2 on wire */
    uint8_t nonce[12];
    uint8_t aad[13];
    size_t aad_len;
    size_t out_len = 0;
    size_t total_record_len;

    record_make_nonce(nonce, st);

    if (st->is_tls13) {
        /* cipher_len = plain_len + inner_ct_byte(1) + tag(16) */
        size_t tls13_cipher_len = plain_len + 1 + 16;
        if (TLS_RECORD_HEADER_LEN + tls13_cipher_len > buf_cap) {
            opssl_memzero(nonce, sizeof(nonce));
            return -1;
        }

        buf[0] = ct_wire;
        opssl_put_be16(buf + 1, ver_wire);
        opssl_put_be16(buf + 3, (uint16_t)tls13_cipher_len);

        uint8_t *payload = buf + TLS_RECORD_HEADER_LEN;
        payload[plain_len] = content_type; /* inner content type */

        aad_len = record_make_aad(aad, st, ct_wire, ver_wire,
                                  (uint16_t)tls13_cipher_len);

        if (!opssl_aead_seal(st->cipher,
                             payload, &out_len, tls13_cipher_len,
                             nonce, 12,
                             payload, plain_len + 1,
                             aad, aad_len)) {
            opssl_memzero(nonce, sizeof(nonce));
            return -1;
        }

        total_record_len = TLS_RECORD_HEADER_LEN + tls13_cipher_len;
    } else {
        /*
         * TLS 1.2: wire payload = explicit_nonce(8) | ciphertext | tag(16).
         * Caller places plaintext at buf[TLS_RECORD_HEADER_LEN + 8].
         */
        size_t tls12_payload_len = 8 + plain_len + 16;
        if (TLS_RECORD_HEADER_LEN + tls12_payload_len > buf_cap) {
            opssl_memzero(nonce, sizeof(nonce));
            return -1;
        }

        buf[0] = ct_wire;
        opssl_put_be16(buf + 1, ver_wire);
        opssl_put_be16(buf + 3, (uint16_t)tls12_payload_len);

        /* Write explicit nonce = sequence number (BE64) */
        uint8_t *explicit_nonce_ptr = buf + TLS_RECORD_HEADER_LEN;
        opssl_put_be64(explicit_nonce_ptr, st->seq);

        /* Plaintext is expected at explicit_nonce_ptr + 8 */
        uint8_t *ciphertext_out = explicit_nonce_ptr + 8;

        /* AAD: seq(8) + type(1) + version(2) + plaintext_length(2) */
        aad_len = record_make_aad(aad, st, ct_wire, ver_wire, (uint16_t)plain_len);

        if (!opssl_aead_seal(st->cipher,
                             ciphertext_out, &out_len, plain_len + 16,
                             nonce, 12,
                             ciphertext_out, plain_len,
                             aad, aad_len)) {
            opssl_memzero(nonce, sizeof(nonce));
            return -1;
        }

        total_record_len = TLS_RECORD_HEADER_LEN + tls12_payload_len;
    }

    st->seq++;
    opssl_memzero(nonce, sizeof(nonce));

    return (int)total_record_len;
}

/*
 * Decrypt a TLS record in place.
 *
 * Input: complete record in buf[0 .. record_len].
 *
 * TLS 1.3:
 *   Wire payload = ciphertext | tag(16).
 *   Nonce = IV XOR seq.  AAD = 5-byte record header.
 *   Inner content type stripped from tail after decryption.
 *
 * TLS 1.2:
 *   Wire payload = explicit_nonce(8) | ciphertext | tag(16).
 *   Nonce: iv[0..3] (implicit) || explicit_nonce_from_record[0..7].
 *   AAD length field = plaintext length (= payload_len - 8 - 16).
 *   Plaintext placed at buf[TLS_RECORD_HEADER_LEN] after decryption.
 *
 * Returns plaintext length on success, -1 on MAC failure / error.
 * *real_content_type is always set on success.
 */
int
opssl_record_decrypt(record_cipher_state_t *st,
                     uint8_t *buf, size_t record_len,
                     uint8_t *real_content_type)
{
    if (!st->cipher || record_len < TLS_RECORD_HEADER_LEN)
        return -1;

    if (st->seq == UINT64_MAX) {
        OPSSL_ERR(OPSSL_ERR_TLS, OPSSL_TLS_ERR_RECORD_OVERFLOW);
        return -1;
    }

    uint8_t ct_wire = buf[0];
    uint16_t ver_wire = opssl_be16(buf + 1);
    uint16_t payload_len = opssl_be16(buf + 3);

    if ((size_t)(TLS_RECORD_HEADER_LEN + payload_len) > record_len)
        return -1;

    uint8_t nonce[12];
    uint8_t aad[13];
    size_t aad_len;
    size_t out_len = 0;

    if (st->is_tls13) {
        if (payload_len < 16) /* need at least a tag */
            return -1;

        record_make_nonce(nonce, st);
        aad_len = record_make_aad(aad, st, ct_wire, ver_wire, payload_len);

        uint8_t *ciphertext = buf + TLS_RECORD_HEADER_LEN;

        if (!opssl_aead_open(st->cipher,
                             ciphertext, &out_len, payload_len,
                             nonce, 12,
                             ciphertext, payload_len,
                             aad, aad_len)) {
            opssl_memzero(nonce, sizeof(nonce));
            OPSSL_ERR(OPSSL_ERR_TLS, OPSSL_TLS_ERR_BAD_RECORD_MAC);
            return -1;
        }

        st->seq++;
        opssl_memzero(nonce, sizeof(nonce));

        /* Strip inner content type, scanning back over padding zeros */
        while (out_len > 0 && ciphertext[out_len - 1] == 0)
            out_len--;

        if (out_len == 0) {
            OPSSL_ERR(OPSSL_ERR_TLS, OPSSL_TLS_ERR_UNEXPECTED_MSG);
            return -1;
        }

        *real_content_type = ciphertext[out_len - 1];
        return (int)(out_len - 1);
    } else {
        /*
         * TLS 1.2: payload = explicit_nonce(8) | ciphertext | tag(16).
         * Minimum: 8 (explicit nonce) + 16 (tag) = 24 bytes.
         */
        if (payload_len < 24)
            return -1;

        uint8_t *explicit_nonce_ptr = buf + TLS_RECORD_HEADER_LEN;
        uint8_t *ciphertext = explicit_nonce_ptr + 8;
        size_t ciphertext_len = (size_t)payload_len - 8; /* includes tag */

        if (ciphertext_len < 16)
            return -1;

        size_t plain_len = ciphertext_len - 16;

        /*
         * Build nonce: iv[0..3] (implicit from key block) ||
         *              explicit_nonce from wire (8 bytes).
         * Do NOT use record_make_nonce() here — it would use st->seq
         * for bytes 4-11, but we must use the wire's explicit nonce.
         */
        memcpy(nonce, st->iv, 4);
        memcpy(nonce + 4, explicit_nonce_ptr, 8);

        /* AAD length field = plaintext length (RFC 5246 §6.2.3.3) */
        aad_len = record_make_aad(aad, st, ct_wire, ver_wire, (uint16_t)plain_len);

        /*
         * Decrypt into buf just after the record header.
         * The output overlaps with the ciphertext region but plaintext is
         * strictly shorter (no explicit nonce, no tag), so the write is safe.
         */
        if (!opssl_aead_open(st->cipher,
                             buf + TLS_RECORD_HEADER_LEN, &out_len, plain_len,
                             nonce, 12,
                             ciphertext, ciphertext_len,
                             aad, aad_len)) {
            opssl_memzero(nonce, sizeof(nonce));
            OPSSL_ERR(OPSSL_ERR_TLS, OPSSL_TLS_ERR_BAD_RECORD_MAC);
            return -1;
        }

        st->seq++;
        opssl_memzero(nonce, sizeof(nonce));

        *real_content_type = ct_wire;
        return (int)out_len;
    }
}

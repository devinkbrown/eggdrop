/*
 * Copyright (c) 2024 OpSSL Project
 * Licensed under the MIT License
 */

#include <opssl/platform.h>
#include <opssl/crypto.h>
#include <opssl/types.h>
#include <opssl/cbs.h>
#include <opssl/err.h>
#include <string.h>
#include <stdlib.h>

/*
 * TLS session state export/import for live migration
 * Enables transferring active TLS connections between processes
 */

#define OPSSL_EXPORT_VERSION 1
#define OPSSL_EXPORT_MAGIC 0x4F505353  /* "OPSS" */

/* Local compat: map non-existent error codes to available ones */
#define OPSSL_ERR_NULL_POINTER         OPSSL_ERR_INVALID_ARGUMENT
#define OPSSL_ERR_CONN_STATE_INVALID   OPSSL_ERR_INVALID_ARGUMENT
#define OPSSL_ERR_INVALID_FORMAT       OPSSL_ERR_INVALID_ARGUMENT
#define OPSSL_ERR_UNSUPPORTED_VERSION  OPSSL_ERR_VERSION_MISMATCH
#define OPSSL_ERR_MEMORY_ALLOCATION    OPSSL_ERR_ALLOC_FAILED
#define OPSSL_ERR_CRYPTO_ERROR         OPSSL_ERR_INVALID_ARGUMENT

/* Wrapper for opssl_set_error that adds NULL message arg */
#define set_error(code) opssl_set_error((code), NULL)

/* Export format:
 * magic(4) || version(2) || cipher(2) || flags(4) ||
 * read_key_len(2) || read_key(var) || read_iv_len(1) || read_iv(var) || read_seq(8) ||
 * write_key_len(2) || write_key(var) || write_iv_len(1) || write_iv(var) || write_seq(8)
 */

/* External accessor functions from handshake.c */
extern int opssl_conn_get_cipher(opssl_conn_t *conn);
extern int opssl_conn_get_write_seq(opssl_conn_t *conn, uint64_t *seq);
extern int opssl_conn_get_read_seq(opssl_conn_t *conn, uint64_t *seq);
extern int opssl_conn_get_write_key(opssl_conn_t *conn, uint8_t *key, size_t *len);
extern int opssl_conn_get_read_key(opssl_conn_t *conn, uint8_t *key, size_t *len);
extern int opssl_conn_get_write_iv(opssl_conn_t *conn, uint8_t *iv, size_t *len);
extern int opssl_conn_get_read_iv(opssl_conn_t *conn, uint8_t *iv, size_t *len);
extern int opssl_conn_set_cipher(opssl_conn_t *conn, int cipher);
extern int opssl_conn_set_write_seq(opssl_conn_t *conn, uint64_t seq);
extern int opssl_conn_set_read_seq(opssl_conn_t *conn, uint64_t seq);
extern int opssl_conn_set_write_key(opssl_conn_t *conn, const uint8_t *key, size_t len);
extern int opssl_conn_set_read_key(opssl_conn_t *conn, const uint8_t *key, size_t len);
extern int opssl_conn_set_write_iv(opssl_conn_t *conn, const uint8_t *iv, size_t len);
extern int opssl_conn_set_read_iv(opssl_conn_t *conn, const uint8_t *iv, size_t len);
extern uint32_t opssl_conn_get_flags(opssl_conn_t *conn);
extern void opssl_conn_set_flags(opssl_conn_t *conn, uint32_t flags);

static void write_be32(uint8_t *buf, uint32_t val)
{
    buf[0] = (val >> 24) & 0xFF;
    buf[1] = (val >> 16) & 0xFF;
    buf[2] = (val >> 8) & 0xFF;
    buf[3] = val & 0xFF;
}

static void write_be16(uint8_t *buf, uint16_t val)
{
    buf[0] = (val >> 8) & 0xFF;
    buf[1] = val & 0xFF;
}

static void write_be64(uint8_t *buf, uint64_t val)
{
    write_be32(buf, (uint32_t)(val >> 32));
    write_be32(buf + 4, (uint32_t)val);
}

static uint32_t read_be32(const uint8_t *buf)
{
    return ((uint32_t)buf[0] << 24) |
           ((uint32_t)buf[1] << 16) |
           ((uint32_t)buf[2] << 8) |
           ((uint32_t)buf[3]);
}

static uint16_t read_be16(const uint8_t *buf)
{
    return ((uint16_t)buf[0] << 8) | ((uint16_t)buf[1]);
}

static uint64_t read_be64(const uint8_t *buf)
{
    uint64_t high = read_be32(buf);
    uint64_t low = read_be32(buf + 4);
    return (high << 32) | low;
}

int opssl_session_export(opssl_conn_t *conn, uint8_t *buf, size_t *buf_len, size_t max_len)
{
    if (!conn || !buf_len) {
        set_error(OPSSL_ERR_NULL_POINTER);
        return -1;
    }

    /* Extract connection state */
    int cipher = opssl_conn_get_cipher(conn);
    if (cipher < 0) {
        set_error(OPSSL_ERR_CONN_STATE_INVALID);
        return -1;
    }

    uint64_t read_seq, write_seq;
    if (opssl_conn_get_read_seq(conn, &read_seq) < 0 ||
        opssl_conn_get_write_seq(conn, &write_seq) < 0) {
        set_error(OPSSL_ERR_CONN_STATE_INVALID);
        return -1;
    }

    uint8_t read_key[32], write_key[32];
    uint8_t read_iv[16], write_iv[16];
    size_t read_key_len = sizeof(read_key);
    size_t write_key_len = sizeof(write_key);
    size_t read_iv_len = sizeof(read_iv);
    size_t write_iv_len = sizeof(write_iv);

    if (opssl_conn_get_read_key(conn, read_key, &read_key_len) < 0 ||
        opssl_conn_get_write_key(conn, write_key, &write_key_len) < 0 ||
        opssl_conn_get_read_iv(conn, read_iv, &read_iv_len) < 0 ||
        opssl_conn_get_write_iv(conn, write_iv, &write_iv_len) < 0) {
        set_error(OPSSL_ERR_CONN_STATE_INVALID);
        return -1;
    }

    uint32_t flags = opssl_conn_get_flags(conn);

    /* Calculate required buffer size */
    size_t required_len = 4 + 2 + 2 + 4 +  /* magic, version, cipher, flags */
                         2 + read_key_len + 1 + read_iv_len + 8 +   /* read state */
                         2 + write_key_len + 1 + write_iv_len + 8;  /* write state */

    if (!buf) {
        *buf_len = required_len;
        return 0;
    }

    if (*buf_len < required_len || max_len < required_len) {
        *buf_len = required_len;
        set_error(OPSSL_ERR_BUFFER_TOO_SMALL);
        return -1;
    }

    /* Write export data */
    uint8_t *ptr = buf;

    /* Header */
    write_be32(ptr, OPSSL_EXPORT_MAGIC);
    ptr += 4;
    write_be16(ptr, OPSSL_EXPORT_VERSION);
    ptr += 2;
    write_be16(ptr, (uint16_t)cipher);
    ptr += 2;
    write_be32(ptr, flags);
    ptr += 4;

    /* Read state */
    write_be16(ptr, (uint16_t)read_key_len);
    ptr += 2;
    memcpy(ptr, read_key, read_key_len);
    ptr += read_key_len;
    *ptr++ = (uint8_t)read_iv_len;
    memcpy(ptr, read_iv, read_iv_len);
    ptr += read_iv_len;
    write_be64(ptr, read_seq);
    ptr += 8;

    /* Write state */
    write_be16(ptr, (uint16_t)write_key_len);
    ptr += 2;
    memcpy(ptr, write_key, write_key_len);
    ptr += write_key_len;
    *ptr++ = (uint8_t)write_iv_len;
    memcpy(ptr, write_iv, write_iv_len);
    ptr += write_iv_len;
    write_be64(ptr, write_seq);
    ptr += 8;

    *buf_len = ptr - buf;

    /* Clear sensitive data */
    opssl_memzero(read_key, sizeof(read_key));
    opssl_memzero(write_key, sizeof(write_key));
    opssl_memzero(read_iv, sizeof(read_iv));
    opssl_memzero(write_iv, sizeof(write_iv));

    return 0;
}

int opssl_session_import(opssl_conn_t *conn, const uint8_t *buf, size_t buf_len)
{
    if (!conn || !buf || buf_len < 12) {
        set_error(OPSSL_ERR_NULL_POINTER);
        return -1;
    }

    const uint8_t *ptr = buf;
    const uint8_t *end = buf + buf_len;

    /* Verify magic and version */
    if (ptr + 4 > end || read_be32(ptr) != OPSSL_EXPORT_MAGIC) {
        set_error(OPSSL_ERR_INVALID_FORMAT);
        return -1;
    }
    ptr += 4;

    if (ptr + 2 > end || read_be16(ptr) != OPSSL_EXPORT_VERSION) {
        set_error(OPSSL_ERR_UNSUPPORTED_VERSION);
        return -1;
    }
    ptr += 2;

    /* Read header */
    if (ptr + 6 > end) {
        set_error(OPSSL_ERR_INVALID_FORMAT);
        return -1;
    }
    uint16_t cipher = read_be16(ptr);
    ptr += 2;
    uint32_t flags = read_be32(ptr);
    ptr += 4;

    /* Read read state */
    if (ptr + 2 > end) {
        set_error(OPSSL_ERR_INVALID_FORMAT);
        return -1;
    }
    uint16_t read_key_len = read_be16(ptr);
    ptr += 2;

    if (read_key_len == 0 || read_key_len > 32 || ptr + read_key_len > end) {
        set_error(OPSSL_ERR_INVALID_FORMAT);
        return -1;
    }
    uint8_t read_key[32];
    memcpy(read_key, ptr, read_key_len);
    ptr += read_key_len;

    if (ptr + 1 > end) {
        set_error(OPSSL_ERR_INVALID_FORMAT);
        return -1;
    }
    uint8_t read_iv_len = *ptr++;

    if (read_iv_len > 16 || ptr + read_iv_len + 8 > end) {
        set_error(OPSSL_ERR_INVALID_FORMAT);
        return -1;
    }
    uint8_t read_iv[16];
    memcpy(read_iv, ptr, read_iv_len);
    ptr += read_iv_len;

    uint64_t read_seq = read_be64(ptr);
    ptr += 8;

    /* Read write state */
    if (ptr + 2 > end) {
        set_error(OPSSL_ERR_INVALID_FORMAT);
        return -1;
    }
    uint16_t write_key_len = read_be16(ptr);
    ptr += 2;

    if (write_key_len == 0 || write_key_len > 32 || ptr + write_key_len > end) {
        set_error(OPSSL_ERR_INVALID_FORMAT);
        return -1;
    }
    uint8_t write_key[32];
    memcpy(write_key, ptr, write_key_len);
    ptr += write_key_len;

    if (ptr + 1 > end) {
        set_error(OPSSL_ERR_INVALID_FORMAT);
        return -1;
    }
    uint8_t write_iv_len = *ptr++;

    if (write_iv_len > 16 || ptr + write_iv_len + 8 > end) {
        set_error(OPSSL_ERR_INVALID_FORMAT);
        return -1;
    }
    uint8_t write_iv[16];
    memcpy(write_iv, ptr, write_iv_len);
    ptr += write_iv_len;

    uint64_t write_seq = read_be64(ptr);
    ptr += 8;

    /* Set connection state */
    if (opssl_conn_set_cipher(conn, cipher) < 0 ||
        opssl_conn_set_read_key(conn, read_key, read_key_len) < 0 ||
        opssl_conn_set_write_key(conn, write_key, write_key_len) < 0 ||
        opssl_conn_set_read_iv(conn, read_iv, read_iv_len) < 0 ||
        opssl_conn_set_write_iv(conn, write_iv, write_iv_len) < 0 ||
        opssl_conn_set_read_seq(conn, read_seq) < 0 ||
        opssl_conn_set_write_seq(conn, write_seq) < 0) {
        /* Clear sensitive data before returning error */
        opssl_memzero(read_key, sizeof(read_key));
        opssl_memzero(write_key, sizeof(write_key));
        opssl_memzero(read_iv, sizeof(read_iv));
        opssl_memzero(write_iv, sizeof(write_iv));
        set_error(OPSSL_ERR_CONN_STATE_INVALID);
        return -1;
    }

    opssl_conn_set_flags(conn, flags);

    /* Clear sensitive data */
    opssl_memzero(read_key, sizeof(read_key));
    opssl_memzero(write_key, sizeof(write_key));
    opssl_memzero(read_iv, sizeof(read_iv));
    opssl_memzero(write_iv, sizeof(write_iv));

    return 0;
}

int opssl_session_export_encrypted(opssl_conn_t *conn,
                                   const uint8_t *wrap_key, size_t key_len,
                                   uint8_t *buf, size_t *buf_len, size_t max_len)
{
    if (!conn || !wrap_key || !buf_len || key_len != 32) {
        set_error(OPSSL_ERR_NULL_POINTER);
        return -1;
    }

    /* First, get the plaintext export size */
    size_t plaintext_len = 0;
    if (opssl_session_export(conn, NULL, &plaintext_len, 0) < 0) {
        return -1;
    }

    /* Allocate buffer for plaintext */
    uint8_t *plaintext = malloc(plaintext_len);
    if (!plaintext) {
        set_error(OPSSL_ERR_MEMORY_ALLOCATION);
        return -1;
    }

    /* Export plaintext session */
    if (opssl_session_export(conn, plaintext, &plaintext_len, plaintext_len) < 0) {
        free(plaintext);
        return -1;
    }

    /* Generate random nonce */
    uint8_t nonce[12];
    if (opssl_random_bytes(nonce, sizeof(nonce)) < 0) {
        opssl_memzero(plaintext, plaintext_len);
        free(plaintext);
        set_error(OPSSL_ERR_CRYPTO_ERROR);
        return -1;
    }

    /* Calculate required buffer size: nonce(12) + ciphertext + tag(16) */
    size_t required_len = 12 + plaintext_len + 16;

    if (*buf_len < required_len) {
        *buf_len = required_len;
        opssl_memzero(plaintext, plaintext_len);
        free(plaintext);
        set_error(OPSSL_ERR_BUFFER_TOO_SMALL);
        return -1;
    }

    if (max_len < required_len) {
        opssl_memzero(plaintext, plaintext_len);
        free(plaintext);
        set_error(OPSSL_ERR_BUFFER_TOO_SMALL);
        return -1;
    }

    if (!buf) {
        *buf_len = required_len;
        opssl_memzero(plaintext, plaintext_len);
        free(plaintext);
        return 0;
    }

    /* Copy nonce to output */
    memcpy(buf, nonce, 12);

    /* Encrypt with AES-256-GCM using AEAD context */
    opssl_aead_ctx_t *aead_ctx = opssl_aead_new(OPSSL_AEAD_AES_256_GCM);
    if (!aead_ctx || !opssl_aead_set_key(aead_ctx, wrap_key, key_len)) {
        opssl_aead_free(aead_ctx);
        opssl_memzero(plaintext, plaintext_len);
        free(plaintext);
        set_error(OPSSL_ERR_CRYPTO_ERROR);
        return -1;
    }

    size_t out_len = 0;
    size_t max_out = plaintext_len + 16;
    if (!opssl_aead_seal(aead_ctx, buf + 12, &out_len, max_out,
                         nonce, 12,
                         plaintext, plaintext_len,
                         NULL, 0)) {
        opssl_aead_free(aead_ctx);
        opssl_memzero(plaintext, plaintext_len);
        free(plaintext);
        set_error(OPSSL_ERR_CRYPTO_ERROR);
        return -1;
    }
    opssl_aead_free(aead_ctx);

    *buf_len = 12 + out_len;

    /* Clear sensitive data */
    opssl_memzero(plaintext, plaintext_len);
    free(plaintext);

    return 0;
}

int opssl_session_import_encrypted(opssl_conn_t *conn,
                                   const uint8_t *wrap_key, size_t key_len,
                                   const uint8_t *buf, size_t buf_len)
{
    if (!conn || !wrap_key || !buf || key_len != 32 || buf_len < 29) {
        set_error(OPSSL_ERR_NULL_POINTER);
        return -1;
    }

    /* Extract nonce */
    const uint8_t *nonce = buf;

    /* Extract ciphertext + tag (aead_open expects tag appended) */
    size_t ciphertext_len = buf_len - 12;
    const uint8_t *ciphertext = buf + 12;
    /* Allocate buffer for plaintext (ct includes tag, plaintext is smaller) */
    uint8_t *plaintext = malloc(ciphertext_len);
    if (!plaintext) {
        set_error(OPSSL_ERR_MEMORY_ALLOCATION);
        return -1;
    }

    /* Decrypt with AES-256-GCM using AEAD context */
    opssl_aead_ctx_t *aead_ctx = opssl_aead_new(OPSSL_AEAD_AES_256_GCM);
    if (!aead_ctx || !opssl_aead_set_key(aead_ctx, wrap_key, key_len)) {
        opssl_aead_free(aead_ctx);
        free(plaintext);
        set_error(OPSSL_ERR_CRYPTO_ERROR);
        return -1;
    }
    size_t plaintext_len = 0;
    if (!opssl_aead_open(aead_ctx, plaintext, &plaintext_len, ciphertext_len,
                         nonce, 12,
                         ciphertext, ciphertext_len,
                         NULL, 0)) {
        opssl_aead_free(aead_ctx);
        free(plaintext);
        set_error(OPSSL_ERR_CRYPTO_ERROR);
        return -1;
    }
    opssl_aead_free(aead_ctx);

    /* Import decrypted session */
    int result = opssl_session_import(conn, plaintext, plaintext_len);

    /* Clear sensitive data */
    opssl_memzero(plaintext, plaintext_len);
    free(plaintext);

    return result;
}
/*
 * Copyright (c) 2024 OpSSL Project
 * Licensed under the MIT License
 */

#include <opssl/ktls.h>
#include <opssl/platform.h>
#include <opssl/err.h>
#include <string.h>

/* Local compat: map non-existent error codes to available ones */
#define OPSSL_ERR_KTLS_NOT_SUPPORTED  OPSSL_ERR_NOT_SUPPORTED
#define OPSSL_ERR_KTLS_NOT_ACTIVE     OPSSL_ERR_INVALID_ARGUMENT
#define OPSSL_ERR_KTLS_ULP_FAILED     OPSSL_ERR_INVALID_ARGUMENT
#define OPSSL_ERR_KTLS_TX_SETUP_FAILED OPSSL_ERR_INVALID_ARGUMENT
#define OPSSL_ERR_KTLS_RX_SETUP_FAILED OPSSL_ERR_INVALID_ARGUMENT
#define OPSSL_ERR_NULL_POINTER        OPSSL_ERR_INVALID_ARGUMENT
#define OPSSL_ERR_INVALID_FD          OPSSL_ERR_INVALID_ARGUMENT
#define OPSSL_ERR_CONN_STATE_INVALID  OPSSL_ERR_INVALID_ARGUMENT
#define OPSSL_ERR_MEMORY_ALLOCATION   OPSSL_ERR_ALLOC_FAILED
#define OPSSL_ERR_UNSUPPORTED_CIPHER  OPSSL_ERR_NOT_SUPPORTED
#define OPSSL_ERR_INVALID_KEY_LENGTH  OPSSL_ERR_INVALID_ARGUMENT
#define OPSSL_ERR_INVALID_IV_LENGTH   OPSSL_ERR_INVALID_ARGUMENT
#define OPSSL_ERR_WANT_READ           OPSSL_ERR_INVALID_ARGUMENT
#define OPSSL_ERR_WANT_WRITE          OPSSL_ERR_INVALID_ARGUMENT
#define OPSSL_ERR_IO_ERROR            OPSSL_ERR_INVALID_ARGUMENT

/* Local compat: cipher IDs used with kTLS */
#define OPSSL_CIPHER_AES_128_GCM  0xC02B
#define OPSSL_CIPHER_AES_256_GCM  0xC02C

/* Wrapper for opssl_set_error that adds NULL message arg */
#define ktls_set_error(code) opssl_set_error((code), NULL)

#ifdef OPSSL_HAVE_KTLS
#include <linux/tls.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <errno.h>
#endif

/* External accessor functions from handshake.c */
extern int opssl_conn_get_fd(opssl_conn_t *conn);
extern int opssl_conn_get_write_seq(opssl_conn_t *conn, uint64_t *seq);
extern int opssl_conn_get_read_seq(opssl_conn_t *conn, uint64_t *seq);
extern int opssl_conn_get_cipher(opssl_conn_t *conn);
extern int opssl_conn_get_write_key(opssl_conn_t *conn, uint8_t *key, size_t *len);
extern int opssl_conn_get_read_key(opssl_conn_t *conn, uint8_t *key, size_t *len);
extern int opssl_conn_get_write_iv(opssl_conn_t *conn, uint8_t *iv, size_t *len);
extern int opssl_conn_get_read_iv(opssl_conn_t *conn, uint8_t *iv, size_t *len);
extern void opssl_conn_set_ktls_active(opssl_conn_t *conn, bool active);
extern bool opssl_conn_is_ktls_active(opssl_conn_t *conn);

bool opssl_ktls_available(void)
{
#ifdef OPSSL_HAVE_KTLS
    /* Check if kernel TLS is available by attempting to set TCP_ULP */
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return false;
    }

    int rc = setsockopt(fd, SOL_TCP, TCP_ULP, "tls", 3);
    close(fd);
    return rc == 0;
#else
    return false;
#endif
}

#ifdef OPSSL_HAVE_KTLS
static int setup_ktls_crypto(int fd, int direction, int cipher,
                            const uint8_t *key, size_t key_len,
                            const uint8_t *iv, size_t iv_len,
                            uint64_t seq_num)
{
    if (cipher == OPSSL_CIPHER_AES_128_GCM) {
        struct tls12_crypto_info_aes_gcm_128 info = {0};
        info.info.version = TLS_1_2_VERSION;
        info.info.cipher_type = TLS_CIPHER_AES_GCM_128;

        if (key_len != TLS_CIPHER_AES_GCM_128_KEY_SIZE) {
            ktls_set_error(OPSSL_ERR_INVALID_KEY_LENGTH);
            return -1;
        }

        if (iv_len != TLS_CIPHER_AES_GCM_128_IV_SIZE) {
            ktls_set_error(OPSSL_ERR_INVALID_IV_LENGTH);
            return -1;
        }

        memcpy(info.key, key, TLS_CIPHER_AES_GCM_128_KEY_SIZE);
        memcpy(info.iv, iv, TLS_CIPHER_AES_GCM_128_IV_SIZE);
        memcpy(info.rec_seq, &seq_num, TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE);

        int tls_direction = (direction == OPSSL_KTLS_TX) ? TLS_TX : TLS_RX;
        return setsockopt(fd, SOL_TLS, tls_direction, &info, sizeof(info));
    }
    else if (cipher == OPSSL_CIPHER_AES_256_GCM) {
        struct tls12_crypto_info_aes_gcm_256 info = {0};
        info.info.version = TLS_1_2_VERSION;
        info.info.cipher_type = TLS_CIPHER_AES_GCM_256;

        if (key_len != TLS_CIPHER_AES_GCM_256_KEY_SIZE) {
            ktls_set_error(OPSSL_ERR_INVALID_KEY_LENGTH);
            return -1;
        }

        if (iv_len != TLS_CIPHER_AES_GCM_256_IV_SIZE) {
            ktls_set_error(OPSSL_ERR_INVALID_IV_LENGTH);
            return -1;
        }

        memcpy(info.key, key, TLS_CIPHER_AES_GCM_256_KEY_SIZE);
        memcpy(info.iv, iv, TLS_CIPHER_AES_GCM_256_IV_SIZE);
        memcpy(info.rec_seq, &seq_num, TLS_CIPHER_AES_GCM_256_REC_SEQ_SIZE);

        int tls_direction = (direction == OPSSL_KTLS_TX) ? TLS_TX : TLS_RX;
        return setsockopt(fd, SOL_TLS, tls_direction, &info, sizeof(info));
    }

    ktls_set_error(OPSSL_ERR_UNSUPPORTED_CIPHER);
    return -1;
}
#endif

int opssl_ktls_promote(opssl_conn_t *conn)
{
#ifdef OPSSL_HAVE_KTLS
    if (!conn) {
        ktls_set_error(OPSSL_ERR_NULL_POINTER);
        return -1;
    }

    if (opssl_conn_is_ktls_active(conn)) {
        /* Already promoted */
        return 0;
    }

    int fd = opssl_conn_get_fd(conn);
    if (fd < 0) {
        ktls_set_error(OPSSL_ERR_INVALID_FD);
        return -1;
    }

    /* Set TCP ULP to "tls" */
    if (setsockopt(fd, SOL_TCP, TCP_ULP, "tls", 3) < 0) {
        ktls_set_error(OPSSL_ERR_KTLS_ULP_FAILED);
        return -1;
    }

    /* Get connection parameters */
    int cipher = opssl_conn_get_cipher(conn);
    uint64_t write_seq, read_seq;
    uint8_t write_key[32], read_key[32];
    uint8_t write_iv[16], read_iv[16];
    size_t write_key_len = sizeof(write_key);
    size_t read_key_len = sizeof(read_key);
    size_t write_iv_len = sizeof(write_iv);
    size_t read_iv_len = sizeof(read_iv);

    if (opssl_conn_get_write_seq(conn, &write_seq) < 0 ||
        opssl_conn_get_read_seq(conn, &read_seq) < 0 ||
        opssl_conn_get_write_key(conn, write_key, &write_key_len) < 0 ||
        opssl_conn_get_read_key(conn, read_key, &read_key_len) < 0 ||
        opssl_conn_get_write_iv(conn, write_iv, &write_iv_len) < 0 ||
        opssl_conn_get_read_iv(conn, read_iv, &read_iv_len) < 0) {
        ktls_set_error(OPSSL_ERR_CONN_STATE_INVALID);
        return -1;
    }

    /* Setup TX direction */
    if (setup_ktls_crypto(fd, OPSSL_KTLS_TX, cipher,
                         write_key, write_key_len,
                         write_iv, write_iv_len,
                         write_seq) < 0) {
        ktls_set_error(OPSSL_ERR_KTLS_TX_SETUP_FAILED);
        return -1;
    }

    /* Setup RX direction */
    if (setup_ktls_crypto(fd, OPSSL_KTLS_RX, cipher,
                         read_key, read_key_len,
                         read_iv, read_iv_len,
                         read_seq) < 0) {
        ktls_set_error(OPSSL_ERR_KTLS_RX_SETUP_FAILED);
        return -1;
    }

    opssl_conn_set_ktls_active(conn, true);
    return 0;
#else
    (void)conn;
    ktls_set_error(OPSSL_ERR_KTLS_NOT_SUPPORTED);
    return -1;
#endif
}

ssize_t opssl_ktls_read(opssl_conn_t *conn, void *buf, size_t len)
{
#ifdef OPSSL_HAVE_KTLS
    if (!conn || !buf) {
        ktls_set_error(OPSSL_ERR_NULL_POINTER);
        return -1;
    }

    if (!opssl_conn_is_ktls_active(conn)) {
        ktls_set_error(OPSSL_ERR_KTLS_NOT_ACTIVE);
        return -1;
    }

    int fd = opssl_conn_get_fd(conn);
    if (fd < 0) {
        ktls_set_error(OPSSL_ERR_INVALID_FD);
        return -1;
    }

    ssize_t result = recv(fd, buf, len, 0);
    if (result < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            ktls_set_error(OPSSL_ERR_WANT_READ);
        } else {
            ktls_set_error(OPSSL_ERR_IO_ERROR);
        }
    }

    return result;
#else
    (void)conn;
    (void)buf;
    (void)len;
    ktls_set_error(OPSSL_ERR_KTLS_NOT_SUPPORTED);
    return -1;
#endif
}

ssize_t opssl_ktls_write(opssl_conn_t *conn, const void *buf, size_t len)
{
#ifdef OPSSL_HAVE_KTLS
    if (!conn || !buf) {
        ktls_set_error(OPSSL_ERR_NULL_POINTER);
        return -1;
    }

    if (!opssl_conn_is_ktls_active(conn)) {
        ktls_set_error(OPSSL_ERR_KTLS_NOT_ACTIVE);
        return -1;
    }

    int fd = opssl_conn_get_fd(conn);
    if (fd < 0) {
        ktls_set_error(OPSSL_ERR_INVALID_FD);
        return -1;
    }

    ssize_t result = send(fd, buf, len, 0);
    if (result < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            ktls_set_error(OPSSL_ERR_WANT_WRITE);
        } else {
            ktls_set_error(OPSSL_ERR_IO_ERROR);
        }
    }

    return result;
#else
    (void)conn;
    (void)buf;
    (void)len;
    ktls_set_error(OPSSL_ERR_KTLS_NOT_SUPPORTED);
    return -1;
#endif
}

opssl_conn_t *opssl_ktls_adopt(int fd, opssl_direction_t dir)
{
#ifdef OPSSL_HAVE_KTLS
    (void)dir;
    if (fd < 0) {
        ktls_set_error(OPSSL_ERR_INVALID_FD);
        return NULL;
    }

    /* Check if the socket has kTLS active */
    socklen_t optlen = 0;
    if (getsockopt(fd, SOL_TLS, TLS_TX, NULL, &optlen) < 0) {
        ktls_set_error(OPSSL_ERR_KTLS_NOT_ACTIVE);
        return NULL;
    }

    /* Create a minimal connection structure for kTLS-only operation */
    opssl_conn_t *conn = calloc(1, sizeof(opssl_conn_t));
    if (!conn) {
        ktls_set_error(OPSSL_ERR_MEMORY_ALLOCATION);
        return NULL;
    }

    /* Set the file descriptor and mark as kTLS active */
    opssl_conn_set_fd(conn, fd);
    opssl_conn_set_ktls_active(conn, true);

    return conn;
#else
    (void)fd;
    (void)dir;
    ktls_set_error(OPSSL_ERR_KTLS_NOT_SUPPORTED);
    return NULL;
#endif
}

int opssl_ktls_extract_keys(opssl_conn_t *conn,
                            opssl_ktls_keys_t *tx, opssl_ktls_keys_t *rx)
{
#ifdef OPSSL_HAVE_KTLS
    if (!conn || !tx || !rx) {
        ktls_set_error(OPSSL_ERR_NULL_POINTER);
        return -1;
    }

    if (!opssl_conn_is_ktls_active(conn)) {
        ktls_set_error(OPSSL_ERR_KTLS_NOT_ACTIVE);
        return -1;
    }

    memset(tx, 0, sizeof(*tx));
    memset(rx, 0, sizeof(*rx));

    size_t write_key_len = sizeof(tx->key);
    size_t read_key_len  = sizeof(rx->key);
    size_t write_iv_len  = sizeof(tx->iv);
    size_t read_iv_len   = sizeof(rx->iv);
    uint64_t write_seq = 0, read_seq = 0;

    if (opssl_conn_get_write_seq(conn, &write_seq) < 0 ||
        opssl_conn_get_read_seq(conn, &read_seq) < 0 ||
        opssl_conn_get_write_key(conn, tx->key, &write_key_len) < 0 ||
        opssl_conn_get_read_key(conn, rx->key, &read_key_len) < 0 ||
        opssl_conn_get_write_iv(conn, tx->iv, &write_iv_len) < 0 ||
        opssl_conn_get_read_iv(conn, rx->iv, &read_iv_len) < 0) {
        ktls_set_error(OPSSL_ERR_CONN_STATE_INVALID);
        return -1;
    }

    tx->key_len = write_key_len;
    rx->key_len = read_key_len;
    memcpy(tx->rec_seq, &write_seq, sizeof(tx->rec_seq));
    memcpy(rx->rec_seq, &read_seq,  sizeof(rx->rec_seq));

    return 0;
#else
    (void)conn;
    (void)tx;
    (void)rx;
    ktls_set_error(OPSSL_ERR_KTLS_NOT_SUPPORTED);
    return -1;
#endif
}
#define _POSIX_C_SOURCE 200809L

/*
 * opssl.c — unified opssl CLI tool with complete subcommand functionality.
 *
 * This tool replaces opssl_cli_minimal.c and merges functionality from
 * several legacy tools into one binary with subcommand dispatch.
 *
 * Copyright (C) 2026 ophion development team
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <getopt.h>
#include <ctype.h>
#include <stdbool.h>
#include <time.h>
#include <sys/time.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>

/* Forward declare only the functions we need from opssl */

/* Version and initialization */
extern int opssl_init(void);
extern void opssl_cleanup(void);
extern const char *opssl_version_string(void);

/* Hash functions - lengths */
#define OPSSL_SHA1_DIGEST_LEN    20
#define OPSSL_SHA256_DIGEST_LEN  32
#define OPSSL_SHA384_DIGEST_LEN  48
#define OPSSL_SHA512_DIGEST_LEN  64
#define OPSSL_SHA3_256_DIGEST_LEN 32
#define OPSSL_SHA3_512_DIGEST_LEN 64

/* One-shot hash functions */
extern void opssl_sha1(const void *data, size_t len, uint8_t out[OPSSL_SHA1_DIGEST_LEN]);
extern void opssl_sha256(const void *data, size_t len, uint8_t out[OPSSL_SHA256_DIGEST_LEN]);
extern void opssl_sha384(const void *data, size_t len, uint8_t out[OPSSL_SHA384_DIGEST_LEN]);
extern void opssl_sha512(const void *data, size_t len, uint8_t out[OPSSL_SHA512_DIGEST_LEN]);
extern void opssl_sha3_256(const void *data, size_t len, uint8_t out[OPSSL_SHA3_256_DIGEST_LEN]);
extern void opssl_sha3_512(const void *data, size_t len, uint8_t out[OPSSL_SHA3_512_DIGEST_LEN]);

/* SHAKE functions */
extern void opssl_shake128(uint8_t *out, size_t out_len, const uint8_t *in, size_t in_len);
extern void opssl_shake256(uint8_t *out, size_t out_len, const uint8_t *in, size_t in_len);

/* Base64 functions */
extern int opssl_base64_encode(const uint8_t *in, size_t in_len, char *out, size_t *out_len);
extern int opssl_base64_decode(const char *in, size_t in_len, uint8_t *out, size_t *out_len);

/* Random bytes */
extern int opssl_random_bytes(void *buf, size_t len);

/* HMAC */
typedef enum {
    OPSSL_HMAC_SHA256 = 0,
    OPSSL_HMAC_SHA384 = 1,
    OPSSL_HMAC_SHA512 = 2,
    OPSSL_HMAC_SHA1   = 3,
} opssl_hmac_algo_t;

extern int opssl_hmac(opssl_hmac_algo_t algo, const uint8_t *key, size_t key_len,
                      const void *data, size_t data_len, uint8_t *out, size_t *out_len);

/* Argon2id */
extern int opssl_argon2id(const uint8_t *password, size_t password_len,
                          const uint8_t *salt, size_t salt_len,
                          uint32_t t_cost, uint32_t m_cost, uint32_t parallelism,
                          uint8_t *out, size_t out_len);
extern int opssl_argon2id_verify(const uint8_t *password, size_t password_len,
                                 const uint8_t *salt, size_t salt_len,
                                 uint32_t t_cost, uint32_t m_cost, uint32_t parallelism,
                                 const uint8_t *expected, size_t expected_len);

/* BLAKE2b */
extern void opssl_blake2b(const void *data, size_t len, uint8_t *out, size_t outlen);

/* HKDF */
extern int opssl_hkdf_extract(opssl_hmac_algo_t algo,
                              const uint8_t *salt, size_t salt_len,
                              const uint8_t *ikm, size_t ikm_len,
                              uint8_t *prk, size_t *prk_len);
extern int opssl_hkdf_expand(opssl_hmac_algo_t algo,
                             const uint8_t *prk, size_t prk_len,
                             const uint8_t *info, size_t info_len,
                             uint8_t *okm, size_t okm_len);

/* PBKDF2 */
extern int opssl_pbkdf2(opssl_hmac_algo_t algo,
                        const uint8_t *password, size_t password_len,
                        const uint8_t *salt, size_t salt_len,
                        uint32_t iterations,
                        uint8_t *out, size_t out_len);

/* AEAD */
typedef enum {
    OPSSL_AEAD_AES_128_GCM = 0,
    OPSSL_AEAD_AES_256_GCM = 1,
    OPSSL_AEAD_CHACHA20_POLY1305 = 2,
    OPSSL_AEAD_AES_128_CCM = 3,
    OPSSL_AEAD_AES_256_CCM = 4,
    OPSSL_AEAD_AES_128_CCM_8 = 5,
    OPSSL_AEAD_AES_256_CCM_8 = 6,
    OPSSL_AEAD_CAMELLIA_128_GCM = 7,
    OPSSL_AEAD_CAMELLIA_256_GCM = 8,
} opssl_aead_algo_t;

typedef struct opssl_aead_ctx opssl_aead_ctx_t;

extern opssl_aead_ctx_t *opssl_aead_new(opssl_aead_algo_t algo);
extern int opssl_aead_set_key(opssl_aead_ctx_t *ctx, const uint8_t *key, size_t key_len);
extern void opssl_aead_free(opssl_aead_ctx_t *ctx);
extern int opssl_aead_seal(opssl_aead_ctx_t *ctx,
                           uint8_t *out, size_t *out_len, size_t max_out,
                           const uint8_t *nonce, size_t nonce_len,
                           const uint8_t *plaintext, size_t plaintext_len,
                           const uint8_t *aad, size_t aad_len);
extern int opssl_aead_open(opssl_aead_ctx_t *ctx,
                           uint8_t *out, size_t *out_len, size_t max_out,
                           const uint8_t *nonce, size_t nonce_len,
                           const uint8_t *ciphertext, size_t ciphertext_len,
                           const uint8_t *aad, size_t aad_len);
extern size_t opssl_aead_key_len(opssl_aead_algo_t algo);
extern size_t opssl_aead_nonce_len(opssl_aead_algo_t algo);
extern size_t opssl_aead_tag_len(opssl_aead_algo_t algo);

/* TLS context and connection */
typedef enum {
    OPSSL_TLS_1_2 = 0x0303,
    OPSSL_TLS_1_3 = 0x0304,
} opssl_tls_version_cli_t;

typedef enum {
    OPSSL_DIR_INBOUND  = 0,
    OPSSL_DIR_OUTBOUND = 1,
} opssl_direction_cli_t;

typedef enum {
    OPSSL_OK_CLI         =  1,
    OPSSL_ERROR_CLI      =  0,
    OPSSL_WANT_READ_CLI  = -2,
    OPSSL_WANT_WRITE_CLI = -3,
    OPSSL_CLOSED_CLI     = -4,
} opssl_result_cli_t;

typedef struct opssl_ctx  opssl_ctx_t;
typedef struct opssl_conn opssl_conn_t;

extern opssl_ctx_t  *opssl_ctx_new(int min_version);
extern void          opssl_ctx_free(opssl_ctx_t *ctx);
extern void          opssl_ctx_set_min_version(opssl_ctx_t *ctx, int ver);
extern void          opssl_ctx_set_max_version(opssl_ctx_t *ctx, int ver);
extern int           opssl_ctx_load_default_verify_paths(opssl_ctx_t *ctx);
extern int           opssl_ctx_load_verify_locations(opssl_ctx_t *ctx, const char *ca_file, const char *ca_dir);
extern void          opssl_ctx_set_verify(opssl_ctx_t *ctx, bool require, void *cb, void *userdata);

extern opssl_conn_t *opssl_conn_new(opssl_ctx_t *ctx, int fd, int dir);
extern void          opssl_conn_free(opssl_conn_t *conn);
extern int           opssl_conn_set_sni(opssl_conn_t *conn, const char *hostname);
extern int           opssl_connect(opssl_conn_t *conn);
extern ssize_t       opssl_read(opssl_conn_t *conn, void *buf, size_t len);
extern ssize_t       opssl_write(opssl_conn_t *conn, const void *buf, size_t len);
extern int           opssl_conn_version(opssl_conn_t *conn);
extern const char   *opssl_conn_cipher_name(opssl_conn_t *conn);
extern int           opssl_conn_get_last_want(opssl_conn_t *conn);
extern const char   *opssl_conn_get_error_string(opssl_conn_t *conn);
extern int           opssl_shutdown(opssl_conn_t *conn);

/* X.509 certificate types */
typedef struct opssl_x509 opssl_x509_t;

extern opssl_x509_t *opssl_conn_get_peer_cert(opssl_conn_t *conn);
typedef struct opssl_x509_chain opssl_x509_chain_t;
typedef struct opssl_x509_store opssl_x509_store_t;

typedef enum {
    OPSSL_FP_SHA1 = 0,
    OPSSL_FP_SHA256 = 1,
    OPSSL_FP_SHA512 = 2,
    OPSSL_FP_SHA3_256 = 3,
    OPSSL_FP_SHA3_512 = 4,
    OPSSL_FP_SPKI_SHA256 = 5,
    OPSSL_FP_SPKI_SHA512 = 6,
    OPSSL_FP_SPKI_SHA3_256 = 7,
    OPSSL_FP_SPKI_SHA3_512 = 8,
} opssl_fingerprint_method_t;

typedef struct {
    int depth;
    int error_code;
    const char *error_string;
    size_t chain_length;
    uint8_t leaf_fingerprint[32];
} opssl_x509_verify_result_t;

/* X.509 certificate functions */
extern opssl_x509_t *opssl_x509_from_file(const char *path);
extern void opssl_x509_free(opssl_x509_t *cert);
extern int opssl_x509_fingerprint_hex(const opssl_x509_t *cert,
                                      opssl_fingerprint_method_t method,
                                      char *out, size_t out_len);
extern int opssl_x509_get_subject(const opssl_x509_t *cert, char *buf, size_t len);
extern int opssl_x509_get_issuer(const opssl_x509_t *cert, char *buf, size_t len);
extern int opssl_x509_get_serial(const opssl_x509_t *cert, uint8_t *buf, size_t *len);
extern int opssl_x509_get_not_before(const opssl_x509_t *cert, int64_t *epoch);
extern int opssl_x509_get_not_after(const opssl_x509_t *cert, int64_t *epoch);

extern opssl_x509_store_t *opssl_x509_store_new(void);
extern void opssl_x509_store_free(opssl_x509_store_t *store);
extern int opssl_x509_store_load_file(opssl_x509_store_t *store, const char *path);
extern opssl_x509_chain_t *opssl_x509_chain_from_file(const char *path);
extern void opssl_x509_chain_free(opssl_x509_chain_t *chain);
extern int opssl_x509_verify(const opssl_x509_chain_t *chain,
                             const opssl_x509_store_t *store,
                             const char *hostname,
                             opssl_x509_verify_result_t *result);

extern void opssl_memzero(void *ptr, size_t len);

extern int opssl_ed25519_keygen(uint8_t pk[32], uint8_t sk[64]);
extern int opssl_ed25519_sign(uint8_t sig[64], const uint8_t *msg, size_t msg_len,
                              const uint8_t sk[64]);
extern int opssl_x25519_keygen(uint8_t priv[32], uint8_t pub[32]);

typedef struct opssl_pkey opssl_pkey_t;
extern opssl_pkey_t *opssl_pkey_from_file(const char *path);
extern void opssl_pkey_free(opssl_pkey_t *key);
extern int opssl_pkey_type(const opssl_pkey_t *key);
extern size_t opssl_pkey_bits(const opssl_pkey_t *key);

extern int opssl_ctx_use_certificate_file(opssl_ctx_t *ctx, const char *path);
extern int opssl_ctx_use_private_key_file(opssl_ctx_t *ctx, const char *path);
extern int opssl_accept(opssl_conn_t *conn);

extern int opssl_x509_get_san_count(const opssl_x509_t *cert);
extern int opssl_x509_get_san(const opssl_x509_t *cert, int idx, char *buf, size_t len);
extern int opssl_x509_is_expired(const opssl_x509_t *cert);

#define BUFFER_SIZE 65536

/* ─── Utility Functions ──────────────────────────────────────────────── */

static void print_hex(const uint8_t *data, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
}

static int hex_to_bytes(const char *hex, uint8_t *bytes, size_t max_bytes)
{
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0) return 0;

    size_t byte_len = hex_len / 2;
    if (byte_len > max_bytes) return 0;

    for (size_t i = 0; i < byte_len; i++) {
        int hi = hex[2*i];
        int lo = hex[2*i + 1];

        if (!isxdigit(hi) || !isxdigit(lo)) return 0;

        hi = hi >= 'a' ? hi - 'a' + 10 : (hi >= 'A' ? hi - 'A' + 10 : hi - '0');
        lo = lo >= 'a' ? lo - 'a' + 10 : (lo >= 'A' ? lo - 'A' + 10 : lo - '0');

        bytes[i] = (hi << 4) | lo;
    }
    return (int)byte_len;
}

static FILE *safe_fopen(const char *path, const char *mode)
{
    if (!path || strcmp(path, "-") == 0) {
        return (mode[0] == 'r') ? stdin : stdout;
    }
    return fopen(path, mode);
}

static void strip_newlines(char *s, size_t *len)
{
    size_t w = 0;
    for (size_t r = 0; r < *len; r++) {
        if (s[r] != '\n' && s[r] != '\r')
            s[w++] = s[r];
    }
    s[w] = '\0';
    *len = w;
}

static void safe_fclose(FILE *f)
{
    if (f && f != stdin && f != stdout && f != stderr) {
        fclose(f);
    }
}

static char *read_file_to_string(const char *path, size_t *len_out)
{
    FILE *f = safe_fopen(path, "rb");
    if (!f) return NULL;

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    char *buf = malloc(size + 1);
    if (!buf) {
        safe_fclose(f);
        return NULL;
    }

    size_t read_size = fread(buf, 1, size, f);
    buf[read_size] = '\0';
    safe_fclose(f);

    if (len_out) *len_out = read_size;
    return buf;
}

/* ─── RFC 3526 DH Primes ─────────────────────────────────────────────── */

static const unsigned char prime_2048[256] = {
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xC9,0x0F,0xDA,0xA2,0x21,0x68,0xC2,0x34,
    0xC4,0xC6,0x62,0x8B,0x80,0xDC,0x1C,0xD1,0x29,0x02,0x4E,0x08,0x8A,0x67,0xCC,0x74,
    0x02,0x0B,0xBE,0xA6,0x3B,0x13,0x9B,0x22,0x51,0x4A,0x08,0x79,0x8E,0x34,0x04,0xDD,
    0xEF,0x95,0x19,0xB3,0xCD,0x3A,0x43,0x1B,0x30,0x2B,0x0A,0x6D,0xF2,0x5F,0x14,0x37,
    0x4F,0xE1,0x35,0x6D,0x6D,0x51,0xC2,0x45,0xE4,0x85,0xB5,0x76,0x62,0x5E,0x7E,0xC6,
    0xF4,0x4C,0x42,0xE9,0xA6,0x37,0xED,0x6B,0x0B,0xFF,0x5C,0xB6,0xF4,0x06,0xB7,0xED,
    0xEE,0x38,0x6B,0xFB,0x5A,0x89,0x9F,0xA5,0xAE,0x9F,0x24,0x11,0x7C,0x4B,0x1F,0xE6,
    0x49,0x28,0x66,0x51,0xEC,0xE4,0x5B,0x3D,0xC2,0x00,0x7C,0xB8,0xA1,0x63,0xBF,0x05,
    0x98,0xDA,0x48,0x36,0x1C,0x55,0xD3,0x9A,0x69,0x16,0x3F,0xA8,0xFD,0x24,0xCF,0x5F,
    0x83,0x65,0x5D,0x23,0xDC,0xA3,0xAD,0x96,0x1C,0x62,0xF3,0x56,0x20,0x85,0x52,0xBB,
    0x9E,0xD5,0x29,0x07,0x70,0x96,0x96,0x6D,0x67,0x0C,0x35,0x4E,0x4A,0xBC,0x98,0x04,
    0xF1,0x74,0x6C,0x08,0xCA,0x18,0x21,0x7C,0x32,0x90,0x5E,0x46,0x2E,0x36,0xCE,0x3B,
    0xE3,0x9E,0x77,0x2C,0x18,0x0E,0x86,0x03,0x9B,0x27,0x83,0xA2,0xEC,0x07,0xA2,0x8F,
    0xB5,0xC5,0x5D,0xF0,0x6F,0x4C,0x52,0xC9,0xDE,0x2B,0xCB,0xF6,0x95,0x58,0x17,0x18,
    0x35,0x99,0x54,0x97,0xCE,0xA9,0x56,0xAE,0x51,0x5D,0x22,0x61,0x89,0x8F,0xA0,0x51,
    0x01,0x57,0x28,0xE5,0xA8,0xAA,0xCA,0xA6,0x8F,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF
};

static const unsigned char prime_3072[384] = {
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xC9,0x0F,0xDA,0xA2,0x21,0x68,0xC2,0x34,
    0xC4,0xC6,0x62,0x8B,0x80,0xDC,0x1C,0xD1,0x29,0x02,0x4E,0x08,0x8A,0x67,0xCC,0x74,
    0x02,0x0B,0xBE,0xA6,0x3B,0x13,0x9B,0x22,0x51,0x4A,0x08,0x79,0x8E,0x34,0x04,0xDD,
    0xEF,0x95,0x19,0xB3,0xCD,0x3A,0x43,0x1B,0x30,0x2B,0x0A,0x6D,0xF2,0x5F,0x14,0x37,
    0x4F,0xE1,0x35,0x6D,0x6D,0x51,0xC2,0x45,0xE4,0x85,0xB5,0x76,0x62,0x5E,0x7E,0xC6,
    0xF4,0x4C,0x42,0xE9,0xA6,0x37,0xED,0x6B,0x0B,0xFF,0x5C,0xB6,0xF4,0x06,0xB7,0xED,
    0xEE,0x38,0x6B,0xFB,0x5A,0x89,0x9F,0xA5,0xAE,0x9F,0x24,0x11,0x7C,0x4B,0x1F,0xE6,
    0x49,0x28,0x66,0x51,0xEC,0xE4,0x5B,0x3D,0xC2,0x00,0x7C,0xB8,0xA1,0x63,0xBF,0x05,
    0x98,0xDA,0x48,0x36,0x1C,0x55,0xD3,0x9A,0x69,0x16,0x3F,0xA8,0xFD,0x24,0xCF,0x5F,
    0x83,0x65,0x5D,0x23,0xDC,0xA3,0xAD,0x96,0x1C,0x62,0xF3,0x56,0x20,0x85,0x52,0xBB,
    0x9E,0xD5,0x29,0x07,0x70,0x96,0x96,0x6D,0x67,0x0C,0x35,0x4E,0x4A,0xBC,0x98,0x04,
    0xF1,0x74,0x6C,0x08,0xCA,0x18,0x21,0x7C,0x32,0x90,0x5E,0x46,0x2E,0x36,0xCE,0x3B,
    0xE3,0x9E,0x77,0x2C,0x18,0x0E,0x86,0x03,0x9B,0x27,0x83,0xA2,0xEC,0x07,0xA2,0x8F,
    0xB5,0xC5,0x5D,0xF0,0x6F,0x4C,0x52,0xC9,0xDE,0x2B,0xCB,0xF6,0x95,0x58,0x17,0x18,
    0x35,0x99,0x54,0x97,0xCE,0xA9,0x56,0xAE,0x51,0x5D,0x22,0x61,0x89,0x8F,0xA0,0x51,
    0x01,0x57,0x28,0xE5,0xA8,0xAA,0xCA,0xA6,0x8F,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xC9,0x0F,0xDA,0xA2,0x21,0x68,0xC2,0x34,
    0xC4,0xC6,0x62,0x8B,0x80,0xDC,0x1C,0xD1,0x29,0x02,0x4E,0x08,0x8A,0x67,0xCC,0x74,
    0x02,0x0B,0xBE,0xA6,0x3B,0x13,0x9B,0x22,0x51,0x4A,0x08,0x79,0x8E,0x34,0x04,0xDD,
    0xEF,0x95,0x19,0xB3,0xCD,0x3A,0x43,0x1B,0x30,0x2B,0x0A,0x6D,0xF2,0x5F,0x14,0x37,
    0x4F,0xE1,0x35,0x6D,0x6D,0x51,0xC2,0x45,0xE4,0x85,0xB5,0x76,0x62,0x5E,0x7E,0xC6,
    0xF4,0x4C,0x42,0xE9,0xA6,0x37,0xED,0x6B,0x0B,0xFF,0x5C,0xB6,0xF4,0x06,0xB7,0xED,
    0xEE,0x38,0x6B,0xFB,0x5A,0x89,0x9F,0xA5,0xAE,0x9F,0x24,0x11,0x7C,0x4B,0x1F,0xE6,
    0x49,0x28,0x66,0x51,0xEC,0xE4,0x5B,0x3D,0xC2,0x00,0x7C,0xB8,0xA1,0x63,0xBF,0x05
};

static const unsigned char prime_4096[512] = {
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xC9,0x0F,0xDA,0xA2,0x21,0x68,0xC2,0x34,
    0xC4,0xC6,0x62,0x8B,0x80,0xDC,0x1C,0xD1,0x29,0x02,0x4E,0x08,0x8A,0x67,0xCC,0x74,
    0x02,0x0B,0xBE,0xA6,0x3B,0x13,0x9B,0x22,0x51,0x4A,0x08,0x79,0x8E,0x34,0x04,0xDD,
    0xEF,0x95,0x19,0xB3,0xCD,0x3A,0x43,0x1B,0x30,0x2B,0x0A,0x6D,0xF2,0x5F,0x14,0x37,
    0x4F,0xE1,0x35,0x6D,0x6D,0x51,0xC2,0x45,0xE4,0x85,0xB5,0x76,0x62,0x5E,0x7E,0xC6,
    0xF4,0x4C,0x42,0xE9,0xA6,0x37,0xED,0x6B,0x0B,0xFF,0x5C,0xB6,0xF4,0x06,0xB7,0xED,
    0xEE,0x38,0x6B,0xFB,0x5A,0x89,0x9F,0xA5,0xAE,0x9F,0x24,0x11,0x7C,0x4B,0x1F,0xE6,
    0x49,0x28,0x66,0x51,0xEC,0xE4,0x5B,0x3D,0xC2,0x00,0x7C,0xB8,0xA1,0x63,0xBF,0x05,
    0x98,0xDA,0x48,0x36,0x1C,0x55,0xD3,0x9A,0x69,0x16,0x3F,0xA8,0xFD,0x24,0xCF,0x5F,
    0x83,0x65,0x5D,0x23,0xDC,0xA3,0xAD,0x96,0x1C,0x62,0xF3,0x56,0x20,0x85,0x52,0xBB,
    0x9E,0xD5,0x29,0x07,0x70,0x96,0x96,0x6D,0x67,0x0C,0x35,0x4E,0x4A,0xBC,0x98,0x04,
    0xF1,0x74,0x6C,0x08,0xCA,0x18,0x21,0x7C,0x32,0x90,0x5E,0x46,0x2E,0x36,0xCE,0x3B,
    0xE3,0x9E,0x77,0x2C,0x18,0x0E,0x86,0x03,0x9B,0x27,0x83,0xA2,0xEC,0x07,0xA2,0x8F,
    0xB5,0xC5,0x5D,0xF0,0x6F,0x4C,0x52,0xC9,0xDE,0x2B,0xCB,0xF6,0x95,0x58,0x17,0x18,
    0x35,0x99,0x54,0x97,0xCE,0xA9,0x56,0xAE,0x51,0x5D,0x22,0x61,0x89,0x8F,0xA0,0x51,
    0x01,0x57,0x28,0xE5,0xA8,0xAA,0xCA,0xA6,0x8F,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xC9,0x0F,0xDA,0xA2,0x21,0x68,0xC2,0x34,
    0xC4,0xC6,0x62,0x8B,0x80,0xDC,0x1C,0xD1,0x29,0x02,0x4E,0x08,0x8A,0x67,0xCC,0x74,
    0x02,0x0B,0xBE,0xA6,0x3B,0x13,0x9B,0x22,0x51,0x4A,0x08,0x79,0x8E,0x34,0x04,0xDD,
    0xEF,0x95,0x19,0xB3,0xCD,0x3A,0x43,0x1B,0x30,0x2B,0x0A,0x6D,0xF2,0x5F,0x14,0x37,
    0x4F,0xE1,0x35,0x6D,0x6D,0x51,0xC2,0x45,0xE4,0x85,0xB5,0x76,0x62,0x5E,0x7E,0xC6,
    0xF4,0x4C,0x42,0xE9,0xA6,0x37,0xED,0x6B,0x0B,0xFF,0x5C,0xB6,0xF4,0x06,0xB7,0xED,
    0xEE,0x38,0x6B,0xFB,0x5A,0x89,0x9F,0xA5,0xAE,0x9F,0x24,0x11,0x7C,0x4B,0x1F,0xE6,
    0x49,0x28,0x66,0x51,0xEC,0xE4,0x5B,0x3D,0xC2,0x00,0x7C,0xB8,0xA1,0x63,0xBF,0x05,
    0x98,0xDA,0x48,0x36,0x1C,0x55,0xD3,0x9A,0x69,0x16,0x3F,0xA8,0xFD,0x24,0xCF,0x5F,
    0x83,0x65,0x5D,0x23,0xDC,0xA3,0xAD,0x96,0x1C,0x62,0xF3,0x56,0x20,0x85,0x52,0xBB,
    0x9E,0xD5,0x29,0x07,0x70,0x96,0x96,0x6D,0x67,0x0C,0x35,0x4E,0x4A,0xBC,0x98,0x04,
    0xF1,0x74,0x6C,0x08,0xCA,0x18,0x21,0x7C,0x32,0x90,0x5E,0x46,0x2E,0x36,0xCE,0x3B,
    0xE3,0x9E,0x77,0x2C,0x18,0x0E,0x86,0x03,0x9B,0x27,0x83,0xA2,0xEC,0x07,0xA2,0x8F,
    0xB5,0xC5,0x5D,0xF0,0x6F,0x4C,0x52,0xC9,0xDE,0x2B,0xCB,0xF6,0x95,0x58,0x17,0x18,
    0x35,0x99,0x54,0x97,0xCE,0xA9,0x56,0xAE,0x51,0x5D,0x22,0x61,0x89,0x8F,0xA0,0x51,
    0x01,0x57,0x28,0xE5,0xA8,0xAA,0xCA,0xA6,0x8F,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF
};

/* RFC 7919 ffdhe6144 — 6144-bit safe prime (TLS 1.3 standard) */
static const unsigned char prime_6144[768] = {
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xAD,0xF8,0x54,0x58,0xA2,0xBB,0x4A,0x9A,
    0xAF,0xDC,0x56,0x20,0x27,0x3D,0x3C,0xF1,0xD8,0xB9,0xC5,0x83,0xCE,0x2D,0x36,0x95,
    0xA9,0xE1,0x36,0x41,0x14,0x64,0x33,0xFB,0xCC,0x93,0x9D,0xCE,0x24,0x9B,0x3E,0xF9,
    0x7D,0x2F,0xE3,0x63,0x63,0x0C,0x75,0xD8,0xF6,0x81,0xB2,0x02,0xAE,0xC4,0x61,0x7A,
    0xD3,0xDF,0x1E,0xD5,0xD5,0xFD,0x65,0x61,0x24,0x33,0xF5,0x1F,0x5F,0x06,0x6E,0xD0,
    0x85,0x63,0x65,0x55,0x3D,0xED,0x1A,0xF3,0xB5,0x57,0x13,0x5E,0x7F,0x57,0xC9,0x35,
    0x98,0x4F,0x0C,0x70,0xE0,0xE6,0x8B,0x77,0xE2,0xA6,0x89,0xDA,0xF3,0xEF,0xE8,0x72,
    0x1D,0xF1,0x58,0xA1,0x36,0xAD,0xE7,0x35,0x30,0xAC,0xCA,0x4F,0x48,0x3A,0x79,0x7A,
    0xBC,0x0A,0xB1,0x82,0xB3,0x24,0xFB,0x61,0xD1,0x08,0xA9,0x4B,0xB2,0xC8,0xE3,0xFB,
    0xB9,0x6A,0xDA,0xB7,0x60,0xD7,0xF4,0x68,0x1D,0x4F,0x42,0xA3,0xDE,0x39,0x4D,0xF4,
    0xAE,0x56,0xED,0xE7,0x63,0x72,0xBB,0x19,0x0B,0x07,0xA7,0xC8,0xEE,0x0A,0x6D,0x70,
    0x9E,0x02,0xFC,0xE1,0xCD,0xF7,0xE2,0xEC,0xC0,0x34,0x04,0xCD,0x28,0x34,0x2F,0x61,
    0x91,0x72,0xFE,0x9C,0xE9,0x85,0x83,0xFF,0x8E,0x4F,0x12,0x32,0xEE,0xF2,0x81,0x83,
    0xC3,0xFE,0x3B,0x1B,0x4C,0x6F,0xAD,0x73,0x3B,0xB5,0xFC,0xBC,0x2E,0xC2,0x20,0x05,
    0xC5,0x8E,0xF1,0x83,0x7D,0x16,0x83,0xB2,0xC6,0xF3,0x4A,0x26,0xC1,0xB2,0xEF,0xFA,
    0x88,0x6B,0x42,0x38,0x61,0x1F,0xCF,0xDC,0xDE,0x35,0x5B,0x3B,0x65,0x19,0x03,0x5B,
    0xBC,0x34,0xF4,0xDE,0xF9,0x9C,0x02,0x38,0x61,0xB4,0x6F,0xC9,0xD6,0xE6,0xC9,0x07,
    0x7A,0xD9,0x1D,0x26,0x91,0xF7,0xF7,0xEE,0x59,0x8C,0xB0,0xFA,0xC1,0x86,0xD9,0x1C,
    0xAE,0xFE,0x13,0x09,0x85,0x13,0x92,0x70,0xB4,0x13,0x0C,0x93,0xBC,0x43,0x79,0x44,
    0xF4,0xFD,0x44,0x52,0xE2,0xD7,0x4D,0xD3,0x64,0xF2,0xE2,0x1E,0x71,0xF5,0x4B,0xFF,
    0x5C,0xAE,0x82,0xAB,0x9C,0x9D,0xF6,0x9E,0xE8,0x6D,0x2B,0xC5,0x22,0x36,0x3A,0x0D,
    0xAB,0xC5,0x21,0x97,0x9B,0x0D,0xEA,0xDA,0x1D,0xBF,0x9A,0x42,0xD5,0xC4,0x48,0x4E,
    0x0A,0xBC,0xD0,0x6B,0xFA,0x53,0xDD,0xEF,0x3C,0x1B,0x20,0xEE,0x3F,0xD5,0x9D,0x7C,
    0x25,0xE4,0x1D,0x2B,0x66,0x9E,0x1E,0xF1,0x6E,0x6F,0x52,0xC3,0x16,0x4D,0xF4,0xFB,
    0x79,0x30,0xE9,0xE4,0xE5,0x88,0x57,0xB6,0xAC,0x7D,0x5F,0x42,0xD6,0x9F,0x6D,0x18,
    0x77,0x63,0xCF,0x1D,0x55,0x03,0x40,0x04,0x87,0xF5,0x5B,0xA5,0x7E,0x31,0xCC,0x7A,
    0x71,0x35,0xC8,0x86,0xEF,0xB4,0x31,0x8A,0xED,0x6A,0x1E,0x01,0x2D,0x9E,0x68,0x32,
    0xA9,0x07,0x60,0x0A,0x91,0x81,0x30,0xC4,0x6D,0xC7,0x78,0xF9,0x71,0xAD,0x00,0x38,
    0x09,0x29,0x99,0xA3,0x33,0xCB,0x8B,0x7A,0x1A,0x1D,0xB9,0x3D,0x71,0x40,0x00,0x3C,
    0x2A,0x4E,0xCE,0xA9,0xF9,0x8D,0x0A,0xCC,0x0A,0x82,0x91,0xCD,0xCE,0xC9,0x7D,0xCF,
    0x8E,0xC9,0xB5,0x5A,0x7F,0x88,0xA4,0x6B,0x4D,0xB5,0xA8,0x51,0xF4,0x41,0x82,0xE1,
    0xC6,0x8A,0x00,0x7E,0x5E,0x0D,0xD9,0x02,0x0B,0xFD,0x64,0xB6,0x45,0x03,0x6C,0x7A,
    0x4E,0x67,0x7D,0x2C,0x38,0x53,0x2A,0x3A,0x23,0xBA,0x44,0x42,0xCA,0xF5,0x3E,0xA6,
    0x3B,0xB4,0x54,0x32,0x9B,0x76,0x24,0xC8,0x91,0x7B,0xDD,0x64,0xB1,0xC0,0xFD,0x4C,
    0xB3,0x8E,0x8C,0x33,0x4C,0x70,0x1C,0x3A,0xCD,0xAD,0x06,0x57,0xFC,0xCF,0xEC,0x71,
    0x9B,0x1F,0x5C,0x3E,0x4E,0x46,0x04,0x1F,0x38,0x81,0x47,0xFB,0x4C,0xFD,0xB4,0x77,
    0xA5,0x24,0x71,0xF7,0xA9,0xA9,0x69,0x10,0xB8,0x55,0x32,0x2E,0xDB,0x63,0x40,0xD8,
    0xA0,0x0E,0xF0,0x92,0x35,0x05,0x11,0xE3,0x0A,0xBE,0xC1,0xFF,0xF9,0xE3,0xA2,0x6E,
    0x7F,0xB2,0x9F,0x8C,0x18,0x30,0x23,0xC3,0x58,0x7E,0x38,0xDA,0x00,0x77,0xD9,0xB4,
    0x76,0x3E,0x4E,0x4B,0x94,0xB2,0xBB,0xC1,0x94,0xC6,0x65,0x1E,0x77,0xCA,0xF9,0x92,
    0xEE,0xAA,0xC0,0x23,0x2A,0x28,0x1B,0xF6,0xB3,0xA7,0x39,0xC1,0x22,0x61,0x16,0x82,
    0x0A,0xE8,0xDB,0x58,0x47,0xA6,0x7C,0xBE,0xF9,0xC9,0x09,0x1B,0x46,0x2D,0x53,0x8C,
    0xD7,0x2B,0x03,0x74,0x6A,0xE7,0x7F,0x5E,0x62,0x29,0x2C,0x31,0x15,0x62,0xA8,0x46,
    0x50,0x5D,0xC8,0x2D,0xB8,0x54,0x33,0x8A,0xE4,0x9F,0x52,0x35,0xC9,0x5B,0x91,0x17,
    0x8C,0xCF,0x2D,0xD5,0xCA,0xCE,0xF4,0x03,0xEC,0x9D,0x18,0x10,0xC6,0x27,0x2B,0x04,
    0x5B,0x3B,0x71,0xF9,0xDC,0x6B,0x80,0xD6,0x3F,0xDD,0x4A,0x8E,0x9A,0xDB,0x1E,0x69,
    0x62,0xA6,0x95,0x26,0xD4,0x31,0x61,0xC1,0xA4,0x1D,0x57,0x0D,0x79,0x38,0xDA,0xD4,
    0xA4,0x0E,0x32,0x9C,0xD0,0xE4,0x0E,0x65,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF
};

/* RFC 7919 ffdhe8192 — 8192-bit safe prime (TLS 1.3 standard) */
static const unsigned char prime_8192[1024] = {
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xAD,0xF8,0x54,0x58,0xA2,0xBB,0x4A,0x9A,
    0xAF,0xDC,0x56,0x20,0x27,0x3D,0x3C,0xF1,0xD8,0xB9,0xC5,0x83,0xCE,0x2D,0x36,0x95,
    0xA9,0xE1,0x36,0x41,0x14,0x64,0x33,0xFB,0xCC,0x93,0x9D,0xCE,0x24,0x9B,0x3E,0xF9,
    0x7D,0x2F,0xE3,0x63,0x63,0x0C,0x75,0xD8,0xF6,0x81,0xB2,0x02,0xAE,0xC4,0x61,0x7A,
    0xD3,0xDF,0x1E,0xD5,0xD5,0xFD,0x65,0x61,0x24,0x33,0xF5,0x1F,0x5F,0x06,0x6E,0xD0,
    0x85,0x63,0x65,0x55,0x3D,0xED,0x1A,0xF3,0xB5,0x57,0x13,0x5E,0x7F,0x57,0xC9,0x35,
    0x98,0x4F,0x0C,0x70,0xE0,0xE6,0x8B,0x77,0xE2,0xA6,0x89,0xDA,0xF3,0xEF,0xE8,0x72,
    0x1D,0xF1,0x58,0xA1,0x36,0xAD,0xE7,0x35,0x30,0xAC,0xCA,0x4F,0x48,0x3A,0x79,0x7A,
    0xBC,0x0A,0xB1,0x82,0xB3,0x24,0xFB,0x61,0xD1,0x08,0xA9,0x4B,0xB2,0xC8,0xE3,0xFB,
    0xB9,0x6A,0xDA,0xB7,0x60,0xD7,0xF4,0x68,0x1D,0x4F,0x42,0xA3,0xDE,0x39,0x4D,0xF4,
    0xAE,0x56,0xED,0xE7,0x63,0x72,0xBB,0x19,0x0B,0x07,0xA7,0xC8,0xEE,0x0A,0x6D,0x70,
    0x9E,0x02,0xFC,0xE1,0xCD,0xF7,0xE2,0xEC,0xC0,0x34,0x04,0xCD,0x28,0x34,0x2F,0x61,
    0x91,0x72,0xFE,0x9C,0xE9,0x85,0x83,0xFF,0x8E,0x4F,0x12,0x32,0xEE,0xF2,0x81,0x83,
    0xC3,0xFE,0x3B,0x1B,0x4C,0x6F,0xAD,0x73,0x3B,0xB5,0xFC,0xBC,0x2E,0xC2,0x20,0x05,
    0xC5,0x8E,0xF1,0x83,0x7D,0x16,0x83,0xB2,0xC6,0xF3,0x4A,0x26,0xC1,0xB2,0xEF,0xFA,
    0x88,0x6B,0x42,0x38,0x61,0x1F,0xCF,0xDC,0xDE,0x35,0x5B,0x3B,0x65,0x19,0x03,0x5B,
    0xBC,0x34,0xF4,0xDE,0xF9,0x9C,0x02,0x38,0x61,0xB4,0x6F,0xC9,0xD6,0xE6,0xC9,0x07,
    0x7A,0xD9,0x1D,0x26,0x91,0xF7,0xF7,0xEE,0x59,0x8C,0xB0,0xFA,0xC1,0x86,0xD9,0x1C,
    0xAE,0xFE,0x13,0x09,0x85,0x13,0x92,0x70,0xB4,0x13,0x0C,0x93,0xBC,0x43,0x79,0x44,
    0xF4,0xFD,0x44,0x52,0xE2,0xD7,0x4D,0xD3,0x64,0xF2,0xE2,0x1E,0x71,0xF5,0x4B,0xFF,
    0x5C,0xAE,0x82,0xAB,0x9C,0x9D,0xF6,0x9E,0xE8,0x6D,0x2B,0xC5,0x22,0x36,0x3A,0x0D,
    0xAB,0xC5,0x21,0x97,0x9B,0x0D,0xEA,0xDA,0x1D,0xBF,0x9A,0x42,0xD5,0xC4,0x48,0x4E,
    0x0A,0xBC,0xD0,0x6B,0xFA,0x53,0xDD,0xEF,0x3C,0x1B,0x20,0xEE,0x3F,0xD5,0x9D,0x7C,
    0x25,0xE4,0x1D,0x2B,0x66,0x9E,0x1E,0xF1,0x6E,0x6F,0x52,0xC3,0x16,0x4D,0xF4,0xFB,
    0x79,0x30,0xE9,0xE4,0xE5,0x88,0x57,0xB6,0xAC,0x7D,0x5F,0x42,0xD6,0x9F,0x6D,0x18,
    0x77,0x63,0xCF,0x1D,0x55,0x03,0x40,0x04,0x87,0xF5,0x5B,0xA5,0x7E,0x31,0xCC,0x7A,
    0x71,0x35,0xC8,0x86,0xEF,0xB4,0x31,0x8A,0xED,0x6A,0x1E,0x01,0x2D,0x9E,0x68,0x32,
    0xA9,0x07,0x60,0x0A,0x91,0x81,0x30,0xC4,0x6D,0xC7,0x78,0xF9,0x71,0xAD,0x00,0x38,
    0x09,0x29,0x99,0xA3,0x33,0xCB,0x8B,0x7A,0x1A,0x1D,0xB9,0x3D,0x71,0x40,0x00,0x3C,
    0x2A,0x4E,0xCE,0xA9,0xF9,0x8D,0x0A,0xCC,0x0A,0x82,0x91,0xCD,0xCE,0xC9,0x7D,0xCF,
    0x8E,0xC9,0xB5,0x5A,0x7F,0x88,0xA4,0x6B,0x4D,0xB5,0xA8,0x51,0xF4,0x41,0x82,0xE1,
    0xC6,0x8A,0x00,0x7E,0x5E,0x0D,0xD9,0x02,0x0B,0xFD,0x64,0xB6,0x45,0x03,0x6C,0x7A,
    0x4E,0x67,0x7D,0x2C,0x38,0x53,0x2A,0x3A,0x23,0xBA,0x44,0x42,0xCA,0xF5,0x3E,0xA6,
    0x3B,0xB4,0x54,0x32,0x9B,0x76,0x24,0xC8,0x91,0x7B,0xDD,0x64,0xB1,0xC0,0xFD,0x4C,
    0xB3,0x8E,0x8C,0x33,0x4C,0x70,0x1C,0x3A,0xCD,0xAD,0x06,0x57,0xFC,0xCF,0xEC,0x71,
    0x9B,0x1F,0x5C,0x3E,0x4E,0x46,0x04,0x1F,0x38,0x81,0x47,0xFB,0x4C,0xFD,0xB4,0x77,
    0xA5,0x24,0x71,0xF7,0xA9,0xA9,0x69,0x10,0xB8,0x55,0x32,0x2E,0xDB,0x63,0x40,0xD8,
    0xA0,0x0E,0xF0,0x92,0x35,0x05,0x11,0xE3,0x0A,0xBE,0xC1,0xFF,0xF9,0xE3,0xA2,0x6E,
    0x7F,0xB2,0x9F,0x8C,0x18,0x30,0x23,0xC3,0x58,0x7E,0x38,0xDA,0x00,0x77,0xD9,0xB4,
    0x76,0x3E,0x4E,0x4B,0x94,0xB2,0xBB,0xC1,0x94,0xC6,0x65,0x1E,0x77,0xCA,0xF9,0x92,
    0xEE,0xAA,0xC0,0x23,0x2A,0x28,0x1B,0xF6,0xB3,0xA7,0x39,0xC1,0x22,0x61,0x16,0x82,
    0x0A,0xE8,0xDB,0x58,0x47,0xA6,0x7C,0xBE,0xF9,0xC9,0x09,0x1B,0x46,0x2D,0x53,0x8C,
    0xD7,0x2B,0x03,0x74,0x6A,0xE7,0x7F,0x5E,0x62,0x29,0x2C,0x31,0x15,0x62,0xA8,0x46,
    0x50,0x5D,0xC8,0x2D,0xB8,0x54,0x33,0x8A,0xE4,0x9F,0x52,0x35,0xC9,0x5B,0x91,0x17,
    0x8C,0xCF,0x2D,0xD5,0xCA,0xCE,0xF4,0x03,0xEC,0x9D,0x18,0x10,0xC6,0x27,0x2B,0x04,
    0x5B,0x3B,0x71,0xF9,0xDC,0x6B,0x80,0xD6,0x3F,0xDD,0x4A,0x8E,0x9A,0xDB,0x1E,0x69,
    0x62,0xA6,0x95,0x26,0xD4,0x31,0x61,0xC1,0xA4,0x1D,0x57,0x0D,0x79,0x38,0xDA,0xD4,
    0xA4,0x0E,0x32,0x9C,0xCF,0xF4,0x6A,0xAA,0x36,0xAD,0x00,0x4C,0xF6,0x00,0xC8,0x38,
    0x1E,0x42,0x5A,0x31,0xD9,0x51,0xAE,0x64,0xFD,0xB2,0x3F,0xCE,0xC9,0x50,0x9D,0x43,
    0x68,0x7F,0xEB,0x69,0xED,0xD1,0xCC,0x5E,0x0B,0x8C,0xC3,0xBD,0xF6,0x4B,0x10,0xEF,
    0x86,0xB6,0x31,0x42,0xA3,0xAB,0x88,0x29,0x55,0x5B,0x2F,0x74,0x7C,0x93,0x26,0x65,
    0xCB,0x2C,0x0F,0x1C,0xC0,0x1B,0xD7,0x02,0x29,0x38,0x88,0x39,0xD2,0xAF,0x05,0xE4,
    0x54,0x50,0x4A,0xC7,0x8B,0x75,0x82,0x82,0x28,0x46,0xC0,0xBA,0x35,0xC3,0x5F,0x5C,
    0x59,0x16,0x0C,0xC0,0x46,0xFD,0x82,0x51,0x54,0x1F,0xC6,0x8C,0x9C,0x86,0xB0,0x22,
    0xBB,0x70,0x99,0x87,0x6A,0x46,0x0E,0x74,0x51,0xA8,0xA9,0x31,0x09,0x70,0x3F,0xEE,
    0x1C,0x21,0x7E,0x6C,0x38,0x26,0xE5,0x2C,0x51,0xAA,0x69,0x1E,0x0E,0x42,0x3C,0xFC,
    0x99,0xE9,0xE3,0x16,0x50,0xC1,0x21,0x7B,0x62,0x48,0x16,0xCD,0xAD,0x9A,0x95,0xF9,
    0xD5,0xB8,0x01,0x94,0x88,0xD9,0xC0,0xA0,0xA1,0xFE,0x30,0x75,0xA5,0x77,0xE2,0x31,
    0x83,0xF8,0x1D,0x4A,0x3F,0x2F,0xA4,0x57,0x1E,0xFC,0x8C,0xE0,0xBA,0x8A,0x4F,0xE8,
    0xB6,0x85,0x5D,0xFE,0x72,0xB0,0xA6,0x6E,0xDE,0xD2,0xFB,0xAB,0xFB,0xE5,0x8A,0x30,
    0xFA,0xFA,0xBE,0x1C,0x5D,0x71,0xA8,0x7E,0x2F,0x74,0x1E,0xF8,0xC1,0xFE,0x86,0xFE,
    0xA6,0xBB,0xFD,0xE5,0x30,0x67,0x7F,0x0D,0x97,0xD1,0x1D,0x49,0xF7,0xA8,0x44,0x3D,
    0x08,0x22,0xE5,0x06,0xA9,0xF4,0x61,0x4E,0x01,0x1E,0x2A,0x94,0x83,0x8F,0xF8,0x8C,
    0xD6,0x8C,0x8B,0xB7,0xC5,0xC6,0x42,0x4C,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF
};

/* ─── DH Parameter DER/PEM Helpers ──────────────────────────────────────── */


static int der_encode_integer(uint8_t *out, const uint8_t *data, size_t len)
{
    uint8_t *p = out;

    *p++ = 0x02;  /* INTEGER tag */

    /* Add padding byte if high bit is set */
    int needs_padding = (data[0] & 0x80) ? 1 : 0;
    size_t total_len = len + needs_padding;

    if (total_len < 0x80) {
        *p++ = (uint8_t)total_len;
    } else if (total_len < 0x100) {
        *p++ = 0x81;
        *p++ = (uint8_t)total_len;
    } else {
        *p++ = 0x82;
        *p++ = (uint8_t)(total_len >> 8);
        *p++ = (uint8_t)total_len;
    }

    if (needs_padding) {
        *p++ = 0x00;
    }

    memcpy(p, data, len);
    p += len;

    return (int)(p - out);
}

static int build_pkcs3_der(uint8_t *out, const uint8_t *prime, size_t prime_len)
{
    uint8_t generator = 2;
    uint8_t *p = out;

    uint8_t prime_der[1100], gen_der[10];
    int prime_der_len = der_encode_integer(prime_der, prime, prime_len);
    int gen_der_len = der_encode_integer(gen_der, &generator, 1);

    /* SEQUENCE tag */
    *p++ = 0x30;

    /* Total content length */
    size_t content_len = prime_der_len + gen_der_len;
    if (content_len < 0x80) {
        *p++ = (uint8_t)content_len;
    } else if (content_len < 0x100) {
        *p++ = 0x81;
        *p++ = (uint8_t)content_len;
    } else {
        *p++ = 0x82;
        *p++ = (uint8_t)(content_len >> 8);
        *p++ = (uint8_t)content_len;
    }

    /* Copy encoded integers */
    memcpy(p, prime_der, prime_der_len);
    p += prime_der_len;
    memcpy(p, gen_der, gen_der_len);
    p += gen_der_len;

    return (int)(p - out);
}

static void write_pem(FILE *f, const char *type, const uint8_t *der, size_t der_len)
{
    fprintf(f, "-----BEGIN %s-----\n", type);

    size_t raw_b64 = ((der_len + 2) / 3) * 4;
    size_t b64_lines = (raw_b64 + 63) / 64;
    size_t alloc_len = raw_b64 + b64_lines + 16;
    char *encoded = malloc(alloc_len);
    size_t encoded_len = alloc_len;

    if (opssl_base64_encode(der, der_len, encoded, &encoded_len)) {
        strip_newlines(encoded, &encoded_len);
        size_t pos = 0;
        while (pos < encoded_len) {
            size_t line_len = (encoded_len - pos > 64) ? 64 : (encoded_len - pos);
            fwrite(encoded + pos, 1, line_len, f);
            fprintf(f, "\n");
            pos += line_len;
        }
    }

    free(encoded);
    fprintf(f, "-----END %s-----\n", type);
}

/* ─── ASN.1 DER Builder Helpers ──────────────────────────────────────────── */

static size_t der_hdr_size(size_t content_len)
{
    if (content_len < 0x80) return 2;
    if (content_len < 0x100) return 3;
    return 4;
}

static size_t der_hdr(uint8_t *out, uint8_t tag, size_t content_len)
{
    uint8_t *p = out;
    *p++ = tag;
    if (content_len < 0x80) {
        *p++ = (uint8_t)content_len;
    } else if (content_len < 0x100) {
        *p++ = 0x81;
        *p++ = (uint8_t)content_len;
    } else {
        *p++ = 0x82;
        *p++ = (uint8_t)(content_len >> 8);
        *p++ = (uint8_t)content_len;
    }
    return (size_t)(p - out);
}

/* ─── Ed25519 / X25519 Key Encoding ─────────────────────────────────────── */

static const uint8_t oid_ed25519[] = {0x06, 0x03, 0x2B, 0x65, 0x70};
static const uint8_t oid_x25519[]  = {0x06, 0x03, 0x2B, 0x65, 0x6E};

static size_t build_ed25519_pkcs8(uint8_t out[48], const uint8_t seed[32])
{
    /* SEQUENCE {
     *   INTEGER 0,
     *   SEQUENCE { OID 1.3.101.112 },
     *   OCTET STRING { OCTET STRING { 32-byte seed } }
     * }
     * Total: 2 + 3 + 7 + 36 = 48 bytes
     */
    uint8_t *p = out;
    *p++ = 0x30; *p++ = 0x2E;           /* SEQUENCE, 46 bytes */
    *p++ = 0x02; *p++ = 0x01; *p++ = 0x00; /* INTEGER 0 */
    *p++ = 0x30; *p++ = 0x05;           /* SEQUENCE, 5 bytes */
    memcpy(p, oid_ed25519, 5); p += 5;  /* OID ed25519 */
    *p++ = 0x04; *p++ = 0x22;           /* OCTET STRING, 34 bytes */
    *p++ = 0x04; *p++ = 0x20;           /* OCTET STRING, 32 bytes */
    memcpy(p, seed, 32); p += 32;
    return 48;
}

static size_t build_x25519_pkcs8(uint8_t out[48], const uint8_t priv[32])
{
    uint8_t *p = out;
    *p++ = 0x30; *p++ = 0x2E;
    *p++ = 0x02; *p++ = 0x01; *p++ = 0x00;
    *p++ = 0x30; *p++ = 0x05;
    memcpy(p, oid_x25519, 5); p += 5;
    *p++ = 0x04; *p++ = 0x22;
    *p++ = 0x04; *p++ = 0x20;
    memcpy(p, priv, 32); p += 32;
    return 48;
}

static size_t build_ed25519_spki(uint8_t out[44], const uint8_t pub[32])
{
    /* SEQUENCE { SEQUENCE { OID ed25519 }, BIT STRING { 00 || pub } } */
    uint8_t *p = out;
    *p++ = 0x30; *p++ = 0x2A;           /* SEQUENCE, 42 bytes */
    *p++ = 0x30; *p++ = 0x05;           /* SEQUENCE, 5 bytes */
    memcpy(p, oid_ed25519, 5); p += 5;  /* OID */
    *p++ = 0x03; *p++ = 0x21;           /* BIT STRING, 33 bytes */
    *p++ = 0x00;                         /* unused bits = 0 */
    memcpy(p, pub, 32); p += 32;
    return 44;
}

/* ─── X.509 Certificate Builder ──────────────────────────────────────────── */

static const uint8_t alg_ed25519[] = {0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70};

static size_t build_x509_name(uint8_t *out, const char *cn)
{
    size_t cn_len = strlen(cn);

    /* OID 2.5.4.3 (commonName) */
    static const uint8_t oid_cn[] = {0x06, 0x03, 0x55, 0x04, 0x03};

    /* UTF8String { cn } */
    uint8_t utf8_hdr[4];
    size_t utf8_hdr_len = der_hdr(utf8_hdr, 0x0C, cn_len);

    /* SET > SEQUENCE > OID + UTF8String */
    size_t attr_val_len = sizeof(oid_cn) + utf8_hdr_len + cn_len;
    size_t seq_len = der_hdr_size(attr_val_len) + attr_val_len;
    size_t set_len = der_hdr_size(seq_len) + seq_len;
    size_t name_len = der_hdr_size(set_len) + set_len;

    uint8_t *p = out;
    p += der_hdr(p, 0x30, set_len);                /* Name SEQUENCE */
    p += der_hdr(p, 0x31, seq_len);                /* SET */
    p += der_hdr(p, 0x30, attr_val_len);           /* SEQUENCE */
    memcpy(p, oid_cn, sizeof(oid_cn)); p += sizeof(oid_cn);
    p += der_hdr(p, 0x0C, cn_len);                 /* UTF8String */
    memcpy(p, cn, cn_len); p += cn_len;

    return name_len;
}

static size_t build_utctime(uint8_t *out, time_t t)
{
    struct tm *tm = gmtime(&t);
    char buf[14];
    snprintf(buf, sizeof(buf), "%02d%02d%02d%02d%02d%02dZ",
             tm->tm_year % 100, tm->tm_mon + 1, tm->tm_mday,
             tm->tm_hour, tm->tm_min, tm->tm_sec);
    out[0] = 0x17;
    out[1] = 13;
    memcpy(out + 2, buf, 13);
    return 15;
}

static int build_selfsigned_ed25519(uint8_t *out, size_t out_max, size_t *out_len,
                                    const char *cn, int days,
                                    const uint8_t pk[32], const uint8_t sk[64])
{
    uint8_t tbs[2048];
    uint8_t *p = tbs;

    /* version: [0] EXPLICIT INTEGER 2 (v3) */
    static const uint8_t version_v3[] = {0xA0, 0x03, 0x02, 0x01, 0x02};
    memcpy(p, version_v3, 5); p += 5;

    /* serialNumber: random 16 bytes */
    uint8_t serial_bytes[16];
    opssl_random_bytes(serial_bytes, sizeof(serial_bytes));
    serial_bytes[0] &= 0x7F;
    *p++ = 0x02; *p++ = 16;
    memcpy(p, serial_bytes, 16); p += 16;

    /* signature algorithm: Ed25519 */
    memcpy(p, alg_ed25519, sizeof(alg_ed25519)); p += sizeof(alg_ed25519);

    /* issuer = subject */
    uint8_t name_der[512];
    size_t name_len = build_x509_name(name_der, cn);
    memcpy(p, name_der, name_len); p += name_len;

    /* validity */
    time_t now = time(NULL);
    time_t exp = now + (time_t)days * 86400;
    uint8_t validity[40];
    uint8_t *vp = validity;
    size_t not_before_len = build_utctime(vp, now);
    vp += not_before_len;
    size_t not_after_len = build_utctime(vp, exp);
    vp += not_after_len;
    size_t validity_content = not_before_len + not_after_len;
    p += der_hdr(p, 0x30, validity_content);
    memcpy(p, validity, validity_content); p += validity_content;

    /* subject */
    memcpy(p, name_der, name_len); p += name_len;

    /* subjectPublicKeyInfo */
    uint8_t spki[44];
    build_ed25519_spki(spki, pk);
    memcpy(p, spki, 44); p += 44;

    size_t tbs_content_len = (size_t)(p - tbs);

    /* Wrap TBSCertificate in SEQUENCE */
    uint8_t tbs_seq[2048];
    size_t tbs_hdr_len = der_hdr(tbs_seq, 0x30, tbs_content_len);
    memcpy(tbs_seq + tbs_hdr_len, tbs, tbs_content_len);
    size_t tbs_total = tbs_hdr_len + tbs_content_len;

    /* Sign TBSCertificate (Ed25519 signs raw DER, no pre-hash) */
    uint8_t sig[64];
    if (opssl_ed25519_sign(sig, tbs_seq, tbs_total, sk) != 1)
        return 0;

    /* Build Certificate SEQUENCE */
    /* signatureAlgorithm */
    /* signatureValue BIT STRING: 0x03, len, 0x00, sig[64] */
    size_t sig_bs_len = 1 + 64;
    size_t cert_content = tbs_total + sizeof(alg_ed25519) +
                          der_hdr_size(sig_bs_len) + sig_bs_len;

    if (der_hdr_size(cert_content) + cert_content > out_max)
        return 0;

    uint8_t *op = out;
    op += der_hdr(op, 0x30, cert_content);
    memcpy(op, tbs_seq, tbs_total); op += tbs_total;
    memcpy(op, alg_ed25519, sizeof(alg_ed25519)); op += sizeof(alg_ed25519);
    op += der_hdr(op, 0x03, sig_bs_len);
    *op++ = 0x00;
    memcpy(op, sig, 64); op += 64;

    *out_len = (size_t)(op - out);
    return 1;
}

/* ─── Command Implementation ─────────────────────────────────────────────── */

static int cmd_version(int argc, char **argv)
{
    (void)argc; (void)argv;
    printf("opssl unified CLI\n");
    printf("Version: %s\n", opssl_version_string());
    return 0;
}

static int cmd_dgst(int argc, char **argv)
{
    const char *algo = "sha256";
    int first_file = 1;

    for (int i = 1; i < argc; i++) {
        if (argv[i][0] != '-') { first_file = i; break; }
        if (strcmp(argv[i], "-sha1") == 0) algo = "sha1";
        else if (strcmp(argv[i], "-sha256") == 0) algo = "sha256";
        else if (strcmp(argv[i], "-sha384") == 0) algo = "sha384";
        else if (strcmp(argv[i], "-sha512") == 0) algo = "sha512";
        else if (strcmp(argv[i], "-sha3-256") == 0) algo = "sha3-256";
        else if (strcmp(argv[i], "-sha3-512") == 0) algo = "sha3-512";
        else {
            fprintf(stderr, "Usage: opssl dgst [-sha1|-sha256|-sha384|-sha512|-sha3-256|-sha3-512] [file...]\n");
            return 1;
        }
        first_file = i + 1;
    }

    uint8_t digest[64];
    size_t digest_len = 0;

    if (strcmp(algo, "sha1") == 0) digest_len = OPSSL_SHA1_DIGEST_LEN;
    else if (strcmp(algo, "sha256") == 0) digest_len = OPSSL_SHA256_DIGEST_LEN;
    else if (strcmp(algo, "sha384") == 0) digest_len = OPSSL_SHA384_DIGEST_LEN;
    else if (strcmp(algo, "sha512") == 0) digest_len = OPSSL_SHA512_DIGEST_LEN;
    else if (strcmp(algo, "sha3-256") == 0) digest_len = OPSSL_SHA3_256_DIGEST_LEN;
    else if (strcmp(algo, "sha3-512") == 0) digest_len = OPSSL_SHA3_512_DIGEST_LEN;

    int file_count = argc - first_file;
    char **files = argv + first_file;

    if (file_count == 0) {
        /* Read from stdin */
        char *data = malloc(BUFFER_SIZE);
        size_t capacity = BUFFER_SIZE, total = 0;
        uint8_t buffer[BUFFER_SIZE];

        size_t bytes;
        while ((bytes = fread(buffer, 1, sizeof(buffer), stdin)) > 0) {
            if (total + bytes > capacity) {
                capacity *= 2;
                data = realloc(data, capacity);
            }
            memcpy(data + total, buffer, bytes);
            total += bytes;
        }

        if (strcmp(algo, "sha1") == 0) {
            opssl_sha1(data, total, digest);
        } else if (strcmp(algo, "sha256") == 0) {
            opssl_sha256(data, total, digest);
        } else if (strcmp(algo, "sha384") == 0) {
            opssl_sha384(data, total, digest);
        } else if (strcmp(algo, "sha512") == 0) {
            opssl_sha512(data, total, digest);
        } else if (strcmp(algo, "sha3-256") == 0) {
            opssl_sha3_256(data, total, digest);
        } else if (strcmp(algo, "sha3-512") == 0) {
            opssl_sha3_512(data, total, digest);
        }

        printf("%s(stdin)= ", algo);
        print_hex(digest, digest_len);
        printf("\n");
        free(data);
    } else {
        for (int i = 0; i < file_count; i++) {
            size_t file_len;
            char *data = read_file_to_string(files[i], &file_len);
            if (!data) {
                fprintf(stderr, "Error reading file %s\n", files[i]);
                continue;
            }

            if (strcmp(algo, "sha1") == 0) {
                opssl_sha1(data, file_len, digest);
            } else if (strcmp(algo, "sha256") == 0) {
                opssl_sha256(data, file_len, digest);
            } else if (strcmp(algo, "sha384") == 0) {
                opssl_sha384(data, file_len, digest);
            } else if (strcmp(algo, "sha512") == 0) {
                opssl_sha512(data, file_len, digest);
            } else if (strcmp(algo, "sha3-256") == 0) {
                opssl_sha3_256(data, file_len, digest);
            } else if (strcmp(algo, "sha3-512") == 0) {
                opssl_sha3_512(data, file_len, digest);
            }

            printf("%s(%s)= ", algo, files[i]);
            print_hex(digest, digest_len);
            printf("\n");

            free(data);
        }
    }

    return 0;
}

static int cmd_rand(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "Usage: opssl rand <num_bytes>\n");
        return 1;
    }

    int num_bytes = atoi(argv[1]);
    if (num_bytes <= 0 || num_bytes > 65536) {
        fprintf(stderr, "Error: invalid number of bytes (1-65536)\n");
        return 1;
    }

    uint8_t *random_data = malloc(num_bytes);
    if (!random_data) {
        fprintf(stderr, "Error: memory allocation failed\n");
        return 1;
    }

    if (opssl_random_bytes(random_data, num_bytes) != 0) {
        fprintf(stderr, "Error: failed to generate random bytes\n");
        free(random_data);
        return 1;
    }

    print_hex(random_data, num_bytes);
    printf("\n");

    free(random_data);
    return 0;
}

static int cmd_base64(int argc, char **argv)
{
    int opt;
    int decode = 0;
    const char *input_file = NULL, *output_file = NULL;

    optind = 1;
    while ((opt = getopt(argc, argv, "di:o:")) != -1) {
        switch (opt) {
            case 'd': decode = 1; break;
            case 'i': input_file = optarg; break;
            case 'o': output_file = optarg; break;
            default:
                fprintf(stderr, "Usage: opssl base64 [-d] [-i file] [-o file]\n");
                return 1;
        }
    }

    FILE *in = safe_fopen(input_file, "rb");
    FILE *out = safe_fopen(output_file, "wb");

    if (!in || !out) {
        fprintf(stderr, "Error opening files\n");
        return 1;
    }

    uint8_t buffer[BUFFER_SIZE];
    size_t bytes_read;

    if (decode) {
        /* Read all input */
        size_t total = 0;
        char *input_data = malloc(BUFFER_SIZE);
        size_t capacity = BUFFER_SIZE;

        while ((bytes_read = fread(buffer, 1, sizeof(buffer), in)) > 0) {
            if (total + bytes_read > capacity) {
                capacity *= 2;
                input_data = realloc(input_data, capacity);
            }
            memcpy(input_data + total, buffer, bytes_read);
            total += bytes_read;
        }

        input_data[total] = '\0';

        uint8_t *decoded = malloc(total);
        size_t decoded_len = total;

        if (opssl_base64_decode(input_data, total, decoded, &decoded_len)) {
            fwrite(decoded, 1, decoded_len, out);
        } else {
            fprintf(stderr, "Error: invalid base64 input\n");
        }

        free(decoded);
        free(input_data);
    } else {
        /* Encode */
        while ((bytes_read = fread(buffer, 1, sizeof(buffer), in)) > 0) {
            size_t raw_b64 = ((bytes_read + 2) / 3) * 4;
            size_t encoded_len = raw_b64 + (raw_b64 / 64) + 2;
            char *encoded = malloc(encoded_len);

            if (opssl_base64_encode(buffer, bytes_read, encoded, &encoded_len)) {
                fwrite(encoded, 1, encoded_len, out);
            }
            free(encoded);
        }
    }

    safe_fclose(in);
    safe_fclose(out);
    return 0;
}

static int cmd_shake(int argc, char **argv)
{
    int opt;
    int bits = 128;
    int length = 32;

    optind = 1;
    while ((opt = getopt(argc, argv, "12l:")) != -1) {
        switch (opt) {
            case '1': bits = 128; break;
            case '2': bits = 256; break;
            case 'l': length = atoi(optarg); break;
            default:
                fprintf(stderr, "Usage: opssl shake [-1|-2] [-l num] [file...]\n");
                return 1;
        }
    }

    if (length <= 0 || length > 8192) {
        fprintf(stderr, "Error: invalid output length\n");
        return 1;
    }

    uint8_t *output = malloc(length);
    if (!output) {
        fprintf(stderr, "Error: memory allocation failed\n");
        return 1;
    }

    if (optind >= argc) {
        /* Read from stdin */
        char *data = malloc(BUFFER_SIZE);
        size_t capacity = BUFFER_SIZE, total = 0;
        uint8_t buffer[BUFFER_SIZE];

        size_t bytes;
        while ((bytes = fread(buffer, 1, sizeof(buffer), stdin)) > 0) {
            if (total + bytes > capacity) {
                capacity *= 2;
                data = realloc(data, capacity);
            }
            memcpy(data + total, buffer, bytes);
            total += bytes;
        }

        if (bits == 128) {
            opssl_shake128(output, length, (uint8_t*)data, total);
        } else {
            opssl_shake256(output, length, (uint8_t*)data, total);
        }

        print_hex(output, length);
        printf("\n");
        free(data);
    } else {
        /* Process files */
        for (int i = optind; i < argc; i++) {
            size_t file_len;
            char *data = read_file_to_string(argv[i], &file_len);
            if (!data) continue;

            if (bits == 128) {
                opssl_shake128(output, length, (uint8_t*)data, file_len);
            } else {
                opssl_shake256(output, length, (uint8_t*)data, file_len);
            }

            printf("SHAKE%d(%s)= ", bits, argv[i]);
            print_hex(output, length);
            printf("\n");
            free(data);
        }
    }

    free(output);
    return 0;
}

static int cmd_hmac(int argc, char **argv)
{
    int opt;
    const char *algo_str = "sha256";
    const char *key_hex = NULL;
    opssl_hmac_algo_t algo = OPSSL_HMAC_SHA256;

    optind = 1;
    while ((opt = getopt(argc, argv, "k:a:")) != -1) {
        switch (opt) {
            case 'k': key_hex = optarg; break;
            case 'a': algo_str = optarg; break;
            default:
                fprintf(stderr, "Usage: opssl hmac [-a sha1|sha256|sha384|sha512] -k hex_key [file...]\n");
                return 1;
        }
    }

    if (strcmp(algo_str, "sha1") == 0) algo = OPSSL_HMAC_SHA1;
    else if (strcmp(algo_str, "sha256") == 0) algo = OPSSL_HMAC_SHA256;
    else if (strcmp(algo_str, "sha384") == 0) algo = OPSSL_HMAC_SHA384;
    else if (strcmp(algo_str, "sha512") == 0) algo = OPSSL_HMAC_SHA512;

    if (!key_hex) {
        fprintf(stderr, "Error: key required\n");
        return 1;
    }

    uint8_t key[64];
    int key_len = hex_to_bytes(key_hex, key, sizeof(key));
    if (key_len == 0) {
        fprintf(stderr, "Error: invalid key format\n");
        return 1;
    }

    uint8_t hmac[64];
    size_t hmac_len = sizeof(hmac);

    if (optind >= argc) {
        /* Read from stdin */
        char *data = malloc(BUFFER_SIZE);
        size_t capacity = BUFFER_SIZE, total = 0;
        uint8_t buffer[BUFFER_SIZE];

        size_t bytes;
        while ((bytes = fread(buffer, 1, sizeof(buffer), stdin)) > 0) {
            if (total + bytes > capacity) {
                capacity *= 2;
                data = realloc(data, capacity);
            }
            memcpy(data + total, buffer, bytes);
            total += bytes;
        }

        if (opssl_hmac(algo, key, key_len, data, total, hmac, &hmac_len)) {
            print_hex(hmac, hmac_len);
            printf("\n");
        }
        free(data);
    } else {
        /* Process files */
        for (int i = optind; i < argc; i++) {
            size_t file_len;
            char *data = read_file_to_string(argv[i], &file_len);
            if (!data) continue;

            hmac_len = sizeof(hmac);
            if (opssl_hmac(algo, key, key_len, data, file_len, hmac, &hmac_len)) {
                printf("%s: ", argv[i]);
                print_hex(hmac, hmac_len);
                printf("\n");
            }
            free(data);
        }
    }

    return 0;
}

static opssl_aead_algo_t parse_cipher(const char *name)
{
    if (strcmp(name, "aes-128-gcm") == 0) return OPSSL_AEAD_AES_128_GCM;
    if (strcmp(name, "aes-256-gcm") == 0) return OPSSL_AEAD_AES_256_GCM;
    if (strcmp(name, "chacha20-poly1305") == 0) return OPSSL_AEAD_CHACHA20_POLY1305;
    if (strcmp(name, "aes-128-ccm") == 0) return OPSSL_AEAD_AES_128_CCM;
    if (strcmp(name, "aes-256-ccm") == 0) return OPSSL_AEAD_AES_256_CCM;
    if (strcmp(name, "camellia-128-gcm") == 0) return OPSSL_AEAD_CAMELLIA_128_GCM;
    if (strcmp(name, "camellia-256-gcm") == 0) return OPSSL_AEAD_CAMELLIA_256_GCM;
    return (opssl_aead_algo_t)-1;
}

static int cmd_enc(int argc, char **argv)
{
    int decode = 0;
    const char *cipher_name = "aes-256-gcm";
    const char *key_hex = NULL;
    const char *iv_hex = NULL;
    const char *aad_hex = NULL;
    const char *input_file = NULL;
    const char *output_file = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-d") == 0) {
            decode = 1;
        } else if (strcmp(argv[i], "-cipher") == 0 && i + 1 < argc) {
            cipher_name = argv[++i];
        } else if (strcmp(argv[i], "-k") == 0 && i + 1 < argc) {
            key_hex = argv[++i];
        } else if (strcmp(argv[i], "-iv") == 0 && i + 1 < argc) {
            iv_hex = argv[++i];
        } else if (strcmp(argv[i], "-aad") == 0 && i + 1 < argc) {
            aad_hex = argv[++i];
        } else if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
            input_file = argv[++i];
        } else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            output_file = argv[++i];
        } else {
            fprintf(stderr, "Usage: opssl enc [-d] -cipher NAME -k HEX_KEY -iv HEX_NONCE [-aad HEX_AAD] [-i FILE] [-o FILE]\n"
                            "Ciphers: aes-128-gcm, aes-256-gcm, chacha20-poly1305, camellia-128-gcm, camellia-256-gcm, aes-128-ccm, aes-256-ccm\n");
            return 1;
        }
    }

    if (!key_hex || !iv_hex) {
        fprintf(stderr, "Error: -k and -iv are required\n");
        return 1;
    }

    opssl_aead_algo_t algo = parse_cipher(cipher_name);
    if (algo == (opssl_aead_algo_t)-1) {
        fprintf(stderr, "Error: unsupported cipher\n");
        return 1;
    }

    /* Parse key and nonce */
    uint8_t key[32], nonce[12], aad[256];
    int key_len = hex_to_bytes(key_hex, key, sizeof(key));
    int nonce_len = hex_to_bytes(iv_hex, nonce, sizeof(nonce));
    int aad_len = aad_hex ? hex_to_bytes(aad_hex, aad, sizeof(aad)) : 0;

    if (key_len != (int)opssl_aead_key_len(algo) || nonce_len != (int)opssl_aead_nonce_len(algo)) {
        fprintf(stderr, "Error: invalid key or nonce length\n");
        return 1;
    }

    opssl_aead_ctx_t *ctx = opssl_aead_new(algo);
    if (!ctx || opssl_aead_set_key(ctx, key, key_len) != 1) {
        fprintf(stderr, "Error: failed to initialize cipher\n");
        opssl_aead_free(ctx);
        return 1;
    }

    FILE *in = safe_fopen(input_file, "rb");
    FILE *out = safe_fopen(output_file, "wb");

    if (!in || !out) {
        fprintf(stderr, "Error opening files\n");
        opssl_aead_free(ctx);
        return 1;
    }

    /* Read input */
    size_t input_len = 0, input_cap = BUFFER_SIZE;
    uint8_t *input_data = malloc(input_cap);
    uint8_t buffer[BUFFER_SIZE];
    size_t bytes;

    while ((bytes = fread(buffer, 1, sizeof(buffer), in)) > 0) {
        if (input_len + bytes > input_cap) {
            input_cap *= 2;
            input_data = realloc(input_data, input_cap);
        }
        memcpy(input_data + input_len, buffer, bytes);
        input_len += bytes;
    }

    if (decode) {
        /* Decrypt: split nonce || ciphertext+tag */
        if (input_len < nonce_len + opssl_aead_tag_len(algo)) {
            fprintf(stderr, "Error: input too short\n");
            free(input_data);
            opssl_aead_free(ctx);
            safe_fclose(in);
            safe_fclose(out);
            return 1;
        }

        memcpy(nonce, input_data, nonce_len);
        size_t ct_len = input_len - nonce_len;
        uint8_t *output_data = malloc(ct_len);
        size_t output_len = ct_len;

        if (opssl_aead_open(ctx, output_data, &output_len, ct_len,
                           nonce, nonce_len,
                           input_data + nonce_len, ct_len,
                           aad_len ? aad : NULL, aad_len) == 1) {
            fwrite(output_data, 1, output_len, out);
        } else {
            fprintf(stderr, "Error: decryption failed\n");
        }
        free(output_data);
    } else {
        /* Encrypt: output nonce || ciphertext+tag */
        size_t max_out = input_len + opssl_aead_tag_len(algo);
        uint8_t *output_data = malloc(max_out);
        size_t output_len = max_out;

        fwrite(nonce, 1, nonce_len, out);

        if (opssl_aead_seal(ctx, output_data, &output_len, max_out,
                           nonce, nonce_len,
                           input_data, input_len,
                           aad_len ? aad : NULL, aad_len) == 1) {
            fwrite(output_data, 1, output_len, out);
        } else {
            fprintf(stderr, "Error: encryption failed\n");
        }
        free(output_data);
    }

    free(input_data);
    opssl_aead_free(ctx);
    safe_fclose(in);
    safe_fclose(out);
    return 0;
}

static int cmd_dhparam(int argc, char **argv)
{
    int bits = 2048;
    const char *output_file = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-bits") == 0 && i + 1 < argc) {
            bits = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-out") == 0 && i + 1 < argc) {
            output_file = argv[++i];
        }
    }

    if (bits != 2048 && bits != 3072 && bits != 4096 &&
        bits != 6144 && bits != 8192) {
        fprintf(stderr, "Usage: opssl dhparam -bits 2048|3072|4096|6144|8192 [-out file]\n");
        return 1;
    }

    const unsigned char *prime;
    size_t prime_len;

    switch (bits) {
        case 2048: prime = prime_2048; prime_len = sizeof(prime_2048); break;
        case 3072: prime = prime_3072; prime_len = sizeof(prime_3072); break;
        case 4096: prime = prime_4096; prime_len = sizeof(prime_4096); break;
        case 6144: prime = prime_6144; prime_len = sizeof(prime_6144); break;
        case 8192: prime = prime_8192; prime_len = sizeof(prime_8192); break;
        default: return 1;
    }

    uint8_t der[1200];
    int der_len = build_pkcs3_der(der, prime, prime_len);

    FILE *out = safe_fopen(output_file, "w");
    if (!out) {
        fprintf(stderr, "Error opening output file\n");
        return 1;
    }

    write_pem(out, "DH PARAMETERS", der, der_len);
    safe_fclose(out);
    return 0;
}

static opssl_fingerprint_method_t parse_fp_method(const char *method)
{
    if (strcmp(method, "sha1") == 0) return OPSSL_FP_SHA1;
    if (strcmp(method, "sha256") == 0) return OPSSL_FP_SHA256;
    if (strcmp(method, "sha512") == 0) return OPSSL_FP_SHA512;
    if (strcmp(method, "sha3-256") == 0) return OPSSL_FP_SHA3_256;
    if (strcmp(method, "sha3-512") == 0) return OPSSL_FP_SHA3_512;
    if (strcmp(method, "spki-sha256") == 0) return OPSSL_FP_SPKI_SHA256;
    if (strcmp(method, "spki-sha512") == 0) return OPSSL_FP_SPKI_SHA512;
    if (strcmp(method, "spki-sha3-256") == 0) return OPSSL_FP_SPKI_SHA3_256;
    if (strcmp(method, "spki-sha3-512") == 0) return OPSSL_FP_SPKI_SHA3_512;
    return (opssl_fingerprint_method_t)-1;
}

static int cmd_fingerprint(int argc, char **argv)
{
    const char *method = "sha256";
    const char *cert_file = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-method") == 0 && i + 1 < argc) {
            method = argv[++i];
        } else if (argv[i][0] != '-') {
            cert_file = argv[i];
        }
    }

    if (!cert_file) {
        fprintf(stderr, "Usage: opssl fingerprint [-method METHOD] cert.pem\n");
        return 1;
    }
    opssl_fingerprint_method_t fp_method = parse_fp_method(method);
    if (fp_method == (opssl_fingerprint_method_t)-1) {
        fprintf(stderr, "Error: invalid fingerprint method\n");
        return 1;
    }

    opssl_x509_t *cert = opssl_x509_from_file(cert_file);
    if (!cert) {
        fprintf(stderr, "Error: failed to load certificate\n");
        return 1;
    }

    char fp_hex[200];
    if (opssl_x509_fingerprint_hex(cert, fp_method, fp_hex, sizeof(fp_hex)) == 1) {
        printf("%s\n", fp_hex);
    } else {
        fprintf(stderr, "Error: failed to compute fingerprint\n");
    }

    opssl_x509_free(cert);
    return 0;
}

static int cmd_verify(int argc, char **argv)
{
    const char *ca_file = NULL;
    const char *hostname = NULL;
    const char *chain_file = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-CAfile") == 0 && i + 1 < argc) {
            ca_file = argv[++i];
        } else if (strcmp(argv[i], "-hostname") == 0 && i + 1 < argc) {
            hostname = argv[++i];
        } else if (argv[i][0] != '-') {
            chain_file = argv[i];
        }
    }

    if (!ca_file || !chain_file) {
        fprintf(stderr, "Usage: opssl verify -CAfile store.pem [-hostname name] chain.pem\n");
        return 1;
    }

    opssl_x509_store_t *store = opssl_x509_store_new();
    if (!store || opssl_x509_store_load_file(store, ca_file) <= 0) {
        fprintf(stderr, "Error: failed to load CA store\n");
        return 1;
    }

    opssl_x509_chain_t *chain = opssl_x509_chain_from_file(chain_file);
    if (!chain) {
        fprintf(stderr, "Error: failed to load certificate chain\n");
        opssl_x509_store_free(store);
        return 1;
    }

    opssl_x509_verify_result_t result;
    int verify_result = opssl_x509_verify(chain, store, hostname, &result);

    if (verify_result == 1) {
        printf("Verification: OK\n");
    } else {
        printf("Verification failed: %s (code=%d)\n",
               result.error_string ? result.error_string : "unknown error",
               result.error_code);
    }

    opssl_x509_chain_free(chain);
    opssl_x509_store_free(store);
    return verify_result == 1 ? 0 : 1;
}

static int cmd_x509(int argc, char **argv)
{
    int show_subject = 0, show_issuer = 0, show_serial = 0;
    int show_dates = 0, show_fingerprint = 0;

    for (int i = 1; i < argc - 1; i++) {
        if (strcmp(argv[i], "-subject") == 0) show_subject = 1;
        else if (strcmp(argv[i], "-issuer") == 0) show_issuer = 1;
        else if (strcmp(argv[i], "-serial") == 0) show_serial = 1;
        else if (strcmp(argv[i], "-dates") == 0) show_dates = 1;
        else if (strcmp(argv[i], "-fingerprint") == 0) show_fingerprint = 1;
    }

    if (argc < 2) {
        fprintf(stderr, "Usage: opssl x509 [-subject] [-issuer] [-serial] [-dates] [-fingerprint] FILE\n");
        return 1;
    }

    const char *cert_file = argv[argc-1];
    opssl_x509_t *cert = opssl_x509_from_file(cert_file);
    if (!cert) {
        fprintf(stderr, "Error: failed to load certificate\n");
        return 1;
    }

    if (show_subject || (!show_issuer && !show_serial && !show_dates && !show_fingerprint)) {
        char subject[500];
        if (opssl_x509_get_subject(cert, subject, sizeof(subject)) == 1) {
            printf("Subject: %s\n", subject);
        }
    }

    if (show_issuer) {
        char issuer[500];
        if (opssl_x509_get_issuer(cert, issuer, sizeof(issuer)) == 1) {
            printf("Issuer: %s\n", issuer);
        }
    }

    if (show_serial) {
        uint8_t serial[32];
        size_t serial_len = sizeof(serial);
        if (opssl_x509_get_serial(cert, serial, &serial_len) == 1) {
            printf("Serial: ");
            print_hex(serial, serial_len);
            printf("\n");
        }
    }

    if (show_dates) {
        int64_t not_before, not_after;
        if (opssl_x509_get_not_before(cert, &not_before) == 1) {
            printf("Not Before: %lld\n", (long long)not_before);
        }
        if (opssl_x509_get_not_after(cert, &not_after) == 1) {
            printf("Not After: %lld\n", (long long)not_after);
        }
    }

    if (show_fingerprint) {
        char fp_hex[100];
        if (opssl_x509_fingerprint_hex(cert, OPSSL_FP_SHA256, fp_hex, sizeof(fp_hex)) == 1) {
            printf("SHA256 Fingerprint: %s\n", fp_hex);
        }
    }

    opssl_x509_free(cert);
    return 0;
}

static int cmd_verifier(int argc, char **argv)
{
    int sha256 = 0, sha512 = 0;
    int iterations = 4096;
    const char *password = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-256") == 0) sha256 = 1;
        else if (strcmp(argv[i], "-512") == 0) sha512 = 1;
        else if (strcmp(argv[i], "-i") == 0 && i+1 < argc) iterations = atoi(argv[++i]);
        else if (strcmp(argv[i], "-p") == 0 && i+1 < argc) password = argv[++i];
    }

    if (!password) {
        fprintf(stderr, "Usage: opssl verifier [-256] [-512] [-i ITERATIONS] -p PASSWORD\n");
        return 1;
    }

    if (!sha256 && !sha512) {
        sha256 = sha512 = 1;
    }

    uint8_t salt[16];
    if (opssl_random_bytes(salt, sizeof(salt)) != 0) {
        fprintf(stderr, "Error: failed to generate salt\n");
        return 1;
    }

    char salt_b64[48];
    size_t salt_b64_len = sizeof(salt_b64);
    opssl_base64_encode(salt, sizeof(salt), salt_b64, &salt_b64_len);
    strip_newlines(salt_b64, &salt_b64_len);

    if (sha256) {
        uint8_t salted_pass[32], client_key[32], stored_key[32], server_key[32];
        size_t hmac_len = 32;

        opssl_pbkdf2(OPSSL_HMAC_SHA256, (uint8_t*)password, strlen(password),
                     salt, sizeof(salt), iterations, salted_pass, 32);

        opssl_hmac(OPSSL_HMAC_SHA256, salted_pass, 32,
                   (uint8_t*)"Client Key", 10, client_key, &hmac_len);

        opssl_sha256(client_key, 32, stored_key);

        hmac_len = 32;
        opssl_hmac(OPSSL_HMAC_SHA256, salted_pass, 32,
                   (uint8_t*)"Server Key", 10, server_key, &hmac_len);

        char stored_key_b64[64], server_key_b64[64];
        size_t stored_key_b64_len = sizeof(stored_key_b64);
        size_t server_key_b64_len = sizeof(server_key_b64);
        opssl_base64_encode(stored_key, 32, stored_key_b64, &stored_key_b64_len);
        strip_newlines(stored_key_b64, &stored_key_b64_len);
        opssl_base64_encode(server_key, 32, server_key_b64, &server_key_b64_len);
        strip_newlines(server_key_b64, &server_key_b64_len);

        printf("scram256_verifier = \"%d:%.*s$%.*s:%.*s\";\n",
               iterations,
               (int)salt_b64_len, salt_b64,
               (int)stored_key_b64_len, stored_key_b64,
               (int)server_key_b64_len, server_key_b64);
    }

    if (sha512) {
        uint8_t salted_pass[64], client_key[64], stored_key[64], server_key[64];
        size_t hmac_len = 64;

        opssl_pbkdf2(OPSSL_HMAC_SHA512, (uint8_t*)password, strlen(password),
                     salt, sizeof(salt), iterations, salted_pass, 64);

        opssl_hmac(OPSSL_HMAC_SHA512, salted_pass, 64,
                   (uint8_t*)"Client Key", 10, client_key, &hmac_len);

        opssl_sha512(client_key, 64, stored_key);

        hmac_len = 64;
        opssl_hmac(OPSSL_HMAC_SHA512, salted_pass, 64,
                   (uint8_t*)"Server Key", 10, server_key, &hmac_len);

        char stored_key_b64[128], server_key_b64[128];
        size_t stored_key_b64_len = sizeof(stored_key_b64);
        size_t server_key_b64_len = sizeof(server_key_b64);
        opssl_base64_encode(stored_key, 64, stored_key_b64, &stored_key_b64_len);
        strip_newlines(stored_key_b64, &stored_key_b64_len);
        opssl_base64_encode(server_key, 64, server_key_b64, &server_key_b64_len);
        strip_newlines(server_key_b64, &server_key_b64_len);

        printf("scram512_verifier = \"%d:%.*s$%.*s:%.*s\";\n",
               iterations,
               (int)salt_b64_len, salt_b64,
               (int)stored_key_b64_len, stored_key_b64,
               (int)server_key_b64_len, server_key_b64);
    }

    return 0;
}

/* ─── Password Hashing (mkpasswd / passwd) ──────────────────────────────── */

static int cmd_mkpasswd(int argc, char **argv)
{
    const char *algo_str = "argon2id";
    const char *password = NULL;
    uint32_t t_cost = 3;
    uint32_t m_cost = 65536;
    uint32_t parallel = 4;
    uint32_t iterations = 600000;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-a") == 0 && i + 1 < argc)
            algo_str = argv[++i];
        else if (strcmp(argv[i], "-t") == 0 && i + 1 < argc)
            t_cost = (uint32_t)atoi(argv[++i]);
        else if (strcmp(argv[i], "-m") == 0 && i + 1 < argc)
            m_cost = (uint32_t)atoi(argv[++i]);
        else if (strcmp(argv[i], "-P") == 0 && i + 1 < argc)
            parallel = (uint32_t)atoi(argv[++i]);
        else if (strcmp(argv[i], "-i") == 0 && i + 1 < argc)
            iterations = (uint32_t)atoi(argv[++i]);
        else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc)
            password = argv[++i];
        else {
            fprintf(stderr,
                "Usage: opssl mkpasswd -p PASSWORD [-a argon2id|pbkdf2-sha256|pbkdf2-sha512]\n"
                "  argon2id options:  [-t T_COST] [-m M_COST] [-P PARALLEL]\n"
                "  pbkdf2 options:    [-i ITERATIONS]\n");
            return 1;
        }
    }

    if (!password) {
        fprintf(stderr, "Error: -p PASSWORD required\n");
        return 1;
    }

    uint8_t salt[16];
    if (opssl_random_bytes(salt, sizeof(salt)) != 0) {
        fprintf(stderr, "Error: failed to generate salt\n");
        return 1;
    }

    if (strcmp(algo_str, "argon2id") == 0) {
        uint8_t hash[32];
        if (opssl_argon2id((const uint8_t *)password, strlen(password),
                           salt, sizeof(salt), t_cost, m_cost, parallel,
                           hash, sizeof(hash)) != 0) {
            fprintf(stderr, "Error: argon2id failed\n");
            return 1;
        }

        char salt_b64[48], hash_b64[64];
        size_t sb64 = sizeof(salt_b64), hb64 = sizeof(hash_b64);
        opssl_base64_encode(salt, sizeof(salt), salt_b64, &sb64);
        strip_newlines(salt_b64, &sb64);
        opssl_base64_encode(hash, sizeof(hash), hash_b64, &hb64);
        strip_newlines(hash_b64, &hb64);

        while (sb64 > 0 && salt_b64[sb64 - 1] == '=') salt_b64[--sb64] = '\0';
        while (hb64 > 0 && hash_b64[hb64 - 1] == '=') hash_b64[--hb64] = '\0';

        printf("$argon2id$v=19$m=%u,t=%u,p=%u$%s$%s\n",
               m_cost, t_cost, parallel, salt_b64, hash_b64);
    } else if (strcmp(algo_str, "pbkdf2-sha256") == 0 ||
               strcmp(algo_str, "pbkdf2-sha512") == 0) {
        int is_512 = (strcmp(algo_str, "pbkdf2-sha512") == 0);
        opssl_hmac_algo_t hmac = is_512 ? OPSSL_HMAC_SHA512 : OPSSL_HMAC_SHA256;
        size_t dklen = is_512 ? 64 : 32;
        uint8_t dk[64];

        if (opssl_pbkdf2(hmac, (const uint8_t *)password, strlen(password),
                         salt, sizeof(salt), iterations, dk, dklen) != 1) {
            fprintf(stderr, "Error: pbkdf2 failed\n");
            return 1;
        }

        char salt_b64[48], hash_b64[128];
        size_t sb64 = sizeof(salt_b64), hb64 = sizeof(hash_b64);
        opssl_base64_encode(salt, sizeof(salt), salt_b64, &sb64);
        strip_newlines(salt_b64, &sb64);
        opssl_base64_encode(dk, dklen, hash_b64, &hb64);
        strip_newlines(hash_b64, &hb64);

        printf("$%s$i=%u$%s$%s\n", algo_str, iterations, salt_b64, hash_b64);
    } else {
        fprintf(stderr, "Error: unknown algorithm '%s'\n", algo_str);
        return 1;
    }

    return 0;
}

static int cmd_passwd(int argc, char **argv)
{
    const char *password = NULL;
    const char *hash_str = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-p") == 0 && i + 1 < argc)
            password = argv[++i];
        else if (argv[i][0] != '-')
            hash_str = argv[i];
        else {
            fprintf(stderr, "Usage: opssl passwd -p PASSWORD HASH_STRING\n");
            return 1;
        }
    }

    if (!password || !hash_str) {
        fprintf(stderr, "Usage: opssl passwd -p PASSWORD HASH_STRING\n");
        return 1;
    }

    if (hash_str[0] != '$') {
        fprintf(stderr, "Error: hash must start with $\n");
        return 1;
    }

    const char *p = hash_str + 1;
    const char *sep = strchr(p, '$');
    if (!sep) { fprintf(stderr, "Error: malformed hash\n"); return 1; }

    char algo[32];
    size_t alen = (size_t)(sep - p);
    if (alen >= sizeof(algo)) { fprintf(stderr, "Error: algorithm name too long\n"); return 1; }
    memcpy(algo, p, alen);
    algo[alen] = '\0';
    p = sep + 1;

    if (strcmp(algo, "argon2id") == 0) {
        /* $argon2id$v=19$m=M,t=T,p=P$salt$hash */
        if (strncmp(p, "v=19$", 5) != 0) { fprintf(stderr, "Error: unsupported argon2 version\n"); return 1; }
        p += 5;

        uint32_t m_cost, t_cost, par;
        if (sscanf(p, "m=%u,t=%u,p=%u", &m_cost, &t_cost, &par) != 3) {
            fprintf(stderr, "Error: failed to parse argon2id parameters\n");
            return 1;
        }

        sep = strchr(p, '$');
        if (!sep) { fprintf(stderr, "Error: malformed hash\n"); return 1; }
        p = sep + 1;

        sep = strchr(p, '$');
        if (!sep) { fprintf(stderr, "Error: malformed hash\n"); return 1; }

        char salt_b64[128];
        size_t sb64 = (size_t)(sep - p);
        if (sb64 >= sizeof(salt_b64) - 4) { fprintf(stderr, "Error: salt too long\n"); return 1; }
        memcpy(salt_b64, p, sb64);
        while (sb64 % 4 != 0) salt_b64[sb64++] = '=';
        salt_b64[sb64] = '\0';

        uint8_t salt[64];
        size_t salt_len = sizeof(salt);
        if (!opssl_base64_decode(salt_b64, sb64, salt, &salt_len)) {
            fprintf(stderr, "Error: invalid salt encoding\n");
            return 1;
        }

        p = sep + 1;
        char hash_b64[256];
        size_t hb64 = strlen(p);
        if (hb64 >= sizeof(hash_b64) - 4) { fprintf(stderr, "Error: hash too long\n"); return 1; }
        memcpy(hash_b64, p, hb64);
        while (hb64 % 4 != 0) hash_b64[hb64++] = '=';
        hash_b64[hb64] = '\0';

        uint8_t expected[128];
        size_t expected_len = sizeof(expected);
        if (!opssl_base64_decode(hash_b64, hb64, expected, &expected_len)) {
            fprintf(stderr, "Error: invalid hash encoding\n");
            return 1;
        }

        int rc = opssl_argon2id_verify(
            (const uint8_t *)password, strlen(password),
            salt, salt_len, t_cost, m_cost, par,
            expected, expected_len);

        printf("%s\n", rc == 0 ? "OK" : "FAIL");
        return rc == 0 ? 0 : 1;

    } else if (strncmp(algo, "pbkdf2-sha", 10) == 0) {
        /* $pbkdf2-sha256$i=N$salt$hash */
        int is_512 = (strcmp(algo, "pbkdf2-sha512") == 0);
        opssl_hmac_algo_t hmac = is_512 ? OPSSL_HMAC_SHA512 : OPSSL_HMAC_SHA256;

        uint32_t iters;
        if (sscanf(p, "i=%u", &iters) != 1) {
            fprintf(stderr, "Error: failed to parse iterations\n");
            return 1;
        }

        sep = strchr(p, '$');
        if (!sep) { fprintf(stderr, "Error: malformed hash\n"); return 1; }
        p = sep + 1;

        sep = strchr(p, '$');
        if (!sep) { fprintf(stderr, "Error: malformed hash\n"); return 1; }

        char salt_b64[128];
        size_t sb64 = (size_t)(sep - p);
        if (sb64 >= sizeof(salt_b64)) { fprintf(stderr, "Error: salt too long\n"); return 1; }
        memcpy(salt_b64, p, sb64);
        salt_b64[sb64] = '\0';

        uint8_t salt[64];
        size_t salt_len = sizeof(salt);
        if (!opssl_base64_decode(salt_b64, sb64, salt, &salt_len)) {
            fprintf(stderr, "Error: invalid salt encoding\n");
            return 1;
        }

        p = sep + 1;
        size_t hb64 = strlen(p);
        uint8_t expected[128];
        size_t expected_len = sizeof(expected);
        if (!opssl_base64_decode(p, hb64, expected, &expected_len)) {
            fprintf(stderr, "Error: invalid hash encoding\n");
            return 1;
        }

        uint8_t dk[64];
        if (opssl_pbkdf2(hmac, (const uint8_t *)password, strlen(password),
                         salt, salt_len, iters, dk, expected_len) != 1) {
            printf("FAIL\n");
            return 1;
        }

        uint8_t diff = 0;
        for (size_t i = 0; i < expected_len; i++)
            diff |= dk[i] ^ expected[i];

        printf("%s\n", diff == 0 ? "OK" : "FAIL");
        return diff == 0 ? 0 : 1;
    } else {
        fprintf(stderr, "Error: unsupported algorithm '%s'\n", algo);
        return 1;
    }
}

/* ─── BLAKE2b ───────────────────────────────────────────────────────────── */

static int cmd_blake2b(int argc, char **argv)
{
    size_t outlen = 64;
    int first_file = argc;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-l") == 0 && i + 1 < argc) {
            outlen = (size_t)atoi(argv[++i]);
            if (outlen < 1 || outlen > 64) {
                fprintf(stderr, "Error: output length must be 1-64\n");
                return 1;
            }
        } else if (argv[i][0] != '-') {
            first_file = i;
            break;
        }
    }

    uint8_t digest[64];

    if (first_file >= argc) {
        char *data = malloc(BUFFER_SIZE);
        size_t capacity = BUFFER_SIZE, total = 0;
        uint8_t buffer[BUFFER_SIZE];
        size_t bytes;

        while ((bytes = fread(buffer, 1, sizeof(buffer), stdin)) > 0) {
            if (total + bytes > capacity) {
                capacity *= 2;
                data = realloc(data, capacity);
            }
            memcpy(data + total, buffer, bytes);
            total += bytes;
        }

        opssl_blake2b(data, total, digest, outlen);
        printf("blake2b(stdin)= ");
        print_hex(digest, outlen);
        printf("\n");
        free(data);
    } else {
        for (int i = first_file; i < argc; i++) {
            size_t file_len;
            char *data = read_file_to_string(argv[i], &file_len);
            if (!data) { fprintf(stderr, "Error reading %s\n", argv[i]); continue; }
            opssl_blake2b(data, file_len, digest, outlen);
            printf("blake2b(%s)= ", argv[i]);
            print_hex(digest, outlen);
            printf("\n");
            free(data);
        }
    }

    return 0;
}

/* ─── HKDF ──────────────────────────────────────────────────────────────── */

static int cmd_hkdf(int argc, char **argv)
{
    const char *algo_str = "sha256";
    const char *ikm_hex = NULL;
    const char *salt_hex = NULL;
    const char *info_hex = NULL;
    int length = 32;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-a") == 0 && i + 1 < argc) algo_str = argv[++i];
        else if (strcmp(argv[i], "-k") == 0 && i + 1 < argc) ikm_hex = argv[++i];
        else if (strcmp(argv[i], "-s") == 0 && i + 1 < argc) salt_hex = argv[++i];
        else if (strcmp(argv[i], "-info") == 0 && i + 1 < argc) info_hex = argv[++i];
        else if (strcmp(argv[i], "-l") == 0 && i + 1 < argc) length = atoi(argv[++i]);
        else {
            fprintf(stderr, "Usage: opssl hkdf -k IKM_HEX [-s SALT_HEX] [-info INFO_HEX] [-a sha256|sha384|sha512] [-l LENGTH]\n");
            return 1;
        }
    }

    if (!ikm_hex) {
        fprintf(stderr, "Error: -k IKM_HEX required\n");
        return 1;
    }

    opssl_hmac_algo_t algo = OPSSL_HMAC_SHA256;
    size_t prk_max = 32;
    if (strcmp(algo_str, "sha384") == 0) { algo = OPSSL_HMAC_SHA384; prk_max = 48; }
    else if (strcmp(algo_str, "sha512") == 0) { algo = OPSSL_HMAC_SHA512; prk_max = 64; }

    uint8_t ikm[256], salt_buf[256], info_buf[256];
    int ikm_len = hex_to_bytes(ikm_hex, ikm, sizeof(ikm));
    if (ikm_len == 0) { fprintf(stderr, "Error: invalid IKM hex\n"); return 1; }

    int salt_len = salt_hex ? hex_to_bytes(salt_hex, salt_buf, sizeof(salt_buf)) : 0;
    int info_len = info_hex ? hex_to_bytes(info_hex, info_buf, sizeof(info_buf)) : 0;

    uint8_t prk[64];
    size_t prk_len = prk_max;
    if (opssl_hkdf_extract(algo, salt_len ? salt_buf : NULL, salt_len,
                           ikm, ikm_len, prk, &prk_len) != 1) {
        fprintf(stderr, "Error: HKDF-Extract failed\n");
        return 1;
    }

    if (length <= 0 || length > 255 * (int)prk_len) {
        fprintf(stderr, "Error: invalid output length\n");
        return 1;
    }

    uint8_t *okm = malloc(length);
    if (opssl_hkdf_expand(algo, prk, prk_len,
                          info_len ? info_buf : NULL, info_len,
                          okm, length) != 1) {
        fprintf(stderr, "Error: HKDF-Expand failed\n");
        free(okm);
        return 1;
    }

    print_hex(okm, length);
    printf("\n");
    free(okm);
    return 0;
}

/* ─── TLS Connect (s_client equivalent) ─────────────────────────────────── */

static volatile sig_atomic_t connect_running = 1;

static void connect_sigint(int sig)
{
    (void)sig;
    connect_running = 0;
}

static const char *tls_version_name(int ver)
{
    switch (ver) {
        case 0x0303: return "TLSv1.2";
        case 0x0304: return "TLSv1.3";
        default:     return "unknown";
    }
}

static int tcp_connect(const char *host, const char *port)
{
    struct addrinfo hints = {0}, *res, *rp;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    int err = getaddrinfo(host, port, &hints, &res);
    if (err != 0) {
        fprintf(stderr, "Error: %s\n", gai_strerror(err));
        return -1;
    }

    int fd = -1;
    for (rp = res; rp; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) break;
        close(fd);
        fd = -1;
    }

    freeaddrinfo(res);

    if (fd < 0) {
        fprintf(stderr, "Error: failed to connect to %s:%s\n", host, port);
    }

    return fd;
}

static int cmd_connect(int argc, char **argv)
{
    const char *sni = NULL;
    const char *ca_file = NULL;
    int force_tls12 = 0;
    int force_tls13 = 0;
    int quiet = 0;
    int noverify = 0;
    const char *target = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-sni") == 0 && i + 1 < argc) {
            sni = argv[++i];
        } else if (strcmp(argv[i], "-CAfile") == 0 && i + 1 < argc) {
            ca_file = argv[++i];
        } else if (strcmp(argv[i], "-tls12") == 0) {
            force_tls12 = 1;
        } else if (strcmp(argv[i], "-tls13") == 0) {
            force_tls13 = 1;
        } else if (strcmp(argv[i], "-q") == 0) {
            quiet = 1;
        } else if (strcmp(argv[i], "-noverify") == 0) {
            noverify = 1;
        } else if (argv[i][0] != '-') {
            target = argv[i];
        } else {
            fprintf(stderr, "Usage: opssl connect [-sni HOST] [-CAfile FILE] [-tls12] [-tls13] [-noverify] [-q] host:port\n");
            return 1;
        }
    }

    if (!target) {
        fprintf(stderr, "Usage: opssl connect [-sni HOST] [-CAfile FILE] [-tls12] [-tls13] [-noverify] [-q] host:port\n");
        return 1;
    }

    char host[256], port[16];
    const char *colon = strrchr(target, ':');
    if (!colon || colon == target) {
        fprintf(stderr, "Error: target must be host:port\n");
        return 1;
    }

    size_t hlen = (size_t)(colon - target);
    if (hlen >= sizeof(host)) hlen = sizeof(host) - 1;
    memcpy(host, target, hlen);
    host[hlen] = '\0';
    snprintf(port, sizeof(port), "%s", colon + 1);

    if (!sni) sni = host;

    if (!quiet)
        fprintf(stderr, "Connecting to %s:%s...\n", host, port);

    int fd = tcp_connect(host, port);
    if (fd < 0) return 1;

    int min_ver = 0x0303;
    int max_ver = 0x0304;

    if (force_tls12) { min_ver = 0x0303; max_ver = 0x0303; }
    if (force_tls13) { min_ver = 0x0304; max_ver = 0x0304; }

    opssl_ctx_t *ctx = opssl_ctx_new(min_ver);
    if (!ctx) {
        fprintf(stderr, "Error: failed to create TLS context\n");
        close(fd);
        return 1;
    }

    opssl_ctx_set_max_version(ctx, max_ver);

    if (noverify) {
        opssl_ctx_set_verify(ctx, false, NULL, NULL);
    } else if (ca_file) {
        if (opssl_ctx_load_verify_locations(ctx, ca_file, NULL) != 1) {
            fprintf(stderr, "Warning: failed to load CA file %s\n", ca_file);
        }
    } else {
        opssl_ctx_load_default_verify_paths(ctx);
    }

    opssl_conn_t *conn = opssl_conn_new(ctx, fd, OPSSL_DIR_OUTBOUND);
    if (!conn) {
        fprintf(stderr, "Error: failed to create TLS connection\n");
        opssl_ctx_free(ctx);
        close(fd);
        return 1;
    }

    opssl_conn_set_sni(conn, sni);

    struct pollfd pfd = { .fd = fd, .events = POLLIN | POLLOUT };

    for (;;) {
        int rc = opssl_connect(conn);
        if (rc == OPSSL_OK_CLI) break;
        if (rc == OPSSL_WANT_READ_CLI) {
            pfd.events = POLLIN;
            poll(&pfd, 1, 10000);
        } else if (rc == OPSSL_WANT_WRITE_CLI) {
            pfd.events = POLLOUT;
            poll(&pfd, 1, 10000);
        } else {
            const char *err = opssl_conn_get_error_string(conn);
            fprintf(stderr, "Error: TLS handshake failed: %s\n", err ? err : "unknown");
            opssl_conn_free(conn);
            opssl_ctx_free(ctx);
            close(fd);
            return 1;
        }
    }

    if (!quiet) {
        int ver = opssl_conn_version(conn);
        const char *cipher = opssl_conn_cipher_name(conn);
        fprintf(stderr, "---\n");
        fprintf(stderr, "Protocol: %s\n", tls_version_name(ver));
        fprintf(stderr, "Cipher:   %s\n", cipher ? cipher : "unknown");
        fprintf(stderr, "SNI:      %s\n", sni);

        opssl_x509_t *peer = opssl_conn_get_peer_cert(conn);
        if (peer) {
            char fp_hex[200];
            if (opssl_x509_fingerprint_hex(peer, OPSSL_FP_SHA256, fp_hex, sizeof(fp_hex)) == 1)
                fprintf(stderr, "Peer SHA256: %s\n", fp_hex);

            char subject[500];
            if (opssl_x509_get_subject(peer, subject, sizeof(subject)) == 1)
                fprintf(stderr, "Subject:  %s\n", subject);

            opssl_x509_free(peer);
        }

        fprintf(stderr, "---\n");
    }

    struct sigaction sa = { .sa_handler = connect_sigint };
    sigaction(SIGINT, &sa, NULL);
    connect_running = 1;

    struct pollfd fds[2];
    fds[0].fd = STDIN_FILENO;
    fds[0].events = POLLIN;
    fds[1].fd = fd;
    fds[1].events = POLLIN;

    while (connect_running) {
        int nready = poll(fds, 2, 1000);
        if (nready < 0) {
            if (errno == EINTR) continue;
            break;
        }

        if (fds[0].revents & POLLIN) {
            char buf[4096];
            ssize_t n = read(STDIN_FILENO, buf, sizeof(buf));
            if (n <= 0) break;

            size_t written = 0;
            while (written < (size_t)n) {
                ssize_t w = opssl_write(conn, buf + written, n - written);
                if (w > 0) {
                    written += w;
                } else if (w == OPSSL_WANT_WRITE_CLI) {
                    struct pollfd wpfd = { .fd = fd, .events = POLLOUT };
                    poll(&wpfd, 1, 5000);
                } else {
                    goto done;
                }
            }
        }

        if (fds[1].revents & POLLIN) {
            char buf[4096];
            ssize_t n = opssl_read(conn, buf, sizeof(buf));
            if (n > 0) {
                fwrite(buf, 1, n, stdout);
                fflush(stdout);
            } else if (n == 0 || n == OPSSL_CLOSED_CLI) {
                if (!quiet)
                    fprintf(stderr, "Connection closed by peer\n");
                break;
            } else if (n == OPSSL_WANT_READ_CLI) {
                continue;
            } else {
                if (!quiet)
                    fprintf(stderr, "Read error\n");
                break;
            }
        }

        if ((fds[0].revents | fds[1].revents) & (POLLHUP | POLLERR))
            break;
    }

done:
    opssl_conn_free(conn);
    opssl_ctx_free(ctx);
    close(fd);
    return 0;
}

/* ─── Cipher Suite Listing ──────────────────────────────────────────────── */

static int cmd_ciphers(int argc, char **argv)
{
    (void)argc; (void)argv;

    printf("Supported TLS cipher suites:\n\n");
    printf("TLS 1.3:\n");
    printf("  TLS_AES_128_GCM_SHA256\n");
    printf("  TLS_AES_256_GCM_SHA384\n");
    printf("  TLS_CHACHA20_POLY1305_SHA256\n");
    printf("\n");
    printf("TLS 1.2:\n");
    printf("  ECDHE-RSA-AES128-GCM-SHA256\n");
    printf("  ECDHE-RSA-AES256-GCM-SHA384\n");
    printf("  ECDHE-RSA-CHACHA20-POLY1305\n");
    printf("  ECDHE-ECDSA-AES128-GCM-SHA256\n");
    printf("  ECDHE-ECDSA-AES256-GCM-SHA384\n");
    printf("  ECDHE-ECDSA-CHACHA20-POLY1305\n");
    printf("\n");
    printf("Key exchange groups:\n");
    printf("  X25519  P-256  P-384  P-521");
#ifdef OPSSL_HAVE_MLKEM
    printf("  ML-KEM-768");
#endif
    printf("\n\n");
    printf("Crypto primitives:\n");
    printf("  Hash:  SHA-1  SHA-256  SHA-384  SHA-512  SHA3-256  SHA3-512  BLAKE2b\n");
    printf("  KDF:   HKDF  PBKDF2  Argon2id\n");
    printf("  AEAD:  AES-128-GCM  AES-256-GCM  ChaCha20-Poly1305  AES-128-CCM  AES-256-CCM\n");
    printf("  Sig:   ECDSA  Ed25519  RSA-PSS\n");
    printf("  XOF:   SHAKE-128  SHAKE-256\n");
    return 0;
}

/* ─── Speed Benchmark ──────────────────────────────────────────────────── */

static double elapsed_ms(struct timeval *start, struct timeval *end)
{
    return (end->tv_sec - start->tv_sec) * 1000.0 +
           (end->tv_usec - start->tv_usec) / 1000.0;
}

static int cmd_speed(int argc, char **argv)
{
    (void)argc; (void)argv;

    const size_t data_len = 1024 * 1024;
    uint8_t *data = malloc(data_len);
    if (!data) {
        fprintf(stderr, "Error: out of memory\n");
        return 1;
    }
    memset(data, 0xAB, data_len);

    uint8_t digest[64];
    struct timeval t0, t1;
    double ms;
    int iters;

    printf("opssl speed benchmark (1 MB blocks)\n");
    printf("%-24s %8s %12s\n", "Algorithm", "Iters", "MB/s");
    printf("%-24s %8s %12s\n", "------------------------", "--------", "------------");

    struct {
        const char *name;
        void (*func)(const void*, size_t, uint8_t*);
        size_t digest_len;
    } hashes[] = {
        {"SHA-1",    (void(*)(const void*,size_t,uint8_t*))opssl_sha1,     20},
        {"SHA-256",  (void(*)(const void*,size_t,uint8_t*))opssl_sha256,   32},
        {"SHA-384",  (void(*)(const void*,size_t,uint8_t*))opssl_sha384,   48},
        {"SHA-512",  (void(*)(const void*,size_t,uint8_t*))opssl_sha512,   64},
        {"SHA3-256", (void(*)(const void*,size_t,uint8_t*))opssl_sha3_256, 32},
        {"SHA3-512", (void(*)(const void*,size_t,uint8_t*))opssl_sha3_512, 64},
    };

    for (size_t h = 0; h < sizeof(hashes)/sizeof(hashes[0]); h++) {
        iters = 0;
        gettimeofday(&t0, NULL);
        do {
            hashes[h].func(data, data_len, digest);
            iters++;
            gettimeofday(&t1, NULL);
            ms = elapsed_ms(&t0, &t1);
        } while (ms < 1000.0);
        printf("%-24s %8d %12.1f\n", hashes[h].name, iters, (double)iters * 1.0 / (ms / 1000.0));
    }

    /* BLAKE2b */
    iters = 0;
    gettimeofday(&t0, NULL);
    do {
        opssl_blake2b(data, data_len, digest, 32);
        iters++;
        gettimeofday(&t1, NULL);
        ms = elapsed_ms(&t0, &t1);
    } while (ms < 1000.0);
    printf("%-24s %8d %12.1f\n", "BLAKE2b-256", iters, (double)iters * 1.0 / (ms / 1000.0));

    /* HMAC-SHA256 */
    uint8_t hmac_key[32];
    memset(hmac_key, 0x42, sizeof(hmac_key));
    iters = 0;
    gettimeofday(&t0, NULL);
    do {
        size_t out_len = 32;
        opssl_hmac(OPSSL_HMAC_SHA256, hmac_key, sizeof(hmac_key),
                   data, data_len, digest, &out_len);
        iters++;
        gettimeofday(&t1, NULL);
        ms = elapsed_ms(&t0, &t1);
    } while (ms < 1000.0);
    printf("%-24s %8d %12.1f\n", "HMAC-SHA-256", iters, (double)iters * 1.0 / (ms / 1000.0));

    /* AEAD: AES-256-GCM */
    opssl_aead_ctx_t *aead = opssl_aead_new(OPSSL_AEAD_AES_256_GCM);
    if (aead) {
        uint8_t key[32], nonce[12];
        memset(key, 0xCC, sizeof(key));
        memset(nonce, 0xDD, sizeof(nonce));
        opssl_aead_set_key(aead, key, sizeof(key));

        uint8_t *ct = malloc(data_len + 16);
        size_t ct_len;

        iters = 0;
        gettimeofday(&t0, NULL);
        do {
            ct_len = data_len + 16;
            opssl_aead_seal(aead, ct, &ct_len, data_len + 16,
                           nonce, sizeof(nonce), data, data_len, NULL, 0);
            iters++;
            gettimeofday(&t1, NULL);
            ms = elapsed_ms(&t0, &t1);
        } while (ms < 1000.0);
        printf("%-24s %8d %12.1f\n", "AES-256-GCM seal", iters, (double)iters * 1.0 / (ms / 1000.0));

        free(ct);
        opssl_aead_free(aead);
    }

    /* AEAD: ChaCha20-Poly1305 */
    aead = opssl_aead_new(OPSSL_AEAD_CHACHA20_POLY1305);
    if (aead) {
        uint8_t key[32], nonce[12];
        memset(key, 0xCC, sizeof(key));
        memset(nonce, 0xDD, sizeof(nonce));
        opssl_aead_set_key(aead, key, sizeof(key));

        uint8_t *ct = malloc(data_len + 16);
        size_t ct_len;

        iters = 0;
        gettimeofday(&t0, NULL);
        do {
            ct_len = data_len + 16;
            opssl_aead_seal(aead, ct, &ct_len, data_len + 16,
                           nonce, sizeof(nonce), data, data_len, NULL, 0);
            iters++;
            gettimeofday(&t1, NULL);
            ms = elapsed_ms(&t0, &t1);
        } while (ms < 1000.0);
        printf("%-24s %8d %12.1f\n", "ChaCha20-Poly1305 seal", iters, (double)iters * 1.0 / (ms / 1000.0));

        free(ct);
        opssl_aead_free(aead);
    }

    free(data);
    return 0;
}

/* ─── PBKDF2 standalone command ────────────────────────────────────────── */

static int cmd_pbkdf2(int argc, char **argv)
{
    const char *password = NULL;
    const char *salt_hex = NULL;
    int iterations = 600000;
    int key_len = 32;
    const char *algo_str = "sha256";

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-p") == 0 && i+1 < argc) password = argv[++i];
        else if (strcmp(argv[i], "-s") == 0 && i+1 < argc) salt_hex = argv[++i];
        else if (strcmp(argv[i], "-i") == 0 && i+1 < argc) iterations = atoi(argv[++i]);
        else if (strcmp(argv[i], "-len") == 0 && i+1 < argc) key_len = atoi(argv[++i]);
        else if (strcmp(argv[i], "-sha256") == 0) algo_str = "sha256";
        else if (strcmp(argv[i], "-sha384") == 0) algo_str = "sha384";
        else if (strcmp(argv[i], "-sha512") == 0) algo_str = "sha512";
    }

    if (!password) {
        fprintf(stderr, "Usage: opssl pbkdf2 -p PASSWORD [-s SALT_HEX] [-i ITERATIONS] [-len BYTES] [-sha256|-sha384|-sha512]\n");
        return 1;
    }

    opssl_hmac_algo_t algo = OPSSL_HMAC_SHA256;
    if (strcmp(algo_str, "sha384") == 0) algo = OPSSL_HMAC_SHA384;
    else if (strcmp(algo_str, "sha512") == 0) algo = OPSSL_HMAC_SHA512;

    uint8_t salt[64];
    size_t salt_len;
    if (salt_hex) {
        int n = hex_to_bytes(salt_hex, salt, sizeof(salt));
        if (n <= 0) {
            fprintf(stderr, "Error: invalid hex salt\n");
            return 1;
        }
        salt_len = n;
    } else {
        salt_len = 16;
        if (opssl_random_bytes(salt, salt_len) != 0) {
            fprintf(stderr, "Error: RNG failure\n");
            return 1;
        }
    }

    if (key_len <= 0 || key_len > 512) {
        fprintf(stderr, "Error: key length must be 1-512\n");
        return 1;
    }

    uint8_t *out = malloc(key_len);
    if (opssl_pbkdf2(algo, (uint8_t*)password, strlen(password),
                     salt, salt_len, iterations, out, key_len) != 1) {
        fprintf(stderr, "Error: PBKDF2 failed\n");
        free(out);
        return 1;
    }

    printf("salt=");
    print_hex(salt, salt_len);
    printf("\nkey=");
    print_hex(out, key_len);
    printf("\n");

    free(out);
    return 0;
}

/* ─── genkey Command ─────────────────────────────────────────────────────── */

static int cmd_genkey(int argc, char **argv)
{
    const char *algo = "ed25519";
    const char *outfile = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-algorithm") == 0 && i + 1 < argc)
            algo = argv[++i];
        else if (strcmp(argv[i], "-out") == 0 && i + 1 < argc)
            outfile = argv[++i];
    }

    FILE *f = stdout;
    if (outfile) {
        f = safe_fopen(outfile, "w");
        if (!f) return 1;
    }

    if (strcmp(algo, "ed25519") == 0) {
        uint8_t pk[32], sk[64];
        opssl_random_bytes(sk, 32);
        memset(sk + 32, 0, 32);
        if (opssl_ed25519_keygen(pk, sk) != 1) {
            fprintf(stderr, "Error: Ed25519 keygen failed\n");
            if (f != stdout) fclose(f);
            return 1;
        }
        uint8_t pkcs8[48];
        build_ed25519_pkcs8(pkcs8, sk);
        write_pem(f, "PRIVATE KEY", pkcs8, 48);
        opssl_memzero(sk, sizeof(sk));
        opssl_memzero(pkcs8, sizeof(pkcs8));
    } else if (strcmp(algo, "x25519") == 0) {
        uint8_t priv[32], pub[32];
        opssl_x25519_keygen(priv, pub);
        uint8_t pkcs8[48];
        build_x25519_pkcs8(pkcs8, priv);
        write_pem(f, "PRIVATE KEY", pkcs8, 48);
        opssl_memzero(priv, sizeof(priv));
        opssl_memzero(pkcs8, sizeof(pkcs8));
    } else {
        fprintf(stderr, "Error: unsupported algorithm '%s' (try ed25519 or x25519)\n", algo);
        if (f != stdout) fclose(f);
        return 1;
    }

    if (f != stdout) fclose(f);
    return 0;
}

/* ─── req Command (self-signed certificate) ──────────────────────────────── */

static int cmd_req(int argc, char **argv)
{
    const char *cn = "localhost";
    int days = 365;
    const char *outfile = NULL;
    const char *keyout = NULL;
    int newkey = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-cn") == 0 && i + 1 < argc)
            cn = argv[++i];
        else if (strcmp(argv[i], "-days") == 0 && i + 1 < argc)
            days = atoi(argv[++i]);
        else if (strcmp(argv[i], "-out") == 0 && i + 1 < argc)
            outfile = argv[++i];
        else if (strcmp(argv[i], "-keyout") == 0 && i + 1 < argc)
            keyout = argv[++i];
        else if (strcmp(argv[i], "-newkey") == 0)
            newkey = 1;
        else if (strcmp(argv[i], "-x509") == 0) {
            /* implied — we always self-sign */
        }
    }

    if (!newkey && !keyout) newkey = 1;

    uint8_t pk[32], sk[64];
    opssl_random_bytes(sk, 32);
    memset(sk + 32, 0, 32);
    if (opssl_ed25519_keygen(pk, sk) != 1) {
        fprintf(stderr, "Error: Ed25519 keygen failed\n");
        return 1;
    }

    uint8_t cert_der[4096];
    size_t cert_len = 0;
    if (!build_selfsigned_ed25519(cert_der, sizeof(cert_der), &cert_len,
                                  cn, days, pk, sk)) {
        fprintf(stderr, "Error: certificate generation failed\n");
        opssl_memzero(sk, sizeof(sk));
        return 1;
    }

    /* Write certificate */
    FILE *cf = stdout;
    if (outfile) {
        cf = safe_fopen(outfile, "w");
        if (!cf) {
            opssl_memzero(sk, sizeof(sk));
            return 1;
        }
    }
    write_pem(cf, "CERTIFICATE", cert_der, cert_len);
    if (cf != stdout) fclose(cf);

    /* Write private key if requested */
    if (keyout) {
        FILE *kf = safe_fopen(keyout, "w");
        if (!kf) {
            opssl_memzero(sk, sizeof(sk));
            return 1;
        }
        uint8_t pkcs8[48];
        build_ed25519_pkcs8(pkcs8, sk);
        write_pem(kf, "PRIVATE KEY", pkcs8, 48);
        opssl_memzero(pkcs8, sizeof(pkcs8));
        fclose(kf);
        fprintf(stderr, "Certificate written to %s\n", outfile ? outfile : "stdout");
        fprintf(stderr, "Private key written to %s\n", keyout);
    } else if (newkey) {
        uint8_t pkcs8[48];
        build_ed25519_pkcs8(pkcs8, sk);
        if (outfile) {
            write_pem(stdout, "PRIVATE KEY", pkcs8, 48);
        }
        opssl_memzero(pkcs8, sizeof(pkcs8));
    }

    opssl_memzero(sk, sizeof(sk));
    return 0;
}

/* ─── pkey Command ───────────────────────────────────────────────────────── */

static int cmd_pkey(int argc, char **argv)
{
    const char *infile = NULL;
    int text = 0;
    int pubout = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-in") == 0 && i + 1 < argc)
            infile = argv[++i];
        else if (strcmp(argv[i], "-text") == 0)
            text = 1;
        else if (strcmp(argv[i], "-pubout") == 0)
            pubout = 1;
    }

    if (!infile) {
        fprintf(stderr, "Usage: opssl pkey -in <keyfile> [-text] [-pubout]\n");
        return 1;
    }

    opssl_pkey_t *key = opssl_pkey_from_file(infile);
    if (!key) {
        fprintf(stderr, "Error: failed to load key from %s\n", infile);
        return 1;
    }

    static const char *type_names[] = {"RSA", "EC", "Ed25519", "Ed448"};
    int type = opssl_pkey_type(key);
    size_t bits = opssl_pkey_bits(key);

    if (text) {
        printf("Private-Key: (%zu bit)\n", bits);
        printf("Type: %s\n", (type >= 0 && type <= 3) ? type_names[type] : "Unknown");
    }

    if (pubout && type == 2) {
        /* Ed25519: extract pub from the pkey and emit SPKI */
        /* Re-derive: load key, keygen from seed to get pub */
        size_t pem_len;
        char *pem_data = read_file_to_string(infile, &pem_len);
        if (pem_data) {
            /* Parse the PEM to get the seed, re-derive pub */
            /* For now, just show key info */
            printf("(pubout for Ed25519 requires re-derivation — use genkey to keep both)\n");
            free(pem_data);
        }
    }

    if (!text && !pubout) {
        printf("Private-Key: (%zu bit)\n", bits);
        printf("Type: %s\n", (type >= 0 && type <= 3) ? type_names[type] : "Unknown");
    }

    opssl_pkey_free(key);
    return 0;
}

/* ─── s_server Command ───────────────────────────────────────────────────── */

static int cmd_s_server(int argc, char **argv)
{
    const char *cert_file = NULL;
    const char *key_file = NULL;
    int port = 4433;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-cert") == 0 && i + 1 < argc)
            cert_file = argv[++i];
        else if (strcmp(argv[i], "-key") == 0 && i + 1 < argc)
            key_file = argv[++i];
        else if (strcmp(argv[i], "-port") == 0 && i + 1 < argc)
            port = atoi(argv[++i]);
    }

    if (!cert_file || !key_file) {
        fprintf(stderr, "Usage: opssl s_server -cert <file> -key <file> [-port <num>]\n");
        return 1;
    }

    opssl_ctx_t *ctx = opssl_ctx_new(OPSSL_TLS_1_2);
    if (!ctx) {
        fprintf(stderr, "Error: failed to create TLS context\n");
        return 1;
    }
    opssl_ctx_set_max_version(ctx, OPSSL_TLS_1_3);

    if (opssl_ctx_use_certificate_file(ctx, cert_file) != 1) {
        fprintf(stderr, "Error: failed to load certificate %s\n", cert_file);
        opssl_ctx_free(ctx);
        return 1;
    }

    if (opssl_ctx_use_private_key_file(ctx, key_file) != 1) {
        fprintf(stderr, "Error: failed to load private key %s\n", key_file);
        opssl_ctx_free(ctx);
        return 1;
    }

    /* Create listening socket */
    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%d", port);

    struct addrinfo hints = {0}, *res;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    if (getaddrinfo(NULL, port_str, &hints, &res) != 0) {
        fprintf(stderr, "Error: getaddrinfo failed\n");
        opssl_ctx_free(ctx);
        return 1;
    }

    int listenfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (listenfd < 0) {
        fprintf(stderr, "Error: socket() failed\n");
        freeaddrinfo(res);
        opssl_ctx_free(ctx);
        return 1;
    }

    int opt = 1;
    setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    if (bind(listenfd, res->ai_addr, res->ai_addrlen) < 0) {
        fprintf(stderr, "Error: bind() failed on port %d\n", port);
        freeaddrinfo(res);
        close(listenfd);
        opssl_ctx_free(ctx);
        return 1;
    }
    freeaddrinfo(res);

    if (listen(listenfd, 5) < 0) {
        fprintf(stderr, "Error: listen() failed\n");
        close(listenfd);
        opssl_ctx_free(ctx);
        return 1;
    }

    fprintf(stderr, "Listening on port %d (TLS echo server, Ctrl+C to stop)\n", port);

    while (1) {
        struct sockaddr_storage addr;
        socklen_t addr_len = sizeof(addr);
        int clientfd = accept(listenfd, (struct sockaddr *)&addr, &addr_len);
        if (clientfd < 0) continue;

        opssl_conn_t *conn = opssl_conn_new(ctx, clientfd, OPSSL_DIR_INBOUND);
        if (!conn) {
            close(clientfd);
            continue;
        }

        struct pollfd cpfd = { .fd = clientfd, .events = POLLIN | POLLOUT };
        int r;
        for (;;) {
            r = opssl_accept(conn);
            if (r == OPSSL_OK_CLI) break;
            if (r == OPSSL_WANT_READ_CLI) {
                cpfd.events = POLLIN;
                poll(&cpfd, 1, 10000);
            } else if (r == OPSSL_WANT_WRITE_CLI) {
                cpfd.events = POLLOUT;
                poll(&cpfd, 1, 10000);
            } else {
                break;
            }
        }
        if (r != OPSSL_OK_CLI) {
            fprintf(stderr, "TLS handshake failed (err=%d)\n", r);
            opssl_conn_free(conn);
            close(clientfd);
            continue;
        }

        fprintf(stderr, "TLS connection established\n");

        uint8_t buf[4096];
        while (1) {
            ssize_t n = opssl_read(conn, buf, sizeof(buf));
            if (n <= 0) break;
            ssize_t w = opssl_write(conn, buf, (size_t)n);
            if (w <= 0) break;
        }

        opssl_shutdown(conn);
        opssl_conn_free(conn);
        close(clientfd);
        fprintf(stderr, "Connection closed\n");
    }

    close(listenfd);
    opssl_ctx_free(ctx);
    return 0;
}

/* ─── Command Dispatch ───────────────────────────────────────────────────── */

struct cmd {
    const char *name;
    int (*func)(int argc, char **argv);
    const char *help;
};

static struct cmd commands[] = {
    {"version", cmd_version, "Show version info"},
    {"dgst", cmd_dgst, "Hash files or stdin"},
    {"rand", cmd_rand, "Generate random hex bytes"},
    {"base64", cmd_base64, "Base64 encode/decode"},
    {"shake", cmd_shake, "SHAKE extendable output function"},
    {"hmac", cmd_hmac, "Compute HMAC"},
    {"enc", cmd_enc, "AEAD encrypt/decrypt"},
    {"dhparam", cmd_dhparam, "Generate DH parameters"},
    {"fingerprint", cmd_fingerprint, "Certificate fingerprinting"},
    {"verify", cmd_verify, "Certificate chain verification"},
    {"x509", cmd_x509, "Certificate information display"},
    {"verifier", cmd_verifier, "SCRAM verifier generation"},
    {"mkpasswd", cmd_mkpasswd, "Password hashing (argon2id, pbkdf2)"},
    {"passwd", cmd_passwd, "Verify password against hash"},
    {"blake2b", cmd_blake2b, "BLAKE2b hash"},
    {"hkdf", cmd_hkdf, "HKDF key derivation"},
    {"connect", cmd_connect, "TLS client connect (s_client)"},
    {"ciphers", cmd_ciphers, "List supported cipher suites"},
    {"speed", cmd_speed, "Benchmark crypto primitives"},
    {"pbkdf2", cmd_pbkdf2, "PBKDF2 key derivation"},
    {"genkey", cmd_genkey, "Generate Ed25519/X25519 private key"},
    {"req", cmd_req, "Generate self-signed X.509 certificate"},
    {"pkey", cmd_pkey, "Display private key information"},
    {"s_server", cmd_s_server, "TLS echo server"},
    {NULL, NULL, NULL}
};

static void show_help(void)
{
    printf("opssl unified CLI - Complete crypto and TLS operations using opssl library\n\n");
    printf("Available commands:\n");

    for (struct cmd *c = commands; c->name; c++) {
        printf("  %-12s %s\n", c->name, c->help);
    }

    printf("\nUse 'opssl COMMAND' to run a command.\n");
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        show_help();
        return 1;
    }

    const char *cmd_name = argv[1];

    if (opssl_init() != 1) {
        fprintf(stderr, "Error: failed to initialize opssl\n");
        return 1;
    }

    if (strcmp(cmd_name, "help") == 0) {
        show_help();
        opssl_cleanup();
        return 0;
    }

    for (struct cmd *c = commands; c->name; c++) {
        if (strcmp(cmd_name, c->name) == 0) {
            int ret = c->func(argc - 1, argv + 1);
            opssl_cleanup();
            return ret;
        }
    }

    fprintf(stderr, "Error: unknown command '%s'\n", cmd_name);
    fprintf(stderr, "Run 'opssl help' for available commands.\n");

    opssl_cleanup();
    return 1;
}

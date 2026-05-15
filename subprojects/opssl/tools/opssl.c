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
#include <sys/time.h>
#include <fcntl.h>
#include <errno.h>

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
} opssl_hmac_algo_t;

extern int opssl_hmac(opssl_hmac_algo_t algo, const uint8_t *key, size_t key_len,
                      const void *data, size_t data_len, uint8_t *out, size_t *out_len);

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

/* X.509 certificate types */
typedef struct opssl_x509 opssl_x509_t;
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

    /* Temporary buffers for INTEGER encoding */
    uint8_t prime_der[600], gen_der[10];
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

    /* Base64 encode the DER data */
    char *encoded = malloc((der_len * 4 / 3) + 10);
    size_t encoded_len = (der_len * 4 / 3) + 10;

    if (opssl_base64_encode(der, der_len, encoded, &encoded_len)) {
        /* Write in 64-character lines */
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
                fprintf(stderr, "Usage: opssl hmac [-a sha256|sha384|sha512] -k hex_key [file...]\n");
                return 1;
        }
    }

    if (strcmp(algo_str, "sha256") == 0) algo = OPSSL_HMAC_SHA256;
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

    if (bits != 2048 && bits != 3072 && bits != 4096) {
        fprintf(stderr, "Usage: opssl dhparam -bits 2048|3072|4096 [-out file]\n");
        return 1;
    }

    const unsigned char *prime;
    size_t prime_len;

    switch (bits) {
        case 2048: prime = prime_2048; prime_len = sizeof(prime_2048); break;
        case 3072: prime = prime_3072; prime_len = sizeof(prime_3072); break;
        case 4096: prime = prime_4096; prime_len = sizeof(prime_4096); break;
        default: return 1;
    }

    uint8_t der[700];
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
    if (!store || opssl_x509_store_load_file(store, ca_file) != 1) {
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
        printf("Verification failed: %s\n", result.error_string ? result.error_string : "unknown error");
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

    char salt_b64[32];
    size_t salt_b64_len = sizeof(salt_b64);
    opssl_base64_encode(salt, sizeof(salt), salt_b64, &salt_b64_len);

    if (sha256) {
        uint8_t salted_pass[64], client_key[32], server_key[32];
        size_t salted_pass_len = sizeof(salted_pass);

        opssl_pbkdf2(OPSSL_HMAC_SHA256, (uint8_t*)password, strlen(password),
                     salt, sizeof(salt), iterations, salted_pass, 32);

        opssl_hmac(OPSSL_HMAC_SHA256, salted_pass, 32,
                   (uint8_t*)"Client Key", 10, client_key, &salted_pass_len);

        opssl_sha256(client_key, 32, client_key);

        opssl_hmac(OPSSL_HMAC_SHA256, salted_pass, 32,
                   (uint8_t*)"Server Key", 10, server_key, &salted_pass_len);

        char server_key_b64[64];
        size_t server_key_b64_len = sizeof(server_key_b64);
        opssl_base64_encode(server_key, 32, server_key_b64, &server_key_b64_len);

        printf("SCRAM-SHA-256: salt=%s,iterations=%d,server-key=%s\n",
               salt_b64, iterations, server_key_b64);
    }

    if (sha512) {
        uint8_t salted_pass[64], client_key[64], server_key[64];
        size_t salted_pass_len = sizeof(salted_pass);

        opssl_pbkdf2(OPSSL_HMAC_SHA512, (uint8_t*)password, strlen(password),
                     salt, sizeof(salt), iterations, salted_pass, 64);

        opssl_hmac(OPSSL_HMAC_SHA512, salted_pass, 64,
                   (uint8_t*)"Client Key", 10, client_key, &salted_pass_len);

        opssl_sha512(client_key, 64, client_key);

        opssl_hmac(OPSSL_HMAC_SHA512, salted_pass, 64,
                   (uint8_t*)"Server Key", 10, server_key, &salted_pass_len);

        char server_key_b64[128];
        size_t server_key_b64_len = sizeof(server_key_b64);
        opssl_base64_encode(server_key, 64, server_key_b64, &server_key_b64_len);

        printf("SCRAM-SHA-512: salt=%s,iterations=%d,server-key=%s\n",
               salt_b64, iterations, server_key_b64);
    }

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
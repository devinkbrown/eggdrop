/*
 * opssl/crypto/pbkdf2.c — PBKDF2-HMAC key derivation (RFC 2898).
 *
 * Password-Based Key Derivation Function 2 using HMAC-SHA1/SHA256/SHA384/SHA512.
 * Implements RFC 2898 section 5.2.
 *
 * Security note: Use high iteration counts (>=4096) and cryptographically
 * strong salts for password derivation.
 *
 * Copyright (C) 2026 ophion development team
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <opssl/crypto.h>
#include <opssl/platform.h>
#include <string.h>
#include "sha_internal.h"

/* Get hash length for HMAC algorithm */
static size_t
get_hash_len(opssl_hmac_algo_t algo)
{
    switch (algo) {
        case OPSSL_HMAC_SHA1: return OPSSL_SHA1_DIGEST_LEN;
        case OPSSL_HMAC_SHA256: return OPSSL_SHA256_DIGEST_LEN;
        case OPSSL_HMAC_SHA384: return OPSSL_SHA384_DIGEST_LEN;
        case OPSSL_HMAC_SHA512: return OPSSL_SHA512_DIGEST_LEN;
        default: return 0;
    }
}

/* PBKDF2 F function (RFC 2898 section 5.2) */
static int
pbkdf2_f(opssl_hmac_algo_t algo,
         const uint8_t *password, size_t password_len,
         const uint8_t *salt, size_t salt_len,
         uint32_t iterations, uint32_t block_index,
         uint8_t *out, size_t out_len)
{
    opssl_hmac_ctx_t hmac_ctx;
    uint8_t u_buf[OPSSL_HMAC_MAX_DIGEST_LEN];
    uint8_t temp_buf[OPSSL_HMAC_MAX_DIGEST_LEN];
    size_t hash_len = get_hash_len(algo);
    uint8_t block_index_be[4];
    size_t hmac_out_len;
    int rc;

    if (hash_len == 0 || out_len < hash_len) {
        return 0;
    }

    /* Initialize HMAC with password */
    rc = opssl_hmac_init(&hmac_ctx, algo, password, password_len);
    if (rc != 1) {
        return 0;
    }

    /* U_1 = HMAC(password, salt || INT_32_BE(i)) */
    opssl_hmac_update(&hmac_ctx, salt, salt_len);
    opssl_put_be32(block_index_be, block_index);
    opssl_hmac_update(&hmac_ctx, block_index_be, 4);

    hmac_out_len = sizeof(u_buf);
    rc = opssl_hmac_final(&hmac_ctx, u_buf, &hmac_out_len);
    if (rc != 1 || hmac_out_len != hash_len) {
        opssl_hmac_cleanup(&hmac_ctx);
        return 0;
    }

    /* T_i = U_1 */
    memcpy(out, u_buf, hash_len);

    /* U_j = HMAC(password, U_{j-1}) for j = 2 to iterations */
    /* T_i = U_1 XOR U_2 XOR ... XOR U_iterations */
    for (uint32_t j = 2; j <= iterations; j++) {
        rc = opssl_hmac_init(&hmac_ctx, algo, password, password_len);
        if (rc != 1) {
            opssl_memzero(u_buf, sizeof(u_buf));
            opssl_memzero(out, hash_len);
            return 0;
        }

        opssl_hmac_update(&hmac_ctx, u_buf, hash_len);

        hmac_out_len = sizeof(temp_buf);
        rc = opssl_hmac_final(&hmac_ctx, temp_buf, &hmac_out_len);
        if (rc != 1 || hmac_out_len != hash_len) {
            opssl_hmac_cleanup(&hmac_ctx);
            opssl_memzero(u_buf, sizeof(u_buf));
            opssl_memzero(temp_buf, sizeof(temp_buf));
            opssl_memzero(out, hash_len);
            return 0;
        }

        /* XOR with accumulated result */
        for (size_t k = 0; k < hash_len; k++) {
            out[k] ^= temp_buf[k];
        }

        /* Update U for next iteration */
        memcpy(u_buf, temp_buf, hash_len);
    }

    opssl_hmac_cleanup(&hmac_ctx);
    opssl_memzero(u_buf, sizeof(u_buf));
    opssl_memzero(temp_buf, sizeof(temp_buf));
    opssl_memzero(block_index_be, sizeof(block_index_be));

    return 1;
}

/* PBKDF2 key derivation (RFC 2898) */
int
opssl_pbkdf2(opssl_hmac_algo_t algo,
             const uint8_t *password, size_t password_len,
             const uint8_t *salt, size_t salt_len,
             uint32_t iterations,
             uint8_t *out, size_t out_len)
{
    size_t hash_len;
    uint32_t blocks_needed;
    uint8_t *out_ptr;
    size_t remaining;
    uint8_t block_buf[OPSSL_HMAC_MAX_DIGEST_LEN];

    if (!password || !salt || !out || out_len == 0 || iterations == 0) {
        return 0;
    }

    hash_len = get_hash_len(algo);
    if (hash_len == 0) {
        return 0;
    }

    /* Calculate number of blocks needed (RFC 2898 section 5.2) */
    blocks_needed = (out_len + hash_len - 1) / hash_len;

    out_ptr = out;
    remaining = out_len;

    /* Generate each block T_i */
    for (uint32_t i = 1; i <= blocks_needed; i++) {
        int rc = pbkdf2_f(algo, password, password_len,
                          salt, salt_len, iterations, i,
                          block_buf, hash_len);
        if (rc != 1) {
            opssl_memzero(out, out_len);
            opssl_memzero(block_buf, sizeof(block_buf));
            return 0;
        }

        /* Copy to output (may be partial for last block) */
        size_t copy_len = (remaining < hash_len) ? remaining : hash_len;
        memcpy(out_ptr, block_buf, copy_len);
        out_ptr += copy_len;
        remaining -= copy_len;
    }

    opssl_memzero(block_buf, sizeof(block_buf));
    return 1;
}

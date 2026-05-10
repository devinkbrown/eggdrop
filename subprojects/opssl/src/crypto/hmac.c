/*
 * opssl/crypto/hmac.c — HMAC (RFC 2104) for SHA-256/384/512.
 *
 * Used throughout TLS for PRF (1.2) and HKDF (1.3).
 *
 * Copyright (C) 2026 ophion development team
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <opssl/crypto.h>
#include <opssl/platform.h>
#include <string.h>
#include "sha_internal.h"

#define HMAC_BLOCK_SIZE_256 64
#define HMAC_BLOCK_SIZE_512 128
#define HMAC_MAX_BLOCK_SIZE 128

static size_t
get_block_size(opssl_hmac_algo_t algo)
{
    switch (algo) {
    case OPSSL_HMAC_SHA256: return 64;
    case OPSSL_HMAC_SHA384: return 128;
    case OPSSL_HMAC_SHA512: return 128;
    }
    return 64;
}

static size_t
get_digest_size(opssl_hmac_algo_t algo)
{
    switch (algo) {
    case OPSSL_HMAC_SHA256: return OPSSL_SHA256_DIGEST_LEN;
    case OPSSL_HMAC_SHA384: return OPSSL_SHA384_DIGEST_LEN;
    case OPSSL_HMAC_SHA512: return OPSSL_SHA512_DIGEST_LEN;
    }
    return OPSSL_SHA256_DIGEST_LEN;
}

int
opssl_hmac_init(opssl_hmac_ctx_t *ctx, opssl_hmac_algo_t algo,
                const uint8_t *key, size_t key_len)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->algo = algo;
    ctx->block_size = get_block_size(algo);
    ctx->digest_size = get_digest_size(algo);

    uint8_t key_block[HMAC_MAX_BLOCK_SIZE];
    memset(key_block, 0, sizeof(key_block));

    if (key_len > ctx->block_size) {
        /* Hash the key if too long */
        switch (algo) {
        case OPSSL_HMAC_SHA256:
            opssl_sha256(key, key_len, key_block);
            break;
        case OPSSL_HMAC_SHA384:
            opssl_sha384(key, key_len, key_block);
            break;
        case OPSSL_HMAC_SHA512:
            opssl_sha512(key, key_len, key_block);
            break;
        }
    } else {
        memcpy(key_block, key, key_len);
    }

    /* ipad = key ^ 0x36 */
    uint8_t ipad[HMAC_MAX_BLOCK_SIZE];
    for (size_t i = 0; i < ctx->block_size; i++)
        ipad[i] = key_block[i] ^ 0x36;

    /* opad = key ^ 0x5c (store for final) */
    for (size_t i = 0; i < ctx->block_size; i++)
        ctx->key_pad[i] = key_block[i] ^ 0x5c;

    /* Init inner hash with ipad */
    switch (algo) {
    case OPSSL_HMAC_SHA256:
        opssl_sha256_init(&ctx->inner.sha256);
        opssl_sha256_update(&ctx->inner.sha256, ipad, ctx->block_size);
        break;
    case OPSSL_HMAC_SHA384:
        opssl_sha384_init(&ctx->inner.sha512);
        opssl_sha512_update(&ctx->inner.sha512, ipad, ctx->block_size);
        break;
    case OPSSL_HMAC_SHA512:
        opssl_sha512_init(&ctx->inner.sha512);
        opssl_sha512_update(&ctx->inner.sha512, ipad, ctx->block_size);
        break;
    }

    opssl_memzero(key_block, sizeof(key_block));
    opssl_memzero(ipad, sizeof(ipad));
    return 1;
}

void
opssl_hmac_update(opssl_hmac_ctx_t *ctx, const void *data, size_t len)
{
    switch (ctx->algo) {
    case OPSSL_HMAC_SHA256:
        opssl_sha256_update(&ctx->inner.sha256, data, len);
        break;
    case OPSSL_HMAC_SHA384:
    case OPSSL_HMAC_SHA512:
        opssl_sha512_update(&ctx->inner.sha512, data, len);
        break;
    }
}

int
opssl_hmac_final(opssl_hmac_ctx_t *ctx, uint8_t *out, size_t *out_len)
{
    uint8_t inner_hash[OPSSL_SHA512_DIGEST_LEN];

    switch (ctx->algo) {
    case OPSSL_HMAC_SHA256:
        opssl_sha256_final(&ctx->inner.sha256, inner_hash);
        break;
    case OPSSL_HMAC_SHA384:
        opssl_sha384_final(&ctx->inner.sha512, inner_hash);
        break;
    case OPSSL_HMAC_SHA512:
        opssl_sha512_final(&ctx->inner.sha512, inner_hash);
        break;
    }

    /* outer hash: H(opad || inner_hash) */
    switch (ctx->algo) {
    case OPSSL_HMAC_SHA256: {
        opssl_sha256_ctx_t outer;
        opssl_sha256_init(&outer);
        opssl_sha256_update(&outer, ctx->key_pad, ctx->block_size);
        opssl_sha256_update(&outer, inner_hash, ctx->digest_size);
        opssl_sha256_final(&outer, out);
        break;
    }
    case OPSSL_HMAC_SHA384: {
        opssl_sha512_ctx_t outer;
        opssl_sha384_init(&outer);
        opssl_sha512_update(&outer, ctx->key_pad, ctx->block_size);
        opssl_sha512_update(&outer, inner_hash, ctx->digest_size);
        opssl_sha384_final(&outer, out);
        break;
    }
    case OPSSL_HMAC_SHA512: {
        opssl_sha512_ctx_t outer;
        opssl_sha512_init(&outer);
        opssl_sha512_update(&outer, ctx->key_pad, ctx->block_size);
        opssl_sha512_update(&outer, inner_hash, ctx->digest_size);
        opssl_sha512_final(&outer, out);
        break;
    }
    }

    if (out_len)
        *out_len = ctx->digest_size;

    opssl_memzero(inner_hash, sizeof(inner_hash));
    return 1;
}

void
opssl_hmac_cleanup(opssl_hmac_ctx_t *ctx)
{
    opssl_memzero(ctx, sizeof(*ctx));
}

int
opssl_hmac(opssl_hmac_algo_t algo,
           const uint8_t *key, size_t key_len,
           const void *data, size_t data_len,
           uint8_t *out, size_t *out_len)
{
    opssl_hmac_ctx_t ctx;
    if (!opssl_hmac_init(&ctx, algo, key, key_len))
        return 0;
    opssl_hmac_update(&ctx, data, data_len);
    return opssl_hmac_final(&ctx, out, out_len);
}

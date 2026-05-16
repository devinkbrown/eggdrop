/*
 * sha_internal.h — internal struct definitions for SHA contexts.
 *
 * Shared between sha256.c, sha512.c, sha3.c, hmac.c, hkdf.c, and TLS files
 * that need to embed or stack-allocate these contexts.
 *
 * Copyright (C) 2026 ophion development team
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef OPSSL_SHA_INTERNAL_H
#define OPSSL_SHA_INTERNAL_H

#include <stdint.h>
#include <stddef.h>

struct opssl_sha256_ctx {
    uint32_t state[8];
    uint64_t count;
    uint8_t  buf[64];
};

struct opssl_sha512_ctx {
    uint64_t state[8];
    uint64_t count[2];
    uint8_t  buf[128];
};


struct opssl_sha3_ctx {
    uint64_t state[25];
    uint8_t  buffer[168];
    size_t   buffer_len;
    size_t   rate;
    uint8_t  pad;
};

struct opssl_hmac_ctx {
    opssl_hmac_algo_t algo;
    uint8_t           key_pad[128];
    union {
        opssl_sha1_ctx_t sha1;
        struct opssl_sha256_ctx sha256;
        struct opssl_sha512_ctx sha512;
    } inner;
    size_t            block_size;
    size_t            digest_size;
};

#endif /* OPSSL_SHA_INTERNAL_H */

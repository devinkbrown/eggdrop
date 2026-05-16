/*
 * opssl/crypto/sha1.c — SHA-1 for legacy compatibility.
 *
 * SHA-1 is cryptographically broken (SHAttered attack) and MUST NOT be used
 * for new security purposes. This implementation exists for compatibility
 * with legacy certificate fingerprinting, HMAC-based KDFs, and signatures.
 *
 * Standard: FIPS PUB 180-4 (SHA-1)
 *
 * Copyright (C) 2026 ophion development team
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <opssl/crypto.h>
#include <opssl/platform.h>
#include <string.h>
#include "sha_internal.h"

/* SHA-1 constants (FIPS 180-4) */
#define SHA1_K0  0x5A827999UL
#define SHA1_K1  0x6ED9EBA1UL
#define SHA1_K2  0x8F1BBCDCUL
#define SHA1_K3  0xCA62C1D6UL

/* Initial hash values (FIPS 180-4 section 5.3.1) */
#define SHA1_H0  0x67452301UL
#define SHA1_H1  0xEFCDAB89UL
#define SHA1_H2  0x98BADCFEUL
#define SHA1_H3  0x10325476UL
#define SHA1_H4  0xC3D2E1F0UL


/* Left rotate */
static inline uint32_t
rotleft(uint32_t value, unsigned int shift)
{
    return (value << shift) | (value >> (32 - shift));
}

/* SHA-1 choice function: Ch(x,y,z) = (x ∧ y) ⊕ (¬x ∧ z) */
static inline uint32_t
ch(uint32_t x, uint32_t y, uint32_t z)
{
    return (x & y) ^ (~x & z);
}

/* SHA-1 parity function: Parity(x,y,z) = x ⊕ y ⊕ z */
static inline uint32_t
parity(uint32_t x, uint32_t y, uint32_t z)
{
    return x ^ y ^ z;
}

/* SHA-1 majority function: Maj(x,y,z) = (x ∧ y) ⊕ (x ∧ z) ⊕ (y ∧ z) */
static inline uint32_t
maj(uint32_t x, uint32_t y, uint32_t z)
{
    return (x & y) ^ (x & z) ^ (y & z);
}

/* Process a single 512-bit block */
static void
sha1_transform(opssl_sha1_ctx_t *ctx)
{
    uint32_t w[80];
    uint32_t a, b, c, d, e;
    uint32_t f, k, temp;
    int t;

    /* Prepare message schedule (FIPS 180-4 section 6.1.2) */
    for (t = 0; t < 16; t++) {
        w[t] = opssl_be32(&ctx->block[t * 4]);
    }

    for (t = 16; t < 80; t++) {
        w[t] = rotleft(w[t-3] ^ w[t-8] ^ w[t-14] ^ w[t-16], 1);
    }

    /* Initialize working variables */
    a = ctx->h[0];
    b = ctx->h[1];
    c = ctx->h[2];
    d = ctx->h[3];
    e = ctx->h[4];

    /* SHA-1 compression function (FIPS 180-4 section 6.1.2) */
    for (t = 0; t < 80; t++) {
        if (t < 20) {
            f = ch(b, c, d);
            k = SHA1_K0;
        } else if (t < 40) {
            f = parity(b, c, d);
            k = SHA1_K1;
        } else if (t < 60) {
            f = maj(b, c, d);
            k = SHA1_K2;
        } else {
            f = parity(b, c, d);
            k = SHA1_K3;
        }

        temp = rotleft(a, 5) + f + e + k + w[t];
        e = d;
        d = c;
        c = rotleft(b, 30);
        b = a;
        a = temp;
    }

    /* Add the working variables to the hash value */
    ctx->h[0] += a;
    ctx->h[1] += b;
    ctx->h[2] += c;
    ctx->h[3] += d;
    ctx->h[4] += e;
}

/* Initialize SHA-1 context */
void
opssl_sha1_init(opssl_sha1_ctx_t *ctx)
{
    ctx->h[0] = SHA1_H0;
    ctx->h[1] = SHA1_H1;
    ctx->h[2] = SHA1_H2;
    ctx->h[3] = SHA1_H3;
    ctx->h[4] = SHA1_H4;
    ctx->bitcount = 0;
    ctx->block_len = 0;
}

/* Process input data */
void
opssl_sha1_update(opssl_sha1_ctx_t *ctx, const void *data, size_t len)
{
    const uint8_t *p = data;
    size_t remaining = len;

    ctx->bitcount += len * 8;

    /* Fill current block */
    while (remaining > 0) {
        size_t chunk = 64 - ctx->block_len;
        if (chunk > remaining)
            chunk = remaining;

        memcpy(&ctx->block[ctx->block_len], p, chunk);
        ctx->block_len += chunk;
        p += chunk;
        remaining -= chunk;

        /* Process complete block */
        if (ctx->block_len == 64) {
            sha1_transform(ctx);
            ctx->block_len = 0;
        }
    }
}

/* Finalize hash computation */
void
opssl_sha1_final(opssl_sha1_ctx_t *ctx, uint8_t out[20])
{
    /* Append padding bit (FIPS 180-4 section 5.1.1) */
    ctx->block[ctx->block_len++] = 0x80;

    /* Pad to 56 bytes, leaving 8 bytes for length */
    if (ctx->block_len > 56) {
        /* Need another block for padding */
        memset(&ctx->block[ctx->block_len], 0, 64 - ctx->block_len);
        sha1_transform(ctx);
        ctx->block_len = 0;
    }

    /* Zero-fill to position 56 */
    memset(&ctx->block[ctx->block_len], 0, 56 - ctx->block_len);

    /* Append bit count as 64-bit big-endian */
    opssl_put_be64(&ctx->block[56], ctx->bitcount);

    /* Final transform */
    sha1_transform(ctx);

    /* Extract hash value as big-endian bytes */
    for (int i = 0; i < 5; i++) {
        opssl_put_be32(&out[i * 4], ctx->h[i]);
    }

    /* Clear sensitive data */
    opssl_memzero(ctx, sizeof(*ctx));
}

/* One-shot SHA-1 computation */
void
opssl_sha1(const void *data, size_t len, uint8_t out[20])
{
    opssl_sha1_ctx_t ctx;

    opssl_sha1_init(&ctx);
    opssl_sha1_update(&ctx, data, len);
    opssl_sha1_final(&ctx, out);
}

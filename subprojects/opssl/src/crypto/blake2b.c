/*
 * opssl/crypto/blake2b.c — BLAKE2b hash function (RFC 7693).
 *
 * Used internally by Argon2id. Supports keyed hashing (MAC mode)
 * and variable-length output (1..64 bytes). Little-endian throughout,
 * unlike the SHA family.
 *
 * Copyright (C) 2026 ophion development team
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <opssl/crypto.h>
#include <opssl/platform.h>
#include <string.h>

#define BLAKE2B_BLOCKBYTES 128

static const uint64_t blake2b_IV[8] = {
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
    0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
    0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
    0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL,
};

static const uint8_t blake2b_sigma[12][16] = {
    {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
    { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
    { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 },
    {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 },
    {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 },
    {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 },
    { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 },
    { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 },
    {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 },
    { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0 },
    {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
    { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
};

static inline uint64_t
load64_le(const uint8_t *p)
{
    return (uint64_t)p[0]       | (uint64_t)p[1] << 8  |
           (uint64_t)p[2] << 16 | (uint64_t)p[3] << 24 |
           (uint64_t)p[4] << 32 | (uint64_t)p[5] << 40 |
           (uint64_t)p[6] << 48 | (uint64_t)p[7] << 56;
}

static inline void
store64_le(uint8_t *p, uint64_t v)
{
    p[0] = (uint8_t)(v);       p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
    p[4] = (uint8_t)(v >> 32); p[5] = (uint8_t)(v >> 40);
    p[6] = (uint8_t)(v >> 48); p[7] = (uint8_t)(v >> 56);
}

static inline void
store32_le(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v);       p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

static inline uint64_t
rotr64(uint64_t x, unsigned n)
{
    return (x >> n) | (x << (64 - n));
}

#define G(r, i, a, b, c, d) do {                              \
    a = a + b + m[blake2b_sigma[r][2*i+0]];                   \
    d = rotr64(d ^ a, 32);                                    \
    c = c + d;                                                \
    b = rotr64(b ^ c, 24);                                    \
    a = a + b + m[blake2b_sigma[r][2*i+1]];                   \
    d = rotr64(d ^ a, 16);                                    \
    c = c + d;                                                \
    b = rotr64(b ^ c, 63);                                    \
} while (0)

static void
blake2b_compress(opssl_blake2b_ctx_t *ctx, const uint8_t block[BLAKE2B_BLOCKBYTES],
                 bool is_last)
{
    uint64_t m[16];
    uint64_t v[16];

    for (int i = 0; i < 16; i++)
        m[i] = load64_le(&block[i * 8]);

    for (int i = 0; i < 8; i++)
        v[i] = ctx->h[i];

    v[ 8] = blake2b_IV[0];
    v[ 9] = blake2b_IV[1];
    v[10] = blake2b_IV[2];
    v[11] = blake2b_IV[3];
    v[12] = blake2b_IV[4] ^ ctx->t[0];
    v[13] = blake2b_IV[5] ^ ctx->t[1];
    v[14] = blake2b_IV[6] ^ (is_last ? ~(uint64_t)0 : 0);
    v[15] = blake2b_IV[7];

    for (int r = 0; r < 12; r++) {
        G(r, 0, v[ 0], v[ 4], v[ 8], v[12]);
        G(r, 1, v[ 1], v[ 5], v[ 9], v[13]);
        G(r, 2, v[ 2], v[ 6], v[10], v[14]);
        G(r, 3, v[ 3], v[ 7], v[11], v[15]);
        G(r, 4, v[ 0], v[ 5], v[10], v[15]);
        G(r, 5, v[ 1], v[ 6], v[11], v[12]);
        G(r, 6, v[ 2], v[ 7], v[ 8], v[13]);
        G(r, 7, v[ 3], v[ 4], v[ 9], v[14]);
    }

    for (int i = 0; i < 8; i++)
        ctx->h[i] ^= v[i] ^ v[i + 8];
}

static void
blake2b_increment_counter(opssl_blake2b_ctx_t *ctx, uint64_t inc)
{
    ctx->t[0] += inc;
    if (ctx->t[0] < inc)
        ctx->t[1]++;
}

int
opssl_blake2b_init(opssl_blake2b_ctx_t *ctx, size_t outlen)
{
    if (outlen == 0 || outlen > OPSSL_BLAKE2B_DIGEST_LEN)
        return -1;

    memset(ctx, 0, sizeof(*ctx));

    for (int i = 0; i < 8; i++)
        ctx->h[i] = blake2b_IV[i];

    /* Parameter block: fanout=1, depth=1, digest_length=outlen */
    ctx->h[0] ^= 0x01010000 ^ outlen;
    ctx->outlen = outlen;

    return 0;
}

int
opssl_blake2b_init_key(opssl_blake2b_ctx_t *ctx, size_t outlen,
                       const void *key, size_t keylen)
{
    if (outlen == 0 || outlen > OPSSL_BLAKE2B_DIGEST_LEN)
        return -1;
    if (keylen == 0 || keylen > OPSSL_BLAKE2B_KEYBYTES)
        return -1;

    memset(ctx, 0, sizeof(*ctx));

    for (int i = 0; i < 8; i++)
        ctx->h[i] = blake2b_IV[i];

    /* Parameter block: fanout=1, depth=1, key_length, digest_length */
    ctx->h[0] ^= 0x01010000 ^ ((uint64_t)keylen << 8) ^ outlen;
    ctx->outlen = outlen;

    /* Pad key to block size and process as first block */
    uint8_t block[BLAKE2B_BLOCKBYTES];
    memset(block, 0, BLAKE2B_BLOCKBYTES);
    memcpy(block, key, keylen);
    opssl_blake2b_update(ctx, block, BLAKE2B_BLOCKBYTES);
    opssl_memzero(block, BLAKE2B_BLOCKBYTES);

    return 0;
}

void
opssl_blake2b_update(opssl_blake2b_ctx_t *ctx, const void *data, size_t len)
{
    const uint8_t *in = data;

    if (len == 0)
        return;

    size_t left = ctx->buflen;
    size_t fill = BLAKE2B_BLOCKBYTES - left;

    if (len > fill) {
        if (left) {
            memcpy(ctx->buf + left, in, fill);
            blake2b_increment_counter(ctx, BLAKE2B_BLOCKBYTES);
            blake2b_compress(ctx, ctx->buf, false);
            in += fill;
            len -= fill;
            ctx->buflen = 0;
        }

        while (len > BLAKE2B_BLOCKBYTES) {
            blake2b_increment_counter(ctx, BLAKE2B_BLOCKBYTES);
            blake2b_compress(ctx, in, false);
            in += BLAKE2B_BLOCKBYTES;
            len -= BLAKE2B_BLOCKBYTES;
        }
    }

    memcpy(ctx->buf + ctx->buflen, in, len);
    ctx->buflen += len;
}

void
opssl_blake2b_final(opssl_blake2b_ctx_t *ctx, uint8_t *out, size_t outlen)
{
    uint8_t buffer[OPSSL_BLAKE2B_DIGEST_LEN];

    blake2b_increment_counter(ctx, ctx->buflen);

    /* Zero-pad remaining buffer */
    memset(ctx->buf + ctx->buflen, 0, BLAKE2B_BLOCKBYTES - ctx->buflen);
    blake2b_compress(ctx, ctx->buf, true);

    /* Output in little-endian */
    for (int i = 0; i < 8; i++)
        store64_le(buffer + i * 8, ctx->h[i]);

    size_t copy = outlen < ctx->outlen ? outlen : ctx->outlen;
    memcpy(out, buffer, copy);
    opssl_memzero(buffer, sizeof(buffer));
    opssl_memzero(ctx, sizeof(*ctx));
}

void
opssl_blake2b(const void *data, size_t len, uint8_t *out, size_t outlen)
{
    opssl_blake2b_ctx_t ctx;
    opssl_blake2b_init(&ctx, outlen);
    opssl_blake2b_update(&ctx, data, len);
    opssl_blake2b_final(&ctx, out, outlen);
}

/*
 * BLAKE2b long output — produces variable-length digests > 64 bytes.
 * Used by Argon2id for expanding short hashes into full block-length output.
 * RFC 9106 §3.2: H' variable-length hash function.
 */
void
opssl_blake2b_long(const void *data, size_t len, uint8_t *out, size_t outlen)
{
    uint8_t outlen_le[4];
    store32_le(outlen_le, (uint32_t)outlen);

    if (outlen <= OPSSL_BLAKE2B_DIGEST_LEN) {
        opssl_blake2b_ctx_t ctx;
        opssl_blake2b_init(&ctx, outlen);
        opssl_blake2b_update(&ctx, outlen_le, 4);
        opssl_blake2b_update(&ctx, data, len);
        opssl_blake2b_final(&ctx, out, outlen);
        return;
    }

    /*
     * For outlen > 64: produce ceil(outlen/32) - 2 intermediate hashes
     * of 64 bytes each, taking the first 32 bytes of each. The final
     * hash produces (outlen - 32*floor((outlen-1)/32)) bytes.
     */
    uint8_t V[OPSSL_BLAKE2B_DIGEST_LEN];
    opssl_blake2b_ctx_t ctx;

    opssl_blake2b_init(&ctx, OPSSL_BLAKE2B_DIGEST_LEN);
    opssl_blake2b_update(&ctx, outlen_le, 4);
    opssl_blake2b_update(&ctx, data, len);
    opssl_blake2b_final(&ctx, V, OPSSL_BLAKE2B_DIGEST_LEN);

    memcpy(out, V, 32);
    out += 32;
    size_t remaining = outlen - 32;

    while (remaining > OPSSL_BLAKE2B_DIGEST_LEN) {
        opssl_blake2b_ctx_t inner;
        opssl_blake2b_init(&inner, OPSSL_BLAKE2B_DIGEST_LEN);
        opssl_blake2b_update(&inner, V, OPSSL_BLAKE2B_DIGEST_LEN);
        opssl_blake2b_final(&inner, V, OPSSL_BLAKE2B_DIGEST_LEN);

        memcpy(out, V, 32);
        out += 32;
        remaining -= 32;
    }

    opssl_blake2b_init(&ctx, remaining);
    opssl_blake2b_update(&ctx, V, OPSSL_BLAKE2B_DIGEST_LEN);
    opssl_blake2b_final(&ctx, out, remaining);

    opssl_memzero(V, sizeof(V));
}

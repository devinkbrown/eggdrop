/*
 * opssl/crypto/chacha20.c — ChaCha20 stream cipher (RFC 8439).
 *
 * Used in TLS as ChaCha20-Poly1305 AEAD. Preferred cipher for
 * mobile clients (no AES-NI) and kTLS offload.
 *
 * Copyright (C) 2026 ophion development team
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <opssl/platform.h>
#include <string.h>

#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

#define QR(a, b, c, d) do {  \
    a += b; d ^= a; d = ROTL32(d, 16); \
    c += d; b ^= c; b = ROTL32(b, 12); \
    a += b; d ^= a; d = ROTL32(d, 8);  \
    c += d; b ^= c; b = ROTL32(b, 7);  \
} while (0)

static void
chacha20_block(uint32_t out[16], const uint32_t in[16])
{
    uint32_t x[16];
    memcpy(x, in, sizeof(x));

    for (int i = 0; i < 10; i++) {
        /* Column rounds */
        QR(x[0], x[4], x[ 8], x[12]);
        QR(x[1], x[5], x[ 9], x[13]);
        QR(x[2], x[6], x[10], x[14]);
        QR(x[3], x[7], x[11], x[15]);
        /* Diagonal rounds */
        QR(x[0], x[5], x[10], x[15]);
        QR(x[1], x[6], x[11], x[12]);
        QR(x[2], x[7], x[ 8], x[13]);
        QR(x[3], x[4], x[ 9], x[14]);
    }

    for (int i = 0; i < 16; i++)
        out[i] = x[i] + in[i];
}

static inline uint32_t
load32_le(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static inline void
store32_le(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

void
opssl_chacha20(uint8_t *out, const uint8_t *in, size_t len,
               const uint8_t key[32], const uint8_t nonce[12],
               uint32_t counter)
{
    uint32_t state[16];

    /* "expand 32-byte k" */
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;

    /* Key */
    for (int i = 0; i < 8; i++)
        state[4 + i] = load32_le(key + i * 4);

    /* Counter + Nonce */
    state[12] = counter;
    state[13] = load32_le(nonce);
    state[14] = load32_le(nonce + 4);
    state[15] = load32_le(nonce + 8);

    uint32_t block[16];
    uint8_t keystream[64];

    while (len > 0) {
        chacha20_block(block, state);

        for (int i = 0; i < 16; i++)
            store32_le(keystream + i * 4, block[i]);

        size_t chunk = len < 64 ? len : 64;
        for (size_t i = 0; i < chunk; i++)
            out[i] = in[i] ^ keystream[i];

        out += chunk;
        in += chunk;
        len -= chunk;
        state[12]++;
    }

    opssl_memzero(state, sizeof(state));
    opssl_memzero(block, sizeof(block));
    opssl_memzero(keystream, sizeof(keystream));
}

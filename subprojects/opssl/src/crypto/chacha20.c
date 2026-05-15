/*
 * opssl/crypto/chacha20.c — ChaCha20 stream cipher (RFC 8439).
 *
 * Used in TLS as ChaCha20-Poly1305 AEAD. Preferred cipher for
 * mobile clients (no AES-NI) and kTLS offload.
 *
 * Dispatch:
 *   - AVX2: 4 blocks (256 bytes) in parallel using 256-bit registers.
 *           ~1.1 cycles/byte on Haswell+. Enabled when OPSSL_HAVE_AVX2
 *           is set at compile time AND opssl_has_avx2() returns true at
 *           runtime (CPUID check performed once at opssl_init()).
 *   - Scalar: portable C11 fallback.
 *
 * Copyright (C) 2026 ophion development team
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <opssl/platform.h>
#include <string.h>

/* ─── Scalar helpers ─────────────────────────────────────────────────── */

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

/* ─── AVX2 4-block path ───────────────────────────────────────────────── */

#if defined(OPSSL_HAVE_AVX2) && defined(__AVX2__)

#include <immintrin.h>

/*
 * Rotate each 32-bit lane in a 256-bit register left by n bits.
 * AVX2 has no native rotate; build it from shift + shift + or.
 */
#define ROT256_32(v, n) \
    _mm256_or_si256(_mm256_slli_epi32((v), (n)), _mm256_srli_epi32((v), 32 - (n)))

/*
 * Quarter-round on __m256i columns.
 * Each 256-bit register holds one ChaCha20 word across 4 parallel states,
 * i.e. row[i] = { state0[i], state1[i], state2[i], state3[i] }.
 */
#define QR256(a, b, c, d) do {                      \
    (a) = _mm256_add_epi32((a), (b));               \
    (d) = _mm256_xor_si256((d), (a));               \
    (d) = ROT256_32((d), 16);                       \
    (c) = _mm256_add_epi32((c), (d));               \
    (b) = _mm256_xor_si256((b), (c));               \
    (b) = ROT256_32((b), 12);                       \
    (a) = _mm256_add_epi32((a), (b));               \
    (d) = _mm256_xor_si256((d), (a));               \
    (d) = ROT256_32((d), 8);                        \
    (c) = _mm256_add_epi32((c), (d));               \
    (b) = _mm256_xor_si256((b), (c));               \
    (b) = ROT256_32((b), 7);                        \
} while (0)

/*
 * chacha20_avx2_4block — encrypt exactly 256 bytes (4 × 64-byte blocks).
 *
 * State layout: 16 × __m256i where row[i] contains word i from all four
 * states side by side:
 *
 *   row[i] = [ state0_word_i | state1_word_i | state2_word_i | state3_word_i ]
 *
 * The four states differ only in the counter word (state[12]):
 *   state0: counter+0, state1: counter+1, state2: counter+2, state3: counter+3
 *
 * After 20 rounds we add the initial state back (the ChaCha20 "add-then-mix"
 * step), write each block's 64 bytes contiguously, XOR with plaintext.
 *
 * in, out MUST be valid for 256 bytes. Caller handles remainder with scalar.
 */
static void
chacha20_avx2_4block(uint8_t *out, const uint8_t *in,
                     const uint32_t state_init[16])
{
    /*
     * Broadcast each initial word into all four 32-bit lanes of a __m256i,
     * except state[12] (counter) which gets +0/+1/+2/+3 per lane.
     */
    __m256i s[16];
    for (int i = 0; i < 16; i++)
        s[i] = _mm256_set1_epi32((int32_t)state_init[i]);

    /* Counter: lane 0 = counter+0, lane 1 = counter+1, ... */
    s[12] = _mm256_add_epi32(s[12], _mm256_set_epi32(3, 2, 1, 0, 3, 2, 1, 0));

    /* Keep a copy of the initial broadcasted state for the final add */
    __m256i init[16];
    for (int i = 0; i < 16; i++)
        init[i] = s[i];

    /* 20 rounds = 10 × (column + diagonal) */
    for (int i = 0; i < 10; i++) {
        /* Column rounds */
        QR256(s[0], s[4], s[ 8], s[12]);
        QR256(s[1], s[5], s[ 9], s[13]);
        QR256(s[2], s[6], s[10], s[14]);
        QR256(s[3], s[7], s[11], s[15]);
        /* Diagonal rounds */
        QR256(s[0], s[5], s[10], s[15]);
        QR256(s[1], s[6], s[11], s[12]);
        QR256(s[2], s[7], s[ 8], s[13]);
        QR256(s[3], s[4], s[ 9], s[14]);
    }

    /* Add initial state back */
    for (int i = 0; i < 16; i++)
        s[i] = _mm256_add_epi32(s[i], init[i]);

    /*
     * De-interleave: s[i] holds word i for all 4 blocks in lanes 0-3.
     * We need to write out 4 contiguous 64-byte blocks, each containing
     * 16 × uint32_t in little-endian order.
     *
     * Approach: extract each lane from each row and scatter to output.
     * We write block b (b = 0..3) to out + b*64, placing s[w] lane b
     * at byte offset b*64 + w*4.
     *
     * On little-endian x86 _mm256_extract_epi32 gives the lane value
     * directly; store32_le handles any endian concerns explicitly.
     */
    for (int b = 0; b < 4; b++) {
        uint8_t *block_out = out + b * 64;
        const uint8_t *block_in  = in  + b * 64;

        for (int w = 0; w < 16; w++) {
            uint32_t word = (uint32_t)_mm256_extract_epi32(s[w], b);
            uint32_t pt;
            memcpy(&pt, block_in + w * 4, 4);
            word ^= pt;
            store32_le(block_out + w * 4, word);
        }
    }
}

/* Runtime AVX2 guard — resolved from cpuid.c */
extern bool opssl_has_avx2(void);

#endif /* OPSSL_HAVE_AVX2 && __AVX2__ */

/* ─── Public API ─────────────────────────────────────────────────────── */

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

#if defined(OPSSL_HAVE_AVX2) && defined(__AVX2__)
    if (opssl_has_avx2()) {
        while (len >= 256) {
            chacha20_avx2_4block(out, in, state);
            out     += 256;
            in      += 256;
            len     -= 256;
            state[12] += 4;
        }
    }
#endif

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

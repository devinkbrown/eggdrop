/*
 * opssl/crypto/sha256_ni.c — SHA-NI accelerated SHA-256 implementation.
 *
 * Hardware-accelerated SHA-256 using Intel SHA-NI instructions.
 * Dispatched from sha256.c when opssl_has_sha_ni() returns true.
 *
 * Performance: ~3-4x speedup vs software implementation.
 * SHA-256 underlies HMAC, HKDF, and all TLS key derivation.
 *
 * Copyright (C) 2026 ophion development team
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <opssl/platform.h>
#include <string.h>

#if defined(__x86_64__) && defined(__SHA__)

#include <immintrin.h>
#include <emmintrin.h>

/* SHA-256 round constants for SHA-NI */
static const uint32_t SHA256_K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

/*
 * Load a 32-bit big-endian value.
 * Equivalent to opssl_be32() but inlined for performance.
 */
static inline uint32_t
load_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) |
           ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] <<  8) |
           ((uint32_t)p[3]      );
}

/*
 * SHA-NI accelerated SHA-256 transform for one or more 64-byte blocks.
 *
 * This function processes blocks using Intel SHA-NI instructions:
 * - _mm_sha256rnds2_epu32: performs 2 rounds of SHA-256
 * - _mm_sha256msg1_epu32: message schedule part 1
 * - _mm_sha256msg2_epu32: message schedule part 2
 *
 * The algorithm follows Intel's SHA-NI programming guide, processing
 * 4 message words per round with the standard message schedule.
 */
void
opssl_sha256_ni_transform(uint32_t state[8], const uint8_t *data, size_t nblocks)
{
    __m128i state0, state1;
    __m128i msg0, msg1, msg2, msg3;
    __m128i tmp;

    /*
     * Intel SHA-NI uses an interleaved state layout:
     *   state0 = ABEF  (lanes [3]=A, [2]=B, [1]=E, [0]=F)
     *   state1 = CDGH  (lanes [3]=C, [2]=D, [1]=G, [0]=H)
     *
     * _mm_sha256rnds2_epu32(dst, src, k):
     *   dst = CDGH, src = ABEF  →  returns new CDGH
     *
     * Load from standard state[0..7] = {A,B,C,D,E,F,G,H} using
     * the Intel reference shuffle sequence.
     */
    __m128i t0 = _mm_loadu_si128((const __m128i *)&state[0]);
    __m128i t1 = _mm_loadu_si128((const __m128i *)&state[4]);
    t0     = _mm_shuffle_epi32(t0, 0xB1);
    t1     = _mm_shuffle_epi32(t1, 0x1B);
    state0 = _mm_alignr_epi8(t0, t1, 8);
    state1 = _mm_blend_epi16(t1, t0, 0xF0);

    /* Process each 64-byte block */
    for (size_t block = 0; block < nblocks; block++) {
        __m128i save_state0 = state0;
        __m128i save_state1 = state1;

        /* Load message words 0-15 and convert from big-endian */
        msg0 = _mm_setr_epi32(
            load_be32(data + 0),  load_be32(data + 4),
            load_be32(data + 8),  load_be32(data + 12)
        );
        msg1 = _mm_setr_epi32(
            load_be32(data + 16), load_be32(data + 20),
            load_be32(data + 24), load_be32(data + 28)
        );
        msg2 = _mm_setr_epi32(
            load_be32(data + 32), load_be32(data + 36),
            load_be32(data + 40), load_be32(data + 44)
        );
        msg3 = _mm_setr_epi32(
            load_be32(data + 48), load_be32(data + 52),
            load_be32(data + 56), load_be32(data + 60)
        );

        /* Rounds 0-3 */
        tmp = _mm_add_epi32(msg0, _mm_setr_epi32(SHA256_K[0], SHA256_K[1], SHA256_K[2], SHA256_K[3]));
        state1 = _mm_sha256rnds2_epu32(state1, state0, tmp);
        tmp = _mm_unpackhi_epi64(tmp, tmp);
        state0 = _mm_sha256rnds2_epu32(state0, state1, tmp);

        /* Rounds 4-7 */
        tmp = _mm_add_epi32(msg1, _mm_setr_epi32(SHA256_K[4], SHA256_K[5], SHA256_K[6], SHA256_K[7]));
        state1 = _mm_sha256rnds2_epu32(state1, state0, tmp);
        tmp = _mm_unpackhi_epi64(tmp, tmp);
        state0 = _mm_sha256rnds2_epu32(state0, state1, tmp);

        /* Rounds 8-11 */
        tmp = _mm_add_epi32(msg2, _mm_setr_epi32(SHA256_K[8], SHA256_K[9], SHA256_K[10], SHA256_K[11]));
        state1 = _mm_sha256rnds2_epu32(state1, state0, tmp);
        tmp = _mm_unpackhi_epi64(tmp, tmp);
        state0 = _mm_sha256rnds2_epu32(state0, state1, tmp);

        /* Rounds 12-15 */
        tmp = _mm_add_epi32(msg3, _mm_setr_epi32(SHA256_K[12], SHA256_K[13], SHA256_K[14], SHA256_K[15]));
        state1 = _mm_sha256rnds2_epu32(state1, state0, tmp);
        tmp = _mm_unpackhi_epi64(tmp, tmp);
        state0 = _mm_sha256rnds2_epu32(state0, state1, tmp);

        /* Process rounds 16-63 with message schedule */
        for (int round = 16; round < 64; round += 4) {
            /* Message schedule: compute next 4 message words */
            msg0 = _mm_sha256msg1_epu32(msg0, msg1);
            tmp = _mm_alignr_epi8(msg3, msg2, 4);
            msg0 = _mm_add_epi32(msg0, tmp);
            msg0 = _mm_sha256msg2_epu32(msg0, msg3);

            /* Perform 4 SHA-256 rounds */
            tmp = _mm_add_epi32(msg0, _mm_setr_epi32(
                SHA256_K[round + 0], SHA256_K[round + 1],
                SHA256_K[round + 2], SHA256_K[round + 3]
            ));
            state1 = _mm_sha256rnds2_epu32(state1, state0, tmp);
            tmp = _mm_unpackhi_epi64(tmp, tmp);
            state0 = _mm_sha256rnds2_epu32(state0, state1, tmp);

            /* Rotate message words for next iteration */
            __m128i msg_tmp = msg0;
            msg0 = msg1;
            msg1 = msg2;
            msg2 = msg3;
            msg3 = msg_tmp;
        }

        /* Add the working variables to the hash state */
        state0 = _mm_add_epi32(state0, save_state0);
        state1 = _mm_add_epi32(state1, save_state1);

        data += 64;
    }

    /* Reverse the ABEF/CDGH interleaving back to {A,B,C,D} {E,F,G,H} */
    t0     = _mm_shuffle_epi32(state0, 0x1B);
    state1 = _mm_shuffle_epi32(state1, 0xB1);
    state0 = _mm_blend_epi16(t0, state1, 0xF0);
    state1 = _mm_alignr_epi8(state1, t0, 8);

    _mm_storeu_si128((__m128i *)&state[0], state0);
    _mm_storeu_si128((__m128i *)&state[4], state1);
}

#else /* No SHA-NI support */

/*
 * Stub implementation when SHA-NI is not available.
 * This should never be called due to the dispatch in sha256.c.
 */
void
opssl_sha256_ni_transform(uint32_t state[8], const uint8_t *data, size_t nblocks)
{
    (void)state;
    (void)data;
    (void)nblocks;
    /* This function should not be called on non-x86 or SHA-NI-less platforms */
}

#endif /* __x86_64__ && __SHA__ */
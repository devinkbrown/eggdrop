/*
 * opssl/crypto/argon2id.c — Argon2id password hashing (RFC 9106).
 *
 * Memory-hard key derivation function. Hybrid of Argon2i (data-independent
 * indexing for first half-passes) and Argon2d (data-dependent for second
 * half-passes). Default parameters: t=3, m=65536 (64 MiB), p=4.
 *
 * Internal hash function is BLAKE2b throughout.
 *
 * Copyright (C) 2026 ophion development team
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <opssl/crypto.h>
#include <opssl/platform.h>
#include <stdint.h>
#include <string.h>

/* Argon2 block = 1024 bytes = 128 uint64_t */
#define ARGON2_BLOCK_SIZE   1024
#define ARGON2_QWORDS       128
#define ARGON2_SYNC_POINTS  4
#define ARGON2_VERSION      0x13

/* Argon2id type tag */
#define ARGON2_TYPE_ID      2

struct argon2_block {
    uint64_t v[ARGON2_QWORDS];
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

static inline uint64_t
fBlaMka(uint64_t x, uint64_t y)
{
    uint64_t m = 0xFFFFFFFFULL;
    uint64_t xy = (x & m) * (y & m);
    return x + y + 2 * xy;
}

#define BLAKE2B_G(a, b, c, d) do {      \
    a = fBlaMka(a, b);                   \
    d = rotr64(d ^ a, 32);              \
    c = fBlaMka(c, d);                   \
    b = rotr64(b ^ c, 24);              \
    a = fBlaMka(a, b);                   \
    d = rotr64(d ^ a, 16);              \
    c = fBlaMka(c, d);                   \
    b = rotr64(b ^ c, 63);              \
} while (0)

#define BLAKE2B_ROUND(v0, v1, v2, v3, v4, v5, v6, v7,   \
                      v8, v9, v10, v11, v12, v13, v14, v15) do { \
    BLAKE2B_G(v0, v4,  v8, v12);                         \
    BLAKE2B_G(v1, v5,  v9, v13);                         \
    BLAKE2B_G(v2, v6, v10, v14);                         \
    BLAKE2B_G(v3, v7, v11, v15);                         \
    BLAKE2B_G(v0, v5, v10, v15);                         \
    BLAKE2B_G(v1, v6, v11, v12);                         \
    BLAKE2B_G(v2, v7,  v8, v13);                         \
    BLAKE2B_G(v3, v4,  v9, v14);                         \
} while (0)

static void
argon2_fill_block(const struct argon2_block *prev, const struct argon2_block *ref,
                  struct argon2_block *next, bool xor_mode)
{
    struct argon2_block tmp;

    for (int i = 0; i < ARGON2_QWORDS; i++)
        tmp.v[i] = prev->v[i] ^ ref->v[i];

    struct argon2_block block_copy;
    memcpy(&block_copy, &tmp, sizeof(tmp));

    /* Apply two rounds of BLAKE2b-based permutation (RFC 9106 §3.4) */
    /* Row-wise */
    for (int i = 0; i < 8; i++) {
        uint64_t *row = &tmp.v[i * 16];
        BLAKE2B_ROUND(row[ 0], row[ 1], row[ 2], row[ 3],
                      row[ 4], row[ 5], row[ 6], row[ 7],
                      row[ 8], row[ 9], row[10], row[11],
                      row[12], row[13], row[14], row[15]);
    }

    /* Column-wise */
    for (int i = 0; i < 8; i++) {
        uint64_t *v = tmp.v;
        BLAKE2B_ROUND(v[i*2],    v[i*2 + 1],  v[i*2 + 16], v[i*2 + 17],
                      v[i*2 + 32], v[i*2 + 33], v[i*2 + 48], v[i*2 + 49],
                      v[i*2 + 64], v[i*2 + 65], v[i*2 + 80], v[i*2 + 81],
                      v[i*2 + 96], v[i*2 + 97], v[i*2 + 112], v[i*2 + 113]);
    }

    if (xor_mode) {
        for (int i = 0; i < ARGON2_QWORDS; i++)
            next->v[i] ^= tmp.v[i] ^ block_copy.v[i];
    } else {
        for (int i = 0; i < ARGON2_QWORDS; i++)
            next->v[i] = tmp.v[i] ^ block_copy.v[i];
    }
}

/*
 * Generate addresses for Argon2i/Argon2id data-independent indexing.
 * RFC 9106 §3.3.
 */
static void
argon2_gen_addresses(uint64_t *pseudo_rands, uint32_t pass, uint32_t lane,
                     uint32_t slice, uint32_t total_blocks,
                     uint32_t segment_length, uint32_t t_cost)
{
    struct argon2_block zero_block, input_block, addr_block;

    memset(&zero_block, 0, sizeof(zero_block));
    memset(&input_block, 0, sizeof(input_block));

    input_block.v[0] = pass;
    input_block.v[1] = lane;
    input_block.v[2] = slice;
    input_block.v[3] = total_blocks;
    input_block.v[4] = t_cost;
    input_block.v[5] = ARGON2_TYPE_ID;

    for (uint32_t i = 0; i < segment_length; i++) {
        uint32_t addr_index = i % ARGON2_QWORDS;
        if (addr_index == 0) {
            input_block.v[6] = i / ARGON2_QWORDS + 1;
            argon2_fill_block(&zero_block, &input_block, &addr_block, false);
            argon2_fill_block(&zero_block, &addr_block, &addr_block, false);
        }
        pseudo_rands[i] = addr_block.v[addr_index];
    }
}

static uint32_t
argon2_index_alpha(uint64_t pseudo_rand, uint32_t lane, uint32_t pass,
                   uint32_t slice, uint32_t index, uint32_t segment_length,
                   uint32_t lanes, uint32_t total_blocks)
{
    uint32_t ref_lane;
    uint32_t reference_area_size;

    uint32_t position = lane * (total_blocks / lanes) + slice * segment_length + index;
    (void)position;

    /* Determine reference lane */
    ref_lane = (uint32_t)((pseudo_rand >> 32) % lanes);
    if (pass == 0 && slice == 0)
        ref_lane = lane;

    /* Determine reference area size (RFC 9106 §3.3) */
    if (pass == 0) {
        if (slice == 0)
            reference_area_size = (index == 0) ? 0 : index - 1;
        else if (ref_lane == lane)
            reference_area_size = slice * segment_length + (index == 0 ? 0 : index - 1);
        else
            reference_area_size = slice * segment_length - (index == 0 ? 1 : 0);
    } else {
        if (ref_lane == lane)
            reference_area_size = (total_blocks / lanes) - segment_length
                                  + (index == 0 ? 0 : index - 1);
        else
            reference_area_size = (total_blocks / lanes) - segment_length
                                  - (index == 0 ? 1 : 0);
    }

    /*
     * Guard against zero/empty reference area: caller must not invoke us when
     * no candidates exist, but defend in depth to avoid uint32 underflow that
     * would otherwise wrap to ~4G and index out of bounds.
     */
    if (reference_area_size == 0)
        return ref_lane * (total_blocks / lanes);

    /* Map pseudo_rand to reference block index (RFC 9106 §3.4.1.2) */
    uint64_t relative_position = pseudo_rand & 0xFFFFFFFFULL;
    relative_position = (relative_position * relative_position) >> 32;
    relative_position = reference_area_size - 1
                        - ((uint64_t)reference_area_size * relative_position >> 32);

    /* Calculate starting position */
    uint32_t start_position;
    if (pass == 0)
        start_position = 0;
    else
        start_position = (slice + 1) * segment_length;

    return ref_lane * (total_blocks / lanes) +
           (start_position + (uint32_t)relative_position) % (total_blocks / lanes);
}

int
opssl_argon2id(const uint8_t *password, size_t password_len,
               const uint8_t *salt, size_t salt_len,
               uint32_t t_cost, uint32_t m_cost, uint32_t parallelism,
               uint8_t *out, size_t out_len)
{
    /*
     * Per RFC 9106 §3.1:
     *   - parallelism (p): 1..2^24-1
     *   - tag length (out_len): 4..2^32-1 (we additionally cap at 64 because
     *     verify() compares against a 64-byte buffer)
     *   - salt length: >= 8
     *   - m_cost: >= 8 * p
     *   - t_cost: >= 1, <= 2^32-1
     */
    if (salt_len < 8 || out_len < 4 || out_len > 64)
        return -1;
    if (t_cost < 1)
        return -1;
    if (parallelism < 1 || parallelism > (1u << 24) - 1)
        return -1;
    if (m_cost < 8u * parallelism)
        return -1;

    /* Determine memory layout — segment_length must be >= 2 per RFC 9106 */
    uint32_t segment_length = m_cost / (parallelism * ARGON2_SYNC_POINTS);
    if (segment_length < 2)
        return -1;
    uint32_t lane_length = segment_length * ARGON2_SYNC_POINTS;
    uint32_t total_blocks = lane_length * parallelism;

    /* Reject size_t overflow on memory allocation (matters on 32-bit hosts) */
    if (total_blocks == 0)
        return -1;
#if SIZE_MAX < (4294967295ULL * 1024ULL)
    if (total_blocks > SIZE_MAX / sizeof(struct argon2_block))
        return -1;
#endif

    /* Allocate memory blocks */
    struct argon2_block *memory = op_calloc(total_blocks, sizeof(struct argon2_block));
    if (!memory)
        return -1;

    /*
     * Initial hash H0 = BLAKE2b-64(
     *   LE32(p) || LE32(T) || LE32(m) || LE32(t) || LE32(v) || LE32(y)
     *   || LE32(|P|) || P || LE32(|S|) || S
     *   || LE32(|X|) || X || LE32(|K|) || K
     * )
     * X = associated data (empty here), K = secret key (empty here)
     */
    uint8_t H0[OPSSL_BLAKE2B_DIGEST_LEN];
    {
        opssl_blake2b_ctx_t h0_ctx;
        uint8_t le32[4];

        opssl_blake2b_init(&h0_ctx, OPSSL_BLAKE2B_DIGEST_LEN);

        store32_le(le32, parallelism);
        opssl_blake2b_update(&h0_ctx, le32, 4);

        store32_le(le32, (uint32_t)out_len);
        opssl_blake2b_update(&h0_ctx, le32, 4);

        store32_le(le32, m_cost);
        opssl_blake2b_update(&h0_ctx, le32, 4);

        store32_le(le32, t_cost);
        opssl_blake2b_update(&h0_ctx, le32, 4);

        store32_le(le32, ARGON2_VERSION);
        opssl_blake2b_update(&h0_ctx, le32, 4);

        store32_le(le32, ARGON2_TYPE_ID);
        opssl_blake2b_update(&h0_ctx, le32, 4);

        store32_le(le32, (uint32_t)password_len);
        opssl_blake2b_update(&h0_ctx, le32, 4);
        opssl_blake2b_update(&h0_ctx, password, password_len);

        store32_le(le32, (uint32_t)salt_len);
        opssl_blake2b_update(&h0_ctx, le32, 4);
        opssl_blake2b_update(&h0_ctx, salt, salt_len);

        /* No secret key */
        store32_le(le32, 0);
        opssl_blake2b_update(&h0_ctx, le32, 4);

        /* No associated data */
        store32_le(le32, 0);
        opssl_blake2b_update(&h0_ctx, le32, 4);

        opssl_blake2b_final(&h0_ctx, H0, OPSSL_BLAKE2B_DIGEST_LEN);
    }

    /* Initialize first two blocks of each lane */
    for (uint32_t lane = 0; lane < parallelism; lane++) {
        uint8_t input[72]; /* H0 || LE32(0/1) || LE32(lane) */
        memcpy(input, H0, OPSSL_BLAKE2B_DIGEST_LEN);

        /* B[lane][0] = H'(H0 || 0 || lane) */
        store32_le(input + 64, 0);
        store32_le(input + 68, lane);
        opssl_blake2b_long(input, 72,
                           (uint8_t *)memory[lane * lane_length].v,
                           ARGON2_BLOCK_SIZE);

        /* B[lane][1] = H'(H0 || 1 || lane) */
        store32_le(input + 64, 1);
        opssl_blake2b_long(input, 72,
                           (uint8_t *)memory[lane * lane_length + 1].v,
                           ARGON2_BLOCK_SIZE);
    }

    opssl_memzero(H0, sizeof(H0));

    /* Main passes */
    for (uint32_t pass = 0; pass < t_cost; pass++) {
        for (uint32_t slice = 0; slice < ARGON2_SYNC_POINTS; slice++) {
            for (uint32_t lane = 0; lane < parallelism; lane++) {
                uint32_t start_index = (pass == 0 && slice == 0) ? 2 : 0;

                /* Argon2id: data-independent for first half of pass 0 */
                bool use_di = (pass == 0 && slice < ARGON2_SYNC_POINTS / 2);

                uint64_t *pseudo_rands = NULL;
                if (use_di) {
                    pseudo_rands = op_malloc(segment_length * sizeof(uint64_t));
                    if (!pseudo_rands) {
                        /*
                         * Fail-closed: silently falling back to data-dependent
                         * indexing would violate the Argon2id contract for the
                         * data-independent half of pass 0 (RFC 9106 §3.4) and
                         * leak password material via timing.
                         */
                        opssl_memzero(memory,
                                      (size_t)total_blocks * sizeof(struct argon2_block));
                        op_free(memory);
                        return -1;
                    }
                    argon2_gen_addresses(pseudo_rands, pass, lane, slice,
                                         total_blocks, segment_length, t_cost);
                }

                for (uint32_t index = start_index; index < segment_length; index++) {
                    uint32_t cur = lane * lane_length + slice * segment_length + index;
                    uint32_t prev = (cur == lane * lane_length)
                                    ? lane * lane_length + lane_length - 1
                                    : cur - 1;

                    uint64_t pseudo_rand;
                    if (use_di && pseudo_rands)
                        pseudo_rand = pseudo_rands[index];
                    else
                        pseudo_rand = memory[prev].v[0];

                    uint32_t ref = argon2_index_alpha(pseudo_rand, lane, pass, slice,
                                                      index, segment_length,
                                                      parallelism, total_blocks);

                    bool xor_mode = (pass > 0);
                    argon2_fill_block(&memory[prev], &memory[ref],
                                      &memory[cur], xor_mode);
                }

                if (pseudo_rands) {
                    opssl_memzero(pseudo_rands,
                                  segment_length * sizeof(uint64_t));
                    op_free(pseudo_rands);
                    pseudo_rands = NULL;
                }
            }
        }
    }

    /* XOR last blocks of all lanes → final block */
    struct argon2_block final_block;
    memcpy(&final_block, &memory[(parallelism - 1) * lane_length + lane_length - 1],
           sizeof(final_block));

    for (uint32_t lane = 0; lane < parallelism - 1; lane++) {
        uint32_t last = lane * lane_length + lane_length - 1;
        for (int i = 0; i < ARGON2_QWORDS; i++)
            final_block.v[i] ^= memory[last].v[i];
    }

    /* Produce output via H' */
    opssl_blake2b_long((const uint8_t *)final_block.v, ARGON2_BLOCK_SIZE,
                       out, out_len);

    /* Cleanup */
    opssl_memzero(memory, (size_t)total_blocks * sizeof(struct argon2_block));
    op_free(memory);
    opssl_memzero(&final_block, sizeof(final_block));

    return 0;
}

/*
 * Verify a password against an Argon2id hash.
 * Constant-time comparison to prevent timing side-channels.
 */
int
opssl_argon2id_verify(const uint8_t *password, size_t password_len,
                      const uint8_t *salt, size_t salt_len,
                      uint32_t t_cost, uint32_t m_cost, uint32_t parallelism,
                      const uint8_t *expected, size_t expected_len)
{
    uint8_t computed[64];

    /*
     * RFC 9106 caps tag length at 2^32-1, but this unkeyed implementation
     * derives the tag from a single BLAKE2b-512 invocation and stores it in
     * a 64-byte stack buffer. Reject anything larger to avoid truncated
     * comparisons that would accept partial matches.
     */
    if (expected_len < 4 || expected_len > sizeof(computed))
        return -1;

    int ret = opssl_argon2id(password, password_len, salt, salt_len,
                             t_cost, m_cost, parallelism,
                             computed, expected_len);
    if (ret != 0) {
        opssl_memzero(computed, sizeof(computed));
        return -1;
    }

    int match = opssl_ct_eq(computed, expected, expected_len);
    opssl_memzero(computed, sizeof(computed));

    return match ? 0 : -1;
}

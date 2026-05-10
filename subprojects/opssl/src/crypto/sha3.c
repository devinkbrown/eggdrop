#include <opssl/crypto.h>
#include <opssl/platform.h>
#include <string.h>
#include "sha_internal.h"

static const uint64_t RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
    0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800aULL,
    0x800000008000000aULL, 0x8000000080008081ULL, 0x8000000000008080ULL,
    0x0000000080000001ULL, 0x8000000080008008ULL, 0x8000000000008000ULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL
};

static const unsigned int rho_offsets[25] = {
     0,  1, 62, 28, 27, 36, 44,  6, 55, 20,
     3, 10, 43, 25, 39, 41, 45, 15, 21,  8,
    18,  2, 61, 56, 14
};

static inline uint64_t rotl64(uint64_t x, unsigned int n) {
    return (x << n) | (x >> (64 - n));
}

static void keccak_f1600(uint64_t state[25]) {
    uint64_t C[5], D[5], B[25];

    for (int round = 0; round < 24; round++) {
        // θ step
        C[0] = state[0] ^ state[5] ^ state[10] ^ state[15] ^ state[20];
        C[1] = state[1] ^ state[6] ^ state[11] ^ state[16] ^ state[21];
        C[2] = state[2] ^ state[7] ^ state[12] ^ state[17] ^ state[22];
        C[3] = state[3] ^ state[8] ^ state[13] ^ state[18] ^ state[23];
        C[4] = state[4] ^ state[9] ^ state[14] ^ state[19] ^ state[24];

        D[0] = C[4] ^ rotl64(C[1], 1);
        D[1] = C[0] ^ rotl64(C[2], 1);
        D[2] = C[1] ^ rotl64(C[3], 1);
        D[3] = C[2] ^ rotl64(C[4], 1);
        D[4] = C[3] ^ rotl64(C[0], 1);

        for (int i = 0; i < 25; i++) {
            state[i] ^= D[i % 5];
        }

        // ρ and π steps
        for (int i = 0; i < 25; i++) {
            int j = (i * 6 + (i / 5) * 3) % 25;
            B[j] = rotl64(state[i], rho_offsets[i]);
        }

        // χ step
        for (int y = 0; y < 5; y++) {
            for (int x = 0; x < 5; x++) {
                int i = 5 * y + x;
                state[i] = B[i] ^ ((~B[5 * y + ((x + 1) % 5)]) & B[5 * y + ((x + 2) % 5)]);
            }
        }

        // ι step
        state[0] ^= RC[round];
    }
}

static void keccak_init(opssl_sha3_ctx_t *ctx, size_t rate, uint8_t pad) {
    opssl_memzero(ctx, sizeof(*ctx));
    ctx->rate = rate;
    ctx->pad = pad;
}

static void keccak_update(opssl_sha3_ctx_t *ctx, const void *data, size_t len) {
    const uint8_t *input = (const uint8_t *)data;
    size_t remaining = len;

    while (remaining > 0) {
        size_t to_copy = ctx->rate - ctx->buffer_len;
        if (to_copy > remaining) {
            to_copy = remaining;
        }

        memcpy(ctx->buffer + ctx->buffer_len, input, to_copy);
        ctx->buffer_len += to_copy;
        input += to_copy;
        remaining -= to_copy;

        if (ctx->buffer_len == ctx->rate) {
            // Absorb block
            for (size_t i = 0; i < ctx->rate; i += 8) {
                size_t lane = i / 8;
                uint64_t value = 0;
                size_t bytes_to_read = ctx->rate - i;
                if (bytes_to_read > 8) {
                    bytes_to_read = 8;
                }

                for (size_t j = 0; j < bytes_to_read; j++) {
                    value |= ((uint64_t)ctx->buffer[i + j]) << (8 * j);
                }
                ctx->state[lane] ^= value;
            }

            keccak_f1600(ctx->state);
            ctx->buffer_len = 0;
        }
    }
}

static void keccak_final(opssl_sha3_ctx_t *ctx, uint8_t *out, size_t out_len) {
    // Padding
    ctx->buffer[ctx->buffer_len] = ctx->pad;
    if (ctx->buffer_len == ctx->rate - 1) {
        ctx->buffer[ctx->buffer_len] |= 0x80;
    } else {
        opssl_memzero(ctx->buffer + ctx->buffer_len + 1, ctx->rate - ctx->buffer_len - 2);
        ctx->buffer[ctx->rate - 1] = 0x80;
    }

    // Final absorption
    for (size_t i = 0; i < ctx->rate; i += 8) {
        size_t lane = i / 8;
        uint64_t value = 0;
        size_t bytes_to_read = ctx->rate - i;
        if (bytes_to_read > 8) {
            bytes_to_read = 8;
        }

        for (size_t j = 0; j < bytes_to_read; j++) {
            value |= ((uint64_t)ctx->buffer[i + j]) << (8 * j);
        }
        ctx->state[lane] ^= value;
    }

    keccak_f1600(ctx->state);

    // Squeeze output
    size_t output_offset = 0;
    while (output_offset < out_len) {
        size_t to_squeeze = out_len - output_offset;
        if (to_squeeze > ctx->rate) {
            to_squeeze = ctx->rate;
        }

        for (size_t i = 0; i < to_squeeze; i += 8) {
            size_t lane = i / 8;
            uint64_t value = ctx->state[lane];
            size_t bytes_to_write = to_squeeze - i;
            if (bytes_to_write > 8) {
                bytes_to_write = 8;
            }

            for (size_t j = 0; j < bytes_to_write; j++) {
                out[output_offset + i + j] = (uint8_t)(value >> (8 * j));
            }
        }

        output_offset += to_squeeze;

        if (output_offset < out_len) {
            keccak_f1600(ctx->state);
        }
    }

    opssl_memzero(ctx, sizeof(*ctx));
}

void opssl_sha3_256_init(opssl_sha3_ctx_t *ctx) {
    keccak_init(ctx, 136, 0x06);
}

void opssl_sha3_256_update(opssl_sha3_ctx_t *ctx, const void *data, size_t len) {
    keccak_update(ctx, data, len);
}

void opssl_sha3_256_final(opssl_sha3_ctx_t *ctx, uint8_t out[32]) {
    keccak_final(ctx, out, 32);
}

void opssl_sha3_256(const void *data, size_t len, uint8_t out[32]) {
    opssl_sha3_ctx_t ctx;
    opssl_sha3_256_init(&ctx);
    opssl_sha3_256_update(&ctx, data, len);
    opssl_sha3_256_final(&ctx, out);
}

void opssl_sha3_512_init(opssl_sha3_ctx_t *ctx) {
    keccak_init(ctx, 72, 0x06);
}

void opssl_sha3_512_update(opssl_sha3_ctx_t *ctx, const void *data, size_t len) {
    keccak_update(ctx, data, len);
}

void opssl_sha3_512_final(opssl_sha3_ctx_t *ctx, uint8_t out[64]) {
    keccak_final(ctx, out, 64);
}

void opssl_sha3_512(const void *data, size_t len, uint8_t out[64]) {
    opssl_sha3_ctx_t ctx;
    opssl_sha3_512_init(&ctx);
    opssl_sha3_512_update(&ctx, data, len);
    opssl_sha3_512_final(&ctx, out);
}

void opssl_shake128(uint8_t *out, size_t out_len, const uint8_t *in, size_t in_len) {
    opssl_sha3_ctx_t ctx;
    keccak_init(&ctx, 168, 0x1F);
    keccak_update(&ctx, in, in_len);
    keccak_final(&ctx, out, out_len);
}

void opssl_shake256(uint8_t *out, size_t out_len, const uint8_t *in, size_t in_len) {
    opssl_sha3_ctx_t ctx;
    keccak_init(&ctx, 136, 0x1F);
    keccak_update(&ctx, in, in_len);
    keccak_final(&ctx, out, out_len);
}
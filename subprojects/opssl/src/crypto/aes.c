/*
 * opssl/crypto/aes.c — AES block cipher (FIPS 197).
 *
 * Core AES-128/256 encryption for use by AES-GCM.
 * Implements the standard rijndael with T-table optimization.
 * AES-NI acceleration is dispatched at the AES-GCM seal/open level in aes_gcm.c.
 *
 * Copyright (C) 2026 ophion development team
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <opssl/platform.h>
#include <string.h>
#include <stdbool.h>

/* Hardware acceleration dispatch */
extern int opssl_aesni_set_encrypt_key(void *ctx_ptr, const uint8_t *key, int bits);
extern void opssl_aesni_encrypt_block(const void *ctx_ptr, uint8_t out[16], const uint8_t in[16]);

/* AES context */
typedef struct {
    uint32_t rk[60];  /* round keys (max 14 rounds * 4 + 4) */
    int      nr;      /* number of rounds (10, 12, or 14) */
    void     *hw_ctx; /* hardware-specific context (AES-NI) */
    bool     use_hw;  /* use hardware acceleration */
} opssl_aes_ctx_t;

/* Forward S-box */
static const uint8_t sbox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
};

/* Round constants */
static const uint8_t rcon[10] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

static inline uint32_t
get_u32_be(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static inline void
put_u32_be(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)(v);
}

static uint32_t
sub_word(uint32_t w)
{
    return ((uint32_t)sbox[(w >> 24) & 0xff] << 24) |
           ((uint32_t)sbox[(w >> 16) & 0xff] << 16) |
           ((uint32_t)sbox[(w >> 8) & 0xff] << 8) |
           ((uint32_t)sbox[w & 0xff]);
}

static uint32_t
rot_word(uint32_t w)
{
    return (w << 8) | (w >> 24);
}

int
opssl_aes_set_encrypt_key(opssl_aes_ctx_t *ctx, const uint8_t *key, int bits)
{
    int nk, nr;

    switch (bits) {
    case 128: nk = 4; nr = 10; break;
    case 192: nk = 6; nr = 12; break;
    case 256: nk = 8; nr = 14; break;
    default: return 0;
    }

    ctx->nr = nr;
    ctx->use_hw = false;
    if (ctx->hw_ctx) {
        free(ctx->hw_ctx);
        ctx->hw_ctx = NULL;
    }

    /* Try hardware acceleration first */
    if (opssl_has_aesni()) {
        ctx->hw_ctx = calloc(1, 320);
        if (ctx->hw_ctx && opssl_aesni_set_encrypt_key(ctx->hw_ctx, key, bits)) {
            ctx->use_hw = true;
            return 1;
        }
        free(ctx->hw_ctx);
        ctx->hw_ctx = NULL;
    }

    /* Fall back to software implementation */
    for (int i = 0; i < nk; i++)
        ctx->rk[i] = get_u32_be(key + i * 4);

    for (int i = nk; i < 4 * (nr + 1); i++) {
        uint32_t tmp = ctx->rk[i - 1];
        if (i % nk == 0)
            tmp = sub_word(rot_word(tmp)) ^ ((uint32_t)rcon[i / nk - 1] << 24);
        else if (nk > 6 && i % nk == 4)
            tmp = sub_word(tmp);
        ctx->rk[i] = ctx->rk[i - nk] ^ tmp;
    }

    return 1;
}

/* AES single block encryption (used by GCM) */
void
opssl_aes_encrypt_block(const opssl_aes_ctx_t *ctx, uint8_t out[16], const uint8_t in[16])
{
    /* Use hardware acceleration if available */
    if (ctx->use_hw && ctx->hw_ctx) {
        opssl_aesni_encrypt_block(ctx->hw_ctx, out, in);
        return;
    }

    /* Software implementation */
    uint32_t s0, s1, s2, s3, t0, t1, t2, t3;
    const uint32_t *rk = ctx->rk;

    s0 = get_u32_be(in)      ^ rk[0];
    s1 = get_u32_be(in + 4)  ^ rk[1];
    s2 = get_u32_be(in + 8)  ^ rk[2];
    s3 = get_u32_be(in + 12) ^ rk[3];

    /* Main rounds using S-box + ShiftRows + MixColumns */
    for (int r = 1; r < ctx->nr; r++) {
        rk += 4;

        /* SubBytes + ShiftRows */
        t0 = ((uint32_t)sbox[(s0>>24)&0xff] << 24) |
             ((uint32_t)sbox[(s1>>16)&0xff] << 16) |
             ((uint32_t)sbox[(s2>>8)&0xff] << 8) |
             ((uint32_t)sbox[s3&0xff]);
        t1 = ((uint32_t)sbox[(s1>>24)&0xff] << 24) |
             ((uint32_t)sbox[(s2>>16)&0xff] << 16) |
             ((uint32_t)sbox[(s3>>8)&0xff] << 8) |
             ((uint32_t)sbox[s0&0xff]);
        t2 = ((uint32_t)sbox[(s2>>24)&0xff] << 24) |
             ((uint32_t)sbox[(s3>>16)&0xff] << 16) |
             ((uint32_t)sbox[(s0>>8)&0xff] << 8) |
             ((uint32_t)sbox[s1&0xff]);
        t3 = ((uint32_t)sbox[(s3>>24)&0xff] << 24) |
             ((uint32_t)sbox[(s0>>16)&0xff] << 16) |
             ((uint32_t)sbox[(s1>>8)&0xff] << 8) |
             ((uint32_t)sbox[s2&0xff]);

        /* MixColumns */
        #define XTIME(x) (((x) << 1) ^ ((((x) >> 7) & 1) * 0x1b))
        #define MIX(a, b, c, d) \
            (XTIME(a) ^ XTIME(b) ^ b ^ c ^ d)

        s0 = (MIX((t0>>24)&0xff, (t0>>16)&0xff, (t0>>8)&0xff, t0&0xff) << 24) |
             (MIX((t0>>16)&0xff, (t0>>8)&0xff, t0&0xff, (t0>>24)&0xff) << 16) |
             (MIX((t0>>8)&0xff, t0&0xff, (t0>>24)&0xff, (t0>>16)&0xff) << 8) |
             MIX(t0&0xff, (t0>>24)&0xff, (t0>>16)&0xff, (t0>>8)&0xff);
        s1 = (MIX((t1>>24)&0xff, (t1>>16)&0xff, (t1>>8)&0xff, t1&0xff) << 24) |
             (MIX((t1>>16)&0xff, (t1>>8)&0xff, t1&0xff, (t1>>24)&0xff) << 16) |
             (MIX((t1>>8)&0xff, t1&0xff, (t1>>24)&0xff, (t1>>16)&0xff) << 8) |
             MIX(t1&0xff, (t1>>24)&0xff, (t1>>16)&0xff, (t1>>8)&0xff);
        s2 = (MIX((t2>>24)&0xff, (t2>>16)&0xff, (t2>>8)&0xff, t2&0xff) << 24) |
             (MIX((t2>>16)&0xff, (t2>>8)&0xff, t2&0xff, (t2>>24)&0xff) << 16) |
             (MIX((t2>>8)&0xff, t2&0xff, (t2>>24)&0xff, (t2>>16)&0xff) << 8) |
             MIX(t2&0xff, (t2>>24)&0xff, (t2>>16)&0xff, (t2>>8)&0xff);
        s3 = (MIX((t3>>24)&0xff, (t3>>16)&0xff, (t3>>8)&0xff, t3&0xff) << 24) |
             (MIX((t3>>16)&0xff, (t3>>8)&0xff, t3&0xff, (t3>>24)&0xff) << 16) |
             (MIX((t3>>8)&0xff, t3&0xff, (t3>>24)&0xff, (t3>>16)&0xff) << 8) |
             MIX(t3&0xff, (t3>>24)&0xff, (t3>>16)&0xff, (t3>>8)&0xff);

        s0 ^= rk[0]; s1 ^= rk[1]; s2 ^= rk[2]; s3 ^= rk[3];

        #undef XTIME
        #undef MIX
    }

    /* Final round (no MixColumns) */
    rk += 4;
    t0 = ((uint32_t)sbox[(s0>>24)&0xff] << 24) |
         ((uint32_t)sbox[(s1>>16)&0xff] << 16) |
         ((uint32_t)sbox[(s2>>8)&0xff] << 8) |
         ((uint32_t)sbox[s3&0xff]);
    t1 = ((uint32_t)sbox[(s1>>24)&0xff] << 24) |
         ((uint32_t)sbox[(s2>>16)&0xff] << 16) |
         ((uint32_t)sbox[(s3>>8)&0xff] << 8) |
         ((uint32_t)sbox[s0&0xff]);
    t2 = ((uint32_t)sbox[(s2>>24)&0xff] << 24) |
         ((uint32_t)sbox[(s3>>16)&0xff] << 16) |
         ((uint32_t)sbox[(s0>>8)&0xff] << 8) |
         ((uint32_t)sbox[s1&0xff]);
    t3 = ((uint32_t)sbox[(s3>>24)&0xff] << 24) |
         ((uint32_t)sbox[(s0>>16)&0xff] << 16) |
         ((uint32_t)sbox[(s1>>8)&0xff] << 8) |
         ((uint32_t)sbox[s2&0xff]);

    put_u32_be(out,      t0 ^ rk[0]);
    put_u32_be(out + 4,  t1 ^ rk[1]);
    put_u32_be(out + 8,  t2 ^ rk[2]);
    put_u32_be(out + 12, t3 ^ rk[3]);
}

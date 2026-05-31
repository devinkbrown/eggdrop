/*
 * opssl/crypto/aes.c — AES block cipher (FIPS 197), constant-time software path.
 *
 * The production hot path is AES-NI (dispatched via aes_ni.c and
 * aes_gcm.c).  This file provides the software fallback used when AES-NI
 * is unavailable (old/weird hardware) and for key schedule (which always
 * runs in software since the AES-NI helper hashes it back through here on
 * some build paths).
 *
 * Earlier revisions of this file used a plain S-box lookup table indexed
 * by secret bytes, which leaks via the L1 data cache (cache-line aliasing
 * of the 256-byte table).  Every S-box use here now goes through
 * `opssl_aes_sbox_ct()` in aes_sbox_ct.c, which performs a full
 * data-independent sweep of the table.
 *
 * Constant-time argument for this TU:
 *   - No branch whose condition depends on secret data.
 *   - Every byte fed to the S-box goes through `opssl_aes_sbox_ct()`,
 *     whose memory access pattern is independent of input (see
 *     aes_sbox_ct.c for that file's argument).
 *   - The round-constant array `rcon[]` is indexed only by the loop
 *     counter `i / nk` during key expansion — public input.
 *   - Round keys `rk[]` are accessed sequentially with a public counter.
 *   - MixColumns / ShiftRows are pure word arithmetic.
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

/* Constant-time S-box (sibling TU, LTO-disabled). */
extern uint8_t opssl_aes_sbox_ct(uint8_t in);

/* AES context — binary-compatible with prior {rk[60], nr, hw_ctx, use_hw} layout */
typedef struct {
    uint32_t rk[60];  /* round keys (max 14 rounds * 4 + 4) */
    int      nr;      /* number of rounds (10, 12, or 14) */
    void     *hw_ctx; /* hardware-specific context (AES-NI) */
    bool     use_hw;  /* use hardware acceleration */
} opssl_aes_ctx_t;

/* Round constants (indexed by PUBLIC counter, safe to keep in table form). */
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

/* Word-wide S-box: apply opssl_aes_sbox_ct() to each of four bytes. */
static uint32_t
sub_word(uint32_t w)
{
    return ((uint32_t)opssl_aes_sbox_ct((uint8_t)(w >> 24)) << 24) |
           ((uint32_t)opssl_aes_sbox_ct((uint8_t)(w >> 16)) << 16) |
           ((uint32_t)opssl_aes_sbox_ct((uint8_t)(w >> 8))  << 8)  |
           ((uint32_t)opssl_aes_sbox_ct((uint8_t)(w)));
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

    /* Software key expansion using the constant-time S-box. */
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

/* AES single block encryption (used by GCM/CCM/CTR). */
void
opssl_aes_encrypt_block(const opssl_aes_ctx_t *ctx, uint8_t out[16], const uint8_t in[16])
{
    /* Hardware path (AES-NI) — unchanged dispatch. */
    if (ctx->use_hw && ctx->hw_ctx) {
        opssl_aesni_encrypt_block(ctx->hw_ctx, out, in);
        return;
    }

    /* Constant-time software path. */
    uint32_t s0, s1, s2, s3, t0, t1, t2, t3;
    const uint32_t *rk = ctx->rk;

    s0 = get_u32_be(in)      ^ rk[0];
    s1 = get_u32_be(in + 4)  ^ rk[1];
    s2 = get_u32_be(in + 8)  ^ rk[2];
    s3 = get_u32_be(in + 12) ^ rk[3];

    /* Main rounds */
    for (int r = 1; r < ctx->nr; r++) {
        rk += 4;

        /* SubBytes + ShiftRows.  Each opssl_aes_sbox_ct() call uses no
         * secret-dependent memory addressing. */
        t0 = ((uint32_t)opssl_aes_sbox_ct((uint8_t)(s0 >> 24)) << 24) |
             ((uint32_t)opssl_aes_sbox_ct((uint8_t)(s1 >> 16)) << 16) |
             ((uint32_t)opssl_aes_sbox_ct((uint8_t)(s2 >> 8))  << 8)  |
             ((uint32_t)opssl_aes_sbox_ct((uint8_t)(s3)));
        t1 = ((uint32_t)opssl_aes_sbox_ct((uint8_t)(s1 >> 24)) << 24) |
             ((uint32_t)opssl_aes_sbox_ct((uint8_t)(s2 >> 16)) << 16) |
             ((uint32_t)opssl_aes_sbox_ct((uint8_t)(s3 >> 8))  << 8)  |
             ((uint32_t)opssl_aes_sbox_ct((uint8_t)(s0)));
        t2 = ((uint32_t)opssl_aes_sbox_ct((uint8_t)(s2 >> 24)) << 24) |
             ((uint32_t)opssl_aes_sbox_ct((uint8_t)(s3 >> 16)) << 16) |
             ((uint32_t)opssl_aes_sbox_ct((uint8_t)(s0 >> 8))  << 8)  |
             ((uint32_t)opssl_aes_sbox_ct((uint8_t)(s1)));
        t3 = ((uint32_t)opssl_aes_sbox_ct((uint8_t)(s3 >> 24)) << 24) |
             ((uint32_t)opssl_aes_sbox_ct((uint8_t)(s0 >> 16)) << 16) |
             ((uint32_t)opssl_aes_sbox_ct((uint8_t)(s1 >> 8))  << 8)  |
             ((uint32_t)opssl_aes_sbox_ct((uint8_t)(s2)));

        /* MixColumns — pure word arithmetic, no tables. */
        #define XTIME(x) (((x) << 1) ^ ((((x) >> 7) & 1) * 0x1b))
        #define MIX(a, b, c, d) \
            (XTIME(a) ^ XTIME(b) ^ (b) ^ (c) ^ (d))

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
    t0 = ((uint32_t)opssl_aes_sbox_ct((uint8_t)(s0 >> 24)) << 24) |
         ((uint32_t)opssl_aes_sbox_ct((uint8_t)(s1 >> 16)) << 16) |
         ((uint32_t)opssl_aes_sbox_ct((uint8_t)(s2 >> 8))  << 8)  |
         ((uint32_t)opssl_aes_sbox_ct((uint8_t)(s3)));
    t1 = ((uint32_t)opssl_aes_sbox_ct((uint8_t)(s1 >> 24)) << 24) |
         ((uint32_t)opssl_aes_sbox_ct((uint8_t)(s2 >> 16)) << 16) |
         ((uint32_t)opssl_aes_sbox_ct((uint8_t)(s3 >> 8))  << 8)  |
         ((uint32_t)opssl_aes_sbox_ct((uint8_t)(s0)));
    t2 = ((uint32_t)opssl_aes_sbox_ct((uint8_t)(s2 >> 24)) << 24) |
         ((uint32_t)opssl_aes_sbox_ct((uint8_t)(s3 >> 16)) << 16) |
         ((uint32_t)opssl_aes_sbox_ct((uint8_t)(s0 >> 8))  << 8)  |
         ((uint32_t)opssl_aes_sbox_ct((uint8_t)(s1)));
    t3 = ((uint32_t)opssl_aes_sbox_ct((uint8_t)(s3 >> 24)) << 24) |
         ((uint32_t)opssl_aes_sbox_ct((uint8_t)(s0 >> 16)) << 16) |
         ((uint32_t)opssl_aes_sbox_ct((uint8_t)(s1 >> 8))  << 8)  |
         ((uint32_t)opssl_aes_sbox_ct((uint8_t)(s2)));

    put_u32_be(out,      t0 ^ rk[0]);
    put_u32_be(out + 4,  t1 ^ rk[1]);
    put_u32_be(out + 8,  t2 ^ rk[2]);
    put_u32_be(out + 12, t3 ^ rk[3]);
}

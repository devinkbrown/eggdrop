/*
 * opssl/crypto/poly1305.c — Poly1305 one-time authenticator (RFC 8439).
 *
 * Paired with ChaCha20 for the ChaCha20-Poly1305 AEAD construction.
 * Constant-time implementation — no secret-dependent branches.
 *
 * Copyright (C) 2026 ophion development team
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <opssl/platform.h>
#include "poly1305_internal.h"
#include <string.h>

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
poly1305_init(poly1305_state_t *st, const uint8_t key[32])
{
    /* r = key[0..15] with clamping */
    st->r[0] = (load32_le(key + 0)) & 0x3ffffff;
    st->r[1] = (load32_le(key + 3) >> 2) & 0x3ffff03;
    st->r[2] = (load32_le(key + 6) >> 4) & 0x3ffc0ff;
    st->r[3] = (load32_le(key + 9) >> 6) & 0x3f03fff;
    st->r[4] = (load32_le(key + 12) >> 8) & 0x00fffff;

    /* s = key[16..31] */
    st->pad[0] = load32_le(key + 16);
    st->pad[1] = load32_le(key + 20);
    st->pad[2] = load32_le(key + 24);
    st->pad[3] = load32_le(key + 28);

    st->h[0] = st->h[1] = st->h[2] = st->h[3] = st->h[4] = 0;
    st->buf_used = 0;
    st->finalized = false;
}

static void
poly1305_blocks(poly1305_state_t *st, const uint8_t *data, size_t len, uint32_t hibit)
{
    uint32_t r0 = st->r[0], r1 = st->r[1], r2 = st->r[2], r3 = st->r[3], r4 = st->r[4];
    uint32_t s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;
    uint32_t h0 = st->h[0], h1 = st->h[1], h2 = st->h[2], h3 = st->h[3], h4 = st->h[4];

    while (len >= 16) {
        h0 += (load32_le(data + 0)) & 0x3ffffff;
        h1 += (load32_le(data + 3) >> 2) & 0x3ffffff;
        h2 += (load32_le(data + 6) >> 4) & 0x3ffffff;
        h3 += (load32_le(data + 9) >> 6) & 0x3ffffff;
        h4 += (load32_le(data + 12) >> 8) | hibit;

        uint64_t d0 = (uint64_t)h0*r0 + (uint64_t)h1*s4 + (uint64_t)h2*s3 + (uint64_t)h3*s2 + (uint64_t)h4*s1;
        uint64_t d1 = (uint64_t)h0*r1 + (uint64_t)h1*r0 + (uint64_t)h2*s4 + (uint64_t)h3*s3 + (uint64_t)h4*s2;
        uint64_t d2 = (uint64_t)h0*r2 + (uint64_t)h1*r1 + (uint64_t)h2*r0 + (uint64_t)h3*s4 + (uint64_t)h4*s3;
        uint64_t d3 = (uint64_t)h0*r3 + (uint64_t)h1*r2 + (uint64_t)h2*r1 + (uint64_t)h3*r0 + (uint64_t)h4*s4;
        uint64_t d4 = (uint64_t)h0*r4 + (uint64_t)h1*r3 + (uint64_t)h2*r2 + (uint64_t)h3*r1 + (uint64_t)h4*r0;

        uint32_t c;
        c = (uint32_t)(d0 >> 26); h0 = (uint32_t)d0 & 0x3ffffff; d1 += c;
        c = (uint32_t)(d1 >> 26); h1 = (uint32_t)d1 & 0x3ffffff; d2 += c;
        c = (uint32_t)(d2 >> 26); h2 = (uint32_t)d2 & 0x3ffffff; d3 += c;
        c = (uint32_t)(d3 >> 26); h3 = (uint32_t)d3 & 0x3ffffff; d4 += c;
        c = (uint32_t)(d4 >> 26); h4 = (uint32_t)d4 & 0x3ffffff; h0 += c * 5;
        c = h0 >> 26; h0 &= 0x3ffffff; h1 += c;

        data += 16;
        len -= 16;
    }

    st->h[0] = h0; st->h[1] = h1; st->h[2] = h2; st->h[3] = h3; st->h[4] = h4;
}

void
poly1305_update(poly1305_state_t *st, const uint8_t *data, size_t len)
{
    if (st->buf_used > 0) {
        size_t need = 16 - st->buf_used;
        if (len < need) {
            memcpy(st->buf + st->buf_used, data, len);
            st->buf_used += len;
            return;
        }
        memcpy(st->buf + st->buf_used, data, need);
        poly1305_blocks(st, st->buf, 16, 1 << 24);
        data += need;
        len -= need;
        st->buf_used = 0;
    }

    if (len >= 16) {
        size_t blocks = len & ~(size_t)15;
        poly1305_blocks(st, data, blocks, 1 << 24);
        data += blocks;
        len -= blocks;
    }

    if (len > 0) {
        memcpy(st->buf, data, len);
        st->buf_used = len;
    }
}

void
poly1305_final(poly1305_state_t *st, uint8_t tag[16])
{
    if (st->buf_used > 0) {
        st->buf[st->buf_used] = 1;
        memset(st->buf + st->buf_used + 1, 0, 16 - st->buf_used - 1);
        poly1305_blocks(st, st->buf, 16, 0);
    }

    uint32_t h0 = st->h[0], h1 = st->h[1], h2 = st->h[2], h3 = st->h[3], h4 = st->h[4];
    uint32_t c;

    c = h1 >> 26; h1 &= 0x3ffffff; h2 += c;
    c = h2 >> 26; h2 &= 0x3ffffff; h3 += c;
    c = h3 >> 26; h3 &= 0x3ffffff; h4 += c;
    c = h4 >> 26; h4 &= 0x3ffffff; h0 += c * 5;
    c = h0 >> 26; h0 &= 0x3ffffff; h1 += c;

    uint32_t g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3ffffff;
    uint32_t g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
    uint32_t g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;
    uint32_t g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
    uint32_t g4 = h4 + c - (1 << 26);

    uint32_t mask = (g4 >> 31) - 1;
    g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
    mask = ~mask;
    h0 = (h0 & mask) | g0;
    h1 = (h1 & mask) | g1;
    h2 = (h2 & mask) | g2;
    h3 = (h3 & mask) | g3;
    h4 = (h4 & mask) | g4;

    uint64_t f;
    f = (uint64_t)(h0 | (h1 << 26)) + st->pad[0]; store32_le(tag + 0, (uint32_t)f);
    f = (uint64_t)((h1 >> 6) | (h2 << 20)) + st->pad[1] + (f >> 32); store32_le(tag + 4, (uint32_t)f);
    f = (uint64_t)((h2 >> 12) | (h3 << 14)) + st->pad[2] + (f >> 32); store32_le(tag + 8, (uint32_t)f);
    f = (uint64_t)((h3 >> 18) | (h4 << 8)) + st->pad[3] + (f >> 32); store32_le(tag + 12, (uint32_t)f);

    opssl_memzero(st, sizeof(*st));
}

/* ─── Public API ─────────────────────────────────────────────────────── */

void
opssl_poly1305(uint8_t tag[16], const uint8_t *msg, size_t len,
               const uint8_t key[32])
{
    poly1305_state_t st;
    poly1305_init(&st, key);
    poly1305_update(&st, msg, len);
    poly1305_final(&st, tag);
}

int
opssl_poly1305_verify(const uint8_t tag[16], const uint8_t *msg, size_t len,
                      const uint8_t key[32])
{
    uint8_t computed[16];
    opssl_poly1305(computed, msg, len, key);
    int ok = opssl_ct_eq(tag, computed, 16);
    opssl_memzero(computed, sizeof(computed));
    return ok;
}

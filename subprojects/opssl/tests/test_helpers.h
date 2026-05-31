/*
 * test_helpers.h — shared helpers for opssl tests.
 *
 * Provides ASSERT macros, hex parsing, and a small handshake driver
 * over a socketpair. Header-only.
 *
 * Copyright (C) 2026 ophion development team
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef OPSSL_TEST_HELPERS_H
#define OPSSL_TEST_HELPERS_H

#include <opssl/opssl.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>

/* ─── Assert plumbing ─────────────────────────────────────────────────── */
static int g_tests_run = 0;
static int g_tests_passed = 0;
static int g_tests_skipped = 0;

#define T_EQ(a, b, msg) do { \
    g_tests_run++; \
    if ((a) == (b)) { g_tests_passed++; } \
    else { printf("FAIL: %s (line %d)\n", (msg), __LINE__); } \
} while (0)

#define T_NE(a, b, msg) do { \
    g_tests_run++; \
    if ((a) != (b)) { g_tests_passed++; } \
    else { printf("FAIL: %s (line %d)\n", (msg), __LINE__); } \
} while (0)

#define T_TRUE(cond, msg) T_NE((cond) ? 1 : 0, 0, msg)

#define T_SKIP(msg) do { \
    g_tests_run++; \
    g_tests_skipped++; \
    printf("SKIP: %s\n", (msg)); \
} while (0)

#define T_REPORT() do { \
    printf("\n%d/%d tests passed (%d skipped)\n", \
           g_tests_passed, g_tests_run, g_tests_skipped); \
} while (0)

#define T_EXIT() ((g_tests_passed + g_tests_skipped) == g_tests_run ? 0 : 1)

/* ─── Hex helpers ─────────────────────────────────────────────────────── */
static inline int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Parse hex string (ignoring whitespace) into out. Returns bytes written, or -1. */
static inline ssize_t hex_decode(const char *in, uint8_t *out, size_t max)
{
    size_t n = 0;
    int hi = -1;
    for (const char *p = in; *p; ++p) {
        if (isspace((unsigned char)*p) || *p == ':' || *p == ',') continue;
        int v = hexval(*p);
        if (v < 0) return -1;
        if (hi < 0) {
            hi = v;
        } else {
            if (n >= max) return -1;
            out[n++] = (uint8_t)((hi << 4) | v);
            hi = -1;
        }
    }
    if (hi >= 0) return -1;
    return (ssize_t)n;
}

/* ─── Socketpair handshake driver ─────────────────────────────────────── */
static inline int th_set_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static inline opssl_ctx_t *th_make_server_ctx(opssl_tls_version_t minv,
                                              opssl_tls_version_t maxv)
{
    opssl_ctx_t *ctx = opssl_ctx_new(minv);
    if (!ctx) return NULL;
    opssl_ctx_set_max_version(ctx, maxv);

    uint8_t pub[32], priv[64];
    if (opssl_ed25519_keygen(pub, priv)) {
        opssl_pkey_t *pk = opssl_pkey_from_ed25519_raw(priv, pub);
        if (pk) {
            opssl_ctx_use_private_key(ctx, pk);
        }
    }
    return ctx;
}

static inline int th_drive_handshake(opssl_conn_t *s, opssl_conn_t *c,
                                     int max_rounds)
{
    bool sdone = false, cdone = false;
    for (int i = 0; i < max_rounds && (!sdone || !cdone); ++i) {
        if (!sdone) {
            opssl_result_t r = opssl_accept(s);
            if (r == OPSSL_OK) sdone = true;
            else if (r != OPSSL_WANT_READ && r != OPSSL_WANT_WRITE) return -1;
        }
        if (!cdone) {
            opssl_result_t r = opssl_connect(c);
            if (r == OPSSL_OK) cdone = true;
            else if (r != OPSSL_WANT_READ && r != OPSSL_WANT_WRITE) return -1;
        }
        struct timespec ts = { .tv_sec = 0, .tv_nsec = 1000000 };
        nanosleep(&ts, NULL);
    }
    return (sdone && cdone) ? 0 : -1;
}

#endif /* OPSSL_TEST_HELPERS_H */

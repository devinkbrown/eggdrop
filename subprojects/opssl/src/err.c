/*
 * err.c — Thread-local error stack for opssl.
 *
 * Thread-safe error reporting with no global state.
 * Ring buffer stores last 8 errors per thread.
 *
 * Copyright (C) 2026 ophion development team
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <opssl/err.h>
#include <stdio.h>
#include <string.h>


#define ERR_RING_SIZE 8
#define ERR_MSG_SIZE  128

/* Error entry stored in the ring buffer */
struct err_entry {
    opssl_err_t     code;
    char           *file;       /* NULL in release builds */
    int             line;       /* 0 in release builds */
    char            msg[ERR_MSG_SIZE];  /* Custom message from opssl_set_error */
};

/* Thread-local error state */
struct err_state {
    struct err_entry ring[ERR_RING_SIZE];
    size_t           head;      /* Next slot to write */
    size_t           count;     /* Number of valid entries */
};

/* Thread-local storage */
static thread_local struct err_state err_tls = {0};

/* Auto-detect category from reason code ranges */
static opssl_err_category_t
detect_category(uint32_t reason)
{
    if (reason >= 1000 && reason < 2000) return OPSSL_ERR_TLS;
    if (reason >= 2000 && reason < 3000) return OPSSL_ERR_CRYPTO;
    if (reason >= 3000 && reason < 4000) return OPSSL_ERR_X509;
    if (reason >= 4000 && reason < 5000) return OPSSL_ERR_IO;
    if (reason >= 5000 && reason < 6000) return OPSSL_ERR_MEMORY;
    if (reason >= 6000 && reason < 7000) return OPSSL_ERR_INTERNAL;
    return OPSSL_ERR_INTERNAL;  /* Default fallback */
}

/* Push error onto the thread-local stack */
void
opssl_err_push(opssl_err_category_t cat, uint32_t reason,
               const char *file, int line)
{
    struct err_state *state = &err_tls;
    struct err_entry *entry = &state->ring[state->head];

    entry->code = OPSSL_ERR_PACK(cat, reason);
    entry->msg[0] = '\0';  /* No custom message */

#ifdef NDEBUG
    /* Release build: no file/line info */
    entry->file = NULL;
    entry->line = 0;
#else
    /* Debug build: store file/line */
    entry->file = (char*)file;
    entry->line = line;
#endif

    /* Advance ring buffer */
    state->head = (state->head + 1) % ERR_RING_SIZE;
    if (state->count < ERR_RING_SIZE) {
        state->count++;
    }
}

/* Convenience function: auto-detect category and store custom message */
void
opssl_set_error(uint32_t reason, const char *msg)
{
    struct err_state *state = &err_tls;
    struct err_entry *entry = &state->ring[state->head];

    opssl_err_category_t cat = detect_category(reason);

    entry->code = OPSSL_ERR_PACK(cat, reason);

    /* Store custom message */
    if (msg) {
        snprintf(entry->msg, ERR_MSG_SIZE, "%.127s", msg);
    } else {
        entry->msg[0] = '\0';
    }

#ifdef NDEBUG
    entry->file = NULL;
    entry->line = 0;
#else
    entry->file = __FILE__;
    entry->line = __LINE__;
#endif

    /* Advance ring buffer */
    state->head = (state->head + 1) % ERR_RING_SIZE;
    if (state->count < ERR_RING_SIZE) {
        state->count++;
    }
}

/* Get oldest error (pop from stack) */
opssl_err_t
opssl_err_get(void)
{
    struct err_state *state = &err_tls;

    if (state->count == 0) {
        return 0;  /* No errors */
    }

    /* Calculate oldest entry position */
    size_t tail = (state->head + ERR_RING_SIZE - state->count) % ERR_RING_SIZE;
    opssl_err_t err = state->ring[tail].code;

    /* Pop the error */
    state->count--;

    return err;
}

/* Peek at oldest error without popping */
opssl_err_t
opssl_err_peek(void)
{
    struct err_state *state = &err_tls;

    if (state->count == 0) {
        return 0;  /* No errors */
    }

    /* Calculate oldest entry position */
    size_t tail = (state->head + ERR_RING_SIZE - state->count) % ERR_RING_SIZE;
    return state->ring[tail].code;
}

/* Clear all errors */
void
opssl_err_clear(void)
{
    struct err_state *state = &err_tls;
    state->count = 0;
    state->head = 0;
}

/* Get human-readable category name */
static const char *
category_string(opssl_err_category_t cat)
{
    switch (cat) {
        case OPSSL_ERR_NONE:     return "none";
        case OPSSL_ERR_TLS:      return "tls";
        case OPSSL_ERR_CRYPTO:   return "crypto";
        case OPSSL_ERR_X509:     return "x509";
        case OPSSL_ERR_IO:       return "io";
        case OPSSL_ERR_MEMORY:   return "memory";
        case OPSSL_ERR_INTERNAL: return "internal";
        default:                 return "unknown";
    }
}

/* Get human-readable error string: "category: reason" */
const char *
opssl_err_string(opssl_err_t err)
{
    static thread_local char buf[256];

    if (err == 0) {
        return "no error";
    }

    opssl_err_category_t cat = OPSSL_ERR_GET_CATEGORY(err);
    uint32_t reason = OPSSL_ERR_GET_REASON(err);

    snprintf(buf, sizeof(buf), "%s: %u", category_string(cat), reason);
    return buf;
}

/* Get just the reason part as a string */
const char *
opssl_err_reason_string(opssl_err_t err)
{
    static thread_local char buf[64];

    if (err == 0) {
        return "success";
    }

    uint32_t reason = OPSSL_ERR_GET_REASON(err);
    snprintf(buf, sizeof(buf), "%u", reason);
    return buf;
}
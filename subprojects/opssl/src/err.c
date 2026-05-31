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
        snprintf(entry->msg, ERR_MSG_SIZE, "%s", msg);
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

/* Map common reason codes to human-readable strings.
 * Returns NULL if no mapping is known so callers can fall back to numeric. */
static const char *
reason_to_string(opssl_err_category_t cat, uint32_t reason)
{
    /* Generic reason codes from opssl/err.h enum */
    switch (reason) {
        case OPSSL_ERR_INVALID_ARGUMENT:     return "invalid argument";
        case OPSSL_ERR_BUFFER_TOO_SMALL:     return "buffer too small";
        case OPSSL_ERR_NOT_SUPPORTED:        return "operation not supported";
        case OPSSL_ERR_VERSION_MISMATCH:     return "version mismatch";
        case OPSSL_ERR_PEM_DECODE:           return "PEM decode failure";
        case OPSSL_ERR_FILE_READ:            return "file read error";
        case OPSSL_ERR_ALLOC_FAILED:         return "allocation failed";
        case OPSSL_ERR_WANT_READ:            return "want read";
        case OPSSL_ERR_WANT_WRITE:           return "want write";
        case OPSSL_ERR_CONNECTION_LOST:      return "connection lost";
        case OPSSL_ERR_IO_ERROR:             return "I/O error";
        case OPSSL_ERR_INVALID_FD:           return "invalid file descriptor";
        case OPSSL_ERR_NULL_POINTER:         return "null pointer";
        case OPSSL_ERR_NO_SPACE:             return "no space";
        case OPSSL_ERR_INVALID_OPERATION:    return "invalid operation";
        case OPSSL_ERR_PROTOCOL:             return "protocol error";
        case OPSSL_ERR_PEER_ALERT:           return "peer alert";
        case OPSSL_ERR_HANDSHAKE_INCOMPLETE: return "handshake incomplete";
        case OPSSL_ERR_SHUTDOWN_SENT:        return "shutdown sent";
        case OPSSL_ERR_PEER_CLOSED:          return "peer closed";
        case OPSSL_ERR_RECORD_TOO_LARGE:     return "record too large";
        case OPSSL_ERR_BUFFER_OVERFLOW:      return "buffer overflow";
        default: break;
    }
    (void)cat;
    return NULL;
}

/* Find the most recently pushed entry matching `err`, if any. */
static const struct err_entry *
find_entry_for(opssl_err_t err)
{
    const struct err_state *state = &err_tls;
    if (state->count == 0) {
        return NULL;
    }
    /* Walk newest-first */
    for (size_t i = 0; i < state->count; i++) {
        size_t idx = (state->head + ERR_RING_SIZE - 1 - i) % ERR_RING_SIZE;
        if (state->ring[idx].code == err) {
            return &state->ring[idx];
        }
    }
    return NULL;
}

/* Get human-readable error string:
 *   "<lib>:<func>:<reason-text> (code=0x...)"
 * where lib is the category, func is __FILE__:line (debug builds), and
 * reason-text is either a known reason name or the custom message.
 */
const char *
opssl_err_string(opssl_err_t err)
{
    static thread_local char buf[256];

    if (err == 0) {
        snprintf(buf, sizeof(buf), "no error");
        return buf;
    }

    opssl_err_category_t cat = OPSSL_ERR_GET_CATEGORY(err);
    uint32_t reason = OPSSL_ERR_GET_REASON(err);
    const char *lib = category_string(cat);
    const struct err_entry *e = find_entry_for(err);

    const char *reason_text = NULL;
    const char *func = "?";
    int line = 0;

    if (e) {
        if (e->msg[0] != '\0') {
            reason_text = e->msg;
        }
        if (e->file) {
            func = e->file;
            line = e->line;
        }
    }
    if (reason_text == NULL) {
        reason_text = reason_to_string(cat, reason);
    }

    if (reason_text) {
        snprintf(buf, sizeof(buf),
                 "%s:%s:%d:%s (code=0x%08x reason=%u)",
                 lib, func, line, reason_text,
                 (unsigned int)err, (unsigned int)reason);
    } else {
        snprintf(buf, sizeof(buf),
                 "%s:%s:%d:reason %u (code=0x%08x)",
                 lib, func, line, (unsigned int)reason, (unsigned int)err);
    }
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
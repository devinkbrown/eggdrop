/*
 * opssl/err.h — error handling.
 *
 * Thread-local error stack with structured error codes.
 * No global mutable state. No errno clobbering.
 *
 * Copyright (C) 2026 ophion development team
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef OPSSL_ERR_H
#define OPSSL_ERR_H

#include <stdint.h>
#include <stddef.h>

/* Error categories */
typedef enum {
    OPSSL_ERR_NONE      = 0,
    OPSSL_ERR_TLS       = 1,   /* TLS protocol error */
    OPSSL_ERR_CRYPTO    = 2,   /* Cryptographic failure */
    OPSSL_ERR_X509      = 3,   /* Certificate error */
    OPSSL_ERR_IO        = 4,   /* I/O / transport error */
    OPSSL_ERR_MEMORY    = 5,   /* Allocation failure */
    OPSSL_ERR_INTERNAL  = 6,   /* Bug / assertion */
} opssl_err_category_t;

/* TLS-specific error reasons */
typedef enum {
    OPSSL_TLS_ERR_NONE = 0,
    OPSSL_TLS_ERR_UNEXPECTED_MSG,
    OPSSL_TLS_ERR_BAD_RECORD_MAC,
    OPSSL_TLS_ERR_RECORD_OVERFLOW,
    OPSSL_TLS_ERR_HANDSHAKE_FAILURE,
    OPSSL_TLS_ERR_BAD_CERTIFICATE,
    OPSSL_TLS_ERR_UNSUPPORTED_CERT,
    OPSSL_TLS_ERR_CERT_REVOKED,
    OPSSL_TLS_ERR_CERT_EXPIRED,
    OPSSL_TLS_ERR_CERT_UNKNOWN,
    OPSSL_TLS_ERR_ILLEGAL_PARAM,
    OPSSL_TLS_ERR_UNKNOWN_CA,
    OPSSL_TLS_ERR_ACCESS_DENIED,
    OPSSL_TLS_ERR_DECODE_ERROR,
    OPSSL_TLS_ERR_DECRYPT_ERROR,
    OPSSL_TLS_ERR_PROTOCOL_VERSION,
    OPSSL_TLS_ERR_INSUFFICIENT_SECURITY,
    OPSSL_TLS_ERR_INTERNAL_ERROR,
    OPSSL_TLS_ERR_NO_RENEGOTIATION,
    OPSSL_TLS_ERR_MISSING_EXTENSION,
    OPSSL_TLS_ERR_UNRECOGNIZED_NAME,
    OPSSL_TLS_ERR_CERTIFICATE_REQUIRED,
    OPSSL_TLS_ERR_NO_APPLICATION_PROTOCOL,
} opssl_tls_err_t;

/* Packed error code: category(8) | reason(24) */
typedef uint32_t opssl_err_t;

#define OPSSL_ERR_PACK(cat, reason) \
    (((uint32_t)(cat) << 24) | ((uint32_t)(reason) & 0x00FFFFFF))

#define OPSSL_ERR_GET_CATEGORY(e) ((opssl_err_category_t)((e) >> 24))
#define OPSSL_ERR_GET_REASON(e)   ((e) & 0x00FFFFFF)

/* Thread-local error stack */
opssl_err_t  opssl_err_get(void);
opssl_err_t  opssl_err_peek(void);
void         opssl_err_clear(void);
const char  *opssl_err_string(opssl_err_t err);
const char  *opssl_err_reason_string(opssl_err_t err);

/* For library internals to push errors */
void opssl_err_push(opssl_err_category_t cat, uint32_t reason,
                    const char *file, int line);

#define OPSSL_ERR(cat, reason) \
    opssl_err_push((cat), (reason), __FILE__, __LINE__)

/* Common reason codes used by opssl_set_error() */
enum {
    OPSSL_ERR_INVALID_ARGUMENT  = 1,
    OPSSL_ERR_BUFFER_TOO_SMALL  = 2,
    OPSSL_ERR_NOT_SUPPORTED     = 3,
    OPSSL_ERR_VERSION_MISMATCH  = 4,
    OPSSL_ERR_PEM_DECODE        = 5,
    OPSSL_ERR_FILE_READ         = 6,
    OPSSL_ERR_ALLOC_FAILED      = 7,
};

/* Convenience: push error with a message string (auto-detects category) */
void opssl_set_error(uint32_t reason, const char *msg);

#endif /* OPSSL_ERR_H */

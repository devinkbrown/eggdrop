/*
 * opssl/ktls.h — Linux kernel TLS offload.
 *
 * First-class kTLS support, not an afterthought.
 * Supports both AES-GCM-128/256 and ChaCha20-Poly1305.
 * Works with TLS 1.2 and TLS 1.3.
 *
 * After activation, the kernel handles encryption/decryption.
 * The socket FD can be transferred via SCM_RIGHTS for live migration.
 *
 * Copyright (C) 2026 ophion development team
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef OPSSL_KTLS_H
#define OPSSL_KTLS_H

#include <opssl/types.h>

/* Check if kTLS is available at runtime (kernel module loaded) */
bool opssl_ktls_available(void);

/*
 * Promote a completed TLS connection to kernel TLS.
 * Must be called immediately after handshake, before any application data.
 *
 * Returns:
 *   1  — promoted successfully (both TX and RX)
 *   0  — not promoted (cipher not supported by kernel, or module not loaded)
 *  -1  — partial promotion (fatal: TX active but RX failed — must close)
 */
int opssl_ktls_promote(opssl_conn_t *conn);

/*
 * Late promotion for established connections.
 * Reads current sequence numbers from the live session.
 * Use before live migration for connections not promoted at handshake time.
 */
int opssl_ktls_promote_late(opssl_conn_t *conn);

/* Check if a connection is using kTLS */
bool opssl_ktls_is_active(const opssl_conn_t *conn);
bool opssl_ktls_tx_active(const opssl_conn_t *conn);
bool opssl_ktls_rx_active(const opssl_conn_t *conn);

/*
 * After kTLS promotion, read/write bypass the TLS library entirely.
 * These are thin wrappers around recv/send that handle:
 * - MSG_NOSIGNAL for writes
 * - close_notify detection via TLS_GET_RECORD_TYPE
 * - Proper errno propagation
 */
ssize_t opssl_ktls_read(opssl_conn_t *conn, void *buf, size_t len);
ssize_t opssl_ktls_write(opssl_conn_t *conn, const void *buf, size_t len);

/*
 * Mark an adopted FD as kTLS-active.
 * Called in the new binary after receiving a migrated kTLS socket via SCM_RIGHTS.
 * The connection object has no TLS state — only the fd and the kTLS flag.
 */
opssl_conn_t *opssl_ktls_adopt(int fd, opssl_direction_t dir);

/*
 * Extract raw key material for manual kTLS setup.
 * Used when the kernel module needs explicit setsockopt calls.
 */
typedef struct {
    uint8_t  key[32];
    uint8_t  iv[12];
    uint8_t  rec_seq[8];
    size_t   key_len;
    uint16_t cipher_type;    /* TLS_CIPHER_AES_GCM_128 etc. */
    uint16_t tls_version;    /* TLS_1_2_VERSION or TLS_1_3_VERSION */
} opssl_ktls_keys_t;

int opssl_ktls_extract_keys(opssl_conn_t *conn,
                            opssl_ktls_keys_t *tx,
                            opssl_ktls_keys_t *rx);

#endif /* OPSSL_KTLS_H */

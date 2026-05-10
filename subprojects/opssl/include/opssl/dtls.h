/*
 * opssl/dtls.h — DTLS 1.2 / 1.3 (Datagram TLS) support.
 *
 * DTLS provides TLS security guarantees over unreliable transports (UDP).
 * Handles retransmission, reordering, fragmentation, and anti-replay.
 *
 * Copyright (C) 2026 ophion development team
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef OPSSL_DTLS_H
#define OPSSL_DTLS_H

#include <opssl/types.h>

/* DTLS protocol versions (defined in types.h as part of opssl_tls_version_t) */
typedef opssl_tls_version_t opssl_dtls_version_t;

/* DTLS connection (wraps opssl_conn_t with datagram semantics) */
typedef struct opssl_dtls_conn opssl_dtls_conn_t;

/* Create / destroy */
opssl_dtls_conn_t *opssl_dtls_conn_new(opssl_ctx_t *ctx, int fd, opssl_direction_t dir);
void               opssl_dtls_conn_free(opssl_dtls_conn_t *conn);

/* Handshake (non-blocking, handles retransmission internally) */
opssl_result_t opssl_dtls_accept(opssl_dtls_conn_t *conn);
opssl_result_t opssl_dtls_connect(opssl_dtls_conn_t *conn);

/* Data transfer */
ssize_t opssl_dtls_read(opssl_dtls_conn_t *conn, void *buf, size_t len);
ssize_t opssl_dtls_write(opssl_dtls_conn_t *conn, const void *buf, size_t len);

/* Shutdown */
opssl_result_t opssl_dtls_shutdown(opssl_dtls_conn_t *conn);

/* MTU management */
void opssl_dtls_set_mtu(opssl_dtls_conn_t *conn, size_t mtu);
size_t opssl_dtls_get_mtu(const opssl_dtls_conn_t *conn);

/* Retransmission timer (call when timer expires) */
opssl_result_t opssl_dtls_handle_timeout(opssl_dtls_conn_t *conn);
int opssl_dtls_get_timeout(const opssl_dtls_conn_t *conn, struct timeval *tv);

/* Cookie verification (DoS protection, RFC 6347 §4.2.1) */
typedef int (*opssl_dtls_cookie_gen_cb)(opssl_dtls_conn_t *conn,
                                        uint8_t *cookie, size_t *cookie_len,
                                        void *userdata);
typedef int (*opssl_dtls_cookie_verify_cb)(opssl_dtls_conn_t *conn,
                                           const uint8_t *cookie, size_t cookie_len,
                                           void *userdata);

void opssl_ctx_set_dtls_cookie_callbacks(opssl_ctx_t *ctx,
                                          opssl_dtls_cookie_gen_cb gen,
                                          opssl_dtls_cookie_verify_cb verify,
                                          void *userdata);

/* Anti-replay window size (default 64 packets) */
void opssl_dtls_set_replay_window(opssl_dtls_conn_t *conn, size_t window_bits);

/* Connection info */
opssl_dtls_version_t opssl_dtls_conn_version(const opssl_dtls_conn_t *conn);
const char          *opssl_dtls_conn_cipher_name(const opssl_dtls_conn_t *conn);

/* SNI / ALPN (mirrors TLS API) */
int opssl_dtls_conn_set_sni(opssl_dtls_conn_t *conn, const char *hostname);
int opssl_dtls_conn_set_alpn(opssl_dtls_conn_t *conn, const char **protos, size_t count);

#endif /* OPSSL_DTLS_H */

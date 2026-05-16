/*
 * opssl/conn.h — per-connection TLS operations.
 *
 * Non-blocking by design. All I/O returns immediately with WANT_READ/WRITE
 * when the operation cannot complete, integrating naturally with event loops.
 *
 * Copyright (C) 2026 ophion development team
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef OPSSL_CONN_H
#define OPSSL_CONN_H

#include <opssl/types.h>
#include <opssl/err.h>

typedef struct opssl_x509_chain opssl_x509_chain_t;

/* Create / destroy */
opssl_conn_t *opssl_conn_new(opssl_ctx_t *ctx, int fd, opssl_direction_t dir);
void          opssl_conn_free(opssl_conn_t *conn);

/* Handshake (non-blocking) */
opssl_result_t opssl_accept(opssl_conn_t *conn);
opssl_result_t opssl_connect(opssl_conn_t *conn);

/* Data transfer (non-blocking) */
ssize_t opssl_read(opssl_conn_t *conn, void *buf, size_t len);
ssize_t opssl_write(opssl_conn_t *conn, const void *buf, size_t len);
int     opssl_pending(opssl_conn_t *conn);

/* Shutdown */
opssl_result_t opssl_shutdown(opssl_conn_t *conn);

/* SNI (client-side: set hostname before connect) */
int opssl_conn_set_sni(opssl_conn_t *conn, const char *hostname);
const char *opssl_conn_get_sni(opssl_conn_t *conn);

/* ALPN */
int opssl_conn_set_alpn(opssl_conn_t *conn, const char **protos, size_t count);
const char *opssl_conn_get_alpn(opssl_conn_t *conn, size_t *len);

/* Connection info post-handshake */
opssl_tls_version_t opssl_conn_version(opssl_conn_t *conn);
const char         *opssl_conn_cipher_name(opssl_conn_t *conn);
opssl_ciphersuite_t opssl_conn_cipher_id(opssl_conn_t *conn);
opssl_named_group_t opssl_conn_group(opssl_conn_t *conn);

/* Peer certificate */
opssl_x509_t *opssl_conn_get_peer_cert(opssl_conn_t *conn);

/* Certificate fingerprint (multiple algorithms) */
int opssl_conn_get_fingerprint(opssl_conn_t *conn,
                               opssl_fingerprint_method_t method,
                               uint8_t *out, size_t *outlen);

/* Keying material export (RFC 5705 / RFC 8446 §7.5) */
int opssl_conn_export_keying_material(opssl_conn_t *conn,
                                      uint8_t *out, size_t outlen,
                                      const char *label,
                                      const uint8_t *context, size_t context_len);

/* Custom I/O callbacks (override fd-based I/O) */
void opssl_conn_set_bio(opssl_conn_t *conn,
                        opssl_read_cb read_cb, opssl_write_cb write_cb,
                        void *userdata);

/* Raw fd access */
int opssl_conn_get_fd(opssl_conn_t *conn);
void opssl_conn_set_fd(opssl_conn_t *conn, int fd);

/* Handshake state inspection */
opssl_handshake_state_t opssl_conn_get_state(opssl_conn_t *conn);

/* Error from last failed operation */
opssl_err_t opssl_conn_get_error(opssl_conn_t *conn);
const char *opssl_conn_get_error_string(opssl_conn_t *conn);

/* Last WANT direction after EAGAIN (OPSSL_WANT_READ or OPSSL_WANT_WRITE) */
opssl_result_t opssl_conn_get_last_want(opssl_conn_t *conn);

/* Connection flags */
bool opssl_conn_is_outgoing(const opssl_conn_t *conn);
bool opssl_conn_is_ktls(const opssl_conn_t *conn);
bool opssl_conn_is_postquantum(const opssl_conn_t *conn);

/*
 * TLS 1.3 post-handshake: drain NewSessionTicket / KeyUpdate messages.
 * Call after handshake completes to consume buffered post-handshake data.
 * Returns OPSSL_OK when drained, WANT_READ if more data pending.
 */
opssl_result_t opssl_conn_drain_post_handshake(opssl_conn_t *conn);

/*
 * Flush any buffered outgoing TLS record data (e.g. NewSessionTicket
 * queued during handshake).  Must be called before kTLS setup so the
 * kernel inherits correct sequence numbers.
 * Returns OPSSL_OK when fully flushed, OPSSL_WANT_WRITE if partial.
 */
opssl_result_t opssl_conn_flush_write(opssl_conn_t *conn);

/*
 * Key update (TLS 1.3 only).
 * Triggers a KeyUpdate message to rotate traffic keys.
 * request_peer_update: also request the peer to update their keys.
 */
opssl_result_t opssl_conn_key_update(opssl_conn_t *conn, bool request_peer_update);

/* Traffic key/IV/seq extraction (for kTLS setup) */
int opssl_conn_get_write_key(opssl_conn_t *conn, uint8_t *key, size_t *len);
int opssl_conn_get_read_key(opssl_conn_t *conn, uint8_t *key, size_t *len);
int opssl_conn_get_write_iv(opssl_conn_t *conn, uint8_t *iv, size_t *len);
int opssl_conn_get_read_iv(opssl_conn_t *conn, uint8_t *iv, size_t *len);
int opssl_conn_get_write_seq(opssl_conn_t *conn, uint64_t *seq);
int opssl_conn_get_read_seq(opssl_conn_t *conn, uint64_t *seq);

/* Send a TLS alert to the peer */
opssl_result_t opssl_conn_send_alert(opssl_conn_t *conn,
                                     opssl_alert_level_t level,
                                     opssl_alert_desc_t desc);

/* Client certificate authentication (TLS 1.3) */
void opssl_conn_request_client_cert(opssl_conn_t *conn, bool request);
void opssl_conn_set_client_cert(opssl_conn_t *conn,
                                const opssl_pkey_t *key,
                                const opssl_x509_chain_t *chain);

/* OCSP stapling (RFC 6066 / RFC 8446 §4.4.2.1) */
void opssl_conn_set_ocsp_response(opssl_conn_t *conn,
                                  const uint8_t *response, size_t len);

/* Certificate Transparency SCT list (RFC 6962) */
void opssl_conn_set_sct_list(opssl_conn_t *conn,
                             const uint8_t *sct_list, size_t len);

/* 0-RTT early data (RFC 8446 §4.2.10) */
void opssl_conn_set_early_data_max(opssl_conn_t *conn, size_t max_bytes);
bool opssl_conn_early_data_accepted(opssl_conn_t *conn);

/* ─── Session Resumption API ─────────────────────────────────────────── */

typedef struct opssl_session opssl_session_t;

opssl_session_t *opssl_conn_get_session(opssl_conn_t *conn);
int              opssl_conn_set_session(opssl_conn_t *conn, const opssl_session_t *sess);
opssl_session_t *opssl_session_from_bytes(const uint8_t *data, size_t len);
int              opssl_session_to_bytes(const opssl_session_t *sess, uint8_t *out, size_t *out_len);
void             opssl_session_free(opssl_session_t *sess);
uint32_t         opssl_session_get_lifetime(const opssl_session_t *sess);
bool             opssl_session_is_resumable(const opssl_session_t *sess);

/* ─── OCSP Response Verification (RFC 6960) ──────────────────────────── */

int opssl_conn_verify_ocsp_response(opssl_conn_t *conn);
const uint8_t *opssl_conn_get_ocsp_response(opssl_conn_t *conn, size_t *len);

/* ─── Certificate Transparency (RFC 6962) ────────────────────────────── */

int opssl_conn_verify_sct_list(opssl_conn_t *conn);
const uint8_t *opssl_conn_get_sct_list(opssl_conn_t *conn, size_t *len);

/* ─── Session migration (hot upgrade) ───────────────────────────────── */

int opssl_conn_export(opssl_conn_t *conn, uint8_t *buf, size_t buflen);
int opssl_conn_import(opssl_conn_t *conn, const uint8_t *buf, size_t len);

#endif /* OPSSL_CONN_H */

/*
 * opssl/ctx.h — TLS context configuration.
 *
 * A context holds shared configuration for multiple connections:
 * certificates, cipher preferences, verification settings, SNI table.
 *
 * Copyright (C) 2026 ophion development team
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef OPSSL_CTX_H
#define OPSSL_CTX_H

#include <opssl/types.h>

/* Create / destroy */
opssl_ctx_t *opssl_ctx_new(opssl_tls_version_t min_version);
opssl_ctx_t *opssl_ctx_ref(opssl_ctx_t *ctx);
void         opssl_ctx_free(opssl_ctx_t *ctx);

/* Certificate & key loading */
int opssl_ctx_use_certificate_file(opssl_ctx_t *ctx, const char *path);
int opssl_ctx_use_certificate_chain_file(opssl_ctx_t *ctx, const char *path);
int opssl_ctx_use_private_key_file(opssl_ctx_t *ctx, const char *path);
int opssl_ctx_use_private_key(opssl_ctx_t *ctx, opssl_pkey_t *key);
int opssl_ctx_check_private_key(opssl_ctx_t *ctx);

/* DH parameters */
int opssl_ctx_use_dh_params_file(opssl_ctx_t *ctx, const char *path);

/* CA / verification */
int opssl_ctx_load_verify_locations(opssl_ctx_t *ctx, const char *ca_file, const char *ca_dir);
int opssl_ctx_load_default_verify_paths(opssl_ctx_t *ctx);
void opssl_ctx_set_verify(opssl_ctx_t *ctx, bool require_client_cert, opssl_verify_cb cb, void *userdata);

/* Cipher configuration */
int opssl_ctx_set_ciphersuites(opssl_ctx_t *ctx, const char *list);
int opssl_ctx_set_curves(opssl_ctx_t *ctx, const char *list);
int opssl_ctx_set_sigalgs(opssl_ctx_t *ctx, const char *list);

/* Protocol version control */
void opssl_ctx_set_min_version(opssl_ctx_t *ctx, opssl_tls_version_t ver);
void opssl_ctx_set_max_version(opssl_ctx_t *ctx, opssl_tls_version_t ver);

/* Options / security flags */
typedef enum {
    OPSSL_OPT_NO_RENEGOTIATION    = (1 << 0),
    OPSSL_OPT_NO_COMPRESSION      = (1 << 1),
    OPSSL_OPT_CIPHER_SERVER_PREF  = (1 << 2),
    OPSSL_OPT_SINGLE_DH_USE       = (1 << 3),
    OPSSL_OPT_SINGLE_ECDH_USE    = (1 << 4),
    OPSSL_OPT_NO_TICKETS          = (1 << 5),
    OPSSL_OPT_PREFER_CHACHA       = (1 << 6),  /* prefer chacha20 for mobile clients */
} opssl_ctx_opt_t;

void opssl_ctx_set_options(opssl_ctx_t *ctx, uint32_t opts);
void opssl_ctx_clear_options(opssl_ctx_t *ctx, uint32_t opts);

/* SNI multi-cert support */
int  opssl_ctx_add_sni(opssl_ctx_t *ctx, const char *hostname, opssl_ctx_t *sni_ctx);
void opssl_ctx_set_sni_callback(opssl_ctx_t *ctx, opssl_sni_cb cb, void *userdata);

/* ALPN */
int  opssl_ctx_set_alpn_protos(opssl_ctx_t *ctx, const char **protos, size_t count);
void opssl_ctx_set_alpn_callback(opssl_ctx_t *ctx, opssl_alpn_cb cb, void *userdata);

/* Session tickets & cache */
void opssl_ctx_set_ticket_keys(opssl_ctx_t *ctx, const uint8_t *keys, size_t len);
void opssl_ctx_disable_session_cache(opssl_ctx_t *ctx);

typedef enum {
    OPSSL_SESS_CACHE_OFF      = 0,
    OPSSL_SESS_CACHE_SERVER   = (1 << 0),
    OPSSL_SESS_CACHE_CLIENT   = (1 << 1),
    OPSSL_SESS_CACHE_BOTH     = (1 << 0) | (1 << 1),
    OPSSL_SESS_CACHE_TICKETS  = (1 << 2),
} opssl_session_cache_mode_t;

void opssl_ctx_set_session_cache_mode(opssl_ctx_t *ctx, uint32_t mode);
uint32_t opssl_ctx_get_session_cache_mode(const opssl_ctx_t *ctx);

/* Certificate chain verification depth */
void opssl_ctx_set_verify_depth(opssl_ctx_t *ctx, int depth);
int  opssl_ctx_get_verify_depth(const opssl_ctx_t *ctx);

/* Async private key operation callback (for HSM / offload) */
typedef int (*opssl_async_sign_cb)(opssl_conn_t *conn,
                                   const uint8_t *digest, size_t digest_len,
                                   uint8_t *sig, size_t *sig_len,
                                   void *userdata);
void opssl_ctx_set_async_sign_callback(opssl_ctx_t *ctx, opssl_async_sign_cb cb, void *userdata);

/* Post-quantum key exchange */
int opssl_ctx_enable_postquantum(opssl_ctx_t *ctx, bool enable);

/* Key logging (SSLKEYLOGFILE format for Wireshark decryption) */
void opssl_ctx_set_keylog_callback(opssl_ctx_t *ctx, opssl_keylog_cb cb, void *userdata);

/* Request (but don't require) client certificates — needed for SASL EXTERNAL */
void opssl_ctx_set_request_client_cert(opssl_ctx_t *ctx, bool request);
bool opssl_ctx_get_request_client_cert(opssl_ctx_t *ctx);

/* Internal accessor functions */
const char **opssl_ctx_get_alpn_protos(opssl_ctx_t *ctx, size_t *count);

/*
 * Security defaults — applied automatically on ctx_new:
 * - TLS 1.2 minimum (override with set_min_version)
 * - No renegotiation
 * - No compression
 * - Server cipher preference
 * - Ephemeral DH/ECDH keys
 * - Strong AEAD ciphersuites only
 * - X25519 preferred curve
 * - Post-quantum hybrids enabled when available
 */

#endif /* OPSSL_CTX_H */

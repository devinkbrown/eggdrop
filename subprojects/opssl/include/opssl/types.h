/*
 * opssl/types.h — core types and forward declarations.
 *
 * Copyright (C) 2026 ophion development team
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef OPSSL_TYPES_H
#define OPSSL_TYPES_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <sys/types.h>

/* Opaque handles */
typedef struct opssl_ctx     opssl_ctx_t;
typedef struct opssl_conn    opssl_conn_t;
typedef struct opssl_cert    opssl_cert_t;
typedef struct opssl_pkey    opssl_pkey_t;
typedef struct opssl_x509    opssl_x509_t;
typedef struct opssl_bio     opssl_bio_t;

/* TLS protocol versions */
typedef enum {
    OPSSL_TLS_1_2 = 0x0303,
    OPSSL_TLS_1_3 = 0x0304,
    OPSSL_DTLS_1_2 = 0xFEFD,
    OPSSL_DTLS_1_3 = 0xFEFC,
} opssl_tls_version_t;

/* Connection direction */
typedef enum {
    OPSSL_DIR_INBOUND  = 0,
    OPSSL_DIR_OUTBOUND = 1,
} opssl_direction_t;

/* Handshake state */
typedef enum {
    OPSSL_HS_IDLE = 0,
    OPSSL_HS_CLIENT_HELLO,
    OPSSL_HS_SERVER_HELLO,
    OPSSL_HS_ENCRYPTED_EXTENSIONS,
    OPSSL_HS_CERTIFICATE,
    OPSSL_HS_CERTIFICATE_VERIFY,
    OPSSL_HS_FINISHED,
    OPSSL_HS_WAIT_FINISHED,
    OPSSL_HS_COMPLETE,
    OPSSL_HS_ERROR,
} opssl_handshake_state_t;

/* I/O result codes */
typedef enum {
    OPSSL_OK           =  1,
    OPSSL_ERROR        =  0,
    OPSSL_WANT_READ    = -2,
    OPSSL_WANT_WRITE   = -3,
    OPSSL_CLOSED       = -4,
    OPSSL_FATAL        = -5,
} opssl_result_t;

/* Certificate fingerprint methods */
typedef enum {
    OPSSL_FP_SHA1       = 0,
    OPSSL_FP_SHA256     = 1,
    OPSSL_FP_SHA512     = 2,
    OPSSL_FP_SHA3_256   = 3,
    OPSSL_FP_SHA3_512   = 4,
    OPSSL_FP_SPKI_SHA256    = 5,
    OPSSL_FP_SPKI_SHA512    = 6,
    OPSSL_FP_SPKI_SHA3_256  = 7,
    OPSSL_FP_SPKI_SHA3_512  = 8,
} opssl_fingerprint_method_t;

/* Cipher suite IDs (IANA assignments) */
typedef enum {
    /* TLS 1.3 */
    OPSSL_TLS_AES_128_GCM_SHA256       = 0x1301,
    OPSSL_TLS_AES_256_GCM_SHA384       = 0x1302,
    OPSSL_TLS_CHACHA20_POLY1305_SHA256 = 0x1303,
    OPSSL_TLS_AES_128_CCM_SHA256       = 0x1304,

    /* TLS 1.3 extended cipher suites (opssl private-use range) */
    OPSSL_TLS_AES_256_CCM_SHA384           = 0xC0B0,
    OPSSL_TLS_AES_256_CCM_8_SHA384         = 0xC0B1,
    OPSSL_TLS_CAMELLIA_128_GCM_SHA256      = 0xC0B2,
    OPSSL_TLS_CAMELLIA_256_GCM_SHA384      = 0xC0B3,

    /* TLS 1.2 ECDHE */
    OPSSL_TLS_ECDHE_RSA_AES_128_GCM    = 0xC02F,
    OPSSL_TLS_ECDHE_RSA_AES_256_GCM    = 0xC030,
    OPSSL_TLS_ECDHE_ECDSA_AES_128_GCM  = 0xC02B,
    OPSSL_TLS_ECDHE_ECDSA_AES_256_GCM  = 0xC02C,
    OPSSL_TLS_ECDHE_RSA_CHACHA20       = 0xCCA8,
    OPSSL_TLS_ECDHE_ECDSA_CHACHA20     = 0xCCA9,

    /* TLS 1.2 DHE */
    OPSSL_TLS_DHE_RSA_AES_128_GCM      = 0x009E,
    OPSSL_TLS_DHE_RSA_AES_256_GCM      = 0x009F,
    OPSSL_TLS_DHE_RSA_CHACHA20         = 0xCCAA,

    /* TLS 1.2 AES-CCM (full 16-byte tag) */
    OPSSL_TLS_ECDHE_ECDSA_AES_128_CCM  = 0xC0AC,
    OPSSL_TLS_ECDHE_ECDSA_AES_256_CCM  = 0xC0AD,
    OPSSL_TLS_DHE_RSA_AES_128_CCM      = 0xC09E,
    OPSSL_TLS_DHE_RSA_AES_256_CCM      = 0xC09F,

    /* TLS 1.2/1.3 AES-CCM_8 (8-byte tag) */
    OPSSL_TLS_AES_128_CCM_8_SHA256     = 0x1305,
    OPSSL_TLS_DHE_RSA_AES_128_CCM_8    = 0xC0A0,
    OPSSL_TLS_DHE_RSA_AES_256_CCM_8    = 0xC0A1,
    OPSSL_TLS_ECDHE_ECDSA_AES_128_CCM_8 = 0xC0AE,
    OPSSL_TLS_ECDHE_ECDSA_AES_256_CCM_8 = 0xC0AF,

    /* TLS 1.2 Camellia-GCM (RFC 6367) */
    OPSSL_TLS_ECDHE_ECDSA_CAMELLIA_128_GCM = 0xC086,
    OPSSL_TLS_ECDHE_ECDSA_CAMELLIA_256_GCM = 0xC087,
    OPSSL_TLS_ECDHE_RSA_CAMELLIA_128_GCM   = 0xC08A,
    OPSSL_TLS_ECDHE_RSA_CAMELLIA_256_GCM   = 0xC08B,
    OPSSL_TLS_DHE_RSA_CAMELLIA_128_GCM     = 0xC07C,
    OPSSL_TLS_DHE_RSA_CAMELLIA_256_GCM     = 0xC07D,
} opssl_ciphersuite_t;

/* Named groups for key exchange */
typedef enum {
    OPSSL_GROUP_X25519         = 0x001D,
    OPSSL_GROUP_X448           = 0x001E,
    OPSSL_GROUP_SECP256R1      = 0x0017,
    OPSSL_GROUP_SECP384R1      = 0x0018,
    OPSSL_GROUP_SECP521R1      = 0x0019,
    OPSSL_GROUP_FFDHE2048      = 0x0100,
    OPSSL_GROUP_FFDHE3072      = 0x0101,
    OPSSL_GROUP_FFDHE4096      = 0x0102,

    /* Post-quantum hybrids (draft-ietf-tls-hybrid-design) */
    OPSSL_GROUP_X25519_MLKEM768     = 0x6399,
    OPSSL_GROUP_SECP256R1_MLKEM768  = 0x639A,
    OPSSL_GROUP_SECP384R1_MLKEM1024 = 0x639B,
} opssl_named_group_t;

/* Signature algorithms */
typedef enum {
    OPSSL_SIG_RSA_PSS_SHA256     = 0x0804,
    OPSSL_SIG_RSA_PSS_SHA384     = 0x0805,
    OPSSL_SIG_RSA_PSS_SHA512     = 0x0806,
    OPSSL_SIG_ECDSA_SECP256R1    = 0x0403,
    OPSSL_SIG_ECDSA_SECP384R1    = 0x0503,
    OPSSL_SIG_ECDSA_SECP521R1    = 0x0603,
    OPSSL_SIG_ED25519            = 0x0807,
    OPSSL_SIG_ED448              = 0x0808,
    OPSSL_SIG_RSA_PKCS1_SHA256   = 0x0401,
    OPSSL_SIG_RSA_PKCS1_SHA384   = 0x0501,
    OPSSL_SIG_RSA_PKCS1_SHA512   = 0x0601,
} opssl_sig_algo_t;

/* ALPN protocol identifiers */
#define OPSSL_ALPN_IRC      "irc"
#define OPSSL_ALPN_HTTP11   "http/1.1"
#define OPSSL_ALPN_DOT      "dot"

/* TLS alert descriptions (RFC 8446 §6.2) */
typedef enum {
    OPSSL_ALERT_CLOSE_NOTIFY            = 0,
    OPSSL_ALERT_UNEXPECTED_MESSAGE      = 10,
    OPSSL_ALERT_BAD_RECORD_MAC          = 20,
    OPSSL_ALERT_RECORD_OVERFLOW         = 22,
    OPSSL_ALERT_HANDSHAKE_FAILURE       = 40,
    OPSSL_ALERT_BAD_CERTIFICATE         = 42,
    OPSSL_ALERT_UNSUPPORTED_CERTIFICATE = 43,
    OPSSL_ALERT_CERTIFICATE_REVOKED     = 44,
    OPSSL_ALERT_CERTIFICATE_EXPIRED     = 45,
    OPSSL_ALERT_CERTIFICATE_UNKNOWN     = 46,
    OPSSL_ALERT_ILLEGAL_PARAMETER       = 47,
    OPSSL_ALERT_UNKNOWN_CA              = 48,
    OPSSL_ALERT_ACCESS_DENIED           = 49,
    OPSSL_ALERT_DECODE_ERROR            = 50,
    OPSSL_ALERT_DECRYPT_ERROR           = 51,
    OPSSL_ALERT_PROTOCOL_VERSION        = 70,
    OPSSL_ALERT_INSUFFICIENT_SECURITY   = 71,
    OPSSL_ALERT_INTERNAL_ERROR          = 80,
    OPSSL_ALERT_INAPPROPRIATE_FALLBACK  = 86,
    OPSSL_ALERT_MISSING_EXTENSION       = 109,
    OPSSL_ALERT_UNSUPPORTED_EXTENSION   = 110,
    OPSSL_ALERT_UNRECOGNIZED_NAME       = 112,
    OPSSL_ALERT_BAD_CERTIFICATE_STATUS  = 113,
    OPSSL_ALERT_UNKNOWN_PSK_IDENTITY    = 115,
    OPSSL_ALERT_CERTIFICATE_REQUIRED    = 116,
    OPSSL_ALERT_NO_APPLICATION_PROTOCOL = 120,
} opssl_alert_desc_t;

/* TLS alert levels */
typedef enum {
    OPSSL_ALERT_LEVEL_WARNING = 1,
    OPSSL_ALERT_LEVEL_FATAL   = 2,
} opssl_alert_level_t;

/* Callback typedefs */
typedef int (*opssl_verify_cb)(int preverify_ok, opssl_x509_t *cert, int depth, void *userdata);
typedef int (*opssl_sni_cb)(opssl_conn_t *conn, const char *hostname, void *userdata);
typedef int (*opssl_alpn_cb)(opssl_conn_t *conn, const char *selected, size_t len, void *userdata);
typedef void (*opssl_keylog_cb)(const char *line, void *userdata);

/* I/O callbacks for custom transport */
typedef ssize_t (*opssl_read_cb)(void *userdata, uint8_t *buf, size_t len);
typedef ssize_t (*opssl_write_cb)(void *userdata, const uint8_t *buf, size_t len);

/* Maximum sizes */
#define OPSSL_MAX_RECORD_SIZE      16384
#define OPSSL_MAX_CERT_CHAIN       10
#define OPSSL_MAX_SNI_CONTEXTS     64
#define OPSSL_MAX_ALPN_PROTOS      8
#define OPSSL_SESSION_EXPORT_MAX   8192

#endif /* OPSSL_TYPES_H */

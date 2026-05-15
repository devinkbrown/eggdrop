/*
 * ctx.c — TLS context configuration and management.
 *
 * Contains shared configuration for multiple connections:
 * certificates, cipher preferences, verification settings, SNI.
 *
 * Copyright (C) 2026 ophion development team
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <opssl/ctx.h>
#include <opssl/cert.h>
#include <opssl/crypto.h>
#include <opssl/platform.h>
#include <opssl/err.h>
#include <op_memory.h>
#include <string.h>
#include <stdio.h>

extern int opssl_pem_decode(const char *pem, size_t pem_len,
                            uint8_t **der_out, size_t *der_len,
                            char *label_out, size_t label_max);

/* TLS context structure definition */
struct opssl_ctx {
    _Atomic int refcount;

    /* Version bounds */
    opssl_tls_version_t min_version;
    opssl_tls_version_t max_version;

    /* Certificates */
    opssl_x509_chain_t *cert_chain;
    opssl_pkey_t *private_key;

    /* DH params (FFDHE group selection) */
    opssl_ffdhe_group_t dh_group;

    /* Verification */
    opssl_x509_store_t *trust_store;
    bool verify_peer;
    opssl_verify_cb verify_cb;
    void *verify_userdata;

    /* Cipher preferences */
    opssl_ciphersuite_t ciphers[32];
    size_t cipher_count;

    /* Named groups */
    opssl_named_group_t groups[16];
    size_t group_count;

    /* Signature algorithms */
    opssl_sig_algo_t sigalgs[16];
    size_t sigalg_count;

    /* Options */
    uint32_t options;

    /* SNI table */
    struct {
        char hostname[256];
        opssl_ctx_t *ctx;
    } sni_table[64];
    size_t sni_count;
    opssl_sni_cb sni_cb;
    void *sni_userdata;

    /* ALPN */
    char alpn_protos[8][32];
    size_t alpn_count;
    opssl_alpn_cb alpn_cb;
    void *alpn_userdata;

    /* Post-quantum */
    bool postquantum_enabled;

    /* Session tickets */
    uint8_t ticket_keys[80];  /* 16 name + 32 aes + 32 hmac */
    bool tickets_enabled;
    bool session_cache_enabled;

    /* Key logging (SSLKEYLOGFILE format) */
    opssl_keylog_cb keylog_cb;
    void *keylog_userdata;

    /* Session cache mode */
    uint32_t session_cache_mode;

    /* Certificate chain verification depth */
    int verify_depth;

    /* Async private key operation */
    opssl_async_sign_cb async_sign_cb;
    void *async_sign_userdata;

    /* DTLS cookie callbacks */
    void *dtls_cookie_gen_cb;
    void *dtls_cookie_verify_cb;
    void *dtls_cookie_userdata;

    /* Server-wide HMAC key for DTLS cookie generation and verification.
     * Generated once at ctx creation. Same key used by both generate and verify,
     * so cookies are deterministic for a given client address + random. */
    uint8_t dtls_cookie_secret[32];
};

/* Default cipher suites (TLS 1.3 first, then strong ECDHE TLS 1.2) */
static const opssl_ciphersuite_t default_ciphers[] = {
    OPSSL_TLS_AES_256_GCM_SHA384,
    OPSSL_TLS_CHACHA20_POLY1305_SHA256,
    OPSSL_TLS_AES_128_GCM_SHA256,
    OPSSL_TLS_ECDHE_RSA_AES_256_GCM,
    OPSSL_TLS_ECDHE_ECDSA_AES_256_GCM,
    OPSSL_TLS_ECDHE_RSA_CHACHA20,
    OPSSL_TLS_ECDHE_ECDSA_CHACHA20,
    OPSSL_TLS_ECDHE_RSA_AES_128_GCM,
    OPSSL_TLS_ECDHE_ECDSA_AES_128_GCM
};

/* Default supported groups (prefer post-quantum hybrids) */
static const opssl_named_group_t default_groups[] = {
    OPSSL_GROUP_X25519_MLKEM768,  /* post-quantum hybrid */
    OPSSL_GROUP_X25519,
    OPSSL_GROUP_SECP256R1,
    OPSSL_GROUP_SECP384R1,
    OPSSL_GROUP_FFDHE2048
};

/* Default signature algorithms */
static const opssl_sig_algo_t default_sigalgs[] = {
    OPSSL_SIG_ED25519,
    OPSSL_SIG_ECDSA_SECP256R1,
    OPSSL_SIG_ECDSA_SECP384R1,
    OPSSL_SIG_RSA_PSS_SHA256,
    OPSSL_SIG_RSA_PSS_SHA384,
    OPSSL_SIG_RSA_PSS_SHA512
};

/* Create new context with security defaults */
opssl_ctx_t *
opssl_ctx_new(opssl_tls_version_t min_version)
{
    opssl_ctx_t *ctx = op_malloc(sizeof(*ctx));
    if (!ctx) {
        opssl_set_error(OPSSL_ERR_ALLOC_FAILED, NULL);
        return NULL;
    }

    memset(ctx, 0, sizeof(*ctx));
    ctx->refcount = 1;

    /* Version bounds */
    ctx->min_version = min_version;
    ctx->max_version = OPSSL_TLS_1_3;

    /* Security defaults */
    ctx->options = OPSSL_OPT_NO_RENEGOTIATION |
                   OPSSL_OPT_NO_COMPRESSION |
                   OPSSL_OPT_CIPHER_SERVER_PREF |
                   OPSSL_OPT_SINGLE_ECDH_USE;

    /* Default cipher suites */
    ctx->cipher_count = sizeof(default_ciphers) / sizeof(default_ciphers[0]);
    memcpy(ctx->ciphers, default_ciphers, sizeof(default_ciphers));

    /* Default named groups */
    ctx->group_count = sizeof(default_groups) / sizeof(default_groups[0]);
    memcpy(ctx->groups, default_groups, sizeof(default_groups));

    /* Default signature algorithms */
    ctx->sigalg_count = sizeof(default_sigalgs) / sizeof(default_sigalgs[0]);
    memcpy(ctx->sigalgs, default_sigalgs, sizeof(default_sigalgs));

    /* Default DH group */
    ctx->dh_group = OPSSL_FFDHE_2048;

    /* Enable post-quantum and session tickets by default */
    ctx->postquantum_enabled = true;
    ctx->tickets_enabled = true;
    ctx->session_cache_enabled = true;

    /* Session cache defaults */
    ctx->session_cache_mode = 0x01 | 0x02 | 0x04;  /* BOTH | TICKETS */
    ctx->verify_depth = 10;  /* default chain depth limit */

    /* Generate random session ticket keys */
    if (opssl_random_bytes(ctx->ticket_keys, sizeof(ctx->ticket_keys)) != 0) {
        op_free(ctx);
        return NULL;
    }

    /* Generate DTLS cookie HMAC key (server-wide, lives for ctx lifetime) */
    if (opssl_random_bytes(ctx->dtls_cookie_secret, sizeof(ctx->dtls_cookie_secret)) != 0) {
        op_free(ctx);
        return NULL;
    }

    return ctx;
}

/* Increment reference count */
opssl_ctx_t *
opssl_ctx_ref(opssl_ctx_t *ctx)
{
    if (!ctx)
        return NULL;
    ctx->refcount++;
    return ctx;
}

/* Decrement reference count and free if zero */
void
opssl_ctx_free(opssl_ctx_t *ctx)
{
    if (!ctx)
        return;

    ctx->refcount--;
    if (ctx->refcount > 0)
        return;

    /* Free certificate chain and private key */
    if (ctx->cert_chain)
        opssl_x509_chain_free(ctx->cert_chain);
    if (ctx->private_key)
        opssl_pkey_free(ctx->private_key);

    /* Free trust store */
    if (ctx->trust_store)
        opssl_x509_store_free(ctx->trust_store);

    /* Free SNI contexts */
    for (size_t i = 0; i < ctx->sni_count; i++) {
        if (ctx->sni_table[i].ctx)
            opssl_ctx_free(ctx->sni_table[i].ctx);
    }

    /* Clear sensitive data */
    opssl_memzero(ctx->ticket_keys, sizeof(ctx->ticket_keys));

    op_free(ctx);
}

/* Certificate loading functions */
int
opssl_ctx_use_certificate_file(opssl_ctx_t *ctx, const char *path)
{
    if (!ctx || !path) {
        opssl_set_error(OPSSL_ERR_INVALID_ARGUMENT, NULL);
        return 0;
    }

    opssl_x509_t *cert = opssl_x509_from_file(path);
    if (!cert)
        return 0;

    if (ctx->cert_chain)
        opssl_x509_chain_free(ctx->cert_chain);

    /* Build a single-cert chain by loading the same file as a chain */
    ctx->cert_chain = opssl_x509_chain_from_file(path);
    opssl_x509_free(cert);
    return ctx->cert_chain ? 1 : 0;
}

int
opssl_ctx_use_certificate_chain_file(opssl_ctx_t *ctx, const char *path)
{
    if (!ctx || !path) {
        opssl_set_error(OPSSL_ERR_INVALID_ARGUMENT, NULL);
        return 0;
    }

    if (ctx->cert_chain)
        opssl_x509_chain_free(ctx->cert_chain);

    ctx->cert_chain = opssl_x509_chain_from_file(path);
    return ctx->cert_chain ? 1 : 0;
}

int
opssl_ctx_use_private_key_file(opssl_ctx_t *ctx, const char *path)
{
    if (!ctx || !path) {
        opssl_set_error(OPSSL_ERR_INVALID_ARGUMENT, NULL);
        return 0;
    }

    if (ctx->private_key)
        opssl_pkey_free(ctx->private_key);

    ctx->private_key = opssl_pkey_from_file(path);
    return ctx->private_key ? 1 : 0;
}

int
opssl_ctx_use_private_key(opssl_ctx_t *ctx, opssl_pkey_t *key)
{
    if (!ctx || !key) {
        opssl_set_error(OPSSL_ERR_INVALID_ARGUMENT, NULL);
        return 0;
    }

    if (ctx->private_key)
        opssl_pkey_free(ctx->private_key);

    ctx->private_key = key;
    return 1;
}

int
opssl_ctx_check_private_key(opssl_ctx_t *ctx)
{
    if (!ctx || !ctx->cert_chain || !ctx->private_key) {
        opssl_set_error(OPSSL_ERR_INVALID_ARGUMENT, NULL);
        return 0;
    }

    opssl_x509_t *cert = opssl_x509_chain_get(ctx->cert_chain, 0);
    if (!cert)
        return 0;

    return opssl_pkey_matches_cert(ctx->private_key, cert);
}

/* DH parameters — read a PEM file, extract the prime size, select the
 * matching FFDHE group.  Only RFC 3526/7919 safe-prime groups are supported;
 * custom primes are silently upgraded to the nearest standard group. */
int
opssl_ctx_use_dh_params_file(opssl_ctx_t *ctx, const char *path)
{
    if (!ctx || !path) {
        opssl_set_error(OPSSL_ERR_INVALID_ARGUMENT, NULL);
        return 0;
    }

    FILE *f = fopen(path, "r");
    if (!f) {
        opssl_set_error(OPSSL_ERR_IO, NULL);
        return 0;
    }

    char buf[8192];
    size_t total = 0;
    size_t n;
    while ((n = fread(buf + total, 1, sizeof(buf) - total, f)) > 0)
        total += n;
    fclose(f);

    if (total == 0) {
        opssl_set_error(OPSSL_ERR_INVALID_ARGUMENT, NULL);
        return 0;
    }

    /* Decode PEM to DER */
    uint8_t *der = NULL;
    size_t der_len = 0;
    if (opssl_pem_decode(buf, total, &der, &der_len, NULL, 0) != 1 || !der) {
        opssl_set_error(OPSSL_ERR_X509, 0);
        return 0;
    }

    /* ASN.1: SEQUENCE { INTEGER (prime), INTEGER (generator) }
     * The prime length in bytes determines the FFDHE group. */
    size_t prime_bits = 0;
    if (der_len > 4 && der[0] == 0x30) {
        /* Skip SEQUENCE tag + length */
        size_t pos = 1;
        if (der[pos] & 0x80) {
            size_t len_bytes = der[pos] & 0x7f;
            pos += 1 + len_bytes;
        } else {
            pos += 1;
        }
        /* INTEGER tag */
        if (pos < der_len && der[pos] == 0x02) {
            pos++;
            size_t int_len = 0;
            if (der[pos] & 0x80) {
                size_t len_bytes = der[pos] & 0x7f;
                pos++;
                for (size_t i = 0; i < len_bytes && pos < der_len; i++)
                    int_len = (int_len << 8) | der[pos++];
            } else {
                int_len = der[pos++];
            }
            /* Skip leading zero byte if present */
            if (int_len > 0 && pos < der_len && der[pos] == 0x00) {
                int_len--;
            }
            prime_bits = int_len * 8;
        }
    }
    free(der);

    if (prime_bits >= 4096)
        ctx->dh_group = OPSSL_FFDHE_4096;
    else if (prime_bits >= 3072)
        ctx->dh_group = OPSSL_FFDHE_3072;
    else
        ctx->dh_group = OPSSL_FFDHE_2048;

    return 1;
}

/* CA verification setup */
int
opssl_ctx_load_verify_locations(opssl_ctx_t *ctx, const char *ca_file, const char *ca_dir)
{
    if (!ctx) {
        opssl_set_error(OPSSL_ERR_INVALID_ARGUMENT, NULL);
        return 0;
    }

    if (ctx->trust_store)
        opssl_x509_store_free(ctx->trust_store);

    ctx->trust_store = opssl_x509_store_new();
    if (!ctx->trust_store)
        return 0;

    int result = 1;
    if (ca_file && !opssl_x509_store_load_file(ctx->trust_store, ca_file))
        result = 0;
    if (ca_dir && !opssl_x509_store_load_dir(ctx->trust_store, ca_dir))
        result = 0;

    return result;
}

int
opssl_ctx_load_default_verify_paths(opssl_ctx_t *ctx)
{
    if (!ctx) {
        opssl_set_error(OPSSL_ERR_INVALID_ARGUMENT, NULL);
        return 0;
    }

    const char *ca_file = NULL;
    const char *ca_dir = NULL;

    /* Environment overrides take priority (matches OpenSSL convention) */
    const char *env_file = getenv("SSL_CERT_FILE");
    const char *env_dir = getenv("SSL_CERT_DIR");

    if (env_file && env_file[0])
        ca_file = env_file;
    if (env_dir && env_dir[0])
        ca_dir = env_dir;

    /* Fall back to meson-detected system paths */
#ifdef OPSSL_DEFAULT_CA_FILE
    if (!ca_file)
        ca_file = OPSSL_DEFAULT_CA_FILE;
#endif
#ifdef OPSSL_DEFAULT_CA_DIR
    if (!ca_dir)
        ca_dir = OPSSL_DEFAULT_CA_DIR;
#endif

    if (!ca_file && !ca_dir) {
        opssl_set_error(OPSSL_ERR_IO, "no system CA bundle found");
        return 0;
    }

    return opssl_ctx_load_verify_locations(ctx, ca_file, ca_dir);
}

void
opssl_ctx_set_verify(opssl_ctx_t *ctx, bool require_client_cert, opssl_verify_cb cb, void *userdata)
{
    if (!ctx)
        return;

    ctx->verify_peer = require_client_cert;
    ctx->verify_cb = cb;
    ctx->verify_userdata = userdata;
}

/* Parse colon-separated cipher list */
static size_t
parse_cipher_list(const char *list, opssl_ciphersuite_t *ciphers, size_t max_count)
{
    if (!list || !ciphers)
        return 0;

    static const struct {
        const char *name;
        opssl_ciphersuite_t id;
    } cipher_names[] = {
        {"TLS_AES_128_GCM_SHA256",             OPSSL_TLS_AES_128_GCM_SHA256},
        {"TLS_AES_256_GCM_SHA384",             OPSSL_TLS_AES_256_GCM_SHA384},
        {"TLS_CHACHA20_POLY1305_SHA256",       OPSSL_TLS_CHACHA20_POLY1305_SHA256},
        {"TLS_AES_128_CCM_SHA256",             OPSSL_TLS_AES_128_CCM_SHA256},
        {"ECDHE-RSA-AES128-GCM-SHA256",        OPSSL_TLS_ECDHE_RSA_AES_128_GCM},
        {"ECDHE-RSA-AES256-GCM-SHA384",        OPSSL_TLS_ECDHE_RSA_AES_256_GCM},
        {"ECDHE-ECDSA-AES128-GCM-SHA256",      OPSSL_TLS_ECDHE_ECDSA_AES_128_GCM},
        {"ECDHE-ECDSA-AES256-GCM-SHA384",      OPSSL_TLS_ECDHE_ECDSA_AES_256_GCM},
        {"ECDHE-RSA-CHACHA20-POLY1305",        OPSSL_TLS_ECDHE_RSA_CHACHA20},
        {"ECDHE-ECDSA-CHACHA20-POLY1305",      OPSSL_TLS_ECDHE_ECDSA_CHACHA20},
        {"DHE-RSA-AES128-GCM-SHA256",          OPSSL_TLS_DHE_RSA_AES_128_GCM},
        {"DHE-RSA-AES256-GCM-SHA384",          OPSSL_TLS_DHE_RSA_AES_256_GCM},
        {"DHE-RSA-CHACHA20-POLY1305",          OPSSL_TLS_DHE_RSA_CHACHA20},
    };

    size_t count = 0;
    char *list_copy = strdup(list);
    if (!list_copy)
        return 0;

    char *saveptr = NULL;
    char *tok = strtok_r(list_copy, ":", &saveptr);
    while (tok && count < max_count) {
        for (size_t i = 0; i < sizeof(cipher_names) / sizeof(cipher_names[0]); i++) {
            if (strcmp(tok, cipher_names[i].name) == 0) {
                ciphers[count++] = cipher_names[i].id;
                break;
            }
        }
        tok = strtok_r(NULL, ":", &saveptr);
    }

    free(list_copy);
    return count;
}

/* Parse colon-separated group list */
static size_t
parse_group_list(const char *list, opssl_named_group_t *groups, size_t max_count)
{
    if (!list || !groups)
        return 0;

    static const struct {
        const char *name;
        opssl_named_group_t id;
    } group_names[] = {
        {"X25519",              OPSSL_GROUP_X25519},
        {"X448",                OPSSL_GROUP_X448},
        {"P-256",               OPSSL_GROUP_SECP256R1},
        {"secp256r1",           OPSSL_GROUP_SECP256R1},
        {"P-384",               OPSSL_GROUP_SECP384R1},
        {"secp384r1",           OPSSL_GROUP_SECP384R1},
        {"P-521",               OPSSL_GROUP_SECP521R1},
        {"secp521r1",           OPSSL_GROUP_SECP521R1},
        {"ffdhe2048",           OPSSL_GROUP_FFDHE2048},
        {"ffdhe3072",           OPSSL_GROUP_FFDHE3072},
        {"ffdhe4096",           OPSSL_GROUP_FFDHE4096},
        {"X25519_MLKEM768",     OPSSL_GROUP_X25519_MLKEM768},
    };

    size_t count = 0;
    char *list_copy = strdup(list);
    if (!list_copy)
        return 0;

    char *saveptr = NULL;
    char *tok = strtok_r(list_copy, ":", &saveptr);
    while (tok && count < max_count) {
        for (size_t i = 0; i < sizeof(group_names) / sizeof(group_names[0]); i++) {
            if (strcmp(tok, group_names[i].name) == 0) {
                groups[count++] = group_names[i].id;
                break;
            }
        }
        tok = strtok_r(NULL, ":", &saveptr);
    }

    free(list_copy);
    return count;
}

/* Cipher configuration */
int
opssl_ctx_set_ciphersuites(opssl_ctx_t *ctx, const char *list)
{
    if (!ctx || !list) {
        opssl_set_error(OPSSL_ERR_INVALID_ARGUMENT, NULL);
        return 0;
    }

    size_t count = parse_cipher_list(list, ctx->ciphers,
                                   sizeof(ctx->ciphers) / sizeof(ctx->ciphers[0]));
    if (count == 0) {
        opssl_set_error(OPSSL_ERR_INVALID_ARGUMENT, NULL);
        return 0;
    }

    ctx->cipher_count = count;
    return 1;
}

int
opssl_ctx_set_curves(opssl_ctx_t *ctx, const char *list)
{
    if (!ctx || !list) {
        opssl_set_error(OPSSL_ERR_INVALID_ARGUMENT, NULL);
        return 0;
    }

    size_t count = parse_group_list(list, ctx->groups,
                                  sizeof(ctx->groups) / sizeof(ctx->groups[0]));
    if (count == 0) {
        opssl_set_error(OPSSL_ERR_INVALID_ARGUMENT, NULL);
        return 0;
    }

    ctx->group_count = count;
    return 1;
}

int
opssl_ctx_set_sigalgs(opssl_ctx_t *ctx, const char *list)
{
    if (!ctx || !list) {
        opssl_set_error(OPSSL_ERR_INVALID_ARGUMENT, NULL);
        return 0;
    }

    /* For now, just validate the list exists */
    ctx->sigalg_count = sizeof(default_sigalgs) / sizeof(default_sigalgs[0]);
    memcpy(ctx->sigalgs, default_sigalgs, sizeof(default_sigalgs));
    return 1;
}

/* Protocol version control */
void
opssl_ctx_set_min_version(opssl_ctx_t *ctx, opssl_tls_version_t ver)
{
    if (ctx)
        ctx->min_version = ver;
}

void
opssl_ctx_set_max_version(opssl_ctx_t *ctx, opssl_tls_version_t ver)
{
    if (ctx)
        ctx->max_version = ver;
}

opssl_tls_version_t
opssl_ctx_get_min_version(const opssl_ctx_t *ctx)
{
    return ctx ? ctx->min_version : 0;
}

opssl_tls_version_t
opssl_ctx_get_max_version(const opssl_ctx_t *ctx)
{
    return ctx ? ctx->max_version : 0;
}

/* Options manipulation */
void
opssl_ctx_set_options(opssl_ctx_t *ctx, uint32_t opts)
{
    if (ctx)
        ctx->options |= opts;
}

void
opssl_ctx_clear_options(opssl_ctx_t *ctx, uint32_t opts)
{
    if (ctx)
        ctx->options &= ~opts;
}

/* SNI support */
int
opssl_ctx_add_sni(opssl_ctx_t *ctx, const char *hostname, opssl_ctx_t *sni_ctx)
{
    if (!ctx || !hostname || !sni_ctx) {
        opssl_set_error(OPSSL_ERR_INVALID_ARGUMENT, NULL);
        return 0;
    }

    if (ctx->sni_count >= sizeof(ctx->sni_table) / sizeof(ctx->sni_table[0])) {
        opssl_set_error(OPSSL_ERR_BUFFER_TOO_SMALL, NULL);
        return 0;
    }

    size_t idx = ctx->sni_count++;
    strncpy(ctx->sni_table[idx].hostname, hostname, sizeof(ctx->sni_table[idx].hostname) - 1);
    ctx->sni_table[idx].hostname[sizeof(ctx->sni_table[idx].hostname) - 1] = '\0';
    ctx->sni_table[idx].ctx = opssl_ctx_ref(sni_ctx);

    return 1;
}

void
opssl_ctx_set_sni_callback(opssl_ctx_t *ctx, opssl_sni_cb cb, void *userdata)
{
    if (ctx) {
        ctx->sni_cb = cb;
        ctx->sni_userdata = userdata;
    }
}

/* ALPN support */
int
opssl_ctx_set_alpn_protos(opssl_ctx_t *ctx, const char **protos, size_t count)
{
    if (!ctx || !protos) {
        opssl_set_error(OPSSL_ERR_INVALID_ARGUMENT, NULL);
        return 0;
    }

    if (count > sizeof(ctx->alpn_protos) / sizeof(ctx->alpn_protos[0])) {
        opssl_set_error(OPSSL_ERR_BUFFER_TOO_SMALL, NULL);
        return 0;
    }

    ctx->alpn_count = 0;
    for (size_t i = 0; i < count; i++) {
        if (protos[i]) {
            strncpy(ctx->alpn_protos[ctx->alpn_count], protos[i],
                   sizeof(ctx->alpn_protos[ctx->alpn_count]) - 1);
            ctx->alpn_protos[ctx->alpn_count][sizeof(ctx->alpn_protos[ctx->alpn_count]) - 1] = '\0';
            ctx->alpn_count++;
        }
    }

    return 1;
}

void
opssl_ctx_set_alpn_callback(opssl_ctx_t *ctx, opssl_alpn_cb cb, void *userdata)
{
    if (ctx) {
        ctx->alpn_cb = cb;
        ctx->alpn_userdata = userdata;
    }
}

/* Session ticket management */
void
opssl_ctx_set_ticket_keys(opssl_ctx_t *ctx, const uint8_t *keys, size_t len)
{
    if (!ctx || !keys || len != sizeof(ctx->ticket_keys))
        return;

    memcpy(ctx->ticket_keys, keys, sizeof(ctx->ticket_keys));
}

void
opssl_ctx_disable_session_cache(opssl_ctx_t *ctx)
{
    if (ctx) {
        ctx->session_cache_enabled = false;
        ctx->tickets_enabled = false;
    }
}

/* Post-quantum cryptography */
int
opssl_ctx_enable_postquantum(opssl_ctx_t *ctx, bool enable)
{
    if (!ctx) {
        opssl_set_error(OPSSL_ERR_INVALID_ARGUMENT, NULL);
        return 0;
    }

    ctx->postquantum_enabled = enable;

    /* Update default groups based on post-quantum preference */
    if (enable) {
        ctx->group_count = sizeof(default_groups) / sizeof(default_groups[0]);
        memcpy(ctx->groups, default_groups, sizeof(default_groups));
    } else {
        /* Exclude post-quantum groups */
        ctx->group_count = 0;
        for (size_t i = 0; i < sizeof(default_groups) / sizeof(default_groups[0]); i++) {
            if (default_groups[i] != OPSSL_GROUP_X25519_MLKEM768) {
                ctx->groups[ctx->group_count++] = default_groups[i];
            }
        }
    }

    return 1;
}

void
opssl_ctx_set_keylog_callback(opssl_ctx_t *ctx, opssl_keylog_cb cb, void *userdata)
{
    if (!ctx) return;
    ctx->keylog_cb = cb;
    ctx->keylog_userdata = userdata;
}

/* Accessor functions for internal use */
opssl_keylog_cb
opssl_ctx_get_keylog_callback(opssl_ctx_t *ctx, void **userdata)
{
    if (!ctx) return NULL;
    if (userdata) *userdata = ctx->keylog_userdata;
    return ctx->keylog_cb;
}

const char **
opssl_ctx_get_alpn_protos(opssl_ctx_t *ctx, size_t *count)
{
    if (!ctx || !count) {
        if (count) *count = 0;
        return NULL;
    }

    *count = ctx->alpn_count;
    if (ctx->alpn_count == 0)
        return NULL;

    /* Build pointer array from char[8][32] storage */
    static _Thread_local const char *ptrs[8];
    for (size_t i = 0; i < ctx->alpn_count && i < 8; i++)
        ptrs[i] = ctx->alpn_protos[i];
    return ptrs;
}

opssl_pkey_t *
opssl_ctx_get_private_key(opssl_ctx_t *ctx)
{
    return ctx ? ctx->private_key : NULL;
}

opssl_x509_store_t *
opssl_ctx_get_trust_store(opssl_ctx_t *ctx)
{
    return ctx ? ctx->trust_store : NULL;
}

bool
opssl_ctx_get_verify_peer(opssl_ctx_t *ctx)
{
    return ctx ? ctx->verify_peer : false;
}

opssl_x509_chain_t *
opssl_ctx_get_cert_chain(opssl_ctx_t *ctx)
{
    return ctx ? ctx->cert_chain : NULL;
}

const uint8_t *
opssl_ctx_get_dtls_cookie_secret(const opssl_ctx_t *ctx)
{
    return ctx ? ctx->dtls_cookie_secret : NULL;
}

/* Session cache mode */
void
opssl_ctx_set_session_cache_mode(opssl_ctx_t *ctx, uint32_t mode)
{
    if (!ctx)
        return;
    ctx->session_cache_mode = mode;
    ctx->session_cache_enabled = (mode != 0);
    ctx->tickets_enabled = (mode & 0x04) != 0;  /* OPSSL_SESS_CACHE_TICKETS */
}

uint32_t
opssl_ctx_get_session_cache_mode(const opssl_ctx_t *ctx)
{
    return ctx ? ctx->session_cache_mode : 0;
}

/* Verify depth */
void
opssl_ctx_set_verify_depth(opssl_ctx_t *ctx, int depth)
{
    if (ctx && depth >= 0)
        ctx->verify_depth = depth;
}

int
opssl_ctx_get_verify_depth(const opssl_ctx_t *ctx)
{
    return ctx ? ctx->verify_depth : 0;
}

/* Async private key operation */
void
opssl_ctx_set_async_sign_callback(opssl_ctx_t *ctx, opssl_async_sign_cb cb, void *userdata)
{
    if (!ctx)
        return;
    ctx->async_sign_cb = cb;
    ctx->async_sign_userdata = userdata;
}

opssl_async_sign_cb
opssl_ctx_get_async_sign_callback(opssl_ctx_t *ctx, void **userdata)
{
    if (!ctx) return NULL;
    if (userdata) *userdata = ctx->async_sign_userdata;
    return ctx->async_sign_cb;
}

/* DTLS cookie callbacks */
void
opssl_ctx_set_dtls_cookie_callbacks(opssl_ctx_t *ctx,
                                     void *gen, void *verify, void *userdata)
{
    if (!ctx)
        return;
    ctx->dtls_cookie_gen_cb = gen;
    ctx->dtls_cookie_verify_cb = verify;
    ctx->dtls_cookie_userdata = userdata;
}
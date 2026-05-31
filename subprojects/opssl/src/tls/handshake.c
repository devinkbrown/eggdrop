/*
 * OpenSSL-compatible TLS library - Handshake dispatcher
 * Copyright (c) 2024 OpSSL Project
 *
 * This file implements the top-level handshake dispatcher that routes
 * to TLS 1.2 or 1.3 implementations based on negotiated version.
 */

#include <opssl/platform.h>
#include <opssl/crypto.h>
#include <opssl/cbs.h>
#include <opssl/err.h>
#include <opssl/types.h>
#include <opssl/cert.h>
#include <opssl/ctx.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <stdio.h>

/* Local compat: map non-existent symbols to available ones */
#define OPSSL_HS_INIT                  OPSSL_HS_IDLE
#define OPSSL_TLS_VERSION_NONE         ((opssl_tls_version_t)0)
#define OPSSL_CIPHER_UNKNOWN           ((opssl_ciphersuite_t)0)
#define OPSSL_GROUP_NONE               ((opssl_named_group_t)0)
#define OPSSL_SERVER                   OPSSL_DIR_INBOUND
#define OPSSL_CLIENT                   OPSSL_DIR_OUTBOUND
#define OPSSL_ERR_UNSUPPORTED_VERSION  OPSSL_ERR_VERSION_MISMATCH
#define OPSSL_ERR_NO_SHARED_VERSION    OPSSL_ERR_NOT_SUPPORTED
#define opssl_aead_ctx_free            opssl_aead_free
extern opssl_tls_version_t opssl_ctx_get_min_version(const opssl_ctx_t *ctx);
extern opssl_tls_version_t opssl_ctx_get_max_version(const opssl_ctx_t *ctx);
#define opssl_ctx_supports_version(ctx, ver) \
    ((ver) >= opssl_ctx_get_min_version(ctx) && (ver) <= opssl_ctx_get_max_version(ctx))

/* TLS record layer constants */
#define TLS_RECORD_HEADER_LEN 5
#define TLS_MAX_RECORD_LEN 16384
#define TLS_MAX_ENCRYPTED_LEN 16640  /* record + MAC + padding */
#define TLS_HANDSHAKE_HEADER_LEN 4
#define TLS12_VERIFY_DATA_LEN 12  /* TLS 1.2 Finished verify_data length */

/* TLS record types */
#define TLS_RT_CHANGE_CIPHER_SPEC 20
#define TLS_RT_ALERT 21
#define TLS_RT_HANDSHAKE 22
#define TLS_RT_APPLICATION_DATA 23

/* TLS handshake types */
#define TLS_HT_CLIENT_HELLO 1
#define TLS_HT_SERVER_HELLO 2
#define TLS_HT_NEW_SESSION_TICKET 4
#define TLS_HT_ENCRYPTED_EXTENSIONS 8
#define TLS_HT_CERTIFICATE 11
#define TLS_HT_SERVER_KEY_EXCHANGE 12
#define TLS_HT_CERTIFICATE_REQUEST 13
#define TLS_HT_SERVER_HELLO_DONE 14
#define TLS_HT_CERTIFICATE_VERIFY 15
#define TLS_HT_CLIENT_KEY_EXCHANGE 16
#define TLS_HT_FINISHED 20

/* TLS encryption epochs (1.3 has three distinct epochs) */
enum tls_epoch {
    TLS_EPOCH_PLAINTEXT = 0,
    TLS_EPOCH_HANDSHAKE = 1,
    TLS_EPOCH_APPLICATION = 2
};

/* Connection structure definition */
struct opssl_conn {
    opssl_ctx_t *ctx;
    int fd;
    opssl_direction_t dir;
    opssl_handshake_state_t hs_state;
    opssl_tls_version_t version;
    opssl_ciphersuite_t cipher;
    opssl_named_group_t group;

    /* I/O buffers */
    uint8_t read_buf[18432];   /* max record + header */
    size_t read_len;
    uint8_t write_buf[18432];
    size_t write_len;
    size_t write_off;

    /* Record layer cipher states */
    opssl_aead_ctx_t *read_cipher;
    opssl_aead_ctx_t *write_cipher;
    uint8_t read_iv[12];
    uint8_t write_iv[12];
    uint64_t read_seq;
    uint64_t write_seq;
    bool read_encrypted;
    bool write_encrypted;
    bool is_tls13;

    /* TLS 1.3 Epoch tracking */
    enum tls_epoch read_epoch;
    enum tls_epoch write_epoch;

    /* Application data buffer (decrypted records waiting for read) */
    uint8_t app_buf[16384];
    size_t app_len;
    size_t app_off;

    /* SNI */
    char sni[256];

    /* ALPN */
    char alpn[32];
    size_t alpn_len;

    /* Custom I/O */
    opssl_read_cb read_cb;
    opssl_write_cb write_cb;
    void *bio_userdata;

    /* Peer certificate */
    opssl_x509_t *peer_cert;

    /* Error */
    opssl_err_t last_error;
    opssl_result_t last_want;

    /* Raw key material (for kTLS offload) */
    uint8_t write_key[32];
    size_t  write_key_len;
    uint8_t read_key[32];
    size_t  read_key_len;

    /* kTLS */
    bool ktls_tx;
    bool ktls_rx;

    /* Traffic secrets (for key update) */
    uint8_t client_traffic_secret[48];
    uint8_t server_traffic_secret[48];
    size_t secret_len;

    /* Resumption (TLS 1.3 session tickets) */
    uint8_t resumption_master_secret[48];
    size_t rms_len;
    uint8_t session_ticket[1024];
    size_t session_ticket_len;
    uint32_t ticket_lifetime;
    uint32_t ticket_age_add;
    uint8_t ticket_psk[48];
    size_t ticket_psk_len;
    bool has_ticket;

    /* TLS 1.3 KeyUpdate write state */
    bool key_update_apply_after_flush;

    /* Handshake state (persists across record exchanges) */
    _Alignas(16) uint8_t hs_buf[4096];  /* opaque storage for tls12_hs_t or tls13_hs_t */
    bool hs_initialized;

    /* Handshake reassembly buffer for multi-record messages */
    uint8_t hs_inbuf[32768];  /* handshake reassembly buffer */
    size_t  hs_inlen;          /* bytes in reassembly buffer */

    /* Post-handshake reassembly buffer (TLS 1.3 NewSessionTicket / KeyUpdate) */
    uint8_t ph_inbuf[4096];   /* post-handshake record accumulator */
    size_t  ph_inlen;          /* bytes accumulated */

    /* Flags */
    bool shutdown_sent;
    bool shutdown_received;
    bool postquantum;
    bool request_client_cert_set;
    bool request_client_cert;

    /* Anti-injection counters: cap spurious CCS records (TLS 1.3 middlebox
     * compat allows exactly one) and cap warning-alert flooding. */
    uint8_t ccs_received;
    uint8_t warning_alerts_received;
};

/* Session resumption structure */
struct opssl_session {
    opssl_tls_version_t version;
    opssl_ciphersuite_t cipher;
    uint8_t psk[48];
    size_t psk_len;
    uint8_t ticket[1024];
    size_t ticket_len;
    uint32_t lifetime;
    uint32_t age_add;
    uint64_t created_at;
};
typedef struct opssl_session opssl_session_t;

/* Forward declarations for handshake handlers */
static opssl_result_t handle_tls12_handshake(opssl_conn_t *conn);
static opssl_result_t handle_tls13_handshake(opssl_conn_t *conn);

/* Forward declaration for cipher setup */
static opssl_result_t setup_cipher_contexts(opssl_conn_t *conn,
                                           const uint8_t *client_key, size_t client_key_len,
                                           const uint8_t *server_key, size_t server_key_len,
                                           const uint8_t *client_iv, size_t client_iv_len,
                                           const uint8_t *server_iv, size_t server_iv_len,
                                           opssl_ciphersuite_t cipher,
                                           enum tls_epoch new_epoch);


/* External handshake implementations — buffer-based state machines.
 * The hs_t structs are opaque here (defined in tls12.c / tls13.c),
 * so we declare with void* and cast from conn->hs_buf. */
extern int opssl_tls12_server_handshake(void *hs, uint8_t *buf, size_t buf_len,
                                        size_t *consumed, uint8_t *out, size_t *out_len,
                                        size_t out_cap);
extern int opssl_tls12_client_handshake(void *hs, uint8_t *buf, size_t buf_len,
                                        size_t *consumed, uint8_t *out, size_t *out_len,
                                        size_t out_cap);
extern int opssl_tls13_server_handshake(void *hs, uint8_t *buf, size_t buf_len,
                                        size_t *consumed, uint8_t *out, size_t *out_len,
                                        size_t out_cap);
extern int opssl_tls13_client_handshake(void *hs, uint8_t *buf, size_t buf_len,
                                        size_t *consumed, uint8_t *out, size_t *out_len,
                                        size_t out_cap);

/* Key extraction functions for cipher setup */
extern int opssl_tls12_extract_traffic_keys(void *hs_opaque,
                                           uint8_t *client_key, size_t *client_key_len,
                                           uint8_t *server_key, size_t *server_key_len,
                                           uint8_t *client_iv, size_t *client_iv_len,
                                           uint8_t *server_iv, size_t *server_iv_len,
                                           opssl_ciphersuite_t *cipher);
extern int opssl_tls13_extract_traffic_keys(void *hs_opaque,
                                           uint8_t *client_key, size_t *client_key_len,
                                           uint8_t *server_key, size_t *server_key_len,
                                           uint8_t *client_iv, size_t *client_iv_len,
                                           uint8_t *server_iv, size_t *server_iv_len,
                                           opssl_ciphersuite_t *cipher);

/* Group accessor for negotiated key exchange group */
extern opssl_named_group_t opssl_tls13_get_negotiated_group(void *hs_opaque);

/* Inject the signing key from ctx into the TLS 1.2 handshake state */
extern void opssl_tls12_set_sign_key(void *hs_opaque, const opssl_pkey_t *key);
extern bool opssl_ciphersuite_get_params(opssl_ciphersuite_t id,
                             opssl_aead_algo_t *aead,
                             opssl_hmac_algo_t *hash,
                             size_t *key_len,
                             size_t *iv_len,
                             size_t *tag_len);
extern void opssl_tls12_set_sni(void *hs_opaque, const char *hostname);
extern const char *opssl_tls12_get_sni(void *hs_opaque);
extern void opssl_tls12_set_alpn_offer(void *hs_opaque, const char **protos, size_t count);
extern void opssl_tls12_set_alpn_supported(void *hs_opaque, const char **protos, size_t count);
extern const char *opssl_tls12_get_alpn(void *hs_opaque);
extern void opssl_tls13_set_sni(void *hs_opaque, const char *hostname);
extern const char *opssl_tls13_get_sni(void *hs_opaque);
extern void opssl_tls13_set_alpn_offer(void *hs_opaque, const char **protos, size_t count);
extern void opssl_tls13_set_alpn_supported(void *hs_opaque, const char **protos, size_t count);
extern const char *opssl_tls13_get_alpn(void *hs_opaque);

/* External: peer cert getters (defined in tls12.c, tls13.c) */
extern const uint8_t *opssl_tls12_get_peer_cert(void *hs_opaque, size_t *out_len);
extern size_t opssl_tls12_get_peer_chain(void *hs_opaque, const uint8_t ***ders,
                                         const size_t **lens);
extern void opssl_tls12_free_peer_cert(void *hs_opaque);
extern const uint8_t *opssl_tls13_get_peer_cert(void *hs_opaque, size_t *out_len);
extern size_t opssl_tls13_get_peer_chain(void *hs_opaque, const uint8_t ***ders,
                                         const size_t **lens);
extern void opssl_tls13_free_peer_cert(void *hs_opaque);
extern void opssl_tls13_set_sign_key(void *hs_opaque, const opssl_pkey_t *key);
extern void opssl_tls13_set_cert_chain(void *hs_opaque, const opssl_x509_chain_t *chain);
extern void opssl_tls13_set_psk(void *hs_opaque, const uint8_t *psk, size_t psk_len,
                                const uint8_t *ticket, size_t ticket_len);
extern const uint8_t *opssl_tls13_get_resumption_master_secret(void *hs_opaque, size_t *out_len);
extern const uint8_t *opssl_tls13_get_client_app_traffic_secret(void *hs_opaque, size_t *out_len);
extern const uint8_t *opssl_tls13_get_server_app_traffic_secret(void *hs_opaque, size_t *out_len);
extern const uint8_t *opssl_tls13_get_exporter_master_secret(void *hs_opaque, size_t *out_len);
extern const uint8_t *opssl_tls13_get_client_random(void *hs_opaque, size_t *out_len);
extern opssl_hmac_algo_t opssl_tls13_get_hash_algo(void *hs_opaque);
extern void opssl_tls13_request_client_cert(void *hs_opaque, bool request);

/* External: ctx accessors (defined in ctx.c) */
extern opssl_pkey_t *opssl_ctx_get_private_key(opssl_ctx_t *ctx);
extern const char **opssl_ctx_get_alpn_protos(opssl_ctx_t *ctx, size_t *count);
extern opssl_x509_store_t *opssl_ctx_get_trust_store(opssl_ctx_t *ctx);
extern bool opssl_ctx_get_verify_peer(opssl_ctx_t *ctx);
extern bool opssl_ctx_get_request_client_cert(opssl_ctx_t *ctx);
extern opssl_x509_chain_t *opssl_ctx_get_cert_chain(opssl_ctx_t *ctx);
extern uint32_t opssl_ctx_get_session_cache_mode(const opssl_ctx_t *ctx);

static opssl_result_t read_record(opssl_conn_t *conn, uint8_t *type, uint8_t **data, size_t *len);
static opssl_result_t write_record(opssl_conn_t *conn, uint8_t type, const uint8_t *data, size_t len);
static ssize_t conn_read(opssl_conn_t *conn, void *buf, size_t len);
static ssize_t conn_write(opssl_conn_t *conn, const void *buf, size_t len);
static opssl_result_t process_application_data(opssl_conn_t *conn, const uint8_t *data, size_t len);
static opssl_result_t process_tls13_post_handshake(opssl_conn_t *conn,
                                                   const uint8_t *data, size_t len);
static opssl_result_t apply_tls13_write_key_update(opssl_conn_t *conn);
static opssl_result_t finish_pending_key_update(opssl_conn_t *conn);

opssl_conn_t *opssl_conn_new(opssl_ctx_t *ctx, int fd, opssl_direction_t dir)
{
    if (!ctx) {
        return NULL;
    }

    opssl_conn_t *conn = calloc(1, sizeof(opssl_conn_t));
    if (!conn) {
        return NULL;
    }

    conn->ctx = opssl_ctx_ref(ctx);
    conn->fd = fd;
    conn->dir = dir;
    conn->hs_state = OPSSL_HS_INIT;
    conn->version = OPSSL_TLS_VERSION_NONE;
    conn->cipher = OPSSL_CIPHER_UNKNOWN;
    conn->group = OPSSL_GROUP_NONE;
    conn->last_error = OPSSL_ERR_NONE;

    /* Set reasonable defaults */
    conn->read_seq = 0;
    conn->write_seq = 0;
    conn->read_encrypted = false;
    conn->write_encrypted = false;
    conn->is_tls13 = false;

    /* Initialize epochs to plaintext */
    conn->read_epoch = TLS_EPOCH_PLAINTEXT;
    conn->write_epoch = TLS_EPOCH_PLAINTEXT;

    return conn;
}

void opssl_conn_free(opssl_conn_t *conn)
{
    if (!conn) {
        return;
    }

    /* Clean up cipher contexts */
    if (conn->read_cipher) {
        opssl_aead_ctx_free(conn->read_cipher);
    }
    if (conn->write_cipher) {
        opssl_aead_ctx_free(conn->write_cipher);
    }

    /* Clean up certificate */
    if (conn->peer_cert) {
        opssl_x509_free(conn->peer_cert);
    }

    conn->fd = -1;   /* fd is owned by libop, not opssl */

    if (conn->ctx) {
        opssl_ctx_free(conn->ctx);
        conn->ctx = NULL;
    }

    opssl_memzero(conn, sizeof(*conn));

    free(conn);
}

opssl_result_t opssl_accept(opssl_conn_t *conn)
{
    if (!conn || conn->dir != OPSSL_SERVER) {
        return OPSSL_ERROR;
    }

    int hs_steps = 0;
    while (conn->hs_state != OPSSL_HS_COMPLETE) {
        if (++hs_steps > 16) {
            conn->last_want = OPSSL_WANT_READ;
            return OPSSL_WANT_READ;
        }

        /* Flush any buffered write data before reading. */
        if (conn->write_len > conn->write_off) {
            ssize_t n = conn_write(conn, conn->write_buf + conn->write_off,
                                   conn->write_len - conn->write_off);
            if (n < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    conn->last_want = OPSSL_WANT_WRITE;
                    return OPSSL_WANT_WRITE;
                }
                conn->last_error = OPSSL_ERR_IO;
                return OPSSL_ERROR;
            }
            conn->write_off += (size_t)n;
            if (conn->write_off < conn->write_len)
                return OPSSL_WANT_WRITE;
            conn->write_len = 0;
            conn->write_off = 0;
        }

        opssl_result_t result;

        /* If we have buffered handshake data, try to process it first */
        if (conn->hs_inlen > 0) {
            if (conn->is_tls13) {
                result = handle_tls13_handshake(conn);
            } else {
                result = handle_tls12_handshake(conn);
            }
            if (result != OPSSL_OK)
                return result;
            continue;
        }

        /* Read and process handshake messages */
        uint8_t record_type;
        uint8_t *record_data;
        size_t record_len;

        result = read_record(conn, &record_type, &record_data, &record_len);
        if (result != OPSSL_OK) {
            return result;
        }

        switch (record_type) {
            case TLS_RT_HANDSHAKE:
                /* Determine TLS version from first message */
                if (conn->version == OPSSL_TLS_VERSION_NONE) {
                    if (record_len < TLS_HANDSHAKE_HEADER_LEN + 2) {
                        conn->last_error = OPSSL_ERR_PROTOCOL;
                        return OPSSL_ERROR;
                    }

                    uint8_t hs_type = record_data[0];
                    if (hs_type != TLS_HT_CLIENT_HELLO) {
                        conn->last_error = OPSSL_ERR_PROTOCOL;
                        return OPSSL_ERROR;
                    }

                    /* Scan ClientHello for supported_versions extension (RFC 8446 §4.2.1).
                     * TLS 1.3 always sends legacy_version=0x0303, so we must
                     * check the extension to distinguish 1.3 from 1.2. */
                    uint16_t client_version = (record_data[4] << 8) | record_data[5];
                    bool has_tls13 = false;

                    uint32_t ch_len = (record_data[1] << 16) | (record_data[2] << 8) | record_data[3];
                    if (4 + ch_len <= record_len) {
                        opssl_cbs_t ch;
                        opssl_cbs_init(&ch, record_data + 4, ch_len);
                        uint16_t ver;
                        opssl_cbs_t random, session_id, ciphers, comp, exts;
                        if (opssl_cbs_get_u16(&ch, &ver) &&
                            opssl_cbs_get_bytes(&ch, &random, 32) &&
                            opssl_cbs_get_u8_length_prefixed(&ch, &session_id) &&
                            opssl_cbs_get_u16_length_prefixed(&ch, &ciphers) &&
                            opssl_cbs_get_u8_length_prefixed(&ch, &comp) &&
                            opssl_cbs_get_u16_length_prefixed(&ch, &exts)) {
                            while (opssl_cbs_len(&exts) >= 4) {
                                uint16_t etype;
                                opssl_cbs_t edata;
                                if (!opssl_cbs_get_u16(&exts, &etype) ||
                                    !opssl_cbs_get_u16_length_prefixed(&exts, &edata))
                                    break;
                                if (etype == 43) { /* supported_versions */
                                    opssl_cbs_t versions;
                                    if (opssl_cbs_get_u8_length_prefixed(&edata, &versions)) {
                                        while (opssl_cbs_len(&versions) >= 2) {
                                            uint16_t sv;
                                            if (!opssl_cbs_get_u16(&versions, &sv)) break;
                                            if (sv == 0x0304) has_tls13 = true;
                                        }
                                    }
                                } else if (etype == 0) { /* server_name */
                                    opssl_cbs_t sni_list;
                                    if (opssl_cbs_get_u16_length_prefixed(&edata, &sni_list)) {
                                        while (opssl_cbs_len(&sni_list) >= 3) {
                                            uint8_t name_type;
                                            opssl_cbs_t name;
                                            if (!opssl_cbs_get_u8(&sni_list, &name_type) ||
                                                !opssl_cbs_get_u16_length_prefixed(&sni_list, &name))
                                                break;
                                            if (name_type == 0) { /* host_name */
                                                size_t nlen = opssl_cbs_len(&name);
                                                if (nlen < sizeof(conn->sni)) {
                                                    memcpy(conn->sni, opssl_cbs_data(&name), nlen);
                                                    conn->sni[nlen] = '\0';
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    if (has_tls13 &&
                        opssl_ctx_supports_version(conn->ctx, OPSSL_TLS_1_3)) {
                        conn->version = OPSSL_TLS_1_3;
                        conn->is_tls13 = true;
                    } else if (client_version >= 0x0303 &&
                               opssl_ctx_supports_version(conn->ctx, OPSSL_TLS_1_2)) {
                        conn->version = OPSSL_TLS_1_2;
                        conn->is_tls13 = false;
                    } else {
                        conn->last_error = OPSSL_ERR_UNSUPPORTED_VERSION;
                        return OPSSL_ERROR;
                    }
                }

                /* Accumulate handshake data in reassembly buffer */
                if (conn->hs_inlen + record_len > sizeof(conn->hs_inbuf)) {
                    conn->last_error = OPSSL_ERR_PROTOCOL;
                    return OPSSL_ERROR;
                }
                memcpy(conn->hs_inbuf + conn->hs_inlen, record_data, record_len);
                conn->hs_inlen += record_len;

                /* Route to appropriate handshake handler */
                if (conn->is_tls13) {
                    result = handle_tls13_handshake(conn);
                } else {
                    result = handle_tls12_handshake(conn);
                }

                conn->read_len = 0;
                if (result != OPSSL_OK)
                    return result;
                break;

            case TLS_RT_CHANGE_CIPHER_SPEC:
                conn->read_len = 0;
                /* Cap spurious CCS to defend against state-confusion injection.
                 * RFC 5246: exactly one CCS per direction immediately before
                 * Finished. RFC 8446 §5: TLS 1.3 permits at most one for
                 * middlebox compatibility. */
                if (conn->ccs_received >= 1) {
                    conn->last_error = OPSSL_ERR_PROTOCOL;
                    return OPSSL_ERROR;
                }
                conn->ccs_received++;
                if (!conn->is_tls13 && conn->read_cipher)
                    conn->read_encrypted = true;
                break;

            case TLS_RT_ALERT:
                conn->read_len = 0;
                /* read_record() guarantees len==2 for ALERT records. */
                if (record_len >= 2) {
                    uint8_t level = record_data[0];
                    uint8_t desc  = record_data[1];
                    /* TLS 1.3 (RFC 8446 §6): every alert during handshake is
                     * fatal regardless of level, with the sole exception of
                     * user_canceled (90). Treat close_notify (0) as fatal too
                     * mid-handshake — peer cannot orderly-close before completion. */
                    if (level == 2 ||
                        (conn->is_tls13 && desc != 90) ||
                        desc == 0) {
                        conn->last_error = OPSSL_ERR_PEER_ALERT;
                        return OPSSL_ERROR;
                    }
                    /* Cap warning-alert flood used as DoS / keepalive vector. */
                    if (++conn->warning_alerts_received > 4) {
                        conn->last_error = OPSSL_ERR_PROTOCOL;
                        return OPSSL_ERROR;
                    }
                }
                break;

            default:
                conn->read_len = 0;
                conn->last_error = OPSSL_ERR_PROTOCOL;
                return OPSSL_ERROR;
        }
    }

    return OPSSL_OK;
}

opssl_result_t opssl_connect(opssl_conn_t *conn)
{
    if (!conn || conn->dir != OPSSL_CLIENT) {
        return OPSSL_ERROR;
    }

    /* Initialize client handshake */
    if (conn->hs_state == OPSSL_HS_INIT) {
        /* Determine preferred TLS version */
        if (opssl_ctx_supports_version(conn->ctx, OPSSL_TLS_1_3)) {
            conn->version = OPSSL_TLS_1_3;
            conn->is_tls13 = true;
        } else if (opssl_ctx_supports_version(conn->ctx, OPSSL_TLS_1_2)) {
            conn->version = OPSSL_TLS_1_2;
            conn->is_tls13 = false;
        } else {
            conn->last_error = OPSSL_ERR_NO_SHARED_VERSION;
            return OPSSL_ERROR;
        }

        conn->hs_state = OPSSL_HS_CLIENT_HELLO;
    }

    int hs_steps = 0;
    while (conn->hs_state != OPSSL_HS_COMPLETE) {
        if (++hs_steps > 16) {
            conn->last_want = OPSSL_WANT_READ;
            return OPSSL_WANT_READ;
        }

        /* Flush any buffered write data before reading.  A previous
         * call may have returned WANT_WRITE with a partial ClientHello
         * (or other handshake flight) still in the write buffer.  The
         * server won't respond until it receives the complete message. */
        if (conn->write_len > conn->write_off) {
            ssize_t n = conn_write(conn, conn->write_buf + conn->write_off,
                                   conn->write_len - conn->write_off);
            if (n < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    conn->last_want = OPSSL_WANT_WRITE;
                    return OPSSL_WANT_WRITE;
                }
                conn->last_error = OPSSL_ERR_IO;
                return OPSSL_ERROR;
            }
            conn->write_off += (size_t)n;
            if (conn->write_off < conn->write_len)
                return OPSSL_WANT_WRITE;
            conn->write_len = 0;
            conn->write_off = 0;
        }

        opssl_result_t result;

        /* First call generates ClientHello without input */
        if (!conn->hs_initialized) {
            if (conn->is_tls13) {
                result = handle_tls13_handshake(conn);
            } else {
                result = handle_tls12_handshake(conn);
            }
            if (result != OPSSL_OK)
                return result;
            continue;
        }

        /* If we have buffered handshake data, try to process it first */
        if (conn->hs_inlen > 0) {
            if (conn->is_tls13) {
                result = handle_tls13_handshake(conn);
            } else {
                result = handle_tls12_handshake(conn);
            }
            if (result != OPSSL_OK) {
                return result;
            }
            /* Continue the loop - we might have more data to process
             * or the handshake might be complete */
            continue;
        }

        /* Read the next record from server */
        uint8_t record_type;
        uint8_t *record_data;
        size_t record_len;

        result = read_record(conn, &record_type, &record_data, &record_len);
        if (result != OPSSL_OK) {
            return result;
        }

        switch (record_type) {
        case TLS_RT_HANDSHAKE:
            /* Accumulate handshake data in reassembly buffer */
            if (conn->hs_inlen + record_len > sizeof(conn->hs_inbuf)) {
                conn->last_error = OPSSL_ERR_PROTOCOL;
                return OPSSL_ERROR;
            }
            memcpy(conn->hs_inbuf + conn->hs_inlen, record_data, record_len);
            conn->hs_inlen += record_len;

            /* Process the accumulated handshake data */
            if (conn->is_tls13) {
                result = handle_tls13_handshake(conn);
            } else {
                result = handle_tls12_handshake(conn);
            }

            /* Always clear read buffer after processing handshake record */
            conn->read_len = 0;

            if (result != OPSSL_OK) {
                return result;
            }
            break;

        case TLS_RT_CHANGE_CIPHER_SPEC:
            conn->read_len = 0;
            if (conn->ccs_received >= 1) {
                conn->last_error = OPSSL_ERR_PROTOCOL;
                return OPSSL_ERROR;
            }
            conn->ccs_received++;
            if (!conn->is_tls13 && conn->read_cipher)
                conn->read_encrypted = true;
            break;

        case TLS_RT_ALERT:
            conn->read_len = 0;
            if (record_len >= 2) {
                uint8_t level = record_data[0];
                uint8_t desc  = record_data[1];
                /* See opssl_accept(): TLS 1.3 treats all alerts as fatal
                 * except user_canceled; close_notify mid-handshake is fatal. */
                if (level == 2 ||
                    (conn->is_tls13 && desc != 90) ||
                    desc == 0) {
                    conn->last_error = OPSSL_ERR_PEER_ALERT;
                    return OPSSL_ERROR;
                }
                if (++conn->warning_alerts_received > 4) {
                    conn->last_error = OPSSL_ERR_PROTOCOL;
                    return OPSSL_ERROR;
                }
            }
            break;

        default:
            conn->read_len = 0;
            conn->last_error = OPSSL_ERR_PROTOCOL;
            return OPSSL_ERROR;
        }
    }

    return OPSSL_OK;
}

ssize_t opssl_read(opssl_conn_t *conn, void *buf, size_t len)
{
    if (!conn || !buf || len == 0) {
        return -1;
    }

    if (conn->hs_state != OPSSL_HS_COMPLETE) {
        conn->last_error = OPSSL_ERR_HANDSHAKE_INCOMPLETE;
        return -1;
    }

    /* First, return any buffered application data */
    if (conn->app_len > conn->app_off) {
        size_t available = conn->app_len - conn->app_off;
        size_t to_copy = (len < available) ? len : available;

        memcpy(buf, conn->app_buf + conn->app_off, to_copy);
        conn->app_off += to_copy;

        /* Reset buffer if fully consumed */
        if (conn->app_off >= conn->app_len) {
            conn->app_len = 0;
            conn->app_off = 0;
        }

        return to_copy;
    }

    /* Need to read more records (bounded to prevent spin on non-app records) */
    int records = 0;
    while (records++ < 16) {
        uint8_t record_type;
        uint8_t *record_data;
        size_t record_len;

        opssl_result_t result = read_record(conn, &record_type, &record_data, &record_len);
        if (result == OPSSL_WANT_READ || result == OPSSL_WANT_WRITE) {
            conn->last_want = result;
            errno = EAGAIN;
            return -1;
        } else if (result != OPSSL_OK) {
            if (conn->last_error == OPSSL_ERR_PEER_CLOSED)
                return 0;
            return -1;
        }

        switch (record_type) {
            case TLS_RT_APPLICATION_DATA:
                result = process_application_data(conn, record_data, record_len);
                conn->read_len = 0;
                if (result != OPSSL_OK) {
                    return -1;
                }

                /* Return data if we have any */
                if (conn->app_len > 0) {
                    size_t to_copy = (len < conn->app_len) ? len : conn->app_len;
                    memcpy(buf, conn->app_buf, to_copy);

                    /* Shift remaining data */
                    if (to_copy < conn->app_len) {
                        memmove(conn->app_buf, conn->app_buf + to_copy,
                               conn->app_len - to_copy);
                        conn->app_len -= to_copy;
                    } else {
                        conn->app_len = 0;
                    }

                    return to_copy;
                }
                break;

            case TLS_RT_ALERT:
                conn->read_len = 0;
                /* read_record() enforces len==2; defensive check anyway. */
                if (record_len < 2) {
                    conn->last_error = OPSSL_ERR_PROTOCOL;
                    return -1;
                }
                {
                    uint8_t level = record_data[0];
                    uint8_t desc  = record_data[1];
                    if (desc == 0) { /* close_notify */
                        conn->shutdown_received = true;
                        return 0; /* EOF */
                    }
                    /* TLS 1.3 (RFC 8446 §6): all alerts fatal except
                     * user_canceled (90). TLS 1.2: only level==fatal kills. */
                    if (level == 2 || (conn->is_tls13 && desc != 90)) {
                        conn->last_error = OPSSL_ERR_PEER_ALERT;
                        return -1;
                    }
                }
                break;

            case TLS_RT_HANDSHAKE:
                conn->read_len = 0;
                if (!conn->is_tls13) {
                    conn->last_error = OPSSL_ERR_PROTOCOL;
                    return -1;
                }
                /* Accumulate into post-handshake reassembly buffer */
                if (record_len > sizeof(conn->ph_inbuf) - conn->ph_inlen) {
                    conn->last_error = OPSSL_ERR_PROTOCOL;
                    return -1;
                }
                memcpy(conn->ph_inbuf + conn->ph_inlen, record_data, record_len);
                conn->ph_inlen += record_len;
                /* Process all complete messages from the buffer */
                while (conn->ph_inlen >= TLS_HANDSHAKE_HEADER_LEN) {
                    uint32_t msg_len = ((uint32_t)conn->ph_inbuf[1] << 16) |
                                       ((uint32_t)conn->ph_inbuf[2] << 8) |
                                       conn->ph_inbuf[3];
                    size_t total = (size_t)TLS_HANDSHAKE_HEADER_LEN + msg_len;
                    if (conn->ph_inlen < total)
                        break; /* wait for more records */
                    result = process_tls13_post_handshake(conn, conn->ph_inbuf, total);
                    /* Consume the processed message */
                    conn->ph_inlen -= total;
                    if (conn->ph_inlen > 0)
                        memmove(conn->ph_inbuf, conn->ph_inbuf + total, conn->ph_inlen);
                    if (result == OPSSL_WANT_READ || result == OPSSL_WANT_WRITE) {
                        conn->last_want = result;
                        errno = EAGAIN;
                        return -1;
                    }
                    if (result != OPSSL_OK)
                        return -1;
                }
                break;

            default:
                conn->read_len = 0;
                conn->last_error = OPSSL_ERR_PROTOCOL;
                return -1;
        }
    }

    conn->last_want = OPSSL_WANT_READ;
    errno = EAGAIN;
    return -1;
}

ssize_t opssl_write(opssl_conn_t *conn, const void *buf, size_t len)
{
    if (!conn || !buf || len == 0) {
        return -1;
    }

    if (conn->hs_state != OPSSL_HS_COMPLETE) {
        conn->last_error = OPSSL_ERR_HANDSHAKE_INCOMPLETE;
        return -1;
    }

    if (conn->shutdown_sent) {
        conn->last_error = OPSSL_ERR_SHUTDOWN_SENT;
        return -1;
    }

    if (conn->key_update_apply_after_flush) {
        opssl_result_t ku = finish_pending_key_update(conn);
        if (ku == OPSSL_WANT_WRITE || ku == OPSSL_WANT_READ) {
            conn->last_want = ku;
            errno = EAGAIN;
            return -1;
        }
        if (ku != OPSSL_OK)
            return -1;
    }

    /* Fragment large writes into TLS record-sized chunks */
    size_t written = 0;
    const uint8_t *data = buf;

    while (written < len) {
        size_t chunk_size = len - written;
        if (chunk_size > TLS_MAX_RECORD_LEN) {
            chunk_size = TLS_MAX_RECORD_LEN;
        }

        uint64_t seq_before = conn->write_seq;
        opssl_result_t result = write_record(conn, TLS_RT_APPLICATION_DATA,
                                           data + written, chunk_size);
        if (result == OPSSL_WANT_WRITE || result == OPSSL_WANT_READ) {
            conn->last_want = result;
            if (conn->write_seq != seq_before)
                written += chunk_size;
            if (written > 0)
                return (ssize_t)written;
            errno = EAGAIN;
            return -1;
        } else if (result != OPSSL_OK) {
            return -1;
        }

        written += chunk_size;
    }

    return written;
}

int opssl_pending(opssl_conn_t *conn)
{
    if (!conn) {
        return 0;
    }

    return (int)(conn->app_len - conn->app_off);
}

opssl_result_t opssl_shutdown(opssl_conn_t *conn)
{
    if (!conn) {
        return OPSSL_ERROR;
    }

    if (!conn->shutdown_sent) {
        /* Send close_notify alert */
        uint8_t alert[2] = {1, 0}; /* warning level, close_notify */
        opssl_result_t result = write_record(conn, TLS_RT_ALERT, alert, 2);
        if (result != OPSSL_OK) {
            return result;
        }
        conn->shutdown_sent = true;
    }

    if (conn->shutdown_received) {
        return OPSSL_OK; /* Clean shutdown complete */
    }

    return OPSSL_WANT_READ; /* Wait for peer's close_notify */
}

opssl_result_t opssl_conn_send_alert(opssl_conn_t *conn,
                                     opssl_alert_level_t level,
                                     opssl_alert_desc_t desc)
{
    if (!conn) return OPSSL_ERROR;

    uint8_t alert[2] = { (uint8_t)level, (uint8_t)desc };
    opssl_result_t result = write_record(conn, TLS_RT_ALERT, alert, 2);
    if (result != OPSSL_OK) return result;

    if (level == OPSSL_ALERT_LEVEL_FATAL) {
        conn->shutdown_sent = true;
    }

    return OPSSL_OK;
}

/* Middlebox compatibility: send fake ChangeCipherSpec (RFC 8446 Appendix D.4) */
static opssl_result_t
send_fake_ccs(opssl_conn_t *conn)
{
    static const uint8_t ccs_byte = 1;
    return write_record(conn, TLS_RT_CHANGE_CIPHER_SPEC, &ccs_byte, 1);
}

/* Key logging in SSLKEYLOGFILE / NSS format */
extern opssl_keylog_cb opssl_ctx_get_keylog_callback(opssl_ctx_t *ctx, void **userdata);

static void
keylog_emit(opssl_conn_t *conn, const char *label,
            const uint8_t *client_random, const uint8_t *secret, size_t secret_len)
{
    if (!conn || !conn->ctx) return;

    void *ud = NULL;
    opssl_keylog_cb cb = opssl_ctx_get_keylog_callback(conn->ctx, &ud);
    if (!cb) return;

    char line[512];
    int off = snprintf(line, sizeof(line), "%s ", label);
    if (off < 0 || (size_t)off >= sizeof(line)) return;

    for (int i = 0; i < 32 && (size_t)off < sizeof(line) - 2; i++)
        off += snprintf(line + off, sizeof(line) - off, "%02x", client_random[i]);

    if ((size_t)off < sizeof(line) - 1)
        off += snprintf(line + off, sizeof(line) - off, " ");

    for (size_t i = 0; i < secret_len && (size_t)off < sizeof(line) - 2; i++)
        off += snprintf(line + off, sizeof(line) - off, "%02x", secret[i]);

    cb(line, ud);
}

int opssl_conn_set_sni(opssl_conn_t *conn, const char *hostname)
{
    if (!conn || !hostname) {
        return 0;
    }

    size_t len = strlen(hostname);
    if (len >= sizeof(conn->sni)) {
        len = sizeof(conn->sni) - 1;
    }

    memcpy(conn->sni, hostname, len);
    conn->sni[len] = '\0';
    return 1;
}

const char *opssl_conn_get_sni(opssl_conn_t *conn)
{
    if (!conn || conn->sni[0] == '\0') {
        return NULL;
    }

    return conn->sni;
}

int opssl_conn_set_alpn(opssl_conn_t *conn, const char **protos, size_t count)
{
    if (!conn || !protos || count == 0) return 0;

    /* Store first protocol that fits */
    size_t len = strlen(protos[0]);
    if (len >= sizeof(conn->alpn)) len = sizeof(conn->alpn) - 1;
    memcpy(conn->alpn, protos[0], len);
    conn->alpn[len] = '\0';
    conn->alpn_len = len;
    return 1;
}

const char *opssl_conn_get_alpn(opssl_conn_t *conn, size_t *len)
{
    if (!conn || conn->alpn_len == 0) {
        if (len) *len = 0;
        return NULL;
    }
    if (len) *len = conn->alpn_len;
    return conn->alpn;
}

opssl_handshake_state_t opssl_conn_get_state(opssl_conn_t *conn)
{
    return conn ? conn->hs_state : OPSSL_HS_INIT;
}

opssl_tls_version_t opssl_conn_version(opssl_conn_t *conn)
{
    return conn ? conn->version : OPSSL_TLS_VERSION_NONE;
}

int opssl_conn_get_fd(opssl_conn_t *conn)
{
    return conn ? conn->fd : -1;
}

void opssl_conn_set_fd(opssl_conn_t *conn, int fd)
{
    if (conn) {
        conn->fd = fd;
    }
}

/* Accessor functions used by ktls.c, export.c, and other modules */

int opssl_conn_get_cipher(opssl_conn_t *conn)
{
    return conn ? (int)conn->cipher : -1;
}

int opssl_conn_set_cipher(opssl_conn_t *conn, int cipher)
{
    if (!conn) return -1;
    conn->cipher = (opssl_ciphersuite_t)cipher;
    return 0;
}

int opssl_conn_get_write_seq(opssl_conn_t *conn, uint64_t *seq)
{
    if (!conn || !seq) return 0;
    *seq = conn->write_seq;
    return 1;
}

int opssl_conn_set_write_seq(opssl_conn_t *conn, uint64_t seq)
{
    if (!conn) return -1;
    conn->write_seq = seq;
    return 0;
}

int opssl_conn_get_read_seq(opssl_conn_t *conn, uint64_t *seq)
{
    if (!conn || !seq) return 0;
    *seq = conn->read_seq;
    return 1;
}

int opssl_conn_set_read_seq(opssl_conn_t *conn, uint64_t seq)
{
    if (!conn) return -1;
    conn->read_seq = seq;
    return 0;
}

int opssl_conn_get_write_key(opssl_conn_t *conn, uint8_t *key, size_t *len)
{
    if (!conn || !key || !len || conn->write_key_len == 0) return -1;
    if (*len < conn->write_key_len) {
        *len = conn->write_key_len;
        return -1;
    }
    memcpy(key, conn->write_key, conn->write_key_len);
    *len = conn->write_key_len;
    return 0;
}

int opssl_conn_set_write_key(opssl_conn_t *conn, const uint8_t *key, size_t len)
{
    if (!conn || !key) return -1;
    if (len > sizeof(conn->write_key)) return -1;
    memcpy(conn->write_key, key, len);
    conn->write_key_len = len;
    if (conn->write_cipher)
        opssl_aead_free(conn->write_cipher);
    opssl_aead_algo_t aead = OPSSL_AEAD_AES_256_GCM;
    if (!opssl_ciphersuite_get_params(conn->cipher, &aead, NULL, NULL, NULL, NULL))
        return -1;
    conn->write_cipher = opssl_aead_new(aead);
    if (!conn->write_cipher) return -1;
    return opssl_aead_set_key(conn->write_cipher, key, len);
}

int opssl_conn_get_read_key(opssl_conn_t *conn, uint8_t *key, size_t *len)
{
    if (!conn || !key || !len || conn->read_key_len == 0) return -1;
    if (*len < conn->read_key_len) {
        *len = conn->read_key_len;
        return -1;
    }
    memcpy(key, conn->read_key, conn->read_key_len);
    *len = conn->read_key_len;
    return 0;
}

int opssl_conn_set_read_key(opssl_conn_t *conn, const uint8_t *key, size_t len)
{
    if (!conn || !key) return -1;
    if (len > sizeof(conn->read_key)) return -1;
    memcpy(conn->read_key, key, len);
    conn->read_key_len = len;
    if (conn->read_cipher)
        opssl_aead_free(conn->read_cipher);
    opssl_aead_algo_t aead = OPSSL_AEAD_AES_256_GCM;
    if (!opssl_ciphersuite_get_params(conn->cipher, &aead, NULL, NULL, NULL, NULL))
        return -1;
    conn->read_cipher = opssl_aead_new(aead);
    if (!conn->read_cipher) return -1;
    return opssl_aead_set_key(conn->read_cipher, key, len);
}

int opssl_conn_get_write_iv(opssl_conn_t *conn, uint8_t *iv, size_t *len)
{
    if (!conn || !iv || !len) return -1;
    if (*len < sizeof(conn->write_iv)) {
        *len = sizeof(conn->write_iv);
        return -1;
    }
    memcpy(iv, conn->write_iv, sizeof(conn->write_iv));
    *len = sizeof(conn->write_iv);
    return 0;
}

int opssl_conn_set_write_iv(opssl_conn_t *conn, const uint8_t *iv, size_t len)
{
    if (!conn || !iv || len > sizeof(conn->write_iv)) return -1;
    memcpy(conn->write_iv, iv, len);
    return 0;
}

int opssl_conn_get_read_iv(opssl_conn_t *conn, uint8_t *iv, size_t *len)
{
    if (!conn || !iv || !len) return -1;
    if (*len < sizeof(conn->read_iv)) {
        *len = sizeof(conn->read_iv);
        return -1;
    }
    memcpy(iv, conn->read_iv, sizeof(conn->read_iv));
    *len = sizeof(conn->read_iv);
    return 0;
}

int opssl_conn_set_read_iv(opssl_conn_t *conn, const uint8_t *iv, size_t len)
{
    if (!conn || !iv || len > sizeof(conn->read_iv)) return -1;
    memcpy(conn->read_iv, iv, len);
    return 0;
}

uint32_t opssl_conn_get_flags(opssl_conn_t *conn)
{
    if (!conn) return 0;
    uint32_t flags = 0;
    if (conn->is_tls13)         flags |= (1u << 0);
    if (conn->read_encrypted)   flags |= (1u << 1);
    if (conn->write_encrypted)  flags |= (1u << 2);
    if (conn->shutdown_sent)    flags |= (1u << 3);
    if (conn->postquantum)      flags |= (1u << 4);
    return flags;
}

void opssl_conn_set_flags(opssl_conn_t *conn, uint32_t flags)
{
    if (!conn) return;
    conn->is_tls13        = (flags & (1u << 0)) != 0;
    conn->read_encrypted  = (flags & (1u << 1)) != 0;
    conn->write_encrypted = (flags & (1u << 2)) != 0;
    conn->shutdown_sent   = (flags & (1u << 3)) != 0;
    conn->postquantum     = (flags & (1u << 4)) != 0;
}

void opssl_conn_set_ktls_active(opssl_conn_t *conn, bool active)
{
    if (!conn) return;
    conn->ktls_tx = active;
    conn->ktls_rx = active;
}

bool opssl_conn_is_ktls_active(opssl_conn_t *conn)
{
    return conn ? (conn->ktls_tx && conn->ktls_rx) : false;
}

void opssl_conn_set_bio(opssl_conn_t *conn, opssl_read_cb read_cb,
                       opssl_write_cb write_cb, void *userdata)
{
    if (!conn) {
        return;
    }

    conn->read_cb = read_cb;
    conn->write_cb = write_cb;
    conn->bio_userdata = userdata;
}

bool opssl_conn_is_outgoing(const opssl_conn_t *conn)
{
    return conn ? (conn->dir == OPSSL_CLIENT) : false;
}

/* ─── Missing conn.h implementations ─────────────────────────────────── */

static const char *cipher_name_table(opssl_ciphersuite_t c)
{
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wswitch"
    switch (c) {
    case OPSSL_TLS_AES_128_GCM_SHA256:       return "TLS_AES_128_GCM_SHA256";
    case OPSSL_TLS_AES_256_GCM_SHA384:       return "TLS_AES_256_GCM_SHA384";
    case OPSSL_TLS_CHACHA20_POLY1305_SHA256: return "TLS_CHACHA20_POLY1305_SHA256";
    case OPSSL_TLS_AES_128_CCM_SHA256:       return "TLS_AES_128_CCM_SHA256";
    case OPSSL_TLS_ECDHE_RSA_AES_128_GCM:   return "ECDHE-RSA-AES128-GCM-SHA256";
    case OPSSL_TLS_ECDHE_RSA_AES_256_GCM:   return "ECDHE-RSA-AES256-GCM-SHA384";
    case OPSSL_TLS_ECDHE_ECDSA_AES_128_GCM: return "ECDHE-ECDSA-AES128-GCM-SHA256";
    case OPSSL_TLS_ECDHE_ECDSA_AES_256_GCM: return "ECDHE-ECDSA-AES256-GCM-SHA384";
    case OPSSL_TLS_ECDHE_RSA_CHACHA20:      return "ECDHE-RSA-CHACHA20-POLY1305";
    case OPSSL_TLS_ECDHE_ECDSA_CHACHA20:    return "ECDHE-ECDSA-CHACHA20-POLY1305";
    case OPSSL_TLS_DHE_RSA_AES_128_GCM:     return "DHE-RSA-AES128-GCM-SHA256";
    case OPSSL_TLS_DHE_RSA_AES_256_GCM:     return "DHE-RSA-AES256-GCM-SHA384";
    case OPSSL_TLS_DHE_RSA_CHACHA20:        return "DHE-RSA-CHACHA20-POLY1305";

    /* TLS 1.2 AES-CCM */
    case OPSSL_TLS_ECDHE_ECDSA_AES_128_CCM: return "ECDHE-ECDSA-AES128-CCM";
    case OPSSL_TLS_ECDHE_ECDSA_AES_256_CCM: return "ECDHE-ECDSA-AES256-CCM";

    default:
        return c == (opssl_ciphersuite_t)0 ? "NONE" : "UNKNOWN";
    }
    #pragma GCC diagnostic pop
}

const char *opssl_conn_cipher_name(opssl_conn_t *conn)
{
    if (!conn) return NULL;
    return cipher_name_table(conn->cipher);
}

opssl_ciphersuite_t opssl_conn_cipher_id(opssl_conn_t *conn)
{
    return conn ? conn->cipher : (opssl_ciphersuite_t)0;
}

opssl_named_group_t opssl_conn_group(opssl_conn_t *conn)
{
    return conn ? conn->group : (opssl_named_group_t)0;
}

opssl_x509_t *opssl_conn_get_peer_cert(opssl_conn_t *conn)
{
    if (!conn || !conn->peer_cert)
        return NULL;
    return opssl_x509_ref(conn->peer_cert);
}

int opssl_conn_get_fingerprint(opssl_conn_t *conn,
                               opssl_fingerprint_method_t method,
                               uint8_t *out, size_t *outlen)
{
    if (!conn || !conn->peer_cert || !out || !outlen)
        return 0;

    /* Use the x509 fingerprinting API directly */
    return opssl_x509_fingerprint(conn->peer_cert, method, out, outlen);
}

int opssl_conn_export_keying_material(opssl_conn_t *conn,
                                      uint8_t *out, size_t outlen,
                                      const char *label,
                                      const uint8_t *context, size_t context_len)
{
    if (!conn || !out || !label || conn->hs_state != OPSSL_HS_COMPLETE)
        return 0;

    if (conn->is_tls13) {
        size_t secret_len = 0;
        const uint8_t *secret =
            opssl_tls13_get_exporter_master_secret(conn->hs_buf, &secret_len);
        if (!secret || secret_len == 0)
            return 0;

        extern int opssl_tls13_derive_secret_compat(uint8_t *out, size_t out_len,
                                                    const uint8_t *secret, size_t secret_len,
                                                    const char *label,
                                                    const uint8_t *context, size_t context_len,
                                                    opssl_hmac_algo_t hash_algo);
        extern int opssl_tls13_hkdf_expand_label(uint8_t *out, size_t out_len,
                                                 const uint8_t *secret, size_t secret_len,
                                                 const char *label,
                                                 const uint8_t *context, size_t context_len,
                                                 opssl_hmac_algo_t hash_algo);
        opssl_hmac_algo_t halgo = opssl_tls13_get_hash_algo(conn->hs_buf);
        uint8_t derived_secret[48];
        uint8_t context_hash[48];

        if (opssl_tls13_derive_secret_compat(derived_secret, secret_len,
                                             secret, secret_len,
                                             label, NULL, 0, halgo) != 1)
            return 0;

        const uint8_t empty_context = 0;
        const uint8_t *context_data = context_len > 0 ? context : &empty_context;
        if (context_len > 0 && !context)
            return 0;

        if (halgo == OPSSL_HMAC_SHA384) {
            opssl_sha384(context_data, context_len, context_hash);
        } else {
            opssl_sha256(context_data, context_len, context_hash);
        }

        int ok = opssl_tls13_hkdf_expand_label(out, outlen,
                                               derived_secret, secret_len,
                                               "exporter",
                                               context_hash, secret_len,
                                               halgo);
        opssl_memzero(derived_secret, sizeof(derived_secret));
        opssl_memzero(context_hash, sizeof(context_hash));
        return ok;
    }

    /* TLS 1.2: RFC 5705 exporter */
    extern int opssl_tls12_export_keying_material(void *hs, uint8_t *out, size_t out_len,
                                                   const char *label,
                                                   const uint8_t *context, size_t context_len);
    return opssl_tls12_export_keying_material(conn->hs_buf, out, outlen,
                                              label, context, context_len);
}

opssl_err_t opssl_conn_get_error(opssl_conn_t *conn)
{
    return conn ? conn->last_error : OPSSL_ERR_PACK(OPSSL_ERR_INTERNAL, OPSSL_ERR_INVALID_ARGUMENT);
}

const char *opssl_conn_get_error_string(opssl_conn_t *conn)
{
    if (!conn) return "null connection";
    if (conn->last_error == OPSSL_ERR_NONE) return "no error";

    opssl_err_category_t category = OPSSL_ERR_GET_CATEGORY(conn->last_error);
    uint32_t reason = OPSSL_ERR_GET_REASON(conn->last_error);

    switch (category) {
    case OPSSL_ERR_NONE:
        switch (reason) {
        case OPSSL_ERR_INVALID_ARGUMENT:     return "invalid argument";
        case OPSSL_ERR_BUFFER_TOO_SMALL:     return "buffer too small";
        case OPSSL_ERR_NOT_SUPPORTED:        return "not supported";
        case OPSSL_ERR_VERSION_MISMATCH:     return "version mismatch";
        case OPSSL_ERR_WANT_READ:            return "want read";
        case OPSSL_ERR_WANT_WRITE:           return "want write";
        case OPSSL_ERR_CONNECTION_LOST:      return "connection lost";
        case OPSSL_ERR_IO_ERROR:             return "I/O error";
        case OPSSL_ERR_PROTOCOL:             return "protocol error";
        case OPSSL_ERR_PEER_ALERT:           return "peer alert";
        case OPSSL_ERR_HANDSHAKE_INCOMPLETE: return "handshake incomplete";
        case OPSSL_ERR_SHUTDOWN_SENT:        return "shutdown already sent";
        case OPSSL_ERR_PEER_CLOSED:          return "peer closed";
        case OPSSL_ERR_RECORD_TOO_LARGE:     return "record too large";
        case OPSSL_ERR_BUFFER_OVERFLOW:      return "buffer overflow";
        default:                             return "unknown error";
        }
    case OPSSL_ERR_TLS:
        switch (reason) {
        case OPSSL_TLS_ERR_HANDSHAKE_FAILURE:    return "TLS handshake failure";
        case OPSSL_TLS_ERR_BAD_CERTIFICATE:      return "bad certificate";
        case OPSSL_TLS_ERR_UNSUPPORTED_CERT:     return "unsupported certificate";
        case OPSSL_TLS_ERR_CERT_REVOKED:         return "certificate revoked";
        case OPSSL_TLS_ERR_CERT_EXPIRED:         return "certificate expired";
        case OPSSL_TLS_ERR_CERT_UNKNOWN:         return "unknown certificate error";
        case OPSSL_TLS_ERR_UNKNOWN_CA:           return "unknown certificate authority";
        case OPSSL_TLS_ERR_ACCESS_DENIED:        return "access denied";
        case OPSSL_TLS_ERR_DECODE_ERROR:         return "decode error";
        case OPSSL_TLS_ERR_DECRYPT_ERROR:        return "decrypt error";
        case OPSSL_TLS_ERR_PROTOCOL_VERSION:     return "protocol version error";
        case OPSSL_TLS_ERR_INSUFFICIENT_SECURITY: return "insufficient security";
        case OPSSL_TLS_ERR_INTERNAL_ERROR:       return "internal TLS error";
        case OPSSL_TLS_ERR_NO_RENEGOTIATION:     return "renegotiation not allowed";
        case OPSSL_TLS_ERR_MISSING_EXTENSION:    return "missing extension";
        case OPSSL_TLS_ERR_UNRECOGNIZED_NAME:    return "unrecognized server name";
        case OPSSL_TLS_ERR_CERTIFICATE_REQUIRED: return "certificate required";
        case OPSSL_TLS_ERR_NO_APPLICATION_PROTOCOL: return "no application protocol";
        default:                                 return "TLS protocol error";
        }
    case OPSSL_ERR_CRYPTO:
        switch (reason) {
        case OPSSL_ERR_INVALID_ARGUMENT:  return "cryptographic invalid argument";
        case OPSSL_ERR_BUFFER_TOO_SMALL:  return "cryptographic buffer too small";
        case OPSSL_ERR_NOT_SUPPORTED:     return "cryptographic operation not supported";
        default:                          return "cryptographic failure";
        }
    case OPSSL_ERR_X509:    return "certificate error";
    case OPSSL_ERR_IO:      return "I/O error";
    case OPSSL_ERR_MEMORY:  return "memory allocation failure";
    case OPSSL_ERR_INTERNAL:
        switch (reason) {
        case OPSSL_ERR_INVALID_ARGUMENT:  return "invalid argument";
        case OPSSL_ERR_BUFFER_TOO_SMALL:  return "buffer too small";
        case OPSSL_ERR_NOT_SUPPORTED:     return "operation not supported";
        case OPSSL_ERR_VERSION_MISMATCH:  return "version mismatch";
        case OPSSL_ERR_PEM_DECODE:        return "PEM decode error";
        case OPSSL_ERR_FILE_READ:         return "file read error";
        case OPSSL_ERR_ALLOC_FAILED:      return "allocation failed";
        default:                          return "internal error";
        }
    default:                return "unknown error";
    }
}

opssl_result_t opssl_conn_get_last_want(opssl_conn_t *conn)
{
    return conn ? conn->last_want : OPSSL_WANT_READ;
}

bool opssl_conn_is_ktls(const opssl_conn_t *conn)
{
    return conn ? (conn->ktls_tx || conn->ktls_rx) : false;
}

bool opssl_conn_is_postquantum(const opssl_conn_t *conn)
{
    if (!conn) return false;

    /* Check if PQ flag is explicitly set */
    if (conn->postquantum) return true;

    /* Check if using a post-quantum hybrid group */
    switch (conn->group) {
    case OPSSL_GROUP_X25519_MLKEM768:
    case OPSSL_GROUP_SECP256R1_MLKEM768:
    case OPSSL_GROUP_SECP384R1_MLKEM1024:
        return true;
    default:
        return false;
    }
}

bool opssl_conn_has_ticket(const opssl_conn_t *conn)
{
    return conn ? conn->has_ticket : false;
}

const uint8_t *opssl_conn_get_ticket_psk(const opssl_conn_t *conn, size_t *out_len)
{
    if (!conn || !conn->has_ticket) {
        if (out_len) *out_len = 0;
        return NULL;
    }
    if (out_len) *out_len = conn->ticket_psk_len;
    return conn->ticket_psk;
}

void opssl_conn_set_psk(opssl_conn_t *conn, const uint8_t *psk, size_t psk_len,
                        const uint8_t *ticket, size_t ticket_len)
{
    if (!conn || !psk || psk_len == 0) return;
    if (psk_len > sizeof(conn->ticket_psk)) psk_len = sizeof(conn->ticket_psk);
    memcpy(conn->ticket_psk, psk, psk_len);
    conn->ticket_psk_len = psk_len;
    if (ticket && ticket_len > 0 && ticket_len <= sizeof(conn->session_ticket)) {
        memcpy(conn->session_ticket, ticket, ticket_len);
        conn->session_ticket_len = ticket_len;
    }
    conn->has_ticket = true;
}

void opssl_conn_request_client_cert(opssl_conn_t *conn, bool request)
{
    if (!conn) return;
    conn->request_client_cert_set = true;
    conn->request_client_cert = request;
    extern void opssl_tls13_request_client_cert(void *hs_opaque, bool request);
    if (conn->is_tls13 && conn->hs_initialized) {
        opssl_tls13_request_client_cert(conn->hs_buf, request);
    }
}

void opssl_conn_set_client_cert(opssl_conn_t *conn,
                                const opssl_pkey_t *key,
                                const opssl_x509_chain_t *chain)
{
    if (!conn) return;
    extern void opssl_tls13_set_client_cert(void *hs_opaque, const opssl_pkey_t *key,
                                            const opssl_x509_chain_t *chain);
    if (conn->is_tls13 && conn->hs_initialized) {
        opssl_tls13_set_client_cert(conn->hs_buf, key, chain);
    }
}

void opssl_conn_set_ocsp_response(opssl_conn_t *conn,
                                  const uint8_t *response, size_t len)
{
    if (!conn) return;
    extern void opssl_tls13_set_ocsp_response(void *hs_opaque, const uint8_t *response, size_t len);
    if (conn->is_tls13 && conn->hs_initialized) {
        opssl_tls13_set_ocsp_response(conn->hs_buf, response, len);
    }
}

void opssl_conn_set_sct_list(opssl_conn_t *conn,
                             const uint8_t *sct_list, size_t len)
{
    if (!conn) return;
    extern void opssl_tls13_set_sct_list(void *hs_opaque, const uint8_t *sct_list, size_t len);
    if (conn->is_tls13 && conn->hs_initialized) {
        opssl_tls13_set_sct_list(conn->hs_buf, sct_list, len);
    }
}

void opssl_conn_set_early_data_max(opssl_conn_t *conn, size_t max_bytes)
{
    if (!conn) return;
    extern void opssl_tls13_set_early_data_max(void *hs_opaque, size_t max_bytes);
    if (conn->is_tls13 && conn->hs_initialized) {
        opssl_tls13_set_early_data_max(conn->hs_buf, max_bytes);
    }
}

bool opssl_conn_early_data_accepted(opssl_conn_t *conn)
{
    if (!conn) return false;
    extern bool opssl_tls13_early_data_accepted(void *hs_opaque);
    if (conn->is_tls13 && conn->hs_initialized) {
        return opssl_tls13_early_data_accepted(conn->hs_buf);
    }
    return false;
}

opssl_result_t opssl_conn_key_update(opssl_conn_t *conn, bool request_peer_update);

opssl_result_t opssl_conn_flush_write(opssl_conn_t *conn)
{
    if (!conn)
        return OPSSL_ERROR;
    if (conn->write_len <= conn->write_off) {
        conn->write_len = 0;
        conn->write_off = 0;
        return OPSSL_OK;
    }
    size_t remain = conn->write_len - conn->write_off;
    ssize_t n = conn_write(conn, conn->write_buf + conn->write_off, remain);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return OPSSL_WANT_WRITE;
        return OPSSL_ERROR;
    }
    conn->write_off += (size_t)n;
    if (conn->write_off >= conn->write_len) {
        conn->write_len = 0;
        conn->write_off = 0;
        return OPSSL_OK;
    }
    return OPSSL_WANT_WRITE;
}

static opssl_result_t
process_tls13_post_handshake(opssl_conn_t *conn, const uint8_t *data, size_t len)
{
    if (!conn || !conn->is_tls13 || !data || len < TLS_HANDSHAKE_HEADER_LEN) {
        if (conn)
            conn->last_error = OPSSL_ERR_PROTOCOL;
        return OPSSL_ERROR;
    }

    size_t off = 0;
    while (off < len) {
        if (len - off < TLS_HANDSHAKE_HEADER_LEN) {
            conn->last_error = OPSSL_ERR_PROTOCOL;
            return OPSSL_ERROR;
        }

        uint8_t msg_type = data[off];
        uint32_t msg_len = ((uint32_t)data[off + 1] << 16) |
                           ((uint32_t)data[off + 2] << 8) |
                           data[off + 3];
        if (msg_len > len - off - TLS_HANDSHAKE_HEADER_LEN) {
            conn->last_error = OPSSL_ERR_PROTOCOL;
            return OPSSL_ERROR;
        }

        const uint8_t *body = data + off + TLS_HANDSHAKE_HEADER_LEN;

        switch (msg_type) {
        case TLS_HT_NEW_SESSION_TICKET: {
            if (msg_len < 12 || conn->rms_len == 0)
                break;

            uint32_t lifetime = ((uint32_t)body[0] << 24) |
                                ((uint32_t)body[1] << 16) |
                                ((uint32_t)body[2] << 8) |
                                body[3];
            uint32_t age_add = ((uint32_t)body[4] << 24) |
                               ((uint32_t)body[5] << 16) |
                               ((uint32_t)body[6] << 8) |
                               body[7];
            uint8_t nonce_len = body[8];
            if ((uint32_t)(9 + nonce_len + 2) > msg_len) {
                conn->last_error = OPSSL_ERR_PROTOCOL;
                return OPSSL_ERROR;
            }

            const uint8_t *nonce = body + 9;
            uint16_t ticket_len = ((uint16_t)body[9 + nonce_len] << 8) |
                                  body[9 + nonce_len + 1];
            if ((uint32_t)(9 + nonce_len + 2 + ticket_len + 2) > msg_len ||
                ticket_len > sizeof(conn->session_ticket)) {
                conn->last_error = OPSSL_ERR_PROTOCOL;
                return OPSSL_ERROR;
            }

            const uint8_t *ticket = body + 9 + nonce_len + 2;
            if (ticket_len > 0) {
                extern int opssl_tls13_hkdf_expand_label(uint8_t *out, size_t out_len,
                    const uint8_t *secret, size_t secret_len,
                    const char *label, const uint8_t *context, size_t context_len,
                    opssl_hmac_algo_t hash_algo);

                opssl_hmac_algo_t halgo = opssl_tls13_get_hash_algo(conn->hs_buf);
                if (opssl_tls13_hkdf_expand_label(conn->ticket_psk, conn->rms_len,
                    conn->resumption_master_secret, conn->rms_len,
                    "resumption", nonce, nonce_len, halgo) != 1) {
                    conn->last_error = OPSSL_ERR_CRYPTO;
                    return OPSSL_ERROR;
                }

                memcpy(conn->session_ticket, ticket, ticket_len);
                conn->session_ticket_len = ticket_len;
                conn->ticket_lifetime = lifetime;
                conn->ticket_age_add = age_add;
                conn->ticket_psk_len = conn->rms_len;
                conn->has_ticket = true;
            }
            break;
        }

        case 24: { /* KeyUpdate */
            if (msg_len != 1 || (body[0] != 0 && body[0] != 1) ||
                conn->secret_len == 0 || conn->read_key_len == 0 ||
                !conn->read_cipher) {
                conn->last_error = OPSSL_ERR_PROTOCOL;
                return OPSSL_ERROR;
            }

            extern int opssl_tls13_hkdf_expand_label(uint8_t *out, size_t out_len,
                                                     const uint8_t *secret, size_t secret_len,
                                                     const char *label,
                                                     const uint8_t *context, size_t context_len,
                                                     opssl_hmac_algo_t hash_algo);

            uint8_t *peer_secret = (conn->dir == OPSSL_SERVER) ?
                conn->client_traffic_secret : conn->server_traffic_secret;
            opssl_hmac_algo_t halgo = opssl_tls13_get_hash_algo(conn->hs_buf);
            uint8_t new_secret[48], new_key[32], new_iv[12];

            if (opssl_tls13_hkdf_expand_label(new_secret, conn->secret_len,
                    peer_secret, conn->secret_len,
                    "traffic upd", NULL, 0, halgo) != 1 ||
                opssl_tls13_hkdf_expand_label(new_key, conn->read_key_len,
                    new_secret, conn->secret_len,
                    "key", NULL, 0, halgo) != 1 ||
                opssl_tls13_hkdf_expand_label(new_iv, sizeof(conn->read_iv),
                    new_secret, conn->secret_len,
                    "iv", NULL, 0, halgo) != 1 ||
                opssl_aead_set_key(conn->read_cipher, new_key, conn->read_key_len) != 1) {
                opssl_memzero(new_secret, sizeof(new_secret));
                opssl_memzero(new_key, sizeof(new_key));
                opssl_memzero(new_iv, sizeof(new_iv));
                conn->last_error = OPSSL_ERR_CRYPTO;
                return OPSSL_ERROR;
            }

            memcpy(peer_secret, new_secret, conn->secret_len);
            memcpy(conn->read_iv, new_iv, sizeof(conn->read_iv));
            memcpy(conn->read_key, new_key, conn->read_key_len);
            conn->read_seq = 0;

            opssl_memzero(new_secret, sizeof(new_secret));
            opssl_memzero(new_key, sizeof(new_key));
            opssl_memzero(new_iv, sizeof(new_iv));

            if (body[0] == 1) {
                opssl_result_t ku = opssl_conn_key_update(conn, false);
                if (ku != OPSSL_OK)
                    return ku;
            }
            break;
        }

        case TLS_HT_CERTIFICATE_REQUEST:
            conn->last_error = OPSSL_ERR_NOT_SUPPORTED;
            return OPSSL_ERROR;

        default:
            conn->last_error = OPSSL_ERR_PROTOCOL;
            return OPSSL_ERROR;
        }

        off += TLS_HANDSHAKE_HEADER_LEN + msg_len;
    }

    return OPSSL_OK;
}

opssl_result_t opssl_conn_drain_post_handshake(opssl_conn_t *conn)
{
    if (!conn || conn->hs_state != OPSSL_HS_COMPLETE)
        return OPSSL_ERROR;

    /* For TLS 1.3 only - drain post-handshake messages */
    if (!conn->is_tls13)
        return OPSSL_OK;

    /* Try to read any pending records without blocking */
    uint8_t record_type;
    uint8_t *data;
    size_t len;

    while (1) {
        opssl_result_t result = read_record(conn, &record_type, &data, &len);

        if (result == OPSSL_WANT_READ) {
            /* No more data available */
            return OPSSL_OK;
        }

        if (result != OPSSL_OK) {
            /* Error reading */
            return result;
        }

        if (record_type == TLS_RT_HANDSHAKE) {
            /* Accumulate into post-handshake reassembly buffer */
            if (len > sizeof(conn->ph_inbuf) - conn->ph_inlen) {
                conn->last_error = OPSSL_ERR_PROTOCOL;
                return OPSSL_ERROR;
            }
            memcpy(conn->ph_inbuf + conn->ph_inlen, data, len);
            conn->ph_inlen += len;
            /* Process all complete messages */
            while (conn->ph_inlen >= TLS_HANDSHAKE_HEADER_LEN) {
                uint32_t msg_len = ((uint32_t)conn->ph_inbuf[1] << 16) |
                                   ((uint32_t)conn->ph_inbuf[2] << 8) |
                                   conn->ph_inbuf[3];
                size_t total = (size_t)TLS_HANDSHAKE_HEADER_LEN + msg_len;
                if (conn->ph_inlen < total)
                    break;
                result = process_tls13_post_handshake(conn, conn->ph_inbuf, total);
                conn->ph_inlen -= total;
                if (conn->ph_inlen > 0)
                    memmove(conn->ph_inbuf, conn->ph_inbuf + total, conn->ph_inlen);
                if (result != OPSSL_OK)
                    return result;
            }
        } else if (record_type == TLS_RT_APPLICATION_DATA) {
            result = process_application_data(conn, data, len);
            if (result != OPSSL_OK)
                return result;
            conn->read_len = 0;
            return OPSSL_OK;
        } else if (record_type == TLS_RT_ALERT) {
            conn->read_len = 0;
            if (len < 2) {
                conn->last_error = OPSSL_ERR_PROTOCOL;
                return OPSSL_ERROR;
            }
            {
                uint8_t level = data[0];
                uint8_t desc  = data[1];
                if (desc == 0) { /* close_notify */
                    conn->shutdown_received = true;
                    return OPSSL_OK;
                }
                /* TLS 1.3 (RFC 8446 §6): all alerts fatal except
                 * user_canceled (90). TLS 1.2: only level==fatal kills. */
                if (level == 2 || (conn->is_tls13 && desc != 90)) {
                    conn->last_error = OPSSL_ERR_PEER_ALERT;
                    return OPSSL_ERROR;
                }
            }
            /* Warning alert in TLS 1.2 or user_canceled in TLS 1.3: ignore */
        } else {
            conn->last_error = OPSSL_ERR_PROTOCOL;
            return OPSSL_ERROR;
        }

        /* Reset read buffer for next record */
        conn->read_len = 0;
    }
}

opssl_result_t opssl_conn_key_update(opssl_conn_t *conn, bool request_peer_update)
{
    if (!conn || !conn->is_tls13 || conn->hs_state != OPSSL_HS_COMPLETE)
        return OPSSL_ERROR;

    if (conn->key_update_apply_after_flush)
        return finish_pending_key_update(conn);

    if (conn->secret_len == 0 || conn->write_key_len == 0 || !conn->write_cipher) {
        conn->last_error = OPSSL_ERR_PROTOCOL;
        return OPSSL_ERROR;
    }

    if (conn->write_len > conn->write_off) {
        opssl_result_t flush = opssl_conn_flush_write(conn);
        if (flush != OPSSL_OK)
            return flush;
    }

    /* Build KeyUpdate message: type (1 byte) */
    uint8_t ku_msg[5];
    ku_msg[0] = 24; /* key_update message type */
    ku_msg[1] = 0; ku_msg[2] = 0; ku_msg[3] = 1; /* length = 1 */
    ku_msg[4] = request_peer_update ? 1 : 0;

    opssl_result_t rc = write_record(conn, TLS_RT_HANDSHAKE, ku_msg, sizeof(ku_msg));
    if (rc == OPSSL_WANT_WRITE || rc == OPSSL_WANT_READ) {
        conn->key_update_apply_after_flush = true;
        return rc;
    }
    if (rc != OPSSL_OK)
        return rc;

    return apply_tls13_write_key_update(conn);
}

static opssl_result_t
finish_pending_key_update(opssl_conn_t *conn)
{
    opssl_result_t flush = opssl_conn_flush_write(conn);
    if (flush != OPSSL_OK)
        return flush;

    conn->key_update_apply_after_flush = false;
    return apply_tls13_write_key_update(conn);
}

static opssl_result_t
apply_tls13_write_key_update(opssl_conn_t *conn)
{
    if (!conn || conn->secret_len == 0 || conn->write_key_len == 0 ||
        !conn->write_cipher) {
        if (conn)
            conn->last_error = OPSSL_ERR_PROTOCOL;
        return OPSSL_ERROR;
    }

    extern int opssl_tls13_hkdf_expand_label(uint8_t *out, size_t out_len,
                                             const uint8_t *secret, size_t secret_len,
                                             const char *label,
                                             const uint8_t *context, size_t context_len,
                                             opssl_hmac_algo_t hash_algo);

    uint8_t *our_secret = (conn->dir == OPSSL_SERVER) ?
        conn->server_traffic_secret : conn->client_traffic_secret;

    opssl_hmac_algo_t halgo_w = opssl_tls13_get_hash_algo(conn->hs_buf);

    uint8_t new_secret[48];
    if (opssl_tls13_hkdf_expand_label(new_secret, conn->secret_len,
                                       our_secret, conn->secret_len,
                                       "traffic upd", NULL, 0,
                                       halgo_w) != 1) {
        conn->last_error = OPSSL_ERR_CRYPTO;
        return OPSSL_ERROR;
    }
    memcpy(our_secret, new_secret, conn->secret_len);

    uint8_t new_key[32], new_iv[12];
    if (opssl_tls13_hkdf_expand_label(new_key, conn->write_key_len,
                                       new_secret, conn->secret_len,
                                       "key", NULL, 0, halgo_w) != 1 ||
        opssl_tls13_hkdf_expand_label(new_iv, 12,
                                       new_secret, conn->secret_len,
                                       "iv", NULL, 0, halgo_w) != 1) {
        opssl_memzero(new_secret, sizeof(new_secret));
        conn->last_error = OPSSL_ERR_CRYPTO;
        return OPSSL_ERROR;
    }

    /* Re-key the write cipher */
    if (opssl_aead_set_key(conn->write_cipher, new_key, conn->write_key_len) != 1) {
        opssl_memzero(new_secret, sizeof(new_secret));
        opssl_memzero(new_key, sizeof(new_key));
        opssl_memzero(new_iv, sizeof(new_iv));
        conn->last_error = OPSSL_ERR_CRYPTO;
        return OPSSL_ERROR;
    }
    memcpy(conn->write_iv, new_iv, 12);
    memcpy(conn->write_key, new_key, conn->write_key_len);
    conn->write_seq = 0;

    opssl_memzero(new_secret, sizeof(new_secret));
    opssl_memzero(new_key, sizeof(new_key));
    opssl_memzero(new_iv, sizeof(new_iv));

    return OPSSL_OK;
}

/* Private implementation functions */

static ssize_t conn_read(opssl_conn_t *conn, void *buf, size_t len)
{
    if (conn->read_cb) {
        /* For custom BIO callbacks: 0 means EOF, -1 with EAGAIN means no data available */
        return conn->read_cb(conn->bio_userdata, buf, len);
    } else {
        return read(conn->fd, buf, len);
    }
}

static ssize_t conn_write(opssl_conn_t *conn, const void *buf, size_t len)
{
    ssize_t result;
    if (conn->write_cb) {
        result = conn->write_cb(conn->bio_userdata, buf, len);
    } else {
        result = write(conn->fd, buf, len);
    }

    /* Issue 12: conn_write() treats 0 as forward progress.
     * If write() returns 0, treat as EAGAIN (no progress) */
    if (result == 0) {
        errno = EAGAIN;
        return -1;
    }

    return result;
}

static opssl_result_t read_record(opssl_conn_t *conn, uint8_t *type,
                                 uint8_t **data, size_t *len)
{
    /* Read TLS record header if not already buffered */
    while (conn->read_len < TLS_RECORD_HEADER_LEN) {
        ssize_t n = conn_read(conn, conn->read_buf + conn->read_len,
                             TLS_RECORD_HEADER_LEN - conn->read_len);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return OPSSL_WANT_READ;
            }
            conn->last_error = OPSSL_ERR_IO;
            return OPSSL_ERROR;
        } else if (n == 0) {
            conn->last_error = OPSSL_ERR_PEER_CLOSED;
            return OPSSL_ERROR;
        }

        conn->read_len += n;
    }

    /* Parse record header */
    *type = conn->read_buf[0];
    uint16_t rec_version = (conn->read_buf[1] << 8) | conn->read_buf[2];
    uint16_t record_len = (conn->read_buf[3] << 8) | conn->read_buf[4];

    /* Issue 14: Validate record version (for practical interoperability) */
    if (rec_version < 0x0300 || rec_version > 0x0304) {
        conn->last_error = OPSSL_ERR_VERSION_MISMATCH;
        return OPSSL_ERROR;
    }

    /* Validate record length */
    if (record_len > TLS_MAX_ENCRYPTED_LEN) {
        conn->last_error = OPSSL_ERR_RECORD_TOO_LARGE;
        return OPSSL_ERROR;
    }

    /* Read record payload */
    size_t total_len = TLS_RECORD_HEADER_LEN + record_len;
    while (conn->read_len < total_len) {
        ssize_t n = conn_read(conn, conn->read_buf + conn->read_len,
                             total_len - conn->read_len);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return OPSSL_WANT_READ;
            }
            conn->last_error = OPSSL_ERR_IO;
            return OPSSL_ERROR;
        } else if (n == 0) {
            conn->last_error = OPSSL_ERR_PEER_CLOSED;
            return OPSSL_ERROR;
        }

        conn->read_len += n;
    }

    /* Decrypt if encryption is active */
    /* TLS 1.3: CCS records are never encrypted (middlebox compatibility) */
    if (conn->is_tls13 && conn->read_encrypted &&
        *type != TLS_RT_APPLICATION_DATA &&
        *type != TLS_RT_CHANGE_CIPHER_SPEC) {
        conn->last_error = OPSSL_ERR_PROTOCOL;
        return OPSSL_ERROR;
    }

    if (*type == TLS_RT_CHANGE_CIPHER_SPEC) {
        if (record_len != 1 ||
            conn->read_buf[TLS_RECORD_HEADER_LEN] != 1 ||
            conn->hs_state == OPSSL_HS_COMPLETE ||
            (!conn->is_tls13 && conn->read_encrypted)) {
            conn->last_error = OPSSL_ERR_PROTOCOL;
            return OPSSL_ERROR;
        }

        *data = conn->read_buf + TLS_RECORD_HEADER_LEN;
        *len = record_len;
        return OPSSL_OK;
    }

    if (conn->read_encrypted && conn->read_cipher &&
        !(*type == TLS_RT_CHANGE_CIPHER_SPEC && conn->is_tls13)) {
        /* Issue 5: Handle different nonce construction and record formats */
        uint8_t nonce[12];
        uint8_t *payload = conn->read_buf + TLS_RECORD_HEADER_LEN;
        size_t ciphertext_len = record_len;

        if (conn->is_tls13) {
            /* TLS 1.3: IV XOR sequence number */
            memcpy(nonce, conn->read_iv, 12);
            for (int i = 0; i < 8; i++) {
                nonce[4 + i] ^= (uint8_t)(conn->read_seq >> (56 - i * 8));
            }
        } else {
            /* TLS 1.2 AEAD - explicit nonce is first 8 bytes of payload */
            if (record_len < 8) {
                conn->last_error = OPSSL_ERR_PROTOCOL;
                return OPSSL_ERROR;
            }

            /* First 4 bytes are implicit nonce from IV, last 8 bytes are explicit */
            memcpy(nonce, conn->read_iv, 4);  /* implicit part */
            memcpy(nonce + 4, payload, 8);   /* explicit part from record */

            /* Actual ciphertext starts after explicit nonce */
            payload += 8;
            ciphertext_len -= 8;
        }

        /* Construct AAD based on TLS version */
        uint8_t aad[13];
        size_t aad_len;
        if (conn->is_tls13) {
            /* TLS 1.3 AAD: record header (content_type=0x17 + legacy_version=0x0303 + length) */
            aad[0] = 0x17;                           /* application_data */
            aad[1] = 0x03; aad[2] = 0x03;           /* legacy version */
            aad[3] = (record_len >> 8) & 0xff;      /* ciphertext length */
            aad[4] = record_len & 0xff;
            aad_len = 5;
        } else {
            /* TLS 1.2 AAD: seq_num(8) + content_type(1) + version(2) + plaintext_length(2) */
            for (int i = 0; i < 8; i++) {
                aad[i] = (uint8_t)(conn->read_seq >> (56 - i * 8));
            }
            aad[8] = *type;                         /* content type */
            aad[9] = 0x03; aad[10] = 0x03;         /* version */
            /* For TLS 1.2, plaintext length = ciphertext length - tag length */
            opssl_aead_algo_t wr_aead = OPSSL_AEAD_AES_256_GCM;
            size_t tag_len = 16;
            if (opssl_ciphersuite_get_params(conn->cipher, &wr_aead, NULL, NULL, NULL, &tag_len) && tag_len == 0)
                tag_len = 16;
            if (ciphertext_len < tag_len) {
                conn->last_error = OPSSL_ERR_PROTOCOL;
                return OPSSL_ERROR;
            }
            size_t plaintext_len = ciphertext_len - tag_len;
            aad[11] = (plaintext_len >> 8) & 0xff;
            aad[12] = plaintext_len & 0xff;
            aad_len = 13;
        }

        /* Decrypt record */
        size_t plaintext_len;
        size_t max_plaintext = sizeof(conn->read_buf) - TLS_RECORD_HEADER_LEN;
        int result = opssl_aead_open(conn->read_cipher,
                                   conn->read_buf + TLS_RECORD_HEADER_LEN,
                                   &plaintext_len, max_plaintext,
                                   nonce, 12,
                                   payload, ciphertext_len,
                                   aad, aad_len);

        if (result != 1) {
            conn->last_error = OPSSL_ERR_PROTOCOL;
            return OPSSL_ERROR;
        }

        /* Issue 7: Check for completely empty decrypted records */
        if (plaintext_len == 0) {
            conn->last_error = OPSSL_ERR_PROTOCOL;
            return OPSSL_ERROR;
        }

        /* Issue 6: TLS 1.3 content type parsing - scan backwards over padding */
        if (conn->is_tls13) {
            /* Scan backwards over zero padding */
            size_t i = plaintext_len;
            while (i > 0 && conn->read_buf[TLS_RECORD_HEADER_LEN + i - 1] == 0)
                i--;

            if (i == 0) {
                /* Error: no content type found (all zeros) */
                conn->last_error = OPSSL_ERR_PROTOCOL;
                return OPSSL_ERROR;
            }

            *type = conn->read_buf[TLS_RECORD_HEADER_LEN + i - 1];
            plaintext_len = i - 1;  /* Content length without the content type byte */
        }

        *data = conn->read_buf + TLS_RECORD_HEADER_LEN;
        *len = plaintext_len;
        conn->read_len = TLS_RECORD_HEADER_LEN + plaintext_len;
        conn->read_seq++;
    } else {
        *data = conn->read_buf + TLS_RECORD_HEADER_LEN;
        *len = record_len;
    }

    if (*type == TLS_RT_ALERT && *len != 2) {
        conn->last_error = OPSSL_ERR_PROTOCOL;
        return OPSSL_ERROR;
    }

    if (conn->hs_state != OPSSL_HS_COMPLETE) {
        if (*type == TLS_RT_APPLICATION_DATA) {
            conn->last_error = OPSSL_ERR_PROTOCOL;
            return OPSSL_ERROR;
        }
        if (*type != TLS_RT_HANDSHAKE && *type != TLS_RT_ALERT) {
            conn->last_error = OPSSL_ERR_PROTOCOL;
            return OPSSL_ERROR;
        }
    } else {
        if (*type == TLS_RT_CHANGE_CIPHER_SPEC ||
            (*type == TLS_RT_HANDSHAKE && !conn->is_tls13)) {
            conn->last_error = OPSSL_ERR_PROTOCOL;
            return OPSSL_ERROR;
        }
        if (*type != TLS_RT_APPLICATION_DATA &&
            *type != TLS_RT_ALERT &&
            *type != TLS_RT_HANDSHAKE) {
            conn->last_error = OPSSL_ERR_PROTOCOL;
            return OPSSL_ERROR;
        }
    }

    return OPSSL_OK;
}

static opssl_result_t write_record(opssl_conn_t *conn, uint8_t type,
                                  const uint8_t *data, size_t len)
{
    /* Issue 8: Validate plaintext length */
    if (len > TLS_MAX_RECORD_LEN) {
        conn->last_error = OPSSL_ERR_PROTOCOL;
        return OPSSL_ERROR;
    }

    /* Flush any pending write data before building a new record */
    if (conn->write_len > conn->write_off) {
        ssize_t n = conn_write(conn, conn->write_buf + conn->write_off,
                              conn->write_len - conn->write_off);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                return OPSSL_WANT_WRITE;
            conn->last_error = OPSSL_ERR_IO;
            return OPSSL_ERROR;
        }
        conn->write_off += (size_t)n;
        if (conn->write_off < conn->write_len)
            return OPSSL_WANT_WRITE;
        conn->write_len = 0;
        conn->write_off = 0;
    }

    /* Build new record */
    uint16_t version = conn->is_tls13 ? 0x0303 : 0x0303; /* TLS 1.2 on wire */

    conn->write_buf[0] = type;
    conn->write_buf[1] = (version >> 8) & 0xff;
    conn->write_buf[2] = version & 0xff;

    if (conn->write_encrypted && conn->write_cipher) {
        /* Issue 5: Construct nonce based on TLS version */
        uint8_t nonce[12];
        memcpy(nonce, conn->write_iv, 12);

        if (conn->is_tls13) {
            /* TLS 1.3: IV XOR sequence number */
            for (int i = 0; i < 8; i++) {
                nonce[4 + i] ^= (uint8_t)(conn->write_seq >> (56 - i * 8));
            }
        } else {
            /* TLS 1.2: explicit nonce is sequence number (last 8 bytes of nonce) */
            for (int i = 0; i < 8; i++) {
                nonce[4 + i] = (uint8_t)(conn->write_seq >> (56 - i * 8));
            }
        }

        /* Prepare plaintext: for TLS 1.3, append real content type */
        uint8_t inner_plaintext[16384 + 1];
        const uint8_t *pt = data;
        size_t pt_len = len;

        if (len > 16384) {
            conn->last_error = OPSSL_ERR_PROTOCOL;
            return OPSSL_ERROR;
        }

        if (conn->is_tls13) {
            memcpy(inner_plaintext, data, len);
            inner_plaintext[len] = type;
            pt = inner_plaintext;
            pt_len = len + 1;
            conn->write_buf[0] = 0x17;  /* outer type is always application_data */
        }

        /* Construct AAD based on TLS version */
        uint8_t aad[13];
        size_t aad_len;
        if (conn->is_tls13) {
            size_t tag_len = 16;
            opssl_ciphersuite_get_params(conn->cipher, NULL, NULL, NULL, NULL, &tag_len);
            if (tag_len == 0) tag_len = 16;
            size_t ct_len = pt_len + tag_len;
            aad[0] = 0x17;
            aad[1] = 0x03; aad[2] = 0x03;
            aad[3] = (ct_len >> 8) & 0xff;
            aad[4] = ct_len & 0xff;
            aad_len = 5;
        } else {
            for (int i = 0; i < 8; i++) {
                aad[i] = (uint8_t)(conn->write_seq >> (56 - i * 8));
            }
            aad[8] = type;
            aad[9] = 0x03; aad[10] = 0x03;
            aad[11] = (len >> 8) & 0xff;
            aad[12] = len & 0xff;
            aad_len = 13;
        }

        /* Issue 5: Handle different record formats for TLS 1.2 vs 1.3 */
        if (conn->is_tls13) {
            /* TLS 1.3: Encrypt directly */
            size_t ciphertext_len;
            size_t max_ciphertext = sizeof(conn->write_buf) - TLS_RECORD_HEADER_LEN;
            int result = opssl_aead_seal(conn->write_cipher,
                                       conn->write_buf + TLS_RECORD_HEADER_LEN,
                                       &ciphertext_len, max_ciphertext,
                                       nonce, 12,
                                       pt, pt_len,
                                       aad, aad_len);

            if (result != 1) {
                conn->last_error = OPSSL_ERR_PROTOCOL;
                return OPSSL_ERROR;
            }

            /* Update record header with ciphertext length */
            conn->write_buf[3] = (ciphertext_len >> 8) & 0xff;
            conn->write_buf[4] = ciphertext_len & 0xff;
            conn->write_len = TLS_RECORD_HEADER_LEN + ciphertext_len;
        } else {
            /* TLS 1.2: Prepend explicit nonce (8 bytes) before ciphertext */
            size_t ciphertext_len;
            size_t max_ciphertext = sizeof(conn->write_buf) - TLS_RECORD_HEADER_LEN - 8;

            /* Write explicit nonce first */
            for (int i = 0; i < 8; i++) {
                conn->write_buf[TLS_RECORD_HEADER_LEN + i] = (uint8_t)(conn->write_seq >> (56 - i * 8));
            }

            int result = opssl_aead_seal(conn->write_cipher,
                                       conn->write_buf + TLS_RECORD_HEADER_LEN + 8,
                                       &ciphertext_len, max_ciphertext,
                                       nonce, 12,
                                       pt, pt_len,
                                       aad, aad_len);

            if (result != 1) {
                conn->last_error = OPSSL_ERR_PROTOCOL;
                return OPSSL_ERROR;
            }

            /* Update record header with total length (explicit nonce + ciphertext) */
            size_t total_len = 8 + ciphertext_len;
            conn->write_buf[3] = (total_len >> 8) & 0xff;
            conn->write_buf[4] = total_len & 0xff;
            conn->write_len = TLS_RECORD_HEADER_LEN + total_len;
        }
        /* RFC 5246 §6.1 / RFC 8446 §5.3: sequence number MUST NOT wrap */
        if (conn->write_seq == UINT64_MAX) {
            conn->last_error = OPSSL_ERR_PROTOCOL;
            return OPSSL_ERROR;
        }
        conn->write_seq++;
    } else {
        conn->write_buf[3] = (len >> 8) & 0xff;
        conn->write_buf[4] = len & 0xff;
        memcpy(conn->write_buf + TLS_RECORD_HEADER_LEN, data, len);
        conn->write_len = TLS_RECORD_HEADER_LEN + len;
    }

    /* Try to write immediately */
    ssize_t n = conn_write(conn, conn->write_buf, conn->write_len);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            conn->write_off = 0;
            return OPSSL_WANT_WRITE;
        }
        conn->last_error = OPSSL_ERR_IO;
        return OPSSL_ERROR;
    }

    conn->write_off = n;
    if (conn->write_off < conn->write_len) {
        return OPSSL_WANT_WRITE;
    }

    /* Successfully written */
    conn->write_len = 0;
    conn->write_off = 0;

    return OPSSL_OK;
}

static opssl_result_t process_application_data(opssl_conn_t *conn,
                                              const uint8_t *data, size_t len)
{
    /* Ensure we have space in application buffer */
    if (len > sizeof(conn->app_buf) - conn->app_len) {
        conn->last_error = OPSSL_ERR_BUFFER_OVERFLOW;
        return OPSSL_ERROR;
    }

    /* Copy decrypted data to application buffer */
    memcpy(conn->app_buf + conn->app_len, data, len);
    conn->app_len += len;

    return OPSSL_OK;
}

static opssl_result_t handle_tls12_handshake(opssl_conn_t *conn)
{
    if (!conn->hs_initialized) {
        memset(conn->hs_buf, 0, sizeof(conn->hs_buf));
        conn->hs_initialized = true;

        size_t alpn_count = 0;
        const char **alpn_protos = opssl_ctx_get_alpn_protos(conn->ctx, &alpn_count);

        if (conn->dir == OPSSL_SERVER) {
            opssl_pkey_t *key = opssl_ctx_get_private_key(conn->ctx);
            if (key)
                opssl_tls12_set_sign_key(conn->hs_buf, key);
            extern void opssl_tls12_set_cert_chain(void *, const opssl_x509_chain_t *);
            opssl_x509_chain_t *chain = opssl_ctx_get_cert_chain(conn->ctx);
            if (chain)
                opssl_tls12_set_cert_chain(conn->hs_buf, chain);
            if (alpn_protos && alpn_count > 0)
                opssl_tls12_set_alpn_supported(conn->hs_buf, alpn_protos, alpn_count);
            extern void opssl_tls12_set_tls13_capable(void *, bool);
            if (opssl_ctx_supports_version(conn->ctx, OPSSL_TLS_1_3))
                opssl_tls12_set_tls13_capable(conn->hs_buf, true);
        } else {
            if (conn->sni[0])
                opssl_tls12_set_sni(conn->hs_buf, conn->sni);
            if (alpn_protos && alpn_count > 0)
                opssl_tls12_set_alpn_offer(conn->hs_buf, alpn_protos, alpn_count);
            extern void opssl_tls12_set_tls13_capable(void *, bool);
            if (opssl_ctx_supports_version(conn->ctx, OPSSL_TLS_1_3))
                opssl_tls12_set_tls13_capable(conn->hs_buf, true);
        }
    }

    opssl_handshake_state_t prev_state;
    memcpy(&prev_state, conn->hs_buf, sizeof(prev_state));

    uint8_t *in_data = conn->hs_inbuf;
    size_t in_len = conn->hs_inlen;

    uint8_t out_data[16384];
    size_t consumed = 0, out_len = 0;

    int rc;
    if (conn->dir == OPSSL_SERVER) {
        rc = opssl_tls12_server_handshake(conn->hs_buf, in_data, in_len,
                                          &consumed, out_data, &out_len,
                                          sizeof(out_data));
    } else {
        rc = opssl_tls12_client_handshake(conn->hs_buf, in_data, in_len,
                                          &consumed, out_data, &out_len,
                                          sizeof(out_data));
    }

    /* Remove consumed data from reassembly buffer */
    if (consumed > 0 && consumed <= conn->hs_inlen) {
        memmove(conn->hs_inbuf, conn->hs_inbuf + consumed, conn->hs_inlen - consumed);
        conn->hs_inlen -= consumed;
    }

    opssl_handshake_state_t cur_state;
    memcpy(&cur_state, conn->hs_buf, sizeof(cur_state));

    if (out_len > 0) {
        /* For client: output from CLIENT_HELLO contains CKE+Finished.
         * Split: send CKE as handshake, then CCS, then Finished as handshake.
         * For server: output from FINISHED is just server Finished — send CCS first. */
        if (cur_state == OPSSL_HS_COMPLETE && prev_state == OPSSL_HS_FINISHED) {
            /* Server sending Finished: CCS first, then write encrypted Finished */
            uint8_t ccs_byte = 1;
            opssl_result_t wr = write_record(conn, TLS_RT_CHANGE_CIPHER_SPEC, &ccs_byte, 1);
            if (wr != OPSSL_OK) return wr;

            if (!conn->is_tls13 && !conn->write_cipher) {
                uint8_t ck[32], sk[32], ci[12], si[12];
                size_t ckl, skl, cil, sil;
                opssl_ciphersuite_t cip;
                if (opssl_tls12_extract_traffic_keys(conn->hs_buf,
                        ck, &ckl, sk, &skl, ci, &cil, si, &sil, &cip) == OPSSL_OK) {
                    setup_cipher_contexts(conn, ck, ckl, sk, skl,
                                         ci, cil, si, sil, cip, TLS_EPOCH_APPLICATION);
                }
            }
            conn->write_encrypted = true;

            wr = write_record(conn, TLS_RT_HANDSHAKE, out_data, out_len);
            if (wr != OPSSL_OK) return wr;
        } else if (cur_state == OPSSL_HS_FINISHED && prev_state == OPSSL_HS_CLIENT_HELLO &&
                   conn->dir == OPSSL_CLIENT) {
            /* Client sending CKE + Finished: split at Finished boundary.
             * Finished is last (4 + TLS12_VERIFY_DATA_LEN) bytes of output. */
            size_t fin_size = 4 + TLS12_VERIFY_DATA_LEN;  /* msg_type(1) + length(3) + verify_data(12) */

            /* Issue 9: Guard against underflow when out_len < fin_size */
            if (out_len < fin_size) {
                conn->last_error = OPSSL_ERR_PROTOCOL;
                return OPSSL_ERROR;
            }

            size_t cke_len = out_len - fin_size;
            opssl_result_t wr = write_record(conn, TLS_RT_HANDSHAKE, out_data, cke_len);
            if (wr != OPSSL_OK) return wr;
            uint8_t ccs_byte = 1;
            wr = write_record(conn, TLS_RT_CHANGE_CIPHER_SPEC, &ccs_byte, 1);
            if (wr != OPSSL_OK) return wr;

            /* TLS 1.2: enable write-side encryption before sending Finished.
             * Read-side stays unencrypted until server's CCS arrives. */
            {
                uint8_t ck[32], sk[32], ci[12], si[12];
                size_t ckl, skl, cil, sil;
                opssl_ciphersuite_t cip;
                int kr = opssl_tls12_extract_traffic_keys(conn->hs_buf,
                        ck, &ckl, sk, &skl, ci, &cil, si, &sil, &cip);
                if (kr == OPSSL_OK) {
                    setup_cipher_contexts(conn, ck, ckl, sk, skl,
                                         ci, cil, si, sil, cip, TLS_EPOCH_APPLICATION);
                    conn->read_encrypted = false;
                }
            }

            wr = write_record(conn, TLS_RT_HANDSHAKE, out_data + cke_len, fin_size);
            if (wr != OPSSL_OK) return wr;
        } else {
            opssl_result_t wr = write_record(conn, TLS_RT_HANDSHAKE, out_data, out_len);
            if (wr != OPSSL_OK) return wr;
        }
    }

    /* Server: after CKE processing (SERVER_HELLO→FINISHED), set up cipher contexts
     * so read_cipher is ready before CCS arrives from the client.
     * Don't enable encryption yet — CCS handler enables read, server CCS enables write. */
    if (conn->dir == OPSSL_SERVER && cur_state == OPSSL_HS_FINISHED &&
        prev_state == OPSSL_HS_SERVER_HELLO && !conn->read_cipher) {
        uint8_t ck[32], sk[32], ci[12], si[12];
        size_t ckl, skl, cil, sil;
        opssl_ciphersuite_t cip;
        if (opssl_tls12_extract_traffic_keys(conn->hs_buf,
                ck, &ckl, sk, &skl, ci, &cil, si, &sil, &cip) == OPSSL_OK) {
            setup_cipher_contexts(conn, ck, ckl, sk, skl,
                                 ci, cil, si, sil, cip, TLS_EPOCH_APPLICATION);
            conn->read_encrypted = false;
            conn->write_encrypted = false;
        }
    }

    /* Check the internal handshake state (first field of hs struct) */
    if (cur_state == OPSSL_HS_COMPLETE && conn->hs_state != OPSSL_HS_COMPLETE) {
        uint8_t client_key[32], server_key[32];
        uint8_t client_iv[12], server_iv[12];
        size_t client_key_len, server_key_len, client_iv_len, server_iv_len;
        opssl_ciphersuite_t cipher;

        if (opssl_tls12_extract_traffic_keys(conn->hs_buf, client_key, &client_key_len,
                                           server_key, &server_key_len,
                                           client_iv, &client_iv_len,
                                           server_iv, &server_iv_len, &cipher) == OPSSL_OK) {
            setup_cipher_contexts(conn, client_key, client_key_len,
                                 server_key, server_key_len,
                                 client_iv, client_iv_len,
                                 server_iv, server_iv_len, cipher, TLS_EPOCH_APPLICATION);
        }

        /* Copy parsed SNI from handshake state to connection */
        if (conn->dir == OPSSL_SERVER && conn->sni[0] == '\0') {
            const char *hs_sni = opssl_tls12_get_sni(conn->hs_buf);
            if (hs_sni) {
                size_t len = strlen(hs_sni);
                if (len >= sizeof(conn->sni)) len = sizeof(conn->sni) - 1;
                memcpy(conn->sni, hs_sni, len);
                conn->sni[len] = '\0';
            }
        }

        /* Copy negotiated group from handshake state to connection */
        extern opssl_named_group_t opssl_tls12_get_group(void *);
        conn->group = opssl_tls12_get_group(conn->hs_buf);

        /* Copy negotiated ALPN from handshake state to connection */
        const char *hs_alpn = opssl_tls12_get_alpn(conn->hs_buf);
        if (hs_alpn) {
            size_t len = strlen(hs_alpn);
            if (len >= sizeof(conn->alpn)) len = sizeof(conn->alpn) - 1;
            memcpy(conn->alpn, hs_alpn, len);
            conn->alpn[len] = '\0';
            conn->alpn_len = len;
        }

        /* Verify peer certificate if trust store is configured */
        size_t peer_der_len = 0;
        const uint8_t *peer_der = opssl_tls12_get_peer_cert(conn->hs_buf, &peer_der_len);
        if (peer_der && peer_der_len > 0) {
            conn->peer_cert = opssl_x509_from_der(peer_der, peer_der_len);

            opssl_x509_store_t *store = opssl_ctx_get_trust_store(conn->ctx);
            if (store && conn->peer_cert) {
                const uint8_t **intermediates = NULL;
                const size_t *intermediate_lens = NULL;
                size_t n_intermediates = opssl_tls12_get_peer_chain(conn->hs_buf,
                    &intermediates, &intermediate_lens);
                opssl_x509_chain_t *chain = opssl_x509_chain_from_ders(peer_der, peer_der_len,
                    intermediates, intermediate_lens, n_intermediates);
                if (chain) {
                    opssl_x509_verify_result_t vresult;
                    const char *hostname = (conn->dir == OPSSL_CLIENT && conn->sni[0]) ?
                        conn->sni : NULL;
                    if (!opssl_x509_verify(chain, store, hostname, &vresult)) {
                        opssl_x509_chain_free(chain);
                        opssl_tls12_free_peer_cert(conn->hs_buf);
                        conn->last_error = OPSSL_ERR_PACK(OPSSL_ERR_TLS, OPSSL_TLS_ERR_BAD_CERTIFICATE);
                        return OPSSL_ERROR;
                    }
                    opssl_x509_chain_free(chain);
                }
            }
            opssl_tls12_free_peer_cert(conn->hs_buf);
        } else if (opssl_ctx_get_verify_peer(conn->ctx)) {
            /* verify_peer is set but peer sent no certificate — reject */
            conn->last_error = OPSSL_ERR_PACK(OPSSL_ERR_TLS, OPSSL_TLS_ERR_BAD_CERTIFICATE);
            return OPSSL_ERROR;
        }

        conn->hs_state = OPSSL_HS_COMPLETE;
    }

    if (rc == OPSSL_ERROR && conn->last_error == OPSSL_ERR_NONE)
        conn->last_error = OPSSL_ERR_PROTOCOL;
    return (opssl_result_t)rc;
}

static void tls13_setup_handshake_cipher(opssl_conn_t *conn)
{
    extern int opssl_tls13_extract_hs_keys(void *hs,
                                           uint8_t *ck, size_t *ckl,
                                           uint8_t *sk, size_t *skl,
                                           uint8_t *ci, size_t *cil,
                                           uint8_t *si, size_t *sil,
                                           opssl_ciphersuite_t *cipher);

    uint8_t client_key[32], server_key[32];
    uint8_t client_iv[12], server_iv[12];
    size_t ckl, skl, cil, sil;
    opssl_ciphersuite_t cipher;

    if (opssl_tls13_extract_hs_keys(conn->hs_buf,
                                    client_key, &ckl, server_key, &skl,
                                    client_iv, &cil, server_iv, &sil,
                                    &cipher) != OPSSL_OK) {
        return;
    }

#ifdef OPSSL_DEBUG_SECRETS
    {
        extern void opssl_tls13_debug_dump_secrets(void *hs);
        opssl_tls13_debug_dump_secrets(conn->hs_buf);
    }
#endif

    setup_cipher_contexts(conn, client_key, ckl, server_key, skl,
                         client_iv, cil, server_iv, sil, cipher, TLS_EPOCH_HANDSHAKE);
}

static opssl_result_t handle_tls13_handshake(opssl_conn_t *conn)
{
    if (!conn->hs_initialized) {
        memset(conn->hs_buf, 0, sizeof(conn->hs_buf));
        conn->hs_initialized = true;

        size_t alpn_count = 0;
        const char **alpn_protos = opssl_ctx_get_alpn_protos(conn->ctx, &alpn_count);

        if (conn->dir == OPSSL_CLIENT) {
            if (conn->sni[0])
                opssl_tls13_set_sni(conn->hs_buf, conn->sni);
            if (alpn_protos && alpn_count > 0)
                opssl_tls13_set_alpn_offer(conn->hs_buf, alpn_protos, alpn_count);
            if (conn->has_ticket && conn->ticket_psk_len > 0)
                opssl_tls13_set_psk(conn->hs_buf, conn->ticket_psk,
                                    conn->ticket_psk_len, conn->session_ticket,
                                    conn->session_ticket_len);
            /* mTLS: make our cert available for CertificateRequest */
            extern void opssl_tls13_set_client_cert(void *, const opssl_pkey_t *,
                                                    const opssl_x509_chain_t *);
            opssl_pkey_t *ckey = opssl_ctx_get_private_key(conn->ctx);
            opssl_x509_chain_t *cchain = opssl_ctx_get_cert_chain(conn->ctx);
            if (ckey && cchain)
                opssl_tls13_set_client_cert(conn->hs_buf, ckey, cchain);
        } else {
            if (alpn_protos && alpn_count > 0)
                opssl_tls13_set_alpn_supported(conn->hs_buf, alpn_protos, alpn_count);
            opssl_pkey_t *pkey = opssl_ctx_get_private_key(conn->ctx);
            if (pkey)
                opssl_tls13_set_sign_key(conn->hs_buf, pkey);
            opssl_x509_chain_t *chain = opssl_ctx_get_cert_chain(conn->ctx);
            if (chain)
                opssl_tls13_set_cert_chain(conn->hs_buf, chain);
            if (conn->has_ticket && conn->ticket_psk_len > 0)
                opssl_tls13_set_psk(conn->hs_buf, conn->ticket_psk,
                                    conn->ticket_psk_len, conn->session_ticket,
                                    conn->session_ticket_len);
            bool request_client_cert = conn->request_client_cert_set
                ? conn->request_client_cert
                : opssl_ctx_get_request_client_cert(conn->ctx);
            if (opssl_ctx_get_verify_peer(conn->ctx) || request_client_cert)
                opssl_tls13_request_client_cert(conn->hs_buf, true);
        }
    }

    for (;;) {
        opssl_handshake_state_t prev_state;
    memcpy(&prev_state, conn->hs_buf, sizeof(prev_state));

        uint8_t *in_data = conn->hs_inbuf;
        size_t in_len = conn->hs_inlen;

        uint8_t out_data[16384];
        size_t consumed = 0, out_len = 0;

        int rc;
        if (conn->dir == OPSSL_SERVER) {
            rc = opssl_tls13_server_handshake(conn->hs_buf, in_data, in_len,
                                              &consumed, out_data, &out_len,
                                              sizeof(out_data));
        } else {
            rc = opssl_tls13_client_handshake(conn->hs_buf, in_data, in_len,
                                              &consumed, out_data, &out_len,
                                              sizeof(out_data));
        }

        /* Remove consumed data from reassembly buffer */
        if (consumed > 0 && consumed <= conn->hs_inlen) {
            memmove(conn->hs_inbuf, conn->hs_inbuf + consumed, conn->hs_inlen - consumed);
            conn->hs_inlen -= consumed;
        }

        opssl_handshake_state_t cur_state;
    memcpy(&cur_state, conn->hs_buf, sizeof(cur_state));

        bool server_just_sent_hello = (prev_state != cur_state &&
                                       conn->dir == OPSSL_SERVER &&
                                       prev_state == OPSSL_HS_IDLE &&
                                       cur_state > OPSSL_HS_IDLE);
        bool client_got_hello = (prev_state != cur_state &&
                                 conn->dir == OPSSL_CLIENT &&
                                 prev_state == OPSSL_HS_CLIENT_HELLO &&
                                 cur_state > OPSSL_HS_CLIENT_HELLO);

        /* Write output BEFORE enabling encryption (ServerHello is plaintext) */
        if (out_len > 0) {
            opssl_result_t wr = write_record(conn, TLS_RT_HANDSHAKE, out_data, out_len);
            if (wr != OPSSL_OK)
                return wr;
        }

        /* Middlebox compatibility: send fake CCS after ServerHello (server) or
         * after receiving ServerHello (client) — RFC 8446 Appendix D.4 */
        if (server_just_sent_hello || client_got_hello) {
            opssl_result_t ccs_rc = send_fake_ccs(conn);
            if (ccs_rc != OPSSL_OK) return ccs_rc;

            if (!conn->write_encrypted) {
                tls13_setup_handshake_cipher(conn);
            }
        }

        /* Check the internal handshake state (first field of hs struct) */
        opssl_handshake_state_t *hs_state = (opssl_handshake_state_t *)conn->hs_buf;
        if (*hs_state == OPSSL_HS_COMPLETE && conn->hs_state != OPSSL_HS_COMPLETE) {
            uint8_t client_key[32], server_key[32];
            uint8_t client_iv[12], server_iv[12];
            size_t client_key_len, server_key_len, client_iv_len, server_iv_len;
            opssl_ciphersuite_t cipher;

            if (opssl_tls13_extract_traffic_keys(conn->hs_buf, client_key, &client_key_len,
                                               server_key, &server_key_len,
                                               client_iv, &client_iv_len,
                                               server_iv, &server_iv_len, &cipher) == OPSSL_OK) {
                setup_cipher_contexts(conn, client_key, client_key_len,
                                     server_key, server_key_len,
                                     client_iv, client_iv_len,
                                     server_iv, server_iv_len, cipher, TLS_EPOCH_APPLICATION);

                size_t client_secret_len = 0, server_secret_len = 0, client_random_len = 0;
                const uint8_t *client_secret =
                    opssl_tls13_get_client_app_traffic_secret(conn->hs_buf, &client_secret_len);
                const uint8_t *server_secret =
                    opssl_tls13_get_server_app_traffic_secret(conn->hs_buf, &server_secret_len);
                const uint8_t *client_random =
                    opssl_tls13_get_client_random(conn->hs_buf, &client_random_len);

                if (client_secret && server_secret &&
                    client_secret_len == server_secret_len &&
                    client_secret_len <= sizeof(conn->client_traffic_secret)) {
                    memcpy(conn->client_traffic_secret, client_secret, client_secret_len);
                    memcpy(conn->server_traffic_secret, server_secret, server_secret_len);
                    conn->secret_len = client_secret_len;

                    if (client_random && client_random_len == 32) {
                        keylog_emit(conn, "CLIENT_TRAFFIC_SECRET_0",
                                    client_random, client_secret, client_secret_len);
                        keylog_emit(conn, "SERVER_TRAFFIC_SECRET_0",
                                    client_random, server_secret, server_secret_len);
                    }
                }
            }

            conn->group = opssl_tls13_get_negotiated_group(conn->hs_buf);

            if (conn->dir == OPSSL_SERVER) {
                const char *peer_sni = opssl_tls13_get_sni(conn->hs_buf);
                if (peer_sni && !conn->sni[0]) {
                    size_t sl = strlen(peer_sni);
                    if (sl < sizeof(conn->sni)) {
                        memcpy(conn->sni, peer_sni, sl);
                        conn->sni[sl] = '\0';
                    }
                }
            }

            /* Copy negotiated ALPN from handshake state */
            const char *hs_alpn = opssl_tls13_get_alpn(conn->hs_buf);
            if (hs_alpn) {
                size_t al = strlen(hs_alpn);
                if (al >= sizeof(conn->alpn)) al = sizeof(conn->alpn) - 1;
                memcpy(conn->alpn, hs_alpn, al);
                conn->alpn[al] = '\0';
                conn->alpn_len = al;
            }

            /* Verify peer certificate if trust store is configured */
            size_t peer_der_len = 0;
            const uint8_t *peer_der = opssl_tls13_get_peer_cert(conn->hs_buf, &peer_der_len);
            if (peer_der && peer_der_len > 0) {
                conn->peer_cert = opssl_x509_from_der(peer_der, peer_der_len);

                opssl_x509_store_t *store = opssl_ctx_get_trust_store(conn->ctx);
                if (store && conn->peer_cert) {
                    const uint8_t **intermediates = NULL;
                    const size_t *intermediate_lens = NULL;
                    size_t n_intermediates = opssl_tls13_get_peer_chain(conn->hs_buf,
                        &intermediates, &intermediate_lens);
                    opssl_x509_chain_t *chain = opssl_x509_chain_from_ders(peer_der, peer_der_len,
                        intermediates, intermediate_lens, n_intermediates);
                    if (chain) {
                        opssl_x509_verify_result_t vresult;
                        const char *hostname = (conn->dir == OPSSL_CLIENT && conn->sni[0]) ?
                            conn->sni : NULL;
                        if (!opssl_x509_verify(chain, store, hostname, &vresult)) {
                            opssl_x509_chain_free(chain);
                            opssl_tls13_free_peer_cert(conn->hs_buf);
                            conn->last_error = OPSSL_ERR_PACK(OPSSL_ERR_TLS, OPSSL_TLS_ERR_BAD_CERTIFICATE);
                            return OPSSL_ERROR;
                        }
                        opssl_x509_chain_free(chain);
                    }
                }
                opssl_tls13_free_peer_cert(conn->hs_buf);
            } else if (opssl_ctx_get_verify_peer(conn->ctx)) {
                /* verify_peer is set but peer sent no certificate — reject */
                conn->last_error = OPSSL_ERR_PACK(OPSSL_ERR_TLS, OPSSL_TLS_ERR_BAD_CERTIFICATE);
                return OPSSL_ERROR;
            }

            /* Copy resumption master secret for session tickets */
            size_t rms_len = 0;
            const uint8_t *rms = opssl_tls13_get_resumption_master_secret(conn->hs_buf, &rms_len);
            if (rms && rms_len > 0 && rms_len <= sizeof(conn->resumption_master_secret)) {
                memcpy(conn->resumption_master_secret, rms, rms_len);
                conn->rms_len = rms_len;
            }

            /* Server sends NewSessionTicket after handshake completes */
            if (conn->dir == OPSSL_SERVER && conn->rms_len > 0 &&
                (opssl_ctx_get_session_cache_mode(conn->ctx) & OPSSL_SESS_CACHE_TICKETS) != 0) {
                uint8_t nonce[8];
                opssl_random_bytes(nonce, sizeof(nonce));
                uint8_t ticket_data[32];
                opssl_random_bytes(ticket_data, sizeof(ticket_data));

                /* Build NewSessionTicket message */
                uint8_t nst_msg[128];
                size_t nst_len = 0;
                nst_msg[nst_len++] = TLS_HT_NEW_SESSION_TICKET;
                /* length placeholder (3 bytes) - fill after */
                size_t len_off = nst_len;
                nst_len += 3;
                /* ticket_lifetime = 7200s */
                nst_msg[nst_len++] = 0; nst_msg[nst_len++] = 0;
                nst_msg[nst_len++] = 0x1C; nst_msg[nst_len++] = 0x20;
                /* ticket_age_add (random) */
                memcpy(nst_msg + nst_len, nonce, 4);
                nst_len += 4;
                /* ticket_nonce */
                nst_msg[nst_len++] = 8;
                memcpy(nst_msg + nst_len, nonce, 8);
                nst_len += 8;
                /* ticket (opaque) */
                nst_msg[nst_len++] = 0; nst_msg[nst_len++] = 32;
                memcpy(nst_msg + nst_len, ticket_data, 32);
                nst_len += 32;
                /* extensions: empty (no early_data — server does not handle 0-RTT) */
                nst_msg[nst_len++] = 0;
                nst_msg[nst_len++] = 0;

                /* Fill in length */
                uint32_t body_len = (uint32_t)(nst_len - 4);
                nst_msg[len_off] = (body_len >> 16) & 0xFF;
                nst_msg[len_off + 1] = (body_len >> 8) & 0xFF;
                nst_msg[len_off + 2] = body_len & 0xFF;

                opssl_result_t nst_wr = write_record(conn, TLS_RT_HANDSHAKE, nst_msg, nst_len);
                if (nst_wr != OPSSL_OK)
                    return nst_wr;
            }

            conn->hs_state = OPSSL_HS_COMPLETE;
            return OPSSL_OK;
        }

        if (rc != OPSSL_OK || cur_state == prev_state) {
            if (rc == OPSSL_ERROR && conn->last_error == OPSSL_ERR_NONE)
                conn->last_error = OPSSL_ERR_PROTOCOL;
            return (opssl_result_t)rc;
        }
    }
}

/*
 * Setup cipher contexts after key derivation.
 * Initializes AEAD contexts for read/write with derived keys and IVs.
 */
static opssl_result_t setup_cipher_contexts(opssl_conn_t *conn,
                                           const uint8_t *client_key, size_t client_key_len,
                                           const uint8_t *server_key, size_t server_key_len,
                                           const uint8_t *client_iv, size_t client_iv_len,
                                           const uint8_t *server_iv, size_t server_iv_len,
                                           opssl_ciphersuite_t cipher,
                                           enum tls_epoch new_epoch)
{
    opssl_aead_algo_t aead_type;

    /* Map cipher suite to AEAD type */
    switch (cipher) {
        case OPSSL_TLS_AES_128_GCM_SHA256:
        case OPSSL_TLS_ECDHE_RSA_AES_128_GCM:
        case OPSSL_TLS_ECDHE_ECDSA_AES_128_GCM:
            aead_type = OPSSL_AEAD_AES_128_GCM;
            break;
        case OPSSL_TLS_AES_256_GCM_SHA384:
        case OPSSL_TLS_ECDHE_RSA_AES_256_GCM:
        case OPSSL_TLS_ECDHE_ECDSA_AES_256_GCM:
            aead_type = OPSSL_AEAD_AES_256_GCM;
            break;
        case OPSSL_TLS_CHACHA20_POLY1305_SHA256:
        case OPSSL_TLS_ECDHE_RSA_CHACHA20:
        case OPSSL_TLS_ECDHE_ECDSA_CHACHA20:
            aead_type = OPSSL_AEAD_CHACHA20_POLY1305;
            break;
        default:
            conn->last_error = OPSSL_ERR_NOT_SUPPORTED;
            return OPSSL_ERROR;
    }

    conn->cipher = cipher;

    /* Clean up existing cipher contexts */
    if (conn->read_cipher) {
        opssl_aead_ctx_free(conn->read_cipher);
        conn->read_cipher = NULL;
    }
    if (conn->write_cipher) {
        opssl_aead_ctx_free(conn->write_cipher);
        conn->write_cipher = NULL;
    }

    /* Set up read cipher context */
    conn->read_cipher = opssl_aead_new(aead_type);
    if (!conn->read_cipher) {
        conn->last_error = OPSSL_ERR_MEMORY;
        return OPSSL_ERROR;
    }

    /* Set up write cipher context */
    conn->write_cipher = opssl_aead_new(aead_type);
    if (!conn->write_cipher) {
        opssl_aead_ctx_free(conn->read_cipher);
        conn->read_cipher = NULL;
        conn->last_error = OPSSL_ERR_MEMORY;
        return OPSSL_ERROR;
    }

    /* Configure keys based on connection direction */
    const uint8_t *read_key, *write_key;
    const uint8_t *read_iv, *write_iv;
    size_t read_key_len, write_key_len, read_iv_len, write_iv_len;

    if (conn->dir == OPSSL_SERVER) {
        /* Server reads client keys, writes server keys */
        read_key = client_key; read_key_len = client_key_len;
        write_key = server_key; write_key_len = server_key_len;
        read_iv = client_iv; read_iv_len = client_iv_len;
        write_iv = server_iv; write_iv_len = server_iv_len;
    } else {
        /* Client reads server keys, writes client keys */
        read_key = server_key; read_key_len = server_key_len;
        write_key = client_key; write_key_len = client_key_len;
        read_iv = server_iv; read_iv_len = server_iv_len;
        write_iv = client_iv; write_iv_len = client_iv_len;
    }

    /* Set read key and IV */
    if (opssl_aead_set_key(conn->read_cipher, read_key, read_key_len) != 1) {
        conn->last_error = OPSSL_ERR_CRYPTO;
        goto error;
    }
    memcpy(conn->read_iv, read_iv, read_iv_len < sizeof(conn->read_iv) ? read_iv_len : sizeof(conn->read_iv));

    /* Set write key and IV */
    if (opssl_aead_set_key(conn->write_cipher, write_key, write_key_len) != 1) {
        conn->last_error = OPSSL_ERR_CRYPTO;
        goto error;
    }
    memcpy(conn->write_iv, write_iv, write_iv_len < sizeof(conn->write_iv) ? write_iv_len : sizeof(conn->write_iv));

    /* Copy keys to connection for kTLS export */
    conn->read_key_len = read_key_len < sizeof(conn->read_key) ? read_key_len : sizeof(conn->read_key);
    memcpy(conn->read_key, read_key, conn->read_key_len);

    conn->write_key_len = write_key_len < sizeof(conn->write_key) ? write_key_len : sizeof(conn->write_key);
    memcpy(conn->write_key, write_key, conn->write_key_len);

    /* Enable encryption */
    conn->read_encrypted = true;
    conn->write_encrypted = true;

    /* Reset sequence numbers only on epoch transitions */
    enum tls_epoch old_read_epoch = conn->read_epoch;
    enum tls_epoch old_write_epoch = conn->write_epoch;

    conn->read_epoch = new_epoch;
    conn->write_epoch = new_epoch;

    if (old_read_epoch != new_epoch) {
        conn->read_seq = 0;
    }
    if (old_write_epoch != new_epoch) {
        conn->write_seq = 0;
    }

    return OPSSL_OK;

error:
    if (conn->read_cipher) {
        opssl_aead_ctx_free(conn->read_cipher);
        conn->read_cipher = NULL;
    }
    if (conn->write_cipher) {
        opssl_aead_ctx_free(conn->write_cipher);
        conn->write_cipher = NULL;
    }
    return OPSSL_ERROR;
}

/* ─── Session Resumption API ─────────────────────────────────────────── */

opssl_session_t *
opssl_conn_get_session(opssl_conn_t *conn)
{
    if (!conn || !conn->has_ticket)
        return NULL;

    opssl_session_t *sess = op_malloc(sizeof(*sess));
    if (!sess)
        return NULL;

    sess->version = conn->version;
    sess->cipher = conn->cipher;
    memcpy(sess->psk, conn->ticket_psk, conn->ticket_psk_len);
    sess->psk_len = conn->ticket_psk_len;
    memcpy(sess->ticket, conn->session_ticket, conn->session_ticket_len);
    sess->ticket_len = conn->session_ticket_len;
    sess->lifetime = conn->ticket_lifetime;
    sess->age_add = conn->ticket_age_add;

    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    sess->created_at = (uint64_t)ts.tv_sec;

    return sess;
}

int
opssl_conn_set_session(opssl_conn_t *conn, const opssl_session_t *sess)
{
    if (!conn || !sess || sess->ticket_len == 0)
        return 0;
    if (sess->psk_len > sizeof(conn->ticket_psk))
        return 0;
    if (sess->ticket_len > sizeof(conn->session_ticket))
        return 0;

    memcpy(conn->ticket_psk, sess->psk, sess->psk_len);
    conn->ticket_psk_len = sess->psk_len;
    memcpy(conn->session_ticket, sess->ticket, sess->ticket_len);
    conn->session_ticket_len = sess->ticket_len;
    conn->ticket_lifetime = sess->lifetime;
    conn->ticket_age_add = sess->age_add;
    conn->has_ticket = true;

    return 1;
}

opssl_session_t *
opssl_session_from_bytes(const uint8_t *data, size_t len)
{
    if (!data || len < 12)
        return NULL;

    opssl_session_t *sess = op_malloc(sizeof(*sess));
    if (!sess)
        return NULL;

    const uint8_t *p = data;
    sess->version = (opssl_tls_version_t)((p[0] << 8) | p[1]); p += 2;
    sess->cipher  = (opssl_ciphersuite_t)((p[0] << 8) | p[1]); p += 2;
    sess->psk_len = (size_t)((p[0] << 8) | p[1]); p += 2;
    if (sess->psk_len > 48 || (size_t)(p - data) + sess->psk_len > len) {
        op_free(sess);
        return NULL;
    }
    memcpy(sess->psk, p, sess->psk_len); p += sess->psk_len;

    if ((size_t)(p - data) + 2 > len) { op_free(sess); return NULL; }
    sess->ticket_len = (size_t)((p[0] << 8) | p[1]); p += 2;
    if (sess->ticket_len > 1024 || (size_t)(p - data) + sess->ticket_len > len) {
        op_free(sess);
        return NULL;
    }
    memcpy(sess->ticket, p, sess->ticket_len); p += sess->ticket_len;

    if ((size_t)(p - data) + 12 > len) { op_free(sess); return NULL; }
    sess->lifetime = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3]; p += 4;
    sess->age_add  = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3]; p += 4;
    sess->created_at = 0;
    for (int i = 0; i < 8; i++)
        sess->created_at = (sess->created_at << 8) | p[i];

    return sess;
}

int
opssl_session_to_bytes(const opssl_session_t *sess, uint8_t *out, size_t *out_len)
{
    if (!sess || !out_len)
        return 0;

    size_t need = 2 + 2 + 2 + sess->psk_len + 2 + sess->ticket_len + 4 + 4 + 8;
    if (!out) {
        *out_len = need;
        return 1;
    }
    if (*out_len < need)
        return 0;

    uint8_t *p = out;
    *p++ = (uint8_t)(sess->version >> 8);
    *p++ = (uint8_t)(sess->version);
    *p++ = (uint8_t)(sess->cipher >> 8);
    *p++ = (uint8_t)(sess->cipher);
    *p++ = (uint8_t)(sess->psk_len >> 8);
    *p++ = (uint8_t)(sess->psk_len);
    memcpy(p, sess->psk, sess->psk_len); p += sess->psk_len;
    *p++ = (uint8_t)(sess->ticket_len >> 8);
    *p++ = (uint8_t)(sess->ticket_len);
    memcpy(p, sess->ticket, sess->ticket_len); p += sess->ticket_len;
    *p++ = (uint8_t)(sess->lifetime >> 24);
    *p++ = (uint8_t)(sess->lifetime >> 16);
    *p++ = (uint8_t)(sess->lifetime >> 8);
    *p++ = (uint8_t)(sess->lifetime);
    *p++ = (uint8_t)(sess->age_add >> 24);
    *p++ = (uint8_t)(sess->age_add >> 16);
    *p++ = (uint8_t)(sess->age_add >> 8);
    *p++ = (uint8_t)(sess->age_add);
    for (int i = 7; i >= 0; i--)
        *p++ = (uint8_t)(sess->created_at >> (i * 8));

    *out_len = need;
    return 1;
}

void
opssl_session_free(opssl_session_t *sess)
{
    if (!sess)
        return;
    opssl_memzero(sess, sizeof(*sess));
    op_free(sess);
}

uint32_t
opssl_session_get_lifetime(const opssl_session_t *sess)
{
    return sess ? sess->lifetime : 0;
}

bool
opssl_session_is_resumable(const opssl_session_t *sess)
{
    if (!sess || sess->ticket_len == 0 || sess->psk_len == 0)
        return false;

    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    uint64_t now = (uint64_t)ts.tv_sec;

    if (sess->created_at > 0 && now > sess->created_at + sess->lifetime)
        return false;

    return true;
}

/* ─── OCSP Response Verification (RFC 6960) ──────────────────────────── */

int
opssl_conn_verify_ocsp_response(opssl_conn_t *conn)
{
    if (!conn)
        return 0;

    if (!conn->is_tls13 || !conn->hs_initialized)
        return 0;

    extern int opssl_tls13_get_ocsp_response(void *hs, const uint8_t **resp, size_t *len);
    const uint8_t *resp = NULL;
    size_t resp_len = 0;

    if (opssl_tls13_get_ocsp_response(conn->hs_buf, &resp, &resp_len) != 1)
        return 0;

    if (!resp || resp_len < 6)
        return 0;

    opssl_x509_t *peer = opssl_conn_get_peer_cert(conn);
    if (!peer)
        return 0;

    extern opssl_ocsp_status_t opssl_ocsp_verify_response(const uint8_t *, size_t,
        const opssl_x509_t *, const opssl_x509_store_t *);

    opssl_ocsp_status_t status = opssl_ocsp_verify_response(resp, resp_len, peer, NULL);
    return (status == OPSSL_OCSP_GOOD) ? 1 : 0;
}

const uint8_t *
opssl_conn_get_ocsp_response(opssl_conn_t *conn, size_t *len)
{
    if (!conn || !len)
        return NULL;

    if (!conn->is_tls13 || !conn->hs_initialized) {
        *len = 0;
        return NULL;
    }

    extern int opssl_tls13_get_ocsp_response(void *hs, const uint8_t **resp, size_t *rlen);
    const uint8_t *resp = NULL;
    size_t resp_len = 0;

    if (opssl_tls13_get_ocsp_response(conn->hs_buf, &resp, &resp_len) != 1) {
        *len = 0;
        return NULL;
    }

    *len = resp_len;
    return resp;
}

/* ─── Certificate Transparency SCT Verification (RFC 6962) ──────────── */

int
opssl_conn_verify_sct_list(opssl_conn_t *conn)
{
    if (!conn)
        return 0;

    if (!conn->is_tls13 || !conn->hs_initialized)
        return 0;

    extern int opssl_tls13_get_sct_list(void *hs, const uint8_t **sct, size_t *len);
    const uint8_t *sct = NULL;
    size_t sct_len = 0;

    if (opssl_tls13_get_sct_list(conn->hs_buf, &sct, &sct_len) != 1)
        return 0;

    if (!sct || sct_len < 4)
        return 0;

    /*
     * SignedCertificateTimestampList (RFC 6962 §3.3):
     * - 2 bytes: total list length
     * - For each SCT:
     *   - 2 bytes: SCT length
     *   - 1 byte: version (must be 0 = v1)
     *   - 32 bytes: log_id (SHA-256 hash of log's public key)
     *   - 8 bytes: timestamp (ms since epoch)
     *   - 2 bytes: extensions length + extensions
     *   - digitally-signed struct (hash algo, sig algo, sig)
     */

    /* Parse total list length */
    uint16_t list_len = (uint16_t)((sct[0] << 8) | sct[1]);
    if ((size_t)list_len + 2 > sct_len)
        return 0;

    size_t pos = 2;
    int sct_count = 0;

    while (pos + 2 < sct_len) {
        uint16_t entry_len = (uint16_t)((sct[pos] << 8) | sct[pos + 1]);
        pos += 2;

        if (pos + entry_len > sct_len)
            return 0;

        /* Validate version byte */
        if (entry_len < 1 || sct[pos] != 0)
            return 0;  /* only v1 supported */

        /* Minimum SCT is: version(1) + log_id(32) + timestamp(8) + extensions_len(2) + sig_min(4) = 47 */
        if (entry_len < 47)
            return 0;

        sct_count++;
        pos += entry_len;
    }

    /* RFC 6962 requires at least 1 SCT for CT compliance;
     * Chrome requires 2-5 depending on cert lifetime. We require >= 1. */
    return sct_count >= 1 ? 1 : 0;
}

const uint8_t *
opssl_conn_get_sct_list(opssl_conn_t *conn, size_t *len)
{
    if (!conn || !len)
        return NULL;

    if (!conn->is_tls13 || !conn->hs_initialized) {
        *len = 0;
        return NULL;
    }

    extern int opssl_tls13_get_sct_list(void *hs, const uint8_t **sct, size_t *slen);
    const uint8_t *sct = NULL;
    size_t sct_len = 0;

    if (opssl_tls13_get_sct_list(conn->hs_buf, &sct, &sct_len) != 1) {
        *len = 0;
        return NULL;
    }

    *len = sct_len;
    return sct;
}

/* ─── Session migration export/import ─────────────────────────────────
 *
 * Serializes a completed TLS connection's record-layer state so a new
 * process can reconstruct the opssl_conn_t and continue reading/writing
 * encrypted application data on the same TCP socket.
 *
 * Format (all little-endian):
 *   4  magic  "OPX2"
 *   4  total_len (including header)
 *   2  version   (opssl_tls_version_t)
 *   2  cipher    (opssl_ciphersuite_t)
 *   2  group     (opssl_named_group_t)
 *   1  dir       (opssl_direction_t)
 *   1  is_tls13
 *   1  read_encrypted
 *   1  write_encrypted
 *   8  read_seq
 *   8  write_seq
 *  12  read_iv
 *  12  write_iv
 *   1  read_key_len
 *   1  write_key_len
 *  32  read_key
 *  32  write_key
 *   2  app_len   (pending decrypted data)
 *   2  app_off
 *   N  app_data  (app_len bytes, max 16384)
 * OPX3 additions (partial TLS record buffers):
 *   2  read_rec_len  (buffered encrypted bytes, partial TLS record)
 *   N  read_rec_data (read_rec_len bytes, max 18432)
 *   2  write_rec_len (buffered encrypted bytes, partial TLS write)
 *   N  write_rec_data (write_rec_len bytes, max 18432)
 */

#define OPX_MAGIC_V2  0x3258504fu  /* "OPX2" little-endian */
#define OPX_MAGIC     0x3358504fu  /* "OPX3" little-endian */
#define OPX_HDR_FIXED  (4+4+2+2+2+1+1+1+1+8+8+12+12+1+1+32+32+2+2)

int
opssl_conn_export(opssl_conn_t *conn, uint8_t *buf, size_t buflen)
{
    if (!conn || !buf)
        return -1;
    if (conn->hs_state != OPSSL_HS_COMPLETE)
        return -1;

    size_t app_payload = conn->app_len - conn->app_off;
    size_t write_pending = (conn->write_len > conn->write_off)
                         ? conn->write_len - conn->write_off : 0;
    size_t total = OPX_HDR_FIXED + app_payload
                 + 2 + conn->read_len
                 + 2 + write_pending;
    if (buflen < total)
        return -1;

    uint8_t *p = buf;

    /* magic */
    uint32_t magic = OPX_MAGIC;
    memcpy(p, &magic, 4); p += 4;

    /* total_len */
    uint32_t tlen = (uint32_t)total;
    memcpy(p, &tlen, 4); p += 4;

    /* version, cipher, group (16-bit each), dir, flags */
    { uint16_t v = (uint16_t)conn->version;  memcpy(p, &v, 2); p += 2; }
    { uint16_t c = (uint16_t)conn->cipher;   memcpy(p, &c, 2); p += 2; }
    { uint16_t g = (uint16_t)conn->group;    memcpy(p, &g, 2); p += 2; }
    *p++ = (uint8_t)conn->dir;
    *p++ = conn->is_tls13 ? 1 : 0;
    *p++ = conn->read_encrypted ? 1 : 0;
    *p++ = conn->write_encrypted ? 1 : 0;

    /* sequence numbers */
    memcpy(p, &conn->read_seq, 8); p += 8;
    memcpy(p, &conn->write_seq, 8); p += 8;

    /* IVs */
    memcpy(p, conn->read_iv, 12); p += 12;
    memcpy(p, conn->write_iv, 12); p += 12;

    /* key lengths + keys */
    *p++ = (uint8_t)conn->read_key_len;
    *p++ = (uint8_t)conn->write_key_len;
    memcpy(p, conn->read_key, 32); p += 32;
    memcpy(p, conn->write_key, 32); p += 32;

    /* pending app data */
    uint16_t alen = (uint16_t)app_payload;
    uint16_t aoff = 0;
    memcpy(p, &alen, 2); p += 2;
    memcpy(p, &aoff, 2); p += 2;
    if (app_payload > 0) {
        memcpy(p, conn->app_buf + conn->app_off, app_payload);
        p += app_payload;
    }

    /* OPX3: partial TLS record buffers */
    { uint16_t rlen = (uint16_t)conn->read_len;
      memcpy(p, &rlen, 2); p += 2; }
    if (conn->read_len > 0) {
        memcpy(p, conn->read_buf, conn->read_len);
        p += conn->read_len;
    }

    { uint16_t wlen = (uint16_t)write_pending;
      memcpy(p, &wlen, 2); p += 2; }
    if (write_pending > 0) {
        memcpy(p, conn->write_buf + conn->write_off, write_pending);
        p += write_pending;
    }

    return (int)total;
}

int
opssl_conn_import(opssl_conn_t *conn, const uint8_t *buf, size_t len)
{
    if (!conn || !buf || len < OPX_HDR_FIXED)
        return -1;

    const uint8_t *p = buf;

    /* magic */
    uint32_t magic;
    memcpy(&magic, p, 4); p += 4;
    if (magic != OPX_MAGIC && magic != OPX_MAGIC_V2)
        return -1;
    bool has_rec_bufs = (magic == OPX_MAGIC);

    /* total_len */
    uint32_t tlen;
    memcpy(&tlen, p, 4); p += 4;
    if ((size_t)tlen > len)
        return -1;

    /* version, cipher, group (16-bit each), dir, flags */
    { uint16_t v; memcpy(&v, p, 2); conn->version = (opssl_tls_version_t)v; p += 2; }
    { uint16_t c; memcpy(&c, p, 2); conn->cipher  = (opssl_ciphersuite_t)c; p += 2; }
    { uint16_t g; memcpy(&g, p, 2); conn->group   = (opssl_named_group_t)g; p += 2; }
    conn->dir             = (opssl_direction_t)*p++;
    conn->is_tls13        = (*p++ != 0);
    conn->read_encrypted  = (*p++ != 0);
    conn->write_encrypted = (*p++ != 0);

    /* sequence numbers */
    memcpy(&conn->read_seq, p, 8); p += 8;
    memcpy(&conn->write_seq, p, 8); p += 8;

    /* IVs */
    memcpy(conn->read_iv, p, 12); p += 12;
    memcpy(conn->write_iv, p, 12); p += 12;

    /* key lengths + keys */
    conn->read_key_len  = *p++;
    conn->write_key_len = *p++;
    memcpy(conn->read_key, p, 32); p += 32;
    memcpy(conn->write_key, p, 32); p += 32;

    /* pending app data */
    uint16_t alen, aoff;
    memcpy(&alen, p, 2); p += 2;
    memcpy(&aoff, p, 2); p += 2;
    if (alen > sizeof(conn->app_buf))
        return -1;
    if (alen > 0)
        memcpy(conn->app_buf, p, alen);
    conn->app_len = alen;
    conn->app_off = 0;

    /* OPX3: restore partial TLS record buffers */
    if (has_rec_bufs && p + 4 <= buf + len) {
        uint16_t rlen;
        memcpy(&rlen, p, 2); p += 2;
        if (rlen > sizeof(conn->read_buf) || p + rlen > buf + len)
            return -1;
        if (rlen > 0)
            memcpy(conn->read_buf, p, rlen);
        conn->read_len = rlen;
        p += rlen;

        uint16_t wlen;
        memcpy(&wlen, p, 2); p += 2;
        if (wlen > sizeof(conn->write_buf) || p + wlen > buf + len)
            return -1;
        if (wlen > 0)
            memcpy(conn->write_buf, p, wlen);
        conn->write_len = wlen;
        conn->write_off = 0;
        p += wlen;
    }

    /* Reconstruct AEAD cipher contexts from the imported keys */
    opssl_aead_algo_t algo;
    switch (conn->cipher) {
    case OPSSL_TLS_AES_128_GCM_SHA256:
    case OPSSL_TLS_ECDHE_RSA_AES_128_GCM:
    case OPSSL_TLS_ECDHE_ECDSA_AES_128_GCM:
        algo = OPSSL_AEAD_AES_128_GCM;
        break;
    case OPSSL_TLS_AES_256_GCM_SHA384:
    case OPSSL_TLS_ECDHE_RSA_AES_256_GCM:
    case OPSSL_TLS_ECDHE_ECDSA_AES_256_GCM:
        algo = OPSSL_AEAD_AES_256_GCM;
        break;
    case OPSSL_TLS_CHACHA20_POLY1305_SHA256:
    case OPSSL_TLS_ECDHE_RSA_CHACHA20:
    case OPSSL_TLS_ECDHE_ECDSA_CHACHA20:
        algo = OPSSL_AEAD_CHACHA20_POLY1305;
        break;
    default:
        return -1;
    }

    if (conn->read_cipher) opssl_aead_free(conn->read_cipher);
    if (conn->write_cipher) opssl_aead_free(conn->write_cipher);

    conn->read_cipher = opssl_aead_new(algo);
    conn->write_cipher = opssl_aead_new(algo);
    if (!conn->read_cipher || !conn->write_cipher)
        return -1;

    if (!opssl_aead_set_key(conn->read_cipher, conn->read_key, conn->read_key_len) ||
        !opssl_aead_set_key(conn->write_cipher, conn->write_key, conn->write_key_len))
        return -1;

    conn->hs_state = OPSSL_HS_COMPLETE;
    conn->hs_initialized = true;
    if (!has_rec_bufs) {
        conn->read_len = 0;
        conn->write_len = 0;
        conn->write_off = 0;
    }

    return 0;
}

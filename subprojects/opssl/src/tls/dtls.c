/*
 * dtls.c — DTLS 1.2 / 1.3 datagram transport layer security.
 *
 * Implements TLS over unreliable datagrams (RFC 6347, RFC 9147).
 * Handles retransmission, reordering, fragmentation, and anti-replay.
 *
 * Key exchange and key derivation reuse the TLS 1.3 state machine from
 * tls13.c via the same opaque hs_buf pattern used by opssl_conn_t in
 * handshake.c.  The DTLS record and handshake framing (epoch, seq,
 * msg_seq, fragment_offset, fragment_length) is handled here; the
 * crypto-level handshake body bytes are identical to TLS 1.3.
 *
 * Copyright (C) 2026 ophion development team
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <opssl/dtls.h>
#include <opssl/cert.h>
#include <opssl/crypto.h>
#include <opssl/err.h>
#include <opssl/platform.h>
#include <op_memory.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <time.h>

#define DTLS_RECORD_HEADER_LEN    13
#define DTLS_HS_HEADER_LEN        12
#define DTLS_TLS_HS_HEADER_LEN     4
#define DTLS_MAX_RECORD_LEN     16384
#define DTLS_DEFAULT_MTU         1500
#define DTLS_OVERHEAD            (DTLS_RECORD_HEADER_LEN + 28)
#define DTLS_MAX_RETRANSMIT         6
#define DTLS_INITIAL_TIMEOUT_MS  1000
#define DTLS_MAX_TIMEOUT_MS     60000
#define DTLS_MAX_HS_MSG_LEN     65536
#define DTLS_FLIGHT_BUF_MAX     (128 * 1024)

#define DTLS_REPLAY_WINDOW_WORDS  4
#define DTLS_REPLAY_WINDOW_BITS   (DTLS_REPLAY_WINDOW_WORDS * 64)

#define DTLS_RT_CHANGE_CIPHER_SPEC  20
#define DTLS_RT_ALERT               21
#define DTLS_RT_HANDSHAKE           22
#define DTLS_RT_APPLICATION_DATA    23

#define DTLS_HT_HELLO_VERIFY_REQUEST   3
#define DTLS_HT_CLIENT_HELLO           1
#define DTLS_HT_SERVER_HELLO           2

typedef enum {
    DTLS_FLIGHT_IDLE = 0,
    DTLS_FLIGHT_SENDING,
    DTLS_FLIGHT_WAITING,
    DTLS_FLIGHT_COMPLETE,
    DTLS_FLIGHT_ERROR,
} dtls_flight_state_t;

typedef struct dtls_reassembly {
    uint8_t  type;
    uint16_t msg_seq;
    uint32_t total_length;
    uint8_t *body;
    uint8_t *coverage;
    uint32_t bytes_received;
    struct dtls_reassembly *next;
} dtls_reassembly_t;

typedef struct {
    uint64_t max_seq;
    uint64_t window[DTLS_REPLAY_WINDOW_WORDS];
} dtls_replay_window_t;

extern int opssl_tls13_server_handshake(void *hs, uint8_t *buf, size_t buf_len,
                                        size_t *consumed, uint8_t *out, size_t *out_len,
                                        size_t out_cap);
extern int opssl_tls13_client_handshake(void *hs, uint8_t *buf, size_t buf_len,
                                        size_t *consumed, uint8_t *out, size_t *out_len,
                                        size_t out_cap);
extern int opssl_tls13_extract_traffic_keys(void *hs_opaque,
                                            uint8_t *client_key, size_t *client_key_len,
                                            uint8_t *server_key, size_t *server_key_len,
                                            uint8_t *client_iv,  size_t *client_iv_len,
                                            uint8_t *server_iv,  size_t *server_iv_len,
                                            opssl_ciphersuite_t *cipher);
extern int opssl_tls13_extract_hs_keys(void *hs_opaque,
                                       uint8_t *client_key, size_t *client_key_len,
                                       uint8_t *server_key, size_t *server_key_len,
                                       uint8_t *client_iv,  size_t *client_iv_len,
                                       uint8_t *server_iv,  size_t *server_iv_len,
                                       opssl_ciphersuite_t *cipher);
extern void opssl_tls13_set_sign_key(void *hs_opaque, const opssl_pkey_t *key);
extern void opssl_tls13_set_cert_chain(void *hs_opaque, const opssl_x509_chain_t *chain);
extern void opssl_tls13_set_sni(void *hs_opaque, const char *hostname);

extern opssl_pkey_t       *opssl_ctx_get_private_key(opssl_ctx_t *ctx);
extern opssl_x509_chain_t *opssl_ctx_get_cert_chain(opssl_ctx_t *ctx);
extern const uint8_t      *opssl_ctx_get_dtls_cookie_secret(const opssl_ctx_t *ctx);

struct opssl_dtls_conn {
    opssl_ctx_t         *ctx;
    int                  fd;
    opssl_direction_t    dir;
    opssl_dtls_version_t version;

    opssl_handshake_state_t hs_state;
    opssl_ciphersuite_t     cipher;
    opssl_named_group_t     group;
    uint16_t                msg_seq_send;
    uint16_t                msg_seq_recv;
    uint16_t                epoch_read;
    uint16_t                epoch_write;

    opssl_aead_ctx_t *read_cipher;
    opssl_aead_ctx_t *write_cipher;
    uint8_t           read_iv[12];
    uint8_t           write_iv[12];
    uint64_t          read_seq;
    uint64_t          write_seq;
    bool              read_encrypted;
    bool              write_encrypted;

    size_t mtu;
    size_t pmtu;

    uint8_t            *flight_buf;
    size_t              flight_len;
    size_t              flight_cap;
    /* Per-record offsets so retransmit re-emits one datagram per record
     * rather than coalescing the whole flight into a single oversized UDP
     * packet (which the kernel rejects with EMSGSIZE). */
    size_t              flight_records[64];
    size_t              flight_record_count;
    dtls_flight_state_t flight_state;
    int                 retransmit_count;
    uint64_t            retransmit_deadline_ms;
    uint32_t            current_timeout_ms;

    dtls_reassembly_t   *reassembly_queue;
    dtls_replay_window_t replay_window;

    uint8_t cookie_hmac_key[32];
    uint8_t cookie[32];
    size_t  cookie_len;
    bool    cookie_verified;

    uint8_t client_random[32];
    bool    client_random_set;

    char   sni[256];
    char   alpn[32];
    size_t alpn_len;

    uint8_t read_buf[18432];
    size_t  read_len;

    opssl_err_t last_error;

    _Alignas(16) uint8_t hs_buf[4096];
    bool hs_initialized;

    bool shutdown_sent;
    bool shutdown_received;
};

/* ─── Utility ──────────────────────────────────────────────────────── */

static uint64_t
now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

/* ─── Anti-replay — 256-bit sliding window ─────────────────────────── */

static int
dtls_replay_check(dtls_replay_window_t *w, uint64_t seq)
{
    /* Reject seq numbers that would imply 48-bit wraparound. RFC 6347
     * mandates rekey or close before exhausting the seq space. */
    if (seq >> 48)
        return 0;

    if (seq > w->max_seq) {
        uint64_t shift = seq - w->max_seq;

        if (shift >= DTLS_REPLAY_WINDOW_BITS) {
            for (int i = 0; i < DTLS_REPLAY_WINDOW_WORDS; i++)
                w->window[i] = 0;
        } else {
            uint64_t word_shift = shift / 64;
            uint64_t bit_shift  = shift % 64;

            if (bit_shift == 0) {
                for (int i = DTLS_REPLAY_WINDOW_WORDS - 1; i >= 0; i--) {
                    int src = i - (int)word_shift;
                    w->window[i] = (src >= 0) ? w->window[src] : 0;
                }
            } else {
                for (int i = DTLS_REPLAY_WINDOW_WORDS - 1; i >= 0; i--) {
                    int src = i - (int)word_shift;
                    uint64_t hi = (src >= 0)     ? w->window[src]     : 0;
                    uint64_t lo = (src - 1 >= 0) ? w->window[src - 1] : 0;
                    w->window[i] = (hi << bit_shift) | (lo >> (64 - bit_shift));
                }
            }
        }

        w->window[0] |= (uint64_t)1;
        w->max_seq = seq;
        return 1;
    }

    uint64_t diff = w->max_seq - seq;
    if (diff >= DTLS_REPLAY_WINDOW_BITS)
        return 0;

    uint64_t word = diff / 64;
    uint64_t bit  = diff % 64;
    uint64_t mask = (uint64_t)1 << bit;

    if (w->window[word] & mask)
        return 0;

    w->window[word] |= mask;
    return 1;
}

/* ─── Flight Buffer ────────────────────────────────────────────────── */

static int
dtls_flight_append(opssl_dtls_conn_t *conn, const uint8_t *data, size_t len)
{
    if (len == 0)
        return 0;

    size_t new_len = conn->flight_len + len;
    if (new_len > DTLS_FLIGHT_BUF_MAX)
        return -1;

    if (new_len > conn->flight_cap) {
        size_t new_cap = conn->flight_cap == 0 ? 4096 : conn->flight_cap * 2;
        while (new_cap < new_len)
            new_cap *= 2;
        if (new_cap > DTLS_FLIGHT_BUF_MAX)
            new_cap = DTLS_FLIGHT_BUF_MAX;

        uint8_t *nbuf = op_malloc(new_cap);
        if (!nbuf)
            return -1;
        if (conn->flight_buf && conn->flight_len)
            memcpy(nbuf, conn->flight_buf, conn->flight_len);
        if (conn->flight_buf)
            op_free(conn->flight_buf);
        conn->flight_buf = nbuf;
        conn->flight_cap = new_cap;
    }

    memcpy(conn->flight_buf + conn->flight_len, data, len);
    if (conn->flight_record_count <
        sizeof(conn->flight_records) / sizeof(conn->flight_records[0])) {
        conn->flight_records[conn->flight_record_count++] = conn->flight_len;
    }
    conn->flight_len = new_len;
    return 0;
}

static void
dtls_flight_clear(opssl_dtls_conn_t *conn)
{
    conn->flight_len = 0;
    conn->flight_record_count = 0;
}

/* ─── Record Layer ─────────────────────────────────────────────────── */

static ssize_t
dtls_send_record(opssl_dtls_conn_t *conn, uint8_t type,
                 const uint8_t *data, size_t len)
{
    uint8_t hdr[DTLS_RECORD_HEADER_LEN];
    hdr[0] = type;
    hdr[1] = 0xFE;
    hdr[2] = 0xFD;
    hdr[3] = (uint8_t)(conn->epoch_write >> 8);
    hdr[4] = (uint8_t)(conn->epoch_write);
    hdr[5] = (uint8_t)(conn->write_seq >> 40);
    hdr[6] = (uint8_t)(conn->write_seq >> 32);
    hdr[7] = (uint8_t)(conn->write_seq >> 24);
    hdr[8] = (uint8_t)(conn->write_seq >> 16);
    hdr[9] = (uint8_t)(conn->write_seq >> 8);
    hdr[10] = (uint8_t)(conn->write_seq);

    if (len > DTLS_MAX_RECORD_LEN)
        return -1;
    size_t record_len = len;
    if (conn->write_encrypted) {
        if (record_len > DTLS_MAX_RECORD_LEN - 16)
            return -1;
        record_len += 16;
    }
    if (record_len > 0xFFFF)
        return -1;

    hdr[11] = (uint8_t)(record_len >> 8);
    hdr[12] = (uint8_t)(record_len);

    uint8_t dgram[18432];
    if (DTLS_RECORD_HEADER_LEN + record_len > sizeof(dgram))
        return -1;

    memcpy(dgram, hdr, DTLS_RECORD_HEADER_LEN);

    if (conn->write_encrypted && conn->write_cipher) {
        uint8_t nonce[12];
        memcpy(nonce, conn->write_iv, 12);
        for (int i = 0; i < 8; i++)
            nonce[4 + i] ^= (uint8_t)(conn->write_seq >> (56 - 8 * i));

        uint8_t aad[DTLS_RECORD_HEADER_LEN];
        memcpy(aad, hdr, DTLS_RECORD_HEADER_LEN);
        aad[11] = (uint8_t)(len >> 8);
        aad[12] = (uint8_t)(len);

        size_t ct_len = 0;
        if (opssl_aead_seal(conn->write_cipher,
                            dgram + DTLS_RECORD_HEADER_LEN, &ct_len, len + 16,
                            nonce, 12, data, len,
                            aad, DTLS_RECORD_HEADER_LEN) != 1)
            return -1;
    } else {
        memcpy(dgram + DTLS_RECORD_HEADER_LEN, data, len);
    }

    size_t dgram_len = DTLS_RECORD_HEADER_LEN + record_len;
    ssize_t sent = send(conn->fd, dgram, dgram_len, 0);
    if (sent < 0 && errno == EPERM)
        sent = write(conn->fd, dgram, dgram_len);
    /* PMTU black-hole: kernel reports EMSGSIZE. Reduce MTU and bubble up
     * so the caller can re-fragment on the next retransmit attempt. */
    if (sent < 0 && errno == EMSGSIZE) {
        if (conn->mtu > 576)
            conn->mtu = 576;
        conn->pmtu = conn->mtu;
        return -1;
    }
    if (sent > 0) {
        conn->write_seq++;
        (void)dtls_flight_append(conn, dgram, dgram_len);
    }

    return sent;
}

static ssize_t
dtls_recv_record(opssl_dtls_conn_t *conn, uint8_t *type,
                 uint8_t *out, size_t out_cap)
{
    uint8_t buf[18432];
    ssize_t n = recv(conn->fd, buf, sizeof(buf), 0);
    if (n <= 0) {
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
            return -2;
        return -1;
    }

    if ((size_t)n < DTLS_RECORD_HEADER_LEN)
        return -1;

    *type = buf[0];
    uint16_t epoch = (uint16_t)((buf[3] << 8) | buf[4]);
    uint64_t seq = 0;
    for (int i = 0; i < 6; i++)
        seq = (seq << 8) | buf[5 + i];
    uint16_t record_len = (uint16_t)((buf[11] << 8) | buf[12]);

    if ((size_t)DTLS_RECORD_HEADER_LEN + record_len > (size_t)n)
        return -1;

    if (conn->read_encrypted && epoch != conn->epoch_read)
        return -1;
    if (conn->read_encrypted && !dtls_replay_check(&conn->replay_window, seq))
        return -1;

    const uint8_t *payload = buf + DTLS_RECORD_HEADER_LEN;

    if (conn->read_encrypted && conn->read_cipher) {
        if (record_len < 16)
            return -1;

        uint8_t nonce[12];
        memcpy(nonce, conn->read_iv, 12);
        for (int i = 0; i < 8; i++)
            nonce[4 + i] ^= (uint8_t)(seq >> (56 - 8 * i));

        uint8_t aad[DTLS_RECORD_HEADER_LEN];
        memcpy(aad, buf, DTLS_RECORD_HEADER_LEN);
        size_t pt_len = record_len - 16;
        aad[11] = (uint8_t)(pt_len >> 8);
        aad[12] = (uint8_t)(pt_len);

        size_t decrypted_len = 0;
        if (opssl_aead_open(conn->read_cipher,
                            out, &decrypted_len, out_cap,
                            nonce, 12, payload, record_len,
                            aad, DTLS_RECORD_HEADER_LEN) != 1)
            return -1;

        conn->read_seq = seq + 1;
        return (ssize_t)decrypted_len;
    }

    if (record_len > out_cap)
        return -1;

    memcpy(out, payload, record_len);
    conn->read_seq = seq + 1;
    return (ssize_t)record_len;
}

/* ─── Handshake Message Framing ────────────────────────────────────── */

static ssize_t
dtls_send_handshake(opssl_dtls_conn_t *conn, uint8_t hs_type,
                    const uint8_t *body, size_t body_len)
{
    /* Guard against MTU underflow (size_t wraparound) on pathologically
     * small MTU values; floor to a 64-byte fragment payload. */
    size_t min_overhead = DTLS_OVERHEAD + DTLS_HS_HEADER_LEN;
    size_t max_frag = (conn->mtu > min_overhead + 64)
                    ? conn->mtu - min_overhead : 64;
    size_t offset = 0;

    do {
        size_t frag_len = body_len - offset;
        if (frag_len > max_frag)
            frag_len = max_frag;

        uint8_t msg[DTLS_MAX_RECORD_LEN];
        msg[0] = hs_type;
        msg[1] = (uint8_t)(body_len >> 16);
        msg[2] = (uint8_t)(body_len >> 8);
        msg[3] = (uint8_t)(body_len);
        msg[4] = (uint8_t)(conn->msg_seq_send >> 8);
        msg[5] = (uint8_t)(conn->msg_seq_send);
        msg[6] = (uint8_t)(offset >> 16);
        msg[7] = (uint8_t)(offset >> 8);
        msg[8] = (uint8_t)(offset);
        msg[9]  = (uint8_t)(frag_len >> 16);
        msg[10] = (uint8_t)(frag_len >> 8);
        msg[11] = (uint8_t)(frag_len);

        if (frag_len > 0)
            memcpy(msg + DTLS_HS_HEADER_LEN, body + offset, frag_len);

        ssize_t rc = dtls_send_record(conn, DTLS_RT_HANDSHAKE,
                                      msg, DTLS_HS_HEADER_LEN + frag_len);
        if (rc < 0)
            return rc;

        offset += frag_len;
    } while (offset < body_len);

    conn->msg_seq_send++;
    return (ssize_t)body_len;
}

/* ─── Fragment Reassembly ──────────────────────────────────────────── */

static void
dtls_reassembly_free(dtls_reassembly_t *r)
{
    if (!r)
        return;
    if (r->body)
        op_free(r->body);
    if (r->coverage)
        op_free(r->coverage);
    op_free(r);
}

static void
dtls_reassembly_purge(opssl_dtls_conn_t *conn)
{
    dtls_reassembly_t *r = conn->reassembly_queue;
    while (r) {
        dtls_reassembly_t *next = r->next;
        dtls_reassembly_free(r);
        r = next;
    }
    conn->reassembly_queue = NULL;
}

static dtls_reassembly_t *
dtls_reassembly_get(opssl_dtls_conn_t *conn, uint16_t msg_seq,
                    uint8_t type, uint32_t total_length)
{
    for (dtls_reassembly_t *r = conn->reassembly_queue; r; r = r->next) {
        if (r->msg_seq == msg_seq)
            return r;
    }

    if (total_length > DTLS_MAX_HS_MSG_LEN)
        return NULL;

    dtls_reassembly_t *r = op_calloc(1, sizeof(*r));
    if (!r)
        return NULL;
    r->type         = type;
    r->msg_seq      = msg_seq;
    r->total_length = total_length;
    r->body         = op_malloc(total_length > 0 ? total_length : 1);
    size_t cov_bytes = (total_length + 7) / 8;
    r->coverage     = op_calloc(1, cov_bytes > 0 ? cov_bytes : 1);
    if (!r->body || !r->coverage) {
        dtls_reassembly_free(r);
        return NULL;
    }

    r->next = conn->reassembly_queue;
    conn->reassembly_queue = r;
    return r;
}

static bool
dtls_reassembly_add_fragment(dtls_reassembly_t *r,
                              uint32_t frag_offset, uint32_t frag_length,
                              const uint8_t *data)
{
    if (!r->body || !r->coverage)
        return false;
    /* Overflow-safe bounds check on the fragment window. */
    if (frag_length > r->total_length ||
        frag_offset > r->total_length - frag_length)
        return false;

    /* Track only bytes newly covered to keep bytes_received accurate
     * against duplicate or overlapping retransmissions. */
    uint32_t newly = 0;
    for (uint32_t i = frag_offset; i < frag_offset + frag_length; i++) {
        uint8_t bit = (uint8_t)(1u << (i % 8));
        if (!(r->coverage[i / 8] & bit)) {
            r->coverage[i / 8] |= bit;
            newly++;
        }
    }
    if (newly > 0) {
        memcpy(r->body + frag_offset, data, frag_length);
        r->bytes_received += newly;
    }
    return (r->bytes_received >= r->total_length);
}

static dtls_reassembly_t *
dtls_reassembly_take(opssl_dtls_conn_t *conn, uint16_t msg_seq)
{
    dtls_reassembly_t **pp = &conn->reassembly_queue;
    while (*pp) {
        if ((*pp)->msg_seq == msg_seq) {
            dtls_reassembly_t *r = *pp;
            *pp = r->next;
            r->next = NULL;
            return r;
        }
        pp = &(*pp)->next;
    }
    return NULL;
}

/* ─── Cookie Generation and Verification ───────────────────────────── */

static int
dtls_make_cookie(opssl_dtls_conn_t *conn,
                 const struct sockaddr *peer, socklen_t peerlen,
                 uint8_t *cookie_out, size_t *cookie_len_out)
{
    uint8_t input[sizeof(struct sockaddr_storage)];
    size_t  input_len = 0;

    if ((peer == NULL && peerlen != 0) ||
        (size_t)peerlen > sizeof(struct sockaddr_storage))
        return 0;

    if (peer != NULL && peerlen > 0) {
        memcpy(input, peer, peerlen);
        input_len = peerlen;
    }
    size_t mac_len = 32;
    if (opssl_hmac(OPSSL_HMAC_SHA256,
                   conn->cookie_hmac_key, sizeof(conn->cookie_hmac_key),
                   input, input_len,
                   cookie_out, &mac_len) != 1)
        return 0;

    *cookie_len_out = mac_len;
    return 1;
}

static int
dtls_generate_cookie(opssl_dtls_conn_t *conn,
                     uint8_t *cookie_out, size_t *cookie_len_out)
{
    struct sockaddr_storage peer;
    socklen_t peerlen = sizeof(peer);
    if (getpeername(conn->fd, (struct sockaddr *)&peer, &peerlen) != 0)
        peerlen = 0;
    return dtls_make_cookie(conn, peerlen ? (struct sockaddr *)&peer : NULL, peerlen,
                            cookie_out, cookie_len_out);
}

static int
dtls_verify_cookie(opssl_dtls_conn_t *conn,
                   const uint8_t *cookie_in, size_t cookie_in_len)
{
    uint8_t expected[32];
    size_t  expected_len = 0;

    if (!dtls_generate_cookie(conn, expected, &expected_len))
        return 0;
    if (expected_len != cookie_in_len)
        return 0;

    uint8_t diff = 0;
    for (size_t i = 0; i < expected_len; i++)
        diff |= expected[i] ^ cookie_in[i];

    return (diff == 0) ? 1 : 0;
}

/* ─── AEAD Cipher Setup ───────────────────────────────────────────── */

static opssl_result_t
dtls_setup_cipher_contexts(opssl_dtls_conn_t *conn,
                           const uint8_t *client_key, size_t client_key_len,
                           const uint8_t *server_key, size_t server_key_len,
                           const uint8_t *client_iv,  size_t client_iv_len,
                           const uint8_t *server_iv,  size_t server_iv_len,
                           opssl_ciphersuite_t cipher)
{
    opssl_aead_algo_t aead_type;
    switch (cipher) {
    case OPSSL_TLS_AES_128_GCM_SHA256:       aead_type = OPSSL_AEAD_AES_128_GCM;       break;
    case OPSSL_TLS_AES_256_GCM_SHA384:       aead_type = OPSSL_AEAD_AES_256_GCM;       break;
    case OPSSL_TLS_CHACHA20_POLY1305_SHA256: aead_type = OPSSL_AEAD_CHACHA20_POLY1305; break;
    default: return OPSSL_ERROR;
    }

    conn->cipher = cipher;

    if (conn->read_cipher)  { opssl_aead_free(conn->read_cipher);  conn->read_cipher  = NULL; }
    if (conn->write_cipher) { opssl_aead_free(conn->write_cipher); conn->write_cipher = NULL; }

    conn->read_cipher  = opssl_aead_new(aead_type);
    conn->write_cipher = opssl_aead_new(aead_type);
    if (!conn->read_cipher || !conn->write_cipher)
        goto err;

    const uint8_t *read_key, *write_key, *read_iv, *write_iv;
    size_t          rkl,       wkl,        rivl,      wivl;

    if (conn->dir == OPSSL_DIR_INBOUND) {
        read_key = client_key; rkl  = client_key_len;
        write_key = server_key; wkl  = server_key_len;
        read_iv  = client_iv;  rivl = client_iv_len;
        write_iv = server_iv;  wivl = server_iv_len;
    } else {
        read_key = server_key; rkl  = server_key_len;
        write_key = client_key; wkl  = client_key_len;
        read_iv  = server_iv;  rivl = server_iv_len;
        write_iv = client_iv;  wivl = client_iv_len;
    }

    if (opssl_aead_set_key(conn->read_cipher, read_key, rkl) != 1)
        goto err;
    memcpy(conn->read_iv, read_iv,
           rivl < sizeof(conn->read_iv) ? rivl : sizeof(conn->read_iv));

    if (opssl_aead_set_key(conn->write_cipher, write_key, wkl) != 1)
        goto err;
    memcpy(conn->write_iv, write_iv,
           wivl < sizeof(conn->write_iv) ? wivl : sizeof(conn->write_iv));

    conn->epoch_write++;
    conn->epoch_read++;
    conn->write_seq       = 0;
    conn->read_seq        = 0;
    conn->read_encrypted  = true;
    conn->write_encrypted = true;
    return OPSSL_OK;

err:
    if (conn->read_cipher)  { opssl_aead_free(conn->read_cipher);  conn->read_cipher  = NULL; }
    if (conn->write_cipher) { opssl_aead_free(conn->write_cipher); conn->write_cipher = NULL; }
    return OPSSL_ERROR;
}

static opssl_result_t
dtls_setup_handshake_cipher(opssl_dtls_conn_t *conn)
{
    if (conn->read_encrypted && conn->write_encrypted)
        return OPSSL_OK;

    uint8_t client_key[48], server_key[48];
    uint8_t client_iv[12],  server_iv[12];
    size_t  ckl = 0, skl = 0, civl = 0, sivl = 0;
    opssl_ciphersuite_t cipher = 0;

    if (opssl_tls13_extract_hs_keys(conn->hs_buf,
                                    client_key, &ckl,
                                    server_key, &skl,
                                    client_iv,  &civl,
                                    server_iv,  &sivl,
                                    &cipher) != OPSSL_OK)
        return OPSSL_ERROR;

    opssl_result_t rc = dtls_setup_cipher_contexts(conn,
                                                   client_key, ckl,
                                                   server_key, skl,
                                                   client_iv,  civl,
                                                   server_iv,  sivl,
                                                   cipher);
    opssl_memzero(client_key, sizeof(client_key));
    opssl_memzero(server_key, sizeof(server_key));
    return rc;
}

/* ─── TLS 1.3 Engine ──────────────────────────────────────────────── */

static void
dtls_hs_engine_init(opssl_dtls_conn_t *conn)
{
    if (conn->hs_initialized)
        return;

    memset(conn->hs_buf, 0, sizeof(conn->hs_buf));
    conn->hs_initialized = true;

    if (conn->dir == OPSSL_DIR_INBOUND) {
        opssl_pkey_t       *pkey  = opssl_ctx_get_private_key(conn->ctx);
        opssl_x509_chain_t *chain = opssl_ctx_get_cert_chain(conn->ctx);
        if (pkey)  opssl_tls13_set_sign_key(conn->hs_buf, pkey);
        if (chain) opssl_tls13_set_cert_chain(conn->hs_buf, chain);
    } else {
        if (conn->sni[0])
            opssl_tls13_set_sni(conn->hs_buf, conn->sni);
    }
}

static opssl_result_t
dtls_send_engine_output(opssl_dtls_conn_t *conn, const uint8_t *out_data, size_t out_len)
{
    const uint8_t *p = out_data;
    size_t remaining = out_len;

    while (remaining >= DTLS_TLS_HS_HEADER_LEN) {
        uint8_t  mtype = p[0];
        uint32_t mlen  = ((uint32_t)p[1] << 16) |
                         ((uint32_t)p[2] << 8)  |
                         (uint32_t)p[3];
        if (DTLS_TLS_HS_HEADER_LEN + mlen > remaining)
            break;

        ssize_t rc = dtls_send_handshake(conn, mtype,
                                         p + DTLS_TLS_HS_HEADER_LEN, mlen);
        if (rc < 0)
            return OPSSL_ERROR;

        if (mtype == DTLS_HT_SERVER_HELLO &&
            dtls_setup_handshake_cipher(conn) != OPSSL_OK)
            return OPSSL_ERROR;

        p         += DTLS_TLS_HS_HEADER_LEN + mlen;
        remaining -= DTLS_TLS_HS_HEADER_LEN + mlen;
    }
    return OPSSL_OK;
}

static opssl_result_t
dtls_drive_tls13_engine(opssl_dtls_conn_t *conn,
                        uint8_t hs_type, const uint8_t *body, size_t body_len)
{
    uint8_t tls_msg[DTLS_MAX_HS_MSG_LEN + DTLS_TLS_HS_HEADER_LEN];
    if (DTLS_TLS_HS_HEADER_LEN + body_len > sizeof(tls_msg))
        return OPSSL_ERROR;

    tls_msg[0] = hs_type;
    tls_msg[1] = (uint8_t)(body_len >> 16);
    tls_msg[2] = (uint8_t)(body_len >> 8);
    tls_msg[3] = (uint8_t)(body_len);
    if (body_len > 0)
        memcpy(tls_msg + DTLS_TLS_HS_HEADER_LEN, body, body_len);

    uint8_t out_data[16384];
    size_t consumed = 0, out_len = 0;
    int rc;

    if (conn->dir == OPSSL_DIR_INBOUND) {
        rc = opssl_tls13_server_handshake(conn->hs_buf,
                                          tls_msg, DTLS_TLS_HS_HEADER_LEN + body_len,
                                          &consumed, out_data, &out_len, sizeof(out_data));
    } else {
        rc = opssl_tls13_client_handshake(conn->hs_buf,
                                          tls_msg, DTLS_TLS_HS_HEADER_LEN + body_len,
                                          &consumed, out_data, &out_len, sizeof(out_data));
    }

    if (out_len > 0) {
        if (dtls_send_engine_output(conn, out_data, out_len) != OPSSL_OK)
            return OPSSL_ERROR;
    }

    if (rc == OPSSL_ERROR)
        return OPSSL_ERROR;

    opssl_handshake_state_t *hs_state_p = (opssl_handshake_state_t *)conn->hs_buf;

    if (conn->dir == OPSSL_DIR_OUTBOUND &&
        hs_type == DTLS_HT_SERVER_HELLO &&
        *hs_state_p > OPSSL_HS_CLIENT_HELLO &&
        !conn->read_encrypted &&
        dtls_setup_handshake_cipher(conn) != OPSSL_OK)
        return OPSSL_ERROR;

    /* Pump through engine states that auto-advance without needing new wire data
     * (e.g. server: CLIENT_HELLO->ENCRYPTED_EXTENSIONS->FINISHED->WAIT_FINISHED).
     * Stop when blocked on input (WANT_READ), an error, or handshake completion. */
    {
        uint8_t empty[1] = {0};
        for (int pump = 0;
             rc == OPSSL_OK && *hs_state_p != OPSSL_HS_COMPLETE && pump < 8;
             pump++) {
            consumed = 0;
            out_len  = 0;
            if (conn->dir == OPSSL_DIR_INBOUND)
                rc = opssl_tls13_server_handshake(conn->hs_buf, empty, 0,
                                                  &consumed, out_data, &out_len,
                                                  sizeof(out_data));
            else
                rc = opssl_tls13_client_handshake(conn->hs_buf, empty, 0,
                                                  &consumed, out_data, &out_len,
                                                  sizeof(out_data));
            if (out_len > 0) {
                if (dtls_send_engine_output(conn, out_data, out_len) != OPSSL_OK)
                    return OPSSL_ERROR;
            }
            if (rc == OPSSL_ERROR)
                return OPSSL_ERROR;
        }
    }

    if (*hs_state_p == OPSSL_HS_COMPLETE && conn->hs_state != OPSSL_HS_COMPLETE) {
        uint8_t client_key[48], server_key[48];
        uint8_t client_iv[12],  server_iv[12];
        size_t  ckl = 0, skl = 0, civl = 0, sivl = 0;
        opssl_ciphersuite_t neg_cipher = 0;

        if (opssl_tls13_extract_traffic_keys(conn->hs_buf,
                                             client_key, &ckl,
                                             server_key, &skl,
                                             client_iv,  &civl,
                                             server_iv,  &sivl,
                                             &neg_cipher) != OPSSL_OK)
            goto key_err;

        if (dtls_setup_cipher_contexts(conn,
                                       client_key, ckl, server_key, skl,
                                       client_iv,  civl, server_iv,  sivl,
                                       neg_cipher) != OPSSL_OK)
            goto key_err;

        opssl_memzero(client_key, sizeof(client_key));
        opssl_memzero(server_key, sizeof(server_key));
        conn->hs_state = OPSSL_HS_COMPLETE;
        conn->version  = OPSSL_DTLS_1_2;
        dtls_flight_clear(conn);
        return OPSSL_OK;

    key_err:
        opssl_memzero(client_key, sizeof(client_key));
        opssl_memzero(server_key, sizeof(server_key));
        return OPSSL_ERROR;
    }

    return (rc == OPSSL_OK) ? OPSSL_OK : OPSSL_WANT_READ;
}

/* ─── Handshake Record Dispatcher ──────────────────────────────────── */

static opssl_result_t
dtls_process_handshake_record(opssl_dtls_conn_t *conn,
                               const uint8_t *record, size_t record_len)
{
    if (record_len < DTLS_HS_HEADER_LEN)
        return OPSSL_ERROR;

    uint8_t  hs_type     = record[0];
    uint32_t total_len   = ((uint32_t)record[1] << 16) |
                           ((uint32_t)record[2] << 8)  |
                           (uint32_t)record[3];
    uint16_t msg_seq     = (uint16_t)((record[4] << 8) | record[5]);
    uint32_t frag_offset = ((uint32_t)record[6] << 16) |
                           ((uint32_t)record[7] << 8)  |
                           (uint32_t)record[8];
    uint32_t frag_len    = ((uint32_t)record[9]  << 16) |
                           ((uint32_t)record[10] << 8)  |
                           (uint32_t)record[11];

    if (DTLS_HS_HEADER_LEN + frag_len > record_len)
        return OPSSL_ERROR;

    const uint8_t *frag_data = record + DTLS_HS_HEADER_LEN;

    /* Server: initial ClientHello cookie exchange */
    if (conn->dir == OPSSL_DIR_INBOUND &&
        conn->hs_state == OPSSL_HS_IDLE &&
        hs_type == DTLS_HT_CLIENT_HELLO)
    {
        if (frag_offset == 0 && frag_len >= 34 && !conn->client_random_set) {
            memcpy(conn->client_random, frag_data + 2, 32);
            conn->client_random_set = true;
        }

        if (!conn->cookie_verified) {
            if (frag_offset != 0 || frag_len < 34)
                return OPSSL_WANT_READ;

            size_t off = 2 + 32;
            if (off >= frag_len) return OPSSL_ERROR;
            uint8_t sid_len = frag_data[off++];
            if (off + sid_len > frag_len) return OPSSL_ERROR;
            off += sid_len;
            if (off >= frag_len) return OPSSL_ERROR;
            uint8_t cookie_len_wire = frag_data[off++];

            if (cookie_len_wire == 0) {
                uint8_t new_cookie[32];
                size_t  new_cookie_len = 0;
                if (!dtls_generate_cookie(conn, new_cookie, &new_cookie_len))
                    return OPSSL_ERROR;
                if (new_cookie_len > sizeof(conn->cookie))
                    return OPSSL_ERROR;
                memcpy(conn->cookie, new_cookie, new_cookie_len);
                conn->cookie_len = new_cookie_len;

                uint8_t hvr[35];
                size_t  hvr_len = 0;
                hvr[hvr_len++] = 0xFE;
                hvr[hvr_len++] = 0xFD;
                hvr[hvr_len++] = (uint8_t)new_cookie_len;
                memcpy(hvr + hvr_len, new_cookie, new_cookie_len);
                hvr_len += new_cookie_len;

                dtls_send_handshake(conn, DTLS_HT_HELLO_VERIFY_REQUEST, hvr, hvr_len);
                conn->retransmit_count       = 0;
                conn->current_timeout_ms     = DTLS_INITIAL_TIMEOUT_MS;
                conn->retransmit_deadline_ms = now_ms() + conn->current_timeout_ms;
                conn->flight_state           = DTLS_FLIGHT_WAITING;
                return OPSSL_WANT_READ;
            }

            if (off + cookie_len_wire > frag_len) return OPSSL_ERROR;
            if (!dtls_verify_cookie(conn, frag_data + off, cookie_len_wire))
                return OPSSL_WANT_READ;

            conn->cookie_verified = true;
            conn->hs_state = OPSSL_HS_CLIENT_HELLO;
        }
    }

    /* Client: HelloVerifyRequest handling */
    if (conn->dir == OPSSL_DIR_OUTBOUND &&
        hs_type == DTLS_HT_HELLO_VERIFY_REQUEST &&
        conn->hs_state == OPSSL_HS_CLIENT_HELLO)
    {
        if (frag_offset != 0 || frag_len < 3)
            return OPSSL_ERROR;

        uint32_t clen = frag_data[2];
        if (3 + clen > frag_len) return OPSSL_ERROR;
        if (clen > sizeof(conn->cookie)) return OPSSL_ERROR;
        memcpy(conn->cookie, frag_data + 3, clen);
        conn->cookie_len = clen;

        conn->msg_seq_send = 0;
        conn->hs_state     = OPSSL_HS_IDLE;
        dtls_flight_clear(conn);
        dtls_reassembly_purge(conn);

        conn->hs_initialized = false;
        dtls_hs_engine_init(conn);

        uint8_t empty[1] = {0};
        uint8_t out_data[16384];
        size_t consumed = 0, out_len = 0;
        opssl_tls13_client_handshake(conn->hs_buf, empty, 0,
                                      &consumed, out_data, &out_len, sizeof(out_data));
        /* Inject DTLS cookie into the TLS 1.3 ClientHello body.
         * Cookie field goes after version(2)+random(32)+session_id in DTLS format. */
        if (out_len >= 4 && conn->cookie_len > 0) {
            uint8_t  msg_type   = out_data[0];
            uint32_t body_len_u = ((uint32_t)out_data[1] << 16) |
                                  ((uint32_t)out_data[2] << 8)  |
                                  (uint32_t)out_data[3];
            const uint8_t *body = out_data + 4;

            if (msg_type == DTLS_HT_CLIENT_HELLO && body_len_u >= 35) {
                size_t body_len  = body_len_u;
                size_t sid_len   = body[34];
                size_t inject_at = 35 + sid_len;

                if (inject_at <= body_len) {
                    size_t   new_len  = body_len + 1 + conn->cookie_len;
                    uint8_t *new_body = op_malloc(new_len);
                    memcpy(new_body, body, inject_at);
                    new_body[inject_at] = (uint8_t)conn->cookie_len;
                    memcpy(new_body + inject_at + 1, conn->cookie, conn->cookie_len);
                    memcpy(new_body + inject_at + 1 + conn->cookie_len,
                           body + inject_at, body_len - inject_at);
                    dtls_send_handshake(conn, msg_type, new_body, new_len);
                    op_free(new_body);
                } else {
                    dtls_send_engine_output(conn, out_data, out_len);
                }
            } else {
                dtls_send_engine_output(conn, out_data, out_len);
            }
        } else if (out_len > 0) {
            dtls_send_engine_output(conn, out_data, out_len);
        }

        conn->hs_state               = OPSSL_HS_CLIENT_HELLO;
        conn->retransmit_count       = 0;
        conn->current_timeout_ms     = DTLS_INITIAL_TIMEOUT_MS;
        conn->retransmit_deadline_ms = now_ms() + conn->current_timeout_ms;
        return OPSSL_WANT_READ;
    }

    dtls_hs_engine_init(conn);

    if (frag_offset == 0 && frag_len == total_len) {
        /* For ClientHello after cookie verification: strip the DTLS cookie field
         * before passing to TLS 1.3 engine (expects plain TLS 1.3 format). */
        if (hs_type == DTLS_HT_CLIENT_HELLO && conn->cookie_verified && frag_len >= 35) {
            size_t sid_len  = frag_data[34];
            size_t strip_at = 35 + sid_len;
            if (strip_at < frag_len) {
                size_t ck_len = frag_data[strip_at];
                size_t skip   = 1 + ck_len;
                if (strip_at + skip <= frag_len) {
                    size_t   new_len  = frag_len - skip;
                    uint8_t *stripped = op_malloc(new_len > 0 ? new_len : 1);
                    memcpy(stripped, frag_data, strip_at);
                    memcpy(stripped + strip_at, frag_data + strip_at + skip,
                           frag_len - strip_at - skip);
                    opssl_result_t r = dtls_drive_tls13_engine(conn, hs_type,
                                                                stripped, new_len);
                    op_free(stripped);
                    return r;
                }
            }
        }
        return dtls_drive_tls13_engine(conn, hs_type, frag_data, frag_len);
    }

    dtls_reassembly_t *r = dtls_reassembly_get(conn, msg_seq, hs_type, total_len);
    if (!r)
        return OPSSL_ERROR;

    bool complete = dtls_reassembly_add_fragment(r, frag_offset, frag_len, frag_data);
    if (!complete)
        return OPSSL_WANT_READ;

    dtls_reassembly_t *done = dtls_reassembly_take(conn, msg_seq);
    if (!done)
        return OPSSL_ERROR;

    opssl_result_t result = dtls_drive_tls13_engine(conn,
                                                     done->type,
                                                     done->body,
                                                     done->total_length);
    dtls_reassembly_free(done);
    return result;
}

/* ─── Handshake Drivers ────────────────────────────────────────────── */

static opssl_result_t
dtls_do_server_handshake(opssl_dtls_conn_t *conn)
{
    if (conn->hs_state == OPSSL_HS_COMPLETE)
        return OPSSL_OK;

    uint8_t buf[18432];
    uint8_t type;

    ssize_t n = dtls_recv_record(conn, &type, buf, sizeof(buf));
    if (n == -2) {
        if (conn->flight_state == DTLS_FLIGHT_WAITING &&
            now_ms() >= conn->retransmit_deadline_ms)
            return opssl_dtls_handle_timeout(conn);
        return OPSSL_WANT_READ;
    }
    if (n < 0)
        return OPSSL_ERROR;
    if (type == DTLS_RT_CHANGE_CIPHER_SPEC)
        return OPSSL_WANT_READ;
    if (type != DTLS_RT_HANDSHAKE)
        return OPSSL_ERROR;

    opssl_result_t r = dtls_process_handshake_record(conn, buf, (size_t)n);
    return r;
}

static opssl_result_t
dtls_do_client_handshake(opssl_dtls_conn_t *conn)
{
    if (conn->hs_state == OPSSL_HS_COMPLETE)
        return OPSSL_OK;

    if (conn->hs_state == OPSSL_HS_IDLE) {
        dtls_hs_engine_init(conn);
        dtls_flight_clear(conn);

        uint8_t empty[1] = {0};
        uint8_t out_data[16384];
        size_t consumed = 0, out_len = 0;
        int r = opssl_tls13_client_handshake(conn->hs_buf, empty, 0,
                                      &consumed, out_data, &out_len, sizeof(out_data));
        (void)r;
        if (out_len > 0)
            dtls_send_engine_output(conn, out_data, out_len);

        conn->hs_state               = OPSSL_HS_CLIENT_HELLO;
        conn->retransmit_count       = 0;
        conn->current_timeout_ms     = DTLS_INITIAL_TIMEOUT_MS;
        conn->retransmit_deadline_ms = now_ms() + conn->current_timeout_ms;
        conn->flight_state           = DTLS_FLIGHT_WAITING;
        return OPSSL_WANT_READ;
    }

    uint8_t buf[18432];
    uint8_t type;

    ssize_t n = dtls_recv_record(conn, &type, buf, sizeof(buf));
    if (n == -2) {
        if (now_ms() >= conn->retransmit_deadline_ms)
            return opssl_dtls_handle_timeout(conn);
        return OPSSL_WANT_READ;
    }
    if (n < 0)
        return OPSSL_ERROR;
    if (type == DTLS_RT_CHANGE_CIPHER_SPEC)
        return OPSSL_WANT_READ;
    if (type != DTLS_RT_HANDSHAKE)
        return OPSSL_ERROR;

    opssl_result_t result = dtls_process_handshake_record(conn, buf, (size_t)n);

    if (result == OPSSL_WANT_READ) {
        conn->retransmit_count       = 0;
        conn->current_timeout_ms     = DTLS_INITIAL_TIMEOUT_MS;
        conn->retransmit_deadline_ms = now_ms() + conn->current_timeout_ms;
    }

    return result;
}

/* ─── Public API ───────────────────────────────────────────────────── */

opssl_dtls_conn_t *
opssl_dtls_conn_new(opssl_ctx_t *ctx, int fd, opssl_direction_t dir)
{
    opssl_dtls_conn_t *conn = op_calloc(1, sizeof(*conn));
    if (!conn)
        return NULL;

    conn->ctx  = ctx;
    conn->fd   = fd;
    conn->dir  = dir;
    conn->mtu  = DTLS_DEFAULT_MTU;
    conn->pmtu = DTLS_DEFAULT_MTU;
    conn->hs_state           = OPSSL_HS_IDLE;
    conn->current_timeout_ms = DTLS_INITIAL_TIMEOUT_MS;

    const uint8_t *secret = opssl_ctx_get_dtls_cookie_secret(ctx);
    if (secret)
        memcpy(conn->cookie_hmac_key, secret, sizeof(conn->cookie_hmac_key));
    else
        opssl_random_bytes(conn->cookie_hmac_key, sizeof(conn->cookie_hmac_key));

    return conn;
}

void
opssl_dtls_conn_free(opssl_dtls_conn_t *conn)
{
    if (!conn)
        return;

    if (conn->read_cipher)  opssl_aead_free(conn->read_cipher);
    if (conn->write_cipher) opssl_aead_free(conn->write_cipher);
    if (conn->flight_buf)   op_free(conn->flight_buf);

    dtls_reassembly_purge(conn);
    opssl_memzero(conn->cookie_hmac_key, sizeof(conn->cookie_hmac_key));
    opssl_memzero(conn->hs_buf, sizeof(conn->hs_buf));
    opssl_memzero(conn, sizeof(*conn));
    op_free(conn);
}

opssl_result_t
opssl_dtls_accept(opssl_dtls_conn_t *conn)
{
    if (!conn || conn->dir != OPSSL_DIR_INBOUND)
        return OPSSL_ERROR;
    return dtls_do_server_handshake(conn);
}

opssl_result_t
opssl_dtls_connect(opssl_dtls_conn_t *conn)
{
    if (!conn || conn->dir != OPSSL_DIR_OUTBOUND)
        return OPSSL_ERROR;
    return dtls_do_client_handshake(conn);
}

ssize_t
opssl_dtls_read(opssl_dtls_conn_t *conn, void *buf, size_t len)
{
    if (!conn || conn->hs_state != OPSSL_HS_COMPLETE)
        return -1;

    uint8_t type;
    uint8_t tmp[16384];
    ssize_t n = dtls_recv_record(conn, &type, tmp, sizeof(tmp));
    if (n == -2) return -2;
    if (n < 0)   return -1;

    if (type == DTLS_RT_ALERT) {
        if (n >= 2 && tmp[1] == 0) conn->shutdown_received = true;
        return 0;
    }
    if (type != DTLS_RT_APPLICATION_DATA)
        return -1;

    size_t copy = (size_t)n < len ? (size_t)n : len;
    memcpy(buf, tmp, copy);
    return (ssize_t)copy;
}

ssize_t
opssl_dtls_write(opssl_dtls_conn_t *conn, const void *buf, size_t len)
{
    if (!conn || conn->hs_state != OPSSL_HS_COMPLETE)
        return -1;

    size_t max_payload = (conn->mtu > DTLS_OVERHEAD + 64)
                       ? conn->mtu - DTLS_OVERHEAD : 64;
    const uint8_t *p  = (const uint8_t *)buf;
    size_t remaining  = len;

    while (remaining > 0) {
        size_t chunk = remaining < max_payload ? remaining : max_payload;
        ssize_t rc = dtls_send_record(conn, DTLS_RT_APPLICATION_DATA, p, chunk);
        if (rc < 0) return rc;
        p         += chunk;
        remaining -= chunk;
    }

    return (ssize_t)len;
}

opssl_result_t
opssl_dtls_shutdown(opssl_dtls_conn_t *conn)
{
    if (!conn)
        return OPSSL_ERROR;

    if (!conn->shutdown_sent) {
        uint8_t alert[2] = {1, 0};
        dtls_send_record(conn, DTLS_RT_ALERT, alert, 2);
        conn->shutdown_sent = true;
    }

    return OPSSL_OK;
}

void
opssl_dtls_set_mtu(opssl_dtls_conn_t *conn, size_t mtu)
{
    if (conn && mtu >= 256 && mtu <= DTLS_MAX_RECORD_LEN) {
        conn->mtu  = mtu;
        conn->pmtu = mtu;
    }
}

size_t
opssl_dtls_get_mtu(const opssl_dtls_conn_t *conn)
{
    return conn ? conn->mtu : 0;
}

opssl_result_t
opssl_dtls_handle_timeout(opssl_dtls_conn_t *conn)
{
    if (!conn)
        return OPSSL_ERROR;
    if (conn->hs_state == OPSSL_HS_COMPLETE)
        return OPSSL_OK;

    uint64_t current = now_ms();
    if (current < conn->retransmit_deadline_ms)
        return OPSSL_WANT_READ;

    if (conn->retransmit_count >= DTLS_MAX_RETRANSMIT) {
        conn->last_error = OPSSL_ERR_PACK(OPSSL_ERR_TLS, 0);
        return OPSSL_FATAL;
    }

    if (conn->flight_buf && conn->flight_len > 0) {
        /* Re-emit each record as an individual datagram so we never exceed
         * the current path MTU. */
        for (size_t i = 0; i < conn->flight_record_count; i++) {
            size_t start = conn->flight_records[i];
            size_t end   = (i + 1 < conn->flight_record_count)
                         ? conn->flight_records[i + 1] : conn->flight_len;
            if (end > start)
                (void)send(conn->fd, conn->flight_buf + start,
                           end - start, 0);
        }
    }

    conn->retransmit_count++;
    conn->current_timeout_ms *= 2;
    if (conn->current_timeout_ms > DTLS_MAX_TIMEOUT_MS)
        conn->current_timeout_ms = DTLS_MAX_TIMEOUT_MS;
    conn->retransmit_deadline_ms = current + conn->current_timeout_ms;

    return OPSSL_WANT_READ;
}

int
opssl_dtls_get_timeout(const opssl_dtls_conn_t *conn, struct timeval *tv)
{
    if (!conn || !tv)
        return -1;

    if (conn->hs_state == OPSSL_HS_COMPLETE) {
        tv->tv_sec  = -1;
        tv->tv_usec = 0;
        return 0;
    }

    uint64_t current = now_ms();
    if (current >= conn->retransmit_deadline_ms) {
        tv->tv_sec  = 0;
        tv->tv_usec = 0;
    } else {
        uint64_t r = conn->retransmit_deadline_ms - current;
        tv->tv_sec  = (long)(r / 1000);
        tv->tv_usec = (long)((r % 1000) * 1000);
    }
    return 0;
}

void
opssl_dtls_set_replay_window(opssl_dtls_conn_t *conn, size_t window_bits)
{
    (void)window_bits;
    if (conn) {
        conn->replay_window.max_seq = 0;
        for (int i = 0; i < DTLS_REPLAY_WINDOW_WORDS; i++)
            conn->replay_window.window[i] = 0;
    }
}

opssl_dtls_version_t
opssl_dtls_conn_version(const opssl_dtls_conn_t *conn)
{
    return conn ? conn->version : 0;
}

const char *
opssl_dtls_conn_cipher_name(const opssl_dtls_conn_t *conn)
{
    if (!conn) return "NONE";
    switch (conn->cipher) {
    case OPSSL_TLS_AES_128_GCM_SHA256:       return "TLS_AES_128_GCM_SHA256";
    case OPSSL_TLS_AES_256_GCM_SHA384:       return "TLS_AES_256_GCM_SHA384";
    case OPSSL_TLS_CHACHA20_POLY1305_SHA256: return "TLS_CHACHA20_POLY1305_SHA256";
    default:                                  return "UNKNOWN";
    }
}

int
opssl_dtls_conn_set_sni(opssl_dtls_conn_t *conn, const char *hostname)
{
    if (!conn || !hostname) return 0;
    size_t len = strlen(hostname);
    if (len >= sizeof(conn->sni)) len = sizeof(conn->sni) - 1;
    memcpy(conn->sni, hostname, len);
    conn->sni[len] = '\0';
    return 1;
}

int
opssl_dtls_conn_set_alpn(opssl_dtls_conn_t *conn, const char **protos, size_t count)
{
    if (!conn || !protos || count == 0) return 0;
    size_t len = strlen(protos[0]);
    if (len >= sizeof(conn->alpn)) len = sizeof(conn->alpn) - 1;
    memcpy(conn->alpn, protos[0], len);
    conn->alpn[len] = '\0';
    conn->alpn_len  = len;
    return 1;
}

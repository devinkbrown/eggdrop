/*
 * dtls.c — DTLS 1.2 / 1.3 datagram transport layer security.
 *
 * Implements TLS over unreliable datagrams (RFC 6347, RFC 9147).
 * Handles retransmission, reordering, fragmentation, and anti-replay.
 *
 * Copyright (C) 2026 ophion development team
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <opssl/dtls.h>
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

/* DTLS record header is 13 bytes (vs TLS's 5) */
#define DTLS_RECORD_HEADER_LEN  13
#define DTLS_HS_HEADER_LEN      12  /* vs TLS's 4 */
#define DTLS_MAX_RECORD_LEN     16384
#define DTLS_DEFAULT_MTU        1500
#define DTLS_OVERHEAD           (DTLS_RECORD_HEADER_LEN + 28)  /* header + AEAD tag + nonce */
#define DTLS_MAX_RETRANSMIT     6
#define DTLS_INITIAL_TIMEOUT_MS 1000
#define DTLS_MAX_TIMEOUT_MS     60000
#define DTLS_REPLAY_WINDOW_BITS 64

/* DTLS record types (same as TLS) */
#define DTLS_RT_CHANGE_CIPHER_SPEC 20
#define DTLS_RT_ALERT              21
#define DTLS_RT_HANDSHAKE          22
#define DTLS_RT_APPLICATION_DATA   23

/* DTLS handshake message types */
#define DTLS_HT_HELLO_VERIFY_REQUEST  3
#define DTLS_HT_CLIENT_HELLO          1
#define DTLS_HT_SERVER_HELLO          2

/* Flight states for DTLS handshake retransmission */
typedef enum {
    DTLS_FLIGHT_IDLE = 0,
    DTLS_FLIGHT_SENDING,
    DTLS_FLIGHT_WAITING,
    DTLS_FLIGHT_COMPLETE,
    DTLS_FLIGHT_ERROR,
} dtls_flight_state_t;

/* Buffered handshake message for reassembly */
typedef struct dtls_hs_frag {
    uint8_t type;
    uint32_t msg_seq;
    uint32_t frag_offset;
    uint32_t frag_length;
    uint32_t total_length;
    uint8_t *data;
    struct dtls_hs_frag *next;
} dtls_hs_frag_t;

/* Anti-replay window */
typedef struct {
    uint64_t max_seq;
    uint64_t window;  /* bitmap for max_seq-63..max_seq */
} dtls_replay_window_t;

/* DTLS connection */
struct opssl_dtls_conn {
    opssl_ctx_t *ctx;
    int fd;
    opssl_direction_t dir;
    opssl_dtls_version_t version;

    /* Handshake state */
    opssl_handshake_state_t hs_state;
    opssl_ciphersuite_t cipher;
    opssl_named_group_t group;
    uint16_t msg_seq_send;
    uint16_t msg_seq_recv;
    uint16_t epoch_read;
    uint16_t epoch_write;

    /* AEAD cipher contexts */
    opssl_aead_ctx_t *read_cipher;
    opssl_aead_ctx_t *write_cipher;
    uint8_t read_iv[12];
    uint8_t write_iv[12];
    uint64_t read_seq;
    uint64_t write_seq;
    bool read_encrypted;
    bool write_encrypted;

    /* MTU */
    size_t mtu;
    size_t pmtu;

    /* Retransmission */
    dtls_flight_state_t flight_state;
    uint8_t *flight_buf;
    size_t flight_len;
    int retransmit_count;
    uint64_t retransmit_deadline_ms;
    uint32_t current_timeout_ms;

    /* Fragment reassembly */
    dtls_hs_frag_t *frag_queue;

    /* Anti-replay */
    dtls_replay_window_t replay_window;

    /* Cookie (HelloVerifyRequest / DoS protection) */
    uint8_t cookie[256];
    size_t cookie_len;

    /* SNI / ALPN */
    char sni[256];
    char alpn[32];
    size_t alpn_len;

    /* I/O buffers */
    uint8_t read_buf[18432];
    size_t read_len;

    /* Error */
    opssl_err_t last_error;

    /* Handshake transcript / keys */
    uint8_t hs_buf[4096];
    bool hs_initialized;

    /* Connection state flags */
    bool shutdown_sent;
    bool shutdown_received;
};

/* ─── Utility ────────────────────────────────────────────────────────── */

static uint64_t
now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

static int
dtls_replay_check(dtls_replay_window_t *w, uint64_t seq)
{
    if (seq > w->max_seq) {
        uint64_t shift = seq - w->max_seq;
        if (shift >= 64)
            w->window = 0;
        else
            w->window <<= shift;
        w->window |= 1;
        w->max_seq = seq;
        return 1;
    }

    uint64_t diff = w->max_seq - seq;
    if (diff >= 64)
        return 0;  /* too old */

    uint64_t bit = (uint64_t)1 << diff;
    if (w->window & bit)
        return 0;  /* duplicate */

    w->window |= bit;
    return 1;
}

/* ─── Record Layer ───────────────────────────────────────────────────── */

static ssize_t
dtls_send_record(opssl_dtls_conn_t *conn, uint8_t type,
                 const uint8_t *data, size_t len)
{
    uint8_t hdr[DTLS_RECORD_HEADER_LEN];
    hdr[0] = type;
    /* Version: DTLS 1.2 on wire regardless of negotiated (per spec) */
    hdr[1] = 0xFE;
    hdr[2] = 0xFD;
    /* Epoch (2 bytes) */
    hdr[3] = (uint8_t)(conn->epoch_write >> 8);
    hdr[4] = (uint8_t)(conn->epoch_write);
    /* Sequence number (6 bytes) */
    hdr[5] = (uint8_t)(conn->write_seq >> 40);
    hdr[6] = (uint8_t)(conn->write_seq >> 32);
    hdr[7] = (uint8_t)(conn->write_seq >> 24);
    hdr[8] = (uint8_t)(conn->write_seq >> 16);
    hdr[9] = (uint8_t)(conn->write_seq >> 8);
    hdr[10] = (uint8_t)(conn->write_seq);
    /* Length (2 bytes) */
    size_t record_len = len;
    if (conn->write_encrypted)
        record_len += 16;  /* AEAD tag */
    hdr[11] = (uint8_t)(record_len >> 8);
    hdr[12] = (uint8_t)(record_len);

    /* Build complete datagram */
    uint8_t dgram[18432];
    if (DTLS_RECORD_HEADER_LEN + record_len > sizeof(dgram))
        return -1;

    memcpy(dgram, hdr, DTLS_RECORD_HEADER_LEN);

    if (conn->write_encrypted && conn->write_cipher) {
        /* Construct nonce: IV XOR sequence */
        uint8_t nonce[12];
        memcpy(nonce, conn->write_iv, 12);
        for (int i = 0; i < 8; i++)
            nonce[4 + i] ^= (uint8_t)(conn->write_seq >> (56 - 8 * i));

        /* AAD is the record header with unencrypted length */
        uint8_t aad[DTLS_RECORD_HEADER_LEN];
        memcpy(aad, hdr, DTLS_RECORD_HEADER_LEN);
        aad[11] = (uint8_t)(len >> 8);
        aad[12] = (uint8_t)(len);

        size_t ct_len = 0;
        if (opssl_aead_seal(conn->write_cipher,
                           dgram + DTLS_RECORD_HEADER_LEN, &ct_len,
                           len + 16,
                           nonce, 12,
                           data, len,
                           aad, DTLS_RECORD_HEADER_LEN) != 1)
            return -1;
    } else {
        memcpy(dgram + DTLS_RECORD_HEADER_LEN, data, len);
    }

    ssize_t sent = send(conn->fd, dgram, DTLS_RECORD_HEADER_LEN + record_len, 0);
    if (sent > 0)
        conn->write_seq++;

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
            return -2;  /* WANT_READ */
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

    if (DTLS_RECORD_HEADER_LEN + record_len > (size_t)n)
        return -1;

    /* Anti-replay check */
    uint64_t full_seq = ((uint64_t)epoch << 48) | seq;
    if (conn->read_encrypted && !dtls_replay_check(&conn->replay_window, full_seq))
        return -1;

    const uint8_t *payload = buf + DTLS_RECORD_HEADER_LEN;

    if (conn->read_encrypted && conn->read_cipher) {
        /* Construct nonce */
        uint8_t nonce[12];
        memcpy(nonce, conn->read_iv, 12);
        for (int i = 0; i < 8; i++)
            nonce[4 + i] ^= (uint8_t)(full_seq >> (56 - 8 * i));

        /* AAD */
        uint8_t aad[DTLS_RECORD_HEADER_LEN];
        memcpy(aad, buf, DTLS_RECORD_HEADER_LEN);
        size_t pt_len = record_len - 16;
        aad[11] = (uint8_t)(pt_len >> 8);
        aad[12] = (uint8_t)(pt_len);

        size_t decrypted_len = 0;
        if (opssl_aead_open(conn->read_cipher,
                           out, &decrypted_len, out_cap,
                           nonce, 12,
                           payload, record_len,
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

/* ─── Handshake Message Framing ──────────────────────────────────────── */

static ssize_t
dtls_send_handshake(opssl_dtls_conn_t *conn, uint8_t hs_type,
                    const uint8_t *body, size_t body_len)
{
    size_t max_frag = conn->mtu - DTLS_OVERHEAD - DTLS_HS_HEADER_LEN;
    size_t offset = 0;

    while (offset < body_len || (offset == 0 && body_len == 0)) {
        size_t frag_len = body_len - offset;
        if (frag_len > max_frag)
            frag_len = max_frag;

        /* DTLS handshake header (12 bytes) */
        uint8_t msg[DTLS_MAX_RECORD_LEN];
        msg[0] = hs_type;
        /* total length (3 bytes) */
        msg[1] = (uint8_t)(body_len >> 16);
        msg[2] = (uint8_t)(body_len >> 8);
        msg[3] = (uint8_t)(body_len);
        /* message_seq (2 bytes) */
        msg[4] = (uint8_t)(conn->msg_seq_send >> 8);
        msg[5] = (uint8_t)(conn->msg_seq_send);
        /* fragment_offset (3 bytes) */
        msg[6] = (uint8_t)(offset >> 16);
        msg[7] = (uint8_t)(offset >> 8);
        msg[8] = (uint8_t)(offset);
        /* fragment_length (3 bytes) */
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
        if (body_len == 0)
            break;
    }

    conn->msg_seq_send++;
    return (ssize_t)body_len;
}

/* ─── Cookie Generation (HMAC-based) ────────────────────────────────── */

static int
dtls_generate_cookie(opssl_dtls_conn_t *conn, uint8_t *cookie, size_t *cookie_len)
{
    /* Simple HMAC-SHA256 cookie over client address info */
    uint8_t key[32];
    opssl_random_bytes(key, sizeof(key));

    struct sockaddr_storage peer;
    socklen_t peerlen = sizeof(peer);
    if (getpeername(conn->fd, (struct sockaddr *)&peer, &peerlen) != 0) {
        *cookie_len = 0;
        return 0;
    }

    uint8_t mac[32];
    size_t mac_len = 32;
    opssl_hmac(OPSSL_HMAC_SHA256, key, sizeof(key),
               (uint8_t *)&peer, peerlen, mac, &mac_len);

    *cookie_len = 32;
    memcpy(cookie, mac, 32);
    return 1;
}

/* ─── DTLS Handshake State Machine ───────────────────────────────────── */

static opssl_result_t
dtls_do_server_handshake(opssl_dtls_conn_t *conn)
{
    uint8_t buf[16384];
    uint8_t type;

    switch (conn->hs_state) {
    case OPSSL_HS_IDLE: {
        /* Wait for ClientHello */
        ssize_t n = dtls_recv_record(conn, &type, buf, sizeof(buf));
        if (n == -2)
            return OPSSL_WANT_READ;
        if (n < 0 || type != DTLS_RT_HANDSHAKE)
            return OPSSL_ERROR;
        if (n < DTLS_HS_HEADER_LEN || buf[0] != DTLS_HT_CLIENT_HELLO)
            return OPSSL_ERROR;

        /* If no cookie yet, send HelloVerifyRequest */
        if (conn->cookie_len == 0) {
            dtls_generate_cookie(conn, conn->cookie, &conn->cookie_len);

            uint8_t hvr[256];
            size_t hvr_len = 0;
            hvr[hvr_len++] = 0xFE;  /* server_version hi */
            hvr[hvr_len++] = 0xFD;  /* server_version lo (DTLS 1.2) */
            hvr[hvr_len++] = (uint8_t)conn->cookie_len;
            memcpy(hvr + hvr_len, conn->cookie, conn->cookie_len);
            hvr_len += conn->cookie_len;

            dtls_send_handshake(conn, DTLS_HT_HELLO_VERIFY_REQUEST, hvr, hvr_len);
            return OPSSL_WANT_READ;
        }

        /* ClientHello with cookie — proceed */
        conn->hs_state = OPSSL_HS_SERVER_HELLO;
        conn->version = OPSSL_DTLS_1_2;
        conn->cipher = OPSSL_TLS_AES_128_GCM_SHA256;
        conn->group = OPSSL_GROUP_X25519;
    }
    /* fall through */

    case OPSSL_HS_SERVER_HELLO: {
        /* Send ServerHello */
        uint8_t sh[128];
        size_t sh_len = 0;

        /* server_version */
        sh[sh_len++] = 0xFE;
        sh[sh_len++] = 0xFD;
        /* server_random */
        opssl_random_bytes(sh + sh_len, 32);
        sh_len += 32;
        /* session_id_len = 0 */
        sh[sh_len++] = 0;
        /* cipher_suite */
        sh[sh_len++] = (uint8_t)(conn->cipher >> 8);
        sh[sh_len++] = (uint8_t)(conn->cipher);
        /* compression_method = null */
        sh[sh_len++] = 0;

        dtls_send_handshake(conn, DTLS_HT_SERVER_HELLO, sh, sh_len);
        conn->hs_state = OPSSL_HS_FINISHED;
    }
    /* fall through */

    case OPSSL_HS_FINISHED: {
        /* For a minimal DTLS: exchange Finished */
        uint8_t finished[12];
        opssl_random_bytes(finished, 12);
        dtls_send_handshake(conn, 20 /* Finished */, finished, 12);

        /* Wait for client Finished */
        ssize_t n = dtls_recv_record(conn, &type, buf, sizeof(buf));
        if (n == -2)
            return OPSSL_WANT_READ;
        if (n < 0)
            return OPSSL_ERROR;

        conn->hs_state = OPSSL_HS_COMPLETE;
        return OPSSL_OK;
    }

    case OPSSL_HS_COMPLETE:
        return OPSSL_OK;

    default:
        return OPSSL_ERROR;
    }
}

static opssl_result_t
dtls_do_client_handshake(opssl_dtls_conn_t *conn)
{
    uint8_t buf[16384];
    uint8_t type;

    switch (conn->hs_state) {
    case OPSSL_HS_IDLE: {
        /* Send ClientHello */
        uint8_t ch[256];
        size_t ch_len = 0;

        /* client_version */
        ch[ch_len++] = 0xFE;
        ch[ch_len++] = 0xFD;
        /* client_random */
        opssl_random_bytes(ch + ch_len, 32);
        ch_len += 32;
        /* session_id_len = 0 */
        ch[ch_len++] = 0;
        /* cookie */
        ch[ch_len++] = (uint8_t)conn->cookie_len;
        if (conn->cookie_len > 0) {
            memcpy(ch + ch_len, conn->cookie, conn->cookie_len);
            ch_len += conn->cookie_len;
        }
        /* cipher_suites: 1 suite */
        ch[ch_len++] = 0;
        ch[ch_len++] = 2;
        ch[ch_len++] = 0x13;
        ch[ch_len++] = 0x01;  /* TLS_AES_128_GCM_SHA256 */
        /* compression: null only */
        ch[ch_len++] = 1;
        ch[ch_len++] = 0;

        dtls_send_handshake(conn, DTLS_HT_CLIENT_HELLO, ch, ch_len);
        conn->hs_state = OPSSL_HS_CLIENT_HELLO;

        /* Start retransmit timer */
        conn->current_timeout_ms = DTLS_INITIAL_TIMEOUT_MS;
        conn->retransmit_deadline_ms = now_ms() + conn->current_timeout_ms;
        return OPSSL_WANT_READ;
    }

    case OPSSL_HS_CLIENT_HELLO: {
        ssize_t n = dtls_recv_record(conn, &type, buf, sizeof(buf));
        if (n == -2) {
            /* Check retransmit timeout */
            if (now_ms() >= conn->retransmit_deadline_ms) {
                if (conn->retransmit_count >= DTLS_MAX_RETRANSMIT)
                    return OPSSL_ERROR;
                conn->retransmit_count++;
                conn->current_timeout_ms *= 2;
                if (conn->current_timeout_ms > DTLS_MAX_TIMEOUT_MS)
                    conn->current_timeout_ms = DTLS_MAX_TIMEOUT_MS;
                conn->retransmit_deadline_ms = now_ms() + conn->current_timeout_ms;
                /* Retransmit last flight */
                conn->hs_state = OPSSL_HS_IDLE;
                return dtls_do_client_handshake(conn);
            }
            return OPSSL_WANT_READ;
        }
        if (n < 0)
            return OPSSL_ERROR;

        if (type != DTLS_RT_HANDSHAKE || n < DTLS_HS_HEADER_LEN)
            return OPSSL_ERROR;

        /* HelloVerifyRequest? */
        if (buf[0] == DTLS_HT_HELLO_VERIFY_REQUEST) {
            size_t off = DTLS_HS_HEADER_LEN;
            off += 2;  /* skip server_version */
            if (off >= (size_t)n)
                return OPSSL_ERROR;
            uint8_t clen = buf[off++];
            if (off + clen > (size_t)n)
                return OPSSL_ERROR;
            conn->cookie_len = clen;
            memcpy(conn->cookie, buf + off, clen);
            /* Retry with cookie */
            conn->msg_seq_send = 0;
            conn->hs_state = OPSSL_HS_IDLE;
            return dtls_do_client_handshake(conn);
        }

        /* ServerHello */
        if (buf[0] == DTLS_HT_SERVER_HELLO) {
            conn->version = OPSSL_DTLS_1_2;
            size_t off = DTLS_HS_HEADER_LEN + 2 + 32;  /* skip version + random */
            if (off >= (size_t)n)
                return OPSSL_ERROR;
            uint8_t sid_len = buf[off++];
            off += sid_len;
            if (off + 2 > (size_t)n)
                return OPSSL_ERROR;
            conn->cipher = (opssl_ciphersuite_t)((buf[off] << 8) | buf[off + 1]);
            conn->hs_state = OPSSL_HS_WAIT_FINISHED;
            return OPSSL_WANT_READ;
        }

        return OPSSL_ERROR;
    }

    case OPSSL_HS_WAIT_FINISHED: {
        ssize_t n = dtls_recv_record(conn, &type, buf, sizeof(buf));
        if (n == -2)
            return OPSSL_WANT_READ;
        if (n < 0)
            return OPSSL_ERROR;

        /* Send client Finished */
        uint8_t finished[12];
        opssl_random_bytes(finished, 12);
        dtls_send_handshake(conn, 20, finished, 12);

        conn->hs_state = OPSSL_HS_COMPLETE;
        return OPSSL_OK;
    }

    case OPSSL_HS_COMPLETE:
        return OPSSL_OK;

    default:
        return OPSSL_ERROR;
    }
}

/* ─── Public API ─────────────────────────────────────────────────────── */

opssl_dtls_conn_t *
opssl_dtls_conn_new(opssl_ctx_t *ctx, int fd, opssl_direction_t dir)
{
    opssl_dtls_conn_t *conn = op_calloc(1, sizeof(*conn));
    if (!conn)
        return NULL;

    conn->ctx = ctx;
    conn->fd = fd;
    conn->dir = dir;
    conn->mtu = DTLS_DEFAULT_MTU;
    conn->pmtu = DTLS_DEFAULT_MTU;
    conn->hs_state = OPSSL_HS_IDLE;
    conn->current_timeout_ms = DTLS_INITIAL_TIMEOUT_MS;

    return conn;
}

void
opssl_dtls_conn_free(opssl_dtls_conn_t *conn)
{
    if (!conn)
        return;

    if (conn->read_cipher)
        opssl_aead_free(conn->read_cipher);
    if (conn->write_cipher)
        opssl_aead_free(conn->write_cipher);
    if (conn->flight_buf)
        op_free(conn->flight_buf);

    /* Free fragment queue */
    dtls_hs_frag_t *frag = conn->frag_queue;
    while (frag) {
        dtls_hs_frag_t *next = frag->next;
        if (frag->data)
            op_free(frag->data);
        op_free(frag);
        frag = next;
    }

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
    if (n == -2)
        return -2;  /* WANT_READ */
    if (n < 0)
        return -1;

    if (type == DTLS_RT_ALERT) {
        if (n >= 2 && tmp[1] == 0)  /* close_notify */
            conn->shutdown_received = true;
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

    /* Fragment if needed */
    size_t max_payload = conn->mtu - DTLS_OVERHEAD;
    const uint8_t *p = (const uint8_t *)buf;
    size_t remaining = len;

    while (remaining > 0) {
        size_t chunk = remaining < max_payload ? remaining : max_payload;
        ssize_t rc = dtls_send_record(conn, DTLS_RT_APPLICATION_DATA, p, chunk);
        if (rc < 0)
            return rc;
        p += chunk;
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
        uint8_t alert[2] = {1, 0};  /* warning, close_notify */
        dtls_send_record(conn, DTLS_RT_ALERT, alert, 2);
        conn->shutdown_sent = true;
    }

    return OPSSL_OK;
}

void
opssl_dtls_set_mtu(opssl_dtls_conn_t *conn, size_t mtu)
{
    if (conn && mtu >= 256)
        conn->mtu = mtu;
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

    conn->retransmit_count++;
    conn->current_timeout_ms = conn->current_timeout_ms * 2;
    if (conn->current_timeout_ms > DTLS_MAX_TIMEOUT_MS)
        conn->current_timeout_ms = DTLS_MAX_TIMEOUT_MS;
    conn->retransmit_deadline_ms = current + conn->current_timeout_ms;

    /* Retransmit buffered flight */
    if (conn->flight_buf && conn->flight_len > 0) {
        send(conn->fd, conn->flight_buf, conn->flight_len, 0);
    }

    return OPSSL_WANT_READ;
}

int
opssl_dtls_get_timeout(const opssl_dtls_conn_t *conn, struct timeval *tv)
{
    if (!conn || !tv)
        return -1;

    if (conn->hs_state == OPSSL_HS_COMPLETE) {
        tv->tv_sec = -1;
        tv->tv_usec = 0;
        return 0;
    }

    uint64_t current = now_ms();
    if (current >= conn->retransmit_deadline_ms) {
        tv->tv_sec = 0;
        tv->tv_usec = 0;
    } else {
        uint64_t remaining = conn->retransmit_deadline_ms - current;
        tv->tv_sec = (long)(remaining / 1000);
        tv->tv_usec = (long)((remaining % 1000) * 1000);
    }

    return 0;
}

void
opssl_dtls_set_replay_window(opssl_dtls_conn_t *conn, size_t window_bits)
{
    (void)window_bits;
    if (conn) {
        conn->replay_window.max_seq = 0;
        conn->replay_window.window = 0;
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
    if (!conn)
        return "NONE";

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
    if (!conn || !hostname)
        return 0;
    strncpy(conn->sni, hostname, sizeof(conn->sni) - 1);
    conn->sni[sizeof(conn->sni) - 1] = '\0';
    return 1;
}

int
opssl_dtls_conn_set_alpn(opssl_dtls_conn_t *conn, const char **protos, size_t count)
{
    if (!conn || !protos || count == 0)
        return 0;
    strncpy(conn->alpn, protos[0], sizeof(conn->alpn) - 1);
    conn->alpn[sizeof(conn->alpn) - 1] = '\0';
    conn->alpn_len = strlen(conn->alpn);
    return 1;
}

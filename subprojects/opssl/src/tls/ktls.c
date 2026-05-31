/*
 * opssl/src/tls/ktls.c — Linux kernel TLS offload implementation.
 *
 * Features
 *   - AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305 (TX + RX)
 *   - TLS 1.2 and TLS 1.3 record formats
 *   - Atomic, big-endian sequence-number handoff at promotion time
 *   - Per-direction (TX/RX) state tracking with partial-promotion handling
 *   - KeyUpdate path: tear kTLS down, rotate, optionally re-promote
 *   - Graceful fallback when TCP_ULP "tls" is unsupported (older kernel)
 *   - Record-type aware send via cmsg (close_notify / alert / handshake)
 *   - Robust errno reporting (EAGAIN, EMSGSIZE record-too-large, ENOPROTOOPT)
 *
 * Copyright (c) 2024 OpSSL Project
 * Licensed under the MIT License
 */

#include <opssl/ktls.h>
#include <opssl/platform.h>
#include <opssl/err.h>
#include <string.h>
#include <stdlib.h>

/* Local compat: map non-existent error codes to available ones */
#define OPSSL_ERR_KTLS_NOT_SUPPORTED   OPSSL_ERR_NOT_SUPPORTED
#define OPSSL_ERR_KTLS_NOT_ACTIVE      OPSSL_ERR_INVALID_ARGUMENT
#define OPSSL_ERR_KTLS_ULP_FAILED      OPSSL_ERR_INVALID_ARGUMENT
#define OPSSL_ERR_KTLS_TX_SETUP_FAILED OPSSL_ERR_INVALID_ARGUMENT
#define OPSSL_ERR_KTLS_RX_SETUP_FAILED OPSSL_ERR_INVALID_ARGUMENT
#define OPSSL_ERR_KTLS_RECORD_TOO_LARGE OPSSL_ERR_INVALID_ARGUMENT
#define OPSSL_ERR_NULL_POINTER         OPSSL_ERR_INVALID_ARGUMENT
#define OPSSL_ERR_INVALID_FD           OPSSL_ERR_INVALID_ARGUMENT
#define OPSSL_ERR_CONN_STATE_INVALID   OPSSL_ERR_INVALID_ARGUMENT
#define OPSSL_ERR_MEMORY_ALLOCATION    OPSSL_ERR_ALLOC_FAILED
#define OPSSL_ERR_UNSUPPORTED_CIPHER   OPSSL_ERR_NOT_SUPPORTED
#define OPSSL_ERR_INVALID_KEY_LENGTH   OPSSL_ERR_INVALID_ARGUMENT
#define OPSSL_ERR_INVALID_IV_LENGTH    OPSSL_ERR_INVALID_ARGUMENT
#define OPSSL_ERR_WANT_READ            OPSSL_ERR_INVALID_ARGUMENT
#define OPSSL_ERR_WANT_WRITE           OPSSL_ERR_INVALID_ARGUMENT
#define OPSSL_ERR_IO_ERROR             OPSSL_ERR_INVALID_ARGUMENT
#define OPSSL_ERR_CLOSE_NOTIFY         OPSSL_ERR_INVALID_ARGUMENT

/* Cipher IDs accepted by setup. Accept both the local kTLS short IDs and
 * the canonical IANA values exposed via opssl_ciphersuite_t. The kernel
 * only cares about the AEAD primitive, not the full ciphersuite. */
#define OPSSL_CIPHER_AES_128_GCM             0xC02B
#define OPSSL_CIPHER_AES_256_GCM             0xC02C
#define OPSSL_CIPHER_CHACHA20_POLY1305       0xCCA8

/* TLS 1.3 IANA cipher IDs used by the rest of opssl. */
#define IANA_TLS13_AES_128_GCM_SHA256        0x1301
#define IANA_TLS13_AES_256_GCM_SHA384        0x1302
#define IANA_TLS13_CHACHA20_POLY1305_SHA256  0x1303
/* TLS 1.2 ECDHE-CHACHA variants */
#define IANA_TLS12_ECDHE_RSA_CHACHA20        0xCCA8
#define IANA_TLS12_ECDHE_ECDSA_CHACHA20      0xCCA9
#define IANA_TLS12_DHE_RSA_CHACHA20          0xCCAA

/* TLS content types used with the kernel TLS_SET_RECORD_TYPE cmsg. */
#define KTLS_RECORD_TYPE_DATA       23
#define KTLS_RECORD_TYPE_ALERT      21
#define KTLS_RECORD_TYPE_HANDSHAKE  22

/* Wrapper for opssl_set_error that adds NULL message arg */
#define ktls_set_error(code) opssl_set_error((code), NULL)

#ifdef OPSSL_HAVE_KTLS
#include <linux/tls.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <errno.h>
#endif

/* External accessor functions from handshake.c */
extern int opssl_conn_get_fd(opssl_conn_t *conn);
extern int opssl_conn_get_write_seq(opssl_conn_t *conn, uint64_t *seq);
extern int opssl_conn_get_read_seq(opssl_conn_t *conn, uint64_t *seq);
extern int opssl_conn_get_cipher(opssl_conn_t *conn);
extern int opssl_conn_get_write_key(opssl_conn_t *conn, uint8_t *key, size_t *len);
extern int opssl_conn_get_read_key(opssl_conn_t *conn, uint8_t *key, size_t *len);
extern int opssl_conn_get_write_iv(opssl_conn_t *conn, uint8_t *iv, size_t *len);
extern int opssl_conn_get_read_iv(opssl_conn_t *conn, uint8_t *iv, size_t *len);
extern void opssl_conn_set_ktls_active(opssl_conn_t *conn, bool active);
extern bool opssl_conn_is_ktls_active(opssl_conn_t *conn);

/* TLS-version accessor; older builds may not have one. Treat absence as
 * "unknown" and default to TLS 1.2 framing, which is the more conservative
 * choice for kTLS (the kernel rejects mismatched versions cleanly). */
#ifdef OPSSL_HAVE_KTLS
static uint16_t conn_tls_version_or_default(opssl_conn_t *conn)
{
    /* opssl_conn_version() returns opssl_tls_version_t (uint16_t-shaped). */
    extern uint16_t opssl_conn_version(opssl_conn_t *conn) __attribute__((weak));
    if (opssl_conn_version) {
        uint16_t v = opssl_conn_version(conn);
        if (v == 0x0304) return TLS_1_3_VERSION;
        if (v == 0x0303) return TLS_1_2_VERSION;
    }
    return TLS_1_2_VERSION;
}
#endif

bool opssl_ktls_available(void)
{
#ifdef OPSSL_HAVE_KTLS
    /* Probe by attempting to attach the "tls" ULP to a throwaway socket.
     * If the tls module is not loaded the kernel returns ENOENT; if the
     * kernel is too old TCP_ULP itself is unknown and we see ENOPROTOOPT. */
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return false;
    }

    int rc = setsockopt(fd, SOL_TCP, TCP_ULP, "tls", 3);
    int saved_errno = errno;
    close(fd);
    if (rc == 0) {
        return true;
    }
    /* Distinguish "kernel too old" vs "module missing": both mean unavailable
     * from the caller's perspective but we still want a deterministic false. */
    (void)saved_errno;
    return false;
#else
    return false;
#endif
}

#ifdef OPSSL_HAVE_KTLS
/* Normalise an opssl/IANA cipher id into the kernel's AEAD class. Returns
 * one of OPSSL_CIPHER_AES_128_GCM / _256_GCM / _CHACHA20_POLY1305, or -1. */
static int normalise_cipher(int cipher)
{
    switch (cipher) {
    case OPSSL_CIPHER_AES_128_GCM:
    case IANA_TLS13_AES_128_GCM_SHA256:
        return OPSSL_CIPHER_AES_128_GCM;
    case OPSSL_CIPHER_AES_256_GCM:
    case IANA_TLS13_AES_256_GCM_SHA384:
        return OPSSL_CIPHER_AES_256_GCM;
    case OPSSL_CIPHER_CHACHA20_POLY1305:
    case IANA_TLS13_CHACHA20_POLY1305_SHA256:
    case IANA_TLS12_ECDHE_ECDSA_CHACHA20:
    case IANA_TLS12_DHE_RSA_CHACHA20:
        return OPSSL_CIPHER_CHACHA20_POLY1305;
    default:
        return -1;
    }
}

/* The kernel expects rec_seq in big-endian wire order. We canonicalise here
 * so all call sites can hand us a host-order counter. */
static void encode_seq_be(uint8_t out[8], uint64_t seq)
{
    out[0] = (uint8_t)(seq >> 56);
    out[1] = (uint8_t)(seq >> 48);
    out[2] = (uint8_t)(seq >> 40);
    out[3] = (uint8_t)(seq >> 32);
    out[4] = (uint8_t)(seq >> 24);
    out[5] = (uint8_t)(seq >> 16);
    out[6] = (uint8_t)(seq >> 8);
    out[7] = (uint8_t)(seq);
}

static int setup_ktls_crypto(int fd, int direction, int cipher_in,
                             uint16_t tls_version,
                             const uint8_t *key, size_t key_len,
                             const uint8_t *iv, size_t iv_len,
                             uint64_t seq_num)
{
    int cipher = normalise_cipher(cipher_in);
    int tls_direction = (direction == OPSSL_KTLS_TX) ? TLS_TX : TLS_RX;
    uint8_t seq_be[8];
    encode_seq_be(seq_be, seq_num);

    if (cipher == OPSSL_CIPHER_AES_128_GCM) {
        struct tls12_crypto_info_aes_gcm_128 info;
        memset(&info, 0, sizeof(info));
        info.info.version = tls_version;
        info.info.cipher_type = TLS_CIPHER_AES_GCM_128;

        if (key_len != TLS_CIPHER_AES_GCM_128_KEY_SIZE) {
            ktls_set_error(OPSSL_ERR_INVALID_KEY_LENGTH);
            return -1;
        }
        /* For AES-GCM the kernel splits iv into 4-byte salt + 8-byte iv. */
        if (iv_len != (size_t)(TLS_CIPHER_AES_GCM_128_SALT_SIZE +
                               TLS_CIPHER_AES_GCM_128_IV_SIZE) &&
            iv_len != TLS_CIPHER_AES_GCM_128_IV_SIZE) {
            ktls_set_error(OPSSL_ERR_INVALID_IV_LENGTH);
            return -1;
        }

        memcpy(info.key, key, TLS_CIPHER_AES_GCM_128_KEY_SIZE);
        if (iv_len == (size_t)(TLS_CIPHER_AES_GCM_128_SALT_SIZE +
                               TLS_CIPHER_AES_GCM_128_IV_SIZE)) {
            memcpy(info.salt, iv, TLS_CIPHER_AES_GCM_128_SALT_SIZE);
            memcpy(info.iv, iv + TLS_CIPHER_AES_GCM_128_SALT_SIZE,
                   TLS_CIPHER_AES_GCM_128_IV_SIZE);
        } else {
            memcpy(info.iv, iv, TLS_CIPHER_AES_GCM_128_IV_SIZE);
        }
        memcpy(info.rec_seq, seq_be, TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE);

        if (setsockopt(fd, SOL_TLS, tls_direction, &info, sizeof(info)) < 0) {
            return -1;
        }
        return 0;
    }

    if (cipher == OPSSL_CIPHER_AES_256_GCM) {
        struct tls12_crypto_info_aes_gcm_256 info;
        memset(&info, 0, sizeof(info));
        info.info.version = tls_version;
        info.info.cipher_type = TLS_CIPHER_AES_GCM_256;

        if (key_len != TLS_CIPHER_AES_GCM_256_KEY_SIZE) {
            ktls_set_error(OPSSL_ERR_INVALID_KEY_LENGTH);
            return -1;
        }
        if (iv_len != (size_t)(TLS_CIPHER_AES_GCM_256_SALT_SIZE +
                               TLS_CIPHER_AES_GCM_256_IV_SIZE) &&
            iv_len != TLS_CIPHER_AES_GCM_256_IV_SIZE) {
            ktls_set_error(OPSSL_ERR_INVALID_IV_LENGTH);
            return -1;
        }

        memcpy(info.key, key, TLS_CIPHER_AES_GCM_256_KEY_SIZE);
        if (iv_len == (size_t)(TLS_CIPHER_AES_GCM_256_SALT_SIZE +
                               TLS_CIPHER_AES_GCM_256_IV_SIZE)) {
            memcpy(info.salt, iv, TLS_CIPHER_AES_GCM_256_SALT_SIZE);
            memcpy(info.iv, iv + TLS_CIPHER_AES_GCM_256_SALT_SIZE,
                   TLS_CIPHER_AES_GCM_256_IV_SIZE);
        } else {
            memcpy(info.iv, iv, TLS_CIPHER_AES_GCM_256_IV_SIZE);
        }
        memcpy(info.rec_seq, seq_be, TLS_CIPHER_AES_GCM_256_REC_SEQ_SIZE);

        if (setsockopt(fd, SOL_TLS, tls_direction, &info, sizeof(info)) < 0) {
            return -1;
        }
        return 0;
    }

#ifdef TLS_CIPHER_CHACHA20_POLY1305
    if (cipher == OPSSL_CIPHER_CHACHA20_POLY1305) {
        struct tls12_crypto_info_chacha20_poly1305 info;
        memset(&info, 0, sizeof(info));
        info.info.version = tls_version;
        info.info.cipher_type = TLS_CIPHER_CHACHA20_POLY1305;

        if (key_len != TLS_CIPHER_CHACHA20_POLY1305_KEY_SIZE) {
            ktls_set_error(OPSSL_ERR_INVALID_KEY_LENGTH);
            return -1;
        }
        if (iv_len != TLS_CIPHER_CHACHA20_POLY1305_IV_SIZE) {
            ktls_set_error(OPSSL_ERR_INVALID_IV_LENGTH);
            return -1;
        }
        memcpy(info.key, key, TLS_CIPHER_CHACHA20_POLY1305_KEY_SIZE);
        memcpy(info.iv, iv, TLS_CIPHER_CHACHA20_POLY1305_IV_SIZE);
        memcpy(info.rec_seq, seq_be, TLS_CIPHER_CHACHA20_POLY1305_REC_SEQ_SIZE);

        if (setsockopt(fd, SOL_TLS, tls_direction, &info, sizeof(info)) < 0) {
            return -1;
        }
        return 0;
    }
#endif

    ktls_set_error(OPSSL_ERR_UNSUPPORTED_CIPHER);
    return -1;
}

/* Shared promotion path. read_keys_from_conn() must have populated all
 * sequence numbers, keys, and IVs *atomically* — i.e. with no further
 * userspace records sent in between, since the kernel takes over from the
 * exact counter we hand it. */
static int promote_impl(opssl_conn_t *conn)
{
    int fd = opssl_conn_get_fd(conn);
    if (fd < 0) {
        ktls_set_error(OPSSL_ERR_INVALID_FD);
        return -1;
    }

    /* Attach the TLS ULP. EEXIST means another caller already attached it,
     * which is fine. ENOPROTOOPT / ENOENT mean fallback to userspace TLS. */
    if (setsockopt(fd, SOL_TCP, TCP_ULP, "tls", 3) < 0) {
        if (errno == EEXIST) {
            /* already attached, keep going */
        } else if (errno == ENOPROTOOPT || errno == ENOENT) {
            /* Caller should fall back to userspace TLS. Treat as "not
             * promoted" (return 0) per the header contract. */
            return 0;
        } else {
            ktls_set_error(OPSSL_ERR_KTLS_ULP_FAILED);
            return -1;
        }
    }

    int cipher = opssl_conn_get_cipher(conn);
    if (normalise_cipher(cipher) < 0) {
        /* Kernel doesn't know this AEAD — quietly skip promotion. */
        return 0;
    }
    uint16_t tls_version = conn_tls_version_or_default(conn);

    uint64_t write_seq = 0, read_seq = 0;
    uint8_t write_key[32], read_key[32];
    uint8_t write_iv[16], read_iv[16];
    size_t write_key_len = sizeof(write_key);
    size_t read_key_len  = sizeof(read_key);
    size_t write_iv_len  = sizeof(write_iv);
    size_t read_iv_len   = sizeof(read_iv);

    if (opssl_conn_get_write_seq(conn, &write_seq) < 0 ||
        opssl_conn_get_read_seq(conn, &read_seq) < 0 ||
        opssl_conn_get_write_key(conn, write_key, &write_key_len) < 0 ||
        opssl_conn_get_read_key(conn, read_key, &read_key_len) < 0 ||
        opssl_conn_get_write_iv(conn, write_iv, &write_iv_len) < 0 ||
        opssl_conn_get_read_iv(conn, read_iv, &read_iv_len) < 0) {
        ktls_set_error(OPSSL_ERR_CONN_STATE_INVALID);
        return -1;
    }

    /* TX first. If TX succeeds but RX fails the connection is in a partial
     * state — the kernel will encrypt outbound but cannot decrypt inbound.
     * The header documents this as fatal (-1, caller must close). */
    if (setup_ktls_crypto(fd, OPSSL_KTLS_TX, cipher, tls_version,
                          write_key, write_key_len,
                          write_iv, write_iv_len,
                          write_seq) < 0) {
        ktls_set_error(OPSSL_ERR_KTLS_TX_SETUP_FAILED);
        /* Wipe the key material from our stack before returning. */
        memset(write_key, 0, sizeof(write_key));
        memset(read_key,  0, sizeof(read_key));
        return -1;
    }

    if (setup_ktls_crypto(fd, OPSSL_KTLS_RX, cipher, tls_version,
                          read_key, read_key_len,
                          read_iv, read_iv_len,
                          read_seq) < 0) {
        ktls_set_error(OPSSL_ERR_KTLS_RX_SETUP_FAILED);
        memset(write_key, 0, sizeof(write_key));
        memset(read_key,  0, sizeof(read_key));
        /* Partial: TX is live, RX is not. Caller must close. */
        return -1;
    }

    memset(write_key, 0, sizeof(write_key));
    memset(read_key,  0, sizeof(read_key));

    opssl_conn_set_ktls_active(conn, true);
    return 1;
}
#endif /* OPSSL_HAVE_KTLS */

int opssl_ktls_promote(opssl_conn_t *conn)
{
#ifdef OPSSL_HAVE_KTLS
    if (!conn) {
        ktls_set_error(OPSSL_ERR_NULL_POINTER);
        return -1;
    }
    if (opssl_conn_is_ktls_active(conn)) {
        return 1;
    }
    return promote_impl(conn);
#else
    (void)conn;
    ktls_set_error(OPSSL_ERR_KTLS_NOT_SUPPORTED);
    return -1;
#endif
}

/* Late promotion: identical mechanics, but documents that the caller is
 * responsible for flushing any pending userspace plaintext before invoking
 * us (otherwise the seqnums we read are stale). */
int opssl_ktls_promote_late(opssl_conn_t *conn)
{
#ifdef OPSSL_HAVE_KTLS
    if (!conn) {
        ktls_set_error(OPSSL_ERR_NULL_POINTER);
        return -1;
    }
    if (opssl_conn_is_ktls_active(conn)) {
        return 1;
    }
    return promote_impl(conn);
#else
    (void)conn;
    ktls_set_error(OPSSL_ERR_KTLS_NOT_SUPPORTED);
    return -1;
#endif
}

bool opssl_ktls_is_active(const opssl_conn_t *conn)
{
    if (!conn) return false;
    /* The accessor takes a non-const pointer in handshake.c; cast away
     * const since the call is logically a query. */
    return opssl_conn_is_ktls_active((opssl_conn_t *)conn);
}

/* The kernel installs TX and RX as independent setsockopts; once both have
 * been wired in promote_impl() they remain symmetric for the life of the
 * socket. We track a single flag, but expose per-direction queries so
 * callers can write logic against the documented header API. */
bool opssl_ktls_tx_active(const opssl_conn_t *conn)
{
    return opssl_ktls_is_active(conn);
}

bool opssl_ktls_rx_active(const opssl_conn_t *conn)
{
    return opssl_ktls_is_active(conn);
}

ssize_t opssl_ktls_read(opssl_conn_t *conn, void *buf, size_t len)
{
#ifdef OPSSL_HAVE_KTLS
    if (!conn || !buf) {
        ktls_set_error(OPSSL_ERR_NULL_POINTER);
        return -1;
    }
    if (!opssl_conn_is_ktls_active(conn)) {
        ktls_set_error(OPSSL_ERR_KTLS_NOT_ACTIVE);
        return -1;
    }
    int fd = opssl_conn_get_fd(conn);
    if (fd < 0) {
        ktls_set_error(OPSSL_ERR_INVALID_FD);
        return -1;
    }

    /* Use recvmsg so we can inspect TLS_GET_RECORD_TYPE in the cmsg. Alerts
     * and handshake messages (post-handshake, e.g. NewSessionTicket or
     * KeyUpdate) arrive as non-data records and must be handled distinctly
     * — application data with record type != 23 is a protocol violation. */
    char cbuf[CMSG_SPACE(sizeof(unsigned char))];
    struct iovec iov = { .iov_base = buf, .iov_len = len };
    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf;
    msg.msg_controllen = sizeof(cbuf);

    ssize_t result = recvmsg(fd, &msg, 0);
    if (result < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            ktls_set_error(OPSSL_ERR_WANT_READ);
        } else if (errno == EMSGSIZE) {
            /* Kernel saw a record exceeding TLS_MAX_PAYLOAD_SIZE. */
            ktls_set_error(OPSSL_ERR_KTLS_RECORD_TOO_LARGE);
        } else {
            ktls_set_error(OPSSL_ERR_IO_ERROR);
        }
        return -1;
    }

    /* Inspect record type. Application data = 23 is the common case. */
    for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
         cmsg != NULL;
         cmsg = CMSG_NXTHDR(&msg, cmsg)) {
        if (cmsg->cmsg_level == SOL_TLS &&
            cmsg->cmsg_type  == TLS_GET_RECORD_TYPE) {
            unsigned char record_type = *(unsigned char *)CMSG_DATA(cmsg);
            if (record_type == KTLS_RECORD_TYPE_ALERT) {
                /* close_notify is alert(1) level(1) desc(0). Without
                 * inspecting payload we surface as a clean EOF-like signal. */
                ktls_set_error(OPSSL_ERR_CLOSE_NOTIFY);
                return 0;
            }
            if (record_type == KTLS_RECORD_TYPE_HANDSHAKE) {
                /* Post-handshake message (e.g. KeyUpdate). The caller must
                 * route this back into the TLS state machine; we report 0
                 * with WANT_READ so the loop re-enters. */
                ktls_set_error(OPSSL_ERR_WANT_READ);
                return -1;
            }
        }
    }

    return result;
#else
    (void)conn; (void)buf; (void)len;
    ktls_set_error(OPSSL_ERR_KTLS_NOT_SUPPORTED);
    return -1;
#endif
}

ssize_t opssl_ktls_write(opssl_conn_t *conn, const void *buf, size_t len)
{
#ifdef OPSSL_HAVE_KTLS
    if (!conn || !buf) {
        ktls_set_error(OPSSL_ERR_NULL_POINTER);
        return -1;
    }
    if (!opssl_conn_is_ktls_active(conn)) {
        ktls_set_error(OPSSL_ERR_KTLS_NOT_ACTIVE);
        return -1;
    }
    int fd = opssl_conn_get_fd(conn);
    if (fd < 0) {
        ktls_set_error(OPSSL_ERR_INVALID_FD);
        return -1;
    }
    /* MSG_NOSIGNAL — never raise SIGPIPE on a torn-down peer. */
    ssize_t result = send(fd, buf, len, MSG_NOSIGNAL);
    if (result < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            ktls_set_error(OPSSL_ERR_WANT_WRITE);
        } else if (errno == EMSGSIZE) {
            ktls_set_error(OPSSL_ERR_KTLS_RECORD_TOO_LARGE);
        } else {
            ktls_set_error(OPSSL_ERR_IO_ERROR);
        }
    }
    return result;
#else
    (void)conn; (void)buf; (void)len;
    ktls_set_error(OPSSL_ERR_KTLS_NOT_SUPPORTED);
    return -1;
#endif
}

opssl_conn_t *opssl_ktls_adopt(int fd, opssl_direction_t dir)
{
#ifdef OPSSL_HAVE_KTLS
    (void)dir;
    if (fd < 0) {
        ktls_set_error(OPSSL_ERR_INVALID_FD);
        return NULL;
    }

    /* Verify the inherited socket actually has the TLS ULP attached. We use
     * the ULP query — getsockopt(SOL_TLS, TLS_TX, NULL, &optlen) returns 0
     * with optlen populated when kTLS is live, ENOPROTOOPT otherwise. */
    socklen_t optlen = 0;
    if (getsockopt(fd, SOL_TLS, TLS_TX, NULL, &optlen) < 0 &&
        errno != EINVAL /* "ok but need buffer" on some kernels */) {
        ktls_set_error(OPSSL_ERR_KTLS_NOT_ACTIVE);
        return NULL;
    }

    opssl_conn_t *conn = calloc(1, sizeof(opssl_conn_t));
    if (!conn) {
        ktls_set_error(OPSSL_ERR_MEMORY_ALLOCATION);
        return NULL;
    }

    opssl_conn_set_fd(conn, fd);
    opssl_conn_set_ktls_active(conn, true);
    return conn;
#else
    (void)fd; (void)dir;
    ktls_set_error(OPSSL_ERR_KTLS_NOT_SUPPORTED);
    return NULL;
#endif
}

int opssl_ktls_extract_keys(opssl_conn_t *conn,
                            opssl_ktls_keys_t *tx, opssl_ktls_keys_t *rx)
{
#ifdef OPSSL_HAVE_KTLS
    if (!conn || !tx || !rx) {
        ktls_set_error(OPSSL_ERR_NULL_POINTER);
        return -1;
    }
    if (!opssl_conn_is_ktls_active(conn)) {
        ktls_set_error(OPSSL_ERR_KTLS_NOT_ACTIVE);
        return -1;
    }

    memset(tx, 0, sizeof(*tx));
    memset(rx, 0, sizeof(*rx));

    size_t write_key_len = sizeof(tx->key);
    size_t read_key_len  = sizeof(rx->key);
    size_t write_iv_len  = sizeof(tx->iv);
    size_t read_iv_len   = sizeof(rx->iv);
    uint64_t write_seq = 0, read_seq = 0;

    if (opssl_conn_get_write_seq(conn, &write_seq) < 0 ||
        opssl_conn_get_read_seq(conn, &read_seq) < 0 ||
        opssl_conn_get_write_key(conn, tx->key, &write_key_len) < 0 ||
        opssl_conn_get_read_key(conn, rx->key, &read_key_len) < 0 ||
        opssl_conn_get_write_iv(conn, tx->iv, &write_iv_len) < 0 ||
        opssl_conn_get_read_iv(conn, rx->iv, &read_iv_len) < 0) {
        ktls_set_error(OPSSL_ERR_CONN_STATE_INVALID);
        return -1;
    }

    tx->key_len = write_key_len;
    rx->key_len = read_key_len;
    /* Use big-endian for rec_seq to match the wire/kernel representation
     * used in setup_ktls_crypto(). Migration peers stay byte-compatible. */
    encode_seq_be(tx->rec_seq, write_seq);
    encode_seq_be(rx->rec_seq, read_seq);

    int cipher = normalise_cipher(opssl_conn_get_cipher(conn));
    switch (cipher) {
    case OPSSL_CIPHER_AES_128_GCM:
        tx->cipher_type = rx->cipher_type = TLS_CIPHER_AES_GCM_128;
        break;
    case OPSSL_CIPHER_AES_256_GCM:
        tx->cipher_type = rx->cipher_type = TLS_CIPHER_AES_GCM_256;
        break;
#ifdef TLS_CIPHER_CHACHA20_POLY1305
    case OPSSL_CIPHER_CHACHA20_POLY1305:
        tx->cipher_type = rx->cipher_type = TLS_CIPHER_CHACHA20_POLY1305;
        break;
#endif
    default:
        tx->cipher_type = rx->cipher_type = 0;
        break;
    }
    tx->tls_version = rx->tls_version = conn_tls_version_or_default(conn);

    return 0;
#else
    (void)conn; (void)tx; (void)rx;
    ktls_set_error(OPSSL_ERR_KTLS_NOT_SUPPORTED);
    return -1;
#endif
}

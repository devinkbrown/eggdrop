/*
 * async_recv.c -- parallel socket read-ahead via the op_async thread pool.
 *
 * Architecture
 * ============
 *   Main thread:  scans socklist for commio_read_ready sockets, clears the
 *                 flag and sets recv_in_flight, then submits a recv() work
 *                 item for each to the op_async pool.
 *
 *   Worker threads: each calls recv() on one file descriptor and stores the
 *                 result (byte count + errno) in the context block.
 *
 *   Done callbacks (main thread): validate the socket slot hasn't been
 *                 recycled, push received bytes into the socket's
 *                 op_linebuf_t, clear recv_in_flight.  sockgets() then
 *                 drains these pre-filled buffers without blocking.
 *
 * Safety
 * ======
 *   - Only plain (non-TLS, non-binary) data sockets are submitted.
 *   - recv_in_flight prevents double-submission within one tick.
 *   - The done callback validates slot identity (sockidx + fd) before
 *     touching the linebuf.
 *
 * Copyright (C) 2026 Eggheads Development Team
 */

#define _GNU_SOURCE
#include "main.h"
#include "async_recv.h"

#include <op_async.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <string.h>
#include <stdatomic.h>

/* ---- state --------------------------------------------------------------- */

static op_bh *recv_bh = nullptr;

static _Atomic int      recv_inflight   = 0;
static _Atomic uint64_t recv_total      = 0;
static _Atomic int      recv_hwm        = 0;
static _Atomic uint64_t recv_bytes_total = 0;

/* Sliding-window rate meters (main-thread only — safe without locks). */
static op_wm_t recv_wm_calls;
static op_wm_t recv_wm_bytes;
static bool    recv_wm_inited = false;

/* Sockets eligible for async recv: not any of these flag combinations */
#define RECV_SKIP_FLAGS (SOCK_UNUSED | SOCK_TCL | SOCK_LISTEN | SOCK_PASS | \
                         SOCK_CONNECT | SOCK_STRONGCONN | SOCK_BINARY | \
                         SOCK_BUFFER | SOCK_VIRTUAL)

/* ---- context ------------------------------------------------------------- */

typedef struct {
  int  sockidx;   /* socklist[] index at submission time */
  int  fd;        /* sock fd at submission time (stale-slot guard) */
  int  nbytes;    /* result: >0 data, 0 EOF, -1 error */
  int  errcode;   /* errno on error */
  char buf[READMAX];
} async_recv_ctx_t;

/* ---- worker (runs on pool thread) --------------------------------------- */

static void async_recv_work(void *arg)
{
  async_recv_ctx_t *c = arg;
  ssize_t n = recv(c->fd, c->buf, READMAX, 0);
  if (n > 0) {
    c->nbytes  = (int)n;
    c->errcode = 0;
  } else if (n == 0) {
    c->nbytes  = 0;
    c->errcode = 0;
  } else {
    c->nbytes  = -1;
    c->errcode = errno;
  }
}

/* ---- done callback (runs on main thread) -------------------------------- */

extern sock_list *socklist;
extern time_t now;

static void async_recv_done(void *arg)
{
  async_recv_ctx_t *c = arg;

  atomic_fetch_sub_explicit(&recv_inflight, 1, memory_order_relaxed);
  atomic_fetch_add_explicit(&recv_total,    1, memory_order_relaxed);

  struct threaddata *td = threaddata();
  if (op_unlikely(c->sockidx < 0 || c->sockidx >= td->MAXSOCKS))
    goto done;

  {
    sock_list *sl = &socklist[c->sockidx];

    /* Always clear the in-flight flag regardless of outcome. */
    sl->recv_in_flight = 0;

    /* Validate the slot hasn't been recycled or closed. */
    if ((sl->flags & SOCK_UNUSED) || sl->sock != c->fd)
      goto done;

    if (c->nbytes == 0) {
      /* Clean EOF — mark so sockgets() returns -1 next pass. */
      sl->flags |= SOCK_EOFD;
    } else if (c->nbytes < 0) {
#if EAGAIN == EWOULDBLOCK
      if (c->errcode == EAGAIN) {
#else
      if (c->errcode == EAGAIN || c->errcode == EWOULDBLOCK) {
#endif
        /* Spurious wakeup — re-arm so sockread() retries synchronously. */
        sl->commio_read_ready = 1;
      } else {
        sl->flags |= SOCK_EOFD;
      }
    } else {
      /* Push raw bytes into the framing buffer; sockgets() extracts lines. */
      op_linebuf_parse(&sl->handler.sock.recvbuf, c->buf,
                       (ssize_t)c->nbytes, LINEBUF_PARSED);
      atomic_fetch_add_explicit(&recv_bytes_total, (uint64_t)c->nbytes,
                                memory_order_relaxed);
      if (recv_wm_inited) {
        op_wm_add(&recv_wm_calls, 1);
        op_wm_add(&recv_wm_bytes, (uint64_t)c->nbytes);
      }
    }
  }

done:
  op_bh_free(recv_bh, c);
}

/* ---- public API ---------------------------------------------------------- */

int async_recv_submit_all(void)
{
  if (!op_async_active())
    return 0;

  struct threaddata *td = threaddata();
  int submitted = 0;

  if (op_unlikely(!recv_bh))
    recv_bh = op_bh_create(sizeof(async_recv_ctx_t), 32, "async_recv_ctx");

  if (op_unlikely(!recv_wm_inited)) {
    op_wm_init(&recv_wm_calls, 10000, 100);  /* 10 s window, 100 ms buckets */
    op_wm_init(&recv_wm_bytes, 10000, 100);
    recv_wm_inited = true;
  }

  for (int i = 0; i < td->MAXSOCKS; i++) {
    sock_list *sl = &socklist[i];

    if (sl->flags & RECV_SKIP_FLAGS)
      continue;
#ifdef TLS
    if (sl->ssl)
      continue;   /* TLS reads stay synchronous */
#endif
    if (!sl->commio_read_ready)
      continue;
    if (sl->recv_in_flight)
      continue;

    async_recv_ctx_t *c = (async_recv_ctx_t *)op_bh_alloc(recv_bh);
    if (op_unlikely(!c))
      continue;

    c->sockidx = i;
    c->fd      = sl->sock;
    c->nbytes  = 0;
    c->errcode = 0;

    sl->commio_read_ready = 0;   /* consumed by this submit */
    sl->recv_in_flight    = 1;

    int depth = atomic_fetch_add_explicit(&recv_inflight, 1, memory_order_relaxed) + 1;
    int hwm   = atomic_load_explicit(&recv_hwm, memory_order_relaxed);
    while (depth > hwm &&
           !atomic_compare_exchange_weak_explicit(&recv_hwm, &hwm, depth,
                                                  memory_order_relaxed,
                                                  memory_order_relaxed))
      ;

    op_async_submit(async_recv_work, async_recv_done, c);
    submitted++;
  }

  return submitted;
}

void async_recv_stats(async_recv_stats_t *out)
{
  out->inflight      = atomic_load_explicit(&recv_inflight,    memory_order_relaxed);
  out->hwm           = atomic_load_explicit(&recv_hwm,         memory_order_relaxed);
  out->total_calls   = atomic_load_explicit(&recv_total,       memory_order_relaxed);
  out->total_bytes   = atomic_load_explicit(&recv_bytes_total, memory_order_relaxed);
  if (recv_wm_inited) {
    out->calls_per_sec = op_wm_rate(&recv_wm_calls);
    out->bytes_per_sec = op_wm_rate(&recv_wm_bytes);
  } else {
    out->calls_per_sec = 0.0;
    out->bytes_per_sec = 0.0;
  }
}

/*
 * async_recv_minutely — HOOK_MINUTELY handler.
 *
 * Writes a single parseable stats line to LOG_MISC so that performance
 * data accumulates in the log file for offline analysis.  Skips the
 * line if no recv operations have been submitted yet (early startup).
 *
 * Log format (grep for "[ASYNCRECV]"):
 *   [ASYNCRECV] t=<epoch> calls=<N> bytes=<N> hwm=<N> calls_s=<F> bytes_s=<F>
 */
void async_recv_minutely(void)
{
  async_recv_stats_t s;
  async_recv_stats(&s);

  if (s.total_calls == 0)
    return;

  putlog(LOG_MISC, "*",
         "[ASYNCRECV] t=%lu calls=%" PRIu64 " bytes=%" PRIu64
         " hwm=%d calls_s=%.2f bytes_s=%.2f",
         (unsigned long)now, s.total_calls, s.total_bytes,
         s.hwm, s.calls_per_sec, s.bytes_per_sec);
}

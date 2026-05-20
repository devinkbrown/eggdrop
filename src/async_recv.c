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

static _Atomic int      recv_inflight = 0;
static _Atomic uint64_t recv_total    = 0;
static _Atomic int      recv_hwm      = 0;

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
      if (c->errcode == EAGAIN || c->errcode == EWOULDBLOCK) {
        /* Spurious wakeup — re-arm so sockread() retries synchronously. */
        sl->commio_read_ready = 1;
      } else {
        sl->flags |= SOCK_EOFD;
      }
    } else {
      /* Push raw bytes into the framing buffer; sockgets() extracts lines. */
      op_linebuf_parse(&sl->handler.sock.recvbuf, c->buf,
                       (ssize_t)c->nbytes, LINEBUF_PARSED);
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

void async_recv_stats(int *inflight_out, uint64_t *total_out, int *hwm_out)
{
  if (inflight_out)
    *inflight_out = atomic_load_explicit(&recv_inflight, memory_order_relaxed);
  if (total_out)
    *total_out    = atomic_load_explicit(&recv_total,    memory_order_relaxed);
  if (hwm_out)
    *hwm_out      = atomic_load_explicit(&recv_hwm,      memory_order_relaxed);
}

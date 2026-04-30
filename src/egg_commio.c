/*
 * egg_commio.c — bridge between eggdrop's socklist[] and libop's commio.
 *
 * Replaces net.c's inline epoll/io_uring/kqueue/IOCP/select dispatch and
 * io_thread.c's dedicated reader thread with commio's unified I/O layer.
 *
 * Design:
 *   - Each eggdrop socket is registered with commio via op_open() + op_setselect().
 *   - The commio read callback sets sock_list.commio_ready = 1.
 *   - sockread() calls op_select(timeout) instead of inline backend dispatch.
 *   - After op_select() returns, sockread()'s dispatch loop checks commio_ready
 *     instead of FD_ISSET(fd, &fdr).
 *
 * Copyright (C) 2026 Eggheads Development Team
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef _GNU_SOURCE
#  define _GNU_SOURCE
#endif

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif
#include "egg_tls.h"
#include "main.h"
#include "egg_commio.h"
#include "tclhash.h"

extern sock_list *socklist;
extern int backgrd;

/* =========================================================================
 * commio callbacks
 *
 * These are fired by op_select() when a socket becomes readable or writable.
 * They set the commio_ready flag so sockread()'s dispatch loop processes it.
 * ====================================================================== */

static void egg_commio_read_cb(op_fde_t *F, void *data)
{
  int slist_idx = (int)(intptr_t)data;
  struct threaddata *td = threaddata();

  (void)F;
  if (slist_idx < 0 || slist_idx >= td->MAXSOCKS)
    return;

  sock_list *sl = &socklist[slist_idx];
  if (sl->flags & SOCK_UNUSED)
    return;

  sl->commio_ready = 1;
}

/* Write callback — used for SOCK_CONNECT (non-blocking connect completion
 * signals write-readiness) and for dequeue_sockets() write-drain detection. */
static void egg_commio_write_cb(op_fde_t *F, void *data)
{
  int slist_idx = (int)(intptr_t)data;
  struct threaddata *td = threaddata();

  (void)F;
  if (slist_idx < 0 || slist_idx >= td->MAXSOCKS)
    return;

  sock_list *sl = &socklist[slist_idx];
  if (sl->flags & SOCK_UNUSED)
    return;

  sl->commio_ready = 1;
}

/* =========================================================================
 * Lifecycle
 * ====================================================================== */

void egg_commio_init(void)
{
  /* Size the fd hash table for eggdrop's typical workload.
   * closeall=0: don't close inherited fds.
   * maxfds=1024: reasonable limit.
   * heapsize=256: slab allocator page count for op_fde_t. */
  op_fdlist_init(0, 1024, 256);
  op_init_netio();
}

/* =========================================================================
 * Socket registration
 * ====================================================================== */

void egg_commio_add(int sock, int slist_idx, int flags)
{
  op_fde_t *F;
  uint16_t type = OP_FD_SOCKET;

  if (sock < 0)
    return;

  /* SOCK_NONSOCK (used for STDOUT/stdin debug console) should not be
   * registered with the I/O backend — it's a file, not a socket. */
  if (flags & (SOCK_NONSOCK | SOCK_VIRTUAL))
    return;

  F = op_open(sock, type, "eggdrop");
  if (!F)
    return;

  /* Install read callback for all sockets.
   * For SOCK_CONNECT, also install a write callback: non-blocking connect()
   * signals completion via write-readiness. */
  op_setselect(F, OP_SELECT_READ, egg_commio_read_cb,
               (void *)(intptr_t)slist_idx);
  if (flags & SOCK_CONNECT)
    op_setselect(F, OP_SELECT_WRITE, egg_commio_write_cb,
                 (void *)(intptr_t)slist_idx);
}

void egg_commio_del(int sock)
{
  op_fde_t *F;

  if (sock < 0)
    return;

  F = op_get_fde(sock);
  if (F)
    op_close(F);
}

void egg_commio_set_ssl(int sock, void *ssl)
{
  op_fde_t *F;

  if (sock < 0)
    return;

  F = op_get_fde(sock);
  if (F)
    op_fde_set_ssl_ptr(F, ssl);
}

/* =========================================================================
 * I/O dispatch
 * ====================================================================== */

int egg_commio_poll(int timeout_ms)
{
  return op_select((long)timeout_ms);
}

/* =========================================================================
 * Write flushing
 * ====================================================================== */

void egg_commio_flush_outbufs(void)
{
  struct threaddata *td = threaddata();

  /* Temporarily arm WRITE interest on sockets with pending outbufs.
   * A zero-timeout op_select() fires write callbacks for writable ones.
   * Then disarm WRITE interest to avoid spinning. */
  int any_pending = 0;
  for (int i = 0; i < td->MAXSOCKS; i++) {
    if (!(socklist[i].flags & (SOCK_UNUSED | SOCK_TCL)) &&
        socklist[i].handler.sock.outbuf != NULL
#ifdef TLS
        && !(socklist[i].ssl && !SSL_is_init_finished(socklist[i].ssl))
#endif
       ) {
      op_fde_t *F = op_get_fde(socklist[i].sock);
      if (F) {
        socklist[i].commio_ready = 0;
        op_setselect(F, OP_SELECT_WRITE, egg_commio_write_cb,
                     (void *)(intptr_t)i);
        any_pending = 1;
      }
    }
  }

  if (!any_pending)
    return;

  /* Zero-timeout poll: just check write-readiness, don't block. */
  op_select(0);

  /* Disarm WRITE interest for sockets that don't need it for connect. */
  for (int i = 0; i < td->MAXSOCKS; i++) {
    if (!(socklist[i].flags & (SOCK_UNUSED | SOCK_TCL)) &&
        socklist[i].handler.sock.outbuf != NULL &&
        !(socklist[i].flags & SOCK_CONNECT)) {
      op_fde_t *F = op_get_fde(socklist[i].sock);
      if (F)
        op_setselect(F, OP_SELECT_WRITE, NULL, NULL);
    }
  }
}

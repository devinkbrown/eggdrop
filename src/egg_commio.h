/*
 * egg_commio.h — bridge between eggdrop's socklist[] and libop's commio.
 *
 * commio provides the I/O multiplexing backend (epoll/io_uring/kqueue/poll/
 * select), replacing net.c's inline backend dispatch and io_thread.c.
 *
 * Each eggdrop socket gets an op_fde_t registered with commio.  The commio
 * read callback fills socklist[].handler.sock.inbuf exactly as the old
 * sockread()/io_thread did, so sockgets() and all consumers are unaffected.
 *
 * Copyright (C) 2026 Eggheads Development Team
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef _EGG_COMMIO_H
#define _EGG_COMMIO_H

#include "eggdrop.h"
#include <op_commio.h>

/* -------------------------------------------------------------------------
 * Lifecycle
 * ---------------------------------------------------------------------- */

/* Initialise commio (fd hash table + backend selection).
 * Must be called once, early in main(), before any sockets are opened. */
void egg_commio_init(void);

/* -------------------------------------------------------------------------
 * Socket ↔ commio bridging
 * ---------------------------------------------------------------------- */

/* Register a socket with commio after allocsock().
 * Installs a read callback that fills socklist inbuf.
 * slist_idx: index in socklist[] for this socket. */
void egg_commio_add(int sock, int slist_idx, int flags);

/* Deregister a socket from commio before closing it.
 * Must be called BEFORE close(sock). */
void egg_commio_del(int sock);

/* Sync an externally-managed SSL pointer (from eggdrop's tls.c) onto the
 * commio FDE so that op_ssl_read()/op_ssl_write() can use it.
 * Pass NULL to clear. */
void egg_commio_set_ssl(int sock, void *ssl);

/* -------------------------------------------------------------------------
 * I/O dispatch (replaces sockread's backend wait)
 * ---------------------------------------------------------------------- */

/* Run one commio poll cycle.  timeout_ms: max ms to block.
 * Returns number of events dispatched (callbacks fired), or -1 on error.
 * After this returns, any received data is in socklist inbufs, ready for
 * sockgets() to drain. */
int egg_commio_poll(int timeout_ms);

/* -------------------------------------------------------------------------
 * Write flushing (replaces dequeue_sockets backend)
 * ---------------------------------------------------------------------- */

/* Flush pending outbufs for all sockets that are write-ready.
 * Uses commio's write-readiness detection (zero-timeout poll). */
void egg_commio_flush_outbufs(void);

#endif /* _EGG_COMMIO_H */

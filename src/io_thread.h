/*
 * io_thread.h — dedicated I/O reader thread for eggdrop.
 *
 * The io_thread runs a separate epoll/select loop over all non-TCL,
 * non-TLS eggdrop sockets.  When data arrives it appends the received
 * bytes to the per-socket inbuf under inbuf_lock, then signals the main
 * thread via an eventfd so sockgets() can drain the buffer immediately
 * without blocking in sockread().
 *
 * TLS sockets are handled by the traditional sockread() path in the main
 * thread because OpenSSL/WolfSSL SSL* objects are not safe to read and
 * write from different threads simultaneously.
 *
 * Copyright (C) 2026 Eggheads Development Team
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef _EGG_IO_THREAD_H
#define _EGG_IO_THREAD_H

#include "eggdrop.h"

/* -------------------------------------------------------------------------
 * Lifecycle
 * ---------------------------------------------------------------------- */

/*
 * io_thread_start — spawn the I/O reader thread.
 *
 * Must be called after the network subsystem is initialised (allocsock has
 * been called at least once so the initial eventfd is open).
 *
 * Returns 0 on success, -1 on error (errno set).
 */
int io_thread_start(void);

/*
 * io_thread_stop — signal the I/O thread to exit and wait for it to join.
 *
 * Safe to call even if io_thread_start() was never called.
 */
void io_thread_stop(void);

/* -------------------------------------------------------------------------
 * Socket registration (called from allocsock / killsock)
 * ---------------------------------------------------------------------- */

/*
 * io_thread_add_sock — register a socket with the io_thread's epoll.
 *
 * slist_idx: index in socklist[] — stored as epoll user_data so the
 *            io_thread can locate inbuf_lock without scanning the list.
 *
 * Must be called with the socket already in socklist[slist_idx].
 * Safe to call before io_thread_start() — registrations are queued.
 */
void io_thread_add_sock(int sock, int slist_idx);

/*
 * io_thread_del_sock — remove a socket from the io_thread's epoll.
 *
 * Must be called BEFORE closing the socket fd and BEFORE destroying
 * socklist[slist_idx].handler.sock.inbuf_lock.
 */
void io_thread_del_sock(int sock);

/* -------------------------------------------------------------------------
 * Main-thread wait
 * ---------------------------------------------------------------------- */

/*
 * io_thread_wait — block the main thread until the io_thread signals that
 * at least one socket has new data, or until the timeout elapses.
 *
 * timeout_ms: maximum milliseconds to wait; 0 = poll, -1 = wait forever.
 *
 * Returns 1 if data is available, 0 on timeout, -1 on error.
 *
 * Only call this when sockgets() has found no buffered data and you are
 * about to block waiting for new input.
 */
int io_thread_wait(int timeout_ms);

/* -------------------------------------------------------------------------
 * Query
 * ---------------------------------------------------------------------- */

/* Returns 1 if the io_thread is running, 0 otherwise. */
int io_thread_active(void);

#endif /* _EGG_IO_THREAD_H */

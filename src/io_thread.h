/*
 * io_thread.h — dedicated I/O reader thread for eggdrop.
 *
 * The io_thread offloads socket recv() calls to a separate thread so
 * they overlap with main-thread handler processing.  Data flows through
 * a lock-free SPSC ring buffer:
 *
 *     io_thread: epoll_wait → recv → ring_push → signal eventfd
 *     main thread: io_thread_drain → ring_pop → op_linebuf_parse → sockgets
 *
 * The SPSC ring buffer provides:
 *   - Zero CAS contention (simple acquire/release on indices)
 *   - Native FIFO order (no LIFO reversal)
 *   - Cache-line padded producer/consumer indices
 *
 * Adaptive epoll timeout:
 *   Hot (1ms) → Warm (50ms) → Cold (500ms) based on recent activity.
 *
 * Requirements:
 *   - Linux (epoll + eventfd).  Non-Linux platforms get no-op stubs.
 *   - Sockets must be added explicitly via io_thread_add_sock().
 *   - TLS, TCL, WebSocket, and listening sockets must NOT be added
 *     (TLS is not thread-safe, the others need main-thread processing).
 *   - io_thread_del_sock() must be called BEFORE closing the fd.
 *
 * Copyright (C) 2026 Eggheads Development Team
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef _EGG_IO_THREAD_H
#define _EGG_IO_THREAD_H

#include "eggdrop.h"

int  io_thread_start(void);
void io_thread_stop(void);
int  io_thread_active(void);

void io_thread_add_sock(int sock, int slist_idx);
void io_thread_del_sock(int sock, int slist_idx);

/* Drain completed reads into linebufs.  Returns count of results
 * processed.  Called from the main thread (sockgets / commio handler). */
int  io_thread_drain(void);

/* Returns 1 if io_thread currently owns reads for this slot. */
int  io_thread_manages(int slist_idx);

/* Set CPU core affinity for the I/O thread (-1 = OS default).
 * Must be called before io_thread_start(). */
void io_thread_set_affinity(int core);

/* Get current CPU affinity setting (-1 = none). */
int  io_thread_get_affinity(void);

/* Auto-detect best CPU core for I/O thread based on topology.
 * Selects a core on a different L2 cache domain from the main thread
 * to maximize cache independence.  Returns the core number, or -1
 * if topology detection fails or the system has only one core. */
int  io_thread_detect_best_core(void);

#endif /* _EGG_IO_THREAD_H */

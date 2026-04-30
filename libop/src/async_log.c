/*
 * libop: ophion support library.
 * async_log.c: Asynchronous log writer thread implementation.
 *
 * Copyright (C) 2026 ophion development team
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <libop_config.h>
#include <op_lib.h>
#include <op_async_log.h>

#include <pthread.h>
#include <stdatomic.h>
#include <string.h>

/* ---- log entry ----------------------------------------------------------- */

#define LOG_MSG_SIZE  2048

typedef struct log_entry
{
	char             msg[LOG_MSG_SIZE];
	struct log_entry *next;   /* Treiber stack link (LIFO order) */
} log_entry_t;

/* ---- MPSC Treiber stack -------------------------------------------------- */

/*
 * log_stack_top — atomic top of the Treiber stack.
 *
 * Producers (any thread) push with a CAS loop (lockfree).
 * The writer thread drains with atomic_exchange (acquires all entries at once).
 */
static _Atomic(log_entry_t *) log_stack_top = NULL;

/* Condvar to wake the writer when entries are available. */
static pthread_mutex_t log_mu    = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  log_cond  = PTHREAD_COND_INITIALIZER;

/*
 * log_pending — set to 1 by producers after each push.
 * Writer resets it to 0 before sleeping.  Using exchange avoids a
 * mutex-protected flag check in the common (non-empty queue) path.
 */
static _Atomic(int) log_pending = 0;

/* ---- writer thread state ------------------------------------------------- */

static pthread_t      log_tid;
static atomic_int     log_stop    = 0;
static _Atomic(int)   log_active  = 0;

/* The log callback to invoke from the writer thread.
 * Set once by op_start_async_log(); read-only thereafter. */
static log_cb *log_writer_cb = NULL;

/* ---- op_async_log_enqueue ------------------------------------------------ */

/*
 * op_async_log_enqueue — called by op_lib_log() when async mode is active.
 *
 * Pushes a pre-formatted message onto the Treiber stack (lockfree, O(1))
 * and signals the writer thread if this is the first entry since the last
 * drain.
 */
void
op_async_log_enqueue(const char *msg)
{
	log_entry_t *e = op_malloc(sizeof(*e));
	snprintf(e->msg, LOG_MSG_SIZE, "%s", msg);

	/* Treiber push: CAS loop with release on success so the writer sees
	 * the fully-written entry. */
	log_entry_t *old = atomic_load_explicit(&log_stack_top, memory_order_relaxed);
	do {
		e->next = old;
	} while (!atomic_compare_exchange_weak_explicit(
	              &log_stack_top, &old, e,
	              memory_order_release,
	              memory_order_relaxed));

	/* Signal once per burst: if log_pending was already 1, the writer is
	 * already awake or will wake itself on the next iteration. */
	if (atomic_exchange_explicit(&log_pending, 1, memory_order_relaxed) == 0)
	{
		pthread_mutex_lock(&log_mu);
		pthread_cond_signal(&log_cond);
		pthread_mutex_unlock(&log_mu);
	}
}

/* ---- drain helper -------------------------------------------------------- */

/*
 * drain_stack — atomically detach the entire stack and deliver entries
 * in chronological order (oldest first).
 *
 * Must only be called from the writer thread.
 */
static void
drain_stack(void)
{
	/* Detach the entire stack atomically. */
	log_entry_t *head = atomic_exchange_explicit(&log_stack_top, NULL,
	                                              memory_order_acquire);
	if (head == NULL)
		return;

	/* The stack is LIFO; reverse to restore chronological order. */
	log_entry_t *reversed = NULL;
	while (head)
	{
		log_entry_t *next = head->next;
		head->next = reversed;
		reversed   = head;
		head       = next;
	}

	/* Deliver and free. */
	while (reversed)
	{
		log_entry_t *next = reversed->next;
		if (log_writer_cb != NULL)
			log_writer_cb(reversed->msg);
		op_free(reversed);
		reversed = next;
	}
}

/* ---- writer thread ------------------------------------------------------- */

static void *
log_writer_fn(void *arg)
{
	(void)arg;

	while (!log_stop)
	{
		pthread_mutex_lock(&log_mu);
		while (!log_pending && !log_stop)
			pthread_cond_wait(&log_cond, &log_mu);
		atomic_store_explicit(&log_pending, 0, memory_order_relaxed);
		pthread_mutex_unlock(&log_mu);

		drain_stack();
	}

	/* Final drain: deliver any entries that arrived during shutdown. */
	drain_stack();
	return NULL;
}

/* ---- public API ---------------------------------------------------------- */

bool
op_start_async_log(log_cb *cb)
{
	if (atomic_load_explicit(&log_active, memory_order_acquire))
		return true;

	log_writer_cb = cb;
	log_stop      = 0;
	atomic_store_explicit(&log_pending, 0, memory_order_relaxed);

	/* Reset condvar to clear any stale signals from a previous run. */
	pthread_cond_destroy(&log_cond);
	pthread_cond_init(&log_cond, NULL);

	int rc = pthread_create(&log_tid, NULL, log_writer_fn, NULL);
	if (rc != 0)
	{
		/* Can't call op_lib_log here — we're setting up the log path.
		 * Write directly to stderr as a last resort. */
		fprintf(stderr, "op_start_async_log: pthread_create: %s\n",
		        strerror(rc));
		return false;
	}

	/* Install the async hook AFTER the thread is running so that early
	 * messages from thread creation itself go through synchronous delivery. */
	atomic_store_explicit(&log_active, 1, memory_order_release);
	op_lib_set_log_hook(op_async_log_enqueue);
	return true;
}

void
op_stop_async_log(void)
{
	if (!atomic_load_explicit(&log_active, memory_order_acquire))
		return;

	/* Remove the hook FIRST so new messages go synchronous immediately.
	 * Any in-flight enqueue() calls that haven't finished yet will still
	 * land in the stack; the final drain_stack() below picks them up. */
	op_lib_set_log_hook(NULL);

	log_stop = 1;
	atomic_store_explicit(&log_active, 0, memory_order_release);

	pthread_mutex_lock(&log_mu);
	pthread_cond_signal(&log_cond);
	pthread_mutex_unlock(&log_mu);

	pthread_join(log_tid, NULL);
	log_writer_cb = NULL;
}

bool
op_async_log_active(void)
{
	return atomic_load_explicit(&log_active, memory_order_acquire);
}

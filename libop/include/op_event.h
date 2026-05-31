/*
 *  libop: ophion support library.
 *  op_event.h: Event scheduler.
 *
 *  Copyright (C) 1990 Jarkko Oikarinen and University of Oulu, Co Center
 *  Copyright (C) 1996-2002 Hybrid Development Team
 *  Copyright (C) 2002-2005 ircd-ratbox development team
 *  Copyright (C) 2025-2026 ophion development team
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301
 *  USA
 *
 */

#ifndef LIBOP_LIB_H
# error "Do not include op_event.h directly; include op_lib.h"
#endif

#ifndef LIBOP_EVENT_H
#define LIBOP_EVENT_H

struct ev_entry;
typedef void EVH(void *);

/*
 * ----------------------------------------------------------------------------
 * Per-shard event context (Phase 1 — Shard refactor, see doc/technical/shard-design.md)
 * ----------------------------------------------------------------------------
 *
 * Each shard thread owns one `op_event_ctx_t`: the epoll fd (or io_uring),
 * the per-shard fd_heap / timeout_heap / closed_list bookkeeping, the SPSC
 * ring used by the poll helper thread, and the timer min-heap from event.c.
 * Process-global concerns (threadpool, RLIMIT_NOFILE accounting, the global
 * `number_fd` atomic) remain file-static.
 *
 * Invariant: any thread that calls an `op_*` IO/event function must have its
 * TLS `t_ev_ctx` pointer set. In debug builds an assertion fires otherwise;
 * production builds skip the check for zero indirection cost beyond the TLS
 * load.
 *
 * The transition strategy keeps existing call sites unchanged. `ircd_main`
 * calls `op_event_ctx_create("io")` once, stores the result in a libop
 * `legacy_global_ctx` static, and calls `op_event_ctx_set_current()` on the
 * main thread. Every legacy entrypoint then routes through `t_ev_ctx` which
 * resolves to that single context.
 */
typedef struct op_event_ctx op_event_ctx_t;

/* TLS pointer to the current thread's event context. NULL until
 * op_event_ctx_set_current() runs on this thread. Declared here so callers
 * that need a fast "current ctx?" check can read it directly; prefer
 * op_event_ctx_current() in non-hot paths for stability across reorgs. */
extern _Thread_local op_event_ctx_t *t_ev_ctx;

/* Create a new event context. `name` is used in telemetry / log messages;
 * it is duplicated internally and may be freed by the caller. Returns NULL
 * on allocation failure or backend init failure. */
op_event_ctx_t *op_event_ctx_create(const char *name);

/* Destroy a previously-created context. All FDs owned by the context must
 * be closed first; in debug builds this is asserted. Must not be called
 * while any thread has the context set as its current ctx. */
void op_event_ctx_destroy(op_event_ctx_t *ctx);

/* Run one iteration of the event loop bound to `ctx`, blocking at most
 * `ms` milliseconds. Equivalent to the legacy op_select() but explicit
 * about which context is being driven. */
int op_event_ctx_select(op_event_ctx_t *ctx, long ms);

/* Return the calling thread's current context, or NULL if none is set. */
op_event_ctx_t *op_event_ctx_current(void);

/* Bind `ctx` to the calling thread. Pass NULL to clear (e.g. during
 * shutdown). Subsequent calls to legacy event/commio entrypoints from
 * this thread will operate on `ctx`. */
void op_event_ctx_set_current(op_event_ctx_t *ctx);

struct ev_entry *op_event_add(const char *name, EVH * func, void *arg, time_t when);
struct ev_entry *op_event_addonce(const char *name, EVH * func, void *arg, time_t when);
struct ev_entry *op_event_addish(const char *name, EVH * func, void *arg, time_t delta_ish);
void op_event_run(void);
void op_event_init(void);
void op_event_delete(struct ev_entry *);
void op_event_find_delete(EVH * func, void *);
void op_event_update(struct ev_entry *, time_t freq);
void op_set_back_events(time_t);
void op_dump_events(void (*func) (char *, void *), void *ptr);
void op_run_one_event(struct ev_entry *);
time_t op_event_next(void);
void op_event_purge_module(const char *mod_name);
extern const char *op_current_loading_module;

/*
 * Priority-aware threadpool API (additive).
 *
 * Existing entrypoints (op_event_post / op_event_post_to_main / any ad-hoc
 * hipri variant) remain ABI-compatible thin wrappers and map to
 * OP_EVENT_PRI_NORMAL. New code should prefer op_event_post_pri() so the
 * scheduler can route work across the BG / normal / hipri / pinned-SPSC
 * lanes uniformly.
 */
typedef enum op_event_priority {
	OP_EVENT_PRI_BG       = 0,  /* deferred / best-effort (idle lane)     */
	OP_EVENT_PRI_NORMAL   = 1,  /* default work queue                     */
	OP_EVENT_PRI_HIGH     = 2,  /* hipri queue (latency-sensitive)        */
	OP_EVENT_PRI_REALTIME = 3   /* pinned SPSC lane (main-thread direct)  */
} op_event_priority_t;

/*
 * Opaque cancellation handle. Zero-valued (.id == 0) handles are reserved
 * to mean "no handle" / "already-completed sentinel" and are always safe
 * to pass to op_event_cancel() (returns false).
 *
 * Implementation hint for event.c agent: pack a slot index plus a per-slot
 * generation counter. op_event_cancel() should atomically bump the slot's
 * generation; the worker compares-and-skips on dispatch. This avoids
 * ABA and lets cancel race execution without locks.
 */
typedef struct op_event_handle {
	uint64_t id;
} op_event_handle_t;

#define OP_EVENT_HANDLE_NULL ((op_event_handle_t){ 0 })

/*
 * Post `func(arg)` onto the lane selected by `pri`. Returns 0 on success,
 * negative errno-style code on failure (queue full, shutting down, ...).
 */
int op_event_post_pri(EVH *func, void *arg, op_event_priority_t pri);

/*
 * Like op_event_post_pri() but returns a cancellation handle. Returns
 * OP_EVENT_HANDLE_NULL on enqueue failure.
 */
op_event_handle_t op_event_post_cancellable(EVH *func, void *arg,
                                            op_event_priority_t pri);

/*
 * Attempt to cancel a previously-posted callback. Returns true iff
 * cancellation won the race (the callback will NOT run); false if the
 * callback already started, already finished, or the handle is stale/null.
 *
 * Safe to call from any thread, including from inside another event.
 */
bool op_event_cancel(op_event_handle_t handle);

/*
 * Advisory hint to the threadpool: target between `min` and `max` worker
 * threads. The pool is free to ignore, defer, or coalesce hints; no
 * immediate resize is guaranteed. `min <= 0` or `max <= 0` resets to
 * built-in defaults. `min > max` is treated as an error (returns -1).
 *
 * Intended caller: ircd autotuner reacting to client load / lag samples.
 */
int op_event_threadpool_recommend_workers(int min, int max);

/*
 * Human-readable name for telemetry / /STATS output. Always returns a
 * non-NULL static string; unknown values map to "unknown".
 */
const char *op_event_priority_name(op_event_priority_t pri);

#endif /* LIBOP_EVENT_H */

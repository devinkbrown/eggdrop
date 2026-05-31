/*
 *  libop: ophion support library.
 *  event-int.h: internal structs for events
 *
 *  Copyright (C) 2007 ircd-ratbox development team
 *  Copyright (C) 2007 Aaron Sethman <androsyn@ratbox.org>
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

struct ev_entry
{
	EVH    *func;
	void   *arg;
	char   *name;
	time_t  frequency;
	time_t  when;       /* absolute time of next firing                 */
	time_t  next;       /* raw (possibly jittered) delta, for reschedule */
	void   *data;
	void   *comm_ptr;
	int     dead;
	size_t  hidx;       /* index into the min-heap array (for O(log n) delete) */
	char   *mod_name;   /* owning module name (NULL = core) for safe unload    */
};
void op_event_io_register_all(void);

/* ---- Phase 1 shard refactor: per-backend ctx hooks ----------------------- *
 *
 * Each I/O backend that participates in the per-shard context (currently only
 * epoll; io_uring and the others remain single-context until later commits)
 * exposes a triple init/destroy/select that operates on an op_event_ctx_t.
 *
 * op_*_ctx_init(ctx) populates ctx->backend_data with a freshly-allocated
 * per-context state struct (epoll fd, SPSC ring, helper thread, ...). It
 * does NOT start the poll helper thread; that is op_*_start_pollthread's job.
 *
 * op_*_ctx_destroy(ctx) tears everything down (stops the helper thread, frees
 * the state struct, closes the epoll fd) and clears ctx->backend_data.
 *
 * op_*_ctx_select(ctx, ms) runs one iteration of the event loop on ctx.
 *
 * The legacy single-shard path keeps its file-static state inside the backend
 * .c file; op_event_ctx_create()'s first invocation adopts that state as the
 * legacy_global_ctx's backend_data so existing call sites that never touch
 * the new API still observe identical behaviour.
 */
/*
 * The full struct op_event_ctx layout lives in event.c, but each backend
 * needs to read/write ctx->backend_data and ctx->name during init/teardown.
 * Defined here (not in op_event.h) so callers outside libop continue to see
 * an opaque typedef.
 */
struct op_event_ctx {
	char *name;
	void *backend_data;
	void *event_data;   /* per-ctx timer heap (struct event_ctx_data *, defined in event.c) */
	void *commio_data;  /* per-ctx fd pools + timeout shards + conn/accept heaps (struct commio_ctx_data *, defined in commio.c) */
	bool  is_legacy;
};

#if defined(HAVE_EPOLL_CTL)
int   op_epoll_ctx_init(struct op_event_ctx *ctx, const char *name);
void  op_epoll_ctx_destroy(struct op_event_ctx *ctx);
int   op_epoll_ctx_select(struct op_event_ctx *ctx, long ms);
void *op_epoll_legacy_data(void);
#endif

/* ---- Phase 1E: per-ctx io_uring backend ----------------------------------- *
 *
 * Mirrors the epoll backend triple: init / destroy / select operating on an
 * op_event_ctx_t. The io_uring backend stores its per-ctx state (the
 * io_uring ring itself, SQE deferral inbox + sqlock, CQ poll thread, eventfds,
 * capability flags, ...) in ctx->backend_data — the same slot epoll uses,
 * since exactly one I/O backend is selected at runtime by g_io.
 *
 * op_uring_legacy_data() returns the file-static struct uring_ctx_data that
 * backs the legacy single-shard path; op_event_ctx_create() adopts it as the
 * legacy global ctx's backend_data on first invocation so both the
 * t_ev_ctx-aware and the fallback (t_ev_ctx == NULL) paths observe identical
 * state.
 *
 * op_fd_table stays process-global (extern, shared with commio.c) — io_uring
 * uses it for fd → op_fde_t lookup just like commio does. FDs never migrate
 * between ctxs (commio commit D4 invariant).
 */
#if defined(HAVE_LIBURING)
int   op_uring_ctx_init(struct op_event_ctx *ctx, const char *name);
void  op_uring_ctx_destroy(struct op_event_ctx *ctx);
int   op_uring_ctx_select(struct op_event_ctx *ctx, long ms);
void *op_uring_legacy_data(void);
/* Call once before spawning worker shards to divide per-ring depth by n,
 * keeping total RLIMIT_MEMLOCK usage within the default 8 MB limit. */
void  op_uring_set_shard_hint(int n);
#else
static inline void op_uring_set_shard_hint(int n) { (void)n; }
#endif

/* ---- Phase 1D: per-ctx commio bookkeeping --------------------------------- *
 *
 * op_commio_legacy_data() returns the file-static commio_ctx_data for the
 * legacy single-shard path. Called by op_event_ctx_create() during the first
 * (legacy-adopting) invocation so the t_ev_ctx-aware and fallback paths
 * observe identical state.
 *
 * op_commio_ctx_init() allocates a fresh per-shard commio_ctx_data and
 * attaches it to ctx->commio_data. op_commio_ctx_destroy() frees it.
 *
 * Per-ctx state moved into commio_ctx_data: fd_heap, closed_list,
 * closed_list_aged, recycled_list, timeout_heap, timeout_shards[16],
 * timeout_total_count, op_timeout_ev, conn_heap, accept_heap.
 *
 * Process-global state retained as file-statics in commio.c: op_fd_table
 * (extern, shared with io_uring.c; FDs never migrate but the hash index
 * stays global), number_fd (_Atomic), op_maxconnections, the g_io vtable,
 * io_close_fd hook, g_poll_thread_active (backend selection is one-shot).
 */
void *op_commio_legacy_data(void);
int   op_commio_ctx_init(struct op_event_ctx *ctx, const char *name);
void  op_commio_ctx_destroy(struct op_event_ctx *ctx);

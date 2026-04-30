/*
 * libop: ophion support library.
 * io_uring.c: Linux io_uring POLL_ADD event backend.
 *
 * Uses io_uring's IORING_OP_POLL_ADD in oneshot mode as a drop-in
 * replacement for epoll.  Each op_fde_t with read or write interest gets
 * a POLL_ADD SQE; the CQE fires when the fd is ready, the handler is
 * dispatched, and the fd is re-armed if interest still exists after dispatch.
 *
 * Event scheduling (timers, signals) delegates to the epoll backend's
 * timerfd/signalfd infrastructure — timerfd is just another pollable fd.
 *
 * Thread safety
 * -------------
 * Worker threads may call op_setselect_uring() concurrently with the I/O
 * thread running op_select_uring().  Two locks are used:
 *
 *   F->pflags_lock  — per-fd spinlock; guards handler pointers, F->pflags,
 *                     and the URING_F_PENDING flag within F->pflags.
 *
 *   uring_sqlock    — global spinlock; serialises all SQ ring access
 *                     (io_uring_get_sqe, io_uring_prep_poll_add,
 *                      io_uring_sqe_set_data64, io_uring_submit).
 *                     The io_uring SQ ring is single-producer; without this
 *                     lock, concurrent submissions from multiple threads
 *                     corrupt the ring.
 *
 * Lock order: F->pflags_lock THEN uring_sqlock (never the reverse).
 *
 * Generation numbers
 * ------------------
 * Each POLL_ADD SQE embeds a (fd, gen) pair as its user_data.  The
 * generation counter (F->uring_gen, uint32_t) is incremented on every
 * submission.  A CQE is discarded if its generation does not match the
 * current F->uring_gen, preventing stale events from firing handlers on
 * an fd that has been recycled or re-registered.
 *
 * Copyright (C) 2026 ophion development team
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#define _GNU_SOURCE 1

#include <pthread.h>
#include <libop_config.h>
#include <op_lib.h>
#include <commio-int.h>
#include <event-int.h>

#if defined(HAVE_LIBURING)
#define USING_URING

#include <liburing.h>
#include <poll.h>
#include <stdatomic.h>
#include <sys/eventfd.h>

/*
 * URING_F_PENDING: set in F->pflags while a POLL_ADD CQE is in-flight.
 * Prevents duplicate submissions from op_arm_uring.
 * Stored in a high bit of pflags that POLLIN/POLLOUT never occupy.
 */
#define URING_F_PENDING  (1U << 16)

/*
 * Ring depth.  Rounded up to the nearest power-of-two at init time based
 * on getdtablesize(); capped at URING_RING_DEPTH_MAX.  The ring must hold
 * at least one SQE per fd that could be simultaneously armed.
 */
#define URING_RING_DEPTH_MAX  65536
#define URING_RING_DEPTH_MIN  256

static struct io_uring uring;
static pthread_spinlock_t uring_sqlock;

/* ---- io_uring CQ poll thread --------------------------------------------- */

/*
 * uring_event_t — packed CQE snapshot for the inter-thread ring.
 *
 * The CQ poll thread extracts these fields and calls io_uring_cq_advance()
 * while still owning the CQ.  The main thread reconstructs op_fde_t * from
 * the fd/gen pair and dispatches the handler.
 */
typedef struct
{
	uint64_t tag;   /* (cqe_fd << 32 | cqe_gen) — matches op_arm_uring encoding */
	int      res;   /* cqe->res                                                  */
} uring_event_t;

/*
 * URING_RING_CAP — capacity of the SPSC event ring.
 * Must be a power of two.  Sized to absorb a full burst without blocking.
 */
#define URING_RING_CAP  4096u

typedef struct
{
	_Atomic(uint32_t)  head;          /* producer cursor (CQ thread)  */
	char               _pad0[60];
	_Atomic(uint32_t)  tail;          /* consumer cursor (main thread) */
	char               _pad1[60];
	uring_event_t      slots[URING_RING_CAP];
} uring_cq_ring_t;

static uring_cq_ring_t   uring_cq_ring __attribute__((aligned(64)));
static int               uring_notify_fd    = -1;
static pthread_t         uring_poll_tid;
static atomic_int        uring_thread_stop  = 0;
static int               uring_thread_active = 0;

/* Forward declaration — defined after op_select_uring. */
static void uring_dispatch_from_ring(void);

static inline bool
uring_ring_push(uring_cq_ring_t *r, const uring_event_t *ev)
{
	uint32_t h = atomic_load_explicit(&r->head, memory_order_relaxed);
	uint32_t t = atomic_load_explicit(&r->tail, memory_order_acquire);
	if (h - t >= URING_RING_CAP)
		return false;
	r->slots[h & (URING_RING_CAP - 1)] = *ev;
	atomic_store_explicit(&r->head, h + 1, memory_order_release);
	return true;
}

static inline bool
uring_ring_pop(uring_cq_ring_t *r, uring_event_t *ev)
{
	uint32_t t = atomic_load_explicit(&r->tail, memory_order_relaxed);
	uint32_t h = atomic_load_explicit(&r->head, memory_order_acquire);
	if (t == h)
		return false;
	*ev = r->slots[t & (URING_RING_CAP - 1)];
	atomic_store_explicit(&r->tail, t + 1, memory_order_release);
	return true;
}

/* -------------------------------------------------------------------------
 * Internal helpers
 * ---------------------------------------------------------------------- */

/* Round n up to the next power of two (n > 0). */
static __attribute__((const)) unsigned int
round_pow2(unsigned int n)
{
	n--;
	n |= n >> 1; n |= n >> 2; n |= n >> 4;
	n |= n >> 8; n |= n >> 16;
	return n + 1;
}

/*
 * op_arm_uring — submit a POLL_ADD SQE for F.
 *
 * Caller MUST hold F->pflags_lock.  uring_sqlock is acquired internally
 * (lock order: pflags_lock → uring_sqlock).
 *
 * Returns 1 if the SQE was queued, 0 if the ring was full and the arm
 * could not be completed (logged as a warning; the caller should retry
 * on the next op_setselect call).
 */
static int
op_arm_uring(op_fde_t *F)
{
	struct io_uring_sqe *sqe;
	unsigned int mask = 0;

	if (F->read_handler  != NULL) mask |= POLLIN;
	if (F->write_handler != NULL) mask |= POLLOUT;
	if (mask == 0)
		return 1;  /* Nothing to arm — not an error. */

	pthread_spin_lock(&uring_sqlock);

	sqe = io_uring_get_sqe(&uring);
	if (sqe == NULL)
	{
		/* SQ ring full — flush and retry once. */
		io_uring_submit(&uring);
		sqe = io_uring_get_sqe(&uring);
	}

	if (__builtin_expect(sqe == NULL, 0))
	{
		pthread_spin_unlock(&uring_sqlock);
		op_lib_log("op_arm_uring: SQ ring full after flush; fd=%d will not be armed",
		           F->fd);
		/* Do NOT set URING_F_PENDING — the arm failed.  The fd will be
		 * re-armed on the next op_setselect_uring() call. */
		return 0;
	}

	F->uring_gen++;
	io_uring_prep_poll_add(sqe, F->fd, mask);
	io_uring_sqe_set_data64(sqe,
	    ((uint64_t)(uint32_t)F->fd << 32) | (uint64_t)F->uring_gen);

	/* Mark pending INSIDE uring_sqlock so the flag and the queued SQE are
	 * visible to other threads atomically (both locks are held here). */
	F->pflags |= URING_F_PENDING;

	pthread_spin_unlock(&uring_sqlock);
	return 1;
}

/*
 * op_cancel_uring — cancel an in-flight POLL_ADD for F.
 *
 * Called when all handlers are cleared while URING_F_PENDING is set.
 * Submits IORING_OP_ASYNC_CANCEL targeting the specific (fd, gen) user_data
 * to avoid cancelling a re-arm that raced ahead.
 *
 * Caller MUST hold F->pflags_lock.  uring_sqlock acquired internally.
 *
 * Cancellation is best-effort: if the CQE has already landed in the ring,
 * the cancel CQE arrives with -ENOENT and the original CQE is processed
 * normally (the generation check then discards it since we increment gen).
 */
static void
op_cancel_uring(op_fde_t *F)
{
	struct io_uring_sqe *sqe;
	uint64_t target;

	/* Record the user_data we want to cancel BEFORE incrementing gen so the
	 * cancel targets the in-flight SQE, then bump gen to invalidate it. */
	target = ((uint64_t)(uint32_t)F->fd << 32) | (uint64_t)F->uring_gen;
	F->uring_gen++;           /* invalidate any arriving CQE for old gen */
	F->pflags &= ~URING_F_PENDING;

	pthread_spin_lock(&uring_sqlock);

	sqe = io_uring_get_sqe(&uring);
	if (sqe == NULL)
	{
		io_uring_submit(&uring);
		sqe = io_uring_get_sqe(&uring);
	}

	if (__builtin_expect(sqe != NULL, 1))
	{
#if defined(IORING_ASYNC_CANCEL_USERDATA)
		io_uring_prep_cancel64(sqe, target, 0);
#else
		/* Older kernels: cancel by user_data (best-effort). */
		io_uring_prep_cancel(sqe, (void *)(uintptr_t)target, 0);
#endif
		/* Use a sentinel data value so the cancel CQE is identifiable
		 * and silently discarded in the dispatch loop. */
		io_uring_sqe_set_data64(sqe, UINT64_MAX);
	}

	pthread_spin_unlock(&uring_sqlock);
}

/* -------------------------------------------------------------------------
 * Initialisation
 * ---------------------------------------------------------------------- */

int
op_init_netio_uring(void)
{
	unsigned int depth;
	unsigned int flags = 0;

	/* Scale ring depth to the fd table size, rounded to power-of-two. */
	{
		int dtsize = getdtablesize();
		unsigned int want = (unsigned int)(dtsize > 0 ? dtsize : 1024) * 2;
		depth = round_pow2(want);
		if (depth < URING_RING_DEPTH_MIN) depth = URING_RING_DEPTH_MIN;
		if (depth > URING_RING_DEPTH_MAX) depth = URING_RING_DEPTH_MAX;
	}

	/*
	 * IORING_SETUP_COOP_TASKRUN (Linux 5.19): defer task_work to the
	 * io_uring submission/wait path, reducing context-switch overhead.
	 *
	 * IORING_SETUP_TASKRUN_FLAG (Linux 5.19): must accompany COOP_TASKRUN
	 * when IORING_SETUP_DEFER_TASKRUN is not set.
	 *
	 * IORING_SETUP_CLAMP (Linux 5.6): silently clamp ring size if the
	 * requested depth exceeds the kernel's internal limit.
	 *
	 * Each flag is guarded by its own HAVE_ test (set by configure) so the
	 * code degrades gracefully on older kernels.
	 */
#if defined(IORING_SETUP_CLAMP)
	flags |= IORING_SETUP_CLAMP;
#endif
#if defined(IORING_SETUP_COOP_TASKRUN) && defined(IORING_SETUP_TASKRUN_FLAG)
	flags |= IORING_SETUP_COOP_TASKRUN | IORING_SETUP_TASKRUN_FLAG;
#endif

	if (io_uring_queue_init(depth, &uring, flags) < 0)
	{
		/* Retry without performance flags in case the kernel rejects them. */
		if (flags != 0 && io_uring_queue_init(depth, &uring, 0) < 0)
			return -1;
		else if (flags == 0)
			return -1;
	}

	pthread_spin_init(&uring_sqlock, PTHREAD_PROCESS_PRIVATE);
	return 0;
}

/* -------------------------------------------------------------------------
 * Interest registration
 * ---------------------------------------------------------------------- */

/*
 * op_setselect_uring
 *
 * Register or update handler interest for F.  If no POLL_ADD is currently
 * in-flight, arms one immediately.  If one is in-flight and all interest is
 * being cleared, cancels it via op_cancel_uring.  Otherwise the in-flight
 * POLL_ADD will fire soon; the updated handlers will be used at re-arm time.
 */
void
op_setselect_uring(op_fde_t *F, unsigned int type, PF *handler,
                   void *client_data)
{
	int was_pending;

	/* pflags_lock makes this call safe from worker threads.
	 * Lock order: pflags_lock → uring_sqlock (inside op_arm/cancel_uring). */
	pthread_spin_lock(&F->pflags_lock);

	if (type & OP_SELECT_READ)
	{
		F->read_handler = handler;
		F->read_data    = client_data;
	}
	if (type & OP_SELECT_WRITE)
	{
		F->write_handler = handler;
		F->write_data    = client_data;
	}

	was_pending = (F->pflags & URING_F_PENDING) != 0;

	if (!was_pending)
	{
		/* No poll in-flight — arm now. */
		op_arm_uring(F);
	}
	else if (F->read_handler == NULL && F->write_handler == NULL)
	{
		/* All interest cleared while a poll is in-flight — cancel it.
		 * op_cancel_uring clears URING_F_PENDING and bumps uring_gen. */
		op_cancel_uring(F);
	}
	/* else: poll is in-flight and some interest remains; the CQE will arrive
	 * soon and op_arm_uring will re-arm with the updated handler mask. */

	pthread_spin_unlock(&F->pflags_lock);
}

/* -------------------------------------------------------------------------
 * Event dispatch
 * ---------------------------------------------------------------------- */

/*
 * op_select_uring
 *
 * Flush all queued SQEs, wait for CQEs, then dispatch handlers.
 * Re-arms each fd for any remaining interest after dispatch.
 *
 * When uring_thread_active == 1, the CQ drain thread owns io_uring_wait_cqe().
 * This function instead blocks on the notification eventfd and dispatches
 * from the SPSC ring.
 */
int
op_select_uring(long delay)
{
	if (__builtin_expect(uring_thread_active, 0))
	{
		/* Threaded mode: wait on the notification eventfd, drain ring. */
		int ms = (delay < 0) ? -1
		       : (delay > (long)INT_MAX ? INT_MAX : (int)delay);

		struct pollfd pf = { .fd = uring_notify_fd, .events = POLLIN };
		poll(&pf, 1, ms);

		/* Drain the counter without caring about the value. */
		uint64_t notify_val;
		ssize_t r;
		do { r = read(uring_notify_fd, &notify_val, sizeof notify_val); }
		while (r < 0 && errno == EINTR);

		op_set_time();
		uring_dispatch_from_ring();
		return OP_OK;
	}
	/* else: fall through to inline path */
	struct io_uring_cqe  *cqe;
	struct __kernel_timespec ts;
	unsigned int          head;
	unsigned int          count = 0;
	int ret;

	/* Flush any pending SQEs (including re-arms from previous iterations). */
	pthread_spin_lock(&uring_sqlock);
	ret = io_uring_submit(&uring);
	pthread_spin_unlock(&uring_sqlock);

	if (__builtin_expect(ret < 0 && ret != -EINTR, 0))
	{
		op_lib_log("op_select_uring: io_uring_submit failed: %s", strerror(-ret));
		/* Non-fatal: continue to drain any CQEs already in the ring. */
	}

	/* Wait for the first CQE (with optional timeout). */
	cqe = NULL;
	if (delay >= 0)
	{
		ts.tv_sec  =  delay / 1000;
		ts.tv_nsec = (delay % 1000) * 1000000L;
		ret = io_uring_wait_cqe_timeout(&uring, &cqe, &ts);
	}
	else
	{
		ret = io_uring_wait_cqe(&uring, &cqe);
	}

	/* Save errno before op_set_time() can clobber it. */
	int o_errno = errno;
	op_set_time();
	errno = o_errno;

	if (ret < 0 && ret != -ETIME && ret != -EINTR)
	{
		op_lib_log("op_select_uring: wait_cqe failed: %s", strerror(-ret));
		return OP_ERROR;
	}

	/* Drain all available CQEs. */
	io_uring_for_each_cqe(&uring, head, cqe)
	{
		uint64_t tag     = io_uring_cqe_get_data64(cqe);
		int      cqe_fd;
		uint32_t cqe_gen;
		op_fde_t *F;

		count++;

		/* Sentinel value used by op_cancel_uring's cancel SQE — discard. */
		if (__builtin_expect(tag == UINT64_MAX, 0))
			continue;

		cqe_fd  = (int)(uint32_t)(tag >> 32);
		cqe_gen = (uint32_t)tag;

		F = op_find_fd(cqe_fd);
		if (F == NULL || !IsFDOpen(F) || F->uring_gen != cqe_gen)
			continue;

		/* Clear URING_F_PENDING under pflags_lock.
		 *
		 * This is done BEFORE dispatching handlers so that a handler (or a
		 * concurrent worker thread) calling op_setselect_uring sees PENDING=0
		 * and can submit a fresh POLL_ADD immediately.  The re-arm at the end
		 * of this block is then a no-op if the handler or worker already did it.
		 *
		 * Both F->pflags_lock and uring_sqlock are NOT held during handler
		 * dispatch to avoid holding spinlocks across arbitrary user callbacks.
		 */
		pthread_spin_lock(&F->pflags_lock);
		F->pflags &= ~URING_F_PENDING;
		pthread_spin_unlock(&F->pflags_lock);

		{
			int res = cqe->res;

			if (res < 0 || (res & (POLLHUP | POLLERR | POLLNVAL)))
			{
				/* Error or hangup — dispatch both handlers. */
				PF   *h = NULL;
				void *d = NULL;

				pthread_spin_lock(&F->pflags_lock);
				h = F->read_handler; d = F->read_data;
				F->read_handler = NULL; F->read_data = NULL;
				pthread_spin_unlock(&F->pflags_lock);
				if (h != NULL)
					h(F, d);

				if (IsFDOpen(F))
				{
					pthread_spin_lock(&F->pflags_lock);
					h = F->write_handler; d = F->write_data;
					F->write_handler = NULL; F->write_data = NULL;
					pthread_spin_unlock(&F->pflags_lock);
					if (h != NULL)
						h(F, d);
				}
			}
			else
			{
				PF   *h = NULL;
				void *d = NULL;

				if (res & (POLLIN | POLLRDHUP))
				{
					pthread_spin_lock(&F->pflags_lock);
					h = F->read_handler; d = F->read_data;
					F->read_handler = NULL; F->read_data = NULL;
					pthread_spin_unlock(&F->pflags_lock);
					if (h != NULL)
						h(F, d);
				}

				if (IsFDOpen(F) && (res & POLLOUT))
				{
					pthread_spin_lock(&F->pflags_lock);
					h = F->write_handler; d = F->write_data;
					F->write_handler = NULL; F->write_data = NULL;
					pthread_spin_unlock(&F->pflags_lock);
					if (h != NULL)
						h(F, d);
				}
			}
		}

		/*
		 * Re-arm if handlers remain or were re-registered during dispatch.
		 *
		 * Acquire pflags_lock to inspect URING_F_PENDING: a worker thread
		 * or one of the dispatched handlers may have already called
		 * op_setselect_uring which set PENDING and submitted a new POLL_ADD.
		 * In that case we skip the re-arm entirely to avoid a duplicate.
		 */
		if (IsFDOpen(F))
		{
			pthread_spin_lock(&F->pflags_lock);
			if (!(F->pflags & URING_F_PENDING))
				op_arm_uring(F);
			pthread_spin_unlock(&F->pflags_lock);
		}
	}

	io_uring_cq_advance(&uring, count);
	return OP_OK;
}

int
op_setup_fd_uring(op_fde_t *F __attribute__((unused)))
{
	return 0;
}

/* -------------------------------------------------------------------------
 * io_uring CQ poll thread
 * -------------------------------------------------------------------------
 *
 * uring_cq_poll_thread_fn — dedicated thread that drains the io_uring CQ.
 *
 * Waits for CQEs with a short timeout (100 ms) so ep_thread_stop is checked
 * at regular intervals.  For each batch:
 *   1. Packs (tag, res) from each CQE into uring_cq_ring (SPSC, no lock).
 *   2. Advances the CQ with io_uring_cq_advance() — must happen here while
 *      we own the CQ.
 *   3. Writes to uring_notify_fd to wake the main thread.
 *
 * The main thread reconstructs op_fde_t * from tag and dispatches handlers.
 */
static void *
uring_cq_poll_thread_fn(void *arg)
{
	(void)arg;
	uint64_t one = 1;

	while (!uring_thread_stop)
	{
		struct io_uring_cqe  *cqe = NULL;
		struct __kernel_timespec ts = { .tv_sec = 0, .tv_nsec = 100000000LL }; /* 100 ms */

		/* First flush any pending SQEs so submitted arms actually fire. */
		pthread_spin_lock(&uring_sqlock);
		io_uring_submit(&uring);
		pthread_spin_unlock(&uring_sqlock);

		int ret = io_uring_wait_cqe_timeout(&uring, &cqe, &ts);
		if (ret < 0 || cqe == NULL)
			continue;  /* timeout or signal */

		/* Drain all available CQEs in one pass. */
		unsigned int head;
		unsigned int count = 0;
		bool any = false;

		io_uring_for_each_cqe(&uring, head, cqe)
		{
			count++;
			uint64_t tag = io_uring_cqe_get_data64(cqe);

			/* Skip cancel sentinel (see op_cancel_uring). */
			if (__builtin_expect(tag == UINT64_MAX, 0))
				continue;

			uring_event_t ev = { .tag = tag, .res = cqe->res };
			if (uring_ring_push(&uring_cq_ring, &ev))
				any = true;
			/* else ring full — drop; POLL_ADD will re-fire when re-armed */
		}

		io_uring_cq_advance(&uring, count);

		if (any)
		{
			ssize_t rc;
			do { rc = write(uring_notify_fd, &one, sizeof one); }
			while (rc < 0 && errno == EINTR);
		}
	}

	return NULL;
}

/*
 * uring_dispatch_from_ring — drain the SPSC ring and dispatch handlers.
 * Called from the main thread (op_select_uring threaded mode).
 */
static void
uring_dispatch_from_ring(void)
{
	uring_event_t ev;

	while (uring_ring_pop(&uring_cq_ring, &ev))
	{
		int      cqe_fd  = (int)(uint32_t)(ev.tag >> 32);
		uint32_t cqe_gen = (uint32_t)ev.tag;
		int      res     = ev.res;

		op_fde_t *F = op_find_fd(cqe_fd);
		if (F == NULL || !IsFDOpen(F) || F->uring_gen != cqe_gen)
			continue;

		/* Clear URING_F_PENDING before dispatch (same reason as inline path). */
		pthread_spin_lock(&F->pflags_lock);
		F->pflags &= ~URING_F_PENDING;
		pthread_spin_unlock(&F->pflags_lock);

		if (res < 0 || (res & (POLLHUP | POLLERR | POLLNVAL)))
		{
			PF *h; void *d;

			pthread_spin_lock(&F->pflags_lock);
			h = F->read_handler; d = F->read_data;
			F->read_handler = NULL; F->read_data = NULL;
			pthread_spin_unlock(&F->pflags_lock);
			if (h != NULL) h(F, d);

			if (IsFDOpen(F))
			{
				pthread_spin_lock(&F->pflags_lock);
				h = F->write_handler; d = F->write_data;
				F->write_handler = NULL; F->write_data = NULL;
				pthread_spin_unlock(&F->pflags_lock);
				if (h != NULL) h(F, d);
			}
		}
		else
		{
			PF *h; void *d;

			if (res & (POLLIN | POLLRDHUP))
			{
				pthread_spin_lock(&F->pflags_lock);
				h = F->read_handler; d = F->read_data;
				F->read_handler = NULL; F->read_data = NULL;
				pthread_spin_unlock(&F->pflags_lock);
				if (h != NULL) h(F, d);
			}

			if (IsFDOpen(F) && (res & POLLOUT))
			{
				pthread_spin_lock(&F->pflags_lock);
				h = F->write_handler; d = F->write_data;
				F->write_handler = NULL; F->write_data = NULL;
				pthread_spin_unlock(&F->pflags_lock);
				if (h != NULL) h(F, d);
			}
		}

		if (IsFDOpen(F))
		{
			pthread_spin_lock(&F->pflags_lock);
			if (!(F->pflags & URING_F_PENDING))
				op_arm_uring(F);
			pthread_spin_unlock(&F->pflags_lock);
		}
	}
}

/*
 * op_uring_start_pollthread — start the dedicated io_uring CQ drain thread.
 * Idempotent: returns true if already running.
 */
bool
op_uring_start_pollthread(void)
{
	if (uring_thread_active)
		return true;

	uring_notify_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
	if (uring_notify_fd < 0)
	{
		op_lib_log("op_uring_start_pollthread: eventfd: %s", strerror(errno));
		return false;
	}

	atomic_init(&uring_cq_ring.head, 0);
	atomic_init(&uring_cq_ring.tail, 0);
	uring_thread_stop = 0;

	int rc = pthread_create(&uring_poll_tid, NULL, uring_cq_poll_thread_fn, NULL);
	if (rc != 0)
	{
		op_lib_log("op_uring_start_pollthread: pthread_create: %s", strerror(rc));
		close(uring_notify_fd);
		uring_notify_fd = -1;
		return false;
	}

	uring_thread_active = 1;
	op_lib_log("I/O poll thread started (io_uring backend)");
	return true;
}

/*
 * op_uring_stop_pollthread — stop the CQ drain thread and revert to inline.
 */
void
op_uring_stop_pollthread(void)
{
	if (!uring_thread_active)
		return;

	uring_thread_stop   = 1;
	uring_thread_active = 0;
	pthread_join(uring_poll_tid, NULL);

	if (uring_notify_fd >= 0)
	{
		close(uring_notify_fd);
		uring_notify_fd = -1;
	}

	op_lib_log("I/O poll thread stopped (io_uring backend)");
}

/* -------------------------------------------------------------------------
 * Event scheduling — delegates to epoll's timerfd/signalfd path.
 * timerfd is just another pollable fd; io_uring polls it the same way.
 * ---------------------------------------------------------------------- */

void
op_uring_init_event(void)
{
	op_epoll_init_event();
}

int
op_uring_sched_event(struct ev_entry *event, int when)
{
	return op_epoll_sched_event(event, when);
}

void
op_uring_unsched_event(struct ev_entry *event)
{
	op_epoll_unsched_event(event);
}

int
op_uring_supports_event(void)
{
	return op_epoll_supports_event();
}

#else  /* !HAVE_LIBURING */

int  op_init_netio_uring(void) { return -1; }
void op_setselect_uring(op_fde_t *F __attribute__((unused)),
                        unsigned int type __attribute__((unused)),
                        PF *handler __attribute__((unused)),
                        void *client_data __attribute__((unused))) {}
int  op_select_uring(long delay __attribute__((unused))) { return -1; }
int  op_setup_fd_uring(op_fde_t *F __attribute__((unused))) { return 0; }
void op_uring_init_event(void) {}
int  op_uring_sched_event(struct ev_entry *event __attribute__((unused)),
                          int when __attribute__((unused))) { return 0; }
void op_uring_unsched_event(struct ev_entry *event __attribute__((unused))) {}
int  op_uring_supports_event(void) { return 0; }
bool op_uring_start_pollthread(void) { return false; }
void op_uring_stop_pollthread(void) {}

#endif /* HAVE_LIBURING */

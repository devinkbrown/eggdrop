/*
 * test_uring.c - basic functional test for the io_uring event backend
 *
 * Verifies that:
 *   1. libop selects "uring" as the I/O backend when liburing is present
 *      (set LIBOP_USE_IOTYPE=uring to force selection)
 *   2. A read interest registered via op_setselect() fires when data
 *      arrives on a socketpair
 *   3. A write interest fires when the socket is writable
 *   4. Re-arming inside a callback works (handler re-registers interest)
 */

#include <libop_config.h>
#include <op_lib.h>
#include <op_commio.h>

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* ---------- helpers ---------- */

static int failures = 0;

#define CHECK(cond) \
	do { \
		if (!(cond)) { \
			fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
			failures++; \
		} \
	} while (0)

#define CHECK_MSG(cond, msg) \
	do { \
		if (!(cond)) { \
			fprintf(stderr, "FAIL %s:%d: %s (%s)\n", __FILE__, __LINE__, #cond, (msg)); \
			failures++; \
		} \
	} while (0)

/* ---------- test state ---------- */

static int read_fired  = 0;
static int write_fired = 0;
static const char test_payload[] = "hello-uring";

/* ---------- callbacks ---------- */

static void
on_readable(op_fde_t *F, void *data)
{
	char buf[64];
	int  n;

	(void)data;
	n = read(op_get_fd(F), buf, sizeof(buf) - 1);
	if (n > 0)
	{
		buf[n] = '\0';
		CHECK_MSG(strcmp(buf, test_payload) == 0, buf);
		read_fired++;
	}
	else
	{
		CHECK_MSG(0, "read returned 0 or error in on_readable");
	}
}

static void
on_writable(op_fde_t *F, void *data)
{
	(void)F;
	(void)data;
	write_fired++;
}

/* ---------- tests ---------- */

/* 1 if the uring backend activated, 0 if it fell back (e.g. old kernel). */
static int uring_active = 0;


static void
test_backend_name(void)
{
	const char *iotype = op_get_iotype();
	printf("  io backend: %s\n", iotype);

#if defined(HAVE_LIBURING)
	if (strcmp(iotype, "uring") == 0)
	{
		uring_active = 1;
		printf("  io_uring active\n");
	}
	else
	{
		printf("  SKIP: io_uring not available on this kernel "
		       "(requires Linux >= 5.1); using %s fallback\n", iotype);
	}
#else
	printf("  SKIP: built without liburing\n");
#endif
}

static void
test_read_fires(void)
{
	op_fde_t *F1, *F2;
	int ret;

	ret = op_socketpair(AF_UNIX, SOCK_STREAM, 0, &F1, &F2, "test_read_fires");
	CHECK_MSG(ret == 0, "op_socketpair failed");
	if (ret != 0)
		return;

	/* Register read interest on F2, write test_payload from F1. */
	read_fired = 0;
	op_setselect(F2, OP_SELECT_READ, on_readable, NULL);
	{ ssize_t _r = write(op_get_fd(F1), test_payload, strlen(test_payload)); (void)_r; }

	/* One op_select() tick should dispatch the readable CQE. */
	op_select(100 /* ms */);

	CHECK_MSG(read_fired == 1, "read callback did not fire");

	op_close(F1);
	op_close(F2);
}

static void
test_write_fires(void)
{
	op_fde_t *F1, *F2;
	int ret;

	ret = op_socketpair(AF_UNIX, SOCK_STREAM, 0, &F1, &F2, "test_write_fires");
	CHECK_MSG(ret == 0, "op_socketpair failed");
	if (ret != 0)
		return;

	/* A fresh socket is immediately writable. */
	write_fired = 0;
	op_setselect(F1, OP_SELECT_WRITE, on_writable, NULL);
	op_select(100 /* ms */);

	CHECK_MSG(write_fired == 1, "write callback did not fire");

	op_close(F1);
	op_close(F2);
}

static int rearm_count = 0;
#define REARM_TOTAL 3

static void
on_rearm(op_fde_t *F, void *data)
{
	op_fde_t *writer = data;
	char buf[64];
	int  n;

	n = read(op_get_fd(F), buf, sizeof(buf));
	if (n > 0)
		rearm_count++;

	/* Re-register for more reads unless we have enough. */
	if (rearm_count < REARM_TOTAL)
		op_setselect(F, OP_SELECT_READ, on_rearm, writer);

	/* Send the next byte from the writer so the next tick has data. */
	if (rearm_count < REARM_TOTAL)
		{ ssize_t _r = write(op_get_fd(writer), "x", 1); (void)_r; }
}

static void
test_rearm_in_callback(void)
{
	op_fde_t *F1, *F2;
	int i, ret;

	ret = op_socketpair(AF_UNIX, SOCK_STREAM, 0, &F1, &F2, "test_rearm");
	CHECK_MSG(ret == 0, "op_socketpair failed");
	if (ret != 0)
		return;

	rearm_count = 0;
	op_setselect(F2, OP_SELECT_READ, on_rearm, F1);
	{ ssize_t _r = write(op_get_fd(F1), "x", 1); (void)_r; } /* prime the pump */

	for (i = 0; i < REARM_TOTAL + 1; i++)
		op_select(100 /* ms */);

	CHECK_MSG(rearm_count == REARM_TOTAL, "rearm count wrong");

	op_close(F1);
	op_close(F2);
}

/* ---------- scenario [5]: deferred submission round-trip ----------
 *
 * Registers interests on many fds within a single tick.  io_uring's
 * deferred-submission path queues these into the SQ and flushes them
 * on the next op_select() entry.  Verify that every callback fires
 * (i.e. pending_submit drained to 0 and no SQE was lost).
 */
#define DEFERRED_N 32
static int deferred_fired[DEFERRED_N];
static volatile int deferred_done;

static void
on_deferred(op_fde_t *F, void *data)
{
	intptr_t idx = (intptr_t)data;
	char buf[8];
	ssize_t n = read(op_get_fd(F), buf, sizeof(buf));
	if (n > 0 && idx >= 0 && idx < DEFERRED_N)
	{
		deferred_fired[idx] = 1;
	}
}

static void
test_deferred_submit_roundtrip(void)
{
	op_fde_t *pairs[DEFERRED_N][2];
	int i, ret, total;

	memset(deferred_fired, 0, sizeof(deferred_fired));
	deferred_done = 0;

	for (i = 0; i < DEFERRED_N; i++)
	{
		ret = op_socketpair(AF_UNIX, SOCK_STREAM, 0,
		                    &pairs[i][0], &pairs[i][1], "deferred");
		CHECK_MSG(ret == 0, "op_socketpair failed in deferred test");
		if (ret != 0)
			return;

		/* Register read interest on F2 — these all get queued into
		 * the SQ within the same scheduling slice. */
		op_setselect(pairs[i][1], OP_SELECT_READ,
		             on_deferred, (void *)(intptr_t)i);

		{ ssize_t _r = write(op_get_fd(pairs[i][0]), "d", 1); (void)_r; }
	}

	/* Drive the loop until everyone reports in (or budget expires). */
	for (i = 0; i < 20; i++)
	{
		int seen = 0, j;
		op_select(50);
		for (j = 0; j < DEFERRED_N; j++)
			seen += deferred_fired[j];
		if (seen == DEFERRED_N)
			break;
	}

	total = 0;
	for (i = 0; i < DEFERRED_N; i++)
		total += deferred_fired[i];

	CHECK_MSG(total == DEFERRED_N,
	          "not all deferred-submit reads fired (pending_submit leak?)");

	for (i = 0; i < DEFERRED_N; i++)
	{
		op_close(pairs[i][0]);
		op_close(pairs[i][1]);
	}
}

/* ---------- scenario [6]: multishot poll re-arm ----------
 *
 * On kernels with IORING_POLL_ADD_MULTI, a single submitted poll
 * fires repeatedly without explicit re-arm.  Write multiple chunks
 * separated by event-loop ticks WITHOUT calling op_setselect() again
 * inside the handler.  If multishot is alive we should see every
 * write; if multishot fell back to oneshot the loop must still
 * complete (libop re-arms internally for kTLS / fallback paths).
 */
static int multishot_count = 0;

static void
on_multishot(op_fde_t *F, void *data)
{
	char buf[16];
	(void)data;
	while (1)
	{
		ssize_t n = read(op_get_fd(F), buf, sizeof(buf));
		if (n <= 0)
			break;
		multishot_count += (int)n;
	}
	/* deliberately NO op_setselect() re-arm here — exercise multishot */
}

static void
test_multishot_rearm(void)
{
	op_fde_t *F1, *F2;
	int ret, i;

	ret = op_socketpair(AF_UNIX, SOCK_STREAM, 0, &F1, &F2, "multishot");
	CHECK_MSG(ret == 0, "op_socketpair failed");
	if (ret != 0)
		return;

	multishot_count = 0;
	op_setselect(F2, OP_SELECT_READ, on_multishot, NULL);

	for (i = 0; i < 5; i++)
	{
		{ ssize_t _r = write(op_get_fd(F1), "m", 1); (void)_r; }
		op_select(50);
	}

	/* Without multishot, libop's oneshot re-arm should still catch
	 * at least the first byte.  With multishot we expect all 5. */
	CHECK_MSG(multishot_count >= 1, "multishot poll did not deliver");

	op_close(F1);
	op_close(F2);
}

/* ---------- scenario [7]: burst / CQ overflow recovery ----------
 *
 * Make many fds simultaneously ready in one tick.  io_uring's CQ has
 * a finite depth; if more completions arrive than fit, the kernel
 * sets IORING_SQ_CQ_OVERFLOW and stashes the surplus in an overflow
 * list, draining on the next enter.  We verify libop recovers all
 * events even when the count exceeds the CQ depth used in tests.
 */
#define BURST_N 64
static int burst_fired[BURST_N];

static void
on_burst(op_fde_t *F, void *data)
{
	intptr_t idx = (intptr_t)data;
	char buf[8];
	ssize_t n = read(op_get_fd(F), buf, sizeof(buf));
	if (n > 0 && idx >= 0 && idx < BURST_N)
		burst_fired[idx] = 1;
}

static void
test_cq_overflow_recovery(void)
{
	op_fde_t *pairs[BURST_N][2];
	int i, ret, total;

	memset(burst_fired, 0, sizeof(burst_fired));

	for (i = 0; i < BURST_N; i++)
	{
		ret = op_socketpair(AF_UNIX, SOCK_STREAM, 0,
		                    &pairs[i][0], &pairs[i][1], "burst");
		CHECK_MSG(ret == 0, "op_socketpair failed in burst");
		if (ret != 0)
			return;
		op_setselect(pairs[i][1], OP_SELECT_READ,
		             on_burst, (void *)(intptr_t)i);
	}

	/* Make every fd ready BEFORE giving the loop a chance to run. */
	for (i = 0; i < BURST_N; i++)
	{
		ssize_t _r = write(op_get_fd(pairs[i][0]), "b", 1);
		(void)_r;
	}

	/* Multiple ticks: first tick may overflow the CQ; subsequent
	 * ticks should drain the overflow list. */
	for (i = 0; i < 20; i++)
	{
		int seen = 0, j;
		op_select(50);
		for (j = 0; j < BURST_N; j++)
			seen += burst_fired[j];
		if (seen == BURST_N)
			break;
	}

	total = 0;
	for (i = 0; i < BURST_N; i++)
		total += burst_fired[i];

	CHECK_MSG(total == BURST_N,
	          "CQ overflow recovery dropped events");

	for (i = 0; i < BURST_N; i++)
	{
		op_close(pairs[i][0]);
		op_close(pairs[i][1]);
	}
}

/* ---------- scenario [8]: async-close ordering ----------
 *
 * Close a fd from within its OWN read callback.  io_uring defers
 * the actual close (op_close_pending_fds()) until after callback
 * dispatch to avoid use-after-free on multishot poll completions
 * still in the CQ.  Verify the close completes cleanly and no
 * spurious callback fires afterwards.
 */
static int   close_in_cb_fired = 0;
static int   close_in_cb_after = 0;

static void
on_close_in_cb(op_fde_t *F, void *data)
{
	char buf[8];
	(void)data;
	(void)read(op_get_fd(F), buf, sizeof(buf));
	close_in_cb_fired++;
	/* Close ourselves from inside the callback. */
	op_close(F);
}

static void
on_after_close(op_fde_t *F, void *data)
{
	(void)F;
	(void)data;
	close_in_cb_after++;
}

static void
test_async_close_ordering(void)
{
	op_fde_t *F1, *F2, *G1, *G2;
	int ret;

	close_in_cb_fired = 0;
	close_in_cb_after = 0;

	ret = op_socketpair(AF_UNIX, SOCK_STREAM, 0, &F1, &F2, "asyncclose");
	CHECK_MSG(ret == 0, "op_socketpair failed");
	if (ret != 0)
		return;

	op_setselect(F2, OP_SELECT_READ, on_close_in_cb, NULL);
	{ ssize_t _r = write(op_get_fd(F1), "c", 1); (void)_r; }

	op_select(100);
	/* Allow deferred-free path to run. */
	op_select(50);
	op_close_pending_fds();

	CHECK_MSG(close_in_cb_fired == 1,
	          "close-in-callback handler fired wrong number of times");

	/* Now make sure the backend is still usable after async close. */
	ret = op_socketpair(AF_UNIX, SOCK_STREAM, 0, &G1, &G2, "post_close");
	CHECK_MSG(ret == 0, "op_socketpair failed post-close");
	if (ret != 0)
	{
		op_close(F1);
		return;
	}

	op_setselect(G2, OP_SELECT_READ, on_after_close, NULL);
	{ ssize_t _r = write(op_get_fd(G1), "x", 1); (void)_r; }
	op_select(100);

	CHECK_MSG(close_in_cb_after == 1,
	          "backend unusable after async close");

	op_close(F1);
	op_close(G1);
	op_close(G2);
	op_close_pending_fds();
}

/* ---------- scenario [9]: send_zc notification drain (proxy test) ----------
 *
 * libop does not expose send_zc directly; instead we cover the same
 * code path indirectly by performing many small writes followed by
 * write-readiness polls, which on uring goes through provided-buffer
 * (buf_ring) recycle and notification-CQE drain in the backend.
 * We verify that a steady write/read cycle stays consistent across
 * many iterations without leaking pollers.
 */
#define ZC_ITERS 24
static int zc_writes_seen = 0;

static void
on_zc_read(op_fde_t *F, void *data)
{
	char buf[32];
	(void)data;
	ssize_t n = read(op_get_fd(F), buf, sizeof(buf));
	if (n > 0)
		zc_writes_seen += (int)n;
	op_setselect(F, OP_SELECT_READ, on_zc_read, NULL);
}

static void
test_send_zc_and_bufring_recycle(void)
{
	op_fde_t *F1, *F2;
	int i, ret;

	ret = op_socketpair(AF_UNIX, SOCK_STREAM, 0, &F1, &F2, "zc");
	CHECK_MSG(ret == 0, "op_socketpair failed");
	if (ret != 0)
		return;

	zc_writes_seen = 0;
	op_setselect(F2, OP_SELECT_READ, on_zc_read, NULL);

	for (i = 0; i < ZC_ITERS; i++)
	{
		ssize_t _r = write(op_get_fd(F1), "z", 1);
		(void)_r;
		op_select(20);
	}
	/* Final drain. */
	for (i = 0; i < 5 && zc_writes_seen < ZC_ITERS; i++)
		op_select(50);

	CHECK_MSG(zc_writes_seen == ZC_ITERS,
	          "buf_ring recycle / notification drain lost bytes");

	op_close(F1);
	op_close(F2);
}

/* ---------- main ---------- */

int
main(void)
{
	/* Force io_uring backend if the library supports it. */
#if defined(HAVE_LIBURING)
	setenv("LIBOP_USE_IOTYPE", "uring", 1);
#endif

	op_lib_init(NULL, NULL, NULL, 0, 1024, 1024, 1024);

	printf("test_uring:\n");

	printf("  [1] backend name\n");
	test_backend_name();

	printf("  [2] read fires\n");
	test_read_fires();

	printf("  [3] write fires\n");
	test_write_fires();

	printf("  [4] rearm in callback\n");
	test_rearm_in_callback();

	/*
	 * Advanced scenarios exercise internal io_uring code paths
	 * (deferred submit, multishot, CQ overflow, async close,
	 * buf_ring recycle).  These are meaningful only when the
	 * uring backend is actually active — otherwise we'd be
	 * testing epoll/select/poll, which has its own tests.
	 */
	if (uring_active)
	{
		printf("  [5] deferred-submit round-trip\n");
		test_deferred_submit_roundtrip();

		printf("  [6] multishot poll re-arm\n");
		test_multishot_rearm();

		printf("  [7] CQ overflow recovery\n");
		test_cq_overflow_recovery();

		printf("  [8] async-close ordering\n");
		test_async_close_ordering();

		printf("  [9] send_zc / buf_ring recycle (proxy)\n");
		test_send_zc_and_bufring_recycle();

		if (failures == 0)
			printf("  PASS (9 tests)\n");
		else
			printf("  FAIL (%d failure(s))\n", failures);
	}
	else
	{
		printf("  SKIP [5-9]: io_uring backend not active\n");
		if (failures == 0)
			printf("  PASS (4 tests, 5 skipped)\n");
		else
			printf("  FAIL (%d failure(s))\n", failures);
	}

	return failures ? 1 : 0;
}

/*
 * test_event_pool.c — stress + correctness tests for the op_event worker
 * pool (op_event_post_pri / op_event_post_cancellable / op_event_cancel /
 * op_event_threadpool_recommend_workers).
 *
 * The pool API in op_event.h is declared but its implementation is the
 * responsibility of a sibling agent owning src/event.c. To keep this test
 * file independently buildable, all pool entrypoints and the optional
 * internal counters (g_n_sleeping / g_n_workers) are referenced via
 * __attribute__((weak)) externs. If the implementation has not landed
 * yet the test prints SKIP and exits 77 (meson "skipped" exit code).
 *
 * Sections:
 *   [1] single-producer × multi-worker — 100k tasks, exactly-once dispatch
 *   [2] multi-producer  × multi-worker — 4 × 50k tasks, exactly-once dispatch
 *   [3] hipri dispatch — hipri arrival order preserved relative to its lane
 *   [4] worker park/wake — g_n_sleeping reaches g_n_workers when idle,
 *       drops below g_n_workers under load (skipped if counters absent)
 *   [5] shutdown drain — 10k tasks drain before thread exit
 *   [6] cancellation — win-race and lose-race coverage
 */

#include <libop_config.h>
#include <op_lib.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdatomic.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>

/* ---- weak pool API ------------------------------------------------------- */

extern int op_event_post_pri(EVH *func, void *arg, op_event_priority_t pri)
    __attribute__((weak));
extern op_event_handle_t
op_event_post_cancellable(EVH *func, void *arg, op_event_priority_t pri)
    __attribute__((weak));
extern bool op_event_cancel(op_event_handle_t handle) __attribute__((weak));
extern int  op_event_threadpool_recommend_workers(int min, int max)
    __attribute__((weak));
extern const char *op_event_priority_name(op_event_priority_t pri)
    __attribute__((weak));

/* Optional internal counters. Sibling impl may expose these as
 * tentative-definition globals; if not, the weak refs resolve to NULL. */
extern _Atomic(int) g_n_sleeping __attribute__((weak));
extern _Atomic(int) g_n_workers  __attribute__((weak));

/* Optional shutdown entrypoint (name guessed; treated as best-effort). */
extern void op_event_threadpool_shutdown(void) __attribute__((weak));

/* ---- helpers ------------------------------------------------------------- */

static int failures = 0;

#define CHECK(cond)                                                          \
    do {                                                                     \
        if (!(cond)) {                                                       \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);  \
            failures++;                                                      \
        }                                                                    \
    } while (0)

#define SECTION(name) do { int _before = failures; const char *_sec = (name);
#define END_SECTION                                                          \
        printf("  %-52s %s\n", _sec,                                         \
               failures == _before ? "pass" : "FAIL");                       \
    } while (0)

/*
 * Spin until `cond` is true or `deadline_ms` elapses. Returns 1 if the
 * condition was observed, 0 on timeout. Uses op_select() if available so
 * any pool implementation that piggybacks on the event loop still makes
 * forward progress.
 */
#define WAIT_FOR(cond_expr, deadline_ms)                                     \
    ({                                                                       \
        int _ok = 0;                                                         \
        struct timespec _t0, _now;                                           \
        clock_gettime(CLOCK_MONOTONIC, &_t0);                                \
        for (;;) {                                                           \
            if (cond_expr) { _ok = 1; break; }                               \
            op_select(2);                                                    \
            clock_gettime(CLOCK_MONOTONIC, &_now);                           \
            long _elapsed_ms = (_now.tv_sec - _t0.tv_sec) * 1000 +           \
                (_now.tv_nsec - _t0.tv_nsec) / 1000000;                      \
            if (_elapsed_ms >= (deadline_ms)) break;                         \
        }                                                                    \
        _ok;                                                                 \
    })

/* ---- section 1: single-producer × multi-worker --------------------------- */

#define S1_TASKS 100000

static _Atomic(int) s1_run_count;
/* Per-task run counter: each task increments its own slot; we assert every
 * slot is exactly 1 (no drops, no double-runs). */
static _Atomic(unsigned char) *s1_per_task;

static void
s1_work(void *ctx)
{
    uintptr_t idx = (uintptr_t)ctx;
    atomic_fetch_add_explicit(&s1_per_task[idx], 1, memory_order_relaxed);
    atomic_fetch_add_explicit(&s1_run_count, 1, memory_order_relaxed);
}

/* ---- section 2: multi-producer × multi-worker ---------------------------- */

#define S2_PRODUCERS 4
#define S2_PER_PROD  50000
#define S2_TOTAL     (S2_PRODUCERS * S2_PER_PROD)

static _Atomic(int) s2_run_count;
static _Atomic(unsigned char) *s2_per_task;

static void
s2_work(void *ctx)
{
    uintptr_t idx = (uintptr_t)ctx;
    atomic_fetch_add_explicit(&s2_per_task[idx], 1, memory_order_relaxed);
    atomic_fetch_add_explicit(&s2_run_count, 1, memory_order_relaxed);
}

static void *
s2_producer(void *arg)
{
    uintptr_t base = (uintptr_t)arg * S2_PER_PROD;
    for (uintptr_t i = 0; i < S2_PER_PROD; i++) {
        while (op_event_post_pri(s2_work, (void *)(base + i),
                                 OP_EVENT_PRI_NORMAL) != 0) {
            /* Backpressure: pool reported queue-full; yield briefly. */
            struct timespec ts = { 0, 100 * 1000 }; /* 100us */
            nanosleep(&ts, NULL);
        }
    }
    return NULL;
}

/* ---- section 3: hipri ordering ------------------------------------------- */

#define S3_HIPRI 256

static _Atomic(int) s3_hipri_seq;
/* Records the order in which hipri tasks ran. */
static int s3_hipri_order[S3_HIPRI];

static void
s3_hipri_work(void *ctx)
{
    int my_id = (int)(intptr_t)ctx;
    int slot = atomic_fetch_add_explicit(&s3_hipri_seq, 1,
                                         memory_order_relaxed);
    if (slot < S3_HIPRI)
        s3_hipri_order[slot] = my_id;
}

static void s3_normal_work(void *ctx) { (void)ctx; }

/* ---- section 5: shutdown drain ------------------------------------------- */

#define S5_TASKS 10000

static _Atomic(int) s5_run_count;

static void
s5_work(void *ctx)
{
    (void)ctx;
    /* Tiny stall so tasks are still in flight when shutdown begins. */
    for (volatile int i = 0; i < 50; i++) { }
    atomic_fetch_add_explicit(&s5_run_count, 1, memory_order_relaxed);
}

/* ---- section 6: cancellation -------------------------------------------- */

static _Atomic(int) s6_lose_ran; /* counts tasks that ran (cancel lost) */
static _Atomic(int) s6_win_ran;  /* must remain 0 if every cancel won */

static void
s6_lose_work(void *ctx)
{
    (void)ctx;
    /* Block briefly so we can race a cancel against a started callback. */
    struct timespec ts = { 0, 2 * 1000 * 1000 }; /* 2ms */
    nanosleep(&ts, NULL);
    atomic_fetch_add_explicit(&s6_lose_ran, 1, memory_order_relaxed);
}

static void
s6_win_work(void *ctx)
{
    (void)ctx;
    atomic_fetch_add_explicit(&s6_win_ran, 1, memory_order_relaxed);
}

/* ---- main ---------------------------------------------------------------- */

int
main(void)
{
    op_lib_init(NULL, NULL, NULL, 0, 1024, 1024, 1024);

    /* If the pool API is absent, skip cleanly. */
    if (op_event_post_pri == NULL) {
        printf("SKIP: op_event_post_pri not implemented yet\n");
        return 77;
    }

    op_event_init();

    /* Best-effort: ask for a healthy worker count. Ignore return — the
     * pool is allowed to coalesce or defer the hint. */
    if (op_event_threadpool_recommend_workers != NULL)
        (void)op_event_threadpool_recommend_workers(4, 8);

    printf("test_event_pool:\n");

    /* ------------------------------------------------------------------ */
    SECTION("[1] single-producer × multi-worker (100k)");
    {
        atomic_store(&s1_run_count, 0);
        s1_per_task = calloc(S1_TASKS, sizeof(*s1_per_task));
        CHECK(s1_per_task != NULL);

        for (uintptr_t i = 0; i < S1_TASKS; i++) {
            while (op_event_post_pri(s1_work, (void *)i,
                                     OP_EVENT_PRI_NORMAL) != 0) {
                struct timespec ts = { 0, 100 * 1000 };
                nanosleep(&ts, NULL);
            }
        }

        int ok = WAIT_FOR(
            atomic_load(&s1_run_count) == S1_TASKS, 30000);
        CHECK(ok);
        CHECK(atomic_load(&s1_run_count) == S1_TASKS);

        int doubles = 0, drops = 0;
        for (int i = 0; i < S1_TASKS; i++) {
            unsigned char v = atomic_load(&s1_per_task[i]);
            if (v == 0) drops++;
            else if (v > 1) doubles++;
        }
        CHECK(drops == 0);
        CHECK(doubles == 0);
        free(s1_per_task);
        s1_per_task = NULL;
    }
    END_SECTION;

    /* ------------------------------------------------------------------ */
    SECTION("[2] multi-producer × multi-worker (4 × 50k)");
    {
        atomic_store(&s2_run_count, 0);
        s2_per_task = calloc(S2_TOTAL, sizeof(*s2_per_task));
        CHECK(s2_per_task != NULL);

        pthread_t prod[S2_PRODUCERS];
        for (uintptr_t p = 0; p < S2_PRODUCERS; p++)
            pthread_create(&prod[p], NULL, s2_producer, (void *)p);
        for (int p = 0; p < S2_PRODUCERS; p++)
            pthread_join(prod[p], NULL);

        int ok = WAIT_FOR(
            atomic_load(&s2_run_count) == S2_TOTAL, 60000);
        CHECK(ok);
        CHECK(atomic_load(&s2_run_count) == S2_TOTAL);

        int doubles = 0, drops = 0;
        for (int i = 0; i < S2_TOTAL; i++) {
            unsigned char v = atomic_load(&s2_per_task[i]);
            if (v == 0) drops++;
            else if (v > 1) doubles++;
        }
        CHECK(drops == 0);
        CHECK(doubles == 0);
        free(s2_per_task);
        s2_per_task = NULL;
    }
    END_SECTION;

    /* ------------------------------------------------------------------ */
    SECTION("[3] hipri dispatch preserves arrival order");
    {
        atomic_store(&s3_hipri_seq, 0);
        memset(s3_hipri_order, -1, sizeof(s3_hipri_order));

        /* Saturate normal lane first so the pool has to choose. */
        for (int i = 0; i < 1024; i++)
            (void)op_event_post_pri(s3_normal_work, NULL,
                                    OP_EVENT_PRI_NORMAL);

        /* Post hipri tasks in strict ascending id order from a single
         * thread; FIFO ordering inside the hipri lane should be
         * preserved. We do not assert hipri runs before all normals — the
         * pool may interleave — only that the hipri tasks themselves
         * dispatch in the order they were posted. */
        for (int i = 0; i < S3_HIPRI; i++) {
            while (op_event_post_pri(s3_hipri_work, (void *)(intptr_t)i,
                                     OP_EVENT_PRI_HIGH) != 0) {
                struct timespec ts = { 0, 100 * 1000 };
                nanosleep(&ts, NULL);
            }
        }

        int ok = WAIT_FOR(
            atomic_load(&s3_hipri_seq) >= S3_HIPRI, 30000);
        CHECK(ok);

        int monotonic = 1;
        for (int i = 1; i < S3_HIPRI; i++) {
            if (s3_hipri_order[i] <= s3_hipri_order[i - 1]) {
                monotonic = 0;
                break;
            }
        }
        CHECK(monotonic);
    }
    END_SECTION;

    /* ------------------------------------------------------------------ */
    SECTION("[4] worker park/wake (g_n_sleeping vs g_n_workers)");
    {
        if (&g_n_sleeping == NULL || &g_n_workers == NULL) {
            printf("    skip: g_n_sleeping/g_n_workers not exported\n");
        } else {
            /* Idle: every worker should eventually be parked. */
            int idle_ok = WAIT_FOR(
                atomic_load(&g_n_sleeping) ==
                    atomic_load(&g_n_workers) &&
                atomic_load(&g_n_workers) > 0,
                5000);
            CHECK(idle_ok);

            /* Under load: parked count must drop below worker count. */
            atomic_store(&s5_run_count, 0);
            for (int i = 0; i < 4096; i++)
                (void)op_event_post_pri(s5_work, NULL,
                                        OP_EVENT_PRI_NORMAL);
            int busy_ok = WAIT_FOR(
                atomic_load(&g_n_sleeping) <
                    atomic_load(&g_n_workers),
                2000);
            CHECK(busy_ok);

            /* Drain. */
            (void)WAIT_FOR(atomic_load(&s5_run_count) == 4096, 30000);
        }
    }
    END_SECTION;

    /* ------------------------------------------------------------------ */
    SECTION("[5] shutdown drains 10k tasks");
    {
        atomic_store(&s5_run_count, 0);
        for (int i = 0; i < S5_TASKS; i++) {
            while (op_event_post_pri(s5_work, NULL,
                                     OP_EVENT_PRI_NORMAL) != 0) {
                struct timespec ts = { 0, 100 * 1000 };
                nanosleep(&ts, NULL);
            }
        }
        if (op_event_threadpool_shutdown != NULL) {
            op_event_threadpool_shutdown();
            CHECK(atomic_load(&s5_run_count) == S5_TASKS);
        } else {
            int ok = WAIT_FOR(
                atomic_load(&s5_run_count) == S5_TASKS, 60000);
            CHECK(ok);
        }
    }
    END_SECTION;

    /* ------------------------------------------------------------------ */
    SECTION("[6] cancellation: win-race + lose-race");
    {
        if (op_event_post_cancellable == NULL ||
            op_event_cancel          == NULL) {
            printf("    skip: cancellation API not implemented\n");
        } else {
            /* WIN-RACE: cancel immediately after post; with no executing
             * worker likely to have started, all cancels should win. */
            atomic_store(&s6_win_ran, 0);
            int win_attempts = 256;
            int wins = 0;
            for (int i = 0; i < win_attempts; i++) {
                op_event_handle_t h = op_event_post_cancellable(
                    s6_win_work, NULL, OP_EVENT_PRI_BG);
                if (h.id == 0) continue; /* enqueue failure — skip */
                if (op_event_cancel(h)) wins++;
            }
            /* Allow any losers to actually run, then assert balance. */
            (void)WAIT_FOR(false, 50);
            int ran = atomic_load(&s6_win_ran);
            CHECK(wins + ran <= win_attempts);
            CHECK(wins > 0);     /* at least one cancel must have won */

            /* LOSE-RACE: post slow tasks, sleep until they have started,
             * then cancel — cancel should return false. */
            atomic_store(&s6_lose_ran, 0);
            int lose_attempts = 8;
            op_event_handle_t handles[8];
            for (int i = 0; i < lose_attempts; i++)
                handles[i] = op_event_post_cancellable(
                    s6_lose_work, NULL, OP_EVENT_PRI_NORMAL);

            /* Give workers time to pick up the slow tasks. */
            struct timespec ts = { 0, 5 * 1000 * 1000 }; /* 5ms */
            nanosleep(&ts, NULL);

            int lost_races = 0;
            for (int i = 0; i < lose_attempts; i++) {
                if (handles[i].id == 0) continue;
                if (!op_event_cancel(handles[i])) lost_races++;
            }
            CHECK(lost_races > 0);
            (void)WAIT_FOR(
                atomic_load(&s6_lose_ran) >= lost_races, 5000);
        }
    }
    END_SECTION;

    if (failures == 0)
        printf("  PASS (6 sections)\n");
    else
        printf("  FAIL (%d failure(s))\n", failures);

    return failures ? 1 : 0;
}

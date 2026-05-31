/*
 * test_mpmc.c — unit and stress tests for op_mpmc_t (Vyukov MPMC queue).
 *
 * Scenarios:
 *   1. Single-thread FIFO order
 *   2. Concurrent 4 producers + 4 consumers, each item observed once
 *   3. Full-queue rejection and recovery
 *   4. Wraparound: push/pop > capacity repeatedly
 *   5. Batch push/pop round-trip (push_batch + pop_batch)
 */

#include <op_mpmc.h>

#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(cond) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "[FAIL] %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            exit(1); \
        } \
    } while (0)

#define SECTION(name) printf("  [%s]\n", name)

#define PTR(n) ((void *)(uintptr_t)(n))
#define VAL(p) ((uintptr_t)(p))

/* ======================================================================== */

static void
test_single_thread_fifo(void)
{
    SECTION("single-thread FIFO order");

    op_mpmc_t q;
    CHECK(op_mpmc_init(&q, 16) == 0);

    /* Alternating push/pop preserves order. */
    for (uintptr_t i = 1; i <= 8; i++)
        CHECK(op_mpmc_push(&q, PTR(i)) == 1);
    for (uintptr_t i = 1; i <= 8; i++) {
        void *p = op_mpmc_pop(&q);
        CHECK(VAL(p) == i);
    }
    CHECK(op_mpmc_pop(&q) == NULL);

    /* Interleaved single-step. */
    for (uintptr_t i = 100; i < 200; i++) {
        CHECK(op_mpmc_push(&q, PTR(i)) == 1);
        void *p = op_mpmc_pop(&q);
        CHECK(VAL(p) == i);
    }

    op_mpmc_destroy(&q);
}

/* ======================================================================== */

static void
test_full_rejection(void)
{
    SECTION("full-queue rejection");

    op_mpmc_t q;
    CHECK(op_mpmc_init(&q, 8) == 0);

    for (uintptr_t i = 1; i <= 8; i++)
        CHECK(op_mpmc_push(&q, PTR(i)) == 1);

    /* Queue full; subsequent push must fail. */
    CHECK(op_mpmc_push(&q, PTR(999)) == 0);
    CHECK(op_mpmc_push(&q, PTR(999)) == 0);

    /* Pop one, push succeeds again. */
    void *p = op_mpmc_pop(&q);
    CHECK(VAL(p) == 1);
    CHECK(op_mpmc_push(&q, PTR(9)) == 1);

    /* Now full again. */
    CHECK(op_mpmc_push(&q, PTR(999)) == 0);

    /* Drain remaining in FIFO order: 2..8, then 9. */
    for (uintptr_t i = 2; i <= 9; i++) {
        p = op_mpmc_pop(&q);
        CHECK(VAL(p) == i);
    }
    CHECK(op_mpmc_pop(&q) == NULL);

    op_mpmc_destroy(&q);
}

/* ======================================================================== */

static void
test_wraparound(void)
{
    SECTION("wraparound > capacity");

    op_mpmc_t q;
    CHECK(op_mpmc_init(&q, 4) == 0);

    /* Push/pop 1000 items through a 4-slot queue. */
    for (uintptr_t i = 1; i <= 1000; i++) {
        CHECK(op_mpmc_push(&q, PTR(i)) == 1);
        void *p = op_mpmc_pop(&q);
        CHECK(VAL(p) == i);
    }

    /* Batched: fill, drain, repeat. */
    for (int rep = 0; rep < 100; rep++) {
        for (uintptr_t i = 1; i <= 4; i++)
            CHECK(op_mpmc_push(&q, PTR(rep * 10 + i)) == 1);
        CHECK(op_mpmc_push(&q, PTR(0xDEAD)) == 0);  /* full */
        for (uintptr_t i = 1; i <= 4; i++) {
            void *p = op_mpmc_pop(&q);
            CHECK(VAL(p) == (uintptr_t)(rep * 10 + i));
        }
        CHECK(op_mpmc_pop(&q) == NULL);
    }

    op_mpmc_destroy(&q);
}

/* ======================================================================== */

#define NTHREADS    4
#define PER_THREAD  25000
#define TOTAL_ITEMS (NTHREADS * PER_THREAD)
#define QCAP        1024

typedef struct {
    op_mpmc_t *q;
    int        tid;
    _Atomic uint64_t *seen;  /* counter array of length TOTAL_ITEMS */
    _Atomic uint64_t *produced;
    _Atomic uint64_t *consumed;
    _Atomic int      *done_producing;
} worker_ctx_t;

static void *
producer_thread(void *arg)
{
    worker_ctx_t *ctx = (worker_ctx_t *)arg;
    uintptr_t base = (uintptr_t)ctx->tid * PER_THREAD;

    for (int i = 0; i < PER_THREAD; i++) {
        /* Encode an item id in [1 .. TOTAL_ITEMS]. */
        uintptr_t id = base + (uintptr_t)i + 1;
        while (op_mpmc_push(ctx->q, PTR(id)) == 0) {
            /* Spin: queue full. */
        }
        atomic_fetch_add_explicit(ctx->produced, 1, memory_order_relaxed);
    }
    return NULL;
}

static void *
consumer_thread(void *arg)
{
    worker_ctx_t *ctx = (worker_ctx_t *)arg;

    for (;;) {
        void *p = op_mpmc_pop(ctx->q);
        if (p == NULL) {
            /* Producers done and queue drained? */
            if (atomic_load_explicit(ctx->done_producing,
                                     memory_order_acquire) == NTHREADS) {
                /* Re-check after seeing done flag. */
                p = op_mpmc_pop(ctx->q);
                if (p == NULL)
                    return NULL;
            } else {
                continue;
            }
        }
        uintptr_t id = VAL(p);
        CHECK(id >= 1 && id <= TOTAL_ITEMS);
        uint64_t prev = atomic_fetch_add_explicit(&ctx->seen[id - 1], 1,
                                                  memory_order_relaxed);
        CHECK(prev == 0);  /* observed exactly once */
        atomic_fetch_add_explicit(ctx->consumed, 1, memory_order_relaxed);
    }
}

static void
test_concurrent_mpmc(void)
{
    SECTION("concurrent 4P/4C, exactly-once");

    op_mpmc_t q;
    CHECK(op_mpmc_init(&q, QCAP) == 0);

    _Atomic uint64_t *seen = calloc(TOTAL_ITEMS, sizeof(_Atomic uint64_t));
    CHECK(seen != NULL);
    _Atomic uint64_t produced = 0;
    _Atomic uint64_t consumed = 0;
    _Atomic int done_producing = 0;

    pthread_t prod[NTHREADS], cons[NTHREADS];
    worker_ctx_t pctx[NTHREADS], cctx[NTHREADS];

    for (int i = 0; i < NTHREADS; i++) {
        pctx[i] = (worker_ctx_t){ &q, i, seen, &produced, &consumed,
                                  &done_producing };
        cctx[i] = (worker_ctx_t){ &q, i, seen, &produced, &consumed,
                                  &done_producing };
    }

    for (int i = 0; i < NTHREADS; i++)
        CHECK(pthread_create(&cons[i], NULL, consumer_thread, &cctx[i]) == 0);
    for (int i = 0; i < NTHREADS; i++)
        CHECK(pthread_create(&prod[i], NULL, producer_thread, &pctx[i]) == 0);

    for (int i = 0; i < NTHREADS; i++)
        pthread_join(prod[i], NULL);

    /* Signal consumers: all producers done. */
    atomic_store_explicit(&done_producing, NTHREADS, memory_order_release);

    for (int i = 0; i < NTHREADS; i++)
        pthread_join(cons[i], NULL);

    CHECK(atomic_load(&produced) == TOTAL_ITEMS);
    CHECK(atomic_load(&consumed) == TOTAL_ITEMS);

    /* Verify every item observed exactly once. */
    for (size_t i = 0; i < TOTAL_ITEMS; i++)
        CHECK(atomic_load_explicit(&seen[i], memory_order_relaxed) == 1);

    CHECK(op_mpmc_pop(&q) == NULL);

    free(seen);
    op_mpmc_destroy(&q);
}

/* ======================================================================== */

static void
test_batch_round_trip(void)
{
    SECTION("batch push/pop round-trip");

    op_mpmc_t q;
    CHECK(op_mpmc_init(&q, 64) == 0);

    void *in[32];
    void *out[32];

    for (uintptr_t i = 0; i < 32; i++)
        in[i] = PTR(i + 1);

    /* Push 32 in one shot. */
    size_t pushed = op_mpmc_push_batch(&q, in, 32);
    CHECK(pushed == 32);

    /* Push another 32 to fill the queue. */
    void *in2[32];
    for (uintptr_t i = 0; i < 32; i++)
        in2[i] = PTR(i + 100);
    pushed = op_mpmc_push_batch(&q, in2, 32);
    CHECK(pushed == 32);

    /* Now full: batch push should report 0. */
    void *one[1] = { PTR(0xBEEF) };
    CHECK(op_mpmc_push_batch(&q, one, 1) == 0);

    /* Pop first 32 -> matches in[]. */
    size_t popped = op_mpmc_pop_batch(&q, out, 32);
    CHECK(popped == 32);
    for (size_t i = 0; i < 32; i++)
        CHECK(VAL(out[i]) == i + 1);

    /* Pop next 32 -> matches in2[]. */
    popped = op_mpmc_pop_batch(&q, out, 32);
    CHECK(popped == 32);
    for (size_t i = 0; i < 32; i++)
        CHECK(VAL(out[i]) == i + 100);

    /* Empty. */
    CHECK(op_mpmc_pop_batch(&q, out, 32) == 0);

    /* Partial batch pop when only some items available. */
    for (uintptr_t i = 0; i < 5; i++)
        CHECK(op_mpmc_push(&q, PTR(i + 1)) == 1);
    popped = op_mpmc_pop_batch(&q, out, 32);
    CHECK(popped == 5);
    for (size_t i = 0; i < 5; i++)
        CHECK(VAL(out[i]) == i + 1);

    op_mpmc_destroy(&q);
}

/* ======================================================================== */

int
main(void)
{
    printf("== test_mpmc ==\n");

    test_single_thread_fifo();
    test_full_rejection();
    test_wraparound();
    test_batch_round_trip();
    test_concurrent_mpmc();

    printf("[OK] all mpmc tests passed\n");
    return 0;
}

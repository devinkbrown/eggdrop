/*
 * libop/include/op_atomic.h — portable C11 atomics wrapper.
 *
 * On GCC, Clang, and Clang-CL: includes <stdatomic.h> directly.
 *
 * On MSVC (cl.exe) without the Clang frontend, <stdatomic.h> is only
 * available in VS 2022 17.5+ (/std:c17).  For earlier toolchains this
 * header provides a minimal shim backed by Windows Interlocked intrinsics.
 *
 * Only the types and operations actually used in Ophion are covered:
 *   Types:   atomic_int, atomic_uint_fast64_t, atomic_size_t,
 *            atomic_uint_fast32_t, atomic_uint64_t, atomic_uint32_t
 *   Ops:     atomic_load / atomic_load_explicit
 *            atomic_store / atomic_store_explicit
 *            atomic_fetch_add / atomic_fetch_add_explicit
 *            atomic_fetch_sub / atomic_fetch_sub_explicit
 *            atomic_thread_fence
 *            atomic_compare_exchange_strong / _weak
 *   Macro:   _Atomic(T)  — type-specifier with parens form
 *            ATOMIC_VAR_INIT
 *
 * Note: the _Atomic T (qualifier form, no parens) is NOT macro-replaceable
 * on MSVC.  All declarations in Ophion use the atomic_T typedef names
 * (e.g. atomic_int) when targeting MSVC.
 */

#ifndef OP_ATOMIC_H
#define OP_ATOMIC_H

#if !defined(_MSC_VER) || defined(__clang__)

/* =========================================================================
 * GCC / Clang / Clang-CL: use the real stdatomic.h
 * ====================================================================== */
# include <stdatomic.h>

#else /* _MSC_VER && !__clang__ */

/* =========================================================================
 * MSVC (cl.exe) shim using Windows Interlocked intrinsics
 * ====================================================================== */

# ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
# endif
# include <windows.h>
# include <intrin.h>
# include <stdint.h>

/* -------------------------------------------------------------------------
 * Memory order enum
 * On x86/x64 the hardware provides strong ordering; we emit a compiler
 * fence for acquire/release and a full MemoryBarrier() for seq_cst.
 * ---------------------------------------------------------------------- */

typedef enum {
    memory_order_relaxed,
    memory_order_consume,
    memory_order_acquire,
    memory_order_release,
    memory_order_acq_rel,
    memory_order_seq_cst
} memory_order;

/* -------------------------------------------------------------------------
 * _Atomic(T) — type-specifier with parens (e.g. _Atomic(size_t) head)
 * Expands to volatile T.  On x86/x64 volatile reads/writes are
 * sequentially consistent at the hardware level; the compiler fence
 * prevents compile-time reordering.
 * ---------------------------------------------------------------------- */

# define _Atomic(T)  volatile T

/* -------------------------------------------------------------------------
 * Standard atomic type aliases (matching <stdatomic.h> names)
 * ---------------------------------------------------------------------- */

typedef volatile int                 atomic_int;
typedef volatile unsigned int        atomic_uint;
typedef volatile long                atomic_long;
typedef volatile unsigned long       atomic_ulong;
typedef volatile long long           atomic_llong;
typedef volatile unsigned long long  atomic_ullong;

/* Fast/least width types used in Ophion */
typedef volatile int32_t             atomic_int_fast32_t;
typedef volatile uint32_t            atomic_uint_fast32_t;
typedef volatile int64_t             atomic_int_fast64_t;
typedef volatile uint64_t            atomic_uint_fast64_t;
typedef volatile int32_t             atomic_int_least32_t;
typedef volatile uint32_t            atomic_uint_least32_t;
typedef volatile int64_t             atomic_int_least64_t;
typedef volatile uint64_t            atomic_uint_least64_t;
typedef volatile int64_t             atomic_intmax_t;
typedef volatile uint64_t            atomic_uintmax_t;

/* Pointer-width types */
typedef volatile size_t              atomic_size_t;
typedef volatile ptrdiff_t           atomic_ptrdiff_t;

/* Boolean */
typedef volatile int                 atomic_bool;
# define ATOMIC_BOOL_LOCK_FREE  2

/* Convenient aliases for 32 and 64 bit */
typedef volatile uint32_t            atomic_uint32_t;
typedef volatile uint64_t            atomic_uint64_t;
typedef volatile int32_t             atomic_int32_t;
typedef volatile int64_t             atomic_int64_t;

/* -------------------------------------------------------------------------
 * Initialisation
 * ---------------------------------------------------------------------- */

# define ATOMIC_VAR_INIT(v)  (v)

/* -------------------------------------------------------------------------
 * Load
 *
 * On x86/x64, plain volatile reads have acquire semantics at the hardware
 * level.  _ReadBarrier() prevents compiler reordering.
 * ---------------------------------------------------------------------- */

static __forceinline void _op_compiler_barrier(void) { _ReadWriteBarrier(); }

# define atomic_load(obj)                 \
    ((_op_compiler_barrier()), (*(obj)))
# define atomic_load_explicit(obj, order) \
    ((_op_compiler_barrier()), (*(obj)))

/* -------------------------------------------------------------------------
 * Store
 *
 * On x86/x64, volatile stores have release semantics at the hardware level.
 * _WriteBarrier() prevents compiler reordering.  For seq_cst we also emit
 * a full MemoryBarrier() after the store.
 * ---------------------------------------------------------------------- */

# define atomic_store(obj, val) \
    do { _ReadWriteBarrier(); *(obj) = (val); MemoryBarrier(); } while (0)
# define atomic_store_explicit(obj, val, order) \
    do { _ReadWriteBarrier(); *(obj) = (val); \
         if ((order) == memory_order_seq_cst) MemoryBarrier(); \
         else _ReadWriteBarrier(); } while (0)

/* -------------------------------------------------------------------------
 * atomic_fetch_add / atomic_fetch_sub
 *
 * Returns the value BEFORE the addition (same as C11 semantics).
 * Dispatches on pointer type via _Generic (available in VS 2015+).
 * ---------------------------------------------------------------------- */

static __forceinline long
_op_fetch_add_32(volatile long *p, long v)
{
    return InterlockedAdd(p, v) - v;
}

static __forceinline long long
_op_fetch_add_64(volatile long long *p, long long v)
{
    return InterlockedAdd64(p, v) - v;
}

/* For unsigned types we alias through a signed pointer cast — safe on x86. */

# define atomic_fetch_add(obj, val)                            \
    _Generic((obj),                                            \
        volatile int *:               _op_fetch_add_32(       \
                (volatile long *)(obj), (long)(val)),          \
        volatile long *:              _op_fetch_add_32(       \
                (volatile long *)(obj), (long)(val)),          \
        volatile unsigned int *:      _op_fetch_add_32(       \
                (volatile long *)(obj), (long)(val)),          \
        volatile unsigned long *:     _op_fetch_add_32(       \
                (volatile long *)(obj), (long)(val)),          \
        volatile long long *:         _op_fetch_add_64(       \
                (volatile long long *)(obj), (long long)(val)),\
        volatile unsigned long long *:_op_fetch_add_64(       \
                (volatile long long *)(obj), (long long)(val)),\
        volatile int64_t *:           _op_fetch_add_64(       \
                (volatile long long *)(obj), (long long)(val)),\
        volatile uint64_t *:          _op_fetch_add_64(       \
                (volatile long long *)(obj), (long long)(val)) \
    )

# define atomic_fetch_add_explicit(obj, val, order) \
    atomic_fetch_add((obj), (val))

# define atomic_fetch_sub(obj, val) \
    atomic_fetch_add((obj), (0 - (val)))
# define atomic_fetch_sub_explicit(obj, val, order) \
    atomic_fetch_sub((obj), (val))

/* -------------------------------------------------------------------------
 * atomic_fetch_or / atomic_fetch_and
 *
 * Returns the value BEFORE the operation (same as C11 semantics).
 * ---------------------------------------------------------------------- */

static __forceinline long
_op_fetch_or_32(volatile long *p, long v)
{
    return InterlockedOr(p, v);
}

static __forceinline long long
_op_fetch_or_64(volatile long long *p, long long v)
{
    return InterlockedOr64(p, v);
}

static __forceinline long
_op_fetch_and_32(volatile long *p, long v)
{
    return InterlockedAnd(p, v);
}

static __forceinline long long
_op_fetch_and_64(volatile long long *p, long long v)
{
    return InterlockedAnd64(p, v);
}

# define atomic_fetch_or(obj, val)                                 \
    _Generic((obj),                                                \
        volatile int *:               _op_fetch_or_32(             \
                (volatile long *)(obj), (long)(val)),              \
        volatile long *:              _op_fetch_or_32(             \
                (volatile long *)(obj), (long)(val)),              \
        volatile unsigned int *:      _op_fetch_or_32(             \
                (volatile long *)(obj), (long)(val)),              \
        volatile long long *:         _op_fetch_or_64(             \
                (volatile long long *)(obj), (long long)(val)),    \
        volatile unsigned long long *:_op_fetch_or_64(             \
                (volatile long long *)(obj), (long long)(val)),    \
        volatile uint64_t *:          _op_fetch_or_64(             \
                (volatile long long *)(obj), (long long)(val))     \
    )

# define atomic_fetch_or_explicit(obj, val, order) \
    atomic_fetch_or((obj), (val))

# define atomic_fetch_and(obj, val)                                \
    _Generic((obj),                                                \
        volatile int *:               _op_fetch_and_32(            \
                (volatile long *)(obj), (long)(val)),              \
        volatile long *:              _op_fetch_and_32(            \
                (volatile long *)(obj), (long)(val)),              \
        volatile unsigned int *:      _op_fetch_and_32(            \
                (volatile long *)(obj), (long)(val)),              \
        volatile long long *:         _op_fetch_and_64(            \
                (volatile long long *)(obj), (long long)(val)),    \
        volatile unsigned long long *:_op_fetch_and_64(            \
                (volatile long long *)(obj), (long long)(val)),    \
        volatile uint64_t *:          _op_fetch_and_64(            \
                (volatile long long *)(obj), (long long)(val))     \
    )

# define atomic_fetch_and_explicit(obj, val, order) \
    atomic_fetch_and((obj), (val))

/* -------------------------------------------------------------------------
 * atomic_compare_exchange_strong / _weak
 *
 * Returns 1 on success, 0 on failure (updates *expected on failure).
 * ---------------------------------------------------------------------- */

static __forceinline int
_op_cas_32(volatile long *p, long *expected, long desired)
{
    long old = InterlockedCompareExchange(p, desired, *expected);
    if (old == *expected)
        return 1;
    *expected = old;
    return 0;
}

static __forceinline int
_op_cas_64(volatile long long *p, long long *expected, long long desired)
{
    long long old = InterlockedCompareExchange64(p, desired, *expected);
    if (old == *expected)
        return 1;
    *expected = old;
    return 0;
}

# define atomic_compare_exchange_strong(obj, expected, desired) \
    _Generic((obj),                                              \
        volatile int *:                _op_cas_32(              \
                (volatile long *)(obj), (long *)(expected),     \
                (long)(desired)),                                \
        volatile long *:               _op_cas_32(              \
                (volatile long *)(obj), (long *)(expected),     \
                (long)(desired)),                                \
        volatile unsigned int *:       _op_cas_32(              \
                (volatile long *)(obj), (long *)(expected),     \
                (long)(desired)),                                \
        volatile long long *:          _op_cas_64(              \
                (volatile long long *)(obj),                    \
                (long long *)(expected), (long long)(desired)), \
        volatile unsigned long long *: _op_cas_64(              \
                (volatile long long *)(obj),                    \
                (long long *)(expected), (long long)(desired))  \
    )

# define atomic_compare_exchange_strong_explicit(obj, exp, des, succ, fail) \
    atomic_compare_exchange_strong((obj), (exp), (des))
# define atomic_compare_exchange_weak                  atomic_compare_exchange_strong
# define atomic_compare_exchange_weak_explicit         atomic_compare_exchange_strong_explicit

/* -------------------------------------------------------------------------
 * atomic_exchange
 * ---------------------------------------------------------------------- */

static __forceinline long
_op_exchange_32(volatile long *p, long val)
{
    return InterlockedExchange(p, val);
}

static __forceinline long long
_op_exchange_64(volatile long long *p, long long val)
{
    return InterlockedExchange64(p, val);
}

# define atomic_exchange(obj, val)                                 \
    _Generic((obj),                                                \
        volatile int *:               _op_exchange_32(             \
                (volatile long *)(obj), (long)(val)),              \
        volatile long *:              _op_exchange_32(             \
                (volatile long *)(obj), (long)(val)),              \
        volatile unsigned int *:      _op_exchange_32(             \
                (volatile long *)(obj), (long)(val)),              \
        volatile long long *:         _op_exchange_64(             \
                (volatile long long *)(obj), (long long)(val)),    \
        volatile unsigned long long *:_op_exchange_64(             \
                (volatile long long *)(obj), (long long)(val))     \
    )

# define atomic_exchange_explicit(obj, val, order) \
    atomic_exchange((obj), (val))

/* -------------------------------------------------------------------------
 * Fence
 * ---------------------------------------------------------------------- */

# define atomic_thread_fence(order) \
    (((order) == memory_order_relaxed) ? _ReadWriteBarrier() : (void)MemoryBarrier())

# define atomic_signal_fence(order)  _ReadWriteBarrier()

/* -------------------------------------------------------------------------
 * Lock-free query (everything above is lock-free on x86/x64)
 * ---------------------------------------------------------------------- */

# define ATOMIC_INT_LOCK_FREE    2
# define ATOMIC_LONG_LOCK_FREE   2
# define ATOMIC_LLONG_LOCK_FREE  2
# define ATOMIC_POINTER_LOCK_FREE 2

#endif /* _MSC_VER && !__clang__ */

/* =========================================================================
 * Lock-free observability primitives
 * =========================================================================
 *
 * Header-only telemetry helpers built on the atomics above. Designed for
 * hot-path use in Ophion: per-frame counters, latency histograms, gauges
 * surfaced to operator dashboards.
 *
 * Usage:
 *
 *   op_atomic_counter_t frames;
 *   op_atomic_counter_init(&frames);
 *   op_atomic_counter_inc(&frames);                 // relaxed, monotonic
 *   uint64_t total = op_atomic_counter_get(&frames);
 *
 *   op_atomic_gauge_t connected_clients;
 *   op_atomic_gauge_init(&connected_clients);
 *   op_atomic_gauge_inc(&connected_clients);        // seq_cst snapshot view
 *   int64_t now = op_atomic_gauge_get(&connected_clients);
 *
 *   op_atomic_histogram_t latency_us;
 *   op_atomic_histogram_init(&latency_us);
 *   op_atomic_histogram_observe(&latency_us, 137);  // bucketed by power-of-2
 *   uint64_t b = op_atomic_histogram_bucket(&latency_us, 7);
 *
 *   op_atomic_percpu_counter_t pkts;
 *   op_atomic_percpu_counter_init(&pkts);
 *   op_atomic_percpu_counter_inc(&pkts);            // local shard, no ping-pong
 *   uint64_t agg = op_atomic_percpu_counter_get(&pkts); // sum across shards
 *
 * Memory ordering:
 *   - counter:   relaxed (monotonic; consumer tolerates eventual consistency)
 *   - gauge:     seq_cst (dashboards see a coherent global snapshot)
 *   - histogram: relaxed per bucket (eventually consistent snapshot)
 *   - percpu:    relaxed per-shard inc, relaxed aggregation read
 *
 * All ops are `static inline` and safe to call from any thread. None
 * allocate. Initialisation is plain assignment (zero-init also works).
 * ====================================================================== */

#include <stdint.h>
#include <stddef.h>

#if defined(__has_include)
# if __has_include(<threads.h>) && !defined(_MSC_VER)
#  include <threads.h>
# endif
#endif

/* Thread-local keyword that works across compilers. */
#if defined(_MSC_VER) && !defined(__clang__)
# define OP_ATOMIC_TLS __declspec(thread)
#elif defined(thread_local)
# define OP_ATOMIC_TLS thread_local
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L && !defined(__STDC_NO_THREADS__)
# define OP_ATOMIC_TLS _Thread_local
#else
# define OP_ATOMIC_TLS __thread
#endif

/* Cache-line size; conservative default avoids false sharing on x86/ARM. */
#ifndef OP_ATOMIC_CACHELINE
# define OP_ATOMIC_CACHELINE 64
#endif

/* -------------------------------------------------------------------------
 * op_atomic_counter_t — monotonic 64-bit counter (relaxed).
 * ---------------------------------------------------------------------- */

typedef struct {
    _Atomic(uint64_t) v;
} op_atomic_counter_t;

static inline void
op_atomic_counter_init(op_atomic_counter_t *c)
{
    atomic_store_explicit(&c->v, 0, memory_order_relaxed);
}

static inline void
op_atomic_counter_inc(op_atomic_counter_t *c)
{
    (void)atomic_fetch_add_explicit(&c->v, 1, memory_order_relaxed);
}

static inline void
op_atomic_counter_add(op_atomic_counter_t *c, uint64_t n)
{
    (void)atomic_fetch_add_explicit(&c->v, n, memory_order_relaxed);
}

static inline uint64_t
op_atomic_counter_get(const op_atomic_counter_t *c)
{
    return atomic_load_explicit((_Atomic(uint64_t) *)&c->v,
                                memory_order_relaxed);
}

static inline void
op_atomic_counter_reset(op_atomic_counter_t *c)
{
    atomic_store_explicit(&c->v, 0, memory_order_relaxed);
}

/* -------------------------------------------------------------------------
 * op_atomic_gauge_t — signed gauge (seq_cst for coherent snapshots).
 * ---------------------------------------------------------------------- */

typedef struct {
    _Atomic(int64_t) v;
} op_atomic_gauge_t;

static inline void
op_atomic_gauge_init(op_atomic_gauge_t *g)
{
    atomic_store_explicit(&g->v, 0, memory_order_seq_cst);
}

static inline void
op_atomic_gauge_set(op_atomic_gauge_t *g, int64_t value)
{
    atomic_store_explicit(&g->v, value, memory_order_seq_cst);
}

static inline int64_t
op_atomic_gauge_get(const op_atomic_gauge_t *g)
{
    return atomic_load_explicit((_Atomic(int64_t) *)&g->v,
                                memory_order_seq_cst);
}

static inline void
op_atomic_gauge_inc(op_atomic_gauge_t *g)
{
    (void)atomic_fetch_add_explicit(&g->v, 1, memory_order_seq_cst);
}

static inline void
op_atomic_gauge_dec(op_atomic_gauge_t *g)
{
    (void)atomic_fetch_sub_explicit(&g->v, 1, memory_order_seq_cst);
}

static inline void
op_atomic_gauge_add(op_atomic_gauge_t *g, int64_t n)
{
    (void)atomic_fetch_add_explicit(&g->v, n, memory_order_seq_cst);
}

/* -------------------------------------------------------------------------
 * op_atomic_histogram_t — fixed 16-bucket power-of-2 histogram.
 *
 * Bucket index for value v (v > 0) is floor(log2(v)) clamped to [0, 15];
 * value 0 maps to bucket 0. Readers see an eventually-consistent snapshot
 * via per-bucket relaxed loads. SWMR (single observer, many readers) is
 * the canonical use, but multiple writers also work because each bucket is
 * an independent atomic counter.
 * ---------------------------------------------------------------------- */

#define OP_ATOMIC_HIST_BUCKETS 16

typedef struct {
    _Atomic(uint64_t) buckets[OP_ATOMIC_HIST_BUCKETS];
    _Atomic(uint64_t) count;
    _Atomic(uint64_t) sum;
} op_atomic_histogram_t;

static inline void
op_atomic_histogram_init(op_atomic_histogram_t *h)
{
    for (int i = 0; i < OP_ATOMIC_HIST_BUCKETS; ++i)
        atomic_store_explicit(&h->buckets[i], 0, memory_order_relaxed);
    atomic_store_explicit(&h->count, 0, memory_order_relaxed);
    atomic_store_explicit(&h->sum,   0, memory_order_relaxed);
}

/* Resolve bucket index without UB on value 0. */
static inline unsigned
op_atomic_histogram_bucket_for(uint64_t value)
{
#if defined(__GNUC__) || defined(__clang__)
    if (value <= 1)
        return 0;
    /* floor(log2(value)) = 63 - clz(value) */
    unsigned idx = (unsigned)(63 - __builtin_clzll(value));
#else
    unsigned idx = 0;
    uint64_t v = value;
    while (v > 1) { v >>= 1; ++idx; }
#endif
    if (idx >= OP_ATOMIC_HIST_BUCKETS)
        idx = OP_ATOMIC_HIST_BUCKETS - 1;
    return idx;
}

static inline void
op_atomic_histogram_observe(op_atomic_histogram_t *h, uint64_t value)
{
    unsigned idx = op_atomic_histogram_bucket_for(value);
    (void)atomic_fetch_add_explicit(&h->buckets[idx], 1, memory_order_relaxed);
    (void)atomic_fetch_add_explicit(&h->count, 1, memory_order_relaxed);
    (void)atomic_fetch_add_explicit(&h->sum, value, memory_order_relaxed);
}

static inline uint64_t
op_atomic_histogram_bucket(const op_atomic_histogram_t *h, unsigned idx)
{
    if (idx >= OP_ATOMIC_HIST_BUCKETS)
        return 0;
    return atomic_load_explicit((_Atomic(uint64_t) *)&h->buckets[idx],
                                memory_order_relaxed);
}

static inline uint64_t
op_atomic_histogram_count(const op_atomic_histogram_t *h)
{
    return atomic_load_explicit((_Atomic(uint64_t) *)&h->count,
                                memory_order_relaxed);
}

static inline uint64_t
op_atomic_histogram_sum(const op_atomic_histogram_t *h)
{
    return atomic_load_explicit((_Atomic(uint64_t) *)&h->sum,
                                memory_order_relaxed);
}

/* -------------------------------------------------------------------------
 * op_atomic_percpu_counter_t — sharded counter to avoid cache-line ping-pong.
 *
 * Strategy:
 *   libop has no per-CPU primitive, so we fall back to a fixed array of
 *   cache-line-padded shards. A thread-local hash index assigns each
 *   thread a sticky shard at first use. Increments hit only that shard,
 *   keeping the cache line hot in the writer's L1. Reads sum all shards
 *   under relaxed ordering (eventually consistent, fine for telemetry).
 *
 *   Shard count defaults to OP_ATOMIC_PERCPU_SHARDS (16), a sensible
 *   ceiling for hardware_concurrency on typical Ophion deployments while
 *   keeping the struct small (~1 KiB padded). Override via -D if needed.
 * ---------------------------------------------------------------------- */

#ifndef OP_ATOMIC_PERCPU_SHARDS
# define OP_ATOMIC_PERCPU_SHARDS 16
#endif

typedef struct {
    /* Each shard padded to its own cache line. */
    struct {
        _Atomic(uint64_t) v;
        char _pad[OP_ATOMIC_CACHELINE - sizeof(uint64_t)];
    } shards[OP_ATOMIC_PERCPU_SHARDS];
} op_atomic_percpu_counter_t;

/* Sticky per-thread shard index. 0xFFFF sentinel = "not yet assigned". */
extern OP_ATOMIC_TLS unsigned _op_atomic_percpu_tls_idx;

/* Tiny splitmix-ish mix of an address to derive a shard. */
static inline unsigned
_op_atomic_percpu_assign(void)
{
    /* Use the address of a TLS variable as a per-thread unique seed. */
    uintptr_t seed = (uintptr_t)&_op_atomic_percpu_tls_idx;
    seed ^= seed >> 33;
    seed *= (uintptr_t)0xff51afd7ed558ccdULL;
    seed ^= seed >> 33;
    _op_atomic_percpu_tls_idx =
        (unsigned)(seed % (uintptr_t)OP_ATOMIC_PERCPU_SHARDS);
    return _op_atomic_percpu_tls_idx;
}

static inline unsigned
_op_atomic_percpu_shard(void)
{
    unsigned idx = _op_atomic_percpu_tls_idx;
    if (idx >= OP_ATOMIC_PERCPU_SHARDS)
        idx = _op_atomic_percpu_assign();
    return idx;
}

static inline void
op_atomic_percpu_counter_init(op_atomic_percpu_counter_t *c)
{
    for (unsigned i = 0; i < OP_ATOMIC_PERCPU_SHARDS; ++i)
        atomic_store_explicit(&c->shards[i].v, 0, memory_order_relaxed);
}

static inline void
op_atomic_percpu_counter_inc(op_atomic_percpu_counter_t *c)
{
    unsigned idx = _op_atomic_percpu_shard();
    (void)atomic_fetch_add_explicit(&c->shards[idx].v, 1,
                                    memory_order_relaxed);
}

static inline void
op_atomic_percpu_counter_add(op_atomic_percpu_counter_t *c, uint64_t n)
{
    unsigned idx = _op_atomic_percpu_shard();
    (void)atomic_fetch_add_explicit(&c->shards[idx].v, n,
                                    memory_order_relaxed);
}

static inline uint64_t
op_atomic_percpu_counter_get(const op_atomic_percpu_counter_t *c)
{
    uint64_t total = 0;
    for (unsigned i = 0; i < OP_ATOMIC_PERCPU_SHARDS; ++i)
        total += atomic_load_explicit(
            (_Atomic(uint64_t) *)&c->shards[i].v, memory_order_relaxed);
    return total;
}

static inline void
op_atomic_percpu_counter_reset(op_atomic_percpu_counter_t *c)
{
    for (unsigned i = 0; i < OP_ATOMIC_PERCPU_SHARDS; ++i)
        atomic_store_explicit(&c->shards[i].v, 0, memory_order_relaxed);
}

#endif /* OP_ATOMIC_H */

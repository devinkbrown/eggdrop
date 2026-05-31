/*
 * libop/src/op_atomic.c — storage for op_atomic observability primitives.
 *
 * The header op_atomic.h declares one extern thread-local: the sticky
 * per-thread shard index used by op_atomic_percpu_counter_t. Defining it
 * once here keeps the rest of the API header-only and inlinable.
 *
 * Sentinel value 0xFFFFFFFFu means "not yet assigned"; the first call to
 * op_atomic_percpu_counter_inc()/add()/get() on a given thread runs the
 * cheap mix in _op_atomic_percpu_assign() to bind a shard for the lifetime
 * of the thread.
 */

#include "op_atomic.h"

OP_ATOMIC_TLS unsigned _op_atomic_percpu_tls_idx = 0xFFFFFFFFu;

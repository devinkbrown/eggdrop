/*
 * libop/include/op_thread_pool.h — generic pthreads work-queue thread pool.
 *
 * Usage:
 *   op_thread_pool_t *pool = op_tpool_create(0);   // 0 = auto (# CPUs, max 16)
 *   op_tpool_submit(pool, my_fn, my_arg);
 *   op_tpool_shutdown(pool);                        // waits for all workers to finish
 */

#ifndef OP_THREAD_POOL_H
#define OP_THREAD_POOL_H

#include <stddef.h>

typedef struct op_thread_pool op_thread_pool_t;

/*
 * op_tpool_create — create a thread pool.
 *
 * nthreads: number of worker threads to spawn.
 *           Pass 0 to auto-detect (sysconf(_SC_NPROCESSORS_ONLN), capped at 16).
 *
 * Returns a pointer to the pool (never NULL; aborts on OOM/pthread failure).
 */
op_thread_pool_t *op_tpool_create(int nthreads);

/*
 * op_tpool_submit — enqueue a work item.
 *
 * fn(arg) will be called exactly once on an arbitrary worker thread.
 * This function is safe to call from any thread.
 * It is NOT safe to call after op_tpool_shutdown().
 */
void op_tpool_submit(op_thread_pool_t *pool, void (*fn)(void *), void *arg);

/*
 * op_tpool_shutdown — drain the queue and destroy the pool.
 *
 * Blocks until all queued work items have completed and all worker threads
 * have exited.  The pool pointer is invalid after this call.
 */
void op_tpool_shutdown(op_thread_pool_t *pool);

/*
 * op_tpool_nthreads — return the number of worker threads in the pool.
 */
int op_tpool_nthreads(const op_thread_pool_t *pool);

#endif /* OP_THREAD_POOL_H */

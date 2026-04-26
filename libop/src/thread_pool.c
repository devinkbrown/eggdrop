/*
 * libop/src/thread_pool.c — generic work-queue thread pool.
 *
 * Design: single shared mutex + condvar; global FIFO work queue using
 * a simple linked list of work items allocated with op_malloc/op_free.
 * Workers block on the condvar when idle.
 * op_tpool_shutdown() sets a stop flag and broadcasts to wake all workers,
 * then joins them before freeing the pool.
 *
 * Three implementations:
 *   _WIN32        — Win32 CRITICAL_SECTION + CONDITION_VARIABLE + CreateThread
 *   C11 threads   — <threads.h>  thrd_t / mtx_t / cnd_t  (C11, no STDC_NO_THREADS)
 *   POSIX         — pthread_mutex_t + pthread_cond_t + pthread_create (fallback)
 */

#include <libop_config.h>
#include <op_thread_pool.h>
#include <op_lib.h>          /* op_malloc, op_free */

#include <string.h>

/* =========================================================================
 * Shared: work-item list node (identical on both platforms)
 * ====================================================================== */

typedef struct work_item {
	void (*fn)(void *);
	void *arg;
	struct work_item *next;
} work_item_t;

/* =========================================================================
 * Windows implementation
 * ====================================================================== */

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
# define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

struct op_thread_pool {
	CRITICAL_SECTION   lock;
	CONDITION_VARIABLE cond;
	work_item_t       *head;
	work_item_t       *tail;
	int                nthreads;
	volatile int       stop;
	HANDLE             threads[];   /* flexible array — nthreads HANDLE entries */
};

static DWORD WINAPI
worker_entry(LPVOID arg)
{
	struct op_thread_pool *pool = arg;

	EnterCriticalSection(&pool->lock);
	for (;;)
	{
		while (pool->head == NULL && !pool->stop)
			SleepConditionVariableCS(&pool->cond, &pool->lock, INFINITE);

		if (pool->head == NULL)
		{
			/* stop == 1 and queue is empty — exit. */
			LeaveCriticalSection(&pool->lock);
			return 0;
		}

		work_item_t *item = pool->head;
		pool->head = item->next;
		if (pool->head == NULL)
			pool->tail = NULL;
		LeaveCriticalSection(&pool->lock);

		item->fn(item->arg);
		op_free(item);

		EnterCriticalSection(&pool->lock);
	}
}

op_thread_pool_t *
op_tpool_create(int nthreads)
{
	if (nthreads <= 0)
	{
		SYSTEM_INFO si;
		GetSystemInfo(&si);
		nthreads = (int)si.dwNumberOfProcessors;
		if (nthreads < 1)  nthreads = 1;
		if (nthreads > 16) nthreads = 16;
	}

	op_thread_pool_t *pool = op_malloc(
		sizeof(op_thread_pool_t) + (size_t)nthreads * sizeof(HANDLE));
	memset(pool, 0, sizeof(op_thread_pool_t));
	pool->nthreads = nthreads;
	pool->stop = 0;

	InitializeCriticalSection(&pool->lock);
	InitializeConditionVariable(&pool->cond);

	for (int i = 0; i < nthreads; i++)
	{
		pool->threads[i] = CreateThread(NULL, 0, worker_entry, pool, 0, NULL);
		if (pool->threads[i] == NULL)
			abort();
	}

	return pool;
}

void
op_tpool_submit(op_thread_pool_t *pool, void (*fn)(void *), void *arg)
{
	work_item_t *item = op_malloc(sizeof(work_item_t));
	item->fn   = fn;
	item->arg  = arg;
	item->next = NULL;

	EnterCriticalSection(&pool->lock);
	if (pool->tail)
		pool->tail->next = item;
	else
		pool->head = item;
	pool->tail = item;
	WakeConditionVariable(&pool->cond);
	LeaveCriticalSection(&pool->lock);
}

void
op_tpool_shutdown(op_thread_pool_t *pool)
{
	EnterCriticalSection(&pool->lock);
	pool->stop = 1;
	WakeAllConditionVariable(&pool->cond);
	LeaveCriticalSection(&pool->lock);

	WaitForMultipleObjects((DWORD)pool->nthreads, pool->threads, TRUE, INFINITE);

	for (int i = 0; i < pool->nthreads; i++)
		CloseHandle(pool->threads[i]);

	DeleteCriticalSection(&pool->lock);
	op_free(pool);
}

int
op_tpool_nthreads(const op_thread_pool_t *pool)
{
	return pool->nthreads;
}

#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L && \
      !defined(__STDC_NO_THREADS__)

/* =========================================================================
 * C11 threads implementation
 * ====================================================================== */

#include <threads.h>
#include <stdlib.h>
#include <unistd.h>          /* sysconf */

struct op_thread_pool {
	mtx_t        lock;
	cnd_t        cond;
	work_item_t *head;
	work_item_t *tail;
	int          nthreads;
	int          stop;
	thrd_t       threads[];   /* flexible array — nthreads entries */
};

static int
worker_entry(void *arg)
{
	struct op_thread_pool *pool = arg;

	mtx_lock(&pool->lock);
	for (;;)
	{
		while (pool->head == NULL && !pool->stop)
			cnd_wait(&pool->cond, &pool->lock);

		if (pool->head == NULL)
		{
			mtx_unlock(&pool->lock);
			return 0;
		}

		work_item_t *item = pool->head;
		pool->head = item->next;
		if (pool->head == NULL)
			pool->tail = NULL;
		mtx_unlock(&pool->lock);

		item->fn(item->arg);
		op_free(item);

		mtx_lock(&pool->lock);
	}
}

op_thread_pool_t *
op_tpool_create(int nthreads)
{
	if (nthreads <= 0)
	{
#ifdef _SC_NPROCESSORS_ONLN
		nthreads = (int)sysconf(_SC_NPROCESSORS_ONLN);
#else
		nthreads = 2;
#endif
		if (nthreads < 1)  nthreads = 1;
		if (nthreads > 16) nthreads = 16;
	}

	op_thread_pool_t *pool = op_malloc(
		sizeof(op_thread_pool_t) + (size_t)nthreads * sizeof(thrd_t));
	memset(pool, 0, sizeof(op_thread_pool_t));
	pool->nthreads = nthreads;

	if (mtx_init(&pool->lock, mtx_plain) != thrd_success) abort();
	if (cnd_init(&pool->cond)            != thrd_success) abort();

	for (int i = 0; i < nthreads; i++)
	{
		if (thrd_create(&pool->threads[i], worker_entry, pool) != thrd_success)
			abort();
	}

	return pool;
}

void
op_tpool_submit(op_thread_pool_t *pool, void (*fn)(void *), void *arg)
{
	work_item_t *item = op_malloc(sizeof(work_item_t));
	item->fn   = fn;
	item->arg  = arg;
	item->next = NULL;

	mtx_lock(&pool->lock);
	if (pool->tail)
		pool->tail->next = item;
	else
		pool->head = item;
	pool->tail = item;
	cnd_signal(&pool->cond);
	mtx_unlock(&pool->lock);
}

void
op_tpool_shutdown(op_thread_pool_t *pool)
{
	mtx_lock(&pool->lock);
	pool->stop = 1;
	cnd_broadcast(&pool->cond);
	mtx_unlock(&pool->lock);

	for (int i = 0; i < pool->nthreads; i++)
		thrd_join(pool->threads[i], NULL);

	mtx_destroy(&pool->lock);
	cnd_destroy(&pool->cond);
	op_free(pool);
}

int
op_tpool_nthreads(const op_thread_pool_t *pool)
{
	return pool->nthreads;
}

#else /* !_WIN32, !C11_THREADS — POSIX pthreads */

/* =========================================================================
 * POSIX implementation
 * ====================================================================== */

#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>          /* sysconf */

struct op_thread_pool {
	pthread_mutex_t  lock;
	pthread_cond_t   cond;
	work_item_t     *head;
	work_item_t     *tail;
	int              nthreads;
	int              stop;
	pthread_t        threads[];   /* flexible array — nthreads entries */
};

static void *
worker_entry(void *arg)
{
	struct op_thread_pool *pool = arg;

	pthread_mutex_lock(&pool->lock);
	for (;;)
	{
		while (pool->head == NULL && !pool->stop)
			pthread_cond_wait(&pool->cond, &pool->lock);

		if (pool->head == NULL)
		{
			pthread_mutex_unlock(&pool->lock);
			return NULL;
		}

		work_item_t *item = pool->head;
		pool->head = item->next;
		if (pool->head == NULL)
			pool->tail = NULL;
		pthread_mutex_unlock(&pool->lock);

		item->fn(item->arg);
		op_free(item);

		pthread_mutex_lock(&pool->lock);
	}
}

op_thread_pool_t *
op_tpool_create(int nthreads)
{
	if (nthreads <= 0)
	{
#ifdef _SC_NPROCESSORS_ONLN
		nthreads = (int)sysconf(_SC_NPROCESSORS_ONLN);
#else
		nthreads = 2;
#endif
		if (nthreads < 1)  nthreads = 1;
		if (nthreads > 16) nthreads = 16;
	}

	op_thread_pool_t *pool = op_malloc(
		sizeof(op_thread_pool_t) + (size_t)nthreads * sizeof(pthread_t));
	memset(pool, 0, sizeof(op_thread_pool_t));
	pool->nthreads = nthreads;

	if (pthread_mutex_init(&pool->lock, NULL) != 0) abort();
	if (pthread_cond_init(&pool->cond, NULL)  != 0) abort();

	for (int i = 0; i < nthreads; i++)
	{
		if (pthread_create(&pool->threads[i], NULL, worker_entry, pool) != 0)
			abort();
	}

	return pool;
}

void
op_tpool_submit(op_thread_pool_t *pool, void (*fn)(void *), void *arg)
{
	work_item_t *item = op_malloc(sizeof(work_item_t));
	item->fn   = fn;
	item->arg  = arg;
	item->next = NULL;

	pthread_mutex_lock(&pool->lock);
	if (pool->tail)
		pool->tail->next = item;
	else
		pool->head = item;
	pool->tail = item;
	pthread_cond_signal(&pool->cond);
	pthread_mutex_unlock(&pool->lock);
}

void
op_tpool_shutdown(op_thread_pool_t *pool)
{
	pthread_mutex_lock(&pool->lock);
	pool->stop = 1;
	pthread_cond_broadcast(&pool->cond);
	pthread_mutex_unlock(&pool->lock);

	for (int i = 0; i < pool->nthreads; i++)
		pthread_join(pool->threads[i], NULL);

	pthread_mutex_destroy(&pool->lock);
	pthread_cond_destroy(&pool->cond);
	op_free(pool);
}

int
op_tpool_nthreads(const op_thread_pool_t *pool)
{
	return pool->nthreads;
}

#endif /* _WIN32 / C11 / pthreads */

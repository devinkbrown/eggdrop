/*
 * libop/include/op_lock.h — thin locking wrappers for Ophion.
 *
 * Three types:
 *   op_mutex_t    — general-purpose mutex
 *   op_rwlock_t   — readers-writer lock
 *   op_spinlock_t — spin lock for hot paths
 *
 * On POSIX platforms (Linux, *BSD, macOS) the implementation uses pthreads.
 * On Windows (_WIN32) it uses native Win32 synchronisation objects:
 *   op_mutex_t    → CRITICAL_SECTION  (spins briefly before blocking)
 *   op_rwlock_t   → SRWLOCK           (Slim Reader/Writer Lock; Vista+)
 *   op_spinlock_t → CRITICAL_SECTION  (alias to op_mutex_t)
 *
 * All init functions abort on error (same policy as op_malloc).
 */

#ifndef OP_LOCK_H
#define OP_LOCK_H

#ifdef _WIN32

/* =========================================================================
 * Windows native implementation
 * ====================================================================== */

#ifndef WIN32_LEAN_AND_MEAN
# define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <stdbool.h>

/* -------------------------------------------------------------------------
 * op_mutex_t — CRITICAL_SECTION
 *
 * CRITICAL_SECTION spins for a short burst before blocking, which is
 * ideal for the briefly-held locks in Ophion.  It also supports
 * TryEnterCriticalSection for non-blocking trylock.
 * ---------------------------------------------------------------------- */

typedef struct { CRITICAL_SECTION cs; } op_mutex_t;

static inline void
op_mutex_init(op_mutex_t *lk)
{
	InitializeCriticalSection(&lk->cs);
}

static inline void
op_mutex_destroy(op_mutex_t *lk)
{
	DeleteCriticalSection(&lk->cs);
}

static inline void
op_mutex_lock(op_mutex_t *lk)
{
	EnterCriticalSection(&lk->cs);
}

static inline void
op_mutex_unlock(op_mutex_t *lk)
{
	LeaveCriticalSection(&lk->cs);
}

static inline int
op_mutex_trylock(op_mutex_t *lk)
{
	return TryEnterCriticalSection(&lk->cs) != 0;
}

/* -------------------------------------------------------------------------
 * op_rwlock_t — SRWLOCK (Slim Reader/Writer Lock, Vista+/2008+)
 *
 * SRWLOCK has separate release functions for shared (reader) and exclusive
 * (writer) modes.  We track which mode is active in a volatile flag that
 * is written before any unlock: the writer is alone by SRWLOCK guarantee,
 * and concurrent readers all write the same value (false), so there is no
 * data race on the flag itself.
 * ---------------------------------------------------------------------- */

typedef struct {
	SRWLOCK       rw;
	volatile bool exclusive;  /* true while a writer holds the lock */
} op_rwlock_t;

static inline void
op_rwlock_init(op_rwlock_t *lk)
{
	InitializeSRWLock(&lk->rw);
	lk->exclusive = false;
}

static inline void
op_rwlock_destroy(op_rwlock_t *lk)
{
	(void)lk;  /* SRWLock has no destructor */
}

static inline void
op_rwlock_rdlock(op_rwlock_t *lk)
{
	AcquireSRWLockShared(&lk->rw);
	lk->exclusive = false;
}

static inline void
op_rwlock_wrlock(op_rwlock_t *lk)
{
	AcquireSRWLockExclusive(&lk->rw);
	lk->exclusive = true;
}

static inline void
op_rwlock_unlock(op_rwlock_t *lk)
{
	if (lk->exclusive)
		ReleaseSRWLockExclusive(&lk->rw);
	else
		ReleaseSRWLockShared(&lk->rw);
}

/* -------------------------------------------------------------------------
 * op_spinlock_t — alias to op_mutex_t on Windows
 *
 * Windows has no direct equivalent of pthread_spinlock_t.  CRITICAL_SECTION
 * already spins for a configurable number of iterations (default 0 for UP,
 * usually 4000 on SMP) before entering the kernel, so it is the closest
 * practical equivalent.
 * ---------------------------------------------------------------------- */

typedef op_mutex_t op_spinlock_t;
# define op_spinlock_init    op_mutex_init
# define op_spinlock_destroy op_mutex_destroy
# define op_spinlock_lock    op_mutex_lock
# define op_spinlock_unlock  op_mutex_unlock

#else /* !_WIN32 — POSIX pthreads */

/* =========================================================================
 * POSIX pthreads implementation (Linux, *BSD, macOS)
 * ====================================================================== */

#include <pthread.h>
#include <stdlib.h>   /* abort() */
#include <errno.h>

/* -------------------------------------------------------------------------
 * op_mutex_t
 * ---------------------------------------------------------------------- */

typedef struct { pthread_mutex_t m; } op_mutex_t;

static inline void
op_mutex_init(op_mutex_t *lk)
{
	if (pthread_mutex_init(&lk->m, NULL) != 0)
		abort();
}

static inline void
op_mutex_destroy(op_mutex_t *lk)
{
	pthread_mutex_destroy(&lk->m);
}

static inline void
op_mutex_lock(op_mutex_t *lk)
{
	if (pthread_mutex_lock(&lk->m) != 0)
		abort();
}

static inline void
op_mutex_unlock(op_mutex_t *lk)
{
	pthread_mutex_unlock(&lk->m);
}

static inline int
op_mutex_trylock(op_mutex_t *lk)
{
	return pthread_mutex_trylock(&lk->m) == 0;
}

/* -------------------------------------------------------------------------
 * op_rwlock_t
 * ---------------------------------------------------------------------- */

typedef struct { pthread_rwlock_t rw; } op_rwlock_t;

static inline void
op_rwlock_init(op_rwlock_t *lk)
{
	if (pthread_rwlock_init(&lk->rw, NULL) != 0)
		abort();
}

static inline void
op_rwlock_destroy(op_rwlock_t *lk)
{
	pthread_rwlock_destroy(&lk->rw);
}

static inline void
op_rwlock_rdlock(op_rwlock_t *lk)
{
	if (pthread_rwlock_rdlock(&lk->rw) != 0)
		abort();
}

static inline void
op_rwlock_wrlock(op_rwlock_t *lk)
{
	if (pthread_rwlock_wrlock(&lk->rw) != 0)
		abort();
}

static inline void
op_rwlock_unlock(op_rwlock_t *lk)
{
	pthread_rwlock_unlock(&lk->rw);
}

/* -------------------------------------------------------------------------
 * op_spinlock_t
 *
 * pthread_spinlock_t is available on Linux/glibc and most BSDs.
 * On platforms that lack it we fall back to a mutex.
 * ---------------------------------------------------------------------- */

#if defined(__linux__) || defined(__FreeBSD__) || defined(__NetBSD__)
# define OP_HAVE_SPINLOCK 1
#endif

#ifdef OP_HAVE_SPINLOCK

typedef struct { pthread_spinlock_t s; } op_spinlock_t;

static inline void
op_spinlock_init(op_spinlock_t *lk)
{
	if (pthread_spin_init(&lk->s, PTHREAD_PROCESS_PRIVATE) != 0)
		abort();
}

static inline void
op_spinlock_destroy(op_spinlock_t *lk)
{
	pthread_spin_destroy(&lk->s);
}

static inline void
op_spinlock_lock(op_spinlock_t *lk)
{
	pthread_spin_lock(&lk->s);
}

static inline void
op_spinlock_unlock(op_spinlock_t *lk)
{
	pthread_spin_unlock(&lk->s);
}

#else  /* fallback: use a mutex */

typedef op_mutex_t op_spinlock_t;
# define op_spinlock_init    op_mutex_init
# define op_spinlock_destroy op_mutex_destroy
# define op_spinlock_lock    op_mutex_lock
# define op_spinlock_unlock  op_mutex_unlock

#endif /* OP_HAVE_SPINLOCK */

#endif /* _WIN32 */

#endif /* OP_LOCK_H */

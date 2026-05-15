/*
 * op_thread.h — C11 thread primitives with pthreads fallback.
 *
 * Provides uniform op_thrd_t, op_mtx_t, op_cnd_t types and wrappers
 * that map to C11 <threads.h> on conforming platforms, or pthreads on
 * POSIX systems that predate C11 thread support.
 *
 * Copyright (C) 2026 Eggheads Development Team
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef OP_THREAD_H
#define OP_THREAD_H

#include <stddef.h>

/* =========================================================================
 * Platform selection
 * ====================================================================== */

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L && \
    !defined(__STDC_NO_THREADS__)
/* ---- Native C11 threads ------------------------------------------------- */
#  define OP_HAVE_C11_THREADS 1
#  include <threads.h>
#  include <stdatomic.h>

typedef thrd_t    op_thrd_t;
typedef mtx_t     op_mtx_t;
typedef cnd_t     op_cnd_t;
typedef once_flag op_once_t;

/* Return value sentinels */
#  define OP_THRD_SUCCESS  thrd_success
#  define OP_THRD_ERROR    thrd_error
#  define OP_THRD_BUSY     thrd_busy
#  define OP_THRD_NOMEM    thrd_nomem
#  define OP_THRD_TIMEDOUT thrd_timedout

/* Thread operations */
#  define op_thrd_create(t, fn, arg)   thrd_create(t, fn, arg)
#  define op_thrd_join(t, res)         thrd_join(t, res)
#  define op_thrd_detach(t)            thrd_detach(t)
#  define op_thrd_current()            thrd_current()
#  define op_thrd_yield()              thrd_yield()
#  define op_thrd_exit(code)           thrd_exit(code)
#  define op_thrd_equal(a, b)          thrd_equal(a, b)

/* Mutex operations (always plain, non-recursive, non-timed) */
#  define op_mtx_init(m)               mtx_init(m, mtx_plain)
#  define op_mtx_lock(m)               mtx_lock(m)
#  define op_mtx_trylock(m)            mtx_trylock(m)
#  define op_mtx_unlock(m)             mtx_unlock(m)
#  define op_mtx_destroy(m)            mtx_destroy(m)

/* Condition variable operations */
#  define op_cnd_init(c)               cnd_init(c)
#  define op_cnd_wait(c, m)            cnd_wait(c, m)
#  define op_cnd_signal(c)             cnd_signal(c)
#  define op_cnd_broadcast(c)          cnd_broadcast(c)
#  define op_cnd_destroy(c)            cnd_destroy(c)

/* Once */
#  define OP_ONCE_INIT                 ONCE_FLAG_INIT
#  define op_call_once(flag, fn)       call_once(flag, fn)

#elif defined(_WIN32)
/* ---- Win32 CRITICAL_SECTION + CONDITION_VARIABLE ------------------------ */
#  define OP_HAVE_WIN32_THREADS 1
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>

typedef HANDLE             op_thrd_t;
typedef CRITICAL_SECTION   op_mtx_t;
typedef CONDITION_VARIABLE op_cnd_t;
typedef INIT_ONCE          op_once_t;

#  define OP_THRD_SUCCESS  0
#  define OP_THRD_ERROR    1
#  define OP_THRD_BUSY     2
#  define OP_THRD_NOMEM    3
#  define OP_THRD_TIMEDOUT 4

/* Thread function adapter: Win32 uses DWORD WINAPI, C11 uses int */
typedef struct { int (*fn)(void *); void *arg; } op__thrd_wrap_t;
static inline DWORD WINAPI op__thrd_tramp(LPVOID p) {
  op__thrd_wrap_t *w = p;
  int r = w->fn(w->arg);
  free(w);
  return (DWORD)r;
}
static inline int op_thrd_create(op_thrd_t *t, int (*fn)(void *), void *arg) {
  op__thrd_wrap_t *w = malloc(sizeof *w);
  if (!w) return OP_THRD_NOMEM;
  w->fn = fn; w->arg = arg;
  *t = CreateThread(nullptr, 0, op__thrd_tramp, w, 0, nullptr);
  return *t ? OP_THRD_SUCCESS : OP_THRD_ERROR;
}
static inline int op_thrd_join(op_thrd_t t, int *res) {
  WaitForSingleObject(t, INFINITE);
  if (res) { DWORD code; GetExitCodeThread(t, &code); *res = (int)code; }
  CloseHandle(t);
  return OP_THRD_SUCCESS;
}
#  define op_thrd_detach(t)            (CloseHandle(t), OP_THRD_SUCCESS)
#  define op_thrd_current()            GetCurrentThread()
#  define op_thrd_yield()              SwitchToThread()
#  define op_thrd_exit(code)           ExitThread((DWORD)(code))
#  define op_thrd_equal(a, b)          (GetThreadId(a) == GetThreadId(b))

#  define op_mtx_init(m)               (InitializeCriticalSection(m), OP_THRD_SUCCESS)
#  define op_mtx_lock(m)               (EnterCriticalSection(m), OP_THRD_SUCCESS)
#  define op_mtx_trylock(m)            (TryEnterCriticalSection(m) ? OP_THRD_SUCCESS : OP_THRD_BUSY)
#  define op_mtx_unlock(m)             (LeaveCriticalSection(m), OP_THRD_SUCCESS)
#  define op_mtx_destroy(m)            DeleteCriticalSection(m)

#  define op_cnd_init(c)               (InitializeConditionVariable(c), OP_THRD_SUCCESS)
#  define op_cnd_wait(c, m)            (SleepConditionVariableCS(c, m, INFINITE) ? OP_THRD_SUCCESS : OP_THRD_ERROR)
#  define op_cnd_signal(c)             (WakeConditionVariable(c), OP_THRD_SUCCESS)
#  define op_cnd_broadcast(c)          (WakeAllConditionVariable(c), OP_THRD_SUCCESS)
#  define op_cnd_destroy(c)            ((void)0)

#  define OP_ONCE_INIT                 INIT_ONCE_STATIC_INIT
static inline void op_call_once(op_once_t *flag, void (*fn)(void)) {
  BOOL pending;
  if (InitOnceBeginInitialize(flag, 0, &pending, nullptr) && pending) {
    fn();
    InitOnceComplete(flag, 0, nullptr);
  }
}

#else
/* ---- POSIX pthreads fallback -------------------------------------------- */
#  define OP_HAVE_PTHREADS 1
#  include <pthread.h>
#  include <stdatomic.h>

typedef pthread_t       op_thrd_t;
typedef pthread_mutex_t op_mtx_t;
typedef pthread_cond_t  op_cnd_t;
typedef pthread_once_t  op_once_t;

#  define OP_THRD_SUCCESS  0
#  define OP_THRD_ERROR    1
#  define OP_THRD_BUSY     2
#  define OP_THRD_NOMEM    3
#  define OP_THRD_TIMEDOUT 4

/* Thread function adapter: pthreads uses void *, C11 uses int */
typedef struct { int (*fn)(void *); void *arg; } op__thrd_wrap_t;
#  include <stdlib.h>
static inline void *op__thrd_tramp(void *p) {
  op__thrd_wrap_t *w = p;
  long r = w->fn(w->arg);
  free(w);
  return (void *)r;
}
static inline int op_thrd_create(op_thrd_t *t, int (*fn)(void *), void *arg) {
  op__thrd_wrap_t *w = malloc(sizeof *w);
  if (!w) return OP_THRD_NOMEM;
  w->fn = fn; w->arg = arg;
  return pthread_create(t, nullptr, op__thrd_tramp, w) ? OP_THRD_ERROR : OP_THRD_SUCCESS;
}
static inline int op_thrd_join(op_thrd_t t, int *res) {
  void *rv;
  int r = pthread_join(t, &rv);
  if (res) *res = (int)(long)rv;
  return r ? OP_THRD_ERROR : OP_THRD_SUCCESS;
}
#  define op_thrd_detach(t)            (pthread_detach(t) ? OP_THRD_ERROR : OP_THRD_SUCCESS)
#  define op_thrd_current()            pthread_self()
#  define op_thrd_yield()              sched_yield()
#  define op_thrd_exit(code)           pthread_exit((void *)(long)(code))
#  define op_thrd_equal(a, b)          pthread_equal(a, b)

#  define op_mtx_init(m)               (pthread_mutex_init(m, nullptr) ? OP_THRD_ERROR : OP_THRD_SUCCESS)
#  define op_mtx_lock(m)               (pthread_mutex_lock(m) ? OP_THRD_ERROR : OP_THRD_SUCCESS)
#  define op_mtx_trylock(m)            (pthread_mutex_trylock(m) == 0 ? OP_THRD_SUCCESS : OP_THRD_BUSY)
#  define op_mtx_unlock(m)             (pthread_mutex_unlock(m) ? OP_THRD_ERROR : OP_THRD_SUCCESS)
#  define op_mtx_destroy(m)            pthread_mutex_destroy(m)

#  define op_cnd_init(c)               (pthread_cond_init(c, nullptr) ? OP_THRD_ERROR : OP_THRD_SUCCESS)
#  define op_cnd_wait(c, m)            (pthread_cond_wait(c, m) ? OP_THRD_ERROR : OP_THRD_SUCCESS)
#  define op_cnd_signal(c)             (pthread_cond_signal(c) ? OP_THRD_ERROR : OP_THRD_SUCCESS)
#  define op_cnd_broadcast(c)          (pthread_cond_broadcast(c) ? OP_THRD_ERROR : OP_THRD_SUCCESS)
#  define op_cnd_destroy(c)            pthread_cond_destroy(c)

#  define OP_ONCE_INIT                 PTHREAD_ONCE_INIT
#  define op_call_once(flag, fn)       pthread_once(flag, fn)

#endif /* platform */

#endif /* OP_THREAD_H */

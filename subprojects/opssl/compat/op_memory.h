/*
 * op_memory.h — standalone compat header for opssl builds without libop.
 *
 * Provides the same allocation API as libop's op_memory.h: all allocators
 * abort on failure via op_outofmemory(), so callers never check for NULL.
 *
 * When the real libop op_memory.h has already been included (LIBOP_MEMORY_H
 * is defined), this file is a no-op.
 */

#ifdef LIBOP_MEMORY_H
/* Real libop is present — skip compat stubs */
#else

#ifndef OP_MEMORY_COMPAT_H
#define OP_MEMORY_COMPAT_H

#include <stdlib.h>
#include <string.h>

void op_outofmemory(void) __attribute__((noreturn));

static inline void *
op_calloc(size_t nmemb, size_t size)
{
    void *p = calloc(nmemb, size);
    if (!p) op_outofmemory();
    return p;
}

static inline void *
op_malloc(size_t size)
{
    void *p = calloc(1, size);
    if (!p) op_outofmemory();
    return p;
}

static inline void *
op_realloc(void *ptr, size_t size)
{
    void *p = realloc(ptr, size);
    if (!p) op_outofmemory();
    return p;
}

static inline char *
op_strndup(const char *s, size_t n)
{
    char *p = strndup(s, n);
    if (!p) op_outofmemory();
    return p;
}

static inline char *
op_strdup(const char *s)
{
    char *p = strdup(s);
    if (!p) op_outofmemory();
    return p;
}

static inline void
op_free(void *ptr)
{
    free(ptr);
}

#endif /* OP_MEMORY_COMPAT_H */
#endif /* !LIBOP_MEMORY_H */

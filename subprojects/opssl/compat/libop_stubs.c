/*
 * libop_stubs.c — minimal libop function stubs for standalone opssl builds.
 *
 * When opssl is built as part of ophion, these symbols come from the real
 * libop. For standalone development and testing, these thin wrappers
 * forward to libc equivalents.
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

void *op_malloc(size_t size)
{
    return malloc(size);
}

void *op_calloc(size_t nmemb, size_t size)
{
    return calloc(nmemb, size);
}

void *op_realloc(void *ptr, size_t size)
{
    return realloc(ptr, size);
}

void op_free(void *ptr)
{
    free(ptr);
}

char *op_strdup(const char *s)
{
    return strdup(s);
}

char *op_strndup(const char *s, size_t n)
{
    return strndup(s, n);
}

__attribute__((noreturn))
void op_outofmemory(void)
{
    fprintf(stderr, "fatal: out of memory\n");
    abort();
}

/*
 * opssl/crypto/platform.c — secure memory and erasure on top of libop.
 *
 * General allocation: op_malloc / op_free (from libop)
 * Key material: opssl_key_alloc / opssl_key_free (mlock + wipe)
 *
 * Copyright (C) 2026 ophion development team
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <opssl/platform.h>

#include <string.h>
#include <sys/mman.h>

/* ─── Secure Erasure ─────────────────────────────────────────────────── */

void
opssl_memzero(void *ptr, size_t len)
{
    if (!ptr || !len)
        return;

#if defined(HAVE_EXPLICIT_BZERO) || defined(__linux__) || defined(__FreeBSD__)
    explicit_bzero(ptr, len);
#elif defined(HAVE_MEMSET_S)
    memset_s(ptr, len, 0, len);
#else
    volatile uint8_t *p = ptr;
    while (len--)
        *p++ = 0;
    __asm__ __volatile__("" ::: "memory");
#endif
}

/* ─── Secure Key Memory ──────────────────────────────────────────────── */

void *
opssl_key_alloc(size_t size)
{
    void *ptr = op_malloc(size);
    memset(ptr, 0, size);
    mlock(ptr, size);
    return ptr;
}

void *
opssl_key_realloc(void *ptr, size_t old_size, size_t new_size)
{
    void *new_ptr = opssl_key_alloc(new_size);
    size_t copy_len = old_size < new_size ? old_size : new_size;
    memcpy(new_ptr, ptr, copy_len);
    opssl_key_free(ptr, old_size);
    return new_ptr;
}

void
opssl_key_free(void *ptr, size_t size)
{
    if (!ptr)
        return;
    opssl_memzero(ptr, size);
    munlock(ptr, size);
    op_free(ptr);
}

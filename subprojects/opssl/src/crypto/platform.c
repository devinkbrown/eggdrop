/*
 * opssl/crypto/platform.c — secure memory and erasure on top of libop.
 *
 * General allocation : op_malloc / op_free (from libop or compat)
 * Key material       : opssl_key_alloc / opssl_key_free (mlock + wipe)
 *
 * Copyright (C) 2026 ophion development team
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <opssl/platform.h>

#include <string.h>
#include <stdint.h>
#include <errno.h>

#if defined(__unix__) || defined(__APPLE__)
# include <sys/mman.h>
#endif

#if defined(_WIN32)
# include <windows.h>
#endif

/* ─── Secure Erasure ─────────────────────────────────────────────────── */

/*
 * opssl_memzero — guaranteed-not-optimised-away memory clear.
 *
 * Selection order:
 *   1. libop's op_memzero_explicit() if linked against real libop
 *   2. SecureZeroMemory() on Windows
 *   3. explicit_bzero(3)  on Linux / FreeBSD / OpenBSD
 *   4. memset_s(3)        on platforms exposing it (C11 Annex K)
 *   5. volatile-pointer loop + compiler memory barrier fallback
 */
void
opssl_memzero(void *ptr, size_t len)
{
    if (ptr == NULL || len == 0)
        return;

#if defined(LIBOP_MEMORY_H)
    /* Real libop is linked in — prefer its hardened helper. */
    op_memzero_explicit(ptr, len);

#elif defined(_WIN32)
    SecureZeroMemory(ptr, len);

#elif defined(__linux__) || defined(__FreeBSD__) || defined(__OpenBSD__) || \
      defined(HAVE_EXPLICIT_BZERO)
    explicit_bzero(ptr, len);

#elif defined(HAVE_MEMSET_S) || defined(__STDC_LIB_EXT1__)
    /* memset_s is part of C11 Annex K; the runtime must define
     * __STDC_WANT_LIB_EXT1__ before including <string.h> for it to be
     * declared.  We compile defensively. */
    (void)memset_s(ptr, len, 0, len);

#else
    /* Portable fallback: volatile pointer prevents the compiler from
     * eliminating the stores; an inline-asm memory barrier prevents
     * reordering the clear past subsequent loads. */
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    size_t n = len;
    while (n--)
        *p++ = 0;
    __asm__ __volatile__("" : : "r"(ptr) : "memory");
#endif
}

/* ─── Secure Key Memory ──────────────────────────────────────────────── */

/*
 * opssl_key_alloc — allocate zero-initialised memory for key material.
 *
 * Pages are mlock()ed so they cannot be paged to swap.  mlock() failure
 * is non-fatal (RLIMIT_MEMLOCK may be too low or we may lack the
 * capability) — the allocation still succeeds, just without the swap
 * guarantee.  op_malloc() aborts on OOM, so the returned pointer is
 * always valid.
 */
void *
opssl_key_alloc(size_t size)
{
    if (size == 0)
        return NULL;

    void *ptr = op_malloc(size);
    /* op_malloc never returns NULL: it aborts via op_outofmemory() on OOM. */

    memset(ptr, 0, size);

#if defined(__unix__) || defined(__APPLE__)
    /* mlock failure is not fatal — try once, ignore EAGAIN/EPERM/ENOMEM. */
    if (mlock(ptr, size) != 0) {
        /* Silently continue — caller still gets zeroed key memory. */
        (void)errno;
    }
#endif

    return ptr;
}

void *
opssl_key_realloc(void *ptr, size_t old_size, size_t new_size)
{
    if (new_size == 0) {
        opssl_key_free(ptr, old_size);
        return NULL;
    }

    void *new_ptr = opssl_key_alloc(new_size);
    if (ptr != NULL && old_size > 0) {
        size_t copy_len = old_size < new_size ? old_size : new_size;
        memcpy(new_ptr, ptr, copy_len);
        opssl_key_free(ptr, old_size);
    }
    return new_ptr;
}

void
opssl_key_free(void *ptr, size_t size)
{
    if (ptr == NULL)
        return;

    /* Wipe BEFORE unlocking so the contents never touch swap on systems
     * that lazily evict from the locked working set. */
    opssl_memzero(ptr, size);

#if defined(__unix__) || defined(__APPLE__)
    if (size > 0)
        (void)munlock(ptr, size);
#endif

    op_free(ptr);
}

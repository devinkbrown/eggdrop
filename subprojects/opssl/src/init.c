/*
 * opssl/init.c — library initialization and lifecycle management.
 *
 * Thread-safe initialization using C23 call_once mechanism.
 * Must be called before using any opssl functions.
 *
 * Copyright (C) 2026 ophion development team
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <opssl/opssl.h>
#include <opssl/platform.h>
#include <opssl/err.h>
#include <threads.h>
#include <stdatomic.h>
#include <stdlib.h>

/* Function declarations for subsystems */
extern void opssl_cpu_detect(void);
extern int  opssl_random_init(void);
extern void opssl_random_cleanup(void);

/*
 * Initialization state. We use a once_flag so the first concurrent caller
 * does the heavy lifting; subsequent callers simply read the cached result.
 * The flag is held in a heap-style sentinel so opssl_cleanup() can reset
 * it for a clean re-init cycle (test suites depend on this).
 */
static once_flag       init_flag   = ONCE_FLAG_INIT;
static atomic_int      init_result = 0; /* 0 = uninit, 1 = success, -1 = failure */
static atomic_int      init_done   = 0; /* set after do_init returns */

/*
 * Internal initialization routine called exactly once per once_flag.
 * Idempotent at the call_once level. Sets init_result/init_done.
 */
static void
do_init(void)
{
    /* Detect CPU capabilities first (cpuid + feature flags). */
    opssl_cpu_detect();

    /* Initialize cryptographic random number generator (seeds DRBG). */
    if (opssl_random_init() != 0) {
        opssl_err_push(OPSSL_ERR_INTERNAL, OPSSL_ERR_ALLOC_FAILED,
                       __FILE__, __LINE__);
        atomic_store_explicit(&init_result, -1, memory_order_release);
    } else {
        atomic_store_explicit(&init_result, 1, memory_order_release);
    }
    atomic_store_explicit(&init_done, 1, memory_order_release);
}

/*
 * Initialize the opssl library.
 * Thread-safe; idempotent. Calling twice is a no-op on the second call.
 * Returns 1 on success, 0 on failure.
 */
int
opssl_init(void)
{
    call_once(&init_flag, do_init);

    /* Spin briefly if another thread is mid-init (call_once already guarantees
     * the slow path is serialized, but the release of init_result happens
     * before call_once returns to *that* thread; other threads still see the
     * write thanks to call_once's happens-before edge.) */
    int r = atomic_load_explicit(&init_result, memory_order_acquire);
    return (r == 1) ? 1 : 0;
}

/*
 * Library constructor — best-effort auto init so callers do not need to
 * remember opssl_init(). We deliberately ignore the result; explicit
 * opssl_init() callers will observe and react to any failure.
 */
__attribute__((constructor))
static void
opssl_auto_init(void)
{
    (void)opssl_init();
}

/*
 * Clean up library resources.
 * Not thread-safe — caller must ensure no other threads are using opssl.
 * After this returns, opssl_init() must be called again before further use.
 */
void
opssl_cleanup(void)
{
    /* Only tear down if we actually initialized; avoids freeing uninit state. */
    if (atomic_load_explicit(&init_done, memory_order_acquire) == 0) {
        return;
    }

    opssl_random_cleanup();
    opssl_err_clear();

    /* Reset state so a subsequent opssl_init() re-runs do_init. */
    atomic_store_explicit(&init_result, 0, memory_order_release);
    atomic_store_explicit(&init_done,   0, memory_order_release);
    init_flag = (once_flag)ONCE_FLAG_INIT;
}

/*
 * Get the library version string.
 * Returns a static string like "1.0.0".
 */
const char *
opssl_version_string(void)
{
    return OPSSL_VERSION_STRING;
}

/*
 * Get the library version as a hexadecimal number.
 * Format: 0xMMmmppXX where:
 *   MM = major version (1)
 *   mm = minor version (0)
 *   pp = patch version (0)
 *   XX = reserved (00)
 *
 * Returns 0x01000000UL for version 1.0.0.
 */
unsigned long
opssl_version_hex(void)
{
    return OPSSL_VERSION_HEX;
}

__attribute__((weak, noreturn)) void
op_outofmemory(void)
{
    abort();
}
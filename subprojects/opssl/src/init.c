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

/* Function declarations for subsystems */
extern void opssl_cpu_detect(void);
extern int opssl_random_init(void);
extern void opssl_random_cleanup(void);

/* Global initialization state */
static once_flag init_flag = ONCE_FLAG_INIT;
static thread_local int init_result = 0;

/*
 * Internal initialization routine called exactly once.
 * Initializes CPU feature detection and random number generator.
 */
static void
do_init(void)
{
    /* Detect CPU capabilities first */
    opssl_cpu_detect();

    /* Initialize cryptographic random number generator */
    if (opssl_random_init() != 0) {
        init_result = 0;  /* Failure */
        return;
    }

    init_result = 1;  /* Success */
}

/*
 * Initialize the opssl library.
 * This function is thread-safe and may be called multiple times.
 * Only the first call performs actual initialization.
 *
 * Returns 1 on success, 0 on failure.
 */
int
opssl_init(void)
{
    /* Ensure initialization happens exactly once across all threads */
    call_once(&init_flag, do_init);

    return init_result;
}

/*
 * Clean up library resources.
 * Should be called when the library is no longer needed.
 * Not thread-safe - caller must ensure no other threads are using opssl.
 */
__attribute__((constructor))
static void opssl_auto_init(void)
{
    opssl_init();
}

void
opssl_cleanup(void)
{
    /* Clean up random number generator state */
    opssl_random_cleanup();

    /* Clear any remaining errors */
    opssl_err_clear();
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
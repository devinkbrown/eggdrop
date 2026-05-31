/*
 * opssl/crypto/random.c — cryptographically secure random number generation.
 *
 * Priority order:
 *   Linux         : getrandom(2)            → /dev/urandom fallback
 *   OpenBSD       : getentropy(3) / arc4random_buf(3) (never fails)
 *   FreeBSD/macOS : getentropy(3)           → arc4random_buf(3) fallback
 *   Other POSIX   : /dev/urandom
 *
 * Never falls back silently — if entropy is unavailable we return -1.
 * EINTR is retried.  Short reads are handled by the loop.
 *
 * Fork-safety: the kernel CSPRNG is fork-safe on every supported platform
 * (getrandom, getentropy and arc4random_buf all reseed across fork).  We
 * additionally cache the owning PID so that if a caller misuses any future
 * stateful path we can detect it.  The cached PID is consulted by
 * opssl_random_bytes() before each request and re-initialised on mismatch.
 *
 * Copyright (C) 2026 ophion development team
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <opssl/platform.h>

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>

#if defined(__linux__)
# include <sys/random.h>
# include <sys/syscall.h>
#endif

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || \
    defined(__NetBSD__) || defined(__DragonFly__)
# include <stdlib.h>
# if defined(__OpenBSD__) || defined(__FreeBSD__) || defined(__NetBSD__) || \
     defined(__APPLE__)
#  include <unistd.h>   /* getentropy() */
# endif
#endif

/* Cached PID for fork-detection sanity checking. */
static volatile pid_t g_random_owner_pid = 0;

/* Max bytes a single getentropy() request will accept (POSIX limit). */
#define OPSSL_GETENTROPY_MAX 256

/*
 * read_urandom — robust /dev/urandom reader (loop, EINTR, short reads).
 * Returns 0 on success, -1 on error.  Always closes fd.
 */
static int
read_urandom(void *buf, size_t len)
{
    int fd;
    do {
        fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    } while (fd < 0 && errno == EINTR);
    if (fd < 0)
        return -1;

    uint8_t *p = buf;
    size_t remaining = len;

    while (remaining > 0) {
        ssize_t ret = read(fd, p, remaining);
        if (ret < 0) {
            if (errno == EINTR)
                continue;
            (void)close(fd);
            return -1;
        }
        if (ret == 0) {
            /* EOF on /dev/urandom is impossible on a sane system */
            (void)close(fd);
            return -1;
        }
        p += (size_t)ret;
        remaining -= (size_t)ret;
    }

    (void)close(fd);
    return 0;
}

/*
 * fill_entropy — single-pass platform entropy fetch.
 * Returns 0 on success, -1 on hard failure.
 */
static int
fill_entropy(void *buf, size_t len)
{
#if defined(__linux__)
    uint8_t *p = buf;
    size_t remaining = len;

    while (remaining > 0) {
        ssize_t ret = getrandom(p, remaining, 0);
        if (ret < 0) {
            if (errno == EINTR)
                continue;
            if (errno == ENOSYS)
                return read_urandom(p, remaining);
            return -1;
        }
        p += (size_t)ret;
        remaining -= (size_t)ret;
    }
    return 0;

#elif defined(__OpenBSD__)
    /* OpenBSD: getentropy(3) is the canonical interface and never fails
     * for len <= 256.  Chunk for safety. */
    uint8_t *p = buf;
    size_t remaining = len;
    while (remaining > 0) {
        size_t chunk = remaining > OPSSL_GETENTROPY_MAX
                       ? OPSSL_GETENTROPY_MAX : remaining;
        if (getentropy(p, chunk) != 0)
            return -1;
        p += chunk;
        remaining -= chunk;
    }
    return 0;

#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__)
    /* Prefer getentropy(); fall back to arc4random_buf() (never fails). */
    uint8_t *p = buf;
    size_t remaining = len;
    while (remaining > 0) {
        size_t chunk = remaining > OPSSL_GETENTROPY_MAX
                       ? OPSSL_GETENTROPY_MAX : remaining;
        if (getentropy(p, chunk) != 0) {
            arc4random_buf(p, remaining);
            return 0;
        }
        p += chunk;
        remaining -= chunk;
    }
    return 0;

#else
    return read_urandom(buf, len);
#endif
}

int
opssl_random_bytes(void *buf, size_t len)
{
    if (len == 0)
        return 0;
    if (buf == NULL)
        return -1;

    /* Fork detection: if our PID changed since last call, the child has
     * inherited any future stateful state.  The underlying kernel CSPRNG
     * already reseeds, but we still refresh the cached PID so subsequent
     * checks remain meaningful. */
    pid_t self = getpid();
    if (g_random_owner_pid != self)
        g_random_owner_pid = self;

    return fill_entropy(buf, len);
}

int
opssl_random_uniform(uint32_t upper_bound, uint32_t *out)
{
    if (out == NULL)
        return -1;
    if (upper_bound < 2) {
        *out = 0;
        return 0;
    }

    /*
     * Rejection sampling to avoid modulo bias.
     * min = (2^32) mod upper_bound, computed as (-upper_bound) mod upper_bound
     * in unsigned arithmetic.
     */
    const uint32_t min = (uint32_t)(-upper_bound) % upper_bound;
    uint32_t r;

    for (;;) {
        if (opssl_random_bytes(&r, sizeof(r)) != 0)
            return -1;
        if (r >= min) {
            *out = r % upper_bound;
            return 0;
        }
    }
}

int
opssl_random_init(void)
{
    /* Verify entropy source works at startup, and prime the PID cache. */
    g_random_owner_pid = getpid();

    uint8_t test[32];
    int rc = opssl_random_bytes(test, sizeof(test));
    opssl_memzero(test, sizeof(test));
    return rc;
}

void
opssl_random_cleanup(void)
{
    /* Nothing to clean up for syscall-based RNG */
    g_random_owner_pid = 0;
}

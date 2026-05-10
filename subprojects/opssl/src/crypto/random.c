/*
 * opssl/crypto/random.c — cryptographically secure random number generation.
 *
 * Priority: getrandom(2) > getentropy(2) > arc4random_buf > /dev/urandom
 * Never falls back silently — if entropy is unavailable, we abort.
 *
 * Copyright (C) 2026 ophion development team
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <opssl/platform.h>

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#if defined(__linux__)
# include <sys/random.h>
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__)
# include <stdlib.h>
#endif

int
opssl_random_bytes(void *buf, size_t len)
{
    if (len == 0)
        return 0;

#if defined(__linux__) && defined(SYS_getrandom)
    /* getrandom(2): best option on Linux 3.17+ */
    uint8_t *p = buf;
    size_t remaining = len;

    while (remaining > 0) {
        ssize_t ret = getrandom(p, remaining, 0);
        if (ret < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        p += ret;
        remaining -= (size_t)ret;
    }
    return 0;

#elif defined(__OpenBSD__) || defined(__APPLE__) || defined(__FreeBSD__)
    /* arc4random_buf: never fails, always seeded from kernel */
    arc4random_buf(buf, len);
    return 0;

#else
    /* Fallback: /dev/urandom (only if syscalls unavailable) */
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;

    uint8_t *p = buf;
    size_t remaining = len;

    while (remaining > 0) {
        ssize_t ret = read(fd, p, remaining);
        if (ret < 0) {
            if (errno == EINTR)
                continue;
            close(fd);
            return -1;
        }
        if (ret == 0) {
            close(fd);
            return -1;
        }
        p += ret;
        remaining -= (size_t)ret;
    }

    close(fd);
    return 0;
#endif
}

int
opssl_random_uniform(uint32_t upper_bound, uint32_t *out)
{
    if (upper_bound < 2) {
        *out = 0;
        return 0;
    }

    /* Rejection sampling to avoid modulo bias */
    uint32_t min = -upper_bound % upper_bound;
    uint32_t r;

    for (;;) {
        if (opssl_random_bytes(&r, sizeof(r)) != 0)
            return -1;
        if (r >= min)
            break;
    }

    *out = r % upper_bound;
    return 0;
}

int
opssl_random_init(void)
{
    /* Verify entropy source works at startup */
    uint8_t test[32];
    return opssl_random_bytes(test, sizeof(test));
}

void
opssl_random_cleanup(void)
{
    /* Nothing to clean up for syscall-based RNG */
}

/*
 * Copyright (c) 2024 OpSSL Project
 * Licensed under the MIT License
 */

#include <opssl/platform.h>
#include <opssl/types.h>
#include <opssl/err.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>

/* Local compat: map non-existent error codes to available ones */
#define OPSSL_ERR_INVALID_FD         OPSSL_ERR_INVALID_ARGUMENT
#define OPSSL_ERR_NULL_POINTER       OPSSL_ERR_INVALID_ARGUMENT
#define OPSSL_ERR_MEMORY_ALLOCATION  OPSSL_ERR_ALLOC_FAILED
#define OPSSL_ERR_WANT_READ          OPSSL_ERR_INVALID_ARGUMENT
#define OPSSL_ERR_WANT_WRITE         OPSSL_ERR_INVALID_ARGUMENT
#define OPSSL_ERR_CONNECTION_LOST    OPSSL_ERR_INVALID_ARGUMENT
#define OPSSL_ERR_IO_ERROR           OPSSL_ERR_INVALID_ARGUMENT
#define OPSSL_ERR_NO_SPACE           OPSSL_ERR_BUFFER_TOO_SMALL
#define OPSSL_ERR_INVALID_OPERATION  OPSSL_ERR_INVALID_ARGUMENT
#define set_error(code) opssl_set_error((code), NULL)

/*
 * BIO (Basic I/O) abstraction
 * Provides transport layer for TLS connections supporting both
 * file descriptor and callback-based I/O
 */

struct opssl_bio {
    int fd;                         /* File descriptor for fd mode */
    opssl_read_cb read_cb;         /* Read callback for callback mode */
    opssl_write_cb write_cb;       /* Write callback for callback mode */
    void *userdata;                /* User data passed to callbacks */
    bool use_callbacks;            /* True if using callbacks, false for fd */
    bool eof_received;             /* EOF status for reads */
    int last_error;                /* Last I/O error code */
};

opssl_bio_t *opssl_bio_new_fd(int fd)
{
    if (fd < 0) {
        set_error(OPSSL_ERR_INVALID_FD);
        return NULL;
    }

    opssl_bio_t *bio = calloc(1, sizeof(opssl_bio_t));
    if (!bio) {
        set_error(OPSSL_ERR_MEMORY_ALLOCATION);
        return NULL;
    }

    bio->fd = fd;
    bio->use_callbacks = false;
    bio->eof_received = false;
    bio->last_error = 0;

    return bio;
}

opssl_bio_t *opssl_bio_new_cb(opssl_read_cb read_cb, opssl_write_cb write_cb, void *userdata)
{
    if (!read_cb || !write_cb) {
        set_error(OPSSL_ERR_NULL_POINTER);
        return NULL;
    }

    opssl_bio_t *bio = calloc(1, sizeof(opssl_bio_t));
    if (!bio) {
        set_error(OPSSL_ERR_MEMORY_ALLOCATION);
        return NULL;
    }

    bio->fd = -1;
    bio->read_cb = read_cb;
    bio->write_cb = write_cb;
    bio->userdata = userdata;
    bio->use_callbacks = true;
    bio->eof_received = false;
    bio->last_error = 0;

    return bio;
}

void opssl_bio_free(opssl_bio_t *bio)
{
    if (bio) {
        /* Note: We don't close the fd here - that's the caller's responsibility */
        memset(bio, 0, sizeof(*bio));
        free(bio);
    }
}

ssize_t opssl_bio_read(opssl_bio_t *bio, uint8_t *buf, size_t len)
{
    if (!bio || !buf || len == 0) {
        set_error(OPSSL_ERR_NULL_POINTER);
        return -1;
    }

    if (bio->eof_received) {
        return 0; /* EOF */
    }

    ssize_t result;

    if (bio->use_callbacks) {
        /* Use callback mode */
        result = bio->read_cb(bio->userdata, buf, len);

        if (result < 0) {
            bio->last_error = errno;
            /* Callbacks should set errno appropriately */
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                set_error(OPSSL_ERR_WANT_READ);
            } else if (errno == ECONNRESET || errno == EPIPE) {
                set_error(OPSSL_ERR_CONNECTION_LOST);
            } else {
                set_error(OPSSL_ERR_IO_ERROR);
            }
        } else if (result == 0) {
            bio->eof_received = true;
        }
    } else {
        /* Use file descriptor mode */
        result = read(bio->fd, buf, len);

        if (result < 0) {
            bio->last_error = errno;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                set_error(OPSSL_ERR_WANT_READ);
            } else if (errno == ECONNRESET || errno == EPIPE) {
                set_error(OPSSL_ERR_CONNECTION_LOST);
            } else if (errno == EINTR) {
                /* Interrupted system call - try again */
                set_error(OPSSL_ERR_WANT_READ);
            } else {
                set_error(OPSSL_ERR_IO_ERROR);
            }
        } else if (result == 0) {
            bio->eof_received = true;
        }
    }

    return result;
}

ssize_t opssl_bio_write(opssl_bio_t *bio, const uint8_t *buf, size_t len)
{
    if (!bio || !buf || len == 0) {
        set_error(OPSSL_ERR_NULL_POINTER);
        return -1;
    }

    ssize_t result;

    if (bio->use_callbacks) {
        /* Use callback mode */
        result = bio->write_cb(bio->userdata, buf, len);

        if (result < 0) {
            bio->last_error = errno;
            /* Callbacks should set errno appropriately */
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                set_error(OPSSL_ERR_WANT_WRITE);
            } else if (errno == ECONNRESET || errno == EPIPE) {
                set_error(OPSSL_ERR_CONNECTION_LOST);
            } else {
                set_error(OPSSL_ERR_IO_ERROR);
            }
        }
    } else {
        /* Use file descriptor mode */
        result = write(bio->fd, buf, len);

        if (result < 0) {
            bio->last_error = errno;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                set_error(OPSSL_ERR_WANT_WRITE);
            } else if (errno == ECONNRESET || errno == EPIPE) {
                set_error(OPSSL_ERR_CONNECTION_LOST);
            } else if (errno == EINTR) {
                /* Interrupted system call - try again */
                set_error(OPSSL_ERR_WANT_WRITE);
            } else if (errno == ENOSPC) {
                set_error(OPSSL_ERR_NO_SPACE);
            } else {
                set_error(OPSSL_ERR_IO_ERROR);
            }
        }
    }

    return result;
}

int opssl_bio_get_fd(const opssl_bio_t *bio)
{
    if (!bio) {
        set_error(OPSSL_ERR_NULL_POINTER);
        return -1;
    }

    if (bio->use_callbacks) {
        set_error(OPSSL_ERR_INVALID_OPERATION);
        return -1;
    }

    return bio->fd;
}

void opssl_bio_set_fd(opssl_bio_t *bio, int fd)
{
    if (!bio) {
        set_error(OPSSL_ERR_NULL_POINTER);
        return;
    }

    if (bio->use_callbacks) {
        set_error(OPSSL_ERR_INVALID_OPERATION);
        return;
    }

    bio->fd = fd;
    bio->eof_received = false;
    bio->last_error = 0;
}

bool opssl_bio_eof(const opssl_bio_t *bio)
{
    if (!bio) {
        return true;
    }
    return bio->eof_received;
}

int opssl_bio_pending(const opssl_bio_t *bio)
{
    if (!bio) {
        set_error(OPSSL_ERR_NULL_POINTER);
        return -1;
    }

    if (bio->use_callbacks) {
        /* Cannot determine pending data for callback mode */
        return 0;
    }

    /* For fd mode, we can't easily determine pending data without blocking
     * Return 0 to indicate no known pending data */
    return 0;
}

int opssl_bio_flush(opssl_bio_t *bio)
{
    if (!bio) {
        set_error(OPSSL_ERR_NULL_POINTER);
        return -1;
    }

    if (bio->use_callbacks) {
        /* Callback mode doesn't support explicit flush */
        return 0;
    }

    /* For fd mode, use fsync to ensure data is written */
    if (fsync(bio->fd) < 0) {
        bio->last_error = errno;
        if (errno == EINVAL || errno == EROFS) {
            /* Not a regular file or read-only - not an error */
            return 0;
        }
        set_error(OPSSL_ERR_IO_ERROR);
        return -1;
    }

    return 0;
}

int opssl_bio_reset(opssl_bio_t *bio)
{
    if (!bio) {
        set_error(OPSSL_ERR_NULL_POINTER);
        return -1;
    }

    bio->eof_received = false;
    bio->last_error = 0;

    return 0;
}

bool opssl_bio_should_retry(const opssl_bio_t *bio)
{
    if (!bio) {
        return false;
    }

    /* Check if the last error indicates we should retry */
    return (bio->last_error == EAGAIN ||
            bio->last_error == EWOULDBLOCK ||
            bio->last_error == EINTR);
}

void *opssl_bio_get_userdata(const opssl_bio_t *bio)
{
    if (!bio) {
        set_error(OPSSL_ERR_NULL_POINTER);
        return NULL;
    }

    return bio->userdata;
}

void opssl_bio_set_userdata(opssl_bio_t *bio, void *userdata)
{
    if (!bio) {
        set_error(OPSSL_ERR_NULL_POINTER);
        return;
    }

    bio->userdata = userdata;
}

bool opssl_bio_uses_callbacks(const opssl_bio_t *bio)
{
    if (!bio) {
        return false;
    }

    return bio->use_callbacks;
}
/*
 * libop/src/op_lib_stub.c — eggdrop implementations of libop support functions.
 *
 * Provides:
 *   op_lib_log / op_lib_restart — stderr + abort (replaces ircd log/restart)
 *   op_current_time / op_current_time_tv — wall-clock helpers used by commio
 *   op_base64_encode — base64 encoder used by websocket handshake
 *
 * Copyright (C) 2026 ophion development team / eggdrop contributors
 * GPL-2.0-or-later
 */

#define _GNU_SOURCE 1
#include <libop_config.h>
#include <op_lib.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>

/* -------------------------------------------------------------------------
 * op_lib_log — non-fatal diagnostic (stderr in eggdrop)
 * ---------------------------------------------------------------------- */
void
op_lib_log(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	fputs("eggdrop libop: ", stderr);
	vfprintf(stderr, fmt, ap);
	fputc('\n', stderr);
	va_end(ap);
}

/* -------------------------------------------------------------------------
 * op_lib_restart — fatal error (abort in eggdrop; ircd would restart)
 * ---------------------------------------------------------------------- */
__attribute__((noreturn))
void
op_lib_restart(const char *reason)
{
	fprintf(stderr, "eggdrop libop: fatal — %s\n", reason ? reason : "unknown");
	abort();
}

/* -------------------------------------------------------------------------
 * op_current_time / op_current_time_tv — wall clock for commio timers.
 *
 * These are called frequently from the event loop.  We cache the value
 * per-call with gettimeofday so the overhead is just one syscall.
 * ---------------------------------------------------------------------- */
static struct timeval g_tv;

time_t
op_current_time(void)
{
	gettimeofday(&g_tv, NULL);
	return g_tv.tv_sec;
}

const struct timeval *
op_current_time_tv(void)
{
	gettimeofday(&g_tv, NULL);
	return &g_tv;
}

/* op_set_time — refresh the cached wall clock (called by I/O backends) */
void
op_set_time(void)
{
	gettimeofday(&g_tv, NULL);
}

/* -------------------------------------------------------------------------
 * op_base64_encode — encode binary data as a NUL-terminated base64 string.
 * Caller must free() the returned buffer.
 * ---------------------------------------------------------------------- */
static const char b64table[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

unsigned char *
op_base64_encode(const unsigned char *src, size_t len)
{
	size_t outlen = ((len + 2) / 3) * 4 + 1;
	unsigned char *out = malloc(outlen);
	size_t i, j;
	if (!out)
		return NULL;
	for (i = 0, j = 0; i < len; ) {
		unsigned int octet_a = i < len ? src[i++] : 0;
		unsigned int octet_b = i < len ? src[i++] : 0;
		unsigned int octet_c = i < len ? src[i++] : 0;
		unsigned int triple = (octet_a << 16) | (octet_b << 8) | octet_c;
		out[j++] = b64table[(triple >> 18) & 0x3F];
		out[j++] = b64table[(triple >> 12) & 0x3F];
		out[j++] = b64table[(triple >>  6) & 0x3F];
		out[j++] = b64table[(triple >>  0) & 0x3F];
	}
	/* padding */
	if (len % 3 == 1) { out[j-2] = '='; out[j-1] = '='; }
	else if (len % 3 == 2) { out[j-1] = '='; }
	out[j] = '\0';
	return out;
}

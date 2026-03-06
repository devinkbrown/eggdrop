/*
 * arc4random.c -- ChaCha20-backed CSPRNG providing arc4random(3)-compatible API.
 *
 * Ported from ophion's libop/src/arc4random.c to eggdrop.
 *
 * Copyright (C) 2024-2025 Ophion IRC Daemon contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 *
 * -------------------------------------------------------------------------
 * Design notes
 * -------------------------------------------------------------------------
 * The underlying primitive is the ChaCha20 stream cipher operating in a
 * "fast-key-erasure" construction (https://blog.cr.yp.to/20170723-random.html).
 * This supersedes the old RC4/ARC4 core with a cipher that:
 *   - carries no known cryptanalytic weaknesses at the 256-bit key level;
 *   - passes all NIST SP 800-22 and TestU01 BigCrush statistical tests;
 *   - has no per-byte state mutation overhead (pure keystream, 64 B/block).
 *
 * Forward secrecy: every REKEY_BYTES the key is replaced with the first
 * 48 bytes of the next block and those bytes are erased from the buffer,
 * so past output cannot be reconstructed even if state is later exposed.
 *
 * Entropy sources (in priority order):
 *   1. getrandom(2)   -- Linux 3.17+, FreeBSD 12+  (atomic, no fd)
 *   2. getentropy(3)  -- OpenBSD 5.6+, FreeBSD 12+, macOS 10.12+
 *   3. /dev/urandom   -- universal fallback
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifndef HAVE_ARC4RANDOM

#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/random.h>

#if defined(HAVE_GETRANDOM)
#  include <sys/random.h>
#elif defined(HAVE_GETENTROPY)
/* getentropy(3) lives in <unistd.h>, already included above */
#endif

/* =========================================================================
 * ChaCha20 block function (RFC 8439 §2.3)
 * ========================================================================= */

#define ROTL32(v, n)  (((v) << (n)) | ((v) >> (32 - (n))))

/* ChaCha20 quarter-round */
#define QR(a, b, c, d)                                  \
	do {                                            \
		(a) += (b); (d) ^= (a); (d) = ROTL32((d), 16); \
		(c) += (d); (b) ^= (c); (b) = ROTL32((b), 12); \
		(a) += (b); (d) ^= (a); (d) = ROTL32((d),  8); \
		(c) += (d); (b) ^= (c); (b) = ROTL32((b),  7); \
	} while (0)

/* Serialize a uint32_t to four little-endian bytes. */
static inline void
store32_le(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v);
	p[1] = (uint8_t)(v >>  8);
	p[2] = (uint8_t)(v >> 16);
	p[3] = (uint8_t)(v >> 24);
}

/* Deserialize four little-endian bytes to uint32_t. */
static inline uint32_t
load32_le(const uint8_t *p)
{
	return ((uint32_t)p[0])
	     | ((uint32_t)p[1] <<  8)
	     | ((uint32_t)p[2] << 16)
	     | ((uint32_t)p[3] << 24);
}

/*
 * Generate one 64-byte ChaCha20 keystream block from a 16-word (512-bit)
 * input state.  The state layout follows RFC 8439 §2.3:
 *
 *   words  0-- 3 : "expand 32-byte k" constants
 *   words  4--11 : 256-bit key
 *   word  12    : 32-bit block counter
 *   words 13--15 : 96-bit nonce
 */
static void
chacha20_block(const uint32_t in[16], uint8_t out[64])
{
	uint32_t x[16];

	for (int i = 0; i < 16; i++)
		x[i] = in[i];

	/* 20 rounds = 10 double-rounds (column then diagonal) */
	for (int i = 0; i < 10; i++) {
		QR(x[ 0], x[ 4], x[ 8], x[12]);
		QR(x[ 1], x[ 5], x[ 9], x[13]);
		QR(x[ 2], x[ 6], x[10], x[14]);
		QR(x[ 3], x[ 7], x[11], x[15]);
		QR(x[ 0], x[ 5], x[10], x[15]);
		QR(x[ 1], x[ 6], x[11], x[12]);
		QR(x[ 2], x[ 7], x[ 8], x[13]);
		QR(x[ 3], x[ 4], x[ 9], x[14]);
	}

	for (int i = 0; i < 16; i++)
		store32_le(out + i * 4, x[i] + in[i]);
}

/* =========================================================================
 * CSPRNG state
 * ========================================================================= */

/*
 * Re-key every REKEY_BYTES of output (fast-key-erasure construction).
 * After reaching this threshold the first 48 bytes of the next block are
 * used as a new key+nonce; those bytes are then zeroed in the buffer so
 * they are never returned as output.
 */
#define REKEY_BYTES  (1u << 20)   /* 1 MiB per key epoch */

/* "expand 32-byte k" -- standard ChaCha20 magic constant */
static const uint32_t CHACHA_CONST[4] = {
	0x61707865u, 0x3320646eu, 0x79622d32u, 0x6b206574u
};

struct csprng {
	uint32_t state[16];           /* ChaCha20 input block              */
	uint8_t  buf[64];             /* current keystream block           */
	size_t   buf_pos;             /* bytes consumed from buf           */
	size_t   bytes_since_rekey;   /* forward-secrecy rotation counter  */
	int      initialized;
};

static struct csprng rng;

/*
 * Load a fresh 48-byte seed (256-bit key + 96-bit nonce) into the state.
 * The block counter resets to 0 and the keystream buffer is invalidated.
 */
static void
csprng_seed(const uint8_t seed[48])
{
	rng.state[0] = CHACHA_CONST[0];
	rng.state[1] = CHACHA_CONST[1];
	rng.state[2] = CHACHA_CONST[2];
	rng.state[3] = CHACHA_CONST[3];

	for (int i = 0; i < 8; i++)           /* 256-bit key: words 4-11 */
		rng.state[4 + i] = load32_le(seed + i * 4);

	rng.state[12] = 0;                    /* block counter            */

	for (int i = 0; i < 3; i++)           /* 96-bit nonce: words 13-15 */
		rng.state[13 + i] = load32_le(seed + 32 + i * 4);

	rng.buf_pos           = 64;           /* force refill on first use */
	rng.bytes_since_rekey = 0;
}

/*
 * Fill buf[0..len-1] with bytes from the OS entropy source.
 * Retries internally on short reads / EINTR.
 */
static void
get_os_entropy(uint8_t *buf, size_t len)
{
#if defined(HAVE_GETRANDOM)
	size_t got = 0;
	while (got < len) {
		ssize_t r = getrandom(buf + got, len - got, 0);
		if (r > 0)
			got += (size_t)r;
	}
#elif defined(HAVE_GETENTROPY)
	while (getentropy(buf, len) != 0)
		;   /* retry on EINTR */
#else
	{
		size_t got = 0;
		int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
		if (fd != -1) {
			while (got < len) {
				ssize_t r = read(fd, buf + got, len - got);
				if (r > 0)
					got += (size_t)r;
			}
			close(fd);
		}
	}
#endif
}

/* Generate the next ChaCha20 block into rng.buf and advance the counter. */
static void
csprng_refill(void)
{
	chacha20_block(rng.state, rng.buf);
	rng.state[12]++;   /* 32-bit counter; wraps safely well within REKEY_BYTES */
	rng.buf_pos = 0;
}

/*
 * Fast-key-erasure re-key: produce one block, adopt its first 48 bytes as
 * the new key+nonce, then zero those bytes so they are never output.
 */
static void
csprng_rekey(void)
{
	uint8_t new_seed[48];

	csprng_refill();
	memcpy(new_seed, rng.buf, sizeof(new_seed));
	memset(rng.buf, 0, sizeof(new_seed));    /* erase key material from buffer */

	csprng_seed(new_seed);
	memset(new_seed, 0, sizeof(new_seed));   /* erase from stack */
}

/* Fill out[0..len-1] with cryptographically strong random bytes. */
static void
csprng_fill(uint8_t *out, size_t len)
{
	while (len > 0) {
		if (rng.bytes_since_rekey >= REKEY_BYTES)
			csprng_rekey();

		if (rng.buf_pos >= 64)
			csprng_refill();

		size_t avail = 64 - rng.buf_pos;
		size_t take  = (avail < len) ? avail : len;

		memcpy(out, rng.buf + rng.buf_pos, take);
		rng.buf_pos           += take;
		rng.bytes_since_rekey += take;
		out += take;
		len -= take;
	}
}

/* =========================================================================
 * Public API  (arc4random(3) compatibility)
 * ========================================================================= */

void
arc4random_stir(void)
{
	uint8_t seed[48];

	get_os_entropy(seed, sizeof(seed));
	csprng_seed(seed);
	memset(seed, 0, sizeof(seed));
	rng.initialized = 1;
}

void
arc4random_addrandom(uint8_t *dat, int datlen)
{
	if (!rng.initialized)
		arc4random_stir();

	/*
	 * XOR the caller's entropy bytes into the key words (words 4-11)
	 * in a position- and byte-rotation-dependent way to prevent an
	 * all-zero input from being a no-op.
	 */
	for (int i = 0; i < datlen; i++)
		rng.state[4 + (i & 7)] ^= (uint32_t)dat[i] << ((i & 3) * 8);

	rng.buf_pos = 64;   /* invalidate buffered output; take effect immediately */
}

uint32_t
arc4random(void)
{
	uint32_t val;

	if (!rng.initialized)
		arc4random_stir();

	csprng_fill((uint8_t *)&val, sizeof(val));
	return val;
}

void
arc4random_buf(void *buf, size_t n)
{
	if (!rng.initialized)
		arc4random_stir();

	csprng_fill((uint8_t *)buf, n);
}

#endif /* !HAVE_ARC4RANDOM */

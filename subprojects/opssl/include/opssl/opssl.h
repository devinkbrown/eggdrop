/*
 * opssl — security-focused TLS library for IRC and beyond.
 *
 * Copyright (C) 2026 ophion development team
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef OPSSL_H
#define OPSSL_H

#include <opssl/types.h>
#include <opssl/err.h>
#include <opssl/ctx.h>
#include <opssl/conn.h>
#include <opssl/crypto.h>
#include <opssl/cert.h>
#include <opssl/ktls.h>
#include <opssl/dtls.h>

#define OPSSL_VERSION_MAJOR  1
#define OPSSL_VERSION_MINOR  0
#define OPSSL_VERSION_PATCH  0
#define OPSSL_VERSION_HEX    0x01000000UL
#define OPSSL_VERSION_STRING "1.0.0"

/*
 * Library lifecycle.
 */
int  opssl_init(void);
void opssl_cleanup(void);

const char *opssl_version_string(void);
unsigned long opssl_version_hex(void);

#endif /* OPSSL_H */

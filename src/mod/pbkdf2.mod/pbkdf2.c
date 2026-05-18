/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * pbkdf2.c -- part of pbkdf2.mod
 *
 * Written by thommey and Michael Ortmann
 *
 * Copyright (C) 2017 - 2025 Eggheads Development Team
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif
#include "src/mod/module.h"

#ifdef TLS
#include <opssl/crypto.h>
#include <opssl/platform.h>
#include <opssl/err.h>

/* Map digest name string to opssl_hmac_algo_t.  Returns -1 if unknown. */
static int pbkdf2_get_algo(const char *name, opssl_hmac_algo_t *algo, int *dlen)
{
  if (!op_strcasecmp(name, "SHA256") || !op_strcasecmp(name, "SHA-256")) {
    *algo = OPSSL_HMAC_SHA256;
    *dlen = OPSSL_SHA256_DIGEST_LEN;
    return 0;
  }
  if (!op_strcasecmp(name, "SHA384") || !op_strcasecmp(name, "SHA-384")) {
    *algo = OPSSL_HMAC_SHA384;
    *dlen = OPSSL_SHA384_DIGEST_LEN;
    return 0;
  }
  if (!op_strcasecmp(name, "SHA512") || !op_strcasecmp(name, "SHA-512")) {
    *algo = OPSSL_HMAC_SHA512;
    *dlen = OPSSL_SHA512_DIGEST_LEN;
    return 0;
  }
  return -1;
}

static Function *global = nullptr; /* before tclpbkdf2.c */
#include "tclpbkdf2.c"

#define MODULE_NAME "encryption2"

/* Salt string length — DO NOT CHANGE; changing breaks stored passwords. */
constexpr int PBKDF2_SALT_LEN = 16;

/* Cryptographic hash function used. */
static char pbkdf2_method[28] = "SHA256";
/* Enable re-encoding of password if pbkdf2-method and / or pbkdf2-rounds
 * change.
 */
static int pbkdf2_re_encode = 1;
/* Number of rounds (iterations) */
static int pbkdf2_rounds = 16000;

static char *pbkdf2_close(void)
{
  return "You cannot unload the " MODULE_NAME " module.";
}

static void bufcount(char **buf, int *buflen, int bytes)
{
  *buf += bytes;
  *buflen -= bytes;
}

static int b64_ntop_without_padding(u_char const *src, size_t srclength,
                                    char *target, size_t targsize)
{
  char *c;

  if (b64_ntop(src, srclength, target, targsize) < 0)
    return -1;
  c = strchr(target, '=');
  if (c) {
    *c = 0;
    targsize = (c - target);
  }
  return targsize;
}

/* Return
 *   hash = "$pbkdf2-<digest>$rounds=<rounds>$<salt>$<hash>" (PHC string format)
 *     salt and hash = base64
 *   nullptr = error
 */
static char *pbkdf2_hash(const char *pass, const char *digest_name,
                         const unsigned char *salt, unsigned int saltlen,
                         unsigned int rounds)
{
  opssl_hmac_algo_t algo;
  int digestlen, ret;
  int outlen, restlen;
  static char out[256]; /* static object is initialized to zero (Standard C) */
  char *out2;
  unsigned char *buf;

  if (pbkdf2_get_algo(digest_name, &algo, &digestlen)) {
    putlog(LOG_MISC, "*", "PBKDF2 error: Unknown message digest '%s'.",
           digest_name);
    return nullptr;
  }
  outlen = strlen("$pbkdf2-") + strlen(digest_name) +
           strlen("$rounds=4294967295$i") + B64_NTOP_CALCULATE_SIZE(saltlen) +
           1 + B64_NTOP_CALCULATE_SIZE(digestlen);
  if ((outlen + 1) > sizeof out) {
    putlog(LOG_MISC, "*", "PBKDF2 error: outlen %i > sizeof out %ld.", outlen,
           (long)sizeof out);
    return nullptr;
  }
  out2 = out;
  restlen = outlen;
  {
    op_strbuf_t _b = {};
    op_strbuf_init(&_b);
    op_strbuf_appendf(&_b, "$pbkdf2-%s$rounds=%u$", digest_name, rounds);
    op_strlcpy((char *) out2, op_strbuf_str(&_b), restlen);
    bufcount(&out2, &restlen, op_strbuf_len(&_b));
    op_strbuf_free(&_b);
  }
  ret = b64_ntop_without_padding(salt, saltlen, out2, restlen);
  if (ret < 0) {
    explicit_bzero(out, outlen);
    putlog(LOG_MISC, "*", "PBKDF2 error: b64_ntop(salt).");
    return nullptr;
  }
  bufcount(&out2, &restlen, ret);
  out2[0] = '$';
  bufcount(&out2, &restlen, 1);
  buf = op_malloc(digestlen);
  struct egg_rusage_timer rt;
  egg_timer_start(&rt);
  if (opssl_pbkdf2(algo,
                   (const uint8_t *) pass, strlen(pass),
                   salt, saltlen, rounds,
                   buf, digestlen) != 1) {
    explicit_bzero(buf, digestlen);
    explicit_bzero(out, outlen);
    putlog(LOG_MISC, "*", "PBKDF2 key derivation error: %s.",
           opssl_err_string(opssl_err_get()));
    op_free(buf);
    return nullptr;
  }
  double ums, sms;
  if (egg_timer_stop(&rt, &ums, &sms))
    debug4("pbkdf2 method %s rounds %i, user %.3fms sys %.3fms",
           digest_name, rounds, ums, sms);
  else
    debug1("PBKDF2 error: getrusage(): %s", strerror(errno));
  if (b64_ntop_without_padding(buf, digestlen, out2, restlen) < 0) {
    explicit_bzero(out, outlen);
    putlog(LOG_MISC, "*", "PBKDF2 error: b64_ntop(hash).");
    op_free(buf);
    return nullptr;
  }
  op_free(buf);
  return out;
}

/* Return
 *   hash = "$pbkdf2-<digest>$rounds=<rounds>$<salt>$<hash>" (PHC string format)
 *     salt and hash = base64
 *   nullptr = error
 */
static char *pbkdf2_encrypt(const char *pass)
{
  unsigned char salt[PBKDF2_SALT_LEN];
  static char *buf;

  if (opssl_random_bytes(salt, sizeof salt) != 1) {
    putlog(LOG_MISC, "*", "PBKDF2 error: opssl_random_bytes(): %s.",
           opssl_err_string(opssl_err_get()));
    return nullptr;
  }
  if (!(buf = pbkdf2_hash(pass, pbkdf2_method, salt, sizeof salt,
                          pbkdf2_rounds))) {
    explicit_bzero(salt, sizeof salt);
    return nullptr;
  }
  explicit_bzero(salt, sizeof salt);
  return buf;
}

/* Return
 *   hash = "$pbkdf2-<digest>$rounds=<rounds>$<salt>$<hash>" (PHC string format)
 *     salt and hash = base64
 *     old encrypted = verify successful
 *     new encrypted = verify successful, reenrypted with new parameters
 *   nullptr = verify failed
 */
static char *pbkdf2_verify(const char *pass, const char *encrypted)
{
  char method[sizeof pbkdf2_method],
       b64salt[B64_NTOP_CALCULATE_SIZE(PBKDF2_SALT_LEN) + 1],
       b64hash[B64_NTOP_CALCULATE_SIZE(256) + 1];
  op_strbuf_t format_buf = {};
  op_strbuf_init(&format_buf);
  unsigned int rounds;
  opssl_hmac_algo_t algo;
  int digestlen;
  unsigned char salt[PBKDF2_SALT_LEN + 1];
  int saltlen;
  static char *buf;

  op_strbuf_appendf(&format_buf, "$pbkdf2-%%%zu[^$]$rounds=%%u$%%%zu[^$]$%%%zus",
                   (sizeof method) - 1, (sizeof b64salt) - 1, (sizeof b64hash) - 1);
  if (op_strbuf_len(&format_buf) != 39) {
    putlog(LOG_MISC, "*", "PBKDF2 error: could not initialize parser for hashed password.");
    op_strbuf_free(&format_buf);
    return nullptr;
  }
  if (sscanf(encrypted, op_strbuf_str(&format_buf), method, &rounds, b64salt, b64hash) != 4) {
    op_strbuf_free(&format_buf);
    putlog(LOG_MISC, "*", "PBKDF2 error: could not parse hashed password.");
    return nullptr;
  }
  op_strbuf_free(&format_buf);
  if (pbkdf2_get_algo(method, &algo, &digestlen)) {
    putlog(LOG_MISC, "*", "PBKDF2 error: Unknown message digest '%s'.", method);
    return nullptr;
  }
  if (b64salt[22] == 0) {
    b64salt[22] = '=';
    b64salt[23] = '=';
    b64salt[24] = 0;
  }
  else if (b64salt[23] == 0) {
    b64salt[23] = '=';
    b64salt[24] = 0;
  }
  saltlen = b64_pton(b64salt, salt, sizeof salt);
  if (saltlen < 0) {
    putlog(LOG_MISC, "*", "PBKDF2 error: b64_pton(%s).", b64salt);
    return nullptr;
  }
  if (!(buf = pbkdf2_hash(pass, method, salt, saltlen, rounds))) {
    explicit_bzero(salt, saltlen);
    return nullptr;
  }
  explicit_bzero(salt, saltlen);
  if (crypto_verify(encrypted, buf)) {
    explicit_bzero(buf, strlen(buf));
    return nullptr;
  }
  explicit_bzero(buf, strlen(buf));
  if (pbkdf2_re_encode &&
      ((rounds != pbkdf2_rounds) || strcmp(method, pbkdf2_method)))
    return pbkdf2_encrypt(pass);
  return (char *) encrypted;
}

static tcl_ints my_tcl_ints[] = {
  {"pbkdf2-re-encode", &pbkdf2_re_encode, 0},
  {"pbkdf2-rounds",    &pbkdf2_rounds,    0},
  {nullptr,               nullptr,              0}
};

static tcl_strings my_tcl_strings[] = {
  {"pbkdf2-method", pbkdf2_method, 27, 0},
  {nullptr,            nullptr,          0,  0}
};

EXPORT_SCOPE char *pbkdf2_start(Function *global_funcs);

static Function pbkdf2_table[] = {
  (Function) pbkdf2_start,
  (Function) pbkdf2_close,
  nullptr, /* expmem */
  nullptr, /* report */
  (Function) pbkdf2_encrypt,
  (Function) pbkdf2_verify
};

static int pbkdf2_init(void)
{
  opssl_hmac_algo_t algo;
  int dlen;

  if (pbkdf2_get_algo(pbkdf2_method, &algo, &dlen)) {
    putlog(LOG_MISC, "*", "PBKDF2 error: Unknown message digest '%s'.",
           pbkdf2_method);
    return 1;
  }
  return 0;
}

#endif
char *pbkdf2_start(Function *global_funcs)
{
#ifdef TLS

  /* `global_funcs' is nullptr if eggdrop is recovering from a restart.
   *
   * As the encryption module is never unloaded, only initialise stuff
   * that got reset during restart, e.g. the tcl bindings.
   */
  if (global_funcs) {
    global = global_funcs;
    if (!module_rename("pbkdf2", MODULE_NAME))
      return "Already loaded.";
    module_register(MODULE_NAME, pbkdf2_table, 1, 0);
    if (!module_depend(MODULE_NAME, "eggdrop", 109, 0)) {
      module_undepend(MODULE_NAME);
      return "This module requires Eggdrop 1.9.0 or later.";
    }
    if (pbkdf2_init()) {
      module_undepend(MODULE_NAME);
      return "Initialization failure";
    }
    add_hook(HOOK_ENCRYPT_PASS2, (Function) pbkdf2_encrypt);
    add_hook(HOOK_VERIFY_PASS2, (Function) pbkdf2_verify);
    add_tcl_commands(my_tcl_cmds);
    add_tcl_ints(my_tcl_ints);
    add_tcl_strings(my_tcl_strings);
  }
  return nullptr;
#else
  return "Initialization failure: configured with --disable-tls or TLS library not found";
#endif
}

/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * sasl.c -- part of server.mod
 *
 * Written by Michael Ortmann
 *
 * Copyright (C) 2019 - 2025 Eggheads Development Team
 */

/* RFC 5802 - printable ASCII characters excluding ','
 * printable = %x21-2B / %x2D-7E
 */
#define CHARSET_SCRAM "\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e"

#define CLIENT_KEY "Client Key"
#define SERVER_KEY "Server Key"

/* Available sasl mechanisms */
enum {
  SASL_MECHANISM_PLAIN,
  SASL_MECHANISM_ECDSA_NIST256P_CHALLENGE,
  SASL_MECHANISM_EXTERNAL,
  SASL_MECHANISM_SCRAM_SHA_256,
  SASL_MECHANISM_SCRAM_SHA_512,
  SASL_MECHANISM_ECDH_X25519_CHALLENGE,
  SASL_MECHANISM_NUM
};

constexpr int SASL_PASSWORD_MAX  = 120;
constexpr int SASL_ECDSA_KEY_MAX = 120;

static int sasl_timeout_time = 0;
static int sasl_continue = 1;
static char sasl_username[NICKMAX + 1];
static int sasl_mechanism = 0;
static char sasl_password[SASL_PASSWORD_MAX + 1];
static char sasl_ecdsa_key[SASL_ECDSA_KEY_MAX + 1];
static char sasl_x25519_key[SASL_ECDSA_KEY_MAX + 1];
static int sasl_timeout = 15;
int sasl = 0;

/* Available sasl mechanisms. */
static char const *SASL_MECHANISMS[SASL_MECHANISM_NUM] = {
  [SASL_MECHANISM_PLAIN]                    = "PLAIN",
  [SASL_MECHANISM_ECDSA_NIST256P_CHALLENGE] = "ECDSA-NIST256P-CHALLENGE",
  [SASL_MECHANISM_EXTERNAL]                 = "EXTERNAL",
  [SASL_MECHANISM_SCRAM_SHA_256]            = "SCRAM-SHA-256",
  [SASL_MECHANISM_SCRAM_SHA_512]            = "SCRAM-SHA-512",
  [SASL_MECHANISM_ECDH_X25519_CHALLENGE]    = "ECDH-X25519-CHALLENGE",
};

/* scram state */
#ifdef TLS
#include <opssl/crypto.h>
#include <opssl/cert.h>
#include <opssl/platform.h>
#include <opssl/err.h>
opssl_hmac_algo_t digest_algo;
uint8_t salted_password[OPSSL_HMAC_MAX_DIGEST_LEN];
static int step = 0;
char nonce[21]; /* atheme defines acceptable client nonce len min 8 max 512 chars
                 * nonce 128 bit = math.ceil(128 / math.log(93, 2)) = 20 chars
                 * 3 major irc clients and postgres use 18, looks like ripping is still a thing ;)
                 */
char client_first_message[1024];
int digest_len, auth_message_len;
char auth_message[3069];
/* a client implementation MAY cache ClientKey&ServerKey */
char last_sasl_password[sizeof sasl_password];
char last_salt_b64[96] = "";
char last_i[32] = "";
uint8_t client_key[OPSSL_HMAC_MAX_DIGEST_LEN];
size_t client_key_len;
int use_cache;
uint8_t server_key[OPSSL_HMAC_MAX_DIGEST_LEN];
size_t server_key_len;
#endif /* TLS */

static void sasl_error(const char *msg)
{
#ifdef TLS
  step = 0;
#endif
  putlog(LOG_SERV, "*", "SASL: error: %s", msg);
  dprintf(DP_MODE, "CAP END\n");
  sasl_timeout_time = 0;
  if (!sasl_continue) {
    putlog(LOG_DEBUG, "*", "SASL: Aborting connection and retrying");
    nuke_server("sasl");
  }
}

/* Format an error message via op_strbuf_t and pass it to sasl_error(). */
static void sasl_errorf(const char *fmt, ...) AFP(1, 2);
static void sasl_errorf(const char *fmt, ...)
{
  va_list ap;
  op_strbuf_t _m = {};
  op_strbuf_init(&_m);
  va_start(ap, fmt);
  op_strbuf_vappendf(&_m, fmt, ap);
  va_end(ap);
  sasl_error(op_strbuf_str(&_m));
  op_strbuf_free(&_m);
}

static void sasl_secondly(void)
{
  if (!--sasl_timeout_time)
    sasl_error("timeout");
}

/* Got 901: RPL_LOGGEDOUT, users account name is unset (whether by SASL or
 * otherwise)
 */
static int got901(char *from, char *msg)
{
  newsplit(&msg); /* nick */
  newsplit(&msg); /* nick!ident@host */
  fixcolon(msg);
  putlog(LOG_SERV, "*", "%s: %s", from, msg);
  return 0;
}

/* Got 902: ERR_NICKLOCKED, authentication fails b/c nick is unavailable
 * Got 904: ERR_SASLFAIL, invalid credentials (or something not covered)
 * Got 905: ERR_SASLTOOLONG, AUTHENTICATE command was too long (>400 bytes)
 * Got 906: ERR_SASL_ABORTED, sent AUTHENTICATE command with * as parameter
 * For easy grepping, this covers got902 got904 got905 got906
 */
static int gotsasl90X(char *from, char *msg)
{
  newsplit(&msg); /* nick */
  fixcolon(msg);
  sasl_error(msg);
  return 0;
}

/* Got 903: RPL_SASLSUCCESS, authentication successful */
static int got903(char *from, char *msg)
{
  newsplit(&msg); /* nick */
  fixcolon(msg);
  putlog(LOG_SERV, "*", "SASL: %s", msg);
  dprintf(DP_MODE, "CAP END\n");
  sasl_timeout_time = 0;
  return 0;
}

/* Got 907: ERR_SASLALREADY, already authenticated */
static int got907(char *from, char *msg)
{
  putlog(LOG_SERV, "*", "SASL: Already authenticated");
  return 0;
}

/* Got 908: RPL_SASLMECHS, available mechanisms by network */
static int got908(char *from, char *msg)
{
  newsplit(&msg); /* nick */
  fixcolon(msg);
  putlog(LOG_SERV, "*", "SASL: Available mechanisms: %s", msg);
  del_capability("sasl");
  {
    op_strbuf_t _b = {};
    op_strbuf_init(&_b);
    op_strbuf_appendf(&_b, "sasl=%s", msg);
    add_capabilities(op_strbuf_str(&_b));
    op_strbuf_free(&_b);
  }
  return 0;
}

static int sasl_plain(char *dst, size_t dstsize)
{
  /* Don't use snprintf() due to \0 inside
   * and don't use stpcpy() for it is POSIX 2008
   */
  size_t n, y = 0;

  n = strlcpy(dst, sasl_username, dstsize);
  dst = dst + n + 1;
  dstsize = dstsize - n - 1;
  y = n + 1;
  n = strlcpy(dst, sasl_username, dstsize);
  dst = dst + n + 1;
  dstsize = dstsize - n - 1;
  y = y + n + 1;
  n = strlcpy(dst, sasl_password, dstsize);
  return y + n;
}

#ifdef TLS
static int sasl_ecdsa_nist256p_challenge_step_0(char *dst, size_t dstsize)
{
  /* Don't use snprintf() due to \0 inside
   * and don't use stpcpy() for it is POSIX 2008
   */
  size_t n, y = 0;

  n = strlcpy(dst, sasl_username, dstsize);
  dst = dst + n + 1;
  dstsize = dstsize - n - 1;
  y = n + 1;
  n = strlcpy(dst, sasl_username, dstsize);
  return y + n;
}

static int sasl_ecdsa_nist256p_challenge_step_1(
  char *restrict client_msg_plain, char *restrict server_msg_plain,
  int server_msg_plain_len)
{
  opssl_pkey_t *pkey;
  size_t siglen = 256;

  pkey = opssl_pkey_from_file(sasl_ecdsa_key);
  if (!pkey) {
    sasl_errorf("AUTHENTICATE: could not load key %s: %s",
                sasl_ecdsa_key, opssl_err_string(opssl_err_get()));
    return -1;
  }
  if (opssl_pkey_type(pkey) != OPSSL_PKEY_EC) {
    sasl_error("AUTHENTICATE: key is not an EC key");
    opssl_pkey_free(pkey);
    return -1;
  }
  if (opssl_pkey_sign(pkey, (const uint8_t *) server_msg_plain,
                      server_msg_plain_len,
                      (uint8_t *) client_msg_plain, &siglen) != 1) {
    sasl_errorf("AUTHENTICATE: signing failed: %s",
                opssl_err_string(opssl_err_get()));
    opssl_pkey_free(pkey);
    return -1;
  }
  opssl_pkey_free(pkey);
  return (int) siglen;
}

static int sasl_scram_step_0(char *client_msg_plain, int client_msg_plain_len)
{
  /* Use opssl_random_bytes() for a cryptographically secure, unbiased nonce.
   * 15 raw bytes base64-encode to exactly 20 printable chars (no ',' in
   * base64 alphabet), fitting the nonce[21] buffer and satisfying RFC 5802.
   */
  unsigned char raw_nonce[15];
  opssl_random_bytes(raw_nonce, sizeof raw_nonce);
  b64_ntop(raw_nonce, sizeof raw_nonce, nonce, sizeof nonce);
  {
    op_strbuf_t _b = {};
    op_strbuf_init(&_b);
    op_strbuf_appendf(&_b, "n,,n=%s,r=%s", sasl_username, nonce);
    strlcpy(client_msg_plain, op_strbuf_str(&_b), client_msg_plain_len);
    op_strbuf_free(&_b);
  }
  return strlcpy(client_first_message, client_msg_plain,
                 sizeof client_first_message);
}

/* Minimal SASLprep (RFC 4013) check for the SCRAM password.
 * Full SASLprep requires Unicode NFC normalization which eggdrop does not
 * implement yet.  For the ASCII subset the only required steps are:
 *   - Prohibit: ASCII control characters (U+0000-U+001F, U+007F)
 *   - Warn: non-ASCII bytes cannot be normalized without a Unicode library
 * Returns 0 on success, -1 if the password contains prohibited characters.
 */
static int sasl_saslprep_check(const char *password)
{
  const unsigned char *p = (const unsigned char *) password;
  int has_highbyte = 0;

  for (; *p; p++) {
    if (*p < 0x20 || *p == 0x7f) {
      sasl_error("AUTHENTICATE: password contains prohibited control character (SASLprep RFC 4013)");
      return -1;
    }
    if (*p > 0x7f)
      has_highbyte = 1;
  }
  if (has_highbyte)
    putlog(LOG_SERV, "*", "SASL: warning: password contains non-ASCII bytes; "
           "SASLprep normalization is not implemented — authentication may "
           "fail on servers that require NFC-normalized passwords");
  return 0;
}

/* ECDH-X25519-CHALLENGE step 1: ECDH key agreement + HMAC-SHA256 response.
 *
 * Protocol (Atheme saslserv):
 *   Server sends:  32-byte ephemeral X25519 public key (base64-decoded)
 *   Client sends:  base64( client_longterm_pubkey[32] || HMAC-SHA256(shared, server_pubkey)[32] )
 *
 * The client must have an X25519 private key stored in sasl-x25519-key.
 * Key file is PKCS#8 PEM (48-byte DER: 16-byte ASN.1 prefix + 32-byte key).
 */
static int sasl_ecdh_x25519_step_1(char *restrict client_msg_plain,
                                   char *restrict server_msg_plain,
                                   int server_msg_plain_len)
{
  FILE *fp;
  char line[256], b64buf[256];
  uint8_t der[48];
  size_t b64len = 0;
  uint8_t priv[OPSSL_X25519_KEY_LEN], client_pubkey[OPSSL_X25519_KEY_LEN];
  uint8_t shared[OPSSL_X25519_SHARED_LEN], hmac_out[OPSSL_SHA256_DIGEST_LEN];
  size_t hmac_len = sizeof hmac_out;
  int in_body = 0;
  static const uint8_t x25519_basepoint[32] = { 9 };

  if (server_msg_plain_len != 32) {
    sasl_errorf("AUTHENTICATE: ECDH-X25519: expected 32-byte server pubkey, got %s",
                int_to_base10(server_msg_plain_len));
    return -1;
  }
  if (!sasl_x25519_key[0]) {
    sasl_error("AUTHENTICATE: ECDH-X25519: sasl-x25519-key not set");
    return -1;
  }
  if (!(fp = fopen(sasl_x25519_key, "r"))) {
    sasl_errorf("AUTHENTICATE: ECDH-X25519: could not open %s: %s",
                sasl_x25519_key, strerror(errno));
    return -1;
  }

  while (fgets(line, sizeof line, fp)) {
    if (strstr(line, "-----BEGIN")) { in_body = 1; continue; }
    if (strstr(line, "-----END")) break;
    if (in_body) {
      size_t ll = strlen(line);
      while (ll > 0 && (line[ll - 1] == '\n' || line[ll - 1] == '\r'))
        line[--ll] = '\0';
      if (b64len + ll >= sizeof b64buf) { fclose(fp); return -1; }
      memcpy(b64buf + b64len, line, ll);
      b64len += ll;
    }
  }
  fclose(fp);
  b64buf[b64len] = '\0';

  if (b64_pton(b64buf, der, sizeof der) != 48) {
    sasl_error("AUTHENTICATE: ECDH-X25519: key file is not a valid X25519 PKCS#8 key");
    return -1;
  }
  memcpy(priv, der + 16, 32);
  opssl_memzero(der, sizeof der);

  if (opssl_x25519_derive(client_pubkey, priv, x25519_basepoint) != 1) {
    sasl_error("AUTHENTICATE: ECDH-X25519: failed to compute public key");
    opssl_memzero(priv, sizeof priv);
    return -1;
  }

  if (opssl_x25519_derive(shared, priv, (const uint8_t *) server_msg_plain) != 1) {
    sasl_error("AUTHENTICATE: ECDH-X25519: key agreement failed");
    opssl_memzero(priv, sizeof priv);
    return -1;
  }
  opssl_memzero(priv, sizeof priv);

  if (opssl_hmac(OPSSL_HMAC_SHA256, shared, sizeof shared,
                 server_msg_plain, 32, hmac_out, &hmac_len) != 1 || hmac_len != 32) {
    sasl_error("AUTHENTICATE: ECDH-X25519: HMAC-SHA256 failed");
    opssl_memzero(shared, sizeof shared);
    return -1;
  }
  opssl_memzero(shared, sizeof shared);

  memcpy(client_msg_plain,      client_pubkey, 32);
  memcpy(client_msg_plain + 32, hmac_out,      32);
  return 64;
}

static int sasl_scram_step_1(char *restrict client_msg_plain,
                             int client_msg_plain_len,
                             char *restrict server_msg_plain)
{
  op_strbuf_t server_first_message = {};
  op_strbuf_init(&server_first_message);
  char *word, *brkb, *server_nonce = 0, *salt_b64 = 0, *i = 0;
  int salt_plain_len, iter, j;
  char salt_plain[64]; /* atheme: Valid values are 8 to 64 (inclusive) */
  uint8_t stored_key[OPSSL_HMAC_MAX_DIGEST_LEN];
  uint8_t client_signature[OPSSL_HMAC_MAX_DIGEST_LEN];
  uint8_t client_proof[OPSSL_HMAC_MAX_DIGEST_LEN];
  char client_proof_b64[1024];
  size_t _hmac_len;

  op_strbuf_append_cstr(&server_first_message, server_msg_plain);
  for (word = strtok_r(server_msg_plain,  ",", &brkb);
       word;
       word = strtok_r(nullptr, ",", &brkb)) {
    switch (*word) {
      case 'r':
        if (!opssl_ct_eq(word + 2, nonce, (sizeof nonce) - 1)) {
          sasl_error("AUTHENTICATE: server nonce != client nonce");
          return -1;
        }
        server_nonce = word + 2;
        break;
      case 's':
        salt_b64 = word + 2;
        break;
      case 'i':
        i = word + 2;
        break;
      case 'e':
        sasl_errorf("AUTHENTICATE: server error: %s", word + 2);
        return -1;
      default:
        putlog(LOG_SERV, "*", "SASL: AUTHENTICATE warning: SCRAM Attribute ignored: %s", word);
    }
  }
  if (!server_nonce) {
    sasl_error("AUTHENTICATE: server nonce missing from SCRAM challenge");
    return -1;
  }
  if (!salt_b64) {
    sasl_error("AUTHENTICATE: salt missing from SCRAM challenge");
    return -1;
  }
  if (!i) {
    sasl_error("AUTHENTICATE: iteration count missing from SCRAM challenge");
    return -1;
  }
  /* SASLprep (RFC 4013): validate and warn about password contents.
   * Full Unicode NFC normalization is not implemented; ASCII passwords are
   * handled correctly.  See sasl_saslprep_check() for details. */
  if (sasl_saslprep_check(sasl_password) < 0)
    return -1;

  /* ClientKey       := HMAC(SaltedPassword, "Client Key") */

  use_cache = (!strcmp(sasl_password, last_sasl_password)) && (!strcmp(salt_b64, last_salt_b64)) && (!strcmp(i, last_i));

  if (!use_cache) {
    if ((salt_plain_len = b64_pton(salt_b64, (unsigned char*) salt_plain, sizeof salt_plain)) == -1) {
      sasl_error("AUTHENTICATE: could not base64 decode salt");
      return -1;
    }
    errno = 0;
    iter = strtol(i, nullptr, 10);
    if (errno) {
      sasl_errorf("AUTHENTICATE: strtol(%s): %s", i, strerror(errno));
      return -1;
    }

    if (sasl_mechanism == SASL_MECHANISM_SCRAM_SHA_256) {
      digest_algo = OPSSL_HMAC_SHA256;
      digest_len = OPSSL_SHA256_DIGEST_LEN;
    } else {
      digest_algo = OPSSL_HMAC_SHA512;
      digest_len = OPSSL_SHA512_DIGEST_LEN;
    }

    struct egg_rusage_timer rt;
    egg_timer_start(&rt);
    if (opssl_pbkdf2(digest_algo,
                     (const uint8_t *) sasl_password, strlen(sasl_password),
                     (const uint8_t *) salt_plain, salt_plain_len,
                     iter, salted_password, digest_len) != 1) {
      sasl_errorf("AUTHENTICATE: opssl_pbkdf2(): %s",
                  opssl_err_string(opssl_err_get()));
      return -1;
    }
    double ums, sms;
    if (egg_timer_stop(&rt, &ums, &sms))
      debug4("SASL: pbkdf2 digest %s iter %i, user %.3fms sys %.3fms",
             digest_algo == OPSSL_HMAC_SHA256 ? "SHA-256" : "SHA-512",
             iter, ums, sms);
    else
      debug1("PBKDF2 error: getrusage(): %s", strerror(errno));

    if (opssl_hmac(digest_algo, salted_password, digest_len,
                   CLIENT_KEY, strlen(CLIENT_KEY),
                   client_key, &client_key_len) != 1) {
      sasl_errorf("AUTHENTICATE: opssl_hmac(): %s",
                  opssl_err_string(opssl_err_get()));
      return -1;
    }
    strlcpy(last_sasl_password, sasl_password, sizeof last_sasl_password);
    strlcpy(last_salt_b64, salt_b64, sizeof last_salt_b64);
    strlcpy(last_i, i, sizeof last_i);
  }
  else
    debug0("SASL: using cached client and server key");

  /* StoredKey       := H(ClientKey) */

  if (digest_algo == OPSSL_HMAC_SHA256)
    opssl_sha256(client_key, client_key_len, stored_key);
  else
    opssl_sha512(client_key, client_key_len, stored_key);

  /* AuthMessage     := client-first-message-bare + "," +
   *                    server-first-message + "," +
   *                    client-final-message-without-proof
   */

  op_strbuf_t _cfmwp = {};
  op_strbuf_init(&_cfmwp);
  op_strbuf_appendf(&_cfmwp, "c=biws,r=%s", server_nonce);

  {
    op_strbuf_t _b = {};
    op_strbuf_init(&_b);
    op_strbuf_appendf(&_b, "%s,%s,%s", client_first_message + 3,
                     op_strbuf_str(&server_first_message), op_strbuf_str(&_cfmwp));
    strlcpy(auth_message, op_strbuf_str(&_b), sizeof auth_message);
    op_strbuf_free(&_b);
  }
  auth_message_len = (int) strlen(auth_message);

  /* ClientSignature := HMAC(StoredKey, AuthMessage) */

  _hmac_len = sizeof client_signature;
  if (opssl_hmac(digest_algo, stored_key, digest_len,
                 auth_message, auth_message_len,
                 client_signature, &_hmac_len) != 1) {
    sasl_errorf("AUTHENTICATE: opssl_hmac(): %s",
                opssl_err_string(opssl_err_get()));
    op_strbuf_free(&_cfmwp);
    return -1;
  }

  /* ClientProof     := ClientKey XOR ClientSignature */

  for (j = 0; j < (int) client_key_len; j++)
    client_proof[j] = client_key[j] ^ client_signature[j];

  if (b64_ntop(client_proof, client_key_len, client_proof_b64, sizeof client_proof_b64) == -1) {
    sasl_error("AUTHENTICATE: could not base64 encode");
    op_strbuf_free(&_cfmwp);
    return -1;
  }

  {
    op_strbuf_t _b = {};
    op_strbuf_init(&_b);
    op_strbuf_appendf(&_b, "%s,p=%s", op_strbuf_str(&_cfmwp), client_proof_b64);
    strlcpy(client_msg_plain, op_strbuf_str(&_b), client_msg_plain_len);
    op_strbuf_free(&_b);
  }
  op_strbuf_free(&_cfmwp);
  return (int) strlen(client_msg_plain);
}

static void sasl_scram_step_2(char *restrict client_msg_plain,
                             int client_msg_plain_len,
                             char *restrict server_msg_plain)
{
  uint8_t server_signature[OPSSL_HMAC_MAX_DIGEST_LEN];
  char server_signature_b64[128];
  int server_signature_b64_len;
  size_t _hmac_len;

  /* ServerKey       := HMAC(SaltedPassword, "Server Key") */

  if ((!use_cache) &&
      (opssl_hmac(digest_algo, salted_password, digest_len,
                  SERVER_KEY, strlen(SERVER_KEY),
                  server_key, &server_key_len) != 1)) {
    sasl_errorf("AUTHENTICATE: opssl_hmac(): %s",
                opssl_err_string(opssl_err_get()));
    return;
  }

  /* ServerSignature := HMAC(ServerKey, AuthMessage) */

  _hmac_len = sizeof server_signature;
  if (opssl_hmac(digest_algo, server_key, digest_len,
                 auth_message, auth_message_len,
                 server_signature, &_hmac_len) != 1) {
    sasl_errorf("AUTHENTICATE: opssl_hmac(): %s",
                opssl_err_string(opssl_err_get()));
    return;
  }

  if ((server_signature_b64_len = b64_ntop(server_signature, digest_len, server_signature_b64, sizeof server_signature_b64)) == -1) {
    sasl_error("AUTHENTICATE: could not base64 encode");
    return;
  }

  if (!opssl_ct_eq(server_msg_plain + 2, server_signature_b64, server_signature_b64_len)) {
    sasl_error("invalid server signature");
    return;
  }

  putlog(LOG_SERV, "*", "SASL: authentication of server successful");
  dprintf(DP_MODE, "AUTHENTICATE +\n");
  sasl_timeout_time = 0;
}
#endif /* TLS */

static int gotauthenticate(char *from, char *msg)
{
  char client_msg_plain[1024];
  int client_msg_plain_len = 0;
#ifdef TLS
  char server_msg_plain[1024];
  int server_msg_plain_len;
#endif
  #ifndef MAX
  #define MAX(a,b) (((a)>(b))?(a):(b))
  #endif
  char client_msg_b64[((MAX((sizeof client_msg_plain), 400) + 2) / 3) << 2] = "";

  fixcolon(msg); /* Because Inspircd does its own thing */
#ifdef TLS
  if (*msg == '+') {
#endif
    if ((sasl_mechanism != SASL_MECHANISM_EXTERNAL) && (!*sasl_username))  {
      putlog(LOG_SERV, "*", "SASL: sasl-username not set, setting it to "
             "username %s", botname);
      strlcpy(sasl_username, botuser, sizeof sasl_username);
    }
#ifdef TLS
    switch (sasl_mechanism) {
      case SASL_MECHANISM_PLAIN:
#endif
        client_msg_plain_len = sasl_plain(client_msg_plain, sizeof client_msg_plain);
#ifdef TLS
        break;
      case SASL_MECHANISM_ECDSA_NIST256P_CHALLENGE:
        client_msg_plain_len = sasl_ecdsa_nist256p_challenge_step_0(client_msg_plain, sizeof client_msg_plain);
        break;
      case SASL_MECHANISM_EXTERNAL:
        dprintf(DP_MODE, "AUTHENTICATE +\n");
        return 0;
      case SASL_MECHANISM_SCRAM_SHA_256:
      case SASL_MECHANISM_SCRAM_SHA_512:
        client_msg_plain_len = sasl_scram_step_0(client_msg_plain, sizeof client_msg_plain);
        break;
      case SASL_MECHANISM_ECDH_X25519_CHALLENGE:
        /* Step 0: identify ourselves (same format as ECDSA step 0) */
        client_msg_plain_len = sasl_ecdsa_nist256p_challenge_step_0(client_msg_plain, sizeof client_msg_plain);
        break;
    }
  } else {
    if ((server_msg_plain_len = b64_pton(msg, (unsigned char*) server_msg_plain, sizeof server_msg_plain)) == -1) {
      sasl_error("AUTHENTICATE: could not base64 decode line from server");
      return 0;
    }
    if (server_msg_plain_len < 2 && sasl_mechanism != SASL_MECHANISM_ECDH_X25519_CHALLENGE) {
      sasl_error("AUTHENTICATE: server message too short");
      return 0;
    }
    if (*server_msg_plain == 'e') {
      sasl_errorf("AUTHENTICATE: server error: %s", server_msg_plain + 2);
      return 0;
    }
    if (sasl_mechanism == SASL_MECHANISM_ECDSA_NIST256P_CHALLENGE) {
      if ((client_msg_plain_len = sasl_ecdsa_nist256p_challenge_step_1(client_msg_plain, server_msg_plain, server_msg_plain_len)) < 0)
        return 0;
    }
    else if (sasl_mechanism == SASL_MECHANISM_ECDH_X25519_CHALLENGE) {
      if ((client_msg_plain_len = sasl_ecdh_x25519_step_1(client_msg_plain, server_msg_plain, server_msg_plain_len)) < 0)
        return 0;
    }
    else
      if (step == 0) {
        if ((client_msg_plain_len = sasl_scram_step_1(client_msg_plain, sizeof client_msg_plain, server_msg_plain)) < 0)
          return 0;
        step++;
      } else {
        sasl_scram_step_2(client_msg_plain, sizeof client_msg_plain, server_msg_plain);
        step = 0;
        return 0;
      }
  }
#endif /* TLS */
  if (b64_ntop((unsigned char *) client_msg_plain, client_msg_plain_len, client_msg_b64, sizeof client_msg_b64) == -1) {
    sasl_error("AUTHENTICATE: could not base64 encode");
    return 0;
  }
  dprintf(DP_MODE, "AUTHENTICATE %s\n", client_msg_b64);
  return 0;
}

[[maybe_unused]] static char *traced_sasl_mechanism(ClientData cdata, Tcl_Interp *irp,
                                   EGG_CONST char *name1,
                                   EGG_CONST char *name2, int flags)
{
  if ((sasl_mechanism < 0) || (sasl_mechanism >= SASL_MECHANISM_NUM))
    return "sasl-mechanism is not set to an allowed value, please check it and"
           " try again";
#ifndef TLS
  if (sasl_mechanism != SASL_MECHANISM_PLAIN)
    return "The selected SASL authentication method requires TLS libraries "
           "which are not installed on this machine. Please choose the PLAIN "
           "method.";
#endif /* TLS */
  return nullptr;
}

static cmd_t sasl_raw[] = {
  {"901",          "",   (IntFunc) got901,          nullptr},
  {"902",          "",   (IntFunc) gotsasl90X,      nullptr},
  {"903",          "",   (IntFunc) got903,          nullptr},
  {"904",          "",   (IntFunc) gotsasl90X,      nullptr},
  {"905",          "",   (IntFunc) gotsasl90X,      nullptr},
  {"906",          "",   (IntFunc) gotsasl90X,      nullptr},
  {"907",          "",   (IntFunc) got907,          nullptr},
  {"908",          "",   (IntFunc) got908,          nullptr},
  {"AUTHENTICATE", "",   (IntFunc) gotauthenticate, nullptr},
  {nullptr,           nullptr, nullptr,                      nullptr}
};

static tcl_ints sasl_tcl_ints[] = {
  {"sasl",           &sasl,           0},
  {"sasl-mechanism", &sasl_mechanism, 0},
  {"sasl-continue",  &sasl_continue,  0},
  {"sasl-timeout",   &sasl_timeout,   0},
  {nullptr,             nullptr,            0}
};

static tcl_strings sasl_tcl_strings[] = {
  {"sasl-username",   sasl_username,   NICKMAX,            0},
  {"sasl-password",   sasl_password,   SASL_PASSWORD_MAX,  0},
  {"sasl-ecdsa-key",  sasl_ecdsa_key,  SASL_ECDSA_KEY_MAX, 0},
  {"sasl-x25519-key", sasl_x25519_key, SASL_ECDSA_KEY_MAX, 0},
  {nullptr,              nullptr,            0,                  0}
};

static void sasl_close(void)
{
  rem_builtins(H_raw, sasl_raw);
  rem_tcl_ints(sasl_tcl_ints);
  rem_tcl_strings(sasl_tcl_strings);
  Tcl_UntraceVar(interp, "sasl-mechanism", TCL_TRACE_WRITES | TCL_TRACE_UNSETS,
                 traced_sasl_mechanism, nullptr);
}

static void sasl_start(void)
{
  Tcl_TraceVar(interp, "sasl-mechanism", TCL_TRACE_WRITES | TCL_TRACE_UNSETS,
               traced_sasl_mechanism, nullptr);
  add_builtins(H_raw, sasl_raw);
  add_tcl_ints(sasl_tcl_ints);
  add_tcl_strings(sasl_tcl_strings);
}

/* There are two forms of the AUTHENTICATE command: initial client message and
 * later messages. The initial client message specifies the SASL mechanism to
 * be used.
*/
int sasl_authenticate_initial(const struct cap_values *cap_value_list)
{
  putlog(LOG_DEBUG, "*", "SASL: Starting authentication process");
#ifdef TLS
  int servidx = findanyidx(serv);
  if ((sasl_mechanism == SASL_MECHANISM_EXTERNAL) && !dcc[servidx].ssl) {
    sasl_error("authentication mechanism EXTERNAL not possible via non-ssl connection");
    return 1;
  }
#endif
  if (!is_cap_value(cap_value_list, SASL_MECHANISMS[sasl_mechanism])) {
    const struct cap_values *v;
    op_strbuf_t _supported = {};
    op_strbuf_init(&_supported);
    /* Build a space-separated list of what the server actually advertised */
    for (v = cap_value_list; v; v = v->next) {
      if (op_strbuf_len(&_supported))
        op_strbuf_append_cstr(&_supported, " ");
      op_strbuf_append_cstr(&_supported, v->name);
    }
    {
      op_strbuf_t _m = {};
      op_strbuf_init(&_m);
      op_strbuf_appendf(&_m, "authentication mechanism %s not supported by server",
                       SASL_MECHANISMS[sasl_mechanism]);
      if (op_strbuf_len(&_supported))
        op_strbuf_appendf(&_m, "; server supports: %s", op_strbuf_str(&_supported));
      sasl_error(op_strbuf_str(&_m));
      op_strbuf_free(&_m);
    }
    op_strbuf_free(&_supported);
    return 1;
  }
  putlog(LOG_DEBUG, "*", "SASL: AUTHENTICATE %s", SASL_MECHANISMS[sasl_mechanism]);
  dprintf(DP_MODE, "AUTHENTICATE %s\n", SASL_MECHANISMS[sasl_mechanism]);
  sasl_timeout_time = sasl_timeout;
  return 0;
}

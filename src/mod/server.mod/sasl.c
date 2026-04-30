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
/* wolfssl already included via egg_tls.h in server.c before module.h */
#ifdef TLS
#if OPENSSL_VERSION_NUMBER >= 0x10000000L /* 1.0.0 */
const EVP_MD *digest;
char salted_password[EVP_MAX_MD_SIZE];
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
char client_key[EVP_MAX_MD_SIZE];
unsigned int client_key_len;
int use_cache;
char server_key[EVP_MAX_MD_SIZE];
unsigned int server_key_len;
#endif /* OPENSSL_VERSION_NUMBER >= 0x10000000L */
#endif /* TLS */

static void sasl_error(const char *msg)
{
#if defined(TLS) && OPENSSL_VERSION_NUMBER >= 0x10000000L
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
  op_strbuf_t _m;
  va_start(ap, fmt);
  op_strbuf_vprintf(&_m, fmt, ap);
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
    op_strbuf_t _b;
    op_strbuf_printf(&_b, "sasl=%s", msg);
    add_capabilities((char *) op_strbuf_str(&_b));
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
  FILE *fp;
  EVP_PKEY *pkey;

  if (!(fp = fopen(sasl_ecdsa_key, "r"))) {
    sasl_errorf("AUTHENTICATE: could not open file sasl_ecdsa_key %s: %s\n",
                sasl_ecdsa_key, strerror(errno));
    return -1;
  }
  if (!(pkey = PEM_read_PrivateKey(fp, NULL, 0, NULL))) {
    sasl_errorf("AUTHENTICATE: PEM_read_PrivateKey(): SSL error = %s\n",
                ERR_error_string(ERR_get_error(), 0));
    fclose(fp);
    return -1;
  }
  fclose(fp);
#if OPENSSL_VERSION_NUMBER >= 0x10000000L /* 1.0.0 */
  EVP_PKEY_CTX *ctx;
  size_t siglen;

  /* The EVP interface to digital signatures should almost always be used in
   * preference to the low level interfaces.
   */
  if (!(ctx = EVP_PKEY_CTX_new(pkey, NULL))) {
    sasl_errorf("AUTHENTICATE: EVP_PKEY_CTX_new(): SSL error = %s\n",
                ERR_error_string(ERR_get_error(), 0));
    return -1;
  }
  EVP_PKEY_free(pkey);
  if (EVP_PKEY_sign_init(ctx) <= 0) {
    sasl_errorf("AUTHENTICATE: EVP_PKEY_sign_init():SSL error = %s\n",
                ERR_error_string(ERR_get_error(), 0));
    EVP_PKEY_CTX_free(ctx);
    return -1;
  }
  if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0) {
    sasl_errorf("AUTHENTICATE: EVP_PKEY_CTX_set_signature_md(): SSL error = %s\n",
                ERR_error_string(ERR_get_error(), 0));
    EVP_PKEY_CTX_free(ctx);
    return -1;
  }
  /* EVP_PKEY_sign() must be used instead of EVP_DigestSign*() and EVP_Sign*(),
   * because EVP_PKEY_sign() does not hash the data to be signed.
   * EVP_PKEY_sign() is for signing digests, EVP_DigestSign*() and EVP_Sign*()
   * are for signing messages.
   */
  if (EVP_PKEY_sign(ctx, NULL, &siglen, (unsigned char *) server_msg_plain, server_msg_plain_len) <= 0) {
    sasl_errorf("AUTHENTICATE: EVP_PKEY_sign(): SSL error = %s\n",
                ERR_error_string(ERR_get_error(), 0));
    EVP_PKEY_CTX_free(ctx);
    return -1;
  }
  if (EVP_PKEY_sign(ctx, (unsigned char *) client_msg_plain, &siglen, (unsigned char *) server_msg_plain, server_msg_plain_len) <= 0) {
    sasl_errorf("AUTHENTICATE: EVP_PKEY_sign(): SSL error = %s\n",
                ERR_error_string(ERR_get_error(), 0));
    EVP_PKEY_CTX_free(ctx);
    return -1;
  }
  EVP_PKEY_CTX_free(ctx);
#else
  EC_KEY *eckey;
  int ret;
  unsigned int siglen;

  eckey = EVP_PKEY_get1_EC_KEY(pkey);
  EVP_PKEY_free(pkey);
  if (!eckey) {
    sasl_errorf("AUTHENTICATE: EVP_PKEY_get1_EC_KEY(): SSL error = %s\n",
                ERR_error_string(ERR_get_error(), 0));
    return -1;
  }
  ret = ECDSA_sign(0, (const unsigned char *) server_msg_plain,
                   server_msg_plain_len,
                   (unsigned char *) client_msg_plain, &siglen, eckey);
  EC_KEY_free(eckey);
  if (!ret) {
    sasl_errorf("AUTHENTICATE: ECDSA_sign() SSL error = %s\n",
                ERR_error_string(ERR_get_error(), 0));
    return -1;
  }
#endif /* OPENSSL_VERSION_NUMBER >= 0x10000000L */
  return siglen;
}

#if OPENSSL_VERSION_NUMBER >= 0x10000000L /* 1.0.0 */
static int sasl_scram_step_0(char *client_msg_plain, int client_msg_plain_len)
{
  /* Use RAND_bytes() for a cryptographically secure, unbiased nonce.
   * 15 raw bytes base64-encode to exactly 20 printable chars (no ',' in
   * base64 alphabet), fitting the nonce[21] buffer and satisfying RFC 5802.
   */
  unsigned char raw_nonce[15];
  RAND_bytes(raw_nonce, sizeof raw_nonce);
  b64_ntop(raw_nonce, sizeof raw_nonce, nonce, sizeof nonce);
  {
    op_strbuf_t _b;
    op_strbuf_printf(&_b, "n,,n=%s,r=%s", sasl_username, nonce);
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

#if OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(HAVE_WOLFSSL) /* 1.1.0: EVP_PKEY_X25519 */
/* ECDH-X25519-CHALLENGE step 1: ECDH key agreement + HMAC-SHA256 response.
 *
 * Protocol (Atheme saslserv):
 *   Server sends:  32-byte ephemeral X25519 public key (base64-decoded)
 *   Client sends:  base64( client_longterm_pubkey[32] || HMAC-SHA256(shared, server_pubkey)[32] )
 *
 * The client must have an X25519 private key stored in sasl-x25519-key.
 */
static int sasl_ecdh_x25519_step_1(char *restrict client_msg_plain,
                                   char *restrict server_msg_plain,
                                   int server_msg_plain_len)
{
  FILE *fp;
  EVP_PKEY *pkey = NULL, *server_pkey = NULL;
  EVP_PKEY_CTX *dh_ctx = NULL;
  unsigned char shared[32], client_pubkey[32], hmac_out[EVP_MAX_MD_SIZE];
  size_t shared_len = sizeof shared, client_pubkey_len = sizeof client_pubkey;
  unsigned int hmac_len;

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
  pkey = PEM_read_PrivateKey(fp, NULL, 0, NULL);
  fclose(fp);
  if (!pkey) {
    sasl_errorf("AUTHENTICATE: ECDH-X25519: PEM_read_PrivateKey(): %s",
                ERR_error_string(ERR_get_error(), NULL));
    return -1;
  }
  if (EVP_PKEY_id(pkey) != EVP_PKEY_X25519) {
    sasl_error("AUTHENTICATE: ECDH-X25519: key file does not contain an X25519 key");
    EVP_PKEY_free(pkey);
    return -1;
  }

  /* Extract our long-term public key (32 bytes, sent to server) */
  if (!EVP_PKEY_get_raw_public_key(pkey, client_pubkey, &client_pubkey_len) ||
      client_pubkey_len != 32) {
    sasl_errorf("AUTHENTICATE: ECDH-X25519: EVP_PKEY_get_raw_public_key(): %s",
                ERR_error_string(ERR_get_error(), NULL));
    EVP_PKEY_free(pkey);
    return -1;
  }

  /* Import server's ephemeral X25519 public key */
  server_pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL,
                                             (unsigned char *) server_msg_plain, 32);
  if (!server_pkey) {
    sasl_errorf("AUTHENTICATE: ECDH-X25519: EVP_PKEY_new_raw_public_key(): %s",
                ERR_error_string(ERR_get_error(), NULL));
    EVP_PKEY_free(pkey);
    return -1;
  }

  /* Perform X25519 key agreement: shared = X25519(client_priv, server_pub) */
  dh_ctx = EVP_PKEY_CTX_new(pkey, NULL);
  if (!dh_ctx || EVP_PKEY_derive_init(dh_ctx) <= 0 ||
      EVP_PKEY_derive_set_peer(dh_ctx, server_pkey) <= 0 ||
      EVP_PKEY_derive(dh_ctx, shared, &shared_len) <= 0) {
    sasl_errorf("AUTHENTICATE: ECDH-X25519: key agreement failed: %s",
                ERR_error_string(ERR_get_error(), NULL));
    EVP_PKEY_CTX_free(dh_ctx);
    EVP_PKEY_free(server_pkey);
    EVP_PKEY_free(pkey);
    return -1;
  }
  EVP_PKEY_CTX_free(dh_ctx);
  EVP_PKEY_free(server_pkey);
  EVP_PKEY_free(pkey);

  /* MAC = HMAC-SHA256(shared_secret, server_ephemeral_pubkey) */
  if (!HMAC(EVP_sha256(), shared, (int) shared_len,
            (unsigned char *) server_msg_plain, 32,
            hmac_out, &hmac_len) || hmac_len != 32) {
    sasl_errorf("AUTHENTICATE: ECDH-X25519: HMAC-SHA256(): %s",
                ERR_error_string(ERR_get_error(), NULL));
    return -1;
  }

  /* Response: client_longterm_pubkey (32) || HMAC (32) = 64 bytes total */
  memcpy(client_msg_plain,      client_pubkey, 32);
  memcpy(client_msg_plain + 32, hmac_out,      32);
  return 64;
}
#endif /* OPENSSL_VERSION_NUMBER >= 0x10100000L */

static int sasl_scram_step_1(char *restrict client_msg_plain,
                             int client_msg_plain_len,
                             char *restrict server_msg_plain)
{
  char server_first_message[1024];
  char *word, *brkb, *server_nonce = 0, *salt_b64 = 0, *i = 0;
  int salt_plain_len, iter, j, ret;
  char salt_plain[64]; /* atheme: Valid values are 8 to 64 (inclusive) */
  unsigned int stored_key_len;
  unsigned char stored_key[EVP_MAX_MD_SIZE];
  char client_final_message_without_proof[1024];
  unsigned char client_signature[EVP_MAX_MD_SIZE];
  unsigned char client_proof[EVP_MAX_MD_SIZE];
  char client_proof_b64[1024];
  struct rusage ru1, ru2;

  strlcpy(server_first_message, server_msg_plain, sizeof server_first_message);
  for (word = strtok_r(server_msg_plain,  ",", &brkb);
       word;
       word = strtok_r(NULL, ",", &brkb)) {
    switch (*word) {
      case 'r':
        if (
#if OPENSSL_VERSION_NUMBER >= 0x1010008fL /* 1.1.0h */
            CRYPTO_memcmp
#else
            memcmp
#endif
            (word + 2, nonce, (sizeof nonce) - 1)) {
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
    iter = strtol(i, NULL, 10);
    if (errno) {
      sasl_errorf("AUTHENTICATE: strtol(%s): %s", i, strerror(errno));
      return -1;
    }

    if (sasl_mechanism == SASL_MECHANISM_SCRAM_SHA_256)
      digest = EVP_sha256();
    else
      digest = EVP_sha512();
    digest_len = EVP_MD_size(digest);

    ret = getrusage(RUSAGE_SELF, &ru1);
    if (!PKCS5_PBKDF2_HMAC(sasl_password, strlen(sasl_password),
                           (const unsigned char *) salt_plain, salt_plain_len,
                           iter, digest, digest_len,
                           (unsigned char *) salted_password)) {
      sasl_errorf("AUTHENTICATE: PKCS5_PBKDF2_HMAC(): %s",
                  ERR_error_string(ERR_get_error(), NULL));
      return -1;
    }
    if (!ret && !getrusage(RUSAGE_SELF, &ru2)) {
      debug4("SASL: pbkdf2 digest %s iter %i, user %.3fms sys %.3fms", EVP_MD_name(digest),
             iter,
             (double) (ru2.ru_utime.tv_usec - ru1.ru_utime.tv_usec) / 1000 +
             (double) (ru2.ru_utime.tv_sec  - ru1.ru_utime.tv_sec ) * 1000,
             (double) (ru2.ru_stime.tv_usec - ru1.ru_stime.tv_usec) / 1000 +
             (double) (ru2.ru_stime.tv_sec  - ru1.ru_stime.tv_sec ) * 1000);
    }
    else {
      debug1("PBKDF2 error: getrusage(): %s", strerror(errno));
    }

    if (!HMAC(digest, salted_password, digest_len, (unsigned char *) CLIENT_KEY,
              strlen(CLIENT_KEY), (unsigned char *) client_key,
              &client_key_len)) {
      sasl_errorf("AUTHENTICATE: HMAC(): %s", ERR_error_string(ERR_get_error(), NULL));
      return -1;
    }
    strlcpy(last_sasl_password, sasl_password, sizeof last_sasl_password);
    strlcpy(last_salt_b64, salt_b64, sizeof last_salt_b64);
    strlcpy(last_i, i, sizeof last_i);
  }
  else
    debug0("SASL: using cached client and server key");

  /* StoredKey       := H(ClientKey) */

  if (!EVP_Digest(client_key, client_key_len, stored_key, &stored_key_len, digest, NULL)) {
    sasl_errorf("AUTHENTICATE: EVP_Digest(): %s", ERR_error_string(ERR_get_error(), NULL));
    return -1;
  }

  /* AuthMessage     := client-first-message-bare + "," +
   *                    server-first-message + "," +
   *                    client-final-message-without-proof
   */

  {
    op_strbuf_t _b;
    op_strbuf_printf(&_b, "c=biws,r=%s", server_nonce);
    strlcpy(client_final_message_without_proof, op_strbuf_str(&_b),
            sizeof client_final_message_without_proof);
    op_strbuf_free(&_b);
  }

  {
    op_strbuf_t _b;
    op_strbuf_printf(&_b, "%s,%s,%s", client_first_message + 3,
                     server_first_message, client_final_message_without_proof);
    strlcpy(auth_message, op_strbuf_str(&_b), sizeof auth_message);
    op_strbuf_free(&_b);
  }
  auth_message_len = (int) strlen(auth_message);

  /* ClientSignature := HMAC(StoredKey, AuthMessage) */

  if (!HMAC(digest, stored_key, digest_len, (unsigned char *) auth_message,
            auth_message_len, client_signature, NULL)) {
    sasl_errorf("AUTHENTICATE: HMAC(): %s", ERR_error_string(ERR_get_error(), NULL));
    return -1;
  }

  /* ClientProof     := ClientKey XOR ClientSignature */

  for (j = 0; j < client_key_len; j++)
    client_proof[j] = client_key[j] ^ client_signature[j];

  if (b64_ntop(client_proof, client_key_len, client_proof_b64, sizeof client_proof_b64) == -1) {
    sasl_error("AUTHENTICATE: could not base64 encode");
    return -1;
  }

  {
    op_strbuf_t _b;
    op_strbuf_printf(&_b, "%s,p=%s", client_final_message_without_proof, client_proof_b64);
    strlcpy(client_msg_plain, op_strbuf_str(&_b), client_msg_plain_len);
    op_strbuf_free(&_b);
  }
  return (int) strlen(client_msg_plain);
}

static void sasl_scram_step_2(char *restrict client_msg_plain,
                             int client_msg_plain_len,
                             char *restrict server_msg_plain)
{
  unsigned char server_signature[EVP_MAX_MD_SIZE];
  char server_signature_b64[128];
  int server_signature_b64_len;

  /* ServerKey       := HMAC(SaltedPassword, "Server Key") */

  if ((!use_cache) &&
      (!HMAC(digest, salted_password, digest_len, (unsigned char *) SERVER_KEY,
             strlen(SERVER_KEY), (unsigned char *) server_key,
             &server_key_len))) {
    sasl_errorf("AUTHENTICATE: HMAC(): %s", ERR_error_string(ERR_get_error(), NULL));
    return;
  }

  /* ServerSignature := HMAC(ServerKey, AuthMessage) */

  if (!HMAC(digest, server_key, digest_len, (unsigned char *) auth_message,
            auth_message_len, server_signature, NULL)) {
    sasl_errorf("AUTHENTICATE: HMAC(): %s", ERR_error_string(ERR_get_error(), NULL));
    return;
  }

  if ((server_signature_b64_len = b64_ntop(server_signature, digest_len, server_signature_b64, sizeof server_signature_b64)) == -1) {
    sasl_error("AUTHENTICATE: could not base64 encode");
    return;
  }

  if (
#if OPENSSL_VERSION_NUMBER >= 0x1010008fL /* 1.1.0h */
      CRYPTO_memcmp
#else
      memcmp
#endif
      (server_msg_plain + 2, server_signature_b64, server_signature_b64_len)) {
    sasl_error("invalid server signature");
    return;
  }

  putlog(LOG_SERV, "*", "SASL: authentication of server successful");
  dprintf(DP_MODE, "AUTHENTICATE +\n");
  sasl_timeout_time = 0;
}
#endif /* OPENSSL_VERSION_NUMBER >= 0x10000000L */
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
#if OPENSSL_VERSION_NUMBER >= 0x10000000L /* 1.0.0 */
      case SASL_MECHANISM_SCRAM_SHA_256:
      case SASL_MECHANISM_SCRAM_SHA_512:
        client_msg_plain_len = sasl_scram_step_0(client_msg_plain, sizeof client_msg_plain);
        break;
#endif /* OPENSSL_VERSION_NUMBER >= 0x10000000L */
#if OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(HAVE_WOLFSSL) /* 1.1.0: X25519 */
      case SASL_MECHANISM_ECDH_X25519_CHALLENGE:
        /* Step 0: identify ourselves (same format as ECDSA step 0) */
        client_msg_plain_len = sasl_ecdsa_nist256p_challenge_step_0(client_msg_plain, sizeof client_msg_plain);
        break;
#endif /* OPENSSL_VERSION_NUMBER >= 0x10100000L */
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
#if OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(HAVE_WOLFSSL) /* 1.1.0: X25519 */
    else if (sasl_mechanism == SASL_MECHANISM_ECDH_X25519_CHALLENGE) {
      if ((client_msg_plain_len = sasl_ecdh_x25519_step_1(client_msg_plain, server_msg_plain, server_msg_plain_len)) < 0)
        return 0;
    }
#endif /* OPENSSL_VERSION_NUMBER >= 0x10100000L */
#if OPENSSL_VERSION_NUMBER >= 0x10000000L /* 1.0.0 */
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
#endif /* OPENSSL_VERSION_NUMBER >= 0x10000000L */
  }
#endif /* TLS */
  if (b64_ntop((unsigned char *) client_msg_plain, client_msg_plain_len, client_msg_b64, sizeof client_msg_b64) == -1) {
    sasl_error("AUTHENTICATE: could not base64 encode");
    return 0;
  }
  dprintf(DP_MODE, "AUTHENTICATE %s\n", client_msg_b64);
  return 0;
}

#ifdef HAVE_TCL
static char *traced_sasl_mechanism(ClientData cdata, Tcl_Interp *irp,
                                   EGG_CONST char *name1,
                                   EGG_CONST char *name2, int flags)
{
  if ((sasl_mechanism < 0) || (sasl_mechanism >= SASL_MECHANISM_NUM))
    return "sasl-mechanism is not set to an allowed value, please check it and"
           " try again";
#ifdef TLS
#ifndef HAVE_EVP_PKEY_GET1_EC_KEY
  if (sasl_mechanism == SASL_MECHANISM_ECDSA_NIST256P_CHALLENGE)
    return "SASL NIST256P functionality missing from your TLS libs, please "
           "choose a different SASL method";
#endif /* HAVE_EVP_PKEY_GET1_EC_KEY */
#if OPENSSL_VERSION_NUMBER < 0x10000000L /* 1.0.0 */
  if ((sasl_mechanism == SASL_MECHANISM_SCRAM_SHA_256) ||
      (sasl_mechanism == SASL_MECHANISM_SCRAM_SHA_512))
    return "SASL SCRAM functionality needs openssl version 1.0.0 or higher, "
           "please choose a different SASL method";
#endif /* OPENSSL_VERSION_NUMBER < 0x10000000L */
#if OPENSSL_VERSION_NUMBER < 0x10100000L /* 1.1.0 */
  if (sasl_mechanism == SASL_MECHANISM_ECDH_X25519_CHALLENGE)
    return "SASL ECDH-X25519-CHALLENGE requires OpenSSL 1.1.0 or higher, "
           "please choose a different SASL method";
#endif /* OPENSSL_VERSION_NUMBER < 0x10100000L */
#else /* TLS */
  if (sasl_mechanism != SASL_MECHANISM_PLAIN)
    return "The selected SASL authentication method requires TLS libraries "
           "which are not installed on this machine. Please choose the PLAIN "
           "method.";
#endif /* TLS */
  return NULL;
}
#endif /* HAVE_TCL */

static cmd_t sasl_raw[] = {
  {"901",          "",   (IntFunc) got901,          NULL},
  {"902",          "",   (IntFunc) gotsasl90X,      NULL},
  {"903",          "",   (IntFunc) got903,          NULL},
  {"904",          "",   (IntFunc) gotsasl90X,      NULL},
  {"905",          "",   (IntFunc) gotsasl90X,      NULL},
  {"906",          "",   (IntFunc) gotsasl90X,      NULL},
  {"907",          "",   (IntFunc) got907,          NULL},
  {"908",          "",   (IntFunc) got908,          NULL},
  {"AUTHENTICATE", "",   (IntFunc) gotauthenticate, NULL},
  {NULL,           NULL, NULL,                      NULL}
};

static tcl_ints sasl_tcl_ints[] = {
  {"sasl",           &sasl,           0},
  {"sasl-mechanism", &sasl_mechanism, 0},
  {"sasl-continue",  &sasl_continue,  0},
  {"sasl-timeout",   &sasl_timeout,   0},
  {NULL,             NULL,            0}
};

static tcl_strings sasl_tcl_strings[] = {
  {"sasl-username",   sasl_username,   NICKMAX,            0},
  {"sasl-password",   sasl_password,   SASL_PASSWORD_MAX,  0},
  {"sasl-ecdsa-key",  sasl_ecdsa_key,  SASL_ECDSA_KEY_MAX, 0},
  {"sasl-x25519-key", sasl_x25519_key, SASL_ECDSA_KEY_MAX, 0},
  {NULL,              NULL,            0,                  0}
};

static void sasl_close(void)
{
  rem_builtins(H_raw, sasl_raw);
  rem_tcl_ints(sasl_tcl_ints);
  rem_tcl_strings(sasl_tcl_strings);
#ifdef HAVE_TCL
  Tcl_UntraceVar(interp, "sasl-mechanism", TCL_TRACE_WRITES | TCL_TRACE_UNSETS,
                 traced_sasl_mechanism, NULL);
#endif /* HAVE_TCL */
}

static void sasl_start(void)
{
#ifdef HAVE_TCL
  Tcl_TraceVar(interp, "sasl-mechanism", TCL_TRACE_WRITES | TCL_TRACE_UNSETS,
               traced_sasl_mechanism, NULL);
#endif /* HAVE_TCL */
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
    op_strbuf_t _supported;
    op_strbuf_init(&_supported);
    /* Build a space-separated list of what the server actually advertised */
    for (v = cap_value_list; v; v = v->next) {
      if (op_strbuf_len(&_supported))
        op_strbuf_append_cstr(&_supported, " ");
      op_strbuf_append_cstr(&_supported, v->name);
    }
    {
      op_strbuf_t _m;
      op_strbuf_printf(&_m, "authentication mechanism %s not supported by server",
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

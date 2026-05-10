/*
 * tls.c -- handles:
 *   TLS support functions
 *   Certificate handling
 *   opssl initialization and shutdown
 */
/*
 * Written by Rumen Stoyanov <pseudo@egg6.net>
 * Migrated to opssl by Claude
 *
 * Copyright (C) 2010 - 2025 Eggheads Development Team
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif
#include "main.h"
#include <op_commio.h>

#ifdef TLS

#include <opssl/opssl.h>
#include <opssl/ctx.h>
#include <opssl/conn.h>
#include <opssl/cert.h>
#include <opssl/err.h>
#include <opssl/types.h>
#include <time.h>
#include <errno.h>
#include <stdio.h>
#include "version.h"

extern int dcc_total, stealth_telnets, tls_vfydcc;
extern struct dcc_t *dcc;

int tls_maxdepth = 9;         /* Max certificate chain verification depth     */
int ssl_files_loaded = 0;     /* Check for loaded SSL key/cert files          */
opssl_ctx_t *ssl_ctx = NULL;  /* TLS context object                           */
char *tls_randfile = NULL;    /* Random seed file for SSL (unused in opssl)   */
char tls_capath[121] = "";    /* Path to trusted CA certificates              */
char tls_cafile[121] = "";    /* File containing trusted CA certificates      */
char tls_certfile[121] = "";  /* Our own digital certificate                  */
char tls_keyfile[121] = "";   /* Private key for use with eggdrop             */
char tls_protocols[61] = "TLSv1 TLSv1.1 TLSv1.2 TLSv1.3" ; /* A list of protocols for SSL to use */
char tls_dhparam[121] = "";   /* dhparam for SSL to use                       */
char tls_ciphers[2049] = "";  /* A list of ciphers for SSL to use             */

/* Storage for ssl_appdata indexed by socket fd */
static ssl_appdata *ssl_appdata_table[FD_SETSIZE];

/* Forward declarations */
static void ssl_handshake_completed(int sock);
static void ssl_showcert(opssl_x509_t *cert, const int loglev);

/* Get the certificate, corresponding to the connection identified by sock.
 *
 * Return value: pointer to a opssl_x509_t certificate or NULL if we couldn't look up
 * the certificate.
 */
static opssl_x509_t *ssl_getcert(int sock)
{
  struct threaddata *td = threaddata();
  int i = findsock(sock);
  if (i == -1 || !td->socklist[i].ssl)
    return NULL;
  return opssl_conn_get_peer_cert(td->socklist[i].ssl);
}

/* Get the certificate fingerprint of the connection corresponding to the
 * socket.
 *
 * Return value: ptr to the hexadecimal representation of the fingerprint or
 * NULL in case of error.
 */
char *ssl_getfp(int sock)
{
  static char fp[65]; /* SHA1 = 20 bytes * 2 + 19 colons + 1 null = 60, but use 65 for safety */
  opssl_x509_t *cert;

  if (!(cert = ssl_getcert(sock)))
    return NULL;

  if (opssl_x509_fingerprint_hex(cert, OPSSL_FP_SHA1, fp, sizeof fp) != 0)
    return NULL;

  return fp;
}

void verify_cert_expiry(int idx) {
  opssl_x509_t *x509;

  x509 = opssl_x509_from_file(tls_certfile);
  if (x509) {
    if (opssl_x509_is_expired(x509)) {
      if (idx) {
        dprintf(idx, "WARNING: SSL/TLS certificate %s expired\n", tls_certfile);
        dprintf(idx, "You can generate new certificates by running 'make sslcert' from the source directory\n\n");
      } else {
        putlog(LOG_MISC, "*", "\nWARNING: SSL/TLS certificate %s expired", tls_certfile);
        putlog(LOG_MISC, "*", "You can generate new certificates by running 'make sslcert' from the source directory\n");
      }
    }
    opssl_x509_free(x509);
  }
}

/* Prepares and initializes TLS stuff
 *
 * Creates a context object, supporting TLS 1.2/1.3;
 * Optionally loads a TLS certificate and a private key.
 * Tell opssl the location of certificate authority certs
 *
 * Return value: 0 on successful initialization, !=0 on failure
 */
int ssl_init(void)
{
  /* opssl library initialization */
  if (opssl_init() != 0) {
    putlog(LOG_MISC, "*", "ERROR: TLS: unable to initialize opssl library. Disabling SSL");
    return -2;
  }

  /* Create TLS context with minimum TLS 1.2 */
  if (!(ssl_ctx = opssl_ctx_new(OPSSL_TLS_1_2))) {
    putlog(LOG_MISC, "*", "ERROR: TLS: unable to create context. Disabling SSL.");
    opssl_cleanup();
    return -1;
  }

  ssl_files_loaded = 0;
  if ((tls_certfile[0] == '\0') != (tls_keyfile[0] == '\0')) {
    /* Both need to be set or unset */
    putlog(LOG_MISC, "*", "ERROR: TLS: %s set but %s unset. Both must be set "
        "to use a certificate, or unset both to disable.",
        tls_certfile[0] ? "ssl-certificate" : "ssl-privatekey",
        tls_certfile[0] ? "ssl-privatekey" : "ssl-certificate");
    fatal("ssl-privatekey and ssl-certificate must both be set or unset.", 0);
  }

  if (tls_certfile[0] && tls_keyfile[0]) {
    /* Load our own certificate and private key. Mandatory for acting as
       server, because we don't support anonymous ciphers by default. */
    if (opssl_ctx_use_certificate_chain_file(ssl_ctx, tls_certfile) != 0) {
      putlog(LOG_MISC, "*", "ERROR: TLS: unable to load own certificate from %s: %s",
          tls_certfile, opssl_err_string(opssl_err_get()));
      fatal("Unable to load TLS certificate (ssl-certificate config setting)!", 0);
    }

    /* Display certificate fingerprints */
    {
      opssl_x509_t *own_cert = opssl_x509_from_file(tls_certfile);
      if (own_cert) {
        char sha1fp[65], sha256fp[129];
        putlog(LOG_MISC, "*", "Certificate loaded: %s", tls_certfile);
        if (opssl_x509_fingerprint_hex(own_cert, OPSSL_FP_SHA1, sha1fp, sizeof sha1fp) == 0)
          putlog(LOG_MISC, "*", "  SHA-1   fingerprint: %s", sha1fp);
        if (opssl_x509_fingerprint_hex(own_cert, OPSSL_FP_SHA256, sha256fp, sizeof sha256fp) == 0)
          putlog(LOG_MISC, "*", "  SHA-256 fingerprint: %s", sha256fp);
        opssl_x509_free(own_cert);
      }
    }

    verify_cert_expiry(0);
    if (opssl_ctx_use_private_key_file(ssl_ctx, tls_keyfile) != 0) {
      putlog(LOG_MISC, "*", "ERROR: TLS: unable to load private key from %s: %s",
          tls_keyfile, opssl_err_string(opssl_err_get()));
      fatal("Unable to load TLS private key (ssl-privatekey config setting)!", 0);
    }

    if (opssl_ctx_check_private_key(ssl_ctx) != 0) {
      putlog(LOG_MISC, "*", "ERROR: TLS: private key does not match certificate");
      fatal("Private key does not match certificate!", 0);
    }
    ssl_files_loaded = 1;
  }

  if ((tls_capath[0] || tls_cafile[0]) &&
      opssl_ctx_load_verify_locations(ssl_ctx, tls_cafile[0] ? tls_cafile : NULL,
      tls_capath[0] ? tls_capath : NULL) != 0) {
    putlog(LOG_MISC, "*", "ERROR: TLS: unable to set CA certificates location: %s",
           opssl_err_string(opssl_err_get()));
  }

  /* Parse and set protocol versions */
  if (tls_protocols[0]) {
    char s[sizeof tls_protocols];
    char *sep = " ";
    char *word;
    bool has_tls12 = false, has_tls13 = false;
    char *saveptr = NULL;
    strlcpy(s, tls_protocols, sizeof(s));
    for (word = strtok_r(s, sep, &saveptr); word; word = strtok_r(NULL, sep, &saveptr)) {
      if (!strcmp(word, "TLSv1.2"))
        has_tls12 = true;
      if (!strcmp(word, "TLSv1.3"))
        has_tls13 = true;
    }

    /* opssl defaults to TLS 1.2 minimum, so we only need to adjust if different */
    if (has_tls13 && !has_tls12) {
      opssl_ctx_set_min_version(ssl_ctx, OPSSL_TLS_1_3);
      opssl_ctx_set_max_version(ssl_ctx, OPSSL_TLS_1_3);
    } else if (has_tls12 && !has_tls13) {
      opssl_ctx_set_min_version(ssl_ctx, OPSSL_TLS_1_2);
      opssl_ctx_set_max_version(ssl_ctx, OPSSL_TLS_1_2);
    }
    /* Otherwise accept both TLS 1.2 and 1.3 (default behavior) */
  }

  /* Set secure defaults */
  opssl_ctx_set_options(ssl_ctx, OPSSL_OPT_NO_COMPRESSION | OPSSL_OPT_CIPHER_SERVER_PREF |
                                 OPSSL_OPT_SINGLE_DH_USE | OPSSL_OPT_SINGLE_ECDH_USE);

  /* Load DH parameters if specified */
  if (tls_dhparam[0]) {
    if (opssl_ctx_use_dh_params_file(ssl_ctx, tls_dhparam) == 0)
      debug1("TLS: setting ssl dhparam %s successful", tls_dhparam);
    else
      putlog(LOG_MISC, "*", "ERROR: TLS: failed to load dhparam from %s: %s",
             tls_dhparam, opssl_err_string(opssl_err_get()));
  }

  /* Set cipher suites if specified */
  if (tls_ciphers[0] && opssl_ctx_set_ciphersuites(ssl_ctx, tls_ciphers) != 0) {
    /* this replaces any preset ciphers so an invalid list is fatal */
    putlog(LOG_MISC, "*", "ERROR: TLS: no valid ciphersuites found. Disabling SSL.");
    opssl_ctx_free(ssl_ctx);
    ssl_ctx = NULL;
    opssl_cleanup();
    return -3;
  }

  /* Set certificate chain verification depth */
  opssl_ctx_set_verify_depth(ssl_ctx, tls_maxdepth);

  return 0;
}

/* Free the TLS CTX, clean up the mess */
void ssl_cleanup(void)
{
  /* Clear the ssl_appdata table */
  for (int i = 0; i < FD_SETSIZE; i++) {
    if (ssl_appdata_table[i]) {
      op_free(ssl_appdata_table[i]);
      ssl_appdata_table[i] = NULL;
    }
  }

  if (ssl_ctx) {
    opssl_ctx_free(ssl_ctx);
    ssl_ctx = NULL;
  }
  opssl_cleanup();
}

char *ssl_fpconv(char *in, char *out)
{
  size_t len;
  char *result;

  if (!in)
    return NULL;

  /* Simple hex fingerprint normalization - opssl provides hex directly */
  len = strlen(in);
  result = user_realloc(out, len + 1);
  if (result) {
    strcpy(result, in);
    return result;
  }
  return NULL;
}

/* Get the UID field from the certificate subject name.
 * The certificate is looked up using the socket of the connection.
 *
 * Return value: Pointer to the uid string or NULL if not found
 */
const char *ssl_getuid(int sock)
{
  static char subject_buf[512];
  char *uid_pos;
  opssl_x509_t *cert;

  if (!(cert = ssl_getcert(sock)))
    return NULL;

  /* Get the subject name */
  if (opssl_x509_get_subject(cert, subject_buf, sizeof subject_buf) != 0)
    return NULL;

  /* Look for UID= in the subject string */
  uid_pos = strstr(subject_buf, "UID=");
  if (!uid_pos)
    return NULL;

  uid_pos += 4; /* Skip "UID=" */

  /* Find the end of the UID (next comma or end of string) */
  char *end = strchr(uid_pos, ',');
  if (end)
    *end = '\0';

  return uid_pos;
}

/* Verification callback for opssl */
static int ssl_verify_callback(int preverify_ok, opssl_x509_t *cert, int depth, void *userdata)
{
  ssl_appdata *data = (ssl_appdata *)userdata;

  if (!data)
    return preverify_ok;

  /* Depth 0 is the peer certificate */
  if (depth == 0) {
    data->flags |= TLS_DEPTH0;

    /* Check certificate expiry if requested */
    if ((data->verify & TLS_VERIFYTO) && opssl_x509_is_expired(cert)) {
      putlog(data->loglevel, "*", "TLS: peer certificate has expired");
      if (data->verify & TLS_VERIFYTO)
        return 0;
    }

    /* Note: hostname verification is handled by opssl internally when SNI is set */
  }

  /* Allow self-signed certificates if TLS_VERIFYISSUER is not set */
  if (!preverify_ok && !(data->verify & TLS_VERIFYISSUER)) {
    putlog(data->loglevel, "*", "TLS: allowing unverified peer certificate");
    return 1;
  }

  return preverify_ok;
}

/* Switch a socket to TLS communication
 *
 * Creates a TLS data structure for the connection;
 * Sets up callbacks and initiates a TLS handshake with the peer;
 * Reports error conditions and performs cleanup upon failure.
 *
 * flags: ssl flags, i.e connect or listen
 * verify: peer certificate verification flags
 * loglevel: is the level to output information about the connection
 * and certificates.
 * host: contains the dns name or ip address of the peer. Used for
 * verification.
 * cb: optional callback, this function will be called after the
 * handshake completes.
 *
 * Return value: 0 on success, !=0 on failure.
 */
int ssl_handshake(int sock, int flags, int verify, int loglevel, char *host,
                  IntFunc cb)
{
  opssl_result_t ret;
  ssl_appdata *data;
  struct threaddata *td = threaddata();
  opssl_direction_t dir;

  debug0("TLS: attempting TLS negotiation...");
  if (!ssl_ctx && ssl_init()) {
    debug0("TLS: Failed. opssl not initialized properly.");
    return -1;
  }
  if ((flags & TLS_LISTEN) && !ssl_files_loaded) {
    putlog(LOG_MISC, "*", "TLS: Failed. Certificate/Key not loaded, cannot support SSL/TLS for client (see doc/TLS).");
    return -4;
  }

  /* find the socket in the list */
  int i = findsock(sock);
  if (i == -1) {
    debug0("TLS: socket not in socklist");
    return -2;
  }
  if (td->socklist[i].ssl) {
    debug0("TLS: handshake not required - TLS session already established");
    return 0;
  }

  /* Determine connection direction */
  dir = (flags & TLS_CONNECT) ? OPSSL_DIR_OUTBOUND : OPSSL_DIR_INBOUND;

  td->socklist[i].ssl = opssl_conn_new(ssl_ctx, td->socklist[i].sock, dir);
  if (!td->socklist[i].ssl) {
    debug1("TLS: cannot initiate TLS session - %s", opssl_err_string(opssl_err_get()));
    return -3;
  }

  /* Sync the opssl_conn_t pointer onto the commio FDE */
  {
    op_fde_t *F = op_get_fde(td->socklist[i].sock);
    if (F) {
      /* TODO: op_fde_set_ssl_ptr needs to be implemented for opssl */
      /* op_fde_set_ssl_ptr(F, td->socklist[i].ssl); */
    }
  }

  /* Prepare ssl appdata struct */
  data = op_malloc(sizeof(ssl_appdata));
  data->flags = flags & (TLS_LISTEN | TLS_CONNECT);
  data->verify = verify;
  /* Invert these flags as their corresponding configuration values express
   * exceptions
   */
  if (data->verify)
      data->verify ^= (TLS_VERIFYISSUER | TLS_VERIFYCN | TLS_VERIFYFROM |
                       TLS_VERIFYTO | TLS_VERIFYREV);
  data->loglevel = loglevel;
  data->cb = cb;
  strlcpy(data->host, host ? host : "", sizeof(data->host));

  /* Store ssl_appdata in our table indexed by fd */
  if (sock >= 0 && sock < FD_SETSIZE) {
    if (ssl_appdata_table[sock])
      op_free(ssl_appdata_table[sock]);
    ssl_appdata_table[sock] = data;
  }

  /* Set up verification callback */
  if (data->verify) {
    opssl_ctx_set_verify(ssl_ctx, data->verify & TLS_VERIFYPEER,
                         ssl_verify_callback, data);
  }

  /* Set SNI for outgoing connections */
  if ((data->flags & TLS_CONNECT) && *data->host) {
    if (opssl_conn_set_sni(td->socklist[i].ssl, data->host) == 0)
      debug1("TLS: setting the server name indication (SNI) to %s successful", data->host);
    else
      debug1("TLS: setting the server name indication (SNI) to %s failed", data->host);
  }

  /* Start the handshake */
  if (data->flags & TLS_CONNECT) {
    /* Introduce 1ms lag so an unpatched hub has time to setup the ssl handshake */
    const struct timespec req = { 0, 1000000L };
    nanosleep(&req, NULL);
    ret = opssl_connect(td->socklist[i].ssl);
    if (ret == OPSSL_FATAL)
      debug0("TLS: connect handshake failed.");
  } else {
    ret = opssl_accept(td->socklist[i].ssl);
    if (ret == OPSSL_FATAL)
      debug0("TLS: accept handshake failed");
  }

  /* Check handshake result */
  if (ret == OPSSL_OK) {
    /* Handshake completed immediately */
    debug0("TLS: handshake completed successfully");
    ssl_handshake_completed(sock);
    if (data->cb)
      ((int (*)(int)) data->cb)(sock);
    return 0;
  } else if (ret == OPSSL_WANT_READ || ret == OPSSL_WANT_WRITE) {
    /* Handshake in progress - will complete asynchronously */
    debug0("TLS: handshake in progress");
    return 0;
  }

  /* Handshake failed */
  opssl_err_t err = opssl_conn_get_error(td->socklist[i].ssl);
  putlog(data->loglevel, "*", "TLS: handshake failed: %s", opssl_conn_get_error_string(td->socklist[i].ssl));

  /* Cleanup on failure */
  opssl_shutdown(td->socklist[i].ssl);
  opssl_conn_free(td->socklist[i].ssl);
  td->socklist[i].ssl = NULL;
  {
    op_fde_t *F = op_get_fde(td->socklist[i].sock);
    if (F) {
      /* TODO: op_fde_set_ssl_ptr needs to be implemented for opssl */
      /* op_fde_set_ssl_ptr(F, NULL); */
    }
  }
  if (sock >= 0 && sock < FD_SETSIZE && ssl_appdata_table[sock]) {
    op_free(ssl_appdata_table[sock]);
    ssl_appdata_table[sock] = NULL;
  }
  return -4;
}

/* Handle completed TLS handshake - called when handshake finishes */
static void ssl_handshake_completed(int sock)
{
  struct threaddata *td = threaddata();
  ssl_appdata *data;
  opssl_x509_t *cert;
  int i = findsock(sock);

  if (i == -1 || !td->socklist[i].ssl)
    return;

  data = (sock >= 0 && sock < FD_SETSIZE) ? ssl_appdata_table[sock] : NULL;
  if (!data)
    return;

  putlog(data->loglevel, "*", "TLS: handshake successful. Secure connection established.");

  /* Display certificate information */
  if ((cert = opssl_conn_get_peer_cert(td->socklist[i].ssl))) {
    ssl_showcert(cert, LOG_DEBUG);
  } else {
    putlog(data->loglevel, "*", "TLS: peer did not present a certificate");
  }

  /* Display cipher information */
  const char *cipher = opssl_conn_cipher_name(td->socklist[i].ssl);
  opssl_tls_version_t version = opssl_conn_version(td->socklist[i].ssl);
  const char *version_str = (version == OPSSL_TLS_1_3) ? "TLSv1.3" :
                           (version == OPSSL_TLS_1_2) ? "TLSv1.2" : "Unknown";

  putlog(LOG_DEBUG, "*", "TLS: cipher used: %s, %s", cipher, version_str);
}

/* Show the user all relevant information about a certificate: subject,
 * issuer, validity dates and fingerprints.
 */
static void ssl_showcert(opssl_x509_t *cert, const int loglev)
{
  char subject[512], issuer[512];
  char sha1fp[65], sha256fp[129];
  int64_t not_before, not_after;

  /* Subject and issuer names */
  if (opssl_x509_get_subject(cert, subject, sizeof subject) == 0) {
    putlog(loglev, "*", "TLS: certificate subject: %s", subject);
  } else {
    putlog(loglev, "*", "TLS: cannot get subject name from certificate!");
  }

  if (opssl_x509_get_issuer(cert, issuer, sizeof issuer) == 0) {
    putlog(loglev, "*", "TLS: certificate issuer: %s", issuer);
  } else {
    putlog(loglev, "*", "TLS: cannot get issuer name from certificate!");
  }

  /* Fingerprints */
  if (opssl_x509_fingerprint_hex(cert, OPSSL_FP_SHA1, sha1fp, sizeof sha1fp) == 0) {
    putlog(loglev, "*", "TLS: certificate SHA1 Fingerprint: %s", sha1fp);
  }
  if (opssl_x509_fingerprint_hex(cert, OPSSL_FP_SHA256, sha256fp, sizeof sha256fp) == 0) {
    putlog(loglev, "*", "TLS: certificate SHA-256 Fingerprint: %s", sha256fp);
  }

  /* Validity time */
  if (opssl_x509_get_not_before(cert, &not_before) == 0 &&
      opssl_x509_get_not_after(cert, &not_after) == 0) {
    /* Convert epochs to readable format */
    char from[32], to[32];
    struct tm *tm;

    tm = gmtime((time_t*)&not_before);
    strftime(from, sizeof from, "%b %d %H:%M:%S %Y GMT", tm);
    tm = gmtime((time_t*)&not_after);
    strftime(to, sizeof to, "%b %d %H:%M:%S %Y GMT", tm);

    putlog(loglev, "*", "TLS: certificate valid from %s to %s", from, to);
  }
}

/* Tcl command handlers */

/* Is the connection secure? */
static int tcl_istls STDVAR
{
  int j;

  BADARGS(2, 2, " idx");

  j = findidx(atoi(argv[1]));
  if (j < 0) {
    Tcl_AppendResult(irp, "invalid idx", NULL);
    return TCL_ERROR;
  }
  if (dcc[j].ssl)
    Tcl_AppendResult(irp, "1", NULL);
  else
    Tcl_AppendResult(irp, "0", NULL);
  return TCL_OK;
}

/* Perform a TLS handshake over an existing plain text connection */
static int tcl_starttls STDVAR
{
  int j;
  struct threaddata *td = threaddata();

  BADARGS(2, 2, " idx");

  j = findidx(atoi(argv[1]));
  if (j < 0 || (dcc[j].type != &DCC_SCRIPT)) {
    Tcl_AppendResult(irp, "invalid idx", NULL);
    return TCL_ERROR;
  }
  if (dcc[j].ssl) {
    Tcl_AppendResult(irp, "already started", NULL);
    return TCL_ERROR;
  }
  /* Determine if we're playing a client or a server */
  j = findsock(dcc[j].sock);
  if (ssl_handshake(dcc[j].sock, (td->socklist[j].flags & SOCK_CONNECT) ?
      TLS_CONNECT : TLS_LISTEN, tls_vfydcc, LOG_MISC, NULL, NULL))
    Tcl_AppendResult(irp, "0", NULL);
  else
    Tcl_AppendResult(irp, "1", NULL);
  return TCL_OK;
}

/* Get all relevant information about an established TLS connection */
static int tcl_tlsstatus STDVAR
{
  opssl_x509_t *cert;
  struct threaddata *td = threaddata();
  Tcl_DString ds;
  char subject[512], issuer[512];
  int64_t not_before, not_after;
  char serial_buf[64];

  BADARGS(2, 2, " idx");

  /* Allow it to be used for any connection, not just scripted ones */
  int i = findanyidx(atoi(argv[1]));
  if (i < 0) {
    Tcl_AppendResult(irp, "invalid idx", NULL);
    return TCL_ERROR;
  }
  int j = findsock(dcc[i].sock);
  if (!j || !dcc[i].ssl || !td->socklist[j].ssl) {
    Tcl_AppendResult(irp, "not a TLS connection", NULL);
    return TCL_ERROR;
  }

  Tcl_DStringInit(&ds);

  /* Try to get a cert, clients aren't required to send a certificate */
  cert = opssl_conn_get_peer_cert(td->socklist[j].ssl);
  if (cert) {
    if (opssl_x509_get_subject(cert, subject, sizeof subject) == 0) {
      Tcl_DStringAppendElement(&ds, "subject");
      Tcl_DStringAppendElement(&ds, subject);
    }
    if (opssl_x509_get_issuer(cert, issuer, sizeof issuer) == 0) {
      Tcl_DStringAppendElement(&ds, "issuer");
      Tcl_DStringAppendElement(&ds, issuer);
    }
    if (opssl_x509_get_not_before(cert, &not_before) == 0) {
      struct tm *tm = gmtime((time_t*)&not_before);
      char date_str[32];
      strftime(date_str, sizeof date_str, "%b %d %H:%M:%S %Y GMT", tm);
      Tcl_DStringAppendElement(&ds, "notBefore");
      Tcl_DStringAppendElement(&ds, date_str);
    }
    if (opssl_x509_get_not_after(cert, &not_after) == 0) {
      struct tm *tm = gmtime((time_t*)&not_after);
      char date_str[32];
      strftime(date_str, sizeof date_str, "%b %d %H:%M:%S %Y GMT", tm);
      Tcl_DStringAppendElement(&ds, "notAfter");
      Tcl_DStringAppendElement(&ds, date_str);
    }

    /* Serial number as hex string */
    uint8_t serial[32];
    size_t serial_len = sizeof serial;
    if (opssl_x509_get_serial(cert, serial, &serial_len) == 0) {
      char *hex_pos = serial_buf;
      for (size_t i = 0; i < serial_len; i++) {
        snprintf(hex_pos, 3, "%02X", serial[i]);
        hex_pos += 2;
      }
      *hex_pos = '\0';
      Tcl_DStringAppendElement(&ds, "serial");
      Tcl_DStringAppendElement(&ds, serial_buf);
    }
  }

  /* Cipher and protocol information */
  const char *cipher = opssl_conn_cipher_name(td->socklist[j].ssl);
  opssl_tls_version_t version = opssl_conn_version(td->socklist[j].ssl);
  if (cipher) {
    const char *version_str = (version == OPSSL_TLS_1_3) ? "TLSv1.3" :
                             (version == OPSSL_TLS_1_2) ? "TLSv1.2" : "Unknown";
    Tcl_DStringAppendElement(&ds, "protocol");
    Tcl_DStringAppendElement(&ds, version_str);
    Tcl_DStringAppendElement(&ds, "cipher");
    Tcl_DStringAppendElement(&ds, cipher);
  }

  /* Done, get a Tcl list from this and return it to the caller */
  Tcl_AppendResult(irp, Tcl_DStringValue(&ds), NULL);
  Tcl_DStringFree(&ds);
  return TCL_OK;
}

/* These will be added by tcl.c which is the established practice */
tcl_cmds tcltls_cmds[] = {
  {"istls",         (IntFunc) tcl_istls},
  {"starttls",   (IntFunc) tcl_starttls},
  {"tlsstatus", (IntFunc) tcl_tlsstatus},
  {NULL,                 NULL}
};

#endif /* TLS */
/* egg_tls.h — wolfSSL include shim that avoids the mp_int/mp_digit conflict
 * between wolfssl/sp_int.h and Tcl's tcl.h.
 *
 * wolfSSL (compiled with WOLFSSL_SP_MATH_ALL) transitively declares:
 *   typedef sp_int mp_int;
 *   typedef unsigned int mp_digit;
 *
 * Tcl (tcl.h) unconditionally declares:
 *   typedef struct mp_int mp_int;
 *   typedef unsigned int  mp_digit;   <- same type, but the struct vs typedef clash
 *
 * Strategy: before including wolfssl headers, redirect the two names to private
 * aliases.  wolfssl's typedef then creates _egg_wolfssl_mp_int / _egg_wolfssl_mp_digit.
 * After the wolfssl headers are processed we restore the names so Tcl sees them
 * as undefined and can declare its own struct-based versions cleanly.
 *
 * Translation units that call wolfssl API (SSL_read, SSL_write, …) must
 *   #include "egg_tls.h"
 * BEFORE any inclusion of main.h / lush.h / tcl.h.
 *
 * Do NOT include this header in the no-TLS build (guard with #ifdef TLS).
 */

#ifndef EGG_TLS_H
#define EGG_TLS_H

#ifdef TLS

/* Redirect wolfssl's math type names away from the Tcl-owned names. */
#define mp_int    _egg_wolfssl_mp_int
#define mp_digit  _egg_wolfssl_mp_digit

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
/* wolfssl/openssl/ssl.h provides many OpenSSL compat macros. */
#include <wolfssl/openssl/ssl.h>
#include <wolfssl/openssl/err.h>
/* pem.h (PEM_read_PrivateKey etc.) is gated behind OPENSSL_ALL in ssl.h;
 * include it directly to ensure it's always available. */
#include <wolfssl/openssl/pem.h>

/* Restore — Tcl (included later via main.h) defines its own versions. */
#undef mp_int
#undef mp_digit

/* wolfSSL guards SSL_set_mode / wolfSSL_ctrl behind OPENSSL_ALL which is not
 * enabled in the installed library — provide a safe no-op instead. */
#ifndef SSL_set_mode
#  define SSL_set_mode(ssl, op)  ((void)(ssl), (void)(op), 0L)
#endif

/* wolfSSL lacks the short-form alert string functions (only _long exist). */
#ifndef SSL_alert_type_string
#  define SSL_alert_type_string(x)  SSL_alert_type_string_long(x)
#endif
#ifndef SSL_alert_desc_string
#  define SSL_alert_desc_string(x)  SSL_alert_desc_string_long(x)
#endif

/* wolfSSL has no SSL_R_PEER_DID_NOT_RETURN_A_CERTIFICATE — stub it. */
#ifndef SSL_R_PEER_DID_NOT_RETURN_A_CERTIFICATE
#  define SSL_R_PEER_DID_NOT_RETURN_A_CERTIFICATE 0
#endif

#endif /* TLS */
#endif /* EGG_TLS_H */

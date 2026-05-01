/*
 * net.c -- handles:
 *   all raw network i/o
 */
/*
 * This is hereby released into the public domain.
 * Robey Pointer, robey@netcom.com
 *
 * Changes after Feb 23, 1999 Copyright Eggheads Development Team
 *
 * Copyright (C) 1999 - 2025 Eggheads Development Team
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

/* Enable GNU extensions (accept4, SOCK_NONBLOCK, etc.) */
#ifndef _GNU_SOURCE
#  define _GNU_SOURCE
#endif
/* egg_tls.h includes wolfSSL before Tcl, redirecting mp_int to avoid the
 * typedef clash between wolfssl/sp_int.h and tcl.h.  Must precede main.h. */
#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif
#include "egg_tls.h"
#include <fcntl.h>
#include <stdatomic.h>
#include "main.h"
#include "modules.h"
#include <op_commio.h>
#include <commio-ssl.h>

/* POSIX select(2) type macros — used only for TCL socket handling. */
#ifndef SELECT_TYPE_ARG1
# define SELECT_TYPE_ARG1 int
#endif
#ifndef SELECT_TYPE_ARG234
# define SELECT_TYPE_ARG234 (fd_set *)
#endif
#ifndef SELECT_TYPE_ARG5
# define SELECT_TYPE_ARG5 (struct timeval *)
#endif
#include <limits.h>
#include <netdb.h>
#if HAVE_SYS_SELECT_H
#  include <sys/select.h>
#endif
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <errno.h>
#if HAVE_UNISTD_H
#  include <unistd.h>
#endif
#include <setjmp.h>
#ifndef EGG_NATIVE_WIN32
#  include <sys/uio.h>
#endif

/* -----------------------------------------------------------------------
 * I/O multiplexing — libop commio callbacks
 *
 * These are fired by op_select() when a socket becomes readable or writable.
 * They set commio_ready so sockread()'s dispatch loop processes the socket.
 * ----------------------------------------------------------------------- */

extern sock_list *socklist;

static void commio_read_cb(op_fde_t *F, void *data)
{
  int slist_idx = (int)(intptr_t)data;
  struct threaddata *td = threaddata();

  (void)F;
  if (slist_idx < 0 || slist_idx >= td->MAXSOCKS)
    return;

  sock_list *sl = &socklist[slist_idx];
  if (sl->flags & SOCK_UNUSED)
    return;

  sl->commio_ready = 1;
}

static void commio_write_cb(op_fde_t *F, void *data)
{
  int slist_idx = (int)(intptr_t)data;
  struct threaddata *td = threaddata();

  (void)F;
  if (slist_idx < 0 || slist_idx >= td->MAXSOCKS)
    return;

  sock_list *sl = &socklist[slist_idx];
  if (sl->flags & SOCK_UNUSED)
    return;

  sl->commio_ready = 1;
}

/* Platform socket shims */
#ifdef EGG_NATIVE_WIN32
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  define egg_closesocket(s)    closesocket(s)
static inline void egg_setnonblock(int sock) {
  u_long on = 1;
  ioctlsocket((SOCKET)(UINT_PTR)sock, FIONBIO, &on);
}
struct iovec { void *iov_base; size_t iov_len; };
static inline int egg_writev(int sock, const struct iovec *iov, int cnt) {
  WSABUF bufs[2];
  DWORD sent = 0;
  for (int i = 0; i < cnt && i < 2; i++) {
    bufs[i].buf = (char *)iov[i].iov_base;
    bufs[i].len = (ULONG)iov[i].iov_len;
  }
  if (WSASend((SOCKET)(UINT_PTR)sock, bufs, (DWORD)cnt, &sent, 0, NULL, NULL) == SOCKET_ERROR)
    return -1;
  return (int)sent;
}
#  define writev(s, iov, cnt) egg_writev(s, iov, cnt)
#  define write(s, buf, len)  send((SOCKET)(UINT_PTR)(s), (const char*)(buf), (int)(len), 0)
#  ifndef EINPROGRESS
#    define EINPROGRESS  WSAEWOULDBLOCK
#  endif
#  ifndef EAGAIN
#    define EAGAIN       WSAEWOULDBLOCK
#  endif
#  ifndef EWOULDBLOCK
#    define EWOULDBLOCK  WSAEWOULDBLOCK
#  endif
#  ifndef ECONNREFUSED
#    define ECONNREFUSED WSAECONNREFUSED
#  endif
#  ifndef ENOTCONN
#    define ENOTCONN     WSAENOTCONN
#  endif
#else  /* POSIX */
#  define egg_closesocket(s)  close(s)
static inline void egg_setnonblock(int sock) {
  fcntl(sock, F_SETFL, O_NONBLOCK);
}
#endif /* EGG_NATIVE_WIN32 */
extern struct dcc_t *dcc;
extern int backgrd, use_stderr, resolve_timeout, dcc_total;
extern _Atomic uint64_t otraffic_irc_today, otraffic_bn_today,
                        otraffic_dcc_today, otraffic_filesys_today,
                        otraffic_trans_today, otraffic_unknown_today;
extern time_t online_since;

char nat_ip[INET_ADDRSTRLEN] = ""; /* Public IPv4 to report for systems behind NAT */
char nat_ip_string[11];
char listen_ip[121] = "";     /* IP (or hostname) for listening sockets       */
char vhost[121] = "";         /* IPv4 vhost for outgoing connections          */
#ifdef IPV6
char vhost6[121] = "";        /* IPv6 vhost for outgoing connections          */
int pref_af = 0;              /* Prefer IPv6 over IPv4?                       */
#endif
char firewall[121] = "";      /* Socks server for firewall.                   */
int firewallport = 1080;      /* Default port of socks 4/5 firewalls.         */
char botuser[USERLEN + 1] = "eggdrop"; /* Username of the user running the bot*/
int dcc_sanitycheck = 0;      /* Do some sanity checking on dcc connections.  */
sock_list *socklist = NULL;   /* Enough to be safe.                           */
sigjmp_buf alarmret;          /* Env buffer for alarm() returns.              */

/* Types of proxies */
constexpr int PROXY_SOCKS = 1;
constexpr int PROXY_SUN   = 2;


/* I need an UNSIGNED long for dcc type stuff
 */
IP my_atoul(char *s)
{
  IP ret = 0;

  while ((*s >= '0') && (*s <= '9')) {
    ret *= 10;
    ret += ((*s) - '0');
    s++;
  }
  return ret;
}

/* Extract the IP address from a sockaddr struct and convert it
 * to presentation format.
 */
char *iptostr(struct sockaddr *sa)
{
  static char s[EGG_INET_ADDRSTRLEN] = "";
#ifdef IPV6
  if (sa->sa_family == AF_INET6)
    inet_ntop(AF_INET6, &((struct sockaddr_in6 *)sa)->sin6_addr,
              s, sizeof s);
  else
#endif
    inet_ntop(AF_INET, &((struct sockaddr_in *)sa)->sin_addr.s_addr, s,
              sizeof s);
  return s;
}

/* Fills in a sockname struct with the given server and port. If the string
 * pointed by src isn't an IP address and allowres is not null, the function
 * will assume it's a hostname and will attempt to resolve it. This is
 * convenient, but you should use the async dns functions where possible, to
 * avoid blocking the bot while the lookup is performed.
 */
int setsockname(sockname_t *addr, char *src, int port, int allowres)
{
  char *endptr, *src2 = src;
  long val;
  IP ip;
  volatile int af = AF_UNSPEC;
  char ip2[EGG_INET_ADDRSTRLEN];
#ifdef IPV6
  volatile int pref;
  struct addrinfo *res0 = NULL, *res;
  int error;
#else
  struct hostent *hp;
  int count;
#endif

  /* DCC CHAT ip is expressed as integer but inet_pton() only accepts dotted
   * addresses */
  val = strtol(src, &endptr, 10);
  if (val && !*endptr) {
    ip = htonl(val);
    if (inet_ntop(AF_INET, &ip, ip2, sizeof ip2)) {
      debug2("net: setsockname(): ip %s -> %s", src, ip2);
      src2 = ip2;
    }
  }
#ifdef IPV6
  /* Clean start */
  egg_bzero(addr, sizeof(sockname_t));
  pref = pref_af ? AF_INET6 : AF_INET;
  if (pref == AF_INET) {
    if (inet_pton(AF_INET, src2, &addr->addr.s4.sin_addr) == 1)
      af = AF_INET;
    else if (inet_pton(AF_INET6, src2, &addr->addr.s6.sin6_addr) == 1)
      af = AF_INET6;
    else
      af = AF_UNSPEC;
  } else {
    if (inet_pton(AF_INET6, src2, &addr->addr.s6.sin6_addr) == 1)
      af = AF_INET6;
    else if (inet_pton(AF_INET, src2, &addr->addr.s4.sin_addr) == 1)
      af = AF_INET;
    else
      af = AF_UNSPEC;
  }

  if (af == AF_UNSPEC && allowres && *src) {
    /* src is a hostname. Attempt to resolve it.. */
    if (!sigsetjmp(alarmret, 1)) {
      alarm(resolve_timeout);
      error = getaddrinfo(src, NULL, NULL, &res0);
      if (!error) {
        for (res = res0; res; res = res->ai_next) {
          if (res == res0 || res->ai_family == (pref_af ? AF_INET6 : AF_INET)) {
            af = res->ai_family;
            memcpy(&addr->addr.sa, res->ai_addr, res->ai_addrlen);
            if (res->ai_family == (pref_af ? AF_INET6 : AF_INET)) {
              break;
            }
          }
        }
        if (res0) /* The behavior of freeadrinfo(NULL) is left unspecified by RFCs
                   * 2553 and 3493. Avoid to be compatible with all OSes. */
          freeaddrinfo(res0);
      }
      else if (error == EAI_NONAME)
        debug1("net: setsockname(): getaddrinfo(): hostname %s not known", src);
      else
        debug1("net: setsockname(): getaddrinfo(): error = %s", gai_strerror(error));
      alarm(0);
    } else {
      debug1("net: setsockname(): getaddrinfo(): hostname %s resolve timeout", src);
    }
  }

  addr->family = (af == AF_UNSPEC) ? pref : af;
  addr->addr.sa.sa_family = addr->family;
  if (addr->family == AF_INET6) {
    addr->addrlen = sizeof(struct sockaddr_in6);
    addr->addr.s6.sin6_port = htons(port);
    addr->addr.s6.sin6_family = AF_INET6;
  } else {
    addr->addrlen = sizeof(struct sockaddr_in);
    addr->addr.s4.sin_port = htons(port);
    addr->addr.s4.sin_family = AF_INET;
  }
#else
  egg_bzero(addr, sizeof(sockname_t));

/* If it's not an IPv4 address, check if its IPv6 (so it can fail/error
 * appropriately). If it's not, and allowres is 1, use gethostbyname()
 * to try and resolve. If allowres is 0, return AF_UNSPEC to allow
 * dns.mod to do it's thing.

 * Also, because we can't be sure inet_pton exists on the system, we
 * have to resort to hackishly counting :s to see if its IPv6 or not.
 * Go internet.
 */
  if (!inet_pton(AF_INET, src2, &addr->addr.s4.sin_addr)) {
    /* Boring way to count :s */
    count = 0;
    for (int i = 0; src[i]; i++) {
      if (src[i] == ':') {
        count++;
        if (count == 2)
          break;
      }
    }
    if (count > 1) {
      putlog(LOG_MISC, "*", "ERROR: This looks like an IPv6 address, \
but this Eggdrop was not compiled with IPv6 support.");
      af = AF_UNSPEC;
    }
    else if (allowres) {
    /* src is a hostname. Attempt to resolve it.. */
      if (!sigsetjmp(alarmret, 1)) {
        alarm(resolve_timeout);
        hp = gethostbyname(src);
        alarm(0);
      } else
        hp = NULL;
      if (hp) {
        memcpy(&addr->addr.s4.sin_addr, hp->h_addr_list[0], hp->h_length);
        af = hp->h_addrtype;
      }
    } else
        af = AF_UNSPEC;
  } else
      af = AF_INET;

  addr->family = addr->addr.s4.sin_family = AF_INET;
  addr->addr.sa.sa_family = addr->family;
  addr->addrlen = sizeof(struct sockaddr_in);
  addr->addr.s4.sin_port = htons(port);
#endif
  return af;
}

/* Get socket address to bind to for outbound connections
 */
void getvhost(sockname_t *addr, int af)
{
  char *h = NULL;

  if (af == AF_INET)
    h = vhost;
#ifdef IPV6
  else
    h = vhost6;
#endif
  if (!h || !h[0] || setsockname(addr, (h ? h : ""), 0, 1) != af)
    setsockname(addr, (af == AF_INET ? "0.0.0.0" : "::"), 0, 0);
  /* Remember this 'self-lookup failed' thingie?
     I have good news - you won't see it again ;) */
}

/* Sets/Unsets options for a specific socket.
 *
 * Returns:  0   - on success
 *           -1  - socket not found
 *           -2  - illegal operation
 */
int sockoptions(int sock, int operation, int sock_options)
{
  struct threaddata *td = threaddata();

  for (int i = 0; i < td->MAXSOCKS; i++)
    if ((td->socklist[i].sock == sock) &&
        !(td->socklist[i].flags & SOCK_UNUSED)) {
      if (operation == EGG_OPTION_SET)
        td->socklist[i].flags |= sock_options;
      else if (operation == EGG_OPTION_UNSET)
        td->socklist[i].flags &= ~sock_options;
      else
        return -2;
      return 0;
    }
  return -1;
}

/* Return a free entry in the socket entry
 */
int allocsock(int sock, int options)
{
  struct threaddata *td = threaddata();

  for (int i = 0; i < td->MAXSOCKS; i++) {
    if (td->socklist[i].flags & SOCK_UNUSED) {
      /* yay!  there is table space */
      if (!(options & SOCK_TCL)) {
        op_linebuf_newbuf(&td->socklist[i].handler.sock.recvbuf);
        td->socklist[i].handler.sock.outbuf = NULL;
      }
      td->socklist[i].flags = options;
      td->socklist[i].sock = sock;
#ifdef TLS
      td->socklist[i].ssl = 0;
#endif
      /* Register with commio for I/O multiplexing. */
      td->socklist[i].commio_ready = 0;
      if (sock >= 0 && !(options & (SOCK_NONSOCK | SOCK_VIRTUAL))) {
        op_fde_t *F = op_open(sock, OP_FD_SOCKET, "eggdrop");
        if (F) {
          op_setselect(F, OP_SELECT_READ, commio_read_cb,
                       (void *)(intptr_t)i);
          if (options & SOCK_CONNECT)
            op_setselect(F, OP_SELECT_WRITE, commio_write_cb,
                         (void *)(intptr_t)i);
        }
      }
      return i;
    }
  }
  /* Try again if enlarging socketlist works */
  if (increase_socks_max())
    return -1;
  else
    return allocsock(sock, options);
}

/* Return a free entry in the socket entry for a tcl socket
 *
 * alloctclsock() can be called by Tcl threads
 */
int alloctclsock(int sock, int mask, Tcl_FileProc *proc, ClientData cd)
{
  int f = -1;
  struct threaddata *td = threaddata();

  for (int i = 0; i < td->MAXSOCKS; i++) {
    if (td->socklist[i].flags & SOCK_UNUSED) {
      if (f == -1)
        f = i;
    } else if ((td->socklist[i].flags & SOCK_TCL) &&
               td->socklist[i].sock == sock) {
      f = i;
      break;
    }
  }
  if (f != -1) {
    td->socklist[f].sock = sock;
    td->socklist[f].flags = SOCK_TCL;
    td->socklist[f].handler.tclsock.mask = mask;
    td->socklist[f].handler.tclsock.proc = proc;
    td->socklist[f].handler.tclsock.cd = cd;
    return f;
  }
  /* Try again if enlarging socketlist works */
  if (increase_socks_max())
    return -1;
  else
    return alloctclsock(sock, mask, proc, cd);
}

/* Request a normal socket for i/o
 */
void setsock(int sock, int options)
{
  int i = allocsock(sock, options), parm = 1;
  struct threaddata *td = threaddata();
  struct linger linger = {0};

  if (i == -1) {
    putlog(LOG_MISC, "*", "Sockettable full.");
    return;
  }
  if (((sock != STDOUT) || backgrd) && !(td->socklist[i].flags & SOCK_NONSOCK)) {
    if (setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &parm, sizeof parm))
      debug2("net: setsock(): setsockopt() s %i level SOL_SOCKET optname SO_KEEPALIVE error %s", sock, strerror(errno));
    if (setsockopt(sock, SOL_SOCKET, SO_LINGER, &linger, sizeof(struct linger)))
      debug2("net: setsock(): setsockopt() s %i level SOL_SOCKET optname SO_LINGER error %s", sock, strerror(errno));
    /* Turn off Nagle's algorithm, see man tcp */
    if (setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &parm, sizeof parm))
      debug2("net: setsock(): setsockopt() s %i level IPPROTO_TCP optname TCP_NODELAY error %s", sock, strerror(errno));
    /* Enlarge kernel socket buffers — reduces data loss under burst load */
    {
      int bufsz = 131072; /* 128 KB */
      if (setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &bufsz, sizeof bufsz))
        debug2("net: setsock(): SO_RCVBUF error %s on sock %d", strerror(errno), sock);
      if (setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &bufsz, sizeof bufsz))
        debug2("net: setsock(): SO_SNDBUF error %s on sock %d", strerror(errno), sock);
    }
    /* Fine-tune per-socket TCP keepalive probe timing.
     * Without these, the kernel defaults are typically 2 h idle / 75 s
     * between probes / 9 retries — far too slow to detect dead links.
     *   TCP_KEEPIDLE  : seconds of inactivity before first probe
     *   TCP_KEEPINTVL : seconds between subsequent probes
     *   TCP_KEEPCNT   : number of failed probes before declaring dead */
#ifdef TCP_KEEPIDLE
    {
      int v = 60; /* 60 s idle before probing */
      setsockopt(sock, IPPROTO_TCP, TCP_KEEPIDLE, &v, sizeof v);
    }
#endif
#ifdef TCP_KEEPINTVL
    {
      int v = 15; /* 15 s between probes */
      setsockopt(sock, IPPROTO_TCP, TCP_KEEPINTVL, &v, sizeof v);
    }
#endif
#ifdef TCP_KEEPCNT
    {
      int v = 4;  /* declare dead after 4 missed probes (60 s) */
      setsockopt(sock, IPPROTO_TCP, TCP_KEEPCNT, &v, sizeof v);
    }
#endif
  }
  if (options & SOCK_LISTEN) {
    /* Tris says this lets us grab the same port again next time */
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &parm, sizeof parm))
      debug2("net: setsock(): setsockopt() s %i level SOL_SOCKET optname SO_REUSEADDR error %s", sock, strerror(errno));
  }
  /* Yay async i/o ! */
  if ((sock != STDOUT) || backgrd) {
    egg_setnonblock(sock);
    fcntl(sock, F_SETFD, fcntl(sock, F_GETFD) | FD_CLOEXEC);
  }
}

int getsock(int af, int options)
{
  int sock = socket(af, SOCK_STREAM
#ifdef SOCK_CLOEXEC
                    | SOCK_CLOEXEC
#endif
                    , 0);

  if (sock >= 0)
    setsock(sock, options);
  else
    putlog(LOG_MISC, "*", "Warning: Can't create new socket: %s!",
           strerror(errno));
  return sock;
}

/* Done with a socket
 */
void killsock(int sock)
{
  struct threaddata *td = threaddata();

  /* Ignore invalid sockets.  */
  if (sock < 0)
    return;

  for (int i = 0; i < td->MAXSOCKS; i++) {
    if ((td->socklist[i].sock == sock) && !(td->socklist[i].flags & SOCK_UNUSED)) {
      if (!(td->socklist[i].flags & SOCK_TCL)) { /* nothing to free for tclsocks */
#ifdef TLS
        if (td->socklist[i].ssl) {
          /* Clear the FDE ssl pointer before op_close frees the FDE. */
          op_fde_t *F_ssl = op_get_fde(sock);
          if (F_ssl)
            op_fde_set_ssl_ptr(F_ssl, NULL);
          SSL_shutdown(td->socklist[i].ssl);
          op_free(SSL_get_app_data(td->socklist[i].ssl));
          SSL_free(td->socklist[i].ssl);
          td->socklist[i].ssl = NULL;
        }
#endif
        /* Deregister from commio BEFORE closing the fd. */
        {
          op_fde_t *F_del = op_get_fde(sock);
          if (F_del)
            op_close(F_del);
        }
        egg_closesocket(td->socklist[i].sock);

        op_linebuf_donebuf(&td->socklist[i].handler.sock.recvbuf);

        if (td->socklist[i].handler.sock.outbuf != NULL) {
          egg_mbuf_free(td->socklist[i].handler.sock.outbuf);
          td->socklist[i].handler.sock.outbuf = NULL;
        }
      }
      td->socklist[i].flags = SOCK_UNUSED;
      return;
    }
  }
  putlog(LOG_MISC, "*", "Warning: Attempt to kill un-allocated socket %d!", sock);
}

/* Done with a tcl socket
 *
 * killtclsock() can be called by Tcl threads
 */
void killtclsock(int sock)
{
  struct threaddata *td = threaddata();

  if (sock < 0)
    return;

  for (int i = 0; i < td->MAXSOCKS; i++) {
    if ((td->socklist[i].flags & SOCK_TCL) && td->socklist[i].sock == sock) {
      td->socklist[i].flags = SOCK_UNUSED;
      return;
    }
  }
}

/* Send connection request to proxy
 */
static int proxy_connect(int sock, sockname_t *addr)
{
  sockname_t name;
  char host[121], s[256];
  int port, proxy;
  struct threaddata *td = threaddata();

  if (!firewall[0])
    return -2;
#ifdef IPV6
  if (addr->family == AF_INET6) {
    putlog(LOG_MISC, "*", "Eggdrop doesn't support IPv6 connections "
           "through proxies yet.");
    return -1;
  }
#endif
  if (firewall[0] == '!') {
    proxy = PROXY_SUN;
    strlcpy(host, &firewall[1], sizeof host);
  } else {
    proxy = PROXY_SOCKS;
    strlcpy(host, firewall, sizeof(host));
  }
  port = ntohs(addr->addr.s4.sin_port);
  setsockname(&name, host, firewallport, 1);
  if (connect(sock, &name.addr.sa, name.addrlen) < 0 && errno != EINPROGRESS)
    return -1;
  if (proxy == PROXY_SOCKS) {
    for (int i = 0; i < td->MAXSOCKS; i++)
      if (!(socklist[i].flags & SOCK_UNUSED) && socklist[i].sock == sock)
        socklist[i].flags |= SOCK_PROXYWAIT;    /* drummer */
    memcpy(host, &addr->addr.s4.sin_addr.s_addr, 4);
    {
      op_strbuf_t _b;
      op_strbuf_printf(&_b, "\004\001%c%c%c%c%c%c%s", (port >> 8) & 0xFF,
                       port & 0xFF, host[0], host[1], host[2], host[3], botuser);
      strlcpy(s, op_strbuf_str(&_b), sizeof s);
      op_strbuf_free(&_b);
    }
    tputs(sock, s, strlen(botuser) + 9);        /* drummer */
  } else if (proxy == PROXY_SUN) {
    inet_ntop(AF_INET, &addr->addr.s4.sin_addr, host, sizeof host);
    {
      op_strbuf_t _b;
      op_strbuf_printf(&_b, "%s %d\n", host, port);
      strlcpy(s, op_strbuf_str(&_b), sizeof s);
      op_strbuf_free(&_b);
    }
    tputs(sock, s, strlen(s));  /* drummer */
  }
  return sock;
}

/* FIXME: if we can break compatibility for 1.9 or 2.0, we can replace this
 * workaround with an additional port parameter for functions in need
 */
static int get_port_from_addr(const sockname_t *addr)
{
#ifdef IPV6
  return ntohs((addr->family == AF_INET) ? addr->addr.s4.sin_port : addr->addr.s6.sin6_port);
#else
  return ntohs(addr->addr.s4.sin_port);
#endif
}

/* Starts a connection attempt through a socket
 *
 * The server address should be filled in addr by setsockname() or by the
 * non-blocking dns functions and setsnport().
 *
 * returns < 0 if connection refused:
 *   -1  strerror() type error
 */
int open_telnet_raw(int sock, sockname_t *addr)
{
  sockname_t name;
  socklen_t res_len;
  fd_set sockset;
  int rc, errno_tmp, res;
  struct threaddata *td = threaddata();

  int i = 0;
  for (; i < dcc_total; i++)
    if (dcc[i].sock == sock) { /* Got idx from sock ? */
#ifdef TLS
      debug5("net: open_telnet_raw(): idx %i host %s ip %s port %i ssl %i",
             i, dcc[i].host, iptostr(&addr->addr.sa), dcc[i].port, dcc[i].ssl);
#else
      debug4("net: open_telnet_raw(): idx %i host %s ip %s port %i",
             i, dcc[i].host, iptostr(&addr->addr.sa), dcc[i].port);
#endif
      break;
    }
  getvhost(&name, addr->family);
  if (bind(sock, &name.addr.sa, name.addrlen) < 0) {
    return -1;
  }
  for (int j = 0; j < td->MAXSOCKS; j++) {
    if (!(socklist[j].flags & SOCK_UNUSED) && (socklist[j].sock == sock))
      socklist[j].flags = (socklist[j].flags & ~SOCK_VIRTUAL) | SOCK_CONNECT;
  }
  if (addr->family == AF_INET && firewall[0])
    return proxy_connect(sock, addr);
  rc = connect(sock, &addr->addr.sa, addr->addrlen);
  /* To minimize a proven race condition, call ident here (especially when
   * rc < 0 and errno == EINPROGRESS)
   */
  if (dcc[i].status & STAT_SERV) {
    errno_tmp = errno;
    check_tcl_event("ident");
    errno = errno_tmp;
  }
  if (rc < 0) {
    if (errno == EINPROGRESS) {
      /*
       * Non-blocking connect is in progress.  Do a zero-timeout check
       * to catch an immediate rejection (e.g. ECONNREFUSED on loopback)
       * without blocking — longer waits are handled asynchronously by the
       * main event loop (sockread → SOCK_CONNECT → SO_ERROR check).
       */
      struct timeval zt = {0, 0};
      FD_ZERO(&sockset);
      FD_SET(sock, &sockset);
      if (select(sock + 1, NULL, &sockset, NULL, &zt) > 0) {
        res_len = sizeof(res);
        getsockopt(sock, SOL_SOCKET, SO_ERROR, &res, &res_len);
        if (res == ECONNREFUSED) {
          debug2("net: attempted socket connection refused: %s:%i",
                 iptostr(&addr->addr.sa), get_port_from_addr(addr));
          errno = res;
          return -4;
        }
        if (res != 0 && res != EINPROGRESS) {
          debug1("net: getsockopt error %d", res);
          errno = res;
          return -1;
        }
      }
      /* Still in progress — return sock and let sockread() finish it */
      return sock;
    }
    else {
      return -1;
    }
  }
  return sock;
}

/* Ordinary non-binary connection attempt
 * Return values:
 *   >=0: connect successful, returned is the socket number
 *    -1: look at errno or use strerror()
 *    -2: lookup failed or server is not a valid IP string
 *    -3: could not allocate socket
 *    -4: connection failed
 */
int open_telnet(int idx, char *server, int port)
{
  int ret;

  ret = setsockname(&dcc[idx].sockname, server, port, 1);
  if (ret == AF_UNSPEC)
    return -2;
  dcc[idx].port = port;
  dcc[idx].sock = getsock(ret, 0);
  if (dcc[idx].sock < 0)
    return -3;
  ret = open_telnet_raw(dcc[idx].sock, &dcc[idx].sockname);
  if (ret < 0) {
    if (findidx(dcc[idx].sock) >= 0) {
      killsock(dcc[idx].sock);
    }
  }
  return ret;
}

/* Returns a socket number for a listening socket that will accept any
 * connection on the given address. The address can be filled in by
 * setsockname().
 */
int open_address_listen(sockname_t *addr)
{
  int sock = 0;

  sock = getsock(addr->family, SOCK_LISTEN);
  if (sock < 0)
    return -1;
#if defined IPV6 && IPV6_V6ONLY
  if (addr->family == AF_INET6) {
    int on = 0;
    setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, (char *) &on, sizeof(on));
  }
#endif
  if (bind(sock, &addr->addr.sa, addr->addrlen) < 0) {
    killsock(sock);
    return -2;
  }

  if (getsockname(sock, &addr->addr.sa, &addr->addrlen) < 0) {
    killsock(sock);
    return -1;
  }
  if (listen(sock, 1) < 0) {
    killsock(sock);
    return -1;
  }

  return sock;
}

/* Returns a socket number for a listening socket that will accept any
 * connection -- port # is returned in port
 */
int open_listen(int *port)
{
  int sock;
  sockname_t name;

  (void) setsockname(&name, listen_ip, *port, 1);
  sock = open_address_listen(&name);
  if (name.addr.sa.sa_family == AF_INET)
    *port = ntohs(name.addr.s4.sin_port);
#ifdef IPV6
  else
    *port = ntohs(name.addr.s6.sin6_port);
#endif
  return sock;
}

/* Short routine to answer a connect received on a listening socket.
 * Returned is the new socket.
 * If port is not NULL, it points to an integer to hold the port number
 * of the caller.
 */
int answer(int sock, sockname_t *caller, uint16_t *port, int binary)
{
  int new_sock;
  caller->addrlen = sizeof(caller->addr);
  /*
   * accept4() atomically sets SOCK_NONBLOCK | SOCK_CLOEXEC on the new
   * socket, avoiding two racy fcntl() calls after plain accept(2).
   * setsock() will still configure keepalive/linger/TCP_NODELAY etc.,
   * but the nonblock + cloexec flags are already in place before any
   * other thread can fork or exec.
   */
#if defined(HAVE_ACCEPT4) && defined(SOCK_NONBLOCK) && defined(SOCK_CLOEXEC)
  new_sock = accept4(sock, &caller->addr.sa, &caller->addrlen,
                     SOCK_NONBLOCK | SOCK_CLOEXEC);
#else
  new_sock = accept(sock, &caller->addr.sa, &caller->addrlen);
#endif

  if (new_sock < 0)
    return -1;

  caller->family = caller->addr.sa.sa_family;
  if (port) {
    if (caller->family == AF_INET)
      *port = ntohs(caller->addr.s4.sin_port);
#ifdef IPV6
    else
      *port = ntohs(caller->addr.s6.sin6_port);
#endif
  }
  setsock(new_sock, (binary ? SOCK_BINARY : 0));
  return new_sock;
}

int getdccaddr(sockname_t *addr, char *s, size_t l)
{
  return getdccfamilyaddr(addr, s, l, AF_UNSPEC);
}

/* Get DCC compatible address for a client to connect (e.g. 1660944385)
 * If addr is not NULL, it should point to the listening socket's address.
 * Otherwise, this function will try to figure out the public address of the
 * machine, using listen_ip and nat_ip. If restrict_af is set, it will limit
 * the possible IPs to the specified family. The result is a string usable
 * for DCC requests
 */
int getdccfamilyaddr(sockname_t *addr, char *s, size_t l, int restrict_af)
{
  char h[256];
  sockname_t name, *r = &name;
  int af = AF_UNSPEC;
#ifdef IPV6
  IP ip = 0;
#endif

  if (addr)
    r = addr;
  else
    setsockname(r, listen_ip, 0, 1);
  if (
#ifdef IPV6
      ((r->family == AF_INET6) &&
      IN6_IS_ADDR_UNSPECIFIED(&r->addr.s6.sin6_addr)) ||
#endif
      (r->family == AF_INET && !r->addr.s4.sin_addr.s_addr)) {
      /* We can't send :: or 0.0.0.0 for dcc, so try
         to figure out some real address */
#ifdef IPV6
     /* If it's listening on an IPv6 :: address,
        try using vhost6 as the source IP */
    if (r->family == AF_INET6 && restrict_af != AF_INET) {
      if (inet_pton(AF_INET6, vhost6, &r->addr.s6.sin6_addr) != 1) {
        r = &name;
        gethostname(h, sizeof h);
        setsockname(r, h, 0, 1);
        if (r->family == AF_INET) {
        /* setsockname tries to resolve both ipv4 and ipv6. ipv4 dns
           resolution comes later in precedence, so if we get an ipv4
           back, reset it to the original addr struct and try
           again */
          if (addr) {
            r = addr;
          } else {
            setsockname(r, listen_ip, 0, 1);
          }
        } else
          af = AF_INET6;
      }
    }
#endif
     /* If IPv6 didn't work or is disabled, or it's listening on an IPv4
        0.0.0.0 address, try using vhost4 as the source */
    if (!af
#ifdef IPV6
        && restrict_af != AF_INET6
#endif
       ) {
      if (inet_pton(AF_INET, vhost, &r->addr.s4.sin_addr) != 1) {
        /* And if THAT fails, try DNS resolution of hostname */
        r = &name;
        gethostname(h, sizeof h);
        setsockname(r, h, 0, 1);
      }
    }
  }

  if (
#ifdef IPV6
      ((r->family == AF_INET6) &&
      IN6_IS_ADDR_UNSPECIFIED(&r->addr.s6.sin6_addr)) ||
      ((r->family == AF_INET6) && (restrict_af == AF_INET)) ||
      ((r->family == AF_INET) && (restrict_af == AF_INET6)) ||
#endif
      (!nat_ip_string[0] && (r->family == AF_INET) && !r->addr.s4.sin_addr.s_addr))
    return 0;

#ifdef IPV6
  if (r->family == AF_INET6) {
    if (IN6_IS_ADDR_V4MAPPED(&r->addr.s6.sin6_addr) ||
        IN6_IS_ADDR_UNSPECIFIED(&r->addr.s6.sin6_addr)) {
      if (*nat_ip_string)
        strlcpy(s, nat_ip_string, l);
      else {
        memcpy(&ip, r->addr.s6.sin6_addr.s6_addr + 12, sizeof ip);
        {
          op_strbuf_t _b;
          op_strbuf_printf(&_b, "%" PRIu32, ntohl(ip));
          strlcpy(s, op_strbuf_str(&_b), l);
          op_strbuf_free(&_b);
        }
      }
    } else
      inet_ntop(AF_INET6, &r->addr.s6.sin6_addr, s, l);
  } else
#endif
  {
    if (*nat_ip_string)
      strlcpy(s, nat_ip_string, l);
    else
      {
        op_strbuf_t _b;
        op_strbuf_printf(&_b, "%" PRIu32, ntohl(r->addr.s4.sin_addr.s_addr));
        strlcpy(s, op_strbuf_str(&_b), l);
        op_strbuf_free(&_b);
      }
  }
  return 1;
}

/* Builds the fd_sets for select(). Eggdrop only cares about readable
 * sockets, but tcl also cares for writable/exceptions.
 * preparefdset() can be called by Tcl Threads
 */
static int preparefdset(fd_set *fds, sock_list *slist, int slistmax, int tclonly, int tclmask)
{
  int fd, maxfd = -1;

  FD_ZERO(fds);
  for (int i = 0; i < slistmax; i++) {
    if (!(slist[i].flags & (SOCK_UNUSED | SOCK_VIRTUAL))) {
      if ((slist[i].sock == STDOUT) && !backgrd)
        fd = STDIN;
      else
        fd = slist[i].sock;
      /*
       * Looks like that having more than a call, in the same
       * program, to the FD_SET macro, triggers a bug in gcc.
       * SIGBUS crashing binaries used to be produced on a number
       * (prolly all?) of 64 bits architectures.
       * Make your best to avoid to make it happen again.
       *
       * ITE
       */
      if (slist[i].flags & SOCK_TCL) {
        if (!(slist[i].handler.tclsock.mask & tclmask))
          continue;
      } else if (tclonly)
        continue;
      if (fd > maxfd)
        maxfd = fd;
      FD_SET(fd, fds);
    }
  }
  return maxfd;
}

/* A safer version of write() that deals with partial writes. */
void safe_write(int fd, const void *buf, size_t count)
{
  const char *bytes = buf;
  ssize_t ret;
  static int inhere = 0;

  do {
    if ((ret = write(fd, bytes, count)) == -1 && errno != EINTR) {
      if (!inhere) {
        inhere = 1;
        putlog(LOG_MISC, "*", "Unexpected write() failure on attempt to write %zd bytes to fd %d: %s.", count, fd, strerror(errno));
        inhere = 0;
      }
      break;
    }
  } while ((bytes += ret, count -= ret));
}

/* Attempts to read from all sockets in slist (upper array boundary slistmax-1)
 * fills s with up to 511 bytes if available, and returns the array index
 * Also calls all handler procs for Tcl sockets
 * sockread() can be called by Tcl threads
 *
 *              on EOF:  returns -1, with socket in len
 *     on socket error:  returns -2
 * if nothing is ready:  returns -3
 *    tcl sockets busy:  returns -5
 */
int sockread(char *s, int *len, sock_list *slist, int slistmax, int tclonly)
{
  struct timeval t;
  fd_set fdr, fdw, fde;
  int x, maxfd_r, maxfd_w, maxfd_e;
  int fd;
  int grab = READMAX, tclsock = -1, events = 0;
  struct threaddata *td = threaddata();
  int maxfd;
#ifdef EGG_TDNS
  struct dns_thread_node *dtn, *dtn_prev;
  void *res;
#endif

  t.tv_sec = td->blocktime.tv_sec;
  t.tv_usec = td->blocktime.tv_usec;

  if (!tclonly) {
    /* --- TCL + TDNS sockets: quick non-blocking select() --- */
    FD_ZERO(&fdr); FD_ZERO(&fdw); FD_ZERO(&fde);
    maxfd_r = maxfd_w = maxfd_e = -1;

    for (int i = 0; i < slistmax; i++) {
      if (!(slist[i].flags & (SOCK_UNUSED | SOCK_VIRTUAL)) &&
          (slist[i].flags & SOCK_TCL)) {
        fd = slist[i].sock;
        if (slist[i].handler.tclsock.mask & TCL_READABLE) {
          FD_SET(fd, &fdr);
          if (fd > maxfd_r) maxfd_r = fd;
        }
        if (slist[i].handler.tclsock.mask & TCL_WRITABLE) {
          FD_SET(fd, &fdw);
          if (fd > maxfd_w) maxfd_w = fd;
        }
        if (slist[i].handler.tclsock.mask & TCL_EXCEPTION) {
          FD_SET(fd, &fde);
          if (fd > maxfd_e) maxfd_e = fd;
        }
      }
    }
#ifdef EGG_TDNS
    for (dtn = dns_thread_head->next; dtn; dtn = dtn->next) {
      fd = dtn->fildes[0];
      FD_SET(fd, &fdr);
      if (fd > maxfd_r) maxfd_r = fd;
    }
#endif
    maxfd = maxfd_r > maxfd_w ? maxfd_r : maxfd_w;
    if (maxfd_e > maxfd) maxfd = maxfd_e;
    if (maxfd >= 0) {
      struct timeval zt = {0, 0};
      select(maxfd + 1,
             maxfd_r >= 0 ? &fdr : NULL,
             maxfd_w >= 0 ? &fdw : NULL,
             maxfd_e >= 0 ? &fde : NULL,
             &zt);
    }

    /* --- Main socket wait via commio --- */
    {
      int timeout_ms = (int)(t.tv_sec * 1000 + (int)(t.tv_usec / 1000));
      call_hook(HOOK_PRE_SELECT);
      x = op_select((long)timeout_ms);
      call_hook(HOOK_POST_SELECT);
      if (x < 0)
        x = (errno == EINTR) ? 0 : -1;
    }

#ifdef EGG_TDNS
    /* Re-check TDNS pipes after the commio wait */
    {
      fd_set tdns_fdr;
      int tdns_maxfd = -1;
      FD_ZERO(&tdns_fdr);
      for (dtn = dns_thread_head->next; dtn; dtn = dtn->next) {
        int tfd = dtn->fildes[0];
        FD_SET(tfd, &tdns_fdr);
        if (tfd > tdns_maxfd) tdns_maxfd = tfd;
      }
      if (tdns_maxfd >= 0) {
        struct timeval zt = {0, 0};
        if (select(tdns_maxfd + 1, &tdns_fdr, NULL, NULL, &zt) > 0) {
          for (dtn = dns_thread_head->next; dtn; dtn = dtn->next) {
            if (FD_ISSET(dtn->fildes[0], &tdns_fdr))
              FD_SET(dtn->fildes[0], &fdr);
          }
        }
      }
    }
#endif

    if (x == -1) return -2;

    /* Count any TCL/TDNS events ready from the earlier select() */
    {
      int tcl_ready = 0;
      for (int i = 0; i < slistmax && !tcl_ready; i++) {
        if (!(slist[i].flags & SOCK_UNUSED) && (slist[i].flags & SOCK_TCL)) {
          int ev2 = 0;
          if (FD_ISSET(slist[i].sock, &fdr)) ev2 |= TCL_READABLE;
          if (FD_ISSET(slist[i].sock, &fdw)) ev2 |= TCL_WRITABLE;
          if (FD_ISSET(slist[i].sock, &fde)) ev2 |= TCL_EXCEPTION;
          if (ev2 & slist[i].handler.tclsock.mask) tcl_ready = 1;
        }
      }
#ifdef EGG_TDNS
      if (!tcl_ready) {
        for (dtn = dns_thread_head->next; dtn && !tcl_ready; dtn = dtn->next)
          if (FD_ISSET(dtn->fildes[0], &fdr)) tcl_ready = 1;
      }
#endif
      /* When commio reports no events (x==0) but a TLS handshake is in
       * progress, do NOT return idle — allow the dispatch loop to run so
       * SSL_read() can make incremental progress on the handshake. */
#ifdef TLS
      {
        int tls_pending = 0;
        if (x == 0 && !tcl_ready) {
          for (int i = 0; i < slistmax; i++) {
            if (!(slist[i].flags & (SOCK_UNUSED | SOCK_TCL)) && slist[i].ssl) {
              if (!SSL_is_init_finished(slist[i].ssl)) {
                tls_pending = 1;
              } else if (slist[i].flags & SOCK_CONNECT) {
                slist[i].commio_ready = 1;
                x = 1;
              }
            }
          }
        }
        if (x == 0 && !tcl_ready && !tls_pending)
          return -3; /* idle */
        if (x > 0 || tcl_ready || tls_pending) x = 1;
      }
#else
      if (x == 0 && !tcl_ready)
        return -3; /* idle */
      if (x > 0 || tcl_ready) x = 1;
#endif
    }
  } else {
    /* tclonly: select() fallback for TCL sockets only */
    maxfd_r = preparefdset(&fdr, slist, slistmax, tclonly, TCL_READABLE);
#ifdef EGG_TDNS
    for (dtn = dns_thread_head->next; dtn; dtn = dtn->next) {
      int dns_fd = dtn->fildes[0];
      FD_SET(dns_fd, &fdr);
      if (dns_fd > maxfd_r) maxfd_r = dns_fd;
    }
#endif
    maxfd_w = preparefdset(&fdw, slist, slistmax, 1, TCL_WRITABLE);
    maxfd_e = preparefdset(&fde, slist, slistmax, 1, TCL_EXCEPTION);
    maxfd = maxfd_r > maxfd_w ? maxfd_r : maxfd_w;
    if (maxfd_e > maxfd) maxfd = maxfd_e;

    call_hook(HOOK_PRE_SELECT);
    x = select((SELECT_TYPE_ARG1) maxfd + 1,
               SELECT_TYPE_ARG234 (maxfd_r >= 0 ? &fdr : NULL),
               SELECT_TYPE_ARG234 (maxfd_w >= 0 ? &fdw : NULL),
               SELECT_TYPE_ARG234 (maxfd_e >= 0 ? &fde : NULL),
               SELECT_TYPE_ARG5 &t);
    call_hook(HOOK_POST_SELECT);
    if (x == -1)
      return -2;
    if (x == 0)
      return -3;
  }

  /* --- Dispatch loop --- */
  for (int i = 0; i < slistmax; i++) {
    if (!tclonly && ((!(slist[i].flags & (SOCK_UNUSED | SOCK_TCL))) &&
        ((slist[i].commio_ready) ||
#ifdef TLS
        (slist[i].ssl && !SSL_is_init_finished(slist[i].ssl)) ||
#endif
        ((slist[i].sock == STDOUT) && (!backgrd) &&
         (FD_ISSET(STDIN, &fdr)))))) {
      slist[i].commio_ready = 0;
      if (slist[i].flags & (SOCK_LISTEN | SOCK_CONNECT)) {
        if (slist[i].flags & SOCK_PROXYWAIT)
          grab = 10;
#ifdef TLS
        else if (!(slist[i].flags & SOCK_STRONGCONN) &&
                 (!(slist[i].ssl) || SSL_is_init_finished(slist[i].ssl))) {
#else
        else if (!(slist[i].flags & SOCK_STRONGCONN)) {
#endif
          debug1("net: connect! sock %d", slist[i].sock);
          s[0] = 0;
          *len = 0;
          return i;
        }
      } else if (slist[i].flags & SOCK_PASS) {
        s[0] = 0;
        *len = 0;
        return i;
      }
      errno = 0;
      if ((slist[i].sock == STDOUT) && !backgrd)
        x = read(STDIN, s, grab);
      else
#ifdef TLS
      {
        if (slist[i].ssl) {
          op_fde_t *F = op_get_fde(slist[i].sock);
          x = (int)op_ssl_read(F, s, grab);
          if (x == 0) {
            /* Clean TLS shutdown (close_notify) */
            *len = slist[i].sock;
            slist[i].flags &= ~SOCK_CONNECT;
            debug1("net: op_ssl_read(): received shutdown sock %i", slist[i].sock);
            return -1;
          } else if (x == OP_RW_SSL_NEED_READ || x == OP_RW_SSL_NEED_WRITE) {
            errno = EAGAIN;
            x = -1;
          } else if (x == OP_RW_IO_ERROR) {
            debug0("net: sockread(): op_ssl_read() I/O error");
            putlog(LOG_MISC, "*", "NET: SSL read failed. Non-SSL connection?");
            x = -1;
          } else if (x < 0) {
            debug1("net: sockread(): op_ssl_read() error %d", x);
            putlog(LOG_MISC, "*", "NET: SSL read error.");
            x = -1;
          }
        } else
          x = read(slist[i].sock, s, grab);
      }
#else
        x = read(slist[i].sock, s, grab);
#endif
      if (x <= 0) {           /* eof */
        if (errno != EAGAIN) {
          *len = slist[i].sock;
          slist[i].flags &= ~SOCK_CONNECT;
          debug1("net: eof!(read) socket %d", slist[i].sock);
          return -1;
        } else {
          debug3("sockread EAGAIN: %d %d (%s)", slist[i].sock, errno,
                 strerror(errno));
          continue;           /* EAGAIN */
        }
      }
#ifdef TLS
      if (socklist[i].flags & SOCK_WS)
        webui_unframe(slist[i].sock, s, &x);
#endif /* TLS */
      s[x] = 0;
      *len = x;
      if (slist[i].flags & SOCK_PROXYWAIT) {
        debug2("net: socket: %d proxy errno: %d", slist[i].sock, s[1]);
        slist[i].flags &= ~(SOCK_CONNECT | SOCK_PROXYWAIT);
        switch (s[1]) {
        case 90:             /* Success */
          s[0] = 0;
          *len = 0;
          return i;
        case 91:             /* Failed */
          errno = ECONNREFUSED;
          break;
        case 92:             /* No identd */
        case 93:             /* Identd said wrong username */
          errno = ENETUNREACH;
          break;
        }
        *len = slist[i].sock;
        return -1;
      }
      return i;
    } else if (tclsock == -1 && (slist[i].flags & SOCK_TCL)) {
      events = FD_ISSET(slist[i].sock, &fdr) ? TCL_READABLE : 0;
      events |= FD_ISSET(slist[i].sock, &fdw) ? TCL_WRITABLE : 0;
      events |= FD_ISSET(slist[i].sock, &fde) ? TCL_EXCEPTION : 0;
      events &= slist[i].handler.tclsock.mask;
      if (events)
        tclsock = i;
    }
  }
  if (!tclonly) {
    s[0] = 0;
    *len = 0;
  }
  if (tclsock != -1) {
    (*slist[tclsock].handler.tclsock.proc)(slist[tclsock].handler.tclsock.cd,
                                           events);
    return -5;
  }
#ifdef EGG_TDNS
  dtn_prev = dns_thread_head;
  for (dtn = dtn_prev->next; dtn; dtn = dtn->next) {
    pthread_mutex_lock(&dtn->mutex);
    if (*dtn->strerror)
      debug2("%s: hostname %s", dtn->strerror, dtn->host);
    fd = dtn->fildes[0];
    if (FD_ISSET(fd, &fdr)) {
      if (dtn->type == DTN_TYPE_HOSTBYIP)
        call_hostbyip(&dtn->addr, dtn->host, !*dtn->strerror);
      else
        call_ipbyhost(dtn->host, &dtn->addr, !*dtn->strerror);
      pthread_mutex_unlock(&dtn->mutex);
      close(fd);
      if (pthread_join(dtn->thread_id, &res))
        putlog(LOG_MISC, "*", "sockread(): pthread_join(): error = %s", strerror(errno));
      dtn_prev->next = dtn->next;
      op_free(dtn);
      dtn = dtn_prev;
    } else
      pthread_mutex_unlock(&dtn->mutex);
    dtn_prev = dtn;
  }
#endif
  return -3;
}

/* sockgets: buffer and read from sockets
 *
 * Attempts to read from all registered sockets for up to one second.  if
 * after one second, no complete data has been received from any of the
 * sockets, 's' will be empty, 'len' will be 0, and sockgets will return -3.
 * if there is returnable data received from a socket, the data will be
 * in 's' (null-terminated if non-binary), the length will be returned
 * in len, and the socket number will be returned.
 * normal sockets have their input buffered, and each call to sockgets
 * will return one line terminated with a '\n'.  binary sockets are not
 * buffered and return whatever coems in as soon as it arrives.
 * listening sockets will return an empty string when a connection comes in.
 * connecting sockets will return an empty string on a successful connect,
 * or EOF on a failed connect.
 * if an EOF is detected from any of the sockets, that socket number will be
 * put in len, and -1 will be returned.
 * the maximum length of the string returned is 512 (including null)
 *
 * Returns -4 if we handled something that shouldn't be handled by the
 * dcc functions. Simply ignore it.
 * Returns -5 if tcl sockets are busy but not eggdrop sockets.
 */
int sockgets(char *s, int *len)
{
  char xx[READMAX + 2];
  int ret, got;
  struct threaddata *td = threaddata();

  for (int i = 0; i < td->MAXSOCKS; i++) {
    if (socklist[i].flags & (SOCK_UNUSED | SOCK_TCL | SOCK_BUFFER))
      continue;

    if (op_linebuf_len(&socklist[i].handler.sock.recvbuf) > 0) {
      if (!(socklist[i].flags & SOCK_BINARY)) {
        /* Text socket: extract the next complete CRLF-terminated line. */
        got = op_linebuf_get(&socklist[i].handler.sock.recvbuf, s,
                             READMAX + 1, 0, 0);
        if (got > 0) {
          *len = got;
          return socklist[i].sock;
        }
      } else {
        /* Binary socket with buffered data (was SOCK_BUFFER before).
         * Return one partial chunk via op_linebuf_get in raw+partial mode. */
        got = op_linebuf_get(&socklist[i].handler.sock.recvbuf, s,
                             READMAX + 1, 1, 1);
        if (got > 0) {
          *len = got;
          return socklist[i].sock;
        }
      }
    }

    /* Check for sockets that EOF'd during write */
    if (!(socklist[i].flags & SOCK_UNUSED) && (socklist[i].flags & SOCK_EOFD)) {
      s[0] = 0;
      *len = socklist[i].sock;
      return -1;
    }
  }

  /* No pent-up data — block in sockread(). */
  *len = 0;
  ret = sockread(xx, len, socklist, td->MAXSOCKS, 0);
  if (ret < 0) {
    s[0] = 0;
    return ret;
  }
  /* sockread can return binary data while socket still has connectflag, process first */
  if (socklist[ret].flags & SOCK_BINARY && *len > 0) {
    socklist[ret].flags &= ~SOCK_CONNECT;
    memcpy(s, xx, *len);
    return socklist[ret].sock;
  }
  /* Binary, listening and passed on sockets don't get buffered. */
  if (socklist[ret].flags & SOCK_CONNECT) {
    if (socklist[ret].flags & SOCK_STRONGCONN) {
      socklist[ret].flags &= ~SOCK_STRONGCONN;
      /* Stash initial connect data into recvbuf (raw mode preserves bytes). */
      if (*len > 0)
        op_linebuf_parse(&socklist[ret].handler.sock.recvbuf, xx,
                         (ssize_t)*len, LINEBUF_RAW);
    }
    socklist[ret].flags &= ~SOCK_CONNECT;
    s[0] = 0;
    return socklist[ret].sock;
  }
  if (socklist[ret].flags & (SOCK_LISTEN | SOCK_PASS | SOCK_TCL)) {
    s[0] = 0; /* for the dcc traffic counters in the mainloop */
    return socklist[ret].sock;
  }
  if (socklist[ret].flags & SOCK_BUFFER) {
    /* Accumulate data without processing (raw mode). */
    op_linebuf_parse(&socklist[ret].handler.sock.recvbuf, xx,
                     (ssize_t)*len, LINEBUF_RAW);
    return -4;                  /* Ignore this one. */
  }
  /* Feed new data into linebuf for CRLF framing. */
  op_linebuf_parse(&socklist[ret].handler.sock.recvbuf, xx,
                   (ssize_t)*len, LINEBUF_PARSED);

  /* Try to extract a complete line. */
  got = op_linebuf_get(&socklist[ret].handler.sock.recvbuf, s,
                       READMAX + 1, 0, 0);
  if (got > 0) {
    *len = got;
    return socklist[ret].sock;
  }

  /* No complete line yet — check for overlong partial that needs flushing. */
  if (op_linebuf_len(&socklist[ret].handler.sock.recvbuf) >= READMAX) {
    got = op_linebuf_get(&socklist[ret].handler.sock.recvbuf, s,
                         READMAX + 1, 1, 0);
    if (got > 0) {
      *len = got;
      return socklist[ret].sock;
    }
  }

  s[0] = 0;
  *len = 0;
  return -3;
}

/* Dump something to a socket
 */
void tputs(int z, char *s, unsigned int len)
{
  int x, idx;
  char *s2 = 0;
  static int inhere = 0;
  struct threaddata *td = threaddata();

  if (z < 0) /* um... HELLO?! sanity check please! */
    return;

  if (((z == STDOUT) || (z == STDERR)) && (!backgrd || use_stderr)) {
    safe_write(z, s, len);
    return;
  }

  for (int i = 0; i < td->MAXSOCKS; i++) {
    if (!(socklist[i].flags & SOCK_UNUSED) && (socklist[i].sock == z)) {
      /* O(1) traffic accounting via sock→dcc map */
      idx = findanyidx(z);
      if (idx >= 0 && dcc[idx].type && dcc[idx].type->name) {
        if (!strncmp(dcc[idx].type->name, "BOT", 3))
          atomic_fetch_add_explicit(&otraffic_bn_today, (uint64_t)len, memory_order_relaxed);
        else if (!strcmp(dcc[idx].type->name, "SERVER"))
          atomic_fetch_add_explicit(&otraffic_irc_today, (uint64_t)len, memory_order_relaxed);
        else if (!strncmp(dcc[idx].type->name, "CHAT", 4))
          atomic_fetch_add_explicit(&otraffic_dcc_today, (uint64_t)len, memory_order_relaxed);
        else if (!strncmp(dcc[idx].type->name, "FILES", 5))
          atomic_fetch_add_explicit(&otraffic_filesys_today, (uint64_t)len, memory_order_relaxed);
        else if (!strcmp(dcc[idx].type->name, "SEND"))
          atomic_fetch_add_explicit(&otraffic_trans_today, (uint64_t)len, memory_order_relaxed);
        else if (!strcmp(dcc[idx].type->name, "FORK_SEND"))
          atomic_fetch_add_explicit(&otraffic_trans_today, (uint64_t)len, memory_order_relaxed);
        else if (!strncmp(dcc[idx].type->name, "GET", 3))
          atomic_fetch_add_explicit(&otraffic_trans_today, (uint64_t)len, memory_order_relaxed);
        else
          atomic_fetch_add_explicit(&otraffic_unknown_today, (uint64_t)len, memory_order_relaxed);
      }

      if (socklist[i].handler.sock.outbuf != NULL) {
        /* Already queueing: append to ring buffer (grows if needed). */
        egg_mbuf_append_grow(socklist[i].handler.sock.outbuf, s, len);
        return;
      }
#ifdef TLS
      if (!(socklist[i].flags & SOCK_WS))
        s2 = s;
      else
        len = webui_frame(&s2, s, len);
      if (socklist[i].ssl) {
        op_fde_t *F = op_get_fde(socklist[i].sock);
        x = (int)op_ssl_write(F, s2, len);
        if (x == OP_RW_SSL_NEED_WRITE || x == OP_RW_SSL_NEED_READ) {
          errno = EAGAIN;
          x = -1;
        } else if (x < 0) {
          if (!inhere) {
            inhere = 1;
            debug1("tputs(): op_ssl_write() error %d", x);
            inhere = 0;
          }
          x = -1;
        }
      } else /* not ssl, use regular write() */
#else
      s2 = s;
#endif /* TLS */
      /* Try. */
      x = write(z, s2, len);
      if (x == -1)
        x = 0;
      if (x < len) {
        /* Socket is full, queue the remainder in a ring buffer */
        size_t rem = len - x;
        size_t initcap = rem < 512 ? 512 : rem;
        socklist[i].handler.sock.outbuf = egg_mbuf_alloc(initcap);
        if (socklist[i].handler.sock.outbuf)
          egg_mbuf_append(socklist[i].handler.sock.outbuf, &s2[x], rem);
      }
      return;
    }
  }
  /* Make sure we don't cause a crash by looping here */
  if (!inhere) {
    inhere = 1;

    putlog(LOG_MISC, "*", "!!! writing to nonexistent socket: %d", z);
    putlog(LOG_MISC, "*", "!-> '%.*s'", (int)(len > 0 ? len - 1 : 0), s);

    inhere = 0;
  }
}

/* tputs might queue data for sockets, let's dump as much of it as
 * possible.
 *
 * Uses commio's write-readiness detection to check which sockets are
 * ready for writing, then drains their outbuf.
 */
void dequeue_sockets(void)
{
  int x;
  struct threaddata *td = threaddata();

  /* Arm WRITE interest on sockets with pending outbufs, do a zero-timeout
   * poll to check write-readiness, then disarm to avoid spinning. */
  {
    int any_pending = 0;
    for (int j = 0; j < td->MAXSOCKS; j++) {
      if (!(socklist[j].flags & (SOCK_UNUSED | SOCK_TCL)) &&
          socklist[j].handler.sock.outbuf != NULL
#ifdef TLS
          && !(socklist[j].ssl && !SSL_is_init_finished(socklist[j].ssl))
#endif
         ) {
        op_fde_t *F = op_get_fde(socklist[j].sock);
        if (F) {
          socklist[j].commio_ready = 0;
          op_setselect(F, OP_SELECT_WRITE, commio_write_cb,
                       (void *)(intptr_t)j);
          any_pending = 1;
        }
      }
    }
    if (any_pending) {
      op_select(0);
      for (int j = 0; j < td->MAXSOCKS; j++) {
        if (!(socklist[j].flags & (SOCK_UNUSED | SOCK_TCL)) &&
            socklist[j].handler.sock.outbuf != NULL &&
            !(socklist[j].flags & SOCK_CONNECT)) {
          op_fde_t *F = op_get_fde(socklist[j].sock);
          if (F)
            op_setselect(F, OP_SELECT_WRITE, NULL, NULL);
        }
      }
    }
  }

  for (int i = 0; i < td->MAXSOCKS; i++) {
    if (!(socklist[i].flags & (SOCK_UNUSED | SOCK_TCL)) &&
        (socklist[i].handler.sock.outbuf != NULL) && socklist[i].commio_ready) {
      socklist[i].commio_ready = 0;
      /* Drain outbuf ring buffer.
       * Use writev() to send both the head and (optional) wrapped tail
       * chunk in a single syscall, avoiding MSG_MORE + second write(). */
      {
        egg_mbuf_t *mb = socklist[i].handler.sock.outbuf;
        char  *p1, *p2;
        size_t c1,  c2;

        egg_mbuf_peek2(mb, &p1, &c1, &p2, &c2);
        errno = 0;
#ifdef TLS
        if (socklist[i].ssl) {
          op_fde_t *F = op_get_fde(socklist[i].sock);
          x = (int)op_ssl_write(F, p1, c1);
          if (x == OP_RW_SSL_NEED_WRITE || x == OP_RW_SSL_NEED_READ) {
            errno = EAGAIN;
            x = -1;
          } else if (x < 0) {
            debug1("dequeue_sockets(): op_ssl_write() error %d", x);
            x = -1;
          }
        } else
#endif
        if (c2 > 0) {
          struct iovec iov[2];
          iov[0].iov_base = p1;
          iov[0].iov_len  = c1;
          iov[1].iov_base = p2;
          iov[1].iov_len  = c2;
          x = (int)writev(socklist[i].sock, iov, 2);
        } else {
          x = write(socklist[i].sock, p1, c1);
        }
        if ((x < 0) && (errno != EAGAIN)
#ifdef EBADSLT
            && (errno != EBADSLT)
#endif
#ifdef ENOTCONN
            && (errno != ENOTCONN)
#endif
          ) {
          debug3("net: eof!(write) socket %d (%s,%d)", socklist[i].sock,
                 strerror(errno), errno);
          socklist[i].flags |= SOCK_EOFD;
        } else if (x > 0) {
          egg_mbuf_consume(mb, (size_t)x);
          if (egg_mbuf_len(mb) == 0) {
            egg_mbuf_free(mb);
            socklist[i].handler.sock.outbuf = NULL;
          }
        } else {
          debug3("dequeue_sockets(): errno = %d (%s) on %d", errno,
                 strerror(errno), socklist[i].sock);
        }
      }
      if (!socklist[i].handler.sock.outbuf) {
        int idx = findanyidx(socklist[i].sock);

        if (idx > 0 && dcc[idx].type && dcc[idx].type->outdone)
          dcc[idx].type->outdone(idx);
      }
    }
  }
}


/*
 *      Debugging stuff
 */

void tell_netdebug(int idx)
{
  struct threaddata *td = threaddata();

  dprintf(idx, "Open sockets:");
  for (int i = 0; i < td->MAXSOCKS; i++) {
    if (!(socklist[i].flags & SOCK_UNUSED)) {
      op_strbuf_t s;
      op_strbuf_printf(&s, " %s", int_to_base10(socklist[i].sock));
      if (socklist[i].flags & SOCK_BINARY)
        op_strbuf_append_cstr(&s, " (binary)");
      if (socklist[i].flags & SOCK_LISTEN)
        op_strbuf_append_cstr(&s, " (listen)");
      if (socklist[i].flags & SOCK_PASS)
        op_strbuf_append_cstr(&s, " (passed on)");
      if (socklist[i].flags & SOCK_CONNECT)
        op_strbuf_append_cstr(&s, " (connecting)");
      if (socklist[i].flags & SOCK_STRONGCONN)
        op_strbuf_append_cstr(&s, " (strong)");
      if (socklist[i].flags & SOCK_NONSOCK)
        op_strbuf_append_cstr(&s, " (file)");
#ifdef TLS
      if (socklist[i].ssl)
        op_strbuf_append_cstr(&s, " (TLS)");
#endif
      if (socklist[i].flags & SOCK_TCL)
        op_strbuf_append_cstr(&s, " (tcl)");
      if (!(socklist[i].flags & SOCK_TCL)) {
        if (op_linebuf_len(&socklist[i].handler.sock.recvbuf) > 0)
          op_strbuf_appendf(&s, " (inbuf: %04zX)",
                            op_linebuf_len(&socklist[i].handler.sock.recvbuf));
        if (socklist[i].handler.sock.outbuf != NULL)
          op_strbuf_appendf(&s, " (outbuf: %06zX)",
                            egg_mbuf_len(socklist[i].handler.sock.outbuf));
      }
      op_strbuf_append_cstr(&s, ",");
      dprintf(idx, "%s", op_strbuf_str(&s));
      op_strbuf_free(&s);
    }
  }
  dprintf(idx, " done.\n");
}

/* Security-flavoured sanity checking on DCC connections of all sorts can be
 * done with this routine.  Feed it the proper information from your DCC
 * before you attempt the connection, and this will make an attempt at
 * figuring out if the connection is really that person, or someone screwing
 * around.  It's not foolproof, but anything that fails this check probably
 * isn't going to work anyway due to masquerading firewalls, NAT routers,
 * or bugs in mIRC.
 */
int sanitycheck_dcc(char *nick, char *from, char *ipaddy, char *port)
{
  /* According to the latest RFC, the clients SHOULD be able to handle
   * DNS names that are up to 255 characters long.  This is not broken.
   */

  char badaddress[INET_ADDRSTRLEN];
#ifdef IPV6
  sockname_t name;
  IP ip = 0;
#else
  IP ip = my_atoul(ipaddy);
#endif
  int prt = atoi(port);

  /* It is disabled HERE so we only have to check in *one* spot! */
  if (!dcc_sanitycheck)
    return 1;

  if (prt < 1) {
    putlog(LOG_MISC, "*", "ALERT: (%s!%s) specified an impossible port of %u!",
           nick, from, prt);
    return 0;
  }
#ifdef IPV6
  if (strchr(ipaddy, ':')) {
    if (inet_pton(AF_INET6, ipaddy, &name.addr.s6.sin6_addr) != 1) {
      putlog(LOG_MISC, "*", "ALERT: (%s!%s) specified an invalid IPv6 "
             "address of %s!", nick, from, ipaddy);
      return 0;
    }
    if (IN6_IS_ADDR_V4MAPPED(&name.addr.s6.sin6_addr)) {
      memcpy(&ip, name.addr.s6.sin6_addr.s6_addr + 12, sizeof ip);
      ip = ntohl(ip);
    }
  }
#endif
  if (ip && inet_ntop(AF_INET, &ip, badaddress, sizeof badaddress) &&
      (ip < (1 << 24))) {
    putlog(LOG_MISC, "*", "ALERT: (%s!%s) specified an impossible IP of %s!",
           nick, from, badaddress);
    return 0;
  }
  return 1;
}

int hostsanitycheck_dcc(char *nick, char *from, sockname_t *ip, char *dnsname,
                        char *prt)
{
  char badaddress[EGG_INET_ADDRSTRLEN];

  /* According to the latest RFC, the clients SHOULD be able to handle
   * DNS names that are up to 255 characters long.  This is not broken.
   */
  char hostn[256];

  /* It is disabled HERE so we only have to check in *one* spot! */
  if (!dcc_sanitycheck)
    return 1;
  strlcpy(badaddress, iptostr(&ip->addr.sa), sizeof badaddress);
  strlcpy(hostn, extracthostname(from), sizeof hostn);
  if (!strcasecmp(hostn, dnsname)) {
    putlog(LOG_DEBUG, "*", "DNS information for submitted IP checks out.");
    return 1;
  }
  if (!strcmp(badaddress, dnsname))
    putlog(LOG_MISC, "*", "ALERT: (%s!%s) sent a DCC request with bogus IP "
           "information of %s port %s. %s does not resolve to %s!", nick, from,
           badaddress, prt, from, badaddress);
  else
    return 1;                   /* <- usually happens when we have
                                 * a user with an unresolved hostmask! */
  return 0;
}

/* Checks whether the referenced socket has data queued.
 *
 * Returns true if the incoming/outgoing (depending on 'type') queues
 * contain data, otherwise false.
 */
int sock_has_data(int type, int sock)
{
  int ret = 0;
  struct threaddata *td = threaddata();

  int i = 0;
  for (; i < td->MAXSOCKS; i++)
    if (!(socklist[i].flags & SOCK_UNUSED) && socklist[i].sock == sock)
      break;
  if (i < td->MAXSOCKS) {
    switch (type) {
    case SOCK_DATA_OUTGOING:
      ret = (socklist[i].handler.sock.outbuf != NULL);
      break;
    case SOCK_DATA_INCOMING:
      ret = (op_linebuf_len(&socklist[i].handler.sock.recvbuf) > 0);
      break;
    }
  } else
    debug1("sock_has_data: could not find socket #%d, returning false.", sock);
  return ret;
}

/* flush_inbuf():
 * checks if there's data in the incoming buffer of an connection
 * and flushes the buffer if possible
 *
 * returns: -1 if the dcc entry wasn't found
 *          -2 if dcc[idx].type->activity doesn't exist and the data couldn't
 *             be handled
 *          0 if buffer was empty
 *          otherwise length of flushed buffer
 */
int flush_inbuf(int idx)
{
  struct threaddata *td = threaddata();

  Assert((idx >= 0) && (idx < dcc_total));
  for (int i = 0; i < td->MAXSOCKS; i++) {
    if ((dcc[idx].sock == socklist[i].sock) &&
        !(socklist[i].flags & SOCK_UNUSED)) {
      size_t total = op_linebuf_len(&socklist[i].handler.sock.recvbuf);
      if (total > 0) {
        if (dcc[idx].type && dcc[idx].type->activity) {
          /* Extract all buffered data into a flat buffer and deliver it.
           * Drain line-by-line in raw+partial mode since there may be
           * multiple linebuf nodes. */
          char *inbuf = op_malloc(total + 1);
          size_t off = 0;
          int got;
          while ((got = op_linebuf_get(&socklist[i].handler.sock.recvbuf,
                                       inbuf + off, total - off + 1,
                                       1, 1)) > 0)
            off += (size_t)got;
          if (off == 0) {
            op_free(inbuf);
            return 0;
          }
          inbuf[off] = '\0';
          dcc[idx].type->activity(idx, inbuf, (int)off);
          op_free(inbuf);
          return (int)off;
        } else
          return -2;
      } else
        return 0;
    }
  }
  return -1;
}

/* Find sock in socklist.
 *
 * Returns index in socklist or -1 if not found.
 */
int findsock(int sock)
{
  struct threaddata *td = threaddata();

  int i = 0;
  for (; i < td->MAXSOCKS; i++)
    if (td->socklist[i].sock == sock)
      break;
  if (i == td->MAXSOCKS)
    return -1;
  return i;
}

/* Trace on my-ip and my-hostname variable to handle transition into vhost4/vhost6/listen-addr.
 */
char *traced_myiphostname(ClientData cd, Tcl_Interp *irp, EGG_CONST char *name1, EGG_CONST char *name2, int flags)
{
  const char *value;

  if (Tcl_InterpDeleted(irp))
    return NULL;

  /* Recover trace in case of unset. */
  if (flags & TCL_TRACE_DESTROYED) {
    Tcl_TraceVar2(irp, name1, name2, TCL_GLOBAL_ONLY|TCL_TRACE_WRITES|TCL_TRACE_UNSETS, traced_myiphostname, cd);
    return NULL;
  }

  value = Tcl_GetVar2(irp, name1, name2, TCL_GLOBAL_ONLY);
  strlcpy(vhost, value, sizeof vhost);
  strlcpy(listen_ip, value, sizeof listen_ip);
  putlog(LOG_MISC, "*", "WARNING: You are using the DEPRECATED variable '%s' in your config file.\n", name1);
  putlog(LOG_MISC, "*", "    To prevent future incompatibility, please use the vhost4/listen-addr variables instead.\n");
  putlog(LOG_MISC, "*", "    More information on this subject can be found in the eggdrop/doc/IPV6 file, or\n");
  putlog(LOG_MISC, "*", "    in the comments above those settings in the example eggdrop.conf that is included with Eggdrop.\n");
  return NULL;
}

char *traced_natip(ClientData cd, Tcl_Interp *irp, EGG_CONST char *name1,
                   EGG_CONST char *name2, int flags)
{
  const char *value;
  int r;
  struct in_addr ia;

  /* Recover trace in case of unset. */
  if (flags & TCL_TRACE_DESTROYED) {
    Tcl_TraceVar2(irp, name1, name2, TCL_GLOBAL_ONLY|TCL_TRACE_WRITES|TCL_TRACE_UNSETS, traced_natip, cd);
    return NULL;
  }

  value = Tcl_GetVar2(irp, name1, name2, TCL_GLOBAL_ONLY);
  if (*value) {
    r = inet_pton(AF_INET, value, &ia);
    if (!r) {
      if (!online_since)
        fatal("ERROR: nat-ip is not a valid IPv4 address", 0);
      return "nat-ip is not a valid IPv4 address";
    }
    if (r < 0) {
      if (!online_since)
        fatal("ERROR: inet_pton(): nat-ip", 0);
      putlog(LOG_MISC, "*", "ERROR: inet_pton(): nat-ip %s", value);
      return strerror(errno);
    }
    {
      op_strbuf_t _b;
      op_strbuf_printf(&_b, "%" PRIu32, ntohl(ia.s_addr));
      strlcpy(nat_ip_string, op_strbuf_str(&_b), sizeof nat_ip_string);
      op_strbuf_free(&_b);
    }
  } else
    *nat_ip_string = '\0';
  return NULL;
}

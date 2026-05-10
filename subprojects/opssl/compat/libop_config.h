/*
 * libop_config.h — standalone build stub for opssl.
 *
 * When opssl is built inside ophion, the real libop_config.h is generated
 * by ophion's meson configure step. This stub provides the minimal defines
 * needed for opssl's standalone development builds.
 */

#ifndef LIBOP_CONFIG_H
#define LIBOP_CONFIG_H

#define HAVE_SNPRINTF 1
#define HAVE_VSNPRINTF 1
#define HAVE_SOCKETPAIR 1
#define HAVE_GETTIMEOFDAY 1
#define HAVE_WRITEV 1
#define HAVE_SENDMSG 1
#define HAVE_GMTIME_R 1
#define HAVE_STRTOK_R 1
#define HAVE_USLEEP 1
#define HAVE_NANOSLEEP 1
#define HAVE_STRNDUP 1
#define HAVE_STRNLEN 1
#define HAVE_STRCASECMP 1
#define HAVE_STRNCASECMP 1
#define HAVE_FSTAT 1
#define HAVE_EPOLL_CTL 1
#define HAVE_ARC4RANDOM_BUF 1
#define HAVE_GETRANDOM 1
#define HAVE_GETRUSAGE 1
#define HAVE_TIMERFD_CREATE 1
#define HAVE_ACCEPT4 1
#define HAVE_PIPE2 1
#define HAVE_CLOCK_GETTIME 1
#define HAVE_SIGNALFD 1

/* opssl does not need zlib from libop */
/* #undef HAVE_ZLIB */
/* #undef HAVE_LIBURING */

#define BRANDING_NAME "opssl"
#define BRANDING_VERSION "1.0.0"

#endif /* LIBOP_CONFIG_H */

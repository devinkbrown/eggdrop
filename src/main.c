/*
 * main.c -- handles:
 *   core event handling
 *   signal handling
 *   command line arguments
 *   context and assert debugging
 */
/*
 * Copyright (C) 1997 Robey Pointer
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
/*
 * The author (Robey Pointer) can be reached at:  robey@netcom.com
 * NOTE: Robey is no long working on this code, there is a discussion
 * list available at eggheads@eggheads.org.
 */

#include <config.h>
#include "main.h"

#include <errno.h>
#include <fcntl.h>
#include <resolv.h>
#include <setjmp.h>
#include <signal.h>

#ifdef STOP_UAC                         /* OSF/1 complains a lot */
#  include <sys/sysinfo.h>
#  define UAC_NOPRINT 0x00000001        /* Don't report unaligned fixups */
#endif

#include "version.h"
#include "chan.h"
#include "modules.h"
#include "bg.h"
#include "configtoml.h"
#include "websetup.h"
#include "threadpool.h"
#include "comqueue.h"
#include "async_log.h"
#include "async_fileio.h"
#include "libop/include/op_iothread.h"
#include "script.h"
#include "async_dns.h"
#include "perf.h"
#include <op_commio.h>
#include <op_async.h>
#include <op_async_log.h>

#ifndef _POSIX_SOURCE
#  define _POSIX_SOURCE 1               /* Solaris needs this */
#endif

extern char origbotname[], botnetnick[];
extern int dcc_total, conmask, cache_hit, cache_miss, max_logs, quiet_save;
extern struct dcc_t *dcc;
extern struct userrec *userlist;
extern struct chanset_t *chanset;
extern log_t *logs;
extern Tcl_Interp *interp;
extern op_vec_t timer, utimer;
extern sigjmp_buf alarmret;
time_t now;
static int argc;
static char **argv;
const char *argv0;

/*
 * Please use the PATCH macro instead of directly altering the version
 * string from now on (it makes it much easier to maintain patches).
 * Also please read the README file regarding your rights to distribute
 * modified versions of this bot.
 */

char *egg_version = nullptr;
int egg_numver = EGG_NUMVER;

char notify_new[121] = "";      /* Person to send a note to for new users */
int default_flags = 0;          /* Default user flags                     */
int default_uflags = 0;         /* Default user-defined flags             */

int backgrd = 1;    /* Run in the background?                        */
int con_chan = 0;   /* Foreground: constantly display channel stats? */
int term_z = -1;    /* Foreground: use the terminal as a partyline?  */
int use_stderr = 1; /* Send stuff to stderr instead of logfiles?     */

char configfile[121] = "eggdrop.toml";  /* Default config file name */
char *pid_file = nullptr;               /* Name of the pid file     */
char helpdir[121] = "help/";            /* Directory of help files  */
char textdir[121] = "text/";            /* Directory for text files */

int keep_all_logs = 0;                  /* Never erase logfiles?    */
int switch_logfiles_at = 300;           /* When to switch logfiles  */

time_t online_since;    /* time that the bot was started */

int make_userfile = 0; /* Using bot in userfile-creation mode? */

int save_users_at = 0;   /* Minutes past the hour to save the userfile?     */
int notify_users_at = 0; /* Minutes past the hour to notify users of notes? */

char version[128];   /* Version info (long form)  */
char ver[41];        /* Version info (short form) */

volatile sig_atomic_t do_restart = 0; /* .restart has been called, restart ASAP */
int resolve_timeout = RES_TIMEOUT;    /* Hostname/address lookup timeout        */
int nthreads = 0;                     /* Worker thread count; 0 = auto-detect   */
char quit_msg[1024];                  /* Quit message                           */

/* Moved here for n flag warning, put back in do_arg if removed */
unsigned short cliflags = 0;


/* Traffic stats — cache-line padded atomic counters (see traffic.h) */
#include "traffic.h"
struct egg_traffic itraffic = {};
struct egg_traffic otraffic = {};

#ifdef DEBUG_CONTEXT
extern char last_bind_called[];
#endif

void fatal(const char *s, int recoverable)
{
  putlog(LOG_MISC, "*", "* %s", s);
  op_stop_pollthread();
  threadpool_shutdown();
  comqueue_destroy();
  async_log_destroy();  /* flushes pending log lines then stops writer */
  op_async_shutdown();
  for (int i = 0; i < dcc_total; i++)
    if (dcc[i].sock >= 0)
      killsock(dcc[i].sock);
#ifdef TLS
  ssl_cleanup();
#endif
  if (pid_file)
    unlink(pid_file);
  if (recoverable != 1) {
    bg_send_quit(BG_ABORT);
    exit(!recoverable);
  }
}

static void check_expired_dcc(void)
{
  for (int i = 0; i < dcc_total; i++)
    if (dcc[i].type && dcc[i].type->timeout_val &&
        ((now - dcc[i].timeval) > *(dcc[i].type->timeout_val))) {
      if (dcc[i].type->timeout)
        dcc[i].type->timeout(i);
      else if (dcc[i].type->eof)
        dcc[i].type->eof(i);
      else
        continue;
      /* Only timeout 1 socket per cycle, too risky for more */
      return;
    }
}

#ifndef DEBUG_CONTEXT
#define write_debug() do {} while (0)
#else
static int nested_debug = 0;

static void write_debug(void)
{
  int x;
  char s[26];

  if (nested_debug) {
    /* Yoicks, if we have this there's serious trouble!
     * All of these are pretty reliable, so we'll try these.
     */
    x = creat("DEBUG.DEBUG", 0644);
    if (x >= 0) {
      setsock(x, SOCK_NONSOCK);
      ctime_r(&now, s);
      dprintf(-x, "Debug (%s) written %s\n"
                  "Please report problem to https://github.com/eggheads/eggdrop/issues\n"
                  "Check doc/BUG-REPORT on how to do so.", ver, s);
#ifdef EGG_PATCH
      dprintf(-x, "Patch level: %s\n", EGG_PATCH);
#else
      dprintf(-x, "Patch level: %s\n", "stable");
#endif
      if (*last_bind_called)
        dprintf(-x, "Last bind (may not be related): %s\n", last_bind_called);
      killsock(x);
      close(x);
    }
    bg_send_quit(BG_ABORT);
    exit(1);                    /* Dont even try & tell people about, that may
                                 * have caused the fault last time. */
  } else
    nested_debug = 1;
  putlog(LOG_MISC, "*", "* Please report problem to https://github.com/eggheads/eggdrop/issues");
  putlog(LOG_MISC, "*", "* Check doc/BUG-REPORT on how to do so.");
  if (*last_bind_called)
    putlog(LOG_MISC, "*", "* Last bind (may not be related): %s", last_bind_called);
  x = creat("DEBUG", 0644);
  setsock(x, SOCK_NONSOCK);
  if (x < 0) {
    putlog(LOG_MISC, "*", "* Failed to write DEBUG");
  } else {
    ctime_r(&now, s);
    dprintf(-x, "Debug (%s) written %s", ver, s);
#ifdef EGG_PATCH
    dprintf(-x, "Patch level: %s\n", EGG_PATCH);
#else
    dprintf(-x, "Patch level: %s\n", "stable");
#endif
#ifdef STATIC
    dprintf(-x, "STATICALLY LINKED\n");
#endif

    if (interp) {
      /* info library */
      dprintf(-x, "Tcl library: %s\n",
              !egg_eval("info library") ? tcl_resultstring() : "*unknown*");

      /* info tclversion/patchlevel */
      dprintf(-x, "Tcl version: %s (header version " TCL_PATCH_LEVEL ")\n",
              !egg_eval("info patchlevel") ? tcl_resultstring() :
              !egg_eval("info tclversion") ? tcl_resultstring() : "*unknown*");

      if (tcl_threaded())
        dprintf(-x, "Tcl is threaded\n");
    } else {
      dprintf(-x, "Tcl scripting: disabled\n");
    }
#ifdef IPV6
    dprintf(-x, "Compiled with IPv6 support\n");
#else
    dprintf(-x, "Compiled without IPv6 support\n");
#endif
#ifdef TLS
    dprintf(-x, "Compiled with TLS support\n");
#else
    dprintf(-x, "Compiled without TLS support\n");
#endif
    if (!strcmp(EGG_AC_ARGS, "")) {
      dprintf(-x, "Configure flags: none\n");
    } else {
      dprintf(-x, "Configure flags: %s\n", EGG_AC_ARGS);
    }
#ifdef CCFLAGS
    dprintf(-x, "Compile flags: %s\n", CCFLAGS);
#endif

#ifdef LDFLAGS
    dprintf(-x, "Link flags: %s\n", LDFLAGS);
#endif

#ifdef STRIPFLAGS
    dprintf(-x, "Strip flags: %s\n", STRIPFLAGS);
#endif
    dprintf(-x, "Last bind (may not be related): %s\n", last_bind_called);
    tell_dcc(-x);
    dprintf(-x, "\n");
    killsock(x);
    close(x);
    putlog(LOG_MISC, "*", "* Wrote DEBUG");
  }
}
#endif /* DEBUG_CONTEXT */

static void got_bus(int z)
{
  write_debug();
  fatal("BUS ERROR -- CRASHING!", 1);
#ifdef SA_RESETHAND
  kill(getpid(), SIGBUS);
#else
  bg_send_quit(BG_ABORT);
  exit(1);
#endif
}

static void got_segv(int z)
{
  write_debug();
  fatal("SEGMENT VIOLATION -- CRASHING!", 1);
#ifdef SA_RESETHAND
  kill(getpid(), SIGSEGV);
#else
  bg_send_quit(BG_ABORT);
  exit(1);
#endif
}

static void got_fpe(int z)
{
  write_debug();
  fatal("FLOATING POINT ERROR -- CRASHING!", 0);
}

static void got_term(int z)
{
  /* Now we die by default on sigterm, but scripts have the chance to
   * catch the event themselves and cancel shutdown by returning 1
   */
  if (check_tcl_signal("sigterm"))
    return;
  kill_bot("ACK, I've been terminated!", "TERMINATE SIGNAL -- SIGNING OFF");
}

static void got_quit(int z)
{
  if (check_tcl_signal("sigquit"))
    return;
  putlog(LOG_MISC, "*", "Received QUIT signal: restarting...");
  do_restart = -1;
  return;
}

static void got_hup(int z)
{
  write_userfile(-1);
  if (check_tcl_signal("sighup"))
    return;
  putlog(LOG_MISC, "*", "Received HUP signal: rehashing...");
  do_restart = -2;
  return;
}

/* A call to resolver (gethostbyname, etc) timed out
 */
static void got_alarm(int z)
{
  siglongjmp(alarmret, 1);

  /* -Never reached- */
}

/* Got ILL signal -- log context and continue
 */
static void got_ill(int z)
{
  check_tcl_signal("sigill");
#ifdef DEBUG_CONTEXT
  putlog(LOG_MISC, "*", "* Please REPORT this BUG!");
  putlog(LOG_MISC, "*", "* Check doc/BUG-REPORT on how to do so.");
  putlog(LOG_MISC, "*", "* Last bind (may not be related): %s", last_bind_called);
#endif
}

#ifdef DEBUG_ASSERT
/* Called from the Assert macro.
 */
void eggAssert(const char *file, int line, const char *module)
{
  write_debug();
  if (!module)
    putlog(LOG_MISC, "*", "* In file %s, line %u", file, line);
  else
    putlog(LOG_MISC, "*", "* In file %s:%s, line %u", module, file, line);
  fatal("ASSERT FAILED -- CRASHING!", 1);
}
#endif

static void show_ver(void) {
  char x[512], *z = x;

  op_strlcpy(x, egg_version, sizeof x);
  (void)newsplit(&z);
  (void)newsplit(&z);
  printf("%s\n", version);
  if (z[0]) {
    printf("  (patches: %s)\n", z);
  }
  if (!strcmp(EGG_AC_ARGS, "")) {
    printf("Configure flags: none\n");
  } else {
    printf("Configure flags: %s\n", EGG_AC_ARGS);
  }
  printf("Compiled with: ");
#ifdef IPV6
  printf("IPv6, ");
#endif
#ifdef TLS
  printf("TLS, ");
#endif
  printf("handlen=%d\n", HANDLEN);
  printf("Build: %s %s\n", __DATE__, __TIME__);
  bg_send_quit(BG_ABORT);
}

/* Hard coded text because config file isn't loaded yet,
   meaning other languages can't be loaded yet.
   English (or an error) is the only possible option.
*/
static void show_help(void) {
  printf("\n%s\n\n", version);
  printf("Usage: %s [options] [config-file]\n\n"
         "Options:\n"
         "-c  Don't background; display channel stats every 10 seconds.\n"
         "-t  Don't background; use terminal to simulate DCC chat.\n"
         "-m  Create userfile.\n"
         "-s  Run the interactive setup wizard and write a TOML config.\n"
         "-w  Run the web-based setup wizard (HTTP). Usage: -w [port] [outfile]\n"
         "-h  Show this help and exit.\n"
         "-v  Show version info and exit.\n\n"
         "Config file formats:\n"
         "  eggdrop.conf  -- traditional Tcl script (default)\n"
         "  eggdrop.toml  -- modern TOML format (auto-detected by extension)\n\n",
         argv0);
  bg_send_quit(BG_ABORT);
}

static void do_arg(void)
{
  int option = 0;
/* Put this back if removing n flag warning
  unsigned char cliflags = 0;
*/
  #define CLI_V        1 << 0
  #define CLI_M        1 << 1
  #define CLI_T        1 << 2
  #define CLI_C        1 << 3
  #define CLI_N        1 << 4
  #define CLI_H        1 << 5
  #define CLI_BAD_FLAG 1 << 6
  #define CLI_S        1 << 7   /* setup wizard */
  #define CLI_W        1 << 8   /* web setup wizard */

  while ((option = getopt(argc, argv, "hnctmvsw")) != -1) {
    switch (option) {
      case 'n':
        cliflags |= CLI_N;
        backgrd = 0;
        break;
      case 'c':
        cliflags |= CLI_C;
        con_chan = 1;
        term_z = -1;
        backgrd = 0;
        break;
      case 't':
        cliflags |= CLI_T;
        con_chan = 0;
        term_z = 0;
        backgrd = 0;
        break;
      case 'm':
        cliflags |= CLI_M;
        make_userfile = 1;
        break;
      case 'v':
        cliflags |= CLI_V;
        break;
      case 'h':
        cliflags |= CLI_H;
        break;
      case 's':
        cliflags |= CLI_S;
        break;
      case 'w':
        cliflags |= CLI_W;
        break;
      default:
        cliflags |= CLI_BAD_FLAG;
        break;
    }
  }
  if (cliflags & CLI_H) {
    show_help();
    exit(0);
  } else if (cliflags & CLI_BAD_FLAG) {
    show_help();
    exit(1);
  } else if (cliflags & CLI_V) {
    show_ver();
    exit(0);
  } else if (cliflags & CLI_S) {
    /* Interactive setup wizard — writes a TOML config, then exits. */
    const char *outfile = (argc > optind) ? argv[optind] : "eggdrop.toml";
    printf("\n%s\n", version);
    exit(run_setup_wizard(outfile));
  } else if (cliflags & CLI_W) {
    /* Web-based setup wizard — HTTP server, then exits.
     * Usage: eggdrop -w [port] [outfile]
     * Defaults: port=8080, outfile=eggdrop.toml
     */
    int wport = 8080;
    const char *outfile = "eggdrop.toml";
    if (argc > optind && atoi(argv[optind]) > 0) {
      wport = atoi(argv[optind]);
      if (argc > optind + 1)
        outfile = argv[optind + 1];
    } else if (argc > optind) {
      outfile = argv[optind];
    }
    printf("\n%s\n", version);
    exit(run_web_setup(wport, outfile));
  } else if (argc > (optind + 1)) {
    printf("\n");
    printf("WARNING: More than one config file value detected\n");
    printf("         Using %s as config file\n", argv[optind]);
  }
  if (argc > optind) {
    op_strlcpy(configfile, argv[optind], sizeof configfile);
  }
}

/* Timer info */
static time_t lastmin;
static time_t then;
static struct tm nowtm;

/* Called once a second.
 */
static void core_secondly(void)
{
  static int cnt = 10; /* Don't wait the first 10 seconds to display */
  int miltime;
  time_t nowmins;
  uint64_t drift_mins;

  do_check_timers(&utimer);     /* Secondly timers */
  cnt++;
  if (cnt >= 10) {              /* Every 10 seconds */
    cnt = 0;
    check_expired_dcc();
    if (con_chan && !backgrd) {
      dprintf(DP_STDOUT, "\033[2J\033[1;1H");
      if ((cliflags & CLI_N) && (cliflags & CLI_C)) {
        printf("NOTE: You don't need to use the -n flag with the\n");
        printf("       -t or -c flag anymore.\n");
      }
      tell_verbose_status(DP_STDOUT);
      do_module_report(DP_STDOUT, 0, "server");
      do_module_report(DP_STDOUT, 0, "channels");
    }
  }
  nowmins = now / 60;
  if (nowmins > lastmin) {
    localtime_r(&now, &nowtm);
    int i = 0;
    /* Once a minute */
    ++lastmin;
    call_hook(HOOK_MINUTELY);
    check_expired_ignores();
    autolink_cycle(nullptr);       /* Attempt autolinks */
    /* In case for some reason more than 1 min has passed: */
    while (nowmins != lastmin) {
      /* Timer drift, dammit */
      drift_mins = nowmins - lastmin;
      debug2("timer: drift (%" PRId64 " minute%s)", drift_mins, drift_mins == 1 ? "" : "s");
      i++;
      ++lastmin;
      call_hook(HOOK_MINUTELY);
    }
    if (i)
      putlog(LOG_MISC, "*", "(!) timer drift -- spun %i minute%s", i, i == 1 ? "" : "s");
    miltime = (nowtm.tm_hour * 100) + (nowtm.tm_min);
    if (nowtm.tm_min % 5 == 0) { /* Every 5 minutes */
      call_hook(HOOK_5MINUTELY);
      check_botnet_pings();
      if (!miltime) {           /* At midnight */
        char s[26];
        ctime_r(&now, s);
        s[24] = 0;
        if (quiet_save < 3)
          putlog(LOG_ALL, "*", "--- %.11s%s", s, s + 20);
        call_hook(HOOK_BACKUP);
        if (async_log_active())
          async_log_flush();
        for (int j = 0; j < max_logs; j++) {
          if (logs[j].filename != nullptr) {
            if (async_log_active() && async_log_slot_open(j))
              async_log_close(j);
            else if (logs[j].f != nullptr) {
              fclose(logs[j].f);
              logs[j].f = nullptr;
            }
          }
        }
      }
    }
    if (nowtm.tm_min == notify_users_at)
      call_hook(HOOK_HOURLY);
    /* These no longer need checking since they are all check vs minutely
     * settings and we only get this far on the minute.
     */
    if (miltime == switch_logfiles_at) {
      call_hook(HOOK_DAILY);
      if (!keep_all_logs) {
        if (quiet_save < 3)
          putlog(LOG_MISC, "*", "%s", MISC_LOGSWITCH);
        if (async_log_active())
          async_log_flush();
        for (int li = 0; li < max_logs; li++)
          if (logs[li].filename) {
            op_strbuf_t sb = {};
            op_strbuf_init(&sb);

            if (async_log_active() && async_log_slot_open(li)) {
              async_log_close(li);
            } else if (logs[li].f) {
              fclose(logs[li].f);
              logs[li].f = nullptr;
            }
            op_strbuf_appendf(&sb, "%s.yesterday", logs[li].filename);
            unlink(op_strbuf_str(&sb));
            async_movefile(logs[li].filename, op_strbuf_str(&sb));
            op_strbuf_free(&sb);
          }
      }
#ifdef TLS
      verify_cert_expiry(0);
#endif
    }
  }
}

static void core_minutely(void)
{
  check_tcl_time_and_cron(&nowtm);
  do_check_timers(&timer);
  if (op_async_active())
    async_check_logsize();
  else
    check_logsize();
}

static void core_hourly(void)
{
  write_userfile(-1);
}

static void event_rehash(void)
{
  check_tcl_event("rehash");
}

static void event_prerehash(void)
{
  check_tcl_event("prerehash");
}

static void event_save(void)
{
  check_tcl_event("save");
}

static void event_logfile(void)
{
  check_tcl_event("logfile");
}

static void event_loaded(void)
{
  check_tcl_event("loaded");
}

void kill_tcl(void);
extern op_vec_t module_vec;
extern op_vec_t dep_vec;
void restart_chons(void);

#ifdef STATIC
void check_static(char *, char *(*)(void));

#include "mod/static.h"
#endif
void init_threaddata(int);
int init_userent(void);
int init_misc(void);
void userrec_heaps_init(void);
void userrec_heaps_destroy(void);
int init_bots(void);
int init_modules(void);
void init_tcl0(int, char **);
void init_tcl1(int, char **);
void init_language(int);
#ifdef TLS
int ssl_init(void);
#endif

static void mainloop(int toplevel)
{
  static int cleanup = 5;
  int xx, i, eggbusy = 1;
  char buf[READMAX + 2];

  egg_perf_tick_begin();
  op_arena_reset(op_event_arena());
  now = time(nullptr);

  /* If we want to restart, we have to unwind to the toplevel.
   * Tcl will Panic if we kill the interp with Tcl_Eval in progress.
   * This is done by returning -1 in tickle_WaitForEvent.
   */
  if (op_unlikely(do_restart && do_restart != -2 && !toplevel))
    return;

  /* Once a second */
  if (op_unlikely(now != then)) {
    call_hook(HOOK_SECONDLY);
    then = now;
  }

  /* Drain both completion queues every tick so DNS/file callbacks land
   * promptly, not just when the main loop goes idle. */
  comqueue_drain();
  op_async_drain();

  /* Only do this every so often. */
  if (!cleanup) {
    cleanup = 5;

    /* Wait for any in-flight workers, then remove dead slots. */
    threadpool_drain();
    dcc_remove_lost();

    /* Check for server or dcc activity. */
    dequeue_sockets();

    /* Free unused structures. */
    garbage_collect_tclhash();
  } else
    cleanup--;

  /* Batch-process all ready sockets in one tick (up to 64 per pass).
   * This reduces wakeup overhead and improves throughput under load. */
  for (int _batch = 0; _batch < 64; _batch++) {
    xx = sockgets(buf, &i);
    if (op_likely(xx >= 0)) {              /* Non-error — common path */
      int idx = findanyidx(xx);  /* O(1) via sock→dcc map */

      if (op_likely(idx >= 0)) {
        if (op_likely(dcc[idx].type && dcc[idx].type->activity)) {
          if (op_likely(dcc[idx].type->name != nullptr)) {
            size_t _nb = strlen(buf) + 1;
            _Atomic uint64_t *ctr;
            switch (dcc[idx].type->name[0]) {
            case 'B': ctr = &itraffic_bn_today;    break;
            case 'S': ctr = dcc[idx].type->name[1] == 'E'
                          ? &itraffic_irc_today
                          : &itraffic_trans_today;
                      break;
            case 'C': ctr = &itraffic_dcc_today;    break;
            case 'W': ctr = &itraffic_dcc_today;
                      _nb = (size_t)i;              break;
            case 'F': ctr = dcc[idx].type->name[1] == 'I'
                          ? &itraffic_dcc_today
                          : &itraffic_trans_today;
                      break;
            case 'G': ctr = &itraffic_trans_today;  break;
            default:  ctr = &itraffic_unknown_today; break;
            }
            atomic_fetch_add_explicit(ctr, _nb, memory_order_relaxed);
          }
          /* Dispatch: parallel-safe types go to thread pool, others inline */
          if ((dcc[idx].type->flags & DCT_PARALLEL) &&
              threadpool_active() &&
              threadpool_submit((pool_work_fn)dcc[idx].type->activity, idx, buf, i) == 0) {
            /* Submitted to worker thread */
          } else {
            dcc[idx].type->activity(idx, buf, i);
          }
        } else
          putlog(LOG_MISC, "*", "ERROR: untrapped dcc activity: type %s, sock %ld",
                 dcc[idx].type ? dcc[idx].type->name : "UNKNOWN", dcc[idx].sock);
      }
    } else if (op_unlikely(xx == -1)) {        /* EOF from someone */
      int idx;

      if (i == STDOUT && !backgrd)
        fatal("END OF FILE ON TERMINAL", 0);
      idx = findanyidx(i);
      if (idx >= 0) {
        if (dcc[idx].type && dcc[idx].type->eof)
          dcc[idx].type->eof(idx);
        else {
          putlog(LOG_MISC, "*",
                 "*** ATTENTION: DEAD SOCKET (%d) OF TYPE %s UNTRAPPED",
                 i, dcc[idx].type ? dcc[idx].type->name : "*UNKNOWN*");
          killsock(i);
          lostdcc(idx);
        }
      } else {
        putlog(LOG_MISC, "*",
               "(@) EOF socket %d, not a dcc socket, not anything.", i);
        close(i);
        killsock(i);
      }
    } else if (op_unlikely(xx == -2 && errno != EINTR)) {
      putlog(LOG_MISC, "*", "* Socket error #%d; recovering.", errno);
      for (i = 0; i < dcc_total; i++) {
        if ((fcntl(dcc[i].sock, F_GETFD, 0) == -1) && (errno == EBADF)) {
          putlog(LOG_MISC, "*",
                 "DCC socket %ld (type %s, name '%s') expired -- pfft",
                 dcc[i].sock, dcc[i].type->name, dcc[i].nick);
          killsock(dcc[i].sock);
          lostdcc(i);
          i--;
        }
      }
      break;
    } else if (xx == -3) {
      call_hook(HOOK_IDLE);
      op_async_drain();
      cleanup = 0;
      eggbusy = 0;
      break;
    } else if (xx == -5) {
      eggbusy = 0;
      break;
    } else {
      break;
    }
  }

  if (do_restart) {
    if (do_restart == -2)
      rehash();
    else if (!toplevel)
      return; /* Unwind to toplevel before restarting */
    else {
      /* Unload as many modules as possible */
      int f = 1;
      module_entry *p;
      Function startfunc;
      char name[256];

      /* oops, I guess we should call this event before tcl is restarted */
      op_stop_pollthread();
      threadpool_drain();
      comqueue_drain();
      async_log_flush();  /* flush pending log lines before restart */
      check_tcl_event("prerestart");

      while (f) {
        f = 0;
        for (size_t _mi = 0; _mi < module_vec.size; _mi++) {
          p = (module_entry *)op_vec_get(&module_vec, _mi);
          int ok = 1;

          for (size_t _di = 0; ok && _di < dep_vec.size; _di++) {
            dependancy *d = (dependancy *)op_vec_get(&dep_vec, _di);
            if (d->needed == p)
              ok = 0;
          }
          if (ok) {
            op_strlcpy(name, p->name, sizeof name);
            if (module_unload(name, botnetnick) == nullptr) {
              f = 1;
              break;
            }
          }
        }
      }

      /* Make sure we don't have any modules left hanging around other than
       * "eggdrop" and the 3 that are supposed to be.
       */
      f = 0;
      for (size_t _mi = 0; _mi < module_vec.size; _mi++) {
        p = (module_entry *)op_vec_get(&module_vec, _mi);
        if (strcmp(p->name, "eggdrop") && strcmp(p->name, "encryption") &&
            strcmp(p->name, "encryption2") && strcmp(p->name, "uptime")) {
          f++;
          putlog(LOG_MISC, "*", "stagnant module %s", p->name);
        }
      }
      if (f != 0) {
        putlog(LOG_MISC, "*", "%s", MOD_STAGNANT);
      }

      kill_tcl();
      init_tcl1(argc, argv);
      init_language(0);

      /* this resets our modules which we didn't unload (encryption and uptime) */
      for (size_t _mi = 0; _mi < module_vec.size; _mi++) {
        p = (module_entry *)op_vec_get(&module_vec, _mi);
        if (p->funcs) {
          startfunc = p->funcs[MODCALL_START];
          if (startfunc)
            ((char *(*)(Function *)) startfunc)(nullptr);
          else
            debug2("module: %s: %s", p->name, MOD_NOSTARTDEF);
        }
      }

      rehash();
#ifdef TLS
      ssl_cleanup();
      ssl_init();
#endif
      restart_chons();
      call_hook(HOOK_LOADED);
    }
    eggbusy = 1;
    do_restart = 0;
  }

  if (!eggbusy) {
    /* Process all pending Tcl events */
    Tcl_ServiceAll();
  }
  egg_perf_tick_end(!eggbusy);
}


int main(int arg_c, char **arg_v)
{
  char s[26];
  FILE *f;
  struct sigaction sv;
  struct chanset_t *chan;
#ifdef DEBUG
  struct rlimit cdlim;
#endif
#ifdef STOP_UAC
  int nvpair[2];
#endif

/* Make sure it can write core, if you make debug. Else it's pretty
 * useless (dw)
 *
 * Only allow unlimited size core files when compiled with DEBUG defined.
 * This is not a good idea for normal builds -- in these cases, use the
 * default system resource limits instead.
 */
#ifdef DEBUG
  cdlim.rlim_cur = RLIM_INFINITY;
  cdlim.rlim_max = RLIM_INFINITY;
  setrlimit(RLIMIT_CORE, &cdlim);
#endif

  argc = arg_c;
  argv = arg_v;
  argv0 = argv[0];

  /* Version info! */
  {
    op_strbuf_t egg_version_buf = {};
    op_strbuf_init(&egg_version_buf);
#ifdef EGG_PATCH
    op_strbuf_appendf(&egg_version_buf, "%s+%s %u", EGG_STRINGVER, EGG_PATCH, egg_numver);
    op_strlcpy(ver, "eggdrop v" EGG_STRINGVER "+" EGG_PATCH, sizeof ver);
    op_strlcpy(version,
            "Eggdrop v" EGG_STRINGVER "+" EGG_PATCH " (C) 1997 Robey Pointer (C) 1999-2025 Eggheads Development Team",
            sizeof version);
#else
    op_strbuf_appendf(&egg_version_buf, "%s %u", EGG_STRINGVER, egg_numver);
    op_strlcpy(ver, "eggdrop v" EGG_STRINGVER, sizeof ver);
    op_strlcpy(version,
            "Eggdrop v" EGG_STRINGVER " (C) 1997 Robey Pointer (C) 1999-2025 Eggheads Development Team",
            sizeof version);
#endif
    op_free(egg_version);
    egg_version = op_strbuf_steal(&egg_version_buf);
  }

/* For OSF/1 */
#ifdef STOP_UAC
  /* Don't print "unaligned access fixup" warning to the user */
  nvpair[0] = SSIN_UACPROC;
  nvpair[1] = UAC_NOPRINT;
  setsysinfo(SSI_NVPAIRS, (char *) nvpair, 1, nullptr, 0);
#endif

  /* Set up error traps: */
  sv.sa_handler = got_bus;
  sigemptyset(&sv.sa_mask);
#ifdef SA_RESETHAND
  sv.sa_flags = SA_RESETHAND;
#else
  sv.sa_flags = 0;
#endif
  sigaction(SIGBUS, &sv, nullptr);
  sv.sa_handler = got_segv;
  sigaction(SIGSEGV, &sv, nullptr);
#ifdef SA_RESETHAND
  sv.sa_flags = 0;
#endif
  sv.sa_handler = got_fpe;
  sigaction(SIGFPE, &sv, nullptr);
  sv.sa_handler = got_term;
  sigaction(SIGTERM, &sv, nullptr);
  sv.sa_handler = got_hup;
  sigaction(SIGHUP, &sv, nullptr);
  sv.sa_handler = got_quit;
  sigaction(SIGQUIT, &sv, nullptr);
  sv.sa_handler = SIG_IGN;
  sigaction(SIGPIPE, &sv, nullptr);
  sv.sa_handler = got_ill;
  sigaction(SIGILL, &sv, nullptr);
  sv.sa_handler = got_alarm;
  sigaction(SIGALRM, &sv, nullptr);
  sv.sa_handler = got_term;
  sigaction(SIGINT, &sv, nullptr);

  /* Initialize variables and stuff */
  now = time(nullptr);
  chanset = nullptr;
  chan_htab_init();
  lastmin = now / 60;
  op_event_init();
  op_init_bh();
  op_init_dlink_nodes(512);
  op_fdlist_init(0, 1024, 256);
  op_init_netio();
  op_linebuf_init(64);
  if (!op_async_init(0))
    fatal("ERROR: Failed to initialise async thread pool.", 0);
  async_log_init(max_logs);  /* start dedicated log writer thread */
  if (argc > 1)
    do_arg();
  /* Pre-scan the config for [paths] settings (lang_dir, mod_path) so language
   * files and modules can be found on the first attempt regardless of section
   * ordering in the config file. */
  prescan_paths(configfile);
  init_tcl0(argc, argv);
  init_language(1);

  printf("\n%s\n", version);

  if (((int) getuid() == 0) || ((int) geteuid() == 0))
    fatal("ERROR: Eggdrop will not run as root!", 0);

  userrec_heaps_init();
  init_userent();
  init_misc();
  init_bots();
  init_modules();
  if (backgrd)
    bg_prepare_split();
  init_tcl1(argc, argv);
  init_language(0);
#ifdef STATIC
  link_statics();
#endif
  ctime_r(&now, s);
  s[24] = 0;
  putlog(LOG_ALL, "*", "--- Loading %s (%s)", ver, s);
  chanprog();
  if (!encrypt_pass2 && !encrypt_pass) {
    printf("%s", MOD_NOCRYPT);
    bg_send_quit(BG_ABORT);
    exit(1);
  }
  int i = 0;
  for (chan = chanset; chan; chan = chan->next)
    i++;
  int j = count_users(userlist);
  putlog(LOG_MISC, "*", "=== %s: %d channel%s, %d user%s.",
         botnetnick, i, (i == 1) ? "" : "s", j, (j == 1) ? "" : "s");
  putlog(LOG_MISC, "*", "Scripting: %s%s",
         interp ? "Tcl " : "",
         module_find("python", 0, 0) ? "Python" : "");
  putlog(LOG_MISC, "*", "Features:%s%s%s",
#ifdef TLS
         " TLS",
#else
         "",
#endif
#ifdef IPV6
         " IPv6",
#else
         "",
#endif
         interp ? " Tcl" : "");
  if ((cliflags & CLI_N) && (cliflags & CLI_T)) {
    printf("\n");
    printf("NOTE: The -n flag is no longer used, it is as effective as Han\n");
    printf("      without Chewie\n");
  }
#ifdef TLS
  ssl_init();
#endif
  cache_miss = 0;
  cache_hit = 0;
  if (!pid_file) {
    op_strbuf_t buf = {};
    op_strbuf_init(&buf);
    op_strbuf_appendf(&buf, "pid.%s", botnetnick);
    pid_file = op_strbuf_steal(&buf);
  }

  /* Check for pre-existing eggdrop! */
  f = fopen(pid_file, "r");
  if (f != nullptr) {
    if (fgets(s, 10, f) != nullptr) {
      int xx = egg_atoi(s);
      if (kill(xx, SIGCHLD) == 0 || errno != ESRCH) {
        printf(EGG_RUNNING1, botnetnick);
        printf(EGG_RUNNING2, pid_file);
        bg_send_quit(BG_ABORT);
        exit(1);
      }
    } else {
      printf("Error checking for existing Eggdrop process.\n");
    }
    fclose(f);
  }

  /* Move into background? */
  if (backgrd) {
    bg_do_split();
  } else {                        /* !backgrd */
    int xx = getpid();
    if (xx != 0) {
      FILE *fp;

      /* Write pid to file */
      unlink(pid_file);
      fp = fopen(pid_file, "w");
      if (fp != nullptr) {
        fprintf(fp, "%u\n", xx);
        if (fflush(fp)) {
          /* Let the bot live since this doesn't appear to be a botchk */
          printf(EGG_NOWRITE, pid_file);
          fclose(fp);
          unlink(pid_file);
        } else
          fclose(fp);
      } else
        printf(EGG_NOWRITE, pid_file);
    }
  }

  use_stderr = 0;               /* Stop writing to stderr now */
  if (backgrd) {
    /* Ok, try to disassociate from controlling terminal (finger cross) */
    setpgid(0, 0);
    /* Tcl wants the stdin, stdout and stderr file handles kept open. */
    if (freopen("/dev/null", "r", stdin) == nullptr) {
      putlog(LOG_MISC, "*", "Error renaming stdin file handle: %s", strerror(errno));
    }
    if (freopen("/dev/null", "w", stdout) == nullptr) {
      putlog(LOG_MISC, "*", "Error renaming stdout file handle: %s", strerror(errno));
    }
    if (freopen("/dev/null", "w", stderr) == nullptr) {
      putlog(LOG_MISC, "*", "Error renaming stderr file handle: %s", strerror(errno));
    }
  }

  /* Terminal emulating dcc chat */
  if (!backgrd && term_z >= 0) {
    /* reuse term_z as glob var to pass it's index in the dcc table around */
    term_z = new_dcc(&DCC_CHAT, sizeof(struct chat_info));

    /* new_dcc returns -1 on error */
    if (term_z < 0)
      fatal("ERROR: Failed to initialize foreground chat.", 0);

    getvhost(&dcc[term_z].sockname, AF_INET);
    dcc[term_z].sock = STDOUT;
    dcc[term_z].timeval = now;
    dcc[term_z].u.chat->con_flags = conmask | EGG_BG_CONMASK;
    dcc[term_z].status = STAT_ECHO;
    if (isatty(dcc[term_z].sock)) {
      debug0("stdout is a tty");
      dcc[term_z].status |= STAT_TELNET;
    } else {
      debug0("stdout is no tty");
      dcc[term_z].u.chat->strip_flags = STRIP_ALL;
    }
    op_strlcpy(dcc[term_z].nick, EGG_BG_HANDLE, sizeof(dcc[term_z].nick));
    op_strlcpy(dcc[term_z].host, "llama@console", sizeof(dcc[term_z].host));
    add_hq_user();
    setsock(STDOUT, 0);          /* Entry in net table */
    dprintf(term_z, "\n### ENTERING DCC CHAT SIMULATION ###\n");
    dprintf(term_z, "You can use the .su command to log into your Eggdrop account.\n\n");
    dcc_chatter(term_z);
  }

  /* -1 to make mainloop() call
   * call_hook(HOOK_SECONDLY)->server_secondly()->connect_server() before first
   * sockgets()->sockread()->select() to avoid an unnecessary select timeout of
   * up to 1 sec while starting up
   */
  then = now - 1;

  online_since = now;
  autolink_cycle(nullptr);         /* Hurry and connect to tandem bots */
  add_help_reference("cmds1.help");
  add_help_reference("cmds2.help");
  add_help_reference("core.help");
  add_hook(HOOK_SECONDLY, (Function) core_secondly);
  add_hook(HOOK_MINUTELY, (Function) core_minutely);
  add_hook(HOOK_HOURLY, (Function) core_hourly);
  add_hook(HOOK_REHASH, (Function) event_rehash);
  add_hook(HOOK_PRE_REHASH, (Function) event_prerehash);
  add_hook(HOOK_USERFILE, (Function) event_save);
  add_hook(HOOK_BACKUP, (Function) backup_userfile);
  add_hook(HOOK_DAILY, (Function) event_logfile);
  add_hook(HOOK_DAILY, (Function) egg_perf_reset_traffic);
  add_hook(HOOK_LOADED, (Function) event_loaded);

  call_hook(HOOK_LOADED);

  /* Completion queue for worker→main thread callbacks */
  comqueue_init(4096);

  /* Worker thread pool — op_tpool with work-stealing */
  if (threadpool_init(nthreads) == 0)
    putlog(LOG_MISC, "*", "Thread pool: %d workers started", threadpool_size());

  /* Dedicated I/O poll thread: epoll_wait runs concurrently with dispatch */
  if (op_start_pollthread())
    putlog(LOG_MISC, "*", "I/O poll thread started");
  else
    putlog(LOG_MISC, "*", "I/O poll thread unavailable (epoll backend required)");

#ifdef HAVE_PLEDGE
  /* OpenBSD: drop to minimal privileges before entering the event loop.
   * stdio — printf/putlog, rpath/wpath/cpath — userfile/chanfile I/O,
   * inet — network sockets, dns — hostname resolution, proc — fork (bg),
   * unix — AF_UNIX for local DCC if ever needed. */
  if (pledge("stdio rpath wpath cpath inet dns proc unix", nullptr) == -1)
    fatal("pledge", 0);
#endif

  debug0("main: entering loop");
  while (1) {
    mainloop(1);
  }
}

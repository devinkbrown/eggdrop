/*
 * tclmisc.c -- handles:
 *   Tcl stubs for everything else
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

#include <errno.h>
#include "main.h"
#include "modules.h"
#include "md5/md5.h"
#include <sys/stat.h>
#include <sys/utsname.h>
#ifdef TLS
#  include <opssl/opssl.h>
#endif
#include <op_async.h>
#include <op_thread_pool.h>
#include "perf.h"
#include "threadpool.h"
#include "comqueue.h"
#include "async_log.h"

/* Tcl command handlers. In non-Tcl builds these compile as dead code
 * (lush.h stubs all Tcl API calls; add_tcl_commands is a no-op).
 */

extern op_vec_t bind_table_vec;
extern op_vec_t timer, utimer;
extern struct dcc_t *dcc;
extern char botnetnick[], quit_msg[];
extern struct userrec *userlist;
extern time_t now;
extern op_vec_t module_vec;
extern op_vec_t dep_vec;
extern int max_logs, cache_hit, cache_miss;
extern log_t *logs;
extern Tcl_Interp *interp;

/*
 *      Logging
 */

/* logfile [<modes> <channel> <filename>] */
static int tcl_logfile STDVAR
{
  BADARGS(1, 4, " ?logModes channel logFile?");

  if (argc == 1) {
    /* They just want a list of the logfiles and modes */
    for (int i = 0; i < max_logs; i++)
      if (logs[i].filename != nullptr) {
        {
          op_strbuf_t logline = {};
          op_strbuf_init(&logline);
          op_strbuf_appendf(&logline, "%s %s %s", masktype(logs[i].mask),
                           logs[i].chname, logs[i].filename);
          Tcl_AppendElement(interp, op_strbuf_str(&logline));
          op_strbuf_free(&logline);
        }
      }
    return TCL_OK;
  }

  BADARGS(4, 4, " ?logModes channel logFile?");

  if (*argv[1] && !*argv[2]) {
    Tcl_AppendResult(interp,
                     "log modes set, but no channel specified", nullptr);
    return TCL_ERROR;
  }
  if (*argv[2] && !strchr(CHANMETA, *argv[2]) && strcmp(argv[2], "*")) {
    Tcl_AppendResult(interp, "invalid channel prefix", nullptr);
    return TCL_ERROR;
  }
  if (*argv[2] && strchr(argv[2], ' ')) {
    Tcl_AppendResult(interp, "channel names cannot contain spaces", nullptr);
    return TCL_ERROR;
  }

  for (int i = 0; i < max_logs; i++)
    if ((logs[i].filename != nullptr) && (!strcmp(logs[i].filename, argv[3]))) {
      logs[i].flags &= ~LF_EXPIRING;
      logs[i].mask = logmodes(argv[1]);
      op_free(logs[i].chname);
      logs[i].chname = nullptr;
      if (!logs[i].mask) {
        /* ending logfile */
        op_free(logs[i].filename);
        logs[i].filename = nullptr;
        if (logs[i].f != nullptr) {
          fclose(logs[i].f);
          logs[i].f = nullptr;
        }
        logs[i].flags = 0;
      } else {
        logs[i].chname = op_strdup(argv[2]);
      }
      Tcl_AppendResult(interp, argv[3], nullptr);
      return TCL_OK;
    }
  /* Do not add logfiles without any flags to log ++rtc */
  if (!logmodes(argv[1])) {
    Tcl_AppendResult(interp, "can't remove \"", argv[3],
                     "\" from list: no such logfile", nullptr);
    return TCL_ERROR;
  }
  for (int i = 0; i < max_logs; i++)
    if (logs[i].filename == nullptr) {
      logs[i].flags = 0;
      logs[i].mask = logmodes(argv[1]);
      logs[i].filename = op_strdup(argv[3]);
      logs[i].chname = op_strdup(argv[2]);
      Tcl_AppendResult(interp, argv[3], nullptr);
      return TCL_OK;
    }
  Tcl_AppendResult(interp, "reached max # of logfiles", nullptr);
  return TCL_ERROR;
}

static int tcl_putlog STDVAR
{
  BADARGS(2, 2, " text");

  putlog(LOG_MISC, "*", "%s", argv[1]);
  return TCL_OK;
}

static int tcl_putcmdlog STDVAR
{
  BADARGS(2, 2, " text");

  putlog(LOG_CMDS, "*", "%s", argv[1]);
  return TCL_OK;
}

static int tcl_putxferlog STDVAR
{
  BADARGS(2, 2, " text");

  putlog(LOG_FILES, "*", "%s", argv[1]);
  return TCL_OK;
}

static int tcl_putloglev STDVAR
{
  int lev = 0;

  BADARGS(4, 4, " flag(s) channel text");

  lev = logmodes(argv[1]);
  if (!lev) {
    Tcl_AppendResult(irp, "No valid log flag given", nullptr);
    return TCL_ERROR;
  }
  putlog(lev, argv[2], "%s", argv[3]);
  return TCL_OK;
}

static int tcl_binds STDVAR
{
  int matching = 0;
  char *g, flg[100];
  EGG_CONST char *list[5];
  tcl_bind_list_t *tl, *tl_kind;
  tcl_bind_mask_t *tm;
  tcl_cmd_t *tc;

  BADARGS(1, 2, " ?type/mask?");

  if (argv[1])
    tl_kind = find_bind_table(argv[1]);
  else
    tl_kind = nullptr;
  if (!tl_kind && argv[1])
    matching = 1;
  size_t num_tl = tl_kind ? 1 : bind_table_vec.size;
  for (size_t ti = 0; ti < num_tl; ti++) {
    tl = tl_kind ? tl_kind : (tcl_bind_list_t *)op_vec_get(&bind_table_vec, ti);
    if (tl->flags & HT_DELETED)
      continue;
    for (size_t mi = 0; mi < tl->masks.size; mi++) {
      tm = (tcl_bind_mask_t *)op_vec_get(&tl->masks, mi);
      if (tm->flags & TBM_DELETED)
        continue;
      for (size_t ci = 0; ci < tm->cmds.size; ci++) {
        tc = (tcl_cmd_t *)op_vec_get(&tm->cmds, ci);
        if (tc->attributes & TC_DELETED)
          continue;
        if (matching &&
            !wild_match_per(argv[1], tl->name) &&
            !wild_match_per(argv[1], tm->mask) &&
            !wild_match_per(argv[1], tc->func_name))
          continue;
        build_flags(flg, &(tc->flags), nullptr);
        list[0] = tl->name;
        list[1] = flg;
        list[2] = tm->mask;
        list[3] = int_to_base10((int) tc->hits);
        list[4] = tc->func_name;
        g = Tcl_Merge(5, list);
        Tcl_AppendElement(irp, g);
        Tcl_Free((char *) g);
      }
    }
  }
  return TCL_OK;
}

int check_timer_syntax(Tcl_Interp *irp, int argc, char *argv[], op_vec_t *stack) {
  char *endptr;
  long val;

  if (egg_atoi(argv[1]) < 0) {
    Tcl_AppendResult(irp, "time value must be positive", nullptr);
    return 1;
  }
  if (argc >=4) {
    val = strtol(argv[3], &endptr, 0);
    if ((*endptr != '\0') || (val < 0)) {
      Tcl_AppendResult(irp, "count value must be >=0", nullptr);
      return 1;
    }
  }
  if (argv[2][0] != '#') {
    if (argc == 5) {
      /* Prevent collisions with unnamed timers */
      if (strncmp(argv[4], "timer", 5) == 0) {
        Tcl_AppendResult(irp, "timer name may not begin with \"timer\"", nullptr);
        return 1;
      }
      /* Check for existing timers by same name */
      if (find_timer(stack, argv[4])) {
        Tcl_AppendResult(irp, "timer already exists by that name", nullptr);
        return 1;
      }
    }
  }
  return 0;
}

static int tcl_timer STDVAR
{
  char *x;

  BADARGS(3, 5, " minutes command ?count ?name??");

  if (check_timer_syntax(irp, argc, argv, &timer)) {
    return TCL_ERROR;
  }
  x = add_timer(&timer, egg_atoi(argv[1]), (argc >= 4 ? egg_atoi(argv[3]) : 1),
                  argv[2], (argc == 5 ? argv[4] : nullptr), 0L);
  if (!x) {
    Tcl_AppendResult(irp, "Too many timers (wow, impressive). Timer not added", nullptr);
    return TCL_ERROR;
  }
  Tcl_AppendResult(irp, x, nullptr);
  return TCL_OK;
}

static int tcl_utimer STDVAR
{
  char *x;

  BADARGS(3, 5, " seconds command ?count ?name??");

  if (check_timer_syntax(irp, argc, argv, &utimer)) {
    return TCL_ERROR;
  }
  x = add_timer(&utimer, egg_atoi(argv[1]), (argc >= 4 ? egg_atoi(argv[3]) : 1),
                  argv[2], (argc == 5 ? argv[4] : '\0'), 0L);
  if (!x) {
    Tcl_AppendResult(irp, "Too many timers (wow, impressive). Timer not added", nullptr);
    return TCL_ERROR;
  }
  Tcl_AppendResult(irp, x, nullptr);
  return TCL_OK;
}

static int tcl_killtimer STDVAR
{
  BADARGS(2, 2, " timerID");

  if (remove_timer(&timer, argv[1]))
    return TCL_OK;
  Tcl_AppendResult(irp, "invalid timer name", nullptr);
  return TCL_ERROR;
}

static int tcl_killutimer STDVAR
{
  BADARGS(2, 2, " timerName");

  if (remove_timer(&utimer, argv[1])) {
    return TCL_OK;
  }
  Tcl_AppendResult(irp, "invalid utimer name", nullptr);
  return TCL_ERROR;
}

static int tcl_timers STDVAR
{
  BADARGS(1, 1, "");

  list_timers(irp, &timer);
  return TCL_OK;
}

static int tcl_utimers STDVAR
{
  BADARGS(1, 1, "");

  list_timers(irp, &utimer);
  return TCL_OK;
}

static int tcl_duration STDVAR
{
  char buf[256];

  BADARGS(2, 2, " seconds");

  long val = atol(argv[1]);
  egg_format_duration(val > 0 ? (uint64_t)val : 0, buf, sizeof buf);
  Tcl_AppendResult(irp, buf, nullptr);
  return TCL_OK;
}

static int tcl_unixtime STDVAR
{
  BADARGS(1, 1, "");

  Tcl_SetObjResult(irp, Tcl_NewWideIntObj((Tcl_WideInt)(int64_t) time(nullptr)));
  return TCL_OK;
}

static int tcl_ctime STDVAR
{
  time_t tt;
  char s[26];

  BADARGS(2, 2, " unixtime");

  tt = (time_t) atol(argv[1]);
  ctime_r(&tt, s);
  s[24] = 0;
  Tcl_AppendResult(irp, s, nullptr);
  return TCL_OK;
}

static int tcl_strftime STDVAR
{
  char buf[512];
  struct tm *tm1;
  time_t t;

  BADARGS(2, 3, " format ?time?");

  if (argc == 3)
    t = atol(argv[2]);
  else
    t = now;
  tm1 = localtime(&t);
  if (!tm1) {
    Tcl_AppendResult(irp, "tcl_strftime(): localtime(): error = ",
                     strerror(errno), nullptr);
    return TCL_ERROR;
  }
  if (strftime(buf, sizeof(buf) - 1, argv[1], tm1)) {
    Tcl_AppendResult(irp, buf, nullptr);
    return TCL_OK;
  }
  Tcl_AppendResult(irp, "tcl_strftime(): strftime(): error", nullptr);
  return TCL_ERROR;
}

static int tcl_myip STDVAR
{
  char s[EGG_INET_ADDRSTRLEN];

  BADARGS(1, 1, "");

  getdccaddr(nullptr, s, sizeof s);
  Tcl_AppendResult(irp, s, nullptr);
  return TCL_OK;
}

static int tcl_rand STDVAR
{
  long i;
  [[maybe_unused]] uint64_t x;

  BADARGS(2, 2, " limit");

  i = atol(argv[1]);

  if (i <= 0) {
    Tcl_AppendResult(irp, "random limit must be greater than 0", nullptr);
    return TCL_ERROR;
  } else if (i > RANDOM_MAX) {
    Tcl_AppendResult(irp, "random limit must be equal to or less than ",
                     int_to_base10(RANDOM_MAX), nullptr);
    return TCL_ERROR;
  }

  x = randint(i);

  Tcl_SetObjResult(irp, Tcl_NewWideIntObj((Tcl_WideInt) x));
  return TCL_OK;
}

static int tcl_sendnote STDVAR
{
  BADARGS(4, 4, " from to message");

  Tcl_SetObjResult(irp, Tcl_NewIntObj(add_note(argv[2], argv[1], argv[3], -1, 0)));
  return TCL_OK;
}

static int tcl_dumpfile STDVAR
{
  struct flag_record fr = { FR_GLOBAL | FR_CHAN };

  BADARGS(3, 3, " nickname filename");

  get_user_flagrec(get_user_by_nick(argv[1]), &fr, nullptr);
  showhelp(argv[1], argv[2], &fr, HELP_TEXT);
  return TCL_OK;
}

static int tcl_dccdumpfile STDVAR
{
  int idx, i;
  struct flag_record fr = { FR_GLOBAL | FR_CHAN | FR_ANYWH };

  BADARGS(3, 3, " idx filename");

  i = egg_atoi(argv[1]);
  idx = findidx(i);
  if (idx < 0) {
    Tcl_AppendResult(irp, "illegal idx", nullptr);
    return TCL_ERROR;
  }
  get_user_flagrec(get_user_by_handle(userlist, dcc[idx].nick), &fr, nullptr);

  tellhelp(idx, argv[2], &fr, HELP_TEXT);
  return TCL_OK;
}

static int tcl_backup STDVAR
{
  BADARGS(1, 1, "");

  call_hook(HOOK_BACKUP);
  return TCL_OK;
}

static int tcl_die STDVAR
{
  op_strbuf_t s = {};
  op_strbuf_init(&s);

  BADARGS(1, 2, " ?reason?");

  if (argc == 2) {
    op_strbuf_appendf(&s, "BOT SHUTDOWN (%s)", argv[1]);
    op_strlcpy(quit_msg, argv[1], 1024);
  } else {
    op_strbuf_append_cstr(&s, "BOT SHUTDOWN (No reason)");
    quit_msg[0] = 0;
  }
  kill_bot(op_strbuf_str(&s), quit_msg[0] ? quit_msg : "EXIT");
  op_strbuf_free(&s);
  return TCL_OK;
}

static int tcl_loadmodule STDVAR
{
  const char *p;

  BADARGS(2, 2, " module-name");

  p = module_load(argv[1]);
  if (p && strcmp(p, MOD_ALREADYLOAD) && !strcmp(argv[0], "loadmodule"))
    putlog(LOG_MISC, "*", "%s %s: %s", MOD_CANTLOADMOD, argv[1], p);
  Tcl_AppendResult(irp, p, nullptr);
  return TCL_OK;
}

static int tcl_unloadmodule STDVAR
{
  BADARGS(2, 2, " module-name");

  Tcl_AppendResult(irp, module_unload(argv[1], botnetnick), nullptr);
  return TCL_OK;
}

static int tcl_unames STDVAR
{
  Tcl_AppendResult(irp, egg_uname(), nullptr);
  return TCL_OK;
}

static int tcl_modules STDVAR
{
  int i;
  char *p;
  EGG_CONST char *list[100], *list2[2];
  dependancy *dep;
  module_entry *current;

  BADARGS(1, 1, "");

  for (size_t _mi = 0; _mi < module_vec.size; _mi++) {
    current = (module_entry *)op_vec_get(&module_vec, _mi);
    list[0] = current->name;
    op_strbuf_t ver = {};
    op_strbuf_init(&ver);
    op_strbuf_appendf(&ver, "%d.%d", current->major, current->minor);
    list[1] = op_strbuf_str(&ver);
    i = 2;
    for (size_t _di = 0; _di < dep_vec.size && i < 100; _di++) {
      dep = (dependancy *)op_vec_get(&dep_vec, _di);
      if (dep->needing == current) {
        list2[0] = dep->needed->name;
        op_strbuf_t depver = {};
        op_strbuf_init(&depver);
        op_strbuf_appendf(&depver, "%d.%d", dep->major, dep->minor);
        list2[1] = op_strbuf_str(&depver);
        list[i] = Tcl_Merge(2, list2);
        op_strbuf_free(&depver);
        i++;
      }
    }
    p = Tcl_Merge(i, list);
    op_strbuf_free(&ver);
    Tcl_AppendElement(irp, p);
    Tcl_Free((char *) p);
    while (i > 2) {
      i--;
      Tcl_Free((char *) list[i]);
    }
  }
  return TCL_OK;
}

static int tcl_loadhelp STDVAR
{
  BADARGS(2, 2, " helpfile-name");

  add_help_reference(argv[1]);
  return TCL_OK;
}

static int tcl_unloadhelp STDVAR
{
  BADARGS(2, 2, " helpfile-name");

  rem_help_reference(argv[1]);
  return TCL_OK;
}

static int tcl_reloadhelp STDVAR
{
  BADARGS(1, 1, "");

  reload_help_data();
  return TCL_OK;
}

static int tcl_callevent STDVAR
{
  BADARGS(2, 3, " event ?arg?");

  if (argc == 2) {
    check_tcl_event(argv[1]);
  } else {
    check_tcl_event_arg(argv[1], argv[2]);
  }
  return TCL_OK;
}

static int tcl_stripcodes STDVAR
{
  int flags = 0;
  char *p;

  BADARGS(3, 3, " strip-flags string");

  for (p = argv[1]; *p; p++)
    switch (*p) {
    case 'c':
      flags |= STRIP_COLOR;
      break;
    case 'b':
      flags |= STRIP_BOLD;
      break;
    case 'r':
      flags |= STRIP_REVERSE;
      break;
    case 'u':
      flags |= STRIP_UNDERLINE;
      break;
    case 'a':
      flags |= STRIP_ANSI;
      break;
    case 'g':
      flags |= STRIP_BELLS;
      break;
    case 'o':
      flags |= STRIP_ORDINARY;
      break;
    case 'i':
      flags |= STRIP_ITALICS;
      break;
    case '*':
      flags |= STRIP_ALL;
      break;
    default:
      Tcl_AppendResult(irp, "Invalid strip-flags: ", argv[1], nullptr);
      return TCL_ERROR;
    }

  p = Tcl_Alloc(strlen(argv[2]) + 1);
  op_strlcpy(p, argv[2], sizeof(p));
  strip_mirc_codes(flags, p);
  Tcl_SetResult(irp, p, TCL_DYNAMIC);
  return TCL_OK;
}

static int tcl_md5 STDVAR
{
  [[maybe_unused]] char digest_string[33];
  unsigned char digest[16];
  BADARGS(2, 2, " string");

  MD5_CTX md5context;
  MD5_Init(&md5context);
  MD5_Update(&md5context, (unsigned char *) argv[1], strlen(argv[1]));
  MD5_Final(digest, &md5context);

  for (int i = 0; i < 16; i++) {
    static const char hex[] = "0123456789abcdef";
    digest_string[i * 2]     = hex[(digest[i] >> 4) & 0xf];
    digest_string[i * 2 + 1] = hex[digest[i] & 0xf];
  }
  digest_string[32] = '\0';
  Tcl_AppendResult(irp, digest_string, nullptr);
  return TCL_OK;
}

static int tcl_matchaddr STDVAR
{
  BADARGS(3, 3, " mask address");

  if (match_addr(argv[1], argv[2]))
    Tcl_AppendResult(irp, "1", nullptr);
  else
    Tcl_AppendResult(irp, "0", nullptr);
  return TCL_OK;
}

static int tcl_matchcidr STDVAR
{
  BADARGS(4, 4, " block address prefix");

  if (cidr_match(argv[1], argv[2], egg_atoi(argv[3])))
    Tcl_AppendResult(irp, "1", nullptr);
  else
    Tcl_AppendResult(irp, "0", nullptr);
  return TCL_OK;
}

static int tcl_matchstr STDVAR
{
  BADARGS(3, 3, " pattern string");

  if (wild_match(argv[1], argv[2]))
    Tcl_AppendResult(irp, "1", nullptr);
  else
    Tcl_AppendResult(irp, "0", nullptr);
  return TCL_OK;
}

static int tcl_status STDVAR
{
  BADARGS(1, 2, " ?type?");

  if ((argc < 2) || !strcmp(argv[1], "cpu")) {
    op_strbuf_t cpu_buf = {};
    op_strbuf_init(&cpu_buf);
    Tcl_AppendElement(irp, "cputime");
    op_strbuf_appendf(&cpu_buf, "%f", getcputime());
    Tcl_AppendElement(irp, op_strbuf_str(&cpu_buf));
    op_strbuf_free(&cpu_buf);
  }
  if ((argc < 2) || !strcmp(argv[1], "mem")) {
    Tcl_AppendElement(irp, "rss_kb");
    Tcl_AppendElement(irp, int_to_base10((int) egg_get_rss_kb()));
  }
  if ((argc < 2) || !strcmp(argv[1], "ipv6")) {
    Tcl_AppendElement(irp, "ipv6");
#ifdef IPV6
    Tcl_AppendElement(irp, "enabled");
#else
    Tcl_AppendElement(irp, "disabled");
#endif
  }
  if ((argc < 2) || !strcmp(argv[1], "tls")) {
    Tcl_AppendElement(irp, "tls");
#ifdef TLS
    {
      op_strbuf_t tls_ver = {};
      op_strbuf_init(&tls_ver);
      op_strbuf_appendf(&tls_ver, "opssl %s", opssl_version_string());
      Tcl_AppendElement(irp, op_strbuf_str(&tls_ver));
      op_strbuf_free(&tls_ver);
    }
#else
    Tcl_AppendElement(irp, "disabled");
#endif
  }
  if ((argc < 2) || !strcmp(argv[1], "cache")) {
    op_strbuf_t cache_buf = {};
    op_strbuf_init(&cache_buf);
    Tcl_AppendElement(irp, "usercache");
    op_strbuf_appendf(&cache_buf, "%4.1f", 100.0 *
                     ((float) cache_hit) / ((float) (cache_hit + cache_miss)));
    Tcl_AppendElement(irp, op_strbuf_str(&cache_buf));
    op_strbuf_free(&cache_buf);
  }

  return TCL_OK;
}

static int tcl_rfcequal STDVAR
{
  BADARGS(3, 3, " string1 string2");

  Tcl_AppendResult(irp, !rfc_casecmp(argv[1], argv[2]) ? "1" : "0", nullptr);

  return TCL_OK;
}

static const char *worker_state_str(int state)
{
  switch (state) {
  case 0:  return "idle";
  case 1:  return "draining";
  case 2:  return "dispatching";
  case 3:  return "stealing";
  default: return "unknown";
  }
}

static int tcl_threadinfo STDVAR
{
  BADARGS(1, 1, "");

  Tcl_AppendElement(irp, "pool_active");
  Tcl_AppendElement(irp, op_async_active() ? "1" : "0");

  Tcl_AppendElement(irp, "pool_threads");
  Tcl_AppendElement(irp, int_to_base10(op_async_nthreads()));

  op_strbuf_t pending_buf = {};
  op_strbuf_init(&pending_buf);
  Tcl_AppendElement(irp, "pool_pending");
  op_strbuf_appendf(&pending_buf, "%zu", op_async_pending());
  Tcl_AppendElement(irp, op_strbuf_str(&pending_buf));
  op_strbuf_free(&pending_buf);

  /* DCC handler thread pool (eggdrop's own op_tpool, separate from op_async) */
  Tcl_AppendElement(irp, "dcc_pool_active");
  Tcl_AppendElement(irp, threadpool_active() ? "1" : "0");

  Tcl_AppendElement(irp, "dcc_pool_threads");
  Tcl_AppendElement(irp, int_to_base10(threadpool_size()));

  {
    op_strbuf_t dcc_buf = {};
    op_strbuf_init(&dcc_buf);
    Tcl_AppendElement(irp, "dcc_pool_pending");
    op_strbuf_appendf(&dcc_buf, "%d", threadpool_pending());
    Tcl_AppendElement(irp, op_strbuf_str(&dcc_buf));
    op_strbuf_free(&dcc_buf);
  }

  /* Completion queue depth (worker→main callbacks awaiting drain) */
  {
    op_strbuf_t cq_buf = {};
    op_strbuf_init(&cq_buf);
    Tcl_AppendElement(irp, "comqueue_pending");
    op_strbuf_appendf(&cq_buf, "%d", comqueue_pending());
    Tcl_AppendElement(irp, op_strbuf_str(&cq_buf));
    op_strbuf_free(&cq_buf);
  }

  /* Async log writer */
  Tcl_AppendElement(irp, "async_log_active");
  Tcl_AppendElement(irp, async_log_active() ? "1" : "0");

  {
    struct egg_perf_metrics pm = egg_perf_snapshot();
    uint64_t avg_ns = pm.tick_count ? pm.tick_ns_total / pm.tick_count : 0;
    op_strbuf_t pbuf = {};
    op_strbuf_init(&pbuf);

    Tcl_AppendElement(irp, "tick_count");
    op_strbuf_appendf(&pbuf, "%llu", (unsigned long long)pm.tick_count);
    Tcl_AppendElement(irp, op_strbuf_str(&pbuf));
    op_strbuf_free(&pbuf);

    Tcl_AppendElement(irp, "tick_avg_us");
    op_strbuf_appendf(&pbuf, "%llu", (unsigned long long)(avg_ns / 1000));
    Tcl_AppendElement(irp, op_strbuf_str(&pbuf));
    op_strbuf_free(&pbuf);

    Tcl_AppendElement(irp, "tick_max_us");
    op_strbuf_appendf(&pbuf, "%llu", (unsigned long long)(pm.tick_ns_max / 1000));
    Tcl_AppendElement(irp, op_strbuf_str(&pbuf));
    op_strbuf_free(&pbuf);

    Tcl_AppendElement(irp, "tick_last_us");
    op_strbuf_appendf(&pbuf, "%llu", (unsigned long long)(pm.tick_ns_last / 1000));
    Tcl_AppendElement(irp, op_strbuf_str(&pbuf));
    op_strbuf_free(&pbuf);

    Tcl_AppendElement(irp, "idle_ticks");
    op_strbuf_appendf(&pbuf, "%llu", (unsigned long long)pm.idle_ticks);
    Tcl_AppendElement(irp, op_strbuf_str(&pbuf));
    op_strbuf_free(&pbuf);

    Tcl_AppendElement(irp, "arena_allocs");
    op_strbuf_appendf(&pbuf, "%llu", (unsigned long long)pm.arena_allocs);
    Tcl_AppendElement(irp, op_strbuf_str(&pbuf));
    op_strbuf_free(&pbuf);

    Tcl_AppendElement(irp, "arena_bytes");
    op_strbuf_appendf(&pbuf, "%llu", (unsigned long long)pm.arena_bytes);
    Tcl_AppendElement(irp, op_strbuf_str(&pbuf));
    op_strbuf_free(&pbuf);

    Tcl_AppendElement(irp, "arena_overflows");
    op_strbuf_appendf(&pbuf, "%llu", (unsigned long long)pm.arena_overflows);
    Tcl_AppendElement(irp, op_strbuf_str(&pbuf));
    op_strbuf_free(&pbuf);

    Tcl_AppendElement(irp, "arena_peak_bytes");
    op_strbuf_appendf(&pbuf, "%llu", (unsigned long long)pm.arena_peak_bytes);
    Tcl_AppendElement(irp, op_strbuf_str(&pbuf));
    op_strbuf_free(&pbuf);

    Tcl_AppendElement(irp, "tick_hist");
    op_strbuf_appendf(&pbuf, "<%s:%llu <%s:%llu <%s:%llu <%s:%llu >=%s:%llu",
      "10us",  (unsigned long long)pm.tick_hist[0],
      "100us", (unsigned long long)pm.tick_hist[1],
      "1ms",   (unsigned long long)pm.tick_hist[2],
      "10ms",  (unsigned long long)pm.tick_hist[3],
      "10ms",  (unsigned long long)pm.tick_hist[4]);
    Tcl_AppendElement(irp, op_strbuf_str(&pbuf));
    op_strbuf_free(&pbuf);

    Tcl_AppendElement(irp, "bind_dispatches");
    op_strbuf_appendf(&pbuf, "%llu", (unsigned long long)pm.bind_dispatches);
    Tcl_AppendElement(irp, op_strbuf_str(&pbuf));
    op_strbuf_free(&pbuf);

    Tcl_AppendElement(irp, "bind_exact_hits");
    op_strbuf_appendf(&pbuf, "%llu", (unsigned long long)pm.bind_exact_hits);
    Tcl_AppendElement(irp, op_strbuf_str(&pbuf));
    op_strbuf_free(&pbuf);

    Tcl_AppendElement(irp, "bind_scan_hits");
    op_strbuf_appendf(&pbuf, "%llu", (unsigned long long)pm.bind_scan_hits);
    Tcl_AppendElement(irp, op_strbuf_str(&pbuf));
    op_strbuf_free(&pbuf);

    Tcl_AppendElement(irp, "traffic_in_bps");
    op_strbuf_appendf(&pbuf, "%llu", (unsigned long long)pm.traffic_in_last_sec);
    Tcl_AppendElement(irp, op_strbuf_str(&pbuf));
    op_strbuf_free(&pbuf);

    Tcl_AppendElement(irp, "traffic_out_bps");
    op_strbuf_appendf(&pbuf, "%llu", (unsigned long long)pm.traffic_out_last_sec);
    Tcl_AppendElement(irp, op_strbuf_str(&pbuf));
    op_strbuf_free(&pbuf);
  }

  int nth = op_async_nthreads();
  if (nth > 0) {
    op_tpool_worker_stats_t stats[16];
    int n = op_async_get_stats(stats, nth < 16 ? nth : 16);
    for (int i = 0; i < n; i++) {
      op_strbuf_t wbuf = {};
      op_strbuf_init(&wbuf);
      op_strbuf_appendf(&wbuf, "worker_%d", stats[i].id);
      Tcl_AppendElement(irp, op_strbuf_str(&wbuf));
      op_strbuf_free(&wbuf);

      op_strbuf_t vbuf = {};
      op_strbuf_init(&vbuf);
      op_strbuf_appendf(&vbuf, "%s dispatched:%llu stolen:%llu fast:%llu",
                        worker_state_str(stats[i].state),
                        (unsigned long long)stats[i].dispatched,
                        (unsigned long long)stats[i].stolen,
                        (unsigned long long)stats[i].fast_path);
      Tcl_AppendElement(irp, op_strbuf_str(&vbuf));
      op_strbuf_free(&vbuf);
    }
  }

  return TCL_OK;
}

tcl_cmds tclmisc_cmds[] = {
  {"logfile",           tcl_logfile},
  {"putlog",             tcl_putlog},
  {"putcmdlog",       tcl_putcmdlog},
  {"putxferlog",     tcl_putxferlog},
  {"putloglev",       tcl_putloglev},
  {"timer",               tcl_timer},
  {"utimer",             tcl_utimer},
  {"killtimer",       tcl_killtimer},
  {"killutimer",     tcl_killutimer},
  {"timers",             tcl_timers},
  {"utimers",           tcl_utimers},
  {"unixtime",         tcl_unixtime},
  {"strftime",         tcl_strftime},
  {"ctime",               tcl_ctime},
  {"myip",                 tcl_myip},
  {"rand",                 tcl_rand},
  {"sendnote",         tcl_sendnote},
  {"dumpfile",         tcl_dumpfile},
  {"dccdumpfile",   tcl_dccdumpfile},
  {"backup",             tcl_backup},
  {"exit",                  tcl_die},
  {"die",                   tcl_die},
  {"unames",             tcl_unames},
  {"unloadmodule", tcl_unloadmodule},
  {"loadmodule",     tcl_loadmodule},
  {"checkmodule",    tcl_loadmodule},
  {"modules",           tcl_modules},
  {"loadhelp",         tcl_loadhelp},
  {"unloadhelp",     tcl_unloadhelp},
  {"reloadhelp",     tcl_reloadhelp},
  {"duration",         tcl_duration},
  {"binds",               tcl_binds},
  {"callevent",       tcl_callevent},
  {"stripcodes",     tcl_stripcodes},
  {"matchaddr",       tcl_matchaddr},
  {"matchcidr",       tcl_matchcidr},
  {"matchstr",         tcl_matchstr},
  {"status",             tcl_status},
  {"rfcequal",         tcl_rfcequal},
  {"md5",                   tcl_md5},
  {"threadinfo",       tcl_threadinfo},
  {nullptr,                       nullptr}
};

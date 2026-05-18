/*
 * tcl.c -- handles:
 *   the code for every command eggdrop adds to Tcl
 *   Tcl initialization
 *   getting and setting Tcl/eggdrop variables
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

#include <stdlib.h>             /* getenv()                             */
#include <locale.h>             /* setlocale()                          */
#include "main.h"

/* Used for read/write to internal strings */
typedef struct {
  char *str;                    /* Pointer to actual string in eggdrop       */
  int max;                      /* max length (negative: read-only var
                                 * when protect is on) (0: read-only ALWAYS) */
  int flags;                    /* 1 = directory                             */
} strinfo;

typedef struct {
  int *var;
  int ro;
} intinfo;


extern time_t now, online_since;

extern char origbotname[], botuser[], motdfile[], admin[], userfile[],
            firewall[], helpdir[], notify_new[], vhost[], moddir[], owner[],
            network[], botnetnick[], bannerfile[], egg_version[], nat_ip[],
            configfile[], logfile_suffix[], log_ts[], textdir[], pid_file[],
            listen_ip[], stealth_prompt[], language[];

extern int flood_telnet_thr, flood_telnet_time, shtime, share_greet,
           require_p, keep_all_logs, allow_new_telnets, stealth_telnets,
           use_telnet_banner, default_flags, conmask, switch_logfiles_at,
           connect_timeout, firewallport, notify_users_at, flood_thr, tands,
           ignore_time, reserved_port_min, reserved_port_max, max_logs,
           max_logsize, dcc_total, raw_log, identtimeout, dcc_sanitycheck,
           dupwait_timeout, egg_numver, share_unlinks, protect_telnet,
           resolve_timeout, default_uflags, userfile_perm, cidr_support,
           remove_pass, show_uname;

#ifdef IPV6
extern char vhost6[];
extern int pref_af;
#endif

#ifdef TLS
extern int tls_maxdepth, tls_vfybots, tls_vfyclients, tls_vfydcc, tls_auth;
extern char tls_capath[], tls_cafile[], tls_certfile[], tls_keyfile[],
            tls_protocols[], tls_dhparam[], tls_ciphers[];
#endif

extern struct dcc_t *dcc;
extern op_vec_t timer, utimer;
extern char store_backend[], store_path[];

#ifdef HAVE_TCL
Tcl_Interp *interp;
#else
void *interp = nullptr;    /* nullptr when Tcl scripting is disabled */
#endif

int protect_readonly = 0; /* Enable read-only protection? */
char whois_fields[1025] = "";

int dcc_flood_thr = 3;
int use_invites = 0;
int use_exempts = 0;
int force_expire = 0;
int remote_boots = 2;
int allow_dk_cmds = 1;
int must_be_owner = 1;
int quiet_reject = 1;
int max_socks = 100;
extern int nthreads;
int par_telnet_flood = 1;
int quiet_save = 0;
int strtot = 0;
int handlen = HANDLEN;

#ifdef HAVE_TCL
extern Tcl_VarTraceProc traced_myiphostname, traced_natip, traced_remove_pass;

/* Unicode workaround for Tcl versions (8.5/8.6) that only support BMP characters (3 byte utf-8) */
#  if TCL_MAJOR_VERSION == 8 && TCL_MINOR_VERSION <= 6 && TCL_UTF_MAX < 4
#    define TCL_WORKAROUND_UNICODESUP 1
struct tcl_unicodesup_info {
  const char *subcmd;
  Tcl_Obj *cmd;
};
#  endif
#endif /* HAVE_TCL */



/* Variable mapping tables — shared between Tcl and no-TCL builds so
 * that notcl_setvar/notcl_getvar can find all registered C variables.
 * (In Tcl builds these are also used by init_traces() to install trace
 * callbacks; in no-TCL builds they are registered via init_tcl1().)
 */
static tcl_strings def_tcl_strings[] = {
  {"botnet-nick",     botnetnick,     HANDLEN,                 0},
  {"userfile",        userfile,       120,           STR_PROTECT},
  {"motd",            motdfile,       120,           STR_PROTECT},
  {"admin",           admin,          120,                     0},
  {"help-path",       helpdir,        120, STR_DIR | STR_PROTECT},
  {"text-path",       textdir,        120, STR_DIR | STR_PROTECT},
#ifdef TLS
  {"ssl-capath",      tls_capath,     120, STR_DIR | STR_PROTECT},
  {"ssl-cafile",      tls_cafile,     120,           STR_PROTECT},
  {"ssl-protocols",   tls_protocols,  60,            STR_PROTECT},
  {"ssl-dhparam",     tls_dhparam,    120,           STR_PROTECT},
  {"ssl-ciphers",     tls_ciphers,    2048,           STR_PROTECT},
  {"ssl-privatekey",  tls_keyfile,    120,           STR_PROTECT},
  {"ssl-certificate", tls_certfile,   120,           STR_PROTECT},
#endif
#ifndef STATIC
  {"mod-path",        moddir,         120, STR_DIR | STR_PROTECT},
#endif
  {"notify-newusers", notify_new,     120,                     0},
  {"owner",           owner,          120,           STR_PROTECT},
  {"vhost4",          vhost,          120,                     0},
#ifdef IPV6
  {"vhost6",          vhost6,         120,                     0},
#endif
  {"listen-addr",     listen_ip,      120,                     0},
  {"network",         network,        40,                      0},
  {"whois-fields",    whois_fields,   1024,                    0},
  {"nat-ip",          nat_ip,         INET_ADDRSTRLEN - 1,     0},
  {"username",        botuser,        USERLEN,                 0},
  {"version",         egg_version,    0,                       0},
  {"firewall",        firewall,       120,                     0},
  {"config",          configfile,     0,                       0},
  {"telnet-banner",   bannerfile,     120,           STR_PROTECT},
  {"logfile-suffix",  logfile_suffix, 20,                      0},
  {"timestamp-format",log_ts,         32,                      0},
  {"pidfile",         pid_file,       120,           STR_PROTECT},
  {"configureargs",   EGG_AC_ARGS,    0,             STR_PROTECT},
  {"stealth-prompt",  stealth_prompt, 80,                      0},
  {"language",        language,       64,            STR_PROTECT},
  {"store-backend",   store_backend,  15,            STR_PROTECT},
  {"store-path",      store_path,     120,           STR_PROTECT},
  {nullptr,              nullptr,           0,                       0}
};

static tcl_ints def_tcl_ints[] = {
  {"ignore-time",           &ignore_time,          0},
  {"handlen",               &handlen,              2},
#ifdef TLS
  {"ssl-chain-depth",       &tls_maxdepth,         0},
  {"ssl-verify-dcc",        &tls_vfydcc,           0},
  {"ssl-verify-clients",    &tls_vfyclients,       0},
  {"ssl-verify-bots",       &tls_vfybots,          0},
  {"ssl-cert-auth",         &tls_auth,             0},
#endif
  {"dcc-flood-thr",         &dcc_flood_thr,        0},
  {"hourly-updates",        &notify_users_at,      0},
  {"switch-logfiles-at",    &switch_logfiles_at,   0},
  {"connect-timeout",       &connect_timeout,      0},
  {"reserved-port",         &reserved_port_min,    0},
  {"require-p",             &require_p,            0},
  {"keep-all-logs",         &keep_all_logs,        0},
  {"open-telnets",          &allow_new_telnets,    0},
  {"stealth-telnets",       &stealth_telnets,      0},
  {"use-telnet-banner",     &use_telnet_banner,    0},
  {"uptime",                (int *) &online_since, 2},
  {"console",               &conmask,              0},
  {"default-flags",         &default_flags,        0},
  {"numversion",            &egg_numver,           2},
  {"remote-boots",          &remote_boots,         1},
  {"max-socks",             &max_socks,            0},
  {"max-logs",              &max_logs,             0},
  {"max-logsize",           &max_logsize,          0},
  {"raw-log",               &raw_log,              1},
  {"protect-telnet",        &protect_telnet,       0},
  {"dcc-sanitycheck",       &dcc_sanitycheck,      0},
  {"ident-timeout",         &identtimeout,         0},
  {"share-unlinks",         &share_unlinks,        0},
  {"log-time",              &shtime,               0},
  {"allow-dk-cmds",         &allow_dk_cmds,        0},
  {"resolve-timeout",       &resolve_timeout,      0},
  {"nthreads",              &nthreads,             0},
  {"must-be-owner",         &must_be_owner,        1},
  {"paranoid-telnet-flood", &par_telnet_flood,     0},
  {"use-exempts",           &use_exempts,          0},
  {"use-invites",           &use_invites,          0},
  {"quiet-save",            &quiet_save,           0},
  {"force-expire",          &force_expire,         0},
  {"dupwait-timeout",       &dupwait_timeout,      0},
  {"userfile-perm",         &userfile_perm,        0},
  {"quiet-reject",          &quiet_reject,         0},
  {"cidr-support",          &cidr_support,         0},
  {"remove-pass",           &remove_pass,          0},
#ifdef IPV6
  {"prefer-ipv6",           &pref_af,              0},
#endif
  {"show-uname",            &show_uname,           0},
  {"share-greet",           &share_greet,          0},
  {nullptr,                    nullptr,                  0}
};

static tcl_coups def_tcl_coups[] = {
  {"telnet-flood",       &flood_telnet_thr,  &flood_telnet_time},
  {"reserved-portrange", &reserved_port_min, &reserved_port_max},
  {nullptr,                 nullptr,                             nullptr}
};

#ifdef HAVE_TCL  /* ---- All Tcl-API-dependent code below ---- */

/* Locale → Tcl encoding mapping table; used during interpreter init.
 * From Tcl's tclUnixInit.c */
typedef struct LocaleTable {
  const char *lang;
  const char *encoding;
} LocaleTable;

static const LocaleTable localeTable[] = {
  {"ja_JP.SJIS",    "shiftjis"},
  {"ja_JP.EUC",       "euc-jp"},
  {"ja_JP.JIS",   "iso2022-jp"},
  {"ja_JP.mscode",  "shiftjis"},
  {"ja_JP.ujis",      "euc-jp"},
  {"ja_JP",           "euc-jp"},
  {"Ja_JP",         "shiftjis"},
  {"Jp_JP",         "shiftjis"},
  {"japan",           "euc-jp"},
#ifdef hpux
  {"japanese",      "shiftjis"},
  {"ja",            "shiftjis"},
#else
  {"japanese",        "euc-jp"},
  {"ja",              "euc-jp"},
#endif
  {"japanese.sjis", "shiftjis"},
  {"japanese.euc",    "euc-jp"},
  {"japanese-sjis", "shiftjis"},
  {"japanese-ujis",   "euc-jp"},
  {"ko",              "euc-kr"},
  {"ko_KR",           "euc-kr"},
  {"ko_KR.EUC",       "euc-kr"},
  {"ko_KR.euc",       "euc-kr"},
  {"ko_KR.eucKR",     "euc-kr"},
  {"korean",          "euc-kr"},
  {"ru",           "iso8859-5"},
  {"ru_RU",        "iso8859-5"},
  {"ru_SU",        "iso8859-5"},
  {"zh",               "cp936"},
  {nullptr,                  nullptr}
};

static void botnet_change(char *new)
{
  if (op_strcasecmp(botnetnick, new)) {
    /* Trying to change bot's nickname */
    if (tands > 0) {
      putlog(LOG_MISC, "*", "* Tried to change my botnet nick, but I'm still "
             "linked to a botnet.");
      putlog(LOG_MISC, "*", "* (Unlink and try again.)");
      return;
    } else {
      if (botnetnick[0])
        putlog(LOG_MISC, "*", "* IDENTITY CHANGE: %s -> %s", botnetnick, new);
      set_botnetnick(new);
    }
  }
}


/*
 *     Vars, traces, misc
 */

int init_misc(void);

/* Used for read/write to integer couplets */
typedef struct {
  int *left;  /* left side of couplet */
  int *right; /* right side */
} coupletinfo;

static op_bh *tcl_strinfo_bh    = nullptr;
static op_bh *tcl_intinfo_bh    = nullptr;
static op_bh *tcl_couplet_bh    = nullptr;
static op_bh *tcl_cdstrinfo_bh  = nullptr;

/* Read/write integer couplets (int1:int2) */
static char *tcl_eggcouplet(ClientData cdata, Tcl_Interp *irp,
                            EGG_CONST char *name1,
                            EGG_CONST char *name2, int flags)
{
  char *s;
  coupletinfo *cp = (coupletinfo *) cdata;

  if (flags & TCL_TRACE_WRITES) {
    s = (char *) Tcl_GetVar2(interp, name1, name2, 0);
    if (s != nullptr) {
      int nr1, nr2;

      nr1 = nr2 = 0;

      if (strlen(s) > 40)
        s[40] = 0;

      sscanf(s, "%d%*c%d", &nr1, &nr2);
      *(cp->left) = nr1;
      *(cp->right) = nr2;
    }
  }
  if (flags & (TCL_TRACE_READS | TCL_TRACE_UNSETS)) {
    {
      op_strbuf_t _b = {};
      op_strbuf_init(&_b);
      op_strbuf_appendf(&_b, "%d:%d", *(cp->left), *(cp->right));
      Tcl_SetVar2(interp, name1, name2, op_strbuf_str(&_b), TCL_GLOBAL_ONLY);
      op_strbuf_free(&_b);
    }
    if (flags & TCL_TRACE_UNSETS)
      Tcl_TraceVar(interp, name1,
                   TCL_TRACE_READS | TCL_TRACE_WRITES | TCL_TRACE_UNSETS,
                   tcl_eggcouplet, cdata);
  }
  return nullptr;
}

/* Read or write normal integer.
 */
static char *tcl_eggint(ClientData cdata, Tcl_Interp *irp,
                        EGG_CONST char *name1,
                        EGG_CONST char *name2, int flags)
{
  char *s, s1[40], *endptr;
  long l;
  intinfo *ii = (intinfo *) cdata;
  int p;

  if (flags & (TCL_TRACE_READS | TCL_TRACE_UNSETS)) {
    /* Special cases */
    if ((int *) ii->var == &conmask)
      op_strlcpy(s1, masktype(conmask), sizeof s1);
    else if ((int *) ii->var == &default_flags) {
      struct flag_record fr = { FR_GLOBAL };
      fr.global = default_flags;

      fr.udef_global = default_uflags;
      build_flags(s1, &fr, 0);
    } else if ((int *) ii->var == &userfile_perm) {
      op_strbuf_t perm_buf = {};
      op_strbuf_init(&perm_buf);
      op_strbuf_appendf(&perm_buf, "0%o", userfile_perm);
      op_strlcpy(s1, op_strbuf_str(&perm_buf), sizeof s1);
      op_strbuf_free(&perm_buf);
    } else
      op_strlcpy(s1, int_to_base10(*(int *) ii->var), sizeof s1);
    Tcl_SetVar2(interp, name1, name2, s1, TCL_GLOBAL_ONLY);
    if (flags & TCL_TRACE_UNSETS)
      Tcl_TraceVar(interp, name1,
                   TCL_TRACE_READS | TCL_TRACE_WRITES | TCL_TRACE_UNSETS,
                   tcl_eggint, cdata);
    return nullptr;
  } else {                        /* Writes */
    s = (char *) Tcl_GetVar2(interp, name1, name2, TCL_GLOBAL_ONLY);
    if (s != nullptr) {
      if ((int *) ii->var == &conmask) {
        if (s[0])
          conmask = logmodes(s);
        else
          conmask = LOG_MODES | LOG_MISC | LOG_CMDS;
      } else if ((int *) ii->var == &default_flags) {
        struct flag_record fr = { FR_GLOBAL };

        break_down_flags(s, &fr, 0);
        default_flags = sanity_check(fr.global);        /* drummer */

        default_uflags = fr.udef_global;
      } else if ((int *) ii->var == &userfile_perm) {
        p = strtol(s, &endptr, 8);
        if ((p < 01) || (p > 0777) || (*endptr))
          return "Invalid userfile permissions, must be octal between 01 and 0777";
        userfile_perm = p;
      } else if ((ii->ro == 2) || ((ii->ro == 1) && protect_readonly))
        return "Read-only variable";
      else {
        if (Tcl_ExprLong(interp, s, &l) == TCL_ERROR)
          return "Variable must have integer value";
        if ((int *) ii->var == &max_socks) {
          if (l < threaddata()->MAXSOCKS)
            return "Decreasing max-socks requires a restart";
          max_socks = l;
        } else if ((int *) ii->var == &max_logs) {
          if (l < 5)
            return "ERROR: max-logs cannot be less than 5";
          if (l < max_logs)
            return "ERROR: Decreasing max-logs requires a restart";
          max_logs = l;
          init_misc();
        } else
          *(ii->var) = (int) l;
      }
    }
    return nullptr;
  }
}

/* Read/write normal string variable
 */
static char *tcl_eggstr(ClientData cdata, Tcl_Interp *irp,
                        EGG_CONST char *name1,
                        EGG_CONST char *name2, int flags)
{
  char *s;
  strinfo *st = (strinfo *) cdata;

  if (flags & (TCL_TRACE_READS | TCL_TRACE_UNSETS)) {
    if ((st->str == firewall) && (firewall[0])) {
      op_strbuf_t _b = {};
      op_strbuf_init(&_b);
      op_strbuf_appendf(&_b, "%s:%d", firewall, firewallport);
      Tcl_SetVar2(interp, name1, name2, op_strbuf_str(&_b), TCL_GLOBAL_ONLY);
      op_strbuf_free(&_b);
    } else
      Tcl_SetVar2(interp, name1, name2, st->str, TCL_GLOBAL_ONLY);
    if (flags & TCL_TRACE_UNSETS) {
      Tcl_TraceVar(interp, name1, TCL_TRACE_READS | TCL_TRACE_WRITES |
                   TCL_TRACE_UNSETS, tcl_eggstr, cdata);
      if ((st->max <= 0) && (protect_readonly || (st->max == 0)))
        return "read-only variable";    /* it won't return the error... */
    }
    return nullptr;
  } else {                        /* writes */
    if ((st->max <= 0) && (protect_readonly || (st->max == 0))) {
      Tcl_SetVar2(interp, name1, name2, st->str, TCL_GLOBAL_ONLY);
      return "read-only variable";
    }
    s = (char *) Tcl_GetVar2(interp, name1, name2, 0);
    if (s != nullptr) {
      if (strlen(s) > abs(st->max)) {
        putlog(LOG_MISC, "*", "WARNING: Value for %s truncated to %i chars", name1, abs(st->max));
        s[abs(st->max)] = 0;
      }
      if (st->str == botnetnick)
        botnet_change(s);
      else if (st->str == logfile_suffix)
        logsuffix_change(s);
      else if (st->str == firewall) {
        splitc(firewall, s, ':');
        if (!firewall[0])
          op_strlcpy(firewall, s, 121);
        else
          firewallport = egg_atoi(s);
      } else
        op_strlcpy(st->str, s, abs(st->max) + 1);
      if ((st->flags) && (s[0])) {
        if (st->str[strlen(st->str) - 1] != '/')
          op_strlcat(st->str, "/", (size_t)abs(st->max) + 1);
      }
    }
    return nullptr;
  }
}

struct tcl_call_stringinfo {
  Tcl_CmdProc *proc;
  ClientData cd;
};

static void tcl_cleanup_stringinfo(ClientData cd)
{
  op_bh_free(tcl_cdstrinfo_bh, cd);
}

/* Compatibility wrapper that calls Tcl functions with String API
 *
 * Is reentrant, can call itself recursively, so argv is dynamically allocated
 * Tcl_IncrRefCount() is needed to preserve the strings we get Tcl_GetString()
 * from being cleaned up if Tcl is invoked from this
 */
static int tcl_call_stringproc_cd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[])
{
  const char **argv;
  int ret;
  struct tcl_call_stringinfo *info = cd;

  /* The string API guarantees argv[argc] == nullptr, unlike the obj API */
  argv = op_malloc((objc + 1) * sizeof *argv);
  for (int i = 0; i < objc; i++) {
    Tcl_IncrRefCount(objv[i]);
    argv[i] = Tcl_GetString(objv[i]);
  }
  argv[objc] = nullptr;
  ret = (info->proc)(info->cd, interp, objc, argv);
  for (int i = 0; i < objc; i++) {
    Tcl_DecrRefCount(objv[i]);
  }
  op_free(argv);
  return ret;
}

/* The standard case of no actual cd */
static int tcl_call_stringproc(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[])
{
  struct tcl_call_stringinfo info;
  info.proc = cd;
  info.cd = nullptr;
  return tcl_call_stringproc_cd(&info, interp, objc, objv);
}

/* Add/remove tcl commands
 */

void add_tcl_commands(tcl_cmds *table)
{
  for (int i = 0; table[i].name; i++)
    Tcl_CreateObjCommand(interp, table[i].name, tcl_call_stringproc, table[i].func, nullptr);
}

void add_cd_tcl_cmds(cd_tcl_cmd *table)
{
  struct tcl_call_stringinfo *info;
  while (table->name) {
    if (table->cdata) {
      if (!tcl_cdstrinfo_bh)
        tcl_cdstrinfo_bh = op_bh_create(sizeof(struct tcl_call_stringinfo), 16, "tcl_cdstrinfo");
      info = op_bh_alloc(tcl_cdstrinfo_bh);
      strtot += sizeof(struct tcl_call_stringinfo);
      info->proc = table->callback;
      info->cd = table->cdata;
      Tcl_CreateObjCommand(interp, table->name, tcl_call_stringproc_cd, info, tcl_cleanup_stringinfo);
    } else {
      Tcl_CreateObjCommand(interp, table->name, tcl_call_stringproc, table->callback, nullptr);
    }
    table++;
  }
}

void rem_tcl_commands(tcl_cmds *table)
{
  for (int i = 0; table[i].name; i++)
    Tcl_DeleteCommand(interp, table[i].name);
}

void add_tcl_objcommands(tcl_cmds *table)
{
  for (int i = 0; table[i].name; i++)
    Tcl_CreateObjCommand(interp, table[i].name, table[i].func, (ClientData) 0,
                         nullptr);
}

/* Get the current tcl result string. */
const char *tcl_resultstring(void)
{
  const char *result;
  result = Tcl_GetStringResult(interp);
  return result;
}

int tcl_resultempty(void) {
  const char *result;
  result = tcl_resultstring();
  return (result && result[0]) ? 0 : 1;
}

/* Get the current tcl result as int. replaces egg_atoi(interp->result) */
int tcl_resultint(void)
{
  int result;
  if (Tcl_GetIntFromObj(nullptr, Tcl_GetObjResult(interp), &result) != TCL_OK)
    result = 0;
  return result;
}

/* Set up Tcl variables that will hook into eggdrop internal vars via
 * trace callbacks.
 */
static void init_traces(void)
{
  add_tcl_coups(def_tcl_coups);
  add_tcl_strings(def_tcl_strings);
  add_tcl_ints(def_tcl_ints);
  Tcl_TraceVar(interp, "my-hostname", TCL_GLOBAL_ONLY|TCL_TRACE_WRITES|TCL_TRACE_UNSETS, traced_myiphostname, nullptr);
  Tcl_TraceVar(interp, "my-ip", TCL_GLOBAL_ONLY|TCL_TRACE_WRITES|TCL_TRACE_UNSETS, traced_myiphostname, nullptr);
  Tcl_TraceVar(interp, "nat-ip", TCL_GLOBAL_ONLY|TCL_TRACE_WRITES|TCL_TRACE_UNSETS, traced_natip, nullptr);
  Tcl_TraceVar(interp, "remove-pass", TCL_GLOBAL_ONLY|TCL_TRACE_WRITES, traced_remove_pass, nullptr);
}

void kill_tcl(void)
{
  rem_tcl_coups(def_tcl_coups);
  rem_tcl_strings(def_tcl_strings);
  rem_tcl_ints(def_tcl_ints);
  Tcl_UntraceVar(interp, "my-hostname", TCL_GLOBAL_ONLY|TCL_TRACE_WRITES|TCL_TRACE_UNSETS, traced_myiphostname, nullptr);
  Tcl_UntraceVar(interp, "my-ip", TCL_GLOBAL_ONLY|TCL_TRACE_WRITES|TCL_TRACE_UNSETS, traced_myiphostname, nullptr);
  Tcl_UntraceVar(interp, "nat-ip", TCL_GLOBAL_ONLY|TCL_TRACE_WRITES|TCL_TRACE_UNSETS, traced_natip, nullptr);
  Tcl_UntraceVar(interp, "remove-pass", TCL_GLOBAL_ONLY|TCL_TRACE_WRITES, traced_remove_pass, nullptr);
  kill_bind();
  Tcl_DeleteInterp(interp);
}

extern tcl_cmds tcluser_cmds[], tcldcc_cmds[], tclmisc_cmds[],
       tclmisc_objcmds[], tcldns_cmds[];
#ifdef TLS
extern tcl_cmds tcltls_cmds[];
#endif

/* The tickle_*() functions replace the Tcl Notifier
 * The tickle_*() functions can be called by Tcl threads
 */
void tickle_SetTimer (TCL_CONST86 Tcl_Time *timePtr)
{
  struct threaddata *td = threaddata();
  /* we can block 1 second maximum, because we have SECONDLY events */
  if (!timePtr || timePtr->sec > 1 || (timePtr->sec == 1 && timePtr->usec > 0)) {
    td->blocktime.tv_sec = 1;
    td->blocktime.tv_usec = 0;
  } else {
    td->blocktime.tv_sec = timePtr->sec;
    td->blocktime.tv_usec = timePtr->usec;
  }
}

int tickle_WaitForEvent (TCL_CONST86 Tcl_Time *timePtr)
{
  struct threaddata *td = threaddata();

  tickle_SetTimer(timePtr);
  return (*td->mainloopfunc)(0);
}

void tickle_CreateFileHandler(int fd, int mask, Tcl_FileProc *proc, ClientData cd)
{
  alloctclsock(fd, mask, proc, cd);
}

void tickle_DeleteFileHandler(int fd)
{
  killtclsock(fd);
}

void tickle_FinalizeNotifier(ClientData cd)
{
  struct threaddata *td = threaddata();
  if (td->socklist)
    op_free(td->socklist);
}

ClientData tickle_InitNotifier(void)
{
  static int ismainthread = 1;
  init_threaddata(ismainthread);
  if (ismainthread)
    ismainthread = 0;
  return nullptr;
}

void tickle_AlertNotifier(ClientData cd)
{
  if (cd) {
    fatal("Error calling Tcl_AlertNotifier", 0);
  }
}

void tickle_ServiceModeHook(int mode)
{
  if (mode != TCL_SERVICE_ALL) {
    fatal("Tcl_ServiceModeHook called with unsupported mode", 0);
  }
}

int tclthreadmainloop(int zero)
{
  return (sockread(nullptr, nullptr, threaddata()->socklist, threaddata()->MAXSOCKS, 1) == -5);
}

struct threaddata *td_main = 0;

struct threaddata *threaddata(void)
{
  static Tcl_ThreadDataKey tdkey;
  struct threaddata *td = Tcl_GetThreadData(&tdkey, sizeof(struct threaddata));
  if (!(td->mainloopfunc) && td_main) /* python thread */
    return td_main;
  return td;
}

void init_threaddata(int mainthread)
{
  struct threaddata *td = threaddata();
/* Nested evaluation (vwait/update) of the event loop only
 * processes Tcl events (after/fileevent) for now. Using
 * eggdrops mainloop() requires caution regarding reentrance.
 * (check_tcl_* -> Tcl_Eval() -> mainloop() -> check_tcl_* etc.)
 */
/* td->mainloopfunc = mainthread ? mainloop : tclthreadmainloop; */
  td->mainloopfunc = tclthreadmainloop;
  td->socklist = nullptr;
  td->mainthread = mainthread;
  td->blocktime.tv_sec = 1;
  td->blocktime.tv_usec = 0;
  td->MAXSOCKS = 0;
  increase_socks_max();
  if (mainthread)
    td_main = td;
}

/* workaround for Tcl that does not support unicode outside BMP (3 byte utf-8 characters) */
#ifdef TCL_WORKAROUND_UNICODESUP

/* Based on https://github.com/skeeto/branchless-utf8 which is released into the public domain */
/* 0 means not utf-8, so the length is still 1 but we can distinguish that case,
 * that's why len = len + !len is used, to convert 0 to 1 and leave the rest as-is
 */
static const char utf8lengths[] = {
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
  0, 0, 0, 0, 0, 0, 0, 0, 2, 2, 2, 2, 3, 3, 4, 0
};

/* quick check if tricks are needed, only if 4-byte utf-8 characters are used */
int needs_unicodesup(const char *str)
{
  while (*str) {
    int len = utf8lengths[((unsigned char)str[0]) >> 3] + !utf8lengths[((unsigned char)str[0]) >> 3];

    if (len == 4) {
      return 1;
    }
    while (len--) {
      if (*str++ == '\0') {
        break;
      }
    }
  }
  return 0;
}

/* return a new Tcl_StringObj with 4-byte utf-8 characters replaced by surrogate pairs
 * - decode 4-byte utf-8 into unicode codepoint c
 * - calculate high and low surrogate unicode codepoints high/low
 * - encode high/low as 3-byte utf-8 strings
 * the length of the result could be len/4*6 bytes long, so
 * to avoid frequent reallocation/string appending, a temporary buffer is used
 * for long strings (>512 characters, which does not apply to IRC lines) chunks are assembled to a Tcl_DString
 * for short strings the 512/4*6 character buffer is enough
 */
Tcl_Obj *egg_string_unicodesup_surrogate(const char *oldstr, int len)
{
  int stridx = 0, bufidx = 0, use_dstring = 0;
  char buf[768];
  Tcl_DString ds;
  Tcl_Obj *result;

  /* chunked */
  if (len > 512) {
    use_dstring = 1;
    Tcl_DStringInit(&ds);
  }

  while (stridx < len) {
    int charlen = utf8lengths[((unsigned char)oldstr[stridx]) >> 3] + !utf8lengths[((unsigned char)oldstr[stridx])>> 3];

    if (charlen == 4 && stridx + 4 <= len) {
      uint32_t c;
      uint16_t high, low;

      /* decode 4-byte utf-8 into unicode codepoint */
      c  = (uint32_t)(oldstr[stridx++] & 0x07) << 18;
      c |= (uint32_t)(oldstr[stridx++] & 0x3f) << 12;
      c |= (uint32_t)(oldstr[stridx++] & 0x3f) <<  6;
      c |= (uint32_t)(oldstr[stridx++] & 0x3f) <<  0;

      /* calculate high and low surrogate unicode codepoints */
      c -= 0x10000;
      high = 0xD800 + ((c & 0xffc00) >> 10);
      low = 0xDC00 + (c & 0x3ff);

      /* encode high surrogate as utf-8 */
      buf[bufidx++] = 0xe0 | ((high >> 12) & 0xf);
      buf[bufidx++] = 0x80 | ((high >> 6) & 0x3f);
      buf[bufidx++] = 0x80 | ((high >> 0) & 0x3f);

      /* encode low surrogate as utf-8 */
      buf[bufidx++] = 0xe0 | ((low >> 12) & 0xf);
      buf[bufidx++] = 0x80 | ((low >> 6) & 0x3f);
      buf[bufidx++] = 0x80 | ((low >> 0) & 0x3f);
    } else {
      /* copy everything else verbatim */
      while (charlen-- && stridx < len) {
        buf[bufidx++] = oldstr[stridx++];
      }
    }
    if (use_dstring && bufidx > sizeof buf - 6) {
      Tcl_DStringAppend(&ds, buf, bufidx);
      bufidx = 0;
    }
  }
  if (use_dstring && bufidx) {
    Tcl_DStringAppend(&ds, buf, bufidx);
    result = Tcl_NewStringObj(Tcl_DStringValue(&ds), Tcl_DStringLength(&ds));
    Tcl_DStringFree(&ds);
  } else {
    result = Tcl_NewStringObj(buf, bufidx);
  }
  return result;
}

/* decode 2 utf-8 sequences that are 3 bytes long and check if they are surrogate pairs */
int decode_surrogates(const char *str, uint32_t *high, uint32_t *low)
{
  *high  = (*str++ & 0xf) << 12;
  *high |= (*str++ & 0x3f) << 6;
  *high |= (*str++ & 0x3f) << 0;
  if (*high < 0xD800 || *high > 0xDBFF) {
    return 0;
  }
  *low  = (*str++ & 0xf) << 12;
  *low |= (*str++ & 0x3f) << 6;
  *low |= (*str++ & 0x3f) << 0;
  if (*low < 0xDC00 || *low > 0xDFFF) {
    return 0;
  }
  return 1;
}

/* returns a new Tcl_StringObj by replacing surrogate pairs back into 4-byte utf-8 sequences
 * - for every 3-byte utf-8 sequence, check if it's a surrogate pair
 * - decode into high/low codepoints
 * - calculate original codepoint and write back a 4-byte utf-8 sequence instead of 3-byte surrogate pairs
 * the length of the result is guaranteed to be equal or shorter than the original, so malloc(len) is sufficient space
 */
Tcl_Obj *egg_string_unicodesup_desurrogate(const char *oldstr, int len)
{
  int stridx = 0, bufidx = 0;
  char *buf = op_malloc(len);
  Tcl_Obj *o;

  while (stridx < len) {
    uint32_t low, high;
    int charlen = utf8lengths[((unsigned char)oldstr[stridx]) >> 3] + !utf8lengths[((unsigned char)oldstr[stridx]) >> 3];

    if (charlen == 3 && stridx + 6 <= len && utf8lengths[((unsigned char)oldstr[stridx + 3]) >> 3] == 3 && decode_surrogates(oldstr + stridx, &high, &low)) {
      uint32_t c = 0x10000 + (high - 0xD800) * 0x400 + (low - 0xDC00);

      buf[bufidx++] = 0xF0 | ((c >> 18) & 0x07);
      buf[bufidx++] = 0x80 | ((c >> 12) & 0x3f);
      buf[bufidx++] = 0x80 | ((c >>  6) & 0x3f);
      buf[bufidx++] = 0x80 | ((c >>  0) & 0x3f);

      stridx += 6;
    } else {
      while (charlen-- && stridx < len) {
        buf[bufidx++] = oldstr[stridx++];
      }
    }
  }

  o = Tcl_NewStringObj(buf, bufidx);
  op_free(buf);
  return o;
}

/* C function called for ::egg_tcl_tolower/toupper/totitle
 * context (original Tcl function and which conversion to do) is in cd
 */
int egg_string_unicodesup(void *cd, Tcl_Interp *interp, int objc, Tcl_Obj *const orig_objv[])
{
  struct tcl_unicodesup_info *info = cd;
  Tcl_Obj **new_objv;
  int ret;

  /* impossible? */
  if (objc == 0) {
    return Tcl_EvalObjv(interp, objc, orig_objv, 0);
  }
  /* new arguments to original Tcl string tolower/toupper/totitle */
  new_objv = op_malloc(objc * sizeof *new_objv);

  for (int i = 0; i < objc; i++) {
    if (i == 0) {
      /* overwrite command objv[0] with original Tcl command instead of this function */
      new_objv[i] = info->cmd;
    } else if (i == 1 && needs_unicodesup(Tcl_GetString(orig_objv[1]))) {
      Tcl_Size len;
      const char *oldstr = Tcl_GetStringFromObj(orig_objv[1], &len);

      /* overwrite string argument by replacing 4-byet utf-8 sequences with surrogate pairs */
      new_objv[1] = egg_string_unicodesup_surrogate(oldstr, len);
    } else {
      /* copy other arguments, e.g. string tolower test 1 2 */
      new_objv[i] = orig_objv[i];
    }
    /* ref count of new objects must be increased before eval and decreased after, orig_objv is read-only */
    Tcl_IncrRefCount(new_objv[i]);
  }

  /* call original Tcl function */
  ret = Tcl_EvalObjv(interp, objc, new_objv, 0);

  /* decrease ref count of new arguments */
  for (int i = 0; i < objc; i++) {
    Tcl_DecrRefCount(new_objv[i]);
  }
  op_free(new_objv);
  /* overwrite Tcl's result by replacing surrogates back to 4-byte utf-8 sequences*/
  if (ret == TCL_OK) {
    Tcl_Size len;
    Tcl_Obj *resultobj = Tcl_GetObjResult(interp);
    const char *str = Tcl_GetStringFromObj(resultobj, &len);

    Tcl_SetObjResult(interp, egg_string_unicodesup_desurrogate(str, len));
  }
  return ret;
}

/* register a single workaround command, making the namespace ensemble string <subcmd> call ::egg_string_<subcmd> instead
 * original command names are ::tcl::string::<subcmd>
 */
void init_unicodesup_cmd(Tcl_Obj *ensdict, const char *subcmd, int index)
{
  Tcl_Obj *orig_cmd;
  static struct tcl_unicodesup_info info[3];
  op_strbuf_t buf = {};
  op_strbuf_init(&buf);

  if (Tcl_DictObjGet(interp, ensdict, Tcl_NewStringObj(subcmd, -1), &orig_cmd) != TCL_OK || !orig_cmd) {
    putlog(LOG_MISC, "*", "ERROR: Tcl non-BMP unicodesup could not find string %s subcommand", subcmd);
    return;
  }

  info[index].subcmd = subcmd;
  info[index].cmd = orig_cmd;
  Tcl_IncrRefCount(orig_cmd);

  op_strbuf_appendf(&buf, "::egg_string_%s", subcmd);
  Tcl_CreateObjCommand(interp, op_strbuf_str(&buf), egg_string_unicodesup, &info[index], nullptr);

  if (Tcl_DictObjPut(interp, ensdict, Tcl_NewStringObj(subcmd, -1),
                     Tcl_NewStringObj(op_strbuf_str(&buf), -1)) != TCL_OK) {
    op_strbuf_free(&buf);
    putlog(LOG_MISC, "*", "ERROR: Tcl non-BMP unicodesup could not set dictionary redirect");
    return;
  }
  op_strbuf_free(&buf);
}

/* register all workaround functions */
void init_unicodesup(void)
{
  Tcl_Obj *ensdict;
  Tcl_Command enscmd = Tcl_FindEnsemble(interp, Tcl_NewStringObj("string", -1), 0);

  if (!enscmd) {
    putlog(LOG_MISC, "*", "ERROR: Tcl non-BMP unicodesup could not find string command");
    return;
  }
  if (!Tcl_IsEnsemble(enscmd)) {
    putlog(LOG_MISC, "*", "ERROR: Tcl non-BMP unicodesup is not a namespace ensemble");
    return;
  }
  if (Tcl_GetEnsembleMappingDict(interp, enscmd, &ensdict) != TCL_OK || !ensdict) {
    putlog(LOG_MISC, "*", "ERROR: Tcl non-BMP unicodesup could not get namespace ensemble dictionary");
    return;
  }

  init_unicodesup_cmd(ensdict, "tolower", 0);
  init_unicodesup_cmd(ensdict, "toupper", 1);
  init_unicodesup_cmd(ensdict, "totitle", 2);

  if (Tcl_SetEnsembleMappingDict(interp, enscmd, ensdict) != TCL_OK) {
    putlog(LOG_MISC, "*", "ERROR: Tcl non-BMP unicodesup could not set namespace ensemble dictionary");
    return;
  }
}
#endif /* TCL_WORKAROUND_UNICODESUP */

void init_tcl0(int argc, char **argv)
{
  Tcl_NotifierProcs notifierprocs;

  op_memzero(&notifierprocs, sizeof(notifierprocs));
  notifierprocs.initNotifierProc = tickle_InitNotifier;
  notifierprocs.createFileHandlerProc = tickle_CreateFileHandler;
  notifierprocs.deleteFileHandlerProc = tickle_DeleteFileHandler;
  notifierprocs.setTimerProc = tickle_SetTimer;
  notifierprocs.waitForEventProc = tickle_WaitForEvent;
  notifierprocs.finalizeNotifierProc = tickle_FinalizeNotifier;
  notifierprocs.alertNotifierProc = tickle_AlertNotifier;
  notifierprocs.serviceModeHookProc = tickle_ServiceModeHook;

  Tcl_SetNotifier(&notifierprocs);

  /* This must be done *BEFORE* Tcl_SetSystemEncoding(),
 * or Tcl_SetSystemEncoding() will cause a segfault.
 */
  /* This is used for 'info nameofexecutable'.
   * The filename in argv[0] must exist in a directory listed in
   * the environment variable PATH for it to register anything.
   */
  Tcl_FindExecutable(argv[0]);
#if TCL_MAJOR_VERSION >= 9
  Tcl_InitSubsystems();
#endif
}

/* Not going through Tcl's crazy main() system (what on earth was he
 * smoking?!) so we gotta initialize the Tcl interpreter
 */
void init_tcl1(int argc, char **argv)
{
  const char *encoding;
  char *langEnv, pver[1024] = "";

  /* Initialize the interpreter */
  interp = Tcl_CreateInterp();


  /* Set Tcl variable tcl_interactive to 0 */
  Tcl_SetVar(interp, "tcl_interactive", "0", TCL_GLOBAL_ONLY);

  /* Setup script library facility */
  Tcl_Init(interp);
  Tcl_SetServiceMode(TCL_SERVICE_ALL);

/* Code based on Tcl's TclpSetInitialEncodings() */
  /* Determine the current encoding from the LC_* or LANG environment
   * variables.
   */
  langEnv = getenv("LC_ALL");
  if (langEnv == nullptr || langEnv[0] == '\0') {
    langEnv = getenv("LC_CTYPE");
  }
  if (langEnv == nullptr || langEnv[0] == '\0') {
    langEnv = getenv("LANG");
  }
  if (langEnv == nullptr || langEnv[0] == '\0') {
    langEnv = nullptr;
  }

  encoding = nullptr;
  if (langEnv != nullptr) {
    for (int i = 0; localeTable[i].lang != nullptr; i++)
      if (strcmp(localeTable[i].lang, langEnv) == 0) {
        encoding = localeTable[i].encoding;
        break;
      }

    /* There was no mapping in the locale table.  If there is an
     * encoding subfield, we can try to guess from that.
     */
    if (encoding == nullptr) {
      char *p;

      for (p = langEnv; *p != '\0'; p++) {
        if (*p == '.') {
          p++;
          break;
        }
      }
      if (*p != '\0') {
        Tcl_DString ds;

        Tcl_DStringInit(&ds);
        Tcl_DStringAppend(&ds, p, -1);

        encoding = Tcl_DStringValue(&ds);
        Tcl_UtfToLower(Tcl_DStringValue(&ds));
        if (Tcl_SetSystemEncoding(nullptr, encoding) == TCL_OK) {
          Tcl_DStringFree(&ds);
          goto resetPath;
        }
        Tcl_DStringFree(&ds);
        encoding = nullptr;
      }
    }
  }

  if (encoding == nullptr) {
    encoding = "iso8859-1";
  }

  Tcl_SetSystemEncoding(nullptr, encoding);

resetPath:

  /* Initialize the C library's locale subsystem. */
  setlocale(LC_CTYPE, "");

  /* In case the initial locale is not "C", ensure that the numeric
   * processing is done in "C" locale regardless. */
  setlocale(LC_NUMERIC, "C");

  /* Keep the iso8859-1 encoding preloaded.  The IO package uses it for
   * gets on a binary channel. */
  Tcl_GetEncoding(nullptr, "iso8859-1");

  /* Add eggdrop to Tcl's package list */
  for (int j = 0; j <= (int)strlen(egg_version); j++) {
    if ((egg_version[j] == ' ') || (egg_version[j] == '+'))
      break;
    pver[strlen(pver)] = egg_version[j];
  }
  Tcl_PkgProvide(interp, "eggdrop", pver);

#ifdef TCL_WORKAROUND_UNICODESUP
  init_unicodesup();
#endif
  /* Initialize binds and traces */
  init_bind();
  init_traces();

  /* Add new commands */
  add_tcl_commands(tcluser_cmds);
  add_tcl_commands(tcldcc_cmds);
  add_tcl_commands(tclmisc_cmds);
  add_tcl_commands(tcldns_cmds);
#ifdef TLS
  add_tcl_commands(tcltls_cmds);
#endif
}

void do_tcl(const char *whatzit, const char *script)
{
  int code;
  char *result;
  Tcl_DString dstr;

  code = Tcl_Eval(interp, script);

  /* properly convert string to system encoding. */
  Tcl_DStringInit(&dstr);
  Tcl_UtfToExternalDString(nullptr, tcl_resultstring(), -1, &dstr);
  result = Tcl_DStringValue(&dstr);

  if (code != TCL_OK) {
    putlog(LOG_MISC, "*", "Tcl error in script for '%s':", whatzit);
    putlog(LOG_MISC, "*", "%s", result);
    Tcl_BackgroundError(interp);
  }

  Tcl_DStringFree(&dstr);
}

/* Interpret tcl file fname.
 *
 * returns:   1 - if everything was okay
 */
int readtclprog(char *fname)
{
  int code;
  EGG_CONST char *result;
  Tcl_DString dstr;

  if (!file_readable(fname))
    return 0;

  code = Tcl_EvalFile(interp, fname);
  result = Tcl_GetVar(interp, "errorInfo", TCL_GLOBAL_ONLY);

  /* properly convert string to system encoding. */
  Tcl_DStringInit(&dstr);
  Tcl_UtfToExternalDString(nullptr, result, -1, &dstr);
  result = Tcl_DStringValue(&dstr);

  if (code != TCL_OK) {
    putlog(LOG_MISC, "*", "Tcl error in file '%s':", fname);
    putlog(LOG_MISC, "*", "%s", result);
    Tcl_BackgroundError(interp);
    code = 0; /* JJM: refactored to remove premature return */
  } else {
    /* Refresh internal variables */
    code = 1;
  }

  Tcl_DStringFree(&dstr);

  return code;
}

void add_tcl_strings(tcl_strings *list)
{
  strinfo *st;
  int tmp;

  for (int i = 0; list[i].name; i++) {
    if (!tcl_strinfo_bh)
      tcl_strinfo_bh = op_bh_create(sizeof(strinfo), 32, "tcl_strinfo");
    st = op_bh_alloc(tcl_strinfo_bh);
    strtot += sizeof(strinfo);
    st->max = list[i].length - (list[i].flags & STR_DIR);
    if (list[i].flags & STR_PROTECT)
      st->max = -st->max;
    st->str = list[i].buf;
    st->flags = (list[i].flags & STR_DIR);
    tmp = protect_readonly;
    protect_readonly = 0;
    tcl_eggstr((ClientData) st, interp, list[i].name, nullptr, TCL_TRACE_WRITES);
    protect_readonly = tmp;
    tcl_eggstr((ClientData) st, interp, list[i].name, nullptr, TCL_TRACE_READS);
    Tcl_TraceVar(interp, list[i].name, TCL_TRACE_READS | TCL_TRACE_WRITES |
                 TCL_TRACE_UNSETS, tcl_eggstr, (ClientData) st);
  }
}

void rem_tcl_strings(tcl_strings *list)
{
  int f;
  strinfo *st;

  f = TCL_GLOBAL_ONLY | TCL_TRACE_READS | TCL_TRACE_WRITES | TCL_TRACE_UNSETS;
  for (int i = 0; list[i].name; i++) {
    st = (strinfo *) Tcl_VarTraceInfo(interp, list[i].name, f, tcl_eggstr,
                                      nullptr);
    Tcl_UntraceVar(interp, list[i].name, f, tcl_eggstr, st);
    if (st != nullptr) {
      strtot -= sizeof(strinfo);
      op_bh_free(tcl_strinfo_bh, st);
    }
  }
}

void add_tcl_ints(tcl_ints *list)
{
  int tmp;
  intinfo *ii;

  for (int i = 0; list[i].name; i++) {
    if (!tcl_intinfo_bh)
      tcl_intinfo_bh = op_bh_create(sizeof(intinfo), 32, "tcl_intinfo");
    ii = op_bh_alloc(tcl_intinfo_bh);
    strtot += sizeof(intinfo);
    ii->var = list[i].val;
    ii->ro = list[i].readonly;
    tmp = protect_readonly;
    protect_readonly = 0;
    tcl_eggint((ClientData) ii, interp, list[i].name, nullptr, TCL_TRACE_WRITES);
    protect_readonly = tmp;
    tcl_eggint((ClientData) ii, interp, list[i].name, nullptr, TCL_TRACE_READS);
    Tcl_TraceVar(interp, list[i].name,
                 TCL_TRACE_READS | TCL_TRACE_WRITES | TCL_TRACE_UNSETS,
                 tcl_eggint, (ClientData) ii);
  }

}

void rem_tcl_ints(tcl_ints *list)
{
  int f;
  intinfo *ii;

  f = TCL_GLOBAL_ONLY | TCL_TRACE_READS | TCL_TRACE_WRITES | TCL_TRACE_UNSETS;
  for (int i = 0; list[i].name; i++) {
    ii = (intinfo *) Tcl_VarTraceInfo(interp, list[i].name, f, tcl_eggint,
                                      nullptr);
    Tcl_UntraceVar(interp, list[i].name, f, tcl_eggint, (ClientData) ii);
    if (ii) {
      strtot -= sizeof(intinfo);
      op_bh_free(tcl_intinfo_bh, ii);
    }
  }
}

/* Allocate couplet space for tracing couplets
 */
void add_tcl_coups(tcl_coups *list)
{
  coupletinfo *cp;

  for (int i = 0; list[i].name; i++) {
    if (!tcl_couplet_bh)
      tcl_couplet_bh = op_bh_create(sizeof(coupletinfo), 16, "tcl_couplet");
    cp = op_bh_alloc(tcl_couplet_bh);
    strtot += sizeof(coupletinfo);
    cp->left = list[i].lptr;
    cp->right = list[i].rptr;
    tcl_eggcouplet((ClientData) cp, interp, list[i].name, nullptr,
                   TCL_TRACE_WRITES | TCL_TRACE_READS);
    Tcl_TraceVar(interp, list[i].name,
                 TCL_TRACE_READS | TCL_TRACE_WRITES | TCL_TRACE_UNSETS,
                 tcl_eggcouplet, (ClientData) cp);
  }
}

void rem_tcl_coups(tcl_coups *list)
{
  int f;
  coupletinfo *cp;

  f = TCL_GLOBAL_ONLY | TCL_TRACE_READS | TCL_TRACE_WRITES | TCL_TRACE_UNSETS;
  for (int i = 0; list[i].name; i++) {
    cp = (coupletinfo *) Tcl_VarTraceInfo(interp, list[i].name, f,
                                          tcl_eggcouplet, nullptr);
    strtot -= sizeof(coupletinfo);
    Tcl_UntraceVar(interp, list[i].name, f, tcl_eggcouplet, (ClientData) cp);
    op_bh_free(tcl_couplet_bh, cp);
  }
}

/* Check if the Tcl library supports threads
*/
int tcl_threaded(void)
{
  if (Tcl_GetCurrentThread() != (Tcl_ThreadId)0)
    return 1;

  return 0;
}

/* Check if we need to fork before initializing Tcl
*/
int fork_before_tcl(void)
{
  return 0;
}

time_t get_expire_time(Tcl_Interp * irp, const char *s) {
  char *endptr;
  long expire_foo = strtol(s, &endptr, 10);

  if (*endptr) {
    Tcl_SetResult(irp, "bogus expire time", TCL_STATIC);
    return -1;
  }
  if (expire_foo < 0) {
    Tcl_SetResult(irp, "expire time must be 0 (perm) or greater than 0 days", TCL_STATIC);
    return -1;
  }
  if (expire_foo == 0)
    return 0;
  if (expire_foo > (60 * 24 * 2000)) {
    Tcl_SetResult(irp, "expire time must be equal to or less than 2000 days", TCL_STATIC);
    return -1;
  }
  return now + 60 * expire_foo;
}

/* notcl_setvar / notcl_getvar: in Tcl builds, delegate to the interpreter
 * which handles variable traces (e.g. writing "nick" fires the trace that
 * copies to origbotname).  This lets configtoml.c and other callers use a
 * single code path without #ifdef HAVE_TCL.
 */
void notcl_setvar(const char *name, const char *value)
{
  Tcl_SetVar(interp, name, value, TCL_GLOBAL_ONLY);
}

const char *notcl_getvar(const char *name, char *buf, size_t bufsz)
{
  const char *v = Tcl_GetVar(interp, name, TCL_GLOBAL_ONLY);
  if (v && buf) {
    op_strlcpy(buf, v, bufsz);
    return buf;
  }
  return v;
}

#else /* !HAVE_TCL — no-op stubs so the rest of the codebase links cleanly */

/* The global interpreter pointer is declared above as 'void *interp = nullptr'. */
/* expmem_tcl() is defined above the #ifdef block and always compiled.       */

/* Forward-declare misc.c helpers used by notcl_setvar's special-case logic. */
int init_misc(void);

void init_tcl0(int argc, char **argv) {}

/* Register the core variable tables so notcl_setvar/notcl_getvar work.
 * This is the no-TCL equivalent of init_traces().
 */
void init_tcl1(int argc, char **argv)
{
  /* In TCL builds tickle_InitNotifier() calls init_threaddata(1) the first
   * time Tcl creates its event loop.  In no-TCL builds there is no notifier,
   * so we must call it explicitly to allocate the dcc/socklist arrays. */
  init_threaddata(1);
  add_tcl_coups(def_tcl_coups);
  add_tcl_strings(def_tcl_strings);
  add_tcl_ints(def_tcl_ints);
}

void kill_tcl(void) {}

void do_tcl(const char *whatzit, const char *script) {}

int readtclprog(char *fname)
{
  return 0;
}

void add_tcl_commands(tcl_cmds *list) {}
void add_tcl_objcommands(tcl_cmds *list) {}
void add_cd_tcl_cmds(cd_tcl_cmd *list) {}
void rem_tcl_commands(tcl_cmds *list) {}

/* --- no-TCL variable registry ---
 * Stores pointers to all tcl_strings/ints/coups tables registered via
 * add_tcl_strings/ints/coups so that notcl_setvar/notcl_getvar can walk
 * them and read/write the underlying C variables.
 */
constexpr int NOTCL_MAXLISTS = 32;
static tcl_strings *notcl_str_lists[NOTCL_MAXLISTS];
static tcl_ints    *notcl_int_lists[NOTCL_MAXLISTS];
static tcl_coups   *notcl_coup_lists[NOTCL_MAXLISTS];
static int notcl_nstr = 0, notcl_nint = 0, notcl_ncoup = 0;

void add_tcl_strings(tcl_strings *list)
{
  if (notcl_nstr < NOTCL_MAXLISTS)
    notcl_str_lists[notcl_nstr++] = list;
}

void rem_tcl_strings(tcl_strings *list)
{
  for (int i = 0; i < notcl_nstr; i++)
    if (notcl_str_lists[i] == list) {
      notcl_str_lists[i] = notcl_str_lists[--notcl_nstr];
      break;
    }
}

void add_tcl_ints(tcl_ints *list)
{
  if (notcl_nint < NOTCL_MAXLISTS)
    notcl_int_lists[notcl_nint++] = list;
}

void rem_tcl_ints(tcl_ints *list)
{
  for (int i = 0; i < notcl_nint; i++)
    if (notcl_int_lists[i] == list) {
      notcl_int_lists[i] = notcl_int_lists[--notcl_nint];
      break;
    }
}

void add_tcl_coups(tcl_coups *list)
{
  if (notcl_ncoup < NOTCL_MAXLISTS)
    notcl_coup_lists[notcl_ncoup++] = list;
}

void rem_tcl_coups(tcl_coups *list)
{
  for (int i = 0; i < notcl_ncoup; i++)
    if (notcl_coup_lists[i] == list) {
      notcl_coup_lists[i] = notcl_coup_lists[--notcl_ncoup];
      break;
    }
}

/* notcl_setvar: write a value into the C variable bound to 'name'.
 * Handles strings, ints, and coups ("N:M" for coupled int pairs).
 */
void notcl_setvar(const char *name, const char *value)
{
  /* Strings */
  for (int i = 0; i < notcl_nstr; i++) {
    tcl_strings *e;
    for (e = notcl_str_lists[i]; e->name; e++) {
      if (!strcmp(e->name, name)) {
        if (e->length > 0 && e->buf)
          op_strlcpy(e->buf, value, e->length + 1);
        return;
      }
    }
  }
  /* Ints */
  for (int i = 0; i < notcl_nint; i++) {
    tcl_ints *e;
    for (e = notcl_int_lists[i]; e->name; e++) {
      if (!strcmp(e->name, name)) {
        if (e->readonly < 2 && e->val) {
          int l = egg_atoi(value);
          /* max-logs: mirror the Tcl write-trace in tcl_eggint — the logs
           * array must be reallocated via init_misc() when the limit grows,
           * otherwise chanprog()'s post-config loop writes past the end of
           * the array and corrupts the heap. */
          if (e->val == &max_logs) {
            if (l < 5) l = 5;
            if (l > max_logs) {
              max_logs = l;
              init_misc();
            }
          /* max-socks: only allow increasing (decreasing needs a restart). */
          } else if (e->val == &max_socks) {
            if (l > max_socks)
              max_socks = l;
          } else {
            *e->val = l;
          }
        }
        return;
      }
    }
  }
  /* Coups ("N:M") */
  for (int i = 0; i < notcl_ncoup; i++) {
    tcl_coups *e;
    for (e = notcl_coup_lists[i]; e->name; e++) {
      if (!strcmp(e->name, name)) {
        int lv = 0, rv = 0;
        sscanf(value, "%d:%d", &lv, &rv);
        if (e->lptr) *e->lptr = lv;
        if (e->rptr) *e->rptr = rv;
        return;
      }
    }
  }
}

/* notcl_getvar: read the current value of a registered variable into buf.
 * Returns buf on success, nullptr if not found.
 */
const char *notcl_getvar(const char *name, char *buf, size_t bufsz)
{
  /* Strings */
  for (int i = 0; i < notcl_nstr; i++) {
    tcl_strings *e;
    for (e = notcl_str_lists[i]; e->name; e++) {
      if (!strcmp(e->name, name)) {
        if (e->buf) {
          op_strlcpy(buf, e->buf, bufsz);
          return buf;
        }
        return nullptr;
      }
    }
  }
  /* Ints */
  for (int i = 0; i < notcl_nint; i++) {
    tcl_ints *e;
    for (e = notcl_int_lists[i]; e->name; e++) {
      if (!strcmp(e->name, name)) {
        if (e->val) {
          op_strlcpy(buf, int_to_base10(*e->val), bufsz);
          return buf;
        }
        return nullptr;
      }
    }
  }
  return nullptr;
}

const char *tcl_resultstring(void) { return ""; }
int tcl_resultint(void) { return 0; }
int tcl_resultempty(void) { return 1; }

int tcl_threaded(void) { return 0; }
int fork_before_tcl(void) { return 0; }

time_t get_expire_time(Tcl_Interp *irp, const char *s)
{
  return 0;
}

/* threaddata / init_threaddata: no-TCL replacements using static storage.
 * Without TCL there is no thread-local storage, but eggdrop without TCL is
 * always single-threaded, so a single static instance is correct. */
static struct threaddata td_static;
struct threaddata *td_main = &td_static;

struct threaddata *threaddata(void)
{
  return &td_static;
}

void init_threaddata(int mainthread)
{
  struct threaddata *td = &td_static;
  td->mainloopfunc = nullptr;
  td->socklist = nullptr;
  td->mainthread = mainthread;
  td->blocktime.tv_sec = 1;
  td->blocktime.tv_usec = 0;
  td->MAXSOCKS = 0;
  increase_socks_max();
}

#endif /* HAVE_TCL */

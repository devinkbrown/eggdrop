/*
 * chanprog.c -- handles:
 *   rmspace()
 *   maintaining the server list
 *   revenge punishment
 *   timers, utimers
 *   telling the current programmed settings
 *   initializing a lot of stuff and loading the tcl scripts
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

#include "main.h"
#ifdef TLS
#  include <wolfssl/version.h>  /* LIBWOLFSSL_VERSION_STRING */
#endif
#include <sys/utsname.h>
#include "modules.h"
#include "configtoml.h"

extern struct dcc_t *dcc;
extern struct userrec *userlist;
extern log_t *logs;
extern Tcl_Interp *interp;
extern char ver[], botnetnick[], firewall[], motdfile[], userfile[], helpdir[],
            moddir[], notify_new[], configfile[];
extern time_t now, online_since;
extern int backgrd, term_z, con_chan, cache_hit, cache_miss, firewallport,
           default_flags, max_logs, conmask, protect_readonly, make_userfile,
           noshare, ignore_time, max_socks;
#ifdef TLS
extern SSL_CTX *ssl_ctx;
#endif

tcl_timer_t *timer = NULL;         /* Minutely timer               */
tcl_timer_t *utimer = NULL;        /* Secondly timer               */

/* Slab allocator for tcl_timer_t nodes — lazy-initialised on first timer. */
static op_bh *timer_bh = NULL;
uint64_t timer_id = 1;             /* Next timer of any sort will
                                    * have this number             */
struct chanset_t *chanset = NULL;  /* Channel list                 */
char admin[121] = "";              /* Admin info                   */
char origbotname[NICKLEN];
char botname[NICKLEN];             /* Primary botname              */
char owner[121] = "";              /* Permanent botowner(s)        */
void remove_timer_from_list(tcl_timer_t ** stack);


/* Remove leading and trailing whitespaces.
 */
void rmspace(char *s)
{
  char *p = NULL, *q = NULL;

  if (!s || !*s)
    return;

  /* Remove trailing whitespaces. */
  for (q = s + strlen(s) - 1; q >= s && egg_isspace(*q); q--);
  *(q + 1) = 0;

  /* Remove leading whitespaces. */
  for (p = s; egg_isspace(*p); p++);

  if (p != s)
    memmove(s, p, q - p + 2);
}


/* Returns memberfields if the nick is in the member list.
 */
memberlist *ismember(struct chanset_t *chan, char *nick)
{
  memberlist *x;

  for (x = chan->channel.member; x && x->nick[0]; x = x->next)
    if (!rfc_casecmp(x->nick, nick))
      return x;
  return NULL;
}

/* Find a chanset by channel name as the server knows it (ie !ABCDEchannel)
 */
struct chanset_t *findchan(const char *name)
{
  struct chanset_t *chan;

  for (chan = chanset; chan; chan = chan->next)
    if (!rfc_casecmp(chan->name, name))
      return chan;
  return NULL;
}

/* Find a chanset by display name (ie !channel)
 */
struct chanset_t *findchan_by_dname(const char *name)
{
  struct chanset_t *chan;

  for (chan = chanset; chan; chan = chan->next)
    if (!rfc_casecmp(chan->dname, name))
      return chan;
  return NULL;
}

/* Clear the user pointers in the chanlists.
 *
 * Necessary when:
 * - a hostmask is added/removed
 * - an account is added/removed
 * - a user is added
 * - new userfile is loaded
 */
void clear_chanlist(void)
{
  memberlist *m;
  struct chanset_t *chan;

  for (chan = chanset; chan; chan = chan->next)
    for (m = chan->channel.member; m && m->nick[0]; m = m->next) {
      m->user = NULL;
      m->tried_getuser = 0;
    }
}

/* Clear the user pointer of a specific nick in the chanlists.
 *
 * Necessary when:
 * - their hostmask changed (chghost)
 * - their account changed
 */
void clear_chanlist_member(const char *nick)
{
  memberlist *m;
  struct chanset_t *chan;

  for (chan = chanset; chan; chan = chan->next)
    for (m = chan->channel.member; m && m->nick[0]; m = m->next)
      if (!rfc_casecmp(m->nick, nick)) {
        m->user = NULL;
        m->tried_getuser = 0;
        break;
      }
}

/* Calculate the memory we should be using
 */
int expmem_chanprog(void)
{
  int tot = 0;
  tcl_timer_t *t;

  for (t = timer; t; t = t->next)
    tot += sizeof(tcl_timer_t) + strlen(t->cmd) + 1;
  for (t = utimer; t; t = t->next)
    tot += sizeof(tcl_timer_t) + strlen(t->cmd) + 1;
  return tot;
}

float getcputime(void)
{
  float stime, utime;
  struct rusage ru;

  getrusage(RUSAGE_SELF, &ru);
  utime = ru.ru_utime.tv_sec + (ru.ru_utime.tv_usec / 1000000.00);
  stime = ru.ru_stime.tv_sec + (ru.ru_stime.tv_usec / 1000000.00);
  return (utime + stime);
}

/* Dump uptime info out to dcc (guppy 9Jan99)
 */
void tell_verbose_uptime(int idx)
{
  char s[256], s1[121];
  time_t now2, hr, min;

  now2 = now - online_since;
  s[0] = 0;
  if (now2 > 86400) {
    /* days */
    snprintf(s, sizeof(s), "%d day", (int) (now2 / 86400));
    if ((int) (now2 / 86400) >= 2)
      strlcat(s, "s", sizeof s);
    strlcat(s, ", ", sizeof s);
    now2 -= (((int) (now2 / 86400)) * 86400);
  }
  hr = (time_t) ((int) now2 / 3600);
  now2 -= (hr * 3600);
  min = (time_t) ((int) now2 / 60);
  op_snprintf_append(s, sizeof(s), "%02d:%02d", (int) hr, (int) min);
  s1[0] = 0;
  if (backgrd)
    strlcpy(s1, MISC_BACKGROUND, sizeof(s1));
  else {
    if (term_z >= 0)
      strlcpy(s1, MISC_TERMMODE, sizeof(s1));
    else if (con_chan)
      strlcpy(s1, MISC_STATMODE, sizeof(s1));
    else
      strlcpy(s1, MISC_LOGMODE, sizeof(s1));
  }
  dprintf(idx, "%s %s  (%s)\n", MISC_ONLINEFOR, s, s1);
}

/* Dump status info out to dcc
 */
void tell_verbose_status(int idx)
{
  char s[256], s1[121], s2[81], *sysrel;
  int i;
  time_t now2 = now - online_since, hr, min;
  double cputime, cache_total;

  i = count_users(userlist);
  dprintf(idx, "I am %s, running %s: %d user%s (mem: %uk).\n",
          botnetnick, ver, i, i == 1 ? "" : "s",
          (int) (expected_memory() / 1024));
  s[0] = 0;
  if (now2 > 86400) {
    /* days */
    snprintf(s, sizeof(s), "%d day", (int) (now2 / 86400));
    if ((int) (now2 / 86400) >= 2)
      strlcat(s, "s", sizeof s);
    strlcat(s, ", ", sizeof s);
    now2 -= (((int) (now2 / 86400)) * 86400);
  }
  hr = (time_t) ((int) now2 / 3600);
  now2 -= (hr * 3600);
  min = (time_t) ((int) now2 / 60);
  op_snprintf_append(s, sizeof(s), "%02d:%02d", (int) hr, (int) min);
  s1[0] = 0;
  if (backgrd)
    strlcpy(s1, MISC_BACKGROUND, sizeof s1);
  else {
    if (term_z >= 0)
      strlcpy(s1, MISC_TERMMODE, sizeof s1);
    else if (con_chan)
      strlcpy(s1, MISC_STATMODE, sizeof s1);
    else
      strlcpy(s1, MISC_LOGMODE, sizeof s1);
  }
  cputime = getcputime();
  if (cputime < 0)
    strlcpy(s2, "CPU: unknown", sizeof s2);
  else {
    hr = cputime / 60;
    cputime -= hr * 60;
    snprintf(s2, sizeof(s2), "CPU: %02d:%05.2f", (int) hr, cputime); /* Actually min/sec */
  }
  if (cache_hit + cache_miss) {      /* 2019, still can't divide by zero */
    cache_total = 100.0 * (cache_hit) / (cache_hit + cache_miss);
  } else
    cache_total = 0;
  dprintf(idx, "%s %s (%s) - %s - %s: %4.1f%%\n", MISC_ONLINEFOR, s, s1, s2,
          MISC_CACHEHIT, cache_total);
  dprintf(idx, "Configured with: " EGG_AC_ARGS "\n");
  if (admin[0])
    dprintf(idx, "Admin: %s\n", admin);
  dprintf(idx, "Config file: %s\n", configfile);
  sysrel = egg_uname();
  if (*sysrel)
    dprintf(idx, "OS: %s\n", sysrel);
  dprintf(idx, "Process ID: %d (parent %d)\n", getpid(), getppid());

#ifdef HAVE_TCL
  /* info library */
  dprintf(idx, "%s %s\n", MISC_TCLLIBRARY,
          ((interp) && (Tcl_Eval(interp, "info library") == TCL_OK)) ?
          tcl_resultstring() : "*unknown*");

  /* info tclversion/patchlevel */
  dprintf(idx, "%s %s (%s %s)\n", MISC_TCLVERSION,
          ((interp) && (Tcl_Eval(interp, "info patchlevel") == TCL_OK)) ?
          tcl_resultstring() : (Tcl_Eval(interp, "info tclversion") == TCL_OK) ?
          tcl_resultstring() : "*unknown*", MISC_HEADERVERSION, TCL_PATCH_LEVEL);

  if (tcl_threaded())
    dprintf(idx, "Tcl is threaded.\n");
#else
  dprintf(idx, "Tcl scripting: disabled\n");
#endif /* HAVE_TCL */
#ifdef TLS
  dprintf(idx, "TLS support is enabled.\n"
               "TLS library: wolfSSL %s (%s)\n",
          LIBWOLFSSL_VERSION_STRING, MISC_HEADERVERSION);
#else
  dprintf(idx, "TLS support is not available.\n");
#endif
#ifdef IPV6
  dprintf(idx, "IPv6 support is enabled.\n"
#else
  dprintf(idx, "IPv6 support is not available.\n"
#endif
#ifdef EGG_TDNS
               "Threaded DNS core is enabled.\n"
#else
               "Threaded DNS core is disabled.\n"
#endif
               "Socket table: %d/%d\n", threaddata()->MAXSOCKS, max_socks);
}

/* Show all internal state variables
 */
void tell_settings(int idx)
{
  char s[1024];
  int i;
  struct flag_record fr = { FR_GLOBAL, 0, 0, 0, 0, 0 };

  dprintf(idx, "Botnet nickname: %s\n", botnetnick);
  if (firewall[0])
    dprintf(idx, "Firewall: %s:%d\n", firewall, firewallport);
  dprintf(idx, "Userfile: %s\n", userfile);
  dprintf(idx, "Motd: %s\n",  motdfile);
  dprintf(idx, "Directories:\n");
#ifndef STATIC
  dprintf(idx, "  Help   : %s\n", helpdir);
  dprintf(idx, "  Modules: %s\n", moddir);
#else
  dprintf(idx, "  Help: %s\n", helpdir);
#endif
  fr.global = default_flags;

  build_flags(s, &fr, NULL);
  dprintf(idx, "%s [%s], %s: %s\n", MISC_NEWUSERFLAGS, s,
          MISC_NOTIFY, notify_new);
  if (owner[0])
    dprintf(idx, "%s: %s\n", MISC_PERMOWNER, owner);
  for (i = 0; i < max_logs; i++)
    if (logs[i].filename != NULL) {
      dprintf(idx, "Logfile #%d: %s on %s (%s: %s)\n", i + 1,
              logs[i].filename, logs[i].chname,
              masktype(logs[i].mask), maskname(logs[i].mask));
    }
  dprintf(idx, "Ignores last %d minute%s.\n", ignore_time,
          (ignore_time != 1) ? "s" : "");
}

void reaffirm_owners(void)
{
  char *p, *q, s[sizeof owner];
  struct userrec *u;

  /* Please stop breaking this function. */
  if (owner[0]) {
    q = owner;
    p = strchr(q, ',');
    while (p) {
      strlcpy(s, q, (p - q) + 1);
      rmspace(s);
      u = get_user_by_handle(userlist, s);
      if (u)
        u->flags = sanity_check(u->flags | USER_OWNER);
      q = p + 1;
      p = strchr(q, ',');
    }
    strlcpy(s, q, sizeof(s));
    rmspace(s);
    u = get_user_by_handle(userlist, s);
    if (u)
      u->flags = sanity_check(u->flags | USER_OWNER);
  }
}

void chanprog(void)
{
  int i;

  admin[0]   = 0;
  helpdir[0] = 0;
  /* default mkcoblxs */
  conmask = LOG_MSGS|LOG_MODES|LOG_CMDS|LOG_MISC|LOG_BOTS|LOG_BOTMSG|LOG_FILES|LOG_SERV;

  for (i = 0; i < max_logs; i++)
    logs[i].flags |= LF_EXPIRING;

  /* Turn off read-only variables (make them write-able) for rehash */
  protect_readonly = 0;

  /* Now read it.
   *
   * .toml extension → TOML parser (no Tcl scripting knowledge required).
   * Any other extension → traditional Tcl-script parser (backward-compat).
   */
  {
    size_t cflen = strlen(configfile);
    int ok;
    if (cflen >= 5 && strcmp(configfile + cflen - 5, ".toml") == 0)
      ok = readtomlconfig(configfile);
    else {
#ifdef HAVE_TCL
      putlog(LOG_MISC, "*",
             "NOTE: Loading '%s' as a Tcl config script. "
             "Consider migrating to TOML: run 'eggdrop --setup' to generate "
             "a modern eggdrop.toml with no Tcl knowledge required.",
             configfile);
      ok = readtclprog(configfile);
#else
      putlog(LOG_MISC, "*",
             "ERROR: Config file '%s' appears to be a Tcl script, but this "
             "eggdrop was built without Tcl support. "
             "Please use a TOML config file (run 'eggdrop --setup' to generate one).",
             configfile);
      ok = 0;
#endif /* HAVE_TCL */
    }
    if (!ok)
      fatal(MISC_NOCONFIGFILE, 0);
  }

  for (i = 0; i < max_logs; i++) {
    if (logs[i].flags & LF_EXPIRING) {
      if (logs[i].filename != NULL) {
        nfree(logs[i].filename);
        logs[i].filename = NULL;
      }
      if (logs[i].chname != NULL) {
        nfree(logs[i].chname);
        logs[i].chname = NULL;
      }
      if (logs[i].f != NULL) {
        fclose(logs[i].f);
        logs[i].f = NULL;
      }
      logs[i].mask = 0;
      logs[i].flags = 0;
    }
  }

  /* We should be safe now */
  call_hook(HOOK_REHASH);
  protect_readonly = 1;

  if (!botnetnick[0])
    set_botnetnick(origbotname);

  if (!botnetnick[0])
    fatal("I don't have a botnet nick!!\n", 0);

  if (!userfile[0])
    fatal(MISC_NOUSERFILE2, 0);

  if (!readuserfile(userfile, &userlist)) {
    if (!make_userfile) {
      if (owner[0]) {
        /* Auto-create the userfile from the owner= list so -m is not needed. */
        char *p, *q, s[sizeof owner];

        printf("\nNo user file found — creating '%s' from owner list.\n",
               userfile);
        q = owner;
        p = strchr(q, ',');
        while (p) {
          strlcpy(s, q, (size_t)(p - q) + 1);
          rmspace(s);
          if (s[0] && !get_user_by_handle(userlist, s)) {
            userlist = adduser(userlist, s, "-", "-",
                               sanity_check(USER_MASTER | USER_OWNER));
            printf("  Created owner: %s\n", s);
          }
          q = p + 1;
          p = strchr(q, ',');
        }
        strlcpy(s, q, sizeof s);
        rmspace(s);
        if (s[0] && !get_user_by_handle(userlist, s)) {
          userlist = adduser(userlist, s, "-", "-",
                             sanity_check(USER_MASTER | USER_OWNER));
          printf("  Created owner: %s\n", s);
        }
        write_userfile(-1);
        make_userfile = 1;
        printf("User file created.  Say '%s hello' on IRC or connect via DCC to set your password.\n\n", origbotname);
      } else {
        char tmp[256];

        snprintf(tmp, sizeof tmp, MISC_NOUSERFILE, configfile);
        fatal(tmp, 0);
      }
    } else {
      printf("\n\n%s\n", MISC_NOUSERFILE2);
      if (module_find("server", 0, 0))
        printf(MISC_USERFCREATE1, origbotname);
      printf("%s\n\n", MISC_USERFCREATE2);
    }
  } else if (make_userfile) {
    make_userfile = 0;
    printf("%s\n", MISC_USERFEXISTS);
  }

  if (helpdir[0])
    if (helpdir[strlen(helpdir) - 1] != '/')
      strlcat(helpdir, "/", 121);

  reaffirm_owners();
  check_tcl_event("userfile-loaded");
}

/* Reload the user file from disk
 */
void reload(void)
{
  if (!file_readable(userfile)) {
    putlog(LOG_MISC, "*", "%s", MISC_CANTRELOADUSER);
    return;
  }

  noshare = 1;
  clear_userlist(userlist);
  noshare = 0;
  userlist = NULL;
  if (!readuserfile(userfile, &userlist))
    fatal(MISC_MISSINGUSERF, 0);
  reaffirm_owners();
  add_hq_user();
  check_tcl_event("userfile-loaded");
  call_hook(HOOK_READ_USERFILE);
}

void rehash(void)
{
  call_hook(HOOK_PRE_REHASH);
  noshare = 1;
  clear_userlist(userlist);
  noshare = 0;
  userlist = NULL;
  chanprog();
  add_hq_user();
}

/*
 *    Brief venture into timers
 */

/* Add a timer
 */
char * add_timer(tcl_timer_t ** stack, int elapse, int count,
                        char *cmd, char *name, unsigned long prev_id)
{
  tcl_timer_t *old = (*stack);
  char stringid[8];
  unsigned int ret;

  if (!timer_bh)
    timer_bh = op_bh_create(sizeof(tcl_timer_t), 16, "tcl_timer");
  *stack = op_bh_alloc(timer_bh);
  (*stack)->next = old;
  (*stack)->mins = (*stack)->interval = elapse;
  (*stack)->count = count;
  {
    size_t cmdlen = strlen(cmd) + 1;
    (*stack)->cmd = nmalloc(cmdlen);
    strlcpy((*stack)->cmd, cmd, cmdlen);
  }
  /* If it's just being added back and already had an id,
   * don't create a new one.
   */
  if (prev_id > 0)
    (*stack)->id = prev_id;
  else
    (*stack)->id = timer_id++;
  if (name) {
    {
      size_t namelen = strlen(name) + 1;
      (*stack)->name = nmalloc(namelen);
      strlcpy((*stack)->name, name, namelen);
    }
  } else {
    (*stack)->name = NULL;
    ret = snprintf(stringid, sizeof stringid, "%lu", (*stack)->id);
    if (ret >= (sizeof stringid)) {
      remove_timer_from_list(stack);
      return NULL;
    }
    (*stack)->name = nmalloc(strlen(stringid) + 6); /* 6 = strlen of "timer" + null */
    snprintf((*stack)->name, (strlen(stringid) + 6), "timer%s", stringid);
  }
  return (*stack)->name;
}

/* Remove timer from linked list */
void remove_timer_from_list(tcl_timer_t ** stack)
{
  tcl_timer_t *old;

  old = *stack;
  *stack = ((*stack)->next);
  nfree(old->cmd);
  if (old->name)
    nfree(old->name);
  op_bh_free(timer_bh, old);
}

/* Remove a timer (via name, not ID)
 */
int remove_timer(tcl_timer_t **stack, char *name)
{
  int ok = 0;

  while (*stack) {
    if ((*stack)->name && !strcasecmp((*stack)->name, name)) {
      ok++;
      remove_timer_from_list(stack);
    } else {
      stack = &((*stack)->next);
    }
  }
  return ok;
}

/* Check timers, execute the ones that have expired.
 */
void do_check_timers(tcl_timer_t ** stack)
{
  tcl_timer_t *mark = *stack, *old = NULL;
  char x[26];

  /* New timers could be added by a Tcl script inside a current timer
   * so i'll just clear out the timer list completely, and add any
   * unexpired timers back on.
   */
  *stack = NULL;
  while (mark) {
    if (mark->mins > 0)
      mark->mins--;
    old = mark;
    mark = mark->next;
    if (!old->mins) {
      snprintf(x, sizeof x, "timer%lu", old->id);
#ifdef HAVE_TCL
      do_tcl(x, old->cmd);
#endif
      if (old->count == 1) {
        nfree(old->cmd);
        if (old->name)
          nfree(old->name);
        nfree(old);
        continue;
      } else {
        old->mins = old->interval;
        if (old->count > 1)
          old->count--;
      }
    }
    old->next = *stack;
    *stack = old;
  }
}

/* Wipe all timers.
 */
void wipe_timers(Tcl_Interp *irp, tcl_timer_t **stack)
{
  tcl_timer_t *mark = *stack, *old;

  while (mark) {
    old = mark;
    mark = mark->next;
    nfree(old->cmd);
    if (old->name)
      nfree(old->name);
    nfree(old);
  }
  *stack = NULL;
}

/* Return list of timers (only meaningful when Tcl is present)
 */
void list_timers(Tcl_Interp *irp, tcl_timer_t *stack)
{
#ifdef HAVE_TCL
  char mins[11], count[11], *x;
  EGG_CONST char *argv[4];
  tcl_timer_t *mark;

  for (mark = stack; mark; mark = mark->next) {
    snprintf(mins, sizeof mins, "%u", mark->mins);
    snprintf(count, sizeof count, "%u", mark->count);
    argv[0] = mins;
    argv[1] = mark->cmd;
    argv[2] = mark->name;
    argv[3] = count;
    x = Tcl_Merge(sizeof(argv)/sizeof(*argv), argv);
    Tcl_AppendElement(irp, x);
    Tcl_Free((char *) x);
  }
#endif /* HAVE_TCL */
}

/* Find a timer by name. Returns 1 if found, 0 if not
 */
int find_timer(tcl_timer_t *stack, char *name)
{
  tcl_timer_t *mark;

  for (mark = stack; mark; mark = mark->next) {
    if (mark->name) {
      if (!strcasecmp(mark->name, name)) {
        return 1;
      }
    }
  }
  return 0;
}

int isowner(char *name) {
  char s[sizeof owner];
  char *sep = ", \t\n\v\f\r";
  char *word;

  char *saveptr = NULL;
  strlcpy(s, owner, sizeof(s));
  for (word = strtok_r(s, sep, &saveptr); word; word = strtok_r(NULL, sep, &saveptr)) {
    if (!strcasecmp(name, word)) {
      return 1;
    }
  }
  return 0;
}

/*
 * Adds the -HQ user to the userlist and takes care of needed permissions
 */
void add_hq_user(void)
{
  if (!backgrd && term_z >= 0) {
    /* HACK: Workaround using dcc[].nick not to pass literal "-HQ" as a non-const arg */
    dcc[term_z].user = get_user_by_handle(userlist, dcc[term_z].nick);
    /* Make sure there's an innocuous -HQ user if needed */
    if (!dcc[term_z].user) {
      userlist = adduser(userlist, dcc[term_z].nick, "none", "-", USER_PARTY);
      dcc[term_z].user = get_user_by_handle(userlist, dcc[term_z].nick);
    }
    /* Give all useful flags: efjlmnoptuvx */
    dcc[term_z].user->flags = USER_EXEMPT | USER_FRIEND | USER_JANITOR |
                              USER_HALFOP | USER_MASTER | USER_OWNER | USER_OP |
                              USER_PARTY | USER_BOTMAST | USER_UNSHARED |
                              USER_VOICE | USER_XFER | USER_HIGHLITE;
    /* Add to permowner list if there's place */
    if (strlen(owner) + sizeof EGG_BG_HANDLE < sizeof owner)
      strlcat(owner, " " EGG_BG_HANDLE, sizeof owner);

    /* Update laston info, gets cleared at rehash/reload */
    touch_laston(dcc[term_z].user, "partyline", now);
  }
}

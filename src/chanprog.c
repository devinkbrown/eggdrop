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
#  include <opssl/opssl.h>
#endif
#include <sys/utsname.h>
#include "modules.h"
#include "configtoml.h"
#include "egg_store.h"
#include "script.h"
#include "async_dns.h"

extern struct dcc_t *dcc;
extern struct userrec *userlist;
extern log_t *logs;
extern Tcl_Interp *interp;
extern op_vec_t module_vec;
extern char ver[], botnetnick[], firewall[], motdfile[], userfile[], helpdir[],
            moddir[], notify_new[], configfile[];
extern time_t now, online_since;
extern int backgrd, term_z, con_chan, cache_hit, cache_miss, firewallport,
           default_flags, max_logs, conmask, protect_readonly, make_userfile,
           noshare, ignore_time, max_socks;
#ifdef TLS
extern opssl_ctx_t *ssl_ctx;
#endif

op_vec_t timer = {};                  /* Minutely timer               */
op_vec_t utimer = {};                 /* Secondly timer               */

/* Slab allocator for tcl_timer_t nodes — lazy-initialised on first timer. */
static op_bh *timer_bh = nullptr;
uint64_t timer_id = 1;             /* Next timer of any sort will
                                    * have this number             */
struct chanset_t *chanset = nullptr;  /* Channel list                 */

/* O(1) channel lookup by server name and display name. */
static op_htab *chan_by_name  = nullptr;
static op_htab *chan_by_dname = nullptr;
char admin[121] = "";              /* Admin info                   */
char origbotname[NICKLEN];
char botname[NICKLEN];             /* Primary botname              */
char owner[121] = "";              /* Permanent botowner(s)        */


/* Remove leading and trailing whitespaces.
 */
void rmspace(char *s)
{
  char *p = nullptr, *q = nullptr;

  if (!s || !*s)
    return;

  /* Remove trailing whitespaces. */
  for (q = s + strlen(s) - 1; q >= s && isspace((unsigned char)(*q)); q--);
  *(q + 1) = 0;

  /* Remove leading whitespaces. */
  for (p = s; isspace((unsigned char)(*p)); p++);

  if (p != s)
    memmove(s, p, q - p + 2);
}


/* Returns memberfields if the nick is in the member list.
 */
memberlist *ismember(struct chanset_t *chan, const char *nick)
{
  memberlist *x;

  if (chan->channel.member_ht) {
    x = op_htab_get(chan->channel.member_ht, nick);
    return x;
  }
  for (x = chan->channel.member; x && x->nick[0]; x = x->next)
    if (!rfc_casecmp(x->nick, nick))
      return x;
  return nullptr;
}

/* Initialise (or reinitialise) the channel hash tables. */
void chan_htab_init(void)
{
  if (chan_by_name)
    op_htab_destroy(chan_by_name, nullptr, nullptr);
  if (chan_by_dname)
    op_htab_destroy(chan_by_dname, nullptr, nullptr);
  chan_by_name  = op_htab_create_istr("chan_name", 16);
  chan_by_dname = op_htab_create_istr("chan_dname", 16);
}

/* Register a channel in the hash tables.  Safe to call repeatedly
 * (e.g. after the server name changes on JOIN). */
void chan_htab_add(struct chanset_t *chan)
{
  if (!chan_by_dname)
    chan_htab_init();
  op_htab_set(chan_by_dname, chan->dname, chan, nullptr);
  if (chan->name[0])
    op_htab_set(chan_by_name, chan->name, chan, nullptr);
}

/* Remove a channel from the hash tables. */
void chan_htab_del(struct chanset_t *chan)
{
  if (chan_by_dname)
    op_htab_del(chan_by_dname, chan->dname);
  if (chan_by_name && chan->name[0])
    op_htab_del(chan_by_name, chan->name);
}

/* Find a chanset by channel name as the server knows it (ie !ABCDEchannel)
 */
struct chanset_t *findchan(const char *name)
{
  if (chan_by_name) {
    struct chanset_t *c = op_htab_get(chan_by_name, name);
    if (c)
      return c;
  }
  /* Fallback: linear scan (htab not yet initialised or name not indexed). */
  for (struct chanset_t *chan = chanset; chan; chan = chan->next)
    if (!rfc_casecmp(chan->name, name))
      return chan;
  return nullptr;
}

/* Find a chanset by display name (ie !channel)
 */
struct chanset_t *findchan_by_dname(const char *name)
{
  if (chan_by_dname) {
    struct chanset_t *c = op_htab_get(chan_by_dname, name);
    if (c)
      return c;
  }
  for (struct chanset_t *chan = chanset; chan; chan = chan->next)
    if (!rfc_casecmp(chan->dname, name))
      return chan;
  return nullptr;
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
      m->user = nullptr;
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
        m->user = nullptr;
        m->tried_getuser = 0;
        break;
      }
}



/* Dump uptime info out to dcc (guppy 9Jan99)
 */
void tell_verbose_uptime(int idx)
{
  char upbuf[64];

  egg_format_uptime(now - online_since, upbuf, sizeof upbuf);
  const char *mode;
  if (backgrd)
    mode = MISC_BACKGROUND;
  else if (term_z >= 0)
    mode = MISC_TERMMODE;
  else if (con_chan)
    mode = MISC_STATMODE;
  else
    mode = MISC_LOGMODE;
  dprintf(idx, "%s %s  (%s)\n", MISC_ONLINEFOR, upbuf, mode);
}

/* Dump status info out to dcc
 */
void tell_verbose_status(int idx)
{
  char *sysrel;
  char upbuf[64];
  double cputime, cache_total;

  int i = count_users(userlist);
  dprintf(idx, "I am %s, running %s: %d user%s (rss: %ldk).\n",
          botnetnick, ver, i, i == 1 ? "" : "s", egg_get_rss_kb());
  egg_format_uptime(now - online_since, upbuf, sizeof upbuf);
  const char *mode;
  if (backgrd)
    mode = MISC_BACKGROUND;
  else if (term_z >= 0)
    mode = MISC_TERMMODE;
  else if (con_chan)
    mode = MISC_STATMODE;
  else
    mode = MISC_LOGMODE;
  cputime = getcputime();
  op_strbuf_t cpubuf = {};
  op_strbuf_init(&cpubuf);
  if (cputime < 0)
    op_strbuf_append_cstr(&cpubuf, "CPU: unknown");
  else {
    int hr = (int)(cputime / 60);
    cputime -= hr * 60;
    op_strbuf_appendf(&cpubuf, "CPU: %02d:%05.2f", hr, cputime);
  }
  if (cache_hit + cache_miss)
    cache_total = 100.0 * (cache_hit) / (cache_hit + cache_miss);
  else
    cache_total = 0;
  dprintf(idx, "%s %s (%s) - %s - %s: %4.1f%%\n", MISC_ONLINEFOR,
          upbuf, mode, op_strbuf_str(&cpubuf), MISC_CACHEHIT, cache_total);
  dprintf(idx, "Configured with: " EGG_AC_ARGS "\n");
  if (admin[0])
    dprintf(idx, "Admin: %s\n", admin);
  dprintf(idx, "Config file: %s\n", configfile);
  sysrel = egg_uname();
  if (*sysrel)
    dprintf(idx, "OS: %s\n", sysrel);
  dprintf(idx, "Process ID: %d (parent %d)\n", getpid(), getppid());

  if (interp) {
    /* info library */
    dprintf(idx, "%s %s\n", MISC_TCLLIBRARY,
            !egg_eval("info library") ? tcl_resultstring() : "*unknown*");

    /* info tclversion/patchlevel */
    dprintf(idx, "%s %s (%s %s)\n", MISC_TCLVERSION,
            !egg_eval("info patchlevel") ? tcl_resultstring() :
            !egg_eval("info tclversion") ? tcl_resultstring() : "*unknown*",
            MISC_HEADERVERSION, TCL_PATCH_LEVEL);

    if (tcl_threaded())
      dprintf(idx, "Tcl is threaded.\n");
  } else {
    dprintf(idx, "Tcl scripting: disabled\n");
  }
  dprintf(idx, "Scripting engines:");
  if (interp) dprintf(idx, " Tcl");
  if (module_find("python", 0, 0)) dprintf(idx, " Python");
  dprintf(idx, "\n");
  {
    dprintf(idx, "Loaded modules: %zu\n", module_vec.size);
  }
  dprintf(idx, "Memory (RSS): %ld KB\n", egg_get_rss_kb());
#ifdef TLS
  dprintf(idx, "TLS support is enabled.\n"
               "TLS library: opssl %s\n",
          opssl_version_string());
#else
  dprintf(idx, "TLS support is not available.\n");
#endif
#ifdef IPV6
  dprintf(idx, "IPv6 support is enabled.\n"
#else
  dprintf(idx, "IPv6 support is not available.\n"
#endif
               "Socket table: %d/%d\n", threaddata()->MAXSOCKS, max_socks);
  op_strbuf_free(&cpubuf);
}

/* Show all internal state variables
 */
void tell_settings(int idx)
{
  char s[1024];
  struct flag_record fr = { FR_GLOBAL };

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

  build_flags(s, &fr, nullptr);
  dprintf(idx, "%s [%s], %s: %s\n", MISC_NEWUSERFLAGS, s,
          MISC_NOTIFY, notify_new);
  if (owner[0])
    dprintf(idx, "%s: %s\n", MISC_PERMOWNER, owner);
  for (int i = 0; i < max_logs; i++)
    if (logs[i].filename != nullptr) {
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
      op_strlcpy(s, q, (p - q) + 1);
      rmspace(s);
      u = get_user_by_handle(userlist, s);
      if (u)
        u->flags = sanity_check(u->flags | USER_OWNER);
      q = p + 1;
      p = strchr(q, ',');
    }
    op_strlcpy(s, q, sizeof(s));
    rmspace(s);
    u = get_user_by_handle(userlist, s);
    if (u)
      u->flags = sanity_check(u->flags | USER_OWNER);
  }
}

void chanprog(void)
{
  admin[0]   = 0;
  helpdir[0] = 0;
  /* default mkcoblxs */
  conmask = LOG_MSGS|LOG_MODES|LOG_CMDS|LOG_MISC|LOG_BOTS|LOG_BOTMSG|LOG_FILES|LOG_SERV;

  for (int i = 0; i < max_logs; i++)
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
      if (interp) {
        putlog(LOG_MISC, "*",
               "NOTE: Loading '%s' as a Tcl config script. "
               "Consider migrating to TOML: run 'eggdrop --setup' to generate "
               "a modern eggdrop.toml with no Tcl knowledge required.",
               configfile);
        ok = readtclprog(configfile);
      } else {
        putlog(LOG_MISC, "*",
               "ERROR: Config file '%s' appears to be a Tcl script, but this "
               "eggdrop was built without Tcl support. "
               "Please use a TOML config file (run 'eggdrop --setup' to generate one).",
               configfile);
        ok = 0;
      }
    }
    if (!ok)
      fatal(MISC_NOCONFIGFILE, 0);
  }

  for (int i = 0; i < max_logs; i++) {
    if (logs[i].flags & LF_EXPIRING) {
      if (logs[i].filename != nullptr) {
        op_free(logs[i].filename);
        logs[i].filename = nullptr;
      }
      if (logs[i].chname != nullptr) {
        op_free(logs[i].chname);
        logs[i].chname = nullptr;
      }
      if (logs[i].f != nullptr) {
        fclose(logs[i].f);
        logs[i].f = nullptr;
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

  /* Initialize the storage backend (LMDB or flat). */
  egg_store_init();

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
          op_strlcpy(s, q, (size_t)(p - q) + 1);
          rmspace(s);
          if (s[0] && !get_user_by_handle(userlist, s)) {
            userlist = adduser(userlist, s, "-", "-",
                               sanity_check(USER_MASTER | USER_OWNER));
            printf("  Created owner: %s\n", s);
          }
          q = p + 1;
          p = strchr(q, ',');
        }
        op_strlcpy(s, q, sizeof s);
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
        op_strbuf_t tmp = {};
        op_strbuf_init(&tmp);
        op_strbuf_appendf(&tmp, MISC_NOUSERFILE, configfile);
        fatal(op_strbuf_str(&tmp), 0);
        op_strbuf_free(&tmp);
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
      op_strlcat(helpdir, "/", 121);

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
  userlist = nullptr;
  if (!readuserfile(userfile, &userlist))
    fatal(MISC_MISSINGUSERF, 0);
  reaffirm_owners();
  add_hq_user();
  check_tcl_event("userfile-loaded");
  call_hook(HOOK_READ_USERFILE);
}

extern void text_cache_flush(void);

void rehash(void)
{
  async_dns_cache_flush();  /* stale DNS mappings won't survive a rehash */
  text_cache_flush();        /* force re-read of MOTD/banner after config reload */
  call_hook(HOOK_PRE_REHASH);
  noshare = 1;
  clear_userlist(userlist);
  noshare = 0;
  userlist = nullptr;
  chanprog();
  add_hq_user();
}

/*
 *    Brief venture into timers
 */

/* op_event callback: fires a Tcl timer, reschedules or removes. */
static void egg_timer_fire(void *arg)
{
  tcl_timer_t *t = arg;

  {
    op_strbuf_t x = {};
    op_strbuf_init(&x);
    op_strbuf_appendf(&x, "timer%lu", t->id);
    do_tcl(op_strbuf_str(&x), t->cmd);
    op_strbuf_free(&x);
  }

  if (t->count == 1) {
    /* Last firing — remove from its vec and free. */
    op_vec_t *head = (t->secs_per_tick == 1) ? &utimer : &timer;
    for (size_t _i = head->size; _i-- > 0; ) {
      if (op_vec_get(head, _i) == t) { op_vec_remove(head, _i); break; }
    }
    op_free(t->cmd);
    if (t->name) op_free(t->name);
    op_bh_free(timer_bh, t);
  } else {
    if (t->count > 1) t->count--;
    time_t when_secs = (time_t)t->interval * t->secs_per_tick;
    t->fire_at = time(nullptr) + when_secs;
    t->ev = op_event_addonce(t->name, egg_timer_fire, t, when_secs);
  }
}

/* Add a timer scheduled via op_event. */
char *add_timer(op_vec_t *stack, int elapse, int count,
                char *cmd, char *name, unsigned long prev_id)
{
  tcl_timer_t *t;

  if (!timer_bh)
    timer_bh = op_bh_create(sizeof(tcl_timer_t), 16, "tcl_timer");
  t = (tcl_timer_t *)op_bh_alloc(timer_bh);
  t->interval = elapse;
  t->count = count;
  t->secs_per_tick = (stack == &utimer) ? 1 : 60;
  {
    size_t cmdlen = strlen(cmd) + 1;
    t->cmd = op_malloc(cmdlen);
    op_strlcpy(t->cmd, cmd, cmdlen);
  }
  if (prev_id > 0)
    t->id = prev_id;
  else
    t->id = timer_id++;
  if (name) {
    size_t namelen = strlen(name) + 1;
    t->name = op_malloc(namelen);
    op_strlcpy(t->name, name, namelen);
  } else {
    op_strbuf_t name_buf = {};
    op_strbuf_init(&name_buf);
    op_strbuf_appendf(&name_buf, "timer%" PRIu64, t->id);
    t->name = op_strdup(op_strbuf_str(&name_buf));
    op_strbuf_free(&name_buf);
  }
  {
    time_t when_secs = (time_t)elapse * t->secs_per_tick;
    t->fire_at = time(nullptr) + when_secs;
    t->ev = op_event_addonce(t->name, egg_timer_fire, t, when_secs);
  }
  op_vec_push(stack, t);
  return t->name;
}

/* Remove a timer by name, cancelling its event. */
int remove_timer(op_vec_t *stack, char *name)
{
  int ok = 0;

  for (size_t _i = stack->size; _i-- > 0; ) {
    tcl_timer_t *t = (tcl_timer_t *)op_vec_get(stack, _i);

    if (t->name && !op_strcasecmp(t->name, name)) {
      ok++;
      op_vec_remove(stack, _i);
      if (t->ev)
        op_event_delete(t->ev);
      op_free(t->cmd);
      if (t->name)
        op_free(t->name);
      op_bh_free(timer_bh, t);
    }
  }
  return ok;
}

/* Fire any expired timers via op_event. */
void do_check_timers([[maybe_unused]] op_vec_t *stack)
{
  op_event_run();
}

/* Wipe all timers. */
void wipe_timers([[maybe_unused]] Tcl_Interp *irp, op_vec_t *stack)
{
  for (size_t _i = 0; _i < stack->size; _i++) {
    tcl_timer_t *t = (tcl_timer_t *)op_vec_get(stack, _i);

    if (t->ev)
      op_event_delete(t->ev);
    op_free(t->cmd);
    if (t->name)
      op_free(t->name);
    op_bh_free(timer_bh, t);
  }
  op_vec_fini(stack, nullptr, nullptr);
}

/* Return list of timers (only meaningful when Tcl is present). */
void list_timers(Tcl_Interp *irp, op_vec_t *stack)
{
  time_t now_t = time(nullptr);

  for (size_t _i = 0; _i < stack->size; _i++) {
    char *x;
    EGG_CONST char *argv[4];
    tcl_timer_t *mark = (tcl_timer_t *)op_vec_get(stack, _i);
    unsigned int remaining = (mark->fire_at > now_t)
      ? (unsigned int)((mark->fire_at - now_t) / mark->secs_per_tick) : 0;
    op_strbuf_t ticks = {}, count = {};

    op_strbuf_appendf(&ticks, "%u", remaining);
    op_strbuf_appendf(&count, "%u", mark->count);
    argv[0] = op_strbuf_str(&ticks);
    argv[1] = mark->cmd;
    argv[2] = mark->name;
    argv[3] = op_strbuf_str(&count);
    x = Tcl_Merge(sizeof(argv)/sizeof(*argv), argv);
    Tcl_AppendElement(irp, x);
    Tcl_Free((char *) x);
    op_strbuf_free(&ticks);
    op_strbuf_free(&count);
  }
}

/* Find a timer by name. Returns 1 if found, 0 if not. */
int find_timer(op_vec_t *stack, char *name)
{
  for (size_t _i = 0; _i < stack->size; _i++) {
    tcl_timer_t *mark = (tcl_timer_t *)op_vec_get(stack, _i);

    if (mark->name && !op_strcasecmp(mark->name, name))
      return 1;
  }
  return 0;
}

int isowner(char *name) {
  char s[sizeof owner];
  char *sep = ", \t\n\v\f\r";
  char *word;

  char *saveptr = nullptr;
  op_strlcpy(s, owner, sizeof(s));
  for (word = strtok_r(s, sep, &saveptr); word; word = strtok_r(nullptr, sep, &saveptr)) {
    if (!op_strcasecmp(name, word)) {
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
      op_strlcat(owner, " " EGG_BG_HANDLE, sizeof owner);

    /* Update laston info, gets cleared at rehash/reload */
    touch_laston(dcc[term_z].user, "partyline", now);
  }
}

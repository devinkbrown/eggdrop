/*
 * cmds.c -- handles:
 *   commands from a user via dcc
 *   (split in 2, this portion contains no-irc commands)
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
#include "tandem.h"
#include "modules.h"
#include "script.h"
#include "threadpool.h"
#include "async_log.h"
#include "async_fileio.h"
#include "async_dns.h"
#include <signal.h>
#include <stdint.h>
#include <inttypes.h>
#include <op_async.h>

extern struct chanset_t *chanset;
extern struct dcc_t *dcc;
extern struct userrec *userlist;
extern op_vec_t timer, utimer;
extern int dcc_total, remote_boots, backgrd, make_userfile, conmask, require_p,
           must_be_owner;
extern volatile sig_atomic_t do_restart;
#include "traffic.h"
extern Tcl_Interp *interp;
extern char botnetnick[], origbotname[], ver[], network[], owner[], quit_msg[];
extern time_t now, online_since;
extern op_vec_t module_vec;

static const char *btos(uint64_t);

/* Define some characters not allowed in address/port string
 */
#define BADADDRCHARS "+/"


/* Add hostmask to a bot's record if possible.
 */
static int add_bot_hostmask(int idx, char *nick)
{
  struct chanset_t *chan;

  for (chan = chanset; chan; chan = chan->next)
    if (channel_active(chan)) {
      memberlist *m = ismember(chan, nick);

      if (m) {
        op_strbuf_t s = {};
        op_strbuf_init(&s);
        struct userrec *u;

        op_strbuf_appendf(&s, "%s!%s", m->nick, m->userhost);
        u = get_user_by_host(op_strbuf_str(&s));
        if (u) {
          op_strbuf_free(&s);
          dprintf(idx, "(Can't add hostmask for %s because it matches %s)\n",
                  nick, u->handle);
          return 0;
        }
        if (strchr("~^+=-", m->userhost[0])) {
          op_strbuf_clear(&s);
          op_strbuf_appendf(&s, "*!?%s", m->userhost + 1);
        } else {
          op_strbuf_clear(&s);
          op_strbuf_appendf(&s, "*!%s", m->userhost);
        }
        dprintf(idx, "(Added hostmask for %s from %s)\n", nick, chan->dname);
        addhost_by_handle(nick, op_strbuf_str(&s));
        op_strbuf_free(&s);
        return 1;
      }
    }
  return 0;
}

static void tell_who(struct userrec *u, int idx, int chan)
{
  int atr = u ? u->flags : 0;
  bool ok = false;
  int nicklen = 9;

  if (!chan)
    dprintf(idx, "%s (* = owner, + = master, %% = botmaster, @ = op, "
            "^ = halfop)\n", BOT_PARTYMEMBS);
  else {
    op_strbuf_t assoccmd = {};
    op_strbuf_init(&assoccmd);
    op_strbuf_appendf(&assoccmd, "assoc %d", chan);
    if (egg_eval(op_strbuf_str(&assoccmd)) || tcl_resultempty())
      dprintf(idx, "%s %s%d: (* = owner, + = master, %% = botmaster, @ = op, "
              "^ = halfop)\n", BOT_PEOPLEONCHAN, (chan < GLOBAL_CHANS) ? "" :
              "*", chan % GLOBAL_CHANS);
    else
      dprintf(idx, "%s '%s' (%s%d): (* = owner, + = master, %% = botmaster, @ = op, "
              "^ = halfop)\n", BOT_PEOPLEONCHAN, tcl_resultstring(),
              (chan < GLOBAL_CHANS) ? "" : "*", chan % GLOBAL_CHANS);
    op_strbuf_free(&assoccmd);
  }

  /* calculate max nicklen */
  for (int i = 0; i < dcc_total; i++) {
    int nl = (int) strlen(dcc[i].nick);
    if (nl > nicklen)
      nicklen = nl;
  }

  for (int i = 0; i < dcc_total; i++)
    if (dcc[i].type == &DCC_CHAT && dcc[i].u.chat->channel == chan) {
      char icon = (geticon(i) == '-') ? ' ' : geticon(i);
      op_strbuf_t s = {};
      op_strbuf_init(&s);
      if (atr & USER_OWNER)
        op_strbuf_appendf(&s, "  [%02lu]  %c%-*s %s", dcc[i].sock, icon,
                         nicklen, dcc[i].nick, dcc[i].host);
      else
        op_strbuf_appendf(&s, "  %c%-*s %s", icon, nicklen, dcc[i].nick,
                         dcc[i].host);
      if ((atr & USER_MASTER) && dcc[i].u.chat->con_flags)
        op_strbuf_appendf(&s, " (con:%s)", masktype(dcc[i].u.chat->con_flags));
      if (now - dcc[i].timeval > 300) {
        uint64_t elapsed = (uint64_t)(now - dcc[i].timeval);
        uint64_t days = elapsed / 86400;
        uint64_t hrs  = (elapsed % 86400) / 3600;
        uint64_t mins = (elapsed % 3600) / 60;
        if (days > 0)
          op_strbuf_appendf(&s, " (idle %" PRIu64 "d%" PRIu64 "h)", days, hrs);
        else if (hrs > 0)
          op_strbuf_appendf(&s, " (idle %" PRIu64 "h%" PRIu64 "m)", hrs, mins);
        else
          op_strbuf_appendf(&s, " (idle %" PRIu64 "m)", mins);
      }
      dprintf(idx, "%s\n", op_strbuf_str(&s));
      op_strbuf_free(&s);
      if (dcc[i].u.chat->away != nullptr)
        dprintf(idx, "      AWAY: %s\n", dcc[i].u.chat->away);
    }

  for (int i = 0; i < dcc_total; i++)
    if (dcc[i].type == &DCC_BOT) {
      char timebuf[14];
      const char *dir  = (dcc[i].status & STAT_CALLED) ? "<-" : "->";
      char        flag = (dcc[i].status & STAT_SHARE)  ? '+' : ' ';
      if (!ok) {
        ok = true;
        dprintf(idx, "Bots connected:\n");
      }
      strftime(timebuf, sizeof timebuf, "%d %b %H:%M", localtime(&dcc[i].timeval));
      if (atr & USER_OWNER)
        dprintf(idx, "  [%02lu]  %s%c%-*s (%s) %s\n", dcc[i].sock,
                dir, flag, nicklen, dcc[i].nick, timebuf,
                dcc[i].u.bot->version);
      else
        dprintf(idx, "  %s%c%-*s (%s) %s\n", dir, flag, nicklen,
                dcc[i].nick, timebuf, dcc[i].u.bot->version);
    }

  ok = false;
  for (int i = 0; i < dcc_total; i++) {
    if (dcc[i].type == &DCC_CHAT && dcc[i].u.chat->channel != chan) {
      char icon = (geticon(i) == '-') ? ' ' : geticon(i);
      op_strbuf_t s = {};
      op_strbuf_init(&s);
      if (!ok) {
        ok = true;
        dprintf(idx, "Other people on the bot:\n");
      }
      if (atr & USER_OWNER)
        op_strbuf_appendf(&s, "  [%02lu]  %c%-*s ", dcc[i].sock, icon,
                         nicklen, dcc[i].nick);
      else
        op_strbuf_appendf(&s, "  %c%-*s ", icon, nicklen, dcc[i].nick);
      if (atr & USER_MASTER) {
        if (dcc[i].u.chat->channel < 0)
          op_strbuf_append_cstr(&s, "(-OFF-) ");
        else if (!dcc[i].u.chat->channel)
          op_strbuf_append_cstr(&s, "(party) ");
        else
          op_strbuf_appendf(&s, "(%5d) ", dcc[i].u.chat->channel);
      }
      op_strbuf_append_cstr(&s, dcc[i].host);
      if ((atr & USER_MASTER) && dcc[i].u.chat->con_flags)
        op_strbuf_appendf(&s, " (con:%s)", masktype(dcc[i].u.chat->con_flags));
      if (now - dcc[i].timeval > 300) {
        int k = (int)((now - dcc[i].timeval) / 60);
        if (k < 60)
          op_strbuf_appendf(&s, " (idle %dm)", k);
        else
          op_strbuf_appendf(&s, " (idle %dh%dm)", k / 60, k % 60);
      }
      dprintf(idx, "%s\n", op_strbuf_str(&s));
      op_strbuf_free(&s);
      if (dcc[i].u.chat->away != nullptr)
        dprintf(idx, "      AWAY: %s\n", dcc[i].u.chat->away);
    }
    if ((atr & USER_MASTER) && (dcc[i].type->flags & DCT_SHOWWHO) &&
        (dcc[i].type != &DCC_CHAT)) {
      char flag = (dcc[i].status & STAT_CHAT) ? '+' : ' ';
      if (!ok) {
        ok = 1;
        dprintf(idx, "Other people on the bot:\n");
      }
      if (atr & USER_OWNER)
        dprintf(idx, "  [%02lu]  %c%-*s (files) %s\n", dcc[i].sock, flag,
                nicklen, dcc[i].nick, dcc[i].host);
      else
        dprintf(idx, "  %c%-*s (files) %s\n", flag, nicklen, dcc[i].nick,
                dcc[i].host);
    }
  }
}

static void cmd_botinfo(struct userrec *u, int idx, char *par)
{
  struct chanset_t *chan;
  time_t now2 = now - online_since;
  int hr, min;

  /* Build uptime string */
  op_strbuf_t s2 = {};
  op_strbuf_init(&s2);
  if (now2 > 86400) {
    int days = (int)(now2 / 86400);
    op_strbuf_appendf(&s2, "%d day%s, ", days, days >= 2 ? "s" : "");
    now2 -= (time_t)days * 86400;
  }
  hr  = (int)(now2 / 3600);
  min = (int)((now2 % 3600) / 60);
  op_strbuf_appendf(&s2, "%02d:%02d", hr, min);

  putlog(LOG_CMDS, "*", "#%s# botinfo", dcc[idx].nick);

  op_strbuf_t infokey = {};
  op_strbuf_init(&infokey);
  op_strbuf_appendf(&infokey, "%ld:%s@%s", dcc[idx].sock, dcc[idx].nick, botnetnick);
  botnet_send_infoq(-1, op_strbuf_str(&infokey));
  op_strbuf_free(&infokey);

  if (module_find("server", 0, 0)) {
    op_strbuf_t chanlist = {};
    op_strbuf_init(&chanlist);
    bool truncated = false;
    for (chan = chanset; chan; chan = chan->next) {
      if (!channel_secret(chan)) {
        /* Leave room for botnetnick, ver, network and protocol overhead */
        if (op_strbuf_len(&chanlist) + strlen(chan->dname) + strlen(network)
            + strlen(botnetnick) + strlen(ver) + 1 >= 490) {
          op_strbuf_append_cstr(&chanlist, "++  ");
          truncated = true;
          break;
        }
        op_strbuf_appendf(&chanlist, "%s, ", chan->dname);
      }
    }
    if (!truncated && op_strbuf_len(&chanlist) >= 2)
      op_strbuf_truncate(&chanlist, op_strbuf_len(&chanlist) - 2);

    if (!op_strbuf_empty(&chanlist))
      dprintf(idx, "*** [%s] %s <%s> (%s) [UP %s]\n", botnetnick, ver,
              network, op_strbuf_str(&chanlist), op_strbuf_str(&s2));
    else
      dprintf(idx, "*** [%s] %s <%s> (%s) [UP %s]\n", botnetnick, ver,
              network, BOT_NOCHANNELS, op_strbuf_str(&s2));
    op_strbuf_free(&chanlist);
  } else
    dprintf(idx, "*** [%s] %s <NO_IRC> [UP %s]\n", botnetnick, ver,
            op_strbuf_str(&s2));
  op_strbuf_free(&s2);
}

static void cmd_whom(struct userrec *u, int idx, char *par)
{
  if (par[0] == '*') {
    putlog(LOG_CMDS, "*", "#%s# whom %s", dcc[idx].nick, par);
    answer_local_whom(idx, -1);
    return;
  } else if (dcc[idx].u.chat->channel < 0) {
    dprintf(idx, "You have chat turned off.\n");
    return;
  }
  putlog(LOG_CMDS, "*", "#%s# whom %s", dcc[idx].nick, par);
  if (!par[0]) {
    answer_local_whom(idx, dcc[idx].u.chat->channel);
  } else {
    int chan = -1;

    if ((par[0] < '0') || (par[0] > '9')) {
      op_strbuf_t assoc_cmd = {};
      op_strbuf_init(&assoc_cmd);
      op_strbuf_appendf(&assoc_cmd, "assoc {%s}", par);
      if (!egg_eval(op_strbuf_str(&assoc_cmd)) && !tcl_resultempty())
        chan = tcl_resultint();
      op_strbuf_free(&assoc_cmd);
      if (chan <= 0) {
        dprintf(idx, "No such channel exists.\n");
        return;
      }
    } else
      chan = egg_atoi(par);
    if ((chan < 0) || (chan >= GLOBAL_CHANS)) {
      dprintf(idx, "Channel number out of range: must be between 0 and %d."
              "\n", GLOBAL_CHANS);
      return;
    }
    answer_local_whom(idx, chan);
  }
}

static void cmd_me(struct userrec *u, int idx, char *par)
{
  if (dcc[idx].u.chat->channel < 0) {
    dprintf(idx, "You have chat turned off.\n");
    return;
  }
  if (!par[0]) {
    dprintf(idx, "Usage: me <action>\n");
    return;
  }
  if (dcc[idx].u.chat->away != nullptr)
    not_away(idx);
  for (int i = 0; i < dcc_total; i++)
    if ((dcc[i].type->flags & DCT_CHAT) &&
        (dcc[i].u.chat->channel == dcc[idx].u.chat->channel) &&
        ((i != idx) || (dcc[i].status & STAT_ECHO)))
      dprintf(i, "* %s %s\n", dcc[idx].nick, par);
  botnet_send_act(idx, botnetnick, dcc[idx].nick,
                  dcc[idx].u.chat->channel, par);
  check_tcl_act(dcc[idx].nick, dcc[idx].u.chat->channel, par);
}

static void cmd_motd(struct userrec *u, int idx, char *par)
{
  if (par[0]) {
    putlog(LOG_CMDS, "*", "#%s# motd %s", dcc[idx].nick, par);
    if (!op_strcasecmp(par, botnetnick))
      show_motd(idx);
    else {
      int i = nextbot(par);
      if (i < 0)
        dprintf(idx, "That bot isn't connected.\n");
      else {
        const char *hl = (u->flags & USER_HIGHLITE) ?
                         ((dcc[idx].status & STAT_TELNET) ? "#" : "!") : "";
        op_strbuf_t x = {};
        op_strbuf_init(&x);
        op_strbuf_appendf(&x, "%s%ld:%s@%s", hl, dcc[idx].sock, dcc[idx].nick,
                         botnetnick);
        botnet_send_motd(i, op_strbuf_str(&x), par);
        op_strbuf_free(&x);
      }
    }
  } else {
    putlog(LOG_CMDS, "*", "#%s# motd", dcc[idx].nick);
    show_motd(idx);
  }
}

static void cmd_away(struct userrec *u, int idx, char *par)
{
  if (strlen(par) > 60)
    par[60] = 0;
  set_away(idx, par);
}

static void cmd_back(struct userrec *u, int idx, char *par)
{
  not_away(idx);
}

/* Take a password provided by the user and check that it isn't too long,
 * too short, or start with a '+' (for encryption reasons).
 *
 * If successful set it and return nullptr.
 *
 * On failure return error message.
 */
char *check_validpass(struct userrec *u, char *new) {
  int l;
  unsigned char *p = (unsigned char *) new;

  l = strlen(new);
  if (l < 6)
    return IRC_PASSFORMAT;
  if (l > PASSWORDMAX)
    return "Passwords cannot be longer than " STRINGIFY(PASSWORDMAX) " characters, please try again.";
  if (new[0] == '+') /* See also: userent.c:pass_set() */
    return "Password cannot start with '+', please try again.";
  while (*p) {
    if ((*p <= 32) || (*p == 127))
      return "Password cannot use weird symbols, please try again.";
    p++;
  }
  set_user(&USERENTRY_PASS, u, new);
  return nullptr;
}

static void cmd_newpass(struct userrec *u, int idx, char *par)
{
  char *new, *s;

  if (!par[0]) {
    dprintf(idx, "Usage: newpass <newpassword>\n");
    return;
  }
  new = newsplit(&par);
  if ((s = check_validpass(u, new))) {
    dprintf(idx, "%s\n", s);
    return;
  }
  putlog(LOG_CMDS, "*", "#%s# newpass...", dcc[idx].nick);
  dprintf(idx, "Changed password to '%s'.\n", new);
}

static void cmd_bots(struct userrec *u, int idx, char *par)
{
  putlog(LOG_CMDS, "*", "#%s# bots", dcc[idx].nick);
  tell_bots(idx);
}

static void cmd_bottree(struct userrec *u, int idx, char *par)
{
  putlog(LOG_CMDS, "*", "#%s# bottree", dcc[idx].nick);
  tell_bottree(idx, 0);
}

static void cmd_vbottree(struct userrec *u, int idx, char *par)
{
  putlog(LOG_CMDS, "*", "#%s# vbottree", dcc[idx].nick);
  tell_bottree(idx, 1);
}

static void cmd_rehelp(struct userrec *u, int idx, char *par)
{
  putlog(LOG_CMDS, "*", "#%s# rehelp", dcc[idx].nick);
  dprintf(idx, "Reload help cache...\n");
  reload_help_data();
}

static void cmd_help(struct userrec *u, int idx, char *par)
{
  struct flag_record fr = { FR_GLOBAL | FR_CHAN };

  get_user_flagrec(u, &fr, dcc[idx].u.chat->con_chan);
  if (par[0]) {
    putlog(LOG_CMDS, "*", "#%s# help %s", dcc[idx].nick, par);
    if (!strcmp(par, "all"))
      tellallhelp(idx, "all", &fr);
    else if (strchr(par, '*') || strchr(par, '?')) {
      char *p = par;

      /* Check if the search pattern only consists of '*' and/or '?'
       * If it does, show help for "all" instead of listing all help
       * entries.
       */
      for (p = par; *p && ((*p == '*') || (*p == '?')); p++);
      if (*p)
        tellwildhelp(idx, par, &fr);
      else
        tellallhelp(idx, "all", &fr);
    } else
      tellhelp(idx, par, &fr, 0);
  } else {
    putlog(LOG_CMDS, "*", "#%s# help", dcc[idx].nick);
    if (glob_op(fr) || glob_botmast(fr) || chan_op(fr))
      tellhelp(idx, "help", &fr, 0);
    else
      tellhelp(idx, "partyline", &fr, 0);
  }
}

static void cmd_addlog(struct userrec *u, int idx, char *par)
{
  if (!par[0]) {
    dprintf(idx, "Usage: addlog <message>\n");
    return;
  }
  dprintf(idx, "Placed entry in the log file.\n");
  putlog(LOG_MISC, "*", "%s: %s", dcc[idx].nick, par);
}

static void cmd_who(struct userrec *u, int idx, char *par)
{
  if (par[0]) {
    if (dcc[idx].u.chat->channel < 0) {
      dprintf(idx, "You have chat turned off.\n");
      return;
    }
    putlog(LOG_CMDS, "*", "#%s# who %s", dcc[idx].nick, par);
    if (!op_strcasecmp(par, botnetnick))
      tell_who(u, idx, dcc[idx].u.chat->channel);
    else {
      int i = nextbot(par);
      if (i < 0) {
        dprintf(idx, "That bot isn't connected.\n");
      } else if (dcc[idx].u.chat->channel >= GLOBAL_CHANS)
        dprintf(idx, "You are on a local channel.\n");
      else {
        op_strbuf_t s = {};
        op_strbuf_init(&s);
        op_strbuf_appendf(&s, "%ld:%s@%s", dcc[idx].sock, dcc[idx].nick, botnetnick);
        botnet_send_who(i, op_strbuf_str(&s), par, dcc[idx].u.chat->channel);
        op_strbuf_free(&s);
      }
    }
  } else {
    putlog(LOG_CMDS, "*", "#%s# who", dcc[idx].nick);
    if (dcc[idx].u.chat->channel < 0)
      tell_who(u, idx, 0);
    else
      tell_who(u, idx, dcc[idx].u.chat->channel);
  }
}

static void cmd_whois(struct userrec *u, int idx, char *par)
{
  if (!par[0]) {
    dprintf(idx, "Usage: whois <handle>\n");
    return;
  }

  putlog(LOG_CMDS, "*", "#%s# whois %s", dcc[idx].nick, par);
  tell_user_ident(idx, par);
}

static void cmd_match(struct userrec *u, int idx, char *par)
{
  int start = 1, limit = 20;
  char *s, *s1, *chname;

  if (!par[0]) {
    dprintf(idx, "Usage: match <nick/host> [[skip] count]\n");
    return;
  }
  putlog(LOG_CMDS, "*", "#%s# match %s", dcc[idx].nick, par);
  s = newsplit(&par);
  if (strchr(CHANMETA, par[0]) != nullptr)
    chname = newsplit(&par);
  else
    chname = "";
  if (egg_atoi(par) > 0) {
    s1 = newsplit(&par);
    if (egg_atoi(par) > 0) {
      start = egg_atoi(s1);
      limit = egg_atoi(par);
    } else
      limit = egg_atoi(s1);
  }
  tell_users_match(idx, s, start, limit, chname);
}

static void cmd_uptime(struct userrec *u, int idx, char *par)
{
  putlog(LOG_CMDS, "*", "#%s# uptime", dcc[idx].nick);
  tell_verbose_uptime(idx);
}

static void cmd_status(struct userrec *u, int idx, char *par)
{
  int atr = u ? u->flags : 0;

  if (!op_strcasecmp(par, "all")) {
    if (!(atr & USER_MASTER)) {
      dprintf(idx, "You do not have Bot Master privileges.\n");
      return;
    }
    putlog(LOG_CMDS, "*", "#%s# status all", dcc[idx].nick);
    tell_verbose_status(idx);
    dprintf(idx, "\n");
    tell_settings(idx);
    do_module_report(idx, 1, nullptr);
  } else {
    putlog(LOG_CMDS, "*", "#%s# status", dcc[idx].nick);
    tell_verbose_status(idx);
    do_module_report(idx, 0, nullptr);
  }
}

static void cmd_threads(struct userrec *u, int idx, char *par)
{
  int i;

  putlog(LOG_CMDS, "*", "#%s# threads", dcc[idx].nick);

  int nthreads = threadpool_size();
  dprintf(idx, "--- Async subsystem status ---\n");
  dprintf(idx, "Worker pool:    %d thread%s  (%s)\n",
          nthreads, nthreads == 1 ? "" : "s",
          threadpool_active() ? "active" : "inactive");

  if (!threadpool_active()) {
    dprintf(idx, "  (pool not active — async ops disabled)\n");
    return;
  }

  /* op_async layer */
  dprintf(idx, "op_async:       %zu item%s pending\n",
          op_async_pending(), op_async_pending() == 1 ? "" : "s");

  /* DCC dispatch shim */
  int dcc_inflight = 0, dcc_queued = 0, pump_inflight = 0, wbuf_inflight = 0;
  for (i = 0; i < dcc_total; i++) {
    dcc_inflight  += (int)atomic_load_explicit(&dcc[i].in_flight,
                                               memory_order_relaxed);
    dcc_queued    += dcc_shim_queue_depth(i);
    if (dcc[i].u.xfer) {
      pump_inflight += (int)atomic_load_explicit(&dcc[i].u.xfer->pump_in_flight,
                                                 memory_order_relaxed);
      wbuf_inflight += (int)atomic_load_explicit(&dcc[i].u.xfer->wbuf.in_flight,
                                                 memory_order_relaxed);
    }
  }
  threadpool_stats_t shim_stats;
  threadpool_get_stats(&shim_stats);
  dprintf(idx, "DCC shim:       %d in-flight, %d queued [hwm %d]",
          dcc_inflight, dcc_queued, shim_stats.hwm);
  if (pump_inflight)
    dprintf(idx, "  %d send pump%s", pump_inflight,
            pump_inflight == 1 ? "" : "s");
  if (wbuf_inflight)
    dprintf(idx, "  %d recv flush%s", wbuf_inflight,
            wbuf_inflight == 1 ? "" : "es");
  dprintf(idx, "\n");
  dprintf(idx, "Shim totals:    %" PRIu64 " dispatched  %" PRIu64 " done",
          shim_stats.submitted, shim_stats.completed);
  if (shim_stats.dropped)
    dprintf(idx, "  ** %" PRIu64 " DROPPED **", shim_stats.dropped);
  dprintf(idx, "\n");
  dprintf(idx, "Pool pending:   %d\n", threadpool_pending());

  /* Async log writer */
  if (async_log_active()) {
    uint64_t lines, bytes;
    async_log_stats(&lines, &bytes);
    dprintf(idx, "Log writer:     active  %" PRIu64 " line%s  %" PRIu64 " byte%s\n",
            lines, lines == 1 ? "" : "s",
            bytes, bytes == 1 ? "" : "s");
  } else {
    dprintf(idx, "Log writer:     inactive (sync fallback)\n");
  }

  /* Async file I/O */
  int fw_inflight = 0, fw_pending = 0;
  async_fileio_stats(&fw_inflight, &fw_pending);
  dprintf(idx, "File I/O:       %d write%s in-flight",
          fw_inflight, fw_inflight == 1 ? "" : "s");
  if (fw_pending)
    dprintf(idx, ", %d coalesced-pending", fw_pending);
  dprintf(idx, "\n");

  /* DNS cache */
  int dns_cached = async_dns_cache_size();
  dprintf(idx, "DNS cache:      %d entr%s (TTL 300s)\n",
          dns_cached, dns_cached == 1 ? "y" : "ies");
}

static void cmd_dccstat(struct userrec *u, int idx, char *par)
{
  putlog(LOG_CMDS, "*", "#%s# dccstat", dcc[idx].nick);
  tell_dcc(idx);
}

static void cmd_boot(struct userrec *u, int idx, char *par)
{
  char *who;

  if (!par[0]) {
    dprintf(idx, "Usage: boot nick[@bot]\n");
    return;
  }
  who = newsplit(&par);
  if (strchr(who, '@') != nullptr) {
    char whonick[HANDLEN + 1];

    splitcn(whonick, who, '@', HANDLEN + 1);
    if (!op_strcasecmp(who, botnetnick)) {
      cmd_boot(u, idx, whonick);
      return;
    }
    if (remote_boots > 0) {
      int i = nextbot(who);
      if (i < 0) {
        dprintf(idx, "No such bot connected.\n");
        return;
      }
      botnet_send_reject(i, dcc[idx].nick, botnetnick, whonick,
                         who, par[0] ? par : dcc[idx].nick);
      putlog(LOG_BOTS, "*", "#%s# boot %s@%s (%s)", dcc[idx].nick, whonick,
             who, par[0] ? par : dcc[idx].nick);
    } else
      dprintf(idx, "Remote boots are disabled here.\n");
    return;
  }
  bool ok = false;
  for (int i = 0; i < dcc_total; i++)
    if (!op_strcasecmp(dcc[i].nick, who) && !ok &&
        (dcc[i].type->flags & DCT_CANBOOT)) {
      struct userrec *u2 = get_user_by_handle(userlist, dcc[i].nick);
      if (u2 && (u2->flags & USER_OWNER) &&
          op_strcasecmp(dcc[idx].nick, who)) {
        dprintf(idx, "You can't boot a bot owner.\n");
        return;
      }
      if (u2 && (u2->flags & USER_MASTER) && !(u && (u->flags & USER_MASTER))) {
        dprintf(idx, "You can't boot a bot master.\n");
        return;
      }
      int files = (dcc[i].type->flags & DCT_FILES);
      if (files)
        dprintf(idx, "Booted %s from the file area.\n", dcc[i].nick);
      else
        dprintf(idx, "Booted %s from the party line.\n", dcc[i].nick);
      putlog(LOG_CMDS, "*", "#%s# boot %s %s", dcc[idx].nick, who, par);
      do_boot(i, dcc[idx].nick, par);
      ok = true;
    }
  if (!ok)
    dprintf(idx, "Who?  No such person on the party line.\n");
}

/* Make changes to user console settings */
static void do_console(struct userrec *u, int idx, char *par, int reset)
{
  char *nick, s[2], s1[512];
  int dest = 0, pls;
  struct flag_record fr = { FR_GLOBAL | FR_CHAN };
  module_entry *me;

  get_user_flagrec(u, &fr, dcc[idx].u.chat->con_chan);
  op_strlcpy(s1, par, sizeof s1);
  nick = newsplit(&par);
  /* Check if the parameter is a handle.
   * Don't remove '+' as someone couldn't have '+' in CHANMETA cause
   * he doesn't use IRCnet ++rtc.
   */
  if (nick[0] && !strchr(CHANMETA "+-*", nick[0]) && glob_master(fr)) {
    bool ok = false;
    for (int i = 0; i < dcc_total; i++) {
      if (!op_strcasecmp(nick, dcc[i].nick) &&
          (dcc[i].type == &DCC_CHAT) && (!ok)) {
        ok = true;
        dest = i;
      }
    }
    if (!ok) {
      dprintf(idx, "No such user on the party line!\n");
      return;
    }
    nick[0] = 0;
  } else
    dest = idx;
  if (!nick[0])
    nick = newsplit(&par);
  /* Check if the parameter is a channel.
   * Consider modeless channels, starting with '+'
   */
  if (nick[0] && !reset && ((nick[0] == '+' && findchan_by_dname(nick)) ||
      (nick[0] != '+' && strchr(CHANMETA "*", nick[0])))) {
    if (strcmp(nick, "*") && !findchan_by_dname(nick)) {
      dprintf(idx, "Invalid console channel: %s.\n", nick);
      return;
    }
    get_user_flagrec(u, &fr, nick);
    if (!chan_op(fr) && !(glob_op(fr) && !chan_deop(fr))) {
      dprintf(idx, "You don't have op or master access to channel %s.\n",
              nick);
      return;
    }
    op_strlcpy(dcc[dest].u.chat->con_chan, nick,
        sizeof dcc[dest].u.chat->con_chan);
    nick[0] = 0;
    if (dest != idx)
      get_user_flagrec(dcc[dest].user, &fr, dcc[dest].u.chat->con_chan);
  }
  if (!nick[0])
    nick = newsplit(&par);
  pls = 1;
  if (!reset && nick[0]) {
    if ((nick[0] != '+') && (nick[0] != '-'))
      dcc[dest].u.chat->con_flags = 0;
    for (; *nick; nick++) {
      if (*nick == '+')
        pls = 1;
      else if (*nick == '-')
        pls = 0;
      else {
        s[0] = *nick;
        s[1] = 0;
        if (pls)
          dcc[dest].u.chat->con_flags |= logmodes(s);
        else
          dcc[dest].u.chat->con_flags &= ~logmodes(s);
      }
    }
  } else if (reset) {
    dcc[dest].u.chat->con_flags = (u->flags & USER_MASTER) ? conmask : 0;
  }
  dcc[dest].u.chat->con_flags = check_conflags(&fr,
                                               dcc[dest].u.chat->con_flags);
  putlog(LOG_CMDS, "*", "#%s# %sconsole %s", dcc[idx].nick, reset ? "reset" : "", s1);
  if (dest == idx) {
    dprintf(idx, "Set your console to %s: %s (%s).\n",
            dcc[idx].u.chat->con_chan,
            masktype(dcc[idx].u.chat->con_flags),
            maskname(dcc[idx].u.chat->con_flags));
  } else {
    dprintf(idx, "Set console of %s to %s: %s (%s).\n", dcc[dest].nick,
            dcc[dest].u.chat->con_chan,
            masktype(dcc[dest].u.chat->con_flags),
            maskname(dcc[dest].u.chat->con_flags));
    dprintf(dest, "%s set your console to %s: %s (%s).\n", dcc[idx].nick,
            dcc[dest].u.chat->con_chan,
            masktype(dcc[dest].u.chat->con_flags),
            maskname(dcc[dest].u.chat->con_flags));
  }
  /* New style autosave -- drummer,07/25/1999 */
  if ((me = module_find("console", 1, 1))) {
    Function *func = me->funcs;

    ((int (*)(int)) func[CONSOLE_DOSTORE])(dest);
  }
}

static void cmd_console(struct userrec *u, int idx, char *par)
{
  if (!par[0]) {
    dprintf(idx, "Your console is %s: %s (%s).\n",
            dcc[idx].u.chat->con_chan,
            masktype(dcc[idx].u.chat->con_flags),
            maskname(dcc[idx].u.chat->con_flags));
    return;
  }
  do_console(u, idx, par, 0);
}

/* Reset console flags to config defaults */
static void cmd_resetconsole(struct userrec *u, int idx, char *par)
{
  do_console(u, idx, par, 1);
}

/* Check if a string is a valid integer and lies non-inclusive
 * between two given integers. Returns 1 if true, 0 if not.
 */
int check_int_range(char *value, int min, int max) {
  char *endptr = nullptr;
  long intvalue;

  if (value && value[0]) {
    intvalue = strtol(value, &endptr, 10);
    if ((intvalue < max) && (intvalue > min) && (*endptr == '\0')) {
      return 1;
    }
  }
  return 0;
}

static void cmd_pls_bot(struct userrec *u, int idx, char *par)
{
  char *handle, *addr, *port, *port2, *relay, *host, *p;
  struct userrec *u1;
  struct bot_addr *bi;
  bool found = false;

  if (!par[0]) {
    dprintf(idx, "Usage: +bot <handle> [address [telnet-port[/relay-port]]] "
            "[host]\n");
    return;
  }

  handle = newsplit(&par);
  addr = newsplit(&par);
  port2 = newsplit(&par);
  {
    char *saveptr = nullptr;
    port  = strtok_r(port2, "/", &saveptr);
    relay = strtok_r(nullptr,  "/", &saveptr);
    if (strtok_r(nullptr, "/", &saveptr)) {
      dprintf(idx, "You've supplied more than 2 ports, make up your mind.\n");
      return;
    }
  }

  host = newsplit(&par);

  if (strlen(handle) > HANDLEN)
    handle[HANDLEN] = 0;

  if (get_user_by_handle(userlist, handle)) {
    dprintf(idx, "Someone already exists by that name.\n");
    return;
  }

  if (strchr(BADHANDCHARS, handle[0]) != nullptr) {
    dprintf(idx, "You can't start a botnick with '%c'.\n", handle[0]);
    return;
  }

/* Check for bad characters throughout the handle */
  for (p = handle; *p; p++)
    if ((unsigned char) *p <= 32 || *p == '@') {
      dprintf(idx, "Invalid character '%c' in handle, try again\n", p[0]);
      return;
    }

  if (addr[0]) {
#ifndef IPV6
 /* Reject IPv6 addresses */
    for (int i=0; addr[i]; i++) {
      if (addr[i] == ':') {
        dprintf(idx, "Invalid IP address format (this Eggdrop "
          "was compiled without IPv6 support).\n");
        return;
      }
    }
#endif
 /* Check if user forgot address field by checking if argument is completely
  * numerical, implying a port was provided as the next argument instead.
  */
    for (int i=0; addr[i]; i++) {
      if (strchr(BADADDRCHARS, addr[i])) {
        dprintf(idx, "Bot address may not contain a '%c'. ", addr[i]);
        break;
      }
      if (!isdigit((unsigned char) addr[i])) {
        found=true;
        break;
      }
    }
    if (!found) {
      dprintf(idx, "Invalid host address.\n");
      dprintf(idx, "Usage: +bot <handle> [address [telnet-port[/relay-port]]] "
              "[host]\n");
      return;
    }
  }

#ifndef TLS
  if ((port && *port == '+') || (relay && relay[0] == '+')) {
    dprintf(idx, "Ports prefixed with '+' are not enabled "
      "(this Eggdrop was compiled without TLS support).\n");
    return;
  }
#endif
  if (port) {
    if (!check_int_range(port, 0, 65536)) {
      dprintf(idx, "Ports must be integers between 1 and 65535.\n");
      return;
    }
  }
  if (relay) {
    if (!check_int_range(relay, 0, 65536)) {
      dprintf(idx, "Ports must be integers between 1 and 65535.\n");
      return;
    }
  }

  if (strlen(addr) > 60)
    addr[60] = 0;

/* Trim IPv6 []s out if present */
  if (addr[0] == '[') {
    addr[strlen(addr)-1] = 0;
    memmove(addr, addr + 1, strlen(addr));
  }
  userlist = adduser(userlist, handle, "none", "-", USER_BOT);
  u1 = get_user_by_handle(userlist, handle);
  bi = user_malloc(sizeof(struct bot_addr));
#ifdef TLS
  bi->ssl = 0;
#endif
  bi->address = op_strdup(addr);

  if (!port) {
    bi->telnet_port = 3333;
    bi->relay_port = 3333;
  } else {
#ifdef TLS
    if (*port == '+')
      bi->ssl |= TLS_BOT;
#endif
    bi->telnet_port = egg_atoi(port);
    if (!relay) {
      bi->relay_port = bi->telnet_port;
#ifdef TLS
      bi->ssl *= TLS_BOT + TLS_RELAY;
#endif
    } else  {
#ifdef TLS
      if (relay[0] == '+')
        bi->ssl |= TLS_RELAY;
#endif
      bi->relay_port = egg_atoi(relay);
    }
  }

  set_user(&USERENTRY_BOTADDR, u1, bi);
  if (addr[0]) {
    putlog(LOG_CMDS, "*", "#%s# +bot %s %s%s%s%s%s %s%s", dcc[idx].nick, handle,
           addr, port ? " " : "", port ? port : "", relay ? " " : "",
           relay ? relay : "", host[0] ? " " : "", host);
#ifdef TLS
    dprintf(idx, "Added bot '%s' with address [%s]:%s%d/%s%d and %s%s%s.\n",
            handle, addr, (bi->ssl & TLS_BOT) ? "+" : "", bi->telnet_port,
            (bi->ssl & TLS_RELAY) ? "+" : "", bi->relay_port, host[0] ?
            "hostmask '" : "no hostmask", host[0] ? host : "",
            host[0] ? "'" : "");
#else
    dprintf(idx, "Added bot '%s' with address [%s]:%d/%d and %s%s%s.\n", handle,
            addr, bi->telnet_port, bi->relay_port, host[0] ? "hostmask '" :
            "no hostmask", host[0] ? host : "", host[0] ? "'" : "");
#endif
  } else {
    putlog(LOG_CMDS, "*", "#%s# +bot %s %s%s", dcc[idx].nick, handle,
           host[0] ? " " : "", host);
    dprintf(idx, "Added bot '%s' with no address and %s%s%s.\n", handle,
            host[0] ? "hostmask '" : "no hostmask", host[0] ? host : "",
            host[0] ? "'" : "");
  }
  if (host[0]) {
    addhost_by_handle(handle, host);
  } else if (!add_bot_hostmask(idx, handle)) {
    dprintf(idx, "You'll want to add a hostmask if this bot will ever be on "
            "any channels that I'm on.\n");
  }
}

static void cmd_chhandle(struct userrec *u, int idx, char *par)
{
  char newhand[HANDLEN + 1];
  int atr = u ? u->flags : 0, atr2;
  struct userrec *u2;
  char *hand = newsplit(&par);

  op_strlcpy(newhand, newsplit(&par), sizeof newhand);

  if (!hand[0] || !newhand[0]) {
    dprintf(idx, "Usage: chhandle <oldhandle> <newhandle>\n");
    return;
  }
  for (int i = 0; i < (int) strlen(newhand); i++)
    if (((unsigned char) newhand[i] <= 32) || (newhand[i] == '@'))
      newhand[i] = '?';
  if (strchr(BADHANDCHARS, newhand[0]) != nullptr)
    dprintf(idx, "Bizarre quantum forces prevent nicknames from starting with "
            "'%c'.\n", newhand[0]);
  else if (get_user_by_handle(userlist, newhand) &&
           op_strcasecmp(hand, newhand))
    dprintf(idx, "Somebody is already using %s.\n", newhand);
  else {
    u2 = get_user_by_handle(userlist, hand);
    atr2 = u2 ? u2->flags : 0;
    if ((atr & USER_BOTMAST) && !(atr & USER_MASTER) && !(atr2 & USER_BOT))
      dprintf(idx, "You can't change handles for non-bots.\n");
    else if (!op_strcasecmp(hand, EGG_BG_HANDLE))
      dprintf(idx, "You can't change the handle of a temporary user.\n");
    else if ((bot_flags(u2) & BOT_SHARE) && !(atr & USER_OWNER))
      dprintf(idx, "You can't change share bot's nick.\n");
    else if ((atr2 & USER_OWNER) && !(atr & USER_OWNER) &&
             op_strcasecmp(dcc[idx].nick, hand))
      dprintf(idx, "You can't change a bot owner's handle.\n");
    else if (isowner(hand) && op_strcasecmp(dcc[idx].nick, hand))
      dprintf(idx, "You can't change a permanent bot owner's handle.\n");
    else if (!op_strcasecmp(newhand, botnetnick) && (!(atr2 & USER_BOT) ||
             nextbot(hand) != -1))
      dprintf(idx, "Hey! That's MY name!\n");
    else if (change_handle(u2, newhand)) {
      putlog(LOG_CMDS, "*", "#%s# chhandle %s %s", dcc[idx].nick, hand, newhand);
      dprintf(idx, "Changed.\n");
    } else
      dprintf(idx, "Failed.\n");
  }
}

static void cmd_handle(struct userrec *u, int idx, char *par)
{
  char newhandle[HANDLEN + 1];

  op_strlcpy(newhandle, newsplit(&par), sizeof newhandle);

  if (!newhandle[0]) {
    dprintf(idx, "Usage: handle <new-handle>\n");
    return;
  }
  for (int i = 0; i < strlen(newhandle); i++)
    if (((unsigned char) newhandle[i] <= 32) || (newhandle[i] == '@'))
      newhandle[i] = '?';
  if (strchr(BADHANDCHARS, newhandle[0]) != nullptr)
    dprintf(idx,
            "Bizarre quantum forces prevent handle from starting with '%c'.\n",
            newhandle[0]);
  else if (!op_strcasecmp(dcc[idx].nick, EGG_BG_HANDLE))
    dprintf(idx, "You can't change the handle of this temporary user.\n");
  else if (get_user_by_handle(userlist, newhandle) &&
           op_strcasecmp(dcc[idx].nick, newhandle))
    dprintf(idx, "Somebody is already using %s.\n", newhandle);
  else if (!op_strcasecmp(newhandle, botnetnick))
    dprintf(idx, "Hey!  That's MY name!\n");
  else {
    char oldhandle[HANDLEN + 1];
    op_strlcpy(oldhandle, dcc[idx].nick, sizeof oldhandle);
    if (change_handle(u, newhandle)) {
      putlog(LOG_CMDS, "*", "#%s# handle %s", oldhandle, newhandle);
      dprintf(idx, "Okay, changed.\n");
    } else
      dprintf(idx, "Failed.\n");
  }
}

static void cmd_chpass(struct userrec *u, int idx, char *par)
{
  char *handle, *new, *s;
  int atr = u ? u->flags : 0;

  if (!par[0])
    dprintf(idx, "Usage: chpass <handle> [password]\n");
  else {
    handle = newsplit(&par);
    u = get_user_by_handle(userlist, handle);
    if (!u)
      dprintf(idx, "No such user.\n");
    else if ((atr & USER_BOTMAST) && !(atr & USER_MASTER) &&
             !(u->flags & USER_BOT))
      dprintf(idx, "You can't change passwords for non-bots.\n");
    else if ((bot_flags(u) & BOT_SHARE) && !(atr & USER_OWNER))
      dprintf(idx, "You can't change a share bot's password.\n");
    else if ((u->flags & USER_OWNER) && !(atr & USER_OWNER) &&
             op_strcasecmp(handle, dcc[idx].nick))
      dprintf(idx, "You can't change a bot owner's password.\n");
    else if (isowner(handle) && op_strcasecmp(dcc[idx].nick, handle))
      dprintf(idx, "You can't change a permanent bot owner's password.\n");
    else if (!par[0]) {
      putlog(LOG_CMDS, "*", "#%s# chpass %s [nothing]", dcc[idx].nick, handle);
      set_user(&USERENTRY_PASS, u, nullptr);
      dprintf(idx, "Removed password.\n");
    } else {
      new = newsplit(&par);
      if ((s = check_validpass(u, new))) {
        dprintf(idx, "%s\n", s);
        return;
      }
      putlog(LOG_CMDS, "*", "#%s# chpass %s [something]", dcc[idx].nick,
             handle);
      dprintf(idx, "Changed password.\n");
    }
  }
}

#ifdef TLS
static void cmd_fprint(struct userrec *u, int idx, char *par)
{
  char *new;

  if (!par[0]) {
    dprintf(idx, "Usage: fprint <newfingerprint|+>\n");
    return;
  }
  new = newsplit(&par);
  if (!strcmp(new, "+")) {
    if (!dcc[idx].ssl) {
      dprintf(idx, "You aren't connected with SSL. "
              "Please set your fingerprint manually.\n");
      return;
    } else if (!(new = ssl_getfp(dcc[idx].sock))) {
      dprintf(idx, "Can't get your current fingerprint. "
              "Set up your client to send a certificate!\n");
      return;
    }
  }
  if (set_user(&USERENTRY_FPRINT, u, new)) {
    putlog(LOG_CMDS, "*", "#%s# fprint...", dcc[idx].nick);
    dprintf(idx, "Changed fingerprint to '%s'.\n", new);
  } else
    dprintf(idx, "Invalid fingerprint. Must be a hexadecimal string.\n");
}

static void cmd_chfinger(struct userrec *u, int idx, char *par)
{
  char *handle, *new;
  int atr = u ? u->flags : 0;

  if (!par[0])
    dprintf(idx, "Usage: chfinger <handle> [fingerprint]\n");
  else {
    handle = newsplit(&par);
    u = get_user_by_handle(userlist, handle);
    if (!u)
      dprintf(idx, "No such user.\n");
    else if ((atr & USER_BOTMAST) && !(atr & USER_MASTER) &&
             !(u->flags & USER_BOT))
      dprintf(idx, "You can't change fingerprints for non-bots.\n");
    else if ((bot_flags(u) & BOT_SHARE) && !(atr & USER_OWNER))
      dprintf(idx, "You can't change a share bot's fingerprint.\n");
    else if ((u->flags & USER_OWNER) && !(atr & USER_OWNER) &&
             op_strcasecmp(handle, dcc[idx].nick))
      dprintf(idx, "You can't change a bot owner's fingerprint.\n");
    else if (isowner(handle) && op_strcasecmp(dcc[idx].nick, handle))
      dprintf(idx, "You can't change a permanent bot owner's fingerprint.\n");
    else if (!par[0]) {
      putlog(LOG_CMDS, "*", "#%s# chfinger %s [nothing]", dcc[idx].nick, handle);
      set_user(&USERENTRY_FPRINT, u, nullptr);
      dprintf(idx, "Removed fingerprint.\n");
    } else {
      new = newsplit(&par);
      if (set_user(&USERENTRY_FPRINT, u, new)) {
        putlog(LOG_CMDS, "*", "#%s# chfinger %s %s", dcc[idx].nick,
               handle, new);
        dprintf(idx, "Changed fingerprint.\n");
      } else
        dprintf(idx, "Invalid fingerprint. Must be a hexadecimal string.\n");
    }
  }
}
#endif

static void cmd_chaddr(struct userrec *u, int idx, char *par)
{
#ifdef TLS
  int use_ssl = 0;
#endif
  bool found = false;
  int telnet_port = 3333, relay_port = 3333;
  char *handle, *addr, *port, *port2, *relay;
  struct bot_addr *bi;
  struct userrec *u1;

  handle = newsplit(&par);
  if (!par[0]) {
    dprintf(idx, "Usage: chaddr <botname> <address> "
            "[telnet-port[/relay-port]]>\n");
    return;
  }
  addr = newsplit(&par);
  port2 = newsplit(&par);
  {
    char *saveptr = nullptr;
    port  = strtok_r(port2, "/", &saveptr);
    relay = strtok_r(nullptr,  "/", &saveptr);
    if (strtok_r(nullptr, "/", &saveptr)) {
      dprintf(idx, "You've supplied more than 2 ports, make up your mind.\n");
      return;
    }
  }

  if (addr[0]) {
#ifndef IPV6
    for (int i = 0; addr[i]; i++) {
      if (addr[i] == ':') {
        dprintf(idx, "Invalid IP address format (this Eggdrop "
          "was compiled without IPv6 support).\n");
        return;
      }
    }
#endif
 /* Check if user forgot address field by checking if argument is completely
  * numerical, implying a port was provided as the next argument instead.
  */
    for (int i = 0; addr[i]; i++) {
      if (strchr(BADADDRCHARS, addr[i])) {
        dprintf(idx, "Bot address may not contain a '%c'. ", addr[i]);
        break;
      }
      if (!isdigit((unsigned char) addr[i])) {
        found=true;
        break;
      }
    }
    if (!found) {
      dprintf(idx, "Invalid host address.\n");
      dprintf(idx, "Usage: chaddr <botname> <address> "
              "[telnet-port[/relay-port]]>\n");
      return;
    }
  }

#ifndef TLS
  if ((port && *port == '+') || (relay && relay[0] == '+')) {
    dprintf(idx, "Ports prefixed with '+' are not enabled "
      "(this Eggdrop was compiled without TLS support).\n");
    return;
  }
#endif
  if (port && port[0]) {
    if (!check_int_range(port, 0, 65536)) {
      dprintf(idx, "Ports must be integers between 1 and 65535.\n");
      return;
    }
  }
  if (relay) {
    if (!check_int_range(relay, 0, 65536)) {
      dprintf(idx, "Ports must be integers between 1 and 65535.\n");
      return;
    }
  }

  if (strlen(addr) > UHOSTMAX)
    addr[UHOSTMAX] = 0;
  u1 = get_user_by_handle(userlist, handle);
  if (!u1 || !(u1->flags & USER_BOT)) {
    dprintf(idx, "This command is only useful for tandem bots.\n");
    return;
  }
  if ((bot_flags(u1) & BOT_SHARE) && (!u || !(u->flags & USER_OWNER))) {
    dprintf(idx, "You can't change a share bot's address.\n");
    return;
  }

  bi = (struct bot_addr *) get_user(&USERENTRY_BOTADDR, u1);
  if (bi) {
    telnet_port = bi->telnet_port;
    relay_port = bi->relay_port;
#ifdef TLS
    use_ssl = bi->ssl;
#endif
  }

/* Trim IPv6 []s out if present */
  if (addr[0] == '[') {
    addr[strlen(addr)-1] = 0;
    memmove(addr, addr + 1, strlen(addr));
  }
  bi = user_malloc(sizeof(struct bot_addr));
  bi->address = op_strdup(addr);

  if (!port) {
    bi->telnet_port = telnet_port;
    bi->relay_port = relay_port;
#ifdef TLS
    bi->ssl = use_ssl;
  } else {
    bi->ssl = 0;
    if (*port == '+')
      bi->ssl |= TLS_BOT;
    bi->telnet_port = egg_atoi(port);
    if (!relay) {
      bi->relay_port = bi->telnet_port;
      bi->ssl *= TLS_BOT + TLS_RELAY;
    } else {
      if (*relay == '+') {
        bi->ssl |= TLS_RELAY;
      }
#else
  } else {
    bi->telnet_port = egg_atoi(port);
    if (!relay) {
      bi->relay_port = bi->telnet_port;
    } else {
#endif
     bi->relay_port = egg_atoi(relay);
    }
  }
  set_user(&USERENTRY_BOTADDR, u1, bi);
  putlog(LOG_CMDS, "*", "#%s# chaddr %s %s%s%s%s%s", dcc[idx].nick, handle,
         addr, port ? " " : "", port ? port : "", relay ? "/" : "", relay ? relay : "");
  dprintf(idx, "Changed bot's address.\n");
}

static void cmd_comment(struct userrec *u, int idx, char *par)
{
  char *handle;
  struct userrec *u1;

  handle = newsplit(&par);
  if (!par[0]) {
    dprintf(idx, "Usage: comment <handle> <newcomment>\n");
    return;
  }
  u1 = get_user_by_handle(userlist, handle);
  if (!u1) {
    dprintf(idx, "No such user!\n");
    return;
  }
  if ((u1->flags & USER_OWNER) && !(u && (u->flags & USER_OWNER)) &&
      op_strcasecmp(handle, dcc[idx].nick)) {
    dprintf(idx, "You can't change comment on a bot owner.\n");
    return;
  }
  putlog(LOG_CMDS, "*", "#%s# comment %s %s", dcc[idx].nick, handle, par);
  if (!op_strcasecmp(par, "none")) {
    dprintf(idx, "Okay, comment blanked.\n");
    set_user(&USERENTRY_COMMENT, u1, nullptr);
    return;
  }
  dprintf(idx, "Changed comment.\n");
  set_user(&USERENTRY_COMMENT, u1, par);
}

static void cmd_restart(struct userrec *u, int idx, char *par)
{
  putlog(LOG_CMDS, "*", "#%s# restart", dcc[idx].nick);
  if (!backgrd) {
    dprintf(idx, "You cannot .restart a bot when running -n/-t (due to Tcl).\n");
    return;
  }
  dprintf(idx, "Restarting.\n");
  if (make_userfile) {
    putlog(LOG_MISC, "*", "Uh, guess you don't need to create a new userfile.");
    make_userfile = 0;
  }
  write_userfile(-1);
  putlog(LOG_MISC, "*", "Restarting ...");
  wipe_timers(interp, &utimer);
  wipe_timers(interp, &timer);
  do_restart = idx;
}

static void cmd_rehash(struct userrec *u, int idx, char *par)
{
  putlog(LOG_CMDS, "*", "#%s# rehash", dcc[idx].nick);
  dprintf(idx, "Rehashing.\n");
  if (make_userfile) {
    putlog(LOG_MISC, "*", "Uh, guess you don't need to create a new userfile.");
    make_userfile = 0;
  }
  write_userfile(-1);
  putlog(LOG_MISC, "*", "Rehashing ...");
  do_restart = -2;
}

static void cmd_reload(struct userrec *u, int idx, char *par)
{
  putlog(LOG_CMDS, "*", "#%s# reload", dcc[idx].nick);
  dprintf(idx, "Reloading user file...\n");
  reload();
}

[[noreturn]] void cmd_die(struct userrec *u, int idx, char *par)
{
  putlog(LOG_CMDS, "*", "#%s# die %s", dcc[idx].nick, par);
  op_strbuf_t s1 = {}, s2 = {};
  if (par[0]) {
    op_strbuf_appendf(&s1, "BOT SHUTDOWN (%s: %s)", dcc[idx].nick, par);
    op_strbuf_appendf(&s2, "DIE BY %s!%s (%s)", dcc[idx].nick, dcc[idx].host, par);
    op_strlcpy(quit_msg, par, 1024);
  } else {
    op_strbuf_appendf(&s1, "BOT SHUTDOWN (Authorized by %s)", dcc[idx].nick);
    op_strbuf_appendf(&s2, "DIE BY %s!%s (request)", dcc[idx].nick, dcc[idx].host);
    op_strlcpy(quit_msg, dcc[idx].nick, 1024);
  }
  kill_bot(op_strbuf_str(&s1), op_strbuf_str(&s2));
  /* kill_bot() is [[noreturn]], but free anyway for correctness */
  op_strbuf_free(&s1);
  op_strbuf_free(&s2);
}

static void cmd_debug(struct userrec *u, int idx, char *par)
{
  if (!op_strcasecmp(par, "help")) {
    putlog(LOG_CMDS, "*", "#%s# debug help", dcc[idx].nick);
    debug_help(idx);
  } else {
    putlog(LOG_CMDS, "*", "#%s# debug", dcc[idx].nick);
    dprintf(idx, "Memory debugging has been removed.\n");
  }
}

static void cmd_simul(struct userrec *u, int idx, char *par)
{
  char *nick = newsplit(&par);

  if (!par[0]) {
    dprintf(idx, "Usage: simul <hand> <text>\n");
    return;
  }
  if (isowner(nick)) {
    dprintf(idx, "Unable to '.simul' permanent owners.\n");
    return;
  }
  bool ok = false;
  for (int i = 0; i < dcc_total; i++)
    if (!op_strcasecmp(nick, dcc[i].nick) && !ok &&
        (dcc[i].type->flags & DCT_SIMUL)) {
      putlog(LOG_CMDS, "*", "#%s# simul %s %s", dcc[idx].nick, nick, par);
      if (dcc[i].type && dcc[i].type->activity) {
        dcc[i].type->activity(i, par, strlen(par));
        ok = true;
      }
    }
  if (!ok)
    dprintf(idx, "No such user on the party line.\n");
}

static void cmd_link(struct userrec *u, int idx, char *par)
{
  if (!par[0]) {
    dprintf(idx, "Usage: link [some-bot] <new-bot>\n");
    return;
  }
  putlog(LOG_CMDS, "*", "#%s# link %s", dcc[idx].nick, par);
  char *s = newsplit(&par);
  if (!par[0] || !op_strcasecmp(par, botnetnick))
    botlink(dcc[idx].nick, idx, s);
  else {
    int i = nextbot(s);
    if (i < 0) {
      dprintf(idx, "No such bot online.\n");
      return;
    }
    op_strbuf_t x = {};
    op_strbuf_init(&x);
    op_strbuf_appendf(&x, "%ld:%s@%s", dcc[idx].sock, dcc[idx].nick, botnetnick);
    botnet_send_link(i, op_strbuf_str(&x), s, par);
    op_strbuf_free(&x);
  }
}

static void cmd_unlink(struct userrec *u, int idx, char *par)
{
  if (!par[0]) {
    dprintf(idx, "Usage: unlink <bot> [reason]\n");
    return;
  }
  putlog(LOG_CMDS, "*", "#%s# unlink %s", dcc[idx].nick, par);
  char *bot = newsplit(&par);
  int i = nextbot(bot);
  if (i < 0) {
    botunlink(idx, bot, par, dcc[idx].nick);
    return;
  }
  /* If we're directly connected to that bot, just do it
   * (is nike gunna sue?)
   */
  if (!op_strcasecmp(dcc[i].nick, bot))
    botunlink(idx, bot, par, dcc[i].nick);
  else {
    op_strbuf_t x = {};
    op_strbuf_init(&x);
    op_strbuf_appendf(&x, "%ld:%s@%s", dcc[idx].sock, dcc[idx].nick, botnetnick);
    botnet_send_unlink(i, op_strbuf_str(&x), lastbot(bot), bot, par);
    op_strbuf_free(&x);
  }
}

static void cmd_relay(struct userrec *u, int idx, char *par)
{
  if (!par[0]) {
    dprintf(idx, "Usage: relay <bot>\n");
    return;
  }
  putlog(LOG_CMDS, "*", "#%s# relay %s", dcc[idx].nick, par);
  tandem_relay(idx, par, 0);
}

static void cmd_save(struct userrec *u, int idx, char *par)
{
  putlog(LOG_CMDS, "*", "#%s# save", dcc[idx].nick);
  dprintf(idx, "Saving user file...\n");
  write_userfile(-1);
}

static void cmd_backup(struct userrec *u, int idx, char *par)
{
  putlog(LOG_CMDS, "*", "#%s# backup", dcc[idx].nick);
  dprintf(idx, "Backing up the channel & user files...\n");
  call_hook(HOOK_BACKUP);
}

static void cmd_trace(struct userrec *u, int idx, char *par)
{
  if (!par[0]) {
    dprintf(idx, "Usage: trace <botname>\n");
    return;
  }
  if (!op_strcasecmp(par, botnetnick)) {
    dprintf(idx, "That's me!  Hiya! :)\n");
    return;
  }
  int i = nextbot(par);
  if (i < 0) {
    dprintf(idx, "Unreachable bot.\n");
    return;
  }
  putlog(LOG_CMDS, "*", "#%s# trace %s", dcc[idx].nick, par);
  op_strbuf_t x = {}, y = {};
  op_strbuf_appendf(&x, "%ld:%s@%s", dcc[idx].sock, dcc[idx].nick, botnetnick);
  op_strbuf_appendf(&y, ":%" PRId64, (int64_t) now);
  botnet_send_trace(i, op_strbuf_str(&x), par, op_strbuf_str(&y));
  op_strbuf_free(&x);
  op_strbuf_free(&y);
}

static void cmd_binds(struct userrec *u, int idx, char *par)
{
  putlog(LOG_CMDS, "*", "#%s# binds %s", dcc[idx].nick, par);
  tell_binds(idx, par);
}

static void cmd_banner(struct userrec *u, int idx, char *par)
{
  if (!par[0]) {
    dprintf(idx, "Usage: banner <message>\n");
    return;
  }
  for (int i = 0; i < dcc_total; i++)
    if (dcc[i].type->flags & DCT_MASTER)
      dprintf(i, "\007### Botwide: [%s] %s\n", dcc[idx].nick, par);
}

/* After messing with someone's user flags, make sure the dcc-chat flags
 * are set correctly.
 */
int check_dcc_attrs(struct userrec *u, int oatr)
{
  struct flag_record fr = { FR_GLOBAL | FR_CHAN };

  if (!u)
    return 0;
  /* Make sure default owners are +n */
  if (isowner(u->handle)) {
    u->flags = sanity_check(u->flags | USER_OWNER);
  }
  for (int i = 0; i < dcc_total; i++) {
    if ((dcc[i].type->flags & DCT_MASTER) &&
        (!op_strcasecmp(u->handle, dcc[i].nick))) {
      int stat = dcc[i].status;
      if ((dcc[i].type == &DCC_CHAT) &&
          ((u->flags & (USER_OP | USER_MASTER | USER_OWNER | USER_BOTMAST)) !=
          (oatr & (USER_OP | USER_MASTER | USER_OWNER | USER_BOTMAST)))) {
        botnet_send_join_idx(i, -1);
      }
      if ((oatr & USER_MASTER) && !(u->flags & USER_MASTER)) {
        dprintf(i, "*** POOF! ***\n");
        dprintf(i, "You are no longer a master on this bot.\n");
      }
      if (!(oatr & USER_MASTER) && (u->flags & USER_MASTER)) {
        dcc[i].u.chat->con_flags |= conmask;
        dprintf(i, "*** POOF! ***\n");
        dprintf(i, "You are now a master on this bot.\n");
      }
      if (!(oatr & USER_BOTMAST) && (u->flags & USER_BOTMAST)) {
        dprintf(i, "### POOF! ###\n");
        dprintf(i, "You are now a botnet master on this bot.\n");
      }
      if ((oatr & USER_BOTMAST) && !(u->flags & USER_BOTMAST)) {
        dprintf(i, "### POOF! ###\n");
        dprintf(i, "You are no longer a botnet master on this bot.\n");
      }
      if (!(oatr & USER_OWNER) && (u->flags & USER_OWNER)) {
        dprintf(i, "@@@ POOF! @@@\n");
        dprintf(i, "You are now an OWNER of this bot.\n");
      }
      if ((oatr & USER_OWNER) && !(u->flags & USER_OWNER)) {
        dprintf(i, "@@@ POOF! @@@\n");
        dprintf(i, "You are no longer an owner of this bot.\n");
      }
      get_user_flagrec(u, &fr, dcc[i].u.chat->con_chan);
      dcc[i].u.chat->con_flags = check_conflags(&fr,
                                                dcc[i].u.chat->con_flags);
      if ((stat & STAT_PARTY) && (u->flags & USER_OP))
        stat &= ~STAT_PARTY;
      if (!(stat & STAT_PARTY) && !(u->flags & USER_OP) &&
          !(u->flags & USER_MASTER))
        stat |= STAT_PARTY;
      if ((stat & STAT_CHAT) && !(u->flags & USER_PARTY) &&
          !(u->flags & USER_MASTER) && (!(u->flags & USER_OP) || require_p))
        stat &= ~STAT_CHAT;
      if ((dcc[i].type->flags & DCT_FILES) && !(stat & STAT_CHAT) &&
          ((u->flags & USER_MASTER) || (u->flags & USER_PARTY) ||
          ((u->flags & USER_OP) && !require_p)))
        stat |= STAT_CHAT;
      dcc[i].status = stat;
      /* Check if they no longer have access to wherever they are.
       *
       * NOTE: DON'T kick someone off the party line just cuz they lost +p
       *       (pinvite script removes +p after 5 mins automatically)
       */
      if ((dcc[i].type->flags & DCT_FILES) && !(u->flags & USER_XFER) &&
          !(u->flags & USER_MASTER)) {
        dprintf(i, "-+- POOF! -+-\n");
        dprintf(i, "You no longer have file area access.\n\n");
        putlog(LOG_MISC, "*", "DCC user [%s]%s removed from file system",
               dcc[i].nick, dcc[i].host);
        if (dcc[i].status & STAT_CHAT) {
          struct chat_info *ci;

          ci = dcc[i].u.file->chat;
          op_free(dcc[i].u.file);
          dcc[i].u.chat = ci;
          dcc[i].status &= (~STAT_CHAT);
          dcc[i].type = &DCC_CHAT;
          if (dcc[i].u.chat->channel >= 0) {
            chanout_but(-1, dcc[i].u.chat->channel, DCC_RETURN, dcc[i].nick);
            if (dcc[i].u.chat->channel < GLOBAL_CHANS)
              botnet_send_join_idx(i, -1);
          }
        } else {
          killsock(dcc[i].sock);
          lostdcc(i);
        }
      }
    }

    if (dcc[i].type == &DCC_BOT && !op_strcasecmp(u->handle, dcc[i].nick)) {
      if ((dcc[i].status & STAT_LEAF) && !(bot_flags(u) & BOT_LEAF))
        dcc[i].status &= ~(STAT_LEAF | STAT_WARNED);
      if (!(dcc[i].status & STAT_LEAF) && (bot_flags(u) & BOT_LEAF))
        dcc[i].status |= STAT_LEAF;
    }
  }

  return u->flags;
}

int check_dcc_chanattrs(struct userrec *u, char *chname, int chflags,
                        int ochatr)
{
  int found = 0;
  struct flag_record fr = { FR_CHAN };
  struct chanset_t *chan;

  if (!u)
    return 0;
  for (int i = 0; i < dcc_total; i++) {
    if ((dcc[i].type->flags & DCT_MASTER) &&
        !op_strcasecmp(u->handle, dcc[i].nick)) {
      if ((dcc[i].type == &DCC_CHAT) &&
          ((chflags & (USER_OP | USER_MASTER | USER_OWNER)) !=
          (ochatr & (USER_OP | USER_MASTER | USER_OWNER))))
        botnet_send_join_idx(i, -1);
      if ((ochatr & USER_MASTER) && !(chflags & USER_MASTER)) {
        dprintf(i, "*** POOF! ***\n");
        dprintf(i, "You are no longer a master on %s.\n", chname);
      }
      if (!(ochatr & USER_MASTER) && (chflags & USER_MASTER)) {
        dcc[i].u.chat->con_flags |= conmask;
        dprintf(i, "*** POOF! ***\n");
        dprintf(i, "You are now a master on %s.\n", chname);
      }
      if (!(ochatr & USER_OWNER) && (chflags & USER_OWNER)) {
        dprintf(i, "@@@ POOF! @@@\n");
        dprintf(i, "You are now an OWNER of %s.\n", chname);
      }
      if ((ochatr & USER_OWNER) && !(chflags & USER_OWNER)) {
        dprintf(i, "@@@ POOF! @@@\n");
        dprintf(i, "You are no longer an owner of %s.\n", chname);
      }
      if (((ochatr & (USER_OP | USER_MASTER | USER_OWNER)) &&
          (!(chflags & (USER_OP | USER_MASTER | USER_OWNER)))) ||
          ((chflags & (USER_OP | USER_MASTER | USER_OWNER)) &&
          (!(ochatr & (USER_OP | USER_MASTER | USER_OWNER))))) {

        for (chan = chanset; chan && !found; chan = chan->next) {
          get_user_flagrec(u, &fr, chan->dname);
          if (fr.chan & (USER_OP | USER_MASTER | USER_OWNER))
            found = 1;
        }
        if (!chan)
          chan = chanset;
        if (chan)
          op_strlcpy(dcc[i].u.chat->con_chan, chan->dname, sizeof(dcc[i].u.chat->con_chan));
        else
          op_strlcpy(dcc[i].u.chat->con_chan, "*", sizeof(dcc[i].u.chat->con_chan));
      }
      fr.match = (FR_CHAN | FR_GLOBAL);
      get_user_flagrec(u, &fr, dcc[i].u.chat->con_chan);
      dcc[i].u.chat->con_flags = check_conflags(&fr,
                                                dcc[i].u.chat->con_flags);
    }
  }
  return chflags;
}

/* helper function to inform the user of conflicts with botattr */
static void bot_attr_inform(const int idx, const int msgids)
{
  if (msgids & BOT_SANE_ALTOWNSHUB)
    dprintf(idx, "INFO: adding +a removes the existing +h flag.\n");
  if (msgids & BOT_SANE_HUBOWNSALT)
    dprintf(idx, "INFO: adding +h removes the existing +a flag.\n");
  if (msgids & BOT_SANE_OWNSALTHUB)
    dprintf(idx, "INFO: adding +ah is not possible, please choose only one.\n");
  if (msgids & BOT_SANE_SHPOWNSAGGR)
    dprintf(idx, "INFO: adding any of the +(bcejnud) flags removes the existing"
        " +s flag.\n");
  if (msgids & BOT_SANE_AGGROWNSSHP)
    dprintf(idx, "INFO: adding +s removes any existing +(bcejnud) flags.\n");
  if (msgids & BOT_SANE_OWNSSHPAGGR)
    dprintf(idx, "INFO: adding +s with any of the +(bcejnud) flags is not"
        " possible, please choose only one.\n");
  if (msgids & BOT_SANE_SHPOWNSPASS)
    dprintf(idx, "INFO: adding any of the +(bcejnud) flags removes the existing"
         " +p flag.\n");
  if (msgids & BOT_SANE_PASSOWNSSHP)
    dprintf(idx, "INFO: adding +p removes any existing +(bcejnud) flags.\n");
  if (msgids & BOT_SANE_OWNSSHPPASS)
    dprintf(idx, "INFO: adding +p with any of the +(bcejnud) flags is not"
        " possible, please choose only one.\n");
  if (msgids & BOT_SANE_SHAREOWNSREJ)
    dprintf(idx, "INFO: adding any of the +(bcejnudps) flags removes the"
        " existing +r flag.\n");
  if (msgids & BOT_SANE_REJOWNSSHARE)
    dprintf(idx, "INFO: adding +r removes any existing +(bcejnudps) flags.\n");
  if (msgids & BOT_SANE_OWNSSHAREREJ)
    dprintf(idx, "INFO: adding +r with any of the +(bcejnudps) flags is not"
        " possible, please choose only one.\n");
  if (msgids & BOT_SANE_HUBOWNSREJ)
    dprintf(idx, "INFO: adding +h removes the existing +r flag.\n");
  if (msgids & BOT_SANE_REJOWNSHUB)
    dprintf(idx, "INFO: adding +r removes the existing +h flag.\n");
  if (msgids & BOT_SANE_OWNSHUBREJ)
    dprintf(idx, "INFO: adding +hr is not possible, please choose only one of"
        " them.\n");
  if (msgids & BOT_SANE_ALTOWNSREJ)
    dprintf(idx, "INFO: adding +a removes the existing +r flag.\n");
  if (msgids & BOT_SANE_REJOWNSALT)
    dprintf(idx, "INFO: adding +r removes the existing +a flag.\n");
  if (msgids & BOT_SANE_OWNSALTREJ)
    dprintf(idx, "INFO: adding +ar is not possible, please choose only one of"
        " them.\n");
  if (msgids & BOT_SANE_AGGROWNSPASS)
    dprintf(idx, "INFO: adding +s removes the existing +p flag.\n");
  if (msgids & BOT_SANE_PASSOWNSAGGR)
    dprintf(idx, "INFO: adding +p removes the existing +s flag.\n");
  if (msgids & BOT_SANE_OWNSAGGRPASS)
    dprintf(idx, "INFO: adding +ps is not possible, please choose only one of"
        " them.\n");
  if (msgids & BOT_SANE_NOSHAREOWNSGLOB)
    dprintf(idx, "INFO: removing the -(bcejnudps) flags will also remove the"
        " current +g flag.\n");
  if (msgids & BOT_SANE_OWNSGLOB)
    dprintf(idx, "INFO: adding +g is only possible with one of the"
        " +(bcejnudps) flags.\n");
}

/* helper function to inform the user of conflicts with chattr */
static void uc_attr_inform(const int idx, const int msgids)
{
  if (msgids & UC_SANE_DEOPOWNSOP)
    dprintf(idx, "INFO: adding +d removes the existing +o flag.\n");
  if (msgids & UC_SANE_OPOWNSDEOP)
    dprintf(idx, "INFO: adding +o removes the existing +d flag.\n");
  if (msgids & UC_SANE_OWNSDEOPOP)
    dprintf(idx, "INFO: adding +do is not possible, please choose only one of"
        " them.\n");
  if (msgids & UC_SANE_DEHALFOPOWNSHALFOP)
    dprintf(idx, "INFO: adding +r removes the existing +l flag.\n");
  if (msgids & UC_SANE_HALFOPOWNSDEHALFOP)
    dprintf(idx, "INFO: adding +l removes the existing +r flag.\n");
  if (msgids & UC_SANE_OWNSDEHALFOPHALFOP)
    dprintf(idx, "INFO: adding +rl is not possible, please choose only one of"
        " them.\n");
  if (msgids & UC_SANE_DEOPOWNSAUTOOP)
    dprintf(idx, "INFO: adding +d removes the existing +a flag.\n");
  if (msgids & UC_SANE_AUTOOPOWNSDEOP)
    dprintf(idx, "INFO: adding +a removes the existing +d flag.\n");
  if (msgids & UC_SANE_OWNSDEOPAUTOOP)
    dprintf(idx, "INFO: adding +da is not possible, please choose only one of"
        " them.\n");
  if (msgids & UC_SANE_DEHALFOPOWNSAHALFOP)
    dprintf(idx, "INFO: adding +r removes the existing +y flag.\n");
  if (msgids & UC_SANE_AHALFOPOWNSDEHALFOP)
    dprintf(idx, "INFO: adding +y removes the existing +r flag.\n");
  if (msgids & UC_SANE_OWNSDEHALFOPAHALFOP)
    dprintf(idx, "INFO: adding +ry is not possible, please choose only one of"
        " them.\n");
  if (msgids & UC_SANE_QUIETOWNSVOICE)
    dprintf(idx, "INFO: adding +q removes the existing +v flag.\n");
  if (msgids & UC_SANE_VOICEOWNSQUIET)
    dprintf(idx, "INFO: adding +v removes the existing +q flag.\n");
  if (msgids & UC_SANE_OWNSQUIETVOICE)
    dprintf(idx, "INFO: adding +qv is not possible, please choose only one of"
        " them.\n");
  if (msgids & UC_SANE_QUIETOWNSGVOICE)
    dprintf(idx, "INFO: adding +q removes the existing +g flag.\n");
  if (msgids & UC_SANE_GVOICEOWNSQUIET)
    dprintf(idx, "INFO: adding +g removes the existing +q flag.\n");
  if (msgids & UC_SANE_OWNSQUIETGVOICE)
    dprintf(idx, "INFO: adding +qg is not possible, please choose only one of"
        " them.\n");
  if (msgids & UC_SANE_OWNERADDSMASTER)
    dprintf(idx, "INFO: adding +n implies adding the +m flag.\n");
  if (msgids & UC_SANE_MASTERADDSOP)
    dprintf(idx, "INFO: adding +m implies adding the +o flag.\n");
  if (msgids & UC_SANE_MASTERADDSBOTMOPJAN)
    dprintf(idx, "INFO: adding +m implies adding the +toj flags.\n");
  if (msgids & UC_SANE_BOTMASTADDSPARTY)
    dprintf(idx, "INFO: adding +t implies adding the +p flag.\n");
  if (msgids & UC_SANE_JANADDSXFER)
    dprintf(idx, "INFO: adding +j implies adding the +x flag.\n");
  if (msgids & UC_SANE_OPADDSHALFOP)
    dprintf(idx, "INFO: adding +o implies adding the +l flag.\n");
  if (msgids & UC_SANE_NOBOTOWNSAGGR)
    dprintf(idx, "INFO: the +s flag can only be added to bots.\n");
  if (msgids & UC_SANE_BOTOWNSPARTY)
    dprintf(idx, "INFO: a bot can't have the +p flag.\n");
  if (msgids & UC_SANE_BOTOWNSMASTER)
    dprintf(idx, "INFO: a bot can't have the +m flag.\n");
  if (msgids & UC_SANE_BOTOWNSCOMMON)
    dprintf(idx, "INFO: a bot can't have the +c flag.\n");
  if (msgids & UC_SANE_BOTOWNSOWNER)
    dprintf(idx, "INFO: a bot can't have the +n flag.\n");
  if (msgids & UC_SANE_AUTOOPADDSOP)
    dprintf(idx, "INFO: adding +a also adds +o for your convenience, if unwanted one can revert with -o.\n");
  if (msgids & UC_SANE_AUTOHALFOPADDSHALFOP)
    dprintf(idx, "INFO: adding +y also adds +l for your convenience, if unwanted one can revert with -l.\n");
  if (msgids & UC_SANE_GVOICEADDSVOICE)
    dprintf(idx, "INFO: adding +g also adds +v for your convenience, if unwanted one can revert with -v.\n");
}

/* Add a host or account to a handle.
 * Type:
    0 = hostmask
    1 = account
 */
static int add_to_handle(struct userrec *u, int idx, char *handle, char *host, int type)
{
  struct flag_record fr2 = { FR_GLOBAL | FR_CHAN | FR_ANYWH },
                      fr = { FR_GLOBAL | FR_CHAN | FR_ANYWH };
  struct userrec *u2;

  if (host) {
    u2 = get_user_by_handle(userlist, handle);
  } else {
    u2 = u;
  }
  if (!u2 || !u) {
    dprintf(idx, "No such user.\n");
    return 1;
  }

  get_user_flagrec(u, &fr, nullptr);
  if (op_strcasecmp(handle, dcc[idx].nick)) {
    get_user_flagrec(u2, &fr2, nullptr);
    if (!glob_master(fr) && !glob_bot(fr2) && !chan_master(fr)) {
      dprintf(idx, "You can't add %s to non-bots.\n",
            type ? "accounts" : "hostmasks");
      return 1;
    }
    if (!(glob_owner(fr) || glob_botmast(fr)) && glob_bot(fr2) && (bot_flags(u2) & BOT_SHARE)) {
      dprintf(idx, "You can't add %s to share bots.\n",
            type ? "accounts" : "hostmasks");
      return 1;
    }
    if ((glob_owner(fr2) || glob_master(fr2)) && !glob_owner(fr)) {
      dprintf(idx, "You can't add %s to a bot owner/master.\n",
            type ? "accounts" : "hostmasks");
      return 1;
    }
    if ((chan_owner(fr2) || chan_master(fr2)) && !glob_master(fr) &&
        !glob_owner(fr) && !chan_owner(fr)) {
      dprintf(idx, "You can't add %s to a channel owner/master.\n",
            type ? "accounts" : "hostmasks");
      return 1;
    }
    if (!glob_botmast(fr) && !glob_master(fr) && !chan_master(fr)) {
      dprintf(idx, "Permission denied.\n");
      return 1;
    }
  }
  if ( !type && !glob_botmast(fr) && !chan_master(fr) && get_user_by_host(host)) {
    dprintf(idx, "You cannot add a host matching another user!\n");
    return 1;
  }
  if (type) {
    // host-variable contains account
    u2 = get_user_by_account(host);
    if (u2) {
      dprintf(idx, "That account already exists for user %s\n", u2->handle);
      return 1;
    }
    addaccount_by_handle(handle, host);
  } else {
    // host
    {
      op_vec_t *_hv = (op_vec_t *)get_user(&USERENTRY_HOSTS, u);

      if (_hv)
        for (size_t _i = 0; _i < _hv->size; _i++) {
          if (!op_strcasecmp((char *)op_vec_get(_hv, _i), host)) {
            dprintf(idx, "That %s is already there.\n",
                  type ? "account" : "hostmask");
            return 1;
          }
        }
    }
    addhost_by_handle(handle, host);
  }
  return 0;
}

static void remove_from_handle(struct userrec *u, int idx, char *handle, char *host, int type)
{
  module_entry *me;
  struct userrec *u2;
  struct flag_record fr2 = { FR_GLOBAL | FR_CHAN | FR_ANYWH },
                      fr = { FR_GLOBAL | FR_CHAN | FR_ANYWH };

  if (host) {
    u2 = get_user_by_handle(userlist, handle);
  } else {
    u2 = u;
  }
  if (!u2 || !u) {
    dprintf(idx, "No such user.\n");
    return;
  }

  get_user_flagrec(u, &fr, nullptr);
  get_user_flagrec(u2, &fr2, nullptr);
  /* check to see if user is +d or +k and don't let them remove hosts */
  if (((glob_deop(fr) || glob_kick(fr)) && !glob_master(fr)) ||
      ((chan_deop(fr) || chan_kick(fr)) && !chan_master(fr))) {
    dprintf(idx, "You can't remove %s while having the +d or +k "
            "flag.\n", type ? "accounts" : "hostmasks");
    return;
  }

  if (op_strcasecmp(handle, dcc[idx].nick)) {
    if (!glob_master(fr) && !glob_bot(fr2) && !chan_master(fr)) {
      dprintf(idx, "You can't remove %s from non-bots.\n",
            type ? "accounts" : "hostmasks");
      return;
    }
    if (glob_bot(fr2) && (bot_flags(u2) & BOT_SHARE) && !glob_owner(fr)) {
      dprintf(idx, "You can't remove %s from a share bot.\n",
            type ? "accounts" : "hostmasks");
      return;
    }
    if ((glob_owner(fr2) || glob_master(fr2)) && !glob_owner(fr)) {
      dprintf(idx, "You can't remove %s from a bot owner/master.\n",
            type ? "accounts" : "hostmasks");
      return;
    }
    if ((chan_owner(fr2) || chan_master(fr2)) && !glob_master(fr) &&
        !glob_owner(fr) && !chan_owner(fr)) {
      dprintf(idx, "You can't remove %s from a channel owner/master.\n",
            type ? "accounts" : "hostmasks");
      return;
    }
    if (!glob_botmast(fr) && !glob_master(fr) && !chan_master(fr)) {
      dprintf(idx, "Permission denied.\n");
      return;
    }
  }
  if (type) {
    if (delaccount_by_handle(handle, host)) {
      putlog(LOG_CMDS, "*", "#%s# -account %s %s", dcc[idx].nick, handle, host);
      dprintf(idx, "Removed '%s' from %s.\n", host, handle);
    } else {
      dprintf(idx, "Failed.\n");
    }
  } else {
    if (delhost_by_handle(handle, host)) {
      putlog(LOG_CMDS, "*", "#%s# -host %s %s", dcc[idx].nick, handle, host);
      dprintf(idx, "Removed '%s' from %s.\n", host, handle);
      if ((me = module_find("irc", 0, 0))) {
        Function *func = me->funcs;

        ((void (*)(char *, int, char *)) func[IRC_CHECK_THIS_USER])(handle, 2, host);
      }
    } else {
      dprintf(idx, "Failed.\n");
    }
  }
}

/* Add a services account name to a handle */
static void cmd_pls_account(struct userrec *u, int idx, char *par)
{
  char *handle, *acct;
  int ret;

  if (!par[0]) {
    dprintf(idx, "Usage: +account [handle] <account>\n");
    return;
  }

  handle = newsplit(&par);
  if (par[0]) {
    acct = newsplit(&par);
  } else {
    acct = handle;
    handle = dcc[idx].nick;
  }
  ret = add_to_handle(u, idx, handle, acct, 1);
  if (!ret) {
    putlog(LOG_CMDS, "*", "#%s# +account %s %s", dcc[idx].nick, handle, acct);
    dprintf(idx, "Added account %s to %s\n", acct, handle);
  }
  return;
}


/* Remove a services account name from a handle */
static void cmd_mns_account(struct userrec *u, int idx, char *par)
{
  char *handle, *acct;

  if (!par[0]) {
    dprintf(idx, "Usage: -account [handle] <account>\n");
    return;
  }
  handle = newsplit(&par);
  if (par[0]) {
    acct = newsplit(&par);
  } else {
    acct = handle;
    handle = dcc[idx].nick;
  }
  remove_from_handle(u, idx, handle, acct, 1);
  return;
}


static void cmd_chattr(struct userrec *u, int idx, char *par)
{
  char *hand, *arg = nullptr, *tmpchg = nullptr, *chg = nullptr, work[1024];
  struct chanset_t *chan = nullptr;
  struct userrec *u2;
  struct flag_record pls = {},
                     mns = {},
                     user = {};
  module_entry *me;
  int fl = -1, of = 0, ocf = 0, msgidsu = 0, msgidsc = 0;

  if (!par[0]) {
    dprintf(idx, "Usage: chattr <handle> [changes] [channel]\n");
    return;
  }
  hand = newsplit(&par);
  u2 = get_user_by_handle(userlist, hand);
  if (!u2) {
    dprintf(idx, "No such user!\n");
    return;
  }

  /* Parse args */
  if (par[0]) {
    arg = newsplit(&par);
    if (par[0]) {
      /* .chattr <handle> <changes> <channel> */
      chg = arg;
      arg = newsplit(&par);
      chan = findchan_by_dname(arg);
    } else {
      chan = findchan_by_dname(arg);
      /* Consider modeless channels, starting with '+' */
      if (!(arg[0] == '+' && chan) &&
          !(arg[0] != '+' && strchr(CHANMETA, arg[0]))) {
        /* .chattr <handle> <changes> */
        chg = arg;
        chan = nullptr; /* uh, !strchr (CHANMETA, channel[0]) && channel found?? */
        arg = nullptr;
      }
      /* .chattr <handle> <channel>: nothing to do... */
    }
  }
  /* arg:  pointer to channel name, nullptr if none specified
   * chan: pointer to channel structure, nullptr if none found or none specified
   * chg:  pointer to changes, nullptr if none specified
   */
  Assert(!(!arg && chan));
  if (arg && !chan) {
    dprintf(idx, "No channel record for %s.\n", arg);
    return;
  }
  if (chg) {
    if (!arg && strpbrk(chg, "&|")) {
      /* .chattr <handle> *[&|]*: use console channel if found... */
      if (!strcmp((arg = dcc[idx].u.chat->con_chan), "*"))
        arg = nullptr;
      else
        chan = findchan_by_dname(arg);
      if (arg && !chan) {
        dprintf(idx, "Invalid console channel %s.\n", arg);
        return;
      }
    } else if (arg && !strpbrk(chg, "&|")) {
      op_strbuf_t sb = {};
      op_strbuf_init(&sb);
      op_strbuf_appendf(&sb, "|%s", chg);
      tmpchg = op_strbuf_steal(&sb);
      chg = tmpchg;
    }
  }
  par = arg;
  user.match = FR_GLOBAL;
  if (chan)
    user.match |= FR_CHAN;
  get_user_flagrec(u, &user, chan ? chan->dname : 0);
  if (!chan && !glob_botmast(user)) {
    dprintf(idx, "You do not have Bot Master privileges.\n");
    if (tmpchg)
      op_free(tmpchg);
    return;
  }
  if (chan && !glob_master(user) && !chan_master(user)) {
    dprintf(idx, "You do not have channel master privileges for channel %s.\n",
            par);
    if (tmpchg)
      op_free(tmpchg);
    return;
  }
  user.match &= fl;
  if (chg) {
    pls.match = user.match;
    break_down_flags(chg, &pls, &mns);
    /* No-one can change these flags on-the-fly */
    pls.global &=~(USER_BOT);
    mns.global &=~(USER_BOT);

    if (chan) {
      pls.chan &= ~(BOT_AGGRESSIVE);
      mns.chan &= ~(BOT_AGGRESSIVE);
    }
    if (!glob_owner(user)) {
      pls.global &=~(USER_OWNER | USER_MASTER | USER_BOTMAST | USER_UNSHARED);
      mns.global &=~(USER_OWNER | USER_MASTER | USER_BOTMAST | USER_UNSHARED);

      if (chan) {
        pls.chan &= ~USER_OWNER;
        mns.chan &= ~USER_OWNER;
      }
      if (!glob_master(user)) {
        pls.global &=USER_PARTY | USER_XFER;
        mns.global &=USER_PARTY | USER_XFER;

        if (!glob_botmast(user)) {
          pls.global = 0;
          mns.global = 0;
        }
      }
    }
    if (chan && !chan_owner(user) && !glob_owner(user)) {
      pls.chan &= ~USER_MASTER;
      mns.chan &= ~USER_MASTER;
      if (!chan_master(user) && !glob_master(user)) {
        pls.chan = 0;
        mns.chan = 0;
      }
    }
    get_user_flagrec(u2, &user, par);
    if (user.match & FR_GLOBAL) {
      of = user.global;
      msgidsu = user_sanity_check(&(user.global), pls.global, mns.global);

      user.udef_global = (user.udef_global | pls.udef_global)
                         & ~mns.udef_global;
    }
    if (chan) {
      ocf = user.chan;
      msgidsc = chan_sanity_check(&(user.chan), pls.chan, mns.chan, user.global);

      user.udef_chan = (user.udef_chan | pls.udef_chan) & ~mns.udef_chan;
    }
    set_user_flagrec(u2, &user, par);
  }
  if (chan)
    putlog(LOG_CMDS, "*", "#%s# (%s) chattr %s %s",
           dcc[idx].nick, chan->dname, hand, chg ? chg : "");
  else
    putlog(LOG_CMDS, "*", "#%s# chattr %s %s", dcc[idx].nick, hand,
           chg ? chg : "");
  /* Get current flags and display them */
  if (user.match & FR_GLOBAL) {
    user.match = FR_GLOBAL;
    if (chg)
      check_dcc_attrs(u2, of);
    get_user_flagrec(u2, &user, nullptr);
    build_flags(work, &user, nullptr);
    /* Display any remarks */
    if (msgidsu)
      uc_attr_inform(idx, msgidsu);
    if (work[0] != '-')
      dprintf(idx, "Global flags for %s are now +%s.\n", hand, work);
    else
      dprintf(idx, "No global flags for %s.\n", hand);
  }
  if (chan) {
    user.match = FR_CHAN;
    get_user_flagrec(u2, &user, par);
    user.chan &= ~BOT_AGGRESSIVE;
    if (chg)
      check_dcc_chanattrs(u2, chan->dname, user.chan, ocf);
    build_flags(work, &user, nullptr);
    /* Display any remarks */
    if (msgidsc)
      uc_attr_inform(idx, msgidsc);
    if (work[0] != '-')
      dprintf(idx, "Channel flags for %s on %s are now +%s.\n", hand,
              chan->dname, work);
    else
      dprintf(idx, "No flags for %s on %s.\n", hand, chan->dname);
  }
  if (chg && (me = module_find("irc", 0, 0))) {
    Function *func = me->funcs;
    ((void (*)(char *, int, char *)) func[IRC_CHECK_THIS_USER])(hand, 0, nullptr);
  }
  if (tmpchg)
    op_free(tmpchg);
}

static void cmd_botattr(struct userrec *u, int idx, char *par)
{
  char *hand, *chg = nullptr, *arg = nullptr, *tmpchg = nullptr, work[1024];
  int msgids = 0;
  struct chanset_t *chan = nullptr;
  struct userrec *u2;
  struct flag_record  pls = {},
                      mns = {},
                      user = {};
  int idx2;

  if (!par[0]) {
    dprintf(idx, "Usage: botattr <handle> [changes] [channel]\n");
    return;
  }
  hand = newsplit(&par);
  u2 = get_user_by_handle(userlist, hand);
  if (!u2 || !(u2->flags & USER_BOT)) {
    dprintf(idx, "No such bot!\n");
    return;
  }
  for (idx2 = 0; idx2 < dcc_total; idx2++)
    if (dcc[idx2].type != &DCC_RELAY && dcc[idx2].type != &DCC_FORK_BOT &&
        !op_strcasecmp(dcc[idx2].nick, hand))
      break;
  if (idx2 != dcc_total) {
    dprintf(idx,
            "You may not change the attributes of a directly linked bot.\n");
    return;
  }
  /* Parse args */
  if (par[0]) {
    arg = newsplit(&par);
    if (par[0]) {
      /* .botattr <handle> <changes> <channel> */
      chg = arg;
      arg = newsplit(&par);
      chan = findchan_by_dname(arg);
    } else {
      chan = findchan_by_dname(arg);
      /* Consider modeless channels, starting with '+' */
      if (!(arg[0] == '+' && chan) &&
          !(arg[0] != '+' && strchr(CHANMETA, arg[0]))) {
        /* .botattr <handle> <changes> */
        chg = arg;
        chan = nullptr; /* uh, !strchr (CHANMETA, channel[0]) && channel found?? */
        arg = nullptr;
      }
      /* .botattr <handle> <channel>: nothing to do... */
    }
  }
  /* arg:  pointer to channel name, nullptr if none specified
   * chan: pointer to channel structure, nullptr if none found or none specified
   * chg:  pointer to changes, nullptr if none specified
   */
  Assert(!(!arg && chan));
  if (arg && !chan) {
    dprintf(idx, "No channel record for %s.\n", arg);
    return;
  }
  if (chg) {
    if (!arg && strpbrk(chg, "&|")) {
      /* botattr <handle> *[&|]*: use console channel if found... */
      if (!strcmp((arg = dcc[idx].u.chat->con_chan), "*"))
        arg = nullptr;
      else
        chan = findchan_by_dname(arg);
      if (arg && !chan) {
        dprintf(idx, "Invalid console channel %s.\n", arg);
        return;
      }
    } else if (arg && !strpbrk(chg, "&|")) {
      op_strbuf_t sb = {};
      op_strbuf_init(&sb);
      op_strbuf_appendf(&sb, "|%s", chg);
      tmpchg = op_strbuf_steal(&sb);
      chg = tmpchg;
    }
  }
  par = arg;

  user.match = FR_GLOBAL;
  get_user_flagrec(u, &user, chan ? chan->dname : 0);
  if (!glob_botmast(user)) {
    dprintf(idx, "You do not have Bot Master privileges.\n");
    if (tmpchg)
      op_free(tmpchg);
    return;
  }
  if (chg) {
    user.match = FR_BOT | (chan ? FR_CHAN : 0);
    pls.match = user.match;
    break_down_flags(chg, &pls, &mns);
    /* No-one can change these flags on-the-fly */
    if (chan && glob_owner(user)) {
      pls.chan &= BOT_AGGRESSIVE;
      mns.chan &= BOT_AGGRESSIVE;
    } else {
      pls.chan = 0;
      mns.chan = 0;
    }
    if (!glob_owner(user) && ((pls.bot | mns.bot) & (BOT_SHARE | BOT_GLOBAL))) {
      pls.bot &= ~(BOT_SHARE | BOT_GLOBAL);
      mns.bot &= ~(BOT_SHARE | BOT_GLOBAL);
      dprintf(idx, "You do not have Global Owner privileges, so you cant change share attributes\n");
    }
    user.match = FR_BOT | (chan ? FR_CHAN : 0);
    get_user_flagrec(u2, &user, par);
    msgids = bot_sanity_check(&(user.bot), pls.bot, mns.bot);
    if (chan)
      user.chan = (user.chan | pls.chan) & ~mns.chan;
    set_user_flagrec(u2, &user, par);
  }
  if (chan)
    putlog(LOG_CMDS, "*", "#%s# (%s) botattr %s %s",
           dcc[idx].nick, chan->dname, hand, chg ? chg : "");
  else
    putlog(LOG_CMDS, "*", "#%s# botattr %s %s", dcc[idx].nick, hand,
           chg ? chg : "");
  /* Display any remarks */
  if (msgids)
    bot_attr_inform(idx, msgids);
  /* get current flags and display them */
  if (!chan || pls.bot || mns.bot) {
    user.match = FR_BOT;
    get_user_flagrec(u2, &user, nullptr);
    build_flags(work, &user, nullptr);
    if (work[0] != '-')
      dprintf(idx, "Bot flags for %s are now +%s.\n", hand, work);
    else
      dprintf(idx, "There are no bot flags for %s.\n", hand);
  }
  if (chan) {
    user.match = FR_CHAN;
    get_user_flagrec(u2, &user, par);
    user.chan &= BOT_AGGRESSIVE;
    user.udef_chan = 0; /* udef chan flags are user only */
    build_flags(work, &user, nullptr);
    if (work[0] != '-')
      dprintf(idx, "Bot flags for %s on %s are now +%s.\n", hand,
              chan->dname, work);
    else
      dprintf(idx, "There are no bot flags for %s on %s.\n", hand, chan->dname);
  }
  if (tmpchg)
    op_free(tmpchg);
}

static void cmd_chat(struct userrec *u, int idx, char *par)
{
  char *arg;
  int localchan = 0;
  int newchan = 0;
  int oldchan;
  module_entry *me;

  arg = newsplit(&par);
  if (!op_strcasecmp(arg, "off")) {
    /* Turn chat off */
    if (dcc[idx].u.chat->channel < 0) {
      dprintf(idx, "You weren't in chat anyway!\n");
      return;
    } else {
      dprintf(idx, "Leaving chat mode...\n");
      check_tcl_chpt(botnetnick, dcc[idx].nick, dcc[idx].sock,
                     dcc[idx].u.chat->channel);
      chanout_but(-1, dcc[idx].u.chat->channel,
                  "*** %s left the party line.\n", dcc[idx].nick);
      if (dcc[idx].u.chat->channel < GLOBAL_CHANS)
        botnet_send_part_idx(idx, "");
    }
    dcc[idx].u.chat->channel = -1;
  } else {
    if (arg[0] == '*') {
      if (((arg[1] < '0') || (arg[1] > '9'))) {
        if (!arg[1])
          newchan = 0;
        else {
          op_strbuf_t assoc_cmd = {};
          op_strbuf_init(&assoc_cmd);
          op_strbuf_appendf(&assoc_cmd, "assoc {%s}", arg);
          if (!egg_eval(op_strbuf_str(&assoc_cmd)) && !tcl_resultempty())
            newchan = tcl_resultint();
          else
            newchan = -1;
          op_strbuf_free(&assoc_cmd);
        }
        if (newchan < 0) {
          dprintf(idx, "No channel exists by that name.\n");
          return;
        }
      } else
        newchan = GLOBAL_CHANS + egg_atoi(arg + 1);
      if (newchan < GLOBAL_CHANS || newchan > 199999) {
        dprintf(idx, "Channel number out of range: local channels must be "
                "*0-*99999.\n");
        return;
      }
    } else {
      if (((arg[0] < '0') || (arg[0] > '9')) && (arg[0])) {
        if (!op_strcasecmp(arg, "on"))
          newchan = 0;
        else {
          op_strbuf_t assoc_cmd = {};
          op_strbuf_init(&assoc_cmd);
          op_strbuf_appendf(&assoc_cmd, "assoc {%s}", arg);
          if (!egg_eval(op_strbuf_str(&assoc_cmd)) && !tcl_resultempty()) {
            newchan = tcl_resultint();
            if ((newchan >= GLOBAL_CHANS) && (newchan <= 199999)) {
              localchan = 1;
            }
          }
          else
            newchan = -1;
          op_strbuf_free(&assoc_cmd);
        }
        if (newchan < 0) {
          dprintf(idx, "No channel exists by that name.\n");
          return;
        }
      } else
        newchan = egg_atoi(arg);
      if ((newchan < 0) || ((newchan >= GLOBAL_CHANS) && (!localchan)) ||
          (newchan >= 199999)) {
        dprintf(idx, "Channel number out of range: must be between 0 and %d."
                "\n", GLOBAL_CHANS);
        return;
      }
    }
    /* If coming back from being off the party line, make sure they're
     * not away.
     */
    if ((dcc[idx].u.chat->channel < 0) && (dcc[idx].u.chat->away != nullptr))
      not_away(idx);
    if (dcc[idx].u.chat->channel == newchan) {
      if (!newchan) {
        dprintf(idx, "You're already on the party line!\n");
        return;
      } else {
        dprintf(idx, "You're already on channel %s%d!\n",
                (newchan < GLOBAL_CHANS) ? "" : "*", newchan % GLOBAL_CHANS);
        return;
      }
    } else {
      oldchan = dcc[idx].u.chat->channel;
      if (oldchan >= 0)
        check_tcl_chpt(botnetnick, dcc[idx].nick, dcc[idx].sock, oldchan);
      if (!oldchan)
        chanout_but(-1, 0, "*** %s left the party line.\n", dcc[idx].nick);
      else if (oldchan > 0)
        chanout_but(-1, oldchan, "*** %s left the channel.\n", dcc[idx].nick);
      dcc[idx].u.chat->channel = newchan;
      if (!newchan) {
        dprintf(idx, "Entering the party line...\n");
        chanout_but(-1, 0, "*** %s joined the party line.\n", dcc[idx].nick);
      } else {
        dprintf(idx, "Joining channel '%s'...\n", arg);
        chanout_but(-1, newchan, "*** %s joined the channel.\n", dcc[idx].nick);
      }
      check_tcl_chjn(botnetnick, dcc[idx].nick, newchan, geticon(idx),
                     dcc[idx].sock, dcc[idx].host);
      if (newchan < GLOBAL_CHANS)
        botnet_send_join_idx(idx, oldchan);
      else if (oldchan < GLOBAL_CHANS)
        botnet_send_part_idx(idx, "");
    }
  }
  /* New style autosave here too -- rtc, 09/28/1999 */
  if ((me = module_find("console", 1, 1))) {
    Function *func = me->funcs;

    ((int (*)(int)) func[CONSOLE_DOSTORE])(idx);
  }
}

static void cmd_echo(struct userrec *u, int idx, char *par)
{
  module_entry *me;

  if (!par[0]) {
    dprintf(idx, "Echo is currently %s.\n", dcc[idx].status & STAT_ECHO ?
            "on" : "off");
    return;
  }
  if (!op_strcasecmp(par, "on")) {
    dprintf(idx, "Echo turned on.\n");
    dcc[idx].status |= STAT_ECHO;
  } else if (!op_strcasecmp(par, "off")) {
    dprintf(idx, "Echo turned off.\n");
    dcc[idx].status &= ~STAT_ECHO;
  } else {
    dprintf(idx, "Usage: echo <on/off>\n");
    return;
  }
  /* New style autosave here too -- rtc, 09/28/1999 */
  if ((me = module_find("console", 1, 1))) {
    Function *func = me->funcs;

    ((int (*)(int)) func[CONSOLE_DOSTORE])(idx);
  }
}

int stripmodes(char *s)
{
  int res = 0;

  for (; *s; s++)
    switch (tolower((unsigned) *s)) {
    case 'c':
      res |= STRIP_COLOR;
      break;
    case 'b':
      res |= STRIP_BOLD;
      break;
    case 'r':
      res |= STRIP_REVERSE;
      break;
    case 'u':
      res |= STRIP_UNDERLINE;
      break;
    case 'a':
      res |= STRIP_ANSI;
      break;
    case 'g':
      res |= STRIP_BELLS;
      break;
    case 'o':
      res |= STRIP_ORDINARY;
      break;
    case 'i':
      res |= STRIP_ITALICS;
      break;
    case '*':
      res |= STRIP_ALL;
      break;
    }
  return res;
}

const char *stripmasktype(int x)
{
  static char s[20];
  char *p = s;

  if (x & STRIP_COLOR)
    *p++ = 'c';
  if (x & STRIP_BOLD)
    *p++ = 'b';
  if (x & STRIP_REVERSE)
    *p++ = 'r';
  if (x & STRIP_UNDERLINE)
    *p++ = 'u';
  if (x & STRIP_ANSI)
    *p++ = 'a';
  if (x & STRIP_BELLS)
    *p++ = 'g';
  if (x & STRIP_ORDINARY)
    *p++ = 'o';
  if (x & STRIP_ITALICS)
    *p++ = 'i';
  if (p == s)
    *p++ = '-';
  *p = 0;
  return s;
}

static const char *stripmaskname(int x)
{
  static op_strbuf_t sb = {};

  op_strbuf_clear(&sb);
  if (x & STRIP_COLOR)     op_strbuf_append_cstr(&sb, "color, ");
  if (x & STRIP_BOLD)      op_strbuf_append_cstr(&sb, "bold, ");
  if (x & STRIP_REVERSE)   op_strbuf_append_cstr(&sb, "reverse, ");
  if (x & STRIP_UNDERLINE) op_strbuf_append_cstr(&sb, "underline, ");
  if (x & STRIP_ANSI)      op_strbuf_append_cstr(&sb, "ansi, ");
  if (x & STRIP_BELLS)     op_strbuf_append_cstr(&sb, "bells, ");
  if (x & STRIP_ORDINARY)  op_strbuf_append_cstr(&sb, "ordinary, ");
  if (x & STRIP_ITALICS)   op_strbuf_append_cstr(&sb, "italics, ");
  if (!op_strbuf_empty(&sb))
    op_strbuf_truncate(&sb, op_strbuf_len(&sb) - 2);  /* strip trailing ", " */
  else
    op_strbuf_append_cstr(&sb, "none");
  return op_strbuf_str(&sb);
}

static void cmd_strip(struct userrec *u, int idx, char *par)
{
  char *nick, *changes, *c, s[2];
  int dest = 0, i, pls, md, ok = 0;
  module_entry *me;

  if (!par[0]) {
    dprintf(idx, "Your current strip settings are: %s (%s).\n",
            stripmasktype(dcc[idx].u.chat->strip_flags),
            stripmaskname(dcc[idx].u.chat->strip_flags));
    return;
  }
  nick = newsplit(&par);
  if ((nick[0] != '+') && (nick[0] != '-') && u && (u->flags & USER_MASTER)) {
    for (i = 0; i < dcc_total; i++)
      if (!op_strcasecmp(nick, dcc[i].nick) && dcc[i].type == &DCC_CHAT && !ok) {
        ok = 1;
        dest = i;
      }
    if (!ok) {
      dprintf(idx, "No such user on the party line!\n");
      return;
    }
    changes = par;
  } else {
    changes = nick;
    nick = "";
    dest = idx;
  }
  c = changes;
  if ((c[0] != '+') && (c[0] != '-'))
    dcc[dest].u.chat->strip_flags = 0;
  s[1] = 0;
  for (pls = 1; *c; c++) {
    switch (*c) {
    case '+':
      pls = 1;
      break;
    case '-':
      pls = 0;
      break;
    default:
      s[0] = *c;
      md = stripmodes(s);
      if (pls == 1)
        dcc[dest].u.chat->strip_flags |= md;
      else
        dcc[dest].u.chat->strip_flags &= ~md;
    }
  }
  if (nick[0])
    putlog(LOG_CMDS, "*", "#%s# strip %s %s", dcc[idx].nick, nick, changes);
  else
    putlog(LOG_CMDS, "*", "#%s# strip %s", dcc[idx].nick, changes);
  if (dest == idx) {
    dprintf(idx, "Your strip settings are: %s (%s).\n",
            stripmasktype(dcc[idx].u.chat->strip_flags),
            stripmaskname(dcc[idx].u.chat->strip_flags));
  } else {
    dprintf(idx, "Strip setting for %s: %s (%s).\n", dcc[dest].nick,
            stripmasktype(dcc[dest].u.chat->strip_flags),
            stripmaskname(dcc[dest].u.chat->strip_flags));
    dprintf(dest, "%s set your strip settings to: %s (%s).\n", dcc[idx].nick,
            stripmasktype(dcc[dest].u.chat->strip_flags),
            stripmaskname(dcc[dest].u.chat->strip_flags));
  }
  /* Set highlight flag here so user is able to control stripping of
   * bold also as intended -- dw 27/12/1999
   */
  if (dcc[dest].u.chat->strip_flags & STRIP_BOLD && u->flags & USER_HIGHLITE) {
    u->flags &= ~USER_HIGHLITE;
  } else if (!(dcc[dest].u.chat->strip_flags & STRIP_BOLD) &&
           !(u->flags & USER_HIGHLITE)) {
    u->flags |= USER_HIGHLITE;
  }
  /* New style autosave here too -- rtc, 09/28/1999 */
  if ((me = module_find("console", 1, 1))) {
    Function *func = me->funcs;

    ((int (*)(int)) func[CONSOLE_DOSTORE])(dest);
  }
}

static void cmd_su(struct userrec *u, int idx, char *par)
{
  int atr = u ? u->flags : 0;
  struct flag_record fr = { FR_ANYWH | FR_CHAN | FR_GLOBAL };

  u = get_user_by_handle(userlist, par);

  if (!par[0])
    dprintf(idx, "Usage: su <user>\n");
  else if (!u)
    dprintf(idx, "No such user.\n");
  else if (u->flags & USER_BOT)
    dprintf(idx, "You can't su to a bot... then again, why would you wanna?\n");
  else if (dcc[idx].u.chat->su_nick)
    dprintf(idx, "You cannot currently double .su; try .su'ing directly.\n");
  else {
    get_user_flagrec(u, &fr, nullptr);
    if ((!glob_party(fr) && (require_p || !(glob_op(fr) || chan_op(fr)))) &&
        !(atr & USER_BOTMAST))
      dprintf(idx, "No party line access permitted for %s.\n", par);
    else {
      correct_handle(par);
      putlog(LOG_CMDS, "*", "#%s# su %s", dcc[idx].nick, par);
      if (!(atr & USER_OWNER) || ((u->flags & USER_OWNER) && (isowner(par)) &&
          !(isowner(dcc[idx].nick)))) {
        /* This check is only important for non-owners */
        if (u_pass_match(u, "-")) {
          dprintf(idx, "No password set for user. You may not .su to them.\n");
          return;
        }
        if (dcc[idx].u.chat->channel < GLOBAL_CHANS)
          botnet_send_part_idx(idx, "");
        chanout_but(-1, dcc[idx].u.chat->channel,
                    "*** %s left the party line.\n", dcc[idx].nick);
        /* Store the old nick in the away section, for weenies who can't get
         * their password right ;)
         */
        if (dcc[idx].u.chat->away != nullptr)
          op_free(dcc[idx].u.chat->away);
        size_t _len1 = strlen(dcc[idx].nick) + 1;
        dcc[idx].u.chat->away = get_data_ptr(_len1);
        op_strlcpy(dcc[idx].u.chat->away, dcc[idx].nick, _len1);
        size_t _len2 = strlen(dcc[idx].nick) + 1;
        dcc[idx].u.chat->su_nick = get_data_ptr(_len2);
        op_strlcpy(dcc[idx].u.chat->su_nick, dcc[idx].nick, _len2);
        dcc[idx].user = u;
        op_strlcpy(dcc[idx].nick, par, sizeof(dcc[idx].nick));
        /* Display password prompt and turn off echo (send IAC WILL ECHO). */
        if (dcc[idx].status & STAT_TELNET) {
          op_strbuf_t buf = {};
          op_strbuf_init(&buf);
          op_strbuf_appendf(&buf, "Enter password for %s" TLN_IAC_C TLN_WILL_C
                           TLN_ECHO_C "\r\n", par);
          tputs(dcc[idx].sock, op_strbuf_str(&buf), op_strbuf_len(&buf));
          op_strbuf_free(&buf);
        } else
          dprintf(idx, "Enter password for %s\n", par);
        dcc[idx].type = &DCC_CHAT_PASS;
      } else if (atr & USER_OWNER) {
        if (dcc[idx].u.chat->channel < GLOBAL_CHANS)
          botnet_send_part_idx(idx, "");
        chanout_but(-1, dcc[idx].u.chat->channel,
                    "*** %s left the party line.\n", dcc[idx].nick);
        dprintf(idx, "Setting your username to %s.\n", par);
        if (atr & USER_MASTER)
          dcc[idx].u.chat->con_flags = conmask;
        size_t _len = strlen(dcc[idx].nick) + 1;
        dcc[idx].u.chat->su_nick = get_data_ptr(_len);
        op_strlcpy(dcc[idx].u.chat->su_nick, dcc[idx].nick, _len);
        dcc[idx].user = u;
        op_strlcpy(dcc[idx].nick, par, sizeof dcc[idx].nick);
        dcc_chatter(idx);
      }
    }
  }
}

static void cmd_fixcodes(struct userrec *u, int idx, char *par)
{
  if (dcc[idx].status & STAT_TELNET) {
    dcc[idx].status |= STAT_ECHO;
    dcc[idx].status &= ~STAT_TELNET;
    dprintf(idx, "Turned off telnet codes.\n");
    putlog(LOG_CMDS, "*", "#%s# fixcodes (telnet off)", dcc[idx].nick);
  } else {
    dcc[idx].status |= STAT_TELNET;
    dcc[idx].status &= ~STAT_ECHO;
    dprintf(idx, "Turned on telnet codes.\n");
    putlog(LOG_CMDS, "*", "#%s# fixcodes (telnet on)", dcc[idx].nick);
  }
}

static void cmd_page(struct userrec *u, int idx, char *par)
{
  int a;
  module_entry *me;

  if (!par[0]) {
    if (dcc[idx].status & STAT_PAGE) {
      dprintf(idx, "Currently paging outputs to %d lines.\n",
              dcc[idx].u.chat->max_line);
    } else
      dprintf(idx, "You don't have paging on.\n");
    return;
  }
  a = egg_atoi(par);
  if ((!a && !par[0]) || !op_strcasecmp(par, "off")) {
    dcc[idx].status &= ~STAT_PAGE;
    dcc[idx].u.chat->max_line = 0x7ffffff;      /* flush_lines needs this */
    while (dcc[idx].u.chat->buffer)
      flush_lines(idx, dcc[idx].u.chat);
    dprintf(idx, "Paging turned off.\n");
    putlog(LOG_CMDS, "*", "#%s# page off", dcc[idx].nick);
  } else if (a > 0) {
    dprintf(idx, "Paging turned on, stopping every %d line%s.\n", a,
            (a != 1) ? "s" : "");
    dcc[idx].status |= STAT_PAGE;
    dcc[idx].u.chat->max_line = a;
    dcc[idx].u.chat->line_count = 0;
    dcc[idx].u.chat->current_lines = 0;
    putlog(LOG_CMDS, "*", "#%s# page %d", dcc[idx].nick, a);
  } else {
    dprintf(idx, "Usage: page <off or #>\n");
    return;
  }
  /* New style autosave here too -- rtc, 09/28/1999 */
  if ((me = module_find("console", 1, 1))) {
    Function *func = me->funcs;

    ((int (*)(int)) func[CONSOLE_DOSTORE])(idx);
  }
}

/* Evaluate a Tcl command, send output to a dcc user.
 */
static void cmd_tcl(struct userrec *u, int idx, char *msg)
{
  if (!interp) {
    dprintf(idx, "Tcl scripting support is not compiled in.\n");
    return;
  }

  struct egg_rusage_timer rt;
  int code;

  if (!isowner(dcc[idx].nick) && must_be_owner) {
    dprintf(idx, "%s", MISC_NOSUCHCMD);
    return;
  }
  debug1("tcl: evaluating .tcl %s", msg);
  egg_timer_start(&rt);
  code = egg_eval(msg);
  double ums, sms;
  if (egg_timer_stop(&rt, &ums, &sms))
    debug3("tcl: evaluated .tcl %s, user %.3fms sys %.3fms", msg, ums, sms);

  if (code == TCL_OK)
    dumplots(idx, "Tcl: ", tcl_resultstring());
  else
    dumplots(idx, "Tcl error: ", tcl_resultstring());
}

static void cmd_python(struct userrec *u, int idx, char *msg)
{
  module_entry *me = module_find("python", 0, 0);
  if (!me) {
    dprintf(idx, "Python module is not loaded.\n");
    return;
  }
  if (!isowner(dcc[idx].nick) && must_be_owner) {
    dprintf(idx, "%s", MISC_NOSUCHCMD);
    return;
  }
  putlog(LOG_CMDS, "*", "#%s# python %s", dcc[idx].nick, msg);
  dprintf(idx, "Use .tcl or Python scripts for evaluation.\n");
}

/* Perform a 'set' command
 */
static void cmd_set(struct userrec *u, int idx, char *msg)
{
  if (!interp) {
    if (!isowner(dcc[idx].nick) && must_be_owner) {
      dprintf(idx, "%s", MISC_NOSUCHCMD);
      return;
    }
    putlog(LOG_CMDS, "*", "#%s# set %s", dcc[idx].nick, msg);
    if (!msg[0]) {
      dprintf(idx, "Usage: .set <variable> [value]\n");
      return;
    }
    char *value = strchr(msg, ' ');
    if (value) {
      *value++ = 0;
      notcl_setvar(msg, value);
      dprintf(idx, "Set %s = %s\n", msg, value);
    } else {
      char buf[512];
      const char *v = notcl_getvar(msg, buf, sizeof buf);
      if (v)
        dprintf(idx, "%s = %s\n", msg, v);
      else
        dprintf(idx, "Variable '%s' not found\n", msg);
    }
    return;
  }

  int code;

  if (!isowner(dcc[idx].nick) && must_be_owner) {
    dprintf(idx, "%s", MISC_NOSUCHCMD);
    return;
  }
  putlog(LOG_CMDS, "*", "#%s# set %s", dcc[idx].nick, msg);
  if (!msg[0]) {
    (void)egg_eval("info globals");
    dumplots(idx, "Global vars: ", tcl_resultstring());
    return;
  }
  {
    op_strbuf_t sb = {};
    op_strbuf_init(&sb);
    op_strbuf_appendf(&sb, "set %s", msg);
    code = egg_eval(op_strbuf_str(&sb));
    op_strbuf_free(&sb);
  }

  if (code == TCL_OK) {
    if (!strchr(msg, ' '))
      dumplots(idx, "Currently: ", tcl_resultstring());
    else
      dprintf(idx, "Ok, set.\n");
  } else
    dprintf(idx, "Error: %s\n", tcl_resultstring());
}

static void cmd_module(struct userrec *u, int idx, char *par)
{
  putlog(LOG_CMDS, "*", "#%s# module %s", dcc[idx].nick, par);
  do_module_report(idx, 2, par[0] ? par : nullptr);
}

static void cmd_loadmod(struct userrec *u, int idx, char *par)
{
  const char *p;

  if (!isowner(dcc[idx].nick) && must_be_owner) {
    dprintf(idx, "%s", MISC_NOSUCHCMD);
    return;
  }
  if (!par[0]) {
    dprintf(idx, "%s: loadmod <module>\n", MISC_USAGE);
  } else {
    p = module_load(par);
    if (p)
      dprintf(idx, "%s: %s %s\n", par, MOD_LOADERROR, p);
    else {
      putlog(LOG_CMDS, "*", "#%s# loadmod %s", dcc[idx].nick, par);
      dprintf(idx, MOD_LOADED, par);
      dprintf(idx, "\n");
    }
  }
}

static void cmd_unloadmod(struct userrec *u, int idx, char *par)
{
  char *p;

  if (!isowner(dcc[idx].nick) && must_be_owner) {
    dprintf(idx, "%s", MISC_NOSUCHCMD);
    return;
  }
  if (!par[0])
    dprintf(idx, "%s: unloadmod <module>\n", MISC_USAGE);
  else {
    p = module_unload(par, dcc[idx].nick);
    if (p)
      dprintf(idx, "%s %s: %s\n", MOD_UNLOADERROR, par, p);
    else {
      putlog(LOG_CMDS, "*", "#%s# unloadmod %s", dcc[idx].nick, par);
      dprintf(idx, "%s %s\n", MOD_UNLOADED, par);
    }
  }
}

static void cmd_pls_ignore(struct userrec *u, int idx, char *par)
{
  char *who, *p, *p_expire;
  char s[UHOSTLEN];
  long expire_foo;
  uint64_t expire_time = 0;

  if (!par[0]) {
    dprintf(idx, "Usage: +ignore <hostmask> [%%<XyXdXhXm>] [comment]\n");
    return;
  }

  who = newsplit(&par);
  if (par[0] == '%') {
    p = newsplit(&par);
    p_expire = p + 1;
    while (*(++p) != 0) {
      switch (tolower((unsigned) *p)) {
      case 'y':
        *p = 0;
        expire_foo = strtol(p_expire, nullptr, 10);
        expire_time += 60 * 60 * 24 * 365 * expire_foo;
        p_expire = p + 1;
        break;
      case 'd':
        *p = 0;
        expire_foo = strtol(p_expire, nullptr, 10);
        expire_time += 60 * 60 * 24 * expire_foo;
        p_expire = p + 1;
        break;
      case 'h':
        *p = 0;
        expire_foo = strtol(p_expire, nullptr, 10);
        expire_time += 60 * 60 * expire_foo;
        p_expire = p + 1;
        break;
      case 'm':
        *p = 0;
        expire_foo = strtol(p_expire, nullptr, 10);
        expire_time += 60 * expire_foo;
        p_expire = p + 1;
      }
    }
    /* For whomever is stuck with maintaining this in 2033 - this will
     * break. Hopefully we've dealt with the max unixtime issue by now
     * (Year 2038 problem), but if you're reading this, clearly we
     * haven't because we are lazy. Sorry.
     */
    if (expire_time > (60 * 60 * 24 * 365 * 5)) {
      dprintf(idx, "expire time must be equal to or less than 5 years "
              "(1825 days)\n");
      return;
    }
  }
  if (!par[0])
    par = "requested";
  else if (strlen(par) > 65)
    par[65] = 0;
  if (strlen(who) > UHOSTMAX - 4)
    who[UHOSTMAX - 4] = 0;

  /* Fix missing ! or @ BEFORE continuing */
  if (!strchr(who, '!')) {
    if (!strchr(who, '@'))
      snprintf(s, sizeof s, "%s!*@*", who);
    else
      snprintf(s, sizeof s, "*!%s", who);
  } else if (!strchr(who, '@'))
    snprintf(s, sizeof s, "%s@*", who);
  else
    op_strlcpy(s, who, sizeof s);

  if (match_ignore(s))
    dprintf(idx, "That already matches an existing ignore.\n");
  else {
    dprintf(idx, "Now ignoring: %s (%s)\n", s, par);
    addignore(s, dcc[idx].nick, par, expire_time ? now + expire_time : 0L);
    putlog(LOG_CMDS, "*", "#%s# +ignore %s %s", dcc[idx].nick, s, par);
  }
}

static void cmd_mns_ignore(struct userrec *u, int idx, char *par)
{
  if (!par[0]) {
    dprintf(idx, "Usage: -ignore <hostmask | ignore #>\n");
    return;
  }
  if (delignore(par)) {
    putlog(LOG_CMDS, "*", "#%s# -ignore %s", dcc[idx].nick, par);
    dprintf(idx, "No longer ignoring: %s\n", par);
  } else
    dprintf(idx, "That ignore cannot be found.\n");
}

static void cmd_ignores(struct userrec *u, int idx, char *par)
{
  putlog(LOG_CMDS, "*", "#%s# ignores %s", dcc[idx].nick, par);
  tell_ignores(idx, par);
}

static void cmd_pls_user(struct userrec *u, int idx, char *par)
{
  char *handle, *host;

  if (!par[0]) {
    dprintf(idx, "Usage: +user <handle> [hostmask]\n");
    return;
  }
  handle = newsplit(&par);
  host = newsplit(&par);
  if (strlen(handle) > HANDLEN)
    handle[HANDLEN] = 0;
  if (get_user_by_handle(userlist, handle))
    dprintf(idx, "Someone already exists by that name.\n");
  else if (strchr(BADHANDCHARS, handle[0]) != nullptr)
    dprintf(idx, "You can't start a handle with '%c'.\n", handle[0]);
  else if (!op_strcasecmp(handle, botnetnick))
    dprintf(idx, "Hey! That's MY name!\n");
  else {
    putlog(LOG_CMDS, "*", "#%s# +user %s %s", dcc[idx].nick, handle, host);
    userlist = adduser(userlist, handle, host, "-", 0);
    dprintf(idx, "Added %s (%s) with no password and no flags.\n", handle,
            host[0] ? host : "no host");
  }
}

static void cmd_mns_user(struct userrec *u, int idx, char *par)
{
  int idx2;
  char *handle;
  struct userrec *u2;
  module_entry *me;

  if (!par[0]) {
    dprintf(idx, "Usage: -user <hand>\n");
    return;
  }
  handle = newsplit(&par);
  u2 = get_user_by_handle(userlist, handle);
  if (!u2 || !u) {
    dprintf(idx, "No such user!\n");
    return;
  }
  if (isowner(u2->handle)) {
    dprintf(idx, "You can't remove a permanent bot owner!\n");
    return;
  }
  if ((u2->flags & USER_OWNER) && !isowner(u->handle)) {
    dprintf(idx, "You can't remove a bot owner!\n");
    return;
  }
  if ((u2->flags & USER_MASTER) && !(u->flags & USER_OWNER)) {
    dprintf(idx, "Only owners can remove a master!\n");
    return;
  }
  if (u2->flags & USER_BOT) {
    if ((bot_flags(u2) & BOT_SHARE) && !(u->flags & USER_OWNER)) {
      dprintf(idx, "You can't remove share bots.\n");
      return;
    }
    for (idx2 = 0; idx2 < dcc_total; idx2++)
      if (dcc[idx2].type != &DCC_RELAY && dcc[idx2].type != &DCC_FORK_BOT &&
          !op_strcasecmp(dcc[idx2].nick, handle))
        break;
    if (idx2 != dcc_total) {
      dprintf(idx, "You can't remove a directly linked bot.\n");
      return;
    }
  }
  if ((u->flags & USER_BOTMAST) && !(u->flags & USER_MASTER) &&
      !(u2->flags & USER_BOT)) {
    dprintf(idx, "You can't remove users who aren't bots!\n");
    return;
  }
  if ((me = module_find("irc", 0, 0))) {
    Function *func = me->funcs;

    ((void (*)(char *, int, char *)) func[IRC_CHECK_THIS_USER])(handle, 1, nullptr);
  }
  if (deluser(handle)) {
    putlog(LOG_CMDS, "*", "#%s# -user %s", dcc[idx].nick, handle);
    dprintf(idx, "Deleted %s.\n", handle);
  } else
    dprintf(idx, "Failed.\n");
}

static void cmd_pls_host(struct userrec *u, int idx, char *par)

{
  int ret;
  char *handle, *host;
  module_entry *me;

  if (!par[0]) {
    dprintf(idx, "Usage: +host [handle] <newhostmask>\n");
    return;
  }

  handle = newsplit(&par);
  if (par[0]) {
    host = newsplit(&par);
  } else {
    host = handle;
    handle = dcc[idx].nick;
  }
  ret = add_to_handle(u, idx, handle, host, 0);
  if (!ret) {
    putlog(LOG_CMDS, "*", "#%s# +host %s %s", dcc[idx].nick, handle, host);
    dprintf(idx, "Added '%s' to %s.\n", host, handle);
    if ((me = module_find("irc", 0, 0))) {
      Function *func = me->funcs;
      ((void (*)(char *, int, char *)) func[IRC_CHECK_THIS_USER])(handle, 0, nullptr);
    }
  }
}

static void cmd_mns_host(struct userrec *u, int idx, char *par)
{
  char *handle, *host;

  if (!par[0]) {
    dprintf(idx, "Usage: -host [handle] <hostmask>\n");
    return;
  }
  handle = newsplit(&par);
  if (par[0]) {
    host = newsplit(&par);
  } else {
    host = handle;
    handle = dcc[idx].nick;
  }
  remove_from_handle(u, idx, handle, host, 0);
}

static void cmd_modules(struct userrec *u, int idx, char *par)
{
  int ptr;
  char *bot;
  putlog(LOG_CMDS, "*", "#%s# modules %s", dcc[idx].nick, par);

  if (!par[0]) {
    dprintf(idx, "Modules loaded:\n");
    for (size_t _mi = 0; _mi < module_vec.size; _mi++) {
      module_entry *me = (module_entry *)op_vec_get(&module_vec, _mi);
      dprintf(idx, "  Module: %s (v%d.%d)\n", me->name, me->major, me->minor);
    }
    dprintf(idx, "End of modules list.\n");
  } else {
    bot = newsplit(&par);
    if ((ptr = nextbot(bot)) >= 0)
      dprintf(ptr, "v %s %s %ld:%s\n", botnetnick, bot, dcc[idx].sock,
              dcc[idx].nick);
    else
      dprintf(idx, "No such bot online.\n");
  }
}

static void cmd_traffic(struct userrec *u, int idx, char *par)
{
  uint64_t itmp, itmp2;

  dprintf(idx, "Traffic since last restart\n");
  dprintf(idx, "==========================\n");
  if (otraffic_irc > 0 || itraffic_irc > 0 || otraffic_irc_today > 0 ||
      itraffic_irc_today > 0) {
    dprintf(idx, "IRC:\n");
    dprintf(idx, "  out: %s", btos(otraffic_irc + otraffic_irc_today));
    dprintf(idx, " (%s today)\n", btos(otraffic_irc_today));
    dprintf(idx, "   in: %s", btos(itraffic_irc + itraffic_irc_today));
    dprintf(idx, " (%s today)\n", btos(itraffic_irc_today));
  }
  if (otraffic_bn > 0 || itraffic_bn > 0 || otraffic_bn_today > 0 ||
      itraffic_bn_today > 0) {
    dprintf(idx, "Botnet:\n");
    dprintf(idx, "  out: %s", btos(otraffic_bn + otraffic_bn_today));
    dprintf(idx, " (%s today)\n", btos(otraffic_bn_today));
    dprintf(idx, "   in: %s", btos(itraffic_bn + itraffic_bn_today));
    dprintf(idx, " (%s today)\n", btos(itraffic_bn_today));
  }
  if (otraffic_dcc > 0 || itraffic_dcc > 0 || otraffic_dcc_today > 0 ||
      itraffic_dcc_today > 0) {
    dprintf(idx, "Partyline:\n");
    itmp = otraffic_dcc + otraffic_dcc_today;
    itmp2 = otraffic_dcc_today;
    dprintf(idx, "  out: %s", btos(itmp));
    dprintf(idx, " (%s today)\n", btos(itmp2));
    dprintf(idx, "   in: %s", btos(itraffic_dcc + itraffic_dcc_today));
    dprintf(idx, " (%s today)\n", btos(itraffic_dcc_today));
  }
  if (otraffic_trans > 0 || itraffic_trans > 0 || otraffic_trans_today > 0 ||
      itraffic_trans_today > 0) {
    dprintf(idx, "Transfer.mod:\n");
    dprintf(idx, "  out: %s", btos(otraffic_trans + otraffic_trans_today));
    dprintf(idx, " (%s today)\n", btos(otraffic_trans_today));
    dprintf(idx, "   in: %s", btos(itraffic_trans + itraffic_trans_today));
    dprintf(idx, " (%s today)\n", btos(itraffic_trans_today));
  }
  if (otraffic_unknown > 0 || otraffic_unknown_today > 0) {
    dprintf(idx, "Misc:\n");
    dprintf(idx, "  out: %s", btos(otraffic_unknown + otraffic_unknown_today));
    dprintf(idx, " (%s today)\n", btos(otraffic_unknown_today));
    dprintf(idx, "   in: %s", btos(itraffic_unknown + itraffic_unknown_today));
    dprintf(idx, " (%s today)\n", btos(itraffic_unknown_today));
  }
  dprintf(idx, "---\n");
  dprintf(idx, "Total:\n");
  itmp = otraffic_irc + otraffic_bn + otraffic_dcc + otraffic_trans +
         otraffic_unknown + otraffic_irc_today + otraffic_bn_today +
         otraffic_dcc_today + otraffic_trans_today + otraffic_unknown_today;
  itmp2 = otraffic_irc_today + otraffic_bn_today + otraffic_dcc_today +
          otraffic_trans_today + otraffic_unknown_today;
  dprintf(idx, "  out: %s", btos(itmp));
  dprintf(idx, " (%s today)\n", btos(itmp2));
  dprintf(idx, "   in: %s", btos(itraffic_irc + itraffic_bn + itraffic_dcc +
          itraffic_trans + itraffic_unknown + itraffic_irc_today +
          itraffic_bn_today + itraffic_dcc_today + itraffic_trans_today +
          itraffic_unknown_today));
  dprintf(idx, " (%s today)\n", btos(itraffic_irc_today + itraffic_bn_today +
          itraffic_dcc_today + itraffic_trans_today + itraffic_unknown_today));
  putlog(LOG_CMDS, "*", "#%s# traffic", dcc[idx].nick);
}

static const char *btos(uint64_t bytes)
{
  static op_strbuf_t sb = {};
  const char *unit;
  float xbytes;

  xbytes = bytes;
  if (xbytes > 1024.0) {
    unit = "KBytes";
    xbytes = xbytes / 1024.0;
  }
  if (xbytes > 1024.0) {
    unit = "MBytes";
    xbytes = xbytes / 1024.0;
  }
  if (xbytes > 1024.0) {
    unit = "GBytes";
    xbytes = xbytes / 1024.0;
  }
  if (xbytes > 1024.0) {
    unit = "TBytes";
    xbytes = xbytes / 1024.0;
  }
  if (bytes > 1024) {
    op_strbuf_clear(&sb);
    op_strbuf_appendf(&sb, "%.2f %s", xbytes, unit);
  } else {
    op_strbuf_clear(&sb);
    op_strbuf_appendf(&sb, "%" PRIu64 " Bytes", bytes);
  }
  return op_strbuf_str(&sb);
}

static void cmd_whoami(struct userrec *u, int idx, char *par)
{
  dprintf(idx, "You are %s@%s.\n", dcc[idx].nick, botnetnick);
  putlog(LOG_CMDS, "*", "#%s# whoami", dcc[idx].nick);
}

/* DCC CHAT COMMANDS
 */
/* Function call should be:
 *   static void cmd_whatever(struct userrec *u, int idx, char *par);
 * As with msg commands, function is responsible for any logging.
 */
cmd_t C_dcc[] = {
  {"+account",  "t|m",  (IntFunc) cmd_pls_account,nullptr},
  {"+bot",      "t",    (IntFunc) cmd_pls_bot,    nullptr},
  {"+host",     "t|m",  (IntFunc) cmd_pls_host,   nullptr},
  {"+ignore",   "m",    (IntFunc) cmd_pls_ignore, nullptr},
  {"+user",     "m",    (IntFunc) cmd_pls_user,   nullptr},
  {"-account",  "",     (IntFunc) cmd_mns_account,nullptr},
  {"-bot",      "t",    (IntFunc) cmd_mns_user,   nullptr},
  {"-host",     "",     (IntFunc) cmd_mns_host,   nullptr},
  {"-ignore",   "m",    (IntFunc) cmd_mns_ignore, nullptr},
  {"-user",     "m",    (IntFunc) cmd_mns_user,   nullptr},
  {"addlog",    "to|o", (IntFunc) cmd_addlog,     nullptr},
  {"away",      "",     (IntFunc) cmd_away,       nullptr},
  {"back",      "",     (IntFunc) cmd_back,       nullptr},
  {"backup",    "m|m",  (IntFunc) cmd_backup,     nullptr},
  {"banner",    "t",    (IntFunc) cmd_banner,     nullptr},
  {"binds",     "m",    (IntFunc) cmd_binds,      nullptr},
  {"boot",      "t",    (IntFunc) cmd_boot,       nullptr},
  {"botattr",   "t",    (IntFunc) cmd_botattr,    nullptr},
  {"botinfo",   "",     (IntFunc) cmd_botinfo,    nullptr},
  {"bots",      "",     (IntFunc) cmd_bots,       nullptr},
  {"bottree",   "",     (IntFunc) cmd_bottree,    nullptr},
  {"chaddr",    "t",    (IntFunc) cmd_chaddr,     nullptr},
  {"chat",      "",     (IntFunc) cmd_chat,       nullptr},
  {"chattr",    "m|m",  (IntFunc) cmd_chattr,     nullptr},
#ifdef TLS
  {"chfinger",  "t",    (IntFunc) cmd_chfinger,   nullptr},
#endif
  {"chhandle",  "t",    (IntFunc) cmd_chhandle,   nullptr},
  {"chnick",    "t",    (IntFunc) cmd_chhandle,   nullptr},
  {"chpass",    "t",    (IntFunc) cmd_chpass,     nullptr},
  {"comment",   "m",    (IntFunc) cmd_comment,    nullptr},
  {"console",   "to|o", (IntFunc) cmd_console,    nullptr},
  {"resetconsole", "to|o", (IntFunc) cmd_resetconsole, nullptr},
  {"dccstat",   "t",    (IntFunc) cmd_dccstat,    nullptr},
  {"debug",     "m",    (IntFunc) cmd_debug,      nullptr},
  {"die",       "n",    (IntFunc) cmd_die,        nullptr},
  {"echo",      "",     (IntFunc) cmd_echo,       nullptr},
#ifdef TLS
  {"fprint",    "",     (IntFunc) cmd_fprint,     nullptr},
#endif
  {"fixcodes",  "",     (IntFunc) cmd_fixcodes,   nullptr},
  {"help",      "",     (IntFunc) cmd_help,       nullptr},
  {"ignores",   "m",    (IntFunc) cmd_ignores,    nullptr},
  {"link",      "t",    (IntFunc) cmd_link,       nullptr},
  {"loadmod",   "n",    (IntFunc) cmd_loadmod,    nullptr},
  {"match",     "to|o", (IntFunc) cmd_match,      nullptr},
  {"me",        "",     (IntFunc) cmd_me,         nullptr},
  {"module",    "m",    (IntFunc) cmd_module,     nullptr},
  {"modules",   "n",    (IntFunc) cmd_modules,    nullptr},
  {"motd",      "",     (IntFunc) cmd_motd,       nullptr},
  {"newpass",   "",     (IntFunc) cmd_newpass,    nullptr},
  {"handle",    "",     (IntFunc) cmd_handle,     nullptr},
  {"nick",      "",     (IntFunc) cmd_handle,     nullptr},
  {"page",      "",     (IntFunc) cmd_page,       nullptr},
  {"python",    "n",    (IntFunc) cmd_python,     nullptr},
  {"quit",      "",     (IntFunc) CMD_LEAVE,      nullptr},
  {"rehash",    "m",    (IntFunc) cmd_rehash,     nullptr},
  {"rehelp",    "n",    (IntFunc) cmd_rehelp,     nullptr},
  {"relay",     "o",    (IntFunc) cmd_relay,      nullptr},
  {"reload",    "m|m",  (IntFunc) cmd_reload,     nullptr},
  {"restart",   "m",    (IntFunc) cmd_restart,    nullptr},
  {"save",      "m|m",  (IntFunc) cmd_save,       nullptr},
  {"set",       "n",    (IntFunc) cmd_set,        nullptr},
  {"simul",     "n",    (IntFunc) cmd_simul,      nullptr},
  {"status",    "m|m",  (IntFunc) cmd_status,     nullptr},
  {"threads",   "m",    (IntFunc) cmd_threads,    nullptr},
  {"strip",     "",     (IntFunc) cmd_strip,      nullptr},
  {"su",        "",     (IntFunc) cmd_su,         nullptr},
  {"tcl",       "n",    (IntFunc) cmd_tcl,        nullptr},
  {"trace",     "t",    (IntFunc) cmd_trace,      nullptr},
  {"unlink",    "t",    (IntFunc) cmd_unlink,     nullptr},
  {"unloadmod", "n",    (IntFunc) cmd_unloadmod,  nullptr},
  {"uptime",    "m|m",  (IntFunc) cmd_uptime,     nullptr},
  {"vbottree",  "",     (IntFunc) cmd_vbottree,   nullptr},
  {"who",       "",     (IntFunc) cmd_who,        nullptr},
  {"whois",     "to|o", (IntFunc) cmd_whois,      nullptr},
  {"whom",      "",     (IntFunc) cmd_whom,       nullptr},
  {"traffic",   "m|m",  (IntFunc) cmd_traffic,    nullptr},
  {"whoami",    "",     (IntFunc) cmd_whoami,     nullptr},
  {nullptr,        nullptr,   nullptr,                     nullptr}
};

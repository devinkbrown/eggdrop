/*
 * share.c -- part of share.mod
 *
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

#define MODULE_NAME "share"
#define MAKING_SHARE

#include <errno.h>
#include "src/mod/module.h"

#include <arpa/inet.h>
#include <sys/stat.h>

#include "src/chan.h"
#include "src/users.h"
#include "transfer.mod/transfer.h"
#include "channels.mod/channels.h"

/*
 * Share protocol framing constants.
 *
 * SHARE_PROTO_VERSION 2 introduces length-prefixed framing on the botlink
 * socket (4-byte big-endian payload length followed by the payload).  This
 * makes the wire format unambiguous and is a prerequisite for TLS support.
 *
 * Version negotiation is done in share_version()/share_ufyes(): a peer that
 * announces SHARE_PROTO_VERSION >= 2 in its capability string may send and
 * expects to receive length-prefixed frames.  Peers that do not announce v2
 * continue to use the existing newline-delimited line protocol (SHARE_PROTO_VERSION 1).
 *
 * MAX_SHARE_FRAME caps the maximum accepted frame payload.  Lines exceeding
 * this limit are dropped with a warning; the peer is not disconnected because
 * the line-mode layer above us has already buffered the full line.
 */
#define SHARE_PROTO_VERSION 2
#define MAX_SHARE_FRAME     65536

/* Minimum version I will share with. */
static const int min_share = 1029900;

/* Earliest version that supports exempts and invites. */
static const int min_exemptinvite = 1032800;

/* Minimum version that supports userfile features. */
static const int min_uffeature = 1050200;

static Function *global = nullptr, *transfer_funcs = nullptr, *channels_funcs = nullptr;

static int private_global = 0;
static int private_user = 0;
static char private_globals[51];
static int allow_resync = 0;
static struct flag_record fr = {};
static int resync_time = 900;
static int overr_local_bots = 0;        /* Override local bots?             */


/* Store info for sharebots.
 * Nodes are allocated from share_msgq_bh and stored by pointer in each
 * tandbuf's op_deque_t — no embedded 'next' pointer needed. */
struct share_msgq {
  struct chanset_t *chan;
  char *msg;
};

typedef struct tandbuf_t {
  char bot[HANDLEN + 1];
  time_t timer;
  op_deque_t q;           /* deque of share_msgq* — embedded, not a pointer */
} tandbuf;

static op_vec_t tbuf_vec;

/* Slab allocator for share_msgq nodes. */
static op_bh *share_msgq_bh = nullptr;
/* Slab allocator for delay_mode nodes. */
static op_bh *delay_mode_bh = nullptr;
/* Slab allocator for tandbuf (resync buffer) nodes. */
static op_bh *tandbuf_bh    = nullptr;

/* Prototypes */
static void start_sending_users(int);
static void shareout_but(struct chanset_t *chan, int x, const char *format, ...) ATTRIBUTE_FORMAT(printf,3,4);
static int flush_tbuf(char *);
static int can_resync(char *);
static void dump_resync(int);
static void q_resync(const char *, struct chanset_t *);
static void cancel_user_xfer(int, void *);
static int private_globals_bitmask(void);

#include "share.h"

#include "uf_features.c"

/*
 *   Sup's delay code
 */

struct delay_mode {
  struct chanset_t *chan;
  int plsmns;
  int mode;
  char *mask;
  time_t seconds;
};

static op_vec_t delay_vec;

static void add_delay(struct chanset_t *chan, int plsmns, int mode, char *mask)
{
  if (!delay_mode_bh)
    delay_mode_bh = op_bh_create(sizeof(struct delay_mode), 16, "share_delay_mode");
  struct delay_mode *d = (struct delay_mode *)op_bh_alloc(delay_mode_bh);
  d->chan = chan;
  d->plsmns = plsmns;
  d->mode = mode;
  d->seconds = now + randint(30);
  d->mask = op_strdup(mask);
  op_vec_push(&delay_vec, d);
}

static void check_delay(void)
{
  for (size_t i = delay_vec.size; i-- > 0; ) {
    struct delay_mode *d = (struct delay_mode *)op_vec_get(&delay_vec, i);
    if (d->seconds <= now) {
      add_mode(d->chan, d->plsmns, d->mode, d->mask);
      op_free(d->mask);
      op_bh_free(delay_mode_bh, d);
      op_vec_remove(&delay_vec, i);
    }
  }
}

static void delay_free_mem(void)
{
  for (size_t i = delay_vec.size; i-- > 0; ) {
    struct delay_mode *d = (struct delay_mode *)op_vec_get(&delay_vec, i);
    op_free(d->mask);
    op_bh_free(delay_mode_bh, d);
  }
  op_vec_clear(&delay_vec, nullptr, nullptr);
}

static int delay_expmem(void)
{
  int size = 0;
  for (size_t i = 0; i < delay_vec.size; i++) {
    struct delay_mode *d = (struct delay_mode *)op_vec_get(&delay_vec, i);
    if (d->mask)
      size += strlen(d->mask) + 1;
    size += sizeof(struct delay_mode);
  }
  return size;
}

/*
 *   Botnet commands
 */

static void share_stick_ban(int idx, char *par)
{
  char *host, *val;
  int yn;

  if (dcc[idx].status & STAT_SHARE) {
    host = newsplit(&par);
    val = newsplit(&par);
    yn = egg_atoi(val);
    noshare = 1;
    if (!par[0]) {              /* Global ban */
      if (u_setsticky_ban(nullptr, host, yn) > 0) {
        putlog(LOG_CMDS, "*", "%s: %s %s", dcc[idx].nick,
               (yn) ? "stick" : "unstick", host);
        shareout_but(nullptr, idx, "s %s %d\n", host, yn);
      }
    } else {
      struct chanset_t *chan = findchan_by_dname(par);
      struct chanuserrec *cr;

      if ((chan != nullptr) && ((channel_shared(chan) &&
          ((cr = get_chanrec(dcc[idx].user, par)) &&
          (cr->flags & BOT_AGGRESSIVE))) ||
          (bot_flags(dcc[idx].user) & BOT_GLOBAL)))
        if (u_setsticky_ban(chan, host, yn) > 0) {
          putlog(LOG_CMDS, "*", "%s: %s %s %s", dcc[idx].nick,
                 (yn) ? "stick" : "unstick", host, par);
          shareout_but(chan, idx, "s %s %d %s\n", host, yn, chan->dname);
          noshare = 0;
          return;
        }
      putlog(LOG_CMDS, "*", "Rejecting invalid sticky ban: %s on %s%s",
             host, par, yn ? "" : " (unstick)");
    }
    noshare = 0;
  }
}

/* Same as share_stick_ban, only for exempts.
 */
static void share_stick_exempt(int idx, char *par)
{
  char *host, *val;
  int yn;

  if (dcc[idx].status & STAT_SHARE) {
    host = newsplit(&par);
    val = newsplit(&par);
    yn = egg_atoi(val);
    noshare = 1;
    if (!par[0]) {              /* Global exempt */
      if (u_setsticky_exempt(nullptr, host, yn) > 0) {
        putlog(LOG_CMDS, "*", "%s: %s %s", dcc[idx].nick,
               (yn) ? "stick" : "unstick", host);
        shareout_but(nullptr, idx, "se %s %d\n", host, yn);
      }
    } else {
      struct chanset_t *chan = findchan_by_dname(par);
      struct chanuserrec *cr;

      if ((chan != nullptr) && ((channel_shared(chan) &&
          ((cr = get_chanrec(dcc[idx].user, par)) &&
          (cr->flags & BOT_AGGRESSIVE))) ||
          (bot_flags(dcc[idx].user) & BOT_GLOBAL)))
        if (u_setsticky_exempt(chan, host, yn) > 0) {
          putlog(LOG_CMDS, "*", "%s: %s %s %s", dcc[idx].nick,
                 (yn) ? "stick" : "unstick", host, par);
          shareout_but(chan, idx, "se %s %d %s\n", host, yn, chan->dname);
          noshare = 0;
          return;
        }
      putlog(LOG_CMDS, "*", "Rejecting invalid sticky exempt: %s on %s%s",
             host, par, yn ? "" : " (unstick)");
    }
    noshare = 0;
  }
}

/* Same as share_stick_ban, only for invites.
 */
static void share_stick_invite(int idx, char *par)
{
  char *host, *val;
  int yn;

  if (dcc[idx].status & STAT_SHARE) {
    host = newsplit(&par);
    val = newsplit(&par);
    yn = egg_atoi(val);
    noshare = 1;
    if (!par[0]) {              /* Global invite */
      if (u_setsticky_invite(nullptr, host, yn) > 0) {
        putlog(LOG_CMDS, "*", "%s: %s %s", dcc[idx].nick,
               (yn) ? "stick" : "unstick", host);
        shareout_but(nullptr, idx, "sInv %s %d\n", host, yn);
      }
    } else {
      struct chanset_t *chan = findchan_by_dname(par);
      struct chanuserrec *cr;

      if ((chan != nullptr) && ((channel_shared(chan) &&
          ((cr = get_chanrec(dcc[idx].user, par)) &&
          (cr->flags & BOT_AGGRESSIVE))) ||
          (bot_flags(dcc[idx].user) & BOT_GLOBAL)))
        if (u_setsticky_invite(chan, host, yn) > 0) {
          putlog(LOG_CMDS, "*", "%s: %s %s %s", dcc[idx].nick,
                 (yn) ? "stick" : "unstick", host, par);
          shareout_but(chan, idx, "sInv %s %d %s\n", host, yn, chan->dname);
          noshare = 0;
          return;
        }
      putlog(LOG_CMDS, "*", "Rejecting invalid sticky invite: %s on %s%s",
             host, par, yn ? "" : " (unstick)");
    }
    noshare = 0;
  }
}

static void share_chhand(int idx, char *par)
{
  char *hand;
  struct userrec *u;

  if ((dcc[idx].status & STAT_SHARE) && !private_user) {
    hand = newsplit(&par);
    u = get_user_by_handle(userlist, hand);
    if (u && !(u->flags & USER_UNSHARED)) {
      shareout_but(nullptr, idx, "h %s %s\n", hand, par);
      noshare = 1;
      if (change_handle(u, par))
        putlog(LOG_CMDS, "*", "%s: handle %s->%s", dcc[idx].nick, hand, par);
      noshare = 0;
    }
  }
}

static void share_chattr(int idx, char *par)
{
  char *hand, *atr, s[100];
  struct chanset_t *cst;
  struct userrec *u;
  struct flag_record fr2;
  int bfl, ofl;
  module_entry *me;

  if ((dcc[idx].status & STAT_SHARE) && !private_user) {
    hand = newsplit(&par);
    u = get_user_by_handle(userlist, hand);
    if (u && !(u->flags & USER_UNSHARED)) {
      atr = newsplit(&par);
      cst = findchan_by_dname(par);
      if (!par[0] || (cst && channel_shared(cst))) {
        if (!(dcc[idx].status & STAT_GETTING) && (cst || !private_global))
          shareout_but(cst, idx, "a %s %s %s\n", hand, atr, par);
        noshare = 1;
        if (par[0] && cst) {
          fr.match = (FR_CHAN | FR_BOT);
          get_user_flagrec(dcc[idx].user, &fr, par);
          if (bot_chan(fr) || bot_global(fr)) {
            fr.match = FR_CHAN;
            fr2.match = FR_CHAN;
            break_down_flags(atr, &fr, 0);
            get_user_flagrec(u, &fr2, par);
            fr.chan = (fr2.chan & BOT_AGGRESSIVE) |
                      (fr.chan & ~BOT_AGGRESSIVE);
            set_user_flagrec(u, &fr, par);
            check_dcc_chanattrs(u, par, fr.chan, fr2.chan);
            noshare = 0;
            build_flags(s, &fr, 0);
            if (!(dcc[idx].status & STAT_GETTING))
              putlog(LOG_CMDS, "*", "%s: chattr %s %s %s",
                     dcc[idx].nick, hand, s, par);
            if ((me = module_find("irc", 0, 0))) {
              Function *func = me->funcs;

              ((void (*)(struct chanset_t *, int)) func[IRC_RECHECK_CHANNEL])(cst, 0);
            }
          } else
            putlog(LOG_CMDS, "*",
                   "Rejected flags for unshared channel %s from %s",
                   par, dcc[idx].nick);
        } else if (!private_global) {
          int pgbm = private_globals_bitmask();

          /* Don't let bot flags be altered */
          fr.match = FR_GLOBAL;
          break_down_flags(atr, &fr, 0);
          bfl = u->flags & USER_BOT;
          ofl = fr.global;
          fr.global = (fr.global &~pgbm) | (u->flags & pgbm);
          fr.global = sanity_check(fr.global |bfl);

          set_user_flagrec(u, &fr, 0);
          check_dcc_attrs(u, ofl);
          noshare = 0;
          build_flags(s, &fr, 0);
          fr.match = FR_CHAN;
          if (!(dcc[idx].status & STAT_GETTING))
            putlog(LOG_CMDS, "*", "%s: chattr %s %s", dcc[idx].nick, hand, s);
          if ((me = module_find("irc", 0, 0))) {
            Function *func = me->funcs;

            for (cst = chanset; cst; cst = cst->next)
              ((void (*)(struct chanset_t *, int)) func[IRC_RECHECK_CHANNEL])(cst, 0);
          }
        } else
          putlog(LOG_CMDS, "*", "Rejected global flags for %s from %s",
                 hand, dcc[idx].nick);
        noshare = 0;
      }
    }
  }
}

static void share_pls_chrec(int idx, char *par)
{
  char *user;
  struct chanset_t *chan;
  struct userrec *u;

  if ((dcc[idx].status & STAT_SHARE) && !private_user) {
    user = newsplit(&par);
    if ((u = get_user_by_handle(userlist, user))) {
      chan = findchan_by_dname(par);
      fr.match = (FR_CHAN | FR_BOT);
      get_user_flagrec(dcc[idx].user, &fr, par);
      if (!chan || !channel_shared(chan) || !(bot_chan(fr) || bot_global(fr)))
        putlog(LOG_CMDS, "*",
               "Rejected info for unshared channel %s from %s",
               par, dcc[idx].nick);
      else {
        noshare = 1;
        shareout_but(chan, idx, "+cr %s %s\n", user, par);
        if (!get_chanrec(u, par)) {
          add_chanrec(u, par);
          putlog(LOG_CMDS, "*", "%s: +chrec %s %s", dcc[idx].nick, user, par);
        }
        noshare = 0;
      }
    }
  }
}

static void share_mns_chrec(int idx, char *par)
{
  char *user;
  struct chanset_t *chan;
  struct userrec *u;

  if ((dcc[idx].status & STAT_SHARE) && !private_user) {
    user = newsplit(&par);
    if ((u = get_user_by_handle(userlist, user))) {
      chan = findchan_by_dname(par);
      fr.match = (FR_CHAN | FR_BOT);
      get_user_flagrec(dcc[idx].user, &fr, par);
      if (!chan || !channel_shared(chan) || !(bot_chan(fr) || bot_global(fr)))
        putlog(LOG_CMDS, "*",
               "Rejected info for unshared channel %s from %s",
               par, dcc[idx].nick);
      else {
        noshare = 1;
        del_chanrec(u, par);
        shareout_but(chan, idx, "-cr %s %s\n", user, par);
        noshare = 0;
        putlog(LOG_CMDS, "*", "%s: -chrec %s %s", dcc[idx].nick, user, par);
      }
    }
  }
}

static void share_newuser(int idx, char *par)
{
  char *nick, *host, *pass, s[100];
  struct userrec *u;

  if ((dcc[idx].status & STAT_SHARE) && !private_user) {
    nick = newsplit(&par);
    host = newsplit(&par);
    pass = newsplit(&par);

    if (!(u = get_user_by_handle(userlist, nick)) ||
        !(u->flags & USER_UNSHARED)) {
      fr.global = 0;

      fr.match = FR_GLOBAL;
      break_down_flags(par, &fr, nullptr);

      /* If user already exists, ignore command */
      shareout_but(nullptr, idx, "n %s %s %s %s\n", nick, host, pass,
                   private_global ? (fr.global &USER_BOT ? "b" : "-") : par);

      if (!u) {
        noshare = 1;
        if (strlen(nick) > HANDLEN)
          nick[HANDLEN] = 0;

        if (private_global)
          fr.global &=USER_BOT;

        else {
          /* It shouldn't be done before sending to other bots? */
          int pgbm = private_globals_bitmask();

          fr.match = FR_GLOBAL;
          fr.global &=~pgbm;
        }

        build_flags(s, &fr, 0);
        userlist = adduser(userlist, nick, host, pass, 0);

        /* Support for userdefinedflag share - drummer */
        u = get_user_by_handle(userlist, nick);
        set_user_flagrec(u, &fr, 0);
        fr.match = FR_CHAN;     /* why?? */
        noshare = 0;
        putlog(LOG_CMDS, "*", "%s: newuser %s %s", dcc[idx].nick, nick, s);
      }
    }
  }
}

static void share_killuser(int idx, char *par)
{
  struct userrec *u;

  /* If user is a share bot, ignore command */
  if ((dcc[idx].status & STAT_SHARE) && !private_user &&
      (u = get_user_by_handle(userlist, par)) &&
      !(u->flags & USER_UNSHARED) &&
      !((u->flags & USER_BOT) && (bot_flags(u) & BOT_SHARE))) {
    noshare = 1;
    if (deluser(par)) {
      shareout_but(nullptr, idx, "k %s\n", par);
      putlog(LOG_CMDS, "*", "%s: killuser %s", dcc[idx].nick, par);
    }
    noshare = 0;
  }
}

/*
 * "s nc <chan>"
 * Received when another bot adds a chan.
 * We (re)send the "s a <user> <flags> <chan>" for this specific chan if
 * this chan is known to us and <user> has <flags> for this chan
 */
static void share_newchan(int idx, char *par)
{
  struct userrec *u;
  struct chanset_t *ch;

  if ((dcc[idx].status & STAT_SHARE) && !private_user) {

    /* Do we have chan as well and do we share it? */
    if ((ch = findchan_by_dname(par)) && channel_shared(ch)) {

      /* Go over users and check if it has flags for that chan */
      for (u = userlist; u; u = u->next) {
        /* Only for shared users */
        if (!(u->flags & USER_UNSHARED)) {
          struct flag_record fr = { FR_CHAN };
          char buffer[100];

          get_user_flagrec(u, &fr, par);

          if (fr.chan) {
            /* send flags to bot requesting */
            build_flags(buffer, &fr, nullptr);
            dprintf(idx, "s a %s %s %s\n", u->handle, buffer, par);
          }
        }
      }
    }

    /* Log, don't shareout to other bots */
    putlog(LOG_CMDS, "*", "%s: newchan %s", dcc[idx].nick, par);
  }
}

static void share_pls_account(int idx, char *par)
{
  char *hand;
  struct userrec *u;

  if ((dcc[idx].status & STAT_SHARE) && !private_user) {
    hand = newsplit(&par);
    if ((u = get_user_by_handle(userlist, hand)) &&
        !(u->flags & USER_UNSHARED)) {
      shareout_but(nullptr, idx, "+a %s %s\n", hand, par);
      set_user(&USERENTRY_ACCOUNT, u, par);
      putlog(LOG_CMDS, "*", "%s: +account %s %s", dcc[idx].nick, hand, par);
    }
  }
}

static void share_pls_host(int idx, char *par)
{
  char *hand;
  struct userrec *u;

  if ((dcc[idx].status & STAT_SHARE) && !private_user) {
    hand = newsplit(&par);
    if ((u = get_user_by_handle(userlist, hand)) &&
        !(u->flags & USER_UNSHARED)) {
      shareout_but(nullptr, idx, "+h %s %s\n", hand, par);
      set_user(&USERENTRY_HOSTS, u, par);
      putlog(LOG_CMDS, "*", "%s: +host %s %s", dcc[idx].nick, hand, par);
    }
  }
}

static void share_pls_botaccount(int idx, char *par)
{
  char *hand, pass[PASSWORDLEN];
  struct userrec *u;

  if ((dcc[idx].status & STAT_SHARE) && !private_user) {
    hand = newsplit(&par);
    if (!(u = get_user_by_handle(userlist, hand)) ||
        !(u->flags & USER_UNSHARED)) {
      if (!(dcc[idx].status & STAT_GETTING))
        shareout_but(nullptr, idx, "+ba %s %s\n", hand, par);
      /* Add bot to userlist if not there */
      if (u) {
        if (!(u->flags & USER_BOT))
          return;               /* ignore */
        set_user(&USERENTRY_ACCOUNT, u, par);
      } else {
        makepass(pass);
        userlist = adduser(userlist, hand, par, pass, USER_BOT);
        explicit_bzero(pass, sizeof pass);
      }
      if (!(dcc[idx].status & STAT_GETTING))
        putlog(LOG_CMDS, "*", "%s: +account %s %s", dcc[idx].nick, hand, par);
    }
  }
}

static void share_pls_bothost(int idx, char *par)
{
  char *hand, pass[PASSWORDLEN];
  struct userrec *u;

  if ((dcc[idx].status & STAT_SHARE) && !private_user) {
    hand = newsplit(&par);
    if (!(u = get_user_by_handle(userlist, hand)) ||
        !(u->flags & USER_UNSHARED)) {
      if (!(dcc[idx].status & STAT_GETTING))
        shareout_but(nullptr, idx, "+bh %s %s\n", hand, par);
      /* Add bot to userlist if not there */
      if (u) {
        if (!(u->flags & USER_BOT))
          return;               /* ignore */
        set_user(&USERENTRY_HOSTS, u, par);
      } else {
        makepass(pass);
        userlist = adduser(userlist, hand, par, pass, USER_BOT);
        explicit_bzero(pass, sizeof pass);
      }
      if (!(dcc[idx].status & STAT_GETTING))
        putlog(LOG_CMDS, "*", "%s: +host %s %s", dcc[idx].nick, hand, par);
    }
  }
}

static void share_mns_account(int idx, char *par)
{
  char *hand;
  struct userrec *u;

  if ((dcc[idx].status & STAT_SHARE) && !private_user) {
    hand = newsplit(&par);
    if ((u = get_user_by_handle(userlist, hand)) &&
        !(u->flags & USER_UNSHARED)) {
      shareout_but(nullptr, idx, "-a %s %s\n", hand, par);
      noshare = 1;
      delaccount_by_handle(hand, par);
      noshare = 0;
      putlog(LOG_CMDS, "*", "%s: -account %s %s", dcc[idx].nick, hand, par);
    }
  }
}

static void share_mns_host(int idx, char *par)
{
  char *hand;
  struct userrec *u;

  if ((dcc[idx].status & STAT_SHARE) && !private_user) {
    hand = newsplit(&par);
    if ((u = get_user_by_handle(userlist, hand)) &&
        !(u->flags & USER_UNSHARED)) {
      shareout_but(nullptr, idx, "-h %s %s\n", hand, par);
      noshare = 1;
      delhost_by_handle(hand, par);
      noshare = 0;
      putlog(LOG_CMDS, "*", "%s: -host %s %s", dcc[idx].nick, hand, par);
    }
  }
}

static void share_change(int idx, char *par)
{
  char *key, *hand, pass[PASSWORDLEN];
  struct userrec *u;
  struct user_entry_type *uet;
  struct user_entry *e;

  if ((dcc[idx].status & STAT_SHARE) && !private_user) {
    key = newsplit(&par);
    hand = newsplit(&par);
    if (!(u = get_user_by_handle(userlist, hand)) ||
        !(u->flags & USER_UNSHARED)) {
      if (!(uet = find_entry_type(key)))
        /* If it's not a supported type, forget it */
        debug2("Ignore ch %s from %s (unknown type)", key, dcc[idx].nick);
      else {
        if (!(dcc[idx].status & STAT_GETTING))
          shareout_but(nullptr, idx, "c %s %s %s\n", key, hand, par);
        noshare = 1;
        if (!u && (uet == &USERENTRY_BOTADDR)) {
          makepass(pass);
          userlist = adduser(userlist, hand, "none", pass, USER_BOT);
          explicit_bzero(pass, sizeof pass);
          u = get_user_by_handle(userlist, hand);
        } else if (!u) {
          noshare = 0;
          return;
        }
        if (uet->got_share) {
          if (!(e = find_user_entry(uet, u))) {
            e = alloc_user_entry();

            e->type = uet;
            e->name = nullptr;
            e->u.list = nullptr;
            list_insert((&(u->entries)), e);
          }
          uet->got_share(u, e, par, idx);
          if (!e->u.list) {
            egg_list_delete((struct list_type **) &(u->entries),
                        (struct list_type *) e);
            free_user_entry(e);
          }
        }
        noshare = 0;
      }
    }
  }
}

static void share_chchinfo(int idx, char *par)
{
  char *hand, *chan;
  struct chanset_t *cst;
  struct userrec *u;

  if ((dcc[idx].status & STAT_SHARE) && !private_user) {
    hand = newsplit(&par);
    if ((u = get_user_by_handle(userlist, hand)) &&
        !(u->flags & USER_UNSHARED) && share_greet) {
      chan = newsplit(&par);
      cst = findchan_by_dname(chan);
      fr.match = (FR_CHAN | FR_BOT);
      get_user_flagrec(dcc[idx].user, &fr, chan);
      if (!cst || !channel_shared(cst) || !(bot_chan(fr) || bot_global(fr)))
        putlog(LOG_CMDS, "*",
               "Info line change from %s denied.  Channel %s not shared.",
               dcc[idx].nick, chan);
      else {
        shareout_but(cst, idx, "chchinfo %s %s %s\n", hand, chan, par);
        noshare = 1;
        set_handle_chaninfo(userlist, hand, chan, par);
        noshare = 0;
        putlog(LOG_CMDS, "*", "%s: change info %s %s", dcc[idx].nick,
               chan, hand);
      }
    }
  }
}

static void share_mns_ban(int idx, char *par)
{
  struct chanset_t *chan = nullptr;

  if (dcc[idx].status & STAT_SHARE) {
    shareout_but(nullptr, idx, "-b %s\n", par);
    putlog(LOG_CMDS, "*", "%s: cancel ban %s", dcc[idx].nick, par);
    str_unescape(par, '\\');
    noshare = 1;
    if (u_delban(nullptr, par, 1) > 0) {
      for (chan = chanset; chan; chan = chan->next)
        add_delay(chan, '-', 'b', par);
    }
    noshare = 0;
  }
}

static void share_mns_exempt(int idx, char *par)
{
  struct chanset_t *chan = nullptr;

  if (dcc[idx].status & STAT_SHARE) {
    shareout_but(nullptr, idx, "-e %s\n", par);
    putlog(LOG_CMDS, "*", "%s: cancel exempt %s", dcc[idx].nick, par);
    str_unescape(par, '\\');
    noshare = 1;
    if (u_delexempt(nullptr, par, 1) > 0) {
      for (chan = chanset; chan; chan = chan->next)
        add_delay(chan, '-', 'e', par);
    }
    noshare = 0;
  }
}

static void share_mns_invite(int idx, char *par)
{
  struct chanset_t *chan = nullptr;

  if (dcc[idx].status & STAT_SHARE) {
    shareout_but(nullptr, idx, "-inv %s\n", par);
    putlog(LOG_CMDS, "*", "%s: cancel invite %s", dcc[idx].nick, par);
    str_unescape(par, '\\');
    noshare = 1;
    if (u_delinvite(nullptr, par, 1) > 0) {
      for (chan = chanset; chan; chan = chan->next)
        add_delay(chan, '-', 'I', par);
    }
    noshare = 0;
  }
}

static void share_mns_banchan(int idx, char *par)
{
  char *chname;
  struct chanset_t *chan;

  if (dcc[idx].status & STAT_SHARE) {
    chname = newsplit(&par);
    chan = findchan_by_dname(chname);
    fr.match = (FR_CHAN | FR_BOT);
    get_user_flagrec(dcc[idx].user, &fr, chname);
    if (!chan || !channel_shared(chan) || !(bot_chan(fr) || bot_global(fr)))
      putlog(LOG_CMDS, "*",
             "Cancel channel ban %s on %s rejected - channel not shared.",
             par, chname);
    else {
      shareout_but(chan, idx, "-bc %s %s\n", chname, par);
      putlog(LOG_CMDS, "*", "%s: cancel ban %s on %s", dcc[idx].nick,
             par, chname);
      str_unescape(par, '\\');
      noshare = 1;
      if (u_delban(chan, par, 1) > 0)
        add_delay(chan, '-', 'b', par);
      noshare = 0;
    }
  }
}

static void share_mns_exemptchan(int idx, char *par)
{
  char *chname;
  struct chanset_t *chan;

  if (dcc[idx].status & STAT_SHARE) {
    chname = newsplit(&par);
    chan = findchan_by_dname(chname);
    fr.match = (FR_CHAN | FR_BOT);
    get_user_flagrec(dcc[idx].user, &fr, chname);
    if (!chan || !channel_shared(chan) || !(bot_chan(fr) || bot_global(fr)))
      putlog(LOG_CMDS, "*",
             "Cancel channel exempt %s on %s rejected - channel not shared.",
             par, chname);
    else {
      shareout_but(chan, idx, "-ec %s %s\n", chname, par);
      putlog(LOG_CMDS, "*", "%s: cancel exempt %s on %s", dcc[idx].nick,
             par, chname);
      str_unescape(par, '\\');
      noshare = 1;
      if (u_delexempt(chan, par, 1) > 0)
        add_delay(chan, '-', 'e', par);
      noshare = 0;
    }
  }
}

static void share_mns_invitechan(int idx, char *par)
{
  char *chname;
  struct chanset_t *chan;

  if (dcc[idx].status & STAT_SHARE) {
    chname = newsplit(&par);
    chan = findchan_by_dname(chname);
    fr.match = (FR_CHAN | FR_BOT);
    get_user_flagrec(dcc[idx].user, &fr, chname);
    if (!chan || !channel_shared(chan) || !(bot_chan(fr) || bot_global(fr)))
      putlog(LOG_CMDS, "*",
             "Cancel channel invite %s on %s rejected - channel not shared.",
             par, chname);
    else {
      shareout_but(chan, idx, "-invc %s %s\n", chname, par);
      putlog(LOG_CMDS, "*", "%s: cancel invite %s on %s", dcc[idx].nick,
             par, chname);
      str_unescape(par, '\\');
      noshare = 1;
      if (u_delinvite(chan, par, 1) > 0)
        add_delay(chan, '-', 'I', par);
      noshare = 0;
    }
  }
}

static void share_mns_ignore(int idx, char *par)
{
  if (dcc[idx].status & STAT_SHARE) {
    shareout_but(nullptr, idx, "-i %s\n", par);
    putlog(LOG_CMDS, "*", "%s: cancel ignore %s", dcc[idx].nick, par);
    str_unescape(par, '\\');
    noshare = 1;
    delignore(par);
    noshare = 0;
  }
}

static void share_pls_ban(int idx, char *par)
{
  time_t expire_time;
  char *ban, *tm, *from;
  int flags = 0;
  module_entry *me;
  struct chanset_t *chan = nullptr;

  if (dcc[idx].status & STAT_SHARE) {
    shareout_but(nullptr, idx, "+b %s\n", par);
    noshare = 1;
    ban = newsplit(&par);
    str_unescape(ban, '\\');
    tm = newsplit(&par);
    from = newsplit(&par);
    if (strchr(from, 's'))
      flags |= MASKREC_STICKY;
    if (strchr(from, 'p'))
      flags |= MASKREC_PERM;
    from = newsplit(&par);
    expire_time = (time_t) egg_atoi(tm);
    if (expire_time != 0L)
      expire_time += now;
    u_addban(nullptr, ban, from, par, expire_time, flags);
    putlog(LOG_CMDS, "*", "%s: global ban %s (%s:%s)", dcc[idx].nick, ban,
           from, par);
    /* check ban against users in chans */
    if ((me = module_find("irc", 0, 0)))
      for (chan = chanset; chan != nullptr; chan = chan->next) {
        fr.match = (FR_CHAN | FR_BOT);
        get_user_flagrec(dcc[idx].user, &fr, chan->dname);
        if (channel_shared(chan) && (bot_chan(fr) || bot_global(fr)))
          ((void (*)(struct chanset_t *, char *, int)) me->funcs[IRC_CHECK_THIS_BAN])(chan, ban, flags & MASKREC_STICKY);
      }
    noshare = 0;
  }
}

static void share_pls_banchan(int idx, char *par)
{
  time_t expire_time;
  int flags = 0;
  struct chanset_t *chan;
  char *ban, *tm, *chname, *from;
  module_entry *me;

  if (dcc[idx].status & STAT_SHARE) {
    ban = newsplit(&par);
    tm = newsplit(&par);
    chname = newsplit(&par);
    chan = findchan_by_dname(chname);
    fr.match = (FR_CHAN | FR_BOT);
    get_user_flagrec(dcc[idx].user, &fr, chname);
    if (!chan || !channel_shared(chan) || !(bot_chan(fr) || bot_global(fr)))
      putlog(LOG_CMDS, "*",
             "Channel ban %s on %s rejected - channel not shared.",
             ban, chname);
    else {
      shareout_but(chan, idx, "+bc %s %s %s %s\n", ban, tm, chname, par);
      str_unescape(ban, '\\');
      from = newsplit(&par);
      if (strchr(from, 's'))
        flags |= MASKREC_STICKY;
      if (strchr(from, 'p'))
        flags |= MASKREC_PERM;
      from = newsplit(&par);
      putlog(LOG_CMDS, "*", "%s: ban %s on %s (%s:%s)", dcc[idx].nick,
             ban, chname, from, par);
      noshare = 1;
      expire_time = (time_t) egg_atoi(tm);
      if (expire_time != 0L)
        expire_time += now;
      u_addban(chan, ban, from, par, expire_time, flags);
      /* check ban against users in chan */
      if ((me = module_find("irc", 0, 0)))
        ((void (*)(struct chanset_t *, char *, int)) me->funcs[IRC_CHECK_THIS_BAN])(chan, ban, flags & MASKREC_STICKY);
      noshare = 0;
    }
  }
}

/* Same as share_pls_ban, only for exempts.
 */
static void share_pls_exempt(int idx, char *par)
{
  time_t expire_time;
  char *exempt, *tm, *from;
  int flags = 0;

  if (dcc[idx].status & STAT_SHARE) {
    shareout_but(nullptr, idx, "+e %s\n", par);
    noshare = 1;
    exempt = newsplit(&par);
    str_unescape(exempt, '\\');
    tm = newsplit(&par);
    from = newsplit(&par);
    if (strchr(from, 's'))
      flags |= MASKREC_STICKY;
    if (strchr(from, 'p'))
      flags |= MASKREC_PERM;
    from = newsplit(&par);
    expire_time = (time_t) egg_atoi(tm);
    if (expire_time != 0L)
      expire_time += now;
    u_addexempt(nullptr, exempt, from, par, expire_time, flags);
    putlog(LOG_CMDS, "*", "%s: global exempt %s (%s:%s)", dcc[idx].nick, exempt,
           from, par);
    noshare = 0;
  }
}

/* Same as share_pls_banchan, only for exempts.
 */
static void share_pls_exemptchan(int idx, char *par)
{
  time_t expire_time;
  int flags = 0;
  struct chanset_t *chan;
  char *exempt, *tm, *chname, *from;

  if (dcc[idx].status & STAT_SHARE) {
    exempt = newsplit(&par);
    tm = newsplit(&par);
    chname = newsplit(&par);
    chan = findchan_by_dname(chname);
    fr.match = (FR_CHAN | FR_BOT);
    get_user_flagrec(dcc[idx].user, &fr, chname);
    if (!chan || !channel_shared(chan) || !(bot_chan(fr) || bot_global(fr)))
      putlog(LOG_CMDS, "*",
             "Channel exempt %s on %s rejected - channel not shared.",
             exempt, chname);
    else {
      shareout_but(chan, idx, "+ec %s %s %s %s\n", exempt, tm, chname, par);
      str_unescape(exempt, '\\');
      from = newsplit(&par);
      if (strchr(from, 's'))
        flags |= MASKREC_STICKY;
      if (strchr(from, 'p'))
        flags |= MASKREC_PERM;
      from = newsplit(&par);
      putlog(LOG_CMDS, "*", "%s: exempt %s on %s (%s:%s)", dcc[idx].nick,
             exempt, chname, from, par);
      noshare = 1;
      expire_time = (time_t) egg_atoi(tm);
      if (expire_time != 0L)
        expire_time += now;
      u_addexempt(chan, exempt, from, par, expire_time, flags);
      noshare = 0;
    }
  }
}

/* Same as share_pls_ban, only for invites.
 */
static void share_pls_invite(int idx, char *par)
{
  time_t expire_time;
  char *invite, *tm, *from;
  int flags = 0;

  if (dcc[idx].status & STAT_SHARE) {
    shareout_but(nullptr, idx, "+inv %s\n", par);
    noshare = 1;
    invite = newsplit(&par);
    str_unescape(invite, '\\');
    tm = newsplit(&par);
    from = newsplit(&par);
    if (strchr(from, 's'))
      flags |= MASKREC_STICKY;
    if (strchr(from, 'p'))
      flags |= MASKREC_PERM;
    from = newsplit(&par);
    expire_time = (time_t) egg_atoi(tm);
    if (expire_time != 0L)
      expire_time += now;
    u_addinvite(nullptr, invite, from, par, expire_time, flags);
    putlog(LOG_CMDS, "*", "%s: global invite %s (%s:%s)", dcc[idx].nick,
           invite, from, par);
    noshare = 0;
  }
}

/* Same as share_pls_banchan, only for invites.
 */
static void share_pls_invitechan(int idx, char *par)
{
  time_t expire_time;
  int flags = 0;
  struct chanset_t *chan;
  char *invite, *tm, *chname, *from;

  if (dcc[idx].status & STAT_SHARE) {
    invite = newsplit(&par);
    tm = newsplit(&par);
    chname = newsplit(&par);
    chan = findchan_by_dname(chname);
    fr.match = (FR_CHAN | FR_BOT);
    get_user_flagrec(dcc[idx].user, &fr, chname);
    if (!chan || !channel_shared(chan) || !(bot_chan(fr) || bot_global(fr)))
      putlog(LOG_CMDS, "*",
             "Channel invite %s on %s rejected - channel not shared.",
             invite, chname);
    else {
      shareout_but(chan, idx, "+invc %s %s %s %s\n", invite, tm, chname, par);
      str_unescape(invite, '\\');
      from = newsplit(&par);
      if (strchr(from, 's'))
        flags |= MASKREC_STICKY;
      if (strchr(from, 'p'))
        flags |= MASKREC_PERM;
      from = newsplit(&par);
      putlog(LOG_CMDS, "*", "%s: invite %s on %s (%s:%s)", dcc[idx].nick,
             invite, chname, from, par);
      noshare = 1;
      expire_time = (time_t) egg_atoi(tm);
      if (expire_time != 0L)
        expire_time += now;
      u_addinvite(chan, invite, from, par, expire_time, flags);
      noshare = 0;
    }
  }
}

/* +i <host> +<seconds-left> <from> <note>
 */
static void share_pls_ignore(int idx, char *par)
{
  time_t expire_time;
  char *ign, *from, *ts;

  if (dcc[idx].status & STAT_SHARE) {
    shareout_but(nullptr, idx, "+i %s\n", par);
    noshare = 1;
    ign = newsplit(&par);
    str_unescape(ign, '\\');
    ts = newsplit(&par);
    if (!egg_atoi(ts))
      expire_time = 0L;
    else
      expire_time = now + egg_atoi(ts);
    from = newsplit(&par);
    if (strchr(from, 'p'))
      expire_time = 0;
    from = newsplit(&par);
    if (strlen(from) > HANDLEN + 1)
      from[HANDLEN + 1] = 0;
    par[65] = 0;
    putlog(LOG_CMDS, "*", "%s: ignore %s (%s: %s)",
           dcc[idx].nick, ign, from, par);
    addignore(ign, from, par, expire_time);
    noshare = 0;
  }
}

static void share_ufno(int idx, char *par)
{
  putlog(LOG_BOTS, "*", "User file rejected by %s: %s", dcc[idx].nick, par);
  dcc[idx].status &= ~STAT_OFFERED;
  if (!(dcc[idx].status & STAT_GETTING))
    dcc[idx].status &= ~(STAT_SHARE | STAT_AGGRESSIVE);
}

static void share_ufyes(int idx, char *par)
{
  if (dcc[idx].status & STAT_OFFERED) {
    dcc[idx].status &= ~STAT_OFFERED;
    dcc[idx].status |= STAT_SHARE;
    dcc[idx].status |= STAT_SENDING;
    uf_features_parse(idx, par);
    start_sending_users(idx);
    putlog(LOG_BOTS, "*", "Sending user file send request to %s",
           dcc[idx].nick);
  }
}

static void share_userfileq(int idx, char *par)
{
  int ok = 1, i, bfl = bot_flags(dcc[idx].user);

  flush_tbuf(dcc[idx].nick);
  if (bfl & (BOT_AGGRESSIVE|BOT_SHPERMS))
    dprintf(idx, "s un I have you marked for Aggressive sharing.\n");
  else if (!(bfl & BOT_PASSIVE))
    dprintf(idx, "s un You are not marked for sharing with me.\n");
  else if (min_share > dcc[idx].u.bot->numver)
    dprintf(idx,
            "s un Your version is not high enough, need v%d.%d.%d\n",
            (min_share / 1000000), (min_share / 10000) % 100,
            (min_share / 100) % 100);
  else {
    for (i = 0; i < dcc_total; i++)
      if (dcc[i].type->flags & DCT_BOT) {
        if ((dcc[i].status & STAT_SHARE) &&
            (dcc[i].status & STAT_AGGRESSIVE) && (i != idx)) {
          ok = 0;
          break;
        }
      }
    if (!ok)
      dprintf(idx, "s un Already sharing.\n");
    else {
      if (dcc[idx].u.bot->numver >= min_uffeature)
        dprintf(idx, "s uy %s\n", uf_features_dump(idx));
      else
        dprintf(idx, "s uy\n");
      /* Set stat-getting to astatic void race condition (robey 23jun1996) */
      dcc[idx].status |= STAT_SHARE | STAT_GETTING | STAT_AGGRESSIVE;
      putlog(LOG_BOTS, "*", "Downloading user file from %s", dcc[idx].nick);
    }
  }
}

/* us <ip> <port> <length>
 */
static void share_ufsend(int idx, char *par)
{
  char *port;
  int sock;
  FILE *f;
  op_strbuf_t _b = {};
  op_strbuf_init(&_b);

  op_strbuf_appendf(&_b, ".share.%s.%" PRId64 ".users", botnetnick,
                   (int64_t) now);
  if (!(b_status(idx) & STAT_SHARE)) {
    dprintf(idx, "s e You didn't ask; you just started sending.\n");
    dprintf(idx, "s e Ask before sending the userfile.\n");
    zapfbot(idx);
  } else if (dcc_total == max_dcc) {
    putlog(LOG_MISC, "*", "NO MORE DCC CONNECTIONS -- can't grab userfile");
    dprintf(idx, "s e I can't open a DCC to you; I'm full.\n");
    zapfbot(idx);
  } else if (!(f = tmpfile())) {
    debug1("share: share_ufsend(): tmpfile(): error: %s", strerror(errno));
    putlog(LOG_MISC, "*", "CAN'T WRITE TEMPORARY USERFILE DOWNLOAD FILE!");
    zapfbot(idx);
  } else {
    /* Ignore longip and use botaddr, arg kept for backward compat for pre 1.8.3 */
    newsplit(&par);
    port = newsplit(&par);
    int i = new_dcc(&DCC_FORK_SEND, sizeof(struct xfer_info));
    /* Use same addr we successfully linked to and change port */
    memcpy(&dcc[i].sockname, &dcc[idx].sockname, sizeof dcc[i].sockname);
    dcc[i].port = egg_atoi(port);
    setsnport(dcc[i].sockname, dcc[i].port);
    /* Don't buffer this -> mark binary. */
    sock = getsock(dcc[i].sockname.family, SOCK_BINARY);
#ifdef TLS
    if (sock < 0 || (open_telnet_raw(sock, &dcc[i].sockname) < 0) ||
        (*port == '+' && ssl_handshake(sock, TLS_CONNECT, tls_vfybots,
        LOG_MISC, dcc[i].host, nullptr))) {
#else
    if (sock < 0 || open_telnet_raw(sock, &dcc[i].sockname) < 0) {
#endif
      lostdcc(i);
      killsock(sock);
      putlog(LOG_BOTS, "*", "Asynchronous connection failed!");
      dprintf(idx, "s e Can't connect to you!\n");
      zapfbot(idx);
      fclose(f);
    } else {
      op_strlcpy(dcc[i].nick, "*users", sizeof(dcc[i].nick));
      dcc[i].u.xfer->filename = op_strbuf_steal(&_b);
      dcc[i].u.xfer->origname = dcc[i].u.xfer->filename;
      dcc[i].u.xfer->length = egg_atoi(par);
      dcc[i].u.xfer->f = f;
      dcc[i].sock = sock;
#ifdef TLS
      if (*port == '+')
        dcc[i].ssl = 1;
#endif
      op_strlcpy(dcc[i].host, dcc[idx].nick, sizeof(dcc[i].host));

      dcc[idx].status |= STAT_GETTING;
    }
  }
  op_strbuf_free(&_b);
}

static void share_resyncq(int idx, char *par)
{
  if (!allow_resync)
    dprintf(idx, "s rn Not permitting resync.\n");
  else {
    int bfl = bot_flags(dcc[idx].user);

    if (!(bfl & BOT_SHARE))
      dprintf(idx, "s rn You are not marked for sharing with me.\n");
    else if (can_resync(dcc[idx].nick)) {
      dprintf(idx, "s r!\n");
      dump_resync(idx);
      dcc[idx].status &= ~STAT_OFFERED;
      dcc[idx].status |= STAT_SHARE;
      putlog(LOG_BOTS, "*", "Resync'd user file with %s", dcc[idx].nick);
      updatebot(-1, dcc[idx].nick, '+', 0);
    } else
      dprintf(idx, "s rn No resync buffer.\n");
  }
}

static void share_resync(int idx, char *par)
{
  if ((dcc[idx].status & STAT_OFFERED) && can_resync(dcc[idx].nick)) {
    dump_resync(idx);
    dcc[idx].status &= ~STAT_OFFERED;
    dcc[idx].status |= STAT_SHARE;
    updatebot(-1, dcc[idx].nick, '+', 0);
    putlog(LOG_BOTS, "*", "Resync'd user file with %s", dcc[idx].nick);
  }
}

static void share_resync_no(int idx, char *par)
{
  putlog(LOG_BOTS, "*", "Resync refused by %s: %s", dcc[idx].nick, par);
  flush_tbuf(dcc[idx].nick);
  dprintf(idx, "s u?\n");
}

static void share_version(int idx, char *par)
{
  /* Cleanup any share flags */
  dcc[idx].status &= ~(STAT_SHARE | STAT_GETTING | STAT_SENDING |
                       STAT_OFFERED | STAT_AGGRESSIVE);
  dcc[idx].u.bot->uff_flags = 0;
  if ((dcc[idx].u.bot->numver >= min_share) &&
      (bot_flags(dcc[idx].user) & (BOT_AGGRESSIVE|BOT_SHPERMS))) {
    if (can_resync(dcc[idx].nick))
      dprintf(idx, "s r?\n");
    else
      dprintf(idx, "s u?\n");
    dcc[idx].status |= STAT_OFFERED;
  }
}

static void hook_read_userfile(void)
{
  if (!noshare) {
    for (int i = 0; i < dcc_total; i++)
      if ((dcc[i].type->flags & DCT_BOT) && (dcc[i].status & STAT_SHARE) &&
          !(dcc[i].status & STAT_AGGRESSIVE)) {
        /* Cancel any existing transfers */
        if (dcc[i].status & STAT_SENDING)
          cancel_user_xfer(-i, 0);
        dprintf(i, "s u?\n");
        dcc[i].status |= STAT_OFFERED;
      }
  }
}

static void share_endstartup(int idx, char *par)
{
  dcc[idx].status &= ~STAT_GETTING;
  /* Send to any other sharebots */
  hook_read_userfile();
}

static void share_end(int idx, char *par)
{
  putlog(LOG_BOTS, "*", "Ending sharing with %s (%s).", dcc[idx].nick, par);
  cancel_user_xfer(-idx, 0);
  dcc[idx].status &= ~(STAT_SHARE | STAT_GETTING | STAT_SENDING |
                       STAT_OFFERED | STAT_AGGRESSIVE);
  dcc[idx].u.bot->uff_flags = 0;
}

static void share_feats(int idx, char *par)
{
  uf_features_check(idx, par);
}


/* Note: these MUST be sorted.
 * Flags (second arg) are compared with OR,
 * here in particular this means +p can execute all
 */
static botscmd_t C_share[] = {
  {"!",        "",  (IntFunc) share_endstartup},
  {"+a",       "psu", (IntFunc) share_pls_account},
  {"+b",       "psb", (IntFunc) share_pls_ban},
  {"+ba",      "psb", (IntFunc) share_pls_botaccount},
  {"+bc",      "psb", (IntFunc) share_pls_banchan},
  {"+bh",      "psu", (IntFunc) share_pls_bothost},
  {"+cr",      "psc", (IntFunc) share_pls_chrec},
  {"+e",       "pse", (IntFunc) share_pls_exempt},
  {"+ec",      "pse", (IntFunc) share_pls_exemptchan},
  {"+h",       "psu", (IntFunc) share_pls_host},
  {"+i",       "psn", (IntFunc) share_pls_ignore},
  {"+inv",     "psj", (IntFunc) share_pls_invite},
  {"+invc",    "psj", (IntFunc) share_pls_invitechan},
  {"-a",       "psu", (IntFunc) share_mns_account},
  {"-b",       "psb", (IntFunc) share_mns_ban},
  {"-bc",      "psb", (IntFunc) share_mns_banchan},
  {"-cr",      "psc", (IntFunc) share_mns_chrec},
  {"-e",       "pse", (IntFunc) share_mns_exempt},
  {"-ec",      "pse", (IntFunc) share_mns_exemptchan},
  {"-h",       "psu", (IntFunc) share_mns_host},
  {"-i",       "psn", (IntFunc) share_mns_ignore},
  {"-inv",     "psj", (IntFunc) share_mns_invite},
  {"-invc",    "psj", (IntFunc) share_mns_invitechan},
  {"a",        "psu", (IntFunc) share_chattr},
  {"c",        "psu", (IntFunc) share_change},
  {"chchinfo", "psu", (IntFunc) share_chchinfo},
  {"e",        "",  (IntFunc) share_end},
  {"feats",    "",  (IntFunc) share_feats},
  {"h",        "psu", (IntFunc) share_chhand},
  {"k",        "psu", (IntFunc) share_killuser},
  {"n",        "psu", (IntFunc) share_newuser},
  {"nc",       "psc", (IntFunc) share_newchan},
  {"r!",       "",  (IntFunc) share_resync},
  {"r?",       "",  (IntFunc) share_resyncq},
  {"rn",       "",  (IntFunc) share_resync_no},
  {"s",        "psb", (IntFunc) share_stick_ban},
  {"se",       "pse", (IntFunc) share_stick_exempt},
  {"sInv",     "psj", (IntFunc) share_stick_invite},
  {"u?",       "",  (IntFunc) share_userfileq},
  {"un",       "",  (IntFunc) share_ufno},
  {"us",       "",  (IntFunc) share_ufsend},
  {"uy",       "",  (IntFunc) share_ufyes},
  {"v",        "",  (IntFunc) share_version},
  {nullptr,       nullptr, nullptr}
};


static void sharein_mod(int idx, char *msg)
{
  char *code;
  int f, i;

  /* Guard against oversized share messages.  In line-mode the botnet layer
   * has already buffered the full line, so we cannot disconnect based on a
   * framing violation here.  Drop the line and log a warning instead. */
  if (msg && strlen(msg) > MAX_SHARE_FRAME) {
    putlog(LOG_BOTS, "*",
           "Share: dropping oversized message from %s (len=%zu, max=%d)",
           dcc[idx].nick, strlen(msg), MAX_SHARE_FRAME);
    return;
  }

  code = newsplit(&msg);
  for (f = 0, i = 0; C_share[i].name && !f; i++) {
    int y = op_strcasecmp(code, C_share[i].name);

    if (!y) {
      /* Found a match */
      struct flag_record fr = { FR_BOT };
      struct flag_record req = { FR_BOT | FR_OR };

      break_down_flags(C_share[i].flags, &req, nullptr);
      get_user_flagrec(dcc[idx].user, &fr, nullptr);
      if (flagrec_eq(&req, &fr)) {
        ((void (*)(int, char *)) C_share[i].func)(idx, msg);
      } else {
        putlog(LOG_DEBUG, "*", "Userfile modification from %s rejected: incorrect bot flag permissions for \"%s %s\"", dcc[idx].nick, code, msg);
      }
    }
    if (y <= 0)
      f = 1;
  }
}

ATTRIBUTE_FORMAT(printf,2,3)
static void shareout_mod(struct chanset_t *chan, const char *format, ...)
{
  va_list va;

  if (!chan || channel_shared(chan)) {
    va_start(va, format);

    op_strbuf_t _s = {};
    op_strbuf_init(&_s);
    op_strbuf_append_cstr(&_s, "s ");
    op_strbuf_vappendf(&_s, format, va);
    if (op_strbuf_len(&_s) > 511)
      op_strbuf_truncate(&_s, 511);
    for (int i = 0; i < dcc_total; i++)
      if ((dcc[i].type->flags & DCT_BOT) &&
          (dcc[i].status & STAT_SHARE) &&
          !(dcc[i].status & (STAT_GETTING | STAT_SENDING))) {
        if (chan) {
          fr.match = (FR_CHAN | FR_BOT);
          get_user_flagrec(dcc[i].user, &fr, chan->dname);
        }
        if (!chan || bot_chan(fr) || bot_global(fr)) {
          putlog(LOG_BOTSHROUT, "*", "{b->%s} %s", dcc[i].nick,
                 op_strbuf_str(&_s) + 2);
          tputs(dcc[i].sock, op_strbuf_str(&_s),
                (unsigned int)op_strbuf_len(&_s));
        }
      }
    q_resync(op_strbuf_str(&_s), chan);
    op_strbuf_free(&_s);
    va_end(va);
  }
}

ATTRIBUTE_FORMAT(printf,3,4)
static void shareout_but(struct chanset_t *chan, int x, const char *format, ...)
{
  va_list va;

  va_start(va, format);

  op_strbuf_t _s = {};
  op_strbuf_init(&_s);
  op_strbuf_append_cstr(&_s, "s ");
  op_strbuf_vappendf(&_s, format, va);
  if (op_strbuf_len(&_s) > 511)
    op_strbuf_truncate(&_s, 511);
  for (int i = 0; i < dcc_total; i++)
    if ((dcc[i].type->flags & DCT_BOT) && (i != x) &&
        (dcc[i].status & STAT_SHARE) &&
        (!(dcc[i].status & STAT_GETTING)) &&
        (!(dcc[i].status & STAT_SENDING))) {
      if (chan) {
        fr.match = (FR_CHAN | FR_BOT);
        get_user_flagrec(dcc[i].user, &fr, chan->dname);
      }
      if (!chan || bot_chan(fr) || bot_global(fr)) {
        putlog(LOG_BOTSHROUT, "*", "{b->%s} %s", dcc[i].nick,
               op_strbuf_str(&_s) + 2);
        tputs(dcc[i].sock, op_strbuf_str(&_s),
              (unsigned int)op_strbuf_len(&_s));
      }
    }
  q_resync(op_strbuf_str(&_s), chan);
  op_strbuf_free(&_s);
  va_end(va);
}


/*
 *    Resync buffers
 */

/* Free a tbuf entry at index i and remove it from tbuf_vec. */
static void tbuf_free(size_t i)
{
  tandbuf *t = (tandbuf *)op_vec_get(&tbuf_vec, i);
  while (!op_deque_empty(&t->q)) {
    struct share_msgq *qe = op_deque_pop_front(&t->q);
    op_free(qe->msg);
    op_bh_free(share_msgq_bh, qe);
  }
  op_deque_fini(&t->q);
  op_bh_free(tandbuf_bh, t);
  op_vec_remove(&tbuf_vec, i);
}

/* Create a tandem buffer for 'bot'.
 */
static void new_tbuf(char *bot)
{
  if (!tandbuf_bh) tandbuf_bh = op_bh_create(sizeof(tandbuf), 8, "tandbuf");
  tandbuf *n = (tandbuf *)op_bh_alloc(tandbuf_bh);
  op_strlcpy(n->bot, bot, sizeof n->bot);
  op_deque_init(&n->q, 8);
  n->timer = now;
  op_vec_push(&tbuf_vec, n);
  putlog(LOG_BOTS, "*", "Creating resync buffer for %s", bot);
}

/* Flush a certain bot's tbuf.
 */
static int flush_tbuf(char *bot)
{
  for (size_t i = tbuf_vec.size; i-- > 0; ) {
    tandbuf *t = (tandbuf *)op_vec_get(&tbuf_vec, i);
    if (!op_strcasecmp(t->bot, bot)) {
      tbuf_free(i);
      return 1;
    }
  }
  return 0;
}

/* Flush all tbufs older than 15 minutes.
 */
static void check_expired_tbufs(void)
{
  for (size_t i = tbuf_vec.size; i-- > 0; ) {
    tandbuf *t = (tandbuf *)op_vec_get(&tbuf_vec, i);
    if ((now - t->timer) > resync_time) {
      putlog(LOG_BOTS, "*", "Flushing resync buffer for clonebot %s.", t->bot);
      tbuf_free(i);
    }
  }
  /* Resend userfile requests */
  for (int i = 0; i < dcc_total; i++)
    if (dcc[i].type->flags & DCT_BOT) {
      if (dcc[i].status & STAT_OFFERED) {
        if ((now - dcc[i].timeval > 120) && (dcc[i].user &&
            (bot_flags(dcc[i].user) & (BOT_AGGRESSIVE|BOT_SHPERMS))))
          dprintf(i, "s u?\n");
          /* ^ send it again in case they missed it */
        /* If it's a share bot that hasnt been sharing, ask again */
      } else if (!(dcc[i].status & STAT_SHARE)) {
        /* Patched from original source by giusc@gbss.it <20040207> */
        if (dcc[i].user && (bot_flags(dcc[i].user) & (BOT_AGGRESSIVE|BOT_SHPERMS)))  {
          dprintf(i, "s u?\n");
          dcc[i].status |= STAT_OFFERED;
        }
      }
    }
}

/* Push a share message onto a bot's tandbuf queue.
 * Silently drops the message when the queue reaches the 1000-entry limit. */
static void q_push_msg(op_deque_t *q, struct chanset_t *chan, const char *s)
{
  struct share_msgq *qe;

  if (op_deque_size(q) >= 1000)
    return;
  qe = op_bh_alloc(share_msgq_bh);
  qe->chan = chan;
  qe->msg = op_strdup(s);
  op_deque_push_back(q, qe);
}

/* Add stuff to a specific bot's tbuf.
 */
static void q_tbuf(char *bot, const char *s, struct chanset_t *chan)
{
  for (size_t i = 0; i < tbuf_vec.size; i++) {
    tandbuf *t = (tandbuf *)op_vec_get(&tbuf_vec, i);
    if (!op_strcasecmp(t->bot, bot)) {
      if (chan) {
        fr.match = (FR_CHAN | FR_BOT);
        get_user_flagrec(get_user_by_handle(userlist, bot), &fr, chan->dname);
      }
      if (!chan || bot_chan(fr) || bot_global(fr))
        q_push_msg(&t->q, chan, s);
      break;
    }
  }
}

/* Add stuff to the resync buffers.
 */
static void q_resync(const char *s, struct chanset_t *chan)
{
  for (size_t i = 0; i < tbuf_vec.size; i++) {
    tandbuf *t = (tandbuf *)op_vec_get(&tbuf_vec, i);
    if (chan) {
      fr.match = (FR_CHAN | FR_BOT);
      get_user_flagrec(get_user_by_handle(userlist, t->bot), &fr, chan->dname);
    }
    if (!chan || bot_chan(fr) || bot_global(fr))
      q_push_msg(&t->q, chan, s);
  }
}

/* Is bot in resync list?
 */
static int can_resync(char *bot)
{
  for (size_t i = 0; i < tbuf_vec.size; i++) {
    tandbuf *t = (tandbuf *)op_vec_get(&tbuf_vec, i);
    if (!op_strcasecmp(bot, t->bot))
      return 1;
  }
  return 0;
}

/* Dump the resync buffer for a bot.
 */
static void dump_resync(int idx)
{
  for (size_t i = 0; i < tbuf_vec.size; i++) {
    tandbuf *t = (tandbuf *)op_vec_get(&tbuf_vec, i);
    if (!op_strcasecmp(dcc[idx].nick, t->bot)) {
      size_t _n = op_deque_size(&t->q);
      for (size_t _i = 0; _i < _n; _i++) {
        struct share_msgq *qe = op_deque_at(&t->q, _i);
        dprintf(idx, "%s", qe->msg);
      }
      flush_tbuf(dcc[idx].nick);
      break;
    }
  }
}

/* Give status report on tbufs.
 */
static void status_tbufs(int idx)
{
  op_strbuf_t s = {};
  op_strbuf_init(&s);
  int first = 1;

  op_strbuf_init(&s);
  for (size_t i = 0; i < tbuf_vec.size; i++) {
    tandbuf *t = (tandbuf *)op_vec_get(&tbuf_vec, i);
    if (!first)
      op_strbuf_append_cstr(&s, ", ");
    op_strbuf_appendf(&s, "%s (%zu)", t->bot, op_deque_size(&t->q));
    first = 0;
  }
  if (!first)
    dprintf(idx, "    Pending sharebot buffers: %s\n", op_strbuf_str(&s));
  op_strbuf_free(&s);
}

static int write_tmp_userfile(char *fn, struct userrec *bu, int idx)
{
  FILE *f;
  struct userrec *u;
  int ok = 0;

  if ((f = fopen(fn, "wb"))) {
    chmod(fn, 0600);            /* make it -rw------- */
    fprintf(f, "#4v: %s -- %s -- transmit\n", ver, botnetnick);
    ok = 1;
    for (u = bu; u && ok; u = u->next)
      if (!write_user(u, f, idx))
        ok = 0;
    if (!write_ignores(f, idx))
      ok = 0;
    if (!write_bans(f, idx))
      ok = 0;
    /* Only share with bots which support exempts and invites.
     *
     * If UFF is supported, we also check the UFF flags before sharing. If
     * UFF isn't supported, but +I/+e is supported, we just share.
     */
    if (dcc[idx].u.bot->numver >= min_exemptinvite) {
      if ((dcc[idx].u.bot->uff_flags & UFF_EXEMPT) ||
          (dcc[idx].u.bot->numver < min_uffeature)) {
        if (!write_exempts(f, idx))
          ok = 0;
      }
      if ((dcc[idx].u.bot->uff_flags & UFF_INVITE) ||
          (dcc[idx].u.bot->numver < min_uffeature)) {
        if (!write_invites(f, idx))
          ok = 0;
      }
    } else
      putlog(LOG_BOTS, "*", "%s is too old: not sharing exempts and invites.",
             dcc[idx].nick);
    fclose(f);
  }
  if (!ok)
    putlog(LOG_MISC, "*", "%s", USERF_ERRWRITE2);
  return ok;
}


/* Create a copy of the entire userlist (for sending user lists to clone
 * bots) -- userlist is reversed in the process, which is OK because the
 * receiving bot reverses the list AGAIN when saving.
 *
 * t = 0:   copy everything BUT tandem-bots
 * t = 1:   copy only tandem-bots
 * t = 2;   copy all entries
 */
static struct userrec *dup_userlist(int t)
{
  struct userrec *u, *u1, *retu, *nu;
  struct chanuserrec *ch;
  struct user_entry *ue;
  char *p;

  nu = retu = nullptr;
  noshare = 1;
  for (u = userlist; u; u = u->next)
    /* Only copying non-bot entries? */
    if (((t == 0) && !(u->flags & (USER_BOT | USER_UNSHARED))) ||
        ((t == 1) && (u->flags & (USER_BOT | USER_UNSHARED))) || (t == 2)) {
      p = get_user(&USERENTRY_PASS, u);
      u1 = adduser(nullptr, u->handle, 0, p, u->flags);
      p = get_user(&USERENTRY_PASS2, u);
      if (p)
        set_user(&USERENTRY_PASS2, u1, p);
      u1->flags_udef = u->flags_udef;
      if (!nu)
        nu = retu = u1;
      else {
        nu->next = u1;
        nu = nu->next;
      }
      for (ch = u->chanrec; ch; ch = ch->next) {
        struct chanuserrec *z = add_chanrec(nu, ch->channel);

        if (z) {
          z->flags = ch->flags;
          z->flags_udef = ch->flags_udef;
          z->laston = ch->laston;
          set_handle_chaninfo(nu, nu->handle, ch->channel, ch->info);
        }
      }
      for (ue = u->entries; ue; ue = ue->next) {
        if (ue->name) {
          struct list_type *lt;
          struct user_entry *nue;

          nue = alloc_user_entry();
          nue->name = op_strdup(ue->name);
          nue->type = nullptr;
          nue->u.list = nullptr;
          list_insert((&nu->entries), nue);
          for (lt = ue->u.list; lt; lt = lt->next) {
            struct list_type *list;

            list = alloc_list_type();
            list->next = nullptr;
            list->extra = op_strdup(lt->extra);
            egg_list_append((&nue->u.list), list);
          }
        } else {
          if (ue->type->dup_user && (t || ue->type->got_share))
            ue->type->dup_user(nu, u, ue);
        }
      }
    }
  noshare = 0;
  return retu;
}

/* Erase old user list, switch to new one.
 */
static void finish_share(int idx)
{
  struct userrec *u = nullptr, *ou = nullptr;
  struct chanset_t *chan;
  int j = -1;

  for (int i = 0; i < dcc_total; i++)
    if (!op_strcasecmp(dcc[i].nick, dcc[idx].host) &&
        (dcc[i].type->flags & DCT_BOT))
      j = i;
  if (j == -1)
    return;

  if (!uff_call_receiving(j, dcc[idx].u.xfer->filename)) {
    putlog(LOG_BOTS, "*", "A uff parsing function failed for the userfile!");
    unlink(dcc[idx].u.xfer->filename);
    return;
  }

  if (dcc[j].u.bot->uff_flags & UFF_OVERRIDE)
    debug1("NOTE: Sharing passively with %s, overriding local bots.",
           dcc[j].nick);
  else
    /* Copy the bots over. The entries will be used in the new user list. */
    u = dup_userlist(1);

  /*
   * This is where we remove all global and channel bans/exempts/invites and
   * ignores since they will be replaced by what our hub gives us.
   */

  noshare = 1;
  fr.match = (FR_CHAN | FR_BOT);
  while (global_bans)
    u_delban(nullptr, global_bans->mask, 1);
  while (global_ign)
    delignore(global_ign->igmask);
  while (global_invites)
    u_delinvite(nullptr, global_invites->mask, 1);
  while (global_exempts)
    u_delexempt(nullptr, global_exempts->mask, 1);
  for (chan = chanset; chan; chan = chan->next)
    if (channel_shared(chan)) {
      get_user_flagrec(dcc[j].user, &fr, chan->dname);
      if (bot_chan(fr) || bot_global(fr)) {
        while (chan->bans)
          u_delban(chan, chan->bans->mask, 1);
        while (chan->exempts)
          u_delexempt(chan, chan->exempts->mask, 1);
        while (chan->invites)
          u_delinvite(chan, chan->invites->mask, 1);
      }
    }
  noshare = 0;
  ou = userlist;                /* Save old user list                   */
  userlist = (void *) -1;       /* Do this to prevent .user messups     */

  /* Bot user pointers are updated to point to the new list, all others
   * are set to nullptr. If our userfile will be overridden, just set _all_
   * to nullptr directly.
   */
  if (u == nullptr)
    for (int i = 0; i < dcc_total; i++)
      dcc[i].user = nullptr;
  else
    for (int i = 0; i < dcc_total; i++)
      dcc[i].user = get_user_by_handle(u, dcc[i].nick);

  /* Read the transferred userfile. Add entries to u, which already holds
   * the bot entries in non-override mode.
   */
  if (!readuserfile(dcc[idx].u.xfer->filename, &u)) {
    putlog(LOG_MISC, "*", "%s", USERF_CANTREAD);
    clear_userlist(u);          /* Clear new, obsolete, user list.      */
    clear_chanlist();           /* Remove all user references from the
                                 * channel lists.                       */
    for (int i = 0; i < dcc_total; i++)
      dcc[i].user = get_user_by_handle(ou, dcc[i].nick);
    userlist = ou;              /* Revert to old user list.             */
    lastuser = nullptr;            /* Reset last accessed user ptr.        */
    return;
  }
  putlog(LOG_BOTS, "*", "%s.", USERF_XFERDONE);

  clear_chanlist();             /* Remove all user references from the
                                 * channel lists.                       */
  userlist = u;                 /* Set new user list.                   */
  lastuser = nullptr;              /* Reset last accessed user ptr.        */

  /*
   * Migrate:
   *   - old channel flags over (unshared channels see)
   *   - unshared (got_share == 0) user entries
   *   - old bot flags and passwords
   */
  fr.match = (FR_CHAN | FR_BOT);
  for (u = userlist; u; u = u->next) {
    struct userrec *u2 = get_user_by_handle(ou, u->handle);

    if ((dcc[j].u.bot->uff_flags & UFF_OVERRIDE) &&
        u2 && (u2->flags & USER_BOT)) {
      /* We knew this bot before, copy flags and the password back over. */
      set_user(&USERENTRY_BOTFL, u, get_user(&USERENTRY_BOTFL, u2));
      set_user(&USERENTRY_PASS, u, get_user(&USERENTRY_PASS, u2));
    } else if ((dcc[j].u.bot->uff_flags & UFF_OVERRIDE) &&
             (u->flags & USER_BOT)) {
      /* This bot was unknown to us, reset it's flags and password. */
      set_user(&USERENTRY_BOTFL, u, nullptr);
      set_user(&USERENTRY_PASS, u, nullptr);
    } else if (u2 && !(u2->flags & (USER_BOT | USER_UNSHARED))) {
      struct chanuserrec *cr, *cr_next, *cr_old = nullptr;
      struct user_entry *ue;

      if (private_global) {
        u->flags = u2->flags;
        u->flags_udef = u2->flags_udef;
      } else {
        int pgbm = private_globals_bitmask();

        u->flags = (u2->flags & pgbm) | (u->flags & ~pgbm);
      }
      noshare = 1;
      for (cr = u2->chanrec; cr; cr = cr_next) {
        struct chanset_t *rchan = findchan_by_dname(cr->channel);

        cr_next = cr->next;
        if (rchan) {
          int not_shared = 0;

          if (!channel_shared(rchan))
            not_shared = 1;
          else {
            get_user_flagrec(dcc[j].user, &fr, rchan->dname);
            if (!bot_chan(fr) && !bot_global(fr))
              not_shared = 1;
          }
          if (not_shared) {
            del_chanrec(u, cr->channel);
            if (cr_old)
              cr_old->next = cr_next;
            else
              u2->chanrec = cr_next;
            cr->next = u->chanrec;
            u->chanrec = cr;
          } else {
            /* Shared channel, still keep old laston time */
            for (cr_old = u->chanrec; cr_old; cr_old = cr_old->next)
              if (!rfc_casecmp(cr_old->channel, cr->channel)) {
                cr_old->laston = cr->laston;
                break;
              }
            cr_old = cr;
          }
        }
      }
      noshare = 0;
      /* Any unshared user entries need copying over */
      for (ue = u2->entries; ue; ue = ue->next)
        if (ue->type && !ue->type->got_share && ue->type->dup_user)
          ue->type->dup_user(u, u2, ue);
    } else if (!u2 && private_global) {
      u->flags = 0;
      u->flags_udef = 0;
    } else
      u->flags = (u->flags & ~private_globals_bitmask());
  }
  clear_userlist(ou);
  unlink(dcc[idx].u.xfer->filename);    /* Done with you!               */
  reaffirm_owners();            /* Make sure my owners are +n   */
  check_tcl_event("userfile-loaded");
  updatebot(-1, dcc[j].nick, '+', 0);
}

/* Begin the user transfer process.
 */
static void start_sending_users(int idx)
{
  struct userrec *u;
  char *share_file;
  char s1[64];
  int i = 1;
  struct chanuserrec *ch;
  struct chanset_t *cst;
  char s[EGG_INET_ADDRSTRLEN];

  {
    op_strbuf_t _b = {};
    op_strbuf_init(&_b);
    op_strbuf_appendf(&_b, ".share.%s.%" PRId64, dcc[idx].nick, (int64_t) now);
    share_file = op_strbuf_steal(&_b);
  }
  if (dcc[idx].u.bot->uff_flags & UFF_OVERRIDE) {
    debug1("NOTE: Sharing aggressively with %s, overriding its local bots.",
           dcc[idx].nick);
    u = dup_userlist(2);        /* All entries          */
  } else
    u = dup_userlist(0);        /* Only non-bots        */
  write_tmp_userfile(share_file, u, idx);
  clear_userlist(u);

  if (!uff_call_sending(idx, share_file)) {
    unlink(share_file);
    dprintf(idx, "s e %s\n", "uff parsing failed");
    putlog(LOG_BOTS, "*", "uff parsing failed");
    dcc[idx].status &= ~(STAT_SHARE | STAT_SENDING | STAT_AGGRESSIVE);
    op_free(share_file);
    return;
  }

  if ((i = raw_dcc_send(share_file, "*users", "(users)")) > 0) {
    unlink(share_file);
    dprintf(idx, "s e %s\n", USERF_CANTSEND);
    putlog(LOG_BOTS, "*", "%s -- can't send userfile",
           i == DCCSEND_FULL ? "NO MORE DCC CONNECTIONS" :
           i == DCCSEND_NOSOCK ? "CAN'T OPEN A LISTENING SOCKET" :
           i == DCCSEND_BADFN ? "BAD FILE" :
           i == DCCSEND_FEMPTY ? "EMPTY FILE" : "UNKNOWN REASON!");
    dcc[idx].status &= ~(STAT_SHARE | STAT_SENDING | STAT_AGGRESSIVE);
  } else {
    updatebot(-1, dcc[idx].nick, '+', 0);
    dcc[idx].status |= STAT_SENDING;
    i = dcc_total - 1;
    op_strlcpy(dcc[i].host, dcc[idx].nick, sizeof(dcc[i].host)); /* Store bot's nick */
    getdccaddr(&dcc[i].sockname, s, sizeof s);
#ifdef TLS
    if (dcc[idx].ssl) {
      dcc[i].ssl = 1;
      dprintf(idx, "s us %s +%d %lu\n", s, dcc[i].port, dcc[i].u.xfer->length);
    } else
#endif
    dprintf(idx, "s us %s %d %lu\n", s, dcc[i].port, dcc[i].u.xfer->length);
    /* Start up a tbuf to queue outgoing changes for this bot until the
     * userlist is done transferring.
     */
    new_tbuf(dcc[idx].nick);
    /* Immediately, queue bot hostmasks & addresses (jump-start) - if we
     * don't override the leaf's local bots.
     */
    if (!(dcc[idx].u.bot->uff_flags & UFF_OVERRIDE)) {
      for (u = userlist; u; u = u->next) {
        if ((u->flags & USER_BOT) && !(u->flags & USER_UNSHARED)) {
          struct bot_addr *bi = get_user(&USERENTRY_BOTADDR, u);
          op_vec_t *_hv = (op_vec_t *)get_user(&USERENTRY_HOSTS, u);
          op_strbuf_t _s2 = {};

          op_strbuf_init(&_s2);
          /* Send hostmasks */
          if (_hv)
            for (size_t _i = 0; _i < _hv->size; _i++) {
              op_strbuf_clear(&_s2);
              op_strbuf_appendf(&_s2, "s +bh %s %s\n", u->handle,
                                (char *)op_vec_get(_hv, _i));
              q_tbuf(dcc[idx].nick, op_strbuf_str(&_s2), nullptr);
            }
          /* Send address */
          if (bi) {
#ifdef TLS
            op_strbuf_clear(&_s2);
            op_strbuf_appendf(&_s2, "s c BOTADDR %s %s %s%d %s%d\n",
                            u->handle, bi->address,
                            (bi->ssl & TLS_BOT) ? "+" : "", bi->telnet_port,
                            (bi->ssl & TLS_RELAY) ? "+" : "", bi->relay_port);
#else
            op_strbuf_clear(&_s2);
            op_strbuf_appendf(&_s2, "s c BOTADDR %s %s %d %d\n",
                            u->handle, bi->address,
                            bi->telnet_port, bi->relay_port);
#endif
            q_tbuf(dcc[idx].nick, op_strbuf_str(&_s2), nullptr);
          }
          fr.match = FR_GLOBAL;
          fr.global = u->flags;

          fr.udef_global = u->flags_udef;
          build_flags(s1, &fr, nullptr);
          op_strbuf_clear(&_s2);
          op_strbuf_appendf(&_s2, "s a %s %s\n", u->handle, s1);
          q_tbuf(dcc[idx].nick, op_strbuf_str(&_s2), nullptr);
          for (ch = u->chanrec; ch; ch = ch->next) {
            if ((ch->flags & ~BOT_AGGRESSIVE) &&
                ((cst = findchan_by_dname(ch->channel)) &&
                 channel_shared(cst))) {
              fr.match = (FR_CHAN | FR_BOT);
              get_user_flagrec(dcc[idx].user, &fr, ch->channel);
              if (bot_chan(fr) || bot_global(fr)) {
                fr.match = FR_CHAN;
                fr.chan = ch->flags & ~BOT_AGGRESSIVE;
                fr.udef_chan = ch->flags_udef;
                build_flags(s1, &fr, nullptr);
                op_strbuf_clear(&_s2);
                op_strbuf_appendf(&_s2, "s a %s %s %s\n", u->handle, s1, ch->channel);
                q_tbuf(dcc[idx].nick, op_strbuf_str(&_s2), cst);
              }
            }
          }
          op_strbuf_free(&_s2);
        }
      }
    }
    q_tbuf(dcc[idx].nick, "s !\n", nullptr);
    /* Unlink the file. We don't really care whether this causes problems
     * for NFS setups. It's not worth the trouble.
     */
    unlink(share_file);
  }
  op_free(share_file);
}

static void (*def_dcc_bot_kill) (int, void *) = 0;

static void cancel_user_xfer(int idx, void *x)
{
  int j, k = 0;

  if (idx < 0) {
    idx = -idx;
    k = 1;
    updatebot(-1, dcc[idx].nick, '-', 0);
  }
  flush_tbuf(dcc[idx].nick);
  if (dcc[idx].status & STAT_SHARE) {
    if (dcc[idx].status & STAT_GETTING) {
      j = 0;
      for (int i = 0; i < dcc_total; i++)
        if (!op_strcasecmp(dcc[i].host, dcc[idx].nick) &&
            ((dcc[i].type->flags & (DCT_FILETRAN | DCT_FILESEND)) ==
             (DCT_FILETRAN | DCT_FILESEND)))
          j = i;
      if (j != 0) {
        killsock(dcc[j].sock);
        unlink(dcc[j].u.xfer->filename);
        lostdcc(j);
      }
      putlog(LOG_BOTS, "*", "(Userlist download aborted.)");
    }
    if (dcc[idx].status & STAT_SENDING) {
      j = 0;
      for (int i = 0; i < dcc_total; i++)
        if ((!op_strcasecmp(dcc[i].host, dcc[idx].nick)) &&
            ((dcc[i].type->flags & (DCT_FILETRAN | DCT_FILESEND)) ==
            DCT_FILETRAN))
          j = i;
      if (j != 0) {
        killsock(dcc[j].sock);
        unlink(dcc[j].u.xfer->filename);
        lostdcc(j);
      }
      putlog(LOG_BOTS, "*", "(Userlist transmit aborted.)");
    }
    if (allow_resync && (!(dcc[idx].status & STAT_GETTING)) &&
        (!(dcc[idx].status & STAT_SENDING)))
      new_tbuf(dcc[idx].nick);
  }
  if (!k)
    def_dcc_bot_kill(idx, x);
}

static tcl_ints my_ints[] = {
  {"allow-resync",      &allow_resync, 0},
  {"resync-time",        &resync_time, 0},
  {"private-global",  &private_global, 0},
  {"private-user",      &private_user, 0},
  {"override-bots", &overr_local_bots, 0},
  {nullptr,                         nullptr, 0}
};

static tcl_strings my_strings[] = {
  {"private-globals", private_globals, 50, 0},
  {nullptr,              nullptr,            0,  0}
};

static void cmd_flush(struct userrec *u, int idx, char *par)
{
  if (!par[0])
    dprintf(idx, "Usage: flush <botname>\n");
  else if (flush_tbuf(par))
    dprintf(idx, "Flushed resync buffer for %s\n", par);
  else
    dprintf(idx, "There is no resync buffer for that bot.\n");
}

static cmd_t my_cmds[] = {
  {"flush", "n",  (IntFunc) cmd_flush, nullptr},
  {nullptr,    nullptr, nullptr,                 nullptr}
};

static char *share_close(void)
{
  module_undepend(MODULE_NAME);
  putlog(LOG_MISC | LOG_BOTS, "*", "Sending 'share end' to all sharebots...");
  for (int i = 0; i < dcc_total; i++)
    if ((dcc[i].type->flags & DCT_BOT) && (dcc[i].status & STAT_SHARE)) {
      dprintf(i, "s e Unload module\n");
      cancel_user_xfer(-i, 0);
      updatebot(-1, dcc[i].nick, '-', 0);
      dcc[i].status &= ~(STAT_SHARE | STAT_GETTING | STAT_SENDING |
                         STAT_OFFERED | STAT_AGGRESSIVE);
      dcc[i].u.bot->uff_flags = 0;
    }
  putlog(LOG_MISC | LOG_BOTS, "*",
         "Unloaded sharing module, flushing tbuf's...");
  while (tbuf_vec.size)
    tbuf_free(0);
  if (share_msgq_bh) {
    op_bh_destroy(share_msgq_bh);
    share_msgq_bh = nullptr;
  }
  del_hook(HOOK_SHAREOUT, (Function) shareout_mod);
  del_hook(HOOK_SHAREIN, (Function) sharein_mod);
  del_hook(HOOK_MINUTELY, (Function) check_expired_tbufs);
  del_hook(HOOK_READ_USERFILE, (Function) hook_read_userfile);
  del_hook(HOOK_SECONDLY, (Function) check_delay);
  DCC_BOT.kill = def_dcc_bot_kill;
  uff_deltable(internal_uff_table);
  if (uff_list_bh) { op_bh_destroy(uff_list_bh); uff_list_bh = nullptr; }
  delay_free_mem();
  if (delay_mode_bh) {
    op_bh_destroy(delay_mode_bh);
    delay_mode_bh = nullptr;
  }
  rem_tcl_ints(my_ints);
  rem_tcl_strings(my_strings);
  rem_builtins(H_dcc, my_cmds);
  rem_help_reference("share.help");
  return nullptr;
}

static int share_expmem(void)
{
  int tot = 0;
  for (size_t i = 0; i < tbuf_vec.size; i++) {
    tandbuf *t = (tandbuf *)op_vec_get(&tbuf_vec, i);
    tot += sizeof(tandbuf);
    size_t _n = op_deque_size(&t->q);
    for (size_t _i = 0; _i < _n; _i++) {
      struct share_msgq *qe = op_deque_at(&t->q, _i);
      tot += sizeof(struct share_msgq) + strlen(qe->msg) + 1;
    }
  }
  tot += uff_expmem();
  tot += delay_expmem();
  return tot;
}

static void share_report(int idx, int details)
{
  if (details) {
    int size = share_expmem();

    dprintf(idx, "    Private owners: %s\n", (private_global ||
            (private_globals_bitmask() & USER_OWNER)) ? "yes" : "no");
    dprintf(idx, "    Allow resync: %s\n", allow_resync ? "yes" : "no");

    for (int i = 0; i < dcc_total; i++) {
      if (dcc[i].type == &DCC_BOT) {
        if (dcc[i].status & STAT_GETTING) {
          int ok = 0;

          for (int j = 0; j < dcc_total; j++)
            if (((dcc[j].type->flags & (DCT_FILETRAN | DCT_FILESEND)) ==
                (DCT_FILETRAN | DCT_FILESEND)) &&
                !op_strcasecmp(dcc[j].host, dcc[i].nick)) {
              dprintf(idx, "    Downloading userlist from %s (%d%% done)\n",
                      dcc[i].nick, (int) (100.0 * ((float) dcc[j].status) /
                      ((float) dcc[j].u.xfer->length)));
              ok = 1;
              break;
            }
          if (!ok)
            dprintf(idx, "    Download userlist from %s (negotiating "
                    "botentries)\n", dcc[i].nick);
        } else if (dcc[i].status & STAT_SENDING) {
          for (int j = 0; j < dcc_total; j++) {
            if (((dcc[j].type->flags & (DCT_FILETRAN | DCT_FILESEND)) ==
                DCT_FILETRAN) && !op_strcasecmp(dcc[j].host, dcc[i].nick)) {
              if (dcc[j].type == &DCC_GET)
                dprintf(idx, "    Sending userlist to %s (%d%% done)\n",
                        dcc[i].nick, (int) (100.0 * ((float) dcc[j].status) /
                        ((float) dcc[j].u.xfer->length)));
              else
                dprintf(idx, "    Sending userlist to %s (waiting for connect)\n",
                        dcc[i].nick);
            }
          }
        } else if (dcc[i].status & STAT_AGGRESSIVE) {
          dprintf(idx, "    Passively sharing with %s.\n", dcc[i].nick);
        } else if (dcc[i].status & STAT_SHARE) {
          dprintf(idx, "    Aggressively sharing with %s.\n", dcc[i].nick);
        }
      }
    }
    status_tbufs(idx);
    dprintf(idx, "    Using %d byte%s of memory\n", size,
            (size != 1) ? "s" : "");
  }
}

EXPORT_SCOPE char *share_start(Function *global_funcs);

static Function share_table[] = {
  /* 0 - 3 */
  (Function) share_start,
  (Function) share_close,
  (Function) share_expmem,
  (Function) share_report,
  /* 4 - 7 */
  (Function) finish_share,
  (Function) dump_resync,
  (Function) uff_addtable,
  (Function) uff_deltable
};

char *share_start(Function *global_funcs)
{

  global = global_funcs;

  module_register(MODULE_NAME, share_table, 2, 5);
  if (!module_depend(MODULE_NAME, "eggdrop", 108, 0)) {
    module_undepend(MODULE_NAME);
    return "This module requires Eggdrop 1.8.0 or later.";
  }
  if (!(transfer_funcs = module_depend(MODULE_NAME, "transfer", 2, 0))) {
    module_undepend(MODULE_NAME);
    return "This module requires transfer module 2.0 or later.";
  }
  if (!(channels_funcs = module_depend(MODULE_NAME, "channels", 1, 0))) {
    module_undepend(MODULE_NAME);
    return "This module requires channels module 1.0 or later.";
  }
  share_msgq_bh = op_bh_create(sizeof(struct share_msgq), 32, "share_msgq");
  add_hook(HOOK_SHAREOUT, (Function) shareout_mod);
  add_hook(HOOK_SHAREIN, (Function) sharein_mod);
  add_hook(HOOK_MINUTELY, (Function) check_expired_tbufs);
  add_hook(HOOK_READ_USERFILE, (Function) hook_read_userfile);
  add_hook(HOOK_SECONDLY, (Function) check_delay);
  add_help_reference("share.help");
  def_dcc_bot_kill = DCC_BOT.kill;
  DCC_BOT.kill = cancel_user_xfer;
  add_tcl_ints(my_ints);
  add_tcl_strings(my_strings);
  add_builtins(H_dcc, my_cmds);
  uff_init();
  uff_addtable(internal_uff_table);
  return nullptr;
}

static int private_globals_bitmask(void)
{
  struct flag_record fr = { FR_GLOBAL };

  break_down_flags(private_globals, &fr, 0);
  return fr.global;
}

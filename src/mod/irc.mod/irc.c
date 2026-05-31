/*
 * irc.c -- part of irc.mod
 *   support for channels within the bot
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

#define MODULE_NAME "irc"
#define MAKING_IRC

#include "src/mod/module.h"
#include "irc.h"
#include "server.mod/server.h"
#include "channels.mod/channels.h"
#include "msgcounter.mod/msgcounter.h"

#include <sys/utsname.h>

static p_tcl_bind_list H_topc, H_splt, H_sign, H_rejn, H_part, H_pub, H_pubm;
static p_tcl_bind_list H_nick, H_mode, H_kick, H_join, H_need, H_invt, H_ircaway;
static p_tcl_bind_list H_account, H_chghost, H_awaynotify;

static Function *global = nullptr, *channels_funcs = nullptr, *server_funcs = nullptr;

static int ctcp_mode;
static int wait_split = 300;    /* Time to wait for user to return from net-split. */
static int max_bans = 30;       /* Modified by net-type 1-4 */
static int max_exempts = 20;    /* Modified by net-type 1-4 */
static int max_invites = 20;    /* Modified by net-type 1-4 */
static int max_modes = 30;      /* Modified by net-type 1-4 */
static int bounce_bans = 0;
static int bounce_exempts = 0;
static int bounce_invites = 0;
static int bounce_modes = 0;
static int learn_users = 0;
static int allow_hello = 1;     /* respond to /msg hello (learn_users/make_userfile) */
static int allow_addhost = 1;   /* respond to /msg addhost <pass> <hostmask> */
static int wait_info = 15;
static int invite_key = 1;
static int no_chanrec_info = 0;
static int modesperline = 3;    /* Number of modes per line to send. */
static int mode_buf_len = 200;  /* Maximum bytes to send in 1 mode. */
static int use_354 = 0;         /* Use ircu's short 354 /who responses. */
static int kick_method = 1;     /* How many kicks does the IRC network support
                                 * at once? Use 0 for as many as possible.
                                 * (Ernst 18/3/1998) */
static int keepnick = 1;        /* Keep nick */
static int twitch = 0;          /* Is this a Twitch server? */
static int prevent_mixing = 1;  /* Prevent mixing old/new modes */
static int rfc_compliant = 1;   /* Value depends on net-type. */
static int include_lk = 1;      /* For correct calculation in real_add_mode. */

static char opchars[8];         /* the chars in a /who reply meaning op */

static Tcl_Obj *tcl_account;

/* -----------------------------------------------------------------------
 * WHOIS rate limiter: max 3 WHOIS requests per nick per 30 seconds.
 * Keyed on the target nick (case-insensitive via istr bucket hash).
 * Defined here, before unity-build includes, so tclirc.c can call it.
 * ----------------------------------------------------------------------- */
static op_htab *whois_rl_ht = nullptr;  /* nick -> op_ratelimit_t* */
static op_bh   *whois_rl_bh = nullptr;  /* block heap for rl structs */

/* Returns 1 if the WHOIS for <nick> should be suppressed (rate limited),
 * 0 if it is permitted. Lazily initialises the table and heap. */
static int whois_check_ratelimit(const char *nick)
{
  if (!whois_rl_bh)
    whois_rl_bh = op_bh_create(sizeof(op_ratelimit_t), 32, "whois_rl");
  if (!whois_rl_ht)
    whois_rl_ht = op_htab_create_istr("whois_rl", 32);

  op_ratelimit_t *rl = (op_ratelimit_t *)op_htab_get(whois_rl_ht, nick);
  if (!rl) {
    rl = (op_ratelimit_t *)op_bh_alloc(whois_rl_bh);
    uint64_t ts = op_current_time_usec();
    /* capacity=3 burst; rate=1 token every 30 s.
     * op_ratelimit_init(rl, capacity, rate_per_sec, ts_usec).
     * Override rate_usec after init to encode 30s/token. */
    op_ratelimit_init(rl, 3, 1, ts);
    rl->rate_usec = 30000000u;  /* 30 000 000 µs = 30s per token */
    char *key = op_strdup(nick);
    op_htab_set(whois_rl_ht, key, rl, nullptr);
  }
  /* Returns 0 when a token is available (allowed); 1 = denied */
  return !op_ratelimit_check(rl, op_current_time_usec());
}

/* -----------------------------------------------------------------------
 * Per-user PRIVMSG flood tracking.
 * Token-bucket rate limiter: capacity=5 msgs, rate=1 token per 3 seconds.
 * Keyed on nick (case-insensitive).  Lazy-initialised.
 * ----------------------------------------------------------------------- */

typedef struct {
  op_ratelimit_t rl;
  char nick[NICKLEN];
} flood_user_t;

static op_htab *flood_user_ht = nullptr;  /* nick (icase) -> flood_user_t* */
static op_bh   *flood_user_bh = nullptr;  /* block heap for flood_user_t    */

/* Return the flood_user_t for <nick>, creating one if not present. */
static flood_user_t *flood_user_get(const char *nick)
{
  if (!flood_user_bh)
    flood_user_bh = op_bh_create(sizeof(flood_user_t), 64, "flood_user");
  if (!flood_user_ht)
    flood_user_ht = op_htab_create_istr("flood_user", 64);

  flood_user_t *fu = (flood_user_t *)op_htab_get(flood_user_ht, nick);
  if (!fu) {
    fu = (flood_user_t *)op_bh_alloc(flood_user_bh);
    op_strlcpy(fu->nick, nick, sizeof fu->nick);
    /* capacity=5 burst; override rate_usec for 1 token/3 s. */
    op_ratelimit_init(&fu->rl, 5, 1, op_current_time_usec());
    fu->rl.rate_usec = 3000000u;  /* 3 000 000 µs = 3 s per token */
    char *key = op_strdup(nick);
    op_htab_set(flood_user_ht, key, fu, nullptr);
  }
  return fu;
}

/* Check per-user PRIVMSG rate limit for <nick> on <chan>.
 * Returns 1 and kicks if the user is flooding beyond 2x the channel threshold.
 * Returns 0 if within limits.
 */
static int flood_user_check(const char *nick, struct chanset_t *chan)
{
  if (!chan || chan->flood_pub_thr <= 0)
    return 0;
  if (match_my_nick(nick))
    return 0;

  flood_user_t *fu = flood_user_get(nick);
  if (op_ratelimit_check(&fu->rl, op_current_time_usec()))
    return 0;  /* within limit */

  /* Rate-limited: check if we should kick (2x channel pub flood threshold). */
  memberlist *m = ismember(chan, nick);
  if (!m)
    return 0;

  /* Don't kick ops/halfops/friends; let detect_chan_flood handle them. */
  struct userrec *u = get_user_from_member(m);
  struct flag_record fr = { FR_GLOBAL | FR_CHAN };
  get_user_flagrec(u, &fr, chan->dname);
  if (glob_bot(fr) || glob_friend(fr) || chan_friend(fr) ||
      glob_master(fr) || chan_master(fr))
    return 0;

  if (!chan_sentkick(m) && (me_op(chan) || (me_halfop(chan) && !chan_hasop(m)))) {
    putlog(LOG_MODES, chan->dname,
           "Per-user flood: kicking %s from %s", nick, chan->dname);
    dprintf(DP_MODE, "KICK %s %s :Flooding\n", chan->name, nick);
    m->flags |= SENTKICK;
    return 1;
  }
  return 0;
}

/* Forward declaration for chan_handlers.c which calls this before irc.c
 * defines it. */
static void check_tcl_awaynotify(char *nick, char *from, struct userrec *u,
                                 char *chan, char *msg);

#include "chan.c"
#include "mode.c"
#include "cmdsirc.c"
#include "msgcmds.c"
#include "tclirc.c"

/* Contains the logic to decide whether we want to punish someone. Returns
 * true (1) if we want to, false (0) if not.
 */
static int want_to_revenge(struct chanset_t *chan, struct userrec *u,
                           struct userrec *u2, const char *badnick,
                           const char *victim, int mevictim)
{
  struct flag_record fr = { FR_GLOBAL | FR_CHAN };

  /* Do not take revenge upon ourselves. */
  if (match_my_nick(badnick))
    return 0;

  get_user_flagrec(u, &fr, chan->dname);

  /* Kickee is not a friend? */
  if (!chan_friend(fr) && !glob_friend(fr) && rfc_casecmp(badnick, victim)) {
    if (mevictim && channel_revengebot(chan))
      return 1;
    else if (channel_revenge(chan) && u2) {
      struct flag_record fr2 = { FR_GLOBAL | FR_CHAN };

      get_user_flagrec(u2, &fr2, chan->dname);
      /* Protecting friends? */
      if ((channel_protectfriends(chan) && (chan_friend(fr2) ||
          (glob_friend(fr2) && !chan_deop(fr2)))) ||
          (channel_protectops(chan) && (chan_op(fr2) || (glob_op(fr2) &&
          !chan_deop(fr2)))))
        return 1;
    }
  }
  return 0;
}

/* Dependent on revenge_mode, punish the offender.
 */
static void punish_badguy(struct chanset_t *chan, char *whobad,
                          struct userrec *u, const char *badnick,
                          const char *victim, int mevictim, int type)
{
  op_strbuf_t reason = {}, comment = {};
  char ct[7], *kick_msg;
  memberlist *m;
  struct flag_record fr = { FR_GLOBAL | FR_CHAN };

  m = ismember(chan, badnick);
  if (!m)
    return;
  get_user_flagrec(u, &fr, chan->dname);

  /* Get current time into a string */
  strftime(ct, sizeof ct, "%d %b", localtime(&now));

  /* Put together log and kick messages */
  op_strbuf_init(&reason);
  op_strbuf_init(&comment);
  switch (type) {
  case REVENGE_KICK:
    kick_msg = IRC_KICK_PROTECT;
    op_strbuf_appendf(&reason, "kicked %s off %s", victim, chan->dname);
    break;
  case REVENGE_DEOP:
    op_strbuf_appendf(&reason, "deopped %s on %s", victim, chan->dname);
    kick_msg = IRC_DEOP_PROTECT;
    break;
  default:
    kick_msg = "revenge!";
  }
  putlog(LOG_MISC, chan->dname, "Punishing %s (%s)", badnick,
         op_strbuf_str(&reason));

  /* Set the offender +d */
  if ((chan->revenge_mode > 0) && !(chan_deop(fr) || glob_deop(fr))) {
    char mask[UHOSTLEN], s1[UHOSTLEN];

    /* Removing op */
    if (chan_op(fr) || (glob_op(fr) && !chan_deop(fr))) {
      fr.match = FR_CHAN;
      if (chan_op(fr))
        fr.chan &= ~USER_OP;
      else
        fr.chan |= USER_DEOP;
      set_user_flagrec(u, &fr, chan->dname);
      putlog(LOG_MISC, "*", "No longer opping %s[%s] (%s)", u->handle, whobad,
             op_strbuf_str(&reason));
    }
    /* ... or just setting to deop */
    else if (u) {
      /* In the user list already, cool :) */
      fr.match = FR_CHAN;
      fr.chan |= USER_DEOP;
      set_user_flagrec(u, &fr, chan->dname);
      op_strbuf_clear(&comment);
      op_strbuf_appendf(&comment, "(%s) %s", ct, op_strbuf_str(&reason));
      putlog(LOG_MISC, "*", "Now deopping %s[%s] (%s)", u->handle, whobad,
             op_strbuf_str(&comment));
    }
    /* ... or creating new user and setting that to deop */
    else {
      op_strlcpy(s1, whobad, sizeof s1);
      maskaddr(s1, mask, chan->ban_type);
      op_strlcpy(s1, badnick, sizeof s1);
      /* If that handle exists use "badX" (where X is an increasing number)
       * instead.
       */
      while (get_user_by_handle(userlist, s1)) {
        if (!strncmp(s1, "bad", 3)) {
          int i;

          i = egg_atoi(s1 + 3);
          op_strlcpy(s1 + 3, int_to_base10(i + 1), sizeof s1 - 3);
        } else
          op_strlcpy(s1, "bad1", sizeof s1);   /* Start with '1' */
      }
      userlist = adduser(userlist, s1, mask, "-", 0);
      fr.match = FR_CHAN;
      fr.chan = USER_DEOP;
      fr.udef_chan = 0;
      u = get_user_by_handle(userlist, s1);
      set_user_flagrec(u, &fr, chan->dname);
      op_strbuf_clear(&comment);
      op_strbuf_appendf(&comment, "(%s) %s (%s)", ct, op_strbuf_str(&reason),
                        whobad);
      set_user(&USERENTRY_COMMENT, u, (void *)op_strbuf_str(&comment));
      putlog(LOG_MISC, "*", "Now deopping %s (%s)", whobad,
             op_strbuf_str(&reason));
    }
  }

  /* Always try to deop the offender */
  if (!mevictim)
    add_mode(chan, '-', 'o', badnick);
  /* Ban. Should be done before kicking. */
  if (chan->revenge_mode > 2) {
    char banmask[UHOSTLEN];

    splitnick(&whobad);
    maskaddr(whobad, banmask, chan->ban_type);
    op_strbuf_clear(&comment);
    op_strbuf_appendf(&comment, "(%s) %s", ct, op_strbuf_str(&reason));
    u_addban(chan, banmask, botnetnick, op_strbuf_str(&comment),
             now + (60 * chan->ban_time), 0);
    if (!mevictim && HALFOP_CANDOMODE('b')) {
      add_mode(chan, '+', 'b', banmask);
      flush_mode(chan, QUICK);
    }
  }
  /* Kick the offender */
  if (!mevictim && (chan->revenge_mode > 1) && (!channel_dontkickops(chan) ||
      (!chan_op(fr) && (!glob_op(fr) || chan_deop(fr)))) &&
      !chan_sentkick(m) && (me_op(chan) || (me_halfop(chan) &&
      !chan_hasop(m) && (strchr(NOHALFOPS_MODES, 'b') == nullptr)))) {
    dprintf(DP_MODE, "KICK %s %s :%s\n", chan->name, badnick, kick_msg);
    m->flags |= SENTKICK;
  }
  op_strbuf_free(&reason);
  op_strbuf_free(&comment);
}

/* Punishes bad guys under certain circumstances using methods as defined
 * by the revenge_mode flag.
 */
static void maybe_revenge(struct chanset_t *chan, const char *whobad,
                          const char *whovictim, int type)
{
  char *badnick, *victim;
  char bad[NICKLEN + UHOSTLEN], vic[NICKLEN + UHOSTLEN];
  char buf[NICKLEN + UHOSTLEN];
  char *bp, *vp;
  int mevictim;
  struct userrec *u, *u2;
  memberlist *m;

  if (!chan || (type < 0))
    return;

  /* Get info about offender */
  op_strlcpy(bad, whobad, sizeof bad);
  op_strlcpy(buf, whobad, sizeof buf);
  bp = bad;
  badnick = splitnick(&bp);
  m = ismember(chan, badnick);
  u = lookup_user_record(m, m ? m->account : nullptr, buf);

  /* Get info about victim */
  op_strlcpy(vic, whovictim, sizeof vic);
  op_strlcpy(buf, whovictim, sizeof buf);
  vp = vic;
  victim = splitnick(&vp);
  m = ismember(chan, victim);
  u2 = lookup_user_record(m, m ? m->account : nullptr, buf);
  mevictim = match_my_nick(victim);

  /* Do we want to revenge? */
  if (want_to_revenge(chan, u, u2, badnick, victim, mevictim))
    punish_badguy(chan, bp, u, badnick, victim, mevictim, type);
}

/* Set the key.
 */
static void set_key(struct chanset_t *chan, char *k)
{
  op_free(chan->channel.key);
  if (k == nullptr) {
    chan->channel.key = (char *) channel_malloc(1);
    chan->channel.key[0] = 0;
    return;
  }
  chan->channel.key = op_strdup(k);
}

static int hand_on_chan(struct chanset_t *chan, struct userrec *u)
{
  memberlist *m;

  for (m = chan->channel.member; m && m->nick[0]; m = m->next) {
    if (u == get_user_from_member(m))
      return 1;
  }
  return 0;
}

static void refresh_who_chan(char *channame)
{
  if (!twitch) {    /* Twitch doesn't support WHOs */
    if (use_354)
      /* Field order: channel, user(ident), host, nick, flags, account.
       * Matches the field-read order in got354() in chan.c. */
      dprintf(DP_MODE, "WHO %s c%%cuhnfa,222\n", channame);
    else
      dprintf(DP_MODE, "WHO %s\n", channame);
  }
  return;
}

/* Adds a ban, exempt or invite mask to the list
 * m should be chan->channel.(exempt|invite|ban)
 */
static void newmask(masklist *m, op_htab *ht, const char *s, const char *who)
{
  /* O(1) duplicate check via hash table */
  if (ht && op_htab_get(ht, s))
    return;                     /* Already existent mask */

  /* Linear fallback to find sentinel (mask[0]==0) */
  for (; m && m->mask[0]; m = m->next);
  if (!m) {
    fatal("newmask: missing sentinel in mask list", 0);
    abort();
  }

  m->next = (masklist *) channel_malloc_mask();
  m->next->next = nullptr;
  m->next->mask = (char *) channel_malloc(1);
  m->next->mask[0] = 0;
  op_free(m->mask);
  m->mask = op_strdup(s);
  m->who = op_strdup(who);
  m->timer = now;
  if (ht)
    op_htab_set(ht, m->mask, m, nullptr);
}

/* Removes a nick from the channel member list (returns 1 if successful)
 */
static int killmember(struct chanset_t *chan, char *nick)
{
  memberlist *x, *old;

  old = nullptr;
  for (x = chan->channel.member; x && x->nick[0]; old = x, x = x->next)
    if (!rfc_casecmp(x->nick, nick))
      break;
  if (!x || !x->nick[0]) {
    if (!channel_pending(chan) && !channel_djoins(chan))
        putlog(LOG_MISC, "*", "(!) killmember(%s) -> nonexistent", nick);
    return 0;
  }
  if (chan->channel.member_ht && x->nick[0])
    op_htab_del(chan->channel.member_ht, x->nick);
  if (old)
    old->next = x->next;
  else
    chan->channel.member = x->next;
  channel_free_member(x);
  chan->channel.members--;

  /* The following two errors should NEVER happen. We will try to correct
   * them though, to keep the bot from crashing.
   */
  if (chan->channel.members < 0) {
    chan->channel.members = 0;
    for (x = chan->channel.member; x && x->nick[0]; x = x->next)
      chan->channel.members++;
    putlog(LOG_MISC, "*", "(!) actually I know of %d members.",
           chan->channel.members);
  }
  if (!chan->channel.member) {
    chan->channel.member = (memberlist *) channel_malloc_member();
    chan->channel.member->nick[0] = 0;
    chan->channel.member->next = nullptr;
  }
  return 1;
}

/* Check if I am a chanop. Returns boolean 1 or 0.
 */
static int me_op(struct chanset_t *chan)
{
  memberlist *mx = nullptr;

  mx = ismember(chan, botname);
  if (!mx)
    return 0;
  if (chan_hasop(mx))
    return 1;
  else
    return 0;
}

/* Check if I am an IRCX owner (+q). Returns boolean 1 or 0.
 */
static int me_owner(struct chanset_t *chan)
{
  memberlist *mx = nullptr;

  mx = ismember(chan, botname);
  if (!mx)
    return 0;
  return (chan_hasowner(mx)) ? 1 : 0;
}

/* Check if I am a halfop. Returns boolean 1 or 0.
 */
static int me_halfop(struct chanset_t *chan)
{
  memberlist *mx = nullptr;

  mx = ismember(chan, botname);
  if (!mx)
    return 0;
  if (chan_hashalfop(mx))
    return 1;
  else
    return 0;
}

/* Check whether I'm voice. Returns boolean 1 or 0.
 */
static int me_voice(struct chanset_t *chan)
{
  memberlist *mx;

  mx = ismember(chan, botname);
  if (!mx)
    return 0;
  if (chan_hasvoice(mx))
    return 1;
  else
    return 0;
}

/* Check if there are any ops on the channel. Returns boolean 1 or 0.
 */
static int any_ops(struct chanset_t *chan)
{
  memberlist *x;

  for (x = chan->channel.member; x && x->nick[0]; x = x->next)
    if (chan_hasop(x))
      break;
  if (!x || !x->nick[0])
    return 0;
  return 1;
}

/* Reset channel information.
 */
void reset_chan_info(struct chanset_t *chan, int reset, int do_reset)
{
  /* Leave the channel if we aren't supposed to be there */
  if (channel_inactive(chan)) {
    dprintf(DP_MODE, "PART %s\n", chan->name);
    return;
  }

  /* Don't reset the channel if we're already resetting it */
  if (channel_pending(chan))
    return;

  if (net_type_int != NETT_TWITCH) { /* Twitch won't reset any of this */
    if (do_reset) {
      clear_channel(chan, reset);
    }
  } else {
    return;
  }
  if ((reset & CHAN_RESETBANS) && !(chan->status & CHAN_ASKEDBANS)) {
    chan->status |= CHAN_ASKEDBANS;
    dprintf(DP_MODE, "MODE %s +b\n", chan->name);
  }
  if ((reset & CHAN_RESETEXEMPTS) &&
      !(chan->ircnet_status & CHAN_ASKED_EXEMPTS) && (use_exempts == 1)) {
    chan->ircnet_status |= CHAN_ASKED_EXEMPTS;
    dprintf(DP_MODE, "MODE %s +e\n", chan->name);
  }
  if ((reset & CHAN_RESETINVITED) &&
      !(chan->ircnet_status & CHAN_ASKED_INVITED) && (use_invites == 1)) {
    chan->ircnet_status |= CHAN_ASKED_INVITED;
    dprintf(DP_MODE, "MODE %s +I\n", chan->name);
  }
  if (reset & CHAN_RESETMODES) {
    /* done here to keep expmem happy, as this is accounted in
       irc.mod, not channels.mod where clear_channel() resides */
    op_free(chan->channel.key);
    chan->channel.key = (char *) channel_malloc(1);
    chan->channel.key[0] = 0;
    chan->status &= ~CHAN_ASKEDMODES;
    dprintf(DP_MODE, "MODE %s\n", chan->name);
  }
  if ((reset & CHAN_RESETWHO) || (reset & CHAN_RESETAWAY)) {
    chan->status |= CHAN_PEND;
    chan->status &= ~CHAN_ACTIVE;
    refresh_who_chan(chan->name);
  }
  if (reset & CHAN_RESETTOPIC)
    dprintf(DP_MODE, "TOPIC %s\n", chan->name);
}

/* Leave the specified channel and notify registered Tcl procs. This
 * should not be called by itself.
 */
static void do_channel_part(struct chanset_t *chan)
{
  if (!channel_inactive(chan) && chan->name[0]) {
    /* Using chan->name is important here, especially for !chans <cybah> */
    dprintf(DP_SERVER, "PART %s\n", chan->name);

    /* As we don't know of this channel anymore when we receive the server's
     * ack for the above PART, we have to notify about it _now_. */
    check_tcl_part(botname, botuserhost, nullptr, chan->dname, nullptr);
  }
}

/* Report the channel status of every active channel to dcc chat every
 * 5 minutes.
 */
static void status_log(void)
{
  masklist *b;
  memberlist *m;
  struct chanset_t *chan;
  op_strbuf_t s = {}, s2 = {};
  int chops, halfops, voice, nonops, bans, invites, exempts;

  if (!server_online)
    return;

  op_strbuf_init(&s);
  op_strbuf_init(&s2);
  for (chan = chanset; chan != nullptr; chan = chan->next) {
    if (channel_active(chan) && channel_logstatus(chan) &&
        !channel_inactive(chan)) {
      chops = 0;
      voice = 0;
      halfops = 0;
      for (m = chan->channel.member; m && m->nick[0]; m = m->next) {
        if (chan_hasop(m))
          chops++;
        else if (chan_hashalfop(m))
          halfops++;
        else if (chan_hasvoice(m))
          voice++;
      }
      nonops = (chan->channel.members - (chops + voice + halfops));

      for (bans = 0, b = chan->channel.ban; b->mask[0]; b = b->next)
        bans++;
      for (exempts = 0, b = chan->channel.exempt; b->mask[0]; b = b->next)
        exempts++;
      for (invites = 0, b = chan->channel.invite; b->mask[0]; b = b->next)
        invites++;

      op_strbuf_clear(&s);
      op_strbuf_appendf(&s, "%d", exempts);
      op_strbuf_clear(&s2);
      op_strbuf_appendf(&s2, "%d", invites);

      putlog(LOG_MISC, chan->dname,
             "%s%s (%s) : [m/%d o/%d h/%d v/%d n/%d b/%d e/%s I/%s]",
             me_op(chan) ? "@" : me_voice(chan) ? "+" :
             me_halfop(chan) ? "%" : "", chan->dname, getchanmode(chan),
             chan->channel.members, chops, halfops, voice, nonops, bans,
             use_exempts ? op_strbuf_str(&s) : "-",
             use_invites ? op_strbuf_str(&s2) : "-");
    }
  }
  op_strbuf_free(&s);
  op_strbuf_free(&s2);
}

/* If i'm the only person on the channel, and i'm not op'd,
 * might as well leave and rejoin. If i'm NOT the only person
 * on the channel, but i'm still not op'd, demand ops.
 */
static void check_lonely_channel(struct chanset_t *chan)
{
  memberlist *m;
  int i = 0;

  if (channel_pending(chan) || !channel_active(chan) || me_op(chan) ||
      me_owner(chan) || channel_inactive(chan) || (chan->channel.mode & CHANANON))
    return;
  /* Count non-split channel members */
  for (m = chan->channel.member; m && m->nick[0]; m = m->next)
    if (!chan_issplit(m))
      i++;
  if (i == 1 && channel_cycle(chan) && !channel_stop_cycle(chan)) {
    if (chan->name[0] != '+') { /* Its pointless to cycle + chans for ops */
      putlog(LOG_MISC, "*", "Trying to cycle %s to regain ops.", chan->dname);
      dprintf(DP_MODE, "PART %s\n", chan->name);

      /* If it's a !chan, we need to recreate the channel with !!chan <cybah> */
      if (chan->key_prot[0])
        dprintf(DP_MODE, "JOIN %s%s %s\n", (chan->dname[0] == '!') ? "!" : "",
                chan->dname, chan->key_prot);
      else
        dprintf(DP_MODE, "JOIN %s%s\n", (chan->dname[0] == '!') ? "!" : "",
                chan->dname);
      chan->status &= ~CHAN_WHINED;
    }
  } else if (any_ops(chan)) {
    chan->status &= ~CHAN_WHINED;
    check_tcl_need(chan->dname, "op");
    if (chan->need_op[0])
      do_tcl("need-op", chan->need_op);
  } else {
    /* Other people here, but none are ops. If there are other bots make
     * them LEAVE!
     */
    int ok = 1;
    struct userrec *u;

    if (!channel_whined(chan)) {
      /* + is opless. Complaining about no ops when without special
       * help(services), we cant get them - Raist
       */
      if (chan->name[0] != '+' && channel_logstatus(chan))
        putlog(LOG_MISC, "*", "%s is active but has no ops :(", chan->dname);
      chan->status |= CHAN_WHINED;
    }
    for (m = chan->channel.member; m && m->nick[0]; m = m->next) {
      u = get_user_from_member(m);
      if (!match_my_nick(m->nick) && (!u || !(u->flags & USER_BOT))) {
        ok = 0;
        break;
      }
    }
    if (ok && channel_cycle(chan)) {
      /* ALL bots!  make them LEAVE!!! */
      for (m = chan->channel.member; m && m->nick[0]; m = m->next)
        if (!match_my_nick(m->nick))
          dprintf(DP_SERVER, "PRIVMSG %s :go %s\n", m->nick, chan->dname);
    } else {
      /* Some humans on channel, but still op-less */
      check_tcl_need(chan->dname, "op");
      if (chan->need_op[0])
        do_tcl("need-op", chan->need_op);
    }
  }
}

static void check_expired_chanstuff(void)
{
  masklist *b, *e;
  memberlist *m, *n;
  char *key;
  struct chanset_t *chan;
  struct flag_record fr = { FR_GLOBAL | FR_CHAN };

  if (!server_online)
    return;
  for (chan = chanset; chan; chan = chan->next) {
    if (channel_active(chan)) {
      if (me_op(chan) || me_halfop(chan)) {
        if (channel_dynamicbans(chan) && chan->ban_time)
          for (b = chan->channel.ban; b->mask[0]; b = b->next)
            if (b->mask[0] != '$' && /* skip extended bans ($a:, $z:, etc.) */
                now - b->timer > 60 * chan->ban_time &&
                !u_sticky_mask(chan->bans, chan->bans_ht, b->mask) &&
                !u_sticky_mask(global_bans, global_bans_ht, b->mask) &&
                expired_mask(chan, b->who)) {
              putlog(LOG_MODES, chan->dname,
                     "(%s) Channel ban on %s expired.", chan->dname, b->mask);
              add_mode(chan, '-', 'b', b->mask);
              b->timer = now;
            }

        if (use_exempts && channel_dynamicexempts(chan) && chan->exempt_time)
          for (e = chan->channel.exempt; e->mask[0]; e = e->next)
            if (now - e->timer > 60 * chan->exempt_time &&
                !u_sticky_mask(chan->exempts, chan->exempts_ht, e->mask) &&
                !u_sticky_mask(global_exempts, global_exempts_ht, e->mask) &&
                expired_mask(chan, e->who)) {
              /* Check to see if it matches a ban */
              int match = 0;

              for (b = chan->channel.ban; b->mask[0]; b = b->next)
                if (mask_match(b->mask, e->mask)) {
                  match = 1;
                  break;
                }
              /* Leave this extra logging in for now. Can be removed later
               * Jason
               */
              if (match) {
                putlog(LOG_MODES, chan->dname,
                       "(%s) Channel exemption %s NOT expired. Exempt still set!",
                       chan->dname, e->mask);
              } else {
                putlog(LOG_MODES, chan->dname,
                       "(%s) Channel exemption on %s expired.",
                       chan->dname, e->mask);
                add_mode(chan, '-', 'e', e->mask);
              }
              e->timer = now;
            }

        if (use_invites && channel_dynamicinvites(chan) &&
            chan->invite_time && !(chan->channel.mode & CHANINV))
          for (b = chan->channel.invite; b->mask[0]; b = b->next)
            if (now - b->timer > 60 * chan->invite_time &&
                !u_sticky_mask(chan->invites, chan->invites_ht, b->mask) &&
                !u_sticky_mask(global_invites, global_invites_ht, b->mask) &&
                expired_mask(chan, b->who)) {
              putlog(LOG_MODES, chan->dname,
                     "(%s) Channel invitation on %s expired.",
                     chan->dname, b->mask);
              add_mode(chan, '-', 'I', b->mask);
              b->timer = now;
            }

        if (chan->idle_kick)
          for (m = chan->channel.member; m && m->nick[0]; m = m->next)
            if (now - m->last >= chan->idle_kick * 60 &&
                !match_my_nick(m->nick) && !chan_issplit(m)) {
              get_user_flagrec(get_user_from_member(m), &fr, chan->dname);
              if ((!(glob_bot(fr) || glob_friend(fr) || (glob_op(fr) &&
                  !chan_deop(fr)) || chan_friend(fr) || chan_op(fr))) &&
                  (me_op(chan) || (me_halfop(chan) && !chan_hasop(m)))) {
                dprintf(DP_SERVER, "KICK %s %s :idle %d min\n", chan->name,
                        m->nick, chan->idle_kick);
                m->flags |= SENTKICK;
              }
            }
      }
      for (m = chan->channel.member; m && m->nick[0]; m = n) {
        n = m->next;
        if (m->split && now - m->split > wait_split) {
          check_tcl_sign(m->nick, m->userhost, get_user_from_member(m),
                         chan->dname, "lost in the netsplit");
          putlog(LOG_JOIN, chan->dname,
                 "%s (%s) got lost in the net-split.", m->nick, m->userhost);
          killmember(chan, m->nick);
        }
      }
      check_lonely_channel(chan);
    } else if (!channel_inactive(chan) && !channel_pending(chan)) {

      key = chan->channel.key[0] ? chan->channel.key : chan->key_prot;
      if (key[0])
        dprintf(DP_SERVER, "JOIN %s %s\n",
                chan->name[0] ? chan->name : chan->dname, key);
      else
        dprintf(DP_SERVER, "JOIN %s\n",
                chan->name[0] ? chan->name : chan->dname);
    }
  }
}

static int channels_6char STDVAR
{
  [[maybe_unused]] Function F = (Function) cd;

  BADARGS(7, 7, " nick user@host handle desto/chan keyword/nick text");

  CHECKVALIDITY(channels_6char);
  Tcl_AppendResult(irp, int_to_base10(((int (*)(char *, char *, char *, char *, char *, char *)) F)(argv[1], argv[2], argv[3], argv[4], argv[5], argv[6])), nullptr);
  return TCL_OK;
}

static int channels_5char STDVAR
{
  Function F = (Function) cd;

  BADARGS(6, 6, " nick user@host handle channel text");

  CHECKVALIDITY(channels_5char);
  ((void (*)(char *, char *, char *, char *, char *)) F)(argv[1], argv[2], argv[3], argv[4], argv[5]);
  return TCL_OK;
}

static int channels_4char STDVAR
{
  Function F = (Function) cd;

  BADARGS(5, 5, " nick uhost hand chan/param");

  CHECKVALIDITY(channels_4char);
  ((void (*)(char *, char *, char *, char *)) F)(argv[1], argv[2], argv[3], argv[4]);
  return TCL_OK;
}

static int channels_2char STDVAR
{
  Function F = (Function) cd;

  BADARGS(3, 3, " channel type");

  CHECKVALIDITY(channels_2char);
  ((void (*)(char *, char *)) F)(argv[1], argv[2]);
  return TCL_OK;
}

static int invite_4char STDVAR
{
  Function F = (Function) cd;

  BADARGS(5, 5, " nick uhost channel invitee");

  CHECKVALIDITY(invite_4char);
  ((void (*)(char *, char *, char *, char *)) F)(argv[1], argv[2], argv[3], argv[4]);
  return TCL_OK;
}

static int check_tcl_chghost(char *nick, char *from, const char *mask, struct userrec *u,
                             char *chan, char *ident, char *host)
{
  struct flag_record fr = { FR_GLOBAL | FR_CHAN | FR_ANYWH };
  op_strbuf_t usermask = {};
  op_strbuf_init(&usermask);
  int x;

  get_user_flagrec(u, &fr, nullptr);
  op_strbuf_appendf(&usermask, "%s!%s@%s", nick, ident, host);

  Tcl_SetVar(interp, "_chghost1", nick, 0);
  Tcl_SetVar(interp, "_chghost2", from, 0);
  Tcl_SetVar(interp, "_chghost3", u ? u->handle : "*", 0);
  Tcl_SetVar(interp, "_chghost4", chan, 0);
  Tcl_SetVar(interp, "_chghost5", op_strbuf_str(&usermask), 0);
  x = check_tcl_bind(H_chghost, mask, &fr,
                " $_chghost1 $_chghost2 $_chghost3 $_chghost4 $_chghost5",
                MATCH_MASK | BIND_USE_ATTR | BIND_STACKABLE);
  op_strbuf_free(&usermask);
  return (x == BIND_EXEC_LOG);
}

static int check_tcl_ircaway(char *nick, char *from, const char *mask,
            struct userrec *u, char *chan, char *msg)
{
  int x;
  char *hand = u ? u->handle : "*";
  struct flag_record fr = { FR_GLOBAL | FR_CHAN | FR_ANYWH };

  Tcl_SetVar(interp, "_ircaway1", nick, 0);
  Tcl_SetVar(interp, "_ircaway2", from, 0);
  Tcl_SetVar(interp, "_ircaway3", hand, 0);
  Tcl_SetVar(interp, "_ircaway4", chan, 0);
  Tcl_SetVar(interp, "_ircaway5", msg ? msg : "", 0);
  x = check_tcl_bind(H_ircaway, mask, &fr, " $_ircaway1 $_ircaway2 $_ircaway3 "
                        "$_ircaway4 $_ircaway5", MATCH_MASK | BIND_STACKABLE);
  return (x == BIND_EXEC_LOG);
}

/* Fire the 'awaynotify' bind when a user's IRCv3 away status changes.
 * Signature: proc myproc {nick host handle chan away_msg}
 * away_msg is "" when the user returns from away.
 */
static void check_tcl_awaynotify(char *nick, char *from, struct userrec *u,
                                 char *chan, char *msg)
{
  struct flag_record fr = { FR_GLOBAL | FR_CHAN | FR_ANYWH };
  op_strbuf_t mask = {};

  op_strbuf_init(&mask);
  op_strbuf_appendf(&mask, "%s %s", chan, from);
  get_user_flagrec(u, &fr, chan);
  Tcl_SetVar(interp, "_awaynotify1", nick, 0);
  Tcl_SetVar(interp, "_awaynotify2", from, 0);
  Tcl_SetVar(interp, "_awaynotify3", u ? u->handle : "*", 0);
  Tcl_SetVar(interp, "_awaynotify4", chan, 0);
  Tcl_SetVar(interp, "_awaynotify5", msg ? msg : "", 0);
  check_tcl_bind(H_awaynotify, op_strbuf_str(&mask), &fr,
                 " $_awaynotify1 $_awaynotify2 $_awaynotify3"
                 " $_awaynotify4 $_awaynotify5",
                 MATCH_MASK | BIND_STACKABLE);
  op_strbuf_free(&mask);
}

static void check_tcl_joinspltrejn(char *nick, char *uhost, struct userrec *u,
                                   char *chname, p_tcl_bind_list table)
{
  struct flag_record fr = { FR_GLOBAL | FR_CHAN };
  op_strbuf_t args = {};

  op_strbuf_init(&args);
  op_strbuf_appendf(&args, "%s %s!%s", chname, nick, uhost);
  get_user_flagrec(u, &fr, chname);
  Tcl_SetVar(interp, "_jp1", nick, 0);
  Tcl_SetVar(interp, "_jp2", uhost, 0);
  Tcl_SetVar(interp, "_jp3", u ? u->handle : "*", 0);
  Tcl_SetVar(interp, "_jp4", chname, 0);
  check_tcl_bind(table, op_strbuf_str(&args), &fr, " $_jp1 $_jp2 $_jp3 $_jp4",
                 MATCH_MASK | BIND_USE_ATTR | BIND_STACKABLE);
  op_strbuf_free(&args);
}

/* we handle part messages now *sigh* (guppy 27Jan2000) */

static void check_tcl_part(char *nick, char *uhost, struct userrec *u,
                           char *chname, char *text)
{
  struct flag_record fr = { FR_GLOBAL | FR_CHAN };
  op_strbuf_t args = {};

  op_strbuf_init(&args);
  op_strbuf_appendf(&args, "%s %s!%s", chname, nick, uhost);
  get_user_flagrec(u, &fr, chname);
  Tcl_SetVar(interp, "_p1", nick, 0);
  Tcl_SetVar(interp, "_p2", uhost, 0);
  Tcl_SetVar(interp, "_p3", u ? u->handle : "*", 0);
  Tcl_SetVar(interp, "_p4", chname, 0);
  Tcl_SetVar(interp, "_p5", text ? text : "", 0);
  check_tcl_bind(H_part, op_strbuf_str(&args), &fr, " $_p1 $_p2 $_p3 $_p4 $_p5",
                 MATCH_MASK | BIND_USE_ATTR | BIND_STACKABLE);
  op_strbuf_free(&args);
}

static void check_tcl_signtopcnick(char *nick, char *uhost, struct userrec *u,
                                   char *chname, char *reason,
                                   p_tcl_bind_list table)
{
  struct flag_record fr = { FR_GLOBAL | FR_CHAN };
  op_strbuf_t args = {};

  op_strbuf_init(&args);
  if (table == H_sign)
    op_strbuf_appendf(&args, "%s %s!%s", chname, nick, uhost);
  else
    op_strbuf_appendf(&args, "%s %s", chname, reason);
  get_user_flagrec(u, &fr, chname);
  Tcl_SetVar(interp, "_stnm1", nick, 0);
  Tcl_SetVar(interp, "_stnm2", uhost, 0);
  Tcl_SetVar(interp, "_stnm3", u ? u->handle : "*", 0);
  Tcl_SetVar(interp, "_stnm4", chname, 0);
  Tcl_SetVar(interp, "_stnm5", reason, 0);
  check_tcl_bind(table, op_strbuf_str(&args), &fr,
                 " $_stnm1 $_stnm2 $_stnm3 $_stnm4 $_stnm5",
                 MATCH_MASK | BIND_USE_ATTR | BIND_STACKABLE);
  op_strbuf_free(&args);
}

static void check_tcl_mode(char *nick, char *uhost, struct userrec *u,
                           char *chname, char *mode, char *target)
{
  struct flag_record fr = { FR_GLOBAL | FR_CHAN };
  op_strbuf_t args = {};

  get_user_flagrec(u, &fr, chname);
  op_strbuf_init(&args);
  op_strbuf_appendf(&args, "%s %s", chname, mode);
  Tcl_SetVar(interp, "_mode1", nick, 0);
  Tcl_SetVar(interp, "_mode2", uhost, 0);
  Tcl_SetVar(interp, "_mode3", u ? u->handle : "*", 0);
  Tcl_SetVar(interp, "_mode4", chname, 0);
  Tcl_SetVar(interp, "_mode5", mode, 0);
  Tcl_SetVar(interp, "_mode6", target, 0);
  check_tcl_bind(H_mode, op_strbuf_str(&args), &fr,
                 " $_mode1 $_mode2 $_mode3 $_mode4 $_mode5 $_mode6",
                 MATCH_MODE | BIND_USE_ATTR | BIND_STACKABLE);
  op_strbuf_free(&args);
}

static void check_tcl_kick(char *nick, char *uhost, struct userrec *u,
                           char *chname, char *dest, char *reason)
{
  struct flag_record fr = { FR_GLOBAL | FR_CHAN };
  op_strbuf_t args = {};

  get_user_flagrec(u, &fr, chname);
  op_strbuf_init(&args);
  op_strbuf_appendf(&args, "%s %s %s", chname, dest, reason);
  Tcl_SetVar(interp, "_kick1", nick, 0);
  Tcl_SetVar(interp, "_kick2", uhost, 0);
  Tcl_SetVar(interp, "_kick3", u ? u->handle : "*", 0);
  Tcl_SetVar(interp, "_kick4", chname, 0);
  Tcl_SetVar(interp, "_kick5", dest, 0);
  Tcl_SetVar(interp, "_kick6", reason, 0);
  check_tcl_bind(H_kick, op_strbuf_str(&args), &fr,
                 " $_kick1 $_kick2 $_kick3 $_kick4 $_kick5 $_kick6",
                 MATCH_MASK | BIND_USE_ATTR | BIND_STACKABLE);
  op_strbuf_free(&args);
}

static void check_tcl_invite(char *nick, char *from, char *chan, char *invitee)
{
  op_strbuf_t args = {};
  op_strbuf_init(&args);

  Tcl_SetVar(interp, "_invite1", nick, 0);
  Tcl_SetVar(interp, "_invite2", from, 0);
  Tcl_SetVar(interp, "_invite3", chan, 0);
  Tcl_SetVar(interp, "_invite4", invitee, 0);
  op_strbuf_appendf(&args, "%s %s", chan, invitee);
  check_tcl_bind(H_invt, op_strbuf_str(&args), 0,
                 " $_invite1 $_invite2 $_invite3 $_invite4",
                 MATCH_MASK | BIND_STACKABLE);
  op_strbuf_free(&args);
}

static int check_tcl_pub(char *nick, char *from, char *chname, char *msg)
{
  struct flag_record fr = { FR_GLOBAL | FR_CHAN };
  int x;
  char buf[512], *args = buf, *cmd, *hand;
  struct chanset_t *chan;
  struct userrec *u = nullptr;
  memberlist *m;

  op_strlcpy(buf, msg, sizeof buf);
  cmd = newsplit(&args);
  chan = findchan(chname);
  m = ismember(chan, nick);
  if (!m)
    m = find_member_from_nick(nick);
  u = lookup_user_record(m, m ? m->account : nullptr, from);
  hand = u ? u->handle : "*";
  get_user_flagrec(u, &fr, chname);
  Tcl_SetVar(interp, "_pub1", nick, 0);
  Tcl_SetVar(interp, "_pub2", from, 0);
  Tcl_SetVar(interp, "_pub3", hand, 0);
  Tcl_SetVar(interp, "_pub4", chname, 0);
  Tcl_SetVar(interp, "_pub5", args, 0);
  Tcl_SetVar(interp, "server_account", current_msgtag_account, TCL_GLOBAL_ONLY);
  x = check_tcl_bind(H_pub, cmd, &fr, " $_pub1 $_pub2 $_pub3 $_pub4 $_pub5",
                     MATCH_EXACT | BIND_USE_ATTR | BIND_HAS_BUILTINS);
  Tcl_SetVar(interp, "server_account", "", TCL_GLOBAL_ONLY);
  if (x == BIND_NOMATCH)
    return 0;
  if (x == BIND_EXEC_LOG)
    putlog(LOG_CMDS, chname, "<<%s>> !%s! %s %s", nick, hand, cmd, args);
  return 1;
}

static int check_tcl_pubm(char *nick, char *from, char *chname, char *msg)
{
  struct flag_record fr = { FR_GLOBAL | FR_CHAN };
  int x;
  op_strbuf_t buf = {};
  op_strbuf_init(&buf);
  struct userrec *u;
  struct chanset_t *chan;
  memberlist *m;

  op_strbuf_appendf(&buf, "%s %s", chname, msg);
  chan = findchan(chname);
  m = ismember(chan, nick);
  if (!m)
    m = find_member_from_nick(nick);
  u = lookup_user_record(m, m ? m->account : nullptr, from);
  get_user_flagrec(u, &fr, chname);
  Tcl_SetVar(interp, "_pubm1", nick, 0);
  Tcl_SetVar(interp, "_pubm2", from, 0);
  Tcl_SetVar(interp, "_pubm3", u ? u->handle : "*", 0);
  Tcl_SetVar(interp, "_pubm4", chname, 0);
  Tcl_SetVar(interp, "_pubm5", msg, 0);
  Tcl_SetVar(interp, "server_account", current_msgtag_account, TCL_GLOBAL_ONLY);
  x = check_tcl_bind(H_pubm, op_strbuf_str(&buf), &fr,
                     " $_pubm1 $_pubm2 $_pubm3 $_pubm4 $_pubm5",
                     MATCH_MASK | BIND_USE_ATTR | BIND_STACKABLE | BIND_STACKRET);
  Tcl_SetVar(interp, "server_account", "", TCL_GLOBAL_ONLY);
  op_strbuf_free(&buf);

  /*
   * 0 - no match
   * 1 - match, log
   * 2 - match, don't log
   */
  if (x == BIND_NOMATCH)
    return 0;
  if (x == BIND_EXEC_LOG)
    return 2;

  return 1;
}

static void check_tcl_need(char *chname, char *type)
{
  op_strbuf_t buf = {};

  op_strbuf_init(&buf);
  op_strbuf_appendf(&buf, "%s %s", chname, type);
  Tcl_SetVar(interp, "_need1", chname, 0);
  Tcl_SetVar(interp, "_need2", type, 0);
  check_tcl_bind(H_need, op_strbuf_str(&buf), 0, " $_need1 $_need2",
                 MATCH_MASK | BIND_STACKABLE);
  op_strbuf_free(&buf);
}

static void check_tcl_account(char *nick, char *uhost, struct userrec *u, char *chan, char *account)
{
  op_strbuf_t mask = {};
  struct flag_record fr = { FR_GLOBAL | FR_CHAN | FR_ANYWH };

  op_strbuf_init(&mask);
  op_strbuf_appendf(&mask, "%s %s!%s %s", chan, nick, uhost, account ? account : "*");
  Tcl_SetVar(interp, "_acnt1", nick, 0);
  Tcl_SetVar(interp, "_acnt2", uhost, 0);
  Tcl_SetVar(interp, "_acnt3", u ? u->handle : "*", 0);
  Tcl_SetVar(interp, "_acnt4", chan, 0);
  Tcl_SetVar(interp, "_acnt5", account, 0);
  check_tcl_bind(H_account, op_strbuf_str(&mask), &fr,
       " $_acnt1 $_acnt2 $_acnt3 $_acnt4 $_acnt5", MATCH_MASK | BIND_STACKABLE);
  op_strbuf_free(&mask);
}


static tcl_strings mystrings[] = {
  {"opchars", opchars, 7, 0},
  {nullptr,      nullptr,    0, 0}
};

static tcl_ints myints[] = {
  {"learn-users",     &learn_users,     0}, /* arthur2 */
  {"allow-hello",     &allow_hello,     0},
  {"allow-addhost",   &allow_addhost,   0},
  {"wait-split",      &wait_split,      0},
  {"wait-info",       &wait_info,       0},
  {"bounce-bans",     &bounce_bans,     0},
  {"bounce-exempts",  &bounce_exempts,  0},
  {"bounce-invites",  &bounce_invites,  0},
  {"bounce-modes",    &bounce_modes,    0},
  {"modes-per-line",  &modesperline,    0},
  {"mode-buf-length", &mode_buf_len,    0},
  {"use-354",         &use_354,         0},
  {"kick-method",     &kick_method,     0},
  {"invite-key",      &invite_key,      0},
  {"no-chanrec-info", &no_chanrec_info, 0},
  {"max-bans",        &max_bans,        0},
  {"max-exempts",     &max_exempts,     0},
  {"max-invites",     &max_invites,     0},
  {"max-modes",       &max_modes,       0},
  {"ctcp-mode",       &ctcp_mode,       0}, /* arthur2 */
  {"keep-nick",       &keepnick,        0}, /* guppy */
  {"prevent-mixing",  &prevent_mixing,  0},
  {"rfc-compliant",   &rfc_compliant,   0},
  {"include-lk",      &include_lk,      0},
  {nullptr,              nullptr,             0}  /* arthur2 */
};

/* Flush the modes for EVERY channel.
 */
static void flush_modes(void)
{
  struct chanset_t *chan;
  memberlist *m;

  if (modesperline > MODES_PER_LINE_MAX)
    modesperline = MODES_PER_LINE_MAX;

  for (chan = chanset; chan; chan = chan->next) {
    for (m = chan->channel.member; m && m->nick[0]; m = m->next) {
      if (m->delay && m->delay <= now) {
        m->delay = 0L;
        m->flags &= ~FULL_DELAY;
        if (chan_sentop(m)) {
          m->flags &= ~SENTOP;
          add_mode(chan, '+', 'o', m->nick);
        }
        if (chan_senthalfop(m)) {
          m->flags &= ~SENTHALFOP;
          add_mode(chan, '+', 'h', m->nick);
        }
        if (chan_sentvoice(m)) {
          m->flags &= ~SENTVOICE;
          add_mode(chan, '+', 'v', m->nick);
        }
      }
    }
    flush_mode(chan, NORMAL);
  }
}

static void tell_account_tracking_status(int idx, int details)
{
  struct capability *current;
  int extjoin = 0, notify = 0, tag = 0, whox = use_354;
  /* List status of account tracking. For 100% accuracy, this requires
   * WHOX ability (354 messages) and the extended-join and account-notify
   * capabilities to be enabled.
   */
  /* Check if CAPs are enabled */
  current = find_capability("extended-join");
  if (current && current->enabled) extjoin = 1;
  current = find_capability("account-notify");
  if (current && current->enabled) notify = 1;
  current = find_capability("account-tag");
  if (current && current->enabled) tag = 1;

  if (whox && notify && extjoin) {
    dprintf(idx, "%s", "    Account tracking: Enabled\n");
  } else {
    if (!details) {
      dprintf(idx, "    Account tracking: Best-effort (Missing capabilities:%s%s%s%s)\n",
                    whox ? "" : " WHOX", notify ? "" : " account-notify", extjoin ? "" : " extended-join",
                    details ? "" : ", see .status all for details");
    } else {
      dprintf(idx, "    Account tracking: Best-effort\n");
      if (!whox) {
        dprintf(idx, "%s", "      - WHOX missing           => Accounts will NOT be known after Eggdrop joins a channel (raw 315)\n");
      } else {
        dprintf(idx, "%s", "      - WHOX enabled           => Accounts will be known after Eggdrop joins a channel (raw 315)\n");
      }

      if (!notify) {
        dprintf(idx, "%s", "      - account-notify missing => Accounts will NOT update immediately when users log in or out\n");
      } else {
        dprintf(idx, "%s", "      - account-notify enabled => Accounts will update immediately when users log in or out\n");
      }
      if (!extjoin) {
        dprintf(idx, "%s", "      - extended-join missing  => Accounts will NOT be known immediately when a user joins (bind join)\n");
      } else {
        dprintf(idx, "%s", "      - extended-join enabled  => Accounts will be known immediately when a user joins (bind join)\n");
      }
      if (tag && (!whox || !notify || !extjoin)) {
        dprintf(idx, "%s", "      - account-tag enabled    => Accounts will update whenever someone messages a channel or this bot\n");
      }
      dprintf(idx, "%s", "      See doc/ACCOUNTS for more details\n");
    }
  }
}

static void irc_report(int idx, int details)
{
  struct flag_record fr = { FR_GLOBAL | FR_CHAN };
  char q[256], *p;
  int k, l;
  struct chanset_t *chan;
  op_strbuf_t _bch = {};

  op_strlcpy(q, "Channels: ", sizeof(q));
  k = 10;
  op_strbuf_init(&_bch);
  for (chan = chanset; chan; chan = chan->next) {
    if (idx != DP_STDOUT)
      get_user_flagrec(dcc[idx].user, &fr, chan->dname);
    if ((idx == DP_STDOUT) || glob_master(fr) || chan_master(fr)) {
      p = nullptr;
      if (!channel_inactive(chan)) {
        if (chan->status & CHAN_JUPED)
          p = MISC_JUPED;
        else if (!(chan->status & CHAN_ACTIVE))
          p = MISC_TRYING;
        else if (chan->status & CHAN_PEND)
          p = MISC_PENDING;
        else if ((chan->dname[0] != '+') && !me_op(chan))
          p = MISC_WANTOPS;
      }
      op_strbuf_clear(&_bch);
      op_strbuf_appendf(&_bch, "%s%s%s%s, ", chan->dname, p ? " (" : "",
                       p ? p : "", p ? ")" : "");
      l = (int) op_strbuf_len(&_bch);
      if ((k + l) > 70) {
        dprintf(idx, "    %s\n", q);
        op_strlcpy(q, "          ", sizeof(q));
        k = 10;
      }
      k = (int)(stpcpy(q + k, op_strbuf_str(&_bch)) - q);
    }
  }
  op_strbuf_free(&_bch);
  if (k > 10) {
    q[k - 2] = 0;
    dprintf(idx, "    %s\n", q);
  }
  tell_account_tracking_status(idx, details);
}

/* Many networks either support max_bans/invite/exempts/ *or*
 * they support max_modes. If they support max_modes, set each of
 * other sub-max settings equal to max_modes
 */
static void do_nettype(void)
{
  switch (net_type_int) {
  case NETT_EFNET:
  case NETT_HYBRID_EFNET:
    kick_method = 1;
    modesperline = 4;
    use_354 = 0;
    use_exempts = 1;
    use_invites = 1;
    max_bans = 100;
    max_exempts = 100;
    max_invites = 100;
    max_modes = 100;
    rfc_compliant = 1;
    include_lk = 0;
    break;
  case NETT_LIBERA:
    kick_method = 1;
    modesperline = 4;
    use_354 = 1;
    use_exempts = 1;
    use_invites = 1;
    max_exempts = 100;
    max_invites = 100;
    max_bans = 100;
    max_modes = 100;
    rfc_compliant = 1;
    include_lk = 0;
    break;
  case NETT_FREENODE:
    kick_method = 1;
    modesperline = 4;
    use_354 = 1;
    use_exempts = 1;
    use_invites = 1;
    max_bans = 100;
    max_exempts = 100;
    max_invites = 100;
    max_modes = 100;
    rfc_compliant = 1;
    include_lk = 0;
    break;
  case NETT_IRCNET:
    kick_method = 4;
    modesperline = 3;
    use_354 = 0;
    use_exempts = 1;
    use_invites = 1;
    max_bans = 64;
    max_exempts = 64;
    max_invites = 64;
    max_modes = 64;
    rfc_compliant = 1;
    include_lk = 1;
    break;
  case NETT_UNDERNET:
    kick_method = 1;
    modesperline = 6;
    use_354 = 1;
    use_exempts = 0;
    use_invites = 0;
    max_bans = 100;
    max_exempts = 0;
    max_invites = 0;
    max_modes = 100;
    rfc_compliant = 1;
    include_lk = 1;
    break;
  case NETT_DALNET:
    kick_method = 4;
    modesperline = 6;
    use_354 = 0;
    use_exempts = 1;
    use_invites = 1;
    max_bans = 200;
    max_exempts = 100;
    max_invites = 100;
    max_modes = 400;
    rfc_compliant = 0;
    include_lk = 1;
    break;
  case NETT_QUAKENET:
    kick_method = 1;
    modesperline = 6;
    use_354 = 1;
    use_exempts = 0;
    use_invites = 0;
    max_bans = 45;
    max_exempts = 0;
    max_invites = 0;
    max_modes = 45;
    rfc_compliant = 1;
    include_lk = 1;
    break;
  case NETT_RIZON:
    kick_method = 1;
    modesperline = 4;
    use_354 = 0;
    use_exempts = 1;
    use_invites = 1;
    max_bans = 250;
    max_exempts = 250;
    max_invites = 250;
    max_modes = 250;
    rfc_compliant = 1;
    include_lk = 0;
    break;
  case NETT_TWITCH:
    keepnick = 0;
    twitch = 1;
    kick_method = 1;
    modesperline = 4;
    use_354 = 0;
    use_exempts = 1;
    use_invites = 1;
    max_bans = 100;
    max_exempts = 100;
    max_invites = 100;
    max_modes = 100;
    rfc_compliant = 1;
    include_lk = 0;
    break;
  default:
    break;
  }
  /* Update all rfc_ function pointers */
  add_hook(HOOK_RFC_CASECMP, (Function) (intptr_t) rfc_compliant);
}

[[maybe_unused]] static char *traced_nettype(ClientData cdata,
                            Tcl_Interp *irp,
                            EGG_CONST char *name1,
                            EGG_CONST char *name2, int flags)
{
  do_nettype();
  return nullptr;
}

[[maybe_unused]] static char *traced_rfccompliant(ClientData cdata,
                                 Tcl_Interp *irp,
                                 EGG_CONST char *name1,
                                 EGG_CONST char *name2, int flags)
{
  /* This hook forces eggdrop core to change the rfc_ match function
   * links to point to the rfc compliant versions if rfc_compliant
   * is 1, or to the normal version if it's 0.
   */
  add_hook(HOOK_RFC_CASECMP, (Function) (intptr_t) rfc_compliant);
  return nullptr;
}

static int irc_expmem(void)
{
  return 0;
}

static char *irc_close(void)
{
  struct chanset_t *chan;

  /* Force bot to part all channels */
  dprintf(DP_MODE, "JOIN 0\n");

  for (chan = chanset; chan; chan = chan->next)
    clear_channel(chan, CHAN_RESETALL);
  del_bind_table(H_topc);
  del_bind_table(H_splt);
  del_bind_table(H_sign);
  del_bind_table(H_rejn);
  del_bind_table(H_part);
  del_bind_table(H_nick);
  del_bind_table(H_mode);
  del_bind_table(H_kick);
  del_bind_table(H_invt);
  del_bind_table(H_join);
  del_bind_table(H_pubm);
  del_bind_table(H_pub);
  del_bind_table(H_need);
  del_bind_table(H_ircaway);
  del_bind_table(H_awaynotify);
  del_bind_table(H_account);
  del_bind_table(H_chghost);
  rem_tcl_strings(mystrings);
  rem_tcl_ints(myints);
  rem_builtins(H_dcc, irc_dcc);
  rem_builtins(H_msg, C_msg);
  rem_builtins(H_raw, irc_raw);
  rem_builtins(H_rawt, irc_rawt);
  Tcl_DecrRefCount(tcl_account);
  rem_builtins(H_isupport, irc_isupport_binds);
  rem_tcl_commands(tclchan_cmds);
  rem_help_reference("irc.help");
  del_hook(HOOK_MINUTELY, (Function) check_expired_chanstuff);
  del_hook(HOOK_5MINUTELY, (Function) status_log);
  del_hook(HOOK_ADD_MODE, (Function) real_add_mode);
  del_hook(HOOK_IDLE, (Function) flush_modes);
  Tcl_UntraceVar(interp, "rfc-compliant",
                 TCL_TRACE_READS | TCL_TRACE_WRITES | TCL_TRACE_UNSETS,
                 traced_rfccompliant, nullptr);
  Tcl_UntraceVar(interp, "net-type",
                 TCL_TRACE_READS | TCL_TRACE_WRITES | TCL_TRACE_UNSETS,
                 traced_nettype, nullptr);
  /* Clean up per-user flood tracking tables. */
  if (flood_user_ht) {
    op_htab_destroy(flood_user_ht, nullptr, nullptr);
    flood_user_ht = nullptr;
  }
  if (flood_user_bh) {
    op_bh_destroy(flood_user_bh);
    flood_user_bh = nullptr;
  }
  /* Clean up sticky-reban block heap (event callbacks free individual ctx). */
  if (sticky_reban_bh) {
    op_bh_destroy(sticky_reban_bh);
    sticky_reban_bh = nullptr;
  }
  /* Clean up WHOIS rate-limit tables. */
  if (whois_rl_ht) {
    op_htab_destroy(whois_rl_ht, nullptr, nullptr);
    whois_rl_ht = nullptr;
  }
  if (whois_rl_bh) {
    op_bh_destroy(whois_rl_bh);
    whois_rl_bh = nullptr;
  }
  module_undepend(MODULE_NAME);
  return nullptr;
}

EXPORT_SCOPE char *irc_start(Function *global_funcs);

static Function irc_table[] = {
  /* 0 - 3 */
  (Function) irc_start,
  (Function) irc_close,
  (Function) irc_expmem,
  (Function) irc_report,
  /* 4 - 7 */
  (Function) & H_splt,          /* p_tcl_bind_list              */
  (Function) & H_rejn,          /* p_tcl_bind_list              */
  (Function) & H_nick,          /* p_tcl_bind_list              */
  (Function) & H_sign,          /* p_tcl_bind_list              */
  /* 8 - 11 */
  (Function) & H_join,          /* p_tcl_bind_list              */
  (Function) & H_part,          /* p_tcl_bind_list              */
  (Function) & H_mode,          /* p_tcl_bind_list              */
  (Function) & H_kick,          /* p_tcl_bind_list              */
  /* 12 - 15 */
  (Function) & H_pubm,          /* p_tcl_bind_list              */
  (Function) & H_pub,           /* p_tcl_bind_list              */
  (Function) & H_topc,          /* p_tcl_bind_list              */
  (Function) recheck_channel,
  /* 16 - 19 */
  (Function) me_op,
  (Function) recheck_channel_modes,
  (Function) & H_need,          /* p_tcl_bind_list              */
  (Function) do_channel_part,
  /* 20 - 23 */
  (Function) check_this_ban,
  (Function) check_this_user,
  (Function) me_halfop,
  (Function) me_voice,
  /* 24 - 27 */
  (Function) getchanmode,
  (Function) reset_chan_info,
  (Function) & H_invt,          /* p_tcl_bind_list              */
  (Function) & twitch,          /* int                          */
  /* 28 - 31 */
  (Function) & H_ircaway,       /* p_tcl_bind_list              */
  (Function) flush_mode,        /* 29: flush pending mode queue */
  (Function) & H_chghost        /* p_tcl_bind_list              */
};

char *irc_start(Function *global_funcs)
{
  struct chanset_t *chan;

  global = global_funcs;

  module_register(MODULE_NAME, irc_table, 1, 5);
  if (!module_depend(MODULE_NAME, "eggdrop", 108, 0)) {
    module_undepend(MODULE_NAME);
    return "This module requires Eggdrop 1.8.0 or later.";
  }
  if (!(server_funcs = module_depend(MODULE_NAME, "server", 1, 5))) {
    module_undepend(MODULE_NAME);
    return "This module requires server module 1.5 or later.";
  }
  if (!(channels_funcs = module_depend(MODULE_NAME, "channels", 1, 1))) {
    module_undepend(MODULE_NAME);
    return "This module requires channels module 1.1 or later.";
  }
  for (chan = chanset; chan; chan = chan->next) {
    if (!channel_inactive(chan)) {
      if (chan->key_prot[0])
        dprintf(DP_SERVER, "JOIN %s %s\n",
                chan->name[0] ? chan->name : chan->dname, chan->key_prot);
      else
        dprintf(DP_SERVER, "JOIN %s\n",
                chan->name[0] ? chan->name : chan->dname);
    }
    chan->status &= ~(CHAN_ACTIVE | CHAN_PEND | CHAN_ASKEDBANS);
    chan->ircnet_status &= ~(CHAN_ASKED_INVITED | CHAN_ASKED_EXEMPTS);
  }
  add_hook(HOOK_MINUTELY, (Function) check_expired_chanstuff);
  add_hook(HOOK_5MINUTELY, (Function) status_log);
  add_hook(HOOK_ADD_MODE, (Function) real_add_mode);
  add_hook(HOOK_IDLE, (Function) flush_modes);
  Tcl_TraceVar(interp, "net-type",
               TCL_TRACE_READS | TCL_TRACE_WRITES | TCL_TRACE_UNSETS,
               traced_nettype, nullptr);
  Tcl_TraceVar(interp, "rfc-compliant",
               TCL_TRACE_READS | TCL_TRACE_WRITES | TCL_TRACE_UNSETS,
               traced_rfccompliant, nullptr);
  op_strlcpy(opchars, "@", sizeof(opchars));
  add_tcl_strings(mystrings);
  add_tcl_ints(myints);
  add_builtins(H_dcc, irc_dcc);
  add_builtins(H_msg, C_msg);
  add_builtins(H_raw, irc_raw);
  tcl_account = Tcl_NewStringObj("account", -1);
  Tcl_IncrRefCount(tcl_account);
  add_builtins(H_rawt, irc_rawt);
  add_builtins(H_isupport, irc_isupport_binds);
  add_tcl_commands(tclchan_cmds);
  add_help_reference("irc.help");
  H_topc = add_bind_table("topc", HT_STACKABLE, channels_5char);
  H_splt = add_bind_table("splt", HT_STACKABLE, channels_4char);
  H_sign = add_bind_table("sign", HT_STACKABLE, channels_5char);
  H_rejn = add_bind_table("rejn", HT_STACKABLE, channels_4char);
  H_part = add_bind_table("part", HT_STACKABLE, channels_5char);
  H_nick = add_bind_table("nick", HT_STACKABLE, channels_5char);
  H_mode = add_bind_table("mode", HT_STACKABLE, channels_6char);
  H_kick = add_bind_table("kick", HT_STACKABLE, channels_6char);
  H_invt = add_bind_table("invt", HT_STACKABLE, invite_4char);
  H_join = add_bind_table("join", HT_STACKABLE, channels_4char);
  H_pubm = add_bind_table("pubm", HT_STACKABLE, channels_5char);
  H_pub = add_bind_table("pub", 0, channels_5char);
  H_need = add_bind_table("need", HT_STACKABLE, channels_2char);
  H_ircaway = add_bind_table("ircaway", HT_STACKABLE, channels_5char);
  H_awaynotify = add_bind_table("awaynotify", HT_STACKABLE, channels_5char);
  H_account = add_bind_table("account", HT_STACKABLE, channels_5char);
  H_chghost = add_bind_table("chghost", HT_STACKABLE, channels_5char);
  do_nettype();
  return nullptr;
}

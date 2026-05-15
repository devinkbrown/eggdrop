/*
 * chan_enforce.c -- part of irc.mod
 *   flood detection, ban/mask enforcement, member checking
 */

static void check_exemptlist(struct chanset_t *chan, const char *from)
{
  masklist *e;
  int ok = 0;

  if (!use_exempts)
    return;

  for (e = chan->channel.exempt; e->mask[0]; e = e->next)
    if (match_addr(e->mask, from)) {
      add_mode(chan, '-', 'e', e->mask);
      ok = 1;
    }
  if (prevent_mixing && ok)
    flush_mode(chan, QUICK);
}

/* Check a channel and clean-out any more-specific matching masks.
 *
 * Moved all do_ban(), do_exempt() and do_invite() into this single function
 * as the code bloat is starting to get ridiculous <cybah>
 */
static void do_mask(struct chanset_t *chan, masklist *m, const char *mask, char mode)
{
  for (; m && m->mask[0]; m = m->next)
    if (cmp_masks(mask, m->mask) && rfc_casecmp(mask, m->mask))
      add_mode(chan, '-', mode, m->mask);
  add_mode(chan, '+', mode, mask);
  flush_mode(chan, QUICK);
}

/* This is a clone of detect_flood, but works for channel specificity now
 * and handles kick & deop as well.
 *
 * victim for flood-deop, account for flood-join
 */
static int detect_chan_flood(char *floodnick, char *floodhost, const char *from,
                             struct chanset_t *chan, int which, char *victim_or_account)
{
  char ftype[12], *p;
  struct userrec *u;
  memberlist *m;
  int thr = 0, lapse = 0;
  struct flag_record fr = { FR_GLOBAL | FR_CHAN };

  if (!chan || (which < 0) || (which >= FLOOD_CHAN_MAX))
    return 0;

  /* Okay, make sure i'm not flood-checking myself */
  if (match_my_nick(floodnick))
    return 0;

  /* My user@host (?) */
  if (!strcasecmp(floodhost, botuserhost))
    return 0;

  m = ismember(chan, floodnick);

  /* Do not punish non-existent channel members and IRC services like
   * ChanServ
   */
  if (!m && (which != FLOOD_JOIN))
    return 0;

  u = lookup_user_record(m, victim_or_account, from);
  get_user_flagrec(u, &fr, chan->dname);
  if (glob_bot(fr) || ((which == FLOOD_DEOP) && (glob_master(fr) ||
      chan_master(fr)) && (glob_friend(fr) || chan_friend(fr))) ||
      ((which == FLOOD_KICK) && (glob_master(fr) || chan_master(fr)) &&
      (glob_friend(fr) || chan_friend(fr))) || ((which != FLOOD_DEOP) &&
      (which != FLOOD_KICK) && (glob_friend(fr) || chan_friend(fr))) ||
      (channel_dontkickops(chan) && (chan_op(fr) || (glob_op(fr) &&
      !chan_deop(fr)))))
    return 0;

  /* Determine how many are necessary to make a flood. */
  switch (which) {
  case FLOOD_PRIVMSG:
  case FLOOD_NOTICE:
    thr = chan->flood_pub_thr;
    lapse = chan->flood_pub_time;
    strlcpy(ftype, "pub", sizeof(ftype));
    break;
  case FLOOD_CTCP:
    thr = chan->flood_ctcp_thr;
    lapse = chan->flood_ctcp_time;
    strlcpy(ftype, "ctcp", sizeof(ftype));
    break;
  case FLOOD_NICK:
    thr = chan->flood_nick_thr;
    lapse = chan->flood_nick_time;
    strlcpy(ftype, "nick", sizeof(ftype));
    break;
  case FLOOD_JOIN:
    thr = chan->flood_join_thr;
    lapse = chan->flood_join_time;
    strlcpy(ftype, "join", sizeof(ftype));
    break;
  case FLOOD_DEOP:
    thr = chan->flood_deop_thr;
    lapse = chan->flood_deop_time;
    strlcpy(ftype, "deop", sizeof(ftype));
    break;
  case FLOOD_KICK:
    thr = chan->flood_kick_thr;
    lapse = chan->flood_kick_time;
    strlcpy(ftype, "kick", sizeof(ftype));
    break;
  }
  if ((thr == 0) || (lapse == 0))
    return 0;                   /* no flood protection */

  if ((which == FLOOD_KICK) || (which == FLOOD_DEOP))
    p = floodnick;
  else {
    p = strchr(floodhost, '@');
    if (p) {
      p++;
    }
    if (!p)
      return 0;
  }
  if (rfc_casecmp(chan->floodwho[which], p)) {  /* new */
    strlcpy(chan->floodwho[which], p, sizeof chan->floodwho[which]);
    chan->floodtime[which] = now;
    chan->floodnum[which] = 1;
    return 0;
  }
  if (chan->floodtime[which] < now - lapse) {
    /* Flood timer expired, reset it */
    chan->floodtime[which] = now;
    chan->floodnum[which] = 1;
    return 0;
  }
  /* Deop'n the same person, sillyness ;) - so just ignore it */
  if (which == FLOOD_DEOP) {
    if (!rfc_casecmp(chan->deopd, victim_or_account))
      return 0;
    else
      strlcpy(chan->deopd, victim_or_account, sizeof chan->deopd);
  }
  chan->floodnum[which]++;
  if (chan->floodnum[which] >= thr) {   /* FLOOD */
    /* Reset counters */
    chan->floodnum[which] = 0;
    chan->floodtime[which] = 0;
    chan->floodwho[which][0] = 0;
    if (which == FLOOD_DEOP)
      chan->deopd[0] = 0;
    if (check_tcl_flud(floodnick, floodhost, u, ftype, chan->dname))
      return 0;
    switch (which) {
    case FLOOD_PRIVMSG:
    case FLOOD_NOTICE:
    case FLOOD_CTCP:
      /* Flooding chan! either by public or notice */
      if (!chan_sentkick(m) &&
          (me_op(chan) || (me_halfop(chan) && !chan_hasop(m)))) {
        putlog(LOG_MODES, chan->dname, IRC_FLOODKICK, floodnick);
        dprintf(DP_MODE, "KICK %s %s :%s\n", chan->name, floodnick, CHAN_FLOOD);
        m->flags |= SENTKICK;
      }
      return 1;
    case FLOOD_JOIN:
    case FLOOD_NICK:
      if (use_exempts && (u_match_mask(global_exempts, from) ||
          u_match_mask_trie(chan->exempts, chan->exempt_ip_trie, from)))
        return 1;
      op_strbuf_t _bh;
      op_strbuf_init(&_bh);
      op_strbuf_appendf(&_bh, "*!*@%s", p);
      if (!isbanned(chan, op_strbuf_str(&_bh)) && (me_op(chan) || me_halfop(chan))) {
        check_exemptlist(chan, from);
        do_mask(chan, chan->channel.ban, op_strbuf_str(&_bh), 'b');
      }
      if ((u_match_mask(global_bans, from)) ||
          (u_match_mask_trie(chan->bans, chan->ban_ip_trie, from))) {
        op_strbuf_free(&_bh);
        return 1;               /* Already banned */
      }
      if (which == FLOOD_JOIN)
        putlog(LOG_MISC | LOG_JOIN, chan->dname, IRC_FLOODIGNORE3, p);
      else
        putlog(LOG_MISC | LOG_JOIN, chan->dname, IRC_FLOODIGNORE4, p);
      strlcpy(ftype + 4, " flood", sizeof(ftype) - 4);
      u_addban(chan, op_strbuf_str(&_bh), botnetnick, ftype, now + (60 * chan->ban_time), 0);
      if (!channel_enforcebans(chan) && (me_op(chan) || me_halfop(chan))) {
        op_strbuf_t _bs;

        op_strbuf_init(&_bs);
        for (m = chan->channel.member; m && m->nick[0]; m = m->next) {
          op_strbuf_clear(&_bs);
          op_strbuf_appendf(&_bs, "%s!%s", m->nick, m->userhost);
          if (wild_match(op_strbuf_str(&_bh), op_strbuf_str(&_bs)) && (m->joined >= chan->floodtime[which]) &&
              !chan_sentkick(m) && !match_my_nick(m->nick) && (me_op(chan) ||
              (me_halfop(chan) && !chan_hasop(m)))) {
            m->flags |= SENTKICK;
            if (which == FLOOD_JOIN)
              dprintf(DP_SERVER, "KICK %s %s :%s\n", chan->name, m->nick,
                      IRC_JOIN_FLOOD);
            else
              dprintf(DP_SERVER, "KICK %s %s :%s\n", chan->name, m->nick,
                      IRC_NICK_FLOOD);
          }
        }
        op_strbuf_free(&_bs);
      }
      op_strbuf_free(&_bh);
      return 1;
    case FLOOD_KICK:
      if ((me_op(chan) || (me_halfop(chan) && !chan_hasop(m))) &&
          !chan_sentkick(m)) {
        putlog(LOG_MODES, chan->dname, "Kicking %s, for mass kick.", floodnick);
        dprintf(DP_MODE, "KICK %s %s :%s\n", chan->name, floodnick,
                IRC_MASSKICK);
        m->flags |= SENTKICK;
      }
      return 1;
    case FLOOD_DEOP:
      if ((me_op(chan) || (me_halfop(chan) && !chan_hasop(m))) &&
          !chan_sentkick(m)) {
        putlog(LOG_MODES, chan->dname, CHAN_MASSDEOP, chan->dname, from);
        dprintf(DP_MODE, "KICK %s %s :%s\n",
                chan->name, floodnick, CHAN_MASSDEOP_KICK);
        m->flags |= SENTKICK;
      }
      return 1;
    }
  }
  return 0;
}

/* Given a [nick!]user@host, place a quick ban on them on a chan.
 */
static char *quickban(struct chanset_t *chan, char *uhost)
{
  static char s1[512];

  maskaddr(uhost, s1, chan->ban_type);
  do_mask(chan, chan->channel.ban, s1, 'b');
  return s1;
}

/* Kick any user (except friends/masters) with certain mask from channel
 * with a specified comment.  Ernst 18/3/1998
 */
static void kick_all(struct chanset_t *chan, char *hostmask,
                     const char *comment, int bantype)
{
  memberlist *m;
  op_strbuf_t kicknick, _s;
  struct flag_record fr = { FR_GLOBAL | FR_CHAN };
  int k, l, flushed;

  if (!me_op(chan) && !me_halfop(chan))
    return;

  k = 0;
  flushed = 0;
  op_strbuf_init(&kicknick);
  op_strbuf_init(&_s);
  for (m = chan->channel.member; m && m->nick[0]; m = m->next) {
    op_strbuf_clear(&_s);
    op_strbuf_appendf(&_s, "%s!%s", m->nick, m->userhost);
    get_user_flagrec(get_user_from_member(m), &fr, chan->dname);
    if ((me_op(chan) || (me_halfop(chan) && !chan_hasop(m))) &&
        match_addr(hostmask, op_strbuf_str(&_s)) && !chan_sentkick(m) &&
        !match_my_nick(m->nick) && !chan_issplit(m) &&
        !glob_friend(fr) && !chan_friend(fr) && !(use_exempts && ((bantype &&
        isexempted(chan, op_strbuf_str(&_s))) ||
        (u_match_mask(global_exempts, op_strbuf_str(&_s)) ||
        u_match_mask_trie(chan->exempts, chan->exempt_ip_trie,
                          op_strbuf_str(&_s))))) &&
        !(channel_dontkickops(chan) &&
        (chan_op(fr) || (glob_op(fr) && !chan_deop(fr))))) {
      if (!flushed) {
        /* We need to kick someone, flush eventual bans first */
        flush_mode(chan, QUICK);
        flushed += 1;
      }
      m->flags |= SENTKICK;     /* Mark as pending kick */
      if (op_strbuf_len(&kicknick))
        op_strbuf_append_cstr(&kicknick, ",");
      op_strbuf_append_cstr(&kicknick, m->nick);
      k += 1;
      l = strlen(chan->name) + op_strbuf_len(&kicknick) + strlen(comment) + 5;
      if ((kick_method != 0 && k == kick_method) || (l > 480)) {
        dprintf(DP_SERVER, "KICK %s %s :%s\n", chan->name, op_strbuf_str(&kicknick), comment);
        k = 0;
        op_strbuf_truncate(&kicknick, 0);
      }
    }
  }
  if (k > 0)
    dprintf(DP_SERVER, "KICK %s %s :%s\n", chan->name, op_strbuf_str(&kicknick), comment);
  op_strbuf_free(&_s);
  op_strbuf_free(&kicknick);
}

/* If any bans match this wildcard expression, refresh them on the channel.
 */
static void refresh_ban_kick(struct chanset_t *chan, const char *user, char *nick)
{
  maskrec *b;
  memberlist *m;
  int cycle;

  m = ismember(chan, nick);
  if (!m || chan_sentkick(m))
    return;

  /* Check global bans in first cycle and channel bans in second cycle. */
  for (cycle = 0; cycle < 2; cycle++) {
    for (b = cycle ? chan->bans : global_bans; b; b = b->next) {
      if (match_addr(b->mask, user)) {
        struct flag_record fr = { FR_GLOBAL | FR_CHAN };
        get_user_flagrec(get_user_from_member(m), &fr,
                         chan->dname);
        if (!glob_friend(fr) && !chan_friend(fr)) {
          op_strbuf_t _bc;
          op_strbuf_init(&_bc);
          add_mode(chan, '-', 'o', nick);       /* Guess it can't hurt. */
          check_exemptlist(chan, user);
          do_mask(chan, chan->channel.ban, b->mask, 'b');
          b->lastactive = now;
          if (b->desc && b->desc[0] != '@')
            op_strbuf_appendf(&_bc, "%s %s", IRC_PREBANNED, b->desc);
          else
            op_strbuf_init(&_bc);
          kick_all(chan, b->mask,
                   op_strbuf_len(&_bc) ? op_strbuf_str(&_bc) : IRC_YOUREBANNED, 0);
          op_strbuf_free(&_bc);
          return;               /* Drop out on 1st ban. */
        }
      }
    }
  }
}

/* This is a bit cumbersome at the moment, but it works... Any improvements
 * then feel free to have a go.. Jason
 */
static void refresh_exempt(struct chanset_t *chan, char *user)
{
  maskrec *e;
  masklist *b;
  int cycle;

  /* Check global exempts in first cycle and channel exempts in second cycle. */
  for (cycle = 0; cycle < 2; cycle++) {
    for (e = cycle ? chan->exempts : global_exempts; e; e = e->next) {
      if (mask_match(user, e->mask)) {
        for (b = chan->channel.ban; b && b->mask[0]; b = b->next) {
          if (b->mask[0] == '$')
            continue; /* skip extended bans, server-side matching only */
          if (mask_match(b->mask, user)) {
            if (e->lastactive < now - 60 && !isexempted(chan, e->mask)) {
              do_mask(chan, chan->channel.exempt, e->mask, 'e');
              e->lastactive = now;
            }
          }
        }
      }
    }
  }
}

static void refresh_invite(struct chanset_t *chan, const char *user)
{
  maskrec *i;
  int cycle;

  /* Check global invites in first cycle and channel invites in second cycle. */
  for (cycle = 0; cycle < 2; cycle++) {
    for (i = cycle ? chan->invites : global_invites; i; i = i->next) {
      if (match_addr(i->mask, user) &&
          ((i->flags & MASKREC_STICKY) || (chan->channel.mode & CHANINV))) {
        if (i->lastactive < now - 60 && !isinvited(chan, i->mask)) {
          do_mask(chan, chan->channel.invite, i->mask, 'I');
          i->lastactive = now;
          return;
        }
      }
    }
  }
}

/* Enforce all channel bans in a given channel.  Ernst 18/3/1998
 */
static void enforce_bans(struct chanset_t *chan)
{
  op_strbuf_t _bme;
  op_strbuf_init(&_bme);
  masklist *b;

  if (HALFOP_CANTDOMODE('b'))
    return;

  op_strbuf_appendf(&_bme, "%s!%s", botname, botuserhost);
  /* Go through all bans, kicking the users.
   * Skip extended bans ($a:, $z:, $r:, etc.) — server-side matching only. */
  for (b = chan->channel.ban; b && b->mask[0]; b = b->next) {
    if (b->mask[0] == '$')
      continue;
    if (!match_addr(b->mask, op_strbuf_str(&_bme)))
      if (!isexempted(chan, b->mask))
        kick_all(chan, b->mask, IRC_YOUREBANNED, 1);
  }
  op_strbuf_free(&_bme);
}

/* Make sure that all who are 'banned' on the userlist are actually in fact
 * banned on the channel.
 *
 * Note: Since i was getting a ban list, i assume i'm chop.
 */
static void recheck_bans(struct chanset_t *chan)
{
  maskrec *u;
  int cycle;

  /* Check global bans in first cycle and channel bans in second cycle. */
  for (cycle = 0; cycle < 2; cycle++) {
    for (u = cycle ? chan->bans : global_bans; u; u = u->next)
      if (!isbanned(chan, u->mask) && (!channel_dynamicbans(chan) ||
          (u->flags & MASKREC_STICKY)))
        add_mode(chan, '+', 'b', u->mask);
  }
}

/* Make sure that all who are exempted on the userlist are actually in fact
 * exempted on the channel.
 *
 * Note: Since i was getting an exempt list, i assume i'm chop.
 */
static void recheck_exempts(struct chanset_t *chan)
{
  maskrec *e;
  masklist *b;
  int cycle;

  /* Check global exempts in first cycle and channel exempts in second cycle. */
  for (cycle = 0; cycle < 2; cycle++) {
    for (e = cycle ? chan->exempts : global_exempts; e; e = e->next) {
      if (!isexempted(chan, e->mask) &&
          (!channel_dynamicexempts(chan) || (e->flags & MASKREC_STICKY)))
        add_mode(chan, '+', 'e', e->mask);
      for (b = chan->channel.ban; b && b->mask[0]; b = b->next) {
        if (mask_match(b->mask, e->mask) &&
            !isexempted(chan, e->mask))
          add_mode(chan, '+', 'e', e->mask);
        /* do_mask(chan, chan->channel.exempt, e->mask, 'e'); */
      }
    }
  }
}

/* Make sure that all who are invited on the userlist are actually in fact
 * invited on the channel.
 *
 * Note: Since i was getting an invite list, i assume i'm chop.
 */
static void recheck_invites(struct chanset_t *chan)
{
  maskrec *ir;
  int cycle;

  /* Check global invites in first cycle and channel invites in second cycle. */
  for (cycle = 0; cycle < 2; cycle++) {
    for (ir = cycle ? chan->invites : global_invites; ir; ir = ir->next) {
      /* If invite isn't set and (channel is not dynamic invites and not invite
       * only) or invite is sticky.
       */
      if (!isinvited(chan, ir->mask) && ((!channel_dynamicinvites(chan) &&
          !(chan->channel.mode & CHANINV)) || ir->flags & MASKREC_STICKY))
        add_mode(chan, '+', 'I', ir->mask);
      /* do_mask(chan, chan->channel.invite, ir->mask, 'I'); */
    }
  }
}

/* Resets the masks on the channel.
 */
static void resetmasks(struct chanset_t *chan, masklist *m, maskrec *mrec,
                       op_htab *mrec_ht, maskrec *global_masks,
                       op_htab *global_masks_ht, char mode)
{
  if (!me_op(chan) && (!me_halfop(chan) ||
      (strchr(NOHALFOPS_MODES, 'b') != nullptr) ||
      (strchr(NOHALFOPS_MODES, 'e') != nullptr) ||
      (strchr(NOHALFOPS_MODES, 'I') != nullptr)))
    return;

  /* Remove masks we didn't put there */
  for (; m && m->mask[0]; m = m->next) {
    if (!u_equals_mask(global_masks, global_masks_ht, m->mask) &&
        !u_equals_mask(mrec, mrec_ht, m->mask))
      add_mode(chan, '-', mode, m->mask);
  }

  /* Make sure the intended masks are still there */
  switch (mode) {
  case 'b':
    recheck_bans(chan);
    break;
  case 'e':
    recheck_exempts(chan);
    break;
  case 'I':
    recheck_invites(chan);
    break;
  default:
    putlog(LOG_MISC, "*", "(!) Invalid mode '%c' in resetmasks()", mode);
    break;
  }
}
static void check_this_ban(struct chanset_t *chan, char *banmask, int sticky)
{
  memberlist *m;
  op_strbuf_t _bu;
  op_strbuf_init(&_bu);

  if (HALFOP_CANTDOMODE('b'))
    return;

  op_strbuf_init(&_bu);
  for (m = chan->channel.member; m && m->nick[0]; m = m->next) {
    op_strbuf_clear(&_bu);
    op_strbuf_appendf(&_bu, "%s!%s", m->nick, m->userhost);
    if (match_addr(banmask, op_strbuf_str(&_bu)) &&
        !(use_exempts &&
          (u_match_mask(global_exempts, op_strbuf_str(&_bu)) ||
           u_match_mask_trie(chan->exempts, chan->exempt_ip_trie, op_strbuf_str(&_bu)))))
      refresh_ban_kick(chan, op_strbuf_str(&_bu), m->nick);
  }
  op_strbuf_free(&_bu);
  if (!isbanned(chan, banmask) && (!channel_dynamicbans(chan) || sticky))
    add_mode(chan, '+', 'b', banmask);
}

static void recheck_channel_modes(struct chanset_t *chan)
{
  int cur = chan->channel.mode, mns = chan->mode_mns_prot,
      pls = chan->mode_pls_prot;

  if (!(chan->status & CHAN_ASKEDMODES)) {
    if (pls & CHANINV && !(cur & CHANINV))
      add_mode(chan, '+', 'i', "");
    else if (mns & CHANINV && cur & CHANINV)
      add_mode(chan, '-', 'i', "");
    if (pls & CHANPRIV && !(cur & CHANPRIV))
      add_mode(chan, '+', 'p', "");
    else if (mns & CHANPRIV && cur & CHANPRIV)
      add_mode(chan, '-', 'p', "");
    if (pls & CHANSEC && !(cur & CHANSEC))
      add_mode(chan, '+', 's', "");
    else if (mns & CHANSEC && cur & CHANSEC)
      add_mode(chan, '-', 's', "");
    if (pls & CHANMODER && !(cur & CHANMODER))
      add_mode(chan, '+', 'm', "");
    else if (mns & CHANMODER && cur & CHANMODER)
      add_mode(chan, '-', 'm', "");
    if (pls & CHANNOCLR && !(cur & CHANNOCLR))
      add_mode(chan, '+', 'c', "");
    else if (mns & CHANNOCLR && cur & CHANNOCLR)
      add_mode(chan, '-', 'c', "");
    if (pls & CHANNOCTCP && !(cur & CHANNOCTCP))
      add_mode(chan, '+', 'C', "");
    else if (mns & CHANNOCTCP && cur & CHANNOCTCP)
      add_mode(chan, '-', 'C', "");
    if (pls & CHANREGON && !(cur & CHANREGON))
      add_mode(chan, '+', 'R', "");
    else if (mns & CHANREGON && cur & CHANREGON)
      add_mode(chan, '-', 'R', "");
    if (pls & CHANMODREG && !(cur & CHANMODREG))
      add_mode(chan, '+', 'M', "");
    else if (mns & CHANMODREG && cur & CHANMODREG)
      add_mode(chan, '-', 'M', "");
    if (pls & CHANLONLY && !(cur & CHANLONLY))
      add_mode(chan, '+', 'r', "");
    else if (mns & CHANLONLY && cur & CHANLONLY)
      add_mode(chan, '-', 'r', "");
    if (pls & CHANDELJN && !(cur & CHANDELJN))
      add_mode(chan, '+', 'D', "");
    else if (mns & CHANDELJN && cur & CHANDELJN)
      add_mode(chan, '-', 'D', "");
    if (pls & CHANSTRIP && !(cur & CHANSTRIP))
      add_mode(chan, '+', 'u', "");
    else if (mns & CHANSTRIP && cur & CHANSTRIP)
      add_mode(chan, '-', 'u', "");
    if (pls & CHANNONOTC && !(cur & CHANNONOTC))
      add_mode(chan, '+', 'N', "");
    else if (mns & CHANNONOTC && cur & CHANNONOTC)
      add_mode(chan, '-', 'N', "");
    if (pls & CHANNOAMSG && !(cur & CHANNOAMSG))
      add_mode(chan, '+', 'T', "");
    else if (mns & CHANNOAMSG && cur & CHANNOAMSG)
      add_mode(chan, '-', 'T', "");
    if (pls & CHANTOPIC && !(cur & CHANTOPIC))
      add_mode(chan, '+', 't', "");
    else if (mns & CHANTOPIC && cur & CHANTOPIC)
      add_mode(chan, '-', 't', "");
    if (pls & CHANNOMSG && !(cur & CHANNOMSG))
      add_mode(chan, '+', 'n', "");
    else if ((mns & CHANNOMSG) && (cur & CHANNOMSG))
      add_mode(chan, '-', 'n', "");
    if ((pls & CHANANON) && !(cur & CHANANON))
      add_mode(chan, '+', 'a', "");
    else if ((mns & CHANANON) && (cur & CHANANON))
      add_mode(chan, '-', 'a', "");
    if ((pls & CHANQUIET) && !(cur & CHANQUIET))
      add_mode(chan, '+', 'q', "");
    else if ((mns & CHANQUIET) && (cur & CHANQUIET))
      add_mode(chan, '-', 'q', "");
    if ((chan->limit_prot != 0) && (chan->channel.maxmembers == 0)) {
      add_mode(chan, '+', 'l', int_to_base10(chan->limit_prot));
    } else if ((mns & CHANLIMIT) && (chan->channel.maxmembers != 0))
      add_mode(chan, '-', 'l', "");
    if (chan->key_prot[0]) {
      if (rfc_casecmp(chan->channel.key, chan->key_prot) != 0) {
        if (chan->channel.key[0])
          add_mode(chan, '-', 'k', chan->channel.key);
        add_mode(chan, '+', 'k', chan->key_prot);
      }
    } else if ((mns & CHANKEY) && (chan->channel.key[0]))
      add_mode(chan, '-', 'k', chan->channel.key);
  }
}

static void check_this_member(struct chanset_t *chan, char *nick,
                              struct flag_record *fr)
{
  memberlist *m;
  char *p;

  m = ismember(chan, nick);
  if (!m || match_my_nick(nick) || (!me_op(chan) && !me_halfop(chan)))
    return;

#ifdef NO_HALFOP_CHANMODES
  if (me_op(chan)) {
#else
  if (me_op(chan) || me_halfop(chan)) {
#endif
    if (HALFOP_CANDOMODE('o')) {
      if (chan_hasop(m) && ((chan_deop(*fr) || (glob_deop(*fr) &&
          !chan_op(*fr))) || (channel_bitch(chan) && (!chan_op(*fr) &&
          !(glob_op(*fr) && !chan_deop(*fr))))) && !chan_stopcheck(m)) {
        add_mode(chan, '-', 'o', m->nick);
      }
      if (!chan_hasop(m) && (chan_op(*fr) || (glob_op(*fr) &&
          !chan_deop(*fr))) && (channel_autoop(chan) || glob_autoop(*fr) ||
          chan_autoop(*fr))) {
        if (!chan->aop_min) {
          if (!chan_stopcheck(m))
            add_mode(chan, '+', 'o', m->nick);
        }
        else {
          set_delay(chan, m->nick);
          m->flags |= SENTOP;
        }
      }
    }

    if (HALFOP_CANDOMODE('h')) {
      if (chan_hashalfop(m) && ((chan_dehalfop(*fr) || (glob_dehalfop(*fr) &&
          !chan_halfop(*fr)) || (channel_bitch(chan) && (!chan_halfop(*fr) &&
          !(glob_halfop(*fr) && !chan_dehalfop(*fr)))))) && !chan_stopcheck(m))
        add_mode(chan, '-', 'h', m->nick);
      if (!chan_sentop(m) && !chan_hasop(m) && !chan_hashalfop(m) &&
          (chan_halfop(*fr) || (glob_halfop(*fr) && !chan_dehalfop(*fr))) &&
          (channel_autohalfop(chan) || glob_autohalfop(*fr) ||
          chan_autohalfop(*fr))) {
        if (!chan->aop_min) {
          if (!chan_stopcheck(m))
            add_mode(chan, '+', 'h', m->nick);
        }
        else {
          set_delay(chan, m->nick);
          m->flags |= SENTHALFOP;
        }
      }
    }

    if (HALFOP_CANDOMODE('v')) {
      if (chan_hasvoice(m) && (chan_quiet(*fr) || (glob_quiet(*fr) &&
          !chan_voice(*fr))) && !chan_stopcheck(m))
        add_mode(chan, '-', 'v', m->nick);
      if (!chan_hasvoice(m) && !chan_hasop(m) && !chan_hashalfop(m) &&
          (chan_voice(*fr) || (glob_voice(*fr) && !chan_quiet(*fr))) &&
          (channel_autovoice(chan) || glob_gvoice(*fr) || chan_gvoice(*fr))) {
        if (!chan->aop_min) {
          if (!chan_stopcheck(m))
            add_mode(chan, '+', 'v', m->nick);
        }
        else {
          set_delay(chan, m->nick);
          m->flags |= SENTVOICE;
        }
      }
    }
  }

  if (!chan_stopcheck(m)) {
    if (!me_op(chan) && (!me_halfop(chan) ||
        (strchr(NOHALFOPS_MODES, 'b') != nullptr) ||
        (strchr(NOHALFOPS_MODES, 'e') != nullptr) ||
        (strchr(NOHALFOPS_MODES, 'I') != nullptr)))
      return;

    op_strbuf_t _bs;
    op_strbuf_init(&_bs);
    op_strbuf_appendf(&_bs, "%s!%s", m->nick, m->userhost);
    if (use_invites && (u_match_mask(global_invites, op_strbuf_str(&_bs)) ||
        u_match_mask_trie(chan->invites, chan->invite_ip_trie, op_strbuf_str(&_bs))))
      refresh_invite(chan, op_strbuf_str(&_bs));
    if (!(use_exempts && (u_match_mask(global_exempts, op_strbuf_str(&_bs)) ||
        u_match_mask_trie(chan->exempts, chan->exempt_ip_trie, op_strbuf_str(&_bs))))) {
      if (u_match_mask(global_bans, op_strbuf_str(&_bs)) ||
          u_match_mask_trie(chan->bans, chan->ban_ip_trie, op_strbuf_str(&_bs)))
        refresh_ban_kick(chan, op_strbuf_str(&_bs), m->nick);
      if (!chan_sentkick(m) && (chan_kick(*fr) || glob_kick(*fr)) &&
          (me_op(chan) || (me_halfop(chan) && !chan_hasop(m)))) {
        check_exemptlist(chan, op_strbuf_str(&_bs));
        (void)quickban(chan, m->userhost);
        p = get_user(&USERENTRY_COMMENT, get_user_from_member(m));
        dprintf(DP_SERVER, "KICK %s %s :%s\n", chan->name, m->nick,
                p ? p : IRC_POLITEKICK);
        m->flags |= SENTKICK;
      }
    }
    op_strbuf_free(&_bs);
  }
}

static void check_this_user(char *hand, int delete, char *host)
{
  memberlist *m;
  struct userrec *u;
  struct chanset_t *chan;
  struct flag_record fr = { FR_GLOBAL | FR_CHAN };
  op_strbuf_t _s;

  op_strbuf_init(&_s);
  for (chan = chanset; chan; chan = chan->next)
    for (m = chan->channel.member; m && m->nick[0]; m = m->next) {
      op_strbuf_clear(&_s);
      op_strbuf_appendf(&_s, "%s!%s", m->nick, m->userhost);
      u = get_user_from_member(m);
      if ((u && !strcasecmp(u->handle, hand) && delete < 2) ||
          (!u && delete == 2 && match_addr(host, op_strbuf_str(&_s)))) {
        u = delete ? nullptr : u;
        get_user_flagrec(u, &fr, chan->dname);
        check_this_member(chan, m->nick, &fr);
      }
    }
  op_strbuf_free(&_s);
}

/* Things to do when i just became a chanop:
 */
static void recheck_channel(struct chanset_t *chan, int dobans)
{
  memberlist *m;
  struct flag_record fr = { FR_GLOBAL | FR_CHAN };
  struct userrec *u;
  static int stacking = 0;
  int stop_reset = 0;

  if (stacking || !userlist)
    return;

  stacking++;
  /* Okay, sort through who needs to be deopped. */
  for (m = chan->channel.member; m && m->nick[0]; m = m->next) {
    u = get_user_from_member(m);
    get_user_flagrec(u, &fr, chan->dname);
    if (glob_bot(fr) && chan_hasop(m) && !match_my_nick(m->nick))
      stop_reset = 1;
    /* Perhaps we were halfop and tried to halfop/kick the user earlier but
     * the server rejected the request, so let's try again. */
    m->flags &= ~(SENTHALFOP | SENTKICK);
    check_this_member(chan, m->nick, &fr);
  }
  /* Most IRCDs nowadays require +h/+o for getting e/I lists,
   * so if we're still waiting for these, we'll request them here.
   * In case we got them on join, nothing will be done */
  if (chan->ircnet_status & (CHAN_ASKED_EXEMPTS | CHAN_ASKED_INVITED)) {
    chan->ircnet_status &= ~(CHAN_ASKED_EXEMPTS | CHAN_ASKED_INVITED);
    reset_chan_info(chan, CHAN_RESETEXEMPTS | CHAN_RESETINVITED, 1);
  }
  if (dobans) {
    if (channel_nouserbans(chan) && !stop_reset)
      resetbans(chan);
    else
      recheck_bans(chan);
    if (use_invites) {
      if (channel_nouserinvites(chan) && !stop_reset)
        resetinvites(chan);
      else
        recheck_invites(chan);
    }
    if (use_exempts) {
      if (channel_nouserexempts(chan) && !stop_reset)
        resetexempts(chan);
      else
        recheck_exempts(chan);
    }
    if (channel_enforcebans(chan))
      enforce_bans(chan);
    if ((chan->status & CHAN_ASKEDMODES) && !channel_inactive(chan))
      dprintf(DP_MODE, "MODE %s\n", chan->name);
    recheck_channel_modes(chan);
  }
  stacking--;
}

static void set_delay(struct chanset_t *chan, char *nick)
{
  time_t a_delay;
  int aop_min, aop_max, aop_diff, count = 0;
  memberlist *m, *m2;

  m = ismember(chan, nick);
  if (!m)
    return;

  /* aop-delay 5:30 -- aop_min:aop_max */
  aop_min = chan->aop_min;
  aop_max = chan->aop_max;
  aop_diff = aop_max - aop_min;

  /* If either min or max is less than or equal to 0 we don't delay. */
  if ((aop_min <= 0) || (aop_max <= 0)) {
    a_delay = now + 1;

  /* Use min value for delay if min greater then or equal to max or if the
   * difference of max and min is greater than RANDOM_MAX (sanity check).
   */
  } else if ((aop_min >= aop_max) || (aop_diff > RANDOM_MAX)) {
    a_delay = now + aop_min;

  /* Set a random delay based on the difference of max and min */
  } else {
    a_delay = now + randint(aop_diff) + aop_min + 1;
  }

  for (m2 = chan->channel.member; m2 && m2->nick[0]; m2 = m2->next)
    if (m2->delay && !(m2->flags & FULL_DELAY))
      count++;

  if (count) {
    for (m2 = chan->channel.member; m2 && m2->nick[0]; m2 = m2->next) {
      if (m2->delay && !(m2->flags & FULL_DELAY)) {
        m2->delay = a_delay;

        if (count + 1 >= modesperline)
          m2->flags |= FULL_DELAY;

      }
    }
  }

  if (count + 1 >= modesperline)
    m->flags |= FULL_DELAY;

  m->delay = a_delay;
}

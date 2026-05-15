/*
 * chan_handlers.c -- part of irc.mod
 *   IRC protocol handlers: WHO/NAMES, numerics, join/part/kick/nick/quit,
 *   message/notice, topic, ISUPPORT, ban/exempt/invite lists
 */

static time_t last_ctcp = (time_t) 0L;
static int count_ctcp = 0;
static time_t last_invtime = (time_t) 0L;
static char last_invchan[CHANNELLEN + 1] = "";
static char botflag005;

static int got315(char *from, char *msg);

/* ID length for !channels.
 */
constexpr int CHANNEL_ID_LEN = 5;

/* got 324: mode status
 * <server> 324 <to> <channel> <mode>
 */
static int got324(char *from, char *msg)
{
  int i = 1;
  bool ok = false;
  char *p, *q, *chname;
  struct chanset_t *chan;

  newsplit(&msg);
  chname = newsplit(&msg);
  chan = findchan(chname);
  if (!chan) {
    putlog(LOG_MISC, "*", "%s: %s", IRC_UNEXPECTEDMODE, chname);
    dprintf(DP_SERVER, "PART %s\n", chname);
    return 0;
  }
  if (chan->status & CHAN_ASKEDMODES)
    ok = true;
  chan->status &= ~CHAN_ASKEDMODES;
  chan->channel.mode = 0;
  while (msg[i] != 0) {
    if (msg[i] == 'i')
      chan->channel.mode |= CHANINV;
    if (msg[i] == 'p')
      chan->channel.mode |= CHANPRIV;
    if (msg[i] == 's')
      chan->channel.mode |= CHANSEC;
    if (msg[i] == 'm')
      chan->channel.mode |= CHANMODER;
    if (msg[i] == 'c')
      chan->channel.mode |= CHANNOCLR;
    if (msg[i] == 'C')
      chan->channel.mode |= CHANNOCTCP;
    if (msg[i] == 'R')
      chan->channel.mode |= CHANREGON;
    if (msg[i] == 'M')
      chan->channel.mode |= CHANMODREG;
    if (msg[i] == 'r')
      chan->channel.mode |= CHANLONLY;
    if (msg[i] == 'D')
      chan->channel.mode |= CHANDELJN;
    if (msg[i] == 'u')
      chan->channel.mode |= CHANSTRIP;
    if (msg[i] == 'N')
      chan->channel.mode |= CHANNONOTC;
    if (msg[i] == 'T')
      chan->channel.mode |= CHANNOAMSG;
    if (msg[i] == 'd')
      chan->channel.mode |= CHANINVIS;
    if (msg[i] == 't')
      chan->channel.mode |= CHANTOPIC;
    if (msg[i] == 'n')
      chan->channel.mode |= CHANNOMSG;
    if (msg[i] == 'a')
      chan->channel.mode |= CHANANON;
    if (msg[i] == 'q')
      chan->channel.mode |= CHANQUIET;
    if (msg[i] == 'k') {
      chan->channel.mode |= CHANKEY;
      p = strchr(msg, ' ');
      if (p != nullptr) {          /* Test for null key assignment */
        p++;
        q = strchr(p, ' ');
        if (q != nullptr) {
          *q = 0;
          set_key(chan, p);
          memmove(p, q + 1, strlen(q + 1) + 1);
        } else {
          set_key(chan, p);
          *p = 0;
        }
      }
      if ((chan->channel.mode & CHANKEY) && (!chan->channel.key[0] ||
          !strcmp("*", chan->channel.key)))
        /* Undernet use to show a blank channel key if one was set when
         * you first joined a channel; however, this has been replaced by
         * an asterisk and this has been agreed upon by other major IRC
         * networks so we'll check for an asterisk here as well
         * (guppy 22Dec2001) */
        chan->status |= CHAN_ASKEDMODES;
    }
    if (msg[i] == 'l') {
      p = strchr(msg, ' ');
      if (p != nullptr) {          /* test for null limit assignment */
        p++;
        q = strchr(p, ' ');
        if (q != nullptr) {
          *q = 0;
          chan->channel.maxmembers = egg_atoi(p);
          memmove(p, q + 1, strlen(q + 1) + 1);
        } else {
          chan->channel.maxmembers = egg_atoi(p);
          *p = 0;
        }
      }
    }
    i++;
  }
  if (ok)
    recheck_channel_modes(chan);
  return 0;
}


static int got352or4(struct chanset_t *chan, char *user, const char *host,
                     char *nick, const char *flags, char *account)
{
  memberlist *m;

  m = ismember(chan, nick);     /* In my channel list copy? */
  if (!m) {                     /* Nope, so update */
    m = newmember(chan);        /* Get a new channel entry */
    m->joined = m->split = m->delay = 0L;       /* Don't know when he joined */
    m->flags = 0;               /* No flags for now */
    m->last = now;              /* Last time I saw him */
  }
  strlcpy(m->nick, nick, sizeof m->nick);        /* Store the nick in list */
  if (chan->channel.member_ht)
    op_htab_set(chan->channel.member_ht, m->nick, m, nullptr);
  /* Store the userhost */
  {
    op_strbuf_t _b;
    op_strbuf_init(&_b);
    op_strbuf_appendf(&_b, "%s@%s", user, host);
    strlcpy(m->userhost, op_strbuf_str(&_b), sizeof m->userhost);
    op_strbuf_free(&_b);
  }
  /* Combine n!u@h */
  if (match_my_nick(nick)) {    /* Is it me? */
    if (!m->joined)
      m->joined = now;
    strlcpy(botuserhost, m->userhost, sizeof(botuserhost));   /* Yes, save my own userhost */
  }
  m->flags |= WHO_SYNCED;
  /* IRCX/Ophion: ~ prefix means channel owner (+q).  Must be checked
   * before the standard opchars so that owners are not mis-flagged
   * only as CHANOP when they hold the higher CHANOWNER status.
   */
  if (strchr(flags, '~') != nullptr)
    m->flags |= (CHANOWNER | CHANOP | WASOP);
  else
    m->flags &= ~CHANOWNER;
  if (strpbrk(flags, opchars) != nullptr)
    m->flags |= (CHANOP | WASOP);
  else if (!(m->flags & CHANOWNER))
    m->flags &= ~(CHANOP | WASOP);
  if (strchr(flags, '%') != nullptr)
    m->flags |= (CHANHALFOP | WASHALFOP);
  else
    m->flags &= ~(CHANHALFOP | WASHALFOP);
  if (strchr(flags, '+') != nullptr)
    m->flags |= CHANVOICE;
  else
    m->flags &= ~CHANVOICE;
  if (strchr(flags, 'G') != nullptr)
    m->flags |= IRCAWAY;
  else
    m->flags &= ~IRCAWAY;
  if (strchr(flags, botflag005) != nullptr)
    m->flags |= IRCBOT;
  else
    m->flags &= ~IRCBOT;
  if (!(m->flags & (CHANVOICE | CHANOP | CHANHALFOP | CHANOWNER)))
    m->flags |= STOPWHO;
  if (match_my_nick(nick) && any_ops(chan) && !me_op(chan)) {
    check_tcl_need(chan->dname, "op");
    if (chan->need_op[0])
      do_tcl("need-op", chan->need_op);
  }

  /* Update accountname in channel records, 0 means logged out */
  /* A 0 is not a change from "" */
  if (account) {
    if (!strcmp(account, "0")) {
      /* normalize "logged out" to "*" */
      account = "*";
    }
    setaccount(nick, account);
  }
  return 0;
}

/* got a 352: who info!
 */
static int got352(char *from, char *msg)
{
  char *nick, *user, *host, *chname, *flags;
  struct chanset_t *chan;

  newsplit(&msg);               /* Skip my nick - efficiently */
  chname = newsplit(&msg);      /* Grab the channel */
  chan = findchan(chname);      /* See if I'm on channel */
  if (chan) {                   /* Am I? */
    user = newsplit(&msg);      /* Grab the user */
    host = newsplit(&msg);      /* Grab the host */
    newsplit(&msg);             /* Skip the server */
    nick = newsplit(&msg);      /* Grab the nick */
    flags = newsplit(&msg);     /* Grab the flags */
    got352or4(chan, user, host, nick, flags, nullptr);
  }
  return 0;
}

/* got a 366 from Twitch; this is a hack that should only be used for Twitch.
 * We should be very clear on the intent of this function- it is not to handle
 * 353 in a normal way, it is only used to fake a reply for Eggdrop so that it
 * knows it is on the channel, since the usual WHO command does not exist here.
 */
static int gottwitch366(char *from, char *msg) {
  char *nick, *chname;
  struct chanset_t *chan;
  char fakemsg[NICKLEN + UHOSTLEN + 15];

  if (net_type_int != NETT_TWITCH) {   /* Seriously- this is only for twitch */
    return 0;
  }

  nick = newsplit(&msg);
  chname = newsplit(&msg);
  chan = findchan(chname);
  if (chan) {
  /* Skip the rest of the message, we only care about the bot itself, and
   * 353s are unreliable on Twitch, so why bother. We'll get other users when
   * TWITCH sends the mass JOIN message.
   */
    chan->status |= CHAN_PEND; /* Channel needs to be PENDING for 1st join */
    {
      op_strbuf_t _bhost;
      op_strbuf_init(&_bhost);
      op_strbuf_appendf(&_bhost, "%s.tmi.twitch.tv", nick);
      got352or4(chan, nick, op_strbuf_str(&_bhost), nick, "H", nullptr);
      op_strbuf_free(&_bhost);
    }
    {
      op_strbuf_t _b;
      op_strbuf_init(&_b);
      op_strbuf_appendf(&_b, "%s %s :End of /who", nick, chan->dname);
      strlcpy(fakemsg, op_strbuf_str(&_b), sizeof fakemsg);
      op_strbuf_free(&_b);
    }
    got315(from, fakemsg);  /* Send end of WHO, to get chan to ACTIVE state */
  }
  return 0;
}

/* got a 354: who info! - ircu style whox
 */
static int got354(char *from, char *msg)
{
  char *nick, *user, *host, *chname, *flags, *account = nullptr;
  struct chanset_t *chan;

  if (use_354) {
    newsplit(&msg);             /* Skip my nick - efficiently */
    if (strncmp(msg, "222", strlen("222"))) {
      return 0;                 /* ignore request without our query type, could be different arguments */
    }
    newsplit(&msg);           /* Skip our query-type magic number" */
    if (msg[0] && (strchr(CHANMETA, msg[0]) != nullptr)) {
      chname = newsplit(&msg);  /* Grab the channel */
      chan = findchan(chname);  /* See if I'm on channel */
      if (chan) {               /* Am I? */
        user = newsplit(&msg);  /* Grab the user (ident) - field 'u' */
        host = newsplit(&msg);  /* Grab the host          - field 'h' */
        nick = newsplit(&msg);  /* Grab the nick          - field 'n' */
        flags = newsplit(&msg); /* Grab the flags         - field 'f' */
        account = newsplit(&msg);   /* Grab the account name */
        fixcolon(account);
        got352or4(chan, user, host, nick, flags, account);
      }
    }
  }
  return 0;
}

/* React to IRCv3 CHGHOST command. CHGHOST changes the hostname and/or
 * ident of the user. Format:
 * :geo!awesome@eggdrop.com CHGHOST tehgeo foo.io
 * changes user hostmask to tehgeo@foo.io
 */
static int gotchghost(char *from, char *msg) {
  struct flag_record fr = { FR_GLOBAL | FR_CHAN };
  struct userrec *u;
  struct chanset_t *chan;
  memberlist *m;
  char *nick, *ident, buf[MSGMAX], *s1=buf, *chname;

  strlcpy(s1, from, sizeof buf);
  nick = splitnick(&s1);
  ident = newsplit(&msg);  /* Get the ident */
  /* Update my own internal hostmask */
  if (match_my_nick(nick)) {
    {
      op_strbuf_t _b;
      op_strbuf_init(&_b);
      op_strbuf_appendf(&_b, "%s@%s", ident, msg);
      strlcpy(botuserhost, op_strbuf_str(&_b), UHOSTMAX);
      op_strbuf_free(&_b);
    }
  }
  /* Run the bind for each channel the user is on */
  for (chan = chanset; chan; chan = chan->next) {
    chname = chan->dname;
    m = ismember(chan, nick);
    if (m) {
      u = get_user_from_member(m);
      {
        op_strbuf_t _b;
        op_strbuf_init(&_b);
        op_strbuf_appendf(&_b, "%s@%s", ident, msg);
        strlcpy(m->userhost, op_strbuf_str(&_b), sizeof m->userhost);
        op_strbuf_free(&_b);
      }
      {
        op_strbuf_t _b;
        op_strbuf_init(&_b);
        op_strbuf_appendf(&_b, "%s %s!%s@%s", chname, nick, ident, msg);
        check_tcl_chghost(nick, from, op_strbuf_str(&_b), u, chname, ident, msg);
        op_strbuf_free(&_b);
      }
      get_user_flagrec(u, &fr, chan->dname);
      check_this_member(chan, m->nick, &fr);
    }
  }
  /* Username for nick could be different after host change, invalidate cache */
  clear_chanlist_member(nick);
  return 0;
}

/* got 353: NAMES
 * <server> 353 <client> <symbol> <chan> :[+/@]nick [+/@]nick ....
 *
 * if userhost-in-names is enabled, nick is nick@userhost.com
 * this function is added solely to handle userhost-in-names stuff, and will
 * update hostnames for nicks received
 */
static int got353(char *from, char *msg)
{
  struct capability *current;
  char prefixchars[64];
  char *nameptr, *chname, *uhost, *nick, *p, *host = nullptr;
  struct chanset_t *chan = nullptr;

  if ((current = find_capability("userhost-in-names")) && current->enabled) {
    strlcpy(prefixchars, isupport_get_prefixchars(), sizeof prefixchars);
    newsplit(&msg);
    newsplit(&msg); /* Get rid of =, @, or * symbol */
    chname = newsplit(&msg);
    nameptr = newsplit(&msg);
    fixcolon(nameptr);
    while ((uhost = newsplit(&nameptr))) {
      if (!strcmp(uhost, "")) {
        break;
      }
      fixcolon(uhost);
      nick = splitnick(&uhost);
      /* Strip @, +, etc chars prefixed to nicks in NAMES */
      for (int i = 0; prefixchars[i]; i++) {
        if(nick[0] == prefixchars[i]) {
          nick=nick+1;
        }
      }
      if ((nick[0] == '+') || (nick[0] == '%')) {
        nick=nick+1;
      }
      p = strchr(uhost, '@');
      if (p) {
        *p = 0;
        host = p+1;
      }
      chan = findchan(chname);      /* See if I'm on channel */
      if (chan && host) {
        /* Pretend we got a WHO and pass the info we got from NAMES */
        got352or4(chan, uhost, host, nick, "", nullptr);
      }
    }
    /* The assumption here is the user enabled userhost-in-names because WHO
     * is disabled. We remove the pending flag here because we'll never get a
     * WHO to do it.
     */
    if (chan) {
      chan->status |= CHAN_ACTIVE;
      chan->status &= ~CHAN_PEND;
    }
  }
  return 0;
}

/* React to 396 numeric (HOSTHIDDEN), sent when user mode +x (hostmasking) was
 * successfully set. Format:
 * :barjavel.freenode.net 396 BeerBot unaffiliated/geo/bot/beerbot :is now your hidden host (set by services.)
 */
static int got396(char *from, char *msg)
{
  char *nick, *ident, *uhost, userbuf[UHOSTLEN];

  nick = newsplit(&msg);
  if (match_my_nick(nick)) {  /* Double check this really is for me */
    char *saveptr = nullptr;
    strlcpy(userbuf, botuserhost, sizeof userbuf);
    ident = strtok_r(userbuf, "@", &saveptr);
    uhost = newsplit(&msg);
    if (ident) {
      {
        op_strbuf_t _b;
        op_strbuf_init(&_b);
        op_strbuf_appendf(&_b, "%s@%s", ident, uhost);
        strlcpy(botuserhost, op_strbuf_str(&_b), UHOSTMAX);
        op_strbuf_free(&_b);
      }
      check_tcl_event("hidden-host");
    }
  }
  return 0;
}

/* got 315: end of who
 * <server> 315 <to> <chan> :End of /who
 */
static int got315(char *from, char *msg)
{
  char *chname, *key;
  struct chanset_t *chan;

  newsplit(&msg);
  chname = newsplit(&msg);
  chan = findchan(chname);
  if (!chan || !channel_pending(chan)) /* Left channel before we got a 315? */
    return 0;

  sync_members(chan);
  chan->status |= CHAN_ACTIVE;
  chan->status &= ~CHAN_PEND;
  check_tcl_event_arg("got-chanlist", chname);
  if (!ismember(chan, botname)) {      /* Am I on the channel now?          */
    putlog(LOG_MISC | LOG_JOIN, chan->dname, "Oops, I'm not really on %s.",
           chan->dname);
    if (net_type_int != NETT_TWITCH) {
      clear_channel(chan, CHAN_RESETALL);
      chan->status &= ~CHAN_ACTIVE;
    }

    key = chan->channel.key[0] ? chan->channel.key : chan->key_prot;
    if (key[0])
      dprintf(DP_SERVER, "JOIN %s %s\n",
              chan->name[0] ? chan->name : chan->dname, key);
    else {
      dprintf(DP_SERVER, "JOIN %s\n",
              chan->name[0] ? chan->name : chan->dname);
    }
  } else if (me_op(chan))
    recheck_channel(chan, 1);
  else if (chan->channel.members == 1)
    chan->status |= CHAN_STOP_CYCLE;
  return 0;                            /* Don't check for I-Lines here.     */
}

/* Got 335 (user is a bot) */
static int got335(char *from, char *msg)
{
  struct chanset_t *chan;
  memberlist *m;
  char *nick;

  {
    char *saveptr = nullptr;
    nick = strtok_r(msg, " ", &saveptr);
  }
  /* Run for each channel the user is on */
  for (chan = chanset; chan; chan = chan->next) {
    m = ismember(chan, nick);
    if (m) {
      m->flags |= IRCBOT;
    }
  }
  return 0;
}

/* Got AWAY message; only valid for IRCv3 away-notify capability */
static int gotaway(char *from, char *msg)
{
  struct userrec *u;
  struct chanset_t *chan;
  memberlist *m;
  char buf[MSGMAX], *nick, *s1 = buf, *chname;

  strlcpy(s1, from, sizeof buf);
  nick = splitnick(&s1);
  /* Run the bind for each channel the user is on */
  for (chan = chanset; chan; chan = chan->next) {
    chname = chan->dname;
    m = ismember(chan, nick);
    if (m) {
      u = get_user_from_member(m);
      {
        op_strbuf_t _b;
        op_strbuf_init(&_b);
        op_strbuf_appendf(&_b, "%s %s", chname, from);
        check_tcl_ircaway(nick, from, op_strbuf_str(&_b), u, chname, msg);
        op_strbuf_free(&_b);
      }
      if (strlen(msg)) {
        m->flags |= IRCAWAY;
        fixcolon(msg);
        putlog(LOG_MODES, chan->dname, "%s is now away: %s", from, msg);
      } else {
        m->flags &= ~IRCAWAY;
        putlog(LOG_MODES, chan->dname, "%s has returned from away status", from);
      }
    }
  }
  return 0;
}

/* got 367: ban info
 * <server> 367 <to> <chan> <ban> [placed-by] [timestamp]
 */
static int got367(char *from, char *origmsg)
{
  char *ban, *who, *chname, buf[511], *msg;
  struct chanset_t *chan;

  strlcpy(buf, origmsg, sizeof buf);
  msg = buf;
  newsplit(&msg);
  chname = newsplit(&msg);
  chan = findchan(chname);
  if (!chan || !(channel_pending(chan) || channel_active(chan)))
    return 0;
  ban = newsplit(&msg);
  who = newsplit(&msg);
  /* Extended timestamp format? */
  if (who[0])
    newban(chan, ban, who);
  else
    newban(chan, ban, "existent");
  return 0;
}

/* got 368: end of ban list
 * <server> 368 <to> <chan> :etc
 */
static int got368(char *from, char *msg)
{
  struct chanset_t *chan;
  char *chname;

  /* Okay, now add bans that i want, which aren't set yet */
  newsplit(&msg);
  chname = newsplit(&msg);
  chan = findchan(chname);
  if (chan)
    chan->status &= ~CHAN_ASKEDBANS;
  /* If i sent a mode -b on myself (deban) in got367, either
   * resetbans() or recheck_bans() will flush that.
   */
  return 0;
}

/* got 348: ban exemption info
 * <server> 348 <to> <chan> <exemption>
 */
static int got348(char *from, char *origmsg)
{
  char *exempt, *who, *chname, buf[511], *msg;
  struct chanset_t *chan;

  if (use_exempts == 0)
    return 0;

  strlcpy(buf, origmsg, sizeof buf);
  msg = buf;
  newsplit(&msg);
  chname = newsplit(&msg);
  chan = findchan(chname);
  if (!chan || !(channel_pending(chan) || channel_active(chan)))
    return 0;
  exempt = newsplit(&msg);
  who = newsplit(&msg);
  /* Extended timestamp format? */
  if (who[0])
    newexempt(chan, exempt, who);
  else
    newexempt(chan, exempt, "existent");
  return 0;
}

/* got 349: end of ban exemption list
 * <server> 349 <to> <chan> :etc
 */
static int got349(char *from, char *msg)
{
  struct chanset_t *chan;
  char *chname;

  if (use_exempts == 1) {
    newsplit(&msg);
    chname = newsplit(&msg);
    chan = findchan(chname);
    if (chan)
      chan->ircnet_status &= ~CHAN_ASKED_EXEMPTS;
  }
  return 0;
}

/* got 346: invite exemption info
 * <server> 346 <to> <chan> <exemption>
 */
static int got346(char *from, char *origmsg)
{
  char *invite, *who, *chname, buf[511], *msg;
  struct chanset_t *chan;

  strlcpy(buf, origmsg, sizeof buf);
  msg = buf;
  if (use_invites == 0)
    return 0;
  newsplit(&msg);
  chname = newsplit(&msg);
  chan = findchan(chname);
  if (!chan || !(channel_pending(chan) || channel_active(chan)))
    return 0;
  invite = newsplit(&msg);
  who = newsplit(&msg);
  /* Extended timestamp format? */
  if (who[0])
    newinvite(chan, invite, who);
  else
    newinvite(chan, invite, "existent");
  return 0;
}

/* got 347: end of invite exemption list
 * <server> 347 <to> <chan> :etc
 */
static int got347(char *from, char *msg)
{
  struct chanset_t *chan;
  char *chname;

  if (use_invites == 1) {
    newsplit(&msg);
    chname = newsplit(&msg);
    chan = findchan(chname);
    if (chan)
      chan->ircnet_status &= ~CHAN_ASKED_INVITED;
  }
  return 0;
}

/* Too many channels.
 */
static int got405(char *from, char *msg)
{
  char *chname;

  newsplit(&msg);
  chname = newsplit(&msg);
  putlog(LOG_MISC, "*", IRC_TOOMANYCHANS, chname);
  return 0;
}

/* This is only of use to us with !channels. We get this message when
 * attempting to join a non-existent !channel... The channel must be
 * created by sending 'JOIN !!<channel>'. <cybah>
 *
 * 403 - ERR_NOSUCHCHANNEL
 */
static int got403(char *from, char *msg)
{
  char *chname;
  struct chanset_t *chan;

  newsplit(&msg);
  chname = newsplit(&msg);
  if (chname && chname[0] == '!') {
    chan = findchan_by_dname(chname);
    if (!chan) {
      chan = findchan(chname);
      if (!chan)
        return 0;               /* Ignore it */
      /* We have the channel unique name, so we have attempted to join
       * a specific !channel that doesnt exist. Now attempt to join the
       * channel using it's short name.
       */
      putlog(LOG_MISC, "*",
             "Unique channel %s does not exist... Attempting to join with "
             "short name.", chname);
      dprintf(DP_SERVER, "JOIN %s\n", chan->dname);
    } else {
      /* We have found the channel, so the server has given us the short
       * name. Prefix another '!' to it, and attempt the join again...
       */
      putlog(LOG_MISC, "*",
             "Channel %s does not exist... Attempting to create it.", chname);
      dprintf(DP_SERVER, "JOIN !%s\n", chan->dname);
    }
  }
  return 0;
}

/* got 471: can't join channel, full
 */
static int got471(char *from, char *msg)
{
  char *chname;
  struct chanset_t *chan;

  newsplit(&msg);
  chname = newsplit(&msg);
  /* !channel short names (also referred to as 'description names'
   * can be received by skipping over the unique ID.
   */
  if ((chname[0] == '!') && (strlen(chname) > CHANNEL_ID_LEN)) {
    chname += CHANNEL_ID_LEN;
    chname[0] = '!';
  }
  /* We use dname because name is first set on JOIN and we might not
   * have joined the channel yet.
   */
  chan = findchan_by_dname(chname);
  if (chan) {
    putlog(LOG_JOIN, chan->dname, IRC_CHANFULL, chan->dname);
    check_tcl_need(chan->dname, "limit");

    chan = findchan_by_dname(chname);
    if (!chan)
      return 0;

    if (chan->need_limit[0])
      do_tcl("need-limit", chan->need_limit);
  } else
    putlog(LOG_JOIN, chname, IRC_CHANFULL, chname);
  return 0;
}

/* got 473: can't join channel, invite only
 */
static int got473(char *from, char *msg)
{
  char *chname;
  struct chanset_t *chan;

  newsplit(&msg);
  chname = newsplit(&msg);
  /* !channel short names (also referred to as 'description names'
   * can be received by skipping over the unique ID.
   */
  if ((chname[0] == '!') && (strlen(chname) > CHANNEL_ID_LEN)) {
    chname += CHANNEL_ID_LEN;
    chname[0] = '!';
  }
  /* We use dname because name is first set on JOIN and we might not
   * have joined the channel yet.
   */
  chan = findchan_by_dname(chname);
  if (chan) {
    putlog(LOG_JOIN, chan->dname, IRC_CHANINVITEONLY, chan->dname);
    check_tcl_need(chan->dname, "invite");

    chan = findchan_by_dname(chname);
    if (!chan)
      return 0;

    if (chan->need_invite[0])
      do_tcl("need-invite", chan->need_invite);
  } else
    putlog(LOG_JOIN, chname, IRC_CHANINVITEONLY, chname);
  return 0;
}

/* got 474: can't join channel, banned
 */
static int got474(char *from, char *msg)
{
  char *chname;
  struct chanset_t *chan;

  newsplit(&msg);
  chname = newsplit(&msg);
  /* !channel short names (also referred to as 'description names'
   * can be received by skipping over the unique ID.
   */
  if ((chname[0] == '!') && (strlen(chname) > CHANNEL_ID_LEN)) {
    chname += CHANNEL_ID_LEN;
    chname[0] = '!';
  }
  /* We use dname because name is first set on JOIN and we might not
   * have joined the channel yet.
   */
  chan = findchan_by_dname(chname);
  if (chan) {
    putlog(LOG_JOIN, chan->dname, IRC_BANNEDFROMCHAN, chan->dname);
    check_tcl_need(chan->dname, "unban");

    chan = findchan_by_dname(chname);
    if (!chan)
      return 0;

    if (chan->need_unban[0])
      do_tcl("need-unban", chan->need_unban);
  } else
    putlog(LOG_JOIN, chname, IRC_BANNEDFROMCHAN, chname);
  return 0;
}

/* got 475: can't join channel, bad key
 */
static int got475(char *from, char *msg)
{
  char *chname;
  struct chanset_t *chan;

  newsplit(&msg);
  chname = newsplit(&msg);
  /* !channel short names (also referred to as 'description names'
   * can be received by skipping over the unique ID.
   */
  if ((chname[0] == '!') && (strlen(chname) > CHANNEL_ID_LEN)) {
    chname += CHANNEL_ID_LEN;
    chname[0] = '!';
  }
  /* We use dname because name is first set on JOIN and we might not
   * have joined the channel yet.
   */
  chan = findchan_by_dname(chname);
  if (chan) {
    putlog(LOG_JOIN, chan->dname, IRC_BADCHANKEY, chan->dname);
    if (chan->channel.key[0]) {
      op_free(chan->channel.key);
      chan->channel.key = (char *) channel_malloc(1);
      chan->channel.key[0] = 0;

      if (chan->key_prot[0])
        dprintf(DP_SERVER, "JOIN %s %s\n", chan->dname, chan->key_prot);
      else
        dprintf(DP_SERVER, "JOIN %s\n", chan->dname);
    } else {
      check_tcl_need(chan->dname, "key");

      chan = findchan_by_dname(chname);
      if (!chan)
        return 0;

      if (chan->need_key[0])
        do_tcl("need-key", chan->need_key);
    }
  } else
    putlog(LOG_JOIN, chname, IRC_BADCHANKEY, chname);
  return 0;
}

/* got invitation. Updated 2019 to handle IRCv3 invite-notify capability
 * where invites seen may not be for you, so we have to check the target and
 * and ignore if it is not for us.
 */
static int gotinvite(char *from, char *msg)
{
  char *nick, *key, *invitee;
  struct chanset_t *chan;

  invitee = newsplit(&msg);
  fixcolon(msg);
  nick = splitnick(&from);
  check_tcl_invite(nick, from, msg, invitee);
/* Because who needs RFCs? Freakin IRCv3... */
  if (!match_my_nick(invitee)) {
    putlog(LOG_DEBUG, "*", "Received invite notification for %s to %s by %s.",
            invitee, msg, nick);
    return 1;
  }
  if (!rfc_casecmp(last_invchan, msg))
    if (now - last_invtime < 30)
      return 0; /* Two invites to the same channel in 30 seconds? */
  putlog(LOG_MISC, "*", "%s!%s invited me to %s", nick, from, msg);
  strlcpy(last_invchan, msg, sizeof last_invchan);
  last_invtime = now;
  chan = findchan(msg);
  if (!chan)
    /* Might be a short-name */
    chan = findchan_by_dname(msg);

  if (chan && (channel_pending(chan) || channel_active(chan)))
    dprintf(DP_HELP, "NOTICE %s :I'm already here.\n", nick);
  else if (chan && !channel_inactive(chan)) {

    key = chan->channel.key[0] ? chan->channel.key : chan->key_prot;
    if (key[0])
      dprintf(DP_SERVER, "JOIN %s %s\n",
              chan->name[0] ? chan->name : chan->dname, key);
    else
      dprintf(DP_SERVER, "JOIN %s\n",
              chan->name[0] ? chan->name : chan->dname);
  }
  return 0;
}

/* Set the topic.
 */
static void set_topic(struct chanset_t *chan, char *k)
{
  if (chan->channel.topic)
    op_free(chan->channel.topic);
  if (k && k[0]) {
    chan->channel.topic = op_strdup(k);
  } else
    chan->channel.topic = nullptr;
}

/* Topic change.
 */
static int gottopic(char *from, char *msg)
{
  char *nick, *chname;
  memberlist *m;
  struct chanset_t *chan;
  struct userrec *u;

  chname = newsplit(&msg);
  fixcolon(msg);
  nick = splitnick(&from);
  chan = findchan(chname);
  if (chan) {
    putlog(LOG_JOIN, chan->dname, "Topic changed on %s by %s!%s: %s",
           chan->dname, nick, from, msg);
    m = ismember(chan, nick);
    if (m != nullptr)
      m->last = now;
    set_topic(chan, msg);
    u = lookup_user_record(m, m ? m->account : nullptr, from);
    check_tcl_topc(nick, from, u, chan->dname, msg);
  }
  return 0;
}

/* 331: no current topic for this channel
 * <server> 331 <to> <chname> :etc
 */
static int got331(char *from, char *msg)
{
  char *chname;
  struct chanset_t *chan;

  newsplit(&msg);
  chname = newsplit(&msg);
  chan = findchan(chname);
  if (chan) {
    set_topic(chan, nullptr);
    check_tcl_topc("*", "*", nullptr, chan->dname, "");
  }
  return 0;
}

/* 332: topic on a channel i've just joined
 * <server> 332 <to> <chname> :topic goes here
 */
static int got332(char *from, char *msg)
{
  struct chanset_t *chan;
  char *chname;

  newsplit(&msg);
  chname = newsplit(&msg);
  chan = findchan(chname);
  if (chan) {
    fixcolon(msg);
    set_topic(chan, msg);
    check_tcl_topc("*", "*", nullptr, chan->dname, msg);
  }
  return 0;
}

/* Set delay for +o, +h, or +v channel modes */

/* Got a join
 */
static int gotjoin(char *from, char *channame)
{
  char *nick, *p, buf[UHOSTLEN], *uhost = buf, *chname, *account = nullptr;
  char *ch_dname = nullptr;
  struct chanset_t *chan;
  memberlist *m;
  masklist *b;
  int extjoin = 0;
  struct capability *captmp;
  struct userrec *u;
  struct flag_record fr = { FR_GLOBAL | FR_CHAN };

  captmp = find_capability("extended-join");
  extjoin = captmp && captmp->enabled;

  strlcpy(uhost, from, sizeof buf);
  nick = splitnick(&uhost);
  // :nick!user@host JOIN :#chan
  chname = newsplit(&channame);
  fixcolon(chname);
  if (extjoin) {
    // :nick!user@host JOIN #chan account :realname
    account = newsplit(&channame);
  }
  chan = findchan_by_dname(chname);
  if (!chan && chname[0] == '!') {
    /* As this is a !channel, we need to search for it by display (short)
     * name now. This will happen when we initially join the channel, as we
     * don't know the unique channel name that the server has made up. <cybah>
     */
    int l_chname = strlen(chname);

    if (l_chname > (CHANNEL_ID_LEN + 1)) {
      {
        op_strbuf_t _b;
        op_strbuf_init(&_b);
        op_strbuf_appendf(&_b, "!%s", chname + (CHANNEL_ID_LEN + 1));
        ch_dname = op_strbuf_steal(&_b);
      }
      if (ch_dname) {
        chan = findchan_by_dname(ch_dname);
        if (!chan) {
          /* Hmm.. okay. Maybe the admin's a genius and doesn't know the
           * difference between id and descriptive channel names. Search
           * the channel name in the dname list using the id-name.
           */
          chan = findchan_by_dname(chname);
          if (chan) {
            /* Duh, I was right. Mark this channel as inactive and log
             * the incident.
             */
            chan->status |= CHAN_INACTIVE;
            putlog(LOG_MISC, "*", "Deactivated channel %s, because it uses "
                   "an ID channel-name. Use the descriptive name instead.",
                   chname);
            dprintf(DP_SERVER, "PART %s\n", chname);
            goto exit;
          }
        }
      }
    }
  } else if (!chan) {
    /* As this is not a !chan, we need to search for it by display name now.
     * Unlike !chan's, we don't need to remove the unique part.
     */
    chan = findchan_by_dname(chname);
  }

  if (!chan || channel_inactive(chan)) {
    if (match_my_nick(nick)) {
      putlog(LOG_MISC, "*", "joined %s but didn't want to!", chname);
      dprintf(DP_MODE, "PART %s\n", chname);
    }
  } else if (!channel_pending(chan)) {
    chan->status &= ~CHAN_STOP_CYCLE;

    detect_chan_flood(nick, uhost, from, chan, FLOOD_JOIN, extjoin ? account : nullptr);

    chan = findchan(chname);
    if (!chan) {
      if (ch_dname)
        chan = findchan_by_dname(ch_dname);
      else
        chan = findchan_by_dname(chname);
    }
    if (!chan)
      /* The channel doesn't exist anymore, so get out of here. */
      goto exit;

    if (!channel_active(chan) && !match_my_nick(nick)) {
      /* uh, what?!  i'm on the channel?! */
      putlog(LOG_MISC, chan->dname,
             "confused bot: guess I'm on %s and didn't realize it",
             chan->dname);
      chan->status |= CHAN_ACTIVE;
      chan->status &= ~CHAN_PEND;
      reset_chan_info(chan, CHAN_RESETALL, 1);
    } else {
      m = ismember(chan, nick);
      u = lookup_user_record(m, account ? account : nullptr, from);
      get_user_flagrec(u, &fr, chan->dname);
      if (m && m->split && !strcasecmp(m->userhost, uhost)) {
        check_tcl_rejn(nick, uhost, u, chan->dname);
        chan = findchan(chname);
        if (!chan) {
          if (ch_dname)
            chan = findchan_by_dname(ch_dname);
          else
            chan = findchan_by_dname(chname);
        }
        if (!chan)
          /* The channel doesn't exist anymore, so get out of here. */
          goto exit;

        /* The tcl binding might have deleted the current user. Recheck. */
        u = get_user_from_member(m);
        m->split = 0;
        m->last = now;
        m->delay = 0L;
        m->flags = (chan_hasop(m) ? WASOP : 0) | (chan_hashalfop(m) ? WASHALFOP : 0);
        m->user = u;
        set_handle_laston(chan->dname, u, now);
        m->flags |= STOPWHO;
        putlog(LOG_JOIN, chan->dname, "%s (%s) returned to %s.", nick, uhost,
               chan->dname);
      } else {
        if (m)
          killmember(chan, nick);
        m = newmember(chan);
        m->joined = now;
        m->split = 0L;
        m->flags = 0;
        m->last = now;
        m->delay = 0L;
        strlcpy(m->nick, nick, sizeof m->nick);
        if (chan->channel.member_ht)
          op_htab_set(chan->channel.member_ht, m->nick, m, nullptr);
        strlcpy(m->userhost, uhost, sizeof m->userhost);
        m->user = u;
        m->flags |= STOPWHO;

        if (extjoin) {
          u = lookup_user_record(m, account, from);
          /* calls check_tcl_account which can delete the channel */
          setaccount(nick, account);

          if (!(chan = findchan(chname)) && !(chan = findchan_by_dname(ch_dname ? ch_dname : chname))) {
            /* The channel doesn't exist anymore, so get out of here. */
            goto exit;
          }
        } else {
          memberlist *_mj = find_member_from_nick(nick);
          u = lookup_user_record(_mj, _mj ? _mj->account : nullptr, from);
        }
        check_tcl_join(nick, uhost, u, chan->dname);

        if (!(chan = findchan(chname)) && !(chan = findchan_by_dname(ch_dname ? ch_dname : chname))) {
          /* The channel doesn't exist anymore, so get out of here. */
          goto exit;
        }

        if (match_my_nick(nick)) {
          /* It was me joining! Need to update the channel record with the
           * unique name for the channel (as the server see's it). <cybah>
           */
          chan_htab_del(chan);
          strlcpy(chan->name, chname, sizeof chan->name);
          chan_htab_add(chan);
          chan->status &= ~CHAN_JUPED;

          /* ... and log us joining. Using chan->dname for the channel is
           * important in this case. As the config file will never contain
           * logs with the unique name.
           */
          if (chname[0] == '!')
            putlog(LOG_JOIN | LOG_MISC, chan->dname, "%s joined %s (%s)",
                   nick, chan->dname, chname);
          else
            putlog(LOG_JOIN | LOG_MISC, chan->dname, "%s joined %s.", nick,
                   chname);
          reset_chan_info(chan, (CHAN_RESETALL & ~CHAN_RESETTOPIC &
            (chan->channel.members == 1 ? ~CHAN_RESETWHO : CHAN_RESETALL)), /* do not remove myself again */
            1);

          /* IRCX/Ophion: on Ophion net-type, after joining a channel,
           * fire the ircx-join Tcl event so scripts can request owner.
           * Scripts use [ircxprop <chan> OWNERKEY <key>] to authenticate.
           */
          if (net_type_int == NETT_OPHION) {
            Tcl_SetVar(interp, "_ircx_chan", chan->dname, TCL_GLOBAL_ONLY);
            check_tcl_event("ircx-join");
          }

        } else {
          struct chanuserrec *cr;

          putlog(LOG_JOIN, chan->dname,
                 "%s (%s) joined %s.", nick, uhost, chan->dname);
          /* Don't re-display greeting if they've been on the channel
           * recently.
           */
          if (u) {
            struct laston_info *li = 0;

            cr = get_chanrec(u, chan->dname);
            if (!cr && no_chanrec_info)
              li = get_user(&USERENTRY_LASTON, u);
            if (channel_greet(chan) && use_info &&
                ((cr && now - cr->laston > wait_info) ||
                (no_chanrec_info && (!li || now - li->laston > wait_info)))) {
              char s1[512], *s;

              if (!(u->flags & USER_BOT)) {
                s = get_user(&USERENTRY_INFO, u);
                get_handle_chaninfo(u->handle, chan->dname, s1, sizeof s1);
                /* Locked info line overrides non-locked channel specific
                 * info line.
                 */
                if (!s || (s1[0] && (s[0] != '@' || s1[0] == '@')))
                  s = s1;
                if (s[0] == '@')
                  s++;
                if (s && s[0])
                  dprintf(DP_HELP, "PRIVMSG %s :[%s] %s\n", chan->name, nick,
                          s);
              }
            }
          }
          set_handle_laston(chan->dname, u, now);
        }
      }
      if (me_op(chan) || me_halfop(chan)) {
        /* Check for and reset exempts and invites.
         *
         * This will require further checking to account for when to use the
         * various modes.
         */
        if ((me_op(chan) || (strchr(NOHALFOPS_MODES, 'I') == nullptr)) &&
            (u_match_mask(global_invites, from) ||
            u_match_mask_trie(chan->invites, chan->invite_ip_trie, from)))
          refresh_invite(chan, from);
        if ((me_op(chan) || (strchr(NOHALFOPS_MODES, 'b') == nullptr)) &&
            (!use_exempts || (!u_match_mask(global_exempts, from) &&
            !u_match_mask_trie(chan->exempts, chan->exempt_ip_trie, from)))) {
          if (channel_enforcebans(chan) && !chan_op(fr) && !glob_op(fr) &&
              !glob_friend(fr) && !chan_friend(fr) && !chan_sentkick(m) &&
              (!use_exempts || !isexempted(chan, from)) && (me_op(chan) ||
              (me_halfop(chan) && !chan_hasop(m)))) {
            for (b = chan->channel.ban; b->mask[0]; b = b->next) {
              if (match_addr(b->mask, from)) {
                dprintf(DP_SERVER, "KICK %s %s :%s\n", chname, m->nick,
                        IRC_YOUREBANNED);
                m->flags |= SENTKICK;
                goto exit;
              }
            }
          }
          /* If it matches a ban, dispose of them. */
          if (u_match_mask(global_bans, from) || u_match_mask_trie(chan->bans, chan->ban_ip_trie, from))
            refresh_ban_kick(chan, from, nick);
          else if (!chan_sentkick(m) && (glob_kick(fr) || chan_kick(fr)) &&
                   (me_op(chan) || (me_halfop(chan) && !chan_hasop(m)))) {
            check_exemptlist(chan, from);
            (void)quickban(chan, from);
            p = get_user(&USERENTRY_COMMENT, get_user_from_member(m));
            dprintf(DP_MODE, "KICK %s %s :%s\n", chname, nick,
                    (p && (p[0] != '@')) ? p : IRC_COMMENTKICK);
            m->flags |= SENTKICK;
          }
        }
#ifdef NO_HALFOP_CHANMODES
        if (me_op(chan)) {
#endif
        if ((me_op(chan) || (strchr(NOHALFOPS_MODES, 'o') == nullptr)) &&
            (chan_op(fr) || (glob_op(fr) && !chan_deop(fr))) &&
            (channel_autoop(chan) || glob_autoop(fr) || chan_autoop(fr))) {
          if (!chan->aop_min)
            add_mode(chan, '+', 'o', nick);
          else {
            set_delay(chan, nick);
            m->flags |= SENTOP;
          }
        } else if ((me_op(chan) || (strchr(NOHALFOPS_MODES, 'h') == nullptr)) &&
                   (chan_halfop(fr) || (glob_halfop(fr) &&
                   !chan_dehalfop(fr))) && (channel_autohalfop(chan) ||
                   glob_autohalfop(fr) || chan_autohalfop(fr))) {
          if (!chan->aop_min)
            add_mode(chan, '+', 'h', nick);
          else {
            set_delay(chan, nick);
            m->flags |= SENTHALFOP;
          }
        } else if ((me_op(chan) || (strchr(NOHALFOPS_MODES, 'v') == nullptr)) &&
                   ((channel_autovoice(chan) && (chan_voice(fr) ||
                   (glob_voice(fr) && !chan_quiet(fr)))) ||
                   ((glob_gvoice(fr) || chan_gvoice(fr)) &&
                   !chan_quiet(fr)))) {
          if (!chan->aop_min)
            add_mode(chan, '+', 'v', nick);
          else {
            set_delay(chan, nick);
            m->flags |= SENTVOICE;
          }
        }
#ifdef NO_HALFOP_CHANMODES
        }
#endif
      }
    }
  }

exit:
  if (ch_dname)
    op_free(ch_dname);
  return 0;
}

/* Got a part
 */
static int gotpart(char *from, char *msg)
{
  char *nick, *chname, uhost[UHOSTLEN], *key;
  struct chanset_t *chan;
  struct userrec *u;
  memberlist *m;

  chname = newsplit(&msg);
  fixcolon(chname);
  fixcolon(msg);
  chan = findchan(chname);
  if (chan && channel_inactive(chan)) {
    clear_channel(chan, CHAN_RESETALL);
    chan->status &= ~(CHAN_ACTIVE | CHAN_PEND);
    return 0;
  }
  if (chan && !channel_pending(chan)) {
    strlcpy(uhost, from, sizeof uhost);
    nick = splitnick(&from);
    m = ismember(chan, nick);
    if (m)
      u = get_user_from_member(m);
    else
      u = get_user_by_host(uhost);
    if (!channel_active(chan)) {
      /* whoa! */
      putlog(LOG_MISC, chan->dname,
             "confused bot: guess I'm on %s and didn't realize it",
             chan->dname);
      chan->status |= CHAN_ACTIVE;
      chan->status &= ~CHAN_PEND;
      reset_chan_info(chan, CHAN_RESETALL, 1);
    }
    set_handle_laston(chan->dname, u, now);
    /* This must be directly above the killmember, in case we're doing anything
     * to the record that would affect the above */
    check_tcl_part(nick, from, u, chan->dname, msg);

    chan = findchan(chname);
    if (!chan)
      return 0;

    if (m)
      killmember(chan, nick);
    if (msg[0])
      putlog(LOG_JOIN, chan->dname, "%s (%s) left %s (%s).", nick, from,
             chan->dname, msg);
    else
      putlog(LOG_JOIN, chan->dname, "%s (%s) left %s.", nick, from,
             chan->dname);
    /* If it was me, all hell breaks loose... */
    if (match_my_nick(nick)) {
      clear_channel(chan, CHAN_RESETALL);
      chan->status &= ~(CHAN_ACTIVE | CHAN_PEND);
      if (!channel_inactive(chan)) {

        key = chan->channel.key[0] ? chan->channel.key : chan->key_prot;
        if (key[0])
          dprintf(DP_SERVER, "JOIN %s %s\n",
                  chan->name[0] ? chan->name : chan->dname, key);
        else
          dprintf(DP_SERVER, "JOIN %s\n",
                  chan->name[0] ? chan->name : chan->dname);
      }
    } else
      check_lonely_channel(chan);
  }
  return 0;
}

/* Got a kick
 */
static int gotkick(char *from, char *origmsg)
{
  char *nick, *whodid, *chname, buf[UHOSTLEN], *uhost;
  char buf2[511], *msg, *key;
  memberlist *m;
  struct chanset_t *chan;
  struct userrec *u;
  struct flag_record fr = { FR_GLOBAL | FR_CHAN };

  strlcpy(buf2, origmsg, sizeof buf2);
  msg = buf2;
  chname = newsplit(&msg);
  chan = findchan(chname);
  if (!chan)
    return 0;
  nick = newsplit(&msg);
  if (match_my_nick(nick) && channel_pending(chan) &&
      !channel_inactive(chan)) {
    chan->status &= ~(CHAN_ACTIVE | CHAN_PEND);

    key = chan->channel.key[0] ? chan->channel.key : chan->key_prot;
    if (key[0])
      dprintf(DP_SERVER, "JOIN %s %s\n",
              chan->name[0] ? chan->name : chan->dname, key);
    else
      dprintf(DP_SERVER, "JOIN %s\n",
              chan->name[0] ? chan->name : chan->dname);
    clear_channel(chan, CHAN_RESETALL);
    return 0; /* rejoin if kicked before getting needed info <Wcc[08/08/02]> */
  }
  if (channel_active(chan)) {
    fixcolon(msg);
    strlcpy(buf, from, sizeof buf);
    uhost = buf;
    whodid = splitnick(&uhost);
    detect_chan_flood(whodid, uhost, from, chan, FLOOD_KICK, nick);

    chan = findchan(chname);
    if (!chan)
      return 0;

    m = ismember(chan, whodid);
    u = lookup_user_record(m, m ? m->account : nullptr, from);
    if (m)
      m->last = now;
    /* This _needs_ to use chan->dname <cybah> */
    get_user_flagrec(u, &fr, chan->dname);
    set_handle_laston(chan->dname, u, now);
    check_tcl_kick(whodid, uhost, u, chan->dname, nick, msg);

    chan = findchan(chname);
    if (!chan)
      return 0;

    m = ismember(chan, nick);
    {
      op_strbuf_t _bk;
      op_strbuf_init(&_bk);
      const char *kicked;

      if (m) {
        struct userrec *u2;

        op_strbuf_appendf(&_bk, "%s!%s", m->nick, m->userhost);
        kicked = op_strbuf_str(&_bk);
        u2 = get_user_from_member(m);
        set_handle_laston(chan->dname, u2, now);
        maybe_revenge(chan, from, kicked, REVENGE_KICK);
      } else {
        op_strbuf_init(&_bk);
        kicked = nick;
      }
      putlog(LOG_MODES, chan->dname, "%s kicked from %s by %s: %s", kicked,
             chan->dname, from, msg);
      op_strbuf_free(&_bk);
    }
    /* Kicked ME?!? the sods! */
    if (match_my_nick(nick) && !channel_inactive(chan)) {
      chan->status &= ~(CHAN_ACTIVE | CHAN_PEND);

      key = chan->channel.key[0] ? chan->channel.key : chan->key_prot;
      if (key[0])
        dprintf(DP_SERVER, "JOIN %s %s\n",
                chan->name[0] ? chan->name : chan->dname, key);
      else
        dprintf(DP_SERVER, "JOIN %s\n",
                chan->name[0] ? chan->name : chan->dname);
      clear_channel(chan, CHAN_RESETALL);
    } else {
      killmember(chan, nick);
      check_lonely_channel(chan);
    }
  }
  return 0;
}

/* Got a nick change
 */
static int gotnick(char *from, char *msg)
{
  char *nick, *chname, s1[UHOSTLEN], buf[UHOSTLEN], *uhost = buf;
  unsigned char found = 0;
  memberlist *m, *mm;
  struct chanset_t *chan, *oldchan = nullptr;
  struct userrec *u;
  struct flag_record fr = { FR_GLOBAL | FR_CHAN };

  strlcpy(uhost, from, sizeof buf);
  nick = splitnick(&uhost);
  fixcolon(msg);
  clear_chanlist_member(nick);  /* Cache for nick 'nick' is meaningless now. */
  for (chan = chanset; chan; chan = chan->next) {
    oldchan = chan;
    chname = chan->dname;
    m = ismember(chan, nick);
    if (m) {
      putlog(LOG_JOIN, chan->dname, "Nick change: %s -> %s", nick, msg);
      m->last = now;
      if (rfc_casecmp(nick, msg)) {
        /* Not just a capitalization change */
        mm = ismember(chan, msg);
        if (mm) {
          /* Someone on channel with old nick?! */
          if (mm->split)
            putlog(LOG_JOIN, chan->dname,
                   "Possible future nick collision: %s", mm->nick);
          else
            putlog(LOG_MISC, chan->dname,
                   "* Bug: nick change to existing nick");
          killmember(chan, mm->nick);
        }
      }
      /*
       * Banned?
       */
      if (chan->channel.member_ht && m->nick[0])
        op_htab_del(chan->channel.member_ht, m->nick);
      strlcpy(m->nick, msg, sizeof m->nick);
      if (chan->channel.member_ht)
        op_htab_set(chan->channel.member_ht, m->nick, m, nullptr);
      detect_chan_flood(msg, uhost, from, chan, FLOOD_NICK, nullptr);

      if (!findchan_by_dname(chname)) {
        chan = oldchan;
        continue;
      }
      /* don't fill the serverqueue with modes or kicks in a nickflood */
      if (chan_sentkick(m) || chan_sentdeop(m) || chan_sentop(m) ||
          chan_sentdehalfop(m) || chan_senthalfop(m) || chan_sentdevoice(m) ||
          chan_sentvoice(m))
        m->flags |= STOPCHECK;
      /* Any pending kick or mode to the old nick is lost. */
      m->flags &= ~(SENTKICK | SENTDEOP | SENTOP | SENTDEHALFOP | SENTHALFOP |
                    SENTVOICE | SENTDEVOICE);
      /* nick-ban or nick is +k or something? */
      u = get_user_from_member(m);
      get_user_flagrec(u, &fr, chan->dname);
      check_this_member(chan, m->nick, &fr);
      /* Make sure this is in the loop, someone could have changed the record
       * in an earlier iteration of the loop. */
      found = 1;
      check_tcl_nick(nick, uhost, u, chan->dname, msg);

      if (!findchan_by_dname(chname)) {
        chan = oldchan;
        continue;
      }
    }
  }
  if (!found) {
    s1[0] = '*';
    s1[1] = 0;
    check_tcl_nick(nick, uhost, nullptr, s1, msg);
  }
  return 0;
}

/* Signoff, similar to part.
 */
static int gotquit(char *from, char *msg)
{
  char *nick, *chname, *p, *alt;
  int split = 0;
  memberlist *m;
  struct chanset_t *chan, *oldchan = nullptr;
  struct userrec *u;

  nick = splitnick(&from);
  fixcolon(msg);
  /* Fred1: Instead of expensive wild_match on signoff, quicker method.
   *        Determine if signoff string matches "%.% %.%", and only one
   *        space.
   */
  p = strchr(msg, ' ');
  if (p && (p == strrchr(msg, ' '))) {
    char *z1, *z2;

    *p = 0;
    z1 = strchr(p + 1, '.');
    z2 = strchr(msg, '.');
    if (z1 && z2 && (*(z1 + 1) != 0) && (z1 - 1 != p) &&
        (z2 + 1 != p) && (z2 != msg)) {
      /* Server split, or else it looked like it anyway (no harm in
       * assuming)
       */
      split = 1;
    } else
      *p = ' ';
  }
  for (chan = chanset; chan; chan = chan->next) {
    oldchan = chan;
    chname = chan->dname;
    m = ismember(chan, nick);
    if (m) {
      u = get_user_from_member(m);
      if (u)
        /* If you remove this, the bot will crash when the user record in
         * question is removed/modified during the tcl binds below, and the
         * users was on more than one monitored channel */
        set_handle_laston(chan->dname, u, now);
      if (split) {
        m->split = now;
        check_tcl_splt(nick, from, u, chan->dname);

        if (!findchan_by_dname(chname)) {
          chan = oldchan;
          continue;
        }
        putlog(LOG_JOIN, chan->dname, "%s (%s) got netsplit.", nick, from);
      } else {
        check_tcl_sign(nick, from, u, chan->dname, msg);

        if (!findchan_by_dname(chname)) {
          chan = oldchan;
          continue;
        }
        putlog(LOG_JOIN, chan->dname, "%s (%s) left irc: %s", nick, from, msg);
        killmember(chan, nick);
        check_lonely_channel(chan);
      }
    }
  }
  /* Our nick quit? if so, grab it. Heck, our altnick quit maybe, maybe
   * we want it.
   */
  if (keepnick) {
    alt = get_altbotnick();
    if (!rfc_casecmp(nick, origbotname)) {
      putlog(LOG_MISC, "*", IRC_GETORIGNICK, origbotname);
      dprintf(DP_SERVER, "NICK %s\n", origbotname);
    } else if (alt[0]) {
      if (!rfc_casecmp(nick, alt) && strcmp(botname, origbotname)) {
        putlog(LOG_MISC, "*", IRC_GETALTNICK, alt);
        dprintf(DP_SERVER, "NICK %s\n", alt);
      }
    }
  }
  return 0;
}

/* Got a private message.
 */
static int gotmsg(char *from, char *msg)
{
  char *to, *realto, buf[UHOSTLEN], *nick, buf2[512], *uhost = buf, *p, *p1,
       *code, *ctcp;
  int ctcp_count = 0, ignoring;
  struct chanset_t *chan;
  struct userrec *u;

  /* Only handle if message is to a channel or a STATUSMSG-prefixed channel
   * (e.g. @#channel for ops, +#channel for voiced).  STATUSMSG prefix chars
   * come from server 005 PREFIX; strip them to find the real channel name. */
  {
    const char *pfx = isupport_get_prefixchars();
    if (!strchr(CHANMETA, msg[0]) && !strchr(pfx, msg[0]))
      return 0;
  }

  to = newsplit(&msg);
  realto = to;
  {
    /* Strip leading STATUSMSG prefix chars (e.g. "@", "+") before the
     * channel name.  A status prefix always precedes a CHANMETA char. */
    const char *pfx = isupport_get_prefixchars();
    while (*realto && strchr(pfx, *realto) && realto[1] && strchr(CHANMETA, realto[1]))
      realto++;
  }
  chan = findchan(realto);
  if (!chan)
    return 0; /* Unknown channel; don't process. */

  fixcolon(msg);
  strlcpy(uhost, from, sizeof buf);
  nick = splitnick(&uhost);
  ignoring = match_ignore(from);

  /* Check for CTCP: */
  op_strbuf_clear(&ctcp_reply);
  p = strchr(msg, 1);
  while (p && *p) {
    p++;
    p1 = p;
    while ((*p != 1) && *p)
      p++;
    if (*p == 1) {
      *p = 0;
      ctcp = buf2;
      strlcpy(buf2, p1, sizeof buf2);
      memmove(p1 - 1, p + 1, strlen(p + 1) + 1);
      detect_chan_flood(nick, uhost, from, chan, strncmp(ctcp, "ACTION ", 7) ?
                        FLOOD_CTCP : FLOOD_PRIVMSG, nullptr);

      chan = findchan(realto);
      if (!chan)
        return 0;

      /* Respond to the first answer_ctcp */
      p = strchr(msg, 1);
      if (ctcp_count < answer_ctcp) {
        ctcp_count++;
        if (ctcp[0] != ' ') {
          code = newsplit(&ctcp);
          {
            memberlist *_mc = find_member_from_nick(nick);
            u = lookup_user_record(_mc, _mc ? _mc->account : nullptr, from);
          }
          if (!ignoring || trigger_on_ignore) {
            if (!check_tcl_ctcp(nick, uhost, u, to, code, ctcp)) {
              chan = findchan(realto);
              if (!chan)
                return 0;

              update_idle(chan->dname, nick);
            }
            if (!ignoring) {
              /* Log DCC, it's to a channel damnit! */
              if (!strcmp(code, "ACTION")) {
                putlog(LOG_PUBLIC, chan->dname, "Action: %s %s", nick, ctcp);
              } else {
                putlog(LOG_PUBLIC, chan->dname,
                       "CTCP %s: %s from %s (%s) to %s", code, ctcp, nick,
                       from, to);
              }
            }
          }
        }
      }
    }
  }

  /* Send out possible ctcp responses. */
  if (!op_strbuf_empty(&ctcp_reply)) {
    if (ctcp_mode != 2) {
      dprintf(DP_HELP, "NOTICE %s :%s\n", nick, op_strbuf_str(&ctcp_reply));
    } else {
      if (now - last_ctcp > flud_ctcp_time) {
        dprintf(DP_HELP, "NOTICE %s :%s\n", nick, op_strbuf_str(&ctcp_reply));
        count_ctcp = 1;
      } else if (count_ctcp < flud_ctcp_thr) {
        dprintf(DP_HELP, "NOTICE %s :%s\n", nick, op_strbuf_str(&ctcp_reply));
        count_ctcp++;
      }
      last_ctcp = now;
    }
  }

  if (msg[0]) {
    int result = 0;

    /* Check even if we're ignoring the host. (modified by Eule 17.7.99) */
    detect_chan_flood(nick, uhost, from, chan, FLOOD_PRIVMSG, nullptr);

    chan = findchan(realto);
    if (!chan)
      return 0;

    update_idle(chan->dname, nick);

    if (!ignoring || trigger_on_ignore) {
      result = check_tcl_pubm(nick, uhost, chan->dname, msg);

      if (!result || !exclusive_binds)
        if (check_tcl_pub(nick, uhost, chan->dname, msg))
          return 0;
    }

    if (!ignoring && result != 2) {
      if (to[0] == '@')
        putlog(LOG_PUBLIC, chan->dname, "@<%s> %s", nick, msg);
      else
        putlog(LOG_PUBLIC, chan->dname, "<%s> %s", nick, msg);
    }
  }
  return 0;
}

/* Got a private notice.
 */
static int gotnotice(char *from, char *msg)
{
  char *to, *realto, *nick, buf2[512], *p, *p1, buf[512], *uhost = buf;
  char *ctcp, *code;
  struct userrec *u;
  struct chanset_t *chan;
  int ignoring;

  {
    const char *pfx = isupport_get_prefixchars();
    if (!strchr(CHANMETA, *msg) && !strchr(pfx, *msg))
      return 0;
  }
  ignoring = match_ignore(from);
  to = newsplit(&msg);
  realto = to;
  {
    const char *pfx = isupport_get_prefixchars();
    while (*realto && strchr(pfx, *realto) && realto[1] && strchr(CHANMETA, realto[1]))
      realto++;
  }
  chan = findchan(realto);
  if (!chan)
    return 0;                   /* Notice to an unknown channel?? */
  fixcolon(msg);
  strlcpy(uhost, from, sizeof buf);
  nick = splitnick(&uhost);
  {
    memberlist *_mn = find_member_from_nick(nick);
    u = lookup_user_record(_mn, _mn ? _mn->account : nullptr, from);
  }
  /* Check for CTCP: */
  p = strchr(msg, 1);
  while (p && *p) {
    p++;
    p1 = p;
    while ((*p != 1) && *p)
      p++;
    if (*p == 1) {
      *p = 0;
      ctcp = buf2;
      strlcpy(ctcp, p1, sizeof(buf2));
      memmove(p1 - 1, p + 1, strlen(p + 1) + 1);
      p = strchr(msg, 1);
      detect_chan_flood(nick, uhost, from, chan,
                        strncmp(ctcp, "ACTION ", 7) ?
                        FLOOD_CTCP : FLOOD_PRIVMSG, nullptr);

      chan = findchan(realto);
      if (!chan)
        return 0;

      if (ctcp[0] != ' ') {
        code = newsplit(&ctcp);
        if (!ignoring || trigger_on_ignore) {
          check_tcl_ctcr(nick, uhost, u, chan->dname, code, msg);

          chan = findchan(realto);
          if (!chan)
            return 0;

          if (!ignoring) {
            putlog(LOG_PUBLIC, chan->dname,
                   "CTCP reply %s: %s from %s (%s) to %s", code, msg, nick,
                   from, chan->dname);
            update_idle(chan->dname, nick);
          }
        }
      }
    }
  }
  if (msg[0]) {

    /* Check even if we're ignoring the host. (modified by Eule 17.7.99) */
    detect_chan_flood(nick, uhost, from, chan, FLOOD_NOTICE, nullptr);

    chan = findchan(realto);
    if (!chan)
      return 0;

    update_idle(chan->dname, nick);

    if (!ignoring || trigger_on_ignore)
      if (check_tcl_notc(nick, uhost, u, to, msg) == 2)
        return 0;

    if (!ignoring)
      putlog(LOG_PUBLIC, chan->dname, "-%s:%s- %s", nick, to, msg);
  }
  return 0;
}

/* Got ACCOUNT message; only valid for account-notify capability */
static int gotaccount(char *from, char *msg) {
  char *nick = splitnick(&from);
  fixcolon(msg);
  /* nick!ident@host ACCOUNT xxx */
  setaccount(nick, msg);
  return 0;
}

static int parse_maxlist(const char *value)
{
  int tmpsum = 0, addtosum;
  char *tmps;
  long tmpl;
  const char *modechar = value, *number;

  max_exempts = 20;
  max_invites = 20;
  max_bans = 30;
  max_modes = 30;

  if (!value || *value == ':') {
    return 0;
  }
  /* e.g. value="be:100,I:50" */
  do {
    number = strchr(modechar, ':');
    if (!number) {
      putlog(LOG_MISC, "*", "Error while parsing ISUPPORT value for MAXLIST: number not found in '%s'", value);
      return -1;
    }
    number++;
    tmpl = strtol(number, &tmps, 10);
    if (*tmps != '\0' && *tmps != ',') {
      putlog(LOG_MISC, "*", "Error while parsing ISUPPORT value for MAXLIST: invalid number in '%s'", value);
      return -2;
    }
    if (tmpl < 10) {
      putlog(LOG_MISC, "*", "Warning while parsing ISUPPORT value for MAXLIST: number too small, setting to 10 in '%s'", value);
      tmpl = 10;
    } else if (tmpl > 100000) {
      putlog(LOG_MISC, "*", "Warning while parsing ISUPPORT value for MAXLIST: number too big, setting to 100000 in '%s'", value);
      tmpl = 100000;
    }
    addtosum = 0;
    do {
      if (*modechar == 'b') {
        max_bans = (int)tmpl;
        addtosum = 1;
      } else if (*modechar == 'e') {
        max_exempts = (int)tmpl;
        addtosum = 1;
      } else if (*modechar == 'I') {
        max_invites = (int)tmpl;
        addtosum = 1;
      } else {
        continue;
      }
    } while (*modechar++ != ':');
    /* Build maxmodes from all sections that interest us for now (beI),
     * e.g. be:100,I:100 means maxmodes=200 (limit for bans + excepts + invites) */
    if (addtosum) {
      tmpsum += (int)tmpl;
    }
    modechar = tmps;
  } while (*modechar++ == ',');

  max_modes = tmpsum;
  return 0;
}

static int irc_isupport(char *key, char *isset_str, char *value)
{
  int isset = !strcmp(isset_str, "1");

  if (!strcmp(key, "WHOX")) {
    use_354 = isset;
  } else if (!strcmp(key, "MODES")) {
    isupport_parseint(key, isset ? value : nullptr, 3, 64, 1, 3, &modesperline);
  } else if (!strcmp(key, "MAXLIST")) {
    parse_maxlist(isset ? value : nullptr);
  } else if (!strcmp(key, "MAXEXCEPTS")) {
    isupport_parseint(key, isset ? value : nullptr, 10, 100000, 1, 20, &max_exempts);
    if (max_exempts > max_modes) {
      max_modes = max_exempts;
    }
  } else if (!strcmp(key, "MAXBANS")) {
    isupport_parseint(key, isset ? value : nullptr, 10, 100000, 1, 30, &max_bans);
    if (max_bans > max_modes) {
      max_modes = max_bans;
    }
  } else if (!strcmp(key, "BOT")) {
    botflag005 = value[0];
  }
  return 0;
}

static int gotrawt(char *from, char *msg, Tcl_Obj *tags) {
  Tcl_Obj *valueobj;
  if (TCL_OK != Tcl_DictObjGet(interp, tags, tcl_account, &valueobj)) {
    putlog(LOG_MISC, "*", "ERROR: irc:rawt called with invalid dictionary");
    return 0;
  }
  if (valueobj) {
    setaccount(splitnick(&from), Tcl_GetString(valueobj));
  }
  return 0;
}

static cmd_t irc_raw[] = {
  {"324",     "",   (IntFunc) got324,          "irc:324"},
  {"352",     "",   (IntFunc) got352,          "irc:352"},
  {"353",     "",   (IntFunc) got353,          "irc:353"},
  {"354",     "",   (IntFunc) got354,          "irc:354"},
  {"315",     "",   (IntFunc) got315,          "irc:315"},
  {"366",     "",   (IntFunc) gottwitch366,   "irc:t366"},
  {"367",     "",   (IntFunc) got367,          "irc:367"},
  {"368",     "",   (IntFunc) got368,          "irc:368"},
  {"403",     "",   (IntFunc) got403,          "irc:403"},
  {"405",     "",   (IntFunc) got405,          "irc:405"},
  {"471",     "",   (IntFunc) got471,          "irc:471"},
  {"473",     "",   (IntFunc) got473,          "irc:473"},
  {"474",     "",   (IntFunc) got474,          "irc:474"},
  {"475",     "",   (IntFunc) got475,          "irc:475"},
  {"INVITE",  "",   (IntFunc) gotinvite,    "irc:invite"},
  {"TOPIC",   "",   (IntFunc) gottopic,      "irc:topic"},
  {"331",     "",   (IntFunc) got331,          "irc:331"},
  {"332",     "",   (IntFunc) got332,          "irc:332"},
  {"JOIN",    "",   (IntFunc) gotjoin,        "irc:join"},
  {"PART",    "",   (IntFunc) gotpart,        "irc:part"},
  {"KICK",    "",   (IntFunc) gotkick,        "irc:kick"},
  {"NICK",    "",   (IntFunc) gotnick,        "irc:nick"},
  {"QUIT",    "",   (IntFunc) gotquit,        "irc:quit"},
  {"PRIVMSG", "",   (IntFunc) gotmsg,          "irc:msg"},
  {"NOTICE",  "",   (IntFunc) gotnotice,    "irc:notice"},
  {"MODE",    "",   (IntFunc) gotmode,        "irc:mode"},
  {"AWAY",    "",   (IntFunc) gotaway,     "irc:gotaway"},
  {"335",     "",   (IntFunc) got335,          "irc:335"},
  {"346",     "",   (IntFunc) got346,          "irc:346"},
  {"347",     "",   (IntFunc) got347,          "irc:347"},
  {"348",     "",   (IntFunc) got348,          "irc:348"},
  {"349",     "",   (IntFunc) got349,          "irc:349"},
  {"396",     "",   (IntFunc) got396,          "irc:396"},
  {"ACCOUNT", "",   (IntFunc) gotaccount,  "irc:account"},
  {"CHGHOST", "",   (IntFunc) gotchghost,  "irc:chghost"},
  {nullptr,     nullptr,  nullptr,                           nullptr}
};

static cmd_t irc_rawt[] = {
  {"*",       "",   (IntFunc) gotrawt,        "irc:rawt"},
  {nullptr,    nullptr,   nullptr,                           nullptr}
};

static cmd_t irc_isupport_binds[] = {
  {"*",       "",   (IntFunc) irc_isupport, "irc:isupport"},
  {nullptr,    nullptr,   nullptr,                             nullptr}
};

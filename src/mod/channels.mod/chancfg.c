/*
 * chancfg.c -- channel configuration core (Tcl-independent)
 *              part of channels.mod
 *
 * Contains init_masklist, init_channel, clear_masklist, clear_channel,
 * tcl_channel_modify, and tcl_channel_add — the channel add/configure
 * logic that must work in both Tcl and no-Tcl builds.
 *
 * Included by channels.c (unity build) before tclchan.c so these
 * functions are available to the whole translation unit.
 */

/* -----------------------------------------------------------------------
 * Masklist / channel initialisation helpers
 * ----------------------------------------------------------------------- */

static void init_masklist(masklist *m)
{
  m->mask = nmalloc(1);
  m->mask[0] = 0;
  m->who = NULL;
  m->next = NULL;
}

/* Initialize channel record fields. */
static void init_channel(struct chanset_t *chan, int reset)
{
  int flags = reset ? reset : CHAN_RESETALL;
  memberlist *m, *m1;

  if (flags & CHAN_RESETWHO) {
    for (m = chan->channel.member; m; m = m1) {
      m1 = m->next;
      channel_free_member(m);
    }
    chan->channel.members = 0;
    chan->channel.member = channel_malloc_member();
    /* channel_malloc_member zero-fills the allocation */
  }

  if (flags & CHAN_RESETMODES) {
    chan->channel.mode = 0;
    chan->channel.maxmembers = 0;
    if (chan->channel.key)
      nfree(chan->channel.key);
    chan->channel.key = nmalloc(1);
    chan->channel.key[0] = 0;
  }

  if (flags & CHAN_RESETBANS) {
    chan->channel.ban = channel_malloc_mask();
    init_masklist(chan->channel.ban);
  }
  if (flags & CHAN_RESETEXEMPTS) {
    chan->channel.exempt = channel_malloc_mask();
    init_masklist(chan->channel.exempt);
  }
  if (flags & CHAN_RESETINVITED) {
    chan->channel.invite = channel_malloc_mask();
    init_masklist(chan->channel.invite);
  }
  if (flags & CHAN_RESETTOPIC)
    chan->channel.topic = NULL;
}

static void clear_masklist(masklist *m)
{
  masklist *temp;

  for (; m; m = temp) {
    temp = m->next;
    if (m->mask)
      nfree(m->mask);
    if (m->who)
      nfree(m->who);
    channel_free_mask(m);
  }
}

/* Clear channel data from memory. */
static void clear_channel(struct chanset_t *chan, int reset)
{
  int flags = reset ? reset : CHAN_RESETALL;
  memberlist *m, *m1;

  if (flags & CHAN_RESETWHO) {
    for (m = chan->channel.member; m; m = m1) {
      m1 = m->next;
      if (reset)
        m->flags &= ~WHO_SYNCED;
      else
        channel_free_member(m);
    }
  }
  if (flags & CHAN_RESETBANS) {
    clear_masklist(chan->channel.ban);
    chan->channel.ban = NULL;
  }
  if (flags & CHAN_RESETEXEMPTS) {
    clear_masklist(chan->channel.exempt);
    chan->channel.exempt = NULL;
  }
  if (flags & CHAN_RESETINVITED) {
    clear_masklist(chan->channel.invite);
    chan->channel.invite = NULL;
  }
  if ((flags & CHAN_RESETTOPIC) && chan->channel.topic)
    nfree(chan->channel.topic);
  if (reset)
    init_channel(chan, reset);
}

/* -----------------------------------------------------------------------
 * Simple list splitter for no-Tcl builds.
 *
 * Splits whitespace-separated tokens and handles Tcl-style brace quoting
 * ({...}) so the format produced by write_channels() can be read back.
 * ----------------------------------------------------------------------- */
#ifndef HAVE_TCL
static int egg_split_list(const char *str, int *argc, char ***argv)
{
  int n = 0, cap = 16;
  const char *p = str;
  char **list = nmalloc(cap * sizeof(char *));

  while (*p) {
    const char *start;
    int len;

    while (*p == ' ' || *p == '\t') p++;
    if (!*p)
      break;

    if (*p == '{') {
      /* brace-quoted token: strip outer braces */
      p++;
      start = p;
      while (*p && *p != '}') p++;
      len = (int)(p - start);
      if (*p == '}') p++;
    } else {
      start = p;
      while (*p && *p != ' ' && *p != '\t') p++;
      len = (int)(p - start);
    }

    if (n >= cap) {
      cap *= 2;
      list = nrealloc(list, cap * sizeof(char *));
    }
    list[n] = nmalloc(len + 1);
    memcpy(list[n], start, len);
    list[n][len] = '\0';
    n++;
  }
  *argc = n;
  *argv = list;
  return TCL_OK;
}

static void egg_free_list(int argc, char **argv)
{
  int i;
  for (i = 0; i < argc; i++)
    nfree(argv[i]);
  nfree(argv);
}
#endif /* !HAVE_TCL */

/* -----------------------------------------------------------------------
 * tcl_channel_modify — apply a list of channel option tokens to chan.
 *
 * The Tcl_Interp * is used only for error reporting via Tcl_AppendResult /
 * Tcl_ResetResult, which are no-ops in no-Tcl builds (lush.h stubs).
 * check_tcl_chanset() calls are guarded with #ifdef HAVE_TCL.
 * ----------------------------------------------------------------------- */
static int tcl_channel_modify(Tcl_Interp *irp, struct chanset_t *chan,
                              int items, char **item)
{
  int i, x = 0, found, old_status = chan->status,
      old_mode_mns_prot = chan->mode_mns_prot,
      old_mode_pls_prot = chan->mode_pls_prot;
  struct udef_struct *ul;
  char s[121];
  char *endptr;
  module_entry *me;

  for (i = 0; i < items; i++) {
#ifdef HAVE_TCL
    if (item[i][0] == '+' || item[i][0] == '-') {
      if (check_tcl_chanset(chan->dname, item[i] + 1,
                            item[i][0] == '+' ? "1" : "0")) {
        Tcl_ResetResult(irp);
        Tcl_AppendResult(irp, "Channel setting ", item[i],
                         " rejected by Tcl script", NULL);
        return TCL_ERROR;
      }
    } else {
      if (i < items - 1) {
        int free_value = 0;
        char *value;

        if (!strncmp("need-", item[i], 5)) {
          value = item[i + 1];
        } else {
          char *sep = strchr(item[i + 1], ' ');
          if (sep) {
            value = nmalloc(sep - item[i + 1] + 1);
            strlcpy(value, item[i + 1], sep - item[i + 1] + 1);
            free_value = 1;
          } else {
            value = item[i + 1];
          }
        }
        if (check_tcl_chanset(chan->dname, item[i], value)) {
          if (free_value)
            nfree(value);
          Tcl_ResetResult(irp);
          Tcl_AppendResult(irp, "Channel setting ", item[i], " to ", value,
                           " rejected by Tcl script", NULL);
          return TCL_ERROR;
        }
        if (free_value)
          nfree(value);
      }
    }
#endif /* HAVE_TCL */
    if (!strcmp(item[i], "need-op")) {
      i++;
      if (i >= items) {
        Tcl_AppendResult(irp, "channel need-op needs argument", NULL);
        return TCL_ERROR;
      }
      strlcpy(chan->need_op, item[i], sizeof chan->need_op);
    } else if (!strcmp(item[i], "need-invite")) {
      i++;
      if (i >= items) {
        Tcl_AppendResult(irp, "channel need-invite needs argument", NULL);
        return TCL_ERROR;
      }
      strlcpy(chan->need_invite, item[i], sizeof chan->need_invite);
    } else if (!strcmp(item[i], "need-key")) {
      i++;
      if (i >= items) {
        Tcl_AppendResult(irp, "channel need-key needs argument", NULL);
        return TCL_ERROR;
      }
      strlcpy(chan->need_key, item[i], sizeof chan->need_key);
    } else if (!strcmp(item[i], "need-limit")) {
      i++;
      if (i >= items) {
        Tcl_AppendResult(irp, "channel need-limit needs argument", NULL);
        return TCL_ERROR;
      }
      strlcpy(chan->need_limit, item[i], sizeof chan->need_limit);
    } else if (!strcmp(item[i], "need-unban")) {
      i++;
      if (i >= items) {
        Tcl_AppendResult(irp, "channel need-unban needs argument", NULL);
        return TCL_ERROR;
      }
      strlcpy(chan->need_unban, item[i], sizeof chan->need_unban);
    } else if (!strcmp(item[i], "chanmode")) {
      i++;
      if (i >= items) {
        Tcl_AppendResult(irp, "channel chanmode needs argument", NULL);
        return TCL_ERROR;
      }
      strlcpy(s, item[i], sizeof s);
      set_mode_protect(chan, s);
    } else if (!strcmp(item[i], "idle-kick")) {
      i++;
      if (i >= items) {
        Tcl_AppendResult(irp, "channel idle-kick needs argument", NULL);
        return TCL_ERROR;
      }
      chan->idle_kick = atoi(item[i]);
    } else if (!strcmp(item[i], "dont-idle-kick"))
      chan->idle_kick = 0;
    else if (!strcmp(item[i], "stopnethack-mode")) {
      i++;
      if (i >= items) {
        Tcl_AppendResult(irp, "channel stopnethack-mode needs argument", NULL);
        return TCL_ERROR;
      }
      chan->stopnethack_mode = atoi(item[i]);
    } else if (!strcmp(item[i], "revenge-mode")) {
      i++;
      if (i >= items) {
        Tcl_AppendResult(irp, "channel revenge-mode needs argument", NULL);
        return TCL_ERROR;
      }
      chan->revenge_mode = atoi(item[i]);
    } else if (!strcmp(item[i], "ban-type")) {
      i++;
      if (i >= items) {
        Tcl_AppendResult(irp, "channel ban-type needs argument", NULL);
        return TCL_ERROR;
      }
      chan->ban_type = atoi(item[i]);
    } else if (!strcmp(item[i], "ban-time")) {
      i++;
      if (i >= items) {
        Tcl_AppendResult(irp, "channel ban-time needs argument", NULL);
        return TCL_ERROR;
      }
      chan->ban_time = atoi(item[i]);
    } else if (!strcmp(item[i], "exempt-time")) {
      i++;
      if (i >= items) {
        Tcl_AppendResult(irp, "channel exempt-time needs argument", NULL);
        return TCL_ERROR;
      }
      chan->exempt_time = atoi(item[i]);
    } else if (!strcmp(item[i], "invite-time")) {
      i++;
      if (i >= items) {
        Tcl_AppendResult(irp, "channel invite-time needs argument", NULL);
        return TCL_ERROR;
      }
      chan->invite_time = atoi(item[i]);
    } else if (!strcmp(item[i], "+enforcebans"))
      chan->status |= CHAN_ENFORCEBANS;
    else if (!strcmp(item[i], "-enforcebans"))
      chan->status &= ~CHAN_ENFORCEBANS;
    else if (!strcmp(item[i], "+dynamicbans"))
      chan->status |= CHAN_DYNAMICBANS;
    else if (!strcmp(item[i], "-dynamicbans"))
      chan->status &= ~CHAN_DYNAMICBANS;
    else if (!strcmp(item[i], "-userbans"))
      chan->status |= CHAN_NOUSERBANS;
    else if (!strcmp(item[i], "+userbans"))
      chan->status &= ~CHAN_NOUSERBANS;
    else if (!strcmp(item[i], "+autoop"))
      chan->status |= CHAN_OPONJOIN;
    else if (!strcmp(item[i], "-autoop"))
      chan->status &= ~CHAN_OPONJOIN;
    else if (!strcmp(item[i], "+autohalfop"))
      chan->status |= CHAN_AUTOHALFOP;
    else if (!strcmp(item[i], "-autohalfop"))
      chan->status &= ~CHAN_AUTOHALFOP;
    else if (!strcmp(item[i], "+bitch"))
      chan->status |= CHAN_BITCH;
    else if (!strcmp(item[i], "-bitch"))
      chan->status &= ~CHAN_BITCH;
    else if (!strcmp(item[i], "+nodesynch"))
      chan->status |= CHAN_NODESYNCH;
    else if (!strcmp(item[i], "-nodesynch"))
      chan->status &= ~CHAN_NODESYNCH;
    else if (!strcmp(item[i], "+greet"))
      chan->status |= CHAN_GREET;
    else if (!strcmp(item[i], "-greet"))
      chan->status &= ~CHAN_GREET;
    else if (!strcmp(item[i], "+protectops"))
      chan->status |= CHAN_PROTECTOPS;
    else if (!strcmp(item[i], "-protectops"))
      chan->status &= ~CHAN_PROTECTOPS;
    else if (!strcmp(item[i], "+protecthalfops"))
      chan->status |= CHAN_PROTECTHALFOPS;
    else if (!strcmp(item[i], "-protecthalfops"))
      chan->status &= ~CHAN_PROTECTHALFOPS;
    else if (!strcmp(item[i], "+protectfriends"))
      chan->status |= CHAN_PROTECTFRIENDS;
    else if (!strcmp(item[i], "-protectfriends"))
      chan->status &= ~CHAN_PROTECTFRIENDS;
    else if (!strcmp(item[i], "+dontkickops"))
      chan->status |= CHAN_DONTKICKOPS;
    else if (!strcmp(item[i], "-dontkickops"))
      chan->status &= ~CHAN_DONTKICKOPS;
    else if (!strcmp(item[i], "+inactive"))
      chan->status |= CHAN_INACTIVE;
    else if (!strcmp(item[i], "-inactive"))
      chan->status &= ~CHAN_INACTIVE;
    else if (!strcmp(item[i], "+statuslog"))
      chan->status |= CHAN_LOGSTATUS;
    else if (!strcmp(item[i], "-statuslog"))
      chan->status &= ~CHAN_LOGSTATUS;
    else if (!strcmp(item[i], "+revenge"))
      chan->status |= CHAN_REVENGE;
    else if (!strcmp(item[i], "-revenge"))
      chan->status &= ~CHAN_REVENGE;
    else if (!strcmp(item[i], "+revengebot"))
      chan->status |= CHAN_REVENGEBOT;
    else if (!strcmp(item[i], "-revengebot"))
      chan->status &= ~CHAN_REVENGEBOT;
    else if (!strcmp(item[i], "+secret"))
      chan->status |= CHAN_SECRET;
    else if (!strcmp(item[i], "-secret"))
      chan->status &= ~CHAN_SECRET;
    else if (!strcmp(item[i], "+shared"))
      chan->status |= CHAN_SHARED;
    else if (!strcmp(item[i], "-shared"))
      chan->status &= ~CHAN_SHARED;
    else if (!strcmp(item[i], "+autovoice"))
      chan->status |= CHAN_AUTOVOICE;
    else if (!strcmp(item[i], "-autovoice"))
      chan->status &= ~CHAN_AUTOVOICE;
    else if (!strcmp(item[i], "+cycle"))
      chan->status |= CHAN_CYCLE;
    else if (!strcmp(item[i], "-cycle"))
      chan->status &= ~CHAN_CYCLE;
    else if (!strcmp(item[i], "+seen"))
      chan->status |= CHAN_SEEN;
    else if (!strcmp(item[i], "-seen"))
      chan->status &= ~CHAN_SEEN;
    else if (!strcmp(item[i], "+static"))
      chan->status |= CHAN_STATIC;
    else if (!strcmp(item[i], "-static"))
      chan->status &= ~CHAN_STATIC;
    else if (!strcmp(item[i], "+dynamicexempts"))
      chan->ircnet_status |= CHAN_DYNAMICEXEMPTS;
    else if (!strcmp(item[i], "-dynamicexempts"))
      chan->ircnet_status &= ~CHAN_DYNAMICEXEMPTS;
    else if (!strcmp(item[i], "-userexempts"))
      chan->ircnet_status |= CHAN_NOUSEREXEMPTS;
    else if (!strcmp(item[i], "+userexempts"))
      chan->ircnet_status &= ~CHAN_NOUSEREXEMPTS;
    else if (!strcmp(item[i], "+dynamicinvites"))
      chan->ircnet_status |= CHAN_DYNAMICINVITES;
    else if (!strcmp(item[i], "-dynamicinvites"))
      chan->ircnet_status &= ~CHAN_DYNAMICINVITES;
    else if (!strcmp(item[i], "-userinvites"))
      chan->ircnet_status |= CHAN_NOUSERINVITES;
    else if (!strcmp(item[i], "+userinvites"))
      chan->ircnet_status &= ~CHAN_NOUSERINVITES;
    /* ignore wasoptest, stopnethack and clearbans in chanfile */
    else if (!strcmp(item[i], "-stopnethack"));
    else if (!strcmp(item[i], "+stopnethack"));
    else if (!strcmp(item[i], "-wasoptest"));
    else if (!strcmp(item[i], "+wasoptest"));
    else if (!strcmp(item[i], "+clearbans"));
    else if (!strcmp(item[i], "-clearbans"));
    else if (!strncmp(item[i], "flood-", 6)) {
      int *pthr = 0, *ptime;
      char *p;

      if (!strcmp(item[i] + 6, "chan")) {
        pthr = &chan->flood_pub_thr;
        ptime = &chan->flood_pub_time;
      } else if (!strcmp(item[i] + 6, "join")) {
        pthr = &chan->flood_join_thr;
        ptime = &chan->flood_join_time;
      } else if (!strcmp(item[i] + 6, "ctcp")) {
        pthr = &chan->flood_ctcp_thr;
        ptime = &chan->flood_ctcp_time;
      } else if (!strcmp(item[i] + 6, "kick")) {
        pthr = &chan->flood_kick_thr;
        ptime = &chan->flood_kick_time;
      } else if (!strcmp(item[i] + 6, "deop")) {
        pthr = &chan->flood_deop_thr;
        ptime = &chan->flood_deop_time;
      } else if (!strcmp(item[i] + 6, "nick")) {
        pthr = &chan->flood_nick_thr;
        ptime = &chan->flood_nick_time;
      } else {
        Tcl_AppendResult(irp, "illegal channel flood type: ", item[i], NULL);
        return TCL_ERROR;
      }
      i++;
      if (i >= items) {
        Tcl_AppendResult(irp, item[i - 1], " needs argument", NULL);
        return TCL_ERROR;
      }
      p = strchr(item[i], ':');
      /* Check for valid X:Y, denying X, :Y, X: and X:Y:Z[:...] */
      if (p && item[i] != p && *(p+1) && !strchr(p+1, ':')) {
        *p++ = 0;
        if (strtol(item[i], &endptr, 10) < 0 || (*endptr)
            || strtol(p, &endptr, 10) < 0 || (*endptr)) {
          *--p = ':';
          Tcl_AppendResult(irp, "values must be integers >= 0: ", item[i],
                           NULL);
          return TCL_ERROR;
        } else {
          *pthr = atoi(item[i]);
          *ptime = atoi(p);
          *--p = ':';
        }
      } else {
        if ((*item[i]) && !strtol(item[i], &endptr, 10) && !(*endptr)) {
          *pthr = 0;
          *ptime = 0;
        } else {
          Tcl_AppendResult(irp, "flood value must be in X:Y format: ",
                           item[i], NULL);
          return TCL_ERROR;
        }
      }
    } else if (!strncmp(item[i], "aop-delay", 9)) {
      char *p;

      i++;
      if (i >= items) {
        Tcl_AppendResult(irp, item[i - 1], " needs argument", NULL);
        return TCL_ERROR;
      }
      p = strchr(item[i], ':');
      if (p) {
        p++;
        chan->aop_min = atoi(item[i]);
        chan->aop_max = atoi(p);
      } else {
        chan->aop_min = atoi(item[i]);
        chan->aop_max = chan->aop_min;
      }
    } else {
      if (!strncmp(item[i] + 1, "udef-flag-", 10))
        initudef(UDEF_FLAG, item[i] + 11, 0);
      else if (!strncmp(item[i], "udef-int-", 9))
        initudef(UDEF_INT, item[i] + 9, 0);
      else if (!strncmp(item[i], "udef-str-", 9))
        initudef(UDEF_STR, item[i] + 9, 0);
      found = 0;
      for (ul = udef; ul; ul = ul->next) {
        if (ul->type == UDEF_FLAG && (!strcasecmp(item[i] + 1, ul->name) ||
            (!strncmp(item[i] + 1, "udef-flag-", 10) &&
            !strcasecmp(item[i] + 11, ul->name)))) {
          if (item[i][0] == '+')
            setudef(ul, chan->dname, 1);
          else
            setudef(ul, chan->dname, 0);
          found = 1;
          break;
        } else if (ul->type == UDEF_INT && (!strcasecmp(item[i], ul->name) ||
                   (!strncmp(item[i], "udef-int-", 9) &&
                   !strcasecmp(item[i] + 9, ul->name)))) {
          i++;
          if (i >= items) {
            Tcl_AppendResult(irp, "this setting needs an argument", NULL);
            return TCL_ERROR;
          }
          setudef(ul, chan->dname, atoi(item[i]));
          found = 1;
          break;
        } else if (ul->type == UDEF_STR &&
                   (!strcasecmp(item[i], ul->name) ||
                   (!strncmp(item[i], "udef-str-", 9) &&
                   !strcasecmp(item[i] + 9, ul->name)))) {
          char *val;

          i++;
          if (i >= items) {
            Tcl_AppendResult(irp, "this setting needs an argument", NULL);
            return TCL_ERROR;
          }
          val = (char *) getudef(ul->values, chan->dname);
          if (val)
            nfree(val);
          /* Get extra room for new braces, etc */
          val = nmalloc(3 * strlen(item[i]) + 10);
          convert_element(item[i], val);
          val = nrealloc(val, strlen(val) + 1);
          setudef(ul, chan->dname, (intptr_t) val);
          found = 1;
          break;
        }
      }
      if (!found) {
        if (irp && item[i][0])  /* ignore "" */
          Tcl_AppendResult(irp, "illegal channel option: ", item[i], "\n",
                           NULL);
        x++;
      }
    }
  }
  /* If protect_readonly == 0 and chan_hack == 0 then bot is processing the
   * config file; don't act yet — wait for the channel file which may
   * override these settings.
   */
  if (protect_readonly || chan_hack) {
    if (((old_status ^ chan->status) & CHAN_INACTIVE) &&
        module_find("irc", 0, 0)) {
      if (channel_inactive(chan) && (chan->status & (CHAN_ACTIVE | CHAN_PEND)))
        dprintf(DP_SERVER, "PART %s\n", chan->name);
      if (!channel_inactive(chan) &&
          !(chan->status & (CHAN_ACTIVE | CHAN_PEND))) {
        char *key;

        key = chan->channel.key[0] ? chan->channel.key : chan->key_prot;
        if (key[0])
          dprintf(DP_SERVER, "JOIN %s %s\n",
                  chan->name[0] ? chan->name : chan->dname, key);
        else
          dprintf(DP_SERVER, "JOIN %s\n",
                  chan->name[0] ? chan->name : chan->dname);
      }
    }
    if ((old_status ^ chan->status) & (CHAN_ENFORCEBANS | CHAN_OPONJOIN |
                                       CHAN_BITCH | CHAN_AUTOVOICE |
                                       CHAN_AUTOHALFOP)) {
      if ((me = module_find("irc", 0, 0)))
        ((void (*)(struct chanset_t *, int)) me->funcs[IRC_RECHECK_CHANNEL])(chan, 1);
    } else if (old_mode_pls_prot != chan->mode_pls_prot ||
               old_mode_mns_prot != chan->mode_mns_prot)
      if ((me = module_find("irc", 1, 2)))
        ((void (*)(struct chanset_t *)) me->funcs[IRC_RECHECK_CHANNEL_MODES])(chan);
  }
  if (x > 0)
    return TCL_ERROR;
  return TCL_OK;
}

/* -----------------------------------------------------------------------
 * tcl_channel_add — create (or reload) a channel and apply options.
 * ----------------------------------------------------------------------- */
static int tcl_channel_add(Tcl_Interp *irp, char *newname, char *options)
{
  Tcl_Size items;
  int ret = TCL_OK;
  int join = 0;
  char buf[2048], buf2[256];
  char **item;
  struct chanset_t *chan;

  if (!newname || !newname[0] || (strchr(CHANMETA, newname[0]) == NULL)) {
    Tcl_AppendResult(irp, "invalid channel prefix", NULL);
    return TCL_ERROR;
  }

  if (strchr(newname, ',') != NULL) {
    Tcl_AppendResult(irp, "invalid channel name", NULL);
    return TCL_ERROR;
  }

  convert_element(glob_chanmode, buf2);
  snprintf(buf, sizeof buf, "chanmode %s %s%s", buf2, glob_chanset, options);

#ifdef HAVE_TCL
  {
    EGG_CONST char **tcl_item;
    Tcl_Size tcl_items;
    if (Tcl_SplitList(NULL, buf, &tcl_items, &tcl_item) != TCL_OK)
      return TCL_ERROR;
    items = tcl_items;
    item = (char **) tcl_item;
  }
#else
  if (egg_split_list(buf, (int *) &items, &item) != TCL_OK)
    return TCL_ERROR;
#endif

  if ((chan = findchan_by_dname(newname))) {
    /* Already existing channel, maybe a reload of the channel file */
    chan->status &= ~CHAN_FLAGGED;      /* don't delete me! :) */
  } else {
    chan = nmalloc(sizeof *chan);
    egg_bzero(chan, sizeof(struct chanset_t));

    chan->flood_pub_thr = gfld_chan_thr;
    chan->flood_pub_time = gfld_chan_time;
    chan->flood_ctcp_thr = gfld_ctcp_thr;
    chan->flood_ctcp_time = gfld_ctcp_time;
    chan->flood_join_thr = gfld_join_thr;
    chan->flood_join_time = gfld_join_time;
    chan->flood_deop_thr = gfld_deop_thr;
    chan->flood_deop_time = gfld_deop_time;
    chan->flood_kick_thr = gfld_kick_thr;
    chan->flood_kick_time = gfld_kick_time;
    chan->flood_nick_thr = gfld_nick_thr;
    chan->flood_nick_time = gfld_nick_time;
    chan->stopnethack_mode = global_stopnethack_mode;
    chan->revenge_mode = global_revenge_mode;
    chan->ban_type = global_ban_type;
    chan->ban_time = global_ban_time;
    chan->exempt_time = global_exempt_time;
    chan->invite_time = global_invite_time;
    chan->idle_kick = global_idle_kick;
    chan->aop_min = global_aop_min;
    chan->aop_max = global_aop_max;

    strlcpy(chan->dname, newname, sizeof chan->dname);

    init_channel(chan, 0);
    egg_list_append((struct list_type **) &chanset,
                    (struct list_type *) chan);
    join = 1;
    /* Request user chanflags from other bots */
    shareout(NULL, "nc %s\n", chan->dname);
  }

  /* If chan_hack is set we're loading the userfile; ignore errors for
   * compatibility if old options are no longer supported.
   */
  if ((tcl_channel_modify(irp, chan, (int) items, item) != TCL_OK) &&
      !chan_hack) {
    ret = TCL_ERROR;
  }

#ifdef HAVE_TCL
  Tcl_Free((char *) item);
#else
  egg_free_list((int) items, item);
#endif

  if (ret == TCL_OK) {
    if (join && !channel_inactive(chan) && module_find("irc", 0, 0)) {
      if (chan->key_prot[0])
        dprintf(DP_SERVER, "JOIN %s %s\n", chan->dname, chan->key_prot);
      else
        dprintf(DP_SERVER, "JOIN %s\n", chan->dname);
    }
  } else
    remove_channel(chan);
  return ret;
}

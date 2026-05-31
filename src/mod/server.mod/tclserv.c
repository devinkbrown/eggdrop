/*
 * tclserv.c -- part of server.mod
 *
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

/* Tcl command handlers for server.mod.
 * In non-Tcl builds lush.h provides no-op stubs for all Tcl APIs.
 */

static int tcl_isbotnick STDVAR
{
  BADARGS(2, 2, " nick");

  if (match_my_nick(argv[1]))
    Tcl_AppendResult(irp, "1", nullptr);
  else
    Tcl_AppendResult(irp, "0", nullptr);
  return TCL_OK;
}

static int tcl_putnow STDVAR
{
  int len;
  char buf[MSGMAX], *p, *q, *r;

  BADARGS(2, 3, " text ?options?");

  if ((argc == 3) && op_strcasecmp(argv[2], "-oneline")) {
    Tcl_AppendResult(irp, "unknown putnow option: should be ",
                     "-oneline", nullptr);
    return TCL_ERROR;
  }
  if (!serv) /* no server - no output */
    return TCL_OK;

  for (p = r = argv[1], q = buf; ; p++) {
    if (*p && *p != '\r' && *p != '\n')
      continue; /* look for message delimiters */
    if (p == r) { /* empty message */
      if (*p) {
        r++;
        continue;
      } else
        break;
    }
    if ((p - r) > (sizeof(buf) - 2 - (q - buf)))
      break; /* That's all folks, no space left */
    len = p - r + 1; /* leave space for '\0' */
    op_strlcpy(q, r, len);
    if (check_tcl_out(0, q, 0)) {
      if (!*p || ((argc == 3) && !op_strcasecmp(argv[2], "-oneline")))
        break;
      r = p + 1;
      continue;
    }
    check_tcl_out(0, q, 1);
    if (q == buf)
      putlog(LOG_SRVOUT, "*", "[r->] %s", q);
    else
      putlog(LOG_SRVOUT, "*", "[+r->] %s", q);
    q += len - 1; /* the '\0' must be overwritten */
    *q++ = '\r';
    *q++ = '\n'; /* comply with the RFC */
    if (!*p || ((argc == 3) && !op_strcasecmp(argv[2], "-oneline")))
      break; /* cut on newline requested or message ended */
    r = p + 1;
  }
  tputs(serv, buf, q - buf); /* q points after the last '\n' */
  return TCL_OK;
}

static int tcl_putquick STDVAR
{
  char s[MSGMAX], *p;

  BADARGS(2, 3, " text ?options?");

  if ((argc == 3) && op_strcasecmp(argv[2], "-next") &&
      op_strcasecmp(argv[2], "-normal")) {
    Tcl_AppendResult(irp, "unknown putquick option: should be one of: ",
                     "-normal -next", nullptr);
    return TCL_ERROR;
  }
  op_strlcpy(s, argv[1], sizeof s);

  p = strchr(s, '\n');
  if (p != nullptr)
    *p = 0;
  p = strchr(s, '\r');
  if (p != nullptr)
    *p = 0;
  if (argc == 3 && !op_strcasecmp(argv[2], "-next"))
    dprintf(DP_MODE_NEXT, "%s\n", s);
  else
    dprintf(DP_MODE, "%s\n", s);
  return TCL_OK;
}

static int tcl_putserv STDVAR
{
  char s[MSGMAX], *p;

  BADARGS(2, 3, " text ?options?");

  if ((argc == 3) && op_strcasecmp(argv[2], "-next") &&
      op_strcasecmp(argv[2], "-normal")) {
    Tcl_AppendResult(irp, "unknown putserv option: should be one of: ",
                     "-normal -next", nullptr);
    return TCL_ERROR;
  }
  op_strlcpy(s, argv[1], sizeof s);

  p = strchr(s, '\n');
  if (p != nullptr)
    *p = 0;
  p = strchr(s, '\r');
  if (p != nullptr)
    *p = 0;
  if (argc == 3 && !op_strcasecmp(argv[2], "-next"))
    dprintf(DP_SERVER_NEXT, "%s\n", s);
  else
    dprintf(DP_SERVER, "%s\n", s);
  return TCL_OK;
}

static int tcl_puthelp STDVAR
{
  char s[MSGMAX], *p;

  BADARGS(2, 3, " text ?options?");

  if ((argc == 3) && op_strcasecmp(argv[2], "-next") &&
      op_strcasecmp(argv[2], "-normal")) {
    Tcl_AppendResult(irp, "unknown puthelp option: should be one of: ",
                     "-normal -next", nullptr);
    return TCL_ERROR;
  }
  op_strlcpy(s, argv[1], sizeof s);

  p = strchr(s, '\n');
  if (p != nullptr)
    *p = 0;
  p = strchr(s, '\r');
  if (p != nullptr)
    *p = 0;
  if (argc == 3 && !op_strcasecmp(argv[2], "-next"))
    dprintf(DP_HELP_NEXT, "%s\n", s);
  else
    dprintf(DP_HELP, "%s\n", s);
  return TCL_OK;
}

/* Get the user's account name from Eggdrop's internal list if a) they are
  * logged in and b) Eggdrop has seen it.
  */
static int tcl_getaccount STDVAR {
  memberlist *m;
  struct chanset_t *chan, *thechan = nullptr;

  BADARGS(2, 3, " nickname ?channel?");

  if (argc > 2) {
    chan = findchan_by_dname(argv[2]);
    thechan = chan;
    if (!thechan) {
      Tcl_AppendResult(irp, "illegal channel: ", argv[2], nullptr);
      return TCL_ERROR;
    }
  } else {
    chan = chanset;
  }
  while (chan && (thechan == nullptr || thechan == chan)) {
    if ((m = ismember(chan, argv[1]))) {
      Tcl_AppendResult(irp, m->account, nullptr);
      return TCL_OK;
    }
    chan = chan->next;
  }
  Tcl_AppendResult(irp, "", nullptr);
  return TCL_OK;
}

static int tcl_isidentified STDVAR {
  memberlist *m;
  struct chanset_t *chan, *thechan = nullptr;

  BADARGS(2, 3, " nickname ?channel?");

  if (argc > 2) {
    chan = findchan_by_dname(argv[2]);
    thechan = chan;
    if (!thechan) {
      Tcl_AppendResult(irp, "illegal channel: ", argv[2], nullptr);
      return TCL_ERROR;
    }
  } else {
    chan = chanset;
  }
  while (chan && (thechan == nullptr || thechan == chan)) {
    if ((m = ismember(chan, argv[1]))) {
      if (strcmp(m->account, "*") && strcmp(m->account, "")) {
        Tcl_AppendResult(irp, "1", nullptr);
        return TCL_OK;
      }
    }
    chan = chan->next;
  }
  Tcl_AppendResult(irp, "0", nullptr);
  return TCL_OK;
}

/* Send a msg to the server prefixed with an IRCv3 message-tag */
static int tcl_tagmsg STDVAR {
  op_strbuf_t tag = {};
  char tagdict[CLITAGMAX-9];
  char target[MSGMAX];
  struct capability *current = 0;
  char *p;
  int i = 1;
  BADARGS(3, 3, " tag target");

  current = find_capability("message-tags");
  if ((!current) || (!(current->enabled))) {
    Tcl_AppendResult(irp, "message-tags not enabled, cannot send tag", nullptr);
    return TCL_ERROR;
  }
  char *saveptr = nullptr;
  op_strlcpy(tagdict, argv[1], sizeof tagdict);
  op_strlcpy(target, argv[2], sizeof target);
  op_strbuf_init(&tag);
  p = strtok_r(tagdict, " ", &saveptr);
  while (p != nullptr) {
    if ((i % 2) != 0) {
      op_strbuf_append_cstr(&tag, p);
    } else {
      if (strcmp(p, "{}") != 0) {
        op_strbuf_append_cstr(&tag, "=");
        op_strbuf_append_cstr(&tag, p);
        op_strbuf_append_cstr(&tag, ";");
      } else {
        op_strbuf_append_cstr(&tag, ";");
      }
    }
    i++;
    p = strtok_r(nullptr, " ", &saveptr);
  }
  p = strchr(target, '\n');
  if (p != nullptr)
    *p = 0;
  p = strchr(target, '\r');
  if (p != nullptr)
    *p = 0;
  dprintf(DP_SERVER, "@%s TAGMSG %s\n", op_strbuf_str(&tag), target);
  op_strbuf_free(&tag);
  return TCL_OK;
}


/* Tcl interface to send CAP messages to server */
static int tcl_cap STDVAR {
  int found = 0;
  struct capability *current;
  [[maybe_unused]] Tcl_Obj *capes, *values;
  BADARGS(2, 3, " sub-cmd ?arg?");

  capes = Tcl_NewListObj(0, nullptr);
  /* List capabilities available on server */
  if (!op_strcasecmp(argv[1], "ls")) {
    for (size_t ci = 0; ci < cap_vec.size; ci++) {
      current = (struct capability *)op_vec_get(&cap_vec, ci);
      Tcl_ListObjAppendElement(irp, capes, Tcl_NewStringObj(current->name, -1));
    }
    Tcl_SetObjResult(irp, capes);
  /* List capabilities Eggdrop is internally tracking as enabled with server */
  } else if (!op_strcasecmp(argv[1], "enabled")) {
    for (size_t ci = 0; ci < cap_vec.size; ci++) {
      current = (struct capability *)op_vec_get(&cap_vec, ci);
      if (current->enabled)
        Tcl_ListObjAppendElement(irp, capes, Tcl_NewStringObj(current->name, -1));
    }
    Tcl_SetObjResult(irp, capes);
  } else if (!op_strcasecmp(argv[1], "values")) {
    capes = Tcl_NewListObj(0, nullptr);
    values = Tcl_NewListObj(0, nullptr);
    for (size_t ci = 0; ci < cap_vec.size; ci++) {
      current = (struct capability *)op_vec_get(&cap_vec, ci);
      if ((argc == 3) && (!op_strcasecmp(argv[2], current->name)))
        found = 1;
      for (size_t vi = 0; vi < current->values.size; vi++) {
        const cap_values_t *cv = (const cap_values_t *)op_vec_get(&current->values, vi);
        if (argc == 3) {
          if (!op_strcasecmp(argv[2], current->name)) {
            /* Don't get confused, we use the capes var but its really values */
            Tcl_ListObjAppendElement(irp, capes, Tcl_NewStringObj(cv->name, -1));
          }
        } else {
          Tcl_ListObjAppendElement(irp, values, Tcl_NewStringObj(cv->name, -1));
        }
      }
      if (argc != 3) {
        Tcl_ListObjAppendElement(irp, capes, Tcl_NewStringObj(current->name, -1));
        Tcl_ListObjAppendElement(irp, capes, values);
        /* Reset for the next capability */
        values = Tcl_NewListObj(0, nullptr);
      }
    }
    if ((argc == 3) && (!found)) {
      op_strbuf_t errmsg = {};
      op_strbuf_init(&errmsg);
      op_strbuf_appendf(&errmsg, "Capability \"%s\" is not enabled", argv[2]);
      Tcl_AppendResult(irp, op_strbuf_str(&errmsg), nullptr);
      op_strbuf_free(&errmsg);
      return TCL_ERROR;
    }
    Tcl_SetObjResult(irp, capes);
  /* Send a request to negotiate a capability with server */
  } else if (!op_strcasecmp(argv[1], "req")) {
    if (argc != 3) {
      Tcl_AppendResult(irp, "No CAP request provided", nullptr);
      return TCL_ERROR;
    } else {
      op_strbuf_t cap_req = {};
      op_strbuf_init(&cap_req);
      op_strbuf_appendf(&cap_req, "CAP REQ :%s", argv[2]);
      dprintf(DP_SERVER, "%s\n", op_strbuf_str(&cap_req));
      op_strbuf_free(&cap_req);
    }
  /* Send a raw CAP command to the server */
  } else if (!op_strcasecmp(argv[1], "raw")) {
    if (argc == 3) {
      op_strbuf_t cap_raw = {};
      op_strbuf_init(&cap_raw);
      op_strbuf_appendf(&cap_raw, "CAP %s", argv[2]);
      dprintf(DP_SERVER, "%s\n", op_strbuf_str(&cap_raw));
      op_strbuf_free(&cap_raw);
    } else {
      Tcl_AppendResult(irp, "Raw requires a CAP sub-command to be provided",
        nullptr);
      return TCL_ERROR;
    }
  } else {
      Tcl_AppendResult(irp, "Invalid cap command, must be ls, enabled, req, or raw", nullptr);
      return TCL_ERROR;
  }
  return TCL_OK;
}

static int tcl_monitor STDVAR
{
  Tcl_Obj *monitorlist;
  int ret;
  BADARGS(2, 3, " command ?nick?");

  monitorlist = Tcl_NewListObj(0, nullptr);
  if (!strcmp(argv[1], "add")) {
    if (argc == 3) {
      ret = monitor_add(argv[2], 1);
      if (!ret) {
        Tcl_AppendResult(irp, "1", nullptr);
        return TCL_OK;
      } else if (ret == 1) {
        Tcl_AppendResult(irp, "nickname already present in monitor list", nullptr);
        return TCL_OK;
        /* ret = 2 */
      } else {
        Tcl_AppendResult(irp,
                "maximum number of nicknames allowed by server reached", nullptr);
        return TCL_ERROR;
      }
    } else {
      Tcl_AppendResult(irp, "nickname required", nullptr);
      return TCL_ERROR;
    }
  } else if (!strcmp(argv[1], "delete")) {
    if (argc == 3) {
      ret = monitor_del(argv[2]);
      if (ret) {
        Tcl_AppendResult(irp, "nickname not found", nullptr);
        return TCL_ERROR;
      } else {
        Tcl_AppendResult(irp, "1", nullptr);
        return TCL_OK;
      }
    } else {
      Tcl_AppendResult(irp, "nickname required", nullptr);
      return TCL_ERROR;
    }
  } else if (!strcmp(argv[1], "list")) {
    monitor_show(monitorlist, 0, nullptr);
    Tcl_AppendResult(irp, Tcl_GetString(monitorlist), nullptr);
    return TCL_OK;
  } else if (!strcmp(argv[1], "online")) {
    monitor_show(monitorlist, 1, nullptr);
    Tcl_AppendResult(irp, Tcl_GetString(monitorlist), nullptr);
    return TCL_OK;
  } else if (!strcmp(argv[1], "offline")) {
    monitor_show(monitorlist, 2, nullptr);
    Tcl_AppendResult(irp, Tcl_GetString(monitorlist), nullptr);
    return TCL_OK;
  } else if (!strcmp(argv[1], "status")) {
    if (argc < 3) {
      Tcl_AppendResult(irp, "nickname required", nullptr);
      return TCL_OK;
    }
    ret = monitor_show(monitorlist, 3, argv[2]);
    if (!ret) {
      Tcl_AppendResult(irp, Tcl_GetString(monitorlist), nullptr);
      return TCL_OK;
    } else {
      Tcl_AppendResult(irp, "nickname not found", nullptr);
      return TCL_ERROR;
    }
  } else if (!op_strcasecmp(argv[1], "clear")) {
    monitor_clear();
    Tcl_AppendResult(irp, "MONITOR list cleared.", nullptr);
    return TCL_OK;
  } else {
    Tcl_AppendResult(irp, "command must be add, delete, list, clear, online, offline, status", nullptr);
    return TCL_ERROR;
  }
}

static int tcl_jump STDVAR
{
  BADARGS(1, 4, " ?server? ?port? ?pass?");

  if (argc >= 2) {
    op_strlcpy(newserver, argv[1], sizeof newserver);
    if (argc >= 3)
#ifdef TLS
    {
      if (*argv[2] == '+')
        use_ssl = 1;
      else
        use_ssl = 0;
      newserverport = egg_atoi(argv[2]);
    }
#else
      newserverport = egg_atoi(argv[2]);
#endif
    else
      newserverport = default_port;
    if (argc == 4)
      op_strlcpy(newserverpass, argv[3], sizeof newserverpass);
  }
  cycle_time = 0;

  nuke_server(IRC_CHANGINGSERV);
  return TCL_OK;
}

static int tcl_clearqueue STDVAR
{
  struct msgq *q, *qq;
  [[maybe_unused]] int msgs = 0;

  BADARGS(2, 2, " queue");

  if (!strcmp(argv[1], "all")) {
    msgs = (int) (modeq.tot + mq.tot + hq.tot);
    for (q = modeq.head; q; q = qq) {
      qq = q->next;
      op_free(q->msg);
      op_bh_free(msgq_node_bh, q);
    }
    for (q = mq.head; q; q = qq) {
      qq = q->next;
      op_free(q->msg);
      op_bh_free(msgq_node_bh, q);
    }
    for (q = hq.head; q; q = qq) {
      qq = q->next;
      op_free(q->msg);
      op_bh_free(msgq_node_bh, q);
    }
    modeq.tot = mq.tot = hq.tot = modeq.warned = mq.warned = hq.warned = 0;
    mq.head = hq.head = modeq.head = mq.last = hq.last = modeq.last = 0;
    double_warned = 0;
    burst = 0;
    Tcl_SetObjResult(irp, Tcl_NewIntObj(msgs));
    return TCL_OK;
  } else if (!strncmp(argv[1], "serv", 4)) {
    msgs = mq.tot;
    for (q = mq.head; q; q = qq) {
      qq = q->next;
      op_free(q->msg);
      op_bh_free(msgq_node_bh, q);
    }
    mq.tot = mq.warned = 0;
    mq.head = mq.last = 0;
    if (modeq.tot == 0)
      burst = 0;
    double_warned = 0;
    mq.tot = mq.warned = 0;
    mq.head = mq.last = 0;
    Tcl_SetObjResult(irp, Tcl_NewIntObj(msgs));
    return TCL_OK;
  } else if (!strcmp(argv[1], "mode")) {
    msgs = modeq.tot;
    for (q = modeq.head; q; q = qq) {
      qq = q->next;
      op_free(q->msg);
      op_bh_free(msgq_node_bh, q);
    }
    if (mq.tot == 0)
      burst = 0;
    double_warned = 0;
    modeq.tot = modeq.warned = 0;
    modeq.head = modeq.last = 0;
    Tcl_SetObjResult(irp, Tcl_NewIntObj(msgs));
    return TCL_OK;
  } else if (!strcmp(argv[1], "help")) {
    msgs = hq.tot;
    for (q = hq.head; q; q = qq) {
      qq = q->next;
      op_free(q->msg);
      op_bh_free(msgq_node_bh, q);
    }
    double_warned = 0;
    hq.tot = hq.warned = 0;
    hq.head = hq.last = 0;
    Tcl_SetObjResult(irp, Tcl_NewIntObj(msgs));
    return TCL_OK;
  }
  Tcl_AppendResult(irp, "bad option \"", argv[1],
                   "\": must be mode, server, help, or all", nullptr);
  return TCL_ERROR;
}

static int tcl_queuesize STDVAR
{
  [[maybe_unused]] int x;

  BADARGS(1, 2, " ?queue?");

  if (argc == 1) {
    x = (int) (modeq.tot + hq.tot + mq.tot);
    Tcl_SetObjResult(irp, Tcl_NewIntObj(x));
    return TCL_OK;
  } else if (!strncmp(argv[1], "serv", 4)) {
    x = (int) (mq.tot);
    Tcl_SetObjResult(irp, Tcl_NewIntObj(x));
    return TCL_OK;
  } else if (!strcmp(argv[1], "mode")) {
    x = (int) (modeq.tot);
    Tcl_SetObjResult(irp, Tcl_NewIntObj(x));
    return TCL_OK;
  } else if (!strcmp(argv[1], "help")) {
    x = (int) (hq.tot);
    Tcl_SetObjResult(irp, Tcl_NewIntObj(x));
    return TCL_OK;
  }

  Tcl_AppendResult(irp, "bad option \"", argv[1],
                   "\": must be mode, server, or help", nullptr);
  return TCL_ERROR;
}

static int tcl_server STDVAR {
  int ret;
  [[maybe_unused]] Tcl_Obj *server;

  BADARGS(2, 5, " subcommand ?host ?port? ?password?");
  if (!strcmp(argv[1], "add")) {
    if (argc < 3) {
      Tcl_SetResult(irp, "wrong # args: should be \"server add host ?port ?password??\"", TCL_STATIC);
      return TCL_ERROR;
    }
    ret = add_server(argv[2], argc >= 4 && argv[3] ? argv[3] : "", argc >= 5 && argv[4] ? argv[4] : "");
    if (!ret) {
      server = Tcl_NewListObj(0, nullptr);
      Tcl_ListObjAppendElement(irp, server, Tcl_NewStringObj(argv[2], -1));
      if ((argc >= 4) && argv[3]) {
        Tcl_ListObjAppendElement(irp, server, Tcl_NewStringObj(argv[3], -1));
      } else {
        Tcl_ListObjAppendElement(irp, server, Tcl_NewStringObj("", -1));
      }
      if ((argc >= 5) && argv[4]) {
        Tcl_ListObjAppendElement(irp, server, Tcl_NewStringObj(argv[4], -1));
      } else {
        Tcl_ListObjAppendElement(irp, server, Tcl_NewStringObj("", -1));
      }
      Tcl_SetObjResult(irp, server);
    }
  } else if (!strcmp(argv[1], "remove")) {
    if (argc < 3) {
      Tcl_SetResult(irp, "wrong # args: should be \"server remove host ?port?\"", TCL_STATIC);
      return TCL_ERROR;
    }
    ret = del_server(argv[2], argc >= 4 && argv[3] ? argv[3] : "");
  } else if (!strcmp(argv[1], "list")) {
    [[maybe_unused]] Tcl_Obj *servers = Tcl_NewListObj(0, nullptr);
    for (size_t zi = 0; zi < serverlist_vec.size; zi++) {
      struct server_list *z = (struct server_list *)op_vec_get(&serverlist_vec, zi);
      server = Tcl_NewListObj(0, nullptr);
      Tcl_ListObjAppendElement(irp, server, Tcl_NewStringObj(z->name, -1));
#ifdef TLS
      {
        op_strbuf_t _b = {};
        op_strbuf_init(&_b);
        op_strbuf_appendf(&_b, "%s%d", z->ssl ? "+" : "", z->port);
        Tcl_ListObjAppendElement(irp, server, Tcl_NewStringObj(op_strbuf_str(&_b), -1));
        op_strbuf_free(&_b);
      }
#else
      Tcl_ListObjAppendElement(irp, server, Tcl_NewStringObj(int_to_base10(z->port), -1));
#endif
      Tcl_ListObjAppendElement(irp, server, Tcl_NewStringObj(z->pass ? z->pass : "", -1));
      Tcl_ListObjAppendElement(irp, servers, server);
    }
    Tcl_SetObjResult(irp, servers);
    return TCL_OK;
  } else {
    Tcl_AppendResult(irp, "Invalid subcommand: ", argv[1],
        ". Should be \"add\", \"remove\", or \"list\"", nullptr);
    return TCL_ERROR;
  }
  if (ret == 0) {
    return TCL_OK;
  }
  if (ret == 1) {
    Tcl_AppendResult(irp, "A ':' was detected in the non-IPv6 address ", argv[2],
            " Make sure the port is separated by a space, not a ':'. ", nullptr);
  } else if (ret == 2) {
    Tcl_AppendResult(irp, "Attempted to add SSL-enabled server, but Eggdrop "
            "was not compiled with SSL libraries.", nullptr);
  } else if (ret == 3) {    /* del_server only */
    Tcl_AppendResult(irp, "Server ", argv[2], argc >= 4 && argv[3] ? ":" : "",
            argc >= 4 && argv[3] ? argv[3] : ""," not found.", nullptr);
  }
  return TCL_ERROR;
}

/* =========================================================================
 * IRCX / Ophion Tcl commands
 *
 * ircxprop <target> <propname> [value]
 *   Get or set an IRCX property. With no value, sends PROP to read.
 *   With a value, sends PROP to write.
 *   Example: ircxprop #lobby TOPIC "Welcome!"
 *            ircxprop #lobby OWNERKEY "s3cr3t"
 *            ircxprop #lobby MEMBERKEY ""     ;# removes key (+k mode)
 *
 * ircxaccess <channel> <list|add|del> [level] [mask]
 *   Manage channel access lists.
 *   Example: ircxaccess #lobby add OWNER *!*@admin.example.com
 *            ircxaccess #lobby add HOST *!*@ops.example.com
 *            ircxaccess #lobby del *!*@ops.example.com
 *            ircxaccess #lobby list
 *
 * ircxcreate <channel> [modes]
 *   Create a channel (IRCX CREATE command). Bot becomes owner (+q).
 *   Example: ircxcreate #lobby +nt
 *
 * ircxautoowner <channel> [ownerkey] [create 0|1] [modes]
 *   Add a channel to the IRCX auto-owner list. On server connect, the
 *   bot will JOIN with the ownerkey to request owner (+q), or CREATE
 *   the channel if create=1.
 *   Example: ircxautoowner #lobby mykey 1 +nt
 *            ircxautoowner #lobby "" 0    ;# join without key, no create
 *
 * ircxnegotiate
 *   Manually send the IRCX command to enable IRCX mode.
 * ========================================================================= */

static int tcl_ircxprop STDVAR
{
  BADARGS(3, 4, " target propname ?value?");

  if (!serv) {
    Tcl_AppendResult(irp, "not connected to server", nullptr);
    return TCL_ERROR;
  }
  if (!ircx_enabled && !ircx_prop_support) {
    Tcl_AppendResult(irp, "IRCX not enabled on this server", nullptr);
    return TCL_ERROR;
  }
  ircx_prop_send(argv[1], argv[2], argc == 4 ? argv[3] : nullptr);
  return TCL_OK;
}

static int tcl_ircxaccess STDVAR
{
  BADARGS(3, 5, " channel list|add|del ?level? ?mask?");

  if (!serv) {
    Tcl_AppendResult(irp, "not connected to server", nullptr);
    return TCL_ERROR;
  }
  if (!ircx_enabled) {
    Tcl_AppendResult(irp, "IRCX not enabled on this server", nullptr);
    return TCL_ERROR;
  }
  if (!op_strcasecmp(argv[2], "list")) {
    ircx_access_list_send(argv[1]);
  } else if (!op_strcasecmp(argv[2], "add")) {
    if (argc < 5) {
      Tcl_AppendResult(irp, "wrong # args: ircxaccess channel add level mask", nullptr);
      return TCL_ERROR;
    }
    ircx_access_add(argv[1], argv[4], argv[3]);
  } else if (!op_strcasecmp(argv[2], "del")) {
    if (argc < 4) {
      Tcl_AppendResult(irp, "wrong # args: ircxaccess channel del mask", nullptr);
      return TCL_ERROR;
    }
    ircx_access_del(argv[1], argv[3]);
  } else {
    Tcl_AppendResult(irp, "unknown subcommand '", argv[2],
                     "': should be list, add, or del", nullptr);
    return TCL_ERROR;
  }
  return TCL_OK;
}

static int tcl_ircxcreate STDVAR
{
  BADARGS(2, 3, " channel ?modes?");

  if (!serv) {
    Tcl_AppendResult(irp, "not connected to server", nullptr);
    return TCL_ERROR;
  }
  if (!ircx_enabled) {
    Tcl_AppendResult(irp, "IRCX not enabled on this server", nullptr);
    return TCL_ERROR;
  }
  ircx_chan_create(argv[1], argc == 3 ? argv[2] : nullptr);
  return TCL_OK;
}

static int tcl_ircxautoowner STDVAR
{
  ircx_autoowner_t *existing = nullptr;
  size_t existing_idx = SIZE_MAX;

  BADARGS(2, 5, " channel ?ownerkey? ?create 0|1? ?modes?");

  /* Find existing entry */
  for (size_t i = 0; i < ircx_autoowner_vec.size; i++) {
    ircx_autoowner_t *ao = (ircx_autoowner_t *)op_vec_get(&ircx_autoowner_vec, i);
    if (!rfc_casecmp(ao->channel, argv[1])) {
      existing = ao;
      existing_idx = i;
      break;
    }
  }

  if (argc == 2) {
    /* No args beyond channel: remove the entry if it exists */
    if (existing) {
      op_vec_remove_fast(&ircx_autoowner_vec, existing_idx);
      op_bh_free(ircx_autoowner_bh, existing);
      Tcl_AppendResult(irp, "removed", nullptr);
    } else {
      Tcl_AppendResult(irp, "not found", nullptr);
    }
    return TCL_OK;
  }

  if (!existing) {
    if (!ircx_autoowner_bh) ircx_autoowner_bh = op_bh_create(sizeof(ircx_autoowner_t), 16, "ircx_autoowner");
    existing = (ircx_autoowner_t *)op_bh_alloc(ircx_autoowner_bh);
    op_vec_push(&ircx_autoowner_vec, existing);
  }
  op_strlcpy(existing->channel, argv[1], sizeof(existing->channel));
  if (argc >= 3)
    op_strlcpy(existing->ownerkey, argv[2], sizeof(existing->ownerkey));
  if (argc >= 4)
    existing->create_if_missing = egg_atoi(argv[3]);
  if (argc >= 5)
    op_strlcpy(existing->create_modes, argv[4], sizeof(existing->create_modes));
  /* Mirror settings into chanset so they are saved in the channel file */
  {
    struct chanset_t *ch = findchan_by_dname(existing->channel);
    if (ch) {
      op_strlcpy(ch->ircx_ownerkey, existing->ownerkey, sizeof(ch->ircx_ownerkey));
      ch->ircx_create = existing->create_if_missing;
      op_strlcpy(ch->ircx_create_modes, existing->create_modes, sizeof(ch->ircx_create_modes));
    }
  }

  putlog(LOG_MISC, existing->channel,
         "IRCX: Auto-owner configured for %s (ownerkey=%s, create=%d)",
         existing->channel,
         existing->ownerkey[0] ? "***" : "(none)",
         existing->create_if_missing);

  /* If IRCX is already active (e.g. this was called after got800()),
   * immediately perform the join/create for this channel. */
  if (ircx_enabled && serv >= 0) {
    if (existing->ownerkey[0]) {
      dprintf(DP_SERVER, "JOIN %s %s\n", existing->channel, existing->ownerkey);
      putlog(LOG_MISC, existing->channel,
             "IRCX: Auto-owner: joining %s with OWNERKEY (IRCX already active)",
             existing->channel);
    } else if (existing->create_if_missing) {
      ircx_chan_create(existing->channel,
                       existing->create_modes[0] ? existing->create_modes : nullptr);
    }
  }
  return TCL_OK;
}

static int tcl_ircxnegotiate STDVAR
{
  BADARGS(1, 1, "");

  if (serv < 0) {
    Tcl_AppendResult(irp, "not connected to server", nullptr);
    return TCL_ERROR;
  }
  /* Force re-negotiate even if already enabled */
  ircx_negotiating = 0;
  ircx_enabled     = 0;
  ircx_send_negotiate(); /* sends IRCX command */
  return TCL_OK;
}

/* knock <channel> — send KNOCK to an invite-only channel */
static int tcl_knock STDVAR {
  BADARGS(2, 2, " channel");
  dprintf(DP_SERVER, "KNOCK %s\n", argv[1]);
  return TCL_OK;
}

/* redact <target> <msgid> ?reason? — send REDACT to retract a message */
static int tcl_redact STDVAR {
  BADARGS(3, 4, " target msgid ?reason?");
  if (argc == 4)
    dprintf(DP_SERVER, "REDACT %s %s :%s\n", argv[1], argv[2], argv[3]);
  else
    dprintf(DP_SERVER, "REDACT %s %s\n", argv[1], argv[2]);
  return TCL_OK;
}

/* ircxlistx ?filter? — send LISTX with optional filter string */
static int tcl_ircxlistx STDVAR {
  BADARGS(1, 2, " ?filter?");
  if (argc == 2)
    dprintf(DP_SERVER, "LISTX %s\n", argv[1]);
  else
    dprintf(DP_SERVER, "LISTX\n");
  return TCL_OK;
}

/* ircxrequest <target> <tag> <text> — send IRCX REQUEST */
static int tcl_ircxrequest STDVAR {
  BADARGS(4, 4, " target tag text");
  dprintf(DP_SERVER, "REQUEST %s %s :%s\n", argv[1], argv[2], argv[3]);
  return TCL_OK;
}

/* ircxreply <target> <tag> <text> — send IRCX REPLY */
static int tcl_ircxreply STDVAR {
  BADARGS(4, 4, " target tag text");
  dprintf(DP_SERVER, "REPLY %s %s :%s\n", argv[1], argv[2], argv[3]);
  return TCL_OK;
}

/* ircxmodex <target> ?modes? — send IRCX MODEX */
static int tcl_ircxmodex STDVAR {
  BADARGS(2, 3, " target ?modes?");
  if (argc == 3)
    dprintf(DP_SERVER, "MODEX %s %s\n", argv[1], argv[2]);
  else
    dprintf(DP_SERVER, "MODEX %s\n", argv[1]);
  return TCL_OK;
}

/* ircxevent <subcmd> ?args? — send IRCX EVENT commands
 * ircxevent add <event> ?mask?
 * ircxevent delete <event>
 * ircxevent clear ?event?
 * ircxevent list ?event? */
static int tcl_ircxevent STDVAR {
  BADARGS(2, 4, " subcmd ?event? ?mask?");
  op_strbuf_t buf = {};
  op_strbuf_init(&buf);
  op_strbuf_append_cstr(&buf, "EVENT");
  for (int i = 1; i < argc; i++)
    op_strbuf_appendf(&buf, " %s", argv[i]);
  dprintf(DP_SERVER, "%s\n", op_strbuf_str(&buf));
  op_strbuf_free(&buf);
  return TCL_OK;
}

/* ircxregister <email|#channel> ?password? — send REGISTER command */
static int tcl_ircxregister STDVAR {
  BADARGS(2, 3, " email|#channel ?password?");
  if (argc == 3)
    dprintf(DP_SERVER, "REGISTER %s %s\n", argv[1], argv[2]);
  else
    dprintf(DP_SERVER, "REGISTER %s\n", argv[1]);
  return TCL_OK;
}

/* getcurrentnick — returns the bot's actual IRC nick in use right now.
 * This may differ from the configured nick after a nick collision forces the
 * bot onto an alternate nick.  Returns an empty string if not yet connected. */
static int tcl_getcurrentnick STDOBJVAR {
  if (objc != 1) {
    Tcl_WrongNumArgs(irp, 1, objv, "");
    return TCL_ERROR;
  }
  Tcl_SetResult(irp, botname[0] ? botname : "", TCL_STATIC);
  return TCL_OK;
}

/* curserver — returns the hostname of the currently connected IRC server.
 * Returns an empty string when not connected. */
static int tcl_curserver STDOBJVAR {
  if (objc != 1) {
    Tcl_WrongNumArgs(irp, 1, objv, "");
    return TCL_ERROR;
  }
  Tcl_SetResult(irp, realservername ? realservername : "", TCL_STATIC);
  return TCL_OK;
}

/* serverport — returns the port of the currently connected IRC server.
 * Returns 0 when not connected. */
static int tcl_serverport STDOBJVAR {
  if (objc != 1) {
    Tcl_WrongNumArgs(irp, 1, objv, "");
    return TCL_ERROR;
  }
  if (serv < 0) {
    Tcl_SetObjResult(irp, Tcl_NewIntObj(0));
    return TCL_OK;
  }
  int servidx = findanyidx(serv);
  if (servidx < 0) {
    Tcl_SetObjResult(irp, Tcl_NewIntObj(0));
    return TCL_OK;
  }
  Tcl_SetObjResult(irp, Tcl_NewIntObj((int)dcc[servidx].port));
  return TCL_OK;
}

/* serverlag — returns the current estimated server lag in milliseconds.
 * server_lag is tracked in seconds; returns server_lag * 1000.
 * Returns 0 when not connected or lag is unknown.
 * Returns -1000 when the server appears to be completely unresponsive. */
static int tcl_serverlag STDOBJVAR {
  if (objc != 1) {
    Tcl_WrongNumArgs(irp, 1, objv, "");
    return TCL_ERROR;
  }
  Tcl_SetObjResult(irp, Tcl_NewIntObj(server_lag * 1000));
  return TCL_OK;
}

/* isupportval <token> — returns the effective value of an ISUPPORT token
 * as a string, or empty string if the token is not set.
 * Use "isupport get <token>" for the error-on-missing variant. */
static int tcl_isupportval STDOBJVAR {
  if (objc != 2) {
    Tcl_WrongNumArgs(irp, 1, objv, "token");
    return TCL_ERROR;
  }
  Tcl_Size keylen;
  const char *key = Tcl_GetStringFromObj(objv[1], &keylen);
  const char *val = isupport_get(key, (size_t)keylen);
  Tcl_SetResult(irp, val ? (char *)val : "", TCL_STATIC);
  return TCL_OK;
}

/* isupportprefix <mode> — returns the PREFIX character for the given mode
 * letter (e.g. 'o' → '@', 'v' → '+'), or empty string if not found. */
static int tcl_isupportprefix STDOBJVAR {
  if (objc != 2) {
    Tcl_WrongNumArgs(irp, 1, objv, "mode");
    return TCL_ERROR;
  }
  const char *modestr = Tcl_GetString(objv[1]);
  if (!modestr || !modestr[0]) {
    Tcl_SetResult(irp, "", TCL_STATIC);
    return TCL_OK;
  }
  char pch = isupport_get_prefix_char(modestr[0]);
  if (pch) {
    char buf[2] = { pch, '\0' };
    Tcl_SetResult(irp, buf, TCL_VOLATILE);
  } else {
    Tcl_SetResult(irp, "", TCL_STATIC);
  }
  return TCL_OK;
}

/* chathistory_latest <target> <count>
 * Sends CHATHISTORY LATEST <target> * <count> when draft/chathistory or
 * chathistory capability is active. */
static int tcl_chathistory_latest STDOBJVAR {
  if (objc < 3) {
    Tcl_WrongNumArgs(irp, 1, objv, "target count");
    return TCL_ERROR;
  }
  struct capability *cap = find_capability("draft/chathistory");
  if (!cap || !cap->enabled)
    cap = find_capability("chathistory");
  if (!cap || !cap->enabled) {
    Tcl_SetResult(irp, "chathistory cap not active", TCL_STATIC);
    return TCL_ERROR;
  }
  const char *target = Tcl_GetString(objv[1]);
  const char *count  = Tcl_GetString(objv[2]);
  dprintf(DP_SERVER, "CHATHISTORY LATEST %s * %s\n", target, count);
  return TCL_OK;
}

static tcl_cmds server_tcl_objcmds[] = {
  {"chathistory_latest", tcl_chathistory_latest},
  {"curserver",          tcl_curserver},
  {"getcurrentnick",     tcl_getcurrentnick},
  {"serverport",         tcl_serverport},
  {"serverlag",          tcl_serverlag},
  {"isupportval",        tcl_isupportval},
  {"isupportprefix",     tcl_isupportprefix},
  {nullptr,              nullptr}
};

static tcl_cmds my_tcl_cmds[] = {
  {"jump",          tcl_jump},
  {"cap",           tcl_cap},
  {"isbotnick",     tcl_isbotnick},
  {"clearqueue",    tcl_clearqueue},
  {"queuesize",     tcl_queuesize},
  {"puthelp",       tcl_puthelp},
  {"putserv",       tcl_putserv},
  {"putquick",      tcl_putquick},
  {"putnow",        tcl_putnow},
  {"tagmsg",        tcl_tagmsg},
  {"knock",         tcl_knock},
  {"redact",        tcl_redact},
  {"server",        tcl_server},
  {"getaccount",    tcl_getaccount},
  {"isidentified",  tcl_isidentified},
  {"monitor",       tcl_monitor},
  /* IRCX / Ophion commands */
  {"ircxprop",      tcl_ircxprop},
  {"ircxaccess",    tcl_ircxaccess},
  {"ircxcreate",    tcl_ircxcreate},
  {"ircxautoowner", tcl_ircxautoowner},
  {"ircxnegotiate", tcl_ircxnegotiate},
  {"ircxlistx",     tcl_ircxlistx},
  {"ircxrequest",   tcl_ircxrequest},
  {"ircxreply",     tcl_ircxreply},
  {"ircxmodex",     tcl_ircxmodex},
  {"ircxevent",     tcl_ircxevent},
  {"ircxregister",  tcl_ircxregister},
  {nullptr,         nullptr}
};

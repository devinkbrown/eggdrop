/*
 * tcltransfer.c -- part of transfer.mod
 *
 * Copyright (C) 2003 - 2025 Eggheads Development Team
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

/* This file requires Tcl — skip compilation when Tcl is disabled. */
#ifdef HAVE_TCL

static int tcl_dccsend STDVAR
{
  char *sys, *nfn;

  BADARGS(3, 3, " filename ircnick");

  if (!file_readable(argv[1])) {
    Tcl_AppendResult(irp, "3", NULL);
    return TCL_OK;
  }
  nfn = strrchr(argv[1], '/');

  if (nfn == NULL)
    nfn = argv[1];
  else
    nfn++;
  if (at_limit(argv[2])) {
    if (nfn == argv[1])
      queue_file("*", nfn, "(script)", argv[2]);
    else {
      nfn--;
      *nfn = 0;
      nfn++;
      {
        op_strbuf_t _b;
        op_strbuf_printf(&_b, "*%s", argv[1]);
        sys = nmalloc(op_strbuf_len(&_b) + 1);
        strlcpy(sys, op_strbuf_str(&_b), op_strbuf_len(&_b) + 1);
        op_strbuf_free(&_b);
      }
      queue_file(sys, nfn, "(script)", argv[2]);
      nfree(sys);
    }
    Tcl_AppendResult(irp, "4", NULL);
    return TCL_OK;
  }
  int i = raw_dcc_send(argv[1], argv[2], "*");
  Tcl_AppendResult(irp, int_to_base10(i), NULL);
  return TCL_OK;
}

static int tcl_getfileq STDVAR
{
  char *s = NULL;
  fileq_t *q;

  BADARGS(2, 2, " handle");

  for (q = fileq; q; q = q->next) {
    if (!strcasecmp(q->nick, argv[1])) {
      {
        op_strbuf_t _b;
        if (q->dir[0] == '*') {
          op_strbuf_printf(&_b, "%s %s/%s", q->to, &q->dir[1], q->file);
        } else {
          if (q->dir[0])
            op_strbuf_printf(&_b, "%s /%s/%s", q->to, q->dir, q->file);
          else
            op_strbuf_printf(&_b, "%s /%s", q->to, q->file);
        }
        s = nrealloc(s, op_strbuf_len(&_b) + 1);
        strlcpy(s, op_strbuf_str(&_b), op_strbuf_len(&_b) + 1);
        op_strbuf_free(&_b);
      }
      Tcl_AppendElement(irp, s);
    }
  }
  if (s)
    nfree(s);
  return TCL_OK;
}

static int tcl_getfilesendtime STDVAR
{
  int sock;

  BADARGS(2, 2, " idx");

  sock = atoi(argv[1]);
  for (int i = 0; i < dcc_total; i++) {
    if (dcc[i].sock == sock) {
      if (dcc[i].type == &DCC_SEND || dcc[i].type == &DCC_GET) {
        op_strbuf_t _b;
        op_strbuf_printf(&_b, "%lu", dcc[i].u.xfer->start_time);
        Tcl_AppendResult(irp, op_strbuf_str(&_b), NULL);
        op_strbuf_free(&_b);
      } else
        Tcl_AppendResult(irp, "-2", NULL); /* Not a valid file transfer */
      return TCL_OK;
    }
  }
  Tcl_AppendResult(irp, "-1", NULL); /* No matching entry found. */
  return TCL_OK;
}

static tcl_cmds mytcls[] = {
  {"dccsend",                 tcl_dccsend},
  {"getfileq",               tcl_getfileq},
  {"getfilesendtime", tcl_getfilesendtime},
  {NULL,                             NULL}
};

#endif /* HAVE_TCL */

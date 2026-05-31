/*
 * msgcounter.c -- part of msgcounter.mod
 *   Per-channel PRIVMSG rate counter.  Tracks message and byte counts per
 *   channel using op_htab and logs [MSGRATE] lines to LOG_MISC once per
 *   minute via HOOK_MINUTELY.
 *
 * Copyright (C) 2026 Eggheads Development Team
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

#define MODULE_NAME "msgcounter"
#define MAKING_MSGCOUNTER

#include <stddef.h>
#include <inttypes.h>
#include <stdio.h>
#include "src/mod/module.h"
#include "msgcounter.h"

static Function *global = nullptr;

/* ---- per-channel counter ------------------------------------------------- */

typedef struct {
  uint64_t msgs_since;
  uint64_t bytes_since;
  uint64_t msgs_total;
  uint64_t bytes_total;
  double   last_rate;    /* msgs/min from the most recent minutely flush */
} chan_counter_t;

static op_htab *counter_ht = NULL;  /* istr: dname -> chan_counter_t * */

/* ---- counter operations -------------------------------------------------- */

static void msgcounter_record(const char *dname, size_t msglen)
{
  if (!counter_ht || !dname)
    return;

  chan_counter_t *c = op_htab_get(counter_ht, dname);
  if (!c) {
    c = op_calloc(1, sizeof *c);
    /* key must outlive the entry; dname is chan->dname (permanent storage) */
    op_htab_set(counter_ht, (void *)dname, c, NULL);
  }
  c->msgs_since++;
  c->bytes_since += (uint64_t)msglen;
  c->msgs_total++;
  c->bytes_total += (uint64_t)msglen;
}

static void msgcounter_minutely(void)
{
  if (!counter_ht)
    return;

  uint64_t total_msgs  = 0;
  uint64_t total_bytes = 0;

  op_htab_iter_t it;
  op_htab_iter_init(counter_ht, &it);
  void *key, *val;
  while (op_htab_iter_next(counter_ht, &it, &key, &val)) {
    const char    *dname = (const char *)key;
    chan_counter_t *c    = (chan_counter_t *)val;

    if (c->msgs_since == 0)
      continue;

    putlog(LOG_MISC, "*",
           "[MSGRATE] t=%lu chan=%s msgs=%" PRIu64 " bytes=%" PRIu64
           " rate=%.2f/s total_msgs=%" PRIu64 " total_bytes=%" PRIu64,
           (unsigned long)now,
           dname,
           c->msgs_since,
           c->bytes_since,
           (double)c->msgs_since / 60.0,
           c->msgs_total,
           c->bytes_total);

    total_msgs  += c->msgs_since;
    total_bytes += c->bytes_since;

    c->last_rate   = (double)c->msgs_since / 60.0;
    c->msgs_since  = 0;
    c->bytes_since = 0;
  }

  if (total_msgs > 0)
    putlog(LOG_MISC, "*",
           "[MSGRATE] t=%lu chan=ALL msgs=%" PRIu64 " bytes=%" PRIu64
           " rate=%.2f/s",
           (unsigned long)now,
           total_msgs,
           total_bytes,
           (double)total_msgs / 60.0);
}

static void free_counter_entry(void *key, void *val, void *ud)
{
  (void)key; (void)ud;
  op_free(val);
}

/* ---- exported query helpers --------------------------------------------- */

/* Return the sum of msgs_total across all channels (global lifetime count). */
uint64_t get_msgcounter_total(void)
{
  if (!counter_ht)
    return 0;
  uint64_t total = 0;
  op_htab_iter_t it;
  op_htab_iter_init(counter_ht, &it);
  void *key, *val;
  while (op_htab_iter_next(counter_ht, &it, &key, &val)) {
    const chan_counter_t *c = (const chan_counter_t *)val;
    total += c->msgs_total;
  }
  return total;
}

/* Return the msgs/min rate for a channel from its most recent minutely flush.
 * Returns 0 if the channel is unknown. */
double get_msgcounter_rate(const char *dname)
{
  if (!counter_ht || !dname)
    return 0.0;
  const chan_counter_t *c = (const chan_counter_t *)op_htab_get(counter_ht, dname);
  return c ? c->last_rate : 0.0;
}

/* ---- Tcl command handlers ----------------------------------------------- */

/* msgrate <channel> — return msgs/min for the channel (0 if unknown) */
static int tcl_msgrate STDVAR
{
  BADARGS(2, 2, " channel");

  double rate = get_msgcounter_rate(argv[1]);

  char buf[32];
  snprintf(buf, sizeof buf, "%.2f", rate);
  Tcl_AppendResult(irp, buf, nullptr);
  return TCL_OK;
}

/* msgtotal — return global lifetime message count */
static int tcl_msgtotal STDVAR
{
  BADARGS(1, 1, "");

  char buf[32];
  snprintf(buf, sizeof buf, "%" PRIu64, get_msgcounter_total());
  Tcl_AppendResult(irp, buf, nullptr);
  return TCL_OK;
}

static tcl_cmds msgcounter_tcls[] = {
  {"msgrate",   tcl_msgrate},
  {"msgtotal",  tcl_msgtotal},
  {nullptr,     nullptr}
};

/* ---- required module functions ------------------------------------------ */

static int msgcounter_expmem(void)
{
  return 0;
}

static void msgcounter_report(int idx, int details)
{
  if (details) {
    dprintf(idx, "    Per-channel PRIVMSG rate counter active\n");
    if (counter_ht)
      dprintf(idx, "    Tracking %zu channel(s)\n",
              op_htab_size(counter_ht));
  }
}

static char *msgcounter_close(void)
{
  rem_tcl_commands(msgcounter_tcls);
  del_hook(HOOK_MINUTELY, (Function) msgcounter_minutely);
  if (counter_ht) {
    op_htab_destroy(counter_ht, free_counter_entry, NULL);
    counter_ht = NULL;
  }
  module_undepend(MODULE_NAME);
  return nullptr;
}

EXPORT_SCOPE char *msgcounter_start(Function *);

static Function msgcounter_table[] = {
  /* 0 - 3: mandatory */
  (Function) msgcounter_start,
  (Function) msgcounter_close,
  (Function) msgcounter_expmem,
  (Function) msgcounter_report,
  /* 4: MSGCOUNTER_record */
  (Function) msgcounter_record,
  /* 5: MSGCOUNTER_get_total */
  (Function) get_msgcounter_total,
  /* 6: MSGCOUNTER_get_rate */
  (Function) get_msgcounter_rate,
};

char *msgcounter_start(Function *global_funcs)
{
  global = global_funcs;

  module_register(MODULE_NAME, msgcounter_table, 1, 0);
  if (!module_depend(MODULE_NAME, "eggdrop", 108, 0)) {
    module_undepend(MODULE_NAME);
    return "This module requires Eggdrop 1.8.0 or later.";
  }

  counter_ht = op_htab_create_istr("msg_counter", 16);
  add_hook(HOOK_MINUTELY, (Function) msgcounter_minutely);
  add_tcl_commands(msgcounter_tcls);
  return nullptr;
}

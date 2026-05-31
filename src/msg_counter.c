/*
 * msg_counter.c -- per-channel PRIVMSG rate counter for perf testing.
 *
 * Copyright (C) 2026 Eggheads Development Team
 */

#include "main.h"
#include "msg_counter.h"

typedef struct {
  uint64_t msgs_since;
  uint64_t bytes_since;
  uint64_t msgs_total;
  uint64_t bytes_total;
} chan_counter_t;

static op_htab *counter_ht = NULL;  /* istr: dname → chan_counter_t * */

extern time_t now;

void msg_counter_init(void)
{
  if (counter_ht)
    return;
  counter_ht = op_htab_create_istr("msg_counter", 16);
}

void msg_counter_record(const char *dname, size_t msglen)
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

void msg_counter_minutely(void)
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

void msg_counter_free(void)
{
  if (!counter_ht)
    return;
  op_htab_destroy(counter_ht, free_counter_entry, NULL);
  counter_ht = NULL;
}

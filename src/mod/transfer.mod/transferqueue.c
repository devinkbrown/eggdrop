/*
 * transferqueue.c -- part of transfer.mod
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

static op_bh *fileq_bh = nullptr;

static int expmem_fileq(void)
{
  int tot = 0;

  for (size_t i = 0; i < fileq_vec.size; i++) {
    const fileq_t *q = (const fileq_t *)op_vec_get(&fileq_vec, i);
    tot += strlen(q->dir) + strlen(q->file) + 2 + sizeof(fileq_t);
  }
  return tot;
}

static void queue_file(const char *dir, const char *file, const char *from, const char *to)
{
  if (!fileq_bh)
    fileq_bh = op_bh_create(sizeof(fileq_t), 32, "transfer_fileq");
  fileq_t *q = (fileq_t *)op_bh_alloc(fileq_bh);
  size_t l = strlen(dir) + 1;
  q->dir = (char *)op_malloc(l);
  op_strlcpy(q->dir, dir, l);
  l = strlen(file) + 1;
  q->file = (char *)op_malloc(l);
  op_strlcpy(q->file, file, l);
  op_strlcpy(q->nick, from, sizeof q->nick);
  op_strlcpy(q->to, to, sizeof q->to);
  op_vec_push(&fileq_vec, q);
}

/* Free and remove the entry at index qi (order-preserving).
 */
static void deq_idx(size_t qi)
{
  fileq_t *q = (fileq_t *)op_vec_get(&fileq_vec, qi);
  op_free(q->dir);
  op_free(q->file);
  op_bh_free(fileq_bh, q);
  op_vec_remove(&fileq_vec, qi);
}

/* Remove all files queued to a certain user (backwards pass avoids index drift).
 */
static void flush_fileq(char *to)
{
  for (size_t i = fileq_vec.size; i-- > 0; ) {
    fileq_t *q = (fileq_t *)op_vec_get(&fileq_vec, i);
    if (!op_strcasecmp(q->to, to))
      deq_idx(i);
  }
}

static void send_next_file(char *to)
{
  fileq_t *this_entry = nullptr;
  size_t this_idx = 0;
  char *s;
  int x;

  /* Find the oldest queued file for this recipient (first match). */
  for (size_t i = 0; i < fileq_vec.size; i++) {
    fileq_t *q = (fileq_t *)op_vec_get(&fileq_vec, i);
    if (!op_strcasecmp(q->to, to)) {
      this_entry = q;
      this_idx = i;
      break;
    }
  }

  if (!this_entry)
    return;

  if (this_entry->dir[0] == '*') { /* Absolute path */
    op_strbuf_t _b = {};
    op_strbuf_init(&_b);
    op_strbuf_appendf(&_b, "%s/%s", &this_entry->dir[1], this_entry->file);
    s = op_strbuf_steal(&_b);
  } else {
    char *p = strchr(this_entry->dir, '*');

    if (p == nullptr) {
      send_next_file(to);
      return;
    }

    p++;
    {
      op_strbuf_t _b = {};
      op_strbuf_init(&_b);
      if (p[0])
        op_strbuf_appendf(&_b, "%s/%s", p, this_entry->file);
      else
        op_strbuf_append_cstr(&_b, this_entry->file);
      s = op_strbuf_steal(&_b);
    }
    op_strlcpy(this_entry->dir, &(p[egg_atoi(this_entry->dir)]), sizeof(this_entry->dir));
  }
  if (this_entry->dir[0] == '*') {
    op_strbuf_t _b = {};
    op_strbuf_init(&_b);
    op_strbuf_appendf(&_b, "%s/%s", &this_entry->dir[1], this_entry->file);
    op_free(s);
    s = op_strbuf_steal(&_b);
  } else {
    op_strbuf_t _b = {};
    op_strbuf_init(&_b);
    if (this_entry->dir[0])
      op_strbuf_appendf(&_b, "%s/%s", this_entry->dir, this_entry->file);
    else
      op_strbuf_append_cstr(&_b, this_entry->file);
    op_free(s);
    s = op_strbuf_steal(&_b);
  }
  x = raw_dcc_send(s, this_entry->to, this_entry->nick);
  if (x == DCCSEND_OK) {
    if (op_strcasecmp(this_entry->to, this_entry->nick))
      dprintf(DP_HELP, TRANSFER_FILE_ARRIVE, this_entry->to, this_entry->nick);
    deq_idx(this_idx);
  } else if (x == DCCSEND_FULL) {
    putlog(LOG_FILES, "*", TRANSFER_LOG_CONFULL, s, this_entry->nick);
    dprintf(DP_HELP, TRANSFER_NOTICE_CONFULL, this_entry->to);
    op_strlcpy(s, this_entry->to, sizeof(s));
    flush_fileq(s);
  } else if (x == DCCSEND_NOSOCK) {
    putlog(LOG_FILES, "*", TRANSFER_LOG_SOCKERR, s, this_entry->nick);
    dprintf(DP_HELP, TRANSFER_NOTICE_SOCKERR, this_entry->to);
    op_strlcpy(s, this_entry->to, sizeof(s));
    flush_fileq(s);
  } else if (x == DCCSEND_FCOPY) {
    putlog(LOG_FILES | LOG_MISC, "*", TRANSFER_COPY_FAILED, this_entry->file);
    dprintf(DP_HELP, TRANSFER_FILESYS_BROKEN, this_entry->to);
    op_strlcpy(s, this_entry->to, sizeof(s));
    flush_fileq(s);
  } else {
    if (x == DCCSEND_FEMPTY) {
      putlog(LOG_FILES, "*", TRANSFER_LOG_FILEEMPTY, this_entry->file);
      dprintf(DP_HELP, TRANSFER_NOTICE_FILEEMPTY, this_entry->to, this_entry->file);
    }
    deq_idx(this_idx);
  }
  op_free(s);
}

static void show_queued_files(int idx)
{
  int cnt = 0, len;
  char spaces[] = "                                 ";

  for (size_t i = 0; i < fileq_vec.size; i++) {
    fileq_t *q = (fileq_t *)op_vec_get(&fileq_vec, i);
    if (!op_strcasecmp(q->nick, dcc[idx].nick)) {
      if (!cnt) {
        spaces[HANDLEN - 9] = 0;
        dprintf(idx, TRANSFER_SEND_TO, spaces);
        dprintf(idx, TRANSFER_LINES, spaces);
        spaces[HANDLEN - 9] = ' ';
      }
      cnt++;
      spaces[len = HANDLEN - strlen(q->to)] = 0;
      if (q->dir[0] == '*')
        dprintf(idx, "  %s%s  %s/%s\n", q->to, spaces, &q->dir[1], q->file);
      else
        dprintf(idx, "  %s%s  /%s%s%s\n", q->to, spaces, q->dir,
                q->dir[0] ? "/" : "", q->file);
      spaces[len] = ' ';
    }
  }
  for (int i = 0; i < dcc_total; i++) {
    if ((dcc[i].type == &DCC_GET_PENDING || dcc[i].type == &DCC_GET) &&
        (!op_strcasecmp(dcc[i].nick, dcc[idx].nick) ||
         !op_strcasecmp(dcc[i].u.xfer->from, dcc[idx].nick))) {
      char *nfn;

      if (!cnt) {
        spaces[HANDLEN - 9] = 0;
        dprintf(idx, TRANSFER_SEND_TO, spaces);
        dprintf(idx, TRANSFER_LINES, spaces);
        spaces[HANDLEN - 9] = ' ';
      }
      nfn = strrchr(dcc[i].u.xfer->origname, '/');
      if (nfn == nullptr)
        nfn = dcc[i].u.xfer->origname;
      else
        nfn++;
      cnt++;
      spaces[len = HANDLEN - strlen(dcc[i].nick)] = 0;
      if (dcc[i].type == &DCC_GET_PENDING)
        dprintf(idx, TRANSFER_WAITING, dcc[i].nick, spaces, nfn);
      else
        dprintf(idx, TRANSFER_DONE, dcc[i].nick, spaces, nfn, (100.0 *
                ((float) dcc[i].status / (float) dcc[i].u.xfer->length)));
      spaces[len] = ' ';
    }
  }
  if (!cnt)
    dprintf(idx, "%s", TRANSFER_QUEUED_UP);
  else
    dprintf(idx, TRANSFER_TOTAL, cnt);
}

static void fileq_cancel(int idx, char *par)
{
  int matches = 0, atot = 0;
  char *s = nullptr;

  /* Backwards pass so removals don't shift unvisited indices. */
  for (size_t i = fileq_vec.size; i-- > 0; ) {
    fileq_t *q = (fileq_t *)op_vec_get(&fileq_vec, i);
    if (!op_strcasecmp(dcc[idx].nick, q->nick)) {
      {
        op_strbuf_t _b = {};
        op_strbuf_init(&_b);
        if (q->dir[0] == '*') {
          op_strbuf_appendf(&_b, "%s/%s", &q->dir[1], q->file);
        } else {
          if (q->dir[0])
            op_strbuf_appendf(&_b, "/%s/%s", q->dir, q->file);
          else
            op_strbuf_appendf(&_b, "/%s", q->file);
        }
        op_free(s);
        s = op_strbuf_steal(&_b);
      }
      if (wild_match_file(par, s) || wild_match_file(par, q->file)) {
        dprintf(idx, TRANSFER_CANCELLED, s, q->to);
        deq_idx(i);
        matches++;
      }
    }
  }

  if (s)
    op_free(s);

  for (int i = 0; i < dcc_total; i++) {
    if ((dcc[i].type == &DCC_GET_PENDING || dcc[i].type == &DCC_GET) &&
        (!op_strcasecmp(dcc[i].nick, dcc[idx].nick) ||
         !op_strcasecmp(dcc[i].u.xfer->from, dcc[idx].nick))) {
      char *nfn = strrchr(dcc[i].u.xfer->origname, '/');

      if (nfn == nullptr)
        nfn = dcc[i].u.xfer->origname;
      else
        nfn++;
      if (wild_match_file(par, nfn)) {
        dprintf(idx, TRANSFER_ABORT_DCCSEND, nfn);
        if (op_strcasecmp(dcc[i].nick, dcc[idx].nick))
          dprintf(DP_HELP, TRANSFER_NOTICE_ABORT, dcc[i].nick, nfn,
                  dcc[idx].nick);
        if (dcc[i].type == &DCC_GET)
          putlog(LOG_FILES, "*", TRANSFER_DCC_CANCEL, nfn, dcc[i].nick,
                 dcc[i].status, dcc[i].u.xfer->length);
        atot++;
        matches++;
        killsock(dcc[i].sock);
        lostdcc(i);
      }
    }
  }
  if (!matches)
    dprintf(idx, "%s", TRANSFER_NO_MATCHES);
  else
    dprintf(idx, TRANSFER_CANCELLED_FILE, matches, (matches != 1) ? "s" : "");
  for (int i = 0; i < atot; i++)
    if (!at_limit(dcc[idx].nick))
      send_next_file(dcc[idx].nick);
}

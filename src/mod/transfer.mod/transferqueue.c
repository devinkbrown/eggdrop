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
  fileq_t *q;
  int tot = 0;

  for (q = fileq; q; q = q->next)
    tot += strlen(q->dir) + strlen(q->file) + 2 + sizeof(fileq_t);

  return tot;
}

static void queue_file(const char *dir, const char *file, const char *from, const char *to)
{
  fileq_t *q = fileq;
  size_t l;

  if (!fileq_bh)
    fileq_bh = op_bh_create(sizeof(fileq_t), 32, "transfer_fileq");
  fileq = op_bh_alloc(fileq_bh);
  fileq->next = q;
  l = strlen(dir) + 1;
  fileq->dir = op_malloc(l);
  strlcpy(fileq->dir, dir, l);
  l = strlen(file) + 1;
  fileq->file = op_malloc(l);
  strlcpy(fileq->file, file, l);
  strlcpy(fileq->nick, from, sizeof fileq->nick);
  strlcpy(fileq->to, to, sizeof fileq->to);
}

static void deq_this(fileq_t *this)
{
  fileq_t *q = fileq, *last = nullptr;

  while (q && q != this) {
    last = q;
    q = q->next;
  }

  if (!q)
    return;

  if (last)
    last->next = q->next;
  else
    fileq = q->next;
  op_free(q->dir);
  op_free(q->file);
  op_bh_free(fileq_bh, q);
}

/* Remove all files queued to a certain user.
 */
static void flush_fileq(char *to)
{
  fileq_t *q;
  int fnd = 1;

  while (fnd) {
    q = fileq;
    fnd = 0;
    while (q != nullptr) {
      if (!strcasecmp(q->to, to)) {
        deq_this(q);
        q = nullptr;
        fnd = 1;
      }
      if (q != nullptr)
        q = q->next;
    }
  }
}

static void send_next_file(char *to)
{
  fileq_t *q, *this = nullptr;
  char *s;
  int x;

  for (q = fileq; q; q = q->next)
    if (!strcasecmp(q->to, to))
      this = q;

  if (this == nullptr)
    return;

  if (this->dir[0] == '*') { /* Absolute path */
    op_strbuf_t _b;
    op_strbuf_init(&_b);
    op_strbuf_appendf(&_b, "%s/%s", &this->dir[1], this->file);
    s = op_strbuf_steal(&_b);
  } else {
    char *p = strchr(this->dir, '*');

    if (p == nullptr) {
      send_next_file(to);
      return;
    }

    p++;
    {
      op_strbuf_t _b;
      op_strbuf_init(&_b);
      if (p[0])
        op_strbuf_appendf(&_b, "%s/%s", p, this->file);
      else
        op_strbuf_appendf(&_b, "%s", this->file);
      s = op_strbuf_steal(&_b);
    }
    strlcpy(this->dir, &(p[egg_atoi(this->dir)]), sizeof(this->dir));
  }
  if (this->dir[0] == '*') {
    op_strbuf_t _b;
    op_strbuf_init(&_b);
    op_strbuf_appendf(&_b, "%s/%s", &this->dir[1], this->file);
    op_free(s);
    s = op_strbuf_steal(&_b);
  } else {
    op_strbuf_t _b;
    op_strbuf_init(&_b);
    if (this->dir[0])
      op_strbuf_appendf(&_b, "%s/%s", this->dir, this->file);
    else
      op_strbuf_appendf(&_b, "%s", this->file);
    op_free(s);
    s = op_strbuf_steal(&_b);
  }
  x = raw_dcc_send(s, this->to, this->nick);
  if (x == DCCSEND_OK) {
    if (strcasecmp(this->to, this->nick))
      dprintf(DP_HELP, TRANSFER_FILE_ARRIVE, this->to, this->nick);
    deq_this(this);
  } else if (x == DCCSEND_FULL) {
    putlog(LOG_FILES, "*", TRANSFER_LOG_CONFULL, s, this->nick);
    dprintf(DP_HELP, TRANSFER_NOTICE_CONFULL, this->to);
    strlcpy(s, this->to, sizeof(s));
    flush_fileq(s);
  } else if (x == DCCSEND_NOSOCK) {
    putlog(LOG_FILES, "*", TRANSFER_LOG_SOCKERR, s, this->nick);
    dprintf(DP_HELP, TRANSFER_NOTICE_SOCKERR, this->to);
    strlcpy(s, this->to, sizeof(s));
    flush_fileq(s);
  } else if (x == DCCSEND_FCOPY) {
    putlog(LOG_FILES | LOG_MISC, "*", TRANSFER_COPY_FAILED, this->file);
    dprintf(DP_HELP, TRANSFER_FILESYS_BROKEN, this->to);
    strlcpy(s, this->to, sizeof(s));
    flush_fileq(s);
  } else {
    if (x == DCCSEND_FEMPTY) {
      putlog(LOG_FILES, "*", TRANSFER_LOG_FILEEMPTY, this->file);
      dprintf(DP_HELP, TRANSFER_NOTICE_FILEEMPTY, this->to, this->file);
    }
    deq_this(this);
  }
  op_free(s);

  return;
}

static void show_queued_files(int idx)
{
  int cnt = 0, len;
  char spaces[] = "                                 ";
  fileq_t *q;

  for (q = fileq; q; q = q->next) {
    if (!strcasecmp(q->nick, dcc[idx].nick)) {
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
        (!strcasecmp(dcc[i].nick, dcc[idx].nick) ||
         !strcasecmp(dcc[i].u.xfer->from, dcc[idx].nick))) {
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
  int fnd = 1, matches = 0, atot = 0;
  fileq_t *q;
  char *s = nullptr;

  while (fnd) {
    q = fileq;
    fnd = 0;
    while (q != nullptr) {
      if (!strcasecmp(dcc[idx].nick, q->nick)) {
        {
          op_strbuf_t _b;
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
        if (wild_match_file(par, s)) {
          dprintf(idx, TRANSFER_CANCELLED, s, q->to);
          fnd = 1;
          deq_this(q);
          q = nullptr;
          matches++;
        }
        if (!fnd && wild_match_file(par, q->file)) {
          dprintf(idx, TRANSFER_CANCELLED, s, q->to);
          fnd = 1;
          deq_this(q);
          q = nullptr;
          matches++;
        }
      }
      if (q != nullptr)
        q = q->next;
    }
  }

  if (s)
    op_free(s);

  for (int i = 0; i < dcc_total; i++) {
    if ((dcc[i].type == &DCC_GET_PENDING || dcc[i].type == &DCC_GET) &&
        (!strcasecmp(dcc[i].nick, dcc[idx].nick) ||
         !strcasecmp(dcc[i].u.xfer->from, dcc[idx].nick))) {
      char *nfn = strrchr(dcc[i].u.xfer->origname, '/');

      if (nfn == nullptr)
        nfn = dcc[i].u.xfer->origname;
      else
        nfn++;
      if (wild_match_file(par, nfn)) {
        dprintf(idx, TRANSFER_ABORT_DCCSEND, nfn);
        if (strcasecmp(dcc[i].nick, dcc[idx].nick))
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

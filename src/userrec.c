/*
 * userrec.c -- handles:
 *   add_q() del_q() str2flags() flags2str() str2chflags() chflags2str()
 *   a bunch of functions to find and change user records
 *   change and check user (and channel-specific) flags
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

#define COMPILING_MEM   /* suppress malloc→dont_use_old_malloc before op_lib.h */
#include <sys/stat.h>
#include <op_lib.h>
#include "main.h"
#include "modules.h"
#include "tandem.h"
#include "egg_store.h"
#include "async_fileio.h"
extern struct dcc_t *dcc;
extern struct chanset_t *chanset;
extern int default_flags, default_uflags, quiet_save, dcc_total, share_greet,
           remove_pass;
extern char ver[], botnetnick[];
extern time_t now;

int noshare = 1;                   /* don't send out to sharebots       */
struct userrec *userlist = nullptr;   /* user records are stored here      */

/* libop balloc heaps for fixed-size user record structs.
 * Replaced op_malloc(sizeof(*x)) / op_free(x) with these wrappers everywhere
 * these structs are allocated or freed, giving O(1) slab alloc/free and
 * returning memory to the OS when the heaps are destroyed on shutdown. */
static op_bh *userrec_heap     = nullptr;
static op_bh *chanuserrec_heap = nullptr;
static op_bh *user_entry_heap  = nullptr;
static op_bh *list_type_heap   = nullptr;
static op_bh *xtra_key_heap    = nullptr;
static op_bh *laston_info_heap = nullptr;
static op_bh *igrec_heap       = nullptr;
static op_bh *maskrec_heap     = nullptr;

void userrec_heaps_init(void)
{
  userrec_heap     = op_bh_create(sizeof(struct userrec),     0, "userrec");
  chanuserrec_heap = op_bh_create(sizeof(struct chanuserrec), 0, "chanuserrec");
  user_entry_heap  = op_bh_create(sizeof(struct user_entry),  0, "user_entry");
  list_type_heap   = op_bh_create(sizeof(struct list_type),   0, "list_type");
  xtra_key_heap    = op_bh_create(sizeof(struct xtra_key),   64, "xtra_key");
  laston_info_heap = op_bh_create(sizeof(struct laston_info), 0, "laston_info");
  igrec_heap       = op_bh_create(sizeof(struct igrec),      16, "igrec");
  maskrec_heap     = op_bh_create(sizeof(maskrec),           32, "maskrec");
}

void userrec_heaps_destroy(void)
{
  if (userrec_heap)     { op_bh_destroy(userrec_heap);     userrec_heap     = nullptr; }
  if (chanuserrec_heap) { op_bh_destroy(chanuserrec_heap); chanuserrec_heap = nullptr; }
  if (user_entry_heap)  { op_bh_destroy(user_entry_heap);  user_entry_heap  = nullptr; }
  if (list_type_heap)   { op_bh_destroy(list_type_heap);   list_type_heap   = nullptr; }
  if (xtra_key_heap)    { op_bh_destroy(xtra_key_heap);    xtra_key_heap    = nullptr; }
  if (laston_info_heap) { op_bh_destroy(laston_info_heap); laston_info_heap = nullptr; }
  if (igrec_heap)       { op_bh_destroy(igrec_heap);       igrec_heap       = nullptr; }
  if (maskrec_heap)     { op_bh_destroy(maskrec_heap);     maskrec_heap     = nullptr; }
}

struct userrec *alloc_userrec(void)
{
  struct userrec *u = op_bh_alloc(userrec_heap);
  memset(u, 0, sizeof *u);
  return u;
}

void free_userrec(struct userrec *u)
{
  op_bh_free(userrec_heap, u);
}

struct chanuserrec *alloc_chanuserrec(void)
{
  struct chanuserrec *cr = op_bh_alloc(chanuserrec_heap);
  memset(cr, 0, sizeof *cr);
  return cr;
}

void free_chanuserrec(struct chanuserrec *cr)
{
  op_bh_free(chanuserrec_heap, cr);
}

struct user_entry *alloc_user_entry(void)
{
  struct user_entry *ue = op_bh_alloc(user_entry_heap);
  memset(ue, 0, sizeof *ue);
  return ue;
}

void free_user_entry(struct user_entry *ue)
{
  op_bh_free(user_entry_heap, ue);
}

struct list_type *alloc_list_type(void)
{
  struct list_type *lt = op_bh_alloc(list_type_heap);
  memset(lt, 0, sizeof *lt);
  return lt;
}

void free_list_type(struct list_type *lt)
{
  op_bh_free(list_type_heap, lt);
}

struct xtra_key *alloc_xtra_key(void)
{
  struct xtra_key *xk = op_bh_alloc(xtra_key_heap);
  memset(xk, 0, sizeof *xk);
  return xk;
}

void free_xtra_key(struct xtra_key *xk)
{
  op_bh_free(xtra_key_heap, xk);
}

struct laston_info *alloc_laston_info(void)
{
  struct laston_info *li = op_bh_alloc(laston_info_heap);
  memset(li, 0, sizeof *li);
  return li;
}

void free_laston_info(struct laston_info *li)
{
  op_bh_free(laston_info_heap, li);
}

struct igrec *alloc_igrec(void)
{
  struct igrec *ig = op_bh_alloc(igrec_heap);
  memset(ig, 0, sizeof *ig);
  return ig;
}

void free_igrec(struct igrec *ig)
{
  op_bh_free(igrec_heap, ig);
}

maskrec *alloc_maskrec(void)
{
  maskrec *m = op_bh_alloc(maskrec_heap);
  memset(m, 0, sizeof *m);
  return m;
}

void free_maskrec(maskrec *m)
{
  op_bh_free(maskrec_heap, m);
}

struct userrec *lastuser = nullptr;   /* last accessed user record         */

/* Mark a user record as dirty for incremental saves */
[[maybe_unused]] static void mark_user_dirty(struct userrec *u)
{
  if (u)
    u->dirty = 1;
}

/* Mark all users as dirty (called after bulk operations) */
[[maybe_unused]] static void mark_all_users_dirty(void)
{
  for (struct userrec *u = userlist; u; u = u->next)
    u->dirty = 1;
}

/* Clear dirty flags for all users (called after successful save) */
[[maybe_unused]] static void clear_all_dirty_flags(void)
{
  for (struct userrec *u = userlist; u; u = u->next)
    u->dirty = 0;
}

/* Splay-tree index from lowercase handle → userrec *.
 * Maintained by adduser/deluser/change_handle/clear_userlist.
 * Rebuilt lazily on first get_user_by_handle() after a bulk load. */
static op_htab *user_handle_dict = nullptr;

static void user_dict_rebuild(void)
{
  struct userrec *u;

  if (user_handle_dict)
    op_htab_destroy(user_handle_dict, nullptr, nullptr);
  user_handle_dict = op_htab_create_istr("userhandles", 64);
  for (u = userlist; u; u = u->next)
    op_htab_set(user_handle_dict, u->handle, u, nullptr);
}

/* Splay-tree index from IRC account name → userrec *.
 *
 * A user can have multiple accounts (each a separate list_type node under
 * USERENTRY_ACCOUNT); every account string gets its own key in this tree
 * pointing at the owning userrec.  "none" placeholder entries are skipped.
 *
 * Maintained by addaccount_by_handle / del_host_or_account(type=1) /
 * deluser / clear_userlist.  Rebuilt lazily on the first
 * get_user_by_account() call after a bulk load (e.g. readuserfile). */
static op_htab *user_account_dict = nullptr;

/* Invalidate (destroy) the account dict so it is lazily rebuilt on the next
 * get_user_by_account() call.  Call this whenever accounts are modified via
 * set_user(&USERENTRY_ACCOUNT, ...) directly rather than through the
 * addaccount_by_handle / delaccount_by_handle API. */
void user_account_dict_invalidate(void)
{
  if (user_account_dict) {
    op_htab_destroy(user_account_dict, nullptr, nullptr);
    user_account_dict = nullptr;
  }
}

static void user_account_dict_rebuild(void)
{
  struct userrec *u;
  struct list_type *q;

  if (user_account_dict)
    op_htab_destroy(user_account_dict, nullptr, nullptr);
  user_account_dict = op_htab_create_istr("useraccounts", 64);
  for (u = userlist; u; u = u->next)
    for (q = get_user(&USERENTRY_ACCOUNT, u); q; q = q->next)
      if (q->extra && strcmp(q->extra, "none"))
        op_htab_set(user_account_dict, q->extra, u, nullptr);
}
maskrec *global_bans = nullptr, *global_exempts = nullptr, *global_invites = nullptr;
op_htab *global_bans_ht = nullptr, *global_exempts_ht = nullptr, *global_invites_ht = nullptr;
struct igrec *global_ign = nullptr;
int cache_hit = 0, cache_miss = 0; /* temporary cache accounting        */
int userfile_perm = 0600;          /* Userfile permissions
                                    * (default rw-------)               */
char userfile[121];                /* where the user records are stored */

/* ABI stubs — internal code uses op_malloc/op_realloc directly via the
 * user_malloc/user_realloc macros (which now expand to op_malloc/op_realloc).
 * These functions remain only so that global_table[39]/[229] resolve for
 * externally compiled modules still calling the old slots.
 */
void *_user_malloc(int size, const char *file, int line)
{
  (void)file; (void)line;
  return op_malloc(size);
}

void *_user_realloc(void *ptr, int size, const char *file, int line)
{
  (void)file; (void)line;
  return op_realloc(ptr, size);
}

[[maybe_unused]] static int expmem_mask(struct maskrec *m)
{
  int result = 0;

  for (; m; m = m->next) {
    result += sizeof(struct maskrec);
    result += strlen(m->mask) + 1;
    if (m->user)
      result += strlen(m->user) + 1;
    if (m->desc)
      result += strlen(m->desc) + 1;
  }

  return result;
}

/* Memory we should be using
 */

int count_users(struct userrec *bu)
{
  int tot = 0;
  struct userrec *u;

  for (u = bu; u; u = u->next)
    tot++;
  return tot;
}

/* Shortcut for get_user_by_handle -- might have user record in dccs
 */
static struct userrec *check_dcclist_hand(char *handle)
{
  for (int i = 0; i < dcc_total; i++)
    if (!strcasecmp(dcc[i].nick, handle))
      return dcc[i].user;
  return nullptr;
}

/* Search every channel record for the provided nickname. Used in cases where
 * we are searching for a user record but don't have a memberlist to start from
 */
memberlist *find_member_from_nick(char *nick) {
  struct chanset_t *chan;
  memberlist *m = nullptr;

  for (chan = chanset; chan; chan = chan->next) {
    for (m = chan->channel.member; m && m->nick[0]; m = m->next) {
      if (!rfc_casecmp(m->nick, nick)) {
        return m;
      }
    }
  }
  return m;
}

/* Search userlist for a provided account name.
 * Returns: userrecord for user containing the account, or nullptr.
 *
 * Uses user_account_dict (splay tree, O(log n)) when available.
 * Falls back to O(n×m) linear scan if the dict has not been built yet;
 * the lazy rebuild triggers on the next call once userlist is populated.
 */
struct userrec *get_user_by_account(const char *acct)
{
  struct userrec *u;
  struct list_type *q;

  if (!acct || !acct[0] || !strcmp(acct, "*"))
    return nullptr;
  /* Lazy-build account index after a bulk load (e.g. readuserfile). */
  if (!user_account_dict && userlist)
    user_account_dict_rebuild();
  if (user_account_dict)
    return op_htab_get(user_account_dict,acct);
  /* Fallback: O(n×m) linear scan (dict unavailable). */
  for (u = userlist; u; u = u->next)
    for (q = get_user(&USERENTRY_ACCOUNT, u); q; q = q->next)
      if (!rfc_casecmp(q->extra, acct))
        return u;
  return nullptr;
}

struct userrec *get_user_by_handle(struct userrec *bu, char *handle)
{
  struct userrec *u, *ret;

  if (!handle)
    return nullptr;
  rmspace(handle);
  if (!handle[0] || (handle[0] == '*'))
    return nullptr;
  if (bu == userlist) {
    /* L1: last-accessed record */
    if (lastuser && !strcasecmp(lastuser->handle, handle)) {
      cache_hit++;
      return lastuser;
    }
    /* L2: active DCC connections */
    ret = check_dcclist_hand(handle);
    if (ret) {
      cache_hit++;
      return ret;
    }
    cache_miss++;
    /* L3: dictionary index — O(log n) instead of O(n) linear scan */
    if (!user_handle_dict && userlist)
      user_dict_rebuild();
    if (user_handle_dict) {
      ret = op_htab_get(user_handle_dict,handle);
      if (ret)
        lastuser = ret;
      return ret;
    }
  }
  for (u = bu; u; u = u->next)
    if (!strcasecmp(u->handle, handle)) {
      if (bu == userlist)
        lastuser = u;
      return u;
    }
  return nullptr;
}

struct userrec *get_user_from_member(memberlist *m)
{
  struct userrec *ret = nullptr;

  /* Check positive/negative cache first */
  if (m->user || m->tried_getuser) {
    return m->user;
  }

  /* Check if there is a user with a matching account if one is provided */
  if (m->account[0] != '*') {
    ret = get_user_by_account(m->account);
    if (ret) {
      goto getuser_done;
    }
  }

  /* Check if there is a user with a matching hostmask if one is provided */
  if ((m->userhost[0] != '\0') && (m->nick[0] != '\0')) {
    op_strbuf_t s = {};
    op_strbuf_init(&s);
    op_strbuf_appendf(&s, "%s!%s", m->nick, m->userhost);
    ret = get_user_by_host(op_strbuf_str(&s));
    op_strbuf_free(&s);
    if (ret) {
      goto getuser_done;
    }
  }

getuser_done:
  m->user = ret;
  m->tried_getuser = 1;
  return ret;
}

/* Wrapper function to find an Eggdrop user record based on either a provided
 * channel memberlist record, host, or account. This function will first check
 * a provided memberlist and return the result. If no user record is found (or
 * the memberlist itself was nullptr), this function will try again based on a
 * provided account, and then again on a provided host.
 *
 * When calling this function it is best to provide all available independent
 * variables- ie, if you provide 'm' for the memberlist, don't provide
 * 'm->account' for the account, use the independent source variable 'account'
 * if available. This allows redundant checking in case of unexpected NULLs
 */
struct userrec *lookup_user_record(memberlist *m, const char *account,
                                   const char *host)
{
  struct userrec *u = nullptr;

/* First check for a user record tied to a memberlist */
  if (m) {
    u = get_user_from_member(m);
    if (u) {
      return u;
    }
  }
/* Next check for a user record tied to an account */
  if (account && account[0]) {
    u = get_user_by_account(account);
    if (u) {
      return u;
    }
  }
/* Last check for a user record tied to a hostmask */
  if (host && host[0]) {
    u = get_user_by_host(host);
    return u;
  }
  return nullptr;
}

/* Fix capitalization, etc
 */
void correct_handle(char *handle)
{
  struct userrec *u;

  u = get_user_by_handle(userlist, handle);
  if (u == nullptr || handle == u->handle)
    return;
  strlcpy(handle, u->handle, sizeof(handle));
}

/* This will be useful in a lot of places, much more code re-use so we
 * endup with a smaller executable bot. <cybah>
 */
void clear_masks(maskrec *m)
{
  maskrec *temp = nullptr;

  for (; m; m = temp) {
    temp = m->next;
    if (m->mask)
      op_free(m->mask);
    if (m->user)
      op_free(m->user);
    if (m->desc)
      op_free(m->desc);
    free_maskrec(m);
  }
}

void clear_userlist(struct userrec *bu)
{
  struct userrec *u, *v;

  for (u = bu; u; u = v) {
    v = u->next;
    freeuser(u);
  }
  if (userlist == bu) {
    struct chanset_t *cst;

    for (int i = 0; i < dcc_total; i++)
      dcc[i].user = nullptr;
    clear_chanlist();
    lastuser = nullptr;
    if (user_handle_dict) {
      op_htab_destroy(user_handle_dict, nullptr, nullptr);
      user_handle_dict = nullptr;
    }
    if (user_account_dict) {
      op_htab_destroy(user_account_dict, nullptr, nullptr);
      user_account_dict = nullptr;
    }

    while (global_ign)
      delignore(global_ign->igmask);

    clear_masks(global_bans);
    clear_masks(global_exempts);
    clear_masks(global_invites);
    global_exempts = global_invites = global_bans = nullptr;

    for (cst = chanset; cst; cst = cst->next) {
      clear_masks(cst->bans);
      clear_masks(cst->exempts);
      clear_masks(cst->invites);

      cst->bans = cst->exempts = cst->invites = nullptr;
    }
  }
  /* Remember to set your userlist to nullptr after calling this */
}

/* Find CLOSEST host match
 * (if "*!*@*" and "*!*@*clemson.edu" both match, use the latter!)
 */
struct userrec *get_user_by_host(const char *host)
{
  struct userrec *u, *ret = nullptr;
  struct list_type *q;
  int cnt, i;
  char host2[UHOSTLEN];

  if (host == nullptr)
    return nullptr;
  strlcpy(host2, host, sizeof host2);
  rmspace(host2);
  if (!host2[0])
    return nullptr;
  cnt = 0;
  cache_miss++;
  for (u = userlist; u; u = u->next) {
    q = get_user(&USERENTRY_HOSTS, u);
    for (; q; q = q->next) {
      i = match_useraddr(q->extra, host2);
      if (i > cnt) {
        ret = u;
        cnt = i;
      }
    }
  }
  if (ret != nullptr) {
    lastuser = ret;
  }
  return ret;
}

/* Description: checks the password given against the user's password.
 * Check against the password "-" to find out if a user has no password set.
 *
 * If encryption2 module is loaded and PASS2 is set PASS2 is compared; else
 * PASS.
 *
 * Returns: 1 if the password matches for that user; 0 otherwise. Or if we are
 * checking against the password "-": 1 if the user has no password set; 0
 * otherwise.
 */
int u_pass_match(struct userrec *u, char *pass)
{
  char *cmp = 0, *new, new2[32];
  int pass2 = 1;
  struct user_entry *e;

  if (!u || !pass)
    return 0;
  if (encrypt_pass2)
    cmp = get_user(&USERENTRY_PASS2, u);
  if (!cmp) { /* implicit && encrypt_pass, due to eggdrop has at least one
                 encryption module loaded */
    cmp = get_user(&USERENTRY_PASS, u);
    pass2 = 0;
  }
  if (pass[0] == '-') {
    if (!cmp)
      return 1;
    return 0;
  }
  /* If password is not set in userrecord, or password is not sent */
  if (!cmp || !pass[0])
    return 0;
  if (u->flags & USER_BOT) {
    if (!crypto_verify(cmp, pass)) /* verify successful */
      return 1;
    return 0;
  }
  if (strlen(pass) > PASSWORDMAX)
    pass[PASSWORDMAX] = 0;
  if (pass2) {
    new = verify_pass2(pass, cmp);
    if (new) { /* verify successful */
      if (new != cmp) /* reenrypted with new parameters,
                         no need to strcmp() */
        set_user(&USERENTRY_PASS2, u, new);
      return 1;
    }
  }
  else if (encrypt_pass) {
    encrypt_pass(pass, new2);
    if (!crypto_verify(cmp, new2)) { /* verify successful */
      if (encrypt_pass2) {
        new = encrypt_pass2(pass);
        if (new) {
          set_user(&USERENTRY_PASS2, u, new);
          if (remove_pass) { /* implicit e->u.extra != nullptr */
            e = find_user_entry(&USERENTRY_PASS, u);
            explicit_bzero(e->u.extra, strlen(e->u.extra));
            op_free(e->u.extra);
            e->u.extra = nullptr;
            egg_list_delete((struct list_type **) &(u->entries), (struct list_type *) e);
            op_free(e);
          }
        }
      }
      return 1;
    }
  }
  return 0;
}

int write_user(struct userrec *u, FILE *f, int idx)
{
  char s[181];
  struct chanuserrec *ch;
  struct chanset_t *cst;
  struct user_entry *ue;
  struct flag_record fr = { FR_GLOBAL };

  fr.global = u->flags;

  fr.udef_global = u->flags_udef;
  build_flags(s, &fr, nullptr);
  if (fprintf(f, "%-10s - %-24s\n", u->handle, s) == EOF)
    return 0;
  for (ch = u->chanrec; ch; ch = ch->next) {
    cst = findchan_by_dname(ch->channel);
    if (cst && ((idx < 0) || channel_shared(cst))) {
      if (idx >= 0) {
        fr.match = (FR_CHAN | FR_BOT);
        get_user_flagrec(dcc[idx].user, &fr, ch->channel);
      } else
        fr.chan = BOT_AGGRESSIVE;
      if ((fr.chan & BOT_AGGRESSIVE) || (fr.bot & BOT_GLOBAL)) {
        fr.match = FR_CHAN;
        fr.chan = ch->flags;
        fr.udef_chan = ch->flags_udef;
        build_flags(s, &fr, nullptr);
        if (fprintf(f, "! %-20s %" PRId64 " %-10s %s\n", ch->channel, (int64_t) ch->laston, s,
            (((idx < 0) || share_greet) && ch->info) ? ch->info : "") == EOF)
          return 0;
      }
    }
  }
  for (ue = u->entries; ue; ue = ue->next) {
    if (ue->name) {
      struct list_type *lt;

      for (lt = ue->u.list; lt; lt = lt->next)
        if (fprintf(f, "--%s %s\n", ue->name, lt->extra) == EOF)
          return 0;
    } else if (!ue->type->write_userfile(f, u, ue))
      return 0;
  }
  return 1;
}

int write_ignores(FILE *f, int idx)
{
  struct igrec *i;
  char *mask;
  long expire, added;

  if (global_ign)
    if (fprintf(f, IGNORE_NAME " - -\n") == EOF)        /* Daemus */
      return 0;
  for (i = global_ign; i; i = i->next) {
    mask = str_escape(i->igmask, ':', '\\');
    expire = i->expire;
    added = i->added;
    if (!mask ||
        fprintf(f, "- %s:%s%lu:%s:%lu:%s\n", mask,
                (i->flags & IGREC_PERM) ? "+" : "", expire,
                i->user ? i->user : botnetnick, added,
                i->msg ? i->msg : "") == EOF) {
      if (mask)
        op_free(mask);
      return 0;
    }
    op_free(mask);
  }
  return 1;
}

static int sort_compare(struct userrec *a, struct userrec *b)
{
  /* Order by flags, then alphabetically
   * first bots: +h / +a / +l / other bots
   * then users: +n / +m / +o / other users
   * return true if (a > b)
   */
  if (a->flags & b->flags & USER_BOT) {
    if (~bot_flags(a) & bot_flags(b) & BOT_HUB)
      return 1;
    if (bot_flags(a) & ~bot_flags(b) & BOT_HUB)
      return 0;
    if (~bot_flags(a) & bot_flags(b) & BOT_ALT)
      return 1;
    if (bot_flags(a) & ~bot_flags(b) & BOT_ALT)
      return 0;
    if (~bot_flags(a) & bot_flags(b) & BOT_LEAF)
      return 1;
    if (bot_flags(a) & ~bot_flags(b) & BOT_LEAF)
      return 0;
  } else {
    if (~a->flags & b->flags & USER_BOT)
      return 1;
    if (a->flags & ~b->flags & USER_BOT)
      return 0;
    if (~a->flags & b->flags & USER_OWNER)
      return 1;
    if (a->flags & ~b->flags & USER_OWNER)
      return 0;
    if (~a->flags & b->flags & USER_MASTER)
      return 1;
    if (a->flags & ~b->flags & USER_MASTER)
      return 0;
    if (~a->flags & b->flags & USER_OP)
      return 1;
    if (a->flags & ~b->flags & USER_OP)
      return 0;
    if (~a->flags & b->flags & USER_HALFOP)
      return 1;
    if (a->flags & ~b->flags & USER_HALFOP)
      return 0;
  }
  return (strcasecmp(a->handle, b->handle) > 0);
}

static void sort_userlist(void)
{
  int again;
  struct userrec *last, *p, *c, *n;

  again = 1;
  last = nullptr;
  while ((userlist != last) && (again)) {
    p = nullptr;
    c = userlist;
    n = c->next;
    again = 0;
    while (n != last) {
      if (sort_compare(c, n)) {
        again = 1;
        c->next = n->next;
        n->next = c;
        if (p == nullptr)
          userlist = n;
        else
          p->next = n;
      }
      p = c;
      c = n;
      n = n->next;
    }
    last = c;
  }
}

/* Rewrite the entire user file. Call USERFILE hook as well, probably
 * causing the channel file to be rewritten as well.
 */
void write_userfile(int idx)
{
  char s[26];
  struct userrec *u;
  int ok;

  if (userlist == nullptr)
    return;

  char *buf = nullptr;
  size_t buflen = 0;
  FILE *f = open_memstream(&buf, &buflen);
  if (f == nullptr) {
    putlog(LOG_MISC, "*", "%s", USERF_ERRWRITE);
    return;
  }
  if (!quiet_save)
    putlog(LOG_MISC, "*", "%s", USERF_WRITING);

  sort_userlist();
  ctime_r(&now, s);
  fprintf(f, "#4v: %s -- %s -- written %s", ver, botnetnick, s);
  ok = 1;
  for (u = userlist; u && ok; u = u->next)
    if (strcasecmp(u->handle, EGG_BG_HANDLE) && !write_user(u, f, idx))
      ok = 0;
  if (!ok || !write_ignores(f, -1) || fflush(f)) {
    putlog(LOG_MISC, "*", "%s", USERF_ERRWRITE);
    fclose(f);
    free(buf);
    return;
  }
  fclose(f);

  call_hook(HOOK_USERFILE);

  if (egg_store && egg_store != &egg_store_flat)
    egg_store->save_users(idx);

  /* Hand the serialized buffer to a worker thread for disk I/O.
   * async_writebuf takes ownership of buf. */
  async_writebuf(userfile, buf, buflen, userfile_perm);
}

void backup_userfile(void)
{
  if (quiet_save < 2)
    putlog(LOG_MISC, "*", "%s", USERF_BACKUP);
  op_strbuf_t s = {};
  op_strbuf_init(&s);
  op_strbuf_appendf(&s, "%s~bak", userfile);
  async_copyfile(userfile, op_strbuf_str(&s));
  op_strbuf_free(&s);
}

int change_handle(struct userrec *u, char *newh)
{
  char s[HANDLEN + 1];

  if (!u)
    return 0;
  /* Don't allow the -t handle to be changed */
  if (!strcasecmp(u->handle, EGG_BG_HANDLE))
    return 0;
  /* Nothing that will confuse the userfile */
  if (!newh[1] && strchr(BADHANDCHARS, newh[0]))
    return 0;
  check_tcl_nkch(u->handle, newh);
  /* Yes, even send bot nick changes now: */
  if (!noshare && !(u->flags & USER_UNSHARED))
    shareout(nullptr, "h %s %s\n", u->handle, newh);
  strlcpy(s, u->handle, sizeof s);
  strlcpy(u->handle, newh, sizeof u->handle);
  u->dirty = 1;  /* Mark as dirty when handle changes */
  if (user_handle_dict) {
    op_htab_del(user_handle_dict,s);
    op_htab_set(user_handle_dict, u->handle, u, nullptr);
  }
  for (int i = 0; i < dcc_total; i++)
    if ((dcc[i].type == &DCC_CHAT || dcc[i].type == &DCC_CHAT_PASS) &&
        !strcasecmp(dcc[i].nick, s)) {
      strlcpy(dcc[i].nick, newh, sizeof dcc[i].nick);
      if (dcc[i].type == &DCC_CHAT && dcc[i].u.chat->channel >= 0) {
        chanout_but(-1, dcc[i].u.chat->channel,
                    "*** Handle change: %s -> %s\n", s, newh);
        if (dcc[i].u.chat->channel < GLOBAL_CHANS)
          botnet_send_nkch(i, s);
      }
    }
  return 1;
}

extern int noxtra;

struct userrec *adduser(struct userrec *bu, char *handle, const char *host,
                        char *pass, int flags)
{
  struct userrec *u, *x;
  struct xtra_key *xk;
  int oldshare = noshare;
  char hostcopy[UHOSTLEN];

  noshare = 1;
  u = alloc_userrec();

  /* u->next=bu; bu=u; */
  strlcpy(u->handle, handle, sizeof u->handle);
  u->next = nullptr;
  u->chanrec = nullptr;
  u->entries = nullptr;
  u->dirty = 1;  /* New user is dirty */
  if (flags != USER_DEFAULT) {  /* drummer */
    u->flags = flags;
    u->flags_udef = 0;
  } else {
    u->flags = default_flags;
    u->flags_udef = default_uflags;
  }
  set_user(&USERENTRY_PASS, u, pass);
  if (!noxtra) {
    xk = alloc_xtra_key();
    xk->key = op_malloc(8);
    strlcpy(xk->key, "created", sizeof(xk->key));
    {
      op_strbuf_t ts = {};
      op_strbuf_init(&ts);
      op_strbuf_appendf(&ts, "%" PRId64, (int64_t) now);
      xk->data = op_strdup(op_strbuf_str(&ts));
      op_strbuf_free(&ts);
    }
    set_user(&USERENTRY_XTRA, u, xk);
  }
  /* Strip out commas -- they're illegal */
  if (host && host[0]) {
    char *p;

    strlcpy(hostcopy, host, sizeof hostcopy);
    p = strchr(hostcopy, ',');
    while (p != nullptr) {
      *p = '?';
      p = strchr(hostcopy, ',');
    }
    set_user(&USERENTRY_HOSTS, u, hostcopy);
  } else
    set_user(&USERENTRY_HOSTS, u, "none");
  if (bu == userlist)
    clear_chanlist();
  noshare = oldshare;
  if ((!noshare) && (handle[0] != '*') && (!(flags & USER_UNSHARED)) &&
      (bu == userlist)) {
    struct flag_record fr = { FR_GLOBAL };
    char flags_str[100];

    fr.global = u->flags;

    fr.udef_global = u->flags_udef;
    build_flags(flags_str, &fr, 0);
    shareout(nullptr, "n %s %s %s %s\n", handle, host && host[0] ? hostcopy : "none",
             pass, flags_str);
  }
  if (bu == nullptr)
    bu = u;
  else {
    if ((bu == userlist) && (lastuser != nullptr))
      x = lastuser;
    else
      x = bu;
    while (x->next != nullptr)
      x = x->next;
    x->next = u;
    if (bu == userlist) {
      lastuser = u;
      if (user_handle_dict)
        op_htab_set(user_handle_dict, u->handle, u, nullptr);
    }
  }
  return bu;
}

void freeuser(struct userrec *u)
{
  struct user_entry *ue, *ut;
  struct chanuserrec *ch, *z;

  if (u == nullptr)
    return;

  ch = u->chanrec;
  while (ch) {
    z = ch;
    ch = ch->next;
    if (z->info != nullptr)
      op_free(z->info);
    free_chanuserrec(z);
  }
  u->chanrec = nullptr;
  for (ue = u->entries; ue; ue = ut) {
    ut = ue->next;
    if (ue->name) {
      struct list_type *lt, *ltt;

      for (lt = ue->u.list; lt; lt = ltt) {
        ltt = lt->next;
        op_free(lt->extra);
        free_list_type(lt);
      }
      op_free(ue->name);
      free_user_entry(ue);
    } else
      ue->type->kill(ue);
  }
  free_userrec(u);
}

int deluser(char *handle)
{
  struct userrec *u = userlist, *prev = nullptr;
  int fnd = 0;

  while ((u != nullptr) && (!fnd)) {
    if (!strcasecmp(u->handle, handle))
      fnd = 1;
    else {
      prev = u;
      u = u->next;
    }
  }
  if (!fnd)
    return 0;
  if (prev == nullptr)
    userlist = u->next;
  else
    prev->next = u->next;
  if (!noshare && (handle[0] != '*') && !(u->flags & USER_UNSHARED))
    shareout(nullptr, "k %s\n", handle);
  for (fnd = 0; fnd < dcc_total; fnd++)
    if (dcc[fnd].user == u)
      dcc[fnd].user = 0;        /* Clear any dcc users for this entry,
                                 * null is safe-ish */
  if (user_handle_dict)
    op_htab_del(user_handle_dict,handle);
  if (user_account_dict) {
    struct list_type *q;
    for (q = get_user(&USERENTRY_ACCOUNT, u); q; q = q->next)
      if (q->extra && strcmp(q->extra, "none"))
        op_htab_del(user_account_dict,q->extra);
  }
  clear_chanlist();
  freeuser(u);
  lastuser = nullptr;
  return 1;
}

static int del_host_or_account(char *handle, char *host, int type)
{
  struct userrec *u;
  struct list_type *q, *qnext, *qprev;
  struct user_entry *e = nullptr;
  int i = 0;

  u = get_user_by_handle(userlist, handle);
  if (!u)
    return 0;
  if (type) {
    q = get_user(&USERENTRY_ACCOUNT, u);
  } else {
    q = get_user(&USERENTRY_HOSTS, u);
  }
  qprev = q;
  if (q) {
    if (!rfc_casecmp(q->extra, host)) {
      if (type) {
        e = find_user_entry(&USERENTRY_ACCOUNT, u);
      } else {
        e = find_user_entry(&USERENTRY_HOSTS, u);
      }
      e->u.extra = q->next;
      op_free(q->extra);
      op_free(q);
      i++;
      qprev = nullptr;
      q = e->u.extra;
    } else
      q = q->next;
    while (q) {
      qnext = q->next;
      if (!rfc_casecmp(q->extra, host)) {
        if (qprev)
          qprev->next = q->next;
        else if (e) {
          e->u.extra = q->next;
          qprev = nullptr;
        }
        op_free(q->extra);
        op_free(q);
        i++;
        /* Mark user as dirty when entries are deleted */
        u->dirty = 1;
      } else
        qprev = q;
      q = qnext;
    }
  }
  if (!qprev) {
    if (type) {
      set_user(&USERENTRY_ACCOUNT, u, "none");
    } else {
      set_user(&USERENTRY_HOSTS, u, "none");
    }
  }
  if (!noshare && i && !(u->flags & USER_UNSHARED))
    shareout(nullptr, "-%s %s %s\n", type ? "a" : "h", handle, host);
  /* For accounts: direct list_type manipulation above bypasses account_set,
   * so invalidate the dict here. set_user("none") at line ~1028 also triggers
   * account_set, but that's an additional redundant invalidate — harmless. */
  if (type && i)
    user_account_dict_invalidate();
  clear_chanlist();
  return i;
}

int delhost_by_handle(char *handle, char *host)
{
  return del_host_or_account(handle, host, 0);
}

int delaccount_by_handle(char *handle, char *acct)
{
  return del_host_or_account(handle, acct, 1);
}


static void add_host_or_account(char *handle, const char *arg, int type)
{
  struct userrec *u = get_user_by_handle(userlist, handle);

  if (type) {
    set_user(&USERENTRY_ACCOUNT, u, (void *) arg);
  } else {
    set_user(&USERENTRY_HOSTS, u, (void *) arg);
  }
  /* Note: set_user already marks u as dirty via userent.c */
  if ((!noshare) && !(u->flags & USER_UNSHARED)) {
    if (u->flags & USER_BOT) {
      shareout(nullptr, "+b%s %s %s\n", type ? "a" : "h", handle, arg);
    } else {
      shareout(nullptr, "+%s %s %s\n", type ? "a" : "h", handle, arg);
    }
  }
  clear_chanlist();
}

void addhost_by_handle(char *handle, const char *host)
{
  add_host_or_account(handle, host, 0);
}

void addaccount_by_handle(char *handle, char *acct)
{
  add_host_or_account(handle, acct, 1);
  /* account_set() (called by set_user inside add_host_or_account) already
   * invalidated user_account_dict; no further maintenance needed here. */
}

void touch_laston(struct userrec *u, const char *where, time_t timeval)
{
  if (!u)
    return;

  if (timeval > 1) {
    struct laston_info *li = get_user(&USERENTRY_LASTON, u);

    if (!li)
      li = alloc_laston_info();

    else if (li->lastonplace)
      op_free(li->lastonplace);
    li->laston = timeval;
    if (where) {
      li->lastonplace = op_strdup(where);
    } else
      li->lastonplace = nullptr;
    set_user(&USERENTRY_LASTON, u, li);
  } else if (timeval == 1)
    set_user(&USERENTRY_LASTON, u, 0);
}

/*  Go through all channel records and try to find a matching
 *  nick. Will return the user's user record if that is known
 *  to the bot.  (Fabian)
 *
 *  Warning: This is unreliable by concept!
 */
struct userrec *get_user_by_nick(char *nick)
{
  struct chanset_t *chan;
  memberlist *m;

  for (chan = chanset; chan; chan = chan->next) {
    for (m = chan->channel.member; m && m->nick[0]; m = m->next) {
      if (!rfc_casecmp(nick, m->nick)) {
        op_strbuf_t word = {};
        op_strbuf_init(&word);
        op_strbuf_appendf(&word, "%s!%s", m->nick, m->userhost);
        struct userrec *r = get_user_by_host(op_strbuf_str(&word));
        op_strbuf_free(&word);
        return r;
      }
    }
  }
  /* Sorry, no matches */
  return nullptr;
}

void user_del_chan(char *dname)
{
  struct chanuserrec *ch, *och;
  struct userrec *u;

  for (u = userlist; u; u = u->next) {
    ch = u->chanrec;
    och = nullptr;
    while (ch) {
      if (!rfc_casecmp(dname, ch->channel)) {
        if (och)
          och->next = ch->next;
        else
          u->chanrec = ch->next;

        if (ch->info)
          op_free(ch->info);
        free_chanuserrec(ch);
        break;
      }
      och = ch;
      ch = ch->next;
    }
  }
}

/* Check if the console flags specified in md are permissible according
 * to the given flagrec. If the FR_CHAN flag is not set in fr->match,
 * only global user flags will be considered.
 * Returns: md with all unallowed flags masked out.
 */
int check_conflags(struct flag_record *fr, int md)
{
  if (!glob_owner(*fr))
    md &= ~(LOG_RAW | LOG_SRVOUT | LOG_BOTNETIN | LOG_BOTNETOUT | LOG_BOTSHRIN | LOG_BOTSHROUT);
  if (!glob_master(*fr)) {
    md &= ~(LOG_FILES | LOG_LEV1 | LOG_LEV2 | LOG_LEV3 | LOG_LEV4 |
            LOG_LEV5 | LOG_LEV6 | LOG_LEV7 | LOG_LEV8 | LOG_DEBUG |
            LOG_WALL);
    if ((fr->match & FR_CHAN) && !chan_master(*fr))
      md &= ~(LOG_MISC | LOG_CMDS);
  }
  if (!glob_botmast(*fr))
    md &= ~(LOG_BOTS | LOG_BOTMSG);
  return md;
}

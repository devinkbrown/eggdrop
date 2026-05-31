/*
 * egg_store_lmdb.c — LMDB-backed storage backend.
 *
 * Provides crash-safe persistent storage using Howard Chu's LMDB
 * (Lightning Memory-Mapped Database).
 *
 * Architecture:
 *   The flat-file format remains the canonical serialization format.
 *   This backend stores the complete flat-file content as an LMDB blob,
 *   gaining atomic write semantics — if the bot crashes mid-save, the
 *   previous LMDB transaction is still intact and can recover the
 *   userfile on next startup.
 *
 *   Additionally, per-user and per-ignore records are written to named
 *   sub-databases for future incremental operations and direct lookups.
 *
 * Sub-databases within the single .mdb environment:
 *   "meta"     — key: string, value: string (version, blobs, etc.)
 *   "users"    — key: handle, value: flat-format text for that user
 *   "hosts"    — key: handle\0hostmask, value: (empty)
 *   "accounts" — key: handle\0account, value: (empty)
 *   "ignores"  — key: mask, value: packed ignore record
 *
 * Copyright (C) 2026 Eggheads Development Team
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "main.h"
#include "egg_store.h"
#include "users.h"
#include "tandem.h"
#include <lmdb.h>
#include <sys/stat.h>

extern struct userrec *userlist;
extern struct igrec *global_ign;
extern char userfile[], botnetnick[], ver[];
extern int noshare;
extern time_t now;

static MDB_env *env;
static MDB_dbi dbi_meta;
static MDB_dbi dbi_users;
static MDB_dbi dbi_hosts;
static MDB_dbi dbi_accounts;
static MDB_dbi dbi_ignores;

/* Flag to control whether we do a full resync on the first save after load */
static bool full_resync = true;

#define DEFAULT_MAPSIZE (64UL * 1024UL * 1024UL)

/* ======================================================================
 * Helpers
 * ====================================================================== */

static MDB_val mk_val(const char *s, size_t len)
{
  MDB_val v;
  v.mv_data = (void *) s;
  v.mv_size = len;
  return v;
}

static MDB_val mk_str(const char *s)
{
  return mk_val(s, strlen(s));
}

static MDB_val mk_key2(op_strbuf_t *sb, const char *a, const char *b)
{
  op_strbuf_init(sb);
  op_strbuf_append_cstr(sb, a);
  op_strbuf_appendc(sb, '\0');
  op_strbuf_append_cstr(sb, b);
  return mk_val(op_strbuf_str(sb), op_strbuf_len(sb));
}

/* ======================================================================
 * Backend implementation
 * ====================================================================== */

static int lmdb_open(const char *path)
{
  int rc = mdb_env_create(&env);
  if (rc) {
    putlog(LOG_MISC, "*", "LMDB: mdb_env_create failed: %s", mdb_strerror(rc));
    return -1;
  }

  mdb_env_set_maxdbs(env, 8);
  mdb_env_set_mapsize(env, DEFAULT_MAPSIZE);

  rc = mdb_env_open(env, path, MDB_NOSUBDIR | MDB_NOSYNC, 0644);
  if (rc) {
    putlog(LOG_MISC, "*", "LMDB: mdb_env_open(%s) failed: %s", path, mdb_strerror(rc));
    mdb_env_close(env);
    env = nullptr;
    return -1;
  }

  MDB_txn *txn;
  rc = mdb_txn_begin(env, nullptr, 0, &txn);
  if (rc) {
    putlog(LOG_MISC, "*", "LMDB: txn_begin failed: %s", mdb_strerror(rc));
    mdb_env_close(env);
    env = nullptr;
    return -1;
  }

  mdb_dbi_open(txn, "meta",     MDB_CREATE, &dbi_meta);
  mdb_dbi_open(txn, "users",    MDB_CREATE, &dbi_users);
  mdb_dbi_open(txn, "hosts",    MDB_CREATE, &dbi_hosts);
  mdb_dbi_open(txn, "accounts", MDB_CREATE, &dbi_accounts);
  mdb_dbi_open(txn, "ignores",  MDB_CREATE, &dbi_ignores);

  mdb_txn_commit(txn);
  putlog(LOG_MISC, "*", "LMDB: opened database at %s", path);
  return 0;
}

static void lmdb_close(void)
{
  if (env) {
    mdb_env_sync(env, 1);
    mdb_env_close(env);
    env = nullptr;
    putlog(LOG_MISC, "*", "LMDB: database closed.");
  }
}

/*
 * Delete all host or account entries for a specific handle.
 * Used to clean up old entries for dirty users before re-inserting current ones.
 */
static void delete_user_entries(MDB_txn *txn, MDB_dbi dbi, const char *handle)
{
  MDB_cursor *cursor;
  MDB_val key, val;
  op_strbuf_t prefix = {};
  op_strbuf_init(&prefix);
  size_t handle_len = strlen(handle);
  int rc;

  rc = mdb_cursor_open(txn, dbi, &cursor);
  if (rc)
    return;

  /* Create search prefix: "handle\0" */
  op_strbuf_init(&prefix);
  op_strbuf_append_cstr(&prefix, handle);
  op_strbuf_appendc(&prefix, '\0');

  key = mk_val(op_strbuf_str(&prefix), op_strbuf_len(&prefix));
  rc = mdb_cursor_get(cursor, &key, &val, MDB_SET_RANGE);

  while (rc == 0) {
    /* Check if this key still starts with our handle prefix */
    if (key.mv_size < handle_len + 1 ||
        memcmp(key.mv_data, handle, handle_len) != 0 ||
        ((char*)key.mv_data)[handle_len] != '\0') {
      /* No more entries for this handle */
      break;
    }

    /* Delete this entry and move to next */
    mdb_cursor_del(cursor, 0);
    rc = mdb_cursor_get(cursor, &key, &val, MDB_NEXT);
  }

  mdb_cursor_close(cursor);
  op_strbuf_free(&prefix);
}

/*
 * lmdb_save_users — persist the in-memory state to LMDB.
 *
 * Called after write_userfile() has written the flat file.  We:
 *  1. Slurp the just-written flat userfile into memory.
 *  2. Store the entire blob in dbi_meta under "userfile_blob".
 *  3. For Layer 2: if full_resync or all users dirty, drop and rebuild.
 *     Otherwise, only update records for dirty users.
 */
static void lmdb_save_users(int idx, const char *flatbuf, size_t flatlen)
{
  MDB_txn *txn;
  int rc;

  if (!env) {
    putlog(LOG_MISC, "*", "LMDB: cannot save — database not open.");
    return;
  }

  rc = mdb_txn_begin(env, nullptr, 0, &txn);
  if (rc) {
    putlog(LOG_MISC, "*", "LMDB: save txn_begin failed: %s", mdb_strerror(rc));
    return;
  }

  /* Layer 1: Store the in-memory flat-file buffer as a crash-recovery blob.
   * Using flatbuf directly avoids reading the file that async_writebuf has
   * not yet flushed to disk. */
  if (flatbuf && flatlen > 0) {
    MDB_val k = mk_str("userfile_blob");
    MDB_val v = mk_val(flatbuf, flatlen);
    mdb_put(txn, dbi_meta, &k, &v, 0);
  }

  /* Store metadata. */
  {
    MDB_val k, v;

    k = mk_str("version");
    v = mk_str(ver);
    mdb_put(txn, dbi_meta, &k, &v, 0);

    k = mk_str("botnetnick");
    v = mk_str(botnetnick);
    mdb_put(txn, dbi_meta, &k, &v, 0);

    op_strbuf_t ts = {};
    op_strbuf_init(&ts);
    op_strbuf_appendf(&ts, "%" PRId64, (int64_t) now);
    k = mk_str("timestamp");
    v = mk_val(op_strbuf_str(&ts), op_strbuf_len(&ts));
    mdb_put(txn, dbi_meta, &k, &v, 0);
    op_strbuf_free(&ts);
  }

  /* Layer 2: Per-user structured data for incremental updates. */
  bool do_full_resync = full_resync;

  /* Check if all users are dirty (which means we should do a full resync) */
  if (!do_full_resync) {
    bool all_dirty = true;
    for (struct userrec *u = userlist; u; u = u->next) {
      if (!u->dirty) {
        all_dirty = false;
        break;
      }
    }
    if (all_dirty)
      do_full_resync = true;
  }

  if (do_full_resync) {
    /* Full resync: drop all and rebuild */
    mdb_drop(txn, dbi_users, 0);
    mdb_drop(txn, dbi_hosts, 0);
    mdb_drop(txn, dbi_accounts, 0);
    mdb_drop(txn, dbi_ignores, 0);

    for (struct userrec *u = userlist; u; u = u->next) {
      struct flag_record fr = { FR_GLOBAL };
      char flags[128];

      fr.global = u->flags;
      fr.udef_global = u->flags_udef;
      build_flags(flags, &fr, nullptr);

      /* User record: flags + channel count as a compact summary. */
      op_strbuf_t sb = {};
      op_strbuf_init(&sb);
      op_strbuf_append_cstr(&sb, flags);

      int nchan = 0;
      for (struct chanuserrec *ch = u->chanrec; ch; ch = ch->next)
        nchan++;
      if (nchan)
        op_strbuf_appendf(&sb, " chans=%d", nchan);

      MDB_val key = mk_str(u->handle);
      MDB_val val = mk_val(op_strbuf_str(&sb), op_strbuf_len(&sb));
      mdb_put(txn, dbi_users, &key, &val, 0);
      op_strbuf_free(&sb);

      /* Host masks. */
      {
        op_vec_t *hv = (op_vec_t *)get_user(&USERENTRY_HOSTS, u);
        if (hv)
          for (size_t _i = 0; _i < hv->size; _i++) {
            op_strbuf_t kb = {};
            key = mk_key2(&kb, u->handle, (const char *)op_vec_get(hv, _i));
            val = mk_val("", 0);
            mdb_put(txn, dbi_hosts, &key, &val, 0);
            op_strbuf_free(&kb);
          }
      }

      /* Accounts. */
      {
        op_vec_t *av = (op_vec_t *)get_user(&USERENTRY_ACCOUNT, u);
        if (av)
          for (size_t _i = 0; _i < av->size; _i++) {
            op_strbuf_t kb = {};
            key = mk_key2(&kb, u->handle, (const char *)op_vec_get(av, _i));
            val = mk_val("", 0);
            mdb_put(txn, dbi_accounts, &key, &val, 0);
            op_strbuf_free(&kb);
          }
      }
    }

    /* Always rebuild ignores completely (they're small and change rarely) */
    for (struct igrec *ig = global_ign; ig; ig = ig->next) {
      op_strbuf_t sb = {};
      op_strbuf_init(&sb);
      op_strbuf_appendf(&sb, "%" PRId64 " %" PRId64 " %d %s %s",
                       (int64_t) ig->expire, (int64_t) ig->added,
                       ig->flags, ig->user ? ig->user : "",
                       ig->msg ? ig->msg : "");
      MDB_val key = mk_str(ig->igmask);
      MDB_val val = mk_val(op_strbuf_str(&sb), op_strbuf_len(&sb));
      mdb_put(txn, dbi_ignores, &key, &val, 0);
      op_strbuf_free(&sb);
    }

    full_resync = false;  /* Clear flag after full resync */
  } else {
    /* Incremental update: only update dirty users */
    for (struct userrec *u = userlist; u; u = u->next) {
      if (!u->dirty)
        continue;

      struct flag_record fr = { FR_GLOBAL };
      char flags[128];

      fr.global = u->flags;
      fr.udef_global = u->flags_udef;
      build_flags(flags, &fr, nullptr);

      /* Update user record */
      op_strbuf_t sb = {};
      op_strbuf_init(&sb);
      op_strbuf_append_cstr(&sb, flags);

      int nchan = 0;
      for (struct chanuserrec *ch = u->chanrec; ch; ch = ch->next)
        nchan++;
      if (nchan)
        op_strbuf_appendf(&sb, " chans=%d", nchan);

      MDB_val key = mk_str(u->handle);
      MDB_val val = mk_val(op_strbuf_str(&sb), op_strbuf_len(&sb));
      mdb_put(txn, dbi_users, &key, &val, 0);
      op_strbuf_free(&sb);

      /* Delete all old host/account entries for this user */
      delete_user_entries(txn, dbi_hosts, u->handle);
      delete_user_entries(txn, dbi_accounts, u->handle);

      /* Re-insert current host masks */
      {
        op_vec_t *hv = (op_vec_t *)get_user(&USERENTRY_HOSTS, u);
        if (hv)
          for (size_t _i = 0; _i < hv->size; _i++) {
            op_strbuf_t kb = {};
            key = mk_key2(&kb, u->handle, (const char *)op_vec_get(hv, _i));
            val = mk_val("", 0);
            mdb_put(txn, dbi_hosts, &key, &val, 0);
            op_strbuf_free(&kb);
          }
      }

      /* Re-insert current accounts */
      {
        op_vec_t *av = (op_vec_t *)get_user(&USERENTRY_ACCOUNT, u);
        if (av)
          for (size_t _i = 0; _i < av->size; _i++) {
            op_strbuf_t kb = {};
            key = mk_key2(&kb, u->handle, (const char *)op_vec_get(av, _i));
            val = mk_val("", 0);
            mdb_put(txn, dbi_accounts, &key, &val, 0);
            op_strbuf_free(&kb);
          }
      }
    }

    /* Always rebuild ignores completely (they're small and change rarely) */
    mdb_drop(txn, dbi_ignores, 0);
    for (struct igrec *ig = global_ign; ig; ig = ig->next) {
      op_strbuf_t sb = {};
      op_strbuf_init(&sb);
      op_strbuf_appendf(&sb, "%" PRId64 " %" PRId64 " %d %s %s",
                       (int64_t) ig->expire, (int64_t) ig->added,
                       ig->flags, ig->user ? ig->user : "",
                       ig->msg ? ig->msg : "");
      MDB_val key = mk_str(ig->igmask);
      MDB_val val = mk_val(op_strbuf_str(&sb), op_strbuf_len(&sb));
      mdb_put(txn, dbi_ignores, &key, &val, 0);
      op_strbuf_free(&sb);
    }
  }

  rc = mdb_txn_commit(txn);
  if (rc) {
    putlog(LOG_MISC, "*", "LMDB: save commit failed: %s", mdb_strerror(rc));
  } else {
    /* Clear dirty flags for all users after successful save */
    for (struct userrec *u = userlist; u; u = u->next)
      u->dirty = 0;
    putlog(LOG_MISC, "*", "LMDB: userfile persisted.");
  }
}

/*
 * lmdb_load_users — load user records from LMDB.
 *
 * Strategy: check if the flat userfile exists and is readable.
 * If not (crash recovery scenario), extract the blob from LMDB,
 * write it to the flat userfile, then load normally.
 */
static int lmdb_load_users(const char *path, struct userrec **list)
{
  /* Try the flat file first — it's the fast path. */
  struct stat st;
  if (stat(userfile, &st) == 0 && st.st_size > 0) {
    full_resync = true;  /* Mark for full resync on next save */
    return egg_store_flat.load_users(userfile, list);
  }

  /* Flat file missing or empty — try to recover from LMDB. */
  if (!env) {
    putlog(LOG_MISC, "*", "LMDB: no database and no flat userfile — cannot load.");
    return 0;
  }

  MDB_txn *txn;
  int rc = mdb_txn_begin(env, nullptr, MDB_RDONLY, &txn);
  if (rc)
    return 0;

  MDB_val key = mk_str("userfile_blob");
  MDB_val val;
  rc = mdb_get(txn, dbi_meta, &key, &val);
  if (rc) {
    mdb_txn_abort(txn);
    putlog(LOG_MISC, "*", "LMDB: no userfile blob in database.");
    return 0;
  }

  /* Write the recovered blob to the flat userfile. */
  putlog(LOG_MISC, "*", "LMDB: recovering userfile from database (%zu bytes).",
         val.mv_size);
  FILE *f = fopen(userfile, "w");
  if (!f) {
    mdb_txn_abort(txn);
    putlog(LOG_MISC, "*", "LMDB: cannot write recovered userfile: %s",
           strerror(errno));
    return 0;
  }
  fwrite(val.mv_data, 1, val.mv_size, f);
  fclose(f);
  mdb_txn_abort(txn);

  putlog(LOG_MISC, "*", "LMDB: userfile recovered.  Loading...");
  full_resync = true;  /* Mark for full resync on next save */
  return egg_store_flat.load_users(userfile, list);
}

static int lmdb_load_channels(void)
{
  return egg_store_flat.load_channels();
}

static void lmdb_save_channels(void)
{
  egg_store_flat.save_channels();
}

static int lmdb_export_flat(const char *path)
{
  return egg_store_flat.export_flat(path);
}

static int lmdb_import_flat(const char *path)
{
  int ret = egg_store_flat.import_flat(path);
  if (ret && env)
    lmdb_save_users(-1, nullptr, 0);
  return ret;
}

egg_store_backend_t egg_store_lmdb = {
  .name           = "lmdb",
  .open           = lmdb_open,
  .close          = lmdb_close,
  .load_users     = lmdb_load_users,
  .save_users     = lmdb_save_users,
  .load_channels  = lmdb_load_channels,
  .save_channels  = lmdb_save_channels,
  .export_flat    = lmdb_export_flat,
  .import_flat    = lmdb_import_flat,
};

/* ======================================================================
 * Per-record public API
 *
 * These functions allow direct per-user reads and writes against the
 * "users" named sub-database.  They are only meaningful when the LMDB
 * backend is active (env != NULL).
 *
 * The serialized blob format is caller-defined (flat-file text for the
 * eggdrop use-case).  All three functions are no-ops when env is NULL,
 * so callers need not guard against the flat-file backend being active.
 * ====================================================================== */

/*
 * egg_lmdb_put_user — write (or overwrite) a single user record.
 *
 * handle     : NUL-terminated handle string (the LMDB key)
 * serialized : blob to store (need not be NUL-terminated)
 * len        : byte length of serialized
 *
 * Returns 0 on success, -1 on error.
 */
int egg_lmdb_put_user(const char *handle, const char *serialized, size_t len)
{
  if (!env || !handle || !serialized)
    return -1;

  MDB_txn *txn;
  int rc = mdb_txn_begin(env, nullptr, 0, &txn);
  if (rc) {
    putlog(LOG_MISC, "*", "LMDB put_user: txn_begin failed: %s", mdb_strerror(rc));
    return -1;
  }

  MDB_val key = mk_str(handle);
  MDB_val val = mk_val(serialized, len);
  rc = mdb_put(txn, dbi_users, &key, &val, 0);
  if (rc) {
    putlog(LOG_MISC, "*", "LMDB put_user(%s): mdb_put failed: %s", handle, mdb_strerror(rc));
    mdb_txn_abort(txn);
    return -1;
  }

  rc = mdb_txn_commit(txn);
  if (rc) {
    putlog(LOG_MISC, "*", "LMDB put_user(%s): commit failed: %s", handle, mdb_strerror(rc));
    return -1;
  }
  return 0;
}

/*
 * egg_lmdb_del_user — remove a user record (and its host/account entries).
 *
 * Returns 0 on success (including "not found"), -1 on hard error.
 */
int egg_lmdb_del_user(const char *handle)
{
  if (!env || !handle)
    return -1;

  MDB_txn *txn;
  int rc = mdb_txn_begin(env, nullptr, 0, &txn);
  if (rc) {
    putlog(LOG_MISC, "*", "LMDB del_user: txn_begin failed: %s", mdb_strerror(rc));
    return -1;
  }

  /* Remove the user record itself (ignore MDB_NOTFOUND). */
  MDB_val key = mk_str(handle);
  rc = mdb_del(txn, dbi_users, &key, nullptr);
  if (rc && rc != MDB_NOTFOUND) {
    putlog(LOG_MISC, "*", "LMDB del_user(%s): mdb_del failed: %s", handle, mdb_strerror(rc));
    mdb_txn_abort(txn);
    return -1;
  }

  /* Also clean up host and account index entries for this handle. */
  delete_user_entries(txn, dbi_hosts,    handle);
  delete_user_entries(txn, dbi_accounts, handle);

  rc = mdb_txn_commit(txn);
  if (rc) {
    putlog(LOG_MISC, "*", "LMDB del_user(%s): commit failed: %s", handle, mdb_strerror(rc));
    return -1;
  }
  return 0;
}

/*
 * egg_lmdb_get_user — read a single user record by handle.
 *
 * handle : NUL-terminated handle to look up
 * out    : set to an op_malloc'd copy of the blob on success (caller must op_free)
 * outlen : set to the byte length of *out
 *
 * Returns 0 on success, -1 on miss or error.
 * *out is always set to NULL on failure.
 */
int egg_lmdb_get_user(const char *handle, char **out, size_t *outlen)
{
  if (out)
    *out = nullptr;
  if (outlen)
    *outlen = 0;

  if (!env || !handle || !out || !outlen)
    return -1;

  MDB_txn *txn;
  int rc = mdb_txn_begin(env, nullptr, MDB_RDONLY, &txn);
  if (rc)
    return -1;

  MDB_val key = mk_str(handle);
  MDB_val val;
  rc = mdb_get(txn, dbi_users, &key, &val);
  if (rc) {
    mdb_txn_abort(txn);
    return -1;   /* MDB_NOTFOUND or error */
  }

  /* Copy out of LMDB's memory-mapped region before aborting the txn. */
  char *buf = op_malloc(val.mv_size + 1);
  memcpy(buf, val.mv_data, val.mv_size);
  buf[val.mv_size] = '\0';

  mdb_txn_abort(txn);

  *out    = buf;
  *outlen = val.mv_size;
  return 0;
}

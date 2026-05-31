/*
 * test_lmdb_recovery.c — LMDB crash-recovery test.
 *
 * Verifies that committed LMDB transactions survive a simulated crash
 * (child process calls _exit() without closing the environment).
 *
 * Test plan:
 *   1. mkdtemp() a temp directory for the LMDB data file.
 *   2. fork() a child that:
 *        a. Opens a new LMDB environment with two named sub-databases:
 *           "meta"  — stores a userfile blob under key "userfile_blob"
 *           "users" — stores per-user records keyed by handle
 *        b. Commits both writes in a single transaction.
 *        c. Calls _exit(0) without mdb_env_close() — simulating a crash
 *           after a successful commit.
 *   3. Parent waits for the child.
 *   4. Parent re-opens the same environment and verifies:
 *        - "userfile_blob" in "meta" contains the expected data.
 *        - Per-user records for two handles are present and correct.
 *   5. Removes the temp directory.
 *
 * Copyright (C) 2026 Eggheads Development Team
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "test_harness.h"

#include <lmdb.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

/* -------------------------------------------------------------------------
 * Helpers
 * ------------------------------------------------------------------------- */

static MDB_val str_val(const char *s)
{
  MDB_val v;
  v.mv_data = (void *)s;
  v.mv_size = strlen(s);
  return v;
}

/* Recursively remove a directory (two-level: remove files then dir). */
static void rmdir_recursive(const char *path)
{
  /* LMDB with MDB_NOSUBDIR creates two files: "path" and "path-lock". */
  char lock[512];
  snprintf(lock, sizeof(lock), "%s-lock", path);
  unlink(path);
  unlink(lock);
  /* The directory itself is the tmpdir. */
}

static void remove_tmpdir(const char *dir, const char *dbfile)
{
  rmdir_recursive(dbfile);
  rmdir(dir);
}

/* -------------------------------------------------------------------------
 * Core: open env + named dbis
 * ------------------------------------------------------------------------- */

#define MAPSIZE (4UL * 1024UL * 1024UL)

static int open_env(const char *dbpath, MDB_env **envp,
                    MDB_dbi *dbi_meta, MDB_dbi *dbi_users)
{
  int rc;

  rc = mdb_env_create(envp);
  if (rc) return rc;

  mdb_env_set_maxdbs(*envp, 4);
  mdb_env_set_mapsize(*envp, MAPSIZE);

  rc = mdb_env_open(*envp, dbpath, MDB_NOSUBDIR | MDB_NOSYNC, 0600);
  if (rc) {
    mdb_env_close(*envp);
    *envp = NULL;
    return rc;
  }

  MDB_txn *txn;
  rc = mdb_txn_begin(*envp, NULL, 0, &txn);
  if (rc) {
    mdb_env_close(*envp);
    *envp = NULL;
    return rc;
  }

  rc = mdb_dbi_open(txn, "meta",  MDB_CREATE, dbi_meta);
  if (rc) { mdb_txn_abort(txn); mdb_env_close(*envp); *envp = NULL; return rc; }

  rc = mdb_dbi_open(txn, "users", MDB_CREATE, dbi_users);
  if (rc) { mdb_txn_abort(txn); mdb_env_close(*envp); *envp = NULL; return rc; }

  rc = mdb_txn_commit(txn);
  if (rc) {
    mdb_env_close(*envp);
    *envp = NULL;
  }
  return rc;
}

/* -------------------------------------------------------------------------
 * Test data constants
 * ------------------------------------------------------------------------- */

#define BLOB_KEY    "userfile_blob"
#define BLOB_VALUE  "# eggdrop userfile\n----- egg1 -----\nflag o\n"
#define USER1_HANDLE "egg1"
#define USER1_VALUE  "flag o chans=1"
#define USER2_HANDLE "egg2"
#define USER2_VALUE  "flag v chans=0"

/* -------------------------------------------------------------------------
 * Child: write data, then _exit() without closing env (crash simulation).
 * ------------------------------------------------------------------------- */

static void child_write_and_crash(const char *dbpath)
{
  MDB_env *env = NULL;
  MDB_dbi dbi_meta, dbi_users;

  int rc = open_env(dbpath, &env, &dbi_meta, &dbi_users);
  if (rc) {
    fprintf(stderr, "child: open_env failed: %s\n", mdb_strerror(rc));
    _exit(1);
  }

  MDB_txn *txn;
  rc = mdb_txn_begin(env, NULL, 0, &txn);
  if (rc) {
    fprintf(stderr, "child: txn_begin failed: %s\n", mdb_strerror(rc));
    _exit(1);
  }

  /* Write userfile blob to meta dbi */
  MDB_val k = str_val(BLOB_KEY);
  MDB_val v = str_val(BLOB_VALUE);
  rc = mdb_put(txn, dbi_meta, &k, &v, 0);
  if (rc) {
    fprintf(stderr, "child: mdb_put blob failed: %s\n", mdb_strerror(rc));
    _exit(1);
  }

  /* Write per-user records */
  k = str_val(USER1_HANDLE);
  v = str_val(USER1_VALUE);
  rc = mdb_put(txn, dbi_users, &k, &v, 0);
  if (rc) {
    fprintf(stderr, "child: mdb_put user1 failed: %s\n", mdb_strerror(rc));
    _exit(1);
  }

  k = str_val(USER2_HANDLE);
  v = str_val(USER2_VALUE);
  rc = mdb_put(txn, dbi_users, &k, &v, 0);
  if (rc) {
    fprintf(stderr, "child: mdb_put user2 failed: %s\n", mdb_strerror(rc));
    _exit(1);
  }

  rc = mdb_txn_commit(txn);
  if (rc) {
    fprintf(stderr, "child: txn_commit failed: %s\n", mdb_strerror(rc));
    _exit(1);
  }

  /* Crash: _exit() without mdb_env_close().
   * LMDB's MVCC design guarantees the committed transaction is durable even
   * without an explicit close — the data pages are already written and the
   * meta-page has been updated atomically. */
  _exit(0);
}

/* -------------------------------------------------------------------------
 * Test: lmdb_crash_recovery
 * ------------------------------------------------------------------------- */

TEST(lmdb_crash_recovery) {
  char tmpdir[] = "/tmp/egg_lmdb_XXXXXX";
  char *dir = mkdtemp(tmpdir);
  ASSERT_NOT_NULL(dir);

  /* Build the path for the LMDB data file inside the temp directory. */
  char dbpath[512];
  snprintf(dbpath, sizeof(dbpath), "%s/data.mdb", dir);

  /* Fork child that writes and crashes */
  pid_t child = fork();
  if (child == 0) {
    child_write_and_crash(dbpath);
    /* unreachable */
    _exit(127);
  }

  ASSERT_TRUE(child > 0);  /* fork() succeeded */

  int status = 0;
  pid_t waited = waitpid(child, &status, 0);
  ASSERT_EQ(waited, child);
  ASSERT_TRUE(WIFEXITED(status));
  ASSERT_EQ(WEXITSTATUS(status), 0);

  /* Re-open the environment and verify data integrity */
  MDB_env *env = NULL;
  MDB_dbi dbi_meta, dbi_users;
  int rc = open_env(dbpath, &env, &dbi_meta, &dbi_users);
  if (rc) {
    printf("  open_env after crash failed: %s\n", mdb_strerror(rc));
    remove_tmpdir(dir, dbpath);
    ASSERT_EQ(rc, 0);  /* force fail */
  }

  MDB_txn *txn;
  rc = mdb_txn_begin(env, NULL, MDB_RDONLY, &txn);
  ASSERT_EQ(rc, 0);

  /* Verify userfile blob */
  MDB_val k = str_val(BLOB_KEY);
  MDB_val v;
  rc = mdb_get(txn, dbi_meta, &k, &v);
  ASSERT_EQ(rc, 0);
  ASSERT_EQ(v.mv_size, strlen(BLOB_VALUE));
  ASSERT_EQ(memcmp(v.mv_data, BLOB_VALUE, v.mv_size), 0);

  /* Verify user1 record */
  k = str_val(USER1_HANDLE);
  rc = mdb_get(txn, dbi_users, &k, &v);
  ASSERT_EQ(rc, 0);
  ASSERT_EQ(v.mv_size, strlen(USER1_VALUE));
  ASSERT_EQ(memcmp(v.mv_data, USER1_VALUE, v.mv_size), 0);

  /* Verify user2 record */
  k = str_val(USER2_HANDLE);
  rc = mdb_get(txn, dbi_users, &k, &v);
  ASSERT_EQ(rc, 0);
  ASSERT_EQ(v.mv_size, strlen(USER2_VALUE));
  ASSERT_EQ(memcmp(v.mv_data, USER2_VALUE, v.mv_size), 0);

  mdb_txn_abort(txn);
  mdb_env_close(env);
  remove_tmpdir(dir, dbpath);
}

/* -------------------------------------------------------------------------
 * Test: lmdb_per_record_ops
 *
 * Exercises the round-trip of writing and reading a single user record
 * without going through the full save_users path.  Validates the same
 * LMDB machinery egg_lmdb_put_user / egg_lmdb_get_user will use.
 * ------------------------------------------------------------------------- */

TEST(lmdb_per_record_ops) {
  char tmpdir[] = "/tmp/egg_lmdb_ops_XXXXXX";
  char *dir = mkdtemp(tmpdir);
  ASSERT_NOT_NULL(dir);

  char dbpath[512];
  snprintf(dbpath, sizeof(dbpath), "%s/data.mdb", dir);

  MDB_env *env = NULL;
  MDB_dbi dbi_meta, dbi_users;
  int rc = open_env(dbpath, &env, &dbi_meta, &dbi_users);
  ASSERT_EQ(rc, 0);

  const char *handle     = "testuser";
  const char *userdata   = "flag op chans=3";
  const char *updated    = "flag op+v chans=4";

  /* Write initial record */
  {
    MDB_txn *txn;
    rc = mdb_txn_begin(env, NULL, 0, &txn);
    ASSERT_EQ(rc, 0);
    MDB_val k = str_val(handle);
    MDB_val v = str_val(userdata);
    rc = mdb_put(txn, dbi_users, &k, &v, 0);
    ASSERT_EQ(rc, 0);
    rc = mdb_txn_commit(txn);
    ASSERT_EQ(rc, 0);
  }

  /* Read it back */
  {
    MDB_txn *txn;
    rc = mdb_txn_begin(env, NULL, MDB_RDONLY, &txn);
    ASSERT_EQ(rc, 0);
    MDB_val k = str_val(handle);
    MDB_val v;
    rc = mdb_get(txn, dbi_users, &k, &v);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(v.mv_size, strlen(userdata));
    ASSERT_EQ(memcmp(v.mv_data, userdata, v.mv_size), 0);
    mdb_txn_abort(txn);
  }

  /* Overwrite with updated record */
  {
    MDB_txn *txn;
    rc = mdb_txn_begin(env, NULL, 0, &txn);
    ASSERT_EQ(rc, 0);
    MDB_val k = str_val(handle);
    MDB_val v = str_val(updated);
    rc = mdb_put(txn, dbi_users, &k, &v, 0);
    ASSERT_EQ(rc, 0);
    rc = mdb_txn_commit(txn);
    ASSERT_EQ(rc, 0);
  }

  /* Verify updated value */
  {
    MDB_txn *txn;
    rc = mdb_txn_begin(env, NULL, MDB_RDONLY, &txn);
    ASSERT_EQ(rc, 0);
    MDB_val k = str_val(handle);
    MDB_val v;
    rc = mdb_get(txn, dbi_users, &k, &v);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ(v.mv_size, strlen(updated));
    ASSERT_EQ(memcmp(v.mv_data, updated, v.mv_size), 0);
    mdb_txn_abort(txn);
  }

  /* Delete the record */
  {
    MDB_txn *txn;
    rc = mdb_txn_begin(env, NULL, 0, &txn);
    ASSERT_EQ(rc, 0);
    MDB_val k = str_val(handle);
    rc = mdb_del(txn, dbi_users, &k, NULL);
    ASSERT_EQ(rc, 0);
    rc = mdb_txn_commit(txn);
    ASSERT_EQ(rc, 0);
  }

  /* Confirm it is gone */
  {
    MDB_txn *txn;
    rc = mdb_txn_begin(env, NULL, MDB_RDONLY, &txn);
    ASSERT_EQ(rc, 0);
    MDB_val k = str_val(handle);
    MDB_val v;
    rc = mdb_get(txn, dbi_users, &k, &v);
    ASSERT_EQ(rc, MDB_NOTFOUND);
    mdb_txn_abort(txn);
  }

  mdb_env_close(env);
  remove_tmpdir(dir, dbpath);
}

/* -------------------------------------------------------------------------
 * main
 * ------------------------------------------------------------------------- */

int main(void)
{
  TEST_MAIN_BEGIN;
  RUN_TEST(lmdb_crash_recovery);
  RUN_TEST(lmdb_per_record_ops);
  TEST_MAIN_END;
}

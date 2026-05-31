/*
 * test_lmdb_roundtrip.c — LMDB save/load roundtrip tests
 *
 * Tests the low-level LMDB operations used by egg_store_lmdb.c:
 *   - Single user write + read (via userfile_blob and per-user records)
 *   - Overwrite existing user record
 *   - Delete user record
 *   - Userfile blob roundtrip
 *
 * The test opens a temporary LMDB environment directly using the LMDB API
 * (the same API egg_store_lmdb.c uses internally) to avoid pulling in the
 * full eggdrop dependency graph (Tcl, putlog, userlist, etc.).
 */

#include "test_harness.h"
#include <lmdb.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

/* ======================================================================
 * Test helpers — open/close a temp LMDB env + named sub-databases
 * ====================================================================== */

#define TEST_MAPSIZE (1UL * 1024UL * 1024UL)  /* 1 MiB is plenty for tests */

static char tmp_path[256];
static MDB_env  *env;
static MDB_dbi   dbi_meta;
static MDB_dbi   dbi_users;

/* Open a fresh LMDB environment in a temp file. Returns 0 on success. */
static int open_test_env(void)
{
  snprintf(tmp_path, sizeof tmp_path, "/tmp/egg_lmdb_rt_XXXXXX");
  int fd = mkstemp(tmp_path);
  if (fd < 0)
    return -1;
  close(fd);
  /* LMDB with MDB_NOSUBDIR opens the named file directly. */

  int rc = mdb_env_create(&env);
  if (rc) return rc;
  mdb_env_set_maxdbs(env, 4);
  mdb_env_set_mapsize(env, TEST_MAPSIZE);
  rc = mdb_env_open(env, tmp_path, MDB_NOSUBDIR | MDB_NOSYNC, 0600);
  if (rc) { mdb_env_close(env); env = nullptr; return rc; }

  MDB_txn *txn;
  rc = mdb_txn_begin(env, nullptr, 0, &txn);
  if (rc) { mdb_env_close(env); env = nullptr; return rc; }
  mdb_dbi_open(txn, "meta",  MDB_CREATE, &dbi_meta);
  mdb_dbi_open(txn, "users", MDB_CREATE, &dbi_users);
  mdb_txn_commit(txn);
  return 0;
}

static void close_test_env(void)
{
  if (env) {
    mdb_env_close(env);
    env = nullptr;
  }
  /* Clean up the temp file and the LMDB lock file. */
  if (tmp_path[0]) {
    unlink(tmp_path);
    char lock[280];
    snprintf(lock, sizeof lock, "%s-lock", tmp_path);
    unlink(lock);
    tmp_path[0] = '\0';
  }
}

/* ======================================================================
 * Helpers that mirror what egg_store_lmdb.c actually stores
 * ====================================================================== */

static int put_user(MDB_txn *txn, const char *handle, const char *data)
{
  MDB_val k = { strlen(handle), (void *)handle };
  MDB_val v = { strlen(data),   (void *)data   };
  return mdb_put(txn, dbi_users, &k, &v, 0);
}

static int get_user(MDB_txn *txn, const char *handle, char *out, size_t outsz)
{
  MDB_val k = { strlen(handle), (void *)handle };
  MDB_val v;
  int rc = mdb_get(txn, dbi_users, &k, &v);
  if (rc) return rc;
  size_t copy = v.mv_size < outsz - 1 ? v.mv_size : outsz - 1;
  memcpy(out, v.mv_data, copy);
  out[copy] = '\0';
  return 0;
}

static int del_user(MDB_txn *txn, const char *handle)
{
  MDB_val k = { strlen(handle), (void *)handle };
  return mdb_del(txn, dbi_users, &k, nullptr);
}

static int put_blob(MDB_txn *txn, const char *key, const char *data, size_t len)
{
  MDB_val k = { strlen(key), (void *)key };
  MDB_val v = { len, (void *)data };
  return mdb_put(txn, dbi_meta, &k, &v, 0);
}

static int get_blob(MDB_txn *txn, const char *key, char *out, size_t outsz,
                    size_t *got)
{
  MDB_val k = { strlen(key), (void *)key };
  MDB_val v;
  int rc = mdb_get(txn, dbi_meta, &k, &v);
  if (rc) return rc;
  size_t copy = v.mv_size < outsz - 1 ? v.mv_size : outsz - 1;
  memcpy(out, v.mv_data, copy);
  out[copy] = '\0';
  if (got) *got = v.mv_size;
  return 0;
}

/* ======================================================================
 * Tests
 * ====================================================================== */

TEST(single_user_write_read) {
  ASSERT_EQ(open_test_env(), 0);

  /* Write */
  MDB_txn *txn;
  ASSERT_EQ(mdb_txn_begin(env, nullptr, 0, &txn), 0);
  ASSERT_EQ(put_user(txn, "Alice", "+no chans=1"), 0);
  ASSERT_EQ(mdb_txn_commit(txn), 0);

  /* Read back */
  char buf[256];
  ASSERT_EQ(mdb_txn_begin(env, nullptr, MDB_RDONLY, &txn), 0);
  ASSERT_EQ(get_user(txn, "Alice", buf, sizeof buf), 0);
  mdb_txn_abort(txn);

  ASSERT_STR_EQ(buf, "+no chans=1");

  close_test_env();
}

TEST(overwrite_existing_user) {
  ASSERT_EQ(open_test_env(), 0);

  MDB_txn *txn;
  /* First write */
  ASSERT_EQ(mdb_txn_begin(env, nullptr, 0, &txn), 0);
  ASSERT_EQ(put_user(txn, "Bob", "+no chans=0"), 0);
  ASSERT_EQ(mdb_txn_commit(txn), 0);

  /* Overwrite */
  ASSERT_EQ(mdb_txn_begin(env, nullptr, 0, &txn), 0);
  ASSERT_EQ(put_user(txn, "Bob", "+o chans=2"), 0);
  ASSERT_EQ(mdb_txn_commit(txn), 0);

  /* Read — should see the updated value */
  char buf[256];
  ASSERT_EQ(mdb_txn_begin(env, nullptr, MDB_RDONLY, &txn), 0);
  ASSERT_EQ(get_user(txn, "Bob", buf, sizeof buf), 0);
  mdb_txn_abort(txn);

  ASSERT_STR_EQ(buf, "+o chans=2");

  close_test_env();
}

TEST(delete_user) {
  ASSERT_EQ(open_test_env(), 0);

  MDB_txn *txn;
  /* Write */
  ASSERT_EQ(mdb_txn_begin(env, nullptr, 0, &txn), 0);
  ASSERT_EQ(put_user(txn, "Carol", "+no"), 0);
  ASSERT_EQ(mdb_txn_commit(txn), 0);

  /* Delete */
  ASSERT_EQ(mdb_txn_begin(env, nullptr, 0, &txn), 0);
  ASSERT_EQ(del_user(txn, "Carol"), 0);
  ASSERT_EQ(mdb_txn_commit(txn), 0);

  /* Read — should be gone (MDB_NOTFOUND == -30798) */
  char buf[256];
  ASSERT_EQ(mdb_txn_begin(env, nullptr, MDB_RDONLY, &txn), 0);
  int rc = get_user(txn, "Carol", buf, sizeof buf);
  mdb_txn_abort(txn);

  ASSERT_EQ(rc, MDB_NOTFOUND);

  close_test_env();
}

TEST(userfile_blob_roundtrip) {
  ASSERT_EQ(open_test_env(), 0);

  const char *blob = "#4v: eggdrop 1.0 -- testbot -- Mon Jan  1 00:00:00 2026\n"
                     "Alice      - +no\n"
                     "--HOSTS none\n";
  size_t blen = strlen(blob);

  MDB_txn *txn;
  /* Store blob under "userfile_blob" key (same key egg_store_lmdb uses) */
  ASSERT_EQ(mdb_txn_begin(env, nullptr, 0, &txn), 0);
  ASSERT_EQ(put_blob(txn, "userfile_blob", blob, blen), 0);
  ASSERT_EQ(mdb_txn_commit(txn), 0);

  /* Retrieve */
  char out[1024];
  size_t got = 0;
  ASSERT_EQ(mdb_txn_begin(env, nullptr, MDB_RDONLY, &txn), 0);
  ASSERT_EQ(get_blob(txn, "userfile_blob", out, sizeof out, &got), 0);
  mdb_txn_abort(txn);

  ASSERT_EQ((long)got, (long)blen);
  ASSERT_EQ(memcmp(out, blob, blen), 0);

  close_test_env();
}

TEST(blob_overwrite_and_reread) {
  ASSERT_EQ(open_test_env(), 0);

  const char *v1 = "version one";
  const char *v2 = "version two — much longer blob content here";

  MDB_txn *txn;

  /* Write v1 */
  ASSERT_EQ(mdb_txn_begin(env, nullptr, 0, &txn), 0);
  ASSERT_EQ(put_blob(txn, "userfile_blob", v1, strlen(v1)), 0);
  ASSERT_EQ(mdb_txn_commit(txn), 0);

  /* Overwrite with v2 */
  ASSERT_EQ(mdb_txn_begin(env, nullptr, 0, &txn), 0);
  ASSERT_EQ(put_blob(txn, "userfile_blob", v2, strlen(v2)), 0);
  ASSERT_EQ(mdb_txn_commit(txn), 0);

  /* Read — should get v2 */
  char out[256];
  size_t got = 0;
  ASSERT_EQ(mdb_txn_begin(env, nullptr, MDB_RDONLY, &txn), 0);
  ASSERT_EQ(get_blob(txn, "userfile_blob", out, sizeof out, &got), 0);
  mdb_txn_abort(txn);

  ASSERT_EQ((long)got, (long)strlen(v2));
  ASSERT_STR_EQ(out, v2);

  close_test_env();
}

TEST(missing_key_returns_not_found) {
  ASSERT_EQ(open_test_env(), 0);

  char buf[64];
  MDB_txn *txn;
  ASSERT_EQ(mdb_txn_begin(env, nullptr, MDB_RDONLY, &txn), 0);
  int rc = get_user(txn, "NonExistent", buf, sizeof buf);
  mdb_txn_abort(txn);

  ASSERT_EQ(rc, MDB_NOTFOUND);

  close_test_env();
}

/* ======================================================================
 * main
 * ====================================================================== */

int main(void)
{
  TEST_MAIN_BEGIN;
  RUN_TEST(single_user_write_read);
  RUN_TEST(overwrite_existing_user);
  RUN_TEST(delete_user);
  RUN_TEST(userfile_blob_roundtrip);
  RUN_TEST(blob_overwrite_and_reread);
  RUN_TEST(missing_key_returns_not_found);
  TEST_MAIN_END;
}

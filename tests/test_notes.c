/*
 * test_notes.c - Tests for notes.mod count cache
 *
 * Exercises the notes count cache that was introduced alongside the async
 * write refactor.  In particular tests that:
 *
 *   1. notes_cache_rebuild_from_buf() correctly counts notes per handle.
 *   2. The cache is path-keyed and invalidated when the path changes.
 *   3. num_notes() returns 0 for unknown handles.
 *   4. Multiple users and mixed-case handles work correctly.
 *   5. Comments and blank lines in the notefile are ignored.
 *   6. A zero-length buffer produces an empty cache.
 *   7. Rebuild after clear on path change produces fresh counts.
 *
 * Functions are extracted / stubbed here to avoid pulling in the full
 * eggdrop dependency graph (same pattern as test_misc.c).
 */

#include "test_harness.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <op_lib.h>

/* ---- Minimal stubs ---- */

static void rmspace(char *s)
{
  if (!s || !*s)
    return;
  char *q = s + strlen(s) - 1;
  while (q >= s && isspace((unsigned char)*q))
    q--;
  *(q + 1) = 0;
  char *p = s;
  while (isspace((unsigned char)*p))
    p++;
  if (p != s)
    memmove(s, p, (size_t)(q - p + 2));
}

static char *newsplit(char **rest)
{
  if (!rest)
    return "";
  char *o = *rest;
  while (*o == ' ')
    o++;
  char *r = o;
  while (*o && *o != ' ')
    o++;
  if (*o)
    *o++ = 0;
  *rest = o;
  return r;
}

/* ---- Replicated cache internals from notes.mod/notes.c ---- */

typedef struct notes_count_entry {
  char                    handle[33];   /* HANDLEN + 1 */
  int                     count;
  struct notes_count_entry *next;
} notes_count_entry_t;

static notes_count_entry_t *notes_count_cache = nullptr;
static char                 notes_cached_path[121] = "";
static char                 notefile[121] = "";

static void notes_cache_clear(void)
{
  notes_count_entry_t *e = notes_count_cache;
  while (e) {
    notes_count_entry_t *tmp = e->next;
    op_free(e);
    e = tmp;
  }
  notes_count_cache = nullptr;
}

static void notes_cache_scan(FILE *f)
{
  char s[513];
  while (fgets(s, sizeof s, f) != nullptr) {
    size_t n = strlen(s);
    if (n > 0 && s[n - 1] == '\n')
      s[n - 1] = 0;
    rmspace(s);
    if (!s[0] || s[0] == '#' || s[0] == ';')
      continue;
    char *s1 = s;
    char *to = newsplit(&s1);
    notes_count_entry_t *e;
    for (e = notes_count_cache; e; e = e->next)
      if (!op_strcasecmp(e->handle, to)) { e->count++; break; }
    if (!e) {
      e = (notes_count_entry_t *)op_malloc(sizeof *e);
      op_strlcpy(e->handle, to, sizeof e->handle);
      e->count = 1;
      e->next  = notes_count_cache;
      notes_count_cache = e;
    }
  }
}

static void notes_cache_rebuild_from_buf(char *buf, size_t len)
{
  notes_cache_clear();
  op_strlcpy(notes_cached_path, notefile, sizeof notes_cached_path);
  if (!buf || !len)
    return;
  FILE *f = fmemopen(buf, len, "r");
  if (!f)
    return;
  notes_cache_scan(f);
  fclose(f);
}

static void notes_cache_build(void)
{
  notes_cache_clear();
  op_strlcpy(notes_cached_path, notefile, sizeof notes_cached_path);
  if (!notefile[0])
    return;
  FILE *f = fopen(notefile, "r");
  if (!f)
    return;
  notes_cache_scan(f);
  fclose(f);
}

static int num_notes(char *user)
{
  if (!notefile[0])
    return 0;
  if (!notes_count_cache || strcmp(notes_cached_path, notefile))
    notes_cache_build();
  for (notes_count_entry_t *e = notes_count_cache; e; e = e->next)
    if (!op_strcasecmp(e->handle, user))
      return e->count;
  return 0;
}

/* ---- Helper: build a synthetic notefile buffer ---- */

static char *make_notebuf(const char *content, size_t *outlen)
{
  *outlen = strlen(content);
  char *buf = op_malloc(*outlen + 1);
  memcpy(buf, content, *outlen + 1);
  return buf;
}

/* ---- Tests ---- */

TEST(empty_buf_gives_zero_counts) {
  char *buf = op_malloc(1);
  buf[0] = 0;
  size_t len = 0;
  notes_cache_rebuild_from_buf(buf, len);
  /* no entries — any handle returns 0 */
  ASSERT_EQ(num_notes("alice"), 0);
  ASSERT_EQ(num_notes("bob"), 0);
  notes_cache_clear();
  op_free(buf);
}

TEST(single_user_single_note) {
  size_t len;
  char *buf = make_notebuf("alice bob 1700000000 hi there\n", &len);
  notes_cache_rebuild_from_buf(buf, len);
  ASSERT_EQ(num_notes("alice"), 1);
  ASSERT_EQ(num_notes("bob"), 0);
  notes_cache_clear();
  op_free(buf);
}

TEST(single_user_multiple_notes) {
  size_t len;
  char *buf = make_notebuf(
    "alice bob 1700000001 note one\n"
    "alice carol 1700000002 note two\n"
    "alice dave 1700000003 note three\n",
    &len);
  notes_cache_rebuild_from_buf(buf, len);
  ASSERT_EQ(num_notes("alice"), 3);
  notes_cache_clear();
  op_free(buf);
}

TEST(multiple_users) {
  size_t len;
  char *buf = make_notebuf(
    "alice bob 1700000001 hi\n"
    "bob alice 1700000002 hey\n"
    "alice carol 1700000003 yo\n"
    "carol bob 1700000004 sup\n",
    &len);
  notes_cache_rebuild_from_buf(buf, len);
  ASSERT_EQ(num_notes("alice"), 2);
  ASSERT_EQ(num_notes("bob"), 1);
  ASSERT_EQ(num_notes("carol"), 1);
  notes_cache_clear();
  op_free(buf);
}

TEST(case_insensitive_handle_lookup) {
  size_t len;
  char *buf = make_notebuf(
    "Alice bob 1700000001 hi\n"
    "ALICE carol 1700000002 hey\n",
    &len);
  notes_cache_rebuild_from_buf(buf, len);
  /* all three casings should return 2 */
  ASSERT_EQ(num_notes("alice"), 2);
  ASSERT_EQ(num_notes("Alice"), 2);
  ASSERT_EQ(num_notes("ALICE"), 2);
  notes_cache_clear();
  op_free(buf);
}

TEST(comments_and_blank_lines_ignored) {
  size_t len;
  char *buf = make_notebuf(
    "# this is a comment\n"
    "; another comment\n"
    "\n"
    "alice bob 1700000001 real note\n"
    "# trailing comment\n",
    &len);
  notes_cache_rebuild_from_buf(buf, len);
  ASSERT_EQ(num_notes("alice"), 1);
  notes_cache_clear();
  op_free(buf);
}

TEST(unknown_handle_returns_zero) {
  size_t len;
  char *buf = make_notebuf("alice bob 1700000001 hi\n", &len);
  notes_cache_rebuild_from_buf(buf, len);
  ASSERT_EQ(num_notes("nobody"), 0);
  ASSERT_EQ(num_notes(""), 0);
  notes_cache_clear();
  op_free(buf);
}

TEST(rebuild_replaces_previous_cache) {
  size_t len1, len2;
  char *buf1 = make_notebuf("alice bob 1700000001 first\n", &len1);
  char *buf2 = make_notebuf(
    "bob alice 1700000002 second\n"
    "bob carol 1700000003 third\n",
    &len2);

  notes_cache_rebuild_from_buf(buf1, len1);
  ASSERT_EQ(num_notes("alice"), 1);
  ASSERT_EQ(num_notes("bob"), 0);

  notes_cache_rebuild_from_buf(buf2, len2);
  ASSERT_EQ(num_notes("alice"), 0);
  ASSERT_EQ(num_notes("bob"), 2);

  notes_cache_clear();
  op_free(buf1);
  op_free(buf2);
}

TEST(path_change_invalidates_cache) {
  /* Build cache for path A */
  op_strlcpy(notefile, "/tmp/eggtest_notes_A.txt", sizeof notefile);

  /* Write a temp file so notes_cache_build() can read it */
  FILE *f = fopen(notefile, "w");
  ASSERT_NOT_NULL(f);
  fprintf(f, "alice bob 1700000001 from A\n");
  fclose(f);

  notes_cache_build();
  ASSERT_EQ(num_notes("alice"), 1);

  /* Change path — cache is now stale for a different path */
  op_strlcpy(notefile, "/tmp/eggtest_notes_B.txt", sizeof notefile);
  f = fopen(notefile, "w");
  ASSERT_NOT_NULL(f);
  fprintf(f, "alice bob 1700000002 from B line 1\n"
             "alice bob 1700000003 from B line 2\n");
  fclose(f);

  /* num_notes must detect the path mismatch and rebuild */
  ASSERT_EQ(num_notes("alice"), 2);

  notes_cache_clear();
  unlink("/tmp/eggtest_notes_A.txt");
  unlink("/tmp/eggtest_notes_B.txt");
  notefile[0] = 0;
}

TEST(cache_survives_no_trailing_newline) {
  /* some editors / truncated writes may omit the final newline */
  const char raw[] = "alice bob 1700000001 no newline";
  size_t len = sizeof raw - 1;
  char *buf = op_malloc(len);
  memcpy(buf, raw, len);
  notes_cache_rebuild_from_buf(buf, len);
  ASSERT_EQ(num_notes("alice"), 1);
  notes_cache_clear();
  op_free(buf);
}

TEST(num_notes_with_empty_notefile_path) {
  notefile[0] = 0;
  notes_cache_clear();
  ASSERT_EQ(num_notes("alice"), 0);
}

int main(void)
{
  TEST_MAIN_BEGIN;
  RUN_TEST(empty_buf_gives_zero_counts);
  RUN_TEST(single_user_single_note);
  RUN_TEST(single_user_multiple_notes);
  RUN_TEST(multiple_users);
  RUN_TEST(case_insensitive_handle_lookup);
  RUN_TEST(comments_and_blank_lines_ignored);
  RUN_TEST(unknown_handle_returns_zero);
  RUN_TEST(rebuild_replaces_previous_cache);
  RUN_TEST(path_change_invalidates_cache);
  RUN_TEST(cache_survives_no_trailing_newline);
  RUN_TEST(num_notes_with_empty_notefile_path);
  TEST_MAIN_END;
}

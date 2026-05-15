/*
 * test_misc.c - Tests for string utilities from misc.c and chanprog.c
 *
 * Functions are extracted here to avoid pulling in the entire eggdrop
 * dependency graph. newsplit uses libop SIMD helpers; the others are pure.
 */

#include "test_harness.h"
#include <string.h>
#include <ctype.h>
#include <op_lib.h>

/* --- Extracted from src/chanprog.c --- */

#define egg_isspace(x) isspace((int)(unsigned char)(x))

static void rmspace(char *s)
{
  char *p = nullptr, *q = nullptr;

  if (!s || !*s)
    return;

  for (q = s + strlen(s) - 1; q >= s && egg_isspace(*q); q--);
  *(q + 1) = 0;

  for (p = s; egg_isspace(*p); p++);

  if (p != s)
    memmove(s, p, (size_t)(q - p + 2));
}

/* --- Extracted from src/misc.c --- */

static char *splitnick(char **blah)
{
  char *p = strchr(*blah, '!'), *q = *blah;

  if (p) {
    *p = 0;
    *blah = p + 1;
    return q;
  }
  return "";
}

static char *newsplit(char **rest)
{
  char *o, *r;

  if (!rest)
    return "";
  o = *rest;
  {
    const char *end = o + strlen(o);
    size_t spaces = op_simd_count_leading(o, end, ' ');
    o += spaces;
    r = o;
    const char *delim = op_simd_find_delim(o, end, ' ', '\0');
    o = (char *)delim;
  }
  if (*o)
    *o++ = 0;
  *rest = o;
  return r;
}

/* --- Tests for newsplit --- */

TEST(newsplit_basic) {
    char input[] = "hello world test";
    char *remaining = input;
    char *first = newsplit(&remaining);

    ASSERT_STR_EQ(first, "hello");
    ASSERT_STR_EQ(remaining, "world test");
}

TEST(newsplit_single_word) {
    char input[] = "onlyword";
    char *remaining = input;
    char *first = newsplit(&remaining);

    ASSERT_STR_EQ(first, "onlyword");
    ASSERT_STR_EQ(remaining, "");
}

TEST(newsplit_multiple_spaces) {
    char input[] = "word1    word2   word3";
    char *remaining = input;
    char *first = newsplit(&remaining);

    ASSERT_STR_EQ(first, "word1");
    ASSERT_STR_EQ(remaining, "word2   word3");
}

TEST(newsplit_leading_spaces) {
    char input[] = "   leading spaces here";
    char *remaining = input;
    char *first = newsplit(&remaining);

    ASSERT_STR_EQ(first, "leading");
    ASSERT_STR_EQ(remaining, "spaces here");
}

TEST(newsplit_empty_string) {
    char input[] = "";
    char *remaining = input;
    char *first = newsplit(&remaining);

    ASSERT_STR_EQ(first, "");
    ASSERT_STR_EQ(remaining, "");
}

TEST(newsplit_null_pointer) {
    char *first = newsplit(nullptr);
    ASSERT_STR_EQ(first, "");
}

/* --- Tests for rmspace --- */

TEST(rmspace_trailing_spaces) {
    char input[] = "hello world   ";
    rmspace(input);
    ASSERT_STR_EQ(input, "hello world");
}

TEST(rmspace_leading_spaces) {
    char input[] = "   hello world";
    rmspace(input);
    ASSERT_STR_EQ(input, "hello world");
}

TEST(rmspace_both_ends) {
    char input[] = "   hello world   ";
    rmspace(input);
    ASSERT_STR_EQ(input, "hello world");
}

TEST(rmspace_tabs_and_spaces) {
    char input[] = "  \t hello world \t  ";
    rmspace(input);
    ASSERT_STR_EQ(input, "hello world");
}

TEST(rmspace_only_whitespace) {
    char input[] = "   \t  \n  ";
    rmspace(input);
    ASSERT_STR_EQ(input, "");
}

TEST(rmspace_no_whitespace) {
    char input[] = "nowhitespace";
    rmspace(input);
    ASSERT_STR_EQ(input, "nowhitespace");
}

TEST(rmspace_empty_string) {
    char input[] = "";
    rmspace(input);
    ASSERT_STR_EQ(input, "");
}

TEST(rmspace_null_pointer) {
    rmspace(nullptr);
}

/* --- Tests for splitnick --- */

TEST(splitnick_full_hostmask) {
    char input[] = "nick!user@host.example.com";
    char *remaining = input;
    char *nick = splitnick(&remaining);

    ASSERT_STR_EQ(nick, "nick");
    ASSERT_STR_EQ(remaining, "user@host.example.com");
}

TEST(splitnick_nick_only) {
    char input[] = "justnick";
    char *remaining = input;
    char *nick = splitnick(&remaining);

    ASSERT_STR_EQ(nick, "");
    ASSERT_STR_EQ(remaining, "justnick");
}

TEST(splitnick_empty_string) {
    char input[] = "";
    char *remaining = input;
    char *nick = splitnick(&remaining);

    ASSERT_STR_EQ(nick, "");
    ASSERT_STR_EQ(remaining, "");
}

TEST(splitnick_exclamation_only) {
    char input[] = "!user@host";
    char *remaining = input;
    char *nick = splitnick(&remaining);

    ASSERT_STR_EQ(nick, "");
    ASSERT_STR_EQ(remaining, "user@host");
}

int main(void) {
    TEST_MAIN_BEGIN;

    RUN_TEST(newsplit_basic);
    RUN_TEST(newsplit_single_word);
    RUN_TEST(newsplit_multiple_spaces);
    RUN_TEST(newsplit_leading_spaces);
    RUN_TEST(newsplit_empty_string);
    RUN_TEST(newsplit_null_pointer);
    RUN_TEST(rmspace_trailing_spaces);
    RUN_TEST(rmspace_leading_spaces);
    RUN_TEST(rmspace_both_ends);
    RUN_TEST(rmspace_tabs_and_spaces);
    RUN_TEST(rmspace_only_whitespace);
    RUN_TEST(rmspace_no_whitespace);
    RUN_TEST(rmspace_empty_string);
    RUN_TEST(rmspace_null_pointer);
    RUN_TEST(splitnick_full_hostmask);
    RUN_TEST(splitnick_nick_only);
    RUN_TEST(splitnick_empty_string);
    RUN_TEST(splitnick_exclamation_only);

    TEST_MAIN_END;
}

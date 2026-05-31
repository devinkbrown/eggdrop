/*
 * test_match.c - Tests for wildcard matching functions
 */

#include "test_harness.h"

/* Include the rfc1459 and match implementations via unity build.
 * main.h (included by both) brings in op_lib.h and eggdrop.h,
 * so we need -DHAVE_CONFIG_H and libop_dep in the build.
 */
#include "../src/rfc1459.c"

/* Provide symbols needed by addr_match/cron_match in match.c */
int (*rfc_toupper)(int) = _rfc_toupper;

int str_isdigit(const char *str)
{
  if (!*str)
    return 0;
  for (; *str; ++str)
    if (!isdigit((unsigned char)(*str)))
      return 0;
  return 1;
}

char *newsplit(char **rest)
{
  char *o, *r;
  if (!rest)
    return "";
  o = *rest;
  while (*o == ' ')
    o++;
  r = o;
  while (*o && *o != ' ')
    o++;
  if (*o)
    *o++ = 0;
  *rest = o;
  return r;
}

#include "../src/match.c"

/* Tests */

TEST(wild_match_exact) {
    ASSERT_TRUE(wild_match("hello", "hello"));
    ASSERT_FALSE(wild_match("hello", "world"));
    ASSERT_FALSE(wild_match("", ""));   /* empty string never matches */
}

TEST(wild_match_asterisk_any) {
    ASSERT_TRUE(wild_match("*", "anything"));
    ASSERT_FALSE(wild_match("*", ""));   /* empty string never matches */
    ASSERT_TRUE(wild_match("test*", "test"));
    ASSERT_TRUE(wild_match("test*", "testing"));
    ASSERT_TRUE(wild_match("*test", "test"));
    ASSERT_TRUE(wild_match("*test", "mytest"));
}

TEST(wild_match_question_single) {
    ASSERT_TRUE(wild_match("?", "a"));
    ASSERT_FALSE(wild_match("?", ""));
    ASSERT_FALSE(wild_match("?", "ab"));
    ASSERT_TRUE(wild_match("te?t", "test"));
    ASSERT_TRUE(wild_match("te?t", "text"));
    ASSERT_FALSE(wild_match("te?t", "tet"));
}

TEST(wild_match_irc_hostmask) {
    ASSERT_TRUE(wild_match("*!*@*", "nick!user@host.com"));
    ASSERT_TRUE(wild_match("nick!*@*", "nick!user@host.com"));
    ASSERT_TRUE(wild_match("*!*@*.com", "nick!user@host.com"));
    ASSERT_FALSE(wild_match("*!*@*.net", "nick!user@host.com"));

    ASSERT_TRUE(wild_match("*!user@*", "nick!user@host.com"));
    ASSERT_FALSE(wild_match("*!admin@*", "nick!user@host.com"));
}

TEST(wild_match_complex_patterns) {
    ASSERT_TRUE(wild_match("a*b*c", "aXXbYYc"));
    ASSERT_TRUE(wild_match("a*b*c", "abc"));
    ASSERT_FALSE(wild_match("a*b*c", "aXXcYYb"));

    ASSERT_TRUE(wild_match("te?t*ing", "testing"));
    ASSERT_TRUE(wild_match("te?t*ing", "texting"));
    ASSERT_TRUE(wild_match("te?t*ing", "teating")); /* te+a+t+""+ing */
}

TEST(wild_match_case_insensitive) {
    ASSERT_TRUE(wild_match("Hello", "HELLO"));
    ASSERT_TRUE(wild_match("test*", "TEST123"));
    ASSERT_TRUE(wild_match("*WoRlD", "helloworld"));
}

TEST(wild_match_edge_cases) {
    ASSERT_FALSE(wild_match("test", ""));
    ASSERT_FALSE(wild_match("", "test"));
    ASSERT_FALSE(wild_match("*", ""));   /* empty string never matches */
    ASSERT_TRUE(wild_match("**", "anything"));
    ASSERT_TRUE(wild_match("*?*", "a"));
}

/* ---- Additional regression tests (Item 19) --------------------------------
 *
 * These cover specific patterns required by the task spec.  Some overlap with
 * existing tests by design (regression safety), but target the concrete
 * assertions listed in the spec.
 * -------------------------------------------------------------------------- */

/* Spec item 2: foo* prefix and barfoo prefix-mismatch */
TEST(wild_match_prefix_mismatch) {
    ASSERT_TRUE(wild_match("foo*", "foobar"));
    ASSERT_FALSE(wild_match("foo*", "barfoo")); /* prefix does not match */
    ASSERT_TRUE(wild_match("foo*", "foo"));     /* empty suffix after * */
    ASSERT_FALSE(wild_match("foo*", "fo"));     /* prefix too short */
}

/* Spec item 3: IRC nick!user@host hostmask */
TEST(wild_match_irc_hostmask_spec) {
    ASSERT_TRUE(wild_match("*!*@*", "nick!user@host"));
    ASSERT_TRUE(wild_match("*!*@*", "n!u@h"));
    /* single-char fields still satisfy the three-part mask */
    ASSERT_TRUE(wild_match("*!*@*", "a!b@c"));
}

/* Spec item 4: ?ick single-char prefix wildcard */
TEST(wild_match_question_prefix) {
    ASSERT_TRUE(wild_match("?ick", "nick"));
    ASSERT_TRUE(wild_match("?ick", "kick"));
    ASSERT_FALSE(wild_match("?ick", "ni"));    /* string too short */
    ASSERT_FALSE(wild_match("?ick", "niick")); /* string too long */
}

/* Spec item 5: case-insensitivity — _wild_match uses toupper() on both sides */
TEST(wild_match_case_insensitive_spec) {
    ASSERT_TRUE(wild_match("NICK", "nick"));
    ASSERT_TRUE(wild_match("nick", "NICK"));
    ASSERT_TRUE(wild_match("Nick!*@*", "NICK!user@host"));
}

/* Spec item 6: wild_match_per — % matches 0 or more non-space characters.
 * Unlike * (which matches anything including spaces), % stops at a space.
 * Signature: wild_match_per(mask, string) via the macro in proto.h which
 * calls _wild_match_per(m, n, casecharcmp, NULL, NULL). */
TEST(wild_match_per_percent_wildcard) {
    /* % matches one or more non-space chars (like * but no spaces) */
    ASSERT_TRUE(wild_match_per("%", "word"));
    ASSERT_TRUE(wild_match_per("foo%", "foobar"));
    ASSERT_TRUE(wild_match_per("%bar", "foobar"));

    /* % does NOT cross a space boundary */
    ASSERT_FALSE(wild_match_per("%", "hello world")); /* space in string */

    /* * DOES cross space; % does not */
    ASSERT_TRUE(wild_match("*", "hello world"));
    ASSERT_FALSE(wild_match_per("%", "hello world"));

    /* mixed: * before space, % after */
    ASSERT_TRUE(wild_match_per("hello %", "hello world"));

    /* empty string never matches */
    ASSERT_FALSE(wild_match_per("%", ""));
    ASSERT_FALSE(wild_match_per("*", ""));
}

/* Spec item 7: empty pattern / empty string edge cases */
TEST(wild_match_empty_edge_cases) {
    /* Empty string never matches any pattern */
    ASSERT_FALSE(wild_match("*",    ""));
    ASSERT_FALSE(wild_match("?",    ""));
    ASSERT_FALSE(wild_match("",     "nonempty"));
    ASSERT_FALSE(wild_match("test", ""));

    /* Wild-match-per: same rules */
    ASSERT_FALSE(wild_match_per("*",    ""));
    ASSERT_FALSE(wild_match_per("%",    ""));
    ASSERT_FALSE(wild_match_per("",     "nonempty"));
    ASSERT_FALSE(wild_match_per("test", ""));
}

/* RFC1459 special-char equivalences ({=[, }=], |=\, ~=^) are handled by
 * rfc1459_match(), not wild_match() which uses plain case-insensitive ASCII. */

/* CIDR matching tests */

TEST(cidr_match_same_subnet) {
    ASSERT_TRUE(cidr_match("192.168.1.0", "192.168.1.100", 24) > 0);
    ASSERT_TRUE(cidr_match("10.0.0.0", "10.0.0.255", 24) > 0);
}

TEST(cidr_match_different_subnet) {
    ASSERT_EQ(cidr_match("192.168.1.0", "192.168.2.100", 24), 0);
    ASSERT_EQ(cidr_match("10.0.0.0", "10.0.1.0", 24), 0);
}

TEST(cidr_match_exact_32) {
    ASSERT_TRUE(cidr_match("10.0.0.1", "10.0.0.1", 32) > 0);
    ASSERT_EQ(cidr_match("10.0.0.1", "10.0.0.2", 32), 0);
}

TEST(cidr_match_zero_prefix) {
    ASSERT_EQ(cidr_match("1.2.3.4", "5.6.7.8", 0), 1);
    ASSERT_EQ(cidr_match("255.255.255.255", "0.0.0.0", 0), 1);
}

TEST(cidr_match_invalid_count) {
    ASSERT_EQ(cidr_match("192.168.1.0", "192.168.1.100", 33), 0);
    ASSERT_EQ(cidr_match("10.0.0.1", "10.0.0.1", 99), 0);
}

TEST(cidr_match_invalid_ip) {
    ASSERT_EQ(cidr_match("not.an.ip", "192.168.1.1", 24), 0);
    ASSERT_EQ(cidr_match("192.168.1.1", "garbage", 24), 0);
    ASSERT_EQ(cidr_match("", "", 24), 0);
}

/* cron_match tests */

TEST(cron_match_wildcard_all) {
    ASSERT_EQ(cron_match("* * * * *", "30 12 15 06 3"), 1);
    ASSERT_EQ(cron_match("* * * * *", "0 0 1 1 0"), 1);
}

TEST(cron_match_exact_minute) {
    ASSERT_EQ(cron_match("30 * * * *", "30 12 15 06 3"), 1);
}

TEST(cron_match_exact_minute_no_match) {
    ASSERT_EQ(cron_match("45 * * * *", "30 12 15 06 3"), 0);
}

TEST(cron_match_range) {
    ASSERT_EQ(cron_match("25-35 * * * *", "30 12 15 06 3"), 1);
    ASSERT_EQ(cron_match("0-10 * * * *", "30 12 15 06 3"), 0);
}

TEST(cron_match_empty_mask) {
    ASSERT_EQ(cron_match("", "30 12 15 06 3"), 0);
}

/* addr_match tests */

TEST(addr_match_simple_hostmask) {
    ASSERT_TRUE(addr_match("*!*@*.example.com",
                           "nick!user@host.example.com", 0, 0) > 0);
}

TEST(addr_match_no_match) {
    ASSERT_EQ(addr_match("*!*@*.net",
                         "nick!user@host.example.com", 0, 0), 0);
}

TEST(addr_match_cidr_notation) {
    int saved = cidr_support;
    cidr_support = 1;
    ASSERT_TRUE(addr_match("*!*@192.168.1.0/24",
                           "nick!user@192.168.1.50", 0, 0) > 0);
    ASSERT_EQ(addr_match("*!*@10.0.0.0/8",
                         "nick!user@192.168.1.50", 0, 0), 0);
    cidr_support = saved;
}

int main(void) {
    TEST_MAIN_BEGIN;

    RUN_TEST(wild_match_exact);
    RUN_TEST(wild_match_asterisk_any);
    RUN_TEST(wild_match_question_single);
    RUN_TEST(wild_match_irc_hostmask);
    RUN_TEST(wild_match_complex_patterns);
    RUN_TEST(wild_match_case_insensitive);
    RUN_TEST(wild_match_edge_cases);
    /* Item 19 regression tests */
    RUN_TEST(wild_match_prefix_mismatch);
    RUN_TEST(wild_match_irc_hostmask_spec);
    RUN_TEST(wild_match_question_prefix);
    RUN_TEST(wild_match_case_insensitive_spec);
    RUN_TEST(wild_match_per_percent_wildcard);
    RUN_TEST(wild_match_empty_edge_cases);

    RUN_TEST(cidr_match_same_subnet);
    RUN_TEST(cidr_match_different_subnet);
    RUN_TEST(cidr_match_exact_32);
    RUN_TEST(cidr_match_zero_prefix);
    RUN_TEST(cidr_match_invalid_count);
    RUN_TEST(cidr_match_invalid_ip);

    RUN_TEST(cron_match_wildcard_all);
    RUN_TEST(cron_match_exact_minute);
    RUN_TEST(cron_match_exact_minute_no_match);
    RUN_TEST(cron_match_range);
    RUN_TEST(cron_match_empty_mask);

    RUN_TEST(addr_match_simple_hostmask);
    RUN_TEST(addr_match_no_match);
    RUN_TEST(addr_match_cidr_notation);

    TEST_MAIN_END;
}

/*
 * test_match.c - Tests for wildcard matching functions
 */

#include "test_harness.h"

/* Include the rfc1459 and match implementations via unity build.
 * main.h (included by both) brings in op_lib.h and eggdrop.h,
 * so we need -DHAVE_CONFIG_H and libop_dep in the build.
 */
#include "../src/rfc1459.c"
#include "../src/match.c"

/* Tests */

TEST(wild_match_exact) {
    ASSERT_TRUE(wild_match("hello", "hello"));
    ASSERT_FALSE(wild_match("hello", "world"));
    ASSERT_TRUE(wild_match("", ""));
}

TEST(wild_match_asterisk_any) {
    ASSERT_TRUE(wild_match("*", "anything"));
    ASSERT_TRUE(wild_match("*", ""));
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
    ASSERT_FALSE(wild_match("te?t*ing", "teating"));
}

TEST(wild_match_case_insensitive) {
    ASSERT_TRUE(wild_match("Hello", "HELLO"));
    ASSERT_TRUE(wild_match("test*", "TEST123"));
    ASSERT_TRUE(wild_match("*WoRlD", "helloworld"));
}

TEST(wild_match_edge_cases) {
    ASSERT_FALSE(wild_match("test", ""));
    ASSERT_FALSE(wild_match("", "test"));
    ASSERT_TRUE(wild_match("*", ""));
    ASSERT_TRUE(wild_match("**", "anything"));
    ASSERT_TRUE(wild_match("*?*", "a"));
}

TEST(wild_match_rfc1459_special) {
    ASSERT_TRUE(wild_match("test{", "TEST["));
    ASSERT_TRUE(wild_match("user|name", "USER\\NAME"));
    ASSERT_TRUE(wild_match("host}", "HOST]"));
    ASSERT_TRUE(wild_match("nick~", "NICK^"));

    ASSERT_TRUE(wild_match("*{*", "before[after"));
    ASSERT_TRUE(wild_match("*|*", "before\\after"));
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
    RUN_TEST(wild_match_rfc1459_special);

    TEST_MAIN_END;
}

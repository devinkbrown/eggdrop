/*
 * test_rfc1459.c - Tests for RFC 1459 casemapping functions
 */

#include "test_harness.h"

/* Include the rfc1459.c implementation (unity build). */
#include "../src/rfc1459.c"

/* Function pointers normally defined in modules.c. */
int (*rfc_casecmp)(const char *, const char *) = _rfc_casecmp;
int (*rfc_ncasecmp)(const char *, const char *, int) = _rfc_ncasecmp;
int (*rfc_toupper)(int) = _rfc_toupper;
int (*rfc_tolower)(int) = _rfc_tolower;

/* Tests */

TEST(rfc_toupper_special_chars) {
    ASSERT_EQ(rfc_toupper('{'), '[');
    ASSERT_EQ(rfc_toupper('|'), '\\');
    ASSERT_EQ(rfc_toupper('}'), ']');
    ASSERT_EQ(rfc_toupper('~'), '^');
}

TEST(rfc_tolower_special_chars) {
    ASSERT_EQ(rfc_tolower('['), '{');
    ASSERT_EQ(rfc_tolower('\\'), '|');
    ASSERT_EQ(rfc_tolower(']'), '}');
    ASSERT_EQ(rfc_tolower('^'), '~');
}

TEST(rfc_toupper_normal_chars) {
    ASSERT_EQ(rfc_toupper('a'), 'A');
    ASSERT_EQ(rfc_toupper('z'), 'Z');
    ASSERT_EQ(rfc_toupper('A'), 'A');
    ASSERT_EQ(rfc_toupper('1'), '1');
}

TEST(rfc_tolower_normal_chars) {
    ASSERT_EQ(rfc_tolower('A'), 'a');
    ASSERT_EQ(rfc_tolower('Z'), 'z');
    ASSERT_EQ(rfc_tolower('a'), 'a');
    ASSERT_EQ(rfc_tolower('1'), '1');
}

TEST(rfc_casecmp_equal_strings) {
    ASSERT_EQ(rfc_casecmp("hello", "HELLO"), 0);
    ASSERT_EQ(rfc_casecmp("test", "test"), 0);
    ASSERT_EQ(rfc_casecmp("", ""), 0);
}

TEST(rfc_casecmp_different_strings) {
    ASSERT_NEQ(rfc_casecmp("hello", "world"), 0);
    ASSERT_NEQ(rfc_casecmp("abc", "def"), 0);
    ASSERT_NEQ(rfc_casecmp("short", "longer"), 0);
}

TEST(rfc_casecmp_irc_special_chars) {
    ASSERT_EQ(rfc_casecmp("nick{", "NICK["), 0);
    ASSERT_EQ(rfc_casecmp("user|name", "USER\\NAME"), 0);
    ASSERT_EQ(rfc_casecmp("host}", "HOST]"), 0);
    ASSERT_EQ(rfc_casecmp("test~", "TEST^"), 0);
}

TEST(rfc_ncasecmp_with_length) {
    ASSERT_EQ(rfc_ncasecmp("hello", "HELLO", 5), 0);
    ASSERT_EQ(rfc_ncasecmp("hello", "HELLO", 3), 0);
    ASSERT_EQ(rfc_ncasecmp("hello", "HELLX", 4), 0);
    ASSERT_NEQ(rfc_ncasecmp("hello", "HELLX", 5), 0);
}

TEST(rfc_ncasecmp_zero_length) {
    ASSERT_EQ(rfc_ncasecmp("abc", "xyz", 0), 0);
}

TEST(rfc_ncasecmp_irc_special) {
    ASSERT_EQ(rfc_ncasecmp("nick{test", "NICK[TEST", 5), 0);
    ASSERT_EQ(rfc_ncasecmp("user|", "USER\\", 5), 0);
}

TEST(rfc_case_roundtrip) {
    char c = '{';
    ASSERT_EQ(rfc_toupper(rfc_tolower(rfc_toupper(c))), rfc_toupper(c));

    c = '[';
    ASSERT_EQ(rfc_tolower(rfc_toupper(rfc_tolower(c))), rfc_tolower(c));
}

int main(void) {
    TEST_MAIN_BEGIN;

    RUN_TEST(rfc_toupper_special_chars);
    RUN_TEST(rfc_tolower_special_chars);
    RUN_TEST(rfc_toupper_normal_chars);
    RUN_TEST(rfc_tolower_normal_chars);
    RUN_TEST(rfc_casecmp_equal_strings);
    RUN_TEST(rfc_casecmp_different_strings);
    RUN_TEST(rfc_casecmp_irc_special_chars);
    RUN_TEST(rfc_ncasecmp_with_length);
    RUN_TEST(rfc_ncasecmp_zero_length);
    RUN_TEST(rfc_ncasecmp_irc_special);
    RUN_TEST(rfc_case_roundtrip);

    TEST_MAIN_END;
}

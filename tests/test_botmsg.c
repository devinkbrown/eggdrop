/*
 * test_botmsg.c - Tests for base conversion functions from botmsg.c/botcmd.c
 *
 * These functions are pure (no global state) so we copy them here to avoid
 * pulling in the entire eggdrop dependency graph.
 */

#include "test_harness.h"
#include <string.h>
#include <stdint.h>
#include <limits.h>

/* --- Extracted from src/botmsg.c --- */

static const char tobase64array[64] = {
  'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
  'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
  'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
  'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  '[', ']'
};

static char *int_to_base64(unsigned int val)
{
  static char buf_base64[12];
  int i = 11;

  buf_base64[11] = 0;
  if (!val) {
    buf_base64[10] = 'A';
    return buf_base64 + 10;
  }
  while (val) {
    i--;
    buf_base64[i] = tobase64array[val & 0x3f];
    val = val >> 6;
  }
  return buf_base64 + i;
}

static char *int_to_base10(int val)
{
  static char buf_base10[17];
  int p = 0;
  int i = 16;

  buf_base10[16] = 0;
  if (!val) {
    buf_base10[15] = '0';
    return buf_base10 + 15;
  }
  if (val < 0) {
    p = 1;
    val *= -1;
  }
  while (val) {
    i--;
    buf_base10[i] = '0' + (val % 10);
    val /= 10;
  }
  if (p) {
    i--;
    buf_base10[i] = '-';
  }
  return buf_base10 + i;
}

static char *unsigned_int_to_base10(unsigned int val)
{
  static char buf_base10[16];
  int i = 15;

  buf_base10[15] = 0;
  if (!val) {
    buf_base10[14] = '0';
    return buf_base10 + 14;
  }
  while (val) {
    i--;
    buf_base10[i] = '0' + (val % 10);
    val /= 10;
  }
  return buf_base10 + i;
}

/* --- Extracted from src/botcmd.c --- */

static const char base64to[256] = {
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 0, 0,
  0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
  15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 62, 0, 63, 0, 0, 0, 26, 27, 28,
  29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48,
  49, 50, 51, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

static int base64_to_int(char *buf)
{
  int i = 0;
  while (*buf) {
    int j = base64to[(uint8_t) *buf];
    if (i > ((INT_MAX >> 6) - j))
      return -1;
    i = (i << 6) + j;
    buf++;
  }
  return i;
}

/* --- Tests --- */

TEST(int_to_base64_zero) {
    ASSERT_STR_EQ(int_to_base64(0), "A");
}

TEST(int_to_base64_single_chars) {
    ASSERT_STR_EQ(int_to_base64(1), "B");
    ASSERT_STR_EQ(int_to_base64(25), "Z");
    ASSERT_STR_EQ(int_to_base64(26), "a");
    ASSERT_STR_EQ(int_to_base64(51), "z");
    ASSERT_STR_EQ(int_to_base64(52), "0");
    ASSERT_STR_EQ(int_to_base64(63), "9");
}

TEST(int_to_base64_multi_digit) {
    char *r = int_to_base64(64);
    ASSERT_NOT_NULL(r);
    ASSERT_TRUE(strlen(r) == 2);

    r = int_to_base64(4095);
    ASSERT_NOT_NULL(r);
    ASSERT_TRUE(strlen(r) > 0);
}

TEST(base64_to_int_single) {
    ASSERT_EQ(base64_to_int("A"), 0);
    ASSERT_EQ(base64_to_int("B"), 1);
    ASSERT_EQ(base64_to_int("Z"), 25);
    ASSERT_EQ(base64_to_int("a"), 26);
    ASSERT_EQ(base64_to_int("z"), 51);
    ASSERT_EQ(base64_to_int("0"), 52);
    ASSERT_EQ(base64_to_int("9"), 63);
}

TEST(base64_round_trip) {
    for (unsigned int i = 0; i < 10000; i++) {
        char *enc = int_to_base64(i);
        int dec = base64_to_int(enc);
        ASSERT_EQ((unsigned int)dec, i);
    }
}

TEST(base64_overflow) {
    ASSERT_EQ(base64_to_int("9999999999999999999"), -1);
}

TEST(int_to_base10_values) {
    ASSERT_STR_EQ(int_to_base10(0), "0");
    ASSERT_STR_EQ(int_to_base10(1), "1");
    ASSERT_STR_EQ(int_to_base10(42), "42");
    ASSERT_STR_EQ(int_to_base10(9999), "9999");
    ASSERT_STR_EQ(int_to_base10(-1), "-1");
    ASSERT_STR_EQ(int_to_base10(-42), "-42");
}

TEST(unsigned_int_to_base10_values) {
    ASSERT_STR_EQ(unsigned_int_to_base10(0), "0");
    ASSERT_STR_EQ(unsigned_int_to_base10(1), "1");
    ASSERT_STR_EQ(unsigned_int_to_base10(4294967295U), "4294967295");
}

int main(void) {
    TEST_MAIN_BEGIN;

    RUN_TEST(int_to_base64_zero);
    RUN_TEST(int_to_base64_single_chars);
    RUN_TEST(int_to_base64_multi_digit);
    RUN_TEST(base64_to_int_single);
    RUN_TEST(base64_round_trip);
    RUN_TEST(base64_overflow);
    RUN_TEST(int_to_base10_values);
    RUN_TEST(unsigned_int_to_base10_values);

    TEST_MAIN_END;
}

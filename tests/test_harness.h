/*
 * test_harness.h - Minimal single-header test framework for eggdrop C tests
 *
 * Usage:
 *   #include "test_harness.h"
 *
 *   TEST(my_test) {
 *     ASSERT_TRUE(1 == 1);
 *     ASSERT_STR_EQ("hello", "hello");
 *   }
 *
 *   int main(void) {
 *     TEST_MAIN_BEGIN;
 *     RUN_TEST(my_test);
 *     TEST_MAIN_END;
 *   }
 */

#ifndef TEST_HARNESS_H
#define TEST_HARNESS_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int _test_passes = 0;
static int _test_failures = 0;

#define TEST(name) static void test_##name(void)

#define ASSERT_TRUE(expr) do { \
  if (!(expr)) { \
    printf("\033[31mFAIL\033[0m %s:%d: ASSERT_TRUE(%s)\n", __FILE__, __LINE__, #expr); \
    return; \
  } \
} while(0)

#define ASSERT_FALSE(expr) do { \
  if ((expr)) { \
    printf("\033[31mFAIL\033[0m %s:%d: ASSERT_FALSE(%s)\n", __FILE__, __LINE__, #expr); \
    return; \
  } \
} while(0)

#define ASSERT_EQ(a, b) do { \
  if ((a) != (b)) { \
    printf("\033[31mFAIL\033[0m %s:%d: ASSERT_EQ(%s, %s) [%ld != %ld]\n", \
           __FILE__, __LINE__, #a, #b, (long)(a), (long)(b)); \
    return; \
  } \
} while(0)

#define ASSERT_NEQ(a, b) do { \
  if ((a) == (b)) { \
    printf("\033[31mFAIL\033[0m %s:%d: ASSERT_NEQ(%s, %s) [%ld == %ld]\n", \
           __FILE__, __LINE__, #a, #b, (long)(a), (long)(b)); \
    return; \
  } \
} while(0)

#define ASSERT_STR_EQ(a, b) do { \
  const char *_sa = (a), *_sb = (b); \
  if (!_sa && !_sb) break; \
  if (!_sa || !_sb || strcmp(_sa, _sb) != 0) { \
    printf("\033[31mFAIL\033[0m %s:%d: ASSERT_STR_EQ(%s, %s) [\"%s\" != \"%s\"]\n", \
           __FILE__, __LINE__, #a, #b, _sa ? _sa : "(null)", _sb ? _sb : "(null)"); \
    return; \
  } \
} while(0)

#define ASSERT_STR_NEQ(a, b) do { \
  const char *_sa = (a), *_sb = (b); \
  if (_sa && _sb && strcmp(_sa, _sb) == 0) { \
    printf("\033[31mFAIL\033[0m %s:%d: ASSERT_STR_NEQ(%s, %s) [\"%s\" == \"%s\"]\n", \
           __FILE__, __LINE__, #a, #b, _sa, _sb); \
    return; \
  } \
} while(0)

#define ASSERT_NULL(ptr) do { \
  if ((ptr) != NULL) { \
    printf("\033[31mFAIL\033[0m %s:%d: ASSERT_NULL(%s) [%p]\n", \
           __FILE__, __LINE__, #ptr, (void*)(ptr)); \
    return; \
  } \
} while(0)

#define ASSERT_NOT_NULL(ptr) do { \
  if ((ptr) == NULL) { \
    printf("\033[31mFAIL\033[0m %s:%d: ASSERT_NOT_NULL(%s)\n", \
           __FILE__, __LINE__, #ptr); \
    return; \
  } \
} while(0)

#define RUN_TEST(name) do { \
  printf("Running test_%s... ", #name); \
  test_##name(); \
  printf("\033[32mPASS\033[0m\n"); \
  _test_passes++; \
} while(0)

#define TEST_MAIN_BEGIN do { \
  printf("Running eggdrop C tests\n"); \
  printf("========================\n"); \
} while(0)

#define TEST_MAIN_END do { \
  printf("\n"); \
  printf("Results: %d passed, %d failed\n", _test_passes, _test_failures); \
  return _test_failures > 0 ? 1 : 0; \
} while(0)

#endif /* TEST_HARNESS_H */
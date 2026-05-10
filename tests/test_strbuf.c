/*
 * test_strbuf.c - Tests for op_strbuf_t dynamic string buffer
 */

#include "test_harness.h"
#include <op_lib.h>

/* Tests */

TEST(strbuf_init_empty) {
    op_strbuf_t sb;
    op_strbuf_init(&sb);

    ASSERT_STR_EQ(op_strbuf_str(&sb), "");
    ASSERT_EQ(op_strbuf_len(&sb), 0);
    ASSERT_TRUE(op_strbuf_empty(&sb));

    op_strbuf_free(&sb);
}

TEST(strbuf_appendf_basic) {
    op_strbuf_t sb;
    op_strbuf_init(&sb);
    op_strbuf_appendf(&sb, "Hello %s", "World");

    ASSERT_STR_EQ(op_strbuf_str(&sb), "Hello World");
    ASSERT_EQ(op_strbuf_len(&sb), 11);
    ASSERT_FALSE(op_strbuf_empty(&sb));

    op_strbuf_free(&sb);
}

TEST(strbuf_appendf_multiple) {
    op_strbuf_t sb;
    op_strbuf_init(&sb);

    op_strbuf_appendf(&sb, "Hello");
    op_strbuf_appendf(&sb, " %s", "World");
    op_strbuf_appendf(&sb, "!");

    ASSERT_STR_EQ(op_strbuf_str(&sb), "Hello World!");
    ASSERT_EQ(op_strbuf_len(&sb), 12);

    op_strbuf_free(&sb);
}

TEST(strbuf_append_cstr) {
    op_strbuf_t sb;
    op_strbuf_init(&sb);

    op_strbuf_append_cstr(&sb, "First");
    op_strbuf_append_cstr(&sb, " Second");

    ASSERT_STR_EQ(op_strbuf_str(&sb), "First Second");
    ASSERT_EQ(op_strbuf_len(&sb), 12);

    op_strbuf_free(&sb);
}

TEST(strbuf_clear_reuse) {
    op_strbuf_t sb;
    op_strbuf_init(&sb);

    op_strbuf_appendf(&sb, "First content");
    ASSERT_STR_EQ(op_strbuf_str(&sb), "First content");

    op_strbuf_clear(&sb);
    op_strbuf_appendf(&sb, "New %s", "content");
    ASSERT_STR_EQ(op_strbuf_str(&sb), "New content");
    ASSERT_EQ(op_strbuf_len(&sb), 11);

    op_strbuf_free(&sb);
}

TEST(strbuf_steal_transfers_ownership) {
    op_strbuf_t sb;
    op_strbuf_init(&sb);
    op_strbuf_appendf(&sb, "Test string");

    char *stolen = op_strbuf_steal(&sb);
    ASSERT_STR_EQ(stolen, "Test string");

    ASSERT_STR_EQ(op_strbuf_str(&sb), "");
    ASSERT_EQ(op_strbuf_len(&sb), 0);

    op_free(stolen);
    op_strbuf_free(&sb);
}

TEST(strbuf_sso_short_string) {
    op_strbuf_t sb;
    op_strbuf_init(&sb);

    op_strbuf_append_cstr(&sb, "Short");

    ASSERT_EQ(sb.ptr, sb.buf);
    ASSERT_STR_EQ(op_strbuf_str(&sb), "Short");

    op_strbuf_free(&sb);
}

TEST(strbuf_grow_beyond_sso) {
    op_strbuf_t sb;
    op_strbuf_init(&sb);

    const char *pattern = "This is a somewhat long string that will be repeated multiple times to exceed the SSO capacity. ";

    for (int i = 0; i < 3; i++) {
        op_strbuf_append_cstr(&sb, pattern);
    }

    ASSERT_NEQ(sb.ptr, sb.buf);
    ASSERT_TRUE(op_strbuf_len(&sb) > OP_STRBUF_INLINE_CAP);

    op_strbuf_free(&sb);
}

TEST(strbuf_appendc_single_char) {
    op_strbuf_t sb;
    op_strbuf_init(&sb);

    op_strbuf_appendc(&sb, 'A');
    op_strbuf_appendc(&sb, 'B');
    op_strbuf_appendc(&sb, 'C');

    ASSERT_STR_EQ(op_strbuf_str(&sb), "ABC");
    ASSERT_EQ(op_strbuf_len(&sb), 3);

    op_strbuf_free(&sb);
}

TEST(strbuf_clear_resets_content) {
    op_strbuf_t sb;
    op_strbuf_init(&sb);
    op_strbuf_appendf(&sb, "Initial content");

    op_strbuf_clear(&sb);
    ASSERT_STR_EQ(op_strbuf_str(&sb), "");
    ASSERT_EQ(op_strbuf_len(&sb), 0);
    ASSERT_TRUE(op_strbuf_empty(&sb));

    op_strbuf_free(&sb);
}

int main(void) {
    TEST_MAIN_BEGIN;

    RUN_TEST(strbuf_init_empty);
    RUN_TEST(strbuf_appendf_basic);
    RUN_TEST(strbuf_appendf_multiple);
    RUN_TEST(strbuf_append_cstr);
    RUN_TEST(strbuf_clear_reuse);
    RUN_TEST(strbuf_steal_transfers_ownership);
    RUN_TEST(strbuf_sso_short_string);
    RUN_TEST(strbuf_grow_beyond_sso);
    RUN_TEST(strbuf_appendc_single_char);
    RUN_TEST(strbuf_clear_resets_content);

    TEST_MAIN_END;
}

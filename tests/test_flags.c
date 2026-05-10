/*
 * test_flags.c - Tests for flag constant values and basic flag logic
 */

#include "test_harness.h"
#include <stdint.h>

/* Include flag constants */
#include "../src/flags.h"

/* Tests for flag constant values */

TEST(user_flag_constants) {
    /* Test that important user flags have expected values */
    ASSERT_EQ(USER_AUTOOP, 0x00000001);
    ASSERT_EQ(USER_BOT, 0x00000002);
    ASSERT_EQ(USER_MASTER, 0x00001000);
    ASSERT_EQ(USER_OWNER, 0x00002000);
    ASSERT_EQ(USER_OP, 0x00004000);
}

TEST(bot_flag_constants) {
    /* Test bot flag values */
    ASSERT_EQ(BOT_ALT, 0x00000001);
    ASSERT_EQ(BOT_SHBAN, 0x00000002);
    ASSERT_EQ(BOT_HUB, 0x00000080);
    ASSERT_EQ(BOT_LEAF, 0x00000800);
    ASSERT_EQ(BOT_AGGRESSIVE, 0x00040000);
}

TEST(chan_flag_constants) {
    /* Test channel flag constants exist and have unique values */
    ASSERT_NEQ(USER_AUTOOP, USER_DEOP);
    ASSERT_NEQ(USER_VOICE, USER_QUIET);
    ASSERT_NEQ(USER_HALFOP, USER_DEHALFOP);
}

TEST(flag_validation_constants) {
    /* Test the validation bitmasks */
    ASSERT_TRUE(USER_VALID != 0);
    ASSERT_TRUE(CHAN_VALID != 0);
    ASSERT_TRUE(BOT_VALID != 0);

    /* Verify some basic flags are included in validation masks */
    ASSERT_TRUE((USER_VALID & USER_AUTOOP) != 0);
    ASSERT_TRUE((USER_VALID & USER_MASTER) != 0);
    ASSERT_TRUE((USER_VALID & USER_OP) != 0);
}

TEST(flag_record_types) {
    /* Test flag record type constants */
    ASSERT_EQ(FR_GLOBAL, 0x00000001);
    ASSERT_EQ(FR_BOT, 0x00000002);
    ASSERT_EQ(FR_CHAN, 0x00000004);
    ASSERT_EQ(FR_OR, 0x40000000);
    ASSERT_EQ(FR_AND, 0x20000000);
}

TEST(bot_sharing_flags) {
    /* Test bot sharing flag combinations */
    ASSERT_TRUE((BOT_SHPERMS & BOT_SHBAN) != 0);
    ASSERT_TRUE((BOT_SHPERMS & BOT_SHCHAN) != 0);
    ASSERT_TRUE((BOT_SHPERMS & BOT_SHEXEMPT) != 0);
    ASSERT_TRUE((BOT_SHARE & BOT_AGGRESSIVE) != 0);
}

TEST(flag_macro_consistency) {
    /* Create a test flag record */
    struct flag_record fr = {0};
    fr.global = USER_OP | USER_MASTER;
    fr.chan = USER_VOICE | USER_AUTOOP;

    /* Test flag checking macros work as expected */
    ASSERT_TRUE(glob_op(fr));
    ASSERT_TRUE(glob_master(fr));
    ASSERT_FALSE(glob_bot(fr));
    ASSERT_FALSE(glob_owner(fr));

    ASSERT_TRUE(chan_voice(fr));
    ASSERT_TRUE(chan_autoop(fr));
    ASSERT_FALSE(chan_op(fr));
}

TEST(flag_combinations) {
    /* Test that flags can be combined correctly */
    int combined = USER_AUTOOP | USER_VOICE;
    ASSERT_TRUE((combined & USER_AUTOOP) != 0);
    ASSERT_TRUE((combined & USER_VOICE) != 0);
    ASSERT_FALSE((combined & USER_OP) != 0);

    /* Test bot flag combinations */
    intptr_t bot_flags = BOT_HUB | BOT_AGGRESSIVE;
    ASSERT_TRUE((bot_flags & BOT_HUB) != 0);
    ASSERT_TRUE((bot_flags & BOT_AGGRESSIVE) != 0);
    ASSERT_FALSE((bot_flags & BOT_LEAF) != 0);
}

TEST(sanity_check_constants) {
    /* Test sanity check message ID constants exist */
    ASSERT_TRUE(BOT_SANE_ALTOWNSHUB != 0);
    ASSERT_TRUE(UC_SANE_DEOPOWNSOP != 0);
    ASSERT_TRUE(UC_SANE_MASTERADDSOP != 0);

    /* Verify they are unique */
    ASSERT_NEQ(BOT_SANE_ALTOWNSHUB, BOT_SANE_HUBOWNSALT);
    ASSERT_NEQ(UC_SANE_DEOPOWNSOP, UC_SANE_OPOWNSDEOP);
}

TEST(flag_bit_positions) {
    /* Verify flags are at expected bit positions (powers of 2) */
    ASSERT_EQ(USER_AUTOOP & (USER_AUTOOP - 1), 0); /* Power of 2 check */
    ASSERT_EQ(USER_BOT & (USER_BOT - 1), 0);
    ASSERT_EQ(USER_MASTER & (USER_MASTER - 1), 0);
    ASSERT_EQ(USER_OWNER & (USER_OWNER - 1), 0);

    ASSERT_EQ(BOT_ALT & (BOT_ALT - 1), 0);
    ASSERT_EQ(BOT_HUB & (BOT_HUB - 1), 0);
    ASSERT_EQ(BOT_LEAF & (BOT_LEAF - 1), 0);
}

int main(void) {
    TEST_MAIN_BEGIN;

    RUN_TEST(user_flag_constants);
    RUN_TEST(bot_flag_constants);
    RUN_TEST(chan_flag_constants);
    RUN_TEST(flag_validation_constants);
    RUN_TEST(flag_record_types);
    RUN_TEST(bot_sharing_flags);
    RUN_TEST(flag_macro_consistency);
    RUN_TEST(flag_combinations);
    RUN_TEST(sanity_check_constants);
    RUN_TEST(flag_bit_positions);

    TEST_MAIN_END;
}
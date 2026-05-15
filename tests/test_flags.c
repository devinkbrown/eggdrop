/*
 * test_flags.c - Tests for flag constant values, basic flag logic, and
 *                extracted flag functions from src/flags.c
 *
 * Pure functions are copied here with static linkage to avoid pulling in
 * the entire eggdrop dependency graph (same pattern as test_botmsg.c).
 */

#include "test_harness.h"
#include <stdint.h>

struct userrec;
struct flag_record;

/* Suppress extern prototypes so we can provide static extractions */
#define MAKING_MODS
#include "../src/flags.h"
#undef MAKING_MODS

/* --- Provide egg_bzero used by break_down_flags --- */
#define egg_bzero(dest, len) memset(dest, 0, len)

/* --- Extracted from src/flags.c: sanity_check (line ~243) --- */

static int sanity_check(int atr)
{
  if ((atr & USER_BOT) &&
      (atr & (USER_PARTY | USER_MASTER | USER_COMMON | USER_OWNER)))
    atr &= ~(USER_PARTY | USER_MASTER | USER_COMMON | USER_OWNER);
  if ((atr & USER_OP) && (atr & USER_DEOP))
    atr &= ~(USER_OP | USER_DEOP);
  if ((atr & USER_HALFOP) && (atr & USER_DEHALFOP))
    atr &= ~(USER_HALFOP | USER_DEHALFOP);
  if ((atr & USER_AUTOOP) && (atr & USER_DEOP))
    atr &= ~(USER_AUTOOP | USER_DEOP);
  if ((atr & USER_AUTOHALFOP) && (atr & USER_DEHALFOP))
    atr &= ~(USER_AUTOHALFOP | USER_DEHALFOP);
  if ((atr & USER_VOICE) && (atr & USER_QUIET))
    atr &= ~(USER_VOICE | USER_QUIET);
  if ((atr & USER_GVOICE) && (atr & USER_QUIET))
    atr &= ~(USER_GVOICE | USER_QUIET);
  /* Can't be owner without also being master */
  if (atr & USER_OWNER)
    atr |= USER_MASTER;
  /* Master implies botmaster, op and janitor */
  if (atr & USER_MASTER)
    atr |= USER_BOTMAST | USER_OP | USER_JANITOR;
  /* Can't be botnet master without party-line access */
  if (atr & USER_BOTMAST)
    atr |= USER_PARTY;
  /* Janitors can use the file area */
  if (atr & USER_JANITOR)
    atr |= USER_XFER;
  /* Ops should be halfops */
  if (atr & USER_OP)
    atr |= USER_HALFOP;
  return atr;
}

/* --- Extracted from src/flags.c: break_down_flags (line ~986) --- */

static void break_down_flags(const char *string, struct flag_record *plus,
                      struct flag_record *minus)
{
  struct flag_record *which = plus;
  int mode = 0;                 /* 0 = glob, 1 = chan, 2 = bot */
  int flags = plus->match;

  if (!(flags & FR_GLOBAL)) {
    if (flags & FR_BOT)
      mode = 2;
    else if (flags & FR_CHAN)
      mode = 1;
    else
      return;                   /* We don't actually want any..huh? */
  }
  egg_bzero(plus, sizeof(struct flag_record));

  if (minus)
    egg_bzero(minus, sizeof(struct flag_record));

  plus->match = FR_OR;          /* Default binding type OR */
  while (*string) {
    switch (*string) {
    case '+':
      which = plus;
      break;
    case '-':
      which = minus ? minus : plus;
      break;
    case '|':
    case '&':
      if (!mode) {
        if (*string == '|')
          plus->match = FR_OR;
        else
          plus->match = FR_AND;
      }
      which = plus;
      mode++;
      if ((mode == 2) && !(flags & (FR_CHAN | FR_BOT)))
        goto breakout;
      else if (mode == 3)
        mode = 1;
      break;
    default:
      if ((*string >= 'a') && (*string <= 'z')) {
        switch (mode) {
        case 0:
          which->global |= 1 << (*string - 'a');
          break;
        case 1:
          which->chan |= 1 << (*string - 'a');
          break;
        case 2:
          if (*string <= 'u')
            which->bot |= 1 << (*string - 'a');
        }
      } else if ((*string >= 'A') && (*string <= 'Z')) {
        switch (mode) {
        case 0:
          which->udef_global |= 1 << (*string - 'A');
          break;
        case 1:
          which->udef_chan |= 1 << (*string - 'A');
          break;
        }
      } else if ((*string >= '0') && (*string <= '9')) {
        switch (mode) {
          /* Map 0->9 to A->K for glob/chan so they are not lost */
        case 0:
          which->udef_global |= 1 << (*string - '0');
          break;
        case 1:
          which->udef_chan |= 1 << (*string - '0');
          break;
        case 2:
          which->bot |= BOT_FLAG0 << (*string - '0');
          break;
        }
      }
    }
    string++;
  }
breakout:
  for (which = plus; which; which = (which == plus ? minus : NULL)) {
    which->global &= USER_VALID;
    which->udef_global &= 0x03ffffff;
    which->chan &= CHAN_VALID;
    which->udef_chan &= 0x03ffffff;
    which->bot &= BOT_VALID;
  }
  plus->match |= flags;
  if (minus) {
    minus->match |= flags;
    if (!(plus->match & (FR_AND | FR_OR)))
      plus->match |= FR_OR;
  }
}

/* --- Extracted from src/flags.c: flagrec_eq (line ~1223) --- */

static int flagrec_eq(struct flag_record *req, struct flag_record *have)
{
  if (req->match & FR_AND) {
    if (req->match & FR_GLOBAL) {
      if ((req->global & have->global) != req->global)
        return 0;
      if ((req->udef_global & have->udef_global) != req->udef_global)
        return 0;
    }
    if (req->match & FR_BOT)
      if ((req->bot & have->bot) != req->bot)
        return 0;
    if (req->match & FR_CHAN) {
      if ((req->chan & have->chan) != req->chan)
        return 0;
      if ((req->udef_chan & have->udef_chan) != req->udef_chan)
        return 0;
    }
    return 1;
  } else if (req->match & FR_OR) {
    if (!req->chan && !req->global && !req->udef_chan &&
        !req->udef_global && !req->bot)
      return 1;
    if (req->match & FR_GLOBAL) {
      if (have->global & req->global)
        return 1;
      if (have->udef_global & req->udef_global)
        return 1;
    }
    if (req->match & FR_BOT)
      if (have->bot & req->bot)
        return 1;
    if (req->match & FR_CHAN) {
      if (have->chan & req->chan)
        return 1;
      if (have->udef_chan & req->udef_chan)
        return 1;
    }
    return 0;
  }
  return 0;                     /* fr0k3 binding, don't pass it */
}


/* ====================================================================
 * Tests for flag constant values (existing tests)
 * ==================================================================== */

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


/* ====================================================================
 * Tests for sanity_check()
 * ==================================================================== */

TEST(sanity_check_zero) {
    /* Zero flags in, zero flags out */
    ASSERT_EQ(sanity_check(0), 0);
}

TEST(sanity_check_passthrough) {
    /* A plain USER_FRIEND flag should pass through unchanged */
    ASSERT_EQ(sanity_check(USER_FRIEND), USER_FRIEND);

    /* USER_PARTY alone should pass through */
    ASSERT_EQ(sanity_check(USER_PARTY), USER_PARTY);
}

TEST(sanity_check_bot_strips_master) {
    /* BOT + MASTER: strips MASTER, PARTY, COMMON, OWNER */
    int result = sanity_check(USER_BOT | USER_MASTER);
    ASSERT_FALSE(result & USER_MASTER);
    ASSERT_FALSE(result & USER_PARTY);
    ASSERT_FALSE(result & USER_COMMON);
    ASSERT_FALSE(result & USER_OWNER);
    ASSERT_TRUE(result & USER_BOT);
}

TEST(sanity_check_bot_strips_owner) {
    /* BOT + OWNER: strips OWNER (and MASTER, PARTY, COMMON) */
    int result = sanity_check(USER_BOT | USER_OWNER);
    ASSERT_FALSE(result & USER_OWNER);
    ASSERT_FALSE(result & USER_MASTER);
    ASSERT_TRUE(result & USER_BOT);
}

TEST(sanity_check_bot_strips_party) {
    /* BOT + PARTY: strips PARTY */
    int result = sanity_check(USER_BOT | USER_PARTY);
    ASSERT_FALSE(result & USER_PARTY);
    ASSERT_TRUE(result & USER_BOT);
}

TEST(sanity_check_op_deop_conflict) {
    /* OP + DEOP: both get stripped */
    int result = sanity_check(USER_OP | USER_DEOP);
    ASSERT_FALSE(result & USER_OP);
    ASSERT_FALSE(result & USER_DEOP);
}

TEST(sanity_check_halfop_dehalfop_conflict) {
    /* HALFOP + DEHALFOP: both get stripped */
    int result = sanity_check(USER_HALFOP | USER_DEHALFOP);
    ASSERT_FALSE(result & USER_HALFOP);
    ASSERT_FALSE(result & USER_DEHALFOP);
}

TEST(sanity_check_autoop_deop_conflict) {
    /* AUTOOP + DEOP: both get stripped */
    int result = sanity_check(USER_AUTOOP | USER_DEOP);
    ASSERT_FALSE(result & USER_AUTOOP);
    ASSERT_FALSE(result & USER_DEOP);
}

TEST(sanity_check_autohalfop_dehalfop_conflict) {
    /* AUTOHALFOP + DEHALFOP: both get stripped */
    int result = sanity_check(USER_AUTOHALFOP | USER_DEHALFOP);
    ASSERT_FALSE(result & USER_AUTOHALFOP);
    ASSERT_FALSE(result & USER_DEHALFOP);
}

TEST(sanity_check_voice_quiet_conflict) {
    /* VOICE + QUIET: both get stripped */
    int result = sanity_check(USER_VOICE | USER_QUIET);
    ASSERT_FALSE(result & USER_VOICE);
    ASSERT_FALSE(result & USER_QUIET);
}

TEST(sanity_check_gvoice_quiet_conflict) {
    /* GVOICE + QUIET: both get stripped */
    int result = sanity_check(USER_GVOICE | USER_QUIET);
    ASSERT_FALSE(result & USER_GVOICE);
    ASSERT_FALSE(result & USER_QUIET);
}

TEST(sanity_check_owner_implies_master) {
    /* OWNER should imply MASTER (and master's implications cascade) */
    int result = sanity_check(USER_OWNER);
    ASSERT_TRUE(result & USER_OWNER);
    ASSERT_TRUE(result & USER_MASTER);
    /* Master implies BOTMAST, OP, JANITOR */
    ASSERT_TRUE(result & USER_BOTMAST);
    ASSERT_TRUE(result & USER_OP);
    ASSERT_TRUE(result & USER_JANITOR);
    /* BOTMAST implies PARTY */
    ASSERT_TRUE(result & USER_PARTY);
    /* JANITOR implies XFER */
    ASSERT_TRUE(result & USER_XFER);
    /* OP implies HALFOP */
    ASSERT_TRUE(result & USER_HALFOP);
}

TEST(sanity_check_master_implies_chain) {
    /* MASTER implies BOTMAST + OP + JANITOR, which cascade further */
    int result = sanity_check(USER_MASTER);
    ASSERT_TRUE(result & USER_MASTER);
    ASSERT_TRUE(result & USER_BOTMAST);
    ASSERT_TRUE(result & USER_OP);
    ASSERT_TRUE(result & USER_JANITOR);
    ASSERT_TRUE(result & USER_PARTY);    /* from BOTMAST */
    ASSERT_TRUE(result & USER_XFER);     /* from JANITOR */
    ASSERT_TRUE(result & USER_HALFOP);   /* from OP */
}

TEST(sanity_check_botmast_implies_party) {
    int result = sanity_check(USER_BOTMAST);
    ASSERT_TRUE(result & USER_BOTMAST);
    ASSERT_TRUE(result & USER_PARTY);
}

TEST(sanity_check_janitor_implies_xfer) {
    int result = sanity_check(USER_JANITOR);
    ASSERT_TRUE(result & USER_JANITOR);
    ASSERT_TRUE(result & USER_XFER);
}

TEST(sanity_check_op_implies_halfop) {
    int result = sanity_check(USER_OP);
    ASSERT_TRUE(result & USER_OP);
    ASSERT_TRUE(result & USER_HALFOP);
}


/* ====================================================================
 * Tests for break_down_flags()
 * ==================================================================== */

TEST(break_down_flags_empty_string) {
    /* Empty string should leave both records zeroed (except match metadata) */
    struct flag_record plus = { .match = FR_GLOBAL };
    struct flag_record minus = {0};
    break_down_flags("", &plus, &minus);
    ASSERT_EQ(plus.global, 0);
    ASSERT_EQ(plus.chan, 0);
    ASSERT_EQ(minus.global, 0);
    ASSERT_EQ(minus.chan, 0);
}

TEST(break_down_flags_plus_o) {
    /* "+o" should set USER_OP in plus->global */
    struct flag_record plus = { .match = FR_GLOBAL };
    struct flag_record minus = {0};
    break_down_flags("+o", &plus, &minus);
    ASSERT_TRUE(plus.global & USER_OP);
    ASSERT_EQ(minus.global, 0);
}

TEST(break_down_flags_minus_d) {
    /* "-d" should set USER_DEOP in minus->global */
    struct flag_record plus = { .match = FR_GLOBAL };
    struct flag_record minus = {0};
    break_down_flags("-d", &plus, &minus);
    ASSERT_EQ(plus.global, 0);
    ASSERT_TRUE(minus.global & USER_DEOP);
}

TEST(break_down_flags_plus_m) {
    /* "+m" should set USER_MASTER in plus->global */
    struct flag_record plus = { .match = FR_GLOBAL };
    struct flag_record minus = {0};
    break_down_flags("+m", &plus, &minus);
    ASSERT_TRUE(plus.global & USER_MASTER);
}

TEST(break_down_flags_combined_plus_minus) {
    /* "+o-d" should set OP in plus, DEOP in minus */
    struct flag_record plus = { .match = FR_GLOBAL };
    struct flag_record minus = {0};
    break_down_flags("+o-d", &plus, &minus);
    ASSERT_TRUE(plus.global & USER_OP);
    ASSERT_TRUE(minus.global & USER_DEOP);
}

TEST(break_down_flags_multiple_plus) {
    /* "+omn" should set OP, MASTER, OWNER in plus->global */
    struct flag_record plus = { .match = FR_GLOBAL };
    struct flag_record minus = {0};
    break_down_flags("+omn", &plus, &minus);
    ASSERT_TRUE(plus.global & USER_OP);
    ASSERT_TRUE(plus.global & USER_MASTER);
    ASSERT_TRUE(plus.global & USER_OWNER);
}

TEST(break_down_flags_pipe_channel) {
    /* "|+o" (pipe switches to channel mode) should set OP in plus->chan */
    struct flag_record plus = { .match = FR_GLOBAL | FR_CHAN };
    struct flag_record minus = {0};
    break_down_flags("|+o", &plus, &minus);
    ASSERT_EQ(plus.global, 0);
    ASSERT_TRUE(plus.chan & USER_OP);
}

TEST(break_down_flags_global_and_channel) {
    /* "+m|+o" should set MASTER globally and OP in channel */
    struct flag_record plus = { .match = FR_GLOBAL | FR_CHAN };
    struct flag_record minus = {0};
    break_down_flags("+m|+o", &plus, &minus);
    ASSERT_TRUE(plus.global & USER_MASTER);
    ASSERT_TRUE(plus.chan & USER_OP);
}

TEST(break_down_flags_no_plus_prefix) {
    /* "o" without a '+' should still set OP (defaults to plus in global mode) */
    struct flag_record plus = { .match = FR_GLOBAL };
    struct flag_record minus = {0};
    break_down_flags("o", &plus, &minus);
    ASSERT_TRUE(plus.global & USER_OP);
}

TEST(break_down_flags_null_minus) {
    /* NULL minus record: '-d' goes to plus instead */
    struct flag_record plus = { .match = FR_GLOBAL };
    break_down_flags("+o-d", &plus, NULL);
    ASSERT_TRUE(plus.global & USER_OP);
    ASSERT_TRUE(plus.global & USER_DEOP);
}

TEST(break_down_flags_and_match) {
    /* "&" should set FR_AND on plus->match */
    struct flag_record plus = { .match = FR_GLOBAL | FR_CHAN };
    struct flag_record minus = {0};
    break_down_flags("+o&+m", &plus, &minus);
    ASSERT_TRUE(plus.match & FR_AND);
    ASSERT_TRUE(plus.global & USER_OP);
    ASSERT_TRUE(plus.chan & USER_MASTER);
}

TEST(break_down_flags_bot_mode) {
    /* Bot mode: FR_BOT without FR_GLOBAL starts in mode 2 */
    struct flag_record plus = { .match = FR_BOT };
    struct flag_record minus = {0};
    break_down_flags("+h", &plus, &minus);
    ASSERT_TRUE(plus.bot & BOT_HUB);
}

TEST(break_down_flags_udef_uppercase) {
    /* Uppercase letters set udef_global */
    struct flag_record plus = { .match = FR_GLOBAL };
    struct flag_record minus = {0};
    break_down_flags("+A", &plus, &minus);
    ASSERT_TRUE(plus.udef_global & (1 << 0)); /* 'A' - 'A' = 0 */
}

TEST(break_down_flags_validity_mask) {
    /* Flags should be masked by USER_VALID after parsing */
    struct flag_record plus = { .match = FR_GLOBAL };
    struct flag_record minus = {0};
    /* 'i' and 's' are unused user flags, but 'i' (bit 8) is USER_I which
     * IS in USER_VALID; 's' (bit 18) is USER_S which IS in USER_VALID.
     * All lowercase letters a-z map to bits 0-25; USER_VALID masks some out.
     * The point is the global field gets ANDed with USER_VALID. */
    break_down_flags("+o", &plus, &minus);
    /* Result should only contain valid flags */
    ASSERT_EQ(plus.global & ~(int)USER_VALID, 0);
}


/* ====================================================================
 * Tests for flagrec_eq()
 * ==================================================================== */

TEST(flagrec_eq_or_empty_req) {
    /* OR mode: empty requirement matches anything */
    struct flag_record req = { .match = FR_GLOBAL | FR_OR };
    struct flag_record have = { .match = FR_GLOBAL | FR_OR, .global = USER_OP };
    ASSERT_EQ(flagrec_eq(&req, &have), 1);
}

TEST(flagrec_eq_or_global_match) {
    /* OR mode: have has the required global flag */
    struct flag_record req = { .match = FR_GLOBAL | FR_OR, .global = USER_OP };
    struct flag_record have = { .match = FR_GLOBAL | FR_OR,
                                .global = USER_OP | USER_MASTER };
    ASSERT_EQ(flagrec_eq(&req, &have), 1);
}

TEST(flagrec_eq_or_global_no_match) {
    /* OR mode: have does NOT have the required global flag */
    struct flag_record req = { .match = FR_GLOBAL | FR_OR, .global = USER_OP };
    struct flag_record have = { .match = FR_GLOBAL | FR_OR,
                                .global = USER_MASTER };
    ASSERT_EQ(flagrec_eq(&req, &have), 0);
}

TEST(flagrec_eq_or_chan_match) {
    /* OR mode: channel flag matches */
    struct flag_record req = { .match = FR_CHAN | FR_OR, .chan = USER_OP };
    struct flag_record have = { .match = FR_CHAN | FR_OR,
                                .chan = USER_OP | USER_VOICE };
    ASSERT_EQ(flagrec_eq(&req, &have), 1);
}

TEST(flagrec_eq_or_chan_no_match) {
    /* OR mode: channel flag does not match */
    struct flag_record req = { .match = FR_CHAN | FR_OR, .chan = USER_OP };
    struct flag_record have = { .match = FR_CHAN | FR_OR, .chan = USER_VOICE };
    ASSERT_EQ(flagrec_eq(&req, &have), 0);
}

TEST(flagrec_eq_or_global_or_chan) {
    /* OR mode with both FR_GLOBAL|FR_CHAN: match if EITHER hits */
    struct flag_record req = { .match = FR_GLOBAL | FR_CHAN | FR_OR,
                               .global = USER_OP, .chan = USER_MASTER };
    /* Have only the channel flag */
    struct flag_record have = { .match = FR_GLOBAL | FR_CHAN | FR_OR,
                                .global = 0, .chan = USER_MASTER };
    ASSERT_EQ(flagrec_eq(&req, &have), 1);
}

TEST(flagrec_eq_and_global_match) {
    /* AND mode: have has ALL the required global flags */
    struct flag_record req = { .match = FR_GLOBAL | FR_AND,
                               .global = USER_OP | USER_MASTER };
    struct flag_record have = { .match = FR_GLOBAL | FR_AND,
                                .global = USER_OP | USER_MASTER | USER_FRIEND };
    ASSERT_EQ(flagrec_eq(&req, &have), 1);
}

TEST(flagrec_eq_and_global_partial) {
    /* AND mode: have only has one of the two required flags -- fail */
    struct flag_record req = { .match = FR_GLOBAL | FR_AND,
                               .global = USER_OP | USER_MASTER };
    struct flag_record have = { .match = FR_GLOBAL | FR_AND,
                                .global = USER_OP };
    ASSERT_EQ(flagrec_eq(&req, &have), 0);
}

TEST(flagrec_eq_and_chan_match) {
    /* AND mode: channel flags must all be present */
    struct flag_record req = { .match = FR_CHAN | FR_AND,
                               .chan = USER_OP | USER_VOICE };
    struct flag_record have = { .match = FR_CHAN | FR_AND,
                                .chan = USER_OP | USER_VOICE | USER_FRIEND };
    ASSERT_EQ(flagrec_eq(&req, &have), 1);
}

TEST(flagrec_eq_and_chan_partial) {
    /* AND mode: missing one required channel flag */
    struct flag_record req = { .match = FR_CHAN | FR_AND,
                               .chan = USER_OP | USER_VOICE };
    struct flag_record have = { .match = FR_CHAN | FR_AND,
                                .chan = USER_OP };
    ASSERT_EQ(flagrec_eq(&req, &have), 0);
}

TEST(flagrec_eq_bot_or_match) {
    /* OR mode: bot flag matches */
    struct flag_record req = { .match = FR_BOT | FR_OR, .bot = BOT_HUB };
    struct flag_record have = { .match = FR_BOT | FR_OR,
                                .bot = BOT_HUB | BOT_LEAF };
    ASSERT_EQ(flagrec_eq(&req, &have), 1);
}

TEST(flagrec_eq_bot_and_match) {
    /* AND mode: all required bot flags present */
    struct flag_record req = { .match = FR_BOT | FR_AND,
                               .bot = BOT_HUB | BOT_AGGRESSIVE };
    struct flag_record have = { .match = FR_BOT | FR_AND,
                                .bot = BOT_HUB | BOT_AGGRESSIVE | BOT_LEAF };
    ASSERT_EQ(flagrec_eq(&req, &have), 1);
}

TEST(flagrec_eq_bot_and_partial) {
    /* AND mode: missing one required bot flag */
    struct flag_record req = { .match = FR_BOT | FR_AND,
                               .bot = BOT_HUB | BOT_AGGRESSIVE };
    struct flag_record have = { .match = FR_BOT | FR_AND, .bot = BOT_HUB };
    ASSERT_EQ(flagrec_eq(&req, &have), 0);
}

TEST(flagrec_eq_no_match_type) {
    /* Neither FR_AND nor FR_OR set: should return 0 (broken binding) */
    struct flag_record req = { .match = FR_GLOBAL, .global = USER_OP };
    struct flag_record have = { .match = FR_GLOBAL, .global = USER_OP };
    ASSERT_EQ(flagrec_eq(&req, &have), 0);
}

TEST(flagrec_eq_udef_or_match) {
    /* OR mode: udef_global matches */
    struct flag_record req = { .match = FR_GLOBAL | FR_OR,
                               .udef_global = (1 << 0) };
    struct flag_record have = { .match = FR_GLOBAL | FR_OR,
                                .udef_global = (1 << 0) | (1 << 3) };
    ASSERT_EQ(flagrec_eq(&req, &have), 1);
}

TEST(flagrec_eq_udef_and_match) {
    /* AND mode: udef_global must all be present */
    struct flag_record req = { .match = FR_GLOBAL | FR_AND,
                               .udef_global = (1 << 0) | (1 << 2) };
    struct flag_record have = { .match = FR_GLOBAL | FR_AND,
                                .udef_global = (1 << 0) };
    ASSERT_EQ(flagrec_eq(&req, &have), 0);
}


/* ====================================================================
 * main
 * ==================================================================== */

int main(void) {
    TEST_MAIN_BEGIN;

    /* Constant tests */
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

    /* sanity_check() tests */
    RUN_TEST(sanity_check_zero);
    RUN_TEST(sanity_check_passthrough);
    RUN_TEST(sanity_check_bot_strips_master);
    RUN_TEST(sanity_check_bot_strips_owner);
    RUN_TEST(sanity_check_bot_strips_party);
    RUN_TEST(sanity_check_op_deop_conflict);
    RUN_TEST(sanity_check_halfop_dehalfop_conflict);
    RUN_TEST(sanity_check_autoop_deop_conflict);
    RUN_TEST(sanity_check_autohalfop_dehalfop_conflict);
    RUN_TEST(sanity_check_voice_quiet_conflict);
    RUN_TEST(sanity_check_gvoice_quiet_conflict);
    RUN_TEST(sanity_check_owner_implies_master);
    RUN_TEST(sanity_check_master_implies_chain);
    RUN_TEST(sanity_check_botmast_implies_party);
    RUN_TEST(sanity_check_janitor_implies_xfer);
    RUN_TEST(sanity_check_op_implies_halfop);

    /* break_down_flags() tests */
    RUN_TEST(break_down_flags_empty_string);
    RUN_TEST(break_down_flags_plus_o);
    RUN_TEST(break_down_flags_minus_d);
    RUN_TEST(break_down_flags_plus_m);
    RUN_TEST(break_down_flags_combined_plus_minus);
    RUN_TEST(break_down_flags_multiple_plus);
    RUN_TEST(break_down_flags_pipe_channel);
    RUN_TEST(break_down_flags_global_and_channel);
    RUN_TEST(break_down_flags_no_plus_prefix);
    RUN_TEST(break_down_flags_null_minus);
    RUN_TEST(break_down_flags_and_match);
    RUN_TEST(break_down_flags_bot_mode);
    RUN_TEST(break_down_flags_udef_uppercase);
    RUN_TEST(break_down_flags_validity_mask);

    /* flagrec_eq() tests */
    RUN_TEST(flagrec_eq_or_empty_req);
    RUN_TEST(flagrec_eq_or_global_match);
    RUN_TEST(flagrec_eq_or_global_no_match);
    RUN_TEST(flagrec_eq_or_chan_match);
    RUN_TEST(flagrec_eq_or_chan_no_match);
    RUN_TEST(flagrec_eq_or_global_or_chan);
    RUN_TEST(flagrec_eq_and_global_match);
    RUN_TEST(flagrec_eq_and_global_partial);
    RUN_TEST(flagrec_eq_and_chan_match);
    RUN_TEST(flagrec_eq_and_chan_partial);
    RUN_TEST(flagrec_eq_bot_or_match);
    RUN_TEST(flagrec_eq_bot_and_match);
    RUN_TEST(flagrec_eq_bot_and_partial);
    RUN_TEST(flagrec_eq_no_match_type);
    RUN_TEST(flagrec_eq_udef_or_match);
    RUN_TEST(flagrec_eq_udef_and_match);

    TEST_MAIN_END;
}
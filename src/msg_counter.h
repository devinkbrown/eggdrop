/*
 * msg_counter.h -- per-channel PRIVMSG rate counter for perf testing.
 *
 * Counts incoming channel messages using op_htab.  Hooked into gotmsg
 * (irc.mod) for counting and HOOK_MINUTELY for stats logging.
 *
 * Copyright (C) 2026 Eggheads Development Team
 */

#ifndef _EGG_MSG_COUNTER_H
#define _EGG_MSG_COUNTER_H

#include <stddef.h>

/* Call once at startup to initialise the counter table. */
void msg_counter_init(void);

/* Increment the counter for channel dname and add msglen to the byte tally.
 * Safe to call from the main thread at any time after msg_counter_init(). */
void msg_counter_record(const char *dname, size_t msglen);

/* HOOK_MINUTELY handler: logs [MSGRATE] lines to LOG_MISC and resets the
 * per-interval counters.  Register with
 *   add_hook(HOOK_MINUTELY, (Function)msg_counter_minutely). */
void msg_counter_minutely(void);

/* Release all resources (called from module unload). */
void msg_counter_free(void);

#endif /* _EGG_MSG_COUNTER_H */

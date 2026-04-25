/*
 * libop/src/op_memory.c — out-of-memory handler for eggdrop's libop subset.
 *
 * This replaces the ophion version which calls op_lib_restart() (IRC-server
 * specific).  Eggdrop simply writes to stderr and aborts.
 *
 * Copyright (C) 2024-2026 Ophion IRC Daemon contributors
 * GPL-2.0-or-later
 */

#include <libop_config.h>
#include <op_lib.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>

__attribute__((cold, noreturn))
void
op_outofmemory(void)
{
	static atomic_int in_flight = 0;

	/* Only the first caller prints; the rest abort immediately. */
	if (atomic_exchange(&in_flight, 1) != 0)
		abort();

	fputs("eggdrop libop: out of memory\n", stderr);
	abort();
}

/*
 * msgcounter.h -- part of msgcounter.mod
 *   Public header for the per-channel PRIVMSG rate counter module.
 *
 * Copyright (C) 2026 Eggheads Development Team
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 */

#ifndef _EGG_MOD_MSGCOUNTER_H
#define _EGG_MOD_MSGCOUNTER_H

#include <stdint.h>

/* Function-table indices (after the mandatory 0-3 slots). */
#define MSGCOUNTER_record     4  /* void     (*)(const char *dname, size_t len)  */
#define MSGCOUNTER_get_total  5  /* uint64_t (*)(void)                           */
#define MSGCOUNTER_get_rate   6  /* double   (*)(const char *dname)              */

/* Direct C prototypes — available when MAKING_MSGCOUNTER is defined or
 * when another translation unit links against the module's exported symbols. */
#ifdef MAKING_MSGCOUNTER
uint64_t get_msgcounter_total(void);
double   get_msgcounter_rate(const char *dname);
#endif

#endif /* _EGG_MOD_MSGCOUNTER_H */

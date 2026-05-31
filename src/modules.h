/*
 * modules.h
 *   support for modules in eggdrop
 *
 * by Darrin Smith (beldin@light.iinet.net.au)
 */
/*
 * Copyright (C) 1997 Robey Pointer
 * Copyright (C) 1999 - 2025 Eggheads Development Team
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef _EGG_MODULE_H
#define _EGG_MODULE_H

/* Module related structures
 */
#include "mod/modvals.h"

#ifndef MAKING_NUMMODS

/* Modules specific functions and functions called by Eggdrop */
void do_module_report(int, int, char *);
int module_register(char *, Function *, int, int);
[[nodiscard]] const char *module_load(char *);
[[nodiscard]] char *module_unload(char *, char *);
[[nodiscard]] module_entry *module_find(char *, int, int);
[[nodiscard]] Function *module_depend(char *, char *, int, int);
int module_undepend(char *);
[[nodiscard]] void *mod_malloc(int, const char *, const char *, int);
[[nodiscard]] void *mod_realloc(void *, int, const char *, const char *, int);
void  mod_free(void *, const char *, const char *, int);
[[nodiscard]] char *mod_strdup(const char *, const char *, const char *, int);
void add_hook(int, Function);
void del_hook(int, Function);

/* hook_list: per-hook dynamic vector of Function pointers (via op_vec_t).
 * op_vec_t stores void* elements; Function is cast to/from void* here. */
extern op_vec_t hook_list[REAL_HOOKS];

#define call_hook(x) do {                                               \
        size_t _hi;                                                     \
        void *_hfp;                                                     \
        OP_VEC_FOREACH(&hook_list[x], _hi, _hfp) {                     \
                ((void (*)(void)) _hfp)();                              \
        }                                                               \
} while (0)

#endif

typedef struct _dependancy {
  struct _module_entry *needed;
  struct _module_entry *needing;
  int major;
  int minor;
  int patch;
} dependancy;

/* Load a module dependency with a full semver version requirement string.
 * ver_req has the form "name op major.minor.patch" where op is one of
 * ">=", "==", or ">" (e.g. "server>=1.2.0").  Returns the dependent
 * module's function table on success, NULL on failure. */
[[nodiscard]] Function *module_depend_ver(char *name1, char *ver_req);
extern op_vec_t module_vec;
extern op_vec_t dep_vec;

#endif /* _EGG_MODULE_H */

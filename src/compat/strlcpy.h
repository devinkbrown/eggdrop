/*
 * strlcpy.h — redirect to libop's op_strlcpy.
 *
 * The old compat/strlcpy.c fallback has been retired; op_strlcpy (from
 * op_tools.h, pulled in via op_lib.h) is always available and is the
 * canonical implementation for the entire tree.
 */

#ifndef _EGG_COMPAT_STRLCPY_H_
#define _EGG_COMPAT_STRLCPY_H_

/* op_strlcpy is declared in op_tools.h (included via op_lib.h → main.h).
 * Redirect the bare name so that existing call sites keep compiling.
 */
#define strlcpy  op_strlcpy
#define strlcat  op_strlcat

#endif /* _EGG_COMPAT_STRLCPY_H_ */

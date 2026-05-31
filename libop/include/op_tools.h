/*
 *  ircd-ratbox: A slightly useful ircd.
 *  tools.h: Header for the various tool functions.
 *
 *  Copyright (C) 1990 Jarkko Oikarinen and University of Oulu, Co Center
 *  Copyright (C) 1996-2002 Hybrid Development Team
 *  Copyright (C) 2002-2005 ircd-ratbox development team
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301
 *  USA
 *
 */

#ifndef LIBOP_LIB_H
# error "Do not use tools.h directly"
#endif

#ifndef __TOOLS_H__
#define __TOOLS_H__

OP_PURE OP_NONNULL(1, 2) int op_strcasecmp(const char *s1, const char *s2);
OP_PURE OP_NONNULL(1, 2) int op_strncasecmp(const char *s1, const char *s2, size_t n);
OP_PURE OP_NONNULL(1, 2) char *op_strcasestr(const char *s, const char *find);
OP_NONNULL(1, 2) size_t op_strlcpy(char *dst, const char *src, size_t siz);
OP_NONNULL(1, 2) size_t op_strlcat(char *dst, const char *src, size_t siz);
OP_PURE OP_NONNULL(1) size_t op_strnlen(const char *s, size_t count);
OP_NONNULL(1, 3) int op_snprintf_append(char *str, size_t len, const char *format, ...) AFP(3,4);
OP_NONNULL(1, 3) int op_snprintf_try_append(char *str, size_t len, const char *format, ...) AFP(3,4);

OP_NONNULL(1) char *op_basename(const char *);
OP_NONNULL(1) char *op_dirname(const char *);

int op_string_to_array(char *string, char **parv, int maxpara);




typedef int (*op_strf_func_t)(char *buf, size_t len, void *args);

typedef struct _op_strf {
	size_t length;			/* length limit to apply to this string (and following strings if their length is 0) */
	const char *format;		/* string or format string */
	op_strf_func_t func;		/* function to print to string */
	union {
		va_list *format_args;	/* non-NULL if this is a format string */
		void *func_args;	/* args for a function */
	};
	const struct _op_strf *next;	/* next string to append */
} op_strf_t;

OP_NONNULL(1, 3) int op_fsnprint(char *buf, size_t len, const op_strf_t *strings);
OP_NONNULL(1, 3, 4) int op_fsnprintf(char *buf, size_t len, const op_strf_t *strings, const char *format, ...) AFP(4, 5);


const char *op_path_to_self(void);

#endif /* __TOOLS_H__ */

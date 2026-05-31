/*
 * libop/include/op_subst.h — ${varname} template variable substitution.
 *
 * Ported from ophion ircd/substitution.c (originally charybdis).
 * Expands ${varname} tokens in a format string using a caller-supplied
 * variable list built with op_subst_append_var().
 *
 * Thread-safety: op_subst_parse() writes into a thread-local buffer.
 * Variable list mutation is not thread-safe; build it in one thread.
 */

#ifndef OP_SUBST_H
#define OP_SUBST_H

#include <stddef.h>

/* The maximum length of the expanded output (static thread-local buffer). */
#define OP_SUBST_BUFSIZE 512

/*
 * op_subst_append_var — add a name=value pair to the variable list.
 *
 * `varlist` must be a pointer to an op_vec_t (or NULL-initialised op_vec_t).
 * Copies both `name` and `value`.
 */
void op_subst_append_var(op_vec_t *varlist, const char *name, const char *value);

/*
 * op_subst_free — release all variable entries in `varlist`.
 * Does not free the op_vec_t itself (caller-managed).
 */
void op_subst_free(op_vec_t *varlist);

/*
 * op_subst_parse — expand ${varname} tokens in `fmt` using `varlist`.
 *
 * Returns a pointer to a static thread-local buffer containing the result.
 * The buffer is overwritten on each call from the same thread.
 */
char *op_subst_parse(const char *fmt, op_vec_t *varlist);

#endif /* OP_SUBST_H */

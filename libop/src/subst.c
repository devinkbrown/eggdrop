/*
 * libop/src/subst.c — ${varname} template variable substitution.
 *
 * Ported from ophion ircd/substitution.c (originally charybdis).
 */

#include <libop_config.h>
#include <op_lib.h>
#include <op_subst.h>

#include <string.h>

struct subst_var {
	char *name;
	char *value;
};

void
op_subst_append_var(op_vec_t *varlist, const char *name, const char *value)
{
	struct subst_var *var = op_malloc(sizeof *var);
	var->name  = op_strdup(name);
	var->value = op_strdup(value);
	op_vec_push(varlist, var);
}

void
op_subst_free(op_vec_t *varlist)
{
	for (size_t i = op_vec_size(varlist); i-- > 0; ) {
		struct subst_var *var = op_vec_get(varlist, i);
		op_vec_remove_fast(varlist, i);
		op_free(var->name);
		op_free(var->value);
		op_free(var);
	}
}

char *
op_subst_parse(const char *fmt, op_vec_t *varlist)
{
	static _Thread_local char buf[OP_SUBST_BUFSIZE];
	char *out      = buf;
	const char *end = buf + sizeof buf - 1;

	for (const char *p = fmt; *p != '\0' && out < end; p++) {
		if (*p != '$' || *(p + 1) != '{') {
			*out++ = *p;
			continue;
		}

		char varname[OP_SUBST_BUFSIZE];
		char *vp = varname;
		p += 2; /* skip ${ */

		for (; *p && *p != '}' && *p != '$'; p++) {
			if (vp < &varname[sizeof varname - 1])
				*vp++ = *p;
		}
		*vp = '\0';

		if (*p == '\0')
			break;

		size_t idx; void *elem;
		OP_VEC_FOREACH(varlist, idx, elem) {
			struct subst_var *var = elem;
			if (!op_strcasecmp(varname, var->name)) {
				size_t remain = (size_t)(end - out);
				size_t vlen   = strlen(var->value);
				if (vlen > remain)
					vlen = remain;
				memcpy(out, var->value, vlen);
				out += vlen;
				break;
			}
		}

		if (*p != '}')
			break;
	}

	*out = '\0';
	return buf;
}

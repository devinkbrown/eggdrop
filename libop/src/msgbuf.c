/*
 * libop/src/msgbuf.c — IRC message buffer parsing and serialisation.
 *
 * Ported from ophion ircd/msgbuf.c.
 * Linebuf-cache and server-specific code (me.name, op_strf_t chains,
 * MsgBuf_cache) are not included.
 *
 * Single-pass parser with SIMD-accelerated tag scanning via
 * op_simd_find_delim().
 */

#include <libop_config.h>
#include <op_lib.h>
#include <op_msgbuf.h>

#include <string.h>
#include <stdarg.h>

/* ── IRCv3 tag value escape tables ─────────────────────────────────── */

/* Characters that must be escaped in a tag value (c → escape char). */
static const char tag_escape_table[256] = {
	/*        x0   x1   x2   x3   x4   x5   x6   x7   x8   x9   xA   xB   xC   xD   xE   xF */
	/* 0x00 */ 0,   0,   0,   0,   0,   0,   0,   0,   0,   0,  'n',  0,   0,  'r',  0,   0,
	/* 0x10 */ 0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
	/* 0x20 */'s',  0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
	/* 0x30 */ 0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,  ':',  0,   0,   0,   0,
	/* 0x40 */ 0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
	/* 0x50 */ 0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,  '\\', 0,   0,   0,
};

/* Escape char after '\' → decoded byte (0 = literal). */
static const char tag_unescape_table[256] = {
	/* 0x00 */ 0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
	/* 0x10 */ 0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
	/* 0x20 */ 0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
	/* 0x30 */ 0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,  ';',  0,   0,   0,   0,
	/* 0x40 */ 0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
	/* 0x50 */ 0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,  '\\', 0,   0,   0,
	/* 0x60 */ 0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,  '\n', 0,
	/* 0x70 */ 0,   0,  '\r', 0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
	/* 0x73='s' → ' ' */
};

/* In-place unescape a tag value.  Overwrites the string. */
void
op_msgbuf_unescape_value(char *value)
{
	if (!value)
		return;

	const char *in  = value;
	char       *out = value;

	while (*in != '\0') {
		if (*in != '\\') {
			*out++ = *in++;
			continue;
		}
		in++;
		if (*in == '\0')
			break;

		/* 's' → space; handled inline since table has no room for it
		 * without a static initialiser trick. */
		char decoded;
		if (*in == 's')
			decoded = ' ';
		else
			decoded = tag_unescape_table[(unsigned char)*in];

		*out++ = decoded ? decoded : *in;
		in++;
	}
	*out = '\0';
}

/* ── Parser ─────────────────────────────────────────────────────────── */

int
op_msgbuf_parse(struct op_msgbuf *msgbuf, char *line)
{
	op_msgbuf_init(msgbuf);

	char *ch = line;

	/* IRCv3 message tags (@...) */
	if (*ch == '@') {
		char *tags_start = ch + 1;
		char *tags_end   = NULL;

		const char *tags_limit = tags_start + (OP_MSGBUF_TAGSLEN - 1);
		char *p = (char *)op_simd_find_delim(tags_start, tags_limit, '\0', ' ');

		if (p == tags_limit) {
			char *last_semi = NULL;
			for (char *q = p - 1; q >= tags_start; q--) {
				if (*q == ';') { last_semi = q; break; }
			}
			char *cut = last_semi ? last_semi : p;
			*cut = '\0';
			tags_end = cut;
		} else {
			if (*p == '\0')
				return OP_PARSE_UNTERMINATED_TAGS;
			tags_end = p;
		}

		*tags_end = '\0';
		ch = tags_end + 1;

		char *t    = tags_start;
		char *tend = tags_end;
		while (t < tend) {
			char *key   = t;
			char *value = NULL;

			char *tag_end = (char *)op_simd_find_delim(t, tend, ';', '\0');

			for (char *q = t; q < tag_end; q++) {
				if (*q == '=' && !value) {
					*q    = '\0';
					value = q + 1;
				}
			}

			bool has_next = (tag_end < tend && *tag_end == ';');
			*tag_end = '\0';
			t = tag_end + 1;

			if (*key != '\0') {
				op_msgbuf_unescape_value(value);
				op_msgbuf_append_tag(msgbuf, key, value, 0);
			}
			if (!has_next)
				break;
		}
	}

	/* Truncate to DATALEN */
	{
		const char *limit = ch + OP_MSGBUF_DATALEN;
		char *p = (char *)op_simd_find_delim(ch, limit, '\0', '\0');
		if (p == limit) {
			while (*p != '\0') p++;
			p = (char *)ch + OP_MSGBUF_DATALEN;
			*p = '\0';
		}
	}

	/* Origin prefix */
	if (*ch == ':') {
		ch++;
		msgbuf->origin = ch;

		const char *bufend = ch + OP_MSGBUF_DATALEN;
		char *end = (char *)op_simd_find_delim(ch, bufend, ' ', '\0');
		if (*end == '\0')
			return OP_PARSE_UNTERMINATED_ORIGIN;
		*end = '\0';
		ch   = end + 1;
	}

	if (*ch == '\0')
		return OP_PARSE_NO_COMMAND;

	msgbuf->endp   = ch + strlen(ch);
	msgbuf->n_para = (size_t)op_string_to_array(ch, (char **)msgbuf->para,
	                                              OP_MSGBUF_MAXPARA);
	if (msgbuf->n_para == 0)
		return OP_PARSE_NO_PARAMS;

	msgbuf->cmd = msgbuf->para[0];
	return OP_PARSE_SUCCESS;
}

void
op_msgbuf_reconstruct_tail(struct op_msgbuf *msgbuf, size_t n)
{
	if (!msgbuf->endp || n >= msgbuf->n_para)
		return;

	const char *start = (n == 0)
		? msgbuf->para[0]
		: msgbuf->para[n - 1] + strlen(msgbuf->para[n - 1]) + 1;

	if (n == msgbuf->n_para && start == msgbuf->endp)
		return;

	msgbuf->para[n] = start;
	for (char *p = (char *)start; p < msgbuf->endp; p++) {
		if (*p == '\0')
			*p = ' ';
	}
}

/* ── Serialisation ──────────────────────────────────────────────────── */

static size_t
msgbuf_unparse_tags(char *buf, size_t buflen,
                    const struct op_msgbuf *msgbuf, uint64_t capmask)
{
	const char *const end = &buf[buflen - 2];
	char *output  = buf;
	char *commit  = buf;
	bool  has_tags = false;

	for (size_t i = 0; i < msgbuf->n_tags; i++) {
		const struct op_msg_tag *tag = &msgbuf->tags[i];

		if ((tag->capmask & capmask) == 0)
			continue;
		if (!tag->key || !*tag->key)
			continue;

		const size_t keylen = strlen(tag->key);
		if (output >= end)
			break;
		*output++ = has_tags ? ';' : '@';

		if (output + keylen > end)
			break;
		memcpy(output, tag->key, keylen);
		output += keylen;

		if (tag->value) {
			if (output >= end)
				break;
			*output++ = '=';

			const char  *v    = tag->value;
			const size_t vlen = strlen(v);

			if (output + vlen > end)
				break;

			bool overflow = false;
			for (size_t n = 0; n < vlen; n++) {
				const unsigned char c      = (unsigned char)v[n];
				const char          escape = tag_escape_table[c];
				if (escape) {
					if (output + 2 > end) { overflow = true; break; }
					*output++ = '\\';
					*output++ = escape;
				} else {
					if (output >= end) { overflow = true; break; }
					*output++ = (char)c;
				}
			}
			if (overflow)
				break;
		}

		has_tags = true;
		commit   = output;
	}

	if (has_tags)
		*commit++ = ' ';
	*commit = '\0';
	return (size_t)(commit - buf);
}

int
op_msgbuf_unparse_prefix(char *buf, size_t *buflen,
                          const struct op_msgbuf *msgbuf, uint64_t capmask)
{
	buf[0] = '\0';

	size_t tags_buflen = (*buflen > OP_MSGBUF_TAGSLEN + 1)
	                   ? OP_MSGBUF_TAGSLEN + 1 : *buflen;
	size_t used = 0;

	if (msgbuf->n_tags > 0)
		used = msgbuf_unparse_tags(buf, tags_buflen, msgbuf, capmask);

	const size_t data_bufmax = used + OP_MSGBUF_DATALEN + 1;
	if (*buflen > data_bufmax)
		*buflen = data_bufmax;

	int ret;
	if (msgbuf->origin) {
		ret = op_snprintf_append(buf, *buflen, ":%s ", msgbuf->origin);
		if (ret > 0) used = (size_t)ret;
	}
	if (msgbuf->cmd) {
		ret = op_snprintf_append(buf, *buflen, "%s ", msgbuf->cmd);
		if (ret > 0) used = (size_t)ret;
	}
	if (msgbuf->target) {
		ret = op_snprintf_append(buf, *buflen, "%s ", msgbuf->target);
		if (ret > 0) used = (size_t)ret;
	}

	if (used > data_bufmax - 1)
		used = data_bufmax - 1;

	return (int)used;
}

int
op_msgbuf_unparse(char *buf, size_t buflen,
                   const struct op_msgbuf *msgbuf, uint64_t capmask)
{
	size_t buflen_copy = buflen;
	op_msgbuf_unparse_prefix(buf, &buflen_copy, msgbuf, capmask);

	for (size_t i = 0; i < msgbuf->n_para; i++) {
		const bool last_with_spaces =
			(i == msgbuf->n_para - 1) &&
			strchr(msgbuf->para[i], ' ') != NULL;
		const char *fmt = last_with_spaces
			? (i == 0 ? ":%s"  : " :%s")
			: (i == 0 ? "%s"   : " %s");
		op_snprintf_append(buf, buflen_copy, fmt, msgbuf->para[i]);
	}
	return 0;
}

int
op_msgbuf_vunparse_fmt(char *buf, size_t buflen,
                        const struct op_msgbuf *head, uint64_t capmask,
                        const char *fmt, va_list va)
{
	size_t buflen_copy = buflen;
	op_msgbuf_unparse_prefix(buf, &buflen_copy, head, capmask);
	const size_t prefixlen = strlen(buf);
	vsnprintf(buf + prefixlen, buflen_copy - prefixlen, fmt, va);
	return 0;
}

int
op_msgbuf_unparse_fmt(char *buf, size_t buflen,
                       const struct op_msgbuf *head, uint64_t capmask,
                       const char *fmt, ...)
{
	va_list va;
	va_start(va, fmt);
	const int res = op_msgbuf_vunparse_fmt(buf, buflen, head, capmask, fmt, va);
	va_end(va);
	return res;
}

/*
 * libop/include/op_msgbuf.h — IRC message buffer parsing and serialisation.
 *
 * Ported from ophion ircd/msgbuf.{c,h} by the ophion development team.
 * Stripped of linebuf-cache and server-specific dependencies for use as a
 * standalone library component.
 *
 * Supports full IRCv3 message-tags (4096-byte tag block), RFC 1459 message
 * data (510 bytes), and up to 15 parameters.
 */

#ifndef OP_MSGBUF_H
#define OP_MSGBUF_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>

/* ── Wire-size constants ────────────────────────────────────────────── */

#define OP_MSGBUF_TAGSLEN  4096   /* IRCv3 tag block (spec: max 4095 + '@') */
#define OP_MSGBUF_DATALEN  510    /* RFC 1459 message data                   */
#define OP_MSGBUF_MAXPARA  15     /* max parameters (including command verb) */

/* ── IRCv3 tag ─────────────────────────────────────────────────────── */

struct op_msg_tag {
	const char  *key;      /* tag name (non-NULL)                  */
	const char  *value;    /* tag value, or NULL for a boolean tag */
	uint64_t     capmask;  /* client capability bits for this tag  */
};

/* ── Parsed/to-be-serialised message ───────────────────────────────── */

struct op_msgbuf {
	size_t          n_tags;
	struct op_msg_tag tags[OP_MSGBUF_MAXPARA];

	const char     *origin;   /* ":nick!user@host" prefix, or NULL    */
	const char     *target;   /* optional secondary target, or NULL   */
	const char     *cmd;      /* command verb (== para[0] after parse) */
	char           *endp;     /* one-past-end of parameter region     */

	size_t          n_para;
	const char     *para[OP_MSGBUF_MAXPARA];
};

/* ── Parse result codes ─────────────────────────────────────────────── */

enum op_parse_result {
	OP_PARSE_SUCCESS             = 0,
	OP_PARSE_UNTERMINATED_TAGS   = 1,
	OP_PARSE_NO_COMMAND          = 2,
	OP_PARSE_NO_PARAMS           = 3,
	OP_PARSE_UNTERMINATED_ORIGIN = 4,
};

/* ── Inline helpers ─────────────────────────────────────────────────── */

static inline void op_msgbuf_init(struct op_msgbuf *m)
{
	__builtin_memset(m, 0, sizeof(*m));
}

static inline void op_msgbuf_append_tag(struct op_msgbuf *m,
                                         const char *key, const char *value,
                                         uint64_t capmask)
{
	if (m->n_tags < OP_MSGBUF_MAXPARA) {
		m->tags[m->n_tags].key     = key;
		m->tags[m->n_tags].value   = value;
		m->tags[m->n_tags].capmask = capmask;
		m->n_tags++;
	}
}

static inline void op_msgbuf_replace_tag(struct op_msgbuf *m,
                                          const char *key, const char *value,
                                          uint64_t capmask)
{
	for (size_t i = 0; i < m->n_tags; i++) {
		if (__builtin_strcmp(m->tags[i].key, key) == 0) {
			m->tags[i].value   = value;
			m->tags[i].capmask = capmask;
			return;
		}
	}
	op_msgbuf_append_tag(m, key, value, capmask);
}

/* ── API ─────────────────────────────────────────────────────────────── */

/* Parsing — modifies `line` in-place. */
int  op_msgbuf_parse(struct op_msgbuf *m, char *line);
void op_msgbuf_reconstruct_tail(struct op_msgbuf *m, size_t n);

/* Unescape an IRCv3 tag value in-place. */
void op_msgbuf_unescape_value(char *value);

/* Serialisation — capmask selects which tags to include. */
int  op_msgbuf_unparse(char *buf, size_t buflen,
                       const struct op_msgbuf *m, uint64_t capmask);
int  op_msgbuf_unparse_prefix(char *buf, size_t *buflen,
                               const struct op_msgbuf *m, uint64_t capmask);
int  op_msgbuf_unparse_fmt(char *buf, size_t buflen,
                            const struct op_msgbuf *head, uint64_t capmask,
                            const char *fmt, ...) AFP(5, 6);
int  op_msgbuf_vunparse_fmt(char *buf, size_t buflen,
                             const struct op_msgbuf *head, uint64_t capmask,
                             const char *fmt, va_list va);

#endif /* OP_MSGBUF_H */

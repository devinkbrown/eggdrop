/*
 * libop/include/op_regex.h — compiled regular expression API
 *
 * Self-contained POSIX ERE engine (Thompson NFA, linear-time matching).
 * No external dependencies; no platform regex.h variance.
 *
 * Supported syntax:
 *   .  * + ?  {n} {n,} {n,m}  |  ( )  [ ] [^ ]  ^ $
 *   \b \B  \d \D \w \W \s \S  \n \t \r  \\
 *   [[:alpha:]] [[:digit:]] [[:alnum:]] [[:space:]] [[:blank:]]
 *   [[:upper:]] [[:lower:]] [[:punct:]] [[:print:]] [[:graph:]]
 *   [[:cntrl:]] [[:xdigit:]]
 *
 * A leading "(?i)" in the pattern implies OP_REGEX_ICASE.
 *
 * Thread safety:
 *   op_regex_compile()  — independent per call.
 *   op_regex_match()    — multiple threads may call concurrently on the
 *   op_regex_search()     same op_regex_t; the compiled object is never mutated.
 *   op_regex_free()     — caller must ensure no concurrent use.
 */

#ifndef OP_REGEX_H
#define OP_REGEX_H

#include <stddef.h>
#include <stdbool.h>

/* ── Compile flags ──────────────────────────────────────────────────── */

#define OP_REGEX_ICASE   0x01u  /* case-insensitive matching             */
#define OP_REGEX_NEWLINE 0x02u  /* '.' does not match '\n'               */

/* ── Opaque handle ──────────────────────────────────────────────────── */

typedef struct op_regex op_regex_t;

/* ── API ────────────────────────────────────────────────────────────── */

/*
 * op_regex_compile — compile an ERE pattern.
 *
 *   pattern  NUL-terminated ERE string.  "(?i)" prefix → ICASE.
 *   flags    OR of OP_REGEX_* constants (0 = defaults).
 *   errbuf   Receives NUL-terminated error description on failure.  May be NULL.
 *   errsz    Capacity of errbuf.
 *
 * Returns op_regex_t* on success, NULL on error.
 * Caller must call op_regex_free() when done.
 */
op_regex_t *op_regex_compile(const char *pattern, unsigned flags,
                              char *errbuf, size_t errsz);

/*
 * op_regex_match — test whether text contains a match for the pattern.
 *
 * Returns true if any substring of text matches.  Anchors ^ / $ restrict
 * where the match may start/end.  Thread-safe on a shared op_regex_t.
 */
bool op_regex_match(const op_regex_t *re, const char *text);

/*
 * op_regex_search — find the leftmost match in text.
 *
 * On success: returns true, writes *match_start (byte offset) and
 * *match_len (byte count) of the leftmost greedy match.  Either output
 * pointer may be NULL.
 *
 * Thread-safe on a shared op_regex_t.
 */
bool op_regex_search(const op_regex_t *re, const char *text,
                     size_t *match_start, size_t *match_len);

/*
 * op_regex_free — release all resources.  Safe to call with NULL.
 */
void op_regex_free(op_regex_t *re);

#endif /* OP_REGEX_H */

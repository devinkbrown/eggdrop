/*
 * libop/src/regex.c — Thompson NFA regex engine (v2)
 *
 * Russ Cox, "Regular Expression Matching Can Be Simple And Fast":
 * https://swtch.com/~rsc/regexp/regexp1.html
 *
 * Compile: tokenise → inject CAT → shunting-yard → Thompson NFA  (O(M))
 * Match:   NFA simulation with generation-counter visited arrays   (O(N·M))
 *
 * Supported syntax:
 *   .           any char (except \n when OP_REGEX_NEWLINE is set)
 *   * + ?       quantifiers
 *   {n} {n,} {n,m}  counted repetition (n,m ≤ 255)
 *   |           alternation
 *   ( … )       grouping  — {n,m} on groups is handled correctly
 *   [ … ]       character class; [^ … ] negated; ranges a-z
 *   [[:name:]]  POSIX bracket expressions (alpha digit alnum space …)
 *   ^ $         line anchors
 *   \b \B       word-boundary / non-word-boundary assertions
 *   \d \D \w \W \s \S   shorthand classes
 *   \n \t \r    escape sequences
 *   (?i)        inline case-insensitive flag (prefix only)
 *
 * Optimisations:
 *   • Generation-counter visited tracking — no memset per character.
 *   • First-char bitmap — skip re-seeding when char cannot start a match.
 *   • Anchored detection — skip re-seeding entirely for ^-anchored patterns.
 */

#include <libop_config.h>
#include <op_lib.h>
#include <op_regex.h>

#include <string.h>
#include <ctype.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>

/* ═══════════════════════════════════════════════════════════════════════
 * Helpers
 * ═══════════════════════════════════════════════════════════════════════ */

/* Locale-independent word-char test (\w semantics). */
static inline bool isword_c(unsigned c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '_';
}

/* ═══════════════════════════════════════════════════════════════════════
 * Character-class bitmap helpers (256-bit = 32 bytes)
 * ═══════════════════════════════════════════════════════════════════════ */

static inline void cls_set(uint8_t cls[32], unsigned c)
    { cls[c >> 3] |= (uint8_t)(1u << (c & 7)); }
static inline void cls_clr(uint8_t cls[32], unsigned c)
    { cls[c >> 3] &= (uint8_t)~(1u << (c & 7)); }
static inline int cls_tst(const uint8_t cls[32], unsigned c)
    { return (cls[c >> 3] >> (c & 7)) & 1; }

static void cls_invert(uint8_t cls[32])
    { for (int i = 0; i < 32; i++) cls[i] ^= 0xFFu; }

static void cls_add_range(uint8_t cls[32], unsigned lo, unsigned hi, bool icase)
{
    if (lo > hi) { unsigned t = lo; lo = hi; hi = t; }
    for (unsigned c = lo; c <= hi; c++) {
        cls_set(cls, c);
        if (icase) {
            if (c >= 'a' && c <= 'z') cls_set(cls, c - 32u);
            else if (c >= 'A' && c <= 'Z') cls_set(cls, c + 32u);
        }
    }
}

/* \d \D \w \W \s \S shorthand classes */
static void cls_add_shorthand(uint8_t cls[32], char code, bool icase)
{
    switch (code) {
    case 'd': cls_add_range(cls, '0', '9', false); break;
    case 'D': for (unsigned c = 0; c < 256; c++) if (c < '0' || c > '9') cls_set(cls, c); break;
    case 'w':
        cls_add_range(cls, 'a', 'z', icase);
        cls_add_range(cls, 'A', 'Z', icase);
        cls_add_range(cls, '0', '9', false);
        cls_set(cls, '_');
        break;
    case 'W': for (unsigned c = 0; c < 256; c++) if (!isword_c(c)) cls_set(cls, c); break;
    case 's': for (unsigned c = 0; c < 256; c++) if (isspace(c)) cls_set(cls, c); break;
    case 'S': for (unsigned c = 0; c < 256; c++) if (!isspace(c)) cls_set(cls, c); break;
    }
}

/* POSIX bracket expression [:name:] → bitmap.  Returns false if unknown. */
static bool cls_add_posix_bracket(uint8_t cls[32], const char *name, bool icase)
{
    if (strcmp(name, "alpha") == 0)
        { for (unsigned c = 0; c < 256; c++) if (isalpha(c)) cls_set(cls, c); }
    else if (strcmp(name, "digit") == 0)
        { cls_add_range(cls, '0', '9', false); }
    else if (strcmp(name, "alnum") == 0)
        { for (unsigned c = 0; c < 256; c++) if (isalnum(c)) cls_set(cls, c); }
    else if (strcmp(name, "space") == 0)
        { for (unsigned c = 0; c < 256; c++) if (isspace(c)) cls_set(cls, c); }
    else if (strcmp(name, "blank") == 0)
        { cls_set(cls, ' '); cls_set(cls, '\t'); }
    else if (strcmp(name, "upper") == 0)
        { cls_add_range(cls, 'A', 'Z', icase); }
    else if (strcmp(name, "lower") == 0)
        { cls_add_range(cls, 'a', 'z', icase); }
    else if (strcmp(name, "punct") == 0)
        { for (unsigned c = 0; c < 256; c++) if (ispunct(c)) cls_set(cls, c); }
    else if (strcmp(name, "print") == 0)
        { for (unsigned c = 0; c < 256; c++) if (isprint(c)) cls_set(cls, c); }
    else if (strcmp(name, "graph") == 0)
        { for (unsigned c = 0; c < 256; c++) if (isgraph(c)) cls_set(cls, c); }
    else if (strcmp(name, "cntrl") == 0)
        { for (unsigned c = 0; c < 256; c++) if (iscntrl(c)) cls_set(cls, c); }
    else if (strcmp(name, "xdigit") == 0)
        { cls_add_range(cls, '0', '9', false);
          cls_add_range(cls, 'a', 'f', icase);
          cls_add_range(cls, 'A', 'F', icase); }
    else
        return false;
    return true;
}

/* ═══════════════════════════════════════════════════════════════════════
 * NFA state
 * ═══════════════════════════════════════════════════════════════════════ */

#define ST_MATCH  0   /* accepting */
#define ST_CHAR   1   /* match literal byte c */
#define ST_CLASS  2   /* match char in 256-bit bitmap */
#define ST_ANY    3   /* match any char (. respecting NEWLINE flag) */
#define ST_SPLIT  4   /* epsilon split → out AND out1 */
#define ST_BOL    5   /* ^ zero-width: passes iff at line start */
#define ST_EOL    6   /* $ zero-width: passes iff at line end */
#define ST_WB     7   /* \b zero-width: passes at word boundary */
#define ST_NWB    8   /* \B zero-width: passes at non-word boundary */

typedef struct NState {
    int8_t   type;
    uint8_t  c;          /* ST_CHAR: the literal byte */
    uint8_t  cls[32];    /* ST_CLASS: 256-bit bitmap */
    struct NState *out;
    struct NState *out1; /* ST_SPLIT second branch */
    int      id;         /* index in pool */
} NState;

/* ═══════════════════════════════════════════════════════════════════════
 * Ptrlist — Thompson dangling-output list
 * ═══════════════════════════════════════════════════════════════════════ */

typedef union Ptrlist { union Ptrlist *next; NState *s; } Ptrlist;

static Ptrlist *pl1(NState **sp) { Ptrlist *l = (Ptrlist *)sp; l->next = NULL; return l; }

static Ptrlist *pl_append(Ptrlist *a, Ptrlist *b)
{
    Ptrlist *p = a;
    while (p->next) p = p->next;
    p->next = b;
    return a;
}

static void pl_patch(Ptrlist *l, NState *s)
{
    while (l) { Ptrlist *n = l->next; l->s = s; l = n; }
}

typedef struct { NState *start; Ptrlist *outs; } Frag;
static inline Frag mkfrag(NState *s, Ptrlist *l) { return (Frag){ s, l }; }

/* ═══════════════════════════════════════════════════════════════════════
 * Token types
 * ═══════════════════════════════════════════════════════════════════════ */

#define TOK_LIT    1
#define TOK_CLASS  2
#define TOK_ANY    3
#define TOK_BOL    4
#define TOK_EOL    5
#define TOK_STAR   6
#define TOK_PLUS   7
#define TOK_QUEST  8
#define TOK_CAT    9
#define TOK_PIPE   10
#define TOK_LPAREN 11
#define TOK_RPAREN 12
#define TOK_WB     13  /* \b */
#define TOK_NWB    14  /* \B */

typedef struct {
    int8_t  type;
    uint8_t c;
    uint8_t cls[32];
} Token;

/* ═══════════════════════════════════════════════════════════════════════
 * Dynamic token buffer
 * ═══════════════════════════════════════════════════════════════════════ */

typedef struct { Token *t; int n, cap; } TBuf;

static bool tbuf_push(TBuf *b, Token tk)
{
    if (b->n >= b->cap) {
        int nc = b->cap ? b->cap * 2 : 64;
        Token *nt = op_realloc(b->t, (size_t)nc * sizeof(Token));
        if (!nt) return false;
        b->t = nt; b->cap = nc;
    }
    b->t[b->n++] = tk;
    return true;
}

/* ═══════════════════════════════════════════════════════════════════════
 * Phase 1 — tokenise
 * ═══════════════════════════════════════════════════════════════════════ */

/* Parse [...] character class.  *pp points just after '['.
   On success advances *pp past ']'.  Returns false on unterminated class. */
static bool parse_class(const char **pp, uint8_t cls[32], bool icase)
{
    memset(cls, 0, 32);
    const char *p = *pp;
    bool neg = (*p == '^');
    if (neg) p++;

    bool first = true;
    while (*p && (*p != ']' || first)) {
        first = false;

        /* POSIX bracket expression [:name:] */
        if (*p == '[' && *(p + 1) == ':') {
            const char *close = strstr(p + 2, ":]");
            if (close) {
                int nlen = (int)(close - (p + 2));
                if (nlen > 0 && nlen <= 12) {
                    char nm[13];
                    memcpy(nm, p + 2, nlen);
                    nm[nlen] = '\0';
                    if (cls_add_posix_bracket(cls, nm, icase)) {
                        p = close + 2;
                        continue;
                    }
                }
            }
        }

        unsigned lo;
        if (*p == '\\' && *(p + 1)) {
            p++;
            switch (*p) {
            case 'd': case 'D': case 'w': case 'W': case 's': case 'S':
                cls_add_shorthand(cls, *p, icase); p++; continue;
            case 'n': lo = '\n'; break;
            case 't': lo = '\t'; break;
            case 'r': lo = '\r'; break;
            default:  lo = (unsigned char)*p; break;
            }
        } else {
            lo = (unsigned char)*p;
        }

        /* Range a-b ? */
        if (*(p + 1) == '-' && *(p + 2) && *(p + 2) != ']') {
            unsigned hi = (unsigned char)*(p + 2);
            cls_add_range(cls, lo, hi, icase);
            p += 3;
        } else {
            cls_set(cls, lo);
            if (icase) {
                if (lo >= 'a' && lo <= 'z') cls_set(cls, lo - 32u);
                else if (lo >= 'A' && lo <= 'Z') cls_set(cls, lo + 32u);
            }
            p++;
        }
    }
    if (*p != ']') return false;
    if (neg) cls_invert(cls);
    *pp = p + 1;
    return true;
}

static bool tokenise(const char *pat, bool icase, bool dotall, TBuf *out,
                     char *errbuf, size_t errsz)
{
    const char *p      = pat;
    int prev_atom      = -1;
    int depth          = 0;
    int lparen_stk[64]; /* stack of LPAREN token indices for {n,m} on groups */
    int lp_sp          = 0;

    while (*p) {

        /* ── Escape sequences ─────────────────────────────────── */
        if (*p == '\\' && *(p + 1)) {
            p++;
            Token t = {0};
            switch (*p) {
            case 'd': case 'D': case 'w': case 'W': case 's': case 'S':
                t.type = TOK_CLASS;
                cls_add_shorthand(t.cls, *p, icase);
                break;
            case 'b': t.type = TOK_WB;  break;
            case 'B': t.type = TOK_NWB; break;
            case 'n': t.type = TOK_LIT; t.c = '\n'; break;
            case 't': t.type = TOK_LIT; t.c = '\t'; break;
            case 'r': t.type = TOK_LIT; t.c = '\r'; break;
            default:
                t.type = TOK_LIT;
                t.c = (uint8_t)(icase ? (uint8_t)tolower((unsigned char)*p)
                                      : (unsigned char)*p);
                break;
            }
            prev_atom = out->n;
            if (!tbuf_push(out, t)) return false;
            p++;
            continue;
        }

        switch (*p) {

        /* ── Quantifiers ──────────────────────────────────────── */
        case '*': { Token t = {0}; t.type = TOK_STAR;  if (!tbuf_push(out, t)) return false; break; }
        case '+': { Token t = {0}; t.type = TOK_PLUS;  if (!tbuf_push(out, t)) return false; break; }
        case '?': { Token t = {0}; t.type = TOK_QUEST; if (!tbuf_push(out, t)) return false; break; }

        /* ── Counted repetition {n,m} ─────────────────────────── */
        case '{': {
            const char *q = p + 1;
            int lo = 0, hi = -1;
            while (*q >= '0' && *q <= '9') lo = lo * 10 + (*q++ - '0');
            if (*q == ',') {
                q++;
                hi = 0;
                while (*q >= '0' && *q <= '9') hi = hi * 10 + (*q++ - '0');
                if (q == p + 2) hi = -1; /* {n,} */
            } else {
                hi = lo;
            }
            if (*q != '}' || lo < 0 || lo > 255 ||
                (hi >= 0 && (hi > 255 || hi < lo))) {
                /* Not a valid {n,m} — treat '{' as literal */
                Token t = {0}; t.type = TOK_LIT; t.c = '{';
                prev_atom = out->n;
                if (!tbuf_push(out, t)) return false;
                break;
            }
            p = q;

            if (prev_atom < 0) break;

            if (lo == 0 && hi == 0) {
                out->n = prev_atom;
                prev_atom = -1;
                break;
            }

            int atom_len = out->n - prev_atom;
            Token *snap  = op_malloc((size_t)atom_len * sizeof(Token));
            if (!snap) return false;
            memcpy(snap, out->t + prev_atom, (size_t)atom_len * sizeof(Token));

            if (lo == 0) {
                Token q2 = {0}; q2.type = TOK_QUEST;
                if (!tbuf_push(out, q2)) { op_free(snap); return false; }
                for (int r = 1; r < hi; r++) {
                    for (int j = 0; j < atom_len; j++)
                        if (!tbuf_push(out, snap[j])) { op_free(snap); return false; }
                    if (!tbuf_push(out, q2)) { op_free(snap); return false; }
                }
            } else {
                for (int r = 1; r < lo; r++)
                    for (int j = 0; j < atom_len; j++)
                        if (!tbuf_push(out, snap[j])) { op_free(snap); return false; }
                if (hi == -1) {
                    Token pl = {0}; pl.type = TOK_PLUS;
                    if (!tbuf_push(out, pl)) { op_free(snap); return false; }
                } else {
                    Token q2 = {0}; q2.type = TOK_QUEST;
                    for (int r = 0; r < hi - lo; r++) {
                        for (int j = 0; j < atom_len; j++)
                            if (!tbuf_push(out, snap[j])) { op_free(snap); return false; }
                        if (!tbuf_push(out, q2)) { op_free(snap); return false; }
                    }
                }
            }
            op_free(snap);
            break;
        }

        /* ── Alternation ──────────────────────────────────────── */
        case '|': {
            Token t = {0}; t.type = TOK_PIPE;
            if (!tbuf_push(out, t)) return false;
            prev_atom = -1;
            break;
        }

        /* ── Grouping ─────────────────────────────────────────── */
        case '(':
            /* Save LPAREN index for potential {n,m} on group */
            if (lp_sp < 64) lparen_stk[lp_sp] = (int)out->n;
            lp_sp++;
            { Token t = {0}; t.type = TOK_LPAREN; if (!tbuf_push(out, t)) return false; }
            depth++;
            prev_atom = -1;
            break;

        case ')':
            if (depth == 0) {
                if (errbuf) snprintf(errbuf, errsz, "unmatched ')'");
                return false;
            }
            { Token t = {0}; t.type = TOK_RPAREN; if (!tbuf_push(out, t)) return false; }
            depth--;
            lp_sp--;
            /* prev_atom = LPAREN index so {n,m} captures the whole group */
            prev_atom = (lp_sp >= 0 && lp_sp < 64) ? lparen_stk[lp_sp] : -1;
            break;

        /* ── Character class ──────────────────────────────────── */
        case '[': {
            p++;
            Token t = {0}; t.type = TOK_CLASS;
            if (!parse_class(&p, t.cls, icase)) {
                if (errbuf) snprintf(errbuf, errsz, "unterminated character class");
                return false;
            }
            prev_atom = out->n;
            if (!tbuf_push(out, t)) return false;
            p--; /* compensate for p++ below */
            break;
        }

        /* ── Anchors ──────────────────────────────────────────── */
        case '^': {
            Token t = {0}; t.type = TOK_BOL;
            prev_atom = out->n;
            if (!tbuf_push(out, t)) return false;
            break;
        }
        case '$': {
            Token t = {0}; t.type = TOK_EOL;
            prev_atom = out->n;
            if (!tbuf_push(out, t)) return false;
            break;
        }

        /* ── Dot ──────────────────────────────────────────────── */
        case '.': {
            Token t = {0};
            if (!dotall) {
                t.type = TOK_CLASS;
                memset(t.cls, 0xFF, 32);
                cls_clr(t.cls, '\n');
            } else {
                t.type = TOK_ANY;
            }
            prev_atom = out->n;
            if (!tbuf_push(out, t)) return false;
            break;
        }

        /* ── Literal ──────────────────────────────────────────── */
        default: {
            Token t = {0};
            t.type = TOK_LIT;
            t.c    = (uint8_t)(icase ? (uint8_t)tolower((unsigned char)*p)
                                     : (unsigned char)*p);
            prev_atom = out->n;
            if (!tbuf_push(out, t)) return false;
            break;
        }
        }
        p++;
    }

    if (depth != 0) {
        if (errbuf) snprintf(errbuf, errsz, "unmatched '('");
        return false;
    }
    return true;
}

/* ═══════════════════════════════════════════════════════════════════════
 * Phase 2 — inject explicit CAT tokens
 * ═══════════════════════════════════════════════════════════════════════ */

static bool tok_ends_atom(int type)
{
    return type == TOK_LIT   || type == TOK_CLASS || type == TOK_ANY  ||
           type == TOK_BOL   || type == TOK_EOL   || type == TOK_WB   ||
           type == TOK_NWB   || type == TOK_RPAREN ||
           type == TOK_STAR  || type == TOK_PLUS  || type == TOK_QUEST;
}
static bool tok_starts_atom(int type)
{
    return type == TOK_LIT   || type == TOK_CLASS || type == TOK_ANY  ||
           type == TOK_BOL   || type == TOK_EOL   || type == TOK_WB   ||
           type == TOK_NWB   || type == TOK_LPAREN;
}

static bool cat_inject(const TBuf *in, TBuf *out)
{
    Token cat = {0}; cat.type = TOK_CAT;
    for (int i = 0; i < in->n; i++) {
        if (i > 0 &&
            tok_ends_atom(in->t[i-1].type) &&
            tok_starts_atom(in->t[i].type))
            if (!tbuf_push(out, cat)) return false;
        if (!tbuf_push(out, in->t[i])) return false;
    }
    return true;
}

/* ═══════════════════════════════════════════════════════════════════════
 * Phase 3 — shunting-yard: infix → postfix
 * ═══════════════════════════════════════════════════════════════════════ */

static int tok_prec(int type)
{
    switch (type) {
    case TOK_STAR: case TOK_PLUS: case TOK_QUEST: return 3;
    case TOK_CAT:                                 return 2;
    case TOK_PIPE:                                return 1;
    default:                                      return 0;
    }
}

static bool shunt(const TBuf *in, TBuf *out, char *errbuf, size_t errsz)
{
    Token stk[512];
    int   stk_n = 0;

    for (int i = 0; i < in->n; i++) {
        Token t = in->t[i];
        switch (t.type) {

        case TOK_LIT: case TOK_CLASS: case TOK_ANY:
        case TOK_BOL: case TOK_EOL:
        case TOK_WB:  case TOK_NWB:
            if (!tbuf_push(out, t)) return false;
            break;

        case TOK_STAR: case TOK_PLUS: case TOK_QUEST:
            while (stk_n > 0 && tok_prec(stk[stk_n-1].type) > tok_prec(t.type))
                if (!tbuf_push(out, stk[--stk_n])) return false;
            if (stk_n >= 512) return false;
            stk[stk_n++] = t;
            break;

        case TOK_CAT: case TOK_PIPE:
            while (stk_n > 0 && stk[stk_n-1].type != TOK_LPAREN &&
                   tok_prec(stk[stk_n-1].type) >= tok_prec(t.type))
                if (!tbuf_push(out, stk[--stk_n])) return false;
            if (stk_n >= 512) return false;
            stk[stk_n++] = t;
            break;

        case TOK_LPAREN:
            if (stk_n >= 512) return false;
            stk[stk_n++] = t;
            break;

        case TOK_RPAREN:
            while (stk_n > 0 && stk[stk_n-1].type != TOK_LPAREN)
                if (!tbuf_push(out, stk[--stk_n])) return false;
            if (stk_n == 0) {
                if (errbuf) snprintf(errbuf, errsz, "unmatched ')'");
                return false;
            }
            stk_n--; /* pop LPAREN */
            break;
        }
    }

    while (stk_n > 0) {
        if (stk[stk_n-1].type == TOK_LPAREN) {
            if (errbuf) snprintf(errbuf, errsz, "unmatched '('");
            return false;
        }
        if (!tbuf_push(out, stk[--stk_n])) return false;
    }
    return true;
}

/* ═══════════════════════════════════════════════════════════════════════
 * op_regex struct
 * ═══════════════════════════════════════════════════════════════════════ */

struct op_regex {
    NState *pool;
    int     nstates;
    NState *start;
    bool    icase;
    bool    anchored;        /* syntactic ^ prefix — skip re-seeding */
    bool    can_empty;       /* NFA can match empty string */
    bool    first_any;       /* first-char bitmap disabled (ANY/WB/NWB reachable) */
    uint8_t first_chars[32]; /* bytes that can start a match */
};

/* ═══════════════════════════════════════════════════════════════════════
 * Phase 4 — build Thompson NFA from postfix
 * ═══════════════════════════════════════════════════════════════════════ */

static NState *st_alloc(struct op_regex *re, int type)
{
    NState *s = &re->pool[re->nstates];
    memset(s, 0, sizeof *s);
    s->type = (int8_t)type;
    s->id   = re->nstates++;
    return s;
}

static bool build_nfa(const TBuf *pf, struct op_regex *re,
                      char *errbuf, size_t errsz)
{
    Frag  fstack[512];
    int   fstack_n = 0;

#define PUSH(f) do { if (fstack_n >= 512) goto err; fstack[fstack_n++] = (f); } while(0)
#define POP()   fstack[--fstack_n]

    for (int i = 0; i < pf->n; i++) {
        Token t = pf->t[i];
        switch (t.type) {

        case TOK_LIT: {
            NState *s = st_alloc(re, ST_CHAR); s->c = t.c;
            PUSH(mkfrag(s, pl1(&s->out))); break;
        }
        case TOK_CLASS: {
            NState *s = st_alloc(re, ST_CLASS); memcpy(s->cls, t.cls, 32);
            PUSH(mkfrag(s, pl1(&s->out))); break;
        }
        case TOK_ANY: {
            NState *s = st_alloc(re, ST_ANY);
            PUSH(mkfrag(s, pl1(&s->out))); break;
        }
        case TOK_BOL: {
            NState *s = st_alloc(re, ST_BOL);
            PUSH(mkfrag(s, pl1(&s->out))); break;
        }
        case TOK_EOL: {
            NState *s = st_alloc(re, ST_EOL);
            PUSH(mkfrag(s, pl1(&s->out))); break;
        }
        case TOK_WB: {
            NState *s = st_alloc(re, ST_WB);
            PUSH(mkfrag(s, pl1(&s->out))); break;
        }
        case TOK_NWB: {
            NState *s = st_alloc(re, ST_NWB);
            PUSH(mkfrag(s, pl1(&s->out))); break;
        }
        case TOK_CAT: {
            if (fstack_n < 2) goto err;
            Frag e2 = POP(), e1 = POP();
            pl_patch(e1.outs, e2.start);
            PUSH(mkfrag(e1.start, e2.outs)); break;
        }
        case TOK_PIPE: {
            if (fstack_n < 2) goto err;
            Frag e2 = POP(), e1 = POP();
            NState *s = st_alloc(re, ST_SPLIT);
            s->out = e1.start; s->out1 = e2.start;
            PUSH(mkfrag(s, pl_append(e1.outs, e2.outs))); break;
        }
        case TOK_STAR: {
            if (fstack_n < 1) goto err;
            Frag e = POP();
            NState *s = st_alloc(re, ST_SPLIT);
            s->out = e.start; pl_patch(e.outs, s);
            PUSH(mkfrag(s, pl1(&s->out1))); break;
        }
        case TOK_PLUS: {
            if (fstack_n < 1) goto err;
            Frag e = POP();
            NState *s = st_alloc(re, ST_SPLIT);
            s->out = e.start; pl_patch(e.outs, s);
            PUSH(mkfrag(e.start, pl1(&s->out1))); break;
        }
        case TOK_QUEST: {
            if (fstack_n < 1) goto err;
            Frag e = POP();
            NState *s = st_alloc(re, ST_SPLIT);
            s->out = e.start;
            PUSH(mkfrag(s, pl_append(pl1(&s->out1), e.outs))); break;
        }
        }
    }

    if (fstack_n != 1) goto err;
    {
        Frag e     = POP();
        NState *ms = st_alloc(re, ST_MATCH);
        pl_patch(e.outs, ms);
        re->start  = e.start;
    }
    return true;

err:
    if (errbuf) snprintf(errbuf, errsz, "NFA construction failed (malformed pattern)");
    return false;
#undef PUSH
#undef POP
}

/* ═══════════════════════════════════════════════════════════════════════
 * Metadata: first-char bitmap, can_empty, anchored
 *
 * collect_first_states follows epsilon transitions unconditionally
 * (BOL/EOL/WB/NWB/SPLIT all followed, ignoring runtime context) so the
 * first-char bitmap includes chars reachable through any zero-width assert.
 * If ST_ANY is reachable, first_any = true and the bitmap is disabled.
 * ═══════════════════════════════════════════════════════════════════════ */

static void collect_first_states(NState *s, bool *vis,
                                  NState **lst, int *nlst)
{
    if (!s || vis[s->id]) return;
    vis[s->id] = true;
    switch (s->type) {
    case ST_SPLIT:
        collect_first_states(s->out,  vis, lst, nlst);
        collect_first_states(s->out1, vis, lst, nlst);
        break;
    case ST_BOL: case ST_EOL:
    case ST_WB:  case ST_NWB:
        collect_first_states(s->out, vis, lst, nlst);
        break;
    default:
        lst[(*nlst)++] = s;
        break;
    }
}

static void compute_metadata(struct op_regex *re)
{
    int n = re->nstates;
    bool    *vis = op_calloc(n, 1);
    NState **lst = op_malloc(n * sizeof(NState *));
    if (!vis || !lst) { op_free(vis); op_free(lst); re->first_any = true; return; }

    int nlst = 0;
    collect_first_states(re->start, vis, lst, &nlst);

    memset(re->first_chars, 0, 32);
    re->can_empty = false;
    re->first_any = false;

    for (int i = 0; i < nlst; i++) {
        NState *s = lst[i];
        switch (s->type) {
        case ST_MATCH:
            re->can_empty = true;
            break;
        case ST_ANY:
            re->first_any = true;
            goto done;
        case ST_CHAR:
            cls_set(re->first_chars, s->c);
            if (re->icase) {
                if (s->c >= 'a' && s->c <= 'z') cls_set(re->first_chars, s->c - 32u);
                else if (s->c >= 'A' && s->c <= 'Z') cls_set(re->first_chars, s->c + 32u);
            }
            break;
        case ST_CLASS:
            for (int j = 0; j < 32; j++) re->first_chars[j] |= s->cls[j];
            break;
        default:
            break;
        }
    }
done:
    op_free(vis);
    op_free(lst);
}

/* ═══════════════════════════════════════════════════════════════════════
 * op_regex_compile
 * ═══════════════════════════════════════════════════════════════════════ */

op_regex_t *
op_regex_compile(const char *pattern, unsigned flags,
                 char *errbuf, size_t errsz)
{
    if (!pattern) {
        if (errbuf) snprintf(errbuf, errsz, "NULL pattern");
        return NULL;
    }

    bool icase  = (flags & OP_REGEX_ICASE) != 0;
    bool dotall = (flags & OP_REGEX_NEWLINE) == 0;
    if (strncmp(pattern, "(?i)", 4) == 0) { icase = true; pattern += 4; }

    bool anchored = (pattern[0] == '^');

    TBuf infix = { NULL, 0, 0 };
    if (!tokenise(pattern, icase, dotall, &infix, errbuf, errsz)) {
        op_free(infix.t); return NULL;
    }

    TBuf cat = { NULL, 0, 0 };
    if (!cat_inject(&infix, &cat)) {
        op_free(infix.t); op_free(cat.t);
        if (errbuf) snprintf(errbuf, errsz, "out of memory");
        return NULL;
    }
    op_free(infix.t);

    TBuf pf = { NULL, 0, 0 };
    if (!shunt(&cat, &pf, errbuf, errsz)) {
        op_free(cat.t); op_free(pf.t); return NULL;
    }
    op_free(cat.t);

    int pool_cap = pf.n * 2 + 4;
    if (pool_cap < 8) pool_cap = 8;

    NState *pool = op_malloc((size_t)pool_cap * sizeof(NState));
    if (!pool) {
        op_free(pf.t);
        if (errbuf) snprintf(errbuf, errsz, "out of memory");
        return NULL;
    }

    struct op_regex *re = op_malloc(sizeof(struct op_regex));
    if (!re) {
        op_free(pool); op_free(pf.t);
        if (errbuf) snprintf(errbuf, errsz, "out of memory");
        return NULL;
    }

    re->pool     = pool;
    re->nstates  = 0;
    re->start    = NULL;
    re->icase    = icase;
    re->anchored = anchored;
    re->can_empty = false;
    re->first_any = false;
    memset(re->first_chars, 0, 32);

    if (!build_nfa(&pf, re, errbuf, errsz)) {
        op_free(pf.t); op_free(pool); op_free(re); return NULL;
    }
    op_free(pf.t);

    compute_metadata(re);
    return re;
}

/* ═══════════════════════════════════════════════════════════════════════
 * NFA simulation — generation-counter visited tracking
 *
 * Each active list uses a uint32_t generation array.  "Clearing" a list
 * is O(1): just increment its generation value.  No memset per character.
 *
 * addstate() follows epsilon transitions (SPLIT, BOL, EOL, WB, NWB)
 * recursively and adds consuming / match states to the list.
 *
 *   vg   — per-state generation tracker for this list
 *   gen  — current generation value; vg[s->id] == gen means "already added"
 *   cur  — pointer to current position in text (for EOL evaluation)
 *   prev_c — previous consumed byte, 0 at start-of-string
 *            (needed for BOL, WB: at_bol = prev_c==0 || prev_c=='\n')
 * ═══════════════════════════════════════════════════════════════════════ */

static void addstate(NState **list, int *nlist, NState *s,
                     uint32_t *vg, uint32_t gen,
                     const char *cur, unsigned prev_c)
{
    if (!s || vg[s->id] == gen) return;
    vg[s->id] = gen;

    switch (s->type) {
    case ST_SPLIT:
        addstate(list, nlist, s->out,  vg, gen, cur, prev_c);
        addstate(list, nlist, s->out1, vg, gen, cur, prev_c);
        return;
    case ST_BOL:
        if (prev_c == 0 || prev_c == '\n')
            addstate(list, nlist, s->out, vg, gen, cur, prev_c);
        return;
    case ST_EOL:
        if (*cur == '\0' || *cur == '\n')
            addstate(list, nlist, s->out, vg, gen, cur, prev_c);
        return;
    case ST_WB: {
        bool pw = isword_c(prev_c);
        bool cw = (*cur != '\0') && isword_c((unsigned char)*cur);
        if (pw != cw)
            addstate(list, nlist, s->out, vg, gen, cur, prev_c);
        return;
    }
    case ST_NWB: {
        bool pw = isword_c(prev_c);
        bool cw = (*cur != '\0') && isword_c((unsigned char)*cur);
        if (pw == cw)
            addstate(list, nlist, s->out, vg, gen, cur, prev_c);
        return;
    }
    default:
        list[(*nlist)++] = s;
    }
}

/* ── Simulation buffer macros ─────────────────────────────────────────── */

#define SIM_STACK_MAX 512

#define SIM_ALLOC(n, vg0, vg1, ls0, ls1, heap, ok)                         \
    do {                                                                     \
        if ((n) > SIM_STACK_MAX) {                                           \
            (heap) = op_malloc((size_t)(n) * 2 * sizeof(uint32_t) +         \
                               (size_t)(n) * 2 * sizeof(NState *));         \
            if (!(heap)) { (ok) = false; break; }                           \
            (vg0)   = (uint32_t *)(heap);                                    \
            (vg1)   = (vg0) + (n);                                           \
            (ls0)   = (NState **)((vg1) + (n));                              \
            (ls1)   = (ls0)  + (n);                                          \
            memset((heap), 0, (size_t)(n) * 2 * sizeof(uint32_t));          \
        } else {                                                             \
            static uint32_t _a[SIM_STACK_MAX], _b[SIM_STACK_MAX];           \
            static NState  *_c[SIM_STACK_MAX], *_d[SIM_STACK_MAX];          \
            memset(_a, 0, (size_t)(n) * sizeof(uint32_t));                  \
            memset(_b, 0, (size_t)(n) * sizeof(uint32_t));                  \
            (vg0) = _a; (vg1) = _b; (ls0) = _c; (ls1) = _d;               \
        }                                                                    \
        (ok) = true;                                                         \
    } while (0)

/* ═══════════════════════════════════════════════════════════════════════
 * op_regex_match
 * ═══════════════════════════════════════════════════════════════════════ */

bool
op_regex_match(const op_regex_t *re, const char *text)
{
    if (!re || !text || !re->start) return false;

    int      n    = re->nstates;
    uint32_t *vg0, *vg1;
    NState  **ls0, **ls1;
    void     *heap = NULL;
    bool      ok;

    uint32_t  _vg_a[SIM_STACK_MAX], _vg_b[SIM_STACK_MAX];
    NState   *_ls_a[SIM_STACK_MAX], *_ls_b[SIM_STACK_MAX];

    if (n > SIM_STACK_MAX) {
        heap = op_malloc((size_t)n * 2 * sizeof(uint32_t) +
                         (size_t)n * 2 * sizeof(NState *));
        if (!heap) return false;
        vg0 = (uint32_t *)heap;
        vg1 = vg0 + n;
        ls0 = (NState **)(vg1 + n);
        ls1 = ls0 + n;
        memset(heap, 0, (size_t)n * 2 * sizeof(uint32_t));
        ok = true;
    } else {
        memset(_vg_a, 0, (size_t)n * sizeof(uint32_t));
        memset(_vg_b, 0, (size_t)n * sizeof(uint32_t));
        vg0 = _vg_a; vg1 = _vg_b;
        ls0 = _ls_a; ls1 = _ls_b;
        ok = true;
    }
    (void)ok;

    /* ci = index of current list (0 or 1), ni = next list */
    int ci = 0, ni = 1;
    uint32_t *vg[2] = { vg0, vg1 };
    NState  **ls[2] = { ls0, ls1 };
    uint32_t  g[2]  = { 1, 2 };
    int       nl[2] = { 0, 0 };

    const char *p    = text;
    bool        matched = false;

    /* Initial seed at position 0, prev_c = 0 (start-of-string) */
    addstate(ls[ci], &nl[ci], re->start, vg[ci], g[ci], p, 0u);

    while (true) {
        /* Check for match in current list */
        for (int i = 0; i < nl[ci]; i++) {
            if (ls[ci][i]->type == ST_MATCH) { matched = true; goto done; }
        }
        if (*p == '\0') break;

        unsigned c     = (unsigned char)*p;
        if (re->icase) c = (unsigned char)tolower((int)c);
        const char *np = p + 1;

        /* "Clear" next list by advancing its generation */
        g[ni]++;
        nl[ni] = 0;

        /* Advance states that consume c */
        for (int i = 0; i < nl[ci]; i++) {
            NState *s = ls[ci][i];
            bool step = false;
            switch (s->type) {
            case ST_CHAR:  step = (s->c == (uint8_t)c); break;
            case ST_CLASS: step = cls_tst(s->cls, c);   break;
            case ST_ANY:   step = true;                  break;
            default: break;
            }
            if (step)
                addstate(ls[ni], &nl[ni], s->out, vg[ni], g[ni], np, c);
        }

        /* Re-seed for unanchored matching */
        if (!re->anchored) {
            /* First-char optimisation: skip re-seed if next char can't start a match */
            bool do_seed = true;
            if (!re->first_any && !re->can_empty && *np != '\0') {
                unsigned nc = (unsigned char)*np;
                if (re->icase) nc = (unsigned char)tolower((int)nc);
                do_seed = cls_tst(re->first_chars, nc) != 0;
            }
            if (do_seed && vg[ni][re->start->id] != g[ni])
                addstate(ls[ni], &nl[ni], re->start, vg[ni], g[ni], np, c);
        }

        /* Swap current ↔ next */
        int tmp_i = ci; ci = ni; ni = tmp_i;
        p++;
    }

    /* Final check: match at end-of-string */
    for (int i = 0; i < nl[ci]; i++)
        if (ls[ci][i]->type == ST_MATCH) { matched = true; break; }

done:
    op_free(heap);
    return matched;
}

/* ═══════════════════════════════════════════════════════════════════════
 * match_at — anchored match starting at `start`, with prev_c context.
 * Returns match length (≥0) or -1.  Greedy: returns the longest match.
 * ═══════════════════════════════════════════════════════════════════════ */

static int
match_at(const op_regex_t *re, const char *start, unsigned prev_c)
{
    int      n    = re->nstates;
    uint32_t *vg0, *vg1;
    NState  **ls0, **ls1;
    void     *heap = NULL;

    uint32_t _vg_a[SIM_STACK_MAX], _vg_b[SIM_STACK_MAX];
    NState  *_ls_a[SIM_STACK_MAX], *_ls_b[SIM_STACK_MAX];

    if (n > SIM_STACK_MAX) {
        heap = op_malloc((size_t)n * 2 * sizeof(uint32_t) +
                         (size_t)n * 2 * sizeof(NState *));
        if (!heap) return -1;
        vg0 = (uint32_t *)heap;
        vg1 = vg0 + n;
        ls0 = (NState **)(vg1 + n);
        ls1 = ls0 + n;
        memset(heap, 0, (size_t)n * 2 * sizeof(uint32_t));
    } else {
        memset(_vg_a, 0, (size_t)n * sizeof(uint32_t));
        memset(_vg_b, 0, (size_t)n * sizeof(uint32_t));
        vg0 = _vg_a; vg1 = _vg_b;
        ls0 = _ls_a; ls1 = _ls_b;
    }

    int ci = 0, ni = 1;
    uint32_t *vg[2] = { vg0, vg1 };
    NState  **ls[2] = { ls0, ls1 };
    uint32_t  g[2]  = { 1, 2 };
    int       nl[2] = { 0, 0 };

    const char *p = start;
    int match_len = -1;
    int len       = 0;

    addstate(ls[ci], &nl[ci], re->start, vg[ci], g[ci], p, prev_c);

    while (true) {
        for (int i = 0; i < nl[ci]; i++)
            if (ls[ci][i]->type == ST_MATCH) { match_len = len; break; }

        if (*p == '\0') break;

        unsigned c     = (unsigned char)*p;
        if (re->icase) c = (unsigned char)tolower((int)c);
        const char *np = p + 1;

        g[ni]++;
        nl[ni] = 0;

        for (int i = 0; i < nl[ci]; i++) {
            NState *s = ls[ci][i];
            bool step = false;
            switch (s->type) {
            case ST_CHAR:  step = (s->c == (uint8_t)c); break;
            case ST_CLASS: step = cls_tst(s->cls, c);   break;
            case ST_ANY:   step = true;                  break;
            default: break;
            }
            if (step)
                addstate(ls[ni], &nl[ni], s->out, vg[ni], g[ni], np, c);
        }
        /* No re-seeding — this is an anchored match from `start`. */

        int tmp_i = ci; ci = ni; ni = tmp_i;
        p++;
        len++;
    }

    for (int i = 0; i < nl[ci]; i++)
        if (ls[ci][i]->type == ST_MATCH) { match_len = len; break; }

    op_free(heap);
    return match_len;
}

/* ═══════════════════════════════════════════════════════════════════════
 * op_regex_search — find the first (leftmost) match in text.
 * Returns the greedy (longest) match starting at the leftmost position.
 * ═══════════════════════════════════════════════════════════════════════ */

bool
op_regex_search(const op_regex_t *re, const char *text,
                size_t *match_start, size_t *match_len)
{
    if (!re || !text || !re->start) return false;

    size_t tlen = strlen(text);

    for (size_t i = 0; i <= tlen; i++) {
        /* First-char optimisation: skip positions that can't start a match */
        if (i < tlen && !re->first_any && !re->can_empty) {
            unsigned c = (unsigned char)text[i];
            if (re->icase) c = (unsigned char)tolower((int)c);
            if (!cls_tst(re->first_chars, c)) {
                if (re->anchored) break;
                continue;
            }
        }

        unsigned prev_c = (i == 0) ? 0u : (unsigned char)text[i - 1];
        if (re->icase && prev_c)
            prev_c = (unsigned char)tolower((int)prev_c);

        int mlen = match_at(re, text + i, prev_c);
        if (mlen >= 0) {
            if (match_start) *match_start = i;
            if (match_len)   *match_len   = (size_t)mlen;
            return true;
        }

        if (re->anchored) break;
    }
    return false;
}

/* ═══════════════════════════════════════════════════════════════════════
 * op_regex_free
 * ═══════════════════════════════════════════════════════════════════════ */

void
op_regex_free(op_regex_t *re)
{
    if (!re) return;
    op_free(re->pool);
    op_free(re);
}

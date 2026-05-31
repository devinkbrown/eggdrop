/*
 * match.c
 *   wildcard matching functions
 *   hostmask matching
 *   cidr matching
 *
 * Wildcard matching (_wild_match, _wild_match_per) uses the op_regex
 * Thompson NFA engine from libop.  IRC wildcard patterns are translated
 * to POSIX ERE before compilation:
 *
 *   *   →  .*          (0+ any chars including spaces)
 *   ?   →  .           (exactly 1 char)
 *   %   →  [^ ]*       (0+ non-space; _wild_match_per only)
 *   ~   →  [ ]+        (1+ spaces;    _wild_match_per only)
 *   \X  →  X           (literal; _wild_match_per only)
 *   other →  escaped if it is a regex metachar
 *
 * All matching is anchored (^...$) and case-insensitive (OP_REGEX_ICASE).
 */
#include "main.h"
#include <op_regex.h>

#define NOMATCH 0

int cidr_support = 0;

int casecharcmp(unsigned char a, unsigned char b)
{
  return (rfc_toupper(a) - rfc_toupper(b));
}

int charcmp(unsigned char a, unsigned char b)
{
  return (a - b);
}

/* Regex metacharacters that must be backslash-escaped when appearing as
 * literals in the translated pattern. */
static const char regex_meta[] = "\\.^$|{}[]()+-?*";

/* Translate an IRC wildcard pattern into a POSIX ERE string.
 *
 * per_mode: also translate %, ~, and \ quoting.
 * Output is always ^...$-anchored and NUL-terminated.
 * Returns the number of bytes written (excluding NUL), or -1 if truncated.
 */
static int irc_to_ere(const unsigned char *m, char *out, size_t outsz,
                      bool per_mode)
{
  char *p = out;
  const char *end = out + outsz - 2; /* leave room for '$' and NUL */

  if (!m || outsz < 4) return -1;

  *p++ = '^';

  while (*m && p < end) {
    if (per_mode && *m == '\\') {
      /* quoting: next char is literal */
      m++;
      if (!*m) break;
      if (strchr(regex_meta, (char)*m)) {
        if (p + 1 >= end) break;
        *p++ = '\\';
      }
      *p++ = (char)*m++;
      continue;
    }

    if (*m == '*') {
      if (p + 2 > end) break;
      *p++ = '.'; *p++ = '*';
      while (*m == '*') m++; /* collapse consecutive */
      continue;
    }

    if (*m == '?') {
      *p++ = '.';
      m++;
      continue;
    }

    if (per_mode && *m == '%') {
      /* [^ ]* — 0+ non-space chars */
      if (p + 5 > end) break;
      *p++ = '['; *p++ = '^'; *p++ = ' '; *p++ = ']'; *p++ = '*';
      while (*m == '%') m++;
      continue;
    }

    if (per_mode && *m == '~') {
      /* [ ]+ — 1+ space chars */
      if (p + 4 > end) break;
      *p++ = '['; *p++ = ' '; *p++ = ']'; *p++ = '+';
      while (*m == '~' || *m == ' ') m++;
      continue;
    }

    /* literal character — escape regex metacharacters */
    if (strchr(regex_meta, (char)*m)) {
      if (p + 1 >= end) break;
      *p++ = '\\';
    }
    *p++ = (char)*m++;
  }

  *p++ = '$';
  *p = '\0';
  return (int)(p - out);
}

/* Generic string matching, use addr_match() for hostmasks! */
int _wild_match(unsigned char *m, unsigned char *n)
{
  char ere[1024];

  if (!m || !n || !*m || !*n) return 0;

  if (irc_to_ere(m, ere, sizeof ere, false) < 0) return 0;

  op_regex_t *re = op_regex_compile(ere, OP_REGEX_ICASE, nullptr, 0);
  if (!re) return 0;
  int result = op_regex_match(re, (const char *)n) ? 1 : 0;
  op_regex_free(re);
  return result;
}

/* Wildcard-matches mask m to n, with extended wildcards (%, ~, \).
 * cmp1/cmp2 and chgpoint are accepted for API compatibility; the match
 * is always performed case-insensitively via op_regex (OP_REGEX_ICASE).
 */
int _wild_match_per(unsigned char *m, unsigned char *n,
                    int (*cmp1)(unsigned char, unsigned char),
                    int (*cmp2)(unsigned char, unsigned char),
                    unsigned char *chgpoint)
{
  char ere[1024];
  (void)cmp1; (void)cmp2; (void)chgpoint;

  if (!m || !n || !*n || !cmp1) return 0;

  if (irc_to_ere(m, ere, sizeof ere, true) < 0) return 0;

  op_regex_t *re = op_regex_compile(ere, OP_REGEX_ICASE, nullptr, 0);
  if (!re) return 0;
  int result = op_regex_match(re, (const char *)n) ? 1 : 0;
  op_regex_free(re);
  return result;
}

/* cidr and RFC1459 compatible host matching
 * Returns: 1 if the address in n matches the hostmask in m.
 * If cmp != 0, m and n will be compared as masks. Returns 1
 * if m is broader, 0 otherwise.
 * If user != 0, the masks are eggdrop user hosts and should
 * be matched regardless of the cidr_support variable.
 * This is required as userhost matching shouldn't depend on
 * server support of cidr.
 */
int addr_match(const char *m, const char *n, int user, int cmp)
{
  char *p, *q, *r = 0, *s = 0;
  char mu[UHOSTLEN], nu[UHOSTLEN];
  int tmpscore, score = 0;

  /* copy the strings into our own buffers
     and convert to rfc uppercase */
  for (p = mu; *m && (p - mu < UHOSTLEN - 1); m++) {
    if (*m == '@')
      r = p;
    *p++ = rfc_toupper(*m);
  }
  for (q = nu; *n && (q - nu < UHOSTLEN - 1); n++) {
    if (*n == '@')
      s = q;
    *q++ = rfc_toupper(*n);
  }
  *p = *q = 0;
  if ((!user && !cidr_support) || !r || !s)
    return wild_match(mu, nu);

  *r++ = *s++ = 0;
  if (!(tmpscore = wild_match(mu, nu)))
    return NOMATCH; /* nick!ident parts don't match */
  score += tmpscore;
  if (!*r && !*s)
    return score; /* end of nonempty strings */

  /* check for CIDR notation and perform
     generic string matching if not found */
  if (!(p = strrchr(r, '/')) || !str_isdigit(p + 1)) {
    tmpscore = wild_match(r, s);
    if (!tmpscore)
      return NOMATCH;
    score += tmpscore;
    return score;
  }

  /* if the two strings are both cidr masks,
     use the broader prefix */
  if (cmp && (q = strrchr(s, '/')) && str_isdigit(q + 1)) {
    if (egg_atoi(p + 1) > egg_atoi(q + 1))
      return NOMATCH;
    *q = 0;
  }
  *p = 0;
  /* looks like a cidr mask */
  if (!(tmpscore = cidr_match(r, s, egg_atoi(p + 1))))
    return NOMATCH;
  score += tmpscore;
  return score;
}

/* Checks for overlapping masks
 * Returns: > 0 if the two masks in m and n overlap, 0 otherwise.
 */
int mask_match(char *m, char *n)
{
  int prefix;
  char *p, *q, *r = 0, *s = 0;
  char mu[UHOSTLEN], nu[UHOSTLEN];

  for (p = mu; *m && (p - mu < UHOSTLEN - 1); m++) {
    if (*m == '@')
      r = p;
    *p++ = rfc_toupper(*m);
  }
  for (q = nu; *n && (q - nu < UHOSTLEN - 1); n++) {
    if (*n == '@')
      s = q;
    *q++ = rfc_toupper(*n);
  }
  *p = *q = 0;
  if (!cidr_support || !r || !s)
    return (wild_match(mu, nu) || wild_match(nu, mu));

  *r++ = *s++ = 0;
  if (!wild_match(mu, nu) && !wild_match(nu, mu))
    return 0;

  if (!*r && !*s)
    return 1;
  p = strrchr(r, '/');
  q = strrchr(s, '/');
  if ((!p || !str_isdigit(p + 1)) && (!q || !str_isdigit(q + 1)))
    return (wild_match(r, s) || wild_match(s, r));

  if (p) {
    *p = 0;
    prefix = egg_atoi(p + 1);
  } else
    prefix = (strchr(r, ':') ? 128 : 32);
  if (q) {
    *q = 0;
    if (egg_atoi(q + 1) < prefix)
      prefix = egg_atoi(q + 1);
  }
  return cidr_match(r, s, prefix);
}

/* Bitwise comparison of two binary IP addresses.
 * Returns 1 if the first `mask` bits are identical, 0 otherwise.
 * Handles both IPv4 (4 bytes) and IPv6 (16 bytes) transparently.
 */
static int comp_with_mask(const void *addr, const void *dest, unsigned int mask)
{
  if (memcmp(addr, dest, mask / 8) != 0)
    return 0;
  if (mask % 8 == 0)
    return 1;
  unsigned int n = mask / 8;
  unsigned char m = (unsigned char)(0xFF << (8 - (mask % 8)));
  return ((((const unsigned char *)addr)[n] & m) ==
          (((const unsigned char *)dest)[n] & m));
}

/* Performs bitwise comparison of two IP addresses stored in presentation
 * (string) format. IPs are first internally converted to binary form.
 * Returns: count if the first count bits are equal, 0 otherwise.
 */
int cidr_match(char *m, char *n, int count)
{
  uint8_t block[16], addr[16];
  int af, maxbits;

  if (strchr(m, ':') || strchr(n, ':')) {
    af = AF_INET6;
    maxbits = 128;
  } else {
    af = AF_INET;
    maxbits = 32;
  }

  if (count > maxbits)
    return NOMATCH;
  if (op_inet_pton(af, m, block) != 1 ||
      op_inet_pton(af, n, addr) != 1)
    return NOMATCH;
  if (count < 1)
    return 1;
  return comp_with_mask(addr, block, (unsigned int)count) ? count : 0;
}

/* Collapse consecutive '*' wildcards in a pattern in-place.
 * Returns pattern.
 */
char *collapse(char *pattern)
{
  char *p = pattern, *po = pattern;
  bool star = false;

  if (!p)
    return nullptr;
  for (char c; (c = *p++);) {
    if (c == '*') {
      if (!star)
        *po++ = '*';
      star = true;
    } else {
      *po++ = c;
      star = false;
    }
  }
  *po = '\0';
  return pattern;
}

/* Like collapse(), but respects backslash-quoting. */
char *collapse_esc(char *pattern)
{
  char *p = pattern, *po = pattern;
  bool star = false, esc = false;

  if (!p)
    return nullptr;
  for (char c; (c = *p++);) {
    if (!esc && c == '*') {
      if (!star)
        *po++ = '*';
      star = true;
    } else if (!esc && c == '\\') {
      *po++ = '\\';
      esc = true;
    } else {
      *po++ = c;
      star = false;
      esc  = false;
    }
  }
  *po = '\0';
  return pattern;
}

/* Inline for cron_match (obviously).
 * Matches a single field of a crontab expression.
 */
static int cron_matchfld(char *mask, int match)
{
  int skip = 0, f, t;
  char *p, *q;

  for (; mask && *mask; mask = p) {
    /* loop through a list of values, if such is given */
    if ((p = strchr(mask, ',')))
      *p++ = 0;
    /* check for the step operator */
    if ((q = strchr(mask, '/'))) {
      if (q == mask)
        continue;
      *q++ = 0;
      skip = egg_atoi(q);
    }
    if (!strcmp(mask, "*") && (!skip || !(match % skip)))
      return 1;
    /* ranges, e.g 10-20 */
    if (strchr(mask, '-')) {
      if (sscanf(mask, "%d-%d", &f, &t) != 2)
        continue;
      if (t < f) {
        if (match <= t)
          match += 60;
        t += 60;
      }
      if ((match >= f && match <= t) &&
          (!skip || !((match - f) % skip)))
        return 1;
    }
    /* no operator found, should be exact match */
    f = strtol(mask, &q, 10);
    if ((q > mask) &&
        (skip ? !((match - f) % skip) : (match == f)))
      return 1;
  }
  return 0;
}

/* Check if the current time matches a crontab-like specification.
 *
 * mask contains a cron-style series of time fields. The following
 * crontab operators are supported: ranges '-', asterisks '*',
 * lists ',' and steps '/'.
 * match must have 5 space separated integers representing in order
 * the current minute, hour, day of month, month and weekday.
 * It should look like this: "53 17 01 03 06", which means
 * Sunday 01 March, 17:53.
 */
int cron_match(const char *mask, const char *match)
{
  int d = 0, i, m = 1, t[5];
  char *p, *q, *buf;

  if (!mask[0])
    return 0;
  if (sscanf(match, "%d %d %d %d %d",
             &t[0], &t[1], &t[2], &t[3], &t[4]) < 5)
    return 0;
  buf = op_strdup(mask);
  for (p = buf, i = 0; *p && i < 5; i++) {
    q = newsplit(&p);
    if (!strcmp(q, "*"))
      continue;
    m = (cron_matchfld(q, t[i]) ||
        (i == 4 && !t[i] && cron_matchfld(q, 7)));
    if (i == 2)
      d = m;
    else if (!m || (i == 3 && d))
      break;
  }
  op_free(buf);
  return m;
}

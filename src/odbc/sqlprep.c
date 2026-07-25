/* SQL statement preprocessing - see sqlprep.h. Pure string transforms.
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0 */
#include "sqlprep.h"

#include "compat.h"

#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

/* Find the '}' that closes the '{' at `p` (quote- and nesting-aware). */
static const char *find_close_brace(const char *p)
{
    int depth = 0;
    char quote = 0;
    for (const char *s = p; *s != '\0'; s++) {
        if (quote) {
            if (*s == quote) quote = 0;
        } else if (*s == '\'' || *s == '"') {
            quote = *s;
        } else if (*s == '{') {
            depth++;
        } else if (*s == '}') {
            if (--depth == 0)
                return s;
        }
    }
    return NULL;
}

/* A small growable string. */
typedef struct { char *b; size_t len, cap; } Buf;
static int buf_put(Buf *x, const char *s, size_t n)
{
    if (x->len + n + 1 > x->cap) {
        size_t nc = x->cap ? x->cap : 64;
        while (nc < x->len + n + 1) nc *= 2;
        char *p = realloc(x->b, nc);
        if (p == NULL) return -1;
        x->b = p;
        x->cap = nc;
    }
    memcpy(x->b + x->len, s, n);
    x->len += n;
    x->b[x->len] = '\0';
    return 0;
}

/* Map a few ODBC {fn} scalar-function names to their Oracle spellings; others
 * pass through unchanged (most match). */
static const char *fn_alias(const char *name, size_t n)
{
    static const struct { const char *odbc, *ora; } map[] = {
        { "UCASE", "UPPER" }, { "LCASE", "LOWER" }, { "SUBSTRING", "SUBSTR" },
        { "IFNULL", "NVL" }, { "CEILING", "CEIL" }, { "TRUNCATE", "TRUNC" },
    };
    for (size_t i = 0; i < sizeof map / sizeof map[0]; i++)
        if (strlen(map[i].odbc) == n && strncasecmp(name, map[i].odbc, n) == 0)
            return map[i].ora;
    return NULL;
}

static char *inline_escapes(const char *in);   /* recursion */

/* Append the translation of one escape body (content between { and }, with the
 * leading keyword already identified) to `out`. */
static int emit_escape(Buf *out, const char *kw, size_t kwlen,
                       const char *rest, size_t restlen)
{
    /* Trim surrounding whitespace of the remainder. */
    while (restlen > 0 && isspace((unsigned char)*rest)) { rest++; restlen--; }
    while (restlen > 0 && isspace((unsigned char)rest[restlen - 1])) restlen--;

    if (kwlen == 2 && strncasecmp(kw, "ts", 2) == 0)
        return buf_put(out, "TIMESTAMP ", 10) || buf_put(out, rest, restlen);
    if (kwlen == 1 && (kw[0] == 'd' || kw[0] == 'D'))
        return buf_put(out, "DATE ", 5) || buf_put(out, rest, restlen);
    if (kwlen == 1 && (kw[0] == 't' || kw[0] == 'T'))   /* time -> dummy-dated */
        return buf_put(out, "TO_DATE(", 8) || buf_put(out, rest, restlen)
            || buf_put(out, ",'HH24:MI:SS')", 14);
    if (kwlen == 6 && strncasecmp(kw, "escape", 6) == 0)
        return buf_put(out, "ESCAPE ", 7) || buf_put(out, rest, restlen);
    if ((kwlen == 2 && strncasecmp(kw, "fn", 2) == 0) ||
        (kwlen == 2 && strncasecmp(kw, "oj", 2) == 0)) {
        char *tmp = seer_strndup(rest, restlen);
        if (tmp == NULL) return -1;
        char *inner = inline_escapes(tmp);    /* recurse (nested escapes) */
        free(tmp);
        if (inner == NULL) return -1;
        int rc = 0;
        if (kwlen == 2 && strncasecmp(kw, "fn", 2) == 0) {
            size_t id = 0;                     /* leading function identifier */
            while (inner[id] && (isalnum((unsigned char)inner[id]) || inner[id] == '_'))
                id++;
            const char *alias = fn_alias(inner, id);
            if (alias != NULL)
                rc = buf_put(out, alias, strlen(alias)) || buf_put(out, inner + id, strlen(inner + id));
            else
                rc = buf_put(out, inner, strlen(inner));
        } else {
            rc = buf_put(out, inner, strlen(inner));
        }
        free(inner);
        return rc;
    }
    /* Unknown escape: emit the original braces verbatim. */
    return buf_put(out, "{", 1) || buf_put(out, kw, kwlen)
        || (restlen ? (buf_put(out, " ", 1) || buf_put(out, rest, restlen)) : 0)
        || buf_put(out, "}", 1);
}

/* Translate inline ODBC escapes ({ts}/{d}/{t}/{fn}/{oj}/{escape}) anywhere in
 * the text, quote- and nesting-aware. */
static char *inline_escapes(const char *in)
{
    Buf out = { 0 };
    char quote = 0;
    for (const char *p = in; *p != '\0'; ) {
        char c = *p;
        if (quote) {
            buf_put(&out, p, 1);
            if (c == quote) quote = 0;
            p++;
        } else if (c == '\'' || c == '"') {
            quote = c;
            buf_put(&out, p, 1);
            p++;
        } else if (c == '{') {
            const char *close = find_close_brace(p);
            if (close == NULL) { buf_put(&out, p, 1); p++; continue; }
            const char *k = p + 1;
            while (isspace((unsigned char)*k)) k++;
            const char *kend = k;
            while (kend < close && (isalpha((unsigned char)*kend))) kend++;
            size_t kwlen = (size_t)(kend - k);
            if (kwlen > 0 && strncasecmp(k, "call", 4) != 0)
                emit_escape(&out, k, kwlen, kend, (size_t)(close - kend));
            else
                buf_put(&out, p, (size_t)(close - p + 1));   /* leave {call}/unknown */
            p = close + 1;
        } else {
            buf_put(&out, p, 1);
            p++;
        }
    }
    if (out.b == NULL)
        return strdup(in);
    return out.b;
}

/* Translate the ODBC {call ...} / {?=call ...} statement escape into an Oracle
 * PL/SQL block, then any inline escapes. Non-call text just gets inline
 * translation. */
static char *translate_escapes(const char *in)
{
    const char *p = in;
    while (*p != '\0' && isspace((unsigned char)*p)) p++;
    if (*p != '{')
        return inline_escapes(in);

    const char *close = find_close_brace(p);
    if (close == NULL)
        return inline_escapes(in);

    const char *q = p + 1;
    while (isspace((unsigned char)*q)) q++;
    bool has_return = false;
    if (*q == '?') {                       /* {? = call func(...)} */
        has_return = true;
        q++;
        while (isspace((unsigned char)*q)) q++;
        if (*q == '=') q++;
        while (isspace((unsigned char)*q)) q++;
    }
    if (strncasecmp(q, "call", 4) != 0 ||
        !(q[4] == '\0' || isspace((unsigned char)q[4]) || q[4] == '('))
        return inline_escapes(in);         /* not a call escape */

    q += 4;
    while (isspace((unsigned char)*q)) q++;
    size_t blen = (size_t)(close - q);
    while (blen > 0 && isspace((unsigned char)q[blen - 1])) blen--;

    char *res = malloc(blen + 32);
    if (res == NULL)
        return NULL;
    int o = sprintf(res, "BEGIN %s", has_return ? "? := " : "");
    memcpy(res + o, q, blen);
    o += (int)blen;
    sprintf(res + o, "; END;");

    char *full = inline_escapes(res);      /* handle {ts}/{d}/... inside the call */
    free(res);
    return full;
}

/* Rewrite ODBC '?' parameter markers to Oracle positional binds :1, :2, ...
 * (Oracle rejects '?'). Markers inside string/quoted-identifier literals are
 * left alone. */
static char *rewrite_params(const char *in)
{
    size_t n = strlen(in);
    char  *out = malloc(n * 6 + 1);   /* worst case '?' -> ':NNNNN' */
    if (out == NULL)
        return NULL;
    size_t o = 0;
    int    pnum = 0;
    char   quote = 0;
    for (size_t i = 0; i < n; i++) {
        char c = in[i];
        if (quote) {
            out[o++] = c;
            if (c == quote) quote = 0;
        } else if (c == '\'' || c == '"') {
            quote = c;
            out[o++] = c;
        } else if (c == '?') {
            o += (size_t)sprintf(out + o, ":%d", ++pnum);
        } else {
            out[o++] = c;
        }
    }
    out[o] = '\0';
    return out;
}

char *seer_sql_prepare(const char *raw)
{
    char *esc = translate_escapes(raw);
    if (esc == NULL)
        return NULL;
    char *out = rewrite_params(esc);
    free(esc);
    return out;
}

/* Word match: `kw` at `p`, case-insensitive, followed by a non-identifier. */
static int kw_at(const char *p, const char *kw)
{
    size_t n = strlen(kw);
    if (strncasecmp(p, kw, n) != 0)
        return 0;
    char c = p[n];
    return !(isalnum((unsigned char)c) || c == '_' || c == '$' || c == '#');
}

/* Skip a dotted identifier (a[.b], each part a word or "quoted"); return the
 * end, and the start of the LAST part in *last (the unqualified name). */
static const char *skip_dotted_ident(const char *p, const char **last)
{
    *last = p;
    for (;;) {
        if (*p == '"') { p++; while (*p && *p != '"') p++; if (*p == '"') p++; }
        else if (isalpha((unsigned char)*p) || *p == '_') {
            while (isalnum((unsigned char)*p) || *p == '_' || *p == '$' || *p == '#') p++;
        } else break;
        if (*p == '.') { p++; *last = p; } else break;
    }
    return p;
}

/* True if `s` carries a top-level (depth 0, outside literals) FOR UPDATE. */
static int has_for_update(const char *s)
{
    int depth = 0;
    char q = 0;
    for (const char *c = s; *c; c++) {
        if (q) { if (*c == q) q = 0; continue; }
        if (*c == '\'' || *c == '"') { q = *c; continue; }
        if (*c == '(') depth++;
        else if (*c == ')') depth--;
        else if (depth == 0 && (c == s || !isalnum((unsigned char)c[-1])) &&
                 kw_at(c, "FOR")) {
            const char *u = c + 3;
            while (isspace((unsigned char)*u)) u++;
            if (kw_at(u, "UPDATE"))
                return 1;
        }
    }
    return 0;
}

char *seer_sql_make_updatable(const char *sql, char **table, int lock)
{
    *table = NULL;
    const char *p = sql;
    while (isspace((unsigned char)*p)) p++;
    if (!kw_at(p, "SELECT"))
        return NULL;
    p += 6;
    while (isspace((unsigned char)*p)) p++;
    if (kw_at(p, "DISTINCT") || kw_at(p, "UNIQUE"))
        return NULL;

    const char *sel_start = p;
    /* Find the top-level FROM (depth 0, outside string/identifier literals). */
    const char *from = NULL;
    int depth = 0;
    char q = 0;
    for (const char *c = p; *c; c++) {
        if (q) { if (*c == q) q = 0; continue; }
        if (*c == '\'' || *c == '"') { q = *c; continue; }
        if (*c == '(') depth++;
        else if (*c == ')') depth--;
        else if (depth == 0 && (*c == ' ' || *c == '\t' || *c == '\n' || *c == '(')
                 && kw_at(c + 1, "FROM")) { from = c + 1; break; }
    }
    if (from == NULL)
        return NULL;
    const char *sel_end = from;                       /* select list is [sel_start, sel_end) */

    /* Reject set operators anywhere at depth 0 (UNION/MINUS/INTERSECT). */
    q = 0; depth = 0;
    for (const char *c = sql; *c; c++) {
        if (q) { if (*c == q) q = 0; continue; }
        if (*c == '\'' || *c == '"') { q = *c; continue; }
        if (*c == '(') depth++;
        else if (*c == ')') depth--;
        else if (depth == 0 && (c == sql || !isalnum((unsigned char)c[-1])) &&
                 (kw_at(c, "UNION") || kw_at(c, "MINUS") || kw_at(c, "INTERSECT")))
            return NULL;
    }

    /* Parse the single table reference after FROM. */
    const char *t = from + 4;
    while (isspace((unsigned char)*t)) t++;
    if (*t == '(')                                    /* subquery / derived table */
        return NULL;
    const char *tbl_last = NULL;
    const char *tbl_start = t;
    const char *tbl_end = skip_dotted_ident(t, &tbl_last);
    if (tbl_end == t)
        return NULL;                                  /* no identifier */
    char *base = seer_strndup(tbl_start, (size_t)(tbl_end - tbl_start));

    /* Optional alias, then the next token must end the single-table FROM. */
    const char *a = tbl_end;
    while (isspace((unsigned char)*a)) a++;
    const char *ref_start = tbl_last;                 /* unqualified table for *-qualify */
    const char *ref_end   = tbl_end;
    if (*a != '\0' && *a != ',' && !kw_at(a, "WHERE") && !kw_at(a, "ORDER") &&
        !kw_at(a, "GROUP") && !kw_at(a, "HAVING") && !kw_at(a, "CONNECT") &&
        !kw_at(a, "START") && !kw_at(a, "FOR") && !kw_at(a, "JOIN") &&
        (isalpha((unsigned char)*a) || *a == '"')) {
        const char *al_last;
        const char *al_end = skip_dotted_ident(a, &al_last);
        ref_start = a; ref_end = al_end;              /* alias qualifies '*' / nothing */
        a = al_end;
        while (isspace((unsigned char)*a)) a++;
    }
    /* After table[+alias] only a clause keyword or end may follow. */
    if (!(*a == '\0' || kw_at(a, "WHERE") || kw_at(a, "ORDER") || kw_at(a, "CONNECT") ||
          kw_at(a, "START") || kw_at(a, "FOR"))) {
        free(base);
        return NULL;                                  /* comma/join/group/having/... */
    }

    /* Build: SELECT <sel'> , ROWIDTOCHAR(ROWID) <from...>. A bare '*' select
     * list is qualified with the table/alias so '*,' stays valid. */
    int   star = 0;
    const char *ss = sel_start;
    while (isspace((unsigned char)*ss)) ss++;
    if (*ss == '*') {
        const char *after = ss + 1;
        while (isspace((unsigned char)*after)) after++;
        if (after == sel_end) star = 1;
    }
    size_t cap = strlen(sql) + (size_t)(ref_end - ref_start) + 64;
    char  *out = malloc(cap);
    if (out == NULL) { free(base); return NULL; }
    int o = snprintf(out, cap, "SELECT ");
    if (star) {
        o += snprintf(out + o, cap - o, "%.*s.*",
                      (int)(ref_end - ref_start), ref_start);
    } else {
        o += snprintf(out + o, cap - o, "%.*s",
                      (int)(sel_end - sel_start), sel_start);
    }
    o += snprintf(out + o, cap - o, ", ROWIDTOCHAR(ROWID) %s", from);
    /* Pessimistic concurrency (SQL_CONCUR_LOCK): lock the fetched rows unless
     * the caller already asked for it. The single-table-SELECT shape we accept
     * above is exactly what FOR UPDATE allows. */
    if (lock && !has_for_update(out))
        o += snprintf(out + o, cap - o, " FOR UPDATE");
    *table = base;
    return out;
}

int seer_sql_count_params(const char *sql)
{
    if (sql == NULL)
        return 0;
    char seen[256][64];
    int  nseen = 0;
    char quote = 0;
    for (const char *p = sql; *p != '\0'; ) {
        char c = *p;
        if (quote) {
            if (c == quote) quote = 0;
            p++;
        } else if (c == '\'' || c == '"') {
            quote = c;
            p++;
        } else if (c == '-' && p[1] == '-') {
            while (*p != '\0' && *p != '\n') p++;
        } else if (c == '/' && p[1] == '*') {
            p += 2;
            while (*p != '\0' && !(*p == '*' && p[1] == '/')) p++;
            if (*p != '\0') p += 2;
        } else if (c == ':' && p[1] != ':' && p[1] != '=') {
            p++;                                   /* consume ':' */
            char tok[64];
            int  tl = 0;
            if (*p == '"') {                       /* :"Quoted Name" */
                p++;
                while (*p != '\0' && *p != '"' && tl < 63) tok[tl++] = *p++;
                if (*p == '"') p++;
            } else if (isdigit((unsigned char)*p)) {
                while (isdigit((unsigned char)*p) && tl < 63) tok[tl++] = *p++;
            } else if (isalpha((unsigned char)*p) || *p == '_') {
                while ((isalnum((unsigned char)*p) || *p == '_' || *p == '$' || *p == '#')
                       && tl < 63)
                    tok[tl++] = *p++;
            }
            tok[tl] = '\0';
            if (tl > 0) {
                int found = 0;
                for (int i = 0; i < nseen; i++)
                    if (strcasecmp(seen[i], tok) == 0) { found = 1; break; }
                if (!found && nseen < 256) {
                    memcpy(seen[nseen], tok, (size_t)tl + 1);
                    nseen++;
                }
            }
        } else {
            p++;
        }
    }
    return nseen;
}

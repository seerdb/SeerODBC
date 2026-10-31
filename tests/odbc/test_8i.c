/* Oracle 8i (8.1.7) core-API integration test (seerdb PROTOCOL.md §19.8-19.10).
 * LOCAL ONLY, like test_9i: 8i runs as a VM, so tests/odbc/run-matrix.sh runs
 * this against it and it is not a meson test(). Exit 0 with a skip when the
 * server is unreachable.
 *
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "seer/seertns.h"

static int pass_n, fail_n, skip_n;
static void pass(const char *n)
{
  printf("  PASS %s\n", n);
  pass_n++;
}
static void fail(const char *n, const char *w)
{
  printf("  FAIL %s: %s\n", n, w);
  fail_n++;
}

static SeerConn *C;

/* Run a query; return its row count (-1 on failure) and copy row `r`, column
 * `col` into `out` (empty when NULL or absent). */
static long query(const char *sql, long r, int col, char *out, size_t osz)
{
  if (out != NULL)
    out[0] = '\0';
  SeerStmt *s = NULL;
  long rows = -1;
  if (seer_stmt_prepare(C, sql, &s) == SEER_OK && seer_stmt_execute(s) == SEER_OK) {
    rows = 0;
    while (seer_stmt_fetch(s) == SEER_OK) {
      if (rows == r && out != NULL) {
        const char *v = NULL;
        int isn = 0;
        if (seer_stmt_get_string(s, col, &v, &isn) == SEER_OK && v != NULL)
          snprintf(out, osz, "%s", v);
      }
      rows++;
    }
  }
  seer_stmt_close(s);
  return rows;
}

static void check_scalar_types(void)
{
  const char *name = "SELECT NUMBER / VARCHAR2 / CHAR / DATE / decimal";
  char a[64], b[64], c[64], d[64], e[64];
  long n = query("SELECT 42, 'hello', CAST('ab' AS CHAR(4)), "
                 "TO_DATE('2026-02-28 13:45:06', 'YYYY-MM-DD HH24:MI:SS'), -3.25 FROM dual",
                 0, 0, a, sizeof a);
  query("SELECT 42, 'hello' FROM dual", 0, 1, b, sizeof b);
  query("SELECT CAST('ab' AS CHAR(4)) FROM dual", 0, 0, c, sizeof c);
  query("SELECT TO_DATE('2026-02-28 13:45:06', 'YYYY-MM-DD HH24:MI:SS') FROM dual", 0, 0, d,
        sizeof d);
  query("SELECT -3.25 FROM dual", 0, 0, e, sizeof e);
  if (n == 1 && strcmp(a, "42") == 0 && strcmp(b, "hello") == 0 && strcmp(c, "ab  ") == 0 &&
      strcmp(d, "2026-02-28 13:45:06") == 0 && strcmp(e, "-3.25") == 0)
    pass(name);
  else {
    char m[400];
    snprintf(m, sizeof m, "rows=%ld '%s' '%s' '%s' '%s' '%s'", n, a, b, c, d, e);
    fail(name, m);
  }
}

static void check_nulls_and_empty(void)
{
  const char *name = "NULL cells and an empty result";
  char a[16] = "x", b[16];
  SeerStmt *s = NULL;
  int isn0 = 0, isn2 = 0;
  if (seer_stmt_prepare(C, "SELECT NULL, 'x', TO_NUMBER(NULL) FROM dual", &s) == SEER_OK &&
      seer_stmt_execute(s) == SEER_OK && seer_stmt_fetch(s) == SEER_OK) {
    const char *v = NULL;
    seer_stmt_get_string(s, 0, &v, &isn0);
    seer_stmt_get_string(s, 1, &v, &isn2);
    snprintf(a, sizeof a, "%s", v ? v : "");
    seer_stmt_get_string(s, 2, &v, &isn2);
  }
  seer_stmt_close(s);
  long empty = query("SELECT 1 FROM dual WHERE 1 = 0", 0, 0, b, sizeof b);
  if (isn0 && isn2 && strcmp(a, "x") == 0 && empty == 0)
    pass(name);
  else {
    char m[128];
    snprintf(m, sizeof m, "null0=%d null2=%d mid='%s' empty=%ld", isn0, isn2, a, empty);
    fail(name, m);
  }
}

/* 250 rows over three fetches; the constant column repeats, so 8i omits it
 * from rows (the row header's bit vector), across batch boundaries too. */
static void check_multibatch(void)
{
  const char *name = "250 rows across fetch batches, repeated columns";
  SeerStmt *s = NULL;
  long rows = 0, bad = 0;
  if (seer_stmt_prepare(C,
                        "SELECT ROWNUM, 'tail', MOD(ROWNUM, 3) FROM all_objects "
                        "WHERE ROWNUM <= 250",
                        &s) == SEER_OK &&
      seer_stmt_execute(s) == SEER_OK) {
    while (seer_stmt_fetch(s) == SEER_OK) {
      const char *a = NULL, *t = NULL, *m = NULL;
      int isn = 0;
      seer_stmt_get_string(s, 0, &a, &isn);
      seer_stmt_get_string(s, 1, &t, &isn);
      seer_stmt_get_string(s, 2, &m, &isn);
      rows++;
      if (a == NULL || atol(a) != rows || t == NULL || strcmp(t, "tail") != 0 || m == NULL ||
          atol(m) != rows % 3)
        bad++;
    }
  }
  seer_stmt_close(s);
  if (rows == 250 && bad == 0)
    pass(name);
  else {
    char m[96];
    snprintf(m, sizeof m, "rows=%ld bad=%ld", rows, bad);
    fail(name, m);
  }
}

/* V$SESSION's 45 columns describe past one 2 KB packet, unmarked. */
static void check_wide_describe(void)
{
  const char *name = "describe across packets (V$SESSION)";
  SeerStmt *s = NULL;
  int ncols = 0;
  long rows = 0;
  if (seer_stmt_prepare(C, "SELECT * FROM v$session WHERE ROWNUM <= 3", &s) == SEER_OK &&
      seer_stmt_execute(s) == SEER_OK) {
    ncols = seer_stmt_num_cols(s);
    while (seer_stmt_fetch(s) == SEER_OK)
      rows++;
  }
  seer_stmt_close(s);
  if (ncols >= 40 && rows == 3)
    pass(name);
  else {
    char m[64];
    snprintf(m, sizeof m, "ncols=%d rows=%ld", ncols, rows);
    fail(name, m);
  }
}

static void check_errors(void)
{
  const char *name = "errors: refused query, describe cut short, then recovery";
  SeerStmt *s = NULL;
  char e1[128] = "", e2[128] = "", e3[128] = "", ok[16];
  if (seer_stmt_prepare(C, "SELECT * FROM no_such_table_8i", &s) == SEER_OK &&
      seer_stmt_execute(s) != SEER_OK && seer_last_error(C))
    snprintf(e1, sizeof e1, "%s", seer_last_error(C));
  seer_stmt_close(s);
  s = NULL;
  /* 8i has no USERENV SID: the describe stops partway and the error follows */
  if (seer_stmt_prepare(C, "SELECT * FROM v$session WHERE sid = sys_context('userenv','sid')",
                        &s) == SEER_OK &&
      seer_stmt_execute(s) != SEER_OK && seer_last_error(C))
    snprintf(e2, sizeof e2, "%s", seer_last_error(C));
  seer_stmt_close(s);
  s = NULL;
  if (seer_stmt_prepare(C, "SELECT 1 / 0 FROM dual", &s) == SEER_OK &&
      seer_stmt_execute(s) != SEER_OK && seer_last_error(C))
    snprintf(e3, sizeof e3, "%s", seer_last_error(C));
  seer_stmt_close(s);
  query("SELECT 'alive' FROM dual", 0, 0, ok, sizeof ok);
  if (strncmp(e1, "ORA-00942", 9) == 0 && strncmp(e2, "ORA-02003", 9) == 0 &&
      strncmp(e3, "ORA-01476", 9) == 0 && strcmp(ok, "alive") == 0)
    pass(name);
  else {
    char m[480];
    snprintf(m, sizeof m, "'%s' / '%s' / '%s' / '%s'", e1, e2, e3, ok);
    fail(name, m);
  }
}

/* 8i's session charset is WE8ISO8859P1: Latin-1 text reads back as UTF-8, and
 * the SQL text goes out in Latin-1. */
static void check_latin1(void)
{
  const char *name = "Latin-1 text both ways";
  char a[32], b[32];
  query("SELECT CHR(252) || 'ber' FROM dual", 0, 0, a, sizeof a);
  query("SELECT LENGTH('\xc3\xa9t\xc3\xa9') || ASCII(SUBSTR('\xc3\xa9', 1, 1)) FROM dual", 0, 0, b,
        sizeof b);
  if (strcmp(a, "\xc3\xbc"
                "ber") == 0 &&
      strcmp(b, "3233") == 0)
    pass(name);
  else {
    char m[96];
    snprintf(m, sizeof m, "'%s' / '%s'", a, b);
    fail(name, m);
  }
}

/* SQL text past 64 bytes goes in 64-byte chunks, and its length past 255 as
 * the fixed ub4 (a variable-width one draws ORA-01009). */
static void check_long_sql(void)
{
  const char *name = "300-byte SQL text";
  char sql[512] = "SELECT ";
  for (int i = 1; i <= 100; i++) {
    char item[8];
    snprintf(item, sizeof item, "%s%d", i > 1 ? "+" : "", i);
    strncat(sql, item, sizeof sql - strlen(sql) - 1);
  }
  strncat(sql, " FROM dual", sizeof sql - strlen(sql) - 1);
  char v[16];
  query(sql, 0, 0, v, sizeof v);
  if (strlen(sql) > 255 && strcmp(v, "5050") == 0)
    pass(name);
  else {
    char m[64];
    snprintf(m, sizeof m, "len=%zu got '%s'", strlen(sql), v);
    fail(name, m);
  }
}

static void check_rowid(void)
{
  const char *name = "ROWID column";
  char r[32], back[16];
  query("SELECT ROWID FROM dual", 0, 0, r, sizeof r);
  char sql[96];
  snprintf(sql, sizeof sql, "SELECT 'found' FROM dual WHERE ROWID = '%s'", r);
  query(sql, 0, 0, back, sizeof back);
  if (strlen(r) == 18 && strcmp(back, "found") == 0)
    pass(name);
  else {
    char m[80];
    snprintf(m, sizeof m, "rowid='%s' back='%s'", r, back);
    fail(name, m);
  }
}

/* Every statement's cursor is closed (piggybacked on the next call); left
 * open, a session runs out at open_cursors with ORA-01000. */
static void check_cursor_hygiene(void)
{
  const char *name = "300 queries in one session (cursors closed)";
  long ok = 0;
  char v[16];
  for (int i = 0; i < 300; i++)
    if (query("SELECT 1 FROM dual", 0, 0, v, sizeof v) == 1 && strcmp(v, "1") == 0)
      ok++;
  if (ok == 300)
    pass(name);
  else {
    char m[96];
    snprintf(m, sizeof m, "%ld/300 succeeded (%s)", ok,
             seer_last_error(C) ? seer_last_error(C) : "");
    fail(name, m);
  }
}

int main(void)
{
  const char *port = getenv("SEER_TEST_PORT");
  SeerConnParams p = {
      .host = getenv("SEER_TEST_HOST"),
      .port = (uint16_t)(port ? atoi(port) : 1521),
      .service_name = getenv("SEER_TEST_SERVICE"),
      .username = getenv("SEER_TEST_USER"),
      .password = getenv("SEER_TEST_PASS"),
  };
  if (p.host == NULL || seer_connect(&p, &C) != SEER_OK) {
    printf("  SKIP 8i: not reachable (%s)\n",
           seer_last_error(NULL) ? seer_last_error(NULL) : "connect failed");
    printf("SUMMARY pass=0 fail=0 skip=1\n");
    return 0;
  }
  check_scalar_types();
  check_nulls_and_empty();
  check_multibatch();
  check_wide_describe();
  check_errors();
  check_latin1();
  check_long_sql();
  check_rowid();
  check_cursor_hygiene();
  seer_disconnect(C);
  printf("SUMMARY pass=%d fail=%d skip=%d\n", pass_n, fail_n, skip_n);
  return fail_n > 0 ? 1 : 0;
}

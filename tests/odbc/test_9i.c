/* Oracle 9i (field-version-2) core-API integration test.
 *
 * 9i speaks the legacy fv2 dialect (O3LOGON auth + the TTI_ALL7 query/DML/PLSQL
 * path + the two-call TTI_LOBOPS LOB read), which the containerized 10g-23ai
 * matrix never exercises. It is validated ONLY here, against a local 9i VM (9i
 * can't be containerized - it needs an old kernel/glibc - so this is deliberately
 * local-only; it is not part of any GitHub CI).
 *
 * Driven through the core seer_* API (not the ODBC DM): 9i is addressed by SID
 * (it predates service-name routing), so set SEER_TEST_SID. Self-gating: if the
 * 9i VM is unreachable, every check skips and the process exits 0.
 *
 * Env: SEER_TEST_HOST, SEER_TEST_PORT, SEER_TEST_SID, SEER_TEST_USER,
 *      SEER_TEST_PASS.
 *
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "seer/seertns.h"

#define T_VARCHAR 1
#define T_NUMBER 2

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
static void skip(const char *n, const char *w)
{
  printf("  SKIP %s: %s\n", n, w);
  skip_n++;
}

static SeerConn *C;

/* Best-effort DDL/DML (setup); ignore "table does not exist" on pre-drops. */
static void run(const char *sql)
{
  SeerStmt *s = NULL;
  if (seer_stmt_prepare(C, sql, &s) == SEER_OK) {
    seer_stmt_execute(s);
    seer_stmt_close(s);
  }
}

/* First column of the first row as text, into `out` (empty on failure). */
static void scalar(const char *sql, char *out, size_t osz)
{
  out[0] = '\0';
  SeerStmt *s = NULL;
  if (seer_stmt_prepare(C, sql, &s) == SEER_OK && seer_stmt_execute(s) == SEER_OK &&
      seer_stmt_fetch(s) == SEER_OK) {
    const char *v = NULL;
    int isn = 0;
    if (seer_stmt_get_string(s, 0, &v, &isn) == SEER_OK && v)
      snprintf(out, osz, "%s", v);
  }
  seer_stmt_close(s);
}

/* ---- checks ---- */

static void check_select_scalar(void)
{
  char out[64];
  scalar("SELECT 42 FROM dual", out, sizeof out);
  if (strcmp(out, "42") == 0)
    pass("SELECT scalar");
  else {
    char m[96];
    snprintf(m, sizeof m, "got '%s'", out);
    fail("SELECT scalar", m);
  }
}

static void check_zero_length_columns(void)
{
  /* A bare NULL / '' is described with MaxLen 0 and the row carries only the
   * NULL indicator (81 01) for it - no value bytes; the next column must still
   * decode. */
  const char *name = "zero-length columns (NULL / '')";
  SeerStmt *s = NULL;
  const char *a = NULL, *b = NULL, *t = NULL;
  int na = 0, nb = 0, nt = 0, ok = 0;
  if (seer_stmt_prepare(C, "SELECT NULL, '', 'tail' FROM dual", &s) == SEER_OK &&
      seer_stmt_execute(s) == SEER_OK && seer_stmt_fetch(s) == SEER_OK &&
      seer_stmt_get_string(s, 0, &a, &na) == SEER_OK &&
      seer_stmt_get_string(s, 1, &b, &nb) == SEER_OK &&
      seer_stmt_get_string(s, 2, &t, &nt) == SEER_OK)
    ok = na && nb && !nt && t && strcmp(t, "tail") == 0;
  if (ok)
    pass(name);
  else {
    char m[96];
    snprintf(m, sizeof m, "null=%d/%d tail='%s'", na, nb, t ? t : "(none)");
    fail(name, m);
  }
  seer_stmt_close(s);
}

static void check_select_table(void)
{
  /* A dictionary view: VARCHAR + NUMBER, multiple rows, real NOT-NULL columns
   * (the fv2 describe null_ok path). */
  const char *name = "SELECT multi-col/row (dictionary)";
  SeerStmt *s = NULL;
  if (seer_stmt_prepare(C,
                        "SELECT username, user_id FROM all_users "
                        "WHERE rownum <= 5 ORDER BY user_id",
                        &s) != SEER_OK ||
      seer_stmt_execute(s) != SEER_OK) {
    fail(name, seer_last_error(C) ? seer_last_error(C) : "prepare/exec");
    seer_stmt_close(s);
    return;
  }
  int rows = 0, ok = 1;
  while (seer_stmt_fetch(s) == SEER_OK) {
    const char *u = NULL, *id = NULL;
    int n = 0;
    seer_stmt_get_string(s, 0, &u, &n);
    seer_stmt_get_string(s, 1, &id, &n);
    if (u == NULL || u[0] == '\0' || id == NULL)
      ok = 0; /* SYS etc. non-empty */
    rows++;
  }
  seer_stmt_close(s);
  if (ok && rows >= 1)
    pass(name);
  else {
    char m[64];
    snprintf(m, sizeof m, "%d rows, ok=%d", rows, ok);
    fail(name, m);
  }
}

static void check_dml_binds(void)
{
  const char *name = "DDL + DML + binds round-trip";
  char out[64];
  run("DROP TABLE seer9t");
  run("CREATE TABLE seer9t (id NUMBER, nm VARCHAR2(20))");
  SeerStmt *s = NULL;
  int inserts_ok = 1;
  const char *names[] = {"alice", "bob", "carol"};
  for (int i = 0; i < 3; i++) {
    s = NULL;
    if (seer_stmt_prepare(C, "INSERT INTO seer9t (id, nm) VALUES (:1, :2)", &s) != SEER_OK ||
        seer_stmt_bind_int64(s, 1, (i + 1) * 10) != SEER_OK ||
        seer_stmt_bind_text(s, 2, names[i], -1) != SEER_OK || seer_stmt_execute(s) != SEER_OK)
      inserts_ok = 0;
    seer_stmt_close(s);
  }
  s = NULL;
  int update_ok =
      seer_stmt_prepare(C, "UPDATE seer9t SET nm='robert' WHERE id=:1", &s) == SEER_OK &&
      seer_stmt_bind_int64(s, 1, 20) == SEER_OK && seer_stmt_execute(s) == SEER_OK;
  seer_stmt_close(s);
  /* SELECT back with a bind on the WHERE; sum ids >= 10 = 60, robert present. */
  long sum = 0;
  int has_robert = 0;
  s = NULL;
  if (seer_stmt_prepare(C, "SELECT id, nm FROM seer9t WHERE id >= :1 ORDER BY id", &s) == SEER_OK &&
      seer_stmt_bind_int64(s, 1, 10) == SEER_OK && seer_stmt_execute(s) == SEER_OK) {
    while (seer_stmt_fetch(s) == SEER_OK) {
      const char *id = NULL, *nm = NULL;
      int n = 0;
      seer_stmt_get_string(s, 0, &id, &n);
      seer_stmt_get_string(s, 1, &nm, &n);
      sum += id ? atol(id) : 0;
      if (nm && strcmp(nm, "robert") == 0)
        has_robert = 1;
    }
  }
  seer_stmt_close(s);
  run("DROP TABLE seer9t");
  if (inserts_ok && update_ok && sum == 60 && has_robert)
    pass(name);
  else {
    char m[96];
    snprintf(m, sizeof m, "ins=%d upd=%d sum=%ld robert=%d", inserts_ok, update_ok, sum,
             has_robert);
    fail(name, m);
    (void)out;
  }
}

static void check_plsql(void)
{
  /* Block with an OUT NUMBER (:1 := 42*2 => 84). */
  {
    const char *name = "PL/SQL block OUT (number)";
    SeerStmt *s = NULL;
    seer_stmt_prepare(C, "BEGIN :1 := 42 * 2; END;", &s);
    SeerStatus b = seer_stmt_bind_out(s, 1, T_NUMBER, 22);
    SeerStatus e = (b == SEER_OK) ? seer_stmt_execute(s) : b;
    const void *d = NULL;
    size_t l = 0;
    int isn = 0, isb = 0;
    seer_stmt_out_data(s, 1, &d, &l, &isn, &isb);
    if (e == SEER_OK && d && strcmp((const char *)d, "84") == 0)
      pass(name);
    else
      fail(name, e ? (seer_last_error(C) ? seer_last_error(C) : "exec") : "wrong OUT");
    seer_stmt_close(s);
  }

  /* Block with IN + OUT VARCHAR (:2 := :1 || '_x'). */
  {
    const char *name = "PL/SQL block IN+OUT (varchar)";
    SeerStmt *s = NULL;
    seer_stmt_prepare(C, "BEGIN :2 := :1 || '_x'; END;", &s);
    seer_stmt_bind_text(s, 1, "hi", -1);
    SeerStatus b = seer_stmt_bind_out(s, 2, T_VARCHAR, 100);
    SeerStatus e = (b == SEER_OK) ? seer_stmt_execute(s) : b;
    const void *d = NULL;
    size_t l = 0;
    int isn = 0, isb = 0;
    seer_stmt_out_data(s, 2, &d, &l, &isn, &isb);
    if (e == SEER_OK && d && strcmp((const char *)d, "hi_x") == 0)
      pass(name);
    else
      fail(name, e ? (seer_last_error(C) ? seer_last_error(C) : "exec") : "wrong OUT");
    seer_stmt_close(s);
  }
}

static void check_block_directions(void)
{
  /* An IN OUT bind: the block reads it and assigns it. The bind prompt's masks
   * say so; sending no value for it (it's declared OUT) gave the block NULL. */
  {
    const char *name = "PL/SQL block IN OUT (number)";
    SeerStmt *s = NULL;
    seer_stmt_prepare(C, "BEGIN :1 := :1 + 1; END;", &s);
    SeerStatus b = seer_stmt_bind_int64(s, 1, 41);
    if (b == SEER_OK)
      b = seer_stmt_bind_set_inout(s, 1, 22);
    SeerStatus e = (b == SEER_OK) ? seer_stmt_execute(s) : b;
    const void *d = NULL;
    size_t l = 0;
    int isn = 0, isb = 0;
    seer_stmt_out_data(s, 1, &d, &l, &isn, &isb);
    if (e == SEER_OK && !isn && d && strcmp((const char *)d, "42") == 0)
      pass(name);
    else
      fail(name, e ? (seer_last_error(C) ? seer_last_error(C) : "exec") : "wrong IN OUT value");
    seer_stmt_close(s);
  }
  /* Declared IN OUT but only read by the block: the masks say IN only, so it
   * gets a value sent and none back - counting it as an output shifted :1's
   * value (seerdb/seerdb@c730f2b). */
  {
    const char *name = "PL/SQL block: IN OUT bind the block only reads";
    SeerStmt *s = NULL;
    seer_stmt_prepare(C, "BEGIN :1 := :2 * 10; END;", &s);
    SeerStatus b = seer_stmt_bind_out(s, 1, T_NUMBER, 22);
    if (b == SEER_OK)
      b = seer_stmt_bind_int64(s, 2, 5);
    if (b == SEER_OK)
      b = seer_stmt_bind_set_inout(s, 2, 22);
    SeerStatus e = (b == SEER_OK) ? seer_stmt_execute(s) : b;
    const void *d = NULL;
    size_t l = 0;
    int isn = 0, isb = 0;
    seer_stmt_out_data(s, 1, &d, &l, &isn, &isb);
    if (e == SEER_OK && !isn && d && strcmp((const char *)d, "50") == 0)
      pass(name);
    else
      fail(name, e ? (seer_last_error(C) ? seer_last_error(C) : "exec") : "wrong OUT value");
    seer_stmt_close(s);
  }
}

static void check_lob(void)
{
  run("DROP TABLE seer9l");
  run("CREATE TABLE seer9l (c CLOB, b BLOB)");
  run("INSERT INTO seer9l VALUES (RPAD(TO_CLOB('c'), 5000, 'c'), HEXTORAW('cafe1234babe'))");
  seer_commit(C);
  char out[64];
  scalar("SELECT c FROM seer9l", out, sizeof out);
  /* 5000-char CLOB spans multiple TTI_LOBOPS READ chunks. */
  {
    SeerStmt *s = NULL;
    long len = -1;
    if (seer_stmt_prepare(C, "SELECT LENGTH(c) FROM seer9l", &s) == SEER_OK &&
        seer_stmt_execute(s) == SEER_OK && seer_stmt_fetch(s) == SEER_OK) {
      const char *v = NULL;
      int n = 0;
      seer_stmt_get_string(s, 0, &v, &n);
      len = v ? atol(v) : -1;
    }
    seer_stmt_close(s);
    if (len == 5000 && out[0] == 'c')
      pass("CLOB read (5000, chunked)");
    else {
      char m[64];
      snprintf(m, sizeof m, "len=%ld head=%c", len, out[0] ? out[0] : '?');
      fail("CLOB read (5000, chunked)", m);
    }
  }
  /* BLOB read: 6 bytes. */
  {
    SeerStmt *s = NULL;
    size_t blen = 0;
    int ok = 0;
    if (seer_stmt_prepare(C, "SELECT b FROM seer9l", &s) == SEER_OK &&
        seer_stmt_execute(s) == SEER_OK && seer_stmt_fetch(s) == SEER_OK) {
      const void *d = NULL;
      int isn = 0, isb = 0;
      seer_stmt_get_data(s, 0, &d, &blen, &isn, &isb);
      ok = (blen == 6 && isb == 1);
    }
    seer_stmt_close(s);
    if (ok)
      pass("BLOB read");
    else {
      char m[48];
      snprintf(m, sizeof m, "len=%zu", blen);
      fail("BLOB read", m);
    }
  }
  run("DROP TABLE seer9l");
}

static void check_bfile(void)
{
  /* Needs the local fixture DIRECTORY BFDIR -> a dir holding hello.bin
   * ("BFILE-9i-content" + ca fe ba be, 20 bytes). Skips if not present. */
  const char *name = "BFILE read (BFDIR/hello.bin)";
  SeerStmt *s = NULL;
  if (seer_stmt_prepare(C, "SELECT BFILENAME('BFDIR','hello.bin') FROM dual", &s) == SEER_OK &&
      seer_stmt_execute(s) == SEER_OK && seer_stmt_fetch(s) == SEER_OK) {
    const void *d = NULL;
    size_t len = 0;
    int isn = 0, isb = 0;
    seer_stmt_get_data(s, 0, &d, &len, &isn, &isb);
    if (len == 20 && d && memcmp(d, "BFILE-9i-content", 16) == 0)
      pass(name);
    else if (len == 0)
      skip(name, "BFDIR/hello.bin fixture not present");
    else {
      char m[64];
      snprintf(m, sizeof m, "len=%zu", len);
      fail(name, m);
    }
  } else {
    skip(name, "BFDIR directory not available");
  }
  seer_stmt_close(s);
}

static void check_national(void)
{
  const char *name = "national-charset bind (NVARCHAR2)";
  char out[64];
  run("DROP TABLE seer9n");
  run("CREATE TABLE seer9n (n NVARCHAR2(20))");
  SeerStmt *s = NULL;
  SeerStatus b = SEER_EPARAM, e = SEER_EPARAM;
  if (seer_stmt_prepare(C, "INSERT INTO seer9n VALUES (:1)", &s) == SEER_OK) {
    b = seer_stmt_bind_ntext(s, 1, "hello-9i", -1);
    e = (b == SEER_OK) ? seer_stmt_execute(s) : b;
  }
  seer_stmt_close(s);
  seer_commit(C);
  /* Read back via TO_CHAR (server converts national->DB charset -> UTF-8). */
  scalar("SELECT TO_CHAR(n) FROM seer9n WHERE n = N'hello-9i'", out, sizeof out);
  run("DROP TABLE seer9n");
  if (e == SEER_OK && strcmp(out, "hello-9i") == 0)
    pass(name);
  else {
    char m[96];
    snprintf(m, sizeof m, "exec=%d got '%s'", e, out);
    fail(name, m);
  }
}

static void check_nullability(void)
{
  /* The fv2 describe null_ok field (§19.1 dispute; SeerODBC's ROOT_CAUSE fix).
   * A NOT-NULL and a nullable column must decode to distinct nullability -
   * the exact bug that garbled describe when read as a phantom ub4. */
  const char *name = "describe null_ok (NOT NULL vs nullable)";
  run("DROP TABLE seer9k");
  run("CREATE TABLE seer9k (a VARCHAR2(8) NOT NULL, b VARCHAR2(8))");
  SeerStmt *s = NULL;
  int ncols = 0, notnull = -1, nullable = -1;
  if (seer_stmt_prepare(C, "SELECT a, b FROM seer9k", &s) == SEER_OK &&
      seer_stmt_execute(s) == SEER_OK) {
    ncols = seer_stmt_num_cols(s);
    notnull = seer_stmt_col_nullable(s, 0);  /* a NOT NULL -> 0 */
    nullable = seer_stmt_col_nullable(s, 1); /* b nullable  -> nonzero */
  }
  seer_stmt_close(s);
  run("DROP TABLE seer9k");
  if (ncols == 2 && notnull == 0 && nullable != 0)
    pass(name);
  else {
    char m[80];
    snprintf(m, sizeof m, "ncols=%d notnull=%d nullable=%d", ncols, notnull, nullable);
    fail(name, m);
  }
}

static void check_null_fetch(void)
{
  /* A SQL NULL cell decodes to is_null (the 81 01 indicator), and a present
   * cell in the same row still reads correctly. */
  const char *name = "NULL cell fetch (indicator)";
  run("DROP TABLE seer9m");
  run("CREATE TABLE seer9m (id NUMBER, v VARCHAR2(10))");
  run("INSERT INTO seer9m VALUES (1, NULL)");
  seer_commit(C);
  SeerStmt *s = NULL;
  int id_ok = 0, v_null = 0, got = 0;
  if (seer_stmt_prepare(C, "SELECT id, v FROM seer9m", &s) == SEER_OK &&
      seer_stmt_execute(s) == SEER_OK && seer_stmt_fetch(s) == SEER_OK) {
    const char *id = NULL, *v = NULL;
    int idn = 0, vn = 0;
    seer_stmt_get_string(s, 0, &id, &idn);
    seer_stmt_get_string(s, 1, &v, &vn);
    id_ok = (idn == 0 && id && strcmp(id, "1") == 0);
    v_null = (vn == 1 && v == NULL);
    got = 1;
  }
  seer_stmt_close(s);
  run("DROP TABLE seer9m");
  if (got && id_ok && v_null)
    pass(name);
  else {
    char m[80];
    snprintf(m, sizeof m, "got=%d id_ok=%d v_null=%d", got, id_ok, v_null);
    fail(name, m);
  }
}

static void check_error_recovery(void)
{
  /* A server error must surface (not silently succeed) AND leave the
   * connection usable for the next statement - covers both the SQL error
   * path (ORA-00942) and the PL/SQL compile-error path (ORA-06550). */
  const char *name = "error surfaced + connection reusable";
  SeerStmt *s = NULL;
  SeerStatus st = seer_stmt_prepare(C, "SELECT * FROM seer_no_such_table_9i", &s);
  SeerStatus ex = (st == SEER_OK) ? seer_stmt_execute(s) : st;
  int sql_err = (ex != SEER_OK);
  seer_stmt_close(s);

  s = NULL;
  st = seer_stmt_prepare(C, "BEGIN this_is_not_valid_plsql END;", &s);
  ex = (st == SEER_OK) ? seer_stmt_execute(s) : st;
  int plsql_err = (ex != SEER_OK);
  seer_stmt_close(s);

  /* The connection must still work after both failures. */
  char out[64];
  scalar("SELECT 7 FROM dual", out, sizeof out);
  if (sql_err && plsql_err && strcmp(out, "7") == 0)
    pass(name);
  else {
    char m[96];
    snprintf(m, sizeof m, "sql_err=%d plsql_err=%d after='%s'", sql_err, plsql_err, out);
    fail(name, m);
  }
}

static void check_multibatch_fetch(void)
{
  /* 200 rows in a real table span many fetch batches (fv2 re-sends the define
   * block per batch, ~10 rows each), exercising the RXH/batch-boundary loop. */
  const char *name = "multi-batch fetch (200 rows)";
  run("DROP TABLE seer9b");
  run("CREATE TABLE seer9b (id NUMBER)");
  run("INSERT INTO seer9b SELECT level FROM dual CONNECT BY level <= 200");
  seer_commit(C);
  SeerStmt *s = NULL;
  long rows = 0, sum = 0;
  if (seer_stmt_prepare(C, "SELECT id FROM seer9b ORDER BY id", &s) == SEER_OK &&
      seer_stmt_execute(s) == SEER_OK) {
    while (seer_stmt_fetch(s) == SEER_OK) {
      const char *v = NULL;
      int n = 0;
      seer_stmt_get_string(s, 0, &v, &n);
      sum += v ? atol(v) : 0;
      rows++;
    }
  }
  seer_stmt_close(s);
  run("DROP TABLE seer9b");
  /* 1..200 => 200 rows, sum 20100. */
  if (rows == 200 && sum == 20100)
    pass(name);
  else {
    char m[80];
    snprintf(m, sizeof m, "rows=%ld sum=%ld", rows, sum);
    fail(name, m);
  }
}

static void check_date_bind(void)
{
  /* DATE bind (fv2 OAC type 12/7) round-trips to second precision. */
  const char *name = "DATE bind + fetch";
  char out[64];
  run("DROP TABLE seer9d");
  run("CREATE TABLE seer9d (d DATE)");
  SeerStmt *s = NULL;
  SeerStatus e = SEER_EPARAM;
  if (seer_stmt_prepare(C, "INSERT INTO seer9d VALUES (:1)", &s) == SEER_OK &&
      seer_stmt_bind_date(s, 1, 2026, 7, 4, 13, 30, 15) == SEER_OK)
    e = seer_stmt_execute(s);
  seer_stmt_close(s);
  seer_commit(C);
  scalar("SELECT TO_CHAR(d, 'YYYY-MM-DD HH24:MI:SS') FROM seer9d", out, sizeof out);
  run("DROP TABLE seer9d");
  if (e == SEER_OK && strcmp(out, "2026-07-04 13:30:15") == 0)
    pass(name);
  else {
    char m[96];
    snprintf(m, sizeof m, "exec=%d got '%s'", e, out);
    fail(name, m);
  }
}

static void check_raw_bind(void)
{
  /* RAW bind (fv2 OAC type 23) round-trips as binary. */
  const char *name = "RAW bind + fetch";
  const uint8_t raw[] = {0xca, 0xfe, 0xba, 0xbe};
  run("DROP TABLE seer9r");
  run("CREATE TABLE seer9r (r RAW(8))");
  SeerStmt *s = NULL;
  SeerStatus e = SEER_EPARAM;
  if (seer_stmt_prepare(C, "INSERT INTO seer9r VALUES (:1)", &s) == SEER_OK &&
      seer_stmt_bind_raw(s, 1, raw, (int)sizeof raw) == SEER_OK)
    e = seer_stmt_execute(s);
  seer_stmt_close(s);
  seer_commit(C);
  int ok = 0;
  size_t len = 0;
  s = NULL;
  if (seer_stmt_prepare(C, "SELECT r FROM seer9r", &s) == SEER_OK &&
      seer_stmt_execute(s) == SEER_OK && seer_stmt_fetch(s) == SEER_OK) {
    const void *d = NULL;
    int isn = 0, isb = 0;
    seer_stmt_get_data(s, 0, &d, &len, &isn, &isb);
    ok = (len == sizeof raw && isb == 1 && d && memcmp(d, raw, sizeof raw) == 0);
  }
  seer_stmt_close(s);
  run("DROP TABLE seer9r");
  if (e == SEER_OK && ok)
    pass(name);
  else {
    char m[80];
    snprintf(m, sizeof m, "exec=%d ok=%d len=%zu", e, ok, len);
    fail(name, m);
  }
}

static void check_rollback(void)
{
  /* With autocommit off, an uncommitted INSERT is discarded by rollback;
   * a committed one survives. (fv2 DML has no autocommit bit - the driver
   * commits explicitly, so rollback must actually reach the server.) */
  const char *name = "rollback discards uncommitted DML";
  run("DROP TABLE seer9x");
  run("CREATE TABLE seer9x (id NUMBER)"); /* DDL implicitly commits */
  seer_set_autocommit(C, 0);
  SeerStmt *s = NULL;
  int ins1 = 0;
  if (seer_stmt_prepare(C, "INSERT INTO seer9x VALUES (:1)", &s) == SEER_OK &&
      seer_stmt_bind_int64(s, 1, 1) == SEER_OK)
    ins1 = (seer_stmt_execute(s) == SEER_OK);
  seer_stmt_close(s);
  seer_rollback(C);
  char after_rb[32];
  scalar("SELECT COUNT(*) FROM seer9x", after_rb, sizeof after_rb);
  /* Now a committed insert must persist. */
  s = NULL;
  if (seer_stmt_prepare(C, "INSERT INTO seer9x VALUES (:1)", &s) == SEER_OK &&
      seer_stmt_bind_int64(s, 1, 2) == SEER_OK)
    seer_stmt_execute(s);
  seer_stmt_close(s);
  seer_commit(C);
  char after_cm[32];
  scalar("SELECT COUNT(*) FROM seer9x", after_cm, sizeof after_cm);
  seer_set_autocommit(C, 1);
  run("DROP TABLE seer9x");
  if (ins1 && strcmp(after_rb, "0") == 0 && strcmp(after_cm, "1") == 0)
    pass(name);
  else {
    char m[96];
    snprintf(m, sizeof m, "ins1=%d after_rb='%s' after_cm='%s'", ins1, after_rb, after_cm);
    fail(name, m);
  }
}

/* A rowid column is defined as its text (the native form desyncs the 9i row
 * stream, ORA-01002), and a UROWID at its full 5267 characters: an IOT's
 * logical rowid holds the key, and a 900-character key gives a 1212-character
 * rowid, which must come back whole and bind back to its row. */
static void check_rowid(void)
{
  const char *name = "ROWID / UROWID fetched as text";
  char rid[64] = "", tail[16] = "";
  SeerStmt *s = NULL;
  if (seer_stmt_prepare(C, "SELECT ROWID, 'tail' FROM dual", &s) == SEER_OK &&
      seer_stmt_execute(s) == SEER_OK && seer_stmt_fetch(s) == SEER_OK) {
    const char *v = NULL;
    int n = 0;
    if (seer_stmt_get_string(s, 0, &v, &n) == SEER_OK && v)
      snprintf(rid, sizeof rid, "%s", v);
    if (seer_stmt_get_string(s, 1, &v, &n) == SEER_OK && v)
      snprintf(tail, sizeof tail, "%s", v);
  }
  seer_stmt_close(s);

  run("DROP TABLE seer9iot");
  run("CREATE TABLE seer9iot (k VARCHAR2(1000) PRIMARY KEY, v NUMBER) ORGANIZATION INDEX");
  run("INSERT INTO seer9iot VALUES (RPAD('k', 900, 'x'), 7)");
  char *urowid = NULL;
  s = NULL;
  if (seer_stmt_prepare(C, "SELECT ROWID FROM seer9iot", &s) == SEER_OK &&
      seer_stmt_execute(s) == SEER_OK && seer_stmt_fetch(s) == SEER_OK) {
    const char *v = NULL;
    int n = 0;
    if (seer_stmt_get_string(s, 0, &v, &n) == SEER_OK && v)
      urowid = strdup(v);
  }
  seer_stmt_close(s);
  char back[16] = "";
  s = NULL;
  if (urowid != NULL &&
      seer_stmt_prepare(C, "SELECT v FROM seer9iot WHERE ROWID = :1", &s) == SEER_OK &&
      seer_stmt_bind_text(s, 1, urowid, -1) == SEER_OK && seer_stmt_execute(s) == SEER_OK &&
      seer_stmt_fetch(s) == SEER_OK) {
    const char *v = NULL;
    int n = 0;
    if (seer_stmt_get_string(s, 0, &v, &n) == SEER_OK && v)
      snprintf(back, sizeof back, "%s", v);
  }
  seer_stmt_close(s);
  run("DROP TABLE seer9iot");

  size_t ulen = urowid ? strlen(urowid) : 0;
  free(urowid);
  if (strlen(rid) == 18 && strcmp(tail, "tail") == 0 && ulen == 1212 && strcmp(back, "7") == 0)
    pass(name);
  else {
    char m[128];
    snprintf(m, sizeof m, "rowid='%s' tail='%s' urowid len=%zu bound back='%s'", rid, tail, ulen,
             back);
    fail(name, m);
  }
}

/* The describe's column count and the execute's define count are ub4s: 300
 * columns are `02 01 2c`, which one byte cannot carry. A column named by an
 * expression longer than 255 bytes has its name chunked. */
static void check_wide_select(void)
{
  const char *name = "300-column SELECT + long column name";
  char sql[4096];
  /* "SELECT 1 c1,2 c2,...,300 c300 FROM dual" (about 2.7 KB) */
  strcpy(sql, "SELECT ");
  for (int i = 1; i <= 300; i++) {
    char item[24];
    snprintf(item, sizeof item, "%s%d c%d", i > 1 ? "," : "", i, i);
    strncat(sql, item, sizeof sql - strlen(sql) - 1);
  }
  strncat(sql, " FROM dual", sizeof sql - strlen(sql) - 1);
  int ncols = 0;
  char last[16] = "";
  SeerStmt *s = NULL;
  if (seer_stmt_prepare(C, sql, &s) == SEER_OK && seer_stmt_execute(s) == SEER_OK &&
      seer_stmt_fetch(s) == SEER_OK) {
    ncols = seer_stmt_num_cols(s);
    const char *v = NULL;
    int n = 0;
    if (seer_stmt_get_string(s, 299, &v, &n) == SEER_OK && v)
      snprintf(last, sizeof last, "%s", v);
  }
  seer_stmt_close(s);

  char a[151], b[151];
  memset(a, 'a', 150);
  memset(b, 'b', 150);
  a[150] = b[150] = '\0';
  snprintf(sql, sizeof sql, "SELECT '%s' || '%s', 'tail' FROM dual", a, b);
  size_t vlen = 0;
  char tail[16] = "";
  s = NULL;
  if (seer_stmt_prepare(C, sql, &s) == SEER_OK && seer_stmt_execute(s) == SEER_OK &&
      seer_stmt_fetch(s) == SEER_OK) {
    const char *v = NULL;
    int n = 0;
    if (seer_stmt_get_string(s, 0, &v, &n) == SEER_OK && v)
      vlen = strlen(v);
    if (seer_stmt_get_string(s, 1, &v, &n) == SEER_OK && v)
      snprintf(tail, sizeof tail, "%s", v);
  }
  seer_stmt_close(s);

  if (ncols == 300 && strcmp(last, "300") == 0 && vlen == 300 && strcmp(tail, "tail") == 0)
    pass(name);
  else {
    char m[128];
    snprintf(m, sizeof m, "ncols=%d last='%s' long value=%zu tail='%s'", ncols, last, vlen, tail);
    fail(name, m);
  }
}

int main(void)
{
  const char *port = getenv("SEER_TEST_PORT");
  const char *sid = getenv("SEER_TEST_SID");
  SeerConnParams p = {
      .host = getenv("SEER_TEST_HOST"),
      .port = (uint16_t)(port ? atoi(port) : 1526),
      .sid = (sid && sid[0]) ? sid : NULL,
      .service_name = getenv("SEER_TEST_SERVICE"),
      .username = getenv("SEER_TEST_USER"),
      .password = getenv("SEER_TEST_PASS"),
  };
  if (seer_connect(&p, &C) != SEER_OK) {
    /* Local-only: the 9i VM isn't reachable -> report nothing ran, exit clean. */
    printf("  SKIP 9i: VM not reachable (%s)\n",
           seer_last_error(NULL) ? seer_last_error(NULL) : "connect failed");
    printf("SUMMARY pass=0 fail=0 skip=1\n");
    return 0;
  }

  check_select_scalar();
  check_zero_length_columns();
  check_select_table();
  check_wide_select();
  check_nullability();
  check_null_fetch();
  check_dml_binds();
  check_date_bind();
  check_raw_bind();
  check_rowid();
  check_multibatch_fetch();
  check_error_recovery();
  check_rollback();
  check_plsql();
  check_block_directions();
  check_lob();
  check_bfile();
  check_national();

  seer_disconnect(C);
  printf("SUMMARY pass=%d fail=%d skip=%d\n", pass_n, fail_n, skip_n);
  return fail_n > 0 ? 1 : 0;
}

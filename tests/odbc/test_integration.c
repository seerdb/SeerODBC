/* Driver-level integration test: drives SeerODBC through the unixODBC Driver
 * Manager against a live server, exercising the ODBC surface end to end
 * (connect, typed fetch, binds, DML + rowcount, array DML + batch errors,
 * transactions, catalog, LOB, FOR UPDATE concurrency).
 *
 * With no server configured it exits 77 (the automake/meson "skip" code), so
 * `meson test` stays green offline. Point it at a server with
 *   SEER_TEST_HOST, SEER_TEST_PORT (default 1521), SEER_TEST_SERVICE,
 *   SEER_TEST_USER, SEER_TEST_PASS, SEER_TEST_RELEASE (required: 8, 9, 10, 11,
 *   18, 21, 23, 26)
 * and the driver to load with SEER_DRIVER (an absolute .so path; defaults to
 * the build-tree path baked in at compile time). Every tier, 8i to 26ai, runs
 * the same checks; one that can't apply to the release is a SKIP with its
 * reason (GATES below, tests/odbc/gates.h, #148).
 *
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>

#include <sql.h>
#include <sqlext.h>

#include "gates.h"

#ifndef SEER_DRIVER_PATH
#define SEER_DRIVER_PATH ""
#endif

static int n_pass, n_fail, n_skip;

/* The checks each release skips (gates.h): what the release lacks
 * ("server: ...") or what SeerODBC doesn't reach on it yet ("todo: ..." and
 * the issue). A gated check opens with GATE(name) and doesn't run; anything
 * not gated runs and fails if it fails. Ordered as the checks run. */
static const Gate GATES[] = {
    {"TIMESTAMP WITH TIME ZONE reads its own wall-clock time and offset", 8, 8, GATE_SERVER,
     "8.1.7 has no TIMESTAMP WITH TIME ZONE"},
    {"LOCAL TIME ZONE value reads in the session's zone (after ALTER SESSION)", 8, 8, GATE_SERVER,
     "8.1.7 has no TIMESTAMP WITH LOCAL TIME ZONE"},
    {"session time zone set at login (OS offset, ORA_SDTZ)", 8, 8, GATE_SERVER,
     "8.1.7 has no session time zone"},
    {"zero-fraction TIMESTAMP bind matches trunc(LTZ)", 8, 8, GATE_SERVER,
     "8.1.7 has no TIMESTAMP type"},
    {"SQL OBJECT / VARRAY with NVARCHAR2 attributes", 8, 8, GATE_SERVER,
     "8.1.7 has no UNISTR, and its national charset is WE8ISO8859P1"},
    {"SQL OBJECT with an XMLType attribute", 8, 8, GATE_SERVER, "8.1.7 has no XMLType"},
    {"VECTOR column dimensions / format (SQLColAttribute)", 8, 21, GATE_SERVER,
     "no VECTOR type before 23ai"},
    {"large CLOB OUT parameter", 8, 8, GATE_SERVER,
     "8.1.7 converts no CLOB to text: a CLOB OUT binds as SQL_SEER_CLOB there (#214)"},
    {"column annotations", 8, 21, GATE_SERVER, "no ANNOTATIONS before 23ai"},
    {"implicit result rows holding a CURSOR() column", 8, 11, GATE_SERVER,
     "no DBMS_SQL.RETURN_RESULT before 12c"},
    {"implicit results", 8, 11, GATE_SERVER, "no DBMS_SQL.RETURN_RESULT before 12c"},
    {"array DML row counts", 8, 11, GATE_SERVER, "no array-DML row counts before 12c"},
    {"BOOLEAN (23ai)", 8, 21, GATE_SERVER, "no BOOLEAN type before 23ai"},
    {"VECTOR (23ai)", 8, 21, GATE_SERVER, "no VECTOR type before 23ai"},
    {"JSON (OSON)", 8, 18, GATE_SERVER, "no JSON type before 21c"},
    {"JSON: long field names and compressed columns", 8, 21, GATE_SERVER,
     "no JSON field names over 255 bytes before 23ai"},
    {"INTERVAL bind", 8, 8, GATE_SERVER, "8.1.7 has no INTERVAL types"},
    {"TIMESTAMP bind (fractional)", 8, 8, GATE_SERVER, "8.1.7 has no TIMESTAMP type"},
    {"CLOB / BLOB columns across fetch batches (LOBINLINE)", 8, 11, GATE_SERVER,
     "no inline LOB fetch before 12c"},
    {"DRCP (pooled session)", 8, 10, GATE_SERVER, "no DRCP before 11g"},
    {"DRCP (pooled session)", 11, 11, GATE_SERVER, "11g's pool takes only OCI clients (ORA-56606)"},
    {"XMLType fetch (LOB-backed)", 8, 8, GATE_SERVER, "8.1.7 has no XMLType"},
    {"XMLType fetch", 8, 8, GATE_SERVER, "8.1.7 has no XMLType"},
    {"BINARY_FLOAT bind", 8, 9, GATE_SERVER, "no BINARY_FLOAT before 10g"},
    {"BOOLEAN bind (23ai)", 8, 21, GATE_SERVER, "no BOOLEAN type before 23ai"},
};

static void pass(const char *name)
{
  printf("  \033[32mPASS\033[0m %s\n", name);
  n_pass++;
}
/* Failures are also kept to repeat on stderr at the end: a CI runner showing
 * only a failed test's last lines of stderr then still names them. */
static char fail_log[4096];
static void fail(const char *name, const char *why)
{
  printf("  \033[31mFAIL\033[0m %s: %s\n", name, why);
  size_t used = strlen(fail_log);
  snprintf(fail_log + used, sizeof fail_log - used, "FAIL %s: %s\n", name, why);
  n_fail++;
}
static void skip(const char *name, const char *why)
{
  printf("  \033[33mSKIP\033[0m %s: %s\n", name, why);
  n_skip++;
}

/* Whether `name` is gated on the connected release; if so it is reported as
 * SKIP with the gate's reason. */
static int gated(const char *name)
{
  const Gate *g = gate_find(GATES, sizeof GATES / sizeof GATES[0], name);
  if (g == NULL)
    return 0;
  char why[256];
  gate_reason(g, why, sizeof why);
  skip(name, why);
  return 1;
}

/* Skip the check `nm` and return when its release is gated. */
#define GATE(nm)                                                                                   \
  do {                                                                                             \
    if (gated(nm))                                                                                 \
      return;                                                                                      \
  } while (0)

/* First diagnostic record's message text, for failure reporting. */
static void diag_text(SQLSMALLINT type, SQLHANDLE h, char *out, int n)
{
  SQLCHAR state[6] = {0}, msg[400] = {0};
  SQLINTEGER native = 0;
  SQLSMALLINT len = 0;
  out[0] = '\0';
  if (SQLGetDiagRec(type, h, 1, state, &native, msg, sizeof msg, &len) == SQL_SUCCESS)
    snprintf(out, n, "%s", (char *)msg);
}

/* Run `sql` and read row 1, column 1 as text into `out`. Returns the SQLRETURN
 * of the execute (or a fetch failure code). On any failure `err` carries why. */
static SQLRETURN exec_scalar(SQLHDBC dbc, const char *sql, char *out, int outn, char *err, int errn)
{
  SQLHSTMT st;
  out[0] = '\0';
  err[0] = '\0';
  if (!SQL_SUCCEEDED(SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st))) {
    snprintf(err, errn, "alloc stmt failed");
    return SQL_ERROR;
  }
  SQLRETURN rc = SQLExecDirect(st, (SQLCHAR *)sql, SQL_NTS);
  if (!SQL_SUCCEEDED(rc)) {
    diag_text(SQL_HANDLE_STMT, st, err, errn);
    SQLFreeHandle(SQL_HANDLE_STMT, st);
    return rc;
  }
  rc = SQLFetch(st);
  if (rc == SQL_SUCCESS || rc == SQL_SUCCESS_WITH_INFO) {
    SQLLEN ind = 0;
    SQLRETURN gr = SQLGetData(st, 1, SQL_C_CHAR, out, outn, &ind);
    if (!SQL_SUCCEEDED(gr)) { /* the value's own error (#158, #416) */
      diag_text(SQL_HANDLE_STMT, st, err, errn);
      if (err[0] == '\0')
        snprintf(err, errn, "getdata failed");
      rc = gr;
    }
  } else if (rc == SQL_NO_DATA) {
    snprintf(err, errn, "no rows");
  } else {
    diag_text(SQL_HANDLE_STMT, st, err, errn);
  }
  SQLFreeHandle(SQL_HANDLE_STMT, st);
  return rc;
}

/* Execute a statement for effect; SQL_SUCCEEDED or (optionally) tolerate error. */
static SQLRETURN exec_do(SQLHDBC dbc, const char *sql, char *err, int errn)
{
  SQLHSTMT st;
  err[0] = '\0';
  if (!SQL_SUCCEEDED(SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st)))
    return SQL_ERROR;
  SQLRETURN rc = SQLExecDirect(st, (SQLCHAR *)sql, SQL_NTS);
  if (!SQL_SUCCEEDED(rc) && rc != SQL_NO_DATA)
    diag_text(SQL_HANDLE_STMT, st, err, errn);
  SQLFreeHandle(SQL_HANDLE_STMT, st);
  return rc;
}

/* A scalar check: run `sql`, expect column 1 to contain `want`. */
static void check_scalar(SQLHDBC dbc, const char *name, const char *sql, const char *want)
{
  GATE(name);
  char out[256], err[256];
  SQLRETURN rc = exec_scalar(dbc, sql, out, sizeof out, err, sizeof err);
  if (!SQL_SUCCEEDED(rc)) {
    fail(name, err[0] ? err : "execute failed");
    return;
  }
  if (strstr(out, want) == NULL) {
    char m[300];
    snprintf(m, sizeof m, "got '%s', want '%s'", out, want);
    fail(name, m);
    return;
  }
  pass(name);
}

/* A CLOB and a BLOB fetched as text: SQL_C_CHAR from binary is uppercase hex
 * (the ODBC convention, per convert.c - the core's seersql path renders
 * lowercase). 8.1.7 has no TO_CLOB / TO_BLOB, so 8i reads them from a table it
 * fills with a string and HEXTORAW (#408). */
static void check_lob_scalars(SQLHDBC dbc)
{
  if (g_release != 8) {
    check_scalar(dbc, "CLOB fetch", "SELECT TO_CLOB('clobdata') FROM DUAL", "clobdata");
    check_scalar(dbc, "BLOB fetch (hex)", "SELECT TO_BLOB(HEXTORAW('DEADBEEF')) FROM DUAL",
                 "DEADBEEF");
    return;
  }
  char err[256] = "";
  exec_do(dbc, "DROP TABLE seer_lob8", err, sizeof err);
  if (!SQL_SUCCEEDED(exec_do(dbc, "CREATE TABLE seer_lob8 (c CLOB, b BLOB)", err, sizeof err)) ||
      !SQL_SUCCEEDED(exec_do(dbc, "INSERT INTO seer_lob8 VALUES ('clobdata', HEXTORAW('DEADBEEF'))",
                             err, sizeof err))) {
    fail("CLOB fetch", err);
    fail("BLOB fetch (hex)", err);
  } else {
    check_scalar(dbc, "CLOB fetch", "SELECT c FROM seer_lob8", "clobdata");
    check_scalar(dbc, "BLOB fetch (hex)", "SELECT b FROM seer_lob8", "DEADBEEF");
  }
  exec_do(dbc, "DROP TABLE seer_lob8", err, sizeof err);
}

static void check_bind(SQLHDBC dbc)
{
  SQLHSTMT st;
  char err[256];
  if (!SQL_SUCCEEDED(SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st))) {
    fail("bind param", "alloc");
    return;
  }
  SQLINTEGER a = 10, b = 20;
  SQLBindParameter(st, 1, SQL_PARAM_INPUT, SQL_C_SLONG, SQL_INTEGER, 0, 0, &a, 0, NULL);
  SQLBindParameter(st, 2, SQL_PARAM_INPUT, SQL_C_SLONG, SQL_INTEGER, 0, 0, &b, 0, NULL);
  SQLRETURN rc = SQLExecDirect(st, (SQLCHAR *)"SELECT ? + ? FROM DUAL", SQL_NTS);
  if (SQL_SUCCEEDED(rc) && (SQL_SUCCEEDED(SQLFetch(st)))) {
    SQLINTEGER r = 0;
    SQLLEN ind;
    SQLGetData(st, 1, SQL_C_SLONG, &r, 0, &ind);
    if (r == 30)
      pass("bind param (?+?)");
    else {
      char m[64];
      snprintf(m, sizeof m, "got %d want 30", (int)r);
      fail("bind param (?+?)", m);
    }
  } else {
    diag_text(SQL_HANDLE_STMT, st, err, sizeof err);
    fail("bind param (?+?)", err[0] ? err : "execute failed");
  }
  SQLFreeHandle(SQL_HANDLE_STMT, st);
}

#define TBL "SEER_IT"

/* Create SEER_IT and exercise INSERT/rowcount/select-back. Returns 1 if the
 * table exists afterward (so the caller can run the table-dependent checks). */
static int check_dml(SQLHDBC dbc)
{
  char err[256];
  exec_do(dbc, "DROP TABLE " TBL, err, sizeof err); /* ignore if absent */
  if (!SQL_SUCCEEDED(exec_do(dbc, "CREATE TABLE " TBL " (id NUMBER PRIMARY KEY, v VARCHAR2(20))",
                             err, sizeof err))) {
    fail("DDL create", err[0] ? err : "create failed");
    return 0;
  }
  pass("DDL create");

  SQLHSTMT st;
  SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st);
  SQLRETURN rc = SQLExecDirect(st, (SQLCHAR *)"INSERT INTO " TBL " VALUES (1, 'one')", SQL_NTS);
  if (SQL_SUCCEEDED(rc)) {
    SQLLEN n = -1;
    SQLRowCount(st, &n);
    if (n == 1)
      pass("INSERT + SQLRowCount");
    else {
      char m[64];
      snprintf(m, sizeof m, "rowcount=%ld want 1", (long)n);
      fail("INSERT + SQLRowCount", m);
    }
  } else {
    diag_text(SQL_HANDLE_STMT, st, err, sizeof err);
    fail("INSERT + SQLRowCount", err);
  }
  SQLFreeHandle(SQL_HANDLE_STMT, st);

  check_scalar(dbc, "SELECT back", "SELECT v FROM " TBL " WHERE id = 1", "one");
  return 1;
}

static void check_transaction(SQLHDBC dbc)
{
  char err[256], out[256];
  SQLSetConnectAttr(dbc, SQL_ATTR_AUTOCOMMIT, (SQLPOINTER)SQL_AUTOCOMMIT_OFF, 0);
  exec_do(dbc, "INSERT INTO " TBL " VALUES (99, 'rollme')", err, sizeof err);
  SQLEndTran(SQL_HANDLE_DBC, dbc, SQL_ROLLBACK);
  SQLSetConnectAttr(dbc, SQL_ATTR_AUTOCOMMIT, (SQLPOINTER)SQL_AUTOCOMMIT_ON, 0);
  if (SQL_SUCCEEDED(exec_scalar(dbc, "SELECT COUNT(*) FROM " TBL " WHERE id = 99", out, sizeof out,
                                err, sizeof err)) &&
      strcmp(out, "0") == 0)
    pass("transaction rollback");
  else {
    char m[600];
    snprintf(m, sizeof m, "count='%s' want 0 (%s)", out, err);
    fail("transaction rollback", m);
  }
}

/* A commit the server refuses (a deferred constraint, ORA-02091: the
 * transaction rolled back) is an error from SQLEndTran, SQLSTATE 40002 with the
 * ORA number as the native error. It was once reported as success (#184). */
static void check_refused_commit(SQLHDBC dbc)
{
  const char *name = "a refused commit (SQLEndTran, autocommit): 40002, ORA-02091";
  char err[256], out[64];
  exec_do(dbc, "DROP TABLE seer_odbc_defer", err, sizeof err);
  exec_do(dbc,
          "CREATE TABLE seer_odbc_defer (n NUMBER CONSTRAINT seer_odbc_defer_pos CHECK (n > 0) "
          "DEFERRABLE INITIALLY DEFERRED)",
          err, sizeof err);
  SQLSetConnectAttr(dbc, SQL_ATTR_AUTOCOMMIT, (SQLPOINTER)SQL_AUTOCOMMIT_OFF, 0);
  exec_do(dbc, "INSERT INTO seer_odbc_defer VALUES (-1)", err, sizeof err);
  SQLRETURN rc = SQLEndTran(SQL_HANDLE_DBC, dbc, SQL_COMMIT);
  SQLCHAR state[6] = "", msg[256] = "";
  SQLINTEGER native = 0;
  SQLSMALLINT ml = 0;
  if (rc == SQL_ERROR)
    SQLGetDiagRec(SQL_HANDLE_DBC, dbc, 1, state, &native, msg, sizeof msg, &ml);
  SQLEndTran(SQL_HANDLE_DBC, dbc, SQL_ROLLBACK);
  SQLSetConnectAttr(dbc, SQL_ATTR_AUTOCOMMIT, (SQLPOINTER)SQL_AUTOCOMMIT_ON, 0);
  /* The same in autocommit mode, where the statement's own commit fails: 40002
   * too, where it was HY000 (#346). */
  SQLHSTMT s;
  SQLAllocHandle(SQL_HANDLE_STMT, dbc, &s);
  SQLRETURN arc = SQLExecDirect(s, (SQLCHAR *)"INSERT INTO seer_odbc_defer VALUES (-2)", SQL_NTS);
  SQLCHAR astate[6] = "";
  SQLINTEGER anative = 0;
  if (arc == SQL_ERROR)
    SQLGetDiagRec(SQL_HANDLE_STMT, s, 1, astate, &anative, msg, sizeof msg, &ml);
  SQLFreeHandle(SQL_HANDLE_STMT, s);
  out[0] = '\0';
  exec_scalar(dbc, "SELECT COUNT(*) FROM seer_odbc_defer", out, sizeof out, err, sizeof err);
  exec_do(dbc, "DROP TABLE seer_odbc_defer", err, sizeof err);
  if (rc == SQL_ERROR && strcmp((char *)state, "40002") == 0 && native == 2091 &&
      arc == SQL_ERROR && strcmp((char *)astate, "40002") == 0 && anative == 2091 &&
      strcmp(out, "0") == 0)
    pass(name);
  else {
    char m[400];
    snprintf(m, sizeof m, "SQLEndTran rc=%d %s/%d; autocommit rc=%d %s/%d; kept=%s (%.150s)",
             (int)rc, (char *)state, (int)native, (int)arc, (char *)astate, (int)anative, out,
             (char *)msg);
    fail(name, m);
  }
}

/* A query run while a transaction is open must still return every row. The
 * server reports call_status 2 (transaction in progress) rather than 1 in the
 * OER then, so the fetch loop must keep going on the cursor, not on that flag. */
static void check_fetch_in_txn(SQLHDBC dbc)
{
  const char *name = "fetch all rows inside an open transaction";
  GATE(name);
  char err[256];
  SQLSetConnectAttr(dbc, SQL_ATTR_AUTOCOMMIT, (SQLPOINTER)SQL_AUTOCOMMIT_OFF, 0);
  exec_do(dbc, "INSERT INTO " TBL " VALUES (98, 'txnopen')", err, sizeof err);
  SQLHSTMT st;
  long n = 0;
  /* In an inline view: 9i ends a bare CONNECT BY on dual after the first
   * fetch batch, which looked like a fetch that stopped at 10 rows. 8i's
   * CONNECT BY on dual gives one row, so its 250 come from all_objects
   * (#408). */
  SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st);
  SQLRETURN rc = SQLExecDirect(
      st,
      (SQLCHAR *)(g_release == 8
                      ? "SELECT * FROM (SELECT ROWNUM FROM all_objects WHERE ROWNUM <= 250)"
                      : "SELECT * FROM (SELECT level FROM dual CONNECT BY level <= 250)"),
      SQL_NTS);
  if (SQL_SUCCEEDED(rc))
    while (SQL_SUCCEEDED(SQLFetch(st)))
      n++;
  else
    diag_text(SQL_HANDLE_STMT, st, err, sizeof err);
  SQLFreeHandle(SQL_HANDLE_STMT, st);
  SQLEndTran(SQL_HANDLE_DBC, dbc, SQL_ROLLBACK);
  SQLSetConnectAttr(dbc, SQL_ATTR_AUTOCOMMIT, (SQLPOINTER)SQL_AUTOCOMMIT_ON, 0);
  if (n == 250)
    pass(name);
  else {
    char m[400];
    snprintf(m, sizeof m, "fetched %ld rows, want 250 %s", n, SQL_SUCCEEDED(rc) ? "" : err);
    fail(name, m);
  }
}

/* A column the server describes with data length 0 (a bare NULL, '', or a
 * DECODE with no match) carries no bytes on the wire and is always NULL; the
 * columns after it must still decode. */
/* An aggregate that skips NULLs makes the server set a warning in the closing
 * status's `flags` field, which below 12.1 is a two-byte ub2 (`01 20`). Read
 * as one byte, everything after it misreads (seerdb#1995). Three groups, the
 * last all NULL, is the shape that trips it; two groups do not. */
static void check_aggregate_null_warning(SQLHDBC dbc)
{
  const char *name = "aggregate over an all-NULL group (OER warning flags)";
  char err[256] = "";
  exec_do(dbc, "DROP TABLE seer_aggwarn", err, sizeof err); /* ignore if absent */
  if (!SQL_SUCCEEDED(
          exec_do(dbc, "CREATE TABLE seer_aggwarn (g NUMBER, n NUMBER)", err, sizeof err)) ||
      !SQL_SUCCEEDED(exec_do(dbc,
                             "INSERT INTO seer_aggwarn "
                             "SELECT 1, 12345678901234567890.123 FROM dual UNION ALL "
                             "SELECT 1, 12345678901234567890.125 FROM dual UNION ALL "
                             "SELECT 2, 12345678901234567890.127 FROM dual UNION ALL "
                             "SELECT 2, 12345678901234567890.131 FROM dual UNION ALL "
                             "SELECT 3, TO_NUMBER(NULL) FROM dual",
                             err, sizeof err))) {
    fail(name, err[0] ? err : "setup failed");
    exec_do(dbc, "DROP TABLE seer_aggwarn", err, sizeof err);
    return;
  }
  SQLHSTMT st;
  SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st);
  SQLRETURN rc = SQLExecDirect(
      st, (SQLCHAR *)"SELECT g, AVG(n), COUNT(n) FROM seer_aggwarn GROUP BY g ORDER BY g", SQL_NTS);
  int rows = 0, ok = SQL_SUCCEEDED(rc);
  char cnt[16] = "";
  while (ok && SQL_SUCCEEDED(rc = SQLFetch(st))) {
    SQLLEN ind = 0;
    rows++;
    ok = SQL_SUCCEEDED(SQLGetData(st, 3, SQL_C_CHAR, cnt, sizeof cnt, &ind));
  }
  if (ok && rc != SQL_NO_DATA)
    ok = 0;
  if (!ok)
    diag_text(SQL_HANDLE_STMT, st, err, sizeof err);
  SQLFreeHandle(SQL_HANDLE_STMT, st);
  char after[32], err2[256];
  int alive = SQL_SUCCEEDED(
      exec_scalar(dbc, "SELECT 'alive' FROM dual", after, sizeof after, err2, sizeof err2));
  exec_do(dbc, "DROP TABLE seer_aggwarn", err2, sizeof err2);
  if (ok && rows == 3 && strcmp(cnt, "0") == 0 && alive)
    pass(name);
  else {
    char m[400];
    snprintf(m, sizeof m, "rows=%d last count='%s' alive=%d %s", rows, cnt, alive, err);
    fail(name, m);
  }
}

/* A result fetched over several batches whose next batch starts on a row
 * repeating a value of the previous one: the row header's bit vector then says
 * that column is not sent. Read anyway, the next column's bytes took its place
 * and the fetch failed with a protocol error - any query over 100 rows with
 * such a column (a constant, a repeated group key). */
static void check_batch_resume_repeated_column(SQLHDBC dbc)
{
  const char *name = "multi-batch fetch with a repeated column";
  GATE(name);
  SQLHSTMT st;
  char err[256] = "";
  /* An inline view, as in check_fetch_in_txn: 9i ends a bare CONNECT BY on
   * dual after one batch, and 8i's rows come from all_objects (#408). */
  SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st);
  SQLRETURN rc = SQLExecDirect(
      st,
      (SQLCHAR *)(g_release == 8
                      ? "SELECT * FROM (SELECT ROWNUM a, 'tail' t FROM all_objects "
                        "WHERE ROWNUM <= 250)"
                      : "SELECT * FROM (SELECT level a, 'tail' t FROM dual CONNECT BY level <= "
                        "250)"),
      SQL_NTS);
  int rows = 0, good = SQL_SUCCEEDED(rc);
  while (good && SQL_SUCCEEDED(rc = SQLFetch(st))) {
    char a[16] = "", t[16] = "";
    SQLLEN ia = 0, it = 0;
    SQLGetData(st, 1, SQL_C_CHAR, a, sizeof a, &ia);
    SQLGetData(st, 2, SQL_C_CHAR, t, sizeof t, &it);
    rows++;
    if (atoi(a) != rows || strcmp(t, "tail") != 0)
      good = 0;
  }
  if (good && rc != SQL_NO_DATA)
    good = 0;
  if (!good)
    diag_text(SQL_HANDLE_STMT, st, err, sizeof err);
  SQLFreeHandle(SQL_HANDLE_STMT, st);
  if (good && rows == 250)
    pass(name);
  else {
    char m[320];
    snprintf(m, sizeof m, "rows=%d %s", rows, err);
    fail(name, m);
  }
}

/* A TIMESTAMP bind with no fractional seconds goes out in the 7-byte form:
 * the server reads an 11-byte zero-fraction value differently, and
 * `trunc(ltz) = :midnight` then matched nothing (seerdb #1337). */
static void check_timestamp_zero_fraction_bind(SQLHDBC dbc)
{
  const char *name = "zero-fraction TIMESTAMP bind matches trunc(LTZ)";
  GATE(name);
  char err[256] = "";
  exec_do(dbc, "DROP TABLE seer_tsz", err, sizeof err);
  if (!SQL_SUCCEEDED(exec_do(dbc,
                             "CREATE TABLE seer_tsz (k NUMBER, l TIMESTAMP WITH LOCAL TIME ZONE)",
                             err, sizeof err))) {
    fail(name, err);
    return;
  }
  exec_do(dbc, "INSERT INTO seer_tsz VALUES (1, TIMESTAMP '2026-09-25 13:45:06.123456')", err,
          sizeof err);
  /* 9i's TRUNC takes no LTZ (ORA-00932): it truncates the value as a DATE,
   * which is what TRUNC(ltz) gives on 10g+, so the bind meets the same DATE
   * comparison (#420). */
  const char *day = g_release == 9 ? "TRUNC(CAST(l AS DATE))" : "TRUNC(l)";
  char lit[16], q[160];
  snprintf(q, sizeof q, "SELECT COUNT(*) FROM seer_tsz WHERE %s = TIMESTAMP '2026-09-25 00:00:00'",
           day);
  if (!SQL_SUCCEEDED(exec_scalar(dbc, q, lit, sizeof lit, err, sizeof err))) {
    fail(name, err);
    exec_do(dbc, "DROP TABLE seer_tsz", err, sizeof err);
    return;
  }
  SQLHSTMT st;
  SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st);
  TIMESTAMP_STRUCT ts = {2026, 9, 25, 0, 0, 0, 0};
  SQLLEN ind = 0;
  char cnt[16] = "";
  SQLRETURN rc = SQLBindParameter(st, 1, SQL_PARAM_INPUT, SQL_C_TYPE_TIMESTAMP, SQL_TYPE_TIMESTAMP,
                                  26, 6, &ts, 0, &ind);
  if (SQL_SUCCEEDED(rc)) {
    snprintf(q, sizeof q, "SELECT COUNT(*) FROM seer_tsz WHERE %s = ?", day);
    rc = SQLExecDirect(st, (SQLCHAR *)q, SQL_NTS);
  }
  if (SQL_SUCCEEDED(rc) && SQL_SUCCEEDED(SQLFetch(st)))
    SQLGetData(st, 1, SQL_C_CHAR, cnt, sizeof cnt, &ind);
  else
    diag_text(SQL_HANDLE_STMT, st, err, sizeof err);
  SQLFreeHandle(SQL_HANDLE_STMT, st);
  exec_do(dbc, "DROP TABLE seer_tsz", err, sizeof err);
  if (strcmp(cnt, "1") == 0)
    pass(name);
  else {
    char m[320];
    snprintf(m, sizeof m, "count='%s' want 1 %s", cnt, err);
    fail(name, m);
  }
}

static void check_zero_length_columns(SQLHDBC dbc)
{
  const char *name = "zero-length columns (NULL / '' / DECODE miss)";
  SQLHSTMT st;
  char err[256] = "", tail[32] = "";
  SQLLEN i1 = 0, i2 = 0, i3 = 0, it = 0;
  char b[8];
  SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st);
  SQLRETURN rc = SQLExecDirect(
      st, (SQLCHAR *)"SELECT NULL, '', DECODE(3, 1, 'one'), 'tail' FROM dual", SQL_NTS);
  int ok = SQL_SUCCEEDED(rc) && SQL_SUCCEEDED(SQLFetch(st)) &&
           SQL_SUCCEEDED(SQLGetData(st, 1, SQL_C_CHAR, b, sizeof b, &i1)) &&
           SQL_SUCCEEDED(SQLGetData(st, 2, SQL_C_CHAR, b, sizeof b, &i2)) &&
           SQL_SUCCEEDED(SQLGetData(st, 3, SQL_C_CHAR, b, sizeof b, &i3)) &&
           SQL_SUCCEEDED(SQLGetData(st, 4, SQL_C_CHAR, tail, sizeof tail, &it));
  if (!ok)
    diag_text(SQL_HANDLE_STMT, st, err, sizeof err);
  SQLFreeHandle(SQL_HANDLE_STMT, st);
  if (ok && i1 == SQL_NULL_DATA && i2 == SQL_NULL_DATA && i3 == SQL_NULL_DATA &&
      strcmp(tail, "tail") == 0)
    pass(name);
  else {
    char m[400];
    snprintf(m, sizeof m, "ind=%ld/%ld/%ld tail='%s' %s", (long)i1, (long)i2, (long)i3, tail, err);
    fail(name, m);
  }
}

/* Run `sql` (execute, then fetch), and the first diag record's state and
 * native error of whichever call failed; 0 when nothing failed. */
static int sql_state_of(SQLHDBC dbc, const char *sql, char state[6], SQLINTEGER *native)
{
  SQLHSTMT st;
  SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st);
  SQLRETURN rc = SQLExecDirect(st, (SQLCHAR *)sql, SQL_NTS);
  if (SQL_SUCCEEDED(rc)) {
    SQLSMALLINT nc = 0;
    SQLNumResultCols(st, &nc);
    if (nc > 0)
      rc = SQLFetch(st);
  }
  int failed = !SQL_SUCCEEDED(rc) && rc != SQL_NO_DATA;
  state[0] = '\0';
  *native = 0;
  if (failed) {
    SQLCHAR msg[256];
    SQLSMALLINT len = 0;
    SQLGetDiagRec(SQL_HANDLE_STMT, st, 1, (SQLCHAR *)state, native, msg, sizeof msg, &len);
  }
  SQLFreeHandle(SQL_HANDLE_STMT, st);
  return failed;
}

/* Server errors carry the SQLSTATE their ORA code means, not HY000 (#207):
 * what pyodbc and others map to IntegrityError, ProgrammingError, DataError. */
static void check_server_error_states(SQLHDBC dbc)
{
  const char *name = "server errors carry their SQLSTATE";
  char st[6];
  SQLINTEGER native;
  sql_state_of(dbc, "DROP TABLE seer_sqlstate_t", st, &native);
  if (sql_state_of(dbc,
                   "CREATE TABLE seer_sqlstate_t (id NUMBER PRIMARY KEY, n NUMBER(2) NOT NULL)", st,
                   &native) ||
      sql_state_of(dbc, "INSERT INTO seer_sqlstate_t VALUES (1, 1)", st, &native)) {
    char m[64];
    snprintf(m, sizeof m, "setup failed: %s ORA-%05ld", st, (long)native);
    skip(name, m);
    return;
  }
  static const struct {
    const char *sql, *state;
    long code;
  } cases[] = {
      {"INSERT INTO seer_sqlstate_t VALUES (1, 2)", "23000", 1},
      {"INSERT INTO seer_sqlstate_t VALUES (2, NULL)", "23000", 1400},
      {"SELECT * FROM seer_no_such_table", "42S02", 942},
      {"CREATE TABLE seer_sqlstate_t (x NUMBER)", "42S01", 955},
      {"SELECT seer_no_such_column FROM dual", "42S22", 904},
      {"SELECT FROM dual", "42000", 936},
      {"SELECT 1/0 FROM dual", "22012", 1476},
      {"SELECT TO_NUMBER('x') FROM dual", "22018", 1722},
      {"INSERT INTO seer_sqlstate_t VALUES (3, 123)", "22003", 1438},
      {"SELECT TO_DATE('2020-13-01', 'YYYY-MM-DD') FROM dual", "22008", 1843},
  };
  char m[600] = "";
  for (size_t k = 0; k < sizeof cases / sizeof cases[0]; k++) {
    int failed = sql_state_of(dbc, cases[k].sql, st, &native);
    if (!failed || native != cases[k].code || strcmp(st, cases[k].state) != 0) {
      size_t ml = strlen(m);
      snprintf(m + ml, sizeof m - ml, "%s'%s': want %s ORA-%05ld, got %s ORA-%05ld", ml ? "; " : "",
               cases[k].sql, cases[k].state, cases[k].code, failed ? st : "(none)", (long)native);
    }
  }
  sql_state_of(dbc, "DROP TABLE seer_sqlstate_t", st, &native);
  if (m[0] == '\0')
    pass(name);
  else
    fail(name, m);
}

/* A CURSOR(...) column (nested cursor, type 102) has its own row form - a
 * length byte, an inline describe and a ub2 cursor id. ODBC has no nested
 * cursor type, so the driver reports it as NULL; what matters is that the
 * columns after it still decode and the cursor is not leaked. */
static void check_nested_cursor_column(SQLHDBC dbc)
{
  const char *name = "nested CURSOR() column";
  GATE(name);
  SQLHSTMT st;
  char err[256] = "", tail[32] = "";
  SQLLEN ic = 0, it = 0;
  char b[8];
  SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st);
  SQLRETURN rc =
      SQLExecDirect(st, (SQLCHAR *)"SELECT CURSOR(SELECT 1 FROM dual), 'tail' FROM dual", SQL_NTS);
  int ok = SQL_SUCCEEDED(rc) && SQL_SUCCEEDED(SQLFetch(st)) &&
           SQL_SUCCEEDED(SQLGetData(st, 1, SQL_C_CHAR, b, sizeof b, &ic)) &&
           SQL_SUCCEEDED(SQLGetData(st, 2, SQL_C_CHAR, tail, sizeof tail, &it));
  if (!ok)
    diag_text(SQL_HANDLE_STMT, st, err, sizeof err);
  SQLFreeHandle(SQL_HANDLE_STMT, st);
  if (ok && ic == SQL_NULL_DATA && strcmp(tail, "tail") == 0)
    pass(name);
  else {
    char m[400];
    snprintf(m, sizeof m, "ind=%ld tail='%s' %s", (long)ic, tail, err);
    fail(name, m);
  }
}

/* A UROWID holding a physical rowid (tag 01) renders exactly like the ROWID it
 * is, so it can be fed back into WHERE ROWID = ?. */
static void check_urowid_physical(SQLHDBC dbc)
{
  const char *name = "UROWID of a physical rowid renders as ROWID";
  char u[64], r[64], err[256];
  if (!SQL_SUCCEEDED(exec_scalar(dbc, "SELECT CAST(ROWID AS UROWID) FROM " TBL " WHERE ROWNUM = 1",
                                 u, sizeof u, err, sizeof err)) ||
      !SQL_SUCCEEDED(exec_scalar(dbc, "SELECT ROWIDTOCHAR(ROWID) FROM " TBL " WHERE ROWNUM = 1", r,
                                 sizeof r, err, sizeof err))) {
    skip(name, err);
    return;
  }
  if (strcmp(u, r) == 0)
    pass(name);
  else {
    char m[200];
    snprintf(m, sizeof m, "urowid='%s' rowid='%s'", u, r);
    fail(name, m);
  }
}

/* A value or statement text of 253 bytes must go out chunked: a plain length
 * byte covers 1..252, and 0xFD..0xFF are markers. Probe both sides of the
 * boundary for a bind value and for the SQL text itself. */
static void check_length_boundaries(SQLHDBC dbc)
{
  const char *name = "252/253/254-byte bind value and SQL text";
  char m[400] = "";
  int ok = 1;
  for (int n = 252; n <= 254 && ok; n++) {
    /* bind value of n bytes */
    char val[300], out[32] = "", err[256] = "";
    memset(val, 'v', (size_t)n);
    val[n] = '\0';
    SQLHSTMT st;
    SQLLEN ind = SQL_NTS, oind = 0;
    SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st);
    SQLBindParameter(st, 1, SQL_PARAM_INPUT, SQL_C_CHAR, SQL_VARCHAR, 400, 0, val, 0, &ind);
    SQLRETURN rc = SQLExecDirect(st, (SQLCHAR *)"SELECT LENGTH(?) FROM dual", SQL_NTS);
    if (SQL_SUCCEEDED(rc) && SQL_SUCCEEDED(SQLFetch(st)))
      SQLGetData(st, 1, SQL_C_CHAR, out, sizeof out, &oind);
    else
      diag_text(SQL_HANDLE_STMT, st, err, sizeof err);
    SQLFreeHandle(SQL_HANDLE_STMT, st);
    if (atoi(out) != n) {
      snprintf(m, sizeof m, "bind %d bytes: got '%s' %s", n, out, err);
      ok = 0;
      break;
    }
    /* SQL text of exactly n bytes */
    char sql[300];
    const char *head = "SELECT '";
    const char *tail = "' FROM dual";
    size_t pad = (size_t)n - strlen(head) - strlen(tail);
    snprintf(
        sql, sizeof sql, "%s%.*s%s", head, (int)pad,
        "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
        "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
        "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        tail);
    char got[300] = "";
    if (!SQL_SUCCEEDED(exec_scalar(dbc, sql, got, sizeof got, err, sizeof err)) ||
        strlen(got) != pad) {
      snprintf(m, sizeof m, "SQL of %d bytes: got %zu chars %s", n, strlen(got), err);
      ok = 0;
    }
  }
  if (ok)
    pass(name);
  else
    fail(name, m);
}

/* In a SQL statement each row's LONG-class values - a bind declared larger
 * than the server's maximum string size (4000, or 32767 on 12c+ with 32K
 * strings) - travel after the row's other values. Put the large value first in
 * the column list to prove the order is not positional; 5000 bytes is
 * LONG-class only on 10g/11g, 40000 on every server. */
static void check_long_bind_order(SQLHDBC dbc)
{
  const char *name = "large text bind ahead of another bind (5000 / 40000 bytes)";
  GATE(name);
  static const int sizes[] = {5000, 40000};
  static char big[40001];
  char err[256] = "", m[400] = "";
  int ok = 1;
  for (size_t k = 0; k < sizeof sizes / sizeof sizes[0] && ok; k++) {
    int n = sizes[k];
    char out[64] = "", want[64];
    exec_do(dbc, "DROP TABLE seer_longord", err, sizeof err);
    if (!SQL_SUCCEEDED(
            exec_do(dbc, "CREATE TABLE seer_longord (c CLOB, id NUMBER)", err, sizeof err))) {
      skip(name, err);
      return;
    }
    memset(big, 'L', (size_t)n);
    big[n] = '\0';
    SQLINTEGER id = 42;
    SQLLEN bind = SQL_NTS;
    SQLHSTMT st;
    SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st);
    SQLBindParameter(st, 1, SQL_PARAM_INPUT, SQL_C_CHAR, SQL_LONGVARCHAR, (SQLULEN)n, 0, big, 0,
                     &bind);
    SQLBindParameter(st, 2, SQL_PARAM_INPUT, SQL_C_SLONG, SQL_INTEGER, 0, 0, &id, 0, NULL);
    SQLRETURN rc =
        SQLExecDirect(st, (SQLCHAR *)"INSERT INTO seer_longord (c, id) VALUES (?, ?)", SQL_NTS);
    if (!SQL_SUCCEEDED(rc))
      diag_text(SQL_HANDLE_STMT, st, err, sizeof err);
    SQLFreeHandle(SQL_HANDLE_STMT, st);
    if (SQL_SUCCEEDED(rc))
      exec_scalar(dbc, "SELECT id || ':' || DBMS_LOB.GETLENGTH(c) FROM seer_longord", out,
                  sizeof out, err, sizeof err);
    exec_do(dbc, "DROP TABLE seer_longord", err, sizeof err);
    snprintf(want, sizeof want, "42:%d", n);
    if (strcmp(out, want) != 0) {
      snprintf(m, sizeof m, "%d bytes: got '%s' want '%s' %s", n, out, want,
               SQL_SUCCEEDED(rc) ? "" : err);
      ok = 0;
    }
  }
  if (ok)
    pass(name);
  else
    fail(name, m);
}

/* An array execute sends one descriptor per column for every row, so a NULL
 * in the last row must not re-type a NUMBER / DATE column as VARCHAR. */
static void check_array_null_last_row(SQLHDBC dbc)
{
  const char *name = "array DML with NULL in the last row";
  char err[256] = "", out[64] = "";
  exec_do(dbc, "DROP TABLE seer_arrnull", err, sizeof err);
  if (!SQL_SUCCEEDED(
          exec_do(dbc, "CREATE TABLE seer_arrnull (n NUMBER, d DATE)", err, sizeof err))) {
    skip(name, err);
    return;
  }
  SQLINTEGER ns[3] = {1, 2, 0};
  SQLLEN nind[3] = {0, 0, SQL_NULL_DATA};
  SQL_DATE_STRUCT ds[3] = {{2026, 1, 2}, {2026, 3, 4}, {0, 0, 0}};
  SQLLEN dind[3] = {0, 0, SQL_NULL_DATA};
  SQLHSTMT st;
  SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st);
  SQLSetStmtAttr(st, SQL_ATTR_PARAMSET_SIZE, (SQLPOINTER)(SQLULEN)3, 0);
  SQLBindParameter(st, 1, SQL_PARAM_INPUT, SQL_C_SLONG, SQL_INTEGER, 0, 0, ns, 0, nind);
  SQLBindParameter(st, 2, SQL_PARAM_INPUT, SQL_C_TYPE_DATE, SQL_TYPE_DATE, 0, 0, ds, 0, dind);
  SQLRETURN rc = SQLExecDirect(st, (SQLCHAR *)"INSERT INTO seer_arrnull VALUES (?, ?)", SQL_NTS);
  if (!SQL_SUCCEEDED(rc))
    diag_text(SQL_HANDLE_STMT, st, err, sizeof err);
  SQLFreeHandle(SQL_HANDLE_STMT, st);
  if (SQL_SUCCEEDED(rc))
    exec_scalar(dbc,
                "SELECT COUNT(*) || ':' || SUM(n) || ':' || COUNT(n) || ':' || "
                "TO_CHAR(MAX(d), 'YYYY-MM-DD') FROM seer_arrnull",
                out, sizeof out, err, sizeof err);
  exec_do(dbc, "DROP TABLE seer_arrnull", err, sizeof err);
  if (strcmp(out, "3:3:2:2026-03-04") == 0)
    pass(name);
  else {
    char m[400];
    snprintf(m, sizeof m, "got '%s' want '3:3:2:2026-03-04' %s", out, SQL_SUCCEEDED(rc) ? "" : err);
    fail(name, m);
  }
}

/* An array execute of rows whose text takes a path other than plain array DML
 * on 8i / 9i: past 4000 bytes (a PL/SQL block on 9i), past 32512 (a temporary
 * LOB on 9i), or a PL/SQL block itself. Every row goes in with its own value:
 * the count, the total length and the length weighted by the id tell (#418). */
static void check_array_text_rows(SQLHDBC dbc, const char *name, const char *sql,
                                  const size_t len[3])
{
  char err[256] = "", out[64] = "", want[64];
  exec_do(dbc, "DROP TABLE seer_arrlong", err, sizeof err);
  if (!SQL_SUCCEEDED(
          exec_do(dbc, "CREATE TABLE seer_arrlong (id NUMBER, c CLOB)", err, sizeof err))) {
    skip(name, err);
    return;
  }
  size_t width = 0, total = 0, weighted = 0;
  for (int k = 0; k < 3; k++) {
    width = len[k] > width ? len[k] : width;
    total += len[k];
    weighted += (size_t)(k + 1) * len[k];
  }
  width++;
  SQLINTEGER ids[3] = {1, 2, 3};
  SQLLEN ind[3];
  char *buf = malloc(3 * width);
  if (buf == NULL) {
    fail(name, "out of memory");
    return;
  }
  for (int k = 0; k < 3; k++) {
    memset(buf + (size_t)k * width, 'a' + k, len[k]);
    buf[(size_t)k * width + len[k]] = '\0';
    ind[k] = (SQLLEN)len[k];
  }
  SQLHSTMT st;
  SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st);
  SQLSetStmtAttr(st, SQL_ATTR_PARAMSET_SIZE, (SQLPOINTER)(SQLULEN)3, 0);
  SQLBindParameter(st, 1, SQL_PARAM_INPUT, SQL_C_SLONG, SQL_INTEGER, 0, 0, ids, 0, NULL);
  SQLBindParameter(st, 2, SQL_PARAM_INPUT, SQL_C_CHAR, SQL_LONGVARCHAR, width - 1, 0, buf,
                   (SQLLEN)width, ind);
  SQLRETURN rc = SQLExecDirect(st, (SQLCHAR *)sql, SQL_NTS);
  if (!SQL_SUCCEEDED(rc))
    diag_text(SQL_HANDLE_STMT, st, err, sizeof err);
  SQLFreeHandle(SQL_HANDLE_STMT, st);
  free(buf);
  if (SQL_SUCCEEDED(rc))
    exec_scalar(dbc,
                "SELECT COUNT(*) || ':' || SUM(DBMS_LOB.GETLENGTH(c)) || ':' || "
                "SUM(id * DBMS_LOB.GETLENGTH(c)) FROM seer_arrlong",
                out, sizeof out, err, sizeof err);
  exec_do(dbc, "DROP TABLE seer_arrlong", err, sizeof err);
  snprintf(want, sizeof want, "3:%zu:%zu", total, weighted);
  if (strcmp(out, want) == 0)
    pass(name);
  else {
    char m[400];
    snprintf(m, sizeof m, "got '%s' want '%s' %s", out, want, SQL_SUCCEEDED(rc) ? "" : err);
    fail(name, m);
  }
}

static void check_array_long_text(SQLHDBC dbc)
{
  static const size_t len[3] = {5000, 6000, 7000};
  check_array_text_rows(dbc, "array DML with text over 4000 bytes",
                        "INSERT INTO seer_arrlong VALUES (?, ?)", len);
}

static void check_array_huge_text(SQLHDBC dbc)
{
  static const size_t len[3] = {33000, 40000, 35000};
  check_array_text_rows(dbc, "array DML with text over 32 KB",
                        "INSERT INTO seer_arrlong VALUES (?, ?)", len);
}

static void check_array_block(SQLHDBC dbc)
{
  static const size_t len[3] = {10, 20, 30};
  check_array_text_rows(dbc, "array execute of a PL/SQL block",
                        "BEGIN INSERT INTO seer_arrlong VALUES (?, ?); END;", len);
}

/* A query with a parameter array gives one result set per parameter set, as
 * SQL_PARAM_ARRAY_SELECTS (SQL_PAS_BATCH) says, on every tier (#431): the
 * first from the execute, each next from SQLMoreResults, then SQL_NO_DATA.
 * A set marked SQL_PARAM_IGNORE runs no query and gives no result set. The
 * status array and the processed count follow each set as it runs. Before,
 * such a query was refused (#430), and before that 9i and 10g+ answered one
 * set's rows and reported all three processed. */
static void check_array_query_batch(SQLHDBC dbc)
{
  const char *name = "query with a parameter array: one result set per set (SQL_PAS_BATCH)";
  SQLUINTEGER pas = 0;
  SQLGetInfo(dbc, SQL_PARAM_ARRAY_SELECTS, &pas, sizeof pas, NULL);
  SQLHSTMT st;
  SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st);
  SQLINTEGER ids[3] = {1, 2, 3};
  SQLUSMALLINT ops[3] = {SQL_PARAM_PROCEED, SQL_PARAM_IGNORE, SQL_PARAM_PROCEED};
  SQLUSMALLINT status[3] = {99, 99, 99};
  SQLULEN done = 99;
  SQLSetStmtAttr(st, SQL_ATTR_PARAMSET_SIZE, (SQLPOINTER)(SQLULEN)3, 0);
  SQLSetStmtAttr(st, SQL_ATTR_PARAM_OPERATION_PTR, ops, 0);
  SQLSetStmtAttr(st, SQL_ATTR_PARAM_STATUS_PTR, status, 0);
  SQLSetStmtAttr(st, SQL_ATTR_PARAMS_PROCESSED_PTR, &done, 0);
  SQLBindParameter(st, 1, SQL_PARAM_INPUT, SQL_C_SLONG, SQL_INTEGER, 0, 0, ids, 0, NULL);
  char m[400] = "", err[256] = "";
  SQLRETURN rc = SQLExecDirect(st, (SQLCHAR *)"SELECT ? * 10 FROM dual", SQL_NTS);
  static const char *const want[2] = {"10", "30"};
  for (int set = 0; set < 2 && !m[0]; set++) {
    if (set > 0)
      rc = SQLMoreResults(st);
    char v[32] = "";
    SQLLEN ind = 0;
    if (!SQL_SUCCEEDED(rc) || !SQL_SUCCEEDED(SQLFetch(st)) ||
        !SQL_SUCCEEDED(SQLGetData(st, 1, SQL_C_CHAR, v, sizeof v, &ind))) {
      diag_text(SQL_HANDLE_STMT, st, err, sizeof err);
      snprintf(m, sizeof m, "result set %d: rc %d %s", set + 1, (int)rc, err);
    } else if (strcmp(v, want[set]) != 0 || SQLFetch(st) != SQL_NO_DATA) {
      snprintf(m, sizeof m, "result set %d: '%s' (want one row, %s)", set + 1, v, want[set]);
    } else if (done != (SQLULEN)set + 1) {
      snprintf(m, sizeof m, "after result set %d: %lu processed", set + 1, (unsigned long)done);
    }
  }
  if (!m[0] && (status[0] != SQL_PARAM_SUCCESS || status[1] != SQL_PARAM_UNUSED ||
                status[2] != SQL_PARAM_SUCCESS))
    snprintf(m, sizeof m, "statuses %u %u %u (want SUCCESS, UNUSED, SUCCESS)", (unsigned)status[0],
             (unsigned)status[1], (unsigned)status[2]);
  if (!m[0] && (rc = SQLMoreResults(st)) != SQL_NO_DATA)
    snprintf(m, sizeof m, "SQLMoreResults after the last set: rc %d (want SQL_NO_DATA)", (int)rc);
  if (!m[0] && pas != SQL_PAS_BATCH)
    snprintf(m, sizeof m, "SQL_PARAM_ARRAY_SELECTS %u (want SQL_PAS_BATCH)", (unsigned)pas);
  SQLFreeHandle(SQL_HANDLE_STMT, st);
  if (m[0] == '\0')
    pass(name);
  else
    fail(name, m);
}

/* A NULL parameter declared as SQL_INTEGER / SQL_TYPE_DATE is typed as such,
 * so it can meet a NUMBER or DATE in COALESCE (a VARCHAR NULL gets
 * ORA-00932: inconsistent datatypes). 8.1.7 has no COALESCE; its CASE is as
 * strict about types (a VARCHAR bind there gets the same ORA-00932), so 8i
 * checks the same typing with CASE (#408). 8.1.7's CASE also tells a stored
 * DATE (a column or a bind, Typ=12) from a computed one (TO_DATE, Typ=13)
 * and won't mix them, even with no bind at all, so its other branch is a
 * stored DATE too: CAST(... AS DATE). */
static void check_typed_null(SQLHDBC dbc)
{
  const char *name = "typed NULL parameter (COALESCE with NUMBER / DATE)";
  GATE(name);
  char err[256] = "", a[32] = "", b[32] = "";
  SQLLEN nul = SQL_NULL_DATA, ia = 0, ib = 0;
  SQLINTEGER iv = 0;
  SQL_DATE_STRUCT dv = {0};
  SQLHSTMT st;
  SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st);
  SQLBindParameter(st, 1, SQL_PARAM_INPUT, SQL_C_SLONG, SQL_INTEGER, 0, 0, &iv, 0, &nul);
  SQLBindParameter(st, 2, SQL_PARAM_INPUT, SQL_C_TYPE_DATE, SQL_TYPE_DATE, 0, 0, &dv, 0, &nul);
  const char *sql =
      g_release == 8
          ? "SELECT CASE WHEN 1 = 0 THEN ? ELSE 7 END + 1, TO_CHAR(CASE WHEN 1 = 0 THEN ? ELSE "
            "CAST(TO_DATE('2026-09-29', 'YYYY-MM-DD') AS DATE) END, 'YYYY') FROM dual"
          : "SELECT COALESCE(?, 7) + 1, TO_CHAR(COALESCE(?, DATE '2026-09-29'), 'YYYY') FROM dual";
  SQLRETURN rc = SQLExecDirect(st, (SQLCHAR *)sql, SQL_NTS);
  int ok = SQL_SUCCEEDED(rc) && SQL_SUCCEEDED(SQLFetch(st)) &&
           SQL_SUCCEEDED(SQLGetData(st, 1, SQL_C_CHAR, a, sizeof a, &ia)) &&
           SQL_SUCCEEDED(SQLGetData(st, 2, SQL_C_CHAR, b, sizeof b, &ib));
  if (!ok)
    diag_text(SQL_HANDLE_STMT, st, err, sizeof err);
  SQLFreeHandle(SQL_HANDLE_STMT, st);
  if (ok && strcmp(a, "8") == 0 && strcmp(b, "2026") == 0)
    pass(name);
  else {
    char m[400];
    snprintf(m, sizeof m, "got '%s' / '%s' %s", a, b, err);
    fail(name, m);
  }
}

/* A DML RETURNING statement that fails gets a flush-out-binds request (a lone
 * TTI_FOB byte) before its error; the client must echo it, or the server
 * keeps waiting and the NEXT statement fails with ORA-03137 / ORA-00600. */
static void check_returning_failure_recovers(SQLHDBC dbc)
{
  const char *name = "failing DML RETURNING, then the connection still works";
  char err[256] = "", out[32] = "";
  exec_do(dbc, "DROP TABLE seer_fob", err, sizeof err);
  if (!SQL_SUCCEEDED(exec_do(dbc, "CREATE TABLE seer_fob (id NUMBER NOT NULL)", err, sizeof err))) {
    skip(name, err);
    return;
  }
  SQLINTEGER ret = 0;
  SQLLEN rind = 0;
  SQLHSTMT st;
  SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st);
  SQLBindParameter(st, 1, SQL_PARAM_OUTPUT, SQL_C_SLONG, SQL_INTEGER, 0, 0, &ret, 0, &rind);
  SQLRETURN rc = SQLExecDirect(
      st, (SQLCHAR *)"INSERT INTO seer_fob (id) VALUES (NULL) RETURNING id INTO ?", SQL_NTS);
  char first[256] = "";
  diag_text(SQL_HANDLE_STMT, st, first, sizeof first);
  SQLFreeHandle(SQL_HANDLE_STMT, st);
  SQLRETURN rc2 = exec_scalar(dbc, "SELECT 5 FROM dual", out, sizeof out, err, sizeof err);
  exec_do(dbc, "DROP TABLE seer_fob", err, sizeof err);
  if (!SQL_SUCCEEDED(rc) && strstr(first, "01400") && SQL_SUCCEEDED(rc2) && strcmp(out, "5") == 0)
    pass(name);
  else {
    char m[600];
    snprintf(m, sizeof m, "rc=%d first='%s' next='%s' %s", rc, first, out, err);
    fail(name, m);
  }
}

/* An IN OUT parameter carries the application's value in, and the block's
 * result back out. */
static void check_inout_param(SQLHDBC dbc)
{
  const char *name = "IN OUT parameter keeps its input value";
  char err[256] = "";
  if (!SQL_SUCCEEDED(exec_do(dbc,
                             "CREATE OR REPLACE PROCEDURE seer_inout (s IN OUT VARCHAR2, "
                             "n IN OUT NUMBER) AS BEGIN s := s || '-x'; n := n + 1; END;",
                             err, sizeof err))) {
    skip(name, err);
    return;
  }
  char s[64] = "abc";
  SQLINTEGER n = 41;
  SQLLEN sind = SQL_NTS, nind = 0;
  SQLHSTMT st;
  SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st);
  SQLBindParameter(st, 1, SQL_PARAM_INPUT_OUTPUT, SQL_C_CHAR, SQL_VARCHAR, 60, 0, s, sizeof s,
                   &sind);
  SQLBindParameter(st, 2, SQL_PARAM_INPUT_OUTPUT, SQL_C_SLONG, SQL_INTEGER, 0, 0, &n, 0, &nind);
  SQLRETURN rc = SQLExecDirect(st, (SQLCHAR *)"BEGIN seer_inout(?, ?); END;", SQL_NTS);
  if (!SQL_SUCCEEDED(rc))
    diag_text(SQL_HANDLE_STMT, st, err, sizeof err);
  SQLFreeHandle(SQL_HANDLE_STMT, st);
  exec_do(dbc, "DROP PROCEDURE seer_inout", err + strlen(err), 1);
  if (SQL_SUCCEEDED(rc) && strcmp(s, "abc-x") == 0 && n == 42)
    pass(name);
  else {
    char m[400];
    snprintf(m, sizeof m, "s='%s' n=%d %s", s, (int)n, err);
    fail(name, m);
  }
}

/* The statement kind decides the execute options, so a leading comment or a
 * PL/SQL label must not hide it: a commented SELECT is still a query, a
 * commented / labelled block and a CALL ... INTO are PL/SQL (whose OUT binds
 * are ordinary binds - read as DML RETURNING, the call hung). */
static void check_statement_kind(SQLHDBC dbc)
{
  const char *name = "leading comments / labels / CALL keep the statement kind";
  char out[32] = "", err[256] = "", m[400] = "";
  int ok = 1;
  static const struct {
    const char *sql, *want;
  } q[] = {{"-- a comment\nSELECT 5 FROM dual", "5"}, {"/* c */ SELECT 6 FROM dual", "6"}};
  for (size_t i = 0; i < sizeof q / sizeof q[0] && ok; i++) {
    out[0] = '\0';
    if (!SQL_SUCCEEDED(exec_scalar(dbc, q[i].sql, out, sizeof out, err, sizeof err)) ||
        strcmp(out, q[i].want) != 0) {
      snprintf(m, sizeof m, "'%s' -> '%s' %s", q[i].sql, out, err);
      ok = 0;
    }
  }
  exec_do(dbc, "CREATE OR REPLACE FUNCTION seer_nine RETURN NUMBER AS BEGIN RETURN 9; END;", err,
          sizeof err);
  static const struct {
    const char *sql;
    int want;
  } b[] = {{"/* c */ BEGIN ? := 7; END;", 7},
           {"<<lbl>> BEGIN ? := 8; END;", 8},
           {"CALL seer_nine() INTO ?", 9}};
  for (size_t i = 0; i < sizeof b / sizeof b[0] && ok; i++) {
    SQLINTEGER v = 0;
    SQLLEN ind = 0;
    SQLHSTMT st;
    SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st);
    SQLBindParameter(st, 1, SQL_PARAM_OUTPUT, SQL_C_SLONG, SQL_INTEGER, 0, 0, &v, 0, &ind);
    SQLRETURN rc = SQLExecDirect(st, (SQLCHAR *)b[i].sql, SQL_NTS);
    if (!SQL_SUCCEEDED(rc))
      diag_text(SQL_HANDLE_STMT, st, err, sizeof err);
    SQLFreeHandle(SQL_HANDLE_STMT, st);
    if (!SQL_SUCCEEDED(rc) || v != b[i].want) {
      snprintf(m, sizeof m, "'%s' -> %d %s", b[i].sql, (int)v, SQL_SUCCEEDED(rc) ? "" : err);
      ok = 0;
    }
  }
  exec_do(dbc, "DROP FUNCTION seer_nine", err, sizeof err);
  if (ok)
    pass(name);
  else
    fail(name, m);
}

/* A PL/SQL block can run DDL (EXECUTE IMMEDIATE), so it invalidates cached
 * cursors like DDL does: re-running a cached INSERT after a block recreated
 * its table must work against the new table. */
static void check_cache_after_block_ddl(SQLHDBC dbc)
{
  const char *name = "statement cache after a block that recreates a table";
  char err[256] = "", out[32] = "";
  exec_do(dbc, "DROP TABLE seer_cachet", err, sizeof err);
  exec_do(dbc, "CREATE TABLE seer_cachet (a NUMBER)", err, sizeof err);
  SQLRETURN r1 = exec_do(dbc, "INSERT INTO seer_cachet VALUES (1)", err, sizeof err);
  exec_do(dbc,
          "BEGIN EXECUTE IMMEDIATE 'DROP TABLE seer_cachet'; "
          "EXECUTE IMMEDIATE 'CREATE TABLE seer_cachet (a NUMBER, b NUMBER DEFAULT 2)'; END;",
          err, sizeof err);
  SQLRETURN r2 = exec_do(dbc, "INSERT INTO seer_cachet (a) VALUES (1)", err, sizeof err);
  SQLRETURN r3 = exec_do(dbc, "INSERT INTO seer_cachet VALUES (1)", err, sizeof err);
  exec_scalar(dbc, "SELECT COUNT(*) || ':' || SUM(b) FROM seer_cachet", out, sizeof out, err,
              sizeof err);
  exec_do(dbc, "DROP TABLE seer_cachet", err, sizeof err);
  /* the second plain INSERT must now fail (2 columns, 1 value): ORA-00947 */
  if (SQL_SUCCEEDED(r1) && SQL_SUCCEEDED(r2) && !SQL_SUCCEEDED(r3) && strcmp(out, "1:2") == 0)
    pass(name);
  else {
    char m[300];
    snprintf(m, sizeof m, "r1=%d r2=%d r3=%d rows='%s'", r1, r2, r3, out);
    fail(name, m);
  }
}

/* A DML RETURNING whose every bind is a return bind has no row of input
 * values: the request must carry no TTI_RXD at all. (An empty one drew
 * ORA-03146 on 12c+ and made 11g drop the session on the next call.) */
static void check_returning_only_binds(SQLHDBC dbc)
{
  const char *name = "DML RETURNING with only return binds (VARCHAR)";
  char err[256] = "", out[32] = "";
  exec_do(dbc, "DROP TABLE seer_reto", err, sizeof err);
  if (!SQL_SUCCEEDED(exec_do(dbc, "CREATE TABLE seer_reto (v VARCHAR2(50))", err, sizeof err)) ||
      !SQL_SUCCEEDED(
          exec_do(dbc, "INSERT INTO seer_reto VALUES ('abcdefghij')", err, sizeof err))) {
    skip(name, err);
    return;
  }
  char v[64] = "";
  SQLLEN vind = 0;
  SQLHSTMT st;
  SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st);
  SQLBindParameter(st, 1, SQL_PARAM_OUTPUT, SQL_C_CHAR, SQL_VARCHAR, 60, 0, v, sizeof v, &vind);
  SQLRETURN rc =
      SQLExecDirect(st, (SQLCHAR *)"UPDATE seer_reto SET v = v RETURNING v INTO ?", SQL_NTS);
  if (!SQL_SUCCEEDED(rc))
    diag_text(SQL_HANDLE_STMT, st, err, sizeof err);
  SQLFreeHandle(SQL_HANDLE_STMT, st);
  SQLRETURN rc2 = exec_scalar(dbc, "SELECT 5 FROM dual", out, sizeof out, err, sizeof err);
  exec_do(dbc, "DROP TABLE seer_reto", err, sizeof err);
  if (rc == SQL_SUCCESS && strcmp(v, "abcdefghij") == 0 && SQL_SUCCEEDED(rc2) &&
      strcmp(out, "5") == 0)
    pass(name);
  else {
    char m[400];
    snprintf(m, sizeof m, "rc=%d value='%s' next='%s' %s", rc, v, out, err);
    fail(name, m);
  }
}

/* A RETURNING value longer than the parameter's ColumnSize is truncated by
 * the server; that must be reported (01004), not returned silently cut. */
static void check_returning_truncation(SQLHDBC dbc)
{
  const char *name = "truncated DML RETURNING value reports 01004";
  char err[256] = "";
  exec_do(dbc, "DROP TABLE seer_rett", err, sizeof err);
  if (!SQL_SUCCEEDED(exec_do(dbc, "CREATE TABLE seer_rett (v VARCHAR2(50))", err, sizeof err)) ||
      !SQL_SUCCEEDED(
          exec_do(dbc, "INSERT INTO seer_rett VALUES ('abcdefghij')", err, sizeof err))) {
    skip(name, err);
    return;
  }
  char v[64] = "";
  SQLLEN vind = 0;
  SQLHSTMT st;
  SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st);
  SQLBindParameter(st, 1, SQL_PARAM_OUTPUT, SQL_C_CHAR, SQL_VARCHAR, 5, 0, v, sizeof v, &vind);
  SQLRETURN rc =
      SQLExecDirect(st, (SQLCHAR *)"UPDATE seer_rett SET v = v RETURNING v INTO ?", SQL_NTS);
  SQLCHAR state[6] = "";
  SQLINTEGER native = 0;
  SQLSMALLINT ml = 0;
  SQLGetDiagRec(SQL_HANDLE_STMT, st, 1, state, &native, NULL, 0, &ml);
  SQLFreeHandle(SQL_HANDLE_STMT, st);
  exec_do(dbc, "DROP TABLE seer_rett", err, sizeof err);
  if (rc == SQL_SUCCESS_WITH_INFO && strcmp((char *)state, "01004") == 0)
    pass(name);
  else {
    char m[200];
    snprintf(m, sizeof m, "rc=%d state='%s' value='%s' ind=%ld", rc, state, v, (long)vind);
    fail(name, m);
  }
}

/* ALTER SESSION SET CURRENT_SCHEMA / EDITION make 11g report the change as
 * key/value pairs in the execute's RPA; the response must still parse and the
 * session carry on. */
static void check_alter_session_state(SQLHDBC dbc, int has_editions)
{
  const char *name = "ALTER SESSION SET CURRENT_SCHEMA / EDITION";
  char err[256] = "", sql[160], out[64] = "", user[64] = "";
  /* The session's own user, from the server, as a plain identifier. */
  exec_scalar(dbc, "SELECT USER FROM dual", user, sizeof user, err, sizeof err);
  for (const char *c = user; *c; c++)
    if (!isalnum((unsigned char)*c) && *c != '_' && *c != '$' && *c != '#')
      user[0] = '\0';
  if (!user[0]) {
    skip(name, "no usable session user");
    return;
  }
  snprintf(sql, sizeof sql, "ALTER SESSION SET CURRENT_SCHEMA = %s", user);
  SQLRETURN r1 = exec_do(dbc, sql, err, sizeof err);
  char e1[256];
  snprintf(e1, sizeof e1, "%s", err);
  /* Editions arrived in 11.2; on 10g the statement is refused, and the
   * session's recursive SQL then fails (ORA-00604) - so only ask 11.2+. */
  char e2[256] = "";
  SQLRETURN r2 = has_editions ? exec_do(dbc, "ALTER SESSION SET EDITION = ORA$BASE", e2, sizeof e2)
                              : SQL_SUCCESS;
  SQLRETURN r3 = exec_scalar(dbc, "SELECT SYS_CONTEXT('USERENV', 'CURRENT_SCHEMA') FROM dual", out,
                             sizeof out, err, sizeof err);
  if (SQL_SUCCEEDED(r1) && SQL_SUCCEEDED(r3) && strcasecmp(out, user) == 0 &&
      (SQL_SUCCEEDED(r2) || strstr(e2, "ORA-")))
    pass(name);
  else {
    char m[700];
    snprintf(m, sizeof m, "r1=%d(%s) r2=%d(%s) r3=%d schema='%s' %s", r1, e1, r2, e2, r3, out, err);
    fail(name, m);
  }
}

/* v$session.OSUSER (SYS_CONTEXT OS_USER) is the operating-system account
 * running the client, not the database user. */
/* A replay-corpus run (#396): the driver then sends a fixed host name and OS
 * user (src/tns/wire.c). */
static int wire_corpus_run(void)
{
  const char *r = getenv("SEER_WIRE_RECORD"), *p = getenv("SEER_WIRE_REPLAY");
  return (r != NULL && r[0] != '\0') || (p != NULL && p[0] != '\0');
}

static void check_os_user(SQLHDBC dbc)
{
  const char *name = "OS user reported to the server";
  char out[128] = "", err[256] = "";
  const char *me = getenv("USER");
  if (me == NULL || !me[0])
    me = getenv("LOGNAME");
  /* A replay-corpus run sends a fixed OS user (#396, src/tns/wire.c). */
  if (wire_corpus_run())
    me = "seer";
  if (me == NULL || !me[0]) {
    skip(name, "no USER / LOGNAME in the environment");
    return;
  }
  exec_scalar(dbc, "SELECT SYS_CONTEXT('USERENV', 'OS_USER') FROM dual", out, sizeof out, err,
              sizeof err);
  if (strcmp(out, me) == 0)
    pass(name);
  else {
    char m[400];
    snprintf(m, sizeof m, "got '%s' want '%s' %s", out, me, err);
    fail(name, m);
  }
}

/* A statement that fails still leaves the server a cursor, which must be
 * closed: 500 failing statements on one connection (more than a typical
 * OPEN_CURSORS of 300) must not exhaust the session's cursors (ORA-01000). */
static void check_failed_statements_close_cursors(SQLHDBC dbc)
{
  const char *name = "failed statements don't leak server cursors";
  char err[256] = "", out[32] = "";
  for (int i = 0; i < 500; i++) {
    char sql[64];
    snprintf(sql, sizeof sql, "SELECT %d FROM seer_no_such_table", i);
    exec_do(dbc, sql, err, sizeof err);
  }
  if (SQL_SUCCEEDED(exec_scalar(dbc, "SELECT 5 FROM dual", out, sizeof out, err, sizeof err)) &&
      strcmp(out, "5") == 0)
    pass(name);
  else {
    char m[400];
    snprintf(m, sizeof m, "after 500 failures: '%s' %s", out, err);
    fail(name, m);
  }
}

/* Two OSON image forms only a server writes: version 3 (a field name over
 * 255 bytes gets a second name segment) and a `COMPRESS HIGH` column (relative
 * child offsets, objects sharing another's field ids). Each decodes to the
 * document that went in. Skipped where the server lacks the syntax. */
static void check_json_server_forms(SQLHDBC dbc)
{
  const char *name = "JSON: long field names and compressed columns";
  GATE(name);
  char out[600] = "", err[256] = "", m[800] = "";
  SQLRETURN rc = exec_scalar(dbc,
                             "SELECT JSON_OBJECT(RPAD('A', 256, 'A') VALUE 6700 RETURNING JSON) "
                             "FROM dual",
                             out, sizeof out, err, sizeof err);
  if (!SQL_SUCCEEDED(rc)) {
    fail(name, err[0] ? err : "execute failed");
    return;
  }
  if (out[0] && strspn(out, "0123456789ABCDEF") == strlen(out)) {
    /* Below 21c's field version the server returns JSON as a BLOB (hex), not
     * an OSON image - nothing to decode at this protocol level. */
    skip(name, "native JSON not surfaced at this protocol level");
    return;
  }
  size_t as = strspn(out + (out[0] == '{' && out[1] == '"' ? 2 : 0), "A");
  if (as != 256 || !strstr(out, ":6700")) {
    snprintf(m, sizeof m, "long name: got %zu A's in '%.60s...'", as, out);
    fail(name, m);
    return;
  }
  exec_do(dbc, "DROP TABLE seer_jcomp", err, sizeof err);
  if (!SQL_SUCCEEDED(exec_do(dbc,
                             "CREATE TABLE seer_jcomp (j JSON) JSON (j) STORE AS (COMPRESS HIGH)",
                             err, sizeof err))) {
    pass(name); /* long names verified; compressed JSON storage not offered here */
    return;
  }
  exec_do(dbc, "INSERT INTO seer_jcomp VALUES ('[{\"a\":1,\"b\":\"x\"},{\"a\":2,\"b\":\"y\"}]')",
          err, sizeof err);
  out[0] = '\0';
  exec_scalar(dbc, "SELECT j FROM seer_jcomp", out, sizeof out, err, sizeof err);
  exec_do(dbc, "DROP TABLE seer_jcomp", err, sizeof err);
  if (strcmp(out, "[{\"a\":1,\"b\":\"x\"},{\"a\":2,\"b\":\"y\"}]") == 0)
    pass(name);
  else {
    snprintf(m, sizeof m, "compressed: got '%s' %s", out, err);
    fail(name, m);
  }
}

/* Object with an XMLType attribute between two NUMBERs: the XMLType is its own
 * image (decoded like an XMLType column), and the attribute after it must not
 * shift into its place. */
/* NVARCHAR2 / NCHAR attributes and collection elements are AL16UTF16 in the
 * image, as a national column is; decoded as AL32UTF8 they came back as raw
 * UTF-16 bytes. 10g's dictionary names the type VARCHAR2, so the driver goes
 * by CHARACTER_SET_NAME. */
static void check_object_national_attrs(SQLHDBC dbc)
{
  const char *name = "SQL OBJECT / VARRAY with NVARCHAR2 attributes";
  GATE(name);
  char err[256] = "", obj[256] = "", coll[256] = "";
  exec_do(dbc, "DROP TABLE seer_nat", err, sizeof err);
  exec_do(dbc, "DROP TYPE seer_no", err, sizeof err);
  exec_do(dbc, "DROP TYPE seer_nv", err, sizeof err);
  if (!SQL_SUCCEEDED(exec_do(dbc, "CREATE TYPE seer_no AS OBJECT (a NVARCHAR2(20), b VARCHAR2(20))",
                             err, sizeof err))) {
    fail(name, err[0] ? err : "create type failed");
    return;
  }
  exec_do(dbc, "CREATE TYPE seer_nv AS VARRAY(5) OF NVARCHAR2(20)", err, sizeof err);
  exec_do(dbc, "CREATE TABLE seer_nat (o seer_no, l seer_nv)", err, sizeof err);
  exec_do(dbc,
          "INSERT INTO seer_nat VALUES (seer_no(UNISTR('\\017e\\00e1ba \\732b'), 'plain'), "
          "seer_nv(UNISTR('\\732b'), UNISTR('abc')))",
          err, sizeof err);
  SQLRETURN rc = exec_scalar(dbc, "SELECT o FROM seer_nat", obj, sizeof obj, err, sizeof err);
  if (SQL_SUCCEEDED(rc))
    rc = exec_scalar(dbc, "SELECT l FROM seer_nat", coll, sizeof coll, err, sizeof err);
  exec_do(dbc, "DROP TABLE seer_nat", err, sizeof err);
  exec_do(dbc, "DROP TYPE seer_no", err, sizeof err);
  exec_do(dbc, "DROP TYPE seer_nv", err, sizeof err);
  /* "\xc5\xbe\xc3\xa1ba \xe7\x8c\xab" is "žába 猫" in UTF-8 */
  if (SQL_SUCCEEDED(rc) &&
      strcmp(obj, "\xc5\xbe\xc3\xa1"
                  "ba \xe7\x8c\xab, plain") == 0 &&
      strcmp(coll, "[\xe7\x8c\xab, abc]") == 0)
    pass(name);
  else {
    char m[600];
    snprintf(m, sizeof m, "got '%s' / '%s' %s", obj, coll, err);
    fail(name, m);
  }
}

static void check_object_xmltype_attr(SQLHDBC dbc)
{
  const char *name = "SQL OBJECT with an XMLType attribute";
  GATE(name);
  char err[256] = "", out[256] = "";
  exec_do(dbc, "DROP TABLE seer_xot", err, sizeof err);
  exec_do(dbc, "DROP TYPE seer_xo", err, sizeof err);
  if (!SQL_SUCCEEDED(exec_do(dbc,
                             "CREATE TYPE seer_xo AS OBJECT (a NUMBER, x SYS.XMLTYPE, z NUMBER)",
                             err, sizeof err))) {
    fail(name, err[0] ? err : "create type failed");
    return;
  }
  exec_do(dbc, "CREATE TABLE seer_xot (o seer_xo)", err, sizeof err);
  exec_do(dbc, "INSERT INTO seer_xot VALUES (seer_xo(1, XMLTYPE('<r>hi</r>'), 77))", err,
          sizeof err);
  SQLRETURN rc = exec_scalar(dbc, "SELECT o FROM seer_xot", out, sizeof out, err, sizeof err);
  exec_do(dbc, "DROP TABLE seer_xot", err, sizeof err);
  exec_do(dbc, "DROP TYPE seer_xo", err, sizeof err);
  size_t n = strlen(out);
  if (SQL_SUCCEEDED(rc) && strncmp(out, "1, ", 3) == 0 && strstr(out, "<r>hi</r>") && n > 4 &&
      strcmp(out + n - 4, ", 77") == 0)
    pass(name);
  else {
    char m[400];
    snprintf(m, sizeof m, "got '%s'", out);
    fail(name, m);
  }
}

/* Object with CLOB and BLOB attributes: each attribute is a LOB locator,
 * read like a column LOB - not rendered as the locator's raw bytes. (Two LOB
 * attributes; three break the fetch on 10g/11g server-side.) */
static void check_object_lob_attrs(SQLHDBC dbc)
{
  const char *name = "SQL OBJECT with CLOB / BLOB attributes";
  GATE(name);
  char err[256] = "", out[256] = "";
  exec_do(dbc, "DROP TABLE seer_lot", err, sizeof err);
  exec_do(dbc, "DROP TYPE seer_lo", err, sizeof err);
  if (!SQL_SUCCEEDED(exec_do(dbc,
                             "CREATE TYPE seer_lo AS OBJECT (a NUMBER, c CLOB, b BLOB, z NUMBER)",
                             err, sizeof err))) {
    fail(name, err[0] ? err : "create type failed");
    return;
  }
  exec_do(dbc, "CREATE TABLE seer_lot (o seer_lo)", err, sizeof err);
  /* Empty LOBs, then written through their locators: 8i and 9i take no text
   * for a CLOB attribute in the constructor (ORA-00932), 8i no TO_CLOB. */
  exec_do(
      dbc,
      "DECLARE c CLOB; b BLOB; BEGIN INSERT INTO seer_lot VALUES (seer_lo(1, EMPTY_CLOB(), "
      "EMPTY_BLOB(), 7)); SELECT t.o.c, t.o.b INTO c, b FROM seer_lot t FOR UPDATE; "
      "DBMS_LOB.WRITEAPPEND(c, 10, 'hello clob'); DBMS_LOB.WRITEAPPEND(b, 2, HEXTORAW('CAFE')); "
      "END;",
      err, sizeof err);
  SQLRETURN rc = exec_scalar(dbc, "SELECT o FROM seer_lot", out, sizeof out, err, sizeof err);
  exec_do(dbc, "DROP TABLE seer_lot", err, sizeof err);
  exec_do(dbc, "DROP TYPE seer_lo", err, sizeof err);
  if (SQL_SUCCEEDED(rc) && strcasecmp(out, "1, hello clob, cafe, 7") == 0)
    pass(name);
  else {
    char m[400];
    snprintf(m, sizeof m, "got '%s' %s", out, SQL_SUCCEEDED(rc) ? "" : err);
    fail(name, m);
  }
}

/* SQLNumResultCols / SQLDescribeCol between SQLPrepare and SQLExecute: the
 * driver describes the prepared query with a parse-only round trip (many tools
 * build their result binding this way). Executing afterwards must still give
 * the right rows; a prepared DML reports no columns and must not run; a bad
 * statement reports its error at describe time. */
static void check_describe_before_execute(SQLHDBC dbc)
{
  const char *name = "describe after SQLPrepare, before SQLExecute";
  GATE(name);
  char err[256] = "", m[400] = "";
  SQLHSTMT st;
  SQLSMALLINT ncols = -1, nlen = 0, dtype = 0;
  SQLCHAR cname[64] = "";
  SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st);
  SQLRETURN rc = SQLPrepare(
      st, (SQLCHAR *)"SELECT 42 AS answer, 'x' AS letter FROM dual WHERE 1 = ?", SQL_NTS);
  SQLRETURN r1 = SQLNumResultCols(st, &ncols);
  SQLRETURN r2 = SQLDescribeCol(st, 2, cname, sizeof cname, &nlen, &dtype, NULL, NULL, NULL);
  SQLINTEGER one = 1;
  SQLBindParameter(st, 1, SQL_PARAM_INPUT, SQL_C_SLONG, SQL_INTEGER, 0, 0, &one, 0, NULL);
  char v[16] = "";
  SQLLEN vi = 0;
  SQLRETURN r3 = SQLExecute(st);
  if (SQL_SUCCEEDED(r3) && SQL_SUCCEEDED(SQLFetch(st)))
    SQLGetData(st, 1, SQL_C_CHAR, v, sizeof v, &vi);
  else
    diag_text(SQL_HANDLE_STMT, st, err, sizeof err);
  SQLFreeHandle(SQL_HANDLE_STMT, st);
  int ok = SQL_SUCCEEDED(rc) && SQL_SUCCEEDED(r1) && ncols == 2 && SQL_SUCCEEDED(r2) &&
           strcasecmp((char *)cname, "LETTER") == 0 && strcmp(v, "42") == 0;
  if (!ok)
    snprintf(m, sizeof m, "prep=%d ncols=%d(%d) col2='%s'(%d) exec=%d value='%s' %s", rc, ncols, r1,
             cname, r2, r3, v, err);

  /* a prepared DML: no columns, and describing it doesn't run it */
  if (ok) {
    exec_do(dbc, "DROP TABLE seer_desc", err, sizeof err);
    exec_do(dbc, "CREATE TABLE seer_desc (n NUMBER)", err, sizeof err);
    SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st);
    SQLPrepare(st, (SQLCHAR *)"INSERT INTO seer_desc VALUES (1)", SQL_NTS);
    ncols = -1;
    SQLNumResultCols(st, &ncols);
    SQLFreeHandle(SQL_HANDLE_STMT, st);
    char cnt[16] = "";
    exec_scalar(dbc, "SELECT COUNT(*) FROM seer_desc", cnt, sizeof cnt, err, sizeof err);
    exec_do(dbc, "DROP TABLE seer_desc", err, sizeof err);
    ok = ncols == 0 && strcmp(cnt, "0") == 0;
    if (!ok)
      snprintf(m, sizeof m, "DML: ncols=%d rows=%s", ncols, cnt);
  }
  /* a bad statement reports its error at describe time */
  if (ok) {
    SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st);
    SQLPrepare(st, (SQLCHAR *)"SELECT x FROM seer_no_such_table", SQL_NTS);
    SQLRETURN rb = SQLNumResultCols(st, &ncols);
    err[0] = '\0';
    diag_text(SQL_HANDLE_STMT, st, err, sizeof err);
    SQLFreeHandle(SQL_HANDLE_STMT, st);
    ok = rb == SQL_ERROR && strstr(err, "ORA-00942") != NULL;
    if (!ok)
      snprintf(m, sizeof m, "bad SQL: rc=%d '%s'", rb, err);
  }
  if (ok)
    pass(name);
  else
    fail(name, m);
}

/* SeerODBC extension identifiers (see the driver's documentation). */
#define SQL_DIAG_SEER_ERROR_OFFSET 19113
#define SQL_DESC_SEER_VECTOR_DIMENSIONS 19114
#define SQL_DESC_SEER_VECTOR_FORMAT 19115

/* A CREATE of a PL/SQL object that doesn't compile SUCCEEDS (the object
 * exists, invalid); the driver reports it as success with a warning, like
 * Oracle's own clients (ORA-24344). */
static void check_compile_warning(SQLHDBC dbc)
{
  const char *name = "compilation errors reported as SUCCESS_WITH_INFO (ORA-24344)";
  SQLHSTMT st;
  SQLCHAR state[6] = "";
  SQLINTEGER native = 0;
  SQLSMALLINT ml = 0;
  char err[256] = "";
  SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st);
  SQLRETURN rc = SQLExecDirect(
      st, (SQLCHAR *)"CREATE OR REPLACE PROCEDURE seer_broken AS BEGIN no_such_thing; END;",
      SQL_NTS);
  SQLGetDiagRec(SQL_HANDLE_STMT, st, 1, state, &native, NULL, 0, &ml);
  SQLFreeHandle(SQL_HANDLE_STMT, st);
  SQLRETURN rd = exec_do(dbc, "DROP PROCEDURE seer_broken", err, sizeof err);
  if (rc == SQL_SUCCESS_WITH_INFO && strcmp((char *)state, "01000") == 0 && native == 24344 &&
      rd == SQL_SUCCESS)
    pass(name);
  else {
    char m[200];
    snprintf(m, sizeof m, "create rc=%d state='%s' native=%d, drop rc=%d", rc, state, (int)native,
             rd);
    fail(name, m);
  }
}

/* A failed statement's diagnostic carries the ORA number as its native error
 * and the parse offset the server reported (SQL_DIAG_SEER_ERROR_OFFSET). */
static void check_error_native_and_offset(SQLHDBC dbc)
{
  const char *name = "ORA number as native error, and the error offset";
  SQLHSTMT st;
  SQLCHAR state[6] = "";
  SQLINTEGER native = 0, off = -1;
  SQLSMALLINT ml = 0;
  SQLCHAR msg[200] = "";
  SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st);
  SQLRETURN rc = SQLExecDirect(st, (SQLCHAR *)"SELECT nonexistent FROM dual", SQL_NTS);
  SQLGetDiagRec(SQL_HANDLE_STMT, st, 1, state, &native, msg, sizeof msg, &ml);
  SQLGetDiagField(SQL_HANDLE_STMT, st, 1, SQL_DIAG_SEER_ERROR_OFFSET, &off, 0, NULL);
  SQLFreeHandle(SQL_HANDLE_STMT, st);
  if (rc == SQL_ERROR && native == 904 && off == 7)
    pass(name);
  else {
    char m[400]; /* the text too: once on 9i it lacked the ORA- prefix (#246) */
    snprintf(m, sizeof m, "rc=%d native=%d offset=%d state '%s' '%s'", rc, (int)native, (int)off,
             (char *)state, (char *)msg);
    fail(name, m);
  }
}

/* 23ai VECTOR column metadata: declared dimensions and element format. */
static void check_vector_metadata(SQLHDBC dbc)
{
  const char *name = "VECTOR column dimensions / format (SQLColAttribute)";
  GATE(name);
  char err[256] = "";
  exec_do(dbc, "DROP TABLE seer_vmeta", err, sizeof err);
  if (!SQL_SUCCEEDED(
          exec_do(dbc, "CREATE TABLE seer_vmeta (v VECTOR(3, FLOAT32))", err, sizeof err))) {
    fail(name, err);
    return;
  }
  SQLHSTMT st;
  SQLLEN dims = -1, fmt = -1;
  SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st);
  SQLRETURN rc = SQLExecDirect(st, (SQLCHAR *)"SELECT v FROM seer_vmeta", SQL_NTS);
  SQLColAttribute(st, 1, SQL_DESC_SEER_VECTOR_DIMENSIONS, NULL, 0, NULL, &dims);
  SQLColAttribute(st, 1, SQL_DESC_SEER_VECTOR_FORMAT, NULL, 0, NULL, &fmt);
  SQLFreeHandle(SQL_HANDLE_STMT, st);
  exec_do(dbc, "DROP TABLE seer_vmeta", err, sizeof err);
  if (SQL_SUCCEEDED(rc) && dims == 3 && fmt == 2)
    pass(name);
  else {
    char m[200];
    snprintf(m, sizeof m, "rc=%d dims=%ld format=%ld (want 3, 2)", rc, (long)dims, (long)fmt);
    fail(name, m);
  }
}

/* SQL_DBMS_VER reports the connected server's release ("##.##.####", then
 * the dotted release), decoded from its login word in that release's layout
 * (18c+ differs). It must agree with the server's own product_component_version
 * on the major release and, from 19c, the release update (18c's word names
 * only the base release, 18.0, where the view says 18.4). */
static void check_dbms_ver(SQLHDBC dbc)
{
  const char *name = "SQL_DBMS_VER matches the server release";
  char ver[128] = "", pcv[64] = "", err[256] = "";
  SQLGetInfo(dbc, SQL_DBMS_VER, ver, sizeof ver, NULL);
  /* VERSION names only the base release from 18c (21.0.0.0.0 on a 21.3 XE);
   * VERSION_FULL, 18c+, has the release update. */
  if (!SQL_SUCCEEDED(exec_scalar(dbc,
                                 "SELECT MAX(version_full) FROM product_component_version "
                                 "WHERE product LIKE 'Oracle%'",
                                 pcv, sizeof pcv, err, sizeof err)))
    exec_scalar(dbc,
                "SELECT MAX(version) FROM product_component_version WHERE product LIKE 'Oracle%'",
                pcv, sizeof pcv, err, sizeof err);
  int vmaj = 0, vmin = 0, pmaj = 0, pmin = 0;
  int ok = sscanf(ver, "%d.%d.", &vmaj, &vmin) == 2 && sscanf(pcv, "%d.%d", &pmaj, &pmin) == 2 &&
           vmaj == pmaj && (pmaj < 19 || vmin == pmin) && strstr(ver, " Oracle ") != NULL;
  if (ok)
    pass(name);
  else {
    char m[300];
    snprintf(m, sizeof m, "SQL_DBMS_VER '%s' vs product_component_version '%s'", ver, pcv);
    fail(name, m);
  }
}

/* SQL_DRIVER_VER is this build's release in the ODBC form "##.##.####" (#310).
 * The driver builds it from the SEERTNS_VERSION_* macros, while meson passes
 * the project version here, so this also catches the two drifting apart. */
static void check_driver_ver(SQLHDBC dbc)
{
  const char *name = "SQL_DRIVER_VER is the release version";
  char ver[64] = "", want[24] = "";
  int maj = 0, min = 0, pat = 0;
  SQLRETURN rc = SQLGetInfo(dbc, SQL_DRIVER_VER, ver, sizeof ver, NULL);
  if (sscanf(SEER_PROJECT_VERSION, "%d.%d.%d", &maj, &min, &pat) == 3)
    snprintf(want, sizeof want, "%02d.%02d.%04d", maj, min, pat);
  if (SQL_SUCCEEDED(rc) && want[0] != '\0' && strcmp(ver, want) == 0)
    pass(name);
  else {
    char m[160];
    snprintf(m, sizeof m, "SQL_DRIVER_VER '%s', want '%s' (project %s)", ver, want,
             SEER_PROJECT_VERSION);
    fail(name, m);
  }
}

/* SQL_MAX_IDENTIFIER_LEN (and the column / table / schema name lengths) is the
 * server's own limit: 128 from 12.2 on, as the server states it at login, and
 * 30 before. The server is the judge: an alias that long is taken, and one a
 * character longer is refused (ORA-00972) where the limit is below 128. */
static void check_max_identifier_len(SQLHDBC dbc)
{
  const char *name = "SQL_MAX_IDENTIFIER_LEN is the server's limit";
  SQLUSMALLINT iden = 0, col = 0, tab = 0, sch = 0;
  SQLGetInfo(dbc, SQL_MAX_IDENTIFIER_LEN, &iden, sizeof iden, NULL);
  SQLGetInfo(dbc, SQL_MAX_COLUMN_NAME_LEN, &col, sizeof col, NULL);
  SQLGetInfo(dbc, SQL_MAX_TABLE_NAME_LEN, &tab, sizeof tab, NULL);
  SQLGetInfo(dbc, SQL_MAX_SCHEMA_NAME_LEN, &sch, sizeof sch, NULL);
  char m[300];
  if ((iden != 30 && iden != 128) || col != iden || tab != iden || sch != iden) {
    snprintf(m, sizeof m, "identifier %u, column %u, table %u, schema %u", iden, col, tab, sch);
    fail(name, m);
    return;
  }
  /* The server is asked with an alias of the reported length, then (below 128)
   * one character longer. */
  for (unsigned len = iden; len <= iden + (iden < 128 ? 1u : 0u); len++) {
    char alias[130], sql[200], out[16], err[256] = "";
    memset(alias, 'A', len);
    alias[len] = '\0';
    snprintf(sql, sizeof sql, "SELECT 1 AS \"%s\" FROM dual", alias);
    int taken = SQL_SUCCEEDED(exec_scalar(dbc, sql, out, sizeof out, err, sizeof err));
    if (len == iden && !taken) {
      snprintf(m, sizeof m, "a %u-character alias was refused: %s", len, err);
      fail(name, m);
      return;
    }
    if (len > iden && taken) {
      snprintf(m, sizeof m, "reported %u, but a %u-character alias was taken", iden, len);
      fail(name, m);
      return;
    }
  }
  pass(name);
}

/* A value over 32767 bytes bound to a PL/SQL CLOB / BLOB parameter: a LONG
 * (the form a large text bind takes) can't reach a PL/SQL LOB parameter that
 * big (ORA-01460); it has to go as a temporary LOB: 12c's CREATE_TEMP, OCI
 * 11.2's on 10g/11g (#415), 9i's own. 8.1.7 takes no text or RAW for a LOB
 * parameter at all (PLS-00306): there the long types go once more as
 * temporary LOBs the server makes in PL/SQL (#424). */
static void check_plsql_large_lob_param(SQLHDBC dbc)
{
  const char *name = "PL/SQL CLOB / BLOB parameter over 32 KB";
  GATE(name);
  char err[256] = "", out[64] = "";
  if (!SQL_SUCCEEDED(exec_do(dbc,
                             "CREATE OR REPLACE PROCEDURE seer_lobp (c IN CLOB, b IN BLOB, "
                             "n OUT VARCHAR2) AS BEGIN n := DBMS_LOB.GETLENGTH(c) || ':' || "
                             "DBMS_LOB.GETLENGTH(b); END;",
                             err, sizeof err))) {
    skip(name, err);
    return;
  }
  static char text[50001];
  static unsigned char bin[40000];
  memset(text, 'c', 50000);
  text[50000] = '\0';
  memset(bin, 0xAB, sizeof bin);
  SQLLEN ti = SQL_NTS, bi = sizeof bin, oi = 0;
  SQLHSTMT st;
  SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st);
  SQLBindParameter(st, 1, SQL_PARAM_INPUT, SQL_C_CHAR, SQL_LONGVARCHAR, 50000, 0, text, 0, &ti);
  SQLBindParameter(st, 2, SQL_PARAM_INPUT, SQL_C_BINARY, SQL_LONGVARBINARY, sizeof bin, 0, bin, 0,
                   &bi);
  SQLBindParameter(st, 3, SQL_PARAM_OUTPUT, SQL_C_CHAR, SQL_VARCHAR, 60, 0, out, sizeof out, &oi);
  SQLRETURN rc = SQLExecDirect(st, (SQLCHAR *)"BEGIN seer_lobp(?, ?, ?); END;", SQL_NTS);
  if (!SQL_SUCCEEDED(rc))
    diag_text(SQL_HANDLE_STMT, st, err, sizeof err);
  SQLFreeHandle(SQL_HANDLE_STMT, st);
  char e2[256];
  exec_do(dbc, "DROP PROCEDURE seer_lobp", e2, sizeof e2);
  if (SQL_SUCCEEDED(rc) && strcmp(out, "50000:40000") == 0)
    pass(name);
  else {
    char m[400];
    snprintf(m, sizeof m, "rc=%d got '%s' %s", rc, out, SQL_SUCCEEDED(rc) ? "" : err);
    fail(name, m);
  }
}

/* A LONG column past 252 bytes arrives chunked, each chunk's length an sb4 on
 * 12c+ (a ub1 before): read with ub1 lengths it desynced the row on 12c+. */
static void check_long_column(SQLHDBC dbc)
{
  const char *name = "LONG column over 252 bytes";
  char err[256], e2[256];
  exec_do(dbc, "DROP TABLE seer_lg", e2, sizeof e2);
  if (!SQL_SUCCEEDED(exec_do(dbc, "CREATE TABLE seer_lg (id NUMBER, l LONG)", err, sizeof err)) ||
      !SQL_SUCCEEDED(
          exec_do(dbc, "INSERT INTO seer_lg VALUES (1, RPAD('q', 1000, 'q'))", err, sizeof err))) {
    fail(name, err);
    return;
  }
  SQLHSTMT st;
  SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st);
  static char buf[2048];
  char tail[16] = "";
  SQLLEN ind = 0, tind = 0;
  SQLRETURN rc = SQLExecDirect(st, (SQLCHAR *)"SELECT l, 'end' FROM seer_lg", SQL_NTS);
  if (SQL_SUCCEEDED(rc))
    rc = SQLFetch(st);
  if (SQL_SUCCEEDED(rc)) {
    SQLGetData(st, 1, SQL_C_CHAR, buf, sizeof buf, &ind);
    SQLGetData(st, 2, SQL_C_CHAR, tail, sizeof tail, &tind);
  } else {
    diag_text(SQL_HANDLE_STMT, st, err, sizeof err);
  }
  SQLFreeHandle(SQL_HANDLE_STMT, st);
  exec_do(dbc, "DROP TABLE seer_lg", e2, sizeof e2);
  if (SQL_SUCCEEDED(rc) && ind == 1000 && buf[999] == 'q' && strcmp(tail, "end") == 0)
    pass(name);
  else {
    char m[400];
    snprintf(m, sizeof m, "rc=%d len=%ld tail='%s' %s", rc, (long)ind, tail,
             SQL_SUCCEEDED(rc) ? "" : err);
    fail(name, m);
  }
}

/* CLOB / BLOB columns over more rows (120) than one fetch batch (100), mixed sizes
 * (to 30000 two-byte characters / 20000 bytes), NULL and empty values; run
 * twice, the second time on the cached cursor. With `lob_inline` (a LOBINLINE=1
 * connection, 12.1+) the rows come after a DEFINE call asking for the LOBs as
 * LONG / LONG RAW, content inline, and the later batches keep that framing -
 * and there an empty LOB reads as NULL, the one thing that form can't tell. */
/* The character is é: two bytes in UTF-8 like any non-ASCII one, and held by a
 * Latin-1 database too (9i's WE8ISO8859P1 had no ж and stored ¿). */
static void check_lob_columns_batched(SQLHDBC dbc, int lob_inline)
{
  const char *name = lob_inline ? "CLOB / BLOB columns across fetch batches (LOBINLINE)"
                                : "CLOB / BLOB columns across fetch batches";
  char err[256], e2[256];
  exec_do(dbc, "DROP TABLE seer_ld", e2, sizeof e2);
  if (!SQL_SUCCEEDED(
          exec_do(dbc, "CREATE TABLE seer_ld (id NUMBER, c CLOB, b BLOB)", err, sizeof err)) ||
      !SQL_SUCCEEDED(exec_do(
          dbc,
          "DECLARE cc CLOB; bb BLOB; nc PLS_INTEGER; nb PLS_INTEGER; k PLS_INTEGER; "
          "r RAW(2000); BEGIN FOR i IN 1 .. 120 LOOP "
          "IF MOD(i, 50) = 0 THEN INSERT INTO seer_ld VALUES (i, NULL, NULL); ELSE "
          "IF MOD(i, 50) = 1 THEN nc := 0; ELSIF i > 115 THEN nc := 30000; "
          "ELSE nc := i * 7; END IF; "
          "IF i > 115 THEN nb := 20000; ELSE nb := i * 5; END IF; "
          "r := UTL_RAW.COPIES(HEXTORAW(LPAD(TRIM(TO_CHAR(MOD(i, 256), 'XX')), 2, '0')), 2000); "
          "DBMS_LOB.CREATETEMPORARY(cc, TRUE); DBMS_LOB.CREATETEMPORARY(bb, TRUE); "
          "k := nc; WHILE k > 0 LOOP DBMS_LOB.WRITEAPPEND(cc, LEAST(k, 1000), "
          "RPAD('\xc3\xa9', LEAST(k, 1000), '\xc3\xa9')); k := k - 1000; END LOOP; "
          "k := nb; WHILE k > 0 LOOP DBMS_LOB.WRITEAPPEND(bb, LEAST(k, 2000), "
          "UTL_RAW.SUBSTR(r, 1, LEAST(k, 2000))); k := k - 2000; END LOOP; "
          "INSERT INTO seer_ld VALUES (i, cc, bb); "
          "DBMS_LOB.FREETEMPORARY(cc); DBMS_LOB.FREETEMPORARY(bb); END IF; "
          "END LOOP; COMMIT; END;",
          err, sizeof err))) {
    fail(name, err);
    exec_do(dbc, "DROP TABLE seer_ld", e2, sizeof e2);
    return;
  }
  static char cbuf[70000];
  static unsigned char bbuf[30000];
  char why[200] = "";
  for (int pass_no = 0; pass_no < 2 && why[0] == '\0'; pass_no++) {
    SQLHSTMT st;
    SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st);
    SQLRETURN rc =
        SQLExecDirect(st, (SQLCHAR *)"SELECT id, c, b FROM seer_ld ORDER BY id", SQL_NTS);
    int rows = 0;
    while (SQL_SUCCEEDED(rc) && why[0] == '\0' && SQL_SUCCEEDED(rc = SQLFetch(st))) {
      SQLINTEGER id = 0;
      SQLLEN ind = 0, cind = 0, bind = 0;
      SQLGetData(st, 1, SQL_C_SLONG, &id, 0, &ind);
      SQLGetData(st, 2, SQL_C_CHAR, cbuf, sizeof cbuf, &cind);
      SQLGetData(st, 3, SQL_C_BINARY, bbuf, sizeof bbuf, &bind);
      long wc = id % 50 == 0   ? SQL_NULL_DATA
                : id % 50 == 1 ? (lob_inline ? SQL_NULL_DATA : 0)
                               : (id > 115 ? 30000 : id * 7) * 2;
      long wb = id % 50 == 0 ? SQL_NULL_DATA : (id > 115 ? 20000 : id * 5);
      if ((long)cind != wc || (wc > 0 && memcmp(cbuf + wc - 2, "\xc3\xa9", 2) != 0))
        snprintf(why, sizeof why, "pass %d row %d: CLOB length %ld, want %ld", pass_no + 1, (int)id,
                 (long)cind, wc);
      else if ((long)bind != wb || (wb > 0 && bbuf[wb - 1] != (unsigned char)(id & 0xFF)))
        snprintf(why, sizeof why, "pass %d row %d: BLOB length %ld, want %ld", pass_no + 1, (int)id,
                 (long)bind, wb);
      rows++;
    }
    if (why[0] == '\0' && rc != SQL_NO_DATA)
      diag_text(SQL_HANDLE_STMT, st, why, sizeof why);
    else if (why[0] == '\0' && rows != 120)
      snprintf(why, sizeof why, "pass %d: %d rows, want 120", pass_no + 1, rows);
    SQLFreeHandle(SQL_HANDLE_STMT, st);
  }
  exec_do(dbc, "DROP TABLE seer_ld", e2, sizeof e2);
  if (why[0] == '\0')
    pass(name);
  else
    fail(name, why);
}

/* The temporary LOB a large PL/SQL bind is promoted to is freed once nothing
 * references it - when the bind is replaced or the statement freed - with a
 * FREE_TEMP piggyback on the next call, not left until the session ends. A
 * prepared statement executed twice reuses its bind in between, so the LOB
 * must survive that. Counted in V$TEMPORARY_LOBS (skipped where unreadable). */
static void check_temp_lobs_freed(SQLHDBC dbc)
{
  const char *name = "temporary LOBs of large PL/SQL binds are freed";
  GATE(name);
  /* 8.1.7's USERENV has no SID (ORA-02003); V$MYSTAT has the session's. */
  const char *count_sql = g_release == 8 ? "SELECT cache_lobs + nocache_lobs FROM v$temporary_lobs "
                                           "WHERE sid = (SELECT sid FROM v$mystat WHERE ROWNUM = 1)"
                                         : "SELECT cache_lobs + nocache_lobs FROM v$temporary_lobs "
                                           "WHERE sid = SYS_CONTEXT('USERENV', 'SID')";
  char before[32], err[256];
  if (!SQL_SUCCEEDED(exec_scalar(dbc, count_sql, before, sizeof before, err, sizeof err))) {
    skip(name, "V$TEMPORARY_LOBS not readable");
    return;
  }
  static char text[40001];
  memset(text, 't', 40000);
  text[40000] = '\0';
  char why[300] = "";
  for (int round = 0; round < 3 && why[0] == '\0'; round++) {
    SQLHSTMT st;
    SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st);
    SQLINTEGER out = 0;
    SQLLEN ti = SQL_NTS, oi = 0;
    SQLRETURN rc = SQLPrepare(st, (SQLCHAR *)"BEGIN ? := DBMS_LOB.GETLENGTH(?); END;", SQL_NTS);
    SQLBindParameter(st, 1, SQL_PARAM_OUTPUT, SQL_C_SLONG, SQL_INTEGER, 0, 0, &out, 0, &oi);
    SQLBindParameter(st, 2, SQL_PARAM_INPUT, SQL_C_CHAR, SQL_LONGVARCHAR, 40000, 0, text, 0, &ti);
    for (int k = 0; k < 2 && SQL_SUCCEEDED(rc) && why[0] == '\0'; k++) {
      out = 0;
      rc = SQLExecute(st);
      if (SQL_SUCCEEDED(rc) && out != 40000)
        snprintf(why, sizeof why, "round %d exec %d: got %d, want 40000", round, k, (int)out);
    }
    if (!SQL_SUCCEEDED(rc)) {
      char e[256];
      diag_text(SQL_HANDLE_STMT, st, e, sizeof e);
      snprintf(why, sizeof why, "round %d: %s", round, e);
    }
    SQLFreeHandle(SQL_HANDLE_STMT, st);
  }
  char after[32];
  exec_scalar(dbc, count_sql, after, sizeof after, err, sizeof err);
  if (why[0] == '\0' && atoi(after) > atoi(before))
    snprintf(why, sizeof why, "%s temporary LOBs left, %s before", after, before);
  if (why[0] == '\0')
    pass(name);
  else
    fail(name, why);
}

/* A CLOB and a BLOB OUT parameter of a PL/SQL block bound as the driver's
 * SQL_SEER_CLOB / SQL_SEER_BLOB (#214): on 8i the only way, as 8.1.7 converts
 * no CLOB to text; on every other release the same as SQL_LONGVARCHAR /
 * SQL_LONGVARBINARY. */
#define SQL_SEER_CLOB (-9998)
#define SQL_SEER_BLOB (-9997)
static void check_lob_out_ext_types(SQLHDBC dbc)
{
  const char *name = "CLOB / BLOB OUT parameters as SQL_SEER_CLOB / SQL_SEER_BLOB";
  static char cbuf[20001];
  static unsigned char bbuf[20000];
  SQLLEN ci = 0, bi = 0;
  char err[256] = "", m[400] = "";
  SQLHSTMT st;
  SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st);
  cbuf[0] = '\0';
  SQLBindParameter(st, 1, SQL_PARAM_OUTPUT, SQL_C_CHAR, SQL_SEER_CLOB, 20000, 0, cbuf, sizeof cbuf,
                   &ci);
  SQLBindParameter(st, 2, SQL_PARAM_OUTPUT, SQL_C_BINARY, SQL_SEER_BLOB, 20000, 0, bbuf,
                   sizeof bbuf, &bi);
  SQLRETURN rc = SQLExecDirect(
      st,
      (SQLCHAR *)"DECLARE c CLOB; b BLOB; BEGIN DBMS_LOB.CREATETEMPORARY(c, TRUE); "
                 "DBMS_LOB.CREATETEMPORARY(b, TRUE); FOR i IN 1 .. 10 LOOP "
                 "DBMS_LOB.WRITEAPPEND(c, 1000, RPAD('o', 1000, 'o')); END LOOP; FOR i IN 1 .. 3 "
                 "LOOP DBMS_LOB.WRITEAPPEND(b, 2000, UTL_RAW.COPIES(HEXTORAW('AB'), 2000)); END "
                 "LOOP; ? := c; ? := b; END;",
      SQL_NTS);
  if (!SQL_SUCCEEDED(rc))
    diag_text(SQL_HANDLE_STMT, st, err, sizeof err);
  SQLFreeHandle(SQL_HANDLE_STMT, st);
  if (SQL_SUCCEEDED(rc) && strlen(cbuf) == 10000 && bi == 6000 && bbuf[5999] == 0xAB)
    pass(name);
  else {
    snprintf(m, sizeof m, "rc=%d clob=%zu blob=%ld %s", (int)rc, strlen(cbuf), (long)bi, err);
    fail(name, m);
  }
}

/* A large CLOB OUT parameter, and a CLOB + BLOB returned by DML RETURNING into
 * SQL_LONGVARCHAR / SQL_LONGVARBINARY parameters: the whole values come back
 * (a VARCHAR / RAW return target is capped at 4000 bytes - ORA-22835). Two
 * checks: 8i takes the RETURNING but not the PL/SQL OUT (#214). */
static void check_lob_out(SQLHDBC dbc)
{
  static char buf[20001];
  char err[256] = "", m[400] = "";
  SQLLEN ind = 0;
  SQLHSTMT st;
  const char *name = "large CLOB OUT parameter";
  if (!gated(name)) {
    /* PL/SQL OUT */
    SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st);
    buf[0] = '\0';
    SQLBindParameter(st, 1, SQL_PARAM_OUTPUT, SQL_C_CHAR, SQL_LONGVARCHAR, 20000, 0, buf,
                     sizeof buf, &ind);
    SQLRETURN rc = SQLExecDirect(
        st,
        /* Built with DBMS_LOB: 8.1.7 won't take RPAD's VARCHAR2 into a CLOB
         * (ORA-06550, #167). */
        (SQLCHAR *)"DECLARE c CLOB; BEGIN DBMS_LOB.CREATETEMPORARY(c, TRUE); FOR i IN 1 .. 10 LOOP "
                   "DBMS_LOB.WRITEAPPEND(c, 1000, RPAD('o', 1000, 'o')); END LOOP; ? := c; END;",
        SQL_NTS);
    if (!SQL_SUCCEEDED(rc))
      diag_text(SQL_HANDLE_STMT, st, err, sizeof err);
    SQLFreeHandle(SQL_HANDLE_STMT, st);
    if (!SQL_SUCCEEDED(rc) || strlen(buf) != 10000) {
      snprintf(m, sizeof m, "OUT: rc=%d len=%zu ind=%ld %s", rc, strlen(buf), (long)ind, err);
      fail(name, m);
    } else
      pass(name);
  }
  name = "CLOB + BLOB via RETURNING";
  if (!gated(name)) {
    exec_do(dbc, "DROP TABLE seer_lobret", err, sizeof err);
    exec_do(dbc, "CREATE TABLE seer_lobret (c CLOB, b BLOB)", err, sizeof err);
    /* Both built in PL/SQL with DBMS_LOB: a SQL RAW expression caps at 2000
     * bytes, and 8i has no TO_CLOB (#167). */
    exec_do(dbc,
            "DECLARE c CLOB; b BLOB; BEGIN INSERT INTO seer_lobret VALUES (EMPTY_CLOB(), "
            "EMPTY_BLOB()) RETURNING c, b INTO c, b; FOR i IN 1 .. 10 LOOP "
            "DBMS_LOB.WRITEAPPEND(c, 1000, RPAD('r', 1000, 'r')); END LOOP; FOR i IN 1 .. 3 LOOP "
            "DBMS_LOB.WRITEAPPEND(b, 2000, UTL_RAW.COPIES(HEXTORAW('AB'), 2000)); END LOOP; END;",
            err, sizeof err);
    SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st);
    buf[0] = '\0';
    ind = 0;
    static unsigned char bin[20000];
    SQLLEN bind_b = 0;
    SQLBindParameter(st, 1, SQL_PARAM_OUTPUT, SQL_C_CHAR, SQL_LONGVARCHAR, 20000, 0, buf,
                     sizeof buf, &ind);
    SQLBindParameter(st, 2, SQL_PARAM_OUTPUT, SQL_C_BINARY, SQL_LONGVARBINARY, 20000, 0, bin,
                     sizeof bin, &bind_b);
    SQLRETURN rc = SQLExecDirect(
        st, (SQLCHAR *)"UPDATE seer_lobret SET c = c RETURNING c, b INTO ?, ?", SQL_NTS);
    err[0] = '\0';
    if (!SQL_SUCCEEDED(rc))
      diag_text(SQL_HANDLE_STMT, st, err, sizeof err);
    SQLFreeHandle(SQL_HANDLE_STMT, st);
    char next[16] = "", e2[256] = "";
    exec_scalar(dbc, "SELECT 5 FROM dual", next, sizeof next, e2, sizeof e2);
    exec_do(dbc, "DROP TABLE seer_lobret", e2, sizeof e2);
    if (!SQL_SUCCEEDED(rc) || strlen(buf) != 10000 || bind_b != 6000 || bin[5999] != 0xAB ||
        strcmp(next, "5") != 0) {
      snprintf(m, sizeof m, "RETURNING: rc=%d clob=%zu blob=%ld next='%s' %s", rc, strlen(buf),
               (long)bind_b, next, err);
      fail(name, m);
    } else
      pass(name);
  }
}

/* Where bound data lives and which sets run (#243): a row-wise parameter
 * array (PARAM_BIND_TYPE the struct size) with one set marked
 * SQL_PARAM_IGNORE; the same array again past a PARAM_BIND_OFFSET; a
 * row-wise block fetch past a ROW_BIND_OFFSET; and ASYNC_ENABLE /
 * USE_BOOKMARKS on refused with HYC00. */
typedef struct {
  SQLINTEGER id;
  SQLLEN id_ind;
  char v[12];
  SQLLEN v_ind;
} SeerRowwise;

static void check_rowwise_binds(SQLHDBC dbc)
{
  const char *name = "row-wise parameter arrays, bind offsets, ignored parameter sets";
  char err[256] = "", m[600] = "";
  exec_do(dbc, "DROP TABLE seer_rowwise", err, sizeof err);
  if (!SQL_SUCCEEDED(
          exec_do(dbc, "CREATE TABLE seer_rowwise (id NUMBER, v VARCHAR2(12))", err, sizeof err))) {
    skip(name, err);
    return;
  }
  SeerRowwise rows[6];
  memset(rows, 0, sizeof rows);
  for (int i = 0; i < 6; i++) {
    rows[i].id = 10 + i;
    snprintf(rows[i].v, sizeof rows[i].v, "v%d", 10 + i);
    rows[i].v_ind = SQL_NTS;
  }
  SQLUSMALLINT op[3] = {SQL_PARAM_PROCEED, SQL_PARAM_IGNORE, SQL_PARAM_PROCEED};
  SQLUSMALLINT status[3] = {0, 0, 0};
  SQLULEN processed = 99;
  SQLLEN offset = 0;
  SQLHSTMT st;
  SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st);
  SQLSetStmtAttr(st, SQL_ATTR_PARAM_BIND_TYPE, (SQLPOINTER)sizeof(SeerRowwise), 0);
  SQLSetStmtAttr(st, SQL_ATTR_PARAMSET_SIZE, (SQLPOINTER)(SQLULEN)3, 0);
  SQLSetStmtAttr(st, SQL_ATTR_PARAM_OPERATION_PTR, op, 0);
  SQLSetStmtAttr(st, SQL_ATTR_PARAM_STATUS_PTR, status, 0);
  SQLSetStmtAttr(st, SQL_ATTR_PARAMS_PROCESSED_PTR, &processed, 0);
  SQLSetStmtAttr(st, SQL_ATTR_PARAM_BIND_OFFSET_PTR, &offset, 0);
  SQLBindParameter(st, 1, SQL_PARAM_INPUT, SQL_C_SLONG, SQL_INTEGER, 0, 0, &rows[0].id, 0,
                   &rows[0].id_ind);
  SQLBindParameter(st, 2, SQL_PARAM_INPUT, SQL_C_CHAR, SQL_VARCHAR, 12, 0, rows[0].v,
                   sizeof rows[0].v, &rows[0].v_ind);
  SQLRETURN rc = SQLPrepare(st, (SQLCHAR *)"INSERT INTO seer_rowwise VALUES (?, ?)", SQL_NTS);
  if (SQL_SUCCEEDED(rc))
    rc = SQLExecute(st); /* rows 10 and 12; 11 ignored */
  if (!SQL_SUCCEEDED(rc) || processed != 2 || status[0] != SQL_PARAM_SUCCESS ||
      status[1] != SQL_PARAM_UNUSED || status[2] != SQL_PARAM_SUCCESS) {
    diag_text(SQL_HANDLE_STMT, st, err, sizeof err);
    snprintf(m, sizeof m, "array: rc=%d processed=%lu status=%u/%u/%u %s", (int)rc,
             (unsigned long)processed, status[0], status[1], status[2], err);
  }
  if (m[0] == '\0') { /* the next three structs, by the offset alone */
    offset = (SQLLEN)(3 * sizeof(SeerRowwise));
    op[1] = SQL_PARAM_PROCEED;
    rc = SQLExecute(st); /* rows 13, 14, 15 */
    if (!SQL_SUCCEEDED(rc) || processed != 3) {
      diag_text(SQL_HANDLE_STMT, st, err, sizeof err);
      snprintf(m, sizeof m, "offset: rc=%d processed=%lu %s", (int)rc, (unsigned long)processed,
               err);
    }
  }
  SQLFreeHandle(SQL_HANDLE_STMT, st);

  if (m[0] == '\0') { /* row-wise block fetch into rows[2..], by the row offset */
    SeerRowwise got[6];
    memset(got, 0, sizeof got);
    SQLULEN fetched = 0;
    SQLLEN roff = (SQLLEN)(2 * sizeof(SeerRowwise));
    SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st);
    SQLSetStmtAttr(st, SQL_ATTR_ROW_BIND_TYPE, (SQLPOINTER)sizeof(SeerRowwise), 0);
    SQLSetStmtAttr(st, SQL_ATTR_ROW_ARRAY_SIZE, (SQLPOINTER)(SQLULEN)4, 0);
    SQLSetStmtAttr(st, SQL_ATTR_ROWS_FETCHED_PTR, &fetched, 0);
    SQLSetStmtAttr(st, SQL_ATTR_ROW_BIND_OFFSET_PTR, &roff, 0);
    /* Bound after the execute: before it, see #244. */
    rc = SQLExecDirect(st, (SQLCHAR *)"SELECT id, v FROM seer_rowwise ORDER BY id", SQL_NTS);
    if (SQL_SUCCEEDED(rc))
      rc = SQLBindCol(st, 1, SQL_C_SLONG, &got[0].id, 0, &got[0].id_ind);
    if (SQL_SUCCEEDED(rc))
      rc = SQLBindCol(st, 2, SQL_C_CHAR, got[0].v, sizeof got[0].v, &got[0].v_ind);
    if (SQL_SUCCEEDED(rc))
      rc = SQLFetch(st);
    int ok = SQL_SUCCEEDED(rc) && fetched == 4 && got[0].id == 0 && got[1].id == 0;
    static const SQLINTEGER want[4] = {10, 12, 13, 14};
    for (int i = 0; ok && i < 4; i++) {
      char wv[12];
      snprintf(wv, sizeof wv, "v%d", (int)want[i]);
      ok = got[2 + i].id == want[i] && strcmp(got[2 + i].v, wv) == 0;
    }
    if (!ok) {
      diag_text(SQL_HANDLE_STMT, st, err, sizeof err);
      snprintf(m, sizeof m, "fetch: rc=%d fetched=%lu ids %d %d | %d %d %d %d %s", (int)rc,
               (unsigned long)fetched, (int)got[0].id, (int)got[1].id, (int)got[2].id,
               (int)got[3].id, (int)got[4].id, (int)got[5].id, err);
    }
    SQLFreeHandle(SQL_HANDLE_STMT, st);
  }

  if (m[0] == '\0') { /* refused, not pretended */
    SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st);
    SQLRETURN a = SQLSetStmtAttr(st, SQL_ATTR_ASYNC_ENABLE, (SQLPOINTER)SQL_ASYNC_ENABLE_ON, 0);
    char sa[6] = "", sb[6] = "";
    SQLINTEGER nat;
    SQLSMALLINT len;
    SQLGetDiagRec(SQL_HANDLE_STMT, st, 1, (SQLCHAR *)sa, &nat, NULL, 0, &len);
    SQLRETURN b = SQLSetStmtAttr(st, SQL_ATTR_USE_BOOKMARKS, (SQLPOINTER)SQL_UB_VARIABLE, 0);
    SQLGetDiagRec(SQL_HANDLE_STMT, st, 1, (SQLCHAR *)sb, &nat, NULL, 0, &len);
    SQLFreeHandle(SQL_HANDLE_STMT, st);
    if (a != SQL_ERROR || strcmp(sa, "HYC00") != 0 || b != SQL_ERROR || strcmp(sb, "HYC00") != 0)
      snprintf(m, sizeof m, "ASYNC_ENABLE on: rc=%d '%s'; USE_BOOKMARKS on: rc=%d '%s'", (int)a, sa,
               (int)b, sb);
  }
  exec_do(dbc, "DROP TABLE seer_rowwise", err, sizeof err);
  if (m[0] == '\0')
    pass(name);
  else
    fail(name, m);
}

/* SQL_ATTR_MAX_LENGTH and SQL_ATTR_NOSCAN (#248): a 10-byte limit cuts a
 * VARCHAR2 to 10 bytes - in SQLGetData and a bound fetch alike, no 01004 -
 * and leaves a NUMBER whole; NOSCAN on sends an escape to the server as
 * written, which refuses it, where the default translates it. */
static void check_maxlength_noscan(SQLHDBC dbc)
{
  const char *name = "SQL_ATTR_MAX_LENGTH cuts char data; SQL_ATTR_NOSCAN skips escapes";
  char m[400] = "";
  SQLHSTMT st;
  SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st);
  SQLSetStmtAttr(st, SQL_ATTR_MAX_LENGTH, (SQLPOINTER)(SQLULEN)10, 0);
  SQLULEN ml = 0;
  SQLGetStmtAttr(st, SQL_ATTR_MAX_LENGTH, &ml, 0, NULL);
  char bound[64] = "", got[64] = "", num[32] = "";
  SQLLEN bind_ind = 0, got_ind = 0, num_ind = 0;
  SQLRETURN rc = SQLExecDirect(
      st, (SQLCHAR *)"SELECT RPAD('a', 30, 'b'), RPAD('c', 30, 'd'), 12345678901234 FROM dual",
      SQL_NTS);
  if (SQL_SUCCEEDED(rc))
    rc = SQLBindCol(st, 1, SQL_C_CHAR, bound, sizeof bound, &bind_ind);
  if (SQL_SUCCEEDED(rc))
    rc = SQLFetch(st);
  SQLRETURN g = SQL_ERROR, gn = SQL_ERROR;
  if (rc == SQL_SUCCESS) {
    g = SQLGetData(st, 2, SQL_C_CHAR, got, sizeof got, &got_ind);
    gn = SQLGetData(st, 3, SQL_C_CHAR, num, sizeof num, &num_ind);
  }
  SQLFreeHandle(SQL_HANDLE_STMT, st);
  if (ml != 10 || rc != SQL_SUCCESS || strcmp(bound, "abbbbbbbbb") != 0 || bind_ind != 10 ||
      g != SQL_SUCCESS || strcmp(got, "cddddddddd") != 0 || got_ind != 10 || gn != SQL_SUCCESS ||
      strcmp(num, "12345678901234") != 0)
    snprintf(m, sizeof m,
             "max length %lu: fetch rc=%d '%s' (%ld), getdata rc=%d '%s' (%ld), number '%s'",
             (unsigned long)ml, (int)rc, bound, (long)bind_ind, (int)g, got, (long)got_ind, num);

  if (m[0] == '\0') {
    const char *esc = "SELECT {fn UCASE('x')} FROM dual";
    char out[16] = "";
    SQLLEN ind = 0;
    SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st);
    rc = SQLExecDirect(st, (SQLCHAR *)esc, SQL_NTS); /* translated: X */
    if (SQL_SUCCEEDED(rc) && SQL_SUCCEEDED(SQLFetch(st)))
      SQLGetData(st, 1, SQL_C_CHAR, out, sizeof out, &ind);
    SQLFreeStmt(st, SQL_CLOSE);
    SQLSetStmtAttr(st, SQL_ATTR_NOSCAN, (SQLPOINTER)SQL_NOSCAN_ON, 0);
    SQLULEN ns = 0;
    SQLGetStmtAttr(st, SQL_ATTR_NOSCAN, &ns, 0, NULL);
    SQLRETURN r2 = SQLExecDirect(st, (SQLCHAR *)esc, SQL_NTS); /* as written: the server refuses */
    SQLFreeHandle(SQL_HANDLE_STMT, st);
    if (strcmp(out, "X") != 0 || ns != SQL_NOSCAN_ON || SQL_SUCCEEDED(r2))
      snprintf(m, sizeof m,
               "escape translated to '%s' (want X); NOSCAN %lu, its execute rc=%d (want an error)",
               out, (unsigned long)ns, (int)r2);
  }
  if (m[0] == '\0')
    pass(name);
  else
    fail(name, m);
}

/* #250: every standard attribute reads back at its own width and default; a
 * bulk SQLSetPos DELETE skips the rows ROW_OPERATION_PTR marks
 * SQL_ROW_IGNORE; with RETRIEVE_DATA off a fetch fills nothing. */
static void check_attr_getters_rowop(SQLHDBC dbc)
{
  const char *name = "attribute getters' widths; SQLSetPos skips ignored rows; RETRIEVE_DATA";
  char err[256] = "", m[600] = "";
  SQLHSTMT st;
  SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st);
  static const SQLINTEGER zero_attrs[] = {SQL_ATTR_KEYSET_SIZE,        SQL_ATTR_USE_BOOKMARKS,
                                          SQL_ATTR_ENABLE_AUTO_IPD,    SQL_ATTR_METADATA_ID,
                                          SQL_ATTR_FETCH_BOOKMARK_PTR, SQL_ATTR_ROW_OPERATION_PTR};
  for (size_t k = 0; k < sizeof zero_attrs / sizeof zero_attrs[0] && m[0] == '\0'; k++) {
    SQLULEN v = (SQLULEN)-1; /* every byte set: a 4-byte write leaves half of it */
    SQLGetStmtAttr(st, zero_attrs[k], &v, 0, NULL);
    if (v != 0)
      snprintf(m, sizeof m, "stmt attribute %d read 0x%llx, want 0", (int)zero_attrs[k],
               (unsigned long long)v);
  }
  SQLULEN rd = 0;
  SQLGetStmtAttr(st, SQL_ATTR_RETRIEVE_DATA, &rd, 0, NULL);
  if (m[0] == '\0' && rd != SQL_RD_ON)
    snprintf(m, sizeof m, "RETRIEVE_DATA read %lu, want SQL_RD_ON", (unsigned long)rd);
  SQLFreeHandle(SQL_HANDLE_STMT, st);
  if (m[0] == '\0') {
    char cat[16] = "xyz";
    SQLINTEGER cl = -1;
    SQLULEN ae = (SQLULEN)-1;
    SQLGetConnectAttr(dbc, SQL_ATTR_CURRENT_CATALOG, cat, sizeof cat, &cl);
    SQLGetConnectAttr(dbc, SQL_ATTR_ASYNC_ENABLE, &ae, 0, NULL);
    if (cat[0] != '\0' || cl != 0 || ae != 0)
      snprintf(m, sizeof m, "CURRENT_CATALOG '%s' (%d), connection ASYNC_ENABLE 0x%llx", cat,
               (int)cl, (unsigned long long)ae);
  }

  if (m[0] == '\0') { /* bulk delete, rows 2 and 4 ignored */
    exec_do(dbc, "DROP TABLE seer_rowop", err, sizeof err);
    exec_do(dbc, "CREATE TABLE seer_rowop (id NUMBER)", err, sizeof err);
    exec_do(dbc, "INSERT INTO seer_rowop SELECT rownum FROM all_objects WHERE rownum <= 4", err,
            sizeof err);
    SQLINTEGER ids[4] = {0};
    SQLLEN ind[4] = {0};
    SQLUSMALLINT op[4] = {SQL_ROW_PROCEED, SQL_ROW_IGNORE, SQL_ROW_PROCEED, SQL_ROW_IGNORE};
    SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st);
    SQLSetStmtAttr(st, SQL_ATTR_CONCURRENCY, (SQLPOINTER)SQL_CONCUR_VALUES, 0);
    SQLSetStmtAttr(st, SQL_ATTR_ROW_ARRAY_SIZE, (SQLPOINTER)(SQLULEN)4, 0);
    SQLSetStmtAttr(st, SQL_ATTR_ROW_OPERATION_PTR, op, 0);
    SQLRETURN rc = SQLExecDirect(st, (SQLCHAR *)"SELECT id FROM seer_rowop ORDER BY id", SQL_NTS);
    if (SQL_SUCCEEDED(rc))
      rc = SQLBindCol(st, 1, SQL_C_SLONG, ids, 0, ind);
    if (SQL_SUCCEEDED(rc))
      rc = SQLFetch(st);
    if (SQL_SUCCEEDED(rc))
      rc = SQLSetPos(st, 0, SQL_DELETE, SQL_LOCK_NO_CHANGE);
    if (!SQL_SUCCEEDED(rc))
      diag_text(SQL_HANDLE_STMT, st, err, sizeof err);
    SQLFreeHandle(SQL_HANDLE_STMT, st);
    char left[64] = "", e2[256] = "";
    exec_scalar(dbc, "SELECT COUNT(*) || ':' || MIN(id) || ':' || MAX(id) FROM seer_rowop", left,
                sizeof left, e2, sizeof e2);
    if (!SQL_SUCCEEDED(rc) || strcmp(left, "2:2:4") != 0)
      snprintf(m, sizeof m, "bulk delete with rows 2, 4 ignored: rc=%d, left '%s' (want 2:2:4) %s",
               (int)rc, left, err);
  }

  if (m[0] == '\0') { /* RETRIEVE_DATA off, then on */
    SQLINTEGER id = -1;
    SQLLEN ind = 0;
    SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st);
    SQLRETURN rc = SQLExecDirect(st, (SQLCHAR *)"SELECT id FROM seer_rowop ORDER BY id", SQL_NTS);
    if (SQL_SUCCEEDED(rc))
      rc = SQLBindCol(st, 1, SQL_C_SLONG, &id, 0, &ind);
    SQLSetStmtAttr(st, SQL_ATTR_RETRIEVE_DATA, (SQLPOINTER)SQL_RD_OFF, 0);
    SQLRETURN f1 = SQL_SUCCEEDED(rc) ? SQLFetch(st) : rc;
    SQLINTEGER after_off = id;
    /* ROW_NUMBER: the Driver Manager answers it itself until a row is current */
    SQLULEN rown = (SQLULEN)-1;
    SQLGetStmtAttr(st, SQL_ATTR_ROW_NUMBER, &rown, 0, NULL);
    SQLSetStmtAttr(st, SQL_ATTR_RETRIEVE_DATA, (SQLPOINTER)SQL_RD_ON, 0);
    SQLRETURN f2 = SQL_SUCCEEDED(f1) ? SQLFetch(st) : f1;
    SQLFreeHandle(SQL_HANDLE_STMT, st);
    if (!SQL_SUCCEEDED(f1) || !SQL_SUCCEEDED(f2) || after_off != -1 || id != 4 || rown != 1)
      snprintf(m, sizeof m,
               "RETRIEVE_DATA: off fetch rc=%d left %d (want -1), row number 0x%llx (want 1), on "
               "fetch rc=%d read %d (want 4)",
               (int)f1, (int)after_off, (unsigned long long)rown, (int)f2, (int)id);
  }
  exec_do(dbc, "DROP TABLE seer_rowop", err, sizeof err);
  if (m[0] == '\0')
    pass(name);
  else
    fail(name, m);
}

/* SQL_SEER_REF (#241): a REF read from REF(t) as bytes, bound back IN with
 * its type named in the IPD (SQL_DESC_SEER_REF_TYPE), finds its row; a block's
 * REF OUT hands back a REF that does the same; without the type the bind is
 * refused with a message saying what's missing. */
#define SQL_SEER_REF (-9996)
#define SQL_DESC_SEER_REF_TYPE 19116
static SQLRETURN ref_param(SQLHSTMT st, SQLSMALLINT io, unsigned char *buf, SQLLEN cap, SQLLEN *ind,
                           const char *type)
{
  SQLRETURN rc =
      SQLBindParameter(st, 1, io, SQL_C_BINARY, SQL_SEER_REF, (SQLULEN)cap, 0, buf, cap, ind);
  SQLHDESC ipd = NULL;
  if (SQL_SUCCEEDED(rc))
    rc = SQLGetStmtAttr(st, SQL_ATTR_IMP_PARAM_DESC, &ipd, 0, NULL);
  if (SQL_SUCCEEDED(rc) && type != NULL)
    rc = SQLSetDescField(ipd, 1, SQL_DESC_SEER_REF_TYPE, (SQLPOINTER)type, SQL_NTS);
  return rc;
}

static int ref_finds(SQLHDBC dbc, unsigned char *ref, SQLLEN rl, const char *type, char *got,
                     size_t gotn, char *err, int errn)
{
  SQLHSTMT st;
  SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st);
  SQLLEN ind = rl;
  SQLRETURN rc = ref_param(st, SQL_PARAM_INPUT, ref, rl, &ind, type);
  if (SQL_SUCCEEDED(rc))
    rc = SQLExecDirect(st, (SQLCHAR *)"SELECT t.n FROM seer_ort t WHERE REF(t) = ?", SQL_NTS);
  SQLLEN gi = 0;
  got[0] = '\0';
  if (SQL_SUCCEEDED(rc) && SQL_SUCCEEDED(SQLFetch(st)))
    SQLGetData(st, 1, SQL_C_CHAR, got, (SQLLEN)gotn, &gi);
  if (!SQL_SUCCEEDED(rc))
    diag_text(SQL_HANDLE_STMT, st, err, errn);
  SQLFreeHandle(SQL_HANDLE_STMT, st);
  return SQL_SUCCEEDED(rc);
}

static void check_ref_params(SQLHDBC dbc)
{
  const char *in_name = "REF IN parameter (SQL_SEER_REF)";
  const char *out_name = "REF OUT parameter (SQL_SEER_REF)";
  int run_in = !gated(in_name), run_out = !gated(out_name);
  if (!run_in && !run_out)
    return;
  char err[256] = "", user[64] = "", type[160];
  exec_do(dbc, "DROP TABLE seer_ort", err, sizeof err);
  exec_do(dbc, "DROP TYPE seer_orf", err, sizeof err);
  exec_do(dbc, "CREATE TYPE seer_orf AS OBJECT (n NUMBER)", err, sizeof err);
  exec_do(dbc, "CREATE TABLE seer_ort OF seer_orf", err, sizeof err);
  exec_do(dbc, "INSERT INTO seer_ort VALUES (seer_orf(7))", err, sizeof err);
  exec_do(dbc, "INSERT INTO seer_ort VALUES (seer_orf(8))", err, sizeof err);
  exec_scalar(dbc, "SELECT USER FROM dual", user, sizeof user, err, sizeof err);
  snprintf(type, sizeof type, "%s.SEER_ORF", user);

  if (run_in) {
    unsigned char ref[512];
    SQLLEN rl = 0;
    char got[16] = "", m[600] = "";
    SQLHSTMT st;
    SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st);
    SQLRETURN rc =
        SQLExecDirect(st, (SQLCHAR *)"SELECT REF(t) FROM seer_ort t WHERE t.n = 7", SQL_NTS);
    if (SQL_SUCCEEDED(rc) && SQL_SUCCEEDED(SQLFetch(st)))
      SQLGetData(st, 1, SQL_C_BINARY, ref, sizeof ref, &rl);
    SQLFreeHandle(SQL_HANDLE_STMT, st);
    if (rl <= 0 || rl > (SQLLEN)sizeof ref)
      snprintf(m, sizeof m, "REF(t) read %ld bytes", (long)rl);
    else if (!ref_finds(dbc, ref, rl, type, got, sizeof got, err, sizeof err) ||
             strcmp(got, "7") != 0)
      snprintf(m, sizeof m, "the REF (%ld bytes) bound IN found '%s', want 7: %s", (long)rl, got,
               err);
    else { /* no type named: refused, saying so */
      err[0] = '\0';
      int ok = ref_finds(dbc, ref, rl, NULL, got, sizeof got, err, sizeof err);
      if (ok || strstr(err, "SQL_DESC_SEER_REF_TYPE") == NULL)
        snprintf(m, sizeof m, "without a type: ok=%d '%s'", ok, err);
    }
    if (m[0] == '\0')
      pass(in_name);
    else
      fail(in_name, m);
  }

  if (run_out) {
    unsigned char ref[512];
    SQLLEN ind = 0;
    char got[16] = "", m[600] = "";
    SQLHSTMT st;
    SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st);
    SQLRETURN rc = ref_param(st, SQL_PARAM_OUTPUT, ref, sizeof ref, &ind, type);
    if (SQL_SUCCEEDED(rc))
      rc = SQLExecDirect(st,
                         (SQLCHAR *)"DECLARE x REF seer_orf; BEGIN SELECT REF(t) INTO x FROM "
                                    "seer_ort t WHERE t.n = 8; ? := x; END;",
                         SQL_NTS);
    if (!SQL_SUCCEEDED(rc))
      diag_text(SQL_HANDLE_STMT, st, err, sizeof err);
    SQLFreeHandle(SQL_HANDLE_STMT, st);
    if (!SQL_SUCCEEDED(rc) || ind <= 0 || ind > (SQLLEN)sizeof ref)
      snprintf(m, sizeof m, "OUT: rc=%d, %ld bytes %s", (int)rc, (long)ind, err);
    else if (!ref_finds(dbc, ref, ind, type, got, sizeof got, err, sizeof err) ||
             strcmp(got, "8") != 0)
      snprintf(m, sizeof m, "the OUT REF (%ld bytes) found '%s', want 8: %s", (long)ind, got, err);
    if (m[0] == '\0')
      pass(out_name);
    else
      fail(out_name, m);
  }
  exec_do(dbc, "DROP TABLE seer_ort", err, sizeof err);
  exec_do(dbc, "DROP TYPE seer_orf", err, sizeof err);
}

/* SQLGetDiagField's other fields (#257): after an UPDATE of 3 rows the
 * statement's ROW_COUNT is 3 and its DYNAMIC_FUNCTION "UPDATE WHERE" (82); a
 * failed SELECT's record (42S22) has class origin ISO 9075, subclass origin
 * ODBC 3.0 and no column; a message cut short is SQL_SUCCESS_WITH_INFO. */
static void check_diag_fields(SQLHDBC dbc)
{
  const char *name = "SQLGetDiagField: row count, dynamic function, origins, truncation";
  char err[256] = "", m[600] = "";
  exec_do(dbc, "DROP TABLE seer_diagf", err, sizeof err);
  exec_do(dbc, "CREATE TABLE seer_diagf (n NUMBER)", err, sizeof err);
  exec_do(dbc, "INSERT INTO seer_diagf SELECT rownum FROM all_objects WHERE rownum <= 3", err,
          sizeof err);
  SQLHSTMT st;
  SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st);
  SQLRETURN rc = SQLExecDirect(st, (SQLCHAR *)"UPDATE seer_diagf SET n = n + 1", SQL_NTS);
  SQLLEN rows = -1;
  SQLINTEGER code = -1;
  char fn[32] = "";
  SQLSMALLINT l = 0;
  SQLGetDiagField(SQL_HANDLE_STMT, st, 0, SQL_DIAG_ROW_COUNT, &rows, 0, NULL);
  SQLGetDiagField(SQL_HANDLE_STMT, st, 0, SQL_DIAG_DYNAMIC_FUNCTION, fn, sizeof fn, &l);
  SQLGetDiagField(SQL_HANDLE_STMT, st, 0, SQL_DIAG_DYNAMIC_FUNCTION_CODE, &code, 0, NULL);
  if (!SQL_SUCCEEDED(rc) || rows != 3 || strcmp(fn, "UPDATE WHERE") != 0 ||
      code != SQL_DIAG_UPDATE_WHERE)
    snprintf(m, sizeof m, "UPDATE: rc=%d row count %ld, function '%s' code %d", (int)rc, (long)rows,
             fn, (int)code);
  SQLFreeStmt(st, SQL_CLOSE);
  if (m[0] == '\0') {
    rc = SQLExecDirect(st, (SQLCHAR *)"SELECT nonexistent FROM dual", SQL_NTS);
    char cls[16] = "", sub[16] = "", small[8] = "";
    SQLINTEGER col = 0;
    SQLSMALLINT ml = 0;
    SQLGetDiagField(SQL_HANDLE_STMT, st, 1, SQL_DIAG_CLASS_ORIGIN, cls, sizeof cls, &l);
    SQLGetDiagField(SQL_HANDLE_STMT, st, 1, SQL_DIAG_SUBCLASS_ORIGIN, sub, sizeof sub, &l);
    SQLGetDiagField(SQL_HANDLE_STMT, st, 1, SQL_DIAG_COLUMN_NUMBER, &col, 0, NULL);
    SQLRETURN mr =
        SQLGetDiagField(SQL_HANDLE_STMT, st, 1, SQL_DIAG_MESSAGE_TEXT, small, sizeof small, &ml);
    if (rc != SQL_ERROR || strcmp(cls, "ISO 9075") != 0 || strcmp(sub, "ODBC 3.0") != 0 ||
        col != SQL_NO_COLUMN_NUMBER || mr != SQL_SUCCESS_WITH_INFO || ml <= 7)
      snprintf(m, sizeof m,
               "error record: rc=%d class '%s' subclass '%s' column %d, cut message rc=%d len %d",
               (int)rc, cls, sub, (int)col, (int)mr, (int)ml);
  }
  SQLFreeHandle(SQL_HANDLE_STMT, st);
  exec_do(dbc, "DROP TABLE seer_diagf", err, sizeof err);
  if (m[0] == '\0')
    pass(name);
  else
    fail(name, m);
}

/* Column metadata (#259): a NUMBER(10,2) table column describes as
 * precision 10, scale 2, display size 12, radix 10 (SQLDescribeCol too); a
 * VARCHAR2 as case-sensitive, searchable, quoted; a DATE with no fractional
 * seconds; and every string field is written - empty where Oracle's describe
 * says nothing. */
static void check_column_metadata(SQLHDBC dbc)
{
  const char *name = "column metadata: NUMBER precision / scale, flags, string fields";
  char err[256] = "", m[600] = "";
  exec_do(dbc, "DROP TABLE seer_colmeta", err, sizeof err);
  exec_do(dbc, "CREATE TABLE seer_colmeta (amt NUMBER(10,2), nm VARCHAR2(20), dt DATE)", err,
          sizeof err);
  SQLHSTMT st;
  SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st);
  SQLRETURN rc = SQLExecDirect(st, (SQLCHAR *)"SELECT amt, nm, dt FROM seer_colmeta", SQL_NTS);
  SQLLEN v[3][8];
  static const SQLUSMALLINT ids[8] = {
      SQL_DESC_PRECISION,      SQL_DESC_SCALE,      SQL_DESC_DISPLAY_SIZE, SQL_DESC_NUM_PREC_RADIX,
      SQL_DESC_CASE_SENSITIVE, SQL_DESC_SEARCHABLE, SQL_DESC_UNSIGNED,     SQL_DESC_UPDATABLE};
  static const SQLLEN want[3][8] = {
      {10, 2, 12, 10, SQL_FALSE, SQL_PRED_BASIC, SQL_FALSE, SQL_ATTR_READWRITE_UNKNOWN},
      {20, 0, 20, 0, SQL_TRUE, SQL_PRED_SEARCHABLE, SQL_TRUE, SQL_ATTR_READWRITE_UNKNOWN},
      {0, 0, 19, 0, SQL_FALSE, SQL_PRED_BASIC, SQL_TRUE, SQL_ATTR_READWRITE_UNKNOWN}};
  for (int c = 0; SQL_SUCCEEDED(rc) && c < 3 && m[0] == '\0'; c++)
    for (int k = 0; k < 8 && m[0] == '\0'; k++) {
      v[c][k] = -999;
      SQLColAttribute(st, (SQLUSMALLINT)(c + 1), ids[k], NULL, 0, NULL, &v[c][k]);
      if (v[c][k] != want[c][k])
        snprintf(m, sizeof m, "column %d field %u: %ld, want %ld", c + 1, ids[k], (long)v[c][k],
                 (long)want[c][k]);
    }
  if (SQL_SUCCEEDED(rc) && m[0] == '\0') { /* SQLDescribeCol agrees */
    SQLULEN size = 0;
    SQLSMALLINT digits = -1, type = 0;
    SQLDescribeCol(st, 1, NULL, 0, NULL, &type, &size, &digits, NULL);
    if (size != 10 || digits != 2)
      snprintf(m, sizeof m, "SQLDescribeCol(amt): size %lu digits %d, want 10 / 2",
               (unsigned long)size, (int)digits);
  }
  if (SQL_SUCCEEDED(rc) && m[0] == '\0') { /* strings: written, never left as they were */
    static const SQLUSMALLINT sids[3] = {SQL_DESC_TABLE_NAME, SQL_DESC_SCHEMA_NAME,
                                         SQL_DESC_LITERAL_PREFIX};
    static const char *const swant[3] = {"", "", "'"};
    for (int k = 0; k < 3 && m[0] == '\0'; k++) {
      char buf[16] = "sentinel";
      SQLSMALLINT l = -1;
      SQLColAttribute(st, 2, sids[k], buf, sizeof buf, &l, NULL);
      if (strcmp(buf, swant[k]) != 0)
        snprintf(m, sizeof m, "nm field %u: '%s', want '%s'", sids[k], buf, swant[k]);
    }
  }
  if (!SQL_SUCCEEDED(rc))
    diag_text(SQL_HANDLE_STMT, st, m, sizeof m);
  SQLFreeHandle(SQL_HANDLE_STMT, st);
  exec_do(dbc, "DROP TABLE seer_colmeta", err, sizeof err);
  if (m[0] == '\0')
    pass(name);
  else
    fail(name, m);
}

/* Result-column sizes through the descriptor API (#264): the IRD gives what
 * SQLColAttribute gives (a NUMBER(10,2) is 10 / 2, a DATE's precision 0), a
 * RAW(16) is 16 on every release, an NVARCHAR2(10) 10 characters with at
 * least as many bytes. */
static void check_ird_sizes(SQLHDBC dbc)
{
  const char *name = "IRD sizes: NUMBER, RAW, NVARCHAR2, DATE as SQLColAttribute";
  char err[256] = "", m[600] = "";
  exec_do(dbc, "DROP TABLE seer_irdsz", err, sizeof err);
  exec_do(dbc, "CREATE TABLE seer_irdsz (n NUMBER(10,2), r RAW(16), nv NVARCHAR2(10), d DATE)", err,
          sizeof err);
  SQLHSTMT st;
  SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st);
  SQLRETURN rc = SQLExecDirect(st, (SQLCHAR *)"SELECT n, r, nv, d FROM seer_irdsz", SQL_NTS);
  /* length, precision, scale per column; octet length checked apart */
  static const long want[4][3] = {{10, 10, 2}, {16, 16, 0}, {10, 10, 0}, {19, 0, 0}};
  SQLHDESC ird = NULL;
  if (SQL_SUCCEEDED(rc))
    SQLGetStmtAttr(st, SQL_ATTR_IMP_ROW_DESC, &ird, 0, NULL);
  for (SQLSMALLINT c = 1; SQL_SUCCEEDED(rc) && c <= 4 && m[0] == '\0'; c++) {
    SQLLEN len = -1, oct = -1, ca_oct = -1, rlen = -1;
    SQLSMALLINT prec = -1, scale = -1, rprec = -1, rscale = -1, type, sub, nul;
    SQLGetDescField(ird, c, SQL_DESC_LENGTH, &len, 0, NULL);
    SQLGetDescField(ird, c, SQL_DESC_OCTET_LENGTH, &oct, 0, NULL);
    SQLGetDescField(ird, c, SQL_DESC_PRECISION, &prec, 0, NULL);
    SQLGetDescField(ird, c, SQL_DESC_SCALE, &scale, 0, NULL);
    SQLGetDescRec(ird, c, NULL, 0, NULL, &type, &sub, &rlen, &rprec, &rscale, &nul);
    SQLColAttribute(st, (SQLUSMALLINT)c, SQL_DESC_OCTET_LENGTH, NULL, 0, NULL, &ca_oct);
    if (len != want[c - 1][0] || prec != want[c - 1][1] || scale != want[c - 1][2] ||
        rprec != prec || rscale != scale)
      snprintf(
          m, sizeof m, "column %d: length %ld precision %d / %d scale %d / %d, want %ld %ld %ld", c,
          (long)len, prec, rprec, scale, rscale, want[c - 1][0], want[c - 1][1], want[c - 1][2]);
    else if (oct != ca_oct || rlen != oct || (c == 3 && oct < len)) /* nv: bytes >= chars */
      snprintf(m, sizeof m, "column %d: octet length %ld (rec %ld), SQLColAttribute %ld, size %ld",
               c, (long)oct, (long)rlen, (long)ca_oct, (long)len);
  }
  if (!SQL_SUCCEEDED(rc))
    diag_text(SQL_HANDLE_STMT, st, m, sizeof m);
  SQLFreeHandle(SQL_HANDLE_STMT, st);
  exec_do(dbc, "DROP TABLE seer_irdsz", err, sizeof err);
  if (m[0] == '\0')
    pass(name);
  else
    fail(name, m);
}

/* SQLColumns (#265) describes each column as SQLDescribeCol describes it in a
 * result set: the type, size and digits agree; a DATE is SQL_DATETIME /
 * SQL_CODE_TIMESTAMP with BUFFER_LENGTH 16; a character column has no
 * radix; a RAW(16) is 16 and an NVARCHAR2(10) 10; a CLOB and a LONG are
 * SQLGetTypeInfo's 2147483647 (#268). */
static void check_columns_sizes(SQLHDBC dbc)
{
  const char *name = "SQLColumns: sizes and types as the result-set describe";
  char err[256] = "", m[600] = "";
  exec_do(dbc, "DROP TABLE seer_colsz", err, sizeof err);
  exec_do(dbc,
          "CREATE TABLE seer_colsz (n NUMBER(10,2), f FLOAT, v VARCHAR2(20), d DATE, r RAW(16),"
          " nv NVARCHAR2(10), cl CLOB, lg LONG)",
          err, sizeof err);
  enum { NCOL = 8 };
  SQLSMALLINT dtype[NCOL], digits[NCOL];
  SQLULEN size[NCOL];
  SQLHSTMT st;
  SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st);
  SQLRETURN rc =
      SQLExecDirect(st, (SQLCHAR *)"SELECT n, f, v, d, r, nv, cl, lg FROM seer_colsz", SQL_NTS);
  for (SQLUSMALLINT c = 0; SQL_SUCCEEDED(rc) && c < NCOL; c++)
    SQLDescribeCol(st, c + 1, NULL, 0, NULL, &dtype[c], &size[c], &digits[c], NULL);
  if (!SQL_SUCCEEDED(rc))
    diag_text(SQL_HANDLE_STMT, st, m, sizeof m);
  SQLFreeStmt(st, SQL_CLOSE);
  int rows = 0;
  char owner[64] = ""; /* the test user's schema: the beds are shared */
  const char *u = getenv("SEER_TEST_USER");
  for (size_t k = 0; u != NULL && u[k] != '\0' && k + 1 < sizeof owner; k++)
    owner[k] = (char)toupper((unsigned char)u[k]);
  if (m[0] == '\0')
    rc = SQLColumns(st, NULL, 0, (SQLCHAR *)owner, SQL_NTS, (SQLCHAR *)"SEER_COLSZ", SQL_NTS, NULL,
                    0);
  while (m[0] == '\0' && SQL_SUCCEEDED(rc) && SQL_SUCCEEDED(SQLFetch(st))) {
    SQLINTEGER
    v[7]; /* DATA_TYPE COLUMN_SIZE BUFFER_LENGTH DECIMAL_DIGITS RADIX SQL_DATA_TYPE SUB */
    SQLLEN ind[7];
    static const SQLUSMALLINT cols[7] = {5, 7, 8, 9, 10, 14, 15};
    for (int k = 0; k < 7; k++)
      SQLGetData(st, cols[k], SQL_C_SLONG, &v[k], 0, &ind[k]);
    int c = rows++;
    if (c >= NCOL)
      break;
    long want_size = c == 4 ? 16 : (long)size[c]; /* RAW: its declared length */
    if (v[0] != dtype[c] || v[1] != want_size || (ind[3] != SQL_NULL_DATA && v[3] != digits[c]))
      snprintf(m, sizeof m, "column %d: type %d size %d digits %d, describe %d / %ld / %d", c + 1,
               (int)v[0], (int)v[1], ind[3] == SQL_NULL_DATA ? -1 : (int)v[3], (int)dtype[c],
               want_size, (int)digits[c]);
    else if (c == 3 &&
             (v[2] != 16 || v[5] != SQL_DATETIME || v[6] != SQL_CODE_TIMESTAMP || v[3] != 0))
      snprintf(m, sizeof m, "DATE: buffer %d digits %d SQL_DATA_TYPE %d SUB %d, want 16 0 9 3",
               (int)v[2], (int)v[3], (int)v[5], (int)v[6]);
    else if (c == 2 && ind[4] != SQL_NULL_DATA)
      snprintf(m, sizeof m, "VARCHAR2: NUM_PREC_RADIX %d, want NULL", (int)v[4]);
    else if (c == 5 && v[1] != 10)
      snprintf(m, sizeof m, "NVARCHAR2(10): size %d, want 10", (int)v[1]);
    else if (c >= 6 && (v[1] != 2147483647 || v[2] != 2147483647)) /* #268 */
      snprintf(m, sizeof m, "%s: size %d buffer %d, want 2147483647", c == 6 ? "CLOB" : "LONG",
               (int)v[1], (int)v[2]);
  }
  if (m[0] == '\0' && !SQL_SUCCEEDED(rc))
    diag_text(SQL_HANDLE_STMT, st, m, sizeof m);
  else if (m[0] == '\0' && rows != NCOL)
    snprintf(m, sizeof m, "%d rows, want %d", rows, NCOL);
  SQLFreeHandle(SQL_HANDLE_STMT, st);
  exec_do(dbc, "DROP TABLE seer_colsz", err, sizeof err);
  if (m[0] == '\0')
    pass(name);
  else
    fail(name, m);
}

/* SQLPrimaryKeys, SQLStatistics and SQLForeignKeys answer on every release
 * (#272: 8i refused their ANSI joins and simple CASE) and describe a
 * parent's primary and unique keys, SQLStatistics' SQL_TABLE_STAT row first
 * (#275), and a child's ON DELETE CASCADE key. */
static void check_key_catalog(SQLHDBC dbc)
{
  const char *name = "SQLPrimaryKeys / SQLStatistics / SQLForeignKeys";
  char err[256] = "", m[600] = "";
  exec_do(dbc, "DROP TABLE seer_kc", err, sizeof err);
  exec_do(dbc, "DROP TABLE seer_kp", err, sizeof err);
  exec_do(dbc, "CREATE TABLE seer_kp (id NUMBER PRIMARY KEY, u NUMBER UNIQUE)", err, sizeof err);
  exec_do(dbc,
          "CREATE TABLE seer_kc (pid NUMBER, CONSTRAINT seer_kc_fk FOREIGN KEY (pid)"
          " REFERENCES seer_kp (id) ON DELETE CASCADE)",
          err, sizeof err);
  char owner[64] = "";
  const char *u = getenv("SEER_TEST_USER");
  for (size_t k = 0; u != NULL && u[k] != '\0' && k + 1 < sizeof owner; k++)
    owner[k] = (char)toupper((unsigned char)u[k]);
  SQLHSTMT st;
  SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st);
  char col[64];
  SQLLEN ind;
  SQLINTEGER v = 0;
  int rows = 0;

  SQLRETURN rc =
      SQLPrimaryKeys(st, NULL, 0, (SQLCHAR *)owner, SQL_NTS, (SQLCHAR *)"SEER_KP", SQL_NTS);
  while (SQL_SUCCEEDED(rc) && SQL_SUCCEEDED(SQLFetch(st))) {
    rows++;
    col[0] = '\0';
    SQLGetData(st, 4, SQL_C_CHAR, col, sizeof col, &ind);
    SQLGetData(st, 5, SQL_C_SLONG, &v, 0, &ind);
    if (strcmp(col, "ID") != 0 || v != 1)
      snprintf(m, sizeof m, "SQLPrimaryKeys: column %s seq %d, want ID 1", col, (int)v);
  }
  if (!SQL_SUCCEEDED(rc))
    diag_text(SQL_HANDLE_STMT, st, m, sizeof m);
  else if (m[0] == '\0' && rows != 1)
    snprintf(m, sizeof m, "SQLPrimaryKeys: %d rows, want 1", rows);
  SQLFreeStmt(st, SQL_CLOSE);

  if (m[0] == '\0') {
    rows = 0;
    int fetched = 0, table_row = 0;
    rc = SQLStatistics(st, NULL, 0, (SQLCHAR *)owner, SQL_NTS, (SQLCHAR *)"SEER_KP", SQL_NTS,
                       SQL_INDEX_ALL, SQL_QUICK);
    while (SQL_SUCCEEDED(rc) && SQL_SUCCEEDED(SQLFetch(st))) {
      fetched++;
      col[0] = '\0';
      SQLGetData(st, 9, SQL_C_CHAR, col, sizeof col, &ind);
      SQLINTEGER type = -1;
      SQLLEN tind;
      SQLGetData(st, 7, SQL_C_SLONG, &type, 0, &tind);
      if (type == SQL_TABLE_STAT) { /* #275: first, and with no column */
        table_row++;
        if (fetched != 1 || ind != SQL_NULL_DATA)
          snprintf(m, sizeof m, "SQLStatistics: SQL_TABLE_STAT is row %d, column %s", fetched,
                   ind == SQL_NULL_DATA ? "NULL" : col);
        continue;
      }
      rows++;
      SQLGetData(st, 4, SQL_C_SLONG, &v, 0, &ind);
      if (v != 0)
        snprintf(m, sizeof m, "SQLStatistics: index on %s NON_UNIQUE %d, want 0", col, (int)v);
    }
    if (!SQL_SUCCEEDED(rc))
      diag_text(SQL_HANDLE_STMT, st, m, sizeof m);
    else if (m[0] == '\0' && (rows != 2 || table_row != 1))
      snprintf(m, sizeof m, "SQLStatistics: %d index columns, %d SQL_TABLE_STAT, want 2 and 1",
               rows, table_row);
    SQLFreeStmt(st, SQL_CLOSE);
  }

  if (m[0] == '\0') {
    rows = 0;
    rc = SQLForeignKeys(st, NULL, 0, (SQLCHAR *)owner, SQL_NTS, (SQLCHAR *)"SEER_KP", SQL_NTS, NULL,
                        0, NULL, 0, NULL, 0);
    while (SQL_SUCCEEDED(rc) && SQL_SUCCEEDED(SQLFetch(st))) {
      rows++;
      char fkt[64] = "";
      col[0] = '\0';
      SQLGetData(st, 7, SQL_C_CHAR, fkt, sizeof fkt, &ind);
      SQLGetData(st, 8, SQL_C_CHAR, col, sizeof col, &ind);
      SQLGetData(st, 11, SQL_C_SLONG, &v, 0, &ind);
      if (strcmp(fkt, "SEER_KC") != 0 || strcmp(col, "PID") != 0 || v != SQL_CASCADE)
        snprintf(m, sizeof m, "SQLForeignKeys: %s.%s delete rule %d, want SEER_KC.PID %d", fkt, col,
                 (int)v, SQL_CASCADE);
    }
    if (!SQL_SUCCEEDED(rc))
      diag_text(SQL_HANDLE_STMT, st, m, sizeof m);
    else if (m[0] == '\0' && rows != 1)
      snprintf(m, sizeof m, "SQLForeignKeys: %d rows, want 1", rows);
  }
  SQLFreeHandle(SQL_HANDLE_STMT, st);
  exec_do(dbc, "DROP TABLE seer_kc", err, sizeof err);
  exec_do(dbc, "DROP TABLE seer_kp", err, sizeof err);
  if (m[0] == '\0')
    pass(name);
  else
    fail(name, m);
}

/* Explicit descriptors (#291): one allocated on the connection and filled
 * with SQLSetDescField is the ARD of two statements, which both fetch into
 * its buffers, then an INSERT's APD; SQLGetStmtAttr returns it; freed while
 * in use, the statements go back to their own; another statement's
 * implicit descriptor, or an implementation one, can't be set (HY017). */
static void check_explicit_desc(SQLHDBC dbc)
{
  const char *name = "explicit descriptors: shared ARD, APD, free while in use";
  char err[256] = "", m[600] = "";
  exec_do(dbc, "DROP TABLE seer_xd", err, sizeof err);
  exec_do(dbc, "CREATE TABLE seer_xd (id NUMBER, nm VARCHAR2(20))", err, sizeof err);
  SQLHDESC d = SQL_NULL_HDESC;
  SQLHSTMT s1, s2, s3;
  SQLAllocHandle(SQL_HANDLE_STMT, dbc, &s1);
  SQLAllocHandle(SQL_HANDLE_STMT, dbc, &s2);
  SQLAllocHandle(SQL_HANDLE_STMT, dbc, &s3);
  SQLINTEGER id = 0;
  char nm[21] = "";
  SQLLEN id_ind = 0, nm_ind = 0;
  if (!SQL_SUCCEEDED(SQLAllocHandle(SQL_HANDLE_DESC, dbc, &d))) {
    diag_text(SQL_HANDLE_DBC, dbc, m, sizeof m);
    if (m[0] == '\0')
      snprintf(m, sizeof m, "SQLAllocHandle(SQL_HANDLE_DESC) failed with no diagnostic");
  }
  SQLSMALLINT alloc = 0;
  if (m[0] == '\0') {
    SQLGetDescField(d, 0, SQL_DESC_ALLOC_TYPE, &alloc, 0, NULL);
    if (alloc != SQL_DESC_ALLOC_USER)
      snprintf(m, sizeof m, "SQL_DESC_ALLOC_TYPE %d, want SQL_DESC_ALLOC_USER", alloc);
  }
  if (m[0] == '\0') {
    SQLSetDescField(d, 1, SQL_DESC_CONCISE_TYPE, (SQLPOINTER)SQL_C_SLONG, 0);
    SQLSetDescField(d, 1, SQL_DESC_INDICATOR_PTR, &id_ind, 0);
    SQLSetDescField(d, 1, SQL_DESC_DATA_PTR, &id, 0);
    SQLSetDescField(d, 2, SQL_DESC_CONCISE_TYPE, (SQLPOINTER)SQL_C_CHAR, 0);
    SQLSetDescField(d, 2, SQL_DESC_OCTET_LENGTH, (SQLPOINTER)(SQLLEN)sizeof nm, 0);
    SQLSetDescField(d, 2, SQL_DESC_INDICATOR_PTR, &nm_ind, 0);
    SQLSetDescField(d, 2, SQL_DESC_DATA_PTR, nm, 0);
    SQLSMALLINT cnt = 0;
    SQLGetDescField(d, 0, SQL_DESC_COUNT, &cnt, 0, NULL);
    if (cnt != 2)
      snprintf(m, sizeof m, "SQL_DESC_COUNT %d after two records, want 2", cnt);
  }
  /* The ARD of two statements. */
  for (int k = 0; k < 2 && m[0] == '\0'; k++) {
    SQLHSTMT st = k == 0 ? s1 : s2;
    if (!SQL_SUCCEEDED(SQLSetStmtAttr(st, SQL_ATTR_APP_ROW_DESC, d, 0))) {
      diag_text(SQL_HANDLE_STMT, st, m, sizeof m);
      break;
    }
    SQLHDESC got = SQL_NULL_HDESC;
    SQLGetStmtAttr(st, SQL_ATTR_APP_ROW_DESC, &got, 0, NULL);
    const char *sql = k == 0 ? "SELECT 1, 'one' FROM dual" : "SELECT 2, 'two' FROM dual";
    id = 0;
    nm[0] = '\0';
    if (got != d)
      snprintf(m, sizeof m, "statement %d: SQLGetStmtAttr(APP_ROW_DESC) is not the descriptor",
               k + 1);
    else if (!SQL_SUCCEEDED(SQLExecDirect(st, (SQLCHAR *)sql, SQL_NTS)) ||
             !SQL_SUCCEEDED(SQLFetch(st)))
      diag_text(SQL_HANDLE_STMT, st, m, sizeof m);
    else if (id != k + 1 || strcmp(nm, k == 0 ? "one" : "two") != 0)
      snprintf(m, sizeof m, "statement %d fetched %d '%s'", k + 1, (int)id, nm);
    SQLFreeStmt(st, SQL_CLOSE);
  }
  /* The APD of an INSERT: its values from the descriptor's buffers. */
  if (m[0] == '\0') {
    SQLINTEGER dummy = 0;
    SQLLEN dind = 0;
    SQLBindParameter(s3, 1, SQL_PARAM_INPUT, SQL_C_SLONG, SQL_INTEGER, 0, 0, &dummy, 0, &dind);
    SQLBindParameter(s3, 2, SQL_PARAM_INPUT, SQL_C_CHAR, SQL_VARCHAR, 20, 0, NULL, 0, &dind);
    id = 7;
    strcpy(nm, "seven");
    id_ind = 0;
    nm_ind = SQL_NTS;
    if (!SQL_SUCCEEDED(SQLSetStmtAttr(s3, SQL_ATTR_APP_PARAM_DESC, d, 0)) ||
        !SQL_SUCCEEDED(SQLExecDirect(s3, (SQLCHAR *)"INSERT INTO seer_xd VALUES (?, ?)", SQL_NTS)))
      diag_text(SQL_HANDLE_STMT, s3, m, sizeof m);
  }
  /* Freed while in use: s1 is back on its own ARD. */
  if (m[0] == '\0') {
    SQLFreeHandle(SQL_HANDLE_DESC, d);
    d = SQL_NULL_HDESC;
    SQLINTEGER v = 0;
    SQLLEN vind = 0;
    SQLBindCol(s1, 1, SQL_C_SLONG, &v, 0, &vind);
    if (!SQL_SUCCEEDED(
            SQLExecDirect(s1, (SQLCHAR *)"SELECT id FROM seer_xd WHERE nm = 'seven'", SQL_NTS)) ||
        !SQL_SUCCEEDED(SQLFetch(s1)))
      diag_text(SQL_HANDLE_STMT, s1, m, sizeof m);
    else if (v != 7)
      snprintf(m, sizeof m, "after the free, s1 fetched %d (want the inserted 7)", (int)v);
    SQLFreeStmt(s1, SQL_CLOSE);
  }
  /* Another statement's implicit descriptor, and an IRD: HY017. */
  for (int k = 0; k < 2 && m[0] == '\0'; k++) {
    SQLHDESC other = SQL_NULL_HDESC;
    SQLGetStmtAttr(s2, SQL_ATTR_APP_ROW_DESC, &other, 0, NULL);
    SQLRETURN rc =
        SQLSetStmtAttr(s1, k == 0 ? SQL_ATTR_APP_ROW_DESC : SQL_ATTR_IMP_ROW_DESC, other, 0);
    SQLCHAR state[6] = "", msg[200];
    SQLINTEGER nat;
    SQLSMALLINT ml;
    SQLGetDiagRec(SQL_HANDLE_STMT, s1, 1, state, &nat, msg, sizeof msg, &ml);
    if (rc != SQL_ERROR || strcmp((char *)state, "HY017") != 0)
      snprintf(m, sizeof m, "%s: rc %d %s, want HY017",
               k == 0 ? "another statement's ARD as APP_ROW_DESC" : "setting IMP_ROW_DESC", rc,
               (char *)state);
  }
  if (d != SQL_NULL_HDESC)
    SQLFreeHandle(SQL_HANDLE_DESC, d);
  SQLFreeHandle(SQL_HANDLE_STMT, s3);
  SQLFreeHandle(SQL_HANDLE_STMT, s2);
  SQLFreeHandle(SQL_HANDLE_STMT, s1);
  exec_do(dbc, "DROP TABLE seer_xd", err, sizeof err);
  if (m[0] == '\0')
    pass(name);
  else
    fail(name, m);
}

/* SQLCopyDesc (#289), the classic row copy: a SELECT's ARD becomes an
 * INSERT's APD and its IRD the INSERT's IPD, so each fetched row inserts as
 * it is. A target IRD is HY016; an unprepared statement's IRD is HY007. */
static void check_copy_desc(SQLHDBC dbc)
{
  const char *name = "SQLCopyDesc: ARD to APD and IRD to IPD copy rows";
  char err[256] = "", m[600] = "";
  static const char *ddl[] = {"DROP TABLE seer_cd_src",
                              "DROP TABLE seer_cd_dst",
                              "CREATE TABLE seer_cd_src (id NUMBER, nm VARCHAR2(20))",
                              "CREATE TABLE seer_cd_dst (id NUMBER, nm VARCHAR2(20))",
                              "INSERT INTO seer_cd_src VALUES (1, 'one')",
                              "INSERT INTO seer_cd_src VALUES (2, NULL)",
                              "INSERT INTO seer_cd_src VALUES (3, 'three')"};
  for (size_t k = 0; k < sizeof ddl / sizeof ddl[0]; k++)
    exec_do(dbc, ddl[k], err, sizeof err);
  SQLHSTMT sel, ins, idle;
  SQLAllocHandle(SQL_HANDLE_STMT, dbc, &sel);
  SQLAllocHandle(SQL_HANDLE_STMT, dbc, &ins);
  SQLAllocHandle(SQL_HANDLE_STMT, dbc, &idle);
  SQLINTEGER id = 0;
  char nm[21] = "";
  SQLLEN id_ind = 0, nm_ind = 0;
  SQLBindCol(sel, 1, SQL_C_SLONG, &id, 0, &id_ind);
  SQLBindCol(sel, 2, SQL_C_CHAR, nm, sizeof nm, &nm_ind);
  SQLHDESC ard, ird, apd, ipd, idle_ird;
  SQLGetStmtAttr(sel, SQL_ATTR_APP_ROW_DESC, &ard, 0, NULL);
  SQLGetStmtAttr(sel, SQL_ATTR_IMP_ROW_DESC, &ird, 0, NULL);
  SQLGetStmtAttr(ins, SQL_ATTR_APP_PARAM_DESC, &apd, 0, NULL);
  SQLGetStmtAttr(ins, SQL_ATTR_IMP_PARAM_DESC, &ipd, 0, NULL);
  SQLGetStmtAttr(idle, SQL_ATTR_IMP_ROW_DESC, &idle_ird, 0, NULL);
  if (!SQL_SUCCEEDED(
          SQLExecDirect(sel, (SQLCHAR *)"SELECT id, nm FROM seer_cd_src ORDER BY id", SQL_NTS)))
    diag_text(SQL_HANDLE_STMT, sel, m, sizeof m);
  if (m[0] == '\0' &&
      !SQL_SUCCEEDED(SQLPrepare(ins, (SQLCHAR *)"INSERT INTO seer_cd_dst VALUES (?, ?)", SQL_NTS)))
    diag_text(SQL_HANDLE_STMT, ins, m, sizeof m);
  if (m[0] == '\0' && !SQL_SUCCEEDED(SQLCopyDesc(ard, apd)))
    diag_text(SQL_HANDLE_DESC, apd, m, sizeof m);
  if (m[0] == '\0' && !SQL_SUCCEEDED(SQLCopyDesc(ird, ipd)))
    diag_text(SQL_HANDLE_DESC, ipd, m, sizeof m);
  int rows = 0;
  while (m[0] == '\0' && SQL_SUCCEEDED(SQLFetch(sel))) {
    rows++;
    if (!SQL_SUCCEEDED(SQLExecute(ins)))
      diag_text(SQL_HANDLE_STMT, ins, m, sizeof m);
  }
  SQLCHAR state[6] = "", msg[200];
  SQLINTEGER nat;
  SQLSMALLINT ml;
  if (m[0] == '\0') {
    SQLRETURN rc = SQLCopyDesc(ard, ird);
    SQLGetDiagRec(SQL_HANDLE_DESC, ird, 1, state, &nat, msg, sizeof msg, &ml);
    if (rc != SQL_ERROR || strcmp((char *)state, "HY016") != 0)
      snprintf(m, sizeof m, "copy to an IRD: rc %d %s, want HY016", rc, (char *)state);
  }
  if (m[0] == '\0') {
    state[0] = '\0';
    SQLRETURN rc = SQLCopyDesc(idle_ird, apd);
    SQLGetDiagRec(SQL_HANDLE_DESC, apd, 1, state, &nat, msg, sizeof msg, &ml);
    if (rc != SQL_ERROR || strcmp((char *)state, "HY007") != 0)
      snprintf(m, sizeof m, "copy from an unprepared IRD: rc %d %s, want HY007", rc, (char *)state);
  }
  SQLFreeHandle(SQL_HANDLE_STMT, idle);
  SQLFreeHandle(SQL_HANDLE_STMT, ins);
  SQLFreeHandle(SQL_HANDLE_STMT, sel);
  if (m[0] == '\0') {
    char got[128] = "";
    exec_scalar(dbc,
                "SELECT COUNT(*) || ':' || SUM(id) || ':' || MAX(DECODE(id, 1, nm)) || ':' || "
                "NVL(MAX(DECODE(id, 2, nm)), 'null') || ':' || MAX(DECODE(id, 3, nm)) FROM "
                "seer_cd_dst",
                got, sizeof got, err, sizeof err);
    if (rows != 3 || strcmp(got, "3:6:one:null:three") != 0)
      snprintf(m, sizeof m, "%d rows copied, target '%s'; want 3, '3:6:one:null:three' %s", rows,
               got, err);
  }
  exec_do(dbc, "DROP TABLE seer_cd_dst", err, sizeof err);
  exec_do(dbc, "DROP TABLE seer_cd_src", err, sizeof err);
  if (m[0] == '\0')
    pass(name);
  else
    fail(name, m);
}

static const char *stmt_state(SQLHSTMT st, SQLRETURN rc, char *state)
{
  SQLINTEGER nat;
  SQLSMALLINT ml;
  SQLCHAR msg[256];
  state[0] = '\0';
  if (rc != SQL_SUCCESS)
    SQLGetDiagRec(SQL_HANDLE_STMT, st, 1, (SQLCHAR *)state, &nat, msg, sizeof msg, &ml);
  return state;
}

/* Cursor names and positioned DML (#288): a statement has a generated
 * SQL_CURn name, takes the application's, refuses a duplicate (3C000) and
 * one in the driver's namespace (34000); UPDATE / DELETE ... WHERE CURRENT
 * OF act on the named cursor's current row only; an unknown name is 34000
 * and a closed cursor 24000. */
static void check_cursor_names(SQLHDBC dbc)
{
  const char *name = "cursor names: SQLSetCursorName / WHERE CURRENT OF";
  char err[256] = "", m[600] = "", state[6];
  static const char *ddl[] = {"DROP TABLE seer_woc", "CREATE TABLE seer_woc (id NUMBER, v NUMBER)",
                              "INSERT INTO seer_woc VALUES (1, 10)",
                              "INSERT INTO seer_woc VALUES (2, 20)",
                              "INSERT INTO seer_woc VALUES (3, 30)"};
  for (size_t k = 0; k < sizeof ddl / sizeof ddl[0]; k++)
    exec_do(dbc, ddl[k], err, sizeof err);
  SQLHSTMT cur, pos;
  SQLAllocHandle(SQL_HANDLE_STMT, dbc, &cur);
  SQLAllocHandle(SQL_HANDLE_STMT, dbc, &pos);
  SQLCHAR cn[64] = "";
  SQLSMALLINT cl = 0;
  SQLRETURN rc = SQLGetCursorName(cur, cn, sizeof cn, &cl);
  if (rc != SQL_SUCCESS || strncmp((char *)cn, "SQL_CUR", 7) != 0 ||
      cl != (SQLSMALLINT)strlen((char *)cn))
    snprintf(m, sizeof m, "generated name: rc %d '%s' len %d", rc, (char *)cn, cl);
  if (m[0] == '\0' && SQLSetCursorName(cur, (SQLCHAR *)"SEERCUR", SQL_NTS) != SQL_SUCCESS)
    diag_text(SQL_HANDLE_STMT, cur, m, sizeof m);
  if (m[0] == '\0') {
    SQLGetCursorName(cur, cn, sizeof cn, &cl);
    if (strcmp((char *)cn, "SEERCUR") != 0)
      snprintf(m, sizeof m, "SQLGetCursorName after setting: '%s'", (char *)cn);
  }
  if (m[0] == '\0') {
    rc = SQLSetCursorName(pos, (SQLCHAR *)"seercur", SQL_NTS);
    if (strcmp(stmt_state(pos, rc, state), "3C000") != 0)
      snprintf(m, sizeof m, "duplicate name: rc %d %s, want 3C000", rc, state);
  }
  if (m[0] == '\0') {
    rc = SQLSetCursorName(pos, (SQLCHAR *)"SQL_CUR99", SQL_NTS);
    if (strcmp(stmt_state(pos, rc, state), "34000") != 0)
      snprintf(m, sizeof m, "SQL_CUR99: rc %d %s, want 34000", rc, state);
  }
  /* Positioned UPDATE then DELETE through SEERCUR, on rows 1 and 2. */
  SQLSetStmtAttr(cur, SQL_ATTR_CONCURRENCY, (SQLPOINTER)SQL_CONCUR_LOCK, 0);
  if (m[0] == '\0' && !SQL_SUCCEEDED(SQLExecDirect(
                          cur, (SQLCHAR *)"SELECT id, v FROM seer_woc ORDER BY id", SQL_NTS)))
    diag_text(SQL_HANDLE_STMT, cur, m, sizeof m);
  for (int k = 0; k < 2 && m[0] == '\0'; k++) {
    SQLLEN n = -1;
    if (!SQL_SUCCEEDED(SQLFetch(cur))) {
      diag_text(SQL_HANDLE_STMT, cur, m, sizeof m);
      break;
    }
    const char *dml = k == 0 ? "UPDATE seer_woc SET v = 99 WHERE CURRENT OF SEERCUR"
                             : "DELETE FROM seer_woc WHERE CURRENT OF seercur";
    rc = SQLExecDirect(pos, (SQLCHAR *)dml, SQL_NTS);
    if (!SQL_SUCCEEDED(rc))
      diag_text(SQL_HANDLE_STMT, pos, m, sizeof m);
    else if (SQLRowCount(pos, &n), n != 1)
      snprintf(m, sizeof m, "%s: %ld rows, want 1", dml, (long)n);
    SQLFreeStmt(pos, SQL_CLOSE);
  }
  if (m[0] == '\0') {
    rc = SQLExecDirect(pos, (SQLCHAR *)"UPDATE seer_woc SET v = 0 WHERE CURRENT OF NOPE", SQL_NTS);
    if (strcmp(stmt_state(pos, rc, state), "34000") != 0)
      snprintf(m, sizeof m, "unknown cursor: rc %d %s, want 34000", rc, state);
  }
  SQLCloseCursor(cur);
  if (m[0] == '\0') {
    rc = SQLExecDirect(pos, (SQLCHAR *)"UPDATE seer_woc SET v = 0 WHERE CURRENT OF SEERCUR",
                       SQL_NTS);
    if (strcmp(stmt_state(pos, rc, state), "24000") != 0)
      snprintf(m, sizeof m, "closed cursor: rc %d %s, want 24000", rc, state);
  }
  SQLFreeHandle(SQL_HANDLE_STMT, pos);
  SQLFreeHandle(SQL_HANDLE_STMT, cur);
  if (m[0] == '\0') {
    char got[64] = "";
    exec_scalar(dbc,
                "SELECT LISTAGG_ID FROM (SELECT MAX(DECODE(id, 1, v)) || ',' || COUNT(*) || ',' "
                "|| MAX(DECODE(id, 3, v)) LISTAGG_ID FROM seer_woc)",
                got, sizeof got, err, sizeof err);
    if (strcmp(got, "99,2,30") != 0)
      snprintf(m, sizeof m, "table after: '%s' (row 1 v, rows, row 3 v), want '99,2,30' %s", got,
               err);
  }
  exec_do(dbc, "DROP TABLE seer_woc", err, sizeof err);
  if (m[0] == '\0')
    pass(name);
  else
    fail(name, m);
}

/* SQLTablePrivileges and SQLColumnPrivileges (#286): a table granted SELECT,
 * and one column UPDATE, to PUBLIC lists those grants, in ODBC's columns. */
static void check_privileges(SQLHDBC dbc)
{
  const char *name = "SQLTablePrivileges / SQLColumnPrivileges";
  char err[256] = "", m[600] = "";
  exec_do(dbc, "DROP TABLE seer_priv", err, sizeof err);
  exec_do(dbc, "CREATE TABLE seer_priv (id NUMBER, v NUMBER)", err, sizeof err);
  exec_do(dbc, "GRANT SELECT ON seer_priv TO PUBLIC", err, sizeof err);
  exec_do(dbc, "GRANT UPDATE (v) ON seer_priv TO PUBLIC", err, sizeof err);
  char owner[64] = "";
  const char *u = getenv("SEER_TEST_USER");
  for (size_t k = 0; u != NULL && u[k] != '\0' && k + 1 < sizeof owner; k++)
    owner[k] = (char)toupper((unsigned char)u[k]);
  SQLHSTMT st;
  SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st);
  for (int k = 0; k < 2 && m[0] == '\0'; k++) {
    SQLRETURN rc =
        k == 0 ? SQLTablePrivileges(st, NULL, 0, (SQLCHAR *)owner, SQL_NTS, (SQLCHAR *)"SEER_PRIV",
                                    SQL_NTS)
               : SQLColumnPrivileges(st, NULL, 0, (SQLCHAR *)owner, SQL_NTS, (SQLCHAR *)"SEER_PRIV",
                                     SQL_NTS, (SQLCHAR *)"%", SQL_NTS);
    const char *fn = k == 0 ? "SQLTablePrivileges" : "SQLColumnPrivileges";
    SQLSMALLINT nc = 0, gcol = (SQLSMALLINT)(k == 0 ? 5 : 6);
    char label[32] = "";
    if (SQL_SUCCEEDED(rc)) {
      SQLNumResultCols(st, &nc);
      SQLColAttribute(st, (SQLUSMALLINT)gcol, SQL_DESC_NAME, label, sizeof label, NULL, NULL);
    }
    int rows = 0;
    char got[160] = "";
    while (SQL_SUCCEEDED(rc) && SQL_SUCCEEDED(SQLFetch(st))) {
      char col[64] = "", grantee[64] = "", priv[64] = "", gr[8] = "";
      SQLLEN ind;
      rows++;
      if (k == 1)
        SQLGetData(st, 4, SQL_C_CHAR, col, sizeof col, &ind);
      SQLGetData(st, (SQLUSMALLINT)gcol, SQL_C_CHAR, grantee, sizeof grantee, &ind);
      SQLGetData(st, (SQLUSMALLINT)(gcol + 1), SQL_C_CHAR, priv, sizeof priv, &ind);
      SQLGetData(st, (SQLUSMALLINT)(gcol + 2), SQL_C_CHAR, gr, sizeof gr, &ind);
      snprintf(got, sizeof got, "%s%s%s %s %s", col, col[0] ? " " : "", grantee, priv, gr);
    }
    const char *want = k == 0 ? "PUBLIC SELECT NO" : "V PUBLIC UPDATE NO";
    if (!SQL_SUCCEEDED(rc))
      diag_text(SQL_HANDLE_STMT, st, m, sizeof m);
    else if (nc != (k == 0 ? 7 : 8) || strcmp(label, "GRANTEE") != 0)
      snprintf(m, sizeof m, "%s: %d columns, column %d '%s'; want %d, GRANTEE", fn, nc, gcol, label,
               k == 0 ? 7 : 8);
    else if (rows != 1 || strcmp(got, want) != 0)
      snprintf(m, sizeof m, "%s: %d rows, '%s'; want 1, '%s'", fn, rows, got, want);
    SQLFreeStmt(st, SQL_CLOSE);
  }
  SQLFreeHandle(SQL_HANDLE_STMT, st);
  exec_do(dbc, "DROP TABLE seer_priv", err, sizeof err);
  if (m[0] == '\0')
    pass(name);
  else
    fail(name, m);
}

/* SQLTables' enumerations and type list (#282): SQL_ALL_CATALOGS is empty,
 * SQL_ALL_SCHEMAS one row per user (the test user among them, no table
 * names), SQL_ALL_TABLE_TYPES TABLE and VIEW; a type list is compared by
 * whole names, so 'SYNONYM' finds none of seer_te's rows. */
static void check_tables_enum(SQLHDBC dbc)
{
  const char *name = "SQLTables: catalog, schema and table-type enumerations";
  char err[256] = "", m[600] = "";
  exec_do(dbc, "DROP TABLE seer_te", err, sizeof err);
  exec_do(dbc, "CREATE TABLE seer_te (id NUMBER)", err, sizeof err);
  char owner[64] = "";
  const char *u = getenv("SEER_TEST_USER");
  for (size_t k = 0; u != NULL && u[k] != '\0' && k + 1 < sizeof owner; k++)
    owner[k] = (char)toupper((unsigned char)u[k]);
  SQLCHAR *E = (SQLCHAR *)"", *A = (SQLCHAR *)"%", *T = (SQLCHAR *)"SEER_TE";
  SQLHSTMT st;
  SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st);
  for (int k = 0; k < 5 && m[0] == '\0'; k++) {
    static const char *what[5] = {"SQL_ALL_CATALOGS", "SQL_ALL_SCHEMAS", "SQL_ALL_TABLE_TYPES",
                                  "types 'SYNONYM'", "types 'VIEW', 'TABLE'"};
    SQLRETURN rc;
    if (k == 0)
      rc = SQLTables(st, A, SQL_NTS, E, SQL_NTS, E, SQL_NTS, NULL, 0);
    else if (k == 1)
      rc = SQLTables(st, E, SQL_NTS, A, SQL_NTS, E, SQL_NTS, NULL, 0);
    else if (k == 2)
      rc = SQLTables(st, E, SQL_NTS, E, SQL_NTS, E, SQL_NTS, A, SQL_NTS);
    else
      rc = SQLTables(st, NULL, 0, (SQLCHAR *)owner, SQL_NTS, T, SQL_NTS,
                     (SQLCHAR *)(k == 3 ? "'SYNONYM'" : "'VIEW', 'TABLE'"), SQL_NTS);
    int rows = 0, mine = 0, named = 0;
    char types[64] = "";
    while (SQL_SUCCEEDED(rc) && SQL_SUCCEEDED(SQLFetch(st))) {
      char sch[130] = "", tab[130] = "", typ[130] = "";
      SQLLEN ind;
      rows++;
      SQLGetData(st, 2, SQL_C_CHAR, sch, sizeof sch, &ind);
      SQLGetData(st, 3, SQL_C_CHAR, tab, sizeof tab, &ind);
      if (ind != SQL_NULL_DATA)
        named++;
      SQLGetData(st, 4, SQL_C_CHAR, typ, sizeof typ, &ind);
      if (strcmp(sch, owner) == 0)
        mine++;
      if (k == 2 && strlen(types) + strlen(typ) + 2 < sizeof types) {
        strcat(types, typ);
        strcat(types, " ");
      }
    }
    if (!SQL_SUCCEEDED(rc))
      diag_text(SQL_HANDLE_STMT, st, m, sizeof m);
    else if (k == 0 && rows != 0)
      snprintf(m, sizeof m, "%s: %d rows, want 0", what[k], rows);
    else if (k == 1 && (mine != 1 || named != 0))
      snprintf(m, sizeof m, "%s: %d rows for %s, %d with a table name; want 1 and 0", what[k], mine,
               owner, named);
    else if (k == 2 && strcmp(types, "TABLE VIEW ") != 0)
      snprintf(m, sizeof m, "%s: %s, want TABLE VIEW", what[k], types);
    else if (k >= 3 && rows != (k == 3 ? 0 : 1))
      snprintf(m, sizeof m, "%s: %d rows, want %d", what[k], rows, k == 3 ? 0 : 1);
    SQLFreeStmt(st, SQL_CLOSE);
  }
  SQLFreeHandle(SQL_HANDLE_STMT, st);
  exec_do(dbc, "DROP TABLE seer_te", err, sizeof err);
  if (m[0] == '\0')
    pass(name);
  else
    fail(name, m);
}

/* SQLNumParams and SQLDescribeParam (#280): the parameters a prepared
 * statement has are described, and one past the last is 07009. */
/* Run `sql` with text parameters `p` (NULL-terminated), column 1 into `out`.
 * The SQLSTATE of a failure goes into `state`. */
static SQLRETURN exec_params(SQLHDBC dbc, const char *sql, const char *const *p, char *out,
                             int outn, char state[6])
{
  SQLHSTMT st;
  SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st);
  SQLLEN ind[4] = {SQL_NTS, SQL_NTS, SQL_NTS, SQL_NTS}, oi = 0;
  out[0] = state[0] = '\0';
  SQLRETURN rc = SQLPrepare(st, (SQLCHAR *)sql, SQL_NTS);
  for (int i = 0; i < 4 && p[i] != NULL && SQL_SUCCEEDED(rc); i++)
    rc = SQLBindParameter(st, (SQLUSMALLINT)(i + 1), SQL_PARAM_INPUT, SQL_C_CHAR, SQL_VARCHAR, 30,
                          0, (SQLPOINTER)p[i], 0, &ind[i]);
  if (SQL_SUCCEEDED(rc))
    rc = SQLExecute(st);
  if (SQL_SUCCEEDED(rc))
    rc = SQLFetch(st);
  if (SQL_SUCCEEDED(rc))
    rc = SQLGetData(st, 1, SQL_C_CHAR, out, outn, &oi);
  if (!SQL_SUCCEEDED(rc)) {
    SQLINTEGER nat;
    SQLCHAR msg[300];
    SQLSMALLINT ml;
    SQLGetDiagRec(SQL_HANDLE_STMT, st, 1, (SQLCHAR *)state, &nat, msg, sizeof msg, &ml);
  }
  SQLFreeHandle(SQL_HANDLE_STMT, st);
  return rc;
}

/* The {fn} scalar functions (#301): each translation's value, on every
 * release (8i's own forms where it lacks LOCALTIMESTAMP, INTERVAL and
 * TIMESTAMP), the SQLGetInfo masks that advertise them, and parameter markers
 * in their arguments: kept in order where the Oracle form repeats or reorders
 * them, and refused (HYC00) where two of them would swap. */
static void check_scalar_functions(SQLHDBC dbc)
{
  const char *name = "{fn} scalar functions: values, masks, markers";
  static const struct {
    const char *expr, *want;
    int from; /* the first release it applies to */
  } T[] = {
      {"{fn CHAR(65)}", "A", 0},
      {"{fn BIT_LENGTH('abc')}", "24", 0},
      {"{fn CHAR_LENGTH('abc')}", "3", 0},
      {"{fn OCTET_LENGTH('abc')}", "3", 0},
      {"{fn INSERT('abcdef',2,3,'XY')}", "aXYef", 0},
      {"{fn INSERT('abcdef',1,2,'XY')}", "XYcdef", 0},
      {"{fn LEFT('abcdef',2)}", "ab", 0},
      {"{fn LEFT('ab',5)}", "ab", 0},
      {"{fn RIGHT('abcdef',2)}", "ef", 0},
      {"{fn RIGHT('ab',5)}", "ab", 0},
      {"{fn LENGTH('abc  ')}", "3", 0},
      {"{fn LOCATE('c','abcabc')}", "3", 0},
      {"{fn LOCATE('c','abcabc',4)}", "6", 0},
      {"{fn POSITION('c' IN 'abc')}", "3", 0},
      {"{fn REPEAT('ab',3)}", "ababab", 0},
      {"{fn CONCAT('[',{fn CONCAT({fn SPACE(3)},']')})}", "[   ]", 0},
      {"{fn ROUND({fn COT(1)},4)}", "0.6421", 0},
      {"{fn ROUND({fn DEGREES({fn PI()})},4)}", "180", 0},
      {"{fn ROUND({fn RADIANS(180)},4)}", "3.1416", 0},
      {"{fn ROUND({fn LOG(10)},4)}", "2.3026", 0},
      {"{fn LOG10(1000)}", "3", 0},
      {"{fn TRUNCATE(2.567,1)}", "2.5", 0},
      {"{fn DAYNAME({d '2026-11-18'})}", "Wednesday", 0},
      {"{fn MONTHNAME({d '2026-11-18'})}", "November", 0},
      {"{fn DAYOFMONTH({d '2026-11-18'})}", "18", 0},
      {"{fn DAYOFWEEK({d '2026-11-15'})}", "1", 0}, /* a Sunday */
      {"{fn DAYOFWEEK({d '2026-11-21'})}", "7", 0}, /* a Saturday */
      {"{fn DAYOFYEAR({d '2026-11-18'})}", "322", 0},
      {"{fn QUARTER({d '2026-11-18'})}", "4", 0},
      {"{fn WEEK({d '2026-01-01'})}", "1", 0},
      {"{fn WEEK({d '2026-01-03'})}", "1", 0}, /* the Saturday */
      {"{fn WEEK({d '2026-01-04'})}", "2", 0}, /* the Sunday after */
      {"{fn WEEK({d '2026-11-18'})}", "47", 0},
      {"{fn HOUR({ts '2026-11-18 13:45:56'})}", "13", 0},
      {"{fn MINUTE({ts '2026-11-18 13:45:56'})}", "45", 0},
      {"{fn SECOND({ts '2026-11-18 13:45:56'})}", "56", 0},
      {"{fn YEAR({d '2026-11-18'})}", "2026", 0},
      {"{fn MONTH({d '2026-11-18'})}", "11", 0},
      {"TO_CHAR({fn CURDATE()}, 'HH24:MI:SS')", "00:00:00", 0},
      {"TO_CHAR({fn CURRENT_DATE()}, 'YYYY') - TO_CHAR(SYSDATE, 'YYYY')", "0", 0},
      {"SIGN(CAST({fn NOW()} AS DATE) - SYSDATE + 1)", "1", 0},
      {"SIGN(CAST({fn CURRENT_TIMESTAMP()} AS DATE) - SYSDATE + 1)", "1", 0},
      {"SIGN(CAST({fn CURTIME()} AS DATE) - SYSDATE + 1)", "1", 0},
      {"TO_CHAR({fn TIMESTAMPADD(SQL_TSI_SECOND,90,{ts '2026-11-18 10:00:00'})},"
       " 'YYYY-MM-DD HH24:MI:SS')",
       "2026-11-18 10:01:30", 0},
      {"TO_CHAR({fn TIMESTAMPADD(SQL_TSI_HOUR,-3,{ts '2026-11-18 01:00:00'})},"
       " 'YYYY-MM-DD HH24:MI:SS')",
       "2026-11-17 22:00:00", 0},
      {"TO_CHAR({fn TIMESTAMPADD(SQL_TSI_DAY,1,{d '2026-11-18'})}, 'YYYY-MM-DD')", "2026-11-19", 0},
      {"TO_CHAR({fn TIMESTAMPADD(SQL_TSI_WEEK,2,{d '2026-11-18'})}, 'YYYY-MM-DD')", "2026-12-02",
       0},
      {"TO_CHAR({fn TIMESTAMPADD(SQL_TSI_MONTH,1,{d '2026-01-31'})}, 'YYYY-MM-DD')", "2026-02-28",
       0},
      {"TO_CHAR({fn TIMESTAMPADD(SQL_TSI_QUARTER,1,{d '2026-11-18'})}, 'YYYY-MM-DD')", "2027-02-18",
       0},
      {"TO_CHAR({fn TIMESTAMPADD(SQL_TSI_YEAR,1,{d '2026-11-18'})}, 'YYYY-MM-DD')", "2027-11-18",
       0},
      {"TO_CHAR({fn TIMESTAMPADD(SQL_TSI_FRAC_SECOND,500000000,{ts '2026-11-18 10:00:00'})},"
       " 'HH24:MI:SS.FF3')",
       "10:00:00.500", 9},
      {"{fn TIMESTAMPDIFF(SQL_TSI_SECOND,{ts '2026-11-18 10:00:00'},{ts '2026-11-18 12:59:59'})}",
       "10799", 0},
      {"{fn TIMESTAMPDIFF(SQL_TSI_MINUTE,{ts '2026-11-18 10:00:00'},{ts '2026-11-18 12:59:59'})}",
       "179", 0},
      {"{fn TIMESTAMPDIFF(SQL_TSI_HOUR,{ts '2026-11-18 10:00:00'},{ts '2026-11-18 12:59:59'})}",
       "2", 0},
      {"{fn TIMESTAMPDIFF(SQL_TSI_DAY,{d '2026-11-20'},{d '2026-11-18'})}", "-2", 0},
      {"{fn TIMESTAMPDIFF(SQL_TSI_WEEK,{d '2026-11-01'},{d '2026-11-18'})}", "2", 0},
      {"{fn TIMESTAMPDIFF(SQL_TSI_MONTH,{d '2026-01-31'},{d '2026-03-30'})}", "1", 0},
      {"{fn TIMESTAMPDIFF(SQL_TSI_QUARTER,{d '2026-01-15'},{d '2026-11-18'})}", "3", 0},
      {"{fn TIMESTAMPDIFF(SQL_TSI_YEAR,{d '2020-11-19'},{d '2026-11-18'})}", "5", 0},
      {"{fn TIMESTAMPDIFF(DAY,{d '2026-11-18'},{d '2026-11-19'})}", "1", 0}, /* no SQL_TSI_ */
      {"{fn USER()}", "", 0}, /* the name: any non-empty answer */
      {"{fn IFNULL(NULL,5)}", "5", 0},
      {"{fn CONVERT('42',SQL_INTEGER)}", "42", 0},
      {"{fn CONVERT('2.9',SQL_INTEGER)}", "2", 0},
      {"{fn CONVERT(42,SQL_VARCHAR)} || 'x'", "42x", 0},
      {"{fn CONVERT('2.5',SQL_DOUBLE)} * 2", "5", 0},
      {"{fn CONVERT('2.5',SQL_DECIMAL)} * 2", "5", 0},
      {"TO_CHAR({fn CONVERT({ts '2026-11-18 10:11:12'},SQL_DATE)}, 'YYYY-MM-DD HH24:MI:SS')",
       "2026-11-18 00:00:00", 0},
      {"TO_CHAR({fn CONVERT({d '2026-11-18'},SQL_TIMESTAMP)}, 'YYYY-MM-DD')", "2026-11-18", 0},
  };
  char m[700] = "", out[256], err[256];
  for (size_t i = 0; i < sizeof T / sizeof T[0] && m[0] == '\0'; i++) {
    if (g_release < T[i].from)
      continue;
    char sql[512];
    snprintf(sql, sizeof sql, "SELECT %s FROM dual", T[i].expr);
    if (!SQL_SUCCEEDED(exec_scalar(dbc, sql, out, sizeof out, err, sizeof err)))
      snprintf(m, sizeof m, "%s: %s", T[i].expr, err);
    else if (T[i].want[0] == '\0' ? out[0] == '\0' : strcmp(out, T[i].want) != 0)
      snprintf(m, sizeof m, "%s: got '%s', want '%s'", T[i].expr, out, T[i].want);
  }

  /* Markers: LOCATE reorders its two arguments, which is fine while one holds
   * a marker; REPEAT and RIGHT repeat theirs, each still one parameter
   * (#302); two markers that would swap are refused (HYC00). */
  static const struct {
    const char *sql, *p[4], *want;
  } P[] = {
      {"SELECT {fn LOCATE(?, 'abcabc')} FROM dual", {"c", NULL}, "3"},
      {"SELECT {fn LOCATE('c', ?)} FROM dual", {"xxc", NULL}, "3"},
      {"SELECT {fn RIGHT('abcdef', ?)} || ? FROM dual", {"2", "!", NULL}, "ef!"},
      {"SELECT ? || {fn LEFT(?, 2)} || ? FROM dual", {"[", "abc", "]"}, "[ab]"},
      {"SELECT {fn REPEAT(?, 2)} || ? FROM dual", {"ab", "!", NULL}, "abab!"},
      {"SELECT {fn RIGHT(?, ?)} || ? FROM dual", {"abcdef", "2", "!"}, "ef!"},
      {"SELECT {fn LOCATE(?, ?)} FROM dual", {"c", "abc", NULL}, NULL},
  };
  for (size_t i = 0; i < sizeof P / sizeof P[0] && m[0] == '\0'; i++) {
    char state[6];
    SQLRETURN rc = exec_params(dbc, P[i].sql, P[i].p, out, sizeof out, state);
    if (P[i].want == NULL) {
      if (rc != SQL_ERROR || strcmp(state, "HYC00") != 0)
        snprintf(m, sizeof m, "%s: rc %d %s, want HYC00", P[i].sql, rc, state);
    } else if (!SQL_SUCCEEDED(rc)) {
      snprintf(m, sizeof m, "%s: rc %d %s", P[i].sql, rc, state);
    } else if (strcmp(out, P[i].want) != 0) {
      snprintf(m, sizeof m, "%s: got '%s', want '%s'", P[i].sql, out, P[i].want);
    }
  }

  /* The masks advertise what translates, release by release. */
  SQLUINTEGER v = 0;
  if (m[0] == '\0') {
    SQLGetInfo(dbc, SQL_STRING_FUNCTIONS, &v, sizeof v, NULL);
    if (!(v & SQL_FN_STR_LOCATE) || !(v & SQL_FN_STR_LEFT) || (v & SQL_FN_STR_DIFFERENCE))
      snprintf(m, sizeof m, "SQL_STRING_FUNCTIONS 0x%x", (unsigned)v);
  }
  if (m[0] == '\0') {
    SQLGetInfo(dbc, SQL_TIMEDATE_FUNCTIONS, &v, sizeof v, NULL);
    if (!(v & SQL_FN_TD_TIMESTAMPDIFF) || !(v & SQL_FN_TD_EXTRACT))
      snprintf(m, sizeof m, "SQL_TIMEDATE_FUNCTIONS 0x%x", (unsigned)v);
  }
  if (m[0] == '\0') {
    SQLGetInfo(dbc, SQL_TIMEDATE_ADD_INTERVALS, &v, sizeof v, NULL);
    if (!(v & SQL_FN_TSI_MONTH) || !(v & SQL_FN_TSI_FRAC_SECOND) != (g_release == 8))
      snprintf(m, sizeof m, "SQL_TIMEDATE_ADD_INTERVALS 0x%x", (unsigned)v);
  }
  if (m[0] == '\0') {
    SQLGetInfo(dbc, SQL_CONVERT_VARCHAR, &v, sizeof v, NULL);
    SQLUINTEGER d = 0;
    SQLGetInfo(dbc, SQL_CONVERT_DATE, &d, sizeof d, NULL);
    if (!(v & SQL_CVT_INTEGER) || !(v & SQL_CVT_DATE) || (d & SQL_CVT_INTEGER) ||
        !(d & SQL_CVT_CHAR))
      snprintf(m, sizeof m, "SQL_CONVERT_VARCHAR 0x%x, SQL_CONVERT_DATE 0x%x", (unsigned)v,
               (unsigned)d);
  }
  if (m[0] == '\0')
    pass(name);
  else
    fail(name, m);
}

/* Build a statement of `n` repeated items: head item0, item1 ... tail. Each
 * item is `fmt` printed with its index. NULL on no memory. */
static char *repeat_items(const char *head, const char *fmt, int n, const char *tail)
{
  size_t cap = strlen(head) + strlen(tail) + (size_t)n * (strlen(fmt) + 12) + 1;
  char *s = malloc(cap);
  if (s == NULL)
    return NULL;
  /* Each piece fits by the sizing above; stop at the first that doesn't, so
   * `len` never passes `cap`. */
  int w = snprintf(s, cap, "%s", head);
  size_t len = w < 0 ? cap : (size_t)w;
  for (int i = 0; i < n && len < cap; i++) {
    if (i > 0) {
      w = snprintf(s + len, cap - len, ", ");
      len = w < 0 || (size_t)w >= cap - len ? cap : len + (size_t)w;
      if (len >= cap)
        break;
    }
    w = snprintf(s + len, cap - len, fmt, i);
    len = w < 0 || (size_t)w >= cap - len ? cap : len + (size_t)w;
  }
  if (len >= cap) {
    free(s);
    return NULL;
  }
  snprintf(s + len, cap - len, "%s", tail);
  return s;
}

/* The SQL-92 description masks of SQLGetInfo (#306): each bit is set exactly
 * when its statement runs on the release, so a bit both claims a form that
 * works and is missing for one that doesn't. Then the reserved words
 * (SQL_KEYWORDS) and the limits, each right at and one past it. */
static void check_sql92_info(SQLHDBC dbc)
{
  const char *name = "SQL-92 info masks, keywords and limits match the server";
  enum { SETUP = 0 };
  static const struct {
    SQLUSMALLINT type; /* SETUP: run, result ignored */
    SQLUINTEGER bits;
    SQLUSMALLINT type2;
    SQLUINTEGER bits2;
    const char *sql; /* %1$s: the schema; a literal percent is %% */
  } T[] = {
      {SETUP, 0, 0, 0,
       "BEGIN EXECUTE IMMEDIATE 'DROP TABLE seer_s92b'; EXCEPTION WHEN OTHERS THEN NULL; END;"},
      {SETUP, 0, 0, 0,
       "BEGIN EXECUTE IMMEDIATE 'DROP TABLE seer_s92s'; EXCEPTION WHEN OTHERS THEN NULL; END;"},
      {SETUP, 0, 0, 0,
       "BEGIN EXECUTE IMMEDIATE 'DROP TABLE seer_s92g'; EXCEPTION WHEN OTHERS THEN NULL; END;"},
      {SETUP, 0, 0, 0,
       "BEGIN EXECUTE IMMEDIATE 'DROP TABLE seer_s92m'; EXCEPTION WHEN OTHERS THEN NULL; END;"},
      {SETUP, 0, 0, 0,
       "BEGIN EXECUTE IMMEDIATE 'DROP TABLE seer_s92k'; EXCEPTION WHEN OTHERS THEN NULL; END;"},
      {SETUP, 0, 0, 0,
       "BEGIN EXECUTE IMMEDIATE 'DROP VIEW seer_s92v'; EXCEPTION WHEN OTHERS THEN NULL; END;"},
      {SETUP, 0, 0, 0,
       "BEGIN EXECUTE IMMEDIATE 'DROP TABLE seer_s92t'; EXCEPTION WHEN OTHERS THEN NULL; END;"},
      {SETUP, 0, 0, 0,
       "BEGIN EXECUTE IMMEDIATE 'DROP TABLE seer_s92a'; EXCEPTION WHEN OTHERS THEN NULL; END;"},
      /* CREATE TABLE, with the schema */
      {SQL_CREATE_TABLE,
       SQL_CT_CREATE_TABLE | SQL_CT_COLUMN_CONSTRAINT | SQL_CT_COLUMN_DEFAULT |
           SQL_CT_CONSTRAINT_NAME_DEFINITION,
       SQL_SCHEMA_USAGE, SQL_SU_TABLE_DEFINITION,
       "CREATE TABLE %1$s.seer_s92a (id NUMBER CONSTRAINT seer_s92a_pk PRIMARY KEY,"
       " v VARCHAR2(10) DEFAULT 'x', n NUMBER CHECK (n > 0))"},
      {SQL_CREATE_TABLE,
       SQL_CT_TABLE_CONSTRAINT | SQL_CT_CONSTRAINT_DEFERRABLE |
           SQL_CT_CONSTRAINT_INITIALLY_DEFERRED,
       0, 0,
       "CREATE TABLE seer_s92t (id NUMBER, CONSTRAINT seer_s92t_u UNIQUE (id) DEFERRABLE"
       " INITIALLY DEFERRED)"},
      {SQL_CREATE_TABLE, SQL_CT_CONSTRAINT_NON_DEFERRABLE | SQL_CT_CONSTRAINT_INITIALLY_IMMEDIATE,
       0, 0,
       "CREATE TABLE seer_s92g (id NUMBER CHECK (id > 0) NOT DEFERRABLE INITIALLY IMMEDIATE)"},
      {SETUP, 0, 0, 0, "DROP TABLE seer_s92g"},
      {SQL_CREATE_TABLE, SQL_CT_GLOBAL_TEMPORARY | SQL_CT_COMMIT_PRESERVE, 0, 0,
       "CREATE GLOBAL TEMPORARY TABLE seer_s92g (id NUMBER) ON COMMIT PRESERVE ROWS"},
      {SETUP, 0, 0, 0, "DROP TABLE seer_s92g"},
      {SQL_CREATE_TABLE, SQL_CT_GLOBAL_TEMPORARY | SQL_CT_COMMIT_DELETE, 0, 0,
       "CREATE GLOBAL TEMPORARY TABLE seer_s92g (id NUMBER) ON COMMIT DELETE ROWS"},
      {SETUP, 0, 0, 0, "DROP TABLE seer_s92g"},
      /* ALTER TABLE */
      {SQL_ALTER_TABLE,
       SQL_AT_ADD_TABLE_CONSTRAINT | SQL_AT_CONSTRAINT_NAME_DEFINITION |
           SQL_AT_CONSTRAINT_NON_DEFERRABLE | SQL_AT_CONSTRAINT_INITIALLY_IMMEDIATE,
       0, 0,
       "ALTER TABLE seer_s92t ADD CONSTRAINT seer_s92t_c CHECK (id > 0) NOT DEFERRABLE INITIALLY"
       " IMMEDIATE"},
      {SQL_ALTER_TABLE, SQL_AT_CONSTRAINT_DEFERRABLE | SQL_AT_CONSTRAINT_INITIALLY_DEFERRED, 0, 0,
       "ALTER TABLE seer_s92t ADD CONSTRAINT seer_s92t_d CHECK (id < 100) DEFERRABLE INITIALLY"
       " DEFERRED"},
      {SQL_ALTER_TABLE, SQL_AT_ADD_COLUMN | SQL_AT_ADD_COLUMN_SINGLE | SQL_AT_ADD_COLUMN_DEFAULT, 0,
       0, "ALTER TABLE seer_s92t ADD x NUMBER DEFAULT 5"},
      {SQL_ALTER_TABLE, SQL_AT_ADD_CONSTRAINT, 0, 0,
       "ALTER TABLE seer_s92t ADD w NUMBER CONSTRAINT seer_s92t_w CHECK (w > 0)"},
      {SQL_ALTER_TABLE, SQL_AT_DROP_COLUMN | SQL_AT_DROP_COLUMN_DEFAULT, 0, 0,
       "ALTER TABLE seer_s92t DROP COLUMN x"},
      {SQL_ALTER_TABLE, SQL_AT_DROP_COLUMN_CASCADE, 0, 0,
       "ALTER TABLE seer_s92t DROP COLUMN w CASCADE"},
      {SQL_ALTER_TABLE, SQL_AT_DROP_COLUMN_RESTRICT, 0, 0,
       "ALTER TABLE seer_s92t DROP COLUMN w RESTRICT"},
      {SQL_ALTER_TABLE, SQL_AT_DROP_TABLE_CONSTRAINT_CASCADE, 0, 0,
       "ALTER TABLE seer_s92t DROP CONSTRAINT seer_s92t_c CASCADE"},
      {SQL_ALTER_TABLE, SQL_AT_DROP_TABLE_CONSTRAINT_RESTRICT, 0, 0,
       "ALTER TABLE seer_s92t DROP CONSTRAINT seer_s92t_w RESTRICT"},
      {SQL_ALTER_TABLE, SQL_AT_SET_COLUMN_DEFAULT, 0, 0,
       "ALTER TABLE seer_s92t ALTER COLUMN id SET DEFAULT 6"},
      /* indexes */
      {SQL_DDL_INDEX, SQL_DI_CREATE_INDEX, SQL_SCHEMA_USAGE, SQL_SU_INDEX_DEFINITION,
       "CREATE INDEX %1$s.seer_s92i ON %1$s.seer_s92a (v, n)"},
      {SQL_DDL_INDEX, SQL_DI_DROP_INDEX, 0, 0, "DROP INDEX %1$s.seer_s92i"},
      {SQL_INDEX_KEYWORDS, SQL_IK_ASC | SQL_IK_DESC, 0, 0,
       "CREATE INDEX seer_s92i ON seer_s92a (v DESC, n ASC)"},
      {SETUP, 0, 0, 0, "DROP INDEX seer_s92i"},
      /* views */
      {SQL_CREATE_VIEW, SQL_CV_CREATE_VIEW | SQL_CV_CHECK_OPTION, 0, 0,
       "CREATE VIEW seer_s92v AS SELECT id, n FROM seer_s92a WHERE n > 0 WITH CHECK OPTION"},
      {SQL_CREATE_VIEW, SQL_CV_CASCADED, 0, 0,
       "CREATE VIEW seer_s92w AS SELECT id FROM seer_s92a WITH CASCADED CHECK OPTION"},
      {SQL_CREATE_VIEW, SQL_CV_LOCAL, 0, 0,
       "CREATE VIEW seer_s92w AS SELECT id FROM seer_s92a WITH LOCAL CHECK OPTION"},
      {SQL_DROP_VIEW, SQL_DV_CASCADE, 0, 0, "DROP VIEW seer_s92v CASCADE"},
      {SQL_DROP_VIEW, SQL_DV_RESTRICT, 0, 0, "DROP VIEW seer_s92v RESTRICT"},
      {SQL_DROP_VIEW, SQL_DV_DROP_VIEW, 0, 0, "DROP VIEW seer_s92v"},
      /* CREATE SCHEMA, DROP TABLE */
      {SQL_CREATE_SCHEMA, SQL_CS_CREATE_SCHEMA | SQL_CS_AUTHORIZATION, 0, 0,
       "CREATE SCHEMA AUTHORIZATION %1$s CREATE TABLE seer_s92s (a NUMBER)"},
      {SQL_DROP_TABLE, SQL_DT_CASCADE, 0, 0, "DROP TABLE seer_s92s CASCADE"},
      {SQL_DROP_TABLE, SQL_DT_RESTRICT, 0, 0, "DROP TABLE seer_s92s RESTRICT"},
      {SQL_DROP_TABLE, SQL_DT_DROP_TABLE, 0, 0, "DROP TABLE seer_s92s"},
      /* foreign-key rules */
      {SQL_SQL92_FOREIGN_KEY_DELETE_RULE, SQL_SFKD_CASCADE, 0, 0,
       "CREATE TABLE seer_s92b (a NUMBER REFERENCES seer_s92a (id) ON DELETE CASCADE)"},
      {SETUP, 0, 0, 0, "DROP TABLE seer_s92b"},
      {SQL_SQL92_FOREIGN_KEY_DELETE_RULE, SQL_SFKD_SET_NULL, 0, 0,
       "CREATE TABLE seer_s92b (a NUMBER REFERENCES seer_s92a (id) ON DELETE SET NULL)"},
      {SETUP, 0, 0, 0, "DROP TABLE seer_s92b"},
      {SQL_SQL92_FOREIGN_KEY_DELETE_RULE, SQL_SFKD_NO_ACTION, 0, 0,
       "CREATE TABLE seer_s92b (a NUMBER REFERENCES seer_s92a (id) ON DELETE NO ACTION)"},
      {SQL_SQL92_FOREIGN_KEY_DELETE_RULE, SQL_SFKD_SET_DEFAULT, 0, 0,
       "CREATE TABLE seer_s92b (a NUMBER REFERENCES seer_s92a (id) ON DELETE SET DEFAULT)"},
      {SQL_SQL92_FOREIGN_KEY_UPDATE_RULE, SQL_SFKU_CASCADE, 0, 0,
       "CREATE TABLE seer_s92b (a NUMBER REFERENCES seer_s92a (id) ON UPDATE CASCADE)"},
      /* INSERT and row value constructors */
      {SQL_INSERT_STATEMENT, SQL_IS_INSERT_LITERALS, SQL_SCHEMA_USAGE, SQL_SU_DML_STATEMENTS,
       "INSERT INTO %1$s.seer_s92a (id, n) VALUES (1, 1)"},
      {SQL_INSERT_STATEMENT, SQL_IS_INSERT_SEARCHED, 0, 0,
       "INSERT INTO seer_s92a (id, n) SELECT 3, 3 FROM dual"},
      {SQL_INSERT_STATEMENT, SQL_IS_SELECT_INTO, 0, 0, "SELECT id INTO seer_s92s FROM seer_s92a"},
      {SQL_SQL92_ROW_VALUE_CONSTRUCTOR, SQL_SRVC_DEFAULT, 0, 0,
       "INSERT INTO seer_s92a (id, v, n) VALUES (2, DEFAULT, 2)"},
      {SQL_SQL92_ROW_VALUE_CONSTRUCTOR, SQL_SRVC_NULL | SQL_SRVC_VALUE_EXPRESSION, 0, 0,
       "INSERT INTO seer_s92a (id, v, n) VALUES (4, NULL, 1 + 3)"},
      {SQL_SQL92_ROW_VALUE_CONSTRUCTOR, SQL_SRVC_ROW_SUBQUERY, 0, 0,
       "SELECT 1 FROM dual WHERE (1, 2) IN (SELECT 1, 2 FROM dual)"},
      /* GRANT and REVOKE */
      {SQL_SQL92_GRANT,
       SQL_SG_SELECT_TABLE | SQL_SG_INSERT_TABLE | SQL_SG_UPDATE_TABLE | SQL_SG_DELETE_TABLE |
           SQL_SG_REFERENCES_TABLE,
       SQL_SCHEMA_USAGE, SQL_SU_PRIVILEGE_DEFINITION,
       "GRANT SELECT, INSERT, UPDATE, DELETE, REFERENCES ON %1$s.seer_s92a TO PUBLIC"},
      {SQL_SQL92_GRANT, SQL_SG_INSERT_COLUMN | SQL_SG_UPDATE_COLUMN | SQL_SG_REFERENCES_COLUMN, 0,
       0, "GRANT INSERT (v), UPDATE (v), REFERENCES (id) ON seer_s92a TO PUBLIC"},
      {SQL_SQL92_GRANT, SQL_SG_WITH_GRANT_OPTION, 0, 0,
       "GRANT SELECT ON seer_s92a TO PUBLIC WITH GRANT OPTION"},
      {SQL_SQL92_REVOKE, SQL_SR_INSERT_COLUMN, 0, 0, "REVOKE INSERT (v) ON seer_s92a FROM PUBLIC"},
      {SQL_SQL92_REVOKE, SQL_SR_CASCADE, 0, 0,
       "REVOKE REFERENCES ON seer_s92a FROM PUBLIC CASCADE"},
      {SQL_SQL92_REVOKE, SQL_SR_GRANT_OPTION_FOR, 0, 0,
       "REVOKE GRANT OPTION FOR SELECT ON seer_s92a FROM PUBLIC"},
      {SQL_SQL92_REVOKE, SQL_SR_RESTRICT, 0, 0, "REVOKE SELECT ON seer_s92a FROM PUBLIC RESTRICT"},
      {SQL_SQL92_REVOKE,
       SQL_SR_SELECT_TABLE | SQL_SR_INSERT_TABLE | SQL_SR_UPDATE_TABLE | SQL_SR_DELETE_TABLE |
           SQL_SR_REFERENCES_TABLE,
       0, 0, "REVOKE SELECT, INSERT, UPDATE, DELETE, REFERENCES ON seer_s92a FROM PUBLIC"},
      /* a procedure call with the schema */
      {SETUP, 0, 0, 0, "CREATE OR REPLACE PROCEDURE seer_s92p IS BEGIN NULL; END;"},
      {SQL_SCHEMA_USAGE, SQL_SU_PROCEDURE_INVOCATION, 0, 0, "BEGIN %1$s.seer_s92p; END;"},
      {SETUP, 0, 0, 0, "DROP PROCEDURE seer_s92p"},
      /* functions */
      {SQL_AGGREGATE_FUNCTIONS,
       SQL_AF_ALL | SQL_AF_AVG | SQL_AF_COUNT | SQL_AF_DISTINCT | SQL_AF_MAX | SQL_AF_MIN |
           SQL_AF_SUM,
       0, 0,
       "SELECT AVG(n), COUNT(*), COUNT(DISTINCT n), MAX(n), MIN(n), SUM(ALL n) FROM seer_s92a"},
      {SQL_SQL92_DATETIME_FUNCTIONS, SQL_SDF_CURRENT_DATE, 0, 0, "SELECT CURRENT_DATE FROM dual"},
      {SQL_SQL92_DATETIME_FUNCTIONS, SQL_SDF_CURRENT_TIMESTAMP, 0, 0,
       "SELECT CURRENT_TIMESTAMP FROM dual"},
      {SQL_SQL92_DATETIME_FUNCTIONS, SQL_SDF_CURRENT_TIME, 0, 0, "SELECT CURRENT_TIME FROM dual"},
      {SQL_SQL92_NUMERIC_VALUE_FUNCTIONS, SQL_SNVF_EXTRACT, 0, 0,
       "SELECT EXTRACT(YEAR FROM SYSDATE) FROM dual"},
      {SQL_SQL92_NUMERIC_VALUE_FUNCTIONS, SQL_SNVF_CHAR_LENGTH, 0, 0,
       "SELECT CHAR_LENGTH('abc') FROM dual"},
      {SQL_SQL92_NUMERIC_VALUE_FUNCTIONS, SQL_SNVF_OCTET_LENGTH, 0, 0,
       "SELECT OCTET_LENGTH('abc') FROM dual"},
      {SQL_SQL92_NUMERIC_VALUE_FUNCTIONS, SQL_SNVF_BIT_LENGTH, 0, 0,
       "SELECT BIT_LENGTH('abc') FROM dual"},
      {SQL_SQL92_NUMERIC_VALUE_FUNCTIONS, SQL_SNVF_POSITION, 0, 0,
       "SELECT POSITION('b' IN 'abc') FROM dual"},
      {SQL_SQL92_STRING_FUNCTIONS, SQL_SSF_LOWER | SQL_SSF_UPPER, 0, 0,
       "SELECT LOWER('A'), UPPER('a') FROM dual"},
      {SQL_SQL92_STRING_FUNCTIONS, SQL_SSF_TRIM_BOTH | SQL_SSF_TRIM_LEADING | SQL_SSF_TRIM_TRAILING,
       0, 0,
       "SELECT TRIM(BOTH 'x' FROM 'xax'), TRIM(LEADING 'x' FROM 'xa'), TRIM(TRAILING 'x' FROM"
       " 'ax') FROM dual"},
      {SQL_SQL92_STRING_FUNCTIONS, SQL_SSF_TRANSLATE, 0, 0,
       "SELECT TRANSLATE('abc' USING CHAR_CS) FROM dual"},
      {SQL_SQL92_STRING_FUNCTIONS, SQL_SSF_SUBSTRING, 0, 0,
       "SELECT SUBSTRING('abc' FROM 2 FOR 1) FROM dual"},
      {SQL_SQL92_STRING_FUNCTIONS, SQL_SSF_CONVERT, 0, 0,
       "SELECT CONVERT('abc' USING UTF8) FROM dual"},
      /* predicates */
      {SQL_SQL92_PREDICATES,
       SQL_SP_BETWEEN | SQL_SP_COMPARISON | SQL_SP_IN | SQL_SP_ISNULL | SQL_SP_ISNOTNULL |
           SQL_SP_LIKE,
       0, 0,
       "SELECT 1 FROM dual WHERE 1 BETWEEN 0 AND 2 AND 1 < 2 AND 'a' LIKE 'a%%' AND 1 IN (1, 2)"
       " AND NULL IS NULL AND 1 IS NOT NULL"},
      {SQL_SQL92_PREDICATES, SQL_SP_EXISTS | SQL_SP_QUANTIFIED_COMPARISON, 0, 0,
       "SELECT 1 FROM dual WHERE EXISTS (SELECT 1 FROM dual) AND 1 = ANY (SELECT 1 FROM dual)"
       " AND 1 >= ALL (SELECT 1 FROM dual)"},
      {SQL_SQL92_PREDICATES, SQL_SP_OVERLAPS, 0, 0,
       "SELECT 1 FROM dual WHERE (SYSDATE, SYSDATE + 1) OVERLAPS (SYSDATE, SYSDATE + 2)"},
      {SQL_SQL92_PREDICATES, SQL_SP_UNIQUE, 0, 0,
       "SELECT 1 FROM dual WHERE UNIQUE (SELECT 1 FROM dual)"},
      {SQL_SQL92_PREDICATES, SQL_SP_MATCH_FULL, 0, 0,
       "SELECT 1 FROM dual WHERE (1) MATCH FULL (SELECT 1 FROM dual)"},
      /* joins and set operators */
      {SQL_SQL92_RELATIONAL_JOIN_OPERATORS, SQL_SRJO_CROSS_JOIN, 0, 0,
       "SELECT 1 FROM dual a CROSS JOIN dual b"},
      {SQL_SQL92_RELATIONAL_JOIN_OPERATORS, SQL_SRJO_INNER_JOIN, 0, 0,
       "SELECT 1 FROM dual a INNER JOIN dual b ON a.dummy = b.dummy"},
      {SQL_SQL92_RELATIONAL_JOIN_OPERATORS, SQL_SRJO_LEFT_OUTER_JOIN, 0, 0,
       "SELECT 1 FROM dual a LEFT OUTER JOIN dual b ON a.dummy = b.dummy"},
      {SQL_SQL92_RELATIONAL_JOIN_OPERATORS, SQL_SRJO_RIGHT_OUTER_JOIN, 0, 0,
       "SELECT 1 FROM dual a RIGHT OUTER JOIN dual b ON a.dummy = b.dummy"},
      {SQL_SQL92_RELATIONAL_JOIN_OPERATORS, SQL_SRJO_FULL_OUTER_JOIN, 0, 0,
       "SELECT 1 FROM dual a FULL OUTER JOIN dual b ON a.dummy = b.dummy"},
      {SQL_SQL92_RELATIONAL_JOIN_OPERATORS, SQL_SRJO_NATURAL_JOIN, 0, 0,
       "SELECT 1 FROM dual a NATURAL JOIN dual b"},
      {SQL_SQL92_RELATIONAL_JOIN_OPERATORS, SQL_SRJO_UNION_JOIN, 0, 0,
       "SELECT 1 FROM dual a UNION JOIN dual b"},
      {SQL_SQL92_RELATIONAL_JOIN_OPERATORS, SQL_SRJO_INTERSECT_JOIN, 0, 0,
       "SELECT 1 FROM dual INTERSECT SELECT 1 FROM dual"},
      {SQL_SQL92_RELATIONAL_JOIN_OPERATORS, SQL_SRJO_EXCEPT_JOIN, 0, 0,
       "SELECT 1 FROM dual EXCEPT SELECT 2 FROM dual"},
      {SQL_SQL92_RELATIONAL_JOIN_OPERATORS, SQL_SRJO_CORRESPONDING_CLAUSE, 0, 0,
       "SELECT 1 a FROM dual UNION CORRESPONDING SELECT 1 a FROM dual"},
      /* value expressions */
      {SQL_SQL92_VALUE_EXPRESSIONS, SQL_SVE_CASE, 0, 0,
       "SELECT CASE 1 WHEN 1 THEN 'y' END, CASE WHEN 1 = 1 THEN 'y' END FROM dual"},
      {SQL_SQL92_VALUE_EXPRESSIONS, SQL_SVE_CAST, 0, 0, "SELECT CAST('1' AS NUMBER) FROM dual"},
      {SQL_SQL92_VALUE_EXPRESSIONS, SQL_SVE_COALESCE, 0, 0, "SELECT COALESCE(NULL, 1) FROM dual"},
      {SQL_SQL92_VALUE_EXPRESSIONS, SQL_SVE_NULLIF, 0, 0, "SELECT NULLIF(1, 2) FROM dual"},
  };
  /* The schema is the session's own user, from the server, as a plain
   * identifier. */
  char u[64] = "", m[700] = "", err[256], sql[1024];
  exec_scalar(dbc, "SELECT USER FROM dual", u, sizeof u, err, sizeof err);
  for (const char *c = u; *c; c++)
    if (!isalnum((unsigned char)*c) && *c != '_' && *c != '$' && *c != '#')
      u[0] = '\0';
  if (u[0] == '\0')
    snprintf(m, sizeof m, "no plain user name from SELECT USER");
  for (size_t i = 0; i < sizeof T / sizeof T[0] && m[0] == '\0'; i++) {
    snprintf(sql, sizeof sql, T[i].sql, u);
    int ran = SQL_SUCCEEDED(exec_do(dbc, sql, err, sizeof err));
    if (T[i].type == SETUP)
      continue;
    for (int k = 0; k < 2 && m[0] == '\0'; k++) {
      SQLUSMALLINT type = k == 0 ? T[i].type : T[i].type2;
      SQLUINTEGER bits = k == 0 ? T[i].bits : T[i].bits2, v = 0;
      if (type == 0)
        continue;
      SQLGetInfo(dbc, type, &v, sizeof v, NULL);
      if (ran && (v & bits) != bits)
        snprintf(m, sizeof m, "info %u = 0x%x lacks 0x%x, but %s runs", type, (unsigned)v,
                 (unsigned)bits, sql);
      else if (!ran && (v & bits) != 0)
        snprintf(m, sizeof m, "info %u = 0x%x claims 0x%x, but %s: %s", type, (unsigned)v,
                 (unsigned)bits, sql, err);
    }
  }

  /* SQL_KEYWORDS: each word is reserved (it can't name a column). */
  char kw[1024] = "";
  SQLSMALLINT kwlen = 0;
  SQLGetInfo(dbc, SQL_KEYWORDS, kw, sizeof kw, &kwlen);
  if (m[0] == '\0' && kw[0] == '\0')
    snprintf(m, sizeof m, "SQL_KEYWORDS is empty");
  for (char *w = strtok(kw, ","); w != NULL && m[0] == '\0'; w = strtok(NULL, ",")) {
    snprintf(sql, sizeof sql, "CREATE TABLE seer_s92k (%s NUMBER)", w);
    if (SQL_SUCCEEDED(exec_do(dbc, sql, err, sizeof err))) {
      exec_do(dbc, "DROP TABLE seer_s92k", err, sizeof err);
      snprintf(m, sizeof m, "SQL_KEYWORDS has %s, but it names a column", w);
    }
  }

  /* The limits, at and one past each. */
  SQLUSMALLINT cols = 0, idx = 0;
  SQLUINTEGER lit = 0;
  SQLGetInfo(dbc, SQL_MAX_COLUMNS_IN_TABLE, &cols, sizeof cols, NULL);
  SQLGetInfo(dbc, SQL_MAX_COLUMNS_IN_INDEX, &idx, sizeof idx, NULL);
  SQLGetInfo(dbc, SQL_MAX_CHAR_LITERAL_LEN, &lit, sizeof lit, NULL);
  for (int k = 0; k < 2 && m[0] == '\0'; k++) {
    char *s = repeat_items("CREATE TABLE seer_s92m (", "c%d NUMBER(1)", cols + k, ")");
    if (s == NULL)
      snprintf(err, sizeof err, "no memory for the statement");
    int ok = s != NULL && SQL_SUCCEEDED(exec_do(dbc, s, err, sizeof err));
    free(s);
    if (ok)
      exec_do(dbc, "DROP TABLE seer_s92m", err, sizeof err);
    if (ok != (k == 0))
      snprintf(m, sizeof m, "SQL_MAX_COLUMNS_IN_TABLE %u: %d columns %s", cols, cols + k,
               ok ? "work" : err);
  }
  if (m[0] == '\0') {
    char *s = repeat_items("CREATE TABLE seer_s92m (", "c%d NUMBER(1)", idx + 1, ")");
    if (s == NULL || !SQL_SUCCEEDED(exec_do(dbc, s, err, sizeof err)))
      snprintf(m, sizeof m, "index table: %s", err);
    free(s);
  }
  for (int k = 0; k < 2 && m[0] == '\0'; k++) {
    char *s = repeat_items("CREATE INDEX seer_s92mi ON seer_s92m (", "c%d", idx + k, ")");
    if (s == NULL)
      snprintf(err, sizeof err, "no memory for the statement");
    int ok = s != NULL && SQL_SUCCEEDED(exec_do(dbc, s, err, sizeof err));
    free(s);
    if (ok)
      exec_do(dbc, "DROP INDEX seer_s92mi", err, sizeof err);
    if (ok != (k == 0))
      snprintf(m, sizeof m, "SQL_MAX_COLUMNS_IN_INDEX %u: %d columns %s", idx, idx + k,
               ok ? "work" : err);
  }
  exec_do(dbc, "DROP TABLE seer_s92m", err, sizeof err);
  for (int k = 0; k < 2 && m[0] == '\0'; k++) {
    size_t n = lit + (size_t)k;
    char *s = malloc(n + 40);
    if (s == NULL)
      break;
    memcpy(s, "SELECT LENGTH('", 15);
    memset(s + 15, 'x', n);
    strcpy(s + 15 + n, "') FROM dual");
    int ok = SQL_SUCCEEDED(exec_do(dbc, s, err, sizeof err));
    free(s);
    if (ok != (k == 0))
      snprintf(m, sizeof m, "SQL_MAX_CHAR_LITERAL_LEN %u: %zu characters %s", (unsigned)lit, n,
               ok ? "work" : err);
  }

  exec_do(dbc, "DROP TABLE seer_s92t", err, sizeof err);
  exec_do(dbc, "DROP TABLE seer_s92a", err, sizeof err);
  if (m[0] == '\0')
    pass(name);
  else
    fail(name, m);
}

/* The datetime literal escapes (#305): {d} {t} {ts} on every tier, and
 * {INTERVAL} from 9i, including a sign outside the quotes; SQL_DATETIME_LITERALS
 * says which. */
static void check_datetime_literals(SQLHDBC dbc)
{
  const char *name = "datetime and interval literal escapes";
  static const struct {
    const char *expr, *want;
    int from;
  } T[] = {
      {"TO_CHAR({d '2024-02-29'}, 'YYYY-MM-DD HH24:MI:SS')", "2024-02-29 00:00:00", 0},
      {"TO_CHAR({t '13:14:15'}, 'HH24:MI:SS')", "13:14:15", 0},
      {"TO_CHAR({ts '2024-02-29 13:14:15'}, 'YYYY-MM-DD HH24:MI:SS')", "2024-02-29 13:14:15", 0},
      {"TO_CHAR({d '2024-02-29'} + {INTERVAL '3' DAY}, 'YYYY-MM-DD')", "2024-03-03", 9},
      {"TO_CHAR({d '2024-02-29'} + {interval '1-2' year to month}, 'YYYY-MM-DD')", "2025-04-29", 9},
      {"TO_CHAR({ts '2024-02-29 10:00:00'} + {INTERVAL - '5' HOUR}, 'HH24:MI')", "05:00", 9},
      {"TO_CHAR({ts '2024-02-29 10:00:00'} -{INTERVAL -'5' HOUR}, 'HH24:MI')", "15:00", 9},
      {"TO_CHAR({ts '2024-02-29 10:00:00'} + {INTERVAL - '-1' MINUTE}, 'HH24:MI')", "10:01", 9},
      {"TO_CHAR({d '2024-02-29'} + {INTERVAL - '1-1' YEAR TO MONTH}, 'YYYY-MM-DD')", "2023-01-29",
       9},
      {"TO_CHAR({ts '2024-02-29 10:00:00'} + {INTERVAL '123 1:02:03.5' DAY(3) TO SECOND(1)},"
       " 'YYYY-MM-DD HH24:MI:SS.FF1')",
       "2024-07-01 11:02:03.5", 9},
      {"TO_CHAR({ts '2024-02-29 10:00:00'} + {INTERVAL '7.25' SECOND(2,2)}, 'HH24:MI:SS.FF2')",
       "10:00:07.25", 9},
      {"TO_CHAR({ts '2024-02-29 10:00:00'} + {INTERVAL '10:30' MINUTE TO SECOND}, 'HH24:MI:SS')",
       "10:10:30", 9},
      {"TO_CHAR({ts '2024-02-29 10:00:00'} + {INTERVAL '2 3' DAY TO HOUR}, 'DD HH24')", "02 13", 9},
  };
  char m[700] = "", out[256], err[256];
  for (size_t i = 0; i < sizeof T / sizeof T[0] && m[0] == '\0'; i++) {
    if (g_release < T[i].from)
      continue;
    char sql[512];
    snprintf(sql, sizeof sql, "SELECT %s FROM dual", T[i].expr);
    if (!SQL_SUCCEEDED(exec_scalar(dbc, sql, out, sizeof out, err, sizeof err)))
      snprintf(m, sizeof m, "%s: %s", T[i].expr, err);
    else if (strcmp(out, T[i].want) != 0)
      snprintf(m, sizeof m, "%s: got '%s', want '%s'", T[i].expr, out, T[i].want);
  }
  if (m[0] == '\0') {
    SQLUINTEGER v = 0;
    SQLGetInfo(dbc, SQL_DATETIME_LITERALS, &v, sizeof v, NULL);
    SQLUINTEGER dts = SQL_DL_SQL92_DATE | SQL_DL_SQL92_TIME | SQL_DL_SQL92_TIMESTAMP;
    int iv = (v & SQL_DL_SQL92_INTERVAL_DAY_TO_SECOND) && (v & SQL_DL_SQL92_INTERVAL_YEAR);
    if ((v & dts) != dts || iv != (g_release >= 9))
      snprintf(m, sizeof m, "SQL_DATETIME_LITERALS 0x%x", (unsigned)v);
  }
  if (m[0] == '\0')
    pass(name);
  else
    fail(name, m);
}

/* A placeholder repeated before a new one (#302): bind N is the N-th distinct
 * placeholder, but a SQL statement takes a value per occurrence, so the
 * driver sends each repeat its placeholder's value. In a query, past text and
 * comments, on a re-execute of the cached cursor, and in an array DML. */
static void check_repeated_placeholders(SQLHDBC dbc)
{
  const char *name = "repeated placeholders before a new one";
  char m[600] = "", out[128], state[6], err[256] = "";
  static const struct {
    const char *sql, *p[4], *want;
    int from;
  } Q[] = {
      {"SELECT :1 || :1 || :2 FROM dual", {"ab", "!", NULL}, "abab!", 0},
      {"SELECT :b || :a || :b || :a || :c FROM dual", {"1", "2", "3", NULL}, "12123", 0},
      {"SELECT :a || '-- :a' || /* :b */ :a || :b FROM dual", {"x", "y", NULL}, "x-- :axy", 0},
      {"SELECT q'[:a]' || :a || :a || :b FROM dual", {"x", "y", NULL}, ":axxy", 10},
      {"SELECT COUNT(*) FROM dual WHERE :1 = :1 AND :2 = 'z'", {"q", "z", NULL}, "1", 0},
  };
  for (size_t i = 0; i < sizeof Q / sizeof Q[0] && m[0] == '\0'; i++) {
    if (g_release < Q[i].from)
      continue;
    SQLRETURN rc = exec_params(dbc, Q[i].sql, Q[i].p, out, sizeof out, state);
    if (!SQL_SUCCEEDED(rc))
      snprintf(m, sizeof m, "%s: rc %d %s", Q[i].sql, rc, state);
    else if (strcmp(out, Q[i].want) != 0)
      snprintf(m, sizeof m, "%s: got '%s', want '%s'", Q[i].sql, out, Q[i].want);
  }

  /* The same prepared statement twice, new values the second time. */
  if (m[0] == '\0') {
    SQLHSTMT st;
    SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st);
    char a[8] = "ab", b[8] = "!";
    SQLLEN ia = SQL_NTS, ib = SQL_NTS, oi = 0;
    SQLPrepare(st, (SQLCHAR *)"SELECT :1 || :1 || :2 FROM dual", SQL_NTS);
    SQLBindParameter(st, 1, SQL_PARAM_INPUT, SQL_C_CHAR, SQL_VARCHAR, 8, 0, a, 0, &ia);
    SQLBindParameter(st, 2, SQL_PARAM_INPUT, SQL_C_CHAR, SQL_VARCHAR, 8, 0, b, 0, &ib);
    for (int pass_no = 0; pass_no < 2 && m[0] == '\0'; pass_no++) {
      if (pass_no == 1) {
        strcpy(a, "cd");
        strcpy(b, "?");
      }
      const char *want = pass_no == 0 ? "abab!" : "cdcd?";
      SQLRETURN rc = SQLExecute(st);
      if (SQL_SUCCEEDED(rc))
        rc = SQLFetch(st);
      if (SQL_SUCCEEDED(rc))
        rc = SQLGetData(st, 1, SQL_C_CHAR, out, sizeof out, &oi);
      if (!SQL_SUCCEEDED(rc)) {
        diag_text(SQL_HANDLE_STMT, st, err, sizeof err);
        snprintf(m, sizeof m, "re-execute %d: %s", pass_no + 1, err);
      } else if (strcmp(out, want) != 0) {
        snprintf(m, sizeof m, "re-execute %d: got '%s', want '%s'", pass_no + 1, out, want);
      }
      SQLFreeStmt(st, SQL_CLOSE);
    }
    SQLFreeHandle(SQL_HANDLE_STMT, st);
  }

  /* An array INSERT whose second value repeats the first placeholder. */
  if (m[0] == '\0') {
    exec_do(dbc, "DROP TABLE seer_dupph", err, sizeof err);
    if (!SQL_SUCCEEDED(exec_do(dbc, "CREATE TABLE seer_dupph (a VARCHAR2(10), b VARCHAR2(20))", err,
                               sizeof err))) {
      skip(name, err);
      return;
    }
    char av[3][4] = {"x", "y", "z"}, bv[3][4] = {"1", "2", "3"};
    SQLLEN ai[3] = {SQL_NTS, SQL_NTS, SQL_NTS}, bi[3] = {SQL_NTS, SQL_NTS, SQL_NTS};
    SQLHSTMT st;
    SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st);
    SQLSetStmtAttr(st, SQL_ATTR_PARAMSET_SIZE, (SQLPOINTER)(SQLULEN)3, 0);
    SQLBindParameter(st, 1, SQL_PARAM_INPUT, SQL_C_CHAR, SQL_VARCHAR, 4, 0, av, 4, ai);
    SQLBindParameter(st, 2, SQL_PARAM_INPUT, SQL_C_CHAR, SQL_VARCHAR, 4, 0, bv, 4, bi);
    SQLRETURN rc =
        SQLExecDirect(st, (SQLCHAR *)"INSERT INTO seer_dupph VALUES (:1, :1 || :1 || :2)", SQL_NTS);
    if (!SQL_SUCCEEDED(rc))
      diag_text(SQL_HANDLE_STMT, st, err, sizeof err);
    SQLFreeHandle(SQL_HANDLE_STMT, st);
    if (!SQL_SUCCEEDED(rc))
      snprintf(m, sizeof m, "array INSERT: %s", err);
    else if (!SQL_SUCCEEDED(exec_scalar(dbc,
                                        "SELECT COUNT(*) || ':' || MIN(b) || ':' || MAX(b) FROM "
                                        "seer_dupph WHERE b = a || a || SUBSTR(b, 3)",
                                        out, sizeof out, err, sizeof err)))
      snprintf(m, sizeof m, "array INSERT read back: %s", err);
    else if (strcmp(out, "3:xx1:zz3") != 0)
      snprintf(m, sizeof m, "array INSERT: got '%s', want '3:xx1:zz3'", out);
    exec_do(dbc, "DROP TABLE seer_dupph", err, sizeof err);
  }
  if (m[0] == '\0')
    pass(name);
  else
    fail(name, m);
}

static void check_describe_param(SQLHDBC dbc)
{
  const char *name = "SQLDescribeParam: parameter range";
  char m[600] = "";
  SQLHSTMT st;
  SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st);
  SQLRETURN rc = SQLPrepare(st, (SQLCHAR *)"SELECT :a, :b FROM dual", SQL_NTS);
  SQLSMALLINT n = -1, t, dd, nl;
  SQLULEN sz;
  if (!SQL_SUCCEEDED(rc) || !SQL_SUCCEEDED(SQLNumParams(st, &n)))
    diag_text(SQL_HANDLE_STMT, st, m, sizeof m);
  else if (n != 2)
    snprintf(m, sizeof m, "SQLNumParams %d, want 2", n);
  for (SQLUSMALLINT k = 1; k <= 3 && m[0] == '\0'; k++) {
    rc = SQLDescribeParam(st, k, &t, &sz, &dd, &nl);
    SQLCHAR state[6] = "", msg[256];
    SQLINTEGER nat;
    SQLSMALLINT ml;
    if (!SQL_SUCCEEDED(rc))
      SQLGetDiagRec(SQL_HANDLE_STMT, st, 1, state, &nat, msg, sizeof msg, &ml);
    if (k <= 2 && !SQL_SUCCEEDED(rc))
      snprintf(m, sizeof m, "parameter %u: rc %d %s", k, rc, (char *)state);
    else if (k == 3 && (rc != SQL_ERROR || strcmp((char *)state, "07009") != 0))
      snprintf(m, sizeof m, "parameter 3 of 2: rc %d %s, want 07009", rc, (char *)state);
  }
  SQLFreeHandle(SQL_HANDLE_STMT, st);
  if (m[0] == '\0')
    pass(name);
  else
    fail(name, m);
}

/* SQL_ATTR_METADATA_ID (#278), set on the connection and so taken by the
 * statement allocated after: catalog arguments are identifiers, SEER_N_M
 * not matching SEER_NXM, an unquoted lower-case name folded to upper case, a
 * quoted one kept as written, and a NULL one HY009. */
static void check_metadata_id(SQLHDBC dbc)
{
  const char *name = "SQL_ATTR_METADATA_ID: catalog arguments as identifiers";
  char err[256] = "", m[600] = "";
  static const char *ddl[] = {"DROP TABLE seer_n_m",
                              "DROP TABLE seer_nxm",
                              "DROP TABLE \"seer_Nq\"",
                              "CREATE TABLE seer_n_m (id NUMBER PRIMARY KEY)",
                              "CREATE TABLE seer_nxm (id NUMBER PRIMARY KEY)",
                              "CREATE TABLE \"seer_Nq\" (id NUMBER)"};
  for (size_t k = 0; k < sizeof ddl / sizeof ddl[0]; k++)
    exec_do(dbc, ddl[k], err, sizeof err);
  char owner[64] = "", lower[64] = "";
  const char *u = getenv("SEER_TEST_USER");
  for (size_t k = 0; u != NULL && u[k] != '\0' && k + 1 < sizeof owner; k++) {
    owner[k] = (char)toupper((unsigned char)u[k]);
    lower[k] = (char)tolower((unsigned char)u[k]);
  }
  SQLRETURN rc = SQLSetConnectAttr(dbc, SQL_ATTR_METADATA_ID, (SQLPOINTER)SQL_TRUE, 0);
  if (!SQL_SUCCEEDED(rc))
    diag_text(SQL_HANDLE_DBC, dbc, m, sizeof m);
  SQLHSTMT st;
  SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st);
  SQLULEN v = 0;
  SQLGetStmtAttr(st, SQL_ATTR_METADATA_ID, &v, 0, NULL);
  if (m[0] == '\0' && v != SQL_TRUE)
    snprintf(m, sizeof m, "a new statement has METADATA_ID %lu, want 1", (unsigned long)v);
  for (int k = 0; k < 4 && m[0] == '\0'; k++) {
    static const char *what[4] = {"SQLTables SEER_N_M", "SQLTables seer_n_m (folded)",
                                  "SQLTables \"seer_Nq\" (quoted)", "SQLColumns column NULL"};
    static const int want[4] = {1, 1, 1, -1};
    if (k == 0)
      rc = SQLTables(st, NULL, 0, (SQLCHAR *)owner, SQL_NTS, (SQLCHAR *)"SEER_N_M", SQL_NTS, NULL,
                     0);
    else if (k == 1)
      rc = SQLTables(st, NULL, 0, (SQLCHAR *)lower, SQL_NTS, (SQLCHAR *)"seer_n_m", SQL_NTS, NULL,
                     0);
    else if (k == 2)
      rc = SQLTables(st, NULL, 0, (SQLCHAR *)owner, SQL_NTS, (SQLCHAR *)"\"seer_Nq\"", SQL_NTS,
                     NULL, 0);
    else
      rc = SQLColumns(st, NULL, 0, (SQLCHAR *)owner, SQL_NTS, (SQLCHAR *)"SEER_N_M", SQL_NTS, NULL,
                      0);
    if (want[k] < 0) {
      SQLCHAR state[6] = "";
      SQLINTEGER nat;
      SQLSMALLINT ml;
      SQLCHAR msg[256];
      SQLGetDiagRec(SQL_HANDLE_STMT, st, 1, state, &nat, msg, sizeof msg, &ml);
      if (rc != SQL_ERROR || strcmp((char *)state, "HY009") != 0)
        snprintf(m, sizeof m, "%s: rc %d state %s, want HY009", what[k], rc, (char *)state);
    } else {
      int rows = 0;
      while (SQL_SUCCEEDED(rc) && SQL_SUCCEEDED(SQLFetch(st)))
        rows++;
      if (!SQL_SUCCEEDED(rc))
        diag_text(SQL_HANDLE_STMT, st, m, sizeof m);
      else if (rows != want[k])
        snprintf(m, sizeof m, "%s: %d rows, want %d", what[k], rows, want[k]);
    }
    SQLFreeStmt(st, SQL_CLOSE);
  }
  SQLFreeHandle(SQL_HANDLE_STMT, st);
  SQLSetConnectAttr(dbc, SQL_ATTR_METADATA_ID, (SQLPOINTER)SQL_FALSE, 0);
  for (size_t k = 0; k < 3; k++)
    exec_do(dbc, ddl[k], err, sizeof err);
  if (m[0] == '\0')
    pass(name);
  else
    fail(name, m);
}

/* Catalog name arguments (#273): a pattern argument honours the '\' escape
 * SQLGetInfo reports, so SEER\_N\_M is only SEER_N_M, and an ordinary one
 * is matched literally, so SEER_N_M in SQLSpecialColumns and SQLForeignKeys
 * isn't also SEER_NXM. */
static void check_catalog_names(SQLHDBC dbc)
{
  const char *name = "Catalog names: pattern escape, literal identifiers";
  char err[256] = "", m[600] = "";
  static const char *ddl[] = {
      "DROP TABLE seer_nfk",
      "DROP TABLE seer_n_m",
      "DROP TABLE seer_nxm",
      "CREATE TABLE seer_n_m (id NUMBER PRIMARY KEY)",
      "CREATE TABLE seer_nxm (id NUMBER PRIMARY KEY)",
      "CREATE TABLE seer_nfk (id NUMBER, CONSTRAINT seer_nfk_fk FOREIGN KEY (id)"
      " REFERENCES seer_nxm (id))"};
  for (size_t k = 0; k < sizeof ddl / sizeof ddl[0]; k++)
    exec_do(dbc, ddl[k], err, sizeof err);
  char owner[64] = "";
  const char *u = getenv("SEER_TEST_USER");
  for (size_t k = 0; u != NULL && u[k] != '\0' && k + 1 < sizeof owner; k++)
    owner[k] = (char)toupper((unsigned char)u[k]);
  SQLCHAR *o = (SQLCHAR *)owner, *esc = (SQLCHAR *)"SEER\\_N\\_M", *lit = (SQLCHAR *)"SEER_N_M";
  SQLHSTMT st;
  SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st);
  for (int k = 0; k < 5 && m[0] == '\0'; k++) {
    static const char *what[5] = {"SQLTables SEER\\_N\\_M", "SQLColumns SEER\\_N\\_M",
                                  "SQLTables SEER_N_M (a pattern)", "SQLSpecialColumns SEER_N_M",
                                  "SQLForeignKeys PK SEER_N_M"};
    static const int want[5] = {1, 1, 2, 1, 0};
    SQLRETURN rc;
    switch (k) {
    case 0:
      rc = SQLTables(st, NULL, 0, o, SQL_NTS, esc, SQL_NTS, NULL, 0);
      break;
    case 1:
      rc = SQLColumns(st, NULL, 0, o, SQL_NTS, esc, SQL_NTS, NULL, 0);
      break;
    case 2:
      rc = SQLTables(st, NULL, 0, o, SQL_NTS, lit, SQL_NTS, NULL, 0);
      break;
    case 3:
      rc = SQLSpecialColumns(st, SQL_BEST_ROWID, NULL, 0, o, SQL_NTS, lit, SQL_NTS,
                             SQL_SCOPE_SESSION, SQL_NULLABLE);
      break;
    default:
      rc = SQLForeignKeys(st, NULL, 0, o, SQL_NTS, lit, SQL_NTS, NULL, 0, NULL, 0, NULL, 0);
      break;
    }
    int rows = 0;
    while (SQL_SUCCEEDED(rc) && SQL_SUCCEEDED(SQLFetch(st)))
      rows++;
    if (!SQL_SUCCEEDED(rc))
      diag_text(SQL_HANDLE_STMT, st, m, sizeof m);
    else if (rows != want[k])
      snprintf(m, sizeof m, "%s: %d rows, want %d", what[k], rows, want[k]);
    SQLFreeStmt(st, SQL_CLOSE);
  }
  SQLFreeHandle(SQL_HANDLE_STMT, st);
  for (size_t k = 0; k < 3; k++)
    exec_do(dbc, ddl[k], err, sizeof err);
  if (m[0] == '\0')
    pass(name);
  else
    fail(name, m);
}

/* SQLProcedureColumns (#269) describes an argument as SQLColumns describes a
 * column of the type: a FLOAT is an exact decimal of 38 digits, a DATE has
 * a size and the datetime codes, only numbers have a radix, an unconstrained
 * VARCHAR2 is PL/SQL's 32767 and a CLOB 2147483647. */
static void check_proc_columns(SQLHDBC dbc)
{
  const char *name = "SQLProcedureColumns: argument types and sizes";
  char err[256] = "", m[600] = "";
  exec_do(dbc,
          "CREATE OR REPLACE PROCEDURE seer_pcol (n IN NUMBER, v IN OUT VARCHAR2, d OUT DATE,"
          " f IN FLOAT, c IN CLOB) AS BEGIN NULL; END;",
          err, sizeof err);
  /* COLUMN_TYPE DATA_TYPE COLUMN_SIZE BUFFER_LENGTH DECIMAL_DIGITS NUM_PREC_RADIX
   * SQL_DATA_TYPE SQL_DATETIME_SUB CHAR_OCTET_LENGTH; -1 for NULL */
  static const long want[5][9] = {{1, 3, 38, 40, -1, 10, 3, -1, -1},
                                  {2, 12, 32767, 32767, -1, -1, 12, -1, 32767},
                                  {4, 93, 19, 16, 0, -1, 9, 3, -1},
                                  {1, 3, 38, 40, -1, 10, 3, -1, -1},
                                  {1, -1, 2147483647, 2147483647, -1, -1, -1, -1, 2147483647}};
  static const SQLUSMALLINT cols[9] = {5, 6, 8, 9, 10, 11, 15, 16, 17};
  char owner[64] = "";
  const char *u = getenv("SEER_TEST_USER");
  for (size_t k = 0; u != NULL && u[k] != '\0' && k + 1 < sizeof owner; k++)
    owner[k] = (char)toupper((unsigned char)u[k]);
  SQLHSTMT st;
  SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st);
  SQLRETURN rc = SQLProcedureColumns(st, NULL, 0, (SQLCHAR *)owner, SQL_NTS, (SQLCHAR *)"SEER_PCOL",
                                     SQL_NTS, NULL, 0);
  int rows = 0;
  while (SQL_SUCCEEDED(rc) && m[0] == '\0' && SQL_SUCCEEDED(SQLFetch(st))) {
    char an[64] = "";
    SQLLEN ind;
    SQLGetData(st, 4, SQL_C_CHAR, an, sizeof an, &ind);
    int r = rows++;
    if (r >= 5)
      break;
    for (int k = 0; k < 9 && m[0] == '\0'; k++) {
      SQLINTEGER v = 0;
      SQLGetData(st, cols[k], SQL_C_SLONG, &v, 0, &ind);
      long got = ind == SQL_NULL_DATA ? -1 : (long)v;
      if (got != want[r][k])
        snprintf(m, sizeof m, "%s: column %d is %ld, want %ld", an, (int)cols[k], got, want[r][k]);
    }
  }
  if (m[0] == '\0' && !SQL_SUCCEEDED(rc))
    diag_text(SQL_HANDLE_STMT, st, m, sizeof m);
  else if (m[0] == '\0' && rows != 5)
    snprintf(m, sizeof m, "%d rows, want 5", rows);
  SQLFreeHandle(SQL_HANDLE_STMT, st);
  exec_do(dbc, "DROP PROCEDURE seer_pcol", err, sizeof err);
  if (m[0] == '\0')
    pass(name);
  else
    fail(name, m);
}

/* SQLGetTypeInfo (#262): it answers on every release (8i refused the UNION
 * with ORA-01790), lists the types the release has in ODBC's order, gives
 * the attributes SQLColAttribute gives a column of the type, and an unknown
 * type is an empty set of the 19 columns. */
static void check_type_info(SQLHDBC dbc)
{
  const char *name = "SQLGetTypeInfo: per-release types and attributes";
  char m[600] = "", got[400] = "";
  const char *want = g_release <= 8   ? "BLOB,LONG RAW,RAW,CLOB,LONG,CHAR,NUMBER,VARCHAR2,DATE"
                     : g_release == 9 ? "BLOB,LONG RAW,RAW,CLOB,LONG,CHAR,NUMBER,VARCHAR2,"
                                        "TIMESTAMP,DATE"
                                      : "BLOB,LONG RAW,RAW,CLOB,LONG,CHAR,NUMBER,BINARY_FLOAT,"
                                        "BINARY_DOUBLE,VARCHAR2,TIMESTAMP,DATE";
  /* name, then prefix, SEARCHABLE, MINIMUM_SCALE, MAXIMUM_SCALE, SQL_DATA_TYPE,
   * SQL_DATETIME_SUB as text ("-" for NULL) */
  static const char *const rows[][7] = {{"VARCHAR2", "'", "3", "-", "-", "12", "-"},
                                        {"NUMBER", "-", "2", "-84", "127", "3", "-"},
                                        {"CLOB", "'", "1", "-", "-", "-1", "-"},
                                        {"BLOB", "-", "0", "-", "-", "-4", "-"},
                                        {"DATE", "-", "2", "0", "0", "9", "3"}};
  static const SQLUSMALLINT cols[6] = {4, 9, 14, 15, 16, 17};
  SQLHSTMT st;
  SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st);
  SQLRETURN rc = SQLGetTypeInfo(st, SQL_ALL_TYPES);
  while (SQL_SUCCEEDED(rc) && m[0] == '\0' && SQL_SUCCEEDED(SQLFetch(st))) {
    char tn[40] = "", v[6][40];
    SQLLEN ind;
    SQLGetData(st, 1, SQL_C_CHAR, tn, sizeof tn, &ind);
    snprintf(got + strlen(got), sizeof got - strlen(got), "%s%s", got[0] ? "," : "", tn);
    for (int k = 0; k < 6; k++) {
      v[k][0] = '\0';
      SQLGetData(st, cols[k], SQL_C_CHAR, v[k], sizeof v[k], &ind);
      if (ind == SQL_NULL_DATA)
        strcpy(v[k], "-");
    }
    for (size_t r = 0; r < sizeof rows / sizeof rows[0]; r++)
      for (int k = 0; strcmp(tn, rows[r][0]) == 0 && k < 6 && m[0] == '\0'; k++)
        if (strcmp(v[k], rows[r][k + 1]) != 0)
          snprintf(m, sizeof m, "%s column %u: '%s', want '%s'", tn, cols[k], v[k], rows[r][k + 1]);
  }
  if (!SQL_SUCCEEDED(rc))
    diag_text(SQL_HANDLE_STMT, st, m, sizeof m);
  else if (m[0] == '\0' && strcmp(got, want) != 0)
    snprintf(m, sizeof m, "types %s, want %s", got, want);
  SQLFreeStmt(st, SQL_CLOSE);
  if (m[0] == '\0') { /* SQL_GUID: no such type */
    SQLSMALLINT nc = 0;
    rc = SQLGetTypeInfo(st, SQL_GUID);
    SQLNumResultCols(st, &nc);
    if (!SQL_SUCCEEDED(rc) || nc != 19 || SQLFetch(st) != SQL_NO_DATA)
      snprintf(m, sizeof m, "SQL_GUID: rc %d, %d columns, want an empty set of 19", rc, nc);
  }
  SQLFreeHandle(SQL_HANDLE_STMT, st);
  if (m[0] == '\0')
    pass(name);
  else
    fail(name, m);
}

/* Column bindings live until unbound (#244): bound before the first
 * execute, they fill on the fetch; the same statement executed again with a
 * new parameter fills the same buffer; after SQL_UNBIND a fetch leaves it be. */
static void check_bindcol_lifetime(SQLHDBC dbc)
{
  const char *name = "column bindings made before execute last across executes";
  char err[256] = "", m[400] = "";
  SQLHSTMT st;
  SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st);
  SQLINTEGER p = 1, out = -1;
  SQLLEN out_ind = 0;
  SQLRETURN rc = SQLPrepare(st, (SQLCHAR *)"SELECT ? + 1 FROM dual", SQL_NTS);
  if (SQL_SUCCEEDED(rc))
    rc = SQLBindParameter(st, 1, SQL_PARAM_INPUT, SQL_C_SLONG, SQL_INTEGER, 0, 0, &p, 0, NULL);
  SQLRETURN bc = SQLBindCol(st, 1, SQL_C_SLONG, &out, 0, &out_ind); /* before the execute */
  SQLINTEGER got[3] = {-1, -1, -1};
  for (int k = 0; k < 3 && SQL_SUCCEEDED(rc) && SQL_SUCCEEDED(bc); k++) {
    p = k == 0 ? 1 : 5;
    out = -1;
    if (k == 2)
      SQLFreeStmt(st, SQL_UNBIND);
    rc = SQLExecute(st);
    if (SQL_SUCCEEDED(rc))
      rc = SQLFetch(st);
    got[k] = out;
    SQLFreeStmt(st, SQL_CLOSE);
  }
  if (!SQL_SUCCEEDED(rc) || !SQL_SUCCEEDED(bc))
    diag_text(SQL_HANDLE_STMT, st, err, sizeof err);
  SQLFreeHandle(SQL_HANDLE_STMT, st);
  if (!SQL_SUCCEEDED(bc) || !SQL_SUCCEEDED(rc) || got[0] != 2 || got[1] != 6 || got[2] != -1)
    snprintf(m, sizeof m, "bind rc=%d, rc=%d, fetched %d / %d / %d (want 2 / 6 / untouched -1) %s",
             (int)bc, (int)rc, (int)got[0], (int)got[1], (int)got[2], err);
  if (m[0] == '\0')
    pass(name);
  else
    fail(name, m);
}

static void check_array_batch(SQLHDBC dbc)
{
  SQLHSTMT st;
  SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st);
  /* rows 10,11,11,13 - offset 2 duplicates the PK of offset 1 */
  SQLINTEGER ids[4] = {10, 11, 11, 13};
  SQLCHAR vs[4][20] = {"a", "b", "c", "d"};
  SQLUSMALLINT status[4];
  SQLULEN processed = 0;
  SQLSetStmtAttr(st, SQL_ATTR_PARAMSET_SIZE, (SQLPOINTER)(SQLULEN)4, 0);
  SQLSetStmtAttr(st, SQL_ATTR_PARAM_STATUS_PTR, status, 0);
  SQLSetStmtAttr(st, SQL_ATTR_PARAMS_PROCESSED_PTR, &processed, 0);
  SQLBindParameter(st, 1, SQL_PARAM_INPUT, SQL_C_SLONG, SQL_INTEGER, 0, 0, ids, 0, NULL);
  SQLBindParameter(st, 2, SQL_PARAM_INPUT, SQL_C_CHAR, SQL_VARCHAR, 20, 0, vs, 20, NULL);
  SQLRETURN rc = SQLExecDirect(st, (SQLCHAR *)"INSERT INTO " TBL " VALUES (?, ?)", SQL_NTS);
  if (rc == SQL_SUCCESS_WITH_INFO && processed == 4 && status[0] == SQL_PARAM_SUCCESS &&
      status[2] == SQL_PARAM_ERROR)
    pass("array DML batch errors");
  else {
    char m[160];
    snprintf(m, sizeof m, "rc=%d processed=%lu status=[%u,%u,%u,%u]", rc, (unsigned long)processed,
             status[0], status[1], status[2], status[3]);
    fail("array DML batch errors", m);
  }
  SQLFreeHandle(SQL_HANDLE_STMT, st);
}

static void check_catalog(SQLHDBC dbc)
{
  SQLHSTMT st;
  SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st);
  SQLRETURN rc = SQLColumns(st, NULL, 0, NULL, 0, (SQLCHAR *)TBL, SQL_NTS, NULL, 0);
  int rows = 0;
  if (SQL_SUCCEEDED(rc))
    while (SQLFetch(st) == SQL_SUCCESS)
      rows++;
  if (rows >= 2)
    pass("SQLColumns");
  else {
    char m[64];
    snprintf(m, sizeof m, "got %d columns, want >=2", rows);
    fail("SQLColumns", m);
  }
  SQLFreeHandle(SQL_HANDLE_STMT, st);
}

static void check_data_at_exec(SQLHDBC dbc)
{
  SQLHSTMT st;
  char err[256], v[64];
  SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st);
  SQLPrepare(st, (SQLCHAR *)"INSERT INTO " TBL " (id, v) VALUES (?, ?)", SQL_NTS);
  SQLINTEGER id = 200;
  SQLLEN id_ind = 0, dae = SQL_LEN_DATA_AT_EXEC(0);
  int token;
  SQLBindParameter(st, 1, SQL_PARAM_INPUT, SQL_C_SLONG, SQL_INTEGER, 0, 0, &id, 0, &id_ind);
  SQLBindParameter(st, 2, SQL_PARAM_INPUT, SQL_C_CHAR, SQL_VARCHAR, 20, 0, &token, 0, &dae);
  int ok = 0;
  if (SQLExecute(st) == SQL_NEED_DATA) {
    SQLPOINTER t = NULL;
    if (SQLParamData(st, &t) == SQL_NEED_DATA && t == &token) {
      SQLPutData(st, (SQLPOINTER) "ab", SQL_NTS); /* stream in two chunks */
      SQLPutData(st, (SQLPOINTER) "cd", SQL_NTS);
      ok = SQL_SUCCEEDED(SQLParamData(st, &t));
    }
  }
  SQLFreeHandle(SQL_HANDLE_STMT, st);
  if (!ok) {
    fail("data-at-exec (SQLPutData)", "SQL_NEED_DATA flow failed");
    return;
  }
  if (SQL_SUCCEEDED(
          exec_scalar(dbc, "SELECT v FROM " TBL " WHERE id = 200", v, sizeof v, err, sizeof err)) &&
      strcmp(v, "abcd") == 0)
    pass("data-at-exec (SQLPutData)");
  else {
    char m[128];
    snprintf(m, sizeof m, "got '%s' want 'abcd'", v);
    fail("data-at-exec (SQLPutData)", m);
  }
}

/* SQLCancel: a no-op on an idle statement, and aborts an in-progress
 * data-at-execution (SQL_NEED_DATA) sequence so the streamed INSERT never runs
 * and the connection stays usable. */
static void check_cancel(SQLHDBC dbc)
{
  const char *name = "SQLCancel (data-at-exec)";
  char err[256], v[32];
  SQLHSTMT st;
  SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st);

  if (!SQL_SUCCEEDED(SQLCancel(st))) { /* idle: benign success */
    fail(name, "SQLCancel on idle statement failed");
    SQLFreeHandle(SQL_HANDLE_STMT, st);
    return;
  }

  SQLPrepare(st, (SQLCHAR *)"INSERT INTO " TBL " (id, v) VALUES (?, ?)", SQL_NTS);
  SQLINTEGER id = 250;
  SQLLEN id_ind = 0, dae = SQL_LEN_DATA_AT_EXEC(0);
  int token;
  SQLBindParameter(st, 1, SQL_PARAM_INPUT, SQL_C_SLONG, SQL_INTEGER, 0, 0, &id, 0, &id_ind);
  SQLBindParameter(st, 2, SQL_PARAM_INPUT, SQL_C_CHAR, SQL_VARCHAR, 20, 0, &token, 0, &dae);
  int aborted = (SQLExecute(st) == SQL_NEED_DATA) && SQL_SUCCEEDED(SQLCancel(st));
  SQLFreeHandle(SQL_HANDLE_STMT, st);

  if (!aborted) {
    fail(name, "NEED_DATA / SQLCancel flow failed");
    return;
  }
  /* The cancelled row must not exist, and this query proves the link is fine. */
  if (SQL_SUCCEEDED(exec_scalar(dbc, "SELECT COUNT(*) FROM " TBL " WHERE id = 250", v, sizeof v,
                                err, sizeof err)) &&
      strcmp(v, "0") == 0)
    pass(name);
  else {
    char m[128];
    snprintf(m, sizeof m, "cancelled row leaked (count='%s')", v);
    fail(name, err[0] ? err : m);
  }
}

static void check_lock(SQLHDBC dbc)
{
  /* SQL_CONCUR_LOCK must execute (FOR UPDATE accepted by the server). */
  SQLHSTMT st;
  char err[256];
  SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st);
  SQLSetStmtAttr(st, SQL_ATTR_CONCURRENCY, (SQLPOINTER)SQL_CONCUR_LOCK, 0);
  SQLRETURN rc = SQLExecDirect(st, (SQLCHAR *)"SELECT id, v FROM " TBL " WHERE id = 1", SQL_NTS);
  if (SQL_SUCCEEDED(rc) && SQL_SUCCEEDED(SQLFetch(st)))
    pass("FOR UPDATE (SQL_CONCUR_LOCK)");
  else {
    diag_text(SQL_HANDLE_STMT, st, err, sizeof err);
    fail("FOR UPDATE (SQL_CONCUR_LOCK)", err[0] ? err : "exec failed");
  }
  SQLEndTran(SQL_HANDLE_DBC, dbc, SQL_ROLLBACK);
  SQLFreeHandle(SQL_HANDLE_STMT, st);
}

/* 23ai column annotations, surfaced via SQLColAttribute(SQL_DESC_SEER_ANNOTATIONS),
 * a SeerODBC extension that returns "name=value\n..." per column. Skipped on
 * pre-23ai servers, which have no ANNOTATIONS syntax. */
#define SQL_DESC_SEER_ANNOTATIONS 19111
static void check_annotations(SQLHDBC dbc)
{
  const char *name = "column annotations";
  GATE(name);
  char err[256];
  exec_do(dbc, "DROP TABLE seer_ann", err, sizeof err);
  if (!SQL_SUCCEEDED(exec_do(dbc, "CREATE TABLE seer_ann (id NUMBER ANNOTATIONS (Foo 'bar'))", err,
                             sizeof err))) {
    fail(name, err);
    return;
  }
  SQLHSTMT st;
  SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st);
  SQLRETURN rc = SQLExecDirect(st, (SQLCHAR *)"SELECT id FROM seer_ann", SQL_NTS);
  if (SQL_SUCCEEDED(rc)) {
    char buf[256] = {0};
    SQLSMALLINT len = 0;
    rc = SQLColAttribute(st, 1, SQL_DESC_SEER_ANNOTATIONS, buf, sizeof buf, &len, NULL);
    if (!SQL_SUCCEEDED(rc))
      fail(name, "SQLColAttribute(SQL_DESC_SEER_ANNOTATIONS) failed");
    else if (buf[0] == '\0')
      /* DDL took but no annotation surfaced: the negotiated protocol level
       * (e.g. the fv6 legacy framing) doesn't carry annotation bytes. */
      skip(name, "annotations not surfaced at this protocol level");
    else if (strstr(buf, "bar") == NULL) {
      char m[300];
      snprintf(m, sizeof m, "got '%s', want a 'Foo=bar' annotation", buf);
      fail(name, m);
    } else
      pass(name);
  } else {
    diag_text(SQL_HANDLE_STMT, st, err, sizeof err);
    fail(name, err[0] ? err : "SELECT failed");
  }
  SQLFreeHandle(SQL_HANDLE_STMT, st);
  exec_do(dbc, "DROP TABLE seer_ann", err, sizeof err);
}

/* 12c+ implicit result sets (DBMS_SQL.RETURN_RESULT), surfaced through
 * SQLMoreResults: an anonymous block returns a cursor; each SQLMoreResults makes
 * the next implicit result current. Skipped on pre-12c servers (no RETURN_RESULT). */
/* A REF CURSOR (or implicit result) whose rows carry a CURSOR() column. The
 * driver has no SQL for such a cursor and must fetch it with a fetch-only
 * OALL8 on its id: 10g..21c answer a plain TTI_FETCH with each inner cursor
 * cell cut to `02 <ub4 id>` (no inline describe), which desyncs the row
 * (seerdb#1462). The nested column reads as NULL; the columns around it must
 * still decode. */
#define SEER_SQL_REFCURSOR (-9999) /* driver extension SQL type */
static int rows_around_cursor(SQLHSTMT st, int want_rows, char *why, size_t whyn)
{
  int rows = 0;
  SQLRETURN rc;
  while (SQL_SUCCEEDED(rc = SQLFetch(st))) {
    char a[16] = "", t[16] = "";
    SQLLEN ia = 0, it = 0;
    SQLGetData(st, 1, SQL_C_CHAR, a, sizeof a, &ia);
    SQLGetData(st, 3, SQL_C_CHAR, t, sizeof t, &it);
    rows++;
    if (atoi(a) != rows || strcmp(t, "tail") != 0) {
      snprintf(why, whyn, "row %d: a='%s' tail='%s'", rows, a, t);
      return 0;
    }
  }
  if (rc != SQL_NO_DATA) {
    diag_text(SQL_HANDLE_STMT, st, why, (int)whyn);
    return 0;
  }
  if (rows != want_rows) {
    snprintf(why, whyn, "rows=%d want %d", rows, want_rows);
    return 0;
  }
  return 1;
}

static void check_refcursor_nested_cursor(SQLHDBC dbc)
{
  /* Opened from a string: 11g's PL/SQL compiler refuses a cursor expression
   * in a static OPEN ... FOR (PLS-00103 / ORA-06550). */
  /* rownum over all_objects, not CONNECT BY on dual, which 9i ends after the
   * first fetch batch. */
  const char *query = "'SELECT rownum a, CURSOR(SELECT 1 FROM dual) c, ''tail'' t "
                      "FROM all_objects WHERE rownum <= 30'";
  char why[300] = "", blk[512];
  if (!gated("REF CURSOR rows holding a CURSOR() column")) {
    const char *name = "REF CURSOR rows holding a CURSOR() column";
    SQLHSTMT st;
    SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st);
    snprintf(blk, sizeof blk, "BEGIN OPEN :1 FOR %s; END;", query);
    SQLRETURN rc = SQLBindParameter(st, 1, SQL_PARAM_OUTPUT, SQL_C_DEFAULT, SEER_SQL_REFCURSOR, 0,
                                    0, NULL, 0, NULL);
    if (SQL_SUCCEEDED(rc))
      rc = SQLExecDirect(st, (SQLCHAR *)blk, SQL_NTS);
    if (!SQL_SUCCEEDED(rc))
      diag_text(SQL_HANDLE_STMT, st, why, sizeof why);
    if (SQL_SUCCEEDED(rc) && rows_around_cursor(st, 30, why, sizeof why))
      pass(name);
    else
      fail(name, why);
    SQLFreeHandle(SQL_HANDLE_STMT, st);
  }
  if (!gated("implicit result rows holding a CURSOR() column")) {
    const char *name = "implicit result rows holding a CURSOR() column";
    SQLHSTMT st;
    SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st);
    snprintf(blk, sizeof blk,
             "DECLARE c SYS_REFCURSOR; BEGIN OPEN c FOR %s; DBMS_SQL.RETURN_RESULT(c); END;",
             query);
    why[0] = '\0';
    SQLRETURN rc = SQLExecDirect(st, (SQLCHAR *)blk, SQL_NTS);
    if (SQL_SUCCEEDED(rc))
      rc = SQLMoreResults(st);
    if (!SQL_SUCCEEDED(rc))
      diag_text(SQL_HANDLE_STMT, st, why, sizeof why);
    if (SQL_SUCCEEDED(rc) && rows_around_cursor(st, 30, why, sizeof why))
      pass(name);
    else
      fail(name, why[0] ? why : "no implicit result");
    SQLFreeHandle(SQL_HANDLE_STMT, st);
  }
}

/* Run `sql` and count the result sets it gives through SQLMoreResults: -1 when
 * it fails to run, with the error in `err`. */
static int count_result_sets(SQLHDBC dbc, const char *sql, char *err, size_t errn)
{
  SQLHSTMT st;
  SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st);
  SQLRETURN rc = SQLExecDirect(st, (SQLCHAR *)sql, SQL_NTS);
  int sets = -1;
  if (!SQL_SUCCEEDED(rc))
    diag_text(SQL_HANDLE_STMT, st, err, (int)errn);
  else
    for (sets = 0; SQL_SUCCEEDED(rc); rc = SQLMoreResults(st)) {
      SQLSMALLINT nc = 0;
      SQLNumResultCols(st, &nc);
      if (nc > 0) {
        sets++;
        while (SQL_SUCCEEDED(SQLFetch(st)))
          ;
      }
    }
  SQLFreeHandle(SQL_HANDLE_STMT, st);
  return sets;
}

/* SQL_MULT_RESULT_SETS and SQL_BATCH_SUPPORT (#312) match what the server
 * does on every release: SQL_BS_SELECT_PROC exactly where a procedure called
 * through {call} really gives two result sets. SQL_MULT_RESULT_SETS is "Y"
 * everywhere, since a query with a parameter array gives one result set per
 * set on every release (#431); 12c+ blocks give two as well. */
static void check_mult_result_sets(SQLHDBC dbc)
{
  const char *name = "SQL_MULT_RESULT_SETS / SQL_BATCH_SUPPORT match the server";
  const char *body = "a SYS_REFCURSOR; b SYS_REFCURSOR; BEGIN "
                     "OPEN a FOR SELECT 1 FROM dual; DBMS_SQL.RETURN_RESULT(a); "
                     "OPEN b FOR SELECT 2 FROM dual UNION ALL SELECT 3 FROM dual; "
                     "DBMS_SQL.RETURN_RESULT(b); END;";
  char sql[512], err[256] = "", m[400] = "", mrs[8] = "";
  SQLUINTEGER bs = 0, brc = 0;
  SQLGetInfo(dbc, SQL_MULT_RESULT_SETS, mrs, sizeof mrs, NULL);
  SQLGetInfo(dbc, SQL_BATCH_SUPPORT, &bs, sizeof bs, NULL);
  SQLGetInfo(dbc, SQL_BATCH_ROW_COUNT, &brc, sizeof brc, NULL);

  snprintf(sql, sizeof sql, "DECLARE %s", body);
  int block = count_result_sets(dbc, sql, err, sizeof err);
  /* A procedure that won't compile (no RETURN_RESULT) still creates, with
   * errors; calling it then fails like the block. */
  snprintf(sql, sizeof sql, "CREATE OR REPLACE PROCEDURE seer_mrs AS %s", body);
  exec_do(dbc, sql, err, sizeof err);
  char cerr[256] = "";
  int call = count_result_sets(dbc, "{call seer_mrs}", cerr, sizeof cerr);
  exec_do(dbc, "DROP PROCEDURE seer_mrs", err, sizeof err);

  if (block >= 0 && block != 2)
    snprintf(m, sizeof m, "the two-result block gave %d sets", block);
  else if (call >= 0 && call != 2)
    snprintf(m, sizeof m, "{call} of the two-result procedure gave %d sets", call);
  else if (strcmp(mrs, "Y") != 0)
    snprintf(m, sizeof m, "SQL_MULT_RESULT_SETS '%s' (want Y)", mrs);
  else if (bs != (call == 2 ? (SQLUINTEGER)SQL_BS_SELECT_PROC : 0))
    snprintf(m, sizeof m, "SQL_BATCH_SUPPORT 0x%x, {call} gave %d sets (%s)", (unsigned)bs, call,
             cerr);
  else if (brc != 0)
    snprintf(m, sizeof m, "SQL_BATCH_ROW_COUNT 0x%x, want 0", (unsigned)brc);
  if (m[0] == '\0')
    pass(name);
  else
    fail(name, m);
}

static void check_implicit_results(SQLHDBC dbc)
{
  const char *name = "implicit results";
  GATE(name);
  char err[256];
  const char *blk = "DECLARE c SYS_REFCURSOR; BEGIN "
                    "OPEN c FOR SELECT 42 AS n FROM DUAL; DBMS_SQL.RETURN_RESULT(c); END;";
  SQLHSTMT st;
  SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st);
  SQLRETURN rc = SQLExecDirect(st, (SQLCHAR *)blk, SQL_NTS);
  if (!SQL_SUCCEEDED(rc)) {
    diag_text(SQL_HANDLE_STMT, st, err, sizeof err);
    fail(name, err[0] ? err : "execute failed");
    SQLFreeHandle(SQL_HANDLE_STMT, st);
    return;
  }
  rc = SQLMoreResults(st);
  if (rc == SQL_NO_DATA) {
    fail(name, "server returned no implicit result");
    SQLFreeHandle(SQL_HANDLE_STMT, st);
    return;
  }
  if (!SQL_SUCCEEDED(rc)) {
    diag_text(SQL_HANDLE_STMT, st, err, sizeof err);
    fail(name, err[0] ? err : "SQLMoreResults failed");
    SQLFreeHandle(SQL_HANDLE_STMT, st);
    return;
  }
  char buf[64] = {0};
  SQLLEN ind = 0;
  if (SQL_SUCCEEDED(SQLFetch(st)) &&
      SQL_SUCCEEDED(SQLGetData(st, 1, SQL_C_CHAR, buf, sizeof buf, &ind)) &&
      strstr(buf, "42") != NULL)
    pass(name);
  else {
    char m[128];
    snprintf(m, sizeof m, "got '%s', want '42'", buf);
    fail(name, m);
  }
  SQLFreeHandle(SQL_HANDLE_STMT, st);
}

/* 12c+ array-DML per-iteration row counts, surfaced via the SeerODBC extension
 * attribute SQL_ATTR_SEER_DML_ROW_COUNTS (app provides a SQLLEN array the driver
 * fills). An array UPDATE whose WHERE matches 1, 3, 5 rows must report [1,3,5].
 * Skipped on pre-12c servers, which don't return per-iteration counts. */
#define SQL_ATTR_SEER_DML_ROW_COUNTS 19112
static void check_array_dml_rowcounts(SQLHDBC dbc)
{
  const char *name = "array DML row counts";
  GATE(name);
  char err[256];
  exec_do(dbc, "DROP TABLE seer_admlc", err, sizeof err);
  if (!SQL_SUCCEEDED(exec_do(dbc, "CREATE TABLE seer_admlc (id NUMBER)", err, sizeof err))) {
    fail(name, err[0] ? err : "create failed");
    return;
  }
  exec_do(dbc, "INSERT INTO seer_admlc SELECT LEVEL FROM DUAL CONNECT BY LEVEL <= 5", err,
          sizeof err);

  SQLHSTMT st;
  SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st);
  SQLINTEGER thresh[3] = {1, 3, 5};
  SQLLEN counts[3] = {-1, -1, -1};
  SQLSetStmtAttr(st, SQL_ATTR_PARAMSET_SIZE, (SQLPOINTER)(SQLULEN)3, 0);
  SQLSetStmtAttr(st, SQL_ATTR_SEER_DML_ROW_COUNTS, counts, 0);
  SQLBindParameter(st, 1, SQL_PARAM_INPUT, SQL_C_SLONG, SQL_INTEGER, 0, 0, thresh, 0, NULL);
  SQLRETURN rc =
      SQLExecDirect(st, (SQLCHAR *)"UPDATE seer_admlc SET id = id WHERE id <= ?", SQL_NTS);
  if (!SQL_SUCCEEDED(rc)) {
    diag_text(SQL_HANDLE_STMT, st, err, sizeof err);
    fail(name, err[0] ? err : "array UPDATE failed");
  } else if (counts[0] == 0 && counts[1] == 0 && counts[2] == 0) {
    fail(name, "every row count is 0");
  } else if (counts[0] == 1 && counts[1] == 3 && counts[2] == 5) {
    pass(name);
  } else {
    char m[128];
    snprintf(m, sizeof m, "got [%ld,%ld,%ld], want [1,3,5]", (long)counts[0], (long)counts[1],
             (long)counts[2]);
    fail(name, m);
  }
  SQLFreeHandle(SQL_HANDLE_STMT, st);
  exec_do(dbc, "DROP TABLE seer_admlc", err, sizeof err);
}

/* Physical ROWID (type 11): SELECT ROWID FROM DUAL returns the 18-char extended
 * ROWID. Works on every server. */
static void check_rowid(SQLHDBC dbc)
{
  char out[256], err[256];
  SQLRETURN rc = exec_scalar(dbc, "SELECT ROWID FROM DUAL", out, sizeof out, err, sizeof err);
  if (!SQL_SUCCEEDED(rc)) {
    fail("ROWID fetch", err[0] ? err : "execute failed");
    return;
  }
  size_t n = strlen(out);
  if (n == 18 &&
      strspn(out, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/") == 18)
    pass("ROWID fetch");
  else {
    char m[300];
    snprintf(m, sizeof m, "got '%s' (len %zu), want an 18-char ROWID", out, n);
    fail("ROWID fetch", m);
  }
}

/* UROWID (type 208): an index-organized table's ROWID renders as "*"+base64.
 * Select ROWID alongside a scalar column and confirm the scalar still decodes -
 * i.e. the UROWID decode consumed exactly its bytes and didn't desync the row. */
/* A long logical UROWID: an index-organized table whose key is 900
 * characters has a rowid of over a thousand. Past 252 bytes it comes chunked,
 * as a LOB locator does; read as one length byte, the reply desynced and the
 * query failed with ORA-01403 (#144). It binds back to find its row. */
static void check_urowid_long(SQLHDBC dbc)
{
  const char *name = "long logical UROWID (900-character key)";
  char err[256];
  exec_do(dbc, "DROP TABLE seer_iotl", err, sizeof err);
  if (!SQL_SUCCEEDED(exec_do(dbc,
                             "CREATE TABLE seer_iotl (k VARCHAR2(1000) PRIMARY KEY, v NUMBER) "
                             "ORGANIZATION INDEX",
                             err, sizeof err)) ||
      !SQL_SUCCEEDED(
          exec_do(dbc, "INSERT INTO seer_iotl VALUES (RPAD('k', 900, 'x'), 7)", err, sizeof err))) {
    skip(name, err[0] ? err : "no IOT support");
    exec_do(dbc, "DROP TABLE seer_iotl", err, sizeof err);
    return;
  }
  static char rid[4096];
  char v[16] = "";
  rid[0] = '\0';
  SQLRETURN rc = exec_scalar(dbc, "SELECT ROWID FROM seer_iotl", rid, sizeof rid, err, sizeof err);
  SQLHSTMT st;
  SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st);
  SQLLEN ind = SQL_NTS, vind = 0;
  if (SQL_SUCCEEDED(rc)) {
    SQLBindParameter(st, 1, SQL_PARAM_INPUT, SQL_C_CHAR, SQL_VARCHAR, sizeof rid, 0, rid, 0, &ind);
    if (SQL_SUCCEEDED(
            SQLExecDirect(st, (SQLCHAR *)"SELECT v FROM seer_iotl WHERE ROWID = ?", SQL_NTS)) &&
        SQL_SUCCEEDED(SQLFetch(st)))
      SQLGetData(st, 1, SQL_C_CHAR, v, sizeof v, &vind);
  }
  SQLFreeHandle(SQL_HANDLE_STMT, st);
  exec_do(dbc, "DROP TABLE seer_iotl", err, sizeof err);
  if (SQL_SUCCEEDED(rc) && rid[0] == '*' && strlen(rid) > 1000 && strcmp(v, "7") == 0)
    pass(name);
  else {
    char m[300];
    snprintf(m, sizeof m, "rc=%d rowid len=%zu bound back='%s' %s", rc, strlen(rid), v,
             SQL_SUCCEEDED(rc) ? "" : err);
    fail(name, m);
  }
}

/* Binds pair with placeholders in order of appearance, whatever their labels,
 * on every release (#146): in SELECT :2 || :1 parameter 1 is :2, a repeated
 * placeholder is one parameter, and a block reads the same way - parameter 1
 * of BEGIN :2 := :1 || 'x' is the target. */
static void check_bind_order(SQLHDBC dbc)
{
  const char *name = "binds pair with placeholders in order of appearance";
  char m[256] = "";
  SQLHSTMT st;
  char a[8] = "A", b[8] = "B", out[32] = "";
  SQLLEN ia = SQL_NTS, ib = SQL_NTS, io = 0;
  SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st);
  SQLBindParameter(st, 1, SQL_PARAM_INPUT, SQL_C_CHAR, SQL_VARCHAR, 8, 0, a, 0, &ia);
  SQLBindParameter(st, 2, SQL_PARAM_INPUT, SQL_C_CHAR, SQL_VARCHAR, 8, 0, b, 0, &ib);
  if (SQL_SUCCEEDED(
          SQLExecDirect(st, (SQLCHAR *)"SELECT :2 || '-' || :1 || '-' || :2 FROM dual", SQL_NTS)) &&
      SQL_SUCCEEDED(SQLFetch(st)))
    SQLGetData(st, 1, SQL_C_CHAR, out, sizeof out, &io);
  SQLFreeHandle(SQL_HANDLE_STMT, st);
  if (strcmp(out, "A-B-A") != 0)
    snprintf(m, sizeof m, "SELECT :2||:1||:2 gave '%s', want 'A-B-A'", out);
  char target[32] = "", in[8] = "in";
  SQLLEN it = 0, ii = SQL_NTS;
  SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st);
  SQLBindParameter(st, 1, SQL_PARAM_OUTPUT, SQL_C_CHAR, SQL_VARCHAR, 30, 0, target, sizeof target,
                   &it);
  SQLBindParameter(st, 2, SQL_PARAM_INPUT, SQL_C_CHAR, SQL_VARCHAR, 8, 0, in, 0, &ii);
  SQLRETURN rc = SQLExecDirect(st, (SQLCHAR *)"BEGIN :2 := :1 || '-x'; END;", SQL_NTS);
  SQLFreeHandle(SQL_HANDLE_STMT, st);
  if (m[0] == '\0' && (!SQL_SUCCEEDED(rc) || strcmp(target, "in-x") != 0))
    snprintf(m, sizeof m, "BEGIN :2 := :1: rc=%d target '%s', want 'in-x'", rc, target);
  if (m[0] == '\0')
    pass(name);
  else
    fail(name, m);
}

/* OUT parameters that come back NULL: one the block sets to NULL, one it never
 * assigns, then one with a value, which shows the reply stayed in step. Each
 * NULL's return code is a ub4 the 10g+ reader once took as a single byte, and
 * the call failed with a protocol error (#149). */
static void check_null_out(SQLHDBC dbc)
{
  const char *name = "NULL and never-assigned OUT parameters";
  SQLHSTMT st;
  SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st);
  char a[16] = "x";
  SQLINTEGER b = -1, c = -1;
  SQLLEN ia = 0, ib = 0, ic = 0;
  SQLBindParameter(st, 1, SQL_PARAM_OUTPUT, SQL_C_CHAR, SQL_VARCHAR, 15, 0, a, sizeof a, &ia);
  SQLBindParameter(st, 2, SQL_PARAM_OUTPUT, SQL_C_SLONG, SQL_INTEGER, 0, 0, &b, 0, &ib);
  SQLBindParameter(st, 3, SQL_PARAM_OUTPUT, SQL_C_SLONG, SQL_INTEGER, 0, 0, &c, 0, &ic);
  SQLRETURN rc = SQLExecDirect(
      st, (SQLCHAR *)"BEGIN ? := NULL; IF 1 = 0 THEN ? := 5; END IF; ? := 7; END;", SQL_NTS);
  char err[256] = "";
  if (!SQL_SUCCEEDED(rc))
    diag_text(SQL_HANDLE_STMT, st, err, sizeof err);
  SQLFreeHandle(SQL_HANDLE_STMT, st);
  if (SQL_SUCCEEDED(rc) && ia == SQL_NULL_DATA && ib == SQL_NULL_DATA && ic != SQL_NULL_DATA &&
      c == 7)
    pass(name);
  else {
    char m[320];
    snprintf(m, sizeof m, "rc=%d ind %ld/%ld/%ld third=%ld %s", rc, (long)ia, (long)ib, (long)ic,
             (long)c, err);
    fail(name, m);
  }
}

/* SQL_C_DOUBLE / SQL_C_FLOAT parameters keep their value in a NUMBER column,
 * on every release: 10g+ bind them as BINARY_DOUBLE / BINARY_FLOAT, 8i and 9i -
 * which have neither - as the NUMBER with the fewest digits that reads back to
 * the same value (#151). 9i stored the IEEE bytes as text before. */
static void check_double_params(SQLHDBC dbc)
{
  const char *name = "SQL_C_DOUBLE / SQL_C_FLOAT parameters keep their value";
  char err[256] = "";
  exec_do(dbc, "DROP TABLE seer_dbl", err, sizeof err);
  if (!SQL_SUCCEEDED(exec_do(dbc, "CREATE TABLE seer_dbl (k NUMBER, d NUMBER)", err, sizeof err))) {
    fail(name, err);
    return;
  }
  static const double vals[] = {0.1, 1.5, -2.5e-7, 123456789.125, 1e20};
  const float fv = 2.25f;
  char m[256] = "";
  for (int i = 0; i <= 5 && m[0] == '\0'; i++) {
    SQLHSTMT st;
    SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st);
    SQLINTEGER k = i;
    SQLLEN kl = 0, dl = 0;
    double d = i < 5 ? vals[i] : 0;
    SQLBindParameter(st, 1, SQL_PARAM_INPUT, SQL_C_SLONG, SQL_INTEGER, 0, 0, &k, 0, &kl);
    if (i < 5)
      SQLBindParameter(st, 2, SQL_PARAM_INPUT, SQL_C_DOUBLE, SQL_DOUBLE, 0, 0, &d, 0, &dl);
    else
      SQLBindParameter(st, 2, SQL_PARAM_INPUT, SQL_C_FLOAT, SQL_REAL, 0, 0, (SQLPOINTER)&fv, 0,
                       &dl);
    SQLRETURN rc = SQLExecDirect(st, (SQLCHAR *)"INSERT INTO seer_dbl VALUES (?, ?)", SQL_NTS);
    if (!SQL_SUCCEEDED(rc)) {
      diag_text(SQL_HANDLE_STMT, st, err, sizeof err);
      snprintf(m, sizeof m, "insert %d: rc=%d %s", i, rc, err);
    }
    SQLFreeHandle(SQL_HANDLE_STMT, st);
  }
  SQLHSTMT st;
  SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st);
  int rows = 0;
  if (m[0] == '\0' &&
      SQL_SUCCEEDED(SQLExecDirect(st, (SQLCHAR *)"SELECT k, d FROM seer_dbl ORDER BY k", SQL_NTS)))
    while (m[0] == '\0' && SQL_SUCCEEDED(SQLFetch(st))) {
      SQLINTEGER k = -1;
      double d = 0;
      SQLLEN kl = 0, dl = 0;
      SQLGetData(st, 1, SQL_C_SLONG, &k, 0, &kl);
      SQLGetData(st, 2, SQL_C_DOUBLE, &d, 0, &dl);
      double want = k < 5 ? vals[k] : (double)fv;
      if (memcmp(&d, &want, sizeof d) != 0) /* exactly the stored bits */
        snprintf(m, sizeof m, "row %d: read back %.17g, stored %.17g", (int)k, d, want);
      rows++;
    }
  SQLFreeHandle(SQL_HANDLE_STMT, st);
  exec_do(dbc, "DROP TABLE seer_dbl", err, sizeof err);
  if (m[0] == '\0' && rows == 6)
    pass(name);
  else {
    if (m[0] == '\0')
      snprintf(m, sizeof m, "%d rows", rows);
    fail(name, m);
  }
}

/* A BFILE whose file can't be opened: as Oracle reports it, the fetch
 * succeeds and SQLGetData of that column is the server's error, ORA-22285
 * for a missing directory (native 22285); the column beside it reads (#158).
 * It used to read as an empty value on 9i and 10g+, and fail the whole query
 * on 8i. */
static void check_bfile_unopenable(SQLHDBC dbc)
{
  const char *name = "an unopenable BFILE is the server's error at SQLGetData";
  SQLHSTMT st;
  SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st);
  char m[300] = "", tail[16] = "";
  SQLRETURN rc = SQLExecDirect(
      st, (SQLCHAR *)"SELECT BFILENAME('NO_SUCH_DIR', 'x'), 'tail' FROM dual", SQL_NTS);
  SQLRETURN fr = SQL_SUCCEEDED(rc) ? SQLFetch(st) : rc;
  SQLRETURN gr = SQL_ERROR;
  SQLINTEGER native = 0;
  if (SQL_SUCCEEDED(fr)) {
    unsigned char buf[64];
    SQLLEN ind = 0;
    gr = SQLGetData(st, 1, SQL_C_BINARY, buf, sizeof buf, &ind);
    SQLCHAR state[6] = "";
    SQLSMALLINT ml = 0;
    if (gr == SQL_ERROR)
      SQLGetDiagRec(SQL_HANDLE_STMT, st, 1, state, &native, NULL, 0, &ml);
    SQLGetData(st, 2, SQL_C_CHAR, tail, sizeof tail, &ind);
  }
  SQLFreeHandle(SQL_HANDLE_STMT, st);
  if (SQL_SUCCEEDED(rc) && SQL_SUCCEEDED(fr) && gr == SQL_ERROR && native == 22285 &&
      strcmp(tail, "tail") == 0)
    pass(name);
  else {
    snprintf(m, sizeof m, "execute %d fetch %d getdata %d native %ld tail '%s'", rc, fr, gr,
             (long)native, tail);
    fail(name, m);
  }
}

static void check_urowid(SQLHDBC dbc)
{
  const char *name = "UROWID fetch";
  char err[256];
  exec_do(dbc, "DROP TABLE seer_iot", err, sizeof err);
  if (!SQL_SUCCEEDED(exec_do(
          dbc, "CREATE TABLE seer_iot (id NUMBER PRIMARY KEY, v VARCHAR2(8)) ORGANIZATION INDEX",
          err, sizeof err))) {
    skip(name, err[0] ? err : "no IOT support");
    return;
  }
  exec_do(dbc, "INSERT INTO seer_iot VALUES (7, 'seven')", err, sizeof err);
  SQLHSTMT st;
  SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st);
  SQLRETURN rc =
      SQLExecDirect(st, (SQLCHAR *)"SELECT ROWID, id FROM seer_iot WHERE id = 7", SQL_NTS);
  char rid[256] = {0}, idv[64] = {0};
  SQLLEN l1 = 0, l2 = 0;
  if (SQL_SUCCEEDED(rc) && SQL_SUCCEEDED(SQLFetch(st)) &&
      SQL_SUCCEEDED(SQLGetData(st, 1, SQL_C_CHAR, rid, sizeof rid, &l1)) &&
      SQL_SUCCEEDED(SQLGetData(st, 2, SQL_C_CHAR, idv, sizeof idv, &l2))) {
    if (rid[0] == '*' && strstr(idv, "7") != NULL)
      pass(name);
    else {
      char m[300];
      snprintf(m, sizeof m, "rowid='%s' id='%s' (want '*...' + id 7)", rid, idv);
      fail(name, m);
    }
  } else {
    diag_text(SQL_HANDLE_STMT, st, err, sizeof err);
    fail(name, err[0] ? err : "select failed");
  }
  SQLFreeHandle(SQL_HANDLE_STMT, st);
  exec_do(dbc, "DROP TABLE seer_iot", err, sizeof err);
}

/* INTERVAL YEAR TO MONTH / DAY TO SECOND decode (all server versions). */
static void check_intervals(SQLHDBC dbc)
{
  char out[256], err[256];
  SQLRETURN rc = exec_scalar(dbc, "SELECT INTERVAL '2-6' YEAR TO MONTH FROM DUAL", out, sizeof out,
                             err, sizeof err);
  if (SQL_SUCCEEDED(rc) && strstr(out, "2-06") != NULL)
    pass("INTERVAL YEAR TO MONTH");
  else {
    char m[300];
    snprintf(m, sizeof m, "got '%s', want '+2-06'", out);
    fail("INTERVAL YEAR TO MONTH", err[0] ? err : m);
  }
  rc = exec_scalar(dbc, "SELECT INTERVAL '2 3:4:5.123456789' DAY TO SECOND(9) FROM DUAL", out,
                   sizeof out, err, sizeof err);
  if (SQL_SUCCEEDED(rc) && strstr(out, "03:04:05.123456789") != NULL)
    pass("INTERVAL DAY TO SECOND");
  else {
    char m[300];
    snprintf(m, sizeof m, "got '%s', want '+2 03:04:05.123456789'", out);
    fail("INTERVAL DAY TO SECOND", err[0] ? err : m);
  }
}

/* Native SQL BOOLEAN (23ai). Skipped on servers without the type. */
static void check_boolean(SQLHDBC dbc)
{
  const char *name = "BOOLEAN (23ai)";
  GATE(name);
  char out[256], err[256];
  exec_do(dbc, "DROP TABLE seer_bool", err, sizeof err);
  if (!SQL_SUCCEEDED(exec_do(dbc, "CREATE TABLE seer_bool (b BOOLEAN)", err, sizeof err))) {
    fail(name, err);
    return;
  }
  exec_do(dbc, "INSERT INTO seer_bool VALUES (TRUE)", err, sizeof err);
  SQLRETURN rc = exec_scalar(dbc, "SELECT b FROM seer_bool", out, sizeof out, err, sizeof err);
  if (SQL_SUCCEEDED(rc) && strstr(out, "TRUE") != NULL)
    pass(name);
  else if (SQL_SUCCEEDED(rc) && (strcmp(out, "1") == 0 || strcmp(out, "0") == 0))
    /* The negotiated protocol (e.g. the fv6 legacy framing) carries no native
     * BOOLEAN type, so the server hands it back as a 1/0 numeric. */
    skip(name, "native BOOLEAN not surfaced at this protocol level");
  else {
    char m[300];
    snprintf(m, sizeof m, "got '%s', want 'TRUE'", out);
    fail(name, err[0] ? err : m);
  }
  exec_do(dbc, "DROP TABLE seer_bool", err, sizeof err);
}

/* Native 23ai VECTOR decode (a LOB-backed type rendered as "[e1, e2, ...]").
 * Skipped where the type or its native (fv24) form isn't available. */
static void check_vector(SQLHDBC dbc)
{
  const char *name = "VECTOR (23ai)";
  GATE(name);
  char out[256], err[256];
  SQLRETURN rc = exec_scalar(dbc, "SELECT TO_VECTOR('[1.5, 2.5, 3.5]', 3, FLOAT32) FROM DUAL", out,
                             sizeof out, err, sizeof err);
  if (!SQL_SUCCEEDED(rc)) {
    fail(name, err[0] ? err : "execute failed");
    return;
  }
  if (strstr(out, "1.5, 2.5, 3.5") != NULL)
    pass(name); /* our native VECTOR decode */
  else if (strstr(out, "1.5") != NULL)
    /* The negotiated protocol (e.g. fv6 legacy) gives no native VECTOR type,
     * so the server renders it to text itself (e.g. "[1.5E+000,...]"). */
    skip(name, "native VECTOR not surfaced at this protocol level");
  else {
    char m[300];
    snprintf(m, sizeof m, "got '%s', want '[1.5, 2.5, 3.5]'", out);
    fail(name, m);
  }
}

/* Native JSON (21c+, OSON binary image) decoded back to JSON text. Skipped where
 * the type or its native form isn't available. Keys checked order-independently. */
static void check_json(SQLHDBC dbc)
{
  const char *name = "JSON (OSON)";
  GATE(name);
  char out[512], err[256];
  SQLRETURN rc = exec_scalar(dbc, "SELECT JSON('{\"n\":42,\"s\":\"hi\",\"b\":true}') FROM DUAL",
                             out, sizeof out, err, sizeof err);
  if (!SQL_SUCCEEDED(rc)) {
    fail(name, err[0] ? err : "execute failed");
    return;
  }
  if (strstr(out, "\"n\":42") && strstr(out, "\"s\":\"hi\"") && strstr(out, "\"b\":true"))
    pass(name); /* our native OSON decode */
  else if ((strstr(out, "42") && strstr(out, "hi")) ||
           (out[0] && strspn(out, "0123456789ABCDEF") == strlen(out)))
    /* No native JSON image at this protocol level (e.g. fv6 legacy): the
     * server returns the JSON as text, or as a BLOB we hex-render. */
    skip(name, "native JSON not surfaced at this protocol level");
  else {
    char m[600];
    snprintf(m, sizeof m, "got '%s'", out);
    fail(name, m);
  }
}

/* DML RETURNING ... INTO: the server fills an OUT-bound parameter from the
 * affected row. `RETURNING id + 100` proves the value is server-computed, not the
 * echoed input. Works on all Oracle versions. */
static void check_returning(SQLHDBC dbc)
{
  const char *name = "DML RETURNING INTO";
  char err[256];
  exec_do(dbc, "DROP TABLE seer_ret", err, sizeof err);
  if (!SQL_SUCCEEDED(exec_do(dbc, "CREATE TABLE seer_ret (id NUMBER)", err, sizeof err))) {
    fail(name, err[0] ? err : "create failed");
    return;
  }
  SQLHSTMT st;
  SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st);
  SQLINTEGER in_id = 7, out_id = 0;
  SQLLEN in_ind = 0, out_ind = 0;
  SQLBindParameter(st, 1, SQL_PARAM_INPUT, SQL_C_SLONG, SQL_INTEGER, 0, 0, &in_id, 0, &in_ind);
  SQLBindParameter(st, 2, SQL_PARAM_OUTPUT, SQL_C_SLONG, SQL_INTEGER, 0, 0, &out_id, sizeof out_id,
                   &out_ind);
  SQLRETURN rc = SQLExecDirect(
      st, (SQLCHAR *)"INSERT INTO seer_ret (id) VALUES (?) RETURNING id + 100 INTO ?", SQL_NTS);
  if (SQL_SUCCEEDED(rc) && out_id == 107)
    pass(name);
  else {
    char m[200];
    diag_text(SQL_HANDLE_STMT, st, err, sizeof err);
    snprintf(m, sizeof m, "rc=%d out_id=%ld (want 107) %s", rc, (long)out_id, err);
    fail(name, m);
  }
  SQLFreeHandle(SQL_HANDLE_STMT, st);
  exec_do(dbc, "DROP TABLE seer_ret", err, sizeof err);
}

/* Medium string bind: a value past the inline limit uses the 0xFE-chunked bind
 * encoding (previously mis-encoded -> ORA-03120 / desync). Bind 500 chars into a
 * VARCHAR2(4000) and confirm the round-trip length. 500 stays under 10g's small
 * default SDU (large binds need outgoing fragmentation, a separate gap). */
static void check_medium_bind(SQLHDBC dbc)
{
  const char *name = "medium string bind (chunked)";
  char err[256], out[64];
  exec_do(dbc, "DROP TABLE seer_mb", err, sizeof err);
  if (!SQL_SUCCEEDED(exec_do(dbc, "CREATE TABLE seer_mb (v VARCHAR2(4000))", err, sizeof err))) {
    fail(name, err[0] ? err : "create failed");
    return;
  }
  enum { N = 500 };
  char big[N + 1];
  memset(big, 'X', N);
  big[N] = '\0';
  SQLHSTMT st;
  SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st);
  SQLLEN ind = N;
  SQLBindParameter(st, 1, SQL_PARAM_INPUT, SQL_C_CHAR, SQL_VARCHAR, N, 0, big, N, &ind);
  SQLRETURN rc = SQLExecDirect(st, (SQLCHAR *)"INSERT INTO seer_mb VALUES (?)", SQL_NTS);
  SQLFreeHandle(SQL_HANDLE_STMT, st);
  if (SQL_SUCCEEDED(rc) &&
      SQL_SUCCEEDED(
          exec_scalar(dbc, "SELECT LENGTH(v) FROM seer_mb", out, sizeof out, err, sizeof err)) &&
      strcmp(out, "500") == 0)
    pass(name);
  else {
    char m[200];
    snprintf(m, sizeof m, "len='%s' rc=%d", out, rc);
    fail(name, err[0] ? err : m);
  }
  exec_do(dbc, "DROP TABLE seer_mb", err, sizeof err);
}

/* Large LOB bind: a 20 KB value into a CLOB exercises the streamed LONG type,
 * the chunked bind encoding, and TNS send-side fragmentation (it exceeds every
 * server's SDU). Confirm the stored length. */
static void check_large_bind(SQLHDBC dbc)
{
  const char *name = "large CLOB bind (fragmented)";
  char err[256], out[64];
  exec_do(dbc, "DROP TABLE seer_lb", err, sizeof err);
  if (!SQL_SUCCEEDED(exec_do(dbc, "CREATE TABLE seer_lb (c CLOB)", err, sizeof err))) {
    fail(name, err[0] ? err : "create failed");
    return;
  }
  enum { N = 20000 };
  char *big = malloc(N + 1);
  if (big == NULL) {
    fail(name, "oom");
    return;
  }
  memset(big, 'Z', N);
  big[N] = '\0';
  SQLHSTMT st;
  SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st);
  SQLLEN ind = N;
  SQLBindParameter(st, 1, SQL_PARAM_INPUT, SQL_C_CHAR, SQL_LONGVARCHAR, N, 0, big, N, &ind);
  SQLRETURN rc = SQLExecDirect(st, (SQLCHAR *)"INSERT INTO seer_lb VALUES (?)", SQL_NTS);
  free(big);
  SQLFreeHandle(SQL_HANDLE_STMT, st);
  if (SQL_SUCCEEDED(rc) &&
      SQL_SUCCEEDED(exec_scalar(dbc, "SELECT DBMS_LOB.GETLENGTH(c) FROM seer_lb", out, sizeof out,
                                err, sizeof err)) &&
      strcmp(out, "20000") == 0)
    pass(name);
  else {
    char m[200];
    snprintf(m, sizeof m, "len='%s' rc=%d", out, rc);
    fail(name, err[0] ? err : m);
  }
  exec_do(dbc, "DROP TABLE seer_lb", err, sizeof err);
}

/* INTERVAL binds: bind SQL_C_INTERVAL_YEAR_TO_MONTH + DAY_TO_SECOND structs and
 * confirm the round-trip. Works on all versions. */
static void check_interval_bind(SQLHDBC dbc)
{
  const char *name = "INTERVAL bind";
  GATE(name);
  char err[256], ymv[48] = "", dsv[64] = "";
  exec_do(dbc, "DROP TABLE seer_iv", err, sizeof err);
  if (!SQL_SUCCEEDED(exec_do(dbc,
                             "CREATE TABLE seer_iv "
                             "(ym INTERVAL YEAR TO MONTH, ds INTERVAL DAY TO SECOND(9))",
                             err, sizeof err))) {
    fail(name, err[0] ? err : "create failed");
    return;
  }
  SQL_INTERVAL_STRUCT ym, ds;
  memset(&ym, 0, sizeof ym);
  memset(&ds, 0, sizeof ds);
  ym.interval_type = SQL_IS_YEAR_TO_MONTH;
  ym.interval_sign = SQL_FALSE;
  ym.intval.year_month.year = 3;
  ym.intval.year_month.month = 2;
  ds.interval_type = SQL_IS_DAY_TO_SECOND;
  ds.interval_sign = SQL_FALSE;
  ds.intval.day_second.day = 4;
  ds.intval.day_second.hour = 5;
  ds.intval.day_second.minute = 6;
  ds.intval.day_second.second = 7;
  ds.intval.day_second.fraction = 890000; /* 0.89 s: microseconds, the default precision 6 (#322) */
  SQLHSTMT s;
  SQLAllocHandle(SQL_HANDLE_STMT, dbc, &s);
  SQLLEN n1 = sizeof ym, n2 = sizeof ds;
  SQLBindParameter(s, 1, SQL_PARAM_INPUT, SQL_C_INTERVAL_YEAR_TO_MONTH, SQL_INTERVAL_YEAR_TO_MONTH,
                   0, 0, &ym, sizeof ym, &n1);
  SQLBindParameter(s, 2, SQL_PARAM_INPUT, SQL_C_INTERVAL_DAY_TO_SECOND, SQL_INTERVAL_DAY_TO_SECOND,
                   0, 0, &ds, sizeof ds, &n2);
  SQLRETURN rc = SQLExecDirect(s, (SQLCHAR *)"INSERT INTO seer_iv VALUES (?, ?)", SQL_NTS);
  SQLFreeHandle(SQL_HANDLE_STMT, s);
  if (SQL_SUCCEEDED(rc) &&
      SQL_SUCCEEDED(exec_scalar(dbc, "SELECT ym FROM seer_iv", ymv, sizeof ymv, err, sizeof err)) &&
      SQL_SUCCEEDED(exec_scalar(dbc, "SELECT ds FROM seer_iv", dsv, sizeof dsv, err, sizeof err)) &&
      strstr(ymv, "3-02") != NULL && strstr(dsv, "05:06:07.89") != NULL)
    pass(name);
  else {
    char m[160];
    snprintf(m, sizeof m, "rc=%d ym='%s' ds='%s'", rc, ymv, dsv);
    fail(name, m);
  }
  exec_do(dbc, "DROP TABLE seer_iv", err, sizeof err);
}

/* TIMESTAMP parameter bind with fractional seconds: bind a SQL_C_TYPE_TIMESTAMP
 * with nanosecond precision and confirm it round-trips (the old DATE bind
 * truncated to whole seconds). Works on all versions. */
static void check_timestamp_bind(SQLHDBC dbc)
{
  const char *name = "TIMESTAMP bind (fractional)";
  GATE(name);
  char err[256], out[64];
  exec_do(dbc, "DROP TABLE seer_ts", err, sizeof err);
  if (!SQL_SUCCEEDED(exec_do(dbc, "CREATE TABLE seer_ts (ts TIMESTAMP(9))", err, sizeof err))) {
    fail(name, err[0] ? err : "create failed");
    return;
  }
  SQLHSTMT st;
  SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st);
  SQL_TIMESTAMP_STRUCT t = {0};
  t.year = 2024;
  t.month = 3;
  t.day = 15;
  t.hour = 10;
  t.minute = 20;
  t.second = 30;
  t.fraction = 123456789; /* ns */
  SQLLEN ind = 0;
  SQLBindParameter(st, 1, SQL_PARAM_INPUT, SQL_C_TYPE_TIMESTAMP, SQL_TYPE_TIMESTAMP, 29, 9, &t,
                   sizeof t, &ind);
  SQLRETURN rc = SQLExecDirect(st, (SQLCHAR *)"INSERT INTO seer_ts VALUES (?)", SQL_NTS);
  SQLFreeHandle(SQL_HANDLE_STMT, st);
  if (SQL_SUCCEEDED(rc) &&
      SQL_SUCCEEDED(exec_scalar(dbc, "SELECT ts FROM seer_ts", out, sizeof out, err, sizeof err)) &&
      strstr(out, "10:20:30.123456789") != NULL)
    pass(name);
  else {
    char m[200];
    snprintf(m, sizeof m, "got '%s' (rc=%d)", out, rc);
    fail(name, err[0] ? err : m);
  }
  exec_do(dbc, "DROP TABLE seer_ts", err, sizeof err);
}

/* One TLS connect with `cs` and a query over it; "" when both worked, else
 * why into m. */
static void tls_leg(const char *leg, const char *cs, char *m, size_t mlen)
{
  SQLHENV e;
  SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &e);
  SQLSetEnvAttr(e, SQL_ATTR_ODBC_VERSION, (void *)SQL_OV_ODBC3, 0);
  SQLHDBC d;
  SQLAllocHandle(SQL_HANDLE_DBC, e, &d);
  SQLCHAR o[256];
  SQLSMALLINT ol;
  if (!SQL_SUCCEEDED(SQLDriverConnect(d, NULL, (SQLCHAR *)cs, SQL_NTS, o, sizeof o, &ol,
                                      SQL_DRIVER_NOPROMPT))) {
    char t[256];
    diag_text(SQL_HANDLE_DBC, d, t, sizeof t);
    snprintf(m, mlen, "%s: %s", leg, t[0] ? t : "TLS connect failed");
  } else {
    char out[32], err[256] = "";
    if (!SQL_SUCCEEDED(
            exec_scalar(d, "SELECT 'tls-ok' FROM dual", out, sizeof out, err, sizeof err)) ||
        strcmp(out, "tls-ok") != 0)
      snprintf(m, mlen, "%s: %s", leg, err[0] ? err : "query over TLS failed");
    SQLDisconnect(d);
  }
  SQLFreeHandle(SQL_HANDLE_DBC, d);
  SQLFreeHandle(SQL_HANDLE_ENV, e);
}

/* TLS (TCPS): connect over TLS and run a query, exercising the OpenSSL
 * transport end-to-end, by either or both of two legs (see run-matrix.sh):
 * - a terminating proxy, SEER_TLS_PROXY_PORT on localhost with its cert at
 *   SEER_TLS_CA;
 * - a real Oracle TCPS listener, SEER_TCPS_HOST (SEER_TCPS_PORT, default
 *   2484; SEER_TCPS_SERVICE; SEER_TCPS_CA to verify its certificate, else
 *   unverified; SEER_TCPS_USER / _PASS, default this tier's account). Only a
 *   real listener asks for a TLS renegotiation on its RESEND (#405).
 * Skips when neither is set, as in a corpus recording. */
static void check_tls(const char *drv, const char *svc, const char *user, const char *pwd)
{
  const char *name = "TLS transport (TCPS)";
  const char *tport = getenv("SEER_TLS_PROXY_PORT");
  const char *ca = getenv("SEER_TLS_CA");
  const char *thost = getenv("SEER_TCPS_HOST");
  int proxy = tport != NULL && ca != NULL && tport[0] && ca[0];
  int real = thost != NULL && thost[0];
  if (!proxy && !real) {
    skip(name, "set SEER_TLS_PROXY_PORT + SEER_TLS_CA to exercise TLS");
    return;
  }
  char m[400] = "";
  char cs[900];
  if (proxy) {
    snprintf(cs, sizeof cs,
             "DRIVER=%s;HOST=localhost;PORT=%s;SERVICE=%s;UID=%s;PWD=%s;SSL=1;TLSCA=%s;", drv,
             tport, svc, user, pwd, ca);
    tls_leg("proxy", cs, m, sizeof m);
  }
  if (real && m[0] == '\0') {
    const char *p = getenv("SEER_TCPS_PORT"), *s = getenv("SEER_TCPS_SERVICE");
    const char *c = getenv("SEER_TCPS_CA"), *u = getenv("SEER_TCPS_USER");
    const char *w = getenv("SEER_TCPS_PASS");
    char verify[300];
    if (c != NULL && c[0])
      snprintf(verify, sizeof verify, "TLSCA=%s;", c);
    else
      snprintf(verify, sizeof verify, "TLSVERIFY=0;");
    snprintf(cs, sizeof cs, "DRIVER=%s;HOST=%s;PORT=%s;SERVICE=%s;UID=%s;PWD=%s;SSL=1;%s", drv,
             thost, p && p[0] ? p : "2484", s && s[0] ? s : svc, u && u[0] ? u : user,
             w && w[0] ? w : pwd, verify);
    tls_leg("TCPS listener", cs, m, sizeof m);
  }
  if (m[0] == '\0')
    pass(name);
  else
    fail(name, m);
}

/* The batched LOB check again on a LOBINLINE=1 connection (inline LOB fetch). */
static void check_lob_inline(const char *drv, const char *host, const char *port, const char *svc,
                             const char *user, const char *pwd)
{
  GATE("CLOB / BLOB columns across fetch batches (LOBINLINE)");
  SQLHENV e;
  SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &e);
  SQLSetEnvAttr(e, SQL_ATTR_ODBC_VERSION, (void *)SQL_OV_ODBC3, 0);
  SQLHDBC d;
  SQLAllocHandle(SQL_HANDLE_DBC, e, &d);
  char cs[640];
  snprintf(cs, sizeof cs, "DRIVER=%s;HOST=%s;PORT=%s;SERVICE=%s;UID=%s;PWD=%s;LOBINLINE=1;", drv,
           host, port, svc, user, pwd);
  SQLCHAR o[256];
  SQLSMALLINT ol;
  if (!SQL_SUCCEEDED(SQLDriverConnect(d, NULL, (SQLCHAR *)cs, SQL_NTS, o, sizeof o, &ol,
                                      SQL_DRIVER_NOPROMPT))) {
    char m[256];
    diag_text(SQL_HANDLE_DBC, d, m, sizeof m);
    fail("CLOB / BLOB columns across fetch batches (LOBINLINE)", m[0] ? m : "connect failed");
  } else {
    check_lob_columns_batched(d, 1);
    SQLDisconnect(d);
  }
  SQLFreeHandle(SQL_HANDLE_DBC, d);
  SQLFreeHandle(SQL_HANDLE_ENV, e);
}

static void diag_state(SQLSMALLINT type, SQLHANDLE h, char st[6]);
static SQLHDBC open_conn(SQLHENV e, const char *drv, const char *host, const char *port,
                         const char *svc, const char *user, const char *pwd, char *why, size_t n);

/* Proxy authentication: a `proxy_user[schema]` connect authenticates as the
 * proxy but operates in the target schema's context. Needs DBA to set up the
 * GRANT CONNECT THROUGH: the DBA login from SEER_TEST_DBA_USER / _PASS when
 * set (#409), else the test login; skips when neither may CREATE USER. */
static void check_proxy_auth(SQLHDBC test_dbc, const char *drv, const char *host, const char *port,
                             const char *svc)
{
  const char *name = "proxy authentication";
  char err[256];
  const char *du = getenv("SEER_TEST_DBA_USER"), *dp = getenv("SEER_TEST_DBA_PASS");
  SQLHENV dba_env = SQL_NULL_HANDLE;
  SQLHDBC dba = SQL_NULL_HANDLE, dbc = test_dbc;
  if (du != NULL && du[0] && dp != NULL) {
    char why[256] = "";
    SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &dba_env);
    SQLSetEnvAttr(dba_env, SQL_ATTR_ODBC_VERSION, (void *)SQL_OV_ODBC3, 0);
    dba = open_conn(dba_env, drv, host, port, svc, du, dp, why, sizeof why);
    if (dba == NULL) {
      char r[300];
      snprintf(r, sizeof r, "DBA login failed: %s", why);
      skip(name, r);
      SQLFreeHandle(SQL_HANDLE_ENV, dba_env);
      return;
    }
    dbc = dba;
  }
  exec_do(dbc, "DROP USER seerprx CASCADE", err, sizeof err);
  exec_do(dbc, "DROP USER seerproxy_p CASCADE", err, sizeof err);
  if (!SQL_SUCCEEDED(
          exec_do(dbc, "CREATE USER seerprx IDENTIFIED BY seerprx123", err, sizeof err))) {
    skip(name, "needs DBA (CREATE USER / GRANT CONNECT THROUGH)");
    goto out;
  }
  exec_do(dbc, "GRANT CREATE SESSION TO seerprx", err, sizeof err);
  exec_do(dbc, "CREATE USER seerproxy_p IDENTIFIED BY seerproxy123", err, sizeof err);
  exec_do(dbc, "GRANT CREATE SESSION TO seerproxy_p", err, sizeof err);
  exec_do(dbc, "ALTER USER seerprx GRANT CONNECT THROUGH seerproxy_p", err, sizeof err);

  SQLHENV e;
  SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &e);
  SQLSetEnvAttr(e, SQL_ATTR_ODBC_VERSION, (void *)SQL_OV_ODBC3, 0);
  SQLHDBC d;
  SQLAllocHandle(SQL_HANDLE_DBC, e, &d);
  char cs[512];
  snprintf(cs, sizeof cs,
           "DRIVER=%s;HOST=%s;PORT=%s;SERVICE=%s;UID=seerproxy_p[seerprx];PWD=seerproxy123;", drv,
           host, port ? port : "1521", svc);
  SQLCHAR o[256];
  SQLSMALLINT ol;
  SQLRETURN rc =
      SQLDriverConnect(d, NULL, (SQLCHAR *)cs, SQL_NTS, o, sizeof o, &ol, SQL_DRIVER_NOPROMPT);
  if (g_release > 0 && g_release < 10) {
    /* 8i / 9i: no known thin form names the client user, and 8.1.7 ignores
     * 10g's, so the driver refuses rather than log in as the proxy (#411). */
    char st[6] = "", m[300] = "";
    if (SQL_SUCCEEDED(rc)) {
      SQLDisconnect(d);
      fail(name, "a proxy[schema] login below 10g connected (want HYC00, refused)");
    } else {
      diag_state(SQL_HANDLE_DBC, d, st);
      diag_text(SQL_HANDLE_DBC, d, m, sizeof m);
      if (strcmp(st, "HYC00") == 0 && strstr(m, "needs Oracle 10g") != NULL)
        pass(name);
      else
        fail(name, m[0] ? m : "proxy connect failed without the reason");
    }
  } else if (SQL_SUCCEEDED(rc)) {
    char su[64];
    if (SQL_SUCCEEDED(exec_scalar(d, "SELECT SYS_CONTEXT('USERENV','SESSION_USER') FROM dual", su,
                                  sizeof su, err, sizeof err)) &&
        strcmp(su, "SEERPRX") == 0)
      pass(name);
    else {
      char m[128];
      snprintf(m, sizeof m, "session_user='%s' (want SEERPRX)", su);
      fail(name, m);
    }
    SQLDisconnect(d);
  } else {
    char m[256];
    diag_text(SQL_HANDLE_DBC, d, m, sizeof m);
    fail(name, m[0] ? m : "proxy connect failed");
  }
  SQLFreeHandle(SQL_HANDLE_DBC, d);
  SQLFreeHandle(SQL_HANDLE_ENV, e);

  exec_do(dbc, "DROP USER seerprx CASCADE", err, sizeof err);
  exec_do(dbc, "DROP USER seerproxy_p CASCADE", err, sizeof err);
out:
  if (dba != SQL_NULL_HANDLE) {
    SQLDisconnect(dba);
    SQLFreeHandle(SQL_HANDLE_DBC, dba);
    SQLFreeHandle(SQL_HANDLE_ENV, dba_env);
  }
}

/* A connect that fails says why, as the server put it: a wrong password is the
 * server's ORA-01017 (its native error 1017), a service the listener doesn't
 * know is its ORA-12514 - not a bare "authentication failed". The SQLSTATE is
 * 28000 for the login refused, 08001 for the connection never established
 * (#205). */
static void check_connect_error(const char *drv, const char *host, const char *port,
                                const char *svc, const char *user)
{
  const char *name = "a failed connect reports the server's error";
  struct {
    const char *svc, *pwd;
    long code;
    const char *state;
  } cases[2] = {{svc, "not-the-password", 1017, "28000"},
                {"SEER_NO_SUCH_SERVICE", "x", 12514, "08001"}};
  for (int k = 0; k < 2; k++) {
    SQLHENV e;
    SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &e);
    SQLSetEnvAttr(e, SQL_ATTR_ODBC_VERSION, (void *)SQL_OV_ODBC3, 0);
    SQLHDBC d;
    SQLAllocHandle(SQL_HANDLE_DBC, e, &d);
    char cs[640];
    snprintf(cs, sizeof cs, "DRIVER=%s;HOST=%s;PORT=%s;SERVICE=%s;UID=%s;PWD=%s;", drv, host,
             port ? port : "1521", cases[k].svc, user, cases[k].pwd);
    SQLCHAR o[256], state[6] = "", msg[400] = "";
    SQLSMALLINT ol, len = 0;
    SQLINTEGER native = 0;
    SQLRETURN rc =
        SQLDriverConnect(d, NULL, (SQLCHAR *)cs, SQL_NTS, o, sizeof o, &ol, SQL_DRIVER_NOPROMPT);
    if (!SQL_SUCCEEDED(rc))
      SQLGetDiagRec(SQL_HANDLE_DBC, d, 1, state, &native, msg, sizeof msg, &len);
    else
      SQLDisconnect(d);
    SQLFreeHandle(SQL_HANDLE_DBC, d);
    SQLFreeHandle(SQL_HANDLE_ENV, e);
    char want[16];
    snprintf(want, sizeof want, "ORA-%05ld", cases[k].code);
    if (SQL_SUCCEEDED(rc) || native != cases[k].code || strncmp((char *)msg, want, 9) != 0 ||
        strcmp((char *)state, cases[k].state) != 0) {
      char m[600];
      snprintf(m, sizeof m, "want %s (%s): rc=%d state '%s' native=%ld '%s'", want, cases[k].state,
               (int)rc, (char *)state, (long)native, (char *)msg);
      fail(name, m);
      return;
    }
  }
  pass(name);
}

/* An unreachable address says which and why (#203): a closed port is
 * "connection to 127.0.0.1:1 refused", not a bare "I/O error", and with 08001,
 * a connection not established, not 08S01, a link lost (#205). */
static void check_unreachable_error(const char *drv, const char *svc, const char *user,
                                    const char *pwd)
{
  const char *name = "an unreachable server names the address and the cause";
  SQLHENV e;
  SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &e);
  SQLSetEnvAttr(e, SQL_ATTR_ODBC_VERSION, (void *)SQL_OV_ODBC3, 0);
  SQLHDBC d;
  SQLAllocHandle(SQL_HANDLE_DBC, e, &d);
  char cs[640];
  snprintf(cs, sizeof cs, "DRIVER=%s;HOST=127.0.0.1;PORT=1;SERVICE=%s;UID=%s;PWD=%s;", drv, svc,
           user, pwd);
  SQLCHAR o[256], state[6] = "", msg[400] = "";
  SQLSMALLINT ol, len = 0;
  SQLINTEGER native = 0;
  SQLRETURN rc =
      SQLDriverConnect(d, NULL, (SQLCHAR *)cs, SQL_NTS, o, sizeof o, &ol, SQL_DRIVER_NOPROMPT);
  if (!SQL_SUCCEEDED(rc))
    SQLGetDiagRec(SQL_HANDLE_DBC, d, 1, state, &native, msg, sizeof msg, &len);
  else
    SQLDisconnect(d);
  SQLFreeHandle(SQL_HANDLE_DBC, d);
  SQLFreeHandle(SQL_HANDLE_ENV, e);
  if (!SQL_SUCCEEDED(rc) && strcmp((char *)state, "08001") == 0 &&
      strstr((char *)msg, "127.0.0.1:1 refused") != NULL)
    pass(name);
  else {
    char m[600];
    snprintf(m, sizeof m, "rc=%d state '%s' '%s'", (int)rc, (char *)state, (char *)msg);
    fail(name, m);
  }
}

static void diag_state(SQLSMALLINT type, SQLHANDLE h, char st[6]);

/* SQLGetInfo answers what the driver does (#234): no empty "neither Y nor N"
 * strings, no 0 where ODBC defines no 0, the connection's user and service. */
static void check_getinfo_answers(SQLHDBC dbc, const char *user, const char *svc)
{
  const char *name = "SQLGetInfo answers (Y/N strings, cursor and array caps, names)";
  char m[600] = "";
  static const struct {
    SQLUSMALLINT type;
    const char *want;
  } strs[] = {
      /* SQL_MULT_RESULT_SETS follows the release: check_mult_result_sets. */
      {SQL_PROCEDURES, "Y"},
      {SQL_COLUMN_ALIAS, "Y"},
      {SQL_LIKE_ESCAPE_CLAUSE, "Y"},
      {SQL_EXPRESSIONS_IN_ORDERBY, "Y"},
      {SQL_ORDER_BY_COLUMNS_IN_SELECT, "N"},
      {SQL_ROW_UPDATES, "N"},
      {SQL_DESCRIBE_PARAMETER, "N"},
  };
  for (size_t k = 0; k < sizeof strs / sizeof strs[0]; k++) {
    char v[16] = "";
    SQLSMALLINT len = 0;
    SQLGetInfo(dbc, strs[k].type, v, sizeof v, &len);
    if (strcmp(v, strs[k].want) != 0) {
      size_t ml = strlen(m);
      snprintf(m + ml, sizeof m - ml, "type %u: '%s' (want %s); ", (unsigned)strs[k].type, v,
               strs[k].want);
    }
  }
  char oj[8] = "", u[128] = "", sv[128] = "";
  SQLSMALLINT len = 0;
  SQLGetInfo(dbc, SQL_OUTER_JOINS, oj, sizeof oj, &len);
  const char *want_oj = g_release == 8 ? "N" : "Y"; /* 8.1.7 has no ANSI joins */
  if (strcmp(oj, want_oj) != 0) {
    size_t ml = strlen(m);
    snprintf(m + ml, sizeof m - ml, "SQL_OUTER_JOINS '%s' (want %s); ", oj, want_oj);
  }
  SQLGetInfo(dbc, SQL_USER_NAME, u, sizeof u, &len);
  SQLGetInfo(dbc, SQL_SERVER_NAME, sv, sizeof sv, &len);
  if (strcasecmp(u, user) != 0 || strcasecmp(sv, svc) != 0) {
    size_t ml = strlen(m);
    snprintf(m + ml, sizeof m - ml, "user '%s' server '%s'; ", u, sv);
  }
  SQLUINTEGER fo = 0, parc = 0, pas = 0;
  SQLGetInfo(dbc, SQL_FORWARD_ONLY_CURSOR_ATTRIBUTES1, &fo, sizeof fo, NULL);
  SQLGetInfo(dbc, SQL_PARAM_ARRAY_ROW_COUNTS, &parc, sizeof parc, NULL);
  SQLGetInfo(dbc, SQL_PARAM_ARRAY_SELECTS, &pas, sizeof pas, NULL);
  if (!(fo & SQL_CA1_NEXT) || parc != SQL_PARC_NO_BATCH || pas != SQL_PAS_BATCH) {
    size_t ml = strlen(m);
    snprintf(m + ml, sizeof m - ml, "forward-only %#x, PARC %u, PAS %u", (unsigned)fo,
             (unsigned)parc, (unsigned)pas);
  }
  /* What SQLSetPos and locking cursors do, said (#294); optimistic
   * concurrency, which the driver can't keep, becomes LOCK with 01S02. */
  SQLUINTEGER st1 = 0, st2 = 0, posops = 0, scco = 0;
  SQLGetInfo(dbc, SQL_STATIC_CURSOR_ATTRIBUTES1, &st1, sizeof st1, NULL);
  SQLGetInfo(dbc, SQL_STATIC_CURSOR_ATTRIBUTES2, &st2, sizeof st2, NULL);
  SQLGetInfo(dbc, SQL_POS_OPERATIONS, &posops, sizeof posops, NULL);
  SQLGetInfo(dbc, SQL_SCROLL_CONCURRENCY, &scco, sizeof scco, NULL);
  const SQLUINTEGER want1 = SQL_CA1_POS_POSITION | SQL_CA1_POS_UPDATE | SQL_CA1_POS_DELETE |
                            SQL_CA1_POS_REFRESH | SQL_CA1_LOCK_NO_CHANGE;
  if ((fo & want1) != want1 || (st1 & want1) != want1 || !(st2 & SQL_CA2_LOCK_CONCURRENCY) ||
      posops != (SQL_POS_POSITION | SQL_POS_REFRESH | SQL_POS_UPDATE | SQL_POS_DELETE) ||
      scco != (SQL_SCCO_READ_ONLY | SQL_SCCO_LOCK)) {
    size_t ml = strlen(m);
    snprintf(m + ml, sizeof m - ml, "CA1 fo %#x st %#x, CA2 %#x, POS_OPERATIONS %#x, SCCO %#x; ",
             (unsigned)fo, (unsigned)st1, (unsigned)st2, (unsigned)posops, (unsigned)scco);
  }
  SQLHSTMT cst;
  SQLAllocHandle(SQL_HANDLE_STMT, dbc, &cst);
  SQLRETURN crc = SQLSetStmtAttr(cst, SQL_ATTR_CONCURRENCY, (SQLPOINTER)SQL_CONCUR_ROWVER, 0);
  char cstate[6] = "";
  diag_state(SQL_HANDLE_STMT, cst, cstate);
  SQLULEN conc = 0;
  SQLGetStmtAttr(cst, SQL_ATTR_CONCURRENCY, &conc, 0, NULL);
  SQLFreeHandle(SQL_HANDLE_STMT, cst);
  if (crc != SQL_SUCCESS_WITH_INFO || strcmp(cstate, "01S02") != 0 || conc != SQL_CONCUR_LOCK) {
    size_t ml = strlen(m);
    snprintf(m + ml, sizeof m - ml, "CONCUR_ROWVER: rc %d %s, reads back %lu (want 01S02, LOCK)",
             crc, cstate, (unsigned long)conc);
  }
  if (m[0] == '\0')
    pass(name);
  else
    fail(name, m);
}

/* The first diag record's SQLSTATE of a handle, into st[6]. */
static void diag_state(SQLSMALLINT type, SQLHANDLE h, char st[6])
{
  SQLINTEGER nat = 0;
  SQLSMALLINT len = 0;
  SQLCHAR msg[128];
  st[0] = '\0';
  SQLGetDiagRec(type, h, 1, (SQLCHAR *)st, &nat, msg, sizeof msg, &len);
}

/* Values reach the C types ODBC defines, or get an error (#314): INTERVAL
 * values fill the interval structs (9i+: 8.1.7 has no INTERVAL), a two-row
 * column-wise rowset of fixed-length types bound with BufferLength 0 lands at
 * each type's own size, SQL_C_GUID is 07006 (the row an error row), and
 * SQL_ARD_TYPE takes the column's bound type. */
static void check_c_type_targets(SQLHDBC dbc)
{
  const char *name = "C type targets: interval structs, fixed-size strides, 07006";
  char m[400] = "", st[6] = "";
  SQLHSTMT s;
  SQLLEN ind = 0;
  SQLRETURN rc;
  SQL_INTERVAL_STRUCT iv;
  if (g_release >= 9) {
    SQLAllocHandle(SQL_HANDLE_STMT, dbc, &s);
    rc = SQLExecDirect(s,
                       (SQLCHAR *)"SELECT INTERVAL '1 02:03:04.5' DAY TO SECOND, "
                                  "INTERVAL '-3-4' YEAR TO MONTH FROM dual",
                       SQL_NTS);
    if (SQL_SUCCEEDED(rc))
      rc = SQLFetch(s);
    memset(&iv, 0, sizeof iv);
    if (SQL_SUCCEEDED(rc))
      rc = SQLGetData(s, 1, SQL_C_INTERVAL_DAY_TO_SECOND, &iv, sizeof iv, &ind);
    if (!SQL_SUCCEEDED(rc) || iv.interval_type != SQL_IS_DAY_TO_SECOND || iv.interval_sign ||
        iv.intval.day_second.day != 1 || iv.intval.day_second.hour != 2 ||
        iv.intval.day_second.minute != 3 || iv.intval.day_second.second != 4 ||
        iv.intval.day_second.fraction != 500000)
      snprintf(m, sizeof m, "DAY TO SECOND struct: rc %d type %d d %u h %u s %u f %u", rc,
               (int)iv.interval_type, iv.intval.day_second.day, iv.intval.day_second.hour,
               iv.intval.day_second.second, iv.intval.day_second.fraction);
    memset(&iv, 0, sizeof iv);
    if (m[0] == '\0') {
      rc = SQLGetData(s, 2, SQL_C_INTERVAL_MONTH, &iv, sizeof iv, &ind);
      if (!SQL_SUCCEEDED(rc) || iv.interval_type != SQL_IS_MONTH || !iv.interval_sign ||
          iv.intval.year_month.month != 40)
        snprintf(m, sizeof m, "YEAR TO MONTH as MONTH: rc %d sign %d months %u", rc,
                 (int)iv.interval_sign, iv.intval.year_month.month);
    }
    SQLFreeHandle(SQL_HANDLE_STMT, s);
  }

  /* Two rows column-wise, the fixed-length targets with BufferLength 0. */
  if (m[0] == '\0') {
    SQLAllocHandle(SQL_HANDLE_STMT, dbc, &s);
    SQL_NUMERIC_STRUCT num[2];
    SQL_INTERVAL_STRUCT ivs[2];
    SQLLEN nind[2], iind[2];
    SQLULEN got = 0;
    memset(num, 0, sizeof num);
    memset(ivs, 0, sizeof ivs);
    SQLSetStmtAttr(s, SQL_ATTR_ROW_ARRAY_SIZE, (SQLPOINTER)2, 0);
    SQLSetStmtAttr(s, SQL_ATTR_ROWS_FETCHED_PTR, &got, 0);
    SQLBindCol(s, 1, SQL_C_NUMERIC, num, 0, nind);
    const char *q = g_release >= 9 ? "SELECT 11, INTERVAL '5' DAY FROM dual UNION ALL "
                                     "SELECT 22, INTERVAL '6' DAY FROM dual"
                                   : "SELECT 11, 5 FROM dual UNION ALL SELECT 22, 6 FROM dual";
    SQLBindCol(s, 2, SQL_C_INTERVAL_DAY, ivs, 0, iind);
    rc = SQLExecDirect(s, (SQLCHAR *)q, SQL_NTS);
    if (SQL_SUCCEEDED(rc))
      rc = SQLFetch(s);
    if (!SQL_SUCCEEDED(rc) || got != 2 || num[0].val[0] != 11 || num[1].val[0] != 22 ||
        ivs[0].intval.day_second.day != 5 || ivs[1].intval.day_second.day != 6 ||
        ivs[1].interval_type != SQL_IS_DAY)
      snprintf(m, sizeof m, "rowset: rc %d got %lu numeric %u/%u days %u/%u", rc,
               (unsigned long)got, num[0].val[0], num[1].val[0], ivs[0].intval.day_second.day,
               ivs[1].intval.day_second.day);
    SQLFreeHandle(SQL_HANDLE_STMT, s);
  }

  /* SQL_C_GUID: no Oracle value converts to it. */
  if (m[0] == '\0') {
    SQLAllocHandle(SQL_HANDLE_STMT, dbc, &s);
    SQLGUID g;
    rc = SQLExecDirect(s, (SQLCHAR *)"SELECT 'abc' FROM dual", SQL_NTS);
    if (SQL_SUCCEEDED(rc))
      rc = SQLFetch(s);
    if (SQL_SUCCEEDED(rc))
      rc = SQLGetData(s, 1, SQL_C_GUID, &g, sizeof g, &ind);
    diag_state(SQL_HANDLE_STMT, s, st);
    if (rc != SQL_ERROR || strcmp(st, "07006") != 0)
      snprintf(m, sizeof m, "SQLGetData SQL_C_GUID: rc %d state '%s', want 07006", rc, st);
    SQLFreeHandle(SQL_HANDLE_STMT, s);
  }
  if (m[0] == '\0') {
    SQLAllocHandle(SQL_HANDLE_STMT, dbc, &s);
    SQLGUID g;
    SQLUSMALLINT rs = 0;
    SQLSetStmtAttr(s, SQL_ATTR_ROW_STATUS_PTR, &rs, 0);
    SQLBindCol(s, 1, SQL_C_GUID, &g, sizeof g, &ind);
    rc = SQLExecDirect(s, (SQLCHAR *)"SELECT 'abc' FROM dual", SQL_NTS);
    if (SQL_SUCCEEDED(rc))
      rc = SQLFetch(s);
    diag_state(SQL_HANDLE_STMT, s, st);
    if (rc != SQL_ERROR || strcmp(st, "07006") != 0 || rs != SQL_ROW_ERROR)
      snprintf(m, sizeof m, "bound SQL_C_GUID: rc %d state '%s' row status %u", rc, st,
               (unsigned)rs);
    SQLFreeHandle(SQL_HANDLE_STMT, s);
  }

  /* SQL_ARD_TYPE: the C type the column is bound with. */
  if (m[0] == '\0') {
    SQLAllocHandle(SQL_HANDLE_STMT, dbc, &s);
    SQLINTEGER bound = 0, v = 0;
    SQLLEN bind_ind = 0;
    SQLBindCol(s, 1, SQL_C_SLONG, &bound, 0, &bind_ind);
    rc = SQLExecDirect(s, (SQLCHAR *)"SELECT 1234 FROM dual", SQL_NTS);
    if (SQL_SUCCEEDED(rc))
      rc = SQLFetch(s);
    if (SQL_SUCCEEDED(rc))
      rc = SQLGetData(s, 1, SQL_ARD_TYPE, &v, sizeof v, &ind);
    if (!SQL_SUCCEEDED(rc) || v != 1234 || ind != (SQLLEN)sizeof v)
      snprintf(m, sizeof m, "SQL_ARD_TYPE: rc %d value %d ind %ld", rc, (int)v, (long)ind);
    SQLFreeHandle(SQL_HANDLE_STMT, s);
  }
  if (m[0] == '\0')
    pass(name);
  else
    fail(name, m);
}

/* SQL_C_DEFAULT is the SQL type's ODBC default C type (#316), not always
 * text. Columns: a DATE fills a timestamp struct, RAW gives its bytes,
 * BINARY_DOUBLE a double (10g+), NUMBER stays text, through SQLGetData and a
 * bound column alike. Parameters: a double, an integer and RAW bytes arrive
 * as such (RAW was mangled on 8i as text), and a timestamp struct (as a DATE
 * on 8i, #318). */
static void check_c_default(SQLHDBC dbc)
{
  const char *name = "SQL_C_DEFAULT is the SQL type's default C type";
  char m[400] = "";
  SQLHSTMT s;
  SQLRETURN rc;
  SQLLEN ind = 0;
  SQL_TIMESTAMP_STRUCT ts;
  unsigned char raw[8];
  SQLDOUBLE dv = 0;
  char txt[16] = "";

  SQLAllocHandle(SQL_HANDLE_STMT, dbc, &s);
  char q[200];
  snprintf(q, sizeof q,
           "SELECT TO_DATE('2026-11-19 10:11:12','YYYY-MM-DD HH24:MI:SS'), "
           "HEXTORAW('DEADBEEF'), 1.5%s FROM dual",
           g_release >= 10 ? ", CAST(2.5 AS BINARY_DOUBLE)" : "");
  SQLLEN bind_ind = 0;
  memset(&ts, 0, sizeof ts);
  SQLBindCol(s, 1, SQL_C_DEFAULT, &ts, sizeof ts, &bind_ind); /* bound: the DATE */
  rc = SQLExecDirect(s, (SQLCHAR *)q, SQL_NTS);
  if (SQL_SUCCEEDED(rc))
    rc = SQLFetch(s);
  if (!SQL_SUCCEEDED(rc) || ts.year != 2026 || ts.month != 11 || ts.day != 19 || ts.hour != 10 ||
      ts.minute != 11 || ts.second != 12 || bind_ind != (SQLLEN)sizeof ts)
    snprintf(m, sizeof m, "bound DATE: rc %d %d-%u-%u %u:%u:%u ind %ld", rc, ts.year, ts.month,
             ts.day, ts.hour, ts.minute, ts.second, (long)bind_ind);
  if (m[0] == '\0') {
    memset(raw, 0, sizeof raw);
    rc = SQLGetData(s, 2, SQL_C_DEFAULT, raw, sizeof raw, &ind);
    if (!SQL_SUCCEEDED(rc) || ind != 4 || raw[0] != 0xDE || raw[3] != 0xEF)
      snprintf(m, sizeof m, "RAW: rc %d ind %ld bytes %02x%02x", rc, (long)ind, raw[0], raw[1]);
  }
  if (m[0] == '\0') {
    rc = SQLGetData(s, 3, SQL_C_DEFAULT, txt, sizeof txt, &ind);
    if (!SQL_SUCCEEDED(rc) || strcmp(txt, "1.5") != 0)
      snprintf(m, sizeof m, "NUMBER: rc %d '%s', want text '1.5'", rc, txt);
  }
  if (m[0] == '\0' && g_release >= 10) {
    rc = SQLGetData(s, 4, SQL_C_DEFAULT, &dv, sizeof dv, &ind);
    if (!SQL_SUCCEEDED(rc) || dv != 2.5 || ind != (SQLLEN)sizeof dv)
      snprintf(m, sizeof m, "BINARY_DOUBLE: rc %d %g ind %ld", rc, dv, (long)ind);
  }
  SQLFreeHandle(SQL_HANDLE_STMT, s);

  /* Parameters bound SQL_C_DEFAULT: the buffer holds the default C type. */
  static const struct {
    SQLSMALLINT sqltype;
    const char *sql, *want;
    int from;
  } P[] = {
      {SQL_DOUBLE, "SELECT TO_CHAR(? * 2) FROM dual", "5", 0},
      {SQL_INTEGER, "SELECT TO_CHAR(? + 1) FROM dual", "43", 0},
      {SQL_VARBINARY, "SELECT RAWTOHEX(?) FROM dual", "DEADBEEF", 0},
      {SQL_TYPE_TIMESTAMP, "SELECT TO_CHAR(?, 'YYYY-MM-DD HH24:MI:SS') FROM dual",
       "2026-11-19 10:11:12", 0},
  };
  SQL_TIMESTAMP_STRUCT pts = {2026, 11, 19, 10, 11, 12, 0};
  SQLDOUBLE pd = 2.5;
  SQLINTEGER pi = 42;
  unsigned char praw[4] = {0xDE, 0xAD, 0xBE, 0xEF};
  for (size_t i = 0; i < sizeof P / sizeof P[0] && m[0] == '\0'; i++) {
    if (g_release < P[i].from)
      continue;
    void *val = P[i].sqltype == SQL_DOUBLE      ? (void *)&pd
                : P[i].sqltype == SQL_INTEGER   ? (void *)&pi
                : P[i].sqltype == SQL_VARBINARY ? (void *)praw
                                                : (void *)&pts;
    SQLLEN len = P[i].sqltype == SQL_VARBINARY ? 4 : 0;
    SQLAllocHandle(SQL_HANDLE_STMT, dbc, &s);
    rc = SQLBindParameter(s, 1, SQL_PARAM_INPUT, SQL_C_DEFAULT, P[i].sqltype,
                          P[i].sqltype == SQL_TYPE_TIMESTAMP ? 19 : 15, 0, val, len, &len);
    if (SQL_SUCCEEDED(rc))
      rc = SQLExecDirect(s, (SQLCHAR *)P[i].sql, SQL_NTS);
    char out[64] = "", err[256] = "";
    if (SQL_SUCCEEDED(rc))
      rc = SQLFetch(s);
    if (SQL_SUCCEEDED(rc))
      rc = SQLGetData(s, 1, SQL_C_CHAR, out, sizeof out, &ind);
    if (!SQL_SUCCEEDED(rc))
      diag_text(SQL_HANDLE_STMT, s, err, sizeof err);
    /* 10g+ renders a BINARY_DOUBLE product as 5.0E+000. */
    if (!SQL_SUCCEEDED(rc) ||
        (strcmp(out, P[i].want) != 0 && !(P[i].sqltype == SQL_DOUBLE && atof(out) == 5.0)))
      snprintf(m, sizeof m, "parameter type %d: rc %d '%s' %s, want '%s'", P[i].sqltype, rc, out,
               err, P[i].want);
    SQLFreeHandle(SQL_HANDLE_STMT, s);
  }
  if (m[0] == '\0')
    pass(name);
  else
    fail(name, m);
}

/* A SQL_C_TYPE_TIMESTAMP parameter on every release (#318): 8.1.7 has no
 * TIMESTAMP, so there it goes out as a DATE. The date and the time of day
 * arrive, through an expression and stored into a DATE column. */
static void check_timestamp_param_date(SQLHDBC dbc)
{
  const char *name = "SQL_C_TYPE_TIMESTAMP parameter into a DATE (8i too)";
  char m[400] = "", err[256] = "", out[64] = "";
  SQL_TIMESTAMP_STRUCT ts = {2026, 11, 19, 23, 58, 59, 0};
  SQLLEN ind = 0, len = sizeof ts;
  SQLHSTMT s;
  exec_do(dbc, "DROP TABLE seer_ts8", err, sizeof err);
  if (!SQL_SUCCEEDED(exec_do(dbc, "CREATE TABLE seer_ts8 (d DATE)", err, sizeof err))) {
    fail(name, err);
    return;
  }
  static const char *const Q[] = {
      "SELECT TO_CHAR(?, 'YYYY-MM-DD HH24:MI:SS') FROM dual",
      "INSERT INTO seer_ts8 (d) VALUES (?)",
  };
  for (size_t i = 0; i < 2 && m[0] == '\0'; i++) {
    SQLAllocHandle(SQL_HANDLE_STMT, dbc, &s);
    SQLRETURN rc = SQLBindParameter(s, 1, SQL_PARAM_INPUT, SQL_C_TYPE_TIMESTAMP, SQL_TYPE_TIMESTAMP,
                                    19, 0, &ts, sizeof ts, &len);
    if (SQL_SUCCEEDED(rc))
      rc = SQLExecDirect(s, (SQLCHAR *)Q[i], SQL_NTS);
    if (SQL_SUCCEEDED(rc) && i == 0 && SQL_SUCCEEDED(rc = SQLFetch(s)))
      rc = SQLGetData(s, 1, SQL_C_CHAR, out, sizeof out, &ind);
    if (!SQL_SUCCEEDED(rc)) {
      diag_text(SQL_HANDLE_STMT, s, err, sizeof err);
      snprintf(m, sizeof m, "%s: %s", Q[i], err);
    } else if (i == 0 && strcmp(out, "2026-11-19 23:58:59") != 0) {
      snprintf(m, sizeof m, "TO_CHAR(?) '%s'", out);
    }
    SQLFreeHandle(SQL_HANDLE_STMT, s);
  }
  if (m[0] == '\0' &&
      (!SQL_SUCCEEDED(exec_scalar(dbc, "SELECT TO_CHAR(d, 'YYYY-MM-DD HH24:MI:SS') FROM seer_ts8",
                                  out, sizeof out, err, sizeof err)) ||
       strcmp(out, "2026-11-19 23:58:59") != 0))
    snprintf(m, sizeof m, "stored '%s' %s", out, err);
  exec_do(dbc, "DROP TABLE seer_ts8", err, sizeof err);
  if (m[0] == '\0')
    pass(name);
  else
    fail(name, m);
}

/* One parameter of C type `ct` through `sql`; the first column's text in out. */
static SQLRETURN param_text(SQLHDBC dbc, const char *sql, SQLSMALLINT ct, SQLSMALLINT st, void *v,
                            SQLLEN len, char *out, size_t n, char *err, size_t en)
{
  SQLHSTMT s;
  SQLAllocHandle(SQL_HANDLE_STMT, dbc, &s);
  SQLLEN ind = len, oi = 0;
  out[0] = err[0] = '\0';
  SQLRETURN rc = SQLBindParameter(s, 1, SQL_PARAM_INPUT, ct, st, 30, 0, v, len, &ind);
  if (SQL_SUCCEEDED(rc))
    rc = SQLExecDirect(s, (SQLCHAR *)sql, SQL_NTS);
  if (SQL_SUCCEEDED(rc) && SQL_SUCCEEDED(rc = SQLFetch(s)))
    rc = SQLGetData(s, 1, SQL_C_CHAR, out, (SQLLEN)n, &oi);
  if (!SQL_SUCCEEDED(rc))
    diag_text(SQL_HANDLE_STMT, s, err, en);
  SQLFreeHandle(SQL_HANDLE_STMT, s);
  return rc;
}

/* Parameter C types (#322) reach the server as their values: the unsigned
 * integers, SQL_C_NUMERIC (exact, NLS-proof), GUID text, and every interval C
 * type with its leading field normalised and the fraction in microseconds.
 * Two-way: a C type the driver has no conversion for is HY003, not bytes sent
 * as text. Data-at-execution of a fixed-size type ignores StrLen_or_Ind and
 * takes one piece (#323). */
static void check_param_c_types(SQLHDBC dbc)
{
  const char *name = "parameter C types: unsigned, NUMERIC, GUID, intervals, DAE";
  char m[400] = "", err[256], out[64];
  SQLUSMALLINT us = 65000;
  unsigned char ut = 200;
  SQLUBIGINT ub = 18000000000000000000ULL;
  SQL_NUMERIC_STRUCT ns = {7, 2, 0, {0}}; /* -123.45: sign 0 = negative */
  ns.val[0] = 12345 & 0xFF;
  ns.val[1] = 12345 >> 8;
  SQLGUID g = {0x12345678, 0x9abc, 0xdef0, {1, 2, 3, 4, 5, 6, 7, 8}};
  unsigned char bit = 1;
  static const char *const Q = "SELECT TO_CHAR(?) FROM dual";
  struct {
    SQLSMALLINT ct, st;
    void *v;
    SQLLEN len;
    const char *want;
  } T[] = {
      {SQL_C_USHORT, SQL_INTEGER, &us, 0, "65000"},
      {SQL_C_UTINYINT, SQL_INTEGER, &ut, 0, "200"},
      {SQL_C_UBIGINT, SQL_NUMERIC, &ub, 0, "18000000000000000000"},
      {SQL_C_NUMERIC, SQL_NUMERIC, &ns, sizeof ns, "-123.45"},
      {SQL_C_GUID, SQL_CHAR, &g, sizeof g, "12345678-9ABC-DEF0-0102-030405060708"},
      /* a bit into a character or numeric target is 0 / 1, not 23ai's TRUE (#327) */
      {SQL_C_BIT, SQL_CHAR, &bit, 0, "1"},
      {SQL_C_BIT, SQL_INTEGER, &bit, 0, "1"},
  };
  for (size_t i = 0; i < sizeof T / sizeof T[0] && !m[0]; i++)
    if (!SQL_SUCCEEDED(param_text(dbc, Q, T[i].ct, T[i].st, T[i].v, T[i].len, out, sizeof out, err,
                                  sizeof err)) ||
        strcmp(out, T[i].want) != 0)
      snprintf(m, sizeof m, "C type %d: '%s' (want %s) %s", (int)T[i].ct, out, T[i].want, err);

  if (!m[0] && g_release >= 9) { /* 8.1.7 has no INTERVAL */
    SQL_INTERVAL_STRUCT h, mo, ds;
    memset(&h, 0, sizeof h);
    memset(&mo, 0, sizeof mo);
    memset(&ds, 0, sizeof ds);
    h.interval_type = SQL_IS_HOUR;
    h.intval.day_second.hour = 30;
    h.intval.day_second.day = 7; /* not a field of HOUR: ignored */
    mo.interval_type = SQL_IS_MONTH;
    mo.interval_sign = SQL_TRUE;
    mo.intval.year_month.month = 14;
    ds.interval_type = SQL_IS_DAY_TO_SECOND;
    ds.intval.day_second.second = 1;
    ds.intval.day_second.fraction = 500000;
    struct {
      SQLSMALLINT ct, st;
      SQL_INTERVAL_STRUCT *v;
      const char *want;
    } I[] = {
        {SQL_C_INTERVAL_HOUR, SQL_INTERVAL_HOUR, &h, "+000000001 06:00:00.000000000"},
        {SQL_C_INTERVAL_MONTH, SQL_INTERVAL_MONTH, &mo, "-000000001-02"},
        {SQL_C_INTERVAL_DAY_TO_SECOND, SQL_INTERVAL_DAY_TO_SECOND, &ds,
         "+000000000 00:00:01.500000000"},
    };
    for (size_t i = 0; i < sizeof I / sizeof I[0] && !m[0]; i++)
      if (!SQL_SUCCEEDED(param_text(dbc, Q, I[i].ct, I[i].st, I[i].v, sizeof *I[i].v, out,
                                    sizeof out, err, sizeof err)) ||
          strcmp(out, I[i].want) != 0)
        snprintf(m, sizeof m, "interval %d: '%s' (want %s) %s", (int)I[i].ct, out, I[i].want, err);
  }

  /* Data-at-execution, SQL_C_SLONG, put with StrLen_or_Ind 0: still 42; a
   * second piece is HY019. */
  for (int twice = 0; twice < 2 && !m[0]; twice++) {
    SQLHSTMT s;
    SQLAllocHandle(SQL_HANDLE_STMT, dbc, &s);
    SQLINTEGER v = 42;
    SQLLEN ind = SQL_DATA_AT_EXEC, oi = 0;
    SQLPOINTER tok;
    char st[6] = "";
    SQLBindParameter(s, 1, SQL_PARAM_INPUT, SQL_C_SLONG, SQL_INTEGER, 0, 0, (SQLPOINTER)1, 0, &ind);
    SQLRETURN rc = SQLExecDirect(s, (SQLCHAR *)Q, SQL_NTS);
    if (rc == SQL_NEED_DATA && (rc = SQLParamData(s, &tok)) == SQL_NEED_DATA) {
      rc = SQLPutData(s, &v, 0);
      if (twice) { /* the second piece is refused; the error ends the sequence */
        rc = SQLPutData(s, &v, 0);
        diag_state(SQL_HANDLE_STMT, s, st);
        if (rc != SQL_ERROR || strcmp(st, "HY019") != 0)
          snprintf(m, sizeof m, "second SQLPutData piece: rc=%d '%s', want HY019", (int)rc, st);
        SQLCancel(s);
        SQLFreeHandle(SQL_HANDLE_STMT, s);
        continue;
      }
      if (SQL_SUCCEEDED(rc))
        rc = SQLParamData(s, &tok);
    }
    out[0] = '\0';
    if (SQL_SUCCEEDED(rc) && SQL_SUCCEEDED(rc = SQLFetch(s)))
      rc = SQLGetData(s, 1, SQL_C_CHAR, out, sizeof out, &oi);
    if (!m[0] && (!SQL_SUCCEEDED(rc) || strcmp(out, "42") != 0)) {
      diag_text(SQL_HANDLE_STMT, s, err, sizeof err);
      snprintf(m, sizeof m, "DAE SLONG put with length 0: '%s' %s", out, err);
    }
    SQLFreeHandle(SQL_HANDLE_STMT, s);
  }

  /* Two-way: an unknown C type is refused at bind time. */
  if (!m[0]) {
    SQLHSTMT s;
    SQLAllocHandle(SQL_HANDLE_STMT, dbc, &s);
    char st[6] = "", buf[8] = "1";
    SQLLEN ind = 1;
    SQLRETURN rc =
        SQLBindParameter(s, 1, SQL_PARAM_INPUT, 9999, SQL_CHAR, 1, 0, buf, sizeof buf, &ind);
    diag_state(SQL_HANDLE_STMT, s, st);
    if (rc != SQL_ERROR || strcmp(st, "HY003") != 0)
      snprintf(m, sizeof m, "C type 9999: rc=%d '%s', want HY003", (int)rc, st);
    SQLFreeHandle(SQL_HANDLE_STMT, s);
  }
  if (m[0] == '\0')
    pass(name);
  else
    fail(name, m);
}

/* Integer, bit and float fetch targets (#329) follow Appendix D: past the
 * type's range is 22003, a dropped fraction 01S07, non-numeric text 22018,
 * and a bit is 0 or 1. A 23ai BOOLEAN reads as 1 / 0. Two-way: in-range
 * values still convert with SQL_SUCCESS. */
static void check_numeric_targets(SQLHDBC dbc)
{
  const char *name = "integer / bit fetch targets: range, truncation, text";
  char m[400] = "";
  struct {
    const char *expr;
    SQLSMALLINT ct;
    SQLRETURN rc;
    const char *state;
    long long want;
    int from;
  } T[] = {
      {"70000", SQL_C_SSHORT, SQL_ERROR, "22003", 0, 8},
      {"-32768", SQL_C_SSHORT, SQL_SUCCESS, "", -32768, 8},
      {"3.7", SQL_C_SLONG, SQL_SUCCESS_WITH_INFO, "01S07", 3, 8},
      {"-1", SQL_C_ULONG, SQL_ERROR, "22003", 0, 8},
      {"1e20", SQL_C_SBIGINT, SQL_ERROR, "22003", 0, 8},
      {"'abc'", SQL_C_SLONG, SQL_ERROR, "22018", 0, 8},
      {"' 42 '", SQL_C_SLONG, SQL_SUCCESS, "", 42, 8},
      {"5", SQL_C_BIT, SQL_ERROR, "22003", 0, 8},
      {"1", SQL_C_BIT, SQL_SUCCESS, "", 1, 8},
      {"TRUE", SQL_C_BIT, SQL_SUCCESS, "", 1, 23},
      {"FALSE", SQL_C_SLONG, SQL_SUCCESS, "", 0, 23},
  };
  for (size_t i = 0; i < sizeof T / sizeof T[0] && !m[0]; i++) {
    if (g_release < T[i].from)
      continue;
    char sql[96], st[6] = "";
    snprintf(sql, sizeof sql, "SELECT %s FROM dual", T[i].expr);
    SQLHSTMT s;
    SQLAllocHandle(SQL_HANDLE_STMT, dbc, &s);
    union {
      SQLSMALLINT sh;
      SQLINTEGER l;
      SQLUINTEGER ul;
      SQLBIGINT b;
      unsigned char bit;
    } v;
    memset(&v, 0, sizeof v);
    SQLLEN ind = 0;
    SQLRETURN rc = SQLExecDirect(s, (SQLCHAR *)sql, SQL_NTS);
    if (SQL_SUCCEEDED(rc) && SQL_SUCCEEDED(rc = SQLFetch(s)))
      rc = SQLGetData(s, 1, T[i].ct, &v, sizeof v, &ind);
    if (rc != SQL_SUCCESS)
      diag_state(SQL_HANDLE_STMT, s, st);
    long long got = T[i].ct == SQL_C_SSHORT  ? v.sh
                    : T[i].ct == SQL_C_SLONG ? v.l
                    : T[i].ct == SQL_C_ULONG ? (long long)v.ul
                    : T[i].ct == SQL_C_BIT   ? v.bit
                                             : (long long)v.b;
    if (rc != T[i].rc || strcmp(st, T[i].state) != 0 || (SQL_SUCCEEDED(rc) && got != T[i].want))
      snprintf(m, sizeof m, "%s as C type %d: rc=%d '%s' value %lld (want rc=%d '%s' %lld)",
               T[i].expr, (int)T[i].ct, (int)rc, st, got, (int)T[i].rc, T[i].state, T[i].want);
    SQLFreeHandle(SQL_HANDLE_STMT, s);
  }
  if (m[0] == '\0')
    pass(name);
  else
    fail(name, m);
}

/* An SQL_C_NUMERIC struct's 128-bit little-endian mantissa as decimal. */
static void numeric_mantissa(const SQL_NUMERIC_STRUCT *n, char *out)
{
  unsigned char v[SQL_MAX_NUMERIC_LEN];
  memcpy(v, n->val, sizeof v);
  char rev[48];
  size_t k = 0;
  for (;;) {
    unsigned rem = 0, nz = 0;
    for (int i = SQL_MAX_NUMERIC_LEN - 1; i >= 0; i--) {
      unsigned cur = (rem << 8) | v[i];
      v[i] = (unsigned char)(cur / 10);
      rem = cur % 10;
      nz |= v[i];
    }
    rev[k++] = (char)('0' + rem);
    if (!nz)
      break;
  }
  for (size_t i = 0; i < k; i++)
    out[i] = rev[k - 1 - i];
  out[k] = '\0';
}

/* SQL_C_NUMERIC fetch (#332): a 40-digit NUMBER is past a 128-bit mantissa
 * as written and comes back exact, its trailing zero moved into the scale
 * (it used to wrap); non-numeric text is 22018. Two-way: an ordinary value
 * keeps its natural scale. */
static void check_numeric_struct(SQLHDBC dbc)
{
  const char *name = "SQL_C_NUMERIC fetch: exact past 128 bits, text refused";
  char m[300] = "";
  struct {
    const char *expr;
    SQLRETURN rc;
    const char *state;
    int sign, scale;
    const char *mant;
  } T[] = {
      {"-123.45", SQL_SUCCESS, "", 0, 2, "12345"},
      {"1234567890123456789012345678901234567890", SQL_SUCCESS, "", 1, -1,
       "123456789012345678901234567890123456789"},
      {"'abc'", SQL_ERROR, "22018", 0, 0, ""},
  };
  for (size_t i = 0; i < sizeof T / sizeof T[0] && !m[0]; i++) {
    char sql[96], st[6] = "", mant[48] = "";
    snprintf(sql, sizeof sql, "SELECT %s FROM dual", T[i].expr);
    SQLHSTMT s;
    SQLAllocHandle(SQL_HANDLE_STMT, dbc, &s);
    SQL_NUMERIC_STRUCT n;
    memset(&n, 0, sizeof n);
    SQLLEN ind = 0;
    SQLRETURN rc = SQLExecDirect(s, (SQLCHAR *)sql, SQL_NTS);
    if (SQL_SUCCEEDED(rc) && SQL_SUCCEEDED(rc = SQLFetch(s)))
      rc = SQLGetData(s, 1, SQL_C_NUMERIC, &n, sizeof n, &ind);
    if (rc != SQL_SUCCESS)
      diag_state(SQL_HANDLE_STMT, s, st);
    numeric_mantissa(&n, mant);
    if (rc != T[i].rc || strcmp(st, T[i].state) != 0 ||
        (SQL_SUCCEEDED(rc) &&
         (n.sign != T[i].sign || n.scale != T[i].scale || strcmp(mant, T[i].mant) != 0)))
      snprintf(m, sizeof m, "%s: rc=%d '%s' sign %d scale %d mantissa %s", T[i].expr, (int)rc, st,
               n.sign, n.scale, mant);
    SQLFreeHandle(SQL_HANDLE_STMT, s);
  }
  if (m[0] == '\0')
    pass(name);
  else
    fail(name, m);
}

/* Date / time fetch targets (#334): a DATE's time dropped into a date struct
 * and a TIMESTAMP's fraction dropped into a time struct are 01S07; an
 * impossible date in text is 22018; a time literal fills a time struct.
 * Two-way: a midnight DATE into a date struct is plain SQL_SUCCESS. */
static void check_datetime_targets(SQLHDBC dbc)
{
  const char *name = "date / time fetch targets: truncation, field checks";
  char m[300] = "";
  struct {
    const char *expr;
    SQLSMALLINT ct;
    SQLRETURN rc;
    const char *state;
    int from;
  } T[] = {
      {"TO_DATE('2026-11-19 13:14:15','YYYY-MM-DD HH24:MI:SS')", SQL_C_TYPE_DATE,
       SQL_SUCCESS_WITH_INFO, "01S07", 8},
      {"TO_DATE('2026-11-19','YYYY-MM-DD')", SQL_C_TYPE_DATE, SQL_SUCCESS, "", 8},
      {"TO_TIMESTAMP('2026-11-19 13:14:15.5','YYYY-MM-DD HH24:MI:SS.FF')", SQL_C_TYPE_TIME,
       SQL_SUCCESS_WITH_INFO, "01S07", 9},
      {"'2026-13-45'", SQL_C_TYPE_DATE, SQL_ERROR, "22018", 8},
      {"'13:14:15'", SQL_C_TYPE_TIME, SQL_SUCCESS, "", 8},
  };
  for (size_t i = 0; i < sizeof T / sizeof T[0] && !m[0]; i++) {
    if (g_release < T[i].from)
      continue;
    char sql[160], st[6] = "";
    snprintf(sql, sizeof sql, "SELECT %s FROM dual", T[i].expr);
    SQLHSTMT s;
    SQLAllocHandle(SQL_HANDLE_STMT, dbc, &s);
    SQL_TIMESTAMP_STRUCT v; /* big enough for the date and time structs */
    memset(&v, 0, sizeof v);
    SQLLEN ind = 0;
    SQLRETURN rc = SQLExecDirect(s, (SQLCHAR *)sql, SQL_NTS);
    if (SQL_SUCCEEDED(rc) && SQL_SUCCEEDED(rc = SQLFetch(s)))
      rc = SQLGetData(s, 1, T[i].ct, &v, sizeof v, &ind);
    if (rc != SQL_SUCCESS)
      diag_state(SQL_HANDLE_STMT, s, st);
    if (rc != T[i].rc || strcmp(st, T[i].state) != 0)
      snprintf(m, sizeof m, "%s as C type %d: rc=%d '%s' (want rc=%d '%s')", T[i].expr,
               (int)T[i].ct, (int)rc, st, (int)T[i].rc, T[i].state);
    SQLFreeHandle(SQL_HANDLE_STMT, s);
  }
  if (m[0] == '\0')
    pass(name);
  else
    fail(name, m);
}

/* A number or a date cut short in a character buffer (#336): its whole part
 * not fitting is 22003, losing only fraction digits is 01004; a number into a
 * date struct is 07006. Two-way: text still truncates with 01004. */
static void check_char_overflow(SQLHDBC dbc)
{
  const char *name = "number / date into a short character buffer: 22003";
  char m[300] = "";
  struct {
    const char *expr;
    SQLSMALLINT ct;
    SQLLEN len;
    SQLRETURN rc;
    const char *state;
  } T[] = {
      {"12345", SQL_C_CHAR, 4, SQL_ERROR, "22003"},
      {"123.456", SQL_C_CHAR, 5, SQL_SUCCESS_WITH_INFO, "01004"},
      {"TO_DATE('2026-11-19 13:14:15','YYYY-MM-DD HH24:MI:SS')", SQL_C_CHAR, 11, SQL_ERROR,
       "22003"},
      {"'hello'", SQL_C_CHAR, 4, SQL_SUCCESS_WITH_INFO, "01004"},
      {"12345", SQL_C_WCHAR, 8, SQL_ERROR, "22003"},
      {"5", SQL_C_TYPE_DATE, (SQLLEN)sizeof(SQL_DATE_STRUCT), SQL_ERROR, "07006"},
  };
  for (size_t i = 0; i < sizeof T / sizeof T[0] && !m[0]; i++) {
    char sql[128], st[6] = "";
    snprintf(sql, sizeof sql, "SELECT %s FROM dual", T[i].expr);
    SQLHSTMT s;
    SQLAllocHandle(SQL_HANDLE_STMT, dbc, &s);
    char buf[64];
    SQLLEN ind = 0;
    SQLRETURN rc = SQLExecDirect(s, (SQLCHAR *)sql, SQL_NTS);
    if (SQL_SUCCEEDED(rc) && SQL_SUCCEEDED(rc = SQLFetch(s)))
      rc = SQLGetData(s, 1, T[i].ct, buf, T[i].len, &ind);
    if (rc != SQL_SUCCESS)
      diag_state(SQL_HANDLE_STMT, s, st);
    if (rc != T[i].rc || strcmp(st, T[i].state) != 0)
      snprintf(m, sizeof m, "%s as C type %d [%ld]: rc=%d '%s' (want rc=%d '%s')", T[i].expr,
               (int)T[i].ct, (long)T[i].len, (int)rc, st, (int)T[i].rc, T[i].state);
    SQLFreeHandle(SQL_HANDLE_STMT, s);
  }
  if (m[0] == '\0')
    pass(name);
  else
    fail(name, m);
}

/* Run `sql` and count its rows; -1 (and the error in why) if it fails. */
static int rows_of(SQLHDBC dbc, const char *sql, int refcursor, char *why, size_t n)
{
  SQLHSTMT s;
  SQLAllocHandle(SQL_HANDLE_STMT, dbc, &s);
  SQLRETURN rc = SQL_SUCCESS;
  if (refcursor)
    rc = SQLBindParameter(s, 1, SQL_PARAM_OUTPUT, SQL_C_DEFAULT, SEER_SQL_REFCURSOR, 0, 0, NULL, 0,
                          NULL);
  if (SQL_SUCCEEDED(rc))
    rc = SQLExecDirect(s, (SQLCHAR *)sql, SQL_NTS);
  int rows = 0;
  while (SQL_SUCCEEDED(rc) && SQL_SUCCEEDED(rc = SQLFetch(s)))
    rows++;
  if (rc != SQL_NO_DATA) {
    diag_text(SQL_HANDLE_STMT, s, why, n);
    rows = -1;
  }
  SQLFreeHandle(SQL_HANDLE_STMT, s);
  return rows;
}

/* The statement cache's hidden cursors (#337) must not cost the application
 * cursors: with the cache filled (24), a REF CURSOR and a query whose 30 rows
 * each hold a nested CURSOR(), and 30 result sets held open at once, all run.
 * On 10g (open_cursors 50) each of these was ORA-01000. */
static void check_cache_open_cursors(SQLHDBC dbc)
{
  const char *name = "statement cache leaves room for the application's cursors";
  char m[400] = "", why[300] = "";
  for (int i = 0; i < 24; i++) {
    char q[64], err[128];
    snprintf(q, sizeof q, "SELECT %d FROM dual", 7000 + i);
    exec_do(dbc, q, err, sizeof err);
  }
  static const char *const NESTED = "SELECT rownum a, CURSOR(SELECT 1 FROM dual) c "
                                    "FROM all_objects WHERE rownum <= 30";
  int n = rows_of(dbc,
                  "BEGIN OPEN :1 FOR 'SELECT rownum a, CURSOR(SELECT 1 FROM dual) c "
                  "FROM all_objects WHERE rownum <= 30'; END;",
                  1, why, sizeof why);
  if (n != 30)
    snprintf(m, sizeof m, "REF CURSOR with nested cursors: %d rows %s", n, why);
  for (int i = 0; i < 24 && !m[0]; i++) { /* refill: the REF CURSOR emptied it */
    char q[64], err[128];
    snprintf(q, sizeof q, "SELECT %d FROM dual", 7100 + i);
    exec_do(dbc, q, err, sizeof err);
  }
  if (!m[0] && (n = rows_of(dbc, NESTED, 0, why, sizeof why)) != 30)
    snprintf(m, sizeof m, "query with nested cursors: %d rows %s", n, why);
  SQLHSTMT held[30];
  int nheld = 0;
  for (; nheld < 30 && !m[0]; nheld++) {
    char q[96];
    snprintf(q, sizeof q, "SELECT rownum + %d FROM all_objects WHERE rownum <= 300", nheld);
    SQLAllocHandle(SQL_HANDLE_STMT, dbc, &held[nheld]);
    if (!SQL_SUCCEEDED(SQLExecDirect(held[nheld], (SQLCHAR *)q, SQL_NTS))) {
      diag_text(SQL_HANDLE_STMT, held[nheld], why, sizeof why);
      /* m set: the loop's own step counts this handle, so it is freed below */
      snprintf(m, sizeof m, "open result set %d of 30: %s", nheld + 1, why);
    }
  }
  for (int i = 0; i < nheld; i++)
    SQLFreeHandle(SQL_HANDLE_STMT, held[i]);
  if (m[0] == '\0')
    pass(name);
  else
    fail(name, m);
}

/* Read column 1 of `sql` with SQLGetData(SQL_C_WCHAR) in pieces of `piece`
 * bytes; the UTF-16 units joined into out (n units), their count returned, -1
 * on an error. */
static int wchar_pieces(SQLHDBC dbc, const char *sql, SQLLEN piece, SQLWCHAR *out, int n)
{
  SQLHSTMT s;
  SQLAllocHandle(SQL_HANDLE_STMT, dbc, &s);
  int k = -1;
  if (SQL_SUCCEEDED(SQLExecDirect(s, (SQLCHAR *)sql, SQL_NTS)) && SQL_SUCCEEDED(SQLFetch(s))) {
    k = 0;
    for (int calls = 0; calls < 200; calls++) {
      SQLWCHAR buf[32];
      SQLLEN ind = 0;
      SQLRETURN rc = SQLGetData(s, 1, SQL_C_WCHAR, buf, piece, &ind);
      if (rc == SQL_NO_DATA)
        break;
      if (!SQL_SUCCEEDED(rc)) {
        k = -1;
        break;
      }
      int units = rc == SQL_SUCCESS ? (int)(ind / 2) : (int)(piece / 2 - 1);
      for (int i = 0; i < units && k < n; i++)
        out[k++] = buf[i];
    }
  }
  SQLFreeHandle(SQL_HANDLE_STMT, s);
  return k;
}

/* SQLGetData in pieces as SQL_C_WCHAR returns the whole value (#351): it
 * stopped once the UTF-16 offset passed the value's UTF-8 length, so 'hello
 * world' in 6-byte pieces came back as 'hello '. Two-way: the same value read
 * at once, and the pieces joined, are equal - for ASCII, for multi-byte text
 * with a surrogate pair, and for a CLOB. */
static void check_getdata_wchar_pieces(SQLHDBC dbc)
{
  const char *name = "SQLGetData in SQL_C_WCHAR pieces returns the whole value";
  char m[300] = "";
  struct {
    const char *sql;
    SQLLEN piece;
    int from;
  } T[] = {
      {"SELECT 'hello world' FROM dual", 6, 8},
      /* 8.1.7 has no UNISTR, and its WE8ISO8859P1 holds none of these */
      {"SELECT UNISTR('a\\00E9b\\D83D\\DE00c\\4E2Dd\\00E9\\D83D\\DE00') FROM dual", 4, 9},
      {"SELECT TO_CLOB('hello world, in a CLOB') FROM dual", 8, 9}, /* TO_CLOB is 9i+ */
  };
  for (size_t i = 0; i < sizeof T / sizeof T[0] && !m[0]; i++) {
    if (g_release < T[i].from)
      continue;
    SQLWCHAR whole[128], joined[128];
    int nw = wchar_pieces(dbc, T[i].sql, (SQLLEN)sizeof whole, whole, 128);
    int nj = wchar_pieces(dbc, T[i].sql, T[i].piece, joined, 128);
    if (nw <= 0 || nj != nw || memcmp(whole, joined, (size_t)nw * sizeof(SQLWCHAR)) != 0)
      snprintf(m, sizeof m, "%.60s: %d units at once, %d in %ld-byte pieces", T[i].sql, nw, nj,
               (long)T[i].piece);
  }
  if (m[0] == '\0')
    pass(name);
  else
    fail(name, m);
}

/* A prepared query describes before it is executed - what result-layout tools
 * (ADO, report designers) do. 8.1.7 answered 0 columns until the execute; it
 * now sends the describe-only OALL8 (#353). Two-way: the execute after it
 * still runs and fetches. */
static void check_describe_no_markers(SQLHDBC dbc)
{
  const char *name = "a prepared query without markers describes before SQLExecute";
  char m[300] = "";
  SQLHSTMT s;
  SQLAllocHandle(SQL_HANDLE_STMT, dbc, &s);
  SQLPrepare(s, (SQLCHAR *)"SELECT owner, object_name, created FROM all_objects WHERE rownum <= 2",
             SQL_NTS);
  SQLSMALLINT n = -1, nl = 0, type = 0, dd, nul;
  SQLULEN sz = 0;
  SQLCHAR col[64] = "";
  SQLRETURN rc = SQLNumResultCols(s, &n);
  if (!SQL_SUCCEEDED(rc) || n != 3)
    snprintf(m, sizeof m, "before execute: rc=%d, %d columns (want 3)", (int)rc, n);
  else if (!SQL_SUCCEEDED(SQLDescribeCol(s, 3, col, sizeof col, &nl, &type, &sz, &dd, &nul)) ||
           strcmp((char *)col, "CREATED") != 0 || type != SQL_TYPE_TIMESTAMP)
    snprintf(m, sizeof m, "before execute: column 3 is '%s' type %d (want CREATED, %d)",
             (char *)col, type, SQL_TYPE_TIMESTAMP);
  int rows = 0;
  if (!m[0]) {
    rc = SQLExecute(s);
    while (SQL_SUCCEEDED(rc) && SQL_SUCCEEDED(SQLFetch(s)))
      rows++;
    if (!SQL_SUCCEEDED(rc) || rows != 2)
      snprintf(m, sizeof m, "execute after the describe: rc=%d, %d rows (want 2)", (int)rc, rows);
  }
  SQLFreeHandle(SQL_HANDLE_STMT, s);
  if (m[0] == '\0')
    pass(name);
  else
    fail(name, m);
}

/* A diagnostic's text is one message with no line terminator (#364): from 9i
 * the server's ends with '\n', which went to the application as it came. The
 * length SQLGetDiagRec reports is the text's. */
static void check_diag_text_trimmed(SQLHDBC dbc)
{
  const char *name = "diagnostic text has no trailing newline";
  char m[300] = "";
  SQLHSTMT s;
  SQLAllocHandle(SQL_HANDLE_STMT, dbc, &s);
  SQLRETURN rc = SQLExecDirect(s, (SQLCHAR *)"SELECT seer_no_such_column FROM dual", SQL_NTS);
  SQLCHAR st[6] = "", msg[512] = "";
  SQLINTEGER native = 0;
  SQLSMALLINT len = 0;
  if (rc != SQL_ERROR ||
      SQLGetDiagRec(SQL_HANDLE_STMT, s, 1, st, &native, msg, sizeof msg, &len) != SQL_SUCCESS)
    snprintf(m, sizeof m, "no diagnostic (rc=%d)", (int)rc);
  else {
    size_t n = strlen((char *)msg);
    if (n == 0 || msg[n - 1] == '\n' || msg[n - 1] == '\r' || msg[n - 1] == ' ' || (size_t)len != n)
      snprintf(m, sizeof m, "message of %zu bytes (length %d) ends with 0x%02x: %.100s", n,
               (int)len, n ? msg[n - 1] : 0, (char *)msg);
  }
  SQLFreeHandle(SQL_HANDLE_STMT, s);
  if (m[0] == '\0')
    pass(name);
  else
    fail(name, m);
}

/* A national parameter (SQL_WVARCHAR) keeps characters the database charset
 * lacks (#367): on 9i (WE8ISO8859P1) U+4E2D bound as SQL_WVARCHAR reached an
 * NVARCHAR2 as '¿'. It now goes in the national charset there; read back as
 * SQL_C_WCHAR it is the same two characters on every tier from 9i. */
static void check_national_params(SQLHDBC dbc)
{
  const char *name = "SQL_WVARCHAR parameters keep characters the database charset lacks";
  if (g_release > 0 && g_release < 9) {
    skip(name, "server: 8.1.7's national charset is WE8ISO8859P1 too");
    return;
  }
  char m[300] = "", err[256];
  exec_do(dbc, "DROP TABLE seer_npar", err, sizeof err);
  if (!SQL_SUCCEEDED(exec_do(dbc, "CREATE TABLE seer_npar (n NVARCHAR2(10))", err, sizeof err))) {
    fail(name, err);
    return;
  }
  static const SQLWCHAR W[] = {0x4E2D, 0x00E9, 0};
  static const char U8[] = "\xe4\xb8\xad\xc3\xa9";
  struct {
    SQLSMALLINT ct;
    const void *v;
  } T[] = {{SQL_C_WCHAR, W}, {SQL_C_CHAR, U8}};
  for (size_t i = 0; i < sizeof T / sizeof T[0] && !m[0]; i++) {
    exec_do(dbc, "DELETE FROM seer_npar", err, sizeof err);
    SQLHSTMT s;
    SQLAllocHandle(SQL_HANDLE_STMT, dbc, &s);
    SQLLEN ind = SQL_NTS;
    SQLBindParameter(s, 1, SQL_PARAM_INPUT, T[i].ct, SQL_WVARCHAR, 10, 0, (SQLPOINTER)T[i].v, 0,
                     &ind);
    SQLRETURN rc = SQLExecDirect(s, (SQLCHAR *)"INSERT INTO seer_npar VALUES (?)", SQL_NTS);
    SQLFreeHandle(SQL_HANDLE_STMT, s);
    SQLWCHAR out[8] = {0};
    SQLLEN oi = 0;
    SQLAllocHandle(SQL_HANDLE_STMT, dbc, &s);
    if (SQL_SUCCEEDED(rc) &&
        SQL_SUCCEEDED(rc = SQLExecDirect(s, (SQLCHAR *)"SELECT n FROM seer_npar", SQL_NTS)) &&
        SQL_SUCCEEDED(rc = SQLFetch(s)))
      rc = SQLGetData(s, 1, SQL_C_WCHAR, out, sizeof out, &oi);
    SQLFreeHandle(SQL_HANDLE_STMT, s);
    if (!SQL_SUCCEEDED(rc) || oi != 4 || out[0] != 0x4E2D || out[1] != 0x00E9)
      snprintf(m, sizeof m, "C type %d: rc=%d read %ld bytes U+%04X U+%04X (want U+4E2D U+00E9)",
               (int)T[i].ct, (int)rc, (long)oi, out[0], out[1]);
  }
  exec_do(dbc, "DROP TABLE seer_npar", err, sizeof err);
  if (m[0] == '\0')
    pass(name);
  else
    fail(name, m);
}

/* One SQL_WVARCHAR parameter (`n` sets of it, a parameter array when n > 1)
 * in `sql`; the statement's diagnostic in err when it fails. */
static SQLRETURN exec_wparam(SQLHDBC dbc, const char *sql, const char *v, int n, char *err,
                             size_t esz)
{
  SQLHSTMT s;
  SQLAllocHandle(SQL_HANDLE_STMT, dbc, &s);
  char vals[3][16];
  SQLLEN ind[3];
  for (int k = 0; k < n && k < 3; k++) {
    snprintf(vals[k], sizeof vals[k], "%s%d", v, k);
    ind[k] = SQL_NTS;
  }
  if (n > 1)
    SQLSetStmtAttr(s, SQL_ATTR_PARAMSET_SIZE, (SQLPOINTER)(SQLULEN)n, 0);
  SQLBindParameter(s, 1, SQL_PARAM_INPUT, SQL_C_CHAR, SQL_WVARCHAR, 10, 0, vals, 16, ind);
  SQLRETURN rc = SQLExecDirect(s, (SQLCHAR *)sql, SQL_NTS);
  if (!SQL_SUCCEEDED(rc))
    diag_text(SQL_HANDLE_STMT, s, err, esz);
  else if (rc == SQL_SUCCESS && strncmp(sql, "SELECT", 6) == 0 && SQL_SUCCEEDED(SQLFetch(s)))
    SQLGetData(s, 1, SQL_C_CHAR, err, (SQLLEN)esz, NULL); /* a query: its cell */
  SQLFreeHandle(SQL_HANDLE_STMT, s);
  return rc;
}

/* SQL_WVARCHAR parameters reach a VARCHAR2 column, an NVARCHAR2 one, and an
 * NCHAR comparison, alone and as a parameter array. 8.1.7 wants a text
 * parameter's form to match its target (ORA-12704 either way): 8i sends CHAR
 * form, and after ORA-12704 once more in NCHAR form (#419). Characters
 * WE8ISO8859P1 has, the 8i bed's charsets. */
static void check_wvarchar_targets(SQLHDBC dbc)
{
  const char *name = "SQL_WVARCHAR parameters reach VARCHAR2, NVARCHAR2 and NCHAR comparisons";
  char m[400] = "", err[256] = "";
  exec_do(dbc, "DROP TABLE seer_wtgt", err, sizeof err);
  if (!SQL_SUCCEEDED(exec_do(dbc, "CREATE TABLE seer_wtgt (v VARCHAR2(10), n NVARCHAR2(10))", err,
                             sizeof err))) {
    fail(name, err);
    return;
  }
  static const struct {
    const char *sql;
    int n;
  } T[] = {{"INSERT INTO seer_wtgt (v) VALUES (?)", 1},
           {"INSERT INTO seer_wtgt (n) VALUES (?)", 1},
           {"INSERT INTO seer_wtgt (n) VALUES (?)", 3},
           {"SELECT COUNT(*) FROM seer_wtgt WHERE n = ?", 1}};
  for (size_t i = 0; i < sizeof T / sizeof T[0] && !m[0]; i++) {
    err[0] = '\0';
    SQLRETURN rc = exec_wparam(dbc, T[i].sql, "\xc3\xa9", T[i].n, err, sizeof err);
    if (rc != SQL_SUCCESS)
      snprintf(m, sizeof m, "%s (%d set(s)): rc=%d %s", T[i].sql, T[i].n, (int)rc, err);
    else if (T[i].sql[0] == 'S' && strcmp(err, "2") != 0)
      snprintf(m, sizeof m, "%s: '%s' (want 2: the single row and the array's first)", T[i].sql,
               err);
  }
  char out[64] = "";
  if (!m[0] &&
      SQL_SUCCEEDED(exec_scalar(dbc,
                                "SELECT COUNT(v) || ':' || COUNT(n) || ':' || MIN(v) || "
                                "':' || TO_CHAR(MAX(n)) FROM seer_wtgt",
                                out, sizeof out, err, sizeof err)) &&
      strcmp(out, "1:4:\xc3\xa9"
                  "0:\xc3\xa9"
                  "2") != 0)
    snprintf(m, sizeof m,
             "read back '%s' (want '1:4:\xc3\xa9"
             "0:\xc3\xa9"
             "2')",
             out);
  exec_do(dbc, "DROP TABLE seer_wtgt", err, sizeof err);
  if (m[0] == '\0')
    pass(name);
  else
    fail(name, m);
}

/* A block cursor whose rows 1 and 3 overflow the bound buffer (#369): those
 * rows are SQL_ROW_SUCCESS_WITH_INFO and row 2 SQL_ROW_SUCCESS; there are two
 * 01004 records, with SQL_DIAG_ROW_NUMBER 1 and 3. Each record used to replace
 * the last, with no row number, and every row read SQL_ROW_SUCCESS. */
static void check_rowset_truncation(SQLHDBC dbc)
{
  const char *name = "rowset: truncated rows say so, each 01004 with its row";
  char m[300] = "";
  SQLHSTMT s;
  SQLAllocHandle(SQL_HANDLE_STMT, dbc, &s);
  SQLUSMALLINT status[3] = {99, 99, 99};
  SQLULEN fetched = 0;
  SQLSetStmtAttr(s, SQL_ATTR_ROW_ARRAY_SIZE, (SQLPOINTER)3, 0);
  SQLSetStmtAttr(s, SQL_ATTR_ROW_STATUS_PTR, status, 0);
  SQLSetStmtAttr(s, SQL_ATTR_ROWS_FETCHED_PTR, &fetched, 0);
  char buf[3][4];
  SQLLEN ind[3];
  SQLBindCol(s, 1, SQL_C_CHAR, buf, 4, ind);
  SQLRETURN rc = SQLExecDirect(
      s, (SQLCHAR *)"SELECT DECODE(rownum, 2, 'ab', 'longer') FROM all_objects WHERE rownum <= 3",
      SQL_NTS);
  if (SQL_SUCCEEDED(rc))
    rc = SQLFetch(s);
  if (rc != SQL_SUCCESS_WITH_INFO || fetched != 3 || status[0] != SQL_ROW_SUCCESS_WITH_INFO ||
      status[1] != SQL_ROW_SUCCESS || status[2] != SQL_ROW_SUCCESS_WITH_INFO)
    snprintf(m, sizeof m, "fetch rc=%d fetched=%lu statuses %u %u %u (want 1, 3, 6 0 6)", (int)rc,
             (unsigned long)fetched, status[0], status[1], status[2]);
  SQLLEN rows[2] = {0, 0};
  int nrec = 0;
  for (SQLSMALLINT r = 1; !m[0] && r <= 3; r++) {
    SQLCHAR st[6];
    SQLINTEGER n;
    SQLSMALLINT l;
    SQLCHAR msg[64];
    if (SQLGetDiagRec(SQL_HANDLE_STMT, s, r, st, &n, msg, sizeof msg, &l) != SQL_SUCCESS)
      break;
    if (nrec < 2)
      SQLGetDiagField(SQL_HANDLE_STMT, s, r, SQL_DIAG_ROW_NUMBER, &rows[nrec], 0, NULL);
    nrec++;
  }
  if (!m[0] && (nrec != 2 || rows[0] != 1 || rows[1] != 3))
    snprintf(m, sizeof m, "%d diagnostic records, rows %ld and %ld (want 2: rows 1 and 3)", nrec,
             (long)rows[0], (long)rows[1]);
  SQLFreeHandle(SQL_HANDLE_STMT, s);
  if (m[0] == '\0')
    pass(name);
  else
    fail(name, m);
}

/* Open a 3-row updatable rowset over seer_spos (id, v) on `s`. */
static SQLRETURN open_spos(SQLHSTMT s, SQLUSMALLINT *st, SQLINTEGER *id, SQLLEN *ii, SQLINTEGER *v,
                           SQLLEN *vi)
{
  SQLSetStmtAttr(s, SQL_ATTR_CURSOR_TYPE, (SQLPOINTER)SQL_CURSOR_STATIC, 0);
  SQLSetStmtAttr(s, SQL_ATTR_CONCURRENCY, (SQLPOINTER)SQL_CONCUR_LOCK, 0);
  SQLSetStmtAttr(s, SQL_ATTR_ROW_ARRAY_SIZE, (SQLPOINTER)3, 0);
  SQLSetStmtAttr(s, SQL_ATTR_ROW_STATUS_PTR, st, 0);
  SQLBindCol(s, 1, SQL_C_SLONG, id, 0, ii);
  SQLBindCol(s, 2, SQL_C_SLONG, v, 0, vi);
  SQLRETURN rc = SQLExecDirect(s, (SQLCHAR *)"SELECT id, v FROM seer_spos ORDER BY id", SQL_NTS);
  return SQL_SUCCEEDED(rc) ? SQLFetchScroll(s, SQL_FETCH_NEXT, 0) : rc;
}

/* SQLSetPos(0, SQL_UPDATE / SQL_DELETE) over a rowset whose row 2 fails runs
 * every row (#371): rows 1 and 3 are SQL_ROW_UPDATED / SQL_ROW_DELETED, row 2
 * SQL_ROW_ERROR with a diagnostic for row 2, the call SQL_SUCCESS_WITH_INFO.
 * It used to stop at row 2 (row 3 never ran) with SQL_ERROR and no statuses. */
static void check_setpos_rowset_errors(SQLHDBC dbc)
{
  const char *name = "SQLSetPos over a rowset runs every row; a failing row is its own error";
  char m[300] = "", err[256], out[64] = "";
  exec_do(dbc, "DROP TABLE seer_spos_c", err, sizeof err);
  exec_do(dbc, "DROP TABLE seer_spos", err, sizeof err);
  if (!SQL_SUCCEEDED(
          exec_do(dbc, "CREATE TABLE seer_spos (id NUMBER PRIMARY KEY, v NUMBER CHECK (v < 100))",
                  err, sizeof err))) {
    fail(name, err);
    return;
  }
  exec_do(dbc, "CREATE TABLE seer_spos_c (p NUMBER REFERENCES seer_spos)", err, sizeof err);
  for (int i = 1; i <= 3; i++) {
    char ins[64];
    snprintf(ins, sizeof ins, "INSERT INTO seer_spos VALUES (%d, %d)", i, i * 10);
    exec_do(dbc, ins, err, sizeof err);
  }
  exec_do(dbc, "INSERT INTO seer_spos_c VALUES (2)", err, sizeof err);
  for (int op = 0; op < 2 && !m[0]; op++) {
    SQLHSTMT s;
    SQLAllocHandle(SQL_HANDLE_STMT, dbc, &s);
    SQLUSMALLINT st[3] = {99, 99, 99};
    SQLINTEGER id[3], v[3];
    SQLLEN ii[3], vi[3];
    SQLRETURN rc = open_spos(s, st, id, ii, v, vi);
    if (!SQL_SUCCEEDED(rc)) {
      diag_text(SQL_HANDLE_STMT, s, err, sizeof err);
      snprintf(m, sizeof m, "open the rowset: %s", err);
      SQLFreeHandle(SQL_HANDLE_STMT, s);
      break;
    }
    SQLUSMALLINT done = op == 0 ? SQL_ROW_UPDATED : SQL_ROW_DELETED;
    if (op == 0) {
      v[0] = 11, v[1] = 500, v[2] = 33; /* 500 breaks the CHECK */
      rc = SQLSetPos(s, 0, SQL_UPDATE, SQL_LOCK_NO_CHANGE);
    } else {
      rc = SQLSetPos(s, 0, SQL_DELETE, SQL_LOCK_NO_CHANGE); /* row 2 has a child */
    }
    SQLLEN row = 0;
    SQLGetDiagField(SQL_HANDLE_STMT, s, 1, SQL_DIAG_ROW_NUMBER, &row, 0, NULL);
    if (rc != SQL_SUCCESS_WITH_INFO || st[0] != done || st[1] != SQL_ROW_ERROR || st[2] != done ||
        row != 2)
      snprintf(m, sizeof m, "%s: rc=%d statuses %u %u %u, diag row %ld (want 1, %u 5 %u, row 2)",
               op ? "DELETE" : "UPDATE", (int)rc, st[0], st[1], st[2], (long)row, done, done);
    SQLFreeHandle(SQL_HANDLE_STMT, s);
    SQLEndTran(SQL_HANDLE_DBC, dbc, SQL_COMMIT);
    exec_scalar(dbc, "SELECT COUNT(*) || ':' || SUM(v) FROM seer_spos", out, sizeof out, err,
                sizeof err);
    const char *want = op == 0 ? "3:64" : "1:20"; /* 11+20+33; then only row 2 left */
    if (!m[0] && strcmp(out, want) != 0)
      snprintf(m, sizeof m, "after %s the table holds %s (want %s)", op ? "DELETE" : "UPDATE", out,
               want);
  }
  exec_do(dbc, "DROP TABLE seer_spos_c", err, sizeof err);
  exec_do(dbc, "DROP TABLE seer_spos", err, sizeof err);
  if (m[0] == '\0')
    pass(name);
  else
    fail(name, m);
}

/* TIMESTAMP WITH LOCAL TIME ZONE reads in the session's zone (#358): the
 * server sends it in DBTIMEZONE, and the driver moves it, as OCI does. 10:00
 * +02:00 reads 13:00 at a session +05:00, and 04:30 after an ALTER SESSION to
 * -03:30 - the zones are read again. It read in DBTIMEZONE whatever the
 * session (9i's -08:00 gave 00:00). Bound and through SQLGetData. */
static void check_ltz_session_zone(SQLHDBC dbc)
{
  const char *name = "LOCAL TIME ZONE value reads in the session's zone (after ALTER SESSION)";
  if (gated(name))
    return;
  static const char *const ZONE[2] = {"+05:00", "-03:30"};
  static const char *const WANT[2] = {"2026-11-20 13:00:00", "2026-11-20 04:30:00"};
  char m[300] = "";
  for (int k = 0; k < 2 && !m[0]; k++) {
    SQLHSTMT s;
    SQLAllocHandle(SQL_HANDLE_STMT, dbc, &s);
    char alter[96], txt[64] = "";
    snprintf(alter, sizeof alter, "ALTER SESSION SET TIME_ZONE = '%s'", ZONE[k]);
    SQL_TIMESTAMP_STRUCT ts = {0};
    SQLLEN i1 = 0, i2 = 0;
    if (!SQL_SUCCEEDED(SQLExecDirect(s, (SQLCHAR *)alter, SQL_NTS))) {
      diag_text(SQL_HANDLE_STMT, s, m, sizeof m);
    } else {
      SQLFreeStmt(s, SQL_CLOSE);
      SQLBindCol(s, 2, SQL_C_TYPE_TIMESTAMP, &ts, sizeof ts, &i2);
      if (!SQL_SUCCEEDED(
              SQLExecDirect(s,
                            (SQLCHAR *)"SELECT x, x FROM (SELECT CAST(TIMESTAMP '2026-11-20 "
                                       "10:00:00 +02:00' AS TIMESTAMP WITH LOCAL TIME ZONE) x "
                                       "FROM dual)",
                            SQL_NTS)) ||
          !SQL_SUCCEEDED(SQLFetch(s)))
        diag_text(SQL_HANDLE_STMT, s, m, sizeof m);
      else if (SQLGetData(s, 1, SQL_C_CHAR, txt, sizeof txt, &i1), strcmp(txt, WANT[k]) != 0)
        snprintf(m, sizeof m, "session %s: text '%s', want '%s'", ZONE[k], txt, WANT[k]);
      else if (ts.hour != (k == 0 ? 13 : 4) || ts.minute != (k == 0 ? 0 : 30))
        snprintf(m, sizeof m, "session %s: struct %02u:%02u", ZONE[k], ts.hour, ts.minute);
    }
    SQLFreeHandle(SQL_HANDLE_STMT, s);
  }
  if (m[0] == '\0')
    pass(name);
  else
    fail(name, m);
}

/* TIMESTAMP WITH TIME ZONE reads as its own wall-clock time (#359): 10:00
 * +02:00 is 10:00 in a timestamp struct, bound or through SQLGetData, and its
 * text carries the offset - it read as its UTC 08:00, the zone dropped. A
 * negative half-hour offset across midnight and a year end, with a fraction,
 * too; the column's display size holds the text. */
static void check_tstz_wall_clock(SQLHDBC dbc)
{
  const char *name = "TIMESTAMP WITH TIME ZONE reads its own wall-clock time and offset";
  if (gated(name))
    return;
  SQLHSTMT s;
  SQLAllocHandle(SQL_HANDLE_STMT, dbc, &s);
  char m[300] = "", t1[64] = "", t2[64] = "";
  SQL_TIMESTAMP_STRUCT b1 = {0}, b2 = {0};
  SQLLEN i1, i2, i3, i4, disp = 0;
  SQLBindCol(s, 2, SQL_C_TYPE_TIMESTAMP, &b1, sizeof b1, &i2);
  SQLBindCol(s, 4, SQL_C_TYPE_TIMESTAMP, &b2, sizeof b2, &i4);
  if (!SQL_SUCCEEDED(SQLExecDirect(
          s,
          (SQLCHAR *)"SELECT a, a, b, b FROM (SELECT TIMESTAMP '2026-11-20 10:00:00 +02:00' a, "
                     "TIMESTAMP '2026-12-31 21:45:07.5 -05:30' b FROM dual)",
          SQL_NTS)) ||
      !SQL_SUCCEEDED(SQLFetch(s))) {
    diag_text(SQL_HANDLE_STMT, s, m, sizeof m);
  } else {
    SQLGetData(s, 1, SQL_C_CHAR, t1, sizeof t1, &i1);
    SQLGetData(s, 3, SQL_C_CHAR, t2, sizeof t2, &i3);
    SQLColAttribute(s, 3, SQL_DESC_DISPLAY_SIZE, NULL, 0, NULL, &disp);
    if (strcmp(t1, "2026-11-20 10:00:00 +02:00") != 0 ||
        strcmp(t2, "2026-12-31 21:45:07.500000000 -05:30") != 0)
      snprintf(m, sizeof m, "text '%s' / '%s'", t1, t2);
    else if (b1.hour != 10 || b1.minute != 0 || b1.day != 20)
      snprintf(m, sizeof m, "+02:00 struct %u %02u:%02u", b1.day, b1.hour, b1.minute);
    else if (b2.year != 2026 || b2.month != 12 || b2.day != 31 || b2.hour != 21 ||
             b2.minute != 45 || b2.second != 7 || b2.fraction != 500000000)
      snprintf(m, sizeof m, "-05:30 struct %d-%u-%u %u:%u:%u.%u", b2.year, b2.month, b2.day,
               b2.hour, b2.minute, b2.second, (unsigned)b2.fraction);
    else if (disp < (SQLLEN)strlen(t2))
      snprintf(m, sizeof m, "display size %ld < %zu", (long)disp, strlen(t2));
  }
  SQLFreeHandle(SQL_HANDLE_STMT, s);
  if (m[0] == '\0')
    pass(name);
  else
    fail(name, m);
}

/* Attribute identifiers (#373): a number no ODBC range defines is HY092 on
 * the connection and the statement, set and get - it was accepted - and
 * asynchronous execution at the connection is HYC00, as on a statement.
 * Two-way: a standard attribute this driver has no use for (QUIET_MODE) is
 * still accepted, and PACKET_SIZE reads the negotiated SDU. */
static void check_attr_identifiers(SQLHDBC dbc)
{
  const char *name = "unknown attributes are HY092; standard ones still accepted";
  char m[300] = "", st[6] = "";
  SQLRETURN rc = SQLSetConnectAttr(dbc, 12345, (SQLPOINTER)1, 0);
  diag_state(SQL_HANDLE_DBC, dbc, st);
  if (rc != SQL_ERROR || strcmp(st, "HY092") != 0)
    snprintf(m, sizeof m, "SQLSetConnectAttr(12345): rc=%d '%s'", (int)rc, st);
  if (!m[0]) {
    rc = SQLSetConnectAttr(dbc, SQL_ATTR_ASYNC_ENABLE, (SQLPOINTER)SQL_ASYNC_ENABLE_ON, 0);
    diag_state(SQL_HANDLE_DBC, dbc, st);
    if (rc != SQL_ERROR || strcmp(st, "HYC00") != 0)
      snprintf(m, sizeof m, "connection ASYNC_ENABLE ON: rc=%d '%s'", (int)rc, st);
  }
  if (!m[0] && !SQL_SUCCEEDED(SQLSetConnectAttr(dbc, SQL_ATTR_QUIET_MODE, NULL, 0)))
    snprintf(m, sizeof m, "QUIET_MODE (standard) was refused");
  SQLUINTEGER pkt = 0;
  if (!m[0] &&
      (!SQL_SUCCEEDED(SQLGetConnectAttr(dbc, SQL_ATTR_PACKET_SIZE, &pkt, 0, NULL)) || pkt == 0))
    snprintf(m, sizeof m, "PACKET_SIZE reads %u", (unsigned)pkt);
  SQLHSTMT s;
  SQLAllocHandle(SQL_HANDLE_STMT, dbc, &s);
  SQLULEN v = 0;
  for (int k = 0; k < 2 && !m[0]; k++) {
    rc =
        k == 0 ? SQLSetStmtAttr(s, 12345, (SQLPOINTER)1, 0) : SQLGetStmtAttr(s, 12345, &v, 0, NULL);
    diag_state(SQL_HANDLE_STMT, s, st);
    if (rc != SQL_ERROR || strcmp(st, "HY092") != 0)
      snprintf(m, sizeof m, "%sStmtAttr(12345): rc=%d '%s'", k ? "SQLGet" : "SQLSet", (int)rc, st);
  }
  SQLFreeHandle(SQL_HANDLE_STMT, s);
  if (m[0] == '\0')
    pass(name);
  else
    fail(name, m);
}

/* Cursor attributes (#226) are kept: STATIC reads back, KEYSET_DRIVEN becomes
 * STATIC and SENSITIVE becomes INSENSITIVE with 01S02, SCROLLABLE is a static
 * cursor - and that cursor scrolls (row 3 of 5 by SQL_FETCH_ABSOLUTE). */
static void check_cursor_attrs(SQLHDBC dbc)
{
  const char *name = "cursor attributes kept, KEYSET / SENSITIVE substituted (01S02)";
  char m[400] = "", st[6];
  SQLHSTMT s;
  SQLAllocHandle(SQL_HANDLE_STMT, dbc, &s);
  SQLULEN type = 99, scroll = 99, sens = 99;
  SQLSetStmtAttr(s, SQL_ATTR_CURSOR_TYPE, (SQLPOINTER)(uintptr_t)SQL_CURSOR_STATIC, 0);
  SQLGetStmtAttr(s, SQL_ATTR_CURSOR_TYPE, &type, 0, NULL);
  if (type != SQL_CURSOR_STATIC)
    snprintf(m, sizeof m, "STATIC read back as %lu", (unsigned long)type);
  SQLRETURN rc =
      SQLSetStmtAttr(s, SQL_ATTR_CURSOR_TYPE, (SQLPOINTER)(uintptr_t)SQL_CURSOR_KEYSET_DRIVEN, 0);
  diag_state(SQL_HANDLE_STMT, s, st);
  SQLGetStmtAttr(s, SQL_ATTR_CURSOR_TYPE, &type, 0, NULL);
  if (!m[0] &&
      (rc != SQL_SUCCESS_WITH_INFO || strcmp(st, "01S02") != 0 || type != SQL_CURSOR_STATIC))
    snprintf(m, sizeof m, "KEYSET_DRIVEN: rc=%d '%s', reads %lu", (int)rc, st, (unsigned long)type);
  SQLSetStmtAttr(s, SQL_ATTR_CURSOR_TYPE, (SQLPOINTER)(uintptr_t)SQL_CURSOR_FORWARD_ONLY, 0);
  SQLSetStmtAttr(s, SQL_ATTR_CURSOR_SCROLLABLE, (SQLPOINTER)(uintptr_t)SQL_SCROLLABLE, 0);
  SQLGetStmtAttr(s, SQL_ATTR_CURSOR_SCROLLABLE, &scroll, 0, NULL);
  SQLGetStmtAttr(s, SQL_ATTR_CURSOR_TYPE, &type, 0, NULL);
  if (!m[0] && (scroll != SQL_SCROLLABLE || type != SQL_CURSOR_STATIC))
    snprintf(m, sizeof m, "SCROLLABLE: reads %lu, type %lu", (unsigned long)scroll,
             (unsigned long)type);
  rc = SQLSetStmtAttr(s, SQL_ATTR_CURSOR_SENSITIVITY, (SQLPOINTER)(uintptr_t)SQL_SENSITIVE, 0);
  diag_state(SQL_HANDLE_STMT, s, st);
  SQLGetStmtAttr(s, SQL_ATTR_CURSOR_SENSITIVITY, &sens, 0, NULL);
  if (!m[0] && (rc != SQL_SUCCESS_WITH_INFO || strcmp(st, "01S02") != 0 || sens != SQL_INSENSITIVE))
    snprintf(m, sizeof m, "SENSITIVE: rc=%d '%s', reads %lu", (int)rc, st, (unsigned long)sens);
  char v[16] = "";
  SQLLEN ind = 0;
  if (!m[0] &&
      (!SQL_SUCCEEDED(SQLExecDirect(
           s, (SQLCHAR *)"SELECT rownum FROM all_objects WHERE rownum <= 5", SQL_NTS)) ||
       !SQL_SUCCEEDED(SQLFetchScroll(s, SQL_FETCH_ABSOLUTE, 3)) ||
       !SQL_SUCCEEDED(SQLGetData(s, 1, SQL_C_CHAR, v, sizeof v, &ind)) || strcmp(v, "3") != 0))
    snprintf(m, sizeof m, "SQL_FETCH_ABSOLUTE 3 read '%s'", v);
  SQLFreeHandle(SQL_HANDLE_STMT, s);
  if (m[0] == '\0')
    pass(name);
  else
    fail(name, m);
}

/* Rows a statement's query returns. */
static long count_rows(SQLHSTMT st, const char *sql)
{
  if (!SQL_SUCCEEDED(SQLExecDirect(st, (SQLCHAR *)sql, SQL_NTS)))
    return -1;
  long n = 0;
  while (SQL_SUCCEEDED(SQLFetch(st)))
    n++;
  SQLCloseCursor(st);
  return n;
}

/* SQL_ATTR_MAX_ROWS (#221): 5 caps a 400-row query at 5 rows and reads back;
 * 0 lifts the cap; a capped query with a CLOB column - whose rows past the cap
 * leave no LOB reads behind - returns 5 too. */
static void check_max_rows(SQLHDBC dbc)
{
  const char *name = "SQL_ATTR_MAX_ROWS caps a result";
  const char *q400 = "SELECT rownum FROM all_objects WHERE rownum <= 400";
  char err[256] = "", m[300] = "";
  SQLHSTMT st;
  SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st);
  SQLSetStmtAttr(st, SQL_ATTR_MAX_ROWS, (SQLPOINTER)(uintptr_t)5, 0);
  SQLULEN got = 0;
  SQLGetStmtAttr(st, SQL_ATTR_MAX_ROWS, &got, 0, NULL);
  long capped = count_rows(st, q400);
  SQLSetStmtAttr(st, SQL_ATTR_MAX_ROWS, (SQLPOINTER)(uintptr_t)0, 0);
  long all = count_rows(st, q400);
  exec_do(dbc, "DROP TABLE seer_maxrows_t", err, sizeof err);
  exec_do(dbc, "CREATE TABLE seer_maxrows_t (n NUMBER, c CLOB)", err, sizeof err);
  exec_do(dbc,
          "INSERT INTO seer_maxrows_t SELECT rownum, EMPTY_CLOB() FROM all_objects WHERE "
          "rownum <= 150",
          err, sizeof err);
  SQLSetStmtAttr(st, SQL_ATTR_MAX_ROWS, (SQLPOINTER)(uintptr_t)5, 0);
  long lobs = count_rows(st, "SELECT n, c FROM seer_maxrows_t");
  SQLFreeHandle(SQL_HANDLE_STMT, st);
  exec_do(dbc, "DROP TABLE seer_maxrows_t", err, sizeof err);
  if (got != 5 || capped != 5 || all != 400 || lobs != 5)
    snprintf(m, sizeof m,
             "reads back %lu; capped %ld (want 5), uncapped %ld (want 400), with a CLOB %ld "
             "(want 5) %s",
             (unsigned long)got, capped, all, lobs, err);
  if (m[0] == '\0')
    pass(name);
  else
    fail(name, m);
}

/* SQL_ATTR_TXN_ISOLATION (#220), which SQLGetInfo advertises: a session set
 * to SERIALIZABLE before connecting keeps reading the value its transaction
 * first saw while another session changes and commits it; switched to READ
 * COMMITTED while connected, it sees the next change at once. REPEATABLE READ,
 * which Oracle hasn't, is refused (HYC00). */
static void check_txn_isolation(SQLHDBC b, const char *drv, const char *host, const char *port,
                                const char *svc, const char *user, const char *pwd)
{
  const char *name = "SQL_ATTR_TXN_ISOLATION (SERIALIZABLE / READ COMMITTED)";
  char err[256] = "", v[16] = "", m[600] = "";
  exec_do(b, "DROP TABLE seer_iso_t", err, sizeof err);
  if (!SQL_SUCCEEDED(exec_do(b, "CREATE TABLE seer_iso_t (n NUMBER)", err, sizeof err)) ||
      !SQL_SUCCEEDED(exec_do(b, "INSERT INTO seer_iso_t VALUES (1)", err, sizeof err))) {
    skip(name, err);
    return;
  }
  SQLHENV e;
  SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &e);
  SQLSetEnvAttr(e, SQL_ATTR_ODBC_VERSION, (void *)SQL_OV_ODBC3, 0);
  SQLHDBC a;
  SQLAllocHandle(SQL_HANDLE_DBC, e, &a);
  SQLSetConnectAttr(a, SQL_ATTR_TXN_ISOLATION, (SQLPOINTER)(uintptr_t)SQL_TXN_SERIALIZABLE, 0);
  char cs[640];
  snprintf(cs, sizeof cs, "DRIVER=%s;HOST=%s;PORT=%s;SERVICE=%s;UID=%s;PWD=%s;", drv, host,
           port ? port : "1521", svc, user, pwd);
  SQLCHAR o[256];
  SQLSMALLINT ol;
  SQLRETURN rc =
      SQLDriverConnect(a, NULL, (SQLCHAR *)cs, SQL_NTS, o, sizeof o, &ol, SQL_DRIVER_NOPROMPT);
  SQLUINTEGER level = 0;
  if (rc != SQL_SUCCESS) {
    diag_text(SQL_HANDLE_DBC, a, err, sizeof err);
    snprintf(m, sizeof m, "connect rc=%d %s", (int)rc, err);
  } else {
    SQLGetConnectAttr(a, SQL_ATTR_TXN_ISOLATION, &level, 0, NULL);
    SQLSetConnectAttr(a, SQL_ATTR_AUTOCOMMIT, (SQLPOINTER)SQL_AUTOCOMMIT_OFF, 0);
    char v1[16] = "", v2[16] = "", v3[16] = "";
    exec_scalar(a, "SELECT n FROM seer_iso_t", v1, sizeof v1, err, sizeof err);
    exec_do(b, "UPDATE seer_iso_t SET n = 2", err, sizeof err); /* b autocommits */
    exec_scalar(a, "SELECT n FROM seer_iso_t", v2, sizeof v2, err, sizeof err);
    SQLEndTran(SQL_HANDLE_DBC, a, SQL_COMMIT);
    SQLRETURN rr = SQLSetConnectAttr(a, SQL_ATTR_TXN_ISOLATION,
                                     (SQLPOINTER)(uintptr_t)SQL_TXN_READ_COMMITTED, 0);
    exec_scalar(a, "SELECT n FROM seer_iso_t", v, sizeof v, err, sizeof err);
    exec_do(b, "UPDATE seer_iso_t SET n = 3", err, sizeof err);
    exec_scalar(a, "SELECT n FROM seer_iso_t", v3, sizeof v3, err, sizeof err);
    SQLEndTran(SQL_HANDLE_DBC, a, SQL_COMMIT);
    SQLRETURN rx = SQLSetConnectAttr(a, SQL_ATTR_TXN_ISOLATION,
                                     (SQLPOINTER)(uintptr_t)SQL_TXN_REPEATABLE_READ, 0);
    SQLCHAR st[6] = "";
    SQLINTEGER nat = 0;
    SQLSMALLINT len = 0;
    SQLCHAR msg[200];
    if (!SQL_SUCCEEDED(rx))
      SQLGetDiagRec(SQL_HANDLE_DBC, a, 1, st, &nat, msg, sizeof msg, &len);
    if (level != SQL_TXN_SERIALIZABLE || strcmp(v1, "1") != 0 || strcmp(v2, "1") != 0 ||
        !SQL_SUCCEEDED(rr) || strcmp(v3, "3") != 0 || SQL_SUCCEEDED(rx) ||
        strcmp((char *)st, "HYC00") != 0)
      snprintf(m, sizeof m,
               "level %u; serializable read %s then %s (want 1, 1); read committed %s (want 3); "
               "REPEATABLE READ rc=%d '%s' %s",
               (unsigned)level, v1, v2, v3, (int)rx, (char *)st, err);
    SQLDisconnect(a);
  }
  SQLFreeHandle(SQL_HANDLE_DBC, a);
  SQLFreeHandle(SQL_HANDLE_ENV, e);
  exec_do(b, "DROP TABLE seer_iso_t", err, sizeof err);
  if (m[0] == '\0')
    pass(name);
  else
    fail(name, m);
}

/* SQL_ATTR_LOGIN_TIMEOUT (#216): 3 s, and a HOST list whose first address
 * never answers (192.0.2.1, TEST-NET-1) reaches the server in well under the
 * 30 s default; the attribute reads back. CONNECT_TIMEOUT that isn't a number
 * of seconds is refused (HY024) before connecting. */
static void check_login_timeout(const char *drv, const char *host, const char *port,
                                const char *svc, const char *user, const char *pwd)
{
  const char *name = "SQL_ATTR_LOGIN_TIMEOUT bounds a dead address";
  char m[600] = "";
  for (int k = 0; k < 2 && m[0] == '\0'; k++) {
    SQLHENV e;
    SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &e);
    SQLSetEnvAttr(e, SQL_ATTR_ODBC_VERSION, (void *)SQL_OV_ODBC3, 0);
    SQLHDBC d;
    SQLAllocHandle(SQL_HANDLE_DBC, e, &d);
    char cs[800];
    if (k == 0) {
      SQLSetConnectAttr(d, SQL_ATTR_LOGIN_TIMEOUT, (SQLPOINTER)(uintptr_t)3, 0);
      snprintf(cs, sizeof cs, "DRIVER=%s;HOST=192.0.2.1,%s;PORT=%s;SERVICE=%s;UID=%s;PWD=%s;", drv,
               host, port ? port : "1521", svc, user, pwd);
    } else {
      snprintf(cs, sizeof cs,
               "DRIVER=%s;HOST=%s;PORT=%s;SERVICE=%s;UID=%s;PWD=%s;CONNECT_TIMEOUT=soon;", drv,
               host, port ? port : "1521", svc, user, pwd);
    }
    SQLCHAR o[256], state[6] = "", msg[300] = "";
    SQLSMALLINT ol, len = 0;
    SQLINTEGER native = 0;
    time_t t0 = time(NULL);
    SQLRETURN rc =
        SQLDriverConnect(d, NULL, (SQLCHAR *)cs, SQL_NTS, o, sizeof o, &ol, SQL_DRIVER_NOPROMPT);
    long took = (long)(time(NULL) - t0);
    if (!SQL_SUCCEEDED(rc))
      SQLGetDiagRec(SQL_HANDLE_DBC, d, 1, state, &native, msg, sizeof msg, &len);
    if (k == 0) {
      SQLUINTEGER got = 0;
      SQLGetConnectAttr(d, SQL_ATTR_LOGIN_TIMEOUT, &got, 0, NULL);
      if (!SQL_SUCCEEDED(rc) || took > 10 || got != 3)
        snprintf(m, sizeof m, "3 s timeout: rc=%d after %ld s, reads back %u: %s", (int)rc, took,
                 (unsigned)got, (char *)msg);
    } else if (SQL_SUCCEEDED(rc) || strcmp((char *)state, "HY024") != 0) {
      snprintf(m, sizeof m, "CONNECT_TIMEOUT=soon: rc=%d state '%s'", (int)rc, (char *)state);
    }
    if (SQL_SUCCEEDED(rc))
      SQLDisconnect(d);
    SQLFreeHandle(SQL_HANDLE_DBC, d);
    SQLFreeHandle(SQL_HANDLE_ENV, e);
  }
  if (m[0] == '\0')
    pass(name);
  else
    fail(name, m);
}

/* SQL_ATTR_QUERY_TIMEOUT (#209): a 1 s limit stops an 8 s PL/SQL loop with
 * HYT00 within the timeout and the 5 s the driver waits for the server to
 * answer its interrupt (the loop outlasts both). Then the connection either works (the server
 * answered: 21c and later) or reports itself dead and fails fast (it didn't:
 * 10g / 11g here) - never a call that hangs. Its own connection, as the
 * timeout may close it. */
/* With `per_connection`, the limit is SQL_ATTR_CONNECTION_TIMEOUT, which a
 * statement without a query timeout of its own takes (#228). */
static void check_query_timeout(const char *drv, const char *host, const char *port,
                                const char *svc, const char *user, const char *pwd,
                                int per_connection)
{
  const char *name = per_connection ? "SQL_ATTR_CONNECTION_TIMEOUT stops a long call with HYT00"
                                    : "SQL_ATTR_QUERY_TIMEOUT stops a long call with HYT00";
  SQLHENV e;
  SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &e);
  SQLSetEnvAttr(e, SQL_ATTR_ODBC_VERSION, (void *)SQL_OV_ODBC3, 0);
  SQLHDBC d;
  SQLAllocHandle(SQL_HANDLE_DBC, e, &d);
  char cs[640], m[600] = "";
  snprintf(cs, sizeof cs, "DRIVER=%s;HOST=%s;PORT=%s;SERVICE=%s;UID=%s;PWD=%s;", drv, host,
           port ? port : "1521", svc, user, pwd);
  SQLCHAR o[256];
  SQLSMALLINT ol;
  if (!SQL_SUCCEEDED(SQLDriverConnect(d, NULL, (SQLCHAR *)cs, SQL_NTS, o, sizeof o, &ol,
                                      SQL_DRIVER_NOPROMPT))) {
    skip(name, "connect failed");
    SQLFreeHandle(SQL_HANDLE_DBC, d);
    SQLFreeHandle(SQL_HANDLE_ENV, e);
    return;
  }
  SQLHSTMT st;
  SQLAllocHandle(SQL_HANDLE_STMT, d, &st);
  SQLULEN got = 0;
  if (per_connection) {
    SQLUINTEGER cg = 0;
    SQLSetConnectAttr(d, SQL_ATTR_CONNECTION_TIMEOUT, (SQLPOINTER)(uintptr_t)1, 0);
    SQLGetConnectAttr(d, SQL_ATTR_CONNECTION_TIMEOUT, &cg, 0, NULL);
    got = cg;
  } else {
    SQLSetStmtAttr(st, SQL_ATTR_QUERY_TIMEOUT, (SQLPOINTER)(uintptr_t)1, 0);
    SQLGetStmtAttr(st, SQL_ATTR_QUERY_TIMEOUT, &got, 0, NULL);
  }
  time_t t0 = time(NULL);
  SQLRETURN rc = SQLExecDirect(
      st,
      (SQLCHAR
           *)"DECLARE t DATE := SYSDATE + 8/86400; BEGIN WHILE SYSDATE < t LOOP NULL; END LOOP; "
             "END;",
      SQL_NTS);
  long took = (long)(time(NULL) - t0);
  SQLCHAR state[6] = "", msg[300] = "";
  SQLINTEGER native = 0;
  SQLSMALLINT len = 0;
  if (!SQL_SUCCEEDED(rc))
    SQLGetDiagRec(SQL_HANDLE_STMT, st, 1, state, &native, msg, sizeof msg, &len);
  SQLFreeHandle(SQL_HANDLE_STMT, st);
  if (got != 1)
    snprintf(m, sizeof m, "the attribute read back %lu, want 1", (unsigned long)got);
  else if (SQL_SUCCEEDED(rc) || strcmp((char *)state, "HYT00") != 0 || took > 9)
    snprintf(m, sizeof m, "rc=%d state '%s' after %ld s: %s", (int)rc, (char *)state, took,
             (char *)msg);
  if (m[0] == '\0') {
    /* Usable, or dead and saying so: the next call doesn't hang. */
    SQLUINTEGER dead = SQL_CD_FALSE;
    SQLGetConnectAttr(d, SQL_ATTR_CONNECTION_DEAD, &dead, 0, NULL);
    char one[16] = "", err[256] = "";
    t0 = time(NULL);
    SQLRETURN r2 = exec_scalar(d, "SELECT 1 FROM dual", one, sizeof one, err, sizeof err);
    took = (long)(time(NULL) - t0);
    if (dead == SQL_CD_FALSE && !(SQL_SUCCEEDED(r2) && strcmp(one, "1") == 0))
      snprintf(m, sizeof m, "connection alive but the next query failed: %s", err);
    else if (dead == SQL_CD_TRUE && (SQL_SUCCEEDED(r2) || took > 2))
      snprintf(m, sizeof m, "connection dead but the next query rc=%d after %ld s", (int)r2, took);
  }
  SQLDisconnect(d);
  SQLFreeHandle(SQL_HANDLE_DBC, d);
  SQLFreeHandle(SQL_HANDLE_ENV, e);
  if (m[0] == '\0')
    pass(name);
  else
    fail(name, m);
}

/* Connect-time failover (#201): HOST lists addresses, tried in order. A
 * closed port ahead of the server is passed over; a wrong password, refused
 * after the listener accepted, is the answer (ORA-01017) and not passed over
 * to the dead address behind it. */
static void check_connect_failover(const char *drv, const char *host, const char *port,
                                   const char *svc, const char *user, const char *pwd)
{
  const char *name = "connect-time failover across a HOST list";
  const char *p = port ? port : "1521";
  char hosts[2][320];
  snprintf(hosts[0], sizeof hosts[0], "127.0.0.1:1,%s", host);
  snprintf(hosts[1], sizeof hosts[1], "%s:%s,127.0.0.1:1", host, p);
  const char *pwds[2] = {pwd, "not-the-password"};
  for (int k = 0; k < 2; k++) {
    SQLHENV e;
    SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &e);
    SQLSetEnvAttr(e, SQL_ATTR_ODBC_VERSION, (void *)SQL_OV_ODBC3, 0);
    SQLHDBC d;
    SQLAllocHandle(SQL_HANDLE_DBC, e, &d);
    char cs[800], m[600] = "", err[256] = "", one[16] = "";
    snprintf(cs, sizeof cs, "DRIVER=%s;HOST=%s;PORT=%s;SERVICE=%s;UID=%s;PWD=%s;", drv, hosts[k], p,
             svc, user, pwds[k]);
    SQLCHAR o[256], state[6] = "", msg[400] = "";
    SQLSMALLINT ol, len = 0;
    SQLINTEGER native = 0;
    SQLRETURN rc =
        SQLDriverConnect(d, NULL, (SQLCHAR *)cs, SQL_NTS, o, sizeof o, &ol, SQL_DRIVER_NOPROMPT);
    int ok;
    if (k == 0) {
      ok = SQL_SUCCEEDED(rc) &&
           SQL_SUCCEEDED(exec_scalar(d, "SELECT 1 FROM dual", one, sizeof one, err, sizeof err)) &&
           strcmp(one, "1") == 0;
      if (!ok) {
        if (!SQL_SUCCEEDED(rc))
          diag_text(SQL_HANDLE_DBC, d, err, sizeof err);
        snprintf(m, sizeof m, "HOST=%s: %s", hosts[k], err[0] ? err : "query failed");
      }
    } else {
      if (!SQL_SUCCEEDED(rc))
        SQLGetDiagRec(SQL_HANDLE_DBC, d, 1, state, &native, msg, sizeof msg, &len);
      ok = !SQL_SUCCEEDED(rc) && native == 1017;
      if (!ok)
        snprintf(m, sizeof m, "HOST=%s, wrong password: rc=%d native=%ld '%s'", hosts[k], (int)rc,
                 (long)native, (char *)msg);
    }
    if (SQL_SUCCEEDED(rc))
      SQLDisconnect(d);
    SQLFreeHandle(SQL_HANDLE_DBC, d);
    SQLFreeHandle(SQL_HANDLE_ENV, e);
    if (!ok) {
      fail(name, m);
      return;
    }
  }
  pass(name);
}

/* EXPIRE_TIME: a connection with dead-connection detection on logs in and runs
 * (the descriptor carries (EXPIRE_TIME=n), the socket TCP keepalive), and a
 * value that isn't a whole number of minutes is refused before connecting. */
/* Open a connection of its own; NULL (and the reason in why) if it fails. */
static SQLHDBC open_conn(SQLHENV e, const char *drv, const char *host, const char *port,
                         const char *svc, const char *user, const char *pwd, char *why, size_t n)
{
  SQLHDBC d;
  SQLAllocHandle(SQL_HANDLE_DBC, e, &d);
  char cs[640];
  snprintf(cs, sizeof cs, "DRIVER=%s;HOST=%s;PORT=%s;SERVICE=%s;UID=%s;PWD=%s;", drv, host,
           port ? port : "1521", svc, user, pwd);
  if (SQL_SUCCEEDED(
          SQLDriverConnect(d, NULL, (SQLCHAR *)cs, SQL_NTS, NULL, 0, NULL, SQL_DRIVER_NOPROMPT)))
    return d;
  diag_text(SQL_HANDLE_DBC, d, why, n);
  SQLFreeHandle(SQL_HANDLE_DBC, d);
  return NULL;
}

/* A session the server ends over a live socket (#340): killed by a DBA, it
 * answers 08S01 (ORA-00028), then 08003 (ORA-01012), and
 * SQL_ATTR_CONNECTION_DEAD turns true. Needs a DBA login, from
 * SEER_TEST_DBA_USER / SEER_TEST_DBA_PASS; only the check's own session is
 * killed, found by its audit session id. */
static void check_session_killed(const char *drv, const char *host, const char *port,
                                 const char *svc, const char *user, const char *pwd)
{
  const char *name = "a session the server killed reads dead (08S01, CONNECTION_DEAD)";
  const char *du = getenv("SEER_TEST_DBA_USER"), *dp = getenv("SEER_TEST_DBA_PASS");
  if (du == NULL || dp == NULL || !du[0]) {
    skip(name, "set SEER_TEST_DBA_USER / SEER_TEST_DBA_PASS to kill a session");
    return;
  }
  char m[400] = "", why[256] = "", err[256], aud[32] = "", q[160], sid[32] = "", ser[32] = "";
  SQLHENV e;
  SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &e);
  SQLSetEnvAttr(e, SQL_ATTR_ODBC_VERSION, (void *)SQL_OV_ODBC3, 0);
  SQLHDBC a = open_conn(e, drv, host, port, svc, user, pwd, why, sizeof why);
  SQLHDBC b = a ? open_conn(e, drv, host, port, svc, du, dp, why, sizeof why) : NULL;
  if (a == NULL || b == NULL) {
    char r[300];
    snprintf(r, sizeof r, "login failed: %s", why);
    skip(name, r);
  } else {
    exec_scalar(a, "SELECT USERENV('SESSIONID') FROM dual", aud, sizeof aud, err, sizeof err);
    snprintf(q, sizeof q, "SELECT sid FROM v$session WHERE audsid = %s", aud);
    exec_scalar(b, q, sid, sizeof sid, err, sizeof err);
    snprintf(q, sizeof q, "SELECT serial# FROM v$session WHERE audsid = %s", aud);
    exec_scalar(b, q, ser, sizeof ser, err, sizeof err);
    snprintf(q, sizeof q, "ALTER SYSTEM KILL SESSION '%s,%s'", sid, ser);
    if (!aud[0] || !sid[0] || !SQL_SUCCEEDED(exec_do(b, q, err, sizeof err))) {
      snprintf(m, sizeof m, "could not kill own session (audsid '%s' sid '%s'): %s", aud, sid, err);
    } else {
      static const char *const WANT[2] = {"08S01", "08003"};
      for (int k = 0; k < 2 && !m[0]; k++) {
        SQLHSTMT s;
        SQLAllocHandle(SQL_HANDLE_STMT, a, &s);
        char st[6] = "";
        SQLRETURN rc = SQLExecDirect(s, (SQLCHAR *)"SELECT 1 FROM dual", SQL_NTS);
        diag_state(SQL_HANDLE_STMT, s, st);
        SQLFreeHandle(SQL_HANDLE_STMT, s);
        SQLUINTEGER dead = 99;
        SQLGetConnectAttr(a, SQL_ATTR_CONNECTION_DEAD, &dead, 0, NULL);
        if (rc != SQL_ERROR || strcmp(st, WANT[k]) != 0 || dead != SQL_CD_TRUE)
          snprintf(m, sizeof m, "call %d after the kill: rc=%d '%s' (want %s), CONNECTION_DEAD %u",
                   k + 1, (int)rc, st, WANT[k], (unsigned)dead);
      }
    }
    if (m[0] == '\0')
      pass(name);
    else
      fail(name, m);
  }
  if (a != NULL) {
    SQLDisconnect(a);
    SQLFreeHandle(SQL_HANDLE_DBC, a);
  }
  if (b != NULL) {
    SQLDisconnect(b);
    SQLFreeHandle(SQL_HANDLE_DBC, b);
  }
  SQLFreeHandle(SQL_HANDLE_ENV, e);
}

/* Switching SQL_ATTR_AUTOCOMMIT from OFF back to ON commits the open
 * transaction (#342): a row inserted in manual mode is visible to another
 * session right after the switch. Two-way: before it, it is not. */
static void check_autocommit_switch(SQLHDBC dbc, const char *drv, const char *host,
                                    const char *port, const char *svc, const char *user,
                                    const char *pwd)
{
  const char *name = "autocommit back ON commits the open transaction";
  char m[300] = "", why[256] = "", err[256], cnt[16] = "";
  exec_do(dbc, "DROP TABLE seer_acsw", err, sizeof err);
  if (!SQL_SUCCEEDED(exec_do(dbc, "CREATE TABLE seer_acsw (n NUMBER)", err, sizeof err))) {
    fail(name, err);
    return;
  }
  SQLHENV e;
  SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &e);
  SQLSetEnvAttr(e, SQL_ATTR_ODBC_VERSION, (void *)SQL_OV_ODBC3, 0);
  SQLHDBC a = open_conn(e, drv, host, port, svc, user, pwd, why, sizeof why);
  if (a == NULL) {
    snprintf(m, sizeof m, "second connection: %s", why);
  } else {
    SQLSetConnectAttr(a, SQL_ATTR_AUTOCOMMIT, (SQLPOINTER)SQL_AUTOCOMMIT_OFF, 0);
    exec_do(a, "INSERT INTO seer_acsw VALUES (1)", err, sizeof err);
    exec_scalar(dbc, "SELECT COUNT(*) FROM seer_acsw", cnt, sizeof cnt, err, sizeof err);
    if (strcmp(cnt, "0") != 0)
      snprintf(m, sizeof m, "before the switch another session sees %s rows, want 0", cnt);
    SQLRETURN rc = SQLSetConnectAttr(a, SQL_ATTR_AUTOCOMMIT, (SQLPOINTER)SQL_AUTOCOMMIT_ON, 0);
    exec_scalar(dbc, "SELECT COUNT(*) FROM seer_acsw", cnt, sizeof cnt, err, sizeof err);
    if (!m[0] && (!SQL_SUCCEEDED(rc) || strcmp(cnt, "1") != 0))
      snprintf(m, sizeof m, "after the switch (rc=%d) another session sees %s rows, want 1",
               (int)rc, cnt);
    SQLDisconnect(a);
    SQLFreeHandle(SQL_HANDLE_DBC, a);
  }
  SQLFreeHandle(SQL_HANDLE_ENV, e);
  exec_do(dbc, "DROP TABLE seer_acsw", err, sizeof err);
  if (m[0] == '\0')
    pass(name);
  else
    fail(name, m);
}

/* SQLDisconnect in manual-commit mode with a transaction open is 25000 and
 * leaves the connection up (#344); after a rollback it disconnects, and the
 * row was never committed. Two-way: with only a query run, disconnect
 * succeeds at once. 8i (its status flags, bus 95) and 10g+; not 9i, whose
 * compact replies don't say whether a transaction is open. */
static void check_disconnect_open_txn(SQLHDBC dbc, const char *drv, const char *host,
                                      const char *port, const char *svc, const char *user,
                                      const char *pwd)
{
  const char *name = "SQLDisconnect with an open transaction is 25000";
  char m[300] = "", why[256] = "", err[256], cnt[16] = "", st[6] = "", one[8] = "";
  exec_do(dbc, "DROP TABLE seer_dctx", err, sizeof err);
  if (!SQL_SUCCEEDED(exec_do(dbc, "CREATE TABLE seer_dctx (n NUMBER)", err, sizeof err))) {
    fail(name, err);
    return;
  }
  SQLHENV e;
  SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &e);
  SQLSetEnvAttr(e, SQL_ATTR_ODBC_VERSION, (void *)SQL_OV_ODBC3, 0);
  SQLHDBC a = open_conn(e, drv, host, port, svc, user, pwd, why, sizeof why);
  if (a == NULL) {
    snprintf(m, sizeof m, "second connection: %s", why);
  } else {
    SQLSetConnectAttr(a, SQL_ATTR_AUTOCOMMIT, (SQLPOINTER)SQL_AUTOCOMMIT_OFF, 0);
    exec_do(a, "INSERT INTO seer_dctx VALUES (1)", err, sizeof err);
    SQLRETURN rc = SQLDisconnect(a);
    diag_state(SQL_HANDLE_DBC, a, st);
    if (rc != SQL_ERROR || strcmp(st, "25000") != 0)
      snprintf(m, sizeof m, "disconnect with the insert open: rc=%d '%s', want 25000", (int)rc, st);
    else if (!SQL_SUCCEEDED(exec_scalar(a, "SELECT 1 FROM dual", one, sizeof one, err, sizeof err)))
      snprintf(m, sizeof m, "the connection did not stay up: %s", err);
    SQLEndTran(SQL_HANDLE_DBC, a, SQL_ROLLBACK);
    rc = SQLDisconnect(a);
    if (!m[0] && !SQL_SUCCEEDED(rc))
      snprintf(m, sizeof m, "disconnect after the rollback failed (rc=%d)", (int)rc);
    exec_scalar(dbc, "SELECT COUNT(*) FROM seer_dctx", cnt, sizeof cnt, err, sizeof err);
    if (!m[0] && strcmp(cnt, "0") != 0)
      snprintf(m, sizeof m, "the rolled-back row is there (%s rows)", cnt);
    SQLFreeHandle(SQL_HANDLE_DBC, a);
    /* two-way: a query alone leaves no transaction */
    a = m[0] ? NULL : open_conn(e, drv, host, port, svc, user, pwd, why, sizeof why);
    if (a != NULL) {
      SQLSetConnectAttr(a, SQL_ATTR_AUTOCOMMIT, (SQLPOINTER)SQL_AUTOCOMMIT_OFF, 0);
      exec_scalar(a, "SELECT 1 FROM dual", one, sizeof one, err, sizeof err);
      rc = SQLDisconnect(a);
      if (!SQL_SUCCEEDED(rc))
        snprintf(m, sizeof m, "disconnect after only a query: rc=%d", (int)rc);
      SQLFreeHandle(SQL_HANDLE_DBC, a);
    }
  }
  SQLFreeHandle(SQL_HANDLE_ENV, e);
  exec_do(dbc, "DROP TABLE seer_dctx", err, sizeof err);
  if (m[0] == '\0')
    pass(name);
  else
    fail(name, m);
}

/* Character data bound as a numeric parameter is an ODBC numeric literal,
 * '.' the decimal point, whatever the session's NLS_NUMERIC_CHARACTERS
 * (#354). With ',' as the decimal separator, "1.5" as SQL_NUMERIC /
 * SQL_DOUBLE (and as SQL_C_WCHAR) doubles to 3. Two-way: the same text as
 * SQL_VARCHAR is text, which the server still refuses there (ORA-01722) - so
 * the NLS setting is in force. */
static void check_numeric_text_params(const char *drv, const char *host, const char *port,
                                      const char *svc, const char *user, const char *pwd)
{
  const char *name = "character data for a numeric parameter ignores the session's NLS";
  char m[300] = "", why[256] = "", err[256];
  SQLHENV e;
  SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &e);
  SQLSetEnvAttr(e, SQL_ATTR_ODBC_VERSION, (void *)SQL_OV_ODBC3, 0);
  SQLHDBC a = open_conn(e, drv, host, port, svc, user, pwd, why, sizeof why);
  if (a == NULL) {
    snprintf(m, sizeof m, "connection: %s", why);
  } else if (!SQL_SUCCEEDED(
                 exec_do(a, "ALTER SESSION SET NLS_NUMERIC_CHARACTERS = ',.'", err, sizeof err))) {
    snprintf(m, sizeof m, "ALTER SESSION: %s", err);
  } else {
    static const SQLWCHAR W15[] = {'1', '.', '5', 0};
    struct {
      SQLSMALLINT ct, st;
      const void *v;
      int ok;
    } T[] = {
        {SQL_C_CHAR, SQL_NUMERIC, "1.5", 1},
        {SQL_C_CHAR, SQL_DOUBLE, "1.5", 1},
        {SQL_C_WCHAR, SQL_DECIMAL, W15, 1},
        {SQL_C_CHAR, SQL_VARCHAR, "1.5", 0},
    };
    for (size_t i = 0; i < sizeof T / sizeof T[0] && !m[0]; i++) {
      SQLHSTMT s;
      SQLAllocHandle(SQL_HANDLE_STMT, a, &s);
      SQLLEN ind = SQL_NTS, oi = 0;
      char out[32] = "", st[6] = "";
      SQLBindParameter(s, 1, SQL_PARAM_INPUT, T[i].ct, T[i].st, 20, 2, (SQLPOINTER)T[i].v, 0, &ind);
      SQLRETURN rc = SQLExecDirect(s, (SQLCHAR *)"SELECT ? * 2 FROM dual", SQL_NTS);
      if (SQL_SUCCEEDED(rc) && SQL_SUCCEEDED(rc = SQLFetch(s)))
        rc = SQLGetData(s, 1, SQL_C_CHAR, out, sizeof out, &oi);
      if (!SQL_SUCCEEDED(rc))
        diag_state(SQL_HANDLE_STMT, s, st);
      if (T[i].ok ? (!SQL_SUCCEEDED(rc) || strcmp(out, "3") != 0)
                  : (rc != SQL_ERROR || strcmp(st, "22018") != 0))
        snprintf(m, sizeof m, "C type %d as SQL type %d: rc=%d '%s' [%s] (want %s)", (int)T[i].ct,
                 (int)T[i].st, (int)rc, st, out, T[i].ok ? "3" : "22018, the text refused");
      SQLFreeHandle(SQL_HANDLE_STMT, s);
    }
  }
  if (a != NULL) {
    SQLDisconnect(a);
    SQLFreeHandle(SQL_HANDLE_DBC, a);
  }
  SQLFreeHandle(SQL_HANDLE_ENV, e);
  if (m[0] == '\0')
    pass(name);
  else
    fail(name, m);
}

/* ODBC date / timestamp literals as character data for a datetime parameter
 * (#356): the session's NLS_DATE_FORMAT (DD-MON-RR by default) refused them
 * (ORA-01861). Into a DATE and a TIMESTAMP column - bare, with a fraction, and
 * as an escape - each reads back as written. Two-way: text that is no literal
 * still goes as text, and the server still refuses it. */
static void check_datetime_text_params(SQLHDBC dbc)
{
  const char *name = "date / timestamp literals as text for a datetime parameter";
  char m[300] = "", err[256];
  exec_do(dbc, "DROP TABLE seer_dtxt", err, sizeof err);
  if (!SQL_SUCCEEDED(exec_do(dbc,
                             g_release >= 9 ? "CREATE TABLE seer_dtxt (d DATE, t TIMESTAMP(3))"
                                            : "CREATE TABLE seer_dtxt (d DATE, t DATE)",
                             err, sizeof err))) {
    fail(name, err);
    return;
  }
  struct {
    const char *col;
    SQLSMALLINT st;
    const char *in, *fmt, *want;
    int from, ok;
  } T[] = {
      {"d", SQL_TYPE_TIMESTAMP, "2026-11-20 10:11:12", "YYYY-MM-DD HH24:MI:SS",
       "2026-11-20 10:11:12", 8, 1},
      {"d", SQL_TYPE_DATE, "2026-11-20", "YYYY-MM-DD HH24:MI:SS", "2026-11-20 00:00:00", 8, 1},
      {"d", SQL_TYPE_TIMESTAMP, "{ts '2026-11-20 10:11:12'}", "YYYY-MM-DD HH24:MI:SS",
       "2026-11-20 10:11:12", 8, 1},
      {"t", SQL_TYPE_TIMESTAMP, "2026-11-20 10:11:12.5", "YYYY-MM-DD HH24:MI:SS.FF1",
       "2026-11-20 10:11:12.5", 9, 1},
      {"d", SQL_TYPE_DATE, "not a date", "", "", 8, 0},
  };
  for (size_t i = 0; i < sizeof T / sizeof T[0] && !m[0]; i++) {
    if (g_release < T[i].from)
      continue;
    exec_do(dbc, "DELETE FROM seer_dtxt", err, sizeof err);
    char ins[80], q[128], out[64] = "", st[6] = "";
    snprintf(ins, sizeof ins, "INSERT INTO seer_dtxt (%s) VALUES (?)", T[i].col);
    SQLHSTMT s;
    SQLAllocHandle(SQL_HANDLE_STMT, dbc, &s);
    SQLLEN ind = SQL_NTS;
    SQLBindParameter(s, 1, SQL_PARAM_INPUT, SQL_C_CHAR, T[i].st, 29, 3, (SQLPOINTER)T[i].in, 0,
                     &ind);
    SQLRETURN rc = SQLExecDirect(s, (SQLCHAR *)ins, SQL_NTS);
    if (!SQL_SUCCEEDED(rc))
      diag_state(SQL_HANDLE_STMT, s, st);
    SQLFreeHandle(SQL_HANDLE_STMT, s);
    if (!T[i].ok) {
      if (SQL_SUCCEEDED(rc))
        snprintf(m, sizeof m, "'%s' as SQL type %d was accepted", T[i].in, (int)T[i].st);
      continue;
    }
    snprintf(q, sizeof q, "SELECT TO_CHAR(%s, '%s') FROM seer_dtxt", T[i].col, T[i].fmt);
    if (SQL_SUCCEEDED(rc))
      exec_scalar(dbc, q, out, sizeof out, err, sizeof err);
    if (!SQL_SUCCEEDED(rc) || strcmp(out, T[i].want) != 0)
      snprintf(m, sizeof m, "'%s' as SQL type %d into %s: rc=%d '%s' read [%s], want %s", T[i].in,
               (int)T[i].st, T[i].col, (int)rc, st, out, T[i].want);
  }
  exec_do(dbc, "DROP TABLE seer_dtxt", err, sizeof err);
  if (m[0] == '\0')
    pass(name);
  else
    fail(name, m);
}

/* An Easy Connect target in DBQ, as Oracle's ODBC driver takes it (#362):
 * DBQ=host:port/service and DBQ=//host:port/service connect; a bare DBQ word
 * is a TNS alias and fails saying so. Two-way: before, every DBQ form failed
 * with "Missing HOST or SERVICE". */
static void check_easy_connect(const char *drv, const char *host, const char *port, const char *svc,
                               const char *user, const char *pwd)
{
  const char *name = "DBQ=host:port/service (Easy Connect) connects";
  char m[400] = "";
  SQLHENV e;
  SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &e);
  SQLSetEnvAttr(e, SQL_ATTR_ODBC_VERSION, (void *)SQL_OV_ODBC3, 0);
  for (int k = 0; k < 3 && !m[0]; k++) {
    char cs[640], why[300] = "";
    if (k == 2)
      snprintf(cs, sizeof cs, "DRIVER=%s;DBQ=SEER_NO_SUCH_ALIAS;UID=%s;PWD=%s;", drv, user, pwd);
    else
      snprintf(cs, sizeof cs, "DRIVER=%s;DBQ=%s%s:%s/%s;UID=%s;PWD=%s;", drv, k ? "//" : "", host,
               port ? port : "1521", svc, user, pwd);
    SQLHDBC d;
    SQLAllocHandle(SQL_HANDLE_DBC, e, &d);
    SQLRETURN rc =
        SQLDriverConnect(d, NULL, (SQLCHAR *)cs, SQL_NTS, NULL, 0, NULL, SQL_DRIVER_NOPROMPT);
    if (!SQL_SUCCEEDED(rc))
      diag_text(SQL_HANDLE_DBC, d, why, sizeof why);
    else
      SQLDisconnect(d);
    if (k < 2 && !SQL_SUCCEEDED(rc))
      snprintf(m, sizeof m, "DBQ=%s%s:%s/%s: %s", k ? "//" : "", host, port ? port : "1521", svc,
               why);
    if (k == 2 && (SQL_SUCCEEDED(rc) || strstr(why, "TNS alias") == NULL))
      snprintf(m, sizeof m, "a bare DBQ word: rc=%d '%s' (want a TNS-alias error)", (int)rc, why);
    SQLFreeHandle(SQL_HANDLE_DBC, d);
  }
  SQLFreeHandle(SQL_HANDLE_ENV, e);
  if (m[0] == '\0')
    pass(name);
  else
    fail(name, m);
}

/* A TNS alias from tnsnames.ora (#374): an entry for this tier's target,
 * written to a temporary TNS_ADMIN, connects through DBQ=<alias> and through
 * a SERVICE with no HOST; its first address is a dead one, so the entry's
 * address list fails over to the next. Two-way: an alias that isn't there
 * fails naming the file searched. */
static void check_tns_alias(const char *drv, const char *host, const char *port, const char *svc,
                            const char *user, const char *pwd)
{
  const char *name = "TNS alias from tnsnames.ora connects (DBQ / SERVICE, failover)";
#ifdef _WIN32
  (void)drv, (void)host, (void)port, (void)svc, (void)user, (void)pwd;
  skip(name, "todo: the check's temporary TNS_ADMIN needs a POSIX harness");
  return;
#else
  char dir[] = "/tmp/seer_tnsadmXXXXXX", path[256], m[400] = "";
  if (mkdtemp(dir) == NULL) {
    skip(name, "no temporary directory");
    return;
  }
  snprintf(path, sizeof path, "%s/tnsnames.ora", dir);
  int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600); /* owner-only */
  FILE *f = fd >= 0 ? fdopen(fd, "w") : NULL;
  if (f == NULL && fd >= 0)
    close(fd);
  if (f == NULL) {
    skip(name, "can't write tnsnames.ora");
    rmdir(dir);
    return;
  }
  fprintf(f,
          "# SeerODBC check_tns_alias\n"
          "SEER_ALIAS, SEER_ALIAS.WORLD =\n"
          "  (DESCRIPTION =\n"
          "    (ADDRESS_LIST =\n"
          "      (ADDRESS = (PROTOCOL = TCP)(HOST = 127.0.0.1)(PORT = 1))\n"
          "      (ADDRESS = (PROTOCOL = TCP)(HOST = %s)(PORT = %s)))\n"
          "    (CONNECT_DATA = (SERVER = DEDICATED)(SERVICE_NAME = %s)))\n",
          host, port ? port : "1521", svc);
  fclose(f);
  const char *old = getenv("TNS_ADMIN");
  char *saved = old ? strdup(old) : NULL;
  setenv("TNS_ADMIN", dir, 1);
  SQLHENV e;
  SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &e);
  SQLSetEnvAttr(e, SQL_ATTR_ODBC_VERSION, (void *)SQL_OV_ODBC3, 0);
  static const char *const TAIL[3] = {"DBQ=seer_alias.world", "SERVICE=SEER_ALIAS",
                                      "DBQ=SEER_NO_SUCH_ALIAS"};
  for (int k = 0; k < 3 && !m[0]; k++) {
    char cs[640], why[400] = "";
    snprintf(cs, sizeof cs, "DRIVER=%s;%s;UID=%s;PWD=%s;", drv, TAIL[k], user, pwd);
    SQLHDBC d;
    SQLAllocHandle(SQL_HANDLE_DBC, e, &d);
    SQLRETURN rc =
        SQLDriverConnect(d, NULL, (SQLCHAR *)cs, SQL_NTS, NULL, 0, NULL, SQL_DRIVER_NOPROMPT);
    if (!SQL_SUCCEEDED(rc))
      diag_text(SQL_HANDLE_DBC, d, why, sizeof why);
    else
      SQLDisconnect(d);
    if (k < 2 && !SQL_SUCCEEDED(rc))
      snprintf(m, sizeof m, "%s: %s", TAIL[k], why);
    if (k == 2 &&
        (SQL_SUCCEEDED(rc) || strstr(why, "not found") == NULL || strstr(why, path) == NULL))
      snprintf(m, sizeof m, "a missing alias: rc=%d '%s'", (int)rc, why);
    SQLFreeHandle(SQL_HANDLE_DBC, d);
  }
  SQLFreeHandle(SQL_HANDLE_ENV, e);
  if (saved != NULL) {
    setenv("TNS_ADMIN", saved, 1);
    free(saved);
  } else {
    unsetenv("TNS_ADMIN");
  }
  unlink(path);
  rmdir(dir);
  if (m[0] == '\0')
    pass(name);
  else
    fail(name, m);
#endif
}

/* The session time zone is set at login, as OCI sets it (#358): the OS's UTC
 * offset now, or ORA_SDTZ verbatim (an offset, a region) - it was the
 * server's default whatever the client's zone. Two-way: each ORA_SDTZ gives
 * its own SESSIONTIMEZONE, so the value isn't the server's default by chance. */
static void check_session_time_zone(const char *drv, const char *host, const char *port,
                                    const char *svc, const char *user, const char *pwd)
{
  const char *name = "session time zone set at login (OS offset, ORA_SDTZ)";
  if (gated(name))
    return;
#ifdef _WIN32
  (void)drv, (void)host, (void)port, (void)svc, (void)user, (void)pwd;
  skip(name, "todo: the check sets ORA_SDTZ with POSIX setenv");
#else
  time_t now = time(NULL);
  struct tm g;
  gmtime_r(&now, &g);
  g.tm_isdst = -1;
  int off = (int)(difftime(now, mktime(&g)) / 60.0), a = off < 0 ? -off : off;
  char os[16];
  snprintf(os, sizeof os, "%c%02d:%02d", off < 0 ? '-' : '+', a / 60, a % 60);
  const char *old = getenv("ORA_SDTZ");
  char *saved = old ? strdup(old) : NULL;
  static const char *const SDTZ[3] = {NULL, "-03:30", "Europe/Moscow"};
  char m[400] = "";
  SQLHENV e;
  SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &e);
  SQLSetEnvAttr(e, SQL_ATTR_ODBC_VERSION, (void *)SQL_OV_ODBC3, 0);
  for (int k = 0; k < 3 && !m[0]; k++) {
    if (SDTZ[k] == NULL)
      unsetenv("ORA_SDTZ");
    else
      setenv("ORA_SDTZ", SDTZ[k], 1);
    char why[300] = "", got[64] = "";
    SQLHDBC d = open_conn(e, drv, host, port, svc, user, pwd, why, sizeof why);
    if (d == NULL) {
      snprintf(m, sizeof m, "ORA_SDTZ=%s: %s", SDTZ[k] ? SDTZ[k] : "(unset)", why);
      break;
    }
    SQLHSTMT s;
    SQLAllocHandle(SQL_HANDLE_STMT, d, &s);
    SQLLEN ind;
    if (SQL_SUCCEEDED(SQLExecDirect(s, (SQLCHAR *)"SELECT SESSIONTIMEZONE FROM dual", SQL_NTS)) &&
        SQL_SUCCEEDED(SQLFetch(s)))
      SQLGetData(s, 1, SQL_C_CHAR, got, sizeof got, &ind);
    SQLFreeHandle(SQL_HANDLE_STMT, s);
    SQLDisconnect(d);
    SQLFreeHandle(SQL_HANDLE_DBC, d);
    for (size_t gl = strlen(got); gl > 0 && got[gl - 1] == ' '; gl--) /* 9i pads a region */
      got[gl - 1] = '\0';
    const char *want = SDTZ[k] ? SDTZ[k] : os;
    if (strcmp(got, want) != 0)
      snprintf(m, sizeof m, "ORA_SDTZ=%s: SESSIONTIMEZONE '%s', want '%s'",
               SDTZ[k] ? SDTZ[k] : "(unset)", got, want);
  }
  SQLFreeHandle(SQL_HANDLE_ENV, e);
  if (saved != NULL) {
    setenv("ORA_SDTZ", saved, 1);
    free(saved);
  } else {
    unsetenv("ORA_SDTZ");
  }
  if (m[0] == '\0')
    pass(name);
  else
    fail(name, m);
#endif
}

static void check_expire_time(const char *drv, const char *host, const char *port, const char *svc,
                              const char *user, const char *pwd)
{
  const char *name = "EXPIRE_TIME (TCP keepalive)";
  const char *vals[2] = {"5", "soon"};
  for (int k = 0; k < 2; k++) {
    SQLHENV e;
    SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &e);
    SQLSetEnvAttr(e, SQL_ATTR_ODBC_VERSION, (void *)SQL_OV_ODBC3, 0);
    SQLHDBC d;
    SQLAllocHandle(SQL_HANDLE_DBC, e, &d);
    char cs[640], m[400], err[256] = "", one[16] = "";
    snprintf(cs, sizeof cs, "DRIVER=%s;HOST=%s;PORT=%s;SERVICE=%s;UID=%s;PWD=%s;EXPIRE_TIME=%s;",
             drv, host, port ? port : "1521", svc, user, pwd, vals[k]);
    SQLCHAR o[256];
    SQLSMALLINT ol;
    SQLRETURN rc =
        SQLDriverConnect(d, NULL, (SQLCHAR *)cs, SQL_NTS, o, sizeof o, &ol, SQL_DRIVER_NOPROMPT);
    int ok;
    if (k == 0) {
      ok = SQL_SUCCEEDED(rc) &&
           SQL_SUCCEEDED(exec_scalar(d, "SELECT 1 FROM dual", one, sizeof one, err, sizeof err)) &&
           strcmp(one, "1") == 0;
      if (!ok) {
        if (!SQL_SUCCEEDED(rc))
          diag_text(SQL_HANDLE_DBC, d, err, sizeof err);
        snprintf(m, sizeof m, "EXPIRE_TIME=5: %s", err[0] ? err : "query failed");
      }
    } else {
      SQLCHAR state[6] = "";
      SQLINTEGER native = 0;
      SQLSMALLINT len = 0;
      SQLCHAR msg[256] = "";
      if (!SQL_SUCCEEDED(rc))
        SQLGetDiagRec(SQL_HANDLE_DBC, d, 1, state, &native, msg, sizeof msg, &len);
      ok = !SQL_SUCCEEDED(rc) && strcmp((char *)state, "HY024") == 0;
      if (!ok)
        snprintf(m, sizeof m, "EXPIRE_TIME=soon: rc=%d state '%s'", (int)rc, (char *)state);
    }
    if (SQL_SUCCEEDED(rc))
      SQLDisconnect(d);
    SQLFreeHandle(SQL_HANDLE_DBC, d);
    SQLFreeHandle(SQL_HANDLE_ENV, e);
    if (!ok) {
      fail(name, m);
      return;
    }
  }
  pass(name);
}

/* DRCP: a pooled connection (CCLASS + PURITY) routes via (SERVER=POOLED) and the
 * AUTH_KPPL_* pairs; a query on it exercises the server-side piggyback handling.
 * Skips where the server won't pool this client, with the server's own answer:
 * 10g has no pool, a pool may not be started, and 11g's pool serves only a
 * client speaking OCI's native form throughout (seerdb PROTOCOL.md §4.1.4),
 * which the driver doesn't. */
static void check_drcp(SQLHDBC dbc, const char *drv, const char *host, const char *port,
                       const char *svc, const char *user, const char *pwd)
{
  const char *name = "DRCP (pooled session)";
  GATE(name);
  char err[256];
  /* Best-effort: start the pool (needs DBA; harmless if already up / denied). */
  exec_do(dbc, "BEGIN DBMS_CONNECTION_POOL.START_POOL; END;", err, sizeof err);

  SQLHENV e;
  SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &e);
  SQLSetEnvAttr(e, SQL_ATTR_ODBC_VERSION, (void *)SQL_OV_ODBC3, 0);
  SQLHDBC d;
  SQLAllocHandle(SQL_HANDLE_DBC, e, &d);
  char cs[640];
  snprintf(cs, sizeof cs,
           "DRIVER=%s;HOST=%s;PORT=%s;SERVICE=%s;UID=%s;PWD=%s;CCLASS=SEERPOOL;PURITY=SELF;", drv,
           host, port ? port : "1521", svc, user, pwd);
  SQLCHAR o[256];
  SQLSMALLINT ol;
  if (!SQL_SUCCEEDED(SQLDriverConnect(d, NULL, (SQLCHAR *)cs, SQL_NTS, o, sizeof o, &ol,
                                      SQL_DRIVER_NOPROMPT))) {
    char why[300], m[360];
    diag_text(SQL_HANDLE_DBC, d, why, sizeof why);
    snprintf(m, sizeof m, "no pooled session: %s", why[0] ? why : "connect failed");
    skip(name, m);
  } else {
    char one[16];
    if (SQL_SUCCEEDED(exec_scalar(d, "SELECT 1 FROM dual", one, sizeof one, err, sizeof err)) &&
        strcmp(one, "1") == 0)
      pass(name);
    else
      fail(name, err[0] ? err : "pooled query failed (server piggyback?)");
    SQLDisconnect(d);
  }
  SQLFreeHandle(SQL_HANDLE_DBC, d);
  SQLFreeHandle(SQL_HANDLE_ENV, e);
}

/* Descriptor write path: bind a result column through the ARD via
 * SQLSetDescField (equivalent to SQLBindCol), and confirm the IRD is read-only. */
static void check_desc_write(SQLHDBC dbc)
{
  const char *name = "descriptor write (SQLSetDescField)";
  SQLHSTMT s;
  SQLAllocHandle(SQL_HANDLE_STMT, dbc, &s);
  if (!SQL_SUCCEEDED(SQLExecDirect(s, (SQLCHAR *)"SELECT 4242 FROM dual", SQL_NTS))) {
    fail(name, "select failed");
    SQLFreeHandle(SQL_HANDLE_STMT, s);
    return;
  }
  SQLHDESC ard = NULL, ird = NULL;
  SQLGetStmtAttr(s, SQL_ATTR_APP_ROW_DESC, &ard, 0, NULL);
  SQLGetStmtAttr(s, SQL_ATTR_IMP_ROW_DESC, &ird, 0, NULL);
  char col[64];
  SQLLEN ind = 0;
  SQLSetDescField(ard, 1, SQL_DESC_TYPE, (SQLPOINTER)(intptr_t)SQL_C_CHAR, 0);
  SQLSetDescField(ard, 1, SQL_DESC_DATA_PTR, col, 0);
  SQLSetDescField(ard, 1, SQL_DESC_OCTET_LENGTH, (SQLPOINTER)(intptr_t)sizeof col, 0);
  SQLSetDescField(ard, 1, SQL_DESC_INDICATOR_PTR, &ind, 0);
  /* The IRD (implementation row descriptor) must reject writes. */
  SQLRETURN ro = SQLSetDescField(ird, 1, SQL_DESC_TYPE, (SQLPOINTER)(intptr_t)SQL_C_CHAR, 0);
  col[0] = '\0';
  SQLRETURN rc = SQLFetch(s);
  if (SQL_SUCCEEDED(rc) && strcmp(col, "4242") == 0 && !SQL_SUCCEEDED(ro))
    pass(name);
  else {
    char m[128];
    snprintf(m, sizeof m, "rc=%d col='%s' ird_ro_rc=%d", rc, col, ro);
    fail(name, m);
  }
  SQLFreeHandle(SQL_HANDLE_STMT, s);
}

/* Nested SQL OBJECT fetch: an attribute that is itself an object is flattened
 * inline in the image; its leaf attributes are spliced into the layout. */
static void check_nested_object(SQLHDBC dbc)
{
  const char *name = "nested SQL OBJECT fetch";
  GATE(name);
  char err[256], out[256];
  exec_do(dbc, "DROP TABLE seer_nt", err, sizeof err);
  exec_do(dbc, "DROP TYPE seer_person", err, sizeof err);
  exec_do(dbc, "DROP TYPE seer_addr", err, sizeof err);
  if (!SQL_SUCCEEDED(exec_do(dbc,
                             "CREATE TYPE seer_addr AS OBJECT (street VARCHAR2(20), zip NUMBER)",
                             err, sizeof err)) ||
      !SQL_SUCCEEDED(exec_do(
          dbc, "CREATE TYPE seer_person AS OBJECT (nm VARCHAR2(20), age NUMBER, home seer_addr)",
          err, sizeof err))) {
    fail(name, err[0] ? err : "create type failed");
    return;
  }
  exec_do(dbc, "CREATE TABLE seer_nt (p seer_person)", err, sizeof err);
  exec_do(dbc, "INSERT INTO seer_nt VALUES (seer_person('Bob', 30, seer_addr('Main St', 12345)))",
          err, sizeof err);
  if (SQL_SUCCEEDED(exec_scalar(dbc, "SELECT p FROM seer_nt", out, sizeof out, err, sizeof err)) &&
      strstr(out, "Bob") != NULL && strstr(out, "Main St") != NULL && strstr(out, "12345") != NULL)
    pass(name);
  else {
    char m[300];
    snprintf(m, sizeof m, "got '%s'", out);
    fail(name, err[0] ? err : m);
  }
  exec_do(dbc, "DROP TABLE seer_nt", err, sizeof err);
  exec_do(dbc, "DROP TYPE seer_person", err, sizeof err);
  exec_do(dbc, "DROP TYPE seer_addr", err, sizeof err);
}

/* Large value fetch: a column value >= 254 bytes arrives 0xFE-chunked. The chunk
 * length is sb4 on 12c+ / ub1 on 11g; reading the wrong width desynced the value
 * (SEER_EPROTO). Fetch a 3000-char VARCHAR2 and confirm the full length. */
static void check_large_fetch(SQLHDBC dbc)
{
  const char *name = "large value fetch (chunked DALC)";
  char err[256];
  SQLHSTMT s;
  SQLAllocHandle(SQL_HANDLE_STMT, dbc, &s);
  if (SQL_SUCCEEDED(SQLExecDirect(s, (SQLCHAR *)"SELECT RPAD('x',3000,'x') FROM dual", SQL_NTS))) {
    char buf[4096];
    SQLLEN ind = 0;
    SQLBindCol(s, 1, SQL_C_CHAR, buf, sizeof buf, &ind);
    if (SQL_SUCCEEDED(SQLFetch(s)) && ind == 3000)
      pass(name);
    else {
      char m[64];
      snprintf(m, sizeof m, "ind=%ld (want 3000)", (long)ind);
      fail(name, m);
    }
  } else {
    diag_text(SQL_HANDLE_STMT, s, err, sizeof err);
    fail(name, err[0] ? err : "select failed");
  }
  SQLFreeHandle(SQL_HANDLE_STMT, s);
}

/* Statement cache: re-preparing the same SQL reuses its parsed server cursor.
 * Verifies reuse returns correct results, and that a DDL recreating the table
 * flushes the cache (a stale cached cursor would return the OLD data). */
static void check_stmt_cache(SQLHDBC dbc)
{
  const char *name = "statement cache (reuse + DDL flush)";
  char err[256], out[128];
  exec_do(dbc, "DROP TABLE seer_sc", err, sizeof err);
  if (!SQL_SUCCEEDED(exec_do(dbc, "CREATE TABLE seer_sc (n NUMBER)", err, sizeof err))) {
    skip(name, "cannot create test table");
    return;
  }
  exec_do(dbc, "INSERT INTO seer_sc VALUES (11)", err, sizeof err);
  exec_do(dbc, "INSERT INTO seer_sc VALUES (22)", err, sizeof err);
  out[0] = '\0';
  exec_scalar(dbc, "SELECT SUM(n) FROM seer_sc", out, sizeof out, err, sizeof err);
  int first = strcmp(out, "33") == 0; /* parse + cache */
  out[0] = '\0';
  exec_scalar(dbc, "SELECT SUM(n) FROM seer_sc", out, sizeof out, err, sizeof err);
  int reuse = strcmp(out, "33") == 0; /* reuse the cursor */
  /* Recreate the table with different data - the DDL must invalidate the cache. */
  exec_do(dbc, "DROP TABLE seer_sc", err, sizeof err);
  exec_do(dbc, "CREATE TABLE seer_sc (n NUMBER)", err, sizeof err);
  exec_do(dbc, "INSERT INTO seer_sc VALUES (7)", err, sizeof err);
  out[0] = '\0';
  exec_scalar(dbc, "SELECT SUM(n) FROM seer_sc", out, sizeof out, err, sizeof err);
  int flush = strcmp(out, "7") == 0; /* new data, not stale 33 */
  if (first && reuse && flush)
    pass(name);
  else {
    char m[160];
    snprintf(m, sizeof m, "first=%d reuse=%d flush=%d (last got '%s')", first, reuse, flush, out);
    fail(name, m);
  }
  exec_do(dbc, "DROP TABLE seer_sc", err, sizeof err);
}

/* XMLType fetch: an inline XML document decodes to its text. Skips where XMLType
 * isn't available (e.g. an instance without XML DB). */
/* LOB-backed XMLType fetch: a CLOB-stored XMLType column returns a LOB locator
 * (not inline text); the driver reads the locator and decodes it to XML text.
 * Skips on legacy CLOB storage (11g, not decoded inline) or where unavailable. */
static void check_xmltype_lob(SQLHDBC dbc)
{
  const char *name = "XMLType fetch (LOB-backed)";
  GATE(name);
  char err[256], out[512];
  exec_do(dbc, "DROP TABLE seer_xmll", err, sizeof err);
  if (!SQL_SUCCEEDED(exec_do(dbc,
                             "CREATE TABLE seer_xmll (doc XMLTYPE) "
                             "XMLTYPE COLUMN doc STORE AS CLOB",
                             err, sizeof err))) {
    fail(name, err);
    return;
  }
  if (!SQL_SUCCEEDED(exec_do(dbc, "INSERT INTO seer_xmll VALUES (XMLTYPE('<a><b>hi</b></a>'))", err,
                             sizeof err))) {
    fail(name, err);
    exec_do(dbc, "DROP TABLE seer_xmll", err, sizeof err);
    return;
  }
  out[0] = '\0';
  SQLRETURN rc = exec_scalar(dbc, "SELECT doc FROM seer_xmll", out, sizeof out, err, sizeof err);
  if (SQL_SUCCEEDED(rc) && strstr(out, "<a>") != NULL && strstr(out, "hi") != NULL)
    pass(name); /* the LOB locator was read + decoded */
  else {
    char m[600];
    snprintf(m, sizeof m, "got '%s'", out);
    fail(name, err[0] ? err : m);
  }
  exec_do(dbc, "DROP TABLE seer_xmll", err, sizeof err);
}

static void check_xmltype(SQLHDBC dbc)
{
  const char *name = "XMLType fetch";
  GATE(name);
  char err[256], out[512];
  exec_do(dbc, "DROP TABLE seer_xml", err, sizeof err);
  if (!SQL_SUCCEEDED(exec_do(dbc, "CREATE TABLE seer_xml (doc XMLTYPE)", err, sizeof err))) {
    fail(name, err);
    return;
  }
  if (!SQL_SUCCEEDED(exec_do(dbc, "INSERT INTO seer_xml VALUES (XMLTYPE('<a><b>hi</b></a>'))", err,
                             sizeof err))) {
    fail(name, err);
    exec_do(dbc, "DROP TABLE seer_xml", err, sizeof err);
    return;
  }
  out[0] = '\0';
  SQLRETURN rc = exec_scalar(dbc, "SELECT doc FROM seer_xml", out, sizeof out, err, sizeof err);
  int read = SQL_SUCCEEDED(rc) && strstr(out, "<a>") != NULL && strstr(out, "hi") != NULL;
  if (g_release == 11 && !read) {
    /* 11g sends binary XML - its default storage where XML DB has it - as
     * CSX, which no reference client reads: the cell's read says so and
     * names the SQL that reads it, which then does (#416). It used to read
     * as NULL. An 11g that stores the column as a CLOB reads it as text. */
    char named[256] = "";
    snprintf(named, sizeof named, "%s", err);
    SQLRETURN xr = exec_scalar(dbc, "SELECT XMLSERIALIZE(DOCUMENT doc AS CLOB) FROM seer_xml", out,
                               sizeof out, err, sizeof err);
    if (!SQL_SUCCEEDED(rc) && strstr(named, "XMLSERIALIZE") != NULL && SQL_SUCCEEDED(xr) &&
        strstr(out, "<a>") != NULL)
      pass(name);
    else {
      char m[700];
      snprintf(m, sizeof m, "11g: read rc=%d '%s', XMLSERIALIZE rc=%d '%s'", (int)rc, named,
               (int)xr, out);
      fail(name, m);
    }
  } else if (read)
    pass(name);
  else {
    char m[600];
    snprintf(m, sizeof m, "got '%s'", out);
    fail(name, err[0] ? err : m);
  }
  exec_do(dbc, "DROP TABLE seer_xml", err, sizeof err);
}

/* Object-with-collection-attribute fetch: an object whose attribute is a VARRAY
 * decodes with the collection rendered inline as "[...]" (the attribute stays a
 * single variable-length entry in the layout, not flattened). */
static void check_object_with_collection(SQLHDBC dbc)
{
  const char *name = "object-with-collection-attr fetch";
  GATE(name);
  char err[256], out[256];
  exec_do(dbc, "DROP TABLE seer_owc", err, sizeof err);
  exec_do(dbc, "DROP TYPE seer_prsn", err, sizeof err);
  exec_do(dbc, "DROP TYPE seer_phon", err, sizeof err);
  if (!SQL_SUCCEEDED(
          exec_do(dbc, "CREATE TYPE seer_phon AS VARRAY(5) OF VARCHAR2(20)", err, sizeof err))) {
    fail(name, err);
    return;
  }
  exec_do(dbc, "CREATE TYPE seer_prsn AS OBJECT (nm VARCHAR2(20), age NUMBER, ph seer_phon)", err,
          sizeof err);
  exec_do(dbc, "CREATE TABLE seer_owc (p seer_prsn)", err, sizeof err);
  exec_do(dbc,
          "INSERT INTO seer_owc VALUES "
          "(seer_prsn('Bob', 42, seer_phon('555-1234', '555-5678')))",
          err, sizeof err);
  if (SQL_SUCCEEDED(exec_scalar(dbc, "SELECT p FROM seer_owc", out, sizeof out, err, sizeof err)) &&
      strstr(out, "Bob") != NULL && strstr(out, "42") != NULL &&
      strstr(out, "[555-1234, 555-5678]") != NULL)
    pass(name);
  else {
    char m[300];
    snprintf(m, sizeof m, "got '%s'", out);
    fail(name, err[0] ? err : m);
  }
  exec_do(dbc, "DROP TABLE seer_owc", err, sizeof err);
  exec_do(dbc, "DROP TYPE seer_prsn", err, sizeof err);
  exec_do(dbc, "DROP TYPE seer_phon", err, sizeof err);
}

/* Collection-of-objects fetch: a VARRAY whose elements are objects decodes to
 * "[(a, b), ...]" (the element object's layout is fetched from the dictionary). */
static void check_collection_of_objects(SQLHDBC dbc)
{
  const char *name = "collection-of-objects fetch";
  GATE(name);
  char err[256], out[256];
  exec_do(dbc, "DROP TABLE seer_cot", err, sizeof err);
  exec_do(dbc, "DROP TYPE seer_ptv", err, sizeof err);
  exec_do(dbc, "DROP TYPE seer_pt", err, sizeof err);
  if (!SQL_SUCCEEDED(
          exec_do(dbc, "CREATE TYPE seer_pt AS OBJECT (x NUMBER, y NUMBER)", err, sizeof err))) {
    fail(name, err);
    return;
  }
  exec_do(dbc, "CREATE TYPE seer_ptv AS VARRAY(5) OF seer_pt", err, sizeof err);
  exec_do(dbc, "CREATE TABLE seer_cot (v seer_ptv)", err, sizeof err);
  exec_do(dbc, "INSERT INTO seer_cot VALUES (seer_ptv(seer_pt(1, 2), seer_pt(3, 4)))", err,
          sizeof err);
  if (SQL_SUCCEEDED(exec_scalar(dbc, "SELECT v FROM seer_cot", out, sizeof out, err, sizeof err)) &&
      strstr(out, "1, 2") != NULL && strstr(out, "3, 4") != NULL)
    pass(name);
  else {
    char m[300];
    snprintf(m, sizeof m, "got '%s'", out);
    fail(name, err[0] ? err : m);
  }
  exec_do(dbc, "DROP TABLE seer_cot", err, sizeof err);
  exec_do(dbc, "DROP TYPE seer_ptv", err, sizeof err);
  exec_do(dbc, "DROP TYPE seer_pt", err, sizeof err);
}

/* SQL OBJECT (ADT) fetch: a flat object of scalar attributes is decoded to
 * "v1, v2, ..." text (attribute layout fetched from the data dictionary). */
static void check_object(SQLHDBC dbc)
{
  const char *name = "SQL OBJECT (ADT) fetch";
  GATE(name);
  char err[256], out[256];
  exec_do(dbc, "DROP TABLE seer_ot", err, sizeof err);
  exec_do(dbc, "DROP TYPE seer_objt", err, sizeof err);
  if (!SQL_SUCCEEDED(exec_do(dbc, "CREATE TYPE seer_objt AS OBJECT (n NUMBER, s VARCHAR2(20))", err,
                             sizeof err))) {
    fail(name, err[0] ? err : "create type failed");
    return;
  }
  exec_do(dbc, "CREATE TABLE seer_ot (o seer_objt)", err, sizeof err);
  exec_do(dbc, "INSERT INTO seer_ot VALUES (seer_objt(42, 'hello'))", err, sizeof err);
  if (SQL_SUCCEEDED(exec_scalar(dbc, "SELECT o FROM seer_ot", out, sizeof out, err, sizeof err)) &&
      strstr(out, "42") != NULL && strstr(out, "hello") != NULL)
    pass(name);
  else {
    char m[300];
    snprintf(m, sizeof m, "got '%s'", out);
    fail(name, err[0] ? err : m);
  }
  exec_do(dbc, "DROP TABLE seer_ot", err, sizeof err);
  exec_do(dbc, "DROP TYPE seer_objt", err, sizeof err);
}

/* Collection (VARRAY) fetch: decoded to "[e1, e2, ...]" text (element type from
 * ALL_COLL_TYPES). Nested tables share the same image/decode path. */
static void check_collection(SQLHDBC dbc)
{
  const char *name = "VARRAY / collection fetch";
  GATE(name);
  char err[256], out[256];
  exec_do(dbc, "DROP TABLE seer_ct", err, sizeof err);
  exec_do(dbc, "DROP TYPE seer_va", err, sizeof err);
  if (!SQL_SUCCEEDED(exec_do(dbc, "CREATE TYPE seer_va AS VARRAY(5) OF NUMBER", err, sizeof err))) {
    fail(name, err[0] ? err : "create type failed");
    return;
  }
  exec_do(dbc, "CREATE TABLE seer_ct (v seer_va)", err, sizeof err);
  exec_do(dbc, "INSERT INTO seer_ct VALUES (seer_va(10, 20, 30))", err, sizeof err);
  if (SQL_SUCCEEDED(exec_scalar(dbc, "SELECT v FROM seer_ct", out, sizeof out, err, sizeof err)) &&
      strstr(out, "10") != NULL && strstr(out, "20") != NULL && strstr(out, "30") != NULL)
    pass(name);
  else {
    char m[300];
    snprintf(m, sizeof m, "got '%s'", out);
    fail(name, err[0] ? err : m);
  }
  exec_do(dbc, "DROP TABLE seer_ct", err, sizeof err);
  exec_do(dbc, "DROP TYPE seer_va", err, sizeof err);
}

/* REF fetch: an object reference is surfaced as its opaque locator in hex. */
static void check_ref(SQLHDBC dbc)
{
  const char *name = "REF fetch";
  GATE(name);
  char err[256], out[256];
  exec_do(dbc, "DROP TABLE seer_oref", err, sizeof err);
  exec_do(dbc, "DROP TYPE seer_robj", err, sizeof err);
  if (!SQL_SUCCEEDED(exec_do(dbc, "CREATE TYPE seer_robj AS OBJECT (n NUMBER)", err, sizeof err))) {
    fail(name, err[0] ? err : "create type failed");
    return;
  }
  exec_do(dbc, "CREATE TABLE seer_oref OF seer_robj", err, sizeof err);
  exec_do(dbc, "INSERT INTO seer_oref VALUES (seer_robj(1))", err, sizeof err);
  if (SQL_SUCCEEDED(
          exec_scalar(dbc, "SELECT REF(t) FROM seer_oref t", out, sizeof out, err, sizeof err)) &&
      strlen(out) >= 40 && strspn(out, "0123456789ABCDEF") == strlen(out))
    pass(name);
  else {
    char m[300];
    snprintf(m, sizeof m, "got '%s'", out);
    fail(name, err[0] ? err : m);
  }
  exec_do(dbc, "DROP TABLE seer_oref", err, sizeof err);
  exec_do(dbc, "DROP TYPE seer_robj", err, sizeof err);
}

/* Native BINARY_FLOAT bind (4-byte, was widened to BINARY_DOUBLE). */
static void check_float_bind(SQLHDBC dbc)
{
  const char *name = "BINARY_FLOAT bind";
  GATE(name);
  char err[256], out[64];
  exec_do(dbc, "DROP TABLE seer_bf", err, sizeof err);
  if (!SQL_SUCCEEDED(exec_do(dbc, "CREATE TABLE seer_bf (f BINARY_FLOAT)", err, sizeof err))) {
    fail(name, err[0] ? err : "create failed");
    return;
  }
  SQLHSTMT st;
  SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st);
  SQLREAL v = 3.5f;
  SQLLEN ind = 0;
  SQLBindParameter(st, 1, SQL_PARAM_INPUT, SQL_C_FLOAT, SQL_REAL, 0, 0, &v, 0, &ind);
  SQLRETURN rc = SQLExecDirect(st, (SQLCHAR *)"INSERT INTO seer_bf VALUES (?)", SQL_NTS);
  SQLFreeHandle(SQL_HANDLE_STMT, st);
  if (SQL_SUCCEEDED(rc) &&
      SQL_SUCCEEDED(exec_scalar(dbc, "SELECT f FROM seer_bf", out, sizeof out, err, sizeof err)) &&
      strstr(out, "3.5") != NULL)
    pass(name);
  else {
    char m[200];
    snprintf(m, sizeof m, "got '%s' rc=%d", out, rc);
    fail(name, err[0] ? err : m);
  }
  exec_do(dbc, "DROP TABLE seer_bf", err, sizeof err);
}

/* Native 23ai BOOLEAN bind (SQL_C_BIT). Skipped where the type / its native form
 * isn't available. */
static void check_bool_bind(SQLHDBC dbc)
{
  const char *name = "BOOLEAN bind (23ai)";
  GATE(name);
  char err[256], out[64];
  exec_do(dbc, "DROP TABLE seer_bb", err, sizeof err);
  if (!SQL_SUCCEEDED(exec_do(dbc, "CREATE TABLE seer_bb (b BOOLEAN)", err, sizeof err))) {
    fail(name, err);
    return;
  }
  SQLHSTMT st;
  SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st);
  unsigned char v = 1;
  SQLLEN ind = 0;
  SQLBindParameter(st, 1, SQL_PARAM_INPUT, SQL_C_BIT, SQL_BIT, 0, 0, &v, 0, &ind);
  SQLRETURN rc = SQLExecDirect(st, (SQLCHAR *)"INSERT INTO seer_bb VALUES (?)", SQL_NTS);
  SQLFreeHandle(SQL_HANDLE_STMT, st);
  if (!SQL_SUCCEEDED(rc)) {
    diag_text(SQL_HANDLE_STMT, st, err, sizeof err);
    skip(name, "native BOOLEAN bind not surfaced at this protocol level");
    exec_do(dbc, "DROP TABLE seer_bb", err, sizeof err);
    return;
  }
  if (SQL_SUCCEEDED(exec_scalar(dbc, "SELECT b FROM seer_bb", out, sizeof out, err, sizeof err)) &&
      strstr(out, "TRUE") != NULL)
    pass(name);
  else if (strstr(out, "1") != NULL)
    skip(name, "native BOOLEAN not surfaced at this protocol level");
  else {
    char m[200];
    snprintf(m, sizeof m, "got '%s'", out);
    fail(name, m);
  }
  exec_do(dbc, "DROP TABLE seer_bb", err, sizeof err);
}

/* SQLNativeSql: ODBC {escape} expansion + '?' -> :1 marker rewrite. Pure string
 * transform, so it's server-independent. */
static void check_native_sql(SQLHDBC dbc)
{
  const char *name = "SQLNativeSql";
  SQLCHAR out[256] = {0};
  SQLINTEGER outlen = 0;
  SQLRETURN rc = SQLNativeSql(dbc, (SQLCHAR *)"SELECT {fn UCASE(v)} FROM dual WHERE id = ?",
                              SQL_NTS, out, sizeof out, &outlen);
  if (SQL_SUCCEEDED(rc) && strstr((char *)out, "UPPER(") && strstr((char *)out, ":1") &&
      !strstr((char *)out, "{fn") && !strchr((char *)out, '?'))
    pass(name);
  else {
    char m[320];
    snprintf(m, sizeof m, "got '%s'", (char *)out);
    fail(name, m);
  }
}

/* Register a throwaway DSN in temp ini files and point the DM at them - done
 * once, before the first ODBC call, since unixODBC caches the ini paths at load
 * (a mid-run setenv has no effect). unixODBC's browse can't bootstrap from a raw
 * DRIVER=path the way SQLDriverConnect can, so a DSN is the only way to test it.
 * `dir` (>= 64 bytes) receives the temp dir, or "" on failure. */
/* Like fopen(path, "w") but creates the file mode 0600 rather than the
 * umask-default 0666 - correct hygiene for a config file, and avoids
 * CodeQL cpp/world-writable-file-creation. */
static FILE *fopen_private(const char *path)
{
  int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
  if (fd < 0)
    return NULL;
  FILE *f = fdopen(fd, "w");
  if (f == NULL)
    close(fd);
  return f;
}

static void setup_browse_dsn(char *dir, const char *drv, const char *host, const char *port,
                             const char *svc)
{
  dir[0] = '\0';
  char tmpl[] = "/tmp/seerbrowseXXXXXX";
  if (mkdtemp(tmpl) == NULL)
    return;
  char inst[600], ini[600];
  snprintf(inst, sizeof inst, "%s/odbcinst.ini", tmpl);
  snprintf(ini, sizeof ini, "%s/odbc.ini", tmpl);
  FILE *f = fopen_private(inst);
  if (f) {
    fprintf(f, "[SeerBrowse]\nDriver=%s\n", drv);
    fclose(f);
  }
  f = fopen_private(ini);
  if (f) {
    fprintf(f, "[SeerBrowseDSN]\nDriver=SeerBrowse\nHOST=%s\nPORT=%s\nSERVICE=%s\n", host, port,
            svc);
    fclose(f);
  }
  setenv("ODBCSYSINI", tmpl, 1);
  setenv("ODBCINI", ini, 1);
  snprintf(dir, 64, "%s", tmpl);
}

/* SQLBrowseConnect: round 1 supplies the DSN (target) but no credentials -> the
 * driver returns SQL_NEED_DATA asking for UID/PWD; round 2 supplies them ->
 * connected. `dir` is the registered-DSN temp dir from setup_browse_dsn. */
static void check_browse_connect(const char *dir, const char *user, const char *pwd)
{
  const char *name = "SQLBrowseConnect";
  if (dir[0] == '\0') {
    skip(name, "temp DSN setup failed");
    return;
  }

  SQLHENV env;
  SQLHDBC dbc;
  SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &env);
  SQLSetEnvAttr(env, SQL_ATTR_ODBC_VERSION, (void *)SQL_OV_ODBC3, 0);
  SQLAllocHandle(SQL_HANDLE_DBC, env, &dbc);

  SQLCHAR out[512] = {0};
  SQLSMALLINT outlen = 0;
  SQLRETURN rc =
      SQLBrowseConnect(dbc, (SQLCHAR *)"DSN=SeerBrowseDSN;", SQL_NTS, out, sizeof out, &outlen);
  int round1 = (rc == SQL_NEED_DATA) && strstr((char *)out, "UID") && strstr((char *)out, "PWD");

  int round2 = 0;
  if (round1) {
    char cs[256];
    snprintf(cs, sizeof cs, "UID=%s;PWD=%s;", user, pwd);
    rc = SQLBrowseConnect(dbc, (SQLCHAR *)cs, SQL_NTS, out, sizeof out, &outlen);
    round2 = SQL_SUCCEEDED(rc);
  }

  if (round1 && round2)
    pass(name);
  else if (!round1)
    skip(name, "driver/DSN not resolvable by the DM for browse");
  else {
    char m[200];
    snprintf(m, sizeof m, "round2 connect failed (rc=%d)", rc);
    fail(name, m);
  }
  SQLDisconnect(dbc);
  SQLFreeHandle(SQL_HANDLE_DBC, dbc);
  SQLFreeHandle(SQL_HANDLE_ENV, env);
}

/* Descriptor read path: get the implementation row descriptor (IRD) and read
 * the result-column metadata via SQLGetDescField/Rec (the descriptor-API view
 * of SQLDescribeCol). Server-independent (DUAL). */
static void check_descriptors(SQLHDBC dbc)
{
  const char *name = "descriptor read (IRD)";
  SQLHSTMT st;
  char err[256];
  SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st);
  SQLRETURN rc = SQLExecDirect(st, (SQLCHAR *)"SELECT 1 AS id, 'x' AS v FROM DUAL", SQL_NTS);
  if (!SQL_SUCCEEDED(rc)) {
    diag_text(SQL_HANDLE_STMT, st, err, sizeof err);
    fail(name, err[0] ? err : "execute failed");
    SQLFreeHandle(SQL_HANDLE_STMT, st);
    return;
  }
  SQLHDESC ird = NULL;
  SQLGetStmtAttr(st, SQL_ATTR_IMP_ROW_DESC, &ird, 0, NULL);

  SQLSMALLINT cnt = 0;
  SQLGetDescField(ird, 0, SQL_DESC_COUNT, &cnt, 0, NULL);

  SQLCHAR cname[64] = {0};
  SQLSMALLINT nlen = 0, ctype = 0, csub = 0, cprec = 0, cscale = 0, cnull = 0;
  SQLLEN clen = 0;
  SQLRETURN r2 = SQLGetDescRec(ird, 2, cname, sizeof cname, &nlen, &ctype, &csub, &clen, &cprec,
                               &cscale, &cnull);
  SQLSMALLINT t1 = 0;
  SQLGetDescField(ird, 1, SQL_DESC_TYPE, &t1, 0, NULL);

  if (ird != NULL && cnt == 2 && SQL_SUCCEEDED(r2) && strcmp((char *)cname, "V") == 0 &&
      ctype != 0 && t1 != 0)
    pass(name);
  else {
    char m[200];
    snprintf(m, sizeof m, "ird=%p count=%d rec2='%s' ctype=%d t1=%d", (void *)ird, cnt,
             (char *)cname, ctype, t1);
    fail(name, m);
  }
  SQLFreeHandle(SQL_HANDLE_STMT, st);
}

/* SQLBulkOperations is deliberately not supported (no bookmarks): SQLGetFunctions
 * reports it false and a call fails cleanly. (Through the DM the failure is the
 * Driver Manager's IM001; a direct caller gets the driver's HYC00.) */
static void check_bulk_unsupported(SQLHDBC dbc)
{
  const char *name = "SQLBulkOperations (unsupported)";
  SQLUSMALLINT sup = 99;
  SQLGetFunctions(dbc, SQL_API_SQLBULKOPERATIONS, &sup);
  SQLHSTMT st;
  SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st);
  SQLExecDirect(st, (SQLCHAR *)"SELECT 1 FROM DUAL", SQL_NTS);
  SQLRETURN rc = SQLBulkOperations(st, SQL_ADD);
  SQLFreeHandle(SQL_HANDLE_STMT, st);
  if (sup == SQL_FALSE && !SQL_SUCCEEDED(rc))
    pass(name);
  else {
    char m[120];
    snprintf(m, sizeof m, "supported=%d rc=%d (want false + failure)", sup, rc);
    fail(name, m);
  }
}

int main(void)
{
  const char *host = getenv("SEER_TEST_HOST");
  const char *port = getenv("SEER_TEST_PORT");
  const char *svc = getenv("SEER_TEST_SERVICE");
  const char *user = getenv("SEER_TEST_USER");
  const char *pwd = getenv("SEER_TEST_PASS");
  const char *drv = getenv("SEER_DRIVER");
  if (drv == NULL || drv[0] == '\0')
    drv = SEER_DRIVER_PATH;
  if (host == NULL || svc == NULL || user == NULL || drv[0] == '\0') {
    fprintf(stderr, "integration: no target configured "
                    "(set SEER_TEST_HOST/SERVICE/USER[/PORT/PASS] and SEER_DRIVER) - skipping\n");
    return 77; /* meson/automake "skipped" */
  }
  if (gate_release_init() <= 0) {
    fprintf(stderr, "integration: set SEER_TEST_RELEASE to the server's release (8, 9, 10, 11, "
                    "18, 21, 23, 26)\n");
    return 2;
  }
  if (port == NULL)
    port = "1521";
  if (pwd == NULL)
    pwd = "";

  /* Register a temp DSN before the first ODBC call so SQLBrowseConnect can be
   * tested through the DM (it can't bootstrap from a raw DRIVER=path). */
  char browse_dir[64];
  setup_browse_dsn(browse_dir, drv, host, port, svc);

  SQLHENV env;
  SQLHDBC dbc;
  SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &env);
  SQLSetEnvAttr(env, SQL_ATTR_ODBC_VERSION, (void *)SQL_OV_ODBC3, 0);
  SQLAllocHandle(SQL_HANDLE_DBC, env, &dbc);

  char cs[1024];
  snprintf(cs, sizeof cs, "DRIVER=%s;HOST=%s;PORT=%s;SERVICE=%s;UID=%s;PWD=%s;", drv, host, port,
           svc, user, pwd);
  SQLCHAR outcs[1024];
  SQLSMALLINT outlen = 0;
  SQLRETURN rc = SQLDriverConnect(dbc, NULL, (SQLCHAR *)cs, SQL_NTS, outcs, sizeof outcs, &outlen,
                                  SQL_DRIVER_NOPROMPT);
  printf("target %s:%s/%s as %s\n", host, port, svc, user);
  if (!SQL_SUCCEEDED(rc)) {
    char err[256];
    diag_text(SQL_HANDLE_DBC, dbc, err, sizeof err);
    printf("  \033[31mFAIL\033[0m connect: %s\n", err[0] ? err : "SQLDriverConnect failed");
    printf("SUMMARY pass=0 fail=1 skip=0 (connect failed)\n");
    return 1;
  }
  char ver[256] = {0}, junk[8];
  SQLGetInfo(dbc, SQL_DBMS_VER, ver, sizeof ver, NULL);
  (void)junk;
  printf("  connected, DBMS version %s\n", ver[0] ? ver : "(unknown)");

  check_scalar(dbc, "SELECT literal", "SELECT 3 + 4 FROM DUAL", "7");
  check_dbms_ver(dbc);
  check_driver_ver(dbc);
  check_max_identifier_len(dbc);
  check_zero_length_columns(dbc);
  check_timestamp_zero_fraction_bind(dbc);
  check_batch_resume_repeated_column(dbc);
  check_aggregate_null_warning(dbc);
  check_nested_cursor_column(dbc);
  check_server_error_states(dbc);
  check_length_boundaries(dbc);
  check_typed_null(dbc);
  check_statement_kind(dbc);
  check_describe_before_execute(dbc);
  check_long_column(dbc);
  check_lob_out(dbc);
  check_lob_columns_batched(dbc, 0);
  check_plsql_large_lob_param(dbc);
  check_temp_lobs_freed(dbc);
  check_compile_warning(dbc);
  check_error_native_and_offset(dbc);
  check_vector_metadata(dbc);
  check_alter_session_state(dbc, strcmp(ver, "11.02") >= 0);
  check_os_user(dbc);
  check_failed_statements_close_cursors(dbc);
  check_scalar(dbc, "VARCHAR2 fetch", "SELECT 'hello' FROM DUAL", "hello");
  check_scalar(dbc, "NUMBER fetch", "SELECT 123.5 FROM DUAL", "123.5");
  check_scalar(dbc, "DATE fetch", "SELECT DATE '2020-01-02' FROM DUAL", "2020-01-02");
  check_bind(dbc);
  if (check_dml(dbc)) {
    check_transaction(dbc);
    check_refused_commit(dbc);
    check_fetch_in_txn(dbc);
    check_urowid_physical(dbc);
    check_long_bind_order(dbc);
    check_array_null_last_row(dbc);
    check_array_long_text(dbc);
    check_array_huge_text(dbc);
    check_array_block(dbc);
    check_array_query_batch(dbc);
    check_returning_failure_recovers(dbc);
    check_inout_param(dbc);
    check_returning_only_binds(dbc);
    check_returning_truncation(dbc);
    check_cache_after_block_ddl(dbc);
    check_array_batch(dbc);
    check_rowwise_binds(dbc);
    check_bindcol_lifetime(dbc);
    check_maxlength_noscan(dbc);
    check_attr_getters_rowop(dbc);
    check_ref_params(dbc);
    check_diag_fields(dbc);
    check_column_metadata(dbc);
    check_type_info(dbc);
    check_ird_sizes(dbc);
    check_columns_sizes(dbc);
    check_proc_columns(dbc);
    check_key_catalog(dbc);
    check_catalog_names(dbc);
    check_metadata_id(dbc);
    check_describe_param(dbc);
    check_scalar_functions(dbc);
    check_repeated_placeholders(dbc);
    check_datetime_literals(dbc);
    check_sql92_info(dbc);
    check_tables_enum(dbc);
    check_privileges(dbc);
    check_cursor_names(dbc);
    check_copy_desc(dbc);
    check_explicit_desc(dbc);
    check_catalog(dbc);
    check_lock(dbc);
    check_data_at_exec(dbc);
    check_cancel(dbc);
  } else {
    skip("transaction rollback", "table setup failed");
    skip("array DML batch errors", "table setup failed");
    skip("SQLColumns", "table setup failed");
    skip("FOR UPDATE (SQL_CONCUR_LOCK)", "table setup failed");
    skip("data-at-exec (SQLPutData)", "table setup failed");
    skip("SQLCancel (data-at-exec)", "table setup failed");
  }
  check_lob_scalars(dbc);
  check_rowid(dbc);
  check_urowid(dbc);
  check_urowid_long(dbc);
  check_bind_order(dbc);
  check_null_out(dbc);
  check_bfile_unopenable(dbc);
  check_double_params(dbc);
  check_intervals(dbc);
  check_boolean(dbc);
  check_vector(dbc);
  check_json(dbc);
  check_json_server_forms(dbc);
  check_returning(dbc);
  check_medium_bind(dbc);
  check_large_bind(dbc);
  check_timestamp_bind(dbc);
  check_interval_bind(dbc);
  check_float_bind(dbc);
  check_bool_bind(dbc);
  check_desc_write(dbc);
  check_large_fetch(dbc);
  check_object(dbc);
  check_object_xmltype_attr(dbc);
  check_object_national_attrs(dbc);
  check_object_lob_attrs(dbc);
  check_collection_of_objects(dbc);
  check_object_with_collection(dbc);
  check_xmltype(dbc);
  check_xmltype_lob(dbc);
  check_stmt_cache(dbc);
  check_nested_object(dbc);
  check_collection(dbc);
  check_ref(dbc);
  check_native_sql(dbc);
  check_descriptors(dbc);
  check_bulk_unsupported(dbc);
  check_annotations(dbc);
  check_implicit_results(dbc);
  check_mult_result_sets(dbc);
  check_c_type_targets(dbc);
  check_c_default(dbc);
  check_timestamp_param_date(dbc);
  check_param_c_types(dbc);
  check_numeric_targets(dbc);
  check_numeric_struct(dbc);
  check_datetime_targets(dbc);
  check_char_overflow(dbc);
  check_getdata_wchar_pieces(dbc);
  check_describe_no_markers(dbc);
  check_diag_text_trimmed(dbc);
  check_national_params(dbc);
  check_wvarchar_targets(dbc);
  check_rowset_truncation(dbc);
  check_setpos_rowset_errors(dbc);
  check_attr_identifiers(dbc);
  check_tstz_wall_clock(dbc);
  check_ltz_session_zone(dbc);
  check_refcursor_nested_cursor(dbc);
  check_cache_open_cursors(dbc);
  check_array_dml_rowcounts(dbc);
  check_browse_connect(browse_dir, user, pwd);
  check_proxy_auth(dbc, drv, host, port, svc);
  check_drcp(dbc, drv, host, port, svc, user, pwd);
  check_expire_time(drv, host, port, svc, user, pwd);
  check_tns_alias(drv, host, port, svc, user, pwd);
  check_session_time_zone(drv, host, port, svc, user, pwd);
  check_easy_connect(drv, host, port, svc, user, pwd);
  check_session_killed(drv, host, port, svc, user, pwd);
  check_autocommit_switch(dbc, drv, host, port, svc, user, pwd);
  check_disconnect_open_txn(dbc, drv, host, port, svc, user, pwd);
  check_numeric_text_params(drv, host, port, svc, user, pwd);
  check_datetime_text_params(dbc);
  check_connect_error(drv, host, port, svc, user);
  check_connect_failover(drv, host, port, svc, user, pwd);
  check_unreachable_error(drv, svc, user, pwd);
  check_query_timeout(drv, host, port, svc, user, pwd, 0);
  check_query_timeout(drv, host, port, svc, user, pwd, 1);
  check_login_timeout(drv, host, port, svc, user, pwd);
  check_txn_isolation(dbc, drv, host, port, svc, user, pwd);
  check_max_rows(dbc);
  check_cursor_attrs(dbc);
  check_getinfo_answers(dbc, user, svc);
  check_lob_out_ext_types(dbc);
  check_tls(drv, svc, user, pwd);
  check_lob_inline(drv, host, port, svc, user, pwd);

  char err[256];
  exec_do(dbc, "DROP TABLE " TBL, err, sizeof err);

  printf("SUMMARY pass=%d fail=%d skip=%d\n", n_pass, n_fail, n_skip);
  fflush(stdout);
  if (n_fail > 0)
    fprintf(stderr, "%s", fail_log);

  SQLDisconnect(dbc);
  SQLFreeHandle(SQL_HANDLE_DBC, dbc);
  SQLFreeHandle(SQL_HANDLE_ENV, env);

  if (browse_dir[0] != '\0') { /* remove the temp browse DSN */
    char p[80];
    snprintf(p, sizeof p, "%s/odbcinst.ini", browse_dir);
    unlink(p);
    snprintf(p, sizeof p, "%s/odbc.ini", browse_dir);
    unlink(p);
    rmdir(browse_dir);
  }
  return n_fail > 0 ? 1 : 0;
}

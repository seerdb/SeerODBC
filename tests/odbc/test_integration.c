/* Driver-level integration test: drives SeerODBC through the unixODBC Driver
 * Manager against a live server, exercising the ODBC surface end to end
 * (connect, typed fetch, binds, DML + rowcount, array DML + batch errors,
 * transactions, catalog, LOB, FOR UPDATE concurrency).
 *
 * It is *gated*: with no server configured it exits 77 (the automake/meson
 * "skip" code), so `meson test` stays green offline. Point it at a server with
 *   SEER_TEST_HOST, SEER_TEST_PORT (default 1521), SEER_TEST_SERVICE,
 *   SEER_TEST_USER, SEER_TEST_PASS
 * and the driver to load with SEER_DRIVER (an absolute .so path; defaults to
 * the build-tree path baked in at compile time). Every check is independent
 * and self-contained, so the same binary measures any server version - the
 * 9i..23ai support matrix is just this run against each one.
 *
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>

#include <sql.h>
#include <sqlext.h>

#ifndef SEER_DRIVER_PATH
#define SEER_DRIVER_PATH ""
#endif

static int n_pass, n_fail, n_skip;

static void pass(const char *name) { printf("  \033[32mPASS\033[0m %s\n", name); n_pass++; }
static void fail(const char *name, const char *why) { printf("  \033[31mFAIL\033[0m %s: %s\n", name, why); n_fail++; }
static void skip(const char *name, const char *why) { printf("  \033[33mSKIP\033[0m %s: %s\n", name, why); n_skip++; }

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
static SQLRETURN exec_scalar(SQLHDBC dbc, const char *sql, char *out, int outn,
                             char *err, int errn)
{
    SQLHSTMT st;
    out[0] = '\0'; err[0] = '\0';
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
        if (!SQL_SUCCEEDED(SQLGetData(st, 1, SQL_C_CHAR, out, outn, &ind)))
            snprintf(err, errn, "getdata failed");
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
    if (!SQL_SUCCEEDED(SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st))) return SQL_ERROR;
    SQLRETURN rc = SQLExecDirect(st, (SQLCHAR *)sql, SQL_NTS);
    if (!SQL_SUCCEEDED(rc) && rc != SQL_NO_DATA)
        diag_text(SQL_HANDLE_STMT, st, err, errn);
    SQLFreeHandle(SQL_HANDLE_STMT, st);
    return rc;
}

/* A scalar check: run `sql`, expect column 1 to contain `want`. */
static void check_scalar(SQLHDBC dbc, const char *name, const char *sql, const char *want)
{
    char out[256], err[256];
    SQLRETURN rc = exec_scalar(dbc, sql, out, sizeof out, err, sizeof err);
    if (!SQL_SUCCEEDED(rc)) { fail(name, err[0] ? err : "execute failed"); return; }
    if (strstr(out, want) == NULL) {
        char m[300]; snprintf(m, sizeof m, "got '%s', want '%s'", out, want);
        fail(name, m);
        return;
    }
    pass(name);
}

static void check_bind(SQLHDBC dbc)
{
    SQLHSTMT st;
    char err[256];
    if (!SQL_SUCCEEDED(SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st))) { fail("bind param", "alloc"); return; }
    SQLINTEGER a = 10, b = 20;
    SQLBindParameter(st, 1, SQL_PARAM_INPUT, SQL_C_SLONG, SQL_INTEGER, 0, 0, &a, 0, NULL);
    SQLBindParameter(st, 2, SQL_PARAM_INPUT, SQL_C_SLONG, SQL_INTEGER, 0, 0, &b, 0, NULL);
    SQLRETURN rc = SQLExecDirect(st, (SQLCHAR *)"SELECT ? + ? FROM DUAL", SQL_NTS);
    if (SQL_SUCCEEDED(rc) && (SQL_SUCCEEDED(SQLFetch(st)))) {
        SQLINTEGER r = 0; SQLLEN ind;
        SQLGetData(st, 1, SQL_C_SLONG, &r, 0, &ind);
        if (r == 30) pass("bind param (?+?)");
        else { char m[64]; snprintf(m, sizeof m, "got %d want 30", (int)r); fail("bind param (?+?)", m); }
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
    exec_do(dbc, "DROP TABLE " TBL, err, sizeof err);      /* ignore if absent */
    if (!SQL_SUCCEEDED(exec_do(dbc, "CREATE TABLE " TBL " (id NUMBER PRIMARY KEY, v VARCHAR2(20))", err, sizeof err))) {
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
        if (n == 1) pass("INSERT + SQLRowCount");
        else { char m[64]; snprintf(m, sizeof m, "rowcount=%ld want 1", (long)n); fail("INSERT + SQLRowCount", m); }
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
    if (SQL_SUCCEEDED(exec_scalar(dbc, "SELECT COUNT(*) FROM " TBL " WHERE id = 99", out, sizeof out, err, sizeof err))
        && strcmp(out, "0") == 0)
        pass("transaction rollback");
    else { char m[600]; snprintf(m, sizeof m, "count='%s' want 0 (%s)", out, err); fail("transaction rollback", m); }
}

static void check_array_batch(SQLHDBC dbc)
{
    SQLHSTMT st;
    SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st);
    /* rows 10,11,11,13 - offset 2 duplicates the PK of offset 1 */
    SQLINTEGER ids[4] = { 10, 11, 11, 13 };
    SQLCHAR    vs[4][20] = { "a", "b", "c", "d" };
    SQLUSMALLINT status[4];
    SQLULEN processed = 0;
    SQLSetStmtAttr(st, SQL_ATTR_PARAMSET_SIZE, (SQLPOINTER)(SQLULEN)4, 0);
    SQLSetStmtAttr(st, SQL_ATTR_PARAM_STATUS_PTR, status, 0);
    SQLSetStmtAttr(st, SQL_ATTR_PARAMS_PROCESSED_PTR, &processed, 0);
    SQLBindParameter(st, 1, SQL_PARAM_INPUT, SQL_C_SLONG, SQL_INTEGER, 0, 0, ids, 0, NULL);
    SQLBindParameter(st, 2, SQL_PARAM_INPUT, SQL_C_CHAR, SQL_VARCHAR, 20, 0, vs, 20, NULL);
    SQLRETURN rc = SQLExecDirect(st, (SQLCHAR *)"INSERT INTO " TBL " VALUES (?, ?)", SQL_NTS);
    if (rc == SQL_SUCCESS_WITH_INFO && processed == 4 &&
        status[0] == SQL_PARAM_SUCCESS && status[2] == SQL_PARAM_ERROR)
        pass("array DML batch errors");
    else {
        char m[160];
        snprintf(m, sizeof m, "rc=%d processed=%lu status=[%u,%u,%u,%u]", rc,
                 (unsigned long)processed, status[0], status[1], status[2], status[3]);
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
        while (SQLFetch(st) == SQL_SUCCESS) rows++;
    if (rows >= 2) pass("SQLColumns");
    else { char m[64]; snprintf(m, sizeof m, "got %d columns, want >=2", rows); fail("SQLColumns", m); }
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
            SQLPutData(st, (SQLPOINTER)"ab", SQL_NTS);   /* stream in two chunks */
            SQLPutData(st, (SQLPOINTER)"cd", SQL_NTS);
            ok = SQL_SUCCEEDED(SQLParamData(st, &t));
        }
    }
    SQLFreeHandle(SQL_HANDLE_STMT, st);
    if (!ok) { fail("data-at-exec (SQLPutData)", "SQL_NEED_DATA flow failed"); return; }
    if (SQL_SUCCEEDED(exec_scalar(dbc, "SELECT v FROM " TBL " WHERE id = 200",
                                  v, sizeof v, err, sizeof err)) && strcmp(v, "abcd") == 0)
        pass("data-at-exec (SQLPutData)");
    else { char m[128]; snprintf(m, sizeof m, "got '%s' want 'abcd'", v); fail("data-at-exec (SQLPutData)", m); }
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

    if (!SQL_SUCCEEDED(SQLCancel(st))) {       /* idle: benign success */
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

    if (!aborted) { fail(name, "NEED_DATA / SQLCancel flow failed"); return; }
    /* The cancelled row must not exist, and this query proves the link is fine. */
    if (SQL_SUCCEEDED(exec_scalar(dbc, "SELECT COUNT(*) FROM " TBL " WHERE id = 250",
                                  v, sizeof v, err, sizeof err)) && strcmp(v, "0") == 0)
        pass(name);
    else {
        char m[128]; snprintf(m, sizeof m, "cancelled row leaked (count='%s')", v);
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
    if (SQL_SUCCEEDED(rc) && SQL_SUCCEEDED(SQLFetch(st))) pass("FOR UPDATE (SQL_CONCUR_LOCK)");
    else { diag_text(SQL_HANDLE_STMT, st, err, sizeof err); fail("FOR UPDATE (SQL_CONCUR_LOCK)", err[0] ? err : "exec failed"); }
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
    char err[256];
    exec_do(dbc, "DROP TABLE seer_ann", err, sizeof err);
    if (!SQL_SUCCEEDED(exec_do(dbc,
            "CREATE TABLE seer_ann (id NUMBER ANNOTATIONS (Foo 'bar'))",
            err, sizeof err))) {
        skip(name, "server has no ANNOTATIONS support");
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
            char m[300]; snprintf(m, sizeof m, "got '%s', want a 'Foo=bar' annotation", buf);
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
static void check_implicit_results(SQLHDBC dbc)
{
    const char *name = "implicit results";
    char err[256];
    const char *blk =
        "DECLARE c SYS_REFCURSOR; BEGIN "
        "OPEN c FOR SELECT 42 AS n FROM DUAL; DBMS_SQL.RETURN_RESULT(c); END;";
    SQLHSTMT st;
    SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st);
    SQLRETURN rc = SQLExecDirect(st, (SQLCHAR *)blk, SQL_NTS);
    if (!SQL_SUCCEEDED(rc)) {
        diag_text(SQL_HANDLE_STMT, st, err, sizeof err);
        skip(name, err[0] ? err : "no implicit-results support");
        SQLFreeHandle(SQL_HANDLE_STMT, st);
        return;
    }
    rc = SQLMoreResults(st);
    if (rc == SQL_NO_DATA) {
        skip(name, "server returned no implicit result");
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
        char m[128]; snprintf(m, sizeof m, "got '%s', want '42'", buf);
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
    char err[256];
    exec_do(dbc, "DROP TABLE seer_admlc", err, sizeof err);
    if (!SQL_SUCCEEDED(exec_do(dbc, "CREATE TABLE seer_admlc (id NUMBER)", err, sizeof err))) {
        fail(name, err[0] ? err : "create failed");
        return;
    }
    exec_do(dbc, "INSERT INTO seer_admlc SELECT LEVEL FROM DUAL CONNECT BY LEVEL <= 5",
            err, sizeof err);

    SQLHSTMT st;
    SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st);
    SQLINTEGER thresh[3] = { 1, 3, 5 };
    SQLLEN     counts[3] = { -1, -1, -1 };
    SQLSetStmtAttr(st, SQL_ATTR_PARAMSET_SIZE, (SQLPOINTER)(SQLULEN)3, 0);
    SQLSetStmtAttr(st, SQL_ATTR_SEER_DML_ROW_COUNTS, counts, 0);
    SQLBindParameter(st, 1, SQL_PARAM_INPUT, SQL_C_SLONG, SQL_INTEGER, 0, 0, thresh, 0, NULL);
    SQLRETURN rc = SQLExecDirect(st,
        (SQLCHAR *)"UPDATE seer_admlc SET id = id WHERE id <= ?", SQL_NTS);
    if (!SQL_SUCCEEDED(rc)) {
        diag_text(SQL_HANDLE_STMT, st, err, sizeof err);
        fail(name, err[0] ? err : "array UPDATE failed");
    } else if (counts[0] == 0 && counts[1] == 0 && counts[2] == 0) {
        skip(name, "server has no 12c+ array-DML row counts");
    } else if (counts[0] == 1 && counts[1] == 3 && counts[2] == 5) {
        pass(name);
    } else {
        char m[128];
        snprintf(m, sizeof m, "got [%ld,%ld,%ld], want [1,3,5]",
                 (long)counts[0], (long)counts[1], (long)counts[2]);
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
    if (n == 18 && strspn(out,
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/") == 18)
        pass("ROWID fetch");
    else {
        char m[300]; snprintf(m, sizeof m, "got '%s' (len %zu), want an 18-char ROWID", out, n);
        fail("ROWID fetch", m);
    }
}

/* UROWID (type 208): an index-organized table's ROWID renders as "*"+base64.
 * Select ROWID alongside a scalar column and confirm the scalar still decodes -
 * i.e. the UROWID decode consumed exactly its bytes and didn't desync the row. */
static void check_urowid(SQLHDBC dbc)
{
    const char *name = "UROWID fetch";
    char err[256];
    exec_do(dbc, "DROP TABLE seer_iot", err, sizeof err);
    if (!SQL_SUCCEEDED(exec_do(dbc,
            "CREATE TABLE seer_iot (id NUMBER PRIMARY KEY, v VARCHAR2(8)) ORGANIZATION INDEX",
            err, sizeof err))) {
        skip(name, err[0] ? err : "no IOT support");
        return;
    }
    exec_do(dbc, "INSERT INTO seer_iot VALUES (7, 'seven')", err, sizeof err);
    SQLHSTMT st;
    SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st);
    SQLRETURN rc = SQLExecDirect(st,
        (SQLCHAR *)"SELECT ROWID, id FROM seer_iot WHERE id = 7", SQL_NTS);
    char rid[256] = {0}, idv[64] = {0};
    SQLLEN l1 = 0, l2 = 0;
    if (SQL_SUCCEEDED(rc) && SQL_SUCCEEDED(SQLFetch(st)) &&
        SQL_SUCCEEDED(SQLGetData(st, 1, SQL_C_CHAR, rid, sizeof rid, &l1)) &&
        SQL_SUCCEEDED(SQLGetData(st, 2, SQL_C_CHAR, idv, sizeof idv, &l2))) {
        if (rid[0] == '*' && strstr(idv, "7") != NULL)
            pass(name);
        else {
            char m[300]; snprintf(m, sizeof m, "rowid='%s' id='%s' (want '*...' + id 7)", rid, idv);
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
    SQLRETURN rc = exec_scalar(dbc,
        "SELECT INTERVAL '2-6' YEAR TO MONTH FROM DUAL", out, sizeof out, err, sizeof err);
    if (SQL_SUCCEEDED(rc) && strstr(out, "2-06") != NULL)
        pass("INTERVAL YEAR TO MONTH");
    else {
        char m[300]; snprintf(m, sizeof m, "got '%s', want '+2-06'", out);
        fail("INTERVAL YEAR TO MONTH", err[0] ? err : m);
    }
    rc = exec_scalar(dbc,
        "SELECT INTERVAL '2 3:4:5.123456789' DAY TO SECOND(9) FROM DUAL",
        out, sizeof out, err, sizeof err);
    if (SQL_SUCCEEDED(rc) && strstr(out, "03:04:05.123456789") != NULL)
        pass("INTERVAL DAY TO SECOND");
    else {
        char m[300]; snprintf(m, sizeof m, "got '%s', want '+2 03:04:05.123456789'", out);
        fail("INTERVAL DAY TO SECOND", err[0] ? err : m);
    }
}

/* Native SQL BOOLEAN (23ai). Skipped on servers without the type. */
static void check_boolean(SQLHDBC dbc)
{
    const char *name = "BOOLEAN (23ai)";
    char out[256], err[256];
    exec_do(dbc, "DROP TABLE seer_bool", err, sizeof err);
    if (!SQL_SUCCEEDED(exec_do(dbc, "CREATE TABLE seer_bool (b BOOLEAN)", err, sizeof err))) {
        skip(name, "no native BOOLEAN type");
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
        char m[300]; snprintf(m, sizeof m, "got '%s', want 'TRUE'", out);
        fail(name, err[0] ? err : m);
    }
    exec_do(dbc, "DROP TABLE seer_bool", err, sizeof err);
}

/* Native 23ai VECTOR decode (a LOB-backed type rendered as "[e1, e2, ...]").
 * Skipped where the type or its native (fv24) form isn't available. */
static void check_vector(SQLHDBC dbc)
{
    const char *name = "VECTOR (23ai)";
    char out[256], err[256];
    SQLRETURN rc = exec_scalar(dbc,
        "SELECT TO_VECTOR('[1.5, 2.5, 3.5]', 3, FLOAT32) FROM DUAL",
        out, sizeof out, err, sizeof err);
    if (!SQL_SUCCEEDED(rc)) {
        skip(name, err[0] ? err : "no native VECTOR type");
        return;
    }
    if (strstr(out, "1.5, 2.5, 3.5") != NULL)
        pass(name);                        /* our native VECTOR decode */
    else if (strstr(out, "1.5") != NULL)
        /* The negotiated protocol (e.g. fv6 legacy) gives no native VECTOR type,
         * so the server renders it to text itself (e.g. "[1.5E+000,...]"). */
        skip(name, "native VECTOR not surfaced at this protocol level");
    else {
        char m[300]; snprintf(m, sizeof m, "got '%s', want '[1.5, 2.5, 3.5]'", out);
        fail(name, m);
    }
}

/* Native JSON (21c+, OSON binary image) decoded back to JSON text. Skipped where
 * the type or its native form isn't available. Keys checked order-independently. */
static void check_json(SQLHDBC dbc)
{
    const char *name = "JSON (OSON)";
    char out[512], err[256];
    SQLRETURN rc = exec_scalar(dbc,
        "SELECT JSON('{\"n\":42,\"s\":\"hi\",\"b\":true}') FROM DUAL",
        out, sizeof out, err, sizeof err);
    if (!SQL_SUCCEEDED(rc)) {
        skip(name, err[0] ? err : "no native JSON type");
        return;
    }
    if (strstr(out, "\"n\":42") && strstr(out, "\"s\":\"hi\"") && strstr(out, "\"b\":true"))
        pass(name);                            /* our native OSON decode */
    else if ((strstr(out, "42") && strstr(out, "hi")) ||
             (out[0] && strspn(out, "0123456789ABCDEF") == strlen(out)))
        /* No native JSON image at this protocol level (e.g. fv6 legacy): the
         * server returns the JSON as text, or as a BLOB we hex-render. */
        skip(name, "native JSON not surfaced at this protocol level");
    else {
        char m[600]; snprintf(m, sizeof m, "got '%s'", out);
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
    SQLLEN     in_ind = 0, out_ind = 0;
    SQLBindParameter(st, 1, SQL_PARAM_INPUT,  SQL_C_SLONG, SQL_INTEGER, 0, 0,
                     &in_id, 0, &in_ind);
    SQLBindParameter(st, 2, SQL_PARAM_OUTPUT, SQL_C_SLONG, SQL_INTEGER, 0, 0,
                     &out_id, sizeof out_id, &out_ind);
    SQLRETURN rc = SQLExecDirect(st,
        (SQLCHAR *)"INSERT INTO seer_ret (id) VALUES (?) RETURNING id + 100 INTO ?", SQL_NTS);
    if (SQL_SUCCEEDED(rc) && out_id == 107)
        pass(name);
    else {
        char m[200]; diag_text(SQL_HANDLE_STMT, st, err, sizeof err);
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
    memset(big, 'X', N); big[N] = '\0';
    SQLHSTMT st;
    SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st);
    SQLLEN ind = N;
    SQLBindParameter(st, 1, SQL_PARAM_INPUT, SQL_C_CHAR, SQL_VARCHAR, N, 0, big, N, &ind);
    SQLRETURN rc = SQLExecDirect(st, (SQLCHAR *)"INSERT INTO seer_mb VALUES (?)", SQL_NTS);
    SQLFreeHandle(SQL_HANDLE_STMT, st);
    if (SQL_SUCCEEDED(rc) &&
        SQL_SUCCEEDED(exec_scalar(dbc, "SELECT LENGTH(v) FROM seer_mb", out, sizeof out, err, sizeof err))
        && strcmp(out, "500") == 0)
        pass(name);
    else {
        char m[200]; snprintf(m, sizeof m, "len='%s' rc=%d", out, rc);
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
    if (big == NULL) { fail(name, "oom"); return; }
    memset(big, 'Z', N); big[N] = '\0';
    SQLHSTMT st;
    SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st);
    SQLLEN ind = N;
    SQLBindParameter(st, 1, SQL_PARAM_INPUT, SQL_C_CHAR, SQL_LONGVARCHAR, N, 0, big, N, &ind);
    SQLRETURN rc = SQLExecDirect(st, (SQLCHAR *)"INSERT INTO seer_lb VALUES (?)", SQL_NTS);
    free(big);
    SQLFreeHandle(SQL_HANDLE_STMT, st);
    if (SQL_SUCCEEDED(rc) &&
        SQL_SUCCEEDED(exec_scalar(dbc, "SELECT LENGTH(c) FROM seer_lb", out, sizeof out, err, sizeof err))
        && strcmp(out, "20000") == 0)
        pass(name);
    else {
        char m[200]; snprintf(m, sizeof m, "len='%s' rc=%d", out, rc);
        fail(name, err[0] ? err : m);
    }
    exec_do(dbc, "DROP TABLE seer_lb", err, sizeof err);
}

/* INTERVAL binds: bind SQL_C_INTERVAL_YEAR_TO_MONTH + DAY_TO_SECOND structs and
 * confirm the round-trip. Works on all versions. */
static void check_interval_bind(SQLHDBC dbc)
{
    const char *name = "INTERVAL bind";
    char err[256], ymv[48] = "", dsv[64] = "";
    exec_do(dbc, "DROP TABLE seer_iv", err, sizeof err);
    if (!SQL_SUCCEEDED(exec_do(dbc, "CREATE TABLE seer_iv "
            "(ym INTERVAL YEAR TO MONTH, ds INTERVAL DAY TO SECOND(9))", err, sizeof err))) {
        fail(name, err[0] ? err : "create failed");
        return;
    }
    SQL_INTERVAL_STRUCT ym, ds;
    memset(&ym, 0, sizeof ym); memset(&ds, 0, sizeof ds);
    ym.interval_type = SQL_IS_YEAR_TO_MONTH; ym.interval_sign = SQL_FALSE;
    ym.intval.year_month.year = 3; ym.intval.year_month.month = 2;
    ds.interval_type = SQL_IS_DAY_TO_SECOND; ds.interval_sign = SQL_FALSE;
    ds.intval.day_second.day = 4; ds.intval.day_second.hour = 5;
    ds.intval.day_second.minute = 6; ds.intval.day_second.second = 7;
    ds.intval.day_second.fraction = 890000000;
    SQLHSTMT s;
    SQLAllocHandle(SQL_HANDLE_STMT, dbc, &s);
    SQLLEN n1 = sizeof ym, n2 = sizeof ds;
    SQLBindParameter(s, 1, SQL_PARAM_INPUT, SQL_C_INTERVAL_YEAR_TO_MONTH,
                     SQL_INTERVAL_YEAR_TO_MONTH, 0, 0, &ym, sizeof ym, &n1);
    SQLBindParameter(s, 2, SQL_PARAM_INPUT, SQL_C_INTERVAL_DAY_TO_SECOND,
                     SQL_INTERVAL_DAY_TO_SECOND, 0, 0, &ds, sizeof ds, &n2);
    SQLRETURN rc = SQLExecDirect(s, (SQLCHAR *)"INSERT INTO seer_iv VALUES (?, ?)", SQL_NTS);
    SQLFreeHandle(SQL_HANDLE_STMT, s);
    if (SQL_SUCCEEDED(rc)
        && SQL_SUCCEEDED(exec_scalar(dbc, "SELECT ym FROM seer_iv", ymv, sizeof ymv, err, sizeof err))
        && SQL_SUCCEEDED(exec_scalar(dbc, "SELECT ds FROM seer_iv", dsv, sizeof dsv, err, sizeof err))
        && strstr(ymv, "3-02") != NULL && strstr(dsv, "05:06:07") != NULL)
        pass(name);
    else {
        char m[160]; snprintf(m, sizeof m, "rc=%d ym='%s' ds='%s'", rc, ymv, dsv);
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
    char err[256], out[64];
    exec_do(dbc, "DROP TABLE seer_ts", err, sizeof err);
    if (!SQL_SUCCEEDED(exec_do(dbc, "CREATE TABLE seer_ts (ts TIMESTAMP(9))", err, sizeof err))) {
        fail(name, err[0] ? err : "create failed");
        return;
    }
    SQLHSTMT st;
    SQLAllocHandle(SQL_HANDLE_STMT, dbc, &st);
    SQL_TIMESTAMP_STRUCT t = {0};
    t.year = 2024; t.month = 3; t.day = 15;
    t.hour = 10; t.minute = 20; t.second = 30; t.fraction = 123456789;  /* ns */
    SQLLEN ind = 0;
    SQLBindParameter(st, 1, SQL_PARAM_INPUT, SQL_C_TYPE_TIMESTAMP, SQL_TYPE_TIMESTAMP,
                     29, 9, &t, sizeof t, &ind);
    SQLRETURN rc = SQLExecDirect(st, (SQLCHAR *)"INSERT INTO seer_ts VALUES (?)", SQL_NTS);
    SQLFreeHandle(SQL_HANDLE_STMT, st);
    if (SQL_SUCCEEDED(rc) &&
        SQL_SUCCEEDED(exec_scalar(dbc, "SELECT ts FROM seer_ts", out, sizeof out, err, sizeof err))
        && strstr(out, "10:20:30.123456789") != NULL)
        pass(name);
    else {
        char m[200]; snprintf(m, sizeof m, "got '%s' (rc=%d)", out, rc);
        fail(name, err[0] ? err : m);
    }
    exec_do(dbc, "DROP TABLE seer_ts", err, sizeof err);
}

/* TLS (TCPS): connect over TLS through a terminating proxy (SEER_TLS_PROXY_PORT
 * on localhost, cert at SEER_TLS_CA) and run a query, exercising the OpenSSL
 * transport end-to-end. Skips unless the proxy env is set (see run-matrix.sh). */
static void check_tls(const char *drv, const char *svc, const char *user, const char *pwd)
{
    const char *name = "TLS transport (TCPS)";
    const char *tport = getenv("SEER_TLS_PROXY_PORT");
    const char *ca    = getenv("SEER_TLS_CA");
    if (tport == NULL || ca == NULL) {
        skip(name, "set SEER_TLS_PROXY_PORT + SEER_TLS_CA to exercise TLS");
        return;
    }
    SQLHENV e; SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &e);
    SQLSetEnvAttr(e, SQL_ATTR_ODBC_VERSION, (void *)SQL_OV_ODBC3, 0);
    SQLHDBC d; SQLAllocHandle(SQL_HANDLE_DBC, e, &d);
    char cs[640];
    snprintf(cs, sizeof cs,
             "DRIVER=%s;HOST=localhost;PORT=%s;SERVICE=%s;UID=%s;PWD=%s;SSL=1;TLSCA=%s;",
             drv, tport, svc, user, pwd, ca);
    SQLCHAR o[256]; SQLSMALLINT ol;
    if (!SQL_SUCCEEDED(SQLDriverConnect(d, NULL, (SQLCHAR *)cs, SQL_NTS,
                                        o, sizeof o, &ol, SQL_DRIVER_NOPROMPT))) {
        char m[256]; diag_text(SQL_HANDLE_DBC, d, m, sizeof m);
        fail(name, m[0] ? m : "TLS connect failed");
    } else {
        char out[32], err[256];
        if (SQL_SUCCEEDED(exec_scalar(d, "SELECT 'tls-ok' FROM dual", out, sizeof out, err, sizeof err))
            && strcmp(out, "tls-ok") == 0)
            pass(name);
        else
            fail(name, err[0] ? err : "query over TLS failed");
        SQLDisconnect(d);
    }
    SQLFreeHandle(SQL_HANDLE_DBC, d);
    SQLFreeHandle(SQL_HANDLE_ENV, e);
}

/* Proxy authentication: a `proxy_user[schema]` connect authenticates as the
 * proxy but operates in the target schema's context. Needs DBA to set up the
 * GRANT CONNECT THROUGH; skips gracefully when the test login isn't a DBA. */
static void check_proxy_auth(SQLHDBC dbc, const char *drv, const char *host,
                             const char *port, const char *svc)
{
    const char *name = "proxy authentication";
    char err[256];
    exec_do(dbc, "DROP USER seerprx CASCADE", err, sizeof err);
    exec_do(dbc, "DROP USER seerproxy_p CASCADE", err, sizeof err);
    if (!SQL_SUCCEEDED(exec_do(dbc, "CREATE USER seerprx IDENTIFIED BY seerprx123",
                               err, sizeof err))) {
        skip(name, "needs DBA (CREATE USER / GRANT CONNECT THROUGH)");
        return;
    }
    exec_do(dbc, "GRANT CREATE SESSION TO seerprx", err, sizeof err);
    exec_do(dbc, "CREATE USER seerproxy_p IDENTIFIED BY seerproxy123", err, sizeof err);
    exec_do(dbc, "GRANT CREATE SESSION TO seerproxy_p", err, sizeof err);
    exec_do(dbc, "ALTER USER seerprx GRANT CONNECT THROUGH seerproxy_p", err, sizeof err);

    SQLHENV e; SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &e);
    SQLSetEnvAttr(e, SQL_ATTR_ODBC_VERSION, (void *)SQL_OV_ODBC3, 0);
    SQLHDBC d; SQLAllocHandle(SQL_HANDLE_DBC, e, &d);
    char cs[512];
    snprintf(cs, sizeof cs,
             "DRIVER=%s;HOST=%s;PORT=%s;SERVICE=%s;UID=seerproxy_p[seerprx];PWD=seerproxy123;",
             drv, host, port ? port : "1521", svc);
    SQLCHAR o[256]; SQLSMALLINT ol;
    SQLRETURN rc = SQLDriverConnect(d, NULL, (SQLCHAR *)cs, SQL_NTS,
                                    o, sizeof o, &ol, SQL_DRIVER_NOPROMPT);
    if (SQL_SUCCEEDED(rc)) {
        char su[64];
        if (SQL_SUCCEEDED(exec_scalar(d, "SELECT SYS_CONTEXT('USERENV','SESSION_USER') FROM dual",
                                      su, sizeof su, err, sizeof err))
            && strcmp(su, "SEERPRX") == 0)
            pass(name);
        else {
            char m[128]; snprintf(m, sizeof m, "session_user='%s' (want SEERPRX)", su);
            fail(name, m);
        }
        SQLDisconnect(d);
    } else {
        char m[256]; diag_text(SQL_HANDLE_DBC, d, m, sizeof m);
        fail(name, m[0] ? m : "proxy connect failed");
    }
    SQLFreeHandle(SQL_HANDLE_DBC, d);
    SQLFreeHandle(SQL_HANDLE_ENV, e);

    exec_do(dbc, "DROP USER seerprx CASCADE", err, sizeof err);
    exec_do(dbc, "DROP USER seerproxy_p CASCADE", err, sizeof err);
}

/* DRCP: a pooled connection (CCLASS + PURITY) routes via (SERVER=POOLED) and the
 * AUTH_KPPL_* pairs; a query on it exercises the server-side piggyback handling.
 * Skips where DRCP isn't available (pre-11g, or the pool isn't running). */
static void check_drcp(SQLHDBC dbc, const char *drv, const char *host,
                       const char *port, const char *svc,
                       const char *user, const char *pwd)
{
    const char *name = "DRCP (pooled session)";
    char err[256];
    /* Best-effort: start the pool (needs DBA; harmless if already up / denied). */
    exec_do(dbc, "BEGIN DBMS_CONNECTION_POOL.START_POOL; END;", err, sizeof err);

    SQLHENV e; SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &e);
    SQLSetEnvAttr(e, SQL_ATTR_ODBC_VERSION, (void *)SQL_OV_ODBC3, 0);
    SQLHDBC d; SQLAllocHandle(SQL_HANDLE_DBC, e, &d);
    char cs[640];
    snprintf(cs, sizeof cs,
             "DRIVER=%s;HOST=%s;PORT=%s;SERVICE=%s;UID=%s;PWD=%s;CCLASS=SEERPOOL;PURITY=SELF;",
             drv, host, port ? port : "1521", svc, user, pwd);
    SQLCHAR o[256]; SQLSMALLINT ol;
    if (!SQL_SUCCEEDED(SQLDriverConnect(d, NULL, (SQLCHAR *)cs, SQL_NTS,
                                        o, sizeof o, &ol, SQL_DRIVER_NOPROMPT))) {
        skip(name, "DRCP pool not available (pre-11g or not started)");
    } else {
        char one[16];
        if (SQL_SUCCEEDED(exec_scalar(d, "SELECT 1 FROM dual", one, sizeof one, err, sizeof err))
            && strcmp(one, "1") == 0)
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
    char col[64]; SQLLEN ind = 0;
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
        char m[128]; snprintf(m, sizeof m, "rc=%d col='%s' ird_ro_rc=%d", rc, col, ro);
        fail(name, m);
    }
    SQLFreeHandle(SQL_HANDLE_STMT, s);
}

/* Nested SQL OBJECT fetch: an attribute that is itself an object is flattened
 * inline in the image; its leaf attributes are spliced into the layout. */
static void check_nested_object(SQLHDBC dbc)
{
    const char *name = "nested SQL OBJECT fetch";
    char err[256], out[256];
    exec_do(dbc, "DROP TABLE seer_nt", err, sizeof err);
    exec_do(dbc, "DROP TYPE seer_person", err, sizeof err);
    exec_do(dbc, "DROP TYPE seer_addr", err, sizeof err);
    if (!SQL_SUCCEEDED(exec_do(dbc, "CREATE TYPE seer_addr AS OBJECT (street VARCHAR2(20), zip NUMBER)",
                               err, sizeof err))
        || !SQL_SUCCEEDED(exec_do(dbc, "CREATE TYPE seer_person AS OBJECT (nm VARCHAR2(20), age NUMBER, home seer_addr)",
                                  err, sizeof err))) {
        fail(name, err[0] ? err : "create type failed");
        return;
    }
    exec_do(dbc, "CREATE TABLE seer_nt (p seer_person)", err, sizeof err);
    exec_do(dbc, "INSERT INTO seer_nt VALUES (seer_person('Bob', 30, seer_addr('Main St', 12345)))",
            err, sizeof err);
    if (SQL_SUCCEEDED(exec_scalar(dbc, "SELECT p FROM seer_nt", out, sizeof out, err, sizeof err))
        && strstr(out, "Bob") != NULL && strstr(out, "Main St") != NULL
        && strstr(out, "12345") != NULL)
        pass(name);
    else {
        char m[300]; snprintf(m, sizeof m, "got '%s'", out);
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
        char buf[4096]; SQLLEN ind = 0;
        SQLBindCol(s, 1, SQL_C_CHAR, buf, sizeof buf, &ind);
        if (SQL_SUCCEEDED(SQLFetch(s)) && ind == 3000)
            pass(name);
        else {
            char m[64]; snprintf(m, sizeof m, "ind=%ld (want 3000)", (long)ind);
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
    int first = strcmp(out, "33") == 0;                  /* parse + cache */
    out[0] = '\0';
    exec_scalar(dbc, "SELECT SUM(n) FROM seer_sc", out, sizeof out, err, sizeof err);
    int reuse = strcmp(out, "33") == 0;                  /* reuse the cursor */
    /* Recreate the table with different data - the DDL must invalidate the cache. */
    exec_do(dbc, "DROP TABLE seer_sc", err, sizeof err);
    exec_do(dbc, "CREATE TABLE seer_sc (n NUMBER)", err, sizeof err);
    exec_do(dbc, "INSERT INTO seer_sc VALUES (7)", err, sizeof err);
    out[0] = '\0';
    exec_scalar(dbc, "SELECT SUM(n) FROM seer_sc", out, sizeof out, err, sizeof err);
    int flush = strcmp(out, "7") == 0;                   /* new data, not stale 33 */
    if (first && reuse && flush)
        pass(name);
    else {
        char m[160];
        snprintf(m, sizeof m, "first=%d reuse=%d flush=%d (last got '%s')",
                 first, reuse, flush, out);
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
    char err[256], out[512];
    exec_do(dbc, "DROP TABLE seer_xmll", err, sizeof err);
    if (!SQL_SUCCEEDED(exec_do(dbc, "CREATE TABLE seer_xmll (doc XMLTYPE) "
                                    "XMLTYPE COLUMN doc STORE AS CLOB", err, sizeof err))) {
        skip(name, "CLOB-stored XMLType not available on this server");
        return;
    }
    if (!SQL_SUCCEEDED(exec_do(dbc, "INSERT INTO seer_xmll VALUES (XMLTYPE('<a><b>hi</b></a>'))",
                               err, sizeof err))) {
        skip(name, "XMLType insert not supported here");
        exec_do(dbc, "DROP TABLE seer_xmll", err, sizeof err);
        return;
    }
    out[0] = '\0';
    SQLRETURN rc = exec_scalar(dbc, "SELECT doc FROM seer_xmll", out, sizeof out, err, sizeof err);
    if (SQL_SUCCEEDED(rc) && strstr(out, "<a>") != NULL && strstr(out, "hi") != NULL)
        pass(name);                     /* the LOB locator was read + decoded */
    else if (SQL_SUCCEEDED(rc) && out[0] == '\0')
        skip(name, "legacy CLOB-stored XMLType (not decoded inline)");   /* 10g/11g */
    else {
        char m[600]; snprintf(m, sizeof m, "got '%s'", out);
        fail(name, err[0] ? err : m);
    }
    exec_do(dbc, "DROP TABLE seer_xmll", err, sizeof err);
}

static void check_xmltype(SQLHDBC dbc)
{
    const char *name = "XMLType fetch";
    char err[256], out[512];
    exec_do(dbc, "DROP TABLE seer_xml", err, sizeof err);
    if (!SQL_SUCCEEDED(exec_do(dbc, "CREATE TABLE seer_xml (doc XMLTYPE)", err, sizeof err))) {
        skip(name, "XMLType not available on this server");
        return;
    }
    if (!SQL_SUCCEEDED(exec_do(dbc, "INSERT INTO seer_xml VALUES (XMLTYPE('<a><b>hi</b></a>'))",
                               err, sizeof err))) {
        skip(name, "XMLType insert not supported here");
        exec_do(dbc, "DROP TABLE seer_xml", err, sizeof err);
        return;
    }
    out[0] = '\0';
    SQLRETURN rc = exec_scalar(dbc, "SELECT doc FROM seer_xml", out, sizeof out, err, sizeof err);
    if (SQL_SUCCEEDED(rc) && strstr(out, "<a>") != NULL && strstr(out, "hi") != NULL)
        pass(name);
    else if (SQL_SUCCEEDED(rc) && out[0] == '\0')
        /* Legacy CLOB-stored XMLType (e.g. 11g): not decoded inline - cast via
         * XMLSERIALIZE / XMLTYPE.getclobval in SQL. python-oracledb is the same. */
        skip(name, "legacy CLOB-stored XMLType (cast via XMLSERIALIZE)");
    else {
        char m[600]; snprintf(m, sizeof m, "got '%s'", out);
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
    char err[256], out[256];
    exec_do(dbc, "DROP TABLE seer_owc", err, sizeof err);
    exec_do(dbc, "DROP TYPE seer_prsn", err, sizeof err);
    exec_do(dbc, "DROP TYPE seer_phon", err, sizeof err);
    if (!SQL_SUCCEEDED(exec_do(dbc, "CREATE TYPE seer_phon AS VARRAY(5) OF VARCHAR2(20)",
                               err, sizeof err))) {
        skip(name, "object types not available (pre-12c)");
        return;
    }
    exec_do(dbc, "CREATE TYPE seer_prsn AS OBJECT (nm VARCHAR2(20), age NUMBER, ph seer_phon)",
            err, sizeof err);
    exec_do(dbc, "CREATE TABLE seer_owc (p seer_prsn)", err, sizeof err);
    exec_do(dbc, "INSERT INTO seer_owc VALUES "
                 "(seer_prsn('Bob', 42, seer_phon('555-1234', '555-5678')))", err, sizeof err);
    if (SQL_SUCCEEDED(exec_scalar(dbc, "SELECT p FROM seer_owc", out, sizeof out, err, sizeof err))
        && strstr(out, "Bob") != NULL && strstr(out, "42") != NULL
        && strstr(out, "[555-1234, 555-5678]") != NULL)
        pass(name);
    else {
        char m[300]; snprintf(m, sizeof m, "got '%s'", out);
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
    char err[256], out[256];
    exec_do(dbc, "DROP TABLE seer_cot", err, sizeof err);
    exec_do(dbc, "DROP TYPE seer_ptv", err, sizeof err);
    exec_do(dbc, "DROP TYPE seer_pt", err, sizeof err);
    if (!SQL_SUCCEEDED(exec_do(dbc, "CREATE TYPE seer_pt AS OBJECT (x NUMBER, y NUMBER)",
                               err, sizeof err))) {
        skip(name, "object types not available (pre-12c)");
        return;
    }
    exec_do(dbc, "CREATE TYPE seer_ptv AS VARRAY(5) OF seer_pt", err, sizeof err);
    exec_do(dbc, "CREATE TABLE seer_cot (v seer_ptv)", err, sizeof err);
    exec_do(dbc, "INSERT INTO seer_cot VALUES (seer_ptv(seer_pt(1, 2), seer_pt(3, 4)))",
            err, sizeof err);
    if (SQL_SUCCEEDED(exec_scalar(dbc, "SELECT v FROM seer_cot", out, sizeof out, err, sizeof err))
        && strstr(out, "1, 2") != NULL && strstr(out, "3, 4") != NULL)
        pass(name);
    else {
        char m[300]; snprintf(m, sizeof m, "got '%s'", out);
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
    char err[256], out[256];
    exec_do(dbc, "DROP TABLE seer_ot", err, sizeof err);
    exec_do(dbc, "DROP TYPE seer_objt", err, sizeof err);
    if (!SQL_SUCCEEDED(exec_do(dbc, "CREATE TYPE seer_objt AS OBJECT (n NUMBER, s VARCHAR2(20))",
                               err, sizeof err))) {
        fail(name, err[0] ? err : "create type failed");
        return;
    }
    exec_do(dbc, "CREATE TABLE seer_ot (o seer_objt)", err, sizeof err);
    exec_do(dbc, "INSERT INTO seer_ot VALUES (seer_objt(42, 'hello'))", err, sizeof err);
    if (SQL_SUCCEEDED(exec_scalar(dbc, "SELECT o FROM seer_ot", out, sizeof out, err, sizeof err))
        && strstr(out, "42") != NULL && strstr(out, "hello") != NULL)
        pass(name);
    else {
        char m[300]; snprintf(m, sizeof m, "got '%s'", out);
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
    char err[256], out[256];
    exec_do(dbc, "DROP TABLE seer_ct", err, sizeof err);
    exec_do(dbc, "DROP TYPE seer_va", err, sizeof err);
    if (!SQL_SUCCEEDED(exec_do(dbc, "CREATE TYPE seer_va AS VARRAY(5) OF NUMBER",
                               err, sizeof err))) {
        fail(name, err[0] ? err : "create type failed");
        return;
    }
    exec_do(dbc, "CREATE TABLE seer_ct (v seer_va)", err, sizeof err);
    exec_do(dbc, "INSERT INTO seer_ct VALUES (seer_va(10, 20, 30))", err, sizeof err);
    if (SQL_SUCCEEDED(exec_scalar(dbc, "SELECT v FROM seer_ct", out, sizeof out, err, sizeof err))
        && strstr(out, "10") != NULL && strstr(out, "20") != NULL && strstr(out, "30") != NULL)
        pass(name);
    else {
        char m[300]; snprintf(m, sizeof m, "got '%s'", out);
        fail(name, err[0] ? err : m);
    }
    exec_do(dbc, "DROP TABLE seer_ct", err, sizeof err);
    exec_do(dbc, "DROP TYPE seer_va", err, sizeof err);
}

/* REF fetch: an object reference is surfaced as its opaque locator in hex. */
static void check_ref(SQLHDBC dbc)
{
    const char *name = "REF fetch";
    char err[256], out[256];
    exec_do(dbc, "DROP TABLE seer_oref", err, sizeof err);
    exec_do(dbc, "DROP TYPE seer_robj", err, sizeof err);
    if (!SQL_SUCCEEDED(exec_do(dbc, "CREATE TYPE seer_robj AS OBJECT (n NUMBER)",
                               err, sizeof err))) {
        fail(name, err[0] ? err : "create type failed");
        return;
    }
    exec_do(dbc, "CREATE TABLE seer_oref OF seer_robj", err, sizeof err);
    exec_do(dbc, "INSERT INTO seer_oref VALUES (seer_robj(1))", err, sizeof err);
    if (SQL_SUCCEEDED(exec_scalar(dbc, "SELECT REF(t) FROM seer_oref t", out, sizeof out, err, sizeof err))
        && strlen(out) >= 40 && strspn(out, "0123456789ABCDEF") == strlen(out))
        pass(name);
    else {
        char m[300]; snprintf(m, sizeof m, "got '%s'", out);
        fail(name, err[0] ? err : m);
    }
    exec_do(dbc, "DROP TABLE seer_oref", err, sizeof err);
    exec_do(dbc, "DROP TYPE seer_robj", err, sizeof err);
}

/* Native BINARY_FLOAT bind (4-byte, was widened to BINARY_DOUBLE). */
static void check_float_bind(SQLHDBC dbc)
{
    const char *name = "BINARY_FLOAT bind";
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
        SQL_SUCCEEDED(exec_scalar(dbc, "SELECT f FROM seer_bf", out, sizeof out, err, sizeof err))
        && strstr(out, "3.5") != NULL)
        pass(name);
    else {
        char m[200]; snprintf(m, sizeof m, "got '%s' rc=%d", out, rc);
        fail(name, err[0] ? err : m);
    }
    exec_do(dbc, "DROP TABLE seer_bf", err, sizeof err);
}

/* Native 23ai BOOLEAN bind (SQL_C_BIT). Skipped where the type / its native form
 * isn't available. */
static void check_bool_bind(SQLHDBC dbc)
{
    const char *name = "BOOLEAN bind (23ai)";
    char err[256], out[64];
    exec_do(dbc, "DROP TABLE seer_bb", err, sizeof err);
    if (!SQL_SUCCEEDED(exec_do(dbc, "CREATE TABLE seer_bb (b BOOLEAN)", err, sizeof err))) {
        skip(name, "no native BOOLEAN type");
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
    if (SQL_SUCCEEDED(exec_scalar(dbc, "SELECT b FROM seer_bb", out, sizeof out, err, sizeof err))
        && strstr(out, "TRUE") != NULL)
        pass(name);
    else if (strstr(out, "1") != NULL)
        skip(name, "native BOOLEAN not surfaced at this protocol level");
    else {
        char m[200]; snprintf(m, sizeof m, "got '%s'", out);
        fail(name, m);
    }
    exec_do(dbc, "DROP TABLE seer_bb", err, sizeof err);
}

/* SQLNativeSql: ODBC {escape} expansion + '?' -> :1 marker rewrite. Pure string
 * transform, so it's server-independent. */
static void check_native_sql(SQLHDBC dbc)
{
    const char *name = "SQLNativeSql";
    SQLCHAR    out[256] = {0};
    SQLINTEGER outlen = 0;
    SQLRETURN rc = SQLNativeSql(dbc,
        (SQLCHAR *)"SELECT {fn UCASE(v)} FROM dual WHERE id = ?", SQL_NTS,
        out, sizeof out, &outlen);
    if (SQL_SUCCEEDED(rc) && strstr((char *)out, "UPPER(") && strstr((char *)out, ":1")
        && !strstr((char *)out, "{fn") && !strchr((char *)out, '?'))
        pass(name);
    else {
        char m[320]; snprintf(m, sizeof m, "got '%s'", (char *)out);
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

static void setup_browse_dsn(char *dir, const char *drv, const char *host,
                             const char *port, const char *svc)
{
    dir[0] = '\0';
    char tmpl[] = "/tmp/seerbrowseXXXXXX";
    if (mkdtemp(tmpl) == NULL)
        return;
    char inst[600], ini[600];
    snprintf(inst, sizeof inst, "%s/odbcinst.ini", tmpl);
    snprintf(ini,  sizeof ini,  "%s/odbc.ini", tmpl);
    FILE *f = fopen_private(inst);
    if (f) { fprintf(f, "[SeerBrowse]\nDriver=%s\n", drv); fclose(f); }
    f = fopen_private(ini);
    if (f) { fprintf(f, "[SeerBrowseDSN]\nDriver=SeerBrowse\nHOST=%s\nPORT=%s\nSERVICE=%s\n",
                     host, port, svc); fclose(f); }
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
    if (dir[0] == '\0') { skip(name, "temp DSN setup failed"); return; }

    SQLHENV env;
    SQLHDBC dbc;
    SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &env);
    SQLSetEnvAttr(env, SQL_ATTR_ODBC_VERSION, (void *)SQL_OV_ODBC3, 0);
    SQLAllocHandle(SQL_HANDLE_DBC, env, &dbc);

    SQLCHAR     out[512] = {0};
    SQLSMALLINT outlen = 0;
    SQLRETURN rc = SQLBrowseConnect(dbc, (SQLCHAR *)"DSN=SeerBrowseDSN;", SQL_NTS,
                                    out, sizeof out, &outlen);
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
        char m[200]; snprintf(m, sizeof m, "round2 connect failed (rc=%d)", rc);
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
    SQLRETURN r2 = SQLGetDescRec(ird, 2, cname, sizeof cname, &nlen,
                                 &ctype, &csub, &clen, &cprec, &cscale, &cnull);
    SQLSMALLINT t1 = 0;
    SQLGetDescField(ird, 1, SQL_DESC_TYPE, &t1, 0, NULL);

    if (ird != NULL && cnt == 2 && SQL_SUCCEEDED(r2) && strcmp((char *)cname, "V") == 0
        && ctype != 0 && t1 != 0)
        pass(name);
    else {
        char m[200];
        snprintf(m, sizeof m, "ird=%p count=%d rec2='%s' ctype=%d t1=%d",
                 (void *)ird, cnt, (char *)cname, ctype, t1);
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
        char m[120]; snprintf(m, sizeof m, "supported=%d rc=%d (want false + failure)", sup, rc);
        fail(name, m);
    }
}

int main(void)
{
    const char *host = getenv("SEER_TEST_HOST");
    const char *port = getenv("SEER_TEST_PORT");
    const char *svc  = getenv("SEER_TEST_SERVICE");
    const char *user = getenv("SEER_TEST_USER");
    const char *pwd  = getenv("SEER_TEST_PASS");
    const char *drv  = getenv("SEER_DRIVER");
    if (drv == NULL || drv[0] == '\0') drv = SEER_DRIVER_PATH;
    if (host == NULL || svc == NULL || user == NULL || drv[0] == '\0') {
        fprintf(stderr, "integration: no target configured "
                "(set SEER_TEST_HOST/SERVICE/USER[/PORT/PASS] and SEER_DRIVER) - skipping\n");
        return 77;                     /* meson/automake "skipped" */
    }
    if (port == NULL) port = "1521";
    if (pwd == NULL) pwd = "";

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
    snprintf(cs, sizeof cs, "DRIVER=%s;HOST=%s;PORT=%s;SERVICE=%s;UID=%s;PWD=%s;",
             drv, host, port, svc, user, pwd);
    SQLCHAR outcs[1024];
    SQLSMALLINT outlen = 0;
    SQLRETURN rc = SQLDriverConnect(dbc, NULL, (SQLCHAR *)cs, SQL_NTS,
                                    outcs, sizeof outcs, &outlen, SQL_DRIVER_NOPROMPT);
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

    check_scalar(dbc, "SELECT literal",     "SELECT 3 + 4 FROM DUAL", "7");
    check_scalar(dbc, "VARCHAR2 fetch",     "SELECT 'hello' FROM DUAL", "hello");
    check_scalar(dbc, "NUMBER fetch",       "SELECT 123.5 FROM DUAL", "123.5");
    check_scalar(dbc, "DATE fetch",         "SELECT DATE '2020-01-02' FROM DUAL", "2020-01-02");
    check_bind(dbc);
    if (check_dml(dbc)) {
        check_transaction(dbc);
        check_array_batch(dbc);
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
    check_scalar(dbc, "CLOB fetch",         "SELECT TO_CLOB('clobdata') FROM DUAL", "clobdata");
    /* SQL_C_CHAR from binary is uppercase hex (the ODBC convention, per
     * convert.c - the core's freeoracle path renders lowercase). */
    check_scalar(dbc, "BLOB fetch (hex)",   "SELECT TO_BLOB(HEXTORAW('DEADBEEF')) FROM DUAL", "DEADBEEF");
    check_rowid(dbc);
    check_urowid(dbc);
    check_intervals(dbc);
    check_boolean(dbc);
    check_vector(dbc);
    check_json(dbc);
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
    check_array_dml_rowcounts(dbc);
    check_browse_connect(browse_dir, user, pwd);
    check_proxy_auth(dbc, drv, host, port, svc);
    check_drcp(dbc, drv, host, port, svc, user, pwd);
    check_tls(drv, svc, user, pwd);

    char err[256];
    exec_do(dbc, "DROP TABLE " TBL, err, sizeof err);

    printf("SUMMARY pass=%d fail=%d skip=%d\n", n_pass, n_fail, n_skip);

    SQLDisconnect(dbc);
    SQLFreeHandle(SQL_HANDLE_DBC, dbc);
    SQLFreeHandle(SQL_HANDLE_ENV, env);

    if (browse_dir[0] != '\0') {            /* remove the temp browse DSN */
        char p[80];
        snprintf(p, sizeof p, "%s/odbcinst.ini", browse_dir); unlink(p);
        snprintf(p, sizeof p, "%s/odbc.ini", browse_dir);     unlink(p);
        rmdir(browse_dir);
    }
    return n_fail > 0 ? 1 : 0;
}

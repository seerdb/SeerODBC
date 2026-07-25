/* Internal definitions shared across the ODBC shim translation units.
 *
 * This header may include ODBC headers (it is part of the shim, src/odbc/).
 * The protocol core, src/tns/, must never include it or them.
 *
 * Every handle struct begins with an OdbcHeader so any SQLHANDLE can be
 * tag-dispatched on its type and carries one diagnostic record (SQLGetDiagRec
 * reads it). The core SeerConn / SeerStmt live behind the DBC / STMT handles.
 *
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SEERODBC_INTERNAL_H
#define SEERODBC_INTERNAL_H

#include "odbc_platform.h"   /* <windows.h> before the ODBC headers on Windows */

#include <sql.h>
#include <sqlext.h>

#include "seer/seertns.h"

/* SeerODBC extension SQL type: bind a PL/SQL REF CURSOR OUT parameter with
 * SQLBindParameter(..., SQL_PARAM_OUTPUT, SQL_C_DEFAULT, SQL_REFCURSOR, ...).
 * After SQLExecute the cursor's rows become the statement's result set, read
 * with SQLNumResultCols / SQLBindCol / SQLFetch / SQLGetData. */
#ifndef SQL_REFCURSOR
#define SQL_REFCURSOR (-9999)
#endif

/* SeerODBC extension SQLColAttribute field identifier: the column's 23ai SQL
 * annotations, returned as a "name=value\n..." character string (name-only
 * annotations have an empty value; empty string when the column has none). */
#define SQL_DESC_SEER_ANNOTATIONS 19111

/* SeerODBC extension SQL_ATTR for SQLSetStmtAttr: point this at a SQLLEN array
 * (>= SQL_ATTR_PARAMSET_SIZE elements) before an array-DML execute and the
 * driver requests 12c+ per-iteration row counts and fills the array with how
 * many rows each parameter set affected. */
#define SQL_ATTR_SEER_DML_ROW_COUNTS 19112

/* A diagnostic record. Most failures post one; an array-DML execute in
 * batch-errors mode posts one per failed row, each carrying its 1-based
 * SQL_DIAG_ROW_NUMBER. */
typedef struct {
    char       state[6];     /* 5-char SQLSTATE + NUL */
    SQLINTEGER native;       /* native error (ORA number), 0 if none */
    char       message[600];
    SQLLEN     row_number;   /* 1-based row, or SQL_NO_ROW_NUMBER */
} OdbcDiagRec;

/* A growable diagnostic-record queue per handle (the buffer is kept across
 * clears; `count` is reset to 0 at each ODBC entry point). */
typedef struct {
    OdbcDiagRec *recs;
    int          count;
    int          cap;
} OdbcDiag;

typedef struct {
    SQLSMALLINT type;        /* SQL_HANDLE_ENV / _DBC / _STMT */
    OdbcDiag    diag;
} OdbcHeader;

typedef struct {
    OdbcHeader  h;
    SQLINTEGER  odbc_version;
} OdbcEnv;

typedef struct {
    OdbcHeader  h;
    OdbcEnv    *env;
    SeerConn   *conn;
    int         connected;
    SQLUINTEGER autocommit;
    char       *browse_cs;     /* SQLBrowseConnect: accumulated attributes */
} OdbcDbc;

/* A column binding set by SQLBindCol. */
typedef struct {
    SQLSMALLINT target_type;   /* SQL_C_* (0 if unbound) */
    SQLPOINTER  buf;
    SQLLEN      buflen;
    SQLLEN     *indicator;
    int         bound;
} OdbcBind;

/* A deferred parameter set by SQLBindParameter (resolved at execute time). */
typedef struct {
    SQLSMALLINT io_type;       /* SQL_PARAM_INPUT / _OUTPUT / _INPUT_OUTPUT */
    SQLSMALLINT c_type;        /* ValueType (SQL_C_*) */
    SQLSMALLINT sql_type;      /* ParameterType (SQL_*) - drives an OUT's OAC */
    SQLULEN     column_size;   /* declared size (OUT buffer / VARCHAR length) */
    SQLPOINTER  buf;
    SQLLEN      buflen;
    SQLLEN     *indicator;
    int         bound;
    /* Data-at-execution (SQLPutData): when the bound indicator is
     * SQL_DATA_AT_EXEC the value is streamed in after execute. `dae` marks such
     * a param for the current execute; `dae_buf`/`dae_len` accumulate the chunks
     * (bound in place of `buf`), `dae_null` records a SQL_NULL_DATA put. */
    int         dae;
    int         dae_null;
    char       *dae_buf;
    size_t      dae_len;
    size_t      dae_cap;
} OdbcParam;

/* The four ODBC descriptors of a statement (SQL_ATTR_*_DESC): application/
 * implementation x row/parameter. Implicitly allocated with the statement; we
 * expose them read-only via SQLGetDescField/Rec, deriving fields from the bind
 * arrays (APD/ARD) and the core column/param metadata (IRD/IPD). */
typedef enum { SEER_DESC_ARD, SEER_DESC_APD, SEER_DESC_IRD, SEER_DESC_IPD } SeerDescKind;

typedef struct {
    OdbcHeader   h;
    void        *stmt;         /* owning OdbcStmt */
    SeerDescKind kind;
} OdbcDesc;

typedef struct {
    OdbcHeader  h;
    OdbcDbc    *dbc;
    char       *sql;           /* prepared statement text (SQLPrepare) */
    SeerStmt   *core;          /* core statement, NULL until execute */
    OdbcDesc    ard, apd, ird, ipd;  /* implicit descriptors */
    OdbcBind   *binds;         /* result columns, [num_binds] */
    int         num_binds;
    OdbcParam  *params;        /* input parameters, [num_params] */
    int         num_params;
    /* Data-at-execution sequence (SQLParamData/SQLPutData) between an execute
     * that returned SQL_NEED_DATA and the final SQLParamData that runs it. */
    int         dae_active;    /* in a SQL_NEED_DATA sequence */
    int         dae_current;   /* param index being filled, -1 before the first */
    int         getdata_col;   /* last SQLGetData column, for fragment tracking */
    SQLLEN      getdata_off;   /* bytes already returned for getdata_col */
    /* Array (bulk) parameter binding. */
    SQLULEN      paramset_size;     /* SQL_ATTR_PARAMSET_SIZE (rows), default 1 */
    SQLULEN      param_bind_type;   /* SQL_ATTR_PARAM_BIND_TYPE, default by-column */
    SQLULEN     *params_processed;  /* SQL_ATTR_PARAMS_PROCESSED_PTR */
    SQLUSMALLINT *param_status;     /* SQL_ATTR_PARAM_STATUS_PTR */
    SQLLEN      *dml_row_counts;    /* SQL_ATTR_SEER_DML_ROW_COUNTS (app buffer) */
    /* Row-array (block) fetch. */
    SQLULEN      row_array_size;    /* SQL_ATTR_ROW_ARRAY_SIZE, default 1 */
    SQLULEN      row_bind_type;     /* SQL_ATTR_ROW_BIND_TYPE (0 = by column) */
    SQLULEN     *rows_fetched;      /* SQL_ATTR_ROWS_FETCHED_PTR */
    SQLUSMALLINT *row_status;       /* SQL_ATTR_ROW_STATUS_PTR */
    long         rowset_start;      /* 0-based first row of the current rowset, -1 = none */
    /* Updatable cursor (positioned update/delete via SQLSetPos). */
    SQLULEN      concurrency;       /* SQL_ATTR_CONCURRENCY, default READ_ONLY */
    int          updatable;         /* this result set supports positioned DML */
    char        *base_table;        /* table for the synthesized UPDATE/DELETE */
    int          rowid_col;         /* core column index of the hidden ROWID, -1 = none */
    char       **rowids;            /* per-row ROWID strings, [num_rowids] */
    size_t       num_rowids;
} OdbcStmt;

/* Result columns visible to the application: the core's column count minus the
 * appended ROWID an updatable cursor hides. */
static inline int odbc_visible_cols(OdbcStmt *s)
{
    int n = (s != NULL && s->core != NULL) ? seer_stmt_num_cols(s->core) : 0;
    return (s != NULL && s->rowid_col >= 0 && n > 0) ? n - 1 : n;
}

/* Record a diagnostic on a handle and return `ret`: clears any existing records
 * and posts this one. `state` is a 5-char SQLSTATE; `msg` may be NULL. */
SQLRETURN seer_odbc_diag(SQLHANDLE handle, const char *state,
                         SQLINTEGER native, const char *msg, SQLRETURN ret);

/* Append a diagnostic record without clearing the existing ones. `row_number`
 * is a 1-based array-DML row, or SQL_NO_ROW_NUMBER. Used for batch errors. */
void seer_odbc_diag_add(SQLHANDLE handle, const char *state, SQLINTEGER native,
                        const char *msg, SQLLEN row_number);

/* Clear a handle's diagnostics (call at the entry of each ODBC function). */
void seer_odbc_diag_clear(SQLHANDLE handle);

/* Release a handle's diagnostic queue (call from SQLFreeHandle). */
void seer_odbc_diag_free(SQLHANDLE handle);

/* Map a core SeerStatus to an ODBC SQLSTATE string. */
const char *seer_odbc_sqlstate(SeerStatus st);

/* Run a driver-generated query with positional text binds and ready the
 * statement for SQLFetch/SQLGetData. Defined in exec.c, used by catalog.c. */
SQLRETURN seer_odbc_run_query(OdbcStmt *s, const char *sql,
                             const char *const *params, int nparams);

/* Positioned DELETE / UPDATE for SQLSetPos on an updatable cursor: `row` is the
 * 0-based result-set row (SQLSetPos has already resolved the rowset offset).
 * Defined in exec.c (where the bind/exec machinery lives), used by results.c.
 * row < 0 applies to every row of the current rowset. */
SQLRETURN seer_odbc_pos_delete(OdbcStmt *s, long row);
SQLRETURN seer_odbc_pos_update(OdbcStmt *s, long row);

/* Free the updatable-cursor bookkeeping (rowids, base table). */
void seer_odbc_free_updatable(OdbcStmt *s);

#endif /* SEERODBC_INTERNAL_H */

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

#include "odbc_platform.h" /* <windows.h> before the ODBC headers on Windows */

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

/* SeerODBC extension SQL types: a CLOB / BLOB OUT parameter of a PL/SQL block,
 * SQLBindParameter(..., SQL_PARAM_OUTPUT, SQL_C_CHAR / SQL_C_BINARY,
 * SQL_SEER_CLOB / SQL_SEER_BLOB, size, ...) (#214). On 8i, which converts no
 * CLOB to text, `? := c` needs it; SQL_LONGVARCHAR there is a LONG / text
 * bind. On every other release it's the same as SQL_LONGVARCHAR /
 * SQL_LONGVARBINARY. */
#ifndef SQL_SEER_CLOB
#define SQL_SEER_CLOB (-9998)
#endif
#ifndef SQL_SEER_BLOB
#define SQL_SEER_BLOB (-9997)
#endif

/* SeerODBC extension SQL type: a REF parameter (#241), its value the REF's
 * bytes as a REF column reads them, SQL_C_BINARY with the byte length in the
 * indicator; SQL_PARAM_INPUT or SQL_PARAM_OUTPUT. The type the REF refers to is
 * named "SCHEMA.TYPE" in the parameter's IPD record, with
 * SQLSetDescField(ipd, n, SQL_DESC_SEER_REF_TYPE, "SCHEMA.TYPE", SQL_NTS): ODBC's
 * own SQL_DESC_TYPE_NAME is read-only there. 8i, 9i and 12c+ take a REF IN;
 * 9i and 12c+ a REF OUT. */
#ifndef SQL_SEER_REF
#define SQL_SEER_REF (-9996)
#endif
#define SQL_DESC_SEER_REF_TYPE 19116

/* SeerODBC extension SQLColAttribute field identifier: the column's 23ai SQL
 * annotations, returned as a "name=value\n..." character string (name-only
 * annotations have an empty value; empty string when the column has none). */
#define SQL_DESC_SEER_ANNOTATIONS 19111

/* SeerODBC extension SQL_ATTR for SQLSetStmtAttr: point this at a SQLLEN array
 * (>= SQL_ATTR_PARAMSET_SIZE elements) before an array-DML execute and the
 * driver requests 12c+ per-iteration row counts and fills the array with how
 * many rows each parameter set affected. */
#define SQL_ATTR_SEER_DML_ROW_COUNTS 19112

/* SeerODBC extension SQLGetDiagField identifier: the parse offset into the SQL
 * text the server reported with the error (SQLINTEGER; 0 when none) - where the
 * parser stopped, as Oracle clients show it. */
#define SQL_DIAG_SEER_ERROR_OFFSET 19113

/* SeerODBC extension SQLColAttribute field identifiers for a 23ai VECTOR
 * column (numeric): its declared dimension count (0 = flexible), and its
 * element format (2 FLOAT32, 3 FLOAT64, 4 INT8, 5 BINARY; 0 = flexible). 0 for
 * any other column. */
#define SQL_DESC_SEER_VECTOR_DIMENSIONS 19114
#define SQL_DESC_SEER_VECTOR_FORMAT 19115

/* A diagnostic record. Most failures post one; an array-DML execute in
 * batch-errors mode posts one per failed row, each carrying its 1-based
 * SQL_DIAG_ROW_NUMBER. */
typedef struct {
  char state[6];     /* 5-char SQLSTATE + NUL */
  SQLINTEGER native; /* native error (ORA number), 0 if none */
  char message[600];
  SQLLEN row_number;       /* 1-based row, or SQL_NO_ROW_NUMBER */
  SQLINTEGER error_offset; /* SQL_DIAG_SEER_ERROR_OFFSET */
} OdbcDiagRec;

/* A growable diagnostic-record queue per handle (the buffer is kept across
 * clears; `count` is reset to 0 at each ODBC entry point). */
typedef struct {
  OdbcDiagRec *recs;
  int count;
  int cap;
} OdbcDiag;

typedef struct {
  SQLSMALLINT type; /* SQL_HANDLE_ENV / _DBC / _STMT */
  OdbcDiag diag;
} OdbcHeader;

typedef struct {
  OdbcHeader h;
  SQLINTEGER odbc_version;
} OdbcEnv;

/* SQLSetCursorName's longest name, as SQL_MAX_CURSOR_NAME_LEN reports it (#288). */
#define SEER_MAX_CURSOR_NAME_LEN 128

typedef struct {
  OdbcHeader h;
  OdbcEnv *env;
  SeerConn *conn;
  int connected;
  int session_dead; /* the server ended the session over a live socket (#340) */
  SQLUINTEGER autocommit;
  long login_timeout;        /* SQL_ATTR_LOGIN_TIMEOUT seconds, 0 = none; -1 unset (#216) */
  SQLUINTEGER txn_isolation; /* SQL_ATTR_TXN_ISOLATION, 0 = the server's default (#220) */
  SQLUINTEGER conn_timeout;  /* SQL_ATTR_CONNECTION_TIMEOUT, seconds; 0 = none (#228) */
  SQLUINTEGER metadata_id;   /* SQL_ATTR_METADATA_ID: the default for new statements (#278) */
  void *stmts;               /* its statements (OdbcStmt), newest first: cursor names (#288) */
  void *descs;               /* its explicit descriptors (OdbcDesc), newest first (#291) */
  unsigned long cursor_seq;  /* the last SQL_CURn generated */
  char *browse_cs;
  /* For SQLGetInfo (#234): the DSN connected through ("" without one), the
   * user and the service or SID, kept from the connect. */
  char *info_dsn, *info_user, *info_server; /* SQLBrowseConnect: accumulated attributes */
  char dbms_ver[64]; /* SQL_DBMS_VER, resolved on first request ("" = not yet) */
} OdbcDbc;

/* A column binding set by SQLBindCol. */
typedef struct {
  SQLSMALLINT target_type; /* SQL_C_* (0 if unbound) */
  SQLPOINTER buf;
  SQLLEN buflen;
  SQLLEN *indicator;
  int bound;
} OdbcBind;

/* An application descriptor's records: a statement's column bindings, or an
 * explicitly allocated descriptor's (#291), which statements share when
 * they use it as their ARD. */
typedef struct {
  OdbcBind *binds; /* [num_binds] */
  int num_binds;
} OdbcBindSet;

/* A deferred parameter set by SQLBindParameter (resolved at execute time). */
typedef struct {
  SQLSMALLINT io_type;  /* SQL_PARAM_INPUT / _OUTPUT / _INPUT_OUTPUT */
  SQLSMALLINT c_type;   /* ValueType (SQL_C_*) */
  SQLSMALLINT sql_type; /* ParameterType (SQL_*) - drives an OUT's OAC */
  SQLULEN column_size;  /* declared size (OUT buffer / VARCHAR length) */
  SQLPOINTER buf;
  SQLLEN buflen;
  SQLLEN *indicator;
  int bound;
  /* Data-at-execution (SQLPutData): when the bound indicator is
   * SQL_DATA_AT_EXEC the value is streamed in after execute. `dae` marks such
   * a param for the current execute; `dae_buf`/`dae_len` accumulate the chunks
   * (bound in place of `buf`), `dae_null` records a SQL_NULL_DATA put. */
  int dae;
  int dae_null;
  char *dae_buf;
  size_t dae_len;
  size_t dae_cap;
  char *ref_type; /* SQL_DESC_SEER_REF_TYPE: "SCHEMA.TYPE" a REF refers to (#241) */
} OdbcParam;

/* The four ODBC descriptors of a statement (SQL_ATTR_*_DESC): application/
 * implementation x row/parameter. Implicitly allocated with the statement; we
 * expose them read-only via SQLGetDescField/Rec, deriving fields from the bind
 * arrays (APD/ARD) and the core column/param metadata (IRD/IPD). */
typedef enum { SEER_DESC_ARD, SEER_DESC_APD, SEER_DESC_IRD, SEER_DESC_IPD } SeerDescKind;

typedef struct {
  OdbcHeader h;
  void *stmt; /* owning OdbcStmt; NULL for an explicit descriptor */
  SeerDescKind kind;
  /* An explicitly allocated descriptor (#291): an application descriptor
   * of the connection, its records its own, used by any of the
   * connection's statements as their ARD (shared in place) or APD (copied
   * into the parameters at execute). */
  int is_explicit;
  OdbcDbc *dbc;
  OdbcBindSet recs;
  void *next_desc; /* the connection's next explicit descriptor */
} OdbcDesc;

typedef struct {
  OdbcHeader h;
  OdbcDbc *dbc;
  char *sql;                   /* prepared statement text (SQLPrepare) */
  SeerStmt *core;              /* core statement, NULL until execute */
  OdbcDesc ard, apd, ird, ipd; /* implicit descriptors */
  OdbcBindSet own_binds;       /* the implicit ARD's records: result-column bindings */
  OdbcBindSet *ab;   /* the current ARD's: own_binds, or an explicit descriptor's (#291) */
  OdbcDesc *ard_ext; /* the explicit ARD in use, NULL = the implicit one (#291) */
  OdbcDesc *apd_ext; /* the explicit APD in use, NULL = the implicit one */
  OdbcParam *params; /* input parameters, [num_params] */
  int num_params;
  /* Data-at-execution sequence (SQLParamData/SQLPutData) between an execute
   * that returned SQL_NEED_DATA and the final SQLParamData that runs it. */
  int dae_active;     /* in a SQL_NEED_DATA sequence */
  int bind_national;  /* 8i: national types bound in NCHAR form, the retry after ORA-12704 (#419) */
  int bind_as_lob;    /* 8i: long types bound for LOB targets, the retry after PLS-00306 (#424) */
  int dae_current;    /* param index being filled, -1 before the first */
  int getdata_col;    /* last SQLGetData column, for fragment tracking */
  SQLLEN getdata_off; /* bytes already returned for getdata_col */
  int getdata_done;   /* getdata_col was returned to its end (#351) */
  /* Array (bulk) parameter binding. */
  SQLULEN paramset_size;         /* SQL_ATTR_PARAMSET_SIZE (rows), default 1 */
  SQLULEN param_bind_type;       /* SQL_ATTR_PARAM_BIND_TYPE, default by-column */
  SQLULEN *params_processed;     /* SQL_ATTR_PARAMS_PROCESSED_PTR */
  SQLUSMALLINT *param_status;    /* SQL_ATTR_PARAM_STATUS_PTR */
  SQLLEN *param_bind_offset;     /* SQL_ATTR_PARAM_BIND_OFFSET_PTR (#243) */
  SQLUSMALLINT *param_operation; /* SQL_ATTR_PARAM_OPERATION_PTR: SQL_PARAM_IGNORE rows */
  SQLULEN *param_rows;           /* the parameter sets executed, by their row (malloc'd) */
  SQLULEN n_param_rows;
  /* A query with a parameter array runs one set per result set
   * (SQL_PAS_BATCH, #431): set pas_k of param_rows now, the next on
   * SQLMoreResults, by re-preparing pas_sql (the SQL as sent). */
  int pas_query;
  SQLULEN pas_k;
  char *pas_sql;
  SQLLEN *dml_row_counts; /* SQL_ATTR_SEER_DML_ROW_COUNTS (app buffer) */
  /* Row-array (block) fetch. */
  SQLULEN row_array_size;      /* SQL_ATTR_ROW_ARRAY_SIZE, default 1 */
  SQLULEN row_bind_type;       /* SQL_ATTR_ROW_BIND_TYPE (0 = by column) */
  SQLLEN *row_bind_offset;     /* SQL_ATTR_ROW_BIND_OFFSET_PTR (#243) */
  SQLUSMALLINT *row_operation; /* SQL_ATTR_ROW_OPERATION_PTR: SQL_ROW_IGNORE rows (#250) */
  SQLULEN retrieve_data;       /* SQL_ATTR_RETRIEVE_DATA: SQL_RD_OFF fetches fill nothing */
  SQLLEN *fetch_bookmark;      /* SQL_ATTR_FETCH_BOOKMARK_PTR, kept (no bookmarks) */
  SQLULEN *rows_fetched;       /* SQL_ATTR_ROWS_FETCHED_PTR */
  SQLUSMALLINT *row_status;    /* SQL_ATTR_ROW_STATUS_PTR */
  long rowset_start;           /* 0-based first row of the current rowset, -1 = none */
  /* Updatable cursor (positioned update/delete via SQLSetPos). */
  SQLULEN concurrency;   /* SQL_ATTR_CONCURRENCY, default READ_ONLY */
  SQLULEN query_timeout; /* SQL_ATTR_QUERY_TIMEOUT, seconds; 0 = none (#209) */
  SQLULEN max_length;    /* SQL_ATTR_MAX_LENGTH: bytes of a char / binary value, 0 = all (#248) */
  SQLULEN noscan;        /* SQL_ATTR_NOSCAN: SQL_NOSCAN_ON sends the text unscanned (#248) */
  SQLULEN max_rows;      /* SQL_ATTR_MAX_ROWS; 0 = no limit (#221) */
  SQLULEN metadata_id;   /* SQL_ATTR_METADATA_ID: catalog arguments are identifiers (#278) */
  SQLULEN cursor_type;   /* SQL_ATTR_CURSOR_TYPE: FORWARD_ONLY (0) or STATIC (#226) */
  SQLULEN sensitivity;   /* SQL_ATTR_CURSOR_SENSITIVITY: UNSPECIFIED (0) or INSENSITIVE */
  int updatable;         /* this result set supports positioned DML */
  char *base_table;      /* table for the synthesized UPDATE/DELETE */
  int rowid_col;         /* core column index of the hidden ROWID, -1 = none */
  char **rowids;         /* per-row ROWID strings, [num_rowids] */
  size_t num_rowids;
  void *next_stmt;   /* the connection's next statement (#288) */
  char *cursor_name; /* SQLSetCursorName's, or a generated SQL_CURn */
  long cur_row;      /* the cursor's current row (0-based), -1 = none */
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
SQLRETURN seer_odbc_diag(SQLHANDLE handle, const char *state, SQLINTEGER native, const char *msg,
                         SQLRETURN ret);

/* Append a diagnostic record without clearing the existing ones. `row_number`
 * is a 1-based array-DML row, or SQL_NO_ROW_NUMBER. Used for batch errors. */
void seer_odbc_diag_add(SQLHANDLE handle, const char *state, SQLINTEGER native, const char *msg,
                        SQLLEN row_number);

/* Clear a handle's diagnostics (call at the entry of each ODBC function). */
void seer_odbc_diag_clear(SQLHANDLE handle);

/* Release a handle's diagnostic queue (call from SQLFreeHandle). */
void seer_odbc_diag_free(SQLHANDLE handle);

/* Map a core SeerStatus to an ODBC SQLSTATE string. */
const char *seer_odbc_sqlstate(SeerStatus st);

/* Where row `row` of a bound buffer is (#243): ODBC adds the bind offset
 * (SQL_ATTR_*_BIND_OFFSET_PTR) to every bound data and indicator pointer,
 * then steps by the bind type - row-wise, the size of the application's
 * struct - or, column-wise (bind type 0), by the element's own size. NULL
 * for an unbound pointer. */
static inline void *seer_odbc_bound_at(void *base, const SQLLEN *offset, SQLULEN bind_type,
                                       size_t elem, SQLULEN row)
{
  if (base == NULL)
    return NULL;
  char *p = (char *)base + (offset != NULL ? *offset : 0);
  return p + row * (bind_type != 0 ? bind_type : elem);
}
/* Make room for column bindings 1..n, keeping those made (#244): a column
 * stays bound until unbound or SQLFreeStmt(SQL_UNBIND), across executes, and
 * may be bound before the statement has run. 0, or -1 when out of memory. */
int seer_odbc_ensure_binds(OdbcStmt *s, int n);
/* Grow a set of bindings (an ARD's or an explicit descriptor's) to n records. */
int seer_odbc_bindset_ensure(OdbcBindSet *b, int n);
/* A result column's C type `t`, SQL_C_DEFAULT taken as the default C type of
 * the SQL type the column is described as (#316). */
SQLSMALLINT seer_odbc_col_c_type(OdbcStmt *s, int col, SQLSMALLINT t);
/* The connected server's major release: 9 for 9i, which sends no version at
 * login; 0 when not connected. */
int seer_odbc_server_major(OdbcDbc *c);
/* Apply SQL_ATTR_TXN_ISOLATION's level on the connection (#220). */
SQLRETURN seer_odbc_apply_isolation(OdbcDbc *c, SQLUINTEGER level);
/* Arm the statement's SQL_ATTR_QUERY_TIMEOUT on its connection before a call
 * to the server (#209). */
void seer_odbc_arm_timeout(OdbcStmt *s);
/* Arm SQL_ATTR_CONNECTION_TIMEOUT for a call that isn't a statement's (#228). */
void seer_odbc_arm_conn_timeout(OdbcDbc *c);

/* Run a driver-generated query with positional text binds and ready the
 * statement for SQLFetch/SQLGetData. Defined in exec.c, used by catalog.c. */
SQLRETURN seer_odbc_run_query(OdbcStmt *s, const char *sql, const char *const *params, int nparams);

/* Result metadata before execution: when the statement has been prepared
 * (SQLPrepare) but has no core statement yet, create it and describe the
 * query's columns with a parse-only round trip, so SQLNumResultCols /
 * SQLDescribeCol / SQLColAttribute answer between SQLPrepare and SQLExecute.
 * A no-op otherwise. Returns SQL_SUCCESS, or SQL_ERROR with a diagnostic when
 * the server rejects the statement. */
SQLRETURN seer_odbc_describe_prepared(OdbcStmt *s);

/* Post the diagnostic for a failed core execute: SQLSTATE from the status,
 * the ORA number as the native error and the server's error offset. */
SQLRETURN seer_odbc_exec_error(OdbcStmt *s, SeerStatus st);

/* Positioned DELETE / UPDATE for SQLSetPos on an updatable cursor: `row` is the
 * 0-based result-set row (SQLSetPos has already resolved the rowset offset).
 * Defined in exec.c (where the bind/exec machinery lives), used by results.c.
 * row < 0 applies to every row of the current rowset. */
SQLRETURN seer_odbc_pos_delete(OdbcStmt *s, long row);
SQLRETURN seer_odbc_pos_update(OdbcStmt *s, long row);

/* Free the updatable-cursor bookkeeping (rowids, base table). */
void seer_odbc_free_updatable(OdbcStmt *s);
/* The next parameter set of a query run one set per result set (#431):
 * SQL_NO_DATA when none is left or none was running. */
SQLRETURN seer_odbc_next_param_set(OdbcStmt *s);

#endif /* SEERODBC_INTERNAL_H */

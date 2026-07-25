/* Statement execution: SQLPrepare / SQLExecute / SQLExecDirect / SQLNumParams /
 * SQLBindParameter / SQLDescribeParam. The statement text is preprocessed -
 * the {call}/{?=call} ODBC escape becomes a PL/SQL block, then '?' parameter
 * markers become Oracle ':1', ':2', ... - before going to the core.
 *
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "charset.h"
#include "compat.h"
#include "convert.h"
#include "odbc_internal.h"
#include "sqlprep.h"

/* Map an ODBC SQL parameter type to the Oracle type for an OUT bind's OAC. */
static int ora_type_for_sql(SQLSMALLINT t)
{
    switch (t) {
    case SQL_INTEGER: case SQL_SMALLINT: case SQL_TINYINT: case SQL_BIGINT:
    case SQL_DECIMAL: case SQL_NUMERIC: case SQL_FLOAT: case SQL_REAL:
    case SQL_DOUBLE:
        return 2;                                   /* NUMBER */
    case SQL_TYPE_TIMESTAMP: case SQL_TIMESTAMP:
    case SQL_TYPE_DATE: case SQL_DATE:
        return 12;                                  /* DATE */
    case SQL_BINARY: case SQL_VARBINARY: case SQL_LONGVARBINARY:
        return 23;                                  /* RAW */
    case SQL_REFCURSOR:
        return 102;                                 /* REF CURSOR */
    default:
        return 1;                                   /* VARCHAR */
    }
}

/* Element stride for column-wise array binding: the bound buffer length for
 * variable types, else the fixed C-type width. */
static size_t ctype_stride(SQLSMALLINT c_type, SQLLEN buflen)
{
    if (buflen > 0)
        return (size_t)buflen;
    switch (c_type) {
    case SQL_C_SLONG: case SQL_C_LONG: case SQL_C_ULONG:    return sizeof(SQLINTEGER);
    case SQL_C_SSHORT: case SQL_C_SHORT: case SQL_C_USHORT: return sizeof(SQLSMALLINT);
    case SQL_C_SBIGINT: case SQL_C_UBIGINT:                 return sizeof(SQLBIGINT);
    case SQL_C_STINYINT: case SQL_C_TINYINT: case SQL_C_UTINYINT: case SQL_C_BIT:
        return 1;
    case SQL_C_FLOAT:                                       return sizeof(SQLREAL);
    case SQL_C_DOUBLE:                                      return sizeof(SQLDOUBLE);
    case SQL_C_TYPE_TIMESTAMP: case SQL_C_TIMESTAMP:        return sizeof(SQL_TIMESTAMP_STRUCT);
    case SQL_C_TYPE_DATE: case SQL_C_DATE:                  return sizeof(SQL_DATE_STRUCT);
    case SQL_C_TYPE_TIME: case SQL_C_TIME:                  return sizeof(SQL_TIME_STRUCT);
    default:                                                return 1;
    }
}

/* Bind one parameter value (the value at `valptr`, length hint `ind`) into core
 * statement `core` at `param`, dispatching on the ODBC C type. */
static SeerStatus bind_one_value(SeerStmt *core, int param, SQLSMALLINT c_type,
                                 const void *valptr, SQLLEN ind)
{
    if (ind == SQL_NULL_DATA || valptr == NULL)
        return seer_stmt_bind_null(core, param);

    switch (c_type) {
    case SQL_C_SLONG: case SQL_C_LONG:
        return seer_stmt_bind_int64(core, param, *(const SQLINTEGER *)valptr);
    case SQL_C_ULONG:
        return seer_stmt_bind_int64(core, param, (int64_t)*(const SQLUINTEGER *)valptr);
    case SQL_C_SSHORT: case SQL_C_SHORT:
        return seer_stmt_bind_int64(core, param, *(const SQLSMALLINT *)valptr);
    case SQL_C_SBIGINT:
        return seer_stmt_bind_int64(core, param, (int64_t)*(const SQLBIGINT *)valptr);
    case SQL_C_STINYINT: case SQL_C_TINYINT:
        return seer_stmt_bind_int64(core, param, *(const signed char *)valptr);
    case SQL_C_FLOAT:
        return seer_stmt_bind_float(core, param, *(const SQLREAL *)valptr);
    case SQL_C_DOUBLE:
        return seer_stmt_bind_double(core, param, *(const SQLDOUBLE *)valptr);
    case SQL_C_BIT:
        return seer_stmt_bind_bool(core, param, *(const unsigned char *)valptr != 0);
    case SQL_C_BINARY:
        return seer_stmt_bind_raw(core, param, valptr, (ind >= 0) ? (int)ind : 0);
    case SQL_C_TYPE_TIMESTAMP: case SQL_C_TIMESTAMP: {
        const SQL_TIMESTAMP_STRUCT *t = valptr;
        /* `fraction` is nanoseconds (ODBC); a native TIMESTAMP bind keeps it
         * (bind_date would truncate to whole seconds). */
        return seer_stmt_bind_timestamp(core, param, t->year, t->month, t->day,
                                        t->hour, t->minute, t->second, t->fraction);
    }
    case SQL_C_TYPE_DATE: case SQL_C_DATE: {
        const SQL_DATE_STRUCT *t = valptr;
        return seer_stmt_bind_date(core, param, t->year, t->month, t->day, 0, 0, 0);
    }
    case SQL_C_TYPE_TIME: case SQL_C_TIME: {
        const SQL_TIME_STRUCT *t = valptr;
        return seer_stmt_bind_date(core, param, 1970, 1, 1,
                                   t->hour, t->minute, t->second);
    }
    case SQL_C_INTERVAL_YEAR_TO_MONTH: {
        const SQL_INTERVAL_STRUCT *iv = valptr;
        int sgn = (iv->interval_sign == SQL_TRUE) ? -1 : 1;
        return seer_stmt_bind_interval_ym(core, param,
                                          sgn * (int32_t)iv->intval.year_month.year,
                                          sgn * (int32_t)iv->intval.year_month.month);
    }
    case SQL_C_INTERVAL_DAY_TO_SECOND: {
        const SQL_INTERVAL_STRUCT *iv = valptr;
        int sgn = (iv->interval_sign == SQL_TRUE) ? -1 : 1;
        return seer_stmt_bind_interval_ds(core, param,
                                          sgn * (int32_t)iv->intval.day_second.day,
                                          sgn * (int32_t)iv->intval.day_second.hour,
                                          sgn * (int32_t)iv->intval.day_second.minute,
                                          sgn * (int32_t)iv->intval.day_second.second,
                                          sgn * (int32_t)iv->intval.day_second.fraction);
    }
    case SQL_C_WCHAR: {
        size_t inbytes;
        if (ind == SQL_NTS) {
            const unsigned short *w = valptr;
            size_t n = 0;
            while (w[n] != 0) n++;
            inbytes = n * sizeof(unsigned short);
        } else {
            inbytes = (ind >= 0) ? (size_t)ind : 0;
        }
        char  *u8 = NULL;
        size_t u8len = 0;
        if (seer_iconv(SEER_UTF16, "UTF-8", (const char *)valptr, inbytes,
                       &u8, &u8len) != 0)
            return SEER_EPROTO;
        SeerStatus st = seer_stmt_bind_text(core, param, u8, (int)u8len);
        free(u8);
        return st;
    }
    case SQL_C_CHAR: case SQL_C_DEFAULT:
    default:
        return seer_stmt_bind_text(core, param, (const char *)valptr,
                                   (ind == SQL_NTS) ? -1 : (int)ind);
    }
}

/* True if a bound parameter's length/indicator marks it data-at-execution
 * (its value is streamed in with SQLPutData after a SQL_NEED_DATA execute). */
static int is_data_at_exec(SQLLEN ind)
{
    return ind == SQL_DATA_AT_EXEC || ind <= SQL_LEN_DATA_AT_EXEC_OFFSET;
}

/* Append a SQLPutData chunk to a parameter's accumulation buffer. */
static int dae_append(OdbcParam *p, const void *data, size_t n)
{
    if (p->dae_len + n + 1 > p->dae_cap) {
        size_t cap = p->dae_cap ? p->dae_cap : 256;
        while (cap < p->dae_len + n + 1)
            cap *= 2;
        char *nb = realloc(p->dae_buf, cap);
        if (nb == NULL)
            return -1;
        p->dae_buf = nb;
        p->dae_cap = cap;
    }
    memcpy(p->dae_buf + p->dae_len, data, n);
    p->dae_len += n;
    p->dae_buf[p->dae_len] = '\0';
    return 0;
}

/* Drop a parameter's data-at-execution accumulation (between executes). */
static void dae_reset(OdbcParam *p)
{
    free(p->dae_buf);
    p->dae_buf  = NULL;
    p->dae_len  = 0;
    p->dae_cap  = 0;
    p->dae      = 0;
    p->dae_null = 0;
}

/* Apply parameters and run the prepared statement, then post-process (OUT
 * params, updatable-cursor ROWID capture, result binding array). Split out of
 * exec_core so a data-at-execution sequence can defer it to SQLParamData. */
static SQLRETURN exec_finish(OdbcStmt *s);

/* Read each deferred parameter's value(s) and apply them to the core. With
 * SQL_ATTR_PARAMSET_SIZE > 1 this binds an array (column-wise): one core
 * iteration per row, each row's value read at buf + row*stride. OUT / IN OUT
 * params declare an OUT bind (single-row only). */
static SQLRETURN apply_params(OdbcStmt *s)
{
    SQLULEN n = s->paramset_size ? s->paramset_size : 1;

    if (n > 1) {
        SeerStatus st = seer_stmt_set_array_size(s->core, (int)n);
        if (st != SEER_OK)
            return seer_odbc_diag(s, seer_odbc_sqlstate(st), 0,
                                  "array bind setup failed", SQL_ERROR);
        /* Array DML reports per-row status (SQL_ATTR_PARAM_STATUS_PTR), so run
         * in batcherrors mode: a bad row doesn't abort the batch - the good
         * rows apply and each failure surfaces as a row status + diag record. */
        seer_stmt_set_batch_errors(s->core, 1);
        /* If the app armed SQL_ATTR_SEER_DML_ROW_COUNTS, request 12c+ per-row
         * counts so we can fill its buffer after execute. */
        if (s->dml_row_counts != NULL)
            seer_stmt_set_array_dml_rowcounts(s->core, 1);
        for (SQLULEN row = 0; row < n; row++) {
            seer_stmt_bind_row(s->core, (int)row);
            for (int i = 0; i < s->num_params; i++) {
                OdbcParam *p = &s->params[i];
                int param = i + 1;
                if (!p->bound || p->buf == NULL || p->io_type == SQL_PARAM_OUTPUT) {
                    seer_stmt_bind_null(s->core, param);
                    continue;
                }
                size_t stride = ctype_stride(p->c_type, p->buflen);
                const void *val = (const char *)p->buf + (size_t)row * stride;
                SQLLEN ind = p->indicator ? p->indicator[row] : SQL_NTS;
                st = bind_one_value(s->core, param, p->c_type, val, ind);
                if (st != SEER_OK)
                    return seer_odbc_diag(s, seer_odbc_sqlstate(st), 0,
                                          "Parameter bind failed", SQL_ERROR);
            }
        }
        return SQL_SUCCESS;
    }

    for (int i = 0; i < s->num_params; i++) {
        OdbcParam *p = &s->params[i];
        int param = i + 1;

        if (p->dae) {                  /* value streamed in via SQLPutData */
            if (p->dae_null)
                seer_stmt_bind_null(s->core, param);
            else if (bind_one_value(s->core, param, p->c_type,
                                    p->dae_buf ? p->dae_buf : "",
                                    (SQLLEN)p->dae_len) != SEER_OK)
                return seer_odbc_diag(s, "HY000", 0, "Parameter bind failed", SQL_ERROR);
            continue;
        }
        if (p->bound && (p->io_type == SQL_PARAM_OUTPUT ||
                         p->io_type == SQL_PARAM_INPUT_OUTPUT)) {
            int sz = (p->column_size > 0) ? (int)p->column_size : (int)p->buflen;
            seer_stmt_bind_out(s->core, param, ora_type_for_sql(p->sql_type), sz);
            continue;
        }
        if (!p->bound) {
            seer_stmt_bind_null(s->core, param);
            continue;
        }
        SQLLEN ind = p->indicator ? *p->indicator : SQL_NTS;
        SeerStatus st = bind_one_value(s->core, param, p->c_type, p->buf, ind);
        if (st != SEER_OK)
            return seer_odbc_diag(s, seer_odbc_sqlstate(st), 0,
                                  "Parameter bind failed", SQL_ERROR);
    }
    return SQL_SUCCESS;
}

/* Run a driver-generated query (the catalog functions use this): prepare,
 * bind the given text parameters positionally, execute, and size the result
 * binding array. */
SQLRETURN seer_odbc_run_query(OdbcStmt *s, const char *sql,
                              const char *const *params, int nparams)
{
    if (s->core != NULL) {
        seer_stmt_close(s->core);
        s->core = NULL;
    }
    SeerStatus st = seer_stmt_prepare(s->dbc->conn, sql, &s->core);
    if (st != SEER_OK)
        return seer_odbc_diag(s, seer_odbc_sqlstate(st), 0, seer_strerror(st), SQL_ERROR);

    for (int i = 0; i < nparams; i++) {
        st = seer_stmt_bind_text(s->core, i + 1, params[i] ? params[i] : "%", -1);
        if (st != SEER_OK)
            return seer_odbc_diag(s, seer_odbc_sqlstate(st), 0, "bind failed", SQL_ERROR);
    }

    st = seer_stmt_execute(s->core);
    if (st != SEER_OK) {
        const char *ora = seer_last_error(s->dbc->conn);
        return seer_odbc_diag(s, seer_odbc_sqlstate(st), 0,
                              ora ? ora : seer_strerror(st), SQL_ERROR);
    }

    int ncols = seer_stmt_num_cols(s->core);
    free(s->binds);
    s->binds = NULL;
    s->num_binds = 0;
    if (ncols > 0) {
        s->binds = calloc((size_t)ncols, sizeof *s->binds);
        if (s->binds == NULL)
            return seer_odbc_diag(s, "HY001", 0, "Out of memory", SQL_ERROR);
        s->num_binds = ncols;
    }
    s->getdata_col = -1;
    s->getdata_off = 0;
    s->rowset_start = -1;
    return SQL_SUCCESS;
}

/* Prepare the statement text: NUL-terminate, then run the SQL preprocessor
 * (escape expansion + '?' marker rewrite, see sqlprep.c). */
static char *dup_sql(SQLCHAR *text, SQLINTEGER len)
{
    size_t n = (len == SQL_NTS) ? strlen((const char *)text) : (size_t)len;
    char *raw = malloc(n + 1);
    if (raw == NULL)
        return NULL;
    memcpy(raw, text, n);
    raw[n] = '\0';
    char *out = seer_sql_prepare(raw);
    free(raw);
    return out;
}

/* Prepare + execute `sql` on the core, and size the binding array. */
static SQLRETURN exec_core(OdbcStmt *s, const char *sql)
{
    seer_odbc_free_updatable(s);
    s->updatable = 0;
    s->rowid_col = -1;

    /* For an updatable cursor (the app set SQL_ATTR_CONCURRENCY), transparently
     * append ROWIDTOCHAR(ROWID) to a simple single-table SELECT and hide it.
     * SQL_CONCUR_LOCK additionally appends FOR UPDATE for pessimistic locking. */
    char *rewritten = NULL;
    if (s->concurrency != SQL_CONCUR_READ_ONLY) {
        char *tbl = NULL;
        rewritten = seer_sql_make_updatable(sql, &tbl,
                                            s->concurrency == SQL_CONCUR_LOCK);
        if (rewritten != NULL) {
            sql = rewritten;
            s->base_table = tbl;
            s->updatable  = 1;
        }
    }
    if (s->core != NULL) {            /* drop any prior result set */
        seer_stmt_close(s->core);
        s->core = NULL;
    }

    SeerStatus st = seer_stmt_prepare(s->dbc->conn, sql, &s->core);
    if (st != SEER_OK) {
        free(rewritten);             /* sql may alias it, but nothing reads sql now */
        return seer_odbc_diag(s, seer_odbc_sqlstate(st), 0, seer_strerror(st), SQL_ERROR);
    }

    /* Data-at-execution: if any single-row INPUT parameter was bound with
     * SQL_DATA_AT_EXEC, defer the execute - return SQL_NEED_DATA and let
     * SQLParamData/SQLPutData stream the values, then run it (#dae). */
    s->dae_active  = 0;
    s->dae_current = -1;
    int has_dae = 0;
    if ((s->paramset_size ? s->paramset_size : 1) == 1) {
        /* Only parameters the statement actually uses count - a leftover binding
         * with a data-at-exec indicator from a prior statement must not turn a
         * paramless execute into SQL_NEED_DATA. */
        int nmarkers = seer_sql_count_params(sql);
        for (int i = 0; i < s->num_params; i++) {
            OdbcParam *p = &s->params[i];
            dae_reset(p);
            if (i < nmarkers && p->bound && p->indicator != NULL &&
                (p->io_type == SQL_PARAM_INPUT || p->io_type == SQL_PARAM_INPUT_OUTPUT) &&
                is_data_at_exec(*p->indicator)) {
                p->dae  = 1;
                has_dae = 1;
            }
        }
    }
    /* seer_stmt_prepare copied the SQL, and the last read of `sql` (which may
     * alias rewritten) was seer_sql_count_params above - so the rewritten
     * buffer is safe to free here, covering both remaining exit paths. */
    free(rewritten);
    if (has_dae) {
        s->dae_active  = 1;
        s->dae_current = -1;
        return SQL_NEED_DATA;
    }
    return exec_finish(s);
}

static SQLRETURN exec_finish(OdbcStmt *s)
{
    SQLRETURN pr = apply_params(s);
    if (pr != SQL_SUCCESS)
        return pr;

    SeerStatus st = seer_stmt_execute(s->core);
    if (st != SEER_OK) {
        const char *ora = seer_last_error(s->dbc->conn);
        return seer_odbc_diag(s, seer_odbc_sqlstate(st), 0,
                              ora ? ora : seer_strerror(st), SQL_ERROR);
    }

    /* Array-bind status: every set was attempted (batcherrors mode). Mark all
     * rows SUCCESS, then flip the failed ones to SQL_PARAM_ERROR and post one
     * diag record per failure (carrying its 1-based SQL_DIAG_ROW_NUMBER). */
    SQLRETURN result = SQL_SUCCESS;
    {
        SQLULEN n = s->paramset_size ? s->paramset_size : 1;
        if (s->params_processed != NULL)
            *s->params_processed = n;
        if (s->param_status != NULL)
            for (SQLULEN r = 0; r < n; r++)
                s->param_status[r] = SQL_PARAM_SUCCESS;

        size_t nbe = seer_stmt_batch_error_count(s->core);
        for (size_t i = 0; i < nbe; i++) {
            unsigned brow = 0, bcode = 0;
            const char *bmsg = NULL;
            seer_stmt_batch_error(s->core, i, &brow, &bcode, &bmsg);
            if (s->param_status != NULL && brow < n)
                s->param_status[brow] = SQL_PARAM_ERROR;
            seer_odbc_diag_add(s, "HY000", (SQLINTEGER)bcode,
                               bmsg ? bmsg : "array DML row error",
                               (SQLLEN)brow + 1);
        }
        if (nbe > 0)
            result = (nbe >= (size_t)n) ? SQL_ERROR : SQL_SUCCESS_WITH_INFO;

        /* Fill the app's SQL_ATTR_SEER_DML_ROW_COUNTS buffer with the per-
         * iteration affected-row counts (12c+); 0 where none were reported. */
        if (s->dml_row_counts != NULL) {
            size_t nc = seer_stmt_array_dml_rowcount_count(s->core);
            for (SQLULEN r = 0; r < n; r++)
                s->dml_row_counts[r] = (r < nc)
                    ? (SQLLEN)seer_stmt_array_dml_rowcount(s->core, r) : 0;
        }
    }

    /* Write OUT / IN OUT parameter values back into the app's buffers. */
    for (int i = 0; i < s->num_params; i++) {
        OdbcParam *p = &s->params[i];
        if (!p->bound || (p->io_type != SQL_PARAM_OUTPUT &&
                          p->io_type != SQL_PARAM_INPUT_OUTPUT))
            continue;
        if (p->sql_type == SQL_REFCURSOR)      /* its value is the result set */
            continue;
        const void *data = NULL;
        size_t dlen = 0;
        int is_null = 0, is_binary = 0;
        if (seer_stmt_out_data(s->core, i + 1, &data, &dlen, &is_null, &is_binary) != SEER_OK)
            continue;
        seer_odbc_convert(data ? data : "", dlen, is_null, is_binary,
                          p->c_type, p->buf, p->buflen, p->indicator, NULL);
    }

    int ncols = seer_stmt_num_cols(s->core);

    /* Updatable cursor: the appended ROWIDTOCHAR(ROWID) is the last column.
     * Capture each row's ROWID, then hide that column from the application. */
    if (s->updatable && ncols > 0) {
        s->rowid_col = ncols - 1;
        long nrows = seer_stmt_row_count(s->core);
        if (nrows > 0) {
            s->rowids = calloc((size_t)nrows, sizeof *s->rowids);
            if (s->rowids != NULL) {
                s->num_rowids = (size_t)nrows;
                for (long r = 0; r < nrows; r++) {
                    const void *d = NULL; size_t l = 0; int isn = 1, isb = 0;
                    if (seer_stmt_set_row(s->core, r) == SEER_OK)
                        seer_stmt_get_data(s->core, s->rowid_col, &d, &l, &isn, &isb);
                    s->rowids[r] = (d != NULL && !isn) ? seer_strndup((const char *)d, l) : NULL;
                }
            }
        }
        ncols -= 1;                  /* hide ROWID from the binding array */
    }

    free(s->binds);
    s->binds = NULL;
    s->num_binds = 0;
    if (ncols > 0) {
        s->binds = calloc((size_t)ncols, sizeof *s->binds);
        if (s->binds == NULL)
            return seer_odbc_diag(s, "HY001", 0, "Out of memory", SQL_ERROR);
        s->num_binds = ncols;
    }
    s->getdata_col = -1;
    s->getdata_off = 0;
    s->rowset_start = -1;
    return result;
}

SQLRETURN SQL_API SQLPrepare(SQLHSTMT   StatementHandle,
                             SQLCHAR   *StatementText,
                             SQLINTEGER TextLength)
{
    OdbcStmt *s = (OdbcStmt *)StatementHandle;
    if (s == NULL)
        return SQL_INVALID_HANDLE;
    seer_odbc_diag_clear(s);
    if (StatementText == NULL)
        return seer_odbc_diag(s, "HY009", 0, "NULL statement text", SQL_ERROR);

    char *sql = dup_sql(StatementText, TextLength);
    if (sql == NULL)
        return seer_odbc_diag(s, "HY001", 0, "Out of memory", SQL_ERROR);
    free(s->sql);
    s->sql = sql;
    return SQL_SUCCESS;
}

SQLRETURN SQL_API SQLExecute(SQLHSTMT StatementHandle)
{
    OdbcStmt *s = (OdbcStmt *)StatementHandle;
    if (s == NULL)
        return SQL_INVALID_HANDLE;
    seer_odbc_diag_clear(s);
    if (s->dbc == NULL || !s->dbc->connected)
        return seer_odbc_diag(s, "08003", 0, "Connection not open", SQL_ERROR);
    if (s->sql == NULL)
        return seer_odbc_diag(s, "HY010", 0, "Statement not prepared", SQL_ERROR);
    return exec_core(s, s->sql);
}

SQLRETURN SQL_API SQLExecDirect(SQLHSTMT   StatementHandle,
                                SQLCHAR   *StatementText,
                                SQLINTEGER TextLength)
{
    OdbcStmt *s = (OdbcStmt *)StatementHandle;
    if (s == NULL)
        return SQL_INVALID_HANDLE;
    seer_odbc_diag_clear(s);
    if (s->dbc == NULL || !s->dbc->connected)
        return seer_odbc_diag(s, "08003", 0, "Connection not open", SQL_ERROR);
    if (StatementText == NULL)
        return seer_odbc_diag(s, "HY009", 0, "NULL statement text", SQL_ERROR);

    char *sql = dup_sql(StatementText, TextLength);
    if (sql == NULL)
        return seer_odbc_diag(s, "HY001", 0, "Out of memory", SQL_ERROR);
    free(s->sql);
    s->sql = sql;
    return exec_core(s, s->sql);
}

/* Data-at-execution driver loop. After an execute that returned SQL_NEED_DATA,
 * the app calls SQLParamData to learn which parameter needs data (its token =
 * the ParameterValuePtr it bound), streams the value with one or more
 * SQLPutData calls, and calls SQLParamData again. When no parameter is left to
 * fill, SQLParamData runs the statement. */
SQLRETURN SQL_API SQLParamData(SQLHSTMT StatementHandle, SQLPOINTER *ValuePtrPtr)
{
    OdbcStmt *s = (OdbcStmt *)StatementHandle;
    if (s == NULL)
        return SQL_INVALID_HANDLE;
    seer_odbc_diag_clear(s);
    if (!s->dae_active)
        return seer_odbc_diag(s, "HY010", 0,
                              "No data-at-execution sequence in progress", SQL_ERROR);

    for (int i = s->dae_current + 1; i < s->num_params; i++) {
        if (s->params[i].dae) {
            s->dae_current = i;
            if (ValuePtrPtr != NULL)
                *ValuePtrPtr = s->params[i].buf;   /* the app's token */
            return SQL_NEED_DATA;
        }
    }

    /* Every data-at-execution parameter has its value; run the statement. */
    s->dae_active  = 0;
    s->dae_current = -1;
    SQLRETURN rc = exec_finish(s);
    for (int i = 0; i < s->num_params; i++)
        dae_reset(&s->params[i]);                  /* core copied the binds */
    return rc;
}

SQLRETURN SQL_API SQLPutData(SQLHSTMT StatementHandle, SQLPOINTER DataPtr,
                             SQLLEN StrLen_or_Ind)
{
    OdbcStmt *s = (OdbcStmt *)StatementHandle;
    if (s == NULL)
        return SQL_INVALID_HANDLE;
    seer_odbc_diag_clear(s);
    if (!s->dae_active || s->dae_current < 0 || s->dae_current >= s->num_params)
        return seer_odbc_diag(s, "HY010", 0, "SQLPutData out of sequence", SQL_ERROR);

    OdbcParam *p = &s->params[s->dae_current];
    if (StrLen_or_Ind == SQL_NULL_DATA) {
        p->dae_null = 1;
        return SQL_SUCCESS;
    }
    size_t n;
    if (StrLen_or_Ind == SQL_NTS)
        n = DataPtr ? strlen((const char *)DataPtr) : 0;
    else if (StrLen_or_Ind < 0)
        return seer_odbc_diag(s, "HY090", 0, "Invalid StrLen_or_Ind", SQL_ERROR);
    else
        n = (size_t)StrLen_or_Ind;
    if (n > 0 && DataPtr != NULL && dae_append(p, DataPtr, n) != 0)
        return seer_odbc_diag(s, "HY001", 0, "Out of memory", SQL_ERROR);
    return SQL_SUCCESS;
}

/* Cancel processing on a statement. Two cases for this synchronous driver:
 *   - In a data-at-execution (SQL_NEED_DATA) sequence: abort it, discarding the
 *     chunks accumulated so far, and leave the statement reusable.
 *   - Otherwise: send a best-effort break to interrupt a call blocked on the
 *     connection (e.g. a long statement running on another thread), which then
 *     returns ORA-01013. A no-op when nothing is in flight. */
SQLRETURN SQL_API SQLCancel(SQLHSTMT StatementHandle)
{
    OdbcStmt *s = (OdbcStmt *)StatementHandle;
    if (s == NULL)
        return SQL_INVALID_HANDLE;
    seer_odbc_diag_clear(s);
    if (s->dae_active) {
        for (int i = 0; i < s->num_params; i++)
            dae_reset(&s->params[i]);
        s->dae_active  = 0;
        s->dae_current = -1;
        return SQL_SUCCESS;
    }
    if (s->dbc != NULL && s->dbc->conn != NULL)
        seer_cancel(s->dbc->conn);
    return SQL_SUCCESS;
}

SQLRETURN SQL_API SQLBindParameter(SQLHSTMT     StatementHandle,
                                   SQLUSMALLINT ParameterNumber,
                                   SQLSMALLINT  InputOutputType,
                                   SQLSMALLINT  ValueType,
                                   SQLSMALLINT  ParameterType,
                                   SQLULEN      ColumnSize,
                                   SQLSMALLINT  DecimalDigits,
                                   SQLPOINTER   ParameterValuePtr,
                                   SQLLEN       BufferLength,
                                   SQLLEN      *StrLen_or_IndPtr)
{
    (void)DecimalDigits;
    OdbcStmt *s = (OdbcStmt *)StatementHandle;
    if (s == NULL)
        return SQL_INVALID_HANDLE;
    seer_odbc_diag_clear(s);
    if (ParameterNumber < 1 || ParameterNumber > 1024)
        return seer_odbc_diag(s, "07009", 0, "Invalid parameter number", SQL_ERROR);

    if (ParameterNumber > (SQLUSMALLINT)s->num_params) {
        OdbcParam *np = realloc(s->params, (size_t)ParameterNumber * sizeof *np);
        if (np == NULL)
            return seer_odbc_diag(s, "HY001", 0, "Out of memory", SQL_ERROR);
        for (int i = s->num_params; i < ParameterNumber; i++)
            np[i] = (OdbcParam){ 0 };
        s->params = np;
        s->num_params = ParameterNumber;
    }

    OdbcParam *p = &s->params[ParameterNumber - 1];
    p->io_type     = InputOutputType;
    p->c_type      = (ValueType == SQL_C_DEFAULT) ? SQL_C_CHAR : ValueType;
    p->sql_type    = ParameterType;
    p->column_size = ColumnSize;
    p->buf         = ParameterValuePtr;
    p->buflen      = BufferLength;
    p->indicator   = StrLen_or_IndPtr;
    p->bound       = 1;
    return SQL_SUCCESS;
}

SQLRETURN SQL_API SQLNumParams(SQLHSTMT StatementHandle, SQLSMALLINT *ParameterCountPtr)
{
    OdbcStmt *s = (OdbcStmt *)StatementHandle;
    if (s == NULL)
        return SQL_INVALID_HANDLE;
    seer_odbc_diag_clear(s);
    if (ParameterCountPtr != NULL) {
        /* The count of markers in the prepared statement (available before the
         * app binds); fall back to the bound count if not yet prepared. */
        int n = seer_sql_count_params(s->sql);
        *ParameterCountPtr = (SQLSMALLINT)(n > 0 ? n : s->num_params);
    }
    return SQL_SUCCESS;
}

SQLRETURN SQL_API SQLDescribeParam(SQLHSTMT     StatementHandle,
                                   SQLUSMALLINT ParameterNumber,
                                   SQLSMALLINT *DataTypePtr,
                                   SQLULEN     *ParameterSizePtr,
                                   SQLSMALLINT *DecimalDigitsPtr,
                                   SQLSMALLINT *NullablePtr)
{
    (void)ParameterNumber;
    OdbcStmt *s = (OdbcStmt *)StatementHandle;
    if (s == NULL)
        return SQL_INVALID_HANDLE;
    seer_odbc_diag_clear(s);
    /* The driver does not introspect parameter types (Oracle does not describe
     * placeholders before execute), so report the universal default: a
     * character type the app can bind anything to. */
    if (DataTypePtr != NULL)      *DataTypePtr = SQL_VARCHAR;
    if (ParameterSizePtr != NULL) *ParameterSizePtr = 4000;
    if (DecimalDigitsPtr != NULL) *DecimalDigitsPtr = 0;
    if (NullablePtr != NULL)      *NullablePtr = SQL_NULLABLE_UNKNOWN;
    return SQL_SUCCESS;
}

/* ----------------------------------------------- positioned update / delete */

void seer_odbc_free_updatable(OdbcStmt *s)
{
    if (s->rowids != NULL) {
        for (size_t i = 0; i < s->num_rowids; i++)
            free(s->rowids[i]);
        free(s->rowids);
        s->rowids = NULL;
    }
    s->num_rowids = 0;
    free(s->base_table);
    s->base_table = NULL;
}

/* Resolve the absolute result-set row range a SQLSetPos call targets: a single
 * row, or (row < 0) every row of the current rowset. */
static void pos_range(OdbcStmt *s, long row, long *first, long *last)
{
    if (row >= 0) {
        *first = *last = row;
    } else {
        long R = (long)(s->row_array_size ? s->row_array_size : 1);
        *first = s->rowset_start;
        *last  = s->rowset_start + R - 1;
    }
}

SQLRETURN seer_odbc_pos_delete(OdbcStmt *s, long row)
{
    long first, last;
    pos_range(s, row, &first, &last);
    for (long r = first; r <= last; r++) {
        if (r < 0 || (size_t)r >= s->num_rowids || s->rowids[r] == NULL)
            continue;
        char sql[256];
        snprintf(sql, sizeof sql, "DELETE FROM %s WHERE ROWID = :1", s->base_table);
        SeerStmt *dml = NULL;
        if (seer_stmt_prepare(s->dbc->conn, sql, &dml) != SEER_OK)
            return seer_odbc_diag(s, "HY000", 0, "prepare failed", SQL_ERROR);
        seer_stmt_bind_text(dml, 1, s->rowids[r], -1);
        SeerStatus st = seer_stmt_execute(dml);
        seer_stmt_close(dml);
        if (st != SEER_OK) {
            const char *ora = seer_last_error(s->dbc->conn);
            return seer_odbc_diag(s, seer_odbc_sqlstate(st), 0,
                                  ora ? ora : seer_strerror(st), SQL_ERROR);
        }
    }
    return SQL_SUCCESS;
}

SQLRETURN seer_odbc_pos_update(OdbcStmt *s, long row)
{
    long first, last;
    pos_range(s, row, &first, &last);
    for (long r = first; r <= last; r++) {
        if (r < 0 || (size_t)r >= s->num_rowids || s->rowids[r] == NULL)
            continue;
        long elem = r - s->rowset_start;        /* index within the bound rowset */
        if (elem < 0)
            continue;

        /* Build UPDATE <table> SET <bound col> = :k, ... WHERE ROWID = :last.
         * snprintf returns the length it WOULD have written, so an unchecked
         * "o += snprintf(...)" can push o past the buffer; the next
         * "sizeof sql - o" then underflows to a huge size_t and the following
         * write runs out of bounds. Guard every append and bail if the
         * statement (schema-derived table + column names) does not fit. */
        char sql[4096];
        int  o = snprintf(sql, sizeof sql, "UPDATE %s SET ", s->base_table);
        if (o < 0 || (size_t)o >= sizeof sql)
            return seer_odbc_diag(s, "HY000", 0, "Updatable cursor statement too long", SQL_ERROR);
        int  nset = 0;
        for (int i = 0; i < s->num_binds; i++) {
            if (!s->binds[i].bound)
                continue;
            const char *name = seer_stmt_col_name(s->core, i);
            if (name == NULL)
                continue;
            int n = snprintf(sql + o, sizeof sql - (size_t)o, "%s%s = :%d",
                             nset ? ", " : "", name, nset + 1);
            if (n < 0 || (size_t)n >= sizeof sql - (size_t)o)
                return seer_odbc_diag(s, "HY000", 0, "Updatable cursor statement too long", SQL_ERROR);
            o += n;
            nset++;
        }
        if (nset == 0)
            return seer_odbc_diag(s, "HY000", 0, "No columns bound for update", SQL_ERROR);
        int wn = snprintf(sql + o, sizeof sql - (size_t)o, " WHERE ROWID = :%d", nset + 1);
        if (wn < 0 || (size_t)wn >= sizeof sql - (size_t)o)
            return seer_odbc_diag(s, "HY000", 0, "Updatable cursor statement too long", SQL_ERROR);

        SeerStmt *dml = NULL;
        if (seer_stmt_prepare(s->dbc->conn, sql, &dml) != SEER_OK)
            return seer_odbc_diag(s, "HY000", 0, "prepare failed", SQL_ERROR);

        int k = 0;
        for (int i = 0; i < s->num_binds; i++) {
            OdbcBind *b = &s->binds[i];
            if (!b->bound || seer_stmt_col_name(s->core, i) == NULL)
                continue;
            void   *vp;
            SQLLEN  ind;
            if (s->row_bind_type == 0) {        /* column-wise */
                vp  = b->buf ? (char *)b->buf + (size_t)elem * ctype_stride(b->target_type, b->buflen) : NULL;
                ind = b->indicator ? b->indicator[elem] : SQL_NTS;
            } else {                            /* row-wise */
                vp  = b->buf ? (char *)b->buf + (size_t)elem * s->row_bind_type : NULL;
                ind = b->indicator ? *(SQLLEN *)((char *)b->indicator + (size_t)elem * s->row_bind_type) : SQL_NTS;
            }
            bind_one_value(dml, ++k, b->target_type, vp, ind);
        }
        seer_stmt_bind_text(dml, nset + 1, s->rowids[r], -1);

        SeerStatus st = seer_stmt_execute(dml);
        seer_stmt_close(dml);
        if (st != SEER_OK) {
            const char *ora = seer_last_error(s->dbc->conn);
            return seer_odbc_diag(s, seer_odbc_sqlstate(st), 0,
                                  ora ? ora : seer_strerror(st), SQL_ERROR);
        }
    }
    return SQL_SUCCESS;
}

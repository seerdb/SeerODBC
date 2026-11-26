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
#include "types.h" /* ORA_TYPE_* */
#include "sqlprep.h"

/* Map an ODBC SQL parameter type to the Oracle type for an OUT bind's OAC. */
static int ora_type_for_sql(SQLSMALLINT t)
{
  switch (t) {
  case SQL_INTEGER:
  case SQL_SMALLINT:
  case SQL_TINYINT:
  case SQL_BIGINT:
  case SQL_DECIMAL:
  case SQL_NUMERIC:
  case SQL_FLOAT:
  case SQL_REAL:
  case SQL_DOUBLE:
    return ORA_TYPE_NUMBER;
  case SQL_TYPE_TIMESTAMP:
  case SQL_TIMESTAMP:
  case SQL_TYPE_DATE:
  case SQL_DATE:
    return ORA_TYPE_DATE;
  case SQL_BINARY:
  case SQL_VARBINARY:
  case SQL_LONGVARBINARY:
    return ORA_TYPE_RAW;
  case SQL_REFCURSOR:
    return ORA_TYPE_REFCURSOR;
  case SQL_SEER_CLOB:
    return ORA_TYPE_CLOB; /* #214 */
  case SQL_SEER_BLOB:
    return ORA_TYPE_BLOB; /* #214 */
  case SQL_SEER_REF:
    return ORA_TYPE_REF; /* #241 */
  default:
    return ORA_TYPE_VARCHAR;
  }
}

/* Element stride for column-wise array binding: a fixed-length C type's own
 * width (SQL_C_NUMERIC and the interval structs too, #314), whatever
 * BufferLength says; a variable one's buffer length. */
static size_t ctype_stride(SQLSMALLINT c_type, SQLLEN buflen)
{
  size_t fixed = seer_odbc_c_fixed_size(c_type);
  if (fixed > 0)
    return fixed;
  return buflen > 0 ? (size_t)buflen : 1;
}

/* bind_one_value's flags. */
#define BIND_DATE_ONLY 0x01 /* no TIMESTAMP on the server (8i, #318) */
#define BIND_NATIONAL 0x02  /* national types in the national charset (#367) */
#define BIND_LOB 0x04       /* long types for a LOB target (8i, #424) */

/* Whether SQL type `t` is a number: character data bound as one is an ODBC
 * numeric literal, '.' the decimal point (#354). */
static bool sql_type_numeric(SQLSMALLINT t)
{
  switch (t) {
  case SQL_NUMERIC:
  case SQL_DECIMAL:
  case SQL_INTEGER:
  case SQL_SMALLINT:
  case SQL_BIGINT:
  case SQL_TINYINT:
  case SQL_FLOAT:
  case SQL_REAL:
  case SQL_DOUBLE:
    return true;
  default:
    return false;
  }
}

/* Character data `txt` for a parameter of SQL type `sql_type`: a numeric
 * literal for a numeric type goes as an exact NUMBER, whatever the session's
 * NLS_NUMERIC_CHARACTERS; anything else as text, for the server to convert
 * (or refuse, ORA-01722 / 22018) as before (#354). */
static SeerStatus bind_char_value(SeerStmt *core, int param, SQLSMALLINT sql_type, const char *txt,
                                  int len, unsigned flags)
{
  bool date_only = (flags & BIND_DATE_ONLY) != 0;
  size_t n = len < 0 ? strlen(txt) : (size_t)len;
  if (sql_type_numeric(sql_type)) {
    char plain[600];
    if (seer_odbc_numeric_literal(txt, n, plain, sizeof plain) > 0)
      return seer_stmt_bind_number_text(core, param, plain);
  }
  /* A datetime literal for a datetime type: the native value, not text the
   * server would read by NLS_DATE_FORMAT (DD-MON-RR by default) (#356). A
   * literal that doesn't fit the type goes as text, as before. */
  SeerOdbcDateTime t;
  if ((sql_type == SQL_TYPE_TIMESTAMP || sql_type == SQL_TIMESTAMP || sql_type == SQL_TYPE_DATE ||
       sql_type == SQL_DATE || sql_type == SQL_TYPE_TIME || sql_type == SQL_TIME) &&
      seer_odbc_datetime_literal(txt, n, &t) == 0) {
    if ((sql_type == SQL_TYPE_TIMESTAMP || sql_type == SQL_TIMESTAMP) && t.has_date)
      return date_only ? seer_stmt_bind_date(core, param, t.year, t.month, t.day, t.hour, t.minute,
                                             t.second) /* 8i: no TIMESTAMP (#318) */
                       : seer_stmt_bind_timestamp(core, param, t.year, t.month, t.day, t.hour,
                                                  t.minute, t.second, (uint32_t)t.nanos);
    if ((sql_type == SQL_TYPE_DATE || sql_type == SQL_DATE) && t.has_date && !t.has_time)
      return seer_stmt_bind_date(core, param, t.year, t.month, t.day, 0, 0, 0);
    if ((sql_type == SQL_TYPE_TIME || sql_type == SQL_TIME) && t.has_time && !t.has_date)
      return seer_stmt_bind_date(core, param, 1970, 1, 1, t.hour, t.minute, t.second);
  }
  /* A national type on a database whose charset can't hold every character:
   * the national charset, or an NVARCHAR2 loses what the database charset
   * lacks (#367). On a Unicode database the plain bind loses nothing, and an
   * NVARCHAR2 bind would make the server convert VARCHAR2 columns it meets
   * (no index). */
  /* A long type for a LOB target: 8.1.7 converts no text to a LOB parameter,
   * so there it goes as a temporary LOB (#424). */
  if ((flags & BIND_LOB) && (sql_type == SQL_LONGVARCHAR || sql_type == SQL_WLONGVARCHAR))
    return seer_stmt_bind_clob(core, param, txt, len);
  if ((flags & BIND_NATIONAL) &&
      (sql_type == SQL_WVARCHAR || sql_type == SQL_WCHAR || sql_type == SQL_WLONGVARCHAR))
    return seer_stmt_bind_ntext(core, param, txt, len);
  return seer_stmt_bind_text(core, param, txt, len);
}

/* Bind one parameter value (the value at `valptr`, length hint `ind`) into core
 * statement `core` at `param`, dispatching on the ODBC C type. `date_only`: the
 * server has no TIMESTAMP (8i, #318), so a timestamp goes out as a DATE. */
static SeerStatus bind_one_value(SeerStmt *core, int param, SQLSMALLINT c_type,
                                 SQLSMALLINT sql_type, const void *valptr, SQLLEN ind,
                                 unsigned flags)
{
  bool date_only = (flags & BIND_DATE_ONLY) != 0;
  /* A NULL still declares the parameter's SQL type (SQLBindParameter's
   * ParameterType), so the server types it as a NUMBER / DATE / RAW rather
   * than VARCHAR - which COALESCE / CASE need, and which keeps a NULL row from
   * re-typing an array-bound column. */
  if (ind == SQL_NULL_DATA || valptr == NULL)
    return sql_type != 0 ? seer_stmt_bind_null_typed(core, param, ora_type_for_sql(sql_type))
                         : seer_stmt_bind_null(core, param);

  switch (c_type) {
  case SQL_C_SLONG:
  case SQL_C_LONG:
    return seer_stmt_bind_int64(core, param, *(const SQLINTEGER *)valptr);
  case SQL_C_ULONG:
    return seer_stmt_bind_int64(core, param, (int64_t)*(const SQLUINTEGER *)valptr);
  case SQL_C_SSHORT:
  case SQL_C_SHORT:
    return seer_stmt_bind_int64(core, param, *(const SQLSMALLINT *)valptr);
  case SQL_C_USHORT:
    return seer_stmt_bind_int64(core, param, *(const SQLUSMALLINT *)valptr);
  case SQL_C_SBIGINT:
    return seer_stmt_bind_int64(core, param, (int64_t)*(const SQLBIGINT *)valptr);
  case SQL_C_UBIGINT: {
    SQLUBIGINT u = *(const SQLUBIGINT *)valptr;
    if (u <= (SQLUBIGINT)INT64_MAX)
      return seer_stmt_bind_int64(core, param, (int64_t)u);
    char dec[24]; /* past INT64_MAX: exact, as a decimal NUMBER */
    snprintf(dec, sizeof dec, "%llu", (unsigned long long)u);
    return seer_stmt_bind_number_text(core, param, dec);
  }
  case SQL_C_STINYINT:
  case SQL_C_TINYINT:
    return seer_stmt_bind_int64(core, param, *(const signed char *)valptr);
  case SQL_C_UTINYINT:
    return seer_stmt_bind_int64(core, param, *(const unsigned char *)valptr);
  case SQL_C_NUMERIC: {
    char dec[300];
    if (seer_odbc_numeric_to_text(valptr, dec, sizeof dec) == 0)
      return SEER_EPARAM;
    return seer_stmt_bind_number_text(core, param, dec);
  }
  case SQL_C_GUID: {
    char g[37];
    seer_odbc_guid_to_text(valptr, g);
    return seer_stmt_bind_text(core, param, g, 36);
  }
  case SQL_C_FLOAT:
    return seer_stmt_bind_float(core, param, *(const SQLREAL *)valptr);
  case SQL_C_DOUBLE:
    return seer_stmt_bind_double(core, param, *(const SQLDOUBLE *)valptr);
  case SQL_C_BIT:
    /* A boolean only for an SQL_BIT target (a BOOLEAN on 23ai+). Into
     * anything else a bit is the number 0 / 1 - "0" / "1" for a character
     * target, Appendix D - on every release, not 23ai's TRUE (#327). */
    if (sql_type == SQL_BIT || sql_type == 0)
      return seer_stmt_bind_bool(core, param, *(const unsigned char *)valptr != 0);
    return seer_stmt_bind_int64(core, param, *(const unsigned char *)valptr != 0);
  case SQL_C_BINARY:
    if ((flags & BIND_LOB) && sql_type == SQL_LONGVARBINARY) /* 8i: a LOB target (#424) */
      return seer_stmt_bind_blob(core, param, valptr, (ind >= 0) ? (int)ind : 0);
    return seer_stmt_bind_raw(core, param, valptr, (ind >= 0) ? (int)ind : 0);
  case SQL_C_TYPE_TIMESTAMP:
  case SQL_C_TIMESTAMP: {
    const SQL_TIMESTAMP_STRUCT *t = valptr;
    /* 8.1.7 has no TIMESTAMP; every column such a value goes to is a DATE,
     * which keeps the time to the second. The fraction is dropped, as 9i+
     * drop it storing a TIMESTAMP into a DATE (#318). */
    if (date_only)
      return seer_stmt_bind_date(core, param, t->year, t->month, t->day, t->hour, t->minute,
                                 t->second);
    /* `fraction` is nanoseconds (ODBC); a native TIMESTAMP bind keeps it
     * (bind_date would truncate to whole seconds). */
    return seer_stmt_bind_timestamp(core, param, t->year, t->month, t->day, t->hour, t->minute,
                                    t->second, t->fraction);
  }
  case SQL_C_TYPE_DATE:
  case SQL_C_DATE: {
    const SQL_DATE_STRUCT *t = valptr;
    return seer_stmt_bind_date(core, param, t->year, t->month, t->day, 0, 0, 0);
  }
  case SQL_C_TYPE_TIME:
  case SQL_C_TIME: {
    const SQL_TIME_STRUCT *t = valptr;
    return seer_stmt_bind_date(core, param, 1970, 1, 1, t->hour, t->minute, t->second);
  }
  case SQL_C_INTERVAL_YEAR:
  case SQL_C_INTERVAL_MONTH:
  case SQL_C_INTERVAL_YEAR_TO_MONTH:
  case SQL_C_INTERVAL_DAY:
  case SQL_C_INTERVAL_HOUR:
  case SQL_C_INTERVAL_MINUTE:
  case SQL_C_INTERVAL_SECOND:
  case SQL_C_INTERVAL_DAY_TO_HOUR:
  case SQL_C_INTERVAL_DAY_TO_MINUTE:
  case SQL_C_INTERVAL_DAY_TO_SECOND:
  case SQL_C_INTERVAL_HOUR_TO_MINUTE:
  case SQL_C_INTERVAL_HOUR_TO_SECOND:
  case SQL_C_INTERVAL_MINUTE_TO_SECOND: {
    /* Only the fields the type names, normalised (HOUR 30 = 1 day 6 hours),
     * and the fraction in microseconds as fetch delivers it (#322). */
    SeerOdbcInterval v;
    if (seer_odbc_interval_from_c(c_type, valptr, &v) != 0)
      return SEER_EPARAM;
    int32_t sgn = v.negative ? -1 : 1;
    if (v.year_month)
      return seer_stmt_bind_interval_ym(core, param, sgn * (int32_t)v.years,
                                        sgn * (int32_t)v.months);
    return seer_stmt_bind_interval_ds(core, param, sgn * (int32_t)v.days, sgn * v.hours,
                                      sgn * v.mins, sgn * v.secs, sgn * (int32_t)v.nanos);
  }
  case SQL_C_WCHAR: {
    size_t inbytes;
    if (ind == SQL_NTS) {
      const unsigned short *w = valptr;
      size_t n = 0;
      while (w[n] != 0)
        n++;
      inbytes = n * sizeof(unsigned short);
    } else {
      inbytes = (ind >= 0) ? (size_t)ind : 0;
    }
    char *u8 = NULL;
    size_t u8len = 0;
    if (seer_iconv(SEER_UTF16, "UTF-8", (const char *)valptr, inbytes, &u8, &u8len) != 0)
      return SEER_EPROTO;
    SeerStatus st = bind_char_value(core, param, sql_type, u8, (int)u8len, flags);
    free(u8);
    return st;
  }
  case SQL_C_CHAR:
  case SQL_C_DEFAULT:
    return bind_char_value(core, param, sql_type, (const char *)valptr,
                           (ind == SQL_NTS) ? -1 : (int)ind, flags);
  default:
    /* Not a C type this driver knows (SQLBindParameter refuses those with
     * HY003; a descriptor field can still set one). Never send its bytes as
     * text (#322). */
    return SEER_ENOTIMPL;
  }
}

/* Whether `t` is a C type a parameter can carry. */
static bool param_c_type_known(SQLSMALLINT t)
{
  return t == SQL_C_CHAR || t == SQL_C_WCHAR || t == SQL_C_BINARY || t == SQL_C_DEFAULT ||
         seer_odbc_c_fixed_size(t) != 0;
}

/* The SQLSTATE for a failed bind_one_value of C type `ct`: 07006 for a C type
 * with no conversion, 22003 / 22015 for a value past the server type's range,
 * else the core's status (#322). */
static const char *bind_sqlstate(SeerStatus st, SQLSMALLINT ct)
{
  if (!param_c_type_known(ct))
    return "07006";
  /* ... and character data for a numeric parameter past NUMBER's range
   * (#354) */
  if (st == SEER_EPARAM &&
      (ct == SQL_C_NUMERIC || ct == SQL_C_UBIGINT || ct == SQL_C_CHAR || ct == SQL_C_WCHAR))
    return "22003";
  /* SQL_C_INTERVAL_x is 100 + SQL_CODE_x, YEAR (1) to MINUTE_TO_SECOND (13). */
  if (st == SEER_EPARAM && ct >= SQL_C_INTERVAL_YEAR && ct <= SQL_C_INTERVAL_MINUTE_TO_SECOND)
    return "22015";
  return seer_odbc_sqlstate(st);
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
  p->dae_buf = NULL;
  p->dae_len = 0;
  p->dae_cap = 0;
  p->dae = 0;
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
/* A single parameter set's value and indicator, past the bind offset (#243). */
/* The parameter's C type, SQL_C_DEFAULT taken as its SQL type's default C
 * type (#316): a timestamp struct for SQL_TYPE_TIMESTAMP, the bytes for
 * SQL_VARBINARY, and text only where ODBC says so. */
static SQLSMALLINT param_c_type(const OdbcParam *p)
{
  return p->c_type == SQL_C_DEFAULT ? seer_odbc_default_c_type(p->sql_type) : p->c_type;
}

/* The server has no TIMESTAMP type: Oracle 8i (#318). 8i binds national
 * types in CHAR form, but in NCHAR form when the server refused that (#419). */
static unsigned bind_flags(const OdbcStmt *s)
{
  if (s->dbc == NULL)
    return 0;
  if (seer_odbc_server_major(s->dbc) == 8)
    return BIND_DATE_ONLY | (s->bind_national ? BIND_NATIONAL : 0) |
           (s->bind_as_lob ? BIND_LOB : 0);
  return s->dbc->conn != NULL && !seer_db_charset_unicode(s->dbc->conn) ? BIND_NATIONAL : 0;
}

/* The parameter set a single-row execute reads: the first, or for a query
 * run one set per result set, the current one (#431). */
static SQLULEN param_row(const OdbcStmt *s)
{
  return s->pas_query && s->pas_k < s->n_param_rows ? s->param_rows[s->pas_k] : 0;
}

static void *param_buf(const OdbcStmt *s, const OdbcParam *p)
{
  return seer_odbc_bound_at(p->buf, s->param_bind_offset, s->param_bind_type,
                            ctype_stride(param_c_type(p), p->buflen), param_row(s));
}

static SQLLEN *param_ind(const OdbcStmt *s, const OdbcParam *p)
{
  return seer_odbc_bound_at(p->indicator, s->param_bind_offset, s->param_bind_type, sizeof(SQLLEN),
                            param_row(s));
}

/* A SQL_SEER_REF parameter (#241): the REF's bytes IN, or a REF OUT, the type
 * it refers to named "SCHEMA.TYPE" in its IPD record (SQL_DESC_SEER_REF_TYPE). */
static SQLRETURN bind_ref_param(OdbcStmt *s, const OdbcParam *p, int param)
{
  const char *dot = p->ref_type != NULL ? strchr(p->ref_type, '.') : NULL;
  if (dot == NULL || dot == p->ref_type || dot[1] == '\0')
    return seer_odbc_diag(s, "HY000", 0,
                          "A SQL_SEER_REF parameter needs its type, \"SCHEMA.TYPE\", in the IPD "
                          "field SQL_DESC_SEER_REF_TYPE",
                          SQL_ERROR);
  char schema[129];
  size_t sl = (size_t)(dot - p->ref_type);
  if (sl >= sizeof schema)
    return seer_odbc_diag(s, "HY000", 0, "The REF parameter's schema name is too long", SQL_ERROR);
  memcpy(schema, p->ref_type, sl);
  schema[sl] = '\0';
  SeerStatus st;
  if (p->io_type == SQL_PARAM_OUTPUT) {
    st = seer_stmt_bind_ref_out(s->core, param, schema, dot + 1);
  } else if (p->io_type == SQL_PARAM_INPUT) {
    const SQLLEN *indp = param_ind(s, p);
    const void *v = param_buf(s, p);
    if (v == NULL || indp == NULL || *indp == SQL_NULL_DATA || *indp <= 0)
      return seer_odbc_diag(s, "HY000", 0,
                            "A NULL REF can't be bound (8i and 9i answer ORA-00600 for one); give "
                            "the REF's bytes and their length",
                            SQL_ERROR);
    st = seer_stmt_bind_ref(s->core, param, schema, dot + 1, v, (size_t)*indp);
  } else {
    return seer_odbc_diag(s, "HYC00", 0, "An IN OUT REF parameter is not supported", SQL_ERROR);
  }
  if (st == SEER_OK)
    return SQL_SUCCESS;
  if (st == SEER_EDB) /* the type's lookup failed on the server */
    return seer_odbc_exec_error(s, st);
  return seer_odbc_diag(s, seer_odbc_sqlstate(st), 0,
                        st == SEER_ENOTIMPL ? "REF parameters of this direction are not supported "
                                              "on this server release"
                                            : "REF parameter bind failed",
                        SQL_ERROR);
}

static SQLRETURN apply_params(OdbcStmt *s)
{
  SQLULEN n = s->paramset_size ? s->paramset_size : 1;

  /* The parameter sets to run, by their row: all of them, less those
   * SQL_ATTR_PARAM_OPERATION_PTR marks SQL_PARAM_IGNORE (#243). Executed,
   * an ignored set was inserted or updated like any other. */
  free(s->param_rows);
  s->param_rows = malloc((size_t)n * sizeof *s->param_rows);
  if (s->param_rows == NULL)
    return seer_odbc_diag(s, "HY001", 0, "Out of memory", SQL_ERROR);
  s->n_param_rows = 0;
  for (SQLULEN row = 0; row < n; row++)
    if (s->param_operation == NULL || s->param_operation[row] != SQL_PARAM_IGNORE)
      s->param_rows[s->n_param_rows++] = row;

  /* A query runs its sets one at a time, each a single-row execute (#431). */
  if (n > 1 && !s->pas_query) {
    for (int i = 0; i < s->num_params; i++)
      if (s->params[i].bound && s->params[i].sql_type == SQL_SEER_REF)
        return seer_odbc_diag(s, "HYC00", 0,
                              "A REF parameter in a parameter array is not supported", SQL_ERROR);
    SQLULEN run = s->n_param_rows;
    SeerStatus st = seer_stmt_set_array_size(s->core, (int)(run > 0 ? run : 1));
    if (st != SEER_OK)
      return seer_odbc_diag(s, seer_odbc_sqlstate(st), 0, "array bind setup failed", SQL_ERROR);
    /* Array DML reports per-row status (SQL_ATTR_PARAM_STATUS_PTR), so run
     * in batcherrors mode: a bad row doesn't abort the batch - the good
     * rows apply and each failure surfaces as a row status + diag record. */
    seer_stmt_set_batch_errors(s->core, 1);
    /* If the app armed SQL_ATTR_SEER_DML_ROW_COUNTS, request 12c+ per-row
     * counts so we can fill its buffer after execute. */
    if (s->dml_row_counts != NULL)
      seer_stmt_set_array_dml_rowcounts(s->core, 1);
    for (SQLULEN k = 0; k < run; k++) {
      SQLULEN row = s->param_rows[k];
      seer_stmt_bind_row(s->core, (int)k);
      for (int i = 0; i < s->num_params; i++) {
        OdbcParam *p = &s->params[i];
        int param = i + 1;
        if (!p->bound || p->buf == NULL || p->io_type == SQL_PARAM_OUTPUT) {
          seer_stmt_bind_null(s->core, param);
          continue;
        }
        /* Row-wise (SQL_ATTR_PARAM_BIND_TYPE the struct size) or by column,
         * past the bind offset. Read by column whatever the attribute, a
         * row-wise set came from the next field and ran past the array. */
        const void *val = seer_odbc_bound_at(p->buf, s->param_bind_offset, s->param_bind_type,
                                             ctype_stride(param_c_type(p), p->buflen), row);
        const SQLLEN *indp = seer_odbc_bound_at(p->indicator, s->param_bind_offset,
                                                s->param_bind_type, sizeof(SQLLEN), row);
        SQLLEN ind = indp ? *indp : SQL_NTS;
        st = bind_one_value(s->core, param, param_c_type(p), p->sql_type, val, ind, bind_flags(s));
        if (st != SEER_OK)
          return seer_odbc_diag(s, bind_sqlstate(st, param_c_type(p)), 0, "Parameter bind failed",
                                SQL_ERROR);
      }
    }
    return SQL_SUCCESS;
  }

  for (int i = 0; i < s->num_params; i++) {
    OdbcParam *p = &s->params[i];
    int param = i + 1;

    if (p->bound && p->sql_type == SQL_SEER_REF) {
      SQLRETURN r = bind_ref_param(s, p, param);
      if (r != SQL_SUCCESS)
        return r;
      continue;
    }
    if (p->dae) { /* value streamed in via SQLPutData */
      if (p->dae_null)
        seer_stmt_bind_null_typed(s->core, param, ora_type_for_sql(p->sql_type));
      else if (p->dae_len < seer_odbc_c_fixed_size(param_c_type(p))) {
        /* No SQLPutData for a fixed-size value: nothing to read (#323). */
        return seer_odbc_diag(s, "HY000", 0, "No data was put for a data-at-execution parameter",
                              SQL_ERROR);
      } else {
        SeerStatus st =
            bind_one_value(s->core, param, param_c_type(p), p->sql_type,
                           p->dae_buf ? p->dae_buf : "", (SQLLEN)p->dae_len, bind_flags(s));
        if (st != SEER_OK)
          return seer_odbc_diag(s, bind_sqlstate(st, param_c_type(p)), 0, "Parameter bind failed",
                                SQL_ERROR);
      }
      continue;
    }
    if (p->bound && (p->io_type == SQL_PARAM_OUTPUT || p->io_type == SQL_PARAM_INPUT_OUTPUT)) {
      int sz = (p->column_size > 0) ? (int)p->column_size : (int)p->buflen;
      /* IN OUT: send the application's value in, then mark it OUT (binding it
       * as a pure OUT sent a NULL, so the procedure never saw the input). */
      if (p->io_type == SQL_PARAM_INPUT_OUTPUT && p->sql_type != SQL_REFCURSOR) {
        const SQLLEN *indp = param_ind(s, p);
        SQLLEN ind = indp ? *indp : SQL_NTS;
        SeerStatus st = bind_one_value(s->core, param, param_c_type(p), p->sql_type,
                                       param_buf(s, p), ind, bind_flags(s));
        if (st == SEER_OK)
          st = seer_stmt_bind_set_inout(s->core, param, sz);
        if (st != SEER_OK)
          return seer_odbc_diag(s, bind_sqlstate(st, param_c_type(p)), 0, "Parameter bind failed",
                                SQL_ERROR);
        continue;
      }
      seer_stmt_bind_out(s->core, param, ora_type_for_sql(p->sql_type), sz);
      continue;
    }
    if (!p->bound) {
      seer_stmt_bind_null(s->core, param);
      continue;
    }
    const SQLLEN *indp = param_ind(s, p);
    SQLLEN ind = indp ? *indp : SQL_NTS;
    SeerStatus st = bind_one_value(s->core, param, param_c_type(p), p->sql_type, param_buf(s, p),
                                   ind, bind_flags(s));
    if (st != SEER_OK)
      return seer_odbc_diag(s, bind_sqlstate(st, param_c_type(p)), 0, "Parameter bind failed",
                            SQL_ERROR);
  }
  return SQL_SUCCESS;
}

/* Run a driver-generated query (the catalog functions use this): prepare,
 * bind the given text parameters positionally, execute, and size the result
 * binding array. */
SQLRETURN seer_odbc_run_query(OdbcStmt *s, const char *sql, const char *const *params, int nparams)
{
  s->pas_query = 0; /* one result set, whatever SQL_ATTR_PARAMSET_SIZE says */
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

  seer_odbc_arm_timeout(s);
  st = seer_stmt_execute(s->core);
  if (st != SEER_OK)
    return seer_odbc_exec_error(s, st);

  int ncols = seer_stmt_num_cols(s->core);
  /* The result's columns; the bindings made stay, before the execute too
   * (#244). Freed and made anew here, every execute unbound them all. */
  if (seer_odbc_ensure_binds(s, ncols) != 0)
    return seer_odbc_diag(s, "HY001", 0, "Out of memory", SQL_ERROR);
  s->getdata_col = -1;
  s->getdata_off = 0;
  s->getdata_done = 0;
  s->rowset_start = -1;
  s->cur_row = -1;
  return SQL_SUCCESS;
}

/* Prepare the statement text: NUL-terminate, then run the SQL preprocessor
 * (escape expansion + '?' marker rewrite, see sqlprep.c). NULL with the
 * diagnostic posted, `*rc` its return. */
static char *dup_sql(OdbcStmt *s, SQLCHAR *text, SQLINTEGER len, SQLRETURN *rc)
{
  size_t n = (len == SQL_NTS) ? strlen((const char *)text) : (size_t)len;
  char *raw = malloc(n + 1);
  const char *err = NULL;
  char *out = NULL;
  if (raw != NULL) {
    memcpy(raw, text, n);
    raw[n] = '\0';
    /* With SQL_ATTR_NOSCAN on, the escapes go as written (#248). */
    out =
        seer_sql_prepare_for(raw, s->noscan != SQL_NOSCAN_ON, seer_odbc_server_major(s->dbc), &err);
    free(raw);
  }
  if (out == NULL)
    *rc = err != NULL ? seer_odbc_diag(s, "HYC00", 0, err, SQL_ERROR)
                      : seer_odbc_diag(s, "HY001", 0, "Out of memory", SQL_ERROR);
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
    rewritten = seer_sql_make_updatable(sql, &tbl, s->concurrency == SQL_CONCUR_LOCK);
    if (rewritten != NULL) {
      sql = rewritten;
      s->base_table = tbl;
      s->updatable = 1;
    }
  }
  if (s->core != NULL) { /* drop any prior result set */
    seer_stmt_close(s->core);
    s->core = NULL;
  }

  SeerStatus st = seer_stmt_prepare(s->dbc->conn, sql, &s->core);
  if (st != SEER_OK) {
    free(rewritten); /* sql may alias it, but nothing reads sql now */
    return seer_odbc_diag(s, seer_odbc_sqlstate(st), 0, seer_strerror(st), SQL_ERROR);
  }

  /* A query with a parameter array runs one set per result set
   * (SQL_PAS_BATCH, #431): the first now, each next on SQLMoreResults, by
   * the SQL as sent here. */
  free(s->pas_sql);
  s->pas_sql = NULL;
  s->pas_k = 0;
  s->pas_query = (s->paramset_size ? s->paramset_size : 1) > 1 && seer_stmt_is_query(s->core);
  if (s->pas_query && (s->pas_sql = strdup(sql)) == NULL) {
    s->pas_query = 0;
    free(rewritten);
    return seer_odbc_diag(s, "HY001", 0, "Out of memory", SQL_ERROR);
  }

  /* Data-at-execution: if any single-row INPUT parameter was bound with
   * SQL_DATA_AT_EXEC, defer the execute - return SQL_NEED_DATA and let
   * SQLParamData/SQLPutData stream the values, then run it (#dae). */
  s->dae_active = 0;
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
      if (i < nmarkers && p->bound && param_ind(s, p) != NULL &&
          (p->io_type == SQL_PARAM_INPUT || p->io_type == SQL_PARAM_INPUT_OUTPUT) &&
          is_data_at_exec(*param_ind(s, p))) {
        p->dae = 1;
        has_dae = 1;
      }
    }
  }
  /* seer_stmt_prepare copied the SQL, and the last read of `sql` (which may
   * alias rewritten) was seer_sql_count_params above - so the rewritten
   * buffer is safe to free here, covering both remaining exit paths. */
  free(rewritten);
  if (has_dae) {
    s->dae_active = 1;
    s->dae_current = -1;
    return SQL_NEED_DATA;
  }
  return exec_finish(s);
}

/* Whether an execute on 8i failed only because a text parameter's form
 * didn't match its target (ORA-12704, character set mismatch) and a national
 * type (SQL_WCHAR / SQL_WVARCHAR / SQL_WLONGVARCHAR) is among the parameters:
 * 8.1.7 won't mix CHAR and NCHAR, either way (#419). The error is the parse's,
 * so nothing ran - for an array, which 8i runs a row at a time, every row
 * failed with it. */
static bool nchar_mismatch(OdbcStmt *s, SeerStatus st)
{
  if (s->bind_national || seer_odbc_server_major(s->dbc) != 8)
    return false;
  bool national = false;
  for (int i = 0; i < s->num_params; i++) {
    SQLSMALLINT t = s->params[i].sql_type;
    national |=
        s->params[i].bound && (t == SQL_WCHAR || t == SQL_WVARCHAR || t == SQL_WLONGVARCHAR);
  }
  if (!national)
    return false;
  if (st == SEER_EDB) {
    const char *e = seer_last_error(s->dbc->conn);
    return e != NULL && strncmp(e, "ORA-12704", 9) == 0;
  }
  size_t nbe = st == SEER_OK ? seer_stmt_batch_error_count(s->core) : 0;
  if (nbe == 0 || nbe != s->n_param_rows)
    return false;
  for (size_t i = 0; i < nbe; i++) {
    unsigned row = 0, code = 0;
    const char *msg = NULL;
    seer_stmt_batch_error(s->core, i, &row, &code, &msg);
    if (code != 12704)
      return false;
  }
  return true;
}

/* Whether a PL/SQL block on 8i failed only because a long type went to a
 * LOB parameter as text / RAW (PLS-00306, wrong types of arguments), which
 * 8.1.7 doesn't convert, and a SQL_LONGVARCHAR / SQL_WLONGVARCHAR /
 * SQL_LONGVARBINARY parameter is bound: they go once more as LOBs (#424).
 * The error is the block's compile, so nothing ran. */
static bool lob_mismatch(OdbcStmt *s, SeerStatus st)
{
  if (s->bind_as_lob || st != SEER_EDB || seer_odbc_server_major(s->dbc) != 8)
    return false;
  const char *e = seer_last_error(s->dbc->conn);
  if (e == NULL || strstr(e, "PLS-00306") == NULL)
    return false;
  for (int i = 0; i < s->num_params; i++) {
    SQLSMALLINT t = s->params[i].sql_type;
    if (s->params[i].bound && s->params[i].io_type == SQL_PARAM_INPUT &&
        (t == SQL_LONGVARCHAR || t == SQL_WLONGVARCHAR || t == SQL_LONGVARBINARY))
      return true;
  }
  return false;
}

/* A query's parameter sets run one at a time, one result set each (#431):
 * the status of set pas_k, the sets processed so far, and on the first set
 * every other set SQL_PARAM_UNUSED (ignored, or not run yet). */
static void pas_status(OdbcStmt *s, SQLUSMALLINT status)
{
  if (!s->pas_query || s->pas_k >= s->n_param_rows)
    return;
  SQLULEN n = s->paramset_size ? s->paramset_size : 1;
  if (s->params_processed != NULL)
    *s->params_processed = s->pas_k + 1;
  if (s->param_status == NULL)
    return;
  if (s->pas_k == 0)
    for (SQLULEN r = 0; r < n; r++)
      s->param_status[r] = SQL_PARAM_UNUSED;
  s->param_status[s->param_rows[s->pas_k]] = status;
}

static SQLRETURN exec_finish(OdbcStmt *s)
{
  SQLRETURN pr = apply_params(s);
  if (pr != SQL_SUCCESS) {
    pas_status(s, SQL_PARAM_ERROR);
    s->pas_query = 0;
    return pr;
  }

  if (s->n_param_rows == 0) { /* every set marked SQL_PARAM_IGNORE: nothing runs */
    s->pas_query = 0;
    SQLULEN n = s->paramset_size ? s->paramset_size : 1;
    if (s->params_processed != NULL)
      *s->params_processed = 0;
    for (SQLULEN r = 0; s->param_status != NULL && r < n; r++)
      s->param_status[r] = SQL_PARAM_UNUSED;
    return SQL_SUCCESS;
  }
  seer_odbc_arm_timeout(s);
  seer_stmt_set_max_rows(s->core, (size_t)s->max_rows);
  SeerStatus st = seer_stmt_execute(s->core);
  /* 8i: once more after a mismatch 8.1.7 doesn't convert - the national
   * types in NCHAR form (#419), the long types as LOBs (#424) - each once. */
  for (;;) {
    if (nchar_mismatch(s, st))
      s->bind_national = 1;
    else if (lob_mismatch(s, st))
      s->bind_as_lob = 1;
    else
      break;
    pr = apply_params(s);
    if (pr != SQL_SUCCESS)
      break;
    seer_odbc_arm_timeout(s);
    st = seer_stmt_execute(s->core);
  }
  s->bind_national = 0;
  s->bind_as_lob = 0;
  if (pr != SQL_SUCCESS || st != SEER_OK) {
    /* A query's set that failed is SQL_PARAM_ERROR, and the sets after it
     * don't run (#431). */
    pas_status(s, SQL_PARAM_ERROR);
    s->pas_query = 0;
    return pr != SQL_SUCCESS ? pr : seer_odbc_exec_error(s, st);
  }
  /* Created, but compiled with errors: success with a warning, as Oracle's own
   * clients report it (ORA-24344). */
  bool compile_warning = seer_stmt_compile_warning(s->core);

  /* Array-bind status: every set was attempted (batcherrors mode). Mark all
   * rows SUCCESS, then flip the failed ones to SQL_PARAM_ERROR and post one
   * diag record per failure (carrying its 1-based SQL_DIAG_ROW_NUMBER). */
  SQLRETURN result = compile_warning ? seer_odbc_diag(s, "01000", 24344,
                                                      "ORA-24344: success with compilation error",
                                                      SQL_SUCCESS_WITH_INFO)
                                     : SQL_SUCCESS;
  if (s->pas_query) {
    pas_status(s, SQL_PARAM_SUCCESS);
  } else {
    SQLULEN n = s->paramset_size ? s->paramset_size : 1;
    SQLULEN run = s->n_param_rows;
    if (s->params_processed != NULL)
      *s->params_processed = run;
    /* An ignored set is SQL_PARAM_UNUSED; the core's set k is the
     * application's row param_rows[k] (#243). */
    if (s->param_status != NULL)
      for (SQLULEN r = 0; r < n; r++)
        s->param_status[r] = SQL_PARAM_UNUSED;
    if (s->param_status != NULL)
      for (SQLULEN k = 0; k < run; k++)
        s->param_status[s->param_rows[k]] = SQL_PARAM_SUCCESS;

    size_t nbe = seer_stmt_batch_error_count(s->core);
    for (size_t i = 0; i < nbe; i++) {
      unsigned brow = 0, bcode = 0;
      const char *bmsg = NULL;
      seer_stmt_batch_error(s->core, i, &brow, &bcode, &bmsg);
      SQLULEN row = brow < run ? s->param_rows[brow] : brow;
      if (s->param_status != NULL && row < n)
        s->param_status[row] = SQL_PARAM_ERROR;
      seer_odbc_diag_add(s, "HY000", (SQLINTEGER)bcode, bmsg ? bmsg : "array DML row error",
                         (SQLLEN)row + 1);
    }
    if (nbe > 0)
      result = (nbe >= (size_t)run) ? SQL_ERROR : SQL_SUCCESS_WITH_INFO;

    /* Fill the app's SQL_ATTR_SEER_DML_ROW_COUNTS buffer with the per-
     * iteration affected-row counts (12c+); 0 where none were reported. */
    if (s->dml_row_counts != NULL) {
      size_t nc = seer_stmt_array_dml_rowcount_count(s->core);
      for (SQLULEN r = 0; r < n; r++)
        s->dml_row_counts[r] = 0;
      for (SQLULEN k = 0; k < run && k < nc; k++)
        s->dml_row_counts[s->param_rows[k]] = (SQLLEN)seer_stmt_array_dml_rowcount(s->core, k);
    }
  }

  /* Write OUT / IN OUT parameter values back into the app's buffers. */
  for (int i = 0; i < s->num_params; i++) {
    OdbcParam *p = &s->params[i];
    if (!p->bound || (p->io_type != SQL_PARAM_OUTPUT && p->io_type != SQL_PARAM_INPUT_OUTPUT))
      continue;
    if (p->sql_type == SQL_REFCURSOR) /* its value is the result set */
      continue;
    const void *data = NULL;
    size_t dlen = 0;
    int is_null = 0, is_binary = 0;
    if (seer_stmt_out_data(s->core, i + 1, &data, &dlen, &is_null, &is_binary) != SEER_OK)
      continue;
    const char *cstate = NULL;
    SQLRETURN crc =
        seer_odbc_convert(data ? data : "", dlen, is_null, is_binary, param_c_type(p),
                          param_buf(s, p), p->buflen, param_ind(s, p), NULL, &cstate, p->sql_type);
    /* A value that won't convert to the parameter's C type (#314). */
    if (crc == SQL_ERROR) {
      result = seer_odbc_diag(s, cstate ? cstate : "HY000", 0, seer_odbc_convert_text(cstate),
                              SQL_ERROR);
      continue;
    }
    if (crc == SQL_SUCCESS_WITH_INFO && cstate != NULL && strcmp(cstate, "01S07") == 0) {
      result = seer_odbc_diag(s, cstate, 0, seer_odbc_convert_text(cstate),
                              result == SQL_SUCCESS ? SQL_SUCCESS_WITH_INFO : result);
      continue;
    }
    /* Truncated either way - by the server to the declared ColumnSize (a
     * RETURNING value), or into the application's buffer - is 01004, with
     * the full length in the indicator where the server told us it. */
    long full = seer_stmt_out_truncated(s->core, i + 1);
    if (full > 0 && param_ind(s, p) != NULL)
      *param_ind(s, p) = (SQLLEN)full;
    if (full > 0 || crc == SQL_SUCCESS_WITH_INFO)
      result = seer_odbc_diag(s, "01004", 0, "String data, right truncated",
                              result == SQL_SUCCESS ? SQL_SUCCESS_WITH_INFO : result);
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
          const void *d = NULL;
          size_t l = 0;
          int isn = 1, isb = 0;
          if (seer_stmt_set_row(s->core, r) == SEER_OK)
            seer_stmt_get_data(s->core, s->rowid_col, &d, &l, &isn, &isb);
          s->rowids[r] = (d != NULL && !isn) ? seer_strndup((const char *)d, l) : NULL;
        }
      }
    }
    ncols -= 1; /* hide ROWID from the binding array */
  }

  /* The result's columns; the bindings made stay, before the execute too
   * (#244). Freed and made anew here, every execute unbound them all. */
  if (seer_odbc_ensure_binds(s, ncols) != 0)
    return seer_odbc_diag(s, "HY001", 0, "Out of memory", SQL_ERROR);
  s->getdata_col = -1;
  s->getdata_off = 0;
  s->getdata_done = 0;
  s->rowset_start = -1;
  s->cur_row = -1;
  return result;
}

SQLRETURN seer_odbc_next_param_set(OdbcStmt *s)
{
  if (!s->pas_query || s->pas_sql == NULL || s->core == NULL || s->pas_k + 1 >= s->n_param_rows) {
    s->pas_query = 0;
    return SQL_NO_DATA;
  }
  s->pas_k++;
  /* The last set's ROWIDs go; an updatable cursor's base table stays. */
  if (s->rowids != NULL) {
    for (size_t i = 0; i < s->num_rowids; i++)
      free(s->rowids[i]);
    free(s->rowids);
    s->rowids = NULL;
  }
  s->num_rowids = 0;
  seer_stmt_close(s->core); /* the cached cursor is re-used, no re-parse */
  s->core = NULL;
  SeerStatus st = seer_stmt_prepare(s->dbc->conn, s->pas_sql, &s->core);
  if (st != SEER_OK) {
    pas_status(s, SQL_PARAM_ERROR);
    s->pas_query = 0;
    return seer_odbc_diag(s, seer_odbc_sqlstate(st), 0, seer_strerror(st), SQL_ERROR);
  }
  return exec_finish(s);
}

/* ------------------------------------------------------ cursor names (#288) */

static OdbcStmt *stmt_by_cursor(OdbcDbc *c, const char *name)
{
  for (OdbcStmt *t = c->stmts; t != NULL; t = t->next_stmt)
    if (t->cursor_name != NULL && strcasecmp(t->cursor_name, name) == 0)
      return t;
  return NULL;
}

/* A positioned UPDATE or DELETE, `... WHERE CURRENT OF name`. Oracle has
 * that only in PL/SQL, for a PL/SQL cursor, so it is rewritten here to the
 * ROWID of the named cursor's current row, which an updatable cursor keeps
 * for every row as SQLSetPos uses it. *out is the rewritten text (caller
 * frees), or NULL when the statement isn't positioned. */
static SQLRETURN current_of(OdbcStmt *s, const char *sql, char **out)
{
  *out = NULL;
  size_t a = 0, b = 0;
  char name[136], msg[300];
  if (!seer_sql_current_of(sql, &a, &b, name, sizeof name))
    return SQL_SUCCESS;
  OdbcStmt *c = stmt_by_cursor(s->dbc, name);
  if (c == NULL) {
    snprintf(msg, sizeof msg, "Invalid cursor name: no statement has cursor %s", name);
    return seer_odbc_diag(s, "34000", 0, msg, SQL_ERROR);
  }
  if (c == s) {
    snprintf(msg, sizeof msg,
             "Invalid cursor state: cursor %s is this statement's own; position it on another "
             "statement",
             name);
    return seer_odbc_diag(s, "24000", 0, msg, SQL_ERROR);
  }
  if (!c->updatable) {
    snprintf(msg, sizeof msg,
             "Invalid cursor state: cursor %s is read-only (set SQL_ATTR_CONCURRENCY and use a "
             "single-table SELECT)",
             name);
    return seer_odbc_diag(s, "24000", 0, msg, SQL_ERROR);
  }
  const char *rid = c->cur_row >= 0 && (size_t)c->cur_row < c->num_rowids && c->rowids != NULL
                        ? c->rowids[c->cur_row]
                        : NULL;
  if (rid == NULL || strchr(rid, '\'') != NULL) {
    snprintf(msg, sizeof msg, "Invalid cursor state: cursor %s is not positioned on a row", name);
    return seer_odbc_diag(s, "24000", 0, msg, SQL_ERROR);
  }
  size_t n = a + strlen(rid) + strlen(sql + b) + 16;
  char *r = malloc(n);
  if (r == NULL)
    return seer_odbc_diag(s, "HY001", 0, "Out of memory", SQL_ERROR);
  snprintf(r, n, "%.*sROWID = '%s'%s", (int)a, sql, rid, sql + b);
  *out = r;
  return SQL_SUCCESS;
}

/* Execute statement text: a positioned one rewritten first. The core keeps
 * its own copy of the text, so the rewrite is freed straight after. */
static SQLRETURN load_explicit_apd(OdbcStmt *s);

static SQLRETURN exec_text(OdbcStmt *s, const char *sql)
{
  if (s->apd_ext != NULL) {
    SQLRETURN lr = load_explicit_apd(s);
    if (lr != SQL_SUCCESS)
      return lr;
  }
  char *pos = NULL;
  SQLRETURN r = current_of(s, sql, &pos);
  if (r != SQL_SUCCESS)
    return r;
  r = exec_core(s, pos != NULL ? pos : sql);
  free(pos);
  return r;
}

SQLRETURN SQL_API SQLSetCursorName(SQLHSTMT StatementHandle, SQLCHAR *CursorName,
                                   SQLSMALLINT NameLength)
{
  OdbcStmt *s = (OdbcStmt *)StatementHandle;
  if (s == NULL)
    return SQL_INVALID_HANDLE;
  seer_odbc_diag_clear(s);
  if (CursorName == NULL)
    return seer_odbc_diag(s, "HY009", 0, "Invalid use of null pointer", SQL_ERROR);
  if (NameLength < 0 && NameLength != SQL_NTS)
    return seer_odbc_diag(s, "HY090", 0, "Invalid string or buffer length", SQL_ERROR);
  size_t n = NameLength == SQL_NTS ? strlen((const char *)CursorName) : (size_t)NameLength;
  if (s->core != NULL && seer_stmt_num_cols(s->core) > 0)
    return seer_odbc_diag(s, "24000", 0, "Invalid cursor state: the cursor is open", SQL_ERROR);
  /* An identifier of at most SQL_MAX_CURSOR_NAME_LEN characters, not in the
   * SQL_CUR / SQLCUR namespace the driver generates names in. */
  int ok = n > 0 && n <= SEER_MAX_CURSOR_NAME_LEN && isalpha(CursorName[0]) &&
           strncasecmp((const char *)CursorName, "SQL_CUR", 7) != 0 &&
           strncasecmp((const char *)CursorName, "SQLCUR", 6) != 0;
  for (size_t i = 0; ok && i < n; i++)
    ok = isalnum(CursorName[i]) || CursorName[i] == '_' || CursorName[i] == '$' ||
         CursorName[i] == '#';
  if (!ok)
    return seer_odbc_diag(s, "34000", 0, "Invalid cursor name", SQL_ERROR);
  char *name = seer_strndup((const char *)CursorName, n);
  if (name == NULL)
    return seer_odbc_diag(s, "HY001", 0, "Out of memory", SQL_ERROR);
  OdbcStmt *other = stmt_by_cursor(s->dbc, name);
  if (other != NULL && other != s) {
    free(name);
    return seer_odbc_diag(s, "3C000", 0, "Duplicate cursor name", SQL_ERROR);
  }
  free(s->cursor_name);
  s->cursor_name = name;
  return SQL_SUCCESS;
}

SQLRETURN SQL_API SQLGetCursorName(SQLHSTMT StatementHandle, SQLCHAR *CursorName,
                                   SQLSMALLINT BufferLength, SQLSMALLINT *NameLengthPtr)
{
  OdbcStmt *s = (OdbcStmt *)StatementHandle;
  if (s == NULL)
    return SQL_INVALID_HANDLE;
  seer_odbc_diag_clear(s);
  if (BufferLength < 0)
    return seer_odbc_diag(s, "HY090", 0, "Invalid string or buffer length", SQL_ERROR);
  const char *name = s->cursor_name != NULL ? s->cursor_name : "";
  size_t n = strlen(name);
  if (NameLengthPtr != NULL)
    *NameLengthPtr = (SQLSMALLINT)n;
  if (CursorName != NULL && BufferLength > 0) {
    size_t cp = n < (size_t)BufferLength - 1 ? n : (size_t)BufferLength - 1;
    memcpy(CursorName, name, cp);
    CursorName[cp] = '\0';
    if (cp < n)
      return seer_odbc_diag(s, "01004", 0, "String data, right truncated", SQL_SUCCESS_WITH_INFO);
  }
  return SQL_SUCCESS;
}

SQLRETURN seer_odbc_describe_prepared(OdbcStmt *s)
{
  if (s == NULL || s->core != NULL || s->sql == NULL || s->dbc == NULL || !s->dbc->connected)
    return SQL_SUCCESS;
  /* A positioned UPDATE / DELETE describes nothing, and the server can't
   * parse it before its CURRENT OF is rewritten (#288). */
  size_t a, b;
  char name[8];
  if (seer_sql_current_of(s->sql, &a, &b, name, sizeof name))
    return SQL_SUCCESS;
  seer_odbc_arm_timeout(s);
  SeerStatus st = seer_stmt_prepare(s->dbc->conn, s->sql, &s->core);
  if (st == SEER_OK)
    st = seer_stmt_describe(s->core);
  if (st != SEER_OK) {
    const char *e = st == SEER_EDB ? seer_last_error(s->dbc->conn) : NULL;
    if (s->core != NULL) {
      seer_stmt_close(s->core);
      s->core = NULL;
    }
    return seer_odbc_diag(s, seer_odbc_sqlstate(st), 0, e ? e : seer_strerror(st), SQL_ERROR);
  }
  return SQL_SUCCESS;
}

SQLRETURN SQL_API SQLPrepare(SQLHSTMT StatementHandle, SQLCHAR *StatementText,
                             SQLINTEGER TextLength)
{
  OdbcStmt *s = (OdbcStmt *)StatementHandle;
  if (s == NULL)
    return SQL_INVALID_HANDLE;
  seer_odbc_diag_clear(s);
  if (StatementText == NULL)
    return seer_odbc_diag(s, "HY009", 0, "NULL statement text", SQL_ERROR);

  SQLRETURN rc = SQL_ERROR;
  char *sql = dup_sql(s, StatementText, TextLength, &rc);
  if (sql == NULL)
    return rc;
  free(s->sql);
  s->sql = sql;
  /* A new statement: drop the previous one's result set, so metadata calls
   * before SQLExecute describe this one rather than report the old columns. */
  if (s->core != NULL) {
    seer_stmt_close(s->core);
    s->core = NULL;
  }
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
  return exec_text(s, s->sql);
}

SQLRETURN SQL_API SQLExecDirect(SQLHSTMT StatementHandle, SQLCHAR *StatementText,
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

  SQLRETURN rc = SQL_ERROR;
  char *sql = dup_sql(s, StatementText, TextLength, &rc);
  if (sql == NULL)
    return rc;
  free(s->sql);
  s->sql = sql;
  return exec_text(s, s->sql);
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
    return seer_odbc_diag(s, "HY010", 0, "No data-at-execution sequence in progress", SQL_ERROR);

  for (int i = s->dae_current + 1; i < s->num_params; i++) {
    if (s->params[i].dae) {
      s->dae_current = i;
      if (ValuePtrPtr != NULL)
        *ValuePtrPtr = s->params[i].buf; /* the app's token */
      return SQL_NEED_DATA;
    }
  }

  /* Every data-at-execution parameter has its value; run the statement. */
  s->dae_active = 0;
  s->dae_current = -1;
  SQLRETURN rc = exec_finish(s);
  for (int i = 0; i < s->num_params; i++)
    dae_reset(&s->params[i]); /* core copied the binds */
  return rc;
}

SQLRETURN SQL_API SQLPutData(SQLHSTMT StatementHandle, SQLPOINTER DataPtr, SQLLEN StrLen_or_Ind)
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
  size_t fixed = seer_odbc_c_fixed_size(param_c_type(p));
  if (fixed != 0) {
    /* Fixed-length data: StrLen_or_Ind is ignored, the C type says the size,
     * and the value comes in one piece (#323). */
    if (p->dae_len != 0)
      return seer_odbc_diag(s, "HY019", 0, "Non-character and non-binary data sent in pieces",
                            SQL_ERROR);
    if (DataPtr == NULL)
      return seer_odbc_diag(s, "HY009", 0, "Invalid use of null pointer", SQL_ERROR);
    if (dae_append(p, DataPtr, fixed) != 0)
      return seer_odbc_diag(s, "HY001", 0, "Out of memory", SQL_ERROR);
    return SQL_SUCCESS;
  }
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
    s->dae_active = 0;
    s->dae_current = -1;
    return SQL_SUCCESS;
  }
  if (s->dbc != NULL && s->dbc->conn != NULL)
    seer_cancel(s->dbc->conn);
  return SQL_SUCCESS;
}

SQLRETURN SQL_API SQLBindParameter(SQLHSTMT StatementHandle, SQLUSMALLINT ParameterNumber,
                                   SQLSMALLINT InputOutputType, SQLSMALLINT ValueType,
                                   SQLSMALLINT ParameterType, SQLULEN ColumnSize,
                                   SQLSMALLINT DecimalDigits, SQLPOINTER ParameterValuePtr,
                                   SQLLEN BufferLength, SQLLEN *StrLen_or_IndPtr)
{
  (void)DecimalDigits;
  OdbcStmt *s = (OdbcStmt *)StatementHandle;
  if (s == NULL)
    return SQL_INVALID_HANDLE;
  seer_odbc_diag_clear(s);
  if (ParameterNumber < 1 || ParameterNumber > 1024)
    return seer_odbc_diag(s, "07009", 0, "Invalid parameter number", SQL_ERROR);
  if (!param_c_type_known(ValueType)) /* #322: never bind unknown bytes as text */
    return seer_odbc_diag(s, "HY003", 0, "Invalid application buffer type", SQL_ERROR);

  if (ParameterNumber > (SQLUSMALLINT)s->num_params) {
    OdbcParam *np = realloc(s->params, (size_t)ParameterNumber * sizeof *np);
    if (np == NULL)
      return seer_odbc_diag(s, "HY001", 0, "Out of memory", SQL_ERROR);
    for (int i = s->num_params; i < ParameterNumber; i++)
      np[i] = (OdbcParam){0};
    s->params = np;
    s->num_params = ParameterNumber;
  }

  OdbcParam *p = &s->params[ParameterNumber - 1];
  p->io_type = InputOutputType;
  p->c_type = ValueType; /* SQL_C_DEFAULT resolves where it is used (#316) */
  p->sql_type = ParameterType;
  p->column_size = ColumnSize;
  p->buf = ParameterValuePtr;
  p->buflen = BufferLength;
  p->indicator = StrLen_or_IndPtr;
  p->bound = 1;
  /* With an explicit APD in use, the value half is that descriptor's (#291). */
  if (s->apd_ext != NULL) {
    if (seer_odbc_bindset_ensure(&s->apd_ext->recs, ParameterNumber) != 0)
      return seer_odbc_diag(s, "HY001", 0, "Out of memory", SQL_ERROR);
    s->apd_ext->recs.binds[ParameterNumber - 1] =
        (OdbcBind){p->c_type, p->buf, p->buflen, p->indicator, 1};
  }
  return SQL_SUCCESS;
}

/* With an explicit APD in use (#291), its records are the parameters' value
 * halves for this execute; the IPD halves stay the statement's. */
static SQLRETURN load_explicit_apd(OdbcStmt *s)
{
  const OdbcBindSet *a = &s->apd_ext->recs;
  if (a->num_binds > s->num_params) {
    OdbcParam *np = realloc(s->params, (size_t)a->num_binds * sizeof *np);
    if (np == NULL)
      return seer_odbc_diag(s, "HY001", 0, "Out of memory", SQL_ERROR);
    for (int i = s->num_params; i < a->num_binds; i++)
      np[i] = (OdbcParam){0};
    s->params = np;
    s->num_params = a->num_binds;
  }
  for (int i = 0; i < s->num_params; i++) {
    OdbcParam *p = &s->params[i];
    const OdbcBind *b = i < a->num_binds ? &a->binds[i] : NULL;
    p->c_type = b != NULL ? b->target_type : 0;
    p->buf = b != NULL ? b->buf : NULL;
    p->buflen = b != NULL ? b->buflen : 0;
    p->indicator = b != NULL ? b->indicator : NULL;
    p->bound = b != NULL && b->bound;
    if (p->bound && p->io_type == 0)
      p->io_type = SQL_PARAM_INPUT;
  }
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

SQLRETURN SQL_API SQLDescribeParam(SQLHSTMT StatementHandle, SQLUSMALLINT ParameterNumber,
                                   SQLSMALLINT *DataTypePtr, SQLULEN *ParameterSizePtr,
                                   SQLSMALLINT *DecimalDigitsPtr, SQLSMALLINT *NullablePtr)
{
  OdbcStmt *s = (OdbcStmt *)StatementHandle;
  if (s == NULL)
    return SQL_INVALID_HANDLE;
  seer_odbc_diag_clear(s);
  /* A parameter the statement has: 1 to what SQLNumParams counts (#280). */
  int n = seer_sql_count_params(s->sql);
  if (n <= 0)
    n = (int)s->num_params;
  if (ParameterNumber < 1 || ParameterNumber > n)
    return seer_odbc_diag(s, "07009", 0, "Invalid descriptor index: no such parameter", SQL_ERROR);
  /* The driver does not introspect parameter types (Oracle does not describe
   * placeholders before execute), so report the universal default: a
   * character type the app can bind anything to. */
  if (DataTypePtr != NULL)
    *DataTypePtr = SQL_VARCHAR;
  if (ParameterSizePtr != NULL)
    *ParameterSizePtr = 4000;
  if (DecimalDigitsPtr != NULL)
    *DecimalDigitsPtr = 0;
  if (NullablePtr != NULL)
    *NullablePtr = SQL_NULLABLE_UNKNOWN;
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
    *last = s->rowset_start + R - 1;
  }
}

/* A bulk SQLSetPos (row < 0, every row of the rowset) skips the rows
 * SQL_ATTR_ROW_OPERATION_PTR marks SQL_ROW_IGNORE (#250); acted on, a row
 * the application excluded was updated or deleted. */
static bool pos_ignored(const OdbcStmt *s, long row, long r)
{
  return row < 0 && s->row_operation != NULL &&
         s->row_operation[r - s->rowset_start] == SQL_ROW_IGNORE;
}

/* One row's result of a positioned UPDATE / DELETE (#371): its status
 * (SQL_ROW_UPDATED / SQL_ROW_DELETED, or SQL_ROW_ERROR with a diagnostic
 * carrying the row's number in the rowset), counted for the call's return. */
static void pos_row_result(OdbcStmt *s, long elem, SeerStatus st, SQLUSMALLINT done, int *ok,
                           int *bad)
{
  if (st == SEER_OK) {
    (*ok)++;
  } else {
    (*bad)++;
    const char *ora = st == SEER_EDB ? seer_last_error(s->dbc->conn) : NULL;
    seer_odbc_diag_add(s, seer_odbc_sqlstate(st), 0, ora ? ora : seer_strerror(st),
                       (SQLLEN)elem + 1);
  }
  if (s->row_status != NULL && elem >= 0)
    s->row_status[elem] = st == SEER_OK ? done : SQL_ROW_ERROR;
}

/* The call's return: every row done, some failed, or all failed. */
static SQLRETURN pos_return(int ok, int bad)
{
  if (bad == 0)
    return SQL_SUCCESS;
  return ok > 0 ? SQL_SUCCESS_WITH_INFO : SQL_ERROR;
}

SQLRETURN seer_odbc_pos_delete(OdbcStmt *s, long row)
{
  long first, last;
  int ok = 0, bad = 0;
  pos_range(s, row, &first, &last);
  for (long r = first; r <= last; r++) {
    if (r < 0 || (size_t)r >= s->num_rowids || s->rowids[r] == NULL || pos_ignored(s, row, r))
      continue;
    char sql[256];
    snprintf(sql, sizeof sql, "DELETE FROM %s WHERE ROWID = :1", s->base_table);
    SeerStmt *dml = NULL;
    if (seer_stmt_prepare(s->dbc->conn, sql, &dml) != SEER_OK)
      return seer_odbc_diag(s, "HY000", 0, "prepare failed", SQL_ERROR);
    seer_stmt_bind_text(dml, 1, s->rowids[r], -1);
    seer_odbc_arm_timeout(s);
    SeerStatus st = seer_stmt_execute(dml);
    seer_stmt_close(dml);
    /* A failing row is its own error; the rest still run (#371). */
    pos_row_result(s, r - s->rowset_start, st, SQL_ROW_DELETED, &ok, &bad);
  }
  return pos_return(ok, bad);
}

SQLRETURN seer_odbc_pos_update(OdbcStmt *s, long row)
{
  long first, last;
  int ok = 0, bad = 0;
  pos_range(s, row, &first, &last);
  for (long r = first; r <= last; r++) {
    if (r < 0 || (size_t)r >= s->num_rowids || s->rowids[r] == NULL || pos_ignored(s, row, r))
      continue;
    long elem = r - s->rowset_start; /* index within the bound rowset */
    if (elem < 0)
      continue;

    /* Build UPDATE <table> SET <bound col> = :k, ... WHERE ROWID = :last.
     * snprintf returns the length it WOULD have written, so an unchecked
     * "o += snprintf(...)" can push o past the buffer; the next
     * "sizeof sql - o" then underflows to a huge size_t and the following
     * write runs out of bounds. Guard every append and bail if the
     * statement (schema-derived table + column names) does not fit. */
    char sql[4096];
    int o = snprintf(sql, sizeof sql, "UPDATE %s SET ", s->base_table);
    if (o < 0 || (size_t)o >= sizeof sql)
      return seer_odbc_diag(s, "HY000", 0, "Updatable cursor statement too long", SQL_ERROR);
    int nset = 0;
    for (int i = 0; i < s->ab->num_binds && i < odbc_visible_cols(s); i++) {
      if (!s->ab->binds[i].bound)
        continue;
      const char *name = seer_stmt_col_name(s->core, i);
      if (name == NULL)
        continue;
      int n =
          snprintf(sql + o, sizeof sql - (size_t)o, "%s%s = :%d", nset ? ", " : "", name, nset + 1);
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
    for (int i = 0; i < s->ab->num_binds && i < odbc_visible_cols(s); i++) {
      OdbcBind *b = &s->ab->binds[i];
      if (!b->bound || seer_stmt_col_name(s->core, i) == NULL)
        continue;
      SQLSMALLINT ct = seer_odbc_col_c_type(s, i, b->target_type); /* #316 */
      void *vp = seer_odbc_bound_at(b->buf, s->row_bind_offset, s->row_bind_type,
                                    ctype_stride(ct, b->buflen), (SQLULEN)elem);
      const SQLLEN *indp = seer_odbc_bound_at(b->indicator, s->row_bind_offset, s->row_bind_type,
                                              sizeof(SQLLEN), (SQLULEN)elem);
      SQLLEN ind = indp ? *indp : SQL_NTS;
      bind_one_value(dml, ++k, ct, 0, vp, ind, bind_flags(s));
    }
    seer_stmt_bind_text(dml, nset + 1, s->rowids[r], -1);

    seer_odbc_arm_timeout(s);
    SeerStatus st = seer_stmt_execute(dml);
    seer_stmt_close(dml);
    pos_row_result(s, elem, st, SQL_ROW_UPDATED, &ok, &bad); /* the rest still run (#371) */
  }
  return pos_return(ok, bad);
}

/* Result-set retrieval: SQLNumResultCols, SQLDescribeCol, SQLColAttribute,
 * SQLBindCol, SQLFetch, SQLGetData, SQLRowCount, SQLFreeStmt, SQLCloseCursor.
 *
 * Column values arrive from the core (text for scalars, raw for binary) and
 * are turned into the requested C type by convert.c (seer_odbc_convert).
 *
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "convert.h"
#include "odbc_internal.h"
#include "types.h" /* ORA_TYPE_* */

/* Map an Oracle type number to an ODBC SQL type. */
static SQLSMALLINT sql_type_of(int ora_type)
{
  switch (ora_type) {
  case ORA_TYPE_NUMBER:
    return SQL_DECIMAL;
  case ORA_TYPE_CHAR:
    return SQL_CHAR;
  case ORA_TYPE_RAW:
    return SQL_VARBINARY;
  case ORA_TYPE_BFLOAT:
    return SQL_REAL;
  case ORA_TYPE_BDOUBLE:
    return SQL_DOUBLE;
  case ORA_TYPE_LONG:
    return SQL_LONGVARCHAR;
  case ORA_TYPE_LONGRAW:
    return SQL_LONGVARBINARY;
  case ORA_TYPE_CLOB:
    return SQL_LONGVARCHAR;
  case ORA_TYPE_BLOB:
  case ORA_TYPE_BFILE:
    return SQL_LONGVARBINARY;
  case ORA_TYPE_DATE:
  case ORA_TYPE_TIMESTAMP:
  case ORA_TYPE_TIMESTAMPTZ:
  case ORA_TYPE_TIMESTAMPLTZ:
    return SQL_TYPE_TIMESTAMP;
  case ORA_TYPE_VARCHAR:
  default:
    return SQL_VARCHAR;
  }
}

/* A TIMESTAMP WITH TIME ZONE value's text ends in its offset (#359),
 * "... 10:00:00 +02:00". The text targets keep it; a date / time / timestamp
 * struct (or any other target) takes the wall-clock time before it, which is
 * the value's own clock time. Returns the length to convert. */
static const char *tz_cut(OdbcStmt *s, int col, const char *val, size_t *vlen, SQLSMALLINT ct,
                          char cut[64])
{
  if (val == NULL || *vlen < 7 || *vlen >= 64 || ct == SQL_C_CHAR || ct == SQL_C_WCHAR ||
      seer_stmt_col_type(s->core, col) != ORA_TYPE_TIMESTAMPTZ)
    return val;
  const char *z = val + *vlen - 7; /* " +HH:MM" */
  if (z[0] != ' ' || (z[1] != '+' && z[1] != '-') || z[4] != ':')
    return val;
  *vlen -= 7; /* a copy: the conversion reads the text up to its NUL */
  memcpy(cut, val, *vlen);
  cut[*vlen] = '\0';
  return cut;
}

SQLSMALLINT seer_odbc_col_c_type(OdbcStmt *s, int col, SQLSMALLINT t)
{
  if (t != SQL_C_DEFAULT || s == NULL || s->core == NULL)
    return t;
  return seer_odbc_default_c_type(sql_type_of(seer_stmt_col_type(s->core, col)));
}

static const char *type_name_of(int ora_type)
{
  switch (ora_type) {
  case ORA_TYPE_NUMBER:
    return "NUMBER";
  case ORA_TYPE_CHAR:
    return "CHAR";
  case ORA_TYPE_RAW:
    return "RAW";
  case ORA_TYPE_BFLOAT:
    return "BINARY_FLOAT";
  case ORA_TYPE_BDOUBLE:
    return "BINARY_DOUBLE";
  case ORA_TYPE_LONG:
    return "LONG";
  case ORA_TYPE_LONGRAW:
    return "LONG RAW";
  case ORA_TYPE_CLOB:
    return "CLOB";
  case ORA_TYPE_BLOB:
    return "BLOB";
  case ORA_TYPE_BFILE:
    return "BFILE";
  case ORA_TYPE_DATE:
    return "DATE";
  case ORA_TYPE_TIMESTAMP:
  case ORA_TYPE_TIMESTAMPTZ:
  case ORA_TYPE_TIMESTAMPLTZ:
    return "TIMESTAMP";
  case ORA_TYPE_INTERVAL_YM:
    return "INTERVAL YEAR TO MONTH";
  case ORA_TYPE_INTERVAL_DS:
    return "INTERVAL DAY TO SECOND";
  case ORA_TYPE_BOOLEAN:
    return "BOOLEAN";
  case ORA_TYPE_VECTOR:
    return "VECTOR";
  default:
    return "VARCHAR2";
  }
}

static SQLLEN display_size_of(int ora_type, int max_size)
{
  switch (ora_type) {
  case ORA_TYPE_NUMBER:
    return 40;
  case ORA_TYPE_BFLOAT:
    return 15;
  case ORA_TYPE_BDOUBLE:
    return 24;
  case ORA_TYPE_DATE:
    return 19;
  case ORA_TYPE_TIMESTAMP:
  case ORA_TYPE_TIMESTAMPLTZ:
    return 29;
  case ORA_TYPE_TIMESTAMPTZ: /* and " +HH:MM" (#359) */
    return 36;
  case ORA_TYPE_RID:
  case ORA_TYPE_ROWID:
    /* The rowid's 18-character text. 8i and 9i describe a ROWID with a 1-byte
     * buffer, and a column size of 1 had applications cut it to its first
     * characters (isql showed "AAAAD"). */
    return 18;
  case ORA_TYPE_LONG:
  case ORA_TYPE_LONGRAW:
  case ORA_TYPE_CLOB:
  case ORA_TYPE_BLOB:
  case ORA_TYPE_BFILE:
    /* As SQLGetTypeInfo has them: the largest SQLINTEGER. The describe's
     * 4000 (9i NCLOB 2000) is a placeholder, not a limit (#268). */
    return 2147483647;
  default:
    return max_size > 0 ? max_size : 4000;
  }
}

/* A result column's ODBC metadata, from its Oracle type and the describe's
 * size, precision and scale (#259). One place, so SQLDescribeCol and
 * SQLColAttribute agree. */
typedef struct {
  SQLLEN column_size;  /* DescribeCol ColumnSize, DESC_LENGTH */
  SQLLEN precision;    /* DESC_PRECISION: digits, or fractional-second digits */
  SQLSMALLINT scale;   /* DecimalDigits, DESC_SCALE */
  SQLLEN display_size; /* DESC_DISPLAY_SIZE */
  SQLLEN octet_length; /* DESC_OCTET_LENGTH */
  int radix;           /* DESC_NUM_PREC_RADIX: 10 for numbers, else 0 */
  int is_char;         /* character data: case-sensitive, quoted literals */
  int searchable;      /* SQL_PRED_* */
} ColMeta;

static ColMeta col_meta(OdbcStmt *s, int col)
{
  int t = seer_stmt_col_type(s->core, col), max_size = seer_stmt_col_size(s->core, col);
  int p = seer_stmt_col_precision(s->core, col), sc = seer_stmt_col_scale(s->core, col);
  ColMeta m = {0};
  m.column_size = m.precision = m.display_size = m.octet_length = display_size_of(t, max_size);
  m.searchable = SQL_PRED_BASIC;
  switch (t) {
  case ORA_TYPE_NUMBER:
    m.radix = 10;
    if (p > 0 && sc == -127) /* FLOAT(b): b binary digits as decimal ones */
      p = (int)((p * 30103L + 99999L) / 100000L);
    else if (p > 0 && sc >= 0)
      m.scale = (SQLSMALLINT)sc;
    if (p <= 0)
      p = 38; /* a NUMBER without a precision, as SQLGetTypeInfo's 38 */
    m.column_size = m.precision = p;
    m.display_size = m.octet_length = p + 2; /* sign and decimal point */
    break;
  case ORA_TYPE_BFLOAT:
  case ORA_TYPE_BDOUBLE:
    m.radix = 10;
    m.column_size = m.precision = t == ORA_TYPE_BFLOAT ? 7 : 15;
    m.octet_length = t == ORA_TYPE_BFLOAT ? 4 : 8;
    break;
  case ORA_TYPE_DATE:
  case ORA_TYPE_TIMESTAMP:
  case ORA_TYPE_TIMESTAMPTZ:
  case ORA_TYPE_TIMESTAMPLTZ: {
    /* ODBC's datetime precision is the fractional-second digits: 0 for a
     * DATE, n for a TIMESTAMP(n); the size the characters of its text. */
    int fs = t == ORA_TYPE_DATE ? 0 : (sc >= 0 && sc <= 9 ? sc : 6);
    m.precision = m.scale = (SQLSMALLINT)fs;
    m.column_size = m.display_size = fs > 0 ? 20 + fs : 19;
    if (t == ORA_TYPE_TIMESTAMPTZ) /* its text ends in " +HH:MM" (#359) */
      m.display_size += 7;
    m.octet_length = (SQLLEN)sizeof(SQL_TIMESTAMP_STRUCT);
    break;
  }
  case ORA_TYPE_VARCHAR:
  case ORA_TYPE_CHAR: {
    m.is_char = 1;
    m.searchable = SQL_PRED_SEARCHABLE;
    /* The size counts characters, the octet length bytes: a VARCHAR2(20
     * CHAR) in AL32UTF8 holds up to 80 (#264). */
    int octets = seer_stmt_col_octets(s->core, col);
    if (octets > 0)
      m.octet_length = octets;
    break;
  }
  case ORA_TYPE_RAW: /* two hex digits a byte, as SQL_C_CHAR shows it */
    m.display_size = 2 * m.column_size;
    break;
  case ORA_TYPE_CLOB: /* LIKE, not = */
    m.is_char = 1;
    m.searchable = SQL_PRED_CHAR;
    break;
  case ORA_TYPE_LONG: /* in no WHERE clause */
    m.is_char = 1;
    m.searchable = SQL_PRED_NONE;
    break;
  case ORA_TYPE_LONGRAW:
  case ORA_TYPE_BLOB:
  case ORA_TYPE_BFILE:
    m.searchable = SQL_PRED_NONE;
    break;
  default:
    break;
  }
  return m;
}

SQLRETURN SQL_API SQLNumResultCols(SQLHSTMT StatementHandle, SQLSMALLINT *ColumnCountPtr)
{
  OdbcStmt *s = (OdbcStmt *)StatementHandle;
  if (s == NULL)
    return SQL_INVALID_HANDLE;
  seer_odbc_diag_clear(s);
  SQLRETURN rc = seer_odbc_describe_prepared(s);
  if (rc != SQL_SUCCESS)
    return rc;
  if (ColumnCountPtr != NULL)
    *ColumnCountPtr = (SQLSMALLINT)odbc_visible_cols(s);
  return SQL_SUCCESS;
}

SQLRETURN SQL_API SQLDescribeCol(SQLHSTMT StatementHandle, SQLUSMALLINT ColumnNumber,
                                 SQLCHAR *ColumnName, SQLSMALLINT BufferLength,
                                 SQLSMALLINT *NameLengthPtr, SQLSMALLINT *DataTypePtr,
                                 SQLULEN *ColumnSizePtr, SQLSMALLINT *DecimalDigitsPtr,
                                 SQLSMALLINT *NullablePtr)
{
  OdbcStmt *s = (OdbcStmt *)StatementHandle;
  if (s == NULL)
    return SQL_INVALID_HANDLE;
  seer_odbc_diag_clear(s);
  SQLRETURN drc = seer_odbc_describe_prepared(s);
  if (drc != SQL_SUCCESS)
    return drc;
  if (s->core == NULL || ColumnNumber < 1 || ColumnNumber > (SQLUSMALLINT)odbc_visible_cols(s))
    return seer_odbc_diag(s, "07009", 0, "Invalid column number", SQL_ERROR);

  int col = ColumnNumber - 1;
  const char *name = seer_stmt_col_name(s->core, col);
  int ora_type = seer_stmt_col_type(s->core, col);
  int max_size = seer_stmt_col_size(s->core, col);

  if (name == NULL)
    name = "";
  size_t nlen = strlen(name);
  if (NameLengthPtr != NULL)
    *NameLengthPtr = (SQLSMALLINT)nlen;
  if (ColumnName != NULL && BufferLength > 0) {
    SQLSMALLINT c =
        (SQLSMALLINT)(nlen < (size_t)BufferLength - 1 ? nlen : (size_t)BufferLength - 1);
    memcpy(ColumnName, name, c);
    ColumnName[c] = '\0';
  }
  if (DataTypePtr != NULL)
    *DataTypePtr = sql_type_of(ora_type);
  ColMeta m = col_meta(s, col);
  (void)max_size;
  if (ColumnSizePtr != NULL)
    *ColumnSizePtr = (SQLULEN)m.column_size;
  if (DecimalDigitsPtr != NULL)
    *DecimalDigitsPtr = m.scale;
  if (NullablePtr != NULL)
    *NullablePtr = seer_stmt_col_nullable(s->core, col) ? SQL_NULLABLE : SQL_NO_NULLS;
  return SQL_SUCCESS;
}

SQLRETURN SQL_API SQLColAttribute(SQLHSTMT StatementHandle, SQLUSMALLINT ColumnNumber,
                                  SQLUSMALLINT FieldIdentifier, SQLPOINTER CharacterAttributePtr,
                                  SQLSMALLINT BufferLength, SQLSMALLINT *StringLengthPtr,
                                  SEER_COLATTR_NUMERIC NumericAttribute)
{
  SQLLEN *NumericAttributePtr = (SQLLEN *)NumericAttribute;
  OdbcStmt *s = (OdbcStmt *)StatementHandle;
  if (s == NULL)
    return SQL_INVALID_HANDLE;
  seer_odbc_diag_clear(s);
  SQLRETURN drc = seer_odbc_describe_prepared(s);
  if (drc != SQL_SUCCESS)
    return drc;
  if (s->core == NULL)
    return seer_odbc_diag(s, "07005", 0, "No result set", SQL_ERROR);

  int ncols = odbc_visible_cols(s);
  if (FieldIdentifier == SQL_DESC_COUNT) {
    if (NumericAttributePtr)
      *NumericAttributePtr = ncols;
    return SQL_SUCCESS;
  }
  if (ColumnNumber < 1 || ColumnNumber > (SQLUSMALLINT)ncols)
    return seer_odbc_diag(s, "07009", 0, "Invalid column number", SQL_ERROR);

  int col = ColumnNumber - 1;
  int ora_type = seer_stmt_col_type(s->core, col);
  ColMeta m = col_meta(s, col);
  const char *str = NULL;

  switch (FieldIdentifier) {
  case SQL_DESC_NAME:
  case SQL_DESC_LABEL:
  case SQL_DESC_BASE_COLUMN_NAME:
    str = seer_stmt_col_name(s->core, col);
    break;
  case SQL_DESC_TYPE_NAME:
    str = type_name_of(ora_type);
    break;
  case SQL_DESC_SEER_ANNOTATIONS:
    str = seer_stmt_col_annotations(s->core, col);
    break;
  case SQL_DESC_SEER_VECTOR_DIMENSIONS:
  case SQL_DESC_SEER_VECTOR_FORMAT: {
    int dims = 0, fmt = 0;
    seer_stmt_col_vector(s->core, col, &dims, &fmt);
    if (NumericAttributePtr)
      *NumericAttributePtr = FieldIdentifier == SQL_DESC_SEER_VECTOR_DIMENSIONS ? dims : fmt;
    return SQL_SUCCESS;
  }
  case SQL_DESC_TYPE:
  case SQL_DESC_CONCISE_TYPE:
    if (NumericAttributePtr)
      *NumericAttributePtr = sql_type_of(ora_type);
    return SQL_SUCCESS;
  /* Sizes from the describe's precision and scale (#259). */
  case SQL_DESC_LENGTH:
  case SQL_COLUMN_PRECISION: /* ODBC 2's precision is the column size */
    if (NumericAttributePtr)
      *NumericAttributePtr = m.column_size;
    return SQL_SUCCESS;
  case SQL_DESC_PRECISION:
    if (NumericAttributePtr)
      *NumericAttributePtr = m.precision;
    return SQL_SUCCESS;
  case SQL_DESC_DISPLAY_SIZE:
    if (NumericAttributePtr)
      *NumericAttributePtr = m.display_size;
    return SQL_SUCCESS;
  case SQL_DESC_OCTET_LENGTH:
    if (NumericAttributePtr)
      *NumericAttributePtr = m.octet_length;
    return SQL_SUCCESS;
  case SQL_DESC_SCALE:
  case SQL_COLUMN_SCALE:
    if (NumericAttributePtr)
      *NumericAttributePtr = m.scale;
    return SQL_SUCCESS;
  case SQL_DESC_NUM_PREC_RADIX:
    if (NumericAttributePtr)
      *NumericAttributePtr = m.radix;
    return SQL_SUCCESS;
  case SQL_DESC_CASE_SENSITIVE:
    if (NumericAttributePtr)
      *NumericAttributePtr = m.is_char ? SQL_TRUE : SQL_FALSE;
    return SQL_SUCCESS;
  case SQL_DESC_SEARCHABLE:
    if (NumericAttributePtr)
      *NumericAttributePtr = m.searchable;
    return SQL_SUCCESS;
  case SQL_DESC_UPDATABLE: /* which columns a statement can write isn't known */
    if (NumericAttributePtr)
      *NumericAttributePtr = SQL_ATTR_READWRITE_UNKNOWN;
    return SQL_SUCCESS;
  case SQL_DESC_LITERAL_PREFIX:
  case SQL_DESC_LITERAL_SUFFIX:
    str = m.is_char ? "'" : "";
    break;
  /* Not in an Oracle describe, or not in Oracle: written empty, as ODBC
   * has it - left unwritten, the application read its own buffer back. */
  case SQL_DESC_TABLE_NAME:
  case SQL_DESC_BASE_TABLE_NAME:
  case SQL_DESC_SCHEMA_NAME:
  case SQL_DESC_CATALOG_NAME:
  case SQL_DESC_LOCAL_TYPE_NAME:
    str = "";
    break;
  case SQL_DESC_NULLABLE:
    if (NumericAttributePtr)
      *NumericAttributePtr = seer_stmt_col_nullable(s->core, col) ? SQL_NULLABLE : SQL_NO_NULLS;
    return SQL_SUCCESS;
  case SQL_DESC_UNSIGNED: /* ODBC: TRUE for a column that isn't numeric */
    if (NumericAttributePtr)
      *NumericAttributePtr = m.radix == 10 ? SQL_FALSE : SQL_TRUE;
    return SQL_SUCCESS;
  default:
    if (NumericAttributePtr)
      *NumericAttributePtr = 0;
    return SQL_SUCCESS;
  }

  if (str == NULL)
    str = "";
  size_t n = strlen(str);
  if (StringLengthPtr != NULL)
    *StringLengthPtr = (SQLSMALLINT)n;
  if (CharacterAttributePtr != NULL && BufferLength > 0) {
    SQLSMALLINT c = (SQLSMALLINT)(n < (size_t)BufferLength - 1 ? n : (size_t)BufferLength - 1);
    memcpy(CharacterAttributePtr, str, c);
    ((char *)CharacterAttributePtr)[c] = '\0';
  }
  return SQL_SUCCESS;
}

/* Advance to the next result set. SeerODBC produces two kinds:
 * - a query run with a parameter array: one result set per parameter set
 *   (SQL_PAS_BATCH, #431), each next one run here;
 * - 12c+ implicit results (DBMS_SQL.RETURN_RESULT): each call drains the next
 *   implicit cursor and makes it current.
 * SQL_NO_DATA when none remain (PEP-249 / ODBC contract). */
SQLRETURN SQL_API SQLMoreResults(SQLHSTMT StatementHandle)
{
  OdbcStmt *s = (OdbcStmt *)StatementHandle;
  if (s == NULL)
    return SQL_INVALID_HANDLE;
  seer_odbc_diag_clear(s);
  if (s->core == NULL)
    return SQL_NO_DATA;
  if (s->pas_query) /* a query has no implicit results */
    return seer_odbc_next_param_set(s);

  seer_odbc_arm_timeout(s);
  SeerStatus st = seer_stmt_next_result(s->core);
  if (st == SEER_ENODATA)
    return SQL_NO_DATA;
  if (st != SEER_OK)
    return seer_odbc_diag(s, seer_odbc_sqlstate(st), 0, seer_strerror(st), SQL_ERROR);

  /* The now-current set's columns; the bindings stay (#244). */
  int ncols = seer_stmt_num_cols(s->core);
  if (seer_odbc_ensure_binds(s, ncols) != 0)
    return seer_odbc_diag(s, "HY001", 0, "Out of memory", SQL_ERROR);
  s->getdata_col = -1;
  s->getdata_off = 0;
  s->getdata_done = 0;
  s->rowset_start = -1;
  s->cur_row = -1;
  return SQL_SUCCESS;
}

/* ----------------------------------------------------------- descriptors */

/* The records of a descriptor that keeps them as column bindings: an
 * explicit descriptor's own, or an implicit ARD's - the statement's own
 * bindings, even while an explicit ARD is in use (#291). NULL otherwise. */
static OdbcBindSet *desc_binds(OdbcDesc *d)
{
  if (d->is_explicit)
    return &d->recs;
  return d->kind == SEER_DESC_ARD ? &((OdbcStmt *)d->stmt)->own_binds : NULL;
}

/* Grow a set of bindings to `n` records, the new ones unbound. */
int seer_odbc_bindset_ensure(OdbcBindSet *b, int n)
{
  if (n <= b->num_binds)
    return 0;
  OdbcBind *nb = realloc(b->binds, (size_t)n * sizeof *nb);
  if (nb == NULL)
    return -1;
  memset(nb + b->num_binds, 0, (size_t)(n - b->num_binds) * sizeof *nb);
  b->binds = nb;
  b->num_binds = n;
  return 0;
}

/* Number of records in a descriptor: result columns (IRD), bound result columns
 * (ARD, explicit), or parameters (APD/IPD). */
static int desc_count(OdbcDesc *d)
{
  OdbcStmt *s = (OdbcStmt *)d->stmt;
  if (desc_binds(d) != NULL)
    return desc_binds(d)->num_binds;
  switch (d->kind) {
  case SEER_DESC_IRD:
    return s->core != NULL ? odbc_visible_cols(s) : 0;
  case SEER_DESC_ARD:
    return 0;
  case SEER_DESC_APD:
  case SEER_DESC_IPD:
    return s->num_params;
  }
  return 0;
}

/* Copy a string descriptor field out (SQLINTEGER-counted, truncating). */
static void desc_str(const char *str, SQLPOINTER buf, SQLINTEGER buflen, SQLINTEGER *lenp)
{
  if (str == NULL)
    str = "";
  size_t n = strlen(str);
  if (lenp != NULL)
    *lenp = (SQLINTEGER)n;
  if (buf != NULL && buflen > 0) {
    size_t cp = (n < (size_t)buflen - 1) ? n : (size_t)buflen - 1;
    memcpy(buf, str, cp);
    ((char *)buf)[cp] = '\0';
  }
}

/* Read-only descriptor access. The implementation row descriptor (IRD) carries
 * the full result-column metadata (the descriptor-API view of SQLDescribeCol);
 * the others expose their record count and concise type. */
SQLRETURN SQL_API SQLGetDescField(SQLHDESC DescriptorHandle, SQLSMALLINT RecNumber,
                                  SQLSMALLINT FieldIdentifier, SQLPOINTER ValuePtr,
                                  SQLINTEGER BufferLength, SQLINTEGER *StringLengthPtr)
{
  (void)BufferLength;
  OdbcDesc *d = (OdbcDesc *)DescriptorHandle;
  if (d == NULL)
    return SQL_INVALID_HANDLE;
  seer_odbc_diag_clear(d);
  OdbcStmt *s = (OdbcStmt *)d->stmt;
  int count = desc_count(d);

  if (FieldIdentifier == SQL_DESC_COUNT) {
    if (ValuePtr != NULL)
      *(SQLSMALLINT *)ValuePtr = (SQLSMALLINT)count;
    return SQL_SUCCESS;
  }
  if (FieldIdentifier == SQL_DESC_ALLOC_TYPE) { /* #291 */
    if (ValuePtr != NULL)
      *(SQLSMALLINT *)ValuePtr = d->is_explicit ? SQL_DESC_ALLOC_USER : SQL_DESC_ALLOC_AUTO;
    return SQL_SUCCESS;
  }
  if (RecNumber < 1 || RecNumber > count)
    return seer_odbc_diag(d, "07009", 0, "Invalid descriptor index", SQL_ERROR);
  int i = RecNumber - 1;

  if (d->kind == SEER_DESC_IRD && s->core != NULL) {
    int ora = seer_stmt_col_type(s->core, i);
    const char *nm = seer_stmt_col_name(s->core, i);
    switch (FieldIdentifier) {
    case SQL_DESC_TYPE:
    case SQL_DESC_CONCISE_TYPE:
      if (ValuePtr)
        *(SQLSMALLINT *)ValuePtr = (SQLSMALLINT)sql_type_of(ora);
      return SQL_SUCCESS;
    case SQL_DESC_TYPE_NAME:
      desc_str(type_name_of(ora), ValuePtr, BufferLength, StringLengthPtr);
      return SQL_SUCCESS;
    case SQL_DESC_NAME:
    case SQL_DESC_LABEL:
    case SQL_DESC_BASE_COLUMN_NAME:
      desc_str(nm, ValuePtr, BufferLength, StringLengthPtr);
      return SQL_SUCCESS;
    /* The sizes as SQLColAttribute gives them, from the same col_meta (#264). */
    case SQL_DESC_LENGTH:
      if (ValuePtr)
        *(SQLULEN *)ValuePtr = (SQLULEN)col_meta(s, i).column_size;
      return SQL_SUCCESS;
    case SQL_DESC_OCTET_LENGTH:
      if (ValuePtr)
        *(SQLLEN *)ValuePtr = col_meta(s, i).octet_length;
      return SQL_SUCCESS;
    case SQL_DESC_PRECISION:
      if (ValuePtr)
        *(SQLSMALLINT *)ValuePtr = (SQLSMALLINT)col_meta(s, i).precision;
      return SQL_SUCCESS;
    case SQL_DESC_SCALE:
      if (ValuePtr)
        *(SQLSMALLINT *)ValuePtr = col_meta(s, i).scale;
      return SQL_SUCCESS;
    case SQL_DESC_DISPLAY_SIZE:
      if (ValuePtr)
        *(SQLLEN *)ValuePtr = col_meta(s, i).display_size;
      return SQL_SUCCESS;
    case SQL_DESC_NUM_PREC_RADIX:
      if (ValuePtr)
        *(SQLINTEGER *)ValuePtr = col_meta(s, i).radix;
      return SQL_SUCCESS;
    case SQL_DESC_NULLABLE:
      if (ValuePtr)
        *(SQLSMALLINT *)ValuePtr = seer_stmt_col_nullable(s->core, i) ? SQL_NULLABLE : SQL_NO_NULLS;
      return SQL_SUCCESS;
    case SQL_DESC_UNNAMED:
      if (ValuePtr)
        *(SQLSMALLINT *)ValuePtr = (nm && nm[0]) ? SQL_NAMED : SQL_UNNAMED;
      return SQL_SUCCESS;
    default:
      break;
    }
  } else if (desc_binds(d) != NULL &&
             (FieldIdentifier == SQL_DESC_DATA_PTR || FieldIdentifier == SQL_DESC_INDICATOR_PTR ||
              FieldIdentifier == SQL_DESC_OCTET_LENGTH_PTR ||
              FieldIdentifier == SQL_DESC_OCTET_LENGTH)) {
    const OdbcBind *b = &desc_binds(d)->binds[i]; /* as SQLSetDescField wrote them (#291) */
    if (ValuePtr == NULL)
      return SQL_SUCCESS;
    if (FieldIdentifier == SQL_DESC_OCTET_LENGTH)
      *(SQLLEN *)ValuePtr = b->buflen;
    else if (FieldIdentifier == SQL_DESC_DATA_PTR)
      *(SQLPOINTER *)ValuePtr = b->bound ? b->buf : NULL;
    else
      *(SQLLEN **)ValuePtr = b->indicator;
    return SQL_SUCCESS;
  } else if (FieldIdentifier == SQL_DESC_TYPE || FieldIdentifier == SQL_DESC_CONCISE_TYPE) {
    SQLSMALLINT t = 0;
    if (desc_binds(d) != NULL)
      t = desc_binds(d)->binds[i].target_type;
    else if (d->kind == SEER_DESC_APD && s->params != NULL)
      t = s->params[i].c_type;
    else if (d->kind == SEER_DESC_IPD && s->params != NULL)
      t = s->params[i].sql_type;
    if (ValuePtr)
      *(SQLSMALLINT *)ValuePtr = t;
    return SQL_SUCCESS;
  }

  /* Unhandled field: leniently report nothing (matches SQLColAttribute). */
  return SQL_SUCCESS;
}

SQLRETURN SQL_API SQLGetDescRec(SQLHDESC DescriptorHandle, SQLSMALLINT RecNumber, SQLCHAR *Name,
                                SQLSMALLINT BufferLength, SQLSMALLINT *StringLengthPtr,
                                SQLSMALLINT *TypePtr, SQLSMALLINT *SubTypePtr, SQLLEN *LengthPtr,
                                SQLSMALLINT *PrecisionPtr, SQLSMALLINT *ScalePtr,
                                SQLSMALLINT *NullablePtr)
{
  OdbcDesc *d = (OdbcDesc *)DescriptorHandle;
  if (d == NULL)
    return SQL_INVALID_HANDLE;
  seer_odbc_diag_clear(d);
  OdbcStmt *s = (OdbcStmt *)d->stmt;
  if (RecNumber < 1 || RecNumber > desc_count(d))
    return SQL_NO_DATA;
  int i = RecNumber - 1;

  if (SubTypePtr)
    *SubTypePtr = 0;
  if (ScalePtr)
    *ScalePtr = 0;
  if (d->kind == SEER_DESC_IRD && s->core != NULL) {
    int ora = seer_stmt_col_type(s->core, i);
    const char *nm = seer_stmt_col_name(s->core, i);
    if (Name != NULL && BufferLength > 0) {
      size_t n = nm ? strlen(nm) : 0;
      size_t cp = (n < (size_t)BufferLength - 1) ? n : (size_t)BufferLength - 1;
      if (nm)
        memcpy(Name, nm, cp);
      Name[cp] = '\0';
    }
    if (StringLengthPtr)
      *StringLengthPtr = (SQLSMALLINT)(nm ? strlen(nm) : 0);
    if (TypePtr)
      *TypePtr = (SQLSMALLINT)sql_type_of(ora);
    ColMeta m = col_meta(s, i); /* as SQLColAttribute (#264) */
    if (LengthPtr)
      *LengthPtr = m.octet_length;
    if (PrecisionPtr)
      *PrecisionPtr = (SQLSMALLINT)m.precision;
    if (ScalePtr)
      *ScalePtr = m.scale;
    if (NullablePtr)
      *NullablePtr = seer_stmt_col_nullable(s->core, i) ? SQL_NULLABLE : SQL_NO_NULLS;
  } else {
    if (Name && BufferLength > 0)
      Name[0] = '\0';
    if (StringLengthPtr)
      *StringLengthPtr = 0;
    if (TypePtr)
      *TypePtr = desc_binds(d) != NULL                     ? desc_binds(d)->binds[i].target_type
                 : (d->kind == SEER_DESC_APD && s->params) ? s->params[i].c_type
                 : (d->kind == SEER_DESC_IPD && s->params) ? s->params[i].sql_type
                                                           : 0;
    if (LengthPtr)
      *LengthPtr = 0;
    if (PrecisionPtr)
      *PrecisionPtr = 0;
    if (NullablePtr)
      *NullablePtr = SQL_NULLABLE_UNKNOWN;
  }
  return SQL_SUCCESS;
}

/* Grow a statement's parameter array so record `rec` (1-based) exists, mirroring
 * SQLBindParameter's growth. New records are zeroed. */
static SQLRETURN desc_ensure_params(OdbcStmt *s, int rec)
{
  if (rec <= s->num_params)
    return SQL_SUCCESS;
  OdbcParam *np = realloc(s->params, (size_t)rec * sizeof *np);
  if (np == NULL)
    return seer_odbc_diag(s, "HY001", 0, "Out of memory", SQL_ERROR);
  for (int i = s->num_params; i < rec; i++)
    np[i] = (OdbcParam){0};
  s->params = np;
  s->num_params = rec;
  return SQL_SUCCESS;
}

/* Descriptor write path. Writing a field updates the same bind/param array the
 * execute/fetch paths consume, so it is equivalent to SQLBindCol (ARD) or the
 * value/type halves of SQLBindParameter (APD/IPD). The implementation row
 * descriptor (IRD) is read-only. Numeric fields arrive as an integer cast into
 * ValuePtr; pointer fields (DATA_PTR / INDICATOR_PTR / OCTET_LENGTH_PTR) arrive
 * as the pointer itself. */
SQLRETURN SQL_API SQLSetDescField(SQLHDESC DescriptorHandle, SQLSMALLINT RecNumber,
                                  SQLSMALLINT FieldIdentifier, SQLPOINTER ValuePtr,
                                  SQLINTEGER BufferLength)
{
  (void)BufferLength;
  OdbcDesc *d = (OdbcDesc *)DescriptorHandle;
  if (d == NULL)
    return SQL_INVALID_HANDLE;
  seer_odbc_diag_clear(d);
  if (d->kind == SEER_DESC_IRD)
    return seer_odbc_diag(d, "HY016", 0, "Cannot modify an implementation row descriptor",
                          SQL_ERROR);
  OdbcStmt *s = (OdbcStmt *)d->stmt;
  SQLINTEGER ival = (SQLINTEGER)(intptr_t)ValuePtr;

  if (FieldIdentifier == SQL_DESC_COUNT) { /* header: record count */
    OdbcBindSet *bs = desc_binds(d);
    if (bs != NULL) { /* ARD count tracks result cols */
      if (ival >= 0 && ival < bs->num_binds)
        bs->num_binds = ival;
      return SQL_SUCCESS;
    }
    return desc_ensure_params(s, ival > 0 ? ival : 0);
  }

  if (RecNumber < 1)
    return seer_odbc_diag(d, "07009", 0, "Invalid descriptor index", SQL_ERROR);
  int i = RecNumber - 1;

  if (desc_binds(d) != NULL) {
    if (seer_odbc_bindset_ensure(desc_binds(d), RecNumber) != 0) /* as SQLBindCol (#244) */
      return seer_odbc_diag(d, "HY001", 0, "Out of memory", SQL_ERROR);
    OdbcBind *b = &desc_binds(d)->binds[i];
    switch (FieldIdentifier) {
    case SQL_DESC_TYPE:
    case SQL_DESC_CONCISE_TYPE:
      b->target_type = (SQLSMALLINT)ival;
      break;
    case SQL_DESC_DATA_PTR:
      b->buf = ValuePtr;
      b->bound = (ValuePtr != NULL);
      break;
    case SQL_DESC_OCTET_LENGTH:
      b->buflen = (SQLLEN)(intptr_t)ValuePtr;
      break;
    case SQL_DESC_INDICATOR_PTR:
    case SQL_DESC_OCTET_LENGTH_PTR:
      b->indicator = (SQLLEN *)ValuePtr;
      break;
    default:
      break; /* lenient on auto/unsupported */
    }
    return SQL_SUCCESS;
  }

  SQLRETURN rc = desc_ensure_params(s, RecNumber); /* APD / IPD -> params */
  if (rc != SQL_SUCCESS)
    return rc;
  OdbcParam *p = &s->params[i];
  if (d->kind == SEER_DESC_APD) {
    switch (FieldIdentifier) {
    case SQL_DESC_TYPE:
    case SQL_DESC_CONCISE_TYPE:
      p->c_type = (SQLSMALLINT)ival;
      break;
    case SQL_DESC_DATA_PTR:
      p->buf = ValuePtr;
      p->bound = 1;
      break;
    case SQL_DESC_OCTET_LENGTH:
      p->buflen = (SQLLEN)(intptr_t)ValuePtr;
      break;
    case SQL_DESC_INDICATOR_PTR:
    case SQL_DESC_OCTET_LENGTH_PTR:
      p->indicator = (SQLLEN *)ValuePtr;
      break;
    default:
      break;
    }
  } else { /* IPD */
    switch (FieldIdentifier) {
    case SQL_DESC_TYPE:
    case SQL_DESC_CONCISE_TYPE:
      p->sql_type = (SQLSMALLINT)ival;
      break;
    case SQL_DESC_PARAMETER_TYPE:
      p->io_type = (SQLSMALLINT)ival;
      break;
    case SQL_DESC_LENGTH:
      p->column_size = (SQLULEN)(intptr_t)ValuePtr;
      break;
    case SQL_DESC_SEER_REF_TYPE: { /* the type a SQL_SEER_REF refers to (#241) */
      free(p->ref_type);
      p->ref_type = NULL;
      if (ValuePtr == NULL)
        break;
      size_t n = BufferLength == SQL_NTS ? strlen((const char *)ValuePtr) : (size_t)BufferLength;
      p->ref_type = malloc(n + 1);
      if (p->ref_type == NULL)
        return seer_odbc_diag(d, "HY001", 0, "Out of memory", SQL_ERROR);
      memcpy(p->ref_type, ValuePtr, n);
      p->ref_type[n] = '\0';
      break;
    }
    default:
      break;
    }
  }
  return SQL_SUCCESS;
}

/* Set a record's common fields in one call (concise form of SQLSetDescField). */
SQLRETURN SQL_API SQLSetDescRec(SQLHDESC DescriptorHandle, SQLSMALLINT RecNumber, SQLSMALLINT Type,
                                SQLSMALLINT SubType, SQLLEN Length, SQLSMALLINT Precision,
                                SQLSMALLINT Scale, SQLPOINTER DataPtr, SQLLEN *StringLengthPtr,
                                SQLLEN *IndicatorPtr)
{
  (void)SubType;
  (void)Precision;
  (void)Scale;
  OdbcDesc *d = (OdbcDesc *)DescriptorHandle;
  if (d == NULL)
    return SQL_INVALID_HANDLE;
  seer_odbc_diag_clear(d);
  if (d->kind == SEER_DESC_IRD)
    return seer_odbc_diag(d, "HY016", 0, "Cannot modify an implementation row descriptor",
                          SQL_ERROR);
  OdbcStmt *s = (OdbcStmt *)d->stmt;
  if (RecNumber < 1)
    return seer_odbc_diag(d, "07009", 0, "Invalid descriptor index", SQL_ERROR);
  int i = RecNumber - 1;
  SQLLEN *ind = IndicatorPtr ? IndicatorPtr : StringLengthPtr;

  if (desc_binds(d) != NULL) {
    if (seer_odbc_bindset_ensure(desc_binds(d), RecNumber) != 0) /* as SQLBindCol (#244) */
      return seer_odbc_diag(d, "HY001", 0, "Out of memory", SQL_ERROR);
    OdbcBind *b = &desc_binds(d)->binds[i];
    b->target_type = Type;
    b->buf = DataPtr;
    b->buflen = Length;
    b->indicator = ind;
    b->bound = (DataPtr != NULL);
    return SQL_SUCCESS;
  }
  SQLRETURN rc = desc_ensure_params(s, RecNumber);
  if (rc != SQL_SUCCESS)
    return rc;
  OdbcParam *p = &s->params[i];
  if (d->kind == SEER_DESC_APD) {
    p->c_type = Type;
    p->buf = DataPtr;
    p->buflen = Length;
    p->indicator = ind;
    p->bound = 1;
  } else { /* IPD */
    p->sql_type = Type;
    p->column_size = (SQLULEN)Length;
  }
  return SQL_SUCCESS;
}

/* One descriptor record, whichever kind it comes from (#289): an application
 * descriptor's (ARD / APD) C type, buffer, length and indicator, an
 * implementation descriptor's (IRD / IPD) SQL type, size, direction and REF
 * type. */
typedef struct {
  SQLSMALLINT type;
  SQLPOINTER buf;
  SQLLEN buflen;
  SQLLEN *indicator;
  int bound;
  SQLULEN size;
  SQLSMALLINT io_type;
  const char *ref_type;
} DescRec;

static int app_desc(SeerDescKind k)
{
  return k == SEER_DESC_ARD || k == SEER_DESC_APD;
}

static DescRec desc_rec_get(OdbcDesc *d, int i)
{
  OdbcStmt *s = (OdbcStmt *)d->stmt;
  SeerDescKind k = d->kind;
  DescRec r = {0};
  r.io_type = SQL_PARAM_INPUT;
  if (desc_binds(d) != NULL) { /* an ARD, or an explicit descriptor (#291) */
    const OdbcBind *b = &desc_binds(d)->binds[i];
    r = (DescRec){b->target_type, b->buf, b->buflen,       b->indicator,
                  b->bound,       0,      SQL_PARAM_INPUT, NULL};
  } else if (k == SEER_DESC_APD) {
    const OdbcParam *p = &s->params[i];
    r = (DescRec){p->c_type, p->buf, p->buflen, p->indicator, p->bound, 0, SQL_PARAM_INPUT, NULL};
  } else if (k == SEER_DESC_IPD) {
    const OdbcParam *p = &s->params[i];
    r.type = p->sql_type;
    r.size = p->column_size;
    r.io_type = p->io_type ? p->io_type : SQL_PARAM_INPUT;
    r.ref_type = p->ref_type;
  } else { /* IRD: the result column as described */
    r.type = (SQLSMALLINT)sql_type_of(seer_stmt_col_type(s->core, i));
    r.size = (SQLULEN)col_meta(s, i).column_size;
  }
  return r;
}

/* Write a record. Between the two classes only the type carries over; the
 * other half of a parameter record (APD vs IPD, one array) is kept. */
static SQLRETURN desc_rec_put(OdbcDesc *d, int i, const DescRec *r, int same)
{
  OdbcStmt *s = (OdbcStmt *)d->stmt;
  SeerDescKind k = d->kind;
  if (desc_binds(d) != NULL) {
    OdbcBind *b = &desc_binds(d)->binds[i];
    *b = same ? (OdbcBind){r->type, r->buf, r->buflen, r->indicator, r->bound}
              : (OdbcBind){r->type, NULL, 0, NULL, 0};
    return SQL_SUCCESS;
  }
  OdbcParam *p = &s->params[i];
  if (k == SEER_DESC_APD) {
    p->c_type = r->type;
    p->buf = same ? r->buf : NULL;
    p->buflen = same ? r->buflen : 0;
    p->indicator = same ? r->indicator : NULL;
    p->bound = same ? r->bound : 0;
    return SQL_SUCCESS;
  }
  p->sql_type = r->type; /* IPD */
  if (!same)
    return SQL_SUCCESS;
  p->column_size = r->size;
  p->io_type = r->io_type;
  char *ref = r->ref_type != NULL ? strdup(r->ref_type) : NULL;
  if (r->ref_type != NULL && ref == NULL)
    return seer_odbc_diag(d, "HY001", 0, "Out of memory", SQL_ERROR);
  free(p->ref_type);
  p->ref_type = ref;
  return SQL_SUCCESS;
}

/* SQLCopyDesc (#289): every record and, between descriptors of one class,
 * the header fields the statement keeps for them (array size, bind type and
 * offset, status and rows-processed pointers). A target IRD is read-only
 * (HY016); a source IRD needs a prepared or executed statement (HY007). */
SQLRETURN SQL_API SQLCopyDesc(SQLHDESC SourceDescHandle, SQLHDESC TargetDescHandle)
{
  OdbcDesc *sd = (OdbcDesc *)SourceDescHandle, *td = (OdbcDesc *)TargetDescHandle;
  if (sd == NULL || td == NULL)
    return SQL_INVALID_HANDLE;
  seer_odbc_diag_clear(td);
  if (td->kind == SEER_DESC_IRD)
    return seer_odbc_diag(td, "HY016", 0, "Cannot modify an implementation row descriptor",
                          SQL_ERROR);
  if (sd == td)
    return SQL_SUCCESS;
  OdbcStmt *ss = (OdbcStmt *)sd->stmt, *ts = (OdbcStmt *)td->stmt;
  if (sd->kind == SEER_DESC_IRD && ss->core == NULL &&
      (ss->sql == NULL || seer_odbc_describe_prepared(ss) != SQL_SUCCESS || ss->core == NULL))
    return seer_odbc_diag(td, "HY007", 0, "Associated statement is not prepared", SQL_ERROR);

  int n = desc_count(sd);
  int same = app_desc(sd->kind) == app_desc(td->kind);
  DescRec *recs = n > 0 ? calloc((size_t)n, sizeof *recs) : NULL;
  if (n > 0 && recs == NULL)
    return seer_odbc_diag(td, "HY001", 0, "Out of memory", SQL_ERROR);
  for (int i = 0; i < n; i++) /* read all first: source and target may share arrays */
    recs[i] = desc_rec_get(sd, i);
  char **refs = n > 0 ? calloc((size_t)n, sizeof *refs) : NULL;
  for (int i = 0; refs != NULL && i < n; i++)
    if (recs[i].ref_type != NULL && (refs[i] = strdup(recs[i].ref_type)) != NULL)
      recs[i].ref_type = refs[i];

  SQLRETURN rc = SQL_SUCCESS;
  OdbcBindSet *tb = desc_binds(td); /* an ARD's or an explicit descriptor's records */
  if (tb != NULL) {
    if (seer_odbc_bindset_ensure(tb, n) != 0)
      rc = seer_odbc_diag(td, "HY001", 0, "Out of memory", SQL_ERROR);
  } else {
    rc = desc_ensure_params(ts, n);
  }
  for (int i = 0; rc == SQL_SUCCESS && i < n; i++)
    rc = desc_rec_put(td, i, &recs[i], same);
  if (rc == SQL_SUCCESS) { /* the count: records past it unbound */
    if (tb != NULL) {
      for (int i = n; i < tb->num_binds; i++)
        tb->binds[i] = (OdbcBind){0};
      tb->num_binds = n;
    } else if (td->kind == SEER_DESC_APD) {
      for (int i = n; i < ts->num_params; i++)
        ts->params[i].bound = 0, ts->params[i].buf = NULL, ts->params[i].indicator = NULL;
    }
  }
  /* The header fields are the statement's, copied only between implicit
   * descriptors: an explicit descriptor has its records only (#291). */
  bool copy_header = !sd->is_explicit && !td->is_explicit && rc == SQL_SUCCESS && same;
  if (copy_header && app_desc(sd->kind)) {
    int sr = sd->kind == SEER_DESC_ARD, tr = td->kind == SEER_DESC_ARD;
    SQLULEN size = sr ? ss->row_array_size : ss->paramset_size;
    SQLULEN bind = sr ? ss->row_bind_type : ss->param_bind_type;
    SQLLEN *off = sr ? ss->row_bind_offset : ss->param_bind_offset;
    SQLUSMALLINT *op = sr ? ss->row_operation : ss->param_operation;
    *(tr ? &ts->row_array_size : &ts->paramset_size) = size;
    *(tr ? &ts->row_bind_type : &ts->param_bind_type) = bind;
    *(tr ? &ts->row_bind_offset : &ts->param_bind_offset) = off;
    *(tr ? &ts->row_operation : &ts->param_operation) = op;
  } else if (copy_header) { /* IRD / IPD -> IPD */
    ts->param_status = sd->kind == SEER_DESC_IRD ? ss->row_status : ss->param_status;
    ts->params_processed = sd->kind == SEER_DESC_IRD ? ss->rows_fetched : ss->params_processed;
  }
  for (int i = 0; refs != NULL && i < n; i++)
    free(refs[i]);
  free(refs);
  free(recs);
  return rc;
}

int seer_odbc_ensure_binds(OdbcStmt *s, int n) /* the current ARD: own, or explicit (#291) */
{
  return seer_odbc_bindset_ensure(s->ab, n);
}

SQLRETURN SQL_API SQLBindCol(SQLHSTMT StatementHandle, SQLUSMALLINT ColumnNumber,
                             SQLSMALLINT TargetType, SQLPOINTER TargetValuePtr, SQLLEN BufferLength,
                             SQLLEN *StrLen_or_IndPtr)
{
  OdbcStmt *s = (OdbcStmt *)StatementHandle;
  if (s == NULL)
    return SQL_INVALID_HANDLE;
  seer_odbc_diag_clear(s);
  if (ColumnNumber < 1)
    return seer_odbc_diag(s, "07009", 0, "Invalid column number", SQL_ERROR);
  /* Any column, before or after the execute: a number past the result's
   * columns is reported when a fetch would fill it (#244). */
  if (ColumnNumber > s->ab->num_binds && (TargetValuePtr != NULL || StrLen_or_IndPtr != NULL) &&
      seer_odbc_ensure_binds(s, ColumnNumber) != 0)
    return seer_odbc_diag(s, "HY001", 0, "Out of memory", SQL_ERROR);
  if (ColumnNumber > s->ab->num_binds)
    return SQL_SUCCESS; /* unbinding a column never bound */

  OdbcBind *b = &s->ab->binds[ColumnNumber - 1];
  if (TargetValuePtr == NULL && StrLen_or_IndPtr == NULL) {
    b->bound = 0; /* unbind */
    return SQL_SUCCESS;
  }
  b->target_type = TargetType;
  b->buf = TargetValuePtr;
  b->buflen = BufferLength;
  b->indicator = StrLen_or_IndPtr;
  b->bound = 1;
  return SQL_SUCCESS;
}

/* Element stride for a column-wise bound C buffer: the buffer length for
 * variable types, else the fixed C-type width. */
static size_t c_elem_stride(SQLSMALLINT t, SQLLEN buflen)
{
  /* A fixed-length type is its own size, whatever BufferLength says (ODBC
   * ignores it for them): SQL_C_NUMERIC and the interval structs too (#314). */
  size_t fixed = seer_odbc_c_fixed_size(t);
  if (fixed > 0)
    return fixed;
  return buflen > 0 ? (size_t)buflen : sizeof(SQLLEN);
}

/* SQL_ATTR_MAX_LENGTH (#248): a character or binary value as at most that
 * many bytes, text cut at a UTF-8 character's start. As ODBC has it, the
 * value is returned as though it were that long: the cut length, no 01004. */
static size_t max_length_cap(OdbcStmt *s, int col, const void *val, size_t vlen, int is_binary)
{
  if (s->max_length == 0 || vlen <= s->max_length || val == NULL)
    return vlen;
  switch (seer_stmt_col_type(s->core, col)) {
  case ORA_TYPE_VARCHAR:
  case ORA_TYPE_CHAR:
  case ORA_TYPE_LONG:
  case ORA_TYPE_CLOB:
  case ORA_TYPE_RAW:
  case ORA_TYPE_LONGRAW:
  case ORA_TYPE_BLOB:
    break;
  default:
    return vlen;
  }
  size_t n = (size_t)s->max_length;
  const unsigned char *p = val;
  while (!is_binary && n > 0 && (p[n] & 0xC0) == 0x80)
    n--; /* p[n], the first byte cut, continues a character */
  return n;
}

/* Deliver the current core row into the bound columns for rowset element `row`.
 * Column-wise (row_bind_type 0): value at buf + row*elem_stride, indicator at
 * &indicator[row]. Row-wise: both at + row*row_bind_type. Both past the row
 * bind offset. */
static SQLRETURN deliver_row(OdbcStmt *s, SQLULEN row)
{
  SQLRETURN ret = SQL_SUCCESS;
  if (s->retrieve_data == SQL_RD_OFF) /* positioned, nothing filled (#250) */
    return SQL_SUCCESS;
  int ncols = odbc_visible_cols(s);
  for (int i = 0; i < s->ab->num_binds; i++) {
    OdbcBind *b = &s->ab->binds[i];
    if (!b->bound)
      continue;
    if (i >= ncols) /* bound, but the result has no such column */
      return seer_odbc_diag(s, "07009", 0, "Bound column number exceeds the result's columns",
                            SQL_ERROR);
    const void *val = NULL;
    size_t vlen = 0;
    int is_null = 0, is_binary = 0;
    if (seer_stmt_get_data(s->core, i, &val, &vlen, &is_null, &is_binary) == SEER_EDB) {
      /* A value the server refused (#158): its error, the column left as is. */
      ret = seer_odbc_exec_error(s, SEER_EDB);
      continue;
    }

    /* Column-wise or row-wise (the struct size), past the bind offset
     * (#243). */
    vlen = max_length_cap(s, i, val, vlen, is_binary);
    const SQLSMALLINT ct = seer_odbc_col_c_type(s, i, b->target_type); /* #316 */
    void *buf = seer_odbc_bound_at(b->buf, s->row_bind_offset, s->row_bind_type,
                                   c_elem_stride(ct, b->buflen), row);
    SQLLEN *ind =
        seer_odbc_bound_at(b->indicator, s->row_bind_offset, s->row_bind_type, sizeof(SQLLEN), row);
    const char *state = NULL;
    char cut[64];
    const char *cv = tz_cut(s, i, val, &vlen, ct, cut);
    SQLRETURN r = seer_odbc_convert(cv ? cv : "", vlen, is_null, is_binary, ct, buf, b->buflen, ind,
                                    NULL, &state, sql_type_of(seer_stmt_col_type(s->core, i)));
    /* Each column's own state: truncation, or a value that won't convert
     * (#314), which makes the row an error row. Appended, with the row's
     * number in the rowset: replacing the queue kept only the last column's,
     * and no row number said which row it was (#369). */
    if (r == SQL_SUCCESS_WITH_INFO || r == SQL_ERROR)
      seer_odbc_diag_add(s, state ? state : "01004", 0, seer_odbc_convert_text(state),
                         (SQLLEN)row + 1);
    if (r == SQL_ERROR)
      ret = SQL_ERROR;
    else if (r == SQL_SUCCESS_WITH_INFO && ret == SQL_SUCCESS)
      ret = SQL_SUCCESS_WITH_INFO;
  }
  return ret;
}

/* Deliver the rowset of up to row_array_size rows starting at result-set row
 * `start`. Sets rows_fetched/row_status and the rowset cursor. SQL_NO_DATA if
 * `start` is outside the result set (no rows delivered). */
static SQLRETURN fetch_rowset(OdbcStmt *s, long start)
{
  SQLULEN R = s->row_array_size ? s->row_array_size : 1;
  SQLULEN got = 0, errs = 0;
  SQLRETURN ret = SQL_SUCCESS;

  for (SQLULEN row = 0; row < R; row++) {
    SeerStatus st = (start < 0) ? SEER_ENODATA : seer_stmt_set_row(s->core, start + (long)row);
    if (st == SEER_ENODATA) {
      if (s->row_status)
        for (SQLULEN k = row; k < R; k++)
          s->row_status[k] = SQL_ROW_NOROW;
      break;
    }
    if (st != SEER_OK)
      return seer_odbc_diag(s, seer_odbc_sqlstate(st), 0, seer_strerror(st), SQL_ERROR);

    SQLRETURN r = deliver_row(s, row);
    if (r == SQL_ERROR)
      errs++;
    else if (r == SQL_SUCCESS_WITH_INFO)
      ret = SQL_SUCCESS_WITH_INFO;
    if (s->row_status) /* a truncated row says so (#369) */
      s->row_status[row] = r == SQL_ERROR               ? SQL_ROW_ERROR
                           : r == SQL_SUCCESS_WITH_INFO ? SQL_ROW_SUCCESS_WITH_INFO
                                                        : SQL_ROW_SUCCESS;
    got++;
  }

  if (s->rows_fetched)
    *s->rows_fetched = got;
  s->rowset_start = (got > 0) ? start : -1;
  s->cur_row = s->rowset_start; /* WHERE CURRENT OF: the rowset's first row (#288) */
  s->getdata_col = -1;          /* SQLGetData targets the last fetched row */
  s->getdata_off = 0;
  s->getdata_done = 0;

  if (got == 0)
    return SQL_NO_DATA;
  /* Each row's diagnostics are already queued. An error row leaves the
   * others delivered (SQL_SUCCESS_WITH_INFO), unless every row is one. */
  if (errs > 0)
    return errs == got ? SQL_ERROR : SQL_SUCCESS_WITH_INFO;
  return ret;
}

SQLRETURN SQL_API SQLFetch(SQLHSTMT StatementHandle)
{
  OdbcStmt *s = (OdbcStmt *)StatementHandle;
  if (s == NULL)
    return SQL_INVALID_HANDLE;
  seer_odbc_diag_clear(s);
  if (s->core == NULL)
    return seer_odbc_diag(s, "24000", 0, "No open cursor", SQL_ERROR);

  SQLULEN R = s->row_array_size ? s->row_array_size : 1;
  long start = (s->rowset_start < 0) ? 0 : s->rowset_start + (long)R;
  return fetch_rowset(s, start);
}

SQLRETURN SQL_API SQLFetchScroll(SQLHSTMT StatementHandle, SQLSMALLINT FetchOrientation,
                                 SQLLEN FetchOffset)
{
  OdbcStmt *s = (OdbcStmt *)StatementHandle;
  if (s == NULL)
    return SQL_INVALID_HANDLE;
  seer_odbc_diag_clear(s);
  if (s->core == NULL)
    return seer_odbc_diag(s, "24000", 0, "No open cursor", SQL_ERROR);

  long R = (long)(s->row_array_size ? s->row_array_size : 1);
  long nrows = (long)seer_stmt_row_count(s->core);
  long cur = s->rowset_start; /* -1 before the first fetch */
  long start;

  switch (FetchOrientation) {
  case SQL_FETCH_NEXT:
    start = (cur < 0) ? 0 : cur + R;
    break;
  case SQL_FETCH_PRIOR:
    if (cur <= 0) /* already at/before the first rowset */
      return fetch_rowset(s, -1);
    start = (cur - R < 0) ? 0 : cur - R;
    break;
  case SQL_FETCH_FIRST:
    start = 0;
    break;
  case SQL_FETCH_LAST:
    start = (nrows > R) ? nrows - R : 0;
    break;
  case SQL_FETCH_ABSOLUTE:
    if (FetchOffset > 0)
      start = FetchOffset - 1; /* 1-based */
    else if (FetchOffset < 0)
      start = nrows + FetchOffset; /* from end */
    else
      start = -1; /* 0 = before start */
    break;
  case SQL_FETCH_RELATIVE:
    start = ((cur < 0) ? 0 : cur) + (long)FetchOffset;
    break;
  case SQL_FETCH_BOOKMARK:
    return seer_odbc_diag(s, "HYC00", 0, "Bookmarks not supported", SQL_ERROR);
  default:
    return seer_odbc_diag(s, "HY106", 0, "Invalid fetch orientation", SQL_ERROR);
  }

  if (start >= nrows || start < 0)
    return fetch_rowset(s, -1); /* positioned before/after the result set */
  return fetch_rowset(s, start);
}

/* Bookmark-based bulk insert/update/delete/fetch. Not implemented: SeerODBC
 * exposes no bookmarks (SQL_ATTR_USE_BOOKMARKS stays off), so there is nothing
 * to operate on. Positioned update/delete is available via SQLSetPos instead.
 * Reported unsupported by SQLGetFunctions; this returns the precise HYC00 if a
 * Driver Manager dispatches the call anyway. */
SQLRETURN SQL_API SQLBulkOperations(SQLHSTMT StatementHandle, SQLSMALLINT Operation)
{
  (void)Operation;
  OdbcStmt *s = (OdbcStmt *)StatementHandle;
  if (s == NULL)
    return SQL_INVALID_HANDLE;
  seer_odbc_diag_clear(s);
  return seer_odbc_diag(s, "HYC00", 0,
                        "SQLBulkOperations (bookmark bulk ops) not implemented; "
                        "use SQLSetPos for positioned update/delete",
                        SQL_ERROR);
}

SQLRETURN SQL_API SQLSetPos(SQLHSTMT StatementHandle, SQLSETPOSIROW RowNumber,
                            SQLUSMALLINT Operation, SQLUSMALLINT LockType)
{
  (void)LockType;
  OdbcStmt *s = (OdbcStmt *)StatementHandle;
  if (s == NULL)
    return SQL_INVALID_HANDLE;
  seer_odbc_diag_clear(s);
  if (s->core == NULL || s->rowset_start < 0)
    return seer_odbc_diag(s, "24000", 0, "No row set positioned", SQL_ERROR);

  SQLULEN R = s->row_array_size ? s->row_array_size : 1;
  if (RowNumber > (SQLSETPOSIROW)R)
    return seer_odbc_diag(s, "HY107", 0, "Row number out of range", SQL_ERROR);

  switch (Operation) {
  case SQL_POSITION: {
    /* RowNumber 0 means "the first row"; otherwise it is 1-based within the
     * rowset. Point the cursor there so SQLGetData reads it. */
    long off = (RowNumber > 0) ? (long)RowNumber - 1 : 0;
    if (seer_stmt_set_row(s->core, s->rowset_start + off) != SEER_OK)
      return seer_odbc_diag(s, "HY107", 0, "Row number out of range", SQL_ERROR);
    s->cur_row = s->rowset_start + off; /* the row WHERE CURRENT OF means (#288) */
    s->getdata_col = -1;
    s->getdata_off = 0;
    s->getdata_done = 0;
    return SQL_SUCCESS;
  }
  case SQL_REFRESH:
    return fetch_rowset(s, s->rowset_start);
  case SQL_DELETE:
  case SQL_UPDATE: {
    if (!s->updatable)
      return seer_odbc_diag(s, "HYC00", 0,
                            "Cursor is not updatable (set SQL_ATTR_CONCURRENCY "
                            "and use a single-table SELECT)",
                            SQL_ERROR);
    /* RowNumber 0 -> every row of the rowset (row = -1); else the 1-based
     * row within the current rowset. */
    long row = (RowNumber > 0) ? s->rowset_start + (long)RowNumber - 1 : -1;
    return (Operation == SQL_DELETE) ? seer_odbc_pos_delete(s, row) : seer_odbc_pos_update(s, row);
  }
  case SQL_ADD:
  default:
    return seer_odbc_diag(s, "HYC00", 0, "Operation not supported", SQL_ERROR);
  }
}

SQLRETURN SQL_API SQLGetData(SQLHSTMT StatementHandle, SQLUSMALLINT ColumnNumber,
                             SQLSMALLINT TargetType, SQLPOINTER TargetValuePtr, SQLLEN BufferLength,
                             SQLLEN *StrLen_or_IndPtr)
{
  OdbcStmt *s = (OdbcStmt *)StatementHandle;
  if (s == NULL)
    return SQL_INVALID_HANDLE;
  seer_odbc_diag_clear(s);
  if (s->core == NULL)
    return seer_odbc_diag(s, "24000", 0, "No open cursor", SQL_ERROR);
  if (ColumnNumber < 1 || ColumnNumber > (SQLUSMALLINT)odbc_visible_cols(s))
    return seer_odbc_diag(s, "07009", 0, "Invalid column number", SQL_ERROR);

  int col = ColumnNumber - 1;
  if ((int)ColumnNumber != s->getdata_col) {
    s->getdata_col = (int)ColumnNumber;
    s->getdata_off = 0;
    s->getdata_done = 0;
  }

  const void *val = NULL;
  size_t vlen = 0;
  int is_null = 0, is_binary = 0;
  SeerStatus gst = seer_stmt_get_data(s->core, col, &val, &vlen, &is_null, &is_binary);
  if (gst != SEER_OK) /* a value the server refused carries its ORA text (#158) */
    return seer_odbc_exec_error(s, gst);
  if (!is_null)
    vlen = max_length_cap(s, col, val, vlen, is_binary);

  /* A repeat call after the value was fully returned signals end-of-column.
   * Known by the last piece having fitted, not by comparing the offset with
   * vlen: the offset counts the target's bytes (UTF-16 for SQL_C_WCHAR),
   * vlen the value's UTF-8 ones (#351). */
  if (!is_null && s->getdata_done)
    return SQL_NO_DATA;

  /* SQL_ARD_TYPE: the type the column's ARD record names (#314). */
  if (TargetType == SQL_ARD_TYPE)
    TargetType = col < s->ab->num_binds && s->ab->binds[col].target_type != 0
                     ? s->ab->binds[col].target_type
                     : SQL_C_DEFAULT;
  TargetType = seer_odbc_col_c_type(s, col, TargetType); /* SQL_C_DEFAULT (#316) */

  const char *state = NULL;
  char cut[64];
  const char *cv = tz_cut(s, col, val, &vlen, TargetType, cut);
  SQLRETURN r = seer_odbc_convert(cv ? cv : "", vlen, is_null, is_binary, TargetType,
                                  TargetValuePtr, BufferLength, StrLen_or_IndPtr, &s->getdata_off,
                                  &state, sql_type_of(seer_stmt_col_type(s->core, col)));
  /* A variable-length target got the rest of the value: the next call on this
   * column is SQL_NO_DATA (#351). */
  if (r == SQL_SUCCESS && !is_null && seer_odbc_c_fixed_size(TargetType) == 0 &&
      TargetValuePtr != NULL)
    s->getdata_done = 1;
  if (r == SQL_SUCCESS_WITH_INFO || r == SQL_ERROR)
    return seer_odbc_diag(s, state ? state : "01004", 0, seer_odbc_convert_text(state), r);
  return r;
}

SQLRETURN SQL_API SQLRowCount(SQLHSTMT StatementHandle, SQLLEN *RowCountPtr)
{
  OdbcStmt *s = (OdbcStmt *)StatementHandle;
  if (s == NULL)
    return SQL_INVALID_HANDLE;
  seer_odbc_diag_clear(s);
  if (RowCountPtr != NULL)
    *RowCountPtr = s->core ? (SQLLEN)seer_stmt_row_count(s->core) : -1;
  return SQL_SUCCESS;
}

SQLRETURN SQL_API SQLFreeStmt(SQLHSTMT StatementHandle, SQLUSMALLINT Option)
{
  OdbcStmt *s = (OdbcStmt *)StatementHandle;
  if (s == NULL)
    return SQL_INVALID_HANDLE;
  seer_odbc_diag_clear(s);

  switch (Option) {
  case SQL_CLOSE:
    if (s->core != NULL) {
      seer_stmt_close(s->core);
      s->core = NULL;
    }
    s->getdata_col = -1;
    s->getdata_off = 0;
    s->getdata_done = 0;
    s->cur_row = -1; /* closed: no current row for WHERE CURRENT OF (#288) */
    return SQL_SUCCESS;
  case SQL_UNBIND:
    for (int i = 0; i < s->ab->num_binds; i++)
      s->ab->binds[i].bound = 0;
    return SQL_SUCCESS;
  case SQL_RESET_PARAMS:
    if (s->apd_ext != NULL) /* the APD in use has no records left (#291) */
      s->apd_ext->recs.num_binds = 0;
    for (int i = 0; i < s->num_params; i++)
      free(s->params[i].dae_buf), free(s->params[i].ref_type);
    free(s->params);
    s->params = NULL;
    s->num_params = 0;
    s->dae_active = 0;
    s->dae_current = -1;
    return SQL_SUCCESS;
  default:
    return SQL_SUCCESS;
  }
}

SQLRETURN SQL_API SQLCloseCursor(SQLHSTMT StatementHandle)
{
  OdbcStmt *s = (OdbcStmt *)StatementHandle;
  if (s == NULL)
    return SQL_INVALID_HANDLE;
  seer_odbc_diag_clear(s);
  if (s->core == NULL)
    return seer_odbc_diag(s, "24000", 0, "No open cursor", SQL_ERROR);
  seer_stmt_close(s->core);
  s->core = NULL;
  s->getdata_col = -1;
  s->getdata_off = 0;
  s->getdata_done = 0;
  s->cur_row = -1;
  return SQL_SUCCESS;
}

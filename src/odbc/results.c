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
  case ORA_TYPE_TIMESTAMPTZ:
  case ORA_TYPE_TIMESTAMPLTZ:
    return 29;
  case ORA_TYPE_RID:
  case ORA_TYPE_ROWID:
    /* The rowid's 18-character text. 8i and 9i describe a ROWID with a 1-byte
     * buffer, and a column size of 1 had applications cut it to its first
     * characters (isql showed "AAAAD"). */
    return 18;
  default:
    return max_size > 0 ? max_size : 4000;
  }
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
  if (ColumnSizePtr != NULL)
    *ColumnSizePtr = (SQLULEN)display_size_of(ora_type, max_size);
  if (DecimalDigitsPtr != NULL)
    *DecimalDigitsPtr = 0;
  if (NullablePtr != NULL)
    *NullablePtr = seer_stmt_col_nullable(s->core, col) ? SQL_NULLABLE : SQL_NO_NULLS;
  return SQL_SUCCESS;
}

SQLRETURN SQL_API SQLColAttribute(SQLHSTMT StatementHandle, SQLUSMALLINT ColumnNumber,
                                  SQLUSMALLINT FieldIdentifier, SQLPOINTER CharacterAttributePtr,
                                  SQLSMALLINT BufferLength, SQLSMALLINT *StringLengthPtr,
                                  SQLLEN *NumericAttributePtr)
{
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
  int max_size = seer_stmt_col_size(s->core, col);
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
  case SQL_DESC_LENGTH:
  case SQL_DESC_DISPLAY_SIZE:
  case SQL_DESC_OCTET_LENGTH:
  case SQL_DESC_PRECISION:
  case SQL_COLUMN_PRECISION:
    if (NumericAttributePtr)
      *NumericAttributePtr = display_size_of(ora_type, max_size);
    return SQL_SUCCESS;
  case SQL_DESC_SCALE:
    if (NumericAttributePtr)
      *NumericAttributePtr = 0;
    return SQL_SUCCESS;
  case SQL_DESC_NULLABLE:
    if (NumericAttributePtr)
      *NumericAttributePtr = seer_stmt_col_nullable(s->core, col) ? SQL_NULLABLE : SQL_NO_NULLS;
    return SQL_SUCCESS;
  case SQL_DESC_UNSIGNED:
    if (NumericAttributePtr)
      *NumericAttributePtr = SQL_FALSE;
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

/* Advance to the next result set. The only multi-result source SeerODBC
 * produces is 23ai/12c implicit results (DBMS_SQL.RETURN_RESULT): each call
 * drains the next implicit cursor and makes it current. SQL_NO_DATA when none
 * remain (PEP-249 / ODBC contract). */
SQLRETURN SQL_API SQLMoreResults(SQLHSTMT StatementHandle)
{
  OdbcStmt *s = (OdbcStmt *)StatementHandle;
  if (s == NULL)
    return SQL_INVALID_HANDLE;
  seer_odbc_diag_clear(s);
  if (s->core == NULL)
    return SQL_NO_DATA;

  SeerStatus st = seer_stmt_next_result(s->core);
  if (st == SEER_ENODATA)
    return SQL_NO_DATA;
  if (st != SEER_OK)
    return seer_odbc_diag(s, seer_odbc_sqlstate(st), 0, seer_strerror(st), SQL_ERROR);

  /* Rebuild the result-column view for the now-current set. */
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

/* ----------------------------------------------------------- descriptors */

/* Number of records in a descriptor: result columns (IRD), bound result columns
 * (ARD), or parameters (APD/IPD). */
static int desc_count(OdbcStmt *s, SeerDescKind kind)
{
  switch (kind) {
  case SEER_DESC_IRD:
    return s->core != NULL ? odbc_visible_cols(s) : 0;
  case SEER_DESC_ARD:
    return s->num_binds;
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
  int count = desc_count(s, d->kind);

  if (FieldIdentifier == SQL_DESC_COUNT) {
    if (ValuePtr != NULL)
      *(SQLSMALLINT *)ValuePtr = (SQLSMALLINT)count;
    return SQL_SUCCESS;
  }
  if (RecNumber < 1 || RecNumber > count)
    return seer_odbc_diag(d, "07009", 0, "Invalid descriptor index", SQL_ERROR);
  int i = RecNumber - 1;

  if (d->kind == SEER_DESC_IRD && s->core != NULL) {
    int ora = seer_stmt_col_type(s->core, i);
    int max = seer_stmt_col_size(s->core, i);
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
    case SQL_DESC_LENGTH:
      if (ValuePtr)
        *(SQLULEN *)ValuePtr = (SQLULEN)display_size_of(ora, max);
      return SQL_SUCCESS;
    case SQL_DESC_OCTET_LENGTH:
      if (ValuePtr)
        *(SQLLEN *)ValuePtr = display_size_of(ora, max);
      return SQL_SUCCESS;
    case SQL_DESC_PRECISION:
      if (ValuePtr)
        *(SQLSMALLINT *)ValuePtr = (SQLSMALLINT)display_size_of(ora, max);
      return SQL_SUCCESS;
    case SQL_DESC_SCALE:
      if (ValuePtr)
        *(SQLSMALLINT *)ValuePtr = 0;
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
  } else if (FieldIdentifier == SQL_DESC_TYPE || FieldIdentifier == SQL_DESC_CONCISE_TYPE) {
    SQLSMALLINT t = 0;
    if (d->kind == SEER_DESC_ARD && s->binds != NULL)
      t = s->binds[i].target_type;
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
  if (RecNumber < 1 || RecNumber > desc_count(s, d->kind))
    return SQL_NO_DATA;
  int i = RecNumber - 1;

  if (SubTypePtr)
    *SubTypePtr = 0;
  if (ScalePtr)
    *ScalePtr = 0;
  if (d->kind == SEER_DESC_IRD && s->core != NULL) {
    int ora = seer_stmt_col_type(s->core, i);
    int max = seer_stmt_col_size(s->core, i);
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
    if (LengthPtr)
      *LengthPtr = display_size_of(ora, max);
    if (PrecisionPtr)
      *PrecisionPtr = (SQLSMALLINT)display_size_of(ora, max);
    if (NullablePtr)
      *NullablePtr = seer_stmt_col_nullable(s->core, i) ? SQL_NULLABLE : SQL_NO_NULLS;
  } else {
    if (Name && BufferLength > 0)
      Name[0] = '\0';
    if (StringLengthPtr)
      *StringLengthPtr = 0;
    if (TypePtr)
      *TypePtr = (d->kind == SEER_DESC_ARD && s->binds)    ? s->binds[i].target_type
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
    if (d->kind == SEER_DESC_ARD) {        /* ARD count tracks result cols */
      if (ival >= 0 && ival < s->num_binds)
        s->num_binds = ival;
      return SQL_SUCCESS;
    }
    return desc_ensure_params(s, ival > 0 ? ival : 0);
  }

  if (RecNumber < 1)
    return seer_odbc_diag(d, "07009", 0, "Invalid descriptor index", SQL_ERROR);
  int i = RecNumber - 1;

  if (d->kind == SEER_DESC_ARD) {
    if (RecNumber > s->num_binds)
      return seer_odbc_diag(d, "07009", 0, "Invalid descriptor index", SQL_ERROR);
    OdbcBind *b = &s->binds[i];
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

  if (d->kind == SEER_DESC_ARD) {
    if (RecNumber > s->num_binds)
      return seer_odbc_diag(d, "07009", 0, "Invalid descriptor index", SQL_ERROR);
    OdbcBind *b = &s->binds[i];
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

SQLRETURN SQL_API SQLBindCol(SQLHSTMT StatementHandle, SQLUSMALLINT ColumnNumber,
                             SQLSMALLINT TargetType, SQLPOINTER TargetValuePtr, SQLLEN BufferLength,
                             SQLLEN *StrLen_or_IndPtr)
{
  OdbcStmt *s = (OdbcStmt *)StatementHandle;
  if (s == NULL)
    return SQL_INVALID_HANDLE;
  seer_odbc_diag_clear(s);
  if (ColumnNumber < 1 || ColumnNumber > (SQLUSMALLINT)s->num_binds)
    return seer_odbc_diag(s, "07009", 0, "Invalid column number", SQL_ERROR);

  OdbcBind *b = &s->binds[ColumnNumber - 1];
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
  if (buflen > 0)
    return (size_t)buflen;
  switch (t) {
  case SQL_C_SLONG:
  case SQL_C_LONG:
  case SQL_C_ULONG:
    return sizeof(SQLINTEGER);
  case SQL_C_SSHORT:
  case SQL_C_SHORT:
  case SQL_C_USHORT:
    return sizeof(SQLSMALLINT);
  case SQL_C_SBIGINT:
  case SQL_C_UBIGINT:
    return sizeof(SQLBIGINT);
  case SQL_C_STINYINT:
  case SQL_C_TINYINT:
  case SQL_C_UTINYINT:
  case SQL_C_BIT:
    return 1;
  case SQL_C_FLOAT:
    return sizeof(SQLREAL);
  case SQL_C_DOUBLE:
    return sizeof(SQLDOUBLE);
  case SQL_C_TYPE_TIMESTAMP:
  case SQL_C_TIMESTAMP:
    return sizeof(SQL_TIMESTAMP_STRUCT);
  case SQL_C_TYPE_DATE:
  case SQL_C_DATE:
    return sizeof(SQL_DATE_STRUCT);
  case SQL_C_TYPE_TIME:
  case SQL_C_TIME:
    return sizeof(SQL_TIME_STRUCT);
  default:
    return sizeof(SQLLEN);
  }
}

/* Deliver the current core row into the bound columns for rowset element `row`.
 * Column-wise (row_bind_type 0): value at buf + row*elem_stride, indicator at
 * &indicator[row]. Row-wise: both at + row*row_bind_type. */
static SQLRETURN deliver_row(OdbcStmt *s, SQLULEN row)
{
  SQLRETURN ret = SQL_SUCCESS;
  for (int i = 0; i < s->num_binds; i++) {
    OdbcBind *b = &s->binds[i];
    if (!b->bound)
      continue;
    const void *val = NULL;
    size_t vlen = 0;
    int is_null = 0, is_binary = 0;
    seer_stmt_get_data(s->core, i, &val, &vlen, &is_null, &is_binary);

    void *buf = b->buf;
    SQLLEN *ind = b->indicator;
    if (s->row_bind_type == 0) { /* column-wise */
      if (buf)
        buf = (char *)buf + row * c_elem_stride(b->target_type, b->buflen);
      if (ind)
        ind = ind + row;
    } else { /* row-wise: row stride = struct size */
      if (buf)
        buf = (char *)buf + row * s->row_bind_type;
      if (ind)
        ind = (SQLLEN *)((char *)ind + row * s->row_bind_type);
    }
    SQLRETURN r = seer_odbc_convert(val ? val : "", vlen, is_null, is_binary, b->target_type, buf,
                                    b->buflen, ind, NULL);
    if (r == SQL_SUCCESS_WITH_INFO)
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
  SQLULEN got = 0;
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
    if (r == SQL_SUCCESS_WITH_INFO)
      ret = SQL_SUCCESS_WITH_INFO;
    if (s->row_status)
      s->row_status[row] = SQL_ROW_SUCCESS;
    got++;
  }

  if (s->rows_fetched)
    *s->rows_fetched = got;
  s->rowset_start = (got > 0) ? start : -1;
  s->getdata_col = -1; /* SQLGetData targets the last fetched row */
  s->getdata_off = 0;

  if (got == 0)
    return SQL_NO_DATA;
  if (ret == SQL_SUCCESS_WITH_INFO)
    seer_odbc_diag(s, "01004", 0, "Data truncated", SQL_SUCCESS_WITH_INFO);
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
    s->getdata_col = -1;
    s->getdata_off = 0;
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
  }

  const void *val = NULL;
  size_t vlen = 0;
  int is_null = 0, is_binary = 0;
  SeerStatus gst = seer_stmt_get_data(s->core, col, &val, &vlen, &is_null, &is_binary);
  if (gst != SEER_OK)
    return seer_odbc_diag(s, seer_odbc_sqlstate(gst), 0, seer_strerror(gst), SQL_ERROR);

  /* A repeat call after the value was fully returned signals end-of-column. */
  if (!is_null && s->getdata_off > 0 && (size_t)s->getdata_off >= vlen)
    return SQL_NO_DATA;

  SQLRETURN r = seer_odbc_convert(val ? val : "", vlen, is_null, is_binary, TargetType,
                                  TargetValuePtr, BufferLength, StrLen_or_IndPtr, &s->getdata_off);
  if (r == SQL_SUCCESS_WITH_INFO)
    return seer_odbc_diag(s, "01004", 0, "Data truncated", SQL_SUCCESS_WITH_INFO);
  if (r == SQL_ERROR)
    return seer_odbc_diag(s, "22002", 0, "Indicator required for NULL", SQL_ERROR);
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
    return SQL_SUCCESS;
  case SQL_UNBIND:
    for (int i = 0; i < s->num_binds; i++)
      s->binds[i].bound = 0;
    return SQL_SUCCESS;
  case SQL_RESET_PARAMS:
    for (int i = 0; i < s->num_params; i++)
      free(s->params[i].dae_buf);
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
  return SQL_SUCCESS;
}

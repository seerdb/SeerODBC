/* Capability reporting: SQLGetInfo / SQLGetFunctions.
 *
 * SQLGetInfo answers the InfoTypes the Driver Manager and consumers query at
 * connect time, several with Oracle-specific answers (identifier quote = ",
 * catalogs absent, schemas present, transactional). Unknown InfoTypes get a
 * benign empty/zero answer so the DM does not abort. The Oracle answer table
 * is tracked in docs/ODBC_CONFORMANCE.md.
 *
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "odbc_internal.h"

static SQLRETURN info_string(const char *val, SQLPOINTER buf, SQLSMALLINT buflen,
                             SQLSMALLINT *strlen_ptr)
{
  size_t n = strlen(val);
  if (strlen_ptr != NULL)
    *strlen_ptr = (SQLSMALLINT)n;
  if (buf != NULL && buflen > 0) {
    SQLSMALLINT c = (SQLSMALLINT)(n < (size_t)buflen - 1 ? n : (size_t)buflen - 1);
    memcpy(buf, val, c);
    ((char *)buf)[c] = '\0';
    if ((size_t)c < n)
      return SQL_SUCCESS_WITH_INFO;
  }
  return SQL_SUCCESS;
}

/* What both cursors do with a rowset (#294): SQLSetPos's operations, any
 * LockType as NO_CHANGE, and positioned UPDATE / DELETE (#288). */
#define CURSOR_CA1                                                                                 \
  (SQL_CA1_NEXT | SQL_CA1_LOCK_NO_CHANGE | SQL_CA1_POS_POSITION | SQL_CA1_POS_UPDATE |             \
   SQL_CA1_POS_DELETE | SQL_CA1_POS_REFRESH | SQL_CA1_POSITIONED_UPDATE |                          \
   SQL_CA1_POSITIONED_DELETE)

static SQLRETURN info_u16(SQLUSMALLINT val, SQLPOINTER buf)
{
  if (buf != NULL)
    *(SQLUSMALLINT *)buf = val;
  return SQL_SUCCESS;
}

static SQLRETURN info_u32(SQLUINTEGER val, SQLPOINTER buf)
{
  if (buf != NULL)
    *(SQLUINTEGER *)buf = val;
  return SQL_SUCCESS;
}

/* The release fields as SQL_DBMS_VER's "##.##.####" (major, minor or update,
 * then the next two fields), followed - as the spec allows - by the full
 * dotted release: e.g. "23.26.0200 Oracle 23.26.2.0.0". */
static void format_dbms_ver(const int v[5], char *out, size_t n)
{
  snprintf(out, n, "%02d.%02d.%04d Oracle %d.%d.%d.%d.%d", v[0], v[1], v[2] * 100 + v[3], v[0],
           v[1], v[2], v[3], v[4]);
}

/* The connected server's release. 10g+ sends it at login; a 9i login does
 * not, so it is asked for once (product_component_version, readable by every
 * user). Cached on the connection; "00.00.0000" if it cannot be had. */
/* The longest identifier: what the server stated at login (128 from 12.2 on),
 * else 30, the limit of 8i to 12.1, which state none. */
static SQLUSMALLINT max_identifier_len(OdbcDbc *c)
{
  int n = c->conn != NULL ? seer_max_identifier_length(c->conn) : 0;
  return (SQLUSMALLINT)(n > 0 && n <= 0xFFFF ? n : 30);
}

static const char *dbms_ver(OdbcDbc *c)
{
  if (c == NULL || c->conn == NULL)
    return "00.00.0000";
  if (c->dbms_ver[0] != '\0')
    return c->dbms_ver;
  int v[5] = {0};
  if (seer_server_version(c->conn, v) == SEER_OK) {
    format_dbms_ver(v, c->dbms_ver, sizeof c->dbms_ver);
    return c->dbms_ver;
  }
  SeerStmt *s = NULL;
  if (seer_stmt_prepare(c->conn,
                        "SELECT version FROM product_component_version "
                        "WHERE product LIKE 'Oracle%' AND ROWNUM = 1",
                        &s) == SEER_OK &&
      seer_stmt_execute(s) == SEER_OK && seer_stmt_fetch(s) == SEER_OK) {
    const char *txt = NULL;
    int isnull = 0;
    if (seer_stmt_get_string(s, 0, &txt, &isnull) == SEER_OK && txt != NULL &&
        sscanf(txt, "%d.%d.%d.%d.%d", &v[0], &v[1], &v[2], &v[3], &v[4]) >= 2)
      format_dbms_ver(v, c->dbms_ver, sizeof c->dbms_ver);
  }
  seer_stmt_close(s);
  return c->dbms_ver[0] != '\0' ? c->dbms_ver : "00.00.0000";
}

int seer_odbc_server_major(OdbcDbc *c)
{
  if (c == NULL || c->conn == NULL)
    return 0;
  int v[5] = {0};
  return seer_server_version(c->conn, v) == SEER_OK ? v[0] : 9;
}

/* Whether the connection is to Oracle 8i (whose SQL has no ANSI joins). */
static bool legacy_8i(OdbcDbc *c)
{
  int v[5] = {0};
  return c != NULL && c->conn != NULL && seer_server_version(c->conn, v) == SEER_OK && v[0] == 8;
}

/* The SQL_CONVERT_<source> answer: the types {fn CONVERT} takes a value of
 * that source type to (#301). Text goes anywhere; numbers to text and
 * numbers; dates and timestamps to text and each other; a long text (a CLOB)
 * only to text. Oracle has no TIME, BIT or interval types to convert, and
 * binary values have no CONVERT form; 8i no CLOB conversion. */
static SQLUINTEGER convert_targets(SQLUSMALLINT source, bool v8i)
{
  const SQLUINTEGER text = SQL_CVT_CHAR | SQL_CVT_VARCHAR | SQL_CVT_WCHAR | SQL_CVT_WVARCHAR |
                           (v8i ? 0 : SQL_CVT_LONGVARCHAR | SQL_CVT_WLONGVARCHAR);
  const SQLUINTEGER num = SQL_CVT_NUMERIC | SQL_CVT_DECIMAL | SQL_CVT_TINYINT | SQL_CVT_SMALLINT |
                          SQL_CVT_INTEGER | SQL_CVT_BIGINT | SQL_CVT_REAL | SQL_CVT_FLOAT |
                          SQL_CVT_DOUBLE;
  const SQLUINTEGER dt = SQL_CVT_DATE | SQL_CVT_TIMESTAMP;
  switch (source) {
  case SQL_CONVERT_CHAR:
  case SQL_CONVERT_VARCHAR:
  case SQL_CONVERT_WCHAR:
  case SQL_CONVERT_WVARCHAR:
    return text | num | dt;
  case SQL_CONVERT_LONGVARCHAR:
  case SQL_CONVERT_WLONGVARCHAR:
    return text;
  case SQL_CONVERT_DATE:
  case SQL_CONVERT_TIMESTAMP:
    return text | dt;
  default: /* the numeric types */
    return text | num;
  }
}

SQLRETURN SQL_API SQLGetInfo(SQLHDBC ConnectionHandle, SQLUSMALLINT InfoType,
                             SQLPOINTER InfoValuePtr, SQLSMALLINT BufferLength,
                             SQLSMALLINT *StringLengthPtr)
{
  OdbcDbc *c = (OdbcDbc *)ConnectionHandle;
  if (c != NULL)
    seer_odbc_diag_clear(c);

  switch (InfoType) {
  /* --- identification --- */
  case SQL_DRIVER_NAME:
#if defined(_WIN32)
    return info_string("seerodbc.dll", InfoValuePtr, BufferLength, StringLengthPtr);
#elif defined(__APPLE__)
    return info_string("libseerodbc.dylib", InfoValuePtr, BufferLength, StringLengthPtr);
#else
    return info_string("libseerodbc.so", InfoValuePtr, BufferLength, StringLengthPtr);
#endif
  case SQL_DRIVER_VER: { /* "##.##.####": 0.4.0 is 00.04.0000 */
    char ver[24];
    snprintf(ver, sizeof ver, "%02d.%02d.%04d", SEERTNS_VERSION_MAJOR, SEERTNS_VERSION_MINOR,
             SEERTNS_VERSION_PATCH);
    return info_string(ver, InfoValuePtr, BufferLength, StringLengthPtr);
  }
  case SQL_DRIVER_ODBC_VER:
    return info_string("03.80", InfoValuePtr, BufferLength, StringLengthPtr);
  case SQL_DBMS_NAME:
    return info_string("Oracle", InfoValuePtr, BufferLength, StringLengthPtr);
  case SQL_DBMS_VER:
    return info_string(dbms_ver(c), InfoValuePtr, BufferLength, StringLengthPtr);
  case SQL_ODBC_VER:
    return info_string("03.80.0000", InfoValuePtr, BufferLength, StringLengthPtr);

  /* --- SQL syntax / naming --- */
  case SQL_IDENTIFIER_QUOTE_CHAR:
    return info_string("\"", InfoValuePtr, BufferLength, StringLengthPtr);
  case SQL_SEARCH_PATTERN_ESCAPE:
    return info_string("\\", InfoValuePtr, BufferLength, StringLengthPtr);
  case SQL_CATALOG_NAME:
    return info_string("N", InfoValuePtr, BufferLength, StringLengthPtr);
  case SQL_CATALOG_NAME_SEPARATOR:
    return info_string(".", InfoValuePtr, BufferLength, StringLengthPtr);
  case SQL_CATALOG_TERM:
    return info_string("", InfoValuePtr, BufferLength, StringLengthPtr);
  case SQL_SCHEMA_TERM:
    return info_string("schema", InfoValuePtr, BufferLength, StringLengthPtr);
  case SQL_TABLE_TERM:
    return info_string("table", InfoValuePtr, BufferLength, StringLengthPtr);
  case SQL_PROCEDURE_TERM:
    return info_string("procedure", InfoValuePtr, BufferLength, StringLengthPtr);
  case SQL_SPECIAL_CHARACTERS:
    return info_string("$#", InfoValuePtr, BufferLength, StringLengthPtr);
  case SQL_IDENTIFIER_CASE:
    return info_u16(SQL_IC_UPPER, InfoValuePtr);
  case SQL_QUOTED_IDENTIFIER_CASE:
    return info_u16(SQL_IC_SENSITIVE, InfoValuePtr);

  /* --- capabilities the DM/apps gate on --- */
  case SQL_ACCESSIBLE_TABLES:
    return info_string("N", InfoValuePtr, BufferLength, StringLengthPtr);
  case SQL_ACCESSIBLE_PROCEDURES:
    return info_string("N", InfoValuePtr, BufferLength, StringLengthPtr);
  case SQL_DATA_SOURCE_READ_ONLY:
    return info_string("N", InfoValuePtr, BufferLength, StringLengthPtr);
  case SQL_NEED_LONG_DATA_LEN:
    return info_string("N", InfoValuePtr, BufferLength, StringLengthPtr);
  case SQL_MULTIPLE_ACTIVE_TXN:
    return info_string("Y", InfoValuePtr, BufferLength, StringLengthPtr);
  case SQL_GETDATA_EXTENSIONS:
    return info_u32(SQL_GD_ANY_COLUMN | SQL_GD_ANY_ORDER | SQL_GD_BOUND, InfoValuePtr);
  case SQL_MAX_COLUMN_NAME_LEN:
  case SQL_MAX_IDENTIFIER_LEN:
  case SQL_MAX_TABLE_NAME_LEN:
  case SQL_MAX_SCHEMA_NAME_LEN:
    return info_u16(max_identifier_len(c), InfoValuePtr);
  case SQL_MAX_CURSOR_NAME_LEN: /* SQLSetCursorName (#288) */
    return info_u16(SEER_MAX_CURSOR_NAME_LEN, InfoValuePtr);
  case SQL_POSITIONED_STATEMENTS: /* WHERE CURRENT OF, rewritten to the ROWID */
    return info_u32(SQL_PS_POSITIONED_DELETE | SQL_PS_POSITIONED_UPDATE, InfoValuePtr);
  case SQL_CATALOG_LOCATION:
    return info_u16(0, InfoValuePtr);
  case SQL_CONCAT_NULL_BEHAVIOR:
    return info_u16(SQL_CB_NULL, InfoValuePtr);
  case SQL_CORRELATION_NAME:
    return info_u16(SQL_CN_ANY, InfoValuePtr);
  case SQL_NON_NULLABLE_COLUMNS:
    return info_u16(SQL_NNC_NON_NULL, InfoValuePtr);

  /* --- transactions --- */
  case SQL_TXN_CAPABLE:
    return info_u16(SQL_TC_ALL, InfoValuePtr);
  case SQL_DEFAULT_TXN_ISOLATION:
    return info_u32(SQL_TXN_READ_COMMITTED, InfoValuePtr);
  case SQL_TXN_ISOLATION_OPTION:
    return info_u32(SQL_TXN_READ_COMMITTED | SQL_TXN_SERIALIZABLE, InfoValuePtr);
  case SQL_CURSOR_COMMIT_BEHAVIOR:
    return info_u16(SQL_CB_PRESERVE, InfoValuePtr);
  case SQL_CURSOR_ROLLBACK_BEHAVIOR:
    return info_u16(SQL_CB_PRESERVE, InfoValuePtr);

  /* --- the connection (#234) --- */
  case SQL_DATA_SOURCE_NAME:
    return info_string(c && c->info_dsn ? c->info_dsn : "", InfoValuePtr, BufferLength,
                       StringLengthPtr);
  case SQL_USER_NAME:
    return info_string(c && c->info_user ? c->info_user : "", InfoValuePtr, BufferLength,
                       StringLengthPtr);
  case SQL_SERVER_NAME:
    return info_string(c && c->info_server ? c->info_server : "", InfoValuePtr, BufferLength,
                       StringLengthPtr);
  case SQL_DATABASE_NAME: /* the current catalog: Oracle has none */
    return info_string("", InfoValuePtr, BufferLength, StringLengthPtr);

  /* --- conformance and SQL support (#234) --- */
  case SQL_SQL_CONFORMANCE:
    return info_u32(SQL_SC_SQL92_ENTRY, InfoValuePtr);
  case SQL_ODBC_INTERFACE_CONFORMANCE:
    return info_u32(SQL_OIC_CORE, InfoValuePtr);
  case SQL_MULT_RESULT_SETS:
    /* A query with a parameter array gives one result set per set, on every
     * release (#431); from 12c a block's implicit results do too (#312). */
    return info_string("Y", InfoValuePtr, BufferLength, StringLengthPtr);
  case SQL_BATCH_SUPPORT:
    /* From 12c a procedure ({call}) returns its implicit results. No explicit
     * batches (Oracle runs one statement at a time), and a procedure's DML
     * gives no separate row counts, so SQL_BATCH_ROW_COUNT stays 0. */
    return info_u32(seer_odbc_server_major(c) >= 12 ? SQL_BS_SELECT_PROC : 0, InfoValuePtr);
  case SQL_PROCEDURES: /* {call ...} */
  case SQL_COLUMN_ALIAS:
  case SQL_LIKE_ESCAPE_CLAUSE: /* {escape ...} */
  case SQL_EXPRESSIONS_IN_ORDERBY:
    return info_string("Y", InfoValuePtr, BufferLength, StringLengthPtr);
  case SQL_ORDER_BY_COLUMNS_IN_SELECT:
  case SQL_ROW_UPDATES:
  case SQL_DESCRIBE_PARAMETER: /* SQLDescribeParam answers a generic default */
    return info_string("N", InfoValuePtr, BufferLength, StringLengthPtr);
  case SQL_OUTER_JOINS:
    /* {oj} becomes ANSI join syntax, which 8.1.7 hasn't. */
    return info_string(legacy_8i(c) ? "N" : "Y", InfoValuePtr, BufferLength, StringLengthPtr);
  case SQL_OJ_CAPABILITIES:
    return info_u32(legacy_8i(c)
                        ? 0
                        : SQL_OJ_LEFT | SQL_OJ_RIGHT | SQL_OJ_FULL | SQL_OJ_NESTED |
                              SQL_OJ_NOT_ORDERED | SQL_OJ_INNER | SQL_OJ_ALL_COMPARISON_OPS,
                    InfoValuePtr);
  /* --- the {fn} scalar functions the preprocessor translates (#301) --- */
  case SQL_STRING_FUNCTIONS: /* no DIFFERENCE */
    return info_u32(
        SQL_FN_STR_ASCII | SQL_FN_STR_BIT_LENGTH | SQL_FN_STR_CHAR | SQL_FN_STR_CHAR_LENGTH |
            SQL_FN_STR_CHARACTER_LENGTH | SQL_FN_STR_CONCAT | SQL_FN_STR_INSERT | SQL_FN_STR_LCASE |
            SQL_FN_STR_LEFT | SQL_FN_STR_LENGTH | SQL_FN_STR_LOCATE | SQL_FN_STR_LOCATE_2 |
            SQL_FN_STR_LTRIM | SQL_FN_STR_OCTET_LENGTH | SQL_FN_STR_POSITION | SQL_FN_STR_REPEAT |
            SQL_FN_STR_REPLACE | SQL_FN_STR_RIGHT | SQL_FN_STR_RTRIM | SQL_FN_STR_SOUNDEX |
            SQL_FN_STR_SPACE | SQL_FN_STR_SUBSTRING | SQL_FN_STR_UCASE,
        InfoValuePtr);
  case SQL_NUMERIC_FUNCTIONS: /* no RAND: SQL can't seed it */
    return info_u32(SQL_FN_NUM_ABS | SQL_FN_NUM_ACOS | SQL_FN_NUM_ASIN | SQL_FN_NUM_ATAN |
                        SQL_FN_NUM_ATAN2 | SQL_FN_NUM_CEILING | SQL_FN_NUM_COS | SQL_FN_NUM_COT |
                        SQL_FN_NUM_DEGREES | SQL_FN_NUM_EXP | SQL_FN_NUM_FLOOR | SQL_FN_NUM_LOG |
                        SQL_FN_NUM_LOG10 | SQL_FN_NUM_MOD | SQL_FN_NUM_PI | SQL_FN_NUM_POWER |
                        SQL_FN_NUM_RADIANS | SQL_FN_NUM_ROUND | SQL_FN_NUM_SIGN | SQL_FN_NUM_SIN |
                        SQL_FN_NUM_SQRT | SQL_FN_NUM_TAN | SQL_FN_NUM_TRUNCATE,
                    InfoValuePtr);
  case SQL_TIMEDATE_FUNCTIONS: /* EXTRACT is Oracle's own, 8i too (#308) */
    return info_u32(SQL_FN_TD_CURRENT_DATE | SQL_FN_TD_CURRENT_TIME | SQL_FN_TD_CURRENT_TIMESTAMP |
                        SQL_FN_TD_CURDATE | SQL_FN_TD_CURTIME | SQL_FN_TD_DAYNAME |
                        SQL_FN_TD_DAYOFMONTH | SQL_FN_TD_DAYOFWEEK | SQL_FN_TD_DAYOFYEAR |
                        SQL_FN_TD_HOUR | SQL_FN_TD_MINUTE | SQL_FN_TD_MONTH | SQL_FN_TD_MONTHNAME |
                        SQL_FN_TD_NOW | SQL_FN_TD_QUARTER | SQL_FN_TD_SECOND |
                        SQL_FN_TD_TIMESTAMPADD | SQL_FN_TD_TIMESTAMPDIFF | SQL_FN_TD_WEEK |
                        SQL_FN_TD_YEAR | SQL_FN_TD_EXTRACT,
                    InfoValuePtr);

  /* The SQL-92 description masks (#306). Each bit is a statement form that
   * runs on the release (tests/odbc: check_sql92_info); forms Oracle spells
   * differently (DROP ... CASCADE CONSTRAINTS, ALTER TABLE ... MODIFY, ON
   * DELETE NO ACTION as the unwritten default) are left out. */
  case SQL_SCHEMA_USAGE:
    return info_u32(SQL_SU_DML_STATEMENTS | SQL_SU_PROCEDURE_INVOCATION | SQL_SU_TABLE_DEFINITION |
                        SQL_SU_INDEX_DEFINITION | SQL_SU_PRIVILEGE_DEFINITION,
                    InfoValuePtr);
  case SQL_CREATE_TABLE:
    return info_u32(SQL_CT_CREATE_TABLE | SQL_CT_GLOBAL_TEMPORARY | SQL_CT_COMMIT_PRESERVE |
                        SQL_CT_COMMIT_DELETE | SQL_CT_COLUMN_CONSTRAINT | SQL_CT_COLUMN_DEFAULT |
                        SQL_CT_TABLE_CONSTRAINT | SQL_CT_CONSTRAINT_NAME_DEFINITION |
                        SQL_CT_CONSTRAINT_INITIALLY_DEFERRED |
                        SQL_CT_CONSTRAINT_INITIALLY_IMMEDIATE | SQL_CT_CONSTRAINT_DEFERRABLE |
                        SQL_CT_CONSTRAINT_NON_DEFERRABLE,
                    InfoValuePtr);
  case SQL_ALTER_TABLE: /* ADD [no COLUMN keyword], DROP COLUMN, DROP CONSTRAINT .. CASCADE */
    return info_u32(SQL_AT_ADD_COLUMN | SQL_AT_DROP_COLUMN | SQL_AT_ADD_COLUMN_SINGLE |
                        SQL_AT_ADD_COLUMN_DEFAULT | SQL_AT_ADD_CONSTRAINT |
                        SQL_AT_ADD_TABLE_CONSTRAINT | SQL_AT_DROP_COLUMN_DEFAULT |
                        SQL_AT_DROP_TABLE_CONSTRAINT_CASCADE | SQL_AT_CONSTRAINT_NAME_DEFINITION |
                        SQL_AT_CONSTRAINT_INITIALLY_DEFERRED |
                        SQL_AT_CONSTRAINT_INITIALLY_IMMEDIATE | SQL_AT_CONSTRAINT_DEFERRABLE |
                        SQL_AT_CONSTRAINT_NON_DEFERRABLE,
                    InfoValuePtr);
  case SQL_CREATE_VIEW: /* WITH CHECK OPTION, but no CASCADED / LOCAL */
    return info_u32(SQL_CV_CREATE_VIEW | SQL_CV_CHECK_OPTION, InfoValuePtr);
  case SQL_CREATE_SCHEMA: /* CREATE SCHEMA AUTHORIZATION <own user> ... */
    return info_u32(SQL_CS_CREATE_SCHEMA | SQL_CS_AUTHORIZATION, InfoValuePtr);
  case SQL_DROP_TABLE:
    return info_u32(SQL_DT_DROP_TABLE, InfoValuePtr);
  case SQL_DROP_VIEW:
    return info_u32(SQL_DV_DROP_VIEW, InfoValuePtr);
  case SQL_DDL_INDEX:
    return info_u32(SQL_DI_CREATE_INDEX | SQL_DI_DROP_INDEX, InfoValuePtr);
  case SQL_INDEX_KEYWORDS:
    return info_u32(SQL_IK_ASC | SQL_IK_DESC, InfoValuePtr);
  case SQL_INSERT_STATEMENT: /* no SELECT ... INTO <table> */
    return info_u32(SQL_IS_INSERT_LITERALS | SQL_IS_INSERT_SEARCHED, InfoValuePtr);
  case SQL_AGGREGATE_FUNCTIONS:
    return info_u32(SQL_AF_ALL | SQL_AF_AVG | SQL_AF_COUNT | SQL_AF_DISTINCT | SQL_AF_MAX |
                        SQL_AF_MIN | SQL_AF_SUM,
                    InfoValuePtr);
  case SQL_SQL92_DATETIME_FUNCTIONS: /* no CURRENT_TIME; 8i has neither */
    return info_u32(legacy_8i(c) ? 0 : SQL_SDF_CURRENT_DATE | SQL_SDF_CURRENT_TIMESTAMP,
                    InfoValuePtr);
  case SQL_SQL92_NUMERIC_VALUE_FUNCTIONS: /* the rest are {fn} only */
    return info_u32(SQL_SNVF_EXTRACT, InfoValuePtr);
  case SQL_SQL92_STRING_FUNCTIONS: /* TRANSLATE ... USING CHAR_CS / NCHAR_CS */
    return info_u32(SQL_SSF_LOWER | SQL_SSF_UPPER | SQL_SSF_TRANSLATE | SQL_SSF_TRIM_BOTH |
                        SQL_SSF_TRIM_LEADING | SQL_SSF_TRIM_TRAILING,
                    InfoValuePtr);
  case SQL_SQL92_PREDICATES:
    return info_u32(SQL_SP_BETWEEN | SQL_SP_COMPARISON | SQL_SP_EXISTS | SQL_SP_IN |
                        SQL_SP_ISNOTNULL | SQL_SP_ISNULL | SQL_SP_LIKE | SQL_SP_OVERLAPS |
                        SQL_SP_QUANTIFIED_COMPARISON,
                    InfoValuePtr);
  case SQL_SQL92_RELATIONAL_JOIN_OPERATORS: { /* ANSI joins from 9i, EXCEPT from 21c */
    int major = seer_odbc_server_major(c);
    return info_u32(SQL_SRJO_INTERSECT_JOIN |
                        (legacy_8i(c) ? 0
                                      : SQL_SRJO_CROSS_JOIN | SQL_SRJO_INNER_JOIN |
                                            SQL_SRJO_LEFT_OUTER_JOIN | SQL_SRJO_RIGHT_OUTER_JOIN |
                                            SQL_SRJO_FULL_OUTER_JOIN | SQL_SRJO_NATURAL_JOIN) |
                        (major >= 21 ? SQL_SRJO_EXCEPT_JOIN : 0),
                    InfoValuePtr);
  }
  case SQL_SQL92_VALUE_EXPRESSIONS: /* 8i: no simple CASE, COALESCE or NULLIF */
    return info_u32(SQL_SVE_CAST |
                        (legacy_8i(c) ? 0 : SQL_SVE_CASE | SQL_SVE_COALESCE | SQL_SVE_NULLIF),
                    InfoValuePtr);
  case SQL_SQL92_ROW_VALUE_CONSTRUCTOR: /* 8i: no DEFAULT in VALUES / SET */
    return info_u32(SQL_SRVC_VALUE_EXPRESSION | SQL_SRVC_NULL | SQL_SRVC_ROW_SUBQUERY |
                        (legacy_8i(c) ? 0 : SQL_SRVC_DEFAULT),
                    InfoValuePtr);
  case SQL_SQL92_GRANT:
    return info_u32(SQL_SG_DELETE_TABLE | SQL_SG_INSERT_TABLE | SQL_SG_INSERT_COLUMN |
                        SQL_SG_REFERENCES_TABLE | SQL_SG_REFERENCES_COLUMN | SQL_SG_SELECT_TABLE |
                        SQL_SG_UPDATE_TABLE | SQL_SG_UPDATE_COLUMN | SQL_SG_WITH_GRANT_OPTION,
                    InfoValuePtr);
  case SQL_SQL92_REVOKE: /* table privileges only; no column REVOKE, CASCADE or RESTRICT */
    return info_u32(SQL_SR_DELETE_TABLE | SQL_SR_INSERT_TABLE | SQL_SR_REFERENCES_TABLE |
                        SQL_SR_SELECT_TABLE | SQL_SR_UPDATE_TABLE,
                    InfoValuePtr);
  case SQL_SQL92_FOREIGN_KEY_DELETE_RULE:
    return info_u32(SQL_SFKD_CASCADE | SQL_SFKD_SET_NULL, InfoValuePtr);
  case SQL_SQL92_FOREIGN_KEY_UPDATE_RULE: /* Oracle has no ON UPDATE */
    return info_u32(0, InfoValuePtr);
  case SQL_CURSOR_SENSITIVITY: /* what SQL_ATTR_CURSOR_SENSITIVITY settles on */
    return info_u32(SQL_INSENSITIVE, InfoValuePtr);
  case SQL_INTEGRITY: /* primary, foreign key, check and unique constraints */
    return info_string("Y", InfoValuePtr, BufferLength, StringLengthPtr);
  case SQL_MAX_ROW_SIZE_INCLUDES_LONG: /* SQL_MAX_ROW_SIZE is 0: no limit */
    return info_string("Y", InfoValuePtr, BufferLength, StringLengthPtr);
  case SQL_KEYWORDS: /* reserved on every release, and not ODBC keywords */
    return info_string("ACCESS,AUDIT,CLUSTER,COMMENT,COMPRESS,EXCLUSIVE,FILE,IDENTIFIED,"
                       "INCREMENT,INITIAL,LEVEL,LOCK,LONG,MAXEXTENTS,MINUS,MLSLABEL,MODE,MODIFY,"
                       "NOAUDIT,NOCOMPRESS,NOWAIT,NUMBER,OFFLINE,ONLINE,PCTFREE,PRIOR,RAW,"
                       "RENAME,RESOURCE,ROW,ROWID,ROWNUM,ROWS,SHARE,SIZE,START,SUCCESSFUL,"
                       "SYNONYM,SYSDATE,TRIGGER,UID,VALIDATE,VARCHAR2,WHENEVER",
                       InfoValuePtr, BufferLength, StringLengthPtr);
  case SQL_MAX_COLUMNS_IN_TABLE: /* ORA-01792 past it */
    return info_u16(1000, InfoValuePtr);
  case SQL_MAX_COLUMNS_IN_INDEX: /* ORA-01793 past it */
    return info_u16(32, InfoValuePtr);
  case SQL_MAX_CHAR_LITERAL_LEN: /* ORA-01704 past it */
    return info_u32(4000, InfoValuePtr);
  case SQL_MAX_PROCEDURE_NAME_LEN:
  case SQL_MAX_USER_NAME_LEN:
    return info_u16(max_identifier_len(c), InfoValuePtr);
  case SQL_SYSTEM_FUNCTIONS: /* no DATABASE: Oracle has no catalogs */
    return info_u32(SQL_FN_SYS_IFNULL | SQL_FN_SYS_USERNAME, InfoValuePtr);
  case SQL_DATETIME_LITERALS: /* {d} {t} {ts} everywhere; {INTERVAL} from 9i */
    return info_u32(
        SQL_DL_SQL92_DATE | SQL_DL_SQL92_TIME | SQL_DL_SQL92_TIMESTAMP |
            (legacy_8i(c)
                 ? 0
                 : SQL_DL_SQL92_INTERVAL_YEAR | SQL_DL_SQL92_INTERVAL_MONTH |
                       SQL_DL_SQL92_INTERVAL_DAY | SQL_DL_SQL92_INTERVAL_HOUR |
                       SQL_DL_SQL92_INTERVAL_MINUTE | SQL_DL_SQL92_INTERVAL_SECOND |
                       SQL_DL_SQL92_INTERVAL_YEAR_TO_MONTH | SQL_DL_SQL92_INTERVAL_DAY_TO_HOUR |
                       SQL_DL_SQL92_INTERVAL_DAY_TO_MINUTE | SQL_DL_SQL92_INTERVAL_DAY_TO_SECOND |
                       SQL_DL_SQL92_INTERVAL_HOUR_TO_MINUTE | SQL_DL_SQL92_INTERVAL_HOUR_TO_SECOND |
                       SQL_DL_SQL92_INTERVAL_MINUTE_TO_SECOND),
        InfoValuePtr);
  case SQL_TIMEDATE_ADD_INTERVALS: /* 8i has no fractional seconds */
    return info_u32((legacy_8i(c) ? 0 : SQL_FN_TSI_FRAC_SECOND) | SQL_FN_TSI_SECOND |
                        SQL_FN_TSI_MINUTE | SQL_FN_TSI_HOUR | SQL_FN_TSI_DAY | SQL_FN_TSI_WEEK |
                        SQL_FN_TSI_MONTH | SQL_FN_TSI_QUARTER | SQL_FN_TSI_YEAR,
                    InfoValuePtr);
  case SQL_TIMEDATE_DIFF_INTERVALS:
    return info_u32(SQL_FN_TSI_SECOND | SQL_FN_TSI_MINUTE | SQL_FN_TSI_HOUR | SQL_FN_TSI_DAY |
                        SQL_FN_TSI_WEEK | SQL_FN_TSI_MONTH | SQL_FN_TSI_QUARTER | SQL_FN_TSI_YEAR,
                    InfoValuePtr);
  case SQL_CONVERT_FUNCTIONS:
    return info_u32(SQL_FN_CVT_CONVERT | SQL_FN_CVT_CAST, InfoValuePtr);
  case SQL_CONVERT_CHAR:
  case SQL_CONVERT_VARCHAR:
  case SQL_CONVERT_WCHAR:
  case SQL_CONVERT_WVARCHAR:
  case SQL_CONVERT_LONGVARCHAR:
  case SQL_CONVERT_WLONGVARCHAR:
  case SQL_CONVERT_NUMERIC:
  case SQL_CONVERT_DECIMAL:
  case SQL_CONVERT_TINYINT:
  case SQL_CONVERT_SMALLINT:
  case SQL_CONVERT_INTEGER:
  case SQL_CONVERT_BIGINT:
  case SQL_CONVERT_REAL:
  case SQL_CONVERT_FLOAT:
  case SQL_CONVERT_DOUBLE:
  case SQL_CONVERT_DATE:
  case SQL_CONVERT_TIMESTAMP:
    return info_u32(convert_targets(InfoType, legacy_8i(c)), InfoValuePtr);

  case SQL_GROUP_BY:
    return info_u16(SQL_GB_GROUP_BY_CONTAINS_SELECT, InfoValuePtr);
  case SQL_UNION:
    return info_u32(SQL_U_UNION | SQL_U_UNION_ALL, InfoValuePtr);
  case SQL_SUBQUERIES:
    return info_u32(SQL_SQ_COMPARISON | SQL_SQ_EXISTS | SQL_SQ_IN | SQL_SQ_QUANTIFIED |
                        SQL_SQ_CORRELATED_SUBQUERIES,
                    InfoValuePtr);
  case SQL_PARAM_ARRAY_ROW_COUNTS: /* one count for the whole array */
    return info_u32(SQL_PARC_NO_BATCH, InfoValuePtr);
  case SQL_PARAM_ARRAY_SELECTS: /* one result set per parameter set (#431) */
    return info_u32(SQL_PAS_BATCH, InfoValuePtr);

  /* --- cursors --- forward-only plus a buffered static (scrollable) cursor.
   * Both take SQLSetPos (POSITION / REFRESH / UPDATE / DELETE, any LockType
   * as NO_CHANGE), positioned DML by ROWID (unique), read-only or locking
   * concurrency (FOR UPDATE), and SQL_ATTR_MAX_ROWS on a SELECT (#294). */
  case SQL_FORWARD_ONLY_CURSOR_ATTRIBUTES1:
    return info_u32(CURSOR_CA1, InfoValuePtr);
  case SQL_STATIC_CURSOR_ATTRIBUTES1:
    return info_u32(CURSOR_CA1 | SQL_CA1_ABSOLUTE | SQL_CA1_RELATIVE, InfoValuePtr);
  case SQL_FORWARD_ONLY_CURSOR_ATTRIBUTES2:
  case SQL_STATIC_CURSOR_ATTRIBUTES2:
    return info_u32(SQL_CA2_READ_ONLY_CONCURRENCY | SQL_CA2_LOCK_CONCURRENCY |
                        SQL_CA2_MAX_ROWS_SELECT | SQL_CA2_SIMULATE_UNIQUE,
                    InfoValuePtr);
  case SQL_SCROLL_OPTIONS:
    return info_u32(SQL_SO_FORWARD_ONLY | SQL_SO_STATIC, InfoValuePtr);
  case SQL_POS_OPERATIONS: /* the 2.x forms of the same */
    return info_u32(SQL_POS_POSITION | SQL_POS_REFRESH | SQL_POS_UPDATE | SQL_POS_DELETE,
                    InfoValuePtr);
  case SQL_SCROLL_CONCURRENCY:
    return info_u32(SQL_SCCO_READ_ONLY | SQL_SCCO_LOCK, InfoValuePtr);
  case SQL_LOCK_TYPES:
    return info_u32(SQL_LCK_NO_CHANGE, InfoValuePtr);

  default:
    /* Unknown InfoType: a benign empty/zero answer keeps the DM happy. */
    if (StringLengthPtr != NULL)
      *StringLengthPtr = 0;
    if (InfoValuePtr != NULL && BufferLength >= (SQLSMALLINT)sizeof(SQLUINTEGER))
      *(SQLUINTEGER *)InfoValuePtr = 0;
    else if (InfoValuePtr != NULL && BufferLength > 0)
      *(char *)InfoValuePtr = '\0';
    return SQL_SUCCESS;
  }
}

/* Functions we implement (ODBC 3.x). */
static int func_supported(SQLUSMALLINT id)
{
  switch (id) {
  case SQL_API_SQLALLOCHANDLE:
  case SQL_API_SQLFREEHANDLE:
  case SQL_API_SQLCONNECT:
  case SQL_API_SQLDRIVERCONNECT:
  case SQL_API_SQLBROWSECONNECT:
  case SQL_API_SQLDISCONNECT:
  case SQL_API_SQLGETINFO:
  case SQL_API_SQLGETFUNCTIONS:
  case SQL_API_SQLGETDIAGREC:
  case SQL_API_SQLGETDIAGFIELD:
  case SQL_API_SQLSETENVATTR:
  case SQL_API_SQLGETENVATTR:
  case SQL_API_SQLSETCONNECTATTR:
  case SQL_API_SQLGETCONNECTATTR:
  case SQL_API_SQLENDTRAN:
  case SQL_API_SQLSETSTMTATTR:
  case SQL_API_SQLGETSTMTATTR:
  case SQL_API_SQLNATIVESQL:
  case SQL_API_SQLEXECDIRECT:
  case SQL_API_SQLPREPARE:
  case SQL_API_SQLEXECUTE:
  case SQL_API_SQLNUMPARAMS:
  case SQL_API_SQLPARAMDATA:
  case SQL_API_SQLPUTDATA:
  case SQL_API_SQLBINDPARAMETER:
  case SQL_API_SQLDESCRIBEPARAM:
  case SQL_API_SQLNUMRESULTCOLS:
  case SQL_API_SQLGETDESCFIELD:
  case SQL_API_SQLGETDESCREC:
  case SQL_API_SQLSETDESCFIELD:
  case SQL_API_SQLSETDESCREC:
  case SQL_API_SQLDESCRIBECOL:
  case SQL_API_SQLCOLATTRIBUTE:
  case SQL_API_SQLFETCHSCROLL:
  case SQL_API_SQLSETPOS:
  case SQL_API_SQLBINDCOL:
  case SQL_API_SQLFETCH:
  case SQL_API_SQLGETDATA:
  case SQL_API_SQLROWCOUNT:
  case SQL_API_SQLMORERESULTS:
  case SQL_API_SQLCANCEL:
  case SQL_API_SQLFREESTMT:
  case SQL_API_SQLCLOSECURSOR:
  case SQL_API_SQLTABLES:
  case SQL_API_SQLCOLUMNS:
  case SQL_API_SQLGETTYPEINFO:
  case SQL_API_SQLPRIMARYKEYS:
  case SQL_API_SQLSTATISTICS:
  case SQL_API_SQLFOREIGNKEYS:
  case SQL_API_SQLPROCEDURES:
  case SQL_API_SQLPROCEDURECOLUMNS:
  case SQL_API_SQLSPECIALCOLUMNS:
  case SQL_API_SQLTABLEPRIVILEGES: /* #286 */
  case SQL_API_SQLCOLUMNPRIVILEGES:
  case SQL_API_SQLGETCURSORNAME: /* #288 */
  case SQL_API_SQLSETCURSORNAME:
  case SQL_API_SQLCOPYDESC: /* #289 */
    return 1;
  default:
    return 0;
  }
}

SQLRETURN SQL_API SQLGetFunctions(SQLHDBC ConnectionHandle, SQLUSMALLINT FunctionId,
                                  SQLUSMALLINT *SupportedPtr)
{
  (void)ConnectionHandle;
  if (SupportedPtr == NULL)
    return SQL_ERROR;

  if (FunctionId == SQL_API_ODBC3_ALL_FUNCTIONS) {
    memset(SupportedPtr, 0, sizeof(SQLUSMALLINT) * SQL_API_ODBC3_ALL_FUNCTIONS_SIZE);
    for (SQLUSMALLINT id = 0; id < 2000; id++)
      if (func_supported(id))
        SupportedPtr[id >> 4] |= (SQLUSMALLINT)(1 << (id & 0x0F));
    return SQL_SUCCESS;
  }
  if (FunctionId == SQL_API_ALL_FUNCTIONS) {
    for (int i = 0; i < 100; i++)
      SupportedPtr[i] = func_supported((SQLUSMALLINT)i) ? SQL_TRUE : SQL_FALSE;
    return SQL_SUCCESS;
  }
  *SupportedPtr = func_supported(FunctionId) ? SQL_TRUE : SQL_FALSE;
  return SQL_SUCCESS;
}

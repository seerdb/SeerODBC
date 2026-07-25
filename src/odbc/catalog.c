/* Catalog functions: SQLTables / SQLColumns.
 *
 * Each is a driver-generated SELECT against the Oracle data dictionary
 * (ALL_TABLES / ALL_VIEWS / ALL_TAB_COLUMNS), aliased to the exact column
 * layout the ODBC spec mandates for the function's result set, then run
 * through the protocol core. The app then reads it like any result set with
 * SQLFetch / SQLGetData.
 *
 * Name/schema arguments are treated as search patterns (the default, with
 * SQL_ATTR_METADATA_ID off) and bound as LIKE parameters; a NULL argument
 * matches everything.
 *
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "compat.h"
#include "odbc_internal.h"

/* Duplicate a possibly non-NUL-terminated ODBC string; NULL/empty -> "%". */
static char *pattern_dup(const void *s, SQLSMALLINT len)
{
    if (s == NULL)
        return strdup("%");
    size_t n = (len == SQL_NTS) ? strlen((const char *)s) : (size_t)len;
    if (n == 0)
        return strdup("%");
    char *d = malloc(n + 1);
    if (d == NULL)
        return NULL;
    memcpy(d, s, n);
    d[n] = '\0';
    return d;
}

SQLRETURN SQL_API SQLTables(SQLHSTMT     StatementHandle,
                            SQLCHAR     *CatalogName, SQLSMALLINT NameLength1,
                            SQLCHAR     *SchemaName,  SQLSMALLINT NameLength2,
                            SQLCHAR     *TableName,   SQLSMALLINT NameLength3,
                            SQLCHAR     *TableType,   SQLSMALLINT NameLength4)
{
    (void)CatalogName; (void)NameLength1;     /* Oracle has no catalogs */
    OdbcStmt *s = (OdbcStmt *)StatementHandle;
    if (s == NULL)
        return SQL_INVALID_HANDLE;
    seer_odbc_diag_clear(s);
    if (s->dbc == NULL || !s->dbc->connected)
        return seer_odbc_diag(s, "08003", 0, "Connection not open", SQL_ERROR);

    char *schema = pattern_dup(SchemaName, NameLength2);
    char *table  = pattern_dup(TableName, NameLength3);
    char *types  = (TableType == NULL) ? strdup("")
                 : pattern_dup(TableType, NameLength4);
    if (schema == NULL || table == NULL || types == NULL) {
        free(schema); free(table); free(types);
        return seer_odbc_diag(s, "HY001", 0, "Out of memory", SQL_ERROR);
    }

    int all  = (types[0] == '\0' || strcmp(types, "%") == 0);
    int want_table = all || seer_strcasestr(types, "TABLE") != NULL;
    int want_view  = all || seer_strcasestr(types, "VIEW") != NULL;
    if (!want_table && !want_view)         /* a specific, unknown type list */
        want_table = want_view = 0;

    static const char *TABLES_SQL =
        "SELECT CAST(NULL AS VARCHAR2(128)) TABLE_CAT, OWNER TABLE_SCHEM,"
        " TABLE_NAME, 'TABLE' TABLE_TYPE, CAST(NULL AS VARCHAR2(1)) REMARKS"
        " FROM ALL_TABLES WHERE OWNER LIKE :1 AND TABLE_NAME LIKE :2";
    static const char *VIEWS_SQL =
        "SELECT CAST(NULL AS VARCHAR2(128)), OWNER, VIEW_NAME, 'VIEW',"
        " CAST(NULL AS VARCHAR2(1)) FROM ALL_VIEWS"
        " WHERE OWNER LIKE :1 AND VIEW_NAME LIKE :2";

    char sql[1024];
    const char *params[4];
    int nparams = 0;

    if (want_table && want_view) {
        snprintf(sql, sizeof sql, "%s UNION ALL %s ORDER BY 2, 3",
                 TABLES_SQL,
                 "SELECT CAST(NULL AS VARCHAR2(128)), OWNER, VIEW_NAME, 'VIEW',"
                 " CAST(NULL AS VARCHAR2(1)) FROM ALL_VIEWS"
                 " WHERE OWNER LIKE :3 AND VIEW_NAME LIKE :4");
        params[0] = schema; params[1] = table;
        params[2] = schema; params[3] = table;
        nparams = 4;
    } else if (want_view) {
        snprintf(sql, sizeof sql, "%s ORDER BY 2, 3", VIEWS_SQL);
        params[0] = schema; params[1] = table;
        nparams = 2;
    } else {
        snprintf(sql, sizeof sql, "%s ORDER BY 2, 3", TABLES_SQL);
        params[0] = schema; params[1] = table;
        nparams = 2;
    }

    SQLRETURN ret = seer_odbc_run_query(s, sql, params, nparams);
    free(schema); free(table); free(types);
    return ret;
}

SQLRETURN SQL_API SQLColumns(SQLHSTMT     StatementHandle,
                             SQLCHAR     *CatalogName, SQLSMALLINT NameLength1,
                             SQLCHAR     *SchemaName,  SQLSMALLINT NameLength2,
                             SQLCHAR     *TableName,   SQLSMALLINT NameLength3,
                             SQLCHAR     *ColumnName,  SQLSMALLINT NameLength4)
{
    (void)CatalogName; (void)NameLength1;
    OdbcStmt *s = (OdbcStmt *)StatementHandle;
    if (s == NULL)
        return SQL_INVALID_HANDLE;
    seer_odbc_diag_clear(s);
    if (s->dbc == NULL || !s->dbc->connected)
        return seer_odbc_diag(s, "08003", 0, "Connection not open", SQL_ERROR);

    char *schema = pattern_dup(SchemaName, NameLength2);
    char *table  = pattern_dup(TableName, NameLength3);
    char *column = pattern_dup(ColumnName, NameLength4);
    if (schema == NULL || table == NULL || column == NULL) {
        free(schema); free(table); free(column);
        return seer_odbc_diag(s, "HY001", 0, "Out of memory", SQL_ERROR);
    }

    /* The 18-column SQLColumns result set. DATA_TYPE / SQL_DATA_TYPE carry the
     * ODBC type code (CASE over Oracle's textual DATA_TYPE). COLUMN_DEF is
     * forced NULL - ALL_TAB_COLUMNS.DATA_DEFAULT is a LONG and not needed. */
    static const char *COLUMNS_SQL =
        "SELECT CAST(NULL AS VARCHAR2(128)) TABLE_CAT, OWNER TABLE_SCHEM,"
        " TABLE_NAME, COLUMN_NAME,"
        " CASE"
        "   WHEN DATA_TYPE='NUMBER' THEN 3 WHEN DATA_TYPE='FLOAT' THEN 6"
        "   WHEN DATA_TYPE IN ('VARCHAR2','NVARCHAR2','VARCHAR') THEN 12"
        "   WHEN DATA_TYPE IN ('CHAR','NCHAR') THEN 1"
        "   WHEN DATA_TYPE='DATE' THEN 93 WHEN DATA_TYPE LIKE 'TIMESTAMP%' THEN 93"
        "   WHEN DATA_TYPE='BINARY_FLOAT' THEN 7 WHEN DATA_TYPE='BINARY_DOUBLE' THEN 8"
        "   WHEN DATA_TYPE='RAW' THEN -3"
        "   WHEN DATA_TYPE IN ('LONG','CLOB','NCLOB') THEN -1"
        "   WHEN DATA_TYPE IN ('LONG RAW','BLOB') THEN -4 ELSE 12 END DATA_TYPE,"
        " DATA_TYPE TYPE_NAME,"
        " CASE WHEN DATA_TYPE='NUMBER' THEN NVL(DATA_PRECISION, 38) ELSE DATA_LENGTH END COLUMN_SIZE,"
        " DATA_LENGTH BUFFER_LENGTH, DATA_SCALE DECIMAL_DIGITS,"
        " 10 NUM_PREC_RADIX,"
        " CASE NULLABLE WHEN 'Y' THEN 1 ELSE 0 END NULLABLE,"
        " CAST(NULL AS VARCHAR2(1)) REMARKS, CAST(NULL AS VARCHAR2(1)) COLUMN_DEF,"
        " CASE"
        "   WHEN DATA_TYPE='NUMBER' THEN 3 WHEN DATA_TYPE='FLOAT' THEN 6"
        "   WHEN DATA_TYPE IN ('VARCHAR2','NVARCHAR2','VARCHAR') THEN 12"
        "   WHEN DATA_TYPE IN ('CHAR','NCHAR') THEN 1"
        "   WHEN DATA_TYPE='DATE' THEN 93 WHEN DATA_TYPE LIKE 'TIMESTAMP%' THEN 93"
        "   WHEN DATA_TYPE='BINARY_FLOAT' THEN 7 WHEN DATA_TYPE='BINARY_DOUBLE' THEN 8"
        "   WHEN DATA_TYPE='RAW' THEN -3"
        "   WHEN DATA_TYPE IN ('LONG','CLOB','NCLOB') THEN -1"
        "   WHEN DATA_TYPE IN ('LONG RAW','BLOB') THEN -4 ELSE 12 END SQL_DATA_TYPE,"
        " CAST(NULL AS NUMBER) SQL_DATETIME_SUB,"
        " CASE WHEN DATA_TYPE IN ('VARCHAR2','NVARCHAR2','VARCHAR','CHAR','NCHAR','RAW')"
        "   THEN DATA_LENGTH ELSE CAST(NULL AS NUMBER) END CHAR_OCTET_LENGTH,"
        " COLUMN_ID ORDINAL_POSITION,"
        " DECODE(NULLABLE, 'Y', 'YES', 'NO') IS_NULLABLE"
        " FROM ALL_TAB_COLUMNS"
        " WHERE OWNER LIKE :1 AND TABLE_NAME LIKE :2 AND COLUMN_NAME LIKE :3"
        " ORDER BY OWNER, TABLE_NAME, COLUMN_ID";

    const char *params[3] = { schema, table, column };
    SQLRETURN ret = seer_odbc_run_query(s, COLUMNS_SQL, params, 3);
    free(schema); free(table); free(column);
    return ret;
}

/* One row of the SQLGetTypeInfo result set, built from dual. The columns the
 * driver actually varies are TYPE_NAME / DATA_TYPE / COLUMN_SIZE /
 * CASE_SENSITIVE / NUM_PREC_RADIX; the rest are sensible constants/NULLs. */
static const struct {
    const char *name;
    int         sql_type;
    long        column_size;
    int         case_sensitive;
    const char *radix;          /* "10" or "NULL" */
} TYPEINFO[] = {
    { "NUMBER",        SQL_DECIMAL,         38, 0, "10"   },
    { "CHAR",          SQL_CHAR,          2000, 1, "NULL" },
    { "VARCHAR2",      SQL_VARCHAR,       4000, 1, "NULL" },
    { "DATE",          SQL_TYPE_TIMESTAMP,  19, 0, "NULL" },
    { "RAW",           SQL_VARBINARY,     2000, 0, "NULL" },
    { "BINARY_FLOAT",  SQL_REAL,             7, 0, "10"   },
    { "BINARY_DOUBLE", SQL_DOUBLE,          15, 0, "10"   },
    { "CLOB",          SQL_LONGVARCHAR, 2147483647, 1, "NULL" },
    { "BLOB",          SQL_LONGVARBINARY, 2147483647, 0, "NULL" },
    { "LONG",          SQL_LONGVARCHAR, 2147483647, 1, "NULL" },
    { "LONG RAW",      SQL_LONGVARBINARY, 2147483647, 0, "NULL" },
};

SQLRETURN SQL_API SQLGetTypeInfo(SQLHSTMT StatementHandle, SQLSMALLINT DataType)
{
    OdbcStmt *s = (OdbcStmt *)StatementHandle;
    if (s == NULL)
        return SQL_INVALID_HANDLE;
    seer_odbc_diag_clear(s);
    if (s->dbc == NULL || !s->dbc->connected)
        return seer_odbc_diag(s, "08003", 0, "Connection not open", SQL_ERROR);

    /* Build a UNION ALL of one row per supported type, optionally filtered to
     * the requested SQL type, ordered by DATA_TYPE (per the ODBC spec). */
    char sql[8192];
    size_t off = 0;
    int emitted = 0;
    /* Every append is guarded: snprintf returns the length it WOULD have
     * written, so an unchecked "off += snprintf(...)" (or a negative return
     * cast to size_t) can push off past the buffer and make the next
     * "sizeof sql - off" underflow into a huge size_t. The TYPEINFO table is
     * statically bounded so this cannot overflow today, but guard it anyway. */
    for (size_t i = 0; i < sizeof TYPEINFO / sizeof TYPEINFO[0]; i++) {
        if (DataType != SQL_ALL_TYPES && DataType != TYPEINFO[i].sql_type)
            continue;
        int n = snprintf(sql + off, sizeof sql - off,
            "%sSELECT '%s' TYPE_NAME, %d DATA_TYPE, %ld COLUMN_SIZE,"
            " CAST(NULL AS VARCHAR2(1)) LITERAL_PREFIX, CAST(NULL AS VARCHAR2(1)) LITERAL_SUFFIX,"
            " CAST(NULL AS VARCHAR2(1)) CREATE_PARAMS, 1 NULLABLE, %d CASE_SENSITIVE,"
            " 3 SEARCHABLE, CAST(NULL AS NUMBER) UNSIGNED_ATTRIBUTE, 0 FIXED_PREC_SCALE,"
            " CAST(NULL AS NUMBER) AUTO_UNIQUE_VALUE, CAST(NULL AS VARCHAR2(1)) LOCAL_TYPE_NAME,"
            " 0 MINIMUM_SCALE, 0 MAXIMUM_SCALE, %d SQL_DATA_TYPE,"
            " CAST(NULL AS NUMBER) SQL_DATETIME_SUB, %s NUM_PREC_RADIX,"
            " CAST(NULL AS NUMBER) INTERVAL_PRECISION FROM dual",
            emitted ? " UNION ALL " : "",
            TYPEINFO[i].name, TYPEINFO[i].sql_type, TYPEINFO[i].column_size,
            TYPEINFO[i].case_sensitive, TYPEINFO[i].sql_type, TYPEINFO[i].radix);
        if (n < 0 || (size_t)n >= sizeof sql - off)
            return seer_odbc_diag(s, "HY000", 0, "Type-info query too long", SQL_ERROR);
        off += (size_t)n;
        emitted = 1;
    }
    if (!emitted)   /* unknown requested type: an empty result set */
        snprintf(sql, sizeof sql,
            "SELECT CAST(NULL AS VARCHAR2(1)) TYPE_NAME, CAST(NULL AS NUMBER) DATA_TYPE"
            " FROM dual WHERE 1=0");
    else {
        int n = snprintf(sql + off, sizeof sql - off, " ORDER BY DATA_TYPE");
        if (n < 0 || (size_t)n >= sizeof sql - off)
            return seer_odbc_diag(s, "HY000", 0, "Type-info query too long", SQL_ERROR);
    }

    return seer_odbc_run_query(s, sql, NULL, 0);
}

SQLRETURN SQL_API SQLPrimaryKeys(SQLHSTMT     StatementHandle,
                                 SQLCHAR     *CatalogName, SQLSMALLINT NameLength1,
                                 SQLCHAR     *SchemaName,  SQLSMALLINT NameLength2,
                                 SQLCHAR     *TableName,   SQLSMALLINT NameLength3)
{
    (void)CatalogName; (void)NameLength1;
    OdbcStmt *s = (OdbcStmt *)StatementHandle;
    if (s == NULL)
        return SQL_INVALID_HANDLE;
    seer_odbc_diag_clear(s);
    if (s->dbc == NULL || !s->dbc->connected)
        return seer_odbc_diag(s, "08003", 0, "Connection not open", SQL_ERROR);

    char *schema = pattern_dup(SchemaName, NameLength2);
    char *table  = pattern_dup(TableName, NameLength3);
    if (schema == NULL || table == NULL) {
        free(schema); free(table);
        return seer_odbc_diag(s, "HY001", 0, "Out of memory", SQL_ERROR);
    }

    static const char *PK_SQL =
        "SELECT CAST(NULL AS VARCHAR2(128)) TABLE_CAT, c.OWNER TABLE_SCHEM,"
        " c.TABLE_NAME, cc.COLUMN_NAME, cc.POSITION KEY_SEQ, c.CONSTRAINT_NAME PK_NAME"
        " FROM ALL_CONSTRAINTS c JOIN ALL_CONS_COLUMNS cc"
        "   ON c.OWNER = cc.OWNER AND c.CONSTRAINT_NAME = cc.CONSTRAINT_NAME"
        " WHERE c.CONSTRAINT_TYPE = 'P' AND c.OWNER LIKE :1 AND c.TABLE_NAME = :2"
        " ORDER BY cc.POSITION";

    const char *params[2] = { schema, table };
    SQLRETURN ret = seer_odbc_run_query(s, PK_SQL, params, 2);
    free(schema); free(table);
    return ret;
}

SQLRETURN SQL_API SQLStatistics(SQLHSTMT     StatementHandle,
                                SQLCHAR     *CatalogName, SQLSMALLINT NameLength1,
                                SQLCHAR     *SchemaName,  SQLSMALLINT NameLength2,
                                SQLCHAR     *TableName,   SQLSMALLINT NameLength3,
                                SQLUSMALLINT Unique,
                                SQLUSMALLINT Reserved)
{
    (void)CatalogName; (void)NameLength1; (void)Reserved;
    OdbcStmt *s = (OdbcStmt *)StatementHandle;
    if (s == NULL)
        return SQL_INVALID_HANDLE;
    seer_odbc_diag_clear(s);
    if (s->dbc == NULL || !s->dbc->connected)
        return seer_odbc_diag(s, "08003", 0, "Connection not open", SQL_ERROR);

    char *schema = pattern_dup(SchemaName, NameLength2);
    char *table  = pattern_dup(TableName, NameLength3);
    if (schema == NULL || table == NULL) {
        free(schema); free(table);
        return seer_odbc_diag(s, "HY001", 0, "Out of memory", SQL_ERROR);
    }

    /* SQL_INDEX_OTHER = 3, ASC_OR_DESC is the leading char of DESCEND. */
    char sql[1400];
    snprintf(sql, sizeof sql,
        "SELECT CAST(NULL AS VARCHAR2(128)) TABLE_CAT, i.TABLE_OWNER TABLE_SCHEM,"
        " i.TABLE_NAME, CASE i.UNIQUENESS WHEN 'UNIQUE' THEN 0 ELSE 1 END NON_UNIQUE,"
        " CAST(NULL AS VARCHAR2(128)) INDEX_QUALIFIER, i.INDEX_NAME, 3 TYPE,"
        " ic.COLUMN_POSITION ORDINAL_POSITION, ic.COLUMN_NAME,"
        " SUBSTR(ic.DESCEND, 1, 1) ASC_OR_DESC, i.DISTINCT_KEYS CARDINALITY,"
        " i.LEAF_BLOCKS PAGES, CAST(NULL AS VARCHAR2(1)) FILTER_CONDITION"
        " FROM ALL_INDEXES i JOIN ALL_IND_COLUMNS ic"
        "   ON i.OWNER = ic.INDEX_OWNER AND i.INDEX_NAME = ic.INDEX_NAME"
        " WHERE i.TABLE_OWNER LIKE :1 AND i.TABLE_NAME = :2%s"
        " ORDER BY NON_UNIQUE, i.INDEX_NAME, ic.COLUMN_POSITION",
        Unique == SQL_INDEX_UNIQUE ? " AND i.UNIQUENESS = 'UNIQUE'" : "");

    const char *params[2] = { schema, table };
    SQLRETURN ret = seer_odbc_run_query(s, sql, params, 2);
    free(schema); free(table);
    return ret;
}

SQLRETURN SQL_API SQLForeignKeys(SQLHSTMT     StatementHandle,
                                 SQLCHAR *PKCatalogName, SQLSMALLINT PKL1,
                                 SQLCHAR *PKSchemaName,  SQLSMALLINT PKL2,
                                 SQLCHAR *PKTableName,   SQLSMALLINT PKL3,
                                 SQLCHAR *FKCatalogName, SQLSMALLINT FKL1,
                                 SQLCHAR *FKSchemaName,  SQLSMALLINT FKL2,
                                 SQLCHAR *FKTableName,   SQLSMALLINT FKL3)
{
    (void)PKCatalogName; (void)PKL1; (void)FKCatalogName; (void)FKL1;
    OdbcStmt *s = (OdbcStmt *)StatementHandle;
    if (s == NULL)
        return SQL_INVALID_HANDLE;
    seer_odbc_diag_clear(s);
    if (s->dbc == NULL || !s->dbc->connected)
        return seer_odbc_diag(s, "08003", 0, "Connection not open", SQL_ERROR);

    char *pksch = pattern_dup(PKSchemaName, PKL2);
    char *pktab = pattern_dup(PKTableName, PKL3);
    char *fksch = pattern_dup(FKSchemaName, FKL2);
    char *fktab = pattern_dup(FKTableName, FKL3);
    if (!pksch || !pktab || !fksch || !fktab) {
        free(pksch); free(pktab); free(fksch); free(fktab);
        return seer_odbc_diag(s, "HY001", 0, "Out of memory", SQL_ERROR);
    }

    /* A foreign key (CONSTRAINT_TYPE 'R') references the PK/UK named by
     * R_CONSTRAINT_NAME; columns pair up by POSITION. Update rule is always
     * NO ACTION (3) on Oracle; delete rule maps CASCADE=0 / SET NULL=2 / else
     * NO ACTION (3). DEFERRABILITY = SQL_NOT_DEFERRABLE (7). */
    static const char *FK_SQL =
        "SELECT CAST(NULL AS VARCHAR2(128)) PKTABLE_CAT, pk.OWNER PKTABLE_SCHEM,"
        " pk.TABLE_NAME PKTABLE_NAME, pkc.COLUMN_NAME PKCOLUMN_NAME,"
        " CAST(NULL AS VARCHAR2(128)) FKTABLE_CAT, fk.OWNER FKTABLE_SCHEM,"
        " fk.TABLE_NAME FKTABLE_NAME, fkc.COLUMN_NAME FKCOLUMN_NAME,"
        " fkc.POSITION KEY_SEQ, 3 UPDATE_RULE,"
        " CASE fk.DELETE_RULE WHEN 'CASCADE' THEN 0 WHEN 'SET NULL' THEN 2 ELSE 3 END DELETE_RULE,"
        " fk.CONSTRAINT_NAME FK_NAME, pk.CONSTRAINT_NAME PK_NAME, 7 DEFERRABILITY"
        " FROM ALL_CONSTRAINTS fk"
        " JOIN ALL_CONSTRAINTS pk ON fk.R_OWNER = pk.OWNER AND fk.R_CONSTRAINT_NAME = pk.CONSTRAINT_NAME"
        " JOIN ALL_CONS_COLUMNS fkc ON fk.OWNER = fkc.OWNER AND fk.CONSTRAINT_NAME = fkc.CONSTRAINT_NAME"
        " JOIN ALL_CONS_COLUMNS pkc ON pk.OWNER = pkc.OWNER AND pk.CONSTRAINT_NAME = pkc.CONSTRAINT_NAME"
        "   AND pkc.POSITION = fkc.POSITION"
        " WHERE fk.CONSTRAINT_TYPE = 'R'"
        "   AND pk.OWNER LIKE :1 AND pk.TABLE_NAME LIKE :2"
        "   AND fk.OWNER LIKE :3 AND fk.TABLE_NAME LIKE :4"
        " ORDER BY fk.TABLE_NAME, fkc.POSITION";

    const char *params[4] = { pksch, pktab, fksch, fktab };
    SQLRETURN ret = seer_odbc_run_query(s, FK_SQL, params, 4);
    free(pksch); free(pktab); free(fksch); free(fktab);
    return ret;
}

SQLRETURN SQL_API SQLProcedures(SQLHSTMT     StatementHandle,
                                SQLCHAR     *CatalogName, SQLSMALLINT NameLength1,
                                SQLCHAR     *SchemaName,  SQLSMALLINT NameLength2,
                                SQLCHAR     *ProcName,    SQLSMALLINT NameLength3)
{
    (void)CatalogName; (void)NameLength1;
    OdbcStmt *s = (OdbcStmt *)StatementHandle;
    if (s == NULL)
        return SQL_INVALID_HANDLE;
    seer_odbc_diag_clear(s);
    if (s->dbc == NULL || !s->dbc->connected)
        return seer_odbc_diag(s, "08003", 0, "Connection not open", SQL_ERROR);

    char *schema = pattern_dup(SchemaName, NameLength2);
    char *proc   = pattern_dup(ProcName, NameLength3);
    if (schema == NULL || proc == NULL) {
        free(schema); free(proc);
        return seer_odbc_diag(s, "HY001", 0, "Out of memory", SQL_ERROR);
    }

    /* PROCEDURE_TYPE: SQL_PT_FUNCTION = 2, SQL_PT_PROCEDURE = 1. */
    static const char *PROC_SQL =
        "SELECT CAST(NULL AS VARCHAR2(128)) PROCEDURE_CAT, OWNER PROCEDURE_SCHEM,"
        " OBJECT_NAME PROCEDURE_NAME, CAST(NULL AS NUMBER) NUM_INPUT_PARAMS,"
        " CAST(NULL AS NUMBER) NUM_OUTPUT_PARAMS, CAST(NULL AS NUMBER) NUM_RESULT_SETS,"
        " CAST(NULL AS VARCHAR2(1)) REMARKS,"
        " CASE OBJECT_TYPE WHEN 'FUNCTION' THEN 2 ELSE 1 END PROCEDURE_TYPE"
        " FROM ALL_OBJECTS"
        " WHERE OBJECT_TYPE IN ('PROCEDURE', 'FUNCTION')"
        "   AND OWNER LIKE :1 AND OBJECT_NAME LIKE :2"
        " ORDER BY OWNER, OBJECT_NAME";

    const char *params[2] = { schema, proc };
    SQLRETURN ret = seer_odbc_run_query(s, PROC_SQL, params, 2);
    free(schema); free(proc);
    return ret;
}

SQLRETURN SQL_API SQLProcedureColumns(SQLHSTMT     StatementHandle,
                                      SQLCHAR     *CatalogName, SQLSMALLINT NameLength1,
                                      SQLCHAR     *SchemaName,  SQLSMALLINT NameLength2,
                                      SQLCHAR     *ProcName,    SQLSMALLINT NameLength3,
                                      SQLCHAR     *ColumnName,  SQLSMALLINT NameLength4)
{
    (void)CatalogName; (void)NameLength1;
    OdbcStmt *s = (OdbcStmt *)StatementHandle;
    if (s == NULL)
        return SQL_INVALID_HANDLE;
    seer_odbc_diag_clear(s);
    if (s->dbc == NULL || !s->dbc->connected)
        return seer_odbc_diag(s, "08003", 0, "Connection not open", SQL_ERROR);

    char *schema = pattern_dup(SchemaName, NameLength2);
    char *proc   = pattern_dup(ProcName, NameLength3);
    char *column = pattern_dup(ColumnName, NameLength4);
    if (schema == NULL || proc == NULL || column == NULL) {
        free(schema); free(proc); free(column);
        return seer_odbc_diag(s, "HY001", 0, "Out of memory", SQL_ERROR);
    }

    /* The 19-column SQLProcedureColumns result set, from ALL_ARGUMENTS (top-level
     * args only, DATA_LEVEL 0). POSITION 0 is the function return value;
     * COLUMN_TYPE maps IN/OUT/IN OUT to SQL_PARAM_* (1/4/2) and the return to
     * SQL_RETURN_VALUE (5). DATA_TYPE mirrors the SQLColumns type CASE. */
    static const char *PROCCOL_SQL =
        "SELECT CAST(NULL AS VARCHAR2(128)) PROCEDURE_CAT, OWNER PROCEDURE_SCHEM,"
        " OBJECT_NAME PROCEDURE_NAME, NVL(ARGUMENT_NAME, ' ') COLUMN_NAME,"
        " CASE WHEN POSITION = 0 THEN 5"
        "      WHEN IN_OUT = 'IN' THEN 1 WHEN IN_OUT = 'OUT' THEN 4"
        "      WHEN IN_OUT = 'IN/OUT' THEN 2 ELSE 0 END COLUMN_TYPE,"
        " CASE"
        "   WHEN DATA_TYPE='NUMBER' THEN 3 WHEN DATA_TYPE='FLOAT' THEN 6"
        "   WHEN DATA_TYPE IN ('VARCHAR2','NVARCHAR2','VARCHAR') THEN 12"
        "   WHEN DATA_TYPE IN ('CHAR','NCHAR') THEN 1"
        "   WHEN DATA_TYPE='DATE' THEN 93 WHEN DATA_TYPE LIKE 'TIMESTAMP%' THEN 93"
        "   WHEN DATA_TYPE='BINARY_FLOAT' THEN 7 WHEN DATA_TYPE='BINARY_DOUBLE' THEN 8"
        "   WHEN DATA_TYPE='RAW' THEN -3"
        "   WHEN DATA_TYPE IN ('LONG','CLOB','NCLOB') THEN -1"
        "   WHEN DATA_TYPE IN ('LONG RAW','BLOB') THEN -4 ELSE 12 END DATA_TYPE,"
        " DATA_TYPE TYPE_NAME,"
        " CASE WHEN DATA_TYPE='NUMBER' THEN NVL(DATA_PRECISION, 38) ELSE DATA_LENGTH END COLUMN_SIZE,"
        " DATA_LENGTH BUFFER_LENGTH, DATA_SCALE DECIMAL_DIGITS, 10 NUM_PREC_RADIX,"
        " 1 NULLABLE, CAST(NULL AS VARCHAR2(1)) REMARKS, CAST(NULL AS VARCHAR2(1)) COLUMN_DEF,"
        " CASE"
        "   WHEN DATA_TYPE='NUMBER' THEN 3 WHEN DATA_TYPE='FLOAT' THEN 6"
        "   WHEN DATA_TYPE IN ('VARCHAR2','NVARCHAR2','VARCHAR') THEN 12"
        "   WHEN DATA_TYPE IN ('CHAR','NCHAR') THEN 1"
        "   WHEN DATA_TYPE='DATE' THEN 93 WHEN DATA_TYPE LIKE 'TIMESTAMP%' THEN 93"
        "   WHEN DATA_TYPE='BINARY_FLOAT' THEN 7 WHEN DATA_TYPE='BINARY_DOUBLE' THEN 8"
        "   WHEN DATA_TYPE='RAW' THEN -3"
        "   WHEN DATA_TYPE IN ('LONG','CLOB','NCLOB') THEN -1"
        "   WHEN DATA_TYPE IN ('LONG RAW','BLOB') THEN -4 ELSE 12 END SQL_DATA_TYPE,"
        " CAST(NULL AS NUMBER) SQL_DATETIME_SUB,"
        " CASE WHEN DATA_TYPE IN ('VARCHAR2','NVARCHAR2','VARCHAR','CHAR','NCHAR','RAW')"
        "   THEN DATA_LENGTH ELSE CAST(NULL AS NUMBER) END CHAR_OCTET_LENGTH,"
        " POSITION ORDINAL_POSITION, 'YES' IS_NULLABLE"
        " FROM ALL_ARGUMENTS"
        " WHERE OWNER LIKE :1 AND OBJECT_NAME LIKE :2"
        "   AND (ARGUMENT_NAME LIKE :3 OR ARGUMENT_NAME IS NULL) AND DATA_LEVEL = 0"
        " ORDER BY OWNER, OBJECT_NAME, POSITION";

    const char *params[3] = { schema, proc, column };
    SQLRETURN ret = seer_odbc_run_query(s, PROCCOL_SQL, params, 3);
    free(schema); free(proc); free(column);
    return ret;
}

SQLRETURN SQL_API SQLSpecialColumns(SQLHSTMT     StatementHandle,
                                    SQLUSMALLINT IdentifierType,
                                    SQLCHAR     *CatalogName, SQLSMALLINT NameLength1,
                                    SQLCHAR     *SchemaName,  SQLSMALLINT NameLength2,
                                    SQLCHAR     *TableName,   SQLSMALLINT NameLength3,
                                    SQLUSMALLINT Scope, SQLUSMALLINT Nullable)
{
    (void)CatalogName; (void)NameLength1; (void)Scope; (void)Nullable;
    OdbcStmt *s = (OdbcStmt *)StatementHandle;
    if (s == NULL)
        return SQL_INVALID_HANDLE;
    seer_odbc_diag_clear(s);
    if (s->dbc == NULL || !s->dbc->connected)
        return seer_odbc_diag(s, "08003", 0, "Connection not open", SQL_ERROR);

    /* SQL_ROWVER: Oracle exposes no auto-updated row-version column - return the
     * 8-column shape with no rows. */
    if (IdentifierType != SQL_BEST_ROWID) {
        static const char *EMPTY_SQL =
            "SELECT CAST(NULL AS NUMBER) SCOPE, CAST(NULL AS VARCHAR2(128)) COLUMN_NAME,"
            " CAST(NULL AS NUMBER) DATA_TYPE, CAST(NULL AS VARCHAR2(128)) TYPE_NAME,"
            " CAST(NULL AS NUMBER) COLUMN_SIZE, CAST(NULL AS NUMBER) BUFFER_LENGTH,"
            " CAST(NULL AS NUMBER) DECIMAL_DIGITS, CAST(NULL AS NUMBER) PSEUDO_COLUMN"
            " FROM dual WHERE 1 = 0";
        return seer_odbc_run_query(s, EMPTY_SQL, NULL, 0);
    }

    /* SQL_BEST_ROWID: the best unique row identifier on Oracle is the ROWID
     * pseudo-column. Emit one descriptor row if the table exists (SCOPE =
     * SQL_SCOPE_SESSION, PSEUDO_COLUMN = SQL_PC_PSEUDO, DATA_TYPE = SQL_VARCHAR). */
    char *schema = pattern_dup(SchemaName, NameLength2);
    char *table  = pattern_dup(TableName, NameLength3);
    if (schema == NULL || table == NULL) {
        free(schema); free(table);
        return seer_odbc_diag(s, "HY001", 0, "Out of memory", SQL_ERROR);
    }
    static const char *ROWID_SQL =
        "SELECT 2 SCOPE, 'ROWID' COLUMN_NAME, 12 DATA_TYPE, 'ROWID' TYPE_NAME,"
        " 18 COLUMN_SIZE, 18 BUFFER_LENGTH, CAST(NULL AS NUMBER) DECIMAL_DIGITS,"
        " 2 PSEUDO_COLUMN"
        " FROM ALL_TABLES WHERE OWNER LIKE :1 AND TABLE_NAME LIKE :2";

    const char *params[2] = { schema, table };
    SQLRETURN ret = seer_odbc_run_query(s, ROWID_SQL, params, 2);
    free(schema); free(table);
    return ret;
}

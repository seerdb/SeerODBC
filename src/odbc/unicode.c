/* Unicode (*W) ODBC entry points.
 *
 * Exporting these makes the unixODBC Driver Manager treat SeerODBC as a
 * Unicode driver: it routes wide application calls here and uses the ANSI
 * functions for ANSI apps. Each wrapper converts its SQLWCHAR (UTF-16, host
 * byte order) string arguments to/from the UTF-8 the ANSI functions speak -
 * which is also Oracle's AL32UTF8 - so there is no lossy locale round-trip.
 *
 * Input-string functions convert their arguments and delegate to the matching
 * ANSI function; output-string functions call the ANSI function into a UTF-8
 * scratch buffer and convert the result back to UTF-16 in the caller's buffer.
 *
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#include "odbc_platform.h"   /* <windows.h> before the ODBC headers on Windows */

#include <sql.h>
#include <sqlext.h>
#include <sqlucode.h>

#include <stdlib.h>
#include <string.h>

#include "charset.h"

/* Decode a SQLWCHAR string (length in characters, or SQL_NTS) to a malloc'd
 * NUL-terminated UTF-8 string. NULL in -> NULL out (a genuinely absent arg). */
static char *w_to_utf8(const SQLWCHAR *w, SQLLEN len_chars)
{
    if (w == NULL)
        return NULL;
    size_t bytes;
    if (len_chars == SQL_NTS) {
        size_t n = 0;
        while (w[n] != 0) n++;
        bytes = n * sizeof(SQLWCHAR);
    } else {
        bytes = (len_chars > 0) ? (size_t)len_chars * sizeof(SQLWCHAR) : 0;
    }
    char  *out = NULL;
    size_t outlen = 0;
    if (seer_iconv(SEER_UTF16, "UTF-8", (const char *)w, bytes, &out, &outlen) != 0)
        return NULL;
    return out;
}

/* Encode a UTF-8 string into a SQLWCHAR buffer of `cap_chars` characters
 * (including the NUL). Sets *out_chars to the full length in characters (not
 * counting the NUL). Truncates on a code-unit boundary -> SQL_SUCCESS_WITH_INFO. */
static SQLRETURN emit_w(const char *u8, SQLWCHAR *buf, SQLLEN cap_chars,
                        SQLLEN *out_chars)
{
    char  *u16 = NULL;
    size_t u16len = 0;
    if (seer_iconv("UTF-8", SEER_UTF16, u8, strlen(u8), &u16, &u16len) != 0) {
        if (out_chars) *out_chars = 0;
        return SQL_ERROR;
    }
    size_t total = u16len / sizeof(SQLWCHAR);
    if (out_chars)
        *out_chars = (SQLLEN)total;

    SQLRETURN r = SQL_SUCCESS;
    if (buf != NULL && cap_chars > 0) {
        size_t cap = (size_t)cap_chars - 1;
        size_t cp  = total < cap ? total : cap;
        memcpy(buf, u16, cp * sizeof(SQLWCHAR));
        buf[cp] = 0;
        if (cp < total)
            r = SQL_SUCCESS_WITH_INFO;
    }
    free(u16);
    return r;
}

/* Byte-unit variant for functions whose buffer length / returned length are in
 * bytes (SQLGetInfoW, SQLColAttributeW) rather than characters. */
static SQLRETURN emit_w_bytes(const char *u8, SQLPOINTER buf, SQLSMALLINT cap_bytes,
                              SQLSMALLINT *out_bytes)
{
    SQLLEN oc = 0;
    SQLRETURN r = emit_w(u8, (SQLWCHAR *)buf,
                         (SQLLEN)(cap_bytes / (SQLSMALLINT)sizeof(SQLWCHAR)), &oc);
    if (out_bytes)
        *out_bytes = (SQLSMALLINT)(oc * (SQLLEN)sizeof(SQLWCHAR));
    return r;
}

/* ------------------------------------------------------------- connection */

SQLRETURN SQL_API SQLConnectW(SQLHDBC hdbc,
                              SQLWCHAR *szDSN, SQLSMALLINT cbDSN,
                              SQLWCHAR *szUID, SQLSMALLINT cbUID,
                              SQLWCHAR *szAuth, SQLSMALLINT cbAuth)
{
    char *dsn = w_to_utf8(szDSN, cbDSN);
    char *uid = w_to_utf8(szUID, cbUID);
    char *pwd = w_to_utf8(szAuth, cbAuth);
    SQLRETURN r = SQLConnect(hdbc,
                             (SQLCHAR *)dsn, dsn ? SQL_NTS : 0,
                             (SQLCHAR *)uid, uid ? SQL_NTS : 0,
                             (SQLCHAR *)pwd, pwd ? SQL_NTS : 0);
    free(dsn); free(uid); free(pwd);
    return r;
}

SQLRETURN SQL_API SQLDriverConnectW(SQLHDBC hdbc, SQLHWND hwnd,
                                    SQLWCHAR *szIn, SQLSMALLINT cbIn,
                                    SQLWCHAR *szOut, SQLSMALLINT cbOutMax,
                                    SQLSMALLINT *pcbOut, SQLUSMALLINT completion)
{
    char *in = w_to_utf8(szIn, cbIn);
    char  outbuf[2048];
    outbuf[0] = '\0';
    SQLSMALLINT outlen_a = 0;
    SQLRETURN r = SQLDriverConnect(hdbc, hwnd, (SQLCHAR *)in, in ? SQL_NTS : 0,
                                   (SQLCHAR *)outbuf, (SQLSMALLINT)sizeof outbuf,
                                   &outlen_a, completion);
    free(in);
    if (SQL_SUCCEEDED(r)) {
        SQLLEN oc = 0;
        SQLRETURN r2 = emit_w(outbuf, szOut, cbOutMax, &oc);
        if (pcbOut) *pcbOut = (SQLSMALLINT)oc;
        if (r == SQL_SUCCESS && r2 == SQL_SUCCESS_WITH_INFO)
            r = r2;
    }
    return r;
}

/* ------------------------------------------------------------- statements */

SQLRETURN SQL_API SQLPrepareW(SQLHSTMT hstmt, SQLWCHAR *szSql, SQLINTEGER cbSql)
{
    char *sql = w_to_utf8(szSql, cbSql);
    if (sql == NULL)
        return SQLPrepare(hstmt, NULL, 0);
    SQLRETURN r = SQLPrepare(hstmt, (SQLCHAR *)sql, SQL_NTS);
    free(sql);
    return r;
}

SQLRETURN SQL_API SQLExecDirectW(SQLHSTMT hstmt, SQLWCHAR *szSql, SQLINTEGER cbSql)
{
    char *sql = w_to_utf8(szSql, cbSql);
    if (sql == NULL)
        return SQLExecDirect(hstmt, NULL, 0);
    SQLRETURN r = SQLExecDirect(hstmt, (SQLCHAR *)sql, SQL_NTS);
    free(sql);
    return r;
}

/* ------------------------------------------------------------- diagnostics */

SQLRETURN SQL_API SQLGetDiagRecW(SQLSMALLINT htype, SQLHANDLE handle, SQLSMALLINT rec,
                                 SQLWCHAR *szState, SQLINTEGER *native,
                                 SQLWCHAR *szMsg, SQLSMALLINT cbMsgMax,
                                 SQLSMALLINT *pcbMsg)
{
    SQLCHAR     state[6] = { 0 };
    SQLCHAR     msg[1024] = { 0 };
    SQLSMALLINT mlen = 0;
    SQLRETURN r = SQLGetDiagRec(htype, handle, rec, state, native,
                                msg, (SQLSMALLINT)sizeof msg, &mlen);
    if (!SQL_SUCCEEDED(r))
        return r;                              /* SQL_NO_DATA / error pass through */

    if (szState != NULL) {                     /* 5 ASCII chars + NUL */
        int i = 0;
        for (; i < 5 && state[i] != '\0'; i++)
            szState[i] = (SQLWCHAR)state[i];
        szState[i] = 0;
    }
    SQLLEN oc = 0;
    SQLRETURN r2 = emit_w((char *)msg, szMsg, cbMsgMax, &oc);
    if (pcbMsg) *pcbMsg = (SQLSMALLINT)oc;
    return (r == SQL_SUCCESS && r2 == SQL_SUCCESS_WITH_INFO) ? r2 : r;
}

/* ---------------------------------------------------------------- get info */

/* The InfoTypes our SQLGetInfo answers with a string (so the W form must
 * widen them); everything else is numeric and passes through untouched. */
static int is_string_info(SQLUSMALLINT t)
{
    switch (t) {
    case SQL_DRIVER_NAME: case SQL_DRIVER_VER: case SQL_DRIVER_ODBC_VER:
    case SQL_DBMS_NAME: case SQL_DBMS_VER: case SQL_ODBC_VER:
    case SQL_IDENTIFIER_QUOTE_CHAR: case SQL_SEARCH_PATTERN_ESCAPE:
    case SQL_CATALOG_NAME: case SQL_CATALOG_NAME_SEPARATOR:
    case SQL_CATALOG_TERM: case SQL_SCHEMA_TERM: case SQL_TABLE_TERM:
    case SQL_PROCEDURE_TERM: case SQL_SPECIAL_CHARACTERS:
    case SQL_ACCESSIBLE_TABLES: case SQL_ACCESSIBLE_PROCEDURES:
    case SQL_DATA_SOURCE_READ_ONLY: case SQL_NEED_LONG_DATA_LEN:
    case SQL_MULTIPLE_ACTIVE_TXN:
        return 1;
    default:
        return 0;
    }
}

SQLRETURN SQL_API SQLGetInfoW(SQLHDBC hdbc, SQLUSMALLINT type,
                              SQLPOINTER buf, SQLSMALLINT cbMax, SQLSMALLINT *pcb)
{
    if (!is_string_info(type))
        return SQLGetInfo(hdbc, type, buf, cbMax, pcb);   /* numeric: untouched */

    SQLCHAR     tmp[1024] = { 0 };
    SQLSMALLINT alen = 0;
    SQLRETURN r = SQLGetInfo(hdbc, type, tmp, (SQLSMALLINT)sizeof tmp, &alen);
    if (!SQL_SUCCEEDED(r))
        return r;
    SQLSMALLINT ob = 0;
    SQLRETURN r2 = emit_w_bytes((char *)tmp, buf, cbMax, &ob);
    if (pcb) *pcb = ob;
    return (r == SQL_SUCCESS) ? r2 : r;
}

/* ------------------------------------------------------------ result metadata */

SQLRETURN SQL_API SQLDescribeColW(SQLHSTMT hstmt, SQLUSMALLINT col,
                                  SQLWCHAR *szName, SQLSMALLINT cbNameMax,
                                  SQLSMALLINT *pcbName, SQLSMALLINT *pType,
                                  SQLULEN *pColDef, SQLSMALLINT *pScale,
                                  SQLSMALLINT *pNullable)
{
    SQLCHAR     name[256] = { 0 };
    SQLSMALLINT nlen = 0;
    SQLRETURN r = SQLDescribeCol(hstmt, col, name, (SQLSMALLINT)sizeof name, &nlen,
                                 pType, pColDef, pScale, pNullable);
    if (!SQL_SUCCEEDED(r))
        return r;
    SQLLEN oc = 0;
    SQLRETURN r2 = emit_w((char *)name, szName, cbNameMax, &oc);   /* length in chars */
    if (pcbName) *pcbName = (SQLSMALLINT)oc;
    return (r == SQL_SUCCESS && r2 == SQL_SUCCESS_WITH_INFO) ? r2 : r;
}

SQLRETURN SQL_API SQLColAttributeW(SQLHSTMT hstmt, SQLUSMALLINT col,
                                   SQLUSMALLINT field, SQLPOINTER pCharAttr,
                                   SQLSMALLINT cbCharMax, SQLSMALLINT *pcbChar,
                                   SQLLEN *pNumAttr)
{
    SQLCHAR     tmp[512] = { 0 };
    SQLSMALLINT slen = 0;
    /* Numeric fields fill pNumAttr and leave tmp empty; string fields fill tmp. */
    SQLRETURN r = SQLColAttribute(hstmt, col, field, tmp, (SQLSMALLINT)sizeof tmp,
                                  &slen, pNumAttr);
    if (!SQL_SUCCEEDED(r))
        return r;
    SQLSMALLINT ob = 0;
    SQLRETURN r2 = emit_w_bytes((char *)tmp, pCharAttr, cbCharMax, &ob);
    if (pcbChar) *pcbChar = ob;
    return (r == SQL_SUCCESS) ? r2 : r;
}

/* ----------------------------------------------------------------- catalog */

SQLRETURN SQL_API SQLTablesW(SQLHSTMT hstmt,
                             SQLWCHAR *cat, SQLSMALLINT lcat,
                             SQLWCHAR *sch, SQLSMALLINT lsch,
                             SQLWCHAR *tab, SQLSMALLINT ltab,
                             SQLWCHAR *typ, SQLSMALLINT ltyp)
{
    char *c = w_to_utf8(cat, lcat), *s = w_to_utf8(sch, lsch);
    char *t = w_to_utf8(tab, ltab), *y = w_to_utf8(typ, ltyp);
    SQLRETURN r = SQLTables(hstmt,
                            (SQLCHAR *)c, c ? SQL_NTS : 0, (SQLCHAR *)s, s ? SQL_NTS : 0,
                            (SQLCHAR *)t, t ? SQL_NTS : 0, (SQLCHAR *)y, y ? SQL_NTS : 0);
    free(c); free(s); free(t); free(y);
    return r;
}

SQLRETURN SQL_API SQLColumnsW(SQLHSTMT hstmt,
                              SQLWCHAR *cat, SQLSMALLINT lcat,
                              SQLWCHAR *sch, SQLSMALLINT lsch,
                              SQLWCHAR *tab, SQLSMALLINT ltab,
                              SQLWCHAR *col, SQLSMALLINT lcol)
{
    char *c = w_to_utf8(cat, lcat), *s = w_to_utf8(sch, lsch);
    char *t = w_to_utf8(tab, ltab), *o = w_to_utf8(col, lcol);
    SQLRETURN r = SQLColumns(hstmt,
                             (SQLCHAR *)c, c ? SQL_NTS : 0, (SQLCHAR *)s, s ? SQL_NTS : 0,
                             (SQLCHAR *)t, t ? SQL_NTS : 0, (SQLCHAR *)o, o ? SQL_NTS : 0);
    free(c); free(s); free(t); free(o);
    return r;
}

SQLRETURN SQL_API SQLGetTypeInfoW(SQLHSTMT hstmt, SQLSMALLINT DataType)
{
    return SQLGetTypeInfo(hstmt, DataType);   /* no string arguments */
}

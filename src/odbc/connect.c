/* Connection establishment: SQLConnect / SQLDriverConnect / SQLDisconnect.
 *
 * SQLConnect resolves the DSN's HOST/PORT/SERVICE from odbc.ini (via our own
 * odbcini.c reader, not the Driver Manager's SQLGetPrivateProfileString, so the
 * driver depends on no instlib); SQLDriverConnect parses those same keywords
 * from the connection string. Both build SeerConnParams and call seer_connect(),
 * stashing the SeerConn on the DBC handle.
 *
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "log.h"
#include "odbc_internal.h"
#include "odbcini.h"
#include "sqlprep.h"

/* Opt-in protocol logging for debugging the driver under a Driver Manager,
 * which (unlike freeoracle) has no -v flag: set SEERODBC_DEBUG=1. */
__attribute__((constructor)) static void seerodbc_log_init(void)
{
    const char *e = getenv("SEERODBC_DEBUG");
    if (e != NULL && *e != '\0')
        seer_log_set_level(SEER_LOG_DEBUG);
}

/* Copy at most n bytes of a (possibly non-NUL-terminated) ODBC string. */
static char *odbc_strndup(const void *s, SQLSMALLINT len)
{
    if (s == NULL)
        return NULL;
    size_t n = (len == SQL_NTS) ? strlen((const char *)s) : (size_t)len;
    char *d = malloc(n + 1);
    if (d == NULL)
        return NULL;
    memcpy(d, s, n);
    d[n] = '\0';
    return d;
}

/* Find a "KEY=VALUE" in a ";"-separated connection string (case-insensitive
 * key). Returns a malloc'd value or NULL. */
static char *conn_str_get(const char *cs, const char *key)
{
    size_t klen = strlen(key);
    for (const char *p = cs; p != NULL && *p != '\0'; ) {
        const char *semi = strchr(p, ';');
        const char *eq   = strchr(p, '=');
        const char *end  = semi ? semi : p + strlen(p);
        if (eq != NULL && eq < end &&
            (size_t)(eq - p) == klen && strncasecmp(p, key, klen) == 0) {
            size_t vlen = (size_t)(end - (eq + 1));
            char *v = malloc(vlen + 1);
            if (v == NULL)
                return NULL;
            memcpy(v, eq + 1, vlen);
            v[vlen] = '\0';
            return v;
        }
        p = semi ? semi + 1 : end;
    }
    return NULL;
}

/* Read a DSN attribute from odbc.ini; returns malloc'd value or NULL. Uses our
 * own reader (odbcini.c) rather than the Driver Manager's
 * SQLGetPrivateProfileString, so the driver needs no libodbcinst/libiodbcinst. */
static char *dsn_get(const char *dsn, const char *key)
{
    char buf[512];
    int n = seer_get_private_profile_string(dsn, key, "", buf, sizeof buf, "odbc.ini");
    if (n <= 0)
        return NULL;
    return odbc_strndup(buf, (SQLSMALLINT)n);
}

/* PURITY connection attribute -> SEER_PURITY_* (DRCP session purity). Accepts
 * SELF / NEW (any case) or a number; absent/unknown is 0 (default). */
static int parse_purity(const char *s)
{
    if (s == NULL || !s[0]) return 0;
    if (s[0] == 'S' || s[0] == 's') return SEER_PURITY_SELF;
    if (s[0] == 'N' || s[0] == 'n') return SEER_PURITY_NEW;
    return atoi(s);
}

/* A DSN/attribute flag is "on" when its first char is 1/y/Y/t/T. */
static int flag_is_on(const char *s)
{
    return s && (s[0]=='1'||s[0]=='y'||s[0]=='Y'||s[0]=='t'||s[0]=='T');
}

/* PROTOCOL=TCPS (any case) selects TLS. */
static int proto_is_tcps(const char *s)
{
    return s && (s[0]=='T'||s[0]=='t') && (s[3]=='S'||s[3]=='s');
}

/* Resolve connection parameters, then connect. Ownership of the temporary
 * strings stays local. */
static SQLRETURN do_connect(OdbcDbc *c, const char *dsn,
                            const char *cs, const char *uid, const char *pwd)
{
    char *host = cs ? conn_str_get(cs, "HOST") : NULL;
    if (host == NULL && cs) host = conn_str_get(cs, "SERVER");
    char *port = cs ? conn_str_get(cs, "PORT") : NULL;
    char *svc  = cs ? conn_str_get(cs, "SERVICE") : NULL;
    if (svc == NULL && cs) svc = conn_str_get(cs, "SID");
    if (svc == NULL && cs) svc = conn_str_get(cs, "DATABASE");
    char *cuid = cs ? conn_str_get(cs, "UID") : NULL;
    char *cpwd = cs ? conn_str_get(cs, "PWD") : NULL;
    char *cclass = cs ? conn_str_get(cs, "CCLASS") : NULL;   /* DRCP */
    char *cpurity = cs ? conn_str_get(cs, "PURITY") : NULL;
    char *cssl = cs ? conn_str_get(cs, "SSL") : NULL;        /* TLS / TCPS */
    char *cproto = cs ? conn_str_get(cs, "PROTOCOL") : NULL;
    char *ctlsca = cs ? conn_str_get(cs, "TLSCA") : NULL;
    char *ctlsverify = cs ? conn_str_get(cs, "TLSVERIFY") : NULL;

    /* Fill any gaps from the DSN section of odbc.ini. */
    if (dsn != NULL) {
        if (host == NULL) { host = dsn_get(dsn, "HOST"); if (host == NULL) host = dsn_get(dsn, "SERVER"); }
        if (port == NULL) port = dsn_get(dsn, "PORT");
        if (svc  == NULL) { svc = dsn_get(dsn, "SERVICE"); if (svc == NULL) svc = dsn_get(dsn, "SID"); if (svc == NULL) svc = dsn_get(dsn, "DATABASE"); }
        if (cuid == NULL) cuid = dsn_get(dsn, "UID");
        if (cpwd == NULL) cpwd = dsn_get(dsn, "PWD");
        if (cclass == NULL) cclass = dsn_get(dsn, "CCLASS");
        if (cpurity == NULL) cpurity = dsn_get(dsn, "PURITY");
        if (cssl == NULL) cssl = dsn_get(dsn, "SSL");
        if (cproto == NULL) cproto = dsn_get(dsn, "PROTOCOL");
        if (ctlsca == NULL) ctlsca = dsn_get(dsn, "TLSCA");
        if (ctlsverify == NULL) ctlsverify = dsn_get(dsn, "TLSVERIFY");
    }

    /* TLS is requested by SSL=1/yes/true or PROTOCOL=TCPS; verification is on by
     * default (TLSVERIFY=0 disables it, e.g. for a self-signed test endpoint). */
    int use_tls = flag_is_on(cssl) || proto_is_tcps(cproto);
    int tls_verify = ctlsverify ? (ctlsverify[0]!='0'&&ctlsverify[0]!='n'&&ctlsverify[0]!='N'
                                   &&ctlsverify[0]!='f'&&ctlsverify[0]!='F') : 1;
    if (ctlsca && !ctlsca[0]) { free(ctlsca); ctlsca = NULL; }   /* empty -> system roots */

    const char *user = uid ? uid : cuid;
    const char *pass = pwd ? pwd : cpwd;

    SQLRETURN ret;
    if (host == NULL || svc == NULL) {
        ret = seer_odbc_diag(c, "08001", 0,
                             "Missing HOST or SERVICE in DSN/connection string", SQL_ERROR);
        goto out;
    }

    SeerConnParams p = {
        .host         = host,
        .port         = port ? (uint16_t)atoi(port) : 1521,
        .service_name = svc,
        .username     = user,
        .password     = pass,
        .use_tls      = use_tls,
        .tls_ca       = ctlsca,
        .tls_verify   = tls_verify,
        .cclass       = cclass,
        .purity       = parse_purity(cpurity),
    };

    SeerConn *conn = NULL;
    SeerStatus st = seer_connect(&p, &conn);
    if (st != SEER_OK) {
        const char *ora = (conn != NULL) ? seer_last_error(conn) : NULL;
        ret = seer_odbc_diag(c, seer_odbc_sqlstate(st), 0,
                             ora ? ora : seer_strerror(st), SQL_ERROR);
        goto out;
    }

    c->conn      = conn;
    c->connected = 1;
    seer_set_autocommit(conn, c->autocommit == SQL_AUTOCOMMIT_ON);
    ret = SQL_SUCCESS;

out:
    free(host); free(port); free(svc); free(cuid); free(cpwd);
    free(cclass); free(cpurity);
    free(cssl); free(cproto); free(ctlsca); free(ctlsverify);
    return ret;
}

SQLRETURN SQL_API SQLConnect(SQLHDBC      ConnectionHandle,
                             SQLCHAR     *ServerName,     SQLSMALLINT NameLength1,
                             SQLCHAR     *UserName,       SQLSMALLINT NameLength2,
                             SQLCHAR     *Authentication, SQLSMALLINT NameLength3)
{
    OdbcDbc *c = (OdbcDbc *)ConnectionHandle;
    if (c == NULL)
        return SQL_INVALID_HANDLE;
    seer_odbc_diag_clear(c);
    if (c->connected)
        return seer_odbc_diag(c, "08002", 0, "Connection already open", SQL_ERROR);

    char *dsn = odbc_strndup(ServerName, NameLength1);
    char *uid = odbc_strndup(UserName, NameLength2);
    char *pwd = odbc_strndup(Authentication, NameLength3);

    SQLRETURN ret = do_connect(c, dsn, NULL, uid, pwd);

    free(dsn); free(uid); free(pwd);
    return ret;
}

SQLRETURN SQL_API SQLDriverConnect(SQLHDBC      ConnectionHandle,
                                   SQLHWND      WindowHandle,
                                   SQLCHAR     *InConnectionString,
                                   SQLSMALLINT  StringLength1,
                                   SQLCHAR     *OutConnectionString,
                                   SQLSMALLINT  BufferLength,
                                   SQLSMALLINT *StringLength2Ptr,
                                   SQLUSMALLINT DriverCompletion)
{
    (void)WindowHandle;
    (void)DriverCompletion;
    OdbcDbc *c = (OdbcDbc *)ConnectionHandle;
    if (c == NULL)
        return SQL_INVALID_HANDLE;
    seer_odbc_diag_clear(c);
    if (c->connected)
        return seer_odbc_diag(c, "08002", 0, "Connection already open", SQL_ERROR);

    char *cs  = odbc_strndup(InConnectionString, StringLength1);
    char *dsn = cs ? conn_str_get(cs, "DSN") : NULL;

    SQLRETURN ret = do_connect(c, dsn, cs, NULL, NULL);

    /* Echo the input string back (a minimal "out" connection string). */
    if (ret == SQL_SUCCESS && OutConnectionString != NULL && BufferLength > 0 && cs != NULL) {
        SQLSMALLINT n = (SQLSMALLINT)snprintf((char *)OutConnectionString,
                                              (size_t)BufferLength, "%s", cs);
        if (StringLength2Ptr != NULL)
            *StringLength2Ptr = n;
    }

    free(cs); free(dsn);
    return ret;
}

/* Copy `s` into a SQLSMALLINT-counted output buffer (truncating, NUL-terminated);
 * *lenp gets the full untruncated length. */
static void out_str_small(const char *s, SQLCHAR *out, SQLSMALLINT buflen,
                          SQLSMALLINT *lenp)
{
    size_t len = strlen(s);
    if (lenp != NULL)
        *lenp = (SQLSMALLINT)len;
    if (out != NULL && buflen > 0) {
        size_t cp = (len < (size_t)buflen - 1) ? len : (size_t)buflen - 1;
        memcpy(out, s, cp);
        out[cp] = '\0';
    }
}

/* Iterative connect: accumulate attributes across calls, return SQL_NEED_DATA
 * with the still-missing keywords as a browse-result string until enough is
 * known to connect, then connect and return SQL_SUCCESS. A target is HOST +
 * SERVICE (or a DSN that resolves them); credentials are UID + PWD. */
SQLRETURN SQL_API SQLBrowseConnect(SQLHDBC      ConnectionHandle,
                                   SQLCHAR     *InConnectionString,
                                   SQLSMALLINT  StringLength1,
                                   SQLCHAR     *OutConnectionString,
                                   SQLSMALLINT  BufferLength,
                                   SQLSMALLINT *StringLength2Ptr)
{
    OdbcDbc *c = (OdbcDbc *)ConnectionHandle;
    if (c == NULL)
        return SQL_INVALID_HANDLE;
    seer_odbc_diag_clear(c);
    if (c->connected)
        return seer_odbc_diag(c, "08002", 0, "Connection already open", SQL_ERROR);

    /* Merge this round's attributes onto any carried from earlier rounds. */
    char *frag = odbc_strndup(InConnectionString, StringLength1);
    if (frag == NULL)
        return seer_odbc_diag(c, "HY001", 0, "Out of memory", SQL_ERROR);
    if (c->browse_cs == NULL) {
        c->browse_cs = frag;
    } else {
        size_t n = strlen(c->browse_cs) + 1 + strlen(frag) + 1;
        char *merged = malloc(n);
        if (merged == NULL) {
            free(frag);
            return seer_odbc_diag(c, "HY001", 0, "Out of memory", SQL_ERROR);
        }
        snprintf(merged, n, "%s;%s", c->browse_cs, frag);
        free(c->browse_cs);
        free(frag);
        c->browse_cs = merged;
    }
    char *cs = c->browse_cs;

    char *dsn  = conn_str_get(cs, "DSN");
    char *host = conn_str_get(cs, "HOST");
    if (host == NULL) host = conn_str_get(cs, "SERVER");
    char *svc  = conn_str_get(cs, "SERVICE");
    if (svc == NULL) svc = conn_str_get(cs, "SID");
    char *uid  = conn_str_get(cs, "UID");
    char *pwd  = conn_str_get(cs, "PWD");

    char missing[256];
    missing[0] = '\0';
    if (dsn == NULL) {
        if (host == NULL) strcat(missing, "HOST:Server=?;");
        if (svc  == NULL) strcat(missing, "SERVICE:Service Name=?;");
    }
    if (uid == NULL) strcat(missing, "UID:User ID=?;");
    if (pwd == NULL) strcat(missing, "PWD:Password=?;");

    SQLRETURN ret;
    if (missing[0] != '\0') {
        out_str_small(missing, OutConnectionString, BufferLength, StringLength2Ptr);
        ret = SQL_NEED_DATA;
    } else {
        ret = do_connect(c, dsn, cs, NULL, NULL);
        if (SQL_SUCCEEDED(ret)) {
            out_str_small(cs, OutConnectionString, BufferLength, StringLength2Ptr);
            free(c->browse_cs);
            c->browse_cs = NULL;
        }
    }
    free(dsn); free(host); free(svc); free(uid); free(pwd);
    return ret;
}

SQLRETURN SQL_API SQLDisconnect(SQLHDBC ConnectionHandle)
{
    OdbcDbc *c = (OdbcDbc *)ConnectionHandle;
    if (c == NULL)
        return SQL_INVALID_HANDLE;
    seer_odbc_diag_clear(c);
    if (c->connected && c->conn != NULL) {
        seer_disconnect(c->conn);
        c->conn = NULL;
        c->connected = 0;
    }
    free(c->browse_cs);            /* drop any half-finished browse */
    c->browse_cs = NULL;
    return SQL_SUCCESS;
}

/* Return the native (Oracle) form of a statement: the same transform SQLPrepare
 * applies - ODBC {escape} expansion and '?' -> :1, :2, ... marker rewriting.
 * Standard string-output truncation: *TextLength2Ptr is the full length. */
SQLRETURN SQL_API SQLNativeSql(SQLHDBC     ConnectionHandle,
                              SQLCHAR    *InStatementText, SQLINTEGER TextLength1,
                              SQLCHAR    *OutStatementText, SQLINTEGER BufferLength,
                              SQLINTEGER *TextLength2Ptr)
{
    OdbcDbc *c = (OdbcDbc *)ConnectionHandle;
    if (c == NULL)
        return SQL_INVALID_HANDLE;
    seer_odbc_diag_clear(c);
    if (InStatementText == NULL)
        return seer_odbc_diag(c, "HY009", 0, "Null statement text", SQL_ERROR);

    size_t n = (TextLength1 == SQL_NTS) ? strlen((const char *)InStatementText)
             : (TextLength1 < 0 ? 0 : (size_t)TextLength1);
    char *in = malloc(n + 1);
    if (in == NULL)
        return seer_odbc_diag(c, "HY001", 0, "Out of memory", SQL_ERROR);
    memcpy(in, InStatementText, n);
    in[n] = '\0';
    char *native = seer_sql_prepare(in);
    free(in);
    if (native == NULL)
        return seer_odbc_diag(c, "HY001", 0, "Out of memory", SQL_ERROR);

    size_t len = strlen(native);
    if (TextLength2Ptr != NULL)
        *TextLength2Ptr = (SQLINTEGER)len;
    SQLRETURN rc = SQL_SUCCESS;
    if (OutStatementText != NULL && BufferLength > 0) {
        size_t cp = (len < (size_t)BufferLength - 1) ? len : (size_t)BufferLength - 1;
        memcpy(OutStatementText, native, cp);
        OutStatementText[cp] = '\0';
        if (cp < len)
            rc = seer_odbc_diag(c, "01004", 0, "String data, right truncated",
                                SQL_SUCCESS_WITH_INFO);
    }
    free(native);
    return rc;
}

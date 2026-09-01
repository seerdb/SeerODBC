/* freeoracle - a tsql-style CLI that links the protocol core DIRECTLY,
 * bypassing ODBC and the Driver Manager entirely. It exists to prove the
 * wire protocol against a real server before (and independently of) the
 * ODBC shim - the same role FreeTDS's `tsql` plays for libtds.
 *
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "seer/seertns.h"

static void usage(const char *argv0)
{
    fprintf(stderr,
        "freeoracle (SeerODBC %d.%d.%d) - direct TNS protocol client\n"
        "usage: %s -H host [-p port] -s service [-u user] [-P password] [-q SQL] [-N int] [-T text] [-v]\n"
        "  -q SQL   run a SELECT and print the rows\n"
        "  -N int   bind the next parameter (:1, :2, ...) as a NUMBER\n"
        "  -T text  bind the next parameter as text\n"
        "  -v       verbose (debug-level protocol logging)\n",
        SEERTNS_VERSION_MAJOR, SEERTNS_VERSION_MINOR, SEERTNS_VERSION_PATCH,
        argv0);
}

/* A command-line bind: -N <int> or -T <text>, applied to :1, :2, ... in order. */
typedef struct { int is_text; long long ival; const char *tval; } CliBind;

/* Run a query and print the result set as tab-separated rows. */
static int run_query(SeerConn *conn, const char *sql,
                     const CliBind *binds, int nbinds)
{
    SeerStmt *stmt = NULL;
    SeerStatus st = seer_stmt_prepare(conn, sql, &stmt);
    if (st != SEER_OK) {
        fprintf(stderr, "prepare failed: %s\n", seer_strerror(st));
        return 1;
    }

    for (int i = 0; i < nbinds; i++) {
        if (binds[i].is_text)
            st = seer_stmt_bind_text(stmt, i + 1, binds[i].tval, -1);
        else
            st = seer_stmt_bind_int64(stmt, i + 1, binds[i].ival);
        if (st != SEER_OK) {
            fprintf(stderr, "bind %d failed: %s\n", i + 1, seer_strerror(st));
            seer_stmt_close(stmt);
            return 1;
        }
    }

    st = seer_stmt_execute(stmt);
    if (st != SEER_OK) {
        const char *ora = seer_last_error(conn);
        fprintf(stderr, "execute failed: %s%s%s\n", seer_strerror(st),
                ora ? " - " : "", ora ? ora : "");
        seer_stmt_close(stmt);
        return 1;
    }

    int ncols = seer_stmt_num_cols(stmt);
    for (int c = 0; c < ncols; c++)
        printf("%s%s", c ? "\t" : "", seer_stmt_col_name(stmt, c));
    printf("\n");

    static const char hexd[] = "0123456789abcdef";
    unsigned long n = 0;
    while ((st = seer_stmt_fetch(stmt)) == SEER_OK) {
        for (int c = 0; c < ncols; c++) {
            const void *val = NULL;
            size_t vlen = 0;
            int is_null = 0, is_binary = 0;
            seer_stmt_get_data(stmt, c, &val, &vlen, &is_null, &is_binary);
            if (c) putchar('\t');
            if (is_null) {
                fputs("(null)", stdout);
            } else if (is_binary) {            /* render binary as hex */
                const unsigned char *b = val;
                for (size_t i = 0; i < vlen; i++) {
                    putchar(hexd[b[i] >> 4]);
                    putchar(hexd[b[i] & 0x0F]);
                }
            } else {
                fwrite(val, 1, vlen, stdout);
            }
        }
        printf("\n");
        n++;
    }
    int rc = (st == SEER_ENODATA) ? 0 : 1;
    if (rc != 0)
        fprintf(stderr, "fetch failed: %s\n", seer_strerror(st));
    fprintf(stderr, "%lu row(s)\n", n);
    seer_stmt_close(stmt);
    return rc;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        usage(argv[0]);
        return 2;
    }

    SeerConnParams p = { .port = 1521 };
    SeerLogLevel level = SEER_LOG_INFO;   /* show the handshake by default */
    const char *sql = NULL;
    CliBind binds[16];
    int nbinds = 0;

    /* A while loop (rather than a for) so consuming an option's argument by
     * advancing the index does not mutate a for-loop counter mid-body. */
    int i = 1;
    while (i < argc) {
        const char *a  = argv[i++];              /* option token */
        const char *v  = (i < argc) ? argv[i] : NULL;   /* its argument, if any */
        int have_arg   = (v != NULL);
        if      (strcmp(a, "-v") == 0) level = SEER_LOG_DEBUG;
        else if (strcmp(a, "-H") == 0 && have_arg) { p.host         = v; i++; }
        else if (strcmp(a, "-p") == 0 && have_arg) { p.port         = (uint16_t)atoi(v); i++; }
        else if (strcmp(a, "-s") == 0 && have_arg) { p.service_name = v; i++; }
        else if (strcmp(a, "-u") == 0 && have_arg) { p.username     = v; i++; }
        else if (strcmp(a, "-P") == 0 && have_arg) { p.password     = v; i++; }
        else if (strcmp(a, "-q") == 0 && have_arg) { sql            = v; i++; }
        else if (strcmp(a, "-N") == 0 && have_arg && nbinds < 16) {
            binds[nbinds].is_text = 0;
            binds[nbinds].ival = atoll(v);
            nbinds++;
            i++;
        }
        else if (strcmp(a, "-T") == 0 && have_arg && nbinds < 16) {
            binds[nbinds].is_text = 1;
            binds[nbinds].tval = v;
            nbinds++;
            i++;
        }
        else { usage(argv[0]); return 2; }
    }

    if (p.host == NULL) {
        usage(argv[0]);
        return 2;
    }

    seer_log_set_level(level);

    SeerConn *conn = NULL;
    SeerStatus st = seer_connect(&p, &conn);

    if (st == SEER_OK) {
        printf("connected to %s:%u\n", p.host, p.port);
        int rc = 0;
        if (sql != NULL)
            rc = run_query(conn, sql, binds, nbinds);
        seer_disconnect(conn);
        return rc;
    }

    if (st == SEER_ENOTIMPL) {
        /* Expected at the current milestone: the handshake + TTC negotiation
         * run to completion and reach the auth challenge (see the log above),
         * but O5LOGON is not wired up yet. Treat it as a successful protocol
         * probe, not a hard failure. */
        printf("login reached the authentication challenge against %s:%u; "
               "O5LOGON not yet implemented.\n", p.host, p.port);
        return 0;
    }

    fprintf(stderr, "connect failed: %s\n", seer_strerror(st));
    return 1;
}

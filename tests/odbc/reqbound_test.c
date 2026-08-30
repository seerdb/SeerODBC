/* Live test for request boundaries (§35) against the core protocol API.
 *
 * Self-gating: exits 77 (skip) unless SEER_TEST_HOST/SERVICE/USER are set, so it
 * is harmless in an offline `meson test`. Request boundaries need a 21c+ server
 * (compile_caps[40] bit 0x40 AND runtime_caps[6] bit 0x10); on 10g/11g the API
 * returns SEER_ENOTIMPL and the wire-level cases are skipped.
 *
 * Drives a logical request: begin -> a query (the REQUEST_BEGIN marker rides its
 * message) -> end (REQUEST_END on a rollback). Correctness is that the server
 * accepts the piggybacks (the query succeeds, no ORA error) and the connection
 * stays usable afterwards (no stream desync). Also covers the begin-with-no-op
 * cancel path.
 *
 *   SEER_TEST_HOST, SEER_TEST_PORT (default 1521), SEER_TEST_SERVICE,
 *   SEER_TEST_USER, SEER_TEST_PASS
 *
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdio.h>
#include <stdlib.h>

#include "seer/seertns.h"

static int pass_n, fail_n, skip_n;
static void pass(const char *n) { printf("  PASS %s\n", n); pass_n++; }
static void fail(const char *n, const char *w) { printf("  FAIL %s: %s\n", n, w); fail_n++; }
static void skip(const char *n, const char *w) { printf("  SKIP %s: %s\n", n, w); skip_n++; }

/* Run "SELECT <lit> FROM dual" and return the value as a long (-1 on failure). */
static long select_lit(SeerConn *c, int lit)
{
    char sql[64];
    snprintf(sql, sizeof sql, "SELECT %d FROM dual", lit);
    SeerStmt *s = NULL;
    if (seer_stmt_prepare(c, sql, &s) != SEER_OK)
        return -1;
    long n = -1;
    if (seer_stmt_execute(s) == SEER_OK && seer_stmt_fetch(s) == SEER_OK) {
        const char *v = NULL; int isnull = 0;
        if (seer_stmt_get_string(s, 0, &v, &isnull) == SEER_OK && v)
            n = atol(v);
    }
    seer_stmt_close(s);
    return n;
}

int main(void)
{
    if (!getenv("SEER_TEST_HOST") || !getenv("SEER_TEST_SERVICE") || !getenv("SEER_TEST_USER")) {
        fprintf(stderr, "reqbound_test: set SEER_TEST_HOST/SERVICE/USER[/PORT/PASS] - skipping\n");
        return 77;
    }
    const char *port = getenv("SEER_TEST_PORT");
    SeerConnParams p = {
        .host = getenv("SEER_TEST_HOST"),
        .port = (uint16_t)(port ? atoi(port) : 1521),
        .service_name = getenv("SEER_TEST_SERVICE"),
        .username = getenv("SEER_TEST_USER"),
        .password = getenv("SEER_TEST_PASS"),
    };
    SeerConn *c = NULL;
    if (seer_connect(&p, &c) != SEER_OK) {
        fprintf(stderr, "reqbound_test: connect failed\n");
        return 1;
    }

    /* Probe support: begin returns SEER_ENOTIMPL on a server without the caps. */
    SeerStatus rc = seer_request_begin(c);
    if (rc == SEER_ENOTIMPL) {
        skip("request boundaries", "server does not advertise the capability (pre-21c)");
        seer_disconnect(c);
        printf("SUMMARY reqbound pass=%d fail=%d skip=%d\n", pass_n, fail_n, skip_n);
        return 0;
    }
    if (rc != SEER_OK) {
        fail("begin", "request_begin failed on a capable server");
        seer_disconnect(c);
        printf("SUMMARY reqbound pass=%d fail=%d skip=%d\n", pass_n, fail_n, skip_n);
        return 1;
    }

    /* Full request: BEGIN rode the arming above; run a query so it flushes in
     * front of that message, then end the request (REQUEST_END on a rollback). */
    seer_set_autocommit(c, 0);
    if (select_lit(c, 41) == 41)
        pass("begin marker rides the query (server accepted it)");
    else
        fail("begin+query", "query after request_begin did not return");

    if (seer_request_end(c) == SEER_OK)
        pass("end marker on rollback accepted");
    else
        fail("end", "request_end failed");

    if (select_lit(c, 42) == 42)
        pass("connection usable after the request (no desync)");
    else
        fail("post-request query", "connection unusable after end");

    /* Cancel path: begin then end with no op in between sends nothing and leaves
     * the connection clean. */
    if (seer_request_begin(c) == SEER_OK && seer_request_end(c) == SEER_OK
        && select_lit(c, 7) == 7)
        pass("begin-then-end with no op cancels cleanly");
    else
        fail("cancel path", "begin/end with no op left the connection unusable");

    seer_disconnect(c);
    printf("SUMMARY reqbound pass=%d fail=%d skip=%d\n", pass_n, fail_n, skip_n);
    return fail_n ? 1 : 0;
}

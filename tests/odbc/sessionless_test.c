/* Live test for sessionless transactions (§31) against the core protocol API.
 *
 * Self-gating: exits 77 (skip) unless SEER_TEST_HOST/SERVICE/USER are set, so it
 * is harmless in an offline `meson test`. Sessionless transactions are 23ai+; on
 * an older server begin returns SEER_ENOTIMPL and the test skips.
 *
 * Drives the whole lifecycle across two connections: begin + insert on A,
 * suspend on A, resume on B, commit on B — then verifies the row is invisible
 * while suspended (isolation) and durable after the cross-session commit. The
 * insert after begin also exercises the server SYNC piggyback (opcode 5) the
 * response carries while a sessionless txn is active.
 *
 *   SEER_TEST_HOST, SEER_TEST_PORT (default 1521), SEER_TEST_SERVICE,
 *   SEER_TEST_USER, SEER_TEST_PASS
 *
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "seer/seertns.h"

static int pass_n, fail_n, skip_n;
static void pass(const char *n) { printf("  PASS %s\n", n); pass_n++; }
static void fail(const char *n, const char *w) { printf("  FAIL %s: %s\n", n, w); fail_n++; }
static void skip(const char *n, const char *w) { printf("  SKIP %s: %s\n", n, w); skip_n++; }

static SeerConn *connect_one(void)
{
    const char *port = getenv("SEER_TEST_PORT");
    SeerConnParams p = {
        .host = getenv("SEER_TEST_HOST"),
        .port = (uint16_t)(port ? atoi(port) : 1521),
        .service_name = getenv("SEER_TEST_SERVICE"),
        .username = getenv("SEER_TEST_USER"),
        .password = getenv("SEER_TEST_PASS"),
    };
    SeerConn *c = NULL;
    return seer_connect(&p, &c) == SEER_OK ? c : NULL;
}

static void exec_sql(SeerConn *c, const char *sql)
{
    SeerStmt *s = NULL;
    if (seer_stmt_prepare(c, sql, &s) != SEER_OK) return;
    seer_stmt_execute(s);
    seer_stmt_close(s);
}

static long count_123(SeerConn *c)
{
    SeerStmt *s = NULL;
    if (seer_stmt_prepare(c, "SELECT COUNT(*) FROM seersless WHERE n=123", &s) != SEER_OK)
        return -1;
    long n = -1;
    if (seer_stmt_execute(s) == SEER_OK && seer_stmt_fetch(s) == SEER_OK) {
        const char *v = NULL; int isnull = 0;
        if (seer_stmt_get_string(s, 0, &v, &isnull) == SEER_OK && v) n = atol(v);
    }
    seer_stmt_close(s);
    return n;
}

int main(void)
{
    if (!getenv("SEER_TEST_HOST") || !getenv("SEER_TEST_SERVICE") || !getenv("SEER_TEST_USER")) {
        fprintf(stderr, "sessionless_test: set SEER_TEST_HOST/SERVICE/USER[/PORT/PASS] - skipping\n");
        return 77;
    }
    SeerConn *a = connect_one();
    SeerConn *b = connect_one();
    if (!a || !b) { fprintf(stderr, "sessionless_test: connect failed\n"); return 1; }

    exec_sql(a, "DROP TABLE seersless");
    exec_sql(a, "CREATE TABLE seersless (n NUMBER)");   /* DDL autocommits */
    seer_set_autocommit(a, 0);
    seer_set_autocommit(b, 0);

    const uint8_t txn[] = "seer-sless-1";
    size_t txn_len = sizeof txn - 1;

    /* Begin on A. Pre-23ai returns ENOTIMPL -> skip the whole feature. */
    SeerStatus rc = seer_txn_begin_sessionless(a, txn, txn_len, 60);
    if (rc == SEER_ENOTIMPL) {
        skip("sessionless transactions", "server is pre-23ai");
        exec_sql(a, "DROP TABLE seersless");
        goto done;
    }
    if (rc != SEER_OK) { fail("begin", "begin_sessionless failed on a 23ai server"); goto cleanup; }
    pass("begin on connection A");

    /* Insert on A (joins the sessionless txn; its response carries the SYNC
     * piggyback, which the parser must consume without desyncing). */
    exec_sql(a, "INSERT INTO seersless VALUES (123)");
    if (count_123(a) == 1)
        pass("insert visible in the owning session (SYNC piggyback consumed)");
    else
        fail("insert", "row not visible in the owning session (possible desync)");

    /* B (not in the txn) must not see the uncommitted row. */
    if (count_123(b) == 0)
        pass("uncommitted row invisible to another session (isolation)");
    else
        fail("isolation", "another session saw the uncommitted sessionless row");

    /* Suspend on A, resume on B, commit on B. */
    if (seer_txn_suspend_sessionless(a) == SEER_OK)
        pass("suspend on A");
    else
        fail("suspend", "suspend_sessionless failed");

    if (seer_txn_resume_sessionless(b, txn, txn_len, 60) == SEER_OK)
        pass("resume on connection B");
    else
        fail("resume", "resume_sessionless failed on B");

    if (seer_commit(b) == SEER_OK)
        pass("commit on B ends the sessionless txn");
    else
        fail("commit", "commit on B failed");

    /* The row is now durable and visible to a fresh check on B. */
    if (count_123(b) == 1)
        pass("row durable after cross-session commit");
    else
        fail("durability", "row missing after resume+commit on B");

cleanup:
    seer_set_autocommit(a, 1);
    exec_sql(a, "DROP TABLE seersless");
done:
    seer_disconnect(a);
    seer_disconnect(b);
    printf("SUMMARY sessionless pass=%d fail=%d skip=%d\n", pass_n, fail_n, skip_n);
    return fail_n ? 1 : 0;
}

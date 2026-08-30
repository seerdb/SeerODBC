/* Live test for request pipelining (§32, #132) — the serial execution path.
 *
 * Self-gating: exits 77 (skip) unless SEER_TEST_HOST/SERVICE/USER are set, so it
 * is harmless in an offline `meson test`. Runs on every server (the single-round-
 * trip wire burst is a later optimisation with identical results). Covers the
 * op/result model, reading a query op's rows, and continue-on-error.
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

static int pass_n, fail_n;
static void pass(const char *n) { printf("  PASS %s\n", n); pass_n++; }
static void fail(const char *n, const char *w) { printf("  FAIL %s: %s\n", n, w); fail_n++; }

static void exec_sql(SeerConn *c, const char *sql)
{
    SeerStmt *s = NULL;
    if (seer_stmt_prepare(c, sql, &s) != SEER_OK) return;
    seer_stmt_execute(s);
    seer_stmt_close(s);
}

int main(void)
{
    if (!getenv("SEER_TEST_HOST") || !getenv("SEER_TEST_SERVICE") || !getenv("SEER_TEST_USER")) {
        fprintf(stderr, "pipeline_test: set SEER_TEST_HOST/SERVICE/USER[/PORT/PASS] - skipping\n");
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
    if (seer_connect(&p, &c) != SEER_OK) { fprintf(stderr, "connect failed\n"); return 1; }

    exec_sql(c, "DROP TABLE seerpipe");
    exec_sql(c, "CREATE TABLE seerpipe (n NUMBER)");   /* DDL autocommits */
    seer_set_autocommit(c, 0);

    /* Happy path: two inserts, a query, a commit — all in order. */
    SeerPipeline *pl = seer_pipeline_create();
    seer_pipeline_add_execute(pl, "INSERT INTO seerpipe VALUES (10)");
    seer_pipeline_add_execute(pl, "INSERT INTO seerpipe VALUES (20)");
    seer_pipeline_add_fetchall(pl, "SELECT n FROM seerpipe ORDER BY n");
    seer_pipeline_add_commit(pl);

    if (seer_pipeline_run(c, pl, 0) == SEER_OK && seer_pipeline_count(pl) == 4)
        pass("run 4 ops");
    else
        fail("run", "run/count wrong");

    int all_ok = 1;
    for (size_t i = 0; i < 4; i++)
        if (seer_pipeline_op_status(pl, i, NULL) != SEER_OK) all_ok = 0;
    if (all_ok) pass("all ops succeeded"); else fail("op status", "an op failed");

    /* The fetchall op (index 2) holds the rows: expect 10 then 20. */
    SeerStmt *q = seer_pipeline_op_stmt(pl, 2);
    long got1 = -1, got2 = -1;
    if (q != NULL) {
        const char *v = NULL; int isn = 0;
        if (seer_stmt_fetch(q) == SEER_OK && seer_stmt_get_string(q, 0, &v, &isn) == SEER_OK && v)
            got1 = atol(v);
        if (seer_stmt_fetch(q) == SEER_OK && seer_stmt_get_string(q, 0, &v, &isn) == SEER_OK && v)
            got2 = atol(v);
    }
    if (got1 == 10 && got2 == 20)
        pass("query op rows readable (10, 20)");
    else
        fail("query rows", "fetchall op did not yield the two rows");

    /* Non-query ops expose no statement. */
    if (seer_pipeline_op_stmt(pl, 0) == NULL && seer_pipeline_op_stmt(pl, 3) == NULL)
        pass("execute/commit ops expose no statement");
    else
        fail("op stmt", "a non-query op unexpectedly kept a statement");

    seer_pipeline_free(pl);

    /* continue-on-error: a bogus op in the middle; the rest still run. */
    SeerPipeline *pe = seer_pipeline_create();
    seer_pipeline_add_fetchall(pe, "SELECT 1 FROM dual");
    seer_pipeline_add_execute(pe, "INSERT INTO nonexistent_table_xyz VALUES (1)");
    seer_pipeline_add_fetchall(pe, "SELECT 2 FROM dual");
    seer_pipeline_run(c, pe, /*continue_on_error=*/1);

    long ora = 0;
    int okA = seer_pipeline_op_status(pe, 0, NULL) == SEER_OK;
    int failB = seer_pipeline_op_status(pe, 1, &ora) != SEER_OK && ora != 0;
    int okC = seer_pipeline_op_status(pe, 2, NULL) == SEER_OK &&
              seer_pipeline_op_stmt(pe, 2) != NULL;
    if (okA && failB && okC)
        pass("continue_on_error: failing op recorded, later ops still ran");
    else
        fail("continue_on_error", "error handling / ordering wrong");

    seer_pipeline_free(pe);

    /* Burst-eligible pipeline (no commit): on an EOR-negotiated 23ai+ server this
     * runs as one token-tagged round trip; elsewhere it runs serially. Either way
     * both query ops' rows must come back correctly (token correlation + describe
     * + rows through the burst). */
    SeerPipeline *pb = seer_pipeline_create();
    seer_pipeline_add_fetchall(pb, "SELECT 100 FROM dual");
    seer_pipeline_add_fetchall(pb, "SELECT 200 FROM dual");
    seer_pipeline_run(c, pb, 0);
    long b1 = -1, b2 = -1;
    SeerStmt *q1 = seer_pipeline_op_stmt(pb, 0);
    SeerStmt *q2 = seer_pipeline_op_stmt(pb, 1);
    const char *v = NULL; int isn = 0;
    if (q1 && seer_stmt_fetch(q1) == SEER_OK && seer_stmt_get_string(q1, 0, &v, &isn) == SEER_OK && v)
        b1 = atol(v);
    if (q2 && seer_stmt_fetch(q2) == SEER_OK && seer_stmt_get_string(q2, 0, &v, &isn) == SEER_OK && v)
        b2 = atol(v);
    if (b1 == 100 && b2 == 200)
        pass("two-query pipeline: both ops' rows correct (token-correlated)");
    else
        fail("burst queries", "the two query ops did not both yield their rows");
    seer_pipeline_free(pb);

    exec_sql(c, "DROP TABLE seerpipe");
    seer_disconnect(c);
    printf("SUMMARY pipeline pass=%d fail=%d\n", pass_n, fail_n);
    return fail_n ? 1 : 0;
}

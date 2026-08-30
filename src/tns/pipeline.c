/* Request pipelining (§32, #132) — the operation/result model and the serial
 * execution path.
 *
 * A SeerPipeline queues several operations that run in order. This file runs
 * them one at a time over the ordinary statement API — the correct fallback that
 * works on every server. On a 23ai+ connection that negotiated end-of-response
 * framing (§32 stages 1-2) the exec-family ops are later sent as a single
 * token-tagged round trip (#158); that wire burst replaces the loop below while
 * keeping this exact result model. The API mirrors seerdb/python-oracledb.
 *
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#include "seer/seertns.h"

#include "conn.h"   /* struct SeerConn (EOR/ANO gate) + the burst entry points */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef enum {
    PIPE_EXECUTE,
    PIPE_FETCHONE,
    PIPE_FETCHMANY,
    PIPE_FETCHALL,
    PIPE_COMMIT,
} PipeOpType;

typedef struct {
    PipeOpType  type;
    char       *sql;         /* NULL for commit                                  */
    uint32_t    num_rows;    /* fetchmany hint (carried for the future burst)    */
    /* Filled by seer_pipeline_run: */
    SeerStmt   *stmt;        /* executed statement for a query op, else NULL     */
    SeerStatus  status;      /* per-op outcome                                   */
    long        ora_code;    /* server ORA number when it failed, else 0         */
} PipeOp;

struct SeerPipeline {
    PipeOp *ops;
    size_t  n;
    size_t  cap;
    int     ran;
};

static int pipe_is_query(PipeOpType t)
{
    return t == PIPE_FETCHONE || t == PIPE_FETCHMANY || t == PIPE_FETCHALL;
}

SeerPipeline *seer_pipeline_create(void)
{
    return calloc(1, sizeof(SeerPipeline));
}

void seer_pipeline_free(SeerPipeline *p)
{
    if (p == NULL)
        return;
    for (size_t i = 0; i < p->n; i++) {
        seer_stmt_close(p->ops[i].stmt);   /* NULL-safe */
        free(p->ops[i].sql);
    }
    free(p->ops);
    free(p);
}

/* Append an operation, growing the array as needed. */
static SeerStatus pipe_add(SeerPipeline *p, PipeOpType type, const char *sql,
                           uint32_t num_rows)
{
    if (p == NULL || (sql == NULL && type != PIPE_COMMIT))
        return SEER_EPARAM;
    if (p->n == p->cap) {
        size_t ncap = p->cap ? p->cap * 2 : 8;
        PipeOp *np = realloc(p->ops, ncap * sizeof *np);
        if (np == NULL)
            return SEER_ENOMEM;
        p->ops = np;
        p->cap = ncap;
    }
    PipeOp *op = &p->ops[p->n];
    memset(op, 0, sizeof *op);
    op->type     = type;
    op->num_rows = num_rows;
    if (sql != NULL) {
        op->sql = strdup(sql);
        if (op->sql == NULL)
            return SEER_ENOMEM;
    }
    p->n++;
    return SEER_OK;
}

SeerStatus seer_pipeline_add_execute(SeerPipeline *p, const char *sql)
{
    return pipe_add(p, PIPE_EXECUTE, sql, 0);
}
SeerStatus seer_pipeline_add_fetchone(SeerPipeline *p, const char *sql)
{
    return pipe_add(p, PIPE_FETCHONE, sql, 1);
}
SeerStatus seer_pipeline_add_fetchmany(SeerPipeline *p, const char *sql, uint32_t num_rows)
{
    return pipe_add(p, PIPE_FETCHMANY, sql, num_rows);
}
SeerStatus seer_pipeline_add_fetchall(SeerPipeline *p, const char *sql)
{
    return pipe_add(p, PIPE_FETCHALL, sql, 0);
}
SeerStatus seer_pipeline_add_commit(SeerPipeline *p)
{
    return pipe_add(p, PIPE_COMMIT, NULL, 0);
}

/* Parse the leading ORA-NNNNN number from a server error message, or 0. */
static long ora_number(SeerConn *conn)
{
    const char *msg = seer_last_error(conn);
    long code = 0;
    if (msg != NULL)
        sscanf(msg, "ORA-%ld", &code);
    return code;
}

/* Run one operation over the ordinary statement API, recording its outcome. */
static void run_op(SeerConn *conn, PipeOp *op)
{
    op->stmt     = NULL;
    op->status   = SEER_OK;
    op->ora_code = 0;

    if (op->type == PIPE_COMMIT) {
        op->status = seer_commit(conn);
        if (op->status == SEER_EDB)
            op->ora_code = ora_number(conn);
        return;
    }

    SeerStmt  *s  = NULL;
    SeerStatus st = seer_stmt_prepare(conn, op->sql, &s);
    if (st != SEER_OK) {
        op->status = st;
        return;
    }
    st = seer_stmt_execute(s);
    if (st != SEER_OK) {
        op->status   = st;
        op->ora_code = ora_number(conn);
        seer_stmt_close(s);
        return;
    }
    /* A query keeps its statement so the caller can read the rows; an execute
     * (DML/DDL/PL-SQL) has none, so close it now. */
    if (pipe_is_query(op->type))
        op->stmt = s;
    else
        seer_stmt_close(s);
}

/* The single-round-trip wire burst (#158) covers the exec-family ops only, and
 * needs an EOR-negotiated connection with no ANO cipher active (the burst framing
 * bypasses the per-packet wrap). A commit / unsupported op, or any other server,
 * falls back to the serial loop — identical API, ordering and results. */
static int pipeline_wire_eligible(SeerConn *conn, SeerPipeline *p)
{
    if (!conn->supports_eor || conn->ano != NULL || p->n == 0)
        return 0;
    for (size_t i = 0; i < p->n; i++)
        if (p->ops[i].type == PIPE_COMMIT)
            return 0;
    return 1;
}

/* Run the whole pipeline as one token-tagged round trip. Prepares a fresh stmt
 * per op (fetch ops get a large inline prefetch), runs the burst, and distributes
 * the per-op outcomes into the result model (identical to the serial path). */
static SeerStatus run_burst(SeerConn *conn, SeerPipeline *p)
{
    SeerStmt **stmts = calloc(p->n, sizeof *stmts);
    long      *codes = calloc(p->n, sizeof *codes);
    if (stmts == NULL || codes == NULL) { free(stmts); free(codes); return SEER_ENOMEM; }

    SeerStatus st = SEER_OK;
    for (size_t i = 0; i < p->n; i++) {
        st = seer_stmt_prepare(conn, p->ops[i].sql, &stmts[i]);
        if (st != SEER_OK)
            break;
        uint32_t pf = 0;
        if (p->ops[i].type == PIPE_FETCHONE)  pf = 1;
        else if (p->ops[i].type == PIPE_FETCHMANY) pf = p->ops[i].num_rows ? p->ops[i].num_rows : 100;
        else if (p->ops[i].type == PIPE_FETCHALL)  pf = 32760;
        if (pf != 0)
            seer_stmt_set_prefetch(stmts[i], pf);
    }
    if (st == SEER_OK)
        st = seer_stmt_pipeline_burst(conn, stmts, p->n, codes);
    if (st != SEER_OK) {
        for (size_t i = 0; i < p->n; i++)
            seer_stmt_close(stmts[i]);
        free(stmts);
        free(codes);
        return st;
    }

    for (size_t i = 0; i < p->n; i++) {
        long code = codes[i];
        p->ops[i].ora_code = code > 0 ? code : 0;
        p->ops[i].status   = code == 0 ? SEER_OK
                           : (code == -1 ? SEER_EPROTO : SEER_EDB);
        if (pipe_is_query(p->ops[i].type) && code == 0)
            p->ops[i].stmt = stmts[i];       /* keep for row access */
        else
            seer_stmt_close(stmts[i]);       /* execute op, or a failed op */
    }
    free(stmts);
    free(codes);
    return SEER_OK;
}

SeerStatus seer_pipeline_run(SeerConn *conn, SeerPipeline *p, int continue_on_error)
{
    if (conn == NULL || p == NULL)
        return SEER_EPARAM;

    /* A re-run releases the prior run's kept statements. */
    for (size_t i = 0; i < p->n; i++) {
        seer_stmt_close(p->ops[i].stmt);
        p->ops[i].stmt = NULL;
    }

    /* Fast path: one token-tagged round trip for an eligible pipeline. The wire
     * always runs continue-on-error (all ops execute), so the caller's
     * continue_on_error only shapes the serial fallback's early stop. */
    if (pipeline_wire_eligible(conn, p)) {
        SeerStatus st = run_burst(conn, p);
        if (st == SEER_OK) {
            p->ran = 1;
            return SEER_OK;
        }
        /* A build-time failure before any bytes went out is safe to retry
         * serially; a mid-wire failure returns the error. */
        if (st != SEER_ENOMEM)
            return st;
    }

    for (size_t i = 0; i < p->n; i++) {
        run_op(conn, &p->ops[i]);
        if (p->ops[i].status != SEER_OK && !continue_on_error) {
            /* Stop, but leave the remaining ops in a clean not-run state. */
            for (size_t j = i + 1; j < p->n; j++) {
                p->ops[j].stmt     = NULL;
                p->ops[j].status   = SEER_OK;
                p->ops[j].ora_code = 0;
            }
            break;
        }
    }
    p->ran = 1;
    return SEER_OK;
}

size_t seer_pipeline_count(const SeerPipeline *p)
{
    return p ? p->n : 0;
}

SeerStatus seer_pipeline_op_status(const SeerPipeline *p, size_t i, long *ora_code)
{
    if (p == NULL || i >= p->n)
        return SEER_EPARAM;
    if (ora_code != NULL)
        *ora_code = p->ops[i].ora_code;
    return p->ops[i].status;
}

SeerStmt *seer_pipeline_op_stmt(const SeerPipeline *p, size_t i)
{
    if (p == NULL || i >= p->n)
        return NULL;
    return p->ops[i].stmt;
}

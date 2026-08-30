/* Internal connection state, shared between session.c (TNS handshake) and
 * ttc.c (TTC negotiation/auth). NOT a public header - the opaque SeerConn in
 * include/seer/seertns.h is all the shim and tools ever see.
 *
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SEER_TNS_CONN_H
#define SEER_TNS_CONN_H

#include <stdbool.h>
#include <stdint.h>

#include "transport.h"
#include "writer.h"

/* Active ANO channel (native encryption + data integrity); defined in ano.c. */
typedef struct SeerAno SeerAno;

struct SeerConn {
    SeerTransport *t;
    SeerAno       *ano;            /* non-NULL once ANO encryption is active  */
    uint16_t       version;        /* negotiated TNS version (from ACCEPT)   */
    uint16_t       sdu;            /* negotiated Session Data Unit           */
    uint8_t        seq;            /* TTC sequence number, 1..127 (wrapping) */
    uint8_t        field_version;  /* negotiated TTC field version (from PRO) */
    bool           authenticated;  /* O5LOGON completed                      */
    bool           autocommit;     /* commit each statement (default true)    */
    /* Request boundaries (§35): server support (from PRO caps), the one-shot
     * armed marker (0 / REQUEST_BEGIN / REQUEST_END) flushed as a func-176
     * piggyback in front of the next call, and whether a logical request is open. */
    bool           req_boundaries;
    uint8_t        session_state;
    bool           in_request;
    /* Sessionless transactions (§31): a sessionless txn is currently begun/resumed
     * on this connection (client-side tracking, like seerdb). */
    bool           sessionless_active;
    uint32_t       server_release; /* packed AUTH_VERSION_NO                  */
    char          *last_error;     /* last ORA-NNNNN message (malloc'd)       */
    volatile bool  in_call;        /* blocked in seer_ttc_recv (cancel window) */
    /* Server cursors of closed statements, flushed as a CLOSE_CURSORS piggyback
     * in front of the next execute so they don't leak until session end. */
    int            close_cursors[256];
    int            n_close;
    /* Statement cache: a closed statement's parsed server cursor is kept open,
     * keyed by its exact SQL text, so re-preparing the same SQL re-executes it
     * without a re-parse. `cols`/`ncols` carry the SELECT column describe (moved
     * to/from the statement - stmt.c owns the SeerColumn type, hence void*).
     * Bounded; the oldest entry is evicted (and its cursor closed). */
    struct { char *sql; int cursor_id; void *cols; int ncols; } stmt_cache[24];
    int            stmt_cache_n;
    /* Opaque transaction context returned by tpc_begin, replayed on the
     * end/prepare/commit/rollback calls of the same global transaction. */
    uint8_t       *tpc_context;
    size_t         tpc_context_len;
};

/* Free every cached statement's SQL + describe columns (session teardown). The
 * server cursors themselves die with the session. Defined in stmt.c, which owns
 * the SeerColumn type. */
void seer_stmt_cache_clear(struct SeerConn *conn);

/* Build a TPC/sessionless TXN_SWITCH message (function 103) into `w`: the
 * fun-header, op, the (optional, NULL) stored context flag, the xid descriptor +
 * 128-byte payload, flags and timeout. Shared by the XA and sessionless paths;
 * exposed (non-static) so the offline KAT can pin the sessionless framing. */
SeerStatus seer_tpc_build_switch(struct SeerConn *c, SeerWriter *w, uint32_t op,
                                 const SeerXid *xid, uint32_t flags, uint32_t timeout);

/* Test-only: parse an execute response, reporting column count + OER error code
 * (defined in stmt.c). Backs the RPA-skip regression test. */
SeerStatus seer_test_parse_execute_response(const uint8_t *buf, size_t len,
                                            uint8_t fv, int *out_ncols,
                                            int64_t *out_err);

#endif /* SEER_TNS_CONN_H */

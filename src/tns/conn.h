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

#endif /* SEER_TNS_CONN_H */

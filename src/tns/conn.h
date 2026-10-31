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
  SeerAno *ano;          /* non-NULL once ANO encryption is active  */
  uint16_t version;      /* negotiated TNS version (from ACCEPT)   */
  uint16_t sdu;          /* negotiated Session Data Unit           */
  uint8_t seq;           /* TTC sequence number, 1..127 (wrapping) */
  uint8_t field_version; /* negotiated TTC field version (from PRO) */
  bool authenticated;    /* O5LOGON completed                      */
  bool is_8i;            /* Oracle 8i (8.1.x): its own login + statement dialect */
  bool autocommit;       /* commit each statement (default true)    */
  bool lob_inline;       /* fetch CLOB / BLOB columns inline (SeerConnParams) */
  /* Request boundaries (§35): server support (from PRO caps), the one-shot
   * armed marker (0 / REQUEST_BEGIN / REQUEST_END) flushed as a func-176
   * piggyback in front of the next call, and whether a logical request is open. */
  bool req_boundaries;
  /* The server's maximum string size: 32767 when it advertises 32K strings,
   * else 4000. A bind declared larger is "LONG-class" (sent after the row's
   * other values in a SQL statement). */
  uint32_t max_string_size;
  /* The field version the server advertised (compile caps), as opposed to the
   * negotiated field_version. Some fields follow the server's release: 21c+
   * sends the OER's SQL type + checksum to every session, even one that
   * negotiated a lower version. */
  uint8_t server_field_version;
  uint8_t session_state;
  bool in_request;
  /* End-of-response framing (§32/#155): the accept advertised it (flags2 bit),
   * so we opt in via the DTY cap and the server terminates every response with
   * a TTI_END_OF_RESPONSE (29) token. Prerequisite for request pipelining. */
  bool supports_eor;
  /* Pipelining (§32/#158): the token written into the fun-header (0 = ordinary
   * call; 1..N tags a pipelined op so the server can correlate its response). */
  uint32_t pipeline_token;
  /* Sessionless transactions (§31): a sessionless txn is currently begun/resumed
   * on this connection (client-side tracking, like seerdb). */
  bool sessionless_active;
  uint32_t server_release; /* packed AUTH_VERSION_NO                  */
  char *last_error;        /* last ORA-NNNNN message (malloc'd)       */
  long last_error_offset;  /* its parse offset into the SQL text, 0 if none */
  volatile bool in_call;   /* blocked in seer_ttc_recv (cancel window) */
  /* Server cursors of closed statements, flushed as a CLOSE_CURSORS piggyback
   * in front of the next execute so they don't leak until session end. */
  int close_cursors[256];
  int n_close;
  /* Temporary LOBs (bind promotions) no longer referenced, to free with a
   * FREE_TEMP piggyback in front of the next execute (like close_cursors). */
  uint8_t **free_lobs;
  size_t *free_lob_lens;
  int n_free_lobs, free_lobs_cap;
  /* Statement cache: a closed statement's parsed server cursor is kept open,
   * keyed by its exact SQL text, so re-preparing the same SQL re-executes it
   * without a re-parse. `cols`/`ncols` carry the SELECT column describe (moved
   * to/from the statement - stmt.c owns the SeerColumn type, hence void*).
   * Bounded; the oldest entry is evicted (and its cursor closed). */
  struct {
    char *sql;
    int cursor_id;
    void *cols;
    int ncols;
  } stmt_cache[24];
  int stmt_cache_n;
  /* Opaque transaction context returned by tpc_begin, replayed on the
   * end/prepare/commit/rollback calls of the same global transaction. */
  uint8_t *tpc_context;
  size_t tpc_context_len;
};

/* Free every cached statement's SQL + describe columns (session teardown). The
 * server cursors themselves die with the session. Defined in stmt.c, which owns
 * the SeerColumn type. */
void seer_stmt_cache_clear(struct SeerConn *conn);

/* Build a TPC/sessionless TXN_SWITCH message (function 103) into `w`: the
 * fun-header, op, the (optional, NULL) stored context flag, the xid descriptor +
 * 128-byte payload, flags and timeout. Shared by the XA and sessionless paths;
 * exposed (non-static) so the offline KAT can pin the sessionless framing. */
SeerStatus seer_tpc_build_switch(struct SeerConn *c, SeerWriter *w, uint32_t op, const SeerXid *xid,
                                 uint32_t flags, uint32_t timeout);

/* Test-only: parse an execute response, reporting column count + OER error code
 * (defined in stmt.c). Backs the RPA-skip regression test. */
SeerStatus seer_test_parse_execute_response(const uint8_t *buf, size_t len, uint8_t fv,
                                            int *out_ncols, int64_t *out_err);

/* Test-only: build the fetch-only OALL8 for `cursor` on a connection at field
 * version `fv` / server release `release`, whose next sequence number is `seq`
 * (defined in stmt.c). The caller frees *out. */
SeerStatus seer_test_build_fetch_only(uint8_t fv, uint32_t release, uint8_t seq, int cursor,
                                      uint8_t **out, size_t *outlen);

/* Test-only: decode a 9i (fv2) DML/DDL status reply into its affected-row count
 * and ORA code (defined in stmt.c). Backs the fv2 status regression test. */
void seer_test_fv2_decode_dml(const uint8_t *buf, size_t len, int64_t *rowcount, int64_t *code);

/* Oracle 8i login (defined in ttc.c): build an OSESSKEY / OAUTH call at 8i's
 * fixed little-endian widths, and read one value of its reply. */
SeerStatus seer_o8i_build_login(SeerConn *conn, SeerWriter *w, uint8_t op, const char *user,
                                uint32_t mode, const char *password_field, const char *host,
                                const char *pid);
SeerStatus seer_o8i_auth_value(const uint8_t *b, size_t n, const char *key, char **val);
SeerStatus seer_test_o8i_all8(uint8_t seq, bool fetch, uint32_t cursor, const char *sql,
                              uint32_t rows, uint8_t **out, size_t *outlen);

/* Test-only: gather a LOBOPS reply's TTI_LOB content (defined in lob.c);
 * SEER_EPROTO when it runs past the end of the reply. */
SeerStatus seer_test_lob_content(const uint8_t *resp, size_t rlen, bool sb4_chunks, uint8_t **out,
                                 size_t *outlen);

/* Pipelining (§32/#158, defined in stmt.c). seer_stmt_set_prefetch tunes a fetch
 * op's inline prefetch; seer_stmt_pipeline_burst runs n freshly-prepared ops as
 * one token-tagged round trip, filling the stmts + per-op ora_codes. Used by the
 * pipeline layer (pipeline.c). */
void seer_stmt_set_prefetch(SeerStmt *stmt, uint32_t rows);
SeerStatus seer_stmt_pipeline_burst(struct SeerConn *conn, SeerStmt **stmts, size_t n,
                                    long *ora_codes);

#endif /* SEER_TNS_CONN_H */

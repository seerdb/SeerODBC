/* TTC (Two-Task Common) presentation layer (PROTOCOL.md §3-4).
 *
 * Rides on TNS_DATA packets once the TNS session is accepted: protocol
 * negotiation (TTI_PRO), data-type negotiation (TTI_DTY), then session setup
 * (TTI_SESS) which elicits the authentication challenge. The O5LOGON response
 * that consumes the challenge is the next milestone.
 *
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SEER_TNS_TTC_H
#define SEER_TNS_TTC_H

#include <stddef.h>
#include <stdint.h>

#include "seer/seertns.h"
#include "writer.h"

/* The server's authentication challenge (PROTOCOL.md §4.4), with the hex-coded
 * wire values decoded to raw bytes. For 11g `csk_salt` is absent (NULL). */
typedef struct {
    uint8_t *sesskey;       /* AUTH_SESSKEY (server session key)   */
    size_t   sesskey_len;
    uint8_t *salt;          /* AUTH_VFR_DATA (verifier salt)       */
    size_t   salt_len;
    uint8_t *csk_salt;      /* AUTH_PBKDF2_CSK_SALT (12c+ only)    */
    size_t   csk_salt_len;
} SeerAuthChallenge;

void seer_auth_challenge_free(SeerAuthChallenge *ch);

/* Run TTI_PRO + TTI_DTY negotiation, then TTI_SESS, and capture the auth
 * challenge into *out_challenge. The connection must already hold an accepted
 * TNS session. */
SeerStatus seer_ttc_login(SeerConn *conn, const SeerConnParams *params,
                          SeerAuthChallenge *out_challenge);

/* Compute the O5LOGON response to `challenge`, send TTI_AUTH, and validate the
 * server's reply. On SEER_OK the connection is authenticated. Only the 11g
 * 192-bit variant is supported (returns SEER_ENOTIMPL otherwise). */
SeerStatus seer_ttc_authenticate(SeerConn *conn, const SeerConnParams *params,
                                 const SeerAuthChallenge *challenge);

/* Best-effort TTI_LOGOFF + TNS EOF marker (PROTOCOL.md §10) on an
 * authenticated connection. Silent no-op otherwise. */
void seer_ttc_logoff(SeerConn *conn);

/* --- Data-message framing, shared with the statement layer (stmt.c). --- */

/* Send a TTC message wrapped in a TNS_DATA packet. */
SeerStatus seer_ttc_send(SeerConn *conn, const uint8_t *msg, size_t len);

/* Receive a complete TTC message (reassembling fragments). *out is malloc'd. */
SeerStatus seer_ttc_recv(SeerConn *conn, uint8_t **out, size_t *outlen);

/* Request pipelining (§32/#158) burst primitives. */
void seer_ttc_pipeline_begin(SeerConn *conn, SeerWriter *w, uint32_t token, uint8_t mode);
void seer_ttc_pipeline_end(SeerConn *conn, SeerWriter *w);
SeerStatus seer_ttc_send_pipeline_op(SeerConn *conn, const uint8_t *data, size_t len,
                                     uint16_t final_flags, uint16_t first_flags);
SeerStatus seer_ttc_recv_pipeline(SeerConn *conn, uint8_t **out, size_t *outlen);

/* Run the ANO native-encryption negotiation (§33) over the accepted TNS
 * session, before PRO. On success the connection's cipher is activated when the
 * server selects an algorithm, else the session stays plaintext. */
SeerStatus seer_ttc_ano_negotiate(SeerConn *conn);

/* Next per-connection TTC sequence number (1..127, wrapping). */
uint8_t seer_ttc_next_seq(SeerConn *conn);

/* Encode a request-boundary (session-state) piggyback (§35) into `w`: func-176,
 * `seq`, an optional ub8 token (fv > 23.1), then the var-int state with the
 * explicit-boundary bit OR'd in. Pure/testable. */
void seer_ttc_session_state_piggyback(SeerWriter *w, uint8_t seq,
                                      uint8_t field_version, uint8_t state);

/* If a request-boundary marker is armed on `conn`, prepend its piggyback into
 * `w` (consuming a sequence number) and clear it (one-shot). No-op otherwise. */
void seer_ttc_flush_session_state(SeerConn *conn, SeerWriter *w);

/* Write a TTC function-message header (TTI_FUN, opcode, seq) into `w`,
 * consuming a fresh sequence number. At fv24 (field_version > 23.1) Oracle
 * writes an extra 0x00 pointer byte after the sequence number on every function
 * message; this helper appends it so callers stay version-agnostic. */
void seer_ttc_fun_header(SeerConn *conn, SeerWriter *w, uint8_t opcode);

#endif /* SEER_TNS_TTC_H */

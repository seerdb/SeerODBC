/* TTC token and function identifiers (PROTOCOL.md §3).
 *
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SEER_TNS_TNS_CONSTS_H
#define SEER_TNS_TNS_CONSTS_H

/* TTC token types (§3.1) */
#define TTI_PRO   1   /* protocol negotiation       */
#define TTI_DTY   2   /* data-type negotiation      */
#define TTI_FUN   3   /* function call              */
#define TTI_OER   4   /* Oracle error / status response */
#define TTI_RXH   6   /* row header                 */
#define TTI_RXD   7   /* row data                   */
#define TTI_RPA   8   /* return parameter (KV pairs)*/
#define TTI_STA   9   /* status (transaction)       */
#define TTI_IOV  11   /* I/O vector (bind directions) */
#define TTI_LOB  14   /* LOB data chunk             */
#define TTI_WRN  15   /* warning                    */
#define TTI_DCB  16   /* describe info (columns)    */
#define TTI_BVC  21   /* bit vector for changed cols */
#define TTI_SVR_PIGGYBACK 23 /* server-side session-state piggyback (DRCP) */
#define TTI_IRD  27   /* implicit result set descriptor (12c+) */
#define TTI_END_OF_RESPONSE 29 /* per-response terminator (EOR framing, #155) */
#define TTI_TOKEN           33 /* response-correlation marker (pipelining, #132) */

/* Request pipelining wire burst (§32/#158). A begin-pipeline piggyback (func
 * 199) rides the first message with data flag BEGIN_PIPELINE; each op message
 * carries END_OF_REQUEST; a pipeline-end message (func 200) closes the burst.
 * The server tags each op's response with a TTI_TOKEN (33) + ub8 token and ends
 * it with TTI_END_OF_RESPONSE (29). The wire always runs continue-on-error. */
#define TNS_FUNC_PIPELINE_BEGIN       199
#define TNS_FUNC_PIPELINE_END         200
#define TNS_DATA_FLAGS_BEGIN_PIPELINE 0x1000
#define TNS_DATA_FLAGS_END_OF_REQUEST 0x0800
#define TNS_PIPELINE_MODE_CONTINUE    1

/* Server-side piggyback opcodes (DRCP, #130). */
#define TNS_SVR_PIG_OS_PID_MTS  2
#define TNS_SVR_PIG_SESS_RET    4
#define TNS_SVR_PIG_SYNC        5   /* sessionless-txn sync state (§31, #133) */

/* Sessionless transactions (§31, #133, 23ai+): reuse the TPC SWITCH (103) with
 * the SESSIONLESS flag OR'd into the START/DETACH flags and a magic format-id in
 * the xid slot (the user txn id goes in the gtrid, bqual empty). Commit/rollback
 * are ordinary TTI_COMMIT/TTI_ROLLBACK. START flags reuse SEER_TPC_BEGIN_NEW /
 * _RESUME (0x01 / 0x04). */
#define TNS_TPC_FLAGS_SESSIONLESS      0x10
#define TNS_TPC_SESSIONLESS_FORMAT_ID  0x4E5C3E
#define TNS_TPC_SESSIONLESS_ID_MAX     64

/* Two-phase commit / XA (TPC, #131). Two function calls carry it: SWITCH attaches
 * or detaches a transaction branch, CHANGE_STATE drives prepare/commit/abort. */
#define TNS_FUNC_TPC_TXN_SWITCH        103
#define TNS_FUNC_TPC_TXN_CHANGE_STATE  104
#define TNS_TPC_TXN_START   1   /* SWITCH op: begin/attach a branch  */
#define TNS_TPC_TXN_DETACH  2   /* SWITCH op: end/suspend the branch */
#define TNS_TPC_TXN_COMMIT  1   /* CHANGE_STATE op: commit           */
#define TNS_TPC_TXN_ABORT   2   /* CHANGE_STATE op: rollback         */
#define TNS_TPC_TXN_PREPARE 3   /* CHANGE_STATE op: prepare          */
/* CHANGE_STATE state values (sent on commit, returned by prepare/commit). */
#define TNS_TPC_TXN_STATE_REQUIRES_COMMIT 1
#define TNS_TPC_TXN_STATE_COMMITTED       2
#define TNS_TPC_TXN_STATE_ABORTED         3
#define TNS_TPC_TXN_STATE_READ_ONLY       4
#define TNS_TPC_TXN_STATE_FORGOTTEN       5
#define TNS_TPC_XID_WIRE_LEN 128   /* gtrid+bqual zero-padded to a fixed size */

/* Advanced Queuing (AQ, #128). ENQ/DEQ carry a queue name, message properties,
 * a 16-byte payload type OID (RAW sentinel = 15 zeros + 0x17), and the payload. */
#define TNS_FUNC_AQ_ENQ                121
#define TNS_FUNC_AQ_DEQ                122
#define TNS_FUNC_ARRAY_AQ             145   /* bulk enqueue / dequeue          */
#define TNS_AQ_ARRAY_ENQ               0x01
#define TNS_AQ_ARRAY_DEQ               0x02
#define TNS_AQ_ARRAY_RETURN_MSGID      0x01 /* return message ids             */
#define TNS_AQ_MESSAGE_VERSION         1
#define TNS_AQ_MESSAGE_ID_LENGTH       16
#define TNS_AQ_ENQ_ON_COMMIT           2    /* enqueue visibility default */
#define TNS_AQ_DEQ_BROWSE             1    /* dequeue mode: peek, leave in queue */
#define TNS_AQ_DEQ_REMOVE              3    /* dequeue mode: remove the message */
#define TNS_AQ_DEQ_FIRST_MSG          1    /* dequeue navigation: (re)start at first */
#define TNS_AQ_DEQ_NEXT_MSG            3    /* dequeue navigation: next message */
#define TNS_AQ_DEQ_ON_COMMIT           2    /* dequeue visibility default */
#define ORA_AQ_NO_MESSAGE          25228    /* dequeue: no message (empty/wait) */
#define ORA_AQ_DEQ_TIMEOUT         25254    /* dequeue: wait timed out          */
#define TNS_AQ_RAW_TOID_SENTINEL       0x17 /* last byte of the RAW payload TOID */
#define TNS_AQ_JSON_TOID_SENTINEL      0x47 /* last byte of the JSON payload TOID */
#define TNS_AQ_EXT_KEYWORD_AGENT_NAME      64
#define TNS_AQ_EXT_KEYWORD_AGENT_ADDRESS   65
#define TNS_AQ_EXT_KEYWORD_AGENT_PROTOCOL  66
#define TNS_AQ_EXT_KEYWORD_ORIGINAL_MSGID  69

/* TTC function IDs carried by TTI_FUN (§3.2) */
#define TTI_LOGOFF   9
#define TTI_COMMIT  14
#define TTI_ROLLBACK 15
#define TTI_FETCH    5   /* fetch rows                       */
#define TTI_LOBOPS  96   /* LOB operations                   */
#define TTI_ALL8    94   /* generic execute (Oracle 8+)      */
#define TTI_ALL7    71   /* 9i (fv2) execute/parse dialect   */

/* al8i4[9] exec-flag values (12c+): request per-iteration array-DML row counts
 * (rides with the al8pidmlrc block), and request implicit result sets. */
#define TNS_AL8I4_ARRAY_DML_ROWCOUNTS 0xC000
#define TNS_AL8I4_IMPLICIT_RESULTSET  0x8000

/* TTI_LOBOPS opcodes (§14.2) */
#define LOB_OP_READ        0x0002
#define LOB_OP_FILE_OPEN   0x0100  /* open a BFILE before reading (§19.8) */
#define LOB_OP_FILE_CLOSE  0x0200  /* close an opened BFILE                */
#define TTI_AUTH   115   /* O5LOGON authentication response  */
#define TTI_SESS   118   /* session setup / auth phase 1     */
#define TTI_3LOGON  81   /* O3LOGON phase 2 (9i, 0x51)       */
#define TTI_3LOGA   82   /* O3LOGON phase 1 (9i, 0x52)       */
/* Oracle 9i (fv2) TTI_ALL7 query dialect function IDs (PROTOCOL.md §19). */
#define O7_OPEN     0x02 /* OOPEN: allocate a server cursor  */
#define O7_DESCRIBE 0x62 /* describe columns (metadata RPA)  */
#define O7_CLOSE    0x14 /* close cursor                     */
#define FV2_BIND_PROMPT 0x0B /* 9i PL/SQL block "send the binds" prompt token */

/* 23ai fast-auth (PROTOCOL.md §20): PRO+DTY+OSESSKEY bundled in one message,
 * marked with this leading byte instead of a TTI token. */
#define TNS_MSG_TYPE_FAST_AUTH    0x22
#define TNS_SERVER_CONVERTS_CHARS 0x01

/* Piggyback (rides in front of a function call): close a batch of server cursors
 * (TTI_OCCA) so they don't leak until session end. */
#define TTI_MSG_TYPE_PIGGYBACK    0x11
#define TTI_OCCA                  105   /* close cursors */

/* Request boundaries (§35, #464): a func-176 SESSION_STATE piggyback telling the
 * server a logical request begins/ends so it can reset session state between
 * requests. The body is a var-int state with the explicit-boundary bit OR'd in.
 * Gated on compile_caps[40] bit 0x40 AND runtime_caps[6] bit 0x10 (21c+). */
#define TNS_FUNC_SESSION_STATE              176
#define TNS_SESSION_STATE_REQUEST_BEGIN     0x04
#define TNS_SESSION_STATE_REQUEST_END       0x08
#define TNS_SESSION_STATE_EXPLICIT_BOUNDARY 0x40
/* The cap slots + bits that gate the feature (server side). */
#define TNS_CCAP_TTC4                       40
#define TNS_CCAP_TTC4_EXPLICIT_BOUNDARY     0x40
#define TNS_RCAP_TTC                        6
#define TNS_RCAP_TTC_SESSION_STATE_OPS      0x10

/* End-of-response framing (§32/#155): opt in by setting compile_caps[40] bit
 * 0x20 in the DTY, but only when the ACCEPT advertised support — the extended
 * flags2 ub4 at accept body offset 33 (present at version >= 318) carries the
 * HAS_END_OF_RESPONSE bit. Once negotiated the server terminates every response
 * with a TTI_END_OF_RESPONSE (29) token. Prerequisite for request pipelining. */
#define TNS_CCAP_TTC4_END_OF_RESPONSE       0x20
#define TNS_VERSION_MIN_OOB_CHECK           318
#define TNS_ACCEPT_FLAG_HAS_END_OF_RESPONSE 0x02000000u
#define TNS_ACCEPT_FLAGS2_OFFSET            33

/* TTC field versions. 11.2 is the long-standing default; 12.1 is the threshold
 * at which the 12c+ wire forms (UB2 datatype table, extended OER, oaccolid in
 * the describe, al8pidmlrc in the execute) kick in. */
#define TTC_FIELD_VERSION_9_2  2        /* Oracle 9i (O3LOGON, TTI_ALL7 dialect) */
#define TTC_FIELD_VERSION_10_2 4        /* Oracle 10g; oldest O5LOGON tier        */
#define TTC_FIELD_VERSION_11_2 6
#define TTC_FIELD_VERSION_12_1 7
#define TTC_FIELD_VERSION_12_2 8
#define TTC_FIELD_VERSION_19_1 12
#define TTC_FIELD_VERSION_19_1_EXT1 13  /* written inside the FAST_AUTH envelope */
#define TTC_FIELD_VERSION_20_1 14
#define TTC_FIELD_VERSION_21_1 16
#define TTC_FIELD_VERSION_23_1 17       /* highest the legacy handshake reaches  */
#define TTC_FIELD_VERSION_23_4 24       /* 23ai max; reached only via fast-auth   */
/* Highest field version we advertise by default. Servers negotiate down to
 * min(server_fv, this), so 9i/10g/11g stay on their native legacy fv untouched;
 * 21c moves to fv16 and 23ai to native fv24 (fast-auth). We expose the biggest
 * version whose data path is complete (currently 23.4: fast-auth login, the
 * fv24 function-header pointer byte, SELECT execute flags, and the describe
 * domain/annotation/vector fields all land at fv24). SEER_MAX_FV overrides it.
 * Raise this as higher fvs are completed. */
#define TTC_FIELD_VERSION_MAX  TTC_FIELD_VERSION_23_4

/* Oracle character set id: AL32UTF8 (real UTF-8). */
#define ORA_CHARSET_AL32UTF8 873

#endif /* SEER_TNS_TNS_CONSTS_H */

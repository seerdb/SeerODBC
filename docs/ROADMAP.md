<!--
SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors

SPDX-License-Identifier: Apache-2.0
-->
# SeerODBC roadmap / feature checklist

A living inventory of what the driver does and doesn't do yet. `[x]` = implemented
and exercised (most against the live 9i/10g/11g/21c/23ai matrix, see
`tests/odbc/run-matrix.sh`); `[ ]` = not yet. Keep this in sync as features land.

## Server versions (negotiated TTC field version)

- [x] Oracle 10g — fv4 (DES verifier, fv4 describe). **Local-only for CI**: it can
      be containerized but its image isn't redistributable, so like 9i it stays out
      of public GitHub CI (tested locally via `run-matrix.sh`).
- [x] Oracle 11g — fv6 (the long-standing baseline).  ┐ public-CI tier
- [x] Oracle 21c — fv16 (native 12c wire forms).      │ (11g XE / 21c XE /
- [x] Oracle 23ai — **fv24 native** (fast-auth), default cap.  ┘ 23ai FREE images)
- [ ] Oracle 12c / 18c / 19c — should negotiate fv7–14, but no container to prove it
- [x] Oracle 9i — **fv2, live-validated against a 9i VM** (127.0.0.1:1526, SID=orcl;
      not containerizable — needs an old kernel/glibc). The whole legacy path is in:
      O3LOGON DES auth, the TTI_ALL7 (`0x47`) query/fetch dialect (distinct from the
      TTI_ALL8 we send 10g+), DML/DDL, binds, PL/SQL blocks (IN/OUT), CLOB/BLOB/BFILE
      read, and national-charset binds — all fv-gated so 10g+ is untouched. See the
      per-feature `[x]` entries below and pyoracle's `docs/PROTOCOL.md` §19. Wired
      into `run-matrix.sh` as a **local-only** 9i row (its own core-API test
      `tests/odbc/test_9i.c`, SID-addressed, self-gating); it is deliberately *not*
      a meson `test()` so `meson test` / GitHub CI never reference 9i (9i and 10g
      stay local; 11g/21c/23ai are the intended public-CI tier). Override the
      endpoint with `SEER_9I_*`.

Default cap is `TTC_FIELD_VERSION_23_4` (24); servers negotiate down via
`min(server_fv, cap)`. `SEER_MAX_FV` overrides for development.

## Authentication & transport

- [x] O5LOGON (AES-128/192/256, PBKDF2 for 12c+)
- [x] 10g legacy DES verifier (OpenSSL legacy provider)
- [x] 23ai fast-auth (`0x22` bundle, fv24)
- [x] TNS redirect; large-SDU / 4-byte packet framing (#155) — the CONNECT
      advertises protocol version 319, and a negotiated version >= 315 (21c/23ai/
      26ai) switches every packet to the 4-byte ("large") length header; older
      servers negotiate down (10g→313, 11g→314, 9i→312) and keep legacy framing.
      The 319 CONNECT carries the large-SDU trailer (32-bit SDU/TDU + connect
      flags) and the accept's ub4 SDU is read from offset 24. Validated live +
      ASan across 10g/11g/21c/26ai incl. fragmentation. (Stage 1 of pipelining §32.)
- [x] End-of-response framing (§32/#155) — stage 2 of pipelining. A >= 318 accept
      carries the flags2 HAS_END_OF_RESPONSE bit; when set (23ai/26ai) we opt in
      via the DTY compile_caps[40] bit 0x20, and the server then terminates every
      response with a TTI_END_OF_RESPONSE (29) token (handled as a terminal in the
      response parser). Prerequisite for the pipeline burst. Validated live + ASan
      on an EOR-active 26ai (full integration suite); 21c/11g don't advertise it
      and are unaffected.
- [x] TLS / TCPS transport — OpenSSL client wraps the socket (SSL=1 or
      PROTOCOL=TCPS); cert verification on by default (TLSCA for a custom CA,
      TLSVERIFY=0 to disable). Validated fv4→fv24 through a terminating proxy
      (tests/odbc/tls_proxy.py); the whole TNS/TTC session rides the TLS socket.
- [x] ANO — native network encryption + data integrity (§33) — the DEADBEEF
      negotiation after the accept, then AES-CBC + an AES-keystream SHA-2 MAC
      wrapping every TNS_DATA payload (`src/tns/ano.c`). ANO-capable is advertised
      (0x0101) and gated on the accept's ACFL flags; a bare-supported server picks
      the null algorithm and stays plaintext. Validated byte-for-byte against the
      seerdb reference + a captured 26ai response (test_ano), live plaintext-
      fallback on 11g, and AES256+SHA256 end-to-end against a required Mirror.
- [ ] External / OS / Kerberos auth
- [x] Proxy authentication (`proxy_user[schema]`) — one `PROXY_CLIENT_NAME` auth
      pair names the target schema; the proxy authenticates normally and the
      server switches the session context. Validated fv4 (10g) → fv24 (23ai).
- [x] DRCP (database resident connection pooling) — CCLASS/PURITY connection
      attrs add (SERVER=POOLED) + AUTH_KPPL_CONN_CLASS/PURITY auth pairs; the
      pooled session's server-side piggyback (TTI_SVR_PIGGYBACK 23) is consumed.
      Validated genuinely pooled on 21c/23ai (V$CPOOL_CONN_INFO).
- [ ] Connection failover / TAF
- [x] 9i O3LOGON handshake — **live-authenticated to a 9i VM** (127.0.0.1:1526,
      SID=orcl). `seer_o3logon` (DES-decrypt AUTH_SESSKEY under the DES verifier,
      DES-encrypt the padded password; reuses the 10g DES machinery; pinned to the
      JDBC-thin→9.2.0.4 vector in `test_auth`) driven by `o3logon_login` in ttc.c:
      TTI_3LOGA `0x52` → session-key RPA → TTI_3LOGON `0x51` → short pre-10g OER.
      Needed three enablers: `sid` connect param (9i predates service names), a
      lower CONNECT floor (300, since 9i's max is 312), and the minimal pre-10g
      caps (no O5LOGON). No regression on 10g/11g/21c/23ai.
- [x] 9i SELECT / fetch — the **TTI_ALL7 (`0x47`) dialect** (`fv2_execute_select`
      in stmt.c, gated on fv<10g). The four-call sequence OOPEN → parse → describe
      (`0x62`) → exec/fetch* (a per-column define block; re-sent until ORA-01403)
      → close (`0x14`). Decodes NUMBER/VARCHAR/CHAR/DATE/NULL over multiple fetch
      batches (validated to 250 rows on the 9i VM); ASan-clean; no regression.
      Deferred: PL/SQL blocks, LOB (the TTI_LOBOPS GETLEN+READ pair),
      national-charset binds.
- [x] 9i DML + binds — `fv2_execute_dml` (OOPEN → a single parse that also
      executes → close; explicit commit since 9i's parse has no autocommit bit).
      DDL routes here too. Binds are shared by SELECT and DML (`fv2_emit_parse` /
      `fv2_bind_oac`): the parse gains the bind OACs + one RXD, reusing the value
      bytes the TTI_ALL8 path already stores. NUMBER + VARCHAR binds validated with
      a CREATE / INSERT×3 / UPDATE / SELECT-with-bind round-trip on the 9i VM;
      ASan-clean; no regression.
- [x] 9i PL/SQL blocks — `fv2_execute_block` (block parse opt `01 21` / `02 04 29`,
      OACs but no inline values), then the 9i bind-prompt exchange: the server
      prompts (`0x0B`), the client sends IN values in one RXD, and the reply carries
      OUT/IN-OUT values (decoded into each OUT bind's cell). IN-bind INSERT, OUT
      NUMBER (`:1 := 42*2` → 84) and IN+OUT VARCHAR (`:2 := :1 || '_x'` → `hi_x`)
      validated on the 9i VM; ASan-clean; no regression.
- [x] 9i LOB read (CLOB + BLOB) — the two-call `TTI_LOBOPS` GETLEN + READ per
      locator (`fv2_resolve_lobs`): the RXD locator is captured during the fetch,
      then resolved while the cursor is open; the READ reply's chunks are
      accumulated across packets to a zero-length terminator (9i's READ carries no
      OER status). Validated with 20-, 3000- and 6000-char CLOBs (multi-chunk) and
      a BLOB on the 9i VM; ASan-clean; no regression. (A non-UTF-8 DB charset
      would need conversion.)
- [x] 9i BFILE read — `fv2_bfile_read`: FILE_OPEN (the reply carries an updated
      open-flagged locator) → GETLEN → READ → FILE_CLOSE over `TTI_LOBOPS`.
      Validated against `BFILENAME('BFDIR','hello.bin')` on the 9i VM (20 bytes,
      exact); ASan-clean; no regression.
- [x] National-charset binds (NVARCHAR2 / NCHAR) — `seer_stmt_bind_ntext`: the
      UTF-8 text is converted to AL16UTF16 and declared csfrm 2. Works on **both**
      the modern (`emit_oac`) and 9i (`fv2_bind_oac`) paths. Validated on 9i **and**
      21c — round-trips via `TO_CHAR`/`LENGTH` and matches `WHERE n = N'...'`;
      ASan-clean; no regression. **This closes the 9i (fv2) work — auth, SQL, DML,
      binds, PL/SQL, LOB/BFILE, national binds all live-validated.**

## ODBC API surface (58 `SQL*` entry points) — COMPLETE

- [x] Handles: SQLAllocHandle, SQLFreeHandle, SQLFreeStmt, SQLCloseCursor
- [x] Connect: SQLConnect(W), SQLDriverConnect(W), SQLDisconnect
- [x] Attrs: SQLSet/GetEnvAttr, SQLSet/GetConnectAttr, SQLSet/GetStmtAttr
- [x] Prepare/exec: SQLPrepare(W), SQLExecDirect(W), SQLExecute, SQLNumParams,
      SQLBindParameter, SQLDescribeParam, SQLParamData, SQLPutData
- [x] Results: SQLNumResultCols, SQLDescribeCol(W), SQLColAttribute(W),
      SQLBindCol, SQLFetch, SQLFetchScroll, SQLGetData, SQLRowCount,
      SQLMoreResults, SQLSetPos
- [x] Txn: SQLEndTran
- [x] Diag: SQLGetDiagRec(W), SQLGetDiagField
- [x] Info: SQLGetInfo(W), SQLGetFunctions, SQLGetTypeInfo(W)
- [x] Catalog: SQLTables(W), SQLColumns(W), SQLPrimaryKeys, SQLForeignKeys,
      SQLStatistics, SQLProcedures, SQLProcedureColumns, SQLSpecialColumns
- [x] SQLCancel — abort a SQL_NEED_DATA sequence; in-band INTERRUPT break for a
      call blocked on the connection (cross-thread interrupt → ORA-01013)
- [x] SQLNativeSql — returns the native SQL (escape expansion + '?' -> :1)
- [x] SQLBrowseConnect — iterative connect (NEED_DATA browse string -> connect)
- [x] SQLGetDescField, SQLGetDescRec — read the implicit descriptors (ARD/APD/
      IRD/IPD via SQLGetStmtAttr handles; IRD = result-column metadata)
- [x] SQLSetDescField, SQLSetDescRec — write path: writing a field updates the
      same bind/param array execute/fetch consume (ARD = SQLBindCol, APD/IPD =
      SQLBindParameter halves); the IRD is read-only (HY016)
- [x] SQLBulkOperations — deliberately unsupported (no bookmarks): reported false
      by SQLGetFunctions; returns HYC00. Use SQLSetPos for positioned DML.

## Data types — fetch (column decode)

- [x] VARCHAR2 / CHAR (AL32UTF8); NVARCHAR2 / NCHAR (national): a national column
      declares charset AL16UTF16 and its value is UTF-16BE on the wire — `decode_cell`
      converts it to UTF-8 (validated 21c/23ai). 9i converts national→session
      server-side and mangles it — read via `TO_CHAR` on 9i.
- [x] NUMBER (and FLOAT)
- [x] DATE, TIMESTAMP, TIMESTAMP WITH (LOCAL) TIME ZONE
- [x] BINARY_FLOAT, BINARY_DOUBLE
- [x] RAW
- [x] LONG, LONG RAW
- [x] CLOB, BLOB, BFILE
- [x] REF CURSOR (nested, drained into the result set)
- [x] ROWID / UROWID — physical ROWID (18-char extended) + UROWID ("*"+base64)
- [x] INTERVAL YEAR TO MONTH / DAY TO SECOND — text "[+|-]Y-MM" / "[+|-]D HH:MM:SS.fffffffff"
- [x] BOOLEAN (23ai SQL boolean) — "TRUE"/"FALSE" (native type 252)
- [x] JSON (type 119, OSON binary image) — LOB-backed; decoded to JSON text (src/tns/oson.c)
- [x] VECTOR (23ai, type 127) — LOB-backed; decoded to "[e1, e2, ...]" (FLOAT32/64/INT8, dense/sparse/binary)
- [x] Object types (ADT), incl. **nested objects** — decoded to "v1, v2, ..."
      text. Layout from ALL_TYPE_ATTRS (cached per column); an embedded object
      attribute is flattened inline (recursive leaf splice via attr_type_owner).
- [x] VARRAY / nested table — decoded to "[e1, e2, ...]" (element type from
      ALL_COLL_TYPES; collection image flag 0x88: count + per-element values)
- [x] REF — the opaque object-reference locator surfaced as hex (like RAW)
- [x] Collections-of-objects fetch — a VARRAY/nested-table whose elements are
      objects: the element type's attribute layout is fetched from ALL_COLL_TYPES
      (elem_type_owner) + build_obj_layout, and each element is decoded via
      decode_object_image -> "[(a, b), ...]". Validated all four servers; ASan-clean.
- [x] Objects-with-collection-attributes fetch — a nested collection attribute
      stays a single variable-length entry in the layout (parallel obj_attr_elem
      array marks it + its element type; build_obj_layout detects it via
      ALL_COLL_TYPES), decoded inline as "[...]" by decode_object_image. Validated
      all four servers; ASan-clean; no regression to existing object binds/fetches.
- [x] OUT associative arrays — seer_stmt_bind_out_array (NUMBER/VARCHAR, capacity)
      + seer_stmt_out_array_len/_get: the array OAC (flag 0x41 + capacity) bound
      OUT with an empty placeholder; parse_iov reads the returned ub4 count + N
      (DALC + ub4 return-code) elements into per-bind SeerCells. Validated 21c/23ai;
      ASan-clean. (Object deep tail complete.)
- [x] XMLType fetch — documents (incl. large, multi-KB) decode to XML text.
      Inline (default binary-XML storage): validated 10g/21c; some 11g uses a
      legacy CLOB storage not decoded inline (cast via XMLSERIALIZE). LOB-backed
      (an explicit STORE AS CLOB column returns a LOB locator): the driver reads
      the locator + decodes it - validated all four servers (incl. 50 KB); ASan-
      clean. 23ai FREE has no default XML DB but STORE AS CLOB works. The "large
      XMLType desync" was the chunked-DALC fetch bug below (fixed), not an insert.
- [x] XMLType bind — seer_stmt_bind_xmltype: XMLType is text on the wire (the
      server parses/validates), so the UTF-8 document is bound directly (VARCHAR2,
      or a streamed LONG past the 4000 limit) and the server converts it - no
      client-side XML processing (unlike JSON's OSON). Small docs validated
      10g/11g/21c; large (>4000, LONG) works 12c+ (10g/11g reject LONG->XMLType,
      ORA-01461); 23ai FREE has no XMLType column. ASan-clean.

## Data types — bind (parameter)

- [x] VARCHAR / string, NUMBER, DATE, RAW, BINARY_DOUBLE
- [x] REF CURSOR (OUT)
- [x] IN / OUT / IN OUT direction, NULL indicators
- [x] TIMESTAMP struct binds (native 11-byte, fractional seconds preserved)
- [ ] TIMESTAMP WITH TIME ZONE binds (the C struct carries no zone; bound as TIMESTAMP)
- [x] BINARY_FLOAT bind (native 4-byte; was widened to BINARY_DOUBLE)
- [x] BOOLEAN bind (23ai native type 252; NUMBER 0/1 fallback pre-23ai)
- [x] INTERVAL binds — SQL_C_INTERVAL_YEAR_TO_MONTH / DAY_TO_SECOND ->
      seer_stmt_bind_interval_ym/_ds (5/11-byte: ub4 biased by 2^31 + ub1 biased
      by 60). Positive + negative round-trip on all four servers (not 12c-gated).
- [x] Native JSON bind (21c+) — seer_stmt_bind_json: JSON text -> OSON (json.c) ->
      the native-LOB bind value (VECTOR/JSON descriptor + ub2 len + 22 zeros +
      bytes-with-length image) + the fixed JSON bind OAC (type 119). Binds the
      binary JSON directly (no server text cast). Round-trip validated 21c/23ai;
      ASan-clean. (Older servers: bind JSON as a string for the server to cast.)
- [x] Native VECTOR bind (23ai) — all element types: dense FLOAT32 / FLOAT64 /
      INT8 (seer_stmt_bind_vector_f32/_f64/_i8; order-preserving 4/8-byte floats
      via seer_encode_bfloat/bdouble, 1 byte for INT8), BINARY bit vectors
      (seer_stmt_bind_vector_binary; version 1, count=nbytes*8), and sparse
      FLOAT32 / FLOAT64 / INT8 (seer_stmt_bind_vector_sparse_f32/_f64/_i8;
      version 2, ub2 nnz + ub4 indices + 4/8/1-byte values). Shared header builder
      (vector_img_start) + native-LOB path (VECTOR OAC, type 127). All round-trip
      on 23ai; ASan-clean.
- [x] Large LOB binds (CLOB/BLOB of any size): chunked bind-value encoding
      (version-split at fv12.2) + streamed LONG / LONG RAW type past the
      VARCHAR/RAW limit + TNS send-side fragmentation past the SDU. Validated to
      50 KB on 10g/11g/21c/23ai. (Was the long-standing "in progress" item.)
- [x] SQL OBJECT + collection + associative-array bind — flat & nested objects
      (seer_stmt_bind_object, nested attrs flattened inline via build_obj_layout),
      VARRAY/nested-table (seer_stmt_bind_collection), and PL/SQL index-by tables
      (seer_stmt_bind_int64_array / _text_array — one OAC with the ARRAY flag 0x40
      + capacity, RXD = count + elements). Core API: image encoder (object 0x84 /
      collection 0x88) + shared TOID/image framing + object OAC + type-OID lookup.
      Values from text: NUMBER (exact base-100 decimal), DATE, TIMESTAMP (nanos),
      char. 12c+. Validated round-trip on 21c/23ai (assoc array via a PL/SQL proc).

## SQL / statement features

- [x] Prepared statements + `?` parameter markers (SQL preprocessor)
- [x] Array (bulk) DML binding (`SQL_ATTR_PARAMSET_SIZE`)
- [x] Array-DML batch errors (per-row status + diag records)
- [x] Array-DML per-iteration row counts (12c+, `SQL_ATTR_SEER_DML_ROW_COUNTS`)
- [x] Implicit result sets (`DBMS_SQL.RETURN_RESULT`, 12c+, via SQLMoreResults)
- [x] Column annotations (23ai, `SQL_DESC_SEER_ANNOTATIONS`)
- [x] Transactions: commit / rollback / autocommit
- [x] Positioned UPDATE / DELETE via SQLSetPos (ROWID-based)
- [x] FOR UPDATE locking (`SQL_CONCUR_LOCK`)
- [x] Data-at-execution (SQLPutData streaming)
- [x] Client-side scrollable fetch (buffered result set)
- [x] LOB read (CLOB → UTF-8, BLOB/BFILE → bytes)
- [x] DML `RETURNING ... INTO` (server-filled OUT binds via SQL_PARAM_OUTPUT)
- [x] Statement caching — a closed statement's parsed server cursor is kept open
      (per-connection LRU cache of 24, keyed by exact SQL); re-preparing the same
      SQL re-executes it with NO re-parse (send the cursor id, drop the PARSE opt
      bit, omit the SQL). The SELECT describe columns move with the cursor (so the
      describe-less reuse response still decodes rows). Transparent (no API change),
      validated all four servers incl. binds reused at new values; ASan-clean; zero
      regression across the whole suite. Correctness guards: DDL is not cached and
      flushes the cache (same-session invalidation), and a reuse that errors falls
      back to one full re-parse (cross-session ORA-00942). Residual limit: a
      cross-session DDL recreating an object with the same name can yield stale
      results silently (rare; oracledb is similar).
- [ ] Server-side scrollable cursors
- [ ] Continuous Query Notification (CQN)

## Sessions / infrastructure

- [x] Advanced Queuing (AQ):
        * [x] RAW enqueue - seer_aq_enq_raw (TNS_FUNC_AQ_ENQ 121); minimal msg
          props, ON_COMMIT, persistent; returns the 16-byte msgid.
        * [x] RAW dequeue - seer_aq_deq_raw (TNS_FUNC_AQ_DEQ 122); FIRST_MSG one-shot,
          ON_COMMIT + a wait; parses msg props + payload (image[4:len]) + msgid;
          empty queue / timeout -> SEER_ENODATA. Full enqueue->dequeue round-trip
          validated on 21c/23ai (payload + drain + empty); 12c+; ASan-clean. Core
          API (not ODBC), like XA.
        * [x] enq/deq options - seer_aq_enq_raw_opt (priority/delay/expiration/
          correlation) + seer_aq_deq_raw_opt (BROWSE peek, correlation filter,
          consumer name, wait). Validated on 21c/23ai: out-of-order correlation
          dequeue, BROWSE-then-REMOVE. ASan-clean.
        * [x] object payloads - seer_aq_enq_object / seer_aq_deq_object; the queue
          TOID is the type OID, the body is the object bind value (reuses the
          object-bind image encoder), dequeue decodes via decode_object_image.
          Round-trip validated on 21c/23ai ((42,"hello") -> "42, hello"); ASan-clean.
        * [x] JSON payloads - seer_aq_enq_json / seer_aq_deq_json; a new JSON-text
          -> OSON encoder (src/tns/json.c) wrapped in the AQ JSON descriptor,
          dequeue decodes the OSON via seer_decode_oson. Round-trip validated on
          21c/23ai (needs an ASSM tablespace for the JSON queue table); ASan-clean.
        * [x] array (bulk) enqueue/dequeue - seer_aq_enq_raw_array (ROW_HEADER +
          ROW_DATA* + STATUS, returns count*16 msgids) + seer_aq_deq_raw_array
          (TNS_FUNC_ARRAY_AQ 145 op DEQ; N placeholder blocks -> up to N messages,
          out_count=actual, empty->0). Bulk round-trip validated 21c/23ai; ASan-clean.
        * [x] multi-consumer - a multiple_consumers queue with named subscribers;
          enqueue once, each consumer dequeues its own copy via the `consumer`
          dequeue option (no new wire code - validates the consumer-name path
          against a real multi-consumer queue). Validated 21c/23ai; ASan-clean.
- [x] Two-phase commit / XA / distributed transactions — core `seer_tpc_*` API
      (begin/end/prepare/commit/rollback) over the TTC TPC functions (SWITCH 103,
      CHANGE_STATE 104), with the server transaction context held + replayed.
      12c+ (ENOTIMPL below). Validated 21c/23ai: full 2PC commit is durable
      cross-connection, rollback discards. Exposed via the core API (Unix ODBC
      has no standard XA binding), not the SQL* surface.
- [x] Sessionless transactions (§31, 23ai+) — a transaction that lives in the DB,
      not the session: `seer_txn_begin_sessionless` / `_resume_sessionless` /
      `_suspend_sessionless` (core API). Reuses the TPC SWITCH (103) machinery
      with the magic format-id 0x4E5C3E in the xid slot and the SESSIONLESS flag
      (0x10) OR'd into START (NEW/RESUME) / DETACH — no new function code; commit
      and rollback are ordinary. While a sessionless txn is active the server
      rides a SYNC piggyback (opcode 5) on the next call's response, consumed
      byte-for-byte in `skip_server_piggyback`. ENOTIMPL below fv23.1 (so 21c
      too). The switch framing is pinned byte-for-byte to seerdb (test_sessionless);
      the full suspend-on-A / resume+commit-on-B lifecycle (incl. cross-session
      isolation + durability, and the SYNC piggyback) runs live on 23ai in CI.
      Core API, not the SQL* surface (like XA).
- [x] Request boundaries (§35) — bracket a logical request so the server can reset
      session state between requests (a DRCP / pool optimisation). Core `seer_request_begin`
      / `seer_request_end` emit a one-shot func-176 `SESSION_STATE` piggyback (the
      state OR'd with the EXPLICIT_BOUNDARY bit): BEGIN rides in front of the next
      call with no extra round-trip; END rides a rollback round-trip; a BEGIN with
      no op in between is cancelled and nothing is sent. Gated on the server
      advertising both compile_caps[40] bit 0x40 AND runtime_caps[6] bit 0x10
      (21c+); returns ENOTIMPL on 10g/11g. Validated live on 21c; the fv24 wire
      (an added ub8 token) is pinned byte-for-byte by test_reqbound against the
      seerdb reference and the §35.3 live-26ai bytes, and exercised on a fresh 23ai
      in CI. **Decision:** exposed via the core API, not the SQL* surface — ODBC has
      no request-boundary verb, and connection pooling lives in the driver manager,
      not the driver; mirrors the XA rationale above. (oracledb ties this to its own
      pool acquire/release; a bare driver leaves the begin/end to the caller.)
- [x] Sharding — **not on the thin wire** (§37); accept-and-reject stub.
      `shardingkey`/`supershardingkey` are an OCI-client capability (shard routing
      happens below the TTC/TNS protocol), so a pure-protocol client has no message
      to carry them. The two `SeerConnParams` fields are accepted for API parity;
      `seer_connect` rejects a non-empty key up front with SEER_ENOTIMPL (no wire
      traffic) rather than silently ignoring it, matching the reference thin drivers.
- [x] Continuous Query Notification — **not on the thin wire** (§38); accept-and-
      reject stub. CQN needs the server to open a callback connection back to a
      client-run listener, which a thin request/response client cannot host.
      `seer_subscribe` / `seer_unsubscribe` exist for API parity and return
      SEER_ENOTIMPL with an explanatory `seer_last_error`.
- [ ] Application Continuity

## Docs & testing

- [x] Offline unit tests (codecs, O5LOGON vectors, SQL preprocessor, conversions)
- [x] Driver-level integration suite + version matrix runner (10g/11g/21c/23ai)
- [x] Large-value fetch fix: a column value >= 254 bytes arrives 0xFE-chunked
      with sb4 chunk lengths on 12c+ (ub1 on 11g); seer_dec_dalc read ub1
      unconditionally, so *every* large VARCHAR/RAW/object/XMLType fetch on 21c/
      23ai returned SEER_EPROTO. Fixed via SeerReader.sb4_chunks (set from the
      field version in the response parsers). Regression test in the suite.
- [x] ASan + UBSan: configure a sanitized build (`meson setup build-asan
      -Db_sanitize=address,undefined -Db_lundef=false`; needs libasan + libubsan).
      Offline tests AND the live protocol paths run clean — the latter via core-API
      live tests (tpc/objbind) plus a broad fetch/decode/bind exerciser
      (`/tmp/exercise.c`) across all four servers. (Sanitizers were never actually
      enabled before; now wired and green.)
- [x] Thread-safety: distinct connections are independent (no shared mutable
      state) → safe to use concurrently; a single connection must not be used
      from two threads at once (the app serialises), except `seer_cancel` which is
      the one deliberate cross-thread call (`volatile in_call`). The OpenSSL
      legacy-provider lazy init is now race-free (`pthread_once`, was a
      check-then-set bug). Log level is a benign int.
- [x] Fuzz harnesses for the response decoders (tests/fuzz/, libFuzzer via
      tests/fuzz/build-fuzz.sh; clang + ASan + UBSan):
        * fuzz_decoders - OSON, the number/date/interval/float codecs, the marshal
          DALC reader. FOUND + FIXED a heap-buffer-overflow in seer_decode_oson
          (ub4-tree header read 6 bytes behind a 4-byte check) in ~9k execs;
          clean over 4.5M execs after.
        * fuzz_images - the ADT image decoders (object/collection/vector), reached
          via seer_fuzz_image_decoders (built under -DSEER_FUZZ). Clean over 15M+
          execs (no bug found - already well-bounded).
        * fuzz_decoders also covers the JSON->OSON encoder (json.c). FOUND + FIXED
          UBSan signed-overflow (negating INT32_MIN) in the interval decoders
          (types.c) - widened to long, matching the nanos path. Offline unit test
          test_json (round-trip encode->decode + malformed-input rejection).
- [x] Refresh `ODBC_CONFORMANCE.md` / `ARCHITECTURE.md` / `README.md` stale notes
      (four-version matrix, fv24 complete, this session's feature surface)

---

### Suggested next pulls (each an isolated, separately-committable feature)

The object/collection arc (incl. the deep tail: collections-of-objects,
objects-with-collection-attributes, OUT associative arrays), Advanced Queuing,
XA/2PC, TLS/TCPS, proxy auth + DRCP, native JSON/VECTOR binds, XMLType fetch/bind
(incl. LOB-backed), statement caching, **Oracle 9i (fv2 / O3LOGON / TTI_ALL7)**,
**ANO native encryption (§33)**, **request boundaries (§35)** and **sessionless
transactions (§31)** have all landed — matrix-validated. The driver spans field
versions 2–24 (9i → 23ai). Reference-backed items still open, from the latest
seerdb/PROTOCOL.md sync:

1. **Request pipelining (§32) — the single-round-trip burst.** The API + result
   model + serial execution path have landed (core `seer_pipeline_*`: create /
   add_execute / add_fetchone|many|all / add_commit / run / op_status / op_stmt,
   with continue-on-error; validated live on 11g/21c/26ai). Still to do: the wire
   burst (#158) that sends the exec-family ops as one token-tagged round trip on
   an EOR-negotiated 23ai+ connection (func 199/200 piggybacks, BEGIN_PIPELINE /
   END_OF_REQUEST data flags, TOKEN-33 correlation, a custom pipelined reader) —
   a transparent optimisation over the serial path, identical results.
2. **Token auth — OAuth2 / OCI IAM (§20.6)** and **end-user security context
   (§34)** — cloud/tcps-gated; validation needs a real IAM token / 26ai TLS path.

Not on the thin wire (documented above, nothing to emit): **sharding** (§37) and
**CQN** (§38) — both OCI-client capabilities a pure-protocol client cannot carry.

Deep-RE / environment-blocked (no reference):

- **12c / 18c / 19c matrix coverage** — the fv7–14 wire forms should already work
  via down-negotiation; unproven only for lack of a container. (Near-zero code.)
- **Server-side scrollable cursors** — fetch is client-buffered today (already a
  correct `SQLFetchScroll`); a true server-side scroll cursor would help very large
  result sets. Attempted 2026-07 and reverted at a wire-framing blocker (the
  scrollable response desyncs the OER); needs a byte-level capture. Ref: §5.2.1.
- **External / OS / Kerberos auth**, **connection failover / TAF**, RAC,
  Application Continuity — larger, environment-dependent (need a KDC / RAC cluster).

Deliberately out of scope: TIMESTAMP WITH TIME ZONE binds (the ODBC struct carries
no zone — would require guessing), AQ recipient-list enqueue (pyoracle only stubs
it), SQLBulkOperations (no bookmarks).

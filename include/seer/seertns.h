/* SeerODBC - protocol core public API.
 *
 * This is the entire surface the ODBC shim (and seersql, and any future
 * binding) is allowed to use. It deals only in native C types: there is
 * deliberately nothing ODBC-shaped here. The core does not know ODBC exists.
 *
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SEER_SEERTNS_H
#define SEER_SEERTNS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SEERTNS_VERSION_MAJOR 0
#define SEERTNS_VERSION_MINOR 6
#define SEERTNS_VERSION_PATCH 0

/* Core result codes. The ODBC shim maps these onto SQLRETURN + SQLSTATE;
 * the core never speaks SQLRETURN itself. */
typedef enum {
  SEER_OK = 0,
  SEER_ENOTIMPL = -1, /* not implemented yet (scaffold) */
  SEER_EIO = -2,      /* socket / transport error */
  SEER_EPROTO = -3,   /* malformed or unexpected wire data */
  SEER_EAUTH = -4,    /* authentication rejected */
  SEER_ENOMEM = -5,   /* allocation failure */
  SEER_EPARAM = -6,   /* bad argument from the caller */
  SEER_ENODATA = -7,  /* no more rows (end of fetch) */
  SEER_EDB = -8,      /* server returned an ORA-NNNNN error */
  SEER_ETIMEOUT = -9, /* the connect / login time limit expired (#403) */
} SeerStatus;

/* Opaque handles - the core owns their layout. */
typedef struct SeerConn SeerConn;
typedef struct SeerStmt SeerStmt;

typedef struct {
  /* The listener's host, or a comma-separated list of addresses for
   * connect-time failover: each `host`, `host:port` or `[ipv6]:port`, a port
   * of its own overriding `port`. They are tried in order; a failure before
   * the listener accepts (no TCP connect, no TLS, a refusal such as
   * ORA-12514) moves on to the next, one after it (a wrong password, a login
   * error) is returned. With all failing, the last address's error is. */
  const char *host;
  uint16_t port;            /* default 1521 */
  const char *service_name; /* service name (SERVICE_NAME in the descriptor) */
  const char *sid;          /* SID (older servers, e.g. 9i); used if set instead
                             * of service_name -> (CONNECT_DATA=(SID=...)) */
  const char *username;
  const char *password;
  int use_tls;        /* non-zero => TCPS (TLS transport) */
  const char *tls_ca; /* CA bundle (PEM) for verification; NULL => system */
  int tls_verify;     /* verify the server cert (default on); 0 => accept any */
  /* DRCP (database resident connection pooling): a connection class and/or
   * session purity request a pooled server. Either being set adds
   * (SERVER=POOLED) to the connect descriptor and the AUTH_KPPL_* auth pairs.
   * purity: 0 default, 1 NEW (fresh session), 2 SELF (reuse). */
  const char *cclass;
  int purity;
  /* Sharding keys (§37). A sharding key routes a connection to a specific shard
   * of a sharded database — an OCI-client capability that the shard resolution
   * performs below the thin TTC/TNS protocol, so a pure-protocol client has no
   * message to carry it. Accepted for API parity: seer_connect rejects a
   * non-empty key with SEER_ENOTIMPL rather than silently ignoring it. */
  const char *shardingkey;
  const char *supershardingkey;
  /* Fetch CLOB / BLOB columns inline (12.1+): a query's LOB content comes in
   * the rows, not through one LOB read round trip per cell - far faster for
   * many LOBs. The cost: in that form an empty LOB (EMPTY_CLOB() /
   * EMPTY_BLOB()) is indistinguishable from NULL and reads as NULL, as a
   * zero-length VARCHAR2 would. Off by default. Applies to results whose other
   * columns are plain scalars; NCLOB, BFILE, JSON, VECTOR and object columns
   * are always read through their locators. */
  int lob_inline;
  /* Dead-connection detection, in minutes (EXPIRE_TIME). Above 0, TCP
   * keepalive is turned on with its first probe after that many minutes of
   * quiet, so a connection idle behind a firewall stays open and one whose
   * peer is gone fails instead of hanging; the descriptor carries
   * (EXPIRE_TIME=<minutes>) too, as python-oracledb writes it. 0: off. */
  int expire_time;
  /* Two-phase commit on 9i: non-zero logs the session on with the names 9.2
   * requires before seer_tpc_begin (AUTH_INTERNALNAME / AUTH_EXTERNALNAME).
   * Such a session raises a refused commit's ORA-02091 again on every statement
   * until a rollback, so it is opt-in (#183). Ignored on other releases, which
   * take two-phase commit on any session. */
  int xa;
  /* How long each address may take to connect and log in, in milliseconds:
   * the TCP connect, then each read and write of the login (#216). 0 keeps
   * the default, 30 s; below 0, no limit. */
  int connect_timeout_ms;
} SeerConnParams;

#define SEER_PURITY_NEW 1
#define SEER_PURITY_SELF 2

/* Connection lifecycle. */
SeerStatus seer_connect(const SeerConnParams *params, SeerConn **out);
/* seer_connect, and when it fails, why: the server's own error, such as
 * "ORA-01017: invalid username/password; logon denied" or a listener's
 * refusal, into `err` (NUL-terminated, cut to errlen). `err` is left empty
 * when the failure has no server error behind it (a network error, say). */
SeerStatus seer_connect_diag(const SeerConnParams *params, SeerConn **out, char *err,
                             size_t errlen);
void seer_disconnect(SeerConn *conn);

/* Transaction control. autocommit (default on) commits each statement; with it
 * off, changes persist only after seer_commit. */
void seer_set_autocommit(SeerConn *conn, int on);
SeerStatus seer_commit(SeerConn *conn);
SeerStatus seer_rollback(SeerConn *conn);
/* Whether a transaction is open on the session, as the server's last reply
 * said: 1 open, 0 none, -1 unknown (8i and 9i replies don't say). */
int seer_txn_open(const SeerConn *conn);
/* The same, asking the database where the replies don't say (9i: one query
 * of DBMS_TRANSACTION.LOCAL_TRANSACTION_ID, #344): 1 open, 0 none, -1 when
 * even that can't tell. */
int seer_txn_check(SeerConn *conn);
/* Whether the database charset holds every character: AL32UTF8 or UTF8, or
 * not yet known. Otherwise (WE8ISO8859P1, say) text for an NVARCHAR2 has to go
 * in the national charset to survive (#367). */
int seer_db_charset_unicode(const SeerConn *conn);
/* The negotiated Session Data Unit in bytes; 0 if not connected (#373). */
unsigned seer_conn_sdu(const SeerConn *conn);

/* Request boundaries (§35, 21c+). Bracket a logical request on a (typically
 * pooled) connection so the server can reset session state between requests.
 * `begin` arms a REQUEST_BEGIN marker that rides in front of the next call with
 * no extra round-trip; `end` sends REQUEST_END piggybacked on a rollback (or, if
 * no call ran after `begin`, cancels it and sends nothing). Both return
 * SEER_ENOTIMPL when the server does not advertise the capability (e.g. 10g/11g),
 * which callers may treat as "feature inactive" and ignore. */
SeerStatus seer_request_begin(SeerConn *conn);
SeerStatus seer_request_end(SeerConn *conn);

/* Two-phase commit / XA (distributed transactions). A global transaction
 * is identified by an Xid (format id + global transaction id + branch
 * qualifier). The branch lifecycle is: begin -> [DML] -> end -> prepare ->
 * commit (or rollback at any point). The opaque transaction context the server
 * returns from begin is held on the connection and replayed automatically. */
typedef struct {
  int32_t format_id;
  const uint8_t *gtrid; /* global transaction id   */
  int gtrid_len;
  const uint8_t *bqual; /* branch qualifier        */
  int bqual_len;
} SeerXid;

#define SEER_TPC_BEGIN_NEW 0x00000001    /* start a new branch          */
#define SEER_TPC_BEGIN_JOIN 0x00000002   /* join an existing branch     */
#define SEER_TPC_BEGIN_RESUME 0x00000004 /* resume a suspended branch   */
#define SEER_TPC_END_NORMAL 0x00000000
#define SEER_TPC_END_SUSPEND 0x00100000 /* suspend (resume-able) end   */

/* Begin (or join/resume) a global transaction branch. `timeout` is the seconds
 * the server holds an idle branch (0 = server default). On 9i the connection
 * must be opened with SeerConnParams.xa set (SEER_ENOTIMPL otherwise). On 8i the
 * calls run as PL/SQL on SYS.JAVA_XA, which the account must be able to
 * execute. */
SeerStatus seer_tpc_begin(SeerConn *conn, const SeerXid *xid, uint32_t flags, uint32_t timeout);
/* End the local work on the branch (detach); flags SEER_TPC_END_*. */
SeerStatus seer_tpc_end(SeerConn *conn, const SeerXid *xid, uint32_t flags);
/* Prepare the branch (phase one). *commit_needed (may be NULL) is set to 1 when
 * a commit is required, 0 when the branch was read-only (nothing to commit). */
SeerStatus seer_tpc_prepare(SeerConn *conn, const SeerXid *xid, int *commit_needed);
/* Commit the branch (phase two). `one_phase` commits directly without a prior
 * prepare (valid only when this is the sole branch). */
SeerStatus seer_tpc_commit(SeerConn *conn, const SeerXid *xid, int one_phase);
/* Roll the branch back. */
SeerStatus seer_tpc_rollback(SeerConn *conn, const SeerXid *xid);

/* Sessionless transactions (§31, 23ai+). A transaction that lives in the database,
 * not the session: begin it on one connection, suspend it, then resume + commit it
 * on any connection. `txn_id` (1..64 bytes) names the transaction and is required
 * — the same id is passed to resume elsewhere. `timeout` is the seconds the server
 * keeps a suspended transaction resumable (0 = server default). Use autocommit off
 * so the DML between begin/resume and suspend/commit joins the transaction; end it
 * with the ordinary seer_commit / seer_rollback. All three return SEER_ENOTIMPL on
 * a pre-23ai server. Only one sessionless transaction may be active per connection. */
SeerStatus seer_txn_begin_sessionless(SeerConn *conn, const uint8_t *txn_id, size_t txn_id_len,
                                      uint32_t timeout);
SeerStatus seer_txn_resume_sessionless(SeerConn *conn, const uint8_t *txn_id, size_t txn_id_len,
                                       uint32_t timeout);
SeerStatus seer_txn_suspend_sessionless(SeerConn *conn);

/* Continuous Query Notification (§38). CQN registers a server-initiated
 * subscription: the database opens a callback connection back to a listener the
 * client runs and pushes change/query notifications to it. Hosting that callback
 * channel is an OCI-client capability outside the thin request/response protocol,
 * so a pure-protocol client cannot offer it. These exist for API parity and
 * always return SEER_ENOTIMPL (with an explanatory seer_last_error). */
SeerStatus seer_subscribe(SeerConn *conn);
SeerStatus seer_unsubscribe(SeerConn *conn);

/* Advanced Queuing: enqueue a RAW message to `queue_name` (current schema unless
 * "SCHEMA.QUEUE"). The queue's payload type must be RAW. On success the 16-byte
 * message id is written to `msgid` (if non-NULL). Enqueue visibility is ON_COMMIT,
 * so commit to make the message available. RAW enqueue / dequeue and their
 * options work on every release: 10g and later in the AQ protocol, 9i and 8i as
 * PL/SQL on DBMS_AQ (the account needs EXECUTE on it), where a payload is at
 * most 32512 bytes. Object payloads work from 8i on (8i and 9i through the
 * DBMS_AQ blocks, #172); JSON payloads need a 21c+ JSON queue. */
/* Enqueue options (all optional; a NULL options pointer means the defaults that
 * seer_aq_enq_raw uses). */
typedef struct {
  unsigned priority;       /* message priority (lower = dequeued first); default 0 */
  unsigned delay;          /* seconds until the message becomes available; default 0 */
  int expiration;          /* seconds it stays available after that; -1 = forever  */
  const char *correlation; /* correlation identifier, or NULL                      */
} SeerAqEnqOptions;

/* Dequeue options (a NULL options pointer means REMOVE, no wait, no filter). */
typedef struct {
  int browse;              /* non-zero = BROWSE (peek, leave in queue); else REMOVE */
  unsigned wait_seconds;   /* seconds to wait for a message; 0 = do not wait        */
  const char *correlation; /* dequeue only messages matching this correlation, or NULL */
  const char *consumer;    /* consumer name for a multi-consumer queue, or NULL     */
} SeerAqDeqOptions;

SeerStatus seer_aq_enq_raw(SeerConn *conn, const char *queue_name, const uint8_t *payload,
                           size_t payload_len, uint8_t msgid[16]);

/* As seer_aq_enq_raw, with message properties from `opt` (NULL = defaults). */
SeerStatus seer_aq_enq_raw_opt(SeerConn *conn, const char *queue_name, const uint8_t *payload,
                               size_t payload_len, const SeerAqEnqOptions *opt, uint8_t msgid[16]);

/* Enqueue a SQL object value to an object-payload queue. `attr_values` are the
 * flattened leaf attributes as text (one per leaf, depth-first; same convention
 * as seer_stmt_bind_object). 12c+. */
SeerStatus seer_aq_enq_object(SeerConn *conn, const char *queue_name, const char *type_schema,
                              const char *type_name, const char *const *attr_values, int n_attrs,
                              uint8_t msgid[16]);

/* Enqueue a JSON document (as JSON text) to a JSON-payload queue. The text is
 * parsed and encoded to OSON (native binary JSON). Needs native JSON queues
 * (server fv >= 20.1; SEER_ENOTIMPL otherwise). */
SeerStatus seer_aq_enq_json(SeerConn *conn, const char *queue_name, const char *json_text,
                            uint8_t msgid[16]);

/* Bulk-enqueue `count` RAW messages to `queue_name` in one round-trip.
 * payloads[i]/lens[i] give each message; `msgids`, if non-NULL, must hold
 * count*16 bytes and receives the assigned message ids. On 10g and 11g, which
 * have no known form for the array call, the messages go one at a time (#187). */
SeerStatus seer_aq_enq_raw_array(SeerConn *conn, const char *queue_name, int count,
                                 const uint8_t *const *payloads, const size_t *lens,
                                 uint8_t *msgids);

/* Bulk-dequeue up to `max_count` RAW messages (REMOVE, the given wait) in one
 * round-trip. `payloads` and `lens` are caller-allocated arrays of max_count;
 * each dequeued message's payload is malloc'd into payloads[i] (caller frees)
 * with its length in lens[i]. *out_count receives the number actually dequeued
 * (0 when the queue is empty). On 10g and 11g it dequeues one at a time: the
 * first waits `wait_seconds`, the rest take only what is already queued (#187). */
SeerStatus seer_aq_deq_raw_array(SeerConn *conn, const char *queue_name, int max_count,
                                 uint32_t wait_seconds, uint8_t **payloads, size_t *lens,
                                 int *out_count);

/* Advanced Queuing: dequeue a RAW message from `queue_name` (REMOVE mode,
 * ON_COMMIT visibility). Waits up to `wait_seconds` for a message (0 = do not
 * wait). On SEER_OK the payload is malloc'd into *payload (caller frees) with its
 * length in *payload_len, and the 16-byte message id into `msgid` (if non-NULL).
 * SEER_ENODATA if no message was available within the wait. Commit to finalise
 * the removal. 12c+ (SEER_ENOTIMPL on older). */
SeerStatus seer_aq_deq_raw(SeerConn *conn, const char *queue_name, uint32_t wait_seconds,
                           uint8_t **payload, size_t *payload_len, uint8_t msgid[16]);

/* As seer_aq_deq_raw, with BROWSE mode / correlation filter / consumer name and
 * wait taken from `opt` (NULL = REMOVE, no wait, no filter). */
SeerStatus seer_aq_deq_raw_opt(SeerConn *conn, const char *queue_name, const SeerAqDeqOptions *opt,
                               uint8_t **payload, size_t *payload_len, uint8_t msgid[16]);

/* Dequeue an object-payload message (REMOVE, the given wait). The decoded object
 * is rendered to text ("v1, v2, ...", as the object fetch path) into *out_text
 * (caller frees). SEER_ENODATA if no message was available. 12c+. */
SeerStatus seer_aq_deq_object(SeerConn *conn, const char *queue_name, const char *type_schema,
                              const char *type_name, uint32_t wait_seconds, char **out_text,
                              uint8_t msgid[16]);

/* Dequeue a JSON-payload message (REMOVE, the given wait). The OSON payload is
 * decoded to JSON text into *out_text (caller frees). SEER_ENODATA if none was
 * available. Needs native JSON queues (fv >= 20.1). */
SeerStatus seer_aq_deq_json(SeerConn *conn, const char *queue_name, uint32_t wait_seconds,
                            char **out_text, uint8_t msgid[16]);

/* Interrupt a call currently blocked waiting for the server on `conn` (e.g. a
 * long-running statement on another thread). Best-effort: a no-op when no call
 * is in flight. The blocked call returns the server's ORA-01013 (cancelled). */
void seer_cancel(SeerConn *conn);

/* Limit a query's result to its first `max_rows` rows (0, the default: no
 * limit), for the executes that follow: rows past it are neither kept nor
 * fetched from the server (SQL_ATTR_MAX_ROWS, #221). */
SeerStatus seer_stmt_set_max_rows(SeerStmt *stmt, size_t max_rows);

/* Bound each round trip to the server to `ms` milliseconds (0, the default:
 * no bound), as python-oracledb's call_timeout. A reply that hasn't started
 * within it gets the interrupt seer_cancel sends: the server stops the call,
 * which fails with its ORA-01013, and the connection stays usable. A server
 * that doesn't answer the interrupt either (seen in lock waits and PL/SQL
 * loops) fails the call as SEER_EIO and the connection is closed
 * (seer_conn_lost). Setting it clears seer_call_timed_out. */
void seer_set_call_timeout(SeerConn *conn, int ms);

/* Whether a call since the last seer_set_call_timeout was stopped by the
 * timeout (its ORA-01013 is then the timeout's, not a seer_cancel's). */
int seer_call_timed_out(const SeerConn *conn);

/* Whether the connection to the server is gone: closed by a call timeout the
 * server never answered (#209). Every later call fails with SEER_EIO. */
int seer_conn_lost(const SeerConn *conn);

/* Statement lifecycle. A literal SELECT (no bind variables) is supported:
 * prepare the text, execute it, then fetch rows one at a time. */
SeerStatus seer_stmt_prepare(SeerConn *conn, const char *sql, SeerStmt **out);

/* Bind an input parameter by 1-based position, before execute. A NUMBER bind
 * carries an integer; a text bind carries UTF-8 (len < 0 => strlen); a null
 * bind carries SQL NULL. Re-binding the same position replaces it.
 *
 * Position N is the N-th distinct placeholder in the statement, in order of
 * appearance; a placeholder's label means nothing. In
 * "SELECT :2 || :1 FROM dual" position 1 is :2 and position 2 is :1, and in
 * "WHERE city = :b AND street = :a" position 1 is :b. A placeholder used again
 * (":x || :x") is the same position. That is how the server reads the binds,
 * and how OCI, JDBC and python-oracledb bind by position; it holds on every
 * release, for SQL and PL/SQL alike. ODBC's ? markers are numbered in order,
 * so they bind as written. */
SeerStatus seer_stmt_bind_int64(SeerStmt *stmt, int param, int64_t value);
/* Bind an exact NUMBER from a plain decimal string ("[-]digits[.digits]", no
 * exponent). Unlike text, it does not depend on the session's
 * NLS_NUMERIC_CHARACTERS. SEER_EPARAM if the string is not a decimal, or is
 * outside NUMBER's range. */
SeerStatus seer_stmt_bind_number_text(SeerStmt *stmt, int param, const char *dec);
SeerStatus seer_stmt_bind_text(SeerStmt *stmt, int param, const char *str, int len);
SeerStatus seer_stmt_bind_raw(SeerStmt *stmt, int param, const void *data, int len);

/* Bind national-charset text (NVARCHAR2 / NCHAR): `str` (UTF-8) is converted to
 * AL16UTF16 and declared with csfrm 2, so the server stores it in the database's
 * national character set. */
SeerStatus seer_stmt_bind_ntext(SeerStmt *stmt, int param, const char *str, int len);

/* Bind text (UTF-8) / bytes for a CLOB / BLOB target, such as a PL/SQL CLOB /
 * BLOB parameter. 9i and later take a text / RAW bind there as it is (the
 * same as seer_stmt_bind_text / _raw); Oracle 8i converts no text or RAW to a
 * LOB parameter, so there the value goes as a temporary LOB. */
SeerStatus seer_stmt_bind_clob(SeerStmt *stmt, int param, const char *str, int len);
SeerStatus seer_stmt_bind_blob(SeerStmt *stmt, int param, const void *data, int len);

/* Bind an XML document to an XMLType target (e.g. INSERT ... VALUES (:1) into an
 * XMLType column). The UTF-8 text is bound and the server parses it to XMLType;
 * handles documents of any size (VARCHAR2 or streamed LONG). */
SeerStatus seer_stmt_bind_xmltype(SeerStmt *stmt, int param, const char *xml_text);
SeerStatus seer_stmt_bind_date(SeerStmt *stmt, int param, int year, int month, int day, int hour,
                               int minute, int second);
/* Bind a TIMESTAMP value (native 11-byte form), preserving `nanos` fractional
 * seconds - unlike bind_date, which is second precision. */
SeerStatus seer_stmt_bind_timestamp(SeerStmt *stmt, int param, int year, int month, int day,
                                    int hour, int minute, int second, uint32_t nanos);
SeerStatus seer_stmt_bind_double(SeerStmt *stmt, int param, double value);
/* Bind INTERVAL YEAR TO MONTH / DAY TO SECOND. A negative interval is expressed
 * by negative component values (the components share one sign). */
SeerStatus seer_stmt_bind_interval_ym(SeerStmt *stmt, int param, int32_t years, int32_t months);
SeerStatus seer_stmt_bind_interval_ds(SeerStmt *stmt, int param, int32_t days, int32_t hours,
                                      int32_t mins, int32_t secs, int32_t nanos);
/* Bind a native BINARY_FLOAT (4-byte). */
SeerStatus seer_stmt_bind_float(SeerStmt *stmt, int param, float value);
/* Bind a boolean: native 23ai BOOLEAN, or a NUMBER 0/1 on older servers. */
SeerStatus seer_stmt_bind_bool(SeerStmt *stmt, int param, int value);
SeerStatus seer_stmt_bind_null(SeerStmt *stmt, int param);
/* Bind a NULL that still declares a type (an Oracle type number: NUMBER,
 * DATE, TIMESTAMP, BINARY_DOUBLE/FLOAT or RAW; anything else binds as the
 * VARCHAR NULL of seer_stmt_bind_null). Lets the server type the NULL - e.g.
 * COALESCE(:1, SYSDATE) - and, in an array execute, keeps a NULL row from
 * re-typing the column. */
SeerStatus seer_stmt_bind_null_typed(SeerStmt *stmt, int param, int ora_type);

/* Bind a SQL OBJECT (ADT) parameter (8i and later; #172). The type is `schema`.`type_name`;
 * its attribute values are supplied as text in attribute order (a NULL entry is
 * a SQL NULL attribute), and `n_attrs` must match the type's attribute count.
 * The driver looks up the type and encodes each value as its attribute's Oracle
 * type: character attributes take the UTF-8 text; NUMBER attributes take an
 * integer parsed from the text. A type declared in a PL/SQL package (a record)
 * is named "PKG.TYPE"; its PLS_INTEGER attributes take an integer and BOOLEAN
 * ones "TRUE"/"FALSE" (or 1/0). */
SeerStatus seer_stmt_bind_object(SeerStmt *stmt, int param, const char *schema,
                                 const char *type_name, const char *const *attr_values,
                                 int n_attrs);

/* Bind a REF IN (#241): `ref` / `len` are the REF's bytes, as a REF column or
 * REF() reads them; `type_schema` / `type_name` name the type it references.
 * 8i, 9i and 12c+; SEER_ENOTIMPL on 10g / 11g, which have no measured form.
 * A NULL REF is SEER_EPARAM (unfilled, 8i and 9i answer ORA-00600). */
SeerStatus seer_stmt_bind_ref(SeerStmt *stmt, int param, const char *type_schema,
                              const char *type_name, const uint8_t *ref, size_t len);

/* Bind a REF OUT parameter of a PL/SQL block (#241), the type it references
 * named as for seer_stmt_bind_ref. Its value is read with seer_stmt_out_data,
 * as the REF's bytes (binary; NULL for a NULL REF). 9i and 12c+; SEER_ENOTIMPL
 * on 8i (its OUT form isn't measured yet) and on 10g / 11g. */
SeerStatus seer_stmt_bind_ref_out(SeerStmt *stmt, int param, const char *type_schema,
                                  const char *type_name);

/* Bind an OUT parameter of an object or collection type (10g+), named as for
 * seer_stmt_bind_object (a package type as "PKG.TYPE"). After execute,
 * seer_stmt_out_data returns the value rendered as text, as a fetched object
 * is: "v1, v2, ..." for an object, "[e1, e2, ...]" for a collection ("[k: e,
 * ...]" for an index-by table, with its keys), NULL for a NULL object. For an
 * IN OUT object, bind the value with seer_stmt_bind_object /
 * seer_stmt_bind_collection and call seer_stmt_bind_set_inout. */
SeerStatus seer_stmt_bind_object_out(SeerStmt *stmt, int param, const char *schema,
                                     const char *type_name);

/* Bind a native JSON parameter (21c+): the JSON document is given as JSON text,
 * parsed and encoded to OSON (native binary JSON) and bound directly - no server-
 * side text-to-JSON cast. SEER_ENOTIMPL on a pre-21c server (bind JSON as a string
 * there); SEER_EPARAM on malformed JSON or a document beyond the encoder's subset. */
SeerStatus seer_stmt_bind_json(SeerStmt *stmt, int param, const char *json_text);

/* Bind a native VECTOR parameter (23ai+): a dense vector of `dims` elements in
 * FLOAT32, FLOAT64, or INT8, encoded to Oracle's binary VECTOR image and bound
 * directly. SEER_ENOTIMPL on a pre-23ai server. */
SeerStatus seer_stmt_bind_vector_f32(SeerStmt *stmt, int param, const float *values, int dims);
SeerStatus seer_stmt_bind_vector_f64(SeerStmt *stmt, int param, const double *values, int dims);
SeerStatus seer_stmt_bind_vector_i8(SeerStmt *stmt, int param, const int8_t *values, int dims);

/* Bind a BINARY VECTOR (23ai+): a bit vector packed as `nbytes` bytes (8 dims per
 * byte, so the vector width is nbytes*8). */
SeerStatus seer_stmt_bind_vector_binary(SeerStmt *stmt, int param, const uint8_t *bytes,
                                        int nbytes);

/* Bind a sparse FLOAT32 VECTOR (23ai+): a `num_dimensions`-wide vector with `nnz`
 * non-zero entries, indices[i] -> values[i] (indices strictly increasing). */
SeerStatus seer_stmt_bind_vector_sparse_f32(SeerStmt *stmt, int param, int num_dimensions, int nnz,
                                            const uint32_t *indices, const float *values);
/* Sparse VECTOR variants with FLOAT64 (8-byte) / INT8 (1-byte) storage. */
SeerStatus seer_stmt_bind_vector_sparse_f64(SeerStmt *stmt, int param, int num_dimensions, int nnz,
                                            const uint32_t *indices, const double *values);
SeerStatus seer_stmt_bind_vector_sparse_i8(SeerStmt *stmt, int param, int num_dimensions, int nnz,
                                           const uint32_t *indices, const int8_t *values);

/* Bind a collection (VARRAY / nested table) parameter (10g+). `type_name` is the
 * collection type; `elem_values` are its `n_elems` element values as text (a NULL
 * entry is a SQL NULL element), each encoded as the collection's element type.
 * A collection type declared in a PL/SQL package is named "PKG.TYPE"; an
 * index-by table (INDEX BY BINARY_INTEGER) gets its elements keyed 0..n-1. */
SeerStatus seer_stmt_bind_collection(SeerStmt *stmt, int param, const char *schema,
                                     const char *type_name, const char *const *elem_values,
                                     int n_elems);

/* Bind a PL/SQL associative array (index-by table) as a single parameter (8i and
 * 10g+; SEER_ENOTIMPL on 9i, #254): the whole `values` array goes in one call.
 * For text, `elem_size` is the declared element max length and a NULL entry is
 * a SQL NULL element. The matching
 * statement is a PL/SQL block whose parameter is an index-by table of NUMBER /
 * VARCHAR2. (Distinct from array DML, which iterates a statement N times.) */
SeerStatus seer_stmt_bind_int64_array(SeerStmt *stmt, int param, const int64_t *values, int n);
SeerStatus seer_stmt_bind_text_array(SeerStmt *stmt, int param, const char *const *values, int n,
                                     int elem_size);

/* Bind a PL/SQL associative-array OUT parameter (8i and 10g+; not 9i, #254):
 * the server fills up to `capacity` elements of `ora_type` (2 NUMBER /
 * 1 VARCHAR; `elem_size` is the per-element max for VARCHAR). After execute,
 * read the results with seer_stmt_out_array_len and seer_stmt_out_array_get. */
SeerStatus seer_stmt_bind_out_array(SeerStmt *stmt, int param, int ora_type, int elem_size,
                                    int capacity);
/* Number of elements returned in an OUT assoc-array bind. */
int seer_stmt_out_array_len(SeerStmt *stmt, int param);
/* Element `index` of an OUT assoc-array bind, decoded to text (*data is
 * NUL-terminated; *isnull optional). */
SeerStatus seer_stmt_out_array_get(SeerStmt *stmt, int param, int index, const char **data,
                                   size_t *len, int *isnull);

/* Declare an OUT parameter of the given Oracle type (2 NUMBER, 1 VARCHAR,
 * 12 DATE, 23 RAW, 101 BINARY_DOUBLE) and max byte size. After execute its
 * value is read with seer_stmt_out_data. */
SeerStatus seer_stmt_bind_out(SeerStmt *stmt, int param, int ora_type, int max_size);
/* Turn an already-bound input parameter into IN OUT: its value is sent in and
 * the block's result comes back in the same place (read it with
 * seer_stmt_out_data). `max_size` reserves room for a VARCHAR / RAW result
 * longer than the value sent. Bind the input value first. */
SeerStatus seer_stmt_bind_set_inout(SeerStmt *stmt, int param, int max_size);
/* For a DML RETURNING bind whose value the server truncated to the bind's
 * declared size: the value's full length. 0 when it arrived whole. */
long seer_stmt_out_truncated(SeerStmt *stmt, int param);

/* Retrieve a captured OUT parameter value (valid after execute). */
SeerStatus seer_stmt_out_data(SeerStmt *stmt, int param, const void **data, size_t *len,
                              int *is_null, int *is_binary);

/* Array (bulk) binding for DML: declare `n` iterations (rows), then for each
 * row select it with seer_stmt_bind_row and bind every parameter's value for
 * that row. A single execute applies the statement n times. Setting the array
 * size clears any existing binds. */
SeerStatus seer_stmt_set_array_size(SeerStmt *stmt, int n);
SeerStatus seer_stmt_bind_row(SeerStmt *stmt, int row);

/* Array-DML batch-errors mode: when armed, a per-row failure no longer aborts
 * an array execute - the good rows apply and each failure is captured (its
 * iteration offset, ORA code, and message). Arm before execute; only affects
 * array DML (n_iters > 1). */
SeerStatus seer_stmt_set_batch_errors(SeerStmt *stmt, int on);

/* Array-DML per-iteration row counts (12c+): arm before an array execute to ask
 * the server for the number of rows each iteration affected. After execute,
 * read them back by index. The count is 0 unless armed and the server is 12.2+. */
SeerStatus seer_stmt_set_array_dml_rowcounts(SeerStmt *stmt, int on);
size_t seer_stmt_array_dml_rowcount_count(SeerStmt *stmt);
unsigned seer_stmt_array_dml_rowcount(SeerStmt *stmt, size_t i);

/* After an array execute in batch-errors mode: the number of per-row failures,
 * and the detail for failure `i` (0-based). `row` is the 0-based iteration that
 * failed; `message` is owned by the statement (valid until the next execute or
 * close) and may be NULL. */
size_t seer_stmt_batch_error_count(SeerStmt *stmt);
SeerStatus seer_stmt_batch_error(SeerStmt *stmt, size_t i, unsigned *row, unsigned *code,
                                 const char **message);

SeerStatus seer_stmt_execute(SeerStmt *stmt);
/* Describe a prepared query's result columns without executing it (a
 * parse-only round trip; binds need not be set). Afterwards seer_stmt_num_cols
 * and the column accessors report them; seer_stmt_execute then parses and
 * describes afresh as usual. A no-op for a statement that is not a
 * query, one already described or executed, and on 8i. On 9i it is a parse
 * without the EXECUTE bit plus a describe. */
SeerStatus seer_stmt_describe(SeerStmt *stmt);
/* Non-zero when the last execute created a PL/SQL object (procedure, function,
 * package, trigger, ...) that compiled with errors: the statement succeeded
 * but the object is invalid (ORA-24344 "success with compilation error"). */
int seer_stmt_compile_warning(SeerStmt *stmt);
/* Non-zero when the prepared statement is a query (SELECT or WITH). A query
 * runs with one parameter set at a time: seer_stmt_execute refuses it with an
 * array of them (#430), and ODBC runs one set per result set (#431). */
int seer_stmt_is_query(const SeerStmt *stmt);
/* A 23ai VECTOR column's declared dimension count (0 = flexible) and element
 * format (2 FLOAT32, 3 FLOAT64, 4 INT8, 5 BINARY; 0 = flexible); both 0 for
 * any other column or an older server. */
SeerStatus seer_stmt_col_vector(SeerStmt *stmt, int col, int *dims, int *format);
/* The parse offset (into the statement text) the server reported with the
 * last execute error - where the parser stopped, e.g. 7 for the bad column in
 * "SELECT nonexistent FROM dual"; 0 when it gave none. */
long seer_last_error_offset(SeerConn *conn);

/* The server's release as its five dotted fields (e.g. 23, 26, 2, 0, 0), from
 * the word it sends at login. Before 18c they are major.minor.app.component.
 * platform; from 18c, major.update.revision.increment.extension. SEER_ENOTIMPL
 * when the server sent none (Oracle 9i). */
SeerStatus seer_server_version(SeerConn *conn, int version[5]);

/* The longest identifier the server takes, in bytes, as it states it at login
 * (AUTH_MAX_IDEN_LENGTH: 128 from 12.2 on). 0 when the server stated none, as
 * 8i to 11g never do; their limit is 30. */
int seer_max_identifier_length(SeerConn *conn);

/* Advance to the next row. SEER_OK if a row is now current, SEER_ENODATA when
 * the result set is exhausted. */
SeerStatus seer_stmt_fetch(SeerStmt *stmt);

/* Advance to the next implicit result set (DBMS_SQL.RETURN_RESULT, 12c+): drains
 * that server cursor and makes it the current result set (column metadata + rows
 * reflect it). SEER_OK if a set is now current, SEER_ENODATA when none remain. */
SeerStatus seer_stmt_next_result(SeerStmt *stmt);

/* Position the cursor at an arbitrary 0-based row of the buffered result set
 * (for scrollable fetch). SEER_ENODATA if `row` is out of range. */
SeerStatus seer_stmt_set_row(SeerStmt *stmt, long row);
void seer_stmt_close(SeerStmt *stmt);

/* Result-set metadata (valid after execute). */
int seer_stmt_num_cols(SeerStmt *stmt);
const char *seer_stmt_col_name(SeerStmt *stmt, int col); /* NULL if out of range */
/* 23ai column annotations for `col`, serialized as "name=value\n..." (name-only
 * annotations have an empty value). NULL if the column has none or the server is
 * pre-23ai. Valid until the next execute or close. */
const char *seer_stmt_col_annotations(SeerStmt *stmt, int col);
int seer_stmt_col_type(SeerStmt *stmt, int col); /* Oracle type number, -1 if bad */
/* The column's declared size: characters for a character column, bytes for
 * a RAW (#264); 0 where the describe gives none, or for a bad column. */
int seer_stmt_col_size(SeerStmt *stmt, int col);
/* The column's largest value in bytes, as the describe states it: a
 * VARCHAR2(20 CHAR) in AL32UTF8 is 80. 0 where it gives none (#264). */
int seer_stmt_col_octets(SeerStmt *stmt, int col);
int seer_stmt_col_nullable(SeerStmt *stmt, int col); /* nonzero if NULLs allowed */
/* The describe's precision and scale (#259): NUMBER(p,s)'s p and s - 0 and
 * -127 for a NUMBER declared without them, -127 for a FLOAT(b) (its binary
 * precision in p); a TIMESTAMP's scale is its fractional-second digits. 0 for
 * a bad column. */
int seer_stmt_col_precision(SeerStmt *stmt, int col);
int seer_stmt_col_scale(SeerStmt *stmt, int col);
long seer_stmt_row_count(SeerStmt *stmt); /* rows in the result set */

/* Current row's value for `col` (valid until the next fetch or close). On a SQL
 * NULL, *value is NULL and *is_null is set. */
SeerStatus seer_stmt_get_string(SeerStmt *stmt, int col, const char **value, int *is_null);

/* Current row's value as raw bytes (binary-safe). *data points at the value
 * (NULL if SQL NULL), *len is its byte length, *is_null is set on NULL, and
 * *is_binary (may be NULL) flags BLOB/RAW/LONG-RAW. Valid until next fetch/close. */
SeerStatus seer_stmt_get_data(SeerStmt *stmt, int col, const void **data, size_t *len, int *is_null,
                              int *is_binary);

/* Human-readable text for a status code (never NULL). */
const char *seer_strerror(SeerStatus status);

/* The last server error message (ORA-NNNNN: ...) for a connection, or NULL. */
const char *seer_last_error(SeerConn *conn);

/* Request pipelining (§32, #132). A pipeline collects several operations that run
 * in order; on a 23ai server that negotiated end-of-response framing they are
 * later sent as one round trip, but the API, ordering and results are identical
 * to running them one at a time. Build one, queue operations, run it, then read
 * each operation's outcome. */
typedef struct SeerPipeline SeerPipeline;

SeerPipeline *seer_pipeline_create(void);
void seer_pipeline_free(SeerPipeline *p);

/* Queue operations (executed in the order added). A query op (fetchone/many/all)
 * keeps its executed statement so the caller can read its rows afterwards; an
 * execute op (DML/DDL/PL-SQL) keeps no rows; commit commits the transaction. */
SeerStatus seer_pipeline_add_execute(SeerPipeline *p, const char *sql);
SeerStatus seer_pipeline_add_fetchone(SeerPipeline *p, const char *sql);
SeerStatus seer_pipeline_add_fetchmany(SeerPipeline *p, const char *sql, uint32_t num_rows);
SeerStatus seer_pipeline_add_fetchall(SeerPipeline *p, const char *sql);
SeerStatus seer_pipeline_add_commit(SeerPipeline *p);

/* Run the queued operations. `continue_on_error` non-zero keeps running after an
 * operation fails (its error is recorded); zero stops after the first failure
 * (recorded too). Returns SEER_OK once the run completes — per-operation success
 * is read via seer_pipeline_op_status. SEER_EPARAM on a bad argument. */
SeerStatus seer_pipeline_run(SeerConn *conn, SeerPipeline *p, int continue_on_error);

/* Results, valid after seer_pipeline_run. */
size_t seer_pipeline_count(const SeerPipeline *p);
/* Operation `i`'s outcome: SEER_OK or its failure status; *ora_code (may be NULL)
 * receives the ORA error number when it failed on the server, else 0. */
SeerStatus seer_pipeline_op_status(const SeerPipeline *p, size_t i, long *ora_code);
/* Operation `i`'s executed statement for a query op (holds the result rows — read
 * with seer_stmt_fetch/get_*), or NULL for execute/commit or a failed op. Borrowed:
 * owned by the pipeline and freed by seer_pipeline_free. */
SeerStmt *seer_pipeline_op_stmt(const SeerPipeline *p, size_t i);

#ifdef __cplusplus
}
#endif

#endif /* SEER_SEERTNS_H */

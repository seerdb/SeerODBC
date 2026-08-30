/* SeerODBC - protocol core public API.
 *
 * This is the entire surface the ODBC shim (and freeoracle, and any future
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
#define SEERTNS_VERSION_MINOR 0
#define SEERTNS_VERSION_PATCH 0

/* Core result codes. The ODBC shim maps these onto SQLRETURN + SQLSTATE;
 * the core never speaks SQLRETURN itself. */
typedef enum {
    SEER_OK       =  0,
    SEER_ENOTIMPL = -1,   /* not implemented yet (scaffold) */
    SEER_EIO      = -2,   /* socket / transport error */
    SEER_EPROTO   = -3,   /* malformed or unexpected wire data */
    SEER_EAUTH    = -4,   /* authentication rejected */
    SEER_ENOMEM   = -5,   /* allocation failure */
    SEER_EPARAM   = -6,   /* bad argument from the caller */
    SEER_ENODATA  = -7,   /* no more rows (end of fetch) */
    SEER_EDB      = -8,   /* server returned an ORA-NNNNN error */
} SeerStatus;

/* Opaque handles - the core owns their layout. */
typedef struct SeerConn SeerConn;
typedef struct SeerStmt SeerStmt;

typedef struct {
    const char *host;
    uint16_t    port;          /* default 1521 */
    const char *service_name;  /* service name (SERVICE_NAME in the descriptor) */
    const char *sid;           /* SID (older servers, e.g. 9i); used if set instead
                                * of service_name -> (CONNECT_DATA=(SID=...)) */
    const char *username;
    const char *password;
    int         use_tls;       /* non-zero => TCPS (TLS transport) */
    const char *tls_ca;        /* CA bundle (PEM) for verification; NULL => system */
    int         tls_verify;    /* verify the server cert (default on); 0 => accept any */
    /* DRCP (database resident connection pooling): a connection class and/or
     * session purity request a pooled server. Either being set adds
     * (SERVER=POOLED) to the connect descriptor and the AUTH_KPPL_* auth pairs.
     * purity: 0 default, 1 NEW (fresh session), 2 SELF (reuse). */
    const char *cclass;
    int         purity;
    /* Sharding keys (§37). A sharding key routes a connection to a specific shard
     * of a sharded database — an OCI-client capability that the shard resolution
     * performs below the thin TTC/TNS protocol, so a pure-protocol client has no
     * message to carry it. Accepted for API parity: seer_connect rejects a
     * non-empty key with SEER_ENOTIMPL rather than silently ignoring it. */
    const char *shardingkey;
    const char *supershardingkey;
} SeerConnParams;

#define SEER_PURITY_NEW  1
#define SEER_PURITY_SELF 2

/* Connection lifecycle. */
SeerStatus seer_connect(const SeerConnParams *params, SeerConn **out);
void       seer_disconnect(SeerConn *conn);

/* Transaction control. autocommit (default on) commits each statement; with it
 * off, changes persist only after seer_commit. */
void       seer_set_autocommit(SeerConn *conn, int on);
SeerStatus seer_commit(SeerConn *conn);
SeerStatus seer_rollback(SeerConn *conn);

/* Request boundaries (§35, 21c+). Bracket a logical request on a (typically
 * pooled) connection so the server can reset session state between requests.
 * `begin` arms a REQUEST_BEGIN marker that rides in front of the next call with
 * no extra round-trip; `end` sends REQUEST_END piggybacked on a rollback (or, if
 * no call ran after `begin`, cancels it and sends nothing). Both return
 * SEER_ENOTIMPL when the server does not advertise the capability (e.g. 10g/11g),
 * which callers may treat as "feature inactive" and ignore. */
SeerStatus seer_request_begin(SeerConn *conn);
SeerStatus seer_request_end(SeerConn *conn);

/* Two-phase commit / XA (distributed transactions, 12c+). A global transaction
 * is identified by an Xid (format id + global transaction id + branch
 * qualifier). The branch lifecycle is: begin -> [DML] -> end -> prepare ->
 * commit (or rollback at any point). The opaque transaction context the server
 * returns from begin is held on the connection and replayed automatically. */
typedef struct {
    int32_t        format_id;
    const uint8_t *gtrid;       /* global transaction id   */
    int            gtrid_len;
    const uint8_t *bqual;       /* branch qualifier        */
    int            bqual_len;
} SeerXid;

#define SEER_TPC_BEGIN_NEW     0x00000001   /* start a new branch          */
#define SEER_TPC_BEGIN_JOIN    0x00000002   /* join an existing branch     */
#define SEER_TPC_BEGIN_RESUME  0x00000004   /* resume a suspended branch   */
#define SEER_TPC_END_NORMAL    0x00000000
#define SEER_TPC_END_SUSPEND   0x00100000   /* suspend (resume-able) end   */

/* Begin (or join/resume) a global transaction branch. `timeout` is the seconds
 * the server holds an idle branch (0 = server default). 12c+ only. */
SeerStatus seer_tpc_begin(SeerConn *conn, const SeerXid *xid, uint32_t flags,
                          uint32_t timeout);
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
SeerStatus seer_txn_begin_sessionless(SeerConn *conn, const uint8_t *txn_id,
                                      size_t txn_id_len, uint32_t timeout);
SeerStatus seer_txn_resume_sessionless(SeerConn *conn, const uint8_t *txn_id,
                                       size_t txn_id_len, uint32_t timeout);
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
 * so commit to make the message available. 12c+ (SEER_ENOTIMPL on older). */
/* Enqueue options (all optional; a NULL options pointer means the defaults that
 * seer_aq_enq_raw uses). */
typedef struct {
    unsigned    priority;     /* message priority (lower = dequeued first); default 0 */
    unsigned    delay;        /* seconds until the message becomes available; default 0 */
    int         expiration;   /* seconds it stays available after that; -1 = forever  */
    const char *correlation;  /* correlation identifier, or NULL                      */
} SeerAqEnqOptions;

/* Dequeue options (a NULL options pointer means REMOVE, no wait, no filter). */
typedef struct {
    int         browse;       /* non-zero = BROWSE (peek, leave in queue); else REMOVE */
    unsigned    wait_seconds; /* seconds to wait for a message; 0 = do not wait        */
    const char *correlation;  /* dequeue only messages matching this correlation, or NULL */
    const char *consumer;     /* consumer name for a multi-consumer queue, or NULL     */
} SeerAqDeqOptions;

SeerStatus seer_aq_enq_raw(SeerConn *conn, const char *queue_name,
                           const uint8_t *payload, size_t payload_len,
                           uint8_t msgid[16]);

/* As seer_aq_enq_raw, with message properties from `opt` (NULL = defaults). */
SeerStatus seer_aq_enq_raw_opt(SeerConn *conn, const char *queue_name,
                               const uint8_t *payload, size_t payload_len,
                               const SeerAqEnqOptions *opt, uint8_t msgid[16]);

/* Enqueue a SQL object value to an object-payload queue. `attr_values` are the
 * flattened leaf attributes as text (one per leaf, depth-first; same convention
 * as seer_stmt_bind_object). 12c+. */
SeerStatus seer_aq_enq_object(SeerConn *conn, const char *queue_name,
                              const char *type_schema, const char *type_name,
                              const char *const *attr_values, int n_attrs,
                              uint8_t msgid[16]);

/* Enqueue a JSON document (as JSON text) to a JSON-payload queue. The text is
 * parsed and encoded to OSON (native binary JSON). Needs native JSON queues
 * (server fv >= 20.1; SEER_ENOTIMPL otherwise). */
SeerStatus seer_aq_enq_json(SeerConn *conn, const char *queue_name,
                            const char *json_text, uint8_t msgid[16]);

/* Bulk-enqueue `count` RAW messages to `queue_name` in one round-trip.
 * payloads[i]/lens[i] give each message; `msgids`, if non-NULL, must hold
 * count*16 bytes and receives the assigned message ids. 12c+. */
SeerStatus seer_aq_enq_raw_array(SeerConn *conn, const char *queue_name, int count,
                                 const uint8_t *const *payloads, const size_t *lens,
                                 uint8_t *msgids);

/* Bulk-dequeue up to `max_count` RAW messages (REMOVE, the given wait) in one
 * round-trip. `payloads` and `lens` are caller-allocated arrays of max_count;
 * each dequeued message's payload is malloc'd into payloads[i] (caller frees)
 * with its length in lens[i]. *out_count receives the number actually dequeued
 * (0 when the queue is empty). 12c+. */
SeerStatus seer_aq_deq_raw_array(SeerConn *conn, const char *queue_name, int max_count,
                                 uint32_t wait_seconds, uint8_t **payloads, size_t *lens,
                                 int *out_count);

/* Advanced Queuing: dequeue a RAW message from `queue_name` (REMOVE mode,
 * ON_COMMIT visibility). Waits up to `wait_seconds` for a message (0 = do not
 * wait). On SEER_OK the payload is malloc'd into *payload (caller frees) with its
 * length in *payload_len, and the 16-byte message id into `msgid` (if non-NULL).
 * SEER_ENODATA if no message was available within the wait. Commit to finalise
 * the removal. 12c+ (SEER_ENOTIMPL on older). */
SeerStatus seer_aq_deq_raw(SeerConn *conn, const char *queue_name,
                           uint32_t wait_seconds, uint8_t **payload,
                           size_t *payload_len, uint8_t msgid[16]);

/* As seer_aq_deq_raw, with BROWSE mode / correlation filter / consumer name and
 * wait taken from `opt` (NULL = REMOVE, no wait, no filter). */
SeerStatus seer_aq_deq_raw_opt(SeerConn *conn, const char *queue_name,
                               const SeerAqDeqOptions *opt, uint8_t **payload,
                               size_t *payload_len, uint8_t msgid[16]);

/* Dequeue an object-payload message (REMOVE, the given wait). The decoded object
 * is rendered to text ("v1, v2, ...", as the object fetch path) into *out_text
 * (caller frees). SEER_ENODATA if no message was available. 12c+. */
SeerStatus seer_aq_deq_object(SeerConn *conn, const char *queue_name,
                              const char *type_schema, const char *type_name,
                              uint32_t wait_seconds, char **out_text, uint8_t msgid[16]);

/* Dequeue a JSON-payload message (REMOVE, the given wait). The OSON payload is
 * decoded to JSON text into *out_text (caller frees). SEER_ENODATA if none was
 * available. Needs native JSON queues (fv >= 20.1). */
SeerStatus seer_aq_deq_json(SeerConn *conn, const char *queue_name,
                            uint32_t wait_seconds, char **out_text, uint8_t msgid[16]);

/* Interrupt a call currently blocked waiting for the server on `conn` (e.g. a
 * long-running statement on another thread). Best-effort: a no-op when no call
 * is in flight. The blocked call returns the server's ORA-01013 (cancelled). */
void       seer_cancel(SeerConn *conn);

/* Statement lifecycle. A literal SELECT (no bind variables) is supported:
 * prepare the text, execute it, then fetch rows one at a time. */
SeerStatus seer_stmt_prepare(SeerConn *conn, const char *sql, SeerStmt **out);

/* Bind an input parameter by 1-based position, before execute. A NUMBER bind
 * carries an integer; a text bind carries UTF-8 (len < 0 => strlen); a null
 * bind carries SQL NULL. Re-binding the same position replaces it. */
SeerStatus seer_stmt_bind_int64(SeerStmt *stmt, int param, int64_t value);
SeerStatus seer_stmt_bind_text(SeerStmt *stmt, int param, const char *str, int len);
SeerStatus seer_stmt_bind_raw(SeerStmt *stmt, int param, const void *data, int len);

/* Bind national-charset text (NVARCHAR2 / NCHAR): `str` (UTF-8) is converted to
 * AL16UTF16 and declared with csfrm 2, so the server stores it in the database's
 * national character set. */
SeerStatus seer_stmt_bind_ntext(SeerStmt *stmt, int param, const char *str, int len);

/* Bind an XML document to an XMLType target (e.g. INSERT ... VALUES (:1) into an
 * XMLType column). The UTF-8 text is bound and the server parses it to XMLType;
 * handles documents of any size (VARCHAR2 or streamed LONG). */
SeerStatus seer_stmt_bind_xmltype(SeerStmt *stmt, int param, const char *xml_text);
SeerStatus seer_stmt_bind_date(SeerStmt *stmt, int param, int year, int month,
                               int day, int hour, int minute, int second);
/* Bind a TIMESTAMP value (native 11-byte form), preserving `nanos` fractional
 * seconds - unlike bind_date, which is second precision. */
SeerStatus seer_stmt_bind_timestamp(SeerStmt *stmt, int param, int year, int month,
                                    int day, int hour, int minute, int second,
                                    uint32_t nanos);
SeerStatus seer_stmt_bind_double(SeerStmt *stmt, int param, double value);
/* Bind INTERVAL YEAR TO MONTH / DAY TO SECOND. A negative interval is expressed
 * by negative component values (the components share one sign). */
SeerStatus seer_stmt_bind_interval_ym(SeerStmt *stmt, int param,
                                      int32_t years, int32_t months);
SeerStatus seer_stmt_bind_interval_ds(SeerStmt *stmt, int param, int32_t days,
                                      int32_t hours, int32_t mins, int32_t secs,
                                      int32_t nanos);
/* Bind a native BINARY_FLOAT (4-byte). */
SeerStatus seer_stmt_bind_float(SeerStmt *stmt, int param, float value);
/* Bind a boolean: native 23ai BOOLEAN, or a NUMBER 0/1 on older servers. */
SeerStatus seer_stmt_bind_bool(SeerStmt *stmt, int param, int value);
SeerStatus seer_stmt_bind_null(SeerStmt *stmt, int param);

/* Bind a SQL OBJECT (ADT) parameter (12c+). The type is `schema`.`type_name`;
 * its attribute values are supplied as text in attribute order (a NULL entry is
 * a SQL NULL attribute), and `n_attrs` must match the type's attribute count.
 * The driver looks up the type and encodes each value as its attribute's Oracle
 * type: character attributes take the UTF-8 text; NUMBER attributes take an
 * integer parsed from the text. (Slice 1: flat object of scalar attributes.) */
SeerStatus seer_stmt_bind_object(SeerStmt *stmt, int param,
                                 const char *schema, const char *type_name,
                                 const char *const *attr_values, int n_attrs);

/* Bind a native JSON parameter (21c+): the JSON document is given as JSON text,
 * parsed and encoded to OSON (native binary JSON) and bound directly - no server-
 * side text-to-JSON cast. SEER_ENOTIMPL on a pre-21c server (bind JSON as a string
 * there); SEER_EPARAM on malformed JSON or a document beyond the encoder's subset. */
SeerStatus seer_stmt_bind_json(SeerStmt *stmt, int param, const char *json_text);

/* Bind a native VECTOR parameter (23ai+): a dense vector of `dims` elements in
 * FLOAT32, FLOAT64, or INT8, encoded to Oracle's binary VECTOR image and bound
 * directly. SEER_ENOTIMPL on a pre-23ai server. */
SeerStatus seer_stmt_bind_vector_f32(SeerStmt *stmt, int param,
                                     const float *values, int dims);
SeerStatus seer_stmt_bind_vector_f64(SeerStmt *stmt, int param,
                                     const double *values, int dims);
SeerStatus seer_stmt_bind_vector_i8(SeerStmt *stmt, int param,
                                    const int8_t *values, int dims);

/* Bind a BINARY VECTOR (23ai+): a bit vector packed as `nbytes` bytes (8 dims per
 * byte, so the vector width is nbytes*8). */
SeerStatus seer_stmt_bind_vector_binary(SeerStmt *stmt, int param,
                                        const uint8_t *bytes, int nbytes);

/* Bind a sparse FLOAT32 VECTOR (23ai+): a `num_dimensions`-wide vector with `nnz`
 * non-zero entries, indices[i] -> values[i] (indices strictly increasing). */
SeerStatus seer_stmt_bind_vector_sparse_f32(SeerStmt *stmt, int param,
                                            int num_dimensions, int nnz,
                                            const uint32_t *indices, const float *values);
/* Sparse VECTOR variants with FLOAT64 (8-byte) / INT8 (1-byte) storage. */
SeerStatus seer_stmt_bind_vector_sparse_f64(SeerStmt *stmt, int param,
                                            int num_dimensions, int nnz,
                                            const uint32_t *indices, const double *values);
SeerStatus seer_stmt_bind_vector_sparse_i8(SeerStmt *stmt, int param,
                                           int num_dimensions, int nnz,
                                           const uint32_t *indices, const int8_t *values);

/* Bind a collection (VARRAY / nested table) parameter (12c+). `type_name` is the
 * collection type; `elem_values` are its `n_elems` element values as text (a NULL
 * entry is a SQL NULL element), each encoded as the collection's element type. */
SeerStatus seer_stmt_bind_collection(SeerStmt *stmt, int param,
                                     const char *schema, const char *type_name,
                                     const char *const *elem_values, int n_elems);

/* Bind a PL/SQL associative array (index-by table) as a single parameter (12c+):
 * the whole `values` array goes in one call. For text, `elem_size` is the
 * declared element max length and a NULL entry is a SQL NULL element. The matching
 * statement is a PL/SQL block whose parameter is an index-by table of NUMBER /
 * VARCHAR2. (Distinct from array DML, which iterates a statement N times.) */
SeerStatus seer_stmt_bind_int64_array(SeerStmt *stmt, int param,
                                      const int64_t *values, int n);
SeerStatus seer_stmt_bind_text_array(SeerStmt *stmt, int param,
                                     const char *const *values, int n, int elem_size);

/* Bind a PL/SQL associative-array OUT parameter (12c+): the server fills up to
 * `capacity` elements of `ora_type` (2 NUMBER / 1 VARCHAR; `elem_size` is the
 * per-element max for VARCHAR). After execute, read the results with
 * seer_stmt_out_array_len and seer_stmt_out_array_get. */
SeerStatus seer_stmt_bind_out_array(SeerStmt *stmt, int param, int ora_type,
                                    int elem_size, int capacity);
/* Number of elements returned in an OUT assoc-array bind. */
int        seer_stmt_out_array_len(SeerStmt *stmt, int param);
/* Element `index` of an OUT assoc-array bind, decoded to text (*data is
 * NUL-terminated; *isnull optional). */
SeerStatus seer_stmt_out_array_get(SeerStmt *stmt, int param, int index,
                                   const char **data, size_t *len, int *isnull);

/* Declare an OUT parameter of the given Oracle type (2 NUMBER, 1 VARCHAR,
 * 12 DATE, 23 RAW, 101 BINARY_DOUBLE) and max byte size. After execute its
 * value is read with seer_stmt_out_data. */
SeerStatus seer_stmt_bind_out(SeerStmt *stmt, int param, int ora_type, int max_size);

/* Retrieve a captured OUT parameter value (valid after execute). */
SeerStatus seer_stmt_out_data(SeerStmt *stmt, int param, const void **data,
                              size_t *len, int *is_null, int *is_binary);

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
size_t     seer_stmt_array_dml_rowcount_count(SeerStmt *stmt);
unsigned   seer_stmt_array_dml_rowcount(SeerStmt *stmt, size_t i);

/* After an array execute in batch-errors mode: the number of per-row failures,
 * and the detail for failure `i` (0-based). `row` is the 0-based iteration that
 * failed; `message` is owned by the statement (valid until the next execute or
 * close) and may be NULL. */
size_t     seer_stmt_batch_error_count(SeerStmt *stmt);
SeerStatus seer_stmt_batch_error(SeerStmt *stmt, size_t i, unsigned *row,
                                 unsigned *code, const char **message);

SeerStatus seer_stmt_execute(SeerStmt *stmt);

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
void       seer_stmt_close(SeerStmt *stmt);

/* Result-set metadata (valid after execute). */
int         seer_stmt_num_cols(SeerStmt *stmt);
const char *seer_stmt_col_name(SeerStmt *stmt, int col);   /* NULL if out of range */
/* 23ai column annotations for `col`, serialized as "name=value\n..." (name-only
 * annotations have an empty value). NULL if the column has none or the server is
 * pre-23ai. Valid until the next execute or close. */
const char *seer_stmt_col_annotations(SeerStmt *stmt, int col);
int         seer_stmt_col_type(SeerStmt *stmt, int col);   /* Oracle type number, -1 if bad */
int         seer_stmt_col_size(SeerStmt *stmt, int col);   /* max size in bytes, 0 if bad */
int         seer_stmt_col_nullable(SeerStmt *stmt, int col); /* nonzero if NULLs allowed */
long        seer_stmt_row_count(SeerStmt *stmt);           /* rows in the result set */

/* Current row's value for `col` (valid until the next fetch or close). On a SQL
 * NULL, *value is NULL and *is_null is set. */
SeerStatus seer_stmt_get_string(SeerStmt *stmt, int col,
                                const char **value, int *is_null);

/* Current row's value as raw bytes (binary-safe). *data points at the value
 * (NULL if SQL NULL), *len is its byte length, *is_null is set on NULL, and
 * *is_binary (may be NULL) flags BLOB/RAW/LONG-RAW. Valid until next fetch/close. */
SeerStatus seer_stmt_get_data(SeerStmt *stmt, int col, const void **data,
                              size_t *len, int *is_null, int *is_binary);

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
void          seer_pipeline_free(SeerPipeline *p);

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

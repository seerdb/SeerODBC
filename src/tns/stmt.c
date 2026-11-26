/* Statement execution and row fetch (PROTOCOL.md §5-6).
 *
 * Supports a literal SELECT with no bind variables: TTI_ALL8 execute, then a
 * walk of the response tokens - TTI_DCB (describe), TTI_RXH/TTI_RXD (rows),
 * TTI_BVC (differential row encoding), TTI_RPA (skipped), TTI_OER (status) -
 * issuing follow-up TTI_FETCH while the server signals more rows. Column
 * values are rendered to text (NUMBER/DATE decoded; VARCHAR2/CHAR as UTF-8).
 *
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#include "seer/seertns.h"

#include "charset.h"
#include "conn.h"
#include "json.h"
#include "lob.h"
#include "oson.h"
#include "placeholders.h"
#include "log.h"
#include "msg.h" /* the messages as schemas (#395 spike) */
#include "marshal.h"
#include "reader.h"
#include "tns_consts.h"
#include "ttc.h"
#include "types.h"
#include "writer.h"

#include <ctype.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h> /* strncasecmp */

#define PREFETCH_ROWS 100

/* Types whose row value has its own framing even when the describe reports a
 * zero data length (LONG / LONG RAW chunked, UROWID, a nested REF CURSOR). For
 * every other type a zero data length means "no bytes, always NULL". */
static bool has_own_row_encoding(uint8_t type)
{
  return type == ORA_TYPE_LONG || type == ORA_TYPE_LONGRAW || type == ORA_TYPE_UROWID ||
         type == ORA_TYPE_REFCURSOR;
}

typedef struct {
  char *name;
  uint8_t ora_type;
  uint16_t charset;
  uint8_t null_ok;
  uint32_t max_size; /* as the describe gives it: the define's size on 8i / 9i */
  /* The declared size for applications (#264): characters for a character
   * column, bytes for a RAW; and the largest value in bytes. */
  uint32_t char_size, byte_size;
  /* Described with a zero data length (a bare NULL / '' / DECODE miss): the
   * row carries no bytes at all for it - not even an empty DALC - and its
   * value is always NULL. Default false = read the value as usual. */
  bool zero_len;
  /* 23ai VECTOR column: declared dimension count (0 = flexible) and element
   * format (2 FLOAT32, 3 FLOAT64, 4 INT8, 5 BINARY; 0 = flexible). */
  uint32_t vector_dims;
  uint8_t vector_format;
  char *annotations; /* 23ai: "name=value\n..." serialized map, or NULL */
  /* The describe's precision and scale (#259): NUMBER(p,s)'s p and s (0 and
   * -127 for a NUMBER without them, -127 for a FLOAT); a TIMESTAMP's scale is
   * its fractional-second digits. */
  int precision;
  int scale;
  /* SQL OBJECT (ADT, type 109) columns: the object type's identity, and its
   * attribute layout (Oracle type per attribute) once resolved/cached. */
  char *type_schema;
  char *type_name;
  uint8_t *toid; /* 9i: the type OID from the describe, for the define (#168) */
  size_t toidlen;
  uint32_t type_version; /* 9i: the describe's type version, echoed in the define */
  uint8_t *obj_attr_types;
  uint8_t *obj_attr_elem;  /* parallel: per attr, collection element type or 0 */
  int n_obj_attrs;         /* -1 = layout not yet fetched, 0 = fetched/empty */
  bool is_collection;      /* VARRAY / nested table (single element type)    */
  uint8_t element_type;    /* collection element's Oracle wire type          */
  uint8_t *elem_obj_types; /* collection-of-objects: the element's attr layout */
  int n_elem_obj_attrs;    /* >0 when the element type is itself an object    */
  /* A CLOB / BLOB column the cursor has a define for (§14.5d): its content
   * comes inline in the row as LONG / LONG RAW, not as a locator. */
  bool inline_long;
} SeerColumn;

/* Free a column array (names + annotation strings + ADT metadata). Safe on a
 * calloc'd, partially-filled array (unset entries hold NULL). */
static void free_columns(SeerColumn *cols, int n)
{
  if (cols == NULL)
    return;
  for (int i = 0; i < n; i++) {
    free(cols[i].name);
    free(cols[i].annotations);
    free(cols[i].type_schema);
    free(cols[i].type_name);
    free(cols[i].toid);
    free(cols[i].obj_attr_types);
    free(cols[i].obj_attr_elem);
    free(cols[i].elem_obj_types);
  }
  free(cols);
}

/* One decoded value. `data` is NUL-terminated for text convenience but `len`
 * is authoritative (binary values contain embedded zeros). NULL data is a SQL
 * NULL. */
typedef struct {
  char *data;
  size_t len;
  bool binary;  /* BLOB / RAW / LONG RAW */
  bool shifted; /* a LOCAL TIME ZONE value already in the session's zone (#358) */
} SeerCell;

/* A bind: the OAC descriptor parameters plus the encoded RXD value. oac_type 0
 * marks an unbound position (sent as a NULL VARCHAR). For an OUT bind, `out`
 * holds the value the server returned in the IOV. */
typedef struct {
  uint8_t oac_type;     /* Oracle type for the OAC (2 NUMBER, 1 VARCHAR, ...) */
  uint32_t oac_size;    /* declared max length (widest value across iters) */
  uint32_t oac_charset; /* 873 for char, 0 otherwise */
  uint8_t oac_flag;     /* 16 for char/raw, 0 otherwise */
  bool is_out;          /* OUT / IN OUT parameter */
  bool type_from_null;  /* the OAC type came from a NULL value (a placeholder) */
  bool out_only;        /* bound by seer_stmt_bind_out: OUT, no value to send   */
  uint8_t **rxd;        /* per-iteration encoded RXD values, [n_iters] */
  size_t *rxd_len;
  SeerCell out;         /* OUT value captured from the IOV response */
  int64_t out_full_len; /* RETURNING value the server truncated: its real length, else 0 */
  uint8_t ret_lob;      /* RETURNING target declared as this LOB type (CLOB/BLOB), else 0 */
  uint8_t fv2_lob;      /* 9i: bound for this execute as a temporary LOB of this type (#169) */
  bool as_lob;          /* seer_stmt_bind_clob / _blob: meant for a LOB target (#424) */
  uint8_t lob_out;      /* bound OUT as a CLOB / BLOB (seer_stmt_bind_out), else 0 (#214) */
  uint8_t *ret_locator; /* its returned locator, resolved after the response */
  size_t ret_loclen;
  bool is_array;     /* PL/SQL associative-array (index-by table) bind  */
  SeerCell *out_arr; /* OUT assoc-array elements captured from the IOV   */
  int out_arr_n;
  uint8_t *oac_override; /* pre-built OAC bytes (SQL OBJECT bind); else emit_oac */
  size_t oac_override_len;
  bool temp_lob;         /* a text / raw value promoted to a temporary LOB (bind_temp_lob) */
  uint8_t *temp_locator; /* that temporary LOB, freed when the bind is replaced */
  size_t temp_loclen;
  /* Object / collection bind: its type (identity, and the layout once resolved)
   * for decoding a returned value, and the image an OUT value brought back,
   * decoded into `out` once the response is in. */
  SeerColumn *obj_type;
  uint8_t *out_image;
  size_t out_imagelen;
} SeerBind;

/* A LOB cell whose locator was captured during parse and whose content is
 * fetched (via TTI_LOBOPS) after the whole result set is in. */
typedef struct {
  size_t row;
  int col;
  uint8_t ora_type; /* CLOB / BLOB */
  uint8_t *locator;
  size_t loclen;
} SeerPendingLob;

/* A SQL OBJECT (ADT) cell whose image was captured during parse and decoded
 * after the result set is in (the attribute layout needs a dictionary query). */
typedef struct {
  size_t row;
  int col;
  uint8_t *image;
  size_t imagelen;
} SeerPendingObj;

/* One per-row failure from an array-DML execute in batch-errors mode (§6.7):
 * iteration `row` failed with ORA-`code`, text `message`. */
typedef struct {
  uint32_t row;  /* 0-based iteration offset that failed */
  uint32_t code; /* ORA error number                    */
  char *message; /* "ORA-NNNNN: ..." (owned), may be NULL */
} SeerBatchError;

/* One implicit result set (DBMS_SQL.RETURN_RESULT): the server cursor's id and
 * its column describe, captured from a TTI_IRD token and drained on demand. */
typedef struct {
  SeerColumn *cols;
  int ncols;
  int cursor_id;
} SeerImplicitResult;

struct SeerStmt {
  SeerConn *conn;
  char *sql;
  SeerBind *pbinds; /* input parameter binds, 0-based by position */
  int npbinds;
  int n_iters;       /* array-bind iteration count (default 1) */
  int cur_iter;      /* iteration the bind functions target */
  uint32_t prefetch; /* execute prefetch row count (0 = PREFETCH_ROWS);
                      * a pipelined op sets it high to pull rows inline */
  SeerColumn *cols;
  int ncols;
  SeerCell **rows; /* rows[r] is a SeerCell array of ncols */
  size_t nrows;
  size_t rows_cap;
  SeerPendingLob *plobs; /* LOB cells awaiting content */
  size_t nplobs;
  size_t plobs_cap;
  /* Cells whose content the server refused to give - a BFILE whose file
   * can't be opened - and its error, which reading the cell returns (#158). */
  struct {
    size_t row;
    int col;
    char *message;
  } *cell_errs;
  size_t ncell_errs;
  SeerPendingObj *pobjs; /* ADT cells awaiting layout + decode */
  size_t npobjs;
  size_t pobjs_cap;
  long cur;      /* current row index, -1 before the first fetch */
  long affected; /* DML affected-row count (from the OER) */
  int cursor_id;
  int reuse_cursor;     /* cached server cursor to re-execute without a re-parse */
  char *reuse_binds;    /* the bind types reuse_cursor was parsed with (bind_signature) */
  bool describe_only;   /* build_exec: a parse + describe, no execute (seer_stmt_describe) */
  bool described_only;  /* cols came from seer_stmt_describe; the execute re-describes */
  bool compile_warning; /* the last execute created an object that compiled with errors */
  bool executed;
  bool batch_errors;     /* arm batcherrors for array DML (continue on row error) */
  SeerBatchError *berrs; /* per-row failures captured from the OER */
  size_t nberrs;
  /* The current cursor is one the statement holds no SQL for (a REF CURSOR,
   * an implicit result): its rows are fetched with a fetch-only OALL8. */
  bool fetch_by_oall8;
  /* 9i: the nested cursors a fetch batch's CURSOR() cells opened, freed
   * before the next batch. */
  uint32_t *fv2_nested;
  size_t fv2_nnested, fv2_nested_cap;
  /* The columns are a drained REF CURSOR's, not this statement's own: the
   * statement cache keeps the block without them (#198). */
  bool cols_adopted;
  /* seer_stmt_set_max_rows: rows past it are neither kept nor fetched (#221). */
  size_t max_rows;
  /* A REF CURSOR captured from a PL/SQL OUT bind (drained into cols/rows). */
  bool refcursor_present;
  int refcursor_id;
  SeerColumn *refcursor_cols;
  int refcursor_ncols;
  /* Implicit result sets (DBMS_SQL.RETURN_RESULT, 12c+): each is a server
   * cursor captured from a TTI_IRD token, drained on demand by next_result. */
  SeerImplicitResult *implicit;
  size_t nimplicit;
  size_t implicit_pos; /* next implicit result to surface */
  /* Array-DML per-iteration row counts (12c+): armed before an array execute,
   * captured from the response RPA piggyback. */
  bool want_dml_rowcounts;
  uint32_t *dml_rowcounts;
  size_t n_dml_rowcounts;
  /* DML RETURNING ... INTO: set when the statement is a DML with OUT binds;
   * those binds are server-filled and their values arrive in a return RXD. */
  bool returning;
  /* 8i: a LOB OUT bind keeps its locator rather than being read (#424). */
  bool keep_lob_locators;
};

/* The OER outcome of one response. */
typedef struct {
  int64_t call_status;
  int64_t err_code;
  int64_t cursor_id;
  int64_t row_count;  /* "current row number" - DML affected rows on 11g */
  bool flush_binds;   /* the server asked for a TTI_FOB echo (see seer_ttc_recv) */
  uint8_t warn_flags; /* 0x20: a PL/SQL object was created with compilation errors */
  int64_t err_offset; /* the error's parse offset into the SQL text */
} OerResult;

/* ----------------------------------------------------------- value decode */

static char *hex_dup(const uint8_t *in, size_t n)
{
  static const char d[] = "0123456789abcdef";
  char *s = malloc(2 * n + 1);
  if (s == NULL)
    return NULL;
  for (size_t i = 0; i < n; i++) {
    s[2 * i] = d[in[i] >> 4];
    s[2 * i + 1] = d[in[i] & 0x0F];
  }
  s[2 * n] = '\0';
  return s;
}

/* Store raw bytes into a cell (NUL-terminated for convenience). */
static SeerStatus cell_set_bytes(SeerCell *c, const void *b, size_t n, bool binary)
{
  char *p = malloc(n + 1);
  if (p == NULL)
    return SEER_ENOMEM;
  if (n > 0)
    memcpy(p, b, n);
  p[n] = '\0';
  c->data = p;
  c->len = n;
  c->binary = binary;
  return SEER_OK;
}

/* Store an owned NUL-terminated string into a cell (text). */
static void cell_set_text(SeerCell *c, char *owned)
{
  c->data = owned;
  c->len = owned ? strlen(owned) : 0;
  c->binary = false;
}

/* Decode one column value from the row stream into `cell` (already zeroed; a
 * SQL NULL leaves it zeroed). Scalar DALC-framed types only - CLOB/BLOB and
 * LONG/LONG RAW are handled in parse_rxd. */
/* LONG (type 8) / LONG RAW (type 24): a marker (0x00 NULL, 0xFE chunked, else a
 * ub1 length) then content, followed by two trailing ub4 indicators (§11.10). */
static SeerStatus decode_long(SeerReader *r, bool is_raw, SeerCell *cell)
{
  /* SEER_LONG_CELL_SCHEMA (#398): the value, then the two trailing
   * indicators; a 00 is NULL, a 0xFE run with no chunks an empty value. */
  SeerSchemaCtx cx = {.codec = SEER_CODEC_THIN,
                      .fv = TTC_FIELD_VERSION_10_2, /* 10g+ only */
                      .wide_chunks = r->sb4_chunks};
  SeerCellMsg m = {0};
  if (!seer_schema_decode(SEER_LONG_CELL_SCHEMA, &cx, r, &m)) {
    seer_schema_free(SEER_LONG_CELL_SCHEMA, &m);
    return SEER_EPROTO;
  }
  SeerStatus st = m.value.p == NULL ? SEER_OK : cell_set_bytes(cell, m.value.p, m.value.n, is_raw);
  seer_schema_free(SEER_LONG_CELL_SCHEMA, &m);
  return st;
}

/* Oracle's printable-ROWID base64 alphabet (not RFC 4648). */
static const char ROWID_ALPHABET[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* Big-endian base64 of `v` across exactly `nchars` digits, into `out`. */
static void rowid_b64(uint32_t v, int nchars, char *out)
{
  for (int i = 0; i < nchars; i++)
    out[i] = ROWID_ALPHABET[(v >> (6 * (nchars - 1 - i))) & 0x3F];
}

/* ROWID (type 11) in RXD (§11): a 1-byte present indicator (0 / 0xFF = NULL),
 * then the physical rowid - data object (ub4), relative file (ub4), an unused
 * ub4, block (ub4), slot (ub4) - rendered as the 18-char extended ROWID
 * "OOOOOOFFFBBBBBBRRR". */
static SeerStatus decode_rowid(SeerReader *r, SeerCell *cell)
{
  /* SEER_ROWID_CELL_SCHEMA (#398): a size (0 or 0xFF NULL), then the object,
   * file, block and slot, rendered as the 18-character rowid. */
  SeerSchemaCtx cx = {.codec = SEER_CODEC_THIN,
                      .fv = TTC_FIELD_VERSION_10_2, /* 10g+ only */
                      .wide_chunks = r->sb4_chunks};
  SeerCellMsg m = {0};
  if (!seer_schema_decode(SEER_ROWID_CELL_SCHEMA, &cx, r, &m))
    return SEER_EPROTO;
  if (m.rowid_size == 0)
    return SEER_OK; /* SQL NULL */
  char rid[18];
  rowid_b64((uint32_t)m.rowid_obj, 6, rid);
  rowid_b64((uint32_t)m.rowid_file, 3, rid + 6);
  rowid_b64((uint32_t)m.rowid_block, 6, rid + 9);
  rowid_b64((uint32_t)m.rowid_slot, 3, rid + 15);
  return cell_set_bytes(cell, rid, sizeof rid, false);
}

/* Standard-alphabet base64 (no padding) of `n` bytes, into the writer. */
static void b64_encode(SeerWriter *w, const uint8_t *p, size_t n)
{
  static const char A[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  size_t i = 0;
  for (; i + 3 <= n; i += 3) {
    uint32_t v = (uint32_t)p[i] << 16 | (uint32_t)p[i + 1] << 8 | p[i + 2];
    seer_writer_u8(w, A[(v >> 18) & 0x3F]);
    seer_writer_u8(w, A[(v >> 12) & 0x3F]);
    seer_writer_u8(w, A[(v >> 6) & 0x3F]);
    seer_writer_u8(w, A[v & 0x3F]);
  }
  if (n - i == 1) {
    uint32_t v = (uint32_t)p[i] << 16;
    seer_writer_u8(w, A[(v >> 18) & 0x3F]);
    seer_writer_u8(w, A[(v >> 12) & 0x3F]);
  } else if (n - i == 2) {
    uint32_t v = (uint32_t)p[i] << 16 | (uint32_t)p[i + 1] << 8;
    seer_writer_u8(w, A[(v >> 18) & 0x3F]);
    seer_writer_u8(w, A[(v >> 12) & 0x3F]);
    seer_writer_u8(w, A[(v >> 6) & 0x3F]);
  }
}

/* UROWID (type 208, logical/universal rowid, e.g. an index-organized table):
 * same RXD framing as a LOB column - ub4 num_bytes, a 1-byte length echo, then
 * num_bytes rowid bytes (a leading type tag + body). Rendered "*" + base64 of
 * the body (the leading tag byte dropped). */
/* A UROWID's bytes (a leading type tag, then the body) as its text. Tag 01: a
 * physical rowid held in a UROWID - object ub4, file ub2, block ub4, slot
 * ub2 (big-endian) - rendered as the 18-char ROWID it is, so it matches
 * ROWIDTOCHAR() and works in WHERE ROWID = ?. Tag 02 (logical, an IOT row)
 * keeps the '*'-prefixed base64 form. 8i sends the same bytes (#136). */
static SeerStatus urowid_cell(const uint8_t *p, size_t nbytes, SeerCell *cell)
{
  if (nbytes == 0)
    return SEER_OK;
  if (p[0] == 0x01 && nbytes == 13) {
    uint32_t obj = (uint32_t)p[1] << 24 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 8 | p[4];
    uint32_t file = (uint32_t)p[5] << 8 | p[6];
    uint32_t blk = (uint32_t)p[7] << 24 | (uint32_t)p[8] << 16 | (uint32_t)p[9] << 8 | p[10];
    uint32_t slot = (uint32_t)p[11] << 8 | p[12];
    char rid[18];
    rowid_b64(obj, 6, rid);
    rowid_b64(file, 3, rid + 6);
    rowid_b64(blk, 6, rid + 9);
    rowid_b64(slot, 3, rid + 15);
    return cell_set_bytes(cell, rid, sizeof rid, false);
  }
  SeerWriter w;
  if (!seer_writer_init(&w, nbytes * 2))
    return SEER_ENOMEM;
  seer_writer_u8(&w, '*');
  if (nbytes > 1)
    b64_encode(&w, p + 1, nbytes - 1); /* drop the leading tag */
  SeerStatus st = seer_writer_ok(&w) ? cell_set_bytes(cell, w.buf, w.len, false) : SEER_ENOMEM;
  seer_writer_free(&w);
  return st;
}

static SeerStatus decode_urowid(SeerReader *r, SeerCell *cell)
{
  /* SEER_UROWID_CELL_SCHEMA (#398): a count (0 NULL), then the rowid as a
   * value - chunked past 252 bytes, as an index-organized table's logical
   * rowid can be (#144). */
  SeerSchemaCtx cx = {.codec = SEER_CODEC_THIN,
                      .fv = TTC_FIELD_VERSION_10_2, /* 10g+ only */
                      .wide_chunks = r->sb4_chunks};
  SeerCellMsg m = {0};
  if (!seer_schema_decode(SEER_UROWID_CELL_SCHEMA, &cx, r, &m)) {
    seer_schema_free(SEER_UROWID_CELL_SCHEMA, &m);
    return SEER_EPROTO;
  }
  SeerStatus st = m.value.p == NULL ? SEER_OK : urowid_cell(m.value.p, m.value.n, cell);
  seer_schema_free(SEER_UROWID_CELL_SCHEMA, &m);
  return st;
}

/* VECTOR binary image format (PROTOCOL.md §18). */
#define VEC_MAGIC 0xDB
#define VEC_TYPE_FLOAT32 2
#define VEC_TYPE_FLOAT64 3
#define VEC_TYPE_INT8 4
#define VEC_TYPE_BINARY 5
#define VEC_FLAG_NORM 0x10   /* an 8-byte cached magnitude follows the header */
#define VEC_FLAG_SPARSE 0x20 /* sparse: ub2 count + ub4 indices + values      */

/* Decode a 23ai VECTOR image (fetched as a LOB) to the text literal
 * "[e1, e2, ...]". Header: magic, version, ub2 flags, ub1 element type, ub4
 * dimension count, an optional 8-byte magnitude (NORM flag), then the elements.
 * FLOAT32/64 elements use the same order-preserving IEEE form as BINARY_FLOAT/
 * DOUBLE. A sparse image renders "[dims, [indices], [values]]". */
static SeerStatus decode_vector_image(const uint8_t *img, size_t len, SeerCell *cell)
{
  if (len < 9 || img[0] != VEC_MAGIC)
    return SEER_EPROTO;
  uint16_t flags = (uint16_t)((uint16_t)img[2] << 8 | img[3]);
  uint8_t etype = img[4];
  uint32_t ndim = (uint32_t)img[5] << 24 | (uint32_t)img[6] << 16 | (uint32_t)img[7] << 8 | img[8];
  size_t pos = 9;
  if (flags & VEC_FLAG_NORM) /* skip the cached magnitude */
    pos += 8;
  bool sparse = (flags & VEC_FLAG_SPARSE) != 0;

  SeerWriter w;
  if (!seer_writer_init(&w, 64))
    return SEER_ENOMEM;

/* Append one numeric element at `*p`, advancing it; bail on short input. */
#define VEC_ELEM(P)                                                                                \
  do {                                                                                             \
    char tmp[40];                                                                                  \
    if (etype == VEC_TYPE_FLOAT32) {                                                               \
      if ((P) + 4 > len)                                                                           \
        goto bad;                                                                                  \
      seer_decode_bfloat(img + (P), 4, tmp, sizeof tmp);                                           \
      (P) += 4;                                                                                    \
    } else if (etype == VEC_TYPE_FLOAT64) {                                                        \
      if ((P) + 8 > len)                                                                           \
        goto bad;                                                                                  \
      seer_decode_bdouble(img + (P), 8, tmp, sizeof tmp);                                          \
      (P) += 8;                                                                                    \
    } else if (etype == VEC_TYPE_INT8) {                                                           \
      if ((P) + 1 > len)                                                                           \
        goto bad;                                                                                  \
      snprintf(tmp, sizeof tmp, "%d", (int)(int8_t)img[(P)]);                                      \
      (P) += 1;                                                                                    \
    } else {                                                                                       \
      goto bad;                                                                                    \
    }                                                                                              \
    seer_writer_bytes(&w, tmp, strlen(tmp));                                                       \
  } while (0)

  if (sparse) {
    if (pos + 2 > len)
      goto bad;
    uint16_t nnz = (uint16_t)((uint16_t)img[pos] << 8 | img[pos + 1]);
    pos += 2;
    char hdr[32];
    snprintf(hdr, sizeof hdr, "[%u, [", ndim);
    seer_writer_bytes(&w, hdr, strlen(hdr));
    size_t ipos = pos; /* indices: nnz × ub4 */
    for (uint16_t i = 0; i < nnz; i++) {
      if (ipos + 4 > len)
        goto bad;
      uint32_t idx = (uint32_t)img[ipos] << 24 | (uint32_t)img[ipos + 1] << 16 |
                     (uint32_t)img[ipos + 2] << 8 | img[ipos + 3];
      ipos += 4;
      char b[16];
      snprintf(b, sizeof b, "%s%u", i ? ", " : "", idx);
      seer_writer_bytes(&w, b, strlen(b));
    }
    seer_writer_bytes(&w, "], [", 4);
    size_t vpos = ipos; /* values: nnz elements */
    for (uint16_t i = 0; i < nnz; i++) {
      if (i)
        seer_writer_bytes(&w, ", ", 2);
      VEC_ELEM(vpos);
    }
    seer_writer_bytes(&w, "]]", 2);
  } else if (etype == VEC_TYPE_BINARY) { /* packed bits, byte list */
    seer_writer_u8(&w, '[');
    size_t nbytes = (ndim + 7) / 8;
    for (size_t i = 0; i < nbytes; i++) {
      if (pos + i >= len)
        goto bad;
      char b[8];
      snprintf(b, sizeof b, "%s%u", i ? ", " : "", img[pos + i]);
      seer_writer_bytes(&w, b, strlen(b));
    }
    seer_writer_u8(&w, ']');
  } else { /* dense FLOAT32/64/INT8 */
    seer_writer_u8(&w, '[');
    for (uint32_t i = 0; i < ndim; i++) {
      if (i)
        seer_writer_bytes(&w, ", ", 2);
      VEC_ELEM(pos);
    }
    seer_writer_u8(&w, ']');
  }
#undef VEC_ELEM

  if (!seer_writer_ok(&w)) {
    seer_writer_free(&w);
    return SEER_ENOMEM;
  }
  SeerStatus st = cell_set_bytes(cell, w.buf, w.len, false);
  seer_writer_free(&w);
  return st;
bad:
  seer_writer_free(&w);
  return SEER_EPROTO;
}

/* Decode already-extracted value bytes (a DALC blob) per Oracle type into a
 * cell. Empty input is a SQL NULL (leaves the cell zeroed). Shared by column
 * decode and PL/SQL OUT-parameter capture. */
static SeerStatus decode_scalar(uint8_t ora_type, const uint8_t *val, size_t vlen, SeerCell *cell)
{
  if (val == NULL || vlen == 0)
    return SEER_OK; /* SQL NULL */

  char buf[192];
  SeerStatus st = SEER_OK;
  switch (ora_type) {
  case ORA_TYPE_NUMBER:
    st = seer_decode_number(val, vlen, buf, sizeof buf);
    if (st == SEER_OK)
      cell_set_text(cell, strdup(buf));
    break;
  case ORA_TYPE_DATE:
  case ORA_TYPE_TIMESTAMP:
  case ORA_TYPE_TIMESTAMPTZ:
  case ORA_TYPE_TIMESTAMPLTZ:
    st = ora_type == ORA_TYPE_TIMESTAMPTZ ? seer_decode_tstz(val, vlen, buf, sizeof buf)
                                          : seer_decode_date(val, vlen, buf, sizeof buf);
    if (st == SEER_OK)
      cell_set_text(cell, strdup(buf));
    break;
  case ORA_TYPE_BFLOAT:
    st = seer_decode_bfloat(val, vlen, buf, sizeof buf);
    if (st == SEER_OK)
      cell_set_text(cell, strdup(buf));
    break;
  case ORA_TYPE_BDOUBLE:
    st = seer_decode_bdouble(val, vlen, buf, sizeof buf);
    if (st == SEER_OK)
      cell_set_text(cell, strdup(buf));
    break;
  case ORA_TYPE_VARCHAR:
  case ORA_TYPE_CHAR:
    st = cell_set_bytes(cell, val, vlen, false); /* AL32UTF8 text */
    break;
  case ORA_TYPE_RAW:
    st = cell_set_bytes(cell, val, vlen, true); /* binary */
    break;
  case ORA_TYPE_REF:
    st = cell_set_bytes(cell, val, vlen, true); /* opaque locator -> hex */
    break;
  case ORA_TYPE_INTERVAL_YM:
    st = seer_decode_interval_ym(val, vlen, buf, sizeof buf);
    if (st == SEER_OK)
      cell_set_text(cell, strdup(buf));
    break;
  case ORA_TYPE_INTERVAL_DS:
    st = seer_decode_interval_ds(val, vlen, buf, sizeof buf);
    if (st == SEER_OK)
      cell_set_text(cell, strdup(buf));
    break;
  case ORA_TYPE_BOOLEAN: /* 23ai: last byte = truth */
    cell_set_text(cell, strdup(val[vlen - 1] ? "TRUE" : "FALSE"));
    break;
  default:
    cell_set_text(cell, hex_dup(val, vlen)); /* unknown: hex text */
    break;
  }
  if (st != SEER_OK)
    return st;
  return (cell->data != NULL) ? SEER_OK : SEER_ENOMEM;
}

/* A national char column (NVARCHAR2 / NCHAR) declares charset AL16UTF16: its
 * value is UTF-16BE on the wire. Convert the decoded cell to UTF-8 so it reads
 * as text, like every other character column. */
static void national_to_utf8(const SeerColumn *col, SeerCell *cell)
{
  if (col->charset != ORA_CHARSET_AL16UTF16 || cell->data == NULL || cell->len == 0 ||
      (col->ora_type != ORA_TYPE_VARCHAR && col->ora_type != ORA_TYPE_CHAR))
    return;
  char *u8 = NULL;
  size_t u8len = 0;
  if (seer_iconv("UTF-16BE", "UTF-8", cell->data, cell->len, &u8, &u8len) == 0) {
    free(cell->data);
    cell->data = u8;
    cell->len = u8len;
  }
}

static SeerStatus decode_cell(SeerReader *r, const SeerColumn *col, SeerCell *cell)
{
  switch (col->ora_type) {
  case ORA_TYPE_LONG: /* LONG (text)              */
    return decode_long(r, false, cell);
  case ORA_TYPE_LONGRAW: /* LONG RAW (binary)        */
    return decode_long(r, true, cell);
  case ORA_TYPE_RID:
  case ORA_TYPE_ROWID: /* ROWID                   */
    return decode_rowid(r, cell);
  case ORA_TYPE_UROWID: /* UROWID                   */
    return decode_urowid(r, cell);
  /* ORA_TYPE_JSON and ORA_TYPE_VECTOR are LOB-backed and intercepted in
   * parse_rxd's deferred-LOB branch (resolved via seer_decode_oson /
   * decode_vector_image), so they never reach here. */
  default:
    break;
  }

  /* SEER_CELL_SCHEMA (#395 spike): the value read in place. */
  SeerSchemaCtx cx = {.codec = SEER_CODEC_THIN,
                      .fv = TTC_FIELD_VERSION_10_2, /* 10g+ only */
                      .wide_chunks = r->sb4_chunks};
  SeerCellMsg m;
  if (!seer_schema_decode(SEER_CELL_SCHEMA, &cx, r, &m)) {
    seer_schema_free(SEER_CELL_SCHEMA, &m);
    return SEER_EPROTO;
  }
  SeerStatus st = decode_scalar(col->ora_type, m.value.p, m.value.n, cell);
  seer_schema_free(SEER_CELL_SCHEMA, &m);
  if (st == SEER_OK)
    national_to_utf8(col, cell);
  return st;
}

/* ------------------------------------------------------------- token parse */

/* Parse a describe body (max row size, column metadata, trailer) - shared by
 * the TTI_DCB token and the inline describe inside a REF CURSOR OUT value. The
 * caller consumes the preamble (chunked field for DCB, a length byte for a
 * REF CURSOR). On success returns the columns in *out_cols / *out_ncols.
 *
 * `fv` is the negotiated TTC field version: the per-column `uds flags` and the
 * trailer's `dcbqcky` (query-cache key) are 11g additions, absent on a 10g
 * (fv 4) describe, so reading them there would eat the next column / the first
 * row token and desync the whole decode. */
/* A decoded byte string as a NUL-terminated malloc'd string ("" when empty). */
static char *bytes_dup_str(const SeerBytes *b)
{
  char *s = malloc(b->n + 1);
  if (s == NULL)
    return NULL;
  if (b->n > 0)
    memcpy(s, b->p, b->n);
  s[b->n] = '\0';
  return s;
}

static SeerStatus parse_describe_body(SeerReader *r, int fv, SeerColumn **out_cols, int *out_ncols)
{
  SeerSchemaCtx cx = seer_msg_ctx(0, (uint8_t)fv, (uint8_t)fv);
  cx.wide_chunks = r->sb4_chunks;
  SeerDescribeHeadMsg hm = {0}; /* SEER_DESCRIBE_HEAD_SCHEMA (#398) */
  if (!seer_schema_decode(SEER_DESCRIBE_HEAD_SCHEMA, &cx, r, &hm) || hm.ncols < 0 ||
      hm.ncols > 4096)
    return SEER_EPROTO;
  int64_t ncols = hm.ncols;

  SeerColumn *cols = calloc((size_t)ncols, sizeof *cols);
  if (cols == NULL && ncols > 0)
    return SEER_ENOMEM;

  for (int64_t i = 0; i < ncols; i++) {
    /* SEER_DCB_COLUMN_SCHEMA (#398): the OAC's fields, nullable, the name and
     * the type's schema and name, the position, 11.2's UDS flags, 23.1's SQL
     * domain; a raw sb1 scale from 12.1. */
    SeerDcbColumnMsg dm = {0};
    if (!seer_schema_decode(SEER_DCB_COLUMN_SCHEMA, &cx, r, &dm)) {
      seer_schema_free(SEER_DCB_COLUMN_SCHEMA, &dm);
      goto fail;
    }
    uint8_t type = (uint8_t)dm.data_type;
    cols[i].precision = (uint8_t)dm.precision;
    cols[i].scale = fv >= TTC_FIELD_VERSION_12_1 ? (int8_t)dm.scale : (int)dm.scale;
    int64_t data_len = dm.max_length; /* buffer size (data length) */
    int64_t charset = dm.charset;
    int64_t max_size = dm.max_chars;
    uint8_t null_ok = (uint8_t)dm.null_ok;
    char *name = bytes_dup_str(&dm.name);
    if (name == NULL) {
      seer_schema_free(SEER_DCB_COLUMN_SCHEMA, &dm);
      goto fail;
    }
    if (type == ORA_TYPE_ADT && dm.type_schema.n > 0 && dm.type_name.n > 0) {
      cols[i].type_schema = bytes_dup_str(&dm.type_schema);
      cols[i].type_name = bytes_dup_str(&dm.type_name);
      cols[i].n_obj_attrs = -1; /* layout not yet fetched */
    }
    seer_schema_free(SEER_DCB_COLUMN_SCHEMA, &dm);
    if (fv > TTC_FIELD_VERSION_23_1) {
      /* 23ai (fv24): per-column annotation map + vector descriptor (#89),
       * SEER_DCB_ANNOTATIONS_HEAD_SCHEMA, the pairs and the tail (#398).
       * The map is serialized as "name=value\n..." (name-only annotations
       * get an empty value) into cols[i].annotations. Both fields must be
       * fully consumed or the row stream desyncs. */
      SeerDcbAnnotationsMsg am = {0};
      if (!seer_schema_decode(SEER_DCB_ANNOTATIONS_HEAD_SCHEMA, &cx, r, &am)) {
        free(name);
        goto fail;
      }
      if (am.count > 0) {
        if (am.count > 4096 || am.count2 > 4096) {
          free(name);
          goto fail;
        }
        SeerWriter ann;
        if (!seer_writer_init(&ann, 64)) {
          free(name);
          goto fail;
        }
        for (int64_t a = 0; a < am.count2 && seer_reader_ok(r); a++) {
          SeerAuthPairMsg pm = {0};
          bool ok = seer_schema_decode(SEER_AUTH_PAIR_SCHEMA, &cx, r, &pm);
          if (ok) {
            seer_writer_bytes(&ann, pm.key.p, pm.key.n);
            seer_writer_u8(&ann, '=');
            seer_writer_bytes(&ann, pm.value.p, pm.value.n);
            seer_writer_u8(&ann, '\n');
          }
          seer_schema_free(SEER_AUTH_PAIR_SCHEMA, &pm);
          if (!ok) {
            seer_writer_free(&ann);
            free(name);
            goto fail;
          }
        }
        (void)seer_schema_decode(SEER_DCB_ANNOTATIONS_TAIL_SCHEMA, &cx, r, &am);
        if (seer_writer_ok(&ann) && ann.len > 0) {
          char *s = malloc(ann.len + 1);
          if (s == NULL) {
            seer_writer_free(&ann);
            free(name);
            goto fail;
          }
          memcpy(s, ann.buf, ann.len);
          s[ann.len] = '\0';
          cols[i].annotations = s;
        }
        seer_writer_free(&ann);
      }
      SeerDcbColumnMsg vm = {0}; /* SEER_DCB_VECTOR_SCHEMA */
      (void)seer_schema_decode(SEER_DCB_VECTOR_SCHEMA, &cx, r, &vm);
      cols[i].vector_dims = (uint32_t)(vm.vector_dims < 0 ? 0 : vm.vector_dims);
      cols[i].vector_format = (uint8_t)vm.vector_format;
    }

    cols[i].name = name;
    cols[i].ora_type = type;
    cols[i].charset = (uint16_t)charset;
    cols[i].null_ok = null_ok;
    cols[i].max_size = (uint32_t)(max_size < 0 ? 0 : max_size);
    /* max_size is the character length, 0 for a column that isn't
     * character data: a RAW's length is its buffer size. */
    cols[i].byte_size = (uint32_t)(data_len < 0 ? 0 : data_len);
    cols[i].char_size = type == ORA_TYPE_RAW ? cols[i].byte_size : cols[i].max_size;
    cols[i].zero_len = data_len == 0 && !has_own_row_encoding(type);

    if (!seer_reader_ok(r)) {
      goto fail;
    }
    continue;
  fail:
    free_columns(cols, (int)ncols);
    return SEER_EPROTO;
  }

  SeerDcbTrailerMsg tm = {0}; /* SEER_DCB_TRAILER_SCHEMA */
  (void)seer_schema_decode(SEER_DCB_TRAILER_SCHEMA, &cx, r, &tm);
  seer_schema_free(SEER_DCB_TRAILER_SCHEMA, &tm);

  if (!seer_reader_ok(r)) {
    free_columns(cols, (int)ncols);
    return SEER_EPROTO;
  }

  *out_cols = cols;
  *out_ncols = (int)ncols;
  return SEER_OK;
}

static SeerStatus parse_dcb(SeerReader *r, SeerStmt *stmt)
{
  /* The describe-info preamble, a value: SEER_VALUE_SCHEMA (#398). */
  SeerSchemaCtx cx = seer_msg_ctx(0, stmt->conn->field_version, stmt->conn->server_field_version);
  cx.wide_chunks = r->sb4_chunks;
  SeerChrMsg pm = {0};
  (void)seer_schema_decode(SEER_VALUE_SCHEMA, &cx, r, &pm);
  seer_schema_free(SEER_VALUE_SCHEMA, &pm);
  SeerColumn *cols = NULL;
  int ncols = 0;
  SeerStatus st = parse_describe_body(r, stmt->conn->field_version, &cols, &ncols);
  if (st != SEER_OK)
    return st;
  stmt->cols = cols;
  stmt->ncols = ncols;
  return SEER_OK;
}

/* A cursor value: a length byte, an inline describe, and the nested cursor id.
 * A REF CURSOR OUT bind (§6.5) follows it with a per-value indicator; a nested
 * CURSOR(...) column in a row does not - there the next byte is the following
 * row's token, so reading an indicator would swallow it. */
static SeerStatus read_cursor_value(SeerReader *r, int fv, bool indicator, SeerColumn **out_cols,
                                    int *out_ncols, int64_t *out_id)
{
  /* SEER_CURSOR_VALUE_HEAD_SCHEMA, the describe, _TAIL_SCHEMA (#398). */
  SeerSchemaCtx cx = seer_msg_ctx(0, (uint8_t)fv, (uint8_t)fv);
  SeerCursorValueMsg m = {.has_indicator = indicator};
  (void)seer_schema_decode(SEER_CURSOR_VALUE_HEAD_SCHEMA, &cx, r, &m);
  SeerColumn *cols = NULL;
  int ncols = 0;
  SeerStatus st = parse_describe_body(r, fv, &cols, &ncols);
  if (st != SEER_OK)
    return st;
  (void)seer_schema_decode(SEER_CURSOR_VALUE_TAIL_SCHEMA, &cx, r, &m);
  int64_t cursor_id = m.cursor_id; /* nested cursor id */
  if (!seer_reader_ok(r)) {
    free_columns(cols, ncols);
    return SEER_EPROTO;
  }
  *out_cols = cols;
  *out_ncols = ncols;
  *out_id = cursor_id;
  return SEER_OK;
}

/* A REF CURSOR OUT value: stash the describe + cursor id; the cursor is drained
 * into the statement result set after execute. */
static SeerStatus parse_refcursor_out(SeerReader *r, SeerStmt *stmt)
{
  SeerColumn *cols = NULL;
  int ncols = 0;
  int64_t cursor_id = 0;
  SeerStatus st = read_cursor_value(r, stmt->conn->field_version, true, &cols, &ncols, &cursor_id);
  if (st != SEER_OK)
    return st;
  if (stmt->refcursor_cols != NULL)
    free_columns(stmt->refcursor_cols, stmt->refcursor_ncols);
  stmt->refcursor_cols = cols;
  stmt->refcursor_ncols = ncols;
  stmt->refcursor_id = (int)cursor_id;
  stmt->refcursor_present = true;
  return SEER_OK;
}

/* Implicit result sets (TTI_IRD, DBMS_SQL.RETURN_RESULT, 12c+): a ub4 result
 * count, then per result a ub1-prefixed preamble, the column describe body, and
 * a ub2 cursor id. Each is stashed as a server cursor drained on demand by
 * seer_stmt_next_result. */
static SeerStatus parse_implicit(SeerReader *r, SeerStmt *stmt)
{
  /* SEER_IMPLICIT_COUNT_SCHEMA, then each result's _HEAD_SCHEMA, describe
   * and _TAIL_SCHEMA (#398). */
  SeerSchemaCtx cx = seer_msg_ctx(0, stmt->conn->field_version, stmt->conn->server_field_version);
  SeerImplicitMsg m = {0};
  if (!seer_schema_decode(SEER_IMPLICIT_COUNT_SCHEMA, &cx, r, &m) || m.nres < 0 || m.nres > 4096)
    return SEER_EPROTO;
  for (int64_t i = 0; i < m.nres; i++) {
    (void)seer_schema_decode(SEER_IMPLICIT_HEAD_SCHEMA, &cx, r, &m);
    SeerColumn *cols = NULL;
    int ncols = 0;
    SeerStatus st = parse_describe_body(r, stmt->conn->field_version, &cols, &ncols);
    if (st != SEER_OK)
      return st;
    (void)seer_schema_decode(SEER_IMPLICIT_TAIL_SCHEMA, &cx, r, &m);
    int64_t cursor_id = m.cursor_id;
    if (!seer_reader_ok(r)) {
      free_columns(cols, ncols);
      return SEER_EPROTO;
    }
    SeerImplicitResult *np = realloc(stmt->implicit, (stmt->nimplicit + 1) * sizeof *np);
    if (np == NULL) {
      free_columns(cols, ncols);
      return SEER_ENOMEM;
    }
    stmt->implicit = np;
    stmt->implicit[stmt->nimplicit++] = (SeerImplicitResult){cols, ncols, (int)cursor_id};
    seer_log(SEER_LOG_DEBUG, "stmt: implicit result %zu: cursor %d (%d cols)", stmt->nimplicit,
             (int)cursor_id, ncols);
  }
  return SEER_OK;
}

/* The row header. Its column bit vector, when it carries one, says which
 * columns the batch's FIRST row sends - as a TTI_BVC does for the row after
 * it: a fetch that resumes a result can start on a row repeating a value of
 * the previous batch's last row, and that column is then not sent. Ignoring
 * the vector read the next column's bytes in its place (seerdb tns.py's RXH
 * handling; python-oracledb _process_row_header). */
static SeerStatus parse_rxh(SeerReader *r, int fv, uint8_t **bv, size_t *bvlen)
{
  /* SEER_RXH_SCHEMA (#398); the bit vector is kept for the rows after it. */
  SeerSchemaCtx cx = seer_msg_ctx(0, (uint8_t)fv, (uint8_t)fv);
  cx.wide_chunks = r->sb4_chunks;
  SeerRxhMsg m = {0};
  if (!seer_schema_decode(SEER_RXH_SCHEMA, &cx, r, &m)) {
    seer_schema_free(SEER_RXH_SCHEMA, &m);
    return SEER_EPROTO;
  }
  if (m.bit_vector.n > 0) {
    uint8_t *copy = malloc(m.bit_vector.n);
    if (copy == NULL) {
      seer_schema_free(SEER_RXH_SCHEMA, &m);
      return SEER_ENOMEM;
    }
    memcpy(copy, m.bit_vector.p, m.bit_vector.n);
    free(*bv);
    *bv = copy;
    *bvlen = m.bit_vector.n;
  }
  seer_schema_free(SEER_RXH_SCHEMA, &m);
  return SEER_OK;
}

static SeerStatus parse_bvc(SeerReader *r, int ncols, uint8_t **bv, size_t *bvlen)
{
  free(*bv);
  *bv = NULL;
  *bvlen = 0;
  /* SEER_BVC_SCHEMA (#398): the count sent, then a bit per column */
  size_t veclen = (size_t)((ncols + 7) / 8);
  SeerSchemaCtx cx = {.codec = SEER_CODEC_THIN, .fv = TTC_FIELD_VERSION_10_2}; /* 10g+ only */
  SeerBvcMsg m = {.bits_len = (int64_t)veclen};
  if (!seer_schema_decode(SEER_BVC_SCHEMA, &cx, r, &m))
    return SEER_EPROTO;
  const uint8_t *p = m.bits.p;
  uint8_t *copy = malloc(veclen ? veclen : 1);
  if (copy == NULL)
    return SEER_ENOMEM;
  memcpy(copy, p, veclen);
  *bv = copy;
  *bvlen = veclen;
  return SEER_OK;
}

static bool bvc_bit_set(const uint8_t *bv, size_t bvlen, int idx)
{
  size_t byte = (size_t)idx / 8;
  if (byte >= bvlen)
    return false;
  return (bv[byte] & (1u << (idx % 8))) != 0;
}

/* Whether the statement holds as many rows as seer_stmt_set_max_rows allows. */
static bool rows_full(const SeerStmt *stmt)
{
  return stmt->max_rows > 0 && stmt->nrows >= stmt->max_rows;
}

static SeerStatus append_row(SeerStmt *stmt, SeerCell *row)
{
  if (rows_full(stmt)) {
    /* Past the limit (#221): the row goes, and the LOB and object reads its
     * cells queued, which name its index, go with it. */
    for (int k = 0; k < stmt->ncols; k++)
      free(row[k].data);
    free(row);
    size_t kept = 0;
    for (size_t k = 0; k < stmt->nplobs; k++) {
      if (stmt->plobs[k].row >= stmt->nrows)
        free(stmt->plobs[k].locator);
      else
        stmt->plobs[kept++] = stmt->plobs[k];
    }
    stmt->nplobs = kept;
    kept = 0;
    for (size_t k = 0; k < stmt->npobjs; k++) {
      if (stmt->pobjs[k].row >= stmt->nrows)
        free(stmt->pobjs[k].image);
      else
        stmt->pobjs[kept++] = stmt->pobjs[k];
    }
    stmt->npobjs = kept;
    return SEER_OK;
  }
  if (stmt->nrows == stmt->rows_cap) {
    size_t cap = stmt->rows_cap ? stmt->rows_cap * 2 : 16;
    SeerCell **nr = realloc(stmt->rows, cap * sizeof *nr);
    if (nr == NULL)
      return SEER_ENOMEM;
    stmt->rows = nr;
    stmt->rows_cap = cap;
  }
  stmt->rows[stmt->nrows++] = row;
  return SEER_OK;
}

/* Read a LOB column's locator from the row stream (§11.9): a 0x00 marks a NULL
 * LOB, otherwise a ub4 size then the locator as a DALC. */
static SeerStatus read_lob_locator(SeerReader *r, uint8_t **loc, size_t *loclen)
{
  /* SEER_LOB_CELL_SCHEMA (#398): the locator's length (0 NULL) and the
   * locator as a value. */
  *loc = NULL;
  *loclen = 0;
  SeerSchemaCtx cx = {.codec = SEER_CODEC_THIN,
                      .fv = TTC_FIELD_VERSION_10_2, /* 10g+ only */
                      .wide_chunks = r->sb4_chunks};
  SeerCellMsg m = {0};
  if (!seer_schema_decode(SEER_LOB_CELL_SCHEMA, &cx, r, &m)) {
    seer_schema_free(SEER_LOB_CELL_SCHEMA, &m);
    return SEER_EPROTO;
  }
  SeerStatus st = SEER_OK;
  if (m.value.n > 0) {
    *loc = malloc(m.value.n);
    if (*loc == NULL)
      st = SEER_ENOMEM;
    else {
      memcpy(*loc, m.value.p, m.value.n);
      *loclen = m.value.n;
    }
  }
  seer_schema_free(SEER_LOB_CELL_SCHEMA, &m);
  return st;
}

/* Record a LOB cell to resolve after the result set is fully fetched. Takes
 * ownership of `loc`. */
static SeerStatus record_pending_lob(SeerStmt *stmt, size_t row, int col, uint8_t ora_type,
                                     uint8_t *loc, size_t loclen)
{
  if (stmt->nplobs == stmt->plobs_cap) {
    size_t cap = stmt->plobs_cap ? stmt->plobs_cap * 2 : 8;
    SeerPendingLob *np = realloc(stmt->plobs, cap * sizeof *np);
    if (np == NULL)
      return SEER_ENOMEM;
    stmt->plobs = np;
    stmt->plobs_cap = cap;
  }
  stmt->plobs[stmt->nplobs++] = (SeerPendingLob){row, col, ora_type, loc, loclen};
  return SEER_OK;
}

/* Read a SQL OBJECT (ADT, type 109) value from the RXD. The wire framing
 * (python-oracledb read_dbobject): type OID, object OID, snapshot - each a
 * ub4 length then, if non-zero, a chunked value - a version (ub2), an image
 * length (ub4; 0 => NULL value), flags (ub2), then the packed image as a chunked
 * byte string. On a non-NULL value *img is a malloc'd image (caller owns). */
static SeerStatus read_object_image(SeerReader *r, uint8_t **img, size_t *imglen)
{
  /* SEER_OBJECT_SCHEMA (#398); thin, 9i's included - the chunk width the
   * reader's */
  *img = NULL;
  *imglen = 0;
  SeerSchemaCtx cx = {
      .codec = SEER_CODEC_THIN, .fv = TTC_FIELD_VERSION_10_2, .wide_chunks = r->sb4_chunks};
  SeerObjectMsg m = {0};
  if (!seer_schema_decode(SEER_OBJECT_SCHEMA, &cx, r, &m)) {
    seer_schema_free(SEER_OBJECT_SCHEMA, &m);
    return SEER_EPROTO;
  }
  SeerStatus st = SEER_OK;
  if (m.image_len != 0 && m.image.n > 0) { /* 0: a NULL object */
    *img = malloc(m.image.n);
    if (*img == NULL)
      st = SEER_ENOMEM;
    else {
      memcpy(*img, m.image.p, m.image.n);
      *imglen = m.image.n;
    }
  }
  seer_schema_free(SEER_OBJECT_SCHEMA, &m);
  return st;
}

/* Record an ADT cell to decode after the result set is fully fetched (its
 * attribute layout needs a dictionary query). Takes ownership of `image`. */
static SeerStatus record_pending_obj(SeerStmt *stmt, size_t row, int col, uint8_t *image,
                                     size_t imagelen)
{
  if (stmt->npobjs == stmt->pobjs_cap) {
    size_t cap = stmt->pobjs_cap ? stmt->pobjs_cap * 2 : 8;
    SeerPendingObj *np = realloc(stmt->pobjs, cap * sizeof *np);
    if (np == NULL)
      return SEER_ENOMEM;
    stmt->pobjs = np;
    stmt->pobjs_cap = cap;
  }
  stmt->pobjs[stmt->npobjs++] = (SeerPendingObj){row, col, image, imagelen};
  return SEER_OK;
}

static SeerStatus parse_rxd(SeerReader *r, SeerStmt *stmt, const uint8_t *bv, size_t bvlen)
{
  if (stmt->ncols <= 0)
    return SEER_EPROTO;

  SeerCell *row = calloc((size_t)stmt->ncols, sizeof *row);
  if (row == NULL)
    return SEER_ENOMEM;

  SeerCell *prev = stmt->nrows > 0 ? stmt->rows[stmt->nrows - 1] : NULL;

  for (int i = 0; i < stmt->ncols; i++) {
    if (bv != NULL && !bvc_bit_set(bv, bvlen, i)) {
      /* Column unchanged from the previous row: duplicate the cell. */
      if (prev != NULL && prev[i].data != NULL) {
        if (cell_set_bytes(&row[i], prev[i].data, prev[i].len, prev[i].binary) != SEER_OK)
          goto oom;
      }
      continue;
    }

    uint8_t type = stmt->cols[i].ora_type;
    if (stmt->cols[i].inline_long) {
      /* LOB content inline (the cursor's define): LONG / LONG RAW framing. */
      if (decode_long(r, type == ORA_TYPE_BLOB, &row[i]) != SEER_OK)
        goto fail;
      continue;
    }
    if (type == ORA_TYPE_CLOB || type == ORA_TYPE_BLOB || type == ORA_TYPE_BFILE ||
        type == ORA_TYPE_VECTOR || type == ORA_TYPE_JSON) { /* all LOB-backed: defer */
      uint8_t *loc = NULL;
      size_t ll = 0;
      SeerStatus st = read_lob_locator(r, &loc, &ll);
      if (st == SEER_OK && loc != NULL)
        st = record_pending_lob(stmt, stmt->nrows, i, type, loc, ll);
      if (st != SEER_OK) {
        free(loc);
        goto fail;
      }
      continue; /* cell filled in the resolve pass */
    }
    if (type == ORA_TYPE_ADT) { /* SQL OBJECT: defer image decode */
      uint8_t *image = NULL;
      size_t ilen = 0;
      SeerStatus st = read_object_image(r, &image, &ilen);
      if (st == SEER_OK && image != NULL)
        st = record_pending_obj(stmt, stmt->nrows, i, image, ilen);
      if (st != SEER_OK) {
        free(image);
        goto fail;
      }
      continue; /* cell filled in the resolve pass */
    }

    if (stmt->cols[i].zero_len)
      continue; /* no bytes on the wire; the cell stays NULL */

    if (type == ORA_TYPE_REFCURSOR) {
      /* A nested CURSOR(...) column. ODBC has no nested-cursor type, so the
       * cell is reported as NULL; the server opened a cursor for it, which is
       * queued to close so it doesn't leak. */
      SeerColumn *ncols_desc = NULL;
      int nn = 0;
      int64_t cid = 0;
      if (read_cursor_value(r, stmt->conn->field_version, false, &ncols_desc, &nn, &cid) != SEER_OK)
        goto fail;
      free_columns(ncols_desc, nn);
      SeerConn *c = stmt->conn;
      if (cid > 0 && c->n_close < (int)(sizeof c->close_cursors / sizeof c->close_cursors[0]))
        c->close_cursors[c->n_close++] = (int)cid;
      continue;
    }

    SeerStatus st = decode_cell(r, &stmt->cols[i], &row[i]);
    if (st != SEER_OK)
      goto fail;
  }

  if (append_row(stmt, row) != SEER_OK)
    goto oom;
  return SEER_OK;

oom:
  for (int j = 0; j < stmt->ncols; j++)
    free(row[j].data);
  free(row);
  return SEER_ENOMEM;
fail:
  for (int j = 0; j < stmt->ncols; j++)
    free(row[j].data);
  free(row);
  return SEER_EPROTO;
}

/* Skip a server session-state RPA piggyback so the next token is the OER. */
static const uint8_t KNOWN_TOKENS[] = {4, 6, 7, 8, 9, 11, 12, 13, 14, 15, 16, 19, 21};
static bool is_known_token(uint8_t t)
{
  for (size_t i = 0; i < sizeof KNOWN_TOKENS; i++)
    if (KNOWN_TOKENS[i] == t)
      return true;
  return false;
}
/* 23ai (talking the fv=6 / 11g framing we negotiate) injects a one-time
 * server-capability block on the *first* execute of a connection, sitting
 * between the RPA return-parameter fields and the trailing OER. It is self-
 * describing: a few header bytes, then a `ub1 L` immediately followed by an
 * equal `ub4` little-endian L, then L data bytes, after which the OER begins.
 * Every other server (10g/11g/21c) lands directly on the OER token here, so the
 * scan only fires for that block. We locate the `<ub1 L><ub4le L>` self-length
 * and skip to just past the L bytes, but only commit if that lands on a known
 * token - otherwise the reader is left untouched and the caller's normal error
 * path runs (no regression). The proper long-term fix is to negotiate the 23ai
 * field version (fv24), where the response framing carries no such block. */
static void skip_capability_block(SeerReader *r)
{
  size_t base = r->pos;
  size_t rem = seer_reader_remaining(r);
  for (size_t off = 0; off + 5 <= rem && off <= 8; off++) {
    const uint8_t *p = r->buf + base + off;
    if (p[0] == p[1] && p[2] == 0 && p[3] == 0 && p[4] == 0) { /* ub1 L, ub4le L */
      size_t end = base + off + 5 + p[0];
      if (end < r->len && is_known_token(r->buf[end])) {
        r->pos = end; /* consumed; now on the OER */
        return;
      }
    }
  }
}

/* The three fields that follow an RPA's al8o4l words: a transaction-id length
 * (+ raw bytes), a count of session-state key/value pairs - each `ub2 text len
 * (+DALC) | ub2 binary len (+DALC) | ub2 keyword` - and a registration length
 * (+ raw bytes). Usually each is a single zero byte, but 11g answers ALTER
 * SESSION SET CURRENT_SCHEMA with two pairs here (keywords 168/169; EDITION
 * likewise). Parsed on a copy: returns true and advances *r only when the parse
 * lands where an RPA can end - a known token, the end of the buffer, or an
 * armed array-DML row-count tail. Otherwise the fields aren't there to read (a
 * changepassword reply's RPA goes straight to its OER) and the caller falls
 * back to skipping zero bytes. Mirrors seerdb's _skip_rpa_tail_fields. */
static bool skip_rpa_tail_fields(SeerReader *r, const SeerStmt *stmt)
{
  /* SEER_RPA_TAIL_SCHEMA (#398), on a copy */
  SeerReader t = *r;
  SeerSchemaCtx cx =
      stmt != NULL ? seer_msg_ctx(0, stmt->conn->field_version, stmt->conn->server_field_version)
                   : seer_msg_ctx(0, TTC_FIELD_VERSION_10_2, TTC_FIELD_VERSION_10_2);
  cx.wide_chunks = r->sb4_chunks;
  SeerRpaMsg m = {0};
  bool whole = seer_schema_decode(SEER_RPA_TAIL_SCHEMA, &cx, &t, &m);
  seer_schema_free(SEER_RPA_TAIL_SCHEMA, &m);
  if (!whole || m.txn_len < 0 || m.npairs < 0 || m.npairs > 1024 || m.reg_len < 0)
    return false;
  bool rowcount_tail = stmt != NULL && stmt->want_dml_rowcounts && stmt->dml_rowcounts == NULL;
  if (seer_reader_remaining(&t) > 0 && !is_known_token(t.buf[t.pos]) && !rowcount_tail)
    return false;
  *r = t;
  return true;
}

static SeerStatus skip_rpa(SeerReader *r, SeerStmt *stmt)
{
  /* The execute/fetch RPA (return-parameter) block precedes the trailing OER.
   * On 9i (fv < 10.2) `num` over-counts and the params end early on the real
   * status token, so we break on a token-valued byte there. From fv4 up `num`
   * is EXACT and must be consumed in full: a param value's length byte can
   * itself equal a token id (e.g. a scrollable-cursor position or, on a 26ai/
   * fv27 server, an execute RPA whose field byte is 0x04) — breaking on that
   * would stop short and decode the OER off by those bytes. Mirrors seerdb's
   * decode_token_rpa_piggyback (#181). */
  bool break_on_token = (stmt == NULL) || stmt->conn->field_version < TTC_FIELD_VERSION_10_2;
  if (break_on_token) {
    int64_t num = seer_dec_sb4(r);
    for (int64_t i = 0; i < num && seer_reader_ok(r); i++) {
      if (seer_reader_remaining(r) == 0 || is_known_token(r->buf[r->pos]))
        break;
      (void)seer_dec_sb4(r);
    }
  } else { /* SEER_RPA_HEAD_SCHEMA (#398) */
    SeerSchemaCtx cx = seer_msg_ctx(0, stmt->conn->field_version, stmt->conn->server_field_version);
    SeerRpaMsg m = {0};
    (void)seer_schema_decode(SEER_RPA_HEAD_SCHEMA, &cx, r, &m);
  }
  if (break_on_token || !skip_rpa_tail_fields(r, stmt))
    while (seer_reader_remaining(r) > 0 && r->buf[r->pos] == 0)
      (void)seer_reader_u8(r);
  /* Array-DML row counts (12c+): when armed, SEER_DML_ROWCOUNTS_SCHEMA and
   * per iteration SEER_DML_ROWCOUNT_SCHEMA ride here, ahead of the OER
   * (#398). */
  if (stmt != NULL && stmt->want_dml_rowcounts && stmt->dml_rowcounts == NULL &&
      seer_reader_remaining(r) > 0 && !is_known_token(r->buf[r->pos])) {
    SeerSchemaCtx cx = seer_msg_ctx(0, stmt->conn->field_version, stmt->conn->server_field_version);
    SeerDmlRowCountsMsg m = {0};
    if (seer_schema_decode(SEER_DML_ROWCOUNTS_SCHEMA, &cx, r, &m) && m.count > 0 &&
        m.count <= 65535) {
      uint32_t *arr = malloc((size_t)m.count * sizeof *arr);
      if (arr != NULL) {
        for (int64_t i = 0; i < m.count && seer_schema_decode(SEER_DML_ROWCOUNT_SCHEMA, &cx, r, &m);
             i++)
          arr[i] = (uint32_t)m.rows;
        stmt->dml_rowcounts = arr;
        stmt->n_dml_rowcounts = (size_t)m.count;
      }
    }
  }
  /* Recover past a 23ai first-response server-capability block, if present. */
  if (seer_reader_remaining(r) > 5 && !is_known_token(r->buf[r->pos]))
    skip_capability_block(r);
  return seer_reader_ok(r) ? SEER_OK : SEER_EPROTO;
}

static void free_batch_errors(SeerStmt *stmt)
{
  for (size_t i = 0; i < stmt->nberrs; i++)
    free(stmt->berrs[i].message);
  free(stmt->berrs);
  stmt->berrs = NULL;
  stmt->nberrs = 0;
}

/* Read an array-DML batch field (§6.7): a ub4 count, then a DALC blob packing
 * that many var-int ub4 values. On SEER_OK *out is a malloc'd array of *n
 * values (NULL/0 when the count is zero); caller frees. */
/* The ub4s a batch-error array's value packs (TTC compressed integers). */
static uint32_t *oer_ub4s(const SeerBytes *b, size_t *n)
{
  *n = 0;
  if (b->n == 0)
    return NULL;
  uint32_t *arr = malloc(b->n * sizeof *arr); /* at most one per byte */
  if (arr == NULL)
    return NULL;
  SeerReader br;
  seer_reader_init(&br, b->p, b->n);
  while (seer_reader_remaining(&br) > 0 && seer_reader_ok(&br))
    arr[(*n)++] = (uint32_t)seer_dec_sb4(&br);
  return arr;
}

/* The batch errors' messages (§6.7), after SEER_OER_BATCH_SCHEMA counted `n`:
 * SEER_OER_MSGS_HEAD_SCHEMA, then each as SEER_OER_MSG_SCHEMA - the same on
 * 10g+ and 9i (#398). Each text NUL-terminated and malloc'd; an empty one ""
 * with `blank` (10g+), else NULL (9i). NULL when the array can't be had. */
static char **oer_batch_msgs(SeerReader *r, const SeerSchemaCtx *cx, int64_t n, bool blank)
{
  char **msgs = calloc((size_t)n, sizeof *msgs);
  SeerOerTextMsg hm = {0};
  (void)seer_schema_decode(SEER_OER_MSGS_HEAD_SCHEMA, cx, r, &hm);
  for (int64_t i = 0; i < n && seer_reader_ok(r); i++) {
    SeerOerTextMsg tm = {0};
    bool ok = seer_schema_decode(SEER_OER_MSG_SCHEMA, cx, r, &tm);
    if (ok && msgs != NULL && (tm.text.n > 0 || blank)) {
      msgs[i] = malloc(tm.text.n + 1);
      if (msgs[i] != NULL) {
        if (tm.text.n > 0)
          memcpy(msgs[i], tm.text.p, tm.text.n);
        msgs[i][tm.text.n] = '\0';
      }
    }
    seer_schema_free(SEER_OER_MSG_SCHEMA, &tm);
    if (!ok)
      break;
  }
  return msgs;
}

/* The end-of-call status, by SEER_OER_HEAD_SCHEMA / _TAIL_SCHEMA (#395
 * spike): the batch errors' messages between them stay code. */
static SeerStatus parse_oer(SeerReader *r, SeerStmt *stmt, OerResult *oer)
{
  SeerConn *c = stmt->conn;
  SeerSchemaCtx cx = seer_msg_ctx(0, c->field_version, c->server_field_version);
  cx.wide_chunks = r->sb4_chunks;
  SeerOerMsg m = {0};
  if (!seer_schema_decode(SEER_OER_HEAD_SCHEMA, &cx, r, &m) ||
      !seer_schema_decode(SEER_OER_FLAGS_SCHEMA, &cx, r, &m) ||
      !seer_schema_decode(SEER_OER_BATCH_SCHEMA, &cx, r, &m)) {
    seer_schema_free(SEER_OER_BATCH_SCHEMA, &m);
    return SEER_EPROTO;
  }
  oer->call_status = m.call_status;
  oer->row_count = m.rows;
  oer->err_code = m.code;
  oer->cursor_id = m.cursor;
  oer->err_offset = m.position;
  oer->warn_flags = (uint8_t)m.warnings;

  /* The batch errors (§6.7): code i hit iteration offsets[i], text msgs[i]. */
  size_t ncodes = 0, noffsets = 0;
  uint32_t *codes = oer_ub4s(&m.codes, &ncodes);
  uint32_t *offsets = oer_ub4s(&m.offsets, &noffsets);
  seer_schema_free(SEER_OER_BATCH_SCHEMA, &m);

  char **msgs = NULL;
  size_t nmsgs = 0;
  if (m.nmsgs > 0 && m.nmsgs < 65536) {
    msgs = oer_batch_msgs(r, &cx, m.nmsgs, true);
    if (msgs != NULL)
      nmsgs = (size_t)m.nmsgs;
  }

  if (!seer_reader_ok(r)) {
    free(codes);
    free(offsets);
    for (size_t i = 0; i < nmsgs; i++)
      free(msgs[i]);
    free(msgs);
    return SEER_EPROTO;
  }

  size_t nb = noffsets;
  if (ncodes > nb)
    nb = ncodes;
  if (nmsgs > nb)
    nb = nmsgs;
  if (nb > 0) {
    free_batch_errors(stmt);
    stmt->berrs = calloc(nb, sizeof *stmt->berrs);
    if (stmt->berrs != NULL) {
      stmt->nberrs = nb;
      for (size_t i = 0; i < nb; i++) {
        stmt->berrs[i].row = i < noffsets ? offsets[i] : 0;
        stmt->berrs[i].code = i < ncodes ? codes[i] : 0;
        stmt->berrs[i].message = i < nmsgs ? msgs[i] : NULL;
        if (i < nmsgs)
          msgs[i] = NULL; /* ownership moved */
      }
    }
  }
  free(codes);
  free(offsets);
  for (size_t i = 0; i < nmsgs; i++)
    free(msgs[i]);
  free(msgs);

  /* The tail: 12.1's extended fields, a 20.1+ server's SQL type and
   * checksum, then the "ORA-NNNNN: ..." text when there is an error. */
  SeerOerMsg t = {.code = oer->err_code};
  (void)seer_schema_decode(SEER_OER_TAIL_SCHEMA, &cx, r, &t);
  if (t.message.n > 0) {
    char *nbuf = malloc(t.message.n + 1);
    if (nbuf != NULL) {
      memcpy(nbuf, t.message.p, t.message.n);
      nbuf[t.message.n] = '\0';
      free(c->last_error);
      c->last_error = nbuf;
    }
  }
  seer_schema_free(SEER_OER_TAIL_SCHEMA, &t);
  return SEER_OK;
}

/* I/O vector for an anonymous PL/SQL block's binds (§6.5). Reads the per-bind
 * directions; for each OUT / IN OUT bind a value follows in a TTI_RXD, which we
 * decode (per the bind's declared type) into pbinds[i].out. */
static SeerStatus parse_iov(SeerReader *r, SeerStmt *stmt)
{
  /* SEER_IOV_SCHEMA, then a direction byte per bind (#398) */
  SeerSchemaCtx cx = seer_msg_ctx(0, stmt->conn->field_version, stmt->conn->server_field_version);
  cx.wide_chunks = r->sb4_chunks;
  SeerIovMsg iov = {0};
  bool whole = seer_schema_decode(SEER_IOV_SCHEMA, &cx, r, &iov);
  seer_schema_free(SEER_IOV_SCHEMA, &iov);
  int64_t num_binds = iov.iterations * 256 + iov.requests;
  if (!whole || num_binds < 0 || num_binds > 100000)
    return SEER_EPROTO;
  iov.nbinds = num_binds;
  if (!seer_schema_decode(SEER_IOV_DIRS_SCHEMA, &cx, r, &iov))
    return SEER_EPROTO;
  uint8_t *dirs = malloc(num_binds ? (size_t)num_binds : 1);
  if (dirs == NULL)
    return SEER_ENOMEM;
  bool has_out = false;
  for (int64_t i = 0; i < num_binds; i++) {
    dirs[i] = iov.directions.p[i];
    if (dirs[i] != 32) /* 32 = IN; else OUT/IN OUT */
      has_out = true;
  }

  /* Returned OUT values, in bind order. A scalar value is a DALC blob plus a
   * 1-byte indicator; a REF CURSOR value is an inline describe + cursor id. */
  if (has_out && seer_reader_remaining(r) > 0 && r->buf[r->pos] == TTI_RXD) {
    (void)seer_reader_u8(r); /* RXD token */
    for (int64_t i = 0; i < num_binds; i++) {
      if (dirs[i] == 32)
        continue;
      SeerBind *b = (stmt != NULL && i < stmt->npbinds) ? &stmt->pbinds[i] : NULL;
      if (b != NULL && b->oac_type == ORA_TYPE_REFCURSOR) {
        if (parse_refcursor_out(r, stmt) != SEER_OK) {
          free(dirs);
          return SEER_EPROTO;
        }
        continue;
      }
      if (b != NULL && b->oac_type == ORA_TYPE_ADT) {
        /* An object / collection value: the object frame a fetched row carries
         * (§21.2), then a ub4 return code - not a DALC. The image is decoded
         * after the response (its layout may need a dictionary query). */
        uint8_t *img = NULL;
        size_t il = 0;
        if (read_object_image(r, &img, &il) != SEER_OK) {
          free(img);
          free(dirs);
          return SEER_EPROTO;
        }
        SeerCellMsg tm = {0}; /* the return code: SEER_OUT_TAIL_SCHEMA (#398) */
        (void)seer_schema_decode(SEER_OUT_TAIL_SCHEMA, &cx, r, &tm);
        free(b->out.data);
        b->out = (SeerCell){0};
        free(b->out_image);
        b->out_image = img; /* NULL for a NULL object */
        b->out_imagelen = il;
        continue;
      }
      if (b != NULL && b->is_array) {
        /* OUT assoc array (#122): SEER_OUT_ARRAY_SCHEMA's count, then each
         * element as SEER_OUT_CELL_SCHEMA - the value and its return code -
         * as on 8i (#398). */
        SeerOutArrayMsg am = {0};
        if (!seer_schema_decode(SEER_OUT_ARRAY_SCHEMA, &cx, r, &am) || am.count < 0 ||
            am.count > 1000000) {
          free(dirs);
          return SEER_EPROTO;
        }
        int64_t count = am.count;
        for (int k = 0; k < b->out_arr_n; k++)
          free(b->out_arr[k].data);
        free(b->out_arr);
        b->out_arr = count ? calloc((size_t)count, sizeof *b->out_arr) : NULL;
        b->out_arr_n = 0;
        for (int64_t e = 0; e < count; e++) {
          SeerCellMsg em = {0};
          if (!seer_schema_decode(SEER_OUT_CELL_SCHEMA, &cx, r, &em)) {
            seer_schema_free(SEER_OUT_CELL_SCHEMA, &em);
            free(dirs);
            return SEER_EPROTO;
          }
          if (b->out_arr != NULL)
            decode_scalar(b->oac_type ? b->oac_type : ORA_TYPE_VARCHAR, em.value.p, em.value.n,
                          &b->out_arr[e]);
          seer_schema_free(SEER_OUT_CELL_SCHEMA, &em);
        }
        b->out_arr_n = (int)count;
        continue;
      }
      /* SEER_OUT_CELL_SCHEMA: the value, then its ub4 return code - 0 for
       * a value and non-zero for a NULL (1405), which takes more bytes; read
       * as one byte, a NULL or never-assigned OUT desynced the reply (#149). */
      SeerCellMsg om = {0};
      if (!seer_schema_decode(SEER_OUT_CELL_SCHEMA, &cx, r, &om)) {
        seer_schema_free(SEER_OUT_CELL_SCHEMA, &om);
        free(dirs);
        return SEER_EPROTO;
      }
      if (b != NULL) {
        free(b->out.data);
        b->out = (SeerCell){0};
        decode_scalar(b->oac_type ? b->oac_type : 1, om.value.p, om.value.n, &b->out);
      }
      seer_schema_free(SEER_OUT_CELL_SCHEMA, &om);
    }
  }
  free(dirs);
  return seer_reader_ok(r) ? SEER_OK : SEER_EPROTO;
}

/* DML RETURNING ... INTO return data (§5.6), by SEER_RETURNING_COUNT_SCHEMA
 * and per row SEER_RETURNING_VALUE_SCHEMA, or _LOB_SCHEMA for a LOB target
 * (#398). We capture the first affected row's value into pbinds[i].out (one
 * ODBC OUT parameter holds one value); a LOB's content is read through its
 * locator once the response is parsed. */
static SeerStatus parse_returning_rxd(SeerReader *r, SeerStmt *stmt)
{
  SeerSchemaCtx cx = seer_msg_ctx(0, stmt->conn->field_version, stmt->conn->server_field_version);
  cx.wide_chunks = r->sb4_chunks;
  for (int i = 0; i < stmt->npbinds; i++) {
    SeerBind *b = &stmt->pbinds[i];
    if (!b->is_out)
      continue;
    b->out_full_len = 0;
    SeerReturningMsg cm = {0};
    if (!seer_schema_decode(SEER_RETURNING_COUNT_SCHEMA, &cx, r, &cm) || cm.nrows < 0 ||
        cm.nrows > 1000000)
      return SEER_EPROTO;
    const SeerField *row_schema =
        b->ret_lob != 0 ? SEER_RETURNING_LOB_SCHEMA : SEER_RETURNING_VALUE_SCHEMA;
    for (int64_t row = 0; row < cm.nrows; row++) {
      SeerReturningMsg m = {0};
      if (!seer_schema_decode(row_schema, &cx, r, &m)) {
        seer_schema_free(row_schema, &m);
        return SEER_EPROTO;
      }
      SeerStatus st = SEER_OK;
      if (row == 0) { /* keep the first row's value */
        free(b->out.data);
        b->out = (SeerCell){0};
        if (b->ret_lob != 0) {
          free(b->ret_locator);
          b->ret_locator = NULL;
          b->ret_loclen = 0;
          if (m.locator.n > 0) {
            b->ret_locator = malloc(m.locator.n);
            if (b->ret_locator == NULL)
              st = SEER_ENOMEM;
            else {
              memcpy(b->ret_locator, m.locator.p, m.locator.n);
              b->ret_loclen = m.locator.n;
            }
          }
        } else {
          decode_scalar(b->oac_type ? b->oac_type : ORA_TYPE_VARCHAR, m.value.p, m.value.n,
                        &b->out);
          b->out_full_len = m.actual_len > (int64_t)m.value.n ? m.actual_len : 0;
        }
      }
      seer_schema_free(row_schema, &m);
      if (st != SEER_OK)
        return st;
    }
  }
  return seer_reader_ok(r) ? SEER_OK : SEER_EPROTO;
}

/* Read the content of each LOB a DML RETURNING returned (their locators were
 * stashed by parse_returning_rxd): CLOB as UTF-8 text, BLOB as bytes. */
static SeerStatus resolve_returned_lobs(SeerStmt *stmt)
{
  for (int i = 0; i < stmt->npbinds; i++) {
    SeerBind *b = &stmt->pbinds[i];
    if (b->ret_locator == NULL)
      continue;
    uint8_t *raw = NULL;
    size_t rawlen = 0;
    SeerStatus st = seer_lob_read(stmt->conn, b->ret_locator, b->ret_loclen, &raw, &rawlen);
    free(b->ret_locator);
    b->ret_locator = NULL;
    b->ret_loclen = 0;
    if (st != SEER_OK)
      return st;
    if (b->ret_lob == ORA_TYPE_CLOB) {
      char *u8 = NULL;
      size_t u8len = 0;
      if (rawlen == 0)
        cell_set_text(&b->out, strdup(""));
      else if (seer_iconv("UTF-16BE", "UTF-8", (const char *)raw, rawlen, &u8, &u8len) == 0) {
        cell_set_bytes(&b->out, u8, u8len, false);
        free(u8);
      }
    } else {
      cell_set_bytes(&b->out, raw, rawlen, true);
    }
    free(raw);
  }
  return SEER_OK;
}

/* Consume a server-side piggyback (TTI_SVR_PIGGYBACK) the server prepends to
 * a response: a pooled session's (DRCP #130), an MTS pid, or a sessionless
 * transaction's sync state (§31, keyword 201 the transaction id). The values
 * aren't needed: the block is read by its schema and dropped, so the real
 * response tokens follow (#398). */
static SeerStatus skip_server_piggyback(SeerReader *r, const SeerConn *c)
{
  uint8_t opcode = seer_reader_u8(r);
  const SeerField *schema = opcode == TNS_SVR_PIG_SESS_RET     ? SEER_SVR_PIG_SESS_RET_SCHEMA
                            : opcode == TNS_SVR_PIG_OS_PID_MTS ? SEER_SVR_PIG_MTS_SCHEMA
                            : opcode == TNS_SVR_PIG_SYNC       ? SEER_SVR_PIG_SYNC_SCHEMA
                                                               : NULL;
  if (schema == NULL)
    return SEER_EPROTO; /* unknown piggyback opcode */
  SeerSchemaCtx cx = seer_msg_ctx(0, c->field_version, c->server_field_version);
  SeerSvrPiggybackMsg m = {0};
  bool ok = seer_schema_decode(schema, &cx, r, &m);
  seer_schema_free(schema, &m);
  return ok ? SEER_OK : SEER_EPROTO;
}

/* Walk one response message, appending rows and capturing the OER outcome. */
/* A reply that failed to decode at `from` may still carry the server's error
 * after it: its message, "ORA-NNNNN: ...", rides length-prefixed (a ub1
 * length, or the long form's chunks) at the end of a status. Find the first
 * one behind the failure point and put it on the connection. */
bool seer_conn_error_from_reply(SeerConn *c, const uint8_t *buf, size_t len, size_t from)
{
  for (size_t i = from; i + 10 <= len; i++) {
    if (memcmp(buf + i, "ORA-", 4) != 0 || buf[i + 4] < '0' || buf[i + 4] > '9')
      continue;
    size_t n = len - i;
    if (i > 0 && buf[i - 1] >= 10 && buf[i - 1] <= n)
      n = buf[i - 1]; /* the length byte in front of it */
    while (n > 0 && (buf[i + n - 1] == '\n' || buf[i + n - 1] == '\0'))
      n--;
    char *m = malloc(n + 1);
    if (m == NULL)
      return false;
    memcpy(m, buf + i, n);
    m[n] = '\0';
    free(c->last_error);
    c->last_error = m;
    c->last_error_offset = 0;
    seer_log(SEER_LOG_DEBUG, "the server reported: %s", m);
    return true;
  }
  return false;
}

void seer_conn_error_code(SeerConn *c, long code)
{
  char m[16];
  snprintf(m, sizeof m, "ORA-%05ld", code);
  char *d = strdup(m);
  if (d == NULL)
    return;
  free(c->last_error);
  c->last_error = d;
  c->last_error_offset = 0;
}

static SeerStatus parse_response(SeerStmt *stmt, const uint8_t *buf, size_t len, bool expect_dcb,
                                 OerResult *oer)
{
  SeerReader r;
  seer_reader_init(&r, buf, len);
  /* 12c+ sends 0xFE-chunked DALC values with sb4 chunk lengths (11g uses ub1);
   * a large value (>= 254 bytes) desyncs without this. */
  r.sb4_chunks = stmt->conn->field_version >= TTC_FIELD_VERSION_12_1;

  uint8_t *bv = NULL;
  size_t bvlen = 0;
  SeerStatus st = SEER_OK;
  bool got_oer = false;

  while (seer_reader_remaining(&r) > 0 && seer_reader_ok(&r)) {
    uint8_t tok = seer_reader_u8(&r);
    switch (tok) {
    case TTI_DCB:
      if (expect_dcb) {
        st = parse_dcb(&r, stmt);
      } else if (stmt->reuse_cursor > 0) {
        /* A cached cursor's re-execute keeps its columns, but the server
         * re-parsed it - another session changed the table - and describes
         * it anew: the new describe replaces the cached one (#212). */
        seer_log(SEER_LOG_DEBUG, "stmt: the cached cursor was re-described by the server");
        free_columns(stmt->cols, stmt->ncols);
        stmt->cols = NULL;
        stmt->ncols = 0;
        st = parse_dcb(&r, stmt);
      } else {
        st = SEER_EPROTO;
      }
      break;
    case TTI_RXH:
      st = parse_rxh(&r, stmt->conn->field_version, &bv, &bvlen);
      break;
    case TTI_BVC:
      st = parse_bvc(&r, stmt->ncols, &bv, &bvlen);
      break;
    case TTI_RXD:
      if (stmt->returning) {
        st = parse_returning_rxd(&r, stmt);
      } else {
        st = parse_rxd(&r, stmt, bv, bvlen);
        free(bv);
        bv = NULL;
        bvlen = 0;
      }
      break;
    case TTI_IOV:
      st = parse_iov(&r, stmt);
      break;
    case TTI_IRD:
      st = parse_implicit(&r, stmt);
      break;
    case TTI_RPA:
      st = skip_rpa(&r, stmt);
      break;
    case TTI_SVR_PIGGYBACK:
      st = skip_server_piggyback(&r, stmt->conn);
      break;
    case TTI_OER:
      st = parse_oer(&r, stmt, oer);
      got_oer = true;
      /* The end-of-call status says whether a transaction is open: bit
       * 0x02, measured on 10g, 11g and 23ai after DML and SELECT FOR UPDATE
       * (open) and after COMMIT, a committing block and DDL (closed). 8i and
       * 9i replies carry no such word: their state stays unknown (#344). */
      if (st == SEER_OK && !stmt->conn->is_8i &&
          stmt->conn->field_version >= TTC_FIELD_VERSION_10_2)
        stmt->conn->txn_state = (oer->call_status & 0x02) ? 1 : 0;
      break;
    case TTI_STA:
      got_oer = true; /* treat as terminal */
      break;
    case TTI_FOB:
      /* Flush-out-binds request: a failing DML RETURNING. 10g/11g send it as a
       * whole message (answered in seer_ttc_recv); 12c+ can send it after an
       * RXD in the same message. Stop here - the caller echoes it and reads
       * the real (error) response that follows. */
      oer->flush_binds = true;
      got_oer = true;
      break;
    case TTI_END_OF_RESPONSE:
      /* EOR framing (§32/#155): the per-response terminator. It normally
       * trails the OER/STA (which already ended the loop), but treat it as
       * a terminal too so an EOR-only response ends cleanly. */
      got_oer = true;
      break;
    case TTI_TOKEN:
      /* Pipelining (§32/#158): a response-correlation marker leading a
       * pipelined op's response — a ub8 token number. Consume it and keep
       * decoding the op body (which ends on its own OER/EOR). */
      {
        SeerCountMsg tm = {0}; /* SEER_COUNT_SCHEMA (#398) */
        SeerSchemaCtx tcx =
            seer_msg_ctx(0, stmt->conn->field_version, stmt->conn->server_field_version);
        (void)seer_schema_decode(SEER_COUNT_SCHEMA, &tcx, &r, &tm);
      }
      break;
    default:
      seer_log(SEER_LOG_ERROR, "stmt: unexpected response token %u", tok);
      st = SEER_EPROTO;
      break;
    }
    if (st != SEER_OK || got_oer)
      break;
  }

  free(bv);
  if (st != SEER_OK) {
    seer_log(SEER_LOG_DEBUG, "stmt: parse failed st=%d at pos %zu/%zu (ok=%d)", (int)st, r.pos,
             r.len, (int)seer_reader_ok(&r));
    /* A server error can arrive inside the rows - a recursive-SQL failure,
     * open_cursors exhausted - leaving a row cut short in front of the status
     * that carries it. The ORA error is the answer, not "protocol error". */
    if (st == SEER_EPROTO && seer_conn_error_from_reply(stmt->conn, buf, len, r.pos))
      return SEER_EDB;
    return st;
  }
  if (!got_oer)
    return SEER_EPROTO;
  return SEER_OK;
}

/* ----------------------------------------------------------- input binds */

/* Place an encoded value at 1-based position `param`, iteration `cur_iter`,
 * growing the bind array as needed and freeing any previous value there. The
 * OAC fields apply to the whole position - one descriptor for every row of an
 * array execute - so they are chosen across iterations: the size grows to the
 * widest value; a NULL (`is_null`) never overrides a type a real value set,
 * while a real value replaces a NULL's placeholder type; and a LONG / LONG RAW
 * value wins over the short VARCHAR / RAW form of the same column. (Taking
 * the last row's type turned a NUMBER column into VARCHAR when the batch
 * ended in a NULL.) Takes ownership of `rxd`. */
static SeerStatus store_bind_ex(SeerStmt *s, int param, uint8_t oac_type, uint32_t oac_size,
                                uint32_t oac_charset, uint8_t oac_flag, bool is_out, bool is_null,
                                uint8_t *rxd, size_t rxd_len)
{
  if (param < 1 || param > 1024) {
    free(rxd);
    return SEER_EPARAM;
  }
  int iters = s->n_iters > 0 ? s->n_iters : 1;
  int it = (s->cur_iter >= 0 && s->cur_iter < iters) ? s->cur_iter : 0;

  if (param > s->npbinds) {
    SeerBind *nb = realloc(s->pbinds, (size_t)param * sizeof *nb);
    if (nb == NULL) {
      free(rxd);
      return SEER_ENOMEM;
    }
    for (int i = s->npbinds; i < param; i++)
      nb[i] = (SeerBind){0};
    s->pbinds = nb;
    s->npbinds = param;
  }

  SeerBind *b = &s->pbinds[param - 1];
  if (b->rxd == NULL) {
    b->rxd = calloc((size_t)iters, sizeof *b->rxd);
    b->rxd_len = calloc((size_t)iters, sizeof *b->rxd_len);
    if (b->rxd == NULL || b->rxd_len == NULL) {
      free(rxd);
      return SEER_ENOMEM;
    }
  }
  bool have_real = b->oac_type != 0 && !b->type_from_null;
  bool demotion = (b->oac_type == ORA_TYPE_LONG && oac_type == ORA_TYPE_VARCHAR) ||
                  (b->oac_type == ORA_TYPE_LONGRAW && oac_type == ORA_TYPE_RAW);
  if (!(have_real && (is_null || demotion))) {
    b->oac_type = oac_type;
    b->oac_charset = oac_charset;
    b->oac_flag = oac_flag;
    b->type_from_null = is_null;
  }
  b->is_out = is_out;
  b->out_only = false;
  b->lob_out = 0;
  if (oac_size > b->oac_size)
    b->oac_size = oac_size;
  free(b->rxd[it]);
  b->rxd[it] = rxd;
  b->rxd_len[it] = rxd_len;
  return SEER_OK;
}

static SeerStatus store_bind(SeerStmt *s, int param, uint8_t oac_type, uint32_t oac_size,
                             uint32_t oac_charset, uint8_t oac_flag, bool is_out, uint8_t *rxd,
                             size_t rxd_len)
{
  return store_bind_ex(s, param, oac_type, oac_size, oac_charset, oac_flag, is_out, false, rxd,
                       rxd_len);
}

/* Encode a bind value (oracledb encode_chr) by SEER_CHR_SCHEMA (#398): from
 * 12.1 inline up to 252 bytes, else 0xFE and 64-byte chunks each with an sb4
 * length; before, inline only up to 64 and each chunk's length a ub1.
 * Sending the wrong chunk width desyncs the server's two-task conversion
 * (ORA-03120). Used for VARCHAR and RAW bind values; malloc'd *out. */
static SeerStatus encode_chr(const uint8_t *data, size_t n, uint8_t fv, uint8_t **out,
                             size_t *outlen)
{
  SeerWriter w;
  if (!seer_writer_init(&w, n + 16))
    return SEER_ENOMEM;
  SeerChrMsg m = {.value = {.p = data, .n = n}};
  SeerSchemaCtx cx = seer_msg_ctx(0, fv, fv);
  seer_schema_encode(SEER_CHR_SCHEMA, &cx, &m, &w);
  if (!seer_writer_ok(&w)) {
    seer_writer_free(&w);
    return SEER_ENOMEM;
  }
  *out = w.buf;
  *outlen = w.len;
  return SEER_OK;
}

/* Wrap a short value (<= 255 bytes: NUMBER, DATE, BINARY_DOUBLE) as <len><bytes>. */
static SeerStatus rxd_short(const uint8_t *data, size_t n, uint8_t **out, size_t *outlen)
{
  uint8_t *rxd = malloc(1 + n);
  if (rxd == NULL)
    return SEER_ENOMEM;
  rxd[0] = (uint8_t)n;
  memcpy(rxd + 1, data, n);
  *out = rxd;
  *outlen = 1 + n;
  return SEER_OK;
}

SeerStatus seer_stmt_bind_int64(SeerStmt *stmt, int param, int64_t value)
{
  if (stmt == NULL)
    return SEER_EPARAM;
  uint8_t num[24];
  size_t nn = seer_encode_number_int(value, num);
  uint8_t *rxd = NULL;
  size_t rl = 0;
  SeerStatus st = rxd_short(num, nn, &rxd, &rl);
  if (st != SEER_OK)
    return st;
  return store_bind(stmt, param, ORA_TYPE_NUMBER, 22, 0, 0, false, rxd, rl);
}

SeerStatus seer_stmt_bind_number_text(SeerStmt *stmt, int param, const char *dec)
{
  if (stmt == NULL || dec == NULL)
    return SEER_EPARAM;
  /* The encoder keeps 127 digits a side and drops the rest without a word;
   * NUMBER itself spans 1e-130 to 1e126. Refuse anything outside that, so a
   * digit is never lost silently. */
  const char *p = dec;
  if (*p == '-' || *p == '+')
    p++;
  while (*p == '0')
    p++;
  size_t ni = 0, nf = 0;
  while (p[ni] >= '0' && p[ni] <= '9')
    ni++;
  if (p[ni] == '.')
    while (p[ni + 1 + nf] >= '0' && p[ni + 1 + nf] <= '9')
      nf++;
  if (ni > 126 || nf > 127)
    return SEER_EPARAM;
  uint8_t num[24];
  size_t nn = seer_encode_number_str(dec, num);
  if (nn == 0)
    return SEER_EPARAM; /* not a plain decimal */
  uint8_t *rxd = NULL;
  size_t rl = 0;
  SeerStatus st = rxd_short(num, nn, &rxd, &rl);
  if (st != SEER_OK)
    return st;
  return store_bind(stmt, param, ORA_TYPE_NUMBER, 22, 0, 0, false, rxd, rl);
}

static bool sql_is_block(const char *sql);
static void emit_lob_oac(SeerWriter *w, int fv, uint8_t lob_type);

/* The largest value a PL/SQL VARCHAR2 / RAW parameter takes. */
#define PLSQL_MAX_STR 32767

/* Whether a text / raw value of `n` bytes goes in as a temporary LOB: past the
 * PL/SQL VARCHAR2 / RAW limit a block's CLOB / BLOB parameter rejects it
 * (ORA-01460), whereas a plain DML statement takes it as a streamed LONG. Not
 * for an array execute (one temp LOB per row is not implemented). 10g+: 9i
 * has its own (fv2_temp_lobs_begin), 10g/11g OCI 11.2's CREATE_TEMP (#415). */
static bool wants_temp_lob(const SeerStmt *s, size_t n)
{
  return n > PLSQL_MAX_STR && s->n_iters <= 1 && s->conn->field_version >= TTC_FIELD_VERSION_10_2 &&
         sql_is_block(s->sql);
}

/* Hand a temporary LOB no bind references any more to the connection, which
 * frees it with the next execute's FREE_TEMP piggyback. Takes ownership. */
static void queue_temp_lob_free(SeerConn *c, uint8_t *loc, size_t len)
{
  if (loc == NULL)
    return;
  if (c->n_free_lobs == c->free_lobs_cap) {
    int cap = c->free_lobs_cap ? c->free_lobs_cap * 2 : 8;
    uint8_t **nl = realloc(c->free_lobs, (size_t)cap * sizeof *nl);
    if (nl != NULL)
      c->free_lobs = nl;
    size_t *nn = realloc(c->free_lob_lens, (size_t)cap * sizeof *nn);
    if (nn != NULL)
      c->free_lob_lens = nn;
    if (nl == NULL || nn == NULL) {
      free(loc); /* out of memory: it lives until the session ends */
      return;
    }
    c->free_lobs_cap = cap;
  }
  c->free_lobs[c->n_free_lobs] = loc;
  c->free_lob_lens[c->n_free_lobs++] = len;
}

/* A LOBOPS reply's status: the RPA (its ub2-prefixed locator skipped - it may
 * hold a 0x04) and then the OER, whose error, if any, lands on the connection.
 * The OER's call status is not a fixed value, so the token is matched with a
 * plausible ub4 length byte behind it (seerdb decode_lobops_oer). */
static SeerStatus lobops_status(SeerConn *c, const uint8_t *resp, size_t rlen)
{
  size_t pos = 0;
  if (rlen >= 3 && resp[0] == TTI_RPA)
    pos = 3 + (((size_t)resp[1] << 8) | resp[2]);
  for (; pos + 1 < rlen; pos++) {
    if (resp[pos] != TTI_OER || resp[pos + 1] < 1 || resp[pos + 1] > 4)
      continue;
    SeerReader r;
    seer_reader_init(&r, resp + pos + 1, rlen - pos - 1);
    SeerStmt tmp = {.conn = c};
    OerResult oer = {0};
    parse_oer(&r, &tmp, &oer);
    free_batch_errors(&tmp);
    if (oer.err_code != 0) {
      seer_log(SEER_LOG_DEBUG, "lob: WRITE failed (ORA-%05ld)", (long)oer.err_code);
      return SEER_EDB;
    }
    return SEER_OK;
  }
  return SEER_OK;
}

/* Bind `n` bytes of `data` as a temporary LOB (seerdb PROTOCOL.md §14.4):
 * CREATE_TEMP allocates it, WRITE fills it - a CLOB with the UTF-8 text as
 * UTF-16BE, a BLOB with the bytes - and the bind carries its locator behind
 * the LOB descriptor prefix `01 28 28` + ub2 length, under the LOB bind OAC.
 * The bind keeps the locator; the temp LOB is freed once the bind is replaced
 * or the statement closed (not at execute: a re-execute reuses the value). */
static SeerStatus bind_temp_lob(SeerStmt *stmt, int param, bool blob, const uint8_t *data, size_t n)
{
  SeerConn *c = stmt->conn;
  char *u16 = NULL;
  size_t u16len = 0;
  if (!blob) {
    if (seer_iconv("UTF-8", "UTF-16BE", (const char *)data, n, &u16, &u16len) != 0)
      return SEER_EPROTO;
    data = (const uint8_t *)u16;
    n = u16len;
  }
  uint8_t *loc = NULL;
  size_t loclen = 0;
  SeerStatus st = seer_lob_create_temp(c, blob, &loc, &loclen);
  if (st == SEER_OK) {
    uint8_t *resp = NULL;
    size_t rlen = 0;
    /* the amount in the LOB's units: UTF-16 code units for a CLOB */
    st = seer_lob_write(c, loc, loclen, data, n, (uint32_t)(blob ? n : n / 2), &resp, &rlen);
    if (st == SEER_OK)
      st = lobops_status(c, resp, rlen);
    free(resp);
  }
  free(u16);
  if (st != SEER_OK) {
    queue_temp_lob_free(c, loc, loclen); /* created, then the WRITE failed */
    return st;
  }

  SeerWriter v, oac;
  bool ok = seer_writer_init(&v, loclen + 8);
  if (ok) {
    SeerLobBindMsg lm = {.loc_len = (int64_t)loclen, .locator = {.p = loc, .n = loclen}};
    SeerSchemaCtx cx = seer_msg_ctx(0, c->field_version, c->server_field_version);
    seer_schema_encode(SEER_LOB_BIND_SCHEMA, &cx, &lm, &v); /* #398 */
    ok = seer_writer_ok(&v);
  }
  if (!ok || !seer_writer_init(&oac, 64)) {
    seer_writer_free(&v);
    queue_temp_lob_free(c, loc, loclen);
    return SEER_ENOMEM;
  }
  uint8_t lob_type = blob ? ORA_TYPE_BLOB : ORA_TYPE_CLOB;
  emit_lob_oac(&oac, c->field_version, lob_type);
  if (!seer_writer_ok(&oac)) {
    seer_writer_free(&v);
    seer_writer_free(&oac);
    queue_temp_lob_free(c, loc, loclen);
    return SEER_ENOMEM;
  }
  st = store_bind(stmt, param, lob_type, 112, blob ? 0 : 873, 0, false, v.buf, v.len);
  if (st != SEER_OK) {
    seer_writer_free(&oac);
    queue_temp_lob_free(c, loc, loclen);
    return st;
  } /* store_bind took v.buf */
  SeerBind *b = &stmt->pbinds[param - 1];
  free(b->oac_override);
  b->oac_override = oac.buf;
  b->oac_override_len = oac.len;
  b->temp_lob = true;
  queue_temp_lob_free(c, b->temp_locator, b->temp_loclen); /* the one it replaces */
  b->temp_locator = loc;
  b->temp_loclen = loclen;
  return SEER_OK;
}

/* A plain text / raw value rebound over an earlier temp-LOB bind drops its
 * LOB OAC. */
static void clear_temp_lob(SeerStmt *stmt, int param)
{
  if (param < 1 || param > stmt->npbinds || !stmt->pbinds[param - 1].temp_lob)
    return;
  SeerBind *b = &stmt->pbinds[param - 1];
  free(b->oac_override);
  b->oac_override = NULL;
  b->oac_override_len = 0;
  b->temp_lob = false;
  queue_temp_lob_free(stmt->conn, b->temp_locator, b->temp_loclen);
  b->temp_locator = NULL;
  b->temp_loclen = 0;
}

SeerStatus seer_stmt_bind_text(SeerStmt *stmt, int param, const char *str, int len)
{
  if (stmt == NULL || str == NULL)
    return SEER_EPARAM;
  size_t n = (len < 0) ? strlen(str) : (size_t)len;
  if (wants_temp_lob(stmt, n))
    return bind_temp_lob(stmt, param, false, (const uint8_t *)str, n);
  clear_temp_lob(stmt, param);
  uint8_t *rxd = NULL;
  size_t rl = 0;
  SeerStatus st = encode_chr((const uint8_t *)str, n, stmt->conn->field_version, &rxd, &rl);
  if (st != SEER_OK)
    return st;
  /* Past the VARCHAR2 limit (e.g. a large CLOB insert) declare a streamed LONG;
   * the chunked value above and TTC fragmentation carry it. A VARCHAR OAC with
   * an over-limit size is rejected by the server. */
  bool big = n > 4000;
  return store_bind(stmt, param, big ? ORA_TYPE_LONG : ORA_TYPE_VARCHAR, (uint32_t)(n ? n : 1), 873,
                    16, false, rxd, rl);
}

/* Bind national-charset text (NVARCHAR2 / NCHAR): the UTF-8 `str` is converted to
 * AL16UTF16 (UTF-16BE) and the bind is declared with charset 2000 / csfrm 2, so the
 * server stores it in the database's national character set. Works on both the
 * modern (emit_oac) and 9i (fv2_bind_oac) paths. */
SeerStatus seer_stmt_bind_ntext(SeerStmt *stmt, int param, const char *str, int len)
{
  if (stmt == NULL || str == NULL)
    return SEER_EPARAM;
  size_t n = (len < 0) ? strlen(str) : (size_t)len;
  if (stmt->conn->is_8i) {
    /* 8i has no AL16UTF16: the value goes as text does, in the session's
     * national charset (WE8ISO8859P1, as the 8i DTY declares it), and only
     * its form says national (o8i_bind_oac). Without that form, 8.1.7 won't
     * mix it with an NCHAR value: ORA-12704 (#419). */
    SeerStatus st = seer_stmt_bind_text(stmt, param, str, (int)n);
    if (st == SEER_OK && param >= 1 && param <= stmt->npbinds &&
        stmt->pbinds[param - 1].oac_type == ORA_TYPE_VARCHAR)
      stmt->pbinds[param - 1].oac_charset = ORA_CHARSET_AL16UTF16; /* the national form */
    return st;
  }
  char *u16 = NULL;
  size_t u16len = 0;
  if (n > 0 && seer_iconv("UTF-8", "UTF-16BE", str, n, &u16, &u16len) != 0)
    return SEER_EPROTO;
  uint8_t *rxd = NULL;
  size_t rl = 0;
  SeerStatus st =
      encode_chr((const uint8_t *)(u16 ? u16 : ""), u16len, stmt->conn->field_version, &rxd, &rl);
  free(u16);
  if (st != SEER_OK)
    return st;
  return store_bind(stmt, param, ORA_TYPE_VARCHAR, (uint32_t)(u16len ? u16len : 1), 2000, 16, false,
                    rxd, rl);
}

/* Text / bytes for a CLOB / BLOB target, a PL/SQL LOB parameter among them
 * (#424): bound as text and RAW are, and marked. 9i and later convert a text
 * or RAW value to a LOB (past the bind limits it goes as a temporary LOB
 * anyway); 8.1.7 converts nothing to a LOB parameter (PLS-00306), so there
 * the value goes as a temporary LOB. */
SeerStatus seer_stmt_bind_clob(SeerStmt *stmt, int param, const char *str, int len)
{
  SeerStatus st = seer_stmt_bind_text(stmt, param, str, len);
  if (st == SEER_OK && param >= 1 && param <= stmt->npbinds)
    stmt->pbinds[param - 1].as_lob = true;
  return st;
}

SeerStatus seer_stmt_bind_blob(SeerStmt *stmt, int param, const void *data, int len)
{
  SeerStatus st = seer_stmt_bind_raw(stmt, param, data, len);
  if (st == SEER_OK && param >= 1 && param <= stmt->npbinds)
    stmt->pbinds[param - 1].as_lob = true;
  return st;
}

/* Bind an XML document to an XMLType target. XMLType is transmitted as text - the
 * server parses and validates the document - so the UTF-8 text is bound directly
 * (VARCHAR2, or a streamed LONG past the VARCHAR2 limit for a large document) and
 * the server converts it. Works with `INSERT ... VALUES (:1)` into an XMLType
 * column for any size; there is no client-side XML processing (unlike JSON, whose
 * OSON binary form we must encode). */
SeerStatus seer_stmt_bind_xmltype(SeerStmt *stmt, int param, const char *xml_text)
{
  return seer_stmt_bind_text(stmt, param, xml_text, -1);
}

SeerStatus seer_stmt_bind_raw(SeerStmt *stmt, int param, const void *data, int len)
{
  if (stmt == NULL || (data == NULL && len > 0))
    return SEER_EPARAM;
  size_t n = (len < 0) ? 0 : (size_t)len;
  if (wants_temp_lob(stmt, n))
    return bind_temp_lob(stmt, param, true, (const uint8_t *)data, n);
  clear_temp_lob(stmt, param);
  uint8_t *rxd = NULL;
  size_t rl = 0;
  SeerStatus st = encode_chr((const uint8_t *)data, n, stmt->conn->field_version, &rxd, &rl);
  if (st != SEER_OK)
    return st;
  /* Past the RAW limit (2000), stream as LONG RAW (e.g. a large BLOB insert). */
  bool big = n > 2000;
  return store_bind(stmt, param, big ? ORA_TYPE_LONGRAW : ORA_TYPE_RAW, (uint32_t)(n ? n : 1), 0,
                    16, false, rxd, rl);
}

SeerStatus seer_stmt_bind_date(SeerStmt *stmt, int param, int year, int month, int day, int hour,
                               int minute, int second)
{
  if (stmt == NULL)
    return SEER_EPARAM;
  uint8_t d[7] = {
      (uint8_t)(year / 100 + 100), (uint8_t)(year % 100 + 100), (uint8_t)month,        (uint8_t)day,
      (uint8_t)(hour + 1),         (uint8_t)(minute + 1),       (uint8_t)(second + 1),
  };
  uint8_t *rxd = NULL;
  size_t rl = 0;
  SeerStatus st = rxd_short(d, sizeof d, &rxd, &rl);
  if (st != SEER_OK)
    return st;
  return store_bind(stmt, param, ORA_TYPE_DATE, 7, 0, 0, false, rxd, rl);
}

SeerStatus seer_stmt_bind_timestamp(SeerStmt *stmt, int param, int year, int month, int day,
                                    int hour, int minute, int second, uint32_t nanos)
{
  if (stmt == NULL)
    return SEER_EPARAM;
  /* 7-byte DATE prefix + 4 big-endian nanoseconds (Oracle TIMESTAMP, §11). */
  uint8_t d[11] = {
      (uint8_t)(year / 100 + 100),
      (uint8_t)(year % 100 + 100),
      (uint8_t)month,
      (uint8_t)day,
      (uint8_t)(hour + 1),
      (uint8_t)(minute + 1),
      (uint8_t)(second + 1),
      (uint8_t)(nanos >> 24),
      (uint8_t)(nanos >> 16),
      (uint8_t)(nanos >> 8),
      (uint8_t)nanos,
  };
  /* A zero fraction goes out in the 7-byte DATE form under the same 11-byte
   * TIMESTAMP descriptor, as the reference client sends it: the server does
   * not read the two forms alike - `trunc(ltz_col) = :midnight` matches only
   * the 7-byte one (seerdb PROTOCOL.md §11.4b, f26fd77). The descriptor stays
   * TIMESTAMP / 11, so an array batch mixing the two forms keeps one type. */
  uint8_t *rxd = NULL;
  size_t rl = 0;
  SeerStatus st = rxd_short(d, nanos == 0 ? 7 : sizeof d, &rxd, &rl);
  if (st != SEER_OK)
    return st;
  return store_bind(stmt, param, ORA_TYPE_TIMESTAMP, 11, 0, 0, false, rxd, rl);
}

/* INTERVAL YEAR TO MONTH (5 bytes): ub4 (years biased by 2^31) + ub1 (months
 * biased by 60). A negative interval carries the sign on both components. */
SeerStatus seer_stmt_bind_interval_ym(SeerStmt *stmt, int param, int32_t years, int32_t months)
{
  if (stmt == NULL)
    return SEER_EPARAM;
  uint32_t by = (uint32_t)years + 0x80000000u;
  uint8_t iv[5] = {
      (uint8_t)(by >> 24), (uint8_t)(by >> 16),    (uint8_t)(by >> 8),
      (uint8_t)by,         (uint8_t)(months + 60),
  };
  uint8_t *rxd = NULL;
  size_t rl = 0;
  SeerStatus st = rxd_short(iv, sizeof iv, &rxd, &rl);
  if (st != SEER_OK)
    return st;
  return store_bind(stmt, param, ORA_TYPE_INTERVAL_YM, 5, 0, 0, false, rxd, rl);
}

/* INTERVAL DAY TO SECOND (11 bytes): ub4 (days biased by 2^31), ub1 H/M/S biased
 * by 60, ub4 (nanoseconds biased by 2^31). */
SeerStatus seer_stmt_bind_interval_ds(SeerStmt *stmt, int param, int32_t days, int32_t hours,
                                      int32_t mins, int32_t secs, int32_t nanos)
{
  if (stmt == NULL)
    return SEER_EPARAM;
  uint32_t bd = (uint32_t)days + 0x80000000u;
  uint32_t bn = (uint32_t)nanos + 0x80000000u;
  uint8_t iv[11] = {
      (uint8_t)(bd >> 24),   (uint8_t)(bd >> 16),  (uint8_t)(bd >> 8),   (uint8_t)bd,
      (uint8_t)(hours + 60), (uint8_t)(mins + 60), (uint8_t)(secs + 60), (uint8_t)(bn >> 24),
      (uint8_t)(bn >> 16),   (uint8_t)(bn >> 8),   (uint8_t)bn,
  };
  uint8_t *rxd = NULL;
  size_t rl = 0;
  SeerStatus st = rxd_short(iv, sizeof iv, &rxd, &rl);
  if (st != SEER_OK)
    return st;
  return store_bind(stmt, param, ORA_TYPE_INTERVAL_DS, 11, 0, 0, false, rxd, rl);
}

/* 8i and 9i have no BINARY_DOUBLE / BINARY_FLOAT: a double or float binds
 * there as a NUMBER instead (#151), written with the fewest significant
 * digits that read back to the very same value - 17 at most for a double, 9
 * for a float - so the caller gets back exactly what it stored. NaN and the
 * infinities have no NUMBER form, and a value past NUMBER's range (about
 * 1e-130 to 1e126) none either: refused, rather than stored wrong. Before
 * this, 9i sent the IEEE bytes as text and stored them garbled. */
static bool binary_float_type_missing(const SeerConn *c)
{
  return c->is_8i || c->field_version < TTC_FIELD_VERSION_10_2;
}

/* Whether two values are the same bits: the exact round trip the shortest
 * decimal must make, where an epsilon would be wrong (and -0.0 is not 0.0). */
static bool same_double(double a, double b)
{
  return memcmp(&a, &b, sizeof a) == 0;
}

static bool same_float(float a, float b)
{
  return memcmp(&a, &b, sizeof a) == 0;
}

static SeerStatus bind_float_as_number(SeerStmt *stmt, int param, double value, bool single)
{
  if (!isfinite(value)) {
    seer_log(SEER_LOG_WARNING, "stmt: Oracle 8i / 9i: NaN and infinity have no NUMBER form");
    return SEER_ENOTIMPL;
  }
  /* The shortest decimal that reads back to `value`, as d.ddde<exp>. */
  char e[40] = "0e+00";
  if (value != 0) {
    for (int prec = 1; prec <= (single ? 9 : 17); prec++) {
      snprintf(e, sizeof e, "%.*e", prec - 1, value);
      double back = strtod(e, NULL);
      if (single ? same_float((float)back, (float)value) : same_double(back, value))
        break;
    }
  }
  /* d.ddd e<exp> -> a plain decimal, the form seer_encode_number_str takes. */
  char digits[24];
  int nd = 0, exp10 = 0;
  bool neg = false;
  const char *q = e;
  if (*q == '-') {
    neg = true;
    q++;
  }
  for (; *q != '\0' && *q != 'e'; q++)
    if (*q >= '0' && *q <= '9' && nd < (int)sizeof digits)
      digits[nd++] = *q;
  if (*q == 'e')
    exp10 = atoi(q + 1);
  /* NUMBER spans 1e-130 to 1e126; the encoder takes 127 digits a side. */
  int point = exp10 + 1; /* digits before the decimal point */
  if (value != 0 && (point > 126 || point - nd < -126)) {
    seer_log(SEER_LOG_WARNING, "stmt: Oracle 8i / 9i: %g is past the range of a NUMBER", value);
    return SEER_ENOTIMPL;
  }
  char plain[300];
  size_t k = 0;
  if (neg)
    plain[k++] = '-';
  if (point <= 0) {
    plain[k++] = '0';
    plain[k++] = '.';
    for (int i = 0; i < -point; i++)
      plain[k++] = '0';
    for (int i = 0; i < nd; i++)
      plain[k++] = digits[i];
  } else {
    for (int i = 0; i < point; i++)
      plain[k++] = i < nd ? digits[i] : '0';
    if (nd > point) {
      plain[k++] = '.';
      for (int i = point; i < nd; i++)
        plain[k++] = digits[i];
    }
  }
  plain[k] = '\0';
  uint8_t num[24];
  size_t nn = value == 0 ? seer_encode_number_int(0, num) : seer_encode_number_str(plain, num);
  if (nn == 0)
    return SEER_EPARAM;
  uint8_t *rxd = NULL;
  size_t rl = 0;
  SeerStatus st = rxd_short(num, nn, &rxd, &rl);
  if (st != SEER_OK)
    return st;
  return store_bind(stmt, param, ORA_TYPE_NUMBER, 22, 0, 0, false, rxd, rl);
}

SeerStatus seer_stmt_bind_double(SeerStmt *stmt, int param, double value)
{
  if (stmt == NULL)
    return SEER_EPARAM;
  if (binary_float_type_missing(stmt->conn))
    return bind_float_as_number(stmt, param, value, false);
  uint8_t enc[8];
  seer_encode_bdouble(value, enc);
  uint8_t *rxd = NULL;
  size_t rl = 0;
  SeerStatus st = rxd_short(enc, sizeof enc, &rxd, &rl);
  if (st != SEER_OK)
    return st;
  return store_bind(stmt, param, ORA_TYPE_BDOUBLE, 8, 0, 0, false, rxd, rl);
}

SeerStatus seer_stmt_bind_float(SeerStmt *stmt, int param, float value)
{
  if (stmt == NULL)
    return SEER_EPARAM;
  if (binary_float_type_missing(stmt->conn))
    return bind_float_as_number(stmt, param, value, true);
  uint8_t enc[4];
  seer_encode_bfloat(value, enc);
  uint8_t *rxd = NULL;
  size_t rl = 0;
  SeerStatus st = rxd_short(enc, sizeof enc, &rxd, &rl);
  if (st != SEER_OK)
    return st;
  return store_bind(stmt, param, ORA_TYPE_BFLOAT, 4, 0, 0, false, rxd, rl);
}

SeerStatus seer_stmt_bind_bool(SeerStmt *stmt, int param, int value)
{
  if (stmt == NULL)
    return SEER_EPARAM;
  /* 23ai native BOOLEAN: RXD value 02 01 <0/1>, OAC type 252. Pre-23ai has no
   * BOOLEAN type, so bind a NUMBER 0/1 there. */
  if (stmt->conn->field_version < TTC_FIELD_VERSION_23_1)
    return seer_stmt_bind_int64(stmt, param, value ? 1 : 0);
  uint8_t v[2] = {0x01, value ? 1 : 0};
  uint8_t *rxd = NULL;
  size_t rl = 0;
  SeerStatus st = rxd_short(v, sizeof v, &rxd, &rl); /* -> 02 01 <0/1> */
  if (st != SEER_OK)
    return st;
  return store_bind(stmt, param, ORA_TYPE_BOOLEAN, 4, 0, 0, false, rxd, rl);
}

SeerStatus seer_stmt_bind_null(SeerStmt *stmt, int param)
{
  if (stmt == NULL)
    return SEER_EPARAM;
  uint8_t *rxd = malloc(1);
  if (rxd == NULL)
    return SEER_ENOMEM;
  rxd[0] = 0; /* NULL value */
  return store_bind_ex(stmt, param, ORA_TYPE_VARCHAR, 1, 873, 16, false, true, rxd, 1);
}

SeerStatus seer_stmt_bind_null_typed(SeerStmt *stmt, int param, int ora_type)
{
  if (stmt == NULL)
    return SEER_EPARAM;
  /* The descriptor a non-NULL value of that type would carry; the value is
   * the NULL byte either way. A NULL declared as VARCHAR can't meet a NUMBER
   * or DATE in COALESCE / CASE (ORA-00932), and in an array execute it must
   * not type the column. */
  uint8_t t;
  uint32_t size, charset = 0;
  uint8_t flag = 0;
  switch (ora_type) {
  case ORA_TYPE_NUMBER:
    t = ORA_TYPE_NUMBER, size = 22;
    break;
  case ORA_TYPE_DATE:
    t = ORA_TYPE_DATE, size = 7;
    break;
  case ORA_TYPE_TIMESTAMP:
    t = ORA_TYPE_TIMESTAMP, size = 11;
    break;
  case ORA_TYPE_BDOUBLE:
    t = ORA_TYPE_BDOUBLE, size = 8;
    break;
  case ORA_TYPE_BFLOAT:
    t = ORA_TYPE_BFLOAT, size = 4;
    break;
  case ORA_TYPE_RAW:
    t = ORA_TYPE_RAW, size = 1, flag = 16;
    break;
  default:
    return seer_stmt_bind_null(stmt, param);
  }
  uint8_t *rxd = malloc(1);
  if (rxd == NULL)
    return SEER_ENOMEM;
  rxd[0] = 0;
  return store_bind_ex(stmt, param, t, size, charset, flag, false, true, rxd, 1);
}

SeerStatus seer_stmt_bind_out(SeerStmt *stmt, int param, int ora_type, int max_size)
{
  if (stmt == NULL)
    return SEER_EPARAM;
  uint8_t oac_type = ORA_TYPE_VARCHAR, oac_flag = 0;
  uint32_t oac_size = 0, oac_charset = 0;
  switch (ora_type) {
  case ORA_TYPE_NUMBER:
    oac_type = ORA_TYPE_NUMBER;
    oac_size = 22;
    break;
  case ORA_TYPE_DATE:
    oac_type = ORA_TYPE_DATE;
    oac_size = 7;
    break;
  case ORA_TYPE_BDOUBLE:
    oac_type = ORA_TYPE_BDOUBLE;
    oac_size = 8;
    break;
  case ORA_TYPE_RAW:
    oac_type = ORA_TYPE_RAW;
    oac_size = (uint32_t)(max_size > 0 ? max_size : 2000);
    oac_flag = 16;
    break;
  case ORA_TYPE_REFCURSOR:
    oac_type = ORA_TYPE_REFCURSOR;
    oac_size = 1;
    oac_charset = 871;
    break;
  case ORA_TYPE_BLOB: /* a BLOB OUT (#214): a wide RAW, a LOB bind before 10g */
    oac_type = ORA_TYPE_RAW;
    oac_size = (uint32_t)(max_size > 0 ? max_size : 32767);
    oac_flag = 16;
    break;
  case ORA_TYPE_CLOB: /* a CLOB OUT (#214): a wide text, a LOB bind before 10g */
    oac_type = ORA_TYPE_VARCHAR;
    oac_size = (uint32_t)(max_size > 0 ? max_size : 32767);
    oac_charset = 873;
    oac_flag = 16;
    break;
  case ORA_TYPE_VARCHAR:
  default:
    oac_type = ORA_TYPE_VARCHAR;
    oac_size = (uint32_t)(max_size > 0 ? max_size : 4000);
    oac_charset = 873;
    oac_flag = 16;
    break;
  }

  uint8_t *rxd;
  size_t rxd_len;
  if (oac_type == ORA_TYPE_REFCURSOR) {
    rxd = malloc(2); /* REF CURSOR slot placeholder {1,0} */
    if (rxd == NULL)
      return SEER_ENOMEM;
    rxd[0] = 1;
    rxd[1] = 0;
    rxd_len = 2;
  } else {
    rxd = malloc(1); /* NULL placeholder value */
    if (rxd == NULL)
      return SEER_ENOMEM;
    rxd[0] = 0;
    rxd_len = 1;
  }
  SeerStatus st =
      store_bind(stmt, param, oac_type, oac_size, oac_charset, oac_flag, true, rxd, rxd_len);
  if (st == SEER_OK)
    stmt->pbinds[param - 1].out_only = true;
  /* A CLOB / BLOB OUT on 8i and 9i: the LOB itself, its locator read back
   * (seerdb PROTOCOL.md §19.17b, as a RETURNING target since #215). 8.1.7
   * converts no CLOB to text, so `? := c` takes nothing else there; 9.2 does,
   * but the LOB carries past 32512. 10g+ keeps the wide text / RAW, which it
   * converts to (#214). */
  if (st == SEER_OK && (ora_type == ORA_TYPE_CLOB || ora_type == ORA_TYPE_BLOB) &&
      stmt->conn->field_version < TTC_FIELD_VERSION_10_2) {
    SeerBind *b = &stmt->pbinds[param - 1];
    b->lob_out = (uint8_t)ora_type;
    b->ret_lob = (uint8_t)ora_type;
  }
  return st;
}

long seer_stmt_out_truncated(SeerStmt *stmt, int param)
{
  if (stmt == NULL || param < 1 || param > stmt->npbinds)
    return 0;
  return (long)stmt->pbinds[param - 1].out_full_len;
}

SeerStatus seer_stmt_bind_set_inout(SeerStmt *stmt, int param, int max_size)
{
  if (stmt == NULL || param < 1 || param > stmt->npbinds || stmt->pbinds[param - 1].oac_type == 0)
    return SEER_EPARAM;
  SeerBind *b = &stmt->pbinds[param - 1];
  if (b->temp_lob)
    return SEER_ENOTIMPL; /* an IN OUT LOB comes back as a locator, not handled */
  if (b->oac_type == ORA_TYPE_ADT && b->obj_type == NULL)
    return SEER_ENOTIMPL; /* no type to decode the returned value with */
  b->is_out = true;
  /* Room for the returned value, which can outgrow the value sent in; only
   * the variable-width types size by value (NUMBER / DATE / ... are fixed). */
  bool variable = b->oac_type == ORA_TYPE_VARCHAR || b->oac_type == ORA_TYPE_RAW;
  if (variable && max_size > 0 && (uint32_t)max_size > b->oac_size)
    b->oac_size = (uint32_t)max_size;
  return SEER_OK;
}

/* Free every stored bind (all positions, all iterations). */
static void free_binds(SeerStmt *s)
{
  int iters = s->n_iters > 0 ? s->n_iters : 1;
  for (int i = 0; i < s->npbinds; i++) {
    if (s->pbinds[i].rxd != NULL)
      for (int k = 0; k < iters; k++)
        free(s->pbinds[i].rxd[k]);
    free(s->pbinds[i].rxd);
    free(s->pbinds[i].rxd_len);
    free(s->pbinds[i].out.data);
    free(s->pbinds[i].ret_locator);
    for (int k = 0; k < s->pbinds[i].out_arr_n; k++)
      free(s->pbinds[i].out_arr[k].data);
    free(s->pbinds[i].out_arr);
    free(s->pbinds[i].oac_override);
    free(s->pbinds[i].out_image);
    queue_temp_lob_free(s->conn, s->pbinds[i].temp_locator, s->pbinds[i].temp_loclen);
    free_columns(s->pbinds[i].obj_type, s->pbinds[i].obj_type ? 1 : 0);
  }
  free(s->pbinds);
  s->pbinds = NULL;
  s->npbinds = 0;
}

SeerStatus seer_stmt_set_array_size(SeerStmt *stmt, int n)
{
  if (stmt == NULL || n < 1)
    return SEER_EPARAM;
  free_binds(stmt); /* iteration count changes the bind layout */
  stmt->n_iters = n;
  stmt->cur_iter = 0;
  return SEER_OK;
}

SeerStatus seer_stmt_bind_row(SeerStmt *stmt, int row)
{
  if (stmt == NULL || row < 0 || row >= (stmt->n_iters > 0 ? stmt->n_iters : 1))
    return SEER_EPARAM;
  stmt->cur_iter = row;
  return SEER_OK;
}

SeerStatus seer_stmt_set_batch_errors(SeerStmt *stmt, int on)
{
  if (stmt == NULL)
    return SEER_EPARAM;
  stmt->batch_errors = (on != 0);
  return SEER_OK;
}

SeerStatus seer_stmt_set_array_dml_rowcounts(SeerStmt *stmt, int on)
{
  if (stmt == NULL)
    return SEER_EPARAM;
  stmt->want_dml_rowcounts = (on != 0);
  return SEER_OK;
}

size_t seer_stmt_array_dml_rowcount_count(SeerStmt *stmt)
{
  return stmt ? stmt->n_dml_rowcounts : 0;
}

/* Per-iteration affected-row count for array-DML iteration `i` (0-based), or 0
 * if out of range / not captured. */
unsigned seer_stmt_array_dml_rowcount(SeerStmt *stmt, size_t i)
{
  if (stmt == NULL || i >= stmt->n_dml_rowcounts)
    return 0;
  return stmt->dml_rowcounts[i];
}

size_t seer_stmt_batch_error_count(SeerStmt *stmt)
{
  return stmt ? stmt->nberrs : 0;
}

SeerStatus seer_stmt_batch_error(SeerStmt *stmt, size_t i, unsigned *row, unsigned *code,
                                 const char **message)
{
  if (stmt == NULL || i >= stmt->nberrs)
    return SEER_EPARAM;
  if (row != NULL)
    *row = stmt->berrs[i].row;
  if (code != NULL)
    *code = stmt->berrs[i].code;
  if (message != NULL)
    *message = stmt->berrs[i].message;
  return SEER_OK;
}

/* ------------------------------------------------------------ exec message */

/* Statement class - drives the execute options, All8 array, and long-max. */
typedef enum { STMT_SELECT, STMT_BLOCK, STMT_CHANGE } StmtKind;

/* Skip what can precede a statement's first keyword: whitespace, `--` and
 * block comments, PL/SQL `<<labels>>`, and the opening parentheses of a
 * "(SELECT ...)". The first keyword decides the execute options, so hiding it
 * behind a comment misclassified the statement. */
static const char *sql_first_keyword(const char *p)
{
  for (;;) {
    while (*p != '\0' && isspace((unsigned char)*p))
      p++;
    if (p[0] == '-' && p[1] == '-') {
      while (*p != '\0' && *p != '\n')
        p++;
    } else if (p[0] == '/' && p[1] == '*') {
      const char *e = strstr(p + 2, "*/");
      p = e ? e + 2 : p + strlen(p);
    } else if (p[0] == '<' && p[1] == '<') {
      const char *e = strstr(p + 2, ">>");
      p = e ? e + 2 : p + strlen(p);
    } else if (*p == '(') {
      p++;
    } else {
      return p;
    }
  }
}

static bool starts_with_word(const char *p, const char *kw)
{
  size_t n = strlen(kw);
  return strncasecmp(p, kw, n) == 0 && !isalnum((unsigned char)p[n]) && p[n] != '_';
}

/* Classify by the leading keyword: SELECT/WITH are queries; BEGIN/DECLARE
 * blocks and CALL are PL/SQL (a CALL ... INTO's target is an ordinary OUT
 * bind - read as DML RETURNING, the client sent no value and the call hung);
 * everything else (DML, DDL) is a "change". */
static StmtKind classify_sql(const char *sql);

static bool sql_is_block(const char *sql)
{
  return sql != NULL && classify_sql(sql) == STMT_BLOCK;
}

static StmtKind classify_sql(const char *sql)
{
  const char *p = sql_first_keyword(sql);
  if (starts_with_word(p, "SELECT") || starts_with_word(p, "WITH"))
    return STMT_SELECT;
  if (starts_with_word(p, "BEGIN") || starts_with_word(p, "DECLARE") || starts_with_word(p, "CALL"))
    return STMT_BLOCK;
  return STMT_CHANGE;
}

/* Whether a statement may have changed the session's time zone: an ALTER
 * SESSION, or a PL/SQL block naming TIME_ZONE (EXECUTE IMMEDIATE, or
 * DBMS_SESSION.SET_TIME_ZONE). A false alarm costs one query when an LTZ
 * value is next read; a miss leaves the old shift (#358). */
static bool may_set_time_zone(const char *sql)
{
  if (sql == NULL)
    return false;
  const char *p = sql_first_keyword(sql);
  if (starts_with_word(p, "ALTER"))
    return starts_with_word(sql_first_keyword(p + 5), "SESSION");
  if (classify_sql(sql) != STMT_BLOCK)
    return false;
  static const char KW[] = "TIME_ZONE";
  for (const char *q = sql; *q; q++)
    if (strncasecmp(q, KW, sizeof KW - 1) == 0)
      return true;
  return false;
}

/* Whether `sql`'s parsed cursor is safe to keep in the statement cache and
 * re-execute without a re-parse. DDL (and anything not SELECT/WITH, DML or a
 * PL/SQL block) is excluded: a no-parse re-execute of e.g. CREATE/DROP does not
 * actually re-run the DDL. */
static bool sql_is_cacheable(const char *sql)
{
  const char *p = sql_first_keyword(sql);
  static const char *const kw[] = {"SELECT", "WITH",  "INSERT", "UPDATE",
                                   "DELETE", "MERGE", "BEGIN",  "DECLARE"};
  for (size_t i = 0; i < sizeof kw / sizeof kw[0]; i++)
    if (starts_with_word(p, kw[i]))
      return true;
  return false;
}

/* Emit one OAC bind descriptor. The 12c+ form (oracledb _write_column_metadata)
 * is differently shaped from 11g's encode_token_raw - a USE_INDICATORS flag
 * byte, a ub8 cont-flag, OID/version, the charset as a ub2 with its csfrm, a LOB
 * prefetch length and (12.2+ only) a trailing oaccolid - and an 11g-shaped OAC to
 * a 12c server is rejected (ORA-03115). The 12c shape starts at 12.1; only the
 * oaccolid waits for 12.2: a 12.1 session sent it answers ORA-03106, one sent
 * the 11g shape ORA-03120 (seerdb/seerdb@50f0a83). */
/* One bind or define descriptor by SEER_OAC_SCHEMA (#398): at 8i's widths, or
 * thin's at field version `fv`. The values are the caller's. */
static void oac_write(SeerWriter *w, bool is_8i, uint8_t fv, const SeerOacMsg *m)
{
  SeerSchemaCtx cx = is_8i ? seer_msg_ctx(1, 0, 0) : seer_msg_ctx(0, fv, fv);
  seer_schema_encode(SEER_OAC_SCHEMA, &cx, m, w);
}

/* A bind value by SEER_CHR_SCHEMA (#398): at 8i's widths, or thin's at
 * field version `fv`. No bytes is the empty value, a NULL. */
static void chr_write(SeerWriter *w, bool is_8i, uint8_t fv, const uint8_t *p, size_t n)
{
  SeerSchemaCtx cx = is_8i ? seer_msg_ctx(1, 0, 0) : seer_msg_ctx(0, fv, fv);
  SeerChrMsg m = {.value = {.p = p, .n = n}};
  seer_schema_encode(SEER_CHR_SCHEMA, &cx, &m, w);
}

/* One of 8i's fixed slots (SEER_O8I_OUT_SLOT_SCHEMA, _CURSOR_SLOT_SCHEMA). */
static void o8i_slot(SeerWriter *w, const SeerField *schema)
{
  SeerSchemaCtx cx = seer_msg_ctx(1, 0, 0);
  SeerChrMsg none = {0};
  seer_schema_encode(schema, &cx, &none, w);
}

/* An associative array's element count, as SEER_OUT_ARRAY_SCHEMA reads it. */
static void aa_count(SeerWriter *w, bool is_8i, uint8_t fv, int n)
{
  SeerSchemaCtx cx = is_8i ? seer_msg_ctx(1, 0, 0) : seer_msg_ctx(0, fv, fv);
  SeerOutArrayMsg m = {.count = n};
  seer_schema_encode(SEER_OUT_ARRAY_SCHEMA, &cx, &m, w);
}

static void emit_oac(SeerWriter *w, int fv, uint8_t dtype, uint32_t length, uint32_t flag,
                     uint32_t charset)
{
  /* The values 10g+ sends; the layout is SEER_OAC_SCHEMA's (#395). From 12.1
   * a charset is AL32UTF8 / AL16UTF16 / none with its form, and the flags are
   * TNS_BIND_USE_INDICATORS; before, the caller's charset and continuation
   * flag, form 2 for AL16UTF16 and 1 otherwise. */
  SeerOacMsg m = {.data_type = dtype, .max_length = length};
  if (fv >= TTC_FIELD_VERSION_12_1) {
    m.flags = 1;
    m.charset = charset == 0 ? 0 : charset == 2000 ? 2000 : 873;
    m.csfrm = charset == 0 ? 0 : charset == 2000 ? 2 : 1;
  } else {
    m.flags = 3;
    m.cont_flags = flag;
    m.charset = charset;
    m.csfrm = charset == 2000 ? 2 : 1;
  }
  oac_write(w, false, (uint8_t)fv, &m);
}

/* The LOB type a DML RETURNING target is declared as, or 0. A VARCHAR / RAW
 * return bind can't receive more than 4000 bytes of a CLOB / BLOB (ORA-22835
 * "buffer too small", even declared as LONG), so a target declared larger goes
 * out as a CLOB / BLOB: the server returns the LOB block and its content is
 * read through the locator. */
static uint8_t returning_lob_type(const SeerStmt *stmt, const SeerBind *b)
{
  if (!stmt->returning || !b->is_out || b->oac_size <= 4000)
    return 0;
  if (b->oac_type == ORA_TYPE_VARCHAR)
    return ORA_TYPE_CLOB;
  if (b->oac_type == ORA_TYPE_RAW)
    return ORA_TYPE_BLOB;
  return 0;
}

/* The CLOB / BLOB bind OAC: 12.1+ sets the LOB cont-flag 0x02000000, and every
 * form announces a max length of 112 - the LOB buffer-size factor, not the
 * value's size (seerdb _encode_lob_bind_oac). */
static void emit_lob_oac(SeerWriter *w, int fv, uint8_t lob_type)
{
  bool clob = lob_type == ORA_TYPE_CLOB;
  if (fv < TTC_FIELD_VERSION_12_1) { /* 11g layout: no cont-flag field */
    emit_oac(w, fv, lob_type, 112, 0, clob ? 873 : 0);
    return;
  }
  SeerOacMsg m = {.data_type = lob_type,
                  .flags = 1, /* TNS_BIND_USE_INDICATORS */
                  .max_length = 112,
                  .cont_flags = 0x02000000, /* LOB */
                  .charset = clob ? 873 : 0,
                  .csfrm = clob ? 1 : 0};
  oac_write(w, false, (uint8_t)fv, &m);
}

static SeerStatus build_exec(SeerStmt *stmt, SeerWriter *w)
{
  size_t qlen = strlen(stmt->sql);
  int nb = stmt->npbinds;
  StmtKind kind = classify_sql(stmt->sql);
  /* Array binding (iteration count > 1) applies to DML/DDL only. */
  int iters = (kind == STMT_CHANGE && stmt->n_iters > 1) ? stmt->n_iters : 1;
  if (!seer_writer_init(w, 160 + qlen + (size_t)iters * 32))
    return SEER_ENOMEM;

  /* Per statement class (PROTOCOL.md §5.1): a SELECT parses+executes+fetches
   * (0x8021, All8 type 1, LONG-max all-ones); a PL/SQL block uses the PL/SQL
   * option set (0x0421); DML/DDL uses 0x8021 with All8 type 0. Binds add
   * 0x8; autocommit adds 0x100 (not on a SELECT - nothing to commit). */
  uint32_t opt = (kind == STMT_BLOCK) ? 0x0421u : 0x8021u;
  /* A describe-only parse (seer_stmt_describe): PARSE | DESCRIBE, no EXECUTE,
   * and no binds - it carries no values however many placeholders there are. */
  if (stmt->describe_only) {
    opt = 0x20001u;
    nb = 0;
  }
  if (nb > 0)
    opt |= 0x0008u;
  if (kind != STMT_SELECT && stmt->conn->autocommit)
    opt |= 0x0100u;
  /* Array-DML batcherrors (§5.1): a per-row error no longer aborts the batch;
   * the good rows apply and the failures come back in the OER batch arrays. */
  if (stmt->batch_errors && kind == STMT_CHANGE && iters > 1)
    opt |= 0x80000u;

  /* DML RETURNING ... INTO: a DML with OUT binds. Those binds are the RETURNING
   * targets - the server fills them, so they get an OAC but no RXD value, and
   * their values come back in a return RXD. */
  bool has_out = false;
  for (int i = 0; i < nb; i++)
    if (stmt->pbinds[i].is_out) {
      has_out = true;
      break;
    }
  stmt->returning = (kind == STMT_CHANGE) && has_out;

  /* Array-DML per-iteration row counts (12c+): al8i4[9] = 0xC000 plus the
   * al8pidmlrc iteration count below; the server then returns one row count per
   * iteration in the response RPA. */
  bool dml_rowcounts = stmt->want_dml_rowcounts && kind == STMT_CHANGE && iters > 1 &&
                       stmt->conn->field_version >= TTC_FIELD_VERSION_12_1;

  uint32_t lmax = (kind == STMT_SELECT) ? 0xFFFFFFFFu : 0u;
  uint32_t all8[13] = {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  if (kind == STMT_SELECT)
    all8[7] = 1; /* type = SELECT          */
  else
    all8[1] = (uint32_t)iters; /* iteration count (rows) */
  if (dml_rowcounts)
    all8[9] = TNS_AL8I4_ARRAY_DML_ROWCOUNTS;

  /* fv24 (23ai) SELECT/fetch execute (PROTOCOL.md §20): the LONG-max sentinel
   * 0xFFFFFFFF must be 0 (else ORA-03120), and the fetch flags options |= 0x40
   * and al8i4[9] |= 0x8000 are required. Setting those flags on a DML/DDL
   * execute instead is rejected (ORA-03137 kpoal8Check-5). */
  if (stmt->conn->field_version > TTC_FIELD_VERSION_23_1 && kind == STMT_SELECT) {
    lmax = 0;
    if (!stmt->describe_only) { /* a parse must not ask to fetch (ORA-01002) */
      opt |= 0x40u;
      all8[9] |= 0x8000u;
    }
  }
  /* A PL/SQL block (12c+) requests implicit result sets (DBMS_SQL.RETURN_RESULT)
   * via al8i4[9] |= 0x8000; the server returns a TTI_IRD token only if the block
   * actually emitted any, so this is harmless on a plain block. */
  if (stmt->conn->field_version >= TTC_FIELD_VERSION_12_1 && kind == STMT_BLOCK)
    all8[9] |= TNS_AL8I4_IMPLICIT_RESULTSET;

  /* Flush an armed request-boundary marker (§35) as a func-176 piggyback in
   * front of this execute (REQUEST_BEGIN rides the first op, no round-trip). */
  SeerConn *c = stmt->conn;
  seer_ttc_flush_session_state(c, w);

  /* Flush any closed statements' server cursors as a CLOSE_CURSORS piggyback in
   * front of this execute, so they don't leak until session end. */
  if (c->n_close > 0) {
    SeerSchemaCtx cx = seer_msg_ctx(0, c->field_version, c->server_field_version);
    SeerFunHeadMsg h = {
        .type = TTI_MSG_TYPE_PIGGYBACK, .function = TTI_OCCA, .seq = seer_ttc_next_seq(c)};
    SeerCloseCursorsMsg cc = {.list_ptr = 1, .ids = c->close_cursors, .n = c->n_close};
    seer_schema_encode(SEER_FUN_HEAD_SCHEMA, &cx, &h, w);
    seer_schema_encode(SEER_CLOSE_CURSORS_SCHEMA, &cx, &cc, w);
    c->n_close = 0;
  }

  /* Free temporary LOBs no bind references any more, the same way: a
   * TTI_LOBOPS piggyback - the FREE_TEMP field block with the ARRAY bit on
   * the operation (0x80111), the source length the locators' total, and the
   * locators behind it, each ub2-prefixed (seerdb PROTOCOL.md §14.5, captured
   * off a 23ai python-oracledb session). */
  if (c->n_free_lobs > 0) {
    size_t total = 0;
    for (int i = 0; i < c->n_free_lobs; i++)
      total += 2 + c->free_lob_lens[i];
    /* SEER_LOBOPS_SCHEMA (#398): FREE_TEMP with the ARRAY bit, the source
     * length the locators' total, the locators each ub2-prefixed. */
    SeerWriter locs;
    if (!seer_writer_init(&locs, total + 1))
      return SEER_ENOMEM;
    SeerSchemaCtx lcx = seer_msg_ctx(0, c->field_version, c->server_field_version);
    for (int i = 0; i < c->n_free_lobs; i++) { /* SEER_LOCATOR_ITEM_SCHEMA each */
      SeerLocatorItemMsg li = {.len = (int64_t)c->free_lob_lens[i],
                               .locator = {.p = c->free_lobs[i], .n = c->free_lob_lens[i]}};
      seer_schema_encode(SEER_LOCATOR_ITEM_SCHEMA, &lcx, &li, &locs);
      free(c->free_lobs[i]);
    }
    c->n_free_lobs = 0;
    SeerFunHeadMsg lh = {
        .type = TTI_MSG_TYPE_PIGGYBACK, .function = TTI_LOBOPS, .seq = seer_ttc_next_seq(c)};
    SeerLobopMsg lm = {.src_ptr = 1,
                       .src_len = (int64_t)total,
                       .op = LOB_OP_FREE_TEMP | LOB_OP_ARRAY,
                       .loc_len = (int64_t)locs.len,
                       .locator = {.p = locs.buf, .n = locs.len}};
    seer_schema_encode(SEER_FUN_HEAD_SCHEMA, &lcx, &lh, w);
    seer_schema_encode(SEER_LOBOPS_SCHEMA, &lcx, &lm, w);
    seer_writer_free(&locs);
  }

  /* Statement-cache reuse: re-execute a parsed cursor with no re-parse - send
   * the cached cursor id, drop the PARSE option bit, and omit the SQL text. */
  bool reuse = stmt->reuse_cursor > 0;
  if (reuse)
    opt &= ~0x0001u; /* PARSE off                    */

  /* The SQL text goes by SF_SQL (#398), framed as the field version wants;
   * a no-parse re-execute has no sql_ptr and sends none, where even a zero
   * length would shift the server's read of the al8i4 array. */
  /* SEER_ALL8_SCHEMA (#398). 12c+ carries al8pidmlrc (12.1+), the SQL-id
   * slot (12.2+) and the 12.2_EXT1 chunk ids - all null for us; without them
   * the server reads al8i4 at the wrong offset (ORA-03120; gating the tail
   * on 12.2 sent a 12.1 session the 11g shape, seerdb/seerdb@50f0a83). A
   * server but 10g takes five more register bytes. */
  seer_ttc_fun_header(stmt->conn, w, TTI_ALL8);
  SeerAll8Msg am = {
      .options = opt,
      .cursor = reuse ? stmt->reuse_cursor : 0,
      .sql_ptr = reuse ? 0 : 1,
      .sql_len = reuse ? 0 : (int64_t)qlen,
      .al8i4_ptr = 1,
      .al8i4_len = 13,
      .prefetch_size = lmax,
      .prefetch_rows = stmt->describe_only ? 1 : (stmt->prefetch ? stmt->prefetch : PREFETCH_ROWS),
      .max_long = 0x7FFFFFFF,
      .binds_ptr = nb > 0,
      .bind_count = nb,
      .reg2 = 1,
      .register_tail = (stmt->conn->server_release >> 24) != 10,
      .pidmlrc_ptr = dml_rowcounts,
      .pidmlrc_len = dml_rowcounts ? 1 + iters : 0, /* al8pidmlrc: 1 + the iterations */
      .pidmlrc_ptr2 = dml_rowcounts,
      .sql = {.p = (const uint8_t *)stmt->sql, .n = reuse ? 0 : qlen},
      .al8i4 = all8,
      .al8i4_n = 13,
  };
  SeerSchemaCtx acx = seer_msg_ctx(0, stmt->conn->field_version, stmt->conn->server_field_version);
  seer_schema_encode(SEER_ALL8_SCHEMA, &acx, &am, w);

  /* Bind section: one OAC descriptor per bind position (sized to the widest
   * value across iterations), then one RXD token per iteration carrying that
   * row's values (PROTOCOL.md §5.3-5.4; array DML §5.5). */
  if (nb > 0) {
    for (int i = 0; i < nb; i++) {
      SeerBind *b = &stmt->pbinds[i];
      int fv = stmt->conn->field_version;
      if (b->oac_override != NULL) /* SQL OBJECT: prebuilt OAC */
        seer_writer_bytes(w, b->oac_override, b->oac_override_len);
      else if (b->oac_type == 0)
        emit_oac(w, fv, ORA_TYPE_VARCHAR, 1, 16, 873); /* unbound -> NULL VARCHAR */
      else if ((b->ret_lob = returning_lob_type(stmt, b)) != 0)
        emit_lob_oac(w, fv, b->ret_lob);
      else
        emit_oac(w, fv, b->oac_type, b->oac_size ? b->oac_size : 1, b->oac_flag, b->oac_charset);
    }
    /* In a SQL statement the server reads each row's LONG-class values after
     * all its other values, whatever their bind positions; a PL/SQL block
     * takes them in order. A bind is LONG-class when its descriptor declares
     * more than the server's maximum string size (4000, or 32767 on a server
     * with 32K strings) - so a 5000-byte text is LONG-class on 11g but an
     * ordinary value on a 12c+ server. Written in position order, a large text
     * bind ahead of another bind lost the row. */
    uint32_t max_str = stmt->conn->max_string_size ? stmt->conn->max_string_size : 4000;
    int passes = (kind == STMT_BLOCK) ? 1 : 2;
    /* A DML RETURNING whose every bind is a return bind has no input row: the
     * request carries no TTI_RXD at all (the iteration count rides in
     * al8i4[1]). An empty one drew ORA-03146 on 12c+, and on 11g left the
     * server out of step so it dropped the session on the next call. */
    int n_in = 0;
    for (int i = 0; i < nb; i++)
      if (!(stmt->returning && stmt->pbinds[i].is_out))
        n_in++;
    for (int it = 0; it < iters && n_in > 0; it++) {
      seer_writer_u8(w, TTI_RXD);
      for (int pass = 0; pass < passes; pass++) {
        for (int i = 0; i < nb; i++) {
          SeerBind *b = &stmt->pbinds[i];
          if (stmt->returning && b->is_out)
            continue; /* return bind: server-filled */
          /* A bind with a prebuilt OAC - native JSON / VECTOR, a SQL object -
           * carries its own descriptor framing and rides in place whatever
           * its size (seerdb PROTOCOL.md §17.2b): moving it last swapped it
           * with the binds after it. */
          bool long_class = b->oac_size > max_str && b->oac_override == NULL;
          if (passes == 2 && long_class != (pass == 1))
            continue;
          uint8_t *rxd = (b->rxd != NULL) ? b->rxd[it] : NULL;
          if (rxd != NULL)
            seer_writer_bytes(w, rxd, b->rxd_len[it]);
          else
            chr_write(w, false, c->field_version, NULL, 0); /* unbound: NULL */
        }
      }
    }
  }

  if (!seer_writer_ok(w)) {
    seer_writer_free(w);
    return SEER_ENOMEM;
  }
  return SEER_OK;
}

/* Whether a query's CLOB / BLOB columns are fetched inline (§14.5d): the
 * rows of a result with a LOB column come with the fetch after the execute,
 * and a DEFINE call in its place - asking for each LOB column as LONG / LONG
 * RAW - has the server put the content in the row, where each cell otherwise
 * costs a TTI_LOBOPS READ round trip. Only for results whose every other
 * column is a plain scalar the define can restate as it is; anything else
 * (NCLOB, BFILE, objects, JSON / VECTOR, ...) keeps the locator path. 12.1+,
 * where the define OAC is the bind OAC's shape. */
static bool wants_lob_define(const SeerStmt *stmt)
{
  if (!stmt->conn->lob_inline || stmt->conn->field_version < TTC_FIELD_VERSION_12_1)
    return false;
  bool any_lob = false;
  for (int i = 0; i < stmt->ncols; i++) {
    const SeerColumn *col = &stmt->cols[i];
    if (col->inline_long || col->zero_len)
      return false; /* the cursor already has its define / a bare-NULL column */
    switch (col->ora_type) {
    case ORA_TYPE_CLOB:
      if (col->charset == 2000)
        return false; /* NCLOB */
      any_lob = true;
      break;
    case ORA_TYPE_BLOB:
      any_lob = true;
      break;
    case ORA_TYPE_VARCHAR:
    case ORA_TYPE_CHAR:
    case ORA_TYPE_NUMBER:
    case ORA_TYPE_DATE:
    case ORA_TYPE_RAW:
    case ORA_TYPE_BFLOAT:
    case ORA_TYPE_BDOUBLE:
    case ORA_TYPE_TIMESTAMP:
      break;
    default:
      return false;
    }
  }
  return any_lob;
}

/* The DEFINE call (§14.5d): an OALL8 with the DEFINE option alone on the
 * executed cursor - no SQL, no binds - and one OAC per column in the bind OAC
 * layout: each LOB column as LONG / LONG RAW (buffer 0x7FFFFFFF), every other
 * column as described. The server answers with the next batch of rows, the
 * LOB content inline, and the define stands for the life of the cursor. */
static SeerStatus build_define(SeerStmt *stmt, SeerWriter *w)
{
  SeerConn *c = stmt->conn;
  int fv = c->field_version;
  if (!seer_writer_init(w, 96 + (size_t)stmt->ncols * 24))
    return SEER_ENOMEM;
  /* SEER_ALL8_SCHEMA with the DEFINE option alone (#398): no SQL, no binds,
   * a define a column */
  seer_ttc_fun_header(c, w, TTI_ALL8);
  uint32_t all8[13] = {0};
  all8[1] = PREFETCH_ROWS; /* rows to return */
  all8[7] = 1;             /* a query */
  SeerAll8Msg am = {
      .options = 0x8010u, /* NOT_PLSQL | DEFINE */
      .cursor = stmt->cursor_id,
      .al8i4_ptr = 1,
      .al8i4_len = 13,
      .prefetch_size = fv > TTC_FIELD_VERSION_23_1 ? 0 : 0xFFFFFFFFu,
      .prefetch_rows = PREFETCH_ROWS,
      .max_long = 0x7FFFFFFF,
      .defines_ptr = 1,
      .define_count = stmt->ncols,
      .reg2 = 1,
      .register_tail = (c->server_release >> 24) != 10,
      .al8i4 = all8,
      .al8i4_n = 13,
  };
  SeerSchemaCtx cx = seer_msg_ctx(0, c->field_version, c->server_field_version);
  seer_schema_encode(SEER_ALL8_SCHEMA, &cx, &am, w);
  for (int i = 0; i < stmt->ncols; i++) {
    const SeerColumn *col = &stmt->cols[i];
    if (col->ora_type == ORA_TYPE_CLOB) /* as LONG, in the database charset */
      emit_oac(w, fv, ORA_TYPE_LONG, 0x7FFFFFFF, 1, 873);
    else if (col->ora_type == ORA_TYPE_BLOB)
      emit_oac(w, fv, ORA_TYPE_LONGRAW, 0x7FFFFFFF, 1, 0);
    else
      emit_oac(w, fv, col->ora_type, col->max_size ? col->max_size : 1, 1,
               col->charset == 2000 ? 2000 : (col->charset ? 873 : 0));
  }
  if (!seer_writer_ok(w)) {
    seer_writer_free(w);
    return SEER_ENOMEM;
  }
  return SEER_OK;
}

static SeerStatus build_fetch(SeerStmt *stmt, SeerWriter *w)
{
  if (!seer_writer_init(w, 16))
    return SEER_ENOMEM;
  seer_ttc_fun_header(stmt->conn, w, TTI_FETCH);
  SeerFetchMsg m = {.cursor = stmt->cursor_id, .rows = PREFETCH_ROWS}; /* #398 */
  SeerSchemaCtx cx = seer_msg_ctx(0, stmt->conn->field_version, stmt->conn->server_field_version);
  seer_schema_encode(SEER_FETCH_SCHEMA, &cx, &m, w);
  if (!seer_writer_ok(w)) {
    seer_writer_free(w);
    return SEER_ENOMEM;
  }
  return SEER_OK;
}

/* A fetch from a cursor the statement holds no SQL for - a REF CURSOR, an
 * implicit result: an OALL8 on its id with no statement and the options
 * NOT_PLSQL | FETCH (0x8040), as python-oracledb and OCI send it. 10g..21c
 * answer a TTI_FETCH on such a cursor with each CURSOR() cell of its rows cut
 * to `02 <ub4 id>`, no inline describe, which desyncs the row; to this call
 * every server sends the full cell. It carries no piggybacks, as a TTI_FETCH
 * carries none: the close queue may hold the cursor's own parent, and closing
 * that first closes this one (seerdb PROTOCOL.md §5.1, #1462). */
static SeerStatus build_fetch_only(SeerStmt *stmt, SeerWriter *w)
{
  SeerConn *c = stmt->conn;
  if (!seer_writer_init(w, 64))
    return SEER_ENOMEM;
  /* SEER_ALL8_SCHEMA with the FETCH option alone (#398): no SQL, no binds,
   * a query's rows */
  seer_ttc_fun_header(c, w, TTI_ALL8);
  uint32_t all8[13] = {0};
  all8[1] = PREFETCH_ROWS; /* rows to return */
  all8[7] = 1;             /* a query */
  SeerAll8Msg am = {
      .options = 0x8040u, /* NOT_PLSQL | FETCH */
      .cursor = stmt->cursor_id,
      .al8i4_ptr = 1,
      .al8i4_len = 13,
      .prefetch_rows = PREFETCH_ROWS,
      .max_long = 0x7FFFFFFF,
      .reg2 = 1,
      .register_tail = (c->server_release >> 24) != 10,
      .al8i4 = all8,
      .al8i4_n = 13,
  };
  SeerSchemaCtx cx = seer_msg_ctx(0, c->field_version, c->server_field_version);
  seer_schema_encode(SEER_ALL8_SCHEMA, &cx, &am, w);
  if (!seer_writer_ok(w)) {
    seer_writer_free(w);
    return SEER_ENOMEM;
  }
  return SEER_OK;
}

/* The call that fetches a query's next rows: a plain TTI_FETCH - or, for a
 * result with LOB columns whose rows have not started, the DEFINE call, from
 * which on those columns come inline as LONG / LONG RAW. The columns are
 * marked to read them that way; the statement cache keeps them with the
 * cursor, which keeps its define. */
static SeerStatus build_next_fetch(SeerStmt *stmt, SeerWriter *w)
{
  if (stmt->nrows > 0 || !wants_lob_define(stmt))
    return stmt->fetch_by_oall8 ? build_fetch_only(stmt, w) : build_fetch(stmt, w);
  for (int i = 0; i < stmt->ncols; i++)
    if (stmt->cols[i].ora_type == ORA_TYPE_CLOB || stmt->cols[i].ora_type == ORA_TYPE_BLOB)
      stmt->cols[i].inline_long = true;
  return build_define(stmt, w);
}

/* Queue a server cursor to be closed with the next call's CLOSE_CURSORS
 * piggyback. */
static void queue_cursor_close(SeerConn *c, int64_t cursor_id)
{
  if (cursor_id > 0 && c->n_close < (int)(sizeof c->close_cursors / sizeof c->close_cursors[0]))
    c->close_cursors[c->n_close++] = (int)cursor_id;
}

/* ------------------------------------------------------------- public API */

/* Whether a cached cursor's error says the cursor itself is stale, so a fresh
 * parse may succeed (#210): the object or a column gone or retyped, a package
 * state discarded, the cursor invalid. */
static bool stale_cursor_error(int64_t code)
{
  switch (code) {
  case 904:  /* invalid identifier */
  case 932:  /* inconsistent datatypes */
  case 942:  /* table or view does not exist */
  case 1001: /* invalid cursor */
  case 1003: /* no statement parsed */
  case 1007: /* variable not in select list */
  case 4061: /* existing state of the package has been invalidated */
  case 4065: /* not executed, the package has been altered or dropped */
  case 4068: /* existing state of packages has been discarded */
    return true;
  default:
    return false;
  }
}

/* What a cursor's parse depends on in its binds: each one's type, charset
 * form and direction. In SELECT :1 a BINARY_DOUBLE bind makes column 1 a
 * BINARY_DOUBLE; re-executed with an int or text bind, the cached cursor and
 * its describe no longer fit the reply - a protocol error, or a value decoded
 * as the wrong type (#162). Malloc'd; "" for a statement without binds. */
static char *bind_signature(const SeerStmt *stmt)
{
  size_t cap = 1 + (size_t)stmt->npbinds * 24;
  char *sig = malloc(cap);
  if (sig == NULL)
    return NULL;
  size_t n = 0;
  sig[0] = '\0';
  for (int i = 0; i < stmt->npbinds; i++) {
    const SeerBind *b = &stmt->pbinds[i];
    int w = snprintf(sig + n, cap - n, "%u.%u.%d.%d;", b->oac_type, b->oac_charset,
                     b->is_out ? 1 : 0, b->is_array ? 1 : 0);
    if (w < 0 || (size_t)w >= cap - n)
      break;
    n += (size_t)w;
  }
  return sig;
}

/* Statement cache. take() returns a cached parsed cursor for `sql`, moving its
 * SELECT column describe out into cols/ncols, and removes the entry (the caller
 * now owns the cursor + columns). Returns 0 (and leaves *cols NULL) if not cached. */
static int stmt_cache_take(SeerConn *c, const char *sql, SeerColumn **cols, int *ncols,
                           char **binds)
{
  for (int i = 0; i < c->stmt_cache_n; i++) {
    if (strcmp(c->stmt_cache[i].sql, sql) == 0) {
      int cid = c->stmt_cache[i].cursor_id;
      *cols = (SeerColumn *)c->stmt_cache[i].cols;
      *ncols = c->stmt_cache[i].ncols;
      *binds = c->stmt_cache[i].binds;
      free(c->stmt_cache[i].sql);
      c->stmt_cache[i] = c->stmt_cache[c->stmt_cache_n - 1];
      c->stmt_cache_n--;
      return cid;
    }
  }
  return 0;
}

/* put() caches (sql, cursor_id) and takes ownership of the describe cols; when
 * full, evicts the oldest entry (queues its cursor to close, frees its cols). */
static void stmt_cache_put(SeerConn *c, const char *sql, int cursor_id, SeerColumn *cols, int ncols,
                           char *binds)
{
  int cap = (int)(sizeof c->stmt_cache / sizeof c->stmt_cache[0]);
  int nclose = (int)(sizeof c->close_cursors / sizeof c->close_cursors[0]);
  if (c->stmt_cache_n >= cap) {
    if (c->n_close < nclose)
      c->close_cursors[c->n_close++] = c->stmt_cache[0].cursor_id;
    free(c->stmt_cache[0].sql);
    free(c->stmt_cache[0].binds);
    free_columns((SeerColumn *)c->stmt_cache[0].cols, c->stmt_cache[0].ncols);
    memmove(&c->stmt_cache[0], &c->stmt_cache[1],
            (size_t)(c->stmt_cache_n - 1) * sizeof c->stmt_cache[0]);
    c->stmt_cache_n--;
  }
  char *dup = strdup(sql);
  if (dup == NULL) { /* can't cache -> close + free */
    if (c->n_close < nclose)
      c->close_cursors[c->n_close++] = cursor_id;
    free_columns(cols, ncols);
    free(binds);
    return;
  }
  c->stmt_cache[c->stmt_cache_n].sql = dup;
  c->stmt_cache[c->stmt_cache_n].binds = binds;
  c->stmt_cache[c->stmt_cache_n].cursor_id = cursor_id;
  c->stmt_cache[c->stmt_cache_n].cols = cols;
  c->stmt_cache[c->stmt_cache_n].ncols = ncols;
  c->stmt_cache_n++;
}

/* Drop every cached cursor (queuing each to be closed) and its describe. Called
 * when a DDL executes on this connection: it can invalidate cached cursors, and a
 * stale cursor reused after the object is recreated returns wrong results rather
 * than a clean error we could retry. */
static void stmt_cache_flush(SeerConn *c)
{
  int nclose = (int)(sizeof c->close_cursors / sizeof c->close_cursors[0]);
  for (int i = 0; i < c->stmt_cache_n; i++) {
    if (c->n_close < nclose)
      c->close_cursors[c->n_close++] = c->stmt_cache[i].cursor_id;
    free(c->stmt_cache[i].sql);
    free(c->stmt_cache[i].binds);
    free_columns((SeerColumn *)c->stmt_cache[i].cols, c->stmt_cache[i].ncols);
  }
  c->stmt_cache_n = 0;
}

void seer_stmt_cache_clear(SeerConn *conn)
{
  if (conn == NULL)
    return;
  for (int i = 0; i < conn->stmt_cache_n; i++) {
    free(conn->stmt_cache[i].sql);
    free(conn->stmt_cache[i].binds);
    free_columns((SeerColumn *)conn->stmt_cache[i].cols, conn->stmt_cache[i].ncols);
  }
  conn->stmt_cache_n = 0;
}

SeerStatus seer_stmt_prepare(SeerConn *conn, const char *sql, SeerStmt **out)
{
  if (conn == NULL || sql == NULL || out == NULL)
    return SEER_EPARAM;
  *out = NULL;

  SeerStmt *s = calloc(1, sizeof *s);
  if (s == NULL)
    return SEER_ENOMEM;
  s->conn = conn;
  s->sql = strdup(sql);
  s->cur = -1;
  s->n_iters = 1;
  /* Reuse a cached parsed cursor (and its describe) for this exact SQL, if any. */
  s->reuse_cursor = stmt_cache_take(conn, sql, &s->cols, &s->ncols, &s->reuse_binds);
  if (s->sql == NULL) {
    free(s);
    return SEER_ENOMEM;
  }
  *out = s;
  return SEER_OK;
}

/* Free the buffered result rows and reset the cursor position. */
static void free_rows(SeerStmt *stmt)
{
  for (size_t i = 0; i < stmt->ncell_errs; i++)
    free(stmt->cell_errs[i].message);
  free(stmt->cell_errs);
  stmt->cell_errs = NULL;
  stmt->ncell_errs = 0;
  for (size_t r = 0; r < stmt->nrows; r++) {
    for (int c = 0; c < stmt->ncols; c++)
      free(stmt->rows[r][c].data);
    free(stmt->rows[r]);
  }
  free(stmt->rows);
  stmt->rows = NULL;
  stmt->nrows = 0;
  stmt->rows_cap = 0;
  stmt->cur = -1;
}

/* Discard any pending (unresolved) LOB cells. */
static void free_pending_lobs(SeerStmt *stmt)
{
  for (size_t k = 0; k < stmt->nplobs; k++)
    free(stmt->plobs[k].locator);
  free(stmt->plobs);
  stmt->plobs = NULL;
  stmt->nplobs = 0;
  stmt->plobs_cap = 0;
}

static void free_pending_objs(SeerStmt *stmt)
{
  for (size_t k = 0; k < stmt->npobjs; k++)
    free(stmt->pobjs[k].image);
  free(stmt->pobjs);
  stmt->pobjs = NULL;
  stmt->npobjs = 0;
  stmt->pobjs_cap = 0;
}

/* Map an ALL_TYPE_ATTRS attr_type_name to the Oracle wire type used inside an
 * object image (the subset slice 1 decodes; unknowns fall back to text). */
/* Pseudo type in an object layout (not an Oracle wire type): an XMLType
 * attribute. Its image field is an XMLType image, decoded like an XMLType
 * column - not a nested object to splice (XMLTYPE has no attributes of its
 * own, so splicing it dropped a slot and shifted every later attribute). */
#define OBJ_ATTR_XMLTYPE 0xF0
/* Pseudo type: a national (NCHAR / NVARCHAR2) attribute or collection element.
 * Its image field carries AL16UTF16 (UTF-16BE), as a national column does,
 * where every other char field carries the session's AL32UTF8 (seerdb
 * PROTOCOL.md §21, #1433). The type name cannot tell it - 10g lists an
 * NVARCHAR2 attribute as VARCHAR2 - so it comes from CHARACTER_SET_NAME. */
#define OBJ_ATTR_NCHAR 0xF1

/* A type declared inside a PL/SQL package is named PKG.TYPE here; its metadata
 * lives in ALL_PLSQL_TYPES / _TYPE_ATTRS / _COLL_TYPES, keyed by the package as
 * well (seerdb PROTOCOL.md §21.6a). Split `name` at its dot: the type part is
 * returned and the package copied into `pkg` ("" for a schema-level type). */
static const char *type_pkg_split(const char *name, char *pkg, size_t pkgsz)
{
  pkg[0] = '\0';
  const char *dot = name != NULL ? strchr(name, '.') : NULL;
  if (dot == NULL || (size_t)(dot - name) >= pkgsz)
    return name;
  memcpy(pkg, name, (size_t)(dot - name));
  pkg[dot - name] = '\0';
  return dot + 1;
}

/* Prepare a dictionary query on a type, schema-level (`sql`, binds owner and
 * type) or package-level (`plsql_sql`, binds owner, package and type), and
 * execute it. On SEER_OK *q is the executed statement (caller closes). */
static SeerStatus type_dict_query(SeerConn *conn, const char *sql, const char *plsql_sql,
                                  const char *owner, const char *name, SeerStmt **q)
{
  char pkg[129];
  const char *tn = type_pkg_split(name, pkg, sizeof pkg);
  *q = NULL;
  SeerStatus st = seer_stmt_prepare(conn, pkg[0] ? plsql_sql : sql, q);
  int k = 1;
  if (st == SEER_OK)
    st = seer_stmt_bind_text(*q, k++, owner, -1);
  if (st == SEER_OK && pkg[0])
    st = seer_stmt_bind_text(*q, k++, pkg, -1);
  if (st == SEER_OK)
    st = seer_stmt_bind_text(*q, k, tn, -1);
  if (st == SEER_OK)
    st = seer_stmt_execute(*q);
  if (st != SEER_OK) {
    seer_stmt_close(*q);
    *q = NULL;
  }
  return st;
}

static uint8_t obj_type_to_ora(const char *tn)
{
  if (tn == NULL)
    return ORA_TYPE_VARCHAR;
  if (!strcmp(tn, "PL/SQL PLS INTEGER") || !strcmp(tn, "PL/SQL BINARY INTEGER"))
    return ORA_TYPE_BINARY_INTEGER;
  if (!strcmp(tn, "PL/SQL BOOLEAN") || !strcmp(tn, "BOOLEAN")) /* 23ai: plain BOOLEAN */
    return ORA_TYPE_BOOLEAN;
  if (!strcmp(tn, "CLOB") || !strcmp(tn, "NCLOB"))
    return ORA_TYPE_CLOB;
  if (!strcmp(tn, "BLOB"))
    return ORA_TYPE_BLOB;
  if (!strcmp(tn, "NUMBER") || !strcmp(tn, "FLOAT") || !strcmp(tn, "INTEGER"))
    return ORA_TYPE_NUMBER;
  if (!strcmp(tn, "DATE"))
    return ORA_TYPE_DATE;
  if (!strcmp(tn, "RAW"))
    return ORA_TYPE_RAW;
  if (!strcmp(tn, "CHAR") || !strcmp(tn, "NCHAR"))
    return ORA_TYPE_CHAR;
  if (!strcmp(tn, "BINARY_FLOAT"))
    return ORA_TYPE_BFLOAT;
  if (!strcmp(tn, "BINARY_DOUBLE"))
    return ORA_TYPE_BDOUBLE;
  if (!strcmp(tn, "TIMESTAMP WITH TZ"))
    return ORA_TYPE_TIMESTAMPTZ;
  if (!strcmp(tn, "TIMESTAMP WITH LOCAL TZ"))
    return ORA_TYPE_TIMESTAMPLTZ;
  if (!strncmp(tn, "TIMESTAMP", 9))
    return ORA_TYPE_TIMESTAMP;
  if (!strcmp(tn, "INTERVAL YEAR TO MONTH"))
    return ORA_TYPE_INTERVAL_YM;
  if (!strcmp(tn, "INTERVAL DAY TO SECOND"))
    return ORA_TYPE_INTERVAL_DS;
  return ORA_TYPE_VARCHAR; /* VARCHAR2/NVARCHAR2/... */
}

/* An attribute's (or element's) layout type from the dictionary's type name and
 * CHARACTER_SET_NAME: a char type whose set is NCHAR_CS is national. */
static uint8_t obj_attr_type(const char *tn, const char *csname)
{
  uint8_t t = obj_type_to_ora(tn);
  if ((t == ORA_TYPE_VARCHAR || t == ORA_TYPE_CHAR) && csname != NULL &&
      strcmp(csname, "NCHAR_CS") == 0)
    return OBJ_ATTR_NCHAR;
  return t;
}

/* Decode one scalar image field by its layout type; a national field is
 * UTF-16BE on the wire and comes back as UTF-8 text. */
static SeerStatus decode_image_scalar(uint8_t type, const uint8_t *val, size_t vlen, SeerCell *cell)
{
  if (type != OBJ_ATTR_NCHAR)
    return decode_scalar(type, val, vlen, cell);
  char *u8 = NULL;
  size_t u8len = 0;
  if (seer_iconv("UTF-16BE", "UTF-8", (const char *)val, vlen, &u8, &u8len) != 0)
    return SEER_EPROTO;
  SeerStatus st = cell_set_bytes(cell, u8, u8len, false);
  free(u8);
  return st;
}

/* Read one length prefix inside an object image: -1 for a NULL attribute (0xFF),
 * -2 on a short/overrun read, otherwise the byte length (0xFE => a 4-byte
 * big-endian length follows). Advances *pos. */
static long obj_read_len(const uint8_t *img, size_t imglen, size_t *pos)
{
  if (*pos >= imglen)
    return -2;
  uint8_t b = img[(*pos)++];
  if (b == 0xFF)
    return -1;
  if (b == 0xFE) {
    if (*pos + 4 > imglen)
      return -2;
    long n = ((long)img[*pos] << 24) | ((long)img[*pos + 1] << 16) | ((long)img[*pos + 2] << 8) |
             (long)img[*pos + 3];
    *pos += 4;
    return n;
  }
  return b;
}

/* Append one Oracle type to a growable layout array. */
/* Append one flattened attribute: its wire type to `types` and (if `elem` is
 * non-NULL) its collection element type to `elem` at the same index - 0 for a
 * plain scalar, the element wire type for a collection attribute. The two arrays
 * grow in lockstep. */
static bool append_attr(uint8_t **types, uint8_t **elem, int *n, int *cap, uint8_t t, uint8_t et)
{
  if (*n == *cap) {
    int nc = *cap ? *cap * 2 : 8;
    uint8_t *nt = realloc(*types, (size_t)nc);
    if (nt == NULL)
      return false;
    *types = nt;
    if (elem != NULL) {
      uint8_t *ne = realloc(*elem, (size_t)nc);
      if (ne == NULL)
        return false;
      *elem = ne;
    }
    *cap = nc;
  }
  (*types)[*n] = t;
  if (elem != NULL)
    (*elem)[*n] = et;
  (*n)++;
  return true;
}

/* Build the *flattened* leaf-attribute layout of an object type. An embedded
 * object attribute is stored inline in the image (no sub-header), so its leaf
 * attributes are spliced in depth-first. A user-defined attribute type (non-NULL
 * attr_type_owner) is one to recurse into; a built-in type maps to its wire type.
 * (A nested *collection* attribute would need runtime length handling - not yet
 * flattened here; it would mis-decode, so depth is bounded as a guard.) */
/* If (owner, name) is a collection type, return its element's wire type (from
 * ALL_COLL_TYPES); 0 if it is not a collection. */
static uint8_t coll_elem_wire_type(SeerConn *conn, const char *owner, const char *name)
{
  uint8_t et = 0;
  SeerStmt *q = NULL;
  if (type_dict_query(conn,
                      "SELECT elem_type_name, character_set_name FROM all_coll_types "
                      "WHERE owner = :1 AND type_name = :2",
                      "SELECT elem_type_name, character_set_name FROM all_plsql_coll_types "
                      "WHERE owner = :1 AND package_name = :2 AND type_name = :3",
                      owner, name, &q) == SEER_OK &&
      seer_stmt_fetch(q) == SEER_OK) {
    const char *en = NULL, *cs = NULL;
    int isn = 0, isn_cs = 0;
    seer_stmt_get_string(q, 0, &en, &isn);
    seer_stmt_get_string(q, 1, &cs, &isn_cs);
    et = obj_attr_type(en, isn_cs ? NULL : cs); /* non-zero (defaults VARCHAR) */
  }
  seer_stmt_close(q);
  return et;
}

/* Build a type's flattened leaf-attribute layout. A nested object attribute is
 * spliced in depth-first (its leaves inline); a nested *collection* attribute is
 * variable-length so it stays a single entry - marked in `elem` (its element wire
 * type) for decode_object_image to walk as an embedded collection image. `elem`
 * may be NULL (bind path: collection attributes aren't supported for binding). */
static void build_obj_layout(SeerConn *conn, const char *owner, const char *name, uint8_t **types,
                             uint8_t **elem, int *n, int *cap, int depth)
{
  if (depth > 8)
    return;
  /* A package-level record names its attribute types with their package
   * (attr_type_package), which goes back on as PKG.TYPE. */
  SeerStmt *q = NULL;
  if (type_dict_query(conn,
                      "SELECT attr_type_owner, NULL, attr_type_name, character_set_name "
                      "FROM all_type_attrs WHERE owner = :1 AND type_name = :2 ORDER BY attr_no",
                      "SELECT attr_type_owner, attr_type_package, attr_type_name, "
                      "character_set_name FROM all_plsql_type_attrs WHERE owner = :1 "
                      "AND package_name = :2 AND type_name = :3 ORDER BY attr_no",
                      owner, name, &q) == SEER_OK) {
    while (seer_stmt_fetch(q) == SEER_OK) {
      const char *aowner = NULL, *apkg = NULL, *atype = NULL;
      int isn = 0, isn_pkg = 0;
      seer_stmt_get_string(q, 0, &aowner, &isn);
      bool user_type = !isn && aowner != NULL && aowner[0] != '\0';
      seer_stmt_get_string(q, 1, &apkg, &isn_pkg);
      seer_stmt_get_string(q, 2, &atype, &isn);
      if (user_type) {
        char *ow = strdup(aowner);
        char *nm = NULL;
        if (!isn_pkg && apkg != NULL && apkg[0] != '\0') {
          size_t l = strlen(apkg) + 1 + strlen(atype ? atype : "") + 1;
          nm = malloc(l);
          if (nm != NULL)
            snprintf(nm, l, "%s.%s", apkg, atype ? atype : "");
        } else {
          nm = strdup(atype ? atype : "");
        }
        if (ow && nm && strcmp(ow, "SYS") == 0 && strcmp(nm, "XMLTYPE") == 0) {
          append_attr(types, elem, n, cap, OBJ_ATTR_XMLTYPE, 0);
        } else if (ow && nm) {
          uint8_t cet = coll_elem_wire_type(conn, ow, nm);
          if (cet != 0) /* collection attribute (one entry) */
            append_attr(types, elem, n, cap, ORA_TYPE_ADT, cet);
          else /* nested object: splice leaves */
            build_obj_layout(conn, ow, nm, types, elem, n, cap, depth + 1);
        }
        free(ow);
        free(nm);
      } else {
        const char *acs = NULL;
        int isn_cs = 0;
        seer_stmt_get_string(q, 3, &acs, &isn_cs);
        if (!append_attr(types, elem, n, cap, obj_attr_type(atype, isn_cs ? NULL : acs), 0))
          break;
      }
    }
  }
  seer_stmt_close(q); /* frees q itself */
}

/* Resolve a type's layout from the data dictionary into `col`. A collection
 * (VARRAY / nested table) has a single element type in ALL_COLL_TYPES; a plain
 * object has a flattened leaf-attribute list (ALL_TYPE_ATTRS, recursing into
 * embedded object attributes). Sets col->n_obj_attrs >= 0 on return (0 marks
 * "resolved, nothing to iterate" - a collection or a failed lookup - not retried). */
static void fetch_obj_layout(SeerConn *conn, SeerColumn *col)
{
  col->n_obj_attrs = 0; /* resolved (don't retry) */

  /* Collection? ALL_COLL_TYPES yields its single element type. When that element
   * is itself an object type (elem_type_owner is set), fetch the element's
   * attribute layout so decode_collection_image can decode object elements. */
  SeerStmt *q = NULL;
  if (type_dict_query(conn,
                      "SELECT elem_type_owner, NULL, elem_type_name, character_set_name "
                      "FROM all_coll_types WHERE owner = :1 AND type_name = :2",
                      "SELECT elem_type_owner, elem_type_package, elem_type_name, "
                      "character_set_name FROM all_plsql_coll_types WHERE owner = :1 "
                      "AND package_name = :2 AND type_name = :3",
                      col->type_schema, col->type_name, &q) == SEER_OK) {
    if (seer_stmt_fetch(q) == SEER_OK) {
      const char *eowner = NULL, *epkg = NULL, *et = NULL, *ecs = NULL;
      int isn_owner = 0, isn_pkg = 0, isn = 0, isn_cs = 0;
      seer_stmt_get_string(q, 0, &eowner, &isn_owner);
      seer_stmt_get_string(q, 1, &epkg, &isn_pkg);
      seer_stmt_get_string(q, 2, &et, &isn);
      seer_stmt_get_string(q, 3, &ecs, &isn_cs);
      bool national = !isn_cs && ecs != NULL && strcmp(ecs, "NCHAR_CS") == 0;
      col->is_collection = true;
      char *eo = (!isn_owner && eowner && eowner[0]) ? strdup(eowner) : NULL;
      char *en = NULL;
      if (et != NULL && !isn_pkg && epkg != NULL && epkg[0] != '\0') {
        size_t l = strlen(epkg) + strlen(et) + 2;
        en = malloc(l);
        if (en != NULL)
          snprintf(en, l, "%s.%s", epkg, et); /* a package type, as PKG.TYPE */
      } else if (et != NULL) {
        en = strdup(et);
      }
      seer_stmt_close(q);
      if (eo != NULL && en != NULL) { /* element is an object type */
        uint8_t *types = NULL;
        int n = 0, cap = 0;
        build_obj_layout(conn, eo, en, &types, NULL, &n, &cap, 0);
        col->elem_obj_types = types;
        col->n_elem_obj_attrs = n;
        col->element_type = ORA_TYPE_ADT;
      } else {
        col->element_type = obj_attr_type(en, national ? "NCHAR_CS" : NULL);
      }
      free(eo);
      free(en);
      return;
    }
    seer_stmt_close(q);
  }

  /* Otherwise a plain object: the flattened leaf-attribute types, plus the
   * parallel element-type array marking any collection attributes. */
  uint8_t *types = NULL, *elem = NULL;
  int n = 0, cap = 0;
  build_obj_layout(conn, col->type_schema, col->type_name, &types, &elem, &n, &cap, 0);
  col->obj_attr_types = types;
  col->obj_attr_elem = elem;
  col->n_obj_attrs = n;
}

/* Decode a flat SQL OBJECT image into "v1, v2, ..." text given its attribute
 * layout. Header: flags, version, image length; an optional prefix segment
 * (absent when flag 0x04 is set); then each attribute length-prefixed. */
static SeerStatus decode_collection_image(const uint8_t *img, size_t imglen, uint8_t element_type,
                                          const uint8_t *elem_obj_types, int n_elem_obj_attrs,
                                          SeerCell *cell);

/* Decode an object image into "v1, v2, ..." text. `elem`, when non-NULL, marks
 * collection attributes (elem[a] != 0 => attribute a is an embedded collection of
 * that element type, decoded as a nested "[...]"). */
static SeerStatus decode_xmltype_image(SeerConn *conn, const uint8_t *img, size_t imglen,
                                       SeerCell *cell);

/* A LOB attribute's image field is the LOB locator exactly as the server
 * minted it - a ub2 length, then that many bytes - and that ub2 is part of the
 * locator, so the whole field goes to TTI_LOBOPS like a column LOB's locator
 * (seerdb PROTOCOL.md §21.14). CLOB -> UTF-8 text, BLOB -> hex. */
static int64_t fv2_lob_getlen(SeerConn *c, const uint8_t *loc, size_t loclen);
static SeerStatus fv2_lob_read(SeerConn *c, const uint8_t *loc, size_t loclen, int64_t amount,
                               uint8_t **content, size_t *contentlen);
static SeerStatus o8i_lob_read(SeerConn *c, const uint8_t *loc, size_t loclen, SeerWriter *content);
static SeerStatus o8i_text_cell(SeerCell *cell, const uint8_t *p, size_t n);

/* A LOB attribute's content on 9i and 8i, by the locator - the same form a
 * column's has there - with that release's own LOB calls: 9i's GETLEN + READ
 * (its text in the session's charset, UTF-8), 8i's single READ (its text in
 * WE8ISO8859P1). The 10g+ read, which these took before, they answer with
 * nothing usable (#168). */
static SeerStatus decode_lob_attr_legacy(SeerConn *conn, uint8_t type, const uint8_t *f, size_t n,
                                         SeerCell *cell)
{
  bool clob = type == ORA_TYPE_CLOB;
  if (conn->is_8i) {
    SeerWriter content;
    if (!seer_writer_init(&content, 256))
      return SEER_ENOMEM;
    SeerStatus st = o8i_lob_read(conn, f, n, &content);
    if (st == SEER_OK && !seer_writer_ok(&content))
      st = SEER_ENOMEM;
    if (st == SEER_OK && clob)
      st = o8i_text_cell(cell, content.buf, content.len);
    else if (st == SEER_OK)
      cell_set_text(cell, hex_dup(content.buf, content.len)); /* as 10g+ renders a BLOB */
    seer_writer_free(&content);
    return st;
  }
  uint8_t *content = NULL;
  size_t clen = 0;
  int64_t amount = fv2_lob_getlen(conn, f, n);
  if (amount < 0)
    return SEER_EPROTO;
  if (amount > 0 && fv2_lob_read(conn, f, n, amount, &content, &clen) != SEER_OK) {
    free(content);
    return SEER_EPROTO;
  }
  SeerStatus st = SEER_OK;
  if (clob)
    st = cell_set_bytes(cell, content ? content : (const uint8_t *)"", clen, false);
  else
    cell_set_text(cell, hex_dup(content, clen)); /* as 10g+ renders a BLOB */
  free(content);
  return st;
}

static SeerStatus decode_lob_attr(SeerConn *conn, uint8_t type, const uint8_t *f, size_t n,
                                  SeerCell *cell)
{
  if (conn == NULL || n < 2)
    return SEER_EPARAM;
  size_t loclen = (size_t)f[0] << 8 | f[1];
  if (loclen == 0 || 2 + loclen != n)
    return SEER_EPROTO;
  if (conn->field_version < TTC_FIELD_VERSION_10_2)
    return decode_lob_attr_legacy(conn, type, f, n, cell);
  uint8_t *raw = NULL;
  size_t rawlen = 0;
  SeerStatus st = seer_lob_read(conn, f, n, &raw, &rawlen);
  if (st != SEER_OK)
    return st;
  if (type == ORA_TYPE_CLOB) {
    char *u8 = NULL;
    size_t u8len = 0;
    if (rawlen == 0)
      cell_set_text(cell, strdup(""));
    else if (seer_iconv("UTF-16BE", "UTF-8", (const char *)raw, rawlen, &u8, &u8len) == 0) {
      cell_set_bytes(cell, u8, u8len, false);
      free(u8);
    } else
      st = SEER_EPROTO;
  } else {
    cell_set_text(cell, hex_dup(raw, rawlen));
  }
  free(raw);
  return st;
}

/* Flatten an object image into "(a, b, ...)"-style text. `conn` resolves LOB
 * and XMLType attributes (a round trip each); NULL renders them unresolved. */
static SeerStatus decode_object_image(SeerConn *conn, const uint8_t *img, size_t imglen,
                                      const uint8_t *types, const uint8_t *elem, int ntypes,
                                      SeerCell *cell)
{
  if (imglen < 3)
    return SEER_EPROTO;
  uint8_t flags = img[0];
  size_t pos = 2;                        /* skip flags + version */
  (void)obj_read_len(img, imglen, &pos); /* image length (skip) */
  if (!(flags & 0x04)) {                 /* prefix segment present */
    long plen = obj_read_len(img, imglen, &pos);
    if (plen > 0)
      pos += (size_t)plen;
  }
  SeerWriter w;
  if (!seer_writer_init(&w, 64))
    return SEER_ENOMEM;
  for (int a = 0; a < ntypes; a++) {
    if (a > 0)
      seer_writer_bytes(&w, ", ", 2);
    long len = obj_read_len(img, imglen, &pos);
    if (len == -2) {
      seer_writer_free(&w);
      return SEER_EPROTO;
    }
    if (len <= 0) { /* NULL / empty attribute */
      seer_writer_bytes(&w, "NULL", 4);
      continue;
    }
    if (pos + (size_t)len > imglen) {
      seer_writer_free(&w);
      return SEER_EPROTO;
    }
    SeerCell tmp = {0};
    SeerStatus ast;
    if (elem != NULL && elem[a] != 0) /* embedded collection */
      ast = decode_collection_image(img + pos, (size_t)len, elem[a], NULL, 0, &tmp);
    else if (types[a] == OBJ_ATTR_XMLTYPE)
      ast = conn ? decode_xmltype_image(conn, img + pos, (size_t)len, &tmp) : SEER_EPARAM;
    else if (types[a] == ORA_TYPE_CLOB || types[a] == ORA_TYPE_BLOB)
      ast = decode_lob_attr(conn, types[a], img + pos, (size_t)len, &tmp);
    else if (types[a] == ORA_TYPE_BOOLEAN) { /* 4 bytes, the truth in the first */
      cell_set_text(&tmp, strdup(img[pos] ? "TRUE" : "FALSE"));
      ast = SEER_OK;
    } else if (types[a] == ORA_TYPE_BINARY_INTEGER && len == 4) { /* big-endian signed */
      char nb[16];
      snprintf(nb, sizeof nb, "%ld",
               (long)(int32_t)(((uint32_t)img[pos] << 24) | ((uint32_t)img[pos + 1] << 16) |
                               ((uint32_t)img[pos + 2] << 8) | img[pos + 3]));
      cell_set_text(&tmp, strdup(nb));
      ast = SEER_OK;
    } else
      ast = decode_image_scalar(types[a], img + pos, (size_t)len, &tmp);
    if (ast == SEER_EDB) { /* binary XML on 11g: the object's read fails with it (#416) */
      free(tmp.data);
      seer_writer_free(&w);
      return SEER_EDB;
    }
    if (ast == SEER_OK && tmp.data != NULL)
      seer_writer_bytes(&w, tmp.data, tmp.len);
    free(tmp.data);
    pos += (size_t)len;
  }
  SeerStatus st = seer_writer_ok(&w) ? cell_set_bytes(cell, w.buf, w.len, false) : SEER_ENOMEM;
  seer_writer_free(&w);
  return st;
}

/* Decode a collection (VARRAY / nested table) image into "[e1, e2, ...]" text.
 * Shares the object header, then a collection-flags byte, a length-prefixed
 * element count, and each element length-prefixed (one common element type). */
static SeerStatus decode_collection_image(const uint8_t *img, size_t imglen, uint8_t element_type,
                                          const uint8_t *elem_obj_types, int n_elem_obj_attrs,
                                          SeerCell *cell)
{
  if (imglen < 3)
    return SEER_EPROTO;
  uint8_t flags = img[0];
  size_t pos = 2;                        /* skip flags + version */
  (void)obj_read_len(img, imglen, &pos); /* image length (skip) */
  if (!(flags & 0x04)) {                 /* prefix segment present */
    long plen = obj_read_len(img, imglen, &pos);
    if (plen > 0)
      pos += (size_t)plen;
  }
  if (pos >= imglen)
    return SEER_EPROTO;
  /* Collection flags: HAS_INDEXES (0x10) - a PL/SQL index-by table - puts each
   * element's key, a 4-byte big-endian signed integer, before it (§21.6b);
   * the elements are rendered as "key: value" then. */
  bool keyed = (img[pos++] & 0x10) != 0;
  long count = obj_read_len(img, imglen, &pos);
  if (count < 0)
    count = 0;

  SeerWriter w;
  if (!seer_writer_init(&w, 64))
    return SEER_ENOMEM;
  seer_writer_u8(&w, '[');
  for (long e = 0; e < count; e++) {
    if (e > 0)
      seer_writer_bytes(&w, ", ", 2);
    if (keyed) {
      if (pos + 4 > imglen) {
        seer_writer_free(&w);
        return SEER_EPROTO;
      }
      int32_t key = (int32_t)(((uint32_t)img[pos] << 24) | ((uint32_t)img[pos + 1] << 16) |
                              ((uint32_t)img[pos + 2] << 8) | img[pos + 3]);
      pos += 4;
      char kb[16];
      int kl = snprintf(kb, sizeof kb, "%ld: ", (long)key);
      seer_writer_bytes(&w, kb, (size_t)kl);
    }
    long len = obj_read_len(img, imglen, &pos);
    if (len == -2) {
      seer_writer_free(&w);
      return SEER_EPROTO;
    }
    if (len <= 0) { /* NULL / empty element */
      seer_writer_bytes(&w, "NULL", 4);
      continue;
    }
    if (pos + (size_t)len > imglen) {
      seer_writer_free(&w);
      return SEER_EPROTO;
    }
    SeerCell tmp = {0};
    SeerStatus est = (n_elem_obj_attrs > 0) /* element is an object image */
                         ? decode_object_image(NULL, img + pos, (size_t)len, elem_obj_types, NULL,
                                               n_elem_obj_attrs, &tmp)
                         : decode_image_scalar(element_type, img + pos, (size_t)len, &tmp);
    if (est == SEER_OK && tmp.data != NULL) {
      if (n_elem_obj_attrs > 0)
        seer_writer_u8(&w, '('); /* nest object as (a, b) */
      seer_writer_bytes(&w, tmp.data, tmp.len);
      if (n_elem_obj_attrs > 0)
        seer_writer_u8(&w, ')');
    }
    free(tmp.data);
    pos += (size_t)len;
  }
  seer_writer_u8(&w, ']');
  SeerStatus st = seer_writer_ok(&w) ? cell_set_bytes(cell, w.buf, w.len, false) : SEER_ENOMEM;
  seer_writer_free(&w);
  return st;
}

/* XMLType image flags (#124). */
#define XML_FLAG_LOB 0x00000001    /* content is a CLOB locator      */
#define XML_FLAG_STRING 0x00000004 /* content is an inline string    */
#define XML_FLAG_SKIP_NEXT_4 0x00100000
/* The locator holds binary XML (CSX), 11g's default XMLType storage: 12c+
 * servers render such a document as text for a thin client, 11g sends the
 * CSX bytes, whose token tables live in the server's XDB repository (#416). */
#define XML_FLAG_BINARY_XML 0x01000000

/* Decode an XMLType image (type 109, type_name XMLTYPE) into XML text. After the
 * shared object header: a 1-byte XML version, a ub4 flag, an optional 4-byte
 * skip, then the content - either an inline UTF-8 document (STRING) or a CLOB
 * locator (LOB) read through the LOB path and converted UTF-16BE -> UTF-8. */
static SeerStatus decode_xmltype_image(SeerConn *conn, const uint8_t *img, size_t imglen,
                                       SeerCell *cell)
{
  if (imglen < 3)
    return SEER_EPROTO;
  uint8_t flags = img[0];
  size_t pos = 2;                        /* skip image flags + version */
  (void)obj_read_len(img, imglen, &pos); /* image length */
  if (!(flags & 0x04)) {                 /* prefix segment present */
    long plen = obj_read_len(img, imglen, &pos);
    if (plen > 0)
      pos += (size_t)plen;
  }
  if (pos + 5 > imglen) /* 1 (xml version) + 4 (flag) */
    return SEER_EPROTO;
  pos += 1; /* XML version */
  uint32_t xflag = (uint32_t)img[pos] << 24 | (uint32_t)img[pos + 1] << 16 |
                   (uint32_t)img[pos + 2] << 8 | img[pos + 3];
  pos += 4;
  if (xflag & XML_FLAG_SKIP_NEXT_4)
    pos += 4;
  if (pos > imglen)
    return SEER_EPROTO;
  const uint8_t *content = img + pos;
  size_t clen = imglen - pos;
  seer_log(SEER_LOG_DEBUG, "stmt: XMLType image: flag 0x%08x, %zu content bytes", xflag, clen);

  if (xflag & XML_FLAG_STRING) /* inline UTF-8 document */
    return cell_set_bytes(cell, content, clen, false);

  if (xflag & XML_FLAG_LOB) { /* a CLOB locator */
    /* 9i and 8i read it with their own LOB calls, as a LOB attribute's
     * (#168); the 10g+ read they answer with nothing usable. */
    if (conn->field_version < TTC_FIELD_VERSION_10_2)
      return decode_lob_attr_legacy(conn, ORA_TYPE_CLOB, content, clen, cell);
    if (xflag & XML_FLAG_BINARY_XML) {
      /* No client decodes CSX without XDB's token tables, and no reference
       * client reads it from 11g (python-oracledb needs 12.1): the cell's
       * read says so and names the SQL that reads it, rather than reading
       * NULL (#416). */
      free(conn->last_error);
      conn->last_error = strdup("this XMLType value is stored as binary XML, which Oracle 11g "
                                "sends undecoded: select XMLSERIALIZE(DOCUMENT col AS CLOB) or "
                                "col.getClobVal() to read it");
      return SEER_EDB;
    }
    uint8_t *raw = NULL;
    size_t rawlen = 0;
    SeerStatus st = seer_lob_read(conn, content, clen, &raw, &rawlen);
    if (st != SEER_OK)
      return st;
    st = SEER_OK;
    if (rawlen == 0) {
      cell_set_text(cell, strdup(""));
    } else {
      char *u8 = NULL;
      size_t u8len = 0;
      if (seer_iconv("UTF-16BE", "UTF-8", (const char *)raw, rawlen, &u8, &u8len) == 0) {
        st = cell_set_bytes(cell, u8, u8len, false);
        free(u8);
      } else {
        st = SEER_EPROTO;
      }
    }
    free(raw);
    return st;
  }
  return SEER_EPROTO;
}

/* Decode every captured ADT cell. The layout is fetched once per column (cached
 * on the SeerColumn) and reused for all its rows: XMLType decodes to its XML
 * text, a collection as "[...]", a plain object as "v1, v2, ...". Per-cell
 * failures are non-fatal. */
/* Decode one object / collection image of the type `col` describes into
 * `cell`, resolving the type's layout first if needed (cached on `col`):
 * XMLType to its XML text, a collection as "[...]", an object as "v1, ...".
 * SEER_ENOTIMPL when no layout could be found. */
static SeerStatus decode_typed_image(SeerConn *conn, SeerColumn *col, const uint8_t *img,
                                     size_t imglen, SeerCell *cell)
{
  if (col->type_name != NULL && strcmp(col->type_name, "XMLTYPE") == 0)
    return decode_xmltype_image(conn, img, imglen, cell); /* no attribute layout */
  if (col->n_obj_attrs < 0 && col->type_schema && col->type_name)
    fetch_obj_layout(conn, col); /* fills column; sets n_obj_attrs>=0 */
  if (col->is_collection)
    return decode_collection_image(img, imglen, col->element_type, col->elem_obj_types,
                                   col->n_elem_obj_attrs, cell);
  if (col->n_obj_attrs > 0)
    return decode_object_image(conn, img, imglen, col->obj_attr_types, col->obj_attr_elem,
                               col->n_obj_attrs, cell);
  return SEER_ENOTIMPL; /* layout unavailable */
}

static void record_cell_error(SeerStmt *stmt, size_t row, int col);

static void resolve_pending_objs(SeerStmt *stmt)
{
  for (size_t k = 0; k < stmt->npobjs; k++) {
    SeerPendingObj *p = &stmt->pobjs[k];
    SeerStatus st = decode_typed_image(stmt->conn, &stmt->cols[p->col], p->image, p->imagelen,
                                       &stmt->rows[p->row][p->col]);
    if (st == SEER_EDB) { /* the value's own error, read with the cell (#416) */
      record_cell_error(stmt, p->row, p->col);
      continue;
    }
    if (st != SEER_OK && st != SEER_ENOTIMPL)
      seer_log(SEER_LOG_WARNING, "stmt: OBJECT/collection decode failed (row %zu col %d)", p->row,
               p->col);
  }
}

/* Decode the object / collection each OUT bind brought back (stashed by
 * parse_iov) into its OUT value. A NULL object leaves the value NULL. */
static SeerStatus resolve_out_objects(SeerStmt *stmt)
{
  for (int i = 0; i < stmt->npbinds; i++) {
    SeerBind *b = &stmt->pbinds[i];
    if (b->out_image == NULL)
      continue;
    SeerStatus st = b->obj_type != NULL ? decode_typed_image(stmt->conn, b->obj_type, b->out_image,
                                                             b->out_imagelen, &b->out)
                                        : SEER_ENOTIMPL;
    free(b->out_image);
    b->out_image = NULL;
    b->out_imagelen = 0;
    if (st != SEER_OK) {
      seer_log(SEER_LOG_ERROR, "stmt: OUT object decode failed (param %d)", i + 1);
      return st == SEER_ENOTIMPL ? SEER_EPROTO : st;
    }
  }
  return SEER_OK;
}

/* Discard captured-but-undrained implicit result sets. */
static void free_implicit(SeerStmt *stmt)
{
  for (size_t i = 0; i < stmt->nimplicit; i++)
    free_columns(stmt->implicit[i].cols, stmt->implicit[i].ncols);
  free(stmt->implicit);
  stmt->implicit = NULL;
  stmt->nimplicit = 0;
  stmt->implicit_pos = 0;
}

/* True while a query's cursor still has rows to hand out. "More rows" is the
 * absence of the end-of-fetch code (ORA-01403) on a cursor that described a
 * result set - NOT the OER call_status, which is a flag word (1 with
 * autocommit on, 2 while a transaction is open, 5 after PL/SQL): gating on
 * call_status == 1 silently stopped after the first batch inside a
 * transaction. Requiring described columns keeps DML (which also carries a
 * cursor handle) from ever being sent a FETCH. */
static bool more_rows_pending(const SeerStmt *stmt, int64_t cursor_id, int64_t err_code)
{
  return stmt->ncols > 0 && cursor_id != 0 && err_code != 1403 && !rows_full(stmt);
}

/* Fetch every remaining row of stmt->cursor_id into stmt->rows (one FETCH is
 * always issued, then more while the cursor has rows pending). */
static SeerStatus fetch_all_rows(SeerStmt *stmt)
{
  SeerWriter w;
  OerResult rc = {0}; /* prime: fetch at least once */
  while (more_rows_pending(stmt, stmt->cursor_id, rc.err_code)) {
    SeerStatus st = build_next_fetch(stmt, &w);
    if (st != SEER_OK)
      return st;
    st = seer_ttc_send(stmt->conn, w.buf, w.len);
    seer_writer_free(&w);
    if (st != SEER_OK)
      return st;
    uint8_t *resp = NULL;
    size_t rlen = 0;
    st = seer_ttc_recv(stmt->conn, &resp, &rlen);
    if (st != SEER_OK)
      return st;
    OerResult f = {0};
    st = parse_response(stmt, resp, rlen, false, &f);
    free(resp);
    if (st != SEER_OK)
      return st;
    if (f.err_code != 0 && f.err_code != 1403) {
      seer_log(SEER_LOG_DEBUG, "stmt: fetch failed (ORA-%05ld)", (long)f.err_code);
      return SEER_EDB;
    }
    rc.err_code = f.err_code;
  }
  return SEER_OK;
}

/* Resolve every captured LOB cell into its content (CLOB -> UTF-8 text, BLOB ->
 * raw bytes). A per-cell read failure is logged and skipped, not fatal. */
static void resolve_pending_lobs(SeerStmt *stmt)
{
  for (size_t k = 0; k < stmt->nplobs; k++) {
    SeerPendingLob *p = &stmt->plobs[k];
    uint8_t *raw = NULL;
    size_t rawlen = 0;
    /* A BFILE is an external file: FILE_OPEN -> READ -> FILE_CLOSE.
     * Persistent CLOB/BLOB/VECTOR is a single READ round-trip. */
    SeerStatus lst = (p->ora_type == ORA_TYPE_BFILE)
                         ? seer_bfile_read(stmt->conn, p->locator, p->loclen, &raw, &rawlen)
                         : seer_lob_read(stmt->conn, p->locator, p->loclen, &raw, &rawlen);
    if (lst == SEER_EDB && p->ora_type == ORA_TYPE_BFILE) {
      record_cell_error(stmt, p->row, p->col);
      continue;
    }
    if (lst != SEER_OK) {
      seer_log(SEER_LOG_WARNING, "stmt: LOB read failed for row %zu col %d", p->row, p->col);
      continue;
    }
    SeerCell *cell = &stmt->rows[p->row][p->col];
    free(cell->data);
    cell->data = NULL;
    cell->len = 0;
    cell->binary = false;
    if (p->ora_type == ORA_TYPE_CLOB) { /* CLOB: UTF-16BE -> UTF-8 text */
      if (rawlen == 0) {
        cell_set_text(cell, strdup(""));
      } else {
        char *u8 = NULL;
        size_t u8len = 0;
        if (seer_iconv("UTF-16BE", "UTF-8", (const char *)raw, rawlen, &u8, &u8len) == 0) {
          cell_set_bytes(cell, u8, u8len, false);
          free(u8);
        }
      }
    } else if (p->ora_type == ORA_TYPE_VECTOR) { /* VECTOR -> "[e1, e2, ...]" text */
      if (decode_vector_image(raw, rawlen, cell) != SEER_OK)
        seer_log(SEER_LOG_WARNING, "stmt: VECTOR decode failed (row %zu col %d)", p->row, p->col);
    } else if (p->ora_type == ORA_TYPE_JSON) { /* JSON (OSON) -> JSON text */
      char *json = NULL;
      if (seer_decode_oson(raw, rawlen, &json) == SEER_OK)
        cell_set_text(cell, json);
      else
        seer_log(SEER_LOG_WARNING, "stmt: JSON decode failed (row %zu col %d)", p->row, p->col);
    } else { /* BLOB: raw binary bytes */
      cell_set_bytes(cell, raw, rawlen, true);
    }
    free(raw);
  }
}

/* ========= Oracle 9i (field version 2): the TTI_ALL7 query dialect ===========
 * 9i speaks an older execute RPC than TTI_ALL8. A SELECT is a four-call sequence
 * (seerdb PROTOCOL.md §19): OOPEN -> parse -> describe -> exec/fetch* -> close.
 * The OOPEN is the session's, once: every statement is parsed, described,
 * executed and closed on that one cursor, named by its id in each call (see
 * fv2_shared_cursor). RE'd from the Oracle JDBC thin driver. */

/* Send one fv2 message; receive the reply into resp/rlen (caller frees resp). */
static SeerStatus fv2_txn(SeerConn *c, const uint8_t *msg, size_t mlen, uint8_t **resp,
                          size_t *rlen)
{
  SeerStatus st = seer_ttc_send(c, msg, mlen);
  if (st != SEER_OK)
    return st;
  return seer_ttc_recv(c, resp, rlen);
}

static void fv2_call_head(SeerWriter *w, uint8_t function);

/* The server cursor every 9i statement runs on, opened by the first one that
 * needs it. Each OOPEN allocates a cursor; one per statement, all parsed on
 * cursor 1, left one open a statement until the session hit open_cursors
 * (ORA-01000; seerdb #2288). The reply is `08 <ub4 id>`. A close (O7_CLOSE)
 * ends a statement on it but keeps the cursor allocated for the next. */
static SeerStatus fv2_shared_cursor(SeerConn *c, uint32_t *out)
{
  if (c->fv2_cursor == 0) {
    /* SEER_OPEN_SCHEMA, and its reply's SEER_OPEN_REPLY_SCHEMA (#398) */
    SeerSchemaCtx cx = seer_msg_ctx(0, TTC_FIELD_VERSION_9_2, TTC_FIELD_VERSION_9_2);
    SeerWriter w;
    if (!seer_writer_init(&w, 8))
      return SEER_ENOMEM;
    fv2_call_head(&w, O7_OPEN);
    SeerOpenMsg om = {.cursor_ptr = 1};
    seer_schema_encode(SEER_OPEN_SCHEMA, &cx, &om, &w);
    uint8_t *resp = NULL;
    size_t rlen = 0;
    SeerStatus st = seer_writer_ok(&w) ? fv2_txn(c, w.buf, w.len, &resp, &rlen) : SEER_ENOMEM;
    seer_writer_free(&w);
    if (st != SEER_OK)
      return st;
    int64_t id = 0;
    if (rlen > 1 && resp[0] == TTI_RPA) {
      SeerReader r;
      seer_reader_init(&r, resp + 1, rlen - 1);
      SeerOpenMsg rm = {0};
      if (seer_schema_decode(SEER_OPEN_REPLY_SCHEMA, &cx, &r, &rm))
        id = rm.cursor;
    }
    free(resp);
    if (id <= 0) {
      seer_log(SEER_LOG_ERROR, "fv2: OOPEN reply carries no cursor id");
      return SEER_EPROTO;
    }
    c->fv2_cursor = (uint32_t)id;
  }
  *out = c->fv2_cursor;
  return SEER_OK;
}

/* End a statement on the shared cursor (best-effort). */
static void fv2_close_cursor(SeerConn *c, uint32_t cursor)
{
  SeerWriter w;
  if (!seer_writer_init(&w, 16))
    return;
  SeerSchemaCtx cx = seer_msg_ctx(0, TTC_FIELD_VERSION_9_2, TTC_FIELD_VERSION_9_2);
  SeerFunHeadMsg h = {.type = TTI_FUN, .function = O7_CLOSE};
  SeerCursorCallMsg m = {.cursor = cursor};
  seer_schema_encode(SEER_FUN_HEAD_SCHEMA, &cx, &h, &w); /* #398 */
  seer_schema_encode(SEER_CURSOR_CALL_SCHEMA, &cx, &m, &w);
  uint8_t *resp = NULL;
  size_t rlen = 0;
  if (seer_writer_ok(&w) && fv2_txn(c, w.buf, w.len, &resp, &rlen) == SEER_OK)
    free(resp);
  seer_writer_free(&w);
}

/* Free a 9i server cursor: function 0x08, the close's schema. A close alone
 * leaves a REF CURSOR, or a nested cursor while its query is open, allocated
 * until the session ends (ORA-01000); ojdbc14 sends close, then free, on the
 * same id (seerdb, measured on 9.2.0.4; #166, #196). */
static void fv2_free_cursor(SeerConn *c, uint32_t cursor)
{
  SeerWriter w;
  if (!seer_writer_init(&w, 16))
    return;
  SeerSchemaCtx cx = seer_msg_ctx(0, TTC_FIELD_VERSION_9_2, TTC_FIELD_VERSION_9_2);
  SeerFunHeadMsg h = {.type = TTI_FUN, .function = O7_FREE};
  SeerCursorCallMsg m = {.cursor = cursor};
  seer_schema_encode(SEER_FUN_HEAD_SCHEMA, &cx, &h, &w); /* #398 */
  seer_schema_encode(SEER_CURSOR_CALL_SCHEMA, &cx, &m, &w);
  uint8_t *resp = NULL;
  size_t rlen = 0;
  if (seer_writer_ok(&w) && fv2_txn(c, w.buf, w.len, &resp, &rlen) == SEER_OK)
    free(resp);
  seer_writer_free(&w);
}

/* A 9i cursor value - a CURSOR() cell, a REF CURSOR OUT - is the cursor's id as
 * a value (`02 01 02` is id 2): a length byte and the id's big-endian bytes
 * (seerdb PROTOCOL.md §19.17a, measured against ojdbc14 on 9.2.0.4; #166). */
static uint32_t fv2_cursor_id(const uint8_t *v, size_t n)
{
  if (n >= 2 && n <= 5 && v[0] == n - 1) {
    v++;
    n--;
  }
  uint32_t id = 0;
  for (size_t i = 0; i < n && i < 4; i++)
    id = id << 8 | v[i];
  return id;
}

static void fv2_note_nested(SeerStmt *stmt, uint32_t id)
{
  if (id == 0)
    return;
  if (stmt->fv2_nnested == stmt->fv2_nested_cap) {
    size_t cap = stmt->fv2_nested_cap ? stmt->fv2_nested_cap * 2 : 16;
    uint32_t *n = realloc(stmt->fv2_nested, cap * sizeof *n);
    if (n == NULL)
      return; /* best-effort: the query's close still frees it */
    stmt->fv2_nested = n;
    stmt->fv2_nested_cap = cap;
  }
  stmt->fv2_nested[stmt->fv2_nnested++] = id;
}

/* Close and free the nested cursors a fetch batch opened, before the next
 * batch. ODBC has no nested-cursor type, so their rows are not read. */
static void fv2_free_nested(SeerStmt *stmt)
{
  for (size_t i = 0; i < stmt->fv2_nnested; i++) {
    fv2_close_cursor(stmt->conn, stmt->fv2_nested[i]);
    fv2_free_cursor(stmt->conn, stmt->fv2_nested[i]);
  }
  free(stmt->fv2_nested);
  stmt->fv2_nested = NULL;
  stmt->fv2_nnested = stmt->fv2_nested_cap = 0;
}

/* The ORA code carried by a short pre-10g OER (token, ub4 rows, ub4 code); 0 if
 * `resp` is not an OER, -1 on a truncated one. */
static int64_t fv2_oer_code(const uint8_t *resp, size_t rlen)
{
  if (rlen < 1 || resp[0] != TTI_OER)
    return 0;
  /* SEER_OER_HEAD_SCHEMA at 9.2 (#398): the row count, then the code */
  SeerReader r;
  seer_reader_init(&r, resp + 1, rlen - 1);
  SeerSchemaCtx cx = seer_msg_ctx(0, TTC_FIELD_VERSION_9_2, TTC_FIELD_VERSION_9_2);
  SeerOerMsg m = {0};
  return seer_schema_decode(SEER_OER_HEAD_SCHEMA, &cx, &r, &m) ? m.code : -1;
}

/* The message of a 9i status as a chunked run starting at resp[i]: 0xFE, then
 * chunks (a length byte and that many bytes), then a zero length that is the
 * reply's last byte. The joined text, or NULL when resp[i] starts no such run
 * or the text is not an "ORA-" message. Caller frees. */
/* A chunked "ORA-..." run at `i`: ending the reply when `at_end`, else
 * anywhere its zero terminator falls inside it (#246). */
static char *fv2_chunked_message(const uint8_t *resp, size_t rlen, size_t i, bool at_end)
{
  if (resp[i] != 0xFE)
    return NULL;
  size_t total = 0, j = i + 1;
  while (j < rlen && resp[j] != 0) {
    total += resp[j];
    j += 1 + (size_t)resp[j];
  }
  if ((at_end ? j != rlen - 1 : j >= rlen) || total < 4)
    return NULL;
  char *msg = malloc(total + 1);
  if (msg == NULL)
    return NULL;
  size_t off = 0;
  for (j = i + 1; resp[j] != 0; j += 1 + (size_t)resp[j]) {
    memcpy(msg + off, resp + j + 1, resp[j]);
    off += resp[j];
  }
  msg[off] = '\0';
  if (strncmp(msg, "ORA-", 4) != 0) {
    free(msg);
    return NULL;
  }
  return msg;
}

/* Surface a 9i OER's trailing "ORA-NNNNN: ..." text on conn->last_error: the
 * reply's last field (middle fields are version-specific), either one
 * length-prefixed run or - past 64 bytes - a chunked one (0xFE, 64-byte
 * chunks, a zero length; seerdb PROTOCOL.md §19, ccd3ee7). Matching only the
 * plain form took the last chunk alone for a long message. */
/* What a 9i status says (seerdb PROTOCOL.md §19.3, its _O7_STATUS_HEAD): the
 * OER token, then rows, ORA code, two array-error fields, cursor and error
 * position (a ub4 each), then sql type and fatal (a byte each), flags (a ub2),
 * cursor options (a ub4), UPI parameter (a byte), and the warning flags. */
typedef struct {
  int64_t rows;
  int64_t code;
  int64_t position; /* 0-based offset of the error in the SQL text, 0 if none */
  uint8_t warnings; /* 0x20: the object a CREATE made compiled with errors */
} Fv2Status;

/* Read the status of a 9i reply: an optional RPA piggyback, then the OER.
 * False when the reply carries none. */
static void fv2_read_batch_errors(SeerReader *r, SeerStmt *stmt);

/* Read the status of a 9i reply: an optional RPA piggyback, then the OER.
 * With `batch` set, the status is read on to its end and the per-row errors a
 * batch-errors array DML collected are stored on that statement. */
static bool fv2_read_status_ex(const uint8_t *data, size_t dlen, Fv2Status *out, SeerStmt *batch)
{
  memset(out, 0, sizeof *out);
  if (dlen == 0)
    return false;
  SeerReader r;
  seer_reader_init(&r, data, dlen);
  if (data[0] == TTI_RPA) { /* skip the RPA piggyback */
    r.pos = 1;
    /* The parameters are consumed by count, SEER_RPA_HEAD_SCHEMA as 10g+'s
     * and 8i's (#398): the first is a counter that grows with the instance,
     * and once past 2^24 its length byte is 0x04 - the OER token - so
     * stopping at a token-valued byte took the counter for the status and
     * made every successful DML/DDL on an aged 9i report a garbled negative
     * ORA code (seerdb/seerdb@0babf60). Only when the counted walk doesn't
     * land on the OER is the old token-sniffing walk used - a recovery, not
     * a message form, so it stays by hand. */
    SeerSchemaCtx rcx = seer_msg_ctx(0, TTC_FIELD_VERSION_9_2, TTC_FIELD_VERSION_9_2);
    SeerRpaMsg rm = {0};
    SeerSchemaResult res = seer_schema_decode_ex(SEER_RPA_HEAD_SCHEMA, &rcx, &r, &rm);
    seer_schema_free(SEER_RPA_HEAD_SCHEMA, &rm);
    while (res == SCH_OK && seer_reader_remaining(&r) > 0 && r.buf[r.pos] == 0)
      r.pos++;
    if (res != SCH_OK || seer_reader_remaining(&r) == 0 || r.buf[r.pos] != TTI_OER) {
      seer_reader_init(&r, data, dlen);
      r.pos = 1;
      int64_t num = seer_dec_sb4(&r);
      for (int64_t i = 0; i < num && i < 100000 && seer_reader_remaining(&r) > 0; i++) {
        uint8_t t = r.buf[r.pos];
        if (t == TTI_OER || t == TTI_RXH || t == TTI_RXD)
          break;
        (void)seer_dec_sb4(&r);
      }
      while (seer_reader_remaining(&r) > 0 && r.buf[r.pos] == 0)
        r.pos++;
    }
  }
  if (seer_reader_remaining(&r) == 0 || r.buf[r.pos] != TTI_OER)
    return false;
  r.pos += 1;
  /* SEER_OER_*_SCHEMA at field version 2 (#395 spike): no call status or
   * sequence, the cursor options a compressed integer - 8 (`01 08`) on a
   * session that logged on with the XA names (#171). */
  SeerSchemaCtx cx = seer_msg_ctx(0, TTC_FIELD_VERSION_9_2, TTC_FIELD_VERSION_9_2);
  SeerOerMsg m = {0};
  if (!seer_schema_decode(SEER_OER_HEAD_SCHEMA, &cx, &r, &m))
    return false;
  out->rows = m.rows;
  out->code = m.code;
  if (seer_schema_decode(SEER_OER_FLAGS_SCHEMA, &cx, &r,
                         &m)) { /* a short one ends after the code */
    out->position = m.position > 0 ? m.position : 0;
    out->warnings = (uint8_t)m.warnings;
    if (batch != NULL)
      fv2_read_batch_errors(&r, batch);
  }
  return true;
}

static bool fv2_read_status(const uint8_t *data, size_t dlen, Fv2Status *out)
{
  return fv2_read_status_ex(data, dlen, out, NULL);
}

/* The rest of a 9i status, from after the warning flags (seerdb PROTOCOL.md
 * §19.3, _O7_STATUS_HEAD's rowid and _O7_STATUS_TAIL; #2247): the rowid
 * (object, file, a reserved byte, block, slot), the OS error, statement and
 * call numbers (a byte each), padding (a ub2), the iterations, the oerrdd
 * (a ub4 length, then the value), then a batch-errors call's three arrays:
 * the codes and the row offsets, each a ub4 count and one value packing that
 * many ub4s, and the messages, a ub4 count, an indicator byte when there are
 * any, and per message a ub4 length, the text and two bytes. Error i hit row
 * offsets[i] with codes[i]. A status cut short stores nothing. */
static void fv2_read_batch_errors(SeerReader *r, SeerStmt *stmt)
{
  /* The rowid to the batch counts: SEER_OER_BATCH_SCHEMA, as 10g+'s (#395). */
  SeerSchemaCtx cx = seer_msg_ctx(0, TTC_FIELD_VERSION_9_2, TTC_FIELD_VERSION_9_2);
  SeerOerMsg bm = {0};
  if (!seer_schema_decode(SEER_OER_BATCH_SCHEMA, &cx, r, &bm)) {
    seer_schema_free(SEER_OER_BATCH_SCHEMA, &bm);
    return;
  }
  size_t nc = 0, no = 0;
  uint32_t *codes = oer_ub4s(&bm.codes, &nc), *offsets = oer_ub4s(&bm.offsets, &no);
  int64_t ncodes = (int64_t)nc, noffsets = (int64_t)no;
  seer_schema_free(SEER_OER_BATCH_SCHEMA, &bm);
  int64_t nmsgs = bm.nmsgs;
  char **msgs = NULL;
  if (nmsgs > 0 && nmsgs <= 65536 && seer_reader_ok(r))
    msgs = oer_batch_msgs(r, &cx, nmsgs, false);
  else
    nmsgs = 0;
  size_t nb = 0;
  if (codes != NULL)
    nb = (size_t)ncodes;
  if (offsets != NULL && (size_t)noffsets > nb)
    nb = (size_t)noffsets;
  if (nb > 0 && seer_reader_ok(r)) {
    free_batch_errors(stmt);
    stmt->berrs = calloc(nb, sizeof *stmt->berrs);
    if (stmt->berrs != NULL) {
      stmt->nberrs = nb;
      for (size_t i = 0; i < nb; i++) {
        stmt->berrs[i].row = (offsets != NULL && i < (size_t)noffsets) ? offsets[i] : 0;
        stmt->berrs[i].code = (codes != NULL && i < (size_t)ncodes) ? codes[i] : 0;
        if (msgs != NULL && i < (size_t)nmsgs) {
          stmt->berrs[i].message = msgs[i]; /* ownership moved */
          msgs[i] = NULL;
        }
      }
    }
  }
  free(codes);
  free(offsets);
  for (int64_t i = 0; msgs != NULL && i < nmsgs; i++)
    free(msgs[i]);
  free(msgs);
}

/* A 9i DML / block reply's affected-row count and ORA code (0 when absent). */
static void fv2_decode_dml_response(const uint8_t *data, size_t dlen, int64_t *rowcount,
                                    int64_t *code)
{
  Fv2Status status;
  fv2_read_status(data, dlen, &status);
  *rowcount = status.rows;
  *code = status.code;
}

/* A length-prefixed "ORA-..." run at `i`: ending the reply when `at_end`,
 * else anywhere inside it. */
static char *fv2_plain_message(const uint8_t *resp, size_t rlen, size_t i, bool at_end)
{
  size_t len = resp[i];
  if (len < 4 || (at_end ? i + 1 + len != rlen : i + 1 + len > rlen) ||
      memcmp(resp + i + 1, "ORA-", 4) != 0)
    return NULL;
  char *msg = malloc(len + 1);
  if (msg != NULL) {
    memcpy(msg, resp + i + 1, len);
    msg[len] = '\0';
  }
  return msg;
}

/* The error's text, the reply's last field. Both forms must read "ORA-":
 * a bare length match took a stray byte for one, and a 9i error now and then
 * came back as 2 bytes of the reply's tail, its ORA number and SQLSTATE lost
 * (#246). Failing that at the end, a run with bytes after it; failing any,
 * the status's ORA code - never the last call's text, which a reply without
 * one used to leave in place. */
static void fv2_set_error(SeerConn *c, const uint8_t *resp, size_t rlen)
{
  char *msg = NULL;
  for (int at_end = 1; at_end >= 0 && msg == NULL; at_end--) {
    for (size_t i = 3; i + 1 < rlen && msg == NULL; i++)
      msg = fv2_chunked_message(resp, rlen, i, at_end);
    for (size_t i = 3; i + 1 < rlen && msg == NULL; i++)
      msg = fv2_plain_message(resp, rlen, i, at_end);
    if (msg != NULL && !at_end)
      seer_log(SEER_LOG_DEBUG, "fv2: the error text is not the reply's last field");
  }
  /* Where in the statement the error is, as 10g+ reports it (seerdb #2263:
   * `select nosuch from dual` is ORA-00904 at 7). */
  Fv2Status status;
  bool have_status = fv2_read_status(resp, rlen, &status);
  if (have_status)
    c->last_error_offset = (long)status.position;
  if (msg == NULL && have_status && status.code > 0) {
    msg = malloc(16);
    if (msg != NULL)
      snprintf(msg, 16, "ORA-%05lld", (long long)status.code);
  }
  if (msg != NULL) {
    free(c->last_error);
    c->last_error = msg;
  }
}

/* Append one fv2 define entry: the client's requested return type for a
 * column, an OAC (SEER_OAC_SCHEMA at 9.2). */
/* The define sizes of a rowid fetched as text on 9i (fv2_define_entry). */
#define FV2_MAX_ROWID_TEXT 128
#define FV2_MAX_UROWID_TEXT 5267

static void fv2_define_entry(SeerWriter *w, const SeerColumn *col)
{
  uint8_t deftype = col->ora_type;
  uint32_t maxsize = col->max_size;
  uint8_t flag = (col->ora_type == ORA_TYPE_CHAR) ? 0x21 : 0x01;
  uint32_t charset = col->charset ? col->charset : 31;
  switch (col->ora_type) {
  case ORA_TYPE_NUMBER:
    deftype = ORA_TYPE_VARNUM;
    maxsize = 22;
    break;
  case ORA_TYPE_DATE:
    maxsize = 7;
    break;
  case ORA_TYPE_TIMESTAMP:
  case ORA_TYPE_TIMESTAMPTZ:
    maxsize = 13;
    break;
  case ORA_TYPE_LONG:
  case ORA_TYPE_LONGRAW:
    maxsize = 0x7FFFFFFFu;
    break;
  case ORA_TYPE_RID:
  case ORA_TYPE_ROWID:
  case ORA_TYPE_UROWID:
    /* A rowid is defined as its text, as JDBC does: the native ROWID return
     * form desyncs the 9i row stream (ORA-01002). A physical ROWID is 18
     * characters; a UROWID (an IOT's logical rowid) holds the table's key and
     * runs to 5267, so it is defined at that or it comes back cut short
     * (seerdb PROTOCOL.md §19.4, #2335). */
    deftype = ORA_TYPE_VARCHAR;
    maxsize = col->ora_type == ORA_TYPE_UROWID ? FV2_MAX_UROWID_TEXT : FV2_MAX_ROWID_TEXT;
    break;
  default:
    break;
  }
  if (col->ora_type == ORA_TYPE_ADT && col->toid != NULL) {
    /* An object or collection names its type, as ojdbc14 defines one: the
     * open-ended size, the type OID as a value and the version - both as the
     * describe gave them (seerdb PROTOCOL.md §19.17c). Defined without them,
     * 9.2 failed the fetch with ORA-00600 [kkdogty01] (#168); so it did for
     * an XMLType column, whose describe gives an all-zero OID and version
     * 256, defined with version 1. */
    SeerOacMsg m = {.data_type = deftype,
                    .flags = flag,
                    .max_length = 0x7FFFFFFF,
                    .toid_length = (int64_t)col->toidlen,
                    .toid = {.p = col->toid, .n = col->toidlen},
                    .version = col->type_version ? col->type_version : 1,
                    .charset = charset};
    oac_write(w, false, TTC_FIELD_VERSION_9_2, &m);
    return;
  }
  /* The charset form: a national column (described in AL16UTF16) must be
   * defined in the national form, 2. Form 0 makes 9i convert its value to the
   * database charset - lossy, and not the UTF-16BE the decoder expects. */
  SeerOacMsg m = {.data_type = deftype,
                  .flags = flag,
                  .max_length = maxsize,
                  .charset = charset,
                  .csfrm = charset == ORA_CHARSET_AL16UTF16 ? 2 : 0};
  oac_write(w, false, TTC_FIELD_VERSION_9_2, &m);
}

/* Decode one fv2 column descriptor (OAC-fv2 + name) into `col`. */
static SeerStatus fv2_decode_column(SeerReader *r, SeerColumn *col)
{
  /* SEER_DCB_COLUMN_SCHEMA at field version 2 (#398): the OAC's fields (no
   * max_chars, a compressed-integer scale), nullable - read properly, where
   * reading it and the name's byte length as one ub4 slipped for a NOT NULL
   * column (seerdb PROTOCOL.md §19.1) - the name, and the type's schema and
   * name. The type's OID is kept: the define names the type by it (#168). */
  SeerSchemaCtx cx = seer_msg_ctx(0, TTC_FIELD_VERSION_9_2, TTC_FIELD_VERSION_9_2);
  SeerDcbColumnMsg dm = {0};
  if (!seer_schema_decode(SEER_DCB_COLUMN_SCHEMA, &cx, r, &dm)) {
    seer_schema_free(SEER_DCB_COLUMN_SCHEMA, &dm);
    return SEER_EPROTO;
  }
  uint8_t data_type = (uint8_t)dm.data_type;
  col->precision = (uint8_t)dm.precision;
  col->scale = (int)dm.scale;
  int64_t max_len = dm.max_length;
  if (dm.toid.n > 0) {
    free(col->toid);
    col->toid = malloc(dm.toid.n);
    if (col->toid != NULL) {
      memcpy(col->toid, dm.toid.p, dm.toid.n);
      col->toidlen = dm.toid.n;
    }
  }
  col->type_version = (uint32_t)dm.version;
  int64_t charset = dm.charset;
  uint8_t null_ok = (uint8_t)dm.null_ok;
  col->name = bytes_dup_str(&dm.name);
  if (col->name == NULL) {
    seer_schema_free(SEER_DCB_COLUMN_SCHEMA, &dm);
    return SEER_ENOMEM;
  }
  if (data_type == ORA_TYPE_ADT && dm.type_schema.n > 0 && dm.type_name.n > 0) {
    col->type_schema = bytes_dup_str(&dm.type_schema);
    col->type_name = bytes_dup_str(&dm.type_name);
  }
  seer_schema_free(SEER_DCB_COLUMN_SCHEMA, &dm);
  col->ora_type = data_type;
  col->charset = (uint16_t)charset;
  col->max_size = (uint32_t)(max_len < 0 ? 0 : max_len);
  /* 9i gives bytes only. A national column is AL16UTF16, two bytes a
   * character, so its characters are exact (#264). */
  col->byte_size = col->max_size;
  col->char_size = charset == ORA_CHARSET_AL16UTF16 ? col->max_size / 2 : col->max_size;
  /* Described with size 0, a column carries no bytes in the row - when it is
   * defined at its described size. fv2_define_entry defines a NUMBER, DATE,
   * TIMESTAMP or rowid at a fixed size instead, and the server sends a cell
   * for it: taken as carrying none, a TO_NUMBER(NULL) column put the reader a
   * cell behind and the fetch out of sequence, ORA-01002 (#156). */
  bool fixed_define = data_type == ORA_TYPE_NUMBER || data_type == ORA_TYPE_DATE ||
                      data_type == ORA_TYPE_TIMESTAMP || data_type == ORA_TYPE_TIMESTAMPTZ ||
                      data_type == ORA_TYPE_RID || data_type == ORA_TYPE_ROWID;
  col->zero_len = max_len == 0 && !has_own_row_encoding(data_type) && !fixed_define;
  col->null_ok = null_ok;
  col->n_obj_attrs = 0;
  return SEER_OK;
}

/* Decode the describe RPA into a column array:
 *   08 <ub4 numcols> <column>*
 *   column = <OAC-fv2> <null_ok> <name...> <ub4 type_schema_len> [<DALC>]
 *            <ub4 type_name_len> [<DALC>]
 * The count is a ub4 (`01 2c` would be 44; 300 columns are `02 01 2c`), and
 * a column that is not an object sends its two type lengths as `00 00`
 * (seerdb PROTOCOL.md §19.1, #2306). */
static SeerStatus fv2_decode_describe(const uint8_t *data, size_t dlen, SeerColumn **out_cols,
                                      int *out_n)
{
  if (dlen < 3 || data[0] != TTI_RPA)
    return SEER_EPROTO;
  SeerReader r;
  seer_reader_init(&r, data + 1, dlen - 1);
  SeerSchemaCtx cx = seer_msg_ctx(0, TTC_FIELD_VERSION_9_2, TTC_FIELD_VERSION_9_2);
  SeerCountMsg cm = {0}; /* the column count: SEER_COUNT_SCHEMA (#398) */
  if (!seer_schema_decode(SEER_COUNT_SCHEMA, &cx, &r, &cm) || cm.n <= 0 || cm.n > 4096)
    return SEER_EPROTO;
  int64_t n = cm.n;
  int ncols = (int)n;
  SeerColumn *cols = calloc((size_t)ncols, sizeof *cols);
  if (cols == NULL)
    return SEER_ENOMEM;
  for (int i = 0; i < ncols; i++) {
    if (fv2_decode_column(&r, &cols[i]) != SEER_OK) {
      free_columns(cols, ncols);
      return SEER_EPROTO;
    }
    /* An object or collection column names its type, whose layout the image
     * decode reads from the dictionary, as on 10g+ (#168). */
    if (cols[i].type_schema != NULL && cols[i].type_name != NULL)
      cols[i].n_obj_attrs = -1;
  }
  *out_cols = cols;
  *out_n = ncols;
  return SEER_OK;
}

/* Decode one exec+fetch response (RXH, RXD rows, short OER); append rows, set
 * *errcode (1403 = end of fetch) and *nadded. */
static SeerStatus fv2_decode_rows(SeerStmt *stmt, const uint8_t *data, size_t dlen,
                                  int64_t *errcode, size_t *nadded)
{
  *errcode = 0;
  *nadded = 0;
  int ncols = stmt->ncols;
  SeerReader r;
  seer_reader_init(&r, data, dlen);
  while (seer_reader_remaining(&r) > 0) {
    uint8_t token = r.buf[r.pos];
    if (token == TTI_RXH) {
      r.pos += 1;
      /* SEER_RXH_SCHEMA at field version 2, as 10g+'s (#398) - where the
       * counts were skipped up to the next token byte */
      SeerSchemaCtx cx = seer_msg_ctx(0, TTC_FIELD_VERSION_9_2, TTC_FIELD_VERSION_9_2);
      SeerRxhMsg m = {0};
      bool whole = seer_schema_decode(SEER_RXH_SCHEMA, &cx, &r, &m);
      seer_schema_free(SEER_RXH_SCHEMA, &m);
      if (!whole)
        break;
    } else if (token == TTI_RXD) {
      r.pos += 1;
      SeerCell *row = calloc(ncols ? (size_t)ncols : 1, sizeof *row);
      if (row == NULL)
        return SEER_ENOMEM;
      for (int ci = 0; ci < ncols; ci++) {
        uint8_t ct = stmt->cols[ci].ora_type;
        if (ct == ORA_TYPE_CLOB || ct == ORA_TYPE_BLOB || ct == ORA_TYPE_BFILE) {
          /* SEER_LOB_CELL_SCHEMA at field version 2 (#398): the locator's
           * length (0 NULL) and the locator, then the indicator. Captured to
           * resolve via TTI_LOBOPS after the fetch; the cell stays NULL now. */
          SeerSchemaCtx lcx = seer_msg_ctx(0, TTC_FIELD_VERSION_9_2, TTC_FIELD_VERSION_9_2);
          SeerCellMsg lm = {0};
          if (!seer_schema_decode(SEER_LOB_CELL_SCHEMA, &lcx, &r, &lm)) {
            seer_schema_free(SEER_LOB_CELL_SCHEMA, &lm);
            for (int k = 0; k < ci; k++)
              free(row[k].data);
            free(row);
            return SEER_EPROTO;
          }
          if (lm.value.n > 0) {
            uint8_t *locv = malloc(lm.value.n);
            if (locv != NULL) {
              memcpy(locv, lm.value.p, lm.value.n);
              if (record_pending_lob(stmt, stmt->nrows, ci, ct, locv, lm.value.n) != SEER_OK)
                free(locv);
            }
          }
          seer_schema_free(SEER_LOB_CELL_SCHEMA, &lm);
          continue;
        }
        if (ct == ORA_TYPE_ADT) {
          /* An object or collection: 10g+'s framing, a 36-byte type block in
           * the type OID's place (read the same way, a ub4 length and the
           * value), then the row's indicator (seerdb PROTOCOL.md §19.17c,
           * #168). The image is decoded once the rows are in. */
          uint8_t *img = NULL;
          size_t imglen = 0;
          if (read_object_image(&r, &img, &imglen) != SEER_OK) {
            free(img);
            for (int k = 0; k < ci; k++)
              free(row[k].data);
            free(row);
            return SEER_EPROTO;
          }
          if (seer_reader_remaining(&r) > 0 && r.buf[r.pos] == 0x81)
            r.pos += 2; /* 81 01: NULL */
          else if (seer_reader_remaining(&r) > 0)
            r.pos += 1; /* present */
          if (img != NULL && record_pending_obj(stmt, stmt->nrows, ci, img, imglen) != SEER_OK)
            free(img);
          continue;
        }
        if (stmt->cols[ci].zero_len) {
          /* MaxLen 0: no value bytes, only the NULL indicator 81 01. */
          if (seer_reader_remaining(&r) >= 2 && r.buf[r.pos] == 0x81)
            r.pos += 2;
          continue; /* cell stays NULL */
        }
        /* SEER_CELL_SCHEMA at field version 2 (#398): the value and its
         * indicator, 00 or 81 01 for NULL */
        SeerSchemaCtx ccx = seer_msg_ctx(0, TTC_FIELD_VERSION_9_2, TTC_FIELD_VERSION_9_2);
        SeerCellMsg cm = {0};
        if (!seer_schema_decode(SEER_CELL_SCHEMA, &ccx, &r, &cm)) {
          seer_schema_free(SEER_CELL_SCHEMA, &cm);
          for (int k = 0; k < ci; k++)
            free(row[k].data);
          free(row);
          return SEER_EPROTO;
        }
        const uint8_t *val = cm.value.p;
        size_t vlen = cm.value.n;
        if (cm.indicator == -1) {
          /* NULL: the cell stays zeroed */
        } else if (ct == ORA_TYPE_REFCURSOR) {
          /* A CURSOR() cell: the nested cursor's id. ODBC has no nested-cursor
           * type, so the cell is NULL, as on 10g+; the cursor is closed and
           * freed before the next batch (#166, #196). */
          fv2_note_nested(stmt, fv2_cursor_id(val, vlen));
        } else {
          if (vlen > 0) {
            /* A rowid column was defined as VARCHAR (fv2_define_entry): its
             * value is the rowid's text, not the native form. A LONG is text
             * and a LONG RAW bytes, which decode_scalar knows as VARCHAR and
             * RAW; as themselves they fell to its unknown-type hex. */
            uint8_t dt = ct;
            if (ct == ORA_TYPE_RID || ct == ORA_TYPE_ROWID || ct == ORA_TYPE_UROWID ||
                ct == ORA_TYPE_LONG)
              dt = ORA_TYPE_VARCHAR;
            else if (ct == ORA_TYPE_LONGRAW)
              dt = ORA_TYPE_RAW;
            if (decode_scalar(dt, val, vlen, &row[ci]) == SEER_OK)
              national_to_utf8(&stmt->cols[ci], &row[ci]);
          }
        }
        seer_schema_free(SEER_CELL_SCHEMA, &cm);
      }
      if (!seer_reader_ok(&r) || append_row(stmt, row) != SEER_OK) {
        for (int k = 0; k < ncols; k++)
          free(row[k].data);
        free(row);
        return seer_reader_ok(&r) ? SEER_ENOMEM : SEER_EPROTO;
      }
      (*nadded)++;
    } else if (token == TTI_OER) {
      *errcode = fv2_oer_code(r.buf + r.pos, seer_reader_remaining(&r));
      break;
    } else {
      break;
    }
  }
  return SEER_OK;
}

/* Append one fv2 bind OAC (the client's declared type for an input bind), derived
 * from the stored bind's Oracle type. Char binds declare AL32UTF8 (the session is
 * UTF-8 and the 9i server converts to its DB charset); NUMBER rides as VARNUM. */
/* Binds past the inline limits (text past 4000 bytes, RAW past 2000), as a 9i
 * PL/SQL block takes them (seerdb PROTOCOL.md §19.3.1, measured against
 * ojdbc14): declared VARCHAR or RAW at 32767, whatever the value's size, their
 * values in the chunked form. The server stores at most 32512 bytes of either;
 * from 32513 it answers ORA-01460 whatever the declaration (measured on
 * 9.2.0.4 by seerdb and here), so longer ones are refused. */
#define FV2_BLOCK_WIDE_DECLARED 32767u
#define FV2_BLOCK_WIDE_MAX 32512u

/* What a 9i statement's IN binds need (seerdb PROTOCOL.md §19.3.1):
 *   FV2_BINDS_INLINE  none past the inline limits;
 *   FV2_BINDS_BLOCK   text past 4000 bytes or RAW past 2000, up to
 *                     FV2_BLOCK_WIDE_MAX: 9.2 takes them only in a PL/SQL
 *                     block, so a DML runs as one;
 *   FV2_BINDS_NONE    longer ones, which 9.2 has no form for.
 * In a plain statement, text past 4000 drew ORA-00600 [koklgloblen: arrlen]
 * at 4001 bytes and ORA-01483 past it; declared at its own size (VARCHAR or
 * LONG) the server closed the connection, and ojdbc14 itself refuses it. */
enum { FV2_BINDS_INLINE, FV2_BINDS_BLOCK, FV2_BINDS_NONE };
static int fv2_long_binds(const SeerStmt *stmt)
{
  int need = FV2_BINDS_INLINE;
  for (int i = 0; i < stmt->npbinds; i++) {
    const SeerBind *b = &stmt->pbinds[i];
    if (b->is_out || b->oac_charset == 2000 || b->fv2_lob != 0)
      continue;
    switch (b->oac_type) {
    case ORA_TYPE_RAW:
    case ORA_TYPE_LONGRAW:
      if (b->oac_size > FV2_BLOCK_WIDE_MAX)
        return FV2_BINDS_NONE;
      if (b->oac_size > 2000)
        need = FV2_BINDS_BLOCK;
      break;
    case ORA_TYPE_VARCHAR:
    case ORA_TYPE_CHAR:
    case ORA_TYPE_LONG:
      if (b->oac_size > FV2_BLOCK_WIDE_MAX)
        return FV2_BINDS_NONE;
      if (b->oac_size > 4000)
        need = FV2_BINDS_BLOCK;
      break;
    default:
      break;
    }
  }
  return need;
}

/* Whether a 9i bind is past the inline limits - text past 4000 bytes, RAW
 * past 2000 - and so declared at a block's 32767. An IN bind is measured by its
 * value, an OUT by the size asked for; either way 9.2 holds at most 32512, and
 * an OUT's value comes back in the chunked long form (seerdb PROTOCOL.md
 * §19.3.1, measured against ojdbc14; #189). */
static bool fv2_block_wide(const SeerBind *b)
{
  if (b->oac_charset == 2000 || b->fv2_lob != 0)
    return false;
  if (b->oac_type == ORA_TYPE_RAW || b->oac_type == ORA_TYPE_LONGRAW)
    return b->oac_size > 2000;
  return b->oac_size > 4000 && (b->oac_type == ORA_TYPE_VARCHAR || b->oac_type == ORA_TYPE_CHAR ||
                                b->oac_type == ORA_TYPE_LONG);
}

static void fv2_bind_oac(SeerWriter *w, const SeerBind *b)
{
  if ((b->oac_type == ORA_TYPE_ADT || b->oac_type == ORA_TYPE_REF) && b->oac_override != NULL) {
    seer_writer_bytes(w, b->oac_override, b->oac_override_len); /* an object, a REF */
    return;
  }
  uint8_t type = ORA_TYPE_VARCHAR;
  uint32_t maxsize = 4000, charset = 873;
  uint8_t csfrm = 1;
  if (b->oac_charset == 2000) { /* national (NVARCHAR2/NCHAR) */
    charset = 2000;
    csfrm = 2; /* value rides as AL16UTF16 (UTF-16BE) */
  } else
    switch (b->oac_type) {
    case ORA_TYPE_NUMBER:
      type = ORA_TYPE_VARNUM;
      maxsize = 22;
      charset = 31;
      csfrm = 1;
      break;
    case ORA_TYPE_RAW:
    case ORA_TYPE_LONGRAW:
      type = ORA_TYPE_RAW;
      maxsize = 2000;
      charset = 31;
      csfrm = 0;
      break;
    case ORA_TYPE_DATE:
      type = ORA_TYPE_DATE;
      maxsize = 7;
      charset = 31;
      csfrm = 0;
      break;
    case ORA_TYPE_TIMESTAMP:
    case ORA_TYPE_TIMESTAMPTZ:
    case ORA_TYPE_TIMESTAMPLTZ:
    case ORA_TYPE_INTERVAL_YM:
    case ORA_TYPE_INTERVAL_DS:
      /* Declared as the type the value is (7-13 bytes, sized as on 10g+):
       * declared VARCHAR, 9i reads the binary value as text (seerdb
       * PROTOCOL.md §19.3, #172, #173). */
      type = b->oac_type;
      maxsize = b->oac_size;
      charset = 31;
      csfrm = 0;
      break;
    case ORA_TYPE_REFCURSOR: /* a REF CURSOR OUT: type 102, length 1 (#166) */
      type = ORA_TYPE_REFCURSOR;
      maxsize = 1;
      charset = 0;
      csfrm = 0;
      break;
    default:
      break; /* VARCHAR / LONG / unbound -> str */
    }
  if (fv2_block_wide(b)) /* past the inline limits: a block's 32767 (§19.3.1) */
    maxsize = FV2_BLOCK_WIDE_DECLARED;
  if (b->fv2_lob != 0) {
    /* A value past what 9.2 takes inline, bound as the temporary LOB it was
     * written to: the LOB at 3876 - under 4000, so a statement doesn't read it
     * as LONG-class, last - charset 31, form 1 (§19.3.1, #169). */
    type = b->fv2_lob;
    maxsize = 3876;
    charset = 31;
    csfrm = 1;
  }
  if (b->ret_lob != 0) {
    /* A RETURNING target that is a CLOB / BLOB: the LOB at its own OAC,
     * charset 31, form 1; any size goes, and a pure OUT sends no value
     * (seerdb PROTOCOL.md §19.17b, ojdbc14 on 9.2.0.4; #167). */
    type = b->ret_lob;
    maxsize = FV2_BLOCK_WIDE_DECLARED;
    charset = 31;
    csfrm = 1;
  }
  SeerOacMsg m = {
      .data_type = type, .flags = 0x01, .max_length = maxsize, .charset = charset, .csfrm = csfrm};
  oac_write(w, false, TTC_FIELD_VERSION_9_2, &m); /* #395 */
}

/* Build the TTI_ALL7 parse message (shared by SELECT and DML). With input binds
 * the option word flips to 0x29, a bind-count field precedes the SQL, and each
 * bind's OAC follows, then one RXD a row (an array DML sends them all in this
 * one call, the tail counting the rows; seerdb #2245). The RXD value bytes are
 * exactly what the TTI_ALL8 path stored in b->rxd. */
/* The SQL's length as 9i reads it in a TTI_ALL7 call: in characters, not the
 * UTF-8 bytes that carry it. Sent the byte count, 9.2.0.4 waited for the
 * characters it was still owed, and a statement with a non-ASCII character
 * in its text hung (#140; seerdb _o7_sql_length, #2275). */
static uint32_t fv2_sql_chars(const char *sql)
{
  uint32_t n = 0;
  for (const unsigned char *p = (const unsigned char *)sql; *p != '\0'; p++)
    if ((*p & 0xC0) != 0x80) /* not a continuation byte */
      n++;
  return n;
}

/* A 9i call's head and body by their schemas (#398): the function header
 * (sequence 0, as ojdbc14 sends it) and SEER_O7_ALL7_SCHEMA. */
static void fv2_call_head(SeerWriter *w, uint8_t function)
{
  SeerSchemaCtx cx = seer_msg_ctx(0, TTC_FIELD_VERSION_9_2, TTC_FIELD_VERSION_9_2);
  SeerFunHeadMsg h = {.type = TTI_FUN, .function = function};
  seer_schema_encode(SEER_FUN_HEAD_SCHEMA, &cx, &h, w);
}

static void fv2_all7(SeerWriter *w, const SeerO7All7Msg *m)
{
  SeerSchemaCtx cx = seer_msg_ctx(0, TTC_FIELD_VERSION_9_2, TTC_FIELD_VERSION_9_2);
  fv2_call_head(w, TTI_ALL7);
  seer_schema_encode(SEER_O7_ALL7_SCHEMA, &cx, m, w);
}

static SeerStatus fv2_emit_parse(SeerStmt *stmt, SeerWriter *w)
{
  size_t qlen = strlen(stmt->sql);
  int nb = stmt->npbinds;
  if (!seer_writer_init(w, 64 + qlen + (size_t)nb * 48))
    return SEER_ENOMEM;
  /* The option word: NOT_PLSQL | EXECUTE | PARSE, + BIND with binds. The
   * EXECUTE bit makes this call run the statement as well, so a describe
   * (seer_stmt_describe) drops it: a parse alone needs no bind values, where
   * with it a statement with placeholders answers ORA-01008. With batch errors
   * armed on an array DML, the 10g+ batch-errors bit, which 9.2 honours too
   * (seerdb #2247). */
  uint32_t opt = nb > 0 ? 0x8029u : 0x8021u;
  if (stmt->describe_only)
    opt &= ~0x20u;
  if (stmt->batch_errors && stmt->n_iters > 1)
    opt |= 0x80000u;
  int rows = (nb > 0 && stmt->n_iters > 1) ? stmt->n_iters : 1;
  SeerO7All7Msg m = {
      .options = opt,
      .cursor = stmt->conn->fv2_cursor,
      .sql_ptr = 1,
      .sql_len = (int64_t)fv2_sql_chars(stmt->sql),
      .binds_ptr = nb > 0,
      .bind_count = nb,
      .sql = {.p = (const uint8_t *)stmt->sql, .n = qlen},
      .rows = rows, /* 1, or an array DML's */
  };
  fv2_all7(w, &m);
  if (nb > 0) {
    for (int i = 0; i < nb; i++)
      fv2_bind_oac(w, &stmt->pbinds[i]);
    for (int row = 0; row < rows; row++) {
      seer_writer_u8(w, TTI_RXD);
      for (int i = 0; i < nb; i++) {
        SeerBind *b = &stmt->pbinds[i];
        uint8_t *rxd = (b->rxd != NULL) ? b->rxd[row] : NULL;
        if (rxd != NULL)
          seer_writer_bytes(w, rxd, b->rxd_len[row]);
        else
          chr_write(w, false, TTC_FIELD_VERSION_9_2, NULL, 0); /* unbound: NULL */
      }
    }
  }
  return seer_writer_ok(w) ? SEER_OK : SEER_ENOMEM;
}

/* Build the TTI_ALL7 anonymous-PL/SQL-block parse message. Like fv2_emit_parse but
 * the option word is 01 21 (no binds) / 02 04 29 (binds) - the 0x8000 inline-values
 * bit is OFF, so only the bind OACs go here; the IN values follow later in their own
 * RXD after the server's bind prompt (see fv2_execute_block). */
static SeerStatus fv2_emit_block(SeerStmt *stmt, SeerWriter *w)
{
  size_t qlen = strlen(stmt->sql);
  int nb = stmt->npbinds;
  if (!seer_writer_init(w, 64 + qlen + (size_t)nb * 32))
    return SEER_ENOMEM;
  /* EXECUTE | PARSE, + BIND and PL/SQL's 0x400 with binds */
  SeerO7All7Msg m = {
      .options = nb > 0 ? 0x0429 : 0x21,
      .cursor = stmt->conn->fv2_cursor,
      .sql_ptr = 1,
      .sql_len = (int64_t)fv2_sql_chars(stmt->sql),
      .binds_ptr = nb > 0,
      .bind_count = nb,
      .sql = {.p = (const uint8_t *)stmt->sql, .n = qlen},
      .rows = 1,
  };
  fv2_all7(w, &m);
  for (int i = 0; i < nb; i++)
    fv2_bind_oac(w, &stmt->pbinds[i]); /* OACs only, no inline values */
  return seer_writer_ok(w) ? SEER_OK : SEER_ENOMEM;
}

/* ---- Oracle 9i (fv2) LOB read: the two-call TTI_LOBOPS GETLEN + READ -------
 * 9i's LOBOPS is far shorter than the 10g+ form and comes as a pair per LOB cell:
 * GETLEN learns the length, READ pulls exactly that many chars/bytes. Every request
 * is `03 60 00 01 <sb4 loclen> <op middle> <locator[1:]> <trailer>`. The captured
 * locator (from the RXD) is echoed with its leading byte dropped. (PROTOCOL §19.5) */

/* Build + send a fv2 LOBOPS request (op `mid`, `trailer`) and receive the reply. */
static SeerStatus fv2_lobop_send(SeerConn *c, const uint8_t *loc, size_t loclen, SeerLobopMsg *m,
                                 const uint8_t *tail, size_t taillen, uint8_t **resp, size_t *rlen)
{
  SeerWriter w;
  if (!seer_writer_init(&w, 64 + loclen + taillen))
    return SEER_ENOMEM;
  fv2_call_head(&w, TTI_LOBOPS);
  m->src_ptr = 1;
  m->src_len = (int64_t)loclen;
  m->loc_len = loclen > 1 ? (int64_t)loclen - 1 : 0; /* its first byte goes as 00 */
  m->locator = (SeerBytes){.p = loclen > 1 ? loc + 1 : loc, .n = (size_t)m->loc_len};
  SeerSchemaCtx cx = seer_msg_ctx(0, TTC_FIELD_VERSION_9_2, TTC_FIELD_VERSION_9_2);
  seer_schema_encode(SEER_LOBOPS_SCHEMA, &cx, m, &w); /* #395 */
  if (taillen > 0)
    seer_writer_bytes(&w, tail, taillen);
  if (!seer_writer_ok(&w)) {
    seer_writer_free(&w);
    return SEER_ENOMEM;
  }
  SeerStatus st = fv2_txn(c, w.buf, w.len, resp, rlen);
  seer_writer_free(&w);
  return st;
}

/* GETLEN: the LOB length (chars for CLOB, bytes for BLOB). -1 on error. */
static int64_t fv2_lob_getlen(SeerConn *c, const uint8_t *loc, size_t loclen)
{
  uint8_t *resp = NULL;
  size_t rlen = 0;
  SeerLobopMsg m = {.short_amount_ptr = 1, .op = LOB_OP_GET_LENGTH, .has_amount = 1};
  if (fv2_lobop_send(c, loc, loclen, &m, NULL, 0, &resp, &rlen) != SEER_OK)
    return -1;
  /* The RPA: the locator echoed, then the length (SEER_LOBOPS_REPLY_SCHEMA). */
  int64_t amount = 0;
  if (rlen >= 1 && resp[0] == TTI_RPA) {
    SeerReader r;
    seer_reader_init(&r, resp + 1, rlen - 1);
    SeerLobopReplyMsg rm = {.has_amount = 1};
    SeerSchemaCtx cx = seer_msg_ctx(0, TTC_FIELD_VERSION_9_2, TTC_FIELD_VERSION_9_2);
    (void)seer_schema_decode(SEER_LOBOPS_REPLY_SCHEMA, &cx, &r, &rm);
    amount = rm.amount;
  }
  free(resp);
  return amount;
}

/* READ `amount` chars/bytes; accumulate reply packets until the zero-length
 * chunk terminator (the fv2 READ reply carries no OER call-status). */
static SeerStatus fv2_lob_read(SeerConn *c, const uint8_t *loc, size_t loclen, int64_t amount,
                               uint8_t **content, size_t *contentlen)
{
  *content = NULL;
  *contentlen = 0;
  uint8_t trailer[8];
  SeerWriter tw;
  if (!seer_writer_init(&tw, 8))
    return SEER_ENOMEM;
  seer_enc_sb4(&tw, (uint32_t)amount);
  size_t trlen = tw.len;
  memcpy(trailer, tw.buf, trlen);
  seer_writer_free(&tw);

  /* Send READ; the first reply comes back via fv2_lobop_send, then accumulate. */
  uint8_t *pkt = NULL;
  size_t plen = 0;
  (void)trlen;
  SeerLobopMsg m = {.short_src_off = 1,
                    .short_amount_ptr = 1,
                    .op = LOB_OP_READ,
                    .has_amount = 1,
                    .amount = amount};
  if (fv2_lobop_send(c, loc, loclen, &m, NULL, 0, &pkt, &plen) != SEER_OK)
    return SEER_EPROTO;
  SeerWriter acc;
  if (!seer_writer_init(&acc, (size_t)amount + 32)) {
    free(pkt);
    return SEER_ENOMEM;
  }
  seer_writer_bytes(&acc, pkt, plen);
  free(pkt);
  for (int guard = 0; guard < 1000000; guard++) {
    /* SEER_LOB_DATA_SCHEMA, its old framing: whole once the zero arrives,
     * short while the chunks are still coming. */
    if (seer_writer_ok(&acc) && acc.len >= 2 && acc.buf[0] == TTI_LOB) {
      SeerReader r;
      seer_reader_init(&r, acc.buf + 1, acc.len - 1);
      SeerSchemaCtx cx = seer_msg_ctx(0, TTC_FIELD_VERSION_9_2, TTC_FIELD_VERSION_9_2);
      SeerLobDataMsg lm = {0};
      SeerSchemaResult res = seer_schema_decode_ex(SEER_LOB_DATA_SCHEMA, &cx, &r, &lm);
      if (res == SCH_OK) {
        size_t n = lm.data.n;
        uint8_t *cont = malloc(n ? n : 1);
        if (cont != NULL && n > 0)
          memcpy(cont, lm.data.p, n);
        seer_schema_free(SEER_LOB_DATA_SCHEMA, &lm);
        seer_writer_free(&acc);
        if (cont == NULL)
          return SEER_ENOMEM;
        *content = cont;
        *contentlen = n;
        return SEER_OK;
      }
      seer_schema_free(SEER_LOB_DATA_SCHEMA, &lm);
    }
    uint8_t *more = NULL;
    size_t morelen = 0;
    if (seer_ttc_recv(c, &more, &morelen) != SEER_OK) {
      seer_writer_free(&acc);
      return SEER_EPROTO;
    }
    seer_writer_bytes(&acc, more, morelen);
    free(more);
  }
  seer_writer_free(&acc);
  return SEER_EPROTO;
}

/* 9i BFILE read: FILE_OPEN -> GETLEN -> READ -> FILE_CLOSE (PROTOCOL §19.8). The
 * FILE_OPEN reply's RPA carries an *updated* (open-flagged) locator that GETLEN /
 * READ / FILE_CLOSE must use. FILE_CLOSE always runs (best-effort). */

static SeerStatus fv2_bfile_read(SeerConn *c, const uint8_t *loc, size_t loclen, uint8_t **content,
                                 size_t *contentlen)
{
  static const uint8_t fopen_trl[] = {0x01, 0x0b};
  *content = NULL;
  *contentlen = 0;

  uint8_t *resp = NULL;
  size_t rlen = 0;
  (void)fopen_trl;
  SeerLobopMsg om = {.short_amount_ptr = 1, .op = LOB_OP_FILE_OPEN, .has_amount = 1, .amount = 11};
  if (fv2_lobop_send(c, loc, loclen, &om, NULL, 0, &resp, &rlen) != SEER_OK)
    return SEER_EPROTO;
  /* Opened locator: RPA 00 <ub1 len><body>  ->  00 <ub1 len><body>. A file
   * that won't open is answered with a status: its error (ORA-22285 for a
   * missing directory) is the cell's (#158). */
  if (rlen > 0 && resp[0] == TTI_OER) {
    fv2_set_error(c, resp, rlen);
    free(resp);
    return SEER_EDB;
  }
  SeerLobopReplyMsg orm = {0};
  SeerSchemaCtx ocx = seer_msg_ctx(0, TTC_FIELD_VERSION_9_2, TTC_FIELD_VERSION_9_2);
  SeerReader orr;
  if (rlen > 0)
    seer_reader_init(&orr, resp + 1, rlen - 1);
  if (rlen < 3 || resp[0] != TTI_RPA ||
      !seer_schema_decode(SEER_LOBOPS_REPLY_SCHEMA, &ocx, &orr, &orm)) {
    free(resp);
    return SEER_EPROTO;
  }
  size_t openedlen = 0;
  uint8_t *opened = seer_lobop_reply_locator(&orm, &openedlen); /* its length + body */
  free(resp);
  if (opened == NULL)
    return SEER_ENOMEM;

  int64_t amount = fv2_lob_getlen(c, opened, openedlen);
  SeerStatus rst = SEER_OK;
  if (amount > 0)
    rst = fv2_lob_read(c, opened, openedlen, amount, content, contentlen);

  uint8_t *cresp = NULL;
  size_t crlen = 0;
  SeerLobopMsg cm = {.op = LOB_OP_FILE_CLOSE};
  if (fv2_lobop_send(c, opened, openedlen, &cm, NULL, 0, &cresp, &crlen) == SEER_OK)
    free(cresp);
  free(opened);
  return rst;
}

/* Resolve every captured 9i LOB locator into its cell (while the cursor is open):
 * CLOB -> text; BLOB -> bytes (GETLEN + READ); BFILE -> bytes (OPEN/READ/CLOSE). */
static void fv2_resolve_lobs(SeerStmt *stmt)
{
  SeerConn *c = stmt->conn;
  for (size_t k = 0; k < stmt->nplobs; k++) {
    SeerPendingLob *p = &stmt->plobs[k];
    if (p->row >= stmt->nrows)
      continue;
    uint8_t *content = NULL;
    size_t clen = 0;
    if (p->ora_type == ORA_TYPE_BFILE) {
      if (fv2_bfile_read(c, p->locator, p->loclen, &content, &clen) == SEER_EDB) {
        record_cell_error(stmt, p->row, p->col);
        continue;
      }
    } else {
      /* A failed GETLEN (a negative length) or READ is the cell's error, as
       * for a BFILE above - not an empty value fetched as success (#349). */
      int64_t amount = fv2_lob_getlen(c, p->locator, p->loclen);
      if (amount < 0 || (amount > 0 && fv2_lob_read(c, p->locator, p->loclen, amount, &content,
                                                    &clen) != SEER_OK)) {
        free(content);
        record_cell_error(stmt, p->row, p->col);
        continue;
      }
    }
    SeerCell *cell = &stmt->rows[p->row][p->col];
    cell_set_bytes(cell, content ? content : (const uint8_t *)"", clen,
                   p->ora_type != ORA_TYPE_CLOB); /* CLOB text; BLOB/BFILE bytes */
    free(content);
  }
}

/* Oracle 9i SELECT: the four-call TTI_ALL7 sequence (binds via fv2_emit_parse). */
/* ===================================================== Oracle 8i dialect */

/* Oracle 8i (8.1.7) speaks neither 9i's ALL7 nor the 10g+ OALL8 but a
 * 9.2-era OALL8, its integers fixed-width little-endian (8i is x86), its
 * replies a fixed-width describe, row cells with a 4-byte trailer, and a
 * status at fixed widths (seerdb PROTOCOL.md §19.9-19.12). 8i marks no packet
 * as a reply's last, so a reply is read on until it decodes whole. */

/* Statement types (OCI_STMT_*), carried in al8i4[7]; 0 is transaction control. */
#define O8I_STMT_SELECT 1
#define O8I_STMT_UPDATE 2
#define O8I_STMT_DELETE 3
#define O8I_STMT_INSERT 4
#define O8I_STMT_CREATE 5
#define O8I_STMT_DROP 6
#define O8I_STMT_ALTER 7
#define O8I_STMT_BEGIN 8
#define O8I_STMT_DECLARE 9
#define O8I_STMT_TXN 0

/* A strict reader over a reply that may still be incomplete: `cut` says a
 * field ran past the bytes received (read on), `bad` that the bytes cannot be
 * the expected reply. */
typedef struct {
  const uint8_t *b;
  size_t n, pos;
  bool cut, bad;
} O8iRd;

static bool o8r_has(O8iRd *r, size_t k)
{
  if (r->cut || r->bad)
    return false;
  if (r->pos + k > r->n) {
    r->cut = true;
    return false;
  }
  return true;
}

static uint8_t o8r_u8(O8iRd *r)
{
  return o8r_has(r, 1) ? r->b[r->pos++] : 0;
}

static void o8w_le32(SeerWriter *w, uint32_t v)
{
  for (int i = 0; i < 4; i++)
    seer_writer_u8(w, (uint8_t)(v >> (8 * i)));
}

/* A value as 8i writes one, SEER_CHR_SCHEMA at 8i's widths (#398): a length
 * byte up to 64 bytes, else 0xFE, 64-byte chunks and a zero length. */
static void o8w_chr(SeerWriter *w, const uint8_t *p, size_t n)
{
  SeerChrMsg m = {.value = {.p = p, .n = n}};
  SeerSchemaCtx cx = seer_msg_ctx(1, 0, 0);
  seer_schema_encode(SEER_CHR_SCHEMA, &cx, &m, w);
}

/* UTF-8 text in 8i's session charset, WE8ISO8859P1: a character it cannot hold
 * becomes the inverted question mark, as the server puts one (seerdb #2276). */
static uint8_t *o8i_latin1_n(const char *u8, size_t n, size_t *outlen)
{
  size_t k = 0;
  uint8_t *out = malloc(n + 1);
  if (out == NULL)
    return NULL;
  for (size_t i = 0; i < n;) {
    unsigned char c = (unsigned char)u8[i];
    uint32_t cp;
    size_t len;
    if (c < 0x80) {
      cp = c, len = 1;
    } else if ((c & 0xE0) == 0xC0 && i + 1 < n) {
      cp = (uint32_t)(c & 0x1F) << 6 | ((unsigned char)u8[i + 1] & 0x3F), len = 2;
    } else if ((c & 0xF0) == 0xE0) {
      cp = 0x100, len = 3;
    } else if ((c & 0xF8) == 0xF0) {
      cp = 0x100, len = 4;
    } else {
      cp = 0x100, len = 1;
    }
    out[k++] = cp < 0x100 ? (uint8_t)cp : 0xBF;
    i += len;
  }
  *outlen = k;
  return out;
}

static uint8_t *o8i_latin1(const char *u8, size_t *outlen)
{
  return o8i_latin1_n(u8, strlen(u8), outlen);
}

/* Latin-1 bytes as a UTF-8 cell. */
static SeerStatus o8i_text_cell(SeerCell *cell, const uint8_t *p, size_t n)
{
  SeerWriter w;
  if (!seer_writer_init(&w, n * 2 + 1))
    return SEER_ENOMEM;
  for (size_t i = 0; i < n; i++) {
    if (p[i] < 0x80) {
      seer_writer_u8(&w, p[i]);
    } else {
      seer_writer_u8(&w, (uint8_t)(0xC0 | p[i] >> 6));
      seer_writer_u8(&w, (uint8_t)(0x80 | (p[i] & 0x3F)));
    }
  }
  SeerStatus st = seer_writer_ok(&w) ? cell_set_bytes(cell, w.buf, w.len, false) : SEER_ENOMEM;
  seer_writer_free(&w);
  return st;
}

/* The 8i OALL8 head (seerdb _O8I_ALL8): the option word, the cursor, the SQL's
 * pointer and length, al8i4's pointer and count (12), al8o4 / al8o4l, the
 * prefetch fields, the LONG size, the binds' pointer and count, the al8app ..
 * al8kvl pointers, then the SQL text when there is one and the twelve al8i4
 * words: [0] 1 for an execute / 0 for a fetch, [1] the execute flag or the
 * rows a fetch asks for, [7] the statement type. */
static void o8i_all8(SeerConn *c, SeerWriter *w, uint32_t options, uint32_t cursor,
                     const uint8_t *sql, size_t sqllen, bool has_sql, uint32_t prefetch_rows,
                     uint32_t max_long, uint32_t bind_count, uint32_t i0, uint32_t i1, uint32_t i7)
{
  seer_ttc_fun_header(c, w, TTI_ALL8);
  /* SEER_ALL8_SCHEMA at 8i's widths (#398): al8o4l and al8kvl set, no
   * defines or register; the SQL by SF_SQL, the pre-10g chunked string. */
  uint32_t i4[12] = {0};
  i4[0] = i0, i4[1] = i1, i4[7] = i7;
  SeerAll8Msg am = {
      .options = options,
      .cursor = cursor,
      .sql_ptr = has_sql,
      .sql_len = has_sql ? (int64_t)sqllen : 0,
      .al8i4_ptr = 1,
      .al8i4_len = 12,
      .al8o4l = 1,
      .prefetch_rows = prefetch_rows,
      .max_long = max_long,
      .binds_ptr = bind_count != 0,
      .bind_count = bind_count,
      .al8kvl = 1,
      .sql = {.p = sql, .n = has_sql ? sqllen : 0},
      .al8i4 = i4,
      .al8i4_n = 12,
  };
  SeerSchemaCtx cx = seer_msg_ctx(1, 0, 0);
  seer_schema_encode(SEER_ALL8_SCHEMA, &cx, &am, w);
}

/* The close of the finished cursors, piggybacked ahead of the next call
 * (seerdb encode_8i_close_cursors, #2286): 8i keeps a statement's cursor open
 * until closed, and left open a session runs out at open_cursors. */
static void o8i_closing(SeerConn *c, SeerWriter *w)
{
  if (c->n_close == 0)
    return;
  /* SEER_CLOSE_CURSORS_SCHEMA, as 10g+'s, at 8i's widths (#398) */
  SeerSchemaCtx cx = seer_msg_ctx(1, 0, 0);
  SeerFunHeadMsg h = {
      .type = TTI_MSG_TYPE_PIGGYBACK, .function = TTI_OCCA, .seq = seer_ttc_next_seq(c)};
  SeerCloseCursorsMsg cc = {.list_ptr = 1, .ids = c->close_cursors, .n = c->n_close};
  seer_schema_encode(SEER_FUN_HEAD_SCHEMA, &cx, &h, w);
  seer_schema_encode(SEER_CLOSE_CURSORS_SCHEMA, &cx, &cc, w);
  c->n_close = 0;
}

/* An 8i status (seerdb _O8I_STATUS), behind an optional RPA (08, ub2 count,
 * that many ub4s, four zero bytes). */
typedef struct {
  uint32_t rows;
  uint32_t code;
  uint32_t cursor;
  uint32_t position;
  uint8_t warnings;
  uint8_t flags; /* 0x40: no transaction open (seerdb bus 95, #344) */
  bool complete; /* the whole fixed part was read */
  char *message; /* UTF-8, when the code is set */
} O8iStatus;

static void o8i_status_free(O8iStatus *s)
{
  free(s->message);
  s->message = NULL;
}

static void o8i_read_status(O8iRd *r, O8iStatus *s)
{
  memset(s, 0, sizeof *s);
  if (o8r_has(r, 1) && r->b[r->pos] == TTI_RPA) {
    r->pos++;
    /* SEER_RPA_HEAD / _TAIL_SCHEMA at 8i's widths (#398): the parameters,
     * the transaction id (0 in every reply seen) and the changed settings -
     * an ALTER SESSION returns its 16 NLS values (8.1.7, 2026-11-14); read as
     * four zero bytes, the status behind one was not found. */
    SeerReader rr;
    seer_reader_init(&rr, r->b + r->pos, r->n - r->pos);
    SeerSchemaCtx rcx = seer_msg_ctx(1, 0, 0);
    SeerRpaMsg rm = {0};
    SeerSchemaResult res = seer_schema_decode_ex(SEER_RPA_HEAD_SCHEMA, &rcx, &rr, &rm);
    if (res == SCH_OK)
      res = seer_schema_decode_ex(SEER_RPA_TAIL_SCHEMA, &rcx, &rr, &rm);
    seer_schema_free(SEER_RPA_TAIL_SCHEMA, &rm);
    if (res == SCH_SHORT) {
      r->cut = true;
      return;
    }
    if (res == SCH_BAD) {
      r->bad = true;
      return;
    }
    r->pos += rr.pos;
  }
  if (!o8r_has(r, 1))
    return; /* cut: the caller reads on until the status arrives */
  if (r->b[r->pos] != TTI_OER) {
    r->bad = true;
    return;
  }
  r->pos++;
  /* SEER_OER_*_SCHEMA at 8i's widths (#395 spike): no call status or
   * sequence; rows a ub4, code / cursor / position ub2s; the flags' 0x40 says
   * no transaction is open (bus 95). The batch counts are three ub4s. */
  SeerReader sr;
  seer_reader_init(&sr, r->b + r->pos, r->n - r->pos);
  SeerSchemaCtx cx = seer_msg_ctx(1, 0, 0);
  SeerOerMsg om = {0};
  bool whole = seer_schema_decode(SEER_OER_HEAD_SCHEMA, &cx, &sr, &om) &&
               seer_schema_decode(SEER_OER_FLAGS_SCHEMA, &cx, &sr, &om) &&
               seer_schema_decode(SEER_OER_BATCH_SCHEMA, &cx, &sr, &om);
  seer_schema_free(SEER_OER_BATCH_SCHEMA, &om);
  s->rows = (uint32_t)om.rows;
  s->code = (uint32_t)om.code;
  s->cursor = (uint32_t)om.cursor;
  s->position = (uint32_t)om.position;
  s->flags = (uint8_t)om.flags;
  s->warnings = (uint8_t)om.warnings;
  if (!whole) {
    r->cut = true;
    return;
  }
  r->pos += sr.pos;
  s->complete = true;
  if (s->code != 0) {
    SeerOerMsg tm = {.code = om.code};
    if (!seer_schema_decode(SEER_OER_TAIL_SCHEMA, &cx, &sr, &tm)) {
      seer_schema_free(SEER_OER_TAIL_SCHEMA, &tm);
      r->cut = true;
      return;
    }
    r->pos = (size_t)(sr.buf - r->b) + sr.pos;
    SeerWriter m;
    if (!seer_writer_init(&m, 64)) {
      seer_schema_free(SEER_OER_TAIL_SCHEMA, &tm);
      r->bad = true;
      return;
    }
    seer_writer_bytes(&m, tm.message.p, tm.message.n);
    seer_schema_free(SEER_OER_TAIL_SCHEMA, &tm);
    if (seer_writer_ok(&m)) {
      SeerCell tmp = {0};
      if (o8i_text_cell(&tmp, m.buf, m.len) == SEER_OK) {
        s->message = malloc(tmp.len + 1);
        if (s->message != NULL) {
          memcpy(s->message, tmp.data, tmp.len);
          s->message[tmp.len] = '\0';
          while (tmp.len > 0 && (s->message[tmp.len - 1] == '\n' || s->message[tmp.len - 1] == ' '))
            s->message[--tmp.len] = '\0';
        }
      }
      free(tmp.data);
    }
    seer_writer_free(&m);
  }
}

/* An 8i status says whether a transaction is open: bit 0x40 of its flags is
 * set when none is - the inverse of 10g's call_status 0x02, and on every
 * status, a query's and an error's too (seerdb bus 95, #344). */
static void o8i_note_txn(SeerConn *c, const O8iStatus *s)
{
  if (c != NULL && s->complete)
    c->txn_state = (s->flags & 0x40) ? 0 : 1;
}

/* Test-only: read an 8i status reply; 0 when well formed (*code the ORA code),
 * -1 when malformed, 1 when cut short. */
int seer_test_o8i_status(const uint8_t *buf, size_t len, uint32_t *code)
{
  O8iRd r = {.b = buf, .n = len};
  O8iStatus s;
  o8i_read_status(&r, &s);
  *code = s.code;
  o8i_status_free(&s);
  return r.bad ? -1 : r.cut ? 1 : 0;
}

/* The 8i describe (seerdb _O8I_DESCRIBE): TTI_DCB, a 25-byte preamble value,
 * the max row size, the column count and - with columns - a byte, then each
 * column (9i's OAC at fixed widths, nullability, the name, the type's schema
 * and name), then the describe time (a ub4 length and the date). */
static void o8i_read_columns(O8iRd *r, bool cursor_cell, SeerColumn **out, int *ncols);
static void o8i_read_describe(O8iRd *r, SeerColumn **out, int *ncols)
{
  *out = NULL;
  *ncols = 0;
  if (o8r_u8(r) != TTI_DCB) {
    if (!r->cut)
      r->bad = true;
    return;
  }
  o8i_read_columns(r, false, out, ncols);
}

static SeerSchemaResult o8i_decode(O8iRd *r, const SeerField *schema, void *msg);

/* The describe's body. A cursor's cell - a REF CURSOR OUT value, a CURSOR()
 * column - carries it too, with the max row size ahead of the preamble, which
 * is empty there (seerdb §19.17a, from sqlplus 9.2 against 8.1.7). `out` may
 * be NULL to read past the columns. */
static void o8i_read_columns(O8iRd *r, bool cursor_cell, SeerColumn **out, int *ncols)
{
  if (out != NULL) {
    *out = NULL;
    *ncols = 0;
  }
  /* The preamble, a value, and the describe head about it (#398): before it
   * the row size in a cursor cell, after it otherwise. */
  SeerDescribeHeadMsg hm = {0};
  SeerChrMsg pm = {0};
  if (cursor_cell)
    (void)o8i_decode(r, SEER_DESCRIBE_ROWSIZE_SCHEMA, &hm);
  if (!r->cut && !r->bad) {
    (void)o8i_decode(r, SEER_VALUE_SCHEMA, &pm);
    seer_schema_free(SEER_VALUE_SCHEMA, &pm);
  }
  if (!r->cut && !r->bad)
    (void)o8i_decode(r, cursor_cell ? SEER_DESCRIBE_COUNT_SCHEMA : SEER_DESCRIBE_HEAD_SCHEMA, &hm);
  if (r->cut || r->bad)
    return;
  if (hm.ncols < 0 || hm.ncols > 4096) {
    r->bad = true;
    return;
  }
  uint32_t n = (uint32_t)hm.ncols;
  SeerColumn *cols = calloc(n ? n : 1, sizeof *cols);
  if (cols == NULL) {
    r->bad = true;
    return;
  }
  SeerSchemaCtx cx = seer_msg_ctx(1, 0, 0);
  for (uint32_t i = 0; i < n && !r->cut && !r->bad; i++) {
    /* SEER_DCB_COLUMN_SCHEMA at 8i's widths (#398): the OAC's fields (no
     * max_chars), nullable, the name and the type's schema and name - an
     * object or collection column's, its layout read by them (#168). */
    SeerColumn *col = &cols[i];
    SeerReader sr;
    seer_reader_init(&sr, r->b + r->pos, r->n - r->pos);
    SeerDcbColumnMsg dm = {0};
    SeerSchemaResult res = seer_schema_decode_ex(SEER_DCB_COLUMN_SCHEMA, &cx, &sr, &dm);
    if (res != SCH_OK) {
      seer_schema_free(SEER_DCB_COLUMN_SCHEMA, &dm);
      if (res == SCH_SHORT)
        r->cut = true;
      else
        r->bad = true;
      break;
    }
    r->pos += sr.pos;
    col->ora_type = (uint8_t)dm.data_type;
    col->precision = (uint8_t)dm.precision;
    col->scale = (int8_t)dm.scale;
    col->max_size = (uint32_t)dm.max_length;
    col->char_size = col->byte_size = col->max_size; /* 8i: byte semantics only */
    col->charset = (uint16_t)dm.charset;
    col->null_ok = (uint8_t)dm.null_ok;
    col->name = bytes_dup_str(&dm.name);
    if (col->name == NULL)
      r->bad = true;
    col->n_obj_attrs = 0;
    if (col->ora_type == ORA_TYPE_ADT && dm.type_schema.n > 0 && dm.type_name.n > 0) {
      col->type_schema = bytes_dup_str(&dm.type_schema);
      col->type_name = bytes_dup_str(&dm.type_name);
      col->n_obj_attrs = -1; /* layout not yet fetched */
    }
    seer_schema_free(SEER_DCB_COLUMN_SCHEMA, &dm);
  }
  if (!r->cut && !r->bad) { /* SEER_DCB_TRAILER_SCHEMA: the describe time */
    SeerReader tr;
    seer_reader_init(&tr, r->b + r->pos, r->n - r->pos);
    SeerDcbTrailerMsg tm = {0};
    SeerSchemaResult res = seer_schema_decode_ex(SEER_DCB_TRAILER_SCHEMA, &cx, &tr, &tm);
    seer_schema_free(SEER_DCB_TRAILER_SCHEMA, &tm);
    if (res == SCH_OK)
      r->pos += tr.pos;
    else if (res == SCH_SHORT)
      r->cut = true;
    else
      r->bad = true;
  }
  if (r->cut || r->bad || out == NULL) {
    free_columns(cols, (int)n);
    return;
  }
  *out = cols;
  *ncols = (int)n;
}

/* A cursor's cell (§19.17a): the describe body, the cursor id (ub4) and a
 * ub2; a CURSOR() column's row cell adds a ub2 return code, as every 8i row
 * cell has. The cursor id into *cursor, the columns into `cols` when
 * non-NULL. */
static void o8i_read_cursor_cell(O8iRd *r, bool row_cell, SeerColumn **cols, int *ncols,
                                 uint32_t *cursor)
{
  o8i_read_columns(r, true, cols, ncols);
  /* The cursor id, SEER_COUNT_SCHEMA, then a row cell's trailer or an OUT
   * value's indicator (#398). */
  SeerCountMsg cm = {0};
  SeerCellMsg tm = {0};
  *cursor = 0;
  if (!r->cut && !r->bad && o8i_decode(r, SEER_COUNT_SCHEMA, &cm) == SCH_OK) {
    *cursor = (uint32_t)cm.n;
    (void)o8i_decode(r, row_cell ? SEER_CELL_TRAILER_SCHEMA : SEER_OUT_TAIL_SCHEMA, &tm);
  }
  if ((r->cut || r->bad) && cols != NULL && *cols != NULL) {
    free_columns(*cols, *ncols);
    *cols = NULL;
    *ncols = 0;
  }
}

/* One 8i cell (seerdb _O8I_CELL and kin): the value and a 4-byte trailer, an
 * sb2 indicator and a ub2 return code; NULL is the trailer alone (`ff ff ..`);
 * a LONG comes chunked, a NULL one as a bare zero; a ROWID a byte (0x0e, 0 for
 * NULL) and the rowid at fixed widths; a UROWID a ub2 length and a value. */
static SeerStatus o8i_read_cell(O8iRd *r, const SeerColumn *col, SeerCell *cell, uint32_t *nested)
{
  uint8_t t = col->ora_type;
  if (t == ORA_TYPE_ADT) {
    /* An object or collection: 9.2's object cell at 8i's widths - the type
     * block (a ub4 length and 36 bytes), the object OID and the snapshot, each
     * a ub4 length and its bytes, a ub2 version, a ub4 image length (0 for
     * NULL), ub2 flags, the image; then the trailer every 8i cell has (seerdb
     * PROTOCOL.md §19.17c, #168). Read as a plain value it came back as raw
     * framing bytes and the rows after it were lost. The image is kept for
     * o8i_resolve_lobs to decode by the type's layout. */
    /* SEER_OBJECT_SCHEMA at 8i's widths, then the cell's trailer (#398) */
    SeerReader sr;
    seer_reader_init(&sr, r->b + r->pos, r->n - r->pos);
    SeerSchemaCtx cx = seer_msg_ctx(1, 0, 0);
    SeerObjectMsg om = {0};
    SeerSchemaResult res = seer_schema_decode_ex(SEER_OBJECT_SCHEMA, &cx, &sr, &om);
    r->pos += sr.pos;
    if (res != SCH_OK) {
      seer_schema_free(SEER_OBJECT_SCHEMA, &om);
      if (res == SCH_SHORT)
        r->cut = true;
      else
        r->bad = true;
      return SEER_OK;
    }
    SeerCellMsg tm = {0}; /* SEER_CELL_TRAILER_SCHEMA: indicator, return code */
    (void)o8i_decode(r, SEER_CELL_TRAILER_SCHEMA, &tm);
    bool null = tm.indicator == 0xFFFF;
    SeerStatus st = SEER_OK;
    if (!r->cut && !r->bad && !null && om.image_len > 0 && om.image.n > 0)
      st = cell_set_bytes(cell, om.image.p, om.image.n, true);
    seer_schema_free(SEER_OBJECT_SCHEMA, &om);
    return st;
  }
  if (t == ORA_TYPE_REFCURSOR) {
    /* A CURSOR() column: ODBC has no nested cursor type, so it reads as NULL,
     * as on 9i; its cursor is named for closing (#166). */
    o8i_read_cursor_cell(r, true, NULL, NULL, nested);
    return SEER_OK;
  }
  /* The cell by its kind's schema, at 8i's widths (#398): a LOB's locator
   * (its ub4 length - 86 for a CLOB or BLOB, not the content's - and the
   * value, §19.10, §19.15, seerdb #387), a UROWID (a ub2 length), a ROWID's
   * fields, a LONG's or any other value; then the trailer, the indicator (-1
   * for NULL) and the return code. A NULL VARCHAR2 from a table comes as an
   * empty value and the trailer with the indicator -1, not as the trailer
   * alone (#153). */
  const SeerField *sch = SEER_CELL_SCHEMA;
  if (t == ORA_TYPE_CLOB || t == ORA_TYPE_BLOB || t == ORA_TYPE_BFILE)
    sch = SEER_LOB_CELL_SCHEMA;
  else if (t == ORA_TYPE_UROWID)
    sch = SEER_UROWID_CELL_SCHEMA;
  else if (t == ORA_TYPE_RID)
    sch = SEER_ROWID_CELL_SCHEMA;
  SeerReader sr;
  seer_reader_init(&sr, r->b + r->pos, r->n - r->pos);
  SeerSchemaCtx cx = seer_msg_ctx(1, 0, 0);
  SeerCellMsg m = {0};
  SeerSchemaResult res = seer_schema_decode_ex(sch, &cx, &sr, &m);
  if (res != SCH_OK) {
    seer_schema_free(sch, &m);
    if (res == SCH_SHORT)
      r->cut = true;
    else
      r->bad = true;
    return SEER_OK;
  }
  r->pos += sr.pos;
  bool null = m.indicator == 0xFFFF;
  if (t == ORA_TYPE_RID) {
    if (null || m.rowid_size == 0)
      return SEER_OK;
    char rid[18];
    rowid_b64((uint32_t)m.rowid_obj, 6, rid);
    rowid_b64((uint32_t)m.rowid_file, 3, rid + 6);
    rowid_b64((uint32_t)m.rowid_block, 6, rid + 9);
    rowid_b64((uint32_t)m.rowid_slot, 3, rid + 15);
    return cell_set_bytes(cell, rid, sizeof rid, false);
  }
  if (m.value.p == NULL)
    null = true;
  SeerWriter v;
  if (!seer_writer_init(&v, m.value.n + 1)) {
    seer_schema_free(sch, &m);
    return SEER_ENOMEM;
  }
  seer_writer_bytes(&v, m.value.p, m.value.n);
  seer_schema_free(sch, &m);
  SeerStatus st = SEER_OK;
  if (!null && seer_writer_ok(&v)) {
    switch (t) {
    case ORA_TYPE_CLOB:
    case ORA_TYPE_BLOB:
    case ORA_TYPE_BFILE:
      /* The locator, read for its content once the rows are in
       * (o8i_resolve_lobs). */
      st = cell_set_bytes(cell, v.buf, v.len, true);
      break;
    case ORA_TYPE_VARCHAR:
    case ORA_TYPE_CHAR:
    case ORA_TYPE_LONG:
      st = o8i_text_cell(cell, v.buf, v.len); /* WE8ISO8859P1 */
      break;
    case ORA_TYPE_UROWID:
      st = urowid_cell(v.buf, v.len, cell);
      break;
    default:
      if (v.len > 0)
        st = decode_scalar(t, v.buf, v.len, cell);
      break;
    }
  }
  seer_writer_free(&v);
  return st;
}

/* Rows (TTI_RXH headers and TTI_RXD rows) up to the status. A header's bit
 * vector names the columns its next row sends; a clear bit repeats the
 * previous row's value - across batches too. The rows go into `rows` (not the
 * statement) so a reply cut short can be read again whole. */
static SeerStatus o8i_read_rows(O8iRd *r, SeerStmt *stmt, SeerCell ***rows, size_t *nrows,
                                SeerWriter *nested)
{
  int ncols = stmt->ncols;
  uint8_t vec[512];
  size_t veclen = 0;
  SeerCell *prev = stmt->nrows > 0 ? stmt->rows[stmt->nrows - 1] : NULL;
  while (!r->cut && !r->bad && o8r_has(r, 1)) {
    uint8_t tok = r->b[r->pos];
    if (tok == TTI_RXH) {
      r->pos++;
      /* SEER_RXH_SCHEMA at 8i's widths: the counts ub2s (#398) */
      SeerReader sr;
      seer_reader_init(&sr, r->b + r->pos, r->n - r->pos);
      SeerSchemaCtx cx = seer_msg_ctx(1, 0, 0);
      SeerRxhMsg m = {0};
      SeerSchemaResult res = seer_schema_decode_ex(SEER_RXH_SCHEMA, &cx, &sr, &m);
      veclen = 0;
      if (res == SCH_OK && m.bit_vector.n > 0 && m.bit_vector.n <= sizeof vec) {
        memcpy(vec, m.bit_vector.p, m.bit_vector.n);
        veclen = m.bit_vector.n;
      }
      seer_schema_free(SEER_RXH_SCHEMA, &m);
      if (res == SCH_SHORT)
        r->cut = true;
      else if (res == SCH_BAD)
        r->bad = true;
      else
        r->pos += sr.pos;
    } else if (tok == TTI_RXD) {
      r->pos++;
      SeerCell *row = calloc(ncols ? (size_t)ncols : 1, sizeof *row);
      if (row == NULL)
        return SEER_ENOMEM;
      for (int i = 0; i < ncols && !r->cut && !r->bad; i++) {
        if (veclen > 0 && !((size_t)i / 8 < veclen && (vec[i / 8] >> (i % 8)) & 1)) {
          if (prev != NULL && prev[i].data != NULL &&
              cell_set_bytes(&row[i], prev[i].data, prev[i].len, prev[i].binary) != SEER_OK) {
            free(row);
            return SEER_ENOMEM;
          }
          continue;
        }
        uint32_t id = 0;
        SeerStatus st = o8i_read_cell(r, &stmt->cols[i], &row[i], &id);
        if (st == SEER_OK && id != 0 && !r->cut && !r->bad)
          o8w_le32(nested, id);
        if (st != SEER_OK) {
          for (int k = 0; k <= i; k++)
            free(row[k].data);
          free(row);
          return st;
        }
      }
      if (r->cut || r->bad) {
        for (int k = 0; k < ncols; k++)
          free(row[k].data);
        free(row);
        return SEER_OK;
      }
      SeerCell **nr = realloc(*rows, (*nrows + 1) * sizeof *nr);
      if (nr == NULL) {
        free(row);
        return SEER_ENOMEM;
      }
      *rows = nr;
      (*rows)[(*nrows)++] = row;
      prev = row;
      veclen = 0;
    } else {
      break;
    }
  }
  return SEER_OK;
}

/* Test-only (conn.h): an 8i query or fetch OALL8, as o8i_execute_select sends it. */
SeerStatus seer_test_o8i_all8(uint8_t seq, bool fetch, uint32_t cursor, const char *sql,
                              uint32_t rows, uint8_t **out, size_t *outlen)
{
  struct SeerConn conn;
  memset(&conn, 0, sizeof conn);
  conn.field_version = TTC_FIELD_VERSION_9_2;
  conn.seq = seq;
  SeerWriter w;
  if (!seer_writer_init(&w, 256))
    return SEER_ENOMEM;
  if (fetch)
    o8i_all8(&conn, &w, 0x40, cursor, NULL, 0, false, 0, 0x7FFFFFFF, 0, 0, rows, O8I_STMT_SELECT);
  else
    o8i_all8(&conn, &w, 0x8061, 0, (const uint8_t *)sql, strlen(sql), true, 1, 0, 0, 1, 0,
             O8I_STMT_SELECT);
  if (!seer_writer_ok(&w)) {
    seer_writer_free(&w);
    return SEER_ENOMEM;
  }
  *out = w.buf;
  *outlen = w.len;
  return SEER_OK;
}

static void o8i_free_staged(SeerCell **rows, size_t n, int ncols)
{
  for (size_t i = 0; i < n; i++) {
    for (int k = 0; k < ncols; k++)
      free(rows[i][k].data);
    free(rows[i]);
  }
  free(rows);
}

/* Receive one 8i reply, appending to `buf`, until `whole` says it decodes. */
static SeerStatus o8i_recv_more(SeerConn *c, SeerWriter *buf)
{
  uint8_t *resp = NULL;
  size_t rlen = 0;
  SeerStatus st = seer_ttc_recv(c, &resp, &rlen);
  if (st != SEER_OK)
    return st;
  seer_writer_bytes(buf, resp, rlen);
  free(resp);
  return seer_writer_ok(buf) ? SEER_OK : SEER_ENOMEM;
}

/* Record a status's error on the connection; SEER_EDB. */
static SeerStatus o8i_fail(SeerConn *c, O8iStatus *s)
{
  free(c->last_error);
  if (s->message != NULL) {
    c->last_error = s->message;
    s->message = NULL;
  } else {
    char m[32];
    snprintf(m, sizeof m, "ORA-%05u", (unsigned)s->code);
    c->last_error = strdup(m);
  }
  c->last_error_offset = (long)s->position;
  seer_log(SEER_LOG_DEBUG, "o8i: %s", c->last_error ? c->last_error : "error");
  return SEER_EDB;
}

/* Read the rows and the status of one execute / fetch reply, reading on until
 * both are whole, and commit the rows to the statement. The batch's CURSOR()
 * cells' cursors are closed ahead of the next call, the parent's next fetch
 * included: left open, 8i ran out at open_cursors (seerdb ID 54, #166). */
static SeerStatus o8i_rows_reply(SeerStmt *stmt, SeerWriter *buf, size_t start, O8iStatus *s)
{
  SeerConn *c = stmt->conn;
  SeerWriter nested;
  if (!seer_writer_init(&nested, 64))
    return SEER_ENOMEM;
  for (;;) {
    O8iRd r = {buf->buf, buf->len, start, false, false};
    SeerCell **rows = NULL;
    size_t nrows = 0;
    nested.len = 0; /* a reply read again names its cursors again */
    SeerStatus st = o8i_read_rows(&r, stmt, &rows, &nrows, &nested);
    if (st == SEER_OK && !r.cut && !r.bad)
      o8i_read_status(&r, s);
    if (!r.cut && !r.bad)
      o8i_note_txn(stmt->conn, s);
    if (st == SEER_OK && !seer_writer_ok(&nested))
      st = SEER_ENOMEM;
    if (st == SEER_OK && !r.cut && !r.bad) {
      for (size_t k = 0; k + 4 <= nested.len; k += 4) {
        const uint8_t *p = nested.buf + k;
        queue_cursor_close(c, (int64_t)((uint32_t)p[0] | (uint32_t)p[1] << 8 |
                                        (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24));
      }
      seer_writer_free(&nested);
      for (size_t i = 0; i < nrows && st == SEER_OK; i++) {
        st = append_row(stmt, rows[i]);
        if (st == SEER_OK)
          rows[i] = NULL;
      }
      for (size_t i = 0; i < nrows; i++)
        if (rows[i] != NULL) {
          for (int k = 0; k < stmt->ncols; k++)
            free(rows[i][k].data);
          free(rows[i]);
        }
      free(rows);
      return st;
    }
    o8i_free_staged(rows, nrows, stmt->ncols);
    o8i_status_free(s);
    if (st == SEER_OK && r.bad) {
      seer_log(SEER_LOG_ERROR, "o8i: unexpected reply at byte %zu", r.pos);
      st = SEER_EPROTO;
    }
    if (st == SEER_OK)
      st = o8i_recv_more(c, buf); /* cut short: the rest is on its way */
    if (st != SEER_OK) {
      seer_writer_free(&nested);
      return st;
    }
  }
}

/* An 8i SELECT (seerdb §19.9-19.10): the OALL8 parse + execute + fetch of the
 * first batch, whose reply is the describe, rows and a status naming the
 * cursor; then fetch OALL8s by that cursor until a batch ends with ORA-01403
 * or brings no rows. The cursor is closed with the next call. */
/* ------------------------------------------------------------ 8i IN binds */

/* Whether 8i can take this bind (seerdb PROTOCOL.md §19.11): VARCHAR2 / CHAR,
 * NUMBER, DATE and RAW values, and NULLs. `why` says what it can't take. */
static bool o8i_bind_ok(const SeerBind *b, bool block, const char **why)
{
  if (b->is_out && !block) {
    *why = "OUT and IN OUT parameters outside a PL/SQL block";
    return false;
  }
  if (b->oac_type == ORA_TYPE_REFCURSOR) {
    if (b->is_out && block)
      return true;
    *why = "REF CURSOR parameters other than a PL/SQL block's OUT";
    return false;
  }
  if ((b->oac_type == ORA_TYPE_ADT || b->oac_type == ORA_TYPE_REF) && b->oac_override != NULL)
    return true; /* an object or collection (#172), a REF (#241) */
  if (b->is_array && b->oac_override != NULL) {
    if (block)
      return true; /* an associative array (#172) */
    *why = "associative-array parameters outside a PL/SQL block";
    return false;
  }
  if (b->is_array || b->oac_override != NULL || b->obj_type != NULL || b->temp_lob) {
    *why = "array, object and LOB parameters";
    return false;
  }
  switch (b->oac_type) {
  case 0: /* unbound: a NULL */
  case ORA_TYPE_VARCHAR:
  case ORA_TYPE_CHAR:
  case ORA_TYPE_LONG:
  case ORA_TYPE_NUMBER:
  case ORA_TYPE_DATE:
  case ORA_TYPE_RAW:
  case ORA_TYPE_LONGRAW:
    return true;
  case ORA_TYPE_TIMESTAMP:
  case ORA_TYPE_TIMESTAMPTZ:
  case ORA_TYPE_TIMESTAMPLTZ:
  case ORA_TYPE_INTERVAL_YM:
  case ORA_TYPE_INTERVAL_DS:
    *why = "TIMESTAMP and INTERVAL parameters (8.1.7 has neither type)";
    return false;
  case ORA_TYPE_BFLOAT:
  case ORA_TYPE_BDOUBLE:
    *why = "BINARY_FLOAT / BINARY_DOUBLE parameters (a 10g type)";
    return false;
  default:
    *why = "parameters of this type";
    return false;
  }
}

static bool o8i_char_bind(const SeerBind *b)
{
  return b->oac_type == 0 || b->oac_type == ORA_TYPE_VARCHAR || b->oac_type == ORA_TYPE_CHAR ||
         b->oac_type == ORA_TYPE_LONG;
}

/* A value the pre-12.2 encode_chr wrote (a ub1 length, or 0xFE, ub1-length
 * chunks and a zero), back to its bytes. */
static SeerStatus o8i_unchunk(const uint8_t *v, size_t n, SeerWriter *out)
{
  if (n == 0)
    return SEER_EPROTO;
  if (v[0] != 0xFE) {
    if ((size_t)v[0] + 1 > n)
      return SEER_EPROTO;
    seer_writer_bytes(out, v + 1, v[0]);
    return SEER_OK;
  }
  for (size_t pos = 1; pos < n;) {
    uint8_t cl = v[pos++];
    if (cl == 0)
      return SEER_OK;
    if (pos + cl > n)
      return SEER_EPROTO;
    seer_writer_bytes(out, v + pos, cl);
    pos += cl;
  }
  return SEER_EPROTO;
}

/* The return buffer an OUT or IN OUT bind declares, at least `size`: text at
 * 4000 bytes and RAW at 2000, as 9i declares them, whatever the caller asked
 * for. A value longer than the caller's size is then cut to it, with the full
 * length kept (seer_stmt_out_truncated, 01004); declared at the caller's size,
 * PL/SQL raised ORA-06502 instead. */
static uint32_t o8i_out_buffer(const SeerBind *b, uint32_t size)
{
  uint32_t floor = 1;
  if (o8i_char_bind(b))
    floor = 4000;
  else if (b->oac_type == ORA_TYPE_RAW || b->oac_type == ORA_TYPE_LONGRAW)
    floor = 2000;
  if (b->oac_size > size)
    size = b->oac_size;
  return size > floor ? size : floor;
}

/* One bind's value as 8i reads it (§19.11), into `val`; its declared size into
 * *size. Text goes in WE8ISO8859P1, the session's charset, as the SQL does; a
 * NULL is the empty value 00; NUMBER, DATE and RAW are the bytes the bind
 * stored. */
static SeerStatus o8i_bind_value(const SeerBind *b, int row, SeerWriter *val, uint32_t *size)
{
  const uint8_t *v = b->rxd != NULL ? b->rxd[row] : NULL;
  size_t vn = b->rxd != NULL ? b->rxd_len[row] : 0;
  if (b->is_array) { /* built in 8i's form by the array bind (#172) */
    seer_writer_bytes(val, v, vn);
    *size = b->oac_size ? b->oac_size : 1;
    return SEER_OK;
  }
  if (b->fv2_lob != 0) { /* a temporary LOB's locator, as o8i_temp_lobs_begin built it */
    seer_writer_bytes(val, v, vn);
    *size = 32;
    return SEER_OK;
  }
  if (b->ret_lob != 0) {
    /* A LOB sends a locator even as a pure OUT: an empty one, a LE ub4 86,
     * the ub1 length 86, 00 54 and 84 zeros. With the OUT placeholder fd 01,
     * 8.1.7 waits for the value and the call hangs (§19.17b, #167). */
    static const uint8_t EMPTY_LOCATOR[86] = {0x00, 0x54};
    SeerLegacyLobBindMsg lm = {.loc_len = sizeof EMPTY_LOCATOR,
                               .locator = {.p = EMPTY_LOCATOR, .n = sizeof EMPTY_LOCATOR}};
    SeerSchemaCtx cx = seer_msg_ctx(1, 0, 0);
    seer_schema_encode(SEER_LEGACY_LOB_BIND_SCHEMA, &cx, &lm, val); /* #398 */
    *size = 32;
    return SEER_OK;
  }
  if (b->oac_type == ORA_TYPE_REF && b->oac_override != NULL) {
    /* A REF, IN or pure OUT: the value ref_bind built (#241, bus 88). */
    seer_writer_bytes(val, v, vn);
    *size = b->oac_size ? b->oac_size : 1;
    return SEER_OK;
  }
  if (b->oac_type == ORA_TYPE_REFCURSOR) {
    /* A REF CURSOR sends an empty slot, 01 00 (§19.17a). */
    o8i_slot(val, SEER_O8I_CURSOR_SLOT_SCHEMA);
    *size = 1;
    return SEER_OK;
  }
  if (b->is_out && b->out_only) {
    /* A pure OUT bind sends the fixed placeholder fd 01 in its slot, and
     * declares its return buffer (§19.14). */
    o8i_slot(val, SEER_O8I_OUT_SLOT_SCHEMA);
    *size = o8i_out_buffer(b, b->oac_size);
    return SEER_OK;
  }
  if (v == NULL || vn == 0 || (vn == 1 && v[0] == 0)) {
    chr_write(val, true, 0, NULL, 0); /* the empty value */
    *size = b->oac_size ? b->oac_size : 1;
    return SEER_OK;
  }
  if (!o8i_char_bind(b)) {
    seer_writer_bytes(val, v, vn);
    *size = b->oac_size ? b->oac_size : 1;
    return SEER_OK;
  }
  SeerWriter u8;
  if (!seer_writer_init(&u8, vn))
    return SEER_ENOMEM;
  SeerStatus st = o8i_unchunk(v, vn, &u8);
  size_t ln = 0;
  uint8_t *l1 =
      st == SEER_OK && seer_writer_ok(&u8) ? o8i_latin1_n((const char *)u8.buf, u8.len, &ln) : NULL;
  seer_writer_free(&u8);
  if (st != SEER_OK)
    return st;
  if (l1 == NULL)
    return SEER_ENOMEM;
  o8w_chr(val, l1, ln);
  free(l1);
  *size = ln ? (uint32_t)ln : 1;
  if (b->is_out) /* an IN OUT's return buffer */
    *size = o8i_out_buffer(b, *size);
  return SEER_OK;
}

/* One bind's descriptor (§19.11), 25 bytes, the describe column's OAC at 8i's
 * widths: the type, 0x03, two zero bytes, max_size as a little-endian ub2,
 * thirteen zero bytes, the charset (big-endian ub4: 31, WE8ISO8859P1, for
 * text), a zero and the form. Text goes as VARCHAR2 whatever its length: past
 * 4000 bytes the server reads it as LONG, after the others (o8i_binds). */
static void o8i_bind_oac(SeerWriter *w, const SeerBind *b, uint32_t size)
{
  if ((b->oac_type == ORA_TYPE_ADT || b->oac_type == ORA_TYPE_REF || b->is_array) &&
      b->oac_override != NULL) {
    seer_writer_bytes(w, b->oac_override, b->oac_override_len); /* an object, a REF, an array */
    return;
  }
  uint8_t type = ORA_TYPE_VARCHAR, csfrm = 1, flag = 0x03;
  uint32_t charset = 31;
  if (b->ret_lob != 0 || b->fv2_lob != 0) {
    /* A RETURNING target that is a CLOB / BLOB: flag 0x01, size 32, a CLOB
     * with its charset and form, a BLOB with neither (§19.17b, sqlplus 9.2
     * against 8.1.7; #167). */
    uint8_t lob = b->ret_lob != 0 ? b->ret_lob : b->fv2_lob;
    bool clob = lob == ORA_TYPE_CLOB;
    SeerOacMsg m = {.data_type = lob,
                    .flags = 0x01,
                    .max_length = 32,
                    .charset = clob ? 31 : 0,
                    .csfrm = clob ? 1 : 0};
    oac_write(w, true, 0, &m); /* #395 */
    return;
  }
  switch (b->oac_type) {
  case ORA_TYPE_NUMBER:
    type = ORA_TYPE_NUMBER, size = 22, charset = 0, csfrm = 0;
    break;
  case ORA_TYPE_DATE:
    type = ORA_TYPE_DATE, size = 7, charset = 0, csfrm = 0;
    break;
  case ORA_TYPE_RAW:
  case ORA_TYPE_LONGRAW:
    type = ORA_TYPE_RAW, charset = 0, csfrm = 0;
    break;
  case ORA_TYPE_REFCURSOR:
    type = ORA_TYPE_REFCURSOR, size = 1, charset = 0, csfrm = 0;
    break;
  default:
    if (b->oac_charset == ORA_CHARSET_AL16UTF16)
      csfrm = 2; /* national text (seer_stmt_bind_ntext), in the same charset */
    break;
  }
  if (size > 0xFFFF)
    size = 0xFFFF;
  SeerOacMsg m = {
      .data_type = type, .flags = flag, .max_length = size, .charset = charset, .csfrm = csfrm};
  oac_write(w, true, 0, &m); /* #395 */
}

/* The statement's binds, refused before anything is sent when 8i can't take
 * one: SEER_ENOTIMPL, the reason logged. */
static SeerStatus o8i_check_binds(SeerStmt *stmt, bool query, bool block)
{
  (void)query; /* an array query is refused on every tier (execute_now) */
  for (int i = 0; i < stmt->npbinds; i++) {
    const char *why = NULL;
    if (!o8i_bind_ok(&stmt->pbinds[i], block, &why)) {
      seer_log(SEER_LOG_WARNING, "stmt: Oracle 8i: %s are not supported (parameter %d)", why,
               i + 1);
      return SEER_ENOTIMPL;
    }
  }
  return SEER_OK;
}

/* The bind section an OALL8 with binds ends in (§19.11): every bind's
 * descriptor, one 0x07, then every value. A value declared past 4000 bytes is
 * LONG-class, and 8i, as 10g+ (§5.4), reads it after the others: written in
 * place, it swapped with the next bind. */
static SeerStatus o8i_binds(SeerStmt *stmt, int row, bool block, SeerWriter *w)
{
  int nb = stmt->npbinds;
  SeerWriter *vals = calloc((size_t)nb, sizeof *vals);
  uint32_t *sizes = calloc((size_t)nb, sizeof *sizes);
  SeerStatus st = (vals == NULL || sizes == NULL) ? SEER_ENOMEM : SEER_OK;
  int made = 0;
  for (; st == SEER_OK && made < nb; made++) {
    if (!seer_writer_init(&vals[made], 32)) {
      st = SEER_ENOMEM;
      break;
    }
    st = o8i_bind_value(&stmt->pbinds[made], row, &vals[made], &sizes[made]);
    if (st == SEER_OK && !seer_writer_ok(&vals[made]))
      st = SEER_ENOMEM;
  }
  if (st == SEER_OK) {
    for (int i = 0; i < nb; i++)
      o8i_bind_oac(w, &stmt->pbinds[i], sizes[i]);
    seer_writer_u8(w, TTI_RXD);
    for (int pass = 0; pass < (block ? 1 : 2); pass++)
      for (int i = 0; i < nb; i++) {
        const SeerBind *b = &stmt->pbinds[i];
        bool varlen =
            o8i_char_bind(b) || b->oac_type == ORA_TYPE_RAW || b->oac_type == ORA_TYPE_LONGRAW;
        bool is_long = !block && varlen && sizes[i] > 4000;
        if (is_long == (pass == 1))
          seer_writer_bytes(w, vals[i].buf, vals[i].len);
      }
  }
  for (int i = 0; i < made && vals != NULL; i++)
    seer_writer_free(&vals[i]);
  free(vals);
  free(sizes);
  return st;
}

/* ------------------------------------------------- 8i DML, DDL, COMMIT */

/* The statement type 8i's OALL8 carries at al8i4[7] (seerdb o8i_stmt_type),
 * from the first keyword: what isn't one of these - COMMIT, ROLLBACK,
 * SAVEPOINT, SET TRANSACTION, GRANT, ... - is 0, a statement with no cursor
 * of its own in the option word. */
static uint32_t o8i_stmt_type(const char *sql)
{
  static const struct {
    const char *kw;
    uint32_t type;
  } map[] = {
      {"SELECT", O8I_STMT_SELECT}, {"UPDATE", O8I_STMT_UPDATE},   {"DELETE", O8I_STMT_DELETE},
      {"INSERT", O8I_STMT_INSERT}, {"CREATE", O8I_STMT_CREATE},   {"DROP", O8I_STMT_DROP},
      {"ALTER", O8I_STMT_ALTER},   {"TRUNCATE", O8I_STMT_CREATE},
  };
  const char *p = sql_first_keyword(sql);
  for (size_t i = 0; i < sizeof map / sizeof map[0]; i++)
    if (starts_with_word(p, map[i].kw))
      return map[i].type;
  return O8I_STMT_TXN;
}

/* One 8i statement that isn't a query (seerdb PROTOCOL.md §19.12): the same
 * OALL8, its option word PARSE | EXECUTE (0x21), + BIND (0x08) with binds,
 * and 0x80 in the next byte for a cursor statement, none for transaction
 * control; al8i4 says execute (1) and the type. `stmt` gives the binds, row
 * `row`, or is NULL. The reply is an RPA and the status, or the status alone;
 * the status is in *s, its cursor closed with the next call. */
static SeerStatus o8i_call(SeerConn *c, SeerStmt *stmt, const char *sql, int row, O8iStatus *s)
{
  memset(s, 0, sizeof *s);
  size_t sqllen = 0;
  uint8_t *text = o8i_latin1(sql, &sqllen);
  if (text == NULL)
    return SEER_ENOMEM;
  int nb = stmt != NULL ? stmt->npbinds : 0;
  uint32_t type = o8i_stmt_type(sql);
  uint32_t options = 0x21 | (nb > 0 ? 0x08 : 0) | (type != O8I_STMT_TXN ? 0x8000 : 0);
  SeerWriter w;
  if (!seer_writer_init(&w, 160 + sqllen + (size_t)nb * 32)) {
    free(text);
    return SEER_ENOMEM;
  }
  o8i_closing(c, &w);
  o8i_all8(c, &w, options, 0, text, sqllen, true, 1, 0, (uint32_t)nb, 1, 1, type);
  free(text);
  SeerStatus st = nb > 0 ? o8i_binds(stmt, row, false, &w) : SEER_OK;
  if (st == SEER_OK)
    st = seer_writer_ok(&w) ? seer_ttc_send(c, w.buf, w.len) : SEER_ENOMEM;
  seer_writer_free(&w);
  if (st != SEER_OK)
    return st;

  SeerWriter buf;
  if (!seer_writer_init(&buf, 256))
    return SEER_ENOMEM;
  /* 8i marks no packet as a reply's last: read on until the status is whole,
   * its message too. */
  for (;;) {
    st = o8i_recv_more(c, &buf);
    if (st != SEER_OK)
      break;
    O8iRd r = {buf.buf, buf.len, 0, false, false};
    o8i_read_status(&r, s);
    o8i_note_txn(c, s);
    if (r.bad) {
      o8i_status_free(s);
      st = SEER_EPROTO;
      break;
    }
    if (!r.cut)
      break;
    o8i_status_free(s);
  }
  seer_writer_free(&buf);
  if (st == SEER_OK && s->cursor != 0)
    queue_cursor_close(c, s->cursor);
  return st;
}

/* COMMIT or ROLLBACK: 8i has no TTI_COMMIT / TTI_ROLLBACK; they go as
 * ordinary statements of type 0 (§19.12). */
SeerStatus seer_o8i_tran(SeerConn *c, bool commit)
{
  O8iStatus s;
  SeerStatus st = o8i_call(c, NULL, commit ? "COMMIT" : "ROLLBACK", 0, &s);
  if (st == SEER_OK && s.code != 0)
    st = o8i_fail(c, &s);
  o8i_status_free(&s);
  return st;
}

/* Record row `row`'s failure of a batch-errors array execute. */
static void o8i_batch_error(SeerStmt *stmt, int row, O8iStatus *s)
{
  SeerBatchError *nb = realloc(stmt->berrs, (stmt->nberrs + 1) * sizeof *nb);
  if (nb == NULL)
    return;
  stmt->berrs = nb;
  nb[stmt->nberrs].row = (uint32_t)row;
  nb[stmt->nberrs].code = s->code;
  nb[stmt->nberrs].message = s->message;
  s->message = NULL;
  stmt->nberrs++;
}

/* INSERT / UPDATE / DELETE, DDL and the rest that isn't a query or a block.
 * 8i has no array DML (its status has no batch-error arrays, §19.12), so an
 * array execute goes a row at a time: it stops at the first failing row, as
 * an array DML does, or with batch errors armed records the row and goes on.
 * Autocommit commits after it, as on 9i. */
static SeerStatus o8i_execute_dml(SeerStmt *stmt)
{
  SeerConn *c = stmt->conn;
  free_rows(stmt);
  free_columns(stmt->cols, stmt->ncols);
  stmt->cols = NULL;
  stmt->ncols = 0;
  free_batch_errors(stmt);
  stmt->compile_warning = false;
  int rows = (stmt->npbinds > 0 && stmt->n_iters > 1) ? stmt->n_iters : 1;
  bool keep_going = stmt->batch_errors && rows > 1;
  long affected = 0;
  for (int row = 0; row < rows; row++) {
    O8iStatus s;
    SeerStatus st = o8i_call(c, stmt, stmt->sql, row, &s);
    if (st != SEER_OK)
      return st;
    if (s.code != 0 && s.code != 1403) {
      if (keep_going) {
        o8i_batch_error(stmt, row, &s);
        o8i_status_free(&s);
        continue;
      }
      stmt->affected = affected;
      st = o8i_fail(c, &s);
      o8i_status_free(&s);
      return st;
    }
    affected += (long)s.rows;
    /* A CREATE whose object compiled with errors succeeds; the warning flags
     * say so (seerdb #2262). */
    if (s.warnings & 0x20)
      stmt->compile_warning = true;
    o8i_status_free(&s);
  }
  stmt->affected = affected;
  stmt->executed = true;
  if (c->autocommit && o8i_stmt_type(stmt->sql) != O8I_STMT_TXN)
    return seer_o8i_tran(c, true);
  return SEER_OK;
}

/* ------------------------------------------------------- 8i LOB reads */

/* One 8i TTI_LOBOPS request (seerdb _O7_LOBOPS at 8i's widths, §19.15,
 * §19.17): the source locator's pointer and ub4 length, no destination, the
 * ub4 source and destination offsets, no charset, the amount's and the null
 * flag's pointers, the ub4 operation, no SCN, then the locator - as the row
 * cell carried it - and the ub4 amount when asked for. */
static SeerStatus o8i_lobop_send(SeerConn *c, const uint8_t *loc, size_t loclen, uint32_t op,
                                 uint32_t offset, bool has_amount, uint32_t amount)
{
  SeerWriter w;
  if (!seer_writer_init(&w, 64 + loclen))
    return SEER_ENOMEM;
  o8i_closing(c, &w);
  seer_ttc_fun_header(c, &w, TTI_LOBOPS);
  SeerLobopMsg m = {
      .src_ptr = 1,
      .src_len = (int64_t)loclen,
      .short_src_off = offset,
      .short_amount_ptr = has_amount,
      .op = op,
      .loc_len = (int64_t)loclen,
      .locator = {.p = loc, .n = loclen},
      .has_amount = has_amount,
      .amount = amount,
  };
  SeerSchemaCtx cx = seer_msg_ctx(1, 0, 0);
  seer_schema_encode(SEER_LOBOPS_SCHEMA, &cx, &m, &w); /* #395 */
  SeerStatus st = seer_writer_ok(&w) ? seer_ttc_send(c, w.buf, w.len) : SEER_ENOMEM;
  seer_writer_free(&w);
  return st;
}

/* One LOBOPS call's reply, read whole (8i marks no packet a reply's last):
 * for a READ the TTI_LOB content (0e, fe, ub1-length chunks, a zero; none
 * for an empty LOB, seerdb #387) into `content`; then the RPA (seerdb
 * _O7_LOBOPS_REPLY at 8i's widths: the locator as the server now has it, a
 * big-endian ub2 length and the bytes, and the ub4 amount when the request
 * asked for one - the length a GETLEN or READ gives, FILE_OPEN's mode) and
 * the status. A call that fails sends the status alone. The locator into
 * *loc when asked for (FILE_OPEN's, its open flag set), the amount into
 * *amount. Measured on 8.1.7: `08 00 54 <84 bytes> 0a 00 00 00 04 ...` after
 * a 10-character CLOB. */
static SeerStatus o8i_lobop_reply(SeerConn *c, bool has_amount, SeerWriter *content, uint8_t **loc,
                                  size_t *loclen, uint32_t *amount)
{
  SeerWriter buf;
  if (!seer_writer_init(&buf, 512))
    return SEER_ENOMEM;
  SeerStatus st;
  O8iStatus s = {0};
  SeerSchemaCtx cx = seer_msg_ctx(1, 0, 0);
  SeerLobDataMsg lm = {0};
  SeerLobopReplyMsg rm = {0};
  /* How far a READ's content has been found whole: seer_schema_value_scan
   * goes on from there as each packet comes, so the content is walked once,
   * not once a packet (#400); it is decoded once it has all arrived. */
  size_t lob_pos = 0;
  bool lob_whole = false;
  for (;;) {
    st = o8i_recv_more(c, &buf);
    if (st != SEER_OK)
      break;
    if (!lob_whole && buf.len > 0 && buf.buf[0] == TTI_LOB) {
      SeerSchemaResult sr = seer_schema_value_scan(&cx, buf.buf, buf.len, 1, &lob_pos);
      if (sr == SCH_SHORT)
        continue;
      if (sr == SCH_BAD) {
        st = SEER_EPROTO;
        break;
      }
      lob_whole = true;
    }
    /* The reply by its schemas, at 8i's widths: the LOB data (a READ's
     * content), the RPA, then the status. A part that hasn't fully arrived
     * reads short: read on (#398). */
    seer_schema_free(SEER_LOB_DATA_SCHEMA, &lm);
    seer_schema_free(SEER_LOBOPS_REPLY_SCHEMA, &rm);
    lm = (SeerLobDataMsg){0};
    rm = (SeerLobopReplyMsg){.has_amount = has_amount};
    SeerReader r;
    seer_reader_init(&r, buf.buf, buf.len);
    SeerSchemaResult res = SCH_OK;
    if (seer_reader_remaining(&r) > 0 && r.buf[r.pos] == TTI_LOB) {
      r.pos++;
      res = seer_schema_decode_ex(SEER_LOB_DATA_SCHEMA, &cx, &r, &lm);
    }
    if (res == SCH_OK && seer_reader_remaining(&r) > 0 && r.buf[r.pos] == TTI_RPA) {
      r.pos++;
      res = seer_schema_decode_ex(SEER_LOBOPS_REPLY_SCHEMA, &cx, &r, &rm);
    }
    if (res == SCH_SHORT)
      continue;
    if (res == SCH_BAD) {
      st = SEER_EPROTO;
      break;
    }
    O8iRd sr = {buf.buf, buf.len, r.pos, false, false};
    o8i_status_free(&s);
    o8i_read_status(&sr, &s);
    o8i_note_txn(c, &s);
    if (sr.bad) {
      st = SEER_EPROTO;
      break;
    }
    if (!sr.cut)
      break;
  }
  if (st == SEER_OK && s.code != 0) {
    st = o8i_fail(c, &s);
  } else if (st == SEER_OK) {
    /* Whole now: take the parts out. */
    if (content != NULL)
      seer_writer_bytes(content, lm.data.p, lm.data.n);
    if (loc != NULL && rm.locator.p != NULL)
      *loc = seer_lobop_reply_locator(&rm, loclen); /* its length and the bytes */
    if (amount != NULL && has_amount)
      *amount = (uint32_t)rm.amount;
    if (content != NULL && !seer_writer_ok(content))
      st = SEER_ENOMEM;
  }
  seer_schema_free(SEER_LOB_DATA_SCHEMA, &lm);
  seer_schema_free(SEER_LOBOPS_REPLY_SCHEMA, &rm);
  o8i_status_free(&s);
  seer_writer_free(&buf);
  return st;
}

/* A CLOB's or BLOB's content (§19.15): one READ from offset 1 reads the whole
 * value - 8i needs no GETLEN first, unlike 9i. */
static SeerStatus o8i_lob_read(SeerConn *c, const uint8_t *loc, size_t loclen, SeerWriter *content)
{
  SeerStatus st = o8i_lobop_send(c, loc, loclen, LOB_OP_READ, 1, true, 0x40000000u);
  return st == SEER_OK ? o8i_lobop_reply(c, true, content, NULL, NULL, NULL) : st;
}

/* One 8i TTI_LOBOPS call of any shape: `m` at 8i's widths with the locator
 * `loc` as its source, then `tail` (a WRITE's content), and its reply - the
 * locator the server now has into *out when asked for (#424). */
static SeerStatus o8i_lobop_call(SeerConn *c, SeerLobopMsg *m, const uint8_t *loc, size_t loclen,
                                 const uint8_t *tail, size_t taillen, uint8_t **out, size_t *outlen)
{
  SeerWriter w;
  if (!seer_writer_init(&w, 64 + loclen + taillen))
    return SEER_ENOMEM;
  o8i_closing(c, &w);
  seer_ttc_fun_header(c, &w, TTI_LOBOPS);
  m->src_ptr = 1;
  m->src_len = (int64_t)loclen;
  m->loc_len = (int64_t)loclen;
  m->locator = (SeerBytes){.p = loc, .n = loclen};
  SeerSchemaCtx cx = seer_msg_ctx(1, 0, 0);
  seer_schema_encode(SEER_LOBOPS_SCHEMA, &cx, m, &w);
  if (taillen > 0)
    seer_writer_bytes(&w, tail, taillen);
  SeerStatus st = seer_writer_ok(&w) ? seer_ttc_send(c, w.buf, w.len) : SEER_ENOMEM;
  seer_writer_free(&w);
  return st == SEER_OK ? o8i_lobop_reply(c, m->has_amount != 0, NULL, out, outlen, NULL) : st;
}

/* FREE_TEMP, the locator alone (#424). */
static void o8i_free_temp(SeerConn *c, const uint8_t *loc, size_t loclen)
{
  SeerLobopMsg m = {.op = LOB_OP_FREE_TEMP};
  if (o8i_lobop_call(c, &m, loc, loclen, NULL, 0, NULL, NULL) != SEER_OK)
    seer_log(SEER_LOG_WARNING, "stmt: 8i: a temporary LOB was not freed");
}

/* A BFILE's content (§19.17): FILE_OPEN (mode 0x0b, read-only), whose reply
 * carries the locator with its open flag set, which the rest use; GETLEN;
 * READ that many bytes; FILE_CLOSE, whatever happened. */
static SeerStatus o8i_bfile_read(SeerConn *c, const uint8_t *loc, size_t loclen,
                                 SeerWriter *content)
{
  SeerStatus st = o8i_lobop_send(c, loc, loclen, LOB_OP_FILE_OPEN, 0, true, 0x0B);
  uint8_t *opened = NULL;
  size_t olen = 0;
  if (st == SEER_OK)
    st = o8i_lobop_reply(c, true, NULL, &opened, &olen, NULL);
  if (st != SEER_OK)
    return st;
  if (opened == NULL)
    return SEER_EPROTO;
  uint32_t length = 0;
  st = o8i_lobop_send(c, opened, olen, LOB_OP_GET_LENGTH, 0, true, 0);
  if (st == SEER_OK)
    st = o8i_lobop_reply(c, true, NULL, NULL, NULL, &length);
  if (st == SEER_OK && length > 0) {
    st = o8i_lobop_send(c, opened, olen, LOB_OP_READ, 1, true, length);
    if (st == SEER_OK)
      st = o8i_lobop_reply(c, true, content, NULL, NULL, NULL);
  }
  SeerStatus cst = o8i_lobop_send(c, opened, olen, LOB_OP_FILE_CLOSE, 0, false, 0);
  if (cst == SEER_OK)
    cst = o8i_lobop_reply(c, false, NULL, NULL, NULL, NULL);
  free(opened);
  return st != SEER_OK ? st : cst;
}

/* Read each LOB cell's content in place of its locator, while the cursor is
 * open: a CLOB's text (in WE8ISO8859P1, the session's charset), a BLOB's or
 * BFILE's bytes. */
static SeerStatus o8i_resolve_lobs(SeerStmt *stmt)
{
  for (int col = 0; col < stmt->ncols; col++) {
    uint8_t t = stmt->cols[col].ora_type;
    if (t == ORA_TYPE_ADT) {
      /* Objects and collections: each cell's image, decoded by its type's
       * layout, which dictionary queries read - now that the rows are in
       * (#168). A cell that won't decode is left NULL and logged. */
      for (size_t row = 0; row < stmt->nrows; row++) {
        SeerCell *cell = &stmt->rows[row][col];
        if (cell->data == NULL)
          continue;
        uint8_t *img = (uint8_t *)cell->data;
        size_t imglen = cell->len;
        *cell = (SeerCell){0};
        SeerStatus st = decode_typed_image(stmt->conn, &stmt->cols[col], img, imglen, cell);
        free(img);
        if (st != SEER_OK && st != SEER_ENOTIMPL)
          seer_log(SEER_LOG_WARNING, "o8i: OBJECT/collection decode failed (row %zu col %d)", row,
                   col);
      }
      continue;
    }
    if (t != ORA_TYPE_CLOB && t != ORA_TYPE_BLOB && t != ORA_TYPE_BFILE)
      continue;
    for (size_t row = 0; row < stmt->nrows; row++) {
      SeerCell *cell = &stmt->rows[row][col];
      if (cell->data == NULL)
        continue; /* NULL */
      SeerWriter content;
      if (!seer_writer_init(&content, 256))
        return SEER_ENOMEM;
      const uint8_t *loc = (const uint8_t *)cell->data;
      SeerStatus st = t == ORA_TYPE_BFILE ? o8i_bfile_read(stmt->conn, loc, cell->len, &content)
                                          : o8i_lob_read(stmt->conn, loc, cell->len, &content);
      if (st == SEER_EDB && t == ORA_TYPE_BFILE) {
        /* The server's error is the cell's, read when the cell is (#158). */
        free(cell->data);
        *cell = (SeerCell){0};
        record_cell_error(stmt, row, col);
        seer_writer_free(&content);
        continue;
      }
      if (st == SEER_OK) {
        free(cell->data);
        *cell = (SeerCell){0};
        st = t == ORA_TYPE_CLOB
                 ? o8i_text_cell(cell, content.buf, content.len)
                 : cell_set_bytes(cell, content.len ? content.buf : (const uint8_t *)"",
                                  content.len, true);
      }
      seer_writer_free(&content);
      if (st != SEER_OK)
        return st;
    }
  }
  return SEER_OK;
}

/* ---------------------------------------------------- 8i PL/SQL blocks */

#define O8I_DIR_OUT 0x10 /* the prompt's mask for a value the block returns */

/* One OUT value of an 8i block reply into `b->out` (§19.14, _O8I_OUT_CELL):
 * a value and an sb2 indicator, -1 for NULL; `ff` and the indicator 3105
 * for one the block never assigned. Text comes in WE8ISO8859P1. */
/* Decode `schema` at 8i's widths from where `r` stands: past it when whole,
 * `cut` when the reply hasn't brought it all yet, `bad` otherwise. */
static SeerSchemaResult o8i_decode(O8iRd *r, const SeerField *schema, void *msg)
{
  SeerReader sr;
  seer_reader_init(&sr, r->b + r->pos, r->n - r->pos);
  SeerSchemaCtx cx = seer_msg_ctx(1, 0, 0);
  SeerSchemaResult res = seer_schema_decode_ex(schema, &cx, &sr, msg);
  if (res == SCH_OK)
    r->pos += sr.pos;
  else if (res == SCH_SHORT)
    r->cut = true;
  else
    r->bad = true;
  return res;
}

static void o8i_out_cell(O8iRd *r, SeerBind *b)
{
  free(b->out.data);
  b->out = (SeerCell){0};
  if (b->is_array) {
    /* An associative array (§19.17c, #172) by SEER_OUT_ARRAY_SCHEMA: a
     * count, then each element by SEER_OUT_CELL_SCHEMA, a value and an
     * indicator (-1 NULL); no return code, as the OAC doesn't ask for one
     * (flag 0x04). Text in WE8ISO8859P1. */
    for (int k = 0; k < b->out_arr_n; k++)
      free(b->out_arr[k].data);
    free(b->out_arr);
    b->out_arr = NULL;
    b->out_arr_n = 0;
    SeerOutArrayMsg am = {0};
    if (o8i_decode(r, SEER_OUT_ARRAY_SCHEMA, &am) != SCH_OK)
      return;
    if (am.count < 0 || am.count > 65535) {
      r->bad = true;
      return;
    }
    uint32_t count = (uint32_t)am.count;
    SeerCell *cells = calloc(count ? count : 1, sizeof *cells);
    if (cells == NULL) {
      r->bad = true;
      return;
    }
    for (uint32_t e = 0; e < count && !r->cut && !r->bad; e++) {
      SeerCellMsg em = {0};
      if (o8i_decode(r, SEER_OUT_CELL_SCHEMA, &em) == SCH_OK && em.indicator != 0xFFFF &&
          em.value.n > 0) {
        if (b->oac_type == ORA_TYPE_NUMBER)
          (void)decode_scalar(ORA_TYPE_NUMBER, em.value.p, em.value.n, &cells[e]);
        else
          (void)o8i_text_cell(&cells[e], em.value.p, em.value.n);
      }
      seer_schema_free(SEER_OUT_CELL_SCHEMA, &em);
    }
    if (r->cut || r->bad) {
      for (uint32_t e = 0; e < count; e++)
        free(cells[e].data);
      free(cells);
      return;
    }
    b->out_arr = cells;
    b->out_arr_n = (int)count;
    return;
  }
  if (b->oac_type == ORA_TYPE_ADT && b->obj_type != NULL) {
    /* An object or collection: the bind value's form - the 8i row cell
     * without its trailer (§19.17c, #172), SEER_OBJECT_SCHEMA at 8i's widths
     * (#398). The image is decoded by the type's layout once the reply is
     * in. Read as a plain value it left the status misaligned and the
     * block's cursor id wrong. */
    SeerObjectMsg om = {0};
    SeerSchemaResult res = o8i_decode(r, SEER_OBJECT_SCHEMA, &om);
    free(b->out_image);
    b->out_image = NULL;
    b->out_imagelen = 0;
    if (res == SCH_OK && om.image_len > 0 && om.image.n > 0) {
      b->out_image = malloc(om.image.n);
      if (b->out_image != NULL) {
        memcpy(b->out_image, om.image.p, om.image.n);
        b->out_imagelen = om.image.n;
      }
    }
    seer_schema_free(SEER_OBJECT_SCHEMA, &om);
    return;
  }
  if (b->oac_type == ORA_TYPE_REF && b->oac_override != NULL) {
    /* A REF: `2a` + its 42 bytes as a value, then - as ref_bind's OUT
     * descriptor sets flag 0x01 - the indicator, SEER_OUT_CELL_SCHEMA's
     * form; no return code. A NULL is an empty value and ff ff (bus 91,
     * #325). Without the flag there is no indicator and a NULL is ORA-01405
     * (bus 85, #241). */
    SeerCellMsg om = {0};
    if (o8i_decode(r, SEER_OUT_CELL_SCHEMA, &om) == SCH_OK && om.indicator != 0xFFFF &&
        om.value.n > 0)
      (void)decode_scalar(ORA_TYPE_REF, om.value.p, om.value.n, &b->out);
    seer_schema_free(SEER_OUT_CELL_SCHEMA, &om);
    return;
  }
  if (b->ret_lob != 0) {
    /* A LOB by SEER_LOB_OUT_SCHEMA: the locator, counted, then the
     * indicator; no return code; NULL is a zero count and ff ff (§19.17b,
     * #167). The content is read by the locator once the reply is in. */
    free(b->ret_locator);
    b->ret_locator = NULL;
    b->ret_loclen = 0;
    SeerCellMsg lm = {0};
    if (o8i_decode(r, SEER_LOB_OUT_SCHEMA, &lm) == SCH_OK && lm.indicator != 0xFFFF &&
        lm.value.n > 2) {
      bool blank = true;
      for (size_t i = 2; i < lm.value.n; i++)
        blank &= lm.value.p[i] == 0;
      if (!blank && (b->ret_locator = malloc(lm.value.n)) != NULL) {
        memcpy(b->ret_locator, lm.value.p, lm.value.n);
        b->ret_loclen = lm.value.n;
      }
    }
    seer_schema_free(SEER_LOB_OUT_SCHEMA, &lm);
    return;
  }
  if (o8r_has(r, 1) && r->b[r->pos] == 0xFF) {
    /* SEER_OUT_UNSET_SCHEMA: a bind the block never assigned */
    SeerCellMsg um = {0};
    (void)o8i_decode(r, SEER_OUT_UNSET_SCHEMA, &um);
    return;
  }
  /* SEER_OUT_CELL_SCHEMA at 8i's widths: the value and its indicator */
  SeerCellMsg om = {0};
  if (o8i_decode(r, SEER_OUT_CELL_SCHEMA, &om) == SCH_OK && om.indicator != 0xFFFF &&
      om.value.n > 0) {
    bool text = b->oac_type == ORA_TYPE_VARCHAR || b->oac_type == ORA_TYPE_CHAR ||
                b->oac_type == ORA_TYPE_LONG || b->oac_type == 0;
    if (text)
      (void)o8i_text_cell(&b->out, om.value.p, om.value.n);
    else
      (void)decode_scalar(b->oac_type, om.value.p, om.value.n, &b->out);
  }
  seer_schema_free(SEER_OUT_CELL_SCHEMA, &om);
}

/* A REF CURSOR OUT value (§19.17a): the cursor cell, its columns and id kept
 * for reading its rows once the reply is in. `ff` and an indicator for a
 * cursor the block never opened. */
static void o8i_refcursor_cell(O8iRd *r, SeerStmt *stmt)
{
  if (stmt->refcursor_cols != NULL)
    free_columns(stmt->refcursor_cols, stmt->refcursor_ncols);
  stmt->refcursor_cols = NULL;
  stmt->refcursor_ncols = 0;
  stmt->refcursor_present = false;
  if (o8r_has(r, 1) && r->b[r->pos] == 0xFF) { /* NULL: ff, the indicator */
    SeerCellMsg um = {0};
    (void)o8i_decode(r, SEER_OUT_UNSET_SCHEMA, &um);
    return;
  }
  SeerColumn *cols = NULL;
  int ncols = 0;
  uint32_t id = 0;
  o8i_read_cursor_cell(r, false, &cols, &ncols, &id);
  if (r->cut || r->bad)
    return;
  stmt->refcursor_cols = cols;
  stmt->refcursor_ncols = ncols;
  stmt->refcursor_id = (int)id;
  stmt->refcursor_present = id != 0;
}

/* An 8i block's reply (§19.13-19.14): the bind prompt when the block has
 * binds - 9i's I/O vector at 8i's widths (0b, the flags, a ub2 of requests, a
 * ub2 of iterations, a ub4, eight bytes, then a mask a bind) - then one RXD
 * with the OUT values in the masks' order, then the RPA and the status. A
 * block that failed sends the status alone. Mask k is bind k: the server
 * pairs the binds with the placeholders in order of appearance (#146). */
static void o8i_block_reply(O8iRd *r, SeerStmt *stmt, O8iStatus *s)
{
  if (o8r_has(r, 1) && r->b[r->pos] == TTI_IOV) {
    r->pos++;
    /* SEER_IOV_SCHEMA at 8i's widths, then a mask a bind (#398) */
    SeerReader ir;
    seer_reader_init(&ir, r->b + r->pos, r->n - r->pos);
    SeerSchemaCtx icx = seer_msg_ctx(1, 0, 0);
    SeerIovMsg iov = {0};
    SeerSchemaResult res = seer_schema_decode_ex(SEER_IOV_SCHEMA, &icx, &ir, &iov);
    seer_schema_free(SEER_IOV_SCHEMA, &iov);
    uint32_t count = (uint32_t)(iov.iterations * 256 + iov.requests);
    if (res == SCH_OK) {
      iov.nbinds = count;
      res = seer_schema_decode_ex(SEER_IOV_DIRS_SCHEMA, &icx, &ir, &iov);
    }
    if (res != SCH_OK) {
      if (res == SCH_SHORT)
        r->cut = true;
      else
        r->bad = true;
      return;
    }
    const uint8_t *masks = iov.directions.p;
    r->pos += ir.pos;
    bool any_out = false;
    for (uint32_t k = 0; k < count; k++)
      any_out |= (masks[k] & O8I_DIR_OUT) != 0;
    if (any_out) {
      if (!o8r_has(r, 1))
        return;
      if (r->b[r->pos] != TTI_RXD) {
        r->bad = true;
        return;
      }
      r->pos++;
      for (uint32_t k = 0; k < count && !r->cut && !r->bad; k++) {
        if (!(masks[k] & O8I_DIR_OUT))
          continue;
        int bi = (int)k;
        if (bi < 0 || bi >= stmt->npbinds) {
          r->bad = true;
          return;
        }
        if (stmt->pbinds[bi].oac_type == ORA_TYPE_REFCURSOR)
          o8i_refcursor_cell(r, stmt);
        else
          o8i_out_cell(r, &stmt->pbinds[bi]);
      }
    }
  }
  if (!r->cut && !r->bad) {
    o8i_read_status(r, s);
    o8i_note_txn(stmt->conn, s);
  }
}

static SeerStatus o8i_fetch_rest(SeerStmt *stmt, uint32_t cursor, O8iStatus *s);
static SeerStatus o8i_resolve_lobs(SeerStmt *stmt);

/* A REF CURSOR OUT's rows become the statement's result set: its columns came
 * in its cell; its rows are fetched by its id with OALL8 fetches, as a
 * query's after the first batch, and the cursor is closed with the next call
 * (§19.17a, #166). */
static SeerStatus o8i_drain_refcursor(SeerStmt *stmt)
{
  uint32_t cursor = (uint32_t)stmt->refcursor_id;
  stmt->refcursor_present = false;
  free_rows(stmt);
  free_columns(stmt->cols, stmt->ncols);
  stmt->cols = stmt->refcursor_cols;
  stmt->ncols = stmt->refcursor_ncols;
  stmt->refcursor_cols = NULL;
  stmt->refcursor_ncols = 0;
  seer_log(SEER_LOG_DEBUG, "o8i: REF CURSOR %u (%d columns)", (unsigned)cursor, stmt->ncols);
  O8iStatus s = {0};
  SeerStatus st = o8i_fetch_rest(stmt, cursor, &s);
  if (st == SEER_OK && (s.code == 0 || s.code == 1403))
    st = o8i_resolve_lobs(stmt);
  queue_cursor_close(stmt->conn, cursor);
  if (st == SEER_OK && s.code != 0 && s.code != 1403)
    st = o8i_fail(stmt->conn, &s);
  o8i_status_free(&s);
  stmt->cols_adopted = true;
  stmt->cur = -1;
  return st;
}

/* An anonymous PL/SQL block (BEGIN / DECLARE) or a CALL, on the OALL8 as
 * statement type 8 / 9 (§19.13): the option word 0x21, + BIND with binds,
 * then 0x04 with binds and 0x04, the block's mark. Unlike 9i, 8i takes the IN
 * values inline - a pure OUT bind sends fd 01 - so a block is one round trip.
 * Bind N is the N-th distinct placeholder in order of appearance, as on every
 * tier (#146); the reply's values follow the same order. */
static SeerStatus o8i_execute_block(SeerStmt *stmt)
{
  SeerConn *c = stmt->conn;
  int nb = stmt->npbinds;
  size_t sqllen = 0;
  uint8_t *text = o8i_latin1(stmt->sql, &sqllen);
  if (text == NULL)
    return SEER_ENOMEM;
  const char *kw = sql_first_keyword(stmt->sql);
  uint32_t type = starts_with_word(kw, "DECLARE") ? O8I_STMT_DECLARE : O8I_STMT_BEGIN;
  uint32_t options = 0x21 | (nb > 0 ? 0x0408 : 0) | 0x040000;
  SeerWriter w;
  if (!seer_writer_init(&w, 160 + sqllen + (size_t)nb * 32)) {
    free(text);
    return SEER_ENOMEM;
  }
  o8i_closing(c, &w);
  o8i_all8(c, &w, options, 0, text, sqllen, true, 1, 0, (uint32_t)nb, 1, 1, type);
  free(text);
  SeerStatus st = nb > 0 ? o8i_binds(stmt, 0, true, &w) : SEER_OK;
  if (st == SEER_OK)
    st = seer_writer_ok(&w) ? seer_ttc_send(c, w.buf, w.len) : SEER_ENOMEM;
  seer_writer_free(&w);
  if (st != SEER_OK)
    return st;

  SeerWriter buf;
  if (!seer_writer_init(&buf, 512))
    return SEER_ENOMEM;
  O8iStatus s = {0};
  /* No packet is marked a reply's last, and long OUT values span several:
   * read on until the prompt, every OUT value and the status are whole
   * (seerdb o8i_block_complete, #2334). */
  for (;;) {
    st = o8i_recv_more(c, &buf);
    if (st != SEER_OK)
      break;
    O8iRd r = {buf.buf, buf.len, 0, false, false};
    o8i_status_free(&s);
    o8i_block_reply(&r, stmt, &s);
    if (r.bad) {
      st = SEER_EPROTO;
      break;
    }
    if (!r.cut && r.pos > 0)
      break;
  }
  seer_writer_free(&buf);
  if (st != SEER_OK) {
    o8i_status_free(&s);
    return st;
  }
  if (s.cursor != 0)
    queue_cursor_close(c, s.cursor);
  if (s.code != 0 && s.code != 1403) {
    stmt->refcursor_present = false;
    st = o8i_fail(c, &s);
    o8i_status_free(&s);
    return st;
  }
  o8i_status_free(&s);
  long rows = (long)s.rows;
  /* OUT objects, decoded by their types' layouts (#172). */
  st = resolve_out_objects(stmt);
  if (st != SEER_OK)
    return st;

  /* The LOBs the block returned, read by their locators before the next call
   * (§19.15's single READ; #167): CLOB text in WE8ISO8859P1, BLOB bytes. */
  for (int k = 0; k < stmt->npbinds; k++) {
    SeerBind *b = &stmt->pbinds[k];
    if (b->ret_locator == NULL || stmt->keep_lob_locators)
      continue;
    SeerWriter content;
    if (!seer_writer_init(&content, 4096))
      return SEER_ENOMEM;
    st = o8i_lob_read(c, b->ret_locator, b->ret_loclen, &content);
    free(b->ret_locator);
    b->ret_locator = NULL;
    b->ret_loclen = 0;
    if (st == SEER_OK && !seer_writer_ok(&content))
      st = SEER_ENOMEM;
    if (st == SEER_OK)
      st = b->ret_lob == ORA_TYPE_CLOB ? o8i_text_cell(&b->out, content.buf, content.len)
                                       : cell_set_bytes(&b->out, content.buf, content.len, true);
    seer_writer_free(&content);
    if (st != SEER_OK)
      return st;
  }
  if (stmt->refcursor_present) {
    st = o8i_drain_refcursor(stmt);
    if (st != SEER_OK)
      return st;
  }
  stmt->affected = rows;
  stmt->executed = true;
  if (c->autocommit)
    return seer_o8i_tran(c, true);
  return SEER_OK;
}

/* Fetch a cursor's rows by its id after a first batch whose status is *s,
 * to a batch that ends with ORA-01403 or brings no rows; *s is the last
 * batch's status. A LONG column returns one row a fetch, and only up to the
 * fetch's LONG size: ask for all of it (seerdb #377). */
static SeerStatus o8i_fetch_rest(SeerStmt *stmt, uint32_t cursor, O8iStatus *s)
{
  SeerConn *c = stmt->conn;
  bool has_long = false;
  for (int i = 0; i < stmt->ncols; i++)
    if (stmt->cols[i].ora_type == ORA_TYPE_LONG || stmt->cols[i].ora_type == ORA_TYPE_LONGRAW)
      has_long = true;
  while (s->code == 0 && cursor != 0 && !rows_full(stmt)) {
    o8i_status_free(s);
    size_t before = stmt->nrows;
    SeerWriter w, buf;
    if (!seer_writer_init(&w, 128))
      return SEER_ENOMEM;
    o8i_closing(c, &w);
    o8i_all8(c, &w, 0x40, cursor, NULL, 0, false, 0, 0x7FFFFFFF, 0, 0, has_long ? 1 : PREFETCH_ROWS,
             O8I_STMT_SELECT);
    SeerStatus st = seer_writer_ok(&w) ? seer_ttc_send(c, w.buf, w.len) : SEER_ENOMEM;
    seer_writer_free(&w);
    if (st == SEER_OK && !seer_writer_init(&buf, 2048))
      st = SEER_ENOMEM;
    if (st != SEER_OK)
      return st;
    st = o8i_recv_more(c, &buf);
    if (st == SEER_OK)
      st = o8i_rows_reply(stmt, &buf, 0, s);
    seer_writer_free(&buf);
    if (st != SEER_OK)
      return st;
    seer_log(SEER_LOG_DEBUG, "o8i: fetch on cursor %u: %zu rows, status ORA-%05u", (unsigned)cursor,
             stmt->nrows - before, (unsigned)s->code);
    if (stmt->nrows == before)
      break;
  }
  return SEER_OK;
}

/* Describe a query on 8.1.7 without running it (#353), as OCI's
 * OCIStmtExecute(OCI_DESCRIBE_ONLY) does (seerdb bus 96): open a cursor
 * (function 2; the reply's RPA names it), then an OALL8 on it with PARSE |
 * DESCRIBE (0x00028001) and no EXECUTE or FETCH. The reply is the usual
 * describe, then the RPA and the status - no rows. The cursor is queued to
 * close with the next call. A query's markers go as value-less descriptors
 * (bus 99). */
static SeerStatus o8i_describe_only(SeerStmt *stmt, int nmarkers)
{
  SeerConn *c = stmt->conn;
  SeerWriter w;
  if (!seer_writer_init(&w, 32))
    return SEER_ENOMEM;
  o8i_closing(c, &w);
  seer_ttc_fun_header(c, &w, TTI_OOPEN);
  SeerSchemaCtx cx = seer_msg_ctx(1, 0, 0); /* SEER_OPEN_SCHEMA (#398) */
  SeerOpenMsg om = {.cursor_ptr = 1};
  seer_schema_encode(SEER_OPEN_SCHEMA, &cx, &om, &w);
  SeerStatus st = seer_writer_ok(&w) ? seer_ttc_send(c, w.buf, w.len) : SEER_ENOMEM;
  seer_writer_free(&w);
  if (st != SEER_OK)
    return st;
  uint8_t *resp = NULL;
  size_t rlen = 0;
  st = seer_ttc_recv(c, &resp, &rlen);
  if (st != SEER_OK)
    return st;
  uint32_t cursor = 0;
  if (rlen > 1 && resp[0] == TTI_RPA) {
    SeerReader r;
    seer_reader_init(&r, resp + 1, rlen - 1);
    SeerOpenMsg rm = {0};
    if (seer_schema_decode(SEER_OPEN_REPLY_SCHEMA, &cx, &r, &rm))
      cursor = (uint32_t)rm.cursor;
  }
  free(resp);
  if (cursor == 0) {
    seer_log(SEER_LOG_DEBUG, "o8i: describe: the server opened no cursor");
    return SEER_EPROTO;
  }

  size_t sqllen = 0;
  uint8_t *sql = o8i_latin1(stmt->sql, &sqllen);
  if (sql == NULL || !seer_writer_init(&w, 160 + sqllen + (size_t)nmarkers * 25)) {
    free(sql);
    queue_cursor_close(c, cursor);
    return SEER_ENOMEM;
  }
  /* With markers: BIND (0x08) and, after al8i4, one descriptor per marker
   * and no value - OCI's for a marker it has no value for is type 1, flag
   * 0x80, size 0, the rest zeros (bus 99). */
  o8i_all8(c, &w, nmarkers > 0 ? 0x00028009 : 0x00028001, cursor, sql, sqllen, true, 1, 0,
           (uint32_t)nmarkers, 1, 0, O8I_STMT_SELECT);
  free(sql);
  SeerOacMsg mm = {.data_type = ORA_TYPE_VARCHAR, .flags = 0x80}; /* the rest 0 */
  for (int i = 0; i < nmarkers; i++)
    oac_write(&w, true, 0, &mm);
  st = seer_writer_ok(&w) ? seer_ttc_send(c, w.buf, w.len) : SEER_ENOMEM;
  seer_writer_free(&w);
  if (st != SEER_OK) {
    queue_cursor_close(c, cursor);
    return st;
  }

  SeerWriter buf;
  if (!seer_writer_init(&buf, 2048)) {
    queue_cursor_close(c, cursor);
    return SEER_ENOMEM;
  }
  st = o8i_recv_more(c, &buf);
  O8iStatus s = {0};
  SeerColumn *cols = NULL;
  int ncols = 0;
  while (st == SEER_OK) {
    if (buf.len > 0 && buf.buf[0] == TTI_OER) { /* refused at parse: its status alone */
      O8iRd r = {buf.buf, buf.len, 0, false, false};
      o8i_read_status(&r, &s);
      if (r.cut) {
        o8i_status_free(&s);
        st = o8i_recv_more(c, &buf);
        continue;
      }
      st = s.code ? o8i_fail(c, &s) : SEER_EPROTO;
      break;
    }
    O8iRd r = {buf.buf, buf.len, 0, false, false};
    o8i_read_describe(&r, &cols, &ncols);
    if (!r.cut && !r.bad)
      o8i_read_status(&r, &s); /* the RPA and the status behind the describe */
    if (r.bad) {
      st = SEER_EPROTO;
      break;
    }
    if (r.cut) { /* read on: the describe or its status spans packets */
      free_columns(cols, ncols);
      cols = NULL;
      ncols = 0;
      o8i_status_free(&s);
      st = o8i_recv_more(c, &buf);
      continue;
    }
    if (s.code != 0)
      st = o8i_fail(c, &s);
    break;
  }
  seer_writer_free(&buf);
  o8i_status_free(&s);
  queue_cursor_close(c, cursor);
  if (st != SEER_OK) {
    free_columns(cols, ncols);
    return st;
  }
  free_columns(stmt->cols, stmt->ncols);
  stmt->cols = cols;
  stmt->ncols = ncols;
  return SEER_OK;
}

static SeerStatus o8i_execute_select(SeerStmt *stmt)
{
  SeerConn *c = stmt->conn;
  free_rows(stmt);
  free_columns(stmt->cols, stmt->ncols);
  stmt->cols = NULL;
  stmt->ncols = 0;

  size_t sqllen = 0;
  uint8_t *sql = o8i_latin1(stmt->sql, &sqllen);
  if (sql == NULL)
    return SEER_ENOMEM;
  SeerWriter w;
  if (!seer_writer_init(&w, 160 + sqllen + (size_t)stmt->npbinds * 32)) {
    free(sql);
    return SEER_ENOMEM;
  }
  o8i_closing(c, &w);
  /* PARSE | EXECUTE | FETCH (0x61), + BIND (0x08) with binds, then 0x80: a
   * cursor statement. A query's execute waits for its fetch: al8i4[1] (the
   * execute flag) is 0. */
  int nb = stmt->npbinds;
  o8i_all8(c, &w, nb > 0 ? 0x8069 : 0x8061, 0, sql, sqllen, true, 1, 0, (uint32_t)nb, 1, 0,
           O8I_STMT_SELECT);
  free(sql);
  SeerStatus st = nb > 0 ? o8i_binds(stmt, 0, false, &w) : SEER_OK;
  if (st != SEER_OK) {
    seer_writer_free(&w);
    return st;
  }
  st = seer_writer_ok(&w) ? seer_ttc_send(c, w.buf, w.len) : SEER_ENOMEM;
  seer_writer_free(&w);
  if (st != SEER_OK)
    return st;

  SeerWriter buf;
  if (!seer_writer_init(&buf, 2048))
    return SEER_ENOMEM;
  st = o8i_recv_more(c, &buf);
  O8iStatus s = {0};
  size_t pos = 0;
  /* The describe, read on across packets; a statement refused at parse or
   * execute answers with its status alone (or cuts the describe short with
   * it), and that error is the answer. */
  while (st == SEER_OK) {
    if (buf.len > 0 && buf.buf[0] == TTI_OER) {
      O8iRd r = {buf.buf, buf.len, 0, false, false};
      o8i_read_status(&r, &s);
      o8i_note_txn(c, &s);
      if (r.cut) {
        o8i_status_free(&s);
        st = o8i_recv_more(c, &buf);
        continue;
      }
      queue_cursor_close(c, s.cursor);
      st = s.code ? o8i_fail(c, &s) : SEER_EPROTO;
      break;
    }
    O8iRd r = {buf.buf, buf.len, 0, false, false};
    SeerColumn *cols = NULL;
    int ncols = 0;
    o8i_read_describe(&r, &cols, &ncols);
    if (r.bad) {
      st = SEER_EPROTO;
      break;
    }
    if (r.cut) {
      /* A statement failing as it executes can stop the describe partway:
       * 8i sends what fitted, then the error as a status of its own, and
       * nothing more (seerdb #1226). That error is the answer - when it
       * carries the server's ORA- text. A wide describe's next packet can
       * open with the byte 0x04 too, as describe data: taken for a status,
       * a select of 200 columns failed with an empty error (#152). */
      uint8_t *more = NULL;
      size_t mlen = 0;
      st = seer_ttc_recv(c, &more, &mlen);
      if (st != SEER_OK)
        break;
      if (mlen > 0 && more[0] == TTI_OER) {
        O8iRd e = {more, mlen, 0, false, false};
        o8i_read_status(&e, &s);
        o8i_note_txn(c, &s);
        if (!e.cut && !e.bad && s.code != 0 && s.message != NULL &&
            strncmp(s.message, "ORA-", 4) == 0) {
          free(more);
          queue_cursor_close(c, s.cursor);
          st = o8i_fail(c, &s);
          break;
        }
        o8i_status_free(&s);
      }
      seer_writer_bytes(&buf, more, mlen);
      free(more);
      if (!seer_writer_ok(&buf))
        st = SEER_ENOMEM;
      continue;
    }
    stmt->cols = cols;
    stmt->ncols = ncols;
    pos = r.pos;
    break;
  }
  if (st == SEER_OK)
    st = o8i_rows_reply(stmt, &buf, pos, &s);
  seer_writer_free(&buf);
  if (st != SEER_OK) {
    o8i_status_free(&s);
    return st;
  }
  uint32_t cursor = s.cursor;
  seer_log(SEER_LOG_DEBUG, "o8i: execute: %d columns, %zu rows, cursor %u, status ORA-%05u",
           stmt->ncols, stmt->nrows, (unsigned)cursor, (unsigned)s.code);
  st = o8i_fetch_rest(stmt, cursor, &s);
  if (st != SEER_OK)
    return st;
  if (s.code == 0 || s.code == 1403) {
    st = o8i_resolve_lobs(stmt);
    if (st != SEER_OK) {
      o8i_status_free(&s);
      queue_cursor_close(c, cursor);
      return st;
    }
  }
  queue_cursor_close(c, cursor);
  if (s.code != 0 && s.code != 1403) {
    st = o8i_fail(c, &s);
    o8i_status_free(&s);
    return st;
  }
  o8i_status_free(&s);
  stmt->cursor_id = 0; /* closed with the next call; 8i keeps no statement cache */
  stmt->executed = true;
  stmt->cur = -1;
  seer_log(SEER_LOG_DEBUG, "o8i: query done (%d columns, %zu rows)", stmt->ncols, stmt->nrows);
  return SEER_OK;
}

/* The first calls of a 9i query: the session's cursor, the parse (with any
 * binds) and the describe, which sets the statement's columns. The cursor is
 * left open on the parsed statement for the caller to execute or close. */
static SeerStatus fv2_describe_cursor(SeerStmt *stmt, uint32_t cursor);
static SeerStatus fv2_parse_describe(SeerStmt *stmt, uint32_t *out_cursor)
{
  SeerConn *c = stmt->conn;
  uint8_t *resp = NULL;
  size_t rlen = 0;
  SeerWriter w;

  /* Call 0: the session's cursor (OOPEN on first use). */
  uint32_t cursor = 0;
  SeerStatus st = fv2_shared_cursor(c, &cursor);
  if (st != SEER_OK)
    return st;

  /* Call 1: parse (TTI_ALL7, with any binds). */
  st = fv2_emit_parse(stmt, &w);
  if (st != SEER_OK)
    return st;
  st = fv2_txn(c, w.buf, w.len, &resp, &rlen);
  seer_writer_free(&w);
  if (st != SEER_OK)
    return st;
  int64_t pcode = fv2_oer_code(resp, rlen);
  if (pcode != 0 && pcode != 1403) {
    fv2_set_error(c, resp, rlen);
    seer_log(SEER_LOG_DEBUG, "fv2: parse failed (ORA-%05ld)", (long)pcode);
    free(resp);
    return SEER_EDB;
  }
  free(resp);
  resp = NULL;

  /* Call 2: describe columns. */
  st = fv2_describe_cursor(stmt, cursor);
  if (st != SEER_OK)
    return st;
  *out_cursor = cursor;
  return SEER_OK;
}

/* Describe the query open on `cursor` into stmt->cols: the statement's own
 * cursor after its parse, or a REF CURSOR's id (#166). */
static SeerStatus fv2_describe_cursor(SeerStmt *stmt, uint32_t cursor)
{
  SeerConn *c = stmt->conn;
  uint8_t *resp = NULL;
  size_t rlen = 0;
  SeerWriter w;
  SeerStatus st;
  if (!seer_writer_init(&w, 16))
    return SEER_ENOMEM;
  fv2_call_head(&w, O7_DESCRIBE); /* and SEER_O7_DESCRIBE_SCHEMA (#398) */
  SeerSchemaCtx cx = seer_msg_ctx(0, TTC_FIELD_VERSION_9_2, TTC_FIELD_VERSION_9_2);
  SeerO7DescribeMsg dm = {.cursor = cursor};
  seer_schema_encode(SEER_O7_DESCRIBE_SCHEMA, &cx, &dm, &w);
  st = fv2_txn(c, w.buf, w.len, &resp, &rlen);
  seer_writer_free(&w);
  if (st != SEER_OK)
    return st;
  int64_t dcode = fv2_oer_code(resp, rlen);
  if (dcode != 0 && dcode != 1403) {
    fv2_set_error(c, resp, rlen);
    free(resp);
    return SEER_EDB;
  }
  SeerColumn *cols = NULL;
  int ncols = 0;
  st = fv2_decode_describe(resp, rlen, &cols, &ncols);
  free(resp);
  resp = NULL;
  if (st != SEER_OK)
    return st;
  stmt->cols = cols;
  stmt->ncols = ncols;
  return SEER_OK;
}

/* Describe a prepared 9i query without executing it (seer_stmt_describe): a
 * parse without the EXECUTE bit, the describe, then the cursor closed. A parse
 * alone needs no bind values; the execute parses and describes afresh, with
 * them. */
static SeerStatus fv2_describe_only(SeerStmt *stmt)
{
  uint32_t cursor = 0;
  stmt->describe_only = true; /* fv2_emit_parse: parse, don't execute */
  SeerStatus st = fv2_parse_describe(stmt, &cursor);
  stmt->describe_only = false;
  if (st != SEER_OK)
    return st;
  fv2_close_cursor(stmt->conn, cursor);
  return SEER_OK;
}

/* Fetch every row of the query open on `cursor` into the statement: the ALL7
 * execute + fetch (02 80 50), re-sent per batch until ORA-01403 or a batch
 * with no rows. *errcode is the batch's ORA code (0, 1403 or an error, its
 * text then on the connection). */
static SeerStatus fv2_fetch_cursor(SeerStmt *stmt, uint32_t cursor, int64_t *errcode)
{
  SeerConn *c = stmt->conn;
  int ncols = stmt->ncols;
  uint8_t *resp = NULL;
  size_t rlen = 0;
  SeerStatus st;
  SeerWriter w;
  *errcode = 0;
  for (;;) {
    if (!seer_writer_init(&w, 48 + (size_t)ncols * 24))
      return SEER_ENOMEM;
    /* execute + fetch: no SQL, a define a column (a ub4 count: 300 is
     * `02 01 2c`), 10 rows */
    SeerO7All7Msg m = {
        .options = 0x8050,
        .cursor = cursor,
        .defines_ptr = 1,
        .define_count = ncols,
        .rows = 10,
    };
    fv2_all7(&w, &m);
    for (int i = 0; i < ncols; i++)
      fv2_define_entry(&w, &stmt->cols[i]);
    if (!seer_writer_ok(&w)) {
      seer_writer_free(&w);
      return SEER_ENOMEM;
    }
    st = fv2_txn(c, w.buf, w.len, &resp, &rlen);
    seer_writer_free(&w);
    if (st != SEER_OK)
      return st;
    size_t nadded = 0;
    st = fv2_decode_rows(stmt, resp, rlen, errcode, &nadded);
    /* Each CURSOR() cell of the batch opened a cursor: free them before the
     * next batch, or a query of more rows than open_cursors fails (#196). */
    fv2_free_nested(stmt);
    /* A query can fail as its rows are made - 1 / 0 is ORA-01476 - and the
     * fetch's reply carries the error: keep its text while the reply is in
     * hand. Taken only after it was freed, the error had no text (#159). */
    if (st == SEER_OK && *errcode != 0 && *errcode != 1403) {
      free(c->last_error);
      c->last_error = NULL;
      fv2_set_error(c, resp, rlen);
      if (c->last_error == NULL)
        seer_conn_error_code(c, (long)*errcode);
    }
    free(resp);
    resp = NULL;
    if (st != SEER_OK)
      return st;
    if (*errcode == 1403 || nadded == 0 || rows_full(stmt))
      break;
  }

  return SEER_OK;
}

/* ---- 9i: a value past what a statement takes, as a temporary LOB (#169) ----
 * seerdb PROTOCOL.md §19.3.1, measured from ojdbc14 on 9.2.0.4: 9.2 has no
 * form for text past 32512 bytes (RAW too), nor for text past 4000 in a query,
 * but a temporary LOB holding it, bound as the LOB, goes into any statement. */

static SeerStatus o8i_unchunk(const uint8_t *v, size_t n, SeerWriter *out);

/* The empty 86-byte locator CREATE_TEMP takes as its source: 00 54, zeros. */
static const uint8_t FV2_EMPTY_LOCATOR[86] = {0x00, 0x54};

/* CREATE_TEMP of a CLOB (112) or BLOB (113) of the session's duration (10):
 * the empty locator as the source, the duration in the destination length and
 * the amount, the charset form and the type in the short offsets, the charset
 * after the locator. The reply's RPA carries the new locator. */
static SeerStatus fv2_create_temp(SeerConn *c, uint8_t type, uint8_t loc[86])
{
  bool blob = type == ORA_TYPE_BLOB;
  /* As ojdbc14 sends it: the duration (10) in the destination length, the
   * charset form and the LOB type in the short offsets - each with its length
   * byte, `01 00` for a BLOB's form - the charset, null-LOB and amount
   * pointers set; the database charset, then the duration again as the
   * amount. */
  SeerLobopMsg m = {
      .dst_len = 10,
      .explicit_short = 1,
      .short_src_off = blob ? 0 : 1,
      .short_dst_off = type,
      .charset_ptr = 1,
      .short_amount_ptr = 1,
      .null_lob_ptr = 1,
      .op = LOB_OP_CREATE_TEMP,
      .charset = c->db_charset ? c->db_charset : 873u,
      .has_amount = 1,
      .amount = 10,
  };
  uint8_t *resp = NULL;
  size_t rlen = 0;
  SeerStatus st =
      fv2_lobop_send(c, FV2_EMPTY_LOCATOR, sizeof FV2_EMPTY_LOCATOR, &m, NULL, 0, &resp, &rlen);
  /* The reply: the new locator, 84 bytes, as the RPA schema reads it. */
  SeerLobopReplyMsg rm = {0};
  SeerSchemaCtx cx = seer_msg_ctx(0, TTC_FIELD_VERSION_9_2, TTC_FIELD_VERSION_9_2);
  SeerReader r;
  if (st == SEER_OK && rlen > 0)
    seer_reader_init(&r, resp + 1, rlen - 1);
  if (st == SEER_OK &&
      (rlen < 1 || resp[0] != TTI_RPA ||
       !seer_schema_decode(SEER_LOBOPS_REPLY_SCHEMA, &cx, &r, &rm) || rm.locator.n != 84)) {
    fv2_set_error(c, resp, rlen);
    st = SEER_EDB;
  }
  if (st == SEER_OK) {
    size_t n = 0;
    uint8_t *full = seer_lobop_reply_locator(&rm, &n); /* 00 54 and the body */
    if (full == NULL)
      st = SEER_ENOMEM;
    else
      memcpy(loc, full, 86);
    free(full);
  }
  free(resp);
  return st;
}

/* WRITE (op 0x40) `n` bytes at offset 1, `amount` characters of a CLOB or
 * bytes of a BLOB: the short amount, then the data as TTI_LOB content - a ub1
 * length and up to 252 bytes, past that 0xFE, 252-byte chunks and a zero. */
static SeerStatus fv2_lob_write(SeerConn *c, const uint8_t loc[86], const uint8_t *data, size_t n,
                                uint32_t amount)
{
  SeerLobopMsg m = {.short_src_off = 1,
                    .short_amount_ptr = 1,
                    .op = LOB_OP_WRITE,
                    .has_amount = 1,
                    .amount = amount};
  SeerWriter tw;
  if (!seer_writer_init(&tw, n + n / 252 + 16))
    return SEER_ENOMEM;
  /* The content as a LOB data message: SEER_LOB_DATA_SCHEMA at 9.2 (#398). */
  seer_writer_u8(&tw, TTI_LOB);
  SeerLobDataMsg lm = {.data = {.p = data, .n = n}};
  SeerSchemaCtx cx = seer_msg_ctx(0, TTC_FIELD_VERSION_9_2, TTC_FIELD_VERSION_9_2);
  seer_schema_encode(SEER_LOB_DATA_SCHEMA, &cx, &lm, &tw);
  uint8_t *resp = NULL;
  size_t rlen = 0;
  SeerStatus st = seer_writer_ok(&tw) ? fv2_lobop_send(c, loc, 86, &m, tw.buf, tw.len, &resp, &rlen)
                                      : SEER_ENOMEM;
  seer_writer_free(&tw);
  if (st == SEER_OK && (rlen < 1 || resp[0] != TTI_RPA)) {
    fv2_set_error(c, resp, rlen);
    st = SEER_EDB;
  }
  free(resp);
  return st;
}

/* FREE_TEMP (op 0x111), as ojdbc14 frees one: the locator, all else zero. */
static void fv2_free_temp(SeerConn *c, const uint8_t loc[86])
{
  SeerLobopMsg m = {.op = LOB_OP_FREE_TEMP};
  uint8_t *resp = NULL;
  size_t rlen = 0;
  if (fv2_lobop_send(c, loc, 86, &m, NULL, 0, &resp, &rlen) == SEER_OK) {
    if (rlen < 1 || resp[0] != TTI_RPA)
      seer_log(SEER_LOG_WARNING, "stmt: 9i: a temporary LOB was not freed (reply %02x)",
               rlen ? resp[0] : 0);
    else
      seer_log(SEER_LOG_DEBUG, "stmt: 9i: temporary LOB freed");
    free(resp);
  }
}

/* A CLOB's text as 9.2 reads a LOB write - in the session's charset, UTF-8,
 * not the database's (measured on 9.2.0.4: an 'é' run converted to the
 * database's WE8ISO8859P1 came up short of its amount, ORA-22993) - and its
 * length in characters. */
static SeerStatus fv2_lob_text(const uint8_t *u8, size_t n, uint8_t **out, size_t *outlen,
                               uint32_t *chars)
{
  uint32_t k = 0;
  for (size_t i = 0; i < n; i++)
    k += (u8[i] & 0xC0) != 0x80;
  *chars = k;
  *out = malloc(n ? n : 1);
  if (*out == NULL)
    return SEER_ENOMEM;
  memcpy(*out, u8, n);
  *outlen = n;
  return SEER_OK;
}

/* Whether a 9i IN bind needs a temporary LOB: text or RAW past 32512 bytes,
 * or, in a query, past the inline 4000 / 2000. */
static bool fv2_needs_temp_lob(const SeerStmt *stmt, const SeerBind *b, bool query)
{
  if (b->is_out || b->oac_charset == 2000 || b->rxd == NULL || b->rxd[0] == NULL)
    return false;
  bool text = b->oac_type == ORA_TYPE_VARCHAR || b->oac_type == ORA_TYPE_CHAR ||
              b->oac_type == ORA_TYPE_LONG;
  bool raw = b->oac_type == ORA_TYPE_RAW || b->oac_type == ORA_TYPE_LONGRAW;
  if (!text && !raw)
    return false;
  (void)stmt;
  return b->oac_size > FV2_BLOCK_WIDE_MAX || (query && fv2_block_wide(b));
}

/* The temporary LOBs of one execute: each promoted bind's locator and the
 * value it replaced, put back by fv2_temp_lobs_done. */
typedef struct {
  int bind;
  uint8_t loc[86];
  uint8_t *saved;
  size_t saved_len;
} Fv2TempLob;

/* Write each bind that needs one to a temporary LOB and bind the LOB for this
 * execute: the value a ub4 86 and the locator in 64-byte chunks. */
static SeerStatus fv2_temp_lobs_begin(SeerStmt *stmt, bool query, Fv2TempLob **out, int *n)
{
  *out = NULL;
  *n = 0;
  for (int i = 0; i < stmt->npbinds; i++) {
    SeerBind *b = &stmt->pbinds[i];
    if (!fv2_needs_temp_lob(stmt, b, query))
      continue;
    if (stmt->n_iters > 1) {
      seer_log(SEER_LOG_WARNING, "stmt: Oracle 9i: an array execute with a value past 32512 "
                                 "bytes is not supported");
      return SEER_ENOTIMPL;
    }
    bool raw = b->oac_type == ORA_TYPE_RAW || b->oac_type == ORA_TYPE_LONGRAW;
    SeerWriter v;
    if (!seer_writer_init(&v, b->rxd_len[0]))
      return SEER_ENOMEM;
    SeerStatus st = o8i_unchunk(b->rxd[0], b->rxd_len[0], &v);
    uint8_t *data = NULL;
    size_t dlen = 0;
    uint32_t amount = 0;
    if (st == SEER_OK && !seer_writer_ok(&v))
      st = SEER_ENOMEM;
    if (st == SEER_OK && raw) {
      data = v.buf;
      dlen = v.len;
      amount = (uint32_t)v.len;
      v.buf = NULL;
    } else if (st == SEER_OK) {
      st = fv2_lob_text(v.buf, v.len, &data, &dlen, &amount);
    }
    seer_writer_free(&v);
    Fv2TempLob *t = realloc(*out, (size_t)(*n + 1) * sizeof *t);
    if (st == SEER_OK && t == NULL)
      st = SEER_ENOMEM;
    if (t != NULL)
      *out = t;
    if (st == SEER_OK) {
      t = &(*out)[*n];
      t->bind = i;
      t->saved = NULL;
      st = fv2_create_temp(stmt->conn, raw ? ORA_TYPE_BLOB : ORA_TYPE_CLOB, t->loc);
      bool made = st == SEER_OK;
      if (st == SEER_OK && amount > 0)
        st = fv2_lob_write(stmt->conn, t->loc, data, dlen, amount);
      if (st == SEER_OK) {
        SeerWriter bv;
        if (!seer_writer_init(&bv, 96)) {
          st = SEER_ENOMEM;
        } else {
          SeerLegacyLobBindMsg lm = {.loc_len = 86, .locator = {.p = t->loc, .n = 86}};
          SeerSchemaCtx cx = seer_msg_ctx(0, TTC_FIELD_VERSION_9_2, TTC_FIELD_VERSION_9_2);
          seer_schema_encode(SEER_LEGACY_LOB_BIND_SCHEMA, &cx, &lm, &bv); /* #398 */
          if (!seer_writer_ok(&bv)) {
            seer_writer_free(&bv);
            st = SEER_ENOMEM;
          } else {
            t->saved = b->rxd[0];
            t->saved_len = b->rxd_len[0];
            b->rxd[0] = bv.buf;
            b->rxd_len[0] = bv.len;
            b->fv2_lob = raw ? ORA_TYPE_BLOB : ORA_TYPE_CLOB;
          }
        }
      }
      if (made && t->saved != NULL)
        (*n)++; /* bound: fv2_temp_lobs_done puts the value back and frees it */
      else if (made)
        fv2_free_temp(stmt->conn, t->loc);
    }
    free(data);
    if (st != SEER_OK)
      return st;
    seer_log(SEER_LOG_DEBUG, "stmt: 9i bind %d: %zu bytes as a temporary %s", i + 1, dlen,
             raw ? "BLOB" : "CLOB");
  }
  return SEER_OK;
}

/* Put the promoted binds' values back and free their temporary LOBs. */
static void fv2_temp_lobs_done(SeerStmt *stmt, Fv2TempLob *t, int n)
{
  for (int k = 0; k < n; k++) {
    SeerBind *b = &stmt->pbinds[t[k].bind];
    if (t[k].saved != NULL) {
      free(b->rxd[0]);
      b->rxd[0] = t[k].saved;
      b->rxd_len[0] = t[k].saved_len;
    }
    b->fv2_lob = 0;
    if (stmt->conn->t != NULL)
      fv2_free_temp(stmt->conn, t[k].loc);
  }
  free(t);
}

static SeerStatus fv2_execute_select(SeerStmt *stmt)
{
  SeerConn *c = stmt->conn;
  free_rows(stmt);
  free_columns(stmt->cols, stmt->ncols);
  stmt->cols = NULL;
  stmt->ncols = 0;

  /* Calls 0-2: the cursor, the parse and the describe. */
  uint32_t cursor = 0;
  SeerStatus st = fv2_parse_describe(stmt, &cursor);
  if (st != SEER_OK)
    return st;

  /* Call 3: execute + fetch, then the nested cursors its rows opened. */
  int64_t errcode = 0;
  st = fv2_fetch_cursor(stmt, cursor, &errcode);
  if (st != SEER_OK)
    return st;

  /* Resolve any captured LOB locators (TTI_LOBOPS) while the cursor is open. */
  if (stmt->nplobs > 0)
    fv2_resolve_lobs(stmt);

  /* End the statement on the cursor (best-effort). */
  fv2_close_cursor(c, cursor);

  if (errcode != 0 && errcode != 1403) {
    seer_log(SEER_LOG_DEBUG, "fv2: fetch failed (ORA-%05ld)", (long)errcode);
    return SEER_EDB;
  }
  /* Object and collection images, decoded by their types' layouts - which
   * dictionary queries read, on the session's one cursor: so only now that
   * the query is done with it (#168). */
  if (stmt->npobjs > 0)
    resolve_pending_objs(stmt);
  stmt->executed = true;
  stmt->cur = -1;
  return SEER_OK;
}

/* Oracle 9i DML / DDL over TTI_ALL7: OOPEN, a single parse that ALSO executes
 * (no describe/fetch), then close. 9i's parse carries no autocommit bit, so we
 * commit explicitly when autocommit is on. */
static SeerStatus fv2_execute_dml(SeerStmt *stmt)
{
  SeerConn *c = stmt->conn;
  uint8_t *resp = NULL;
  size_t rlen = 0;
  SeerStatus st;
  SeerWriter w;

  /* The session's cursor (OOPEN on first use). */
  uint32_t cursor = 0;
  st = fv2_shared_cursor(c, &cursor);
  if (st != SEER_OK)
    return st;

  /* Parse (also executes). */
  st = fv2_emit_parse(stmt, &w);
  if (st != SEER_OK)
    return st;
  st = fv2_txn(c, w.buf, w.len, &resp, &rlen);
  seer_writer_free(&w);
  if (st != SEER_OK)
    return st;

  Fv2Status status;
  free_batch_errors(stmt); /* clear any prior execute's failures */
  fv2_read_status_ex(resp, rlen, &status, stmt);
  int64_t rowcount = status.rows, code = status.code;
  /* ORA-24381 is the summary of a batch-errors array DML: the good rows were
   * applied and each failure is in stmt->berrs, as on 10g+. */
  bool failed = (code != 0 && code != 1403 && !(code == 24381 && stmt->nberrs > 0));
  /* A CREATE whose object compiled with errors succeeds; only the warning
   * flags say so (seerdb #2262), as on 10g+. */
  stmt->compile_warning = !failed && (status.warnings & 0x20) != 0;
  if (failed) {
    fv2_set_error(c, resp, rlen);
    seer_log(SEER_LOG_DEBUG, "fv2: DML failed (ORA-%05ld)", (long)code);
  }
  free(resp);
  resp = NULL;

  /* End the statement on the cursor (best-effort). */
  fv2_close_cursor(c, cursor);
  if (failed)
    return SEER_EDB;

  stmt->affected = (long)rowcount;
  stmt->executed = true;
  /* No autocommit bit on the 9i parse: commit here, and report it - a commit
   * the server refuses (a deferred constraint, ORA-02091) rolled the work
   * back (#347). */
  if (c->autocommit)
    return seer_commit(c);
  return SEER_OK;
}

/* Bind direction masks in a 9i bind prompt (PROTOCOL §19.7). */
#define FV2_DIR_OUT 0x10
#define FV2_DIR_IN 0x20

/* The direction of each of `nbinds` binds from a 9i bind prompt - `0b 05 01 <n>
 * 00 01 01 00`, padding, then one mask per bind (0x10 OUT, 0x20 IN, 0x30 IN
 * OUT) as the last n bytes before the first RXD / RPA, since the padding
 * varies. False when `d` doesn't open with a prompt for that many binds. The
 * server's masks are authoritative: a bind the block only reads is IN whatever
 * the application declared (seerdb/seerdb@c730f2b). */
static bool fv2_bind_directions(const uint8_t *d, size_t n, int nbinds, uint8_t *dirs)
{
  if (nbinds <= 0 || n < 8 || d[0] != FV2_BIND_PROMPT || d[3] != (uint8_t)nbinds)
    return false;
  size_t end = 8;
  while (end < n && d[end] != TTI_RXD && d[end] != TTI_RPA)
    end++;
  if (end - 8 < (size_t)nbinds)
    return false;
  memcpy(dirs, d + end - (size_t)nbinds, (size_t)nbinds);
  return true;
}

/* Decode a 9i PL/SQL block reply: strip any leading bind prompt, read `n_out`
 * OUT/IN-OUT values (DALC + indicator, in bind order) into the OUT binds' `out`
 * cells - the binds the prompt's masks mark OUT when there was one (`dirs`),
 * else those declared OUT - then read the trailing RPA + short OER for rowcount
 * + status. */
static void fv2_decode_block_out(SeerStmt *stmt, const uint8_t *data, size_t dlen, int n_out,
                                 const uint8_t *dirs, int64_t *rowcount, int64_t *code)
{
  *rowcount = 0;
  *code = 0;
  const uint8_t *rest = data;
  size_t restlen = dlen;
  SeerSchemaCtx cx = seer_msg_ctx(0, TTC_FIELD_VERSION_9_2, TTC_FIELD_VERSION_9_2);
  if (dlen >= 1 && data[0] == FV2_BIND_PROMPT) {
    /* The bind prompt, an I/O vector: SEER_IOV_SCHEMA and its direction
     * bytes, as 10g+'s (#398) - where it was skipped to the next RXD / RPA */
    SeerReader pr;
    seer_reader_init(&pr, data + 1, dlen - 1);
    SeerIovMsg iov = {0};
    if (seer_schema_decode(SEER_IOV_SCHEMA, &cx, &pr, &iov)) {
      iov.nbinds = iov.iterations * 256 + iov.requests;
      (void)seer_schema_decode(SEER_IOV_DIRS_SCHEMA, &cx, &pr, &iov);
    }
    seer_schema_free(SEER_IOV_SCHEMA, &iov);
    rest = data + 1 + pr.pos;
    restlen = dlen - 1 - pr.pos;
  }
  SeerReader r;
  seer_reader_init(&r, rest, restlen);
  if (n_out > 0 && seer_reader_remaining(&r) > 0 && r.buf[r.pos] == TTI_RXD) {
    r.pos += 1;
    for (int k = 0; k < stmt->npbinds; k++) {
      SeerBind *b = &stmt->pbinds[k];
      if (dirs != NULL ? !(dirs[k] & FV2_DIR_OUT) : !b->is_out)
        continue;
      /* An OUT bind the block never assigned - what a RETURNING ... INTO that
       * matched no row leaves - is four fixed bytes, neither a value with its
       * indicator nor an assigned NULL (empty value + 81 01): tried as
       * SEER_O7_OUT_UNSET_SCHEMA on a copy of the reader. Read as a value,
       * it desynced every OUT bind after it (seerdb #801). */
      SeerReader t = r;
      SeerCellMsg um = {0};
      if (seer_schema_decode_ex(SEER_O7_OUT_UNSET_SCHEMA, &cx, &t, &um) == SCH_OK) {
        r = t;
        free(b->out.data);
        b->out = (SeerCell){0}; /* NULL */
        continue;
      }
      free(b->ret_locator);
      b->ret_locator = NULL;
      b->ret_loclen = 0;
      if (b->oac_type == ORA_TYPE_ADT && b->obj_type != NULL) {
        /* An OUT object: the row cell's form, type block included, then the
         * indicator (§19.17c, #172); decoded by its layout after the block. */
        free(b->out.data);
        b->out = (SeerCell){0};
        uint8_t *img = NULL;
        size_t il = 0;
        if (read_object_image(&r, &img, &il) != SEER_OK) {
          free(img);
          break;
        }
        SeerCellMsg im = {0};
        (void)seer_schema_decode(SEER_OUT_IND_SCHEMA, &cx, &r, &im);
        free(b->out_image);
        b->out_image = img;
        b->out_imagelen = il;
        continue;
      }
      if (b->ret_lob != 0) {
        /* A LOB by SEER_LOB_OUT_SCHEMA, as 8i's: the locator, counted, then
         * the indicator; NULL is a zero count and 81 01. A NULL LOB from a
         * RETURNING comes as a locator all zero past its first two bytes,
         * which no real one is (§19.17b, #167). */
        free(b->out.data);
        b->out = (SeerCell){0};
        SeerCellMsg lm = {0};
        if (!seer_schema_decode(SEER_LOB_OUT_SCHEMA, &cx, &r, &lm)) {
          seer_schema_free(SEER_LOB_OUT_SCHEMA, &lm);
          break;
        }
        bool blank = true;
        for (size_t i = 2; i < lm.value.n; i++)
          blank &= lm.value.p[i] == 0;
        if (lm.value.n > 2 && !blank && (b->ret_locator = malloc(lm.value.n)) != NULL) {
          memcpy(b->ret_locator, lm.value.p, lm.value.n);
          b->ret_loclen = lm.value.n;
        }
        seer_schema_free(SEER_LOB_OUT_SCHEMA, &lm);
        continue;
      }
      /* SEER_OUT_CELL_SCHEMA: the value and its indicator, 81 01 NULL */
      SeerCellMsg om = {0};
      if (!seer_schema_decode(SEER_OUT_CELL_SCHEMA, &cx, &r, &om)) {
        seer_schema_free(SEER_OUT_CELL_SCHEMA, &om);
        break;
      }
      const uint8_t *val = om.value.p;
      size_t vlen = om.value.n;
      free(b->out.data);
      b->out = (SeerCell){0};
      if (om.indicator == -1) {
        /* NULL */
      } else {
        if (b->oac_type == ORA_TYPE_REFCURSOR) {
          /* The opened cursor's id: its rows become the statement's result
           * set once the block is done (#166). */
          uint32_t id = fv2_cursor_id(val, vlen);
          if (id != 0) {
            stmt->refcursor_id = (int)id;
            stmt->refcursor_present = true;
          }
        } else if (vlen > 0)
          decode_scalar(b->oac_type ? b->oac_type : ORA_TYPE_VARCHAR, val, vlen, &b->out);
      }
      seer_schema_free(SEER_OUT_CELL_SCHEMA, &om);
    }
  }
  fv2_decode_dml_response(r.buf + r.pos, seer_reader_remaining(&r), rowcount, code);
}

/* Release one bind's buffers (free_binds' per-bind part). */
static void free_one_bind(SeerStmt *s, SeerBind *b)
{
  int iters = s->n_iters > 0 ? s->n_iters : 1;
  if (b->rxd != NULL)
    for (int k = 0; k < iters; k++)
      free(b->rxd[k]);
  free(b->rxd);
  free(b->rxd_len);
  free(b->out.data);
  free(b->ret_locator);
  for (int k = 0; k < b->out_arr_n; k++)
    free(b->out_arr[k].data);
  free(b->out_arr);
  free(b->oac_override);
  free(b->out_image);
  queue_temp_lob_free(s->conn, b->temp_locator, b->temp_loclen);
  free_columns(b->obj_type, b->obj_type ? 1 : 0);
  memset(b, 0, sizeof *b);
}

/* A 9i DML that only a PL/SQL block can run: a RETURNING ... INTO, which 9.2
 * refuses in a TTI_ALL7 statement (ORA-00439: feature not enabled: RETURNING
 * clause from this client type), and one with a text bind past 4000 bytes,
 * which it takes only in a block, declared at 32767 (seerdb PROTOCOL.md
 * §19.3.1). In the block the INTO targets are ordinary OUT binds (§19.3,
 * #801):
 *
 *   BEGIN <dml>; :seer_rowcount := SQL%ROWCOUNT; END;
 *
 * The appended OUT bind carries the DML's row count; the block's own is 1.
 * Two differences from the 10g+ form are made up for here: a value longer
 * than its bind's declared size is cut to it with the full length recorded
 * (seer_stmt_out_truncated, 01004), where a PL/SQL OUT variable would raise
 * ORA-06502 - the block declares text at 4000; and a LOB target, which needs a
 * 9i LOB OUT bind, is refused, as is an array RETURNING. */
static SeerStatus fv2_execute_block(SeerStmt *stmt);
static SeerStatus fv2_execute_in_block(SeerStmt *stmt)
{
  const char *rel = stmt->conn->is_8i ? "8i" : "9i";
  if (stmt->n_iters > 1) {
    seer_log(SEER_LOG_WARNING,
             "stmt: Oracle %s: an array DML with RETURNING or long binds is not supported", rel);
    return SEER_ENOTIMPL;
  }
  /* A RETURNING target wider than a VARCHAR2 / RAW column holds is a LOB's,
   * as on 10g+ (returning_lob_type): bound as the LOB, its locator comes back
   * and its content is read (#167). Bound as text, 9i cut it to 4000 / 2000
   * bytes and reported success. */
  for (int i = 0; i < stmt->npbinds; i++) {
    SeerBind *b = &stmt->pbinds[i];
    b->ret_lob = b->lob_out; /* an explicit CLOB / BLOB OUT stays one (#214) */
    if (b->ret_lob != 0)
      continue;
    if (b->is_out && b->oac_size > 4000 && b->oac_type == ORA_TYPE_VARCHAR)
      b->ret_lob = ORA_TYPE_CLOB;
    else if (b->is_out && b->oac_size > 4000 && b->oac_type == ORA_TYPE_RAW)
      b->ret_lob = ORA_TYPE_BLOB;
  }

  size_t n = strlen(stmt->sql);
  while (n > 0 && (isspace((unsigned char)stmt->sql[n - 1]) || stmt->sql[n - 1] == ';'))
    n--; /* a trailing ';' would close the statement early inside the block */
  static const char RC[] = "seer_rowcount";
  size_t wlen = n + sizeof RC + 48;
  char *wrapped = malloc(wlen);
  if (wrapped == NULL)
    return SEER_ENOMEM;
  snprintf(wrapped, wlen, "BEGIN %.*s; :%s := SQL%%ROWCOUNT; END;", (int)n, stmt->sql, RC);

  int nuser = stmt->npbinds;
  SeerStatus st = seer_stmt_bind_out(stmt, nuser + 1, ORA_TYPE_NUMBER, 22);
  if (st != SEER_OK) {
    free(wrapped);
    return st;
  }
  char *orig = stmt->sql;
  stmt->sql = wrapped;
  st = stmt->conn->is_8i ? o8i_execute_block(stmt) : fv2_execute_block(stmt);
  stmt->sql = orig;
  free(wrapped);

  SeerBind *rcb = &stmt->pbinds[nuser];
  long rows = (rcb->out.data != NULL && rcb->out.len > 0) ? atol(rcb->out.data) : 0;
  free_one_bind(stmt, rcb);
  stmt->npbinds = nuser;
  if (st != SEER_OK)
    return st;
  stmt->affected = rows;

  for (int i = 0; i < nuser; i++) {
    SeerBind *b = &stmt->pbinds[i];
    bool sized = b->oac_type == ORA_TYPE_VARCHAR || b->oac_type == ORA_TYPE_CHAR ||
                 b->oac_type == ORA_TYPE_RAW;
    if (b->is_out && sized && b->oac_size > 0 && b->out.data != NULL && b->out.len > b->oac_size) {
      b->out_full_len = (int64_t)b->out.len;
      b->out.len = b->oac_size;
      b->out.data[b->out.len] = '\0';
    }
  }
  return SEER_OK;
}

/* Oracle 9i anonymous PL/SQL block over TTI_ALL7 (PROTOCOL §19.6/§19.7): OOPEN,
 * block parse (bind OACs, no inline values), then - if there are IN values - the
 * server sends a bind prompt and we reply with the IN values in one RXD; the reply
 * carries any OUT/IN-OUT values. */
static SeerStatus fv2_execute_block(SeerStmt *stmt)
{
  SeerConn *c = stmt->conn;
  uint8_t *resp = NULL;
  size_t rlen = 0;
  SeerStatus st;
  SeerWriter w;

  int n_in = 0, n_out = 0;
  for (int i = 0; i < stmt->npbinds; i++) {
    if (stmt->pbinds[i].is_out)
      n_out++;
    else
      n_in++;
  }

  /* The session's cursor (OOPEN on first use). */
  uint32_t cursor = 0;
  st = fv2_shared_cursor(c, &cursor);
  if (st != SEER_OK)
    return st;

  /* Block parse (OACs, no inline values). */
  st = fv2_emit_block(stmt, &w);
  if (st != SEER_OK)
    return st;
  st = fv2_txn(c, w.buf, w.len, &resp, &rlen);
  seer_writer_free(&w);
  if (st != SEER_OK)
    return st;

  /* When the block reads any bind, the reply is a bind prompt whose masks say
   * which binds the server wants a value for (IN, IN OUT) and which it returns
   * (OUT, IN OUT). Follow them rather than the declared directions: an IN OUT
   * parameter is declared OUT but must send its value, or the block sees NULL.
   * A block that only assigns its binds gets a prompt too, with its OUT values
   * already following it - nothing to send then. With no prompt the declared
   * directions stand. */
  uint8_t *dirs = stmt->npbinds > 0 ? calloc((size_t)stmt->npbinds, 1) : NULL;
  bool prompted = dirs != NULL && fv2_bind_directions(resp, rlen, stmt->npbinds, dirs);
  /* Mask k is bind k: the server pairs the binds with the placeholders in
   * order of appearance, as on every tier (#146). */
  if (prompted) {
    n_in = n_out = 0;
    for (int k = 0; k < stmt->npbinds; k++) {
      n_in += (dirs[k] & FV2_DIR_IN) != 0;
      n_out += (dirs[k] & FV2_DIR_OUT) != 0;
    }
  } else {
    free(dirs);
    dirs = NULL;
  }

  /* With IN values, the reply is the bind prompt (or a compile OER); send the
   * IN values in one RXD, then the reply carries the OUT values. */
  if (n_in > 0) {
    int64_t pc = prompted ? 0 : fv2_oer_code(resp, rlen);
    if (pc != 0 && pc != 1403) {
      fv2_set_error(c, resp, rlen);
      seer_log(SEER_LOG_DEBUG, "fv2: block compile failed (ORA-%05ld)", (long)pc);
      free(resp);
      free(dirs);
      return SEER_EDB;
    }
    free(resp);
    resp = NULL;
    if (!seer_writer_init(&w, 32 + (size_t)n_in * 16)) {
      free(dirs);
      return SEER_ENOMEM;
    }
    seer_writer_u8(&w, TTI_RXD);
    for (int k = 0; k < stmt->npbinds; k++) {
      SeerBind *b = &stmt->pbinds[k];
      if (dirs != NULL ? !(dirs[k] & FV2_DIR_IN) : b->is_out)
        continue;
      uint8_t *rxd = (b->rxd != NULL) ? b->rxd[0] : NULL;
      if (rxd != NULL)
        seer_writer_bytes(&w, rxd, b->rxd_len[0]);
      else
        chr_write(&w, false, TTC_FIELD_VERSION_9_2, NULL, 0); /* unbound: NULL */
    }
    if (!seer_writer_ok(&w)) {
      seer_writer_free(&w);
      free(dirs);
      return SEER_ENOMEM;
    }
    st = fv2_txn(c, w.buf, w.len, &resp, &rlen);
    seer_writer_free(&w);
    if (st != SEER_OK) {
      free(dirs);
      return st;
    }
  }

  int64_t rowcount = 0, code = 0;
  fv2_decode_block_out(stmt, resp, rlen, n_out, dirs, &rowcount, &code);
  free(dirs);
  bool failed = (code != 0 && code != 1403);
  if (failed) {
    fv2_set_error(c, resp, rlen);
    seer_log(SEER_LOG_DEBUG, "fv2: block failed (ORA-%05ld)", (long)code);
  }
  free(resp);
  resp = NULL;

  /* End the statement on the cursor (best-effort). */
  fv2_close_cursor(c, cursor);
  if (failed) {
    stmt->refcursor_present = false;
    return SEER_EDB;
  }

  /* A REF CURSOR OUT: read the cursor the block opened as a query's own -
   * describe, execute + fetch to ORA-01403 - adopting its rows as this
   * statement's result set, as the 10g+ path does; then close and free it
   * (seerdb, ojdbc14 on 9.2.0.4; #166). */
  if (stmt->refcursor_present) {
    uint32_t rc = (uint32_t)stmt->refcursor_id;
    stmt->refcursor_present = false;
    free_rows(stmt);
    free_columns(stmt->cols, stmt->ncols);
    stmt->cols = NULL;
    stmt->ncols = 0;
    int64_t errcode = 0;
    st = fv2_describe_cursor(stmt, rc);
    if (st == SEER_OK)
      st = fv2_fetch_cursor(stmt, rc, &errcode);
    if (st == SEER_OK && stmt->nplobs > 0)
      fv2_resolve_lobs(stmt);
    fv2_close_cursor(c, rc);
    fv2_free_cursor(c, rc);
    if (st != SEER_OK)
      return st;
    if (errcode != 0 && errcode != 1403)
      return SEER_EDB;
    stmt->cur = -1;
  }

  /* OUT objects, decoded by their types' layouts (#172). */
  st = resolve_out_objects(stmt);
  if (st != SEER_OK)
    return st;

  /* The LOBs the block returned, read by their locators before anything else
   * goes to the server (§19.5 GETLEN + READ, #167): CLOB text, BLOB bytes. */
  for (int k = 0; k < stmt->npbinds; k++) {
    SeerBind *b = &stmt->pbinds[k];
    if (b->ret_locator == NULL)
      continue;
    uint8_t *content = NULL;
    size_t clen = 0;
    int64_t amount = fv2_lob_getlen(c, b->ret_locator, b->ret_loclen);
    if (amount > 0 &&
        fv2_lob_read(c, b->ret_locator, b->ret_loclen, amount, &content, &clen) != SEER_OK) {
      free(content);
      return SEER_EPROTO;
    }
    cell_set_bytes(&b->out, content ? content : (const uint8_t *)"", clen,
                   b->ret_lob != ORA_TYPE_CLOB);
    free(content);
    free(b->ret_locator);
    b->ret_locator = NULL;
    b->ret_loclen = 0;
  }

  stmt->affected = (long)rowcount;
  stmt->executed = true;
  if (c->autocommit)
    return seer_commit(c); /* its failure is the statement's (#347) */
  return SEER_OK;
}

/* A 9i statement by its kind: a query's four calls, a DML (in a block when its
 * binds or a RETURNING need one), a block as it is. */
static SeerStatus fv2_execute_kind(SeerStmt *stmt)
{
  StmtKind kind = classify_sql(stmt->sql);
  int binds = fv2_long_binds(stmt);
  bool sql = kind == STMT_SELECT || kind == STMT_CHANGE; /* a block goes as it is */
  if (sql && (binds == FV2_BINDS_NONE || (binds == FV2_BINDS_BLOCK && kind == STMT_SELECT))) {
    seer_log(SEER_LOG_WARNING, "stmt: Oracle 9i: a bind over 32512 bytes, or over 4000 of "
                               "text / 2000 of RAW in a query, is not supported");
    return SEER_ENOTIMPL;
  }
  if (kind == STMT_SELECT)
    return fv2_execute_select(stmt);
  if (kind == STMT_CHANGE) {
    if (binds == FV2_BINDS_BLOCK) /* long text: only a block takes it */
      return fv2_execute_in_block(stmt);
    for (int i = 0; i < stmt->npbinds; i++)
      if (stmt->pbinds[i].is_out) /* OUT binds on a DML: RETURNING ... INTO */
        return fv2_execute_in_block(stmt);
    return fv2_execute_dml(stmt);
  }
  return fv2_execute_block(stmt); /* BEGIN / DECLARE */
}

SeerStatus seer_stmt_set_max_rows(SeerStmt *stmt, size_t max_rows)
{
  if (stmt == NULL)
    return SEER_EPARAM;
  stmt->max_rows = max_rows;
  return SEER_OK;
}

SeerStatus seer_stmt_col_vector(SeerStmt *stmt, int col, int *dims, int *format)
{
  if (stmt == NULL || col < 0 || col >= stmt->ncols)
    return SEER_EPARAM;
  if (dims != NULL)
    *dims = (int)stmt->cols[col].vector_dims;
  if (format != NULL)
    *format = stmt->cols[col].vector_format;
  return SEER_OK;
}

int seer_stmt_compile_warning(SeerStmt *stmt)
{
  return stmt != NULL && stmt->compile_warning;
}

int seer_stmt_is_query(const SeerStmt *stmt)
{
  return stmt != NULL && stmt->sql != NULL && classify_sql(stmt->sql) == STMT_SELECT;
}

/* ----------------------------------------- one value per occurrence (#302) */

/* The binds as the API set them, while the expanded set is on the statement. */
typedef struct {
  SeerBind *orig; /* NULL: nothing expanded */
  int norig;
  int *occ; /* per occurrence, its distinct placeholder */
  int nocc, ndistinct;
  int *first; /* per distinct placeholder, its first occurrence */
} BindExpansion;

/* A repeat of `b` for a later occurrence: the same descriptor, its own copy
 * of the values (an execute may replace them, as 9i's temporary LOBs do), and
 * nothing it owns besides. */
static SeerStatus dup_bind(const SeerStmt *s, const SeerBind *b, SeerBind *d)
{
  int iters = s->n_iters > 0 ? s->n_iters : 1;
  *d = *b;
  d->rxd = NULL;
  d->rxd_len = NULL;
  d->oac_override = NULL;
  d->out = (SeerCell){0};
  d->ret_locator = NULL;
  d->out_arr = NULL;
  d->out_arr_n = 0;
  d->out_image = NULL;
  d->temp_locator = NULL; /* the first occurrence owns the temporary LOB */
  d->temp_loclen = 0;
  if (b->rxd != NULL) {
    d->rxd = calloc((size_t)iters, sizeof *d->rxd);
    d->rxd_len = calloc((size_t)iters, sizeof *d->rxd_len);
    if (d->rxd == NULL || d->rxd_len == NULL)
      return SEER_ENOMEM;
    for (int k = 0; k < iters; k++) {
      d->rxd_len[k] = b->rxd_len[k];
      if (b->rxd[k] == NULL)
        continue;
      d->rxd[k] = malloc(b->rxd_len[k] > 0 ? b->rxd_len[k] : 1);
      if (d->rxd[k] == NULL)
        return SEER_ENOMEM;
      memcpy(d->rxd[k], b->rxd[k], b->rxd_len[k]);
    }
  }
  if (b->oac_override != NULL) {
    d->oac_override = malloc(b->oac_override_len);
    if (d->oac_override == NULL)
      return SEER_ENOMEM;
    memcpy(d->oac_override, b->oac_override, b->oac_override_len);
  }
  return SEER_OK;
}

/* Free what dup_bind made (obj_type is the first occurrence's). */
static void free_dup_bind(const SeerStmt *s, SeerBind *d)
{
  int iters = s->n_iters > 0 ? s->n_iters : 1;
  if (d->rxd != NULL)
    for (int k = 0; k < iters; k++)
      free(d->rxd[k]);
  free(d->rxd);
  free(d->rxd_len);
  free(d->oac_override);
  memset(d, 0, sizeof *d);
}

/* For a SQL statement whose placeholders repeat, put on the statement one
 * bind per occurrence, each a copy of its distinct placeholder's: the server
 * pairs a SQL statement's values with occurrences, so `:1 || :1 || :2` with
 * two left :2 unbound (ORA-01008). Not for what runs as a PL/SQL block, which
 * takes one value per name: a block, a DML with OUT binds (RETURNING, which
 * 8i / 9i wrap in a block, and where python-oracledb refuses repeated names),
 * a 9i DML with a long text bind. Nor when fewer binds are set than names,
 * which the server reports as it is. */
static SeerStatus expand_binds(SeerStmt *stmt, BindExpansion *x)
{
  *x = (BindExpansion){0};
  if (stmt->npbinds == 0 || stmt->sql == NULL)
    return SEER_OK;
  StmtKind kind = classify_sql(stmt->sql);
  if (kind == STMT_BLOCK)
    return SEER_OK;
  for (int i = 0; i < stmt->npbinds; i++)
    if (stmt->pbinds[i].is_out)
      return SEER_OK;
  if (kind == STMT_CHANGE && !stmt->conn->is_8i &&
      stmt->conn->field_version < TTC_FIELD_VERSION_10_2 && fv2_long_binds(stmt) == FV2_BINDS_BLOCK)
    return SEER_OK;
  int *occ = NULL, nocc = 0, nd = 0;
  if (seer_sql_placeholders(stmt->sql, &occ, &nocc, &nd) != 0)
    return SEER_ENOMEM;
  if (nocc == nd || nd > stmt->npbinds) {
    free(occ);
    return SEER_OK;
  }
  int extra = stmt->npbinds - nd; /* set past the last name: kept, after */
  SeerBind *e = calloc((size_t)(nocc + extra), sizeof *e);
  int *first = malloc((size_t)nd * sizeof *first);
  if (e == NULL || first == NULL) {
    free(e);
    free(first);
    free(occ);
    return SEER_ENOMEM;
  }
  for (int k = 0; k < nd; k++)
    first[k] = -1;
  SeerStatus st = SEER_OK;
  for (int j = 0; j < nocc && st == SEER_OK; j++) {
    int k = occ[j];
    if (first[k] < 0) {
      e[j] = stmt->pbinds[k];
      first[k] = j;
    } else {
      st = dup_bind(stmt, &stmt->pbinds[k], &e[j]);
    }
  }
  if (st != SEER_OK) {
    for (int j = 0; j < nocc; j++)
      if (first[occ[j]] != j)
        free_dup_bind(stmt, &e[j]);
    free(e);
    free(first);
    free(occ);
    return st;
  }
  for (int t = 0; t < extra; t++)
    e[nocc + t] = stmt->pbinds[nd + t];
  *x = (BindExpansion){stmt->pbinds, stmt->npbinds, occ, nocc, nd, first};
  stmt->pbinds = e;
  stmt->npbinds = nocc + extra;
  seer_log(SEER_LOG_DEBUG, "stmt: %d placeholders, %d occurrences: one value each", nd, nocc);
  return SEER_OK;
}

/* Back to the binds as set: the first occurrences and the extras carry
 * whatever the call left in them; the repeats go. */
static void restore_binds(SeerStmt *stmt, BindExpansion *x)
{
  if (x->orig == NULL)
    return;
  int extra = x->norig - x->ndistinct;
  for (int k = 0; k < x->ndistinct; k++)
    x->orig[k] = stmt->pbinds[x->first[k]];
  for (int t = 0; t < extra; t++)
    x->orig[x->ndistinct + t] = stmt->pbinds[x->nocc + t];
  for (int j = 0; j < x->nocc; j++)
    if (x->first[x->occ[j]] != j)
      free_dup_bind(stmt, &stmt->pbinds[j]);
  free(stmt->pbinds);
  stmt->pbinds = x->orig;
  stmt->npbinds = x->norig;
  free(x->occ);
  free(x->first);
  *x = (BindExpansion){0};
}

static SeerStatus describe_now(SeerStmt *stmt);
static SeerStatus execute_now(SeerStmt *stmt);

SeerStatus seer_stmt_describe(SeerStmt *stmt)
{
  if (stmt == NULL)
    return SEER_EPARAM;
  BindExpansion x;
  SeerStatus st = expand_binds(stmt, &x);
  if (st != SEER_OK)
    return st;
  st = describe_now(stmt);
  restore_binds(stmt, &x);
  return st;
}

SeerStatus seer_stmt_execute(SeerStmt *stmt)
{
  if (stmt == NULL)
    return SEER_EPARAM;
  if (!stmt->conn->authenticated)
    return SEER_EPROTO;
  /* A REF CURSOR OUT hands back a cursor whose rows can each hold a nested
   * CURSOR(), and from 10g the server keeps every one of those open while the
   * query is (10g's default open_cursors is 50). Its rows are fetched by a
   * call that carries no piggybacks, so the statement cache's hidden cursors
   * are queued closed now and go out ahead of this execute, freeing their
   * slots before the nested cursors need them (#337). */
  if (stmt->conn->stmt_cache_n > 0)
    for (int i = 0; i < stmt->npbinds; i++)
      if (stmt->pbinds[i].oac_type == ORA_TYPE_REFCURSOR && stmt->pbinds[i].is_out) {
        stmt_cache_flush(stmt->conn);
        break;
      }
  BindExpansion x;
  SeerStatus st = expand_binds(stmt, &x);
  if (st != SEER_OK)
    return st;
  st = execute_now(stmt);
  restore_binds(stmt, &x);
  if (st == SEER_OK && may_set_time_zone(stmt->sql))
    stmt->conn->ltz_state = 0; /* the LOCAL TIME ZONE shift is read again (#358) */
  return st;
}

static SeerStatus describe_now(SeerStmt *stmt)
{
  if (stmt == NULL)
    return SEER_EPARAM;
  /* Already known (a cached cursor brings its describe), or nothing to
   * describe: only a query has a result set to describe. */
  if (stmt->ncols > 0 || stmt->executed || classify_sql(stmt->sql) != STMT_SELECT)
    return SEER_OK;
  if (stmt->conn->is_8i) {
    /* A describe-only OALL8 (#353), markers sent as value-less descriptors. */
    int *occ = NULL, nocc = 0, ndistinct = 0;
    int pr = seer_sql_placeholders(stmt->sql, &occ, &nocc, &ndistinct);
    free(occ);
    if (pr != 0)
      return SEER_OK;
    /* SQL binds by occurrence (#302): one descriptor per marker in the text */
    SeerStatus ost = o8i_describe_only(stmt, nocc);
    if (ost == SEER_OK)
      stmt->described_only = true;
    return ost;
  }
  if (stmt->conn->field_version < TTC_FIELD_VERSION_10_2) { /* 9i: parse + describe */
    SeerStatus fst = fv2_describe_only(stmt);
    if (fst == SEER_OK)
      stmt->described_only = true;
    return fst;
  }

  SeerWriter w;
  stmt->describe_only = true;
  SeerStatus st = build_exec(stmt, &w);
  stmt->describe_only = false;
  if (st != SEER_OK)
    return st;
  st = seer_ttc_send(stmt->conn, w.buf, w.len);
  seer_writer_free(&w);
  if (st != SEER_OK)
    return st;
  uint8_t *resp = NULL;
  size_t rlen = 0;
  st = seer_ttc_recv(stmt->conn, &resp, &rlen);
  if (st != SEER_OK)
    return st;
  OerResult oer = {0};
  st = parse_response(stmt, resp, rlen, true, &oer);
  free(resp);
  if (st != SEER_OK)
    return st;
  if (oer.err_code != 0) {
    queue_cursor_close(stmt->conn, oer.cursor_id);
    seer_log(SEER_LOG_DEBUG, "stmt: describe failed (ORA-%05ld)", (long)oer.err_code);
    return SEER_EDB;
  }
  /* The reply is the describe and a success status - no rows, and no drain:
   * a FETCH on a cursor that was only parsed is ORA-01002. Re-executing that
   * parse-only cursor without a parse proved unreliable, so it is closed and
   * the execute parses afresh (replacing these columns with its describe). */
  queue_cursor_close(stmt->conn, oer.cursor_id);
  stmt->described_only = true;
  return SEER_OK;
}

/* Swap iteration `row`'s values into iteration 0, where the single-row paths
 * read them (and back: the swap is its own inverse). */
static void swap_row(SeerStmt *stmt, int row)
{
  for (int i = 0; i < stmt->npbinds; i++) {
    SeerBind *b = &stmt->pbinds[i];
    if (b->rxd == NULL || row == 0)
      continue;
    uint8_t *v = b->rxd[0];
    size_t n = b->rxd_len[0];
    b->rxd[0] = b->rxd[row];
    b->rxd_len[0] = b->rxd_len[row];
    b->rxd[row] = v;
    b->rxd_len[row] = n;
  }
}

/* An array execute that only a single-row path takes - a PL/SQL block on
 * any tier (#428); on 8i / 9i a DML in one (RETURNING, text past 4000 bytes)
 * or with a temporary LOB (#418): run `one` a row at a time, as an array execute
 * reports it. The row counts add up; an OUT bind keeps the last row's value,
 * as the last RXD of a 10g+ array RETURNING does; a failing row stops the
 * rest, or with batch errors armed is recorded at its offset and the rest
 * run. Autocommit commits once, after the last row, as one execute would. */
static SeerStatus by_row(SeerStmt *stmt, SeerStatus (*one)(SeerStmt *))
{
  SeerConn *c = stmt->conn;
  int rows = stmt->n_iters;
  bool keep_going = stmt->batch_errors, autocommit = c->autocommit;
  SeerBatchError *berrs = NULL;
  size_t nberrs = 0;
  long affected = 0;
  SeerStatus st = SEER_OK;
  free_batch_errors(stmt);
  stmt->n_iters = 1;
  stmt->batch_errors = false; /* one row: its error is the row's own */
  c->autocommit = false;
  for (int row = 0; row < rows && st == SEER_OK; row++) {
    swap_row(stmt, row);
    SeerStatus rs = one(stmt);
    swap_row(stmt, row);
    if (rs == SEER_OK) {
      affected += stmt->affected;
    } else if (rs == SEER_EDB && keep_going) {
      SeerBatchError *nb = realloc(berrs, (nberrs + 1) * sizeof *nb);
      if (nb == NULL) {
        st = SEER_ENOMEM;
        break;
      }
      berrs = nb;
      unsigned code = 0;
      if (c->last_error != NULL)
        sscanf(c->last_error, "ORA-%u", &code);
      nb[nberrs].row = (uint32_t)row;
      nb[nberrs].code = code;
      nb[nberrs].message = c->last_error;
      c->last_error = NULL;
      nberrs++;
    } else {
      st = rs;
    }
  }
  stmt->n_iters = rows;
  stmt->batch_errors = keep_going;
  c->autocommit = autocommit;
  free_batch_errors(stmt); /* a row's own run may have left some */
  stmt->berrs = berrs;
  stmt->nberrs = nberrs;
  stmt->affected = affected;
  if (st != SEER_OK)
    return st;
  stmt->executed = true;
  if (autocommit)
    return seer_commit(c); /* its failure is the statement's (#347) */
  return SEER_OK;
}

/* 8i: the binds marked for a LOB target (seer_stmt_bind_clob / _blob) as
 * temporary LOBs for one execute (#424). 8.1.7's PL/SQL takes no text or RAW
 * for a LOB parameter (PLS-00306, whatever its length): each value goes into
 * a temporary LOB - a CLOB's text in WE8ISO8859P1, the session's charset -
 * and the bind sends its locator. o8i_temp_lobs_done puts the values back and
 * frees the LOBs. */
typedef struct {
  int bind;
  uint8_t *loc;
  size_t loclen;
  uint8_t *saved;
  size_t saved_len;
} O8iTempLob;

/* A temporary LOB holding `data` (a CLOB's UTF-8 text, a BLOB's bytes), made
 * by the server: 8.1.7 refuses 9.2's CREATE_TEMP call (ORA-22275, its empty
 * source locator), so one PL/SQL block creates it, appends the value in
 * chunks each bind takes inline (4000 bytes of text, 2000 of RAW) and hands
 * the locator back through a LOB OUT bind, kept rather than read (#424). */
static SeerStatus o8i_server_temp_lob(SeerConn *c, bool blob, const uint8_t *data, size_t n,
                                      uint8_t **loc, size_t *loclen)
{
  const size_t piece = blob ? 2000 : 4000;
  size_t chunks = n == 0 ? 0 : (n + piece - 1) / piece + 1; /* text splits at a character */
  SeerWriter sql;
  if (!seer_writer_init(&sql, 128 + chunks * 48))
    return SEER_ENOMEM;
  char line[96];
  snprintf(line, sizeof line, "DECLARE l %s; BEGIN DBMS_LOB.CREATETEMPORARY(l, TRUE); ",
           blob ? "BLOB" : "CLOB");
  seer_writer_bytes(&sql, line, strlen(line));
  size_t *cut = calloc(chunks + 1, sizeof *cut); /* chunk k is data[cut[k] .. cut[k + 1]) */
  uint32_t *amount = calloc(chunks + 1, sizeof *amount);
  int nchunks = 0;
  SeerStatus st = cut == NULL || amount == NULL ? SEER_ENOMEM : SEER_OK;
  for (size_t at = 0; st == SEER_OK && at < n; nchunks++) {
    size_t end = at + piece < n ? at + piece : n;
    while (!blob && end < n && (data[end] & 0xC0) == 0x80)
      end--; /* not inside a UTF-8 sequence */
    uint32_t chars = 0;
    for (size_t i = at; i < end; i++)
      chars += blob || (data[i] & 0xC0) != 0x80;
    cut[nchunks] = at;
    amount[nchunks] = chars;
    snprintf(line, sizeof line, "DBMS_LOB.WRITEAPPEND(l, %u, :%d); ", (unsigned)chars, nchunks + 1);
    seer_writer_bytes(&sql, line, strlen(line));
    at = end;
  }
  if (cut != NULL)
    cut[nchunks] = n;
  /* Binds go by appearance (#146): the chunks, then the locator. */
  snprintf(line, sizeof line, ":%d := l; END;", nchunks + 1);
  seer_writer_bytes(&sql, line, strlen(line) + 1); /* with its NUL */
  if (st == SEER_OK && !seer_writer_ok(&sql))
    st = SEER_ENOMEM;
  SeerStmt *s = NULL;
  if (st == SEER_OK)
    st = seer_stmt_prepare(c, (const char *)sql.buf, &s);
  if (st == SEER_OK)
    st = seer_stmt_bind_out(s, nchunks + 1, blob ? ORA_TYPE_BLOB : ORA_TYPE_CLOB, 0);
  for (int k = 0; st == SEER_OK && k < nchunks; k++) {
    const uint8_t *p = data + cut[k];
    int len = (int)(cut[k + 1] - cut[k]);
    st = blob ? seer_stmt_bind_raw(s, k + 1, p, len)
              : seer_stmt_bind_text(s, k + 1, (const char *)p, len);
  }
  if (st == SEER_OK) {
    s->keep_lob_locators = true;
    st = seer_stmt_execute(s);
  }
  SeerBind *ob = s != NULL && s->npbinds > nchunks ? &s->pbinds[nchunks] : NULL;
  if (st == SEER_OK && (ob == NULL || ob->ret_locator == NULL))
    st = SEER_EPROTO;
  if (st == SEER_OK) {
    *loc = ob->ret_locator;
    *loclen = ob->ret_loclen;
    ob->ret_locator = NULL;
    ob->ret_loclen = 0;
  }
  seer_stmt_close(s);
  seer_writer_free(&sql);
  free(cut);
  free(amount);
  return st;
}

static void o8i_temp_lobs_done(SeerStmt *stmt, O8iTempLob *t, int n)
{
  for (int k = 0; k < n; k++) {
    SeerBind *b = &stmt->pbinds[t[k].bind];
    if (t[k].saved != NULL) {
      free(b->rxd[0]);
      b->rxd[0] = t[k].saved;
      b->rxd_len[0] = t[k].saved_len;
    }
    b->fv2_lob = 0;
    if (stmt->conn->t != NULL && t[k].loc != NULL)
      o8i_free_temp(stmt->conn, t[k].loc, t[k].loclen);
    free(t[k].loc);
  }
  free(t);
}

static SeerStatus o8i_temp_lobs_begin(SeerStmt *stmt, O8iTempLob **out, int *n)
{
  *out = NULL;
  *n = 0;
  for (int i = 0; i < stmt->npbinds; i++) {
    SeerBind *b = &stmt->pbinds[i];
    if (!b->as_lob || b->is_out || b->rxd == NULL || b->rxd[0] == NULL)
      continue;
    bool blob = b->oac_type == ORA_TYPE_RAW || b->oac_type == ORA_TYPE_LONGRAW;
    SeerWriter v;
    if (!seer_writer_init(&v, b->rxd_len[0] + 1))
      return SEER_ENOMEM;
    SeerStatus st = o8i_unchunk(b->rxd[0], b->rxd_len[0], &v);
    if (st == SEER_OK && !seer_writer_ok(&v))
      st = SEER_ENOMEM;
    uint8_t *data = NULL; /* a CLOB's UTF-8 text, a BLOB's bytes */
    size_t dlen = 0;
    if (st == SEER_OK)
      data = v.buf, dlen = v.len, v.buf = NULL;
    seer_writer_free(&v);
    O8iTempLob *t = st == SEER_OK ? realloc(*out, (size_t)(*n + 1) * sizeof *t) : NULL;
    if (st == SEER_OK && t == NULL)
      st = SEER_ENOMEM;
    if (st == SEER_OK) {
      *out = t;
      t = &t[*n];
      *t = (O8iTempLob){.bind = i};
      st = o8i_server_temp_lob(stmt->conn, blob, data, dlen, &t->loc, &t->loclen);
      if (st == SEER_OK)
        (*n)++; /* made: o8i_temp_lobs_done frees it */
      if (st == SEER_OK) {
        SeerWriter bv;
        if (!seer_writer_init(&bv, t->loclen + 8)) {
          st = SEER_ENOMEM;
        } else {
          SeerLegacyLobBindMsg lm = {.loc_len = (int64_t)t->loclen,
                                     .locator = {.p = t->loc, .n = t->loclen}};
          SeerSchemaCtx cx = seer_msg_ctx(1, 0, 0);
          seer_schema_encode(SEER_LEGACY_LOB_BIND_SCHEMA, &cx, &lm, &bv);
          if (!seer_writer_ok(&bv)) {
            seer_writer_free(&bv);
            st = SEER_ENOMEM;
          } else {
            t->saved = b->rxd[0];
            t->saved_len = b->rxd_len[0];
            b->rxd[0] = bv.buf;
            b->rxd_len[0] = bv.len;
            b->fv2_lob = blob ? ORA_TYPE_BLOB : ORA_TYPE_CLOB;
          }
        }
      }
    }
    free(data);
    if (st != SEER_OK)
      return st;
    seer_log(SEER_LOG_DEBUG, "stmt: 8i bind %d: %zu bytes as a temporary %s", i + 1, dlen,
             blob ? "BLOB" : "CLOB");
  }
  return SEER_OK;
}

/* 8i: a PL/SQL block, or a DML run in one (RETURNING ... INTO), its LOB-bound
 * values as temporary LOBs (#424). */
static SeerStatus o8i_execute_in_block_kind(SeerStmt *stmt)
{
  O8iTempLob *tl = NULL;
  int ntl = 0;
  SeerStatus st = o8i_temp_lobs_begin(stmt, &tl, &ntl);
  if (st == SEER_OK)
    st = classify_sql(stmt->sql) == STMT_BLOCK ? o8i_execute_block(stmt)
                                               : fv2_execute_in_block(stmt);
  o8i_temp_lobs_done(stmt, tl, ntl);
  return st;
}

/* 9i: one execute, its values past what 9.2 takes inline as temporary LOBs
 * for it (#169). */
static SeerStatus fv2_execute_one(SeerStmt *stmt)
{
  Fv2TempLob *tl = NULL;
  int ntl = 0;
  SeerStatus st = fv2_temp_lobs_begin(stmt, classify_sql(stmt->sql) == STMT_SELECT, &tl, &ntl);
  if (st == SEER_OK)
    st = fv2_execute_kind(stmt);
  fv2_temp_lobs_done(stmt, tl, ntl);
  return st;
}

/* Whether a 9i array execute needs a single-row path: a block, or a DML that
 * goes in one or with a temporary LOB. */
static bool fv2_array_by_row(const SeerStmt *stmt)
{
  if (stmt->n_iters <= 1 || stmt->npbinds == 0)
    return false;
  StmtKind kind = classify_sql(stmt->sql);
  if (kind == STMT_BLOCK)
    return true;
  if (kind != STMT_CHANGE)
    return false;
  for (int i = 0; i < stmt->npbinds; i++)
    if (stmt->pbinds[i].is_out || fv2_needs_temp_lob(stmt, &stmt->pbinds[i], false))
      return true;
  return fv2_long_binds(stmt) == FV2_BINDS_BLOCK;
}

static SeerStatus thin_execute(SeerStmt *stmt);

static SeerStatus execute_now(SeerStmt *stmt)
{
  if (stmt == NULL)
    return SEER_EPARAM;
  if (!stmt->conn->authenticated)
    return SEER_EPROTO;
  /* An error message belongs to the call that drew it: a failure here that
   * carries none must not report the previous statement's. */
  free(stmt->conn->last_error);
  stmt->conn->last_error = NULL;
  stmt->conn->last_error_offset = 0;
  /* A query with an array of parameter sets is refused on every tier, as
   * SQL_PARAM_ARRAY_SELECTS (SQL_PAS_NO_SELECT) says: 10g+ sent the first
   * set and 9i the last, and either returned that set's rows alone (#430). */
  if (stmt->n_iters > 1 && stmt->npbinds > 0 && classify_sql(stmt->sql) == STMT_SELECT) {
    stmt->conn->last_error =
        strdup("a query can't run with an array of parameter sets: run it once "
               "per set");
    seer_log(SEER_LOG_WARNING, "stmt: an array execute of a query is not supported");
    return SEER_ENOTIMPL;
  }
  if (stmt->conn->is_8i) {
    /* Oracle 8i: its own 9.2-era OALL8 dialect (seerdb §19.9-19.12):
     * queries, DML, DDL and transaction control. PL/SQL blocks are not
     * spoken yet (#134) - refuse rather than send 9i's ALL7, which 8i never
     * answers. */
    StmtKind kind = classify_sql(stmt->sql);
    bool has_out = false;
    for (int i = 0; i < stmt->npbinds; i++)
      has_out |= stmt->pbinds[i].is_out;
    /* A DML with OUT binds is a RETURNING ... INTO: run in a block, as on 9i. */
    bool in_block = kind == STMT_BLOCK || (kind == STMT_CHANGE && has_out);
    SeerStatus bst = o8i_check_binds(stmt, kind == STMT_SELECT, in_block);
    if (bst != SEER_OK)
      return bst;
    if (in_block) /* a single-row path: an array goes a row at a time */
      return stmt->n_iters > 1 && stmt->npbinds > 0 ? by_row(stmt, o8i_execute_in_block_kind)
                                                    : o8i_execute_in_block_kind(stmt);
    return kind == STMT_SELECT ? o8i_execute_select(stmt) : o8i_execute_dml(stmt);
  }

  /* Oracle 9i (fv2) speaks the TTI_ALL7 dialect, not TTI_ALL8: SELECT is a
   * four-call fetch sequence, DML/DDL a single parse-execute. Values past
   * what 9.2 takes inline go as temporary LOBs for the execute (#169). An
   * array that only a single-row path takes goes a row at a time. */
  if (stmt->conn->field_version < TTC_FIELD_VERSION_10_2)
    return fv2_array_by_row(stmt) ? by_row(stmt, fv2_execute_one) : fv2_execute_one(stmt);

  /* 10g+ sends a PL/SQL block as one iteration (build_exec): an array of
   * them goes a row at a time, as python-oracledb's executemany runs a block
   * whose binds it doesn't know yet (#428). */
  if (stmt->n_iters > 1 && stmt->npbinds > 0 && classify_sql(stmt->sql) == STMT_BLOCK)
    return by_row(stmt, thin_execute);
  return thin_execute(stmt);
}

/* One 10g+ execute over TTI_ALL8. */
static SeerStatus thin_execute(SeerStmt *stmt)
{
  if (stmt->described_only) { /* the execute parses and describes afresh */
    free_columns(stmt->cols, stmt->ncols);
    stmt->cols = NULL;
    stmt->ncols = 0;
    stmt->described_only = false;
  }
  free_batch_errors(stmt); /* clear any prior execute's failures */
  free_implicit(stmt);     /* and any prior implicit result sets   */
  stmt->fetch_by_oall8 = false;
  stmt->cols_adopted = false;
  free(stmt->dml_rowcounts); /* and any prior array-DML row counts   */
  stmt->dml_rowcounts = NULL;
  stmt->n_dml_rowcounts = 0;

  /* A cached cursor is reused only for binds of the types it was parsed
   * with; for others it is closed and the statement parsed afresh (#162). */
  if (stmt->reuse_cursor > 0) {
    char *sig = bind_signature(stmt);
    if (sig == NULL || stmt->reuse_binds == NULL || strcmp(sig, stmt->reuse_binds) != 0) {
      queue_cursor_close(stmt->conn, stmt->reuse_cursor);
      stmt->reuse_cursor = 0;
      free_columns(stmt->cols, stmt->ncols);
      stmt->cols = NULL;
      stmt->ncols = 0;
      free(stmt->reuse_binds);
      stmt->reuse_binds = NULL;
    }
    free(sig);
  }
  bool was_reuse = stmt->reuse_cursor > 0;
  bool retried_open_cursors = false; /* #337 */
  SeerWriter w;
  uint8_t *resp = NULL;
  size_t rlen = 0;
  OerResult oer;
  SeerStatus st;

retry_exec:
  oer = (OerResult){0};
  st = build_exec(stmt, &w);
  if (st != SEER_OK)
    return st;
  st = seer_ttc_send(stmt->conn, w.buf, w.len);
  seer_writer_free(&w);
  if (st != SEER_OK)
    return st;

  resp = NULL;
  rlen = 0;
  st = seer_ttc_recv(stmt->conn, &resp, &rlen);
  if (st != SEER_OK)
    return st;

  /* A reused cursor's response carries no describe (we kept the columns); a
   * fresh parse does. */
  st = parse_response(stmt, resp, rlen, stmt->reuse_cursor == 0, &oer);
  if (st == SEER_OK)
    st = resolve_returned_lobs(stmt);
  if (st == SEER_OK)
    st = resolve_out_objects(stmt);
  free(resp);
  resp = NULL;
  if (st != SEER_OK)
    return st;
  /* The server asked to flush out-binds (a failing DML RETURNING): echo the
   * TTI_FOB and read the real response behind it - the statement's error. */
  for (int asked = 0; oer.flush_binds; asked++) {
    if (asked == 3) {
      seer_log(SEER_LOG_ERROR, "stmt: server keeps asking to flush out-binds");
      return SEER_EPROTO;
    }
    const uint8_t fob = TTI_FOB;
    st = seer_ttc_send(stmt->conn, &fob, 1);
    if (st == SEER_OK)
      st = seer_ttc_recv(stmt->conn, &resp, &rlen);
    if (st != SEER_OK)
      return st;
    oer = (OerResult){0};
    st = parse_response(stmt, resp, rlen, false, &oer);
    free(resp);
    resp = NULL;
    if (st != SEER_OK)
      return st;
  }

  seer_log(SEER_LOG_DEBUG, "stmt: exec OER call_status=%ld err=%ld cursor=%ld rows=%zu",
           (long)oer.call_status, (long)oer.err_code, (long)oer.cursor_id, stmt->nrows);

  /* ORA-24381 is the non-fatal "error(s) in array DML" summary raised in
   * batcherrors mode: the per-row failures are in stmt->berrs and the good
   * rows applied, so the execute itself succeeded. */
  bool batch_summary = (oer.err_code == 24381 && stmt->nberrs > 0);
  if (oer.err_code != 0 && oer.err_code != 1403 && !batch_summary) {
    /* A reused cached cursor can be invalidated server-side (e.g. DDL
     * recreated the referenced object -> ORA-00942). Drop the stale cursor
     * and its describe and retry once with a full parse before surfacing -
     * for an error that says the cursor is stale, and no other: retried on
     * any, a deadlock or lock wait waited twice, and a call stopped by a
     * cancel or the call timeout ran again (#209, #210). */
    if (was_reuse && stale_cursor_error(oer.err_code)) {
      was_reuse = false;
      queue_cursor_close(stmt->conn, stmt->reuse_cursor); /* the stale cursor */
      stmt->reuse_cursor = 0;
      free_columns(stmt->cols, stmt->ncols);
      stmt->cols = NULL;
      stmt->ncols = 0;
      free_rows(stmt);
      free_pending_lobs(stmt);
      free_pending_objs(stmt);
      stmt->cursor_id = 0;
      goto retry_exec;
    }
    /* ORA-01000 (alone, or under ORA-00604 when recursive SQL hit it) while
     * the statement cache holds parsed cursors: those are the
     * driver's, unseen by the application, and on a server with a small
     * open_cursors (10g's default is 50) they can be what tips it over.
     * Queue them closed - the retry's request carries the closes ahead of
     * the parse - and run the statement once more. The failed call was
     * rolled back by the server, so the retry repeats no transactional work
     * (#337). */
    bool open_cursors =
        oer.err_code == 1000 || (oer.err_code == 604 && stmt->conn->last_error != NULL &&
                                 strstr(stmt->conn->last_error, "ORA-01000") != NULL);
    if (open_cursors && stmt->conn->stmt_cache_n > 0 && !retried_open_cursors) {
      retried_open_cursors = true;
      seer_log(SEER_LOG_DEBUG, "stmt: ORA-01000 with %d cached cursors: closing them, retrying",
               stmt->conn->stmt_cache_n);
      stmt_cache_flush(stmt->conn);
      queue_cursor_close(stmt->conn, oer.cursor_id);
      if (was_reuse) {
        was_reuse = false;
        queue_cursor_close(stmt->conn, stmt->reuse_cursor);
        stmt->reuse_cursor = 0;
        free_columns(stmt->cols, stmt->ncols);
        stmt->cols = NULL;
        stmt->ncols = 0;
      }
      free_rows(stmt);
      free_pending_lobs(stmt);
      free_pending_objs(stmt);
      stmt->cursor_id = 0;
      goto retry_exec;
    }
    /* A failed statement still holds a server cursor; close it, or every
     * error leaks one until the session hits ORA-01000. */
    queue_cursor_close(stmt->conn, oer.cursor_id);
    stmt->cursor_id = 0;
    stmt->conn->last_error_offset = (long)oer.err_offset;
    seer_log(SEER_LOG_DEBUG, "stmt: execute failed (ORA-%05ld)", (long)oer.err_code);
    return SEER_EDB;
  }
  stmt->cursor_id = (int)oer.cursor_id;
  stmt->affected = (long)oer.row_count;
  /* A CREATE of a PL/SQL object that compiled with errors SUCCEEDS (error 0):
   * only warn_flags bit 0x20 tells (seerdb/seerdb@6cc60d3). */
  stmt->compile_warning = (oer.warn_flags & 0x20) != 0;

  /* A DDL (non-cacheable) statement can invalidate other cached cursors; drop
   * the cache so none is reused stale after an object is recreated. A PL/SQL
   * block can run DDL too (EXECUTE IMMEDIATE), so it flushes the same way. */
  if (!sql_is_cacheable(stmt->sql) || classify_sql(stmt->sql) == STMT_BLOCK)
    stmt_cache_flush(stmt->conn);

  /* Fetch more while the cursor has rows pending. */
  while (more_rows_pending(stmt, oer.cursor_id, oer.err_code)) {
    seer_log(SEER_LOG_DEBUG, "stmt: issuing FETCH on cursor %ld", (long)oer.cursor_id);
    st = build_next_fetch(stmt, &w);
    if (st != SEER_OK)
      return st;
    st = seer_ttc_send(stmt->conn, w.buf, w.len);
    seer_writer_free(&w);
    if (st != SEER_OK)
      return st;
    st = seer_ttc_recv(stmt->conn, &resp, &rlen);
    if (st != SEER_OK)
      return st;
    OerResult more = {0};
    st = parse_response(stmt, resp, rlen, false, &more);
    free(resp);
    if (st != SEER_OK)
      return st;
    if (more.err_code != 0 && more.err_code != 1403) {
      seer_log(SEER_LOG_DEBUG, "stmt: fetch failed (ORA-%05ld)", (long)more.err_code);
      return SEER_EDB;
    }
    oer.err_code = more.err_code;
  }

  /* A REF CURSOR OUT bind: adopt the nested cursor's describe as this
   * statement's result set and drain its rows. */
  if (stmt->refcursor_present) {
    /* The block keeps its own cursor (closed or cached with the statement);
     * the REF CURSOR is drained here and then closed. Left in cursor_id, the
     * block's cursor was never closed: one per block, ORA-01000 (#198). */
    int64_t block_cursor = stmt->cursor_id;
    stmt->cols = stmt->refcursor_cols;
    stmt->ncols = stmt->refcursor_ncols;
    stmt->refcursor_cols = NULL;
    stmt->cursor_id = stmt->refcursor_id;
    stmt->fetch_by_oall8 = true;
    seer_log(SEER_LOG_DEBUG, "stmt: draining REF CURSOR %d (%d columns)", stmt->refcursor_id,
             stmt->ncols);
    st = fetch_all_rows(stmt);
    queue_cursor_close(stmt->conn, stmt->refcursor_id);
    stmt->refcursor_present = false;
    stmt->cursor_id = block_cursor;
    stmt->fetch_by_oall8 = false;
    stmt->cols_adopted = true;
    if (st != SEER_OK)
      return st;
  }

  /* The cursor is drained; now fetch the content of any LOB cells, then decode
   * any SQL OBJECT cells (the latter may run dictionary queries). */
  resolve_pending_lobs(stmt);
  resolve_pending_objs(stmt);

  stmt->executed = true;
  stmt->cur = -1;
  seer_log(SEER_LOG_DEBUG, "stmt: executed (%d columns, %zu rows%s)", stmt->ncols, stmt->nrows,
           stmt->nplobs ? ", LOBs resolved" : "");
  return SEER_OK;
}

/* Pipelining (§32/#158): set a fetch op's prefetch so its rows arrive inline in
 * the burst response (the burst can't interleave follow-up TTI_FETCH calls). */
void seer_stmt_set_prefetch(SeerStmt *stmt, uint32_t rows)
{
  if (stmt != NULL)
    stmt->prefetch = rows;
}

/* Run an eligible pipeline as one token-tagged round trip (§32/#158). Each stmt
 * is freshly prepared + configured by the caller. Build every op's execute (token
 * 1..n), send the burst (begin piggyback + ops + end message), then read and
 * parse the n token-tagged responses back-to-back into the stmts, plus the
 * end-pipeline terminating response (discarded). ora_codes[i] gets op i's server
 * error (0 = success; -1 = a response that failed to decode). Returns SEER_OK
 * once the wire burst completes; a wire-level send/recv failure aborts it (the
 * connection may then be unusable). */
SeerStatus seer_stmt_pipeline_burst(SeerConn *c, SeerStmt **stmts, size_t n, long *ora_codes)
{
  if (c == NULL || stmts == NULL || ora_codes == NULL || n == 0)
    return SEER_EPARAM;

  SeerWriter *msgs = calloc(n, sizeof *msgs);
  if (msgs == NULL)
    return SEER_ENOMEM;
  size_t built = 0;
  SeerStatus st = SEER_OK;

  /* Phase 1: the begin piggyback + each op's execute (token 1..n, fresh parse). */
  SeerWriter begin;
  if (!seer_writer_init(&begin, 16)) {
    free(msgs);
    return SEER_ENOMEM;
  }
  seer_ttc_pipeline_begin(c, &begin, 1, TNS_PIPELINE_MODE_CONTINUE);

  for (size_t i = 0; i < n; i++) {
    stmts[i]->reuse_cursor = 0; /* pipelined ops never cache-reuse */
    c->pipeline_token = (uint32_t)(i + 1);
    BindExpansion x; /* one value per occurrence, as seer_stmt_execute (#302) */
    st = expand_binds(stmts[i], &x);
    if (st == SEER_OK)
      st = build_exec(stmts[i], &msgs[i]);
    restore_binds(stmts[i], &x);
    c->pipeline_token = 0;
    if (st != SEER_OK)
      goto cleanup;
    built = i + 1;
  }

  SeerWriter end;
  if (!seer_writer_init(&end, 16)) {
    st = SEER_ENOMEM;
    goto cleanup;
  }
  seer_ttc_pipeline_end(c, &end);

  /* Phase 2: send. First packet = begin ++ op 1 (BEGIN_PIPELINE|END_OF_REQUEST);
   * ops 2..n each END_OF_REQUEST; then the ordinary end-pipeline message. */
  SeerWriter first;
  if (!seer_writer_init(&first, begin.len + msgs[0].len)) {
    seer_writer_free(&end);
    st = SEER_ENOMEM;
    goto cleanup;
  }
  seer_writer_bytes(&first, begin.buf, begin.len);
  seer_writer_bytes(&first, msgs[0].buf, msgs[0].len);
  st = seer_writer_ok(&first)
           ? seer_ttc_send_pipeline_op(c, first.buf, first.len, TNS_DATA_FLAGS_END_OF_REQUEST,
                                       TNS_DATA_FLAGS_BEGIN_PIPELINE)
           : SEER_ENOMEM;
  seer_writer_free(&first);
  for (size_t i = 1; i < n && st == SEER_OK; i++)
    st = seer_ttc_send_pipeline_op(c, msgs[i].buf, msgs[i].len, TNS_DATA_FLAGS_END_OF_REQUEST, 0);
  if (st == SEER_OK)
    st = seer_ttc_send(c, end.buf, end.len); /* ordinary send (data flags 0) */
  seer_writer_free(&end);
  if (st != SEER_OK)
    goto cleanup;

  /* Phase 3: read + parse each op's response (no resolve calls yet — the line
   * still holds the queued responses). A decode failure is per-op; keep reading
   * so the stream stays in sync. A wire recv failure aborts the whole burst. */
  for (size_t i = 0; i < n; i++) {
    uint8_t *resp = NULL;
    size_t rlen = 0;
    st = seer_ttc_recv_pipeline(c, &resp, &rlen);
    if (st != SEER_OK)
      goto cleanup;
    OerResult oer = {0};
    SeerStatus pst = parse_response(stmts[i], resp, rlen, /*expect_dcb=*/true, &oer);
    free(resp);
    if (pst != SEER_OK) {
      ora_codes[i] = -1;
      continue;
    }
    stmts[i]->cursor_id = (int)oer.cursor_id;
    stmts[i]->affected = (long)oer.row_count;
    stmts[i]->executed = true;
    stmts[i]->cur = -1;
    ora_codes[i] = (oer.err_code == 1403) ? 0 : (long)oer.err_code;
  }
  /* The end-pipeline message draws its own terminating response after the n op
   * responses; read and discard it so the next call is not left reading it. */
  {
    uint8_t *er = NULL;
    size_t el = 0;
    if (seer_ttc_recv_pipeline(c, &er, &el) == SEER_OK)
      free(er);
  }

  /* Phase 4: the line is clean now — resolve any LOB/object cells (these issue
   * their own calls) for every successful op. */
  for (size_t i = 0; i < n; i++) {
    if (ora_codes[i] == 0) {
      resolve_pending_lobs(stmts[i]);
      resolve_pending_objs(stmts[i]);
    }
  }

cleanup:
  seer_writer_free(&begin);
  for (size_t i = 0; i < built; i++)
    seer_writer_free(&msgs[i]);
  free(msgs);
  return st;
}

SeerStatus seer_stmt_next_result(SeerStmt *stmt)
{
  if (stmt == NULL)
    return SEER_EPARAM;
  if (stmt->implicit_pos >= stmt->nimplicit)
    return SEER_ENODATA;
  SeerImplicitResult *ir = &stmt->implicit[stmt->implicit_pos++];

  /* Drop the current result set's rows/LOBs/columns and adopt this implicit
   * cursor's describe; then drain its rows (and resolve any LOBs in them). */
  free_rows(stmt);
  free_pending_lobs(stmt);
  free_pending_objs(stmt);
  free_columns(stmt->cols, stmt->ncols);
  stmt->cols = ir->cols;
  stmt->ncols = ir->ncols;
  ir->cols = NULL; /* moved out; close won't double-free */
  ir->ncols = 0;
  stmt->cursor_id = ir->cursor_id;
  stmt->fetch_by_oall8 = true;

  SeerStatus st = fetch_all_rows(stmt);
  if (st != SEER_OK)
    return st;
  resolve_pending_lobs(stmt);
  resolve_pending_objs(stmt);
  stmt->executed = true;
  stmt->cur = -1;
  seer_log(SEER_LOG_DEBUG, "stmt: implicit result set now current (%d cols, %zu rows)", stmt->ncols,
           stmt->nrows);
  return SEER_OK;
}

SeerStatus seer_stmt_fetch(SeerStmt *stmt)
{
  if (stmt == NULL)
    return SEER_EPARAM;
  if (!stmt->executed)
    return SEER_EPROTO;
  if (stmt->cur + 1 >= (long)stmt->nrows)
    return SEER_ENODATA;
  stmt->cur++;
  return SEER_OK;
}

SeerStatus seer_stmt_set_row(SeerStmt *stmt, long row)
{
  if (stmt == NULL)
    return SEER_EPARAM;
  if (!stmt->executed)
    return SEER_EPROTO;
  if (row < 0 || (size_t)row >= stmt->nrows)
    return SEER_ENODATA;
  stmt->cur = row;
  return SEER_OK;
}

void seer_stmt_close(SeerStmt *stmt)
{
  if (stmt == NULL)
    return;
  for (size_t r = 0; r < stmt->nrows; r++) {
    for (int c = 0; c < stmt->ncols; c++)
      free(stmt->rows[r][c].data);
    free(stmt->rows[r]);
  }
  free(stmt->rows);
  for (size_t i = 0; i < stmt->ncell_errs; i++) /* the cells' errors (#158) */
    free(stmt->cell_errs[i].message);
  free(stmt->cell_errs);
  /* Keep this statement's parsed server cursor open in the statement cache,
   * keyed by its SQL, so re-preparing the same SQL re-executes it without a
   * re-parse. The describe columns move with it. (A full cache evicts + closes
   * its oldest cursor.) Done after the rows are freed - that loop needs ncols. */
  SeerConn *c = stmt->conn;
  /* A statement closed before it executed may still hold a parsed cursor - taken
   * taken from the statement cache at prepare - which goes back the same way
   * (it used to be dropped without a close, leaking the server cursor). */
  int keep_cursor = stmt->cursor_id > 0 ? stmt->cursor_id : stmt->reuse_cursor;
  if (c != NULL && c->authenticated && keep_cursor > 0 && stmt->sql != NULL) {
    if (sql_is_cacheable(stmt->sql)) {
      /* The bind types the cursor was last parsed or run with: this
       * execute's, or - closed unexecuted - those it came from the cache with. */
      char *binds = stmt->cursor_id > 0 ? bind_signature(stmt) : stmt->reuse_binds;
      if (binds == stmt->reuse_binds)
        stmt->reuse_binds = NULL;
      if (stmt->cols_adopted) { /* a block: it describes no columns of its own */
        stmt_cache_put(c, stmt->sql, keep_cursor, NULL, 0, binds);
      } else {
        stmt_cache_put(c, stmt->sql, keep_cursor, stmt->cols, stmt->ncols, binds);
        stmt->cols = NULL; /* moved to the cache; don't free */
        stmt->ncols = 0;
      }
    } else if (c->n_close < (int)(sizeof c->close_cursors / sizeof c->close_cursors[0])) {
      c->close_cursors[c->n_close++] = keep_cursor; /* DDL etc: just close */
    }
  }
  free_columns(stmt->cols, stmt->ncols);
  if (stmt->refcursor_cols != NULL) /* captured but never drained */
    free_columns(stmt->refcursor_cols, stmt->refcursor_ncols);
  free_binds(stmt);
  for (size_t k = 0; k < stmt->nplobs; k++)
    free(stmt->plobs[k].locator);
  free(stmt->plobs);
  for (size_t k = 0; k < stmt->npobjs; k++)
    free(stmt->pobjs[k].image);
  free(stmt->pobjs);
  free_batch_errors(stmt);
  free_implicit(stmt);
  free(stmt->dml_rowcounts);
  free(stmt->sql);
  free(stmt->reuse_binds);
  free(stmt);
}

int seer_stmt_num_cols(SeerStmt *stmt)
{
  return stmt ? stmt->ncols : 0;
}

const char *seer_stmt_col_name(SeerStmt *stmt, int col)
{
  if (stmt == NULL || col < 0 || col >= stmt->ncols)
    return NULL;
  return stmt->cols[col].name;
}

const char *seer_stmt_col_annotations(SeerStmt *stmt, int col)
{
  if (stmt == NULL || col < 0 || col >= stmt->ncols)
    return NULL;
  return stmt->cols[col].annotations;
}

int seer_stmt_col_type(SeerStmt *stmt, int col)
{
  if (stmt == NULL || col < 0 || col >= stmt->ncols)
    return -1;
  return stmt->cols[col].ora_type;
}

int seer_stmt_col_size(SeerStmt *stmt, int col)
{
  if (stmt == NULL || col < 0 || col >= stmt->ncols)
    return 0;
  return (int)stmt->cols[col].char_size;
}

int seer_stmt_col_octets(SeerStmt *stmt, int col)
{
  if (stmt == NULL || col < 0 || col >= stmt->ncols)
    return 0;
  return (int)stmt->cols[col].byte_size;
}

int seer_stmt_col_precision(SeerStmt *stmt, int col)
{
  if (stmt == NULL || col < 0 || col >= stmt->ncols)
    return 0;
  return stmt->cols[col].precision;
}

int seer_stmt_col_scale(SeerStmt *stmt, int col)
{
  if (stmt == NULL || col < 0 || col >= stmt->ncols)
    return 0;
  return stmt->cols[col].scale;
}

int seer_stmt_col_nullable(SeerStmt *stmt, int col)
{
  if (stmt == NULL || col < 0 || col >= stmt->ncols)
    return 1;
  return stmt->cols[col].null_ok;
}

long seer_stmt_row_count(SeerStmt *stmt)
{
  if (stmt == NULL)
    return 0;
  /* A result set reports its row count; DML reports affected rows. */
  return stmt->ncols > 0 ? (long)stmt->nrows : stmt->affected;
}

/* Keep the error the server gave for this cell's content - the connection's
 * last error - so reading the cell returns it, as Oracle's clients report a
 * BFILE that can't be opened when they read it, not when the row is fetched
 * (#158). The cell stays NULL; the query and the other cells go on. */
static void record_cell_error(SeerStmt *stmt, size_t row, int col)
{
  SeerConn *c = stmt->conn;
  void *n = realloc(stmt->cell_errs, (stmt->ncell_errs + 1) * sizeof *stmt->cell_errs);
  if (n == NULL)
    return;
  stmt->cell_errs = n;
  stmt->cell_errs[stmt->ncell_errs].row = row;
  stmt->cell_errs[stmt->ncell_errs].col = col;
  stmt->cell_errs[stmt->ncell_errs].message =
      strdup(c->last_error != NULL ? c->last_error : "the server refused the value");
  stmt->ncell_errs++;
  free(c->last_error);
  c->last_error = NULL; /* the query itself succeeded */
}

/* The minutes from DBTIMEZONE to SESSIONTIMEZONE, read with one query the
 * first time a session needs them and kept (#358): a TIMESTAMP WITH LOCAL
 * TIME ZONE value arrives in the database's zone, and OCI moves it to the
 * session's on the client - nothing on the wire says either zone, and no
 * define makes the server do it (seerdb, bus 100 / 103). Only numeric offsets
 * convert exactly: a region on either side needs its daylight-saving rules,
 * which the wire doesn't carry, so the value is then left as it came. */
static bool ltz_shift(SeerConn *conn, int *minutes)
{
  if (conn->ltz_state == 0) {
    conn->ltz_state = -1;
    SeerStmt *q = NULL;
    const char *db = NULL, *ses = NULL;
    int null1 = 1, null2 = 1, dbm = 0, sesm = 0;
    if (seer_stmt_prepare(conn, "SELECT DBTIMEZONE, SESSIONTIMEZONE FROM dual", &q) == SEER_OK &&
        seer_stmt_execute(q) == SEER_OK && seer_stmt_fetch(q) == SEER_OK &&
        seer_stmt_get_string(q, 0, &db, &null1) == SEER_OK &&
        seer_stmt_get_string(q, 1, &ses, &null2) == SEER_OK && !null1 && !null2) {
      if (seer_parse_offset(db, &dbm) && seer_parse_offset(ses, &sesm)) {
        conn->ltz_state = 1;
        conn->ltz_shift_min = sesm - dbm;
      } else {
        seer_log(SEER_LOG_WARNING,
                 "LOCAL TIME ZONE values stay in DBTIMEZONE (%s), not moved to the session "
                 "zone %s: a region's daylight-saving rules are not on the wire",
                 db, ses);
      }
    } else {
      seer_log(SEER_LOG_WARNING, "LOCAL TIME ZONE values stay in DBTIMEZONE: the zones "
                                 "couldn't be read");
    }
    seer_stmt_close(q);
  }
  *minutes = conn->ltz_shift_min;
  return conn->ltz_state == 1;
}

static void ltz_shift_cell(SeerConn *conn, SeerCell *cell)
{
  cell->shifted = true;
  int m = 0;
  char buf[64];
  if (!ltz_shift(conn, &m) || m == 0 ||
      seer_shift_datetime_text(cell->data, m, buf, sizeof buf) != SEER_OK)
    return;
  char *t = strdup(buf);
  if (t == NULL)
    return;
  free(cell->data);
  cell->data = t;
  cell->len = strlen(t);
}

SeerStatus seer_stmt_get_data(SeerStmt *stmt, int col, const void **data, size_t *len, int *is_null,
                              int *is_binary)
{
  if (stmt == NULL || data == NULL || len == NULL || is_null == NULL)
    return SEER_EPARAM;
  *data = NULL;
  *len = 0;
  *is_null = 1;
  if (is_binary != NULL)
    *is_binary = 0;
  if (col < 0 || col >= stmt->ncols)
    return SEER_EPARAM;
  if (stmt->cur < 0 || (size_t)stmt->cur >= stmt->nrows)
    return SEER_EPROTO;

  for (size_t i = 0; i < stmt->ncell_errs; i++)
    if (stmt->cell_errs[i].row == (size_t)stmt->cur && stmt->cell_errs[i].col == col) {
      free(stmt->conn->last_error);
      stmt->conn->last_error =
          stmt->cell_errs[i].message ? strdup(stmt->cell_errs[i].message) : NULL;
      return SEER_EDB;
    }

  SeerCell *cell = &stmt->rows[stmt->cur][col];
  if (cell->data != NULL && !cell->shifted && stmt->cols[col].ora_type == ORA_TYPE_TIMESTAMPLTZ)
    ltz_shift_cell(stmt->conn, cell);
  if (cell->data != NULL) {
    *data = cell->data;
    *len = cell->len;
    *is_null = 0;
    if (is_binary != NULL)
      *is_binary = cell->binary;
  }
  return SEER_OK;
}

SeerStatus seer_stmt_get_string(SeerStmt *stmt, int col, const char **value, int *is_null)
{
  const void *data = NULL;
  size_t len = 0;
  SeerStatus st = seer_stmt_get_data(stmt, col, &data, &len, is_null, NULL);
  if (value != NULL)
    *value = (const char *)data;
  return st;
}

SeerStatus seer_stmt_out_data(SeerStmt *stmt, int param, const void **data, size_t *len,
                              int *is_null, int *is_binary)
{
  if (stmt == NULL || data == NULL || len == NULL || is_null == NULL)
    return SEER_EPARAM;
  *data = NULL;
  *len = 0;
  *is_null = 1;
  if (is_binary != NULL)
    *is_binary = 0;
  if (param < 1 || param > stmt->npbinds || !stmt->pbinds[param - 1].is_out)
    return SEER_EPARAM;

  SeerCell *c = &stmt->pbinds[param - 1].out;
  if (c->data != NULL) {
    *data = c->data;
    *len = c->len;
    *is_null = 0;
    if (is_binary != NULL)
      *is_binary = c->binary;
  }
  return SEER_OK;
}

/* ----------------------------------------------- SQL OBJECT (ADT) bind encode */

/* 4-byte big-endian length, as used inside an object image (NOT the variable
 * sb4 form the surrounding bind framing uses). */
static void obj_be4(SeerWriter *w, uint32_t v)
{
  seer_writer_u8(w, (uint8_t)(v >> 24));
  seer_writer_u8(w, (uint8_t)(v >> 16));
  seer_writer_u8(w, (uint8_t)(v >> 8));
  seer_writer_u8(w, (uint8_t)v);
}

/* An object-image length prefix: one byte for <= 245, else 0xFE + a 4-byte BE
 * length (oracledb DbObjectPickleBuffer.write_length). */
static void obj_write_length(SeerWriter *w, uint32_t n)
{
  if (n <= 245) {
    seer_writer_u8(w, (uint8_t)n);
  } else {
    seer_writer_u8(w, 0xFE);
    obj_be4(w, n);
  }
}

/* Append `data` length-framed as oracledb write_bytes_with_length (the 12c+ form
 * of encode_chr): <ub1 len> inline up to 252, else 0xFE + sb4 chunks. */
static SeerStatus obj_append_chr(SeerWriter *w, const uint8_t *data, size_t n, uint8_t fv)
{
  SeerChrMsg m = {.value = {.p = data, .n = n}};
  SeerSchemaCtx cx = seer_msg_ctx(0, fv, fv);
  seer_schema_encode(SEER_CHR_SCHEMA, &cx, &m, w);
  return seer_writer_ok(w) ? SEER_OK : SEER_ENOMEM;
}

/* Look up an object type's 16-byte OID (ALL_TYPES) and its ordered attribute
 * wire-types (ALL_TYPE_ATTRS). Caller owns *types. */
/* Look up an object/collection type's 16-byte OID (ALL_TYPES). */
static SeerStatus obj_lookup_oid(SeerConn *conn, const char *schema, const char *name,
                                 uint8_t oid[16])
{
  SeerStmt *q = NULL;
  bool got = false;
  if (type_dict_query(conn,
                      "SELECT type_oid FROM all_types "
                      "WHERE owner = :1 AND type_name = :2",
                      "SELECT type_oid FROM all_plsql_types "
                      "WHERE owner = :1 AND package_name = :2 AND type_name = :3",
                      schema, name, &q) == SEER_OK &&
      seer_stmt_fetch(q) == SEER_OK) {
    const void *d = NULL;
    size_t dl = 0;
    int isnull = 0, isbin = 0;
    if (seer_stmt_get_data(q, 0, &d, &dl, &isnull, &isbin) == SEER_OK && d != NULL && dl == 16) {
      memcpy(oid, d, 16);
      got = true;
    }
  }
  seer_stmt_close(q);
  return got ? SEER_OK : SEER_EDB; /* not found / not RAW(16) */
}

/* A collection type's single element wire-type (ALL_COLL_TYPES, or
 * ALL_PLSQL_COLL_TYPES for PKG.TYPE), and whether it is a PL/SQL index-by
 * table - whose image keys every element (§21.6b). */
static SeerStatus obj_lookup_elem(SeerConn *conn, const char *schema, const char *name,
                                  uint8_t *elem_type, bool *index_table)
{
  SeerStmt *q = NULL;
  bool got = false;
  *index_table = false;
  if (type_dict_query(conn,
                      "SELECT elem_type_name, coll_type, character_set_name FROM all_coll_types "
                      "WHERE owner = :1 AND type_name = :2",
                      "SELECT elem_type_name, coll_type, character_set_name "
                      "FROM all_plsql_coll_types "
                      "WHERE owner = :1 AND package_name = :2 AND type_name = :3",
                      schema, name, &q) == SEER_OK &&
      seer_stmt_fetch(q) == SEER_OK) {
    const char *tn = NULL, *kind = NULL, *cs = NULL;
    int isnull = 0, isn_cs = 0;
    seer_stmt_get_string(q, 0, &tn, &isnull);
    seer_stmt_get_string(q, 2, &cs, &isn_cs);
    *elem_type = obj_attr_type(tn, isn_cs ? NULL : cs);
    seer_stmt_get_string(q, 1, &kind, &isnull);
    *index_table = !isnull && kind != NULL && strcmp(kind, "PL/SQL INDEX TABLE") == 0;
    got = true;
  }
  seer_stmt_close(q);
  return got ? SEER_OK : SEER_EDB;
}

/* The explicit UTC offset at the end of a datetime text, in minutes: "+HH:MM",
 * "-HH:MM", "+HHMM" or "Z". false when the text carries none - a WITH TIME
 * ZONE value is then refused, never given a zone the caller did not state. */
static bool parse_utc_offset(const char *val, int *minutes)
{
  const char *p = val + strlen(val);
  while (p > val && p[-1] == ' ')
    p--;
  if (p > val && (p[-1] == 'Z' || p[-1] == 'z')) {
    *minutes = 0;
    return true;
  }
  /* back up over the offset's digits and an optional ':' to its sign */
  const char *e = p;
  while (p > val && (isdigit((unsigned char)p[-1]) || p[-1] == ':'))
    p--;
  if (p == val || (p[-1] != '+' && p[-1] != '-') || p - 1 == val || p[-2] != ' ')
    return false; /* not a sign standing alone after the time ("2020-01-01" has '-' too) */
  int hh = 0, mm = 0;
  char digits[8] = "";
  size_t nd = 0;
  for (const char *q = p; q < e && nd < sizeof digits - 1; q++)
    if (isdigit((unsigned char)*q))
      digits[nd++] = *q;
  if (nd == 4) {
    hh = (digits[0] - '0') * 10 + (digits[1] - '0');
    mm = (digits[2] - '0') * 10 + (digits[3] - '0');
  } else if (nd == 2 || nd == 1) {
    hh = atoi(digits);
  } else {
    return false;
  }
  if (hh > 14 || mm > 59)
    return false;
  *minutes = (p[-1] == '-' ? -1 : 1) * (hh * 60 + mm);
  return true;
}

/* Encode one image field (object attribute or collection element) from text:
 * 0xFF for NULL, else <length><raw scalar bytes> by Oracle type - NUMBER as an
 * exact base-100 decimal, DATE/TIMESTAMP from "YYYY-MM-DD[ HH:MM:SS[.fff]]", and
 * everything else as UTF-8 text. A temporal field takes its width from its
 * type, as a declared bind does (seerdb PROTOCOL.md §21, faa08ee): DATE 7
 * bytes; TIMESTAMP and LTZ 11, or 7 when the fraction is zero; WITH TIME ZONE
 * always 13 - the UTC instant, then the offset's hour + 20 and minute + 60 -
 * from a value that states its offset (" +02:00", " -0530", "Z"). One that
 * does not is SEER_EPARAM. */
static SeerStatus obj_encode_field(SeerWriter *body, uint8_t ora_type, const char *val)
{
  if (val == NULL) {
    seer_writer_u8(body, 0xFF);
    return SEER_OK;
  }
  if (ora_type == ORA_TYPE_BINARY_INTEGER || ora_type == ORA_TYPE_BOOLEAN) {
    /* PLS_INTEGER / BOOLEAN of a PL/SQL record: a 4-byte big-endian integer
     * (a BOOLEAN is 1 / 0, from "1"/"TRUE" or "0"/"FALSE"). */
    long long v = atoll(val);
    if (ora_type == ORA_TYPE_BOOLEAN)
      v = (strcasecmp(val, "TRUE") == 0 || v != 0) ? 1 : 0;
    obj_write_length(body, 4);
    if (ora_type == ORA_TYPE_BOOLEAN) { /* as the server writes one: 01 00 00 00 */
      seer_writer_u8(body, (uint8_t)v);
      for (int k = 0; k < 3; k++)
        seer_writer_u8(body, 0);
    } else {
      obj_be4(body, (uint32_t)(int32_t)v);
    }
  } else if (ora_type == ORA_TYPE_NUMBER) {
    uint8_t num[24];
    size_t nn = seer_encode_number_str(val, num);
    if (nn == 0) /* not a decimal: fall back to integer */
      nn = seer_encode_number_int(atoll(val), num);
    obj_write_length(body, (uint32_t)nn);
    seer_writer_bytes(body, num, nn);
  } else if (ora_type == ORA_TYPE_DATE || ora_type == ORA_TYPE_TIMESTAMP ||
             ora_type == ORA_TYPE_TIMESTAMPLTZ || ora_type == ORA_TYPE_TIMESTAMPTZ) {
    int y = 1, mo = 1, d = 1, h = 0, mi = 0, s = 0;
    double frac = 0.0;
    sscanf(val, "%d-%d-%d %d:%d:%lf", &y, &mo, &d, &h, &mi, &frac);
    s = (int)frac;
    uint32_t nanos = ora_type == ORA_TYPE_DATE ? 0 : (uint32_t)((frac - (double)s) * 1e9 + 0.5);
    int off = 0;
    if (ora_type == ORA_TYPE_TIMESTAMPTZ) {
      if (!parse_utc_offset(val, &off)) {
        seer_log(SEER_LOG_WARNING, "obj: a TIMESTAMP WITH TIME ZONE value needs its UTC offset "
                                   "(e.g. \"2020-01-01 10:00:00 +02:00\")");
        return SEER_EPARAM;
      }
      /* the wire carries the UTC instant: shift the wall clock back by the offset */
      int64_t mins = (seer_days_from_civil(y, mo, d) * 24 + h) * 60 + mi - off;
      int64_t days = mins >= 0 ? mins / 1440 : -((-mins + 1439) / 1440);
      int64_t rem = mins - days * 1440;
      seer_civil_from_days(days, &y, &mo, &d);
      h = (int)(rem / 60);
      mi = (int)(rem % 60);
    }
    uint8_t dt[13] = {
        (uint8_t)(y / 100 + 100),
        (uint8_t)(y % 100 + 100),
        (uint8_t)mo,
        (uint8_t)d,
        (uint8_t)(h + 1),
        (uint8_t)(mi + 1),
        (uint8_t)(s + 1),
        (uint8_t)(nanos >> 24),
        (uint8_t)(nanos >> 16),
        (uint8_t)(nanos >> 8),
        (uint8_t)nanos,
        (uint8_t)(off / 60 + 20), /* offset hour + 20 */
        (uint8_t)(off % 60 + 60), /* offset minute + 60 */
    };
    size_t n = 7;
    if (ora_type == ORA_TYPE_TIMESTAMPTZ)
      n = 13;
    else if (ora_type != ORA_TYPE_DATE && nanos != 0)
      n = 11;
    obj_write_length(body, (uint32_t)n);
    seer_writer_bytes(body, dt, n);
  } else if (ora_type == OBJ_ATTR_NCHAR) { /* national: AL16UTF16 (UTF-16BE) */
    char *u16 = NULL;
    size_t u16len = 0;
    size_t vl = strlen(val);
    if (vl > 0 && seer_iconv("UTF-8", "UTF-16BE", val, vl, &u16, &u16len) != 0)
      return SEER_EPARAM; /* not valid UTF-8 */
    obj_write_length(body, (uint32_t)u16len);
    seer_writer_bytes(body, (const uint8_t *)u16, u16len);
    free(u16);
  } else { /* char (and best-effort default): UTF-8 */
    size_t vl = strlen(val);
    obj_write_length(body, (uint32_t)vl);
    seer_writer_bytes(body, (const uint8_t *)val, vl);
  }
  return SEER_OK;
}

/* An object value's frame, written by SEER_OBJECT_SCHEMA (#398): the type
 * block `tb` (36 bytes, or none on 9i), an empty object OID, a zero snapshot
 * and version, the image's length, the TOP_LEVEL flag and the image. */
static SeerStatus obj_frame_write(SeerWriter *bv, const SeerSchemaCtx *cx, const uint8_t *tb,
                                  size_t tblen, const uint8_t *img, size_t imglen)
{
  SeerObjectMsg m = {.type_oid = {.p = tb, .n = tblen},
                     .image_len = (int64_t)imglen,
                     .flags = 1, /* TOP_LEVEL */
                     .image = {.p = img, .n = imglen}};
  seer_schema_encode(SEER_OBJECT_SCHEMA, cx, &m, bv);
  return seer_writer_ok(bv) ? SEER_OK : SEER_ENOMEM;
}

/* The 36-byte type block an object value names its type by, on 10g+ and on
 * 8i (oracledb write_dbobject): 00 22 02 08, the 16-byte type OID, then the
 * extent OID - 16 bytes ending 00 01 00 01. */
static void obj_type_block(const uint8_t oid[16], uint8_t tb[36])
{
  static const uint8_t PFX[4] = {0x00, 0x22, 0x02, 0x08};
  static const uint8_t EXT[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1};
  memcpy(tb, PFX, 4);
  memcpy(tb + 4, oid, 16);
  memcpy(tb + 20, EXT, 16);
}

/* Object bind-value framing (oracledb write_dbobject), shared by SQL object
 * binds and AQ object payloads: the frame with the type block. */
static SeerStatus obj_encode_bind_value(SeerWriter *bv, const uint8_t oid[16], const uint8_t *img,
                                        size_t imglen, uint8_t fv)
{
  uint8_t tb[36];
  obj_type_block(oid, tb);
  SeerSchemaCtx cx = seer_msg_ctx(0, fv, fv);
  return obj_frame_write(bv, &cx, tb, sizeof tb, img, imglen);
}

/* The object frame of a NULL object of the type `oid`: the frame an object
 * value binds with, with a zero image gate and no image - what a pure OUT
 * object / collection bind sends (seerdb encode_object_column_value). */
static SeerStatus obj_encode_null_value(SeerWriter *bv, const uint8_t oid[16], uint8_t fv)
{
  return obj_encode_bind_value(bv, oid, NULL, 0, fv); /* image length 0: no image */
}

/* Store an object / collection bind of type (schema, type_name), OID `oid`:
 * the value is `img`'s image, or with `img` NULL the NULL-object frame of a
 * pure OUT bind (`is_out`). The OAC announces the image size, at least 2000 -
 * the size an object column describes with - so a value coming back has
 * room. The type is kept on the bind to decode a returned value. Takes
 * ownership of `img` (always frees it). */
static void o8w_le32(SeerWriter *w, uint32_t v);
static void o8w_chr(SeerWriter *w, const uint8_t *p, size_t n);

/* An object or collection bind's descriptor and value before 10g (seerdb
 * PROTOCOL.md §19.17c, #172), into oac / bv:
 * - 9i (ojdbc14 on 9.2.0.4): a scalar's descriptor with the type's OID and
 *   version - 6d 01 00 00, the size (the image's; 0x7FFFFFFF for a NULL or
 *   an OUT), 00 00, the OID as a value, version 1, charset 31, form 0. The
 *   value is the row cell's frame without the type block: the type-OID,
 *   object-OID, snapshot and version fields empty, the image's length, flags
 *   01 01 and the image; a NULL is 00 00 00 00 00 01 01.
 * - 8i (OCI 9.2 against 8.1.7): the same descriptor at 8i's widths, 42 bytes,
 *   size 2000. The value is the 8i row cell without its trailer: the 36-byte
 *   type block (00 22 02 08, the OID, 16 bytes ending 00 01 00 01), the
 *   object OID's and snapshot's lengths, version, image length, flags 01 00
 *   and the image; a NULL has a zero length and no image. */
static SeerStatus obj_legacy_bind(SeerConn *c, const uint8_t oid[16], const uint8_t *img,
                                  size_t imglen, bool is_out, SeerWriter *oac, SeerWriter *bv)
{
  SeerOacMsg m = {.data_type = ORA_TYPE_ADT,
                  .toid_length = 16,
                  .toid = {.p = oid, .n = 16},
                  .version = 1}; /* SEER_OAC_SCHEMA (#398) */
  if (c->is_8i) {
    m.max_length = 2000;
    oac_write(oac, true, 0, &m);

    /* The frame at 8i's widths, with 10g+'s type block (#398). */
    uint8_t tb[36];
    obj_type_block(oid, tb);
    SeerSchemaCtx cx = seer_msg_ctx(1, 0, 0);
    if (obj_frame_write(bv, &cx, tb, sizeof tb, img, imglen) != SEER_OK)
      return SEER_ENOMEM;
  } else {
    m.flags = 0x01;
    m.max_length = imglen > 0 && !is_out ? (int64_t)imglen : 0x7FFFFFFF;
    m.charset = 31;
    oac_write(oac, false, TTC_FIELD_VERSION_9_2, &m);

    /* The frame with no type block: the type is the descriptor's (#398). */
    SeerSchemaCtx cx = seer_msg_ctx(0, TTC_FIELD_VERSION_9_2, TTC_FIELD_VERSION_9_2);
    if (obj_frame_write(bv, &cx, NULL, 0, img, imglen) != SEER_OK)
      return SEER_ENOMEM;
  }
  return seer_writer_ok(oac) && seer_writer_ok(bv) ? SEER_OK : SEER_ENOMEM;
}

static SeerStatus obj_store_bind(SeerStmt *stmt, int param, const char *schema,
                                 const char *type_name, const uint8_t oid[16], SeerWriter *img,
                                 bool is_out)
{
  uint8_t fv = stmt->conn->field_version;
  size_t imglen = img != NULL ? img->len : 0;
  SeerStatus st = SEER_ENOMEM;
  SeerWriter empty = {0};
  if (img == NULL)
    img = &empty;

  SeerWriter bv, oac;
  if (!seer_writer_init(&bv, 64 + imglen)) {
    seer_writer_free(img);
    return SEER_ENOMEM;
  }
  if (fv < TTC_FIELD_VERSION_10_2) { /* 9i and 8i (#172) */
    if (!seer_writer_init(&oac, 64))
      goto fail;
    if (obj_legacy_bind(stmt->conn, oid, img->buf, imglen, is_out, &oac, &bv) != SEER_OK) {
      seer_writer_free(&oac);
      goto fail;
    }
    goto store;
  }
  if ((imglen > 0 ? obj_encode_bind_value(&bv, oid, img->buf, imglen, fv)
                  : obj_encode_null_value(&bv, oid, fv)) != SEER_OK)
    goto fail;

  if (!seer_writer_init(&oac, 64))
    goto fail;
  /* SEER_OAC_SCHEMA (#398): the buffer size, the type's OID and version 1.
   * No oaccolid before 12.2: 11g and 10g answer it with a fatal ORA-03106
   * (seerdb PROTOCOL.md, measured against JDBC thin 11.2, #172). */
  SeerOacMsg m = {.data_type = ORA_TYPE_ADT,
                  .flags = 1, /* USE_INDICATORS */
                  .max_length = (int64_t)(imglen > 2000 ? imglen : 2000),
                  .toid_length = 16,
                  .toid = {.p = oid, .n = 16},
                  .version = 1};
  oac_write(&oac, false, fv, &m);
  if (!seer_writer_ok(&oac)) {
    seer_writer_free(&oac);
    goto fail;
  }

store:
  seer_writer_free(img); /* image now copied into bv */
  SeerColumn *type = calloc(1, sizeof *type);
  if (type == NULL || (type->type_schema = strdup(schema)) == NULL ||
      (type->type_name = strdup(type_name)) == NULL) {
    free_columns(type, type ? 1 : 0);
    seer_writer_free(&oac);
    seer_writer_free(&bv);
    return SEER_ENOMEM;
  }
  type->n_obj_attrs = -1; /* layout resolved on first decode */
  st = store_bind(stmt, param, ORA_TYPE_ADT, (uint32_t)imglen, 0, 0, is_out, bv.buf, bv.len);
  if (st != SEER_OK) {
    free_columns(type, 1);
    seer_writer_free(&oac);
    return st;
  } /* store_bind freed bv.buf */
  SeerBind *b = &stmt->pbinds[param - 1];
  free(b->oac_override);
  b->oac_override = oac.buf; /* ownership transferred */
  b->oac_override_len = oac.len;
  free_columns(b->obj_type, b->obj_type ? 1 : 0);
  b->obj_type = type;
  return SEER_OK;

fail:
  seer_writer_free(img);
  seer_writer_free(&bv);
  return st;
}

/* Build the flattened object image for (schema, type_name) from text attribute
 * values: look up the type OID, fetch the *flattened* leaf-attribute layout (an
 * embedded object attribute is stored inline, its leaves spliced in depth-first,
 * one value per leaf), then emit the image header (0x84, version, 0xFE, BE4
 * total) + per-attribute fields. On SEER_OK fills oid[16] and the `img` writer
 * (caller frees img). Shared by SQL object binds and AQ object payloads. */
static SeerStatus obj_build_image(SeerConn *c, const char *schema, const char *type_name,
                                  const char *const *attr_values, int n_attrs, uint8_t oid[16],
                                  SeerWriter *img)
{
  SeerStatus st = obj_lookup_oid(c, schema, type_name, oid);
  if (st != SEER_OK)
    return st;
  uint8_t *types = NULL;
  int ntypes = 0, cap = 0;
  build_obj_layout(c, schema, type_name, &types, NULL, &ntypes, &cap, 0);
  if (n_attrs != ntypes) {
    free(types);
    return SEER_EPARAM;
  }
  /* A LOB or XMLType attribute needs a locator in the image (a temporary LOB
   * created and written first), not text - refuse rather than send a value
   * the server would reject or misread. */
  for (int i = 0; i < ntypes; i++)
    if (types[i] == ORA_TYPE_CLOB || types[i] == ORA_TYPE_BLOB || types[i] == OBJ_ATTR_XMLTYPE) {
      free(types);
      return SEER_ENOTIMPL;
    }

  SeerWriter body;
  if (!seer_writer_init(&body, 64)) {
    free(types);
    return SEER_ENOMEM;
  }
  for (int i = 0; i < n_attrs && st == SEER_OK; i++)
    st = obj_encode_field(&body, types[i], attr_values[i]);
  free(types);
  if (st != SEER_OK) {
    seer_writer_free(&body);
    return st;
  }
  if (!seer_writer_ok(&body)) {
    seer_writer_free(&body);
    return SEER_ENOMEM;
  }

  uint32_t total = 7 + (uint32_t)body.len;
  if (!seer_writer_init(img, total)) {
    seer_writer_free(&body);
    return SEER_ENOMEM;
  }
  seer_writer_u8(img, 0x84);
  seer_writer_u8(img, 0x01);
  seer_writer_u8(img, 0xFE);
  obj_be4(img, total);
  seer_writer_bytes(img, body.buf, body.len);
  seer_writer_free(&body);
  return seer_writer_ok(img) ? SEER_OK : SEER_ENOMEM;
}

SeerStatus seer_stmt_bind_object(SeerStmt *stmt, int param, const char *schema,
                                 const char *type_name, const char *const *attr_values, int n_attrs)
{
  if (stmt == NULL || schema == NULL || type_name == NULL || (n_attrs > 0 && attr_values == NULL))
    return SEER_EPARAM;

  uint8_t oid[16];
  SeerWriter img;
  SeerStatus st = obj_build_image(stmt->conn, schema, type_name, attr_values, n_attrs, oid, &img);
  if (st != SEER_OK)
    return st;
  return obj_store_bind(stmt, param, schema, type_name, oid, &img, false);
}

/* A REF bind (#241): the referenced type's OID in a descriptor of each
 * release's own (seerdb PROTOCOL.md §19.17c and bus 77 / 79), the REF bytes as
 * the value. 10g and 11g take the 12c+ form without its 12.2 oaccolid - JDBC
 * thin's (ojdbc6 11.2 on 10.2.0.5 and 11.2.0.2, bus 106). A NULL REF isn't sent
 * on any release (unfilled, 8.1.7 and 9.2 answer ORA-00600 [kokeermd1]). */
/* A REF OUT (#241, bus 85 / 86) takes the IN REF's descriptor - size 4000
 * on 9i, as for a NULL - and comes back as the REF's bytes: on 12c+ a value
 * and its ub4 return code (NULL: an empty value, return code -1); on 9i the
 * block's OUT cell. A pure OUT sends an empty value on 12c+ (JDBC thin) and
 * none on 9i, which prompts for INs only. 8i sends OCI's empty OCIRef,
 * `04 00 02 00 00` (bus 88), and reads back the REF as a value with no
 * indicator after it (bus 85). */
static SeerStatus ref_bind(SeerStmt *stmt, int param, const char *type_schema,
                           const char *type_name, const uint8_t *ref, size_t len, bool out)
{
  if (stmt == NULL || type_schema == NULL || type_name == NULL ||
      (!out && (ref == NULL || len == 0)) || len > 4000)
    return SEER_EPARAM;
  SeerConn *c = stmt->conn;
  uint8_t fv = c->field_version;
  bool o8i = c->is_8i, o9i = !o8i && fv < TTC_FIELD_VERSION_10_2;
  uint8_t oid[16];
  SeerStatus st = obj_lookup_oid(c, type_schema, type_name, oid);
  if (st != SEER_OK)
    return st;
  SeerWriter oac, v;
  if (!seer_writer_init(&oac, 64))
    return SEER_ENOMEM;
  if (!seer_writer_init(&v, len + 16)) {
    seer_writer_free(&oac);
    return SEER_ENOMEM;
  }
  /* Each path's descriptor is SEER_OAC_SCHEMA with the type's OID and
   * version 1 (#398). */
  SeerOacMsg m = {
      .data_type = ORA_TYPE_REF, .toid_length = 16, .toid = {.p = oid, .n = 16}, .version = 1};
  if (o8i) { /* OCIBindObject (SQLT_REF) on 8.1.7: the 8i object descriptor, type 111 */
    /* flag 0x01 on an OUT: an indicator comes back, so a NULL is -1, not
     * ORA-01405 (bus 91, #325) */
    m.flags = out ? 0x01 : 0x00;
    m.max_length = 2000;
    oac_write(&oac, true, 0, &m);
    if (out) {
      /* OCI's image of an empty OCIRef: body length 2, a 2-byte zero body
       * (bus 88, the same on 9.2 native). */
      static const uint8_t EMPTY_REF[4] = {0x00, 0x02, 0x00, 0x00};
      o8w_chr(&v, EMPTY_REF, sizeof EMPTY_REF);
    } else {
      o8w_chr(&v, ref, len);
    }
  } else if (o9i) { /* ojdbc14 9.0.2 on 9.2.0.4 */
    m.flags = 0x01;
    m.max_length = out ? 4000 : (int64_t)len;
    m.charset = 31;
    oac_write(&oac, false, TTC_FIELD_VERSION_9_2, &m);
    if (out)
      chr_write(&v, false, fv, NULL, 0); /* the empty value */
    else if (obj_append_chr(&v, ref, len, fv) != SEER_OK)
      st = SEER_ENOMEM;
  } else { /* 10g+, a JDBC thin capture (seerdb #139; 10g / 11g bus 106) */
    m.flags = 0x03;
    m.max_length = 4000;
    m.charset = 2;
    oac_write(&oac, false, fv, &m); /* oaccolid from 12.2; 12.1 refuses it (seerdb #1144) */
    if (out)
      chr_write(&v, false, fv, NULL, 0); /* an empty value, as JDBC sends */
    else if (st == SEER_OK && obj_append_chr(&v, ref, len, fv) != SEER_OK)
      st = SEER_ENOMEM;
  }
  if (st == SEER_OK && (!seer_writer_ok(&oac) || !seer_writer_ok(&v)))
    st = SEER_ENOMEM;
  if (st != SEER_OK) {
    seer_writer_free(&oac);
    seer_writer_free(&v);
    return st;
  }
  st = store_bind(stmt, param, ORA_TYPE_REF, out ? 4000u : (uint32_t)len, 0, 0, out, v.buf, v.len);
  if (st != SEER_OK) {
    seer_writer_free(&oac);
    return st;
  } /* store_bind freed v.buf */
  SeerBind *b = &stmt->pbinds[param - 1];
  free(b->oac_override);
  b->oac_override = oac.buf;
  b->oac_override_len = oac.len;
  return SEER_OK;
}

SeerStatus seer_stmt_bind_ref(SeerStmt *stmt, int param, const char *type_schema,
                              const char *type_name, const uint8_t *ref, size_t len)
{
  return ref_bind(stmt, param, type_schema, type_name, ref, len, false);
}

SeerStatus seer_stmt_bind_ref_out(SeerStmt *stmt, int param, const char *type_schema,
                                  const char *type_name)
{
  return ref_bind(stmt, param, type_schema, type_name, NULL, 0, true);
}

SeerStatus seer_stmt_bind_object_out(SeerStmt *stmt, int param, const char *schema,
                                     const char *type_name)
{
  if (stmt == NULL || schema == NULL || type_name == NULL)
    return SEER_EPARAM;
  uint8_t oid[16];
  SeerStatus st = obj_lookup_oid(stmt->conn, schema, type_name, oid);
  if (st != SEER_OK)
    return st;
  return obj_store_bind(stmt, param, schema, type_name, oid, NULL, true);
}

/* Bind a native LOB-backed value (JSON #70 / VECTOR #62): wrap `image` in the
 * native inline bind value (the 19-byte descriptor + ub2 image length + 22 zero
 * bytes + the bytes-with-length image) and attach the fixed per-type OAC. Shared
 * by the JSON and VECTOR binds. */
static SeerStatus native_lob_bind(SeerStmt *stmt, int param, uint8_t ora_type, const uint8_t *image,
                                  size_t imagelen, const uint8_t *oac_bytes, size_t oac_len)
{
  /* The 18-byte descriptor, then the image length as THREE bytes - not a
   * 19-byte descriptor + ub2: identical below 64 KiB (the 19th byte is the
   * length's high byte), but a ub2 can't carry a bigger image, e.g. a float64
   * vector past ~8190 dimensions (seerdb/seerdb@d15e421). */
  if (imagelen > 0xFFFFFF)
    return SEER_EPARAM;
  SeerConn *c = stmt->conn;
  /* SEER_LOB_BIND_SCHEMA with the value LOB's 38-byte locator, then the
   * image (#398). */
  SeerWriter loc;
  if (!seer_writer_init(&loc, SEER_VALUE_LOCATOR_LEN))
    return SEER_ENOMEM;
  SeerValueLocatorMsg vl = {.len_hi = (int64_t)(imagelen >> 16),
                            .len_lo = (int64_t)(imagelen & 0xFFFF)};
  SeerSchemaCtx cx = seer_msg_ctx(0, c->field_version, c->server_field_version);
  seer_schema_encode(SEER_VALUE_LOCATOR_SCHEMA, &cx, &vl, &loc);
  SeerWriter v;
  if (!seer_writer_ok(&loc) || !seer_writer_init(&v, 64 + imagelen)) {
    seer_writer_free(&loc);
    return SEER_ENOMEM;
  }
  SeerLobBindMsg lm = {.loc_len = (int64_t)loc.len,
                       .locator = {.p = loc.buf, .n = loc.len},
                       .has_image = 1,
                       .image = {.p = image, .n = imagelen}};
  seer_schema_encode(SEER_LOB_BIND_SCHEMA, &cx, &lm, &v);
  seer_writer_free(&loc);
  if (!seer_writer_ok(&v)) {
    seer_writer_free(&v);
    return SEER_ENOMEM;
  }

  uint8_t *oac = malloc(oac_len);
  if (oac == NULL) {
    seer_writer_free(&v);
    return SEER_ENOMEM;
  }
  memcpy(oac, oac_bytes, oac_len);

  SeerStatus st = store_bind(stmt, param, ora_type, (uint32_t)imagelen, 0, 0, false, v.buf, v.len);
  if (st != SEER_OK) {
    free(oac);
    return st;
  } /* store_bind freed v.buf */
  SeerBind *b = &stmt->pbinds[param - 1];
  free(b->oac_override);
  b->oac_override = oac;
  b->oac_override_len = oac_len;
  return SEER_OK;
}

/* Native JSON bind (#70): parse json_text to OSON and bind it directly (no server
 * text cast). 21c+ (SEER_ENOTIMPL on older servers; bind JSON as text there). */
SeerStatus seer_stmt_bind_json(SeerStmt *stmt, int param, const char *json_text)
{
  if (stmt == NULL || json_text == NULL)
    return SEER_EPARAM;
  if (stmt->conn->field_version < TTC_FIELD_VERSION_20_1)
    return SEER_ENOTIMPL;

  static const uint8_t JSON_OAC[25] = {
      0x77, 0x01, 0x00, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00, 0x00, 0x04, 0x02, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00, 0x00,
  };
  uint8_t *oson = NULL;
  size_t osonlen = 0;
  SeerStatus st = seer_json_to_oson(json_text, &oson, &osonlen);
  if (st != SEER_OK)
    return st;
  st = native_lob_bind(stmt, param, ORA_TYPE_JSON, oson, osonlen, JSON_OAC, sizeof JSON_OAC);
  free(oson);
  return st;
}

/* VECTOR image flag words (oracledb _BIND_HEADER): the NORM bit is always set
 * (an 8-byte norm placeholder follows the header). */
#define VEC_FLAGS_DENSE 0x0012  /* FLOAT32/64/INT8: NORM | 0x02          */
#define VEC_FLAGS_BINARY 0x0010 /* BINARY: NORM only                     */
#define VEC_FLAGS_SPARSE 0x0032 /* sparse FLOAT32: NORM | 0x02 | SPARSE  */

/* Start a VECTOR bind image: gate (23ai) and write the header - magic, version,
 * ub2 flags, element type, ub4 count, then the 8-byte norm placeholder. On
 * SEER_OK the caller appends the element data and calls vector_img_finish. */
static SeerStatus vector_img_start(SeerStmt *stmt, uint8_t version, uint16_t flags, uint8_t etype,
                                   uint32_t count, size_t body_hint, SeerWriter *img)
{
  if (stmt == NULL)
    return SEER_EPARAM;
  if (stmt->conn->field_version < TTC_FIELD_VERSION_23_1)
    return SEER_ENOTIMPL; /* VECTOR is 23ai */
  if (!seer_writer_init(img, 17 + body_hint))
    return SEER_ENOMEM;
  seer_writer_u8(img, VEC_MAGIC);
  seer_writer_u8(img, version);
  seer_writer_u8(img, (uint8_t)(flags >> 8));
  seer_writer_u8(img, (uint8_t)(flags & 0xFF));
  seer_writer_u8(img, etype);
  obj_be4(img, count); /* element / dimension count      */
  for (int i = 0; i < 8; i++)
    seer_writer_u8(img, 0); /* norm placeholder  */
  return SEER_OK;
}

/* Wrap a completed VECTOR image in the native-LOB bind value (VECTOR OAC, type
 * 127) and store it. Frees `img`. */
static SeerStatus vector_img_finish(SeerStmt *stmt, int param, SeerWriter *img)
{
  static const uint8_t VEC_OAC[25] = {
      0x7f, 0x01, 0x00, 0x00, 0x04, 0x00, 0x10, 0x00, 0x00, 0x00, 0x04, 0x02, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x10, 0x00, 0x00, 0x00,
  };
  if (!seer_writer_ok(img)) {
    seer_writer_free(img);
    return SEER_ENOMEM;
  }
  SeerStatus st =
      native_lob_bind(stmt, param, ORA_TYPE_VECTOR, img->buf, img->len, VEC_OAC, sizeof VEC_OAC);
  seer_writer_free(img);
  return st;
}

/* Native VECTOR bind (#62), dense FLOAT32: order-preserving 4-byte elements. 23ai+. */
SeerStatus seer_stmt_bind_vector_f32(SeerStmt *stmt, int param, const float *values, int dims)
{
  if (dims < 0 || (dims > 0 && values == NULL))
    return SEER_EPARAM;
  SeerWriter img;
  SeerStatus st = vector_img_start(stmt, 0, VEC_FLAGS_DENSE, VEC_TYPE_FLOAT32, (uint32_t)dims,
                                   (size_t)dims * 4, &img);
  if (st != SEER_OK)
    return st;
  for (int i = 0; i < dims; i++) {
    uint8_t e[4];
    seer_encode_bfloat(values[i], e);
    seer_writer_bytes(&img, e, 4);
  }
  return vector_img_finish(stmt, param, &img);
}

/* Native VECTOR bind, dense FLOAT64: order-preserving 8-byte elements. 23ai+. */
SeerStatus seer_stmt_bind_vector_f64(SeerStmt *stmt, int param, const double *values, int dims)
{
  if (dims < 0 || (dims > 0 && values == NULL))
    return SEER_EPARAM;
  SeerWriter img;
  SeerStatus st = vector_img_start(stmt, 0, VEC_FLAGS_DENSE, VEC_TYPE_FLOAT64, (uint32_t)dims,
                                   (size_t)dims * 8, &img);
  if (st != SEER_OK)
    return st;
  for (int i = 0; i < dims; i++) {
    uint8_t e[8];
    seer_encode_bdouble(values[i], e);
    seer_writer_bytes(&img, e, 8);
  }
  return vector_img_finish(stmt, param, &img);
}

/* Native VECTOR bind, dense INT8: one signed byte per element. 23ai+. */
SeerStatus seer_stmt_bind_vector_i8(SeerStmt *stmt, int param, const int8_t *values, int dims)
{
  if (dims < 0 || (dims > 0 && values == NULL))
    return SEER_EPARAM;
  SeerWriter img;
  SeerStatus st =
      vector_img_start(stmt, 0, VEC_FLAGS_DENSE, VEC_TYPE_INT8, (uint32_t)dims, (size_t)dims, &img);
  if (st != SEER_OK)
    return st;
  for (int i = 0; i < dims; i++)
    seer_writer_u8(&img, (uint8_t)values[i]);
  return vector_img_finish(stmt, param, &img);
}

/* Native VECTOR bind, BINARY: a bit vector packed as `nbytes` bytes (8 dimensions
 * per byte). Version 1, count = nbytes*8. 23ai+. */
SeerStatus seer_stmt_bind_vector_binary(SeerStmt *stmt, int param, const uint8_t *bytes, int nbytes)
{
  if (nbytes < 0 || (nbytes > 0 && bytes == NULL))
    return SEER_EPARAM;
  SeerWriter img;
  SeerStatus st = vector_img_start(stmt, 1, VEC_FLAGS_BINARY, VEC_TYPE_BINARY, (uint32_t)nbytes * 8,
                                   (size_t)nbytes, &img);
  if (st != SEER_OK)
    return st;
  if (nbytes > 0)
    seer_writer_bytes(&img, bytes, (size_t)nbytes);
  return vector_img_finish(stmt, param, &img);
}

/* Native VECTOR bind, sparse FLOAT32: a `num_dimensions`-wide vector with `nnz`
 * non-zero entries (indices[i] -> values[i]). Version 2; the body is ub2 nnz,
 * then nnz ub4 indices, then nnz order-preserving 4-byte values. 23ai+. */
SeerStatus seer_stmt_bind_vector_sparse_f32(SeerStmt *stmt, int param, int num_dimensions, int nnz,
                                            const uint32_t *indices, const float *values)
{
  if (num_dimensions < 0 || nnz < 0 || nnz > 0xFFFF ||
      (nnz > 0 && (indices == NULL || values == NULL)))
    return SEER_EPARAM;
  SeerWriter img;
  SeerStatus st = vector_img_start(stmt, 2, VEC_FLAGS_SPARSE, VEC_TYPE_FLOAT32,
                                   (uint32_t)num_dimensions, 2 + (size_t)nnz * 8, &img);
  if (st != SEER_OK)
    return st;
  seer_writer_u8(&img, (uint8_t)((unsigned)nnz >> 8)); /* ub2 non-zero count */
  seer_writer_u8(&img, (uint8_t)((unsigned)nnz & 0xFF));
  for (int i = 0; i < nnz; i++)
    obj_be4(&img, indices[i]); /* ub4 indices        */
  for (int i = 0; i < nnz; i++) {
    uint8_t e[4];
    seer_encode_bfloat(values[i], e); /* 4-byte values      */
    seer_writer_bytes(&img, e, 4);
  }
  return vector_img_finish(stmt, param, &img);
}

/* Native VECTOR bind, sparse FLOAT64: as sparse FLOAT32 but 8-byte values. 23ai+. */
SeerStatus seer_stmt_bind_vector_sparse_f64(SeerStmt *stmt, int param, int num_dimensions, int nnz,
                                            const uint32_t *indices, const double *values)
{
  if (num_dimensions < 0 || nnz < 0 || nnz > 0xFFFF ||
      (nnz > 0 && (indices == NULL || values == NULL)))
    return SEER_EPARAM;
  SeerWriter img;
  SeerStatus st = vector_img_start(stmt, 2, VEC_FLAGS_SPARSE, VEC_TYPE_FLOAT64,
                                   (uint32_t)num_dimensions, 2 + (size_t)nnz * 12, &img);
  if (st != SEER_OK)
    return st;
  seer_writer_u8(&img, (uint8_t)((unsigned)nnz >> 8)); /* ub2 non-zero count */
  seer_writer_u8(&img, (uint8_t)((unsigned)nnz & 0xFF));
  for (int i = 0; i < nnz; i++)
    obj_be4(&img, indices[i]); /* ub4 indices        */
  for (int i = 0; i < nnz; i++) {
    uint8_t e[8];
    seer_encode_bdouble(values[i], e); /* 8-byte values      */
    seer_writer_bytes(&img, e, 8);
  }
  return vector_img_finish(stmt, param, &img);
}

/* Native VECTOR bind, sparse INT8: as sparse FLOAT32 but 1 signed byte per value. 23ai+. */
SeerStatus seer_stmt_bind_vector_sparse_i8(SeerStmt *stmt, int param, int num_dimensions, int nnz,
                                           const uint32_t *indices, const int8_t *values)
{
  if (num_dimensions < 0 || nnz < 0 || nnz > 0xFFFF ||
      (nnz > 0 && (indices == NULL || values == NULL)))
    return SEER_EPARAM;
  SeerWriter img;
  SeerStatus st = vector_img_start(stmt, 2, VEC_FLAGS_SPARSE, VEC_TYPE_INT8,
                                   (uint32_t)num_dimensions, 2 + (size_t)nnz * 5, &img);
  if (st != SEER_OK)
    return st;
  seer_writer_u8(&img, (uint8_t)((unsigned)nnz >> 8)); /* ub2 non-zero count */
  seer_writer_u8(&img, (uint8_t)((unsigned)nnz & 0xFF));
  for (int i = 0; i < nnz; i++)
    obj_be4(&img, indices[i]); /* ub4 indices        */
  for (int i = 0; i < nnz; i++)
    seer_writer_u8(&img, (uint8_t)values[i]); /* 1-byte values      */
  return vector_img_finish(stmt, param, &img);
}

SeerStatus seer_stmt_bind_collection(SeerStmt *stmt, int param, const char *schema,
                                     const char *type_name, const char *const *elem_values,
                                     int n_elems)
{
  if (stmt == NULL || schema == NULL || type_name == NULL || (n_elems > 0 && elem_values == NULL))
    return SEER_EPARAM;

  uint8_t oid[16];
  SeerStatus st = obj_lookup_oid(stmt->conn, schema, type_name, oid);
  if (st != SEER_OK)
    return st;
  uint8_t elem_type = 0;
  bool index_table = false;
  st = obj_lookup_elem(stmt->conn, schema, type_name, &elem_type, &index_table);
  if (st != SEER_OK)
    return st;

  /* Collection image body: a collection-flags byte, the length-prefixed element
   * count, then each element field. A PL/SQL index-by table sets HAS_INDEXES
   * (0x10) and puts each element's key before it - a 4-byte big-endian signed
   * integer, here 0..n-1, as PL/SQL indexes such arrays from zero (§21.6b). */
  SeerWriter body;
  if (!seer_writer_init(&body, 64))
    return SEER_ENOMEM;
  seer_writer_u8(&body, index_table ? 0x10 : 0x00); /* collection flags */
  obj_write_length(&body, (uint32_t)(n_elems > 0 ? n_elems : 0));
  for (int i = 0; i < n_elems && st == SEER_OK; i++) {
    if (index_table)
      obj_be4(&body, (uint32_t)i);
    st = obj_encode_field(&body, elem_type, elem_values[i]);
  }
  if (st != SEER_OK) {
    seer_writer_free(&body);
    return st;
  }
  if (!seer_writer_ok(&body)) {
    seer_writer_free(&body);
    return SEER_ENOMEM;
  }

  /* Collection image: header (0x88, version, 0xFE, BE4 total) + prefix seg [1,1]
   * + body. Total counts the 7-byte header and the 2-byte prefix segment. */
  SeerWriter img;
  uint32_t total = 9 + (uint32_t)body.len;
  if (!seer_writer_init(&img, total)) {
    seer_writer_free(&body);
    return SEER_ENOMEM;
  }
  seer_writer_u8(&img, 0x88);
  seer_writer_u8(&img, 0x01);
  seer_writer_u8(&img, 0xFE);
  obj_be4(&img, total);
  seer_writer_u8(&img, 1);
  seer_writer_u8(&img, 1);
  seer_writer_bytes(&img, body.buf, body.len);
  seer_writer_free(&body);
  if (!seer_writer_ok(&img)) {
    seer_writer_free(&img);
    return SEER_ENOMEM;
  }
  return obj_store_bind(stmt, param, schema, type_name, oid, &img, false);
}

/* Build the OAC for an associative-array (PL/SQL index-by) bind: the scalar OAC
 * with the ARRAY flag (0x40) set and the declared capacity in the max-array-
 * elements field. `length` is the element's max byte size. Returns malloc'd bytes
 * in *out_len (caller owns), or NULL. 12c+ OAC shape. */
static uint8_t *aa_build_oac(uint8_t fv, uint8_t dtype, uint32_t length, uint32_t charset,
                             uint8_t csfrm, uint32_t capacity, size_t *out_len)
{
  SeerWriter w;
  if (!seer_writer_init(&w, 48))
    return NULL;
  /* TNS_BIND_USE_INDICATORS | ARRAY; below 12.1 the flags are 03 | ARRAY, as
   * JDBC thin 11.2 sends them, and there is no oaccolid (seerdb, measured on
   * 11g XE and 10.2.0.5; #172). */
  SeerOacMsg m = {.data_type = dtype,
                  .flags = fv < TTC_FIELD_VERSION_12_1 ? 0x43 : 0x41,
                  .max_length = length,
                  .max_array = capacity ? capacity : 1,
                  .charset = charset,
                  .csfrm = csfrm};
  oac_write(&w, false, fv, &m);
  if (!seer_writer_ok(&w)) {
    seer_writer_free(&w);
    return NULL;
  }
  *out_len = w.len;
  return w.buf; /* ownership transferred */
}

/* An 8i associative-array bind (seerdb PROTOCOL.md §19.17c, bus 84, OCI 9.2
 * index-by binds on 8.1.7): the 25-byte scalar descriptor with flag 0x43 (the
 * ARRAY bit 0x40 on the usual 0x03) and the maximum element count, a LE ub4,
 * at +8 in its reserved bytes. The value is a LE ub4 count, then each element
 * as a length-prefixed value, a NULL one fd 01; a pure OUT, the count 0. */
static uint8_t *o8i_aa_oac(uint8_t dtype, uint32_t length, uint32_t capacity, size_t *out_len)
{
  bool text = dtype != ORA_TYPE_NUMBER;
  SeerWriter w;
  if (!seer_writer_init(&w, 32))
    return NULL;
  SeerOacMsg m = {.data_type = dtype,
                  .flags = 0x43,
                  .max_length = length > 0xFFFF ? 0xFFFF : length,
                  .max_array = capacity ? capacity : 1,
                  .charset = text ? 31 : 0, /* WE8ISO8859P1 for text */
                  .csfrm = text ? 1 : 0};
  oac_write(&w, true, 0, &m);
  if (!seer_writer_ok(&w)) {
    seer_writer_free(&w);
    return NULL;
  }
  *out_len = w.len;
  return w.buf; /* ownership transferred */
}

static void o8i_aa_elem(SeerWriter *v, const uint8_t *p, size_t n)
{
  if (p == NULL)
    o8i_slot(v, SEER_O8I_OUT_SLOT_SCHEMA); /* a NULL element */
  else
    chr_write(v, true, 0, p, n);
}

/* Attach a prebuilt array OAC + RXD to a bind position (a single PL/SQL
 * associative-array parameter). Takes ownership of `rxd` and `oac`. */
static SeerStatus aa_store(SeerStmt *stmt, int param, uint8_t dtype, uint32_t length, uint8_t *rxd,
                           size_t rxd_len, uint8_t *oac, size_t oac_len)
{
  SeerStatus st = store_bind(stmt, param, dtype, length, 0, 0, false, rxd, rxd_len);
  if (st != SEER_OK) {
    free(oac);
    return st;
  } /* store_bind freed rxd */
  SeerBind *b = &stmt->pbinds[param - 1];
  free(b->oac_override);
  b->oac_override = oac;
  b->oac_override_len = oac_len;
  b->is_array = true;
  return SEER_OK;
}

/* Bind a PL/SQL associative-array (index-by table) OUT parameter (12c+): the
 * server fills up to `capacity` elements of type `ora_type` (NUMBER or VARCHAR).
 * Read them back with seer_stmt_out_array_len / seer_stmt_out_array_get. */
SeerStatus seer_stmt_bind_out_array(SeerStmt *stmt, int param, int ora_type, int elem_size,
                                    int capacity)
{
  if (stmt == NULL || capacity <= 0)
    return SEER_EPARAM;
  uint8_t dtype = (ora_type == ORA_TYPE_NUMBER) ? ORA_TYPE_NUMBER : ORA_TYPE_VARCHAR;
  uint32_t length = (dtype == ORA_TYPE_NUMBER) ? 22 : (uint32_t)(elem_size > 0 ? elem_size : 2000);
  if (stmt->conn->is_8i) { /* §19.17c: the count 0 as a pure OUT's value */
    size_t ol = 0;
    uint8_t *oac = o8i_aa_oac(dtype, length, (uint32_t)capacity, &ol);
    uint8_t *rxd = calloc(1, 4);
    if (oac == NULL || rxd == NULL) {
      free(oac);
      free(rxd);
      return SEER_ENOMEM;
    }
    SeerStatus st = store_bind(stmt, param, dtype, length, 0, 0, true, rxd, 4);
    if (st != SEER_OK) {
      free(oac);
      return st;
    }
    SeerBind *b = &stmt->pbinds[param - 1];
    free(b->oac_override);
    b->oac_override = oac;
    b->oac_override_len = ol;
    b->is_array = true;
    return SEER_OK;
  }
  if (stmt->conn->field_version < TTC_FIELD_VERSION_10_2)
    return SEER_ENOTIMPL; /* 9i: no reference client binds one in its compact form (#254) */

  uint32_t charset = (dtype == ORA_TYPE_NUMBER) ? 0 : 873;
  uint8_t csfrm = (dtype == ORA_TYPE_NUMBER) ? 0 : 1;

  size_t oac_len = 0;
  uint8_t *oac = aa_build_oac(stmt->conn->field_version, dtype, length, charset, csfrm,
                              (uint32_t)capacity, &oac_len);
  if (oac == NULL)
    return SEER_ENOMEM;
  uint8_t *rxd = malloc(1); /* empty-array placeholder (ub4 count 0) */
  if (rxd == NULL) {
    free(oac);
    return SEER_ENOMEM;
  }
  rxd[0] = 0;

  SeerStatus st = store_bind(stmt, param, dtype, length, charset, 0, true, rxd, 1);
  if (st != SEER_OK) {
    free(oac);
    return st;
  }
  SeerBind *b = &stmt->pbinds[param - 1];
  free(b->oac_override);
  b->oac_override = oac;
  b->oac_override_len = oac_len;
  b->is_array = true;
  return SEER_OK;
}

/* Number of elements returned in an OUT assoc-array bind (0 if none). */
int seer_stmt_out_array_len(SeerStmt *stmt, int param)
{
  if (stmt == NULL || param < 1 || param > stmt->npbinds)
    return 0;
  SeerBind *b = &stmt->pbinds[param - 1];
  return b->is_array ? b->out_arr_n : 0;
}

/* Fetch element `index` of an OUT assoc-array bind as decoded text (*data is
 * NUL-terminated; *isnull set for a NULL element). SEER_EPARAM if out of range. */
SeerStatus seer_stmt_out_array_get(SeerStmt *stmt, int param, int index, const char **data,
                                   size_t *len, int *isnull)
{
  if (stmt == NULL || param < 1 || param > stmt->npbinds || data == NULL)
    return SEER_EPARAM;
  SeerBind *b = &stmt->pbinds[param - 1];
  if (!b->is_array || index < 0 || index >= b->out_arr_n)
    return SEER_EPARAM;
  SeerCell *c = &b->out_arr[index];
  *data = c->data;
  if (len)
    *len = c->len;
  if (isnull)
    *isnull = (c->data == NULL);
  return SEER_OK;
}

SeerStatus seer_stmt_bind_int64_array(SeerStmt *stmt, int param, const int64_t *values, int n)
{
  if (stmt == NULL || n < 0 || (n > 0 && values == NULL))
    return SEER_EPARAM;
  if (stmt->conn->is_8i) {
    SeerWriter v;
    if (!seer_writer_init(&v, 8 + (size_t)n * 24))
      return SEER_ENOMEM;
    aa_count(&v, true, 0, n);
    for (int i = 0; i < n; i++) {
      uint8_t num[24];
      size_t nn = seer_encode_number_int(values[i], num);
      o8i_aa_elem(&v, num, nn);
    }
    size_t ol = 0;
    uint8_t *oac = seer_writer_ok(&v) ? o8i_aa_oac(ORA_TYPE_NUMBER, 22, (uint32_t)n, &ol) : NULL;
    if (oac == NULL) {
      seer_writer_free(&v);
      return SEER_ENOMEM;
    }
    return aa_store(stmt, param, ORA_TYPE_NUMBER, 22, v.buf, v.len, oac, ol);
  }
  if (stmt->conn->field_version < TTC_FIELD_VERSION_10_2)
    return SEER_ENOTIMPL; /* 9i: no reference client binds one in its compact form (#254) */

  /* RXD: the element count, then each element a bind value (#398). */
  SeerWriter rxd;
  if (!seer_writer_init(&rxd, 16 + (size_t)n * 12))
    return SEER_ENOMEM;
  aa_count(&rxd, false, stmt->conn->field_version, n);
  for (int i = 0; i < n; i++) {
    uint8_t num[24];
    size_t nn = seer_encode_number_int(values[i], num);
    chr_write(&rxd, false, stmt->conn->field_version, num, nn);
  }
  if (!seer_writer_ok(&rxd)) {
    seer_writer_free(&rxd);
    return SEER_ENOMEM;
  }

  size_t oac_len = 0;
  uint8_t *oac =
      aa_build_oac(stmt->conn->field_version, ORA_TYPE_NUMBER, 22, 0, 0, (uint32_t)n, &oac_len);
  if (oac == NULL) {
    seer_writer_free(&rxd);
    return SEER_ENOMEM;
  }
  return aa_store(stmt, param, ORA_TYPE_NUMBER, 22, rxd.buf, rxd.len, oac, oac_len);
}

SeerStatus seer_stmt_bind_text_array(SeerStmt *stmt, int param, const char *const *values, int n,
                                     int elem_size)
{
  if (stmt == NULL || n < 0 || (n > 0 && values == NULL) || elem_size <= 0)
    return SEER_EPARAM;
  if (stmt->conn->is_8i) { /* each element in WE8ISO8859P1, the session's charset */
    SeerWriter v;
    if (!seer_writer_init(&v, 8 + (size_t)n * 16))
      return SEER_ENOMEM;
    aa_count(&v, true, 0, n);
    for (int i = 0; i < n; i++) {
      if (values[i] == NULL) {
        o8i_aa_elem(&v, NULL, 0);
        continue;
      }
      size_t ln = 0;
      uint8_t *l1 = o8i_latin1(values[i], &ln);
      if (l1 == NULL) {
        seer_writer_free(&v);
        return SEER_ENOMEM;
      }
      o8i_aa_elem(&v, l1, ln);
      free(l1);
    }
    size_t ol = 0;
    uint8_t *oac = seer_writer_ok(&v)
                       ? o8i_aa_oac(ORA_TYPE_VARCHAR, (uint32_t)elem_size, (uint32_t)n, &ol)
                       : NULL;
    if (oac == NULL) {
      seer_writer_free(&v);
      return SEER_ENOMEM;
    }
    return aa_store(stmt, param, ORA_TYPE_VARCHAR, (uint32_t)elem_size, v.buf, v.len, oac, ol);
  }
  if (stmt->conn->field_version < TTC_FIELD_VERSION_10_2)
    return SEER_ENOTIMPL; /* 9i: no reference client binds one in its compact form (#254) */

  /* RXD: the count, then each element a bind value, a NULL one empty
   * (#398). */
  SeerWriter rxd;
  if (!seer_writer_init(&rxd, 32 + (size_t)n * 16))
    return SEER_ENOMEM;
  aa_count(&rxd, false, stmt->conn->field_version, n);
  for (int i = 0; i < n; i++)
    chr_write(&rxd, false, stmt->conn->field_version, (const uint8_t *)values[i],
              values[i] != NULL ? strlen(values[i]) : 0);
  if (!seer_writer_ok(&rxd)) {
    seer_writer_free(&rxd);
    return SEER_ENOMEM;
  }

  size_t oac_len = 0;
  uint8_t *oac = aa_build_oac(stmt->conn->field_version, ORA_TYPE_VARCHAR, (uint32_t)elem_size, 873,
                              1, (uint32_t)n, &oac_len);
  if (oac == NULL) {
    seer_writer_free(&rxd);
    return SEER_ENOMEM;
  }
  return aa_store(stmt, param, ORA_TYPE_VARCHAR, (uint32_t)elem_size, rxd.buf, rxd.len, oac,
                  oac_len);
}

/* The status of a reply to a call that returns no rows (a commit, a rollback):
 * SEER_OK unless it carries an error (TTI_OER with a non-zero code), which is
 * then put on the connection and returned as SEER_EDB. A refused commit is a
 * real error - ORA-02091, the transaction rolled back - and once went
 * unreported on 9i and later (#184). */
SeerStatus seer_conn_call_status(SeerConn *c, const uint8_t *resp, size_t rlen)
{
  if (rlen == 0 || resp[0] != TTI_OER)
    return SEER_OK;
  if (c->field_version < TTC_FIELD_VERSION_10_2) { /* 9i's short status */
    int64_t code = fv2_oer_code(resp, rlen);
    if (code == 0)
      return SEER_OK;
    free(c->last_error);
    c->last_error = NULL;
    fv2_set_error(c, resp, rlen);
    if (c->last_error == NULL && code > 0)
      seer_conn_error_code(c, (long)code);
    return SEER_EDB;
  }
  SeerReader r;
  seer_reader_init(&r, resp + 1, rlen - 1);
  r.sb4_chunks = c->field_version >= TTC_FIELD_VERSION_12_1;
  SeerStmt tmp = {.conn = c};
  OerResult oer = {0};
  free(c->last_error);
  c->last_error = NULL;
  parse_oer(&r, &tmp, &oer);
  free_batch_errors(&tmp);
  if (oer.err_code == 0)
    return SEER_OK;
  if (c->last_error == NULL)
    seer_conn_error_code(c, (long)oer.err_code);
  return SEER_EDB;
}

/* ------------------------------------------------- two-phase commit (XA/TPC) */

/* Reject an out-of-range Xid (XA caps gtrid and bqual at 64 bytes each). */
static bool xid_valid(const SeerXid *xid)
{
  return xid != NULL && xid->gtrid_len >= 0 && xid->bqual_len >= 0 && xid->gtrid_len <= 64 &&
         xid->bqual_len <= 64 && (xid->gtrid_len + xid->bqual_len) <= TNS_TPC_XID_WIRE_LEN;
}

/* A TPC message's head and tail from the connection and the xid: the stored
 * context, replayed, and the xid's descriptor and 128-byte payload - gtrid
 * then bqual, zero-padded - into `xbuf`. */
static void tpc_msg(const SeerConn *c, const SeerXid *xid, uint32_t op,
                    uint8_t xbuf[TNS_TPC_XID_WIRE_LEN], SeerTpcMsg *m)
{
  *m = (SeerTpcMsg){.op = op};
  if (c->tpc_context != NULL) {
    m->ctx_ptr = 1;
    m->ctx_len = (int64_t)c->tpc_context_len;
    m->ctx = (SeerBytes){c->tpc_context, c->tpc_context_len, 0};
  }
  if (xid != NULL) {
    memset(xbuf, 0, TNS_TPC_XID_WIRE_LEN);
    if (xid->gtrid_len > 0)
      memcpy(xbuf, xid->gtrid, (size_t)xid->gtrid_len);
    if (xid->bqual_len > 0)
      memcpy(xbuf + xid->gtrid_len, xid->bqual, (size_t)xid->bqual_len);
    m->format_id = (uint32_t)xid->format_id;
    m->gtrid_len = xid->gtrid_len;
    m->bqual_len = xid->bqual_len;
    m->xid_ptr = 1;
    m->xid_len = TNS_TPC_XID_WIRE_LEN;
    m->xid = (SeerBytes){xbuf, TNS_TPC_XID_WIRE_LEN, 0};
  }
}

/* Build a TXN_SWITCH (begin/end) message by SEER_TPC_SWITCH_SCHEMA, replaying
 * any stored context. Before 11g the internal and external names are absent:
 * their pointers, lengths and bytes (seerdb PROTOCOL.md §28, "Before 12c"). */
SeerStatus seer_tpc_build_switch(SeerConn *c, SeerWriter *w, uint32_t op, const SeerXid *xid,
                                 uint32_t flags, uint32_t timeout)
{
  if (!seer_writer_init(w, 256))
    return SEER_ENOMEM;
  seer_ttc_fun_header(c, w, TNS_FUNC_TPC_TXN_SWITCH);
  uint8_t xbuf[TNS_TPC_XID_WIRE_LEN];
  SeerTpcMsg m;
  tpc_msg(c, xid, op, xbuf, &m);
  m.flags = flags;
  m.timeout = timeout;
  SeerSchemaCtx cx = seer_msg_ctx(0, c->field_version, c->server_field_version);
  seer_schema_encode(SEER_TPC_SWITCH_SCHEMA, &cx, &m, w);
  return seer_writer_ok(w) ? SEER_OK : SEER_ENOMEM;
}

/* Build a TXN_CHANGE_STATE (prepare/commit/abort) message by
 * SEER_TPC_CHANGE_STATE_SCHEMA. 9i has no flags: the context follows the
 * out-state pointer (PROTOCOL.md §28). */
static SeerStatus tpc_build_change_state(SeerConn *c, SeerWriter *w, uint32_t op, uint32_t state,
                                         const SeerXid *xid)
{
  if (!seer_writer_init(w, 256))
    return SEER_ENOMEM;
  seer_ttc_fun_header(c, w, TNS_FUNC_TPC_TXN_CHANGE_STATE);
  uint8_t xbuf[TNS_TPC_XID_WIRE_LEN];
  SeerTpcMsg m;
  tpc_msg(c, xid, op, xbuf, &m);
  m.state = state;
  m.out_ptr = 1;
  SeerSchemaCtx cx = seer_msg_ctx(0, c->field_version, c->server_field_version);
  seer_schema_encode(SEER_TPC_CHANGE_STATE_SCHEMA, &cx, &m, w);
  return seer_writer_ok(w) ? SEER_OK : SEER_ENOMEM;
}

/* Send a built TPC message (frees `w`) and decode the reply: TTI_RPA carries the
 * begin context (want_context) or the ub4 change-state, with a trailing OER call
 * status; a reply leading with TTI_OER is an ORA error. */
static SeerStatus tpc_call(SeerConn *c, SeerWriter *w, bool want_context, uint8_t **ctx,
                           size_t *ctxlen, uint32_t *state)
{
  SeerStatus st = seer_ttc_send(c, w->buf, w->len);
  seer_writer_free(w);
  if (st != SEER_OK)
    return st;
  uint8_t *resp = NULL;
  size_t rlen = 0;
  st = seer_ttc_recv(c, &resp, &rlen);
  if (st != SEER_OK)
    return st;

  SeerReader r;
  seer_reader_init(&r, resp, rlen);
  r.sb4_chunks = c->field_version >= TTC_FIELD_VERSION_12_1;
  SeerStmt tmp = {.conn = c};
  OerResult oer = {0};
  SeerStatus ret = SEER_OK;
  bool fv2 = c->field_version < TTC_FIELD_VERSION_10_2; /* 9i */
  uint8_t tok = seer_reader_u8(&r);

  if (tok == TTI_RPA) {
    SeerSchemaCtx scx = seer_msg_ctx(0, c->field_version, c->server_field_version);
    SeerTpcMsg m = {0};
    if (want_context) {
      if (!seer_schema_decode(SEER_TPC_CONTEXT_REPLY_SCHEMA, &scx, &r, &m)) {
        free(resp);
        return SEER_EPROTO;
      }
      uint8_t *cx = malloc(m.ctx.n ? m.ctx.n : 1);
      if (cx == NULL) {
        free(resp);
        return SEER_ENOMEM;
      }
      if (m.ctx.n > 0)
        memcpy(cx, m.ctx.p, m.ctx.n);
      *ctx = cx;
      *ctxlen = m.ctx.n;
    } else if (state != NULL) {
      (void)seer_schema_decode(SEER_TPC_STATE_REPLY_SCHEMA, &scx, &r, &m);
      *state = (uint32_t)m.state;
    }
    if (seer_reader_remaining(&r) > 0 && seer_reader_u8(&r) == TTI_OER) {
      if (fv2) {
        size_t at = rlen - seer_reader_remaining(&r) - 1;
        if (fv2_oer_code(resp + at, rlen - at) != 0) {
          fv2_set_error(c, resp + at, rlen - at);
          ret = SEER_EDB;
        }
        r.pos = r.len; /* 9i's short status: read by the fv2 helpers */
      } else {
        parse_oer(&r, &tmp, &oer);
        if (oer.err_code != 0)
          ret = SEER_EDB;
      }
    }
  } else if (tok == TTI_OER) {
    if (fv2) {
      fv2_set_error(c, resp, rlen);
      r.pos = r.len;
    } else {
      parse_oer(&r, &tmp, &oer);
    }
    ret = SEER_EDB;
  } else {
    ret = SEER_EPROTO;
  }
  free_batch_errors(&tmp);
  if (ret == SEER_OK && !seer_reader_ok(&r))
    ret = SEER_EPROTO;
  free(resp);
  return ret;
}

/* 8i has no native TPC form: its XA runs as PL/SQL on SYS.JAVA_XA (seerdb
 * PROTOCOL.md §28, "Before 12c"). Each xa_*_new function takes the format id,
 * the gtrid and bqual as RAW and up to two numbers, and returns an X/Open XA
 * code, or the number of an ORA error (positive, e.g. 24756). */
#define XA_TMNOFLAGS 0x00000000L
#define XA_TMJOIN 0x00200000L
#define XA_TMRESUME 0x08000000L
#define XA_TMSUCCESS 0x04000000L
#define XA_TMSUSPEND 0x02000000L
#define XA_OK 0
#define XA_RDONLY 3

static const char *xa_code_name(long rc)
{
  switch (rc) {
  case 3:
    return "XA_RDONLY";
  case -2:
    return "XAER_ASYNC";
  case -3:
    return "XAER_RMERR";
  case -4:
    return "XAER_NOTA";
  case -5:
    return "XAER_INVAL";
  case -6:
    return "XAER_PROTO";
  case -7:
    return "XAER_RMFAIL";
  case -8:
    return "XAER_DUPID";
  case -9:
    return "XAER_OUTSIDE";
  default:
    return rc >= 100 && rc <= 107 ? "XA_RB*" : "unknown";
  }
}

/* Call JAVA_XA.`fn`(format id, gtrid, bqual[, a[, b]]) and return its XA code
 * in *rc. SEER_OK means the call ran, whatever code it returned. */
static SeerStatus o8i_xa_call(SeerConn *c, const char *fn, const SeerXid *xid, int nextra,
                              int64_t a, int64_t b, long *rc)
{
  static const char *const tail[] = {")); END;", ", :5)); END;", ", :5, :6)); END;"};
  char sql[128];
  snprintf(sql, sizeof sql, "BEGIN :1 := TO_CHAR(JAVA_XA.%s(:2, :3, :4%s", fn, tail[nextra]);
  SeerStmt *s = NULL;
  SeerStatus st = seer_stmt_prepare(c, sql, &s);
  if (st != SEER_OK)
    return st;
  st = seer_stmt_bind_out(s, 1, ORA_TYPE_VARCHAR, 40);
  if (st == SEER_OK)
    st = seer_stmt_bind_int64(s, 2, xid->format_id);
  if (st == SEER_OK)
    st = seer_stmt_bind_raw(s, 3, xid->gtrid, xid->gtrid_len);
  if (st == SEER_OK)
    st = seer_stmt_bind_raw(s, 4, xid->bqual, xid->bqual_len);
  if (st == SEER_OK && nextra >= 1)
    st = seer_stmt_bind_int64(s, 5, a);
  if (st == SEER_OK && nextra >= 2)
    st = seer_stmt_bind_int64(s, 6, b);
  if (st == SEER_OK)
    st = seer_stmt_execute(s);
  const void *d = NULL;
  size_t n = 0;
  int isnull = 0, isbin = 0;
  if (st == SEER_OK && seer_stmt_out_data(s, 1, &d, &n, &isnull, &isbin) != SEER_OK)
    st = SEER_EPROTO;
  if (st == SEER_OK) {
    char num[24];
    if (isnull || n == 0 || n >= sizeof num) {
      st = SEER_EPROTO;
    } else {
      memcpy(num, d, n);
      num[n] = '\0';
      char *end = NULL;
      *rc = strtol(num, &end, 10);
      if (end == num || *end != '\0')
        st = SEER_EPROTO;
    }
  }
  seer_stmt_close(s);
  return st;
}

/* Turn an XA code other than those `fn` accepts into an error on the connection. */
static SeerStatus o8i_xa_result(SeerConn *c, const char *fn, long rc, bool rdonly_ok)
{
  if (rc == XA_OK || (rdonly_ok && rc == XA_RDONLY))
    return SEER_OK;
  char m[96];
  if (rc > 107) /* past the XA codes: an ORA error number (24756, "transaction does not exist") */
    snprintf(m, sizeof m, "ORA-%05ld (from JAVA_XA.%s)", rc, fn);
  else
    snprintf(m, sizeof m, "JAVA_XA.%s returned XA code %ld (%s)", fn, rc, xa_code_name(rc));
  char *d = strdup(m);
  if (d != NULL) {
    free(c->last_error);
    c->last_error = d;
    c->last_error_offset = 0;
  }
  return SEER_EDB;
}

static SeerStatus o8i_tpc(SeerConn *c, const char *fn, const SeerXid *xid, int nextra, int64_t a,
                          int64_t b, bool rdonly_ok, long *rc_out)
{
  long rc = 0;
  SeerStatus st = o8i_xa_call(c, fn, xid, nextra, a, b, &rc);
  if (st != SEER_OK)
    return st;
  if (rc_out != NULL)
    *rc_out = rc;
  return o8i_xa_result(c, fn, rc, rdonly_ok);
}

SeerStatus seer_tpc_begin(SeerConn *conn, const SeerXid *xid, uint32_t flags, uint32_t timeout)
{
  if (conn == NULL || !xid_valid(xid))
    return SEER_EPARAM;
  if (!conn->is_8i && conn->field_version < TTC_FIELD_VERSION_10_2 && !conn->xa) {
    /* 9i takes it only on a session that logged on for it (#183). */
    free(conn->last_error);
    conn->last_error = strdup("two-phase commit on 9i needs a connection opened with "
                              "SeerConnParams.xa set");
    return SEER_ENOTIMPL;
  }
  if (conn->is_8i) {
    int64_t xf = (flags & SEER_TPC_BEGIN_JOIN)     ? XA_TMJOIN
                 : (flags & SEER_TPC_BEGIN_RESUME) ? XA_TMRESUME
                                                   : XA_TMNOFLAGS;
    return o8i_tpc(conn, "xa_start_new", xid, 2, timeout, xf, false, NULL);
  }
  SeerWriter w;
  SeerStatus st = seer_tpc_build_switch(conn, &w, TNS_TPC_TXN_START, xid, flags, timeout);
  if (st != SEER_OK)
    return st;
  uint8_t *ctx = NULL;
  size_t ctxlen = 0;
  st = tpc_call(conn, &w, true, &ctx, &ctxlen, NULL);
  if (st != SEER_OK) {
    free(ctx);
    return st;
  }
  free(conn->tpc_context);
  conn->tpc_context = ctx;
  conn->tpc_context_len = ctxlen;
  return SEER_OK;
}

SeerStatus seer_tpc_end(SeerConn *conn, const SeerXid *xid, uint32_t flags)
{
  if (conn == NULL || !xid_valid(xid))
    return SEER_EPARAM;
  if (conn->is_8i)
    return o8i_tpc(conn, "xa_end_new", xid, 1,
                   (flags & SEER_TPC_END_SUSPEND) ? XA_TMSUSPEND : XA_TMSUCCESS, 0, false, NULL);
  SeerWriter w;
  SeerStatus st = seer_tpc_build_switch(conn, &w, TNS_TPC_TXN_DETACH, xid, flags, 0);
  if (st != SEER_OK)
    return st;
  st = tpc_call(conn, &w, false, NULL, NULL, NULL);
  free(conn->tpc_context);
  conn->tpc_context = NULL;
  conn->tpc_context_len = 0;
  return st;
}

SeerStatus seer_tpc_prepare(SeerConn *conn, const SeerXid *xid, int *commit_needed)
{
  if (conn == NULL || !xid_valid(xid))
    return SEER_EPARAM;
  if (conn->is_8i) {
    long rc = 0;
    SeerStatus st = o8i_tpc(conn, "xa_prepare_new", xid, 0, 0, 0, true, &rc);
    if (st == SEER_OK && commit_needed != NULL)
      *commit_needed = rc != XA_RDONLY;
    return st;
  }
  SeerWriter w;
  SeerStatus st = tpc_build_change_state(conn, &w, TNS_TPC_TXN_PREPARE, 0, xid);
  if (st != SEER_OK)
    return st;
  uint32_t state = 0;
  st = tpc_call(conn, &w, false, NULL, NULL, &state);
  if (st != SEER_OK)
    return st;
  if (state != TNS_TPC_TXN_STATE_REQUIRES_COMMIT && state != TNS_TPC_TXN_STATE_READ_ONLY)
    return SEER_EPROTO;
  if (commit_needed != NULL)
    *commit_needed = (state == TNS_TPC_TXN_STATE_REQUIRES_COMMIT);
  return SEER_OK;
}

SeerStatus seer_tpc_commit(SeerConn *conn, const SeerXid *xid, int one_phase)
{
  if (conn == NULL || !xid_valid(xid))
    return SEER_EPARAM;
  if (conn->is_8i) /* the last argument is one-phase: 1 commits without a prepare */
    return o8i_tpc(conn, "xa_commit_new", xid, 1, one_phase ? 1 : 0, 0, false, NULL);
  uint32_t want = one_phase ? TNS_TPC_TXN_STATE_READ_ONLY : TNS_TPC_TXN_STATE_COMMITTED;
  SeerWriter w;
  SeerStatus st = tpc_build_change_state(conn, &w, TNS_TPC_TXN_COMMIT, want, xid);
  if (st != SEER_OK)
    return st;
  uint32_t state = 0;
  st = tpc_call(conn, &w, false, NULL, NULL, &state);
  free(conn->tpc_context);
  conn->tpc_context = NULL;
  conn->tpc_context_len = 0;
  if (st != SEER_OK)
    return st;
  bool ok = one_phase
                ? (state == TNS_TPC_TXN_STATE_READ_ONLY || state == TNS_TPC_TXN_STATE_COMMITTED)
                : (state == TNS_TPC_TXN_STATE_FORGOTTEN);
  return ok ? SEER_OK : SEER_EPROTO;
}

SeerStatus seer_tpc_rollback(SeerConn *conn, const SeerXid *xid)
{
  if (conn == NULL || !xid_valid(xid))
    return SEER_EPARAM;
  if (conn->is_8i)
    return o8i_tpc(conn, "xa_rollback_new", xid, 0, 0, 0, false, NULL);
  SeerWriter w;
  SeerStatus st =
      tpc_build_change_state(conn, &w, TNS_TPC_TXN_ABORT, TNS_TPC_TXN_STATE_ABORTED, xid);
  if (st != SEER_OK)
    return st;
  uint32_t state = 0;
  st = tpc_call(conn, &w, false, NULL, NULL, &state);
  free(conn->tpc_context);
  conn->tpc_context = NULL;
  conn->tpc_context_len = 0;
  if (st != SEER_OK)
    return st;
  return (state == TNS_TPC_TXN_STATE_ABORTED) ? SEER_OK : SEER_EPROTO;
}

/* ---- Sessionless transactions (§31, 23ai+) ------------------------------ */

/* Send a sessionless TXN_SWITCH (start/resume/detach) and consume its reply.
 * Reuses the XA switch builder + reply parser (the response shape is the same
 * TTI_RPA + trailing OER); the START context blob is read and discarded, since a
 * sessionless transaction is identified by its id, not a replayed context. */
static SeerStatus sessionless_switch(SeerConn *conn, uint32_t op, const SeerXid *xid,
                                     uint32_t flags, uint32_t timeout)
{
  if (conn == NULL)
    return SEER_EPARAM;
  if (conn->field_version < TTC_FIELD_VERSION_23_1)
    return SEER_ENOTIMPL; /* sessionless txns are 23ai+ */
  SeerWriter w;
  SeerStatus st = seer_tpc_build_switch(conn, &w, op, xid, flags, timeout);
  if (st != SEER_OK)
    return st;
  if (op == TNS_TPC_TXN_START) {
    uint8_t *ctx = NULL;
    size_t ctxlen = 0;
    st = tpc_call(conn, &w, true, &ctx, &ctxlen, NULL);
    free(ctx); /* not replayed for sessionless */
  } else {
    st = tpc_call(conn, &w, false, NULL, NULL, NULL);
  }
  return st;
}

/* Reject a sessionless transaction id that is empty or over the 64-byte cap. */
static bool sessionless_id_valid(const uint8_t *id, size_t len)
{
  return id != NULL && len > 0 && len <= TNS_TPC_SESSIONLESS_ID_MAX;
}

SeerStatus seer_txn_begin_sessionless(SeerConn *conn, const uint8_t *txn_id, size_t txn_id_len,
                                      uint32_t timeout)
{
  if (conn == NULL)
    return SEER_EPARAM;
  if (!sessionless_id_valid(txn_id, txn_id_len))
    return SEER_EPARAM;
  if (conn->sessionless_active)
    return SEER_EPARAM; /* one sessionless txn at a time */
  SeerXid xid = {
      .format_id = TNS_TPC_SESSIONLESS_FORMAT_ID,
      .gtrid = txn_id,
      .gtrid_len = (int)txn_id_len,
      .bqual = NULL,
      .bqual_len = 0,
  };
  SeerStatus st = sessionless_switch(conn, TNS_TPC_TXN_START, &xid,
                                     SEER_TPC_BEGIN_NEW | TNS_TPC_FLAGS_SESSIONLESS, timeout);
  if (st == SEER_OK)
    conn->sessionless_active = true;
  return st;
}

SeerStatus seer_txn_resume_sessionless(SeerConn *conn, const uint8_t *txn_id, size_t txn_id_len,
                                       uint32_t timeout)
{
  if (conn == NULL)
    return SEER_EPARAM;
  if (!sessionless_id_valid(txn_id, txn_id_len))
    return SEER_EPARAM;
  if (conn->sessionless_active)
    return SEER_EPARAM;
  SeerXid xid = {
      .format_id = TNS_TPC_SESSIONLESS_FORMAT_ID,
      .gtrid = txn_id,
      .gtrid_len = (int)txn_id_len,
      .bqual = NULL,
      .bqual_len = 0,
  };
  SeerStatus st = sessionless_switch(conn, TNS_TPC_TXN_START, &xid,
                                     SEER_TPC_BEGIN_RESUME | TNS_TPC_FLAGS_SESSIONLESS, timeout);
  if (st == SEER_OK)
    conn->sessionless_active = true;
  return st;
}

SeerStatus seer_txn_suspend_sessionless(SeerConn *conn)
{
  if (conn == NULL)
    return SEER_EPARAM;
  if (!conn->sessionless_active)
    return SEER_EPARAM; /* nothing to suspend */
  /* DETACH with the SESSIONLESS flag and no xid attached. */
  SeerStatus st = sessionless_switch(conn, TNS_TPC_TXN_DETACH, NULL, TNS_TPC_FLAGS_SESSIONLESS, 0);
  if (st == SEER_OK)
    conn->sessionless_active = false;
  return st;
}

/* ---- Advanced Queuing (AQ, #128) ---------------------------------------- */

/* The message-property block (oracledb write_msg_props), shared by single and
 * array enqueue and the array dequeue: SEER_AQ_PROPS_HEAD_SCHEMA with the
 * priority, delay, expiration (-1 = forever) and correlation, the four agent
 * keyword extensions (AGENT_PROTOCOL carries a one-byte 0x00 binary), then
 * SEER_AQ_PROPS_TAIL_SCHEMA, from 21.1 with no shard (-1). */
static void aq_write_msg_props(SeerWriter *w, const SeerSchemaCtx *cx, unsigned priority,
                               unsigned delay, int expiration, const char *correlation)
{
  size_t cn = correlation != NULL ? strlen(correlation) : 0;
  SeerAqPropsMsg p = {.priority = priority,
                      .delay = delay,
                      .expiration = (uint32_t)expiration,
                      .correlation_len = (int64_t)cn,
                      .correlation = {(const uint8_t *)correlation, cn, 0},
                      .n_ext = 4,
                      .ext_lead = 0x0e, /* oracledb's fixed extra byte */
                      .shard_id = 0xFFFFFFFFu};
  seer_schema_encode(SEER_AQ_PROPS_HEAD_SCHEMA, cx, &p, w);
  static const uint8_t zero = 0;
  const SeerAqExtMsg ext[4] = {
      {.keyword = TNS_AQ_EXT_KEYWORD_AGENT_NAME},
      {.keyword = TNS_AQ_EXT_KEYWORD_AGENT_ADDRESS},
      {.bin_len = 1, .bin = {&zero, 1, 0}, .keyword = TNS_AQ_EXT_KEYWORD_AGENT_PROTOCOL},
      {.keyword = TNS_AQ_EXT_KEYWORD_ORIGINAL_MSGID},
  };
  for (size_t i = 0; i < 4; i++)
    seer_schema_encode(SEER_AQ_EXT_SCHEMA, cx, &ext[i], w);
  seer_schema_encode(SEER_AQ_PROPS_TAIL_SCHEMA, cx, &p, w);
}

enum { AQ_PL_RAW = 0, AQ_PL_OBJECT = 1, AQ_PL_JSON = 2 };

/* Build an enqueue (TNS_FUNC_AQ_ENQ), mirroring oracledb AqEnqMessage: the given
 * message properties (priority/delay/expiration/correlation), no recipients,
 * ON_COMMIT visibility, persistent delivery. `payload_kind` selects the payload
 * flags (RAW / object / JSON); `toid16` is the payload type OID (RAW/JSON
 * sentinel or the object type's OID) and `payload` the already-framed body. */
static SeerStatus aq_build_enq(SeerConn *c, SeerWriter *w, const char *qname,
                               const uint8_t *payload, size_t plen, unsigned priority,
                               unsigned delay, int expiration, const char *correlation,
                               int payload_kind, const uint8_t *toid16)
{
  size_t qn = strlen(qname);
  if (!seer_writer_init(w, 256))
    return SEER_ENOMEM;
  seer_ttc_fun_header(c, w, TNS_FUNC_AQ_ENQ);
  SeerSchemaCtx cx = seer_msg_ctx(0, c->field_version, c->server_field_version);
  /* By SEER_AQ_ENQ_HEAD_SCHEMA, the properties and SEER_AQ_ENQ_TAIL_SCHEMA:
   * no recipients, ON_COMMIT visibility, persistent delivery; the payload
   * flags by kind - an object's payload pointer, a RAW's pointer and length,
   * a JSON's own pointer (from 20.1) - and the data section, the queue name,
   * the 16-byte TOID (the RAW / JSON sentinel or the object type's OID) and
   * the payload (raw bytes / the object bind value). */
  SeerAqEnqMsg m = {.qname_ptr = 1,
                    .qname_len = (int64_t)qn,
                    .visibility = TNS_AQ_ENQ_ON_COMMIT,
                    .toid_ptr = 1,
                    .toid_len = 16,
                    .msg_version = TNS_AQ_MESSAGE_VERSION,
                    .payload_ptr = payload_kind == AQ_PL_OBJECT,
                    .raw_ptr = payload_kind == AQ_PL_RAW,
                    .raw_len = payload_kind == AQ_PL_RAW ? (int64_t)plen : 0,
                    .msgid_ptr = 1,
                    .msgid_len = TNS_AQ_MESSAGE_ID_LENGTH,
                    .json_ptr = payload_kind == AQ_PL_JSON,
                    .qname = {(const uint8_t *)qname, qn, 0},
                    .toid = {toid16, 16, 0},
                    .payload = {payload, plen, 0},
                    .payload_len = (int64_t)plen};
  seer_schema_encode(SEER_AQ_ENQ_HEAD_SCHEMA, &cx, &m, w);
  aq_write_msg_props(w, &cx, priority, delay, expiration, correlation);
  seer_schema_encode(SEER_AQ_ENQ_TAIL_SCHEMA, &cx, &m, w);
  return seer_writer_ok(w) ? SEER_OK : SEER_ENOMEM;
}

static SeerStatus aq_read_msgid(const SeerSchemaCtx *cx, SeerReader *r, uint8_t msgid[16]);

/* Send a built AQ enqueue request and read the reply: TTI_RPA then the 16-byte
 * message id, or TTI_OER on error. Frees the writer. */
static SeerStatus aq_enq_send(SeerConn *conn, SeerWriter *w, uint8_t msgid[16])
{
  SeerStatus st = seer_ttc_send(conn, w->buf, w->len);
  seer_writer_free(w);
  if (st != SEER_OK)
    return st;
  uint8_t *resp = NULL;
  size_t rlen = 0;
  st = seer_ttc_recv(conn, &resp, &rlen);
  if (st != SEER_OK)
    return st;
  SeerReader r;
  seer_reader_init(&r, resp, rlen);
  r.sb4_chunks = conn->field_version >= TTC_FIELD_VERSION_12_1;
  SeerStmt tmp = {.conn = conn};
  OerResult oer = {0};
  uint8_t tok = seer_reader_u8(&r);
  if (tok == TTI_RPA) {
    SeerSchemaCtx cx = seer_msg_ctx(0, conn->field_version, conn->server_field_version);
    st = aq_read_msgid(&cx, &r, msgid);
  } else if (tok == TTI_OER) {
    parse_oer(&r, &tmp, &oer);
    st = SEER_EDB;
  } else {
    st = SEER_EPROTO;
  }
  free_batch_errors(&tmp);
  free(resp);
  return st;
}

/* 9i and 8i: AQ through PL/SQL on DBMS_AQ, the route their era's clients have
 * (seerdb PROTOCOL.md §29: 9.2 closes a thin session on the native enqueue,
 * and 8.1.7 has no native form in any reference client). Every option is a
 * field of DBMS_AQ's PL/SQL records, set in the block (#173). */
#define PLSQL_AQ_MAX_RAW 32512 /* the most RAW a 9i block takes or returns (§19.3.1) */

static SeerStatus plsql_aq_stmt(SeerConn *c, const char *sql, SeerStmt **out)
{
  *out = NULL;
  return seer_stmt_prepare(c, sql, out);
}

static SeerStatus plsql_aq_text(SeerStmt *s, int param, const char *v)
{
  if (v == NULL || v[0] == '\0')
    return seer_stmt_bind_null_typed(s, param, ORA_TYPE_VARCHAR);
  return seer_stmt_bind_text(s, param, v, (int)strlen(v));
}

static SeerStatus plsql_aq_enq(SeerConn *c, const char *queue_name, const uint8_t *payload,
                               size_t payload_len, const SeerAqEnqOptions *opt, uint8_t msgid[16])
{
  static const char SQL[] =
      "DECLARE eo DBMS_AQ.ENQUEUE_OPTIONS_T; mp DBMS_AQ.MESSAGE_PROPERTIES_T; m RAW(16); "
      "BEGIN mp.priority := :1; mp.delay := :2; mp.expiration := :3; mp.correlation := :4; "
      "DBMS_AQ.ENQUEUE(:5, eo, mp, :6, m); :7 := m; END;";
  if (payload_len > PLSQL_AQ_MAX_RAW)
    return SEER_EPARAM;
  SeerStmt *s = NULL;
  SeerStatus st = plsql_aq_stmt(c, SQL, &s);
  if (st == SEER_OK)
    st = seer_stmt_bind_int64(s, 1, opt ? (int64_t)opt->priority : 0);
  if (st == SEER_OK)
    st = seer_stmt_bind_int64(s, 2, opt ? (int64_t)opt->delay : 0);
  if (st == SEER_OK) /* -1 is DBMS_AQ.NEVER */
    st = seer_stmt_bind_int64(s, 3, opt ? (int64_t)opt->expiration : -1);
  if (st == SEER_OK)
    st = plsql_aq_text(s, 4, opt ? opt->correlation : NULL);
  if (st == SEER_OK)
    st = seer_stmt_bind_text(s, 5, queue_name, (int)strlen(queue_name));
  if (st == SEER_OK)
    st = seer_stmt_bind_raw(s, 6, payload, (int)payload_len);
  if (st == SEER_OK)
    st = seer_stmt_bind_out(s, 7, ORA_TYPE_RAW, 16);
  if (st == SEER_OK)
    st = seer_stmt_execute(s);
  if (st == SEER_OK && msgid != NULL) {
    const void *d = NULL;
    size_t n = 0;
    int isnull = 0, isbin = 0;
    if (seer_stmt_out_data(s, 7, &d, &n, &isnull, &isbin) == SEER_OK && !isnull && n == 16)
      memcpy(msgid, d, 16);
    else
      st = SEER_EPROTO;
  }
  seer_stmt_close(s);
  return st;
}

static SeerStatus plsql_aq_deq(SeerConn *c, const char *queue_name, const SeerAqDeqOptions *opt,
                               uint8_t **payload, size_t *payload_len, uint8_t msgid[16])
{
  static const char SQL[] =
      "DECLARE do DBMS_AQ.DEQUEUE_OPTIONS_T; mp DBMS_AQ.MESSAGE_PROPERTIES_T; m RAW(16); "
      "p RAW(32767); BEGIN do.wait := :1; do.navigation := DBMS_AQ.FIRST_MESSAGE; "
      "IF :2 = 1 THEN do.dequeue_mode := DBMS_AQ.BROWSE; END IF; do.correlation := :3; "
      "do.consumer_name := :4; DBMS_AQ.DEQUEUE(:5, do, mp, p, m); :6 := p; :7 := m; END;";
  SeerStmt *s = NULL;
  SeerStatus st = plsql_aq_stmt(c, SQL, &s);
  if (st == SEER_OK) /* 0 is DBMS_AQ.NO_WAIT */
    st = seer_stmt_bind_int64(s, 1, opt ? (int64_t)opt->wait_seconds : 0);
  if (st == SEER_OK)
    st = seer_stmt_bind_int64(s, 2, (opt && opt->browse) ? 1 : 0);
  if (st == SEER_OK)
    st = plsql_aq_text(s, 3, opt ? opt->correlation : NULL);
  if (st == SEER_OK)
    st = plsql_aq_text(s, 4, opt ? opt->consumer : NULL);
  if (st == SEER_OK)
    st = seer_stmt_bind_text(s, 5, queue_name, (int)strlen(queue_name));
  if (st == SEER_OK)
    st = seer_stmt_bind_out(s, 6, ORA_TYPE_RAW, PLSQL_AQ_MAX_RAW);
  if (st == SEER_OK)
    st = seer_stmt_bind_out(s, 7, ORA_TYPE_RAW, 16);
  if (st == SEER_OK)
    st = seer_stmt_execute(s);
  if (st == SEER_EDB) {
    const char *e = seer_last_error(c);
    if (e != NULL && (strncmp(e, "ORA-25228", 9) == 0 || strncmp(e, "ORA-25254", 9) == 0))
      st = SEER_ENODATA; /* empty queue, or the wait ran out */
  }
  if (st == SEER_OK) {
    const void *d = NULL;
    size_t n = 0;
    int isnull = 0, isbin = 0;
    if (seer_stmt_out_data(s, 6, &d, &n, &isnull, &isbin) != SEER_OK) {
      st = SEER_EPROTO;
    } else if (payload != NULL) {
      uint8_t *pl = malloc(n ? n : 1);
      if (pl == NULL) {
        st = SEER_ENOMEM;
      } else {
        if (n > 0 && !isnull)
          memcpy(pl, d, n);
        *payload = pl;
        if (payload_len != NULL)
          *payload_len = isnull ? 0 : n;
      }
    }
    if (st == SEER_OK && msgid != NULL &&
        (seer_stmt_out_data(s, 7, &d, &n, &isnull, &isbin) != SEER_OK || isnull || n != 16))
      st = SEER_EPROTO;
    else if (st == SEER_OK && msgid != NULL)
      memcpy(msgid, d, 16);
  }
  seer_stmt_close(s);
  return st;
}

/* Whether `s` is a plain SQL identifier - letters, digits, _ $ # - safe to
 * name a type with in a block's text (an object queue's payload type). */
static bool plsql_ident_ok(const char *s)
{
  size_t n = s != NULL ? strlen(s) : 0;
  if (n == 0 || n > 128)
    return false;
  for (size_t i = 0; i < n; i++) {
    unsigned char ch = (unsigned char)s[i];
    if (!(isalnum(ch) || ch == '_' || ch == '$' || ch == '#'))
      return false;
  }
  return true;
}

/* An object payload on 8i and 9i (#172): DBMS_AQ.ENQUEUE / DEQUEUE in a block,
 * the object bound IN to the enqueue and OUT of the dequeue - the object binds
 * of #236 - where 10g+ speaks AQ's own calls. */
static SeerStatus plsql_aq_enq_object(SeerConn *c, const char *queue_name, const char *schema,
                                      const char *type_name, const char *const *attr_values,
                                      int n_attrs, uint8_t msgid[16])
{
  static const char SQL[] =
      "DECLARE eo DBMS_AQ.ENQUEUE_OPTIONS_T; mp DBMS_AQ.MESSAGE_PROPERTIES_T; "
      "m RAW(16); BEGIN DBMS_AQ.ENQUEUE(:1, eo, mp, :2, m); :3 := m; END;";
  SeerStmt *s = NULL;
  SeerStatus st = plsql_aq_stmt(c, SQL, &s);
  if (st == SEER_OK)
    st = seer_stmt_bind_text(s, 1, queue_name, (int)strlen(queue_name));
  if (st == SEER_OK)
    st = seer_stmt_bind_object(s, 2, schema, type_name, attr_values, n_attrs);
  if (st == SEER_OK)
    st = seer_stmt_bind_out(s, 3, ORA_TYPE_RAW, 16);
  if (st == SEER_OK)
    st = seer_stmt_execute(s);
  if (st == SEER_OK && msgid != NULL) {
    const void *d = NULL;
    size_t n = 0;
    int isnull = 0, isbin = 0;
    if (seer_stmt_out_data(s, 3, &d, &n, &isnull, &isbin) == SEER_OK && !isnull && n == 16)
      memcpy(msgid, d, 16);
    else
      st = SEER_EPROTO;
  }
  seer_stmt_close(s);
  return st;
}

static SeerStatus plsql_aq_deq_object(SeerConn *c, const char *queue_name, const char *schema,
                                      const char *type_name, uint32_t wait_seconds, char **out_text,
                                      uint8_t msgid[16])
{
  /* The payload's variable needs its type named in the text: refused unless
   * the names are plain identifiers. */
  if (!plsql_ident_ok(schema) || !plsql_ident_ok(type_name))
    return SEER_EPARAM;
  char sql[512];
  snprintf(sql, sizeof sql,
           "DECLARE do DBMS_AQ.DEQUEUE_OPTIONS_T; mp DBMS_AQ.MESSAGE_PROPERTIES_T; m RAW(16); "
           "p %s.%s; BEGIN do.wait := :1; do.navigation := DBMS_AQ.FIRST_MESSAGE; "
           "DBMS_AQ.DEQUEUE(:2, do, mp, p, m); :3 := p; :4 := m; END;",
           schema, type_name);
  SeerStmt *s = NULL;
  SeerStatus st = plsql_aq_stmt(c, sql, &s);
  if (st == SEER_OK) /* 0 is DBMS_AQ.NO_WAIT */
    st = seer_stmt_bind_int64(s, 1, (int64_t)wait_seconds);
  if (st == SEER_OK)
    st = seer_stmt_bind_text(s, 2, queue_name, (int)strlen(queue_name));
  if (st == SEER_OK)
    st = seer_stmt_bind_object_out(s, 3, schema, type_name);
  if (st == SEER_OK)
    st = seer_stmt_bind_out(s, 4, ORA_TYPE_RAW, 16);
  if (st == SEER_OK)
    st = seer_stmt_execute(s);
  if (st == SEER_EDB) {
    const char *e = seer_last_error(c);
    if (e != NULL && (strncmp(e, "ORA-25228", 9) == 0 || strncmp(e, "ORA-25254", 9) == 0))
      st = SEER_ENODATA; /* empty queue, or the wait ran out */
  }
  const void *d = NULL;
  size_t n = 0;
  int isnull = 0, isbin = 0;
  if (st == SEER_OK && out_text != NULL &&
      seer_stmt_out_data(s, 3, &d, &n, &isnull, &isbin) == SEER_OK && !isnull) {
    *out_text = malloc(n + 1);
    if (*out_text == NULL) {
      st = SEER_ENOMEM;
    } else {
      memcpy(*out_text, d, n);
      (*out_text)[n] = '\0';
    }
  }
  if (st == SEER_OK && msgid != NULL) {
    if (seer_stmt_out_data(s, 4, &d, &n, &isnull, &isbin) == SEER_OK && !isnull && n == 16)
      memcpy(msgid, d, 16);
    else
      st = SEER_EPROTO;
  }
  seer_stmt_close(s);
  return st;
}

SeerStatus seer_aq_enq_raw_opt(SeerConn *conn, const char *queue_name, const uint8_t *payload,
                               size_t payload_len, const SeerAqEnqOptions *opt, uint8_t msgid[16])
{
  if (conn == NULL || queue_name == NULL)
    return SEER_EPARAM;
  if (conn->field_version < TTC_FIELD_VERSION_10_2)
    return plsql_aq_enq(conn, queue_name, payload, payload_len, opt, msgid);

  unsigned pri = opt ? opt->priority : 0;
  unsigned dly = opt ? opt->delay : 0;
  int exp = opt ? opt->expiration : -1;
  const char *cor = opt ? opt->correlation : NULL;

  uint8_t raw_toid[16] = {0};
  raw_toid[15] = TNS_AQ_RAW_TOID_SENTINEL;

  SeerWriter w;
  SeerStatus st = aq_build_enq(conn, &w, queue_name, payload, payload_len, pri, dly, exp, cor,
                               AQ_PL_RAW, raw_toid);
  if (st != SEER_OK) {
    seer_writer_free(&w);
    return st;
  }
  return aq_enq_send(conn, &w, msgid);
}

/* Enqueue a SQL object value (flat or nested-flattened, scalar leaf attributes
 * as text) to an object-payload queue. The payload TOID is the type's OID and the
 * body is the object bind value. 12c+. */
SeerStatus seer_aq_enq_object(SeerConn *conn, const char *queue_name, const char *type_schema,
                              const char *type_name, const char *const *attr_values, int n_attrs,
                              uint8_t msgid[16])
{
  if (conn == NULL || queue_name == NULL || type_schema == NULL || type_name == NULL ||
      (n_attrs > 0 && attr_values == NULL))
    return SEER_EPARAM;
  if (conn->field_version < TTC_FIELD_VERSION_10_2) /* 9i and 8i: a block (#172) */
    return plsql_aq_enq_object(conn, queue_name, type_schema, type_name, attr_values, n_attrs,
                               msgid);

  uint8_t oid[16];
  SeerWriter img;
  SeerStatus st = obj_build_image(conn, type_schema, type_name, attr_values, n_attrs, oid, &img);
  if (st != SEER_OK)
    return st;

  SeerWriter bv;
  if (!seer_writer_init(&bv, 64 + img.len)) {
    seer_writer_free(&img);
    return SEER_ENOMEM;
  }
  st = obj_encode_bind_value(&bv, oid, img.buf, img.len, conn->field_version);
  seer_writer_free(&img);
  if (st != SEER_OK) {
    seer_writer_free(&bv);
    return st;
  }

  SeerWriter w;
  st = aq_build_enq(conn, &w, queue_name, bv.buf, bv.len, 0, 0, -1, NULL, AQ_PL_OBJECT, oid);
  seer_writer_free(&bv);
  if (st != SEER_OK) {
    seer_writer_free(&w);
    return st;
  }
  return aq_enq_send(conn, &w, msgid);
}

/* Enqueue a JSON document (given as JSON text) to a JSON-payload queue: the text
 * is parsed and encoded to OSON, then wrapped in the AQ JSON descriptor. Needs a
 * server with native JSON queues (fv >= 20.1; SEER_ENOTIMPL otherwise). */
SeerStatus seer_aq_enq_json(SeerConn *conn, const char *queue_name, const char *json_text,
                            uint8_t msgid[16])
{
  if (conn == NULL || queue_name == NULL || json_text == NULL)
    return SEER_EPARAM;
  if (conn->field_version < TTC_FIELD_VERSION_20_1)
    return SEER_ENOTIMPL;

  uint8_t *oson = NULL;
  size_t osonlen = 0;
  SeerStatus st = seer_json_to_oson(json_text, &oson, &osonlen);
  if (st != SEER_OK)
    return st;
  if (osonlen > 0xFFFF) {
    free(oson);
    return SEER_EPARAM;
  }

  /* payload: 18-byte JSON descriptor + ub2 OSON length + 22 zero bytes + the
   * OSON image (bytes-with-length framed). */
  static const uint8_t JSON_DESC[18] = {
      0x01, 0x28, 0x00, 0x26, 0x00, 0x04, 0x61, 0x08, 0x00,
      0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  };
  SeerWriter pw;
  if (!seer_writer_init(&pw, 64 + osonlen)) {
    free(oson);
    return SEER_ENOMEM;
  }
  seer_writer_bytes(&pw, JSON_DESC, sizeof JSON_DESC);
  seer_writer_u8(&pw, (uint8_t)(osonlen >> 8));
  seer_writer_u8(&pw, (uint8_t)(osonlen & 0xFF));
  for (int i = 0; i < 22; i++)
    seer_writer_u8(&pw, 0);
  obj_append_chr(&pw, oson, osonlen, conn->field_version);
  free(oson);
  if (!seer_writer_ok(&pw)) {
    seer_writer_free(&pw);
    return SEER_ENOMEM;
  }

  uint8_t json_toid[16] = {0};
  json_toid[15] = TNS_AQ_JSON_TOID_SENTINEL;

  SeerWriter w;
  st = aq_build_enq(conn, &w, queue_name, pw.buf, pw.len, 0, 0, -1, NULL, AQ_PL_JSON, json_toid);
  seer_writer_free(&pw);
  if (st != SEER_OK) {
    seer_writer_free(&w);
    return st;
  }
  return aq_enq_send(conn, &w, msgid);
}

SeerStatus seer_aq_enq_raw(SeerConn *conn, const char *queue_name, const uint8_t *payload,
                           size_t payload_len, uint8_t msgid[16])
{
  return seer_aq_enq_raw_opt(conn, queue_name, payload, payload_len, NULL, msgid);
}

/* Consume one length-prefixed AQ string (read_str_with_length): a ub4 count,
 * then the 0xFE-aware DALC bytes when non-zero. We only need to skip these in a
 * RAW message's properties and payload header. */
/* Build a RAW-payload dequeue (TNS_FUNC_AQ_DEQ) by SEER_AQ_DEQ_SCHEMA: the
 * given mode (REMOVE/BROWSE), FIRST_MSG navigation, ON_COMMIT visibility,
 * wait, and optional consumer name / correlation filter. Mirrors oracledb
 * AqDeqMessage. */
static SeerStatus aq_build_deq(SeerConn *c, SeerWriter *w, const char *qname, uint32_t mode,
                               uint32_t wait_seconds, const char *correlation, const char *consumer,
                               const uint8_t *toid16)
{
  size_t qn = strlen(qname);
  size_t un = consumer != NULL ? strlen(consumer) : 0;
  size_t cn = correlation != NULL ? strlen(correlation) : 0;
  if (!seer_writer_init(w, 192))
    return SEER_ENOMEM;
  seer_ttc_fun_header(c, w, TNS_FUNC_AQ_DEQ);
  SeerAqDeqMsg m = {.qname_ptr = 1,
                    .qname_len = (int64_t)qn,
                    .props_ptr = 1,
                    .props_len_ptr = 1,
                    .recip_ptr = 1,
                    .recip_len_ptr = 1,
                    .consumer_ptr = un > 0,
                    .consumer_len = (int64_t)un,
                    .mode = mode,
                    .navigation = TNS_AQ_DEQ_FIRST_MSG, /* each call is one-shot */
                    .visibility = TNS_AQ_DEQ_ON_COMMIT,
                    .wait = wait_seconds,
                    .corr_ptr = cn > 0,
                    .corr_len = (int64_t)cn,
                    .toid_ptr = 1,
                    .toid_len = 16,
                    .msg_version = TNS_AQ_MESSAGE_VERSION,
                    .payload_ptr = 1,
                    .msgid_ptr = 1,
                    .msgid_len = TNS_AQ_MESSAGE_ID_LENGTH,
                    .shard_id = 0xFFFFFFFFu, /* -1 */
                    .qname = {(const uint8_t *)qname, qn, 0},
                    .consumer = {(const uint8_t *)consumer, un, 0},
                    .correlation = {(const uint8_t *)correlation, cn, 0},
                    .toid = {toid16, 16, 0}};
  SeerSchemaCtx cx = seer_msg_ctx(0, c->field_version, c->server_field_version);
  seer_schema_encode(SEER_AQ_DEQ_SCHEMA, &cx, &m, w);
  return seer_writer_ok(w) ? SEER_OK : SEER_ENOMEM;
}

/* Pass over a reply's message-property block, SEER_AQ_PROPS_SCHEMA (parse
 * order mirrors oracledb _parse_aq_msg_props); we keep only the payload and
 * msgid. */
static SeerStatus aq_skip_msg_props(const SeerSchemaCtx *cx, SeerReader *r)
{
  SeerAqPropsMsg p = {0};
  bool ok = seer_schema_decode(SEER_AQ_PROPS_SCHEMA, cx, r, &p);
  seer_schema_free(SEER_AQ_PROPS_SCHEMA, &p);
  return ok ? SEER_OK : SEER_EPROTO;
}

/* Send a dequeue request and consume the reply up to the payload: the empty-queue
 * OER (-> SEER_ENODATA), the RPA token, the body-length gate, the message
 * properties, and the recipient count. On SEER_OK *r is left positioned at the
 * payload; *resp must be freed by the caller in all cases. Frees the writer. */
static SeerStatus aq_deq_exchange(SeerConn *conn, SeerWriter *w, SeerReader *r, uint8_t **resp,
                                  size_t *rlen)
{
  *resp = NULL;
  *rlen = 0;
  SeerStatus st = seer_ttc_send(conn, w->buf, w->len);
  seer_writer_free(w);
  if (st != SEER_OK)
    return st;
  st = seer_ttc_recv(conn, resp, rlen);
  if (st != SEER_OK)
    return st;
  uint8_t fv = conn->field_version;
  seer_reader_init(r, *resp, *rlen);
  r->sb4_chunks = fv >= TTC_FIELD_VERSION_12_1;
  SeerSchemaCtx cx = seer_msg_ctx(0, fv, conn->server_field_version);
  uint8_t tok = seer_reader_u8(r);
  if (tok == TTI_OER) { /* empty queue / timeout / error */
    SeerStmt tmp = {.conn = conn};
    OerResult oer = {0};
    parse_oer(r, &tmp, &oer);
    free_batch_errors(&tmp);
    return (oer.err_code == ORA_AQ_NO_MESSAGE || oer.err_code == ORA_AQ_DEQ_TIMEOUT) ? SEER_ENODATA
                                                                                     : SEER_EDB;
  }
  if (tok != TTI_RPA)
    return SEER_EPROTO;
  /* SEER_AQ_DEQ_REPLY_HEAD_SCHEMA, the properties, then
   * SEER_AQ_DEQ_REPLY_MID_SCHEMA */
  SeerAqReplyMsg m = {0};
  (void)seer_schema_decode(SEER_AQ_DEQ_REPLY_HEAD_SCHEMA, &cx, r, &m);
  if (m.props_len == 0) /* no message body */
    return SEER_ENODATA;
  if (aq_skip_msg_props(&cx, r) != SEER_OK)
    return SEER_EPROTO;
  (void)seer_schema_decode(SEER_AQ_DEQ_REPLY_MID_SCHEMA, &cx, r, &m);
  return SEER_OK;
}

/* Read the RAW-form payload from a dequeue reply positioned at the payload:
 * SEER_OBJECT_HEAD_SCHEMA - toid/oid/snapshot/version, image_length, flags -
 * then, past an image's 4-byte header alone, SEER_OBJECT_IMAGE_SCHEMA: the
 * payload is image[4:image_length]. On SEER_OK *out is malloc'd (NULL/0 for
 * an empty payload); the caller frees it. For a JSON queue this payload is
 * itself an OSON image. */
static SeerStatus aq_read_payload(const SeerSchemaCtx *cx, SeerReader *r, uint8_t **out,
                                  size_t *outlen)
{
  *out = NULL;
  *outlen = 0;
  SeerObjectMsg m = {0};
  bool ok = seer_schema_decode(SEER_OBJECT_HEAD_SCHEMA, cx, r, &m);
  seer_schema_free(SEER_OBJECT_HEAD_SCHEMA, &m);
  if (!ok)
    return SEER_EPROTO;
  if (m.image_len <= 4)
    return SEER_OK; /* empty payload */
  if (!seer_schema_decode(SEER_OBJECT_IMAGE_SCHEMA, cx, r, &m)) {
    seer_schema_free(SEER_OBJECT_IMAGE_SCHEMA, &m);
    return SEER_EPROTO;
  }
  SeerStatus st = SEER_OK;
  if ((size_t)m.image_len > m.image.n) {
    st = SEER_EPROTO;
  } else {
    size_t plen = (size_t)m.image_len - 4;
    uint8_t *p = malloc(plen ? plen : 1);
    if (p == NULL) {
      st = SEER_ENOMEM;
    } else {
      memcpy(p, m.image.p + 4, plen);
      *out = p;
      *outlen = plen;
    }
  }
  seer_schema_free(SEER_OBJECT_IMAGE_SCHEMA, &m);
  return st;
}

/* Read the 16-byte message id that ends an AQ reply, SEER_AQ_MSGID_SCHEMA,
 * into `msgid` (when given). */
static SeerStatus aq_read_msgid(const SeerSchemaCtx *cx, SeerReader *r, uint8_t msgid[16])
{
  SeerAqReplyMsg m = {.msgid_len = TNS_AQ_MESSAGE_ID_LENGTH};
  if (!seer_schema_decode(SEER_AQ_MSGID_SCHEMA, cx, r, &m))
    return SEER_EPROTO;
  if (msgid != NULL)
    memcpy(msgid, m.msgid.p, TNS_AQ_MESSAGE_ID_LENGTH);
  return SEER_OK;
}

SeerStatus seer_aq_deq_raw_opt(SeerConn *conn, const char *queue_name, const SeerAqDeqOptions *opt,
                               uint8_t **payload, size_t *payload_len, uint8_t msgid[16])
{
  if (conn == NULL || queue_name == NULL)
    return SEER_EPARAM;
  if (payload != NULL)
    *payload = NULL;
  if (payload_len != NULL)
    *payload_len = 0;
  if (conn->field_version < TTC_FIELD_VERSION_10_2)
    return plsql_aq_deq(conn, queue_name, opt, payload, payload_len, msgid);

  uint32_t mode = (opt && opt->browse) ? TNS_AQ_DEQ_BROWSE : TNS_AQ_DEQ_REMOVE;
  uint32_t wait = opt ? opt->wait_seconds : 0;
  const char *cor = opt ? opt->correlation : NULL;
  const char *cons = opt ? opt->consumer : NULL;
  uint8_t raw_toid[16] = {0};
  raw_toid[15] = TNS_AQ_RAW_TOID_SENTINEL;

  SeerWriter w;
  SeerStatus st = aq_build_deq(conn, &w, queue_name, mode, wait, cor, cons, raw_toid);
  if (st != SEER_OK) {
    seer_writer_free(&w);
    return st;
  }

  SeerReader r;
  uint8_t *resp = NULL;
  size_t rlen = 0;
  st = aq_deq_exchange(conn, &w, &r, &resp, &rlen);
  if (st != SEER_OK) {
    free(resp);
    return st;
  }

  uint8_t *pl = NULL;
  size_t pll = 0;
  SeerSchemaCtx cx = seer_msg_ctx(0, conn->field_version, conn->server_field_version);
  st = aq_read_payload(&cx, &r, &pl, &pll);
  if (st == SEER_OK) {
    if (payload != NULL) {
      *payload = pl;
      if (payload_len)
        *payload_len = pll;
    } else
      free(pl);
    st = aq_read_msgid(&cx, &r, msgid);
  }
  free(resp);
  return st;
}

SeerStatus seer_aq_deq_raw(SeerConn *conn, const char *queue_name, uint32_t wait_seconds,
                           uint8_t **payload, size_t *payload_len, uint8_t msgid[16])
{
  SeerAqDeqOptions opt = {.wait_seconds = wait_seconds};
  return seer_aq_deq_raw_opt(conn, queue_name, &opt, payload, payload_len, msgid);
}

/* Dequeue an object-payload message (REMOVE, the given wait). The decoded object
 * is rendered to text ("v1, v2, ...", same as the object fetch path) into
 * *out_text (caller frees). SEER_ENODATA if no message was available. 12c+. */
SeerStatus seer_aq_deq_object(SeerConn *conn, const char *queue_name, const char *type_schema,
                              const char *type_name, uint32_t wait_seconds, char **out_text,
                              uint8_t msgid[16])
{
  if (conn == NULL || queue_name == NULL || type_schema == NULL || type_name == NULL)
    return SEER_EPARAM;
  if (out_text != NULL)
    *out_text = NULL;
  if (conn->field_version < TTC_FIELD_VERSION_10_2) /* 9i and 8i: a block (#172) */
    return plsql_aq_deq_object(conn, queue_name, type_schema, type_name, wait_seconds, out_text,
                               msgid);

  uint8_t oid[16];
  SeerStatus st = obj_lookup_oid(conn, type_schema, type_name, oid);
  if (st != SEER_OK)
    return st;
  uint8_t *types = NULL;
  int ntypes = 0, cap = 0;
  build_obj_layout(conn, type_schema, type_name, &types, NULL, &ntypes, &cap, 0);

  SeerWriter w;
  st = aq_build_deq(conn, &w, queue_name, TNS_AQ_DEQ_REMOVE, wait_seconds, NULL, NULL, oid);
  if (st != SEER_OK) {
    free(types);
    seer_writer_free(&w);
    return st;
  }

  SeerReader r;
  uint8_t *resp = NULL;
  size_t rlen = 0;
  st = aq_deq_exchange(conn, &w, &r, &resp, &rlen);
  if (st != SEER_OK) {
    free(types);
    free(resp);
    return st;
  }

  /* object payload: read the object image, decode it with the type's layout */
  uint8_t *img = NULL;
  size_t imglen = 0;
  st = read_object_image(&r, &img, &imglen);
  if (st == SEER_OK && img != NULL && ntypes > 0) {
    SeerCell cell = {0};
    if (decode_object_image(conn, img, imglen, types, NULL, ntypes, &cell) == SEER_OK &&
        out_text != NULL) {
      *out_text = cell.data; /* transfer ownership */
      cell.data = NULL;
    }
    free(cell.data);
  }
  free(img);
  if (st == SEER_OK) {
    SeerSchemaCtx cx = seer_msg_ctx(0, conn->field_version, conn->server_field_version);
    st = aq_read_msgid(&cx, &r, msgid);
  }
  free(types);
  free(resp);
  return st;
}

/* Dequeue a JSON-payload message (REMOVE, the given wait). The OSON payload is
 * decoded to JSON text into *out_text (caller frees). SEER_ENODATA if no message
 * was available. Needs native JSON queues (fv >= 20.1). */
SeerStatus seer_aq_deq_json(SeerConn *conn, const char *queue_name, uint32_t wait_seconds,
                            char **out_text, uint8_t msgid[16])
{
  if (conn == NULL || queue_name == NULL)
    return SEER_EPARAM;
  if (conn->field_version < TTC_FIELD_VERSION_20_1)
    return SEER_ENOTIMPL;
  if (out_text != NULL)
    *out_text = NULL;

  uint8_t json_toid[16] = {0};
  json_toid[15] = TNS_AQ_JSON_TOID_SENTINEL;

  SeerWriter w;
  SeerStatus st =
      aq_build_deq(conn, &w, queue_name, TNS_AQ_DEQ_REMOVE, wait_seconds, NULL, NULL, json_toid);
  if (st != SEER_OK) {
    seer_writer_free(&w);
    return st;
  }

  SeerReader r;
  uint8_t *resp = NULL;
  size_t rlen = 0;
  st = aq_deq_exchange(conn, &w, &r, &resp, &rlen);
  if (st != SEER_OK) {
    free(resp);
    return st;
  }

  /* the payload is an OSON image; decode it to JSON text */
  uint8_t *oson = NULL;
  size_t osonlen = 0;
  SeerSchemaCtx cx = seer_msg_ctx(0, conn->field_version, conn->server_field_version);
  st = aq_read_payload(&cx, &r, &oson, &osonlen);
  if (st == SEER_OK) {
    if (oson != NULL && out_text != NULL) {
      char *txt = NULL;
      if (seer_decode_oson(oson, osonlen, &txt) == SEER_OK)
        *out_text = txt;
      else
        free(txt);
    }
    free(oson);
    st = aq_read_msgid(&cx, &r, msgid);
  }
  free(resp);
  return st;
}

/* Build a bulk RAW enqueue (TNS_FUNC_ARRAY_AQ): a ROW_HEADER (queue name + TOID +
 * version/flags) then one ROW_DATA per message (props + visibility + RAW length +
 * bytes), closed by a STATUS marker. Mirrors oracledb _aq_write_array_enq. */
/* An array reply's iteration up to its payload: SEER_AQ_ITER_HEAD_SCHEMA, the
 * properties when there are any, and SEER_AQ_ITER_MID_SCHEMA (the
 * recipients, the payload's presence). */
static SeerStatus aq_iter_head(const SeerSchemaCtx *cx, SeerReader *r, SeerAqReplyMsg *m)
{
  if (!seer_schema_decode(SEER_AQ_ITER_HEAD_SCHEMA, cx, r, m))
    return SEER_EPROTO;
  if (m->props_len > 0 && aq_skip_msg_props(cx, r) != SEER_OK)
    return SEER_EPROTO;
  return seer_schema_decode(SEER_AQ_ITER_MID_SCHEMA, cx, r, m) ? SEER_OK : SEER_EPROTO;
}

static SeerStatus aq_build_array_enq_raw(SeerConn *c, SeerWriter *w, const char *qname, int count,
                                         const uint8_t *const *payloads, const size_t *lens)
{
  size_t qn = strlen(qname);
  uint8_t raw_toid[16] = {0};
  raw_toid[15] = TNS_AQ_RAW_TOID_SENTINEL;
  if (!seer_writer_init(w, 256))
    return SEER_ENOMEM;
  seer_ttc_fun_header(c, w, TNS_FUNC_ARRAY_AQ);
  SeerSchemaCtx cx = seer_msg_ctx(0, c->field_version, c->server_field_version);
  /* SEER_AQ_ARRAY_HEAD_SCHEMA with the enqueue's operands (no input
   * parameters, the output's pointer, the iteration count's pointer, no
   * shard), the enqueue's head, then a row per message with default
   * properties, and the closing status. */
  SeerAqArrayMsg m = {.ret_flags = TNS_AQ_ARRAY_RETURN_MSGID,
                      .out_ptr = 1,
                      .op = TNS_AQ_ARRAY_ENQ,
                      .iters_ptr = 1,
                      .shard_id = 0xFFFF,
                      .iters = count,
                      .rxh = TTI_RXH,
                      .qname_len = (int64_t)qn,
                      .qname = {(const uint8_t *)qname, qn, 0},
                      .toid = {raw_toid, 16, 0},
                      .toid_len = 16,
                      .msg_version = TNS_AQ_MESSAGE_VERSION,
                      .rxd = TTI_RXD,
                      .visibility = TNS_AQ_ENQ_ON_COMMIT,
                      .sta = TTI_STA};
  seer_schema_encode(SEER_AQ_ARRAY_HEAD_SCHEMA, &cx, &m, w);
  seer_schema_encode(SEER_AQ_ARRAY_ENQ_HEAD_SCHEMA, &cx, &m, w);
  for (int i = 0; i < count; i++) {
    seer_schema_encode(SEER_AQ_ARRAY_ENQ_ROW_SCHEMA, &cx, &m, w);
    aq_write_msg_props(w, &cx, 0, 0, -1, NULL);
    m.raw_len = (int64_t)lens[i];
    m.payload = (SeerBytes){payloads[i], lens[i], 0};
    seer_schema_encode(SEER_AQ_ARRAY_ENQ_ROW_TAIL_SCHEMA, &cx, &m, w);
  }
  seer_schema_encode(SEER_AQ_ARRAY_ENQ_END_SCHEMA, &cx, &m, w);
  return seer_writer_ok(w) ? SEER_OK : SEER_ENOMEM;
}

SeerStatus seer_aq_enq_raw_array(SeerConn *conn, const char *queue_name, int count,
                                 const uint8_t *const *payloads, const size_t *lens,
                                 uint8_t *msgids)
{
  if (conn == NULL || queue_name == NULL || count <= 0 || payloads == NULL || lens == NULL)
    return SEER_EPARAM;
  if (conn->field_version < TTC_FIELD_VERSION_12_2) {
    /* No reference client sends ARRAY_AQ (145) before 12c, so its form there is
     * unknown: enqueue one message at a time instead. Visibility is on commit,
     * so the outcome in the transaction is the same (#187). */
    for (int i = 0; i < count; i++) {
      SeerStatus st = seer_aq_enq_raw(conn, queue_name, payloads[i], lens[i],
                                      msgids != NULL ? msgids + 16 * (size_t)i : NULL);
      if (st != SEER_OK)
        return st;
    }
    return SEER_OK;
  }

  SeerWriter w;
  SeerStatus st = aq_build_array_enq_raw(conn, &w, queue_name, count, payloads, lens);
  if (st != SEER_OK) {
    seer_writer_free(&w);
    return st;
  }
  st = seer_ttc_send(conn, w.buf, w.len);
  seer_writer_free(&w);
  if (st != SEER_OK)
    return st;

  uint8_t *resp = NULL;
  size_t rlen = 0;
  st = seer_ttc_recv(conn, &resp, &rlen);
  if (st != SEER_OK)
    return st;

  SeerReader r;
  seer_reader_init(&r, resp, rlen);
  r.sb4_chunks = conn->field_version >= TTC_FIELD_VERSION_12_1;
  SeerStmt tmp = {.conn = conn};
  OerResult oer = {0};
  uint8_t tok = seer_reader_u8(&r);
  if (tok == TTI_OER) {
    parse_oer(&r, &tmp, &oer);
    st = SEER_EDB;
    goto out;
  }
  if (tok != TTI_RPA) {
    st = SEER_EPROTO;
    goto out;
  }

  /* Response: ub4 iteration count, then per iteration props/recipients/payload
   * flags (0 for a bare enqueue ack), the returned message-id block, and two
   * trailing ub2s. The msgid block holds count*16 bytes. */
  SeerSchemaCtx cx = seer_msg_ctx(0, conn->field_version, conn->server_field_version);
  SeerAqReplyMsg m = {0};
  bool ok = seer_schema_decode(SEER_AQ_ARRAY_REPLY_HEAD_SCHEMA, &cx, &r, &m);
  for (int64_t it = 0; ok && it < m.iters && seer_reader_ok(&r); it++) {
    if (aq_iter_head(&cx, &r, &m) != SEER_OK) {
      ok = false;
      break;
    }
    if (m.payload_n > 0) {
      uint8_t *pp = NULL;
      size_t ppl = 0;
      ok = aq_read_payload(&cx, &r, &pp, &ppl) == SEER_OK;
      free(pp);
    }
    if (ok && seer_schema_decode(SEER_AQ_ITER_TAIL_SCHEMA, &cx, &r, &m) && msgids != NULL &&
        m.msgid.n > 0) {
      size_t want = (size_t)count * 16;
      memcpy(msgids, m.msgid.p, m.msgid.n < want ? m.msgid.n : want);
    }
    seer_schema_free(SEER_AQ_ITER_TAIL_SCHEMA, &m);
  }
  if (!ok || !seer_reader_ok(&r))
    st = SEER_EPROTO;

out:
  free_batch_errors(&tmp);
  free(resp);
  return st;
}

/* Build a bulk RAW dequeue (TNS_FUNC_ARRAY_AQ, op DEQ): `count` placeholder
 * dequeue blocks (REMOVE / NEXT_MSG / ON_COMMIT + wait, no filters). Mirrors
 * oracledb _aq_write_array_deq. */
static SeerStatus aq_build_array_deq_raw(SeerConn *c, SeerWriter *w, const char *qname, int count,
                                         uint32_t wait)
{
  size_t qn = strlen(qname);
  uint8_t raw_toid[16] = {0};
  raw_toid[15] = TNS_AQ_RAW_TOID_SENTINEL;
  if (!seer_writer_init(w, 256))
    return SEER_ENOMEM;
  seer_ttc_fun_header(c, w, TNS_FUNC_ARRAY_AQ);
  SeerSchemaCtx cx = seer_msg_ctx(0, c->field_version, c->server_field_version);
  /* SEER_AQ_ARRAY_HEAD_SCHEMA with the dequeue's operands (the input
   * parameters, one per message, the output's pointer and length, no
   * iteration count, no shard), then per message a row:
   * SEER_AQ_ARRAY_DEQ_ROW_HEAD_SCHEMA, default properties and
   * SEER_AQ_ARRAY_DEQ_ROW_TAIL_SCHEMA - no filters, the payload TOID. */
  SeerAqArrayMsg h = {.in_ptr = 1,
                      .in_len = count,
                      .ret_flags = TNS_AQ_ARRAY_RETURN_MSGID,
                      .out_ptr = 1,
                      .out_len = 1,
                      .op = TNS_AQ_ARRAY_DEQ,
                      .shard_id = 0xFFFF};
  seer_schema_encode(SEER_AQ_ARRAY_HEAD_SCHEMA, &cx, &h, w);
  SeerAqArrayDeqRowMsg row = {.qname_len = (int64_t)qn,
                              .qname = {(const uint8_t *)qname, qn, 0},
                              .mode = TNS_AQ_DEQ_REMOVE,
                              .navigation = TNS_AQ_DEQ_NEXT_MSG, /* sequential */
                              .visibility = TNS_AQ_DEQ_ON_COMMIT,
                              .wait = wait,
                              .toid_len = 16,
                              .toid = {raw_toid, 16, 0},
                              .msg_version = TNS_AQ_MESSAGE_VERSION};
  for (int i = 0; i < count; i++) {
    seer_schema_encode(SEER_AQ_ARRAY_DEQ_ROW_HEAD_SCHEMA, &cx, &row, w);
    aq_write_msg_props(w, &cx, 0, 0, -1, NULL);
    seer_schema_encode(SEER_AQ_ARRAY_DEQ_ROW_TAIL_SCHEMA, &cx, &row, w);
  }
  return seer_writer_ok(w) ? SEER_OK : SEER_ENOMEM;
}

SeerStatus seer_aq_deq_raw_array(SeerConn *conn, const char *queue_name, int max_count,
                                 uint32_t wait_seconds, uint8_t **payloads, size_t *lens,
                                 int *out_count)
{
  if (conn == NULL || queue_name == NULL || max_count <= 0 || payloads == NULL || lens == NULL ||
      out_count == NULL)
    return SEER_EPARAM;
  *out_count = 0;
  for (int i = 0; i < max_count; i++) {
    payloads[i] = NULL;
    lens[i] = 0;
  }
  if (conn->field_version < TTC_FIELD_VERSION_12_2) {
    /* One message at a time before 12c (#187): wait for the first, then take
     * what is already there, stopping at the first empty dequeue. */
    for (int i = 0; i < max_count; i++) {
      SeerStatus st = seer_aq_deq_raw(conn, queue_name, i == 0 ? wait_seconds : 0, &payloads[i],
                                      &lens[i], NULL);
      if (st == SEER_ENODATA)
        break;
      if (st != SEER_OK) {
        for (int k = 0; k <= i; k++) {
          free(payloads[k]);
          payloads[k] = NULL;
          lens[k] = 0;
        }
        *out_count = 0;
        return st;
      }
      *out_count = i + 1;
    }
    return SEER_OK;
  }

  SeerWriter w;
  SeerStatus st = aq_build_array_deq_raw(conn, &w, queue_name, max_count, wait_seconds);
  if (st != SEER_OK) {
    seer_writer_free(&w);
    return st;
  }
  st = seer_ttc_send(conn, w.buf, w.len);
  seer_writer_free(&w);
  if (st != SEER_OK)
    return st;

  uint8_t *resp = NULL;
  size_t rlen = 0;
  st = seer_ttc_recv(conn, &resp, &rlen);
  if (st != SEER_OK)
    return st;

  uint8_t fv = conn->field_version;
  SeerReader r;
  seer_reader_init(&r, resp, rlen);
  r.sb4_chunks = fv >= TTC_FIELD_VERSION_12_1;
  SeerStmt tmp = {.conn = conn};
  OerResult oer = {0};
  uint8_t tok = seer_reader_u8(&r);
  if (tok == TTI_OER) { /* empty queue -> 0 messages */
    parse_oer(&r, &tmp, &oer);
    st = (oer.err_code == ORA_AQ_NO_MESSAGE || oer.err_code == ORA_AQ_DEQ_TIMEOUT) ? SEER_OK
                                                                                   : SEER_EDB;
    goto out;
  }
  if (tok != TTI_RPA) {
    st = SEER_EPROTO;
    goto out;
  }

  SeerSchemaCtx cx = seer_msg_ctx(0, fv, conn->server_field_version);
  SeerAqReplyMsg m = {0};
  bool ok = seer_schema_decode(SEER_AQ_ARRAY_REPLY_HEAD_SCHEMA, &cx, &r, &m);
  int64_t iters = m.iters;
  if (iters < 0)
    iters = 0;
  if (iters > max_count)
    iters = max_count; /* defensive clamp */
  for (int64_t it = 0; ok && it < iters && seer_reader_ok(&r); it++) {
    if (aq_iter_head(&cx, &r, &m) != SEER_OK) {
      ok = false;
      break;
    }
    if (m.payload_n > 0) {
      uint8_t *pp = NULL;
      size_t ppl = 0;
      if (aq_read_payload(&cx, &r, &pp, &ppl) == SEER_OK) {
        payloads[it] = pp;
        lens[it] = ppl;
      } else {
        free(pp);
        ok = false;
        break;
      }
    }
    ok = seer_schema_decode(SEER_AQ_ITER_TAIL_SCHEMA, &cx, &r, &m);
    seer_schema_free(SEER_AQ_ITER_TAIL_SCHEMA, &m);
    if (ok)
      *out_count = (int)(it + 1);
  }
  if (!ok || !seer_reader_ok(&r)) {
    for (int i = 0; i < *out_count; i++) {
      free(payloads[i]);
      payloads[i] = NULL;
      lens[i] = 0;
    }
    *out_count = 0;
    st = SEER_EPROTO;
  }

out:
  free_batch_errors(&tmp);
  free(resp);
  return st;
}

/* Test-only entry point: run the execute-response token parser over `buf` at
 * field version `fv`, reporting the column count and the trailing OER error
 * code. Used by the RPA-skip regression test (a 26ai/fv27 execute response whose
 * RPA field byte 0x04 collided with the OER token). Not exported from the .so. */
void seer_test_fv2_set_error(SeerConn *c, const uint8_t *buf, size_t len)
{
  fv2_set_error(c, buf, len);
}

void seer_test_fv2_decode_dml(const uint8_t *buf, size_t len, int64_t *rowcount, int64_t *code)
{
  fv2_decode_dml_response(buf, len, rowcount, code);
}

SeerStatus seer_test_build_fetch_only(uint8_t fv, uint32_t release, uint8_t seq, int cursor,
                                      uint8_t **out, size_t *outlen)
{
  struct SeerConn conn;
  memset(&conn, 0, sizeof conn);
  conn.field_version = fv;
  conn.server_release = release;
  conn.seq = seq;
  SeerStmt stmt = {.conn = &conn, .cursor_id = cursor};
  SeerWriter w;
  SeerStatus st = build_fetch_only(&stmt, &w);
  if (st != SEER_OK)
    return st;
  *out = w.buf;
  *outlen = w.len;
  return SEER_OK;
}

SeerStatus seer_test_parse_execute_response(const uint8_t *buf, size_t len, uint8_t fv,
                                            int *out_ncols, int64_t *out_err)
{
  struct SeerConn conn;
  memset(&conn, 0, sizeof conn);
  conn.field_version = fv;
  SeerStmt *stmt = calloc(1, sizeof *stmt);
  if (stmt == NULL)
    return SEER_ENOMEM;
  stmt->conn = &conn;
  stmt->cur = -1;
  OerResult oer = {0};
  SeerStatus st = parse_response(stmt, buf, len, /*expect_dcb=*/true, &oer);
  if (out_ncols)
    *out_ncols = stmt->ncols;
  if (out_err)
    *out_err = oer.err_code;
  seer_stmt_close(stmt);
  free(conn.last_error); /* the OER message; normally freed by seer_disconnect */
  return st;
}

#ifdef SEER_FUZZ
/* Test-only entry point (NOT built into production - SEER_FUZZ). Drives the
 * static image decoders from raw fuzzer bytes so libFuzzer can exercise their
 * bounds handling. The object attribute layout and the collection element type
 * are taken from the input so the fuzzer can steer them. These decoders are pure
 * (no I/O), so this is safe to run offline. */
void seer_fuzz_image_decoders(const uint8_t *img, size_t n);
void seer_fuzz_image_decoders(const uint8_t *img, size_t n)
{
  static const uint8_t types[8] = {
      ORA_TYPE_VARCHAR,   ORA_TYPE_NUMBER, ORA_TYPE_DATE,        ORA_TYPE_CHAR,
      ORA_TYPE_TIMESTAMP, ORA_TYPE_RAW,    ORA_TYPE_INTERVAL_DS, ORA_TYPE_BDOUBLE,
  };
  SeerCell cell;

  /* object: attribute count + types derived from the leading bytes */
  uint8_t attrs[8];
  int na = n ? (int)(img[0] & 7) : 0;
  for (int i = 0; i < na; i++)
    attrs[i] = types[((size_t)(i + 1) < n ? img[i + 1] : (uint8_t)i) % 8];
  cell = (SeerCell){0};
  decode_object_image(NULL, img, n, attrs, NULL, na, &cell);
  free(cell.data);

  /* collection: element type from a byte */
  cell = (SeerCell){0};
  decode_collection_image(img, n, types[(n ? img[0] : 0) % 8], &cell);
  free(cell.data);

  /* vector */
  cell = (SeerCell){0};
  decode_vector_image(img, n, &cell);
  free(cell.data);
}
#endif

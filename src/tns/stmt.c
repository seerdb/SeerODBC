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
#include "log.h"
#include "marshal.h"
#include "reader.h"
#include "tns_consts.h"
#include "ttc.h"
#include "types.h"
#include "writer.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>   /* strncasecmp */

#define PREFETCH_ROWS 100

typedef struct {
    char    *name;
    uint8_t  ora_type;
    uint16_t charset;
    uint8_t  null_ok;
    uint32_t max_size;
    char    *annotations;    /* 23ai: "name=value\n..." serialized map, or NULL */
    /* SQL OBJECT (ADT, type 109) columns: the object type's identity, and its
     * attribute layout (Oracle type per attribute) once resolved/cached. */
    char    *type_schema;
    char    *type_name;
    uint8_t *obj_attr_types;
    uint8_t *obj_attr_elem;   /* parallel: per attr, collection element type or 0 */
    int      n_obj_attrs;     /* -1 = layout not yet fetched, 0 = fetched/empty */
    bool     is_collection;   /* VARRAY / nested table (single element type)    */
    uint8_t  element_type;    /* collection element's Oracle wire type          */
    uint8_t *elem_obj_types;  /* collection-of-objects: the element's attr layout */
    int      n_elem_obj_attrs;/* >0 when the element type is itself an object    */
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
    char   *data;
    size_t  len;
    bool    binary;          /* BLOB / RAW / LONG RAW */
} SeerCell;

/* A bind: the OAC descriptor parameters plus the encoded RXD value. oac_type 0
 * marks an unbound position (sent as a NULL VARCHAR). For an OUT bind, `out`
 * holds the value the server returned in the IOV. */
typedef struct {
    uint8_t   oac_type;      /* Oracle type for the OAC (2 NUMBER, 1 VARCHAR, ...) */
    uint32_t  oac_size;      /* declared max length (widest value across iters) */
    uint32_t  oac_charset;   /* 873 for char, 0 otherwise */
    uint8_t   oac_flag;      /* 16 for char/raw, 0 otherwise */
    bool      is_out;        /* OUT / IN OUT parameter */
    uint8_t **rxd;           /* per-iteration encoded RXD values, [n_iters] */
    size_t   *rxd_len;
    SeerCell  out;           /* OUT value captured from the IOV response */
    bool      is_array;      /* PL/SQL associative-array (index-by table) bind  */
    SeerCell *out_arr;       /* OUT assoc-array elements captured from the IOV   */
    int       out_arr_n;
    uint8_t  *oac_override;  /* pre-built OAC bytes (SQL OBJECT bind); else emit_oac */
    size_t    oac_override_len;
} SeerBind;

/* A LOB cell whose locator was captured during parse and whose content is
 * fetched (via TTI_LOBOPS) after the whole result set is in. */
typedef struct {
    size_t   row;
    int      col;
    uint8_t  ora_type;       /* CLOB / BLOB */
    uint8_t *locator;
    size_t   loclen;
} SeerPendingLob;

/* A SQL OBJECT (ADT) cell whose image was captured during parse and decoded
 * after the result set is in (the attribute layout needs a dictionary query). */
typedef struct {
    size_t   row;
    int      col;
    uint8_t *image;
    size_t   imagelen;
} SeerPendingObj;

/* One per-row failure from an array-DML execute in batch-errors mode (§6.7):
 * iteration `row` failed with ORA-`code`, text `message`. */
typedef struct {
    uint32_t row;            /* 0-based iteration offset that failed */
    uint32_t code;           /* ORA error number                    */
    char    *message;        /* "ORA-NNNNN: ..." (owned), may be NULL */
} SeerBatchError;

/* One implicit result set (DBMS_SQL.RETURN_RESULT): the server cursor's id and
 * its column describe, captured from a TTI_IRD token and drained on demand. */
typedef struct {
    SeerColumn *cols;
    int         ncols;
    int         cursor_id;
} SeerImplicitResult;

struct SeerStmt {
    SeerConn   *conn;
    char       *sql;
    SeerBind   *pbinds;      /* input parameter binds, 0-based by position */
    int         npbinds;
    int         n_iters;     /* array-bind iteration count (default 1) */
    int         cur_iter;    /* iteration the bind functions target */
    uint32_t    prefetch;    /* execute prefetch row count (0 = PREFETCH_ROWS);
                              * a pipelined op sets it high to pull rows inline */
    SeerColumn *cols;
    int         ncols;
    SeerCell  **rows;        /* rows[r] is a SeerCell array of ncols */
    size_t      nrows;
    size_t      rows_cap;
    SeerPendingLob *plobs;   /* LOB cells awaiting content */
    size_t      nplobs;
    size_t      plobs_cap;
    SeerPendingObj *pobjs;   /* ADT cells awaiting layout + decode */
    size_t      npobjs;
    size_t      pobjs_cap;
    long        cur;         /* current row index, -1 before the first fetch */
    long        affected;    /* DML affected-row count (from the OER) */
    int         cursor_id;
    int         reuse_cursor;    /* cached server cursor to re-execute without a re-parse */
    bool        executed;
    bool        batch_errors;    /* arm batcherrors for array DML (continue on row error) */
    SeerBatchError *berrs;       /* per-row failures captured from the OER */
    size_t      nberrs;
    /* A REF CURSOR captured from a PL/SQL OUT bind (drained into cols/rows). */
    bool        refcursor_present;
    int         refcursor_id;
    SeerColumn *refcursor_cols;
    int         refcursor_ncols;
    /* Implicit result sets (DBMS_SQL.RETURN_RESULT, 12c+): each is a server
     * cursor captured from a TTI_IRD token, drained on demand by next_result. */
    SeerImplicitResult *implicit;
    size_t      nimplicit;
    size_t      implicit_pos;    /* next implicit result to surface */
    /* Array-DML per-iteration row counts (12c+): armed before an array execute,
     * captured from the response RPA piggyback. */
    bool        want_dml_rowcounts;
    uint32_t   *dml_rowcounts;
    size_t      n_dml_rowcounts;
    /* DML RETURNING ... INTO: set when the statement is a DML with OUT binds;
     * those binds are server-filled and their values arrive in a return RXD. */
    bool        returning;
};

/* The OER outcome of one response. */
typedef struct {
    int64_t call_status;
    int64_t err_code;
    int64_t cursor_id;
    int64_t row_count;     /* "current row number" - DML affected rows on 11g */
} OerResult;

/* ----------------------------------------------------------- value decode */

static char *hex_dup(const uint8_t *in, size_t n)
{
    static const char d[] = "0123456789abcdef";
    char *s = malloc(2 * n + 1);
    if (s == NULL)
        return NULL;
    for (size_t i = 0; i < n; i++) {
        s[2 * i]     = d[in[i] >> 4];
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
    c->data   = p;
    c->len    = n;
    c->binary = binary;
    return SEER_OK;
}

/* Store an owned NUL-terminated string into a cell (text). */
static void cell_set_text(SeerCell *c, char *owned)
{
    c->data   = owned;
    c->len    = owned ? strlen(owned) : 0;
    c->binary = false;
}

/* Decode one column value from the row stream into `cell` (already zeroed; a
 * SQL NULL leaves it zeroed). Scalar DALC-framed types only - CLOB/BLOB and
 * LONG/LONG RAW are handled in parse_rxd. */
/* LONG (type 8) / LONG RAW (type 24): a marker (0x00 NULL, 0xFE chunked, else a
 * ub1 length) then content, followed by two trailing ub4 indicators (§11.10). */
static SeerStatus decode_long(SeerReader *r, bool is_raw, SeerCell *cell)
{
    SeerWriter acc;
    if (!seer_writer_init(&acc, 64))
        return SEER_ENOMEM;

    uint8_t marker = seer_reader_u8(r);
    if (!seer_reader_ok(r)) {
        seer_writer_free(&acc);
        return SEER_EPROTO;
    }
    bool is_null = (marker == 0x00);
    if (marker == 0xFE) {
        for (;;) {
            uint8_t clen = seer_reader_u8(r);
            if (!seer_reader_ok(r) || clen == 0)
                break;
            const uint8_t *p = seer_reader_bytes(r, clen);
            if (p == NULL)
                break;
            seer_writer_bytes(&acc, p, clen);
        }
    } else if (!is_null) {
        const uint8_t *p = seer_reader_bytes(r, marker);
        if (p != NULL)
            seer_writer_bytes(&acc, p, marker);
    }
    (void)seer_dec_sb4(r);                 /* trailing indicator 1 */
    (void)seer_dec_sb4(r);                 /* trailing indicator 2 */

    if (!seer_reader_ok(r) || !seer_writer_ok(&acc)) {
        seer_writer_free(&acc);
        return SEER_EPROTO;
    }
    if (is_null) {
        seer_writer_free(&acc);
        return SEER_OK;                    /* leaves the cell as SQL NULL */
    }
    SeerStatus st = cell_set_bytes(cell, acc.buf, acc.len, is_raw);
    seer_writer_free(&acc);
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
    uint8_t ind = seer_reader_u8(r);
    if (!seer_reader_ok(r))
        return SEER_EPROTO;
    if (ind == 0 || ind == 0xFF)
        return SEER_OK;                    /* SQL NULL */
    uint32_t obj  = (uint32_t)seer_dec_sb4(r);
    uint32_t file = (uint32_t)seer_dec_sb4(r);
    (void)seer_dec_sb4(r);                 /* unused */
    uint32_t blk  = (uint32_t)seer_dec_sb4(r);
    uint32_t slot = (uint32_t)seer_dec_sb4(r);
    if (!seer_reader_ok(r))
        return SEER_EPROTO;
    char s[18];
    rowid_b64(obj, 6, s);
    rowid_b64(file, 3, s + 6);
    rowid_b64(blk, 6, s + 9);
    rowid_b64(slot, 3, s + 15);
    return cell_set_bytes(cell, s, sizeof s, false);
}

/* Standard-alphabet base64 (no padding) of `n` bytes, into the writer. */
static void b64_encode(SeerWriter *w, const uint8_t *p, size_t n)
{
    static const char A[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t i = 0;
    for (; i + 3 <= n; i += 3) {
        uint32_t v = (uint32_t)p[i] << 16 | (uint32_t)p[i + 1] << 8 | p[i + 2];
        seer_writer_u8(w, A[(v >> 18) & 0x3F]); seer_writer_u8(w, A[(v >> 12) & 0x3F]);
        seer_writer_u8(w, A[(v >> 6) & 0x3F]);  seer_writer_u8(w, A[v & 0x3F]);
    }
    if (n - i == 1) {
        uint32_t v = (uint32_t)p[i] << 16;
        seer_writer_u8(w, A[(v >> 18) & 0x3F]); seer_writer_u8(w, A[(v >> 12) & 0x3F]);
    } else if (n - i == 2) {
        uint32_t v = (uint32_t)p[i] << 16 | (uint32_t)p[i + 1] << 8;
        seer_writer_u8(w, A[(v >> 18) & 0x3F]); seer_writer_u8(w, A[(v >> 12) & 0x3F]);
        seer_writer_u8(w, A[(v >> 6) & 0x3F]);
    }
}

/* UROWID (type 208, logical/universal rowid, e.g. an index-organized table):
 * same RXD framing as a LOB column - ub4 num_bytes, a 1-byte length echo, then
 * num_bytes rowid bytes (a leading type tag + body). Rendered "*" + base64 of
 * the body (the leading tag byte dropped). */
static SeerStatus decode_urowid(SeerReader *r, SeerCell *cell)
{
    int64_t nbytes = seer_dec_sb4(r);
    if (nbytes <= 0)
        return seer_reader_ok(r) ? SEER_OK : SEER_EPROTO;   /* NULL */
    (void)seer_reader_u8(r);               /* 1-byte length echo */
    const uint8_t *p = seer_reader_bytes(r, (size_t)nbytes);
    if (p == NULL)
        return SEER_EPROTO;
    SeerWriter w;
    if (!seer_writer_init(&w, (size_t)nbytes * 2))
        return SEER_ENOMEM;
    seer_writer_u8(&w, '*');
    if (nbytes > 1)
        b64_encode(&w, p + 1, (size_t)nbytes - 1);   /* drop the leading tag */
    SeerStatus st = seer_writer_ok(&w)
        ? cell_set_bytes(cell, w.buf, w.len, false) : SEER_ENOMEM;
    seer_writer_free(&w);
    return st;
}

/* VECTOR binary image format (PROTOCOL.md §18). */
#define VEC_MAGIC        0xDB
#define VEC_TYPE_FLOAT32 2
#define VEC_TYPE_FLOAT64 3
#define VEC_TYPE_INT8    4
#define VEC_TYPE_BINARY  5
#define VEC_FLAG_NORM    0x10   /* an 8-byte cached magnitude follows the header */
#define VEC_FLAG_SPARSE  0x20   /* sparse: ub2 count + ub4 indices + values      */

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
    uint8_t  etype = img[4];
    uint32_t ndim  = (uint32_t)img[5] << 24 | (uint32_t)img[6] << 16 |
                     (uint32_t)img[7] << 8  | img[8];
    size_t   pos   = 9;
    if (flags & VEC_FLAG_NORM)             /* skip the cached magnitude */
        pos += 8;
    bool sparse = (flags & VEC_FLAG_SPARSE) != 0;

    SeerWriter w;
    if (!seer_writer_init(&w, 64))
        return SEER_ENOMEM;

    /* Append one numeric element at `*p`, advancing it; bail on short input. */
    #define VEC_ELEM(P) do {                                                  \
        char tmp[40];                                                          \
        if (etype == VEC_TYPE_FLOAT32) {                                       \
            if ((P) + 4 > len) goto bad;                                       \
            seer_decode_bfloat(img + (P), 4, tmp, sizeof tmp); (P) += 4;       \
        } else if (etype == VEC_TYPE_FLOAT64) {                               \
            if ((P) + 8 > len) goto bad;                                       \
            seer_decode_bdouble(img + (P), 8, tmp, sizeof tmp); (P) += 8;      \
        } else if (etype == VEC_TYPE_INT8) {                                  \
            if ((P) + 1 > len) goto bad;                                       \
            snprintf(tmp, sizeof tmp, "%d", (int)(int8_t)img[(P)]); (P) += 1;  \
        } else { goto bad; }                                                   \
        seer_writer_bytes(&w, tmp, strlen(tmp));                              \
    } while (0)

    if (sparse) {
        if (pos + 2 > len) goto bad;
        uint16_t nnz = (uint16_t)((uint16_t)img[pos] << 8 | img[pos + 1]);
        pos += 2;
        char hdr[32];
        snprintf(hdr, sizeof hdr, "[%u, [", ndim);
        seer_writer_bytes(&w, hdr, strlen(hdr));
        size_t ipos = pos;                 /* indices: nnz × ub4 */
        for (uint16_t i = 0; i < nnz; i++) {
            if (ipos + 4 > len) goto bad;
            uint32_t idx = (uint32_t)img[ipos] << 24 | (uint32_t)img[ipos + 1] << 16 |
                           (uint32_t)img[ipos + 2] << 8 | img[ipos + 3];
            ipos += 4;
            char b[16]; snprintf(b, sizeof b, "%s%u", i ? ", " : "", idx);
            seer_writer_bytes(&w, b, strlen(b));
        }
        seer_writer_bytes(&w, "], [", 4);
        size_t vpos = ipos;                /* values: nnz elements */
        for (uint16_t i = 0; i < nnz; i++) {
            if (i) seer_writer_bytes(&w, ", ", 2);
            VEC_ELEM(vpos);
        }
        seer_writer_bytes(&w, "]]", 2);
    } else if (etype == VEC_TYPE_BINARY) { /* packed bits, byte list */
        seer_writer_u8(&w, '[');
        size_t nbytes = (ndim + 7) / 8;
        for (size_t i = 0; i < nbytes; i++) {
            if (pos + i >= len) goto bad;
            char b[8]; snprintf(b, sizeof b, "%s%u", i ? ", " : "", img[pos + i]);
            seer_writer_bytes(&w, b, strlen(b));
        }
        seer_writer_u8(&w, ']');
    } else {                               /* dense FLOAT32/64/INT8 */
        seer_writer_u8(&w, '[');
        for (uint32_t i = 0; i < ndim; i++) {
            if (i) seer_writer_bytes(&w, ", ", 2);
            VEC_ELEM(pos);
        }
        seer_writer_u8(&w, ']');
    }
    #undef VEC_ELEM

    if (!seer_writer_ok(&w)) { seer_writer_free(&w); return SEER_ENOMEM; }
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
static SeerStatus decode_scalar(uint8_t ora_type, const uint8_t *val, size_t vlen,
                                SeerCell *cell)
{
    if (val == NULL || vlen == 0)
        return SEER_OK;                    /* SQL NULL */

    char buf[192];
    SeerStatus st = SEER_OK;
    switch (ora_type) {
    case ORA_TYPE_NUMBER:
        st = seer_decode_number(val, vlen, buf, sizeof buf);
        if (st == SEER_OK) cell_set_text(cell, strdup(buf));
        break;
    case ORA_TYPE_DATE: case ORA_TYPE_TIMESTAMP:
    case ORA_TYPE_TIMESTAMPTZ: case ORA_TYPE_TIMESTAMPLTZ:
        st = seer_decode_date(val, vlen, buf, sizeof buf);
        if (st == SEER_OK) cell_set_text(cell, strdup(buf));
        break;
    case ORA_TYPE_BFLOAT:
        st = seer_decode_bfloat(val, vlen, buf, sizeof buf);
        if (st == SEER_OK) cell_set_text(cell, strdup(buf));
        break;
    case ORA_TYPE_BDOUBLE:
        st = seer_decode_bdouble(val, vlen, buf, sizeof buf);
        if (st == SEER_OK) cell_set_text(cell, strdup(buf));
        break;
    case ORA_TYPE_VARCHAR: case ORA_TYPE_CHAR:
        st = cell_set_bytes(cell, val, vlen, false);    /* AL32UTF8 text */
        break;
    case ORA_TYPE_RAW:
        st = cell_set_bytes(cell, val, vlen, true);     /* binary */
        break;
    case ORA_TYPE_REF:
        st = cell_set_bytes(cell, val, vlen, true);     /* opaque locator -> hex */
        break;
    case ORA_TYPE_INTERVAL_YM:
        st = seer_decode_interval_ym(val, vlen, buf, sizeof buf);
        if (st == SEER_OK) cell_set_text(cell, strdup(buf));
        break;
    case ORA_TYPE_INTERVAL_DS:
        st = seer_decode_interval_ds(val, vlen, buf, sizeof buf);
        if (st == SEER_OK) cell_set_text(cell, strdup(buf));
        break;
    case ORA_TYPE_BOOLEAN:                              /* 23ai: last byte = truth */
        cell_set_text(cell, strdup(val[vlen - 1] ? "TRUE" : "FALSE"));
        break;
    default:
        cell_set_text(cell, hex_dup(val, vlen));        /* unknown: hex text */
        break;
    }
    if (st != SEER_OK)
        return st;
    return (cell->data != NULL) ? SEER_OK : SEER_ENOMEM;
}

static SeerStatus decode_cell(SeerReader *r, const SeerColumn *col, SeerCell *cell)
{
    switch (col->ora_type) {
    case ORA_TYPE_LONG:                    /* LONG (text)              */
        return decode_long(r, false, cell);
    case ORA_TYPE_LONGRAW:                 /* LONG RAW (binary)        */
        return decode_long(r, true, cell);
    case ORA_TYPE_RID: case ORA_TYPE_ROWID: /* ROWID                   */
        return decode_rowid(r, cell);
    case ORA_TYPE_UROWID:                  /* UROWID                   */
        return decode_urowid(r, cell);
    /* ORA_TYPE_JSON and ORA_TYPE_VECTOR are LOB-backed and intercepted in
     * parse_rxd's deferred-LOB branch (resolved via seer_decode_oson /
     * decode_vector_image), so they never reach here. */
    default:
        break;
    }

    uint8_t *val = NULL;
    size_t   vlen = 0;
    SeerStatus st = seer_dec_dalc(r, &val, &vlen);
    if (st != SEER_OK)
        return st;
    st = decode_scalar(col->ora_type, val, vlen, cell);
    free(val);
    /* A national char column (NVARCHAR2 / NCHAR) declares charset AL16UTF16 (2000):
     * its value is UTF-16BE on the wire. Convert to UTF-8 so it reads as text. */
    if (st == SEER_OK && col->charset == 2000 && cell->data != NULL && cell->len > 0
        && (col->ora_type == ORA_TYPE_VARCHAR || col->ora_type == ORA_TYPE_CHAR)) {
        char  *u8 = NULL;
        size_t u8len = 0;
        if (seer_iconv("UTF-16BE", "UTF-8", cell->data, cell->len, &u8, &u8len) == 0) {
            free(cell->data);
            cell->data = u8;
            cell->len  = u8len;
        }
    }
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
static SeerStatus parse_describe_body(SeerReader *r, int fv,
                                      SeerColumn **out_cols, int *out_ncols)
{
    (void)seer_dec_sb4(r);                 /* max row size */
    int64_t ncols = seer_dec_sb4(r);
    if (ncols < 0 || ncols > 4096 || !seer_reader_ok(r))
        return SEER_EPROTO;
    if (ncols > 0)
        (void)seer_reader_u8(r);           /* reserved byte */

    SeerColumn *cols = calloc((size_t)ncols, sizeof *cols);
    if (cols == NULL && ncols > 0)
        return SEER_ENOMEM;

    for (int64_t i = 0; i < ncols; i++) {
        uint8_t type = seer_reader_u8(r);
        (void)seer_reader_u8(r);           /* flags     */
        (void)seer_reader_u8(r);           /* precision */
        if (fv >= TTC_FIELD_VERSION_12_2)
            (void)seer_reader_u8(r);       /* scale: a raw sb1 on 12c+ */
        else
            (void)seer_dec_sb4(r);         /* scale: variable on 11g */
        (void)seer_dec_sb4(r);             /* buffer size */
        (void)seer_dec_sb4(r);             /* max array elems */
        (void)seer_dec_sb4(r);             /* cont flags */
        int64_t oidlen = seer_dec_sb4(r);
        if (oidlen > 0)
            seer_skip_chunked(r);
        (void)seer_dec_sb4(r);             /* version */
        int64_t charset = seer_dec_sb4(r);
        (void)seer_reader_u8(r);           /* csfrm */
        int64_t max_size = seer_dec_sb4(r);
        if (fv >= TTC_FIELD_VERSION_12_2)
            (void)seer_dec_sb4(r);         /* oaccolid (12.2+) */
        uint8_t null_ok = seer_reader_u8(r);
        (void)seer_reader_u8(r);           /* v7 name length */

        char *name = NULL;
        SeerStatus st = seer_read_str(r, &name);
        if (st != SEER_OK) { cols[i].name = NULL; goto fail; }
        char *schema = NULL, *tname = NULL;
        st = seer_read_str(r, &schema);             /* type owner (ADT) */
        if (st != SEER_OK) { free(name); goto fail; }
        st = seer_read_str(r, &tname);              /* type name (ADT)  */
        if (st != SEER_OK) { free(name); free(schema); goto fail; }
        if (type == ORA_TYPE_ADT && schema && schema[0] && tname && tname[0]) {
            cols[i].type_schema = schema; schema = NULL;
            cols[i].type_name   = tname;  tname  = NULL;
            cols[i].n_obj_attrs = -1;               /* layout not yet fetched */
        }
        free(schema); free(tname);
        char *skip = NULL;
        (void)seer_dec_sb4(r);             /* column position */
        if (fv >= TTC_FIELD_VERSION_11_2)
            (void)seer_dec_sb4(r);         /* uds flags (11g+ only) */
        if (fv >= TTC_FIELD_VERSION_23_1) {
            /* 23c+ (fv>=17): the column's SQL-domain schema and name, each a
             * DALC string (empty 0x00 for a column with no domain). */
            st = seer_read_str(r, &skip); free(skip);
            if (st != SEER_OK) { free(name); goto fail; }
            st = seer_read_str(r, &skip); free(skip);
            if (st != SEER_OK) { free(name); goto fail; }
        }
        if (fv > TTC_FIELD_VERSION_23_1) {
            /* 23ai (fv24): per-column annotation map + vector descriptor (#89).
             * The count is sent twice around a 1-byte pointer; each key/value
             * pair is followed by a ub4 flags word, with a trailing ub4 after
             * the loop. The map is serialized as "name=value\n..." (name-only
             * annotations get an empty value) into cols[i].annotations. Both
             * fields must be fully consumed or the row stream desyncs. */
            int64_t nann = seer_dec_sb4(r);
            if (nann > 0) {
                if (nann > 4096) { free(name); goto fail; }
                SeerWriter ann;
                if (!seer_writer_init(&ann, 64)) { free(name); goto fail; }
                (void)seer_reader_u8(r);   /* pointer            */
                nann = seer_dec_sb4(r);    /* count, repeated    */
                (void)seer_reader_u8(r);   /* pointer            */
                for (int64_t a = 0; a < nann && seer_reader_ok(r); a++) {
                    char *akey = NULL, *aval = NULL;
                    st = seer_read_str(r, &akey);
                    if (st == SEER_OK) st = seer_read_str(r, &aval);
                    if (st != SEER_OK) {
                        free(akey); free(aval);
                        seer_writer_free(&ann); free(name); goto fail;
                    }
                    seer_writer_bytes(&ann, akey, strlen(akey));
                    seer_writer_u8(&ann, '=');
                    seer_writer_bytes(&ann, aval, strlen(aval));
                    seer_writer_u8(&ann, '\n');
                    free(akey); free(aval);
                    (void)seer_dec_sb4(r); /* per-pair flags     */
                }
                (void)seer_dec_sb4(r);     /* trailing flags     */
                if (seer_writer_ok(&ann) && ann.len > 0) {
                    char *s = malloc(ann.len + 1);
                    if (s == NULL) { seer_writer_free(&ann); free(name); goto fail; }
                    memcpy(s, ann.buf, ann.len);
                    s[ann.len] = '\0';
                    cols[i].annotations = s;
                }
                seer_writer_free(&ann);
            }
            (void)seer_dec_sb4(r);         /* vector dimensions  */
            (void)seer_reader_u8(r);       /* vector format      */
            (void)seer_reader_u8(r);       /* vector flags       */
        }

        cols[i].name     = name;
        cols[i].ora_type = type;
        cols[i].charset  = (uint16_t)charset;
        cols[i].null_ok  = null_ok;
        cols[i].max_size = (uint32_t)(max_size < 0 ? 0 : max_size);

        if (!seer_reader_ok(r)) { goto fail; }
        continue;
    fail:
        free_columns(cols, (int)ncols);
        return SEER_EPROTO;
    }

    seer_skip_bytes_with_length(r);        /* current date */
    for (int k = 0; k < 4; k++)
        (void)seer_dec_sb4(r);             /* dcbflag/dcbmdbz/dcbmnpr/dcbmxpr */
    if (fv >= TTC_FIELD_VERSION_11_2)
        seer_skip_bytes_with_length(r);    /* dcbqcky - query-cache key (11g+) */

    if (!seer_reader_ok(r)) {
        free_columns(cols, (int)ncols);
        return SEER_EPROTO;
    }

    *out_cols  = cols;
    *out_ncols = (int)ncols;
    return SEER_OK;
}

static SeerStatus parse_dcb(SeerReader *r, SeerStmt *stmt)
{
    seer_skip_chunked(r);                  /* describe-info preamble */
    SeerColumn *cols = NULL;
    int ncols = 0;
    SeerStatus st = parse_describe_body(r, stmt->conn->field_version, &cols, &ncols);
    if (st != SEER_OK)
        return st;
    stmt->cols  = cols;
    stmt->ncols = ncols;
    return SEER_OK;
}

/* A REF CURSOR OUT value (§6.5): a length byte, an inline describe, the nested
 * cursor id, and an indicator. Stash the describe + cursor id; the cursor is
 * drained into the statement result set after execute. */
static SeerStatus parse_refcursor_out(SeerReader *r, SeerStmt *stmt)
{
    (void)seer_reader_u8(r);               /* value length */
    SeerColumn *cols = NULL;
    int ncols = 0;
    SeerStatus st = parse_describe_body(r, stmt->conn->field_version, &cols, &ncols);
    if (st != SEER_OK)
        return st;
    int64_t cursor_id = seer_dec_sb4(r);   /* nested cursor id */
    (void)seer_reader_u8(r);               /* per-value indicator */
    if (!seer_reader_ok(r)) {
        free_columns(cols, ncols);
        return SEER_EPROTO;
    }
    if (stmt->refcursor_cols != NULL)
        free_columns(stmt->refcursor_cols, stmt->refcursor_ncols);
    stmt->refcursor_cols    = cols;
    stmt->refcursor_ncols   = ncols;
    stmt->refcursor_id      = (int)cursor_id;
    stmt->refcursor_present = true;
    return SEER_OK;
}

/* Implicit result sets (TTI_IRD, DBMS_SQL.RETURN_RESULT, 12c+): a ub4 result
 * count, then per result a ub1-prefixed preamble, the column describe body, and
 * a ub2 cursor id. Each is stashed as a server cursor drained on demand by
 * seer_stmt_next_result. */
static SeerStatus parse_implicit(SeerReader *r, SeerStmt *stmt)
{
    int64_t nres = seer_dec_sb4(r);
    if (nres < 0 || nres > 4096 || !seer_reader_ok(r))
        return SEER_EPROTO;
    for (int64_t i = 0; i < nres; i++) {
        uint8_t prelen = seer_reader_u8(r);    /* preamble length */
        if (prelen > 0)
            seer_reader_bytes(r, prelen);
        SeerColumn *cols = NULL;
        int ncols = 0;
        SeerStatus st = parse_describe_body(r, stmt->conn->field_version, &cols, &ncols);
        if (st != SEER_OK)
            return st;
        int64_t cursor_id = seer_dec_sb4(r);   /* ub2 cursor id */
        if (!seer_reader_ok(r)) {
            free_columns(cols, ncols);
            return SEER_EPROTO;
        }
        SeerImplicitResult *np = realloc(stmt->implicit,
                                         (stmt->nimplicit + 1) * sizeof *np);
        if (np == NULL) {
            free_columns(cols, ncols);
            return SEER_ENOMEM;
        }
        stmt->implicit = np;
        stmt->implicit[stmt->nimplicit++] =
            (SeerImplicitResult){ cols, ncols, (int)cursor_id };
        seer_log(SEER_LOG_DEBUG, "stmt: implicit result %zu: cursor %d (%d cols)",
                 stmt->nimplicit, (int)cursor_id, ncols);
    }
    return SEER_OK;
}

static SeerStatus parse_rxh(SeerReader *r)
{
    (void)seer_reader_u8(r);               /* flags */
    for (int i = 0; i < 4; i++)
        (void)seer_dec_sb4(r);             /* num requests/iter/iters/buffer len */
    int64_t bvlen = seer_dec_sb4(r);
    if (bvlen > 0) {
        (void)seer_reader_u8(r);           /* repeated length */
        seer_reader_bytes(r, (size_t)bvlen);
    }
    seer_skip_bytes_with_length(r);        /* rxhrid */
    return seer_reader_ok(r) ? SEER_OK : SEER_EPROTO;
}

static SeerStatus parse_bvc(SeerReader *r, int ncols, uint8_t **bv, size_t *bvlen)
{
    free(*bv);
    *bv = NULL;
    *bvlen = 0;
    (void)seer_dec_sb4(r);                 /* num columns sent */
    size_t veclen = (size_t)((ncols + 7) / 8);
    const uint8_t *p = seer_reader_bytes(r, veclen);
    if (p == NULL)
        return SEER_EPROTO;
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

static SeerStatus append_row(SeerStmt *stmt, SeerCell *row)
{
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
    *loc = NULL;
    *loclen = 0;
    if (seer_reader_remaining(r) == 0)
        return SEER_EPROTO;
    if (r->buf[r->pos] == 0x00) {
        (void)seer_reader_u8(r);          /* NULL LOB */
        return SEER_OK;
    }
    int64_t num_bytes = seer_dec_sb4(r);
    if (num_bytes <= 0 || !seer_reader_ok(r))
        return seer_reader_ok(r) ? SEER_OK : SEER_EPROTO;
    return seer_dec_dalc(r, loc, loclen);
}

/* Record a LOB cell to resolve after the result set is fully fetched. Takes
 * ownership of `loc`. */
static SeerStatus record_pending_lob(SeerStmt *stmt, size_t row, int col,
                                     uint8_t ora_type, uint8_t *loc, size_t loclen)
{
    if (stmt->nplobs == stmt->plobs_cap) {
        size_t cap = stmt->plobs_cap ? stmt->plobs_cap * 2 : 8;
        SeerPendingLob *np = realloc(stmt->plobs, cap * sizeof *np);
        if (np == NULL)
            return SEER_ENOMEM;
        stmt->plobs = np;
        stmt->plobs_cap = cap;
    }
    stmt->plobs[stmt->nplobs++] = (SeerPendingLob){ row, col, ora_type, loc, loclen };
    return SEER_OK;
}

/* Read a SQL OBJECT (ADT, type 109) value from the RXD. The wire framing
 * (python-oracledb read_dbobject): type OID, object OID, snapshot - each a
 * ub4 length then, if non-zero, a chunked value - a version (ub2), an image
 * length (ub4; 0 => NULL value), flags (ub2), then the packed image as a chunked
 * byte string. On a non-NULL value *img is a malloc'd image (caller owns). */
static SeerStatus read_object_image(SeerReader *r, uint8_t **img, size_t *imglen)
{
    *img = NULL;
    *imglen = 0;
    for (int k = 0; k < 3; k++) {              /* type OID, object OID, snapshot */
        int64_t n = seer_dec_sb4(r);
        if (n > 0)
            seer_skip_chunked(r);
    }
    (void)seer_dec_sb4(r);                      /* version */
    int64_t present = seer_dec_sb4(r);          /* image length (gate) */
    (void)seer_dec_sb4(r);                      /* flags */
    if (!seer_reader_ok(r))
        return SEER_EPROTO;
    if (present == 0)
        return SEER_OK;                         /* NULL object */
    return seer_dec_dalc(r, img, imglen);
}

/* Record an ADT cell to decode after the result set is fully fetched (its
 * attribute layout needs a dictionary query). Takes ownership of `image`. */
static SeerStatus record_pending_obj(SeerStmt *stmt, size_t row, int col,
                                     uint8_t *image, size_t imagelen)
{
    if (stmt->npobjs == stmt->pobjs_cap) {
        size_t cap = stmt->pobjs_cap ? stmt->pobjs_cap * 2 : 8;
        SeerPendingObj *np = realloc(stmt->pobjs, cap * sizeof *np);
        if (np == NULL)
            return SEER_ENOMEM;
        stmt->pobjs = np;
        stmt->pobjs_cap = cap;
    }
    stmt->pobjs[stmt->npobjs++] = (SeerPendingObj){ row, col, image, imagelen };
    return SEER_OK;
}

static SeerStatus parse_rxd(SeerReader *r, SeerStmt *stmt,
                            const uint8_t *bv, size_t bvlen)
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
                if (cell_set_bytes(&row[i], prev[i].data, prev[i].len,
                                   prev[i].binary) != SEER_OK)
                    goto oom;
            }
            continue;
        }

        uint8_t type = stmt->cols[i].ora_type;
        if (type == ORA_TYPE_CLOB || type == ORA_TYPE_BLOB || type == ORA_TYPE_BFILE
            || type == ORA_TYPE_VECTOR || type == ORA_TYPE_JSON) { /* all LOB-backed: defer */
            uint8_t *loc = NULL;
            size_t   ll  = 0;
            SeerStatus st = read_lob_locator(r, &loc, &ll);
            if (st == SEER_OK && loc != NULL)
                st = record_pending_lob(stmt, stmt->nrows, i, type, loc, ll);
            if (st != SEER_OK) {
                free(loc);
                goto fail;
            }
            continue;                          /* cell filled in the resolve pass */
        }
        if (type == ORA_TYPE_ADT) {            /* SQL OBJECT: defer image decode */
            uint8_t *image = NULL;
            size_t   ilen  = 0;
            SeerStatus st = read_object_image(r, &image, &ilen);
            if (st == SEER_OK && image != NULL)
                st = record_pending_obj(stmt, stmt->nrows, i, image, ilen);
            if (st != SEER_OK) {
                free(image);
                goto fail;
            }
            continue;                          /* cell filled in the resolve pass */
        }

        SeerStatus st = decode_cell(r, &stmt->cols[i], &row[i]);
        if (st != SEER_OK)
            goto fail;
    }

    if (append_row(stmt, row) != SEER_OK)
        goto oom;
    return SEER_OK;

oom:
    for (int j = 0; j < stmt->ncols; j++) free(row[j].data);
    free(row);
    return SEER_ENOMEM;
fail:
    for (int j = 0; j < stmt->ncols; j++) free(row[j].data);
    free(row);
    return SEER_EPROTO;
}

/* Skip a server session-state RPA piggyback so the next token is the OER. */
static const uint8_t KNOWN_TOKENS[] = { 4, 6, 7, 8, 9, 11, 12, 13, 14, 15, 16, 19, 21 };
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
    size_t rem  = seer_reader_remaining(r);
    for (size_t off = 0; off + 5 <= rem && off <= 8; off++) {
        const uint8_t *p = r->buf + base + off;
        if (p[0] == p[1] && p[2] == 0 && p[3] == 0 && p[4] == 0) {   /* ub1 L, ub4le L */
            size_t end = base + off + 5 + p[0];
            if (end < r->len && is_known_token(r->buf[end])) {
                r->pos = end;                  /* consumed; now on the OER */
                return;
            }
        }
    }
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
    bool break_on_token = (stmt == NULL) ||
                          stmt->conn->field_version < TTC_FIELD_VERSION_10_2;
    int64_t num = seer_dec_sb4(r);
    for (int64_t i = 0; i < num && seer_reader_ok(r); i++) {
        if (seer_reader_remaining(r) == 0)
            break;
        if (break_on_token && is_known_token(r->buf[r->pos]))
            break;
        (void)seer_dec_sb4(r);
    }
    while (seer_reader_remaining(r) > 0 && r->buf[r->pos] == 0)
        (void)seer_reader_u8(r);
    /* Array-DML row counts (12c+): when armed, a ub4 count and that many ub4
     * per-iteration affected-row counts ride here, ahead of the OER. */
    if (stmt != NULL && stmt->want_dml_rowcounts && stmt->dml_rowcounts == NULL
        && seer_reader_remaining(r) > 0 && !is_known_token(r->buf[r->pos])) {
        int64_t cnt = seer_dec_sb4(r);
        if (cnt > 0 && cnt <= 65535 && seer_reader_ok(r)) {
            uint32_t *arr = malloc((size_t)cnt * sizeof *arr);
            if (arr != NULL) {
                for (int64_t i = 0; i < cnt && seer_reader_ok(r); i++)
                    arr[i] = (uint32_t)seer_dec_sb4(r);
                stmt->dml_rowcounts   = arr;
                stmt->n_dml_rowcounts = (size_t)cnt;
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
    stmt->berrs  = NULL;
    stmt->nberrs = 0;
}

/* Read an array-DML batch field (§6.7): a ub4 count, then a DALC blob packing
 * that many var-int ub4 values. On SEER_OK *out is a malloc'd array of *n
 * values (NULL/0 when the count is zero); caller frees. */
static SeerStatus read_batch_ub4_array(SeerReader *r, uint32_t **out, size_t *n)
{
    *out = NULL;
    *n   = 0;
    int64_t count = seer_dec_sb4(r);
    if (count <= 0 || count > 65535)
        return seer_reader_ok(r) ? SEER_OK : SEER_EPROTO;

    uint8_t *blob = NULL;
    size_t   blen = 0;
    if (seer_dec_dalc(r, &blob, &blen) != SEER_OK)
        return SEER_EPROTO;
    uint32_t *arr = malloc((size_t)count * sizeof *arr);
    if (arr == NULL) {
        free(blob);
        return SEER_ENOMEM;
    }
    SeerReader br;
    seer_reader_init(&br, blob, blen);
    for (int64_t i = 0; i < count; i++)
        arr[i] = (uint32_t)seer_dec_sb4(&br);
    free(blob);
    *out = arr;
    *n   = (size_t)count;
    return SEER_OK;
}

static SeerStatus parse_oer(SeerReader *r, SeerStmt *stmt, OerResult *oer)
{
    oer->call_status = seer_dec_sb4(r);
    (void)seer_dec_sb4(r);                 /* end-to-end seq# */
    oer->row_count = seer_dec_sb4(r);      /* current row number / DML rowcount */
    oer->err_code = seer_dec_sb4(r);
    (void)seer_dec_sb4(r);                 /* array elem error 1 */
    (void)seer_dec_sb4(r);                 /* array elem error 2 */
    oer->cursor_id = seer_dec_sb4(r);
    (void)seer_dec_sb4(r);                 /* error position */
    seer_reader_bytes(r, 6);               /* sql_type..warn_flags */
    (void)seer_dec_sb4(r);                 /* rowid: data object  */
    (void)seer_dec_sb4(r);                 /* rowid: file         */
    seer_reader_bytes(r, 1);               /* rowid: reserved     */
    (void)seer_dec_sb4(r);                 /* rowid: block        */
    (void)seer_dec_sb4(r);                 /* rowid: slot         */
    (void)seer_dec_sb4(r);                 /* os error            */
    seer_reader_bytes(r, 2);               /* statement #, call # */
    (void)seer_dec_sb4(r);                 /* padding             */
    (void)seer_dec_sb4(r);                 /* successful iterations */
    seer_skip_bytes_with_length(r);        /* oerrdd */

    /* Batch-error arrays (all empty for a plain statement; populated by an
     * array-DML execute in batcherrors mode, §6.7). The code and offset arrays
     * line up by position with the messages: error i hit iteration
     * offsets[i] with ORA-codes[i] and text messages[i]. */
    uint32_t *codes = NULL, *offsets = NULL;
    size_t    ncodes = 0, noffsets = 0;
    SeerStatus bst = read_batch_ub4_array(r, &codes, &ncodes);
    if (bst == SEER_OK)
        bst = read_batch_ub4_array(r, &offsets, &noffsets);
    if (bst != SEER_OK) {
        free(codes);
        free(offsets);
        return bst;
    }

    char  **msgs = NULL;
    size_t  nmsgs = 0;
    int64_t nmsg = seer_dec_sb4(r);
    if (nmsg > 0 && nmsg < 65536) {
        msgs = calloc((size_t)nmsg, sizeof *msgs);
        seer_reader_bytes(r, 1);                /* indicator byte */
        for (int64_t i = 0; i < nmsg && seer_reader_ok(r); i++) {
            char *m = NULL;
            seer_read_str(r, &m);
            if (msgs != NULL)
                msgs[i] = m;                    /* takes ownership */
            else
                free(m);
            seer_reader_bytes(r, 2);            /* per-message trailer */
        }
        if (msgs != NULL)
            nmsgs = (size_t)nmsg;
    }

    if (!seer_reader_ok(r)) {
        free(codes);
        free(offsets);
        for (size_t i = 0; i < nmsgs; i++) free(msgs[i]);
        free(msgs);
        return SEER_EPROTO;
    }

    /* Assemble the captured per-row failures onto the statement. */
    size_t nb = noffsets;
    if (ncodes > nb) nb = ncodes;
    if (nmsgs  > nb) nb = nmsgs;
    if (nb > 0) {
        free_batch_errors(stmt);
        stmt->berrs = calloc(nb, sizeof *stmt->berrs);
        if (stmt->berrs != NULL) {
            stmt->nberrs = nb;
            for (size_t i = 0; i < nb; i++) {
                stmt->berrs[i].row     = i < noffsets ? offsets[i] : 0;
                stmt->berrs[i].code    = i < ncodes   ? codes[i]   : 0;
                stmt->berrs[i].message = i < nmsgs    ? msgs[i]    : NULL;
                if (i < nmsgs) msgs[i] = NULL;  /* ownership moved */
            }
        }
    }
    free(codes);
    free(offsets);
    for (size_t i = 0; i < nmsgs; i++) free(msgs[i]);
    free(msgs);

    /* 12c+ extends the OER before the trailing message: an extended error number
     * + rowcount (12.1+), then a SQL type + server checksum (20.1+). Skipping
     * these by field version keeps the message DALC aligned. */
    if (stmt->conn->field_version >= TTC_FIELD_VERSION_12_1) {
        (void)seer_dec_sb4(r);             /* extended error number */
        (void)seer_dec_sb4(r);             /* extended rowcount (ub8) */
        if (stmt->conn->field_version >= TTC_FIELD_VERSION_20_1) {
            (void)seer_dec_sb4(r);         /* SQL type */
            (void)seer_dec_sb4(r);         /* server checksum */
        }
    }

    /* Trailing "ORA-NNNNN: ..." message when the error code is non-zero. */
    if (oer->err_code != 0 && seer_reader_remaining(r) > 0) {
        uint8_t *msg = NULL;
        size_t   mlen = 0;
        if (seer_dec_dalc(r, &msg, &mlen) == SEER_OK && msg != NULL) {
            /* Build the replacement first, then swap: the old buffer is only
             * freed once the new one is fully populated, so no read ever touches
             * freed memory and an allocation failure leaves the prior error
             * intact instead of nulling it. */
            char *nbuf = malloc(mlen + 1);
            if (nbuf != NULL) {
                memcpy(nbuf, msg, mlen);
                nbuf[mlen] = '\0';
                free(stmt->conn->last_error);
                stmt->conn->last_error = nbuf;
            }
        }
        free(msg);
    }
    return SEER_OK;
}

/* I/O vector for an anonymous PL/SQL block's binds (§6.5). Reads the per-bind
 * directions; for each OUT / IN OUT bind a value follows in a TTI_RXD, which we
 * decode (per the bind's declared type) into pbinds[i].out. */
static SeerStatus parse_iov(SeerReader *r, SeerStmt *stmt)
{
    (void)seer_reader_u8(r);                       /* flag */
    int64_t num_requests = seer_dec_sb4(r);
    int64_t num_iters    = seer_dec_sb4(r);
    int64_t num_binds    = num_iters * 256 + num_requests;
    (void)seer_dec_sb4(r);                         /* num iters this time   */
    (void)seer_dec_sb4(r);                         /* uac buffer length     */
    int64_t bvlen = seer_dec_sb4(r);               /* fast-fetch bit vector */
    if (bvlen > 0) seer_reader_bytes(r, (size_t)bvlen);
    int64_t ridlen = seer_dec_sb4(r);              /* rowid                 */
    if (ridlen > 0) seer_reader_bytes(r, (size_t)ridlen);
    if (num_binds < 0 || num_binds > 100000 || !seer_reader_ok(r))
        return SEER_EPROTO;

    uint8_t *dirs = malloc(num_binds ? (size_t)num_binds : 1);
    if (dirs == NULL)
        return SEER_ENOMEM;
    bool has_out = false;
    for (int64_t i = 0; i < num_binds; i++) {
        dirs[i] = seer_reader_u8(r);
        if (dirs[i] != 32)                         /* 32 = IN; else OUT/IN OUT */
            has_out = true;
    }
    if (!seer_reader_ok(r)) {
        free(dirs);
        return SEER_EPROTO;
    }

    /* Returned OUT values, in bind order. A scalar value is a DALC blob plus a
     * 1-byte indicator; a REF CURSOR value is an inline describe + cursor id. */
    if (has_out && seer_reader_remaining(r) > 0 && r->buf[r->pos] == TTI_RXD) {
        (void)seer_reader_u8(r);                   /* RXD token */
        for (int64_t i = 0; i < num_binds; i++) {
            if (dirs[i] == 32)
                continue;
            SeerBind *b = (stmt != NULL && i < stmt->npbinds) ? &stmt->pbinds[i] : NULL;
            if (b != NULL && b->oac_type == ORA_TYPE_REFCURSOR) {
                if (parse_refcursor_out(r, stmt) != SEER_OK) { free(dirs); return SEER_EPROTO; }
                continue;
            }
            if (b != NULL && b->is_array) {
                /* OUT assoc array (#122): ub4 count, then each element as a DALC
                 * value + a ub4 per-element return code. */
                int64_t count = seer_dec_sb4(r);
                if (count < 0 || count > 1000000 || !seer_reader_ok(r)) { free(dirs); return SEER_EPROTO; }
                for (int k = 0; k < b->out_arr_n; k++) free(b->out_arr[k].data);
                free(b->out_arr);
                b->out_arr = count ? calloc((size_t)count, sizeof *b->out_arr) : NULL;
                b->out_arr_n = 0;
                for (int64_t e = 0; e < count; e++) {
                    uint8_t *ev = NULL; size_t evl = 0;
                    if (seer_dec_dalc(r, &ev, &evl) != SEER_OK) { free(ev); free(dirs); return SEER_EPROTO; }
                    (void)seer_dec_sb4(r);         /* per-element return code (ub4) */
                    if (b->out_arr != NULL)
                        decode_scalar(b->oac_type ? b->oac_type : ORA_TYPE_VARCHAR,
                                      ev, evl, &b->out_arr[e]);
                    free(ev);
                }
                b->out_arr_n = (int)count;
                continue;
            }
            uint8_t *v = NULL;
            size_t   vl = 0;
            if (seer_dec_dalc(r, &v, &vl) != SEER_OK) { free(v); free(dirs); return SEER_EPROTO; }
            (void)seer_reader_u8(r);               /* present/NULL indicator */
            if (b != NULL) {
                free(b->out.data);
                b->out = (SeerCell){ 0 };
                decode_scalar(b->oac_type ? b->oac_type : 1, v, vl, &b->out);
            }
            free(v);
        }
    }
    free(dirs);
    return seer_reader_ok(r) ? SEER_OK : SEER_EPROTO;
}

/* DML RETURNING ... INTO return data (§5.6): for each OUT (return) bind, in bind
 * order, a ub4 affected-row count then per row a DALC value and an sb4 truncation
 * length. We capture the first affected row's value into pbinds[i].out (one ODBC
 * OUT parameter holds one value). */
static SeerStatus parse_returning_rxd(SeerReader *r, SeerStmt *stmt)
{
    for (int i = 0; i < stmt->npbinds; i++) {
        SeerBind *b = &stmt->pbinds[i];
        if (!b->is_out)
            continue;
        int64_t num_rows = seer_dec_sb4(r);
        if (num_rows < 0 || num_rows > 1000000 || !seer_reader_ok(r))
            return SEER_EPROTO;
        for (int64_t row = 0; row < num_rows; row++) {
            uint8_t *v = NULL;
            size_t   vl = 0;
            if (seer_dec_dalc(r, &v, &vl) != SEER_OK) { free(v); return SEER_EPROTO; }
            (void)seer_dec_sb4(r);                 /* sb4 actual/truncation length */
            if (row == 0) {                        /* keep the first row's value */
                free(b->out.data);
                b->out = (SeerCell){ 0 };
                decode_scalar(b->oac_type ? b->oac_type : ORA_TYPE_VARCHAR, v, vl, &b->out);
            }
            free(v);
        }
    }
    return seer_reader_ok(r) ? SEER_OK : SEER_EPROTO;
}

/* Consume a server-side piggyback (TTI_SVR_PIGGYBACK, DRCP #130) the server
 * prepends to a pooled session's response. The values (assigned session id /
 * serial, session-state pairs, MTS pid) aren't needed - skip the block
 * byte-for-byte so the real response tokens follow. Mirrors python-oracledb. */
static SeerStatus skip_server_piggyback(SeerReader *r)
{
    uint8_t opcode = seer_reader_u8(r);
    if (opcode == TNS_SVR_PIG_SESS_RET) {
        (void)seer_dec_sb4(r);                 /* number of DTYs (ub2)   */
        (void)seer_reader_u8(r);               /* length of DTYs (ub1)   */
        int64_t npairs = seer_dec_sb4(r);      /* number of pairs (ub2)  */
        if (npairs > 0) {
            (void)seer_reader_u8(r);
            for (int64_t i = 0; i < npairs && seer_reader_ok(r); i++) {
                if (seer_dec_sb4(r) > 0) seer_skip_chunked(r);   /* key   */
                if (seer_dec_sb4(r) > 0) seer_skip_chunked(r);   /* value */
                (void)seer_dec_sb4(r);         /* pair flags (ub2)       */
            }
        }
        (void)seer_dec_sb4(r);                 /* session flags (ub4)    */
        (void)seer_dec_sb4(r);                 /* session id (ub4)       */
        (void)seer_dec_sb4(r);                 /* serial number (ub2)    */
    } else if (opcode == TNS_SVR_PIG_OS_PID_MTS) {
        (void)seer_dec_sb4(r);                 /* ub2                    */
        seer_skip_chunked(r);                  /* pid bytes              */
    } else if (opcode == TNS_SVR_PIG_SYNC) {
        /* Sessionless-txn sync state (§31): keyword-value pairs (keyword 201 =
         * the transaction id) the server piggybacks on the next call's response
         * while a sessionless txn is active. The values aren't needed - consume
         * the block byte-for-byte so the real tokens follow. The pair loop is
         * framed like SESS_RET but the length ub1 is always present. */
        (void)seer_dec_sb4(r);                 /* number of DTYs (ub2)   */
        (void)seer_reader_u8(r);               /* length of DTYs (ub1)   */
        int64_t npairs = seer_dec_sb4(r);      /* number of pairs (ub2)  */
        (void)seer_reader_u8(r);               /* length (ub1)           */
        for (int64_t i = 0; i < npairs && seer_reader_ok(r); i++) {
            if (seer_dec_sb4(r) > 0) seer_skip_chunked(r);   /* text value   */
            if (seer_dec_sb4(r) > 0) seer_skip_chunked(r);   /* binary value */
            (void)seer_dec_sb4(r);             /* keyword num (ub2)      */
        }
        (void)seer_dec_sb4(r);                 /* overall flags (ub4)    */
    } else {
        return SEER_EPROTO;                    /* unknown piggyback opcode */
    }
    return seer_reader_ok(r) ? SEER_OK : SEER_EPROTO;
}

/* Walk one response message, appending rows and capturing the OER outcome. */
static SeerStatus parse_response(SeerStmt *stmt, const uint8_t *buf, size_t len,
                                 bool expect_dcb, OerResult *oer)
{
    SeerReader r;
    seer_reader_init(&r, buf, len);
    /* 12c+ sends 0xFE-chunked DALC values with sb4 chunk lengths (11g uses ub1);
     * a large value (>= 254 bytes) desyncs without this. */
    r.sb4_chunks = stmt->conn->field_version >= TTC_FIELD_VERSION_12_1;

    uint8_t *bv = NULL;
    size_t   bvlen = 0;
    SeerStatus st = SEER_OK;
    bool got_oer = false;

    while (seer_reader_remaining(&r) > 0 && seer_reader_ok(&r)) {
        uint8_t tok = seer_reader_u8(&r);
        switch (tok) {
        case TTI_DCB:
            st = expect_dcb ? parse_dcb(&r, stmt) : SEER_EPROTO;
            break;
        case TTI_RXH:
            st = parse_rxh(&r);
            break;
        case TTI_BVC:
            st = parse_bvc(&r, stmt->ncols, &bv, &bvlen);
            break;
        case TTI_RXD:
            if (stmt->returning) {
                st = parse_returning_rxd(&r, stmt);
            } else {
                st = parse_rxd(&r, stmt, bv, bvlen);
                free(bv); bv = NULL; bvlen = 0;
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
            st = skip_server_piggyback(&r);
            break;
        case TTI_OER:
            st = parse_oer(&r, stmt, oer);
            got_oer = true;
            break;
        case TTI_STA:
            got_oer = true;            /* treat as terminal */
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
            (void)seer_dec_sb4(&r);
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
        seer_log(SEER_LOG_DEBUG, "stmt: parse failed st=%d at pos %zu/%zu (ok=%d)",
                 (int)st, r.pos, r.len, (int)seer_reader_ok(&r));
        return st;
    }
    if (!got_oer)
        return SEER_EPROTO;
    return SEER_OK;
}

/* ----------------------------------------------------------- input binds */

/* Place an encoded value at 1-based position `param`, iteration `cur_iter`,
 * growing the bind array as needed and freeing any previous value there. The
 * OAC fields apply to the position (size grows to the widest value across
 * iterations). Takes ownership of `rxd`. */
static SeerStatus store_bind(SeerStmt *s, int param, uint8_t oac_type,
                             uint32_t oac_size, uint32_t oac_charset, uint8_t oac_flag,
                             bool is_out, uint8_t *rxd, size_t rxd_len)
{
    if (param < 1 || param > 1024) {
        free(rxd);
        return SEER_EPARAM;
    }
    int iters = s->n_iters > 0 ? s->n_iters : 1;
    int it    = (s->cur_iter >= 0 && s->cur_iter < iters) ? s->cur_iter : 0;

    if (param > s->npbinds) {
        SeerBind *nb = realloc(s->pbinds, (size_t)param * sizeof *nb);
        if (nb == NULL) {
            free(rxd);
            return SEER_ENOMEM;
        }
        for (int i = s->npbinds; i < param; i++)
            nb[i] = (SeerBind){ 0 };
        s->pbinds  = nb;
        s->npbinds = param;
    }

    SeerBind *b = &s->pbinds[param - 1];
    if (b->rxd == NULL) {
        b->rxd     = calloc((size_t)iters, sizeof *b->rxd);
        b->rxd_len = calloc((size_t)iters, sizeof *b->rxd_len);
        if (b->rxd == NULL || b->rxd_len == NULL) {
            free(rxd);
            return SEER_ENOMEM;
        }
    }
    b->oac_type    = oac_type;
    b->oac_charset = oac_charset;
    b->oac_flag    = oac_flag;
    b->is_out      = is_out;
    if (oac_size > b->oac_size)
        b->oac_size = oac_size;
    free(b->rxd[it]);
    b->rxd[it]     = rxd;
    b->rxd_len[it] = rxd_len;
    return SEER_OK;
}

/* Encode a bind value (oracledb encode_chr). Two forms, split at 12.2:
 *   - 12.2+ (write_bytes_with_length): inline <ub1 len><bytes> for n < 254, else
 *     the 0xFE marker + 64-byte chunks each prefixed by an *sb4* length, then a
 *     zero-length terminator.
 *   - pre-12.2 (11g/10g): inline <ub1 len><bytes> for n <= 64, else 0xFE + 64-byte
 *     chunks each prefixed by a bare *ub1* length, then a 0 terminator.
 * Sending the wrong chunk width desyncs the server's two-task conversion
 * (ORA-03120). Used for VARCHAR and RAW bind values; malloc'd *out. */
static SeerStatus encode_chr(const uint8_t *data, size_t n, uint8_t fv,
                             uint8_t **out, size_t *outlen)
{
    bool new_form = fv >= TTC_FIELD_VERSION_12_2;
    size_t inline_max = new_form ? 253 : 64;
    SeerWriter w;
    if (!seer_writer_init(&w, n + 16))
        return SEER_ENOMEM;
    if (n <= inline_max) {
        seer_writer_u8(&w, (uint8_t)n);
        seer_writer_bytes(&w, data, n);
    } else {
        seer_writer_u8(&w, 0xFE);
        for (size_t i = 0; i < n; i += 0x40) {
            size_t chunk = (n - i < 0x40) ? n - i : 0x40;
            if (new_form) seer_enc_sb4(&w, (uint32_t)chunk);
            else          seer_writer_u8(&w, (uint8_t)chunk);
            seer_writer_bytes(&w, data + i, chunk);
        }
        if (new_form) seer_enc_sb4(&w, 0);     /* zero-length terminator */
        else          seer_writer_u8(&w, 0);
    }
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
    size_t  nn = seer_encode_number_int(value, num);
    uint8_t *rxd = NULL; size_t rl = 0;
    SeerStatus st = rxd_short(num, nn, &rxd, &rl);
    if (st != SEER_OK)
        return st;
    return store_bind(stmt, param, ORA_TYPE_NUMBER, 22, 0, 0, false, rxd, rl);
}

SeerStatus seer_stmt_bind_text(SeerStmt *stmt, int param, const char *str, int len)
{
    if (stmt == NULL || str == NULL)
        return SEER_EPARAM;
    size_t n = (len < 0) ? strlen(str) : (size_t)len;
    uint8_t *rxd = NULL; size_t rl = 0;
    SeerStatus st = encode_chr((const uint8_t *)str, n, stmt->conn->field_version, &rxd, &rl);
    if (st != SEER_OK)
        return st;
    /* Past the VARCHAR2 limit (e.g. a large CLOB insert) declare a streamed LONG;
     * the chunked value above and TTC fragmentation carry it. A VARCHAR OAC with
     * an over-limit size is rejected by the server. */
    bool big = n > 4000;
    return store_bind(stmt, param, big ? ORA_TYPE_LONG : ORA_TYPE_VARCHAR,
                      (uint32_t)(n ? n : 1), 873, 16, false, rxd, rl);
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
    char  *u16    = NULL;
    size_t u16len = 0;
    if (n > 0 && seer_iconv("UTF-8", "UTF-16BE", str, n, &u16, &u16len) != 0)
        return SEER_EPROTO;
    uint8_t *rxd = NULL; size_t rl = 0;
    SeerStatus st = encode_chr((const uint8_t *)(u16 ? u16 : ""), u16len,
                               stmt->conn->field_version, &rxd, &rl);
    free(u16);
    if (st != SEER_OK)
        return st;
    return store_bind(stmt, param, ORA_TYPE_VARCHAR,
                      (uint32_t)(u16len ? u16len : 1), 2000, 16, false, rxd, rl);
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
    uint8_t *rxd = NULL; size_t rl = 0;
    SeerStatus st = encode_chr((const uint8_t *)data, n, stmt->conn->field_version, &rxd, &rl);
    if (st != SEER_OK)
        return st;
    /* Past the RAW limit (2000), stream as LONG RAW (e.g. a large BLOB insert). */
    bool big = n > 2000;
    return store_bind(stmt, param, big ? ORA_TYPE_LONGRAW : ORA_TYPE_RAW,
                      (uint32_t)(n ? n : 1), 0, 16, false, rxd, rl);
}

SeerStatus seer_stmt_bind_date(SeerStmt *stmt, int param, int year, int month,
                               int day, int hour, int minute, int second)
{
    if (stmt == NULL)
        return SEER_EPARAM;
    uint8_t d[7] = {
        (uint8_t)(year / 100 + 100), (uint8_t)(year % 100 + 100),
        (uint8_t)month, (uint8_t)day,
        (uint8_t)(hour + 1), (uint8_t)(minute + 1), (uint8_t)(second + 1),
    };
    uint8_t *rxd = NULL; size_t rl = 0;
    SeerStatus st = rxd_short(d, sizeof d, &rxd, &rl);
    if (st != SEER_OK)
        return st;
    return store_bind(stmt, param, ORA_TYPE_DATE, 7, 0, 0, false, rxd, rl);
}

SeerStatus seer_stmt_bind_timestamp(SeerStmt *stmt, int param, int year, int month,
                                    int day, int hour, int minute, int second,
                                    uint32_t nanos)
{
    if (stmt == NULL)
        return SEER_EPARAM;
    /* 7-byte DATE prefix + 4 big-endian nanoseconds (Oracle TIMESTAMP, §11). */
    uint8_t d[11] = {
        (uint8_t)(year / 100 + 100), (uint8_t)(year % 100 + 100),
        (uint8_t)month, (uint8_t)day,
        (uint8_t)(hour + 1), (uint8_t)(minute + 1), (uint8_t)(second + 1),
        (uint8_t)(nanos >> 24), (uint8_t)(nanos >> 16),
        (uint8_t)(nanos >> 8),  (uint8_t)nanos,
    };
    uint8_t *rxd = NULL; size_t rl = 0;
    SeerStatus st = rxd_short(d, sizeof d, &rxd, &rl);
    if (st != SEER_OK)
        return st;
    return store_bind(stmt, param, ORA_TYPE_TIMESTAMP, 11, 0, 0, false, rxd, rl);
}

/* INTERVAL YEAR TO MONTH (5 bytes): ub4 (years biased by 2^31) + ub1 (months
 * biased by 60). A negative interval carries the sign on both components. */
SeerStatus seer_stmt_bind_interval_ym(SeerStmt *stmt, int param,
                                      int32_t years, int32_t months)
{
    if (stmt == NULL)
        return SEER_EPARAM;
    uint32_t by = (uint32_t)years + 0x80000000u;
    uint8_t iv[5] = {
        (uint8_t)(by >> 24), (uint8_t)(by >> 16), (uint8_t)(by >> 8), (uint8_t)by,
        (uint8_t)(months + 60),
    };
    uint8_t *rxd = NULL; size_t rl = 0;
    SeerStatus st = rxd_short(iv, sizeof iv, &rxd, &rl);
    if (st != SEER_OK)
        return st;
    return store_bind(stmt, param, ORA_TYPE_INTERVAL_YM, 5, 0, 0, false, rxd, rl);
}

/* INTERVAL DAY TO SECOND (11 bytes): ub4 (days biased by 2^31), ub1 H/M/S biased
 * by 60, ub4 (nanoseconds biased by 2^31). */
SeerStatus seer_stmt_bind_interval_ds(SeerStmt *stmt, int param, int32_t days,
                                      int32_t hours, int32_t mins, int32_t secs,
                                      int32_t nanos)
{
    if (stmt == NULL)
        return SEER_EPARAM;
    uint32_t bd = (uint32_t)days  + 0x80000000u;
    uint32_t bn = (uint32_t)nanos + 0x80000000u;
    uint8_t iv[11] = {
        (uint8_t)(bd >> 24), (uint8_t)(bd >> 16), (uint8_t)(bd >> 8), (uint8_t)bd,
        (uint8_t)(hours + 60), (uint8_t)(mins + 60), (uint8_t)(secs + 60),
        (uint8_t)(bn >> 24), (uint8_t)(bn >> 16), (uint8_t)(bn >> 8), (uint8_t)bn,
    };
    uint8_t *rxd = NULL; size_t rl = 0;
    SeerStatus st = rxd_short(iv, sizeof iv, &rxd, &rl);
    if (st != SEER_OK)
        return st;
    return store_bind(stmt, param, ORA_TYPE_INTERVAL_DS, 11, 0, 0, false, rxd, rl);
}

SeerStatus seer_stmt_bind_double(SeerStmt *stmt, int param, double value)
{
    if (stmt == NULL)
        return SEER_EPARAM;
    uint8_t enc[8];
    seer_encode_bdouble(value, enc);
    uint8_t *rxd = NULL; size_t rl = 0;
    SeerStatus st = rxd_short(enc, sizeof enc, &rxd, &rl);
    if (st != SEER_OK)
        return st;
    return store_bind(stmt, param, ORA_TYPE_BDOUBLE, 8, 0, 0, false, rxd, rl);
}

SeerStatus seer_stmt_bind_float(SeerStmt *stmt, int param, float value)
{
    if (stmt == NULL)
        return SEER_EPARAM;
    uint8_t enc[4];
    seer_encode_bfloat(value, enc);
    uint8_t *rxd = NULL; size_t rl = 0;
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
    uint8_t v[2] = { 0x01, value ? 1 : 0 };
    uint8_t *rxd = NULL; size_t rl = 0;
    SeerStatus st = rxd_short(v, sizeof v, &rxd, &rl);   /* -> 02 01 <0/1> */
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
    rxd[0] = 0;                     /* NULL value */
    return store_bind(stmt, param, ORA_TYPE_VARCHAR, 1, 873, 16, false, rxd, 1); /* NULL */
}

SeerStatus seer_stmt_bind_out(SeerStmt *stmt, int param, int ora_type, int max_size)
{
    if (stmt == NULL)
        return SEER_EPARAM;
    uint8_t  oac_type = ORA_TYPE_VARCHAR, oac_flag = 0;
    uint32_t oac_size = 0, oac_charset = 0;
    switch (ora_type) {
    case ORA_TYPE_NUMBER:
        oac_type = ORA_TYPE_NUMBER;  oac_size = 22; break;
    case ORA_TYPE_DATE:
        oac_type = ORA_TYPE_DATE;    oac_size = 7;  break;
    case ORA_TYPE_BDOUBLE:
        oac_type = ORA_TYPE_BDOUBLE; oac_size = 8;  break;
    case ORA_TYPE_RAW:
        oac_type = ORA_TYPE_RAW;     oac_size = (uint32_t)(max_size > 0 ? max_size : 2000);
        oac_flag = 16;  break;
    case ORA_TYPE_REFCURSOR:
        oac_type = ORA_TYPE_REFCURSOR; oac_size = 1; oac_charset = 871; break;
    case ORA_TYPE_VARCHAR: default:
        oac_type = ORA_TYPE_VARCHAR; oac_size = (uint32_t)(max_size > 0 ? max_size : 4000);
        oac_charset = 873; oac_flag = 16; break;
    }

    uint8_t *rxd;
    size_t   rxd_len;
    if (oac_type == ORA_TYPE_REFCURSOR) {
        rxd = malloc(2);               /* REF CURSOR slot placeholder {1,0} */
        if (rxd == NULL)
            return SEER_ENOMEM;
        rxd[0] = 1;
        rxd[1] = 0;
        rxd_len = 2;
    } else {
        rxd = malloc(1);               /* NULL placeholder value */
        if (rxd == NULL)
            return SEER_ENOMEM;
        rxd[0] = 0;
        rxd_len = 1;
    }
    return store_bind(stmt, param, oac_type, oac_size, oac_charset, oac_flag,
                      true, rxd, rxd_len);
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
        for (int k = 0; k < s->pbinds[i].out_arr_n; k++)
            free(s->pbinds[i].out_arr[k].data);
        free(s->pbinds[i].out_arr);
        free(s->pbinds[i].oac_override);
    }
    free(s->pbinds);
    s->pbinds = NULL;
    s->npbinds = 0;
}

SeerStatus seer_stmt_set_array_size(SeerStmt *stmt, int n)
{
    if (stmt == NULL || n < 1)
        return SEER_EPARAM;
    free_binds(stmt);              /* iteration count changes the bind layout */
    stmt->n_iters  = n;
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

SeerStatus seer_stmt_batch_error(SeerStmt *stmt, size_t i, unsigned *row,
                                 unsigned *code, const char **message)
{
    if (stmt == NULL || i >= stmt->nberrs)
        return SEER_EPARAM;
    if (row != NULL)     *row     = stmt->berrs[i].row;
    if (code != NULL)    *code    = stmt->berrs[i].code;
    if (message != NULL) *message = stmt->berrs[i].message;
    return SEER_OK;
}

/* ------------------------------------------------------------ exec message */

/* Statement class - drives the execute options, All8 array, and long-max. */
typedef enum { STMT_SELECT, STMT_BLOCK, STMT_CHANGE } StmtKind;

/* Classify by the leading keyword: SELECT/WITH are queries, BEGIN/DECLARE are
 * anonymous PL/SQL blocks, everything else (DML, DDL) is a "change". */
static StmtKind classify_sql(const char *sql)
{
    const char *p = sql;
    while (*p != '\0' && isspace((unsigned char)*p))
        p++;
    while (*p == '(') {                 /* "(SELECT ...)" */
        p++;
        while (*p != '\0' && isspace((unsigned char)*p))
            p++;
    }
    if (strncasecmp(p, "SELECT", 6) == 0 || strncasecmp(p, "WITH", 4) == 0)
        return STMT_SELECT;
    if (strncasecmp(p, "BEGIN", 5) == 0 || strncasecmp(p, "DECLARE", 7) == 0)
        return STMT_BLOCK;
    return STMT_CHANGE;
}

/* Whether `sql`'s parsed cursor is safe to keep in the statement cache and
 * re-execute without a re-parse. DDL (and anything not SELECT/WITH, DML or a
 * PL/SQL block) is excluded: a no-parse re-execute of e.g. CREATE/DROP does not
 * actually re-run the DDL. */
static bool sql_is_cacheable(const char *sql)
{
    const char *p = sql;
    while (*p != '\0' && isspace((unsigned char)*p))
        p++;
    while (*p == '(') {
        p++;
        while (*p != '\0' && isspace((unsigned char)*p))
            p++;
    }
    static const char *const kw[] = { "SELECT", "WITH", "INSERT", "UPDATE",
                                      "DELETE", "MERGE", "BEGIN", "DECLARE" };
    for (size_t i = 0; i < sizeof kw / sizeof kw[0]; i++) {
        size_t n = strlen(kw[i]);
        if (strncasecmp(p, kw[i], n) == 0
            && !isalnum((unsigned char)p[n]) && p[n] != '_')
            return true;
    }
    return false;
}

/* Emit one OAC bind descriptor. The 12c+ form (oracledb _write_column_metadata)
 * is differently shaped from 11g's encode_token_raw - a USE_INDICATORS flag
 * byte, a ub8 cont-flag, OID/version, the charset as a ub2 with its csfrm, a LOB
 * prefetch length and a trailing oaccolid - and an 11g-shaped OAC to a 12c
 * server is rejected (ORA-03115). */
static void emit_oac(SeerWriter *w, int fv, uint8_t dtype, uint32_t length,
                     uint32_t flag, uint32_t charset)
{
    if (fv >= TTC_FIELD_VERSION_12_2) {
        uint32_t bind_charset;
        uint8_t  csfrm;
        if (charset == 0)         { bind_charset = 0;    csfrm = 0; }
        else if (charset == 2000) { bind_charset = 2000; csfrm = 2; }  /* AL16UTF16 */
        else                      { bind_charset = 873;  csfrm = 1; }  /* AL32UTF8  */
        seer_writer_u8(w, dtype);
        seer_writer_u8(w, 1);          /* TNS_BIND_USE_INDICATORS */
        seer_writer_u8(w, 0);
        seer_writer_u8(w, 0);
        seer_enc_sb4(w, length);
        seer_enc_sb4(w, 0);            /* max number of array elements */
        seer_enc_sb4(w, 0);            /* cont flag (ub8) */
        seer_enc_sb4(w, 0);            /* OID */
        seer_enc_sb4(w, 0);            /* version */
        seer_enc_sb4(w, bind_charset); /* charset id (ub2) */
        seer_writer_u8(w, csfrm);      /* character set form */
        seer_enc_sb4(w, 0);            /* LOB prefetch length */
        seer_enc_sb4(w, 0);            /* oaccolid */
        return;
    }
    uint8_t form_of_use = (charset == 2000) ? 2 : 1;   /* AL16UTF16 => 2 */
    seer_writer_u8(w, dtype);
    seer_writer_u8(w, 3);
    seer_writer_u8(w, 0);
    seer_writer_u8(w, 0);
    seer_enc_sb4(w, length);
    seer_writer_u8(w, 0);
    seer_enc_sb4(w, flag);
    seer_writer_u8(w, 0);
    seer_writer_u8(w, 0);
    seer_enc_sb4(w, charset);
    seer_writer_u8(w, form_of_use);
    seer_enc_sb4(w, 0);                                  /* max */
}

static SeerStatus build_exec(SeerStmt *stmt, SeerWriter *w)
{
    size_t qlen = strlen(stmt->sql);
    int    nb   = stmt->npbinds;
    StmtKind kind = classify_sql(stmt->sql);
    /* Array binding (iteration count > 1) applies to DML/DDL only. */
    int    iters = (kind == STMT_CHANGE && stmt->n_iters > 1) ? stmt->n_iters : 1;
    if (!seer_writer_init(w, 160 + qlen + (size_t)iters * 32))
        return SEER_ENOMEM;

    /* Per statement class (PROTOCOL.md §5.1): a SELECT parses+executes+fetches
     * (0x8021, All8 type 1, LONG-max all-ones); a PL/SQL block uses the PL/SQL
     * option set (0x0421); DML/DDL uses 0x8021 with All8 type 0. Binds add
     * 0x8; autocommit adds 0x100 (not on a SELECT - nothing to commit). */
    uint32_t opt = (kind == STMT_BLOCK) ? 0x0421u : 0x8021u;
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
        if (stmt->pbinds[i].is_out) { has_out = true; break; }
    stmt->returning = (kind == STMT_CHANGE) && has_out;

    /* Array-DML per-iteration row counts (12c+): al8i4[9] = 0xC000 plus the
     * al8pidmlrc iteration count below; the server then returns one row count per
     * iteration in the response RPA. */
    bool dml_rowcounts = stmt->want_dml_rowcounts && kind == STMT_CHANGE && iters > 1
                         && stmt->conn->field_version >= TTC_FIELD_VERSION_12_2;

    uint32_t lmax = (kind == STMT_SELECT) ? 0xFFFFFFFFu : 0u;
    uint32_t all8[13] = { 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    if (kind == STMT_SELECT)
        all8[7] = 1;                       /* type = SELECT          */
    else
        all8[1] = (uint32_t)iters;         /* iteration count (rows) */
    if (dml_rowcounts)
        all8[9] = TNS_AL8I4_ARRAY_DML_ROWCOUNTS;

    /* fv24 (23ai) SELECT/fetch execute (PROTOCOL.md §20): the LONG-max sentinel
     * 0xFFFFFFFF must be 0 (else ORA-03120), and the fetch flags options |= 0x40
     * and al8i4[9] |= 0x8000 are required. Setting those flags on a DML/DDL
     * execute instead is rejected (ORA-03137 kpoal8Check-5). */
    if (stmt->conn->field_version > TTC_FIELD_VERSION_23_1 && kind == STMT_SELECT) {
        lmax     = 0;
        opt     |= 0x40u;
        all8[9] |= 0x8000u;
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
        seer_writer_u8(w, TTI_MSG_TYPE_PIGGYBACK);
        seer_writer_u8(w, TTI_OCCA);
        seer_writer_u8(w, seer_ttc_next_seq(c));
        if (c->field_version > TTC_FIELD_VERSION_23_1)
            seer_enc_sb4(w, 0);                /* ub8 token (fv24) */
        seer_writer_u8(w, 1);                  /* cursor-list pointer present */
        seer_enc_sb4(w, (uint32_t)c->n_close);
        for (int i = 0; i < c->n_close; i++)
            seer_enc_sb4(w, (uint32_t)c->close_cursors[i]);
        c->n_close = 0;
    }

    /* Statement-cache reuse: re-execute a parsed cursor with no re-parse - send
     * the cached cursor id, drop the PARSE option bit, and omit the SQL text. */
    bool reuse = stmt->reuse_cursor > 0;
    if (reuse)
        opt &= ~0x0001u;                   /* PARSE off                    */

    seer_ttc_fun_header(stmt->conn, w, TTI_ALL8);
    seer_enc_sb4(w, opt);
    seer_enc_sb4(w, reuse ? (uint32_t)stmt->reuse_cursor : 0);  /* cursor    */
    seer_writer_u8(w, reuse ? 0 : 1);      /* query present                */
    seer_enc_sb4(w, reuse ? 0 : (uint32_t)qlen);   /* query length         */
    seer_writer_u8(w, 1);                  /* all8 present                 */
    seer_enc_sb4(w, 13);                   /* all8 length                  */
    seer_writer_u8(w, 0);
    seer_writer_u8(w, 0);
    seer_enc_sb4(w, lmax);                 /* long max value               */
    seer_enc_sb4(w, stmt->prefetch ? stmt->prefetch : PREFETCH_ROWS); /* prefetch */
    seer_enc_sb4(w, 0x7FFFFFFF);           /* max value                    */
    seer_writer_u8(w, nb > 0 ? 1 : 0);     /* bind present                 */
    seer_enc_sb4(w, (uint32_t)nb);         /* bind count                   */
    for (int i = 0; i < 5; i++) seer_writer_u8(w, 0);
    seer_writer_u8(w, 0);                  /* define present               */
    seer_enc_sb4(w, 0);                    /* define length                */

    seer_writer_u8(w, 0);                  /* OALL8 header: register 0,0,1 ..*/
    seer_writer_u8(w, 0);
    seer_writer_u8(w, 1);
    if ((stmt->conn->server_release >> 24) != 10)
        for (int i = 0; i < 5; i++) seer_writer_u8(w, 0);   /* .. reg_lsb..msb */

    /* 12c+ OALL8 carries the al8pidmlrc block, the al8sqlsig / SQL-id slot, and
     * (12.2_EXT1+) chunk-id pointers - all null for us - and length-prefixes the
     * SQL. Without these the server reads the al8i4 array at the wrong offset
     * and rejects the call (ORA-03120). */
    if (stmt->conn->field_version >= TTC_FIELD_VERSION_12_2) {
        if (dml_rowcounts) {
            /* al8pidmlrc: pointer(1) + ub4 (1 + iteration count) + 1. */
            seer_writer_u8(w, 1);
            seer_enc_sb4(w, (uint32_t)(1 + iters));
            seer_writer_u8(w, 1);
        } else {
            for (int i = 0; i < 3; i++) seer_writer_u8(w, 0); /* al8pidmlrc    */
        }
        for (int i = 0; i < 5; i++) seer_writer_u8(w, 0);   /* al8sqlsig / SQL id */
        if (stmt->conn->field_version > TTC_FIELD_VERSION_12_2)
            for (int i = 0; i < 2; i++) seer_writer_u8(w, 0); /* 12.2_EXT1 chunk ids */
        /* On a no-parse re-execute the SQL bytes are omitted entirely - even a
         * zero-length prefix would shift the server's read of the al8i4 array. */
        if (!reuse) {
            if (qlen < 254) {                               /* length-prefixed SQL */
                seer_writer_u8(w, (uint8_t)qlen);
                seer_writer_bytes(w, stmt->sql, qlen);
            } else {
                seer_writer_u8(w, 254);                     /* LONG chunked form */
                seer_enc_sb4(w, (uint32_t)qlen);
                seer_writer_bytes(w, stmt->sql, qlen);
                seer_enc_sb4(w, 0);                         /* zero-length terminator */
            }
        }
    } else if (!reuse) {
        seer_writer_bytes(w, stmt->sql, qlen);              /* raw SQL text (11g) */
    }
    for (int i = 0; i < 13; i++)
        seer_enc_sb4(w, all8[i]);                           /* All8 array    */

    /* Bind section: one OAC descriptor per bind position (sized to the widest
     * value across iterations), then one RXD token per iteration carrying that
     * row's values (PROTOCOL.md §5.3-5.4; array DML §5.5). */
    if (nb > 0) {
        for (int i = 0; i < nb; i++) {
            SeerBind *b = &stmt->pbinds[i];
            int fv = stmt->conn->field_version;
            if (b->oac_override != NULL)                        /* SQL OBJECT: prebuilt OAC */
                seer_writer_bytes(w, b->oac_override, b->oac_override_len);
            else if (b->oac_type == 0)
                emit_oac(w, fv, ORA_TYPE_VARCHAR, 1, 16, 873);  /* unbound -> NULL VARCHAR */
            else
                emit_oac(w, fv, b->oac_type, b->oac_size ? b->oac_size : 1,
                         b->oac_flag, b->oac_charset);
        }
        for (int it = 0; it < iters; it++) {
            seer_writer_u8(w, TTI_RXD);
            for (int i = 0; i < nb; i++) {
                SeerBind *b = &stmt->pbinds[i];
                if (stmt->returning && b->is_out)
                    continue;                              /* return bind: server-filled */
                uint8_t *rxd = (b->rxd != NULL) ? b->rxd[it] : NULL;
                if (rxd != NULL)
                    seer_writer_bytes(w, rxd, b->rxd_len[it]);
                else
                    seer_writer_u8(w, 0);                   /* unbound/NULL -> 0 */
            }
        }
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
    seer_enc_sb4(w, (uint32_t)stmt->cursor_id);
    seer_enc_sb4(w, PREFETCH_ROWS);
    if (!seer_writer_ok(w)) {
        seer_writer_free(w);
        return SEER_ENOMEM;
    }
    return SEER_OK;
}

/* ------------------------------------------------------------- public API */

/* Statement cache. take() returns a cached parsed cursor for `sql`, moving its
 * SELECT column describe out into cols/ncols, and removes the entry (the caller
 * now owns the cursor + columns). Returns 0 (and leaves *cols NULL) if not cached. */
static int stmt_cache_take(SeerConn *c, const char *sql, SeerColumn **cols, int *ncols)
{
    for (int i = 0; i < c->stmt_cache_n; i++) {
        if (strcmp(c->stmt_cache[i].sql, sql) == 0) {
            int cid = c->stmt_cache[i].cursor_id;
            *cols  = (SeerColumn *)c->stmt_cache[i].cols;
            *ncols = c->stmt_cache[i].ncols;
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
static void stmt_cache_put(SeerConn *c, const char *sql, int cursor_id,
                           SeerColumn *cols, int ncols)
{
    int cap    = (int)(sizeof c->stmt_cache / sizeof c->stmt_cache[0]);
    int nclose = (int)(sizeof c->close_cursors / sizeof c->close_cursors[0]);
    if (c->stmt_cache_n >= cap) {
        if (c->n_close < nclose)
            c->close_cursors[c->n_close++] = c->stmt_cache[0].cursor_id;
        free(c->stmt_cache[0].sql);
        free_columns((SeerColumn *)c->stmt_cache[0].cols, c->stmt_cache[0].ncols);
        memmove(&c->stmt_cache[0], &c->stmt_cache[1],
                (size_t)(c->stmt_cache_n - 1) * sizeof c->stmt_cache[0]);
        c->stmt_cache_n--;
    }
    char *dup = strdup(sql);
    if (dup == NULL) {                          /* can't cache -> close + free */
        if (c->n_close < nclose)
            c->close_cursors[c->n_close++] = cursor_id;
        free_columns(cols, ncols);
        return;
    }
    c->stmt_cache[c->stmt_cache_n].sql       = dup;
    c->stmt_cache[c->stmt_cache_n].cursor_id = cursor_id;
    c->stmt_cache[c->stmt_cache_n].cols      = cols;
    c->stmt_cache[c->stmt_cache_n].ncols     = ncols;
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
    s->conn    = conn;
    s->sql     = strdup(sql);
    s->cur     = -1;
    s->n_iters = 1;
    /* Reuse a cached parsed cursor (and its describe) for this exact SQL, if any. */
    s->reuse_cursor = stmt_cache_take(conn, sql, &s->cols, &s->ncols);
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
    for (size_t r = 0; r < stmt->nrows; r++) {
        for (int c = 0; c < stmt->ncols; c++)
            free(stmt->rows[r][c].data);
        free(stmt->rows[r]);
    }
    free(stmt->rows);
    stmt->rows     = NULL;
    stmt->nrows    = 0;
    stmt->rows_cap = 0;
    stmt->cur      = -1;
}

/* Discard any pending (unresolved) LOB cells. */
static void free_pending_lobs(SeerStmt *stmt)
{
    for (size_t k = 0; k < stmt->nplobs; k++)
        free(stmt->plobs[k].locator);
    free(stmt->plobs);
    stmt->plobs     = NULL;
    stmt->nplobs    = 0;
    stmt->plobs_cap = 0;
}

static void free_pending_objs(SeerStmt *stmt)
{
    for (size_t k = 0; k < stmt->npobjs; k++)
        free(stmt->pobjs[k].image);
    free(stmt->pobjs);
    stmt->pobjs     = NULL;
    stmt->npobjs    = 0;
    stmt->pobjs_cap = 0;
}

/* Map an ALL_TYPE_ATTRS attr_type_name to the Oracle wire type used inside an
 * object image (the subset slice 1 decodes; unknowns fall back to text). */
static uint8_t obj_type_to_ora(const char *tn)
{
    if (tn == NULL)                                   return ORA_TYPE_VARCHAR;
    if (!strcmp(tn, "NUMBER") || !strcmp(tn, "FLOAT")
        || !strcmp(tn, "INTEGER"))                    return ORA_TYPE_NUMBER;
    if (!strcmp(tn, "DATE"))                          return ORA_TYPE_DATE;
    if (!strcmp(tn, "RAW"))                           return ORA_TYPE_RAW;
    if (!strcmp(tn, "CHAR") || !strcmp(tn, "NCHAR"))  return ORA_TYPE_CHAR;
    if (!strcmp(tn, "BINARY_FLOAT"))                  return ORA_TYPE_BFLOAT;
    if (!strcmp(tn, "BINARY_DOUBLE"))                 return ORA_TYPE_BDOUBLE;
    if (!strncmp(tn, "TIMESTAMP", 9))                 return ORA_TYPE_TIMESTAMP;
    if (!strcmp(tn, "INTERVAL YEAR TO MONTH"))        return ORA_TYPE_INTERVAL_YM;
    if (!strcmp(tn, "INTERVAL DAY TO SECOND"))        return ORA_TYPE_INTERVAL_DS;
    return ORA_TYPE_VARCHAR;                           /* VARCHAR2/NVARCHAR2/... */
}

/* Read one length prefix inside an object image: -1 for a NULL attribute (0xFF),
 * -2 on a short/overrun read, otherwise the byte length (0xFE => a 4-byte
 * big-endian length follows). Advances *pos. */
static long obj_read_len(const uint8_t *img, size_t imglen, size_t *pos)
{
    if (*pos >= imglen) return -2;
    uint8_t b = img[(*pos)++];
    if (b == 0xFF) return -1;
    if (b == 0xFE) {
        if (*pos + 4 > imglen) return -2;
        long n = ((long)img[*pos] << 24) | ((long)img[*pos + 1] << 16)
               | ((long)img[*pos + 2] << 8) | (long)img[*pos + 3];
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
static bool append_attr(uint8_t **types, uint8_t **elem, int *n, int *cap,
                        uint8_t t, uint8_t et)
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
    if (seer_stmt_prepare(conn, "SELECT elem_type_name FROM all_coll_types "
                                "WHERE owner = :1 AND type_name = :2", &q) == SEER_OK) {
        if (seer_stmt_bind_text(q, 1, owner, -1) == SEER_OK
            && seer_stmt_bind_text(q, 2, name, -1) == SEER_OK
            && seer_stmt_execute(q) == SEER_OK
            && seer_stmt_fetch(q) == SEER_OK) {
            const char *en = NULL; int isn = 0;
            seer_stmt_get_string(q, 0, &en, &isn);
            et = obj_type_to_ora(en);              /* non-zero (defaults VARCHAR) */
        }
    }
    seer_stmt_close(q);
    return et;
}

/* Build a type's flattened leaf-attribute layout. A nested object attribute is
 * spliced in depth-first (its leaves inline); a nested *collection* attribute is
 * variable-length so it stays a single entry - marked in `elem` (its element wire
 * type) for decode_object_image to walk as an embedded collection image. `elem`
 * may be NULL (bind path: collection attributes aren't supported for binding). */
static void build_obj_layout(SeerConn *conn, const char *owner, const char *name,
                             uint8_t **types, uint8_t **elem, int *n, int *cap, int depth)
{
    if (depth > 8)
        return;
    SeerStmt *q = NULL;
    if (seer_stmt_prepare(conn,
            "SELECT attr_type_owner, attr_type_name FROM all_type_attrs "
            "WHERE owner = :1 AND type_name = :2 ORDER BY attr_no", &q) != SEER_OK)
        return;
    if (seer_stmt_bind_text(q, 1, owner, -1) == SEER_OK
        && seer_stmt_bind_text(q, 2, name, -1) == SEER_OK
        && seer_stmt_execute(q) == SEER_OK) {
        while (seer_stmt_fetch(q) == SEER_OK) {
            const char *aowner = NULL, *atype = NULL;
            int isn = 0;
            seer_stmt_get_string(q, 0, &aowner, &isn);
            bool user_type = !isn && aowner != NULL && aowner[0] != '\0';
            seer_stmt_get_string(q, 1, &atype, &isn);
            if (user_type) {
                char *ow = strdup(aowner);
                char *nm = strdup(atype ? atype : "");
                if (ow && nm) {
                    uint8_t cet = coll_elem_wire_type(conn, ow, nm);
                    if (cet != 0)                  /* collection attribute (one entry) */
                        append_attr(types, elem, n, cap, ORA_TYPE_ADT, cet);
                    else                           /* nested object: splice leaves */
                        build_obj_layout(conn, ow, nm, types, elem, n, cap, depth + 1);
                }
                free(ow);
                free(nm);
            } else if (!append_attr(types, elem, n, cap, obj_type_to_ora(atype), 0)) {
                break;
            }
        }
    }
    seer_stmt_close(q);                            /* frees q itself */
}

/* Resolve a type's layout from the data dictionary into `col`. A collection
 * (VARRAY / nested table) has a single element type in ALL_COLL_TYPES; a plain
 * object has a flattened leaf-attribute list (ALL_TYPE_ATTRS, recursing into
 * embedded object attributes). Sets col->n_obj_attrs >= 0 on return (0 marks
 * "resolved, nothing to iterate" - a collection or a failed lookup - not retried). */
static void fetch_obj_layout(SeerConn *conn, SeerColumn *col)
{
    col->n_obj_attrs = 0;                          /* resolved (don't retry) */

    /* Collection? ALL_COLL_TYPES yields its single element type. When that element
     * is itself an object type (elem_type_owner is set), fetch the element's
     * attribute layout so decode_collection_image can decode object elements. */
    SeerStmt *q = NULL;
    if (seer_stmt_prepare(conn, "SELECT elem_type_owner, elem_type_name FROM all_coll_types "
                                "WHERE owner = :1 AND type_name = :2", &q) == SEER_OK) {
        if (seer_stmt_bind_text(q, 1, col->type_schema, -1) == SEER_OK
            && seer_stmt_bind_text(q, 2, col->type_name, -1) == SEER_OK
            && seer_stmt_execute(q) == SEER_OK
            && seer_stmt_fetch(q) == SEER_OK) {
            const char *eowner = NULL, *et = NULL;
            int isn_owner = 0, isn = 0;
            seer_stmt_get_string(q, 0, &eowner, &isn_owner);
            seer_stmt_get_string(q, 1, &et, &isn);
            col->is_collection = true;
            char *eo = (!isn_owner && eowner && eowner[0]) ? strdup(eowner) : NULL;
            char *en = et ? strdup(et) : NULL;
            seer_stmt_close(q);
            if (eo != NULL && en != NULL) {         /* element is an object type */
                uint8_t *types = NULL;
                int n = 0, cap = 0;
                build_obj_layout(conn, eo, en, &types, NULL, &n, &cap, 0);
                col->elem_obj_types   = types;
                col->n_elem_obj_attrs = n;
                col->element_type     = ORA_TYPE_ADT;
            } else {
                col->element_type = obj_type_to_ora(en);
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
    col->obj_attr_elem  = elem;
    col->n_obj_attrs    = n;
}

/* Decode a flat SQL OBJECT image into "v1, v2, ..." text given its attribute
 * layout. Header: flags, version, image length; an optional prefix segment
 * (absent when flag 0x04 is set); then each attribute length-prefixed. */
static SeerStatus decode_collection_image(const uint8_t *img, size_t imglen,
                                          uint8_t element_type,
                                          const uint8_t *elem_obj_types,
                                          int n_elem_obj_attrs, SeerCell *cell);

/* Decode an object image into "v1, v2, ..." text. `elem`, when non-NULL, marks
 * collection attributes (elem[a] != 0 => attribute a is an embedded collection of
 * that element type, decoded as a nested "[...]"). */
static SeerStatus decode_object_image(const uint8_t *img, size_t imglen,
                                      const uint8_t *types, const uint8_t *elem,
                                      int ntypes, SeerCell *cell)
{
    if (imglen < 3)
        return SEER_EPROTO;
    uint8_t flags = img[0];
    size_t  pos   = 2;                             /* skip flags + version */
    (void)obj_read_len(img, imglen, &pos);         /* image length (skip) */
    if (!(flags & 0x04)) {                         /* prefix segment present */
        long plen = obj_read_len(img, imglen, &pos);
        if (plen > 0) pos += (size_t)plen;
    }
    SeerWriter w;
    if (!seer_writer_init(&w, 64))
        return SEER_ENOMEM;
    for (int a = 0; a < ntypes; a++) {
        if (a > 0)
            seer_writer_bytes(&w, ", ", 2);
        long len = obj_read_len(img, imglen, &pos);
        if (len == -2) { seer_writer_free(&w); return SEER_EPROTO; }
        if (len <= 0) {                            /* NULL / empty attribute */
            seer_writer_bytes(&w, "NULL", 4);
            continue;
        }
        if (pos + (size_t)len > imglen) { seer_writer_free(&w); return SEER_EPROTO; }
        SeerCell tmp = { 0 };
        SeerStatus ast = (elem != NULL && elem[a] != 0)   /* embedded collection */
            ? decode_collection_image(img + pos, (size_t)len, elem[a], NULL, 0, &tmp)
            : decode_scalar(types[a], img + pos, (size_t)len, &tmp);
        if (ast == SEER_OK && tmp.data != NULL)
            seer_writer_bytes(&w, tmp.data, tmp.len);
        free(tmp.data);
        pos += (size_t)len;
    }
    SeerStatus st = seer_writer_ok(&w)
        ? cell_set_bytes(cell, w.buf, w.len, false) : SEER_ENOMEM;
    seer_writer_free(&w);
    return st;
}

/* Decode a collection (VARRAY / nested table) image into "[e1, e2, ...]" text.
 * Shares the object header, then a collection-flags byte, a length-prefixed
 * element count, and each element length-prefixed (one common element type). */
static SeerStatus decode_collection_image(const uint8_t *img, size_t imglen,
                                          uint8_t element_type,
                                          const uint8_t *elem_obj_types,
                                          int n_elem_obj_attrs, SeerCell *cell)
{
    if (imglen < 3)
        return SEER_EPROTO;
    uint8_t flags = img[0];
    size_t  pos   = 2;                             /* skip flags + version */
    (void)obj_read_len(img, imglen, &pos);         /* image length (skip) */
    if (!(flags & 0x04)) {                         /* prefix segment present */
        long plen = obj_read_len(img, imglen, &pos);
        if (plen > 0) pos += (size_t)plen;
    }
    if (pos >= imglen)
        return SEER_EPROTO;
    pos++;                                          /* collection flags byte */
    long count = obj_read_len(img, imglen, &pos);
    if (count < 0) count = 0;

    SeerWriter w;
    if (!seer_writer_init(&w, 64))
        return SEER_ENOMEM;
    seer_writer_u8(&w, '[');
    for (long e = 0; e < count; e++) {
        if (e > 0)
            seer_writer_bytes(&w, ", ", 2);
        long len = obj_read_len(img, imglen, &pos);
        if (len == -2) { seer_writer_free(&w); return SEER_EPROTO; }
        if (len <= 0) {                            /* NULL / empty element */
            seer_writer_bytes(&w, "NULL", 4);
            continue;
        }
        if (pos + (size_t)len > imglen) { seer_writer_free(&w); return SEER_EPROTO; }
        SeerCell tmp = { 0 };
        SeerStatus est = (n_elem_obj_attrs > 0)     /* element is an object image */
            ? decode_object_image(img + pos, (size_t)len, elem_obj_types, NULL,
                                  n_elem_obj_attrs, &tmp)
            : decode_scalar(element_type, img + pos, (size_t)len, &tmp);
        if (est == SEER_OK && tmp.data != NULL) {
            if (n_elem_obj_attrs > 0) seer_writer_u8(&w, '(');   /* nest object as (a, b) */
            seer_writer_bytes(&w, tmp.data, tmp.len);
            if (n_elem_obj_attrs > 0) seer_writer_u8(&w, ')');
        }
        free(tmp.data);
        pos += (size_t)len;
    }
    seer_writer_u8(&w, ']');
    SeerStatus st = seer_writer_ok(&w)
        ? cell_set_bytes(cell, w.buf, w.len, false) : SEER_ENOMEM;
    seer_writer_free(&w);
    return st;
}

/* XMLType image flags (#124). */
#define XML_FLAG_LOB            0x00000001   /* content is a CLOB locator      */
#define XML_FLAG_STRING         0x00000004   /* content is an inline string    */
#define XML_FLAG_SKIP_NEXT_4    0x00100000
#define XML_FLAG_LEGACY_STORAGE 0x01000000   /* 11g CLOB-stored (unsupported)  */

/* Decode an XMLType image (type 109, type_name XMLTYPE) into XML text. After the
 * shared object header: a 1-byte XML version, a ub4 flag, an optional 4-byte
 * skip, then the content - either an inline UTF-8 document (STRING) or a CLOB
 * locator (LOB) read through the LOB path and converted UTF-16BE -> UTF-8. */
static SeerStatus decode_xmltype_image(SeerConn *conn, const uint8_t *img,
                                       size_t imglen, SeerCell *cell)
{
    if (imglen < 3)
        return SEER_EPROTO;
    uint8_t flags = img[0];
    size_t  pos   = 2;                         /* skip image flags + version */
    (void)obj_read_len(img, imglen, &pos);     /* image length */
    if (!(flags & 0x04)) {                      /* prefix segment present */
        long plen = obj_read_len(img, imglen, &pos);
        if (plen > 0) pos += (size_t)plen;
    }
    if (pos + 5 > imglen)                       /* 1 (xml version) + 4 (flag) */
        return SEER_EPROTO;
    pos += 1;                                   /* XML version */
    uint32_t xflag = (uint32_t)img[pos] << 24 | (uint32_t)img[pos + 1] << 16
                   | (uint32_t)img[pos + 2] << 8 | img[pos + 3];
    pos += 4;
    if (xflag & XML_FLAG_SKIP_NEXT_4)
        pos += 4;
    if (pos > imglen)
        return SEER_EPROTO;
    const uint8_t *content = img + pos;
    size_t         clen    = imglen - pos;

    if (xflag & XML_FLAG_STRING)                /* inline UTF-8 document */
        return cell_set_bytes(cell, content, clen, false);

    if (xflag & XML_FLAG_LOB) {                 /* a CLOB locator */
        if (xflag & XML_FLAG_LEGACY_STORAGE)
            return SEER_ENOTIMPL;               /* 11g CLOB-stored XMLType */
        uint8_t *raw = NULL;
        size_t   rawlen = 0;
        SeerStatus st = seer_lob_read(conn, content, clen, &raw, &rawlen);
        if (st != SEER_OK)
            return st;
        st = SEER_OK;
        if (rawlen == 0) {
            cell_set_text(cell, strdup(""));
        } else {
            char  *u8 = NULL;
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
static void resolve_pending_objs(SeerStmt *stmt)
{
    for (size_t k = 0; k < stmt->npobjs; k++) {
        SeerPendingObj *p = &stmt->pobjs[k];
        SeerColumn *col = &stmt->cols[p->col];
        SeerCell *cell = &stmt->rows[p->row][p->col];

        if (col->type_name != NULL && strcmp(col->type_name, "XMLTYPE") == 0) {
            if (decode_xmltype_image(stmt->conn, p->image, p->imagelen, cell) != SEER_OK)
                seer_log(SEER_LOG_WARN, "stmt: XMLType decode failed (row %zu col %d)",
                         p->row, p->col);
            continue;                          /* XMLType has no attribute layout */
        }

        if (col->n_obj_attrs < 0 && col->type_schema && col->type_name)
            fetch_obj_layout(stmt->conn, col);     /* fills column; sets n_obj_attrs>=0 */

        SeerStatus st;
        if (col->is_collection)
            st = decode_collection_image(p->image, p->imagelen, col->element_type,
                                         col->elem_obj_types, col->n_elem_obj_attrs, cell);
        else if (col->n_obj_attrs > 0)
            st = decode_object_image(p->image, p->imagelen, col->obj_attr_types,
                                     col->obj_attr_elem, col->n_obj_attrs, cell);
        else
            continue;                              /* layout unavailable */
        if (st != SEER_OK)
            seer_log(SEER_LOG_WARN, "stmt: OBJECT/collection decode failed (row %zu col %d)",
                     p->row, p->col);
    }
}

/* Discard captured-but-undrained implicit result sets. */
static void free_implicit(SeerStmt *stmt)
{
    for (size_t i = 0; i < stmt->nimplicit; i++)
        free_columns(stmt->implicit[i].cols, stmt->implicit[i].ncols);
    free(stmt->implicit);
    stmt->implicit     = NULL;
    stmt->nimplicit    = 0;
    stmt->implicit_pos = 0;
}

/* Fetch every remaining row of stmt->cursor_id into stmt->rows (one FETCH is
 * always issued, then more while the server reports rows pending). */
static SeerStatus fetch_all_rows(SeerStmt *stmt)
{
    SeerWriter w;
    OerResult rc = { .call_status = 1 };       /* prime: fetch at least once */
    while (rc.call_status == 1 && stmt->cursor_id != 0 && rc.err_code != 1403) {
        SeerStatus st = build_fetch(stmt, &w);
        if (st != SEER_OK)
            return st;
        st = seer_ttc_send(stmt->conn, w.buf, w.len);
        seer_writer_free(&w);
        if (st != SEER_OK)
            return st;
        uint8_t *resp = NULL;
        size_t   rlen = 0;
        st = seer_ttc_recv(stmt->conn, &resp, &rlen);
        if (st != SEER_OK)
            return st;
        OerResult f = { 0 };
        st = parse_response(stmt, resp, rlen, false, &f);
        free(resp);
        if (st != SEER_OK)
            return st;
        if (f.err_code != 0 && f.err_code != 1403) {
            seer_log(SEER_LOG_ERROR, "stmt: fetch failed (ORA-%05ld)", (long)f.err_code);
            return SEER_EDB;
        }
        rc.call_status = f.err_code == 1403 ? 0 : f.call_status;
        rc.err_code    = f.err_code;
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
        size_t   rawlen = 0;
        /* A BFILE is an external file: FILE_OPEN -> READ -> FILE_CLOSE.
         * Persistent CLOB/BLOB/VECTOR is a single READ round-trip. */
        SeerStatus lst = (p->ora_type == ORA_TYPE_BFILE)
            ? seer_bfile_read(stmt->conn, p->locator, p->loclen, &raw, &rawlen)
            : seer_lob_read(stmt->conn, p->locator, p->loclen, &raw, &rawlen);
        if (lst != SEER_OK) {
            seer_log(SEER_LOG_WARN, "stmt: LOB read failed for row %zu col %d",
                     p->row, p->col);
            continue;
        }
        SeerCell *cell = &stmt->rows[p->row][p->col];
        free(cell->data);
        cell->data = NULL;
        cell->len = 0;
        cell->binary = false;
        if (p->ora_type == ORA_TYPE_CLOB) {    /* CLOB: UTF-16BE -> UTF-8 text */
            if (rawlen == 0) {
                cell_set_text(cell, strdup(""));
            } else {
                char  *u8 = NULL;
                size_t u8len = 0;
                if (seer_iconv("UTF-16BE", "UTF-8", (const char *)raw, rawlen,
                               &u8, &u8len) == 0) {
                    cell_set_bytes(cell, u8, u8len, false);
                    free(u8);
                }
            }
        } else if (p->ora_type == ORA_TYPE_VECTOR) {  /* VECTOR -> "[e1, e2, ...]" text */
            if (decode_vector_image(raw, rawlen, cell) != SEER_OK)
                seer_log(SEER_LOG_WARN, "stmt: VECTOR decode failed (row %zu col %d)",
                         p->row, p->col);
        } else if (p->ora_type == ORA_TYPE_JSON) {    /* JSON (OSON) -> JSON text */
            char *json = NULL;
            if (seer_decode_oson(raw, rawlen, &json) == SEER_OK)
                cell_set_text(cell, json);
            else
                seer_log(SEER_LOG_WARN, "stmt: JSON decode failed (row %zu col %d)",
                         p->row, p->col);
        } else {                               /* BLOB: raw binary bytes */
            cell_set_bytes(cell, raw, rawlen, true);
        }
        free(raw);
    }
}

/* ========= Oracle 9i (field version 2): the TTI_ALL7 query dialect ===========
 * 9i speaks an older execute RPC than TTI_ALL8. A SELECT is a four-call sequence
 * (pyoracle PROTOCOL.md §19): OOPEN -> parse -> describe -> exec/fetch* -> close.
 * All calls carry sequence byte 0 and cursor field 0 (the server tracks the one
 * cursor OOPEN allocated). RE'd from the Oracle JDBC thin driver. */

/* Send one fv2 message; receive the reply into resp/rlen (caller frees resp). */
static SeerStatus fv2_txn(SeerConn *c, const uint8_t *msg, size_t mlen,
                          uint8_t **resp, size_t *rlen)
{
    SeerStatus st = seer_ttc_send(c, msg, mlen);
    if (st != SEER_OK)
        return st;
    return seer_ttc_recv(c, resp, rlen);
}

/* The ORA code carried by a short pre-10g OER (token, ub4 rows, ub4 code); 0 if
 * `resp` is not an OER, -1 on a truncated one. */
static int64_t fv2_oer_code(const uint8_t *resp, size_t rlen)
{
    if (rlen < 1 || resp[0] != TTI_OER)
        return 0;
    SeerReader r;
    seer_reader_init(&r, resp + 1, rlen - 1);
    (void)seer_dec_sb4(&r);                     /* rows-this-fetch / rowcount */
    int64_t code = seer_dec_sb4(&r);
    return seer_reader_ok(&r) ? code : -1;
}

/* Surface a 9i OER's trailing "ORA-NNNNN: ..." text on conn->last_error (the
 * final length-prefixed run; middle fields are version-specific). */
static void fv2_set_error(SeerConn *c, const uint8_t *resp, size_t rlen)
{
    for (size_t i = 3; i + 1 < rlen; i++) {
        size_t len = resp[i];
        if (len && i + 1 + len == rlen) {
            free(c->last_error);
            c->last_error = malloc(len + 1);
            if (c->last_error != NULL) {
                memcpy(c->last_error, resp + i + 1, len);
                c->last_error[len] = '\0';
            }
            return;
        }
    }
}

/* Append one fv2 define entry: the client's requested return type for a column. */
static void fv2_define_entry(SeerWriter *w, const SeerColumn *col)
{
    uint8_t  deftype = col->ora_type;
    uint32_t maxsize = col->max_size;
    uint8_t  flag    = (col->ora_type == ORA_TYPE_CHAR) ? 0x21 : 0x01;
    uint32_t charset = col->charset ? col->charset : 31;
    switch (col->ora_type) {
    case ORA_TYPE_NUMBER:      deftype = ORA_TYPE_VARNUM; maxsize = 22; break;
    case ORA_TYPE_DATE:        maxsize = 7;  break;
    case ORA_TYPE_TIMESTAMP:
    case ORA_TYPE_TIMESTAMPTZ: maxsize = 13; break;
    case ORA_TYPE_LONG:
    case ORA_TYPE_LONGRAW:     maxsize = 0x7FFFFFFFu; break;
    default: break;
    }
    seer_writer_u8(w, deftype);
    seer_writer_u8(w, flag);
    seer_writer_u8(w, 0);
    seer_writer_u8(w, 0);
    seer_enc_sb4(w, maxsize);
    for (int i = 0; i < 4; i++) seer_writer_u8(w, 0);
    seer_enc_sb4(w, charset);
    seer_writer_u8(w, 0);                        /* csfrm */
}

/* Decode one fv2 column descriptor (OAC-fv2 + name) into `col`. */
static SeerStatus fv2_decode_column(SeerReader *r, SeerColumn *col)
{
    uint8_t data_type = seer_reader_u8(r);
    (void)seer_reader_u8(r);                     /* flag       */
    (void)seer_reader_u8(r);                     /* precision  */
    (void)seer_dec_sb4(r);                       /* data_scale */
    int64_t max_len = seer_dec_sb4(r);
    (void)seer_dec_sb4(r);                       /* _mal       */
    (void)seer_dec_sb4(r);                       /* _fl2       */
    uint8_t *toid = NULL; size_t toidlen = 0;
    if (seer_dec_dalc(r, &toid, &toidlen) != SEER_OK) { free(toid); return SEER_EPROTO; }
    free(toid);                                  /* _toid      */
    (void)seer_dec_sb4(r);                       /* _vsn       */
    int64_t charset = seer_dec_sb4(r);
    (void)seer_reader_u8(r);                     /* csfrm      */
    /* Before the name: null_ok(1B) + name-length-in-bytes(1B), then the name length
     * in chars (a real ub4, always width 1 for a <=255-char name), then the DALC
     * name. NOTE: pyoracle's §19.1 mislabels the null_ok + byte-length pair as one
     * "ub4 namelen" - which only decodes cleanly for a NULLABLE column (null_ok=1
     * mimics a width-1 ub4); a NOT-NULL column (null_ok=0) makes that ub4 slip.
     * Verified live: a NOT NULL vs nullable pair with identical 9-char names differ
     * only in this first byte (00 vs 01). We read null_ok properly; the two length
     * fields are redundant with the DALC and discarded. */
    uint8_t null_ok = seer_reader_u8(r);         /* 0 = NOT NULL, 1 = nullable */
    (void)seer_reader_u8(r);                     /* name length in bytes (redundant) */
    (void)seer_dec_sb4(r);                       /* name length in chars (ub4) */
    uint8_t *name = NULL; size_t namelen = 0;
    if (seer_dec_dalc(r, &name, &namelen) != SEER_OK) { free(name); return SEER_EPROTO; }
    if (!seer_reader_ok(r)) { free(name); return SEER_EPROTO; }
    col->name = malloc(namelen + 1);
    if (col->name == NULL) { free(name); return SEER_ENOMEM; }
    memcpy(col->name, name, namelen);
    col->name[namelen] = '\0';
    free(name);
    col->ora_type    = data_type;
    col->charset     = (uint16_t)charset;
    col->max_size    = (uint32_t)(max_len < 0 ? 0 : max_len);
    col->null_ok     = null_ok;
    col->n_obj_attrs = 0;
    return SEER_OK;
}

/* Decode the describe RPA (08 01 numcols, then per column) into a column array. */
static SeerStatus fv2_decode_describe(const uint8_t *data, size_t dlen,
                                      SeerColumn **out_cols, int *out_n)
{
    if (dlen < 3 || data[0] != TTI_RPA)
        return SEER_EPROTO;
    int ncols = data[2];
    if (ncols <= 0 || ncols > 4096)
        return SEER_EPROTO;
    SeerColumn *cols = calloc((size_t)ncols, sizeof *cols);
    if (cols == NULL)
        return SEER_ENOMEM;
    SeerReader r;
    seer_reader_init(&r, data + 3, dlen - 3);
    for (int i = 0; i < ncols; i++) {
        if (fv2_decode_column(&r, &cols[i]) != SEER_OK) {
            free_columns(cols, ncols);
            return SEER_EPROTO;
        }
        if (seer_reader_remaining(&r) >= 2 && r.buf[r.pos] == 0 && r.buf[r.pos + 1] == 0)
            r.pos += 2;                          /* inter-column separator */
    }
    *out_cols = cols;
    *out_n    = ncols;
    return SEER_OK;
}

/* Decode one exec+fetch response (RXH, RXD rows, short OER); append rows, set
 * *errcode (1403 = end of fetch) and *nadded. */
static SeerStatus fv2_decode_rows(SeerStmt *stmt, const uint8_t *data, size_t dlen,
                                  int64_t *errcode, size_t *nadded)
{
    *errcode = 0;
    *nadded  = 0;
    int ncols = stmt->ncols;
    SeerReader r;
    seer_reader_init(&r, data, dlen);
    while (seer_reader_remaining(&r) > 0) {
        uint8_t token = r.buf[r.pos];
        if (token == TTI_RXH) {
            r.pos += 1;
            (void)seer_reader_u8(&r);            /* flags */
            while (seer_reader_remaining(&r) > 0) {
                uint8_t t = r.buf[r.pos];
                if (t == TTI_RXD || t == TTI_OER || t == TTI_RXH)
                    break;
                (void)seer_dec_sb4(&r);          /* a small RXH count field */
            }
        } else if (token == TTI_RXD) {
            r.pos += 1;
            SeerCell *row = calloc(ncols ? (size_t)ncols : 1, sizeof *row);
            if (row == NULL)
                return SEER_ENOMEM;
            for (int ci = 0; ci < ncols; ci++) {
                uint8_t ct = stmt->cols[ci].ora_type;
                if (ct == ORA_TYPE_CLOB || ct == ORA_TYPE_BLOB || ct == ORA_TYPE_BFILE) {
                    /* LOB column: a locator (ub4 num_bytes + DALC) then an indicator,
                     * or a bare 0x00 = NULL LOB. Capture the locator to resolve via
                     * TTI_LOBOPS after the fetch; the cell is left NULL for now. */
                    if (seer_reader_remaining(&r) > 0 && r.buf[r.pos] == 0x00) {
                        r.pos += 1;
                        if (seer_reader_remaining(&r) > 0 && r.buf[r.pos] == 0x81) r.pos += 2;
                    } else {
                        (void)seer_dec_sb4(&r);              /* ub4 num_bytes */
                        uint8_t *locv = NULL; size_t loclen = 0;
                        if (seer_dec_dalc(&r, &locv, &loclen) != SEER_OK) {
                            free(locv);
                            for (int k = 0; k < ci; k++) free(row[k].data);
                            free(row);
                            return SEER_EPROTO;
                        }
                        if (seer_reader_remaining(&r) > 0) r.pos += 1;   /* present indicator */
                        if (locv != NULL && loclen > 0
                            && record_pending_lob(stmt, stmt->nrows, ci, ct, locv, loclen) != SEER_OK)
                            free(locv);
                        else if (locv == NULL || loclen == 0)
                            free(locv);
                    }
                    continue;
                }
                uint8_t *val = NULL; size_t vlen = 0;
                if (seer_dec_dalc(&r, &val, &vlen) != SEER_OK) {
                    free(val);
                    for (int k = 0; k < ci; k++) free(row[k].data);
                    free(row);
                    return SEER_EPROTO;
                }
                if (seer_reader_remaining(&r) > 0 && r.buf[r.pos] == 0x81) {
                    r.pos += 2;                  /* 81 01 = NULL (leave cell zeroed) */
                } else {
                    (void)seer_reader_u8(&r);    /* present indicator (0x00) */
                    if (vlen > 0)
                        decode_scalar(stmt->cols[ci].ora_type, val, vlen, &row[ci]);
                }
                free(val);
            }
            if (!seer_reader_ok(&r) || append_row(stmt, row) != SEER_OK) {
                for (int k = 0; k < ncols; k++) free(row[k].data);
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
static void fv2_bind_oac(SeerWriter *w, const SeerBind *b)
{
    uint8_t  type    = ORA_TYPE_VARCHAR;
    uint32_t maxsize = 4000, charset = 873;
    uint8_t  csfrm   = 1;
    if (b->oac_charset == 2000) {                /* national (NVARCHAR2/NCHAR) */
        charset = 2000; csfrm = 2;               /* value rides as AL16UTF16 (UTF-16BE) */
    } else switch (b->oac_type) {
    case ORA_TYPE_NUMBER:  type = ORA_TYPE_VARNUM; maxsize = 22;   charset = 31;  csfrm = 1; break;
    case ORA_TYPE_RAW:
    case ORA_TYPE_LONGRAW: type = ORA_TYPE_RAW;    maxsize = 2000; charset = 31;  csfrm = 0; break;
    case ORA_TYPE_DATE:    type = ORA_TYPE_DATE;   maxsize = 7;    charset = 31;  csfrm = 0; break;
    default: break;                              /* VARCHAR / LONG / unbound -> str */
    }
    seer_writer_u8(w, type);
    seer_writer_u8(w, 0x01);
    seer_writer_u8(w, 0);
    seer_writer_u8(w, 0);
    seer_enc_sb4(w, maxsize);
    for (int i = 0; i < 4; i++) seer_writer_u8(w, 0);
    seer_enc_sb4(w, charset);
    seer_writer_u8(w, csfrm);
}

/* Build the TTI_ALL7 parse message (shared by SELECT and DML). With input binds
 * the option word flips to 0x29, a bind-count field precedes the SQL, and each
 * bind's OAC + one RXD carrying all values are appended (the RXD value bytes are
 * exactly what the TTI_ALL8 path stored in b->rxd). */
static SeerStatus fv2_emit_parse(SeerStmt *stmt, SeerWriter *w)
{
    size_t qlen = strlen(stmt->sql);
    int    nb   = stmt->npbinds;
    if (!seer_writer_init(w, 64 + qlen + (size_t)nb * 48))
        return SEER_ENOMEM;
    seer_writer_u8(w, TTI_FUN); seer_writer_u8(w, TTI_ALL7); seer_writer_u8(w, 0);
    seer_writer_u8(w, 0x02); seer_writer_u8(w, 0x80);
    seer_writer_u8(w, nb > 0 ? 0x29 : 0x21);
    seer_writer_u8(w, 0x01); seer_writer_u8(w, 0x01); seer_writer_u8(w, 0x01);
    seer_enc_sb4(w, (uint32_t)qlen);
    { static const uint8_t mid[] = {0,0,0x01,0x01,0x07,0x01,0x01,0x02,0,0,0};
      seer_writer_bytes(w, mid, sizeof mid); }
    if (nb > 0) {
        seer_writer_u8(w, 0x01); seer_writer_u8(w, 0x01); seer_writer_u8(w, (uint8_t)nb);
    } else {
        seer_writer_u8(w, 0); seer_writer_u8(w, 0);
    }
    seer_writer_bytes(w, (const uint8_t *)stmt->sql, qlen);
    { static const uint8_t tl[] = {0x01,0x01,0x01,0x01,0,0,0,0,0};
      seer_writer_bytes(w, tl, sizeof tl); }
    if (nb > 0) {
        for (int i = 0; i < nb; i++)
            fv2_bind_oac(w, &stmt->pbinds[i]);
        seer_writer_u8(w, TTI_RXD);
        for (int i = 0; i < nb; i++) {
            SeerBind *b   = &stmt->pbinds[i];
            uint8_t  *rxd = (b->rxd != NULL) ? b->rxd[0] : NULL;
            if (rxd != NULL)
                seer_writer_bytes(w, rxd, b->rxd_len[0]);
            else
                seer_writer_u8(w, 0);            /* unbound -> NULL value */
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
    int    nb   = stmt->npbinds;
    if (!seer_writer_init(w, 64 + qlen + (size_t)nb * 32))
        return SEER_ENOMEM;
    seer_writer_u8(w, TTI_FUN); seer_writer_u8(w, TTI_ALL7); seer_writer_u8(w, 0);
    if (nb > 0) { seer_writer_u8(w, 0x02); seer_writer_u8(w, 0x04); seer_writer_u8(w, 0x29); }
    else        { seer_writer_u8(w, 0x01); seer_writer_u8(w, 0x21); }
    seer_writer_u8(w, 0x01); seer_writer_u8(w, 0x01); seer_writer_u8(w, 0x01);
    seer_enc_sb4(w, (uint32_t)qlen);
    { static const uint8_t mid[] = {0,0,0x01,0x01,0x07,0x01,0x01,0x02,0,0,0};
      seer_writer_bytes(w, mid, sizeof mid); }
    if (nb > 0) { seer_writer_u8(w, 0x01); seer_writer_u8(w, 0x01); seer_writer_u8(w, (uint8_t)nb); }
    else        { seer_writer_u8(w, 0); seer_writer_u8(w, 0); }
    seer_writer_bytes(w, (const uint8_t *)stmt->sql, qlen);
    { static const uint8_t tl[] = {0x01,0x01,0x01,0x01,0,0,0,0,0};
      seer_writer_bytes(w, tl, sizeof tl); }
    for (int i = 0; i < nb; i++)
        fv2_bind_oac(w, &stmt->pbinds[i]);       /* OACs only, no inline values */
    return seer_writer_ok(w) ? SEER_OK : SEER_ENOMEM;
}

/* ---- Oracle 9i (fv2) LOB read: the two-call TTI_LOBOPS GETLEN + READ -------
 * 9i's LOBOPS is far shorter than the 10g+ form and comes as a pair per LOB cell:
 * GETLEN learns the length, READ pulls exactly that many chars/bytes. Every request
 * is `03 60 00 01 <sb4 loclen> <op middle> <locator[1:]> <trailer>`. The captured
 * locator (from the RXD) is echoed with its leading byte dropped. (PROTOCOL §19.5) */
static const uint8_t FV2_LOBOP_GETLEN_MID[] = { 0,0,0,0,0,1,0,1,1,0,0,0 };
static const uint8_t FV2_LOBOP_READ_MID[]   = { 0,0,1,1,0,0,1,0,1,2,0,0,0 };

/* Parse an accumulated 9i LOBOPS READ reply: TTI_LOB(0e) [fe] then <ub1 len><bytes>
 * chunks ending at a zero-length chunk. *complete is false until that terminator is
 * seen (content spans more packets). Caller frees *out. */
static void fv2_parse_lob_chunks(const uint8_t *data, size_t dlen,
                                 uint8_t **out, size_t *outlen, bool *complete)
{
    *out = NULL; *outlen = 0; *complete = false;
    if (dlen < 2 || data[0] != TTI_LOB)
        return;
    size_t pos = (data[1] == 0xFE) ? 2 : 1;
    SeerWriter w;
    if (!seer_writer_init(&w, dlen))
        return;
    while (pos < dlen) {
        uint8_t clen = data[pos];
        if (clen == 0) { *complete = true; break; }
        if (pos + 1 + clen > dlen) break;        /* chunk split across packets */
        seer_writer_bytes(&w, data + pos + 1, clen);
        pos += 1 + clen;
    }
    if (seer_writer_ok(&w)) { *out = w.buf; *outlen = w.len; }
    else                      seer_writer_free(&w);
}

/* Build + send a fv2 LOBOPS request (op `mid`, `trailer`) and receive the reply. */
static SeerStatus fv2_lobop_send(SeerConn *c, const uint8_t *loc, size_t loclen,
                                 const uint8_t *mid, size_t midlen,
                                 const uint8_t *trailer, size_t trlen,
                                 uint8_t **resp, size_t *rlen)
{
    SeerWriter w;
    if (!seer_writer_init(&w, 16 + loclen + midlen + trlen))
        return SEER_ENOMEM;
    seer_writer_u8(&w, TTI_FUN); seer_writer_u8(&w, TTI_LOBOPS); seer_writer_u8(&w, 0);
    seer_writer_u8(&w, 0x01);
    seer_enc_sb4(&w, (uint32_t)loclen);
    seer_writer_bytes(&w, mid, midlen);
    if (loclen > 1)
        seer_writer_bytes(&w, loc + 1, loclen - 1);     /* locator[1:] */
    if (trlen > 0)
        seer_writer_bytes(&w, trailer, trlen);
    if (!seer_writer_ok(&w)) { seer_writer_free(&w); return SEER_ENOMEM; }
    SeerStatus st = fv2_txn(c, w.buf, w.len, resp, rlen);
    seer_writer_free(&w);
    return st;
}

/* GETLEN: the LOB length (chars for CLOB, bytes for BLOB). -1 on error. */
static int64_t fv2_lob_getlen(SeerConn *c, const uint8_t *loc, size_t loclen)
{
    static const uint8_t trl[] = { 0 };
    uint8_t *resp = NULL; size_t rlen = 0;
    if (fv2_lobop_send(c, loc, loclen, FV2_LOBOP_GETLEN_MID, sizeof FV2_LOBOP_GETLEN_MID,
                       trl, sizeof trl, &resp, &rlen) != SEER_OK)
        return -1;
    int64_t amount = 0;                          /* RPA 00 <ub1 loclen><echo> <ub4 amount> */
    if (rlen >= 3 && resp[0] == TTI_RPA) {
        size_t pos = 2;
        size_t el  = resp[pos];
        pos += 1 + el;
        if (pos < rlen) {
            SeerReader r;
            seer_reader_init(&r, resp + pos, rlen - pos);
            amount = seer_dec_sb4(&r);
        }
    }
    free(resp);
    return amount;
}

/* READ `amount` chars/bytes; accumulate reply packets until the zero-length
 * chunk terminator (the fv2 READ reply carries no OER call-status). */
static SeerStatus fv2_lob_read(SeerConn *c, const uint8_t *loc, size_t loclen,
                               int64_t amount, uint8_t **content, size_t *contentlen)
{
    *content = NULL; *contentlen = 0;
    uint8_t trailer[8];
    SeerWriter tw;
    if (!seer_writer_init(&tw, 8)) return SEER_ENOMEM;
    seer_enc_sb4(&tw, (uint32_t)amount);
    size_t trlen = tw.len;
    memcpy(trailer, tw.buf, trlen);
    seer_writer_free(&tw);

    /* Send READ; the first reply comes back via fv2_lobop_send, then accumulate. */
    uint8_t *pkt = NULL; size_t plen = 0;
    if (fv2_lobop_send(c, loc, loclen, FV2_LOBOP_READ_MID, sizeof FV2_LOBOP_READ_MID,
                       trailer, trlen, &pkt, &plen) != SEER_OK)
        return SEER_EPROTO;
    SeerWriter acc;
    if (!seer_writer_init(&acc, (size_t)amount + 32)) { free(pkt); return SEER_ENOMEM; }
    seer_writer_bytes(&acc, pkt, plen);
    free(pkt);
    for (int guard = 0; guard < 1000000; guard++) {
        uint8_t *cont = NULL; size_t clen = 0; bool complete = false;
        if (seer_writer_ok(&acc))
            fv2_parse_lob_chunks(acc.buf, acc.len, &cont, &clen, &complete);
        if (complete) {
            *content = cont; *contentlen = clen;
            seer_writer_free(&acc);
            return SEER_OK;
        }
        free(cont);
        uint8_t *more = NULL; size_t morelen = 0;
        if (seer_ttc_recv(c, &more, &morelen) != SEER_OK) { seer_writer_free(&acc); return SEER_EPROTO; }
        seer_writer_bytes(&acc, more, morelen);
        free(more);
    }
    seer_writer_free(&acc);
    return SEER_EPROTO;
}

/* 9i BFILE read: FILE_OPEN -> GETLEN -> READ -> FILE_CLOSE (PROTOCOL §19.8). The
 * FILE_OPEN reply's RPA carries an *updated* (open-flagged) locator that GETLEN /
 * READ / FILE_CLOSE must use. FILE_CLOSE always runs (best-effort). */
static const uint8_t FV2_LOBOP_FOPEN_MID[]  = { 0,0,0,0,0,1,0,2,1,0,0,0,0 };
static const uint8_t FV2_LOBOP_FCLOSE_MID[] = { 0,0,0,0,0,0,0,2,2,0,0,0,0 };

static SeerStatus fv2_bfile_read(SeerConn *c, const uint8_t *loc, size_t loclen,
                                 uint8_t **content, size_t *contentlen)
{
    static const uint8_t fopen_trl[] = { 0x01, 0x0b };
    *content = NULL; *contentlen = 0;

    uint8_t *resp = NULL; size_t rlen = 0;
    if (fv2_lobop_send(c, loc, loclen, FV2_LOBOP_FOPEN_MID, sizeof FV2_LOBOP_FOPEN_MID,
                       fopen_trl, sizeof fopen_trl, &resp, &rlen) != SEER_OK)
        return SEER_EPROTO;
    /* Opened locator: RPA 00 <ub1 len><body>  ->  00 <ub1 len><body>. */
    if (rlen < 3 || resp[0] != TTI_RPA) { free(resp); return SEER_EPROTO; }
    size_t olen = resp[2];
    if (3 + olen > rlen) { free(resp); return SEER_EPROTO; }
    size_t   openedlen = 2 + olen;
    uint8_t *opened    = malloc(openedlen);
    if (opened == NULL) { free(resp); return SEER_ENOMEM; }
    opened[0] = 0;
    memcpy(opened + 1, resp + 2, 1 + olen);      /* the length byte + body */
    free(resp);

    int64_t    amount = fv2_lob_getlen(c, opened, openedlen);
    SeerStatus rst    = SEER_OK;
    if (amount > 0)
        rst = fv2_lob_read(c, opened, openedlen, amount, content, contentlen);

    uint8_t *cresp = NULL; size_t crlen = 0;
    if (fv2_lobop_send(c, opened, openedlen, FV2_LOBOP_FCLOSE_MID, sizeof FV2_LOBOP_FCLOSE_MID,
                       NULL, 0, &cresp, &crlen) == SEER_OK)
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
        size_t   clen    = 0;
        if (p->ora_type == ORA_TYPE_BFILE) {
            fv2_bfile_read(c, p->locator, p->loclen, &content, &clen);
        } else {
            int64_t amount = fv2_lob_getlen(c, p->locator, p->loclen);
            if (amount > 0)
                fv2_lob_read(c, p->locator, p->loclen, amount, &content, &clen);
        }
        SeerCell *cell = &stmt->rows[p->row][p->col];
        cell_set_bytes(cell, content ? content : (const uint8_t *)"", clen,
                       p->ora_type != ORA_TYPE_CLOB);   /* CLOB text; BLOB/BFILE bytes */
        free(content);
    }
}

/* Oracle 9i SELECT: the four-call TTI_ALL7 sequence (binds via fv2_emit_parse). */
static SeerStatus fv2_execute_select(SeerStmt *stmt)
{
    SeerConn *c = stmt->conn;
    free_rows(stmt);
    free_columns(stmt->cols, stmt->ncols);
    stmt->cols = NULL; stmt->ncols = 0;

    uint8_t *resp = NULL;
    size_t   rlen = 0;
    SeerStatus st;
    SeerWriter w;

    /* Call 0: OOPEN (allocate the server cursor). */
    if (!seer_writer_init(&w, 8)) return SEER_ENOMEM;
    seer_writer_u8(&w, TTI_FUN); seer_writer_u8(&w, O7_OPEN); seer_writer_u8(&w, 0);
    seer_writer_u8(&w, 0x01); seer_writer_u8(&w, 0x00);
    st = fv2_txn(c, w.buf, w.len, &resp, &rlen); seer_writer_free(&w);
    if (st != SEER_OK) return st;
    free(resp); resp = NULL;

    /* Call 1: parse (TTI_ALL7, with any binds). */
    st = fv2_emit_parse(stmt, &w);
    if (st != SEER_OK) return st;
    st = fv2_txn(c, w.buf, w.len, &resp, &rlen); seer_writer_free(&w);
    if (st != SEER_OK) return st;
    int64_t pcode = fv2_oer_code(resp, rlen);
    if (pcode != 0 && pcode != 1403) {
        fv2_set_error(c, resp, rlen);
        seer_log(SEER_LOG_ERROR, "fv2: parse failed (ORA-%05ld)", (long)pcode);
        free(resp);
        return SEER_EDB;
    }
    free(resp); resp = NULL;

    /* Call 2: describe columns. */
    if (!seer_writer_init(&w, 16)) return SEER_ENOMEM;
    seer_writer_u8(&w, TTI_FUN); seer_writer_u8(&w, O7_DESCRIBE); seer_writer_u8(&w, 0);
    { static const uint8_t d[] = {0x07,0x01,0x01,0,0,0x01,0x02,0x01,0x01};
      seer_writer_bytes(&w, d, sizeof d); }
    st = fv2_txn(c, w.buf, w.len, &resp, &rlen); seer_writer_free(&w);
    if (st != SEER_OK) return st;
    int64_t dcode = fv2_oer_code(resp, rlen);
    if (dcode != 0 && dcode != 1403) {
        fv2_set_error(c, resp, rlen); free(resp); return SEER_EDB;
    }
    SeerColumn *cols = NULL; int ncols = 0;
    st = fv2_decode_describe(resp, rlen, &cols, &ncols);
    free(resp); resp = NULL;
    if (st != SEER_OK) return st;
    stmt->cols = cols; stmt->ncols = ncols;

    /* Call 3: execute + fetch (re-sent per batch until ORA-01403 / no rows). */
    int64_t errcode = 0;
    for (;;) {
        if (!seer_writer_init(&w, 48 + (size_t)ncols * 24)) return SEER_ENOMEM;
        seer_writer_u8(&w, TTI_FUN); seer_writer_u8(&w, TTI_ALL7); seer_writer_u8(&w, 0);
        { static const uint8_t h[]  = {0x02,0x80,0x50,0x01,0x01,0,0,0,0,0x01,0x01,0x07,0x01,0x01,0x02,0};
          seer_writer_bytes(&w, h, sizeof h); }
        seer_writer_u8(&w, 0x01); seer_writer_u8(&w, 0x01); seer_writer_u8(&w, (uint8_t)ncols);
        { static const uint8_t h2[] = {0,0,0x01,0x01,0x01,0x0a,0,0,0,0,0};
          seer_writer_bytes(&w, h2, sizeof h2); }
        for (int i = 0; i < ncols; i++) fv2_define_entry(&w, &cols[i]);
        if (!seer_writer_ok(&w)) { seer_writer_free(&w); return SEER_ENOMEM; }
        st = fv2_txn(c, w.buf, w.len, &resp, &rlen); seer_writer_free(&w);
        if (st != SEER_OK) return st;
        size_t nadded = 0;
        st = fv2_decode_rows(stmt, resp, rlen, &errcode, &nadded);
        free(resp); resp = NULL;
        if (st != SEER_OK) return st;
        if (errcode == 1403 || nadded == 0)
            break;
    }

    /* Resolve any captured LOB locators (TTI_LOBOPS) while the cursor is open. */
    if (stmt->nplobs > 0)
        fv2_resolve_lobs(stmt);

    /* Call 4: close the cursor (best-effort). */
    if (seer_writer_init(&w, 8)) {
        seer_writer_u8(&w, TTI_FUN); seer_writer_u8(&w, O7_CLOSE); seer_writer_u8(&w, 0);
        seer_writer_u8(&w, 0x01); seer_writer_u8(&w, 0x01);
        if (seer_ttc_send(c, w.buf, w.len) == SEER_OK) {
            seer_writer_free(&w);
            if (seer_ttc_recv(c, &resp, &rlen) == SEER_OK) free(resp);
        } else {
            seer_writer_free(&w);
        }
    }

    if (errcode != 0 && errcode != 1403) {
        seer_log(SEER_LOG_ERROR, "fv2: fetch failed (ORA-%05ld)", (long)errcode);
        return SEER_EDB;
    }
    stmt->executed = true;
    stmt->cur      = -1;
    return SEER_OK;
}

/* Decode a 9i DML parse-execute response: an optional RPA piggyback then the
 * short OER whose first field is the affected-row count and second the ORA code. */
static void fv2_decode_dml_response(const uint8_t *data, size_t dlen,
                                    int64_t *rowcount, int64_t *code)
{
    *rowcount = 0;
    *code     = 0;
    if (dlen == 0)
        return;
    SeerReader r;
    seer_reader_init(&r, data, dlen);
    if (data[0] == TTI_RPA) {                    /* skip the RPA piggyback */
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
    if (seer_reader_remaining(&r) > 0 && r.buf[r.pos] == TTI_OER) {
        r.pos += 1;
        *rowcount = seer_dec_sb4(&r);
        *code     = seer_dec_sb4(&r);
    }
}

/* Oracle 9i DML / DDL over TTI_ALL7: OOPEN, a single parse that ALSO executes
 * (no describe/fetch), then close. 9i's parse carries no autocommit bit, so we
 * commit explicitly when autocommit is on. */
static SeerStatus fv2_execute_dml(SeerStmt *stmt)
{
    SeerConn *c = stmt->conn;
    uint8_t *resp = NULL;
    size_t   rlen = 0;
    SeerStatus st;
    SeerWriter w;

    /* OOPEN. */
    if (!seer_writer_init(&w, 8)) return SEER_ENOMEM;
    seer_writer_u8(&w, TTI_FUN); seer_writer_u8(&w, O7_OPEN); seer_writer_u8(&w, 0);
    seer_writer_u8(&w, 0x01); seer_writer_u8(&w, 0x00);
    st = fv2_txn(c, w.buf, w.len, &resp, &rlen); seer_writer_free(&w);
    if (st != SEER_OK) return st;
    free(resp); resp = NULL;

    /* Parse (also executes). */
    st = fv2_emit_parse(stmt, &w);
    if (st != SEER_OK) return st;
    st = fv2_txn(c, w.buf, w.len, &resp, &rlen); seer_writer_free(&w);
    if (st != SEER_OK) return st;

    int64_t rowcount = 0, code = 0;
    fv2_decode_dml_response(resp, rlen, &rowcount, &code);
    bool failed = (code != 0 && code != 1403);
    if (failed) {
        fv2_set_error(c, resp, rlen);
        seer_log(SEER_LOG_ERROR, "fv2: DML failed (ORA-%05ld)", (long)code);
    }
    free(resp); resp = NULL;

    /* Close (best-effort). */
    if (seer_writer_init(&w, 8)) {
        seer_writer_u8(&w, TTI_FUN); seer_writer_u8(&w, O7_CLOSE); seer_writer_u8(&w, 0);
        seer_writer_u8(&w, 0x01); seer_writer_u8(&w, 0x01);
        if (seer_ttc_send(c, w.buf, w.len) == SEER_OK) {
            seer_writer_free(&w);
            if (seer_ttc_recv(c, &resp, &rlen) == SEER_OK) free(resp);
        } else {
            seer_writer_free(&w);
        }
    }
    if (failed)
        return SEER_EDB;

    stmt->affected = (long)rowcount;
    stmt->executed = true;
    if (c->autocommit)
        seer_commit(c);                          /* no autocommit bit on the 9i parse */
    return SEER_OK;
}

/* Decode a 9i PL/SQL block reply: strip any leading bind prompt, read `n_out`
 * OUT/IN-OUT values (DALC + indicator, in OUT-position order) into the OUT binds'
 * `out` cells, then read the trailing RPA + short OER for rowcount + status. */
static void fv2_decode_block_out(SeerStmt *stmt, const uint8_t *data, size_t dlen,
                                 int n_out, int64_t *rowcount, int64_t *code)
{
    *rowcount = 0;
    *code     = 0;
    const uint8_t *rest = data;
    size_t         restlen = dlen;
    if (dlen >= 8 && data[0] == FV2_BIND_PROMPT) {   /* skip the bind prompt */
        size_t pos = 8;
        while (pos < dlen && data[pos] != TTI_RXD && data[pos] != TTI_RPA)
            pos++;
        rest = data + pos;
        restlen = dlen - pos;
    }
    SeerReader r;
    seer_reader_init(&r, rest, restlen);
    if (n_out > 0 && seer_reader_remaining(&r) > 0 && r.buf[r.pos] == TTI_RXD) {
        r.pos += 1;
        for (int i = 0; i < stmt->npbinds; i++) {
            SeerBind *b = &stmt->pbinds[i];
            if (!b->is_out)
                continue;
            uint8_t *val = NULL; size_t vlen = 0;
            if (seer_dec_dalc(&r, &val, &vlen) != SEER_OK) { free(val); break; }
            free(b->out.data);
            b->out = (SeerCell){ 0 };
            if (seer_reader_remaining(&r) > 0 && r.buf[r.pos] == 0x81) {
                r.pos += 2;                          /* 81 01 NULL */
            } else {
                if (seer_reader_remaining(&r) > 0) r.pos += 1;   /* present indicator */
                if (vlen > 0)
                    decode_scalar(b->oac_type ? b->oac_type : ORA_TYPE_VARCHAR,
                                  val, vlen, &b->out);
            }
            free(val);
        }
    }
    fv2_decode_dml_response(r.buf + r.pos, seer_reader_remaining(&r), rowcount, code);
}

/* Oracle 9i anonymous PL/SQL block over TTI_ALL7 (PROTOCOL §19.6/§19.7): OOPEN,
 * block parse (bind OACs, no inline values), then - if there are IN values - the
 * server sends a bind prompt and we reply with the IN values in one RXD; the reply
 * carries any OUT/IN-OUT values. */
static SeerStatus fv2_execute_block(SeerStmt *stmt)
{
    SeerConn *c = stmt->conn;
    uint8_t *resp = NULL;
    size_t   rlen = 0;
    SeerStatus st;
    SeerWriter w;

    int n_in = 0, n_out = 0;
    for (int i = 0; i < stmt->npbinds; i++) {
        if (stmt->pbinds[i].is_out) n_out++;
        else                        n_in++;
    }

    /* OOPEN. */
    if (!seer_writer_init(&w, 8)) return SEER_ENOMEM;
    seer_writer_u8(&w, TTI_FUN); seer_writer_u8(&w, O7_OPEN); seer_writer_u8(&w, 0);
    seer_writer_u8(&w, 0x01); seer_writer_u8(&w, 0x00);
    st = fv2_txn(c, w.buf, w.len, &resp, &rlen); seer_writer_free(&w);
    if (st != SEER_OK) return st;
    free(resp); resp = NULL;

    /* Block parse (OACs, no inline values). */
    st = fv2_emit_block(stmt, &w);
    if (st != SEER_OK) return st;
    st = fv2_txn(c, w.buf, w.len, &resp, &rlen); seer_writer_free(&w);
    if (st != SEER_OK) return st;

    /* With IN values, the reply is the bind prompt (or a compile OER); send the
     * IN values in one RXD, then the reply carries the OUT values. */
    if (n_in > 0) {
        int64_t pc = fv2_oer_code(resp, rlen);
        if (pc != 0 && pc != 1403) {
            fv2_set_error(c, resp, rlen);
            seer_log(SEER_LOG_ERROR, "fv2: block compile failed (ORA-%05ld)", (long)pc);
            free(resp);
            return SEER_EDB;
        }
        free(resp); resp = NULL;
        if (!seer_writer_init(&w, 32 + (size_t)n_in * 16)) return SEER_ENOMEM;
        seer_writer_u8(&w, TTI_RXD);
        for (int i = 0; i < stmt->npbinds; i++) {
            SeerBind *b = &stmt->pbinds[i];
            if (b->is_out) continue;
            uint8_t *rxd = (b->rxd != NULL) ? b->rxd[0] : NULL;
            if (rxd != NULL) seer_writer_bytes(&w, rxd, b->rxd_len[0]);
            else             seer_writer_u8(&w, 0);
        }
        if (!seer_writer_ok(&w)) { seer_writer_free(&w); return SEER_ENOMEM; }
        st = fv2_txn(c, w.buf, w.len, &resp, &rlen); seer_writer_free(&w);
        if (st != SEER_OK) return st;
    }

    int64_t rowcount = 0, code = 0;
    fv2_decode_block_out(stmt, resp, rlen, n_out, &rowcount, &code);
    bool failed = (code != 0 && code != 1403);
    if (failed) {
        fv2_set_error(c, resp, rlen);
        seer_log(SEER_LOG_ERROR, "fv2: block failed (ORA-%05ld)", (long)code);
    }
    free(resp); resp = NULL;

    /* Close (best-effort). */
    if (seer_writer_init(&w, 8)) {
        seer_writer_u8(&w, TTI_FUN); seer_writer_u8(&w, O7_CLOSE); seer_writer_u8(&w, 0);
        seer_writer_u8(&w, 0x01); seer_writer_u8(&w, 0x01);
        if (seer_ttc_send(c, w.buf, w.len) == SEER_OK) {
            seer_writer_free(&w);
            if (seer_ttc_recv(c, &resp, &rlen) == SEER_OK) free(resp);
        } else {
            seer_writer_free(&w);
        }
    }
    if (failed)
        return SEER_EDB;

    stmt->affected = (long)rowcount;
    stmt->executed = true;
    if (c->autocommit)
        seer_commit(c);
    return SEER_OK;
}

SeerStatus seer_stmt_execute(SeerStmt *stmt)
{
    if (stmt == NULL)
        return SEER_EPARAM;
    if (!stmt->conn->authenticated)
        return SEER_EPROTO;

    /* Oracle 9i (fv2) speaks the TTI_ALL7 dialect, not TTI_ALL8: SELECT is a
     * four-call fetch sequence, DML/DDL a single parse-execute. PL/SQL blocks are
     * the next fv2 slice. */
    if (stmt->conn->field_version < TTC_FIELD_VERSION_10_2) {
        StmtKind kind = classify_sql(stmt->sql);
        if (kind == STMT_SELECT)
            return fv2_execute_select(stmt);
        if (kind == STMT_CHANGE)
            return fv2_execute_dml(stmt);
        return fv2_execute_block(stmt);          /* BEGIN / DECLARE */
    }

    free_batch_errors(stmt);          /* clear any prior execute's failures */
    free_implicit(stmt);              /* and any prior implicit result sets   */
    free(stmt->dml_rowcounts);        /* and any prior array-DML row counts   */
    stmt->dml_rowcounts   = NULL;
    stmt->n_dml_rowcounts = 0;

    bool       was_reuse = stmt->reuse_cursor > 0;
    SeerWriter w;
    uint8_t   *resp = NULL;
    size_t     rlen = 0;
    OerResult  oer;
    SeerStatus st;

retry_exec:
    oer = (OerResult){ 0 };
    st  = build_exec(stmt, &w);
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
    free(resp);
    if (st != SEER_OK)
        return st;

    seer_log(SEER_LOG_DEBUG, "stmt: exec OER call_status=%ld err=%ld cursor=%ld rows=%zu",
             (long)oer.call_status, (long)oer.err_code, (long)oer.cursor_id, stmt->nrows);

    /* ORA-24381 is the non-fatal "error(s) in array DML" summary raised in
     * batcherrors mode: the per-row failures are in stmt->berrs and the good
     * rows applied, so the execute itself succeeded. */
    bool batch_summary = (oer.err_code == 24381 && stmt->nberrs > 0);
    if (oer.err_code != 0 && oer.err_code != 1403 && !batch_summary) {
        /* A reused cached cursor can be invalidated server-side (e.g. DDL
         * recreated the referenced object -> ORA-00942). Drop the stale cursor
         * and its describe and retry once with a full parse before surfacing. */
        if (was_reuse) {
            was_reuse          = false;
            stmt->reuse_cursor = 0;
            free_columns(stmt->cols, stmt->ncols);
            stmt->cols  = NULL;
            stmt->ncols = 0;
            free_rows(stmt);
            free_pending_lobs(stmt);
            free_pending_objs(stmt);
            stmt->cursor_id = 0;
            goto retry_exec;
        }
        seer_log(SEER_LOG_ERROR, "stmt: execute failed (ORA-%05ld)", (long)oer.err_code);
        return SEER_EDB;
    }
    stmt->cursor_id = (int)oer.cursor_id;
    stmt->affected  = (long)oer.row_count;

    /* A DDL (non-cacheable) statement can invalidate other cached cursors; drop
     * the cache so none is reused stale after an object is recreated. */
    if (!sql_is_cacheable(stmt->sql))
        stmt_cache_flush(stmt->conn);

    /* Fetch more while the server reports rows pending. */
    while (oer.call_status == 1 && oer.cursor_id != 0 && oer.err_code != 1403) {
        seer_log(SEER_LOG_DEBUG, "stmt: issuing FETCH on cursor %ld", (long)oer.cursor_id);
        st = build_fetch(stmt, &w);
        if (st != SEER_OK)
            return st;
        st = seer_ttc_send(stmt->conn, w.buf, w.len);
        seer_writer_free(&w);
        if (st != SEER_OK)
            return st;
        st = seer_ttc_recv(stmt->conn, &resp, &rlen);
        if (st != SEER_OK)
            return st;
        OerResult more = { 0 };
        st = parse_response(stmt, resp, rlen, false, &more);
        free(resp);
        if (st != SEER_OK)
            return st;
        if (more.err_code != 0 && more.err_code != 1403) {
            seer_log(SEER_LOG_ERROR, "stmt: fetch failed (ORA-%05ld)", (long)more.err_code);
            return SEER_EDB;
        }
        oer.call_status = more.err_code == 1403 ? 0 : more.call_status;
        oer.err_code    = more.err_code;
    }

    /* A REF CURSOR OUT bind: adopt the nested cursor's describe as this
     * statement's result set and drain its rows. */
    if (stmt->refcursor_present) {
        stmt->cols           = stmt->refcursor_cols;
        stmt->ncols          = stmt->refcursor_ncols;
        stmt->refcursor_cols = NULL;
        stmt->cursor_id      = stmt->refcursor_id;
        seer_log(SEER_LOG_DEBUG, "stmt: draining REF CURSOR %d (%d columns)",
                 stmt->refcursor_id, stmt->ncols);
        st = fetch_all_rows(stmt);
        if (st != SEER_OK)
            return st;
    }

    /* The cursor is drained; now fetch the content of any LOB cells, then decode
     * any SQL OBJECT cells (the latter may run dictionary queries). */
    resolve_pending_lobs(stmt);
    resolve_pending_objs(stmt);

    stmt->executed = true;
    stmt->cur = -1;
    seer_log(SEER_LOG_INFO, "stmt: executed (%d columns, %zu rows%s)",
             stmt->ncols, stmt->nrows,
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
SeerStatus seer_stmt_pipeline_burst(SeerConn *c, SeerStmt **stmts, size_t n,
                                    long *ora_codes)
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
    if (!seer_writer_init(&begin, 16)) { free(msgs); return SEER_ENOMEM; }
    seer_ttc_pipeline_begin(c, &begin, 1, TNS_PIPELINE_MODE_CONTINUE);

    for (size_t i = 0; i < n; i++) {
        stmts[i]->reuse_cursor = 0;               /* pipelined ops never cache-reuse */
        c->pipeline_token = (uint32_t)(i + 1);
        st = build_exec(stmts[i], &msgs[i]);
        c->pipeline_token = 0;
        if (st != SEER_OK)
            goto cleanup;
        built = i + 1;
    }

    SeerWriter end;
    if (!seer_writer_init(&end, 16)) { st = SEER_ENOMEM; goto cleanup; }
    seer_ttc_pipeline_end(c, &end);

    /* Phase 2: send. First packet = begin ++ op 1 (BEGIN_PIPELINE|END_OF_REQUEST);
     * ops 2..n each END_OF_REQUEST; then the ordinary end-pipeline message. */
    SeerWriter first;
    if (!seer_writer_init(&first, begin.len + msgs[0].len)) {
        seer_writer_free(&end); st = SEER_ENOMEM; goto cleanup;
    }
    seer_writer_bytes(&first, begin.buf, begin.len);
    seer_writer_bytes(&first, msgs[0].buf, msgs[0].len);
    st = seer_writer_ok(&first)
       ? seer_ttc_send_pipeline_op(c, first.buf, first.len,
                                   TNS_DATA_FLAGS_END_OF_REQUEST,
                                   TNS_DATA_FLAGS_BEGIN_PIPELINE)
       : SEER_ENOMEM;
    seer_writer_free(&first);
    for (size_t i = 1; i < n && st == SEER_OK; i++)
        st = seer_ttc_send_pipeline_op(c, msgs[i].buf, msgs[i].len,
                                       TNS_DATA_FLAGS_END_OF_REQUEST, 0);
    if (st == SEER_OK)
        st = seer_ttc_send(c, end.buf, end.len);   /* ordinary send (data flags 0) */
    seer_writer_free(&end);
    if (st != SEER_OK)
        goto cleanup;

    /* Phase 3: read + parse each op's response (no resolve calls yet — the line
     * still holds the queued responses). A decode failure is per-op; keep reading
     * so the stream stays in sync. A wire recv failure aborts the whole burst. */
    for (size_t i = 0; i < n; i++) {
        uint8_t *resp = NULL;
        size_t   rlen = 0;
        st = seer_ttc_recv_pipeline(c, &resp, &rlen);
        if (st != SEER_OK)
            goto cleanup;
        OerResult  oer = { 0 };
        SeerStatus pst = parse_response(stmts[i], resp, rlen, /*expect_dcb=*/true, &oer);
        free(resp);
        if (pst != SEER_OK) {
            ora_codes[i] = -1;
            continue;
        }
        stmts[i]->cursor_id = (int)oer.cursor_id;
        stmts[i]->affected  = (long)oer.row_count;
        stmts[i]->executed  = true;
        stmts[i]->cur       = -1;
        ora_codes[i] = (oer.err_code == 1403) ? 0 : (long)oer.err_code;
    }
    /* The end-pipeline message draws its own terminating response after the n op
     * responses; read and discard it so the next call is not left reading it. */
    {
        uint8_t *er = NULL;
        size_t   el = 0;
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
    stmt->cols      = ir->cols;
    stmt->ncols     = ir->ncols;
    ir->cols        = NULL;            /* moved out; close won't double-free */
    ir->ncols       = 0;
    stmt->cursor_id = ir->cursor_id;

    SeerStatus st = fetch_all_rows(stmt);
    if (st != SEER_OK)
        return st;
    resolve_pending_lobs(stmt);
    resolve_pending_objs(stmt);
    stmt->executed = true;
    stmt->cur      = -1;
    seer_log(SEER_LOG_INFO, "stmt: implicit result set now current (%d cols, %zu rows)",
             stmt->ncols, stmt->nrows);
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
    /* Keep this statement's parsed server cursor open in the statement cache,
     * keyed by its SQL, so re-preparing the same SQL re-executes it without a
     * re-parse. The describe columns move with it. (A full cache evicts + closes
     * its oldest cursor.) Done after the rows are freed - that loop needs ncols. */
    SeerConn *c = stmt->conn;
    if (c != NULL && c->authenticated && stmt->cursor_id > 0 && stmt->sql != NULL) {
        if (sql_is_cacheable(stmt->sql)) {
            stmt_cache_put(c, stmt->sql, stmt->cursor_id, stmt->cols, stmt->ncols);
            stmt->cols  = NULL;                 /* moved to the cache; don't free */
            stmt->ncols = 0;
        } else if (c->n_close < (int)(sizeof c->close_cursors / sizeof c->close_cursors[0])) {
            c->close_cursors[c->n_close++] = stmt->cursor_id;   /* DDL etc: just close */
        }
    }
    free_columns(stmt->cols, stmt->ncols);
    if (stmt->refcursor_cols != NULL)          /* captured but never drained */
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
    return (int)stmt->cols[col].max_size;
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

SeerStatus seer_stmt_get_data(SeerStmt *stmt, int col, const void **data,
                              size_t *len, int *is_null, int *is_binary)
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

    SeerCell *cell = &stmt->rows[stmt->cur][col];
    if (cell->data != NULL) {
        *data = cell->data;
        *len = cell->len;
        *is_null = 0;
        if (is_binary != NULL)
            *is_binary = cell->binary;
    }
    return SEER_OK;
}

SeerStatus seer_stmt_get_string(SeerStmt *stmt, int col,
                                const char **value, int *is_null)
{
    const void *data = NULL;
    size_t len = 0;
    SeerStatus st = seer_stmt_get_data(stmt, col, &data, &len, is_null, NULL);
    if (value != NULL)
        *value = (const char *)data;
    return st;
}

SeerStatus seer_stmt_out_data(SeerStmt *stmt, int param, const void **data,
                              size_t *len, int *is_null, int *is_binary)
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
 * of encode_chr): <ub1 len> inline for <254, else 0xFE + sb4 chunks. */
static SeerStatus obj_append_chr(SeerWriter *w, const uint8_t *data, size_t n, uint8_t fv)
{
    uint8_t *enc = NULL;
    size_t   enclen = 0;
    SeerStatus st = encode_chr(data, n, fv, &enc, &enclen);
    if (st != SEER_OK)
        return st;
    seer_writer_bytes(w, enc, enclen);
    free(enc);
    return SEER_OK;
}

/* Look up an object type's 16-byte OID (ALL_TYPES) and its ordered attribute
 * wire-types (ALL_TYPE_ATTRS). Caller owns *types. */
/* Look up an object/collection type's 16-byte OID (ALL_TYPES). */
static SeerStatus obj_lookup_oid(SeerConn *conn, const char *schema, const char *name,
                                 uint8_t oid[16])
{
    SeerStmt *q = NULL;
    if (seer_stmt_prepare(conn, "SELECT type_oid FROM all_types "
                                "WHERE owner = :1 AND type_name = :2", &q) != SEER_OK)
        return SEER_EPROTO;
    bool got = false;
    if (seer_stmt_bind_text(q, 1, schema, -1) == SEER_OK
        && seer_stmt_bind_text(q, 2, name, -1) == SEER_OK
        && seer_stmt_execute(q) == SEER_OK
        && seer_stmt_fetch(q) == SEER_OK) {
        const void *d = NULL; size_t dl = 0; int isnull = 0, isbin = 0;
        if (seer_stmt_get_data(q, 0, &d, &dl, &isnull, &isbin) == SEER_OK
            && d != NULL && dl == 16) {
            memcpy(oid, d, 16);
            got = true;
        }
    }
    seer_stmt_close(q);
    return got ? SEER_OK : SEER_EDB;           /* not found / not RAW(16) */
}

/* A collection type's single element wire-type (ALL_COLL_TYPES). */
static SeerStatus obj_lookup_elem(SeerConn *conn, const char *schema, const char *name,
                                  uint8_t *elem_type)
{
    SeerStmt *q = NULL;
    if (seer_stmt_prepare(conn, "SELECT elem_type_name FROM all_coll_types "
                                "WHERE owner = :1 AND type_name = :2", &q) != SEER_OK)
        return SEER_EPROTO;
    bool got = false;
    if (seer_stmt_bind_text(q, 1, schema, -1) == SEER_OK
        && seer_stmt_bind_text(q, 2, name, -1) == SEER_OK
        && seer_stmt_execute(q) == SEER_OK
        && seer_stmt_fetch(q) == SEER_OK) {
        const char *tn = NULL; int isnull = 0;
        seer_stmt_get_string(q, 0, &tn, &isnull);
        *elem_type = obj_type_to_ora(tn);
        got = true;
    }
    seer_stmt_close(q);
    return got ? SEER_OK : SEER_EDB;
}

/* Encode one image field (object attribute or collection element) from text:
 * 0xFF for NULL, else <length><raw scalar bytes> by Oracle type - NUMBER as an
 * exact base-100 decimal, DATE/TIMESTAMP from "YYYY-MM-DD[ HH:MM:SS[.fff]]", and
 * everything else as UTF-8 text. */
static void obj_encode_field(SeerWriter *body, uint8_t ora_type, const char *val)
{
    if (val == NULL) {
        seer_writer_u8(body, 0xFF);
        return;
    }
    if (ora_type == ORA_TYPE_NUMBER) {
        uint8_t num[24];
        size_t  nn = seer_encode_number_str(val, num);
        if (nn == 0)                           /* not a decimal: fall back to integer */
            nn = seer_encode_number_int(atoll(val), num);
        obj_write_length(body, (uint32_t)nn);
        seer_writer_bytes(body, num, nn);
    } else if (ora_type == ORA_TYPE_DATE || ora_type == ORA_TYPE_TIMESTAMP) {
        int y = 1, mo = 1, d = 1, h = 0, mi = 0, s = 0;
        double frac = 0.0;
        sscanf(val, "%d-%d-%d %d:%d:%lf", &y, &mo, &d, &h, &mi, &frac);
        s = (int)frac;
        uint8_t dt[11] = {
            (uint8_t)(y / 100 + 100), (uint8_t)(y % 100 + 100),
            (uint8_t)mo, (uint8_t)d,
            (uint8_t)(h + 1), (uint8_t)(mi + 1), (uint8_t)(s + 1),
            0, 0, 0, 0,
        };
        if (ora_type == ORA_TYPE_TIMESTAMP) {  /* + 4 big-endian nanoseconds */
            uint32_t nanos = (uint32_t)((frac - (double)s) * 1e9 + 0.5);
            dt[7] = (uint8_t)(nanos >> 24); dt[8] = (uint8_t)(nanos >> 16);
            dt[9] = (uint8_t)(nanos >> 8);  dt[10] = (uint8_t)nanos;
            obj_write_length(body, 11);
            seer_writer_bytes(body, dt, 11);
        } else {
            obj_write_length(body, 7);
            seer_writer_bytes(body, dt, 7);
        }
    } else {                                   /* char (and best-effort default): UTF-8 */
        size_t vl = strlen(val);
        obj_write_length(body, (uint32_t)vl);
        seer_writer_bytes(body, (const uint8_t *)val, vl);
    }
}

/* Shared finalize for an object/collection bind: given the encoded image and the
 * 16-byte type OID, build the bind-value framing + the object OAC and store the
 * bind. Takes ownership of `img` (always frees it). */
/* Object bind-value framing (oracledb write_dbobject), shared by SQL object
 * binds and AQ object payloads: a 36-byte TOID (prefix + the 16-byte type OID +
 * extent OID), empty object OID, zero snapshot/version, the image length, the
 * TOP_LEVEL flag, then the image - each length-framed. */
static SeerStatus obj_encode_bind_value(SeerWriter *bv, const uint8_t oid[16],
                                        const uint8_t *img, size_t imglen, uint8_t fv)
{
    static const uint8_t PFX[4]  = { 0x00, 0x22, 0x02, 0x08 };
    static const uint8_t EXT[16] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,1 };
    uint8_t toid[36];
    memcpy(toid, PFX, 4);
    memcpy(toid + 4, oid, 16);
    memcpy(toid + 20, EXT, 16);
    seer_enc_sb4(bv, 36);
    if (obj_append_chr(bv, toid, sizeof toid, fv) != SEER_OK) return SEER_ENOMEM;
    seer_enc_sb4(bv, 0);                        /* object OID (empty) */
    seer_enc_sb4(bv, 0);                        /* snapshot */
    seer_enc_sb4(bv, 0);                        /* version */
    seer_enc_sb4(bv, (uint32_t)imglen);         /* image length */
    seer_enc_sb4(bv, 1);                        /* flags: TOP_LEVEL */
    if (obj_append_chr(bv, img, imglen, fv) != SEER_OK) return SEER_ENOMEM;
    return seer_writer_ok(bv) ? SEER_OK : SEER_ENOMEM;
}

static SeerStatus obj_finalize_bind(SeerStmt *stmt, int param,
                                    const uint8_t oid[16], SeerWriter *img)
{
    uint8_t fv     = stmt->conn->field_version;
    size_t  imglen = img->len;
    SeerStatus st  = SEER_ENOMEM;

    SeerWriter bv, oac;
    if (!seer_writer_init(&bv, 64 + imglen)) { seer_writer_free(img); return SEER_ENOMEM; }
    if (obj_encode_bind_value(&bv, oid, img->buf, imglen, fv) != SEER_OK) goto fail;

    if (!seer_writer_init(&oac, 64)) goto fail;
    seer_writer_u8(&oac, ORA_TYPE_ADT);
    seer_writer_u8(&oac, 1);                    /* USE_INDICATORS */
    seer_writer_u8(&oac, 0);
    seer_writer_u8(&oac, 0);
    seer_enc_sb4(&oac, (uint32_t)imglen);       /* buffer size */
    seer_enc_sb4(&oac, 0);                      /* max array elements */
    seer_enc_sb4(&oac, 0);                      /* cont flag */
    seer_enc_sb4(&oac, 16);
    if (obj_append_chr(&oac, oid, 16, fv) != SEER_OK) { seer_writer_free(&oac); goto fail; }
    seer_enc_sb4(&oac, 1);                      /* type version */
    seer_enc_sb4(&oac, 0);                      /* charset */
    seer_writer_u8(&oac, 0);                    /* csfrm */
    seer_enc_sb4(&oac, 0);                      /* LOB prefetch length */
    seer_enc_sb4(&oac, 0);                      /* oaccolid */
    if (!seer_writer_ok(&oac)) { seer_writer_free(&oac); goto fail; }

    seer_writer_free(img);                      /* image now copied into bv */
    st = store_bind(stmt, param, ORA_TYPE_ADT, (uint32_t)imglen, 0, 0, false, bv.buf, bv.len);
    if (st != SEER_OK) { seer_writer_free(&oac); return st; }   /* store_bind freed bv.buf */
    SeerBind *b = &stmt->pbinds[param - 1];
    free(b->oac_override);
    b->oac_override     = oac.buf;              /* ownership transferred */
    b->oac_override_len = oac.len;
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
static SeerStatus obj_build_image(SeerConn *c, const char *schema,
                                  const char *type_name, const char *const *attr_values,
                                  int n_attrs, uint8_t oid[16], SeerWriter *img)
{
    SeerStatus st = obj_lookup_oid(c, schema, type_name, oid);
    if (st != SEER_OK)
        return st;
    uint8_t *types = NULL;
    int      ntypes = 0, cap = 0;
    build_obj_layout(c, schema, type_name, &types, NULL, &ntypes, &cap, 0);
    if (n_attrs != ntypes) { free(types); return SEER_EPARAM; }

    SeerWriter body;
    if (!seer_writer_init(&body, 64)) { free(types); return SEER_ENOMEM; }
    for (int i = 0; i < n_attrs; i++)
        obj_encode_field(&body, types[i], attr_values[i]);
    free(types);
    if (!seer_writer_ok(&body)) { seer_writer_free(&body); return SEER_ENOMEM; }

    uint32_t total = 7 + (uint32_t)body.len;
    if (!seer_writer_init(img, total)) { seer_writer_free(&body); return SEER_ENOMEM; }
    seer_writer_u8(img, 0x84);
    seer_writer_u8(img, 0x01);
    seer_writer_u8(img, 0xFE);
    obj_be4(img, total);
    seer_writer_bytes(img, body.buf, body.len);
    seer_writer_free(&body);
    return seer_writer_ok(img) ? SEER_OK : SEER_ENOMEM;
}

SeerStatus seer_stmt_bind_object(SeerStmt *stmt, int param, const char *schema,
                                 const char *type_name, const char *const *attr_values,
                                 int n_attrs)
{
    if (stmt == NULL || schema == NULL || type_name == NULL
        || (n_attrs > 0 && attr_values == NULL))
        return SEER_EPARAM;
    if (stmt->conn->field_version < TTC_FIELD_VERSION_12_2)
        return SEER_ENOTIMPL;                  /* object binds are 12c+ */

    uint8_t    oid[16];
    SeerWriter img;
    SeerStatus st = obj_build_image(stmt->conn, schema, type_name, attr_values,
                                    n_attrs, oid, &img);
    if (st != SEER_OK)
        return st;
    return obj_finalize_bind(stmt, param, oid, &img);
}

/* Bind a native LOB-backed value (JSON #70 / VECTOR #62): wrap `image` in the
 * native inline bind value (the 19-byte descriptor + ub2 image length + 22 zero
 * bytes + the bytes-with-length image) and attach the fixed per-type OAC. Shared
 * by the JSON and VECTOR binds. */
static SeerStatus native_lob_bind(SeerStmt *stmt, int param, uint8_t ora_type,
                                  const uint8_t *image, size_t imagelen,
                                  const uint8_t *oac_bytes, size_t oac_len)
{
    if (imagelen > 0xFFFF)
        return SEER_EPARAM;
    uint8_t fv = stmt->conn->field_version;
    static const uint8_t DESC[19] = {
        0x01, 0x28, 0x28, 0x00, 0x26, 0x00, 0x04, 0x61, 0x08, 0x00,
        0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    SeerWriter v;
    if (!seer_writer_init(&v, 64 + imagelen))
        return SEER_ENOMEM;
    seer_writer_bytes(&v, DESC, sizeof DESC);
    seer_writer_u8(&v, (uint8_t)(imagelen >> 8));
    seer_writer_u8(&v, (uint8_t)(imagelen & 0xFF));
    for (int i = 0; i < 22; i++) seer_writer_u8(&v, 0);
    obj_append_chr(&v, image, imagelen, fv);
    if (!seer_writer_ok(&v)) { seer_writer_free(&v); return SEER_ENOMEM; }

    uint8_t *oac = malloc(oac_len);
    if (oac == NULL) { seer_writer_free(&v); return SEER_ENOMEM; }
    memcpy(oac, oac_bytes, oac_len);

    SeerStatus st = store_bind(stmt, param, ora_type, (uint32_t)imagelen, 0, 0, false, v.buf, v.len);
    if (st != SEER_OK) { free(oac); return st; }   /* store_bind freed v.buf */
    SeerBind *b = &stmt->pbinds[param - 1];
    free(b->oac_override);
    b->oac_override     = oac;
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
        0x77, 0x01, 0x00, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00, 0x00,
        0x04, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
        0x02, 0x00, 0x00, 0x00, 0x00,
    };
    uint8_t *oson = NULL; size_t osonlen = 0;
    SeerStatus st = seer_json_to_oson(json_text, &oson, &osonlen);
    if (st != SEER_OK)
        return st;
    st = native_lob_bind(stmt, param, ORA_TYPE_JSON, oson, osonlen, JSON_OAC, sizeof JSON_OAC);
    free(oson);
    return st;
}

/* VECTOR image flag words (oracledb _BIND_HEADER): the NORM bit is always set
 * (an 8-byte norm placeholder follows the header). */
#define VEC_FLAGS_DENSE  0x0012   /* FLOAT32/64/INT8: NORM | 0x02          */
#define VEC_FLAGS_BINARY 0x0010   /* BINARY: NORM only                     */
#define VEC_FLAGS_SPARSE 0x0032   /* sparse FLOAT32: NORM | 0x02 | SPARSE  */

/* Start a VECTOR bind image: gate (23ai) and write the header - magic, version,
 * ub2 flags, element type, ub4 count, then the 8-byte norm placeholder. On
 * SEER_OK the caller appends the element data and calls vector_img_finish. */
static SeerStatus vector_img_start(SeerStmt *stmt, uint8_t version, uint16_t flags,
                                   uint8_t etype, uint32_t count, size_t body_hint,
                                   SeerWriter *img)
{
    if (stmt == NULL)
        return SEER_EPARAM;
    if (stmt->conn->field_version < TTC_FIELD_VERSION_23_1)
        return SEER_ENOTIMPL;                  /* VECTOR is 23ai */
    if (!seer_writer_init(img, 17 + body_hint))
        return SEER_ENOMEM;
    seer_writer_u8(img, VEC_MAGIC);
    seer_writer_u8(img, version);
    seer_writer_u8(img, (uint8_t)(flags >> 8));
    seer_writer_u8(img, (uint8_t)(flags & 0xFF));
    seer_writer_u8(img, etype);
    obj_be4(img, count);                       /* element / dimension count      */
    for (int i = 0; i < 8; i++) seer_writer_u8(img, 0);     /* norm placeholder  */
    return SEER_OK;
}

/* Wrap a completed VECTOR image in the native-LOB bind value (VECTOR OAC, type
 * 127) and store it. Frees `img`. */
static SeerStatus vector_img_finish(SeerStmt *stmt, int param, SeerWriter *img)
{
    static const uint8_t VEC_OAC[25] = {
        0x7f, 0x01, 0x00, 0x00, 0x04, 0x00, 0x10, 0x00, 0x00, 0x00,
        0x04, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
        0x00, 0x10, 0x00, 0x00, 0x00,
    };
    if (!seer_writer_ok(img)) { seer_writer_free(img); return SEER_ENOMEM; }
    SeerStatus st = native_lob_bind(stmt, param, ORA_TYPE_VECTOR, img->buf, img->len,
                                    VEC_OAC, sizeof VEC_OAC);
    seer_writer_free(img);
    return st;
}

/* Native VECTOR bind (#62), dense FLOAT32: order-preserving 4-byte elements. 23ai+. */
SeerStatus seer_stmt_bind_vector_f32(SeerStmt *stmt, int param,
                                     const float *values, int dims)
{
    if (dims < 0 || (dims > 0 && values == NULL))
        return SEER_EPARAM;
    SeerWriter img;
    SeerStatus st = vector_img_start(stmt, 0, VEC_FLAGS_DENSE, VEC_TYPE_FLOAT32,
                                     (uint32_t)dims, (size_t)dims * 4, &img);
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
SeerStatus seer_stmt_bind_vector_f64(SeerStmt *stmt, int param,
                                     const double *values, int dims)
{
    if (dims < 0 || (dims > 0 && values == NULL))
        return SEER_EPARAM;
    SeerWriter img;
    SeerStatus st = vector_img_start(stmt, 0, VEC_FLAGS_DENSE, VEC_TYPE_FLOAT64,
                                     (uint32_t)dims, (size_t)dims * 8, &img);
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
SeerStatus seer_stmt_bind_vector_i8(SeerStmt *stmt, int param,
                                    const int8_t *values, int dims)
{
    if (dims < 0 || (dims > 0 && values == NULL))
        return SEER_EPARAM;
    SeerWriter img;
    SeerStatus st = vector_img_start(stmt, 0, VEC_FLAGS_DENSE, VEC_TYPE_INT8,
                                     (uint32_t)dims, (size_t)dims, &img);
    if (st != SEER_OK)
        return st;
    for (int i = 0; i < dims; i++)
        seer_writer_u8(&img, (uint8_t)values[i]);
    return vector_img_finish(stmt, param, &img);
}

/* Native VECTOR bind, BINARY: a bit vector packed as `nbytes` bytes (8 dimensions
 * per byte). Version 1, count = nbytes*8. 23ai+. */
SeerStatus seer_stmt_bind_vector_binary(SeerStmt *stmt, int param,
                                        const uint8_t *bytes, int nbytes)
{
    if (nbytes < 0 || (nbytes > 0 && bytes == NULL))
        return SEER_EPARAM;
    SeerWriter img;
    SeerStatus st = vector_img_start(stmt, 1, VEC_FLAGS_BINARY, VEC_TYPE_BINARY,
                                     (uint32_t)nbytes * 8, (size_t)nbytes, &img);
    if (st != SEER_OK)
        return st;
    if (nbytes > 0)
        seer_writer_bytes(&img, bytes, (size_t)nbytes);
    return vector_img_finish(stmt, param, &img);
}

/* Native VECTOR bind, sparse FLOAT32: a `num_dimensions`-wide vector with `nnz`
 * non-zero entries (indices[i] -> values[i]). Version 2; the body is ub2 nnz,
 * then nnz ub4 indices, then nnz order-preserving 4-byte values. 23ai+. */
SeerStatus seer_stmt_bind_vector_sparse_f32(SeerStmt *stmt, int param,
                                            int num_dimensions, int nnz,
                                            const uint32_t *indices, const float *values)
{
    if (num_dimensions < 0 || nnz < 0 || nnz > 0xFFFF
        || (nnz > 0 && (indices == NULL || values == NULL)))
        return SEER_EPARAM;
    SeerWriter img;
    SeerStatus st = vector_img_start(stmt, 2, VEC_FLAGS_SPARSE, VEC_TYPE_FLOAT32,
                                     (uint32_t)num_dimensions, 2 + (size_t)nnz * 8, &img);
    if (st != SEER_OK)
        return st;
    seer_writer_u8(&img, (uint8_t)((unsigned)nnz >> 8));   /* ub2 non-zero count */
    seer_writer_u8(&img, (uint8_t)((unsigned)nnz & 0xFF));
    for (int i = 0; i < nnz; i++)
        obj_be4(&img, indices[i]);                         /* ub4 indices        */
    for (int i = 0; i < nnz; i++) {
        uint8_t e[4];
        seer_encode_bfloat(values[i], e);                  /* 4-byte values      */
        seer_writer_bytes(&img, e, 4);
    }
    return vector_img_finish(stmt, param, &img);
}

/* Native VECTOR bind, sparse FLOAT64: as sparse FLOAT32 but 8-byte values. 23ai+. */
SeerStatus seer_stmt_bind_vector_sparse_f64(SeerStmt *stmt, int param,
                                            int num_dimensions, int nnz,
                                            const uint32_t *indices, const double *values)
{
    if (num_dimensions < 0 || nnz < 0 || nnz > 0xFFFF
        || (nnz > 0 && (indices == NULL || values == NULL)))
        return SEER_EPARAM;
    SeerWriter img;
    SeerStatus st = vector_img_start(stmt, 2, VEC_FLAGS_SPARSE, VEC_TYPE_FLOAT64,
                                     (uint32_t)num_dimensions, 2 + (size_t)nnz * 12, &img);
    if (st != SEER_OK)
        return st;
    seer_writer_u8(&img, (uint8_t)((unsigned)nnz >> 8));   /* ub2 non-zero count */
    seer_writer_u8(&img, (uint8_t)((unsigned)nnz & 0xFF));
    for (int i = 0; i < nnz; i++)
        obj_be4(&img, indices[i]);                         /* ub4 indices        */
    for (int i = 0; i < nnz; i++) {
        uint8_t e[8];
        seer_encode_bdouble(values[i], e);                 /* 8-byte values      */
        seer_writer_bytes(&img, e, 8);
    }
    return vector_img_finish(stmt, param, &img);
}

/* Native VECTOR bind, sparse INT8: as sparse FLOAT32 but 1 signed byte per value. 23ai+. */
SeerStatus seer_stmt_bind_vector_sparse_i8(SeerStmt *stmt, int param,
                                           int num_dimensions, int nnz,
                                           const uint32_t *indices, const int8_t *values)
{
    if (num_dimensions < 0 || nnz < 0 || nnz > 0xFFFF
        || (nnz > 0 && (indices == NULL || values == NULL)))
        return SEER_EPARAM;
    SeerWriter img;
    SeerStatus st = vector_img_start(stmt, 2, VEC_FLAGS_SPARSE, VEC_TYPE_INT8,
                                     (uint32_t)num_dimensions, 2 + (size_t)nnz * 5, &img);
    if (st != SEER_OK)
        return st;
    seer_writer_u8(&img, (uint8_t)((unsigned)nnz >> 8));   /* ub2 non-zero count */
    seer_writer_u8(&img, (uint8_t)((unsigned)nnz & 0xFF));
    for (int i = 0; i < nnz; i++)
        obj_be4(&img, indices[i]);                         /* ub4 indices        */
    for (int i = 0; i < nnz; i++)
        seer_writer_u8(&img, (uint8_t)values[i]);          /* 1-byte values      */
    return vector_img_finish(stmt, param, &img);
}

SeerStatus seer_stmt_bind_collection(SeerStmt *stmt, int param, const char *schema,
                                     const char *type_name, const char *const *elem_values,
                                     int n_elems)
{
    if (stmt == NULL || schema == NULL || type_name == NULL
        || (n_elems > 0 && elem_values == NULL))
        return SEER_EPARAM;
    if (stmt->conn->field_version < TTC_FIELD_VERSION_12_2)
        return SEER_ENOTIMPL;                  /* collection binds are 12c+ */

    uint8_t oid[16];
    SeerStatus st = obj_lookup_oid(stmt->conn, schema, type_name, oid);
    if (st != SEER_OK)
        return st;
    uint8_t elem_type = 0;
    st = obj_lookup_elem(stmt->conn, schema, type_name, &elem_type);
    if (st != SEER_OK)
        return st;

    /* Collection image body: a collection-flags byte, the length-prefixed element
     * count, then each element field. */
    SeerWriter body;
    if (!seer_writer_init(&body, 64)) return SEER_ENOMEM;
    seer_writer_u8(&body, 0x00);               /* collection flags */
    obj_write_length(&body, (uint32_t)(n_elems > 0 ? n_elems : 0));
    for (int i = 0; i < n_elems; i++)
        obj_encode_field(&body, elem_type, elem_values[i]);
    if (!seer_writer_ok(&body)) { seer_writer_free(&body); return SEER_ENOMEM; }

    /* Collection image: header (0x88, version, 0xFE, BE4 total) + prefix seg [1,1]
     * + body. Total counts the 7-byte header and the 2-byte prefix segment. */
    SeerWriter img;
    uint32_t total = 9 + (uint32_t)body.len;
    if (!seer_writer_init(&img, total)) { seer_writer_free(&body); return SEER_ENOMEM; }
    seer_writer_u8(&img, 0x88);
    seer_writer_u8(&img, 0x01);
    seer_writer_u8(&img, 0xFE);
    obj_be4(&img, total);
    seer_writer_u8(&img, 1);
    seer_writer_u8(&img, 1);
    seer_writer_bytes(&img, body.buf, body.len);
    seer_writer_free(&body);
    if (!seer_writer_ok(&img)) { seer_writer_free(&img); return SEER_ENOMEM; }
    return obj_finalize_bind(stmt, param, oid, &img);
}

/* Build the OAC for an associative-array (PL/SQL index-by) bind: the scalar OAC
 * with the ARRAY flag (0x40) set and the declared capacity in the max-array-
 * elements field. `length` is the element's max byte size. Returns malloc'd bytes
 * in *out_len (caller owns), or NULL. 12c+ OAC shape. */
static uint8_t *aa_build_oac(uint8_t dtype, uint32_t length, uint32_t charset,
                             uint8_t csfrm, uint32_t capacity, size_t *out_len)
{
    SeerWriter w;
    if (!seer_writer_init(&w, 48))
        return NULL;
    seer_writer_u8(&w, dtype);
    seer_writer_u8(&w, 0x41);              /* TNS_BIND_USE_INDICATORS | ARRAY */
    seer_writer_u8(&w, 0);
    seer_writer_u8(&w, 0);
    seer_enc_sb4(&w, length);              /* element max length */
    seer_enc_sb4(&w, capacity ? capacity : 1);   /* max number of array elements */
    seer_enc_sb4(&w, 0);                   /* cont flag (ub8) */
    seer_enc_sb4(&w, 0);                   /* OID */
    seer_enc_sb4(&w, 0);                   /* version */
    seer_enc_sb4(&w, charset);             /* charset id (ub2) */
    seer_writer_u8(&w, csfrm);             /* character set form */
    seer_enc_sb4(&w, 0);                   /* LOB prefetch length */
    seer_enc_sb4(&w, 0);                   /* oaccolid */
    if (!seer_writer_ok(&w)) { seer_writer_free(&w); return NULL; }
    *out_len = w.len;
    return w.buf;                          /* ownership transferred */
}

/* Attach a prebuilt array OAC + RXD to a bind position (a single PL/SQL
 * associative-array parameter). Takes ownership of `rxd` and `oac`. */
static SeerStatus aa_store(SeerStmt *stmt, int param, uint8_t dtype, uint32_t length,
                           uint8_t *rxd, size_t rxd_len, uint8_t *oac, size_t oac_len)
{
    SeerStatus st = store_bind(stmt, param, dtype, length, 0, 0, false, rxd, rxd_len);
    if (st != SEER_OK) { free(oac); return st; }   /* store_bind freed rxd */
    SeerBind *b = &stmt->pbinds[param - 1];
    free(b->oac_override);
    b->oac_override     = oac;
    b->oac_override_len = oac_len;
    b->is_array         = true;
    return SEER_OK;
}

/* Bind a PL/SQL associative-array (index-by table) OUT parameter (12c+): the
 * server fills up to `capacity` elements of type `ora_type` (NUMBER or VARCHAR).
 * Read them back with seer_stmt_out_array_len / seer_stmt_out_array_get. */
SeerStatus seer_stmt_bind_out_array(SeerStmt *stmt, int param, int ora_type,
                                    int elem_size, int capacity)
{
    if (stmt == NULL || capacity <= 0)
        return SEER_EPARAM;
    if (stmt->conn->field_version < TTC_FIELD_VERSION_12_2)
        return SEER_ENOTIMPL;

    uint8_t  dtype   = (ora_type == ORA_TYPE_NUMBER) ? ORA_TYPE_NUMBER : ORA_TYPE_VARCHAR;
    uint32_t length  = (dtype == ORA_TYPE_NUMBER) ? 22
                                                  : (uint32_t)(elem_size > 0 ? elem_size : 2000);
    uint32_t charset = (dtype == ORA_TYPE_NUMBER) ? 0 : 873;
    uint8_t  csfrm   = (dtype == ORA_TYPE_NUMBER) ? 0 : 1;

    size_t oac_len = 0;
    uint8_t *oac = aa_build_oac(dtype, length, charset, csfrm, (uint32_t)capacity, &oac_len);
    if (oac == NULL)
        return SEER_ENOMEM;
    uint8_t *rxd = malloc(1);              /* empty-array placeholder (ub4 count 0) */
    if (rxd == NULL) { free(oac); return SEER_ENOMEM; }
    rxd[0] = 0;

    SeerStatus st = store_bind(stmt, param, dtype, length, charset, 0, true, rxd, 1);
    if (st != SEER_OK) { free(oac); return st; }
    SeerBind *b = &stmt->pbinds[param - 1];
    free(b->oac_override);
    b->oac_override     = oac;
    b->oac_override_len = oac_len;
    b->is_array         = true;
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
SeerStatus seer_stmt_out_array_get(SeerStmt *stmt, int param, int index,
                                   const char **data, size_t *len, int *isnull)
{
    if (stmt == NULL || param < 1 || param > stmt->npbinds || data == NULL)
        return SEER_EPARAM;
    SeerBind *b = &stmt->pbinds[param - 1];
    if (!b->is_array || index < 0 || index >= b->out_arr_n)
        return SEER_EPARAM;
    SeerCell *c = &b->out_arr[index];
    *data = c->data;
    if (len)    *len    = c->len;
    if (isnull) *isnull = (c->data == NULL);
    return SEER_OK;
}

SeerStatus seer_stmt_bind_int64_array(SeerStmt *stmt, int param,
                                      const int64_t *values, int n)
{
    if (stmt == NULL || n < 0 || (n > 0 && values == NULL))
        return SEER_EPARAM;
    if (stmt->conn->field_version < TTC_FIELD_VERSION_12_2)
        return SEER_ENOTIMPL;              /* the array-bind OAC shape is 12c+ */

    /* RXD: ub4 element count, then each element <ub1 len><NUMBER bytes>. */
    SeerWriter rxd;
    if (!seer_writer_init(&rxd, 16 + (size_t)n * 12))
        return SEER_ENOMEM;
    seer_enc_sb4(&rxd, (uint32_t)n);
    for (int i = 0; i < n; i++) {
        uint8_t num[24];
        size_t  nn = seer_encode_number_int(values[i], num);
        seer_writer_u8(&rxd, (uint8_t)nn);
        seer_writer_bytes(&rxd, num, nn);
    }
    if (!seer_writer_ok(&rxd)) { seer_writer_free(&rxd); return SEER_ENOMEM; }

    size_t oac_len = 0;
    uint8_t *oac = aa_build_oac(ORA_TYPE_NUMBER, 22, 0, 0, (uint32_t)n, &oac_len);
    if (oac == NULL) { seer_writer_free(&rxd); return SEER_ENOMEM; }
    return aa_store(stmt, param, ORA_TYPE_NUMBER, 22, rxd.buf, rxd.len, oac, oac_len);
}

SeerStatus seer_stmt_bind_text_array(SeerStmt *stmt, int param,
                                     const char *const *values, int n, int elem_size)
{
    if (stmt == NULL || n < 0 || (n > 0 && values == NULL) || elem_size <= 0)
        return SEER_EPARAM;
    if (stmt->conn->field_version < TTC_FIELD_VERSION_12_2)
        return SEER_ENOTIMPL;

    /* RXD: ub4 count, then each element as a length-framed CHR value. */
    SeerWriter rxd;
    if (!seer_writer_init(&rxd, 32 + (size_t)n * 16))
        return SEER_ENOMEM;
    seer_enc_sb4(&rxd, (uint32_t)n);
    for (int i = 0; i < n; i++) {
        if (values[i] == NULL) {
            seer_writer_u8(&rxd, 0);       /* NULL element (zero-length) */
            continue;
        }
        if (obj_append_chr(&rxd, (const uint8_t *)values[i], strlen(values[i]),
                           stmt->conn->field_version) != SEER_OK) {
            seer_writer_free(&rxd);
            return SEER_ENOMEM;
        }
    }
    if (!seer_writer_ok(&rxd)) { seer_writer_free(&rxd); return SEER_ENOMEM; }

    size_t oac_len = 0;
    uint8_t *oac = aa_build_oac(ORA_TYPE_VARCHAR, (uint32_t)elem_size, 873, 1,
                                (uint32_t)n, &oac_len);
    if (oac == NULL) { seer_writer_free(&rxd); return SEER_ENOMEM; }
    return aa_store(stmt, param, ORA_TYPE_VARCHAR, (uint32_t)elem_size,
                    rxd.buf, rxd.len, oac, oac_len);
}

/* ------------------------------------------------- two-phase commit (XA/TPC) */

/* Reject an out-of-range Xid (XA caps gtrid and bqual at 64 bytes each). */
static bool xid_valid(const SeerXid *xid)
{
    return xid != NULL && xid->gtrid_len >= 0 && xid->bqual_len >= 0
        && xid->gtrid_len <= 64 && xid->bqual_len <= 64
        && (xid->gtrid_len + xid->bqual_len) <= TNS_TPC_XID_WIRE_LEN;
}

/* The format-id / gtrid-len / bqual-len / xid-pointer descriptor block shared by
 * both TPC messages (the 128-byte xid payload follows later in the body). */
static void tpc_xid_descriptor(SeerWriter *w, const SeerXid *xid)
{
    if (xid != NULL) {
        seer_enc_sb4(w, (uint32_t)xid->format_id);
        seer_enc_sb4(w, (uint32_t)xid->gtrid_len);
        seer_enc_sb4(w, (uint32_t)xid->bqual_len);
        seer_writer_u8(w, 1);
        seer_enc_sb4(w, TNS_TPC_XID_WIRE_LEN);
    } else {
        seer_enc_sb4(w, 0); seer_enc_sb4(w, 0); seer_enc_sb4(w, 0);
        seer_writer_u8(w, 0); seer_enc_sb4(w, 0);
    }
}

/* The 128-byte wire xid: gtrid then bqual, zero-padded. */
static void tpc_xid_payload(SeerWriter *w, const SeerXid *xid)
{
    uint8_t buf[TNS_TPC_XID_WIRE_LEN] = { 0 };
    int g = xid->gtrid_len, b = xid->bqual_len;
    if (g > 0) memcpy(buf, xid->gtrid, (size_t)g);
    if (b > 0) memcpy(buf + g, xid->bqual, (size_t)b);
    seer_writer_bytes(w, buf, sizeof buf);
}

/* Build a TXN_SWITCH (begin/end) message, replaying any stored context. */
SeerStatus seer_tpc_build_switch(SeerConn *c, SeerWriter *w, uint32_t op,
                                 const SeerXid *xid, uint32_t flags, uint32_t timeout)
{
    if (!seer_writer_init(w, 256))
        return SEER_ENOMEM;
    seer_ttc_fun_header(c, w, TNS_FUNC_TPC_TXN_SWITCH);
    seer_enc_sb4(w, op);
    if (c->tpc_context != NULL) {
        seer_writer_u8(w, 1);
        seer_enc_sb4(w, (uint32_t)c->tpc_context_len);
    } else {
        seer_writer_u8(w, 0);
        seer_enc_sb4(w, 0);
    }
    tpc_xid_descriptor(w, xid);
    seer_enc_sb4(w, flags);
    seer_enc_sb4(w, timeout);
    seer_writer_u8(w, 1); seer_writer_u8(w, 1); seer_writer_u8(w, 1);  /* ptrs */
    seer_writer_u8(w, 0); seer_enc_sb4(w, 0);   /* internal name: none */
    seer_writer_u8(w, 0); seer_enc_sb4(w, 0);   /* external name: none */
    if (c->tpc_context != NULL)
        seer_writer_bytes(w, c->tpc_context, c->tpc_context_len);
    if (xid != NULL)
        tpc_xid_payload(w, xid);
    seer_enc_sb4(w, 0);                          /* app value */
    return seer_writer_ok(w) ? SEER_OK : SEER_ENOMEM;
}

/* Build a TXN_CHANGE_STATE (prepare/commit/abort) message. */
static SeerStatus tpc_build_change_state(SeerConn *c, SeerWriter *w, uint32_t op,
                                         uint32_t state, const SeerXid *xid)
{
    if (!seer_writer_init(w, 256))
        return SEER_ENOMEM;
    seer_ttc_fun_header(c, w, TNS_FUNC_TPC_TXN_CHANGE_STATE);
    seer_enc_sb4(w, op);
    if (c->tpc_context != NULL) {
        seer_writer_u8(w, 1);
        seer_enc_sb4(w, (uint32_t)c->tpc_context_len);
    } else {
        seer_writer_u8(w, 0);
        seer_enc_sb4(w, 0);
    }
    tpc_xid_descriptor(w, xid);
    seer_enc_sb4(w, 0);          /* timeout */
    seer_enc_sb4(w, state);
    seer_writer_u8(w, 1);        /* out-state pointer */
    seer_enc_sb4(w, 0);          /* flags */
    if (c->tpc_context != NULL)
        seer_writer_bytes(w, c->tpc_context, c->tpc_context_len);
    if (xid != NULL)
        tpc_xid_payload(w, xid);
    return seer_writer_ok(w) ? SEER_OK : SEER_ENOMEM;
}

/* Send a built TPC message (frees `w`) and decode the reply: TTI_RPA carries the
 * begin context (want_context) or the ub4 change-state, with a trailing OER call
 * status; a reply leading with TTI_OER is an ORA error. */
static SeerStatus tpc_call(SeerConn *c, SeerWriter *w, bool want_context,
                           uint8_t **ctx, size_t *ctxlen, uint32_t *state)
{
    SeerStatus st = seer_ttc_send(c, w->buf, w->len);
    seer_writer_free(w);
    if (st != SEER_OK)
        return st;
    uint8_t *resp = NULL; size_t rlen = 0;
    st = seer_ttc_recv(c, &resp, &rlen);
    if (st != SEER_OK)
        return st;

    SeerReader r;
    seer_reader_init(&r, resp, rlen);
    r.sb4_chunks = c->field_version >= TTC_FIELD_VERSION_12_1;
    SeerStmt   tmp = { .conn = c };
    OerResult  oer = { 0 };
    SeerStatus ret = SEER_OK;
    uint8_t    tok = seer_reader_u8(&r);

    if (tok == TTI_RPA) {
        if (want_context) {
            (void)seer_dec_sb4(&r);                 /* app value */
            int64_t clen = seer_dec_sb4(&r);
            if (clen < 0 || (size_t)clen > seer_reader_remaining(&r)) {
                free(resp);
                return SEER_EPROTO;
            }
            uint8_t *cx = malloc((size_t)clen ? (size_t)clen : 1);
            if (cx == NULL) { free(resp); return SEER_ENOMEM; }
            const uint8_t *p = seer_reader_bytes(&r, (size_t)clen);
            if (p != NULL && clen > 0) memcpy(cx, p, (size_t)clen);
            *ctx = cx;
            *ctxlen = (size_t)clen;
        } else if (state != NULL) {
            *state = (uint32_t)seer_dec_sb4(&r);
        }
        if (seer_reader_remaining(&r) > 0 && seer_reader_u8(&r) == TTI_OER) {
            parse_oer(&r, &tmp, &oer);
            if (oer.err_code != 0)
                ret = SEER_EDB;
        }
    } else if (tok == TTI_OER) {
        parse_oer(&r, &tmp, &oer);
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

SeerStatus seer_tpc_begin(SeerConn *conn, const SeerXid *xid, uint32_t flags,
                          uint32_t timeout)
{
    if (conn == NULL || !xid_valid(xid))
        return SEER_EPARAM;
    if (conn->field_version < TTC_FIELD_VERSION_12_1)
        return SEER_ENOTIMPL;                       /* TPC is 12c+ */
    SeerWriter w;
    SeerStatus st = seer_tpc_build_switch(conn, &w, TNS_TPC_TXN_START, xid, flags, timeout);
    if (st != SEER_OK)
        return st;
    uint8_t *ctx = NULL; size_t ctxlen = 0;
    st = tpc_call(conn, &w, true, &ctx, &ctxlen, NULL);
    if (st != SEER_OK) { free(ctx); return st; }
    free(conn->tpc_context);
    conn->tpc_context     = ctx;
    conn->tpc_context_len = ctxlen;
    return SEER_OK;
}

SeerStatus seer_tpc_end(SeerConn *conn, const SeerXid *xid, uint32_t flags)
{
    if (conn == NULL || !xid_valid(xid))
        return SEER_EPARAM;
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
    SeerWriter w;
    SeerStatus st = tpc_build_change_state(conn, &w, TNS_TPC_TXN_PREPARE, 0, xid);
    if (st != SEER_OK)
        return st;
    uint32_t state = 0;
    st = tpc_call(conn, &w, false, NULL, NULL, &state);
    if (st != SEER_OK)
        return st;
    if (state != TNS_TPC_TXN_STATE_REQUIRES_COMMIT
        && state != TNS_TPC_TXN_STATE_READ_ONLY)
        return SEER_EPROTO;
    if (commit_needed != NULL)
        *commit_needed = (state == TNS_TPC_TXN_STATE_REQUIRES_COMMIT);
    return SEER_OK;
}

SeerStatus seer_tpc_commit(SeerConn *conn, const SeerXid *xid, int one_phase)
{
    if (conn == NULL || !xid_valid(xid))
        return SEER_EPARAM;
    uint32_t want = one_phase ? TNS_TPC_TXN_STATE_READ_ONLY
                              : TNS_TPC_TXN_STATE_COMMITTED;
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
    SeerWriter w;
    SeerStatus st = tpc_build_change_state(conn, &w, TNS_TPC_TXN_ABORT,
                                           TNS_TPC_TXN_STATE_ABORTED, xid);
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
static SeerStatus sessionless_switch(SeerConn *conn, uint32_t op,
                                     const SeerXid *xid, uint32_t flags,
                                     uint32_t timeout)
{
    if (conn == NULL)
        return SEER_EPARAM;
    if (conn->field_version < TTC_FIELD_VERSION_23_1)
        return SEER_ENOTIMPL;                  /* sessionless txns are 23ai+ */
    SeerWriter w;
    SeerStatus st = seer_tpc_build_switch(conn, &w, op, xid, flags, timeout);
    if (st != SEER_OK)
        return st;
    if (op == TNS_TPC_TXN_START) {
        uint8_t *ctx = NULL; size_t ctxlen = 0;
        st = tpc_call(conn, &w, true, &ctx, &ctxlen, NULL);
        free(ctx);                             /* not replayed for sessionless */
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

SeerStatus seer_txn_begin_sessionless(SeerConn *conn, const uint8_t *txn_id,
                                      size_t txn_id_len, uint32_t timeout)
{
    if (conn == NULL)
        return SEER_EPARAM;
    if (!sessionless_id_valid(txn_id, txn_id_len))
        return SEER_EPARAM;
    if (conn->sessionless_active)
        return SEER_EPARAM;                    /* one sessionless txn at a time */
    SeerXid xid = {
        .format_id = TNS_TPC_SESSIONLESS_FORMAT_ID,
        .gtrid = txn_id, .gtrid_len = (int)txn_id_len,
        .bqual = NULL,   .bqual_len = 0,
    };
    SeerStatus st = sessionless_switch(conn, TNS_TPC_TXN_START, &xid,
                                       SEER_TPC_BEGIN_NEW | TNS_TPC_FLAGS_SESSIONLESS,
                                       timeout);
    if (st == SEER_OK)
        conn->sessionless_active = true;
    return st;
}

SeerStatus seer_txn_resume_sessionless(SeerConn *conn, const uint8_t *txn_id,
                                       size_t txn_id_len, uint32_t timeout)
{
    if (conn == NULL)
        return SEER_EPARAM;
    if (!sessionless_id_valid(txn_id, txn_id_len))
        return SEER_EPARAM;
    if (conn->sessionless_active)
        return SEER_EPARAM;
    SeerXid xid = {
        .format_id = TNS_TPC_SESSIONLESS_FORMAT_ID,
        .gtrid = txn_id, .gtrid_len = (int)txn_id_len,
        .bqual = NULL,   .bqual_len = 0,
    };
    SeerStatus st = sessionless_switch(conn, TNS_TPC_TXN_START, &xid,
                                       SEER_TPC_BEGIN_RESUME | TNS_TPC_FLAGS_SESSIONLESS,
                                       timeout);
    if (st == SEER_OK)
        conn->sessionless_active = true;
    return st;
}

SeerStatus seer_txn_suspend_sessionless(SeerConn *conn)
{
    if (conn == NULL)
        return SEER_EPARAM;
    if (!conn->sessionless_active)
        return SEER_EPARAM;                    /* nothing to suspend */
    /* DETACH with the SESSIONLESS flag and no xid attached. */
    SeerStatus st = sessionless_switch(conn, TNS_TPC_TXN_DETACH, NULL,
                                       TNS_TPC_FLAGS_SESSIONLESS, 0);
    if (st == SEER_OK)
        conn->sessionless_active = false;
    return st;
}

/* ---- Advanced Queuing (AQ, #128) ---------------------------------------- */

/* Write an AQ value-with-length (write_value_with_length): a ub4 count, then the
 * bytes-with-length form when non-empty; NULL/empty -> just the zero count. */
static void aq_value_with_length(SeerWriter *w, const char *s, uint8_t fv)
{
    size_t n = (s != NULL) ? strlen(s) : 0;
    seer_enc_sb4(w, (uint32_t)n);
    if (n > 0)
        obj_append_chr(w, (const uint8_t *)s, n, fv);
}

/* Write a pointer+length pair: ptr byte (1 if present) then the sb4 length. The
 * value bytes themselves go in the data section. */
static void aq_ptr_len(SeerWriter *w, const char *s)
{
    size_t n = (s != NULL) ? strlen(s) : 0;
    seer_writer_u8(w, n > 0 ? 1 : 0);
    seer_enc_sb4(w, (uint32_t)n);
}

/* Write a two-length byte value (oracledb write_bytes_with_two_lengths): a ub4
 * count then the bytes-with-length form. Used for the queue name and TOID. */
static void aq_two_lengths(SeerWriter *w, const uint8_t *data, size_t n, uint8_t fv)
{
    seer_enc_sb4(w, (uint32_t)n);
    obj_append_chr(w, data, n, fv);
}

/* The message-property block (oracledb write_msg_props), shared by single and
 * array enqueue: priority/delay/expiration/correlation, the four agent keyword
 * extensions (AGENT_PROTOCOL carries a one-byte 0x00 binary), the trailing
 * user-property/cscn/dscn/flags, and (at fv >= 21.1) a shard id. */
static void aq_write_msg_props(SeerWriter *w, unsigned priority, unsigned delay,
                               int expiration, const char *correlation, uint8_t fv)
{
    seer_enc_sb4(w, priority);
    seer_enc_sb4(w, delay);
    seer_enc_sb4(w, (uint32_t)expiration);    /* -1 = forever                   */
    aq_value_with_length(w, correlation, fv);
    seer_enc_sb4(w, 0);                       /* number of attempts             */
    seer_enc_sb4(w, 0);                       /* exception queue (none)         */
    seer_enc_sb4(w, 0);                       /* message state                  */
    seer_enc_sb4(w, 0);                       /* enqueue time length            */
    seer_enc_sb4(w, 0);                       /* enq txn id (none)              */
    seer_enc_sb4(w, 4);                       /* number of extensions           */
    seer_writer_u8(w, 0x0e);                  /* oracledb's fixed extra byte    */
    seer_enc_sb4(w, 0); seer_enc_sb4(w, 0); seer_enc_sb4(w, TNS_AQ_EXT_KEYWORD_AGENT_NAME);
    seer_enc_sb4(w, 0); seer_enc_sb4(w, 0); seer_enc_sb4(w, TNS_AQ_EXT_KEYWORD_AGENT_ADDRESS);
    seer_enc_sb4(w, 0);
    { uint8_t z = 0; seer_enc_sb4(w, 1); obj_append_chr(w, &z, 1, fv); }
    seer_enc_sb4(w, TNS_AQ_EXT_KEYWORD_AGENT_PROTOCOL);
    seer_enc_sb4(w, 0); seer_enc_sb4(w, 0); seer_enc_sb4(w, TNS_AQ_EXT_KEYWORD_ORIGINAL_MSGID);
    seer_enc_sb4(w, 0);                       /* user property                  */
    seer_enc_sb4(w, 0);                       /* cscn                           */
    seer_enc_sb4(w, 0);                       /* dscn                           */
    seer_enc_sb4(w, 0);                       /* flags                          */
    if (fv >= TTC_FIELD_VERSION_21_1)
        seer_enc_sb4(w, 0xFFFFFFFFu);         /* shard id                       */
}

enum { AQ_PL_RAW = 0, AQ_PL_OBJECT = 1, AQ_PL_JSON = 2 };

/* Build an enqueue (TNS_FUNC_AQ_ENQ), mirroring oracledb AqEnqMessage: the given
 * message properties (priority/delay/expiration/correlation), no recipients,
 * ON_COMMIT visibility, persistent delivery. `payload_kind` selects the payload
 * flags (RAW / object / JSON); `toid16` is the payload type OID (RAW/JSON
 * sentinel or the object type's OID) and `payload` the already-framed body. */
static SeerStatus aq_build_enq(SeerConn *c, SeerWriter *w, const char *qname,
                               const uint8_t *payload, size_t plen,
                               unsigned priority, unsigned delay,
                               int expiration, const char *correlation,
                               int payload_kind, const uint8_t *toid16)
{
    uint8_t fv = c->field_version;
    size_t  qn = strlen(qname);
    if (!seer_writer_init(w, 256))
        return SEER_ENOMEM;
    seer_ttc_fun_header(c, w, TNS_FUNC_AQ_ENQ);
    seer_writer_u8(w, 1); seer_enc_sb4(w, (uint32_t)qn);   /* queue name ptr + len */

    aq_write_msg_props(w, priority, delay, expiration, correlation, fv);

    seer_writer_u8(w, 0); seer_enc_sb4(w, 0); /* recipients ptr + count         */
    seer_enc_sb4(w, TNS_AQ_ENQ_ON_COMMIT);    /* visibility                     */
    seer_writer_u8(w, 0); seer_enc_sb4(w, 0); /* relative message id ptr + len  */
    seer_enc_sb4(w, 0);                       /* sequence deviation             */
    seer_writer_u8(w, 1); seer_enc_sb4(w, 16);/* payload TOID ptr + len         */
    seer_enc_sb4(w, TNS_AQ_MESSAGE_VERSION);  /* message version (ub2)          */
    if (payload_kind == AQ_PL_OBJECT) {
        seer_writer_u8(w, 1); seer_writer_u8(w, 0);
        seer_enc_sb4(w, 0);                   /* payload 1, RAW 0, RAW len 0    */
    } else if (payload_kind == AQ_PL_JSON) {
        seer_writer_u8(w, 0); seer_writer_u8(w, 0);
        seer_enc_sb4(w, 0);                   /* payload 0, RAW 0, RAW len 0    */
    } else {
        seer_writer_u8(w, 0); seer_writer_u8(w, 1);
        seer_enc_sb4(w, (uint32_t)plen);      /* payload 0, RAW 1, RAW len      */
    }
    seer_writer_u8(w, 1); seer_enc_sb4(w, TNS_AQ_MESSAGE_ID_LENGTH); /* return msgid */
    seer_enc_sb4(w, 0);                       /* enqueue flags (persistent)     */
    seer_writer_u8(w, 0); seer_enc_sb4(w, 0); /* extensions 1 ptr + count       */
    seer_writer_u8(w, 0); seer_enc_sb4(w, 0); /* extensions 2 ptr + count       */
    seer_writer_u8(w, 0); seer_enc_sb4(w, 0); /* source sequence num ptr + len  */
    seer_writer_u8(w, 0); seer_enc_sb4(w, 0); /* max sequence num ptr + len     */
    seer_writer_u8(w, 0);                     /* output ack length              */
    seer_writer_u8(w, 0); seer_enc_sb4(w, 0); /* correlation ptr + len          */
    seer_writer_u8(w, 0); seer_enc_sb4(w, 0); /* sender name ptr + len          */
    seer_writer_u8(w, 0); seer_enc_sb4(w, 0); /* sender address ptr + len       */
    seer_writer_u8(w, 0);                     /* sender charset id ptr          */
    seer_writer_u8(w, 0);                     /* sender ncharset id ptr         */
    if (fv >= TTC_FIELD_VERSION_20_1)
        seer_writer_u8(w, payload_kind == AQ_PL_JSON ? 1 : 0);  /* JSON payload ptr */

    /* data section: queue name, the 16-byte payload TOID (RAW sentinel or the
     * object type's OID), then the payload (raw bytes / the object bind value). */
    obj_append_chr(w, (const uint8_t *)qname, qn, fv);
    seer_writer_bytes(w, toid16, 16);
    if (plen > 0)
        seer_writer_bytes(w, payload, plen);
    return seer_writer_ok(w) ? SEER_OK : SEER_ENOMEM;
}

/* Send a built AQ enqueue request and read the reply: TTI_RPA then the 16-byte
 * message id, or TTI_OER on error. Frees the writer. */
static SeerStatus aq_enq_send(SeerConn *conn, SeerWriter *w, uint8_t msgid[16])
{
    SeerStatus st = seer_ttc_send(conn, w->buf, w->len);
    seer_writer_free(w);
    if (st != SEER_OK)
        return st;
    uint8_t *resp = NULL; size_t rlen = 0;
    st = seer_ttc_recv(conn, &resp, &rlen);
    if (st != SEER_OK)
        return st;
    SeerReader r;
    seer_reader_init(&r, resp, rlen);
    r.sb4_chunks = conn->field_version >= TTC_FIELD_VERSION_12_1;
    SeerStmt  tmp = { .conn = conn };
    OerResult oer = { 0 };
    uint8_t   tok = seer_reader_u8(&r);
    if (tok == TTI_RPA) {
        const uint8_t *mid = seer_reader_bytes(&r, TNS_AQ_MESSAGE_ID_LENGTH);
        if (mid != NULL && msgid != NULL)
            memcpy(msgid, mid, TNS_AQ_MESSAGE_ID_LENGTH);
        st = seer_reader_ok(&r) ? SEER_OK : SEER_EPROTO;
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

SeerStatus seer_aq_enq_raw_opt(SeerConn *conn, const char *queue_name,
                               const uint8_t *payload, size_t payload_len,
                               const SeerAqEnqOptions *opt, uint8_t msgid[16])
{
    if (conn == NULL || queue_name == NULL)
        return SEER_EPARAM;
    if (conn->field_version < TTC_FIELD_VERSION_12_2)
        return SEER_ENOTIMPL;

    unsigned    pri = opt ? opt->priority : 0;
    unsigned    dly = opt ? opt->delay : 0;
    int         exp = opt ? opt->expiration : -1;
    const char *cor = opt ? opt->correlation : NULL;

    uint8_t raw_toid[16] = { 0 };
    raw_toid[15] = TNS_AQ_RAW_TOID_SENTINEL;

    SeerWriter w;
    SeerStatus st = aq_build_enq(conn, &w, queue_name, payload, payload_len,
                                 pri, dly, exp, cor, AQ_PL_RAW, raw_toid);
    if (st != SEER_OK) { seer_writer_free(&w); return st; }
    return aq_enq_send(conn, &w, msgid);
}

/* Enqueue a SQL object value (flat or nested-flattened, scalar leaf attributes
 * as text) to an object-payload queue. The payload TOID is the type's OID and the
 * body is the object bind value. 12c+. */
SeerStatus seer_aq_enq_object(SeerConn *conn, const char *queue_name,
                              const char *type_schema, const char *type_name,
                              const char *const *attr_values, int n_attrs,
                              uint8_t msgid[16])
{
    if (conn == NULL || queue_name == NULL || type_schema == NULL || type_name == NULL
        || (n_attrs > 0 && attr_values == NULL))
        return SEER_EPARAM;
    if (conn->field_version < TTC_FIELD_VERSION_12_2)
        return SEER_ENOTIMPL;

    uint8_t    oid[16];
    SeerWriter img;
    SeerStatus st = obj_build_image(conn, type_schema, type_name, attr_values,
                                    n_attrs, oid, &img);
    if (st != SEER_OK)
        return st;

    SeerWriter bv;
    if (!seer_writer_init(&bv, 64 + img.len)) { seer_writer_free(&img); return SEER_ENOMEM; }
    st = obj_encode_bind_value(&bv, oid, img.buf, img.len, conn->field_version);
    seer_writer_free(&img);
    if (st != SEER_OK) { seer_writer_free(&bv); return st; }

    SeerWriter w;
    st = aq_build_enq(conn, &w, queue_name, bv.buf, bv.len, 0, 0, -1, NULL,
                      AQ_PL_OBJECT, oid);
    seer_writer_free(&bv);
    if (st != SEER_OK) { seer_writer_free(&w); return st; }
    return aq_enq_send(conn, &w, msgid);
}

/* Enqueue a JSON document (given as JSON text) to a JSON-payload queue: the text
 * is parsed and encoded to OSON, then wrapped in the AQ JSON descriptor. Needs a
 * server with native JSON queues (fv >= 20.1; SEER_ENOTIMPL otherwise). */
SeerStatus seer_aq_enq_json(SeerConn *conn, const char *queue_name,
                            const char *json_text, uint8_t msgid[16])
{
    if (conn == NULL || queue_name == NULL || json_text == NULL)
        return SEER_EPARAM;
    if (conn->field_version < TTC_FIELD_VERSION_20_1)
        return SEER_ENOTIMPL;

    uint8_t *oson = NULL; size_t osonlen = 0;
    SeerStatus st = seer_json_to_oson(json_text, &oson, &osonlen);
    if (st != SEER_OK)
        return st;
    if (osonlen > 0xFFFF) { free(oson); return SEER_EPARAM; }

    /* payload: 18-byte JSON descriptor + ub2 OSON length + 22 zero bytes + the
     * OSON image (bytes-with-length framed). */
    static const uint8_t JSON_DESC[18] = {
        0x01, 0x28, 0x00, 0x26, 0x00, 0x04, 0x61, 0x08, 0x00, 0x00,
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    SeerWriter pw;
    if (!seer_writer_init(&pw, 64 + osonlen)) { free(oson); return SEER_ENOMEM; }
    seer_writer_bytes(&pw, JSON_DESC, sizeof JSON_DESC);
    seer_writer_u8(&pw, (uint8_t)(osonlen >> 8));
    seer_writer_u8(&pw, (uint8_t)(osonlen & 0xFF));
    for (int i = 0; i < 22; i++) seer_writer_u8(&pw, 0);
    obj_append_chr(&pw, oson, osonlen, conn->field_version);
    free(oson);
    if (!seer_writer_ok(&pw)) { seer_writer_free(&pw); return SEER_ENOMEM; }

    uint8_t json_toid[16] = { 0 };
    json_toid[15] = TNS_AQ_JSON_TOID_SENTINEL;

    SeerWriter w;
    st = aq_build_enq(conn, &w, queue_name, pw.buf, pw.len, 0, 0, -1, NULL,
                      AQ_PL_JSON, json_toid);
    seer_writer_free(&pw);
    if (st != SEER_OK) { seer_writer_free(&w); return st; }
    return aq_enq_send(conn, &w, msgid);
}

SeerStatus seer_aq_enq_raw(SeerConn *conn, const char *queue_name,
                           const uint8_t *payload, size_t payload_len,
                           uint8_t msgid[16])
{
    return seer_aq_enq_raw_opt(conn, queue_name, payload, payload_len, NULL, msgid);
}

/* Consume one length-prefixed AQ string (read_str_with_length): a ub4 count,
 * then the 0xFE-aware DALC bytes when non-zero. We only need to skip these in a
 * RAW message's properties and payload header. */
static SeerStatus aq_skip_str(SeerReader *r)
{
    int64_t n = seer_dec_sb4(r);
    if (n > 0) {
        uint8_t *b = NULL; size_t bl = 0;
        SeerStatus st = seer_dec_dalc(r, &b, &bl);
        free(b);
        return st;
    }
    return SEER_OK;
}

/* Build a RAW-payload dequeue (TNS_FUNC_AQ_DEQ): the given mode (REMOVE/BROWSE),
 * NEXT_MSG navigation, ON_COMMIT visibility, wait, and optional consumer name /
 * correlation filter. Mirrors oracledb AqDeqMessage. */
static SeerStatus aq_build_deq(SeerConn *c, SeerWriter *w, const char *qname,
                               uint32_t mode, uint32_t wait_seconds,
                               const char *correlation, const char *consumer,
                               const uint8_t *toid16)
{
    uint8_t fv = c->field_version;
    size_t  qn = strlen(qname);
    if (!seer_writer_init(w, 192))
        return SEER_ENOMEM;
    seer_ttc_fun_header(c, w, TNS_FUNC_AQ_DEQ);
    seer_writer_u8(w, 1); seer_enc_sb4(w, (uint32_t)qn);   /* queue name ptr + len */
    seer_writer_u8(w, 1); seer_writer_u8(w, 1);
    seer_writer_u8(w, 1); seer_writer_u8(w, 1);   /* msg props + recipient list ptrs */
    aq_ptr_len(w, consumer);                      /* consumer name                  */
    seer_enc_sb4(w, mode);                        /* mode (REMOVE / BROWSE)         */
    seer_enc_sb4(w, TNS_AQ_DEQ_FIRST_MSG);        /* navigation: each call is one-shot */
    seer_enc_sb4(w, TNS_AQ_DEQ_ON_COMMIT);        /* visibility                     */
    seer_enc_sb4(w, wait_seconds);                /* wait                           */
    seer_writer_u8(w, 0); seer_enc_sb4(w, 0);     /* selector msgid (none)          */
    aq_ptr_len(w, correlation);                   /* correlation filter             */
    seer_writer_u8(w, 1); seer_enc_sb4(w, 16);    /* payload TOID ptr + len         */
    seer_enc_sb4(w, TNS_AQ_MESSAGE_VERSION);      /* message version (ub2)          */
    seer_writer_u8(w, 1);                         /* payload ptr                    */
    seer_writer_u8(w, 1); seer_enc_sb4(w, TNS_AQ_MESSAGE_ID_LENGTH); /* return msgid */
    seer_enc_sb4(w, 0);                           /* dequeue flags (persistent)     */
    seer_writer_u8(w, 0); seer_enc_sb4(w, 0);     /* condition (none)               */
    seer_writer_u8(w, 0); seer_enc_sb4(w, 0);     /* extensions ptr + count         */
    if (fv >= TTC_FIELD_VERSION_20_1)
        seer_writer_u8(w, 0);                     /* JSON payload ptr               */
    if (fv >= TTC_FIELD_VERSION_21_1)
        seer_enc_sb4(w, 0xFFFFFFFFu);             /* shard id = -1                  */

    /* data section: queue name, optional consumer, optional correlation, then the
     * 16-byte RAW payload TOID (order mirrors AqDeqMessage). */
    obj_append_chr(w, (const uint8_t *)qname, qn, fv);
    if (consumer != NULL && consumer[0] != '\0')
        obj_append_chr(w, (const uint8_t *)consumer, strlen(consumer), fv);
    if (correlation != NULL && correlation[0] != '\0')
        obj_append_chr(w, (const uint8_t *)correlation, strlen(correlation), fv);
    seer_writer_bytes(w, toid16, 16);
    return seer_writer_ok(w) ? SEER_OK : SEER_ENOMEM;
}

/* Skip the message-property block in a dequeue reply (parse order mirrors
 * oracledb _parse_aq_msg_props); we keep only the payload and msgid. */
static SeerStatus aq_skip_msg_props(SeerReader *r, uint8_t fv)
{
    seer_dec_sb4(r); seer_dec_sb4(r); seer_dec_sb4(r);  /* priority/delay/expiration */
    aq_skip_str(r);                                     /* correlation               */
    seer_dec_sb4(r);                                    /* number of attempts        */
    aq_skip_str(r);                                     /* exception queue           */
    seer_dec_sb4(r);                                    /* state                     */
    if (seer_dec_sb4(r) > 0) {                          /* enqueue time present       */
        uint8_t *b = NULL; size_t bl = 0;
        seer_dec_dalc(r, &b, &bl); free(b);
    }
    aq_skip_str(r);                                     /* enqueue txn id            */
    int64_t next = seer_dec_sb4(r);                     /* number of extensions      */
    if (next > 0) {
        seer_reader_u8(r);                              /* skip_ub1                  */
        for (int64_t i = 0; i < next && seer_reader_ok(r); i++) {
            aq_skip_str(r); aq_skip_str(r); seer_dec_sb4(r);  /* text, binary, keyword */
        }
    }
    seer_dec_sb4(r); seer_dec_sb4(r); seer_dec_sb4(r); seer_dec_sb4(r); /* user/csn/dsn/flags */
    if (fv >= TTC_FIELD_VERSION_21_1)
        seer_dec_sb4(r);                                /* shard id                  */
    return seer_reader_ok(r) ? SEER_OK : SEER_EPROTO;
}

/* Send a dequeue request and consume the reply up to the payload: the empty-queue
 * OER (-> SEER_ENODATA), the RPA token, the body-length gate, the message
 * properties, and the recipient count. On SEER_OK *r is left positioned at the
 * payload; *resp must be freed by the caller in all cases. Frees the writer. */
static SeerStatus aq_deq_exchange(SeerConn *conn, SeerWriter *w, SeerReader *r,
                                  uint8_t **resp, size_t *rlen)
{
    *resp = NULL; *rlen = 0;
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
    uint8_t tok = seer_reader_u8(r);
    if (tok == TTI_OER) {                              /* empty queue / timeout / error */
        SeerStmt  tmp = { .conn = conn };
        OerResult oer = { 0 };
        parse_oer(r, &tmp, &oer);
        free_batch_errors(&tmp);
        return (oer.err_code == ORA_AQ_NO_MESSAGE || oer.err_code == ORA_AQ_DEQ_TIMEOUT)
                   ? SEER_ENODATA : SEER_EDB;
    }
    if (tok != TTI_RPA)
        return SEER_EPROTO;
    if (seer_dec_sb4(r) == 0)                          /* no message body */
        return SEER_ENODATA;
    if (aq_skip_msg_props(r, fv) != SEER_OK)
        return SEER_EPROTO;
    seer_dec_sb4(r);                                   /* number of recipients */
    return SEER_OK;
}

/* Read the RAW-form payload from a dequeue reply positioned at the payload: skip
 * toid/oid/snapshot/version, read image_length + flags, then the image whose
 * first 4 bytes are a header - the payload is image[4:image_length]. On SEER_OK
 * *out is malloc'd (NULL/0 for an empty payload); the caller frees it. For a JSON
 * queue this payload is itself an OSON image. */
static SeerStatus aq_read_payload(SeerReader *r, uint8_t **out, size_t *outlen)
{
    *out = NULL; *outlen = 0;
    aq_skip_str(r); aq_skip_str(r); aq_skip_str(r);   /* toid / oid / snapshot */
    seer_dec_sb4(r);                                   /* version (ub2) */
    int64_t image_length = seer_dec_sb4(r);
    seer_dec_sb4(r);                                   /* flags (ub2)   */
    if (image_length <= 4)
        return seer_reader_ok(r) ? SEER_OK : SEER_EPROTO;   /* empty payload */
    uint8_t *img = NULL; size_t imglen = 0;
    SeerStatus st = seer_dec_dalc(r, &img, &imglen);
    if (st != SEER_OK)
        return st;
    if ((size_t)image_length > imglen) { free(img); return SEER_EPROTO; }
    size_t plen = (size_t)image_length - 4;
    uint8_t *p = malloc(plen ? plen : 1);
    if (p == NULL) { free(img); return SEER_ENOMEM; }
    memcpy(p, img + 4, plen);
    free(img);
    *out = p; *outlen = plen;
    return SEER_OK;
}

SeerStatus seer_aq_deq_raw_opt(SeerConn *conn, const char *queue_name,
                               const SeerAqDeqOptions *opt, uint8_t **payload,
                               size_t *payload_len, uint8_t msgid[16])
{
    if (conn == NULL || queue_name == NULL)
        return SEER_EPARAM;
    if (conn->field_version < TTC_FIELD_VERSION_12_2)
        return SEER_ENOTIMPL;
    if (payload != NULL) *payload = NULL;
    if (payload_len != NULL) *payload_len = 0;

    uint32_t    mode = (opt && opt->browse) ? TNS_AQ_DEQ_BROWSE : TNS_AQ_DEQ_REMOVE;
    uint32_t    wait = opt ? opt->wait_seconds : 0;
    const char *cor  = opt ? opt->correlation : NULL;
    const char *cons = opt ? opt->consumer : NULL;
    uint8_t raw_toid[16] = { 0 };
    raw_toid[15] = TNS_AQ_RAW_TOID_SENTINEL;

    SeerWriter w;
    SeerStatus st = aq_build_deq(conn, &w, queue_name, mode, wait, cor, cons, raw_toid);
    if (st != SEER_OK) { seer_writer_free(&w); return st; }

    SeerReader r;
    uint8_t *resp = NULL; size_t rlen = 0;
    st = aq_deq_exchange(conn, &w, &r, &resp, &rlen);
    if (st != SEER_OK) { free(resp); return st; }

    uint8_t *pl = NULL; size_t pll = 0;
    st = aq_read_payload(&r, &pl, &pll);
    if (st == SEER_OK) {
        if (payload != NULL) { *payload = pl; if (payload_len) *payload_len = pll; }
        else free(pl);
        const uint8_t *mid = seer_reader_bytes(&r, TNS_AQ_MESSAGE_ID_LENGTH);
        if (mid != NULL && msgid != NULL)
            memcpy(msgid, mid, TNS_AQ_MESSAGE_ID_LENGTH);
        if (!seer_reader_ok(&r))
            st = SEER_EPROTO;
    }
    free(resp);
    return st;
}

SeerStatus seer_aq_deq_raw(SeerConn *conn, const char *queue_name,
                           uint32_t wait_seconds, uint8_t **payload,
                           size_t *payload_len, uint8_t msgid[16])
{
    SeerAqDeqOptions opt = { .wait_seconds = wait_seconds };
    return seer_aq_deq_raw_opt(conn, queue_name, &opt, payload, payload_len, msgid);
}

/* Dequeue an object-payload message (REMOVE, the given wait). The decoded object
 * is rendered to text ("v1, v2, ...", same as the object fetch path) into
 * *out_text (caller frees). SEER_ENODATA if no message was available. 12c+. */
SeerStatus seer_aq_deq_object(SeerConn *conn, const char *queue_name,
                              const char *type_schema, const char *type_name,
                              uint32_t wait_seconds, char **out_text, uint8_t msgid[16])
{
    if (conn == NULL || queue_name == NULL || type_schema == NULL || type_name == NULL)
        return SEER_EPARAM;
    if (conn->field_version < TTC_FIELD_VERSION_12_2)
        return SEER_ENOTIMPL;
    if (out_text != NULL) *out_text = NULL;

    uint8_t oid[16];
    SeerStatus st = obj_lookup_oid(conn, type_schema, type_name, oid);
    if (st != SEER_OK)
        return st;
    uint8_t *types = NULL;
    int      ntypes = 0, cap = 0;
    build_obj_layout(conn, type_schema, type_name, &types, NULL, &ntypes, &cap, 0);

    SeerWriter w;
    st = aq_build_deq(conn, &w, queue_name, TNS_AQ_DEQ_REMOVE, wait_seconds, NULL, NULL, oid);
    if (st != SEER_OK) { free(types); seer_writer_free(&w); return st; }

    SeerReader r;
    uint8_t *resp = NULL; size_t rlen = 0;
    st = aq_deq_exchange(conn, &w, &r, &resp, &rlen);
    if (st != SEER_OK) { free(types); free(resp); return st; }

    /* object payload: read the object image, decode it with the type's layout */
    uint8_t *img = NULL; size_t imglen = 0;
    st = read_object_image(&r, &img, &imglen);
    if (st == SEER_OK && img != NULL && ntypes > 0) {
        SeerCell cell = { 0 };
        if (decode_object_image(img, imglen, types, NULL, ntypes, &cell) == SEER_OK
            && out_text != NULL) {
            *out_text = cell.data;             /* transfer ownership */
            cell.data = NULL;
        }
        free(cell.data);
    }
    free(img);
    if (st == SEER_OK) {
        const uint8_t *mid = seer_reader_bytes(&r, TNS_AQ_MESSAGE_ID_LENGTH);
        if (mid != NULL && msgid != NULL)
            memcpy(msgid, mid, TNS_AQ_MESSAGE_ID_LENGTH);
        if (!seer_reader_ok(&r))
            st = SEER_EPROTO;
    }
    free(types);
    free(resp);
    return st;
}

/* Dequeue a JSON-payload message (REMOVE, the given wait). The OSON payload is
 * decoded to JSON text into *out_text (caller frees). SEER_ENODATA if no message
 * was available. Needs native JSON queues (fv >= 20.1). */
SeerStatus seer_aq_deq_json(SeerConn *conn, const char *queue_name,
                            uint32_t wait_seconds, char **out_text, uint8_t msgid[16])
{
    if (conn == NULL || queue_name == NULL)
        return SEER_EPARAM;
    if (conn->field_version < TTC_FIELD_VERSION_20_1)
        return SEER_ENOTIMPL;
    if (out_text != NULL) *out_text = NULL;

    uint8_t json_toid[16] = { 0 };
    json_toid[15] = TNS_AQ_JSON_TOID_SENTINEL;

    SeerWriter w;
    SeerStatus st = aq_build_deq(conn, &w, queue_name, TNS_AQ_DEQ_REMOVE,
                                 wait_seconds, NULL, NULL, json_toid);
    if (st != SEER_OK) { seer_writer_free(&w); return st; }

    SeerReader r;
    uint8_t *resp = NULL; size_t rlen = 0;
    st = aq_deq_exchange(conn, &w, &r, &resp, &rlen);
    if (st != SEER_OK) { free(resp); return st; }

    /* the payload is an OSON image; decode it to JSON text */
    uint8_t *oson = NULL; size_t osonlen = 0;
    st = aq_read_payload(&r, &oson, &osonlen);
    if (st == SEER_OK) {
        if (oson != NULL && out_text != NULL) {
            char *txt = NULL;
            if (seer_decode_oson(oson, osonlen, &txt) == SEER_OK)
                *out_text = txt;
            else
                free(txt);
        }
        free(oson);
        const uint8_t *mid = seer_reader_bytes(&r, TNS_AQ_MESSAGE_ID_LENGTH);
        if (mid != NULL && msgid != NULL)
            memcpy(msgid, mid, TNS_AQ_MESSAGE_ID_LENGTH);
        if (!seer_reader_ok(&r))
            st = SEER_EPROTO;
    }
    free(resp);
    return st;
}

/* Build a bulk RAW enqueue (TNS_FUNC_ARRAY_AQ): a ROW_HEADER (queue name + TOID +
 * version/flags) then one ROW_DATA per message (props + visibility + RAW length +
 * bytes), closed by a STATUS marker. Mirrors oracledb _aq_write_array_enq. */
static SeerStatus aq_build_array_enq_raw(SeerConn *c, SeerWriter *w, const char *qname,
                                         int count, const uint8_t *const *payloads,
                                         const size_t *lens)
{
    uint8_t fv = c->field_version;
    size_t  qn = strlen(qname);
    uint8_t raw_toid[16] = { 0 };
    raw_toid[15] = TNS_AQ_RAW_TOID_SENTINEL;
    if (!seer_writer_init(w, 256))
        return SEER_ENOMEM;
    seer_ttc_fun_header(c, w, TNS_FUNC_ARRAY_AQ);
    seer_writer_u8(w, 0); seer_enc_sb4(w, 0);         /* input params ptr + len (ENQ) */
    seer_enc_sb4(w, TNS_AQ_ARRAY_RETURN_MSGID);
    seer_writer_u8(w, 1); seer_writer_u8(w, 0);       /* output params ptr + len (ENQ) */
    seer_enc_sb4(w, TNS_AQ_ARRAY_ENQ);                /* operation */
    seer_writer_u8(w, 1);                             /* num iters ptr (ENQ) */
    if (fv >= TTC_FIELD_VERSION_21_1)
        seer_enc_sb4(w, 0xFFFF);                      /* shard id */
    seer_enc_sb4(w, (uint32_t)count);                 /* num iters */

    seer_enc_sb4(w, 0);                               /* relative msgid length */
    seer_writer_u8(w, TTI_RXH);                       /* ROW_HEADER */
    aq_two_lengths(w, (const uint8_t *)qname, qn, fv);
    seer_writer_bytes(w, raw_toid, 16);
    seer_enc_sb4(w, TNS_AQ_MESSAGE_VERSION);
    seer_enc_sb4(w, 0);                               /* flags */
    for (int i = 0; i < count; i++) {
        seer_writer_u8(w, TTI_RXD);                   /* ROW_DATA */
        seer_enc_sb4(w, 0);                           /* aqi flags */
        aq_write_msg_props(w, 0, 0, -1, NULL, fv);
        seer_enc_sb4(w, 0);                           /* num recipients */
        seer_enc_sb4(w, TNS_AQ_ENQ_ON_COMMIT);        /* visibility */
        seer_enc_sb4(w, 0);                           /* relative message id */
        seer_enc_sb4(w, 0);                           /* sequence deviation */
        seer_enc_sb4(w, (uint32_t)lens[i]);           /* RAW payload length */
        if (lens[i] > 0)
            seer_writer_bytes(w, payloads[i], lens[i]);
    }
    seer_writer_u8(w, TTI_STA);                       /* STATUS */
    return seer_writer_ok(w) ? SEER_OK : SEER_ENOMEM;
}

SeerStatus seer_aq_enq_raw_array(SeerConn *conn, const char *queue_name, int count,
                                 const uint8_t *const *payloads, const size_t *lens,
                                 uint8_t *msgids)
{
    if (conn == NULL || queue_name == NULL || count <= 0 || payloads == NULL || lens == NULL)
        return SEER_EPARAM;
    if (conn->field_version < TTC_FIELD_VERSION_12_2)
        return SEER_ENOTIMPL;

    SeerWriter w;
    SeerStatus st = aq_build_array_enq_raw(conn, &w, queue_name, count, payloads, lens);
    if (st != SEER_OK) { seer_writer_free(&w); return st; }
    st = seer_ttc_send(conn, w.buf, w.len);
    seer_writer_free(&w);
    if (st != SEER_OK)
        return st;

    uint8_t *resp = NULL; size_t rlen = 0;
    st = seer_ttc_recv(conn, &resp, &rlen);
    if (st != SEER_OK)
        return st;

    SeerReader r;
    seer_reader_init(&r, resp, rlen);
    r.sb4_chunks = conn->field_version >= TTC_FIELD_VERSION_12_1;
    SeerStmt  tmp = { .conn = conn };
    OerResult oer = { 0 };
    uint8_t   tok = seer_reader_u8(&r);
    if (tok == TTI_OER) { parse_oer(&r, &tmp, &oer); st = SEER_EDB; goto out; }
    if (tok != TTI_RPA) { st = SEER_EPROTO; goto out; }

    /* Response: ub4 iteration count, then per iteration props/recipients/payload
     * flags (0 for a bare enqueue ack), the returned message-id block, and two
     * trailing ub2s. The msgid block holds count*16 bytes. */
    int64_t iters = seer_dec_sb4(&r);
    for (int64_t it = 0; it < iters && seer_reader_ok(&r); it++) {
        if (seer_dec_sb4(&r) > 0) {                    /* props present */
            seer_reader_u8(&r);
            aq_skip_msg_props(&r, conn->field_version);
        }
        seer_dec_sb4(&r);                              /* num recipients */
        if (seer_dec_sb4(&r) > 0) {                    /* payload present */
            uint8_t *pp = NULL; size_t ppl = 0;
            aq_read_payload(&r, &pp, &ppl);
            free(pp);
        }
        if (seer_dec_sb4(&r) > 0) {                    /* msgid block (_aq_str) */
            uint8_t *mb = NULL; size_t mbl = 0;
            if (seer_dec_dalc(&r, &mb, &mbl) == SEER_OK && msgids != NULL) {
                size_t want = (size_t)count * 16;
                memcpy(msgids, mb, mbl < want ? mbl : want);
            }
            free(mb);
        }
        seer_dec_sb4(&r);                              /* extensions length */
        seer_dec_sb4(&r);                              /* output ack */
    }
    if (!seer_reader_ok(&r))
        st = SEER_EPROTO;

out:
    free_batch_errors(&tmp);
    free(resp);
    return st;
}

/* Build a bulk RAW dequeue (TNS_FUNC_ARRAY_AQ, op DEQ): `count` placeholder
 * dequeue blocks (REMOVE / NEXT_MSG / ON_COMMIT + wait, no filters). Mirrors
 * oracledb _aq_write_array_deq. */
static SeerStatus aq_build_array_deq_raw(SeerConn *c, SeerWriter *w, const char *qname,
                                         int count, uint32_t wait)
{
    uint8_t fv = c->field_version;
    size_t  qn = strlen(qname);
    uint8_t raw_toid[16] = { 0 };
    raw_toid[15] = TNS_AQ_RAW_TOID_SENTINEL;
    if (!seer_writer_init(w, 256))
        return SEER_ENOMEM;
    seer_ttc_fun_header(c, w, TNS_FUNC_ARRAY_AQ);
    seer_writer_u8(w, 1); seer_enc_sb4(w, (uint32_t)count); /* input params ptr + len (DEQ) */
    seer_enc_sb4(w, TNS_AQ_ARRAY_RETURN_MSGID);
    seer_writer_u8(w, 1); seer_writer_u8(w, 1);            /* output params (DEQ) */
    seer_enc_sb4(w, TNS_AQ_ARRAY_DEQ);                     /* operation */
    seer_writer_u8(w, 0);                                 /* num iters ptr (DEQ) */
    if (fv >= TTC_FIELD_VERSION_21_1)
        seer_enc_sb4(w, 0xFFFF);                          /* shard id */
    for (int i = 0; i < count; i++) {
        aq_two_lengths(w, (const uint8_t *)qname, qn, fv);
        aq_write_msg_props(w, 0, 0, -1, NULL, fv);
        seer_enc_sb4(w, 0);                               /* num recipients */
        seer_enc_sb4(w, 0);                               /* consumer name (none) */
        seer_enc_sb4(w, TNS_AQ_DEQ_REMOVE);               /* mode */
        seer_enc_sb4(w, TNS_AQ_DEQ_NEXT_MSG);             /* navigation (sequential) */
        seer_enc_sb4(w, TNS_AQ_DEQ_ON_COMMIT);            /* visibility */
        seer_enc_sb4(w, wait);                            /* wait */
        seer_enc_sb4(w, 0);                               /* selector msgid (none) */
        seer_enc_sb4(w, 0);                               /* correlation (none) */
        seer_enc_sb4(w, 0);                               /* condition (none) */
        seer_enc_sb4(w, 0);                               /* extensions */
        seer_enc_sb4(w, 0);                               /* relative message id */
        seer_enc_sb4(w, 0);                               /* sequence deviation */
        aq_two_lengths(w, raw_toid, 16, fv);              /* payload TOID */
        seer_enc_sb4(w, TNS_AQ_MESSAGE_VERSION);
        seer_enc_sb4(w, 0);                               /* payload length */
        seer_enc_sb4(w, 0);                               /* raw payload length */
        seer_enc_sb4(w, 0);
        seer_enc_sb4(w, 0);                               /* flags */
        seer_enc_sb4(w, 0);                               /* extensions length */
        seer_enc_sb4(w, 0);                               /* source sequence length */
    }
    return seer_writer_ok(w) ? SEER_OK : SEER_ENOMEM;
}

SeerStatus seer_aq_deq_raw_array(SeerConn *conn, const char *queue_name, int max_count,
                                 uint32_t wait_seconds, uint8_t **payloads, size_t *lens,
                                 int *out_count)
{
    if (conn == NULL || queue_name == NULL || max_count <= 0
        || payloads == NULL || lens == NULL || out_count == NULL)
        return SEER_EPARAM;
    if (conn->field_version < TTC_FIELD_VERSION_12_2)
        return SEER_ENOTIMPL;
    *out_count = 0;
    for (int i = 0; i < max_count; i++) { payloads[i] = NULL; lens[i] = 0; }

    SeerWriter w;
    SeerStatus st = aq_build_array_deq_raw(conn, &w, queue_name, max_count, wait_seconds);
    if (st != SEER_OK) { seer_writer_free(&w); return st; }
    st = seer_ttc_send(conn, w.buf, w.len);
    seer_writer_free(&w);
    if (st != SEER_OK)
        return st;

    uint8_t *resp = NULL; size_t rlen = 0;
    st = seer_ttc_recv(conn, &resp, &rlen);
    if (st != SEER_OK)
        return st;

    uint8_t fv = conn->field_version;
    SeerReader r;
    seer_reader_init(&r, resp, rlen);
    r.sb4_chunks = fv >= TTC_FIELD_VERSION_12_1;
    SeerStmt  tmp = { .conn = conn };
    OerResult oer = { 0 };
    uint8_t   tok = seer_reader_u8(&r);
    if (tok == TTI_OER) {                                 /* empty queue -> 0 messages */
        parse_oer(&r, &tmp, &oer);
        st = (oer.err_code == ORA_AQ_NO_MESSAGE || oer.err_code == ORA_AQ_DEQ_TIMEOUT)
                 ? SEER_OK : SEER_EDB;
        goto out;
    }
    if (tok != TTI_RPA) { st = SEER_EPROTO; goto out; }

    int64_t iters = seer_dec_sb4(&r);
    if (iters < 0) iters = 0;
    if (iters > max_count) iters = max_count;             /* defensive clamp */
    for (int64_t it = 0; it < iters && seer_reader_ok(&r); it++) {
        if (seer_dec_sb4(&r) > 0) {                       /* props present */
            seer_reader_u8(&r);
            aq_skip_msg_props(&r, fv);
        }
        seer_dec_sb4(&r);                                 /* num recipients */
        if (seer_dec_sb4(&r) > 0) {                       /* payload present */
            uint8_t *pp = NULL; size_t ppl = 0;
            if (aq_read_payload(&r, &pp, &ppl) == SEER_OK) {
                payloads[it] = pp;
                lens[it] = ppl;
            } else {
                free(pp);
            }
        }
        if (seer_dec_sb4(&r) > 0) {                       /* msgid block (_aq_str) */
            uint8_t *mb = NULL; size_t mbl = 0;
            seer_dec_dalc(&r, &mb, &mbl);
            free(mb);
        }
        seer_dec_sb4(&r);                                 /* extensions length */
        seer_dec_sb4(&r);                                 /* output ack */
        *out_count = (int)(it + 1);
    }
    if (!seer_reader_ok(&r)) {
        for (int i = 0; i < *out_count; i++) { free(payloads[i]); payloads[i] = NULL; lens[i] = 0; }
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
SeerStatus seer_test_parse_execute_response(const uint8_t *buf, size_t len,
                                            uint8_t fv, int *out_ncols,
                                            int64_t *out_err)
{
    struct SeerConn conn;
    memset(&conn, 0, sizeof conn);
    conn.field_version = fv;
    SeerStmt *stmt = calloc(1, sizeof *stmt);
    if (stmt == NULL)
        return SEER_ENOMEM;
    stmt->conn = &conn;
    stmt->cur  = -1;
    OerResult oer = { 0 };
    SeerStatus st = parse_response(stmt, buf, len, /*expect_dcb=*/true, &oer);
    if (out_ncols) *out_ncols = stmt->ncols;
    if (out_err)   *out_err   = oer.err_code;
    seer_stmt_close(stmt);
    free(conn.last_error);   /* the OER message; normally freed by seer_disconnect */
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
        ORA_TYPE_VARCHAR, ORA_TYPE_NUMBER,   ORA_TYPE_DATE,        ORA_TYPE_CHAR,
        ORA_TYPE_TIMESTAMP, ORA_TYPE_RAW,    ORA_TYPE_INTERVAL_DS, ORA_TYPE_BDOUBLE,
    };
    SeerCell cell;

    /* object: attribute count + types derived from the leading bytes */
    uint8_t attrs[8];
    int na = n ? (int)(img[0] & 7) : 0;
    for (int i = 0; i < na; i++)
        attrs[i] = types[((size_t)(i + 1) < n ? img[i + 1] : (uint8_t)i) % 8];
    cell = (SeerCell){ 0 };
    decode_object_image(img, n, attrs, NULL, na, &cell);
    free(cell.data);

    /* collection: element type from a byte */
    cell = (SeerCell){ 0 };
    decode_collection_image(img, n, types[(n ? img[0] : 0) % 8], &cell);
    free(cell.data);

    /* vector */
    cell = (SeerCell){ 0 };
    decode_vector_image(img, n, &cell);
    free(cell.data);
}
#endif

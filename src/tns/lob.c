/*
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "lob.h"

#include "conn.h"
#include "log.h"
#include "marshal.h"
#include "reader.h"
#include "tns_consts.h"
#include "ttc.h"
#include "types.h"
#include "writer.h"

#include <stdlib.h>
#include <string.h>

/* Reading 0xFFFFFFFF as the "all" amount makes XE 11g stop responding; 1 GiB
 * is well past any LOB we expect and stays inside signed-int32. */
#define LOB_READ_AMOUNT 0x40000000u

/* BFILE FILE_OPEN open mode: read-only (PROTOCOL.md §19.8 trailer 0x0B). */
#define BFILE_MODE_READONLY 0x0B

/* Build a TTI_LOBOPS request (PROTOCOL.md §14.1). One field layout serves every
 * opcode; the caller varies:
 *   op            - the operation (READ / FILE_OPEN / FILE_CLOSE / ...).
 *   prefixed      - send the locator as a ub2-length-prefixed field and declare
 *                   source_locator_length as loclen+2 (temp LOBs and BFILEs);
 *                   otherwise the raw locator with the bare length (persistent
 *                   reads, which regress if switched to the prefixed form).
 *   source_offset - the 1-based read offset (1 for READ, 0 for the FILE_* ops).
 *   send_amount   - emit the amount-pointer flag and a trailing sb4 `amount`
 *                   (the read ceiling for READ, the open mode for FILE_OPEN);
 *                   FILE_CLOSE clears it and sends neither. */
static SeerStatus build_lobop(SeerConn *c, const uint8_t *loc, size_t loclen, uint32_t op,
                              bool prefixed, uint32_t source_offset, bool send_amount,
                              uint32_t amount, SeerWriter *w)
{
  if (!seer_writer_init(w, loclen + 64))
    return SEER_ENOMEM;

  seer_ttc_fun_header(c, w, TTI_LOBOPS);

  seer_writer_u8(w, 1);                                        /* source pointer present     */
  seer_enc_sb4(w, (uint32_t)(prefixed ? loclen + 2 : loclen)); /* src loc len */
  seer_writer_u8(w, 0);                                        /* dest pointer absent        */
  seer_enc_sb4(w, 0);                                          /* dest length                */
  seer_enc_sb4(w, 0);                                          /* short source offset        */
  seer_enc_sb4(w, 0);                                          /* short dest offset          */
  seer_writer_u8(w, 0);                                        /* charset pointer absent     */
  seer_writer_u8(w, 0);                                        /* short amount absent        */
  seer_writer_u8(w, 0);                                        /* null lob pointer absent    */
  seer_enc_sb4(w, op);                                         /* operation                  */
  seer_writer_u8(w, 0);                                        /* scn array pointer absent   */
  seer_writer_u8(w, 0);                                        /* scn array length           */
  seer_enc_sb4(w, source_offset);                              /* source offset (1-based)    */
  seer_enc_sb4(w, 0);                                          /* dest offset                */
  seer_writer_u8(w, send_amount ? 1 : 0);                      /* amount pointer present     */
  for (int i = 0; i < 6; i++)                                  /* three reserved array slots */
    seer_writer_u8(w, 0);
  if (prefixed)
    seer_writer_u16(w, (uint16_t)loclen); /* ub2 length prefix       */
  seer_writer_bytes(w, loc, loclen);      /* locator                    */
  if (send_amount)
    seer_enc_sb4(w, amount); /* read amount / open mode    */

  if (!seer_writer_ok(w)) {
    seer_writer_free(w);
    return SEER_ENOMEM;
  }
  return SEER_OK;
}

/* 12c+ length-prefixes each chunk inside a 0xFE run with an sb4 (length byte +
 * magnitude); 11g writes a bare ub1. */
static bool sb4_lob_chunks(const SeerConn *c)
{
  return c->field_version >= TTC_FIELD_VERSION_12_1;
}

/* Accumulate the leading TTI_LOB content chunk(s) of a LOBOPS reply into a
 * fresh buffer; stop at the first non-LOB token (the RPA/OER trailer). The
 * 0xFE marker introduces a chunked run whose per-chunk lengths are sb4-prefixed
 * on 12c+ (`sb4_chunks`) and a bare ub1 on 11g, ended by a zero length. On
 * SEER_OK *out is a malloc'd buffer of *outlen bytes (caller frees). A chunk
 * or length that runs past the end of the reply is SEER_EPROTO: the content
 * is incomplete, and handing back what arrived would be a silently truncated
 * LOB (seerdb a618d4c). */
static SeerStatus accumulate_lob_content(const uint8_t *resp, size_t rlen, bool sb4_chunks,
                                         uint8_t **out, size_t *outlen)
{
  SeerReader r;
  seer_reader_init(&r, resp, rlen);
  SeerWriter acc;
  if (!seer_writer_init(&acc, 256))
    return SEER_ENOMEM;

  bool truncated = false;
  while (!truncated && seer_reader_remaining(&r) > 0) {
    if (r.buf[r.pos] != TTI_LOB)
      break;
    (void)seer_reader_u8(&r); /* TTI_LOB token */
    uint8_t len = seer_reader_u8(&r);
    if (!seer_reader_ok(&r)) {
      truncated = true;
      break;
    }
    if (len == 0)
      continue;
    if (len == 0xFE) {
      for (;;) {
        int64_t clen = sb4_chunks ? seer_dec_sb4(&r) : (int64_t)seer_reader_u8(&r);
        if (!seer_reader_ok(&r)) {
          truncated = true;
          break;
        }
        if (clen <= 0)
          break; /* the run's terminator */
        const uint8_t *p = seer_reader_bytes(&r, (size_t)clen);
        if (p == NULL) {
          truncated = true;
          break;
        }
        seer_writer_bytes(&acc, p, (size_t)clen);
      }
    } else {
      const uint8_t *p = seer_reader_bytes(&r, len);
      if (p == NULL) {
        truncated = true;
        break;
      }
      seer_writer_bytes(&acc, p, len);
    }
  }
  if (truncated) {
    seer_log(SEER_LOG_ERROR, "lob: content runs past the end of the reply (%zu bytes)", rlen);
    seer_writer_free(&acc);
    return SEER_EPROTO;
  }

  if (!seer_writer_ok(&acc)) {
    seer_writer_free(&acc);
    return SEER_ENOMEM;
  }
  *out = acc.buf;
  *outlen = acc.len;
  return SEER_OK;
}

/* Send a prepared LOBOPS request and receive the raw reply (caller frees
 * *resp). */
static SeerStatus lobop_round_trip(SeerConn *conn, SeerWriter *req, uint8_t **resp, size_t *rlen)
{
  SeerStatus st = seer_ttc_send(conn, req->buf, req->len);
  seer_writer_free(req);
  if (st != SEER_OK)
    return st;
  return seer_ttc_recv(conn, resp, rlen);
}

SeerStatus seer_lob_read(SeerConn *conn, const uint8_t *locator, size_t loclen, uint8_t **out,
                         size_t *outlen)
{
  *out = NULL;
  *outlen = 0;
  if (conn == NULL || locator == NULL || loclen == 0)
    return SEER_EPARAM;

  SeerWriter req;
  SeerStatus st =
      build_lobop(conn, locator, loclen, LOB_OP_READ, false, 1, true, LOB_READ_AMOUNT, &req);
  if (st != SEER_OK)
    return st;

  uint8_t *resp = NULL;
  size_t rlen = 0;
  st = lobop_round_trip(conn, &req, &resp, &rlen);
  if (st != SEER_OK)
    return st;

  st = accumulate_lob_content(resp, rlen, sb4_lob_chunks(conn), out, outlen);
  free(resp);
  if (st == SEER_OK)
    seer_log(SEER_LOG_DEBUG, "lob: read %zu bytes", *outlen);
  return st;
}

SeerStatus seer_bfile_read(SeerConn *conn, const uint8_t *locator, size_t loclen, uint8_t **out,
                           size_t *outlen)
{
  *out = NULL;
  *outlen = 0;
  if (conn == NULL || locator == NULL || loclen == 0)
    return SEER_EPARAM;

  /* The locator captured from RXD carries a leading ub2 inner-length
   * (== loclen-2); strip it so the encoder's own ub2 prefix isn't doubled
   * (PROTOCOL.md §19.8). */
  if (loclen >= 2 && (size_t)((locator[0] << 8) | locator[1]) == loclen - 2) {
    locator += 2;
    loclen -= 2;
  }

  /* FILE_OPEN: open the external file read-only. The reply RPA returns an
   * updated, open-flagged locator that READ and FILE_CLOSE must use; a READ
   * against the original (unopened) locator returns empty bytes. */
  SeerWriter req;
  SeerStatus st = build_lobop(conn, locator, loclen, LOB_OP_FILE_OPEN, true, 0, true,
                              BFILE_MODE_READONLY, &req);
  if (st != SEER_OK)
    return st;
  uint8_t *resp = NULL;
  size_t rlen = 0;
  st = lobop_round_trip(conn, &req, &resp, &rlen);
  if (st != SEER_OK)
    return st;

  /* Reply: TTI_RPA, then a ub2 length and the opened locator. Anything else
   * (e.g. an OER for ORA-22288 on a bad directory/file) means FILE_OPEN
   * failed - nothing was opened, so no FILE_CLOSE is owed. */
  SeerReader r;
  seer_reader_init(&r, resp, rlen);
  if (seer_reader_u8(&r) != TTI_RPA) {
    seer_log(SEER_LOG_WARN, "bfile: FILE_OPEN not acknowledged");
    free(resp);
    return SEER_EPROTO;
  }
  uint16_t open_len = seer_reader_u16(&r);
  const uint8_t *open_ptr = seer_reader_bytes(&r, open_len);
  if (open_ptr == NULL || open_len == 0) {
    free(resp);
    return SEER_EPROTO;
  }
  uint8_t *opened = malloc(open_len);
  if (opened == NULL) {
    free(resp);
    return SEER_ENOMEM;
  }
  memcpy(opened, open_ptr, open_len);
  free(resp);

  /* READ the opened (ub2-prefixed) locator. */
  st = build_lobop(conn, opened, open_len, LOB_OP_READ, true, 1, true, LOB_READ_AMOUNT, &req);
  if (st == SEER_OK) {
    resp = NULL;
    rlen = 0;
    st = lobop_round_trip(conn, &req, &resp, &rlen);
    if (st == SEER_OK) {
      st = accumulate_lob_content(resp, rlen, sb4_lob_chunks(conn), out, outlen);
      free(resp);
    }
  }

  /* FILE_CLOSE unconditionally so an opened file is always released, even if
   * the READ failed. Its own failure can't undo a good read. */
  SeerWriter cls;
  if (build_lobop(conn, opened, open_len, LOB_OP_FILE_CLOSE, true, 0, false, 0, &cls) == SEER_OK) {
    uint8_t *cresp = NULL;
    size_t clen = 0;
    if (lobop_round_trip(conn, &cls, &cresp, &clen) == SEER_OK)
      free(cresp);
  }
  free(opened);

  if (st == SEER_OK)
    seer_log(SEER_LOG_DEBUG, "bfile: read %zu bytes", *outlen);
  return st;
}

SeerStatus seer_lob_create_temp(SeerConn *conn, bool blob, uint8_t **locator, size_t *loclen)
{
  *locator = NULL;
  *loclen = 0;
  if (conn == NULL)
    return SEER_EPARAM;
  if (conn->field_version < TTC_FIELD_VERSION_12_1)
    return SEER_ENOTIMPL; /* 11g drops the connection on a CREATE_TEMP */

  /* CREATE_TEMP carries no locator; its body is a fixed field block with the
   * LOB kind and charset spliced in (PROTOCOL.md §14.2): the shared head, the
   * charset form (CLOB `01 01`, BLOB none), `01` + the LOB type, 47 zero bytes,
   * then the charset id. */
  static const uint8_t HEAD[16] = {0x01, 0x01, 0x28, 0x00, 0x01, 0x0a, 0x00, 0x00,
                                   0x01, 0x00, 0x01, 0x02, 0x01, 0x10, 0x00, 0x00};
  SeerWriter req;
  if (!seer_writer_init(&req, 128))
    return SEER_ENOMEM;
  seer_ttc_fun_header(conn, &req, TTI_LOBOPS);
  seer_writer_bytes(&req, HEAD, sizeof HEAD);
  if (!blob) {
    seer_writer_u8(&req, 0x01);
    seer_writer_u8(&req, 0x01); /* implicit (database) charset form */
  } else {
    seer_writer_u8(&req, 0x00);
  }
  seer_writer_u8(&req, 0x01);
  seer_writer_u8(&req, blob ? ORA_TYPE_BLOB : ORA_TYPE_CLOB);
  for (int i = 0; i < 47; i++)
    seer_writer_u8(&req, 0);
  seer_enc_sb4(&req, 873); /* AL32UTF8, for BLOB too */
  if (!seer_writer_ok(&req)) {
    seer_writer_free(&req);
    return SEER_ENOMEM;
  }

  uint8_t *resp = NULL;
  size_t rlen = 0;
  SeerStatus st = lobop_round_trip(conn, &req, &resp, &rlen);
  if (st != SEER_OK)
    return st;

  /* Reply: TTI_RPA, a ub2 length and the new locator. */
  SeerReader r;
  seer_reader_init(&r, resp, rlen);
  if (seer_reader_u8(&r) != TTI_RPA) {
    seer_log(SEER_LOG_ERROR, "lob: CREATE_TEMP refused");
    free(resp);
    return SEER_EDB;
  }
  uint16_t len = seer_reader_u16(&r);
  const uint8_t *p = seer_reader_bytes(&r, len);
  if (p == NULL || len == 0) {
    free(resp);
    return SEER_EPROTO;
  }
  uint8_t *loc = malloc(len);
  if (loc == NULL) {
    free(resp);
    return SEER_ENOMEM;
  }
  memcpy(loc, p, len);
  free(resp);
  *locator = loc;
  *loclen = len;
  return SEER_OK;
}

SeerStatus seer_lob_write(SeerConn *conn, const uint8_t *locator, size_t loclen,
                          const uint8_t *data, size_t n, uint8_t **resp, size_t *rlen)
{
  *resp = NULL;
  *rlen = 0;
  if (conn == NULL || locator == NULL || loclen == 0 || (data == NULL && n > 0))
    return SEER_EPARAM;

  /* The READ field block with the WRITE op, the temp locator ub2-prefixed, no
   * amount, and the data appended behind a 0x0E marker as chunked bytes: a ub1
   * length for up to 0xFC bytes, else 0xFE + sb4-prefixed chunks of at most
   * 0x7FFF bytes and a zero-length terminator (PROTOCOL.md §14.2). */
  SeerWriter req;
  SeerStatus st = build_lobop(conn, locator, loclen, LOB_OP_WRITE, true, 1, false, 0, &req);
  if (st != SEER_OK)
    return st;
  seer_writer_u8(&req, 0x0E);
  if (n <= 0xFC) {
    seer_writer_u8(&req, (uint8_t)n);
    seer_writer_bytes(&req, data, n);
  } else {
    seer_writer_u8(&req, 0xFE);
    for (size_t i = 0; i < n; i += 0x7FFF) {
      size_t chunk = n - i < 0x7FFF ? n - i : 0x7FFF;
      seer_enc_sb4(&req, (uint32_t)chunk);
      seer_writer_bytes(&req, data + i, chunk);
    }
    seer_enc_sb4(&req, 0);
  }
  if (!seer_writer_ok(&req)) {
    seer_writer_free(&req);
    return SEER_ENOMEM;
  }
  return lobop_round_trip(conn, &req, resp, rlen);
}

SeerStatus seer_test_lob_content(const uint8_t *resp, size_t rlen, bool sb4_chunks, uint8_t **out,
                                 size_t *outlen)
{
  return accumulate_lob_content(resp, rlen, sb4_chunks, out, outlen);
}

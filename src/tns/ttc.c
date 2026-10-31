/*
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "ttc.h"

#include "ano.h"
#include "auth.h"
#include "conn.h"
#include "log.h"
#include "marshal.h"
#include "netcompat.h" /* gethostname(): <unistd.h> on POSIX, Winsock on Windows */
#include "packet.h"
#include "reader.h"
#include "tns_consts.h"
#include "writer.h"

#include <openssl/crypto.h> /* OPENSSL_cleanse */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#ifndef _WIN32
#include <pwd.h>
#endif

/* ---------------------------------------------------------- static messages */

/* TTI_PRO request: token, version vector 6..0 (0-terminated), driver name. */
static const uint8_t PRO_MSG[] = {
    TTI_PRO, 6, 5, 4, 3, 2, 1, 0, 'p', 'y', 't', 'h', 'o', 'n', 0,
};

/* TTI_DTY capability arrays for field version 6 (11.2), byte-identical to the
 * reference client (see PROTOCOL.md §4.2). compile_caps[7] is the field
 * version. */
static const uint8_t COMPILE_CAPS[] = {
    0x06, 0x01, 0x00, 0x00, 0x6a, 0x01, 0x01, 0x06, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x00, 0x29, 0x90, 0x03, 0x07, 0x03, 0x00, 0x01, 0x00, 0x4f, 0x01, 0x37,
    0x04, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x06, 0x00, 0x01, 0x01,
};
static const uint8_t RUNTIME_CAPS[] = {
    0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

/* 12c+ capability arrays (the python-oracledb 21.1 base vector; the contents are
 * stable across 12c+ releases, only CCAP_FIELD_VERSION[7] differs, patched per
 * negotiated version). 53-byte compile / 11-byte runtime. */
static const uint8_t COMPILE_CAPS_12C[] = {
    0x06, 0x00, 0x00, 0x00, 0xea, 0x18, 0x00, 0x15, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x29, 0x90, 0x03, 0x07, 0x03, 0x00, 0x01, 0x00, 0xcf, 0x00, 0x00, 0x04, 0x01,
    0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x0c, 0x20, 0x00, 0xb8, 0x00, 0x08, 0x44, 0x00,
    0x05, 0x00, 0x3e, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
};
static const uint8_t RUNTIME_CAPS_12C[] = {
    0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00,
};

/* The 12c+ datatype table is a flat list of UB2 (type, conv, repr) entries.
 * conv defaults to type and repr to 1, except the overrides below (repr 10 =
 * Oracle-native: NUMBER/DATE families). Ported from python-oracledb 4.0.1's
 * DATA_TYPES (verified by seerdb against a 21c capture). */
static const uint16_t DTY_12C_TYPES[] = {
    1,   2,   8,   12,  23,  24,  25,  26,  27,  28,  29,  30,  31,  32,  33,  10,  11,  40,  41,
    117, 120, 290, 291, 292, 293, 294, 298, 299, 300, 301, 302, 303, 304, 305, 306, 307, 308, 309,
    310, 311, 312, 313, 315, 316, 317, 318, 319, 320, 321, 322, 323, 327, 328, 329, 331, 333, 334,
    335, 336, 337, 338, 339, 340, 341, 342, 343, 344, 345, 346, 348, 349, 354, 355, 359, 363, 380,
    381, 382, 383, 384, 385, 386, 387, 388, 389, 390, 391, 393, 394, 395, 396, 397, 398, 399, 400,
    401, 404, 405, 406, 407, 413, 414, 415, 416, 417, 418, 419, 420, 421, 422, 423, 424, 425, 426,
    427, 429, 430, 431, 432, 433, 449, 450, 454, 455, 456, 457, 458, 459, 460, 461, 462, 463, 466,
    467, 468, 469, 470, 471, 472, 473, 474, 475, 476, 477, 478, 479, 480, 481, 482, 483, 484, 485,
    486, 490, 491, 492, 493, 494, 495, 496, 498, 499, 500, 501, 502, 509, 510, 513, 514, 516, 517,
    518, 519, 520, 521, 522, 523, 524, 525, 526, 527, 528, 529, 530, 531, 532, 533, 534, 535, 536,
    537, 538, 539, 540, 541, 542, 543, 560, 565, 572, 573, 574, 575, 576, 578, 563, 564, 579, 580,
    581, 582, 583, 584, 585, 3,   4,   5,   6,   7,   9,   15,  39,  68,  91,  94,  95,  96,  97,
    100, 101, 102, 104, 106, 108, 109, 110, 111, 112, 113, 114, 115, 116, 119, 198, 146, 152, 153,
    154, 155, 156, 172, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 195, 196,
    197, 208, 231, 232, 233, 241, 252, 590, 591, 592, 613, 614, 615, 616, 611, 612, 593, 594, 595,
    596, 597, 598, 599, 600, 601, 602, 603, 604, 605, 622, 623, 624, 625, 626, 627, 628, 629, 630,
    631, 632, 637, 638, 636, 639, 663, 640, 652, 646, 647, 127, 660, 661, 665, 669, 670,
};
/* (type, conv, repr) overrides; everything else is (type, type, 1). */
static const uint16_t DTY_12C_OVERRIDES[][3] = {
    {2, 2, 10},    {12, 12, 10},  {27, 27, 10},  {3, 2, 10},    {4, 2, 10},    {5, 1, 1},
    {6, 2, 10},    {7, 2, 10},    {9, 1, 1},     {15, 1, 1},    {68, 2, 10},   {91, 2, 10},
    {94, 1, 1},    {95, 23, 1},   {97, 96, 1},   {104, 11, 1},  {108, 109, 1}, {110, 111, 1},
    {116, 102, 1}, {152, 2, 10},  {153, 2, 10},  {154, 2, 10},  {155, 1, 1},   {156, 12, 10},
    {172, 2, 10},  {184, 12, 10}, {195, 112, 1}, {196, 113, 1}, {197, 114, 1}, {232, 231, 1},
    {241, 109, 1},
};

/* Append the 12c+ datatype table (uniform UB2 entries + UB2 0 terminator). */
static void write_dty_12c_table(SeerWriter *w)
{
  for (size_t i = 0; i < sizeof DTY_12C_TYPES / sizeof DTY_12C_TYPES[0]; i++) {
    uint16_t type = DTY_12C_TYPES[i], conv = type, repr = 1;
    for (size_t j = 0; j < sizeof DTY_12C_OVERRIDES / sizeof DTY_12C_OVERRIDES[0]; j++)
      if (DTY_12C_OVERRIDES[j][0] == type) {
        conv = DTY_12C_OVERRIDES[j][1];
        repr = DTY_12C_OVERRIDES[j][2];
        break;
      }
    seer_writer_u16(w, type);
    seer_writer_u16(w, conv);
    seer_writer_u16(w, repr);
    seer_writer_u16(w, 0);
  }
  seer_writer_u16(w, 0);
}

/* TTI_DTY data-type override table (the identity map for ids 1..245 is
 * generated; this is the override tail), terminated by a 0 type. */
static const uint8_t TYPE_OVERRIDES[] = {
    2,   2,  10,  0,   3,   2,  10,  0,   4,   2,  10,  0, 5,   1,  1,   0,   6,   2,  10,  0,
    7,   2,  10,  0,   9,   1,  1,   0,   12,  12, 10,  0, 13,  0,  14,  0,   15,  23, 1,   0,
    16,  0,  17,  0,   18,  0,  19,  0,   20,  0,  21,  0, 22,  0,  39,  120, 1,   0,  58,  0,
    68,  2,  10,  0,   69,  0,  70,  0,   74,  0,  6,   0, 91,  2,  10,  0,   94,  1,  1,   0,
    95,  23, 1,   0,   96,  96, 1,   0,   97,  96, 1,   0, 104, 11, 1,   0,   105, 0,  108, 109,
    1,   0,  110, 111, 1,   0,  116, 102, 1,   0,  118, 0, 119, 0,  121, 0,   122, 0,  123, 0,
    136, 0,  146, 146, 1,   0,  147, 0,   152, 2,  10,  0, 153, 2,  10,  0,   154, 2,  10,  0,
    155, 1,  1,   0,   156, 12, 10,  0,   172, 2,  10,  0, 209, 0,  3,   0,   0,
};

/* TNS_DATA payload = 2-byte data flags + a TTC message-body chunk. The final
 * (or only) packet carries data flags 0x0000; a non-final fragment carries
 * 0x0020 ("more data follows", §1.3). */
#define TTC_DATA_FLAG_FINAL 0x0000
#define TTC_DATA_FLAG_MORE 0x0020

/* ------------------------------------------------------------ data framing */

/* Send a TTC message as one or more TNS_DATA packets. A message larger than the
 * negotiated SDU is split into SDU-sized fragments (each = 8-byte header + 2-byte
 * data flags + chunk); non-final fragments are exactly SDU bytes and flag 0x0020,
 * the last is smaller and flags 0x0000. The server reassembles them. */
SeerStatus seer_ttc_send(SeerConn *c, const uint8_t *msg, size_t len)
{
  /* Body bytes per non-final fragment: SDU minus the 8-byte header and 2-byte
   * data flags. With no SDU yet (pre-accept) send the whole message at once.
   * With ANO active each fragment's body is the (larger) wrapped ciphertext,
   * so we chunk the *plaintext* at SDU-64 (§33.3) and wrap per fragment. */
  size_t max_chunk;
  if (c->ano != NULL)
    max_chunk = seer_ano_max_plain(c->sdu);
  else
    max_chunk = (c->sdu > TNS_HEADER_LEN + 2) ? (size_t)c->sdu - TNS_HEADER_LEN - 2 : len;
  if (max_chunk == 0)
    max_chunk = len ? len : 1;

  size_t off = 0;
  do {
    size_t remaining = len - off;
    bool last = remaining <= max_chunk;
    size_t chunk = last ? remaining : max_chunk;

    const uint8_t *payload = msg + off;
    size_t plen = chunk;
    uint8_t *wrapped = NULL;
    if (c->ano != NULL) {
      SeerStatus wst = seer_ano_wrap(c->ano, msg + off, chunk, &wrapped, &plen);
      if (wst != SEER_OK)
        return wst;
      payload = wrapped;
    }

    SeerWriter w;
    if (!seer_writer_init(&w, plen + 2)) {
      free(wrapped);
      return SEER_ENOMEM;
    }
    seer_writer_u16(&w, last ? TTC_DATA_FLAG_FINAL : TTC_DATA_FLAG_MORE);
    seer_writer_bytes(&w, payload, plen);
    free(wrapped);
    if (!seer_writer_ok(&w)) {
      seer_writer_free(&w);
      return SEER_ENOMEM;
    }
    SeerStatus st = seer_packet_send(c->t, TNS_PT_DATA, w.buf, w.len);
    seer_writer_free(&w);
    if (st != SEER_OK)
      return st;
    off += chunk;
  } while (off < len);
  return SEER_OK;
}

void seer_cancel(SeerConn *c)
{
  /* Only interrupt a call actually blocked in seer_ttc_recv; sending a break
   * to an idle connection would leave a stray reset marker desyncing the next
   * call. Safe to call from another thread (a bare marker send vs the read).
   * In-band INTERRUPT marker (§15): the server interrupts the running call and
   * answers with break/reset markers + the inline ORA-01013, which the blocked
   * recv drains and surfaces. */
  if (c == NULL || c->t == NULL || !c->in_call)
    return;
  const uint8_t interrupt[3] = {0x01, 0x00, 0x03};
  seer_packet_send(c->t, TNS_PT_MARKER, interrupt, sizeof interrupt);
}

/* Receive one complete TTC message, reassembling across TNS_DATA packets. Each
 * packet carries 2 data-flag bytes that are stripped; the server signals "more
 * fragments follow" by sizing a packet to exactly SDU-37 or SDU-81 (§1.3).
 * *out is malloc'd; caller frees. */
/* How long to wait, after a packet sized like a non-final fragment, for the
 * continuation before deciding the message ended with it. */
#define FRAGMENT_WAIT_MS 2000

/* Whether the message continues past a DATA packet of `total` bytes. The
 * server marks nothing: a non-final fragment is filled to exactly SDU-37 (or
 * SDU-81) bytes (§1.3), and a shorter packet ends the message. But a message
 * can also END in a packet of exactly that size - a 10g LOB read whose reply
 * came to 2001 bytes on a 2048 SDU did - and waiting for a continuation that
 * never comes stalled the call for the full 30 s socket timeout, then failed
 * it. A real continuation is already in flight when its predecessor arrives
 * (the server wrote the whole message), so it is waited for only briefly:
 * nothing to read by then means the message is complete. */
/* Whether `total` is a size a non-final fragment can have. In the clear it is
 * exactly SDU-37 or SDU-81. With native encryption each packet is encrypted on
 * its own, whole AES blocks plus two trailer bytes, so a fragment filled as far
 * as it goes can end up to a block short of that limit - or a byte over it: a
 * 26ai LOB read on an 8192 SDU came in 8156-byte fragments. */
static bool fragment_sized(const SeerConn *c, size_t total)
{
  static const size_t LIMITS[] = {37, 81};
  for (size_t i = 0; i < sizeof LIMITS / sizeof LIMITS[0]; i++) {
    if (c->sdu <= LIMITS[i] + 16)
      continue;
    size_t limit = (size_t)c->sdu - LIMITS[i];
    if (total == limit)
      return true;
    if (c->ano != NULL && total + 16 > limit && total <= limit + 1)
      return true;
  }
  return false;
}

static bool more_fragments(SeerConn *c, size_t total)
{
  if (c->sdu == 0 || !fragment_sized(c, total))
    return false;
  if (seer_transport_wait_readable(c->t, FRAGMENT_WAIT_MS) == 0) {
    seer_log(SEER_LOG_DEBUG, "ttc: a %zu-byte packet ended its message", total);
    return false;
  }
  return true; /* data (or an error the next read reports) */
}

static SeerStatus recv_message(SeerConn *c, uint8_t **out, size_t *outlen)
{
  *out = NULL;
  *outlen = 0;

  SeerWriter acc;
  if (!seer_writer_init(&acc, 512))
    return SEER_ENOMEM;

  bool sent_reset = false; /* one client reset per break episode (§1.4) */

  c->in_call = true; /* blocked waiting for the server: cancellable */
  for (;;) {
    uint8_t type = 0;
    uint8_t *body = NULL;
    size_t blen = 0;
    SeerStatus st = seer_packet_recv(c->t, &type, &body, &blen);
    if (st != SEER_OK) {
      c->in_call = false;
      seer_writer_free(&acc);
      return st;
    }

    /* The server brackets a cancelled/errored call with break+reset
     * markers (§15). Answer the first with exactly one reset, then drain
     * the rest silently until the real DATA (the inline error) arrives. */
    if (type == TNS_PT_MARKER) {
      free(body);
      if (!sent_reset) {
        const uint8_t reset[3] = {0x01, 0x00, 0x02};
        seer_packet_send(c->t, TNS_PT_MARKER, reset, sizeof reset);
        sent_reset = true;
        /* With data integrity on, the break/reset renews both MAC
         * keystreams; the server's reply after it is already under the new
         * ones. */
        if (c->ano != NULL && seer_ano_reset(c->ano) != SEER_OK) {
          c->in_call = false;
          seer_writer_free(&acc);
          return SEER_EPROTO;
        }
      }
      continue;
    }

    if (type != TNS_PT_DATA || blen < 2) {
      seer_log(SEER_LOG_ERROR, "ttc: expected DATA packet (got type %u, %zu bytes)", type, blen);
      free(body);
      c->in_call = false;
      seer_writer_free(&acc);
      return SEER_EPROTO;
    }

    size_t total = blen + TNS_HEADER_LEN; /* full TNS packet size */
    /* Each DATA body (after the 2 data-flag bytes) is an independent unit.
     * With ANO active it is encrypted + MAC'd, so decrypt/verify per packet
     * before reassembly concatenates the plaintext (§33.3). */
    if (c->ano != NULL) {
      uint8_t *plain = NULL;
      size_t plen = 0;
      SeerStatus ust = seer_ano_unwrap(c->ano, body + 2, blen - 2, &plain, &plen);
      free(body);
      if (ust != SEER_OK) {
        c->in_call = false;
        seer_writer_free(&acc);
        return ust;
      }
      seer_writer_bytes(&acc, plain, plen);
      free(plain);
    } else {
      seer_writer_bytes(&acc, body + 2, blen - 2); /* drop data flags */
      free(body);
    }

    if (!more_fragments(c, total))
      break;
  }
  c->in_call = false;

  if (!seer_writer_ok(&acc)) {
    seer_writer_free(&acc);
    return SEER_ENOMEM;
  }
  *out = acc.buf;
  *outlen = acc.len;
  return SEER_OK;
}

/* Receive a TTC response. A message that is nothing but TTI_FOB is not a
 * response but a request: a DML statement with a RETURNING clause that FAILS
 * makes the server ask the client to flush its out-binds, and it then waits for
 * the same single byte back before sending the real error. Answer it (a
 * bounded number of times, so a server that never stops asking ends the call)
 * and return the response behind it. Left unanswered, the server stays in the
 * previous call and the NEXT statement fails with ORA-03137 (ORA-00600 on
 * 10g). */
SeerStatus seer_ttc_recv(SeerConn *c, uint8_t **out, size_t *outlen)
{
  for (int asked = 0;; asked++) {
    SeerStatus st = recv_message(c, out, outlen);
    if (st != SEER_OK || *outlen != 1 || (*out)[0] != TTI_FOB)
      return st;
    free(*out);
    *out = NULL;
    *outlen = 0;
    if (asked == 3) {
      seer_log(SEER_LOG_ERROR, "ttc: server keeps asking to flush out-binds");
      return SEER_EPROTO;
    }
    const uint8_t fob = TTI_FOB;
    st = seer_ttc_send(c, &fob, 1);
    if (st != SEER_OK)
      return st;
  }
}

/* -------------------------------------------------- request pipelining (§32) */

/* Build the begin-pipeline piggyback (func 199) into `w`: it rides the first
 * pipelined message, shares op 1's token, and carries the (continue-on-error)
 * mode. Consumes a sequence number. */
void seer_ttc_pipeline_begin(SeerConn *c, SeerWriter *w, uint32_t token, uint8_t mode)
{
  seer_writer_u8(w, TTI_MSG_TYPE_PIGGYBACK);
  seer_writer_u8(w, TNS_FUNC_PIPELINE_BEGIN);
  seer_writer_u8(w, seer_ttc_next_seq(c));
  if (c->field_version > TTC_FIELD_VERSION_23_1)
    seer_enc_sb4(w, token);
  seer_enc_sb4(w, 0);
  seer_writer_u8(w, 0);
  seer_writer_u8(w, mode);
}

/* Build the pipeline-end message (func 200) into `w`, closing the burst. Uses an
 * ordinary (token 0) function header. Consumes a sequence number. */
void seer_ttc_pipeline_end(SeerConn *c, SeerWriter *w)
{
  uint32_t saved = c->pipeline_token;
  c->pipeline_token = 0;
  seer_ttc_fun_header(c, w, TNS_FUNC_PIPELINE_END);
  c->pipeline_token = saved;
  seer_enc_sb4(w, 0);
}

/* Send one pipelined op's request as DATA packet(s) with explicit data flags: an
 * oversized op fragments at the SDU with the 0x0020 "more" flag; the final
 * fragment carries `final_flags` (END_OF_REQUEST), and the very first packet of
 * the whole burst additionally carries `first_flags` (BEGIN_PIPELINE). */
SeerStatus seer_ttc_send_pipeline_op(SeerConn *c, const uint8_t *data, size_t len,
                                     uint16_t final_flags, uint16_t first_flags)
{
  size_t body_max = (c->sdu > TNS_HEADER_LEN + 2) ? (size_t)c->sdu - TNS_HEADER_LEN - 2 : len;
  if (body_max == 0)
    body_max = len ? len : 1;

  size_t off = 0;
  bool first = true;
  do {
    size_t remaining = len - off;
    bool last = remaining <= body_max;
    size_t chunk = last ? remaining : body_max;
    uint16_t flags =
        (uint16_t)((last ? final_flags : TTC_DATA_FLAG_MORE) | (first ? first_flags : 0));

    SeerWriter w;
    if (!seer_writer_init(&w, chunk + 2))
      return SEER_ENOMEM;
    seer_writer_u16(&w, flags);
    seer_writer_bytes(&w, data + off, chunk);
    if (!seer_writer_ok(&w)) {
      seer_writer_free(&w);
      return SEER_ENOMEM;
    }
    SeerStatus st = seer_packet_send(c->t, TNS_PT_DATA, w.buf, w.len);
    seer_writer_free(&w);
    if (st != SEER_OK)
      return st;
    off += chunk;
    first = false;
  } while (off < len);
  return SEER_OK;
}

/* Read exactly one pipelined op's response (TOKEN .. EOR) as one unit. Unlike
 * seer_ttc_recv, a break marker between op responses is skipped silently (the
 * server does not wait for a reset during a burst, #158), and the read stops at
 * the first non-fragment (response-final) packet without coalescing the next
 * op's response. *out is malloc'd; caller frees. */
SeerStatus seer_ttc_recv_pipeline(SeerConn *c, uint8_t **out, size_t *outlen)
{
  *out = NULL;
  *outlen = 0;
  SeerWriter acc;
  if (!seer_writer_init(&acc, 512))
    return SEER_ENOMEM;

  for (;;) {
    uint8_t type = 0;
    uint8_t *body = NULL;
    size_t blen = 0;
    SeerStatus st = seer_packet_recv(c->t, &type, &body, &blen);
    if (st != SEER_OK) {
      seer_writer_free(&acc);
      return st;
    }

    if (type == TNS_PT_MARKER) { /* per-op error break: skip, no reset */
      free(body);
      continue;
    }
    if (type != TNS_PT_DATA || blen < 2) {
      free(body);
      seer_writer_free(&acc);
      return SEER_EPROTO;
    }
    seer_writer_bytes(&acc, body + 2, blen - 2); /* drop data flags */
    size_t total = blen + TNS_HEADER_LEN;
    free(body);

    if (!more_fragments(c, total))
      break;
  }
  if (!seer_writer_ok(&acc)) {
    seer_writer_free(&acc);
    return SEER_ENOMEM;
  }
  *out = acc.buf;
  *outlen = acc.len;
  return SEER_OK;
}

/* Native network encryption negotiation (§33). Runs before PRO, over the
 * plaintext session: send round 1 (offered algorithms), read the server's
 * selection, and — when encryption was selected — complete the Diffie-Hellman
 * exchange (round 2) and activate the connection's per-packet cipher + MAC. */
SeerStatus seer_ttc_ano_negotiate(SeerConn *c)
{
  uint8_t *req = NULL;
  size_t reqlen = 0;
  SeerStatus st = seer_ano_build_round1(&req, &reqlen);
  if (st != SEER_OK)
    return st;
  st = seer_ttc_send(c, req, reqlen);
  free(req);
  if (st != SEER_OK)
    return st;

  uint8_t *resp = NULL;
  size_t resplen = 0;
  st = seer_ttc_recv(c, &resp, &resplen);
  if (st != SEER_OK)
    return st;

  SeerAnoResponse ar;
  st = seer_ano_parse_response(resp, resplen, &ar);
  free(resp);
  if (st != SEER_OK)
    return st;

  /* No encryption selected (bare-supported server, or no DH): stay plaintext. */
  if (ar.enc_id == 0 || !ar.have_dh) {
    seer_log(SEER_LOG_INFO, "TNS: ANO negotiated, no encryption (enc=%u)", ar.enc_id);
    seer_ano_response_free(&ar);
    return SEER_OK;
  }

  uint8_t *cpub = NULL, *sk = NULL;
  size_t cpub_len = 0, sk_len = 0;
  st = seer_ano_dh(&ar, &cpub, &cpub_len, &sk, &sk_len);
  if (st != SEER_OK) {
    seer_ano_response_free(&ar);
    return st;
  }

  uint8_t *r2 = NULL;
  size_t r2len = 0;
  st = seer_ano_build_round2(cpub, cpub_len, &r2, &r2len);
  if (st == SEER_OK) {
    st = seer_ttc_send(c, r2, r2len); /* last plaintext packet */
    free(r2);
  }
  free(cpub);

  if (st == SEER_OK) {
    SeerAno *ch = NULL;
    st = seer_ano_channel_new(ar.enc_id, ar.int_id, sk, sk_len, ar.server_iv, ar.server_iv_len,
                              /*client_side=*/true, &ch);
    if (st == SEER_OK) {
      c->ano = ch; /* every DATA packet from PRO onward is now wrapped */
      seer_log(SEER_LOG_INFO, "TNS: ANO active (enc=%u integrity=%u)", ar.enc_id, ar.int_id);
    }
  }

  OPENSSL_cleanse(sk, sk_len);
  free(sk);
  seer_ano_response_free(&ar);
  return st;
}

uint8_t seer_ttc_next_seq(SeerConn *c)
{
  uint8_t s = c->seq;
  c->seq = (uint8_t)(c->seq % 127 + 1); /* wraps 127 -> 1 */
  return s;
}

void seer_ttc_fun_header(SeerConn *c, SeerWriter *w, uint8_t opcode)
{
  seer_writer_u8(w, TTI_FUN);
  seer_writer_u8(w, opcode);
  seer_writer_u8(w, seer_ttc_next_seq(c));
  /* fv24 (23ai): oracledb writes a ub8 token after the sequence number on every
   * function message (seerdb _fun_header, PROTOCOL.md §20). It is 0 for an
   * ordinary call (encoding to a single 0x00) and 1..N for a pipelined op
   * (§32/#158), so the server can correlate each burst response. */
  if (c->field_version > TTC_FIELD_VERSION_23_1)
    seer_enc_sb4(w, c->pipeline_token);
}

/* ------------------------------------------------------------- TTI_PRO/DTY */

/* Walk a TTI_PRO reply and pull out the server's TTC field version
 * (compile_caps[7]) and whether it advertises explicit request boundaries (§35:
 * compile_caps[40] bit 0x40 AND runtime_caps[6] bit 0x10). Returns SEER_EPROTO
 * on a bounds violation reading the field version; the request-boundary probe is
 * best-effort and never fails the login (*req_bnd defaults to false). */
/* The major release named in a PRO banner ("...8.1.7..." -> 8): the first
 * "<n>.<n>.<n>" in it, 0 when there is none. */
static int banner_major(const uint8_t *s, size_t n)
{
  for (size_t i = 0; i < n; i++) {
    if (s[i] < '0' || s[i] > '9' || (i > 0 && s[i - 1] >= '0' && s[i - 1] <= '9'))
      continue;
    size_t j = i;
    int major = 0, dots = 0;
    while (j < n && s[j] >= '0' && s[j] <= '9')
      major = major * 10 + (s[j++] - '0');
    for (int part = 0; part < 2; part++) {
      if (j + 1 < n && s[j] == '.' && s[j + 1] >= '0' && s[j + 1] <= '9') {
        j++;
        while (j < n && s[j] >= '0' && s[j] <= '9')
          j++;
        dots++;
      }
    }
    if (dots == 2)
      return major;
  }
  return 0;
}

/* `*server_fv` is 0 when the reply carries no compile caps at all - Oracle 8i,
 * whose PRO has none (seerdb PROTOCOL.md §19.8); `*major` (may be NULL) is the
 * banner's release. */
static SeerStatus parse_pro(const uint8_t *b, size_t n, uint8_t *server_fv, bool *req_bnd,
                            bool *str32k, int *major)
{
  if (req_bnd != NULL)
    *req_bnd = false;
  if (str32k != NULL)
    *str32k = false;
  if (major != NULL)
    *major = 0;
  size_t o = 0;
  if (n < 1 || b[0] != TTI_PRO)
    return SEER_EPROTO;
  o = 1;
  o += 1; /* server version byte */
  o += 1; /* trailing zero       */
  size_t banner = o;
  while (o < n && b[o] != 0) /* NUL-terminated banner */
    o++;
  if (major != NULL)
    *major = banner_major(b + banner, o - banner);
  o += 1; /* the NUL itself */
  o += 2; /* charset id (LE) */
  o += 1; /* server flags    */
  if (o + 2 > n)
    return SEER_EPROTO;
  uint16_t numelem = (uint16_t)(b[o] | (b[o + 1] << 8)); /* little-endian */
  o += 2;
  o += (size_t)numelem * 5; /* charset element array */
  if (o + 2 > n)
    return SEER_EPROTO;
  uint16_t fdolen = (uint16_t)((b[o] << 8) | b[o + 1]); /* big-endian */
  o += 2;
  o += fdolen;
  if (o + 1 > n)
    return SEER_EPROTO;
  uint8_t cclen = b[o];
  o += 1;
  if (cclen == 0) { /* no caps to negotiate: 8i */
    *server_fv = 0;
    return SEER_OK;
  }
  if (cclen < 8 || o + cclen > n)
    return SEER_EPROTO;
  *server_fv = b[o + 7]; /* CCAP_FIELD_VERSION */

  /* Request-boundary caps (best-effort): compile_caps[40] bit 0x40, then the
   * runtime-cap array (rclen + bytes) that follows the compile caps, and its
   * index 6 bit 0x10. Any shortfall just leaves the feature off. */
  uint8_t cc40 = (cclen > TNS_CCAP_TTC4) ? b[o + TNS_CCAP_TTC4] : 0;
  size_t ro = o + cclen;
  if (ro + 1 <= n) {
    uint8_t rclen = b[ro];
    ro += 1;
    if (ro + rclen <= n) {
      uint8_t rc6 = (rclen > TNS_RCAP_TTC) ? b[ro + TNS_RCAP_TTC] : 0;
      if (req_bnd != NULL)
        *req_bnd =
            (cc40 & TNS_CCAP_TTC4_EXPLICIT_BOUNDARY) && (rc6 & TNS_RCAP_TTC_SESSION_STATE_OPS);
      if (str32k != NULL)
        *str32k = (rc6 & TNS_RCAP_TTC_32K) != 0;
    }
  }
  return SEER_OK;
}

/* Oracle 9i (fv2) minimal capabilities (seerdb capability_arrays, fv<10g): all
 * zero except compile-cap index 17 = 0x03, and a single 0x02 runtime byte.
 * Critically CCAP_LOGON_TYPES (index 4) stays 0 - we must NOT advertise O5LOGON,
 * else 9i tries a verifier the account lacks and the O3LOGON path never engages
 * (the server errors instead of returning the session key). */
static const uint8_t O3_COMPILE_CAPS[21] = {[17] = 0x03};
static const uint8_t O3_RUNTIME_CAPS[1] = {0x02};

/* Build the TTI_DTY message (token, charset in/out, flag, caps, type table).
 * `eor` opts into end-of-response framing (§32/#155) by setting the CCAP_TTC4
 * bit; the caller passes it only when the accept advertised support. */
static SeerStatus build_dty(SeerWriter *w, uint8_t fv, bool eor)
{
  bool is12c = fv >= TTC_FIELD_VERSION_12_1;
  if (!seer_writer_init(w, is12c ? 2600 : 1300))
    return SEER_ENOMEM;

  seer_writer_u8(w, TTI_DTY);
  /* charset_in and charset_out, both AL32UTF8, little-endian. */
  for (int i = 0; i < 2; i++) {
    seer_writer_u8(w, (uint8_t)(ORA_CHARSET_AL32UTF8 & 0xFF));
    seer_writer_u8(w, (uint8_t)(ORA_CHARSET_AL32UTF8 >> 8));
  }
  /* The encoding flag follows the table form: 3 (multi-byte/conv-length) for
   * the 12c+ UB2 table, 1 for the 11g 1-byte table. */
  seer_writer_u8(w, is12c ? 3 : 1);

  if (is12c) {
    uint8_t caps[sizeof COMPILE_CAPS_12C];
    memcpy(caps, COMPILE_CAPS_12C, sizeof caps);
    caps[7] = fv; /* CCAP_FIELD_VERSION */
    if (eor)      /* §32/#155 opt-in */
      caps[TNS_CCAP_TTC4] |= TNS_CCAP_TTC4_END_OF_RESPONSE;
    seer_writer_u8(w, (uint8_t)sizeof caps);
    seer_writer_bytes(w, caps, sizeof caps);
    seer_writer_u8(w, (uint8_t)sizeof RUNTIME_CAPS_12C);
    seer_writer_bytes(w, RUNTIME_CAPS_12C, sizeof RUNTIME_CAPS_12C);
    write_dty_12c_table(w);
  } else {
    /* 9i (fv2) advertises the minimal pre-10g caps (no O5LOGON); 10g/11g use
     * the 11.2 vector. The charset flag + type table are shared. */
    const uint8_t *cc = COMPILE_CAPS;
    size_t ccl = sizeof COMPILE_CAPS;
    const uint8_t *rc = RUNTIME_CAPS;
    size_t rcl = sizeof RUNTIME_CAPS;
    if (fv < TTC_FIELD_VERSION_10_2) {
      cc = O3_COMPILE_CAPS;
      ccl = sizeof O3_COMPILE_CAPS;
      rc = O3_RUNTIME_CAPS;
      rcl = sizeof O3_RUNTIME_CAPS;
    }
    seer_writer_u8(w, (uint8_t)ccl);
    seer_writer_bytes(w, cc, ccl);
    seer_writer_u8(w, (uint8_t)rcl);
    seer_writer_bytes(w, rc, rcl);
    for (int x = 1; x <= 245; x++) { /* identity map */
      seer_writer_u8(w, (uint8_t)x);
      seer_writer_u8(w, (uint8_t)x);
      seer_writer_u8(w, 1);
      seer_writer_u8(w, 0);
    }
    seer_writer_bytes(w, TYPE_OVERRIDES, sizeof TYPE_OVERRIDES);
  }

  if (!seer_writer_ok(w)) {
    seer_writer_free(w);
    return SEER_ENOMEM;
  }
  return SEER_OK;
}

/* --------------------------------------------------------------- TTI_SESS */

/* Proxy auth (#126): a `proxy_user[schema]` username authenticates as proxy_user
 * but operates in schema's context. Copies the clean (proxy) user into `ubuf` and
 * returns the schema substring (NULL when the name has no trailing [..]), with its
 * length in *schema_len. Both the challenge and auth phases send the clean user;
 * build_auth additionally sends the schema as a PROXY_CLIENT_NAME auth pair. */
static const char *proxy_split(const char *raw, char *ubuf, size_t bufsz, size_t *schema_len)
{
  *schema_len = 0;
  size_t rl = strlen(raw);
  const char *lb = strchr(raw, '[');
  if (lb != NULL && lb != raw && rl > 0 && raw[rl - 1] == ']') {
    size_t ul = (size_t)(lb - raw);
    if (ul < bufsz) {
      memcpy(ubuf, raw, ul);
      ubuf[ul] = '\0';
      *schema_len = rl - ul - 2; /* chars between [ and ] */
      return lb + 1;
    }
  }
  size_t cp = rl < bufsz ? rl : bufsz - 1;
  memcpy(ubuf, raw, cp);
  ubuf[cp] = '\0';
  return NULL;
}

static SeerStatus build_sess(SeerConn *c, const SeerConnParams *p, SeerWriter *w)
{
  char ubuf[256];
  size_t schema_len;
  proxy_split((p->username && *p->username) ? p->username : "", ubuf, sizeof ubuf, &schema_len);
  const char *user = ubuf;
  size_t ulen = strlen(user);

  char host[256];
  if (gethostname(host, sizeof host - 1) != 0)
    strcpy(host, "localhost");
  host[sizeof host - 1] = '\0';

  char pid[16];
  snprintf(pid, sizeof pid, "%ld", (long)getpid());

  /* AUTH_SID is the operating-system account running the client - the server
   * shows it as v$session.OSUSER / SYS_CONTEXT('USERENV','OS_USER') - not the
   * database user (seerdb/seerdb@dd06c5d). */
  char osuser[128] = "";
#ifndef _WIN32
  struct passwd pw, *pwres = NULL;
  char pwbuf[1024];
  if (getpwuid_r(geteuid(), &pw, pwbuf, sizeof pwbuf, &pwres) == 0 && pwres != NULL &&
      pwres->pw_name != NULL)
    snprintf(osuser, sizeof osuser, "%s", pwres->pw_name);
#endif
  if (!osuser[0]) {
    const char *e = getenv("USER");
    if (e == NULL || !e[0])
      e = getenv("LOGNAME");
    if (e == NULL || !e[0])
      e = getenv("USERNAME"); /* Windows */
    snprintf(osuser, sizeof osuser, "%s", (e != NULL && e[0]) ? e : "unknown");
  }

  static const char APP[] = "seerodbc";

  if (!seer_writer_init(w, 256))
    return SEER_ENOMEM;

  bool is12c = c->field_version >= TTC_FIELD_VERSION_12_1;
  seer_writer_u8(w, TTI_FUN);
  seer_writer_u8(w, TTI_SESS);
  seer_writer_u8(w, seer_ttc_next_seq(c));
  seer_writer_u8(w, 1);
  seer_enc_sb4(w, (uint32_t)ulen); /* user length          */
  seer_enc_sb4(w, 1);              /* logon mode (basic)   */
  seer_writer_u8(w, 1);
  /* 12c+ sends 5 pairs (leading AUTH_TERMINAL) and a length-prefixed
   * username; 11g sends 4 pairs and the raw username (read via UserLen). */
  seer_enc_sb4(w, is12c ? 5 : 4); /* key/value pairs      */
  seer_writer_u8(w, 1);
  seer_writer_u8(w, 1);
  if (is12c) {
    seer_writer_u8(w, (uint8_t)ulen); /* length-prefixed username */
    seer_writer_bytes(w, user, ulen);
    seer_enc_kv(w, "AUTH_TERMINAL", 13, "unknown", 7, 0,
                c->field_version >= TTC_FIELD_VERSION_12_1);
  } else {
    seer_writer_bytes(w, user, ulen); /* raw username (11g) */
  }
  seer_enc_kv(w, "AUTH_PROGRAM_NM", 15, APP, sizeof APP - 1, 0,
              c->field_version >= TTC_FIELD_VERSION_12_1);
  seer_enc_kv(w, "AUTH_MACHINE", 12, host, strlen(host), 0,
              c->field_version >= TTC_FIELD_VERSION_12_1);
  seer_enc_kv(w, "AUTH_PID", 8, pid, strlen(pid), 0, c->field_version >= TTC_FIELD_VERSION_12_1);
  seer_enc_kv(w, "AUTH_SID", 8, osuser, strlen(osuser), 0,
              c->field_version >= TTC_FIELD_VERSION_12_1);

  if (!seer_writer_ok(w)) {
    seer_writer_free(w);
    return SEER_ENOMEM;
  }
  return SEER_OK;
}

/* ----------------------------------------------------------- challenge KV */

static int hexval(uint8_t c)
{
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  return -1;
}

/* Decode an ASCII-hex string to raw bytes (malloc'd). */
static SeerStatus hex_decode(const uint8_t *in, size_t inlen, uint8_t **out, size_t *outlen)
{
  *out = NULL;
  *outlen = 0;
  if (inlen == 0)
    return SEER_OK;
  if (inlen % 2 != 0)
    return SEER_EPROTO;
  uint8_t *buf = malloc(inlen / 2);
  if (buf == NULL)
    return SEER_ENOMEM;
  for (size_t i = 0; i < inlen / 2; i++) {
    int hi = hexval(in[2 * i]);
    int lo = hexval(in[2 * i + 1]);
    if (hi < 0 || lo < 0) {
      free(buf);
      return SEER_EPROTO;
    }
    buf[i] = (uint8_t)((hi << 4) | lo);
  }
  *out = buf;
  *outlen = inlen / 2;
  return SEER_OK;
}

static bool key_is(const uint8_t *k, size_t kl, const char *name)
{
  return kl == strlen(name) && memcmp(k, name, kl) == 0;
}

/* Parse the TTI_RPA auth challenge: a count followed by KV pairs. The hex
 * AUTH_SESSKEY / AUTH_VFR_DATA / AUTH_PBKDF2_CSK_SALT values are decoded to
 * raw bytes into *ch. */
static SeerStatus parse_challenge(const uint8_t *b, size_t n, SeerAuthChallenge *ch)
{
  memset(ch, 0, sizeof *ch);

  if (n < 1) {
    return SEER_EPROTO;
  }
  if (b[0] == TTI_OER) {
    seer_log(SEER_LOG_ERROR, "ttc: server returned an error to session setup");
    return SEER_EAUTH;
  }
  if (b[0] != TTI_RPA) {
    seer_log(SEER_LOG_ERROR, "ttc: expected RPA challenge, got token %u", b[0]);
    return SEER_EPROTO;
  }

  SeerReader r;
  seer_reader_init(&r, b + 1, n - 1);
  int64_t num = seer_dec_sb4(&r);
  if (num < 0 || num > 256 || !seer_reader_ok(&r))
    return SEER_EPROTO;

  SeerStatus st = SEER_OK;
  for (int64_t i = 0; i < num; i++) {
    uint8_t *k = NULL, *v = NULL;
    size_t kl = 0, vl = 0;

    st = seer_dec_field(&r, &k, &kl);
    if (st != SEER_OK) {
      free(k);
      goto out;
    }
    st = seer_dec_field(&r, &v, &vl);
    if (st != SEER_OK) {
      free(k);
      free(v);
      goto out;
    }

    /* Skip the inter-pair trailer (flag byte + that many bytes). */
    if (seer_reader_remaining(&r) > 0) {
      uint8_t flag = seer_reader_u8(&r);
      if (flag > 0)
        seer_reader_bytes(&r, flag);
    }

    if (key_is(k, kl, "AUTH_SESSKEY"))
      st = hex_decode(v, vl, &ch->sesskey, &ch->sesskey_len);
    else if (key_is(k, kl, "AUTH_VFR_DATA"))
      st = hex_decode(v, vl, &ch->salt, &ch->salt_len);
    else if (key_is(k, kl, "AUTH_PBKDF2_CSK_SALT"))
      st = hex_decode(v, vl, &ch->csk_salt, &ch->csk_salt_len);

    free(k);
    free(v);
    if (st != SEER_OK)
      goto out;
  }

  if (!seer_reader_ok(&r)) {
    st = SEER_EPROTO;
    goto out;
  }
  if (ch->sesskey == NULL) {
    seer_log(SEER_LOG_ERROR, "ttc: challenge missing AUTH_SESSKEY");
    st = SEER_EPROTO;
    goto out;
  }
  /* An absent or empty AUTH_VFR_DATA (salt) means a 10g account carrying only
   * the legacy DES verifier - seer_o5logon derives the AES-128 key from that
   * verifier (salt == NULL). 11g/12c always send a non-empty salt. */
  return SEER_OK;

out:
  seer_auth_challenge_free(ch);
  return st;
}

/* ------------------------------------------------------------- public API */

void seer_auth_challenge_free(SeerAuthChallenge *ch)
{
  if (ch == NULL)
    return;
  free(ch->sesskey);
  free(ch->salt);
  free(ch->csk_salt);
  memset(ch, 0, sizeof *ch);
}

/* 23ai fast-auth (PROTOCOL.md §20): bundle PRO, DTY and OSESSKEY (TTI_SESS) into
 * one TNS_MSG_TYPE_FAST_AUTH message. The legacy three-message handshake is
 * rejected (ORA-03146) once we advertise fv >= 18, so this is the only path to
 * fv24. The PRO already exchanged in seer_ttc_login is harmlessly repeated in
 * the bundle. The reply concatenates the PRO, DTY and challenge responses; we
 * locate the auth-challenge RPA and hand it to the normal phase-two auth path. */
static SeerStatus fast_auth_login(SeerConn *conn, const SeerConnParams *params,
                                  SeerAuthChallenge *ch)
{
  SeerWriter dty, sess, bundle;
  SeerStatus st = build_dty(&dty, conn->field_version, conn->supports_eor);
  if (st != SEER_OK)
    return st;
  st = build_sess(conn, params, &sess);
  if (st != SEER_OK) {
    seer_writer_free(&dty);
    return st;
  }

  if (!seer_writer_init(&bundle, sizeof PRO_MSG + dty.len + sess.len + 16)) {
    seer_writer_free(&dty);
    seer_writer_free(&sess);
    return SEER_ENOMEM;
  }
  seer_writer_u8(&bundle, TNS_MSG_TYPE_FAST_AUTH);
  seer_writer_u8(&bundle, 1); /* version          */
  seer_writer_u8(&bundle, TNS_SERVER_CONVERTS_CHARS);
  seer_writer_u8(&bundle, 0); /* flag2            */
  seer_writer_bytes(&bundle, PRO_MSG, sizeof PRO_MSG);
  for (int i = 0; i < 5; i++) /* charset/flag/ncharset */
    seer_writer_u8(&bundle, 0);
  seer_writer_u8(&bundle, TTC_FIELD_VERSION_19_1_EXT1);
  seer_writer_bytes(&bundle, dty.buf, dty.len);
  seer_writer_bytes(&bundle, sess.buf, sess.len);
  seer_writer_free(&dty);
  seer_writer_free(&sess);
  if (!seer_writer_ok(&bundle)) {
    seer_writer_free(&bundle);
    return SEER_ENOMEM;
  }

  st = seer_ttc_send(conn, bundle.buf, bundle.len);
  seer_writer_free(&bundle);
  if (st != SEER_OK)
    return st;

  uint8_t *resp = NULL;
  size_t rlen = 0;
  st = seer_ttc_recv(conn, &resp, &rlen);
  if (st != SEER_OK)
    return st;

  /* Locate the challenge RPA. The DTY datatype table contains stray 0x08
   * (TTI_RPA) bytes, so accept only an RPA whose decode yields a session key. */
  st = SEER_EPROTO;
  for (size_t off = 0; off < rlen; off++) {
    if (resp[off] != TTI_RPA)
      continue;
    SeerAuthChallenge tmp;
    if (parse_challenge(resp + off, rlen - off, &tmp) == SEER_OK && tmp.sesskey_len > 0) {
      *ch = tmp; /* move ownership   */
      st = SEER_OK;
      break;
    }
    seer_auth_challenge_free(&tmp);
  }
  free(resp);
  if (st != SEER_OK)
    seer_log(SEER_LOG_ERROR, "fast-auth: no challenge RPA in bundled reply");
  else
    seer_log(SEER_LOG_INFO, "TTC: fast-auth challenge received (fv=%u)", conn->field_version);
  return st;
}

/* Oracle 8i's DTY, captured from a 9.2 client logging in to 8.1.7 (seerdb
 * _DTY_8I, PROTOCOL.md §19.8): the TTI_DTY token, charset and national
 * charset WE8ISO8859P1 (31) - 8i has no Unicode charset -, the 26-byte fv2
 * capability vector, the database time-zone block at UTC, then the 8i
 * conversion table, which predates ~37 later types. The modern DTY draws
 * ORA-03120 on the OSESSKEY that follows. 1019 bytes. */
static const uint8_t DTY_8I[] = {
    0x02, 0x1f, 0x00, 0x1f, 0x00, 0x02, 0x15, 0x06, 0x01, 0x01, 0x01, 0x05, 0x01, 0x01, 0x02, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x7f, 0x0f, 0x03, 0x06, 0x03, 0x00, 0x02, 0x02, 0x01, 0x80,
    0x00, 0x00, 0x00, 0x3c, 0x3c, 0x3c, 0x80, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x00, 0x02, 0x02,
    0x0a, 0x00, 0x08, 0x08, 0x01, 0x00, 0x0c, 0x0c, 0x0a, 0x00, 0x17, 0x17, 0x01, 0x00, 0x18, 0x18,
    0x01, 0x00, 0x19, 0x19, 0x18, 0x19, 0x01, 0x00, 0x1a, 0x1a, 0x19, 0x1a, 0x01, 0x00, 0x1b, 0x1b,
    0x0a, 0x1b, 0x01, 0x00, 0x1c, 0x1c, 0x16, 0x1c, 0x01, 0x00, 0x1d, 0x1d, 0x17, 0x1d, 0x01, 0x00,
    0x1e, 0x1e, 0x17, 0x1e, 0x01, 0x00, 0x1f, 0x1f, 0x19, 0x1f, 0x01, 0x00, 0x20, 0x20, 0x0c, 0x20,
    0x01, 0x00, 0x21, 0x21, 0x0c, 0x21, 0x01, 0x00, 0x0a, 0x0a, 0x01, 0x00, 0x0b, 0x0b, 0x01, 0x00,
    0x22, 0x22, 0x01, 0x00, 0x23, 0x23, 0x01, 0x23, 0x01, 0x00, 0x24, 0x24, 0x01, 0x00, 0x25, 0x25,
    0x01, 0x00, 0x26, 0x26, 0x01, 0x00, 0x28, 0x28, 0x01, 0x00, 0x29, 0x29, 0x01, 0x00, 0x2a, 0x2a,
    0x01, 0x00, 0x2b, 0x2b, 0x01, 0x00, 0x2c, 0x2c, 0x01, 0x00, 0x2d, 0x2d, 0x01, 0x00, 0x2e, 0x2e,
    0x01, 0x00, 0x2f, 0x2f, 0x01, 0x00, 0x30, 0x30, 0x01, 0x00, 0x31, 0x31, 0x01, 0x00, 0x32, 0x32,
    0x01, 0x00, 0x33, 0x33, 0x01, 0x00, 0x34, 0x34, 0x01, 0x00, 0x35, 0x35, 0x01, 0x00, 0x36, 0x36,
    0x01, 0x00, 0x37, 0x37, 0x01, 0x00, 0x38, 0x38, 0x01, 0x00, 0x39, 0x39, 0x01, 0x00, 0x3b, 0x3b,
    0x01, 0x00, 0x3c, 0x3c, 0x01, 0x00, 0x3d, 0x3d, 0x01, 0x00, 0x3e, 0x3e, 0x01, 0x00, 0x3f, 0x3f,
    0x01, 0x00, 0x40, 0x40, 0x01, 0x00, 0x41, 0x41, 0x01, 0x00, 0x42, 0x42, 0x01, 0x00, 0x43, 0x43,
    0x01, 0x00, 0x47, 0x47, 0x01, 0x00, 0x48, 0x48, 0x01, 0x00, 0x49, 0x49, 0x01, 0x00, 0x4b, 0x4b,
    0x01, 0x00, 0x4d, 0x4d, 0x01, 0x00, 0x4e, 0x4e, 0x01, 0x00, 0x4f, 0x4f, 0x01, 0x00, 0x50, 0x50,
    0x01, 0x00, 0x51, 0x51, 0x01, 0x00, 0x52, 0x52, 0x01, 0x00, 0x53, 0x53, 0x01, 0x00, 0x54, 0x54,
    0x01, 0x00, 0x55, 0x55, 0x01, 0x00, 0x56, 0x56, 0x01, 0x00, 0x57, 0x57, 0x01, 0x57, 0x01, 0x00,
    0x59, 0x59, 0x01, 0x00, 0x5a, 0x5a, 0x01, 0x00, 0x5c, 0x5c, 0x01, 0x00, 0x5d, 0x5d, 0x01, 0x00,
    0x62, 0x62, 0x01, 0x00, 0x63, 0x63, 0x01, 0x00, 0x67, 0x67, 0x01, 0x00, 0x6b, 0x6b, 0x01, 0x00,
    0x75, 0x75, 0x01, 0x00, 0x78, 0x78, 0x01, 0x00, 0x7c, 0x7c, 0x01, 0x42, 0x01, 0x00, 0x7d, 0x7d,
    0x01, 0x00, 0x7e, 0x7e, 0x01, 0x00, 0x7f, 0x7f, 0x01, 0x00, 0x80, 0x80, 0x01, 0x00, 0x81, 0x81,
    0x01, 0x00, 0x82, 0x82, 0x01, 0x00, 0x83, 0x83, 0x01, 0x00, 0x84, 0x84, 0x01, 0x00, 0x85, 0x85,
    0x01, 0x00, 0x86, 0x86, 0x01, 0x00, 0x87, 0x87, 0x01, 0x00, 0x89, 0x89, 0x01, 0x00, 0x8a, 0x8a,
    0x01, 0x00, 0x8b, 0x8b, 0x01, 0x00, 0x8c, 0x8c, 0x01, 0x00, 0x8d, 0x8d, 0x01, 0x00, 0x8e, 0x8e,
    0x01, 0x00, 0x8f, 0x8f, 0x01, 0x00, 0x90, 0x90, 0x01, 0x00, 0x91, 0x91, 0x01, 0x00, 0x94, 0x94,
    0x01, 0x25, 0x01, 0x00, 0x95, 0x95, 0x01, 0x00, 0x96, 0x96, 0x01, 0x00, 0x97, 0x97, 0x01, 0x00,
    0x9d, 0x9d, 0x01, 0x00, 0x9e, 0x9e, 0x01, 0x00, 0x9f, 0x9f, 0x01, 0x00, 0xa0, 0xa0, 0x01, 0x00,
    0xa1, 0xa1, 0x01, 0x00, 0xa2, 0xa2, 0x01, 0x00, 0xa3, 0xa3, 0x01, 0x00, 0xa4, 0xa4, 0x01, 0x00,
    0xa5, 0xa5, 0x01, 0x00, 0xa6, 0xa6, 0x01, 0x00, 0xa7, 0xa7, 0x01, 0x00, 0xa8, 0xa8, 0x01, 0x00,
    0xa9, 0xa9, 0x01, 0x00, 0xaa, 0xaa, 0x01, 0x00, 0xab, 0xab, 0x01, 0x00, 0xad, 0xad, 0x01, 0x00,
    0xae, 0xae, 0x01, 0x00, 0xaf, 0xaf, 0x01, 0x00, 0xb0, 0xb0, 0x01, 0x00, 0xb1, 0xb1, 0x01, 0x00,
    0xc1, 0xc1, 0x01, 0x00, 0xc2, 0xc2, 0x01, 0x25, 0x01, 0x00, 0xc6, 0xc6, 0x01, 0x00, 0xc7, 0xc7,
    0x01, 0x00, 0xc8, 0xc8, 0x01, 0x00, 0xc9, 0xc9, 0x01, 0x00, 0xca, 0xca, 0x01, 0x9f, 0x01, 0x00,
    0xcb, 0xcb, 0x01, 0xa0, 0x01, 0x00, 0xcc, 0xcc, 0x01, 0xa2, 0x01, 0x00, 0xcd, 0xcd, 0x01, 0xa3,
    0x01, 0x00, 0xce, 0xce, 0x01, 0xb1, 0x01, 0x00, 0xcf, 0xcf, 0x01, 0x22, 0x01, 0x00, 0xd2, 0xd2,
    0x01, 0x00, 0xd3, 0xd3, 0x01, 0xab, 0x01, 0x00, 0xd4, 0xd4, 0x01, 0x00, 0xd5, 0xd5, 0x01, 0x00,
    0xd6, 0xd6, 0x01, 0x00, 0xd7, 0xd7, 0x01, 0x00, 0xd8, 0xd8, 0x01, 0x00, 0xd9, 0xd9, 0x01, 0x00,
    0xda, 0xda, 0x01, 0x00, 0xdb, 0xdb, 0x01, 0x00, 0xdc, 0xdc, 0x01, 0x00, 0xdd, 0xdd, 0x01, 0x00,
    0xde, 0xde, 0x01, 0x00, 0xdf, 0xdf, 0x01, 0x00, 0xe0, 0xe0, 0x01, 0x00, 0xe1, 0xe1, 0x01, 0x00,
    0xe2, 0xe2, 0x01, 0x00, 0xe3, 0xe3, 0x01, 0x6b, 0x01, 0x00, 0xe4, 0xe4, 0x01, 0x00, 0xe5, 0xe5,
    0x01, 0x00, 0xe6, 0xe6, 0x01, 0x00, 0xea, 0xea, 0x01, 0x00, 0xeb, 0xeb, 0x01, 0x00, 0xec, 0xec,
    0x01, 0x00, 0xed, 0xed, 0x01, 0x00, 0xee, 0xee, 0x01, 0x00, 0xef, 0xef, 0x01, 0x00, 0xf2, 0xf2,
    0x01, 0x00, 0xf4, 0xf4, 0x01, 0x00, 0xf5, 0xf5, 0x01, 0x00, 0x03, 0x02, 0x0a, 0x00, 0x04, 0x02,
    0x0a, 0x00, 0x05, 0x01, 0x01, 0x00, 0x06, 0x02, 0x0a, 0x00, 0x07, 0x02, 0x0a, 0x00, 0x09, 0x01,
    0x01, 0x00, 0x0d, 0x00, 0x0e, 0x00, 0x0f, 0x17, 0x01, 0x00, 0x10, 0x00, 0x11, 0x00, 0x12, 0x00,
    0x13, 0x00, 0x14, 0x00, 0x15, 0x00, 0x16, 0x00, 0x27, 0x78, 0x01, 0x5d, 0x01, 0x26, 0x01, 0x00,
    0x3a, 0x6d, 0x01, 0x00, 0x44, 0x02, 0x0a, 0x00, 0x45, 0x00, 0x46, 0x00, 0x4a, 0x6d, 0x01, 0x00,
    0x4c, 0x00, 0x58, 0x00, 0x5b, 0x02, 0x0a, 0x00, 0x5e, 0x01, 0x01, 0x00, 0x5f, 0x17, 0x01, 0x00,
    0x60, 0x60, 0x01, 0x00, 0x61, 0x60, 0x01, 0x00, 0x64, 0x00, 0x65, 0x00, 0x66, 0x66, 0x01, 0x00,
    0x68, 0x00, 0x69, 0x00, 0x6a, 0x6a, 0x01, 0x00, 0x6c, 0x6d, 0x01, 0x00, 0x6d, 0x6d, 0x01, 0x00,
    0x6e, 0x6f, 0x01, 0x00, 0x6f, 0x6f, 0x01, 0x00, 0x70, 0x70, 0x01, 0x00, 0x71, 0x71, 0x01, 0x00,
    0x72, 0x72, 0x01, 0x00, 0x73, 0x73, 0x01, 0x00, 0x74, 0x66, 0x01, 0x00, 0x76, 0x00, 0x77, 0x00,
    0x79, 0x6d, 0x01, 0x00, 0x7a, 0x6d, 0x01, 0x00, 0x7b, 0x6d, 0x01, 0x00, 0x88, 0x00, 0x92, 0x92,
    0x01, 0x00, 0x93, 0x93, 0x01, 0x00, 0x98, 0x02, 0x0a, 0x00, 0x99, 0x02, 0x0a, 0x00, 0x9a, 0x02,
    0x0a, 0x00, 0x9b, 0x01, 0x01, 0x00, 0x9c, 0x0c, 0x0a, 0x00, 0xac, 0x02, 0x0a, 0x00, 0xb2, 0xb2,
    0x01, 0x00, 0xb3, 0xb3, 0x01, 0x00, 0xb4, 0xb4, 0x01, 0x00, 0xb5, 0xb5, 0x01, 0x00, 0xb6, 0xb6,
    0x01, 0x00, 0xb7, 0xb7, 0x01, 0x00, 0xb8, 0x0c, 0x0a, 0x00, 0xb9, 0xb2, 0x01, 0x00, 0xba, 0xb3,
    0x01, 0x00, 0xbb, 0xb4, 0x01, 0x00, 0xbc, 0xb5, 0x01, 0x00, 0xbd, 0xb6, 0x01, 0x00, 0xbe, 0xb7,
    0x01, 0x00, 0xbf, 0x00, 0xc0, 0x00, 0xc3, 0x70, 0x01, 0x00, 0xc4, 0x71, 0x01, 0x00, 0xc5, 0x72,
    0x01, 0x00, 0xd0, 0xd0, 0x01, 0x00, 0xd1, 0x00, 0xe7, 0xe7, 0x01, 0x00, 0xe8, 0xe7, 0x01, 0x00,
    0xe9, 0x00, 0xf0, 0x00, 0xf1, 0x6d, 0x01, 0x00, 0xf3, 0x00, 0x00,
};

static SeerStatus o3logon_login(SeerConn *conn, const SeerConnParams *params);
static SeerStatus o8i_login(SeerConn *conn, const SeerConnParams *params);

SeerStatus seer_ttc_login(SeerConn *conn, const SeerConnParams *params,
                          SeerAuthChallenge *out_challenge)
{
  memset(out_challenge, 0, sizeof *out_challenge);

  uint8_t *resp = NULL;
  size_t rlen = 0;
  SeerStatus st;

  /* --- TTI_PRO: protocol negotiation --- */
  st = seer_ttc_send(conn, PRO_MSG, sizeof PRO_MSG);
  if (st != SEER_OK)
    return st;
  st = seer_ttc_recv(conn, &resp, &rlen);
  if (st != SEER_OK)
    return st;
  uint8_t server_fv = 0;
  bool req_bnd = false, str32k = false;
  int major = 0;
  st = parse_pro(resp, rlen, &server_fv, &req_bnd, &str32k, &major);
  free(resp);
  /* Oracle 8i (8.1.x) carries no caps to negotiate: pin field version 2, as
   * 9i, and take the 8i login and statement dialect (seerdb §19.8). */
  if ((st != SEER_OK || server_fv == 0) && major == 8) {
    conn->is_8i = true;
    server_fv = TTC_FIELD_VERSION_9_2;
    st = SEER_OK;
  }
  if (st == SEER_OK && server_fv == 0)
    st = SEER_EPROTO;
  if (st != SEER_OK) {
    seer_log(SEER_LOG_ERROR, "ttc: could not parse PRO reply");
    return st;
  }
  conn->req_boundaries = req_bnd; /* §35: explicit request-boundary support */
  conn->max_string_size = str32k ? 32767 : 4000;
  conn->server_field_version = server_fv;
  seer_log(SEER_LOG_DEBUG, "ttc: server max string size %u", conn->max_string_size);
  /* Advertise up to TTC_FIELD_VERSION_MAX (the biggest version whose data path
   * is complete); SEER_MAX_FV overrides it. The server negotiates down: we use
   * min(server_fv, our_max), so 9i/10g/11g stay on the legacy fv path
   * untouched while 12c+ servers move onto the native fv path. */
  uint8_t max_fv = TTC_FIELD_VERSION_MAX;
  const char *fvenv = getenv("SEER_MAX_FV");
  if (fvenv != NULL) {
    int v = atoi(fvenv);
    if (v > 0 && v < 256)
      max_fv = (uint8_t)v;
  }
  conn->field_version = (server_fv < max_fv) ? server_fv : max_fv;
  seer_log(SEER_LOG_INFO, "TTC: protocol negotiated (server fv=%u, using fv=%u)", server_fv,
           conn->field_version);

  /* fv24 (23ai): fv >= 18 rejects the legacy OSESSKEY handshake, so bundle
   * PRO+DTY+OSESSKEY into one fast-auth message (PROTOCOL.md §20). */
  if (conn->field_version > TTC_FIELD_VERSION_23_1)
    return fast_auth_login(conn, params, out_challenge);

  /* --- TTI_DTY: data-type negotiation --- */
  if (conn->is_8i) {
    st = seer_ttc_send(conn, DTY_8I, sizeof DTY_8I);
  } else {
    SeerWriter dty;
    st = build_dty(&dty, conn->field_version, conn->supports_eor);
    if (st != SEER_OK)
      return st;
    st = seer_ttc_send(conn, dty.buf, dty.len);
    seer_writer_free(&dty);
  }
  if (st != SEER_OK)
    return st;
  st = seer_ttc_recv(conn, &resp, &rlen);
  if (st != SEER_OK)
    return st;
  if (rlen < 1 || resp[0] != TTI_DTY) {
    seer_log(SEER_LOG_ERROR, "ttc: unexpected reply to DTY (token %u)", rlen ? resp[0] : 0);
    free(resp);
    return SEER_EPROTO;
  }
  free(resp);
  seer_log(SEER_LOG_INFO, "TTC: data types negotiated");

  /* Oracle 9i (fv2): the pre-10g O3LOGON DES flow, not the O5LOGON TTI_SESS
   * challenge. o3logon_login authenticates the connection in place. */
  if (conn->is_8i)
    return o8i_login(conn, params);
  if (conn->field_version < TTC_FIELD_VERSION_10_2)
    return o3logon_login(conn, params);

  /* --- TTI_SESS: session setup -> auth challenge --- */
  SeerWriter sess;
  st = build_sess(conn, params, &sess);
  if (st != SEER_OK)
    return st;
  st = seer_ttc_send(conn, sess.buf, sess.len);
  seer_writer_free(&sess);
  if (st != SEER_OK)
    return st;
  st = seer_ttc_recv(conn, &resp, &rlen);
  if (st != SEER_OK)
    return st;
  st = parse_challenge(resp, rlen, out_challenge);
  free(resp);
  if (st != SEER_OK)
    return st;

  seer_log(SEER_LOG_INFO, "TTC: auth challenge received (sesskey=%zu, salt=%zu bytes)",
           out_challenge->sesskey_len, out_challenge->salt_len);
  return SEER_OK;
}

/* -------------------------------------------------------------- TTI_AUTH */

/* Uppercase-hex encode into a fresh NUL-terminated string. */
static char *hex_upper(const uint8_t *in, size_t n)
{
  static const char digits[] = "0123456789ABCDEF";
  char *s = malloc(2 * n + 1);
  if (s == NULL)
    return NULL;
  for (size_t i = 0; i < n; i++) {
    s[2 * i] = digits[in[i] >> 4];
    s[2 * i + 1] = digits[in[i] & 0x0F];
  }
  s[2 * n] = '\0';
  return s;
}

/* O3LOGON (Oracle 9i, field version 2): the pre-10g DES thin authenticator, the
 * path the Oracle JDBC thin driver uses against 9i. Phase 1 (TTI_3LOGA) sends the
 * username; the server returns an 8-byte session key as positional ASCII-hex in an
 * RPA. Phase 2 (TTI_3LOGON) sends AUTH_PASSWORD = upper-hex(DES-encrypt the padded
 * password under the recovered session key) + decimal pad count. A clean OER
 * (code 0/1403) means authenticated - there is no separate TTI_AUTH step, and no
 * AUTH_SVR_RESPONSE to validate. The fixed message skeletons and env strings match
 * the JDBC thin driver byte-for-byte (seerdb/seerdb#90). */
static const uint8_t O3_MID1[] = {
    /* 31 bytes (seerdb _O3_MID1) */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x07, 0x01, 0x01, 0x03, 0x01, 0x01, 0x04, 0x02,
    0x10, 0x00, 0x00, 0x00, 0x01, 0x01, 0x10, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x10, 0x01,
};
static const uint8_t O3_MID2[] = {
    /* 29 bytes (seerdb _O3_MID2) */
    0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x07, 0x01, 0x01, 0x03, 0x01, 0x01, 0x04, 0x02, 0x10,
    0x00, 0x00, 0x00, 0x01, 0x01, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x10, 0x00,
};
static const char O3_ENV[] = "unknowno9irootJDBC Thin Client";

static SeerStatus o3logon_login(SeerConn *conn, const SeerConnParams *params)
{
  const char *user = (params->username && params->username[0]) ? params->username : "";
  const char *pass = params->password ? params->password : "";
  size_t ulen = strlen(user);

  /* --- Phase 1: TTI_3LOGA, fetch the session key --- */
  SeerWriter w;
  if (!seer_writer_init(&w, 96 + ulen))
    return SEER_ENOMEM;
  seer_ttc_fun_header(conn, &w, TTI_3LOGA);
  seer_writer_u8(&w, 1);
  seer_enc_sb4(&w, (uint32_t)ulen);
  seer_writer_bytes(&w, O3_MID1, sizeof O3_MID1);
  seer_writer_bytes(&w, (const uint8_t *)user, ulen);
  seer_writer_bytes(&w, (const uint8_t *)O3_ENV, sizeof O3_ENV - 1);
  if (!seer_writer_ok(&w)) {
    seer_writer_free(&w);
    return SEER_ENOMEM;
  }
  SeerStatus st = seer_ttc_send(conn, w.buf, w.len);
  seer_writer_free(&w);
  if (st != SEER_OK)
    return st;

  uint8_t *resp = NULL;
  size_t rlen = 0;
  st = seer_ttc_recv(conn, &resp, &rlen);
  if (st != SEER_OK)
    return st;
  /* RPA: [TTI_RPA][ub1 count][ub1 hexlen][<hexlen ASCII-hex chars>]. */
  if (rlen < 3 || resp[0] != TTI_RPA) {
    seer_log(SEER_LOG_ERROR, "o3logon: phase-1 reply not RPA (token %u)", rlen ? resp[0] : 0);
    free(resp);
    return SEER_EPROTO;
  }
  size_t hexlen = resp[2];
  if (hexlen == 0 || 3 + hexlen > rlen) {
    free(resp);
    return SEER_EPROTO;
  }
  uint8_t *sesskey = NULL;
  size_t skl = 0;
  st = hex_decode(resp + 3, hexlen, &sesskey, &skl);
  free(resp);
  if (st != SEER_OK)
    return st;

  /* --- AUTH_PASSWORD = upper-hex(DES(session key, padded password)) + pad --- */
  uint8_t verifier[8];
  seer_des_verifier(user, pass, verifier);
  uint8_t *authpass = NULL;
  size_t apn = 0;
  st = seer_o3logon(sesskey, skl, verifier, pass, &authpass, &apn);
  free(sesskey);
  if (st != SEER_OK)
    return st;
  char *hexpw = hex_upper(authpass, apn);
  free(authpass);
  if (hexpw == NULL)
    return SEER_ENOMEM;
  size_t pl = strlen(pass);
  unsigned padcount = (unsigned)((8 - (pl % 8)) % 8);
  char pwdfield[300];
  int pwn = snprintf(pwdfield, sizeof pwdfield, "%s%u", hexpw, padcount);
  free(hexpw);
  if (pwn < 0 || (size_t)pwn >= sizeof pwdfield)
    return SEER_EPROTO;
  size_t pwlen = (size_t)pwn;

  /* --- Phase 2: TTI_3LOGON, send AUTH_PASSWORD --- */
  if (!seer_writer_init(&w, 128 + ulen + pwlen))
    return SEER_ENOMEM;
  seer_ttc_fun_header(conn, &w, TTI_3LOGON);
  seer_writer_u8(&w, 1);
  seer_enc_sb4(&w, (uint32_t)ulen);
  seer_writer_u8(&w, 1);
  seer_enc_sb4(&w, (uint32_t)pwlen);
  seer_writer_bytes(&w, O3_MID2, sizeof O3_MID2);
  seer_writer_bytes(&w, (const uint8_t *)user, ulen);
  seer_writer_bytes(&w, (const uint8_t *)pwdfield, pwlen);
  seer_writer_bytes(&w, (const uint8_t *)O3_ENV, sizeof O3_ENV - 1);
  if (!seer_writer_ok(&w)) {
    seer_writer_free(&w);
    return SEER_ENOMEM;
  }
  st = seer_ttc_send(conn, w.buf, w.len);
  seer_writer_free(&w);
  if (st != SEER_OK)
    return st;

  st = seer_ttc_recv(conn, &resp, &rlen);
  if (st != SEER_OK)
    return st;
  /* Short pre-10g OER: token, then ub4 call_status, seq, rowcount, then the ub4
   * ORA code (no batch-error arrays, no message). 0 / 1403 = authenticated. */
  if (rlen < 1 || resp[0] != TTI_OER) {
    seer_log(SEER_LOG_ERROR, "o3logon: phase-2 reply not OER (token %u)", rlen ? resp[0] : 0);
    free(resp);
    return SEER_EPROTO;
  }
  SeerReader r;
  seer_reader_init(&r, resp + 1, rlen - 1);
  (void)seer_dec_sb4(&r); /* call_status */
  (void)seer_dec_sb4(&r); /* seq         */
  (void)seer_dec_sb4(&r); /* rowcount    */
  int64_t code = seer_dec_sb4(&r);
  free(resp);
  if (!seer_reader_ok(&r))
    return SEER_EPROTO;
  if (code != 0 && code != 1403) {
    seer_log(SEER_LOG_ERROR, "o3logon: authentication failed (ORA-%05ld)", (long)code);
    return SEER_EDB;
  }
  conn->authenticated = true;
  seer_log(SEER_LOG_INFO, "TTC: authenticated (O3LOGON / 9i, fv=%u)", conn->field_version);
  return SEER_OK;
}

/* ------------------------------------------------------- Oracle 8i login */

/* 8i's login integers are fixed-width little-endian (8i is x86), not the
 * variable-width TTC form. */
static void o8i_le32(SeerWriter *w, uint32_t v)
{
  for (int i = 0; i < 4; i++)
    seer_writer_u8(w, (uint8_t)(v >> (8 * i)));
}

/* The longest informational value an 8i key-value field carries: its ub1
 * length stops at 252 - 253..255 are TTC markers, and 8.1.7 fails the login
 * on them (seerdb #1773). */
#define O8I_INFO_VALUE_MAX 252

/* One AUTH_ pair at 8i's widths (seerdb _AUTH_PAIR): a ub4 key length and the
 * key as a value (ub1 length + bytes), a ub4 value length and the value - none
 * at all when empty, as 8.1.7 writes one - then a ub4 flags word (0). */
static void o8i_pair(SeerWriter *w, const char *key, const char *val)
{
  size_t kl = strlen(key), vl = strlen(val);
  if (vl > O8I_INFO_VALUE_MAX)
    vl = O8I_INFO_VALUE_MAX;
  o8i_le32(w, (uint32_t)kl);
  seer_writer_u8(w, (uint8_t)kl);
  seer_writer_bytes(w, (const uint8_t *)key, kl);
  o8i_le32(w, (uint32_t)vl);
  if (vl > 0) {
    seer_writer_u8(w, (uint8_t)vl);
    seer_writer_bytes(w, (const uint8_t *)val, vl);
  }
  o8i_le32(w, 0);
}

/* Build one 8i login call (seerdb _AUTH_HEAD at the 8i codec's widths):
 * OSESSKEY (TTI_SESS, mode 1) or OAUTH (TTI_AUTH, mode 0x101). A pointer, the
 * user's ub4 length, the ub4 mode, a pointer, the ub4 pair count, two
 * pointers, the user as a value, then the pairs: AUTH_PASSWORD first when
 * given, the informational ones, and AUTH_ACL on the OAUTH. */
SeerStatus seer_o8i_build_login(SeerConn *conn, SeerWriter *w, uint8_t op, const char *user,
                                uint32_t mode, const char *password_field, const char *host,
                                const char *pid)
{
  size_t ulen = strlen(user);
  if (ulen > O8I_INFO_VALUE_MAX)
    return SEER_EPARAM;
  uint32_t npairs = 3 + (password_field != NULL ? 2 : 0);
  if (!seer_writer_init(w, 256 + ulen + strlen(host)))
    return SEER_ENOMEM;
  seer_ttc_fun_header(conn, w, op);
  seer_writer_u8(w, 1); /* pointer */
  o8i_le32(w, (uint32_t)ulen);
  o8i_le32(w, mode);
  seer_writer_u8(w, 1); /* pointer */
  o8i_le32(w, npairs);
  seer_writer_u8(w, 1); /* pointers */
  seer_writer_u8(w, 1);
  seer_writer_u8(w, (uint8_t)ulen);
  seer_writer_bytes(w, (const uint8_t *)user, ulen);
  if (password_field != NULL)
    o8i_pair(w, "AUTH_PASSWORD", password_field);
  o8i_pair(w, "AUTH_PROGRAM_NM", "seerodbc");
  o8i_pair(w, "AUTH_MACHINE", host);
  o8i_pair(w, "AUTH_PID", pid);
  if (password_field != NULL)
    o8i_pair(w, "AUTH_ACL", "8000");
  if (!seer_writer_ok(w)) {
    seer_writer_free(w);
    return SEER_ENOMEM;
  }
  return SEER_OK;
}

static SeerStatus o8i_login_call(SeerConn *conn, uint8_t op, const char *user, uint32_t mode,
                                 const char *password_field)
{
  char host[256];
  if (gethostname(host, sizeof host - 1) != 0)
    strcpy(host, "localhost");
  host[sizeof host - 1] = '\0';
  char pid[16];
  snprintf(pid, sizeof pid, "%ld", (long)getpid());
  SeerWriter w;
  SeerStatus st = seer_o8i_build_login(conn, &w, op, user, mode, password_field, host, pid);
  if (st != SEER_OK)
    return st;
  st = seer_ttc_send(conn, w.buf, w.len);
  seer_writer_free(&w);
  return st;
}

/* Read an 8i login value: a ub1 length and the bytes, or 0xFE then ub1-length
 * chunks to a zero length. Returns the bytes (malloc'd, NUL-terminated). */
static SeerStatus o8i_read_value(const uint8_t *b, size_t n, size_t *pos, char **out)
{
  *out = NULL;
  if (*pos >= n)
    return SEER_EPROTO;
  SeerWriter acc;
  if (!seer_writer_init(&acc, 32))
    return SEER_ENOMEM;
  uint8_t len = b[(*pos)++];
  if (len != 0xFE) {
    if (*pos + len > n) {
      seer_writer_free(&acc);
      return SEER_EPROTO;
    }
    seer_writer_bytes(&acc, b + *pos, len);
    *pos += len;
  } else {
    for (;;) {
      if (*pos >= n) {
        seer_writer_free(&acc);
        return SEER_EPROTO;
      }
      uint8_t cl = b[(*pos)++];
      if (cl == 0)
        break;
      if (*pos + cl > n) {
        seer_writer_free(&acc);
        return SEER_EPROTO;
      }
      seer_writer_bytes(&acc, b + *pos, cl);
      *pos += cl;
    }
  }
  seer_writer_u8(&acc, 0);
  if (!seer_writer_ok(&acc)) {
    seer_writer_free(&acc);
    return SEER_ENOMEM;
  }
  *out = (char *)acc.buf;
  return SEER_OK;
}

static uint32_t o8i_rd32(const uint8_t *p)
{
  return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

/* The value of `key` in an 8i login reply (seerdb _PRE10_AUTH_REPLY): TTI_RPA,
 * a ub2 pair count, the pairs at _AUTH_PAIR's 8i widths. A key's length may
 * count a NUL terminator (8.1.7's AUTH_NLS_ keys), so it is compared without
 * one. SEER_OK with *val NULL when the reply is pairs but lacks the key. */
SeerStatus seer_o8i_auth_value(const uint8_t *b, size_t n, const char *key, char **val)
{
  *val = NULL;
  if (n < 3 || b[0] != TTI_RPA)
    return SEER_EPROTO;
  size_t pos = 1;
  unsigned count = (unsigned)(b[pos] | b[pos + 1] << 8);
  pos += 2;
  for (unsigned i = 0; i < count; i++) {
    char *k = NULL, *v = NULL;
    if (pos + 4 > n)
      return SEER_EPROTO;
    uint32_t kl = o8i_rd32(b + pos);
    pos += 4;
    if (kl > 0 && o8i_read_value(b, n, &pos, &k) != SEER_OK)
      return SEER_EPROTO;
    if (pos + 4 > n) {
      free(k);
      return SEER_EPROTO;
    }
    uint32_t vl = o8i_rd32(b + pos);
    pos += 4;
    if (vl > 0 && o8i_read_value(b, n, &pos, &v) != SEER_OK) {
      free(k);
      return SEER_EPROTO;
    }
    if (pos + 4 > n) {
      free(k);
      free(v);
      return SEER_EPROTO;
    }
    pos += 4; /* flags */
    if (*val == NULL && k != NULL && strcmp(k, key) == 0) {
      *val = v != NULL ? v : strdup("");
      v = NULL;
    }
    free(k);
    free(v);
  }
  return SEER_OK;
}

/* The ORA code of an 8i status (TTI_OER, ub4 LE rows, ub2 LE code; seerdb
 * _O8I_STATUS), 0 if `b` is not one. */
static int64_t o8i_status_code(const uint8_t *b, size_t n)
{
  if (n < 7 || b[0] != TTI_OER)
    return 0;
  return (int64_t)(b[5] | b[6] << 8);
}

/* Oracle 8i's O3LOGON (seerdb PROTOCOL.md §19.8): 9i's DES crypto, carried in
 * the 10g-style OSESSKEY / OAUTH envelope at 8i's fixed little-endian widths
 * (9i's positional TTI_3LOGA draws an OER on 8i). Phase 1 returns the 8-byte
 * session key as AUTH_SESSKEY (ASCII hex); phase 2 sends AUTH_PASSWORD =
 * upper-hex(DES blocks) + the decimal pad count, and a reply of pairs - not a
 * status - means authenticated; there is no server proof to check. */
static SeerStatus o8i_login(SeerConn *conn, const SeerConnParams *params)
{
  const char *user = (params->username && params->username[0]) ? params->username : "";
  const char *pass = params->password ? params->password : "";

  SeerStatus st = o8i_login_call(conn, TTI_SESS, user, 1, NULL);
  if (st != SEER_OK)
    return st;
  uint8_t *resp = NULL;
  size_t rlen = 0;
  st = seer_ttc_recv(conn, &resp, &rlen);
  if (st != SEER_OK)
    return st;
  char *skhex = NULL;
  st = seer_o8i_auth_value(resp, rlen, "AUTH_SESSKEY", &skhex);
  int64_t code = o8i_status_code(resp, rlen);
  free(resp);
  if (st != SEER_OK || skhex == NULL) {
    free(skhex);
    seer_log(SEER_LOG_ERROR, "o8i: no AUTH_SESSKEY in the OSESSKEY reply (ORA-%05ld)", (long)code);
    return code ? SEER_EAUTH : SEER_EPROTO;
  }
  uint8_t *sesskey = NULL;
  size_t skl = 0;
  st = hex_decode((const uint8_t *)skhex, strlen(skhex), &sesskey, &skl);
  free(skhex);
  if (st != SEER_OK)
    return st;

  uint8_t verifier[8];
  seer_des_verifier(user, pass, verifier);
  uint8_t *authpass = NULL;
  size_t apn = 0;
  st = seer_o3logon(sesskey, skl, verifier, pass, &authpass, &apn);
  free(sesskey);
  if (st != SEER_OK)
    return st;
  char *hexpw = hex_upper(authpass, apn);
  free(authpass);
  if (hexpw == NULL)
    return SEER_ENOMEM;
  char pwdfield[300];
  int pwn =
      snprintf(pwdfield, sizeof pwdfield, "%s%u", hexpw, (unsigned)((8 - (strlen(pass) % 8)) % 8));
  free(hexpw);
  if (pwn < 0 || (size_t)pwn >= sizeof pwdfield)
    return SEER_EPROTO;

  st = o8i_login_call(conn, TTI_AUTH, user, 0x101, pwdfield);
  if (st != SEER_OK)
    return st;
  st = seer_ttc_recv(conn, &resp, &rlen);
  if (st != SEER_OK)
    return st;
  if (rlen < 1 || resp[0] != TTI_RPA) {
    code = o8i_status_code(resp, rlen);
    free(resp);
    seer_log(SEER_LOG_ERROR, "o8i: authentication failed (ORA-%05ld)", (long)code);
    return SEER_EAUTH;
  }
  char *ver = NULL;
  if (seer_o8i_auth_value(resp, rlen, "AUTH_VERSION_NO", &ver) == SEER_OK && ver != NULL)
    conn->server_release = (uint32_t)strtoul(ver, NULL, 10);
  free(ver);
  free(resp);
  conn->authenticated = true;
  seer_log(SEER_LOG_INFO, "TTC: authenticated (O3LOGON / 8i, release %u.%u.%u)",
           conn->server_release >> 24, conn->server_release >> 20 & 0x0F,
           conn->server_release >> 12 & 0xFF);
  return SEER_OK;
}

/* Build the TTI_AUTH message for whichever verifier variant the server
 * offered, and return the connection key (16/24/32 bytes) plus its length for
 * validating the server's response. */
static SeerStatus build_auth(SeerConn *c, const SeerConnParams *p, const SeerAuthChallenge *ch,
                             SeerWriter *w, uint8_t conn_key[32], size_t *conn_key_len)
{
  char ubuf[256];
  size_t schema_len;
  const char *proxy_schema =
      proxy_split((p->username && *p->username) ? p->username : "", ubuf, sizeof ubuf, &schema_len);
  const char *user = ubuf;
  const char *password = p->password ? p->password : "";

  SeerO5Logon lo;
  SeerStatus st = seer_o5logon(ch->sesskey, ch->sesskey_len, ch->salt, ch->salt_len, ch->csk_salt,
                               ch->csk_salt_len, user, password, &lo);
  if (st == SEER_ENOTIMPL) {
    seer_log(SEER_LOG_ERROR,
             "auth: unsupported verifier scheme "
             "(salt=%s, csk_salt=%s)",
             ch->salt ? "present" : "absent", ch->csk_salt ? "present" : "absent");
    return st;
  }
  if (st != SEER_OK)
    return st;

  char *passhex = hex_upper(lo.auth_pass, lo.auth_pass_len);
  char *sesshex = hex_upper(lo.auth_sess, lo.auth_sess_len);
  char *speedyhex = lo.speedy_key ? hex_upper(lo.speedy_key, lo.speedy_key_len) : NULL;
  bool has_speedy = (lo.speedy_key != NULL);
  memcpy(conn_key, lo.conn_key, lo.conn_key_len);
  *conn_key_len = lo.conn_key_len;
  seer_o5logon_free(&lo);
  if (passhex == NULL || sesshex == NULL || (has_speedy && speedyhex == NULL)) {
    free(passhex);
    free(sesshex);
    free(speedyhex);
    return SEER_ENOMEM;
  }

  size_t ulen = strlen(user);

  st = SEER_ENOMEM;
  if (!seer_writer_init(w, 512))
    goto out;

  seer_ttc_fun_header(c, w, TTI_AUTH);
  seer_writer_u8(w, 1);
  seer_enc_sb4(w, (uint32_t)ulen); /* user length              */
  /* fv24 phase-two auth adds the 0x20000 logon-mode flag (else ORA-03120). */
  uint32_t logon_mode = 1 | 256; /* password | O5LOGON       */
  if (c->field_version > TTC_FIELD_VERSION_23_1)
    logon_mode |= 0x20000;
  seer_enc_sb4(w, logon_mode);
  /* DRCP (#130): a connection class and/or session purity request a pooled
   * session. When DRCP is requested without an explicit purity, a standalone
   * connection defaults to NEW (matching python-oracledb). */
  const char *cclass = (p->cclass && p->cclass[0]) ? p->cclass : NULL;
  int purity = p->purity;
  if ((cclass || purity) && purity == 0)
    purity = SEER_PURITY_NEW;

  seer_writer_u8(w, 1);
  seer_enc_sb4(w, (uint32_t)((has_speedy ? 3 : 2) + (proxy_schema ? 1 : 0) + (cclass ? 1 : 0) +
                             (purity ? 1 : 0))); /* KV count */
  seer_writer_u8(w, 1);
  seer_writer_u8(w, 1);
  if (c->field_version >= TTC_FIELD_VERSION_12_1) {
    seer_writer_u8(w, (uint8_t)ulen); /* 12c+: length-prefixed username */
    seer_writer_bytes(w, user, ulen);
  } else {
    seer_writer_bytes(w, user, ulen); /* 11g: raw (read via UserLen) */
  }
  /* Order matters: AUTH_PASSWORD, then AUTH_PBKDF2_SPEEDY_KEY (12c), then
   * AUTH_SESSKEY (the last pair carries the trailing flag). */
  seer_enc_kv(w, "AUTH_PASSWORD", 13, passhex, strlen(passhex), 0,
              c->field_version >= TTC_FIELD_VERSION_12_1);
  if (has_speedy)
    seer_enc_kv(w, "AUTH_PBKDF2_SPEEDY_KEY", 22, speedyhex, strlen(speedyhex), 0,
                c->field_version >= TTC_FIELD_VERSION_12_1);
  if (proxy_schema)
    seer_enc_kv(w, "PROXY_CLIENT_NAME", 17, proxy_schema, schema_len, 0,
                c->field_version >= TTC_FIELD_VERSION_12_1);
  seer_enc_kv(w, "AUTH_SESSKEY", 12, sesshex, strlen(sesshex), 1,
              c->field_version >= TTC_FIELD_VERSION_12_1);
  if (cclass)
    seer_enc_kv(w, "AUTH_KPPL_CONN_CLASS", 20, cclass, strlen(cclass), 0,
                c->field_version >= TTC_FIELD_VERSION_12_1);
  if (purity) {
    char ps[16];
    int pl = snprintf(ps, sizeof ps, "%d", purity);
    seer_enc_kv(w, "AUTH_KPPL_PURITY", 16, ps, (size_t)pl, 1,
                c->field_version >= TTC_FIELD_VERSION_12_1);
  }

  if (!seer_writer_ok(w)) {
    seer_writer_free(w);
    goto out;
  }
  st = SEER_OK;

out:
  free(passhex);
  free(sesshex);
  free(speedyhex);
  return st;
}

/* Parse the auth result RPA: validate AUTH_SVR_RESPONSE and decode the packed
 * AUTH_VERSION_NO. */
static SeerStatus parse_auth_result(const uint8_t *b, size_t n, const uint8_t *conn_key,
                                    size_t conn_key_len, uint32_t *server_release)
{
  *server_release = 0;
  if (n < 1)
    return SEER_EPROTO;
  if (b[0] == TTI_OER) {
    seer_log(SEER_LOG_ERROR, "auth: server rejected the login (ORA error)");
    return SEER_EAUTH;
  }
  if (b[0] != TTI_RPA) {
    seer_log(SEER_LOG_ERROR, "auth: unexpected reply token %u", b[0]);
    return SEER_EPROTO;
  }

  SeerReader r;
  seer_reader_init(&r, b + 1, n - 1);
  int64_t num = seer_dec_sb4(&r);
  if (num < 0 || num > 256 || !seer_reader_ok(&r))
    return SEER_EPROTO;

  uint8_t *resp = NULL;
  size_t resp_len = 0;
  bool have_resp = false;
  char verbuf[32] = {0};

  SeerStatus st = SEER_OK;
  for (int64_t i = 0; i < num; i++) {
    uint8_t *k = NULL, *v = NULL;
    size_t kl = 0, vl = 0;

    st = seer_dec_field(&r, &k, &kl);
    if (st != SEER_OK) {
      free(k);
      goto out;
    }
    st = seer_dec_field(&r, &v, &vl);
    if (st != SEER_OK) {
      free(k);
      free(v);
      goto out;
    }

    if (seer_reader_remaining(&r) > 0) {
      uint8_t flag = seer_reader_u8(&r);
      if (flag > 0)
        seer_reader_bytes(&r, flag);
    }

    if (key_is(k, kl, "AUTH_SVR_RESPONSE")) {
      st = hex_decode(v, vl, &resp, &resp_len);
      have_resp = true;
    } else if (key_is(k, kl, "AUTH_VERSION_NO") && vl > 0 && vl < sizeof verbuf) {
      memcpy(verbuf, v, vl);
      verbuf[vl] = '\0';
    }

    free(k);
    free(v);
    if (st != SEER_OK)
      goto out;
  }

  if (!seer_reader_ok(&r)) {
    st = SEER_EPROTO;
    goto out;
  }
  if (!have_resp || resp == NULL) {
    seer_log(SEER_LOG_ERROR, "auth: no AUTH_SVR_RESPONSE - authentication failed");
    st = SEER_EAUTH;
    goto out;
  }
  if (!seer_o5logon_validate(resp, resp_len, conn_key, conn_key_len)) {
    seer_log(SEER_LOG_ERROR, "auth: server response failed validation");
    st = SEER_EAUTH;
    goto out;
  }
  if (verbuf[0] != '\0')
    *server_release = (uint32_t)strtoul(verbuf, NULL, 10);
  st = SEER_OK;

out:
  free(resp);
  return st;
}

SeerStatus seer_ttc_authenticate(SeerConn *conn, const SeerConnParams *params,
                                 const SeerAuthChallenge *challenge)
{
  /* 9i (O3LOGON) already authenticated the connection in seer_ttc_login; there
   * is no separate O5LOGON-style TTI_AUTH step on the pre-10g path. */
  if (conn->authenticated)
    return SEER_OK;

  SeerWriter w;
  uint8_t conn_key[32];
  size_t conn_key_len = 0;
  SeerStatus st = build_auth(conn, params, challenge, &w, conn_key, &conn_key_len);
  if (st != SEER_OK)
    return st;

  st = seer_ttc_send(conn, w.buf, w.len);
  seer_writer_free(&w);
  if (st != SEER_OK) {
    memset(conn_key, 0, sizeof conn_key);
    return st;
  }

  uint8_t *resp = NULL;
  size_t rlen = 0;
  st = seer_ttc_recv(conn, &resp, &rlen);
  if (st != SEER_OK) {
    memset(conn_key, 0, sizeof conn_key);
    return st;
  }

  uint32_t release = 0;
  st = parse_auth_result(resp, rlen, conn_key, conn_key_len, &release);
  free(resp);
  memset(conn_key, 0, sizeof conn_key);
  if (st != SEER_OK)
    return st;

  conn->server_release = release;
  conn->authenticated = true;
  int v[5];
  seer_release_fields(release, v);
  seer_log(SEER_LOG_INFO, "TTC: authenticated (server release %d.%d.%d.%d.%d)", v[0], v[1], v[2],
           v[3], v[4]);
  return SEER_OK;
}

/* The five dotted fields of a release word (seerdb PROTOCOL.md, AUTH_VERSION_NO).
 * Before 18c: major (bits 24-31), minor (20-23), app (12-19), component (8-11),
 * platform (0-7). From 18c the release update's: major (24-31), update (16-23),
 * revision (12-15), increment (4-11), extension (0-3) - the older reading
 * gave 23ai's word as 23.1.162.0.0 instead of 23.26.2.0.0. */
void seer_release_fields(uint32_t r, int v[5])
{
  v[0] = (int)(r >> 24 & 0xFF);
  if (v[0] >= 18) {
    v[1] = (int)(r >> 16 & 0xFF);
    v[2] = (int)(r >> 12 & 0x0F);
    v[3] = (int)(r >> 4 & 0xFF);
    v[4] = (int)(r & 0x0F);
  } else {
    v[1] = (int)(r >> 20 & 0x0F);
    v[2] = (int)(r >> 12 & 0xFF);
    v[3] = (int)(r >> 8 & 0x0F);
    v[4] = (int)(r & 0xFF);
  }
}

/* Request-boundary (§35) piggyback helpers, used by the execute builder and the
 * commit/rollback path to ride an armed marker in front of the next call. */
void seer_ttc_session_state_piggyback(SeerWriter *w, uint8_t seq, uint8_t field_version,
                                      uint8_t state)
{
  seer_writer_u8(w, TTI_MSG_TYPE_PIGGYBACK);
  seer_writer_u8(w, TNS_FUNC_SESSION_STATE);
  seer_writer_u8(w, seq);
  if (field_version > TTC_FIELD_VERSION_23_1)
    seer_enc_sb4(w, 0); /* ub8 token (fv24) */
  seer_enc_sb4(w, (uint32_t)(state | TNS_SESSION_STATE_EXPLICIT_BOUNDARY));
}

void seer_ttc_flush_session_state(SeerConn *c, SeerWriter *w)
{
  if (c->session_state == 0)
    return;
  seer_ttc_session_state_piggyback(w, seer_ttc_next_seq(c), c->field_version, c->session_state);
  c->session_state = 0; /* one-shot */
}

/* Commit or rollback: a bare TTI_FUN call (§8), with any armed request-boundary
 * marker (§35) prepended. The response (STA/OER) is read to keep the stream in
 * sync; commit errors are rare and surface on the next operation. */
static SeerStatus seer_ttc_tran(SeerConn *conn, uint8_t func)
{
  if (conn == NULL || conn->t == NULL || !conn->authenticated)
    return SEER_EPARAM;
  SeerStatus st;
  if (conn->session_state != 0) {
    /* A request-boundary marker (§35) rides in front of this call. */
    SeerWriter w;
    if (!seer_writer_init(&w, 16))
      return SEER_ENOMEM;
    seer_ttc_flush_session_state(conn, &w);
    seer_writer_u8(&w, TTI_FUN);
    seer_writer_u8(&w, func);
    seer_writer_u8(&w, seer_ttc_next_seq(conn));
    if (conn->field_version > TTC_FIELD_VERSION_23_1)
      seer_writer_u8(&w, 0);
    if (!seer_writer_ok(&w)) {
      seer_writer_free(&w);
      return SEER_ENOMEM;
    }
    st = seer_ttc_send(conn, w.buf, w.len);
    seer_writer_free(&w);
  } else {
    uint8_t msg[4] = {TTI_FUN, func, seer_ttc_next_seq(conn), 0};
    size_t msglen = (conn->field_version > TTC_FIELD_VERSION_23_1) ? 4 : 3;
    st = seer_ttc_send(conn, msg, msglen);
  }
  if (st != SEER_OK)
    return st;
  uint8_t *resp = NULL;
  size_t rlen = 0;
  st = seer_ttc_recv(conn, &resp, &rlen);
  if (st != SEER_OK)
    return st;
  free(resp);
  /* An ordinary commit/rollback ends any active sessionless transaction (§31);
   * the server rides a SYNC piggyback on this response, harmlessly discarded. */
  conn->sessionless_active = false;
  return SEER_OK;
}

SeerStatus seer_request_begin(SeerConn *conn)
{
  if (conn == NULL)
    return SEER_EPARAM;
  if (!conn->req_boundaries)
    return SEER_ENOTIMPL; /* 10g/11g: server does not advertise it */
  if (conn->in_request)
    return SEER_EPARAM; /* a request is already open */
  /* Arm REQUEST_BEGIN; it rides in front of the next call (no round-trip). */
  conn->session_state = TNS_SESSION_STATE_REQUEST_BEGIN;
  conn->in_request = true;
  return SEER_OK;
}

SeerStatus seer_request_end(SeerConn *conn)
{
  if (conn == NULL)
    return SEER_EPARAM;
  if (!conn->req_boundaries)
    return SEER_ENOTIMPL;
  if (!conn->in_request)
    return SEER_OK; /* nothing open */
  if (conn->session_state != 0) {
    /* BEGIN was armed but never rode a call (no operation ran): nothing was
     * sent, so cancel it and send nothing. */
    conn->session_state = 0;
    conn->in_request = false;
    return SEER_OK;
  }
  /* Send REQUEST_END piggybacked on a rollback round-trip. */
  conn->session_state = TNS_SESSION_STATE_REQUEST_END;
  conn->in_request = false;
  return seer_rollback(conn);
}

SeerStatus seer_commit(SeerConn *conn)
{
  if (conn != NULL && conn->is_8i)
    return SEER_ENOTIMPL; /* 8i has no TTI_COMMIT: COMMIT rides its OALL8 */
  return seer_ttc_tran(conn, TTI_COMMIT);
}

SeerStatus seer_rollback(SeerConn *conn)
{
  if (conn != NULL && conn->is_8i)
    return SEER_ENOTIMPL; /* likewise ROLLBACK */
  return seer_ttc_tran(conn, TTI_ROLLBACK);
}

void seer_ttc_logoff(SeerConn *conn)
{
  if (conn == NULL || conn->t == NULL || !conn->authenticated)
    return;

  uint8_t msg[4] = {TTI_FUN, TTI_LOGOFF, seer_ttc_next_seq(conn), 0};
  size_t msglen = (conn->field_version > TTC_FIELD_VERSION_23_1) ? 4 : 3;
  if (seer_ttc_send(conn, msg, msglen) != SEER_OK)
    return;

  uint8_t *resp = NULL;
  size_t rlen = 0;
  if (seer_ttc_recv(conn, &resp, &rlen) == SEER_OK)
    free(resp);

  /* TNS EOF marker: an empty DATA packet with data flags 0x0040 (§10). */
  const uint8_t eof[2] = {0x00, 0x40};
  seer_packet_send(conn->t, TNS_PT_DATA, eof, sizeof eof);
}

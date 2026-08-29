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
#include "netcompat.h"   /* gethostname(): <unistd.h> on POSIX, Winsock on Windows */
#include "packet.h"
#include "reader.h"
#include "tns_consts.h"
#include "writer.h"

#include <openssl/crypto.h>   /* OPENSSL_cleanse */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ---------------------------------------------------------- static messages */

/* TTI_PRO request: token, version vector 6..0 (0-terminated), driver name. */
static const uint8_t PRO_MSG[] = {
    TTI_PRO, 6, 5, 4, 3, 2, 1, 0, 'p', 'y', 't', 'h', 'o', 'n', 0,
};

/* TTI_DTY capability arrays for field version 6 (11.2), byte-identical to the
 * reference client (see PROTOCOL.md §4.2). compile_caps[7] is the field
 * version. */
static const uint8_t COMPILE_CAPS[] = {
    0x06, 0x01, 0x00, 0x00, 0x6a, 0x01, 0x01, 0x06, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x00, 0x29, 0x90, 0x03, 0x07, 0x03,
    0x00, 0x01, 0x00, 0x4f, 0x01, 0x37, 0x04, 0x00, 0x00, 0x00,
    0x00, 0x0c, 0x00, 0x00, 0x06, 0x00, 0x01, 0x01,
};
static const uint8_t RUNTIME_CAPS[] = {
    0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

/* 12c+ capability arrays (the python-oracledb 21.1 base vector; the contents are
 * stable across 12c+ releases, only CCAP_FIELD_VERSION[7] differs, patched per
 * negotiated version). 53-byte compile / 11-byte runtime. */
static const uint8_t COMPILE_CAPS_12C[] = {
    0x06, 0x00, 0x00, 0x00, 0xea, 0x18, 0x00, 0x15, 0x01, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x29, 0x90, 0x03, 0x07, 0x03,
    0x00, 0x01, 0x00, 0xcf, 0x00, 0x00, 0x04, 0x01, 0x00, 0x00,
    0x00, 0x10, 0x00, 0x00, 0x0c, 0x20, 0x00, 0xb8, 0x00, 0x08,
    0x44, 0x00, 0x05, 0x00, 0x3e, 0x02, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x03,
};
static const uint8_t RUNTIME_CAPS_12C[] = {
    0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00,
};

/* The 12c+ datatype table is a flat list of UB2 (type, conv, repr) entries.
 * conv defaults to type and repr to 1, except the overrides below (repr 10 =
 * Oracle-native: NUMBER/DATE families). Ported from python-oracledb 4.0.1's
 * DATA_TYPES (verified by pyoracle against a 21c capture). */
static const uint16_t DTY_12C_TYPES[] = {
    1, 2, 8, 12, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 10, 11, 40,
    41, 117, 120, 290, 291, 292, 293, 294, 298, 299, 300, 301, 302, 303,
    304, 305, 306, 307, 308, 309, 310, 311, 312, 313, 315, 316, 317,
    318, 319, 320, 321, 322, 323, 327, 328, 329, 331, 333, 334, 335,
    336, 337, 338, 339, 340, 341, 342, 343, 344, 345, 346, 348, 349,
    354, 355, 359, 363, 380, 381, 382, 383, 384, 385, 386, 387, 388,
    389, 390, 391, 393, 394, 395, 396, 397, 398, 399, 400, 401, 404,
    405, 406, 407, 413, 414, 415, 416, 417, 418, 419, 420, 421, 422,
    423, 424, 425, 426, 427, 429, 430, 431, 432, 433, 449, 450, 454,
    455, 456, 457, 458, 459, 460, 461, 462, 463, 466, 467, 468, 469,
    470, 471, 472, 473, 474, 475, 476, 477, 478, 479, 480, 481, 482,
    483, 484, 485, 486, 490, 491, 492, 493, 494, 495, 496, 498, 499,
    500, 501, 502, 509, 510, 513, 514, 516, 517, 518, 519, 520, 521,
    522, 523, 524, 525, 526, 527, 528, 529, 530, 531, 532, 533, 534,
    535, 536, 537, 538, 539, 540, 541, 542, 543, 560, 565, 572, 573,
    574, 575, 576, 578, 563, 564, 579, 580, 581, 582, 583, 584, 585, 3,
    4, 5, 6, 7, 9, 15, 39, 68, 91, 94, 95, 96, 97, 100, 101, 102, 104,
    106, 108, 109, 110, 111, 112, 113, 114, 115, 116, 119, 198, 146,
    152, 153, 154, 155, 156, 172, 178, 179, 180, 181, 182, 183, 184,
    185, 186, 187, 188, 189, 190, 195, 196, 197, 208, 231, 232, 233,
    241, 252, 590, 591, 592, 613, 614, 615, 616, 611, 612, 593, 594,
    595, 596, 597, 598, 599, 600, 601, 602, 603, 604, 605, 622, 623,
    624, 625, 626, 627, 628, 629, 630, 631, 632, 637, 638, 636, 639,
    663, 640, 652, 646, 647, 127, 660, 661, 665, 669, 670,
};
/* (type, conv, repr) overrides; everything else is (type, type, 1). */
static const uint16_t DTY_12C_OVERRIDES[][3] = {
    {2,2,10},{12,12,10},{27,27,10},{3,2,10},{4,2,10},{5,1,1},{6,2,10},
    {7,2,10},{9,1,1},{15,1,1},{68,2,10},{91,2,10},{94,1,1},{95,23,1},
    {97,96,1},{104,11,1},{108,109,1},{110,111,1},{116,102,1},{152,2,10},
    {153,2,10},{154,2,10},{155,1,1},{156,12,10},{172,2,10},{184,12,10},
    {195,112,1},{196,113,1},{197,114,1},{232,231,1},{241,109,1},
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
    2, 2, 10, 0,   3, 2, 10, 0,   4, 2, 10, 0,   5, 1, 1, 0,
    6, 2, 10, 0,   7, 2, 10, 0,   9, 1, 1, 0,    12, 12, 10, 0,
    13, 0,  14, 0,
    15, 23, 1, 0,  16, 0, 17, 0, 18, 0, 19, 0, 20, 0, 21, 0, 22, 0,
    39, 120, 1, 0,
    58, 0,
    68, 2, 10, 0,  69, 0, 70, 0, 74, 0,
    6, 0,
    91, 2, 10, 0,  94, 1, 1, 0,   95, 23, 1, 0,
    96, 96, 1, 0,  97, 96, 1, 0,
    104, 11, 1, 0, 105, 0,
    108, 109, 1, 0, 110, 111, 1, 0,
    116, 102, 1, 0,
    118, 0, 119, 0, 121, 0, 122, 0, 123, 0, 136, 0,
    146, 146, 1, 0, 147, 0,
    152, 2, 10, 0, 153, 2, 10, 0, 154, 2, 10, 0,
    155, 1, 1, 0,  156, 12, 10, 0,
    172, 2, 10, 0,
    209, 0, 3, 0,
    0,
};

/* TNS_DATA payload = 2-byte data flags + a TTC message-body chunk. The final
 * (or only) packet carries data flags 0x0000; a non-final fragment carries
 * 0x0020 ("more data follows", §1.3). */
#define TTC_DATA_FLAG_FINAL 0x0000
#define TTC_DATA_FLAG_MORE  0x0020

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
        max_chunk = (c->sdu > TNS_HEADER_LEN + 2)
                    ? (size_t)c->sdu - TNS_HEADER_LEN - 2 : len;
    if (max_chunk == 0)
        max_chunk = len ? len : 1;

    size_t off = 0;
    do {
        size_t remaining = len - off;
        bool   last      = remaining <= max_chunk;
        size_t chunk     = last ? remaining : max_chunk;

        const uint8_t *payload = msg + off;
        size_t         plen    = chunk;
        uint8_t       *wrapped = NULL;
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
    const uint8_t interrupt[3] = { 0x01, 0x00, 0x03 };
    seer_packet_send(c->t, TNS_PT_MARKER, interrupt, sizeof interrupt);
}

/* Receive a complete TTC message, reassembling across TNS_DATA packets. Each
 * packet carries 2 data-flag bytes that are stripped; the server signals "more
 * fragments follow" by sizing a packet to exactly SDU-37 or SDU-81 (§1.3).
 * *out is malloc'd; caller frees. */
SeerStatus seer_ttc_recv(SeerConn *c, uint8_t **out, size_t *outlen)
{
    *out    = NULL;
    *outlen = 0;

    SeerWriter acc;
    if (!seer_writer_init(&acc, 512))
        return SEER_ENOMEM;

    bool sent_reset = false;   /* one client reset per break episode (§1.4) */

    c->in_call = true;         /* blocked waiting for the server: cancellable */
    for (;;) {
        uint8_t  type = 0;
        uint8_t *body = NULL;
        size_t   blen = 0;
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
                const uint8_t reset[3] = { 0x01, 0x00, 0x02 };
                seer_packet_send(c->t, TNS_PT_MARKER, reset, sizeof reset);
                sent_reset = true;
            }
            continue;
        }

        if (type != TNS_PT_DATA || blen < 2) {
            seer_log(SEER_LOG_ERROR, "ttc: expected DATA packet (got type %u, %zu bytes)",
                     type, blen);
            free(body);
            c->in_call = false;
            seer_writer_free(&acc);
            return SEER_EPROTO;
        }

        size_t total = blen + TNS_HEADER_LEN;          /* full TNS packet size */
        /* Each DATA body (after the 2 data-flag bytes) is an independent unit.
         * With ANO active it is encrypted + MAC'd, so decrypt/verify per packet
         * before reassembly concatenates the plaintext (§33.3). */
        if (c->ano != NULL) {
            uint8_t *plain = NULL;
            size_t   plen  = 0;
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
            seer_writer_bytes(&acc, body + 2, blen - 2);   /* drop data flags */
            free(body);
        }

        bool fragment = c->sdu > 0 &&
                        (total == (size_t)c->sdu - 37 || total == (size_t)c->sdu - 81);
        if (!fragment)
            break;
    }
    c->in_call = false;

    if (!seer_writer_ok(&acc)) {
        seer_writer_free(&acc);
        return SEER_ENOMEM;
    }
    *out    = acc.buf;
    *outlen = acc.len;
    return SEER_OK;
}

/* Native network encryption negotiation (§33). Runs before PRO, over the
 * plaintext session: send round 1 (offered algorithms), read the server's
 * selection, and — when encryption was selected — complete the Diffie-Hellman
 * exchange (round 2) and activate the connection's per-packet cipher + MAC. */
SeerStatus seer_ttc_ano_negotiate(SeerConn *c)
{
    uint8_t   *req = NULL;
    size_t     reqlen = 0;
    SeerStatus st = seer_ano_build_round1(&req, &reqlen);
    if (st != SEER_OK)
        return st;
    st = seer_ttc_send(c, req, reqlen);
    free(req);
    if (st != SEER_OK)
        return st;

    uint8_t *resp = NULL;
    size_t   resplen = 0;
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
        seer_log(SEER_LOG_INFO, "TNS: ANO negotiated, no encryption (enc=%u)",
                 ar.enc_id);
        seer_ano_response_free(&ar);
        return SEER_OK;
    }

    uint8_t *cpub = NULL, *sk = NULL;
    size_t   cpub_len = 0, sk_len = 0;
    st = seer_ano_dh(&ar, &cpub, &cpub_len, &sk, &sk_len);
    if (st != SEER_OK) {
        seer_ano_response_free(&ar);
        return st;
    }

    uint8_t *r2 = NULL;
    size_t   r2len = 0;
    st = seer_ano_build_round2(cpub, cpub_len, &r2, &r2len);
    if (st == SEER_OK) {
        st = seer_ttc_send(c, r2, r2len);   /* last plaintext packet */
        free(r2);
    }
    free(cpub);

    if (st == SEER_OK) {
        SeerAno *ch = NULL;
        st = seer_ano_channel_new(ar.enc_id, ar.int_id, sk, sk_len,
                                  ar.server_iv, ar.server_iv_len,
                                  /*client_side=*/true, &ch);
        if (st == SEER_OK) {
            c->ano = ch;   /* every DATA packet from PRO onward is now wrapped */
            seer_log(SEER_LOG_INFO, "TNS: ANO active (enc=%u integrity=%u)",
                     ar.enc_id, ar.int_id);
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
    c->seq = (uint8_t)(c->seq % 127 + 1);   /* wraps 127 -> 1 */
    return s;
}

void seer_ttc_fun_header(SeerConn *c, SeerWriter *w, uint8_t opcode)
{
    seer_writer_u8(w, TTI_FUN);
    seer_writer_u8(w, opcode);
    seer_writer_u8(w, seer_ttc_next_seq(c));
    /* fv24 (23ai): oracledb writes an extra pointer byte after the sequence
     * number on every function message (pyoracle _fun_header, PROTOCOL.md §20).
     * PRO/DTY/SESS keep their legacy headers - only post-PRO function calls. */
    if (c->field_version > TTC_FIELD_VERSION_23_1)
        seer_writer_u8(w, 0);
}

/* ------------------------------------------------------------- TTI_PRO/DTY */

/* Walk a TTI_PRO reply and pull out the server's TTC field version
 * (compile_caps[7]). Returns SEER_EPROTO on any bounds violation. */
static SeerStatus parse_pro(const uint8_t *b, size_t n, uint8_t *server_fv)
{
    size_t o = 0;
    if (n < 1 || b[0] != TTI_PRO)
        return SEER_EPROTO;
    o = 1;
    o += 1;                              /* server version byte */
    o += 1;                              /* trailing zero       */
    while (o < n && b[o] != 0)           /* NUL-terminated banner */
        o++;
    o += 1;                              /* the NUL itself */
    o += 2;                              /* charset id (LE) */
    o += 1;                              /* server flags    */
    if (o + 2 > n)
        return SEER_EPROTO;
    uint16_t numelem = (uint16_t)(b[o] | (b[o + 1] << 8));   /* little-endian */
    o += 2;
    o += (size_t)numelem * 5;            /* charset element array */
    if (o + 2 > n)
        return SEER_EPROTO;
    uint16_t fdolen = (uint16_t)((b[o] << 8) | b[o + 1]);    /* big-endian */
    o += 2;
    o += fdolen;
    if (o + 1 > n)
        return SEER_EPROTO;
    uint8_t cclen = b[o];
    o += 1;
    if (cclen < 8 || o + cclen > n)
        return SEER_EPROTO;
    *server_fv = b[o + 7];               /* CCAP_FIELD_VERSION */
    return SEER_OK;
}

/* Oracle 9i (fv2) minimal capabilities (pyoracle capability_arrays, fv<10g): all
 * zero except compile-cap index 17 = 0x03, and a single 0x02 runtime byte.
 * Critically CCAP_LOGON_TYPES (index 4) stays 0 - we must NOT advertise O5LOGON,
 * else 9i tries a verifier the account lacks and the O3LOGON path never engages
 * (the server errors instead of returning the session key). */
static const uint8_t O3_COMPILE_CAPS[21] = { [17] = 0x03 };
static const uint8_t O3_RUNTIME_CAPS[1]  = { 0x02 };

/* Build the TTI_DTY message (token, charset in/out, flag, caps, type table). */
static SeerStatus build_dty(SeerWriter *w, uint8_t fv)
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
        caps[7] = fv;                                      /* CCAP_FIELD_VERSION */
        seer_writer_u8(w, (uint8_t)sizeof caps);
        seer_writer_bytes(w, caps, sizeof caps);
        seer_writer_u8(w, (uint8_t)sizeof RUNTIME_CAPS_12C);
        seer_writer_bytes(w, RUNTIME_CAPS_12C, sizeof RUNTIME_CAPS_12C);
        write_dty_12c_table(w);
    } else {
        /* 9i (fv2) advertises the minimal pre-10g caps (no O5LOGON); 10g/11g use
         * the 11.2 vector. The charset flag + type table are shared. */
        const uint8_t *cc = COMPILE_CAPS;  size_t ccl = sizeof COMPILE_CAPS;
        const uint8_t *rc = RUNTIME_CAPS;  size_t rcl = sizeof RUNTIME_CAPS;
        if (fv < TTC_FIELD_VERSION_10_2) {
            cc = O3_COMPILE_CAPS;  ccl = sizeof O3_COMPILE_CAPS;
            rc = O3_RUNTIME_CAPS;  rcl = sizeof O3_RUNTIME_CAPS;
        }
        seer_writer_u8(w, (uint8_t)ccl);
        seer_writer_bytes(w, cc, ccl);
        seer_writer_u8(w, (uint8_t)rcl);
        seer_writer_bytes(w, rc, rcl);
        for (int x = 1; x <= 245; x++) {                   /* identity map */
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
static const char *proxy_split(const char *raw, char *ubuf, size_t bufsz,
                               size_t *schema_len)
{
    *schema_len = 0;
    size_t rl = strlen(raw);
    const char *lb = strchr(raw, '[');
    if (lb != NULL && lb != raw && rl > 0 && raw[rl - 1] == ']') {
        size_t ul = (size_t)(lb - raw);
        if (ul < bufsz) {
            memcpy(ubuf, raw, ul);
            ubuf[ul] = '\0';
            *schema_len = rl - ul - 2;       /* chars between [ and ] */
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
    char   ubuf[256];
    size_t schema_len;
    proxy_split((p->username && *p->username) ? p->username : "",
                ubuf, sizeof ubuf, &schema_len);
    const char *user = ubuf;
    size_t ulen = strlen(user);

    char host[256];
    if (gethostname(host, sizeof host - 1) != 0)
        strcpy(host, "localhost");
    host[sizeof host - 1] = '\0';

    char pid[16];
    snprintf(pid, sizeof pid, "%ld", (long)getpid());

    static const char APP[] = "seerodbc";

    if (!seer_writer_init(w, 256))
        return SEER_ENOMEM;

    bool is12c = c->field_version >= TTC_FIELD_VERSION_12_1;
    seer_writer_u8(w, TTI_FUN);
    seer_writer_u8(w, TTI_SESS);
    seer_writer_u8(w, seer_ttc_next_seq(c));
    seer_writer_u8(w, 1);
    seer_enc_sb4(w, (uint32_t)ulen);            /* user length          */
    seer_enc_sb4(w, 1);                         /* logon mode (basic)   */
    seer_writer_u8(w, 1);
    /* 12c+ sends 5 pairs (leading AUTH_TERMINAL) and a length-prefixed
     * username; 11g sends 4 pairs and the raw username (read via UserLen). */
    seer_enc_sb4(w, is12c ? 5 : 4);             /* key/value pairs      */
    seer_writer_u8(w, 1);
    seer_writer_u8(w, 1);
    if (is12c) {
        seer_writer_u8(w, (uint8_t)ulen);       /* length-prefixed username */
        seer_writer_bytes(w, user, ulen);
        seer_enc_kv(w, "AUTH_TERMINAL", 13, "unknown", 7, 0);
    } else {
        seer_writer_bytes(w, user, ulen);       /* raw username (11g) */
    }
    seer_enc_kv(w, "AUTH_PROGRAM_NM", 15, APP, sizeof APP - 1, 0);
    seer_enc_kv(w, "AUTH_MACHINE",    12, host, strlen(host),  0);
    seer_enc_kv(w, "AUTH_PID",         8, pid,  strlen(pid),   0);
    seer_enc_kv(w, "AUTH_SID",         8, user, ulen,          0);

    if (!seer_writer_ok(w)) {
        seer_writer_free(w);
        return SEER_ENOMEM;
    }
    return SEER_OK;
}

/* ----------------------------------------------------------- challenge KV */

static int hexval(uint8_t c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
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
        if (st != SEER_OK) { free(k); goto out; }
        st = seer_dec_field(&r, &v, &vl);
        if (st != SEER_OK) { free(k); free(v); goto out; }

        /* Skip the inter-pair trailer (flag byte + that many bytes). */
        if (seer_reader_remaining(&r) > 0) {
            uint8_t flag = seer_reader_u8(&r);
            if (flag > 0)
                seer_reader_bytes(&r, flag);
        }

        if      (key_is(k, kl, "AUTH_SESSKEY"))         st = hex_decode(v, vl, &ch->sesskey,  &ch->sesskey_len);
        else if (key_is(k, kl, "AUTH_VFR_DATA"))        st = hex_decode(v, vl, &ch->salt,     &ch->salt_len);
        else if (key_is(k, kl, "AUTH_PBKDF2_CSK_SALT")) st = hex_decode(v, vl, &ch->csk_salt, &ch->csk_salt_len);

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
    SeerStatus st = build_dty(&dty, conn->field_version);
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
    seer_writer_u8(&bundle, 1);                          /* version          */
    seer_writer_u8(&bundle, TNS_SERVER_CONVERTS_CHARS);
    seer_writer_u8(&bundle, 0);                          /* flag2            */
    seer_writer_bytes(&bundle, PRO_MSG, sizeof PRO_MSG);
    for (int i = 0; i < 5; i++)                          /* charset/flag/ncharset */
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
    size_t   rlen = 0;
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
        if (parse_challenge(resp + off, rlen - off, &tmp) == SEER_OK
            && tmp.sesskey_len > 0) {
            *ch = tmp;                                   /* move ownership   */
            st  = SEER_OK;
            break;
        }
        seer_auth_challenge_free(&tmp);
    }
    free(resp);
    if (st != SEER_OK)
        seer_log(SEER_LOG_ERROR, "fast-auth: no challenge RPA in bundled reply");
    else
        seer_log(SEER_LOG_INFO, "TTC: fast-auth challenge received (fv=%u)",
                 conn->field_version);
    return st;
}

static SeerStatus o3logon_login(SeerConn *conn, const SeerConnParams *params);

SeerStatus seer_ttc_login(SeerConn *conn, const SeerConnParams *params,
                          SeerAuthChallenge *out_challenge)
{
    memset(out_challenge, 0, sizeof *out_challenge);

    uint8_t *resp = NULL;
    size_t   rlen = 0;
    SeerStatus st;

    /* --- TTI_PRO: protocol negotiation --- */
    st = seer_ttc_send(conn, PRO_MSG, sizeof PRO_MSG);
    if (st != SEER_OK)
        return st;
    st = seer_ttc_recv(conn, &resp, &rlen);
    if (st != SEER_OK)
        return st;
    uint8_t server_fv = 0;
    st = parse_pro(resp, rlen, &server_fv);
    free(resp);
    if (st != SEER_OK) {
        seer_log(SEER_LOG_ERROR, "ttc: could not parse PRO reply");
        return st;
    }
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
    seer_log(SEER_LOG_INFO, "TTC: protocol negotiated (server fv=%u, using fv=%u)",
             server_fv, conn->field_version);

    /* fv24 (23ai): fv >= 18 rejects the legacy OSESSKEY handshake, so bundle
     * PRO+DTY+OSESSKEY into one fast-auth message (PROTOCOL.md §20). */
    if (conn->field_version > TTC_FIELD_VERSION_23_1)
        return fast_auth_login(conn, params, out_challenge);

    /* --- TTI_DTY: data-type negotiation --- */
    SeerWriter dty;
    st = build_dty(&dty, conn->field_version);
    if (st != SEER_OK)
        return st;
    st = seer_ttc_send(conn, dty.buf, dty.len);
    seer_writer_free(&dty);
    if (st != SEER_OK)
        return st;
    st = seer_ttc_recv(conn, &resp, &rlen);
    if (st != SEER_OK)
        return st;
    if (rlen < 1 || resp[0] != TTI_DTY) {
        seer_log(SEER_LOG_ERROR, "ttc: unexpected reply to DTY (token %u)",
                 rlen ? resp[0] : 0);
        free(resp);
        return SEER_EPROTO;
    }
    free(resp);
    seer_log(SEER_LOG_INFO, "TTC: data types negotiated");

    /* Oracle 9i (fv2): the pre-10g O3LOGON DES flow, not the O5LOGON TTI_SESS
     * challenge. o3logon_login authenticates the connection in place. */
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
        s[2 * i]     = digits[in[i] >> 4];
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
 * the JDBC thin driver byte-for-byte (pyoracle #90). */
static const uint8_t O3_MID1[] = {   /* 31 bytes (pyoracle _O3_MID1) */
    0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x01,0x07,0x01,0x01,0x03,0x01,0x01,0x04,0x02,
    0x10,0x00,0x00,0x00,0x01,0x01,0x10,0x00,0x00,0x00,0x00,0x01,0x01,0x10,0x01,
};
static const uint8_t O3_MID2[] = {   /* 29 bytes (pyoracle _O3_MID2) */
    0x00,0x00,0x00,0x00,0x01,0x01,0x07,0x01,0x01,0x03,0x01,0x01,0x04,0x02,0x10,0x00,
    0x00,0x00,0x01,0x01,0x10,0x00,0x00,0x00,0x00,0x00,0x01,0x10,0x00,
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
    if (!seer_writer_ok(&w)) { seer_writer_free(&w); return SEER_ENOMEM; }
    SeerStatus st = seer_ttc_send(conn, w.buf, w.len);
    seer_writer_free(&w);
    if (st != SEER_OK)
        return st;

    uint8_t *resp = NULL;
    size_t   rlen = 0;
    st = seer_ttc_recv(conn, &resp, &rlen);
    if (st != SEER_OK)
        return st;
    /* RPA: [TTI_RPA][ub1 count][ub1 hexlen][<hexlen ASCII-hex chars>]. */
    if (rlen < 3 || resp[0] != TTI_RPA) {
        seer_log(SEER_LOG_ERROR, "o3logon: phase-1 reply not RPA (token %u)",
                 rlen ? resp[0] : 0);
        free(resp);
        return SEER_EPROTO;
    }
    size_t hexlen = resp[2];
    if (hexlen == 0 || 3 + hexlen > rlen) { free(resp); return SEER_EPROTO; }
    uint8_t *sesskey = NULL;
    size_t   skl = 0;
    st = hex_decode(resp + 3, hexlen, &sesskey, &skl);
    free(resp);
    if (st != SEER_OK)
        return st;

    /* --- AUTH_PASSWORD = upper-hex(DES(session key, padded password)) + pad --- */
    uint8_t verifier[8];
    seer_des_verifier(user, pass, verifier);
    uint8_t *authpass = NULL;
    size_t   apn = 0;
    st = seer_o3logon(sesskey, skl, verifier, pass, &authpass, &apn);
    free(sesskey);
    if (st != SEER_OK)
        return st;
    char *hexpw = hex_upper(authpass, apn);
    free(authpass);
    if (hexpw == NULL)
        return SEER_ENOMEM;
    size_t   pl       = strlen(pass);
    unsigned padcount = (unsigned)((8 - (pl % 8)) % 8);
    char pwdfield[300];
    int  pwn = snprintf(pwdfield, sizeof pwdfield, "%s%u", hexpw, padcount);
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
    if (!seer_writer_ok(&w)) { seer_writer_free(&w); return SEER_ENOMEM; }
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
        seer_log(SEER_LOG_ERROR, "o3logon: phase-2 reply not OER (token %u)",
                 rlen ? resp[0] : 0);
        free(resp);
        return SEER_EPROTO;
    }
    SeerReader r;
    seer_reader_init(&r, resp + 1, rlen - 1);
    (void)seer_dec_sb4(&r);                 /* call_status */
    (void)seer_dec_sb4(&r);                 /* seq         */
    (void)seer_dec_sb4(&r);                 /* rowcount    */
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

/* Build the TTI_AUTH message for whichever verifier variant the server
 * offered, and return the connection key (16/24/32 bytes) plus its length for
 * validating the server's response. */
static SeerStatus build_auth(SeerConn *c, const SeerConnParams *p,
                             const SeerAuthChallenge *ch, SeerWriter *w,
                             uint8_t conn_key[32], size_t *conn_key_len)
{
    char        ubuf[256];
    size_t      schema_len;
    const char *proxy_schema = proxy_split(
        (p->username && *p->username) ? p->username : "", ubuf, sizeof ubuf, &schema_len);
    const char *user     = ubuf;
    const char *password = p->password ? p->password : "";

    SeerO5Logon lo;
    SeerStatus st = seer_o5logon(ch->sesskey, ch->sesskey_len,
                                 ch->salt, ch->salt_len,
                                 ch->csk_salt, ch->csk_salt_len,
                                 user, password, &lo);
    if (st == SEER_ENOTIMPL) {
        seer_log(SEER_LOG_ERROR, "auth: unsupported verifier scheme "
                 "(salt=%s, csk_salt=%s)",
                 ch->salt ? "present" : "absent",
                 ch->csk_salt ? "present" : "absent");
        return st;
    }
    if (st != SEER_OK)
        return st;

    char *passhex   = hex_upper(lo.auth_pass, lo.auth_pass_len);
    char *sesshex   = hex_upper(lo.auth_sess, lo.auth_sess_len);
    char *speedyhex = lo.speedy_key ? hex_upper(lo.speedy_key, lo.speedy_key_len) : NULL;
    bool  has_speedy = (lo.speedy_key != NULL);
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
    seer_enc_sb4(w, (uint32_t)ulen);            /* user length              */
    /* fv24 phase-two auth adds the 0x20000 logon-mode flag (else ORA-03120). */
    uint32_t logon_mode = 1 | 256;              /* password | O5LOGON       */
    if (c->field_version > TTC_FIELD_VERSION_23_1)
        logon_mode |= 0x20000;
    seer_enc_sb4(w, logon_mode);
    /* DRCP (#130): a connection class and/or session purity request a pooled
     * session. When DRCP is requested without an explicit purity, a standalone
     * connection defaults to NEW (matching python-oracledb). */
    const char *cclass = (p->cclass && p->cclass[0]) ? p->cclass : NULL;
    int         purity = p->purity;
    if ((cclass || purity) && purity == 0)
        purity = SEER_PURITY_NEW;

    seer_writer_u8(w, 1);
    seer_enc_sb4(w, (uint32_t)((has_speedy ? 3 : 2)
                               + (proxy_schema ? 1 : 0)
                               + (cclass ? 1 : 0) + (purity ? 1 : 0)));  /* KV count */
    seer_writer_u8(w, 1);
    seer_writer_u8(w, 1);
    if (c->field_version >= TTC_FIELD_VERSION_12_1) {
        seer_writer_u8(w, (uint8_t)ulen);       /* 12c+: length-prefixed username */
        seer_writer_bytes(w, user, ulen);
    } else {
        seer_writer_bytes(w, user, ulen);       /* 11g: raw (read via UserLen) */
    }
    /* Order matters: AUTH_PASSWORD, then AUTH_PBKDF2_SPEEDY_KEY (12c), then
     * AUTH_SESSKEY (the last pair carries the trailing flag). */
    seer_enc_kv(w, "AUTH_PASSWORD", 13, passhex, strlen(passhex), 0);
    if (has_speedy)
        seer_enc_kv(w, "AUTH_PBKDF2_SPEEDY_KEY", 22, speedyhex, strlen(speedyhex), 0);
    if (proxy_schema)
        seer_enc_kv(w, "PROXY_CLIENT_NAME", 17, proxy_schema, schema_len, 0);
    seer_enc_kv(w, "AUTH_SESSKEY",  12, sesshex, strlen(sesshex), 1);
    if (cclass)
        seer_enc_kv(w, "AUTH_KPPL_CONN_CLASS", 20, cclass, strlen(cclass), 0);
    if (purity) {
        char ps[16];
        int pl = snprintf(ps, sizeof ps, "%d", purity);
        seer_enc_kv(w, "AUTH_KPPL_PURITY", 16, ps, (size_t)pl, 1);
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
static SeerStatus parse_auth_result(const uint8_t *b, size_t n,
                                    const uint8_t *conn_key, size_t conn_key_len,
                                    uint32_t *server_release)
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
    size_t   resp_len = 0;
    bool     have_resp = false;
    char     verbuf[32] = { 0 };

    SeerStatus st = SEER_OK;
    for (int64_t i = 0; i < num; i++) {
        uint8_t *k = NULL, *v = NULL;
        size_t kl = 0, vl = 0;

        st = seer_dec_field(&r, &k, &kl);
        if (st != SEER_OK) { free(k); goto out; }
        st = seer_dec_field(&r, &v, &vl);
        if (st != SEER_OK) { free(k); free(v); goto out; }

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

    if (!seer_reader_ok(&r)) { st = SEER_EPROTO; goto out; }
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
    size_t  conn_key_len = 0;
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
    size_t   rlen = 0;
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
    conn->authenticated  = true;
    seer_log(SEER_LOG_INFO, "TTC: authenticated (server release %u.%u.%u.%u.%u)",
             (release >> 24) & 0xFF, (release >> 20) & 0x0F,
             (release >> 12) & 0xFF, (release >> 8) & 0x0F, release & 0xFF);
    return SEER_OK;
}

/* Commit or rollback: a bare TTI_FUN call (§8). The response (STA/OER) is read
 * to keep the stream in sync; commit errors are rare and surface on the next
 * operation. */
static SeerStatus seer_ttc_tran(SeerConn *conn, uint8_t func)
{
    if (conn == NULL || conn->t == NULL || !conn->authenticated)
        return SEER_EPARAM;
    uint8_t msg[4] = { TTI_FUN, func, seer_ttc_next_seq(conn), 0 };
    size_t  msglen = (conn->field_version > TTC_FIELD_VERSION_23_1) ? 4 : 3;
    SeerStatus st = seer_ttc_send(conn, msg, msglen);
    if (st != SEER_OK)
        return st;
    uint8_t *resp = NULL;
    size_t   rlen = 0;
    st = seer_ttc_recv(conn, &resp, &rlen);
    if (st != SEER_OK)
        return st;
    free(resp);
    return SEER_OK;
}

SeerStatus seer_commit(SeerConn *conn)
{
    return seer_ttc_tran(conn, TTI_COMMIT);
}

SeerStatus seer_rollback(SeerConn *conn)
{
    return seer_ttc_tran(conn, TTI_ROLLBACK);
}

void seer_ttc_logoff(SeerConn *conn)
{
    if (conn == NULL || conn->t == NULL || !conn->authenticated)
        return;

    uint8_t msg[4] = { TTI_FUN, TTI_LOGOFF, seer_ttc_next_seq(conn), 0 };
    size_t  msglen = (conn->field_version > TTC_FIELD_VERSION_23_1) ? 4 : 3;
    if (seer_ttc_send(conn, msg, msglen) != SEER_OK)
        return;

    uint8_t *resp = NULL;
    size_t   rlen = 0;
    if (seer_ttc_recv(conn, &resp, &rlen) == SEER_OK)
        free(resp);

    /* TNS EOF marker: an empty DATA packet with data flags 0x0040 (§10). */
    const uint8_t eof[2] = { 0x00, 0x40 };
    seer_packet_send(conn->t, TNS_PT_DATA, eof, sizeof eof);
}

/* Known-answer test for the request-boundary (session-state) piggyback encoder
 * (ttc.c, §35), pinned to seerdb's encode_session_state_piggyback and the bytes
 * cited in PROTOCOL.md §35.3 (validated live on 26ai).
 *
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#include "tns_consts.h"
#include "ttc.h"
#include "writer.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void check(const char *what, uint8_t seq, uint8_t fv, uint8_t state,
                  const uint8_t *exp, size_t explen)
{
    SeerWriter w;
    assert(seer_writer_init(&w, 16));
    seer_ttc_session_state_piggyback(&w, seq, fv, state);
    assert(seer_writer_ok(&w));
    if (w.len != explen || memcmp(w.buf, exp, explen) != 0) {
        fprintf(stderr, "FAIL %s: got %zu bytes\n", what, w.len);
        assert(0 && "piggyback vector mismatch");
    }
    seer_writer_free(&w);
}

int main(void)
{
    /* fv24 (> 23.1): carries the ub8 token (0). REQUEST_BEGIN|EXPLICIT = 0x44. */
    check("fv24 begin", 7, 24, TNS_SESSION_STATE_REQUEST_BEGIN,
          (const uint8_t[]){ 0x11, 0xb0, 0x07, 0x00, 0x01, 0x44 }, 6);
    /* REQUEST_END|EXPLICIT = 0x48. */
    check("fv24 end", 9, 24, TNS_SESSION_STATE_REQUEST_END,
          (const uint8_t[]){ 0x11, 0xb0, 0x09, 0x00, 0x01, 0x48 }, 6);
    /* fv == 23.1 (17), not > 23.1: no token. */
    check("fv17 begin", 7, TTC_FIELD_VERSION_23_1, TNS_SESSION_STATE_REQUEST_BEGIN,
          (const uint8_t[]){ 0x11, 0xb0, 0x07, 0x01, 0x44 }, 5);
    /* legacy 11g fv6. */
    check("fv6 end", 5, TTC_FIELD_VERSION_11_2, TNS_SESSION_STATE_REQUEST_END,
          (const uint8_t[]){ 0x11, 0xb0, 0x05, 0x01, 0x48 }, 5);

    printf("reqbound: all piggyback vectors match\n");
    return 0;
}

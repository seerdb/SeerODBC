/* Known-answer test for the sessionless-transaction TXN_SWITCH framing (§31),
 * pinned to seerdb's encode_tpc_switch. Sessionless begin/resume/suspend reuse
 * the XA switch builder with the magic format-id 0x4E5C3E, the SESSIONLESS flag,
 * and (for suspend) no xid — this fixes those novel bits byte-for-byte.
 *
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#include "conn.h"
#include "tns_consts.h"
#include "writer.h"

#include "seer/seertns.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static size_t unhex(const char *hex, uint8_t *out)
{
    size_t n = strlen(hex) / 2;
    for (size_t i = 0; i < n; i++) {
        unsigned b;
        if (sscanf(hex + 2 * i, "%2x", &b) != 1) { assert(0 && "bad hex"); }
        out[i] = (uint8_t)b;
    }
    return n;
}

/* Build a switch with a fresh conn at seq=7, fv=24 and compare to `hex`. */
static void check(const char *what, uint32_t op, const SeerXid *xid,
                  uint32_t flags, uint32_t timeout, const char *hex)
{
    struct SeerConn c;
    memset(&c, 0, sizeof c);
    c.seq = 7;
    c.field_version = 24;

    SeerWriter w;
    assert(seer_tpc_build_switch(&c, &w, op, xid, flags, timeout) == SEER_OK);

    static uint8_t exp[512];
    size_t n = unhex(hex, exp);
    if (w.len != n || memcmp(w.buf, exp, n) != 0) {
        fprintf(stderr, "FAIL %s: got %zu bytes, want %zu\n", what, w.len, n);
        assert(0 && "switch vector mismatch");
    }
    seer_writer_free(&w);
}

/* seerdb encode_tpc_switch(seq=7, fv=24, ..., txn="mytxn"); the 128-byte xid
 * payload (gtrid "mytxn" then zero-padding) is the long zero tail. */
static const char *BEGIN = "0367070001010000034e5c3e0105000101800111013c010101000000006d7974786e00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
static const char *RESUME = "0367070001010000034e5c3e0105000101800114013c010101000000006d7974786e00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
static const char *SUSPEND = "036707000102000000000000000110000101010000000000";

int main(void)
{
    const uint8_t txn[] = { 'm', 'y', 't', 'x', 'n' };
    SeerXid xid = {
        .format_id = TNS_TPC_SESSIONLESS_FORMAT_ID,
        .gtrid = txn, .gtrid_len = (int)sizeof txn,
        .bqual = NULL, .bqual_len = 0,
    };

    check("begin",  TNS_TPC_TXN_START, &xid,
          SEER_TPC_BEGIN_NEW | TNS_TPC_FLAGS_SESSIONLESS, 60, BEGIN);
    check("resume", TNS_TPC_TXN_START, &xid,
          SEER_TPC_BEGIN_RESUME | TNS_TPC_FLAGS_SESSIONLESS, 60, RESUME);
    check("suspend", TNS_TPC_TXN_DETACH, NULL,
          TNS_TPC_FLAGS_SESSIONLESS, 0, SUSPEND);

    printf("sessionless: all switch vectors match\n");
    return 0;
}

/* Regression test for the execute-RPA skip (stmt.c), against a captured 26ai /
 * fv27 `SELECT 42 FROM dual` response. That server's execute RPA carries a
 * return-parameter field whose length byte is 0x04 — the same value as the OER
 * token — so the old skip_rpa heuristic (break on any token-valued byte) stopped
 * 14 bytes short and decoded the trailing OER off by those bytes, surfacing a
 * bogus "ORA-00002" instead of the real end-of-fetch ORA-01403. The fix consumes
 * exactly `num` RPA fields at fv >= 10.2 (only 9i breaks on a token). This pins
 * the fixed behaviour to real server bytes.
 *
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#include "conn.h"

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

/* A live 26ai (23.1.162, advertises fv27) `SELECT 42 FROM dual` execute response:
 * DCB describe, one NUMBER row (42 = c1 2b), the return-parameter RPA (6 fields,
 * one with a 0x04 length byte), then the trailing OER carrying ORA-01403. */
static const char *FV27_SELECT42 =
    "101702de395c46a81570fe57e087a41552a1787e081e0e2d2e010201018202000081010200"
    "000000000000000102010202343200000000000000000000010707787e081e0e330a00021f"
    "e80102010200062201010001640000000702c12b080106040144c0d600010200000000"
    "0000040101010e010102057b0000010200030000000000000000000000000300010100"
    "00000002057b0101010300194f52412d30313430333a206e6f206461746120666f756e640a";

int main(void)
{
    static uint8_t buf[512];
    size_t len = unhex(FV27_SELECT42, buf);

    int     ncols = -1;
    int64_t err   = -1;
    SeerStatus st = seer_test_parse_execute_response(buf, len, 24, &ncols, &err);

    assert(st == SEER_OK);
    if (ncols != 1) {
        fprintf(stderr, "FAIL: ncols=%d (want 1)\n", ncols);
        assert(0);
    }
    /* The real trailing status is ORA-01403 (no data found = end of fetch), NOT
     * the bogus ORA-00002 the desync produced. */
    if (err != 1403) {
        fprintf(stderr, "FAIL: OER err=%lld (want 1403; a desync yields ~2)\n",
                (long long)err);
        assert(0);
    }
    printf("rpa_skip: fv27 execute RPA decoded correctly (ncols=1, OER=1403)\n");
    return 0;
}

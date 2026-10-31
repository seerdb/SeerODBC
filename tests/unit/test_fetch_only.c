/* The fetch-only OALL8 a REF CURSOR / implicit result is drained with, byte
 * for byte against the call a live 11g answered with the nested cursors'
 * describes (seerdb tests/test_tns_encode.py, #1462): OALL8 on cursor 2, no
 * SQL, options 0x8040 (NOT_PLSQL | FETCH), 100 rows, no piggybacks.
 *
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#include "conn.h"
#include "tns_consts.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char WANT_11G[] = "035e090280400102000001010d0000000164047fffffff000000000000000000"
                               "0000010000000000000164000000000001010000000000";

int main(void)
{
  uint8_t *buf = NULL;
  size_t len = 0;
  SeerStatus st = seer_test_build_fetch_only(6 /* 11.2 */, 0x0B200200u, 9, 2, &buf, &len);
  assert(st == SEER_OK);
  char got[256] = "";
  for (size_t i = 0; i < len && 2 * i + 2 < sizeof got; i++)
    snprintf(got + 2 * i, 3, "%02x", buf[i]);
  free(buf);
  if (strcmp(got, WANT_11G) != 0) {
    fprintf(stderr, "got  %s\nwant %s\n", got, WANT_11G);
    return 1;
  }
  printf("fetch-only OALL8 (11g): OK\n");
  return 0;
}

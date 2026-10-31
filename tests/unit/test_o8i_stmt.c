/* Oracle 8i's OALL8 (seerdb PROTOCOL.md §19.9): the query and fetch calls at
 * 8i's fixed little-endian widths, byte for byte against seerdb's encoders
 * (encode_8i_oall8_query / _fetch, as a live 8.1.7 answers them): a short
 * query, one past 64 bytes (its text in 64-byte chunks), and fetches on cursors
 * below and above 256.
 *
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#include "conn.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char Q1[] =
    "035e0561800000000000000112000000010c00000000010000000001000000000000000000000000"
    "00000000011273656c65637420312066726f6d206475616c01000000000000000000000000000000"
    "0000000000000000000000000100000000000000000000000000000000000000";
static const char QL[] =
    "035e06618000000000000001f4000000010c00000000010000000001000000000000000000000000"
    "0000000001fe4073656c65637420312c322c332c342c352c362c372c382c392c31302c31312c3132"
    "2c31332c31342c31352c31362c31372c31382c31392c32302c32312c32322c4032332c32342c3235"
    "2c32362c32372c32382c32392c33302c33312c33322c33332c33342c33352c33362c33372c33382c"
    "33392c34302c34312c34322c34332c3440342c34352c34362c34372c34382c34392c35302c35312c"
    "35322c35332c35342c35352c35362c35372c35382c35392c36302c36312c36322c36332c36342c36"
    "35342c36362c36372c36382c36392c37302c37312c37322c37332c37342c37352c37362c37372c37"
    "382c37392066726f6d206475616c0001000000000000000000000000000000000000000000000000"
    "0000000100000000000000000000000000000000000000";
static const char F1[] =
    "035e0740000000020000000000000000010c00000000010000000000000000ffffff7f0000000000"
    "00000000010000000064000000000000000000000000000000000000000000000001000000000000"
    "00000000000000000000000000";
static const char F300[] =
    "035e08400000002c0100000000000000010c00000000010000000000000000ffffff7f0000000000"
    "00000000010000000001000000000000000000000000000000000000000000000001000000000000"
    "00000000000000000000000000";

static int same(const char *what, SeerStatus st, uint8_t *buf, size_t len, const char *want)
{
  if (st != SEER_OK) {
    fprintf(stderr, "%s: build failed (%d)\n", what, (int)st);
    return 0;
  }
  char *got = malloc(2 * len + 1);
  for (size_t i = 0; i < len; i++)
    sprintf(got + 2 * i, "%02x", buf[i]);
  int ok = strcmp(got, want) == 0;
  if (!ok)
    fprintf(stderr, "%s:\n got  %s\n want %s\n", what, got, want);
  free(got);
  free(buf);
  return ok;
}

int main(void)
{
  char longsql[512];
  size_t off = 0;
  off += (size_t)snprintf(longsql, sizeof longsql, "select ");
  for (int i = 1; i < 80; i++) {
    char item[8];
    snprintf(item, sizeof item, "%s%d", i > 1 ? "," : "", i);
    strncat(longsql, item, sizeof longsql - strlen(longsql) - 1);
  }
  strncat(longsql, " from dual", sizeof longsql - strlen(longsql) - 1);
  (void)off;

  uint8_t *b = NULL;
  size_t n = 0;
  int ok = 1;
  SeerStatus st = seer_test_o8i_all8(5, false, 0, "select 1 from dual", 0, &b, &n);
  ok &= same("query", st, b, n, Q1);
  st = seer_test_o8i_all8(6, false, 0, longsql, 0, &b, &n);
  ok &= same("long query", st, b, n, QL);
  st = seer_test_o8i_all8(7, true, 2, NULL, 100, &b, &n);
  ok &= same("fetch", st, b, n, F1);
  st = seer_test_o8i_all8(8, true, 300, NULL, 1, &b, &n);
  ok &= same("fetch, cursor 300", st, b, n, F300);
  if (!ok)
    return 1;
  printf("8i OALL8: OK\n");
  return 0;
}

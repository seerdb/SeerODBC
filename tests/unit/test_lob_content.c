/* A LOBOPS reply's TTI_LOB content (14), whole or cut short. Whole replies -
 * one inline chunk, or a 0xFE run of chunks ended by a zero length (ub1
 * lengths on 11g, sb4 on 12c+) - give their bytes; a reply whose chunk or
 * length runs past its end is SEER_EPROTO, not the bytes that did arrive
 * (a silently truncated LOB, seerdb a618d4c).
 *
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#include "conn.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static SeerStatus content(const uint8_t *r, size_t n, bool sb4, char *out, size_t outsz)
{
  uint8_t *buf = NULL;
  size_t len = 0;
  SeerStatus st = seer_test_lob_content(r, n, sb4, &buf, &len);
  out[0] = '\0';
  if (st == SEER_OK) {
    assert(len < outsz);
    memcpy(out, buf, len);
    out[len] = '\0';
  }
  free(buf);
  return st;
}

int main(void)
{
  char got[64];

  /* inline: 0e 05 "hello", then the RPA trailer (08 ...) */
  static const uint8_t inl[] = {14, 5, 'h', 'e', 'l', 'l', 'o', 8, 0};
  assert(content(inl, sizeof inl, false, got, sizeof got) == SEER_OK);
  assert(strcmp(got, "hello") == 0);

  /* 11g chunked: 0e fe 03 "abc" 02 "de" 00 */
  static const uint8_t ub1[] = {14, 0xFE, 3, 'a', 'b', 'c', 2, 'd', 'e', 0, 8, 0};
  assert(content(ub1, sizeof ub1, false, got, sizeof got) == SEER_OK);
  assert(strcmp(got, "abcde") == 0);

  /* 12c+ chunked, sb4 lengths: 0e fe 01 03 "abc" 01 02 "de" 00 */
  static const uint8_t sb4[] = {14, 0xFE, 1, 3, 'a', 'b', 'c', 1, 2, 'd', 'e', 0, 8, 0};
  assert(content(sb4, sizeof sb4, true, got, sizeof got) == SEER_OK);
  assert(strcmp(got, "abcde") == 0);

  /* cut short: an inline chunk of 5 with 2 bytes */
  static const uint8_t cut_inl[] = {14, 5, 'h', 'e'};
  assert(content(cut_inl, sizeof cut_inl, false, got, sizeof got) == SEER_EPROTO);

  /* cut short inside a chunked run, and right after a chunk (no terminator) */
  static const uint8_t cut_run[] = {14, 0xFE, 3, 'a', 'b', 'c', 4, 'd'};
  assert(content(cut_run, sizeof cut_run, false, got, sizeof got) == SEER_EPROTO);
  static const uint8_t cut_sb4[] = {14, 0xFE, 1, 3, 'a', 'b', 'c', 1};
  assert(content(cut_sb4, sizeof cut_sb4, true, got, sizeof got) == SEER_EPROTO);

  /* a reply with no TTI_LOB at all is empty content, not an error */
  static const uint8_t none[] = {8, 0};
  assert(content(none, sizeof none, false, got, sizeof got) == SEER_OK);
  assert(got[0] == '\0');

  printf("LOB content: OK\n");
  return 0;
}

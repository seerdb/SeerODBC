/* Oracle 8i login (seerdb PROTOCOL.md §19.8): the OSESSKEY / OAUTH calls at 8i's
 * fixed little-endian widths, byte for byte against seerdb's encoders
 * (encode_o3logon_osesskey_phase1 / _oauth_phase2, the frames a live 8.1.7
 * accepts), and reading a value out of the pairs reply.
 *
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#include "conn.h"
#include "tns_consts.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Always evaluated, unlike REQUIRE() (which NDEBUG drops). */
#define REQUIRE(cond)                                                                              \
  do {                                                                                             \
    if (!(cond)) {                                                                                 \
      fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #cond);                                   \
      return 1;                                                                                    \
    }                                                                                              \
  } while (0)

static void hex(const uint8_t *b, size_t n, char *out)
{
  for (size_t i = 0; i < n; i++)
    sprintf(out + 2 * i, "%02x", b[i]);
}

static int check(const char *what, SeerWriter *w, const char *want)
{
  char *got = malloc(2 * w->len + 1);
  hex(w->buf, w->len, got);
  int ok = strcmp(got, want) == 0;
  if (!ok)
    fprintf(stderr, "%s:\n got  %s\n want %s\n", what, got, want);
  free(got);
  seer_writer_free(w);
  return ok;
}

/* seerdb, user SYSTEM, AUTH_PROGRAM_NM seerodbc, AUTH_MACHINE host1, AUTH_PID 4242 */
static const char P1[] = "037603010600000001000000010300000001010653595354454d0f0000000f415554"
                         "485f50524f4752414d5f4e4d0800000008736565726f646263000000000c0000000c"
                         "415554485f4d414348494e450500000005686f737431000000000800000008415554"
                         "485f50494404000000043432343200000000";
/* phase two, AUTH_PASSWORD 0123456789ABCDEF2 first and AUTH_ACL 8000 last */
static const char P2[] =
    "037304010600000001010000010500000001010653595354454d0d0000000d415554485f50415353574f52"
    "4411000000113031323334353637383941424344454632000000000f0000000f415554485f50524f475241"
    "4d5f4e4d0800000008736565726f646263000000000c0000000c415554485f4d414348494e450500000005"
    "686f737431000000000800000008415554485f504944040000000434323432000000000800000008415554"
    "485f41434c04000000043830303000000000";

int main(void)
{
  struct SeerConn conn;
  memset(&conn, 0, sizeof conn);
  conn.field_version = TTC_FIELD_VERSION_9_2;
  int ok = 1;

  SeerWriter w;
  conn.seq = 3;
  REQUIRE(seer_o8i_build_login(&conn, &w, TTI_SESS, "SYSTEM", 1, NULL, "host1", "4242") == SEER_OK);
  ok &= check("OSESSKEY", &w, P1);
  conn.seq = 4;
  REQUIRE(seer_o8i_build_login(&conn, &w, TTI_AUTH, "SYSTEM", 0x101, "0123456789ABCDEF2", "host1",
                               "4242") == SEER_OK);
  ok &= check("OAUTH", &w, P2);

  /* A reply: RPA, ub2 count 3, then AUTH_NLS_X (its length counting a NUL, as
   * 8.1.7 sends it) = "AMERICAN", AUTH_EMPTY with no value, AUTH_SESSKEY. */
  static const uint8_t reply[] = {
      0x08, 0x03, 0x00,                                                                /* RPA, 3 */
      0x0b, 0,    0,    0, 0x0b, 'A',  'U', 'T', 'H', '_', 'N', 'L', 'S', '_', 'X', 0, /* key */
      0x08, 0,    0,    0, 0x08, 'A',  'M', 'E', 'R', 'I', 'C', 'A', 'N', 0,   0,   0,
      0,                                                                            /* val, flags */
      0x0a, 0,    0,    0, 0x0a, 'A',  'U', 'T', 'H', '_', 'E', 'M', 'P', 'T', 'Y', /* key */
      0,    0,    0,    0, 0,    0,    0,   0,                                      /* no val */
      0x0c, 0,    0,    0, 0x0c, 'A',  'U', 'T', 'H', '_', 'S', 'E', 'S', 'S', 'K', 'E',
      'Y',  0x04, 0,    0, 0,    0x04, 'A', '1', 'B', '2', 0,   0,   0,   0,
  };
  char *v = NULL;
  REQUIRE(seer_o8i_auth_value(reply, sizeof reply, "AUTH_SESSKEY", &v) == SEER_OK && v != NULL);
  ok &= strcmp(v, "A1B2") == 0;
  free(v);
  REQUIRE(seer_o8i_auth_value(reply, sizeof reply, "AUTH_NLS_X", &v) == SEER_OK && v != NULL);
  ok &= strcmp(v, "AMERICAN") == 0;
  free(v);
  REQUIRE(seer_o8i_auth_value(reply, sizeof reply, "AUTH_EMPTY", &v) == SEER_OK && v != NULL);
  ok &= v[0] == '\0';
  free(v);
  REQUIRE(seer_o8i_auth_value(reply, sizeof reply, "AUTH_NONE", &v) == SEER_OK && v == NULL);
  /* cut short: an error, not a partial answer */
  REQUIRE(seer_o8i_auth_value(reply, sizeof reply - 6, "AUTH_SESSKEY", &v) == SEER_EPROTO);

  if (!ok)
    return 1;
  printf("8i login: OK\n");
  return 0;
}

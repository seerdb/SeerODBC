/* Live test for SQL OBJECT (ADT) and collection (VARRAY/nested table) parameter
 * binding against the core API.
 *
 * Self-gating: exits 77 (skip) unless SEER_TEST_HOST/SERVICE/USER are set. Binds
 * an object and a VARRAY, inserts each, and reads them back through the decode
 * path. Object/collection binds are 12c+; older servers skip.
 *
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "seer/seertns.h"

static int pass_n, fail_n, skip_n;
static void pass(const char *n)
{
  printf("  PASS %s\n", n);
  pass_n++;
}
/* Failures are also kept to repeat on stderr at the end: a CI runner showing
 * only a failed test's last lines of stderr then still names them. */
static char fail_log[4096];
static void fail(const char *n, const char *w)
{
  printf("  FAIL %s: %s\n", n, w);
  size_t used = strlen(fail_log);
  snprintf(fail_log + used, sizeof fail_log - used, "FAIL %s: %s\n", n, w);
  fail_n++;
}
static void skip(const char *n, const char *w)
{
  printf("  SKIP %s: %s\n", n, w);
  skip_n++;
}

static SeerConn *connect_one(void)
{
  const char *port = getenv("SEER_TEST_PORT");
  SeerConnParams p = {
      .host = getenv("SEER_TEST_HOST"),
      .port = (uint16_t)(port ? atoi(port) : 1521),
      .service_name = getenv("SEER_TEST_SERVICE"),
      .username = getenv("SEER_TEST_USER"),
      .password = getenv("SEER_TEST_PASS"),
  };
  SeerConn *c = NULL;
  return seer_connect(&p, &c) == SEER_OK ? c : NULL;
}

static void run(SeerConn *c, const char *sql)
{
  SeerStmt *s = NULL;
  if (seer_stmt_prepare(c, sql, &s) != SEER_OK)
    return;
  seer_stmt_execute(s);
  seer_stmt_close(s);
}

/* SELECT a single rendered value; returns 1 if it contains both needles. */
static int readback_has(SeerConn *c, const char *sql, const char *a, const char *b)
{
  SeerStmt *s = NULL;
  int ok = 0;
  if (seer_stmt_prepare(c, sql, &s) == SEER_OK && seer_stmt_execute(s) == SEER_OK &&
      seer_stmt_fetch(s) == SEER_OK) {
    const char *v = NULL;
    int isnull = 0;
    if (seer_stmt_get_string(s, 0, &v, &isnull) == SEER_OK && v != NULL)
      ok = (strstr(v, a) != NULL && strstr(v, b) != NULL);
  }
  seer_stmt_close(s);
  return ok;
}

/* Run `sql` - a block assigning a VARCHAR2 result to :1 - with an object (or,
 * `collection`, a collection) of type `type_name` bound to :2; the result goes
 * to out[]. Returns the bind / execute status. */
static SeerStatus call_with_type(SeerConn *c, const char *sql, const char *schema,
                                 const char *type_name, int collection, const char *const *vals,
                                 int n, char *out, size_t outsz)
{
  SeerStmt *s = NULL;
  out[0] = '\0';
  SeerStatus st = seer_stmt_prepare(c, sql, &s);
  if (st == SEER_OK)
    st = seer_stmt_bind_out(s, 1, 1, 200);
  if (st == SEER_OK)
    st = collection ? seer_stmt_bind_collection(s, 2, schema, type_name, vals, n)
                    : seer_stmt_bind_object(s, 2, schema, type_name, vals, n);
  if (st == SEER_OK)
    st = seer_stmt_execute(s);
  if (st == SEER_OK) {
    const void *d = NULL;
    size_t l = 0;
    int isnull = 0, isbin = 0;
    if (seer_stmt_out_data(s, 1, &d, &l, &isnull, &isbin) == SEER_OK && d != NULL)
      snprintf(out, outsz, "%.*s", (int)l, (const char *)d);
  }
  seer_stmt_close(s);
  return st;
}

int main(void)
{
  if (!getenv("SEER_TEST_HOST") || !getenv("SEER_TEST_SERVICE") || !getenv("SEER_TEST_USER")) {
    fprintf(stderr, "objbind_test: set SEER_TEST_HOST/SERVICE/USER[/PORT/PASS] - skipping\n");
    return 77;
  }
  SeerConn *c = connect_one();
  if (!c) {
    fprintf(stderr, "objbind_test: connect failed\n");
    return 1;
  }

  char schema[64];
  snprintf(schema, sizeof schema, "%s", getenv("SEER_TEST_USER"));
  for (char *p = schema; *p; p++)
    *p = (char)toupper((unsigned char)*p);

  /* --- object bind with a LOB attribute: refused, not sent as text --- */
  run(c, "DROP TYPE seerlb_o");
  run(c, "CREATE TYPE seerlb_o AS OBJECT (n NUMBER, c CLOB)");
  {
    /* A LOB attribute needs a locator in the image (a temporary LOB written
     * first), which the object bind can't build yet: it must say so rather
     * than put the text where the server expects a locator (ORA-22275). */
    const char *name = "object bind with a LOB attribute is refused";
    const char *attrs[2] = {"1", "text"};
    SeerStmt *ins = NULL;
    seer_stmt_prepare(c, "SELECT 1 FROM dual WHERE :1 IS NOT NULL", &ins);
    SeerStatus st = seer_stmt_bind_object(ins, 1, schema, "SEERLB_O", attrs, 2);
    seer_stmt_close(ins);
    if (st == SEER_ENOTIMPL)
      pass(name);
    else
      fail(name, "bind accepted a LOB attribute value as text");
  }
  run(c, "DROP TYPE seerlb_o");

  /* --- SQL OBJECT bind --- */
  run(c, "DROP TABLE seerob_t");
  run(c, "DROP TYPE seerob_o");
  run(c, "CREATE TYPE seerob_o AS OBJECT (n NUMBER, s VARCHAR2(20))");
  run(c, "CREATE TABLE seerob_t (o seerob_o)");
  {
    const char *name = "SQL OBJECT bind";
    const char *attrs[2] = {"42", "hello"};
    SeerStmt *ins = NULL;
    seer_stmt_prepare(c, "INSERT INTO seerob_t VALUES (:1)", &ins);
    SeerStatus st = seer_stmt_bind_object(ins, 1, schema, "SEEROB_O", attrs, 2);
    if (st == SEER_ENOTIMPL) {
      skip(name, "object bind requires a 12c+ server");
    } else if (st != SEER_OK || seer_stmt_execute(ins) != SEER_OK) {
      fail(name, seer_last_error(c) ? seer_last_error(c) : "bind/insert");
    } else {
      seer_stmt_close(ins);
      ins = NULL;
      seer_commit(c);
      if (readback_has(c, "SELECT o FROM seerob_t", "42", "hello"))
        pass(name);
      else
        fail(name, "read-back");
    }
    seer_stmt_close(ins);
  }
  run(c, "DROP TABLE seerob_t");
  run(c, "DROP TYPE seerob_o");

  /* --- collection (VARRAY) bind --- */
  run(c, "DROP TABLE seerva_t");
  run(c, "DROP TYPE seerva_o");
  run(c, "CREATE TYPE seerva_o AS VARRAY(5) OF NUMBER");
  run(c, "CREATE TABLE seerva_t (v seerva_o)");
  {
    const char *name = "VARRAY bind";
    const char *elems[3] = {"10", "20", "30"};
    SeerStmt *ins = NULL;
    seer_stmt_prepare(c, "INSERT INTO seerva_t VALUES (:1)", &ins);
    SeerStatus st = seer_stmt_bind_collection(ins, 1, schema, "SEERVA_O", elems, 3);
    if (st == SEER_ENOTIMPL) {
      skip(name, "collection bind requires a 12c+ server");
    } else if (st != SEER_OK || seer_stmt_execute(ins) != SEER_OK) {
      fail(name, seer_last_error(c) ? seer_last_error(c) : "bind/insert");
    } else {
      seer_stmt_close(ins);
      ins = NULL;
      seer_commit(c);
      if (readback_has(c, "SELECT v FROM seerva_t", "10", "30"))
        pass(name);
      else
        fail(name, "read-back");
    }
    seer_stmt_close(ins);
  }
  run(c, "DROP TABLE seerva_t");
  run(c, "DROP TYPE seerva_o");

  /* --- temporal attributes --- each takes its type's width: a WITH TIME ZONE
   * one is 13 bytes (UTC + offset), so "10:00 +02:00" must store 08:00 UTC
   * with a +2 zone, not an 11-byte value the server reads as another; and a
   * WITH TIME ZONE value that names no offset is refused, not guessed. */
  run(c, "DROP TABLE seertz_t");
  run(c, "DROP TYPE seertz_o");
  run(c, "CREATE TYPE seertz_o AS OBJECT (ts TIMESTAMP, tz TIMESTAMP WITH TIME ZONE, "
         "ltz TIMESTAMP WITH LOCAL TIME ZONE, d DATE)");
  run(c, "CREATE TABLE seertz_t (o seertz_o)");
  {
    const char *name = "TIMESTAMP / WITH TIME ZONE / LTZ / DATE attribute bind";
    const char *attrs[4] = {"2020-02-29 00:00:00", "2020-02-29 10:00:00.25 +02:00",
                            "2020-02-29 10:00:00.5", "2020-02-29 12:34:56"};
    SeerStmt *ins = NULL;
    seer_stmt_prepare(c, "INSERT INTO seertz_t VALUES (:1)", &ins);
    SeerStatus st = seer_stmt_bind_object(ins, 1, schema, "SEERTZ_O", attrs, 4);
    if (st == SEER_ENOTIMPL) {
      skip(name, "object bind requires a 12c+ server");
    } else if (st != SEER_OK || seer_stmt_execute(ins) != SEER_OK) {
      fail(name, seer_last_error(c) ? seer_last_error(c) : "bind/insert");
    } else {
      seer_stmt_close(ins);
      ins = NULL;
      seer_commit(c);
      int ok = readback_has(c,
                            "SELECT TO_CHAR(t.o.ts, 'YYYY-MM-DD HH24:MI:SS.FF3') || '|' || "
                            "TO_CHAR(SYS_EXTRACT_UTC(t.o.tz), 'YYYY-MM-DD HH24:MI:SS.FF2') || '|' "
                            "|| EXTRACT(TIMEZONE_HOUR FROM t.o.tz) || '|' || "
                            "TO_CHAR(t.o.ltz, 'FF1') || '|' || "
                            "TO_CHAR(t.o.d, 'YYYY-MM-DD HH24:MI:SS') FROM seertz_t t",
                            "2020-02-29 00:00:00.000|2020-02-29 08:00:00.25|2|5|",
                            "|2020-02-29 12:34:56");
      /* no offset on the WITH TIME ZONE attribute: refused */
      const char *nozone[4] = {"2020-02-29 00:00:00", "2020-02-29 10:00:00", "2020-02-29 10:00:00",
                               "2020-02-29 12:34:56"};
      SeerStmt *bad = NULL;
      seer_stmt_prepare(c, "INSERT INTO seertz_t VALUES (:1)", &bad);
      SeerStatus bst = seer_stmt_bind_object(bad, 1, schema, "SEERTZ_O", nozone, 4);
      seer_stmt_close(bad);
      if (ok && bst == SEER_EPARAM)
        pass(name);
      else
        fail(name, !ok ? "server-side values" : "a zone-less WITH TIME ZONE value was accepted");
    }
    seer_stmt_close(ins);
  }
  run(c, "DROP TABLE seertz_t");
  run(c, "DROP TYPE seertz_o");

  /* --- national (NVARCHAR2 / NCHAR) attributes and elements --- the image
   * carries them in AL16UTF16; written as UTF-8 the server would store other
   * characters (only LENGTH / LENGTHB on the server shows it). */
  run(c, "DROP TABLE seernc_t");
  run(c, "DROP TYPE seernc_o");
  run(c, "DROP TYPE seernc_v");
  run(c, "CREATE TYPE seernc_o AS OBJECT (a NVARCHAR2(20), b VARCHAR2(20))");
  run(c, "CREATE TYPE seernc_v AS VARRAY(5) OF NVARCHAR2(20)");
  run(c, "CREATE TABLE seernc_t (o seernc_o, l seernc_v)");
  {
    const char *name = "NVARCHAR2 object attribute + element bind";
    /* "žába 猫" and "猫" */
    const char *attrs[2] = {"\xc5\xbe\xc3\xa1"
                            "ba \xe7\x8c\xab",
                            "plain"};
    const char *elems[2] = {"\xe7\x8c\xab", "abc"};
    SeerStmt *ins = NULL;
    seer_stmt_prepare(c, "INSERT INTO seernc_t VALUES (:1, :2)", &ins);
    SeerStatus st = seer_stmt_bind_object(ins, 1, schema, "SEERNC_O", attrs, 2);
    if (st == SEER_OK)
      st = seer_stmt_bind_collection(ins, 2, schema, "SEERNC_V", elems, 2);
    if (st == SEER_ENOTIMPL) {
      skip(name, "object bind requires a 12c+ server");
    } else if (st != SEER_OK || seer_stmt_execute(ins) != SEER_OK) {
      fail(name, seer_last_error(c) ? seer_last_error(c) : "bind/insert");
    } else {
      seer_stmt_close(ins);
      ins = NULL;
      seer_commit(c);
      /* Server side: 6 characters in 12 AL16UTF16 bytes; elements 1/2, 3/6. */
      int lens = readback_has(c,
                              "SELECT LENGTH(t.o.a) || '/' || LENGTHB(t.o.a) || ' ' || "
                              "(SELECT LISTAGG(LENGTH(column_value) || '/' || "
                              "LENGTHB(column_value), ',') WITHIN GROUP (ORDER BY 1) "
                              "FROM TABLE(t.l)) FROM seernc_t t",
                              "6/12 ", "1/2,3/6");
      int text = readback_has(c, "SELECT o FROM seernc_t", attrs[0], "plain") &&
                 readback_has(c, "SELECT l FROM seernc_t", elems[0], "abc");
      if (lens && text)
        pass(name);
      else
        fail(name, lens ? "read-back text" : "server-side LENGTH/LENGTHB");
    }
    seer_stmt_close(ins);
  }
  run(c, "DROP TABLE seernc_t");
  run(c, "DROP TYPE seernc_o");
  run(c, "DROP TYPE seernc_v");

  /* --- nested object bind (an attribute that is itself an ADT, flattened) --- */
  run(c, "DROP TABLE seerpe_t");
  run(c, "DROP TYPE seerpe_o");
  run(c, "DROP TYPE seerad_o");
  run(c, "CREATE TYPE seerad_o AS OBJECT (street VARCHAR2(20), zip NUMBER)");
  run(c, "CREATE TYPE seerpe_o AS OBJECT (nm VARCHAR2(20), age NUMBER, home seerad_o)");
  run(c, "CREATE TABLE seerpe_t (p seerpe_o)");
  {
    const char *name = "nested object bind";
    const char *vals[4] = {"Bob", "30", "Main St", "12345"}; /* flattened leaves */
    SeerStmt *ins = NULL;
    seer_stmt_prepare(c, "INSERT INTO seerpe_t VALUES (:1)", &ins);
    SeerStatus st = seer_stmt_bind_object(ins, 1, schema, "SEERPE_O", vals, 4);
    if (st == SEER_ENOTIMPL) {
      skip(name, "object bind requires a 12c+ server");
    } else if (st != SEER_OK || seer_stmt_execute(ins) != SEER_OK) {
      fail(name, seer_last_error(c) ? seer_last_error(c) : "bind/insert");
    } else {
      seer_stmt_close(ins);
      ins = NULL;
      seer_commit(c);
      if (readback_has(c, "SELECT p FROM seerpe_t", "Main St", "12345"))
        pass(name);
      else
        fail(name, "read-back");
    }
    seer_stmt_close(ins);
  }
  run(c, "DROP TABLE seerpe_t");
  run(c, "DROP TYPE seerpe_o");
  run(c, "DROP TYPE seerad_o");

  /* --- typed attributes: decimal NUMBER + DATE --- */
  run(c, "DROP TABLE seerty_t");
  run(c, "DROP TYPE seerty_o");
  run(c, "CREATE TYPE seerty_o AS OBJECT (amt NUMBER, born DATE)");
  run(c, "CREATE TABLE seerty_t (o seerty_o)");
  {
    const char *name = "object bind (decimal+DATE)";
    const char *vals[2] = {"-1234.567", "1999-12-31 23:59:58"};
    SeerStmt *ins = NULL;
    seer_stmt_prepare(c, "INSERT INTO seerty_t VALUES (:1)", &ins);
    SeerStatus st = seer_stmt_bind_object(ins, 1, schema, "SEERTY_O", vals, 2);
    if (st == SEER_ENOTIMPL) {
      skip(name, "object bind requires a 12c+ server");
    } else if (st != SEER_OK || seer_stmt_execute(ins) != SEER_OK) {
      fail(name, seer_last_error(c) ? seer_last_error(c) : "bind/insert");
    } else {
      seer_stmt_close(ins);
      ins = NULL;
      seer_commit(c);
      if (readback_has(c, "SELECT o FROM seerty_t", "-1234.567", "1999-12-31"))
        pass(name);
      else
        fail(name, "read-back");
    }
    seer_stmt_close(ins);
  }
  run(c, "DROP TABLE seerty_t");
  run(c, "DROP TYPE seerty_o");

  /* --- PL/SQL associative-array (index-by table) binds --- */
  run(c, "CREATE OR REPLACE PACKAGE seeraa AS\n"
         "  TYPE num_tab IS TABLE OF NUMBER INDEX BY BINARY_INTEGER;\n"
         "  TYPE str_tab IS TABLE OF VARCHAR2(40) INDEX BY BINARY_INTEGER;\n"
         "  PROCEDURE sum_arr(a IN num_tab, total OUT NUMBER);\n"
         "  PROCEDURE cat_arr(a IN str_tab, result OUT VARCHAR2);\n"
         "  PROCEDURE out_nums(a OUT num_tab);\n"
         "END;");
  run(c, "CREATE OR REPLACE PACKAGE BODY seeraa AS\n"
         "  PROCEDURE sum_arr(a IN num_tab, total OUT NUMBER) IS BEGIN\n"
         "    total := 0; FOR i IN 1..a.COUNT LOOP total := total + a(i); END LOOP; END;\n"
         "  PROCEDURE cat_arr(a IN str_tab, result OUT VARCHAR2) IS BEGIN\n"
         "    result := NULL; FOR i IN 1..a.COUNT LOOP result := result || a(i); END LOOP; END;\n"
         "  PROCEDURE out_nums(a OUT num_tab) IS BEGIN a(1):=10; a(2):=20; a(3):=30; END;\n"
         "END;");
  {
    const char *name = "assoc-array bind (NUMBER)";
    SeerStmt *s = NULL;
    int64_t nums[3] = {10, 20, 30};
    seer_stmt_prepare(c, "BEGIN seeraa.sum_arr(:1, :2); END;", &s);
    SeerStatus b = seer_stmt_bind_int64_array(s, 1, nums, 3);
    if (b == SEER_ENOTIMPL) {
      skip(name, "assoc-array bind requires a 12c+ server");
    } else if (b != SEER_OK || seer_stmt_bind_out(s, 2, 2, 22) != SEER_OK ||
               seer_stmt_execute(s) != SEER_OK) {
      fail(name, seer_last_error(c) ? seer_last_error(c) : "bind/exec");
    } else {
      const void *d = NULL;
      size_t dl = 0;
      int isn = 0, isb = 0;
      seer_stmt_out_data(s, 2, &d, &dl, &isn, &isb);
      if (d != NULL && dl == 2 && memcmp(d, "60", 2) == 0)
        pass(name);
      else {
        char m[64];
        snprintf(m, sizeof m, "total='%.*s'", (int)dl, (const char *)d);
        fail(name, m);
      }
    }
    seer_stmt_close(s);
  }
  {
    const char *name = "assoc-array bind (VARCHAR)";
    SeerStmt *s = NULL;
    const char *strs[2] = {"foo", "bar"};
    seer_stmt_prepare(c, "BEGIN seeraa.cat_arr(:1, :2); END;", &s);
    SeerStatus b = seer_stmt_bind_text_array(s, 1, strs, 2, 40);
    if (b == SEER_ENOTIMPL) {
      skip(name, "assoc-array bind requires a 12c+ server");
    } else if (b != SEER_OK || seer_stmt_bind_out(s, 2, 1, 100) != SEER_OK ||
               seer_stmt_execute(s) != SEER_OK) {
      fail(name, seer_last_error(c) ? seer_last_error(c) : "bind/exec");
    } else {
      const void *d = NULL;
      size_t dl = 0;
      int isn = 0, isb = 0;
      seer_stmt_out_data(s, 2, &d, &dl, &isn, &isb);
      if (d != NULL && dl == 6 && memcmp(d, "foobar", 6) == 0)
        pass(name);
      else {
        char m[64];
        snprintf(m, sizeof m, "result='%.*s'", (int)dl, (const char *)d);
        fail(name, m);
      }
    }
    seer_stmt_close(s);
  }
  {
    const char *name = "OUT assoc-array (NUMBER)";
    SeerStmt *s = NULL;
    seer_stmt_prepare(c, "BEGIN seeraa.out_nums(:1); END;", &s);
    SeerStatus b = seer_stmt_bind_out_array(s, 1, 2 /*NUMBER*/, 0, 10);
    if (b == SEER_ENOTIMPL) {
      skip(name, "assoc-array bind requires a 12c+ server");
    } else if (b != SEER_OK || seer_stmt_execute(s) != SEER_OK) {
      fail(name, seer_last_error(c) ? seer_last_error(c) : "bind/exec");
    } else {
      int ok = (seer_stmt_out_array_len(s, 1) == 3);
      const char *want[3] = {"10", "20", "30"};
      for (int i = 0; ok && i < 3; i++) {
        const char *d = NULL;
        size_t l = 0;
        int isn = 0;
        if (seer_stmt_out_array_get(s, 1, i, &d, &l, &isn) != SEER_OK || d == NULL ||
            strcmp(d, want[i]) != 0)
          ok = 0;
      }
      if (ok)
        pass(name);
      else
        fail(name, "wrong count / elements");
    }
    seer_stmt_close(s);
  }
  run(c, "DROP PACKAGE seeraa");

  {
    const char *name = "native JSON bind";
    run(c, "DROP TABLE seerjb");
    run(c, "CREATE TABLE seerjb (doc JSON) TABLESPACE USERS");
    SeerStmt *s = NULL;
    seer_stmt_prepare(c, "INSERT INTO seerjb VALUES (:1)", &s);
    SeerStatus b = seer_stmt_bind_json(s, 1, "{\"name\":\"alice\",\"n\":30}");
    SeerStatus e = (b == SEER_OK) ? seer_stmt_execute(s) : b;
    seer_stmt_close(s);
    seer_commit(c);
    const char *er = seer_last_error(c);
    if (b == SEER_ENOTIMPL) {
      skip(name, "native JSON bind requires a 21c+ server");
    } else if (e != SEER_OK) {
      /* JSON column type / ASSM tablespace may be unavailable -> skip */
      if (er && (strstr(er, "ORA-00902") || strstr(er, "ORA-43853") || strstr(er, "ORA-00942")))
        skip(name, "JSON column type / ASSM tablespace not available");
      else
        fail(name, er ? er : "bind/exec");
    } else if (!readback_has(c, "SELECT doc FROM seerjb", "alice", "30")) {
      fail(name, "readback mismatch");
    } else if (!readback_has(c,
                             "SELECT JSON_VALUE(doc, '$.name') FROM seerjb "
                             "WHERE JSON_EXISTS(doc, '$.n')",
                             "alice", "alice")) {
      /* The server finds fields through the image's hash array: an image with
       * zeroed hashes / unsorted names reads back as text but no path query
       * ever matches it. */
      fail(name, "JSON_EXISTS / JSON_VALUE don't find the bound document's fields");
    } else {
      pass(name);
    }
    run(c, "DROP TABLE seerjb");
  }

  {
    const char *name = "native VECTOR bind (f32/f64/i8)";
    run(c, "DROP TABLE seervb");
    run(c, "CREATE TABLE seervb (a VECTOR(3,FLOAT32), b VECTOR(3,FLOAT64), "
           "c VECTOR(3,INT8)) TABLESPACE USERS");
    SeerStmt *s = NULL;
    float f32[3] = {1.5f, -2.25f, 3.0f};
    double f64[3] = {1.5, -2.25, 3.0};
    int8_t i8[3] = {1, -2, 3};
    seer_stmt_prepare(c, "INSERT INTO seervb VALUES (:1, :2, :3)", &s);
    SeerStatus b1 = seer_stmt_bind_vector_f32(s, 1, f32, 3);
    SeerStatus b2 = seer_stmt_bind_vector_f64(s, 2, f64, 3);
    SeerStatus b3 = seer_stmt_bind_vector_i8(s, 3, i8, 3);
    SeerStatus e = (b1 == SEER_OK && b2 == SEER_OK && b3 == SEER_OK) ? seer_stmt_execute(s) : b1;
    seer_stmt_close(s);
    seer_commit(c);
    const char *er = seer_last_error(c);
    if (b1 == SEER_ENOTIMPL) {
      skip(name, "native VECTOR bind requires a 23ai server");
    } else if (e != SEER_OK) {
      if (er && (strstr(er, "ORA-00907") || strstr(er, "ORA-00902") || strstr(er, "ORA-00942") ||
                 strstr(er, "ORA-43853")))
        skip(name, "VECTOR column type not available here");
      else
        fail(name, er ? er : "bind/exec");
    } else if (readback_has(c, "SELECT a FROM seervb", "1.5", "-2.25") &&
               readback_has(c, "SELECT b FROM seervb", "1.5", "-2.25") &&
               readback_has(c, "SELECT c FROM seervb", "1", "-2")) {
      pass(name);
    } else {
      fail(name, "readback mismatch");
    }
    run(c, "DROP TABLE seervb");
  }

  {
    /* A large VECTOR ahead of another bind: its image rides in place (it is
     * not a LONG-class value, whatever its size), and past 64 KiB its length
     * needs the 3-byte field. 5000 FLOAT64 dimensions = ~40 KB, 30000 = ~240 KB. */
    const char *name = "native VECTOR bind, large, ahead of another bind";
    run(c, "DROP TABLE seervl");
    run(c, "CREATE TABLE seervl (v VECTOR(*, FLOAT64), id NUMBER) TABLESPACE USERS");
    static const int sizes[] = {5000, 30000};
    static double big[30000];
    for (int i = 0; i < 30000; i++)
      big[i] = i * 0.5;
    const char *why = NULL;
    SeerStatus b = SEER_OK;
    for (size_t k = 0; k < sizeof sizes / sizeof sizes[0] && why == NULL; k++) {
      SeerStmt *s = NULL;
      seer_stmt_prepare(c, "INSERT INTO seervl (v, id) VALUES (:1, :2)", &s);
      b = seer_stmt_bind_vector_f64(s, 1, big, sizes[k]);
      SeerStatus e = b == SEER_OK ? seer_stmt_bind_int64(s, 2, sizes[k]) : b;
      if (e == SEER_OK)
        e = seer_stmt_execute(s);
      seer_stmt_close(s);
      seer_commit(c);
      char q[128], want[32];
      snprintf(q, sizeof q,
               "SELECT id || ':' || VECTOR_DIMENSION_COUNT(v) FROM seervl WHERE id = %d", sizes[k]);
      snprintf(want, sizeof want, "%d:%d", sizes[k], sizes[k]);
      if (b == SEER_ENOTIMPL)
        break;
      if (e != SEER_OK)
        why = seer_last_error(c) ? seer_last_error(c) : "bind/exec";
      else if (!readback_has(c, q, want, want))
        why = sizes[k] == 5000 ? "5000 dims: readback mismatch" : "30000 dims: readback mismatch";
    }
    if (b == SEER_ENOTIMPL)
      skip(name, "native VECTOR bind requires a 23ai server");
    else if (why != NULL)
      fail(name, why);
    else
      pass(name);
    run(c, "DROP TABLE seervl");
  }

  {
    const char *name = "native VECTOR bind (binary/sparse)";
    run(c, "DROP TABLE seervbin");
    run(c, "DROP TABLE seervsp");
    run(c, "DROP TABLE seervspd");
    run(c, "DROP TABLE seervspi");
    run(c, "CREATE TABLE seervbin (v VECTOR(16, BINARY)) TABLESPACE USERS");
    run(c, "CREATE TABLE seervsp (v VECTOR(10, FLOAT32, SPARSE)) TABLESPACE USERS");
    run(c, "CREATE TABLE seervspd (v VECTOR(10, FLOAT64, SPARSE)) TABLESPACE USERS");
    run(c, "CREATE TABLE seervspi (v VECTOR(10, INT8, SPARSE)) TABLESPACE USERS");
    uint8_t bits[2] = {0xA5, 0x3C};
    SeerStmt *s = NULL;
    seer_stmt_prepare(c, "INSERT INTO seervbin VALUES (:1)", &s);
    SeerStatus bb = seer_stmt_bind_vector_binary(s, 1, bits, 2);
    SeerStatus eb = (bb == SEER_OK) ? seer_stmt_execute(s) : bb;
    seer_stmt_close(s);
    s = NULL;
    uint32_t idx[2] = {2, 7};
    float val[2] = {1.5f, -2.25f};
    seer_stmt_prepare(c, "INSERT INTO seervsp VALUES (:1)", &s);
    SeerStatus bs = seer_stmt_bind_vector_sparse_f32(s, 1, 10, 2, idx, val);
    SeerStatus es = (bs == SEER_OK) ? seer_stmt_execute(s) : bs;
    seer_stmt_close(s);
    s = NULL;
    double vald[2] = {1.5, -2.25};
    seer_stmt_prepare(c, "INSERT INTO seervspd VALUES (:1)", &s);
    SeerStatus bsd = seer_stmt_bind_vector_sparse_f64(s, 1, 10, 2, idx, vald);
    SeerStatus esd = (bsd == SEER_OK) ? seer_stmt_execute(s) : bsd;
    seer_stmt_close(s);
    s = NULL;
    int8_t vali[2] = {5, -3};
    seer_stmt_prepare(c, "INSERT INTO seervspi VALUES (:1)", &s);
    SeerStatus bsi = seer_stmt_bind_vector_sparse_i8(s, 1, 10, 2, idx, vali);
    SeerStatus esi = (bsi == SEER_OK) ? seer_stmt_execute(s) : bsi;
    seer_stmt_close(s);
    seer_commit(c);
    const char *er = seer_last_error(c);
    if (bb == SEER_ENOTIMPL) {
      skip(name, "native VECTOR bind requires a 23ai server");
    } else if (eb != SEER_OK || es != SEER_OK || esd != SEER_OK || esi != SEER_OK) {
      if (er && (strstr(er, "ORA-00907") || strstr(er, "ORA-00902") || strstr(er, "ORA-00942") ||
                 strstr(er, "ORA-43853")))
        skip(name, "VECTOR BINARY/SPARSE not available here");
      else
        fail(name, er ? er : "bind/exec");
    } else if (readback_has(c, "SELECT v FROM seervbin", "165", "60") &&
               readback_has(c, "SELECT v FROM seervsp", "[2, 7]", "1.5") &&
               readback_has(c, "SELECT v FROM seervspd", "[2, 7]", "-2.25") &&
               readback_has(c, "SELECT v FROM seervspi", "[2, 7]", "-3")) {
      pass(name);
    } else {
      fail(name, "readback mismatch");
    }
    run(c, "DROP TABLE seervbin");
    run(c, "DROP TABLE seervsp");
    run(c, "DROP TABLE seervspd");
    run(c, "DROP TABLE seervspi");
  }

  {
    const char *name = "XMLType bind";
    run(c, "DROP TABLE seer_xb");
    run(c, "CREATE TABLE seer_xb (x XMLTYPE)");
    SeerStmt *s = NULL;
    seer_stmt_prepare(c, "INSERT INTO seer_xb VALUES (:1)", &s);
    SeerStatus b = seer_stmt_bind_xmltype(s, 1, "<a><b>hi</b></a>");
    SeerStatus e = (b == SEER_OK) ? seer_stmt_execute(s) : b;
    seer_stmt_close(s);
    seer_commit(c);
    const char *er = seer_last_error(c);
    if (e != SEER_OK) {
      if (er && (strstr(er, "ORA-00942") || strstr(er, "ORA-43853") || strstr(er, "ORA-01031")))
        skip(name, "XMLType column not available here");
      else
        fail(name, er ? er : "bind/exec");
    } else if (readback_has(c, "SELECT t.x.getStringVal() FROM seer_xb t", "<a>", "hi")) {
      /* getStringVal() returns the XML as text, so the check works even where
       * XMLType is legacy CLOB-stored (11g) and not decoded inline on fetch. */
      pass(name);
    } else {
      fail(name, "readback mismatch");
    }
    run(c, "DROP TABLE seer_xb");
  }

  /* --- PL/SQL package-level types: a record (with PLS_INTEGER / BOOLEAN / DATE
   * attributes), a record nesting a record, a nested table and an index-by
   * table, named PKG.TYPE. Their metadata is in ALL_PLSQL_TYPES & co., and an
   * index-by table keys each element from 0. --- */
  run(c, "CREATE OR REPLACE PACKAGE seer_pkt AS "
         "TYPE rec IS RECORD (id NUMBER, name VARCHAR2(30), n PLS_INTEGER, b BOOLEAN, d DATE); "
         "TYPE outer_rec IS RECORD (r rec, tag VARCHAR2(10)); "
         "TYPE numtab IS TABLE OF NUMBER; "
         "TYPE strix IS TABLE OF VARCHAR2(40) INDEX BY BINARY_INTEGER; "
         "FUNCTION f(r rec) RETURN VARCHAR2; FUNCTION o(x outer_rec) RETURN VARCHAR2; "
         "FUNCTION g(t numtab) RETURN VARCHAR2; FUNCTION h(t strix) RETURN VARCHAR2; END;");
  run(c, "CREATE OR REPLACE PACKAGE BODY seer_pkt AS "
         "FUNCTION f(r rec) RETURN VARCHAR2 IS BEGIN RETURN r.id || '/' || r.name || '/' || r.n "
         "|| '/' || CASE WHEN r.b THEN 'T' WHEN NOT r.b THEN 'F' ELSE 'N' END || '/' || "
         "TO_CHAR(r.d, 'YYYY-MM-DD'); END; "
         "FUNCTION o(x outer_rec) RETURN VARCHAR2 IS BEGIN RETURN f(x.r) || '#' || x.tag; END; "
         "FUNCTION g(t numtab) RETURN VARCHAR2 IS s NUMBER := 0; BEGIN "
         "FOR i IN 1 .. t.COUNT LOOP s := s + t(i); END LOOP; RETURN t.COUNT || ':' || s; END; "
         "FUNCTION h(t strix) RETURN VARCHAR2 IS BEGIN RETURN t.COUNT || ':' || t.FIRST || ':' "
         "|| t(t.FIRST) || ',' || t(t.LAST); END; END;");
  {
    static const struct {
      const char *name, *sql, *type;
      int collection, n;
      const char *vals[6];
      const char *want;
    } cases[] = {
        {"package record bind",
         "BEGIN :1 := seer_pkt.f(:2); END;",
         "SEER_PKT.REC",
         0,
         5,
         {"42", "alpha", "-7", "TRUE", "2024-05-06"},
         "42/alpha/-7/T/2024-05-06"},
        {"package record nesting a record bind",
         "BEGIN :1 := seer_pkt.o(:2); END;",
         "SEER_PKT.OUTER_REC",
         0,
         6,
         {"7", "beta", "3", "FALSE", "2020-01-02", "tg"},
         "7/beta/3/F/2020-01-02#tg"},
        {"package nested table bind",
         "BEGIN :1 := seer_pkt.g(:2); END;",
         "SEER_PKT.NUMTAB",
         1,
         3,
         {"1", "2.5", "40"},
         "3:43.5"},
        {"package index-by table bind",
         "BEGIN :1 := seer_pkt.h(:2); END;",
         "SEER_PKT.STRIX",
         1,
         3,
         {"zero", "one", "two"},
         "3:0:zero,two"},
    };
    for (size_t k = 0; k < sizeof cases / sizeof cases[0]; k++) {
      char out[256];
      SeerStatus st = call_with_type(c, cases[k].sql, schema, cases[k].type, cases[k].collection,
                                     cases[k].vals, cases[k].n, out, sizeof out);
      if (st == SEER_ENOTIMPL) {
        skip(cases[k].name, "object binds require a 12c+ server");
      } else if (st != SEER_OK) {
        fail(cases[k].name, seer_last_error(c) ? seer_last_error(c) : "bind/exec");
      } else if (strcmp(out, cases[k].want) != 0) {
        char m[400];
        snprintf(m, sizeof m, "got '%s', want '%s'", out, cases[k].want);
        fail(cases[k].name, m);
      } else {
        pass(cases[k].name);
      }
    }
  }
  run(c, "DROP PACKAGE seer_pkt");

  /* --- a SQL object with a BOOLEAN attribute (23ai): bound and fetched back.
   * In the image the attribute is 4 bytes with the truth in the first. --- */
  run(c, "DROP TABLE seer_bo_t");
  run(c, "DROP TYPE seer_bo");
  {
    const char *name = "SQL OBJECT with a BOOLEAN attribute";
    /* Before 23ai a CREATE TYPE with a BOOLEAN attribute succeeds "with
     * compilation errors", so ask for a SQL BOOLEAN directly. */
    SeerStmt *s = NULL;
    int has_bool = seer_stmt_prepare(c, "SELECT TRUE FROM dual", &s) == SEER_OK &&
                   seer_stmt_execute(s) == SEER_OK;
    seer_stmt_close(s);
    if (!has_bool) {
      skip(name, "no SQL BOOLEAN before 23ai");
    } else {
      run(c, "CREATE TYPE seer_bo AS OBJECT (n NUMBER, b BOOLEAN)");
      run(c, "CREATE TABLE seer_bo_t (id NUMBER, o seer_bo)");
      const char *t[2] = {"1", "TRUE"}, *f[2] = {"2", "FALSE"};
      SeerStatus e = SEER_OK;
      for (int k = 0; k < 2 && e == SEER_OK; k++) {
        SeerStmt *ins = NULL;
        seer_stmt_prepare(c, "INSERT INTO seer_bo_t VALUES (:1, :2)", &ins);
        e = seer_stmt_bind_int64(ins, 1, k + 1);
        if (e == SEER_OK)
          e = seer_stmt_bind_object(ins, 2, schema, "SEER_BO", k == 0 ? t : f, 2);
        if (e == SEER_OK)
          e = seer_stmt_execute(ins);
        seer_stmt_close(ins);
      }
      seer_commit(c);
      if (e != SEER_OK)
        fail(name, seer_last_error(c) ? seer_last_error(c) : "bind/insert");
      else if (!readback_has(c, "SELECT o FROM seer_bo_t WHERE id = 1", "1", "TRUE") ||
               !readback_has(c, "SELECT o FROM seer_bo_t WHERE id = 2", "2", "FALSE") ||
               !readback_has(c,
                             "SELECT CASE WHEN t.o.b THEN 'yes' END || COUNT(*) FROM seer_bo_t t "
                             "WHERE t.o.b GROUP BY t.o.b",
                             "yes", "1"))
        fail(name, "readback mismatch");
      else
        pass(name);
      run(c, "DROP TABLE seer_bo_t");
      run(c, "DROP TYPE seer_bo");
    }
  }

  /* --- object / collection OUT binds: the value comes back in the object
   * frame a fetched row carries and is rendered as a fetched object is. --- */
  run(c, "CREATE OR REPLACE TYPE seer_oo AS OBJECT (n NUMBER, s VARCHAR2(20))");
  run(c, "CREATE OR REPLACE TYPE seer_on AS OBJECT (id NUMBER, inner seer_oo)");
  run(c, "CREATE OR REPLACE TYPE seer_ol AS VARRAY(10) OF NUMBER");
  run(c, "CREATE OR REPLACE TYPE seer_obig AS OBJECT (a VARCHAR2(4000), b VARCHAR2(4000))");
  run(c, "CREATE OR REPLACE PACKAGE seer_pko AS "
         "TYPE rec IS RECORD (id NUMBER, name VARCHAR2(30), n PLS_INTEGER, d DATE); "
         "TYPE strix IS TABLE OF VARCHAR2(40) INDEX BY BINARY_INTEGER; END;");
  run(c, "CREATE OR REPLACE PROCEDURE seer_oip(o IN OUT seer_oo) AS BEGIN "
         "o := seer_oo(o.n + 100, o.s || 'yz'); END;");
  {
    static const struct {
      const char *name, *sql, *type, *want;
      int want_null;
    } cases[] = {
        {"object OUT bind", "BEGIN :1 := seer_oo(42, 'hello'); END;", "SEER_OO", "42, hello", 0},
        {"nested object OUT bind", "BEGIN :1 := seer_on(7, seer_oo(8, 'in')); END;", "SEER_ON",
         "7, 8, in", 0},
        {"collection OUT bind", "BEGIN :1 := seer_ol(1, 2.5, 3); END;", "SEER_OL", "[1, 2.5, 3]",
         0},
        {"NULL object OUT bind", "BEGIN :1 := NULL; END;", "SEER_OO", "", 1},
        {"package record OUT bind",
         "DECLARE r seer_pko.rec; BEGIN r.id := 5; r.name := 'rec'; r.n := -3; "
         "r.d := DATE '2021-02-03'; :1 := r; END;",
         "SEER_PKO.REC", "5, rec, -3, 2021-02-03 00:00:00", 0},
        {"index-by table OUT bind",
         "DECLARE t seer_pko.strix; BEGIN t(-5) := 'neg'; t(10) := 'ten'; :1 := t; END;",
         "SEER_PKO.STRIX", "[-5: neg, 10: ten]", 0},
    };
    for (size_t k = 0; k < sizeof cases / sizeof cases[0]; k++) {
      SeerStmt *s = NULL;
      SeerStatus st = seer_stmt_prepare(c, cases[k].sql, &s);
      if (st == SEER_OK)
        st = seer_stmt_bind_object_out(s, 1, schema, cases[k].type);
      if (st == SEER_OK)
        st = seer_stmt_execute(s);
      const void *d = NULL;
      size_t l = 0;
      int isnull = 0, isbin = 0;
      if (st == SEER_OK)
        st = seer_stmt_out_data(s, 1, &d, &l, &isnull, &isbin);
      char got[128];
      snprintf(got, sizeof got, "%.*s", (int)l, d ? (const char *)d : "");
      seer_stmt_close(s);
      if (st == SEER_ENOTIMPL) {
        skip(cases[k].name, "object binds require a 12c+ server");
      } else if (st != SEER_OK) {
        fail(cases[k].name, seer_last_error(c) ? seer_last_error(c) : "bind/exec");
      } else if (isnull != cases[k].want_null || strcmp(got, cases[k].want) != 0) {
        char m[300];
        snprintf(m, sizeof m, "got '%s' (null=%d), want '%s'", got, isnull, cases[k].want);
        fail(cases[k].name, m);
      } else {
        pass(cases[k].name);
      }
    }
  }
  {
    /* An object image well past the 2000 bytes the OUT bind announces. */
    const char *name = "large object OUT bind";
    SeerStmt *s = NULL;
    SeerStatus st = seer_stmt_prepare(
        c, "BEGIN :1 := seer_obig(RPAD('a', 3500, 'a'), RPAD('b', 3900, 'b')); END;", &s);
    if (st == SEER_OK)
      st = seer_stmt_bind_object_out(s, 1, schema, "SEER_OBIG");
    if (st == SEER_OK)
      st = seer_stmt_execute(s);
    const void *d = NULL;
    size_t l = 0;
    int isnull = 0, isbin = 0;
    if (st == SEER_OK)
      st = seer_stmt_out_data(s, 1, &d, &l, &isnull, &isbin);
    int ok = st == SEER_OK && l == 3500 + 2 + 3900 && ((const char *)d)[0] == 'a' &&
             ((const char *)d)[l - 1] == 'b';
    seer_stmt_close(s);
    if (st == SEER_ENOTIMPL)
      skip(name, "object binds require a 12c+ server");
    else if (!ok)
      fail(name, st != SEER_OK && seer_last_error(c) ? seer_last_error(c) : "value mismatch");
    else
      pass(name);
  }
  {
    const char *name = "object IN OUT bind";
    const char *v[2] = {"1", "x"};
    SeerStmt *s = NULL;
    SeerStatus st = seer_stmt_prepare(c, "BEGIN seer_oip(:1); END;", &s);
    if (st == SEER_OK)
      st = seer_stmt_bind_object(s, 1, schema, "SEER_OO", v, 2);
    if (st == SEER_OK)
      st = seer_stmt_bind_set_inout(s, 1, 0);
    if (st == SEER_OK)
      st = seer_stmt_execute(s);
    const void *d = NULL;
    size_t l = 0;
    int isnull = 0, isbin = 0;
    if (st == SEER_OK)
      st = seer_stmt_out_data(s, 1, &d, &l, &isnull, &isbin);
    char got[64];
    snprintf(got, sizeof got, "%.*s", (int)l, d ? (const char *)d : "");
    seer_stmt_close(s);
    if (st == SEER_ENOTIMPL)
      skip(name, "object binds require a 12c+ server");
    else if (st != SEER_OK)
      fail(name, seer_last_error(c) ? seer_last_error(c) : "bind/exec");
    else if (strcmp(got, "101, xyz") != 0)
      fail(name, got);
    else
      pass(name);
  }
  run(c, "DROP PROCEDURE seer_oip");
  run(c, "DROP PACKAGE seer_pko");
  run(c, "DROP TYPE seer_on");
  run(c, "DROP TYPE seer_oo");
  run(c, "DROP TYPE seer_ol");
  run(c, "DROP TYPE seer_obig");

  seer_disconnect(c);
  printf("SUMMARY pass=%d fail=%d skip=%d\n", pass_n, fail_n, skip_n);
  fflush(stdout);
  if (fail_n > 0)
    fprintf(stderr, "%s", fail_log);
  return fail_n > 0 ? 1 : 0;
}

/* Handle allocation/deallocation: SQLAllocHandle / SQLFreeHandle.
 *
 * In ODBC 3.x these subsume the deprecated SQLAllocEnv/Connect/Stmt and
 * SQLFreeEnv/Connect/Stmt; the Driver Manager maps the old 2.x calls onto
 * these for us, so we implement only the 3.x form.
 *
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "odbc_internal.h"

/* A statement on connection `c`: its attribute defaults, a cursor name of
 * its own, its implicit descriptors, and its place in the connection's list. */
static SQLRETURN alloc_stmt(OdbcDbc *c, SQLHANDLE *OutputHandle)
{
  if (!c->connected)
    return seer_odbc_diag(c, "08003", 0, "Connection not open", SQL_ERROR);
  OdbcStmt *s = calloc(1, sizeof *s);
  if (s == NULL)
    return SQL_ERROR;
  s->h.type = SQL_HANDLE_STMT;
  s->dbc = c;
  s->getdata_col = -1;
  s->paramset_size = 1;
  s->row_array_size = 1;
  s->rowset_start = -1;
  s->concurrency = SQL_CONCUR_READ_ONLY;
  s->retrieve_data = SQL_RD_ON; /* SQL_RD_OFF is 0: calloc would turn retrieval off */
  s->rowid_col = -1;
  s->metadata_id = c->metadata_id; /* the connection's default (#278) */
  /* A cursor name of its own, SQL_CURn, until the application sets one;
   * the connection lists its statements to find one by name (#288). */
  char name[32];
  snprintf(name, sizeof name, "SQL_CUR%lu", ++c->cursor_seq);
  s->cursor_name = strdup(name);
  if (s->cursor_name == NULL) {
    free(s);
    return SQL_ERROR;
  }
  s->cur_row = -1;
  s->next_stmt = c->stmts;
  c->stmts = s;
  /* The implicit descriptors share the statement's lifetime. */
  s->ard.h.type = s->apd.h.type = s->ird.h.type = s->ipd.h.type = SQL_HANDLE_DESC;
  s->ard.stmt = s->apd.stmt = s->ird.stmt = s->ipd.stmt = s;
  s->ard.kind = SEER_DESC_ARD;
  s->apd.kind = SEER_DESC_APD;
  s->ird.kind = SEER_DESC_IRD;
  s->ipd.kind = SEER_DESC_IPD;
  s->ab = &s->own_binds; /* the implicit ARD's records, until one is set (#291) */
  *OutputHandle = (SQLHANDLE)s;
  return SQL_SUCCESS;
}

SQLRETURN SQL_API SQLAllocHandle(SQLSMALLINT HandleType, SQLHANDLE InputHandle,
                                 SQLHANDLE *OutputHandle)
{
  if (OutputHandle == NULL)
    return SQL_ERROR;
  *OutputHandle = SQL_NULL_HANDLE;

  switch (HandleType) {
  case SQL_HANDLE_ENV: {
    OdbcEnv *e = calloc(1, sizeof *e);
    if (e == NULL)
      return SQL_ERROR;
    e->h.type = SQL_HANDLE_ENV;
    *OutputHandle = (SQLHANDLE)e;
    return SQL_SUCCESS;
  }
  case SQL_HANDLE_DBC: {
    if (InputHandle == NULL)
      return SQL_INVALID_HANDLE;
    OdbcDbc *c = calloc(1, sizeof *c);
    if (c == NULL)
      return SQL_ERROR;
    c->h.type = SQL_HANDLE_DBC;
    c->env = (OdbcEnv *)InputHandle;
    c->autocommit = SQL_AUTOCOMMIT_ON;
    c->login_timeout = -1;
    *OutputHandle = (SQLHANDLE)c;
    return SQL_SUCCESS;
  }
  case SQL_HANDLE_STMT:
    if (InputHandle == NULL)
      return SQL_INVALID_HANDLE;
    return alloc_stmt((OdbcDbc *)InputHandle, OutputHandle);
  case SQL_HANDLE_DESC: { /* explicit: an application descriptor of the connection (#291) */
    if (InputHandle == NULL)
      return SQL_INVALID_HANDLE;
    OdbcDbc *c = (OdbcDbc *)InputHandle;
    if (!c->connected)
      return seer_odbc_diag(c, "08003", 0, "Connection not open", SQL_ERROR);
    OdbcDesc *d = calloc(1, sizeof *d);
    if (d == NULL)
      return seer_odbc_diag(c, "HY001", 0, "Out of memory", SQL_ERROR);
    d->h.type = SQL_HANDLE_DESC;
    d->kind = SEER_DESC_ARD; /* an application descriptor; ARD or APD as it is used */
    d->is_explicit = 1;
    d->dbc = c;
    d->next_desc = c->descs;
    c->descs = d;
    *OutputHandle = (SQLHANDLE)d;
    return SQL_SUCCESS;
  }
  default:
    return SQL_ERROR;
  }
}

/* Free an explicit descriptor: the statements using it go back to their
 * implicit ARD / APD (#291). */
static void free_explicit_desc(OdbcDesc *d)
{
  OdbcDbc *c = d->dbc;
  for (OdbcStmt *s = c->stmts; s != NULL; s = s->next_stmt) {
    if (s->ard_ext == d) {
      s->ard_ext = NULL;
      s->ab = &s->own_binds;
    }
    if (s->apd_ext == d)
      s->apd_ext = NULL;
  }
  for (void **pp = &c->descs; *pp != NULL; pp = &((OdbcDesc *)*pp)->next_desc)
    if (*pp == d) {
      *pp = d->next_desc;
      break;
    }
  free(d->recs.binds);
  seer_odbc_diag_free(d);
  free(d);
}

SQLRETURN SQL_API SQLFreeHandle(SQLSMALLINT HandleType, SQLHANDLE Handle)
{
  if (Handle == NULL)
    return SQL_INVALID_HANDLE;

  switch (HandleType) {
  case SQL_HANDLE_STMT: {
    OdbcStmt *s = (OdbcStmt *)Handle;
    if (s->core != NULL)
      seer_stmt_close(s->core);
    seer_odbc_free_updatable(s);
    seer_odbc_diag_free(s);
    seer_odbc_diag_free(&s->ard);
    seer_odbc_diag_free(&s->apd);
    seer_odbc_diag_free(&s->ird);
    seer_odbc_diag_free(&s->ipd);
    free(s->own_binds.binds);
    for (int i = 0; i < s->num_params; i++)
      free(s->params[i].dae_buf), free(s->params[i].ref_type);
    free(s->params);
    free(s->param_rows);
    free(s->pas_sql);
    free(s->sql);
    for (void **pp = &s->dbc->stmts; *pp != NULL; pp = &((OdbcStmt *)*pp)->next_stmt)
      if (*pp == s) {
        *pp = s->next_stmt;
        break;
      }
    free(s->cursor_name);
    free(s);
    return SQL_SUCCESS;
  }
  case SQL_HANDLE_DESC:
    /* An implicit descriptor is its statement's, freed with it. */
    if (!((OdbcDesc *)Handle)->is_explicit)
      return seer_odbc_diag(Handle, "HY017", 0,
                            "Invalid use of an automatically allocated "
                            "descriptor handle",
                            SQL_ERROR);
    free_explicit_desc((OdbcDesc *)Handle);
    return SQL_SUCCESS;
  case SQL_HANDLE_DBC: {
    OdbcDbc *c = (OdbcDbc *)Handle;
    if (c->connected && c->conn != NULL)
      seer_disconnect(c->conn);
    while (c->descs != NULL) /* explicit descriptors go with their connection */
      free_explicit_desc(c->descs);
    free(c->browse_cs);
    free(c->info_dsn);
    free(c->info_user);
    free(c->info_server);
    seer_odbc_diag_free(c);
    free(c);
    return SQL_SUCCESS;
  }
  case SQL_HANDLE_ENV:
    seer_odbc_diag_free(Handle);
    free(Handle);
    return SQL_SUCCESS;
  default:
    return SQL_ERROR;
  }
}

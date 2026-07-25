/* The SQL_C_* conversion seam (docs/ARCHITECTURE.md rule 3).
 *
 * The protocol core renders every value to a canonical form - text for
 * NUMBER/DATE/strings, raw bytes for binary. This is the one place that turns
 * that into whatever ODBC C type the application asked for.
 *
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SEERODBC_CONVERT_H
#define SEERODBC_CONVERT_H

#include <stddef.h>

#include "odbc_platform.h"   /* <windows.h> before the ODBC headers on Windows */

#include <sql.h>

/* Convert a column value (val/vallen; binary if is_binary) to the C type
 * `target`, into `buf`/`buflen`, setting *ind (StrLen_or_Ind). `offset` (may
 * be NULL) tracks partial SQL_C_CHAR/BINARY retrieval across SQLGetData calls,
 * in source-byte units. Returns SQL_SUCCESS, SQL_SUCCESS_WITH_INFO (truncated),
 * or SQL_ERROR (e.g. NULL with no indicator, or an unconvertible target). */
SQLRETURN seer_odbc_convert(const void *val, size_t vallen, int is_null,
                            int is_binary, SQLSMALLINT target,
                            SQLPOINTER buf, SQLLEN buflen, SQLLEN *ind,
                            SQLLEN *offset);

#endif /* SEERODBC_CONVERT_H */

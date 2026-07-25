/* Self-contained odbc.ini / odbcinst.ini reader. See odbcini.h for the rationale
 * (loading identically under unixODBC and iODBC with no instlib at run time) and
 * the SQLGetPrivateProfileString-compatible contract.
 *
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "compat.h"
#include "odbcini.h"

/* Trim leading whitespace by advancing the pointer; trailing whitespace
 * (including the CR of a CRLF file) by writing a NUL. Returns the new start. */
static char *trim(char *s)
{
    while (*s == ' ' || *s == '\t')
        s++;
    char *end = s + strlen(s);
    while (end > s && (end[-1] == ' ' || end[-1] == '\t' ||
                       end[-1] == '\r' || end[-1] == '\n'))
        *--end = '\0';
    return s;
}

/* Copy val (NULL treated as "") into retbuf per the ODBC contract; return the
 * number of bytes written, excluding the NUL. */
static int copy_out(const char *val, char *retbuf, int retbuf_len)
{
    if (retbuf == NULL || retbuf_len <= 0)
        return 0;
    if (val == NULL)
        val = "";
    int n = (int)strlen(val);
    if (n > retbuf_len - 1)
        n = retbuf_len - 1;
    memcpy(retbuf, val, (size_t)n);
    retbuf[n] = '\0';
    return n;
}

/* Scan one INI file for section/entry (both case-insensitive). Returns a
 * malloc'd value, or NULL if the file or key is absent. */
static char *lookup_in_file(const char *path, const char *section,
                            const char *entry)
{
#ifdef _WIN32
    FILE *f = fopen(path, "r");    /* no close-on-exec concept on Windows */
#else
    FILE *f = fopen(path, "re");   /* 'e' = O_CLOEXEC */
#endif
    if (f == NULL)
        return NULL;

    char *line = NULL, *found = NULL;
    size_t cap = 0;
    int in_section = 0;
    ptrdiff_t len;
    while ((len = seer_getline(&line, &cap, f)) != -1) {
        char *p = trim(line);
        if (*p == '\0' || *p == ';' || *p == '#')
            continue;
        if (*p == '[') {
            char *close = strchr(p, ']');
            if (close == NULL)
                continue;
            *close = '\0';
            in_section = (strcasecmp(trim(p + 1), section) == 0);
            continue;
        }
        if (!in_section)
            continue;
        char *eq = strchr(p, '=');
        if (eq == NULL)
            continue;
        *eq = '\0';
        if (strcasecmp(trim(p), entry) == 0) {
            found = strdup(trim(eq + 1));
            break;
        }
    }
    free(line);
    fclose(f);
    return found;
}

/* Directory holding the system files: ODBCSYSINI, else /etc. */
static const char *system_dir(void)
{
    const char *d = getenv("ODBCSYSINI");
    return (d != NULL && d[0] != '\0') ? d : "/etc";
}

int seer_get_private_profile_string(const char *section, const char *entry,
                                    const char *defstr, char *retbuf,
                                    int retbuf_len, const char *filename)
{
    /* Enumeration is out of scope; nothing to match without both names. */
    if (section == NULL || entry == NULL || filename == NULL)
        return copy_out(defstr, retbuf, retbuf_len);

    char path[4096];
    char *val = NULL;

    if (strchr(filename, '/') != NULL) {
        /* An explicit path: use it verbatim. */
        val = lookup_in_file(filename, section, entry);
    } else if (strcasecmp(filename, "odbc.ini") == 0) {
        /* User file first (so its entries win), then the system file. */
        const char *odbcini = getenv("ODBCINI");
        const char *home = getenv("HOME");
        if (odbcini != NULL && odbcini[0] != '\0')
            val = lookup_in_file(odbcini, section, entry);
        if (val == NULL && home != NULL && home[0] != '\0') {
            snprintf(path, sizeof path, "%s/.odbc.ini", home);
            val = lookup_in_file(path, section, entry);
        }
        if (val == NULL) {
            snprintf(path, sizeof path, "%s/odbc.ini", system_dir());
            val = lookup_in_file(path, section, entry);
        }
    } else if (strcasecmp(filename, "odbcinst.ini") == 0) {
        const char *inst = getenv("ODBCINSTINI");
        if (inst != NULL && inst[0] == '/') {
            val = lookup_in_file(inst, section, entry);
        } else {
            snprintf(path, sizeof path, "%s/odbcinst.ini", system_dir());
            val = lookup_in_file(path, section, entry);
        }
    } else {
        /* Any other bare name: resolve against the system directory. */
        snprintf(path, sizeof path, "%s/%s", system_dir(), filename);
        val = lookup_in_file(path, section, entry);
    }

    int n = copy_out(val != NULL ? val : defstr, retbuf, retbuf_len);
    free(val);
    return n;
}

/* Protocol core - connection and statement lifecycle.
 *
 * Implements the TNS connection phase (PROTOCOL.md §2): build a TNS_CONNECT
 * with the fixed 58-byte header and a connect descriptor, send it, and react
 * to the server's reply - ACCEPT (negotiate SDU), REDIRECT (reconnect and
 * retry), RESEND (resend), or REFUSE (surface the error). This reaches the
 * point of an accepted TNS session; the TTC protocol negotiation and O5LOGON
 * authentication that follow (PROTOCOL.md §3-4) are the next M1 increment, so
 * seer_connect currently returns SEER_ENOTIMPL once the handshake succeeds.
 *
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#include "seer/seertns.h"

#include "conn.h"
#include "log.h"
#include "netcompat.h"   /* gethostname(): <unistd.h> on POSIX, Winsock on Windows */
#include "packet.h"
#include "reader.h"
#include "transport.h"
#include "ttc.h"
#include "writer.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* TNS_CONNECT fixed-header constants (PROTOCOL.md §2.1). */
#define TNS_VERSION_DESIRED   0x0139   /* 313 - 11g */
/* Lowest-compatible version we accept. Kept low (300) so pre-11g servers can
 * settle at their own ceiling - Oracle 9i's max is 312, so a 313 floor would make
 * it reject the CONNECT. Newer servers still negotiate up to TNS_VERSION_DESIRED. */
#define TNS_VERSION_MIN_COMPAT 0x012C  /* 300 */
#define TNS_SDU_DEFAULT       0x2000   /* 8192 */
#define TNS_TDU_DEFAULT       0xFFFF   /* 65535 */
#define TNS_PROTO_CHARS       0x4F98
#define TNS_HW_BYTE_ORDER     0x0001   /* big-endian */
#define TNS_CONNECT_DATA_OFF  0x003A   /* 58 = 8-byte TNS header + 50-byte body */
#define TNS_ANO_FLAGS         0x8484   /* ANO (Native Network Encryption) disabled */
#define TNS_CONNECT_HDR_RSVD  24       /* zero padding to reach the 50-byte body */

#define MAX_REDIRECTS 5
#define MAX_RESENDS   3

/* struct SeerConn lives in conn.h (shared with ttc.c). */

/* ------------------------------------------------------------------ helpers */

/* Build the TNS_CONNECT body (everything after the 8-byte TNS header): the
 * 50-byte fixed header followed by the connect descriptor string. */
static SeerStatus build_connect_body(const SeerConnParams *p, SeerWriter *w)
{
    char hostname[256];
    if (gethostname(hostname, sizeof hostname - 1) != 0)
        strcpy(hostname, "localhost");
    hostname[sizeof hostname - 1] = '\0';

    const char *user  = (p->username && *p->username) ? p->username : "seerodbc";
    const char *proto = p->use_tls ? "TCPS" : "TCP";
    /* DRCP: route to the connection broker's pooled server (#130). */
    const char *pooled = ((p->cclass && p->cclass[0]) || p->purity)
                         ? "(SERVER=POOLED)" : "";

    /* Address by SID (older servers, e.g. 9i) if given, else by SERVICE_NAME. */
    char target[288];
    if (p->sid && p->sid[0])
        snprintf(target, sizeof target, "(SID=%s)", p->sid);
    else
        snprintf(target, sizeof target, "(SERVICE_NAME=%s)",
                 p->service_name ? p->service_name : "");

    char desc[1024];
    int dlen = snprintf(desc, sizeof desc,
        "(DESCRIPTION="
          "(CONNECT_DATA="
            "%s"
            "%s"
            "(CID=(PROGRAM=seerodbc)(HOST=%s)(USER=%s)))"
          "(ADDRESS=(PROTOCOL=%s)(HOST=%s)(PORT=%u)))",
        target,
        pooled,
        hostname, user, proto,
        p->host ? p->host : "", (unsigned)(p->port ? p->port : 1521));
    if (dlen < 0 || (size_t)dlen >= sizeof desc)
        return SEER_EPARAM;

    if (!seer_writer_init(w, 64 + (size_t)dlen))
        return SEER_ENOMEM;

    seer_writer_u16(w, TNS_VERSION_DESIRED);   /* off  0: protocol version     */
    seer_writer_u16(w, TNS_VERSION_MIN_COMPAT);/* off  2: lowest compatible    */
    seer_writer_u16(w, 0x0000);                /* off  4: global svc options   */
    seer_writer_u16(w, TNS_SDU_DEFAULT);       /* off  6: SDU                  */
    seer_writer_u16(w, TNS_TDU_DEFAULT);       /* off  8: TDU                  */
    seer_writer_u16(w, TNS_PROTO_CHARS);       /* off 10: proto characteristics*/
    seer_writer_u16(w, 0x0000);                /* off 12: max packets before ACK*/
    seer_writer_u16(w, TNS_HW_BYTE_ORDER);     /* off 14: hardware byte order  */
    seer_writer_u16(w, 0x0000);                /* off 16: connect data length  */
    seer_writer_u16(w, TNS_CONNECT_DATA_OFF);  /* off 18: connect data offset  */
    seer_writer_u32(w, 0x00000000);            /* off 20: max recv connect data*/
    seer_writer_u16(w, TNS_ANO_FLAGS);         /* off 24: ANO flags            */
    for (int i = 0; i < TNS_CONNECT_HDR_RSVD; i++)
        seer_writer_u8(w, 0x00);               /* off 26..50: reserved         */

    seer_writer_bytes(w, desc, (size_t)dlen);  /* off 50: connect descriptor   */
    seer_writer_patch_u16(w, 16, (uint16_t)dlen);

    if (!seer_writer_ok(w)) {
        seer_writer_free(w);
        return SEER_ENOMEM;
    }
    return SEER_OK;
}

/* Copy the value of `key` (e.g. "(HOST=") from `s` up to the next ')'. */
static bool find_kv(const char *s, const char *key, char *out, size_t out_sz)
{
    const char *p = strstr(s, key);
    if (p == NULL)
        return false;
    p += strlen(key);
    size_t i = 0;
    while (*p != '\0' && *p != ')' && i + 1 < out_sz)
        out[i++] = *p++;
    out[i] = '\0';
    return i > 0;
}

/* Pull HOST/PORT out of the ADDRESS block of a REDIRECT descriptor. */
static bool parse_redirect(const uint8_t *body, size_t len,
                           char *host, size_t host_sz, uint16_t *port)
{
    if (body == NULL || len == 0)
        return false;

    const uint8_t *s = body;
    size_t n = len;
    if (n >= 2 && s[0] != '(') {   /* optional 2-byte data-length prefix */
        s += 2;
        n -= 2;
    }

    char *str = malloc(n + 1);
    if (str == NULL)
        return false;
    memcpy(str, s, n);
    str[n] = '\0';

    /* Scope to ADDRESS so we don't grab the client HOST echoed in CID. */
    const char *scope = strstr(str, "(ADDRESS=");
    if (scope == NULL)
        scope = str;

    char portbuf[16];
    bool ok = find_kv(scope, "(HOST=", host, host_sz) &&
              find_kv(scope, "(PORT=", portbuf, sizeof portbuf);
    if (ok)
        *port = (uint16_t)atoi(portbuf);

    free(str);
    return ok;
}

static void log_refuse(const uint8_t *body, size_t len)
{
    if (body == NULL || len < 4) {
        seer_log(SEER_LOG_ERROR, "TNS: REFUSE (no detail)");
        return;
    }
    size_t errlen = ((size_t)body[2] << 8) | body[3];
    size_t avail  = len - 4;
    if (errlen > avail)
        errlen = avail;
    seer_log(SEER_LOG_ERROR, "TNS: REFUSE: %.*s", (int)errlen, (const char *)(body + 4));
}

/* ------------------------------------------------------------- public API */

SeerStatus seer_connect(const SeerConnParams *params, SeerConn **out)
{
    if (params == NULL || out == NULL || params->host == NULL)
        return SEER_EPARAM;
    *out = NULL;

    SeerWriter body;
    SeerStatus st = build_connect_body(params, &body);
    if (st != SEER_OK)
        return st;

    SeerConn *conn = calloc(1, sizeof *conn);
    if (conn == NULL) {
        seer_writer_free(&body);
        return SEER_ENOMEM;
    }
    conn->seq = 1;            /* TTC sequence numbers start at 1 */
    conn->autocommit = true;  /* ODBC default */

    char cur_host[256];
    snprintf(cur_host, sizeof cur_host, "%s", params->host);
    uint16_t cur_port = params->port ? params->port : 1521;

    int redirects = 0;
    int resends   = 0;

    for (;;) {
        if (conn->t == NULL) {
            st = seer_transport_connect(cur_host, cur_port, 0, &conn->t);
            if (st != SEER_OK)
                goto fail;
            /* TCPS: wrap the (possibly redirected) socket in TLS before any TNS
             * bytes flow. The SNI / verified hostname is the host we dialled. */
            if (params->use_tls) {
                st = seer_transport_start_tls(conn->t, cur_host, params->tls_ca,
                                              params->tls_verify);
                if (st != SEER_OK)
                    goto fail;
            }
        }

        st = seer_packet_send(conn->t, TNS_PT_CONNECT, body.buf, body.len);
        if (st != SEER_OK)
            goto fail;

        uint8_t  type  = 0;
        uint8_t *rbody = NULL;
        size_t   rlen  = 0;
        st = seer_packet_recv(conn->t, &type, &rbody, &rlen);
        if (st != SEER_OK)
            goto fail;

        if (type == TNS_PT_ACCEPT) {
            SeerReader r;
            seer_reader_init(&r, rbody, rlen);
            conn->version = seer_reader_u16(&r);  /* body off 0 */
            (void)seer_reader_u16(&r);            /* body off 2: service options */
            conn->sdu = seer_reader_u16(&r);      /* body off 4 */
            free(rbody);

            seer_log(SEER_LOG_INFO, "TNS: ACCEPT from %s:%u (version=%u, sdu=%u)",
                     cur_host, cur_port, conn->version, conn->sdu);
            break;   /* TNS session established; proceed to TTC negotiation */
        }

        if (type == TNS_PT_RESEND) {
            free(rbody);
            if (++resends > MAX_RESENDS) {
                seer_log(SEER_LOG_ERROR, "TNS: too many RESEND requests");
                st = SEER_EPROTO;
                goto fail;
            }
            seer_log(SEER_LOG_DEBUG, "TNS: RESEND (%d)", resends);
            continue;
        }

        if (type == TNS_PT_REDIRECT) {
            char     nh[256];
            uint16_t np = 0;
            bool ok = parse_redirect(rbody, rlen, nh, sizeof nh, &np);
            free(rbody);
            if (!ok) {
                seer_log(SEER_LOG_ERROR, "TNS: REDIRECT could not be parsed");
                st = SEER_EPROTO;
                goto fail;
            }
            if (++redirects > MAX_REDIRECTS) {
                seer_log(SEER_LOG_ERROR, "TNS: too many redirects");
                st = SEER_EPROTO;
                goto fail;
            }
            seer_log(SEER_LOG_INFO, "TNS: REDIRECT -> %s:%u", nh, np);
            seer_transport_close(conn->t);
            conn->t = NULL;
            snprintf(cur_host, sizeof cur_host, "%s", nh);
            cur_port = np;
            continue;
        }

        if (type == TNS_PT_REFUSE) {
            log_refuse(rbody, rlen);
            free(rbody);
            st = SEER_EPROTO;
            goto fail;
        }

        seer_log(SEER_LOG_ERROR, "TNS: unexpected packet type %u during handshake", type);
        free(rbody);
        st = SEER_EPROTO;
        goto fail;
    }

    /* TNS session is up. The connect body is no longer needed. */
    seer_writer_free(&body);

    /* TTC negotiation (PRO/DTY) + session setup, ending at the auth challenge. */
    SeerAuthChallenge challenge;
    st = seer_ttc_login(conn, params, &challenge);
    if (st != SEER_OK) {
        seer_disconnect(conn);
        return st;
    }

    /* O5LOGON: answer the challenge, send TTI_AUTH, validate the response. */
    st = seer_ttc_authenticate(conn, params, &challenge);
    seer_auth_challenge_free(&challenge);
    if (st != SEER_OK) {
        seer_disconnect(conn);
        return st;
    }

    *out = conn;
    return SEER_OK;

fail:
    seer_writer_free(&body);
    seer_disconnect(conn);
    return st;
}

void seer_disconnect(SeerConn *conn)
{
    if (conn == NULL)
        return;
    seer_ttc_logoff(conn);   /* best-effort TTI_LOGOFF + EOF on a live session */
    seer_transport_close(conn->t);
    seer_stmt_cache_clear(conn);
    free(conn->last_error);
    free(conn->tpc_context);
    free(conn);
}

/* seer_stmt_* live in stmt.c. */

const char *seer_last_error(SeerConn *conn)
{
    return conn ? conn->last_error : NULL;
}

void seer_set_autocommit(SeerConn *conn, int on)
{
    if (conn != NULL)
        conn->autocommit = (on != 0);
}

const char *seer_strerror(SeerStatus status)
{
    switch (status) {
    case SEER_OK:       return "ok";
    case SEER_ENOTIMPL: return "not implemented";
    case SEER_EIO:      return "I/O error";
    case SEER_EPROTO:   return "protocol error";
    case SEER_EAUTH:    return "authentication failed";
    case SEER_ENOMEM:   return "out of memory";
    case SEER_EPARAM:   return "invalid parameter";
    case SEER_ENODATA:  return "no more data";
    case SEER_EDB:      return "database error";
    }
    return "unknown error";
}

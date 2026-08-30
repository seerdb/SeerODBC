/*
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "packet.h"

#include "log.h"

#include <stdlib.h>

/* Largest body we frame in a single 16-bit-length packet. */
#define TNS_MAX_PAYLOAD (0xFFFFu - TNS_HEADER_LEN)

SeerStatus seer_packet_send(SeerTransport *t, uint8_t type,
                            const void *payload, size_t payload_len)
{
    if (t == NULL || (payload == NULL && payload_len > 0))
        return SEER_EPARAM;
    if (payload_len > TNS_MAX_PAYLOAD)
        return SEER_EPARAM;   /* fragmentation belongs to the TTC layer */

    /* Two header layouts, both 8 bytes with the type at byte 4: legacy (ub2
     * length + ub2 checksum) or large-SDU (ub4 length, replacing the legacy
     * length + checksum) once the negotiated version >= 315 (§1.1, #155). */
    uint32_t total = (uint32_t)(TNS_HEADER_LEN + payload_len);
    uint8_t hdr[TNS_HEADER_LEN];
    if (seer_transport_large_frames(t)) {
        hdr[0] = (uint8_t)(total >> 24); hdr[1] = (uint8_t)(total >> 16);
        hdr[2] = (uint8_t)(total >> 8);  hdr[3] = (uint8_t)total;
    } else {
        hdr[0] = (uint8_t)(total >> 8);  hdr[1] = (uint8_t)total;
        hdr[2] = 0x00;                   hdr[3] = 0x00;   /* packet flags */
    }
    hdr[4] = type;
    hdr[5] = 0x00;                       /* flags           */
    hdr[6] = 0x00; hdr[7] = 0x00;        /* header checksum */

    SeerStatus st = seer_transport_write_all(t, hdr, sizeof hdr);
    if (st != SEER_OK)
        return st;
    if (payload_len > 0)
        st = seer_transport_write_all(t, payload, payload_len);
    return st;
}

SeerStatus seer_packet_recv(SeerTransport *t, uint8_t *out_type,
                            uint8_t **out_body, size_t *out_len)
{
    if (t == NULL || out_type == NULL || out_body == NULL || out_len == NULL)
        return SEER_EPARAM;
    *out_body = NULL;
    *out_len  = 0;

    uint8_t hdr[TNS_HEADER_LEN];
    SeerStatus st = seer_transport_read_full(t, hdr, sizeof hdr);
    if (st != SEER_OK)
        return st;

    /* Large-SDU framing reads the length from the 4-byte field; legacy from the
     * 2-byte field. The type is at byte 4 in both. */
    uint32_t total = seer_transport_large_frames(t)
        ? ((uint32_t)hdr[0] << 24 | (uint32_t)hdr[1] << 16 |
           (uint32_t)hdr[2] << 8  | (uint32_t)hdr[3])
        : ((uint32_t)hdr[0] << 8  | (uint32_t)hdr[1]);
    uint8_t  type  = hdr[4];
    if (total < TNS_HEADER_LEN) {
        seer_log(SEER_LOG_ERROR, "packet: bogus length %u (< header)", total);
        return SEER_EPROTO;
    }

    size_t body_len = (size_t)total - TNS_HEADER_LEN;
    *out_type = type;
    if (body_len == 0)
        return SEER_OK;

    uint8_t *body = malloc(body_len);
    if (body == NULL)
        return SEER_ENOMEM;

    st = seer_transport_read_full(t, body, body_len);
    if (st != SEER_OK) {
        free(body);
        return st;
    }

    *out_body = body;
    *out_len  = body_len;
    seer_log(SEER_LOG_DEBUG, "packet: recv type=%u body=%zu", type, body_len);
    return SEER_OK;
}

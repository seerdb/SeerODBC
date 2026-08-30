/* Oracle Advanced Networking (ANO) — native network encryption + data
 * integrity (PROTOCOL.md §33, seerdb #437).
 *
 * ANO negotiates a native encryption cipher (AES-CBC) and a data-integrity MAC
 * (SHA-2 over an AES keystream) right after the TNS accept and before the PRO
 * exchange, using a self-contained "DEADBEEF" container format. Once the server
 * selects an algorithm, every TNS_DATA payload from PRO onward is wrapped as
 *
 *     AES-CBC( plaintext ‖ MAC(plaintext) ) ‖ 0x00
 *
 * This header exposes the sans-io codec (round-1 request, response parse, the
 * Diffie-Hellman step, round-2 request) plus the per-packet channel (wrap /
 * unwrap). ttc.c orchestrates the exchange; session.c gates it on the accept.
 * The layouts mirror seerdb/common/ano*.py, validated byte-for-byte against a
 * live 26ai server requiring AES256 + SHA256.
 *
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SEER_TNS_ANO_H
#define SEER_TNS_ANO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "seer/seertns.h"

/* The ANO-capable CONNECT flag (body offset 24). The legacy 0x8484 ("disabled")
 * makes an ANO server RESET after round 1. */
#define SEER_ANO_FLAGS_CAPABLE 0x0101

/* The active per-packet cipher + MAC. Opaque; created by seer_ano_channel_new. */
typedef struct SeerAno SeerAno;

/* The parsed server negotiation response: the selected algorithm ids and, when
 * the server chose encryption, the Diffie-Hellman parameters (pointers into a
 * single owned buffer, freed by seer_ano_response_free). */
typedef struct {
    uint8_t  enc_id;      /* selected encryption algorithm id (0 = none)       */
    uint8_t  int_id;      /* selected data-integrity algorithm id (0 = none)   */
    bool     have_dh;     /* true when a DH exchange was carried (8 subpackets) */
    uint8_t *owned;       /* backing buffer for the pointers below             */
    const uint8_t *prime;       size_t prime_len;
    const uint8_t *generator;   size_t generator_len;
    const uint8_t *server_pub;  size_t server_pub_len;
    const uint8_t *server_iv;   size_t server_iv_len;
} SeerAnoResponse;

/* Build the client's round-1 negotiation container (offers RC4/DES/AES +
 * MD5/SHA-1/SHA-2, each null-prefixed). Malloc'd into *out; caller frees. */
SeerStatus seer_ano_build_round1(uint8_t **out, size_t *outlen);

/* Locate the DEADBEEF container inside `body` and parse it into `*out`. */
SeerStatus seer_ano_parse_response(const uint8_t *body, size_t len,
                                   SeerAnoResponse *out);
void seer_ano_response_free(SeerAnoResponse *r);

/* Run the client half of the DH exchange over the response's group: pick a
 * random private key, and return the client public key (to send back) and the
 * shared session key, both left-padded to the prime's byte length. Malloc'd. */
SeerStatus seer_ano_dh(const SeerAnoResponse *r,
                       uint8_t **client_pub, size_t *client_pub_len,
                       uint8_t **session_key, size_t *session_key_len);

/* As seer_ano_dh but with a caller-supplied private key (deterministic tests). */
SeerStatus seer_ano_dh_priv(const SeerAnoResponse *r,
                            const uint8_t *priv, size_t priv_len,
                            uint8_t **client_pub, size_t *client_pub_len,
                            uint8_t **session_key, size_t *session_key_len);

/* Build the round-2 container carrying the client's DH public key. Malloc'd. */
SeerStatus seer_ano_build_round2(const uint8_t *client_pub, size_t len,
                                 uint8_t **out, size_t *outlen);

/* Create the session channel from the negotiated algorithms + key material.
 * `enc_id` must be an AES id and `int_id` (when non-zero) a SHA-2 id. */
SeerStatus seer_ano_channel_new(uint8_t enc_id, uint8_t int_id,
                                const uint8_t *session_key, size_t sk_len,
                                const uint8_t *server_iv, size_t iv_len,
                                bool client_side, SeerAno **out);

void seer_ano_free(SeerAno *a);

/* Max plaintext bytes to pack in one wrapped fragment for a given SDU: SDU-64
 * leaves room for the MAC, cipher padding, marker + fold byte, and framing. */
size_t seer_ano_max_plain(uint16_t sdu);

/* Encrypt+MAC a plaintext fragment for sending. Malloc'd into *out. */
SeerStatus seer_ano_wrap(SeerAno *a, const uint8_t *pt, size_t len,
                         uint8_t **out, size_t *outlen);

/* Decrypt+verify a received wrapped fragment. Malloc'd into *out (may be a
 * zero-length allocation for an empty payload). SEER_EPROTO on a bad MAC. */
SeerStatus seer_ano_unwrap(SeerAno *a, const uint8_t *ct, size_t len,
                           uint8_t **out, size_t *outlen);

#endif /* SEER_TNS_ANO_H */

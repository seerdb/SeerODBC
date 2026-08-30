/* TCP transport for the TNS layer.
 *
 * A thin, blocking byte pipe: connect to host:port, then read/write whole
 * buffers with a timeout. Knows nothing about TNS framing - packet.c layers
 * that on top. TLS (TCPS, port 2484) will wrap this same interface later via
 * OpenSSL; nothing above transport.c needs to change when it does.
 *
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SEER_TNS_TRANSPORT_H
#define SEER_TNS_TRANSPORT_H

#include <stddef.h>
#include <stdint.h>

#include "seer/seertns.h"

typedef struct SeerTransport SeerTransport;

/* Connect to host:port. `timeout_ms` bounds the connect attempt (<=0 picks a
 * default); it also seeds the per-read/write socket timeout. */
SeerStatus seer_transport_connect(const char *host, uint16_t port,
                                  int timeout_ms, SeerTransport **out);

void seer_transport_close(SeerTransport *t);

/* Wrap an already-connected transport in TLS (TCPS): perform a client TLS
 * handshake, after which read/write transparently encrypt. `sni_host` is the
 * server name (SNI + hostname verification). When `verify` is non-zero the peer
 * certificate is checked against `ca_file` (a PEM bundle) or, if NULL, the system
 * default CAs; with `verify` zero the certificate is accepted unchecked. */
SeerStatus seer_transport_start_tls(SeerTransport *t, const char *sni_host,
                                    const char *ca_file, int verify);

/* Large-SDU framing (§ negotiated TNS version >= 315, #155): once set, packets
 * use the 4-byte packet-length header instead of the legacy 2-byte length. Set
 * after the ACCEPT (which is itself always legacy-framed); read by packet.c. */
void seer_transport_set_large_frames(SeerTransport *t, int on);
int  seer_transport_large_frames(const SeerTransport *t);

/* Write exactly `len` bytes (looping over short writes). */
SeerStatus seer_transport_write_all(SeerTransport *t, const void *buf, size_t len);

/* Read exactly `len` bytes (looping over short reads). SEER_EIO on EOF or
 * error before `len` bytes arrive. */
SeerStatus seer_transport_read_full(SeerTransport *t, void *buf, size_t len);

#endif /* SEER_TNS_TRANSPORT_H */

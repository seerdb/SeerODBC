/* Offline test for the accept-and-reject stubs of features that are not on the
 * thin wire: sharding keys (§37) and Continuous Query Notification (§38). Both
 * are OCI-client-only capabilities; a pure-protocol driver accepts the API for
 * parity and rejects with SEER_ENOTIMPL. These paths take no network.
 *
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#include "seer/seertns.h"

#include <assert.h>
#include <stdio.h>

int main(void)
{
    /* Sharding (§37): seer_connect rejects a non-empty key up front, before any
     * network I/O, so this is a pure offline check (the host is never dialled). */
    SeerConn *c = NULL;
    SeerConnParams p = { .host = "unused.invalid", .service_name = "X",
                         .shardingkey = "region=west" };
    assert(seer_connect(&p, &c) == SEER_ENOTIMPL);
    assert(c == NULL);

    SeerConnParams sp = { .host = "unused.invalid", .service_name = "X",
                          .supershardingkey = "tenant=42" };
    assert(seer_connect(&sp, &c) == SEER_ENOTIMPL);
    assert(c == NULL);

    /* CQN (§38): the subscribe/unsubscribe stubs always report unsupported. */
    assert(seer_subscribe(NULL) == SEER_ENOTIMPL);
    assert(seer_unsubscribe(NULL) == SEER_ENOTIMPL);

    printf("stubs: sharding + CQN reject cleanly (SEER_ENOTIMPL)\n");
    return 0;
}

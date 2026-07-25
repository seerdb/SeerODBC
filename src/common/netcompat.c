/*
 * SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "netcompat.h"

#ifdef _WIN32

/* Winsock must be started once per process before any socket call. Use
 * InitOnceExecuteOnce (kernel32, always linked) so the init is race-free without
 * pulling a threads dependency into the common library. WSACleanup is
 * deliberately never called: the sockets live for the process's lifetime, and
 * the OS reclaims the Winsock refcount on exit. */
static INIT_ONCE g_wsa_once = INIT_ONCE_STATIC_INIT;

static BOOL CALLBACK wsa_startup(PINIT_ONCE once, PVOID param, PVOID *context)
{
    (void)once; (void)param; (void)context;
    WSADATA wsadata;
    return WSAStartup(MAKEWORD(2, 2), &wsadata) == 0 ? TRUE : FALSE;
}

int seer_net_init(void)
{
    return InitOnceExecuteOnce(&g_wsa_once, wsa_startup, NULL, NULL) ? 0 : -1;
}

#else /* POSIX: the sockets API needs no process-wide init. */

int seer_net_init(void)
{
    return 0;
}

#endif

#!/usr/bin/env bash

# SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
#
# SPDX-License-Identifier: Apache-2.0

# Run the live test suites against every Oracle tier in the matrix.
#
# usage: tests/odbc/run-matrix.sh [--only TIERS] [--skip TIERS] [BUILD_DIR]
#
#   BUILD_DIR      meson build directory (default: build)
#   --only TIERS   run just these tiers (comma/space separated, e.g. "11g,23ai")
#   --skip TIERS   leave these tiers out
#
# Where the servers are is configured through environment variables, so the
# same script drives a laptop full of containers or a remote lab:
#
#   SEER_CONTAINER_HOST   host running the container tiers (default 127.0.0.1)
#   SEER_9I_HOST          host of the Oracle 9i VM (unset = the 9i tier is skipped)
#   SEER_8I_HOST          host of the Oracle 8i VM (unset = the 8i tier is skipped)
#   SEER_MATRIX_USER      default account for every tier   (default pyo)
#   SEER_MATRIX_PASS      default password for every tier  (default pyo123)
#   SEER_MATRIX_ONLY      same as --only
#   SEER_MATRIX_SKIP      same as --skip
#
# Any field of one tier can be overridden with SEER_<TIER>_HOST, _PORT, _TARGET,
# _USER or _PASS, where <TIER> is the tier name in upper case (11G, 18C, 21C,
# 23AI, 26AI, 10G, 9I, 8I) - e.g. SEER_23AI_USER=system SEER_23AI_PASS=secret.
#
# Settings can live in a file instead of the shell: the script sources
# $SEER_MATRIX_ENV, or tests/odbc/matrix.env if that exists (it is gitignored;
# see matrix.env.example). Variables already set in the environment win.
#
# A tier whose listener does not answer is reported as unreachable and skipped.
# The exit status is non-zero if any tier that ran had a failing check.
set -u

here="$(cd "$(dirname "$0")" && pwd)"

# ---- configuration file (environment takes precedence) ----------------------
env_file="${SEER_MATRIX_ENV:-$here/matrix.env}"
if [[ -f "$env_file" ]]; then
    saved_env="$(export -p)"
    # shellcheck disable=SC1090
    source "$env_file"
    eval "$saved_env"
fi

# ---- arguments ----------------------------------------------------------------
ONLY="${SEER_MATRIX_ONLY:-}"
SKIP="${SEER_MATRIX_SKIP:-}"
BUILD=build
while [[ $# -gt 0 ]]; do
    case "$1" in
        --only) ONLY="$2"; shift 2 ;;
        --only=*) ONLY="${1#*=}"; shift ;;
        --skip) SKIP="$2"; shift 2 ;;
        --skip=*) SKIP="${1#*=}"; shift ;;
        -h|--help) sed -n '7,34p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) BUILD="$1"; shift ;;
    esac
done
ONLY="${ONLY//,/ }"
SKIP="${SKIP//,/ }"

BIN="$BUILD/tests/test_integration"
TPC_BIN="$BUILD/tests/test_tpc"
OBJBIND_BIN="$BUILD/tests/test_objbind"
AQ_BIN="$BUILD/tests/test_aq"
NINE_BIN="$BUILD/tests/test_9i"
EIGHT_BIN="$BUILD/tests/test_8i"
if [[ ! -x "$BIN" ]]; then
    echo "integration test not built: $BIN (run: meson compile -C $BUILD)" >&2
    exit 1
fi

CONTAINER_HOST="${SEER_CONTAINER_HOST:-127.0.0.1}"
NINE_HOST="${SEER_9I_HOST:-}"
EIGHT_HOST="${SEER_8I_HOST:-}"
DEF_USER="${SEER_MATRIX_USER:-pyo}"
DEF_PASS="${SEER_MATRIX_PASS:-pyo123}"

# ---- tiers ---------------------------------------------------------------------
# Row: name|group|host|port|target|kind
#   group=public -> freely redistributable image, eligible for public GitHub CI
#   group=local  -> ours to test only (10g's image can't be redistributed, the
#                   26ai native-encryption bed is lab-specific, 9i is a VM)
#   kind=odbc    -> ODBC integration test (+ core-API extras); target = SERVICE_NAME
#   kind=fv2     -> Oracle 9i core-API test (test_9i);          target = SID
#   kind=o8i     -> Oracle 8i core-API test (test_8i);          target = SERVICE_NAME
TIERS=(
    "11g|public|$CONTAINER_HOST|1521|XE|odbc"
    "18c|public|$CONTAINER_HOST|1527|XEPDB1|odbc"
    "21c|public|$CONTAINER_HOST|1522|XEPDB1|odbc"
    "23ai|public|$CONTAINER_HOST|1523|FREEPDB1|odbc"
    "26ai|local|$CONTAINER_HOST|1526|freepdb1|odbc"
    "10g|local|$CONTAINER_HOST|1525|orcl|odbc"
    "9i|local|$NINE_HOST|1521|orcl|fv2"
    "8i|local|$EIGHT_HOST|1521|ORCL|o8i"
)

in_list() {   # $1 word  $2 space-separated list
    local w
    for w in $2; do [[ "$w" == "$1" ]] && return 0; done
    return 1
}

upper() { printf '%s' "$1" | tr '[:lower:]' '[:upper:]'; }

override() {  # $1 tier  $2 field  $3 default -> value
    local var; var="SEER_$(upper "$1")_$2"
    printf '%s' "${!var:-$3}"
}

reachable() { # $1 host  $2 port  (GNU timeout if present, so a dead host can't hang us)
    if command -v timeout >/dev/null 2>&1; then
        timeout 3 bash -c "</dev/tcp/$1/$2" 2>/dev/null
    else
        bash -c "</dev/tcp/$1/$2" 2>/dev/null
    fi
}

# Per-tier results, kept in RESULT_<tier> variables (bash 3.2 has no associative
# arrays, and macOS still ships it).
set_result() { eval "RESULT_$1=\$2"; }
get_result() { eval "printf '%s' \"\${RESULT_$1-}\""; }
has_result() { eval "[[ -n \"\${RESULT_$1+x}\" ]]"; }

# ---- optional TLS leg ------------------------------------------------------------
# A terminating proxy (tls_proxy.py) gives the driver a TCPS endpoint forwarding
# to each server's plaintext listener. Needs python3 + openssl; without them the
# TLS check skips.
PROXY_SCRIPT="$here/tls_proxy.py"
have_tls_proxy=0
command -v python3 >/dev/null 2>&1 && command -v openssl >/dev/null 2>&1 \
    && [[ -f "$PROXY_SCRIPT" ]] && have_tls_proxy=1

start_tls_proxy() {   # $1 backend_host  $2 backend_port -> sets TLS_PORT/TLS_CA/TLS_PID
    TLS_PORT=""; TLS_CA=""; TLS_PID=""
    [[ $have_tls_proxy -eq 1 ]] || return 0
    local out; out=$(mktemp)
    python3 "$PROXY_SCRIPT" "$1" "$2" >"$out" 2>/dev/null &
    TLS_PID=$!
    for _ in $(seq 1 30); do
        grep -q '^CA=' "$out" && break
        sleep 0.2
    done
    TLS_PORT=$(sed -n 's/^PORT=//p' "$out")
    TLS_CA=$(sed -n 's/^CA=//p' "$out")
    rm -f "$out"
    [[ -n "$TLS_PORT" && -n "$TLS_CA" ]] || { kill "$TLS_PID" 2>/dev/null; TLS_PID=""; }
}

# ---- run ---------------------------------------------------------------------------
any_fail=0
log=$(mktemp)
xlog=$(mktemp)
trap 'rm -f "$log" "$xlog"' EXIT

for row in "${TIERS[@]}"; do
    IFS='|' read -r name group host port target kind <<<"$row"
    if [[ -n "$ONLY" ]] && ! in_list "$name" "$ONLY"; then continue; fi
    if in_list "$name" "$SKIP"; then set_result "$name" "skipped (--skip)"; continue; fi

    host=$(override "$name" HOST "$host")
    port=$(override "$name" PORT "$port")
    target=$(override "$name" TARGET "$target")
    user=$(override "$name" USER "$DEF_USER")
    pass=$(override "$name" PASS "$DEF_PASS")

    echo "============================================================"
    echo " $name  ($host:$port/$target as $user)"
    echo "============================================================"
    if [[ -z "$host" ]]; then
        set_result "$name" "skipped (no host: set SEER_$(upper "$name")_HOST)"
        echo "  $(get_result "$name")"
        continue
    fi
    if ! reachable "$host" "$port"; then
        set_result "$name" "unreachable ($host:$port)"
        echo "  $(get_result "$name")"
        continue
    fi
    : >"$xlog"

    export SEER_TEST_HOST="$host" SEER_TEST_PORT="$port" \
           SEER_TEST_USER="$user" SEER_TEST_PASS="$pass"
    if [[ "$kind" == "fv2" ]]; then
        # Oracle 9i: its own core-API test, SID-addressed.
        SEER_TEST_SID="$target" "$NINE_BIN" >"$log" 2>/dev/null
        grep -v '^SUMMARY' "$log" | sed 's/^/  /'
    elif [[ "$kind" == "o8i" ]]; then
        # Oracle 8i: its own core-API test.
        SEER_TEST_SERVICE="$target" "$EIGHT_BIN" >"$log" 2>/dev/null
        grep -v '^SUMMARY' "$log" | sed 's/^/  /'
    else
        # ODBC integration test (+ core-API extras: two-phase commit, object
        # bind, AQ), service-name addressed, with an optional TLS-proxy leg.
        start_tls_proxy "$host" "$port"
        SEER_TEST_SERVICE="$target" SEER_TLS_PROXY_PORT="$TLS_PORT" SEER_TLS_CA="$TLS_CA" \
            "$BIN" >"$log" 2>/dev/null
        [[ -n "$TLS_PID" ]] && kill "$TLS_PID" 2>/dev/null
        grep -vE '^(target|SUMMARY)' "$log" | sed 's/^/  /'
        for extra in "$TPC_BIN" "$OBJBIND_BIN" "$AQ_BIN"; do
            [[ -x "$extra" ]] || continue
            SEER_TEST_SERVICE="$target" "$extra" 2>/dev/null | grep -v '^SUMMARY' \
                | tee -a "$xlog" | sed 's/^/  /'
        done
    fi
    unset SEER_TEST_HOST SEER_TEST_PORT SEER_TEST_USER SEER_TEST_PASS

    summary=$(grep '^SUMMARY' "$log")
    result="${summary:-no summary (connect failed)}"
    if [[ -z "$summary" || "$summary" != *"fail=0"* ]]; then any_fail=1; fi
    if grep -q 'FAIL' "$xlog"; then
        result="$result; core-API extras FAILED"
        any_fail=1
    fi
    set_result "$name" "$result"
    printf '%-6s %s\n' "$name" "$result"
done

echo
echo "==================== matrix ================================"
for group in public local; do
    if [[ $group == public ]]; then
        echo "-- public CI tier (redistributable containers) --"
    else
        echo "-- local only (not in public CI) --"
    fi
    for row in "${TIERS[@]}"; do
        IFS='|' read -r name g _ <<<"$row"
        [[ "$g" == "$group" ]] || continue
        has_result "$name" || continue
        printf '%-6s %s\n' "$name" "$(get_result "$name")"
    done
done
exit $any_fail

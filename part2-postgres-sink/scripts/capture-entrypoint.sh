#!/usr/bin/env bash

set -uo pipefail

IFACE="${IFACE:-lo}"
LOG="${LOG:-/work/output/pg_capture.pcap}"
OUTPUT_DIR="$(dirname "${LOG}")"
PG_HOST="${PG_HOST:-127.0.0.1}"
PG_PORT="${PG_PORT:-5432}"
PG_USER="${PG_USER:-packets}"
PG_DB="${PG_DB:-packets}"
PG_PASSWORD="${PG_PASSWORD:-packets}"

HOST_UID="${HOST_UID:-1000}"
HOST_GID="${HOST_GID:-1000}"

EXIT_AFTER_PROBE="${EXIT_AFTER_PROBE:-0}"

CAP_PID=""
CLEANING=0

log() { printf '\033[1;36m==>\033[0m %s\n' "$*"; }

fix_perms() {
    [[ -d "${OUTPUT_DIR}" ]] && chown -R "${HOST_UID}:${HOST_GID}" "${OUTPUT_DIR}" 2>/dev/null || true
}
log "Fixing output permissions (${HOST_UID}:${HOST_GID})..."
fix_perms

cleanup() {

    [[ "${CLEANING}" -eq 1 ]] && return
    CLEANING=1
    log "Cleaning up: stopping capture, detaching XDP from ${IFACE}..."
    [[ -n "${CAP_PID}" ]] && kill "${CAP_PID}" 2>/dev/null || true
    wait 2>/dev/null || true

    ip link set dev "${IFACE}" xdpgeneric off 2>/dev/null || true
    fix_perms
    log "Stopped."
}
trap cleanup EXIT INT TERM

log "Waiting for postgres at ${PG_HOST}:${PG_PORT} ..."
for i in $(seq 1 60); do
    if pg_isready -h "${PG_HOST}" -p "${PG_PORT}" -U "${PG_USER}" -d "${PG_DB}" >/dev/null 2>&1; then
        echo "    postgres is ready"
        break
    fi
    sleep 0.5
done
if ! pg_isready -h "${PG_HOST}" -p "${PG_PORT}" -U "${PG_USER}" -d "${PG_DB}" >/dev/null 2>&1; then
    echo "ERROR: postgres never became ready after 30s" >&2
    exit 1
fi

mkdir -p "${OUTPUT_DIR}"
cd /app
if [[ ! -x ./capture_loader || ! -f ./xdp_capture.bpf.o ]]; then
    echo "ERROR: capture_loader or xdp_capture.bpf.o missing under /app" >&2
    exit 1
fi

log "Attaching XDP capture to ${IFACE}; writing to ${LOG}"
: > "${LOG}"
fix_perms
./capture_loader "${IFACE}" "${LOG}" &
CAP_PID=$!
sleep 1

log "Probing: SELECT 1"
PGPASSWORD="${PG_PASSWORD}" psql -h "${PG_HOST}" -p "${PG_PORT}" -U "${PG_USER}" -d "${PG_DB}" \
    -c "SELECT 1 AS probe;" >/dev/null 2>&1 || echo "    (probe query failed - capture still running)"

if [[ "${EXIT_AFTER_PROBE}" == "1" ]]; then
    sleep 0.5
    log "EXIT_AFTER_PROBE=1 - capture written to ${LOG}"
    exit 0
fi

log "Streaming capture (stop with: docker compose down)"
wait "${CAP_PID}" 2>/dev/null || true

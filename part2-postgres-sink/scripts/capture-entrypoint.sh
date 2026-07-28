#!/usr/bin/env bash
# In-container entrypoint for the XDP capture service.
#
# Runs in the host network namespace (network_mode: host) with elevated
# privileges, so it can attach an XDP program to `lo` and observe Postgres
# traffic between a local psql client and the postgres server (which both
# also run with network_mode: host - everything shares `lo`).
#
# Lifecycle:
#   docker compose up   ->  wait for pg ready, build, attach XDP, stream count.
#   docker compose down ->  Docker sends SIGTERM; trap detaches XDP + flushes.
#
# NOTE on `lo`: XDP_GENERIC (driver-less) attaches work on loopback on modern
# kernels; if the attach fails with -EINVAL, your kernel may not support
# generic XDP on lo - in that case rebind the demo to a real veth pair like
# part1 does.

set -uo pipefail

# --- Config (override via `docker compose` environment:) ----------------------
IFACE="${IFACE:-lo}"
LOG="${LOG:-/work/output/pg_capture.pcap}"
OUTPUT_DIR="$(dirname "${LOG}")"
PG_HOST="${PG_HOST:-127.0.0.1}"
PG_PORT="${PG_PORT:-5432}"
PG_USER="${PG_USER:-packets}"
PG_DB="${PG_DB:-packets}"
PG_PASSWORD="${PG_PASSWORD:-packets}"
# Host user UID/GID (passed in via docker-compose). Artifacts written to the
# bind-mounted output dir get chowned to this id so you can rm/edit/git them
# on the host without sudo - otherwise the container leaves them root-owned.
HOST_UID="${HOST_UID:-1000}"
HOST_GID="${HOST_GID:-1000}"
# Set to 1 to exit right after the startup probe instead of streaming forever.
EXIT_AFTER_PROBE="${EXIT_AFTER_PROBE:-0}"
# ------------------------------------------------------------------------------

CAP_PID=""
CLEANING=0

log() { printf '\033[1;36m==>\033[0m %s\n' "$*"; }

# Recursively hand ownership of the output dir to the host user. We run as
# root in here, so this succeeds even though the host user couldn't do it.
fix_perms() {
    [[ -d "${OUTPUT_DIR}" ]] && chown -R "${HOST_UID}:${HOST_GID}" "${OUTPUT_DIR}" 2>/dev/null || true
}

cleanup() {
    # Guard against double-invocation (EXIT + TERM both fire).
    [[ "${CLEANING}" -eq 1 ]] && return
    CLEANING=1
    log "Cleaning up: stopping capture, detaching XDP from ${IFACE}..."
    [[ -n "${CAP_PID}" ]] && kill "${CAP_PID}" 2>/dev/null || true
    wait 2>/dev/null || true
    # capture_loader detaches XDP itself on clean exit, but be belt-and-braces
    # in case it was force-killed before getting there.
    ip link set dev "${IFACE}" xdpgeneric off 2>/dev/null || true
    fix_perms
    log "Stopped."
}
trap cleanup EXIT INT TERM

# 1. Wait for postgres to accept connections before we attach + generate traffic.
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

# 2. The loader + BPF object were compiled in the Docker build stage and copied
#    into the image at /app (see Dockerfile.core). No build tools are present
#    in the runtime image, so we just run the prebuilt binary.
mkdir -p "${OUTPUT_DIR}"
cd /app
if [[ ! -x ./capture_loader || ! -f ./xdp_capture.bpf.o ]]; then
    echo "ERROR: capture_loader or xdp_capture.bpf.o missing under /app" >&2
    exit 1
fi

# 3. Attach the XDP capture to the chosen interface and stream packet count.
log "Attaching XDP capture to ${IFACE}; writing to ${LOG}"
: > "${LOG}"   # truncate so each `up` starts a fresh capture
fix_perms      # hand the (fresh, empty) pcap to the host user up front
./capture_loader "${IFACE}" "${LOG}" &
CAP_PID=$!
sleep 1        # let it attach before we generate traffic

# 4. Optional one-shot probe: run a trivial query so we know the pcap will
#    contain at least a few Postgres protocol messages.
log "Probing: SELECT 1"
PGPASSWORD="${PG_PASSWORD}" psql -h "${PG_HOST}" -p "${PG_PORT}" -U "${PG_USER}" -d "${PG_DB}" \
    -c "SELECT 1 AS probe;" >/dev/null 2>&1 || echo "    (probe query failed - capture still running)"

# One-shot mode: print whatever we captured, then bail (trap will clean up).
if [[ "${EXIT_AFTER_PROBE}" == "1" ]]; then
    sleep 0.5
    log "EXIT_AFTER_PROBE=1 - capture written to ${LOG}"
    exit 0
fi

# 5. Stream the loader's packet-count line; container stays alive until signal.
log "Streaming capture (stop with: docker compose down)"
wait "${CAP_PID}" 2>/dev/null || true
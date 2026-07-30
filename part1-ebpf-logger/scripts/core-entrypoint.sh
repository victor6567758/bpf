#!/usr/bin/env bash

set -uo pipefail

VETH0="${VETH0:-veth0}"
VETH1="${VETH1:-veth1}"
VETH0_IP="${VETH0_IP:-10.0.0.1/24}"
VETH1_IP="${VETH1_IP:-10.0.0.2/24}"
VETH0_IP_NO_MASK="${VETH0_IP_NO_MASK:-10.0.0.1}"
VETH1_IP_NO_MASK="${VETH1_IP_NO_MASK:-10.0.0.2}"
PEER_NS="${PEER_NS:-bpfpeer}"
LOG="${LOG:-/work/output/packets.log}"
OUTPUT_DIR="$(dirname "${LOG}")"

HOST_UID="${HOST_UID:-1000}"
HOST_GID="${HOST_GID:-1000}"
TEST_ON_START="${TEST_ON_START:-1}"

EXIT_AFTER_TEST="${EXIT_AFTER_TEST:-0}"

LOGGER_PID=""
TAIL_PID=""
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
    log "Cleaning up: detaching XDP, removing veth pair + peer namespace..."
    [[ -n "${LOGGER_PID}" ]] && kill "${LOGGER_PID}" 2>/dev/null || true
    [[ -n "${TAIL_PID}"   ]] && kill "${TAIL_PID}"   2>/dev/null || true
    wait 2>/dev/null || true

    ip link del "${VETH0}" 2>/dev/null && echo "    removed ${VETH0}" || echo "    ${VETH0} already gone"

    ip netns del "${PEER_NS}" 2>/dev/null && echo "    removed namespace ${PEER_NS}" || true
    fix_perms
    log "Stopped."
}
trap cleanup EXIT INT TERM

ip netns del "${PEER_NS}" 2>/dev/null || true
ip netns add "${PEER_NS}"
echo "    created namespace ${PEER_NS}"

ip link del "${VETH0}" 2>/dev/null || true
log "Creating veth pair ${VETH0} (host) <-> ${VETH1} (${PEER_NS})"
ip link add "${VETH0}" type veth peer name "${VETH1}"
ip link set "${VETH1}" netns "${PEER_NS}"

ip addr add "${VETH0_IP}" dev "${VETH0}"
ip link set "${VETH0}" up

ip netns exec "${PEER_NS}" ip addr add "${VETH1_IP}" dev "${VETH1}"
ip netns exec "${PEER_NS}" ip link set "${VETH1}" up
ip netns exec "${PEER_NS}" ip link set lo up
echo "    ${VETH0}=${VETH0_IP} (host), ${VETH1}=${VETH1_IP} (${PEER_NS})"

mkdir -p build output
log "Building packet_logger (cmake)"
if ! cmake -S . -B build >&2 || ! cmake --build build -j >&2; then
    echo "Build failed" >&2
    exit 1
fi

log "Attaching XDP logger to ${VETH0}; writing to ${LOG}"
: > "${LOG}"
fix_perms
./build/packet_logger "${VETH0}" "${LOG}" &
LOGGER_PID=$!
sleep 1

[[ "${TEST_ON_START}" == "1" ]] && /work/scripts/send-traffic.sh all

if [[ "${EXIT_AFTER_TEST}" == "1" ]]; then
    sleep 0.5
    log "EXIT_AFTER_TEST=1 - captured packets:"
    cat "${LOG}"
    exit 0
fi

sleep 0.5
log "Streaming ${LOG} (stop with: docker compose down)"
log "---- captured packets ----"
tail -n +1 -f "${LOG}" &
TAIL_PID=$!

wait "${LOGGER_PID}" 2>/dev/null || true

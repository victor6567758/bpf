#!/usr/bin/env bash
# In-container entrypoint. Because docker-compose runs this container with
# `privileged: true` + `network_mode: host`, it can create veth interfaces and
# network namespaces on the host directly - no host-side setup needed.
#
# Topology:
#
#   default netns (host)            peer netns (bpfpeer)
#   ┌──────────────────┐            ┌──────────────────┐
#   │ veth0 10.0.0.1   │<<<<<<<<<<<<│ veth1 10.0.0.2   │
#   │  + XDP logger    │  veth wire │  (clients run    │
#   │  + nc listeners  │            │   from here)     │
#   └──────────────────┘            └──────────────────┘
#
# Traffic sent FROM veth1 (peer ns) TO veth0 (host ns) crosses the veth
# pair and arrives as ingress on veth0, where XDP catches it. If both
# ends lived in the same netns the kernel would short-circuit local
# delivery through `lo` and XDP would never see the packets.
#
# Lifecycle:
#   docker compose up   ->  create ns + veth pair, build, attach XDP logger,
#                           send a burst of test traffic, stream the log.
#   docker compose down ->  Docker sends SIGTERM; the trap below detaches
#                           the logger, deletes the veth pair + peer ns.

set -uo pipefail

# --- Config (override via `docker compose` environment:) ----------------------
VETH0="${VETH0:-veth0}"
VETH1="${VETH1:-veth1}"
VETH0_IP="${VETH0_IP:-10.0.0.1/24}"
VETH1_IP="${VETH1_IP:-10.0.0.2/24}"
VETH0_IP_NO_MASK="${VETH0_IP_NO_MASK:-10.0.0.1}"
VETH1_IP_NO_MASK="${VETH1_IP_NO_MASK:-10.0.0.2}"
PEER_NS="${PEER_NS:-bpfpeer}"
LOG="${LOG:-/work/output/packets.log}"
OUTPUT_DIR="$(dirname "${LOG}")"
# Host user UID/GID (passed in via docker-compose). Artifacts written to the
# bind-mounted output dir get chowned to this id so you can rm/edit/git them
# on the host without sudo - otherwise the container leaves them root-owned.
HOST_UID="${HOST_UID:-1000}"
HOST_GID="${HOST_GID:-1000}"
TEST_ON_START="${TEST_ON_START:-1}"
# Set to 1 to exit right after the startup test burst instead of streaming
# the log forever. Handy for one-shot "capture a burst and quit" runs; the
# trap still detaches the XDP program and removes the veth pair on the way out.
EXIT_AFTER_TEST="${EXIT_AFTER_TEST:-0}"
# ------------------------------------------------------------------------------

LOGGER_PID=""
TAIL_PID=""
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
    log "Cleaning up: detaching XDP, removing veth pair + peer namespace..."
    [[ -n "${LOGGER_PID}" ]] && kill "${LOGGER_PID}" 2>/dev/null || true
    [[ -n "${TAIL_PID}"   ]] && kill "${TAIL_PID}"   2>/dev/null || true
    wait 2>/dev/null || true
    # Deleting veth0 destroys the whole pair (veth1 goes with it).
    ip link del "${VETH0}" 2>/dev/null && echo "    removed ${VETH0}" || echo "    ${VETH0} already gone"
    # Delete the peer namespace (veth1 was moved into it).
    ip netns del "${PEER_NS}" 2>/dev/null && echo "    removed namespace ${PEER_NS}" || true
    fix_perms
    log "Stopped."
}
trap cleanup EXIT INT TERM

# 1. Create the peer network namespace.
#    Clean up any stale namespace from a previous crashed run first.
ip netns del "${PEER_NS}" 2>/dev/null || true
ip netns add "${PEER_NS}"
echo "    created namespace ${PEER_NS}"

# 2. Create the veth pair and move veth1 into the peer namespace.
#    veth0 stays in the default (host) namespace; veth1 moves to PEER_NS.
ip link del "${VETH0}" 2>/dev/null || true   # clean up any stale pair
log "Creating veth pair ${VETH0} (host) <-> ${VETH1} (${PEER_NS})"
ip link add "${VETH0}" type veth peer name "${VETH1}"
ip link set "${VETH1}" netns "${PEER_NS}"

# 3. Configure IPs and bring both ends up.
ip addr add "${VETH0_IP}" dev "${VETH0}"
ip link set "${VETH0}" up

ip netns exec "${PEER_NS}" ip addr add "${VETH1_IP}" dev "${VETH1}"
ip netns exec "${PEER_NS}" ip link set "${VETH1}" up
ip netns exec "${PEER_NS}" ip link set lo up   # lo is down by default in a new ns
echo "    ${VETH0}=${VETH0_IP} (host), ${VETH1}=${VETH1_IP} (${PEER_NS})"

# 4. Build the logger + BPF object.
mkdir -p build output
log "Building packet_logger (cmake)"
if ! cmake -S . -B build >&2 || ! cmake --build build -j >&2; then
    echo "Build failed" >&2
    exit 1
fi

# 5. Attach the XDP logger to veth0 in the background.
log "Attaching XDP logger to ${VETH0}; writing to ${LOG}"
: > "${LOG}"   # truncate so each `up` starts a fresh capture
fix_perms      # hand the (fresh, empty) log to the host user up front
./build/packet_logger "${VETH0}" "${LOG}" &
LOGGER_PID=$!
sleep 1        # let it attach before we generate traffic

# 6. Send a burst of test traffic across the pair (shared with `make test`).
[[ "${TEST_ON_START}" == "1" ]] && /work/scripts/send-traffic.sh all

# One-shot mode: print whatever we captured, then bail (trap will clean up).
if [[ "${EXIT_AFTER_TEST}" == "1" ]]; then
    sleep 0.5
    log "EXIT_AFTER_TEST=1 - captured packets:"
    cat "${LOG}"
    exit 0
fi

# 7. Stream the log; the container stays alive until SIGTERM/SIGINT.
sleep 0.5
log "Streaming ${LOG} (stop with: docker compose down)"
log "---- captured packets ----"
tail -n +1 -f "${LOG}" &
TAIL_PID=$!

# Block here. On signal, the trap runs cleanup and we exit.
wait "${LOGGER_PID}" 2>/dev/null || true
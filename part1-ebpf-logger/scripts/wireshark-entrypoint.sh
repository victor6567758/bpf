#!/usr/bin/env bash
# Wireshark/tshark sidecar entrypoint. Runs alongside the BPF logger and
# produces two artifacts in the shared output volume:
#   capture.pcap  - raw pcap, open in Wireshark GUI for full detail
#   decoded.txt   - tshark's human-readable decode of every packet
#
# Lifecycle:
#   - Waits for veth0 to appear (created by the packet-logger service).
#   - Captures to capture.pcap until SIGTERM.
#   - On SIGTERM: stops capture, runs `tshark -r capture.pcap -V > decoded.txt`,
#     so the decode is always in sync with whatever was captured.

set -uo pipefail

VETH0="${VETH0:-veth0}"
OUT_DIR="${OUT_DIR:-/work/output}"
CAPTURE_FILE="${CAPTURE_FILE:-${OUT_DIR}/capture.pcap}"
DECODED_FILE="${DECODED_FILE:-${OUT_DIR}/decoded.txt}"
FILTER="${FILTER:-}"   # optional capture filter, e.g. "ip"
# Host user UID/GID (passed in via docker-compose). Artifacts written to the
# bind-mounted output dir get chowned to this id so you can rm/edit/git them
# on the host without sudo - otherwise the container leaves them root-owned.
HOST_UID="${HOST_UID:-1000}"
HOST_GID="${HOST_GID:-1000}"

DUMP_PID=""
CLEANING=0

mkdir -p "${OUT_DIR}"

log() { printf '\033[1;35m[wireshark]\033[0m %s\n' "$*"; }

# Recursively hand ownership of the output dir to the host user. We run as
# root in here, so this succeeds even though the host user couldn't do it.
fix_perms() {
    [[ -d "${OUT_DIR}" ]] && chown -R "${HOST_UID}:${HOST_GID}" "${OUT_DIR}" 2>/dev/null || true
}

decode() {
    if [[ -s "${CAPTURE_FILE}" ]]; then
        log "Decoding ${CAPTURE_FILE} -> ${DECODED_FILE}"
        # -V = full protocol detail, -r = read from file.
        # Don't suppress stderr — if tshark fails we need to see why.
        if tshark -r "${CAPTURE_FILE}" -V > "${DECODED_FILE}" 2>&1; then
            local lines
            lines=$(wc -l < "${DECODED_FILE}")
            if [[ "${lines}" -gt 0 ]]; then
                log "Wrote ${lines} lines to ${DECODED_FILE}"
            else
                log "WARNING: decoded.txt is empty (tshark succeeded but produced no output)"
            fi
        else
            log "ERROR: tshark decode failed. Keeping partial output in ${DECODED_FILE} for diagnosis."
        fi
    else
        log "No packets in ${CAPTURE_FILE}; skipping decode"
    fi
}

cleanup() {
    [[ "${CLEANING}" -eq 1 ]] && return
    CLEANING=1
    log "Stopping capture..."
    [[ -n "${DUMP_PID}" ]] && kill "${DUMP_PID}" 2>/dev/null || true
    wait 2>/dev/null || true
    sleep 0.3   # let dumpcap flush the file
    decode
    fix_perms
    log "Done."
}
trap cleanup EXIT INT TERM

# Wait for the packet-logger service to create veth0.
log "Waiting for ${VETH0} to appear..."
for i in $(seq 1 60); do
    if ip link show "${VETH0}" &>/dev/null; then
        break
    fi
    sleep 0.5
done
if ! ip link show "${VETH0}" &>/dev/null; then
    log "ERROR: ${VETH0} never appeared after 30s. Is the packet-logger service running?"
    exit 1
fi

# NOTE: do NOT chown capture.pcap here. dumpcap drops cap_dac_override (a
# Wireshark hardening measure), so it can only write to files owned by root.
# We chown to the host user in cleanup() AFTER dumpcap has been killed and
# flushed - see fix_perms() in the trap.
: > "${CAPTURE_FILE}"   # fresh capture each run (root-owned; dumpcap writes here)
log "Capturing ${VETH0} -> ${CAPTURE_FILE}"
[[ -n "${FILTER}" ]] && log "Capture filter: ${FILTER}"

# dumpcap is what tshark uses under the hood; -q = quiet, -U = packet-buffered.
if [[ -n "${FILTER}" ]]; then
    dumpcap -i "${VETH0}" -q -f "${FILTER}" -w "${CAPTURE_FILE}" &
else
    dumpcap -i "${VETH0}" -q -w "${CAPTURE_FILE}" &
fi
DUMP_PID=$!

# Block until signaled. On SIGTERM the trap stops capture and decodes.
wait "${DUMP_PID}" 2>/dev/null || true
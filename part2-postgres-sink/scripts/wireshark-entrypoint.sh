#!/usr/bin/env bash
# Tshark decoder sidecar for part2-postgres-sink.
#
# This container does NOT capture anything itself. The `capture` service runs
# the XDP program that writes pg_capture.pcap; our only job is to sit idle and
# decode that file to pg_decoded.txt when we're told to stop (so the pcap is
# complete and flushed by the time we read it).
#
# Why a separate container just to decode? Because tshark (and its libwiretap
# dependencies) are heavy, and we don't want them in the privileged capture
# image. Keeping decode in its own unprivileged sidecar also lets you re-run
# it on an existing pcap without restarting the capture:
#
#   make decode            # one-shot: docker exec wireshark tshark -r ...
#   make decode WRITE=1    # save to output/pg_decoded.txt
#
# Lifecycle:
#   - Idle (sleep) until SIGTERM.
#   - On SIGTERM: if pg_capture.pcap exists, run `tshark -r ... -V` into
#     pg_decoded.txt, then chown both files to the host user.

set -uo pipefail

OUT_DIR="${OUT_DIR:-/work/output}"
CAPTURE_FILE="${CAPTURE_FILE:-${OUT_DIR}/pg_capture.pcap}"
DECODED_FILE="${DECODED_FILE:-${OUT_DIR}/pg_decoded.txt}"
HOST_UID="${HOST_UID:-1000}"
HOST_GID="${HOST_GID:-1000}"

CLEANING=0

mkdir -p "${OUT_DIR}"

log() { printf '\033[1;35m[wireshark]\033[0m %s\n' "$*"; }

# Recursively hand ownership of the output dir to the host user. We run as
# root in here, so this succeeds even though the host user couldn't do it.
fix_perms() {
    [[ -d "${OUT_DIR}" ]] && chown -R "${HOST_UID}:${HOST_GID}" "${OUT_DIR}" 2>/dev/null || true
}

decode() {
    if [[ ! -s "${CAPTURE_FILE}" ]]; then
        log "No ${CAPTURE_FILE} to decode (empty or missing). Was the capture service running?"
        return 0
    fi

    log "Decoding ${CAPTURE_FILE} -> ${DECODED_FILE}"

    # Write to a temp file, then atomically rename on success. This prevents
    # a SIGKILL mid-decode from leaving a truncated/partial pg_decoded.txt —
    # if we're killed before the mv, the previous file (e.g. one written by
    # `make decode WRITE=1`) is left intact.
    local tmp
    tmp="${DECODED_FILE}.tmp.$$"

    # -V = full protocol detail, -r = read from file.
    # Stderr (the "Running as root" warning) goes to a log, NOT the decode.
    if tshark -r "${CAPTURE_FILE}" -V > "${tmp}" 2>/dev/null; then
        local lines
        lines=$(wc -l < "${tmp}")
        if [[ "${lines}" -gt 0 ]]; then
            mv -f "${tmp}" "${DECODED_FILE}"
            log "Wrote ${lines} lines to ${DECODED_FILE}"
        else
            rm -f "${tmp}"
            log "WARNING: tshark produced no output (0 lines). Keeping previous ${DECODED_FILE} if any."
        fi
    else
        rm -f "${tmp}"
        log "ERROR: tshark decode failed. Keeping previous ${DECODED_FILE} if any."
    fi
}

cleanup() {
    [[ "${CLEANING}" -eq 1 ]] && return
    CLEANING=1
    log "Stopping..."
    decode
    fix_perms
    log "Done."
}
trap cleanup EXIT INT TERM

log "Ready. Idle until stopped (will decode ${CAPTURE_FILE} on shutdown)."

# Block forever until SIGTERM/SIGINT fires the trap above. `sleep infinity` is
# portable across coreutils/busybox and doesn't spin.
while true; do
    sleep 3600 &
    wait $!
done
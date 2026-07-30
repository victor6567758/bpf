#!/usr/bin/env bash

set -uo pipefail

OUT_DIR="${OUT_DIR:-/work/output}"
CAPTURE_FILE="${CAPTURE_FILE:-${OUT_DIR}/pg_capture.pcap}"
DECODED_FILE="${DECODED_FILE:-${OUT_DIR}/pg_decoded.txt}"
HOST_UID="${HOST_UID:-1000}"
HOST_GID="${HOST_GID:-1000}"

CLEANING=0

mkdir -p "${OUT_DIR}"

log() { printf '\033[1;35m[wireshark]\033[0m %s\n' "$*"; }

fix_perms() {
    [[ -d "${OUT_DIR}" ]] && chown -R "${HOST_UID}:${HOST_GID}" "${OUT_DIR}" 2>/dev/null || true
}
log "Fixing output permissions (${HOST_UID}:${HOST_GID})..."
fix_perms

decode() {
    if [[ ! -s "${CAPTURE_FILE}" ]]; then
        log "No ${CAPTURE_FILE} to decode (empty or missing). Was the capture service running?"
        return 0
    fi

    log "Decoding ${CAPTURE_FILE} -> ${DECODED_FILE}"

    local tmp
    tmp="${DECODED_FILE}.tmp.$$"

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

while true; do
    sleep 3600 &
    wait $!
done

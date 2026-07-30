#!/usr/bin/env bash

set -uo pipefail

VETH0="${VETH0:-veth0}"
OUT_DIR="${OUT_DIR:-/work/output}"
CAPTURE_FILE="${CAPTURE_FILE:-${OUT_DIR}/capture.pcap}"
DECODED_FILE="${DECODED_FILE:-${OUT_DIR}/decoded.txt}"
FILTER="${FILTER:-}"
TMP_CAPTURE="/tmp/capture_tmp.pcap"

HOST_UID="${HOST_UID:-1000}"
HOST_GID="${HOST_GID:-1000}"

DUMP_PID=""
CLEANING=0

mkdir -p "${OUT_DIR}"

log() { printf '\033[1;35m[wireshark]\033[0m %s\n' "$*"; }

fix_perms() {
    [[ -d "${OUT_DIR}" ]] && chown -R "${HOST_UID}:${HOST_GID}" "${OUT_DIR}" 2>/dev/null || true
}

log "Fixing output permissions (${HOST_UID}:${HOST_GID})..."
fix_perms

decode() {
    if [[ -s "${CAPTURE_FILE}" ]]; then
        log "Decoding ${CAPTURE_FILE} -> ${DECODED_FILE}"

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
    sleep 0.3

    if [[ -s "${TMP_CAPTURE}" ]]; then
        cp -f "${TMP_CAPTURE}" "${CAPTURE_FILE}"
        log "Copied ${TMP_CAPTURE} -> ${CAPTURE_FILE}"
    fi

    decode
    fix_perms
    log "Done."
}
trap cleanup EXIT INT TERM

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

rm -f "${CAPTURE_FILE}" "${TMP_CAPTURE}"
log "Capturing ${VETH0} -> ${TMP_CAPTURE} (-> ${CAPTURE_FILE})"
[[ -n "${FILTER}" ]] && log "Capture filter: ${FILTER}"

if [[ -n "${FILTER}" ]]; then
    dumpcap -i "${VETH0}" -q -f "${FILTER}" -w "${TMP_CAPTURE}" &
else
    dumpcap -i "${VETH0}" -q -w "${TMP_CAPTURE}" &
fi
DUMP_PID=$!

wait "${DUMP_PID}" 2>/dev/null || true
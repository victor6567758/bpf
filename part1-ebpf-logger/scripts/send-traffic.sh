#!/usr/bin/env bash

set -uo pipefail

WHAT="${1:-all}"

PEER_NS="${PEER_NS:-bpfpeer}"
SRC_IP="${VETH1_IP_NO_MASK:-10.0.0.2}"
DST_IP="${VETH0_IP_NO_MASK:-10.0.0.1}"

log() { printf '\033[1;36m==>\033[0m %s\n' "$*"; }

case "$WHAT" in
    icmp|all)
        log "ICMP: 3 pings ${SRC_IP} -> ${DST_IP}"
        ip netns exec "$PEER_NS" ping -c 3 "$DST_IP" >/dev/null 2>&1 || true
        ;;
esac

case "$WHAT" in
    udp|all)
        if command -v nc >/dev/null 2>&1; then
            log "UDP: 5 packets ${SRC_IP} -> ${DST_IP}:9123"
            ( nc -u -l "$DST_IP" 9123 >/dev/null 2>&1 ) & udp_pid=$!
            sleep 0.3
            for i in 1 2 3 4 5; do
                echo "udp-packet-$i" | ip netns exec "$PEER_NS" nc -u -w1 "$DST_IP" 9123 >/dev/null 2>&1 || true
            done
            kill "$udp_pid" 2>/dev/null || true
        fi
        ;;
esac

case "$WHAT" in
    tcp|all)
        if command -v nc >/dev/null 2>&1; then
            log "TCP: 1 connection ${SRC_IP} -> ${DST_IP}:9222"
            ( nc -l "$DST_IP" 9222 >/dev/null 2>&1 ) & tcp_pid=$!
            sleep 0.3
            echo "tcp-handshake-test" | ip netns exec "$PEER_NS" nc -w1 "$DST_IP" 9222 >/dev/null 2>&1 || true
            kill "$tcp_pid" 2>/dev/null || true
        fi
        ;;
esac

case "$WHAT" in
    http|all)

        if command -v nc >/dev/null 2>&1; then
            log "HTTP: GET http://${DST_IP}:8080/hello"

            (
                printf 'HTTP/1.1 200 OK\r\n'
                printf 'Content-Type: text/plain\r\n'
                printf 'Connection: close\r\n'
                printf '\r\n'
                printf 'Hello from the eBPF packet-logger demo!\n'
                sleep 1
            ) | nc -l "$DST_IP" 8080 >/dev/null 2>&1 &
            http_pid=$!
            sleep 0.3

            ip netns exec "$PEER_NS" bash -c \
                "printf 'GET /hello HTTP/1.1\r\nHost: %s\r\nUser-Agent: bpf-demo/1.0\r\nConnection: close\r\n\r\n' '$DST_IP' | nc -w2 '$DST_IP' 8080" \
                >/dev/null 2>&1 || true
            kill "$http_pid" 2>/dev/null || true
            wait "$http_pid" 2>/dev/null || true
        fi
        ;;
esac

log "Sent ($WHAT)."

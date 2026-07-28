// xdp_capture.bpf.c
//
// Captures packets to/from TCP port 5432 (Postgres) and ships them to
// userspace via a ring buffer. Writes full Ethernet+IP+TCP+payload so the
// resulting pcap can be opened in Wireshark, which has a built-in Postgres
// wire-protocol dissector that will decode query text, result rows, etc.
// directly — no custom parsing needed on our end, assuming the connection
// is NOT using SSL (see note below).

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "common.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22); // 4 MB — query/result payloads can be chunky
} events SEC(".maps");

SEC("xdp")
int xdp_capture_prog(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    __u16 sport = bpf_ntohs(tcp->source);
    __u16 dport = bpf_ntohs(tcp->dest);

    // Only care about Postgres traffic in either direction (client->server
    // queries land on dport 5432, server->client responses on sport 5432).
    if (sport != PG_PORT && dport != PG_PORT)
        return XDP_PASS;

    // pkt_len is data_end - data; both pointers are already validated above.
    __u32 pkt_len = data_end - data;
    __u32 cap_len = pkt_len > CAPTURE_LEN ? CAPTURE_LEN : pkt_len;
    // Re-assert the bound so the verifier sees cap_len <= CAPTURE_LEN-1 as a
    // known constant range when it's passed to bpf_probe_read_kernel. Without
    // this the helper's size argument is treated as unbounded (-EACCES).
    cap_len &= CAPTURE_MASK;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return XDP_PASS; // never drop real traffic just because capture is backed up

    e->pkt_len = pkt_len;
    e->cap_len = cap_len;

    // bpf_probe_read_kernel handles source bounds (won't read past data_end)
    // and the verifier trusts it for the destination since cap_len is clamped
    // to CAPTURE_LEN (the compile-time size of e->data). This is far simpler
    // for the verifier than a manual byte-copy loop.
    bpf_probe_read_kernel(e->data, cap_len, data);

    bpf_ringbuf_submit(e, 0);

    return XDP_PASS; // pure observer — always pass the packet through
}

char _license[] SEC("license") = "GPL";

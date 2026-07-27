// SPDX-License-Identifier: GPL-2.0
// XDP program: inspects every packet on the attached interface, extracts a
// small summary (protocol, src/dst IP, ports, length) and pushes it to
// userspace through a BPF ring buffer. Does NOT drop or modify traffic.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "packet_event.h"

// Ring buffer used to stream events to userspace. 256KB is plenty for a
// demo/logging workload; bump it if the consumer can fall behind bursts.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18);
} events SEC(".maps");

SEC("xdp")
int xdp_logger(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // Only interested in IPv4 for this demo; everything else passes through
    // untouched.
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    struct packet_event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
        return XDP_PASS; // ring buffer full - drop the log, keep the packet

    evt->timestamp_ns = bpf_ktime_get_ns();
    evt->src_ip       = ip->saddr;
    evt->dst_ip       = ip->daddr;
    evt->protocol     = ip->protocol;
    evt->pkt_len      = bpf_ntohs(ip->tot_len);
    evt->src_port     = 0;
    evt->dst_port     = 0;

    // Best-effort port extraction for TCP/UDP; bounds-checked for the verifier.
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) <= data_end) {
            evt->src_port = bpf_ntohs(tcp->source);
            evt->dst_port = bpf_ntohs(tcp->dest);
        }
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + (ip->ihl * 4);
        if ((void *)(udp + 1) <= data_end) {
            evt->src_port = bpf_ntohs(udp->source);
            evt->dst_port = bpf_ntohs(udp->dest);
        }
    }

    bpf_ringbuf_submit(evt, 0);

    // XDP_PASS: we only observe traffic here. Switch to XDP_DROP for
    // specific conditions if you want to actually filter/block packets.
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";

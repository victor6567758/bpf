// SPDX-License-Identifier: GPL-2.0
// Userspace loader for xdp_logger.bpf.c
//
// - Loads and attaches the XDP program to a network interface (given by
//   name, e.g. "eth0").
// - Polls the BPF ring buffer for events and appends a line per packet to
//   an output file (default: ./output/packets.log).
// - Exits cleanly and detaches the program on Ctrl-C / SIGTERM.

#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include <netinet/in.h>

#include "../bpf/packet_event.h"
#include "xdp_logger.skel.h"

static volatile sig_atomic_t keep_running = 1;
static FILE *out_fp = NULL;

static void handle_signal(int sig)
{
    (void)sig;
    keep_running = 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    if (level == LIBBPF_DEBUG)
        return 0; // keep the demo output readable
    return vfprintf(stderr, format, args);
}

static const char *proto_name(uint8_t proto)
{
    switch (proto) {
        case IPPROTO_TCP: return "TCP";
        case IPPROTO_UDP: return "UDP";
        case IPPROTO_ICMP: return "ICMP";
        default: return "OTHER";
    }
}

// Called by ring_buffer__poll() for every event the kernel side submits.
static int handle_event(void *ctx, void *data, size_t data_sz)
{
    (void)ctx;
    (void)data_sz;
    const struct packet_event *e = data;

    struct in_addr src = { .s_addr = e->src_ip };
    struct in_addr dst = { .s_addr = e->dst_ip };
    char src_buf[INET_ADDRSTRLEN];
    char dst_buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &src, src_buf, sizeof(src_buf));
    inet_ntop(AF_INET, &dst, dst_buf, sizeof(dst_buf));

    time_t sec = e->timestamp_ns / 1000000000ULL;
    struct tm tm_info;
    localtime_r(&sec, &tm_info);
    char time_buf[32];
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", &tm_info);

    fprintf(out_fp, "%s proto=%s %s:%u -> %s:%u len=%u\n",
            time_buf, proto_name(e->protocol),
            src_buf, e->src_port, dst_buf, e->dst_port, e->pkt_len);
    fflush(out_fp); // flush so `tail -f` on the log file shows events live

    return 0;
}

static void usage(const char *prog)
{
    fprintf(stderr, "Usage: %s <interface> [output_file]\n", prog);
    fprintf(stderr, "  interface    network interface to attach to, e.g. eth0\n");
    fprintf(stderr, "  output_file  path to append packet log lines to (default: ./output/packets.log)\n");
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    const char *ifname = argv[1];
    const char *out_path = argc > 2 ? argv[2] : "./output/packets.log";

    int ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        fprintf(stderr, "Interface '%s' not found: %s\n", ifname, strerror(errno));
        return 1;
    }

    out_fp = fopen(out_path, "a");
    if (!out_fp) {
        fprintf(stderr, "Could not open output file '%s': %s\n", out_path, strerror(errno));
        return 1;
    }
    setvbuf(out_fp, NULL, _IOLBF, 0); // line-buffered

    libbpf_set_print(libbpf_print_fn);

    struct xdp_logger_bpf *skel = xdp_logger_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open/load BPF skeleton\n");
        fclose(out_fp);
        return 1;
    }

    struct bpf_link *link = bpf_program__attach_xdp(skel->progs.xdp_logger, ifindex);
    if (!link) {
        fprintf(stderr, "Failed to attach XDP program to %s: %s\n", ifname, strerror(errno));
        xdp_logger_bpf__destroy(skel);
        fclose(out_fp);
        return 1;
    }

    struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        bpf_link__destroy(link);
        xdp_logger_bpf__destroy(skel);
        fclose(out_fp);
        return 1;
    }

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    printf("Attached to interface '%s' (ifindex %d). Logging to '%s'. Press Ctrl-C to stop.\n",
           ifname, ifindex, out_path);

    while (keep_running) {
        int err = ring_buffer__poll(rb, 200 /* ms */);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }
    }

    printf("Detaching and shutting down...\n");
    ring_buffer__free(rb);
    bpf_link__destroy(link);
    xdp_logger_bpf__destroy(skel);
    fclose(out_fp);
    return 0;
}

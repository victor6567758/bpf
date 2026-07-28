// loader.c
//
// Loads xdp_capture.bpf.o, attaches it to the given interface, and writes
// every captured packet to a standard pcap file (readable directly in
// Wireshark/tcpdump). Ctrl+C to stop; detaches cleanly on exit.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/time.h>
#include <net/if.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "common.h"

struct pcap_hdr {
    __u32 magic_number;
    __u16 version_major;
    __u16 version_minor;
    __s32 thiszone;
    __u32 sigfigs;
    __u32 snaplen;
    __u32 network;
};

struct pcaprec_hdr {
    __u32 ts_sec;
    __u32 ts_usec;
    __u32 incl_len;
    __u32 orig_len;
};

static volatile sig_atomic_t stop;
static FILE *outfile;
static long packet_count;

static void handle_sigint(int sig)
{
    (void)sig;
    stop = 1;
}

// docker compose down sends SIGTERM (not SIGINT). Without this handler the
// loader would be killed after stop_grace_period without detaching XDP,
// leaving the program attached to the interface.
static void install_signal_handlers(void)
{
    struct sigaction sa = {0};
    sa.sa_handler = handle_sigint;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);   // writes to a closed pcap should not kill us
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    (void)ctx;
    (void)data_sz;
    struct event *e = data;
    struct pcaprec_hdr rec;
    struct timeval tv;

    gettimeofday(&tv, NULL);
    rec.ts_sec = (__u32)tv.tv_sec;
    rec.ts_usec = (__u32)tv.tv_usec;
    rec.incl_len = e->cap_len;
    rec.orig_len = e->pkt_len;

    fwrite(&rec, sizeof(rec), 1, outfile);
    fwrite(e->data, 1, e->cap_len, outfile);
    fflush(outfile);

    packet_count++;
    if (packet_count % 10 == 0)
        printf("\rcaptured %ld packets", packet_count);
    fflush(stdout);

    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr, "usage: sudo %s <interface> <output.pcap>\n", argv[0]);
        fprintf(stderr, "example: sudo %s eth0 pg_capture.pcap\n", argv[0]);
        return 1;
    }

    const char *ifname = argv[1];
    int ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        fprintf(stderr, "unknown interface: %s\n", ifname);
        return 1;
    }

    outfile = fopen(argv[2], "wb");
    if (!outfile) {
        perror("fopen");
        return 1;
    }

    struct pcap_hdr hdr = {
        .magic_number = 0xa1b2c3d4,
        .version_major = 2,
        .version_minor = 4,
        .thiszone = 0,
        .sigfigs = 0,
        .snaplen = CAPTURE_LEN,
        .network = 1, // LINKTYPE_ETHERNET
    };
    fwrite(&hdr, sizeof(hdr), 1, outfile);

    struct bpf_object *obj = bpf_object__open_file("xdp_capture.bpf.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "failed to open BPF object (is xdp_capture.bpf.o next to this binary?)\n");
        return 1;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "failed to load BPF object into kernel\n");
        return 1;
    }

    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "xdp_capture_prog");
    if (!prog) {
        fprintf(stderr, "couldn't find xdp_capture_prog in object file\n");
        return 1;
    }
    int prog_fd = bpf_program__fd(prog);

    if (bpf_xdp_attach(ifindex, prog_fd, 0, NULL) < 0) {
        fprintf(stderr, "failed to attach XDP program to %s (run with sudo?)\n", ifname);
        return 1;
    }

    struct bpf_map *map = bpf_object__find_map_by_name(obj, "events");
    struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(map), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "failed to create ring buffer\n");
        bpf_xdp_attach(ifindex, -1, 0, NULL);
        return 1;
    }

    install_signal_handlers();
    printf("capturing Postgres traffic (port 5432) on %s -> %s\n", ifname, argv[2]);
    printf("press Ctrl+C to stop\n");

    while (!stop) {
        ring_buffer__poll(rb, 100 /* ms timeout */);
    }

    printf("\ndetaching and closing %ld packets captured\n", packet_count);
    bpf_xdp_attach(ifindex, -1, 0, NULL);
    ring_buffer__free(rb);
    bpf_object__close(obj);
    fclose(outfile);

    return 0;
}

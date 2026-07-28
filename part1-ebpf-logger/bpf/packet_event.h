#ifndef PACKET_EVENT_H
#define PACKET_EVENT_H

// Use the kernel's fixed-width types instead of C99 <stdint.h>: this header
// is compiled both by clang -target bpf (kernel side) and by the normal
// userspace toolchain, and linux/types.h is the one set of typedefs both
// sides agree on without pulling in glibc headers that confuse the bpf
// target triple.
#include <linux/types.h>

// Layout shared between the BPF program (kernel side) and the userspace
// loader. Keep this POD/packed-friendly - no pointers, no padding surprises.
struct packet_event {
    __u64 timestamp_ns;
    __u32 src_ip;   // network byte order
    __u32 dst_ip;   // network byte order
    __u16 src_port; // host byte order
    __u16 dst_port; // host byte order
    __u8  protocol; // IPPROTO_TCP / IPPROTO_UDP / etc.
    __u8  _pad[3];
    __u32 pkt_len;
};

#endif // PACKET_EVENT_H

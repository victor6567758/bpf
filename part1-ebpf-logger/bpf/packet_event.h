#ifndef PACKET_EVENT_H
#define PACKET_EVENT_H

#include <linux/types.h>

struct packet_event {
    __u64 timestamp_ns;
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;
    __u8  _pad[3];
    __u32 pkt_len;
};

#endif

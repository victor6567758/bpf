// common.h
//
// Shared between xdp_capture.bpf.c (kernel side) and loader.c (userspace).
// This is the single source of truth for the ring buffer's wire format -
// both sides #include this instead of each declaring their own copy of
// struct event, so a change to CAPTURE_LEN or the struct layout can never
// silently desync between kernel and userspace.

#ifndef PG_CAPTURE_COMMON_H
#define PG_CAPTURE_COMMON_H

#include <linux/types.h>

#define PG_PORT 5432
// CAPTURE_LEN must be a power of two so the BPF program can re-bound the
// cap_len variable with `cap_len &= (CAPTURE_LEN - 1)` to satisfy the
// verifier without changing the value when cap_len <= CAPTURE_LEN already.
// 4096 is plenty for a Postgres protocol snapshot.
#define CAPTURE_LEN 4096
#define CAPTURE_MASK (CAPTURE_LEN - 1)

struct event {
    __u32 pkt_len; // original packet length on the wire
    __u32 cap_len; // how many bytes of `data` are actually valid (<= CAPTURE_LEN)
    __u8 data[CAPTURE_LEN];
};

#endif // PG_CAPTURE_COMMON_H
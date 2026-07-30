#ifndef PG_CAPTURE_COMMON_H
#define PG_CAPTURE_COMMON_H

#include <linux/types.h>

#define PG_PORT 5432

#define CAPTURE_LEN 4096
#define CAPTURE_MASK (CAPTURE_LEN - 1)

struct event {
    __u32 pkt_len;
    __u32 cap_len;
    __u8 data[CAPTURE_LEN];
};

#endif

## Learning eBPF by Building Two Hands-On XDP Projects

eBPF on its own is a sprawling topic - it covers networking (XDP, TC), tracing (kprobes, uprobes, tracepoints), security enforcement (LSM hooks, seccomp), and profiling, spanning dozens of hook types, several verifier generations, and an entire ecosystem (libbpf, BCC, bpftrace, Cilium) built on top of it. No single article covers all of that, and this one doesn't try.

This is a two-part learning book built around two small, complete eBPF projects in this repo, each teaching one narrow, well-defined slice of that larger space: writing, compiling, loading, and attaching an XDP program - one specific eBPF hook, chosen because it's the earliest and simplest place to observe raw network traffic - to an interface. Both parts are about eBPF: the kernel-side C program, the verifier, the map that carries data out, and the userspace loader that ties it all together. That progression, at two different levels of difficulty, is the entire arc of the book:
- **Part 1 - `part1-ebpf-logger`** attaches to a veth pair between two
  network namespaces, parses Ethernet/IP/TCP/UDP headers by hand, and
  streams a one-line summary of every packet to a log file. It's the
  smallest possible XDP program: read some header fields, push a small
  fixed-size struct through a ring buffer, done.
- **Part 2 - `part2-postgres-sink`** attaches to the loopback interface,
  copies raw packet bytes (not parsed fields) for anything on port 5432,
  and writes a real `.pcap` file that Wireshark's own `pgsql` dissector
  decodes into human-readable SQL. It's the same core skills - maps, the
  verifier, ring buffers - applied to a different goal: instead of
  extracting fields yourself, you let Wireshark do the protocol parsing,
  and your BPF program's only job is to get the right bytes off the wire
  and into a file.

Every project also runs an independent **Wireshark/tshark sidecar** that
taps the same interface via `dumpcap`, completely separate from the BPF
program. Comparing "what my 60-line kernel program extracted" against
"what a mature, general-purpose protocol analyzer sees on the same wire"
is a big part of what makes both parts worth doing side by side - it's
where the eBPF half and the Wireshark half of this book meet.

## Scope: what this article does and doesn't cover

To keep two small projects teachable in one sitting each, this book
deliberately narrows the field. It's worth being explicit about the
boundary, since both eBPF and Wireshark are easy to over-generalize from
a single example.

**In scope:**

- Writing, compiling, loading, and attaching an XDP program with libbpf
  and its skeleton API
- The BPF verifier's bounds-checking requirements, from the caller's side
  (what you have to write to satisfy it), not its internal implementation
- Ring buffers (`BPF_MAP_TYPE_RINGBUF`) as the kernel-to-userspace
  transport
- Native vs. generic XDP attach modes, and why the interface you choose
  decides which one is available
- Reading and writing the pcap file format by hand
- Using `tshark`/Wireshark as an independent, general-purpose comparison
  point for whatever the BPF program captured

**Explicitly out of scope** (mentioned only in passing, if at all, and
worth researching separately once this book's foundation feels solid):

- Other eBPF hook types - kprobes, uprobes, tracepoints, cgroup/TC hooks,
  LSM hooks, sockmaps, syscall tracing - which is most of what tools like
  bpftrace, BCC, and Tetragon actually build on
- eBPF for anything other than observation - traffic *shaping*,
  *forwarding*, or *rewriting* (what Cilium and Katran do) is a
  meaningfully harder problem this book doesn't touch
- CO-RE (Compile Once – Run Everywhere) and BTF-based portability across
  kernel versions - both demos assume a single known kernel and skip the
  portability work a real-world deployment needs
- XDP hardware offload mode, and any performance benchmarking of native
  vs. generic mode
- Writing a new Wireshark/tshark dissector, or any protocol other than
  the handful of fields/messages these two demos happen to touch
  (IPv4/TCP/UDP headers in Part 1, the Postgres wire protocol in Part 2)
- Security hardening, production deployment concerns, or running any of
  this outside the Docker-based demo environment described here

If you finish both parts and want to go further in any of those
directions, the "Where this shows up in the real world" and "Further
reading" sections at the end point to the projects and docs that do.

## How to use this book

Read Part 1 first, start to finish, and run its demo (`cd
part1-ebpf-logger && make up`) alongside it - every section maps onto a
specific, short piece of code you can have open at the same time. Part 1
also introduces, once and in depth, several ideas (the BPF verifier,
bounds checks, ring buffers, `SEC()` sections, the libbpf skeleton) that
Part 2 relies on without re-explaining. Once Part 1 feels solid, move to
Part 2, which reuses that foundation to tackle a harder problem:
capturing raw bytes instead of parsed fields, decoding a real
application protocol, and orchestrating four containers instead of two.
Come back to individual sections later as a reference.

## Table of contents

**Part 1 - Building an XDP Packet Logger with eBPF**

1. [Why eBPF, why XDP](#1-why-ebpf-why-xdp)
2. [The 30,000-foot view](#2-the-30000-foot-view)
3. [The kernel side, statement by statement](#3-the-kernel-side-statement-by-statement)
4. [The struct that bridges two worlds](#4-the-struct-that-bridges-two-worlds)
5. [From C source to a program the kernel will run](#5-from-c-source-to-a-program-the-kernel-will-run)
6. [The userspace loader and the BPF API surface](#6-the-userspace-loader-and-the-bpf-api-surface)
7. [Why the demo needs a veth pair and a namespace](#7-why-the-demo-needs-a-veth-pair-and-a-namespace)
8. [Containers, Compose, and the two-service dance](#8-containers-compose-and-the-two-service-dance)
9. [Running it and reading the output](#9-running-it-and-reading-the-output)
10. [The BPF API, distilled](#10-the-bpf-api-distilled)
11. [Exercises: extending the logger](#11-exercises-extending-the-logger)

**Part 2 - Capturing Postgres Wire Traffic with XDP**

1. [What we're building](#1-what-were-building)
2. [The big picture](#2-the-big-picture)
3. [The kernel side: the XDP capture program](#3-the-kernel-side-the-xdp-capture-program)
4. [The shared wire format](#4-the-shared-wire-format)
5. [The userspace loader](#5-the-userspace-loader)
6. [How BPF code is compiled](#6-how-bpf-code-is-compiled)
7. [The Docker build](#7-the-docker-build)
8. [Docker Compose orchestration](#8-docker-compose-orchestration)
9. [The entrypoint scripts](#9-the-entrypoint-scripts)
10. [The tshark decode sidecar](#10-the-tshark-decode-sidecar)
11. [The Makefile](#11-the-makefile)
12. [End-to-end walkthrough](#12-end-to-end-walkthrough)
13. [Key concepts and gotchas](#13-key-concepts-and-gotchas)

**Wrapping up**

- [Comparing the two projects](#comparing-the-two-projects)
- [Why one project needs a fake network and the other doesn't](#why-one-project-needs-a-fake-network-and-the-other-doesnt)
- [Exercises: extending the Postgres capture](#exercises-extending-the-postgres-capture)
- [Where this shows up in the real world](#where-this-shows-up-in-the-real-world)
- [Further reading](#further-reading)

---

# Part 1 - Building an XDP Packet Logger with eBPF

This part is a guided, line-by-line tour of **part1-ebpf-logger** - the
project in this repo that attaches a small eBPF program to a network
interface and streams a one-line summary of every IPv4 packet to
userspace. Nothing here is exotic; that's the point. It's small enough to
read in one sitting, and every line teaches you a piece of the real
eBPF/XDP API that you'll reuse in Part 2 and in bigger programs beyond
this repo.

### 1. Why eBPF, why XDP

**eBPF** (extended Berkeley Packet Filter) lets you load small, sandboxed
programs into the Linux kernel and attach them to hook points - network
events, syscalls, function entry/exit, scheduler events, and more. The
kernel never runs code it hasn't verified: before your program is attached,
a component called the **verifier** statically proves it can't crash the
kernel, read out-of-bounds memory, or loop forever.

**XDP** (eXpress Data Path) is one specific hook point: the earliest place
in the receive path where you can run a BPF program, before the kernel
has allocated an `sk_buff` or done any protocol processing. That makes it
extremely fast - it's how high-performance firewalls and load balancers
are built - but it also means your program sees *raw bytes*, not
conveniently parsed structures. You do your own header parsing, by hand,
with bounds checks the verifier can prove are safe.

This project's XDP program does the simplest possible thing with that
power: look, don't touch. It reads each packet's IP/port/protocol/length,
sends a summary to userspace, and always returns `XDP_PASS` - meaning
every packet still reaches the network stack untouched. You could change
one `return` statement and turn it into a firewall; section 11 asks you to
try that.

| Approach                | Where it runs           | Per-packet cost | Sees packet before... |
|--------------------------|--------------------------|-----------------|------------------------|
| `tcpdump` / libpcap      | AF_PACKET socket          | copy + syscall  | ...the stack has processed it |
| kprobe on `tcp_recvmsg`  | kernel function hook      | probe overhead  | ...the socket layer delivers it |
| **XDP** (this project)   | **driver / generic rx hook** | **near-zero**   | **...an `sk_buff` even exists** |

---

### 2. The 30,000-foot view

```
   veth1 (peer netns)                    veth0 (host netns)
   10.0.0.2  ── test traffic ──wire──►   10.0.0.1
                                           │
                                     XDP hook (ingress)
                                           │
                              ┌────────────┴─────────────┐
                              │   xdp_logger.bpf.c        │  kernel space
                              │   (compiled, verified,    │
                              │    running per-packet)    │
                              └────────────┬─────────────┘
                                           │ bpf_ringbuf_reserve/submit
                                           ▼
                                   BPF ring buffer map
                                           │ ring_buffer__poll()
                                           ▼
                              ┌────────────┴─────────────┐
                              │   loader.c (packet_logger) │  userspace
                              │   formats + appends a line │
                              └────────────┬─────────────┘
                                           ▼
                                output/packets.log
```

At the same time, a separate `wireshark` sidecar container taps `veth0`
independently (via `dumpcap`, the same engine behind `tcpdump`) and writes a
standard `.pcap`, which it later decodes to text. The BPF program and the
sidecar are two independent observers of the same wire - neither depends on
the other, which is a useful thing to notice: **XDP doesn't own the
interface**, it's just the first program that gets to look at each packet.

Three files carry the actual logic:

| File | Runs where | Job |
|------|-----------|-----|
| `bpf/xdp_logger.bpf.c` | kernel (verified BPF bytecode) | parse headers, push a `packet_event` to the ring buffer |
| `bpf/packet_event.h` | both (shared struct definition) | the wire format between kernel and userspace |
| `src/loader.c` | userspace (normal Linux process) | load the program, attach it, drain the ring buffer, format log lines |

---

### 3. The kernel side, statement by statement

**File: `bpf/xdp_logger.bpf.c`** (about 65 lines - read the whole thing once
before this section; it's short).

#### 3.1 Includes: no libc

```c
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
```

The `<linux/*>` headers are kernel UAPI struct definitions (`struct
ethhdr`, `struct iphdr`, ...) - the same layouts the kernel itself uses.
`<bpf/bpf_helpers.h>` and `<bpf/bpf_endian.h>` come from libbpf and declare
the **BPF helper functions** and macros (`SEC()`, `bpf_ntohs()`, etc.).

There is deliberately no `<stdio.h>`, no `malloc`, no libc at all. BPF
programs run in a restricted execution environment inside the kernel: no
dynamic allocation, no arbitrary function calls, no unbounded loops. Every
capability you have comes from a fixed set of **BPF helper functions**
(`bpf_*`) that the kernel exposes and the verifier knows how to reason
about.

#### 3.2 Declaring a map

```c
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18);
} events SEC(".maps");
```

A **BPF map** is a kernel-managed data structure that both your BPF program
and userspace can access - it's the *only* way data crosses that boundary
(besides return values). This is the modern "BTF-defined" way to declare
one: an anonymous struct with `__uint(...)` macros describing its
properties, placed into the special ELF section `.maps` via `SEC(".maps")`.
libbpf's loader recognizes this section and creates the map for you at
load time - you never call a "create map" function yourself.

`BPF_MAP_TYPE_RINGBUF` is a **ring buffer**: a single, globally-ordered,
lock-free queue that the kernel side writes into and userspace reads out
of. `max_entries` here is actually the buffer size in bytes (`1 << 18` =
256 KiB) and must be a power of two. Compare this to the older
`BPF_MAP_TYPE_PERF_EVENT_ARRAY` ("perf buffer"), which allocates one buffer
*per CPU* - events from different cores can then arrive out of order
relative to each other. A ring buffer has one buffer, so ordering is
preserved and there's no per-CPU bookkeeping in userspace. Unless you have
a specific reason to reach for the perf buffer, prefer the ring buffer.

#### 3.3 The program entry point and its context

```c
SEC("xdp")
int xdp_logger(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;
```

`SEC("xdp")` is how you tell libbpf "this function is an XDP program" -
the loader reads the section name to know which attach type to use and
which kind of context struct to expect. Change the string to `SEC("tc")`
or `SEC("kprobe/...")` and the *same toolchain* would build a completely
different kind of BPF program; the section name is the load-time contract.

`struct xdp_md *ctx` is the XDP context: it doesn't hand you a parsed
packet, just two `__u32` fields, `data` and `data_end`, holding the start
and end of the packet's memory. They arrive as integers rather than
pointers because the verifier tracks BPF register types precisely, and
`(void *)(long)` is the idiomatic cast that turns them into real pointers
without confusing that tracking.

#### 3.4 Bounds checks: the verifier's core demand

```c
struct ethhdr *eth = data;
if ((void *)(eth + 1) > data_end)
    return XDP_PASS;
```

This is the single most important pattern in any BPF packet program.
`eth + 1` is "one past the end of the Ethernet header" - if that address
is beyond `data_end`, there isn't a full header here (a truncated or
malformed packet), so bail out. **Every** dereference through `eth` after
this point is safe *because the verifier can statically prove* this check
happened first - it walks all possible execution paths and rejects the
load if any path reaches a dereference without a matching bounds check.
This is the trade you make for kernel-level speed with user-supplied data:
you do the safety proof once, explicitly, in C, instead of the kernel
doing runtime bounds checking on every access.

The same pattern repeats for each header we peel back:

```c
if (eth->h_proto != bpf_htons(ETH_P_IP))
    return XDP_PASS;                 // not IPv4 - not interested, pass it on

struct iphdr *ip = (void *)(eth + 1);
if ((void *)(ip + 1) > data_end)
    return XDP_PASS;
```

`bpf_htons()` converts a host-order `__u16` to network byte order so it can
be compared against `eth->h_proto`, which arrives off the wire in network
order. Network protocols are big-endian; x86/ARM userspace is
little-endian; BPF programs run wherever the packet arrived, so you must
convert explicitly every time you compare or store a multi-byte network
field. `bpf_htons`/`bpf_ntohs` (host→network / network→host) are the two
you'll use constantly.

#### 3.5 Reserving space in the ring buffer

```c
struct packet_event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
if (!evt)
    return XDP_PASS; // ring buffer full - drop the log, keep the packet
```

`bpf_ringbuf_reserve()` asks the map for `sizeof(*evt)` bytes and, on
success, returns a pointer you can write into *directly* - there's no
separate "build a local struct then copy it in" step, which matters when
events get larger (part2 in this repo copies raw packet bytes this way).
If the ring buffer is full (userspace hasn't drained it fast enough), you
get `NULL`. The choice of what to do next is a design decision, and this
program makes an explicit one: drop the *log entry*, never the *packet*.
`XDP_PASS` still lets the real traffic through - observability failures
should never become network failures.

#### 3.6 Filling in the fields

```c
evt->timestamp_ns = bpf_ktime_get_ns();
evt->src_ip       = ip->saddr;
evt->dst_ip       = ip->daddr;
evt->protocol     = ip->protocol;
evt->pkt_len      = bpf_ntohs(ip->tot_len);
evt->src_port     = 0;
evt->dst_port     = 0;
```

`bpf_ktime_get_ns()` is a BPF helper returning a monotonic kernel
timestamp in nanoseconds - you can't call `clock_gettime()` from kernel
space, so the helper exists specifically to give BPF programs a time
source. `ip->saddr`/`ip->daddr` are left in network byte order on purpose
(a comment in `packet_event.h` documents this) - the loader converts them
with `inet_ntop()`, which itself expects network order, so no conversion
is needed on either side. `ip->tot_len`, by contrast, *is* converted with
`bpf_ntohs()` immediately, because the loader treats `pkt_len` as a plain
host-order integer to print. Notice the asymmetry: the "right" byte order
depends entirely on what the consumer expects to do with the value, not on
a blanket rule.

#### 3.7 Best-effort port extraction

```c
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
```

`ip->ihl` is the IP header length **in 32-bit words**, not bytes - that's
why it's multiplied by 4. Skipping by `ihl * 4` rather than
`sizeof(struct iphdr)` correctly accounts for IP options when they're
present. This block is "best effort" in the sense that if the TCP/UDP
header would run past `data_end`, we simply leave the ports as `0` rather
than rejecting the packet - a truncated capture still gets logged with
whatever we could safely read.

#### 3.8 Submitting the event and returning

```c
    bpf_ringbuf_submit(evt, 0);
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
```

`bpf_ringbuf_submit()` makes the event visible to userspace consumers -
until this call, the reserved space is invisible even though it's been
written to. (There's a matching `bpf_ringbuf_discard()` if you reserve
space and then decide not to publish it.) The function always ends with
`return XDP_PASS`, one of a small enum of **XDP actions**:

| Action | Meaning |
|--------|---------|
| `XDP_PASS` | Let the packet continue up the stack (what this program always does) |
| `XDP_DROP` | Silently discard the packet - the fastest possible firewall rule |
| `XDP_TX` | Bounce the packet back out the same interface it arrived on |
| `XDP_REDIRECT` | Send the packet to a different interface or CPU |
| `XDP_ABORTED` | Drop and emit a tracepoint - signals a program bug |

Finally, `char LICENSE[] SEC("license") = "GPL";` is not optional
decoration. The kernel checks this string at load time, and a number of
BPF helpers (including ones commonly used for deeper introspection) are
gated to `GPL`-licensed programs only. Without it, `bpf_program__load()`
in the loader would fail outright.

---

### 4. The struct that bridges two worlds

**File: `bpf/packet_event.h`** (24 lines) - `#include`d by *both*
`xdp_logger.bpf.c` (kernel) and `src/loader.c` (userspace):

```c
#include <linux/types.h>

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
```

Two details worth internalizing, because they generalize to every
kernel/userspace BPF interface you'll write:

**Why `linux/types.h` instead of `<stdint.h>`.** This same header gets
compiled twice - once by `clang -target bpf` for the kernel side, once by
the normal host compiler for `loader.c`. `linux/types.h`'s `__u64`/`__u32`
typedefs are understood by both toolchains without pulling in glibc
headers that the `bpf` target doesn't fully support. It's the one
vocabulary both sides can agree on.

**Why the explicit `_pad[3]`.** Nothing in BPF *forbids* struct padding,
but leaving it implicit invites two compilers (or even the same compiler
built for two different targets) to disagree on layout, and it leaves
3 bytes of uninitialized kernel stack memory copied into a struct that
gets shared outside the kernel - a real information-leak class the
verifier partially, but not perfectly, guards against. Naming the padding
field makes the layout an explicit contract instead of an implementation
detail, and gives you a natural place to zero it if you ever need to.

This "one header, both sides" pattern is the standard way to keep a BPF
program and its userspace loader in sync: change a field here, rebuild,
and both sides see the same struct - no separate schema, no versioning
protocol, no chance of the two silently drifting apart.

---

### 5. From C source to a program the kernel will run

Three tools turn `xdp_logger.bpf.c` into something `loader.c` can attach,
and `CMakeLists.txt` wires them together as three build steps:

```
xdp_logger.bpf.c ──clang -target bpf──► xdp_logger.bpf.o ──bpftool gen skeleton──► xdp_logger.skel.h ──┐
                                                                                                          │
                                                                          loader.c ── gcc/clang ── links ─┴──► packet_logger
```

**Step 1 - compile to a BPF object file:**

```bash
clang -g -O2 -target bpf -I/usr/include/x86_64-linux-gnu \
      -c bpf/xdp_logger.bpf.c -o xdp_logger.bpf.o
```

`-target bpf` tells clang to emit **BPF bytecode** - a small RISC-like
instruction set - instead of x86/ARM machine code. The output is a regular
ELF object file; the `.maps`, `xdp`, and `license` sections you saw with
`SEC()` above become real ELF sections in this file, which is exactly what
lets a generic loader (libbpf) introspect the object without knowing
anything about the program's source in advance.

**Step 2 - generate a typed skeleton:**

```bash
bpftool gen skeleton xdp_logger.bpf.o > xdp_logger.skel.h
```

`bpftool` reads the compiled object (using embedded BTF - BPF Type
Format - debug info) and emits a C header defining a struct
(`xdp_logger_bpf`) with a typed field for every program (`progs.xdp_logger`)
and every map (`maps.events`) in the object, plus generated
`xdp_logger_bpf__open_and_load()` / `__destroy()` functions. Without the
skeleton, you'd load programs and maps by string name
(`bpf_object__find_program_by_name(obj, "xdp_logger")`) and get back
untyped handles; the skeleton exists purely for developer ergonomics -
compile-time-checked, autocompleting access to your own program.

**Step 3 - compile and link the loader** against this generated header and
libbpf:

```bash
gcc src/loader.c -I<build-dir> -I bpf/ $(pkg-config --cflags libbpf) \
    $(pkg-config --libs libbpf) -lelf -lz -o packet_logger
```

`CMakeLists.txt` expresses exactly these three steps as custom commands
with proper `DEPENDS` edges, so `cmake --build build -j` reruns only what
changed - edit `xdp_logger.bpf.c` and only steps 1–3 rerun; edit only
`loader.c` and step 3 alone reruns.

> **A note on portability (CO-RE).** This project compiles with fixed
> kernel headers baked into the Docker image, so the same kernel struct
> layouts are assumed at compile time and run time. Production BPF
> programs usually go further and use **CO-RE** ("Compile Once – Run
> Everywhere"): they compile against BTF-relocatable field accesses so the
> *same* compiled `.o` file adapts itself to whatever kernel struct layout
> it finds at load time, via `libbpf`'s CO-RE relocation step. That's a
> layer of extra complexity this demo intentionally skips - worth knowing
> the term exists for when you outgrow "build inside a pinned container."

---

### 6. The userspace loader and the BPF API surface

**File: `src/loader.c`** - this is a *normal* C program (no `-target bpf`,
compiles with whatever your host toolchain is), linked against **libbpf**,
the userspace library that knows how to load BPF object files, create
their maps, attach their programs, and drain their ring buffers. Walking
`main()` top to bottom is basically a tour of libbpf's core API:

```c
struct xdp_logger_bpf *skel = xdp_logger_bpf__open_and_load();
```

This single generated call does what would otherwise be several manual
steps: open the ELF object, create every declared map (`events`, in our
case), load every declared program into the kernel (which is the point at
which **the verifier runs** - if it rejects the program, this call fails
and `libbpf_print_fn` below will have printed why), and resolve all the
typed `skel->progs.*` / `skel->maps.*` handles.

```c
struct bpf_link *link = bpf_program__attach_xdp(skel->progs.xdp_logger, ifindex);
```

Loading a program and attaching it are two separate steps in the API -
you can have a program loaded into the kernel without it being hooked to
anything yet. `bpf_program__attach_xdp()` performs the attach and hands
back a `struct bpf_link*`, a handle representing "this program is live on
this interface." Destroying the link (`bpf_link__destroy()`) detaches it;
the process exiting uncleanly (e.g. `kill -9`) would also eventually tear
it down when the kernel notices the owning fd is gone, but this program
attaches it as a *pinned-to-process* link, not a persistent one - clean
shutdown is the intended path, which is exactly why the entrypoint script
gives it a `SIGTERM` and a grace period rather than just killing the
container (see section 8).

```c
struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(skel->maps.events),
                                           handle_event, NULL, NULL);
```

`bpf_map__fd()` gets the raw kernel file descriptor for the `events` map
out of the typed skeleton handle. `ring_buffer__new()` wraps that fd in a
libbpf ring-buffer *consumer*, registering `handle_event` as the callback
to invoke for every event the kernel side submits - this is the userspace
half of the `bpf_ringbuf_reserve`/`bpf_ringbuf_submit` pair you saw in
section 3.5.

```c
while (keep_running) {
    int err = ring_buffer__poll(rb, 200 /* ms */);
    ...
}
```

`ring_buffer__poll()` blocks (up to the given timeout) waiting for new
entries, then synchronously calls `handle_event()` once per entry that
arrived. This is a normal poll loop - nothing BPF-specific about the
mechanism itself, it's built on an `epoll` fd under the hood - but it's
the piece that actually moves data out of the kernel into your process's
address space.

`handle_event()` itself is pure userspace C: it reads a `struct
packet_event *` straight out of the buffer libbpf handed it, formats an
`inet_ntop()`'d address, a `strftime()`'d timestamp, and appends one line
to the log file. No BPF API involved here at all - by this point the data
has fully crossed into ordinary userspace land.

Finally, cleanup mirrors setup in reverse, which is a good general rule
for any libbpf program:

```c
ring_buffer__free(rb);
bpf_link__destroy(link);        // detach from the interface
xdp_logger_bpf__destroy(skel);  // unload the program, destroy the maps
fclose(out_fp);
```

#### The libbpf print callback

```c
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    if (level == LIBBPF_DEBUG)
        return 0;
    return vfprintf(stderr, format, args);
}
...
libbpf_set_print(libbpf_print_fn);
```

libbpf logs internally - including, critically, **verifier rejection
messages** when a load fails. Registering your own print function (rather
than accepting the default, which prints everything including noisy debug
lines) is how you keep that signal visible without drowning in
`LIBBPF_DEBUG` chatter. If you ever see `xdp_logger_bpf__open_and_load()`
fail with no other explanation, this is the first place to look - set the
filter to pass `LIBBPF_DEBUG` through too and rerun.

---

### 7. Why the demo needs a veth pair and a namespace

If you only remember one non-obvious fact from this project, make it this
one: **XDP fires on ingress to a specific interface**, so to *see* traffic
with XDP, that traffic has to actually arrive as ingress on the interface
you attached to. Two processes talking over `lo` (loopback) never
"arrive" on `lo` from XDP's point of view in the way you'd expect - local
delivery is short-circuited by the kernel before the interface's ingress
path is exercised the same way real cross-host traffic would be. (Compare
with part2 in this repo, which specifically works around this by relying
on generic-mode XDP's looser semantics on `lo` - see that project's
article for the tradeoffs.)

This project sidesteps the question entirely by manufacturing two
interfaces that really do have wire-like ingress between them: a **veth
pair**.

```
   default netns (host, where the container lives)     "bpfpeer" netns
   ┌────────────────────────────────────┐               ┌───────────────────┐
   │  veth0  10.0.0.1/24                │◄═══veth wire══►│  veth1 10.0.0.2/24│
   │   + XDP logger attached (ingress)  │                │  (test clients    │
   │   + nc listeners for test traffic  │                │   run from here)  │
   └────────────────────────────────────┘               └───────────────────┘
```

A veth pair is two virtual interfaces that are permanently connected to
each other, as if by a cable - whatever goes out one always arrives as
ingress on the other. `core-entrypoint.sh` creates a **separate network
namespace** (`bpfpeer`) and moves `veth1` into it, specifically so that
traffic sent from `veth1` genuinely has to cross a "wire" to reach `veth0`,
rather than the two ends being able to see each other as local addresses
in the same namespace. All test traffic is therefore deliberately sent
*from* the peer namespace *to* the host namespace:

```bash
ip netns exec bpfpeer ping -c 3 10.0.0.1
```

This is why `send-traffic.sh` is careful to run clients with `ip netns
exec bpfpeer ...` and listeners in the default namespace - get the
direction backwards and the XDP program (attached to `veth0`, watching
only ingress) simply never sees the packets.

The container can do all this namespace/interface manipulation because
`docker-compose.yml` runs it with `privileged: true` and `network_mode:
host` - it's directly manipulating the host's network namespace, not some
isolated container-private network.

---

### 8. Containers, Compose, and the two-service dance

Two services, both privileged, both on `network_mode: host` so they share
the same set of interfaces and namespaces the entrypoint script creates:

| Service | Image | Job |
|---------|-------|-----|
| `packet-logger` | built from `Dockerfile.core` | creates the veth pair + netns, builds the BPF program, attaches it, streams `packets.log` |
| `wireshark` | built from `Dockerfile.wireshark` | waits for `veth0` to exist, captures it independently via `dumpcap`, decodes to text on shutdown |

`Dockerfile.core` is worth a second look for one specific reason: it
builds `bpftool` **from source** in a separate build stage, rather than
`apt install`-ing it:

```dockerfile
FROM ubuntu:24.04 AS bpftool-builder
RUN git clone --depth 1 https://github.com/libbpf/bpftool.git /tmp/bpftool \
    && cd /tmp/bpftool && git submodule update --init --recursive \
    && cd src && make -j"$(nproc)" \
    && install -m 0755 bpftool /usr/local/bin/bpftool
```

Distro-packaged `bpftool` is often tied to the exact running kernel
version (some distros ship it as part of the `linux-tools-$(uname -r)`
package), which breaks the moment the container runs on a different
kernel than the one the package was built against - a near-guarantee in
containerized environments where the container image and the host kernel
are versioned completely independently. Building from source in a
throwaway stage, then copying just the binary into the final image (`COPY
--from=bpftool-builder`), sidesteps that entirely.

`docker-compose.yml`'s comment on `privileged: true` also names the
minimal alternative, worth knowing for anything beyond a demo:

```yaml
# Loading BPF programs and attaching XDP requires elevated privileges.
# `privileged: true` is the simplest path; for production you'd instead
# grant just CAP_BPF, CAP_NET_ADMIN, CAP_NET_RAW, CAP_SYS_ADMIN.
services:
  packet-logger:
    build:
      context: .
      dockerfile: Dockerfile.core
    container_name: ebpf-packet-logger
    privileged: true
...
```

`CAP_BPF` (loading programs and creating maps), `CAP_NET_ADMIN` (creating
veth pairs, moving interfaces between namespaces), `CAP_NET_RAW` (packet
capture), and `CAP_SYS_ADMIN` (some older kernels still require this for
certain BPF operations) - granting exactly these instead of `privileged:
true` is meaningfully narrower, at the cost of more Compose config to
maintain. Good to know the boundary exists even in a repo that takes the
simple path.

#### core-entrypoint.sh: the full startup sequence

Section 7 already covers *why* this script builds a veth pair and a
namespace; here's *how*, step by step, since a single `make up` is
actually doing seven distinct things in order:

##### Step 1-2: build the namespace and the veth pair

```bash
ip netns del "${PEER_NS}" 2>/dev/null || true
ip netns add "${PEER_NS}"

ip link del "${VETH0}" 2>/dev/null || true   # clean up any stale pair
ip link add "${VETH0}" type veth peer name "${VETH1}"
ip link set "${VETH1}" netns "${PEER_NS}"
```

Both steps delete-then-create defensively (`del ... || true`), because a
container that crashed mid-run on a previous `make up` can leave a stale
namespace or veth pair behind on the host - `network_mode: host` means
these objects genuinely persist on the host between container runs,
unlike most container state. Cleaning up unconditionally before creating
means `make up` is safe to run repeatedly without a manual `make down` in
between.

##### Step 3: configure IPs and bring both ends up

```bash
ip addr add "${VETH0_IP}" dev "${VETH0}"
ip link set "${VETH0}" up

ip netns exec "${PEER_NS}" ip addr add "${VETH1_IP}" dev "${VETH1}"
ip netns exec "${PEER_NS}" ip link set "${VETH1}" up
ip netns exec "${PEER_NS}" ip link set lo up   # lo is down by default in a new ns
```

Easy to miss: a brand-new network namespace's own loopback interface
starts **down**, not up - anything inside `bpfpeer` that happens to talk
to itself over `127.0.0.1` (rather than across the veth pair to `veth0`)
would otherwise silently fail. Bringing `bpfpeer`'s `lo` up is cheap
insurance, not something the demo strictly requires today.

##### Step 4: build inside the running container

```bash
mkdir -p build output
if ! cmake -S . -B build >&2 || ! cmake --build build -j >&2; then
    echo "Build failed" >&2
    exit 1
fi
```

Unlike Part 2 (which compiles once in a separate Docker build stage - see
that project's section 6), Part 1 compiles **every time** you run `make
up`, inside the already-running container. That's a deliberate
simplicity trade-off for a teaching repo: no multi-stage Dockerfile to
reason about, at the cost of a few extra seconds on every `up`.

##### Step 5: attach XDP and prepare the log file

```bash
: > "${LOG}"   # truncate so each `up` starts a fresh capture
fix_perms      # hand the (fresh, empty) log to the host user up front
./build/packet_logger "${VETH0}" "${LOG}" &
LOGGER_PID=$!
sleep 1        # let it attach before we generate traffic
```

Same pattern you'll see again in Part 2's `capture-entrypoint.sh`:
truncate any previous run's output, hand ownership to the host user
*before* anything is written (so `packets.log`'s permissions are correct
from the very first byte), start the loader in the background, then
pause briefly so the XDP attach completes before any test traffic is
generated.

##### Step 6: fire the test traffic, or exit early

```bash
[[ "${TEST_ON_START}" == "1" ]] && /work/scripts/send-traffic.sh all

if [[ "${EXIT_AFTER_TEST}" == "1" ]]; then
    sleep 0.5
    cat "${LOG}"
    exit 0
fi
```

`send-traffic.sh all` is what actually generates the ICMP/UDP/TCP/HTTP
burst you see logged on a fresh `make up` - and per section 7, it's
careful to originate that traffic *from* the `bpfpeer` namespace so it
genuinely crosses the veth pair as ingress. `EXIT_AFTER_TEST=1` turns
this into a one-shot "capture a burst, print it, quit" run instead of a
long-lived service - useful for scripting or CI, where the trap still
runs and tears down the veth pair on the way out.

##### Step 7: stream and block

```bash
tail -n +1 -f "${LOG}" &
TAIL_PID=$!
wait "${LOGGER_PID}" 2>/dev/null || true
```

The script blocks here indefinitely, `tail -f`-ing the log to your
terminal, until a signal arrives - at which point the cleanup trap
(described next) runs.

#### Shutdown is a designed sequence, not an afterthought

```yaml
stop_grace_period: 5s
init: true
```

`docker compose down` sends `SIGTERM`. `init: true` runs a minimal init
process (tini) as PID 1 so that signal actually reaches the entrypoint
script's `bash`, rather than being swallowed the way PID 1 sometimes
swallows signals it has no handler for. The script's own `trap cleanup
EXIT INT TERM` then runs: kill the loader (closing its `bpf_link`, which
detaches the XDP program), delete `veth0` (which atomically takes
`veth1` and the whole pair with it), delete the `bpfpeer` namespace.
`stop_grace_period: 5s` is the budget Docker gives that trap to finish
before escalating to `SIGKILL` - long enough for cleanup, short enough
that `make down` doesn't hang.

---

### 9. Running it and reading the output

```bash
cd part1-ebpf-logger
make up
```

This single command builds both images, starts both services, creates the
veth pair and namespace, compiles the BPF program inside the container,
attaches it, fires a burst of ICMP/UDP/TCP/HTTP test traffic across the
pair, and streams the resulting log to your terminal. Stop it with
`Ctrl-C`, or `make down` from another terminal for a clean, decoded
teardown.

A line from `output/packets.log` looks like:

```
2026-07-27 14:02:11 proto=TCP 10.0.0.1:51422 -> 10.0.0.2:443 len=60
```

exactly the fields `xdp_logger.bpf.c` filled into `struct packet_event`,
formatted by `handle_event()` in the loader. Compare that against
`output/decoded.txt`, tshark's full protocol decode of the *same* burst of
packets, captured completely independently by the `wireshark` sidecar.
Seeing the same five TCP fields your 65-line kernel program extracted
sitting inside tshark's much deeper decode is a good way to build
intuition for how little data you actually need to answer most "what's
happening on this link" questions.

Useful variations:

```bash
make test TRAFFIC=udp                      # send just UDP into a running demo
make decode FILTER='udp port 9123'         # tshark-decode one flow, right now
EXIT_AFTER_TEST=1 make up                  # one-shot: capture the startup burst and exit
```

---

### 10. The BPF API, distilled

A quick-reference glossary of every BPF-specific symbol this project
touches, since it's easy to lose the forest for the trees across ten
sections of walkthrough:

| Symbol | Side | What it does |
|--------|------|---------------|
| `SEC("xdp")` | kernel (compile-time) | marks a function as an XDP program for libbpf to find |
| `SEC(".maps")` | kernel (compile-time) | marks a struct declaration as a BPF map for libbpf to create |
| `SEC("license")` | kernel (compile-time) | declares program license; gates access to GPL-only helpers |
| `struct xdp_md *ctx` | kernel | the XDP program's context: raw `data`/`data_end` pointers into the packet |
| `bpf_htons` / `bpf_ntohs` | kernel | host ↔ network byte-order conversion for multi-byte fields |
| `bpf_ktime_get_ns()` | kernel | monotonic kernel timestamp; the only clock source available in-program |
| `bpf_ringbuf_reserve()` | kernel | claim space in a ring-buffer map to write an event into |
| `bpf_ringbuf_submit()` | kernel | publish a reserved event so userspace consumers can see it |
| `bpf_ringbuf_discard()` | kernel | (not used here) abandon a reserved event without publishing it |
| `XDP_PASS` / `XDP_DROP` / ... | kernel | the program's return value; tells the kernel what to do with the packet |
| the BPF **verifier** | kernel (load-time) | statically proves every pointer access is bounds-checked before allowing the program to load |
| `xdp_logger_bpf__open_and_load()` | userspace | (generated) open the compiled object, create maps, load programs - this is where the verifier runs |
| `bpf_program__attach_xdp()` | userspace | attach a loaded program to a specific interface (by ifindex) |
| `bpf_map__fd()` | userspace | get the raw kernel fd for a map, from the typed skeleton handle |
| `ring_buffer__new()` | userspace | create a consumer for a ring-buffer map, registering a per-event callback |
| `ring_buffer__poll()` | userspace | block (with timeout) and dispatch any events that have arrived |
| `bpf_link__destroy()` | userspace | detach a program from wherever it was attached |
| `xdp_logger_bpf__destroy()` | userspace | (generated) unload programs, destroy maps, free the skeleton |
| `libbpf_set_print()` | userspace | redirect libbpf's internal logging (including verifier errors) to your own handler |
| `bpftool gen skeleton` | build-time | turn a compiled `.bpf.o` into a typed C header for the loader |

A useful mental model to carry forward: **everything in the left column of
"kernel" rows above is code the verifier scrutinizes before it's allowed
to run even once.** Everything in the userspace rows is ordinary,
unverified C - the verifier's guarantees stop exactly at the kernel/user
boundary this project's `packet_event.h` defines.

---

### 11. Exercises: extending the logger

The README already suggests a couple of tweaks; here they are as concrete
exercises, roughly in order of difficulty, each exercising a different
part of the API above:

1. **Add a packet counter map.** Declare a second map,
   `BPF_MAP_TYPE_ARRAY` with one entry, and increment it on every packet
   the program logs (`bpf_map_lookup_elem` + an atomic add, or
   `bpf_map__update_elem` from userspace to reset it). Print the total in
   the loader on exit. This introduces you to a map type that isn't
   ring-buffer-shaped - most BPF programs use several map types together.

2. **Filter before you reserve.** Right now every IPv4 packet costs a ring
   buffer reservation. Add a check - say, only log traffic on a specific
   port - *before* the `bpf_ringbuf_reserve()` call, and confirm with
   `make test TRAFFIC=udp` that non-matching traffic no longer produces
   log lines. This is the standard pattern for keeping a high-traffic XDP
   program cheap: filter early, pay the (relatively) expensive ring buffer
   cost only for traffic you actually care about.

3. **Turn the logger into a filter.** Change one `return XDP_PASS` to
   `return XDP_DROP` under some condition (e.g. `dst_port == 9123`). Rerun
   `make test TRAFFIC=udp` and confirm those packets vanish from
   `packets.log` *and* never reach the `nc` listener in
   `send-traffic.sh` - but notice they still show up faintly differently
   in the wireshark sidecar's capture, since `dumpcap` taps at a different
   point than XDP's drop decision. Reasoning about *where exactly* in the
   pipeline a drop takes effect is a core XDP skill.

4. **Add IPv6 support.** The program currently returns early on anything
   that isn't `ETH_P_IP`. Add a parallel branch using `struct ipv6hdr`
   (already included) and `ETH_P_IPV6`, and extend `packet_event` to carry
   16-byte addresses conditionally, or a separate event type. This is the
   exercise that will make you actually understand the bounds-check
   pattern in section 3.4, because you'll have to write it three more
   times from scratch under a different header layout.

---

# Part 2 - Capturing Postgres Wire Traffic with XDP

You've now seen the whole shape of a minimal XDP program: a map, a bounds-
checked parse, a ring buffer, and `XDP_PASS`. Part 2 reuses every one of
those ideas but points them at a harder, more realistic goal.

Where Part 1's `xdp_logger.bpf.c` **parsed** each packet down to a handful
of fixed fields (addresses, ports, length) and shipped a small fixed-size
`struct packet_event` to userspace, Part 2's `xdp_capture.bpf.c` does the
opposite: it copies the packet's **raw bytes** - Ethernet, IP, and TCP
headers plus payload, up to 4 KB - into the ring buffer untouched, and
lets a real protocol analyzer (Wireshark/tshark) do the parsing on the
userspace side. That single design choice ripples through the rest of the
project: the shared struct now embeds a byte array instead of scalar
fields, the verifier needs a bitmask idiom to prove a copy length is safe,
and the userspace loader's job shifts from "format a log line" to "write a
correct `.pcap` file byte-for-byte." It also moves from a veth pair
between two namespaces to the loopback interface, which means **generic**
XDP mode instead of native mode - one more axis Part 1 didn't need to
cover.

This part is a self-contained deep dive into **part2-postgres-sink** - a
demo that attaches an eBPF/XDP program to loopback, captures Postgres wire
traffic, writes it to a pcap file, and decodes the SQL queries using
Wireshark's built-in `pgsql` dissector. Read it the same way as Part 1:
top to bottom once, with `cd part2-postgres-sink && make demo` running
alongside it.

### 1. What we're building

The goal is simple to state:

> **See the actual SQL queries that a Postgres client sends, by capturing
> packets at the network layer - without modifying the client, the server, or
> the application.**

The tool that makes this possible is **XDP (eXpress Data Path)**, a Linux
kernel feature that lets you run a small BPF program on every packet that
hits a network interface, *before* it reaches the kernel's networking stack.
Our program:

- Intercepts packets to/from TCP port 5432 (Postgres)
- Copies them to a ring buffer
- Never drops or modifies anything (pure observer - `XDP_PASS`)

A userspace process drains the ring buffer and writes a standard pcap file.
Wireshark then decodes that pcap using its built-in Postgres protocol
dissector, giving us the SQL for free - no parsing on our side.

#### Why XDP and not tcpdump/libpcap?

| Approach         | Where it runs          | Overhead      | Visibility              |
|------------------|------------------------|---------------|-------------------------|
| `tcpdump`        | af_packet socket       | Copy per pkt  | After netif rx          |
| **XDP**          | **Driver/generic hook**| **No copy**   | **Before netif rx**     |
| kprobe on `tcp_recvmsg` | Kernel probe    | Probe overhead| Per-syscall             |

XDP is the earliest interception point. For a learning project it also
teaches you the eBPF toolchain: BPF maps, the verifier, ring buffers, and
object file loading.

#### The SSL caveat

Postgres wire traffic is plaintext **only if SSL is off**. The compose file
starts postgres with `POSTGRES_HOST_SSL_METHOD: disable`, and our capture
filter assumes plaintext. If the connection negotiates TLS, the captured
bytes are ciphertext and the dissector fails. For capturing real encrypted
traffic you'd need to hook into the TLS layer (e.g. via uprobes on OpenSSL)
or dump session keys - both far beyond this demo.

---

### 2. The big picture

Four Docker services, all sharing the host network namespace:

```
┌─────────────── host netns (network_mode: host) ──────────────┐
│                                                              │
│  db-client (psql) ──┐                        ┌── postgres    │
│                     │   both cross lo        │   (ssl=off)   │
│                     ├────────────────────────┤   :5432       │
│  XDP capture ───────┘   ingress + egress     └──────────────│
│  (writes pg_capture.pcap)                                    │
│                                                              │
│  tshark sidecar ────── idle; decodes pg_capture.pcap        │
│  (writes pg_decoded.txt on shutdown)                         │
└──────────────────────────────────────────────────────────────┘
```

Because everything shares `lo`, both directions of the client↔server
conversation cross the loopback interface - which is where the XDP program
attaches (in generic/driver-less mode).

| Service     | Image            | Job                                         |
|-------------|------------------|---------------------------------------------|
| `postgres`  | `postgres:16`    | The database, started with SSL off          |
| `capture`   | `bpf-pg-capture` | Builds + runs the XDP loader, writes pcap   |
| `wireshark` | `bpf-pg-wireshark` | Idle sidecar; decodes pcap to text on stop|
| `db-client` | `postgres:16`    | One-shot psql runner that generates traffic |

The file flow:

```
  packets on lo
       │
       ▼
  XDP program ──► ring buffer ──► capture_loader ──► output/pg_capture.pcap
                                                                  │
                                                                  ▼
                                                   tshark -V  (on shutdown)
                                                                  │
                                                                  ▼
                                                        output/pg_decoded.txt
```

---

### 3. The kernel side: the XDP capture program

**File: `bpf/xdp_capture.bpf.c`** (82 lines)

This is the BPF program - the code that runs inside the kernel on every
packet. Let's walk through it section by section.

#### 3.1 Headers and includes

```c
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "common.h"
```

The `<linux/*>` headers come from the kernel's UAPI headers (installed via
`linux-headers-amd64` in the Docker image). The `<bpf/*>` headers come from
libbpf-dev. `common.h` is our own shared header (covered in section 4).

You'll notice there is **no `<stdlib.h>`, no `<stdio.h>`** - BPF programs
run in a constrained environment with no libc. Every "function call" is
either a macro expansion or a call to a BPF helper function.

#### 3.2 The ring buffer map

```c
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22); // 4 MB
} events SEC(".maps");
```

This is a **BPF map** declared using the modern BTF-defined syntax (the
`SEC(".maps")` macro places it in a special ELF section that libbpf
recognizes). It's a **ring buffer** - a lock-free, memory-efficient,
multi-producer/single-consumer queue.

A ring buffer is the right choice here (vs. the older perf buffer) because:

- It has a single consolidated buffer (not per-CPU), so events are globally
  ordered.
- `bpf_ringbuf_reserve()` + `bpf_ringbuf_submit()` lets you write directly
  into the buffer without an intermediate copy - important when packets can
  be up to 4 KB.

The `1 << 22` (4 MB) size is a power of two (required), and is generous
enough that bursts of query/response traffic don't cause drops.

#### 3.3 The XDP program entry point

```c
SEC("xdp")
int xdp_capture_prog(struct xdp_md *ctx)
{
```

`SEC("xdp")` tells libbpf this is an XDP program. The `struct xdp_md *ctx`
is the context - for XDP it contains the packet data pointers.

#### 3.4 Parsing the packet headers (with bounds checks)

```c
void *data_end = (void *)(long)ctx->data_end;
void *data     = (void *)(long)ctx->data;

struct ethhdr *eth = data;
if ((void *)(eth + 1) > data_end)
    return XDP_PASS;
```

The `(long)` casts are idiomatic - `ctx->data` is `__u32`, but we need a
pointer. The cast goes through `long` to satisfy the verifier's pointer
arithmetic rules.

**Every** pointer dereference in a BPF program must be preceded by a bounds
check. The verifier statically proves you can't read past `data_end`. The
pattern `(ptr + 1) > data_end` checks that there's room for one full struct
of the pointer's type.

We then walk the headers:

```c
if (eth->h_proto != bpf_htons(ETH_P_IP))
    return XDP_PASS;                          // not IPv4

struct iphdr *ip = (void *)(eth + 1);
if ((void *)(ip + 1) > data_end)
    return XDP_PASS;

if (ip->protocol != IPPROTO_TCP)
    return XDP_PASS;                          // not TCP

struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
if ((void *)(tcp + 1) > data_end)
    return XDP_PASS;
```

Note `ip->ihl * 4` - the IP header length is in 32-bit words, so multiply by
4 to get bytes. This correctly skips IP options if present.

#### 3.5 The Postgres port filter

```c
__u16 sport = bpf_ntohs(tcp->source);
__u16 dport = bpf_ntohs(tcp->dest);

if (sport != PG_PORT && dport != PG_PORT)
    return XDP_PASS;
```

`bpf_ntohs` converts from network byte order (big-endian) to host byte
order. `PG_PORT` is `5432` (from `common.h`). We match on **either** source
or destination port so we see both directions:

- Client → server: destination port is 5432 (the query)
- Server → client: source port is 5432 (the result rows)

#### 3.6 Capture length clamping

```c
__u32 pkt_len = data_end - data;
__u32 cap_len = pkt_len > CAPTURE_LEN ? CAPTURE_LEN : pkt_len;
cap_len &= CAPTURE_MASK;
```

This looks redundant - why clamp with both a ternary and a bitmask? Because
of how the **BPF verifier** reasons about values.

The verifier tracks a known range for every variable. After the ternary,
`cap_len` is at most `CAPTURE_LEN`. But when we pass `cap_len` as the size
to `bpf_probe_read_kernel()`, the verifier needs `cap_len` to be **strictly
less than** the destination buffer size (`CAPTURE_LEN`). The bitmask
`cap_len &= (CAPTURE_LEN - 1)` makes the verifier see `cap_len` as bounded
by `[0, CAPTURE_LEN-1]` - a known-constant range - without changing the
value (since `cap_len <= CAPTURE_LEN` already means the high bit is clear).

This is a common BPF idiom for "re-assert a bound to the verifier."

#### 3.7 Reserving ring buffer space and copying

```c
struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
if (!e)
    return XDP_PASS;

e->pkt_len = pkt_len;
e->cap_len = cap_len;

bpf_probe_read_kernel(e->data, cap_len, data);

bpf_ringbuf_submit(e, 0);

return XDP_PASS;
```

Key points:

- `bpf_ringbuf_reserve()` returns a pointer to writable space in the ring
  buffer. If the buffer is full, it returns NULL - and we `XDP_PASS` because
  we never want to drop real traffic just because capture is backed up.
- `bpf_probe_read_kernel()` is a BPF helper that copies `cap_len` bytes from
  `data` (the packet) into `e->data` (the ring buffer slot). It handles
  source bounds checking internally, and the verifier trusts it for the
  destination because `cap_len` is clamped.
- We write the entire `struct event` (with the full Ethernet+IP+TCP+payload)
  so the resulting pcap is directly openable in Wireshark.

#### 3.8 The license

```c
char _license[] SEC("license") = "GPL";
```

The kernel checks this string. Many BPF helpers (including
`bpf_probe_read_kernel`) are GPL-only, so the program must declare `GPL`
license to use them.

---

### 4. The shared wire format

**File: `bpf/common.h`** (28 lines)

```c
#define PG_PORT 5432
#define CAPTURE_LEN 4096
#define CAPTURE_MASK (CAPTURE_LEN - 1)

struct event {
    __u32 pkt_len; // original packet length on the wire
    __u32 cap_len; // how many bytes of `data` are actually valid
    __u8 data[CAPTURE_LEN];
};
```

This header is `#include`d by **both** sides:

- `bpf/xdp_capture.bpf.c` (kernel) - defines what gets written
- `src/loader.c` (userspace) - defines what gets read

Having a single source of truth means you can never accidentally desync the
struct layout between kernel and userspace. Change `CAPTURE_LEN` here and
both sides recompile consistently.

The `CAPTURE_LEN` of 4096 is chosen as a power of two (required for the
bitmask trick in section 3.6) and is large enough for typical
query/response traffic. A huge `COPY` payload would be truncated, but the
first 4 KB is enough to see the query text.

---

### 5. The userspace loader

**File: `src/loader.c`** (162 lines)

This is a normal C program that:

1. Opens and loads the compiled BPF object file
2. Attaches the XDP program to an interface
3. Polls the ring buffer and writes each event to a pcap file
4. On Ctrl+C/SIGTERM, detaches and cleans up

#### 5.1 The pcap file format

We write the pcap file by hand - no libpcap dependency needed. The format
is simple: a 24-byte global header, then a 16-byte per-packet header +
packet data for each record.

```c
struct pcap_hdr {
    __u32 magic_number;   // 0xa1b2c3d4 - identifies this as pcap
    __u16 version_major;  // 2
    __u16 version_minor;  // 4
    __s32 thiszone;       // 0 (UTC)
    __u32 sigfigs;        // 0
    __u32 snaplen;        // max captured length (CAPTURE_LEN)
    __u32 network;        // 1 = LINKTYPE_ETHERNET
};
```

```c
struct pcaprec_hdr {
    __u32 ts_sec;   // timestamp seconds
    __u32 ts_usec;  // timestamp microseconds
    __u32 incl_len; // bytes actually captured (cap_len)
    __u32 orig_len; // original packet length on the wire (pkt_len)
};
```

The global header is written once at startup:

```c
struct pcap_hdr hdr = {
    .magic_number = 0xa1b2c3d4,
    .version_major = 2,
    .version_minor = 4,
    .snaplen = CAPTURE_LEN,
    .network = 1, // LINKTYPE_ETHERNET
};
fwrite(&hdr, sizeof(hdr), 1, outfile);
```

The magic number `0xa1b2c3d4` (native byte order) tells Wireshark/tcpdump
this is a pcap file (not pcapng, not big-endian pcap). `network = 1` means
the packets start with an Ethernet header - which they do, because our XDP
program copies from `data` which starts at the Ethernet header.

#### 5.2 Signal handling

```c
static void handle_sigint(int sig)
{
    (void)sig;
    stop = 1;
}

static void install_signal_handlers(void)
{
    struct sigaction sa = {0};
    sa.sa_handler = handle_sigint;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);  // docker compose down sends SIGTERM
    signal(SIGPIPE, SIG_IGN);
}
```

Two important details:

- **SIGTERM** is handled identically to SIGINT because `docker compose down`
  sends SIGTERM, not SIGINT. Without this, the loader would be killed
  without detaching the XDP program.
- **SIGPIPE** is ignored so a write to a closed pcap (e.g. disk full) doesn't
  terminate the process mid-capture.

#### 5.3 The ring buffer callback

```c
static int handle_event(void *ctx, void *data, size_t data_sz)
{
    struct event *e = data;
    struct pcaprec_hdr rec;
    struct timeval tv;

    gettimeofday(&tv, NULL);
    rec.ts_sec  = (__u32)tv.tv_sec;
    rec.ts_usec = (__u32)tv.tv_usec;
    rec.incl_len = e->cap_len;
    rec.orig_len = e->pkt_len;

    fwrite(&rec, sizeof(rec), 1, outfile);
    fwrite(e->data, 1, e->cap_len, outfile);
    fflush(outfile);

    packet_count++;
    return 0;
}
```

Every time the ring buffer has data, libbpf calls this function with a
pointer to the event. We wrap it in a pcap record header and write it out.
`fflush()` after every packet ensures that even if the process is killed
abruptly, the pcap is valid up to the last flushed record.

The timestamp is the **userspace receive time**, not the kernel capture
time. This is a simplification - for accurate timestamps you'd use
`bpf_ktime_get_ns()` in the BPF program and convert with
`clock_gettime(CLOCK_MONOTONIC)`.

#### 5.4 Loading and attaching

```c
struct bpf_object *obj = bpf_object__open_file("xdp_capture.bpf.o", NULL);
if (libbpf_get_error(obj)) { ... }

if (bpf_object__load(obj)) { ... }

struct bpf_program *prog = bpf_object__find_program_by_name(obj, "xdp_capture_prog");
int prog_fd = bpf_program__fd(prog);

if (bpf_xdp_attach(ifindex, prog_fd, 0, NULL) < 0) { ... }
```

Three steps:

1. **Open** - parse the ELF object file, find the program and map
   definitions. No kernel interaction yet.
2. **Load** - create the maps in the kernel, load the bytecode, run the
   verifier. If the verifier rejects the program, this fails.
3. **Attach** - hook the program to a network interface's XDP hook.

Note we open `"xdp_capture.bpf.o"` by relative path. The CMake build copies
the `.o` file next to the loader binary (see section 6), and the
entrypoint runs the loader from `/app` where both files live.

#### 5.5 The main loop and cleanup

```c
while (!stop) {
    ring_buffer__poll(rb, 100 /* ms timeout */);
}

printf("\ndetaching and closing %ld packets captured\n", packet_count);
bpf_xdp_attach(ifindex, -1, 0, NULL);  // -1 fd = detach
ring_buffer__free(rb);
bpf_object__close(obj);
fclose(outfile);
```

`ring_buffer__poll()` with a 100ms timeout means we wake up 10 times per
second even when there's no traffic - this ensures the `stop` flag is
checked promptly. On exit, we detach by passing `-1` as the program fd.

---

### 6. How BPF code is compiled

**File: `CMakeLists.txt`** (46 lines)

This is where many people get stuck, so let's be thorough.

#### 6.1 Two compilers, two targets

The build produces **two** artifacts from **two** compilers:

| Artifact               | Compiler       | Target architecture |
|------------------------|----------------|---------------------|
| `xdp_capture.bpf.o`    | `clang -target bpf` | BPF bytecode    |
| `capture_loader`       | `gcc`          | x86_64 (host)       |

The BPF program is compiled to **BPF bytecode**, not x86 machine code. The
kernel's JIT translates it to native code at load time. This is why we need
`clang` with the `bpf` target - `gcc` can't (traditionally) produce BPF
bytecode.

#### 6.2 The BPF object compilation

```cmake
find_program(CLANG_BIN clang REQUIRED)

set(BPF_SRC ${CMAKE_CURRENT_SOURCE_DIR}/bpf/xdp_capture.bpf.c)
set(BPF_OBJ ${CMAKE_CURRENT_BINARY_DIR}/xdp_capture.bpf.o)

add_custom_command(
    OUTPUT ${BPF_OBJ}
    COMMAND ${CLANG_BIN}
        -O2 -g -target bpf -I/usr/include/x86_64-linux-gnu
        -c ${BPF_SRC} -o ${BPF_OBJ}
    DEPENDS ${BPF_SRC} ${CMAKE_CURRENT_SOURCE_DIR}/bpf/common.h
    COMMENT "Compiling xdp_capture.bpf.c -> BPF bytecode"
    VERBATIM
)
add_custom_target(pg_bpf_object ALL DEPENDS ${BPF_OBJ})
```

Breaking down the flags:

- **`-O2`** - optimize. The verifier can reject unoptimized BPF code due to
  instruction count limits.
- **`-g`** - include debug info (DWARF/BTF). This lets `bpftool` and the
  verifier produce human-readable error messages.
- **`-target bpf`** - compile for the BPF instruction set, not the host CPU.
- **`-I/usr/include/x86_64-linux-gnu`** - find the architecture-specific
  kernel headers. Without this, `<asm/types.h>` won't be found.

The `add_custom_target` + `add_custom_command` pattern is how you tell
CMake "this file is produced by a custom command, not by a normal
compiler."

#### 6.3 The userspace loader

```cmake
add_executable(capture_loader src/loader.c)
add_dependencies(capture_loader pg_bpf_object)
target_include_directories(capture_loader PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/bpf     # common.h
    ${LIBBPF_INCLUDE_DIRS})
target_link_libraries(capture_loader PRIVATE PkgConfig::LIBBPF elf z)
```

- `add_dependencies(capture_loader pg_bpf_object)` ensures the `.o` is built
  before the loader.
- `target_include_directories(... bpf)` lets `loader.c` `#include "common.h"`
  from the `bpf/` directory.
- `PkgConfig::LIBBPF` links libbpf (discovered via pkg-config).
- `elf` and `z` (zlib) are libbpf's dependencies for reading ELF object
  files.

#### 6.4 Copying the object file next to the binary

```cmake
add_custom_command(TARGET capture_loader POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy ${BPF_OBJ} $<TARGET_FILE_DIR:capture_loader>
)
```

This is critical because `loader.c` opens `"xdp_capture.bpf.o"` as a
**relative path** at runtime. CMake puts the loader binary in
`${CMAKE_RUNTIME_OUTPUT_DIRECTORY}` (the `build/` dir), so we copy the `.o`
there too. Now `cd build && ./capture_loader lo out.pcap` works.

---

### 7. The Docker build

**File: `Dockerfile.core`** (47 lines)

We use a **multi-stage build** to keep the final image small.

#### 7.1 Build stage

```dockerfile
FROM debian:bookworm-slim AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
    clang llvm libbpf-dev libelf-dev pkg-config cmake make gcc \
    linux-headers-amd64 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

RUN cmake -B build . && cmake --build build -j
```

This installs the full build toolchain and compiles both the BPF object and
the loader. Note `linux-headers-amd64` - this provides the kernel headers
that `bpf/xdp_capture.bpf.c` includes.

#### 7.2 Runtime stage

```dockerfile
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libbpf1 libelf1 iproute2 postgresql-client \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=build /src/build/capture_loader ./capture_loader
COPY --from=build /src/build/xdp_capture.bpf.o ./xdp_capture.bpf.o
COPY scripts/capture-entrypoint.sh ./scripts/capture-entrypoint.sh
RUN chmod +x ./scripts/capture-entrypoint.sh

ENTRYPOINT ["/app/scripts/capture-entrypoint.sh"]
```

The runtime image has:

- `libbpf1`, `libelf1` - shared libraries the loader links against
- `iproute2` - for `ip link` (used in the cleanup trap to detach XDP)
- `postgresql-client` - for `pg_isready` and `psql` (the startup probe)

No compiler, no headers, no build tools - just what's needed to run.

---

### 8. Docker Compose orchestration

**File: `docker-compose.yml`** (140 lines)

#### 8.1 The postgres service

```yaml
postgres:
  image: postgres:16
  network_mode: host
  environment:
    POSTGRES_DB: ${POSTGRES_DB:-packets}
    POSTGRES_USER: ${POSTGRES_USER:-packets}
    POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:-packets}
    POSTGRES_HOST_SSL_METHOD: disable
  volumes:
    - pgdata:/var/lib/postgresql/data
  healthcheck:
    test: ["CMD-SHELL", "pg_isready -U ${POSTGRES_USER:-packets}"]
    interval: 5s
    timeout: 3s
    retries: 10
```

Key points:

- **`network_mode: host`** - the container shares the host's network
  namespace. This is critical: it means postgres's traffic on port 5432
  crosses the host's `lo` interface, where the XDP program is attached.
- **`POSTGRES_HOST_SSL_METHOD: disable`** - forces plaintext protocol so
  the capture is decodable.
- **`healthcheck`** - other services `depends_on` this with
  `condition: service_healthy`, so they don't start until postgres is ready.

#### 8.2 The capture service

```yaml
capture:
  build: { context: ., dockerfile: Dockerfile.core }
  privileged: true
  network_mode: host
  stop_grace_period: 5s
  init: true
  volumes:
    - /sys/kernel/debug:/sys/kernel/debug:ro
    - /sys/fs/bpf:/sys/fs/bpf
    - ./output:/work/output
  environment:
    IFACE: "lo"
    LOG: "/work/output/pg_capture.pcap"
```

- **`privileged: true`** - loading BPF programs and attaching XDP requires
  elevated privileges. For production you'd instead grant specific
  capabilities: `CAP_BPF`, `CAP_NET_ADMIN`, `CAP_NET_RAW`, `CAP_SYS_ADMIN`.
- **`/sys/fs/bpf`** - the BPF filesystem, where pinned maps live.
- **`/sys/kernel/debug`** - needed by some BPF tooling.
- **`stop_grace_period: 5s`** - gives the entrypoint's SIGTERM trap time to
  detach XDP before Docker sends SIGKILL.
- **`init: true`** - uses an init process (tini) so signals are forwarded
  correctly to the entrypoint.

#### 8.3 The wireshark sidecar

```yaml
wireshark:
  build: { context: ., dockerfile: Dockerfile.wireshark }
  init: true
  stop_grace_period: 5s
  volumes:
    - ./output:/work/output
```

This container does **not** capture anything. It sits idle until SIGTERM,
then decodes `pg_capture.pcap` to `pg_decoded.txt`. It's a separate image
because tshark and its dependencies (libwiretap, etc.) are heavy (~400 MB)
and we don't want them in the privileged capture image.

#### 8.4 The db-client

```yaml
db-client:
  image: postgres:16
  network_mode: host
  profiles: ["manual"]
  command: >
    psql -v ON_ERROR_STOP=1
      -c "SELECT 'db-client start', now();"
      -c "CREATE TABLE IF NOT EXISTS demo (...);"
      -c "INSERT INTO demo (note) VALUES (...);"
      ...
```

- **`profiles: ["manual"]`** - this service is NOT started by `docker
  compose up`. It only runs when explicitly invoked via
  `docker compose run --rm db-client` (which `make traffic` does).
- It runs a handful of varied queries (DDL, INSERT, SELECT) so the capture
  has interesting protocol messages to decode.

---

### 9. The entrypoint scripts

#### 9.1 capture-entrypoint.sh

**File: `scripts/capture-entrypoint.sh`** (111 lines)

This is the in-container entrypoint for the capture service. Its lifecycle:

```
docker compose up  →  wait for pg ready
                    →  run capture_loader (attaches XDP)
                    →  probe: SELECT 1
                    →  stream packet count forever

docker compose down →  SIGTERM
                    →  trap: kill loader, detach XDP, fix perms
```

That "wait for pg ready" step is doing more work than the diagram lets
on, and it's worth walking through the script's numbered steps in order,
since this is where most of the actual demo setup logic lives.

##### Step 1: block until Postgres will actually accept connections

```bash
log "Waiting for postgres at ${PG_HOST}:${PG_PORT} ..."
for i in $(seq 1 60); do
    if pg_isready -h "${PG_HOST}" -p "${PG_PORT}" -U "${PG_USER}" -d "${PG_DB}" >/dev/null 2>&1; then
        echo "    postgres is ready"
        break
    fi
    sleep 0.5
done
if ! pg_isready -h "${PG_HOST}" -p "${PG_PORT}" -U "${PG_USER}" -d "${PG_DB}" >/dev/null 2>&1; then
    echo "ERROR: postgres never became ready after 30s" >&2
    exit 1
fi
```

Docker Compose's own `depends_on` only guarantees the postgres
*container* has started, not that the database inside it is accepting
connections yet - initdb, WAL replay, and Postgres's own startup can all
take a moment. This polls `pg_isready` every 0.5s for up to 60 tries (30s
total) before giving up. Attaching XDP and generating traffic before
Postgres is actually listening would mean capturing nothing (or a
connection-refused burst) instead of a real session - this loop is what
makes the demo reliable across different machines and cold-start times.

##### Step 2: use the prebuilt binary, don't compile here

```bash
mkdir -p "${OUTPUT_DIR}"
cd /app
if [[ ! -x ./capture_loader || ! -f ./xdp_capture.bpf.o ]]; then
    echo "ERROR: capture_loader or xdp_capture.bpf.o missing under /app" >&2
    exit 1
fi
```

Unlike Part 1 (which compiles on every `up`, from inside the running
container - see section 7 there), Part 2's runtime image is compiled
once in the Docker **build** stage (section 7.1) and only the finished
`capture_loader` binary and `xdp_capture.bpf.o` object are copied into
the slim runtime image. This entrypoint doesn't build anything; it just
sanity-checks that the expected artifacts actually made it into the
image before trying to run them, and fails fast with a clear message if
not, rather than hitting a confusing "command not found" further down.

##### Step 3: attach XDP and start the loader

```bash
log "Attaching XDP capture to ${IFACE}; writing to ${LOG}"
: > "${LOG}"   # truncate so each `up` starts a fresh capture
fix_perms      # hand the (fresh, empty) pcap to the host user up front
./capture_loader "${IFACE}" "${LOG}" &
CAP_PID=$!
sleep 1        # let it attach before we generate traffic
```

The `: > "${LOG}"` truncates any pcap left over from a previous run, so
`output/pg_capture.pcap` never accumulates packets across multiple `make
demo` invocations. `capture_loader` runs in the background (`&`) so the
script can continue to the probe step below; the `sleep 1` is a small,
deliberate race-avoidance measure - giving the XDP program time to
actually attach before any traffic is generated, so the probe query in
step 4 is guaranteed to be captured rather than possibly racing the
attach.

##### Step 4: generate a guaranteed-present probe query

```bash
log "Probing: SELECT 1"
PGPASSWORD="${PG_PASSWORD}" psql -h "${PG_HOST}" -p "${PG_PORT}" -U "${PG_USER}" -d "${PG_DB}" \
    -c "SELECT 1 AS probe;" >/dev/null 2>&1 || echo "    (probe query failed - capture still running)"
```

Even if you never run `db-client` at all, this guarantees the pcap
contains at least one real Postgres session (including the SSL
negotiation and startup handshake described earlier in this section) -
useful for confirming the whole pipeline works before worrying about
your own queries.

##### Step 5: stream or exit

```bash
log "Streaming capture (stop with: docker compose down)"
wait "${CAP_PID}" 2>/dev/null || true
```

By default the script blocks here, keeping the container (and the XDP
attachment) alive until `docker compose down` sends `SIGTERM`. Setting
`EXIT_AFTER_PROBE=1` skips straight to printing where the capture was
written and exiting - handy for scripted, one-shot runs that don't need
the container to stay up.

##### The cleanup trap

```bash
cleanup() {
    [[ "${CLEANING}" -eq 1 ]] && return   # guard against double-invocation
    CLEANING=1
    log "Cleaning up: stopping capture, detaching XDP from ${IFACE}..."
    [[ -n "${CAP_PID}" ]] && kill "${CAP_PID}" 2>/dev/null || true
    wait 2>/dev/null || true
    ip link set dev "${IFACE}" xdpgeneric off 2>/dev/null || true
    fix_perms
}
trap cleanup EXIT INT TERM
```

Belt-and-braces: even though `capture_loader` detaches XDP on clean exit,
we also run `ip link ... xdpgeneric off` in case the loader was
force-killed. The `CLEANING` guard prevents the trap from running twice
(EXIT fires after TERM). Note the comment above `IFACE` in the script's
header: since this is generic-mode XDP on `lo` (see "Why one project
needs a fake network and the other doesn't" for why), a failed attach
with `-EINVAL` on an older kernel is a real possibility the script's
authors call out explicitly - the fallback in that case is rebinding the
demo to a real veth pair the way Part 1 does, not a bug in this script.

##### Permission fixing

```bash
fix_perms() {
    [[ -d "${OUTPUT_DIR}" ]] && chown -R "${HOST_UID}:${HOST_GID}" "${OUTPUT_DIR}" 2>/dev/null || true
}
```

The container runs as root, so files written to the bind-mounted
`./output/` dir are root-owned. `fix_perms` chowns them back to the host
user's UID/GID (passed in via environment) so you can `rm`/`git`/edit them
without sudo.

#### 9.2 wireshark-entrypoint.sh

**File: `scripts/wireshark-entrypoint.sh`** (92 lines)

This is the decode sidecar. It's simpler:

```bash
cleanup() {
    [[ "${CLEANING}" -eq 1 ]] && return
    CLEANING=1
    decode
    fix_perms
}
trap cleanup EXIT INT TERM

# Block forever until SIGTERM
while true; do
    sleep 3600 &
    wait $!
done
```

The `decode()` function (shown earlier) runs `tshark -r ... -V` into a temp
file, then atomically renames on success. The atomic temp+rename pattern
means a SIGKILL mid-decode can't corrupt a previous good decode.

---

### 10. The tshark decode sidecar

**File: `Dockerfile.wireshark`** (19 lines)

```dockerfile
FROM ubuntu:24.04

RUN apt-get update && apt-get install -y --no-install-recommends tshark \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /work
COPY scripts/wireshark-entrypoint.sh /work/scripts/wireshark-entrypoint.sh
RUN chmod +x /work/scripts/wireshark-entrypoint.sh

CMD ["/work/scripts/wireshark-entrypoint.sh"]
```

Just tshark on Ubuntu. The decode happens on shutdown via the entrypoint
trap.


The Makefile exposes some tshark invocations:

**Full verbose decode** (used by `make down` and `make decode`):
```bash
tshark -r /work/output/pg_capture.pcap -V
```
- `-r <file>` - read from pcap (no live capture)
- `-V` - verbose: full protocol tree decode per packet

**SQL extraction** (`make sql`):
```bash
tshark -r /work/output/pg_capture.pcap \
    -Y pgsql.query \
    -T fields -e pgsql.query
```
- `-Y pgsql.query` - display filter: only Postgres Query messages
- `-T fields` - output format: field values only
- `-e pgsql.query` - extract the SQL text field


`pgsql.query` isn't a parameter with options - it's a single named field
exposed by Wireshark's `pgsql` dissector, holding the raw SQL text of a
Postgres **Simple Query** message (the `'Q'` message type). Both uses
above lean on the same fact about it:

- As a **display filter** (`-Y pgsql.query`, no comparison operator),
  it's a field-existence test: "only show packets where this field is
  present." Since only Query messages populate it, this doubles as "only
  show Query packets" - every handshake, auth, and row-description packet
  gets filtered out.
- As a **field extractor** (`-e pgsql.query`, with `-T fields`), it tells
  tshark to print just that field's value instead of a full packet
  dissection - which is why `make sql`'s output is clean SQL text, one
  query per line, with no headers or hex alongside it.

It's one field among many in the `pgsql.*` namespace (defined in
Wireshark's `epan/dissectors/packet-pgsql.c`). The ones you'll actually
see values for in this demo's traffic:

| Field | What it holds |
|---|---|
| `pgsql.type` | The message type character (`Q`, `P`, `T`, `D`, `C`, `Z`, ...) |
| `pgsql.length` | The message's declared length |
| `pgsql.query` | SQL text (Simple Query messages only) |
| `pgsql.authtype` | Authentication method code, in `AuthenticationRequest` messages |
| `pgsql.status` | Transaction status byte in `ReadyForQuery` (`I`=idle, `T`=in transaction, `E`=failed transaction) |
| `pgsql.message` | Human-readable text in error/notice responses |
| `pgsql.parameter_name` / `pgsql.parameter_value` | Server parameter reports sent during startup (e.g. `server_version`, `TimeZone`) |
| `pgsql.field.name` | Column name, inside `RowDescription` messages |

You can combine several with multiple `-e` flags to build a richer table
than `make sql` gives you - for example, every Postgres message (not just
queries), with its type and transaction status alongside any query text:

```bash
docker exec bpf-pg-wireshark tshark -r /work/output/pg_capture.pcap \
    -Y pgsql \
    -T fields -e frame.number -e pgsql.type -e pgsql.query -e pgsql.status \
    -E separator='|'
```

**Filtered verbose decode** (`make decode FILTER="pgsql"`):
```bash
tshark -r /work/output/pg_capture.pcap -Y pgsql -V
```

#### How to read `pg_decoded.txt`

`pg_decoded.txt` is nothing more than the redirected output of `tshark -V`
(command 1 above). For **every packet** in the capture, tshark prints the
full protocol tree as indented plain text, from the Ethernet frame down to
the Postgres application layer:

```
Frame 42: 187 bytes on wire (1496 bits), 187 bytes captured on interface lo
Ethernet II, Src: ..., Dst: ...
Internet Protocol Version 4, Src: 127.0.0.1, Dst: 127.0.0.1
Transmission Control Protocol, Src Port: 54012, Dst Port: 5432, Len: 121
PostgreSQL
    Type: Query
    Length: 45
    Query: SELECT id, note, ts FROM demo ORDER BY id DESC LIMIT 5;
```

Skim past Ethernet/IP/TCP (always the same on loopback) straight to the
`PostgreSQL` block, and scan its `Type` field - that's the Postgres wire
protocol's own message framing, and it's the thing worth knowing by name:

| `Type` | Direction | What it means |
|---|---|---|
| `Startup Message` | client → server | Initial handshake: protocol version, username, database |
| `Authentication Request` | server → client | Auth challenge/response |
| `Query` | client → server | The actual SQL text being sent (simple query protocol) |
| `Row Description` | server → client | Column names/types for an upcoming result set |
| `Data Row` | server → client | One row of query results |
| `Command Complete` | server → client | Result summary, e.g. `SELECT 5` |
| `Ready For Query` | server → client | Server is idle and ready for the next command |

Two things to keep in mind while reading it:

- **Packets are in wire order, not grouped by query.** TCP can split one
  logical Postgres message across several `Frame N` blocks, and
  request/response traffic interleaves. You're reading a chronological
  trace, not a clean transcript - this is exactly the gap `make sql`
  closes, by throwing away every layer except `pgsql.query` and printing
  just the SQL strings back to back (see command 2 above).
- **Jump by `Frame` number, filter by message type.** To scan the file
  quickly: `grep -n "^Frame" pg_decoded.txt` lists every packet boundary
  with its line number; `grep -A 5 "Type: Query" pg_decoded.txt` pulls out
  just the query blocks with a bit of surrounding context.

#### Recognizing the handshake before the first `Query`

If you open the capture in a viewer that doesn't have a Postgres
dissector at all (a generic pcap/hex viewer, rather than Wireshark or
tshark), the first few data-carrying packets look like meaningless bytes - and it's easy to conclude the capture is broken or that no SQL was
sent. It isn't broken; you're just looking at the handshake that always
precedes any SQL. In order, on the wire:

1. **The three-way TCP handshake** (`SYN`, `SYN,ACK`, `ACK`) - no
   Postgres bytes at all yet, ignore these.
2. **`SSLRequest`** - the very first payload-carrying packet. It's
   exactly 8 bytes: a 4-byte length field (`00 00 00 08`) followed by the
   fixed magic number `04 D2 16 2F` (decimal `80877103`, which decodes to
   `(1234 << 16) | 5679`). This is the client asking "can we negotiate
   SSL before I send anything real?" - it's part of the Postgres wire
   protocol's startup phase, defined long before any query can be sent.
3. **The server's one-byte answer** - a single `N` (`0x4E`, "no SSL") or
   `S` (`0x53`, "yes, switch to TLS now"). This demo runs with
   `POSTGRES_HOST_SSL_METHOD` set to disable TLS (see the "SSL caveat" in
   section 1), so you'll always see `N` here - which is exactly what
   makes the rest of the traffic readable at all. If your viewer shows
   `S` here instead, everything after this point is TLS-encrypted and
   there is no plaintext SQL left to find in this pcap.
4. **The plaintext `Startup Message`** - protocol version plus
   parameters like `user` and `database`, still not SQL.
5. **A short authentication exchange** - minimal in this demo, since the
   compose file uses `trust` auth (no password challenge to decode).
6. **Finally, the first `Query` message** - look for a payload byte
   `0x51` (ASCII `'Q'`) followed by a 4-byte length, followed by the SQL
   text itself, null-terminated, in plain ASCII. This is the packet
   where a hex/ASCII dump will show something directly readable, like
   `SELECT 1 AS probe;`.

The fastest way to find it without a Postgres-aware tool: scan the ASCII
column of your hex dump for SQL keywords (`SELECT`, `CREATE`, `INSERT`) -
with SSL off, they sit in the payload as plain, uninterrupted text, no
decoding required. If you never find them, check step 3 above first -
you may be looking at a capture where the server answered `S` (SSL
accepted) rather than `N`.

**References:**

- [tshark(1) man page](https://www.wireshark.org/docs/man-pages/tshark.html) - full flag reference, including `-V`, `-Y`, `-T fields`, `-e`
- [Wireshark PostgreSQL dissector wiki](https://wiki.wireshark.org/PostgreSQL) - which fields the `pgsql` dissector exposes (`pgsql.query`, `pgsql.type`, etc.)
- [PostgreSQL frontend/backend protocol reference](https://www.postgresql.org/docs/current/protocol.html) - the authoritative spec for every message type (`Query`, `RowDescription`, `DataRow`, `ReadyForQuery`, and the rest) tshark is decoding
- [PostgreSQL protocol message formats](https://www.postgresql.org/docs/current/protocol-message-formats.html) - byte-level layout of each message, useful once you want to go past tshark's decode and read the raw pcap yourself
- [PostgreSQL SSL/TLS support and the `SSLRequest` negotiation](https://www.postgresql.org/docs/current/protocol-flow.html#PROTOCOL-FLOW-SSL) - the exact handshake step 2-3 above are describing
- [Wireshark User's Guide - Filtering while capturing/reading](https://www.wireshark.org/docs/wsug_html_chunked/ChWorkBuildDisplayFilterSection.html) - background on the `-Y` display-filter syntax used throughout this section

---

### 11. The Makefile

**File: `Makefile`** (~200 lines)

The Makefile is pure orchestration - it only ever calls `docker compose` and
`docker exec`, never the compiler directly. The build happens inside the
container.

#### Key targets

| Target        | What it does                                           |
|---------------|--------------------------------------------------------|
| `make demo`   | One-shot: up → traffic → show SQL → decode → down      |
| `make up`     | Start all services in the foreground                   |
| `make up-d`   | Start all services detached                            |
| `make traffic`| Run the db-client to generate queries                  |
| `make sql`    | Print all captured SQL queries (needs running stack)   |
| `make down`   | Stop services (decodes pcap first)                     |
| `make decode` | Decode the pcap to stdout or `pg_decoded.txt`          |
| `make clean`  | Stop + remove output artifacts (keeps DB volume)       |
| `make nuke`   | Stop + delete the DB volume (fresh DB next time)       |

#### The demo target

```makefile
demo: ## One-shot: up -> generate traffic -> show SQL -> decode -> down.
	@echo "==> [1/5] Starting services..."
	@$(COMPOSE) up --build -d >/dev/null 2>&1
	@echo "==> [2/5] Waiting for capture service to attach XDP..."
	@for i in $$(seq 1 60); do \
		if docker logs $(CTR_CAPTURE) 2>&1 | grep -q "Streaming capture"; then break; fi; \
		sleep 1; \
	done
	@echo "==> [3/5] Generating Postgres traffic (7 queries)..."
	@$(COMPOSE) run --rm db-client >/dev/null 2>&1 || true
	@echo "==> [4/5] Captured SQL queries:"
	@docker exec $(CTR_WIRESHARK) tshark -r /work/output/pg_capture.pcap \
		-Y pgsql.query -T fields -e pgsql.query 2>/dev/null | sed 's/^/    /'
	@echo "==> [5/5] Decoding and shutting down..."
	@$(MAKE) --no-print-directory down >/dev/null 2>&1
```

This is the end-to-end smoke test. It waits for the capture service to
print "Streaming capture" (its ready signal) before generating traffic,
ensuring the XDP program is attached.

---

### 12. End-to-end walkthrough

Let's trace what happens when you run `make demo`:

#### Step 1: Build and start

```
docker compose up --build -d
```

Docker builds two images:
- `bpf-pg-capture` (from Dockerfile.core): compiles the BPF program and
  loader in a build stage, copies the artifacts to a slim runtime image.
- `bpf-pg-wireshark` (from Dockerfile.wireshark): tshark on Ubuntu.

Three containers start: `postgres`, `capture`, `wireshark`.

#### Step 2: capture-entrypoint runs

Inside the `capture` container:

1. **Wait for postgres** - polls `pg_isready` every 0.5s up to 30s.
2. **Run the loader** - `./capture_loader lo /work/output/pg_capture.pcap &`
   - Opens `xdp_capture.bpf.o`, loads it into the kernel
   - Attaches the XDP program to `lo`
   - Writes the pcap global header
   - Polls the ring buffer, writing each packet as a pcap record
3. **Probe** - runs `SELECT 1` so we know the capture will have at least
  one query.
4. **Wait** - `wait $CAP_PID` keeps the container alive.

#### Step 3: Traffic is generated

`docker compose run --rm db-client` executes 7 psql queries:

```sql
SELECT 1 AS probe;
SELECT 'db-client start', now();
CREATE TABLE IF NOT EXISTS demo (id serial PRIMARY KEY, note text, ...);
INSERT INTO demo (note) VALUES ('hello from db-client'), ('another row'), ('third');
SELECT id, note, ts FROM demo ORDER BY id DESC LIMIT 5;
SELECT count(*) AS total FROM demo;
SELECT 'db-client done', now();
```

Each query and its result cross `lo` twice (request and response), and the
XDP program captures all of it.

#### Step 4: Inside the kernel

For each packet on `lo`:

1. The XDP program runs.
2. It parses Ethernet → IP → TCP headers with bounds checks.
3. If source or dest port is 5432, it copies up to 4096 bytes into the ring
   buffer.
4. It returns `XDP_PASS` - the packet continues to the kernel networking
   stack normally.

The loader's `handle_event` callback fires for each ring buffer entry,
writing a pcap record to disk.

#### Step 5: SQL extraction

```bash
docker exec bpf-pg-wireshark tshark -r /work/output/pg_capture.pcap \
    -Y pgsql.query -T fields -e pgsql.query
```

tshark reads the pcap, applies the `pgsql` dissector to each packet, and
extracts the query text from every Query message:

```
SELECT 1 AS probe;
SELECT 'db-client start', now();
CREATE TABLE IF NOT EXISTS demo (id serial PRIMARY KEY, note text, ts timestamptz DEFAULT now());
INSERT INTO demo (note) VALUES ('hello from db-client'), ('another row'), ('third');
SELECT id, note, ts FROM demo ORDER BY id DESC LIMIT 5;
SELECT count(*) AS total FROM demo;
SELECT 'db-client done', now();
```

#### Step 6: Shutdown and decode

`make down` runs `docker compose down`, which:

1. **Stops `capture` first** (in the `down` target) so the pcap is flushed.
2. **Decodes** the pcap using the still-running wireshark sidecar:
   ```bash
   tshark -r /work/output/pg_capture.pcap -V > /work/output/pg_decoded.txt
   ```
3. **Brings everything down** - the wireshark sidecar's EXIT trap also
   decodes (atomic temp+rename so it can't corrupt the file).

Final artifacts:

```
output/pg_capture.pcap   (5.8 KB)  - open in Wireshark GUI
output/pg_decoded.txt    (204 KB)  - full verbose text decode
```

---

### 13. Key concepts and gotchas

#### 13.1 The BPF verifier

The verifier is the kernel component that statically analyzes your BPF
program before allowing it to load. It checks:

- **No out-of-bounds accesses** - every pointer dereference must be preceded
  by a bounds check it can prove.
- **No infinite loops** - the program must terminate (bounded loops are now
  allowed, but historically all loops had to be unrollable).
- **Instruction limit** - historically 4096 instructions, now 1 million.

Our `cap_len &= CAPTURE_MASK` trick (section 3.6) is a direct consequence
of how the verifier reasons about value ranges.

#### 13.2 XDP generic vs. native vs. offload

XDP has three attach modes:

| Mode       | Where it runs         | Loopback support |
|------------|-----------------------|------------------|
| **Generic** (`xdpgeneric`) | Early in netif rx | Yes (modern kernels) |
| **Native** (`xdpdrv`)      | In the NIC driver | No (lo has no driver) |
| **Offload** (`xdpoffload`) | On the NIC itself | No |

We use generic mode because we're attaching to `lo`, which has no NIC
driver. Native mode gives better performance but requires a real interface.

#### 13.3 Ring buffer vs. perf buffer

The older `BPF_MAP_TYPE_PERF_EVENT_ARRAY` (perf buffer) has one buffer per
CPU. Events from different CPUs can interleave unpredictably. The newer
`BPF_MAP_TYPE_RINGBUF` (used here) has a single shared buffer with proper
ordering - better for correlating request/response traffic.

#### 13.4 Why we write pcap by hand

libpcap would add a dependency and complexity. The pcap format is trivial
(24-byte header + per-packet records), so writing it directly keeps the
loader minimal and dependency-free. The loader links only against libbpf,
libelf, and zlib.

#### 13.5 The atomic rename pattern

Both entrypoint scripts use the temp-file-then-rename pattern:

```bash
tshark ... > "${DECODED_FILE}.tmp.$$"
mv -f "${DECODED_FILE}.tmp.$$" "${DECODED_FILE}"
```

This ensures that a SIGKILL mid-write can't leave a truncated/partial file.
The previous good file (if any) remains intact until the rename succeeds.

#### 13.6 HOST_UID / HOST_GID and the permission lifecycle

Docker containers run as root by default, so any file they create inside a
bind-mounted `output/` directory ends up root-owned on the host - and
`rm output/packets.log` starts demanding `sudo`. Both projects' main
loader entrypoints (`core-entrypoint.sh`, `capture-entrypoint.sh`) fix
this by calling `fix_perms` at three points:

1. **Immediately on startup**, before anything else runs - so the output
   directory is host-owned from the very first line of the script, even
   before the veth pair/namespace (Part 1) or the postgres-readiness wait
   (Part 2) begins.
2. **Right after truncating the output file** (`: > "${LOG}"`), before the
   loader is started - so the freshly emptied file is re-handed to the
   host user immediately, in case truncation reset its ownership.
3. **In the cleanup trap**, as the last step before exit - so the final,
   fully populated file is chowned once more just before the container
   goes away.

```bash
fix_perms() {
    [[ -d "${OUTPUT_DIR}" ]] && chown -R "${HOST_UID}:${HOST_GID}" "${OUTPUT_DIR}" 2>/dev/null || true
}
log "Fixing output permissions (${HOST_UID}:${HOST_GID})..."
fix_perms
```

The wireshark sidecars call `fix_perms` at **two** of those three points -
early on startup and again in their cleanup trap - but skip the
"after truncating" call, since neither sidecar truncates its own output
file the way the main loaders do.

That early chown has a side effect worth tracing through for Part 1's
sidecar specifically. Because `fix_perms` now runs *before* `dumpcap`
ever starts, the bind-mounted output directory is already host-owned by
the time capture begins - and `dumpcap` has dropped the `CAP_DAC_OVERRIDE`
capability as a hardening measure, so even running as root it's held to
normal Unix permission rules, same as any unprivileged process. A root
process without that capability can't create a file inside a directory
it doesn't own. So `wireshark-entrypoint.sh` doesn't have `dumpcap` write
into the (now host-owned) output directory at all - it captures to
`/tmp/capture_tmp.pcap` instead, which is inside the container's own
writable layer and untouched by the early chown:

```bash
rm -f "${CAPTURE_FILE}" "${TMP_CAPTURE}"
dumpcap -i "${VETH0}" -q -w "${TMP_CAPTURE}" &
```

Then, in the cleanup trap, after `dumpcap` has been killed and its output
flushed, a plain `cp` - which hasn't dropped any capabilities - copies the
finished capture from `/tmp` into the bind-mounted output directory,
where the trailing `fix_perms` call chowns it one last time:

```bash
if [[ -s "${TMP_CAPTURE}" ]]; then
    cp -f "${TMP_CAPTURE}" "${CAPTURE_FILE}"
fi
decode
fix_perms
```

Part 2's wireshark sidecar never hits this at all, because it never
captures live traffic in the first place - it only reads an
already-complete pcap with `tshark -r`, which does no capturing and
never needs `CAP_DAC_OVERRIDE`.

`HOST_UID` and `HOST_GID` come from the host's `id -u` / `id -g` and are
exported by the Makefile:

```makefile
export HOST_UID := $(shell id -u)
export HOST_GID := $(shell id -g)
```

Docker Compose passes them through (`HOST_UID: "${HOST_UID:-1000}"`), so
the entrypoint knows exactly which UID:GID to chown to. The `:-1000`
fallback handles the case where you run `docker compose up` directly
without `make` - you'll get `1000:1000`, which is the first non-root user
on most Linux distros.
---

# Wrapping up

## Comparing the two projects

Both projects are "observe traffic without touching the app," but nearly
every design decision inside them differs, which is exactly what makes
running them back to back useful - each choice only really makes sense in
contrast with the other one:

| Dimension | Part 1: `part1-ebpf-logger` | Part 2: `part2-postgres-sink` |
|---|---|---|
| Interface | `veth0`, one end of a veth pair into a namespace | `lo` (loopback) |
| XDP mode | Native (`xdpdrv`) - veth has a driver | Generic (`xdpgeneric`) - `lo` has none |
| What crosses the kernel/user boundary | Parsed scalar fields (`packet_event`: IPs, ports, length) | Raw bytes (`event`: up to 4 KB of the original packet) |
| Kernel-side helper for payload | none needed - direct struct field assignment | `bpf_probe_read_kernel()`, plus a bitmask to satisfy the verifier |
| Ring buffer size | 256 KiB (`1 << 18`) | 4 MiB (`1 << 22`) - raw bytes are much bigger than scalar fields |
| Userspace output | Plain-text log line per packet | Hand-written binary `.pcap` file |
| Who parses the protocol | The BPF program (by hand, in C) | Wireshark's `pgsql` dissector (for free, at decode time) |
| Containers | 2 (loader + wireshark sidecar) | 4 (postgres + capture + wireshark + one-shot db-client) |
| What the wireshark sidecar decodes | The same 5 fields the BPF program already extracted, but via tshark's full protocol stack | Full SQL query/response text, which the BPF program never parsed at all |

The line to internalize: **the more of the protocol you want Wireshark to
understand for you, the more raw bytes your BPF program has to move, and
the more careful the verifier gets about proving those copies are safe.**
Part 1's approach - extract a few fields yourself - is the right call when
you know exactly what you want to log and can afford to write the parser.
Part 2's approach - copy bytes and let a dissector handle it - is the
right call when the protocol is complex (SQL, HTTP, TLS handshakes) and
reimplementing its parser in bounds-checked BPF C would be its own
multi-week project.

### Why one project needs a fake network and the other doesn't

The interface and XDP-mode row in that table (`veth0`/native vs. `lo`/
generic) is a single line, but it's the most consequential design
decision in either project, and it's worth unpacking on its own - it's
really two separate questions, one about **networking** and one about
**BPF attach modes**, that happen to point the same direction.

**The networking question: does traffic actually cross the interface as
ingress?**

XDP only fires on packets arriving as ingress on the specific interface
it's attached to. That's trivially true for real NICs - a packet from
another host has no way to reach your machine except by arriving on a
physical interface. It's *not* obviously true for two processes on the
same box talking over `lo`, because the kernel is free to take shortcuts
for intra-host delivery. In practice, Linux's loopback driver
(`loopback_xmit()`) re-queues every transmitted packet straight into the
receive path via `netif_rx()` - so `lo` traffic genuinely does traverse
an ingress path, it's just a path with no physical wire behind it, no
driver-level RX ring, and no hardware descriptors to speak of.

Part 1 doesn't attach to `lo` at all, precisely to avoid relying on that
loopback-specific behavior and to get a topology closer to "real" traffic:
`core-entrypoint.sh` creates a **veth pair** (`veth0`/`veth1`) with one end
moved into a separate network namespace (`bpfpeer`). A veth pair behaves
like a real point-to-point cable - whatever one end transmits, the other
receives as genuine ingress, driver ring and all. Sending from the peer
namespace to the host namespace (`ip netns exec bpfpeer ping 10.0.0.1`)
forces traffic to cross that "wire" instead of taking any intra-host
shortcut, so the demo behaves like a program attached to a real physical
NIC would.

Part 2 attaches directly to `lo`, deliberately taking the shortcut Part 1
avoided - because the traffic it cares about (a Postgres client and
server both running on the same host) *only* exists on loopback. There's
no veth pair to insert here without changing what's being captured, so
the project has to make `lo` itself work with XDP instead.

**The BPF question: which XDP attach mode does the interface support?**

This is where the two answers connect. XDP has two attach modes that
matter here:

| Mode | Where the hook actually lives | Requires a driver hook? |
|---|---|---|
| **Native** (`xdpdrv`) | Inside the NIC driver's RX poll routine, processing hardware descriptors before an `sk_buff` is even allocated | Yes - the driver must implement `ndo_bpf`/XDP support |
| **Generic** (`xdpgeneric`) | A hook the kernel synthesizes in the *core* receive path (`do_xdp_generic()`, called from `netif_receive_skb()`), after the `sk_buff` already exists | No - works on any net device |

`veth0` in Part 1 is a real (virtual) network driver, so it supports
**native** mode: `xdp_logger.bpf.c` runs at the earliest possible point,
before the kernel has built an `sk_buff`, which is why the whole project
can credibly call itself "near-zero overhead."

`lo` has no driver in that sense - there's no RX ring, no hardware
descriptors, nothing for native mode to hook into. So Part 2's loader has
no choice but to request **generic** mode. Generic mode is slower (the
`sk_buff` already exists, so you've paid the allocation cost native mode
avoids) and slightly less representative of "real" XDP performance
characteristics - but it works on literally any interface, including
`lo`, precisely because it doesn't depend on driver support. That's the
actual mechanism behind the one-line note in section 13.2's mode table:
`lo`'s "Native: No / Generic: Yes" isn't an arbitrary limitation, it's a
direct consequence of `lo` having no hardware-descriptor RX path for
native mode to attach to, while generic mode's kernel-synthesized hook
doesn't care.

Put the two answers together and the design choices in both projects stop
looking like arbitrary preferences and start looking like the only two
ways to satisfy the same constraint (see traffic as real ingress) for two
different kinds of traffic (cross-namespace vs. same-host):

- **Want real, physical-feeling ingress and the best-case native XDP
  performance?** Manufacture a veth pair - Part 1's approach.
- **Need to observe traffic that only ever exists on `lo`, and can't
  insert a veth pair without changing what you're capturing?** Use
  generic mode, accept the performance trade-off, and let the kernel's
  synthesized hook do the work - Part 2's approach.

### Why Part 1's wireshark sidecar captures traffic itself (and Part 2's doesn't)

The comparison table's "What the wireshark sidecar decodes" row hides a
second, less obvious asymmetry: **Part 1's sidecar actively captures
traffic itself**, while Part 2's sidecar sits completely idle until
shutdown. That difference comes from how each project's BPF program
writes its output.

**Part 1's BPF program writes a human-readable text log** - one line per
packet with parsed IP/port/protocol fields. That's great for reading
inline (`cat output/packets.log`), but it's *not* a pcap file, so if you
want Wireshark's full protocol decode for comparison you need a
completely separate capture from scratch. The sidecar does that with
`dumpcap` (the same capture engine behind `tcpdump`/Wireshark itself),
tapping `veth0` independently and writing its own `capture.pcap`.

**Part 2's BPF program writes a pcap file directly** - the loader
(`capture_loader`) writes the global pcap header and per-packet records
by hand, so the output (`pg_capture.pcap`) is already in exactly the
format tshark expects. There's nothing for the sidecar to capture; it
just decodes the existing pcap to text on shutdown.

Part 1's live capture runs into a permission subtlety that's worth
knowing about if you ever poke at `wireshark-entrypoint.sh`: it doesn't
write straight to the bind-mounted `capture.pcap`, but to
`/tmp/capture_tmp.pcap` first, copying the finished file over only in
the cleanup trap. Section 13.6's "permission lifecycle" walkthrough
covers exactly why - in short, `dumpcap` drops the `CAP_DAC_OVERRIDE`
capability as a hardening measure, and by the time capture starts the
output directory has already been chowned to the host user, so `dumpcap`
(root, but without that capability) can no longer create a file there.
Capturing to `/tmp` and letting a plain `cp` move it afterward sidesteps
that entirely. Part 2's sidecar never hits this, because it never calls
`dumpcap` in the first place - it only reads an already-complete pcap
with `tshark -r`, which does no capturing and never needs
`CAP_DAC_OVERRIDE`.

This is a good example of how the same "observe traffic" goal can run
into completely different operational constraints depending on which
tool does the capturing: a dedicated capture tool that hardens itself by
dropping capabilities needs a different permission-ordering strategy than
a general-purpose program that just calls `fwrite()`.

## Exercises: extending the Postgres capture

Part 1 ended with four exercises against `xdp_logger.bpf.c`. Here are four
more against `xdp_capture.bpf.c` and its surrounding userspace/Docker
pieces, again roughly in order of difficulty:

1. **Cap the capture length differently.** `CAPTURE_LEN` is currently a
   flat 4096 bytes for every matching packet, regardless of whether it's a
   two-byte ACK or a multi-KB result set. Add a second, smaller constant
   for pure-ACK TCP segments (payload length 0) and use it in the ternary
   in section 3.6, so your ring buffer fills up more slowly under bursty
   traffic without losing any query/response bytes.

2. **Add a packet counter, the same way Part 1's exercise 1 did.** Declare
   a `BPF_MAP_TYPE_ARRAY` map with one entry, increment it once per
   packet that passes the port filter in section 3.5, and print the total
   from `capture_loader` on shutdown alongside the existing "N packets
   captured" line. This is good repetition: the pattern is identical to
   Part 1, but you're now writing it against a program that also uses
   `bpf_probe_read_kernel()`, so you'll see the two map types coexist in
   one program.

3. **Filter on both ports independently.** Right now section 3.5 matches
   if *either* the source or destination port is 5432. Add an env-var- or
   compile-time-configurable second port (say, a Redis or MySQL port) and
   OR it into the same filter, then run two `db-client`-style workloads at
   once and confirm both protocols land in the same pcap, cleanly
   interleaved and still decodable - `tshark` will apply whichever
   dissector matches each stream's port automatically.

4. **Follow the SSL caveat to its logical conclusion.** Section 1's "SSL
   caveat" callout explains that this whole approach only works because
   the compose file disables Postgres's TLS. Without changing any BPF
   code, flip `POSTGRES_HOST_SSL_METHOD` back on, rerun `make demo`, and
   look at what `pg_decoded.txt` shows instead of query text. Then research
   (you don't have to implement it) how tools like `sslsplit` or an
   OpenSSL uprobe would need to hook a *different* layer of the stack
   entirely to see plaintext again - a good way to feel, concretely, where
   XDP's visibility ends.

## Where this shows up in the real world

The two toy projects in this repo use the same primitives - XDP hooks,
ring buffers, the verifier - that power a good chunk of the modern
cloud-native networking and security stack. Seeing where each idea scales
up is a good way to anchor what you just built:

- **[Cilium](https://github.com/cilium/cilium)** - the reference example
  of "XDP instead of iptables." It replaces most of a Kubernetes cluster's
  networking, load balancing, and network policy enforcement with eBPF
  programs, several of them attached at XDP for line-rate packet handling
  before the kernel's normal routing path even runs - the same hook this
  repo's Part 1 attaches to, just with a vastly larger program and a
  Go-based control plane on top.
- **[Hubble](https://github.com/cilium/hubble)** - built on Cilium,
  this is the "what does my BPF program actually see" idea from Part 1's
  ring-buffer walkthrough, scaled up into a full network observability
  platform with flow logs, service maps, and a UI.
- **[Tetragon](https://github.com/cilium/tetragon)** - same eBPF
  foundation, pointed at security instead of networking: it hooks kernel
  functions and syscalls (not just XDP) to observe and enforce policy on
  process execution, file access, and network activity in real time.
- **[Katran](https://github.com/facebookincubator/katran)** - Meta's
  open-sourced layer-4 load balancer. It's the most direct "grown-up"
  version of Part 1's program: same XDP hook, same idea of parsing
  headers and making a fast decision per packet, but forwarding/rewriting
  packets at scale instead of just logging them.
- **[Falco](https://github.com/falcosecurity/falco)** - a CNCF runtime
  security tool that uses eBPF (among other backends) to watch kernel
  events and flag anomalous behavior, conceptually similar to this
  article's "observe without touching the app" theme but applied to
  syscalls rather than packets.
- **[Pixie](https://github.com/pixie-io/pixie)** and
  **[Parca](https://github.com/parca-dev/parca)** - eBPF-based Kubernetes
  observability and continuous profiling, respectively. Both lean on the
  same "attach a small verified program to a kernel hook, ship data out
  through a map" pattern this repo teaches, just at hooks other than XDP
  (uprobes, perf events).
- **[bpftrace](https://github.com/bpftrace/bpftrace)** and the
  **[BCC tools](https://github.com/iovisor/bcc)** - if you want to
  experiment with more BPF hooks without writing a full loader/skeleton
  like Part 1 and Part 2 do, these give you a scripting front end over the
  same verifier and map machinery.
- **[xdp-tools](https://github.com/xdp-project/xdp-tools)** - the
  reference userspace tooling for XDP maintained by the kernel's XDP
  authors, including `xdp-loader` and `xdp-dump`, which do roughly what
  this repo's `loader.c` does, but as a general-purpose, production-grade
  tool rather than a teaching example.
- **Cloudflare's DDoS mitigation pipeline** - a widely cited real-world
  case study of XDP filtering packets at the earliest possible point,
  the same `XDP_PASS`/`XDP_DROP` decision Part 1's exercises ask you to
  experiment with, but defending production edge network capacity.

---

## Further reading

Shared across both parts:

- [Linux kernel BPF documentation](https://www.kernel.org/doc/html/latest/bpf/)
- [libbpf documentation](https://github.com/libbpf/libbpf)
- [Cilium's BPF and XDP Reference Guide](https://docs.cilium.io/en/stable/bpf/)
- [BPF CO-RE reference guide (Andrii Nakryiko)](https://nakryiko.com/posts/bpf-core-reference-guide/)
- [ebpf.io - applications and getting-started guides](https://ebpf.io/)
- [awesome-ebpf (qmonnet) - curated list of eBPF projects, talks, and papers](https://github.com/qmonnet/awesome-ebpf)
- [eBPF Foundation project list](https://ebpf.foundation/projects/)

Part 1 specific:

- [XDP project tutorials (xdp-project/xdp-tutorial)](https://github.com/xdp-project/xdp-tutorial)
- [xdp-tools (reference XDP userspace tooling)](https://github.com/xdp-project/xdp-tools)
- [Katran - Meta's XDP-based L4 load balancer](https://github.com/facebookincubator/katran)

Part 2 specific:

- [BPF Compiler Collection (BCC)](https://github.com/iovisor/bcc)
- [Wireshark PostgreSQL dissector](https://wiki.wireshark.org/PostgreSQL)
- [Wireshark Developer's Guide](https://www.wireshark.org/docs/wsdg_html_chunked/)

Real-world projects built on these ideas:

- [Cilium](https://github.com/cilium/cilium) - eBPF-based Kubernetes networking, security, and observability
- [Hubble](https://github.com/cilium/hubble) - network observability built on Cilium
- [Tetragon](https://github.com/cilium/tetragon) - eBPF-based runtime security observability and enforcement
- [Falco](https://github.com/falcosecurity/falco) - CNCF runtime security / anomaly detection
- [Pixie](https://github.com/pixie-io/pixie) - no-instrumentation Kubernetes application observability
- [Parca](https://github.com/parca-dev/parca) - continuous, eBPF-based profiling
- [bpftrace](https://github.com/bpftrace/bpftrace) - high-level tracing language for eBPF

---

*This article covers both `part1-ebpf-logger/` and `part2-postgres-sink/`.
To run either demo yourself:*

```bash
# Part 1 - packet logger
cd part1-ebpf-logger
make up

# Part 2 - Postgres capture
cd part2-postgres-sink
make demo
```

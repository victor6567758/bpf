# eBPF Packet Logger (XDP)

Attaches an XDP eBPF program to a network interface, streams a one-line
summary of every IPv4 packet (timestamp, protocol, src/dst IP:port, length)
to userspace over a BPF ring buffer, and appends it to a log file. Traffic
is only observed — every packet is still passed through (`XDP_PASS`).

A companion **tshark** sidecar captures the same traffic to a `.pcap` and
writes a full human-readable decode, so you get three views of the same
packets: BPF-level summary, raw pcap, and decoded text.

```
ebpf-packet-logger/
├── bpf/
│   ├── xdp_logger.bpf.c        # the eBPF program (runs in the kernel)
│   └── packet_event.h          # struct shared between kernel and userspace
├── src/
│   └── loader.c                # userspace: attaches the program, drains events
├── scripts/                    # all run *inside* the container
│   ├── core-entrypoint.sh      # logger lifecycle: veth + build + attach + test + teardown
│   ├── wireshark-entrypoint.sh # sidecar lifecycle: wait for veth0, capture, decode on exit
│   └── send-traffic.sh         # shared ICMP/UDP/TCP burst (startup + `make test`)
├── CMakeLists.txt              # builds everything, incl. the CLion-friendly steps
├── Dockerfile.core             # full toolchain: clang/llvm, libbpf, bpftool
├── Dockerfile.wireshark        # tshark-only image for the decode sidecar
├── docker-compose.yml          # runs both services with the privileges eBPF needs
├── Makefile                    # THE host entry point: up/down/test/decode/...
└── output/                     # packets.log, capture.pcap, decoded.txt land here
```

Why Docker at all: loading BPF programs needs root-equivalent privileges
(`CAP_BPF`/`CAP_NET_ADMIN`/`CAP_SYS_ADMIN`) and a matching kernel toolchain.
Containerizing it means you don't need any of that installed on your host,
and the environment is identical for everyone on the team.

---

## Quick start (one command)

```bash
make up
```

That's it. The `packet-logger` service:

1. Creates a `veth` pair (`veth0` ↔ `veth1`, `10.0.0.1/24` ↔ `10.0.0.2/24`)
   in the host netns (the container is `--network host` + privileged).
2. Builds the BPF program and loader inside the container.
3. Attaches the XDP logger to `veth0`, writing to `output/packets.log`.
4. Sends a burst of ICMP + UDP + TCP test traffic across the pair.
5. Streams the capture log to stdout until you stop it.

Meanwhile the `wireshark` sidecar captures `veth0` to `output/capture.pcap`.

Stop everything with `Ctrl-C` (or in another terminal):

```bash
make down
```

`docker compose down` sends SIGTERM; each container's trap then cleans up
(the logger detaches XDP and deletes the veth pair; tshark decodes its
pcap to `output/decoded.txt` before exiting).

---

## The Makefile (your one-stop shop)

This is the only host-side entry point. It only ever calls `docker compose` —
it never touches cmake, ninja, or the compiler. The in-container build is
completely separate (see "Build layers" below).

Run `make` (or `make help`) to see this list:

| Target          | What it does |
|-----------------|--------------|
| `make up`       | Start both services in the foreground (Ctrl-C to stop). |
| `make up-d`     | Start detached (background); use `make logs` to view. |
| `make down`     | Stop services (triggers clean teardown: XDP detach + veth removal + tshark decode). |
| `make logs`     | Tail logs from all services. |
| `make logs-logger` / `make logs-wireshark` | Tail just one service. |
| `make status`   | Show container status. |
| `make test`     | Send more traffic into the running demo. Override: `make test TRAFFIC=udp`. |
| `make decode`   | Decode current pcap to stdout. Flags: `WRITE=1`, `FILTER="udp port 9123"`. |
| `make view-log` | Show `output/packets.log`. |
| `make view-decoded` | Show `output/decoded.txt` (or prompt to create it). |
| `make clean`    | Stop services + remove output artifacts (keeps source). |
| `make rebuild`  | Force a clean rebuild of the Docker images. |

Common variations:
```bash
make up-d                                  # background, then go do other things
make logs                                  # tail
make test TRAFFIC=udp                      # inject just UDP
make decode WRITE=1 FILTER='udp port 9123' # decode one flow to decoded.txt
make                                       # same as `make help`
```

The old `scripts/start.sh` / `stop.sh` / `test.sh` / `capture.sh` / `decode.sh`
host wrappers have been removed — `make` replaces all of them. The three
scripts that remain in `scripts/` all run **inside** the container.

---

## What you get in `output/`

Three independent views of the same packets:

| File             | Source        | What it is                                      | When it exists |
|------------------|---------------|-------------------------------------------------|----------------|
| `packets.log`    | BPF logger    | One-line summary per packet (the XDP program).  | Live, while the logger runs. |
| `capture.pcap`   | tshark sidecar| Raw pcap, open in Wireshark's GUI for detail.   | Live, while the sidecar runs (written incrementally). |
| `decoded.txt`    | tshark sidecar| Full `tshark -V` decode of every packet.        | On `make down` (explicit decode) or `make decode WRITE=1`. |

> **Note:** `make down` decodes the full capture to `decoded.txt` **before**
> stopping the containers, so you always get a complete decode of the whole
> run. To see the decode *while the demo is still running*, use `make decode`.

```bash
# While the demo is running:
make view-log                       # live BPF summary
make decode                         # decode the partial pcap to stdout, right now
make decode WRITE=1                 # ...and also write output/decoded.txt
make decode FILTER='udp port 9123'  # filter the decode to a flow

# After stopping:
make view-decoded                   # full decode of the whole run
wireshark output/capture.pcap       # interactive GUI (needs Wireshark on host)
```

A sample `packets.log` line:
```
2026-07-27 14:02:11 proto=TCP 10.0.0.1:51422 -> 10.0.0.2:443 len=60
```

---

## Build layers — why the Makefile and `build.ninja` don't conflict

There are two completely separate build systems in this repo, by design:

```
┌─────────────────────────────────────────────────────────────────┐
│ HOST                                                            │
│  make up  ──>  docker compose up  ──>  starts containers        │
│  (Makefile only orchestrates Docker; never compiles anything)   │
└─────────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│ CONTAINER (packet-logger)                                       │
│  core-entrypoint.sh  ──>  cmake -B build  ──>  generates build.ninja │
│                     cmake --build build  ──>  invokes ninja      │
│                     ninja: clang (BPF obj) + bpftool (skeleton) │
│                              + gcc (loader)                     │
│  (this is the only thing that compiles code)                    │
└─────────────────────────────────────────────────────────────────┘
```

- The **Makefile** lives at the repo root and is the human-facing entry
  point. It's purely orchestration: `docker compose up/down/logs/exec`.
- **CMake + Ninja** run *inside the container*, in `/work/build/`, and
  produce `packet_logger` + `xdp_logger.bpf.o`. They're invoked by
  `core-entrypoint.sh`, not by the Makefile.
- The `cmake-build-debug/build.ninja` you may see in CLion is a *third*
  context: CLion's own CMake profile for IDE indexing/debugging. It's
  independent of both the Makefile and the in-container build.

This is a standard pattern for containerized C/C++ projects: a top-level
Makefile (or `Justfile`, `Taskfile`) for the developer workflow, with the
real build system living inside the container where the toolchain is pinned.

---

## Configuration (environment variables)

Override any of these via your shell or the `environment:` block in
`docker-compose.yml`.

### `packet-logger` service
| Var               | Default            | Meaning                                             |
|-------------------|--------------------|----------------------------------------------------|
| `VETH0` / `VETH1` | `veth0` / `veth1`  | veth pair endpoint names.                          |
| `VETH0_IP` / `VETH1_IP` | `10.0.0.1/24` / `10.0.0.2/24` | IPs assigned to each end.            |
| `TEST_ON_START`   | `1`                | Send the startup ICMP/UDP/TCP burst. Set `0` to skip. |
| `EXIT_AFTER_TEST` | `0`                | Exit right after the startup burst (one-shot mode). |
| `LOG`             | `/work/output/packets.log` | Where the BPF logger writes its summary.   |

### `wireshark` service
| Var            | Default                       | Meaning                                |
|----------------|-------------------------------|----------------------------------------|
| `VETH0`        | `veth0`                       | Interface to capture on.               |
| `CAPTURE_FILE` | `/work/output/capture.pcap`   | Raw pcap output.                       |
| `DECODED_FILE` | `/work/output/decoded.txt`    | Decoded text output (written on exit). |
| `FILTER`       | _(empty = all traffic)_       | Optional capture filter, e.g. `ip` or `udp port 9123`. |

Examples:
```bash
# One-shot: capture the startup burst and exit
EXIT_AFTER_TEST=1 make up

# Re-send just UDP traffic into a running demo
make test TRAFFIC=udp

# Start the logger without auto-generated traffic, you'll drive it yourself
TEST_ON_START=0 make up
```

---

## Prerequisites

- Docker Desktop (or Docker Engine on Linux) running.
- Linux kernel ≥ 5.8 on the machine that *runs* the container (BPF ring
  buffer support). On Docker Desktop for Mac/Windows this is satisfied by
  the Docker Desktop VM.
- `sudo` available on the host for `make down`'s defensive veth cleanup
  (only used if a container was force-killed before its trap ran).
- `make` (GNU Make) on the host.

---

## Building / debugging in CLion (optional)

The Docker workflow above is the recommended path. If you want to
build/debug from the IDE directly, CLion can use the Dockerfile as a
toolchain so you never install clang/libbpf/bpftool on the host:

1. `Settings > Build, Execution, Deployment > Toolchains` → `+` → `Docker`.
2. **Image**: "Build from Dockerfile", point at this project's `Dockerfile.core`.
3. **Container run options**:
   ```
   --privileged --network host -v /sys/fs/bpf:/sys/fs/bpf
   ```
4. `Settings > Build, Execution, Deployment > CMake`: set the profile's
   **Toolchain** to the Docker one. Apply; CLion builds the image once.

Under the hood CMake does three things (you'll see them in the build log):
1. `clang -target bpf` compiles `bpf/xdp_logger.bpf.c` → `xdp_logger.bpf.o`.
2. `bpftool gen skeleton` turns that object into `xdp_logger.skel.h`.
3. `src/loader.c` compiles + links against `libbpf` into `packet_logger`.

If the indexer underlines `#include "xdp_logger.skel.h"` in red before the
first build — that's expected; the header is generated in step 2.

To run/debug from CLion: edit the `packet_logger` run config, set
**Program arguments** to `veth0 output/packets.log`, and hit Run. Create the
veth pair first (`make up` then Ctrl-C, or manually with `ip link add`).
Breakpoints in `loader.c` work; you can't breakpoint inside `.bpf.c`
(it runs in the kernel).

---

## How teardown stays clean

`make down` does two things in order:
1. **Decodes** — while the `wireshark` sidecar is still running, it runs
   `tshark -r capture.pcap -V > decoded.txt` via `docker exec`. This is the
   reliable path; the sidecar's own SIGTERM trap (below) is a backup.
2. **Stops** — `docker compose down` → SIGTERM → `init: true` (tini) forwards
   the signal to bash → each service's trap runs:
   - **packet-logger**: kills the loader process (closing its `bpf_link`), then
     `ip link del veth0` (which atomically destroys `veth1` too).
   - **wireshark**: stops `dumpcap` (and would decode again if the explicit
     step above somehow didn't run).

`stop_grace_period: 5s` gives that work time to finish before Docker
escalates to SIGKILL. `make down` adds belt-and-braces host-side veth
cleanup in case a container died before its trap could run.

---

## Common issues

- **"Operation not permitted" attaching XDP** → the container isn't
  privileged / missing `CAP_NET_ADMIN`. Check `docker-compose.yml`'s
  `privileged: true`.
- **`wireshark` service logs "veth0 never appeared"** → the `packet-logger`
  service failed to start or create the veth pair. Check its logs:
  `make logs-logger`.
- **No lines in `packets.log` but the sidecar has a pcap** → the XDP
  program attaches but your traffic isn't crossing `veth0`. Make sure test
  traffic is between `10.0.0.1` and `10.0.0.2` (the veth endpoints).
- **`capture.pcap` is empty but `packets.log` has entries** → rare; means
  tshark started after the test burst. Re-run `make test` while both
  services are up.

---

## Adjusting what gets captured

`bpf/xdp_logger.bpf.c` currently matches IPv4 only and never drops anything.
Useful tweaks:
- Add an IPv6 branch (`ETH_P_IPV6` / `struct ipv6hdr`) alongside the IPv4 one.
- Filter by port/protocol before `bpf_ringbuf_reserve` to only pay the
  ring-buffer cost for traffic you care about.
- Return `XDP_DROP` under some condition to turn the logger into a filter —
  the userspace side doesn't need to change. (Note: dropping packets will
  also stop them reaching the tshark sidecar, since that taps downstream.)
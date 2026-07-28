# bpf monorepo

A two-part eBPF/XDP project. Each part is an independent subproject with its
own `docker-compose.yml`, `Makefile`, and runtime; the top-level
`CMakeLists.txt` is the common build that pulls both in.

- **part1-ebpf-logger** — the original XDP packet logger. Captures ICMP/UDP/TCP
  traffic on a synthetic veth pair, logs summaries, and produces a pcap.
- **part2-postgres-sink** — a second XDP capture project, this time targeting
  Postgres wire traffic (ssl=off) and decoding it with tshark's `pgsql`
  dissector. Bundles its own postgres + db-client so it's self-contained.

```
bpf/
├── CMakeLists.txt            # common build: add_subdirectory(part1) + part2
├── Makefile                  # convenience delegator (see below)
├── README.md                 # this file
├── LICENSE
│
├── part1-ebpf-logger/        # XDP packet logger (original project)
│   ├── CMakeLists.txt        #   relocatable: builds standalone OR via root
│   ├── Dockerfile.core       #   full clang/libbpf/bpftool toolchain image
│   ├── Dockerfile.wireshark  #   tshark decode sidecar image
│   ├── docker-compose.yml    #   logger + wireshark services (privileged)
│   ├── Makefile              #   up/down/logs/test/decode/...
│   ├── bpf/                  #   xdp_logger.bpf.c + packet_event.h
│   ├── src/                  #   loader.c (userspace)
│   ├── scripts/              #   in-container entrypoints + traffic generator
│   ├── output/               #   packets.log, capture.pcap, decoded.txt
│   └── README.md             #   part1-specific docs
│
└── part2-postgres-sink/      # XDP capture of Postgres wire traffic
    ├── CMakeLists.txt        #   relocatable: builds standalone OR via root
    ├── Dockerfile.core       #   clang/libbpf toolchain image (XDP capture)
    ├── Dockerfile.wireshark  #   tshark decode sidecar image
    ├── docker-compose.yml    #   postgres + capture + wireshark + db-client
    ├── Makefile              #   up/down/logs/traffic/decode/psql/...
    ├── bpf/                  #   xdp_capture.bpf.c + common.h
    ├── src/                  #   loader.c (userspace)
    ├── scripts/              #   in-container entrypoints
    ├── output/               #   pg_capture.pcap, pg_decoded.txt
    ├── .env.example
    └── README.md             #   part2-specific docs
```

## Independence

The two parts are **completely independent at runtime**:

- Each runs in its own privileged container with `network_mode: host` (both
  attach XDP programs).
- They don't share networks, volumes, or compose projects. You can run either
  one without starting the other.
- Different interfaces: part1 attaches to a synthetic veth pair it creates;
  part2 attaches to `lo` (where its bundled postgres + psql client cross
  traffic).
- Different output dirs: part1 writes `output/capture.pcap`; part2 writes
  `output/pg_capture.pcap`.

The only conceptual link is that both share the same libbpf-based XDP
architecture (ring buffer + per-event write to a pcap file).

## Common build (top-level CMake)

The root `CMakeLists.txt` exists so CLion (or a developer at the command line)
can configure the whole repo as a single CMake project:

```bash
cmake -S . -B build
cmake --build build -j
```

This produces both parts' targets under one build tree. Each subproject is
also relocatable - you can build it on its own:

```bash
cmake -S part1-ebpf-logger -B part1-ebpf-logger/build && cmake --build part1-ebpf-logger/build -j
cmake -S part2-postgres-sink -B part2-postgres-sink/build && cmake --build part2-postgres-sink/build -j
```

> **Note on the BPF build:** building the BPF programs requires clang with the
> bpf target and `bpftool`, which are only available inside each project's
> container (or on a host with the full eBPF toolchain). If you configure the
> root on a plain dev machine, the configure step may fail looking for
> `bpftool`. That's expected - for day-to-day work, use `make up` inside the
> relevant subproject (the build happens inside the container). The root
> configure path is mainly useful under CLion's Docker toolchain.

## Top-level Makefile (convenience)

The root `Makefile` is a thin delegator so you don't have to remember which
subdirectory to `cd` into. It forwards to each part's own Makefile.

```
make help         # show all targets

# part1: eBPF packet logger (log-*):
make log-up       # start the logger (foreground)
make log-up-d     # start the logger (detached)
make log-down     # stop the logger
make log-logs     # tail logger logs
make log-test     # send test traffic into the logger
make log-rebuild  # force a clean rebuild of the logger images

# part2: postgres capture (pg-*):
make pg-up        # start postgres capture (foreground)
make pg-up-d      # start postgres capture (detached)
make pg-down      # stop postgres capture (keeps the pgdata volume)
make pg-logs      # tail postgres capture logs
make pg-traffic   # run part2's db-client to generate queries
make pg-psql      # psql into part2's postgres
make pg-rebuild   # force a clean rebuild of part2's images

# both:
make rebuild-all  # force a clean rebuild of both parts' images
make down-all     # stop both parts
```

> **Build vs start:** `up` implies a build if needed (compose's default
> behavior). There is no separate `build` target — to force a clean rebuild,
> use `log-rebuild` / `pg-rebuild` / `rebuild-all`.

For anything beyond these convenience targets, work directly inside the
subproject directory - each part has its own richer `Makefile` and `README.md`.

## Where to start

- **New to the project?** Read `part1-ebpf-logger/README.md` for what the
  packet logger does and how to run it.
- **Looking for the postgres capture?** Read `part2-postgres-sink/README.md`.
- **Configuring CLion / the whole repo?** See "Common build" above.
# Postgres XDP Capture (part2)

Captures unencrypted Postgres wire traffic via XDP and produces a pcap you
can open directly in Wireshark, which has a built-in `pgsql` dissector that
decodes queries, result rows, parse/bind/execute, etc. — no custom parsing.

**SSL must be off.** The compose file starts postgres with `-c ssl=off` and
the capture filter targets the plaintext protocol. If the connection
negotiates TLS, the captured bytes are ciphertext and the dissector fails.

This subproject is independent from `../part1-ebpf-logger` — different code,
different compose stack, different README. See the root `../README.md` for
how the two fit into the same monorepo.

## Quick start

**One-shot demo** (does everything in one command):

```bash
make demo
```

This starts the stack, generates traffic, prints the captured SQL queries,
decodes the pcap, and shuts down — leaving `output/pg_capture.pcap` and
`output/pg_decoded.txt` behind.

**Step-by-step** (interactive, for exploring while it runs):

```bash
make up        # build + start postgres, capture, wireshark (foreground)
```

In another terminal, while it's running:

```bash
make traffic   # one-shot: runs a few psql queries to generate traffic
make sql       # print the captured SQL queries
```

Stop with `Ctrl+C` (or `make down` if detached). The wireshark sidecar
auto-decodes the capture to `output/pg_decoded.txt` on shutdown.

## What ends up in `output/`

| File                 | Source             | Notes                                        |
|----------------------|--------------------|----------------------------------------------|
| `pg_capture.pcap`    | XDP capture loader | Raw packets from the BPF ring buffer          |
| `pg_decoded.txt`     | tshark sidecar     | `tshark -V` decode of `pg_capture.pcap`       |

Open the `.pcap` in Wireshark and filter on `pgsql` in the display filter bar
to see only decoded Postgres protocol messages. There is only one pcap — the
tshark sidecar is decode-only, not a second capture path.

## Architecture

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

All four services share the host network namespace, so client→server and
server→client packets both cross `lo`, which is where the XDP program
attaches (generic/driver-less mode). The tshark sidecar does not capture —
it is decode-only, reading the pcap the capture service wrote and producing
`pg_decoded.txt` on shutdown. Keeping decode in its own container keeps
tshark's heavy dependencies out of the privileged capture image.

## Makefile targets

```
  help          show this help
  up            start all services in the foreground (Ctrl-C to stop)
  up-d          start all services detached
  demo          one-shot: up -> traffic -> show SQL -> decode -> down
  down          stop services (wireshark decodes pcap -> pg_decoded.txt)
  logs          tail logs from all services
  logs-capture  tail only the XDP capture service
  logs-wireshark tail only the tshark sidecar
  logs-pg       tail only postgres
  status        show container status
  traffic       run the one-shot db-client to generate queries
  sql           list all captured SQL queries (tshark -Y pgsql.query)
  decode        decode current pcap to stdout (WRITE=1 saves file; FILTER="pgsql")
  view-capture  show the capture_loader's packet count
  view-decoded  print output/pg_decoded.txt
  psql          connect to the DB with psql
  query         run a SQL statement (SQL='SELECT ...')
  clean         stop + remove output artifacts (keeps pgdata volume)
  nuke          stop + delete the pgdata volume (fresh DB next up)
  rebuild       force a clean rebuild of the Docker images
```

## Viewing SQL queries

The whole point of the capture is to see the actual SQL. There are three ways:

**1. While the stack is running** (fastest):

```bash
make sql
```

This runs `tshark -r output/pg_capture.pcap -Y pgsql.query -T fields -e pgsql.query`
via the wireshark sidecar, printing every query on its own line:

```
=== SQL queries in output/pg_capture.pcap ===
  SELECT 1 AS probe;
  SELECT 'db-client start', now();
  CREATE TABLE IF NOT EXISTS demo (id serial PRIMARY KEY, note text, ts timestamptz DEFAULT now());
  INSERT INTO demo (note) VALUES ('hello from db-client'), ('another row'), ('third');
  SELECT id, note, ts FROM demo ORDER BY id DESC LIMIT 5;
  SELECT count(*) AS total FROM demo;
  SELECT 'db-client done', now();
```

**2. After `make down`** — the full verbose decode is in `output/pg_decoded.txt`.
Queries appear as `Statement: <SQL>` lines under each Query message:

```bash
grep -A1 "Statement:" output/pg_decoded.txt
```

**3. Open the pcap in Wireshark** (GUI) — filter `pgsql` in the display filter
bar and click any `Query` packet; the SQL appears in the protocol tree under
PostgreSQL → Statement.

## Building the C code

You don't need to — the capture container builds it on startup via
`scripts/capture-entrypoint.sh`. If you want to build locally (e.g. for
CLion's indexer), install the toolchain and run CMake:

```bash
sudo apt install clang llvm libbpf-dev libelf-dev pkg-config cmake make gcc \
                 linux-headers-$(uname -r)
cmake -B build . && cmake --build build -j
```

XDP attach requires root, so even a locally-built binary must be run via
`sudo ./build/capture_loader <iface> <out.pcap>`. The container path
(`make up`) handles all of this automatically.

## Notes

- **`lo` and generic XDP**: the kernel supports XDP_GENERIC attaches on
  loopback on recent kernels; if the attach fails with `-EINVAL`, your
  kernel may be too old. In that case, use a real interface or a veth pair.
- **`CAPTURE_LEN` (4096)**: generous for typical query/result traffic, but
  very large `COPY` payloads or huge result sets may get truncated. Bump
  it in `bpf/common.h` if needed (the ring buffer is 4 MB).
- **`XDP_PASS`**: the program is a pure observer — it never drops or
  modifies traffic, so postgres connectivity is unaffected.
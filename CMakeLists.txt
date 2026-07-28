cmake_minimum_required(VERSION 3.16)
project(bpf_monorepo C)

# This is the common/top-level build. It pulls each independent subproject in
# via add_subdirectory(). Each part owns its own CMakeLists.txt and can also
# be built standalone (see partN-*/CMakeLists.txt comments).
#
# Top-level usage from the repo root:
#   cmake -S . -B build && cmake --build build -j
#
# Each subproject's targets are namespaced under their directory name, e.g.:
#   part1-ebpf-logger::packet_logger
#
# NOTE on part1: building the BPF program requires clang with the bpf target
# and bpftool, which are only available inside its container (or a host with
# the full eBPF toolchain). If those are missing, configure will fail at the
# subproject level. For day-to-day work prefer `make up` in part1-ebpf-logger/
# (which builds in-container). This top-level configure is mainly useful when
# you have the toolchain installed natively or via CLion's Docker toolchain.

# part1: the existing eBPF XDP packet logger (kernel + userspace loader).
add_subdirectory(part1-ebpf-logger)

# part2: postgres-backed sink for captured packet events. Currently a
# placeholder library/target so the common build stays green while the real
# implementation is developed. It deliberately avoids any host toolchain
# requirements beyond a C compiler.
add_subdirectory(part2-postgres-sink)
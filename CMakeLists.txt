cmake_minimum_required(VERSION 3.16)
project(bpf_monorepo C)

add_subdirectory(part1-ebpf-logger)

add_subdirectory(part2-postgres-sink)

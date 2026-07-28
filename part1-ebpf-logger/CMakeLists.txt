cmake_minimum_required(VERSION 3.16)
project(ebpf_packet_logger C)

set(CMAKE_C_STANDARD 11)
# Use CMAKE_CURRENT_* instead of CMAKE_* so this file is relocatable: it
# works whether built standalone (`cmake -S part1-ebpf-logger`) or pulled
# into the monorepo root via add_subdirectory().
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

find_program(CLANG_BIN clang REQUIRED)
find_program(BPFTOOL_BIN bpftool REQUIRED)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBBPF REQUIRED IMPORTED_TARGET libbpf)

set(BPF_SRC   ${CMAKE_CURRENT_SOURCE_DIR}/bpf/xdp_logger.bpf.c)
set(BPF_OBJ   ${CMAKE_CURRENT_BINARY_DIR}/xdp_logger.bpf.o)
set(BPF_SKEL  ${CMAKE_CURRENT_BINARY_DIR}/xdp_logger.skel.h)

# 1. Compile the BPF C source into a BPF ELF object with clang targeting bpf.
add_custom_command(
        OUTPUT ${BPF_OBJ}
        COMMAND ${CLANG_BIN}
        -g -O2 -target bpf -I/usr/include/x86_64-linux-gnu
        -c ${BPF_SRC} -o ${BPF_OBJ}
        DEPENDS ${BPF_SRC} ${CMAKE_CURRENT_SOURCE_DIR}/bpf/packet_event.h
        COMMENT "Compiling XDP BPF object"
        VERBATIM
)

# 2. Generate a libbpf skeleton header from the compiled object. The
#    skeleton gives the loader typed access to skel->progs.* / skel->maps.*
add_custom_command(
        OUTPUT ${BPF_SKEL}
        COMMAND ${BPFTOOL_BIN} gen skeleton ${BPF_OBJ} > ${BPF_SKEL}
        DEPENDS ${BPF_OBJ}
        COMMENT "Generating libbpf skeleton"
        VERBATIM
)

add_custom_target(bpf_skeleton DEPENDS ${BPF_SKEL})

# 3. Userspace loader
add_executable(packet_logger src/loader.c)
add_dependencies(packet_logger bpf_skeleton)
target_include_directories(packet_logger PRIVATE
        ${CMAKE_CURRENT_BINARY_DIR}        # generated xdp_logger.skel.h
        ${CMAKE_CURRENT_SOURCE_DIR}/bpf    # packet_event.h
        ${LIBBPF_INCLUDE_DIRS})
target_link_libraries(packet_logger PRIVATE PkgConfig::LIBBPF elf z)

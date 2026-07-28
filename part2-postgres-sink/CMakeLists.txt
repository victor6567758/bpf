cmake_minimum_required(VERSION 3.16)
project(pg_xdp_capture C)

set(CMAKE_C_STANDARD 11)
# Use CMAKE_CURRENT_* instead of CMAKE_* so this file is relocatable: it
# works whether built standalone (`cmake -S part2-postgres-sink`) or pulled
# into the monorepo root via add_subdirectory(). In practice the Dockerfile
# builds this subproject on its own, but staying relocatable keeps the root
# CMakeLists.txt green if you configure the whole monorepo at once.
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

find_program(CLANG_BIN clang REQUIRED)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBBPF REQUIRED IMPORTED_TARGET libbpf)

# --- Kernel-side BPF object -------------------------------------------
# Compiled separately with clang -target bpf, since this targets the BPF
# instruction set, not your host architecture.
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

# --- Userspace loader --------------------------------------------------
add_executable(capture_loader src/loader.c)
add_dependencies(capture_loader pg_bpf_object)
target_include_directories(capture_loader PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/bpf     # common.h
    ${LIBBPF_INCLUDE_DIRS})
target_link_libraries(capture_loader PRIVATE PkgConfig::LIBBPF elf z)

# The loader opens "xdp_capture.bpf.o" from its working directory at
# runtime, so copy it next to the built binary.
add_custom_command(TARGET capture_loader POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy ${BPF_OBJ} $<TARGET_FILE_DIR:capture_loader>
)
# VaultNode: Encrypted RFID Access Controller & Server Room Telemetry Firmware.
# Protocol and behaviour: docs/PROTOCOL.md (authoritative).
#
# Build inside Docker only. The firmware depends on Linux-only APIs (eventfd,
# SCHED_FIFO), so configuring on any other host is a hard error.
cmake_minimum_required(VERSION 3.20)
project(vaultnode VERSION 0.1.0 LANGUAGES CXX)

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
  message(FATAL_ERROR
    "VaultNode builds on Linux only (eventfd/SCHED_FIFO). "
    "Build inside Docker: docker compose run --rm vaultnode-firmware ...")
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)  # consumed by cppcheck

option(VAULTNODE_SIM_CONTROL
  "Compile the UNAUTHENTICATED fault-injection control socket (TCP 5556, PROTOCOL.md 4.1)" ON)

# ASan + UBSan build. LeakSanitizer is part of ASan and runs at process exit.
# Valgrind (memcheck) runs on the NON-sanitized build: the two cannot be
# combined, because ASan replaces malloc and reserves shadow memory, which
# Valgrind cannot run under.
option(VAULTNODE_SANITIZE "Build with -fsanitize=address,undefined (incompatible with Valgrind)" OFF)

enable_testing()
add_subdirectory(firmware)

message(STATUS "VaultNode: VAULTNODE_SIM_CONTROL=${VAULTNODE_SIM_CONTROL} VAULTNODE_SANITIZE=${VAULTNODE_SANITIZE}")

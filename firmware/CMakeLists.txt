# VaultNode firmware: vaultnode_core (all logic), vaultnode-firmware (entry
# point), and vaultnode_tests (unit tests, registered with CTest).

find_package(OpenSSL 3.0 REQUIRED COMPONENTS Crypto)
find_package(nlohmann_json 3.11 REQUIRED)
find_package(Threads REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(MOSQUITTO REQUIRED IMPORTED_TARGET libmosquitto)

# ---------------------------------------------------------------------------
# Hardening, applied to every firmware target (and only to them, so -Werror
# never trips on third-party code).
# ---------------------------------------------------------------------------
add_library(vaultnode_hardening INTERFACE)
target_compile_options(vaultnode_hardening INTERFACE
  -Wall -Wextra -Werror
  -fstack-protector-strong
  -fPIE
  -O2)  # _FORTIFY_SOURCE needs optimization; forced even for Debug builds
target_link_options(vaultnode_hardening INTERFACE
  -pie
  -Wl,-z,relro,-z,now)

if(VAULTNODE_SANITIZE)
  # FORTIFY is left off here: fortified libc wrappers bypass ASan's
  # interceptors and hide the very bugs ASan is meant to report.
  target_compile_options(vaultnode_hardening INTERFACE
    -fsanitize=address,undefined -fno-sanitize-recover=all
    -fno-omit-frame-pointer -g)
  target_link_options(vaultnode_hardening INTERFACE
    -fsanitize=address,undefined)
else()
  # Ubuntu's GCC already predefines _FORTIFY_SOURCE=3; undefine it first so
  # redefining it as 2 does not raise a -Werror redefinition error.
  target_compile_options(vaultnode_hardening INTERFACE
    -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2)
endif()

# ---------------------------------------------------------------------------
# vaultnode_core: all firmware logic
# ---------------------------------------------------------------------------
add_library(vaultnode_core STATIC
  src/build_info.cpp
  src/crypto.cpp)

if(VAULTNODE_SIM_CONTROL)
  # When OFF, the control socket is neither listed as a source nor defined,
  # so none of its code can end up in the binary.
  target_sources(vaultnode_core PRIVATE src/control_socket.cpp)
  target_compile_definitions(vaultnode_core PUBLIC VAULTNODE_SIM_CONTROL=1)
endif()

target_include_directories(vaultnode_core PUBLIC include)
target_link_libraries(vaultnode_core
  PUBLIC
    OpenSSL::Crypto
    nlohmann_json::nlohmann_json
    PkgConfig::MOSQUITTO
    Threads::Threads
  PRIVATE
    vaultnode_hardening)
target_compile_definitions(vaultnode_core PRIVATE
  VAULTNODE_VERSION="${PROJECT_VERSION}")

# ---------------------------------------------------------------------------
# vaultnode-firmware: entry point
# ---------------------------------------------------------------------------
add_executable(vaultnode-firmware src/main.cpp)
target_link_libraries(vaultnode-firmware PRIVATE vaultnode_core vaultnode_hardening)

# ---------------------------------------------------------------------------
# vaultnode_tests: header-only harness (tests/test_harness.hpp), no external deps
# ---------------------------------------------------------------------------
add_executable(vaultnode_tests
  tests/test_main.cpp
  tests/test_build_info.cpp
  tests/test_crypto.cpp)
target_include_directories(vaultnode_tests PRIVATE tests)
target_link_libraries(vaultnode_tests PRIVATE vaultnode_core vaultnode_hardening)

add_test(NAME vaultnode_tests COMMAND vaultnode_tests)
if(VAULTNODE_SANITIZE)
  set_tests_properties(vaultnode_tests PROPERTIES ENVIRONMENT
    "ASAN_OPTIONS=detect_leaks=1:abort_on_error=1;UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1")
endif()

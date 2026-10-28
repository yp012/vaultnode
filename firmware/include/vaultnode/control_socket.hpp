// Test-only fault-injection control socket (TCP 5556, PROTOCOL.md 4.1).
// UNAUTHENTICATED. Exists only when built with -DVAULTNODE_SIM_CONTROL=ON.
#pragma once

#ifndef VAULTNODE_SIM_CONTROL
#error "control_socket.hpp included without VAULTNODE_SIM_CONTROL"
#endif

#include <cstdint>

namespace vaultnode::sim {

constexpr std::uint16_t kControlPort = 5556;

// Stub; the real implementation comes in a later step.
const char* control_socket_banner();

}  // namespace vaultnode::sim

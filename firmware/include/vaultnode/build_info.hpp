// Build and dependency information. Stub module that proves every dependency
// links; real modules (crypto, reader, mqtt, sensors, lockout) come later.
#pragma once

#include <string>

namespace vaultnode {

std::string firmware_version();
std::string openssl_version();
std::string mosquitto_version();
std::string json_version();

// True when the unauthenticated control socket was compiled in.
constexpr bool sim_control_enabled() {
#ifdef VAULTNODE_SIM_CONTROL
    return true;
#else
    return false;
#endif
}

}  // namespace vaultnode

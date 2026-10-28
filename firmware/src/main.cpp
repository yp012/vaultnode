// vaultnode-firmware entry point (stub).
#include <cstdio>

#include "vaultnode/build_info.hpp"
#ifdef VAULTNODE_SIM_CONTROL
#include "vaultnode/control_socket.hpp"
#endif

int main() {
    std::printf("vaultnode-firmware %s (%s, libmosquitto %s, nlohmann_json %s)\n",
                vaultnode::firmware_version().c_str(), vaultnode::openssl_version().c_str(),
                vaultnode::mosquitto_version().c_str(), vaultnode::json_version().c_str());
#ifdef VAULTNODE_SIM_CONTROL
    std::printf("WARNING: %s on port %u\n", vaultnode::sim::control_socket_banner(),
                static_cast<unsigned>(vaultnode::sim::kControlPort));
#endif
    return 0;
}

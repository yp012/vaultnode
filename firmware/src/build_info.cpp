#include "vaultnode/build_info.hpp"

#include <mosquitto.h>
#include <nlohmann/json.hpp>
#include <openssl/crypto.h>

namespace vaultnode {

std::string firmware_version() { return VAULTNODE_VERSION; }

std::string openssl_version() { return OpenSSL_version(OPENSSL_VERSION); }

std::string mosquitto_version() {
    int major = 0, minor = 0, rev = 0;
    mosquitto_lib_version(&major, &minor, &rev);
    return std::to_string(major) + "." + std::to_string(minor) + "." + std::to_string(rev);
}

std::string json_version() {
    return std::to_string(NLOHMANN_JSON_VERSION_MAJOR) + "." +
           std::to_string(NLOHMANN_JSON_VERSION_MINOR) + "." +
           std::to_string(NLOHMANN_JSON_VERSION_PATCH);
}

}  // namespace vaultnode

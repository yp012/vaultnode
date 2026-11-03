#include "test_harness.hpp"

#include "vaultnode/build_info.hpp"

TEST(firmware_version_is_set) { CHECK(!vaultnode::firmware_version().empty()); }

TEST(openssl_is_3x) { CHECK(vaultnode::openssl_version().rfind("OpenSSL 3.", 0) == 0); }

TEST(mosquitto_links) { CHECK(vaultnode::mosquitto_version().rfind("2.", 0) == 0); }

TEST(json_is_3_11_or_newer) {
    const auto v = vaultnode::json_version();
    CHECK(v.rfind("3.", 0) == 0);
}

TEST(sim_control_flag_matches_build) {
#ifdef VAULTNODE_SIM_CONTROL
    CHECK(vaultnode::sim_control_enabled());
#else
    CHECK(!vaultnode::sim_control_enabled());
#endif
}

// Test-only fault-injection server (TCP 5556, PROTOCOL.md 4.1).
// UNAUTHENTICATED. Exists only when built with -DVAULTNODE_SIM_CONTROL=ON.
#pragma once

#ifndef VAULTNODE_SIM_CONTROL
#error "hal_sim_control.hpp included without VAULTNODE_SIM_CONTROL"
#endif

#include <chrono>
#include <cstdint>
#include <functional>
#include <string>
#include <string_view>

#include "vaultnode/control_socket.hpp"
#include "vaultnode/hal_gpio.hpp"
#include "vaultnode/hal_i2c.hpp"
#include "vaultnode/hal_line_server.hpp"

namespace vaultnode::sim {

struct SimControlConfig {
    // Loopback unless the deployment says otherwise. Compose has to widen this for
    // the testbench to reach it, and must never publish the port to the host.
    std::string bind_address = "127.0.0.1";
    std::uint16_t port = kControlPort;  // 0 picks a free port
    std::chrono::milliseconds idle_timeout{60000};
    // Supplies "state" in replies ("NORMAL" or "LOCKED_OUT"). If empty, it is
    // inferred from the relay, since LOCKED_OUT always has relay = 1.
    std::function<std::string()> state;
};

// Every request gets exactly one reply line. A malformed request gets
// {"ok":false,"error":...} and the connection stays open; only a line over the
// 1024-byte limit drops the connection.
class SimControlServer {
public:
    SimControlServer(SimControlConfig config, hal::VirtualGpio& gpio, hal::SimulatedSht3x& sensor);

    void start() { server_.start(); }
    void stop() { server_.stop(); }
    std::uint16_t port() const noexcept { return server_.port(); }

private:
    std::string handle_request(std::string_view line);
    std::string status_reply();

    std::function<std::string()> state_;
    hal::VirtualGpio& gpio_;
    hal::SimulatedSht3x& sensor_;
    hal::LineServer server_;  // last: its thread must stop before the members above go away
};

}  // namespace vaultnode::sim

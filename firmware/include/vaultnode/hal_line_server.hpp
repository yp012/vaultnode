// Newline-framed TCP server shared by the reader channel and the control socket.
// One thread multiplexes every connection with poll(), so a stalled client
// cannot hold up the others.
#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <string_view>
#include <thread>

#include "vaultnode/hal_fd.hpp"

namespace vaultnode::hal {

struct LineServerConfig {
    std::string bind_address = "127.0.0.1";  // IPv4 literal
    std::uint16_t port = 0;                  // 0 picks a free port; see LineServer::port()
    std::size_t max_line_bytes = 1024;       // including the newline
    // A connection is closed if this long passes without a complete line.
    // Partial data does not extend it, so a slow drip of bytes cannot hold a slot.
    std::chrono::milliseconds read_timeout{10000};
    std::size_t max_connections = 16;  // connections beyond this are accepted and closed
};

struct LineResult {
    std::string reply;   // sent with a trailing newline; empty sends nothing
    bool close = false;  // close once the reply is flushed; remaining input is discarded
};

// Runs on the server thread. The line excludes the newline and is not validated
// in any way (it may be empty, or contain NUL or invalid UTF-8). A handler that
// throws has its connection closed. Handlers must not call stop().
using LineHandler = std::function<LineResult(std::uint64_t connection_id, std::string_view line)>;

// Called once per connection after it closes, however it closed. May be empty.
using CloseHandler = std::function<void(std::uint64_t connection_id)>;

class LineServer {
public:
    LineServer(LineServerConfig config, LineHandler on_line, CloseHandler on_close = {});
    ~LineServer();

    LineServer(const LineServer&) = delete;
    LineServer& operator=(const LineServer&) = delete;

    // Binds and listens before returning, so clients can connect immediately.
    // Throws std::runtime_error if the socket cannot be set up or already running.
    void start();

    // Closes all connections and joins the thread. Safe to call repeatedly.
    void stop();

    // The bound port once started (it stays readable after stop()).
    std::uint16_t port() const noexcept { return port_; }

private:
    void run();

    LineServerConfig config_;
    LineHandler on_line_;
    CloseHandler on_close_;
    std::uint16_t port_ = 0;
    UniqueFd listen_fd_;
    UniqueFd wake_fd_;
    std::thread thread_;
};

}  // namespace vaultnode::hal

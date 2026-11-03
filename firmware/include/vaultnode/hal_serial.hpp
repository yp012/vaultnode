// Virtual serial RFID reader: the transport of the reader channel (PROTOCOL.md 2).
// It enforces framing only. Invalid UTF-8 or JSON is the line handler's to detect:
// it must return LineResult{"", true} so the connection closes without a reply.
#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string>

#include "vaultnode/hal_line_server.hpp"

namespace vaultnode::hal {

constexpr std::uint16_t kSerialPort = 5555;
constexpr std::size_t kSerialMaxLineBytes = 1024;  // including the newline
constexpr std::chrono::milliseconds kSerialReadTimeout{10000};

struct SerialReaderConfig {
    std::string bind_address = "127.0.0.1";
    std::uint16_t port = kSerialPort;  // 0 picks a free port
    std::chrono::milliseconds read_timeout = kSerialReadTimeout;
};

class VirtualSerialReader {
public:
    VirtualSerialReader(SerialReaderConfig config, LineHandler on_line, CloseHandler on_close = {});

    void start() { server_.start(); }
    void stop() { server_.stop(); }
    std::uint16_t port() const noexcept { return server_.port(); }

private:
    LineServer server_;
};

}  // namespace vaultnode::hal

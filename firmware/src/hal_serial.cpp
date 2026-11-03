#include "vaultnode/hal_serial.hpp"

#include <utility>

namespace vaultnode::hal {

namespace {

LineServerConfig to_line_config(SerialReaderConfig config) {
    LineServerConfig line;
    line.bind_address = std::move(config.bind_address);
    line.port = config.port;
    line.max_line_bytes = kSerialMaxLineBytes;
    line.read_timeout = config.read_timeout;
    return line;
}

}  // namespace

VirtualSerialReader::VirtualSerialReader(SerialReaderConfig config, LineHandler on_line, CloseHandler on_close)
    : server_(to_line_config(std::move(config)), std::move(on_line), std::move(on_close)) {}

}  // namespace vaultnode::hal

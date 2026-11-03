// Loopback TCP client for the socket tests.
#pragma once

#include <arpa/inet.h>
#include <dirent.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include "vaultnode/hal_fd.hpp"

namespace vn_test {

constexpr std::chrono::milliseconds kIoWait{5000};

class TestClient {
public:
    explicit TestClient(std::uint16_t port) : fd_(::socket(AF_INET, SOCK_STREAM, 0)) {
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        connected_ = ::connect(fd_.get(), reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) == 0;
    }

    bool connected() const { return connected_; }

    // False if the peer has already gone away.
    bool send_all(std::string_view data) {
        std::size_t sent = 0;
        while (sent < data.size()) {
            const ssize_t n = ::send(fd_.get(), data.data() + sent, data.size() - sent, MSG_NOSIGNAL);
            if (n <= 0) return false;
            sent += static_cast<std::size_t>(n);
        }
        return true;
    }

    // The next line without its newline; std::nullopt on close, error, or timeout.
    std::optional<std::string> read_line(std::chrono::milliseconds wait = kIoWait) {
        for (;;) {
            const auto newline = buffer_.find('\n');
            if (newline != std::string::npos) {
                std::string line = buffer_.substr(0, newline);
                buffer_.erase(0, newline + 1);
                return line;
            }
            if (fill(wait) <= 0) return std::nullopt;
        }
    }

    // True if the server closes the connection in time. Discards any data before the close.
    bool wait_closed(std::chrono::milliseconds wait = kIoWait) {
        const auto give_up = std::chrono::steady_clock::now() + wait;
        while (std::chrono::steady_clock::now() < give_up) {
            const ssize_t n = fill(wait);
            if (n == 0 || (n < 0 && !timed_out_)) return true;
        }
        return false;
    }

    // True if nothing arrives and the connection stays up for the whole wait.
    bool stays_open_and_silent(std::chrono::milliseconds wait) {
        return fill(wait) < 0 && timed_out_;
    }

    void close() { fd_.reset(); }

private:
    // Bytes read, 0 on orderly close, -1 on error or timeout (timed_out_ tells which).
    ssize_t fill(std::chrono::milliseconds wait) {
        timed_out_ = false;
        pollfd pfd{fd_.get(), POLLIN, 0};
        const int ready = ::poll(&pfd, 1, static_cast<int>(wait.count()));
        if (ready == 0) timed_out_ = true;
        if (ready <= 0) return -1;
        char chunk[4096];
        const ssize_t n = ::recv(fd_.get(), chunk, sizeof(chunk), 0);
        if (n > 0) buffer_.append(chunk, static_cast<std::size_t>(n));
        return n;
    }

    vaultnode::hal::UniqueFd fd_;
    std::string buffer_;
    bool connected_ = false;
    bool timed_out_ = false;
};

inline int open_fd_count() {
    int count = 0;
    DIR* dir = ::opendir("/proc/self/fd");
    if (dir == nullptr) return -1;
    while (::readdir(dir) != nullptr) ++count;
    ::closedir(dir);
    return count;
}

}  // namespace vn_test

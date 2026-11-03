// RAII owner of a POSIX file descriptor. This is the only place in the firmware
// that calls close().
#pragma once

#include <unistd.h>

#include <utility>

namespace vaultnode::hal {

class UniqueFd {
public:
    UniqueFd() noexcept = default;
    explicit UniqueFd(int fd) noexcept : fd_(fd) {}
    ~UniqueFd() { reset(); }

    UniqueFd(const UniqueFd&) = delete;
    UniqueFd& operator=(const UniqueFd&) = delete;
    UniqueFd(UniqueFd&& other) noexcept : fd_(std::exchange(other.fd_, -1)) {}
    UniqueFd& operator=(UniqueFd&& other) noexcept {
        if (this != &other) reset(std::exchange(other.fd_, -1));
        return *this;
    }

    int get() const noexcept { return fd_; }
    bool valid() const noexcept { return fd_ >= 0; }

    // close() is not retried on EINTR: on Linux the descriptor is already released.
    void reset(int fd = -1) noexcept {
        if (fd_ >= 0) ::close(fd_);
        fd_ = fd;
    }

private:
    int fd_ = -1;
};

}  // namespace vaultnode::hal

#include "vaultnode/hal_line_server.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <exception>
#include <stdexcept>
#include <utility>
#include <vector>

namespace vaultnode::hal {

namespace {

using Clock = std::chrono::steady_clock;

constexpr std::size_t kReadChunk = 4096;
constexpr std::size_t kMaxPendingOutput = 64 * 1024;  // a client that never reads gets dropped
constexpr int kMaxAcceptsPerPass = 16;
constexpr std::chrono::milliseconds kAcceptBackoff{100};  // e.g. after EMFILE

[[noreturn]] void throw_errno(const std::string& what) {
    throw std::runtime_error(what + ": " + std::strerror(errno));
}

struct Connection {
    std::uint64_t id;
    UniqueFd fd;
    Clock::time_point deadline;
    std::string in;
    std::string out;
    bool closing = false;  // no more input; close once out has drained
    bool dead = false;     // close now
};

class ConnectionIo {
public:
    ConnectionIo(const LineServerConfig& config, const LineHandler& on_line)
        : config_(config), on_line_(on_line) {}

    void service(Connection& c, short revents, Clock::time_point now) {
        if (revents & (POLLIN | POLLHUP | POLLERR)) {
            if (c.closing) {
                if (revents & (POLLHUP | POLLERR)) c.dead = true;
            } else {
                read_some(c, now);
            }
        }
        if (!c.dead && !c.out.empty()) flush(c);
        if (c.closing && c.out.empty()) c.dead = true;
        if (now >= c.deadline) c.dead = true;
    }

private:
    void begin_close(Connection& c, Clock::time_point now) const {
        c.closing = true;
        c.in.clear();
        c.deadline = now + config_.read_timeout;  // bounds the time spent flushing
    }

    void read_some(Connection& c, Clock::time_point now) const {
        std::array<char, kReadChunk> chunk;
        const ssize_t n = ::recv(c.fd.get(), chunk.data(), chunk.size(), 0);
        if (n == 0) {
            begin_close(c, now);  // a trailing partial line is discarded
            return;
        }
        if (n < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) c.dead = true;
            return;
        }
        c.in.append(chunk.data(), static_cast<std::size_t>(n));
        process_lines(c, now);
    }

    void process_lines(Connection& c, Clock::time_point now) const {
        std::size_t start = 0;
        while (!c.closing) {
            const std::size_t newline = c.in.find('\n', start);
            if (newline == std::string::npos) break;
            if (newline - start + 1 > config_.max_line_bytes) {
                begin_close(c, now);
                return;
            }
            c.deadline = now + config_.read_timeout;
            handle_line(c, std::string_view(c.in).substr(start, newline - start), now);
            start = newline + 1;
        }
        if (c.closing) return;
        c.in.erase(0, start);
        // No newline yet, and with one the line would already be over the limit.
        if (c.in.size() >= config_.max_line_bytes) begin_close(c, now);
    }

    void handle_line(Connection& c, std::string_view line, Clock::time_point now) const {
        LineResult result;
        try {
            result = on_line_(c.id, line);
        } catch (const std::exception& e) {
            std::fprintf(stderr, "line server: handler threw: %s\n", e.what());
            result = LineResult{{}, true};
        } catch (...) {
            std::fprintf(stderr, "line server: handler threw\n");
            result = LineResult{{}, true};
        }
        if (!result.reply.empty()) {
            if (c.out.size() + result.reply.size() + 1 > kMaxPendingOutput) {
                c.dead = true;
                result.close = true;
            } else {
                c.out += result.reply;
                c.out += '\n';
            }
        }
        // begin_close clears c.in, which line points into: nothing may use line after this.
        if (result.close) begin_close(c, now);
    }

    static void flush(Connection& c) {
        std::size_t sent = 0;
        while (sent < c.out.size()) {
            const ssize_t n = ::send(c.fd.get(), c.out.data() + sent, c.out.size() - sent, MSG_NOSIGNAL);
            if (n > 0) {
                sent += static_cast<std::size_t>(n);
            } else if (n < 0 && errno == EINTR) {
                continue;
            } else {
                if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) c.dead = true;
                break;
            }
        }
        c.out.erase(0, sent);
    }

    const LineServerConfig& config_;
    const LineHandler& on_line_;
};

}  // namespace

LineServer::LineServer(LineServerConfig config, LineHandler on_line, CloseHandler on_close)
    : config_(std::move(config)), on_line_(std::move(on_line)), on_close_(std::move(on_close)) {
    if (!on_line_) throw std::invalid_argument("line server: line handler is required");
}

LineServer::~LineServer() { stop(); }

void LineServer::start() {
    if (thread_.joinable()) throw std::runtime_error("line server: already running");

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(config_.port);
    if (::inet_pton(AF_INET, config_.bind_address.c_str(), &addr.sin_addr) != 1) {
        throw std::runtime_error("line server: invalid bind address: " + config_.bind_address);
    }

    UniqueFd listener(::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0));
    if (!listener.valid()) throw_errno("line server: socket");
    const int one = 1;
    if (::setsockopt(listener.get(), SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) != 0) {
        throw_errno("line server: SO_REUSEADDR");
    }
    if (::bind(listener.get(), reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) != 0) {
        throw_errno("line server: bind port " + std::to_string(config_.port));
    }
    if (::listen(listener.get(), SOMAXCONN) != 0) throw_errno("line server: listen");

    sockaddr_in bound{};
    socklen_t bound_len = sizeof(bound);
    if (::getsockname(listener.get(), reinterpret_cast<sockaddr*>(&bound), &bound_len) != 0) {
        throw_errno("line server: getsockname");
    }

    UniqueFd wake(::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC));
    if (!wake.valid()) throw_errno("line server: eventfd");

    listen_fd_ = std::move(listener);
    wake_fd_ = std::move(wake);
    port_ = ntohs(bound.sin_port);
    thread_ = std::thread([this] { run(); });
}

void LineServer::stop() {
    if (!thread_.joinable()) return;
    const std::uint64_t one = 1;
    // Only fails if the counter is saturated, in which case poll() is already woken.
    if (::write(wake_fd_.get(), &one, sizeof(one)) < 0) {
        std::fprintf(stderr, "line server: wake failed: %s\n", std::strerror(errno));
    }
    thread_.join();
    listen_fd_.reset();
    wake_fd_.reset();
}

void LineServer::run() {
    std::vector<Connection> connections;
    std::vector<pollfd> fds;
    ConnectionIo io(config_, on_line_);
    Clock::time_point accept_resume{};
    std::uint64_t next_id = 1;

    const auto notify_closed = [this](const Connection& c) {
        if (!on_close_) return;
        try {
            on_close_(c.id);
        } catch (...) {
            std::fprintf(stderr, "line server: close handler threw\n");
        }
    };

    for (;;) {
        const Clock::time_point before = Clock::now();
        const bool accepting = before >= accept_resume;

        fds.clear();
        fds.push_back({wake_fd_.get(), POLLIN, 0});
        fds.push_back({accepting ? listen_fd_.get() : -1, POLLIN, 0});  // poll ignores fd < 0
        for (const auto& c : connections) {
            const short events = static_cast<short>((c.closing ? 0 : POLLIN) | (c.out.empty() ? 0 : POLLOUT));
            fds.push_back({c.fd.get(), events, 0});
        }

        int timeout_ms = -1;
        const auto consider = [&](Clock::time_point when) {
            const auto ms = std::chrono::ceil<std::chrono::milliseconds>(when - before).count();
            const int clamped = static_cast<int>(std::clamp<std::int64_t>(ms, 0, 60000));
            timeout_ms = timeout_ms < 0 ? clamped : std::min(timeout_ms, clamped);
        };
        for (const auto& c : connections) consider(c.deadline);
        if (!accepting) consider(accept_resume);

        if (::poll(fds.data(), fds.size(), timeout_ms) < 0) {
            if (errno == EINTR) continue;
            std::fprintf(stderr, "line server: poll: %s\n", std::strerror(errno));
            break;
        }
        if (fds[0].revents != 0) break;  // stop() was called

        const Clock::time_point now = Clock::now();
        for (std::size_t i = 0; i < connections.size(); ++i) {
            io.service(connections[i], fds[i + 2].revents, now);
        }

        const auto first_dead = std::stable_partition(connections.begin(), connections.end(),
                                                      [](const Connection& c) { return !c.dead; });
        for (auto it = first_dead; it != connections.end(); ++it) {
            it->fd.reset();
            notify_closed(*it);
        }
        connections.erase(first_dead, connections.end());

        if (fds[1].revents == 0) continue;
        for (int i = 0; i < kMaxAcceptsPerPass; ++i) {
            UniqueFd client(::accept4(listen_fd_.get(), nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC));
            if (!client.valid()) {
                // Out of descriptors and the like: the listener stays readable,
                // so back off rather than spin on it.
                if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR && errno != ECONNABORTED) {
                    std::fprintf(stderr, "line server: accept: %s\n", std::strerror(errno));
                    accept_resume = now + kAcceptBackoff;
                }
                break;
            }
            if (connections.size() >= config_.max_connections) continue;  // client closes here
            const int one = 1;
            // Replies are short request/response lines; do not let Nagle delay them.
            ::setsockopt(client.get(), IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
            Connection c;
            c.id = next_id++;
            c.fd = std::move(client);
            c.deadline = now + config_.read_timeout;
            connections.push_back(std::move(c));
        }
    }

    for (auto& c : connections) {
        c.fd.reset();
        notify_closed(c);
    }
}

}  // namespace vaultnode::hal

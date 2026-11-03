#include <fcntl.h>
#include <unistd.h>

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <set>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include "test_harness.hpp"
#include "test_net.hpp"
#include "vaultnode/hal_serial.hpp"

using namespace std::chrono_literals;
using vaultnode::hal::CloseHandler;
using vaultnode::hal::kSerialMaxLineBytes;
using vaultnode::hal::kSerialPort;
using vaultnode::hal::kSerialReadTimeout;
using vaultnode::hal::LineResult;
using vaultnode::hal::LineServer;
using vaultnode::hal::LineServerConfig;
using vaultnode::hal::SerialReaderConfig;
using vaultnode::hal::UniqueFd;
using vaultnode::hal::VirtualSerialReader;
using vn_test::TestClient;

namespace {

// Echoes each line back as "ack:<line>" so a client can synchronize on delivery.
class Recorder {
public:
    LineResult on_line(std::uint64_t, std::string_view line) {
        const std::lock_guard<std::mutex> lock(mu_);
        lines_.emplace_back(line);
        return {"ack:" + std::string(line), false};
    }
    void on_close(std::uint64_t id) {
        const std::lock_guard<std::mutex> lock(mu_);
        closed_.push_back(id);
        closed_cv_.notify_all();
    }
    std::vector<std::string> lines() {
        const std::lock_guard<std::mutex> lock(mu_);
        return lines_;
    }
    std::vector<std::uint64_t> closed() {
        const std::lock_guard<std::mutex> lock(mu_);
        return closed_;
    }
    bool wait_closed_count(std::size_t n) {
        std::unique_lock<std::mutex> lock(mu_);
        return closed_cv_.wait_for(lock, vn_test::kIoWait, [&] { return closed_.size() >= n; });
    }

private:
    std::mutex mu_;
    std::condition_variable closed_cv_;
    std::vector<std::string> lines_;
    std::vector<std::uint64_t> closed_;
};

struct Fixture {
    explicit Fixture(std::chrono::milliseconds timeout = 10s)
        : reader(make_config(timeout),
                 [this](std::uint64_t id, std::string_view line) { return recorder.on_line(id, line); },
                 [this](std::uint64_t id) { recorder.on_close(id); }) {
        reader.start();
    }

    static SerialReaderConfig make_config(std::chrono::milliseconds timeout) {
        SerialReaderConfig config;
        config.port = 0;
        config.read_timeout = timeout;
        return config;
    }

    Recorder recorder;
    VirtualSerialReader reader;
};

}  // namespace

TEST(serial_defaults_match_protocol) {
    CHECK_EQ(kSerialPort, 5555);
    CHECK_EQ(kSerialMaxLineBytes, 1024U);
    CHECK_EQ(kSerialReadTimeout.count(), 10000);
    const SerialReaderConfig config;
    CHECK_EQ(config.port, 5555);
    CHECK_EQ(config.read_timeout.count(), 10000);
}

TEST(serial_port_is_configurable) {
    Fixture f;
    CHECK(f.reader.port() != 0);
    TestClient client(f.reader.port());
    CHECK(client.connected());
}

TEST(serial_reassembles_partial_line) {
    Fixture f;
    TestClient client(f.reader.port());
    CHECK(client.send_all("{\"type\":"));
    CHECK(client.stays_open_and_silent(100ms));  // nothing delivered yet
    CHECK(f.recorder.lines().empty());
    CHECK(client.send_all("\"hel"));
    CHECK(client.stays_open_and_silent(50ms));
    CHECK(client.send_all("lo\"}\n"));
    CHECK_EQ(client.read_line().value_or(""), "ack:{\"type\":\"hello\"}");
    CHECK_EQ(f.recorder.lines().size(), 1U);
}

TEST(serial_splits_two_lines_in_one_send) {
    Fixture f;
    TestClient client(f.reader.port());
    CHECK(client.send_all("first\nsecond\n"));
    CHECK_EQ(client.read_line().value_or(""), "ack:first");
    CHECK_EQ(client.read_line().value_or(""), "ack:second");
    CHECK(f.recorder.lines() == (std::vector<std::string>{"first", "second"}));
}

TEST(serial_handles_line_and_a_half_across_sends) {
    Fixture f;
    TestClient client(f.reader.port());
    CHECK(client.send_all("one\ntw"));
    CHECK_EQ(client.read_line().value_or(""), "ack:one");
    CHECK(client.send_all("o\nthree\n"));
    CHECK_EQ(client.read_line().value_or(""), "ack:two");
    CHECK_EQ(client.read_line().value_or(""), "ack:three");
}

TEST(serial_handles_many_lines_larger_than_a_read_chunk) {
    Fixture f;
    TestClient client(f.reader.port());
    std::string burst;
    const int count = 2000;  // ~20 KB, several times the server's read chunk
    for (int i = 0; i < count; ++i) burst += "line-" + std::to_string(i) + "\n";
    CHECK(client.send_all(burst));
    for (int i = 0; i < count; ++i) {
        const auto expected = "ack:line-" + std::to_string(i);
        const auto got = client.read_line();
        if (got != expected) {
            CHECK_EQ(got.value_or("<none>"), expected);
            break;
        }
    }
}

TEST(serial_accepts_line_of_exactly_max_length) {
    Fixture f;
    TestClient client(f.reader.port());
    const std::string payload(kSerialMaxLineBytes - 1, 'x');  // 1024 bytes with the newline
    CHECK(client.send_all(payload + "\n"));
    CHECK_EQ(client.read_line().value_or(""), "ack:" + payload);
}

TEST(serial_drops_oversize_line_with_newline) {
    Fixture f;
    TestClient client(f.reader.port());
    CHECK(client.send_all(std::string(kSerialMaxLineBytes, 'x') + "\n"));  // 1025 bytes
    CHECK(client.wait_closed());
    CHECK(f.recorder.lines().empty());
}

TEST(serial_drops_oversize_line_before_any_newline) {
    Fixture f;
    TestClient client(f.reader.port());
    // The newline could only be byte 1025, so there is no reason to wait for it.
    CHECK(client.send_all(std::string(kSerialMaxLineBytes, 'x')));
    CHECK(client.wait_closed());
    CHECK(f.recorder.lines().empty());
}

TEST(serial_keeps_connection_at_longest_possible_partial) {
    Fixture f;
    TestClient client(f.reader.port());
    const std::string payload(kSerialMaxLineBytes - 1, 'x');
    CHECK(client.send_all(payload));
    CHECK(client.stays_open_and_silent(100ms));
    CHECK(client.send_all("\n"));
    CHECK_EQ(client.read_line().value_or(""), "ack:" + payload);
}

TEST(serial_delivers_valid_line_before_oversize_then_drops) {
    Fixture f;
    TestClient client(f.reader.port());
    CHECK(client.send_all("ok\n" + std::string(kSerialMaxLineBytes, 'x') + "\nafter\n"));
    CHECK_EQ(client.read_line().value_or(""), "ack:ok");
    CHECK(client.wait_closed());
    CHECK(f.recorder.lines() == (std::vector<std::string>{"ok"}));
}

TEST(serial_oversize_drop_does_not_affect_other_clients) {
    Fixture f;
    TestClient good(f.reader.port());
    TestClient bad(f.reader.port());
    CHECK(bad.send_all(std::string(5000, 'x')));
    CHECK(bad.wait_closed());
    CHECK(good.send_all("still here\n"));
    CHECK_EQ(good.read_line().value_or(""), "ack:still here");
}

TEST(serial_passes_empty_and_binary_lines_to_handler) {
    Fixture f;
    TestClient client(f.reader.port());
    const std::string binary("a\0b\xff", 4);
    CHECK(client.send_all("\n" + binary + "\n"));
    CHECK_EQ(client.read_line().value_or("x"), "ack:");
    CHECK_EQ(client.read_line().value_or("x"), "ack:" + binary);
}

TEST(serial_times_out_silent_connection) {
    Fixture f(150ms);
    TestClient client(f.reader.port());
    const auto start = std::chrono::steady_clock::now();
    CHECK(client.wait_closed());
    CHECK(std::chrono::steady_clock::now() - start >= 140ms);
}

TEST(serial_partial_bytes_do_not_extend_timeout) {
    Fixture f(300ms);
    TestClient client(f.reader.port());
    const auto start = std::chrono::steady_clock::now();
    // Drip bytes for longer than the timeout, without ever finishing a line.
    bool closed_early = false;
    while (std::chrono::steady_clock::now() - start < 2s) {
        if (!client.send_all("x") || !client.stays_open_and_silent(50ms)) {
            closed_early = true;
            break;
        }
    }
    CHECK(closed_early);
    CHECK(std::chrono::steady_clock::now() - start < 2s);
    CHECK(f.recorder.lines().empty());
}

TEST(serial_complete_line_restarts_timeout) {
    Fixture f(400ms);
    TestClient client(f.reader.port());
    for (int i = 0; i < 4; ++i) {
        CHECK(client.stays_open_and_silent(200ms));
        CHECK(client.send_all("tick\n"));
        CHECK_EQ(client.read_line().value_or(""), "ack:tick");
    }
    CHECK(client.wait_closed());
}

TEST(serial_stalled_client_does_not_block_others) {
    Fixture f;
    TestClient stalled(f.reader.port());
    CHECK(stalled.send_all("partial"));
    TestClient other(f.reader.port());
    CHECK(other.send_all("hello\n"));
    CHECK_EQ(other.read_line(1s).value_or(""), "ack:hello");
}

TEST(serial_handler_can_reply_and_close) {
    VirtualSerialReader reader(
        Fixture::make_config(10s), [](std::uint64_t, std::string_view line) {
            if (line == "bad") return LineResult{"", true};
            if (line == "bye") return LineResult{"goodbye", true};
            return LineResult{"ok", false};
        });
    reader.start();

    TestClient silent(reader.port());
    CHECK(silent.send_all("bad\nnever-processed\n"));
    CHECK(silent.wait_closed());

    TestClient polite(reader.port());
    CHECK(polite.send_all("fine\nbye\nnever-processed\n"));
    CHECK_EQ(polite.read_line().value_or(""), "ok");
    CHECK_EQ(polite.read_line().value_or(""), "goodbye");
    CHECK(!polite.read_line().has_value());  // closed, and no third reply
}

TEST(serial_handler_exception_closes_only_that_connection) {
    VirtualSerialReader reader(
        Fixture::make_config(10s), [](std::uint64_t, std::string_view line) -> LineResult {
            if (line == "boom") throw std::runtime_error("expected test error");
            if (line == "boom2") throw 42;
            return {"ok", false};
        });
    reader.start();
    for (const char* trigger : {"boom\n", "boom2\n"}) {
        TestClient client(reader.port());
        CHECK(client.send_all(trigger));
        CHECK(client.wait_closed());
    }
    TestClient after(reader.port());
    CHECK(after.send_all("x\n"));
    CHECK_EQ(after.read_line().value_or(""), "ok");
}

TEST(serial_client_disconnect_discards_partial_line_and_notifies) {
    Fixture f;
    {
        TestClient client(f.reader.port());
        CHECK(client.send_all("complete\nincomplete"));
        CHECK_EQ(client.read_line().value_or(""), "ack:complete");
    }
    CHECK(f.recorder.wait_closed_count(1));
    CHECK(f.recorder.lines() == (std::vector<std::string>{"complete"}));
}

TEST(serial_close_handler_fires_once_per_connection_including_on_stop) {
    Fixture f;
    auto one = std::make_unique<TestClient>(f.reader.port());
    auto two = std::make_unique<TestClient>(f.reader.port());
    CHECK(one->send_all("a\n"));
    CHECK(one->read_line().has_value());
    CHECK(two->send_all("b\n"));
    CHECK(two->read_line().has_value());
    one.reset();
    CHECK(f.recorder.wait_closed_count(1));
    f.reader.stop();
    CHECK(two->wait_closed());
    const auto closed = f.recorder.closed();
    CHECK_EQ(closed.size(), 2U);
    CHECK_EQ(std::set<std::uint64_t>(closed.begin(), closed.end()).size(), 2U);
}

TEST(serial_rejects_connections_over_the_limit_then_recovers) {
    LineServerConfig config;
    config.max_connections = 2;
    LineServer server(config, [](std::uint64_t, std::string_view) { return LineResult{"ok", false}; });
    server.start();

    auto a = std::make_unique<TestClient>(server.port());
    TestClient b(server.port());
    CHECK(a->send_all("x\n"));
    CHECK(a->read_line().has_value());
    CHECK(b.send_all("x\n"));
    CHECK(b.read_line().has_value());

    TestClient rejected(server.port());
    CHECK(rejected.wait_closed());

    a.reset();
    // The slot frees once the server has seen the close; retry until it has.
    bool recovered = false;
    for (int i = 0; i < 200 && !recovered; ++i) {
        TestClient retry(server.port());
        recovered = retry.send_all("x\n") && retry.read_line(200ms).has_value();
    }
    CHECK(recovered);
}

TEST(serial_client_that_never_reads_is_dropped) {
    Fixture f;
    TestClient client(f.reader.port());
    const std::string burst(1000, 'x');
    // Never read the acks. Sending must eventually fail once the server gives up
    // on this client, instead of its output queue growing without bound.
    bool dropped = false;
    const auto start = std::chrono::steady_clock::now();
    const std::string line = burst + "\n";
    while (!dropped && std::chrono::steady_clock::now() - start < 30s) {
        dropped = !client.send_all(line);
    }
    CHECK(dropped);
}

TEST(serial_invalid_config_and_port_conflict_throw) {
    Fixture f;
    SerialReaderConfig busy;
    busy.port = f.reader.port();
    VirtualSerialReader conflict(busy, [](std::uint64_t, std::string_view) { return LineResult{}; });
    bool threw = false;
    try {
        conflict.start();
    } catch (const std::runtime_error&) {
        threw = true;
    }
    CHECK(threw);

    SerialReaderConfig bad_address;
    bad_address.port = 0;
    bad_address.bind_address = "not-an-ip";
    VirtualSerialReader invalid(bad_address, [](std::uint64_t, std::string_view) { return LineResult{}; });
    threw = false;
    try {
        invalid.start();
    } catch (const std::runtime_error&) {
        threw = true;
    }
    CHECK(threw);

    threw = false;
    try {
        f.reader.start();  // already running
    } catch (const std::runtime_error&) {
        threw = true;
    }
    CHECK(threw);

    threw = false;
    try {
        VirtualSerialReader no_handler(SerialReaderConfig{}, nullptr);
    } catch (const std::invalid_argument&) {
        threw = true;
    }
    CHECK(threw);
}

TEST(serial_port_rebinds_while_old_connection_in_time_wait) {
    std::uint16_t port = 0;
    {
        Fixture f;
        port = f.reader.port();
        TestClient client(port);
        CHECK(client.send_all("x\n"));
        CHECK(client.read_line().has_value());
        f.reader.stop();  // the server closes first, so its side lands in TIME_WAIT
        CHECK(client.wait_closed());
        client.close();
    }
    SerialReaderConfig config;
    config.port = port;
    VirtualSerialReader again(config, [](std::uint64_t, std::string_view) { return LineResult{"ok", false}; });
    bool started = true;
    try {
        again.start();  // needs SO_REUSEADDR
    } catch (const std::runtime_error& e) {
        std::fprintf(stderr, "  rebind failed: %s\n", e.what());
        started = false;
    }
    CHECK(started);
}

TEST(serial_can_restart_after_stop) {
    Fixture f;
    f.reader.stop();
    f.reader.stop();  // idempotent
    f.reader.start();
    TestClient client(f.reader.port());
    CHECK(client.send_all("back\n"));
    CHECK_EQ(client.read_line().value_or(""), "ack:back");
}

TEST(serial_leaks_no_file_descriptors) {
    const int before = vn_test::open_fd_count();
    CHECK(before > 0);
    {
        Fixture f(100ms);
        for (int i = 0; i < 20; ++i) {
            TestClient client(f.reader.port());
            switch (i % 4) {
                case 0:
                    client.send_all("line\n");
                    client.read_line();
                    break;
                case 1:
                    client.send_all(std::string(2000, 'x'));
                    client.wait_closed();
                    break;
                case 2:
                    client.wait_closed();  // timeout
                    break;
                default:
                    break;  // client just disconnects
            }
        }
        TestClient held_open_across_stop(f.reader.port());
        f.reader.stop();
    }
    CHECK_EQ(vn_test::open_fd_count(), before);
}

TEST(unique_fd_owns_and_moves) {
    int fds[2] = {-1, -1};
    CHECK_EQ(::pipe(fds), 0);
    const int read_end = fds[0];
    const int write_end = fds[1];
    const auto is_open = [](int fd) { return ::fcntl(fd, F_GETFD) != -1; };
    {
        UniqueFd a(read_end);
        UniqueFd write_owner(write_end);
        CHECK(a.valid());
        UniqueFd b(std::move(a));
        CHECK(!a.valid());
        CHECK_EQ(b.get(), read_end);
        CHECK(is_open(read_end));

        UniqueFd c;
        c = std::move(b);
        CHECK(!b.valid());
        CHECK(is_open(read_end));

        UniqueFd& self = c;
        c = std::move(self);  // self-move keeps the descriptor
        CHECK(is_open(read_end));

        c = std::move(write_owner);  // assignment closes what c held
        CHECK(!is_open(read_end));
        CHECK(is_open(write_end));
    }
    CHECK(!is_open(write_end));
}

#include <atomic>
#include <future>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <vector>

#include "test_harness.hpp"
#include "vaultnode/hal_gpio.hpp"

using vaultnode::hal::Edge;
using vaultnode::hal::kPinLed;
using vaultnode::hal::kPinRelay;
using vaultnode::hal::kPinTamper;
using vaultnode::hal::VirtualGpio;

TEST(gpio_pins_match_protocol_and_start_low) {
    CHECK_EQ(kPinTamper, 17);
    CHECK_EQ(kPinRelay, 27);
    VirtualGpio gpio;
    for (const int pin : {kPinTamper, kPinRelay, kPinLed}) {
        CHECK(gpio.read(pin).has_value());
        CHECK(!gpio.read(pin).value_or(true));
    }
}

TEST(gpio_enforces_direction_and_rejects_unknown_pins) {
    VirtualGpio gpio;
    CHECK(!gpio.write(kPinTamper, true));
    CHECK(!gpio.drive_input(kPinRelay, true));
    CHECK(!gpio.read(kPinTamper).value_or(true));
    CHECK(!gpio.read(kPinRelay).value_or(true));

    CHECK(!gpio.read(5).has_value());
    CHECK(!gpio.write(5, true));
    CHECK(!gpio.drive_input(5, true));
    CHECK(!gpio.on_edge(5, Edge::Both, [](int, bool) {}).has_value());
    CHECK(!gpio.on_edge(kPinRelay, Edge::Both, nullptr).has_value());
    CHECK(!gpio.remove_callback(12345));
}

TEST(gpio_callback_fires_on_change_only) {
    VirtualGpio gpio;
    std::vector<bool> levels;
    gpio.on_edge(kPinRelay, Edge::Both, [&](int pin, bool level) {
        CHECK_EQ(pin, kPinRelay);
        levels.push_back(level);
    });

    CHECK(gpio.write(kPinRelay, false));  // already low
    CHECK_EQ(levels.size(), 0U);
    CHECK(gpio.write(kPinRelay, true));
    CHECK_EQ(levels.size(), 1U);
    CHECK(gpio.write(kPinRelay, true));  // repeated value: no edge
    CHECK_EQ(levels.size(), 1U);
    CHECK(gpio.write(kPinRelay, false));
    CHECK_EQ(levels.size(), 2U);
    CHECK(levels == (std::vector<bool>{true, false}));
    CHECK_EQ(gpio.read(kPinRelay).value_or(true), false);
}

TEST(gpio_callback_filters_by_edge_and_pin) {
    VirtualGpio gpio;
    int rising = 0, falling = 0, both = 0;
    gpio.on_edge(kPinTamper, Edge::Rising, [&](int, bool) { ++rising; });
    gpio.on_edge(kPinTamper, Edge::Falling, [&](int, bool) { ++falling; });
    gpio.on_edge(kPinTamper, Edge::Both, [&](int, bool) { ++both; });

    gpio.drive_input(kPinTamper, true);
    gpio.drive_input(kPinTamper, false);
    gpio.drive_input(kPinTamper, true);
    gpio.write(kPinLed, true);  // a different pin

    CHECK_EQ(rising, 2);
    CHECK_EQ(falling, 1);
    CHECK_EQ(both, 3);
}

TEST(gpio_callback_can_call_back_into_gpio) {
    VirtualGpio gpio;
    bool seen_level = false;
    int relay_edges = 0;
    gpio.on_edge(kPinRelay, Edge::Rising, [&](int, bool) { ++relay_edges; });
    // Tamper drives the relay from the callback, as the lockout path will. Holding
    // the internal lock during callbacks would deadlock here (caught by the test timeout).
    gpio.on_edge(kPinTamper, Edge::Rising, [&](int pin, bool) {
        seen_level = gpio.read(pin).value_or(false);
        CHECK(gpio.write(kPinRelay, true));
        const auto id = gpio.on_edge(kPinLed, Edge::Both, [](int, bool) {});
        CHECK(id.has_value());
        CHECK(gpio.remove_callback(id.value_or(0)));
    });

    gpio.drive_input(kPinTamper, true);
    CHECK(seen_level);
    CHECK(gpio.read(kPinRelay).value_or(false));
    CHECK_EQ(relay_edges, 1);
}

TEST(gpio_nested_writes_are_delivered_in_order) {
    VirtualGpio gpio;
    std::vector<int> order;
    gpio.on_edge(kPinRelay, Edge::Both, [&](int, bool) { order.push_back(2); });
    gpio.on_edge(kPinTamper, Edge::Both, [&](int, bool) {
        order.push_back(1);
        gpio.write(kPinRelay, true);
        order.push_back(10);  // the relay edge has not been delivered yet: no recursion
    });
    gpio.drive_input(kPinTamper, true);
    CHECK(order == (std::vector<int>{1, 10, 2}));
}

TEST(gpio_removed_callback_stops_firing_and_can_remove_itself) {
    VirtualGpio gpio;
    int count = 0;
    std::optional<VirtualGpio::CallbackId> id;
    id = gpio.on_edge(kPinLed, Edge::Both, [&](int, bool) {
        ++count;
        CHECK(gpio.remove_callback(*id));
    });
    gpio.write(kPinLed, true);
    gpio.write(kPinLed, false);
    CHECK_EQ(count, 1);
    CHECK(!gpio.remove_callback(*id));
}

TEST(gpio_throwing_callback_does_not_wedge_dispatch) {
    VirtualGpio gpio;
    int later_callback = 0;
    gpio.on_edge(kPinLed, Edge::Both, [](int, bool) { throw std::runtime_error("expected test error"); });
    gpio.on_edge(kPinLed, Edge::Both, [](int, bool) { throw 42; });
    gpio.on_edge(kPinLed, Edge::Both, [&](int, bool) { ++later_callback; });
    CHECK(gpio.write(kPinLed, true));
    CHECK(gpio.write(kPinLed, false));
    CHECK_EQ(later_callback, 2);
}

TEST(gpio_concurrent_edges_arrive_in_order) {
    VirtualGpio gpio;
    // No lock in the callback: delivery must already be serialized (TSan would flag it otherwise).
    int edges = 0;
    bool last = false;
    bool alternates = true;
    gpio.on_edge(kPinLed, Edge::Both, [&](int, bool level) {
        if (level == last) alternates = false;
        last = level;
        ++edges;
    });

    std::vector<std::thread> threads;
    std::atomic<bool> go{false};
    for (int t = 0; t < 4; ++t) {
        threads.emplace_back([&, t] {
            while (!go.load()) std::this_thread::yield();
            for (int i = 0; i < 5000; ++i) gpio.write(kPinLed, (i + t) % 2 == 0);
        });
    }
    go.store(true);
    for (auto& thread : threads) thread.join();

    // Force a final known edge pair so that this thread observes a drained queue.
    int final_edges = 0;
    gpio.on_edge(kPinRelay, Edge::Both, [&](int, bool) { ++final_edges; });
    gpio.write(kPinRelay, true);
    CHECK_EQ(final_edges, 1);
    CHECK(alternates);
    CHECK(edges > 0);
    CHECK_EQ(last, gpio.read(kPinLed).value_or(!last));
}

TEST(gpio_remove_waits_for_in_flight_callback) {
    VirtualGpio gpio;
    std::promise<void> entered;
    std::promise<void> release;
    std::shared_future<void> released(release.get_future());
    std::atomic<bool> finished{false};
    const auto id = gpio.on_edge(kPinLed, Edge::Both, [&](int, bool) {
        entered.set_value();
        released.wait();
        finished.store(true);
    });

    std::thread writer([&] { gpio.write(kPinLed, true); });
    entered.get_future().wait();

    std::atomic<bool> removed{false};
    std::thread remover([&] {
        gpio.remove_callback(id.value_or(0));
        removed.store(true);
        CHECK(finished.load());  // must not return while the callback is still running
    });

    // While the callback is blocked, another thread's edge must not block on the lock.
    CHECK(gpio.write(kPinRelay, true));
    CHECK(!removed.load());

    release.set_value();
    remover.join();
    writer.join();
    CHECK(removed.load());
}

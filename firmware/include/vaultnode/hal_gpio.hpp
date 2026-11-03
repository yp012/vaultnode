// Simulated GPIO (PROTOCOL.md 4). Edge callbacks stand in for interrupts.
#pragma once

#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <thread>
#include <vector>

namespace vaultnode::hal {

constexpr int kPinTamper = 17;  // input: 1 = enclosure open
constexpr int kPinRelay = 27;   // output: 1 = relay engaged (lockout)
constexpr int kPinLed = 22;     // output: status LED (not part of PROTOCOL.md)

enum class Edge { Rising, Falling, Both };

// Edges are delivered in the order they happened, outside the internal lock,
// so a callback may call back into the GPIO. The thread that finds no dispatch
// in progress delivers the queue; consequently:
//   - with no contention, write() returns after its callbacks have run;
//   - a write made from inside a callback, or while another thread is
//     delivering, returns at once and its edge is delivered by that dispatcher.
// A callback that throws is logged and does not affect other callbacks.
class VirtualGpio {
public:
    using EdgeCallback = std::function<void(int pin, bool level)>;
    using CallbackId = std::uint64_t;

    VirtualGpio();

    // std::nullopt for a pin that does not exist.
    std::optional<bool> read(int pin) const;

    // Firmware side: drives an output pin. False if pin is not an output.
    bool write(int pin, bool level);

    // Outside-world side: drives an input pin. False if pin is not an input.
    bool drive_input(int pin, bool level);

    // std::nullopt if the pin does not exist or the callback is empty.
    std::optional<CallbackId> on_edge(int pin, Edge edge, EdgeCallback callback);

    // Once this returns, the callback will not start again and is not running,
    // unless the caller is itself inside a callback (which cannot wait for
    // itself). Do not hold a lock that the callback takes while calling this.
    bool remove_callback(CallbackId id);

private:
    struct Pin {
        bool is_output;
        bool level;
    };
    struct Registration {
        CallbackId id;
        int pin;
        Edge edge;
        std::shared_ptr<const EdgeCallback> callback;
    };
    struct PendingEdge {
        int pin;
        bool level;
    };

    bool set_level(int pin, bool level, bool want_output);
    void dispatch_pending(std::unique_lock<std::mutex>& lock);

    mutable std::mutex mu_;
    std::condition_variable dispatch_progress_;
    std::map<int, Pin> pins_;
    std::vector<Registration> registrations_;
    std::deque<PendingEdge> pending_;
    CallbackId next_id_ = 1;
    bool dispatching_ = false;
    std::thread::id dispatcher_;
    std::uint64_t edges_delivered_ = 0;
};

}  // namespace vaultnode::hal

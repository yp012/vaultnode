#include "vaultnode/hal_gpio.hpp"

#include <algorithm>
#include <cstdio>
#include <exception>
#include <utility>

namespace vaultnode::hal {

namespace {

bool edge_matches(Edge edge, bool level) {
    return edge == Edge::Both || (edge == Edge::Rising) == level;
}

}  // namespace

VirtualGpio::VirtualGpio()
    : pins_{{kPinTamper, {false, false}}, {kPinRelay, {true, false}}, {kPinLed, {true, false}}} {}

std::optional<bool> VirtualGpio::read(int pin) const {
    const std::lock_guard<std::mutex> lock(mu_);
    const auto it = pins_.find(pin);
    if (it == pins_.end()) return std::nullopt;
    return it->second.level;
}

bool VirtualGpio::write(int pin, bool level) { return set_level(pin, level, true); }

bool VirtualGpio::drive_input(int pin, bool level) { return set_level(pin, level, false); }

bool VirtualGpio::set_level(int pin, bool level, bool want_output) {
    std::unique_lock<std::mutex> lock(mu_);
    const auto it = pins_.find(pin);
    if (it == pins_.end() || it->second.is_output != want_output) return false;
    if (it->second.level == level) return true;  // no change, no edge
    it->second.level = level;
    pending_.push_back({pin, level});
    dispatch_pending(lock);
    return true;
}

void VirtualGpio::dispatch_pending(std::unique_lock<std::mutex>& lock) {
    if (dispatching_) return;  // the current dispatcher will deliver our edge
    dispatching_ = true;
    dispatcher_ = std::this_thread::get_id();

    while (!pending_.empty()) {
        const PendingEdge edge = pending_.front();
        pending_.pop_front();

        std::vector<std::shared_ptr<const EdgeCallback>> matching;
        for (const auto& r : registrations_) {
            if (r.pin == edge.pin && edge_matches(r.edge, edge.level)) matching.push_back(r.callback);
        }

        lock.unlock();
        for (const auto& callback : matching) {
            try {
                (*callback)(edge.pin, edge.level);
            } catch (const std::exception& e) {
                std::fprintf(stderr, "gpio: callback on pin %d threw: %s\n", edge.pin, e.what());
            } catch (...) {
                std::fprintf(stderr, "gpio: callback on pin %d threw\n", edge.pin);
            }
        }
        matching.clear();  // drop captured state outside the lock
        lock.lock();

        ++edges_delivered_;
        dispatch_progress_.notify_all();
    }

    dispatching_ = false;
    dispatcher_ = std::thread::id();
    dispatch_progress_.notify_all();
}

std::optional<VirtualGpio::CallbackId> VirtualGpio::on_edge(int pin, Edge edge, EdgeCallback callback) {
    if (!callback) return std::nullopt;
    const std::lock_guard<std::mutex> lock(mu_);
    if (pins_.find(pin) == pins_.end()) return std::nullopt;
    const CallbackId id = next_id_++;
    registrations_.push_back({id, pin, edge, std::make_shared<const EdgeCallback>(std::move(callback))});
    return id;
}

bool VirtualGpio::remove_callback(CallbackId id) {
    std::shared_ptr<const EdgeCallback> removed;  // destroyed after the lock is released
    std::unique_lock<std::mutex> lock(mu_);
    const auto it = std::find_if(registrations_.begin(), registrations_.end(),
                                 [id](const Registration& r) { return r.id == id; });
    if (it == registrations_.end()) return false;
    removed = std::move(it->callback);
    registrations_.erase(it);

    // Only the edge in flight can still hold this callback; later edges build
    // their list after the erase above, so waiting for one delivery is enough.
    if (dispatcher_ != std::this_thread::get_id()) {
        const std::uint64_t seen = edges_delivered_;
        dispatch_progress_.wait(lock, [&] { return !dispatching_ || edges_delivered_ != seen; });
    }
    return true;
}

}  // namespace vaultnode::hal

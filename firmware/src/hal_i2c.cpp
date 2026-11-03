#include "vaultnode/hal_i2c.hpp"

#include <algorithm>
#include <utility>

namespace vaultnode::hal {

bool VirtualI2cBus::attach(std::uint8_t address, std::shared_ptr<I2cDevice> device) {
    if (!device || address > 0x7f) return false;
    const std::lock_guard<std::mutex> lock(mu_);
    return devices_.emplace(address, std::move(device)).second;
}

std::optional<std::uint16_t> VirtualI2cBus::read_register(std::uint8_t address, std::uint8_t reg) {
    std::shared_ptr<I2cDevice> device;
    {
        const std::lock_guard<std::mutex> lock(mu_);
        const auto it = devices_.find(address);
        if (it == devices_.end()) return std::nullopt;
        device = it->second;
    }
    return device->read_register(reg);
}

std::int32_t SimulatedSht3x::Channel::next_drift() {
    const std::int32_t step = static_cast<std::int32_t>(rng() % 5) - 2;  // -2..+2 hundredths
    drift = std::clamp(drift + step, -kMaxDriftX100, kMaxDriftX100);
    return drift;
}

SimulatedSht3x::SimulatedSht3x(std::uint32_t seed) : temp_(seed), humidity_(seed ^ 0x9e3779b9U) {}

std::optional<std::uint16_t> SimulatedSht3x::read_register(std::uint8_t reg) {
    const std::lock_guard<std::mutex> lock(mu_);
    if (reg == kSht3xRegTemperature) {
        if (temp_.override_raw) return temp_.override_raw;
        return sht3x_temp_cx100_to_raw(kDefaultTempCx100 + temp_.next_drift());
    }
    if (reg == kSht3xRegHumidity) {
        if (humidity_.override_raw) return humidity_.override_raw;
        return sht3x_humidity_px100_to_raw(kDefaultHumidityPx100 + humidity_.next_drift());
    }
    return std::nullopt;
}

bool SimulatedSht3x::override_temp_cx100(std::int32_t cx100) {
    if (cx100 < kTempCx100Min || cx100 > kTempCx100Max) return false;
    const std::lock_guard<std::mutex> lock(mu_);
    temp_.override_raw = sht3x_temp_cx100_to_raw(cx100);
    return true;
}

bool SimulatedSht3x::override_humidity_px100(std::int32_t px100) {
    if (px100 < kHumidityPx100Min || px100 > kHumidityPx100Max) return false;
    const std::lock_guard<std::mutex> lock(mu_);
    humidity_.override_raw = sht3x_humidity_px100_to_raw(px100);
    return true;
}

void SimulatedSht3x::reset_overrides() {
    const std::lock_guard<std::mutex> lock(mu_);
    temp_.override_raw.reset();
    humidity_.override_raw.reset();
}

}  // namespace vaultnode::hal

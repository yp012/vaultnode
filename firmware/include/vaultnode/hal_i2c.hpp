// Simulated I2C bus and SHT3x-style temperature/humidity sensor (PROTOCOL.md 4).
// A real SHT3x takes 16-bit commands and returns 6 bytes with CRCs; this model
// keeps only the part the firmware's conversion depends on: raw 16-bit samples.
#pragma once

#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <random>

namespace vaultnode::hal {

constexpr std::uint8_t kSht3xAddress = 0x44;
constexpr std::uint8_t kSht3xRegTemperature = 0x00;
constexpr std::uint8_t kSht3xRegHumidity = 0x01;

// The range the 16-bit SHT3x formulas can represent.
constexpr std::int32_t kTempCx100Min = -4500;
constexpr std::int32_t kTempCx100Max = 13000;
constexpr std::int32_t kHumidityPx100Min = 0;
constexpr std::int32_t kHumidityPx100Max = 10000;

constexpr std::int32_t kDefaultTempCx100 = 2200;
constexpr std::int32_t kDefaultHumidityPx100 = 4000;
constexpr std::int32_t kMaxDriftX100 = 25;  // drift stays within +/-0.25 of the default
constexpr std::uint32_t kDefaultSensorSeed = 0x56544e44;

// temp C = -45 + 175 * raw / 65535, in integer hundredths, rounded to nearest.
constexpr std::int32_t sht3x_raw_to_temp_cx100(std::uint16_t raw) {
    return static_cast<std::int32_t>((std::int64_t{17500} * raw + 32767) / 65535) - 4500;
}

// humidity % = 100 * raw / 65535, in integer hundredths, rounded to nearest.
constexpr std::int32_t sht3x_raw_to_humidity_px100(std::uint16_t raw) {
    return static_cast<std::int32_t>((std::int64_t{10000} * raw + 32767) / 65535);
}

// Inverses, for in-range values only. One raw step is under 0.27 hundredths of
// a unit, so raw -> x100 returns exactly the value given here.
constexpr std::uint16_t sht3x_temp_cx100_to_raw(std::int32_t cx100) {
    return static_cast<std::uint16_t>(((std::int64_t{cx100} + 4500) * 65535 + 8750) / 17500);
}

constexpr std::uint16_t sht3x_humidity_px100_to_raw(std::int32_t px100) {
    return static_cast<std::uint16_t>((std::int64_t{px100} * 65535 + 5000) / 10000);
}

class I2cDevice {
public:
    virtual ~I2cDevice() = default;
    // std::nullopt for a register the device does not have.
    virtual std::optional<std::uint16_t> read_register(std::uint8_t reg) = 0;
};

class VirtualI2cBus {
public:
    // False for a null device, an address above 7 bits, or an occupied address.
    bool attach(std::uint8_t address, std::shared_ptr<I2cDevice> device);

    // std::nullopt (a NACK) if nothing answers at the address or the device has no such register.
    std::optional<std::uint16_t> read_register(std::uint8_t address, std::uint8_t reg);

private:
    std::mutex mu_;
    std::map<std::uint8_t, std::shared_ptr<I2cDevice>> devices_;
};

// Reads follow a bounded random walk around 22.00 C / 40.00 %RH. Each channel
// has its own generator, so for a given seed the sequence of a channel depends
// only on how many times that channel has been read. An override returns its
// exact value without drift, so threshold tests are not perturbed by noise.
class SimulatedSht3x : public I2cDevice {
public:
    explicit SimulatedSht3x(std::uint32_t seed = kDefaultSensorSeed);

    std::optional<std::uint16_t> read_register(std::uint8_t reg) override;

    // False, with nothing changed, if the value is outside the sensor's range.
    bool override_temp_cx100(std::int32_t cx100);
    bool override_humidity_px100(std::int32_t px100);

    // Back to the walk, which resumes where it left off.
    void reset_overrides();

private:
    struct Channel {
        explicit Channel(std::uint32_t seed) : rng(seed) {}
        std::int32_t next_drift();

        std::mt19937 rng;
        std::int32_t drift = 0;
        std::optional<std::uint16_t> override_raw;
    };

    std::mutex mu_;
    Channel temp_;
    Channel humidity_;
};

}  // namespace vaultnode::hal

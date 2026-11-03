#include <cstdint>
#include <memory>
#include <thread>
#include <vector>

#include "test_harness.hpp"
#include "vaultnode/hal_i2c.hpp"

using namespace vaultnode::hal;

namespace {

std::int32_t read_temp(SimulatedSht3x& s) {
    return sht3x_raw_to_temp_cx100(s.read_register(kSht3xRegTemperature).value_or(0));
}

std::int32_t read_humidity(SimulatedSht3x& s) {
    return sht3x_raw_to_humidity_px100(s.read_register(kSht3xRegHumidity).value_or(0));
}

}  // namespace

// Expected values worked by hand from temp = -45 + 175 * raw / 65535 and
// humidity = 100 * raw / 65535, as in the SHT3x datasheet.
TEST(sht3x_temp_conversion_at_known_raw_values) {
    CHECK_EQ(sht3x_raw_to_temp_cx100(0), -4500);          // -45.00 C
    CHECK_EQ(sht3x_raw_to_temp_cx100(65535), 13000);      // 130.00 C
    CHECK_EQ(sht3x_raw_to_temp_cx100(16852), 0);          // 0.0000 C (+0.0004 before rounding)
    CHECK_EQ(sht3x_raw_to_temp_cx100(26214), 2500);       // exactly 25.00 C
    CHECK_EQ(sht3x_raw_to_temp_cx100(32768), 4250);       // 42.5013 C
    CHECK_EQ(sht3x_raw_to_temp_cx100(33705), 4500);       // 45.0034 C
    CHECK_EQ(sht3x_raw_to_temp_cx100(1), -4500);          // -44.9973 C rounds to -45.00
    CHECK_EQ(sht3x_raw_to_temp_cx100(2), -4499);          // -44.9947 C rounds to -44.99
}

TEST(sht3x_humidity_conversion_at_known_raw_values) {
    CHECK_EQ(sht3x_raw_to_humidity_px100(0), 0);
    CHECK_EQ(sht3x_raw_to_humidity_px100(65535), 10000);
    CHECK_EQ(sht3x_raw_to_humidity_px100(26214), 4000);   // exactly 40.00 %RH
    CHECK_EQ(sht3x_raw_to_humidity_px100(32768), 5000);   // 50.0008 %RH
    CHECK_EQ(sht3x_raw_to_humidity_px100(55705), 8500);   // 85.0004 %RH
}

TEST(sht3x_conversion_round_trips_every_fixed_point_value) {
    bool temp_ok = true, humidity_ok = true;
    for (std::int32_t v = kTempCx100Min; v <= kTempCx100Max; ++v) {
        temp_ok = temp_ok && sht3x_raw_to_temp_cx100(sht3x_temp_cx100_to_raw(v)) == v;
    }
    for (std::int32_t v = kHumidityPx100Min; v <= kHumidityPx100Max; ++v) {
        humidity_ok = humidity_ok && sht3x_raw_to_humidity_px100(sht3x_humidity_px100_to_raw(v)) == v;
    }
    CHECK(temp_ok);
    CHECK(humidity_ok);
}

TEST(i2c_bus_routes_by_address_and_nacks_otherwise) {
    VirtualI2cBus bus;
    CHECK_EQ(kSht3xAddress, 0x44);
    CHECK(!bus.read_register(kSht3xAddress, kSht3xRegTemperature).has_value());

    auto sensor = std::make_shared<SimulatedSht3x>();
    CHECK(sensor->override_temp_cx100(2500));
    CHECK(bus.attach(kSht3xAddress, sensor));
    CHECK(!bus.attach(kSht3xAddress, std::make_shared<SimulatedSht3x>()));  // occupied
    CHECK(!bus.attach(0x45, nullptr));
    CHECK(!bus.attach(0x80, std::make_shared<SimulatedSht3x>()));  // not a 7-bit address

    CHECK_EQ(bus.read_register(kSht3xAddress, kSht3xRegTemperature).value_or(0), 26214);
    CHECK(!bus.read_register(0x45, kSht3xRegTemperature).has_value());
    CHECK(!bus.read_register(kSht3xAddress, 0x02).has_value());
}

TEST(sht3x_default_reading_stays_near_protocol_default) {
    SimulatedSht3x sensor;
    bool temp_moved = false, humidity_moved = false;
    for (int i = 0; i < 5000; ++i) {
        const auto t = read_temp(sensor);
        const auto h = read_humidity(sensor);
        CHECK(t >= kDefaultTempCx100 - kMaxDriftX100 && t <= kDefaultTempCx100 + kMaxDriftX100);
        CHECK(h >= kDefaultHumidityPx100 - kMaxDriftX100 && h <= kDefaultHumidityPx100 + kMaxDriftX100);
        temp_moved = temp_moved || t != kDefaultTempCx100;
        humidity_moved = humidity_moved || h != kDefaultHumidityPx100;
    }
    CHECK_EQ(kDefaultTempCx100, 2200);
    CHECK_EQ(kDefaultHumidityPx100, 4000);
    CHECK(temp_moved);
    CHECK(humidity_moved);
}

TEST(sht3x_noise_is_reproducible_for_a_seed) {
    SimulatedSht3x a(7), b(7), c(8);
    std::vector<std::uint16_t> seq_a, seq_b, seq_c;
    for (int i = 0; i < 200; ++i) {
        seq_a.push_back(a.read_register(kSht3xRegTemperature).value_or(0));
        seq_b.push_back(b.read_register(kSht3xRegTemperature).value_or(0));
        // Reading the other channel must not shift this one's sequence.
        b.read_register(kSht3xRegHumidity);
        seq_c.push_back(c.read_register(kSht3xRegTemperature).value_or(0));
    }
    CHECK(seq_a == seq_b);
    CHECK(seq_a != seq_c);
}

TEST(sht3x_noise_is_stable_across_builds) {
    // Regression pin, captured from this implementation. std::mt19937's sequence
    // is fixed by the C++ standard, so these must not vary by compiler or platform.
    SimulatedSht3x sensor;
    std::vector<std::int32_t> temps, humidities;
    for (int i = 0; i < 8; ++i) {
        temps.push_back(read_temp(sensor));
        humidities.push_back(read_humidity(sensor));
    }
    CHECK(temps == (std::vector<std::int32_t>{2200, 2198, 2199, 2200, 2198, 2197, 2197, 2196}));
    CHECK(humidities == (std::vector<std::int32_t>{4002, 4002, 4002, 4001, 4001, 3999, 4001, 4003}));
}

TEST(sht3x_override_is_exact_and_clearable) {
    SimulatedSht3x sensor;
    CHECK(sensor.override_temp_cx100(4650));
    CHECK(sensor.override_humidity_px100(9000));
    for (int i = 0; i < 50; ++i) {
        CHECK_EQ(read_temp(sensor), 4650);
        CHECK_EQ(read_humidity(sensor), 9000);
    }

    // The breach boundary is strict (PROTOCOL.md 4): both sides must survive the raw conversion.
    CHECK(sensor.override_temp_cx100(4500));
    CHECK_EQ(read_temp(sensor), 4500);
    CHECK(sensor.override_temp_cx100(4501));
    CHECK_EQ(read_temp(sensor), 4501);
    CHECK(sensor.override_humidity_px100(8500));
    CHECK_EQ(read_humidity(sensor), 8500);
    CHECK(sensor.override_humidity_px100(8501));
    CHECK_EQ(read_humidity(sensor), 8501);

    sensor.reset_overrides();
    const auto t = read_temp(sensor);
    const auto h = read_humidity(sensor);
    CHECK(t >= kDefaultTempCx100 - kMaxDriftX100 && t <= kDefaultTempCx100 + kMaxDriftX100);
    CHECK(h >= kDefaultHumidityPx100 - kMaxDriftX100 && h <= kDefaultHumidityPx100 + kMaxDriftX100);
}

TEST(sht3x_override_rejects_out_of_range_and_keeps_old_value) {
    SimulatedSht3x sensor;
    CHECK(sensor.override_temp_cx100(3000));
    CHECK(sensor.override_humidity_px100(5000));

    CHECK(!sensor.override_temp_cx100(kTempCx100Max + 1));
    CHECK(!sensor.override_temp_cx100(kTempCx100Min - 1));
    CHECK(!sensor.override_humidity_px100(kHumidityPx100Max + 1));
    CHECK(!sensor.override_humidity_px100(-1));
    CHECK_EQ(read_temp(sensor), 3000);
    CHECK_EQ(read_humidity(sensor), 5000);

    CHECK(sensor.override_temp_cx100(kTempCx100Min));
    CHECK_EQ(read_temp(sensor), kTempCx100Min);
    CHECK(sensor.override_temp_cx100(kTempCx100Max));
    CHECK_EQ(read_temp(sensor), kTempCx100Max);
    CHECK(sensor.override_humidity_px100(kHumidityPx100Min));
    CHECK_EQ(read_humidity(sensor), kHumidityPx100Min);
    CHECK(sensor.override_humidity_px100(kHumidityPx100Max));
    CHECK_EQ(read_humidity(sensor), kHumidityPx100Max);
}

TEST(sht3x_is_safe_under_concurrent_reads_and_overrides) {
    VirtualI2cBus bus;
    auto sensor = std::make_shared<SimulatedSht3x>();
    CHECK(bus.attach(kSht3xAddress, sensor));
    std::thread reader([&] {
        for (int i = 0; i < 20000; ++i) bus.read_register(kSht3xAddress, kSht3xRegTemperature);
    });
    std::thread writer([&] {
        for (int i = 0; i < 20000; ++i) {
            sensor->override_temp_cx100(i % 5000);
            sensor->reset_overrides();
        }
    });
    reader.join();
    writer.join();
}

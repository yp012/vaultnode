#include "vaultnode/hal_sim_control.hpp"

#include <nlohmann/json.hpp>

#include <cstdint>
#include <optional>
#include <utility>

namespace vaultnode::sim {

namespace {

using nlohmann::json;

std::string error_reply(const char* error) { return json{{"ok", false}, {"error", error}}.dump(); }

hal::LineServerConfig to_line_config(const SimControlConfig& config) {
    hal::LineServerConfig line;
    line.bind_address = config.bind_address;
    line.port = config.port;
    line.read_timeout = config.idle_timeout;
    return line;
}

// The integer field `key` of an object, if it is present, an integer, and in
// [lo, hi]. Floats are refused: PROTOCOL.md 4.1 carries fixed-point integers only.
std::optional<std::int32_t> int_field(const json& request, const char* key, std::int32_t lo, std::int32_t hi) {
    const auto it = request.find(key);
    if (it == request.end() || !it->is_number_integer()) return std::nullopt;
    // Check the unsigned case separately: a huge uint64 must not wrap to a small int64.
    if (it->is_number_unsigned()) {
        const auto value = it->get<std::uint64_t>();
        if (hi < 0 || value > static_cast<std::uint64_t>(hi)) return std::nullopt;
        if (static_cast<std::int64_t>(value) < lo) return std::nullopt;
        return static_cast<std::int32_t>(value);
    }
    const auto value = it->get<std::int64_t>();
    if (value < lo || value > hi) return std::nullopt;
    return static_cast<std::int32_t>(value);
}

}  // namespace

SimControlServer::SimControlServer(SimControlConfig config, hal::VirtualGpio& gpio, hal::SimulatedSht3x& sensor)
    : state_(std::move(config.state)),
      gpio_(gpio),
      sensor_(sensor),
      server_(to_line_config(config), [this](std::uint64_t, std::string_view line) {
          return hal::LineResult{handle_request(line), false};
      }) {}

std::string SimControlServer::handle_request(std::string_view line) {
    const json request = json::parse(line, nullptr, false);  // no exceptions; invalid UTF-8 is refused too
    if (request.is_discarded() || !request.is_object()) return error_reply("malformed_json");

    const auto op_it = request.find("op");
    if (op_it == request.end() || !op_it->is_string()) return error_reply("missing_op");
    const auto& op = op_it->get_ref<const std::string&>();

    if (op == "tamper") {
        const auto value = request.find("value");
        if (value == request.end() || !value->is_boolean()) return error_reply("bad_value");
        gpio_.drive_input(hal::kPinTamper, value->get<bool>());
    } else if (op == "set_temp") {
        const auto value = int_field(request, "value_cx100", hal::kTempCx100Min, hal::kTempCx100Max);
        if (!value) return error_reply("bad_value");
        sensor_.override_temp_cx100(*value);
    } else if (op == "set_humidity") {
        const auto value = int_field(request, "value_px100", hal::kHumidityPx100Min, hal::kHumidityPx100Max);
        if (!value) return error_reply("bad_value");
        sensor_.override_humidity_px100(*value);
    } else if (op == "clear_overrides") {
        sensor_.reset_overrides();
    } else if (op != "status") {
        return error_reply("unknown_op");
    }
    return status_reply();
}

// A status request counts as a sensor sample, so it advances the simulated drift.
std::string SimControlServer::status_reply() {
    const bool relay = gpio_.read(hal::kPinRelay).value_or(false);
    const bool tamper = gpio_.read(hal::kPinTamper).value_or(false);
    const auto temp_raw = sensor_.read_register(hal::kSht3xRegTemperature);
    const auto humidity_raw = sensor_.read_register(hal::kSht3xRegHumidity);
    if (!temp_raw || !humidity_raw) return error_reply("sensor_read_failed");

    return json{{"ok", true},
                {"state", state_ ? state_() : std::string(relay ? "LOCKED_OUT" : "NORMAL")},
                {"relay", relay ? 1 : 0},
                {"tamper", tamper},
                {"temp_cx100", hal::sht3x_raw_to_temp_cx100(*temp_raw)},
                {"humidity_px100", hal::sht3x_raw_to_humidity_px100(*humidity_raw)}}
        .dump();
}

}  // namespace vaultnode::sim

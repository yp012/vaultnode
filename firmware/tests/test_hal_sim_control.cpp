// Compiled only when VAULTNODE_SIM_CONTROL=ON.
#include <nlohmann/json.hpp>

#include <atomic>
#include <string>
#include <vector>

#include "test_harness.hpp"
#include "test_net.hpp"
#include "vaultnode/hal_sim_control.hpp"

using nlohmann::json;
using vaultnode::hal::kDefaultTempCx100;
using vaultnode::hal::kMaxDriftX100;
using vaultnode::hal::kPinRelay;
using vaultnode::hal::kPinTamper;
using vaultnode::hal::SimulatedSht3x;
using vaultnode::hal::VirtualGpio;
using vaultnode::sim::kControlPort;
using vaultnode::sim::SimControlConfig;
using vaultnode::sim::SimControlServer;
using vn_test::TestClient;

namespace {

SimControlConfig free_port_config() {
    SimControlConfig config;
    config.port = 0;
    return config;
}

struct Fixture {
    explicit Fixture(SimControlConfig config = free_port_config())
        : server(std::move(config), gpio, sensor), client((server.start(), server.port())) {}

    json request(const std::string& line) {
        CHECK(client.send_all(line + "\n"));
        const auto reply = client.read_line();
        CHECK(reply.has_value());
        return json::parse(reply.value_or("null"), nullptr, false);
    }

    VirtualGpio gpio;
    SimulatedSht3x sensor;
    SimControlServer server;
    TestClient client;
};

bool is_ok(const json& reply) { return reply.is_object() && reply.value("ok", false) == true; }

bool is_error(const json& reply) {
    return reply.is_object() && reply.value("ok", true) == false && reply.contains("error") &&
           reply["error"].is_string();
}

}  // namespace

TEST(control_default_port_matches_protocol) {
    CHECK_EQ(kControlPort, 5556);
    CHECK_EQ(SimControlConfig{}.port, 5556);
}

TEST(control_status_reply_has_exactly_the_protocol_fields) {
    Fixture f;
    const auto reply = f.request(R"({"op":"status"})");
    CHECK(is_ok(reply));
    CHECK_EQ(reply.size(), 6U);
    CHECK(reply["state"].is_string());
    CHECK(reply["relay"].is_number_integer());
    CHECK(reply["tamper"].is_boolean());
    CHECK(reply["temp_cx100"].is_number_integer());
    CHECK(reply["humidity_px100"].is_number_integer());
    CHECK_EQ(reply["state"].get<std::string>(), "NORMAL");
    CHECK_EQ(reply["relay"].get<int>(), 0);
    CHECK_EQ(reply["tamper"].get<bool>(), false);
    const auto temp = reply["temp_cx100"].get<int>();
    CHECK(temp >= kDefaultTempCx100 - kMaxDriftX100 && temp <= kDefaultTempCx100 + kMaxDriftX100);
}

TEST(control_tamper_drives_gpio_and_fires_the_edge) {
    Fixture f;
    std::atomic<int> rising{0};
    f.gpio.on_edge(kPinTamper, vaultnode::hal::Edge::Rising, [&](int, bool) { ++rising; });

    auto reply = f.request(R"({"op":"tamper","value":true})");
    CHECK(is_ok(reply));
    CHECK_EQ(reply["tamper"].get<bool>(), true);
    CHECK(f.gpio.read(kPinTamper).value_or(false));
    CHECK_EQ(rising.load(), 1);

    reply = f.request(R"({"op":"tamper","value":true})");  // same value: no second edge
    CHECK(is_ok(reply));
    CHECK_EQ(rising.load(), 1);

    reply = f.request(R"({"op":"tamper","value":false})");
    CHECK(is_ok(reply));
    CHECK_EQ(reply["tamper"].get<bool>(), false);
    CHECK(!f.gpio.read(kPinTamper).value_or(true));
}

TEST(control_set_temp_and_humidity_override_the_sensor) {
    Fixture f;
    auto reply = f.request(R"({"op":"set_temp","value_cx100":4650})");
    CHECK(is_ok(reply));
    CHECK_EQ(reply["temp_cx100"].get<int>(), 4650);

    reply = f.request(R"({"op":"set_humidity","value_px100":9000})");
    CHECK(is_ok(reply));
    CHECK_EQ(reply["humidity_px100"].get<int>(), 9000);
    CHECK_EQ(reply["temp_cx100"].get<int>(), 4650);

    reply = f.request(R"({"op":"set_temp","value_cx100":-4500})");  // negative is in range
    CHECK(is_ok(reply));
    CHECK_EQ(reply["temp_cx100"].get<int>(), -4500);
}

TEST(control_clear_overrides_returns_to_drift) {
    Fixture f;
    CHECK(is_ok(f.request(R"({"op":"set_temp","value_cx100":4650})")));
    CHECK(is_ok(f.request(R"({"op":"tamper","value":true})")));
    const auto reply = f.request(R"({"op":"clear_overrides"})");
    CHECK(is_ok(reply));
    const auto temp = reply["temp_cx100"].get<int>();
    CHECK(temp >= kDefaultTempCx100 - kMaxDriftX100 && temp <= kDefaultTempCx100 + kMaxDriftX100);
    CHECK_EQ(reply["tamper"].get<bool>(), true);  // sensor overrides only
}

TEST(control_reports_relay_and_state) {
    Fixture f;
    CHECK(f.gpio.write(kPinRelay, true));
    const auto reply = f.request(R"({"op":"status"})");
    CHECK_EQ(reply["relay"].get<int>(), 1);
    CHECK_EQ(reply["state"].get<std::string>(), "LOCKED_OUT");

    SimControlConfig config = free_port_config();
    config.state = [] { return std::string("LOCKED_OUT"); };
    Fixture provided(std::move(config));  // relay is low; the provider wins
    const auto provided_reply = provided.request(R"({"op":"status"})");
    CHECK_EQ(provided_reply["relay"].get<int>(), 0);
    CHECK_EQ(provided_reply["state"].get<std::string>(), "LOCKED_OUT");
}

TEST(control_ignores_unknown_fields) {
    Fixture f;
    CHECK(is_ok(f.request(R"({"op":"status","extra":[1,{"a":null}]})")));
    const auto reply = f.request(R"({"note":"x","op":"set_temp","value_cx100":3000})");
    CHECK(is_ok(reply));
    CHECK_EQ(reply["temp_cx100"].get<int>(), 3000);
}

TEST(control_rejects_malformed_requests_and_stays_up) {
    Fixture f;
    const std::vector<std::string> bad = {
        "",
        "not json",
        "{",
        R"({"op":"status")",
        R"({"op":"status"} trailing)",
        "[]",
        "42",
        "null",
        R"("status")",
        "{}",
        R"({"op":1})",
        R"({"op":null})",
        R"({"op":["status"]})",
        std::string("{\"op\":\"status\xff\"}"),      // invalid UTF-8
        std::string("{\"op\":\"st\0atus\"}", 16),    // embedded NUL
    };
    for (const auto& line : bad) {
        const auto reply = f.request(line);
        if (!is_error(reply)) {
            CHECK_EQ(line, "<expected an error reply for this line>");
        }
    }
    CHECK(is_ok(f.request(R"({"op":"status"})")));
}

TEST(control_error_codes_distinguish_the_failure) {
    Fixture f;
    for (const char* line : {"not json", "[]", "42", "null"}) {
        CHECK_EQ(f.request(line).value("error", ""), "malformed_json");
    }
    CHECK_EQ(f.request("{}").value("error", ""), "missing_op");
    CHECK_EQ(f.request(R"({"op":1})").value("error", ""), "missing_op");
    CHECK_EQ(f.request(R"({"op":"tamper","value":1})").value("error", ""), "bad_value");
}

TEST(control_rejects_unknown_ops) {
    Fixture f;
    for (const char* line : {R"({"op":"reboot"})", R"({"op":""})", R"({"op":"STATUS"})",
                             R"({"op":"set_temp "})"}) {
        const auto reply = f.request(line);
        CHECK(is_error(reply));
        CHECK_EQ(reply.value("error", ""), "unknown_op");
    }
}

// The message forms from the task prompt; PROTOCOL.md 4.1 defines "op" instead.
TEST(control_rejects_non_protocol_set_format) {
    Fixture f;
    for (const char* line : {R"({"set":"tamper","value":true})", R"({"set":"temp","value":52.0})",
                             R"({"set":"humidity","value":40})"}) {
        CHECK(is_error(f.request(line)));
    }
    CHECK(!f.gpio.read(kPinTamper).value_or(true));
}

TEST(control_rejects_bad_values_without_side_effects) {
    Fixture f;
    CHECK(is_ok(f.request(R"({"op":"set_temp","value_cx100":3000})")));
    CHECK(is_ok(f.request(R"({"op":"set_humidity","value_px100":5000})")));

    const std::vector<std::string> bad = {
        R"({"op":"tamper"})",
        R"({"op":"tamper","value":1})",
        R"({"op":"tamper","value":"true"})",
        R"({"op":"tamper","value":null})",
        R"({"op":"set_temp"})",
        R"({"op":"set_temp","value":4650})",
        R"({"op":"set_temp","value_cx100":46.5})",
        R"({"op":"set_temp","value_cx100":4650.0})",
        R"({"op":"set_temp","value_cx100":"4650"})",
        R"({"op":"set_temp","value_cx100":true})",
        R"({"op":"set_temp","value_cx100":13001})",
        R"({"op":"set_temp","value_cx100":-4501})",
        R"({"op":"set_temp","value_cx100":18446744073709551615})",  // would wrap to -1 as int64
        R"({"op":"set_temp","value_cx100":4294967296})",            // would truncate to 0 as int32
        R"({"op":"set_temp","value_cx100":1e400})",
        R"({"op":"set_humidity","value_px100":-1})",
        R"({"op":"set_humidity","value_px100":10001})",
        R"({"op":"set_humidity","value_px100":18446744073709551615})",
        R"({"op":"set_humidity","value_cx100":4000})",
    };
    for (const auto& line : bad) {
        const auto reply = f.request(line);
        if (!is_error(reply)) {
            CHECK_EQ(line, "<expected an error reply for this line>");
        }
    }

    const auto status = f.request(R"({"op":"status"})");
    CHECK_EQ(status["temp_cx100"].get<int>(), 3000);
    CHECK_EQ(status["humidity_px100"].get<int>(), 5000);
    CHECK_EQ(status["tamper"].get<bool>(), false);
}

TEST(control_drops_oversize_line_and_keeps_serving) {
    Fixture f;
    TestClient big(f.server.port());
    CHECK(big.send_all(std::string(2000, 'x') + "\n"));
    CHECK(big.wait_closed());
    CHECK(is_ok(f.request(R"({"op":"status"})")));
}

TEST(control_handles_two_requests_in_one_send) {
    Fixture f;
    CHECK(f.client.send_all("{\"op\":\"set_temp\",\"value_cx100\":3100}\n{\"op\":\"bogus\"}\n"));
    const auto first = json::parse(f.client.read_line().value_or("null"), nullptr, false);
    const auto second = json::parse(f.client.read_line().value_or("null"), nullptr, false);
    CHECK(is_ok(first));
    CHECK(is_error(second));
}

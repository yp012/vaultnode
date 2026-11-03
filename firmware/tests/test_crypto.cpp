// Known-answer and negative tests for vaultnode::crypto.
#include "test_harness.hpp"

#include "vaultnode/crypto.hpp"

#include <nlohmann/json.hpp>

#include <stdexcept>
#include <string>
#include <type_traits>

using namespace vaultnode::crypto;

namespace {

Bytes H(std::string_view hex) {
    auto b = hex_decode(hex);
    if (!b) throw std::invalid_argument("bad hex in test vector");
    return *b;
}

Bytes str(std::string_view s) { return Bytes(s.begin(), s.end()); }

Bytes cat(std::initializer_list<ByteView> parts) {
    Bytes out;
    for (const auto& p : parts) out.insert(out.end(), p.data(), p.data() + p.size());
    return out;
}

std::string hmac_hex(ByteView key, ByteView data) { return hex_encode(hmac_sha256(key, data)); }

// PROTOCOL.md section 6 dev keys (public, fake).
const Bytes kMaster = H("4445562d4f4e4c592d4d41535445522d4b45592d444f2d4e4f542d5553452121");
const Bytes kCommandKey = H("4445562d4f4e4c592d434f4d4d414e442d4b45592d444f4e4f54555345212121");
const Bytes kTelemetryKey = H("4445562d4f4e4c592d54454c454d455452592d4b45592d444f4e4f5455534521");

// PROTOCOL.md 6.1 inputs.
const Bytes kUid = H("04a1b2c3");
const Bytes kFwNonce = H("000102030405060708090a0b0c0d0e0f");
const Bytes kBadgeNonce = H("101112131415161718191a1b1c1d1e1f");
const Bytes kTsBE = H("0000019b76daa800");  // 1767225600000 ms, 8 bytes big-endian
const Bytes kIv = H("a0a1a2a3a4a5a6a7a8a9aaabacadaeaf");
const std::string kCt =
    "a754ec49d6d64f89d354796953d0a68118c441ebc646fccd725bb4aeb1d020e796c1fc06eac7077547ea1be9ba036560";
const std::string kMac = "6e7c79e918af8d5050b21db0f8641aa34b2ad88a05eb75398513b21f1f8dc39b";

BadgeKeys kat_keys() {
    auto k = derive_badge_keys(kMaster, kUid);
    if (!k) throw std::runtime_error("derive_badge_keys failed");
    return std::move(*k);
}

}  // namespace

// ===========================================================================
// PROTOCOL.md section 6 known-answer vectors
// ===========================================================================
TEST(protocol_6_1_key_diversification) {
    const auto k = kat_keys();
    CHECK_EQ(k.enc.size(), kAesKeyLen);
    CHECK_EQ(k.mac.size(), kHmacLen);
    CHECK_EQ(hex_encode(k.enc), std::string("a9bb273b2402972e55089c11dbbeb760"));
    CHECK_EQ(hex_encode(k.mac), std::string("293feade86e4fcd77d88e01314bb8eb56699c34918ced27453552f8e2fdf7457"));
}

TEST(protocol_6_1_encrypted_response_and_mac) {
    const auto k = kat_keys();
    const Bytes plaintext = cat({kFwNonce, kBadgeNonce, kTsBE});
    CHECK_EQ(plaintext.size(), std::size_t{40});

    const auto ct = aes128cbc_encrypt(k.enc, kIv, plaintext);
    CHECK(ct.has_value());
    if (!ct) return;
    CHECK_EQ(hex_encode(*ct), kCt);

    const auto mac = hmac_sha256(k.mac, cat({kUid, kFwNonce, kIv, *ct}));
    CHECK_EQ(hex_encode(mac), kMac);
    CHECK(constant_time_equal(mac, H(kMac)));

    const auto pt = aes128cbc_decrypt(k.enc, kIv, H(kCt));
    CHECK(pt.has_value());
    if (pt) CHECK_EQ(hex_encode(*pt), hex_encode(plaintext));
}

TEST(protocol_6_1_firmware_proof) {
    const auto k = kat_keys();
    CHECK_EQ(hmac_hex(k.mac, cat({ByteView::of_string("fw"), kBadgeNonce})),
             std::string("9ae8cde1f9cadc59b713bf24f46a0c230184bd158c5654bce8b6c79f53e0fe94"));
}

TEST(protocol_6_2_signed_commands) {
    CHECK_EQ(hmac_hex(kCommandKey, str("unlock||1|1767225600000")),
             std::string("e6223be3f3de847eaa313eea8f903cbd55edeba728ad167afc3725124a06f5c5"));
    CHECK_EQ(hmac_hex(kCommandKey, str("revoke|04a1b2c3|2|1767225601000")),
             std::string("faf6ce6bea1bb8bafa3e7e00b2222e0f75206ea0942835f981482f1a3d70393e"));
}

TEST(protocol_6_3_signed_telemetry) {
    const nlohmann::json data = {
        {"temp_cx100", 4650}, {"humidity_px100", 4000}, {"cause", "thermal"}, {"state", "LOCKED_OUT"}};
    const std::string canon = "thermal|vn-01|7|1767225600000|" + data.dump();
    CHECK_EQ(canon, std::string("thermal|vn-01|7|1767225600000|"
                                "{\"cause\":\"thermal\",\"humidity_px100\":4000,\"state\":\"LOCKED_OUT\","
                                "\"temp_cx100\":4650}"));
    CHECK_EQ(hmac_hex(kTelemetryKey, str(canon)),
             std::string("e2f7f5867c29f6241504aaef9da87be4c7f5f486cc6438f9f817af0e2f5003b6"));
}

// ===========================================================================
// RFC 4231 HMAC-SHA256 (test case 5 omitted: truncated output)
// ===========================================================================
TEST(rfc4231_hmac_sha256) {
    CHECK_EQ(hmac_hex(Bytes(20, 0x0b), str("Hi There")),
             std::string("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"));
    CHECK_EQ(hmac_hex(str("Jefe"), str("what do ya want for nothing?")),
             std::string("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"));
    CHECK_EQ(hmac_hex(Bytes(20, 0xaa), Bytes(50, 0xdd)),
             std::string("773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"));
    CHECK_EQ(hmac_hex(H("0102030405060708090a0b0c0d0e0f10111213141516171819"), Bytes(50, 0xcd)),
             std::string("82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"));
    CHECK_EQ(hmac_hex(Bytes(131, 0xaa), str("Test Using Larger Than Block-Size Key - Hash Key First")),
             std::string("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"));
    CHECK_EQ(hmac_hex(Bytes(131, 0xaa),
                      str("This is a test using a larger than block-size key and a larger than block-size "
                          "data. The key needs to be hashed before being used by the HMAC algorithm.")),
             std::string("9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"));
}

TEST(hmac_rejects_empty_key) {
    bool threw = false;
    try {
        (void)hmac_sha256(Bytes{}, str("x"));
    } catch (const std::invalid_argument&) {
        threw = true;
    }
    CHECK(threw);
}

TEST(hmac_empty_message_ok) {
    // HMAC-SHA256(key="key", msg="") as published by Wikipedia/common test suites
    CHECK_EQ(hmac_hex(str("key"), Bytes{}),
             std::string("5d5d139563c95b5967b9bd9a8c9b233a9dedb45072794cd232dc1b74832607d0"));
}

// ===========================================================================
// NIST SP 800-38A F.2.1 CBC-AES128.Encrypt
// The NIST vector is unpadded (4 full blocks). Our API always applies PKCS7,
// so the output is those 4 NIST blocks plus one full padding block.
// ===========================================================================
TEST(nist_sp800_38a_aes128_cbc) {
    const Bytes key = H("2b7e151628aed2a6abf7158809cf4f3c");
    const Bytes iv = H("000102030405060708090a0b0c0d0e0f");
    const Bytes pt = H(
        "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
        "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710");
    const std::string nist_ct =
        "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2"
        "73bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7";

    const auto ct = aes128cbc_encrypt(key, iv, pt);
    CHECK(ct.has_value());
    if (!ct) return;
    CHECK_EQ(ct->size(), std::size_t{80});
    CHECK_EQ(hex_encode(*ct).substr(0, 128), nist_ct);

    const auto back = aes128cbc_decrypt(key, iv, *ct);
    CHECK(back.has_value());
    if (back) CHECK_EQ(hex_encode(*back), hex_encode(pt));
}

// ===========================================================================
// Round trips
// ===========================================================================
TEST(aes_round_trip_all_lengths) {
    const Bytes key = secure_random(kAesKeyLen);
    const Bytes iv = secure_random(kAesBlockLen);
    for (std::size_t n = 0; n <= 64; ++n) {
        const Bytes pt = secure_random(n);
        const auto ct = aes128cbc_encrypt(key, iv, pt);
        CHECK(ct.has_value());
        if (!ct) continue;
        CHECK_EQ(ct->size(), (n / kAesBlockLen + 1) * kAesBlockLen);  // PKCS7 always pads
        const auto back = aes128cbc_decrypt(key, iv, *ct);
        CHECK(back.has_value());
        if (back) CHECK(*back == pt);
    }
}

TEST(hex_round_trip) {
    const Bytes b = secure_random(64);
    const auto back = hex_decode(hex_encode(b));
    CHECK(back.has_value());
    if (back) CHECK(*back == b);
    CHECK_EQ(hex_encode(H("00ff10ab")), std::string("00ff10ab"));
}

TEST(secure_random_lengths_and_uniqueness) {
    CHECK(secure_random(0).empty());
    const Bytes a = secure_random(16), b = secure_random(16);
    CHECK_EQ(a.size(), std::size_t{16});
    CHECK(a != b);  // 2^-128 false-failure probability
}

// ===========================================================================
// Tamper tests
// ===========================================================================
TEST(tamper_flip_any_ct_bit_breaks_mac) {
    const auto k = kat_keys();
    const Bytes ct = H(kCt);
    const Bytes good_mac = H(kMac);
    for (std::size_t byte = 0; byte < ct.size(); ++byte) {
        for (int bit = 0; bit < 8; ++bit) {
            Bytes t = ct;
            t[byte] ^= static_cast<std::uint8_t>(1u << bit);
            CHECK(!constant_time_equal(hmac_sha256(k.mac, cat({kUid, kFwNonce, kIv, t})), good_mac));
        }
    }
}

TEST(tamper_other_mac_inputs_break_mac) {
    const auto k = kat_keys();
    const Bytes ct = H(kCt), good = H(kMac);
    Bytes uid2 = kUid, nonce2 = kFwNonce, iv2 = kIv;
    uid2[3] ^= 1;
    nonce2[0] ^= 1;
    iv2[15] ^= 1;
    CHECK(!constant_time_equal(hmac_sha256(k.mac, cat({uid2, kFwNonce, kIv, ct})), good));
    CHECK(!constant_time_equal(hmac_sha256(k.mac, cat({kUid, nonce2, kIv, ct})), good));
    CHECK(!constant_time_equal(hmac_sha256(k.mac, cat({kUid, kFwNonce, iv2, ct})), good));
    // A cloned UID with the wrong master key derives different keys.
    const auto other = derive_badge_keys(secure_random(kMasterKeyLen), kUid);
    CHECK(other.has_value());
    if (other) CHECK(!constant_time_equal(hmac_sha256(other->mac, cat({kUid, kFwNonce, kIv, ct})), good));
}

TEST(tamper_bad_padding_single_failure) {
    const auto k = kat_keys();
    // Flipping the last byte of the second-to-last block flips the final
    // plaintext byte: padding 0x08 -> 0x09, which is invalid PKCS7.
    Bytes ct = H(kCt);
    ct[ct.size() - kAesBlockLen - 1] ^= 0x01;
    CHECK(!aes128cbc_decrypt(k.enc, kIv, ct).has_value());
    // The wrong key gives the same single failure result (no distinguishable cause).
    const Bytes wrong_key(kAesKeyLen, 0x42);
    const auto r = aes128cbc_decrypt(wrong_key, kIv, H(kCt));
    // A wrong key yields valid padding with probability ~1/256. If it does, the
    // plaintext must differ; either way the caller never sees an error reason.
    if (r) CHECK(hex_encode(*r) != hex_encode(cat({kFwNonce, kBadgeNonce, kTsBE})));
}

// ===========================================================================
// constant_time_equal
// ===========================================================================
TEST(constant_time_equal_semantics) {
    const Bytes a = H("00112233"), b = H("00112233"), c = H("00112234");
    CHECK(constant_time_equal(a, b));
    CHECK(!constant_time_equal(a, c));
    CHECK(!constant_time_equal(a, H("001122")));      // length mismatch (prefix)
    CHECK(!constant_time_equal(a, H("0011223300")));  // length mismatch (extension)
    CHECK(constant_time_equal(Bytes{}, Bytes{}));
    CHECK(!constant_time_equal(Bytes{}, a));
}

// ===========================================================================
// Wrong-length input handling
// ===========================================================================
TEST(aes_rejects_bad_key_lengths) {
    const Bytes iv(16, 0), pt(16, 1);
    for (std::size_t n : {0u, 15u, 17u, 24u, 32u}) {
        CHECK(!aes128cbc_encrypt(Bytes(n, 1), iv, pt).has_value());
        CHECK(!aes128cbc_decrypt(Bytes(n, 1), iv, Bytes(16, 0)).has_value());
    }
}

TEST(aes_rejects_bad_iv_lengths) {
    const Bytes key(16, 1), pt(16, 1);
    for (std::size_t n : {0u, 8u, 15u, 17u, 32u}) {
        CHECK(!aes128cbc_encrypt(key, Bytes(n, 0), pt).has_value());
        CHECK(!aes128cbc_decrypt(key, Bytes(n, 0), Bytes(16, 0)).has_value());
    }
}

TEST(aes_decrypt_rejects_bad_ciphertext_lengths) {
    const auto k = kat_keys();
    CHECK(!aes128cbc_decrypt(k.enc, kIv, Bytes{}).has_value());  // empty
    for (std::size_t n : {1u, 15u, 17u, 47u, 49u}) {
        CHECK(!aes128cbc_decrypt(k.enc, kIv, Bytes(n, 0)).has_value());
    }
    Bytes truncated = H(kCt);
    truncated.pop_back();
    CHECK(!aes128cbc_decrypt(k.enc, kIv, truncated).has_value());
}

TEST(aes_encrypt_empty_plaintext_is_one_padding_block) {
    const auto ct = aes128cbc_encrypt(Bytes(16, 1), Bytes(16, 0), Bytes{});
    CHECK(ct.has_value());
    if (ct) CHECK_EQ(ct->size(), std::size_t{16});
}

TEST(derive_rejects_bad_lengths) {
    CHECK(!derive_badge_keys(Bytes(31, 1), kUid).has_value());
    CHECK(!derive_badge_keys(Bytes(33, 1), kUid).has_value());
    CHECK(!derive_badge_keys(Bytes{}, kUid).has_value());
    CHECK(!derive_badge_keys(kMaster, H("04a1b2")).has_value());
    CHECK(!derive_badge_keys(kMaster, H("04a1b2c3d4")).has_value());
    // Hex text instead of raw bytes is rejected too (8 bytes, not 4).
    CHECK(!derive_badge_keys(kMaster, ByteView::of_string("04a1b2c3")).has_value());
}

TEST(hex_decode_strict) {
    CHECK(hex_decode("").has_value());
    CHECK(hex_decode("ABCDEF").has_value());  // uppercase accepted (PROTOCOL.md 0)
    CHECK(!hex_decode("abc").has_value());    // odd length
    CHECK(!hex_decode("0g").has_value());     // non-hex
    CHECK(!hex_decode("0x00").has_value());   // prefix
    CHECK(!hex_decode("00 11").has_value());  // whitespace
    CHECK(!hex_decode("00\n").has_value());
    CHECK(!hex_decode(std::string_view("00\0" "1", 4)).has_value());  // embedded NUL
    CHECK(hex_decode("04a1b2c3", kUidLen).has_value());
    CHECK(!hex_decode("04a1b2", kUidLen).has_value());       // too short
    CHECK(!hex_decode("04a1b2c3d4", kUidLen).has_value());   // too long
    CHECK(!hex_decode("04a1b2cz", kUidLen).has_value());     // right length, bad char
}

// ===========================================================================
// SecureBytes
// ===========================================================================
static_assert(!std::is_copy_constructible_v<SecureBytes>, "SecureBytes must not be copyable");
static_assert(!std::is_copy_assignable_v<SecureBytes>, "SecureBytes must not be copy-assignable");
static_assert(std::is_nothrow_move_constructible_v<SecureBytes>, "SecureBytes must be movable");
static_assert(std::is_nothrow_move_assignable_v<SecureBytes>, "SecureBytes must be move-assignable");
static_assert(!std::is_convertible_v<std::string, ByteView>, "text must not silently become bytes");

TEST(secure_bytes_move_semantics) {
    SecureBytes a(H("deadbeef"));
    CHECK_EQ(a.size(), std::size_t{4});
    SecureBytes b(std::move(a));
    CHECK(a.empty());  // NOLINT(bugprone-use-after-move): moved-from state is specified
    CHECK_EQ(hex_encode(b), std::string("deadbeef"));
    SecureBytes c(2);
    c = std::move(b);
    CHECK(b.empty());  // NOLINT(bugprone-use-after-move)
    CHECK_EQ(hex_encode(c), std::string("deadbeef"));
}

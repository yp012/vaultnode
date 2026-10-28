// Cryptographic primitives for VaultNode (PROTOCOL.md sections 0, 2.1, 2.2, 3).
// OpenSSL EVP APIs only; no deprecated low-level AES_* / HMAC_CTX calls.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace vaultnode::crypto {

using Bytes = std::vector<std::uint8_t>;

constexpr std::size_t kAesKeyLen = 16;
constexpr std::size_t kAesBlockLen = 16;
constexpr std::size_t kHmacLen = 32;
constexpr std::size_t kMasterKeyLen = 32;
constexpr std::size_t kUidLen = 4;

using Digest = std::array<std::uint8_t, kHmacLen>;

// Fixed-size buffer for key material. Wiped with OPENSSL_cleanse on
// destruction and on move-assignment. Non-copyable, so key bytes are never
// silently duplicated. It never reallocates (no push_back), so no
// unwiped stale copy is left behind on the heap.
class SecureBytes {
public:
    SecureBytes() = default;
    explicit SecureBytes(std::size_t n);
    SecureBytes(const std::uint8_t* p, std::size_t n);
    // Takes ownership of the buffer without copying it (no stray copy).
    explicit SecureBytes(Bytes&& b) noexcept;
    ~SecureBytes();

    SecureBytes(const SecureBytes&) = delete;
    SecureBytes& operator=(const SecureBytes&) = delete;
    SecureBytes(SecureBytes&& other) noexcept;
    SecureBytes& operator=(SecureBytes&& other) noexcept;

    std::uint8_t* data() noexcept { return buf_.data(); }
    const std::uint8_t* data() const noexcept { return buf_.data(); }
    std::size_t size() const noexcept { return buf_.size(); }
    bool empty() const noexcept { return buf_.empty(); }

private:
    void wipe() noexcept;
    Bytes buf_;
};

// Non-owning read-only view over contiguous bytes. Strings never convert
// implicitly: passing hex text where raw bytes are expected is a classic
// bug, so text needs the explicit ByteView::of_string().
class ByteView {
public:
    constexpr ByteView() noexcept = default;
    constexpr ByteView(const std::uint8_t* p, std::size_t n) noexcept : p_(p), n_(n) {}
    ByteView(const Bytes& b) noexcept : p_(b.data()), n_(b.size()) {}
    ByteView(const SecureBytes& b) noexcept : p_(b.data()), n_(b.size()) {}
    template <std::size_t N>
    ByteView(const std::array<std::uint8_t, N>& a) noexcept : p_(a.data()), n_(N) {}

    static ByteView of_string(std::string_view s) noexcept {
        return {reinterpret_cast<const std::uint8_t*>(s.data()), s.size()};
    }

    const std::uint8_t* data() const noexcept { return p_; }
    std::size_t size() const noexcept { return n_; }
    bool empty() const noexcept { return n_ == 0; }

private:
    const std::uint8_t* p_ = nullptr;
    std::size_t n_ = 0;
};

// HMAC-SHA256. Throws std::invalid_argument for an empty key and
// std::runtime_error if OpenSSL fails (fail closed).
Digest hmac_sha256(ByteView key, ByteView data);

// Constant-time comparison via CRYPTO_memcmp. Lengths are public, so a
// length mismatch returns false immediately; the content comparison
// never exits early.
bool constant_time_equal(ByteView a, ByteView b) noexcept;

// AES-128-CBC with PKCS7 padding. Returns std::nullopt if the key is not 16
// bytes, the IV is not 16 bytes, or OpenSSL fails.
std::optional<Bytes> aes128cbc_encrypt(ByteView key, ByteView iv, ByteView plaintext);

// Returns std::nullopt for every failure (wrong key/IV length, ciphertext
// empty or not a multiple of 16, bad padding). Callers cannot tell the
// causes apart. Per PROTOCOL.md 2.4, only call this after the MAC has
// been verified.
std::optional<Bytes> aes128cbc_decrypt(ByteView key, ByteView iv, ByteView ciphertext);

// n bytes from RAND_bytes. Throws std::runtime_error if the CSPRNG fails:
// the firmware must never continue with predictable nonces.
Bytes secure_random(std::size_t n);

struct BadgeKeys {
    SecureBytes enc;  // 16 bytes: HMAC-SHA256(MASTER, "enc" || uid)[0:16]
    SecureBytes mac;  // 32 bytes: HMAC-SHA256(MASTER, "mac" || uid)
};

// PROTOCOL.md 2.1. Returns std::nullopt unless master_key is 32 bytes and
// uid is 4 raw bytes.
std::optional<BadgeKeys> derive_badge_keys(ByteView master_key, ByteView uid);

// Lowercase hex.
std::string hex_encode(ByteView data);

// Strict hex decoding: even length, [0-9a-fA-F] only, no prefix, no whitespace.
std::optional<Bytes> hex_decode(std::string_view hex);
// The same, and the decoded length must be exactly expected_len bytes.
std::optional<Bytes> hex_decode(std::string_view hex, std::size_t expected_len);

}  // namespace vaultnode::crypto

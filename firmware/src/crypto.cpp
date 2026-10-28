#include "vaultnode/crypto.hpp"

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/rand.h>

#include <algorithm>
#include <climits>
#include <memory>
#include <stdexcept>
#include <utility>

namespace vaultnode::crypto {

// ---------------------------------------------------------------------------
// SecureBytes
// ---------------------------------------------------------------------------
SecureBytes::SecureBytes(std::size_t n) : buf_(n, 0) {}

SecureBytes::SecureBytes(const std::uint8_t* p, std::size_t n) : buf_(p, p + n) {}

SecureBytes::SecureBytes(Bytes&& b) noexcept : buf_(std::move(b)) {}

SecureBytes::~SecureBytes() { wipe(); }

SecureBytes::SecureBytes(SecureBytes&& other) noexcept : buf_(std::move(other.buf_)) {
    other.buf_.clear();
}

SecureBytes& SecureBytes::operator=(SecureBytes&& other) noexcept {
    if (this != &other) {
        wipe();
        buf_ = std::move(other.buf_);
        other.buf_.clear();
    }
    return *this;
}

void SecureBytes::wipe() noexcept {
    if (!buf_.empty()) OPENSSL_cleanse(buf_.data(), buf_.size());
}

namespace {

// ---------------------------------------------------------------------------
// RAII wrappers for OpenSSL handles
// ---------------------------------------------------------------------------
struct CipherCtxDeleter {
    void operator()(EVP_CIPHER_CTX* c) const noexcept { EVP_CIPHER_CTX_free(c); }
};
struct MacCtxDeleter {
    void operator()(EVP_MAC_CTX* c) const noexcept { EVP_MAC_CTX_free(c); }
};

class CipherCtx {
public:
    CipherCtx() : ctx_(EVP_CIPHER_CTX_new()) {}
    explicit operator bool() const noexcept { return ctx_ != nullptr; }
    EVP_CIPHER_CTX* get() const noexcept { return ctx_.get(); }

private:
    std::unique_ptr<EVP_CIPHER_CTX, CipherCtxDeleter> ctx_;
};

using MacCtx = std::unique_ptr<EVP_MAC_CTX, MacCtxDeleter>;

// Fetched once and kept for the process lifetime (fetching on every call
// costs a provider lookup on the hot auth path). Static init is thread-safe.
EVP_MAC* hmac_algorithm() {
    static EVP_MAC* const mac = EVP_MAC_fetch(nullptr, "HMAC", nullptr);
    return mac;
}

bool fits_int(std::size_t n) { return n <= static_cast<std::size_t>(INT_MAX - kAesBlockLen); }

}  // namespace

// ---------------------------------------------------------------------------
// HMAC-SHA256 (EVP_MAC)
// ---------------------------------------------------------------------------
Digest hmac_sha256(ByteView key, ByteView data) {
    if (key.empty()) throw std::invalid_argument("hmac_sha256: empty key");

    EVP_MAC* alg = hmac_algorithm();
    if (alg == nullptr) throw std::runtime_error("hmac_sha256: HMAC unavailable");
    MacCtx ctx(EVP_MAC_CTX_new(alg));
    if (!ctx) throw std::runtime_error("hmac_sha256: EVP_MAC_CTX_new failed");

    char digest_name[] = "SHA256";
    const OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, digest_name, 0),
        OSSL_PARAM_construct_end()};

    Digest out{};
    std::size_t out_len = 0;
    if (EVP_MAC_init(ctx.get(), key.data(), key.size(), params) != 1 ||
        EVP_MAC_update(ctx.get(), data.data(), data.size()) != 1 ||
        EVP_MAC_final(ctx.get(), out.data(), &out_len, out.size()) != 1 || out_len != kHmacLen) {
        ERR_clear_error();
        throw std::runtime_error("hmac_sha256: OpenSSL failure");
    }
    return out;
}

bool constant_time_equal(ByteView a, ByteView b) noexcept {
    if (a.size() != b.size()) return false;
    if (a.empty()) return true;
    return CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}

// ---------------------------------------------------------------------------
// AES-128-CBC + PKCS7 (EVP_Cipher*)
// ---------------------------------------------------------------------------
std::optional<Bytes> aes128cbc_encrypt(ByteView key, ByteView iv, ByteView plaintext) {
    if (key.size() != kAesKeyLen || iv.size() != kAesBlockLen || !fits_int(plaintext.size())) {
        return std::nullopt;
    }
    CipherCtx ctx;
    if (!ctx) return std::nullopt;

    Bytes out(plaintext.size() + kAesBlockLen);
    int len1 = 0, len2 = 0;
    if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_128_cbc(), nullptr, key.data(), iv.data()) != 1 ||
        EVP_EncryptUpdate(ctx.get(), out.data(), &len1, plaintext.data(),
                          static_cast<int>(plaintext.size())) != 1 ||
        EVP_EncryptFinal_ex(ctx.get(), out.data() + len1, &len2) != 1) {
        OPENSSL_cleanse(out.data(), out.size());
        ERR_clear_error();
        return std::nullopt;
    }
    out.resize(static_cast<std::size_t>(len1 + len2));
    return out;
}

std::optional<Bytes> aes128cbc_decrypt(ByteView key, ByteView iv, ByteView ciphertext) {
    if (key.size() != kAesKeyLen || iv.size() != kAesBlockLen || ciphertext.empty() ||
        ciphertext.size() % kAesBlockLen != 0 || !fits_int(ciphertext.size())) {
        return std::nullopt;
    }
    CipherCtx ctx;
    if (!ctx) return std::nullopt;

    Bytes out(ciphertext.size() + kAesBlockLen);
    int len1 = 0, len2 = 0;
    const bool ok =
        EVP_DecryptInit_ex(ctx.get(), EVP_aes_128_cbc(), nullptr, key.data(), iv.data()) == 1 &&
        EVP_DecryptUpdate(ctx.get(), out.data(), &len1, ciphertext.data(),
                          static_cast<int>(ciphertext.size())) == 1 &&
        EVP_DecryptFinal_ex(ctx.get(), out.data() + len1, &len2) == 1;
    if (!ok) {
        // A single failure result. Wipe the partial plaintext and drop
        // OpenSSL's error queue so no "bad decrypt" detail survives.
        OPENSSL_cleanse(out.data(), out.size());
        ERR_clear_error();
        return std::nullopt;
    }
    out.resize(static_cast<std::size_t>(len1 + len2));
    return out;
}

// ---------------------------------------------------------------------------
// CSPRNG
// ---------------------------------------------------------------------------
Bytes secure_random(std::size_t n) {
    if (n > static_cast<std::size_t>(INT_MAX)) throw std::invalid_argument("secure_random: too large");
    Bytes out(n);
    if (n > 0 && RAND_bytes(out.data(), static_cast<int>(n)) != 1) {
        ERR_clear_error();
        throw std::runtime_error("secure_random: RAND_bytes failed");
    }
    return out;
}

// ---------------------------------------------------------------------------
// Key diversification (PROTOCOL.md 2.1)
// ---------------------------------------------------------------------------
std::optional<BadgeKeys> derive_badge_keys(ByteView master_key, ByteView uid) {
    if (master_key.size() != kMasterKeyLen || uid.size() != kUidLen) return std::nullopt;

    constexpr std::size_t kLabelLen = 3;  // "enc" / "mac", without the NUL
    auto derive = [&](const char (&label)[kLabelLen + 1]) {
        std::array<std::uint8_t, kLabelLen + kUidLen> msg{};
        std::copy(label, label + kLabelLen, msg.begin());
        std::copy(uid.data(), uid.data() + kUidLen, msg.begin() + kLabelLen);
        return hmac_sha256(master_key, msg);
    };

    Digest enc_full = derive("enc");
    Digest mac_full = derive("mac");
    BadgeKeys keys{SecureBytes(enc_full.data(), kAesKeyLen), SecureBytes(mac_full.data(), kHmacLen)};
    OPENSSL_cleanse(enc_full.data(), enc_full.size());
    OPENSSL_cleanse(mac_full.data(), mac_full.size());
    return keys;
}

// ---------------------------------------------------------------------------
// Hex
// ---------------------------------------------------------------------------
std::string hex_encode(ByteView data) {
    static constexpr char kDigits[] = "0123456789abcdef";
    std::string s;
    s.reserve(data.size() * 2);
    for (std::size_t i = 0; i < data.size(); ++i) {
        s.push_back(kDigits[data.data()[i] >> 4]);
        s.push_back(kDigits[data.data()[i] & 0x0f]);
    }
    return s;
}

namespace {
int nibble(char c) noexcept {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
}  // namespace

std::optional<Bytes> hex_decode(std::string_view hex) {
    if (hex.size() % 2 != 0) return std::nullopt;
    Bytes out;
    out.reserve(hex.size() / 2);
    for (std::size_t i = 0; i < hex.size(); i += 2) {
        const int hi = nibble(hex[i]);
        const int lo = nibble(hex[i + 1]);
        if (hi < 0 || lo < 0) {
            // The input may be a key; don't leave a partial decode on the heap.
            OPENSSL_cleanse(out.data(), out.size());
            return std::nullopt;
        }
        out.push_back(static_cast<std::uint8_t>((hi << 4) | lo));
    }
    return out;
}

std::optional<Bytes> hex_decode(std::string_view hex, std::size_t expected_len) {
    if (hex.size() != expected_len * 2) return std::nullopt;
    return hex_decode(hex);
}

}  // namespace vaultnode::crypto

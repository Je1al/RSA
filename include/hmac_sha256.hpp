#ifndef RSA_HMAC_SHA256_HPP
#define RSA_HMAC_SHA256_HPP

#include <cstdint>
#include <cstddef>
#include <array>
#include <vector>

#include "sha256.hpp"

// HMAC-SHA256 (RFC 2104 / FIPS 198-1), built on the from-scratch SHA-256.
class HmacSha256 {
public:
    static constexpr size_t MAC_SIZE = Sha256::DIGEST_SIZE;  // 32 bytes

    using Mac = std::array<uint8_t, MAC_SIZE>;

    HmacSha256(const uint8_t* key, size_t keyLen);

    void update(const uint8_t* data, size_t len);
    void update(const std::vector<uint8_t>& data);

    // Finalises and returns the MAC.
    Mac final();

    static Mac mac(const uint8_t* key, size_t keyLen,
                   const uint8_t* data, size_t dataLen);
    static Mac mac(const std::vector<uint8_t>& key,
                   const std::vector<uint8_t>& data);

private:
    void init(const uint8_t* key, size_t keyLen);

    Sha256  inner_;
    uint8_t opad_[Sha256::BLOCK_SIZE];
};

#endif // RSA_HMAC_SHA256_HPP

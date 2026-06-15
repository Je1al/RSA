#ifndef RSA_SHA256_HPP
#define RSA_SHA256_HPP

#include <cstdint>
#include <cstddef>
#include <array>
#include <vector>
#include <string>

// SHA-256 (FIPS 180-4), implemented from scratch with no external dependencies.
//
// Streaming API:
//     Sha256 h;
//     h.update(data, len);
//     auto md = h.final();          // 32-byte digest
//
// One-shot helpers are provided for convenience.
class Sha256 {
public:
    static constexpr size_t DIGEST_SIZE = 32;  // 256 bits
    static constexpr size_t BLOCK_SIZE  = 64;  // 512-bit message block

    using Digest = std::array<uint8_t, DIGEST_SIZE>;

    Sha256();

    void reset();
    void update(const uint8_t* data, size_t len);
    void update(const std::vector<uint8_t>& data);

    // Finalises the hash and returns the digest. The object is reset afterwards.
    Digest final();

    // One-shot convenience helpers.
    static Digest hash(const uint8_t* data, size_t len);
    static Digest hash(const std::vector<uint8_t>& data);
    static std::string hexdigest(const std::vector<uint8_t>& data);

private:
    void processBlock(const uint8_t* block);

    uint32_t state_[8];
    uint8_t  buffer_[BLOCK_SIZE];
    size_t   bufferLen_;
    uint64_t bitLen_;
};

#endif // RSA_SHA256_HPP

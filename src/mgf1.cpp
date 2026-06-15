#include "mgf1.hpp"
#include "sha256.hpp"

#include <cstring>

std::vector<uint8_t> mgf1_sha256(const uint8_t* seed, size_t seedLen, size_t maskLen) {
    std::vector<uint8_t> mask;
    mask.reserve(maskLen);

    // T = T || Hash(seed || I2OSP(counter, 4)), counter = 0, 1, ...
    for (uint32_t counter = 0; mask.size() < maskLen; ++counter) {
        Sha256 h;
        h.update(seed, seedLen);
        uint8_t c[4] = {
            static_cast<uint8_t>(counter >> 24),
            static_cast<uint8_t>(counter >> 16),
            static_cast<uint8_t>(counter >> 8),
            static_cast<uint8_t>(counter),
        };
        h.update(c, 4);
        Sha256::Digest block = h.final();
        mask.insert(mask.end(), block.begin(), block.end());
    }

    mask.resize(maskLen);
    return mask;
}

std::vector<uint8_t> mgf1_sha256(const std::vector<uint8_t>& seed, size_t maskLen) {
    return mgf1_sha256(seed.data(), seed.size(), maskLen);
}

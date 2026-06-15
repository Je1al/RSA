#include "hmac_sha256.hpp"

#include <cstring>

HmacSha256::HmacSha256(const uint8_t* key, size_t keyLen) {
    init(key, keyLen);
}

void HmacSha256::init(const uint8_t* key, size_t keyLen) {
    uint8_t k0[Sha256::BLOCK_SIZE];
    std::memset(k0, 0, sizeof(k0));

    // Keys longer than the block size are hashed first (RFC 2104).
    if (keyLen > Sha256::BLOCK_SIZE) {
        Sha256::Digest h = Sha256::hash(key, keyLen);
        std::memcpy(k0, h.data(), h.size());
    } else {
        std::memcpy(k0, key, keyLen);
    }

    uint8_t ipad[Sha256::BLOCK_SIZE];
    for (size_t i = 0; i < Sha256::BLOCK_SIZE; ++i) {
        ipad[i]  = k0[i] ^ 0x36;
        opad_[i] = k0[i] ^ 0x5c;
    }

    inner_.reset();
    inner_.update(ipad, sizeof(ipad));
}

void HmacSha256::update(const uint8_t* data, size_t len) {
    inner_.update(data, len);
}

void HmacSha256::update(const std::vector<uint8_t>& data) {
    inner_.update(data);
}

HmacSha256::Mac HmacSha256::final() {
    Sha256::Digest innerDigest = inner_.final();

    Sha256 outer;
    outer.update(opad_, sizeof(opad_));
    outer.update(innerDigest.data(), innerDigest.size());
    Sha256::Digest out = outer.final();

    Mac mac;
    std::memcpy(mac.data(), out.data(), MAC_SIZE);
    return mac;
}

HmacSha256::Mac HmacSha256::mac(const uint8_t* key, size_t keyLen,
                                const uint8_t* data, size_t dataLen) {
    HmacSha256 h(key, keyLen);
    h.update(data, dataLen);
    return h.final();
}

HmacSha256::Mac HmacSha256::mac(const std::vector<uint8_t>& key,
                                const std::vector<uint8_t>& data) {
    return mac(key.data(), key.size(), data.data(), data.size());
}

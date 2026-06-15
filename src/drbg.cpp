#include "drbg.hpp"
#include "hmac_sha256.hpp"

#include <cstring>
#include <stdexcept>

HmacDrbg::HmacDrbg() : reseedCounter_(0), initialized_(false) {
    std::memset(K_, 0, sizeof(K_));
    std::memset(V_, 0, sizeof(V_));
}

// SP 800-90A 10.1.2.2 — HMAC_DRBG_Update.
//
//   K = HMAC(K, V || 0x00 || provided_data)
//   V = HMAC(K, V)
//   if provided_data != "":
//       K = HMAC(K, V || 0x01 || provided_data)
//       V = HMAC(K, V)
void HmacDrbg::update(const uint8_t* providedData, size_t providedLen) {
    for (uint8_t round = 0x00; ; ++round) {
        // K = HMAC(K, V || round || provided_data)
        HmacSha256 mac(K_, sizeof(K_));
        mac.update(V_, sizeof(V_));
        mac.update(&round, 1);
        if (providedLen > 0) mac.update(providedData, providedLen);
        HmacSha256::Mac newK = mac.final();
        std::memcpy(K_, newK.data(), sizeof(K_));

        // V = HMAC(K, V)
        HmacSha256::Mac newV = HmacSha256::mac(K_, sizeof(K_), V_, sizeof(V_));
        std::memcpy(V_, newV.data(), sizeof(V_));

        if (round == 0x01 || providedLen == 0) break;  // run once if no data, else twice
    }
}

void HmacDrbg::instantiate(const uint8_t* entropy, size_t entropyLen,
                           const uint8_t* nonce, size_t nonceLen,
                           const uint8_t* perso, size_t persoLen) {
    // seed_material = entropy_input || nonce || personalization_string
    std::vector<uint8_t> seed;
    seed.reserve(entropyLen + nonceLen + persoLen);
    if (entropyLen) seed.insert(seed.end(), entropy, entropy + entropyLen);
    if (nonceLen)   seed.insert(seed.end(), nonce,   nonce   + nonceLen);
    if (persoLen)   seed.insert(seed.end(), perso,   perso   + persoLen);

    std::memset(K_, 0x00, sizeof(K_));  // Key  = 0x00 ... 0x00
    std::memset(V_, 0x01, sizeof(V_));  // V    = 0x01 ... 0x01

    update(seed.data(), seed.size());
    reseedCounter_ = 1;
    initialized_   = true;
}

void HmacDrbg::reseed(const uint8_t* entropy, size_t entropyLen,
                      const uint8_t* additional, size_t addLen) {
    std::vector<uint8_t> seed;
    seed.reserve(entropyLen + addLen);
    if (entropyLen) seed.insert(seed.end(), entropy, entropy + entropyLen);
    if (addLen)     seed.insert(seed.end(), additional, additional + addLen);

    update(seed.data(), seed.size());
    reseedCounter_ = 1;
}

bool HmacDrbg::generate(uint8_t* out, size_t outLen,
                        const uint8_t* additional, size_t addLen) {
    if (!initialized_) {
        throw std::logic_error("HmacDrbg::generate called before instantiate");
    }
    if (reseedCounter_ > RESEED_INTERVAL) {
        return false;  // caller must reseed
    }

    if (addLen > 0) {
        update(additional, addLen);
    }

    size_t produced = 0;
    while (produced < outLen) {
        // V = HMAC(K, V)
        HmacSha256::Mac v = HmacSha256::mac(K_, sizeof(K_), V_, sizeof(V_));
        std::memcpy(V_, v.data(), sizeof(V_));

        size_t take = outLen - produced;
        if (take > sizeof(V_)) take = sizeof(V_);
        std::memcpy(out + produced, V_, take);
        produced += take;
    }

    update(additional, addLen);  // additional may be null/0 — handled by update()
    ++reseedCounter_;
    return true;
}

#ifndef RSA_DRBG_HPP
#define RSA_DRBG_HPP

#include <cstdint>
#include <cstddef>
#include <vector>

// HMAC_DRBG using SHA-256, per NIST SP 800-90A Rev.1 (Section 10.1.2).
//
// This is the deterministic core of the CSPRNG: given the same seed material it
// produces the same output, which makes it verifiable against the NIST DRBGVS
// known-answer tests. The non-deterministic, OS-entropy-seeded wrapper lives in
// rng.hpp.
class HmacDrbg {
public:
    static constexpr size_t SEEDLEN = 32;  // SHA-256 output / internal state size

    // Maximum number of generate calls between reseeds (SP 800-90A: 2^48).
    static constexpr uint64_t RESEED_INTERVAL = (uint64_t(1) << 48);

    HmacDrbg();

    // SP 800-90A Instantiate: seed = entropy_input || nonce || personalization.
    void instantiate(const uint8_t* entropy, size_t entropyLen,
                     const uint8_t* nonce, size_t nonceLen,
                     const uint8_t* perso, size_t persoLen);

    // SP 800-90A Reseed.
    void reseed(const uint8_t* entropy, size_t entropyLen,
                const uint8_t* additional, size_t addLen);

    // SP 800-90A Generate. Returns false if a reseed is required first.
    bool generate(uint8_t* out, size_t outLen,
                  const uint8_t* additional = nullptr, size_t addLen = 0);

    uint64_t reseedCounter() const { return reseedCounter_; }
    bool     initialized()   const { return initialized_; }

private:
    // SP 800-90A Update: the core state-mixing function.
    void update(const uint8_t* providedData, size_t providedLen);

    uint8_t  K_[SEEDLEN];
    uint8_t  V_[SEEDLEN];
    uint64_t reseedCounter_;
    bool     initialized_;
};

#endif // RSA_DRBG_HPP

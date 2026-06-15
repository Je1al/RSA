#include "oaep.hpp"
#include "sha256.hpp"
#include "mgf1.hpp"
#include "rng.hpp"
#include "bigmath.hpp"

#include <stdexcept>

namespace oaep {

namespace {
constexpr size_t HLEN = Sha256::DIGEST_SIZE;  // 32

size_t modulusBytes(const BigInt& n) { return n.byteLength(); }

// EME-OAEP encoding (RFC 8017 7.1.1 steps 2a-2i) into a k-byte block.
std::vector<uint8_t> encode(const std::vector<uint8_t>& message,
                            const std::vector<uint8_t>& label,
                            const std::vector<uint8_t>& seed,
                            size_t k) {
    if (k < 2 * HLEN + 2 || message.size() > k - 2 * HLEN - 2) {
        throw std::runtime_error("message too long");
    }
    if (seed.size() != HLEN) {
        throw std::runtime_error("OAEP seed must be hLen bytes");
    }

    Sha256::Digest lHash = Sha256::hash(label);

    // DB = lHash || PS(0x00...) || 0x01 || M    (length k - hLen - 1)
    std::vector<uint8_t> db(k - HLEN - 1, 0);
    std::copy(lHash.begin(), lHash.end(), db.begin());
    size_t psLen = k - message.size() - 2 * HLEN - 2;
    db[HLEN + psLen] = 0x01;
    std::copy(message.begin(), message.end(), db.begin() + HLEN + psLen + 1);

    // maskedDB = DB xor MGF1(seed, k-hLen-1)
    std::vector<uint8_t> dbMask = mgf1_sha256(seed, k - HLEN - 1);
    for (size_t i = 0; i < db.size(); ++i) db[i] ^= dbMask[i];

    // maskedSeed = seed xor MGF1(maskedDB, hLen)
    std::vector<uint8_t> seedMask = mgf1_sha256(db, HLEN);
    std::vector<uint8_t> maskedSeed(HLEN);
    for (size_t i = 0; i < HLEN; ++i) maskedSeed[i] = seed[i] ^ seedMask[i];

    // EM = 0x00 || maskedSeed || maskedDB
    std::vector<uint8_t> em;
    em.reserve(k);
    em.push_back(0x00);
    em.insert(em.end(), maskedSeed.begin(), maskedSeed.end());
    em.insert(em.end(), db.begin(), db.end());
    return em;
}

} // namespace

size_t maxMessageLen(const RSA::PublicKey& pub) {
    size_t k = modulusBytes(*pub.n);
    if (k < 2 * HLEN + 2) return 0;
    return k - 2 * HLEN - 2;
}

std::vector<uint8_t> encryptWithSeed(const RSA::PublicKey& pub,
                                     const std::vector<uint8_t>& message,
                                     const std::vector<uint8_t>& seed,
                                     const std::vector<uint8_t>& label) {
    size_t k = modulusBytes(*pub.n);
    std::vector<uint8_t> em = encode(message, label, seed, k);

    BigInt m = BigInt::fromBytesBE(em);
    auto c = RSA::encrypt(m, pub);
    if (!c) throw std::runtime_error("RSA encryption primitive failed");
    return c->toBytesBE(k);
}

std::vector<uint8_t> encrypt(const RSA::PublicKey& pub,
                             const std::vector<uint8_t>& message,
                             const std::vector<uint8_t>& label) {
    return encryptWithSeed(pub, message, rng::randomBytes(HLEN), label);
}

std::vector<uint8_t> decrypt(const RSA::PrivateKey& priv,
                             const std::vector<uint8_t>& ciphertext,
                             const std::vector<uint8_t>& label) {
    size_t k = modulusBytes(*priv.n);

    // Length checks. These do not depend on secret data.
    if (k < 2 * HLEN + 2 || ciphertext.size() != k) {
        throw std::runtime_error("decryption error");
    }

    BigInt c = BigInt::fromBytesBE(ciphertext);
    auto m = RSA::decrypt(c, priv);
    if (!m) throw std::runtime_error("decryption error");
    std::vector<uint8_t> em = m->toBytesBE(k);

    Sha256::Digest lHash = Sha256::hash(label);

    // EM = Y(1) || maskedSeed(hLen) || maskedDB(k-hLen-1)
    const uint8_t Y = em[0];
    std::vector<uint8_t> maskedSeed(em.begin() + 1, em.begin() + 1 + HLEN);
    std::vector<uint8_t> maskedDB(em.begin() + 1 + HLEN, em.end());

    std::vector<uint8_t> seedMask = mgf1_sha256(maskedDB, HLEN);
    std::vector<uint8_t> seed(HLEN);
    for (size_t i = 0; i < HLEN; ++i) seed[i] = maskedSeed[i] ^ seedMask[i];

    std::vector<uint8_t> dbMask = mgf1_sha256(seed, k - HLEN - 1);
    std::vector<uint8_t> db(maskedDB.size());
    for (size_t i = 0; i < db.size(); ++i) db[i] = maskedDB[i] ^ dbMask[i];

    // Validate without branching on which check fails: accumulate a mask so the
    // error path is uniform (Manger-attack resistant). The bignum operations
    // above are not constant-time, but the padding decision here is.
    uint8_t bad = 0;
    bad |= Y;  // first byte must be 0x00
    for (size_t i = 0; i < HLEN; ++i) bad |= (db[i] ^ lHash[i]);  // lHash' == lHash

    // Find the 0x01 separator after the zero padding string.
    size_t oneIndex = 0;
    uint8_t foundOne = 0;
    for (size_t i = HLEN; i < db.size(); ++i) {
        uint8_t isOne  = (db[i] == 0x01) ? 1 : 0;
        uint8_t isZero = (db[i] == 0x00) ? 1 : 0;
        // Record the first 0x01; any non-zero byte before it is a padding error.
        if (!foundOne && isOne) { foundOne = 1; oneIndex = i; }
        else if (!foundOne && !isZero) { bad |= 1; }
    }
    if (!foundOne) bad |= 1;

    if (bad != 0) throw std::runtime_error("decryption error");

    return std::vector<uint8_t>(db.begin() + oneIndex + 1, db.end());
}

} // namespace oaep

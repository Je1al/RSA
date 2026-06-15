#include "pss.hpp"
#include "sha256.hpp"
#include "mgf1.hpp"
#include "rng.hpp"
#include "bigmath.hpp"

#include <stdexcept>

namespace pss {

namespace {
constexpr size_t HLEN = Sha256::DIGEST_SIZE;  // 32

// EMSA-PSS-ENCODE (RFC 8017 9.1.1).
std::vector<uint8_t> emsaPssEncode(const std::vector<uint8_t>& message,
                                   const std::vector<uint8_t>& salt,
                                   size_t emBits) {
    size_t emLen = (emBits + 7) / 8;
    size_t sLen  = salt.size();

    Sha256::Digest mHash = Sha256::hash(message);

    if (emLen < HLEN + sLen + 2) {
        throw std::runtime_error("encoding error: modulus too small for PSS");
    }

    // M' = (0x00 * 8) || mHash || salt ; H = Hash(M')
    std::vector<uint8_t> mPrime(8, 0x00);
    mPrime.insert(mPrime.end(), mHash.begin(), mHash.end());
    mPrime.insert(mPrime.end(), salt.begin(), salt.end());
    Sha256::Digest H = Sha256::hash(mPrime);

    // DB = PS(0x00...) || 0x01 || salt    (length emLen - hLen - 1)
    std::vector<uint8_t> db(emLen - HLEN - 1, 0x00);
    size_t psLen = emLen - sLen - HLEN - 2;
    db[psLen] = 0x01;
    std::copy(salt.begin(), salt.end(), db.begin() + psLen + 1);

    std::vector<uint8_t> dbMask = mgf1_sha256(H.data(), H.size(), emLen - HLEN - 1);
    for (size_t i = 0; i < db.size(); ++i) db[i] ^= dbMask[i];

    // Zero the leftmost 8*emLen - emBits bits of the leftmost octet.
    size_t topBits = 8 * emLen - emBits;
    db[0] &= static_cast<uint8_t>(0xFF >> topBits);

    // EM = maskedDB || H || 0xbc
    std::vector<uint8_t> em;
    em.reserve(emLen);
    em.insert(em.end(), db.begin(), db.end());
    em.insert(em.end(), H.begin(), H.end());
    em.push_back(0xbc);
    return em;
}

// EMSA-PSS-VERIFY (RFC 8017 9.1.2). sLen is the expected salt length.
bool emsaPssVerify(const std::vector<uint8_t>& message,
                   const std::vector<uint8_t>& em,
                   size_t emBits, size_t sLen) {
    size_t emLen = (emBits + 7) / 8;
    if (em.size() != emLen) return false;
    if (emLen < HLEN + sLen + 2) return false;
    if (em.back() != 0xbc) return false;

    Sha256::Digest mHash = Sha256::hash(message);

    std::vector<uint8_t> maskedDB(em.begin(), em.begin() + (emLen - HLEN - 1));
    std::vector<uint8_t> H(em.begin() + (emLen - HLEN - 1), em.end() - 1);

    // The leftmost 8*emLen - emBits bits of maskedDB must be zero.
    size_t topBits = 8 * emLen - emBits;
    if (topBits > 0 && (maskedDB[0] & (0xFF << (8 - topBits))) != 0) return false;

    std::vector<uint8_t> dbMask = mgf1_sha256(H.data(), H.size(), emLen - HLEN - 1);
    std::vector<uint8_t> db(maskedDB.size());
    for (size_t i = 0; i < db.size(); ++i) db[i] = maskedDB[i] ^ dbMask[i];
    db[0] &= static_cast<uint8_t>(0xFF >> topBits);

    size_t psLen = emLen - HLEN - sLen - 2;
    for (size_t i = 0; i < psLen; ++i) {
        if (db[i] != 0x00) return false;
    }
    if (db[psLen] != 0x01) return false;

    std::vector<uint8_t> salt(db.end() - sLen, db.end());

    std::vector<uint8_t> mPrime(8, 0x00);
    mPrime.insert(mPrime.end(), mHash.begin(), mHash.end());
    mPrime.insert(mPrime.end(), salt.begin(), salt.end());
    Sha256::Digest Hprime = Sha256::hash(mPrime);

    return std::equal(H.begin(), H.end(), Hprime.begin());
}

} // namespace

std::vector<uint8_t> signWithSalt(const RSA::PrivateKey& priv,
                                  const std::vector<uint8_t>& message,
                                  const std::vector<uint8_t>& salt) {
    size_t modBits = priv.n->bitLength();
    size_t k = priv.n->byteLength();

    std::vector<uint8_t> em = emsaPssEncode(message, salt, modBits - 1);

    BigInt m = BigInt::fromBytesBE(em);
    auto s = RSA::decrypt(m, priv);  // RSASP1: s = m^d mod n
    if (!s) throw std::runtime_error("PSS signing primitive failed");
    return s->toBytesBE(k);
}

std::vector<uint8_t> sign(const RSA::PrivateKey& priv,
                          const std::vector<uint8_t>& message) {
    return signWithSalt(priv, message, rng::randomBytes(SALT_LEN));
}

bool verify(const RSA::PublicKey& pub,
            const std::vector<uint8_t>& message,
            const std::vector<uint8_t>& signature) {
    size_t modBits = pub.n->bitLength();
    size_t k = pub.n->byteLength();
    if (signature.size() != k) return false;

    BigInt s = BigInt::fromBytesBE(signature);
    if (s.cmp(*pub.n) >= 0) return false;

    auto m = RSA::encrypt(s, pub);  // RSAVP1: m = s^e mod n
    if (!m) return false;

    size_t emBits = modBits - 1;
    size_t emLen  = (emBits + 7) / 8;
    if (m->byteLength() > emLen) return false;  // I2OSP would overflow -> inconsistent

    std::vector<uint8_t> em = m->toBytesBE(emLen);
    return emsaPssVerify(message, em, emBits, SALT_LEN);
}

} // namespace pss

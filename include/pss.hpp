#ifndef RSA_PSS_HPP
#define RSA_PSS_HPP

#include <cstdint>
#include <vector>

#include "rsa.hpp"

// RSASSA-PSS (RFC 8017 / PKCS#1 v2.2, Section 8.1) with SHA-256, MGF1-SHA-256,
// and a salt length equal to the hash length (32 bytes).
//
// PSS is the modern, provably secure RSA signature scheme. Unlike the
// deterministic textbook "sign = hash^d mod n", PSS randomises every signature
// and has a tight security reduction, blocking the existential-forgery tricks
// that affect naive RSA signatures.
namespace pss {

constexpr size_t SALT_LEN = 32;

// Returns a `k`-byte signature (k = modulus length in bytes).
std::vector<uint8_t> sign(const RSA::PrivateKey& priv,
                          const std::vector<uint8_t>& message);

// Returns true iff `signature` is a valid PSS signature of `message` under `pub`.
bool verify(const RSA::PublicKey& pub,
            const std::vector<uint8_t>& message,
            const std::vector<uint8_t>& signature);

// Test-only: sign with a caller-supplied salt (SALT_LEN bytes) for KATs.
std::vector<uint8_t> signWithSalt(const RSA::PrivateKey& priv,
                                  const std::vector<uint8_t>& message,
                                  const std::vector<uint8_t>& salt);

} // namespace pss

#endif // RSA_PSS_HPP

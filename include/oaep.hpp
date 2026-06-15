#ifndef RSA_OAEP_HPP
#define RSA_OAEP_HPP

#include <cstdint>
#include <vector>

#include "rsa.hpp"

// RSAES-OAEP (RFC 8017 / PKCS#1 v2.2, Section 7.1) with SHA-256 and MGF1-SHA-256.
//
// OAEP turns RSA into an IND-CCA2-secure scheme: encryption is randomised (the
// same plaintext encrypts to different ciphertexts) and the padding check makes
// the chosen-ciphertext attacks that break textbook and PKCS#1 v1.5 RSA infeasible.
namespace oaep {

// Largest message (bytes) encryptable under a given modulus: k - 2*hLen - 2.
size_t maxMessageLen(const RSA::PublicKey& pub);

// Throws std::runtime_error("message too long") if the message does not fit.
std::vector<uint8_t> encrypt(const RSA::PublicKey& pub,
                             const std::vector<uint8_t>& message,
                             const std::vector<uint8_t>& label = {});

// Throws std::runtime_error("decryption error") on any padding/length failure.
// The failure path is uniform: it does not reveal which check failed (defends
// against Manger's adaptive chosen-ciphertext attack).
std::vector<uint8_t> decrypt(const RSA::PrivateKey& priv,
                             const std::vector<uint8_t>& ciphertext,
                             const std::vector<uint8_t>& label = {});

// Test-only: encrypt with a caller-supplied seed (must be hLen = 32 bytes) so
// known-answer vectors can be reproduced. Production code must use encrypt().
std::vector<uint8_t> encryptWithSeed(const RSA::PublicKey& pub,
                                     const std::vector<uint8_t>& message,
                                     const std::vector<uint8_t>& seed,
                                     const std::vector<uint8_t>& label = {});

} // namespace oaep

#endif // RSA_OAEP_HPP

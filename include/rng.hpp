#ifndef RSA_RNG_HPP
#define RSA_RNG_HPP

#include <cstdint>
#include <cstddef>
#include <vector>

// Cryptographically secure randomness for the whole library.
//
//   OS entropy  ->  HMAC-DRBG (SP 800-90A)  ->  consumers (key generation, …)
//
// This replaces the std::mt19937 / std::random_device generators that the
// original implementation used for key material — Mersenne Twister is fully
// predictable from 624 observed outputs and must never seed a private key.
namespace rng {

// Fills `buf` with `len` bytes pulled directly from the operating system CSPRNG
// (getentropy / getrandom / BCryptGenRandom, with a /dev/urandom fallback).
// Throws std::runtime_error if the OS cannot provide entropy.
void osEntropy(uint8_t* buf, size_t len);

// Fills `buf` with `len` cryptographically secure bytes from the process-global
// HMAC-DRBG (lazily seeded from osEntropy, automatically reseeded). Thread-safe.
void randomBytes(uint8_t* buf, size_t len);

std::vector<uint8_t> randomBytes(size_t len);

// Returns a uniformly distributed value in [0, bound) without modulo bias,
// using rejection sampling over the global CSPRNG. bound must be > 0.
uint64_t randomBelow(uint64_t bound);

} // namespace rng

#endif // RSA_RNG_HPP

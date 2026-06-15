#ifndef RSA_MGF1_HPP
#define RSA_MGF1_HPP

#include <cstdint>
#include <cstddef>
#include <vector>

// MGF1 mask generation function with SHA-256 (RFC 8017 Appendix B.2.1).
// Produces `maskLen` bytes deterministically from `seed`.
std::vector<uint8_t> mgf1_sha256(const uint8_t* seed, size_t seedLen, size_t maskLen);
std::vector<uint8_t> mgf1_sha256(const std::vector<uint8_t>& seed, size_t maskLen);

#endif // RSA_MGF1_HPP

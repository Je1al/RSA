#ifndef RSA_KEYIO_HPP
#define RSA_KEYIO_HPP

#include <string>

#include "rsa.hpp"

// DER/PEM serialization that interoperates with OpenSSL:
//   - public keys  as SubjectPublicKeyInfo   (PEM label "PUBLIC KEY")
//   - private keys as PKCS#8 PrivateKeyInfo   (PEM label "PRIVATE KEY")
//
// Encoding follows X.509 / PKCS#1 / PKCS#8 (RFC 5280, RFC 8017, RFC 5958).
// This is what lets a key generated here be loaded by `openssl pkey`, and lets
// this library consume keys that OpenSSL produced.
namespace keyio {

std::string toPublicPem(const RSA::PublicKey& pub);    // SubjectPublicKeyInfo
std::string toPrivatePem(const RSA::PrivateKey& priv); // PKCS#8 PrivateKeyInfo

// Parse PEM (throws std::runtime_error on malformed input).
RSA::PublicKey  publicFromPem(const std::string& pem);
RSA::PrivateKey privateFromPem(const std::string& pem);

} // namespace keyio

#endif // RSA_KEYIO_HPP

#ifndef RSA_HPP
#define RSA_HPP

#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>
#include "bigmath.hpp"

class RSA
{
public:
    static constexpr uint32_t DEFAULT_E = 65537;

    struct PublicKey
    {
        // Modulus
        std::shared_ptr<BigInt> n;

        // Public exponent
        std::shared_ptr<BigInt> e;
        size_t bitlen = 0;
    };

    struct PrivateKey
    {
        // Modulus
        std::shared_ptr<BigInt> n;

        // Private exponent
        std::shared_ptr<BigInt> d;

        // Prime factors
        std::shared_ptr<BigInt> p;
        std::shared_ptr<BigInt> q;

        // d mod (p-1)
        std::shared_ptr<BigInt> dp;

        // d mod (q-1)
        std::shared_ptr<BigInt> dq;

        // q^-1 mod p
        std::shared_ptr<BigInt> qinv;

        // Public exponent. Held only for in-memory keys so decryption can apply
        // base blinding (a timing/fault-attack mitigation). May be null for keys
        // loaded from disk, in which case decryption runs CRT without blinding.
        std::shared_ptr<BigInt> e;

        size_t bitlen = 0;
    };

    static bool generateKeys(PublicKey& pub,
        PrivateKey& priv,
        size_t bits,
        uint32_t e_value = DEFAULT_E);

    static std::shared_ptr<BigInt> encrypt(const BigInt& m, const PublicKey& pub);
    static std::shared_ptr<BigInt> decrypt(const BigInt& c, const PrivateKey& priv);

    static std::shared_ptr<BigInt> strToNumber(const uint8_t* str, size_t len);
    static std::vector<uint8_t> numberToStr(const BigInt& m);

    static bool checkKeypair(const PublicKey& pub, const PrivateKey& priv);
    static bool verify_mod_inverse(const BigInt& e, const BigInt& d, const BigInt& phi_n);
    static BigInt brute_force_mod_inverse(const BigInt& e, const BigInt& phi_n);

    static void setEncoding(bool useUtf8);

private:
    static std::shared_ptr<BigInt> modExp(const BigInt& base, const BigInt& exp, const BigInt& mod);
    static std::shared_ptr<BigInt> modInverse(const BigInt& a, const BigInt& m);
    static bool millerRabinTest(const BigInt& candidate, int rounds = 40);
    static std::shared_ptr<BigInt> randomPrime(size_t bits);

    static bool g_use_utf8;
};

#endif // RSA_HPP

// rsa.cpp
#include "rsa.hpp"
#include "prime_generator.hpp"
#include "bigmath_internal.hpp"
#include "utils.hpp"
#include <iostream>
#include <stdexcept>
#include <random>
#include <chrono>

using namespace std;


// Static instance of prime number generator
static unique_ptr<MillerRabinPrimeGenerator> g_prime_generator = make_unique<MillerRabinPrimeGenerator>();
bool RSA::g_use_utf8 = false;

namespace {
    // Helper functions

    // Function to check if e and φ(n) are coprime
    bool areCoprime(const BigInt& a, const BigInt& b) {
        // Use Euclidean algorithm
        BigInt x = a;
        BigInt y = b;

        while (y.cmp(BigInt::fromU64(0)) != 0) {
            BigInt temp = y;
            // Use modNaive instead of division with remainder
            BigInt remainder = BigInt::modNaive(x, y);
            y = remainder;
            x = temp;
        }

        // If GCD = 1, numbers are coprime
        return x.cmp(BigInt::fromU64(1)) == 0;
    }

    BigInt computeEulerPhi(const BigInt& p, const BigInt& q) {
        // φ(n) = (p-1)*(q-1)
        BigInt one = BigInt::fromU64(1);

        // p-1
        BigInt p_minus_1 = exported_internal_sub(p, one);
        // q-1
        BigInt q_minus_1 = exported_internal_sub(q, one);

        return BigInt::mulNaive(p_minus_1, q_minus_1);
    }

    // Check if number is less than modulus
    bool isLessThanModulus(const BigInt& m, const BigInt& n) {
        return m.cmp(n) < 0;
    }
}

// Implementation of static methods of RSA class

bool RSA::generateKeys(PublicKey& pub, PrivateKey& priv, size_t bits, uint32_t e_value) {
    try {
        // Validate input parameters
        if (bits < 16) {
            throw invalid_argument("Key length must be at least 16 bits");
        }

        if (e_value % 2 == 0) {
            throw invalid_argument("Public exponent must be odd");
        }

        // Generate prime numbers p and q
        size_t p_bits = bits / 2;
        size_t q_bits = bits - p_bits;

        // Ensure both numbers are sufficiently large
        if (p_bits < 8 || q_bits < 8) {
            throw invalid_argument("Prime numbers too small");
        }

        shared_ptr<BigInt> p = make_shared<BigInt>(g_prime_generator->generatePrime(p_bits));
        shared_ptr<BigInt> q = make_shared<BigInt>(g_prime_generator->generatePrime(q_bits));

        // Ensure p != q and they are sufficiently different
        int max_attempts = 5;
        int attempts = 0;

        // Simple condition: p != q
        while (p->cmp(*q) == 0 && attempts < max_attempts) {
            q = make_shared<BigInt>(g_prime_generator->generatePrime(q_bits));
            attempts++;
        }

        if (p->cmp(*q) == 0) {
            throw runtime_error("Failed to generate distinct prime numbers");
        }

        // Ensure p > q for convenience (not required but useful for CRT)
        if (p->cmp(*q) < 0) {
            swap(p, q);
        }

        // Compute n = p * q
        shared_ptr<BigInt> n = make_shared<BigInt>(BigInt::mulNaive(*p, *q));

        // Compute φ(n) = (p-1)*(q-1)
        BigInt phi_n = computeEulerPhi(*p, *q);

        // Create public exponent
        shared_ptr<BigInt> e = make_shared<BigInt>(BigInt::fromU64(e_value));

        // Verify that e is coprime with φ(n)
        if (!areCoprime(*e, phi_n)) {
            throw runtime_error("Public exponent is not coprime with phi(n)");
        }

        // Compute private exponent d = e^(-1) mod φ(n)
        BigInt d_calc = exported_mod_inverse_binary(*e, phi_n);

        if (d_calc.cmp(BigInt::fromU64(0)) == 0) {
            // Try alternative method
            d_calc = brute_force_mod_inverse(*e, phi_n);

            if (d_calc.cmp(BigInt::fromU64(0)) == 0) {
                throw runtime_error("Failed to compute modular inverse");
            }
        }

        shared_ptr<BigInt> d = make_shared<BigInt>(d_calc);

        BigInt e_times_d = BigInt::mulNaive(*e, d_calc);
        BigInt e_times_d_mod_phi = BigInt::modNaive(e_times_d, phi_n);

        if (e_times_d_mod_phi.cmp(BigInt::fromU64(1)) != 0) {
            throw runtime_error("Key validation failed: e*d mod φ(n) != 1");
        }

        // Fill public key structure
        pub.n = n;
        pub.e = e;
        pub.bitlen = bits;

        // Fill private key structure
        priv.n = n;
        priv.d = d;
        priv.p = p;
        priv.q = q;
        priv.bitlen = bits;

        // Compute additional parameters for CRT (optimization)
        // dp = d mod (p-1)
        BigInt p_minus_1 = exported_internal_sub(*p, BigInt::fromU64(1));
        priv.dp = make_shared<BigInt>(BigInt::modNaive(*d, p_minus_1));

        // dq = d mod (q-1)
        BigInt q_minus_1 = exported_internal_sub(*q, BigInt::fromU64(1));
        priv.dq = make_shared<BigInt>(BigInt::modNaive(*d, q_minus_1));

        // qinv = q^(-1) mod p
        priv.qinv = make_shared<BigInt>(exported_mod_inverse_binary(*q, *p));

        return true;

    }
    catch (const exception& e) {
        cerr << "Key generation failed: " << e.what() << endl;
        return false;
    }
}

bool RSA::verify_mod_inverse(const BigInt& e, const BigInt& d, const BigInt& phi_n) {
    cout << "\n=== VERIFICATION ===" << endl;
    cout << "e: " << e.toHex() << endl;
    cout << "d: " << d.toHex() << endl;
    cout << "phi(n): " << phi_n.toHex() << endl;

    // Compute e*d
    BigInt e_times_d = BigInt::mulNaive(e, d);
    cout << "e*d: " << e_times_d.toHex() << endl;

    // Compute e*d mod φ(n)
    BigInt result = BigInt::modNaive(e_times_d, phi_n);
    cout << "e*d mod φ(n): " << result.toHex() << endl;

    // Check if equals 1
    bool ok = result.cmp(BigInt::fromU64(1)) == 0;
    cout << "Is 1? " << (ok ? "YES" : "NO") << endl;
    cout << "==================" << endl;

    return ok;
}

BigInt RSA::brute_force_mod_inverse(const BigInt& e, const BigInt& phi_n) {
    // Simple brute force for debugging (only for small numbers)
    cout << "\nTrying brute force..." << endl;

    BigInt one = BigInt::fromU64(1);
    BigInt k = BigInt::fromU64(1);

    for (int i = 0; i < 10000; i++) {
        // Compute (phi_n * k + 1)
        BigInt phi_k = BigInt::mulNaive(phi_n, k);
        BigInt value = exported_internal_add(phi_k, one);

        // Check if divisible by e
        if (BigInt::modNaive(value, e).cmp(BigInt::fromU64(0)) == 0) {
            // d = (phi_n * k + 1) / e
            BigInt d = BigInt::divmod(value, e, nullptr);
            cout << "Found k = " << k.toHex() << ", d = " << d.toHex() << endl;
            return d;
        }

        k = exported_internal_add(k, one);
    }

    cout << "Brute force failed" << endl;
    return BigInt::fromU64(0);
}

shared_ptr<BigInt> RSA::encrypt(const BigInt& m, const PublicKey& pub) {
    try {
        // Validate message
        if (!isLessThanModulus(m, *pub.n)) {
            throw invalid_argument("Message must be less than modulus n");
        }

        // Encryption: c = m^e mod n
        BigInt result = BigInt::modExp(m, *pub.e, *pub.n);
        return make_shared<BigInt>(result);

    }
    catch (const exception& e) {
        cerr << "Encryption failed: " << e.what() << endl;
        return nullptr;
    }
}

shared_ptr<BigInt> RSA::decrypt(const BigInt& c, const PrivateKey& priv) {
    try {
        // Validate ciphertext
        if (!isLessThanModulus(c, *priv.n)) {
            throw invalid_argument("Ciphertext must be less than modulus n");
        }

        // Decryption: m = c^d mod n
        BigInt result = BigInt::modExp(c, *priv.d, *priv.n);
        return make_shared<BigInt>(result);

    }
    catch (const exception& e) {
        cerr << "Decryption failed: " << e.what() << endl;
        return nullptr;
    }
}

void RSA::setEncoding(bool useUtf8) {
    g_use_utf8 = useUtf8;
}

shared_ptr<BigInt> RSA::strToNumber(const uint8_t* str, size_t len) {
    try {
        if (len == 0) {
            return make_shared<BigInt>(BigInt::fromU64(0));
        }

        BigInt result = BigInt::fromU64(0);
        BigInt base = BigInt::fromU64(256);

        if (g_use_utf8) {
            // For UTF-8: process all bytes as is
            for (size_t i = 0; i < len; ++i) {
                result = BigInt::mulNaive(result, base);
                uint64_t byte_val = static_cast<uint64_t>(str[i]);
                BigInt byte_bigint = BigInt::fromU64(byte_val);
                result = exported_internal_add(result, byte_bigint);
            }
        }
        else {
            // For ASCII/ANSI: single-byte characters
            for (size_t i = 0; i < len; ++i) {
                result = BigInt::mulNaive(result, base);
                uint64_t byte_val = static_cast<uint64_t>(str[i]);
                BigInt byte_bigint = BigInt::fromU64(byte_val);
                result = exported_internal_add(result, byte_bigint);
            }
        }

        return make_shared<BigInt>(result);

    }
    catch (const exception& e) {
        cerr << "String to number conversion failed: " << e.what() << endl;
        return nullptr;
    }
}

vector<uint8_t> RSA::numberToStr(const BigInt& m) {
    try {
        if (m.cmp(BigInt::fromU64(0)) == 0) {
            return vector<uint8_t>();
        }

        vector<uint8_t> bytes;
        BigInt temp = m;
        BigInt zero = BigInt::fromU64(0);
        BigInt base_256 = BigInt::fromU64(256);

        // Extract bytes (same for both encodings)
        while (temp.cmp(zero) > 0) {
            BigInt remainder = BigInt::modNaive(temp, base_256);
            uint64_t byte_val = remainder.toU64OrDie();
            bytes.push_back(static_cast<uint8_t>(byte_val));

            // Divide by 256
            temp = BigInt::divmod(temp, base_256, nullptr);
        }

        // Bytes were extracted in reverse order (least significant first)
        reverse(bytes.begin(), bytes.end());

        return bytes;

    }
    catch (const exception& e) {
        cerr << "Number to string conversion failed: " << e.what() << endl;
        return vector<uint8_t>();
    }
}

bool RSA::checkKeypair(const PublicKey& pub, const PrivateKey& priv) {
    try {
        // Generate test message smaller than n
        BigInt test_msg = exported_random_in_range(
            BigInt::fromU64(2),
            exported_internal_sub(*pub.n, BigInt::fromU64(1))
        );

        // Encrypt
        auto encrypted = encrypt(test_msg, pub);
        if (!encrypted) {
            cout << "Encryption failed in checkKeypair" << endl;
            return false;
        }

        // Decrypt
        auto decrypted = decrypt(*encrypted, priv);
        if (!decrypted) {
            cout << "Decryption failed in checkKeypair" << endl;
            return false;
        }

        // Check for match
        bool match = test_msg.cmp(*decrypted) == 0;
        if (!match) {
            cout << "Mismatch in checkKeypair:" << endl;
            cout << "Original: " << test_msg.toHex() << endl;
            cout << "Decrypted: " << decrypted->toHex() << endl;
        }
        return match;

    }
    catch (const exception& e) {
        cerr << "Exception in checkKeypair: " << e.what() << endl;
        return false;
    }
}

// Private methods of RSA
shared_ptr<BigInt> RSA::modExp(const BigInt& base, const BigInt& exp, const BigInt& mod) {
    try {
        BigInt result = BigInt::modExp(base, exp, mod);
        return make_shared<BigInt>(result);
    }
    catch (const exception& e) {
        cerr << "Modular exponentiation failed: " << e.what() << endl;
        return nullptr;
    }
}

shared_ptr<BigInt> RSA::modInverse(const BigInt& a, const BigInt& m) {
    try {
        BigInt result = exported_mod_inverse_binary(a, m);
        return make_shared<BigInt>(result);
    }
    catch (const exception& e) {
        cerr << "Modular inverse calculation failed: " << e.what() << endl;
        return nullptr;
    }
}

bool RSA::millerRabinTest(const BigInt& candidate, int rounds) {
    return g_prime_generator->isPrime(candidate, rounds);
}

shared_ptr<BigInt> RSA::randomPrime(size_t bits) {
    try {
        BigInt prime = g_prime_generator->generatePrime(bits);
        return make_shared<BigInt>(prime);
    }
    catch (const exception& e) {
        cerr << "Prime generation failed: " << e.what() << endl;
        return nullptr;
    }
}

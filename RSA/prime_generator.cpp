#include "prime_generator.hpp"
#include "bigmath_internal.hpp"
#include "bigmath.hpp"
#include <random>
#include <chrono>
#include <stdexcept>
#include <cstring>

// Helper function for checking small prime numbers
bool isSmallPrime(uint64_t n) {
    if (n < 2) return false;
    if (n == 2 || n == 3) return true;
    if (n % 2 == 0 || n % 3 == 0) return false;

    for (uint64_t i = 5; i * i <= n; i += 6) {
        if (n % i == 0 || n % (i + 2) == 0) return false;
    }
    return true;
}

void MillerRabinPrimeGenerator::decompose(const BigInt& n, BigInt& d, size_t& s) {
    // Calculate n-1
    BigInt n_minus_1 = exported_internal_sub(n, BigInt::fromU64(1));
    d = n_minus_1;
    s = 0;

    // Divide by 2 until d becomes odd
    while (exported_is_even(d)) {
        d = exported_big_rshift(d, 1);
        s++;
    }
}

bool MillerRabinPrimeGenerator::millerTest(const BigInt& d, const BigInt& n, const BigInt& a) {
    // Calculate x = a^d mod n
    BigInt x = BigInt::modExp(a, d, n);

    if (x.cmp(BigInt::fromU64(1)) == 0 || x.cmp(exported_internal_sub(n, BigInt::fromU64(1))) == 0) {
        return true;
    }

    // Repeat s-1 times
    BigInt n_minus_1 = exported_internal_sub(n, BigInt::fromU64(1));
    for (size_t i = 0; i < exported_count_bits(d); i++) {
        x = BigInt::modExp(x, BigInt::fromU64(2), n);

        if (x.cmp(n_minus_1) == 0) return true;
        if (x.cmp(BigInt::fromU64(1)) == 0) return false;
    }

    return false;
}

bool MillerRabinPrimeGenerator::isPrime(const BigInt& number, int rounds) {
    // Check trivial cases
    if (number.cmp(BigInt::fromU64(2)) < 0) return false;
    if (number.cmp(BigInt::fromU64(2)) == 0 || number.cmp(BigInt::fromU64(3)) == 0) return true;

    // Check if even
    if (exported_is_even(number)) return false;

    // Check small prime divisors (up to 1000)
    for (uint64_t p : {2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37}) {
        if (BigInt::modNaive(number, BigInt::fromU64(p)).cmp(BigInt::fromU64(0)) == 0) {
            return (number.cmp(BigInt::fromU64(p)) == 0);
        }
    }

    // Decompose n-1 = 2^s * d
    BigInt d;
    size_t s;
    decompose(number, d, s);

    // Random number generator
    std::random_device rd;
    std::mt19937_64 gen(rd());

    // Perform rounds of Miller-Rabin test
    for (int i = 0; i < rounds; i++) {
        // Generate random a in range [2, n-2]
        BigInt a = exported_random_in_range(BigInt::fromU64(2), exported_internal_sub(number, BigInt::fromU64(2)));

        if (!millerTest(d, number, a)) {
            return false;
        }
    }

    return true;
}

BigInt MillerRabinPrimeGenerator::generatePrime(size_t bits) {
    if (bits < 2) {
        throw std::invalid_argument("Bit length must be at least 2");
    }

    // For small bit lengths
    if (bits <= 16) {
        uint64_t min_val = 1ULL << (bits - 1);
        uint64_t max_val = (bits == 16) ? 65535 : ((1ULL << bits) - 1);

        std::random_device rd;
        std::mt19937_64 gen(rd());
        std::uniform_int_distribution<uint64_t> dis(min_val, max_val);

        for (int attempt = 0; attempt < 1000; attempt++) {
            uint64_t candidate = dis(gen);
            candidate |= 1; // Make it odd

            if (isSmallPrime(candidate)) {
                return BigInt::fromU64(candidate);
            }
        }
        throw std::runtime_error("Failed to generate small prime");
    }

    // For larger numbers
    const int MAX_ATTEMPTS = 100 * bits;

    for (int attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
        // Generate random number
        BigInt candidate = exported_generate_random_bigint(bits);

        // Set the most significant bit (to ensure required length)
        BigInt one = BigInt::fromU64(1);
        BigInt msb_mask = exported_big_lshift(one, bits - 1);
        candidate = exported_internal_add(candidate, msb_mask);

        // Make it odd
        if (exported_is_even(candidate)) {
            candidate = exported_internal_add(candidate, one);
        }

        // Check for primality
        if (isPrime(candidate, 10)) {
            return candidate;
        }
    }

    throw std::runtime_error("Failed to generate prime number after maximum attempts");
}

#include "prime_generator.hpp"
#include "bigmath_internal.hpp"
#include "bigmath.hpp"
#include "rng.hpp"
#include <stdexcept>
#include <cstring>

namespace {

// First 54 odd primes (3 .. 251). Trial division against these rejects the vast
// majority of random composite candidates far more cheaply than a Miller-Rabin
// round, which keeps key generation fast.
const uint32_t SMALL_PRIMES[] = {
      3,   5,   7,  11,  13,  17,  19,  23,  29,  31,  37,  41,  43,  47,  53,
     59,  61,  67,  71,  73,  79,  83,  89,  97, 101, 103, 107, 109, 113, 127,
    131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199,
    211, 223, 227, 229, 233, 239, 241, 251,
};

// Miller-Rabin round count for a 2^-128 worst-case error probability,
// following NIST FIPS 186-5 Appendix C.1 (Table C.1).
int millerRabinRounds(size_t bits) {
    if (bits >= 1536) return 4;
    if (bits >= 1024) return 5;
    if (bits >= 512)  return 7;
    return 40;  // small / toy keys: be conservative
}

} // namespace

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

bool MillerRabinPrimeGenerator::millerTest(const BigInt& d, size_t s, const BigInt& n, const BigInt& a) {
    BigInt one         = BigInt::fromU64(1);
    BigInt two         = BigInt::fromU64(2);
    BigInt n_minus_1   = exported_internal_sub(n, one);

    // x = a^d mod n
    BigInt x = BigInt::modExp(a, d, n);
    if (x.cmp(one) == 0 || x.cmp(n_minus_1) == 0) {
        return true;  // probable prime to base a
    }

    // Square s-1 times, watching for a nontrivial square root of 1.
    // (The original code looped count_bits(d) times instead of s-1, which is a
    //  bug: it does not match the factorisation n-1 = 2^s * d.)
    for (size_t i = 1; i < s; ++i) {
        x = BigInt::modExp(x, two, n);
        if (x.cmp(n_minus_1) == 0) return true;   // probable prime
        if (x.cmp(one) == 0)       return false;  // nontrivial sqrt of 1 => composite
    }

    return false;  // composite
}

bool MillerRabinPrimeGenerator::isPrime(const BigInt& number, int rounds) {
    // Check trivial cases
    if (number.cmp(BigInt::fromU64(2)) < 0) return false;
    if (number.cmp(BigInt::fromU64(2)) == 0 || number.cmp(BigInt::fromU64(3)) == 0) return true;

    // Check if even
    if (exported_is_even(number)) return false;

    // Trial division by small odd primes using the fast O(words) remainder:
    // cheaply discards most composites before any Miller-Rabin exponentiation.
    for (uint32_t p : SMALL_PRIMES) {
        if (exported_mod_small(number, p) == 0) {
            return number.cmp(BigInt::fromU64(p)) == 0;  // divisible by p
        }
    }

    // Decompose n-1 = 2^s * d
    BigInt d;
    size_t s;
    decompose(number, d, s);

    // Witness bases are drawn from the cryptographic CSPRNG (rng), not from the
    // predictable std::mt19937_64 the original code used here.
    BigInt low  = BigInt::fromU64(2);
    BigInt high = exported_internal_sub(number, BigInt::fromU64(2));
    for (int i = 0; i < rounds; i++) {
        BigInt a = exported_random_in_range(low, high);
        if (!millerTest(d, s, number, a)) {
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
        uint64_t span    = ((bits == 16) ? 65536ULL : (1ULL << bits)) - min_val;

        for (int attempt = 0; attempt < 100000; attempt++) {
            uint64_t candidate = min_val + rng::randomBelow(span);
            candidate |= 1;  // make it odd

            if (isSmallPrime(candidate)) {
                return BigInt::fromU64(candidate);
            }
        }
        throw std::runtime_error("Failed to generate small prime");
    }

    // For larger numbers
    const int MAX_ATTEMPTS = 100 * bits;

    BigInt one = BigInt::fromU64(1);
    for (int attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
        // Random `bits`-bit candidate (generate_random_bigint already sets bit
        // bits-1, giving the exact length).
        BigInt candidate = exported_generate_random_bigint(bits);

        // Force the second-highest bit as well. With the top two bits of both
        // primes set, the product p*q is guaranteed to have exactly the full key
        // length (the original code re-added the MSB here, which carried into an
        // extra bit and produced a modulus one bit too long).
        if (bits >= 2 && !exported_get_bigint_bit(candidate, bits - 2)) {
            candidate = exported_internal_add(candidate, exported_big_lshift(one, bits - 2));
        }

        // Make it odd
        if (exported_is_even(candidate)) {
            candidate = exported_internal_add(candidate, one);
        }

        // Check for primality with a FIPS 186-5 round count for this bit size.
        if (isPrime(candidate, millerRabinRounds(bits))) {
            return candidate;
        }
    }

    throw std::runtime_error("Failed to generate prime number after maximum attempts");
}

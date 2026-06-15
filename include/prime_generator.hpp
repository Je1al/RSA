#ifndef PRIME_GENERATOR_HPP
#define PRIME_GENERATOR_HPP

#include "bigmath.hpp"
#include <memory>
#include <vector>

// Class for generating prime numbers using the Miller-Rabin algorithm
class IPrimeGenerator {
public:
    virtual ~IPrimeGenerator() = default;

    // Generate a prime number of the specified bit length
    virtual BigInt generatePrime(size_t bits) = 0;

    // Check if a number is prime, number: number to check, rounds: number of Miller-Rabin test rounds
    virtual bool isPrime(const BigInt& number, int rounds = 40) = 0;
};

// Prime number generator based on the Miller-Rabin algorithm
class MillerRabinPrimeGenerator : public IPrimeGenerator {
public:
    BigInt generatePrime(size_t bits) override;
    bool isPrime(const BigInt& number, int rounds = 40) override;

private:
    /**
     * @brief Single Miller-Rabin round for one witness base
     * @param d Odd integer such that n-1 = 2^s * d
     * @param s Power of two in the factorisation n-1 = 2^s * d
     * @param n Number to test
     * @param a Witness base
     * @return true if n is a probable prime to base a, false if a proves it composite
     */
    bool millerTest(const BigInt& d, size_t s, const BigInt& n, const BigInt& a);

    /**
     * @brief Decompose n-1 into the form 2^s * d
     * @param n Number to decompose
     * @param d Output parameter - odd integer d
     * @param s Output parameter - exponent s
     */
    void decompose(const BigInt& n, BigInt& d, size_t& s);
};

#endif // PRIME_GENERATOR_HPP

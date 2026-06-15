// Attack: Fermat factorization of a modulus whose primes are too close.
//
// If p and q are near each other, n = p*q = a^2 - b^2 with a ~ sqrt(n) and a
// small b. Starting from a = ceil(sqrt(n)) and incrementing, a^2 - n becomes a
// perfect square b^2 after only a few steps, giving p = a-b, q = a+b and total
// break of the key.
//
// Defence: generate p and q independently. Two random k-bit primes differ by
// roughly 2^(k-1) on average, so b ~ 2^(k-2) and Fermat would need ~2^(k-2)
// iterations -- utterly infeasible.

#include "lab.hpp"

using namespace lab;

// Smallest prime strictly greater than `start` (start assumed odd).
static BigInt nextPrime(BigInt cand) {
    MillerRabinPrimeGenerator gen;
    cand = add(cand, u(2));
    while (!gen.isPrime(cand, 25)) cand = add(cand, u(2));
    return cand;
}

int main() {
    std::cout << "Fermat factorization: close primes break RSA\n";

    MillerRabinPrimeGenerator gen;

    rule("Vulnerable key: q chosen as the next prime after p");
    BigInt p = gen.generatePrime(512);
    BigInt q = nextPrime(p);                 // q very close to p
    BigInt n = mul(p, q);
    std::cout << "n = " << n.bitLength() << " bits, |p - q| = "
              << sub(q, p).toHex() << " (tiny)\n";

    // Fermat's method.
    BigInt a = isqrt(n);
    if (mul(a, a).cmp(n) < 0) a = add(a, u(1));   // a = ceil(sqrt(n))
    BigInt b;
    long iters = 0;
    while (true) {
        BigInt b2 = sub(mul(a, a), n);            // a^2 - n  (a^2 >= n)
        if (isPerfectSquare(b2, b)) break;
        a = add(a, u(1));
        if (++iters > 5000000) { std::cout << "gave up\n"; return 1; }
    }
    BigInt fp = sub(a, b), fq = add(a, b);
    bool ok = (eq(fp, p) && eq(fq, q)) || (eq(fp, q) && eq(fq, p));
    std::cout << "Recovered factors in " << iters << " iterations: "
              << (ok ? "SUCCESS -- n fully factored" : "mismatch") << "\n";
    std::cout << "  p recovered? " << (eq(fp, p) || eq(fq, p) ? "yes" : "no") << "\n";

    rule("Defence: independently generated primes");
    BigInt rp, rq, rn, rphi;
    makePrimes(512, rp, rq, rn, rphi);
    BigInt gap = (rp.cmp(rq) >= 0) ? sub(rp, rq) : sub(rq, rp);
    std::cout << "|p - q| for random primes = " << gap.bitLength()
              << "-bit number => Fermat needs ~2^" << (gap.bitLength() - 1)
              << " iterations (infeasible).\n";

    return 0;
}

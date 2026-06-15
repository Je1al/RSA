#ifndef RSA_ATTACK_LAB_HPP
#define RSA_ATTACK_LAB_HPP

// Shared helpers for the offensive attack demonstrations.
//
// These programs intentionally build *weak* RSA keys (small exponent, small
// private exponent, close primes, shared modulus) to show how each weakness is
// exploited and how the library's defaults — random primes, e = 65537, OAEP and
// PSS padding — prevent the attack.

#include "bigmath.hpp"
#include "bigmath_internal.hpp"
#include "prime_generator.hpp"
#include "rsa.hpp"

#include <iostream>
#include <string>
#include <vector>

namespace lab {

inline BigInt u(uint64_t v)        { return BigInt::fromU64(v); }
inline BigInt add(const BigInt& a, const BigInt& b) { return exported_internal_add(a, b); }
inline BigInt sub(const BigInt& a, const BigInt& b) { return exported_internal_sub(a, b); } // a >= b
inline BigInt mul(const BigInt& a, const BigInt& b) { return BigInt::mulNaive(a, b); }
inline BigInt mod(const BigInt& a, const BigInt& m) { return BigInt::modNaive(a, m); }
inline BigInt divq(const BigInt& a, const BigInt& b){ return BigInt::divmod(a, b, nullptr); }
inline BigInt modExp(const BigInt& b, const BigInt& e, const BigInt& m) { return BigInt::modExp(b, e, m); }
inline BigInt modInverse(const BigInt& a, const BigInt& m) { return exported_mod_inverse_binary(a, m); }
inline bool   isZero(const BigInt& a) { return a.cmp(u(0)) == 0; }
inline bool   eq(const BigInt& a, const BigInt& b) { return a.cmp(b) == 0; }

// (a - b) mod m, with a, b reduced first so the subtraction never goes negative.
inline BigInt subMod(const BigInt& a, const BigInt& b, const BigInt& m) {
    BigInt am = mod(a, m), bm = mod(b, m);
    if (am.cmp(bm) >= 0) return sub(am, bm);
    return sub(add(am, m), bm);
}

// floor(n^(1/2)) by Newton's method.
inline BigInt isqrt(const BigInt& n) {
    if (isZero(n)) return u(0);
    size_t bits = n.bitLength();
    BigInt x = exported_big_lshift(u(1), (bits + 2) / 2);  // upper bound on the root
    while (true) {
        BigInt nx   = divq(n, x);
        BigInt next = exported_big_rshift(add(x, nx), 1);  // (x + n/x) / 2
        if (next.cmp(x) >= 0) break;
        x = next;
    }
    while (mul(x, x).cmp(n) > 0) x = sub(x, u(1));
    return x;
}

inline bool isPerfectSquare(const BigInt& n, BigInt& root) {
    root = isqrt(n);
    return eq(mul(root, root), n);
}

inline BigInt ipow(const BigInt& base, unsigned k) {
    BigInt r = u(1);
    for (unsigned i = 0; i < k; ++i) r = mul(r, base);
    return r;
}

// floor(n^(1/k)) by binary search; sets `exact` if the root is exact.
inline BigInt iroot(const BigInt& n, unsigned k, bool& exact) {
    if (isZero(n)) { exact = true; return u(0); }
    size_t bits = n.bitLength();
    BigInt lo = u(0), hi = exported_big_lshift(u(1), bits / k + 1);
    while (lo.cmp(hi) < 0) {
        BigInt mid = exported_big_rshift(add(add(lo, hi), u(1)), 1);  // ceil((lo+hi)/2)
        if (ipow(mid, k).cmp(n) <= 0) lo = mid; else hi = sub(mid, u(1));
    }
    exact = eq(ipow(lo, k), n);
    return lo;
}

// CRT for two coprime moduli: returns the unique x in [0, n1*n2) with
// x = a1 (mod n1) and x = a2 (mod n2).
inline BigInt crt2(const BigInt& a1, const BigInt& n1,
                   const BigInt& a2, const BigInt& n2) {
    BigInt inv  = modInverse(mod(n1, n2), n2);   // n1^{-1} mod n2
    BigInt diff = subMod(a2, a1, n2);
    BigInt t    = mod(mul(diff, inv), n2);
    return add(a1, mul(n1, t));                  // a1 + n1 * t
}

// Generate a distinct prime pair of the given bit size and their product /
// Euler totient. Used to build deliberately weak keys.
inline void makePrimes(size_t bits, BigInt& p, BigInt& q, BigInt& n, BigInt& phi) {
    MillerRabinPrimeGenerator gen;
    p = gen.generatePrime(bits);
    do { q = gen.generatePrime(bits); } while (eq(p, q));
    n   = mul(p, q);
    phi = mul(sub(p, u(1)), sub(q, u(1)));
}

inline std::vector<uint8_t> toBytes(const std::string& s) {
    return std::vector<uint8_t>(s.begin(), s.end());
}

inline void rule(const std::string& title) {
    std::cout << "\n=== " << title << " ===\n";
}

} // namespace lab

#endif // RSA_ATTACK_LAB_HPP

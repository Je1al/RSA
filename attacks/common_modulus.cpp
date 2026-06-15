// Attack: common-modulus. If the same modulus n is handed to two users with
// different, coprime public exponents e1, e2, then anyone who captures the two
// ciphertexts of the SAME message recovers it with no private key at all.
//
// Because gcd(e1, e2) = 1 there exist a, b with a*e1 + b*e2 = 1, so
//     c1^a * c2^b = m^(a*e1 + b*e2) = m   (mod n).
// We take a = e1^{-1} mod e2 (>= 0) and b = -(a*e1 - 1)/e2, using a modular
// inverse of c2 for the negative exponent.
//
// Defence: never share a modulus between users. Every key gets its own n.

#include "lab.hpp"

using namespace lab;

int main() {
    std::cout << "Common-modulus attack: shared n, two coprime exponents\n";

    // Build a key and read its factorisation so we can pick valid exponents.
    // Retry until we find a second exponent coprime to phi (avoids any chance of
    // a zero divisor later).
    RSA::PublicKey pub;
    RSA::PrivateKey priv;
    BigInt n, phi, e1 = u(65537), e2;
    bool haveE2 = false;
    while (!haveE2) {
        while (!RSA::generateKeys(pub, priv, 1024)) {}
        n   = *pub.n;
        phi = mul(sub(*priv.p, u(1)), sub(*priv.q, u(1)));
        for (uint64_t cand : {3ull, 5ull, 7ull, 11ull, 13ull, 17ull, 19ull, 23ull, 65539ull}) {
            BigInt c = u(cand);
            if (eq(exported_gcd_euclidean(c, phi), u(1)) &&
                eq(exported_gcd_euclidean(c, e1), u(1))) {
                e2 = c; haveE2 = true; break;
            }
        }
    }
    std::cout << "Shared modulus n (" << n.bitLength() << " bits); e1 = " << e1.toHex()
              << ", e2 = " << e2.toHex() << "\n";

    BigInt m = BigInt::fromBytesBE(toBytes("launch code: 0451"));
    BigInt c1 = modExp(m, e1, n);   // user 1's ciphertext
    BigInt c2 = modExp(m, e2, n);   // user 2's ciphertext

    rule("Recovery using only c1, c2, e1, e2, n");
    BigInt a = modInverse(e1, e2);            // a = e1^{-1} mod e2
    BigInt t = divq(sub(mul(a, e1), u(1)), e2);  // a*e1 - 1 = t*e2  (so b = -t)
    BigInt c2inv = modInverse(c2, n);

    BigInt rec = mod(mul(modExp(c1, a, n), modExp(c2inv, t, n)), n);
    std::cout << "  a*e1 - t*e2 == 1 ? " << (eq(sub(mul(a, e1), mul(t, e2)), u(1)) ? "yes" : "no") << "\n";
    std::cout << "  recovered == m ? " << (eq(rec, m) ? "YES -- message recovered" : "no") << "\n";
    std::cout << "  message: " << [&]{ auto b = rec.toBytesBE(); return std::string(b.begin(), b.end()); }() << "\n";

    rule("Defence");
    std::cout << "Give each user an independent modulus; a captured pair then\n"
                 "carries no exploitable algebraic relation.\n";
    return 0;
}

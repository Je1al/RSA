// Attack: Hastad's broadcast attack on a low public exponent.
//
// The same message m is sent to three recipients, each with e = 3 and a
// different modulus n1, n2, n3:   c_i = m^3 mod n_i.
// Since m < n_i for all i, we have m^3 < n1*n2*n3. The CRT recombination of
// (c1, c2, c3) is therefore exactly m^3 over the integers, and an ordinary
// integer cube root recovers m -- no private key required.
//
// Defence: randomised padding (RSAES-OAEP) makes the encrypted integer
// different for every recipient, so no single cube root exists. A large
// exponent (e = 65537) also defeats small-broadcast variants.

#include "lab.hpp"
#include "oaep.hpp"

using namespace lab;

// Generate an RSA key whose public exponent is exactly 3.
static void genE3Key(size_t bits, RSA::PublicKey& pub, RSA::PrivateKey& priv) {
    while (!RSA::generateKeys(pub, priv, bits, 3)) {}
}

int main() {
    std::cout << "Hastad broadcast attack: e = 3 to three recipients\n";

    const size_t bits = 768;
    RSA::PublicKey p1, p2, p3;
    RSA::PrivateKey s1, s2, s3;
    genE3Key(bits, p1, s1);
    genE3Key(bits, p2, s2);
    genE3Key(bits, p3, s3);

    BigInt n1 = *p1.n, n2 = *p2.n, n3 = *p3.n;
    BigInt m = BigInt::fromBytesBE(toBytes("MEET AT MIDNIGHT -- coordinates 48.13,11.57"));

    rule("Textbook RSA (no padding)");
    BigInt c1 = modExp(m, u(3), n1);
    BigInt c2 = modExp(m, u(3), n2);
    BigInt c3 = modExp(m, u(3), n3);

    // CRT over the three moduli, then an integer cube root.
    BigInt n12 = mul(n1, n2);
    BigInt x   = crt2(crt2(c1, n1, c2, n2), n12, c3, n3);  // = m^3 mod n1 n2 n3 = m^3
    bool exact = false;
    BigInt recovered = iroot(x, 3, exact);

    std::cout << "CRT product is a perfect cube? " << (exact ? "yes" : "no") << "\n";
    std::cout << "recovered == m ? " << (eq(recovered, m) ? "YES -- message recovered" : "no") << "\n";
    std::cout << "  message: " << [&]{ auto b = recovered.toBytesBE(); return std::string(b.begin(), b.end()); }() << "\n";

    rule("Defence: RSAES-OAEP padding");
    auto pt = toBytes("MEET AT MIDNIGHT");
    BigInt o1 = BigInt::fromBytesBE(oaep::encrypt(p1, pt));
    BigInt o2 = BigInt::fromBytesBE(oaep::encrypt(p2, pt));
    BigInt o3 = BigInt::fromBytesBE(oaep::encrypt(p3, pt));
    BigInt xo = crt2(crt2(o1, n1, o2, n2), n12, o3, n3);
    bool exactO = false;
    iroot(xo, 3, exactO);
    std::cout << "With OAEP, CRT product is a perfect cube? "
              << (exactO ? "yes (!)" : "no -- attack fails") << "\n";

    return 0;
}

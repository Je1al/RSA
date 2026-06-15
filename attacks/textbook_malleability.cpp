// Attack: why "textbook" RSA (no padding) is insecure.
//
//   1. It is deterministic   -> equal plaintexts give equal ciphertexts, so an
//                               eavesdropper can detect and replay known messages.
//   2. It is malleable       -> given C = E(m), an attacker who never learns m
//                               can forge E(m*s) for a chosen s, because
//                               E(m)*E(s) = (m*s)^e = E(m*s) (mod n).
//
// Defence: RSAES-OAEP randomises every encryption and rejects mauled
// ciphertexts, providing IND-CCA2 security.

#include "lab.hpp"
#include "oaep.hpp"

using namespace lab;

int main() {
    std::cout << "Textbook RSA: determinism and malleability\n";

    RSA::PublicKey pub;
    RSA::PrivateKey priv;
    while (!RSA::generateKeys(pub, priv, 1024)) {}
    const BigInt& n = *pub.n;
    const BigInt& e = *pub.e;

    BigInt m = BigInt::fromBytesBE(toBytes("transfer 100 EUR"));

    rule("1. Determinism");
    BigInt c1 = *RSA::encrypt(m, pub);
    BigInt c2 = *RSA::encrypt(m, pub);
    std::cout << "E(m) called twice -> identical ciphertext? "
              << (eq(c1, c2) ? "YES (leaks equality of plaintexts)" : "no") << "\n";

    rule("2. Malleability / forgery without the private key");
    // Attacker knows only C = E(m), e, n. Choose multiplier s = 2.
    BigInt s = u(2);
    BigInt factor = modExp(s, e, n);             // s^e mod n
    BigInt cForged = mod(mul(c1, factor), n);    // C * s^e = E(m*s)
    BigInt recovered = *RSA::decrypt(cForged, priv);
    BigInt expected = mod(mul(m, s), n);         // m*s mod n
    std::cout << "Forged C' = C * s^e (s=2), no private key used.\n";
    std::cout << "Victim decrypts C' to m*s ? "
              << (eq(recovered, expected) ? "YES -- ciphertext successfully mauled" : "no") << "\n";
    std::cout << "  original m : " << m.toHex() << "\n";
    std::cout << "  decrypted  : " << recovered.toHex() << "  (= 2*m mod n)\n";

    rule("Defence: RSAES-OAEP");
    auto pt = toBytes("transfer 100 EUR");
    auto o1 = oaep::encrypt(pub, pt);
    auto o2 = oaep::encrypt(pub, pt);
    std::cout << "OAEP E(m) twice -> identical? "
              << (o1 == o2 ? "yes" : "NO (randomised, no plaintext leak)") << "\n";

    // Maul an OAEP ciphertext the same way and try to decrypt.
    BigInt oc = BigInt::fromBytesBE(o1);
    BigInt ocForged = mod(mul(oc, factor), n);
    bool rejected = false;
    try { oaep::decrypt(priv, ocForged.toBytesBE(n.byteLength())); }
    catch (const std::runtime_error&) { rejected = true; }
    std::cout << "Mauled OAEP ciphertext -> decryption "
              << (rejected ? "REJECTED (integrity enforced)" : "accepted (!)") << "\n";

    return 0;
}

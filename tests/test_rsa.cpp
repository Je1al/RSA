// RSA core: key generation, the raw primitive, and the CRT + blinding path.

#include "test_framework.hpp"
#include "rsa.hpp"
#include "bigmath.hpp"

#include <chrono>

int main() {
    std::cout << "[rsa]    keygen + raw primitive + CRT/blinding\n";

    RSA::PublicKey pub;
    RSA::PrivateKey priv;

    auto t0 = std::chrono::steady_clock::now();
    bool ok = RSA::generateKeys(pub, priv, 512);
    auto t1 = std::chrono::steady_clock::now();
    double ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
    std::cout << "         512-bit keygen: " << ms << " ms\n";
    CHECK(ok);

    // n must have the requested bit length and be odd.
    CHECK(pub.n && priv.n);
    CHECK_EQ(pub.n->bitLength(), size_t(512));

    // Raw round-trip on a sample value.
    BigInt m = BigInt::fromU64(0xdeadbeefcafe1234ULL);
    auto c = RSA::encrypt(m, pub);
    CHECK(c != nullptr);
    auto d = RSA::decrypt(*c, priv);
    CHECK(d != nullptr);
    CHECK(m == *d);

    // Textbook RSA is deterministic: ciphertext differs from plaintext.
    CHECK(*c != m);

    // The CRT + blinding decryption must equal the textbook c^d mod n.
    BigInt plain = BigInt::modExp(*c, *priv.d, *priv.n);
    CHECK(plain == *d);

    // Self-test helper.
    CHECK(RSA::checkKeypair(pub, priv));

    return TF_REPORT();
}

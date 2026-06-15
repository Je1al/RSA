// RSAES-OAEP and RSASSA-PSS: round-trips, randomisation, and rejection of
// tampered ciphertexts / forged signatures.

#include "test_framework.hpp"
#include "rsa.hpp"
#include "oaep.hpp"
#include "pss.hpp"

#include <string>
#include <vector>

static std::vector<uint8_t> bytes(const std::string& s) {
    return std::vector<uint8_t>(s.begin(), s.end());
}

int main() {
    std::cout << "[oaep/pss] schemes over a freshly generated 1024-bit key\n";

    RSA::PublicKey pub;
    RSA::PrivateKey priv;
    CHECK(RSA::generateKeys(pub, priv, 1024));

    // ---- OAEP -------------------------------------------------------------
    auto msg = bytes("attack at dawn -- automotive secure boot key wrap");

    auto c1 = oaep::encrypt(pub, msg);
    auto c2 = oaep::encrypt(pub, msg);
    CHECK_EQ(c1.size(), priv.n->byteLength());
    CHECK(tf::toHex(c1) != tf::toHex(c2));        // randomised: ciphertexts differ
    CHECK_EQ(tf::toHex(oaep::decrypt(priv, c1)), tf::toHex(msg));
    CHECK_EQ(tf::toHex(oaep::decrypt(priv, c2)), tf::toHex(msg));

    // Empty message and a label.
    auto cl = oaep::encrypt(pub, {}, bytes("ctx"));
    CHECK(oaep::decrypt(priv, cl, bytes("ctx")).empty());

    // Wrong label must fail.
    {
        bool threw = false;
        try { oaep::decrypt(priv, cl, bytes("WRONG")); }
        catch (const std::runtime_error&) { threw = true; }
        CHECK(threw);
    }

    // Tampered ciphertext must fail (integrity from the OAEP check).
    {
        auto bad = c1;
        bad[bad.size() - 1] ^= 0x01;
        bool threw = false;
        try { oaep::decrypt(priv, bad); }
        catch (const std::runtime_error&) { threw = true; }
        CHECK(threw);
    }

    // Oversized message must be rejected.
    {
        std::vector<uint8_t> big(oaep::maxMessageLen(pub) + 1, 0x41);
        bool threw = false;
        try { oaep::encrypt(pub, big); }
        catch (const std::runtime_error&) { threw = true; }
        CHECK(threw);
    }

    // ---- PSS --------------------------------------------------------------
    auto doc = bytes("firmware-image-v4.2.1 sha256:deadbeef");
    auto sig = pss::sign(priv, doc);
    CHECK_EQ(sig.size(), priv.n->byteLength());
    CHECK(pss::verify(pub, doc, sig));

    // Randomised: two signatures over the same document differ but both verify.
    auto sig2 = pss::sign(priv, doc);
    CHECK(tf::toHex(sig) != tf::toHex(sig2));
    CHECK(pss::verify(pub, doc, sig2));

    // Forgery / tamper rejection.
    CHECK(!pss::verify(pub, bytes("firmware-image-v4.2.2 sha256:deadbeef"), sig));
    {
        auto badSig = sig;
        badSig[10] ^= 0x80;
        CHECK(!pss::verify(pub, doc, badSig));
    }

    // ---- deterministic hooks (used to reproduce known-answer vectors) ------
    {
        std::vector<uint8_t> seed(32, 0x5a);
        auto a = oaep::encryptWithSeed(pub, msg, seed);
        auto b = oaep::encryptWithSeed(pub, msg, seed);
        CHECK_EQ(tf::toHex(a), tf::toHex(b));                 // same seed -> same ct
        CHECK_EQ(tf::toHex(oaep::decrypt(priv, a)), tf::toHex(msg));

        std::vector<uint8_t> salt(32, 0x33);
        auto s1 = pss::signWithSalt(priv, doc, salt);
        auto s2 = pss::signWithSalt(priv, doc, salt);
        CHECK_EQ(tf::toHex(s1), tf::toHex(s2));               // same salt -> same sig
        CHECK(pss::verify(pub, doc, s1));
    }

    return TF_REPORT();
}

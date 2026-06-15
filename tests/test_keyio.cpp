// DER/PEM serialization: round-trip export -> import and confirm the
// reconstructed keys still encrypt/decrypt/sign/verify.

#include "test_framework.hpp"
#include "rsa.hpp"
#include "keyio.hpp"
#include "oaep.hpp"
#include "pss.hpp"

#include <string>

static std::vector<uint8_t> bytes(const std::string& s) {
    return std::vector<uint8_t>(s.begin(), s.end());
}

int main() {
    std::cout << "[keyio]  PEM export/import round-trip (SPKI + PKCS#8)\n";

    RSA::PublicKey pub;
    RSA::PrivateKey priv;
    CHECK(RSA::generateKeys(pub, priv, 1024));

    std::string pubPem  = keyio::toPublicPem(pub);
    std::string privPem = keyio::toPrivatePem(priv);

    // Sanity on the PEM envelopes.
    CHECK(pubPem.find("-----BEGIN PUBLIC KEY-----")   != std::string::npos);
    CHECK(privPem.find("-----BEGIN PRIVATE KEY-----") != std::string::npos);

    RSA::PublicKey  pub2  = keyio::publicFromPem(pubPem);
    RSA::PrivateKey priv2 = keyio::privateFromPem(privPem);

    // Re-imported components match the originals.
    CHECK(pub2.n->cmp(*pub.n) == 0);
    CHECK(pub2.e->cmp(*pub.e) == 0);
    CHECK(priv2.n->cmp(*priv.n) == 0);
    CHECK(priv2.d->cmp(*priv.d) == 0);
    CHECK(priv2.p->cmp(*priv.p) == 0);
    CHECK(priv2.qinv->cmp(*priv.qinv) == 0);

    // Cross-use: encrypt with the re-imported public key, decrypt with the
    // re-imported private key.
    auto msg = bytes("interop round-trip payload");
    auto ct  = oaep::encrypt(pub2, msg);
    CHECK_EQ(tf::toHex(oaep::decrypt(priv2, ct)), tf::toHex(msg));

    auto sig = pss::sign(priv2, msg);
    CHECK(pss::verify(pub2, msg, sig));

    // Idempotent re-export.
    CHECK_EQ(keyio::toPublicPem(pub2), pubPem);

    return TF_REPORT();
}

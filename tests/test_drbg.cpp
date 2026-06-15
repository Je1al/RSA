// Known-answer test for HMAC_DRBG (SHA-256), NIST SP 800-90A.
//
// Vector source: NIST CAVP HMAC_DRBG.rsp
//   [SHA-256], PredictionResistance = False, EntropyInputLen = 256,
//   NonceLen = 128, PersonalizationStringLen = 256, AdditionalInputLen = 0,
//   ReturnedBitsLen = 1024.  With reseed.  Per the CAVP protocol the first
//   Generate output is discarded and the second is compared.

#include "test_framework.hpp"
#include "drbg.hpp"

#include <vector>

int main() {
    std::cout << "[drbg]   NIST SP 800-90A HMAC_DRBG (SHA-256) KAT\n";

    auto entropy = tf::fromHex("fa0ee1fe39c7c390aa94159d0de97564342b591777f3e5f6a4ba2aea342ec840");
    auto nonce   = tf::fromHex("dd0820655cb2ffdb0da9e9310a67c9e5");
    auto perso   = tf::fromHex("f2e58fe60a3afc59dad37595415ffd318ccf69d67780f6fa0797dc9aa43e144c");
    auto reseed  = tf::fromHex("e0629b6d7975ddfa96a399648740e60f1f9557dc58b3d7415f9ba9d4dbb501f6");
    std::string expected =
        "f92d4cf99a535b20222a52a68db04c5af6f5ffc7b66a473a37a256bd8d298f9b"
        "4aa4af7e8d181e02367903f93bdb744c6c2f3f3472626b40ce9bd6a70e7b8f939"
        "92a16a76fab6b5f162568e08ee6c3e804aefd952ddd3acb791c50f2ad69e9a040"
        "28a06a9c01d3a62aca2aaf6efe69ed97a016213a2dd642b4886764072d9cbe";

    HmacDrbg drbg;
    drbg.instantiate(entropy.data(), entropy.size(),
                     nonce.data(),   nonce.size(),
                     perso.data(),   perso.size());
    drbg.reseed(reseed.data(), reseed.size(), nullptr, 0);

    std::vector<uint8_t> out(128);
    drbg.generate(out.data(), out.size());     // first batch — discarded
    drbg.generate(out.data(), out.size());     // second batch — compared
    CHECK_EQ(tf::toHex(out), expected);

    // Determinism: identical seeding -> identical stream.
    HmacDrbg a, b;
    a.instantiate(entropy.data(), entropy.size(), nonce.data(), nonce.size(), nullptr, 0);
    b.instantiate(entropy.data(), entropy.size(), nonce.data(), nonce.size(), nullptr, 0);
    std::vector<uint8_t> oa(64), ob(64);
    a.generate(oa.data(), oa.size());
    b.generate(ob.data(), ob.size());
    CHECK_EQ(tf::toHex(oa), tf::toHex(ob));

    // A different nonce must diverge.
    HmacDrbg c;
    auto nonce2 = tf::fromHex("dd0820655cb2ffdb0da9e9310a67c9e6");
    c.instantiate(entropy.data(), entropy.size(), nonce2.data(), nonce2.size(), nullptr, 0);
    std::vector<uint8_t> oc(64);
    c.generate(oc.data(), oc.size());
    CHECK(tf::toHex(oc) != tf::toHex(oa));

    return TF_REPORT();
}

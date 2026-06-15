// libFuzzer harness for the OAEP decode and PSS verify paths.
//
// Feeds arbitrary bytes as a ciphertext / signature against a fixed key to hunt
// for memory errors or undefined behaviour in the parsing and bignum code. All
// rejections are expected; the fuzzer is looking for crashes, not failures.
//
// Build (needs LLVM Clang with libFuzzer):
//   make fuzz && ./build/fuzz_oaep -runs=200000

#include "rsa.hpp"
#include "oaep.hpp"
#include "pss.hpp"

#include <cstdint>
#include <vector>

namespace {
struct Fixture {
    RSA::PublicKey  pub;
    RSA::PrivateKey priv;
    size_t k;
    Fixture() {
        while (!RSA::generateKeys(pub, priv, 1024)) {}
        k = pub.n->byteLength();
    }
};
Fixture& fixture() { static Fixture f; return f; }
} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    Fixture& f = fixture();

    // Normalise the input to a modulus-sized block so it reaches the OAEP decode.
    std::vector<uint8_t> block(data, data + size);
    block.resize(f.k);

    try { (void)oaep::decrypt(f.priv, block); }
    catch (const std::exception&) { /* expected for invalid padding */ }

    // Treat the same bytes as a signature over an arbitrary message.
    (void)pss::verify(f.pub, std::vector<uint8_t>(data, data + size), block);
    return 0;
}

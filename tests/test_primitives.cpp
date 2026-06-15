// Known-answer tests for the cryptographic primitives:
//   SHA-256        (FIPS 180-4 examples + NIST CAVS)
//   HMAC-SHA256    (RFC 4231)
//   BigInt <-> bytes round-trips (RFC 8017 I2OSP / OS2IP)

#include "test_framework.hpp"
#include "sha256.hpp"
#include "hmac_sha256.hpp"
#include "bigmath.hpp"

#include <string>
#include <vector>

static std::vector<uint8_t> bytes(const std::string& s) {
    return std::vector<uint8_t>(s.begin(), s.end());
}

static void test_sha256() {
    std::cout << "[sha256] FIPS 180-4 / NIST vectors\n";
    CHECK_EQ(Sha256::hexdigest(bytes("")),
             std::string("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
    CHECK_EQ(Sha256::hexdigest(bytes("abc")),
             std::string("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    CHECK_EQ(Sha256::hexdigest(bytes("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")),
             std::string("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"));

    // One million 'a' characters (classic NIST long-message vector), streamed.
    Sha256 h;
    std::vector<uint8_t> chunk(1000, 'a');
    for (int i = 0; i < 1000; ++i) h.update(chunk);
    CHECK_EQ(tf::toHex(h.final()),
             std::string("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"));
}

static void test_hmac() {
    std::cout << "[hmac]   RFC 4231 vectors\n";
    // Test Case 1
    {
        std::vector<uint8_t> key(20, 0x0b);
        auto m = HmacSha256::mac(key, bytes("Hi There"));
        CHECK_EQ(tf::toHex(m),
                 std::string("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"));
    }
    // Test Case 2 ("Jefe" / "what do ya want for nothing?")
    {
        auto m = HmacSha256::mac(bytes("Jefe"), bytes("what do ya want for nothing?"));
        CHECK_EQ(tf::toHex(m),
                 std::string("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"));
    }
    // Test Case 3 (key 0xaa*20, data 0xdd*50) — exercises block-sized processing
    {
        std::vector<uint8_t> key(20, 0xaa);
        std::vector<uint8_t> data(50, 0xdd);
        auto m = HmacSha256::mac(key, data);
        CHECK_EQ(tf::toHex(m),
                 std::string("773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"));
    }
    // Test Case 6 (key longer than block size -> hashed first)
    {
        std::vector<uint8_t> key(131, 0xaa);
        auto m = HmacSha256::mac(key, bytes("Test Using Larger Than Block-Size Key - Hash Key First"));
        CHECK_EQ(tf::toHex(m),
                 std::string("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"));
    }
}

static void test_bigint_bytes() {
    std::cout << "[bigint] I2OSP / OS2IP round-trips\n";
    // OS2IP of a known octet string.
    auto v = tf::fromHex("0102030405");
    BigInt n = BigInt::fromBytesBE(v);
    CHECK_EQ(n.toHex(), std::string("102030405"));

    // I2OSP back to a fixed width with zero left-padding.
    auto out = n.toBytesBE(8);
    CHECK_EQ(tf::toHex(out), std::string("0000000102030405"));

    // Round-trip a chunk of random bytes through OS2IP then I2OSP.
    std::vector<uint8_t> r = tf::fromHex("00ff00deadbeefcafe0011223344556677889900");
    BigInt m = BigInt::fromBytesBE(r);
    auto back = m.toBytesBE(r.size());
    CHECK_EQ(tf::toHex(back), tf::toHex(r));

    // toBytesBE must reject an integer that does not fit in the requested length.
    bool threw = false;
    try { (void)BigInt::fromU64(0x1234).toBytesBE(1); }
    catch (const std::overflow_error&) { threw = true; }
    CHECK(threw);
}

int main() {
    test_sha256();
    test_hmac();
    test_bigint_bytes();
    return TF_REPORT();
}

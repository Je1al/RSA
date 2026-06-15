// Cross-checks BigInt::modExp (Montgomery path) against reference values
// computed independently with Python's pow(base, exp, mod).

#include "test_framework.hpp"
#include "bigmath.hpp"

struct Vec { const char* base; const char* exp; const char* mod; const char* expect; };

int main() {
    std::cout << "[modexp] Montgomery modExp vs reference (Python pow)\n";

    const Vec vecs[] = {
        {"4", "d", "1f1", "1bd"},
        {"75bcd15", "3ade68b1", "3b9aca07", "26e4fd0e"},
        {"deadbeef", "cafebabe", "fffffffffffffffb", "c211cf6db9c8a57e"},
        {"1234567890abcdef1234567890abcdef",
         "fedcba9876543210fedcba9876543210",
         "c0ffee00000000000000000000000000000000000000000000000000000000fd",
         "a40b3ac72f62b90eac654190dc1522da67541706b2cffab059da90300a271c4a"},
    };

    for (const auto& v : vecs) {
        BigInt b(std::string(v.base));
        BigInt e(std::string(v.exp));
        BigInt m(std::string(v.mod));
        BigInt r = BigInt::modExp(b, e, m);
        CHECK_EQ(r.toHex(), std::string(v.expect));
    }

    // base > mod and base == 0 edge cases.
    CHECK_EQ(BigInt::modExp(BigInt(std::string("ffff")), BigInt::fromU64(2),
                            BigInt(std::string("101"))).toHex(),
             BigInt::modExp(BigInt(std::string("ffff")), BigInt::fromU64(2),
                            BigInt(std::string("101"))).toHex());
    CHECK_EQ(BigInt::modExp(BigInt::fromU64(0), BigInt::fromU64(5),
                            BigInt(std::string("101"))).toHex(), std::string("0"));

    return TF_REPORT();
}

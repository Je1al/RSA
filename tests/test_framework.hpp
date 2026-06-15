#ifndef RSA_TEST_FRAMEWORK_HPP
#define RSA_TEST_FRAMEWORK_HPP

// Minimal header-only test harness — no external dependencies.
//
//   int main() {
//       CHECK(x == y);
//       CHECK_EQ(actual, expected);
//       return TF_REPORT();
//   }

#include <cstdint>
#include <iostream>
#include <string>
#include <vector>
#include <array>

namespace tf {
inline int g_checks   = 0;
inline int g_failures = 0;

inline std::vector<uint8_t> fromHex(const std::string& hex) {
    std::vector<uint8_t> out;
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        out.push_back(static_cast<uint8_t>((nib(hex[i]) << 4) | nib(hex[i + 1])));
    }
    return out;
}

inline std::string toHex(const uint8_t* p, size_t n) {
    static const char* d = "0123456789abcdef";
    std::string s;
    s.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) { s += d[p[i] >> 4]; s += d[p[i] & 0xF]; }
    return s;
}
inline std::string toHex(const std::vector<uint8_t>& v) { return toHex(v.data(), v.size()); }
template <size_t N>
inline std::string toHex(const std::array<uint8_t, N>& v) { return toHex(v.data(), N); }
} // namespace tf

#define CHECK(cond)                                                            \
    do {                                                                       \
        ++tf::g_checks;                                                        \
        if (!(cond)) {                                                         \
            ++tf::g_failures;                                                  \
            std::cerr << "  FAIL " << __FILE__ << ":" << __LINE__              \
                      << "  " << #cond << "\n";                               \
        }                                                                      \
    } while (0)

#define CHECK_EQ(actual, expected)                                             \
    do {                                                                       \
        ++tf::g_checks;                                                        \
        auto _a = (actual);                                                    \
        auto _e = (expected);                                                  \
        if (!(_a == _e)) {                                                     \
            ++tf::g_failures;                                                  \
            std::cerr << "  FAIL " << __FILE__ << ":" << __LINE__              \
                      << "  " << #actual << " == " << #expected << "\n"        \
                      << "        actual:   " << _a << "\n"                    \
                      << "        expected: " << _e << "\n";                   \
        }                                                                      \
    } while (0)

#define TF_REPORT()                                                            \
    ((std::cout << (tf::g_failures == 0 ? "  PASS " : "  FAIL ")               \
                << (tf::g_checks - tf::g_failures) << "/" << tf::g_checks      \
                << " checks\n"),                                               \
     tf::g_failures == 0 ? 0 : 1)

#endif // RSA_TEST_FRAMEWORK_HPP

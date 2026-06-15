#include "rng.hpp"
#include "drbg.hpp"

#include <cstring>
#include <mutex>
#include <stdexcept>

#if defined(_WIN32)
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#  include <bcrypt.h>
#  pragma comment(lib, "bcrypt.lib")
#else
#  include <unistd.h>
#  include <sys/types.h>
#  if defined(__linux__) || defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__)
#    include <sys/random.h>
#  endif
#  include <cstdio>
#endif

namespace rng {

namespace {

#if !defined(_WIN32)
// Last-resort fallback when getentropy() is unavailable.
bool readDevUrandom(uint8_t* buf, size_t len) {
    FILE* f = std::fopen("/dev/urandom", "rb");
    if (!f) return false;
    size_t got = std::fread(buf, 1, len, f);
    std::fclose(f);
    return got == len;
}
#endif

} // namespace

void osEntropy(uint8_t* buf, size_t len) {
#if defined(_WIN32)
    if (BCryptGenRandom(nullptr, buf, static_cast<ULONG>(len),
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
        throw std::runtime_error("BCryptGenRandom failed");
    }
#else
    size_t off = 0;
    while (off < len) {
        size_t chunk = len - off;
        if (chunk > 256) chunk = 256;  // getentropy() caps at 256 bytes per call
        if (getentropy(buf + off, chunk) != 0) {
            if (!readDevUrandom(buf, len)) {
                throw std::runtime_error("OS entropy source unavailable");
            }
            return;
        }
        off += chunk;
    }
#endif
}

namespace {

// Process-global CSPRNG: an HMAC-DRBG seeded from OS entropy, guarded by a mutex.
class GlobalCsprng {
public:
    void fill(uint8_t* buf, size_t len) {
        std::lock_guard<std::mutex> lock(mtx_);
        ensureSeeded();
        if (!drbg_.generate(buf, len)) {
            reseed();
            drbg_.generate(buf, len);
        }
    }

private:
    void ensureSeeded() {
        if (drbg_.initialized()) return;
        uint8_t entropy[48];   // 384 bits — 256-bit security strength + margin
        uint8_t nonce[16];     // 128-bit nonce, per SP 800-90A
        osEntropy(entropy, sizeof(entropy));
        osEntropy(nonce, sizeof(nonce));
        static const char kPerso[] = "rsa-toolkit/hmac-drbg/v1";
        drbg_.instantiate(entropy, sizeof(entropy),
                          nonce, sizeof(nonce),
                          reinterpret_cast<const uint8_t*>(kPerso), sizeof(kPerso) - 1);
        std::memset(entropy, 0, sizeof(entropy));
        std::memset(nonce, 0, sizeof(nonce));
    }

    void reseed() {
        uint8_t entropy[48];
        osEntropy(entropy, sizeof(entropy));
        drbg_.reseed(entropy, sizeof(entropy), nullptr, 0);
        std::memset(entropy, 0, sizeof(entropy));
    }

    HmacDrbg   drbg_;
    std::mutex mtx_;
};

GlobalCsprng& global() {
    static GlobalCsprng instance;
    return instance;
}

} // namespace

void randomBytes(uint8_t* buf, size_t len) {
    global().fill(buf, len);
}

std::vector<uint8_t> randomBytes(size_t len) {
    std::vector<uint8_t> out(len);
    if (len) global().fill(out.data(), len);
    return out;
}

uint64_t randomBelow(uint64_t bound) {
    if (bound == 0) throw std::invalid_argument("randomBelow: bound must be > 0");
    if (bound == 1) return 0;

    // Rejection sampling to avoid modulo bias.
    const uint64_t limit = UINT64_MAX - (UINT64_MAX % bound);
    uint64_t r;
    do {
        uint8_t b[8];
        randomBytes(b, sizeof(b));
        r = 0;
        for (int i = 0; i < 8; ++i) r = (r << 8) | b[i];
    } while (r >= limit);
    return r % bound;
}

} // namespace rng

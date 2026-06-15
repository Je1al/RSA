#include "keyio.hpp"
#include "bigmath.hpp"
#include "bigmath_internal.hpp"

#include <stdexcept>
#include <memory>
#include <initializer_list>

namespace keyio {

namespace {

using Bytes = std::vector<uint8_t>;

// OID 1.2.840.113549.1.1.1 rsaEncryption, fully DER-encoded with the NULL
// parameters: SEQUENCE { OID, NULL }.
const Bytes RSA_ALG_ID = {
    0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
    0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
};

// ---- DER encoding ---------------------------------------------------------

void appendLen(Bytes& out, size_t len) {
    if (len < 0x80) {
        out.push_back(static_cast<uint8_t>(len));
        return;
    }
    Bytes tmp;
    while (len > 0) { tmp.push_back(static_cast<uint8_t>(len & 0xFF)); len >>= 8; }
    out.push_back(static_cast<uint8_t>(0x80 | tmp.size()));
    for (auto it = tmp.rbegin(); it != tmp.rend(); ++it) out.push_back(*it);
}

Bytes tlv(uint8_t tag, const Bytes& content) {
    Bytes out;
    out.push_back(tag);
    appendLen(out, content.size());
    out.insert(out.end(), content.begin(), content.end());
    return out;
}

// DER INTEGER from a non-negative BigInt (prepend 0x00 if the high bit is set).
Bytes encInteger(const BigInt& v) {
    Bytes mag = v.toBytesBE();
    if (mag.empty()) mag.push_back(0x00);
    if (mag[0] & 0x80) mag.insert(mag.begin(), 0x00);
    return tlv(0x02, mag);
}

Bytes concat(std::initializer_list<Bytes> parts) {
    Bytes out;
    for (const auto& p : parts) out.insert(out.end(), p.begin(), p.end());
    return out;
}

// ---- DER decoding ---------------------------------------------------------

struct Cursor {
    const uint8_t* p;
    size_t n;
    size_t pos = 0;

    uint8_t byte() {
        if (pos >= n) throw std::runtime_error("DER: unexpected end of input");
        return p[pos++];
    }

    size_t length() {
        uint8_t first = byte();
        if (first < 0x80) return first;
        size_t numBytes = first & 0x7F;
        if (numBytes == 0 || numBytes > sizeof(size_t)) {
            throw std::runtime_error("DER: bad length encoding");
        }
        size_t len = 0;
        for (size_t i = 0; i < numBytes; ++i) len = (len << 8) | byte();
        return len;
    }

    // Expect a tag; return a cursor over its content and advance past it.
    Cursor expect(uint8_t tag) {
        uint8_t t = byte();
        if (t != tag) throw std::runtime_error("DER: unexpected tag");
        size_t len = length();
        if (pos + len > n) throw std::runtime_error("DER: length exceeds input");
        Cursor inner{p + pos, len, 0};
        pos += len;
        return inner;
    }

    void skip(uint8_t tag) {
        byte() == tag ? void() : throw std::runtime_error("DER: unexpected tag");
        size_t len = length();
        pos += len;
    }

    BigInt integer() {
        uint8_t t = byte();
        if (t != 0x02) throw std::runtime_error("DER: expected INTEGER");
        size_t len = length();
        if (pos + len > n) throw std::runtime_error("DER: INTEGER overruns input");
        BigInt v = BigInt::fromBytesBE(p + pos, len);  // leading 0x00 sign byte ignored
        pos += len;
        return v;
    }
};

// ---- Base64 / PEM ---------------------------------------------------------

const char* B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string base64(const Bytes& in) {
    std::string out;
    size_t i = 0;
    while (i + 3 <= in.size()) {
        uint32_t n = (in[i] << 16) | (in[i + 1] << 8) | in[i + 2];
        out += B64[(n >> 18) & 63]; out += B64[(n >> 12) & 63];
        out += B64[(n >> 6) & 63];  out += B64[n & 63];
        i += 3;
    }
    if (in.size() - i == 1) {
        uint32_t n = in[i] << 16;
        out += B64[(n >> 18) & 63]; out += B64[(n >> 12) & 63];
        out += "==";
    } else if (in.size() - i == 2) {
        uint32_t n = (in[i] << 16) | (in[i + 1] << 8);
        out += B64[(n >> 18) & 63]; out += B64[(n >> 12) & 63];
        out += B64[(n >> 6) & 63];  out += '=';
    }
    return out;
}

int b64val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

Bytes base64decode(const std::string& in) {
    Bytes out;
    int buf = 0, bits = 0;
    for (char c : in) {
        if (c == '=') break;
        int v = b64val(c);
        if (v < 0) continue;  // skip whitespace / newlines
        buf = (buf << 6) | v;
        bits += 6;
        if (bits >= 8) { bits -= 8; out.push_back(static_cast<uint8_t>((buf >> bits) & 0xFF)); }
    }
    return out;
}

std::string pem(const std::string& label, const Bytes& der) {
    std::string b = base64(der);
    std::string out = "-----BEGIN " + label + "-----\n";
    for (size_t i = 0; i < b.size(); i += 64) out += b.substr(i, 64) + "\n";
    out += "-----END " + label + "-----\n";
    return out;
}

Bytes derFromPem(const std::string& s, const std::string& label) {
    std::string begin = "-----BEGIN " + label + "-----";
    std::string end   = "-----END " + label + "-----";
    size_t b = s.find(begin);
    size_t e = s.find(end);
    if (b == std::string::npos || e == std::string::npos || e < b) {
        throw std::runtime_error("PEM: missing " + label + " block");
    }
    return base64decode(s.substr(b + begin.size(), e - b - begin.size()));
}

std::shared_ptr<BigInt> shared(const BigInt& v) { return std::make_shared<BigInt>(v); }

} // namespace

// ---- public API -----------------------------------------------------------

std::string toPublicPem(const RSA::PublicKey& pub) {
    // RSAPublicKey ::= SEQUENCE { n INTEGER, e INTEGER }
    Bytes rsaPub = tlv(0x30, concat({ encInteger(*pub.n), encInteger(*pub.e) }));
    // BIT STRING wraps the RSAPublicKey (0 unused bits).
    Bytes bitStr = rsaPub; bitStr.insert(bitStr.begin(), 0x00);
    Bytes spki = tlv(0x30, concat({ RSA_ALG_ID, tlv(0x03, bitStr) }));
    return pem("PUBLIC KEY", spki);
}

std::string toPrivatePem(const RSA::PrivateKey& priv) {
    // RSAPrivateKey ::= SEQUENCE { version, n, e, d, p, q, dp, dq, qinv }
    Bytes rsaPriv = tlv(0x30, concat({
        encInteger(BigInt::fromU64(0)),
        encInteger(*priv.n), encInteger(*priv.e), encInteger(*priv.d),
        encInteger(*priv.p), encInteger(*priv.q),
        encInteger(*priv.dp), encInteger(*priv.dq), encInteger(*priv.qinv),
    }));
    // PKCS#8 PrivateKeyInfo ::= SEQUENCE { version, algId, OCTET STRING(RSAPrivateKey) }
    Bytes pkcs8 = tlv(0x30, concat({
        encInteger(BigInt::fromU64(0)),
        RSA_ALG_ID,
        tlv(0x04, rsaPriv),
    }));
    return pem("PRIVATE KEY", pkcs8);
}

RSA::PublicKey publicFromPem(const std::string& pemStr) {
    Bytes der = derFromPem(pemStr, "PUBLIC KEY");
    Cursor top{der.data(), der.size()};
    Cursor spki = top.expect(0x30);
    spki.skip(0x30);                      // AlgorithmIdentifier
    Cursor bitStr = spki.expect(0x03);
    bitStr.byte();                        // leading "unused bits" octet (0)
    Cursor rsaPub{bitStr.p + bitStr.pos, bitStr.n - bitStr.pos};
    Cursor seq = rsaPub.expect(0x30);

    RSA::PublicKey pub;
    pub.n = shared(seq.integer());
    pub.e = shared(seq.integer());
    pub.bitlen = pub.n->bitLength();
    return pub;
}

RSA::PrivateKey privateFromPem(const std::string& pemStr) {
    Bytes der = derFromPem(pemStr, "PRIVATE KEY");
    Cursor top{der.data(), der.size()};
    Cursor pkcs8 = top.expect(0x30);
    pkcs8.skip(0x02);                     // version
    pkcs8.skip(0x30);                     // AlgorithmIdentifier
    Cursor oct = pkcs8.expect(0x04);
    Cursor seq = oct.expect(0x30);        // RSAPrivateKey

    seq.skip(0x02);                       // version
    RSA::PrivateKey priv;
    priv.n    = shared(seq.integer());
    priv.e    = shared(seq.integer());
    priv.d    = shared(seq.integer());
    priv.p    = shared(seq.integer());
    priv.q    = shared(seq.integer());
    priv.dp   = shared(seq.integer());
    priv.dq   = shared(seq.integer());
    priv.qinv = shared(seq.integer());
    priv.bitlen = priv.n->bitLength();
    return priv;
}

} // namespace keyio

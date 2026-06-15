// Attack: Wiener's continued-fraction attack on a small private exponent.
//
// If d < (1/3) * n^(1/4), then k/d is one of the convergents of the continued
// fraction expansion of e/n (because e*d = 1 + k*phi means e/n is very close to
// k/d). For each convergent (k, d) we test a candidate phi = (e*d - 1)/k and
// check whether x^2 - (n - phi + 1)x + n has integer roots; if so we have
// factored n and recovered the private exponent.
//
// Defence: a full-size private exponent. With e = 65537 the matching d is about
// as large as n, so it can never appear as a low-order convergent.

#include "lab.hpp"

using namespace lab;

// Runs Wiener's attack on (e, n). Returns true and sets dOut if it recovers d.
static bool wiener(const BigInt& e, const BigInt& n, BigInt& dOut, int& convergents) {
    BigInt a = e, b = n;
    BigInt hPrev2 = u(0), hPrev1 = u(1);   // numerator   (the multiplier k)
    BigInt kPrev2 = u(1), kPrev1 = u(0);   // denominator (the private exponent d)
    convergents = 0;

    while (!isZero(b)) {
        BigInt rem;
        BigInt qq = BigInt::divmod(a, b, &rem);
        BigInt h = add(mul(qq, hPrev1), hPrev2);   // candidate k
        BigInt k = add(mul(qq, kPrev1), kPrev2);   // candidate d
        ++convergents;

        if (!isZero(h)) {
            BigInt num = sub(mul(e, k), u(1));      // e*d - 1
            BigInt rem2;
            BigInt phi = BigInt::divmod(num, h, &rem2);
            if (isZero(rem2) && n.cmp(phi) > 0) {
                BigInt s = add(sub(n, phi), u(1));  // s = p + q = n - phi + 1
                BigInt s2 = mul(s, s), n4 = mul(n, u(4));
                if (s2.cmp(n4) >= 0) {
                    BigInt disc = sub(s2, n4), root;
                    if (isPerfectSquare(disc, root)) {
                        dOut = k;
                        return true;
                    }
                }
            }
        }

        a = b; b = rem;
        hPrev2 = hPrev1; hPrev1 = h;
        kPrev2 = kPrev1; kPrev1 = k;
    }
    return false;
}

int main() {
    std::cout << "Wiener's attack: small private exponent\n";

    // ---- build a vulnerable key with a deliberately tiny d -----------------
    BigInt p, q, n, phi;
    makePrimes(512, p, q, n, phi);                 // n ~ 1024 bits

    BigInt d;
    do {
        d = exported_generate_random_bigint(200);  // d ~ 2^200  <<  n^(1/4)/3 ~ 2^254
        if (exported_is_even(d)) d = add(d, u(1));
    } while (!eq(exported_gcd_euclidean(d, phi), u(1)));
    BigInt e = modInverse(d, phi);                 // large public exponent

    rule("Vulnerable key (d ~ 200 bits)");
    std::cout << "n = " << n.bitLength() << " bits, e = " << e.bitLength()
              << " bits, d = " << d.bitLength() << " bits\n";

    BigInt recovered;
    int conv = 0;
    bool ok = wiener(e, n, recovered, conv);
    std::cout << "Wiener recovered d after scanning " << conv << " convergents: "
              << (ok && eq(recovered, d) ? "SUCCESS -- private key broken" : "failed") << "\n";

    // ---- the library's default key resists the attack ----------------------
    rule("Defence: full-size d (e = 65537)");
    RSA::PublicKey pub;
    RSA::PrivateKey priv;
    while (!RSA::generateKeys(pub, priv, 1024)) {}
    BigInt d2, recovered2;
    int conv2 = 0;
    bool ok2 = wiener(*pub.e, *pub.n, recovered2, conv2);
    std::cout << "d size for e=65537: " << priv.d->bitLength() << " bits\n";
    std::cout << "Wiener on the secure key: "
              << (ok2 ? "recovered (!)" : "FAILED -- d too large to be a convergent") << "\n";

    return 0;
}

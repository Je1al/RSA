# RSA Attack Lab

Five self-contained programs that **break deliberately weak RSA keys**, then show
how this toolkit's defaults prevent each attack. They turn the cryptography from
"it encrypts" into "here is exactly *why* the modern parameters and padding
schemes are mandatory" — the reasoning a security engineer is expected to have.

Build and run them all:

```bash
make attacks
for a in build/attacks/*; do echo "### $a"; "$a"; echo; done
```

Each program ends with a **Defence** section that runs the same attack against a
properly generated key (random independent primes, `e = 65537`, OAEP/PSS) and
shows it failing.

| Attack | Weakness exploited | Defence in this toolkit |
|--------|--------------------|--------------------------|
| Textbook malleability | No padding (raw `m^e mod n`) | RSAES-OAEP (randomised, integrity-checked) |
| Håstad broadcast | Low exponent `e=3` + no padding | OAEP randomises each ciphertext; `e=65537` |
| Common modulus | Shared `n` across users | Independent modulus per key |
| Wiener | Small private exponent `d` | Full-size `d` (`e=65537`) |
| Fermat factorization | Primes too close | Independent random primes |

---

## 1. Textbook RSA malleability & determinism — `textbook_malleability`

**Theory.** Raw RSA is a deterministic, multiplicatively homomorphic permutation:
`E(m1)·E(m2) = (m1·m2)^e = E(m1·m2) (mod n)`. So (a) equal plaintexts give equal
ciphertexts, leaking message equality, and (b) an attacker who only has
`C = E(m)` can forge `C·s^e = E(m·s)` for any chosen `s` without the private key.

**Result.** `E(m)` twice yields identical ciphertext; the forged `C·2^e` decrypts
to `2·m mod n`.

**Defence.** RSAES-OAEP randomises every encryption (ciphertexts differ) and the
padding check rejects the mauled ciphertext — IND-CCA2 security.

## 2. Håstad broadcast attack — `hastad_broadcast`

**Theory.** The same message is sent to three recipients with `e = 3` and moduli
`n1, n2, n3`. Each `c_i = m^3 mod n_i`, and since `m < n_i`, `m^3 < n1·n2·n3`. CRT
recombination yields `m^3` over the integers, so an integer cube root returns `m`.

**Result.** The CRT product is a perfect cube and the plaintext is recovered with
no private key.

**Defence.** OAEP pads `m` with fresh randomness per recipient, so the three
encrypted integers differ and no common cube root exists; the attack reports
"not a perfect cube". `e = 65537` defeats small-broadcast variants outright.

## 3. Common-modulus attack — `common_modulus`

**Theory.** Two users share `n` with coprime exponents `e1, e2`. From
`a·e1 + b·e2 = 1` (extended Euclid) and the two ciphertexts of the same message,
`c1^a · c2^b = m^(a·e1+b·e2) = m (mod n)`. The implementation uses
`a = e1^{-1} mod e2` and a modular inverse of `c2` for the negative coefficient.

**Result.** The message is recovered from `(c1, c2, e1, e2, n)` alone.

**Defence.** Never share a modulus. Each key gets its own `n`, so two ciphertexts
carry no exploitable algebraic relation.

## 4. Wiener's attack — `wiener`

**Theory.** When `d < (1/3)·n^{1/4}`, the fraction `k/d` (from `e·d = 1 + k·phi`)
is a convergent of the continued fraction of `e/n`. For each convergent we test
`phi = (e·d − 1)/k` and check whether `x² − (n − phi + 1)x + n` has integer roots;
if so, `n` is factored and `d` recovered.

**Result.** A key with a ~200-bit `d` (where `n` is 1024-bit) is broken after
scanning ~100 convergents.

**Defence.** With `e = 65537` the matching `d` is essentially full-size (~1024
bits) and never appears as a low-order convergent — the attack fails.

## 5. Fermat factorization — `fermat_factorization`

**Theory.** If `p, q` are close, `n = a² − b²` with `a ≈ sqrt(n)` and small `b`.
Starting at `a = ceil(sqrt(n))` and incrementing, `a² − n` becomes a perfect
square `b²` within a few steps, giving `p = a − b`, `q = a + b`.

**Result.** A modulus whose `q` is the next prime after `p` is factored in ~0
iterations.

**Defence.** Independently generated `k`-bit primes differ by ~`2^{k-1}` on
average, so Fermat would require ~`2^{k-2}` iterations — infeasible.

---

### References

- D. Boneh, *Twenty Years of Attacks on the RSA Cryptosystem*, Notices of the AMS, 1999.
- M. Wiener, *Cryptanalysis of Short RSA Secret Exponents*, IEEE TIT, 1990.
- J. Håstad, *Solving Simultaneous Modular Equations of Low Degree*, SIAM J. Comput., 1988.
- RFC 8017, *PKCS #1: RSA Cryptography Specifications Version 2.2*.

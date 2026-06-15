# Security notes

This document states the threat model, the design choices behind the
randomness and padding, and — importantly — the limits of what this code
guarantees. Honesty about the boundary is itself part of the security posture.

## Status

Educational / portfolio code. It is correct against the cited standards and
their test vectors, but it has **not** undergone independent audit or
side-channel evaluation. Use a vetted library (OpenSSL, BoringSSL, libsodium)
in production.

## Threat model

In scope — attacks this project defends against and demonstrates:

- **Predictable key material.** Keys are generated from an SP 800-90A HMAC-DRBG
  seeded by the OS CSPRNG, not from `std::mt19937`/`std::random_device`.
- **Chosen-ciphertext / malleability.** RSAES-OAEP provides IND-CCA2 security;
  the decoder reports a single uniform error to resist Manger's attack.
- **Existential forgery.** RSASSA-PSS replaces deterministic textbook signatures.
- **Algebraic key/parameter attacks.** Demonstrated and defended in
  [ATTACKS.md](ATTACKS.md): Håstad broadcast, common modulus, Wiener, Fermat.
- **Coarse timing on the secret exponent.** CRT decryption uses base blinding so
  the modular exponentiation operates on a value the attacker cannot control.

Out of scope:

- **Full constant-time / microarchitectural resistance** (cache, branch, power,
  EM). See below.
- **Fault-injection** beyond what blinding incidentally helps with.
- **Memory zeroization** of all secret intermediates.

## Randomness design

```
OS CSPRNG (getentropy / getrandom / BCryptGenRandom)
        │  48 bytes entropy + 16 bytes nonce + personalization
        ▼
HMAC_DRBG (SHA-256, SP 800-90A)  ──►  key generation, OAEP seeds, PSS salts, blinding
        │  automatic reseed from fresh OS entropy at the SP 800-90A interval
```

The DRBG is the deterministic core (verified against the NIST CAVP HMAC_DRBG
vector in `tests/test_drbg.cpp`); the process-global wrapper in `rng.cpp` adds
OS seeding, thread-safety (mutex), and reseeding. Splitting it this way keeps the
algorithm itself testable while the live generator stays non-deterministic.

## Constant-time considerations

The **padding decisions** that historically leak — the OAEP decode result and
the PSS comparison — are written to avoid branching on which check failed
(uniform error, full-length compare).

The underlying **bignum arithmetic is *not* constant-time.** Montgomery
multiplication, the square-and-multiply exponent loop, and comparisons branch and
allocate based on operand values. A determined local attacker with precise timing
or microarchitectural side channels could extract key bits. Base blinding raises
the bar for remote timing attacks but does not make the code constant-time. A
production hardening pass would need fixed-width limbs, branch-free conditional
selects, and a constant-time exponentiation ladder.

## Reporting

This is a personal learning project; open a GitHub issue for anything you find.

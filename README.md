# RSA Toolkit — applied cryptography & attack lab in C++

[![CI](https://github.com/Je1al/RSA/actions/workflows/ci.yml/badge.svg)](https://github.com/Je1al/RSA/actions/workflows/ci.yml)
![C++17](https://img.shields.io/badge/C%2B%2B-17-blue)
![License: MIT](https://img.shields.io/badge/License-MIT-green)
![Dependencies](https://img.shields.io/badge/dependencies-none-success)

A from-scratch RSA implementation in **C++17 with zero external crypto
libraries** — every primitive, from the bignum arithmetic to SHA-256, the
CSPRNG, and the PKCS#1 v2.2 padding schemes, is built and validated here.

It is two things at once:

1. A **standards-compliant RSA library** — RSAES-OAEP encryption and RSASSA-PSS
   signatures over a NIST-validated HMAC-DRBG, hardened against timing attacks.
2. An **offensive attack lab** — five programs that break deliberately weak keys
   (Håstad, Wiener, common-modulus, Fermat, textbook malleability) and then show
   the library's defaults defeating each attack.

> Educational/portfolio project. It demonstrates *how RSA works and how it
> breaks*; for production use a vetted library (OpenSSL, libsodium, BoringSSL).

---

## Why this project

Implementing a cipher is one thing; understanding its failure modes is what
security work is actually about. This repo pairs a correct, modern RSA stack
with concrete demonstrations of the classic attacks — and proves, in runnable
code, that the standard defences stop them.

### Security hardening — before → after

The starting point was a typical "textbook" RSA implementation. The table shows
what was wrong and what this project changed.

| Area | Before | After |
|------|--------|-------|
| Randomness | `std::mt19937` (Mersenne Twister) seeds keys — fully predictable | OS entropy → **HMAC-DRBG (NIST SP 800-90A)**, validated against NIST CAVP vectors |
| Encryption | Raw `m^e mod n` — deterministic & malleable | **RSAES-OAEP** (RFC 8017), randomised, IND-CCA2, Manger-resistant decode |
| Signatures | none | **RSASSA-PSS** (RFC 8017), randomised salt |
| Decryption | `c^d mod n`, CRT params computed but unused, no blinding | **CRT (Garner)** + **base blinding** (timing/fault-attack mitigation) |
| Primality | Miller–Rabin squaring loop count was wrong (`count_bits(d)`) | Correct `s−1` loop, **FIPS 186-5** round counts, fast trial-division sieve |
| Key size | modulus came out 1 bit long | top-two-bits primes → modulus has the **exact** requested length |
| Performance | 512-bit keygen unusable (killed at 60 s) | Montgomery `modExp` + `R²` + fast small-mod: **2048-bit keygen ≈ 0.5 s** |

---

## Features

- **BigInt**: arbitrary-precision integers with Montgomery modular exponentiation.
- **SHA-256** (FIPS 180-4) and **HMAC-SHA256** (RFC 2104) from scratch.
- **HMAC-DRBG** (NIST SP 800-90A) seeded from the OS CSPRNG
  (`getentropy`/`getrandom`/`BCryptGenRandom`).
- **RSA**: key generation, raw primitive, CRT decryption with base blinding.
- **RSAES-OAEP** and **RSASSA-PSS** (PKCS#1 v2.2) with SHA-256 / MGF1.
- **DER/PEM** key serialization (SPKI public, PKCS#8 private) that
  **interoperates with OpenSSL** — keys, OAEP, and PSS validated both directions.
- **Attack lab**: five runnable exploits with built-in defence demonstrations.
- **Tests**: known-answer tests against FIPS / RFC / NIST CAVP vectors; clean
  under AddressSanitizer + UndefinedBehaviorSanitizer.
- **CI**: build matrix (Linux/macOS × GCC/Clang), tests, sanitizers, fuzzing.

## Build & run

No dependencies beyond a C++17 compiler. Either build system works:

```bash
make              # build the CLI            -> build/rsa-cli
make test         # build & run all KAT/unit tests
make attacks      # build the attack demos   -> build/attacks/*
make asan         # run the tests under ASan + UBSan
make interop      # cross-check against OpenSSL (keys, OAEP, PSS)

# or with CMake
cmake -B build && cmake --build build && ctest --test-dir build
```

Try the secure pipeline end-to-end:

```bash
$ ./build/rsa-cli demo
Generating a 2048-bit key with the SP 800-90A CSPRNG...
  n = 2048 bits, e = 10001  (520 ms)
OAEP encryption ... round-trip: OK
PSS signature   ... verify: VALID   tampered: INVALID (rejected)
```

Run an attack:

```bash
$ ./build/attacks/wiener
Wiener recovered d after scanning 116 convergents: SUCCESS -- private key broken
Defence: full-size d (e=65537) ... FAILED -- d too large to be a convergent
```

## Library usage

```cpp
#include "rsa.hpp"
#include "oaep.hpp"
#include "pss.hpp"

RSA::PublicKey pub; RSA::PrivateKey priv;
RSA::generateKeys(pub, priv, 2048);                 // CSPRNG-backed

auto ct  = oaep::encrypt(pub, message);             // RSAES-OAEP
auto pt  = oaep::decrypt(priv, ct);                 // throws on bad padding

auto sig = pss::sign(priv, document);               // RSASSA-PSS
bool ok  = pss::verify(pub, document, sig);
```

## OpenSSL interoperability

`make interop` round-trips keys and messages through OpenSSL in both directions
and fails on any mismatch:

- our SPKI/PKCS#8 PEM keys parse under `openssl pkey`;
- our PSS signature verifies under `openssl dgst`, and an OpenSSL PSS signature
  verifies under ours;
- our OAEP ciphertext decrypts under `openssl pkeyutl`, and an OpenSSL OAEP
  ciphertext decrypts under ours.

## Performance

Apple M-class, `-O2`, from-scratch arithmetic:

| Key size | Key generation | OAEP encrypt | CRT+blinded decrypt |
|----------|----------------|--------------|----------------------|
| 1024-bit | ~0.17 s        | < 1 ms       | ~65 ms               |
| 2048-bit | ~0.53 s        | < 1 ms       | ~0.42 s              |
| 3072-bit | ~2.2 s         | ~2 ms        | ~1.3 s               |

## Layout

```
include/      public headers
src/          core library (bigint, rng, sha256, hmac, drbg, mgf1, oaep, pss, rsa, keyio)
src/app/      interactive console application
apps/cli.cpp  entry point (interactive + demo / genpem / sign / verify / oaep subcommands)
tests/        known-answer & round-trip tests
attacks/      offensive demonstrations (see docs/ATTACKS.md)
fuzz/         libFuzzer harness
scripts/      interop_openssl.sh — OpenSSL cross-validation
docs/         SECURITY.md, DESIGN.md, ATTACKS.md
```

## Documentation

- [docs/ATTACKS.md](docs/ATTACKS.md) — the attack lab: theory, reproduction, defence.
- [docs/SECURITY.md](docs/SECURITY.md) — threat model, RNG design, constant-time notes.
- [docs/DESIGN.md](docs/DESIGN.md) — architecture and module map.

## Standards & references

- RFC 8017 — PKCS #1 v2.2 (RSAES-OAEP, RSASSA-PSS, MGF1, I2OSP/OS2IP)
- NIST SP 800-90A Rev.1 — HMAC_DRBG
- FIPS 180-4 — SHA-256 · FIPS 186-5 — Miller–Rabin iteration counts
- D. Boneh, *Twenty Years of Attacks on the RSA Cryptosystem* (1999)

## License

MIT — see [LICENSE](LICENSE).

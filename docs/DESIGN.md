# Design & architecture

The toolkit is layered so that each module depends only on the ones beneath it.
Nothing depends on a third-party crypto library.

```
                 ┌─────────────────────────────────────────────┐
   schemes       │  oaep (RSAES-OAEP)     pss (RSASSA-PSS)       │
                 └───────────────┬─────────────────┬────────────┘
                                 │  mgf1           │
                 ┌───────────────┴─────────────────┴────────────┐
   RSA core      │  rsa  (keygen, raw primitive, CRT+blinding)   │
                 │  prime_generator (Miller–Rabin, sieve)        │
                 └───────────────┬─────────────────┬────────────┘
                                 │                 │
        ┌────────────────────────┴───┐   ┌─────────┴─────────────┐
   prim │  rng (CSPRNG)              │   │  bigmath (BigInt,      │
        │   └─ drbg (HMAC_DRBG)      │   │   Montgomery)          │
        │       └─ hmac_sha256       │   └────────────────────────┘
        │           └─ sha256        │
        └────────────────────────────┘
```

## Modules

| File | Responsibility |
|------|----------------|
| `bigmath.{hpp,cpp}` | `BigInt` arbitrary-precision integers; `MontgomeryCtx` modular exponentiation; I2OSP/OS2IP byte conversions |
| `sha256.{hpp,cpp}` | SHA-256 (FIPS 180-4), streaming + one-shot |
| `hmac_sha256.{hpp,cpp}` | HMAC-SHA256 (RFC 2104) |
| `drbg.{hpp,cpp}` | HMAC_DRBG (SP 800-90A) — deterministic, KAT-testable |
| `rng.{hpp,cpp}` | OS entropy + process-global DRBG, thread-safe |
| `prime_generator.{hpp,cpp}` | random prime generation, Miller–Rabin, small-prime sieve |
| `rsa.{hpp,cpp}` | key generation, RSAEP/RSADP, CRT decryption + blinding |
| `mgf1.{hpp,cpp}` | MGF1 mask generation (SHA-256) |
| `oaep.{hpp,cpp}` | RSAES-OAEP encrypt / decrypt |
| `pss.{hpp,cpp}` | RSASSA-PSS sign / verify |

## Key data structures

- `RSA::PublicKey` — `{ n, e }`.
- `RSA::PrivateKey` — `{ n, d, p, q, dp, dq, qinv, e }`. The CRT parameters
  `dp = d mod (p-1)`, `dq = d mod (q-1)`, `qinv = q^{-1} mod p` drive Garner's
  recombination; `e` is kept in memory so decryption can apply base blinding.

## Performance-critical decisions

- **`BigInt::modExp` dispatches to Montgomery** for odd moduli (all RSA moduli
  and primes), avoiding the schoolbook-division reduction. `R² mod N` is
  precomputed by modular doubling so `toMont` is a Montgomery multiply, not a
  division.
- **Trial division uses a fast `O(words)` `mod_small`** rather than the general
  shift-and-subtract `modNaive`, which is what makes prime generation tractable.

## Notes on the BigInt internals

`BigInt` keeps its limbs private and the implementation reaches them through a
layout-compatible `BigIntAccess` view inside `bigmath.cpp`. This is a deliberate
encapsulation boundary inherited from the original code; the new modules only use
the public `BigInt` API plus the `exported_*` helpers declared in
`bigmath_internal.hpp`.

## Build

`Makefile` (zero-dependency) and `CMakeLists.txt` produce the same targets:
the `rsacore` library, the `rsa-cli` executable, one test binary per
`tests/*.cpp`, and one binary per `attacks/*.cpp`. See the project README for
commands.

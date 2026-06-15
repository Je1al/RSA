#!/usr/bin/env bash
#
# Cross-validates this toolkit against OpenSSL (or LibreSSL) in both directions:
# key serialization, RSAES-OAEP, and RSASSA-PSS. Any mismatch fails the script.
#
# Usage: scripts/interop_openssl.sh [path-to-rsa-cli]
set -euo pipefail

CLI="${1:-build/rsa-cli}"
[ -x "$CLI" ] || { echo "rsa-cli not found at $CLI (run 'make' first)"; exit 1; }

D="$(mktemp -d)"
trap 'rm -rf "$D"' EXIT
echo "BMW secure-boot interop payload $(date +%s)" > "$D/msg.txt"

pass() { printf '  [ok] %s\n' "$1"; }

echo "OpenSSL interop ($(openssl version))"

# 1. Generate a key with this toolkit and write PEMs.
"$CLI" genpem "$D/pub.pem" "$D/priv.pem"
pass "generated SPKI public + PKCS#8 private key"

# 2-3. OpenSSL must be able to parse both of our PEM files.
openssl pkey -pubin -in "$D/pub.pem" -noout
pass "OpenSSL parsed our public key (SubjectPublicKeyInfo)"
openssl pkey -in "$D/priv.pem" -noout
pass "OpenSSL parsed our private key (PKCS#8)"

# 4. Our PSS signature must verify under OpenSSL.
"$CLI" pss-sign "$D/priv.pem" "$D/msg.txt" "$D/our.sig"
openssl dgst -sha256 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32 \
    -verify "$D/pub.pem" -signature "$D/our.sig" "$D/msg.txt" >/dev/null
pass "OpenSSL verified our RSASSA-PSS signature"

# 5. An OpenSSL PSS signature must verify under our code.
openssl dgst -sha256 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32 \
    -sign "$D/priv.pem" -out "$D/ossl.sig" "$D/msg.txt"
[ "$("$CLI" pss-verify "$D/pub.pem" "$D/msg.txt" "$D/ossl.sig")" = "VALID" ]
pass "we verified OpenSSL's RSASSA-PSS signature"

# 6. OpenSSL OAEP ciphertext must decrypt under our code.
openssl pkeyutl -encrypt -pubin -inkey "$D/pub.pem" \
    -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 \
    -in "$D/msg.txt" -out "$D/ossl.enc"
"$CLI" oaep-decrypt "$D/priv.pem" "$D/ossl.enc" "$D/dec1.txt"
cmp -s "$D/msg.txt" "$D/dec1.txt"
pass "we decrypted OpenSSL's RSAES-OAEP ciphertext"

# 7. Our OAEP ciphertext must decrypt under OpenSSL.
"$CLI" oaep-encrypt "$D/pub.pem" "$D/msg.txt" "$D/our.enc"
openssl pkeyutl -decrypt -inkey "$D/priv.pem" \
    -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 \
    -in "$D/our.enc" -out "$D/dec2.txt"
cmp -s "$D/msg.txt" "$D/dec2.txt"
pass "OpenSSL decrypted our RSAES-OAEP ciphertext"

echo "All OpenSSL interop checks passed."

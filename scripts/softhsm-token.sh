#!/bin/bash
#
# Build a throwaway SoftHSM token with one RSA key and a self-signed
# certificate, for the agent's tests.
#
# SoftHSM is a real PKCS #11 module: same C_Login, same C_Sign, same attribute
# rules as the card. That makes it the difference between an agent that is
# tested and one that is only tested when someone plugs a token in — and it is
# what lets CI run this at all.
#
# Everything lands under $1 (default: a temp dir). Nothing touches the user's
# own SoftHSM configuration, which is why SOFTHSM2_CONF is written here rather
# than assumed.
set -euo pipefail

ROOT="${1:-$(mktemp -d)}"
PIN="${SOFTHSM_PIN:-123456}"
SO_PIN="${SOFTHSM_SO_PIN:-654321}"
LABEL="SignBridge Test Token"

MODULE="$(brew --prefix softhsm 2>/dev/null)/lib/softhsm/libsofthsm2.so"
[ -f "$MODULE" ] || { echo "SoftHSM not found — brew install softhsm" >&2; exit 1; }

mkdir -p "$ROOT/tokens"
cat > "$ROOT/softhsm2.conf" <<CONF
directories.tokendir = $ROOT/tokens
objectstore.backend = file
log.level = ERROR
CONF
export SOFTHSM2_CONF="$ROOT/softhsm2.conf"

softhsm2-util --init-token --free --label "$LABEL" --pin "$PIN" --so-pin "$SO_PIN" >/dev/null

# The key is generated ON the token, so the private key never exists as a file
# — the same shape as the card, where it never exists anywhere else at all.
pkcs11-tool --module "$MODULE" --login --pin "$PIN" \
    --keypairgen --key-type rsa:2048 --id 01 --label "signing-key" >/dev/null

# A self-signed certificate over that key, written back onto the token.
# OpenSSL drives the key through the module rather than holding it, which is
# the only way to sign a certificate with a key it cannot read.
OPENSSL="$(brew --prefix openssl@3 2>/dev/null)/bin/openssl"
[ -x "$OPENSSL" ] || OPENSSL=openssl
PKCS11_MODULE_PATH="$MODULE" "$OPENSSL" req -new -x509 -days 3650 \
    -engine pkcs11 -keyform engine -key "pkcs11:token=$LABEL;id=%01;type=private;pin-value=$PIN" \
    -subj "/CN=SignBridge Test Signer/O=Test/C=CZ" \
    -out "$ROOT/cert.pem" 2>/dev/null || {
    # No pkcs11 engine (OpenSSL 3 dropped engines in favour of providers, and
    # the provider is a separate install). Fall back to a certificate made from
    # the token's own public key, signed by a throwaway key held here: the
    # tests care that a certificate with the token key's SPKI is on the token,
    # not who vouched for it.
    pkcs11-tool --module "$MODULE" --login --pin "$PIN" --id 01 \
        --read-object --type pubkey --output-file "$ROOT/pub.der" >/dev/null
    "$OPENSSL" rsa -pubin -inform DER -in "$ROOT/pub.der" -out "$ROOT/pub.pem" >/dev/null 2>&1
    "$OPENSSL" req -new -x509 -days 3650 -newkey rsa:2048 -nodes \
        -keyout "$ROOT/ca.key" -out "$ROOT/ca.pem" -subj "/CN=SignBridge Test CA" >/dev/null 2>&1
    "$OPENSSL" x509 -req -force_pubkey "$ROOT/pub.pem" -days 3650 \
        -in <("$OPENSSL" req -new -key "$ROOT/ca.key" -subj "/CN=SignBridge Test Signer/O=Test/C=CZ") \
        -CA "$ROOT/ca.pem" -CAkey "$ROOT/ca.key" -set_serial 1 \
        -out "$ROOT/cert.pem" >/dev/null 2>&1
}

"$OPENSSL" x509 -in "$ROOT/cert.pem" -outform DER -out "$ROOT/cert.der"
pkcs11-tool --module "$MODULE" --login --pin "$PIN" --id 01 --label "signing-key" \
    --write-object "$ROOT/cert.der" --type cert >/dev/null

echo "SOFTHSM2_CONF=$ROOT/softhsm2.conf"
echo "SIGNBRIDGE_TEST_MODULE=$MODULE"
echo "SIGNBRIDGE_TEST_PIN=$PIN"

#!/bin/bash
#
# Build SignBridge.app: a universal binary in a bundle, signed with a
# Developer ID and hardened, ready to be notarized.
#
#   packaging/build-app.sh <version> [outdir]
#
# Signing is skipped when SIGN_IDENTITY is unset, which is what a local build
# does — the result runs on the machine that built it and nowhere else. A
# RELEASE must be signed: see .github/workflows/release.yml, which sets it.
set -euo pipefail

VERSION="${1:?usage: build-app.sh <version> [outdir]}"
OUT="${2:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/build}"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP="$OUT/SignBridge.app"

say() { echo "signbridge  $*"; }

rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"

# Universal, because a Developer ID release is downloaded by machines we do not
# know. An arm64-only build fails on an Intel Mac with a message about the
# application not being supported, which reads like a broken download.
say "building universal (arm64 + x86_64)…"
(cd "$REPO/agent" && swift build -c release --arch arm64 --arch x86_64 --product signbridge-host)
BIN="$REPO/agent/.build/apple/Products/Release/signbridge-host"
[ -f "$BIN" ] || { echo "signbridge  ERROR  no binary at $BIN" >&2; exit 1; }
cp "$BIN" "$APP/Contents/MacOS/signbridge-host"
# Cleared at the source: a quarantine flag or a stray Finder info attribute from
# the toolchain survives into the pkg payload and fails notarization. (macOS
# re-stamps com.apple.provenance immediately and that one is fine — see
# build-pkg.sh.)
xattr -cr "$APP"

sed -e "s/__VERSION__/$VERSION/g" \
    -e "s/__COPYRIGHT__/Copyright © $(date +%Y) Vojtěch Zicha. MIT licensed./g" \
    "$REPO/packaging/Info.plist" > "$APP/Contents/Info.plist"

# The bundle is not what Chrome launches — the native-messaging manifest names
# the executable inside it directly — but it is what codesign, notarization and
# Gatekeeper all reason about, and what /Applications expects to hold.
say "assembled $APP"

if [ -z "${SIGN_IDENTITY:-}" ]; then
  say "SIGN_IDENTITY is unset — leaving the app UNSIGNED."
  say "It will run here and be refused by Gatekeeper anywhere else."
  exit 0
fi

# --options runtime is the hardened runtime, which notarization requires and
# which is also what makes the entitlements file mean anything: without it,
# library validation is not enforced and disable-library-validation is inert.
# --timestamp is required for notarization; a signature without one is rejected.
say "signing with ${SIGN_IDENTITY}…"
codesign --force --sign "$SIGN_IDENTITY" \
    --options runtime \
    --timestamp \
    --entitlements "$REPO/packaging/SignBridge.entitlements" \
    "$APP/Contents/MacOS/signbridge-host"
codesign --force --sign "$SIGN_IDENTITY" \
    --options runtime \
    --timestamp \
    --entitlements "$REPO/packaging/SignBridge.entitlements" \
    "$APP"

# Verified rather than assumed: codesign exits 0 on plenty of signatures
# Gatekeeper will not accept.
codesign --verify --strict --verbose=2 "$APP"
say "signed and verified."

# The entitlement is the whole reason this product exists rather than Fortify,
# so it is asserted on the artifact and not just in the file that requested it.
if ! codesign -d --entitlements - --xml "$APP" 2>/dev/null \
    | plutil -convert xml1 -o - - 2>/dev/null \
    | grep -q 'com.apple.security.cs.disable-library-validation'; then
  echo "signbridge  ERROR  the signed app is missing disable-library-validation." >&2
  echo "signbridge         It would be killed by macOS the moment it opened a card." >&2
  exit 1
fi
say "disable-library-validation is present."

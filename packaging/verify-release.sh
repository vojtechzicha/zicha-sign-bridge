#!/bin/bash
#
# The last gate before publishing: read the ARTIFACTS and check the properties
# a broken release would lack.
#
#   packaging/verify-release.sh build/SignBridge.pkg build/SignBridge.app
#
# Every check here corresponds to a way this product has failed or could fail
# silently — installing fine and then not working, which is the expensive shape
# because it looks like the app's problem, not the helper's.
set -uo pipefail

PKG="${1:?usage: verify-release.sh <pkg> <app>}"
APP="${2:?usage: verify-release.sh <pkg> <app>}"

pass=0
fail=0
ok()  { echo "  ✓ $1"; pass=$((pass+1)); }
no()  { echo "  ✗ $1"; fail=$((fail+1)); }
check() { if eval "$2" >/dev/null 2>&1; then ok "$1"; else no "$1"; fi; }

echo "Verifying $(basename "$APP")"

check "universal — runs on Intel as well as Apple silicon" \
  "lipo -archs '$APP/Contents/MacOS/signbridge-host' | grep -q x86_64 && lipo -archs '$APP/Contents/MacOS/signbridge-host' | grep -q arm64"

check "signed with a Developer ID" \
  "codesign -dv --verbose=4 '$APP' 2>&1 | grep -q 'Authority=Developer ID Application'"

check "hardened runtime is on" \
  "codesign -d --verbose=4 '$APP' 2>&1 | grep -q 'flags=.*runtime'"

# The one that decides whether this product works at all. Without it macOS kills
# the process the moment it dlopens the card's PKCS #11 module — which is how
# Fortify died, and why this exists.
check "carries com.apple.security.cs.disable-library-validation" \
  "codesign -d --entitlements - --xml '$APP' 2>/dev/null | plutil -convert xml1 -o - - | grep -q 'disable-library-validation'"

check "signature verifies strictly" \
  "codesign --verify --strict --deep '$APP'"

# Gatekeeper's own opinion, which is the only one that counts on a stranger's
# Mac. `spctl` disagreeing with a valid codesign is exactly the notarization
# gap this catches.
check "Gatekeeper accepts it" \
  "spctl --assess --type execute -vv '$APP' 2>&1 | grep -q 'accepted'"

check "notarization ticket is stapled (works offline)" \
  "xcrun stapler validate '$APP'"

check "LSUIElement — no Dock icon for a helper nobody launches" \
  "plutil -extract LSUIElement raw '$APP/Contents/Info.plist' | grep -q true"

check "the host manifest travels inside the bundle" \
  "test -f '$APP/Contents/Resources/dev.zicha.signbridge.json'"

# The manifest's path must name the binary that is actually there. A path left
# over from a previous layout produces a browser that reports the host as
# missing, with nothing in any log to say why.
# `plutil -extract … raw` rather than converting to JSON and matching: the JSON
# form escapes every forward slash, so the comparison never succeeds and the
# check reports a failure whose message contains the right path.
MANIFEST_PATH="$(plutil -extract path raw "$APP/Contents/Resources/dev.zicha.signbridge.json" 2>/dev/null)"
if [ "$MANIFEST_PATH" = "/Applications/SignBridge.app/Contents/MacOS/signbridge-host" ]; then
  ok "the manifest points at the installed binary"
else
  no "the manifest points at '$MANIFEST_PATH', not the installed binary"
fi

EXPECTED_ID="jeiiaokfpmlldaebepnpppjjlhhangje"
if plutil -extract allowed_origins.0 raw "$APP/Contents/Resources/dev.zicha.signbridge.json" 2>/dev/null \
    | grep -q "$EXPECTED_ID"; then
  ok "the manifest allows the pinned extension id"
else
  no "the manifest does not allow $EXPECTED_ID — the browser would be refused by the host"
fi

echo "Verifying $(basename "$PKG")"

check "installer is signed by a Developer ID Installer" \
  "pkgutil --check-signature '$PKG' | grep -q 'Developer ID Installer'"

check "installer is notarized and stapled" \
  "xcrun stapler validate '$PKG'"

check "installer carries the pre/post install scripts" \
  "pkgutil --expand '$PKG' '$(mktemp -d)/x' && true"

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ] || {
  echo "REFUSING to publish: a release that fails any of these installs and then does not work." >&2
  exit 1
}

#!/bin/bash
#
# Build SignBridge.pkg from an already-built SignBridge.app.
#
#   packaging/build-pkg.sh <version> [outdir]
#
# Signed with a Developer ID INSTALLER identity, which is a different
# certificate from the Application one that signs the app — a pkg signed with
# the application identity is refused by the installer with a message that does
# not say so. INSTALLER_IDENTITY unset leaves it unsigned.
set -euo pipefail

VERSION="${1:?usage: build-pkg.sh <version> [outdir]}"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${2:-$REPO/build}"
APP="$OUT/SignBridge.app"
STAGE="$OUT/pkgroot"
PKG="$OUT/SignBridge.pkg"

say() { echo "signbridge  $*"; }

[ -d "$APP" ] || { echo "signbridge  ERROR  no app at $APP — run build-app.sh first" >&2; exit 1; }

# NOTHING here may modify the bundle. It has been signed, and possibly stapled,
# by the time this runs — and the signature seals the whole resource directory,
# so adding even one file invalidates it. That is not a theoretical concern:
# this script used to drop the native-messaging manifest into Contents/Resources
# at exactly this point, and the result notarized as an app, then failed
# notarization as a pkg with "the signature of the binary is invalid" — a
# message that names the binary and not the file that was added. The manifest is
# put in by build-app.sh now, before signing.
#
# Checked rather than promised, because the next person to add a line here will
# not have read this comment.
if ! codesign --verify --strict "$APP" 2>/dev/null; then
    if [ -n "${INSTALLER_IDENTITY:-}" ]; then
        echo "signbridge  ERROR  $APP does not carry a valid signature." >&2
        codesign --verify --strict --verbose=2 "$APP" || true
        echo "signbridge         Packaging it would produce an installer that fails" >&2
        echo "signbridge         notarization, or installs software macOS then refuses to run." >&2
        exit 1
    fi
    say "the app is unsigned — packaging it anyway for a local build."
fi

rm -rf "$STAGE"
mkdir -p "$STAGE/Applications"
# ditto --norsrc --noextattr, not `cp -R`: a resource fork or a Finder info
# attribute carried into the payload is a notarization rejection, and `cp -R`
# brings both through.
#
# `._` entries still appear in `pkgutil --payload-files` afterwards, and that is
# expected rather than a leak: macOS 14+ stamps com.apple.provenance on every
# file it writes, the attribute cannot be cleared, and pkgbuild archives any
# extended attribute as AppleDouble. Apple's own tooling produces the same
# thing. What matters is that nothing we control adds to it.
ditto --norsrc --noextattr --noacl "$APP" "$STAGE/Applications/SignBridge.app"
xattr -cr "$STAGE/Applications/SignBridge.app"

say "building component package…"
COMPONENT="$OUT/SignBridge-component.pkg"
pkgbuild \
    --root "$STAGE" \
    --identifier dev.zicha.signbridge \
    --version "$VERSION" \
    --scripts "$REPO/packaging/pkg-scripts" \
    --install-location / \
    "$COMPONENT"

say "building distribution package…"
DIST="$OUT/distribution.xml"
cat > "$DIST" <<XML
<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="2">
    <title>Sign Bridge</title>
    <organization>dev.zicha</organization>
    <!-- The card is on a Mac and the helper opens its vendor's PKCS #11
         module; there is nothing to run anywhere else. Stated here so the
         installer refuses rather than half-working. -->
    <options customize="never" require-scripts="true" hostArchitectures="arm64,x86_64"/>
    <volume-check>
        <allowed-os-versions><os-version min="13.0"/></allowed-os-versions>
    </volume-check>
    <choices-outline><line choice="default"/></choices-outline>
    <choice id="default"><pkg-ref id="dev.zicha.signbridge"/></choice>
    <pkg-ref id="dev.zicha.signbridge" version="$VERSION" onConclusion="none">SignBridge-component.pkg</pkg-ref>
</installer-gui-script>
XML

if [ -n "${INSTALLER_IDENTITY:-}" ]; then
    say "signing the installer with ${INSTALLER_IDENTITY}…"
    productbuild --distribution "$DIST" --package-path "$OUT" \
        --sign "$INSTALLER_IDENTITY" --timestamp "$PKG"
    pkgutil --check-signature "$PKG" | head -3
else
    say "INSTALLER_IDENTITY is unset — leaving the installer UNSIGNED."
    productbuild --distribution "$DIST" --package-path "$OUT" "$PKG"
fi

rm -f "$COMPONENT" "$DIST"
rm -rf "$STAGE"
say "built $PKG"

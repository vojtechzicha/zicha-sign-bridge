#!/bin/bash
#
# Notarize an app or a pkg, wait for the verdict, and staple it.
#
#   packaging/notarize.sh build/SignBridge.pkg
#
# Needs an App Store Connect API key in the environment: ASC_KEY_ID,
# ASC_ISSUER_ID and ASC_KEY_P8_BASE64. A key rather than an Apple ID and
# app-specific password because it is the only one of the two that survives the
# account having two-factor authentication turned on, which every account does.
set -euo pipefail

TARGET="${1:?usage: notarize.sh <app-or-pkg>}"
say() { echo "signbridge  $*"; }

: "${ASC_KEY_ID:?ASC_KEY_ID is required}"
: "${ASC_ISSUER_ID:?ASC_ISSUER_ID is required}"
: "${ASC_KEY_P8_BASE64:?ASC_KEY_P8_BASE64 is required}"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
KEY="$WORK/asc.p8"
echo "$ASC_KEY_P8_BASE64" | base64 --decode > "$KEY"

# An .app cannot be submitted as a directory; it goes up inside a zip. A .pkg
# is a single file and goes as it is. ditto -c -k --keepParent is the archive
# format notarytool expects — a `zip -r` of a bundle loses the symlinks inside
# a framework and is rejected.
case "$TARGET" in
  *.app)
    UPLOAD="$WORK/upload.zip"
    ditto -c -k --keepParent "$TARGET" "$UPLOAD"
    ;;
  *)
    UPLOAD="$TARGET"
    ;;
esac

say "submitting $(basename "$TARGET") for notarization…"
set +e
OUTPUT="$(xcrun notarytool submit "$UPLOAD" \
    --key "$KEY" --key-id "$ASC_KEY_ID" --issuer "$ASC_ISSUER_ID" \
    --wait --timeout 30m 2>&1)"
STATUS=$?
set -e
echo "$OUTPUT"

# `notarytool submit --wait` exits 0 for a submission that was ACCEPTED and
# also for one that came back Invalid — the exit status reports whether the
# CONVERSATION worked, not whether Apple liked the software. Reading it as a
# verdict ships a rejected build.
if [ $STATUS -ne 0 ] || ! grep -q "status: Accepted" <<<"$OUTPUT"; then
  say "ERROR  notarization did not come back Accepted."
  ID="$(grep -m1 -o '  id: [0-9a-f-]\{36\}' <<<"$OUTPUT" | awk '{print $2}' || true)"
  if [ -n "${ID:-}" ]; then
    say "fetching the log for $ID…"
    xcrun notarytool log "$ID" --key "$KEY" --key-id "$ASC_KEY_ID" --issuer "$ASC_ISSUER_ID" || true
  fi
  exit 1
fi

say "accepted — stapling…"
xcrun stapler staple "$TARGET"
xcrun stapler validate "$TARGET"

# The point of stapling: the ticket travels IN the artifact, so a Mac with no
# network still opens it without a Gatekeeper warning. Asserted here rather
# than trusted, because `stapler staple` on an unnotarized file is a no-op that
# does not fail loudly enough.
say "stapled and validated $(basename "$TARGET")."

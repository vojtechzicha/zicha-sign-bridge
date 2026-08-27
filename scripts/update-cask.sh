#!/bin/bash
#
# Point the Homebrew cask at a published release.
#
#   scripts/update-cask.sh 1.2.0
#
# Run AFTER the GitHub release exists — it downloads the published pkg to take
# its checksum, because a cask whose sha256 does not match what people actually
# download fails at install time with a message about a corrupted file, and the
# only way to be sure is to hash the artifact rather than the local build.
set -euo pipefail

VERSION="${1:?usage: update-cask.sh <version>}"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TAP="${TAP_DIR:-$HOME/Developer/github-vojtechzicha/homebrew-tap}"
URL="https://github.com/vojtechzicha/zicha-sign-bridge/releases/download/v$VERSION/SignBridge.pkg"

say() { echo "cask  $*"; }

[ -d "$TAP" ] || { echo "cask  ERROR  no tap checkout at $TAP (set TAP_DIR)" >&2; exit 1; }

say "downloading the published pkg to hash it…"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
curl -fsSL "$URL" -o "$TMP/SignBridge.pkg" || {
    echo "cask  ERROR  could not download $URL" >&2
    echo "cask         Has the release been published yet?" >&2
    exit 1
}
SHA="$(shasum -a 256 "$TMP/SignBridge.pkg" | awk '{print $1}')"
say "sha256 $SHA"

# Sanity: what was downloaded should be a notarized installer, not a 404 page
# that curl was happy with.
xcrun stapler validate "$TMP/SignBridge.pkg" >/dev/null 2>&1 \
    || { echo "cask  ERROR  the downloaded pkg is not stapled — refusing to publish a cask for it" >&2; exit 1; }

mkdir -p "$TAP/Casks"
sed -e "s/^  version \".*\"/  version \"$VERSION\"/" \
    -e "s/^  sha256 \".*\"/  sha256 \"$SHA\"/" \
    "$REPO/packaging/homebrew/sign-bridge.rb" > "$TAP/Casks/sign-bridge.rb"

say "wrote $TAP/Casks/sign-bridge.rb"
say "audit it before pushing:  brew audit --cask --online $TAP/Casks/sign-bridge.rb"

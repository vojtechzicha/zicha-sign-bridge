#!/bin/bash
#
# Set the version in the four places it lives, together.
#
#   scripts/bump-version.sh 1.2.0
#
# Together is the point: the page decides whether to tell someone their helper
# is out of date by comparing the version the HOST reports against the minimum
# the EXTENSION declares, so a half-bumped release misreports itself and the
# install prompt never goes away. scripts/check-version.mjs fails the release
# if they drift, and this is the tool that keeps them from drifting.
set -euo pipefail

VERSION="${1:?usage: bump-version.sh <version>}"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# The Chrome Web Store accepts 1-4 dot-separated integers and nothing else — no
# -rc1, no +build. Checked here so a bad version is caught before it is written
# into four files rather than at the end of a release.
if ! [[ "$VERSION" =~ ^[0-9]+(\.[0-9]+){0,3}$ ]]; then
    echo "bump  ERROR  '$VERSION' is not a version the Chrome Web Store accepts." >&2
    echo "bump         1 to 4 integers separated by dots, no suffix." >&2
    exit 1
fi

edit() {
    local file="$1" pattern="$2"
    perl -i -pe "$pattern" "$REPO/$file"
    echo "bump  $file"
}

edit extension/manifest.json 's/("version"\s*:\s*")[^"]+(")/${1}'"$VERSION"'${2}/'
edit extension/package.json  's/("version"\s*:\s*")[^"]+(")/${1}'"$VERSION"'${2}/'
edit agent/Sources/SignBridgeCore/Protocol.swift \
    's/(hostVersion\s*=\s*")[^"]+(")/${1}'"$VERSION"'${2}/'

node "$REPO/scripts/check-version.mjs" "$VERSION"
echo
echo "Next:  git commit -am \"Release $VERSION\" && git tag v$VERSION && git push --tags"

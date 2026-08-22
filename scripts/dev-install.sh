#!/bin/bash
#
# Register the locally-built host with the Chromium browsers on this machine,
# so an unpacked extension can reach it.
#
# Everything it writes is per-user (~/Library/...), so no admin, and
# `--uninstall` takes it all away again. This is the development path; the
# shipped .pkg installs the same manifest pointing at /Applications instead.
#
#   scripts/dev-install.sh                 # host talks to SecureStore (the card)
#   scripts/dev-install.sh --softhsm DIR   # host talks to a SoftHSM token
#   scripts/dev-install.sh --uninstall
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HOST_NAME="dev.zicha.signbridge"
LAUNCHER="$HOME/Library/Application Support/SignBridge/signbridge-host-dev"

# Every Chromium browser looks in its own directory. Writing to all of them is
# cheaper than asking which one is in use.
TARGETS=(
    "$HOME/Library/Application Support/Google/Chrome/NativeMessagingHosts"
    "$HOME/Library/Application Support/Google/Chrome Beta/NativeMessagingHosts"
    "$HOME/Library/Application Support/Microsoft Edge/NativeMessagingHosts"
    "$HOME/Library/Application Support/BraveSoftware/Brave-Browser/NativeMessagingHosts"
    "$HOME/Library/Application Support/Chromium/NativeMessagingHosts"
)

if [ "${1:-}" = "--uninstall" ]; then
    for dir in "${TARGETS[@]}"; do rm -f "$dir/$HOST_NAME.json"; done
    rm -f "$LAUNCHER"
    echo "Removed $HOST_NAME from every Chromium profile directory."
    exit 0
fi

MODULE=""
if [ "${1:-}" = "--softhsm" ]; then
    SOFTHSM_DIR="${2:?--softhsm needs the directory scripts/softhsm-token.sh wrote}"
    MODULE="$(brew --prefix softhsm)/lib/softhsm/libsofthsm2.so"
    SOFTHSM_CONF="$SOFTHSM_DIR/softhsm2.conf"
fi

echo "Building the host…"
(cd "$REPO/agent" && swift build --product signbridge-host)
BINARY="$REPO/agent/.build/debug/signbridge-host"

# Chrome launches the host with a bare environment, so anything the debug build
# needs has to be baked into a launcher rather than exported in a shell. The
# shipped host reads SecureStore's default path and needs none of this.
mkdir -p "$(dirname "$LAUNCHER")"
{
    echo '#!/bin/bash'
    echo '# Written by scripts/dev-install.sh — not part of the shipped product.'
    [ -n "$MODULE" ] && echo "export SIGNBRIDGE_MODULE=\"$MODULE\""
    [ -n "$MODULE" ] && echo "export SOFTHSM2_CONF=\"$SOFTHSM_CONF\""
    echo "exec \"$BINARY\" \"\$@\""
} > "$LAUNCHER"
chmod +x "$LAUNCHER"

# The allowed_origins list is the shipped one — the extension id is pinned, so
# the unpacked build and the published build are the same extension.
ALLOWED="$(python3 -c "
import json,sys
print(json.dumps(json.load(open('$REPO/packaging/native-messaging/$HOST_NAME.json'))['allowed_origins']))
")"

for dir in "${TARGETS[@]}"; do
    mkdir -p "$dir"
    cat > "$dir/$HOST_NAME.json" <<JSON
{
  "name": "$HOST_NAME",
  "description": "Sign Bridge native host (development build)",
  "path": "$LAUNCHER",
  "type": "stdio",
  "allowed_origins": $ALLOWED
}
JSON
done

echo "Registered $HOST_NAME → $LAUNCHER"
[ -n "$MODULE" ] && echo "  using SoftHSM at $MODULE" || echo "  using SecureStore (the card)"
echo
echo "Now load $REPO/extension/dist as an unpacked extension in chrome://extensions."

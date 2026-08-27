# Homebrew cask for Sign Bridge.
#
# Lives in a PERSONAL TAP (vojtechzicha/homebrew-tap), not in homebrew-cask.
# The official repository has a notability bar — roughly 75 stars or 30 forks —
# that a new tool does not clear, and submitting anyway wastes a maintainer's
# time. A tap installs with one extra command and is otherwise identical:
#
#   brew tap vojtechzicha/tap
#   brew install --cask sign-bridge
#
# `version` and `sha256` are rewritten by .github/workflows/release.yml, which
# opens a pull request against the tap after a release is published. They are
# not edited by hand — a cask whose sha256 does not match its download fails at
# install time with a message about a corrupted file.
cask "sign-bridge" do
  version "0.1.0"
  sha256 "0000000000000000000000000000000000000000000000000000000000000000"

  url "https://github.com/vojtechzicha/zicha-sign-bridge/releases/download/v#{version}/SignBridge.pkg"
  name "Sign Bridge"
  desc "Sign PDFs in the browser with a qualified certificate on a hardware token"
  homepage "https://github.com/vojtechzicha/zicha-sign-bridge"

  livecheck do
    url :url
    strategy :github_latest
  end

  # The card is on a Mac and the helper dlopens its vendor's PKCS #11 module.
  # There is nothing to run anywhere else, and macOS 13 is where the Swift
  # package's platform floor sits.
  depends_on macos: ">= :ventura"

  pkg "SignBridge.pkg"

  # The pkg's postinstall writes a native-messaging manifest into every
  # Chromium browser's system-wide directory; uninstalling has to take those
  # back, or a browser keeps launching a host that is no longer there.
  uninstall pkgutil: "dev.zicha.signbridge",
            delete:  [
              "/Library/Google/Chrome/NativeMessagingHosts/dev.zicha.signbridge.json",
              "/Library/Google/Chrome Beta/NativeMessagingHosts/dev.zicha.signbridge.json",
              "/Library/Google/Chrome Dev/NativeMessagingHosts/dev.zicha.signbridge.json",
              "/Library/Google/Chrome Canary/NativeMessagingHosts/dev.zicha.signbridge.json",
              "/Library/Microsoft/Edge/NativeMessagingHosts/dev.zicha.signbridge.json",
              "/Library/Application Support/Chromium/NativeMessagingHosts/dev.zicha.signbridge.json",
              "/Library/Application Support/BraveSoftware/Brave-Browser/NativeMessagingHosts/dev.zicha.signbridge.json",
              "/Library/Application Support/Vivaldi/NativeMessagingHosts/dev.zicha.signbridge.json",
            ]

  # The pairing decisions, and nothing else. Kept out of `uninstall` and put in
  # `zap` deliberately: reinstalling should not silently re-approve the origins
  # someone approved before, but a plain uninstall should not throw away a
  # decision they may want back either. `brew uninstall --zap` is the explicit
  # "forget everything" that this is.
  zap trash: "~/Library/Application Support/SignBridge"

  caveats <<~EOS
    Sign Bridge is two halves and this is one of them. The browser extension is
    the other, and signing does not work without both:

      https://chromewebstore.google.com/detail/#{"jeiiaokfpmlldaebepnpppjjlhhangje"}

    Restart your browser after installing, so it picks up the native messaging
    host this just registered.
  EOS
end

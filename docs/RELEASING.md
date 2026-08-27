# Releasing Sign Bridge

Two artifacts, two channels, one version number. The helper goes out as a
notarized `.pkg` on GitHub Releases (and through a Homebrew cask that points at
it); the extension goes to the Chrome Web Store. They are useless apart —
neither half signs anything on its own — so they are versioned together and
released together.

## The short version

```bash
scripts/bump-version.sh 1.2.0     # rewrites the four places the version lives
git commit -am "Release 1.2.0" && git tag v1.2.0 && git push --tags
```

The tag does the rest: build, sign, notarize, staple, verify, publish. Then
upload the extension zip from the release to the Chrome Web Store by hand (see
below — that step cannot be automated into a tag push, and should not be).

## What has to exist first

### Apple: one certificate pair and one API key

Developer ID signing needs the **Apple Developer Program** ($99/yr). Two
different certificates are involved and they are not interchangeable — a `.pkg`
signed with the Application identity is refused by the installer, with a message
that does not explain why:

| | |
|---|---|
| **Developer ID Application** | signs `SignBridge.app` |
| **Developer ID Installer** | signs `SignBridge.pkg` |

Create both at [developer.apple.com/account/resources/certificates](https://developer.apple.com/account/resources/certificates),
then export them together from Keychain Access as one `.p12` (select both, right
click → Export 2 items), with a password.

Notarization needs an **App Store Connect API key** (Users and Access → Keys →
`Developer` role). Download the `.p8` once — Apple does not offer it again.
A key rather than an Apple ID and app-specific password because a key is the
only one of the two that keeps working with two-factor authentication on, which
every account has.

### The GitHub secrets

Repository → Settings → Secrets and variables → Actions:

| Secret | Where it comes from |
|---|---|
| `APPLE_CERT_P12_BASE64` | `base64 -i certs.p12 \| pbcopy` |
| `APPLE_CERT_PASSWORD` | the password used at export |
| `APPLE_SIGN_IDENTITY` | `Developer ID Application: Your Name (TEAMID)` — copy from `security find-identity -v -p codesigning` |
| `APPLE_INSTALLER_IDENTITY` | `Developer ID Installer: Your Name (TEAMID)` |
| `ASC_KEY_ID` | the 10-character key id from App Store Connect |
| `ASC_ISSUER_ID` | the issuer UUID on the same page |
| `ASC_KEY_P8_BASE64` | `base64 -i AuthKey_XXXXXXXXXX.p8 \| pbcopy` |

Keep the same values in 1Password (vault `Development`, item
`zicha-sign-bridge-ci`). The `.p8` cannot be re-downloaded; losing it means
issuing a new key.

### The Chrome Web Store

A one-off **$5** developer registration at
[chrome.google.com/webstore/devconsole](https://chrome.google.com/webstore/devconsole).
The listing is **unlisted**: reachable by link, not by search. That suits a tool
whose only job is to serve one web app, and it still auto-updates on every
machine signed into the same profile — which is the actual reason to use the
store rather than a self-hosted CRX.

**The extension key must not change.** `manifest.json` pins it, which is what
makes the unpacked development build and the published build the same
extension. The id is baked into three places — the app's bridge, the native host
manifest's `allowed_origins`, and any policy install — so a new id is a
reinstall everywhere. Keep the private half in 1Password beside the CI item.

## What the tag actually does

`.github/workflows/release.yml`, in order:

1. **Checks the version is consistent** across the tag, both extension files and
   the host's `hostVersion`. They must agree: the page compares the version the
   host reports against the minimum the extension declares in order to say
   "your helper is out of date", so drift produces an install prompt that
   nothing makes go away.
2. **Runs the checks** — the agent's and the extension's. A release that has not
   passed them is not a release.
3. **Builds universal** (arm64 + x86_64), signs with the hardened runtime and
   the entitlements, notarizes, staples.
4. **Builds the `.pkg`**, signs it with the Installer identity, notarizes and
   staples that too. Both are stapled: a stapled app inside an unstapled
   installer still warns at the moment people actually see it — the
   double-click on the download.
5. **Verifies the artifacts** (`packaging/verify-release.sh`) and refuses to
   publish if any property is missing. Every check there is a way this has
   failed or could fail silently — installing fine and then not working.
6. **Publishes** the release with the pkg, the extension zip and `SHA256SUMS.txt`.

### The entitlement that matters

`com.apple.security.cs.disable-library-validation`. The host `dlopen`s a PKCS #11
module signed by someone else; under the hardened runtime, which notarization
requires, that is refused without this. It is exactly what killed Fortify, and
`verify-release.sh` asserts it on the signed artifact rather than trusting the
file that requested it.

## The two manual steps

### Chrome Web Store

Automating an upload into a tag push would be joining a human review queue on a
git push, and a rejected review would leave a published helper with no extension
to talk to. So:

1. Download `sign-bridge-extension-<version>.zip` from the GitHub release.
2. Developer console → the item → Package → Upload new package.
3. Submit for review. Expect anything from hours to a few days.

Reviewers ask about `nativeMessaging` every time. The honest answer is the whole
design: the extension is a relay and a gate, it contains no cryptography, the
private key never leaves the token, and the origins allowed to talk to it are
pinned in `externally_connectable`. Point at this repository — it is public.

### Homebrew

After the release is published:

```bash
scripts/update-cask.sh 1.2.0    # rewrites version + sha256, opens a PR on the tap
```

The tap is `vojtechzicha/homebrew-tap`. It is a personal tap rather than
homebrew-cask because the official repository has a notability bar (roughly 75
stars) that a new tool does not clear.

## Rolling back

A release that installs and does not work is worse than no release. Delete the
GitHub release and the tag, revert the cask PR, and — if the extension already
shipped — publish the previous zip again from the store console. The extension
and the helper tolerate a version gap in one direction only: an OLD extension
with a NEW helper is fine (the protocol is versioned), a new extension with an
old helper reports `helper-outdated` and sends people to install the pkg.

# Sign Bridge

Lets a web page sign with the qualified certificate on a hardware token, on
macOS. Built for [track.zicha.dev](https://track.zicha.dev), whose PAdES export
needs a QES that a browser has no way to reach on its own.

Two halves, and both are needed:

- a **Chrome/Edge extension**, which is the only thing the browser will let an
  approved origin talk to, and
- a **native host**, which owns the PKCS#11 module, the card and the PIN.

```
page → extension → signbridge-host → PKCS#11 module → reader → card
```

Design, alternatives considered, and why not a localhost daemon:
[`docs/sign-bridge-plan.md`](https://github.com/vojtechzicha/toggl-track-quick-view/blob/main/docs/sign-bridge-plan.md)
in the app repository. The wire format is [`protocol/protocol.md`](protocol/protocol.md).

## Security

Four layers, each independent of the others:

1. **Origin, enforced by the browser.** `externally_connectable.matches` in
   `extension/manifest.json` lists the origins allowed to connect. Page script
   cannot forge the origin the extension is told it is talking to.
2. **Extension identity, enforced by the OS.** The native host manifest's
   `allowed_origins` names one extension id. The id is pinned by the `key` in
   the extension manifest, so it does not change between the unpacked build and
   a published one.
3. **Pairing, per origin, once.** First contact puts a four-character code in
   the host's window; the page shows the same code. Approving records the
   origin in `~/Library/Application Support/SignBridge/paired.json`, which is a
   plain file you can read and delete.
4. **The PIN is the consent.** `C_Login` happens per signature, in the host's
   own window, alongside the document name and the digest of what is being
   signed. A page can ask for a signature; only a person can produce one.

There is no "remember the PIN", no unattended mode, and no request that signs
without the confirmation window.

## Layout

| | |
|---|---|
| `agent/` | Swift package: `SignBridgeCore` (PKCS#11, protocol, consent), `signbridge-host` (what Chrome launches), `signbridge-check` (the checks) |
| `extension/` | MV3 extension — a relay and a gate, no cryptography |
| `protocol/` | the wire format, which is the contract between the two |
| `packaging/` | native messaging manifests, entitlements |
| `scripts/` | `softhsm-token.sh`, `dev-install.sh` |

## Developing

```bash
brew install softhsm opensc

# A throwaway PKCS#11 token to develop against — a real module, no card needed.
eval "$(scripts/softhsm-token.sh ~/.signbridge-dev)"

cd agent && swift run signbridge-check     # 49 checks
cd ../extension && npm ci && npm run check && npm run build

# Register the debug host with every Chromium browser on this machine (no admin).
scripts/dev-install.sh --softhsm ~/.signbridge-dev
```

Then load `extension/dist` as an unpacked extension at `chrome://extensions`
with Developer mode on. The id is pinned, so it is the same extension the
published build will be, and the host manifest already allows it.

To point the host at the real card instead, re-run `scripts/dev-install.sh`
with no arguments; `scripts/dev-install.sh --uninstall` removes everything it
wrote.

### Checks

`swift run signbridge-check` covers the DigestInfo encoding, module loading,
token discovery, signing, and the protocol's access rules. Token checks are
**skipped rather than failed** when no token is configured, so a clone with no
SoftHSM still builds and still runs the rest.

They are an executable rather than a test target on purpose: XCTest and
swift-testing both ship with Xcode, not the Command Line Tools, and the checks
should run on any machine with a Swift toolchain and in CI without selecting one.

Signing is checked by verifying the result through Security.framework against
the certificate's own public key — with a wrong DigestInfo prefix the token
still returns 256 entirely plausible bytes, and that assertion is the only
thing anywhere that would notice.

## Notes for the impatient

- **macOS only**, deliberately. The card is on a Mac.
- **Chrome and Edge only.** Firefox has no `externally_connectable` and needs a
  content-script transport; Safari has no native messaging for pages at all.
- The token this exists for offers **no `CKM_SHA256_RSA_PKCS`**, so the host
  builds the DigestInfo itself and signs with raw `CKM_RSA_PKCS`. That is the
  path every token supports, so it is the only path here.
- The host reports certificates as **raw DER and nothing derived from it**. The
  web app parses subject, validity, key usage and the qualified claim, because
  it already carries an ASN.1 stack and a second implementation here could
  disagree with it.

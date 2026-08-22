# Sign Bridge protocol v1

One request/response protocol, spoken end to end:

```
page ──chrome.runtime.sendMessage──▶ extension ──native messaging──▶ host ──PKCS#11──▶ token
```

The extension does not interpret anything. It checks that the sender's origin is
one it serves, attaches that origin, and relays. Every decision that matters is
taken by the host, where the person is.

## Framing

Page ↔ extension is structured clone; extension ↔ host is Chrome native
messaging (4-byte little-endian length prefix, then UTF-8 JSON).

Every request carries an `id` the response echoes. `type` selects the operation.

## Requests

### `hello`

```json
{ "id": "1", "type": "hello", "protocol": 1 }
```
```json
{ "id": "1", "ok": true, "protocol": 1, "hostVersion": "0.1.0",
  "paired": false,
  "tokens": [{ "label": "…", "model": "…", "serial": "…",
               "loginRequired": true, "pinInitialized": true }] }
```

Answered without pairing and without a PIN — it is how the page learns the
helper exists, which version it is, and whether a token is in the reader. It
must never have a side effect, because the page calls it unprompted.

### `pair`

```json
{ "id": "2", "type": "pair" }
```
```json
{ "id": "2", "ok": true, "event": "pairing-code", "code": "K7F2" }
```

The host displays the same four characters and waits. On approval it records the
origin and answers a final frame `{"id":"2","ok":true,"paired":true}`; on
refusal, `{"ok":false,"code":"refused"}`.

**A frame carrying `event` is not the answer.** It is news from a request still
in progress, and the code has to reach the page while the host's window is still
on screen — which is the entire point of a code. That is why the page connects
with `chrome.runtime.connect` and not `sendMessage`: a single request/response
call cannot deliver anything before the request finishes, so the code would
arrive after the window it was meant to be compared against had gone.

The code exists so the person can tell that the window in front of them belongs
to the page in front of them. It is not a secret and not a password.

### `listCertificates`

```json
{ "id": "3", "type": "listCertificates" }
```
```json
{ "id": "3", "ok": true, "certificates": [
  { "id": "9203070300022806:01", "der": "MIIF…", "hasPrivateKey": true,
    "tokenSerial": "9203070300022806", "tokenLabel": "…" }] }
```

Requires pairing, not a PIN: certificates are public objects on the token.

**The host reports DER and nothing derived from it.** Subject, issuer, validity,
key usage and whether the certificate claims to be qualified are all read from
these bytes by the web app, which already carries an ASN.1 stack for building
the CMS. One implementation of "is this qualified", in the place where it can be
tested against fixtures, rather than a second one in Swift that could disagree
with it.

### `sign`

```json
{ "id": "4", "type": "sign", "certificateId": "…", "hash": "SHA-256",
  "data": "MYIB…",
  "context": { "documentName": "Timesheet 2026-08.pdf", "digest": "9f86d0…" } }
```
```json
{ "id": "4", "ok": true, "signature": "Q2FI…" }
```

`data` is base64 of the bytes to sign — for PAdES, the DER SignedAttributes. The
host hashes them, wraps the hash as a DigestInfo and signs with raw
`CKM_RSA_PKCS`; the token never sees the document.

`context` is not decoration. The host's confirmation window shows the document
name and digest, so what a person approves is tied to what is being signed
rather than to what the page says it is doing. A request without it is refused.

## Errors

```json
{ "id": "4", "ok": false, "code": "pin_failed", "message": "…" }
```

| code | meaning |
|---|---|
| `unsupported_protocol` | the page speaks a version this host does not |
| `not_paired` | send `pair` first |
| `refused` | the person declined the pairing or the signature |
| `no_token` | nothing usable in any reader |
| `not_found` | no such certificate on any present token |
| `no_private_key` | that certificate cannot sign — it is a CA or a contact's |
| `pin_failed` | wrong PIN; retrying is reasonable |
| `pin_locked` | the card has locked itself; retrying makes it worse |
| `token_error` | anything else from PKCS #11, with the CKR_ name in `message` |

`pin_failed` and `pin_locked` are distinct because the first means "try again"
and the second means "stop", and a UI that confuses them will lock a card.

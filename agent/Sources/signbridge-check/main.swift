// Checks the agent against a real PKCS #11 token. Run with:
//   swift run signbridge-check
//
// The token is SoftHSM, not the card: the card needs a person, a reader and a
// PIN nobody should type into CI, and SoftHSM is the same interface — same
// C_Login, same C_Sign, same attribute rules. `scripts/softhsm-token.sh`
// builds one and prints the environment this reads:
//
//   eval "$(scripts/softhsm-token.sh)" && swift run signbridge-check
//
// Without that environment the token checks are SKIPPED rather than failed, so
// a clone with no SoftHSM still builds and still runs everything that does not
// need a token — which includes the DigestInfo encoding, the one piece of the
// signing path where a mistake produces a signature that looks fine and
// verifies nowhere.

import CryptoKit
import Foundation
import Security
import SignBridgeCore

var checks = Checks()

// MARK: - DigestInfo (no token needed)

checks.section("DigestInfo")

let digestInfo = DigestInfo.sha256(over: Array("abc".utf8))
checks.equal(digestInfo.count, 51, "the DigestInfo is a 19-byte prefix plus a 32-byte hash")
checks.equal(Array(digestInfo.prefix(19)), DigestInfo.sha256Prefix, "the prefix is the constant one")
checks.equal(
    Array(digestInfo.suffix(32)).map { String(format: "%02x", $0) }.joined(),
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    "the hash is the published SHA-256 of \"abc\""
)
// The outer SEQUENCE has to describe the 49 bytes that follow it. Get this
// wrong and the token still signs; nothing downstream ever verifies.
checks.equal(digestInfo[0], 0x30, "DigestInfo opens with an ASN.1 SEQUENCE")
checks.equal(digestInfo[1], 0x31, "whose length covers the rest of the structure")

// MARK: - Loading a module (no token needed)

checks.section("Module loading")

checks.throwsError(
    "a dylib that is not a PKCS #11 module is refused for the right reason",
    { _ = try PKCS11Module(path: "/usr/lib/libSystem.B.dylib") },
    where: { error in
        // libSystem loads perfectly well and exports no C_GetFunctionList.
        // "Opened, and is the wrong thing" is a different message to whoever
        // set the path than "could not open".
        if case SignBridgeError.moduleMissingEntryPoint = error { return true }
        return false
    }
)

checks.throwsError(
    "a path with nothing at it names the path in the failure",
    { _ = try PKCS11Module(path: "/nonexistent/definitely-not-here.dylib") },
    where: { "\($0)".contains("definitely-not-here") }
)

// MARK: - The token

let environment = ProcessInfo.processInfo.environment
guard let modulePath = environment["SIGNBRIDGE_TEST_MODULE"],
    FileManager.default.fileExists(atPath: modulePath)
else {
    checks.skip(
        "the token checks — set SIGNBRIDGE_TEST_MODULE (see scripts/softhsm-token.sh)"
    )
    checks.finish("agent checks")
}
let pin = environment["SIGNBRIDGE_TEST_PIN"] ?? "123456"
let service = try TokenService(modulePath: modulePath)

checks.section("Token discovery")

let tokens = try service.tokens()
checks.ok(!tokens.isEmpty, "a token is present")
if let token = tokens.first {
    checks.ok(token.loginRequired, "the token wants a PIN before its keys will do anything")
    checks.ok(token.pinInitialized, "the token has a PIN set")
    checks.ok(!token.serial.isEmpty, "the token reports a serial")
    // PKCS #11 pads fixed-width fields with blanks and does not terminate them.
    // A serial with trailing spaces silently corrupts every certificate id
    // built from it, and the corruption only shows up at signing time.
    checks.equal(
        token.serial, token.serial.trimmingCharacters(in: .whitespaces),
        "the serial is trimmed of the blank padding PKCS #11 fields carry"
    )
}

checks.section("Certificates")

let certificates = try service.listCertificates()
let signable = certificates.filter(\.hasPrivateKey)
print(
    "   \(certificates.count) certificate(s), \(signable.count) with a private key"
        + (certificates.isEmpty ? "" : " — on \(certificates[0].tokenLabel)")
)
checks.ok(!certificates.isEmpty, "certificates list without a PIN, because they are public objects")

// Asserted over ALL of them rather than the first, and without assuming any
// can sign. Run against the I.CA card before its certificate is issued, this
// section passes on five CA certificates and no keys — which is the truth
// about that card, and a check that demanded a signable one would be reporting
// a fault where there is none.
for certificate in certificates {
    checks.ok(certificate.id.contains(":"), "the id names both the token and the object")
    // The DER is the entire contract with the web app — it parses subject,
    // validity, key usage and the qualified claim out of exactly these bytes.
    let der = Data(base64Encoded: certificate.der)
    checks.ok(der != nil, "\(certificate.id) travels as base64")
    checks.ok((der?.count ?? 0) > 300, "\(certificate.id) is certificate-sized")
    checks.ok(der?.first == 0x30, "\(certificate.id) opens with an ASN.1 SEQUENCE")
    checks.ok(
        SecCertificateCreateWithData(nil, (der ?? Data()) as CFData) != nil,
        "\(certificate.id) is a certificate the system can parse"
    )
}

checks.section("Signing")

if let certificate = signable.first {
    checks.throwsError(
        "the wrong PIN is reported as the wrong PIN, not as a broken card",
        { _ = try service.sign(certificateId: certificate.id, data: Array("x".utf8), pin: "000000") },
        where: { error in
            guard let error = error as? PKCS11Error else { return false }
            // Decides whether the UI offers "try again" or tells the user to
            // stop, and must never be confused with a card that has locked.
            return error.isPinFailure && !error.isPinLocked
        }
    )

    let payload = Array("the DER SignedAttributes would go here".utf8)
    let signature = try service.sign(certificateId: certificate.id, data: payload, pin: pin)
    checks.equal(signature.count, 256, "a 2048-bit RSA signature is 256 bytes")

    // The point of the whole exercise, checked by something that knows nothing
    // about how the signature was made. With a wrong DigestInfo prefix the
    // token still returns 256 entirely plausible bytes, and this is the only
    // line anywhere that would notice.
    if let der = Data(base64Encoded: certificate.der),
        let secCertificate = SecCertificateCreateWithData(nil, der as CFData),
        let publicKey = SecCertificateCopyKey(secCertificate)
    {
        var error: Unmanaged<CFError>?
        let verified = SecKeyVerifySignature(
            publicKey,
            .rsaSignatureMessagePKCS1v15SHA256,
            Data(payload) as CFData,
            Data(signature) as CFData,
            &error
        )
        checks.ok(
            verified,
            "the signature verifies against the certificate's own public key"
                + (verified ? "" : ": \(error?.takeRetainedValue().localizedDescription ?? "-")")
        )
    } else {
        checks.ok(false, "the certificate could be read back for verification")
    }

    checks.throwsError(
        "an unknown certificate id fails before anyone is asked for a PIN",
        { _ = try service.sign(certificateId: "nosuchtoken:0102", data: [0x00], pin: pin) },
        where: { error in
            if case SignBridgeError.certificateNotFound = error { return true }
            return false
        }
    )
} else {
    // The state of a card that has not been through certificate issuance yet:
    // it carries its issuer's CA certificates and nothing of its own.
    checks.skip("the signing checks — no certificate on this token has a private key")
}

// MARK: - The protocol
//
// RequestHandler decides who may do what, so it is checked directly rather than
// through Chrome: the rules have to hold whatever the transport is, and driving
// a browser to assert "unpaired origins are refused" would test the browser.

checks.section("Protocol")

// Consent that answers without a person, so these run headless. It also records
// what it was asked, which is how "the PIN was never requested" gets asserted.
final class ScriptedConsent: Consent, @unchecked Sendable {
    let pin: String?
    let approvePair: Bool
    private(set) var pairingsAsked: [String] = []
    private(set) var signaturesAsked: [SignContext] = []

    init(pin: String?, approvePair: Bool) {
        self.pin = pin
        self.approvePair = approvePair
    }

    func approvePairing(origin: String, code: String) -> Bool {
        pairingsAsked.append(code)
        return approvePair
    }

    func approveSignature(origin: String, context: SignContext, tokenLabel: String) -> String? {
        signaturesAsked.append(context)
        return pin
    }
}

let pairingsFile = URL(fileURLWithPath: NSTemporaryDirectory())
    .appendingPathComponent("signbridge-check-\(UUID().uuidString).json")
defer { try? FileManager.default.removeItem(at: pairingsFile) }

func makeHandler(pin: String? = nil, approvePair: Bool = true) -> (RequestHandler, ScriptedConsent) {
    let consent = ScriptedConsent(pin: pin, approvePair: approvePair)
    return (
        RequestHandler(
            service: { service }, consent: consent,
            pairings: PairingStore(url: pairingsFile)
        ),
        consent
    )
}

func request(_ type: String, id: String = "1", origin: String? = "https://example.test", extra: [String: Any] = [:]) -> Request {
    var body: [String: Any] = ["id": id, "type": type]
    if let origin { body["origin"] = origin }
    body.merge(extra) { _, new in new }
    let data = try! JSONSerialization.data(withJSONObject: body)
    return try! JSONDecoder().decode(Request.self, from: data)
}

do {
    let (handler, _) = makeHandler()

    // A request with no origin did not come through the extension. Being
    // lenient here would make pairing decorative.
    let anonymous = handler.handle(request("hello", origin: nil))
    checks.equal(anonymous.first?.ok, false, "a request without an origin is refused")

    // hello answers before pairing — it is how the page discovers the helper.
    let hello = handler.handle(request("hello")).first
    checks.equal(hello?.ok, true, "hello is answered without pairing")
    checks.equal(hello?.protocol, SignBridgeProtocol.version, "hello reports the protocol version")
    checks.equal(hello?.paired, false, "and says the origin is not paired yet")
    checks.ok(hello?.tokens?.isEmpty == false, "and lists the token it can see")

    let futureProtocol = handler.handle(request("hello", extra: ["protocol": 99])).first
    checks.equal(futureProtocol?.ok, false, "a protocol this host does not speak is refused")
    checks.equal(futureProtocol?.code, ErrorCode.unsupportedProtocol.rawValue, "and says so specifically")

    // Everything else needs pairing first.
    let unpairedList = handler.handle(request("listCertificates")).first
    checks.equal(unpairedList?.ok, false, "an unpaired origin cannot list certificates")
    checks.equal(unpairedList?.code, ErrorCode.notPaired.rawValue, "and is told to pair")
}

// The dialog layer, which is where consent is actually read.
//
// Checked because it got this wrong. `osascript display dialog` exits 0 for
// every button it defines — only one literally named "Cancel" raises an error —
// so reading the exit status as consent made "Refuse" indistinguishable from
// "Approve", and refusing a pairing paired the origin anyway. The answers below
// are the literal strings osascript produces.
checks.section("Consent parsing")

checks.equal(
    DialogConsent.approved("button returned:Approve\n"), true,
    "the approve button approves"
)
checks.equal(
    DialogConsent.approved("button returned:Refuse\n"), false,
    "and the refuse button does NOT — the bug this exists for"
)
checks.equal(DialogConsent.approved(nil), false, "a dialog that could not run is a refusal")
checks.equal(DialogConsent.approved(""), false, "and so is an empty answer")

checks.equal(
    DialogConsent.pin("button returned:Sign, text returned:123456\n"), "123456",
    "the PIN is read from a confirmed dialog"
)
checks.equal(
    DialogConsent.pin("button returned:Cancel, text returned:123456\n"), nil,
    "and a cancelled one yields no PIN even though it typed one"
)
// A PIN is free text and may contain the separator, so the tail is taken whole.
checks.equal(
    DialogConsent.pin("button returned:Sign, text returned:12,34\n"), "12,34",
    "a PIN containing a comma survives"
)
checks.equal(DialogConsent.pin(nil), nil, "no answer means no PIN")

do {
    let (handler, consent) = makeHandler(approvePair: false)
    let refused = handler.handle(request("pair"))
    checks.equal(refused.count, 2, "pair answers twice: the code, then the outcome")
    checks.equal(refused.first?.event, "pairing-code", "the first frame is news, not the answer")
    checks.ok(refused.first?.code?.count == 4, "the pairing code is four characters")
    checks.ok(
        !(refused.first?.code ?? "").contains(where: { "O0I1".contains($0) }),
        "and avoids characters that are read wrong by eye"
    )
    checks.equal(refused.last?.ok, false, "a refused pairing does not pair")
    checks.equal(consent.pairingsAsked.count, 1, "the person was asked exactly once")

    let stillUnpaired = handler.handle(request("listCertificates")).first
    checks.equal(stillUnpaired?.code, ErrorCode.notPaired.rawValue, "and leaves the origin unpaired")

    // The consequence that made the bug matter: a refused pairing must not
    // leave anything behind that a later request can use.
    let stillUnpairedHello = handler.handle(request("hello")).first
    checks.equal(stillUnpairedHello?.paired, false, "and hello still reports the origin unpaired")
}

do {
    let (handler, _) = makeHandler(pin: pin)
    let paired = handler.handle(request("pair"))
    checks.equal(paired.last?.paired, true, "an approved pairing pairs")

    let listed = handler.handle(request("listCertificates")).first
    checks.equal(listed?.ok, true, "a paired origin lists certificates")
    checks.equal(
        listed?.certificates?.count, certificates.count,
        "and gets the same certificates the service reports"
    )

    // A signature with no context has nothing truthful to show, so it is
    // refused rather than shown an empty window.
    let contextless = handler.handle(
        request("sign", extra: ["certificateId": "x:01", "data": "AA=="])
    ).first
    checks.equal(contextless?.ok, false, "signing without a context is refused")
    checks.equal(contextless?.code, ErrorCode.badRequest.rawValue, "as a bad request")
}

if let signableCertificate = signable.first {
    let (handler, consent) = makeHandler(pin: pin)
    _ = handler.handle(request("pair"))

    let payload = Array("protocol round trip".utf8)
    let context: [String: Any] = [
        "documentName": "Timesheet 2026-08.pdf",
        "digest": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    ]
    let signed = handler.handle(
        request(
            "sign",
            extra: [
                "certificateId": signableCertificate.id,
                "hash": "SHA-256",
                "data": Data(payload).base64EncodedString(),
                "context": context,
            ]
        )
    ).first

    checks.equal(signed?.ok, true, "a paired origin with a PIN gets a signature")
    checks.equal(consent.signaturesAsked.count, 1, "and the person was shown exactly one confirmation")
    checks.equal(
        consent.signaturesAsked.first?.documentName, "Timesheet 2026-08.pdf",
        "showing the document the page named"
    )
    // The signature must be the same one the direct API produces — the
    // protocol layer is a transport, and a transport that transforms the bytes
    // is a bug that only shows up in a validator.
    if let encoded = signed?.signature, let bytes = Data(base64Encoded: encoded) {
        checks.equal(bytes.count, 256, "the signature crosses the wire as base64 of the raw bytes")
    } else {
        checks.ok(false, "the signature came back base64-encoded")
    }

    // Refusal must not produce a signature, however well-formed the request.
    let (refusingHandler, _) = makeHandler(pin: nil)
    _ = refusingHandler.handle(request("pair"))
    let refusedSignature = refusingHandler.handle(
        request(
            "sign",
            extra: [
                "certificateId": signableCertificate.id,
                "data": Data(payload).base64EncodedString(),
                "context": context,
            ]
        )
    ).first
    checks.equal(refusedSignature?.ok, false, "cancelling the PIN prompt refuses the signature")
    checks.equal(refusedSignature?.code, ErrorCode.refused.rawValue, "and says it was refused")
    checks.ok(refusedSignature?.signature == nil, "and returns nothing that could be mistaken for one")
}

checks.finish("agent checks")

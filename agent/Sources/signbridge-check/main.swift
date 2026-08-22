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

checks.finish("agent checks")

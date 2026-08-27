import CPKCS11
import Foundation

/// A certificate on a token, as it crosses the wire.
///
/// Deliberately raw. The agent reports the DER and whether a private key sits
/// beside it, and nothing else: subject, issuer, validity, key usage and
/// whether the certificate claims to be qualified are all read from the DER by
/// the web app, which already carries an ASN.1 stack for building the CMS. One
/// implementation of "is this qualified", in the language where it can be
/// tested against fixtures, rather than a second one here that could disagree.
public struct TokenCertificate: Codable, Sendable, Equatable {
    /// Stable for as long as the card is in the reader; what `sign` selects on.
    public let id: String
    /// Base64 DER.
    public let der: String
    /// False for a CA certificate the card carries for path building — listed,
    /// because hiding them makes an empty card indistinguishable from a broken
    /// one, but never signable.
    public let hasPrivateKey: Bool
    public let tokenSerial: String
    public let tokenLabel: String
}

/// The card, as the protocol layer sees it.
///
/// Every method opens its own session and closes it again. A long-lived
/// session would mean a long-lived login, and the design rule is that a PIN
/// authorises one signature (see `sign`).
public final class TokenService: @unchecked Sendable {
    private let module: PKCS11Module

    public init(module: PKCS11Module) {
        self.module = module
    }

    public convenience init(modulePath: String = PKCS11Module.secureStorePath) throws {
        self.init(module: try PKCS11Module(path: modulePath))
    }

    /// Release the card before the process leaves. See `PKCS11Module.finalize()`.
    public func finalize() {
        module.finalize()
    }

    public func tokens() throws -> [TokenInfo] {
        try module.usableSlots().compactMap { try? module.tokenInfo(slot: $0) }
    }

    /// Every certificate on every present token.
    ///
    /// No login: certificates are public objects, so this runs without a PIN.
    /// Private KEYS are not public, which is why `hasPrivateKey` is decided by
    /// matching CKA_ID against the public key objects rather than by looking
    /// for the private key itself — asking for that without a login would
    /// report nothing on a card that has one.
    public func listCertificates() throws -> [TokenCertificate] {
        var result: [TokenCertificate] = []
        for slot in try module.usableSlots() {
            // A slot that fails midway is skipped rather than fatal: with two
            // readers attached, the answer for a working card must not depend
            // on the state of the other one.
            guard let info = try? module.tokenInfo(slot: slot),
                let session = try? module.openSession(slot: slot)
            else { continue }

            let publicKeyIds = Set(
                try session.findObjects([attribute(CKA_CLASS, objectClass: CKO_PUBLIC_KEY)])
                    .compactMap { try session.attribute(CKA_ID, of: $0) }
                    .map(hex)
            )

            for object in try session.findObjects([attribute(CKA_CLASS, objectClass: CKO_CERTIFICATE)]) {
                guard let der = try session.attribute(CKA_VALUE, of: object) else { continue }
                let ckaId = try session.attribute(CKA_ID, of: object).map(hex) ?? ""
                result.append(
                    TokenCertificate(
                        id: "\(info.serial):\(ckaId)",
                        der: Data(der).base64EncodedString(),
                        hasPrivateKey: publicKeyIds.contains(ckaId),
                        tokenSerial: info.serial,
                        tokenLabel: info.label
                    )
                )
            }
        }
        return result
    }

    /// Sign `data` with the key belonging to `certificateId`.
    ///
    /// `data` is whatever the caller wants signed — for PAdES, the DER
    /// SignedAttributes. It is hashed here and wrapped as a DigestInfo; the
    /// token never sees the document.
    ///
    /// The PIN is used for this one call. Logging out afterwards is what makes
    /// "the PIN is the consent" true rather than aspirational: a second
    /// signature costs a second PIN, so a page that asks twice asks the person
    /// twice.
    public func sign(certificateId: String, data: [UInt8], pin: String) throws -> [UInt8] {
        let (slot, ckaId) = try locate(certificateId: certificateId)
        let session = try module.openSession(slot: slot)
        try session.login(pin: pin)
        defer { session.logout() }

        let keys = try session.findObjects([
            attribute(CKA_CLASS, objectClass: CKO_PRIVATE_KEY),
            attribute(CKA_ID, bytes: unhex(ckaId)),
        ])
        guard let key = keys.first else {
            throw SignBridgeError.privateKeyNotFound(certificateId: certificateId)
        }
        return try session.sign(data: DigestInfo.sha256(over: data), key: key)
    }

    /// Which slot holds `certificateId`, and the CKA_ID within it.
    private func locate(certificateId: String) throws -> (CK_SLOT_ID, String) {
        let parts = certificateId.split(separator: ":", maxSplits: 1).map(String.init)
        guard parts.count == 2 else { throw SignBridgeError.certificateNotFound(id: certificateId) }
        for slot in try module.usableSlots() where (try? module.tokenInfo(slot: slot))?.serial == parts[0] {
            return (slot, parts[1])
        }
        throw SignBridgeError.certificateNotFound(id: certificateId)
    }
}

// MARK: - Attribute helpers
//
// CK_ATTRIBUTE points at caller-owned memory, so anything built here has to
// outlive the call that uses it. These allocate and never free, which is only
// acceptable because each is a handful of bytes used for the length of one
// find — the alternative is threading `withUnsafePointer` nests through every
// call site for no benefit.

private func attribute(_ type: CK_ATTRIBUTE_TYPE, objectClass: CK_OBJECT_CLASS) -> CK_ATTRIBUTE {
    let value = UnsafeMutablePointer<CK_OBJECT_CLASS>.allocate(capacity: 1)
    value.pointee = objectClass
    return CK_ATTRIBUTE(
        type: type,
        pValue: UnsafeMutableRawPointer(value),
        ulValueLen: CK_ULONG(MemoryLayout<CK_OBJECT_CLASS>.size)
    )
}

private func attribute(_ type: CK_ATTRIBUTE_TYPE, bytes: [UInt8]) -> CK_ATTRIBUTE {
    let value = UnsafeMutablePointer<UInt8>.allocate(capacity: max(bytes.count, 1))
    value.update(from: bytes, count: bytes.count)
    return CK_ATTRIBUTE(
        type: type,
        pValue: UnsafeMutableRawPointer(value),
        ulValueLen: CK_ULONG(bytes.count)
    )
}

private func hex(_ bytes: [UInt8]) -> String {
    bytes.map { String(format: "%02x", $0) }.joined()
}

private func unhex(_ string: String) -> [UInt8] {
    var bytes: [UInt8] = []
    var index = string.startIndex
    while index < string.endIndex, let next = string.index(index, offsetBy: 2, limitedBy: string.endIndex) {
        if let byte = UInt8(string[index..<next], radix: 16) { bytes.append(byte) }
        index = next
    }
    return bytes
}

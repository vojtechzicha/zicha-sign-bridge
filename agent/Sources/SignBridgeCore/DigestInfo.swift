import CryptoKit
import Foundation

/// The DigestInfo an RSA PKCS #1 v1.5 signature is actually computed over.
///
/// `CKM_RSA_PKCS` signs whatever bytes it is given after padding them — it does
/// not know what a hash is. RFC 8017 says those bytes must be a DER DigestInfo:
///
///     DigestInfo ::= SEQUENCE { digestAlgorithm AlgorithmIdentifier, digest OCTET STRING }
///
/// For SHA-256 the encoding is entirely fixed except for the 32 hash bytes, so
/// the prefix is a constant rather than something worth an ASN.1 encoder. Get
/// this wrong and the token still returns a signature — one that verifies
/// nowhere, which is the failure mode worth having a test for.
public enum DigestInfo {
    /// SEQUENCE { SEQUENCE { OID 2.16.840.1.101.3.4.2.1, NULL }, OCTET STRING (32) }
    public static let sha256Prefix: [UInt8] = [
        0x30, 0x31,
        0x30, 0x0d,
        0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        0x05, 0x00,
        0x04, 0x20,
    ]

    /// Hash `data` with SHA-256 and wrap it ready for `CKM_RSA_PKCS`.
    public static func sha256(over data: [UInt8]) -> [UInt8] {
        sha256Prefix + Array(SHA256.hash(data: data))
    }
}

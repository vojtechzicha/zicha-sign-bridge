import Foundation

/// The wire types of protocol/protocol.md.
///
/// Codable structs rather than dictionaries so that a field renamed on one side
/// fails to compile on this one — the protocol document is the contract, and
/// these are it in a form the compiler can hold.
public enum SignBridgeProtocol {
    public static let version = 1
    public static let hostVersion = "0.1.0"
}

public struct Request: Decodable, Sendable {
    public let id: String
    public let type: String
    public let `protocol`: Int?
    public let certificateId: String?
    public let hash: String?
    /// Base64 of the bytes to sign.
    public let data: String?
    public let context: SignContext?
    /// Attached by the extension, never by the page: the browser tells the
    /// extension who is calling and the extension passes that on. A page
    /// cannot set it, which is what makes pairing mean anything.
    public let origin: String?
}

public struct SignContext: Codable, Sendable {
    public let documentName: String
    /// Hex SHA-256 of the document, shown so approval is tied to a document
    /// rather than to the page's description of one.
    public let digest: String

    public init(documentName: String, digest: String) {
        self.documentName = documentName
        self.digest = digest
    }
}

public struct Response: Encodable, Sendable {
    public let id: String
    public let ok: Bool
    public var `protocol`: Int?
    public var hostVersion: String?
    public var paired: Bool?
    public var tokens: [TokenInfo]?
    public var certificates: [TokenCertificate]?
    public var signature: String?
    public var code: String?
    public var message: String?

    public static func ok(_ id: String) -> Response { Response(id: id, ok: true) }

    public static func failure(_ id: String, _ code: ErrorCode, _ message: String) -> Response {
        var response = Response(id: id, ok: false)
        response.code = code.rawValue
        response.message = message
        return response
    }
}

public enum ErrorCode: String, Sendable {
    case unsupportedProtocol = "unsupported_protocol"
    case notPaired = "not_paired"
    case refused
    case noToken = "no_token"
    case notFound = "not_found"
    case noPrivateKey = "no_private_key"
    case pinFailed = "pin_failed"
    case pinLocked = "pin_locked"
    case tokenError = "token_error"
    case badRequest = "bad_request"

    /// How a PKCS #11 failure reaches the page.
    ///
    /// `pinFailed` and `pinLocked` are kept apart all the way to the UI: the
    /// first means "try again", the second means "stop", and a caller that
    /// retries the second locks the card for good.
    public static func from(_ error: Error) -> (ErrorCode, String) {
        if let error = error as? PKCS11Error {
            if error.isPinLocked { return (.pinLocked, error.description) }
            if error.isPinFailure { return (.pinFailed, error.description) }
            return (.tokenError, error.description)
        }
        if let error = error as? SignBridgeError {
            switch error {
            case .noTokenPresent: return (.noToken, error.description)
            case .certificateNotFound: return (.notFound, error.description)
            case .privateKeyNotFound: return (.noPrivateKey, error.description)
            default: return (.tokenError, error.description)
            }
        }
        return (.tokenError, "\(error)")
    }
}

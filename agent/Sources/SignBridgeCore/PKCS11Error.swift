import CPKCS11
import Foundation

/// A PKCS #11 call that did not return CKR_OK.
///
/// The numeric code is kept because it is the only thing that survives across a
/// vendor's documentation, and the name because a log line reading
/// "CKR_PIN_INCORRECT" is worth a great deal more than "0x000000A0".
public struct PKCS11Error: Error, CustomStringConvertible, Sendable {
    public let function: String
    public let code: CK_RV

    public var name: String { PKCS11Error.names[code] ?? String(format: "CKR_0x%08X", code) }
    public var description: String { "\(function) failed: \(name)" }

    /// True when the user got their PIN wrong, as opposed to anything else —
    /// the one failure that deserves "try again" rather than "something broke".
    public var isPinFailure: Bool {
        code == CK_RV(CKR_PIN_INCORRECT) || code == CK_RV(CKR_PIN_INVALID)
            || code == CK_RV(CKR_PIN_LEN_RANGE)
    }

    /// True when the card has locked itself. Retrying makes this worse.
    public var isPinLocked: Bool {
        code == CK_RV(CKR_PIN_LOCKED) || code == CK_RV(CKR_USER_PIN_NOT_INITIALIZED)
    }

    static func check(_ function: String, _ rv: CK_RV) throws {
        guard rv == CK_RV(CKR_OK) else { throw PKCS11Error(function: function, code: rv) }
    }

    // Only the codes this agent can actually provoke. A module is free to
    // return anything, which is what the hex fallback above is for.
    private static let names: [CK_RV: String] = [
        CK_RV(CKR_OK): "CKR_OK",
        CK_RV(CKR_CANCEL): "CKR_CANCEL",
        CK_RV(CKR_HOST_MEMORY): "CKR_HOST_MEMORY",
        CK_RV(CKR_SLOT_ID_INVALID): "CKR_SLOT_ID_INVALID",
        CK_RV(CKR_GENERAL_ERROR): "CKR_GENERAL_ERROR",
        CK_RV(CKR_FUNCTION_FAILED): "CKR_FUNCTION_FAILED",
        CK_RV(CKR_ARGUMENTS_BAD): "CKR_ARGUMENTS_BAD",
        CK_RV(CKR_ATTRIBUTE_TYPE_INVALID): "CKR_ATTRIBUTE_TYPE_INVALID",
        CK_RV(CKR_ATTRIBUTE_VALUE_INVALID): "CKR_ATTRIBUTE_VALUE_INVALID",
        CK_RV(CKR_DATA_INVALID): "CKR_DATA_INVALID",
        CK_RV(CKR_DATA_LEN_RANGE): "CKR_DATA_LEN_RANGE",
        CK_RV(CKR_DEVICE_ERROR): "CKR_DEVICE_ERROR",
        CK_RV(CKR_DEVICE_MEMORY): "CKR_DEVICE_MEMORY",
        CK_RV(CKR_DEVICE_REMOVED): "CKR_DEVICE_REMOVED",
        CK_RV(CKR_FUNCTION_CANCELED): "CKR_FUNCTION_CANCELED",
        CK_RV(CKR_KEY_HANDLE_INVALID): "CKR_KEY_HANDLE_INVALID",
        CK_RV(CKR_KEY_TYPE_INCONSISTENT): "CKR_KEY_TYPE_INCONSISTENT",
        CK_RV(CKR_MECHANISM_INVALID): "CKR_MECHANISM_INVALID",
        CK_RV(CKR_MECHANISM_PARAM_INVALID): "CKR_MECHANISM_PARAM_INVALID",
        CK_RV(CKR_OPERATION_NOT_INITIALIZED): "CKR_OPERATION_NOT_INITIALIZED",
        CK_RV(CKR_PIN_INCORRECT): "CKR_PIN_INCORRECT",
        CK_RV(CKR_PIN_INVALID): "CKR_PIN_INVALID",
        CK_RV(CKR_PIN_LEN_RANGE): "CKR_PIN_LEN_RANGE",
        CK_RV(CKR_PIN_LOCKED): "CKR_PIN_LOCKED",
        CK_RV(CKR_SESSION_CLOSED): "CKR_SESSION_CLOSED",
        CK_RV(CKR_SESSION_HANDLE_INVALID): "CKR_SESSION_HANDLE_INVALID",
        CK_RV(CKR_SESSION_READ_ONLY): "CKR_SESSION_READ_ONLY",
        CK_RV(CKR_SIGNATURE_INVALID): "CKR_SIGNATURE_INVALID",
        CK_RV(CKR_TEMPLATE_INCOMPLETE): "CKR_TEMPLATE_INCOMPLETE",
        CK_RV(CKR_TOKEN_NOT_PRESENT): "CKR_TOKEN_NOT_PRESENT",
        CK_RV(CKR_TOKEN_NOT_RECOGNIZED): "CKR_TOKEN_NOT_RECOGNIZED",
        CK_RV(CKR_USER_ALREADY_LOGGED_IN): "CKR_USER_ALREADY_LOGGED_IN",
        CK_RV(CKR_USER_NOT_LOGGED_IN): "CKR_USER_NOT_LOGGED_IN",
        CK_RV(CKR_USER_PIN_NOT_INITIALIZED): "CKR_USER_PIN_NOT_INITIALIZED",
        CK_RV(CKR_USER_TYPE_INVALID): "CKR_USER_TYPE_INVALID",
        CK_RV(CKR_CRYPTOKI_ALREADY_INITIALIZED): "CKR_CRYPTOKI_ALREADY_INITIALIZED",
        CK_RV(CKR_CRYPTOKI_NOT_INITIALIZED): "CKR_CRYPTOKI_NOT_INITIALIZED",
    ]
}

/// Something wrong on our side of the boundary rather than the module's.
public enum SignBridgeError: Error, CustomStringConvertible, Sendable {
    case moduleNotLoaded(path: String, reason: String)
    case moduleMissingEntryPoint(path: String)
    case noTokenPresent
    case certificateNotFound(id: String)
    case privateKeyNotFound(certificateId: String)
    case unsupportedKeyType

    public var description: String {
        switch self {
        case .moduleNotLoaded(let path, let reason):
            return "Could not load the PKCS #11 module at \(path): \(reason)"
        case .moduleMissingEntryPoint(let path):
            return "\(path) is not a PKCS #11 module — it has no C_GetFunctionList."
        case .noTokenPresent:
            return "No token is present in any slot."
        case .certificateNotFound(let id):
            return "No certificate \(id) on this token."
        case .privateKeyNotFound(let certificateId):
            return "Certificate \(certificateId) has no private key on this token."
        case .unsupportedKeyType:
            return "Only RSA keys can sign here."
        }
    }
}

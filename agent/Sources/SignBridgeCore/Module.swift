import CPKCS11
import Foundation

/// A loaded PKCS #11 module.
///
/// One instance per dylib, holding the function list every call goes through.
/// `dlopen` is the reason the shipped agent needs
/// `com.apple.security.cs.disable-library-validation`: the module is a
/// third-party library signed by someone else, and a hardened process refuses
/// to map one without that entitlement. Fortify died of exactly this.
public final class PKCS11Module: @unchecked Sendable {
    public let path: String
    private let handle: UnsafeMutableRawPointer
    let functions: CK_FUNCTION_LIST

    /// Where SecureStore installs itself. The default rather than a hardcoded
    /// constant: tests point at SoftHSM, and nothing else about the agent
    /// changes between the two.
    public static let secureStorePath = "/usr/local/lib/pkcs11/libICASecureStorePkcs11.dylib"

    public init(path: String) throws {
        self.path = path

        // RTLD_LOCAL: two modules may both export C_GetFunctionList, and a
        // global namespace would let whichever loaded first answer for both.
        guard let handle = dlopen(path, RTLD_NOW | RTLD_LOCAL) else {
            let reason = dlerror().map { String(cString: $0) } ?? "dlopen gave no reason"
            throw SignBridgeError.moduleNotLoaded(path: path, reason: reason)
        }
        self.handle = handle

        guard let symbol = dlsym(handle, "C_GetFunctionList") else {
            dlclose(handle)
            throw SignBridgeError.moduleMissingEntryPoint(path: path)
        }
        typealias GetFunctionList = @convention(c) (UnsafeMutablePointer<CK_FUNCTION_LIST_PTR?>?) -> CK_RV
        let getFunctionList = unsafeBitCast(symbol, to: GetFunctionList.self)

        var list: CK_FUNCTION_LIST_PTR?
        try PKCS11Error.check("C_GetFunctionList", getFunctionList(&list))
        guard let list else {
            dlclose(handle)
            throw SignBridgeError.moduleMissingEntryPoint(path: path)
        }
        self.functions = list.pointee

        // CKF_OS_LOCKING_OK: the module may use OS threading primitives. The
        // agent serialises its own calls anyway, but a module that insists on
        // locking support refuses to initialise without this.
        var args = CK_C_INITIALIZE_ARGS()
        args.flags = CK_FLAGS(CKF_OS_LOCKING_OK)
        let rv = withUnsafeMutablePointer(to: &args) { functions.C_Initialize!($0) }
        // Another component in this process may have got there first, which is
        // success as far as we are concerned.
        if rv != CK_RV(CKR_CRYPTOKI_ALREADY_INITIALIZED) {
            do {
                try PKCS11Error.check("C_Initialize", rv)
            } catch {
                dlclose(handle)
                throw error
            }
        }
    }

    deinit {
        _ = functions.C_Finalize?(nil)
        dlclose(handle)
    }

    /// Close the module's own view of the reader, without unloading it.
    ///
    /// Separate from `deinit` because the two halves cannot both be done on
    /// the way out: SecureStore's dylib destructor joins a heartbeat thread
    /// that only C_Finalize stops, so `dlclose` — and `exit`, which runs the
    /// same destructor — hang forever on a module that is still initialised.
    /// The host calls this and then leaves by `_exit` (see signbridge-host),
    /// which is the one ordering that both releases the card and terminates.
    public func finalize() {
        _ = functions.C_Finalize?(nil)
    }

    /// Slots holding a token that is actually usable — present, initialised,
    /// and willing to answer C_GetTokenInfo.
    ///
    /// `C_GetSlotList(tokenPresent: TRUE)` is not the same question. SoftHSM
    /// advertises a spare slot with an uninitialised token in it, and a reader
    /// holding an unformatted or unreadable card does the same; opening a
    /// session on either fails with CKR_TOKEN_NOT_RECOGNIZED. Filtering here
    /// means one bad card in a second reader cannot take the good one down
    /// with it.
    public func usableSlots() throws -> [CK_SLOT_ID] {
        try rawSlotsWithToken().filter { slot in
            guard let info = try? tokenInfo(slot: slot) else { return false }
            return info.initialized
        }
    }

    /// Every slot reporting a token, usable or not. `usableSlots()` is what
    /// callers want; this is what the standard hands back.
    func rawSlotsWithToken() throws -> [CK_SLOT_ID] {
        var count: CK_ULONG = 0
        try PKCS11Error.check("C_GetSlotList", functions.C_GetSlotList!(CK_BBOOL(CK_TRUE), nil, &count))
        guard count > 0 else { return [] }
        var slots = [CK_SLOT_ID](repeating: 0, count: Int(count))
        try PKCS11Error.check("C_GetSlotList", functions.C_GetSlotList!(CK_BBOOL(CK_TRUE), &slots, &count))
        return Array(slots.prefix(Int(count)))
    }

    public func tokenInfo(slot: CK_SLOT_ID) throws -> TokenInfo {
        var info = CK_TOKEN_INFO()
        try PKCS11Error.check("C_GetTokenInfo", functions.C_GetTokenInfo!(slot, &info))
        return TokenInfo(info)
    }

    /// Open a read-only session. Login happens separately, per signature.
    public func openSession(slot: CK_SLOT_ID) throws -> PKCS11Session {
        var handle = CK_SESSION_HANDLE(CK_INVALID_HANDLE)
        try PKCS11Error.check(
            "C_OpenSession",
            functions.C_OpenSession!(slot, CK_FLAGS(CKF_SERIAL_SESSION), nil, nil, &handle)
        )
        return PKCS11Session(module: self, handle: handle)
    }
}

/// What the agent reports about a token. Everything a person would use to tell
/// one card from another, and nothing that needs a PIN to read.
public struct TokenInfo: Codable, Sendable, Equatable {
    public let label: String
    public let manufacturer: String
    public let model: String
    public let serial: String
    /// The token demands a PIN before its private keys will do anything.
    public let loginRequired: Bool
    /// Set once a PIN has been established — a blank card reads false.
    public let pinInitialized: Bool
    /// The token has been formatted. A slot advertising an uninitialised token
    /// is a slot no session can be opened on.
    public let initialized: Bool

    init(_ info: CK_TOKEN_INFO) {
        self.label = TokenInfo.text(info.label)
        self.manufacturer = TokenInfo.text(info.manufacturerID)
        self.model = TokenInfo.text(info.model)
        self.serial = TokenInfo.text(info.serialNumber)
        self.loginRequired = info.flags & CK_FLAGS(CKF_LOGIN_REQUIRED) != 0
        self.pinInitialized = info.flags & CK_FLAGS(CKF_USER_PIN_INITIALIZED) != 0
        self.initialized = info.flags & CK_FLAGS(CKF_TOKEN_INITIALIZED) != 0
    }

    /// PKCS #11 fixed-width fields are blank-padded and NOT null-terminated,
    /// and Swift imports them as tuples. Reading one means walking its bytes.
    private static func text<T>(_ field: T) -> String {
        var value = field
        let bytes = withUnsafeBytes(of: &value) { Array($0) }
        return String(decoding: bytes, as: UTF8.self)
            .trimmingCharacters(in: .whitespacesAndNewlines)
    }
}

import CPKCS11
import Foundation

/// One PKCS #11 session. Closed when it goes out of scope.
public final class PKCS11Session {
    private let module: PKCS11Module
    private let handle: CK_SESSION_HANDLE
    private var loggedIn = false

    init(module: PKCS11Module, handle: CK_SESSION_HANDLE) {
        self.module = module
        self.handle = handle
    }

    deinit {
        if loggedIn { _ = module.functions.C_Logout?(handle) }
        _ = module.functions.C_CloseSession?(handle)
    }

    // MARK: - Login

    /// Log in as the user. The PIN is zeroed the moment the call returns,
    /// whether it succeeded or not — it exists in this process for the length
    /// of one C call and no longer.
    public func login(pin: String) throws {
        var bytes = Array(pin.utf8)
        defer { for i in bytes.indices { bytes[i] = 0 } }
        let rv = bytes.withUnsafeMutableBufferPointer { buffer in
            module.functions.C_Login!(handle, CK_USER_TYPE(CKU_USER), buffer.baseAddress, CK_ULONG(buffer.count))
        }
        if rv == CK_RV(CKR_USER_ALREADY_LOGGED_IN) {
            loggedIn = true
            return
        }
        try PKCS11Error.check("C_Login", rv)
        loggedIn = true
    }

    public func logout() {
        guard loggedIn else { return }
        _ = module.functions.C_Logout?(handle)
        loggedIn = false
    }

    // MARK: - Objects

    /// Handles of every object matching a template.
    func findObjects(_ template: [CK_ATTRIBUTE]) throws -> [CK_OBJECT_HANDLE] {
        var template = template
        try PKCS11Error.check(
            "C_FindObjectsInit",
            module.functions.C_FindObjectsInit!(handle, &template, CK_ULONG(template.count))
        )
        defer { _ = module.functions.C_FindObjectsFinal?(handle) }

        var found: [CK_OBJECT_HANDLE] = []
        // A page at a time: a software token can hold a great many objects and
        // C_FindObjects is defined to be called until it stops producing.
        let pageSize = 32
        while true {
            var page = [CK_OBJECT_HANDLE](repeating: 0, count: pageSize)
            var count: CK_ULONG = 0
            try PKCS11Error.check(
                "C_FindObjects",
                module.functions.C_FindObjects!(handle, &page, CK_ULONG(pageSize), &count)
            )
            guard count > 0 else { break }
            found.append(contentsOf: page.prefix(Int(count)))
            if Int(count) < pageSize { break }
        }
        return found
    }

    /// One attribute's raw bytes, or nil when the object does not have it.
    ///
    /// Two calls, as the standard requires: the first asks how long the value
    /// is, the second fetches it. An attribute the object lacks answers
    /// CKR_ATTRIBUTE_TYPE_INVALID, which is an answer rather than a failure.
    func attribute(_ type: CK_ATTRIBUTE_TYPE, of object: CK_OBJECT_HANDLE) throws -> [UInt8]? {
        var probe = CK_ATTRIBUTE(type: type, pValue: nil, ulValueLen: 0)
        let sizeRv = module.functions.C_GetAttributeValue!(handle, object, &probe, 1)
        if sizeRv == CK_RV(CKR_ATTRIBUTE_TYPE_INVALID) || sizeRv == CK_RV(CKR_ATTRIBUTE_SENSITIVE) {
            return nil
        }
        try PKCS11Error.check("C_GetAttributeValue", sizeRv)
        // -1 is the standard's way of saying "this object has no such value".
        guard probe.ulValueLen != CK_ULONG(bitPattern: -1), probe.ulValueLen > 0 else { return nil }

        var buffer = [UInt8](repeating: 0, count: Int(probe.ulValueLen))
        try buffer.withUnsafeMutableBufferPointer { raw in
            var fetch = CK_ATTRIBUTE(
                type: type, pValue: raw.baseAddress, ulValueLen: CK_ULONG(raw.count)
            )
            try PKCS11Error.check(
                "C_GetAttributeValue", module.functions.C_GetAttributeValue!(handle, object, &fetch, 1)
            )
        }
        return buffer
    }

    // MARK: - Signing

    /// Sign `data` with `key` using raw RSA PKCS #1 v1.5.
    ///
    /// Always `CKM_RSA_PKCS`, never `CKM_SHA256_RSA_PKCS`, and deliberately:
    /// the I.CA Starcos 3.74 this exists for offers no combined
    /// digest-and-sign mechanism at all (`pkcs11-tool -M` lists `RSA-PKCS`,
    /// `RSA-PKCS-PSS` and the digests separately). The caller therefore hands
    /// in a finished DigestInfo — see `DigestInfo.sha256` — which is the one
    /// path every token supports, and so the only path worth having and
    /// testing.
    public func sign(data: [UInt8], key: CK_OBJECT_HANDLE) throws -> [UInt8] {
        var mechanism = CK_MECHANISM(mechanism: CK_MECHANISM_TYPE(CKM_RSA_PKCS), pParameter: nil, ulParameterLen: 0)
        try PKCS11Error.check("C_SignInit", module.functions.C_SignInit!(handle, &mechanism, key))

        var data = data
        var length: CK_ULONG = 0
        try data.withUnsafeMutableBufferPointer { input in
            try PKCS11Error.check(
                "C_Sign",
                module.functions.C_Sign!(handle, input.baseAddress, CK_ULONG(input.count), nil, &length)
            )
        }

        var signature = [UInt8](repeating: 0, count: Int(length))
        try data.withUnsafeMutableBufferPointer { input in
            try signature.withUnsafeMutableBufferPointer { output in
                try PKCS11Error.check(
                    "C_Sign",
                    module.functions.C_Sign!(
                        handle, input.baseAddress, CK_ULONG(input.count), output.baseAddress, &length
                    )
                )
            }
        }
        return Array(signature.prefix(Int(length)))
    }
}

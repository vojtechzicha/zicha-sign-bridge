// The native messaging host: what Chrome launches when the extension connects.
//
// It reads framed JSON from stdin, hands each request to RequestHandler, and
// writes the responses back. Nothing else may be written to stdout — that is
// the wire, and a stray line on it corrupts the stream and drops the
// connection with no message anywhere.
//
// One process per browser connection, which is how Chrome works. That is
// tolerable while a session is opened and closed around each operation and the
// PIN authorises exactly one signature; if a card ever objects to two processes
// at once, the fix is to move the token behind a single long-lived agent and
// make this a pipe to it. The protocol does not change either way.

import Foundation
import SignBridgeCore

setvbuf(stderr, nil, _IONBF, 0)

/// Which PKCS #11 module to talk to. SecureStore unless told otherwise, so the
/// checks and a SoftHSM run need no special build.
let modulePath =
    ProcessInfo.processInfo.environment["SIGNBRIDGE_MODULE"] ?? PKCS11Module.secureStorePath

/// Built once, lazily, and kept: dlopen and C_Initialize are not free, and a
/// service that survives between requests keeps the module's view of the reader
/// warm. A failure is reported per request rather than at startup — `hello` has
/// to answer on a machine with no middleware installed at all, because that is
/// precisely the case the page needs to explain to someone.
///
/// A class rather than a top-level `var` because top-level state is
/// main-actor-isolated under Swift 6 and the handler's closure is not. This
/// process reads one message at a time, so there is no contention to protect
/// against — only a compiler to satisfy honestly.
final class LazyTokenService {
    private let modulePath: String
    private var service: TokenService?

    init(modulePath: String) { self.modulePath = modulePath }

    func get() throws -> TokenService {
        if let service { return service }
        let created = try TokenService(modulePath: modulePath)
        service = created
        return created
    }
}

let services = LazyTokenService(modulePath: modulePath)
let handler = RequestHandler(service: { try services.get() }, consent: DialogConsent())
let channel = NativeMessaging()
let decoder = JSONDecoder()
let encoder = JSONEncoder()

FileHandle.standardError.write(
    Data("signbridge-host \(SignBridgeProtocol.hostVersion) using \(modulePath)\n".utf8)
)

while true {
    let message: Data?
    do {
        message = try channel.read()
    } catch {
        FileHandle.standardError.write(Data("read failed: \(error)\n".utf8))
        exit(1)
    }
    // End of stream: the browser closed the port, which is the normal way this
    // process ends.
    guard let message else { break }

    let responses: [Response]
    do {
        responses = handler.handle(try decoder.decode(Request.self, from: message))
    } catch {
        // Undecodable input still gets an answer, because the page is waiting
        // on an id it will never see otherwise. Without the id there is
        // nothing to answer, so the frame is dropped and logged.
        FileHandle.standardError.write(Data("undecodable request: \(error)\n".utf8))
        continue
    }

    for response in responses {
        do {
            try channel.write(try encoder.encode(response))
        } catch {
            FileHandle.standardError.write(Data("write failed: \(error)\n".utf8))
            exit(1)
        }
    }
}

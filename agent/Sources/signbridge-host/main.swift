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

    /// Hand the card back, if we ever took it.
    func release() {
        service?.finalize()
        service = nil
    }
}

let services = LazyTokenService(modulePath: modulePath)

/// The only way out of this process.
///
/// `exit` runs the loaded module's destructors, and SecureStore's joins a
/// heartbeat thread that C_Finalize — and nothing else — stops. Returning from
/// `main` does the same thing by another name. So the card is released first
/// and the process then leaves by `_exit`, which runs no destructor and cannot
/// be held: a host that lingers here holds the card, and the next connection
/// finds a reader that is busy for no reason anyone can see.
@MainActor
func leave(_ code: Int32) -> Never {
    services.release()
    _exit(code)
}
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
        leave(1)
    }
    // End of stream: the browser closed the port, which is the normal way this
    // process ends.
    guard let message else { leave(0) }

    let request: Request
    do {
        request = try decoder.decode(Request.self, from: message)
    } catch {
        // Undecodable input still deserves an answer, because the page is
        // waiting on an id it will otherwise never see. Without the id there
        // is nothing to answer, so the frame is dropped and logged.
        FileHandle.standardError.write(Data("undecodable request: \(error)\n".utf8))
        continue
    }

    // Written as they are produced rather than collected first: `pair` puts its
    // code on the wire and only then opens the window that code is meant to be
    // compared against, and a frame held back until the handler returns arrives
    // after that window has gone.
    var writeFailed = false
    handler.handle(request) { response in
        guard !writeFailed else { return }
        do {
            try channel.write(try encoder.encode(response))
        } catch {
            FileHandle.standardError.write(Data("write failed: \(error)\n".utf8))
            writeFailed = true
        }
    }
    if writeFailed { leave(1) }
}

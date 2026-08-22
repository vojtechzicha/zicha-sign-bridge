import CryptoKit
import Foundation

/// The protocol, applied.
///
/// Every rule about who may do what lives here rather than in the transport, so
/// the same decisions hold whether a request arrived from Chrome, from a test,
/// or from whatever transport replaces native messaging later.
public struct RequestHandler {
    private let service: () throws -> TokenService
    private let consent: Consent
    private let pairings: PairingStore
    /// Deferred: a token service is built by dlopening a module, and a helper
    /// launched with no card in the reader must still be able to answer
    /// `hello` rather than dying at startup.
    public init(
        service: @escaping () throws -> TokenService,
        consent: Consent,
        pairings: PairingStore = PairingStore()
    ) {
        self.service = service
        self.consent = consent
        self.pairings = pairings
    }

    /// Handle one request. Returns every frame to send, in order — `pair` is
    /// the only operation that answers twice.
    public func handle(_ request: Request) -> [Response] {
        // The origin is attached by the extension from what the browser told
        // it. Its absence means the request did not come through the
        // extension, which is not a case to be lenient about.
        guard let origin = request.origin, !origin.isEmpty else {
            return [.failure(request.id, .badRequest, "No origin — this request did not come from the extension.")]
        }

        switch request.type {
        case "hello":
            return [hello(request, origin: origin)]
        case "pair":
            return pair(request, origin: origin)
        case "listCertificates":
            return [requirePairing(request, origin: origin) ?? listCertificates(request)]
        case "sign":
            return [requirePairing(request, origin: origin) ?? sign(request, origin: origin)]
        default:
            return [.failure(request.id, .badRequest, "Unknown request type \"\(request.type)\".")]
        }
    }

    private func requirePairing(_ request: Request, origin: String) -> Response? {
        guard pairings.isPaired(origin) else {
            return .failure(request.id, .notPaired, "\(origin) has not been approved for this token yet.")
        }
        return nil
    }

    // MARK: - Operations

    /// Answered without pairing and without a PIN, because the page calls it
    /// unprompted to find out whether the helper exists. It must stay free of
    /// side effects for that reason.
    private func hello(_ request: Request, origin: String) -> Response {
        guard request.protocol == nil || request.protocol == SignBridgeProtocol.version else {
            return .failure(
                request.id, .unsupportedProtocol,
                "This helper speaks protocol \(SignBridgeProtocol.version)."
            )
        }
        var response = Response.ok(request.id)
        response.protocol = SignBridgeProtocol.version
        response.hostVersion = SignBridgeProtocol.hostVersion
        response.paired = pairings.isPaired(origin)
        // A missing module or an empty reader is reported as no tokens, not as
        // a failure: "the helper is here and sees no card" is a state the page
        // knows how to explain.
        response.tokens = (try? service().tokens()) ?? []
        return response
    }

    private func pair(_ request: Request, origin: String) -> [Response] {
        if pairings.isPaired(origin) {
            var already = Response.ok(request.id)
            already.paired = true
            return [already]
        }
        // Four characters from an unambiguous alphabet — no O/0 or I/1, since
        // the whole job of the code is to be compared by eye.
        let alphabet = Array("ABCDEFGHJKLMNPQRSTUVWXYZ23456789")
        let code = String((0..<4).map { _ in alphabet[Int.random(in: 0..<alphabet.count)] })

        var shown = Response.ok(request.id)
        shown.code = code

        let approved = consent.approvePairing(origin: origin, code: code)
        if approved { pairings.approve(origin) }

        var result = Response.ok(request.id)
        result.paired = approved
        return [
            shown,
            approved ? result : .failure(request.id, .refused, "The pairing was refused."),
        ]
    }

    private func listCertificates(_ request: Request) -> Response {
        do {
            var response = Response.ok(request.id)
            response.certificates = try service().listCertificates()
            return response
        } catch {
            let (code, message) = ErrorCode.from(error)
            return .failure(request.id, code, message)
        }
    }

    private func sign(_ request: Request, origin: String) -> Response {
        guard let certificateId = request.certificateId,
            let encoded = request.data,
            let payload = Data(base64Encoded: encoded)
        else {
            return .failure(request.id, .badRequest, "sign needs certificateId and base64 data.")
        }
        guard request.hash == nil || request.hash == "SHA-256" else {
            return .failure(request.id, .badRequest, "Only SHA-256 is supported.")
        }
        // Refused rather than defaulted: without a context there is nothing
        // truthful to put in the confirmation window, and a window that says
        // nothing is worse than no window at all.
        guard let context = request.context else {
            return .failure(request.id, .badRequest, "sign needs a context to show before signing.")
        }

        do {
            let service = try service()
            let tokenLabel = (try? service.tokens().first?.label) ?? "your token"
            guard
                let pin = consent.approveSignature(
                    origin: origin, context: context, tokenLabel: tokenLabel ?? "your token"
                )
            else {
                return .failure(request.id, .refused, "The signature was refused.")
            }
            let signature = try service.sign(
                certificateId: certificateId, data: Array(payload), pin: pin
            )
            var response = Response.ok(request.id)
            response.signature = Data(signature).base64EncodedString()
            return response
        } catch {
            let (code, message) = ErrorCode.from(error)
            return .failure(request.id, code, message)
        }
    }
}

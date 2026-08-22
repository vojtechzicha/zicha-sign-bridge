import Foundation

/// Everything that needs a person.
///
/// Kept behind a protocol for two reasons: the checks drive the host without a
/// human, and the windows themselves are due to be replaced. `DialogConsent`
/// below shells out to AppleScript, which is honest for a helper that has no
/// bundle to put a window in yet — the menu-bar agent that replaces it changes
/// this file and nothing else.
public protocol Consent: Sendable {
    /// Show `code` and wait. True when the person approves the origin.
    func approvePairing(origin: String, code: String) -> Bool
    /// Show what is about to be signed and collect the PIN. nil when refused.
    func approveSignature(origin: String, context: SignContext, tokenLabel: String) -> String?
}

/// Consent through system dialogs.
///
/// **Interim.** AppleScript dialogs are system-drawn, which is the only good
/// thing about them: they are not ours, they cannot show a document preview,
/// and a determined local process could put up something similar. They are
/// enough to prove the wire and to keep the PIN out of the browser, which are
/// the two properties that matter before the real window exists.
public struct DialogConsent: Consent {
    /// Button labels, named once because the answer is matched against them.
    /// A label changed in the dialog and not here reads every click as a
    /// refusal — which fails safe, but silently.
    enum Buttons {
        static let approve = "Approve"
        static let sign = "Sign"
    }

    public init() {}

    public func approvePairing(origin: String, code: String) -> Bool {
        let message =
            "\(origin) is asking to use your signing token.\n\n"
            + "Approve only if the page shows this code:\n\n\t\(code)"
        let result = runOsascript(
            "display dialog \(quote(message)) with title \"Sign Bridge\" "
                + "buttons {\"Refuse\", \"\(Buttons.approve)\"} default button \"Refuse\" with icon caution"
        )
        return DialogConsent.approved(result)
    }

    /// Whether an `osascript display dialog` answer means the approve button.
    ///
    /// Split out and made static so it can be checked without a dialog, which
    /// it needs to be: this got it wrong. `display dialog` exits 0 for every
    /// button it defines — only one literally named "Cancel" raises an error —
    /// so reading the exit status as consent treats "Refuse" as approval. It
    /// did, and a refused pairing paired the origin.
    public static func approved(_ answer: String?) -> Bool {
        answer?.contains("button returned:\(Buttons.approve)") ?? false
    }

    /// The PIN out of an answer, or nil if the dialog was not confirmed.
    ///
    /// The answer is "button returned:Sign, text returned:1234" — and a PIN may
    /// itself contain a comma, so the tail is taken whole rather than split.
    public static func pin(_ answer: String?) -> String? {
        guard let answer, answer.contains("button returned:\(Buttons.sign)") else { return nil }
        guard let range = answer.range(of: "text returned:") else { return nil }
        return String(answer[range.upperBound...]).trimmingCharacters(in: .whitespacesAndNewlines)
    }

    public func approveSignature(origin: String, context: SignContext, tokenLabel: String) -> String? {
        // The digest is shown in full. Nobody will read all of it, but it is
        // the only thing tying this window to a specific set of bytes, and a
        // truncated one ties it to nothing.
        let message =
            "\(origin) wants to sign with \(tokenLabel).\n\n"
            + "Document: \(context.documentName)\n"
            + "SHA-256: \(context.digest)\n\n"
            + "Enter your token PIN to sign, or Cancel."
        let result = runOsascript(
            "display dialog \(quote(message)) with title \"Sign Bridge\" "
                + "default answer \"\" with hidden answer "
                + "buttons {\"Cancel\", \"\(Buttons.sign)\"} default button \"\(Buttons.sign)\" with icon caution"
        )
        return DialogConsent.pin(result)
    }

    /// nil when the user cancelled or the dialog could not be shown. A refusal
    /// and a failure are the same outcome here: nothing gets signed.
    private func runOsascript(_ script: String) -> String? {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        process.arguments = ["-e", script]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        do {
            try process.run()
        } catch {
            return nil
        }
        let output = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else { return nil }
        return String(decoding: output, as: UTF8.self)
    }

    private func quote(_ text: String) -> String {
        "\"" + text.replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"") + "\""
    }
}

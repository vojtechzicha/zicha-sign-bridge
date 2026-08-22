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
    public init() {}

    public func approvePairing(origin: String, code: String) -> Bool {
        let message =
            "\(origin) is asking to use your signing token.\n\n"
            + "Approve only if the page shows this code:\n\n\t\(code)"
        return runOsascript(
            "display dialog \(quote(message)) with title \"Sign Bridge\" "
                + "buttons {\"Refuse\", \"Approve\"} default button \"Refuse\" with icon caution"
        ) != nil
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
                + "buttons {\"Cancel\", \"Sign\"} default button \"Sign\" with icon caution"
        )
        guard let result else { return nil }
        // `display dialog` answers "button returned:Sign, text returned:1234".
        guard let range = result.range(of: "text returned:") else { return nil }
        return String(result[range.upperBound...]).trimmingCharacters(in: .whitespacesAndNewlines)
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

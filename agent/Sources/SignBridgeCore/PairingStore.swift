import Foundation

/// Which origins have been approved, on disk.
///
/// In Application Support rather than the keychain: this is a list of web
/// origins, not a secret, and a file the user can read, audit and delete is a
/// feature. The key is that it is per-user and outside the browser — a page
/// cannot clear it by clearing site data, and reinstalling the extension does
/// not silently re-approve anything.
public final class PairingStore: @unchecked Sendable {
    private let url: URL
    private var approved: Set<String>

    public static var defaultURL: URL {
        FileManager.default
            .urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("SignBridge", isDirectory: true)
            .appendingPathComponent("paired.json")
    }

    public init(url: URL = PairingStore.defaultURL) {
        self.url = url
        let data = try? Data(contentsOf: url)
        self.approved = Set((try? JSONDecoder().decode([String].self, from: data ?? Data())) ?? [])
    }

    public func isPaired(_ origin: String) -> Bool { approved.contains(origin) }

    public func approve(_ origin: String) {
        approved.insert(origin)
        persist()
    }

    public func revoke(_ origin: String) {
        approved.remove(origin)
        persist()
    }

    public var origins: [String] { approved.sorted() }

    private func persist() {
        try? FileManager.default.createDirectory(
            at: url.deletingLastPathComponent(), withIntermediateDirectories: true
        )
        // Sorted so the file is stable and a diff means something changed.
        guard let data = try? JSONEncoder().encode(approved.sorted()) else { return }
        try? data.write(to: url, options: .atomic)
    }
}

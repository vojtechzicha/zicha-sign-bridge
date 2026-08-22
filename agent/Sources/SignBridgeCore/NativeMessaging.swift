import Foundation

/// Chrome's native messaging framing: a 4-byte little-endian length, then that
/// many bytes of UTF-8 JSON, on stdin and stdout.
///
/// stdout is the wire. Anything else written there — a stray print, a library's
/// warning — corrupts the stream and the browser drops the connection with no
/// explanation, so diagnostics go to stderr and nowhere else.
public struct NativeMessaging {
    /// Chrome refuses anything larger than 1 MB from a host, and a length
    /// prefix read from a broken pipe can be nonsense, so it is bounded before
    /// it is used to allocate.
    public static let maxMessageBytes = 1024 * 1024

    private let input: FileHandle
    private let output: FileHandle

    public init(input: FileHandle = .standardInput, output: FileHandle = .standardOutput) {
        self.input = input
        self.output = output
    }

    /// The next message, or nil at end of stream (the browser hung up).
    public func read() throws -> Data? {
        guard let header = try readExactly(4) else { return nil }
        let length = header.withUnsafeBytes { $0.loadUnaligned(as: UInt32.self).littleEndian }
        guard length > 0, Int(length) <= NativeMessaging.maxMessageBytes else {
            throw NativeMessagingError.badLength(Int(length))
        }
        guard let body = try readExactly(Int(length)) else {
            throw NativeMessagingError.truncated
        }
        return body
    }

    public func write(_ payload: Data) throws {
        guard payload.count <= NativeMessaging.maxMessageBytes else {
            throw NativeMessagingError.tooLarge(payload.count)
        }
        var length = UInt32(payload.count).littleEndian
        var frame = Data(bytes: &length, count: 4)
        frame.append(payload)
        try output.write(contentsOf: frame)
    }

    /// A pipe read returns what it has, not what was asked for — so this loops
    /// until the count is met. Getting this wrong shows up only under load,
    /// when a large certificate list happens to arrive in two pieces.
    private func readExactly(_ count: Int) throws -> Data? {
        var buffer = Data()
        while buffer.count < count {
            guard let chunk = try input.read(upToCount: count - buffer.count), !chunk.isEmpty else {
                return buffer.isEmpty ? nil : buffer
            }
            buffer.append(chunk)
        }
        return buffer
    }
}

public enum NativeMessagingError: Error, CustomStringConvertible {
    case badLength(Int)
    case truncated
    case tooLarge(Int)

    public var description: String {
        switch self {
        case .badLength(let n): return "implausible message length \(n)"
        case .truncated: return "the stream ended mid-message"
        case .tooLarge(let n): return "a \(n)-byte reply exceeds the 1 MB native messaging limit"
        }
    }
}

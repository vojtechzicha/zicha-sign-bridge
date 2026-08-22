import Foundation

/// A check harness the size of the job.
///
/// Counts assertions, prints one line per section, exits non-zero on the first
/// failure with enough context to act on. Same shape as the web app's
/// `scripts/check-*.ts`, so a failure reads the same wherever it comes from.
struct Checks {
    private(set) var count = 0
    private var failures: [String] = []
    private var skipped: [String] = []

    mutating func ok(_ condition: @autoclosure () -> Bool, _ message: String) {
        count += 1
        if !condition() { failures.append(message) }
    }

    mutating func equal<T: Equatable>(_ actual: T, _ expected: T, _ message: String) {
        count += 1
        if actual != expected { failures.append("\(message)\n      expected \(expected), got \(actual)") }
    }

    /// Assert that `body` throws, and that the thrown error satisfies `check`.
    mutating func throwsError(_ message: String, _ body: () throws -> Void, where check: (Error) -> Bool = { _ in true }) {
        count += 1
        do {
            try body()
            failures.append("\(message)\n      expected a failure, none was thrown")
        } catch {
            if !check(error) { failures.append("\(message)\n      unexpected error: \(error)") }
        }
    }

    mutating func skip(_ reason: String) {
        skipped.append(reason)
    }

    func section(_ title: String) {
        print("── \(title)")
    }

    func finish(_ label: String) -> Never {
        for reason in skipped { print("ℹ skipped — \(reason)") }
        guard failures.isEmpty else {
            print("\n✗ \(failures.count) of \(count) \(label) failed:\n")
            for failure in failures { print("  • \(failure)") }
            exit(1)
        }
        print("✓ \(count) \(label) passed")
        exit(0)
    }
}

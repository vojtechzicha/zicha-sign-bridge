// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "SignBridge",
    platforms: [.macOS(.v13)],
    products: [
        .library(name: "SignBridgeCore", targets: ["SignBridgeCore"]),
        .executable(name: "signbridge-check", targets: ["signbridge-check"]),
    ],
    targets: [
        // The vendored OASIS PKCS #11 headers plus the platform macros they
        // require. No sources: it exists so Swift can see the C types.
        .target(name: "CPKCS11"),
        .target(name: "SignBridgeCore", dependencies: ["CPKCS11"]),

        // The checks are an executable rather than a `.testTarget`, and
        // deliberately: XCTest and swift-testing both ship with Xcode, not with
        // the Command Line Tools, so a test target cannot be built — let alone
        // run — on a machine that has only the latter. A plain executable needs
        // nothing but the toolchain, runs identically on a laptop and on a CI
        // runner, and matches how the web app this serves states its own
        // results ("✓ 103 signature checks passed").
        .executableTarget(name: "signbridge-check", dependencies: ["SignBridgeCore"]),
    ]
)

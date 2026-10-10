// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "ADSearchTools",
    defaultLocalization: "ru",
    platforms: [.macOS(.v13)],
    targets: [
        .target(name: "ADKit", linkerSettings: [.linkedLibrary("ldap")]),
        .executableTarget(name: "ADSearchTools", dependencies: ["ADKit"]),
        // `swift run ADKitChecks` — unit checks; with AD_TEST_URL set also runs against a live DC (see TestDC/).
        .executableTarget(name: "ADKitChecks", dependencies: ["ADKit"]),
    ]
)

// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "PiAPManager",
    platforms: [.macOS(.v14)],
    targets: [
        .executableTarget(
            name: "PiAPManager",
            path: "Sources/PiAPManager",
            swiftSettings: [.unsafeFlags(["-Xfrontend", "-warn-long-expression-type-checking=200"])]
        )
    ],
    swiftLanguageVersions: [.v5]
)

// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "MacPersistenceChecker",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        .executable(name: "MacPersistenceChecker", targets: ["MacPersistenceChecker"]),
        .executable(name: "mpc-server", targets: ["MPCServer"])
    ],
    dependencies: [
        .package(url: "https://github.com/groue/GRDB.swift.git", from: "6.24.0")
    ],
    targets: [
        .executableTarget(
            name: "MacPersistenceChecker",
            dependencies: [
                .product(name: "GRDB", package: "GRDB.swift")
            ],
            path: "MacPersistenceChecker",
            resources: [
                .process("Resources/KnownVendors.json")
            ]
        ),
        .executableTarget(
            name: "MPCServer",
            dependencies: [
                .product(name: "GRDB", package: "GRDB.swift")
            ],
            path: "Sources/MPCServer"
        )
    ]
)

// swift-tools-version:5.5
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "SwiftHawk",
    platforms: [
        .macOS(.v10_15),
        .tvOS(.v13),
        .watchOS(.v6),
        .iOS(.v13)
    ],
    products: [
        .library(name: "SwiftHawk", targets: ["SwiftHawk"]),
    ],
    targets: [
        .target(name: "SwiftHawk", dependencies: []),
    ]
)

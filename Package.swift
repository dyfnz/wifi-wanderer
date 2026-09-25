// swift-tools-version:6.0
import PackageDescription

// Absolute paths are needed because the linker flags below are passed verbatim.
let root = Context.packageDirectory

let package = Package(
    name: "wifi-wanderer",
    platforms: [.macOS(.v13)],
    targets: [
        .executableTarget(
            name: "wifi-wanderer",
            path: "Sources/WiFiWanderer",
            exclude: ["Info.plist", "Resources"],
            linkerSettings: [
                .linkedFramework("CoreWLAN"),
                .linkedFramework("CoreLocation"),
                // Embed an Info.plist so macOS can attribute the Location Services
                // request (needed to un-redact SSID/BSSID) to this binary, and embed
                // the OUI database so the binary is fully self-contained.
                .unsafeFlags([
                    "-Xlinker", "-sectcreate", "-Xlinker", "__TEXT", "-Xlinker", "__info_plist",
                    "-Xlinker", "\(root)/Sources/WiFiWanderer/Info.plist",
                    "-Xlinker", "-sectcreate", "-Xlinker", "__TEXT", "-Xlinker", "__oui_db",
                    "-Xlinker", "\(root)/Sources/WiFiWanderer/Resources/manuf",
                ]),
            ]
        ),
    ],
    swiftLanguageModes: [.v5]
)

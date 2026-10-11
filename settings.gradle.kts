pluginManagement {
    repositories {
        google {
            content {
                includeGroupByRegex("com\\.android.*")
                includeGroupByRegex("com\\.google.*")
                includeGroupByRegex("androidx.*")
            }
        }
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    // Fail the build if any module declares its own repositories: every artifact
    // must come from the two audited repositories below.
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "zcp-map"

// Pure-Kotlin/JVM modules (no Android framework dependency, unit-testable on any JVM)
include(":core:protocol")   // ZCP1 wire framing, Merkle trees, lifecycle FSM, strict JSON schema
include(":core:security")   // Noise XX, AEAD + replay window, HKDF, attestation, capability tokens
include(":core:mesh")       // Per-peer session coordinator (handshake -> distance bound -> settlement)
include(":core:agent")      // Claude kernel, MCP server, security airlock

// Android library modules (framework bindings)
include(":core:keystore")   // Android Keystore identity (StrongBox/TEE) + secret vault
include(":core:transport")  // UWB secure ranging, Nearby Connections, Wi-Fi Aware

// Application
include(":app")

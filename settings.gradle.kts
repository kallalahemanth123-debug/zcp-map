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

// ---------------------------------------------------------------------------------------------
// Environment checks. They run before anything else is resolved, so a wrong setup fails in the
// first second with an instruction instead of a confusing error deep inside the build.
// ---------------------------------------------------------------------------------------------
run {
    val fix = """
        |
        |  Android Studio: Settings > Build, Execution, Deployment > Build Tools > Gradle > Gradle JDK
        |                  > choose "jbr-21" (bundled) or any JDK 17/21.
        |  Command line:   install JDK 17 or 21 (e.g. https://adoptium.net) and set JAVA_HOME to it.
        """.trimMargin()
    if (!JavaVersion.current().isCompatibleWith(JavaVersion.VERSION_17)) {
        throw GradleException(
            "ZCP-MAP needs JDK 17 or newer to build, but Gradle is running on Java ${JavaVersion.current()} " +
                "(${System.getProperty("java.home")}).$fix",
        )
    }
    if (javax.tools.ToolProvider.getSystemJavaCompiler() == null) {
        throw GradleException(
            "Gradle is running on a Java runtime without a compiler (a JRE): ${System.getProperty("java.home")}. " +
                "A full JDK 17 or 21 is required.$fix",
        )
    }
    if (!file("gradle/libs.versions.toml").isFile) {
        throw GradleException(
            "gradle/libs.versions.toml is missing. It defines every plugin and library version (the `libs.` " +
                "aliases in the build files). Restore it from the repository or the original zip.",
        )
    }
}

dependencyResolutionManagement {
    // Every artifact comes from these two audited repositories, and a module that declares its
    // own repository fails the build on purpose (no silent extra download sources).
    //
    // To use a library from another repository, add it HERE, limited to the groups it serves, e.g.:
    //     maven("https://jitpack.io") { content { includeGroup("com.github.someuser") } }
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
include(":core:agent")      // Agent kernel, rule-based agent, local model backends, MCP server, airlock

// Android library modules (framework bindings)
include(":core:keystore")   // Android Keystore identity (StrongBox/TEE) + secret vault
include(":core:transport")  // UWB secure ranging, Nearby Connections, Wi-Fi Aware

// Application
include(":app")

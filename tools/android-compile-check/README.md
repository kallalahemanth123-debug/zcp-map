Compile-only stubs used to type-check the Android modules where Google's Maven repository is unreachable.
Not part of the Gradle build. Signatures were checked against androidx-main sources (core/uwb, Compose,
Material3, Lifecycle, Activity) and android/connectivity-samples (Nearby). LiteRT-LM was compiled from its
real v0.18.0 Kotlin sources; the Android platform came from a real android-35 jar.

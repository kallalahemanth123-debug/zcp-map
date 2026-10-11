# kotlinx.serialization JsonElement API is used reflection-free; nothing to keep.
# Keep BouncyCastle curve math used by the security module.
-keep class org.bouncycastle.math.ec.rfc7748.** { *; }
-keep class org.bouncycastle.math.ec.rfc8032.** { *; }
-keep class org.bouncycastle.crypto.modes.ChaCha20Poly1305 { *; }
-dontwarn org.bouncycastle.**

# LiteRT-LM (on-device model): JNI entry points and the classes the native layer calls back into.
-keep class com.google.ai.edge.litertlm.** { *; }
-keepclasseswithmembernames class * { native <methods>; }
-keep class kotlin.Metadata { *; }

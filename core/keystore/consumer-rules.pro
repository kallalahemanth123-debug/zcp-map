# BouncyCastle lightweight API is referenced reflectively by nothing, but R8 must
# not strip the rfc7748/rfc8032 math classes used through static calls.
-keep class org.bouncycastle.math.ec.rfc7748.** { *; }
-keep class org.bouncycastle.math.ec.rfc8032.** { *; }

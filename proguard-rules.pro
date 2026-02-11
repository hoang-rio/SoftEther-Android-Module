# ProGuard rules for SoftEtherClient module

# Keep native methods
-keepclasseswithmembernames class * {
    native <methods>;
}

# Keep JNI bridge class
-keep class vn.unlimit.softether.client.SoftEtherClient {
    native <methods>;
}

# Keep VPN service
-keep class vn.unlimit.softether.SoftEtherVpnService {
    public *;
}

# Keep data classes used for serialization
-keep class vn.unlimit.softether.model.** {
    *;
}

# Keep exception classes
-keep class vn.unlimit.softether.exception.** extends java.lang.Exception {
    *;
}

# Kotlin coroutines
-keepclassmembernames class kotlinx.** {
    volatile <fields>;
}

# BouncyCastle (if used)
-keep class org.bouncycastle.** { *; }
-dontwarn org.bouncycastle.**

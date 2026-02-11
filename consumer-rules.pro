# Consumer ProGuard rules for SoftEtherClient
# These rules will be automatically applied when consumers use this library

# Keep all public API classes
-keep public class vn.unlimit.softether.** {
    public *;
}

# Keep native methods
-keepclasseswithmembernames class * {
    native <methods>;
}

# SoftEtherNative Testing Guide

## Important: Unit Tests vs Instrumented Tests

### Unit Tests (Robolectric)
- Run on JVM (desktop Java)
- **CANNOT load Android native libraries (.so files)**
- Tests will skip native method calls with "native library not available" message
- Use for testing Kotlin wrapper logic only

### Instrumented Tests (Android)
- Run on Android device/emulator
- **CAN load native libraries**
- Tests actually call native methods
- Use for testing native functionality

## Running Tests

### Unit Tests (No Native)
```bash
./gradlew :SoftEtherClient:testDebugUnitTest
```

### Instrumented Tests (With Native)
```bash
# Connect device or start emulator
adb devices

# Run instrumented tests
./gradlew :SoftEtherClient:connectedDebugAndroidTest
```

## Test Files

- `SoftEtherNativeUnitTest.kt` - Unit tests (Kotlin layer only)
- `SoftEtherNativeTestConnectTest.kt` - Unit tests with native calls (will skip on JVM)
- `SoftEtherNativeConnectInstrumentedTest.kt` - Instrumented tests (full native testing)

## Why Native Library Not Available?

The native library (`libsoftether-native.so`) is built for Android architectures:
- arm64-v8a
- armeabi-v7a
- x86
- x86_64

These cannot be loaded on desktop JVM. The `System.loadLibrary()` throws `UnsatisfiedLinkError` when running unit tests.

## Solution

Use **Android Instrumented Tests** to test native functionality:
1. Connect Android device or start emulator
2. Run: `./gradlew :SoftEtherClient:connectedDebugAndroidTest`

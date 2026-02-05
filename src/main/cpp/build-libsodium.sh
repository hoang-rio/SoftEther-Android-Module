#!/bin/bash
# Build libsodium for Android - All ABIs
# Usage: ./build-libsodium.sh [ABI]
# If ABI is not specified, builds for all ABIs

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIBSODIUM_DIR="$SCRIPT_DIR/libsodium"
BUILD_DIR="$SCRIPT_DIR/libsodium-build"
JNILIBS_DIR="$SCRIPT_DIR/../jniLibs"

# Android NDK settings
export ANDROID_NDK_HOME="${ANDROID_NDK_HOME:-/Volumes/HoangND/Sdks/Android/sdk/ndk/28.2.13676358}"
export NDK_PLATFORM="${NDK_PLATFORM:-android-23}"

# ABI configurations
# Format: ABI_NAME:TARGET_ARCH:ARCH:HOST_COMPILER:CFLAGS
ABIS=(
    "arm64-v8a:armv8-a+crypto:arm64:aarch64-linux-android:-Os -march=armv8-a+crypto -fPIC"
    "armeabi-v7a:armv7-a:arm:armv7a-linux-androideabi:-Os -march=armv7-a -fPIC"
    "x86:i686:x86:i686-linux-android:-Os -march=i686 -fPIC"
    "x86_64:westmere:x86_64:x86_64-linux-android:-Os -march=westmere -fPIC"
)

build_libsodium() {
    local ABI="$1"
    local TARGET_ARCH="$2"
    local ARCH="$3"
    local HOST_COMPILER="$4"
    local CFLAGS="$5"
    
    echo "=========================================="
    echo "Building libsodium for $ABI"
    echo "=========================================="
    
    local OUTPUT_DIR="$BUILD_DIR/$ABI"
    mkdir -p "$OUTPUT_DIR"
    
    cd "$LIBSODIUM_DIR"
    
    # Clean previous builds
    make clean 2>/dev/null || true
    
    # Export build environment
    export TARGET_ARCH
    export ARCH
    export HOST_COMPILER
    export CFLAGS="$CFLAGS -Wl,-z,max-page-size=16384"
    export LDFLAGS="-Wl,-z,max-page-size=16384"
    export PREFIX="$OUTPUT_DIR"
    export TOOLCHAIN_OS_DIR="$(uname | tr '[:upper:]' '[:lower:]')-x86_64"
    export TOOLCHAIN_DIR="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/${TOOLCHAIN_OS_DIR}"
    export PATH="${TOOLCHAIN_DIR}/bin:$PATH"
    
    SDK_VERSION=$(echo "$NDK_PLATFORM" | cut -f2 -d"-")
    export CC="${HOST_COMPILER}${SDK_VERSION}-clang"
    
    # Run autogen if needed
    if [ ! -f ./configure ]; then
        ./autogen.sh
    fi
    
    # Configure and build
    ./configure \
        --disable-soname-versions \
        --disable-pie \
        --enable-minimal \
        --host="${HOST_COMPILER}" \
        --prefix="${PREFIX}" \
        --with-sysroot="${TOOLCHAIN_DIR}/sysroot"
    
    make clean
    make -j$(sysctl -n hw.ncpu) install
    
    echo "✓ Build complete for $ABI"
    echo "  Libraries: $OUTPUT_DIR/lib/"
}

# Main
if [ $# -eq 1 ]; then
    # Build specific ABI
    TARGET_ABI="$1"
    FOUND=0
    for ABI_PAIR in "${ABIS[@]}"; do
        IFS=':' read -r ABI_NAME TARGET_ARCH ARCH HOST_COMPILER CFLAGS <<< "$ABI_PAIR"
        if [ "$ABI_NAME" = "$TARGET_ABI" ]; then
            build_libsodium "$ABI_NAME" "$TARGET_ARCH" "$ARCH" "$HOST_COMPILER" "$CFLAGS"
            FOUND=1
            break
        fi
    done
    if [ $FOUND -eq 0 ]; then
        echo "Error: Unknown ABI '$TARGET_ABI'"
        echo "Supported ABIs: arm64-v8a, armeabi-v7a, x86, x86_64"
        exit 1
    fi
else
    # Build all ABIs
    echo "Building libsodium for all ABIs..."
    for ABI_PAIR in "${ABIS[@]}"; do
        IFS=':' read -r ABI_NAME TARGET_ARCH ARCH HOST_COMPILER CFLAGS <<< "$ABI_PAIR"
        build_libsodium "$ABI_NAME" "$TARGET_ARCH" "$ARCH" "$HOST_COMPILER" "$CFLAGS"
    done
    echo ""
    echo "=========================================="
    echo "All libsodium builds completed successfully!"
    echo "=========================================="
fi

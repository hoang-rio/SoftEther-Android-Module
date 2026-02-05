#!/bin/bash
# Build OpenSSL for Android - All ABIs
# Usage: ./build-openssl.sh [ABI]
# If ABI is not specified, builds for all ABIs

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OPENSSL_DIR="$SCRIPT_DIR/openssl"
BUILD_DIR="$SCRIPT_DIR/openssl-build"
JNILIBS_DIR="$SCRIPT_DIR/../jniLibs"

# Android NDK settings
export ANDROID_NDK_ROOT="${ANDROID_NDK_ROOT:-/Volumes/HoangND/Sdks/Android/sdk/ndk/28.2.13676358}"
export ANDROID_API="${ANDROID_API:-23}"

# ABI mappings
# Format: ABI_NAME:OPENSSL_TARGET
ABIS=(
    "arm64-v8a:android-arm64"
    "armeabi-v7a:android-arm"
    "x86:android-x86"
    "x86_64:android-x86_64"
)

# Setup PATH for NDK toolchain
NDK_TOOLCHAIN="$ANDROID_NDK_ROOT/toolchains/llvm/prebuilt/darwin-x86_64/bin"
if [ ! -d "$NDK_TOOLCHAIN" ]; then
    echo "Error: NDK toolchain not found at $NDK_TOOLCHAIN"
    exit 1
fi
export PATH="$NDK_TOOLCHAIN:$PATH"

build_openssl() {
    local ABI="$1"
    local OPENSSL_TARGET="$2"
    
    echo "=========================================="
    echo "Building OpenSSL for $ABI"
    echo "=========================================="
    
    local OUTPUT_DIR="$BUILD_DIR/$ABI"
    mkdir -p "$OUTPUT_DIR"
    
    cd "$OPENSSL_DIR"
    
    # Clean previous builds
    make clean 2>/dev/null || true
    
    # Configure OpenSSL for Android
    # Use no-asm for arm64 to avoid SVE2 relocation issues
    local EXTRA_OPTS=""
    if [ "$ABI" = "arm64-v8a" ]; then
        EXTRA_OPTS="no-asm"
    fi
    
    ./Configure \
        $OPENSSL_TARGET \
        -D__ANDROID_API__=$ANDROID_API \
        -fPIC \
        -static \
        no-shared \
        $EXTRA_OPTS \
        --prefix="$OUTPUT_DIR" \
        --openssldir="$OUTPUT_DIR"
    
    # Build only the libraries
    make -j$(sysctl -n hw.ncpu) build_libs
    
    # Install the libraries and headers
    make install_sw
    
    echo "✓ Build complete for $ABI"
    echo "  Libraries: $OUTPUT_DIR/lib/"
}

# Main
if [ $# -eq 1 ]; then
    # Build specific ABI
    TARGET_ABI="$1"
    FOUND=0
    for ABI_PAIR in "${ABIS[@]}"; do
        IFS=':' read -r ABI_NAME OPENSSL_TARGET <<< "$ABI_PAIR"
        if [ "$ABI_NAME" = "$TARGET_ABI" ]; then
            build_openssl "$ABI_NAME" "$OPENSSL_TARGET"
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
    echo "Building OpenSSL for all ABIs..."
    for ABI_PAIR in "${ABIS[@]}"; do
        IFS=':' read -r ABI_NAME OPENSSL_TARGET <<< "$ABI_PAIR"
        build_openssl "$ABI_NAME" "$OPENSSL_TARGET"
    done
    echo ""
    echo "=========================================="
    echo "All OpenSSL builds completed successfully!"
    echo "=========================================="
fi

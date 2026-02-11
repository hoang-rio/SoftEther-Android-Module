#!/bin/bash
# Build OpenSSL for Android - All ABIs
# Usage: ./build-openssl-android.sh [ABI]
# If ABI is not specified, builds for all ABIs

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OPENSSL_DIR="$SCRIPT_DIR/openssl"
BUILD_DIR="$SCRIPT_DIR/openssl-build"
JNILIBS_DIR="$SCRIPT_DIR/../jniLibs"

# Android NDK settings
export ANDROID_NDK_ROOT="${ANDROID_NDK_ROOT:-/Volumes/HoangND/Sdks/Android/sdk/ndk/28.2.13676358}"
export ANDROID_NDK_HOME="$ANDROID_NDK_ROOT"  # OpenSSL uses ANDROID_NDK_HOME
export ANDROID_API="${ANDROID_API:-23}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# ABI mappings
# Format: ABI_NAME:OPENSSL_TARGET
ABIS=(
    "arm64-v8a:android-arm64"
    "armeabi-v7a:android-arm"
    "x86:android-x86"
    "x86_64:android-x86_64"
)

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    if [ ! -d "$ANDROID_NDK_ROOT" ]; then
        log_error "Android NDK not found at $ANDROID_NDK_ROOT"
        log_error "Please set ANDROID_NDK_ROOT environment variable"
        exit 1
    fi
    
    if [ ! -d "$OPENSSL_DIR" ]; then
        log_error "OpenSSL directory not found at $OPENSSL_DIR"
        log_error "Please run: git submodule update --init"
        exit 1
    fi
    
    # Check for required tools
    if ! command -v perl &> /dev/null; then
        log_error "Perl is required but not installed"
        exit 1
    fi
    
    log_info "Prerequisites check passed"
}

# Setup PATH for NDK toolchain
setup_ndk_toolchain() {
    local ABI="$1"
    
    NDK_TOOLCHAIN="$ANDROID_NDK_ROOT/toolchains/llvm/prebuilt/darwin-x86_64/bin"
    if [ ! -d "$NDK_TOOLCHAIN" ]; then
        # Try Linux path
        NDK_TOOLCHAIN="$ANDROID_NDK_ROOT/toolchains/llvm/prebuilt/linux-x86_64/bin"
    fi
    
    if [ ! -d "$NDK_TOOLCHAIN" ]; then
        log_error "NDK toolchain not found at $NDK_TOOLCHAIN"
        exit 1
    fi
    
    export PATH="$NDK_TOOLCHAIN:$PATH"
}

# Build OpenSSL for a specific ABI
build_openssl() {
    local ABI="$1"
    local OPENSSL_TARGET="$2"
    
    log_info "=========================================="
    log_info "Building OpenSSL for $ABI"
    log_info "=========================================="
    
    local OUTPUT_DIR="$BUILD_DIR/$ABI"
    local JNI_ABI_DIR="$JNILIBS_DIR/$ABI"
    
    mkdir -p "$OUTPUT_DIR"
    mkdir -p "$JNI_ABI_DIR"
    
    cd "$OPENSSL_DIR"
    
    # Clean previous builds
    log_info "Cleaning previous build..."
    make clean 2>/dev/null || true
    rm -f Makefile include/openssl/opensslconf.h 2>/dev/null || true
    
    # Setup NDK toolchain
    setup_ndk_toolchain "$ABI"
    
    # Configure OpenSSL for Android
    log_info "Configuring OpenSSL for $OPENSSL_TARGET..."
    
    # Use no-asm for arm64 and x86 to avoid assembly issues
    local EXTRA_OPTS=""
    if [ "$ABI" = "arm64-v8a" ] || [ "$ABI" = "x86" ]; then
        EXTRA_OPTS="no-asm"
        log_warn "Using no-asm for $ABI to avoid assembly issues"
    fi
    
    ./Configure \
        "$OPENSSL_TARGET" \
        -D__ANDROID_API__="$ANDROID_API" \
        -fPIC \
        -static \
        no-shared \
        no-stdio \
        no-tests \
        $EXTRA_OPTS \
        --prefix="$OUTPUT_DIR" \
        --openssldir="$OUTPUT_DIR"
    
    # Build only the libraries
    log_info "Building OpenSSL libraries..."
    make -j"$(sysctl -n hw.ncpu 2>/dev/null || echo 4)" build_libs
    
    # Install the libraries and headers
    log_info "Installing OpenSSL libraries..."
    make install_sw
    
    # Copy libraries to jniLibs
    log_info "Copying libraries to jniLibs/$ABI/"
    cp "$OUTPUT_DIR/lib/libssl.a" "$JNI_ABI_DIR/"
    cp "$OUTPUT_DIR/lib/libcrypto.a" "$JNI_ABI_DIR/"
    
    # Show file sizes
    log_info "Built libraries:"
    ls -lh "$JNI_ABI_DIR/"*.a
    
    log_info "✓ Build complete for $ABI"
}

# Generate headers for development
generate_headers() {
    log_info "=========================================="
    log_info "Generating OpenSSL headers for development"
    log_info "=========================================="
    
    cd "$OPENSSL_DIR"
    
    # Generate headers using a simple config
    log_info "Configuring for header generation..."
    ./Configure gcc -DOPENSSL_NO_ASM --prefix=/tmp/openssl-headers 2>/dev/null || true
    
    # Generate headers
    log_info "Generating headers..."
    make build_generated 2>/dev/null || true
    
    if [ -f "$OPENSSL_DIR/include/openssl/opensslconf.h" ]; then
        log_info "✓ Headers generated successfully"
    else
        log_warn "Headers may not have been generated properly"
    fi
}

# Main function
main() {
    log_info "OpenSSL Android Build Script"
    log_info "============================"
    log_info "NDK: $ANDROID_NDK_ROOT"
    log_info "API Level: $ANDROID_API"
    log_info "OpenSSL: $OPENSSL_DIR"
    log_info ""
    
    check_prerequisites
    
    # Create output directories
    mkdir -p "$BUILD_DIR"
    mkdir -p "$JNILIBS_DIR"
    
    # Generate headers first (for development)
    generate_headers
    
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
            log_error "Unknown ABI '$TARGET_ABI'"
            log_error "Supported ABIs: arm64-v8a, armeabi-v7a, x86, x86_64"
            exit 1
        fi
    else
        # Build all ABIs
        log_info "Building OpenSSL for all ABIs..."
        for ABI_PAIR in "${ABIS[@]}"; do
            IFS=':' read -r ABI_NAME OPENSSL_TARGET <<< "$ABI_PAIR"
            build_openssl "$ABI_NAME" "$OPENSSL_TARGET"
        done
    fi
    
    log_info ""
    log_info "=========================================="
    log_info "OpenSSL build completed successfully!"
    log_info "=========================================="
    log_info ""
    log_info "Libraries are available in:"
    log_info "  $JNILIBS_DIR/"
    log_info ""
    log_info "To use in your project:"
    log_info "  ./gradlew :SoftEtherClient:buildCMakeDebug"
}

# Show usage
show_usage() {
    echo "Usage: $0 [ABI]"
    echo ""
    echo "Build OpenSSL for Android"
    echo ""
    echo "Arguments:"
    echo "  ABI       Target ABI (optional, builds all if not specified)"
    echo ""
    echo "Supported ABIs:"
    echo "  arm64-v8a     ARM 64-bit"
    echo "  armeabi-v7a   ARM 32-bit"
    echo "  x86           x86 32-bit"
    echo "  x86_64        x86 64-bit"
    echo ""
    echo "Environment Variables:"
    echo "  ANDROID_NDK_ROOT    Path to Android NDK (default: /Volumes/HoangND/Sdks/Android/sdk/ndk/28.2.13676358)"
    echo "  ANDROID_API         Android API level (default: 23)"
    echo ""
    echo "Examples:"
    echo "  $0                  Build for all ABIs"
    echo "  $0 arm64-v8a        Build for ARM64 only"
    echo "  $0 x86_64           Build for x86_64 only"
}

# Handle command line
if [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
    show_usage
    exit 0
fi

main "$@"

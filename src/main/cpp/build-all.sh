#!/bin/bash
# Master build script for SoftEtherClient native libraries
# Builds OpenSSL and libsodium for all ABIs and copies to jniLibs

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OPENSSL_BUILD_DIR="$SCRIPT_DIR/openssl-build"
LIBSODIUM_BUILD_DIR="$SCRIPT_DIR/libsodium-build"
JNILIBS_DIR="$SCRIPT_DIR/../jniLibs"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# ABIs to build
ABIS=("arm64-v8a" "armeabi-v7a" "x86" "x86_64")

print_header() {
    echo ""
    echo "=========================================="
    echo "$1"
    echo "=========================================="
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_info() {
    echo -e "${YELLOW}→ $1${NC}"
}

copy_libs() {
    print_header "Copying built libraries to jniLibs"
    
    for ABI in "${ABIS[@]}"; do
        print_info "Processing $ABI..."
        
        # Create ABI directory in jniLibs if it doesn't exist
        mkdir -p "$JNILIBS_DIR/$ABI"
        
        # Copy OpenSSL static libraries
        if [ -f "$OPENSSL_BUILD_DIR/$ABI/lib/libcrypto.a" ]; then
            cp "$OPENSSL_BUILD_DIR/$ABI/lib/libcrypto.a" "$JNILIBS_DIR/$ABI/"
            print_success "Copied libcrypto.a for $ABI"
        else
            print_error "OpenSSL libcrypto.a not found for $ABI"
        fi
        
        if [ -f "$OPENSSL_BUILD_DIR/$ABI/lib/libssl.a" ]; then
            cp "$OPENSSL_BUILD_DIR/$ABI/lib/libssl.a" "$JNILIBS_DIR/$ABI/"
            print_success "Copied libssl.a for $ABI"
        else
            print_error "OpenSSL libssl.a not found for $ABI"
        fi
        
        # Copy libsodium shared library
        if [ -f "$LIBSODIUM_BUILD_DIR/$ABI/lib/libsodium.so" ]; then
            cp "$LIBSODIUM_BUILD_DIR/$ABI/lib/libsodium.so" "$JNILIBS_DIR/$ABI/"
            print_success "Copied libsodium.so for $ABI"
        elif [ -f "$LIBSODIUM_BUILD_DIR/$ABI/lib/libsodium.a" ]; then
            cp "$LIBSODIUM_BUILD_DIR/$ABI/lib/libsodium.a" "$JNILIBS_DIR/$ABI/"
            print_success "Copied libsodium.a for $ABI"
        else
            print_error "libsodium library not found for $ABI"
        fi
    done
    
    print_success "All libraries copied to jniLibs/"
}

show_usage() {
    echo "Usage: $0 [command] [options]"
    echo ""
    echo "Commands:"
    echo "  all              Build everything (OpenSSL, libsodium, copy to jniLibs)"
    echo "  openssl          Build OpenSSL only"
    echo "  libsodium        Build libsodium only"
    echo "  copy             Copy built libraries to jniLibs only"
    echo "  clean            Clean all build directories"
    echo ""
    echo "Options:"
    echo "  <ABI>            Build for specific ABI (arm64-v8a, armeabi-v7a, x86, x86_64)"
    echo ""
    echo "Examples:"
    echo "  $0 all                          Build everything for all ABIs"
    echo "  $0 openssl arm64-v8a            Build OpenSSL for arm64-v8a only"
    echo "  $0 libsodium armeabi-v7a        Build libsodium for armeabi-v7a only"
    echo "  $0 copy                         Copy all built libraries to jniLibs"
}

# Main
if [ $# -eq 0 ]; then
    show_usage
    exit 0
fi

COMMAND="$1"
ABI="${2:-}"

case "$COMMAND" in
    all)
        print_header "Building all native libraries"
        print_info "This will build OpenSSL and libsodium for all ABIs"
        
        if [ -n "$ABI" ]; then
            print_info "Building for ABI: $ABI"
            cd "$SCRIPT_DIR"
            ./build-openssl.sh "$ABI"
            ./build-libsodium.sh "$ABI"
        else
            print_info "Building for all ABIs..."
            cd "$SCRIPT_DIR"
            ./build-openssl.sh
            ./build-libsodium.sh
        fi
        
        copy_libs
        
        print_header "Build Complete!"
        echo "Built libraries are available at:"
        echo "  - OpenSSL: $OPENSSL_BUILD_DIR/"
        echo "  - libsodium: $LIBSODIUM_BUILD_DIR/"
        echo "  - jniLibs: $JNILIBS_DIR/"
        ;;
    
    openssl)
        print_header "Building OpenSSL"
        cd "$SCRIPT_DIR"
        if [ -n "$ABI" ]; then
            ./build-openssl.sh "$ABI"
        else
            ./build-openssl.sh
        fi
        print_success "OpenSSL build complete!"
        ;;
    
    libsodium)
        print_header "Building libsodium"
        cd "$SCRIPT_DIR"
        if [ -n "$ABI" ]; then
            ./build-libsodium.sh "$ABI"
        else
            ./build-libsodium.sh
        fi
        print_success "libsodium build complete!"
        ;;
    
    copy)
        copy_libs
        ;;
    
    clean)
        print_header "Cleaning build directories"
        rm -rf "$OPENSSL_BUILD_DIR"/*
        rm -rf "$LIBSODIUM_BUILD_DIR"/*
        print_success "Build directories cleaned!"
        ;;
    
    help|--help|-h)
        show_usage
        ;;
    
    *)
        print_error "Unknown command: $COMMAND"
        show_usage
        exit 1
        ;;
esac

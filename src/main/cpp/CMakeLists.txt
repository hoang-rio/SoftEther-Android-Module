cmake_minimum_required(VERSION 3.22.1)
project("softetherclient")

# Find required libraries
find_library(log-lib log)
find_library(android-lib android)

# OpenSSL for crypto - using find_package if available, otherwise manual path
if(EXISTS "${ANDROID_HOME}/ndk/${ndkVersion}/toolchains/llvm/prebuilt/darwin-x86_64/sysroot/usr/lib")
    # Android NDK OpenSSL
    set(OPENSSL_ROOT_DIR "${ANDROID_HOME}/ndk/${ndkVersion}/toolchains/llvm/prebuilt/darwin-x86_64/sysroot/usr")
endif()

# Try to find OpenSSL package
find_package(OpenSSL QUIET)

# If OpenSSL not found, set paths manually
if(NOT OPENSSL_FOUND)
    message(STATUS "OpenSSL package not found, using manual paths")
    set(OPENSSL_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../../openssl/include")
    set(OPENSSL_LIBRARIES "ssl" "crypto")
endif()

# Include directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/softether-core/include
    ${OPENSSL_INCLUDE_DIR}
)

# Source files for main library
set(SOFTETHER_SOURCES
    jni/softether_jni.c
    softether-core/src/proto/softether_protocol.c
    softether-core/src/crypto/aes_wrapper.c
    softether-core/src/socket/tcp_socket.c
    softether-core/src/packet/packet_handler.c
    softether-core/src/packet/serializer.c
)

# Create main shared library
add_library(softether SHARED ${SOFTETHER_SOURCES})

# Link libraries for main library
target_link_libraries(softether
    ${log-lib}
    ${android-lib}
)

# Link OpenSSL if found
if(OPENSSL_FOUND)
    target_link_libraries(softether OpenSSL::SSL OpenSSL::Crypto)
else()
    target_link_libraries(softether ${OPENSSL_LIBRARIES})
endif()

# Test library sources
set(TEST_SOURCES
    test/native_test.c
    test/test_jni_bridge.c
    ${SOFTETHER_SOURCES}
)

# Create test shared library
add_library(softether_test SHARED ${TEST_SOURCES})

# Include directories for test library
target_include_directories(softether_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/softether-core/include
    ${CMAKE_CURRENT_SOURCE_DIR}/test
    ${OPENSSL_INCLUDE_DIR}
)

# Link libraries for test library
target_link_libraries(softether_test
    ${log-lib}
    ${android-lib}
)

# Link OpenSSL for test library
if(OPENSSL_FOUND)
    target_link_libraries(softether_test OpenSSL::SSL OpenSSL::Crypto)
else()
    target_link_libraries(softether_test ${OPENSSL_LIBRARIES})
endif()

# Export compile commands for IDE support
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

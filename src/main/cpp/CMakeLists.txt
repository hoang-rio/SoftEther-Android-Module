cmake_minimum_required(VERSION 3.22.1)
project("softetherclient")

set(CMAKE_C_STANDARD 11)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Find required libraries
find_library(log-lib log)
find_library(android-lib android)

# Directories
set(PREBUILT_JNILIBS_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../jniLibs)

# Prebuilt OpenSSL libraries
set(OPENSSL_ROOT ${PREBUILT_JNILIBS_DIR}/${ANDROID_ABI})
set(OPENSSL_LIBRARIES
    ${OPENSSL_ROOT}/libssl.a
    ${OPENSSL_ROOT}/libcrypto.a
)

# Check if prebuilt libraries exist
if(EXISTS ${OPENSSL_ROOT}/libssl.a AND EXISTS ${OPENSSL_ROOT}/libcrypto.a)
    message(STATUS "Using prebuilt OpenSSL from ${OPENSSL_ROOT}")
    set(USE_PREBUILT_OPENSSL TRUE)
else()
    message(WARNING "Prebuilt OpenSSL not found in ${OPENSSL_ROOT}, trying system OpenSSL")
    set(USE_PREBUILT_OPENSSL FALSE)
endif()

# Include directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/softether-core/include
    ${CMAKE_CURRENT_SOURCE_DIR}/openssl/include
)

# If prebuilt OpenSSL exists, also include its headers from build dir
if(USE_PREBUILT_OPENSSL)
    # OpenSSL headers are typically in the build directory after install
    # For now, we'll use the system headers or create a minimal include dir
    file(MAKE_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/openssl/include/openssl)
endif()

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

# Link prebuilt OpenSSL if available
if(USE_PREBUILT_OPENSSL)
    target_link_libraries(softether ${OPENSSL_LIBRARIES})
else()
    # Fallback to system OpenSSL
    target_link_libraries(softether ssl crypto)
endif()

# Compiler flags
target_compile_options(softether PRIVATE
    -Wall
    -Wno-unused-parameter
    -Wno-unused-variable
    -fPIC
)

# Debug/Release specific flags
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(softether PRIVATE -g -O0)
else()
    target_compile_options(softether PRIVATE -O2)
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
)

# Link libraries for test library
target_link_libraries(softether_test
    ${log-lib}
    ${android-lib}
)

# Link prebuilt OpenSSL for test library if available
if(USE_PREBUILT_OPENSSL)
    target_link_libraries(softether_test ${OPENSSL_LIBRARIES})
else()
    target_link_libraries(softether_test ssl crypto)
endif()

# Compiler flags for test library
target_compile_options(softether_test PRIVATE
    -Wall
    -Wno-unused-parameter
    -Wno-unused-variable
    -fPIC
)

# Export compile commands for IDE support
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

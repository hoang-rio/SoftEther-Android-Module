cmake_minimum_required(VERSION 3.22.1)
project(softether-native)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Directories
set(REIMPL_DIR ${CMAKE_CURRENT_LIST_DIR}/softether-native)
set(PREBUILT_JNILIBS_DIR ${CMAKE_CURRENT_LIST_DIR}/../jniLibs)

# Android platform settings
if(ANDROID)
    set(THREADS_PREFER_PTHREAD_FLAG OFF)
    set(CMAKE_THREAD_LIBS_INIT "")
    set(CMAKE_HAVE_THREADS_LIBRARY 1)
    set(CMAKE_USE_PTHREADS_INIT 1)
    set(CMAKE_HAVE_LIBC_PTHREAD 1)
    set(Threads_FOUND TRUE)
endif()

# Include directories
include_directories(${REIMPL_DIR})

# Source files for the reimplemented SoftEther protocol
set(SOFTETHER_NATIVE_SOURCES
    ${REIMPL_DIR}/softether_protocol.c
    ${REIMPL_DIR}/softether_jni_bridge.c
)

# Create the native library
add_library(softether-native SHARED ${SOFTETHER_NATIVE_SOURCES})

# Link libraries
target_link_libraries(softether-native
    android
    log
)

# Compiler flags for Android
target_compile_options(softether-native PRIVATE
    -Wall
    -Wextra
    -Wno-unused-parameter
    -Wno-unused-variable
    -fPIC
)

# Debug/Release specific flags
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(softether-native PRIVATE -g -O0 -DDEBUG)
else()
    target_compile_options(softether-native PRIVATE -O3 -DNDEBUG)
endif()

# Export all symbols for JNI
set_target_properties(softether-native PROPERTIES
    CXX_VISIBILITY_PRESET default
    VISIBILITY_INLINES_HIDDEN NO
)

# Installation rules (optional, for debugging)
install(TARGETS softether-native DESTINATION lib/${ANDROID_ABI})

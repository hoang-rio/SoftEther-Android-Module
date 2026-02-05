cmake_minimum_required(VERSION 3.22.1)
project(softether-android)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Directories
set(SOFTETHER_DIR ${CMAKE_CURRENT_LIST_DIR}/SoftEtherVPN/src)
set(OPENSSL_DIR   ${CMAKE_CURRENT_LIST_DIR}/openssl)
set(LIBSODIUM_DIR ${CMAKE_CURRENT_LIST_DIR}/libsodium)
set(PREBUILT_OPENSSL_DIR ${CMAKE_CURRENT_LIST_DIR}/openssl-build)
set(PREBUILT_JNILIBS_DIR ${CMAKE_CURRENT_LIST_DIR}/../jniLibs)
set(BUILD_DIRECTORY ${CMAKE_BINARY_DIR}/softether-build)
set(TOP_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}/SoftEtherVPN)
file(MAKE_DIRECTORY ${BUILD_DIRECTORY})

# Map ABI to OpenSSL android target
if(ANDROID_ABI STREQUAL "armeabi-v7a")
  set(OPENSSL_ANDROID_TARGET "android-arm")
elseif(ANDROID_ABI STREQUAL "arm64-v8a")
  set(OPENSSL_ANDROID_TARGET "android-arm64")
elseif(ANDROID_ABI STREQUAL "x86")
  set(OPENSSL_ANDROID_TARGET "android-x86")
elseif(ANDROID_ABI STREQUAL "x86_64")
  set(OPENSSL_ANDROID_TARGET "android-x86_64")
else()
  message(FATAL_ERROR "Unsupported ANDROID_ABI: ${ANDROID_ABI}")
endif()

set(OPENSSL_INSTALL_DIR ${PREBUILT_OPENSSL_DIR}/${ANDROID_ABI})

set(OPENSSL_ROOT_DIR ${OPENSSL_INSTALL_DIR})
set(OPENSSL_CRYPTO_LIBRARY ${OPENSSL_INSTALL_DIR}/lib/libcrypto.a)
set(OPENSSL_SSL_LIBRARY ${OPENSSL_INSTALL_DIR}/lib/libssl.a)
set(OPENSSL_INCLUDE_DIR ${OPENSSL_INSTALL_DIR}/include)

add_library(openssl-crypto STATIC IMPORTED)
add_library(openssl-ssl STATIC IMPORTED)
set_target_properties(openssl-crypto PROPERTIES IMPORTED_LOCATION ${OPENSSL_INSTALL_DIR}/lib/libcrypto.a)
set_target_properties(openssl-ssl    PROPERTIES IMPORTED_LOCATION ${OPENSSL_INSTALL_DIR}/lib/libssl.a)
set(OPENSSL_INCLUDE_DIR ${OPENSSL_INSTALL_DIR}/include)

# Use static libsodium library where possible
# Note: arm64-v8a static library has -fPIC issues, excluded from build.gradle
add_library(sodium STATIC IMPORTED)
set_target_properties(sodium PROPERTIES IMPORTED_LOCATION ${PREBUILT_JNILIBS_DIR}/${ANDROID_ABI}/libsodium.a)
set(SODIUM_INCLUDE_DIRS ${LIBSODIUM_DIR}/src/libsodium/include)

# SoftEther expects definitions
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
  add_definitions(-DCPU_64)
endif()
add_definitions(-D_REENTRANT -DREENTRANT -D_THREAD_SAFE -D_THREADSAFE -DTHREAD_SAFE -DTHREADSAFE -D_FILE_OFFSET_BITS=64)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
  add_definitions(-D_DEBUG -DDEBUG)
else()
  add_definitions(-DNDEBUG -DVPN_SPEED)
endif()
add_definitions(-DUNIX -DOS_UNIX -DUNIX_LINUX)

if(ANDROID)
  set(THREADS_PREFER_PTHREAD_FLAG OFF)
  set(CMAKE_THREAD_LIBS_INIT "")
  set(CMAKE_HAVE_THREADS_LIBRARY 1)
  set(CMAKE_USE_PTHREADS_INIT 1)
  set(CMAKE_USE_WIN32_THREADS_INIT 0)
  set(CMAKE_HAVE_LIBC_PTHREAD 1)
  set(CMAKE_THREAD_LIBS_INIT "-pthread")
  set(Threads_FOUND TRUE)
  
  # Android Bionic doesn't have iconv - use our shim
  add_definitions(-DANDROID_ICONV_SHIM)
  include_directories(${CMAKE_CURRENT_LIST_DIR})
endif()

include_directories(${SOFTETHER_DIR})
include_directories(${OPENSSL_INCLUDE_DIR})
include_directories(${SODIUM_INCLUDE_DIRS})

link_directories(${BUILD_DIRECTORY})

# Android iconv shim library (for Bionic libc) - MUST be created BEFORE Mayaqua
if(ANDROID)
  add_library(android-iconv-shim STATIC android_iconv_shim.c)
endif()

# Add libhamcore first (needed by Mayaqua)
add_subdirectory(${SOFTETHER_DIR}/libhamcore ${CMAKE_BINARY_DIR}/libhamcore)

# Add only Mayaqua and Cedar (skip executables for Android)
add_subdirectory(${SOFTETHER_DIR}/Mayaqua ${CMAKE_BINARY_DIR}/mayaqua)
add_subdirectory(${SOFTETHER_DIR}/Cedar ${CMAKE_BINARY_DIR}/cedar)

# JNI bridge implementation
add_library(softether-jni SHARED softether_jni.c)
target_link_libraries(softether-jni
  android
  log
  cedar
  mayaqua
  libhamcore
  openssl-ssl
  openssl-crypto
  sodium
)

if(ANDROID)
  target_link_libraries(softether-jni android-iconv-shim)
  # Also link iconv shim to mayaqua since it's a shared library
  target_link_libraries(mayaqua PRIVATE android-iconv-shim)
endif()

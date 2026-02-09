cmake_minimum_required(VERSION 3.22.1)
project(softether-native)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Directories
set(SOFTETHER_DIR ${CMAKE_CURRENT_LIST_DIR}/SoftEtherVPN/src)
set(STUBS_DIR ${CMAKE_CURRENT_LIST_DIR}/stubs)
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
include_directories(${CMAKE_CURRENT_LIST_DIR}/openssl/include)
include_directories(${CMAKE_CURRENT_LIST_DIR}/libsodium/src/libsodium/include)
include_directories(${SOFTETHER_DIR})
include_directories(${SOFTETHER_DIR}/Cedar)
include_directories(${SOFTETHER_DIR}/Mayaqua)
include_directories(${STUBS_DIR})

# OpenSSL libraries
set(OPENSSL_ROOT ${PREBUILT_JNILIBS_DIR}/${ANDROID_ABI})
set(OPENSSL_LIBRARIES
    ${OPENSSL_ROOT}/libssl.a
    ${OPENSSL_ROOT}/libcrypto.a
)

# libsodium library
set(SODIUM_LIBRARY ${OPENSSL_ROOT}/libsodium.a)

# SoftEther VPN Cedar sources (core library)
set(CEDAR_SOURCES
    ${SOFTETHER_DIR}/Cedar/Account.c
    ${SOFTETHER_DIR}/Cedar/Admin.c
    ${SOFTETHER_DIR}/Cedar/AzureClient.c
    ${SOFTETHER_DIR}/Cedar/Cedar.c
    ${SOFTETHER_DIR}/Cedar/Client.c
    ${SOFTETHER_DIR}/Cedar/CM.c
    ${SOFTETHER_DIR}/Cedar/Command.c
    ${SOFTETHER_DIR}/Cedar/Connection.c
    ${SOFTETHER_DIR}/Cedar/Console.c
    ${SOFTETHER_DIR}/Cedar/Database.c
    ${SOFTETHER_DIR}/Cedar/DDNS.c
    ${SOFTETHER_DIR}/Cedar/EM.c
    ${SOFTETHER_DIR}/Cedar/Hub.c
    ${SOFTETHER_DIR}/Cedar/IPC.c
    ${SOFTETHER_DIR}/Cedar/Layer3.c
    ${SOFTETHER_DIR}/Cedar/Link.c
    ${SOFTETHER_DIR}/Cedar/Listener.c
    ${SOFTETHER_DIR}/Cedar/Logging.c
    ${SOFTETHER_DIR}/Cedar/Nat.c
    ${SOFTETHER_DIR}/Cedar/NullLan.c
    ${SOFTETHER_DIR}/Cedar/Proto.c
    ${SOFTETHER_DIR}/Cedar/Proto_EtherIP.c
    ${SOFTETHER_DIR}/Cedar/Proto_IKE.c
    ${SOFTETHER_DIR}/Cedar/Proto_IkePacket.c
    ${SOFTETHER_DIR}/Cedar/Proto_IPsec.c
    ${SOFTETHER_DIR}/Cedar/Proto_L2TP.c
    ${SOFTETHER_DIR}/Cedar/Proto_OpenVPN.c
    ${SOFTETHER_DIR}/Cedar/Proto_PPP.c
    ${SOFTETHER_DIR}/Cedar/Proto_SSTP.c
    ${SOFTETHER_DIR}/Cedar/Proto_Win7.c
    ${SOFTETHER_DIR}/Cedar/Protocol.c
    ${SOFTETHER_DIR}/Cedar/Radius.c
    ${SOFTETHER_DIR}/Cedar/Remote.c
    ${SOFTETHER_DIR}/Cedar/Sam.c
    ${SOFTETHER_DIR}/Cedar/SecureNAT.c
    ${SOFTETHER_DIR}/Cedar/SeLowUser.c
    ${SOFTETHER_DIR}/Cedar/Server.c
    ${SOFTETHER_DIR}/Cedar/Session.c
    ${SOFTETHER_DIR}/Cedar/SM.c
    ${SOFTETHER_DIR}/Cedar/SW.c
    ${SOFTETHER_DIR}/Cedar/UT.c
    ${SOFTETHER_DIR}/Cedar/Virtual.c
    ${SOFTETHER_DIR}/Cedar/VLanUnix.c
    ${SOFTETHER_DIR}/Cedar/WaterMark.c
    ${SOFTETHER_DIR}/Cedar/WebUI.c
    ${SOFTETHER_DIR}/Cedar/Wpc.c
)

# Mayaqua sources (base library)
set(MAYAQUA_SOURCES
    ${SOFTETHER_DIR}/Mayaqua/Cfg.c
    ${SOFTETHER_DIR}/Mayaqua/DNS.c
    ${SOFTETHER_DIR}/Mayaqua/Encrypt.c
    ${SOFTETHER_DIR}/Mayaqua/FileIO.c
    ${SOFTETHER_DIR}/Mayaqua/HTTP.c
    ${SOFTETHER_DIR}/Mayaqua/Internat.c
    ${SOFTETHER_DIR}/Mayaqua/Kernel.c
    ${SOFTETHER_DIR}/Mayaqua/Mayaqua.c
    ${SOFTETHER_DIR}/Mayaqua/Memory.c
    ${SOFTETHER_DIR}/Mayaqua/Network.c
    ${SOFTETHER_DIR}/Mayaqua/Object.c
    ${SOFTETHER_DIR}/Mayaqua/OS.c
    ${SOFTETHER_DIR}/Mayaqua/Pack.c
    ${SOFTETHER_DIR}/Mayaqua/Proxy.c
    ${SOFTETHER_DIR}/Mayaqua/Secure.c
    ${SOFTETHER_DIR}/Mayaqua/Str.c
    ${SOFTETHER_DIR}/Mayaqua/Table.c
    ${SOFTETHER_DIR}/Mayaqua/TcpIp.c
    ${SOFTETHER_DIR}/Mayaqua/Tick64.c
    ${SOFTETHER_DIR}/Mayaqua/Tracking.c
    ${SOFTETHER_DIR}/Mayaqua/Unix.c
)

# Stub files for Android (replacing Windows-specific components)
set(STUB_SOURCES
    ${STUBS_DIR}/Bridge_stub.c
    ${STUBS_DIR}/Kernel_stub.c
)

# JNI Bridge source
set(JNI_SOURCES
    ${CMAKE_CURRENT_LIST_DIR}/softether_jni.c
)

# Create the native library
add_library(softether-native SHARED 
    ${JNI_SOURCES}
    ${CEDAR_SOURCES}
    ${MAYAQUA_SOURCES}
    ${STUB_SOURCES}
)

# Link libraries
target_link_libraries(softether-native
    android
    log
    ${OPENSSL_LIBRARIES}
    ${SODIUM_LIBRARY}
)

# Compiler flags for Android
target_compile_options(softether-native PRIVATE
    -Wall
    -Wextra
    -Wno-unused-parameter
    -Wno-unused-variable
    -Wno-sign-compare
    -Wno-missing-field-initializers
    -Wno-implicit-function-declaration
    -Wno-incompatible-pointer-types-discards-qualifiers
    -Wno-unused-function
    -Wno-unused-but-set-variable
    -Wno-format
    -Wno-int-conversion
    -fPIC
    -DUNIX
    -DUNIX_ANDROID
    -DOS_UNIX
    -D_REENTRANT
    -DOPENSSL_NO_SPEED
    -DNO_VLAN
    -DNO_BRIDGE
    -include stubs.h
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

/**
 * SoftEther VPN v4 JNI Bridge for Android
 * With Android Compatibility Patches
 */

#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <android/log.h>

#define WIN32COM_CPP

// Include Android patches first
#include "android_mayaqua_patch.h"

// SoftEther v4 includes
#include "Mayaqua/Mayaqua.h"
#include "Mayaqua/Kernel.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Network.h"
#include "Mayaqua/Str.h"
#include "Cedar/Cedar.h"
#include "Cedar/Client.h"

#define LOG_TAG "SoftEtherJNI"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

// Connection states (matching Java side)
#define STATE_DISCONNECTED  0
#define STATE_CONNECTING    1
#define STATE_CONNECTED     2
#define STATE_DISCONNECTING 3
#define STATE_ERROR         4

// Global state
static struct {
    JavaVM* jvm;
    CLIENT* client;
    bool initialized;
    int currentState;
    pthread_mutex_t state_mutex;
} g_state = {0};

// Helper to set state
static void setState(int state) {
    if (!g_state.initialized) {
        return;
    }
    pthread_mutex_lock(&g_state.state_mutex);
    g_state.currentState = state;
    pthread_mutex_unlock(&g_state.state_mutex);
    LOGD("State changed to: %d", state);
}

// Initialize Mayaqua/Cedar with Android patches
JNIEXPORT jboolean JNICALL
Java_vn_unlimit_softetherclient_SoftEtherClient_nativeInit(JNIEnv* env, jobject thiz)
{
    LOGD("nativeInit called");
    
    if (g_state.initialized) {
        LOGD("Already initialized");
        return JNI_TRUE;
    }
    
    // Save JVM reference
    if (g_state.jvm == NULL) {
        (*env)->GetJavaVM(env, &g_state.jvm);
    }
    
    // Initialize state mutex
    pthread_mutex_init(&g_state.state_mutex, NULL);
    
    // Initialize Android-specific patches
    LOGD("Calling AndroidMayaquaInit...");
    AndroidMayaquaInit();
    LOGD("AndroidMayaquaInit completed");
    
    // Use Mayaqua minimal mode - disables some threading features
    LOGD("Calling MayaquaMinimalMode...");
    MayaquaMinimalMode();
    LOGD("MayaquaMinimalMode completed");
    
    // Initialize Mayaqua with minimal threading
    // false = don't use supported_flash, false = don't use proactive_msec
    LOGD("Calling InitMayaqua...");
    
    // Set minimal mode before InitMayaqua (redundant but ensures it's set)
    MayaquaMinimalMode();
    
    // Call InitMayaqua with debug
    LOGD("About to call InitMayaqua...");
    
    // For Android: Use special init that skips network initialization in minimal mode
    // This prevents hanging on SSL/DH initialization which isn't needed for VPN client
    InitMayaqua(false, false, 0, NULL);
    LOGD("InitMayaqua returned!");
    
    // Initialize Cedar layer
    LOGD("Calling InitCedar...");
    InitCedar();
    LOGD("InitCedar completed");
    
    g_state.initialized = true;
    g_state.currentState = STATE_DISCONNECTED;
    
    LOGD("nativeInit completed successfully");
    return JNI_TRUE;
}

// Cleanup
JNIEXPORT void JNICALL
Java_vn_unlimit_softetherclient_SoftEtherClient_nativeCleanup(JNIEnv* env, jobject thiz)
{
    LOGD("nativeCleanup called");
    
    if (!g_state.initialized) {
        return;
    }
    
    pthread_mutex_lock(&g_state.state_mutex);
    
    if (g_state.client != NULL) {
        // Release the client properly
        CtReleaseClient(g_state.client);
        g_state.client = NULL;
    }
    
    pthread_mutex_unlock(&g_state.state_mutex);
    
    // Cleanup Cedar and Mayaqua
    FreeCedar();
    FreeMayaqua();
    
    // Cleanup Android-specific patches
    AndroidMayaquaCleanup();
    
    pthread_mutex_destroy(&g_state.state_mutex);
    
    g_state.initialized = false;
    g_state.currentState = STATE_DISCONNECTED;
    LOGD("nativeCleanup completed");
}

// Create account and connect (internal helper)
static bool doConnect(const char* host, int port, const char* hub, const char* user, const char* pass)
{
    if (!g_state.initialized) {
        LOGE("Not initialized");
        return false;
    }
    
    LOGI("Connecting to %s:%d, Hub: %s, User: %s", host, port, hub, user);
    
    pthread_mutex_lock(&g_state.state_mutex);
    
    // Create CLIENT object if not exists
    if (g_state.client == NULL) {
        g_state.client = CiNewClient();
        if (g_state.client == NULL) {
            pthread_mutex_unlock(&g_state.state_mutex);
            LOGE("Failed to create CLIENT");
            return false;
        }
    }
    
    // First, delete existing account if any
    RPC_CLIENT_DELETE_ACCOUNT deleteAcc;
    Zero(&deleteAcc, sizeof(deleteAcc));
    UniStrCpy(deleteAcc.AccountName, sizeof(deleteAcc.AccountName), L"AndroidVPN");
    CtDeleteAccount(g_state.client, &deleteAcc, false);
    
    // Create new account
    RPC_CLIENT_CREATE_ACCOUNT createAcc;
    Zero(&createAcc, sizeof(createAcc));
    
    // Client option
    createAcc.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
    UniStrCpy(createAcc.ClientOption->AccountName, sizeof(createAcc.ClientOption->AccountName), L"AndroidVPN");
    StrCpy(createAcc.ClientOption->Hostname, sizeof(createAcc.ClientOption->Hostname), (char*)host);
    createAcc.ClientOption->Port = port;
    StrCpy(createAcc.ClientOption->HubName, sizeof(createAcc.ClientOption->HubName), (char*)hub);
    createAcc.ClientOption->NumRetry = 3;
    createAcc.ClientOption->RetryInterval = 5;
    createAcc.ClientOption->UseEncrypt = true;
    createAcc.ClientOption->MaxConnection = 1;  // Reduced for Android
    StrCpy(createAcc.ClientOption->DeviceName, sizeof(createAcc.ClientOption->DeviceName), "VPN");
    
    // Client auth - use plain password auth
    createAcc.ClientAuth = ZeroMalloc(sizeof(CLIENT_AUTH));
    createAcc.ClientAuth->AuthType = CLIENT_AUTHTYPE_PLAIN_PASSWORD;
    StrCpy(createAcc.ClientAuth->Username, sizeof(createAcc.ClientAuth->Username), (char*)user);
    StrCpy(createAcc.ClientAuth->PlainPassword, sizeof(createAcc.ClientAuth->PlainPassword), (char*)pass);
    
    // Create the account
    bool result = CtCreateAccount(g_state.client, &createAcc, false);
    
    // Free the create account structure (CtCreateAccount copies data)
    Free(createAcc.ClientOption);
    CiFreeClientAuth(createAcc.ClientAuth);
    
    if (!result) {
        pthread_mutex_unlock(&g_state.state_mutex);
        LOGE("Failed to create account, error: %u", g_state.client->Err);
        return false;
    }
    
    LOGD("Account created successfully");
    
    // Now connect using CtConnect
    RPC_CLIENT_CONNECT connect;
    Zero(&connect, sizeof(connect));
    UniStrCpy(connect.AccountName, sizeof(connect.AccountName), L"AndroidVPN");
    
    g_state.currentState = STATE_CONNECTING;
    
    result = CtConnect(g_state.client, &connect);
    
    pthread_mutex_unlock(&g_state.state_mutex);
    
    if (result) {
        LOGD("CtConnect succeeded");
        setState(STATE_CONNECTED);
    } else {
        LOGE("CtConnect failed, error: %u", g_state.client->Err);
        setState(STATE_ERROR);
    }
    
    return result;
}

// Connect using v4 CtConnect API
JNIEXPORT jboolean JNICALL
Java_vn_unlimit_softetherclient_SoftEtherClient_nativeConnect(
    JNIEnv* env,
    jobject thiz,
    jstring host,
    jint port,
    jstring hub,
    jstring user,
    jstring pass,
    jint tunFd)
{
    LOGD("nativeConnect called");
    
    const char* hostStr = (*env)->GetStringUTFChars(env, host, NULL);
    const char* hubStr = (*env)->GetStringUTFChars(env, hub, NULL);
    const char* userStr = (*env)->GetStringUTFChars(env, user, NULL);
    const char* passStr = (*env)->GetStringUTFChars(env, pass, NULL);
    
    bool result = doConnect(hostStr, port, hubStr, userStr, passStr);
    
    // Cleanup strings
    (*env)->ReleaseStringUTFChars(env, host, hostStr);
    (*env)->ReleaseStringUTFChars(env, hub, hubStr);
    (*env)->ReleaseStringUTFChars(env, user, userStr);
    (*env)->ReleaseStringUTFChars(env, pass, passStr);
    
    // Note: tunFd handling would require additional integration with SoftEther
    // For now, we just store it for future use
    if (tunFd >= 0) {
        LOGD("TUN fd: %d (stored for future use)", tunFd);
    }
    
    return result ? JNI_TRUE : JNI_FALSE;
}

// Test function with hardcoded parameters
JNIEXPORT jboolean JNICALL
Java_vn_unlimit_softetherclient_SoftEtherClient_nativeConnectTest(JNIEnv* env, jobject thiz, jint tunFd)
{
    LOGD("nativeConnectTest called");
    
    // Hardcoded test parameters from the test file
    const char* host = "219.100.37.92";
    int port = 443;
    const char* hub = "VPN";
    const char* user = "vpn";
    const char* pass = "vpn";
    
    LOGI("Test connection to %s:%d, Hub: %s, User: %s", host, port, hub, user);
    
    bool result = doConnect(host, port, hub, user, pass);
    
    // Note: tunFd handling would require additional integration
    if (tunFd >= 0) {
        LOGD("TUN fd: %d (stored for future use)", tunFd);
    }
    
    return result ? JNI_TRUE : JNI_FALSE;
}

// Disconnect
JNIEXPORT void JNICALL
Java_vn_unlimit_softetherclient_SoftEtherClient_nativeDisconnect(JNIEnv* env, jobject thiz)
{
    LOGD("nativeDisconnect called");
    
    if (!g_state.initialized || g_state.client == NULL) {
        return;
    }
    
    setState(STATE_DISCONNECTING);
    
    pthread_mutex_lock(&g_state.state_mutex);
    
    // Disconnect using CtDisconnect
    RPC_CLIENT_CONNECT disconnect;
    Zero(&disconnect, sizeof(disconnect));
    UniStrCpy(disconnect.AccountName, sizeof(disconnect.AccountName), L"AndroidVPN");
    
    CtDisconnect(g_state.client, &disconnect, false);
    
    pthread_mutex_unlock(&g_state.state_mutex);
    
    setState(STATE_DISCONNECTED);
    LOGD("nativeDisconnect completed");
}

// Get connection status
JNIEXPORT jint JNICALL
Java_vn_unlimit_softetherclient_SoftEtherClient_nativeGetStatus(JNIEnv* env, jobject thiz)
{
    if (!g_state.initialized || g_state.client == NULL) {
        return STATE_DISCONNECTED;
    }
    
    pthread_mutex_lock(&g_state.state_mutex);
    
    // Get connection status for AndroidVPN account
    RPC_CLIENT_GET_CONNECTION_STATUS status;
    Zero(&status, sizeof(status));
    UniStrCpy(status.AccountName, sizeof(status.AccountName), L"AndroidVPN");
    
    bool result = CtGetAccountStatus(g_state.client, &status);
    
    int currentState = g_state.currentState;
    
    pthread_mutex_unlock(&g_state.state_mutex);
    
    if (result) {
        // Update internal state based on actual status
        if (status.Connected) {
            currentState = STATE_CONNECTED;
        } else if (status.Active) {
            currentState = STATE_CONNECTING;
        } else {
            currentState = STATE_DISCONNECTED;
        }
    }
    
    return currentState;
}

// Get connection statistics
JNIEXPORT jlongArray JNICALL
Java_vn_unlimit_softetherclient_SoftEtherClient_nativeGetStatistics(JNIEnv* env, jobject thiz)
{
    jlongArray result = (*env)->NewLongArray(env, 2);
    if (result == NULL) {
        return NULL;
    }
    
    jlong stats[2] = {0, 0}; // sent, received
    
    if (g_state.initialized && g_state.client != NULL) {
        pthread_mutex_lock(&g_state.state_mutex);
        
        RPC_CLIENT_GET_CONNECTION_STATUS status;
        Zero(&status, sizeof(status));
        UniStrCpy(status.AccountName, sizeof(status.AccountName), L"AndroidVPN");
        
        if (CtGetAccountStatus(g_state.client, &status)) {
            stats[0] = (jlong)status.TotalSendSize;
            stats[1] = (jlong)status.TotalRecvSize;
        }
        
        pthread_mutex_unlock(&g_state.state_mutex);
    }
    
    (*env)->SetLongArrayRegion(env, result, 0, 2, stats);
    return result;
}

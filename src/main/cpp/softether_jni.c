/**
 * SoftEther VPN JNI Bridge for Android
 *
 * This implementation provides a native interface between Android's Java layer
 * and the SoftEther VPN client library (Cedar/Mayaqua).
 *
 * Architecture:
 * - Uses SoftEther's IPC (Inter-Process Communication) layer for VPN connectivity
 * - Implements a packet adapter that bridges between Android TUN and SoftEther
 * - Runs the VPN session in a dedicated native thread
 */

#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <android/log.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>

// SoftEther includes
#include "SoftEtherVPN/src/Cedar/Cedar.h"
#include "SoftEtherVPN/src/Cedar/Client.h"
#include "SoftEtherVPN/src/Cedar/Session.h"
#include "SoftEtherVPN/src/Cedar/Connection.h"
#include "SoftEtherVPN/src/Cedar/IPC.h"
#include "SoftEtherVPN/src/Cedar/Virtual.h"
#include "SoftEtherVPN/src/Mayaqua/Mayaqua.h"
#include "SoftEtherVPN/src/Mayaqua/Kernel.h"
#include "SoftEtherVPN/src/Mayaqua/Memory.h"
#include "SoftEtherVPN/src/Mayaqua/Network.h"
#include "SoftEtherVPN/src/Mayaqua/Str.h"
#include "SoftEtherVPN/src/Mayaqua/Object.h"

#define LOG_TAG "SoftEtherJNI"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

// Connection states
#define JNI_STATE_DISCONNECTED  0
#define JNI_STATE_CONNECTING    1
#define JNI_STATE_CONNECTED     2
#define JNI_STATE_DISCONNECTING 3
#define JNI_STATE_ERROR         4

// Error codes - use SE_ prefix to avoid conflicts with SoftEther defines
#define SE_ERR_NO_ERROR                0
#define SE_ERR_CONNECT_FAILED          1
#define SE_ERR_AUTH_FAILED             2
#define SE_ERR_SERVER_CERT_INVALID     3
#define SE_ERR_DHCP_FAILED             4
#define SE_ERR_TUN_CREATE_FAILED       5

// Buffer sizes - use SE_ prefix to avoid conflicts
#define SE_MAX_PACKET_SIZE     8192
#define SE_TUN_READ_BUFFER     32768

// Global state
static struct {
    JavaVM* jvm;
    jobject javaClient;
    jmethodID onConnectionEstablished;
    jmethodID onError;
    jmethodID onBytesTransferred;
    jmethodID onPacketReceived;

    // SoftEther state
    CEDAR* cedar;
    IPC* ipc;
    SESSION* session;
    THREAD* sessionThread;
    THREAD* tunReadThread;

    // TUN state
    int tunFd;
    bool halt;
    bool connected;

    // Statistics
    UINT64 bytesSent;
    UINT64 bytesReceived;

    // Synchronization
    LOCK* lock;
    EVENT* haltEvent;

    // Packet adapter
    PACKET_ADAPTER* packetAdapter;
} g_client = {0};

// Forward declarations
static void ReportError(int errorCode, const char* message);
static void ReportConnectionEstablished(const char* virtualIp, const char* subnetMask, const char* dnsServer);
static void ReportBytesTransferred(UINT64 sent, UINT64 received);
static void InitMayaquaWrapper(void);
static void CleanupMayaquaWrapper(void);

// ============================================================================
// Packet Adapter Implementation for Android TUN
// ============================================================================

/**
 * Packet Adapter Init - Called when session starts
 */
static bool AndroidPaInit(SESSION* s)
{
    LOGD("PacketAdapter: Init");
    if (g_client.halt) {
        return false;
    }
    return true;
}

/**
 * Packet Adapter GetCancel - Returns cancel object for select/poll
 */
static CANCEL* AndroidPaGetCancel(SESSION* s)
{
    LOGD("PacketAdapter: GetCancel");
    return NewCancel();
}

/**
 * Packet Adapter GetNextPacket - Read packet from TUN interface
 * This is called by SoftEther to get outgoing packets to send to the VPN server
 */
static UINT AndroidPaGetNextPacket(SESSION* s, void** data)
{
    if (g_client.halt || g_client.tunFd < 0) {
        return 0;
    }

    // For now, return 0 packets - the actual packet reading is done in TunReadThread
    // and passed via tube mechanism. This is a simplified approach.
    return 0;
}

/**
 * Packet Adapter PutPacket - Write packet to TUN interface
 * This is called by SoftEther when a packet is received from the VPN server
 */
static bool AndroidPaPutPacket(SESSION* s, void* data, UINT size)
{
    if (g_client.halt || g_client.tunFd < 0 || data == NULL || size == 0) {
        if (data != NULL) {
            Free(data);
        }
        return false;
    }

    // Write packet to TUN interface
    ssize_t written = write(g_client.tunFd, data, size);
    if (written < 0) {
        LOGE("Failed to write to TUN: %s", strerror(errno));
        Free(data);
        return false;
    }

    g_client.bytesReceived += size;
    Free(data);
    return true;
}

/**
 * Packet Adapter Free - Cleanup
 */
static void AndroidPaFree(SESSION* s)
{
    LOGD("PacketAdapter: Free");
}

/**
 * Create packet adapter for Android TUN
 */
static PACKET_ADAPTER* NewAndroidPacketAdapter(void)
{
    return NewPacketAdapter(
        AndroidPaInit,
        AndroidPaGetCancel,
        AndroidPaGetNextPacket,
        AndroidPaPutPacket,
        AndroidPaFree
    );
}

// ============================================================================
// TUN Interface Handling
// ============================================================================

/**
 * TUN Read Thread - Reads packets from TUN and sends to SoftEther
 */
static void TunReadThreadProc(THREAD* thread, void* param)
{
    UCHAR buffer[SE_TUN_READ_BUFFER];

    LOGD("TUN Read Thread started");

    while (!g_client.halt && g_client.tunFd >= 0) {
        // Read packet from TUN
        ssize_t len = read(g_client.tunFd, buffer, sizeof(buffer));

        if (len < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // No data available, wait a bit
                SleepThread(1);
                continue;
            }
            if (errno == EBADF || errno == EINVAL) {
                // TUN interface closed
                break;
            }
            LOGE("TUN read error: %s", strerror(errno));
            break;
        }

        if (len == 0) {
            continue;
        }

        // Update statistics
        g_client.bytesSent += len;

        // Send packet to VPN server via session's connection
        if (g_client.ipc != NULL) {
            IPCSendIPv4(g_client.ipc, buffer, (UINT)len);
        }

        // Report statistics periodically (every 1MB)
        static UINT64 lastReported = 0;
        if ((g_client.bytesSent + g_client.bytesReceived) - lastReported > 1048576) {
            ReportBytesTransferred(g_client.bytesSent, g_client.bytesReceived);
            lastReported = g_client.bytesSent + g_client.bytesReceived;
        }
    }

    LOGD("TUN Read Thread ended");
}

// ============================================================================
// JNI Bridge Functions
// ============================================================================

JNIEXPORT jboolean JNICALL
Java_vn_unlimit_softetherclient_SoftEtherClient_nativeInit(JNIEnv* env, jobject thiz)
{
    LOGD("nativeInit called");

    if (g_client.jvm == NULL) {
        (*env)->GetJavaVM(env, &g_client.jvm);
    }

    // Store global reference to Java client
    if (g_client.javaClient != NULL) {
        (*env)->DeleteGlobalRef(env, g_client.javaClient);
    }
    g_client.javaClient = (*env)->NewGlobalRef(env, thiz);

    // Cache method IDs
    jclass cls = (*env)->GetObjectClass(env, g_client.javaClient);
    g_client.onConnectionEstablished = (*env)->GetMethodID(env, cls, "onConnectionEstablished",
        "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V");
    g_client.onError = (*env)->GetMethodID(env, cls, "onError", "(ILjava/lang/String;)V");
    g_client.onBytesTransferred = (*env)->GetMethodID(env, cls, "onBytesTransferred", "(JJ)V");
    g_client.onPacketReceived = (*env)->GetMethodID(env, cls, "onPacketReceived", "([B)V");

    // Check if method IDs were found
    if (g_client.onConnectionEstablished == NULL ||
        g_client.onError == NULL ||
        g_client.onBytesTransferred == NULL ||
        g_client.onPacketReceived == NULL) {
        LOGE("Failed to cache method IDs - check method signatures match Java class");
        (*env)->DeleteGlobalRef(env, g_client.javaClient);
        g_client.javaClient = NULL;
        return JNI_FALSE;
    }

    // Initialize SoftEther libraries
    InitMayaquaWrapper();

    // Initialize synchronization
    g_client.lock = NewLock();
    g_client.haltEvent = NewEvent();
    g_client.halt = false;
    g_client.connected = false;

    LOGD("nativeInit completed successfully");
    return JNI_TRUE;
}

JNIEXPORT void JNICALL
Java_vn_unlimit_softetherclient_SoftEtherClient_nativeCleanup(JNIEnv* env, jobject thiz)
{
    LOGD("nativeCleanup called");

    // Disconnect if still connected
    if (g_client.connected) {
        // Call disconnect directly
        if (g_client.lock != NULL) {
            Lock(g_client.lock);

            if (g_client.connected) {
                g_client.halt = true;
                g_client.connected = false;

                if (g_client.haltEvent != NULL) {
                    Set(g_client.haltEvent);
                }
            }

            Unlock(g_client.lock);

            // Wait for TUN read thread to finish
            if (g_client.tunReadThread != NULL) {
                WaitThread(g_client.tunReadThread, INFINITE);
                ReleaseThread(g_client.tunReadThread);
                g_client.tunReadThread = NULL;
            }

            Lock(g_client.lock);

            // Free IPC
            if (g_client.ipc != NULL) {
                FreeIPC(g_client.ipc);
                g_client.ipc = NULL;
            }

            // Free packet adapter
            if (g_client.packetAdapter != NULL) {
                FreePacketAdapter(g_client.packetAdapter);
                g_client.packetAdapter = NULL;
            }

            // Release Cedar
            if (g_client.cedar != NULL) {
                ReleaseCedar(g_client.cedar);
                g_client.cedar = NULL;
            }

            // Close TUN fd
            if (g_client.tunFd >= 0) {
                close(g_client.tunFd);
                g_client.tunFd = -1;
            }

            g_client.bytesSent = 0;
            g_client.bytesReceived = 0;

            Unlock(g_client.lock);
        }
    }

    // Cleanup synchronization
    if (g_client.haltEvent != NULL) {
        ReleaseEvent(g_client.haltEvent);
        g_client.haltEvent = NULL;
    }

    if (g_client.lock != NULL) {
        DeleteLock(g_client.lock);
        g_client.lock = NULL;
    }

    // Cleanup SoftEther libraries
    CleanupMayaquaWrapper();

    // Release global reference
    if (g_client.javaClient != NULL) {
        (*env)->DeleteGlobalRef(env, g_client.javaClient);
        g_client.javaClient = NULL;
    }

    LOGD("nativeCleanup completed");
}

JNIEXPORT jboolean JNICALL
Java_vn_unlimit_softetherclient_SoftEtherClient_nativeConnect(
    JNIEnv* env,
    jobject thiz,
    jobject params,
    jint tunFd)
{
    LOGD("nativeConnect called with tunFd=%d", tunFd);

    Lock(g_client.lock);

    if (g_client.connected) {
        LOGE("Already connected");
        Unlock(g_client.lock);
        return JNI_FALSE;
    }

    // Store TUN fd
    g_client.tunFd = tunFd;
    g_client.halt = false;

    // Get connection parameters from Java object
    jclass paramsClass = (*env)->GetObjectClass(env, params);

    jfieldID serverHostField = (*env)->GetFieldID(env, paramsClass, "serverHost", "Ljava/lang/String;");
    jfieldID serverPortField = (*env)->GetFieldID(env, paramsClass, "serverPort", "I");
    jfieldID hubNameField = (*env)->GetFieldID(env, paramsClass, "hubName", "Ljava/lang/String;");
    jfieldID usernameField = (*env)->GetFieldID(env, paramsClass, "username", "Ljava/lang/String;");
    jfieldID passwordField = (*env)->GetFieldID(env, paramsClass, "password", "Ljava/lang/String;");
    jfieldID useEncryptField = (*env)->GetFieldID(env, paramsClass, "useEncrypt", "Z");

    jstring serverHost = (jstring)(*env)->GetObjectField(env, params, serverHostField);
    jint serverPort = (*env)->GetIntField(env, params, serverPortField);
    jstring hubName = (jstring)(*env)->GetObjectField(env, params, hubNameField);
    jstring username = (jstring)(*env)->GetObjectField(env, params, usernameField);
    jstring password = (jstring)(*env)->GetObjectField(env, params, passwordField);
    jboolean useEncrypt = (*env)->GetBooleanField(env, params, useEncryptField);

    const char* serverHostStr = (*env)->GetStringUTFChars(env, serverHost, NULL);
    const char* hubNameStr = (*env)->GetStringUTFChars(env, hubName, NULL);
    const char* usernameStr = (*env)->GetStringUTFChars(env, username, NULL);
    const char* passwordStr = (*env)->GetStringUTFChars(env, password, NULL);

    LOGI("Connecting to %s:%d, Hub: %s, User: %s", serverHostStr, serverPort, hubNameStr, usernameStr);

    // Create Cedar instance
    g_client.cedar = NewCedar(NULL, NULL);
    if (g_client.cedar == NULL) {
        LOGE("Failed to create Cedar");
        ReportError(SE_ERR_CONNECT_FAILED, "Failed to create VPN client");
        goto cleanup;
    }

    // Create IPC parameters
    IPC_PARAM ipcParam;
    Zero(&ipcParam, sizeof(ipcParam));

    StrCpy(ipcParam.ClientName, sizeof(ipcParam.ClientName), "SoftEtherAndroid");
    StrCpy(ipcParam.HubName, sizeof(ipcParam.HubName), hubNameStr);
    StrCpy(ipcParam.UserName, sizeof(ipcParam.UserName), usernameStr);
    StrCpy(ipcParam.Password, sizeof(ipcParam.Password), passwordStr);

    // Set server address
    IP serverIp;
    Zero(&serverIp, sizeof(serverIp));
    // Try to parse as IP first, otherwise let SoftEther handle hostname resolution
    if (!StrToIP(&serverIp, (char*)serverHostStr)) {
        // If not a valid IP string, SoftEther will resolve the hostname
        // Set a dummy IP for now (will be resolved by NewIPCByParam)
        StrToIP(&serverIp, "0.0.0.0");
    }

    Copy(&ipcParam.ServerIp, &serverIp, sizeof(IP));
    ipcParam.ServerPort = serverPort;

    // Get local IP
    IP clientIp;
    GetLocalHostIP4(&clientIp);
    Copy(&ipcParam.ClientIp, &clientIp, sizeof(IP));
    ipcParam.ClientPort = 0; // Let system assign

    StrCpy(ipcParam.CryptName, sizeof(ipcParam.CryptName), useEncrypt ? "AES128-GCM-SHA256" : "NULL");
    ipcParam.BridgeMode = false;
    ipcParam.Mss = 1400;
    ipcParam.Layer = IPC_LAYER_3; // Use Layer 3 mode for TUN

    // Connect via IPC
    UINT errorCode = 0;
    g_client.ipc = NewIPCByParam(g_client.cedar, &ipcParam, &errorCode);

    if (g_client.ipc == NULL) {
        LOGE("Failed to create IPC, error: %u", errorCode);

        int clientError = SE_ERR_CONNECT_FAILED;
        if (errorCode == ERR_AUTH_FAILED) {
            clientError = SE_ERR_AUTH_FAILED;
        } else if (errorCode == ERR_CERT_NOT_TRUSTED) {
            clientError = SE_ERR_SERVER_CERT_INVALID;
        }

        ReportError(clientError, "Connection failed");
        goto cleanup;
    }

    LOGI("IPC connection established");

    // Get assigned IP configuration
    char virtualIp[64] = {0};
    char subnetMask[64] = {0};
    char dnsServer[64] = {0};

    IPToStr(virtualIp, sizeof(virtualIp), &g_client.ipc->ClientIPAddress);
    IPToStr(subnetMask, sizeof(subnetMask), &g_client.ipc->SubnetMask);

    // Get DNS if available
    if (!IsZeroIP(&g_client.ipc->DefaultGateway)) {
        IPToStr(dnsServer, sizeof(dnsServer), &g_client.ipc->DefaultGateway);
    }

    LOGI("Virtual IP: %s, Subnet: %s, DNS: %s", virtualIp, subnetMask, dnsServer);

    // Create packet adapter
    g_client.packetAdapter = NewAndroidPacketAdapter();

    // Mark as connected
    g_client.connected = true;

    // Start TUN read thread
    g_client.tunReadThread = NewThread(TunReadThreadProc, NULL);

    // Report success
    ReportConnectionEstablished(virtualIp, subnetMask, dnsServer);

    Unlock(g_client.lock);

    // Cleanup strings
    (*env)->ReleaseStringUTFChars(env, serverHost, serverHostStr);
    (*env)->ReleaseStringUTFChars(env, hubName, hubNameStr);
    (*env)->ReleaseStringUTFChars(env, username, usernameStr);
    (*env)->ReleaseStringUTFChars(env, password, passwordStr);

    LOGD("nativeConnect completed successfully");
    return JNI_TRUE;

cleanup:
    Unlock(g_client.lock);

    // Cleanup strings
    (*env)->ReleaseStringUTFChars(env, serverHost, serverHostStr);
    (*env)->ReleaseStringUTFChars(env, hubName, hubNameStr);
    (*env)->ReleaseStringUTFChars(env, username, usernameStr);
    (*env)->ReleaseStringUTFChars(env, password, passwordStr);

    // Cleanup on failure
    if (g_client.ipc != NULL) {
        FreeIPC(g_client.ipc);
        g_client.ipc = NULL;
    }

    if (g_client.cedar != NULL) {
        ReleaseCedar(g_client.cedar);
        g_client.cedar = NULL;
    }

    return JNI_FALSE;
}

JNIEXPORT void JNICALL
Java_vn_unlimit_softetherclient_SoftEtherClient_nativeDisconnect(JNIEnv* env, jobject thiz)
{
    LOGD("nativeDisconnect called");

    if (g_client.lock == NULL) {
        return;
    }

    Lock(g_client.lock);

    if (!g_client.connected) {
        Unlock(g_client.lock);
        return;
    }

    g_client.halt = true;
    g_client.connected = false;

    // Signal halt event
    if (g_client.haltEvent != NULL) {
        Set(g_client.haltEvent);
    }

    Unlock(g_client.lock);

    // Wait for TUN read thread to finish
    if (g_client.tunReadThread != NULL) {
        WaitThread(g_client.tunReadThread, INFINITE);
        ReleaseThread(g_client.tunReadThread);
        g_client.tunReadThread = NULL;
    }

    Lock(g_client.lock);

    // Free IPC
    if (g_client.ipc != NULL) {
        FreeIPC(g_client.ipc);
        g_client.ipc = NULL;
    }

    // Free packet adapter
    if (g_client.packetAdapter != NULL) {
        FreePacketAdapter(g_client.packetAdapter);
        g_client.packetAdapter = NULL;
    }

    // Release Cedar
    if (g_client.cedar != NULL) {
        ReleaseCedar(g_client.cedar);
        g_client.cedar = NULL;
    }

    // Close TUN fd
    if (g_client.tunFd >= 0) {
        close(g_client.tunFd);
        g_client.tunFd = -1;
    }

    g_client.bytesSent = 0;
    g_client.bytesReceived = 0;

    Unlock(g_client.lock);

    LOGD("nativeDisconnect completed");
}

JNIEXPORT jint JNICALL
Java_vn_unlimit_softetherclient_SoftEtherClient_nativeGetStatus(JNIEnv* env, jobject thiz)
{
    Lock(g_client.lock);
    jint status = g_client.connected ? JNI_STATE_CONNECTED : JNI_STATE_DISCONNECTED;
    Unlock(g_client.lock);
    return status;
}

JNIEXPORT jlongArray JNICALL
Java_vn_unlimit_softetherclient_SoftEtherClient_nativeGetStatistics(JNIEnv* env, jobject thiz)
{
    jlongArray result = (*env)->NewLongArray(env, 2);
    if (result == NULL) {
        return NULL;
    }

    Lock(g_client.lock);
    jlong stats[2] = {
        (jlong)g_client.bytesSent,
        (jlong)g_client.bytesReceived
    };
    Unlock(g_client.lock);

    (*env)->SetLongArrayRegion(env, result, 0, 2, stats);
    return result;
}

// ============================================================================
// Helper Functions
// ============================================================================

static void ReportError(int errorCode, const char* message)
{
    if (g_client.jvm == NULL || g_client.javaClient == NULL) {
        return;
    }

    JNIEnv* env;
    jint attachResult = (*g_client.jvm)->AttachCurrentThread(g_client.jvm, &env, NULL);
    if (attachResult != JNI_OK) {
        LOGE("Failed to attach thread to JVM");
        return;
    }

    jstring jMessage = (*env)->NewStringUTF(env, message);
    (*env)->CallVoidMethod(env, g_client.javaClient, g_client.onError, errorCode, jMessage);
    (*env)->DeleteLocalRef(env, jMessage);

    // Don't detach if we attached the thread - it might be needed later
}

static void ReportConnectionEstablished(const char* virtualIp, const char* subnetMask, const char* dnsServer)
{
    if (g_client.jvm == NULL || g_client.javaClient == NULL) {
        return;
    }

    JNIEnv* env;
    jint attachResult = (*g_client.jvm)->AttachCurrentThread(g_client.jvm, &env, NULL);
    if (attachResult != JNI_OK) {
        LOGE("Failed to attach thread to JVM");
        return;
    }

    jstring jVirtualIp = (*env)->NewStringUTF(env, virtualIp);
    jstring jSubnetMask = (*env)->NewStringUTF(env, subnetMask);
    jstring jDnsServer = (*env)->NewStringUTF(env, dnsServer);

    (*env)->CallVoidMethod(env, g_client.javaClient, g_client.onConnectionEstablished,
        jVirtualIp, jSubnetMask, jDnsServer);

    (*env)->DeleteLocalRef(env, jVirtualIp);
    (*env)->DeleteLocalRef(env, jSubnetMask);
    (*env)->DeleteLocalRef(env, jDnsServer);
}

static void ReportBytesTransferred(UINT64 sent, UINT64 received)
{
    if (g_client.jvm == NULL || g_client.javaClient == NULL) {
        return;
    }

    JNIEnv* env;
    jint attachResult = (*g_client.jvm)->AttachCurrentThread(g_client.jvm, &env, NULL);
    if (attachResult != JNI_OK) {
        return;
    }

    (*env)->CallVoidMethod(env, g_client.javaClient, g_client.onBytesTransferred,
        (jlong)sent, (jlong)received);
}

static void InitMayaquaWrapper(void)
{
    // Initialize Mayaqua/SoftEther libraries
    // Use minimal mode for Android to avoid checks that call exit()
    // (e.g., executable file existence check, /tmp check)
    MayaquaMinimalMode();
    
    // Initialize with minimal flags - avoid the standard initialization
    // that calls exit() on Android
    InitMayaqua(false, false, 0, NULL);
    InitCedar();
}

static void CleanupMayaquaWrapper(void)
{
    FreeCedar();
    FreeMayaqua();
}

// ============================================================================
// Legacy Stub Functions (for backward compatibility)
// ============================================================================

// Legacy init function - kept for compatibility
JNIEXPORT jint JNICALL
Java_vn_unlimit_softetherclient_NativeStub_init(JNIEnv* env, jobject thiz)
{
    LOGD("Legacy NativeStub.init called - redirecting to new implementation");
    return Java_vn_unlimit_softetherclient_SoftEtherClient_nativeInit(env, thiz) ? 1 : 0;
}

/**
 * JNI Bridge for SoftEther VPN Reimplementation
 *
 * This provides the Java Native Interface between Android's Java layer
 * and the reimplemented SoftEther protocol.
 */

#include <jni.h>
#include <stdlib.h>
#include <string.h>
#include <android/log.h>
#include "softether_protocol.h"

#define LOG_TAG "SoftEtherJNIBridge"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

// Global JVM reference
static JavaVM* g_jvm = NULL;

// Connection state callbacks structure
typedef struct {
    jobject java_client;
    jmethodID on_connected;
    jmethodID on_disconnected;
    jmethodID on_error;
    jmethodID on_bytes_transferred;
    jmethodID on_packet_received;
} jni_callback_data_t;

// Native connection handle wrapper
typedef struct {
    se_connection_t* conn;
    jni_callback_data_t callbacks;
    int tun_fd;
} native_handle_t;

// Map error codes between native and Java
static jint map_error_code(int native_error) {
    switch (native_error) {
        case SE_ERR_SUCCESS:              return 0;   // ERR_NO_ERROR
        case SE_ERR_CONNECT_FAILED:       return 1;   // ERR_CONNECT_FAILED
        case SE_ERR_AUTH_FAILED:          return 2;   // ERR_AUTH_FAILED
        case SE_ERR_SSL_HANDSHAKE_FAILED: return 3;   // ERR_SERVER_CERT_INVALID
        case SE_ERR_DHCP_FAILED:          return 4;   // ERR_DHCP_FAILED
        case SE_ERR_TUN_FAILED:           return 5;   // ERR_TUN_CREATE_FAILED
        default:                          return 1;   // Default to connect failed
    }
}

// Map state codes between native and Java
static jint map_state(int native_state) {
    switch (native_state) {
        case SE_STATE_DISCONNECTED:   return 0;
        case SE_STATE_CONNECTING:     return 1;
        case SE_STATE_CONNECTED:      return 2;
        case SE_STATE_DISCONNECTING:  return 3;
        case SE_STATE_ERROR:          return 4;
        default:                      return 0;
    }
}

// JNI OnLoad
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved) {
    g_jvm = vm;
    LOGD("JNI_OnLoad called");
    return JNI_VERSION_1_6;
}

// Helper to get JNIEnv
static JNIEnv* get_jni_env(void) {
    JNIEnv* env = NULL;
    if (g_jvm) {
        jint ret = (*g_jvm)->GetEnv(g_jvm, (void**)&env, JNI_VERSION_1_6);
        if (ret == JNI_EDETACHED) {
            if ((*g_jvm)->AttachCurrentThread(g_jvm, &env, NULL) != 0) {
                return NULL;
            }
        }
    }
    return env;
}

// Native callback: on_connected
static void native_on_connected(se_connection_t* conn, const se_network_config_t* config) {
    native_handle_t* handle = (native_handle_t*)conn->user_data;
    if (!handle) return;

    JNIEnv* env = get_jni_env();
    if (!env) return;

    // Convert IP addresses to strings
    char client_ip[16], subnet_mask[16], dns1[16];
    se_ip_int_to_string(config->client_ip, client_ip, sizeof(client_ip));
    se_ip_int_to_string(config->subnet_mask, subnet_mask, sizeof(subnet_mask));
    se_ip_int_to_string(config->dns1, dns1, sizeof(dns1));

    jstring jClientIp = (*env)->NewStringUTF(env, client_ip);
    jstring jSubnetMask = (*env)->NewStringUTF(env, subnet_mask);
    jstring jDns = (*env)->NewStringUTF(env, dns1);

    (*env)->CallVoidMethod(env, handle->callbacks.java_client,
                          handle->callbacks.on_connected,
                          jClientIp, jSubnetMask, jDns);

    (*env)->DeleteLocalRef(env, jClientIp);
    (*env)->DeleteLocalRef(env, jSubnetMask);
    (*env)->DeleteLocalRef(env, jDns);
}

// Native callback: on_disconnected
static void native_on_disconnected(se_connection_t* conn, int reason) {
    native_handle_t* handle = (native_handle_t*)conn->user_data;
    if (!handle) return;

    JNIEnv* env = get_jni_env();
    if (!env) return;

    // Notify Java layer
    LOGD("Native on_disconnected: reason=%d", reason);
}

// Native callback: on_error
static void native_on_error(se_connection_t* conn, int error_code, const char* message) {
    native_handle_t* handle = (native_handle_t*)conn->user_data;
    if (!handle) return;

    JNIEnv* env = get_jni_env();
    if (!env) return;

    jint jErrorCode = map_error_code(error_code);
    jstring jMessage = (*env)->NewStringUTF(env, message ? message : "Unknown error");

    (*env)->CallVoidMethod(env, handle->callbacks.java_client,
                          handle->callbacks.on_error,
                          jErrorCode, jMessage);

    (*env)->DeleteLocalRef(env, jMessage);
}

// ============================================================================
// JNI Methods
// ============================================================================

JNIEXPORT jlong JNICALL
Java_vn_unlimit_softetherclient_SoftEtherNative_nativeInit(JNIEnv* env, jobject thiz) {
    LOGD("nativeInit called");

    native_handle_t* handle = (native_handle_t*)calloc(1, sizeof(native_handle_t));
    if (!handle) {
        LOGE("Failed to allocate native handle");
        return 0;
    }

    handle->conn = se_connection_new();
    if (!handle->conn) {
        LOGE("Failed to create connection");
        free(handle);
        return 0;
    }

    handle->tun_fd = -1;
    handle->conn->user_data = handle;
    handle->conn->on_connected = native_on_connected;
    handle->conn->on_disconnected = native_on_disconnected;
    handle->conn->on_error = native_on_error;

    // Cache Java callbacks
    handle->callbacks.java_client = (*env)->NewGlobalRef(env, thiz);
    jclass cls = (*env)->GetObjectClass(env, thiz);
    handle->callbacks.on_connected = (*env)->GetMethodID(env, cls, "onConnectionEstablished",
                                                          "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V");
    handle->callbacks.on_error = (*env)->GetMethodID(env, cls, "onError",
                                                     "(ILjava/lang/String;)V");
    handle->callbacks.on_bytes_transferred = (*env)->GetMethodID(env, cls, "onBytesTransferred",
                                                                  "(JJ)V");
    handle->callbacks.on_packet_received = (*env)->GetMethodID(env, cls, "onPacketReceived",
                                                                "([B)V");

    LOGD("nativeInit completed, handle=%p", (void*)handle);
    return (jlong)handle;
}

JNIEXPORT void JNICALL
Java_vn_unlimit_softetherclient_SoftEtherNative_nativeCleanup(JNIEnv* env, jobject thiz, jlong handle) {
    LOGD("nativeCleanup called, handle=%p", (void*)handle);

    native_handle_t* h = (native_handle_t*)handle;
    if (!h) return;

    if (h->conn) {
        se_connection_free(h->conn);
    }

    if (h->callbacks.java_client) {
        (*env)->DeleteGlobalRef(env, h->callbacks.java_client);
    }

    free(h);
    LOGD("nativeCleanup completed");
}

JNIEXPORT jboolean JNICALL
Java_vn_unlimit_softetherclient_SoftEtherNative_nativeConnect(JNIEnv* env, jobject thiz,
                                                               jlong handle,
                                                               jstring serverHost,
                                                               jint serverPort,
                                                               jstring hubName,
                                                               jstring username,
                                                               jstring password,
                                                               jboolean useEncrypt,
                                                               jboolean useCompress,
                                                               jboolean checkServerCert,
                                                               jint tunFd) {
    LOGD("nativeConnect called, handle=%p", (void*)handle);

    native_handle_t* h = (native_handle_t*)handle;
    if (!h || !h->conn) {
        LOGE("Invalid handle");
        return JNI_FALSE;
    }

    // Extract strings
    const char* c_serverHost = (*env)->GetStringUTFChars(env, serverHost, NULL);
    const char* c_hubName = (*env)->GetStringUTFChars(env, hubName, NULL);
    const char* c_username = (*env)->GetStringUTFChars(env, username, NULL);
    const char* c_password = (*env)->GetStringUTFChars(env, password, NULL);

    // Build connection parameters
    se_connection_params_t params;
    memset(&params, 0, sizeof(params));

    strncpy(params.server_host, c_serverHost, SE_MAX_HOSTNAME_LEN - 1);
    params.server_port = serverPort;
    strncpy(params.hub_name, c_hubName, SE_MAX_HUBNAME_LEN - 1);
    strncpy(params.username, c_username, SE_MAX_USERNAME_LEN - 1);
    strncpy(params.password, c_password, SE_MAX_PASSWORD_LEN - 1);
    params.use_encrypt = useEncrypt;
    params.use_compress = useCompress;
    params.verify_server_cert = checkServerCert;
    params.mtu = 1400;

    // Release strings
    (*env)->ReleaseStringUTFChars(env, serverHost, c_serverHost);
    (*env)->ReleaseStringUTFChars(env, hubName, c_hubName);
    (*env)->ReleaseStringUTFChars(env, username, c_username);
    (*env)->ReleaseStringUTFChars(env, password, c_password);

    // Set TUN fd
    h->tun_fd = tunFd;
    se_connection_set_tun_fd(h->conn, tunFd);

    // Connect
    int result = se_connection_connect(h->conn, &params);

    LOGD("nativeConnect result: %d", result);
    return (result == SE_ERR_SUCCESS) ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT void JNICALL
Java_vn_unlimit_softetherclient_SoftEtherNative_nativeDisconnect(JNIEnv* env, jobject thiz, jlong handle) {
    LOGD("nativeDisconnect called, handle=%p", (void*)handle);

    native_handle_t* h = (native_handle_t*)handle;
    if (!h || !h->conn) return;

    se_connection_disconnect(h->conn);
    LOGD("nativeDisconnect completed");
}

JNIEXPORT jint JNICALL
Java_vn_unlimit_softetherclient_SoftEtherNative_nativeGetStatus(JNIEnv* env, jobject thiz, jlong handle) {
    native_handle_t* h = (native_handle_t*)handle;
    if (!h || !h->conn) return 0;

    int state = se_connection_get_state(h->conn);
    return map_state(state);
}

JNIEXPORT jlongArray JNICALL
Java_vn_unlimit_softetherclient_SoftEtherNative_nativeGetStatistics(JNIEnv* env, jobject thiz, jlong handle) {
    native_handle_t* h = (native_handle_t*)handle;

    jlongArray result = (*env)->NewLongArray(env, 2);
    if (!result) return NULL;

    jlong stats[2] = {0, 0};

    if (h && h->conn) {
        se_statistics_t native_stats;
        se_connection_get_statistics(h->conn, &native_stats);
        stats[0] = (jlong)native_stats.bytes_sent;
        stats[1] = (jlong)native_stats.bytes_received;
    }

    (*env)->SetLongArrayRegion(env, result, 0, 2, stats);
    return result;
}

JNIEXPORT jint JNICALL
Java_vn_unlimit_softetherclient_SoftEtherNative_nativeGetLastError(JNIEnv* env, jobject thiz, jlong handle) {
    native_handle_t* h = (native_handle_t*)handle;
    if (!h || !h->conn) return 1;

    int error = se_connection_get_last_error(h->conn);
    return map_error_code(error);
}

JNIEXPORT jstring JNICALL
Java_vn_unlimit_softetherclient_SoftEtherNative_nativeGetErrorString(JNIEnv* env, jobject thiz, jlong handle) {
    native_handle_t* h = (native_handle_t*)handle;
    if (!h || !h->conn) {
        return (*env)->NewStringUTF(env, "Invalid handle");
    }

    const char* error_str = se_connection_get_error_string(h->conn);
    return (*env)->NewStringUTF(env, error_str);
}

// Test helper - get native protocol version
JNIEXPORT jint JNICALL
Java_vn_unlimit_softetherclient_SoftEtherNative_nativeGetProtocolVersion(JNIEnv* env, jobject thiz) {
    return (SE_VERSION_MAJOR << 16) | (SE_VERSION_MINOR << 8) | SE_VERSION_BUILD;
}

// Test helper - check if native library is loaded
JNIEXPORT jboolean JNICALL
Java_vn_unlimit_softetherclient_SoftEtherNative_nativeIsLibraryLoaded(JNIEnv* env, jobject thiz) {
    return JNI_TRUE;
}

// ============================================================================
// Test Functions - For testing without VPN service
// ============================================================================

/**
 * Test native connection without VPN service
 * This function tests the connection logic without requiring TUN interface
 */
JNIEXPORT jint JNICALL
Java_vn_unlimit_softetherclient_SoftEtherNative_nativeTestConnect(
    JNIEnv* env,
    jobject thiz,
    jstring serverHost,
    jint serverPort,
    jstring hubName,
    jstring username,
    jstring password)
{
    LOGD("nativeTestConnect called");

    // Extract strings
    const char* c_serverHost = (*env)->GetStringUTFChars(env, serverHost, NULL);
    const char* c_hubName = (*env)->GetStringUTFChars(env, hubName, NULL);
    const char* c_username = (*env)->GetStringUTFChars(env, username, NULL);
    const char* c_password = (*env)->GetStringUTFChars(env, password, NULL);

    LOGD("Test connect to %s:%d, hub=%s, user=%s", c_serverHost, serverPort, c_hubName, c_username);

    // Create a temporary connection (not using the main handle)
    se_connection_t* testConn = se_connection_new();
    if (!testConn) {
        LOGE("Failed to create test connection");
        (*env)->ReleaseStringUTFChars(env, serverHost, c_serverHost);
        (*env)->ReleaseStringUTFChars(env, hubName, c_hubName);
        (*env)->ReleaseStringUTFChars(env, username, c_username);
        (*env)->ReleaseStringUTFChars(env, password, c_password);
        return -1;
    }

    // Build connection parameters
    se_connection_params_t params;
    memset(&params, 0, sizeof(params));

    strncpy(params.server_host, c_serverHost, SE_MAX_HOSTNAME_LEN - 1);
    params.server_port = serverPort;
    strncpy(params.hub_name, c_hubName, SE_MAX_HUBNAME_LEN - 1);
    strncpy(params.username, c_username, SE_MAX_USERNAME_LEN - 1);
    strncpy(params.password, c_password, SE_MAX_PASSWORD_LEN - 1);
    params.use_encrypt = true;
    params.use_compress = false;
    params.verify_server_cert = false;
    params.mtu = 1400;

    // Release strings
    (*env)->ReleaseStringUTFChars(env, serverHost, c_serverHost);
    (*env)->ReleaseStringUTFChars(env, hubName, c_hubName);
    (*env)->ReleaseStringUTFChars(env, username, c_username);
    (*env)->ReleaseStringUTFChars(env, password, c_password);

    // Attempt connection (without TUN fd - will fail at data transfer but tests handshake)
    LOGD("Attempting test connection...");
    int result = se_connection_connect(testConn, &params);

    LOGD("Test connection result: %d (%s)", result, se_error_string(result));

    // Get final state
    int finalState = se_connection_get_state(testConn);
    LOGD("Test connection final state: %d", finalState);

    // Cleanup test connection
    se_connection_free(testConn);

    // Return result
    // 0 = success, >0 = error code
    return result;
}

/**
 * Test function to verify native method calling works
 */
JNIEXPORT jstring JNICALL
Java_vn_unlimit_softetherclient_SoftEtherNative_nativeTestEcho(JNIEnv* env, jobject thiz, jstring message) {
    const char* c_message = (*env)->GetStringUTFChars(env, message, NULL);

    char response[256];
    snprintf(response, sizeof(response), "Native echo: %s", c_message);

    (*env)->ReleaseStringUTFChars(env, message, c_message);

    return (*env)->NewStringUTF(env, response);
}

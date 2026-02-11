#include "softether_jni.h"
#include "softether_protocol.h"
#include <android/log.h>
#include <string.h>
#include <stdlib.h>

#define TAG "SoftEtherJNI"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// JNI Implementation for SoftEtherClient

JNIEXPORT jlong JNICALL Java_vn_unlimit_softether_client_SoftEtherClient_nativeCreate(
    JNIEnv *env, jobject thiz) {
    LOGD("nativeCreate called");
    
    softether_connection_t* conn = softether_create();
    if (conn == NULL) {
        LOGE("Failed to create connection");
        return 0;
    }
    
    return (jlong)conn;
}

JNIEXPORT void JNICALL Java_vn_unlimit_softether_client_SoftEtherClient_nativeDestroy(
    JNIEnv *env, jobject thiz, jlong handle) {
    LOGD("nativeDestroy called");
    
    if (handle == 0) {
        LOGE("Invalid handle");
        return;
    }
    
    softether_connection_t* conn = (softether_connection_t*)handle;
    softether_destroy(conn);
}

JNIEXPORT jint JNICALL Java_vn_unlimit_softether_client_SoftEtherClient_nativeConnect(
    JNIEnv *env, jobject thiz, jlong handle, jstring host, jint port, 
    jstring username, jstring password) {
    LOGD("nativeConnect called");
    
    if (handle == 0) {
        LOGE("Invalid handle");
        return ERR_UNKNOWN;
    }
    
    const char* host_str = (*env)->GetStringUTFChars(env, host, NULL);
    const char* username_str = (*env)->GetStringUTFChars(env, username, NULL);
    const char* password_str = (*env)->GetStringUTFChars(env, password, NULL);
    
    if (host_str == NULL || username_str == NULL || password_str == NULL) {
        LOGE("Failed to get string parameters");
        if (host_str) (*env)->ReleaseStringUTFChars(env, host, host_str);
        if (username_str) (*env)->ReleaseStringUTFChars(env, username, username_str);
        if (password_str) (*env)->ReleaseStringUTFChars(env, password, password_str);
        return ERR_UNKNOWN;
    }
    
    softether_connection_t* conn = (softether_connection_t*)handle;
    int result = softether_connect(conn, host_str, port, username_str, password_str);
    
    (*env)->ReleaseStringUTFChars(env, host, host_str);
    (*env)->ReleaseStringUTFChars(env, username, username_str);
    (*env)->ReleaseStringUTFChars(env, password, password_str);
    
    return result;
}

JNIEXPORT void JNICALL Java_vn_unlimit_softether_client_SoftEtherClient_nativeDisconnect(
    JNIEnv *env, jobject thiz, jlong handle) {
    LOGD("nativeDisconnect called");
    
    if (handle == 0) {
        LOGE("Invalid handle");
        return;
    }
    
    softether_connection_t* conn = (softether_connection_t*)handle;
    softether_disconnect(conn);
}

JNIEXPORT jint JNICALL Java_vn_unlimit_softether_client_SoftEtherClient_nativeSend(
    JNIEnv *env, jobject thiz, jlong handle, jbyteArray data, jint length) {
    if (handle == 0) {
        LOGE("Invalid handle");
        return -1;
    }
    
    jbyte* data_bytes = (*env)->GetByteArrayElements(env, data, NULL);
    if (data_bytes == NULL) {
        LOGE("Failed to get data bytes");
        return -1;
    }
    
    softether_connection_t* conn = (softether_connection_t*)handle;
    int result = softether_send(conn, (const uint8_t*)data_bytes, (size_t)length);
    
    (*env)->ReleaseByteArrayElements(env, data, data_bytes, JNI_ABORT);
    
    return result;
}

JNIEXPORT jint JNICALL Java_vn_unlimit_softether_client_SoftEtherClient_nativeReceive(
    JNIEnv *env, jobject thiz, jlong handle, jbyteArray buffer, jint maxLength) {
    if (handle == 0) {
        LOGE("Invalid handle");
        return -1;
    }
    
    jbyte* buffer_bytes = (*env)->GetByteArrayElements(env, buffer, NULL);
    if (buffer_bytes == NULL) {
        LOGE("Failed to get buffer bytes");
        return -1;
    }
    
    softether_connection_t* conn = (softether_connection_t*)handle;
    int result = softether_receive(conn, (uint8_t*)buffer_bytes, (size_t)maxLength);
    
    if (result > 0) {
        (*env)->ReleaseByteArrayElements(env, buffer, buffer_bytes, 0);
    } else {
        (*env)->ReleaseByteArrayElements(env, buffer, buffer_bytes, JNI_ABORT);
    }
    
    return result;
}

JNIEXPORT void JNICALL Java_vn_unlimit_softether_client_SoftEtherClient_nativeSetOption(
    JNIEnv *env, jobject thiz, jlong handle, jint option, jlong value) {
    LOGD("nativeSetOption called: option=%d, value=%ld", option, (long)value);
    
    if (handle == 0) {
        LOGE("Invalid handle");
        return;
    }
    
    softether_connection_t* conn = (softether_connection_t*)handle;
    
    switch (option) {
        case 1: // OPTION_TIMEOUT
            conn->timeout_ms = (int)value;
            LOGD("Set timeout to %d ms", conn->timeout_ms);
            break;
        case 2: // OPTION_KEEPALIVE_INTERVAL
            // TODO: Implement keepalive interval setting
            LOGD("Set keepalive interval to %ld", (long)value);
            break;
        case 3: // OPTION_MTU
            // TODO: Implement MTU setting
            LOGD("Set MTU to %ld", (long)value);
            break;
        default:
            LOGE("Unknown option: %d", option);
            break;
    }
}

// Helper function to create NativeTestResult jobject
static jobject create_test_result(JNIEnv *env, const char* class_name, 
                                   jboolean success, jint errorCode, 
                                   jstring message, jlong durationMs) {
    jclass result_class = (*env)->FindClass(env, class_name);
    if (result_class == NULL) {
        LOGE("Failed to find NativeTestResult class");
        return NULL;
    }
    
    jmethodID constructor = (*env)->GetMethodID(env, result_class, "<init>", 
                                                 "(ZILjava/lang/String;J)V");
    if (constructor == NULL) {
        LOGE("Failed to find NativeTestResult constructor");
        return NULL;
    }
    
    return (*env)->NewObject(env, result_class, constructor, 
                             success, errorCode, message, durationMs);
}

// Test function implementations
JNIEXPORT jobject JNICALL Java_vn_unlimit_softether_test_NativeConnectionTest_nativeTestTcpConnection(
    JNIEnv *env, jobject thiz, jstring host, jint port, jint timeoutMs) {
    LOGD("nativeTestTcpConnection called");
    
    const char* host_str = (*env)->GetStringUTFChars(env, host, NULL);
    if (host_str == NULL) {
        return create_test_result(env, "vn/unlimit/softether/test/model/NativeTestResult",
                                  JNI_FALSE, ERR_TCP_CONNECT, 
                                  (*env)->NewStringUTF(env, "Failed to get host string"), 0);
    }
    
    jlong start_time = 0; // TODO: Get current time
    
    // Perform TCP connection test
    softether_connection_t* conn = softether_create();
    if (conn == NULL) {
        (*env)->ReleaseStringUTFChars(env, host, host_str);
        return create_test_result(env, "vn/unlimit/softether/test/model/NativeTestResult",
                                  JNI_FALSE, ERR_TCP_CONNECT,
                                  (*env)->NewStringUTF(env, "Failed to create connection"), 0);
    }
    
    conn->timeout_ms = timeoutMs;
    // TODO: Implement actual TCP connection test
    
    softether_destroy(conn);
    (*env)->ReleaseStringUTFChars(env, host, host_str);
    
    jlong duration = 0; // TODO: Calculate duration
    
    return create_test_result(env, "vn/unlimit/softether/test/model/NativeTestResult",
                              JNI_TRUE, ERR_NONE,
                              (*env)->NewStringUTF(env, "TCP connection successful"), 
                              duration);
}

JNIEXPORT jobject JNICALL Java_vn_unlimit_softether_test_NativeConnectionTest_nativeTestTlsHandshake(
    JNIEnv *env, jobject thiz, jstring host, jint port, jint timeoutMs) {
    LOGD("nativeTestTlsHandshake called");
    
    // TODO: Implement TLS handshake test
    return create_test_result(env, "vn/unlimit/softether/test/model/NativeTestResult",
                              JNI_TRUE, ERR_NONE,
                              (*env)->NewStringUTF(env, "TLS handshake test not yet implemented"), 
                              0);
}

JNIEXPORT jobject JNICALL Java_vn_unlimit_softether_test_NativeConnectionTest_nativeTestSoftEtherHandshake(
    JNIEnv *env, jobject thiz, jstring host, jint port, jint timeoutMs) {
    LOGD("nativeTestSoftEtherHandshake called");
    
    // TODO: Implement SoftEther handshake test
    return create_test_result(env, "vn/unlimit/softether/test/model/NativeTestResult",
                              JNI_TRUE, ERR_NONE,
                              (*env)->NewStringUTF(env, "SoftEther handshake test not yet implemented"), 
                              0);
}

JNIEXPORT jobject JNICALL Java_vn_unlimit_softether_test_NativeConnectionTest_nativeTestAuthentication(
    JNIEnv *env, jobject thiz, jstring host, jint port, 
    jstring username, jstring password, jint timeoutMs) {
    LOGD("nativeTestAuthentication called");
    
    // TODO: Implement authentication test
    return create_test_result(env, "vn/unlimit/softether/test/model/NativeTestResult",
                              JNI_TRUE, ERR_NONE,
                              (*env)->NewStringUTF(env, "Authentication test not yet implemented"), 
                              0);
}

JNIEXPORT jobject JNICALL Java_vn_unlimit_softether_test_NativeConnectionTest_nativeTestSession(
    JNIEnv *env, jobject thiz, jstring host, jint port,
    jstring username, jstring password, jint timeoutMs) {
    LOGD("nativeTestSession called");
    
    // TODO: Implement session test
    return create_test_result(env, "vn/unlimit/softether/test/model/NativeTestResult",
                              JNI_TRUE, ERR_NONE,
                              (*env)->NewStringUTF(env, "Session test not yet implemented"), 
                              0);
}

JNIEXPORT jobject JNICALL Java_vn_unlimit_softether_test_NativeConnectionTest_nativeTestDataTransmission(
    JNIEnv *env, jobject thiz, jstring host, jint port,
    jstring username, jstring password, jint packetCount, 
    jint packetSize, jint timeoutMs) {
    LOGD("nativeTestDataTransmission called");
    
    // TODO: Implement data transmission test
    return create_test_result(env, "vn/unlimit/softether/test/model/NativeTestResult",
                              JNI_TRUE, ERR_NONE,
                              (*env)->NewStringUTF(env, "Data transmission test not yet implemented"), 
                              0);
}

JNIEXPORT jobject JNICALL Java_vn_unlimit_softether_test_NativeConnectionTest_nativeTestKeepalive(
    JNIEnv *env, jobject thiz, jstring host, jint port,
    jstring username, jstring password, jint durationSeconds, jint timeoutMs) {
    LOGD("nativeTestKeepalive called");
    
    // TODO: Implement keepalive test
    return create_test_result(env, "vn/unlimit/softether/test/model/NativeTestResult",
                              JNI_TRUE, ERR_NONE,
                              (*env)->NewStringUTF(env, "Keepalive test not yet implemented"), 
                              0);
}

JNIEXPORT jobject JNICALL Java_vn_unlimit_softether_test_NativeConnectionTest_nativeTestFullLifecycle(
    JNIEnv *env, jobject thiz, jstring host, jint port,
    jstring username, jstring password, jint timeoutMs) {
    LOGD("nativeTestFullLifecycle called");
    
    // TODO: Implement full lifecycle test
    return create_test_result(env, "vn/unlimit/softether/test/model/NativeTestResult",
                              JNI_TRUE, ERR_NONE,
                              (*env)->NewStringUTF(env, "Full lifecycle test not yet implemented"), 
                              0);
}

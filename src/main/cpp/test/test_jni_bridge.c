#include "../jni/softether_jni.h"
#include "native_test.h"
#include <string.h>
#include <stdlib.h>
#include <android/log.h>

#define TAG "TestJNIBridge"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// Helper function to create NativeTestResult jobject from native_test_result_t
static jobject create_test_result(JNIEnv *env, const native_test_result_t* native_result) {
    jclass result_class = (*env)->FindClass(env, "vn/unlimit/softether/test/model/NativeTestResult");
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
    
    jstring message = (*env)->NewStringUTF(env, native_result->message);
    
    jobject result = (*env)->NewObject(env, result_class, constructor,
                                       native_result->success ? JNI_TRUE : JNI_FALSE,
                                       native_result->error_code,
                                       message,
                                       (jlong)native_result->duration_ms);
    
    (*env)->DeleteLocalRef(env, message);
    (*env)->DeleteLocalRef(env, result_class);
    
    return result;
}

// Helper function to convert Java strings to test config
static int fill_test_config(JNIEnv *env, jstring host, jint port,
                             jstring username, jstring password,
                             jint timeoutMs, jint packetCount, jint packetSize,
                             jint durationSeconds, native_test_config_t* config) {
    
    const char* host_str = (*env)->GetStringUTFChars(env, host, NULL);
    const char* username_str = (*env)->GetStringUTFChars(env, username, NULL);
    const char* password_str = (*env)->GetStringUTFChars(env, password, NULL);
    
    if (host_str == NULL || username_str == NULL || password_str == NULL) {
        if (host_str) (*env)->ReleaseStringUTFChars(env, host, host_str);
        if (username_str) (*env)->ReleaseStringUTFChars(env, username, username_str);
        if (password_str) (*env)->ReleaseStringUTFChars(env, password, password_str);
        return -1;
    }
    
    // Note: The config stores pointers to the Java string data
    // We need to copy them since we'll release the Java strings
    // For simplicity, we'll use the direct pointers here but in production
    // these should be properly duplicated
    config->host = host_str;
    config->port = port;
    config->username = username_str;
    config->password = password_str;
    config->timeout_ms = timeoutMs;
    config->packet_count = packetCount;
    config->packet_size = packetSize;
    config->duration_seconds = durationSeconds;
    
    return 0;
}

static void release_test_config(JNIEnv *env, jstring host, jstring username, jstring password,
                                 native_test_config_t* config) {
    if (config->host) (*env)->ReleaseStringUTFChars(env, host, config->host);
    if (config->username) (*env)->ReleaseStringUTFChars(env, username, config->username);
    if (config->password) (*env)->ReleaseStringUTFChars(env, password, config->password);
}

// JNI implementations for test functions

JNIEXPORT jobject JNICALL Java_vn_unlimit_softether_test_NativeConnectionTest_nativeTestTcpConnection(
    JNIEnv *env, jobject thiz, jstring host, jint port, jint timeoutMs) {
    
    LOGD("nativeTestTcpConnection called");
    
    native_test_config_t config = {0};
    config.host = (*env)->GetStringUTFChars(env, host, NULL);
    config.port = port;
    config.timeout_ms = timeoutMs;
    config.packet_count = 0;
    config.packet_size = 0;
    config.duration_seconds = 0;
    
    if (config.host == NULL) {
        native_test_result_t error_result = {0};
        test_result_init(&error_result, false, ERR_TCP_CONNECT,
                        "Failed to get host string", 0);
        return create_test_result(env, &error_result);
    }
    
    native_test_result_t result = test_tcp_connection(&config);
    
    (*env)->ReleaseStringUTFChars(env, host, config.host);
    
    return create_test_result(env, &result);
}

JNIEXPORT jobject JNICALL Java_vn_unlimit_softether_test_NativeConnectionTest_nativeTestTlsHandshake(
    JNIEnv *env, jobject thiz, jstring host, jint port, jint timeoutMs) {
    
    LOGD("nativeTestTlsHandshake called");
    
    native_test_config_t config = {0};
    config.host = (*env)->GetStringUTFChars(env, host, NULL);
    config.port = port;
    config.timeout_ms = timeoutMs;
    
    if (config.host == NULL) {
        native_test_result_t error_result = {0};
        test_result_init(&error_result, false, ERR_TLS_HANDSHAKE,
                        "Failed to get host string", 0);
        return create_test_result(env, &error_result);
    }
    
    native_test_result_t result = test_tls_handshake(&config);
    
    (*env)->ReleaseStringUTFChars(env, host, config.host);
    
    return create_test_result(env, &result);
}

JNIEXPORT jobject JNICALL Java_vn_unlimit_softether_test_NativeConnectionTest_nativeTestSoftEtherHandshake(
    JNIEnv *env, jobject thiz, jstring host, jint port, jint timeoutMs) {
    
    LOGD("nativeTestSoftEtherHandshake called");
    
    native_test_config_t config = {0};
    config.host = (*env)->GetStringUTFChars(env, host, NULL);
    config.port = port;
    config.timeout_ms = timeoutMs;
    
    if (config.host == NULL) {
        native_test_result_t error_result = {0};
        test_result_init(&error_result, false, ERR_PROTOCOL_VERSION,
                        "Failed to get host string", 0);
        return create_test_result(env, &error_result);
    }
    
    native_test_result_t result = test_softether_handshake(&config);
    
    (*env)->ReleaseStringUTFChars(env, host, config.host);
    
    return create_test_result(env, &result);
}

JNIEXPORT jobject JNICALL Java_vn_unlimit_softether_test_NativeConnectionTest_nativeTestAuthentication(
    JNIEnv *env, jobject thiz, jstring host, jint port,
    jstring username, jstring password, jint timeoutMs) {
    
    LOGD("nativeTestAuthentication called");
    
    native_test_config_t config = {0};
    config.host = (*env)->GetStringUTFChars(env, host, NULL);
    config.port = port;
    config.username = (*env)->GetStringUTFChars(env, username, NULL);
    config.password = (*env)->GetStringUTFChars(env, password, NULL);
    config.timeout_ms = timeoutMs;
    
    if (config.host == NULL || config.username == NULL || config.password == NULL) {
        if (config.host) (*env)->ReleaseStringUTFChars(env, host, config.host);
        if (config.username) (*env)->ReleaseStringUTFChars(env, username, config.username);
        if (config.password) (*env)->ReleaseStringUTFChars(env, password, config.password);
        
        native_test_result_t error_result = {0};
        test_result_init(&error_result, false, ERR_AUTHENTICATION,
                        "Failed to get parameters", 0);
        return create_test_result(env, &error_result);
    }
    
    native_test_result_t result = test_authentication(&config);
    
    (*env)->ReleaseStringUTFChars(env, host, config.host);
    (*env)->ReleaseStringUTFChars(env, username, config.username);
    (*env)->ReleaseStringUTFChars(env, password, config.password);
    
    return create_test_result(env, &result);
}

JNIEXPORT jobject JNICALL Java_vn_unlimit_softether_test_NativeConnectionTest_nativeTestSession(
    JNIEnv *env, jobject thiz, jstring host, jint port,
    jstring username, jstring password, jint timeoutMs) {
    
    LOGD("nativeTestSession called");
    
    native_test_config_t config = {0};
    config.host = (*env)->GetStringUTFChars(env, host, NULL);
    config.port = port;
    config.username = (*env)->GetStringUTFChars(env, username, NULL);
    config.password = (*env)->GetStringUTFChars(env, password, NULL);
    config.timeout_ms = timeoutMs;
    
    if (config.host == NULL || config.username == NULL || config.password == NULL) {
        if (config.host) (*env)->ReleaseStringUTFChars(env, host, config.host);
        if (config.username) (*env)->ReleaseStringUTFChars(env, username, config.username);
        if (config.password) (*env)->ReleaseStringUTFChars(env, password, config.password);
        
        native_test_result_t error_result = {0};
        test_result_init(&error_result, false, ERR_SESSION,
                        "Failed to get parameters", 0);
        return create_test_result(env, &error_result);
    }
    
    native_test_result_t result = test_session(&config);
    
    (*env)->ReleaseStringUTFChars(env, host, config.host);
    (*env)->ReleaseStringUTFChars(env, username, config.username);
    (*env)->ReleaseStringUTFChars(env, password, config.password);
    
    return create_test_result(env, &result);
}

JNIEXPORT jobject JNICALL Java_vn_unlimit_softether_test_NativeConnectionTest_nativeTestDataTransmission(
    JNIEnv *env, jobject thiz, jstring host, jint port,
    jstring username, jstring password, jint packetCount,
    jint packetSize, jint timeoutMs) {
    
    LOGD("nativeTestDataTransmission called");
    
    native_test_config_t config = {0};
    config.host = (*env)->GetStringUTFChars(env, host, NULL);
    config.port = port;
    config.username = (*env)->GetStringUTFChars(env, username, NULL);
    config.password = (*env)->GetStringUTFChars(env, password, NULL);
    config.timeout_ms = timeoutMs;
    config.packet_count = packetCount;
    config.packet_size = packetSize;
    
    if (config.host == NULL || config.username == NULL || config.password == NULL) {
        if (config.host) (*env)->ReleaseStringUTFChars(env, host, config.host);
        if (config.username) (*env)->ReleaseStringUTFChars(env, username, config.username);
        if (config.password) (*env)->ReleaseStringUTFChars(env, password, config.password);
        
        native_test_result_t error_result = {0};
        test_result_init(&error_result, false, ERR_DATA_TRANSMISSION,
                        "Failed to get parameters", 0);
        return create_test_result(env, &error_result);
    }
    
    native_test_result_t result = test_data_transmission(&config);
    
    (*env)->ReleaseStringUTFChars(env, host, config.host);
    (*env)->ReleaseStringUTFChars(env, username, config.username);
    (*env)->ReleaseStringUTFChars(env, password, config.password);
    
    return create_test_result(env, &result);
}

JNIEXPORT jobject JNICALL Java_vn_unlimit_softether_test_NativeConnectionTest_nativeTestKeepalive(
    JNIEnv *env, jobject thiz, jstring host, jint port,
    jstring username, jstring password, jint durationSeconds, jint timeoutMs) {
    
    LOGD("nativeTestKeepalive called");
    
    native_test_config_t config = {0};
    config.host = (*env)->GetStringUTFChars(env, host, NULL);
    config.port = port;
    config.username = (*env)->GetStringUTFChars(env, username, NULL);
    config.password = (*env)->GetStringUTFChars(env, password, NULL);
    config.timeout_ms = timeoutMs;
    config.duration_seconds = durationSeconds;
    
    if (config.host == NULL || config.username == NULL || config.password == NULL) {
        if (config.host) (*env)->ReleaseStringUTFChars(env, host, config.host);
        if (config.username) (*env)->ReleaseStringUTFChars(env, username, config.username);
        if (config.password) (*env)->ReleaseStringUTFChars(env, password, config.password);
        
        native_test_result_t error_result = {0};
        test_result_init(&error_result, false, ERR_DATA_TRANSMISSION,
                        "Failed to get parameters", 0);
        return create_test_result(env, &error_result);
    }
    
    native_test_result_t result = test_keepalive(&config);
    
    (*env)->ReleaseStringUTFChars(env, host, config.host);
    (*env)->ReleaseStringUTFChars(env, username, config.username);
    (*env)->ReleaseStringUTFChars(env, password, config.password);
    
    return create_test_result(env, &result);
}

JNIEXPORT jobject JNICALL Java_vn_unlimit_softether_test_NativeConnectionTest_nativeTestFullLifecycle(
    JNIEnv *env, jobject thiz, jstring host, jint port,
    jstring username, jstring password, jint timeoutMs) {
    
    LOGD("nativeTestFullLifecycle called");
    
    native_test_config_t config = {0};
    config.host = (*env)->GetStringUTFChars(env, host, NULL);
    config.port = port;
    config.username = (*env)->GetStringUTFChars(env, username, NULL);
    config.password = (*env)->GetStringUTFChars(env, password, NULL);
    config.timeout_ms = timeoutMs;
    
    if (config.host == NULL || config.username == NULL || config.password == NULL) {
        if (config.host) (*env)->ReleaseStringUTFChars(env, host, config.host);
        if (config.username) (*env)->ReleaseStringUTFChars(env, username, config.username);
        if (config.password) (*env)->ReleaseStringUTFChars(env, password, config.password);
        
        native_test_result_t error_result = {0};
        test_result_init(&error_result, false, ERR_UNKNOWN,
                        "Failed to get parameters", 0);
        return create_test_result(env, &error_result);
    }
    
    native_test_result_t result = test_full_lifecycle(&config);
    
    (*env)->ReleaseStringUTFChars(env, host, config.host);
    (*env)->ReleaseStringUTFChars(env, username, config.username);
    (*env)->ReleaseStringUTFChars(env, password, config.password);
    
    return create_test_result(env, &result);
}

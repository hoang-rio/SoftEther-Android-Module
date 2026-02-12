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
    
    // Get state before destroying for logging
    softether_state_t state = softether_get_state(conn);
    LOGD("Destroying connection in state: %s", softether_state_string(state));
    
    softether_destroy(conn);
    LOGD("nativeDestroy completed");
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
    
    // Check if connection is in a state that can be disconnected
    softether_state_t state = softether_get_state(conn);
    if (state == STATE_DISCONNECTED || state == STATE_DISCONNECTING) {
        LOGD("Connection already disconnected or disconnecting, state=%s", 
             softether_state_string(state));
        return;
    }
    
    LOGD("Disconnecting connection in state: %s", softether_state_string(state));
    softether_disconnect(conn);
    LOGD("nativeDisconnect completed");
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

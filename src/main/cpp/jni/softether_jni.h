#ifndef SOFTETHER_JNI_H
#define SOFTETHER_JNI_H

#include <jni.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Connection management
JNIEXPORT jlong JNICALL Java_vn_unlimit_softether_client_SoftEtherClient_nativeCreate(
    JNIEnv *env, jobject thiz);

JNIEXPORT void JNICALL Java_vn_unlimit_softether_client_SoftEtherClient_nativeDestroy(
    JNIEnv *env, jobject thiz, jlong handle);

JNIEXPORT jint JNICALL Java_vn_unlimit_softether_client_SoftEtherClient_nativeConnect(
    JNIEnv *env, jobject thiz, jlong handle, jstring host, jint port, 
    jstring username, jstring password);

JNIEXPORT void JNICALL Java_vn_unlimit_softether_client_SoftEtherClient_nativeDisconnect(
    JNIEnv *env, jobject thiz, jlong handle);

// Data I/O
JNIEXPORT jint JNICALL Java_vn_unlimit_softether_client_SoftEtherClient_nativeSend(
    JNIEnv *env, jobject thiz, jlong handle, jbyteArray data, jint length);

JNIEXPORT jint JNICALL Java_vn_unlimit_softether_client_SoftEtherClient_nativeReceive(
    JNIEnv *env, jobject thiz, jlong handle, jbyteArray buffer, jint maxLength);

// Configuration
JNIEXPORT void JNICALL Java_vn_unlimit_softether_client_SoftEtherClient_nativeSetOption(
    JNIEnv *env, jobject thiz, jlong handle, jint option, jlong value);

// Test functions for instrumentation tests
JNIEXPORT jobject JNICALL Java_vn_unlimit_softether_test_NativeConnectionTest_nativeTestTcpConnection(
    JNIEnv *env, jobject thiz, jstring host, jint port, jint timeoutMs);

JNIEXPORT jobject JNICALL Java_vn_unlimit_softether_test_NativeConnectionTest_nativeTestTlsHandshake(
    JNIEnv *env, jobject thiz, jstring host, jint port, jint timeoutMs);

JNIEXPORT jobject JNICALL Java_vn_unlimit_softether_test_NativeConnectionTest_nativeTestSoftEtherHandshake(
    JNIEnv *env, jobject thiz, jstring host, jint port, jint timeoutMs);

JNIEXPORT jobject JNICALL Java_vn_unlimit_softether_test_NativeConnectionTest_nativeTestAuthentication(
    JNIEnv *env, jobject thiz, jstring host, jint port, 
    jstring username, jstring password, jint timeoutMs);

JNIEXPORT jobject JNICALL Java_vn_unlimit_softether_test_NativeConnectionTest_nativeTestSession(
    JNIEnv *env, jobject thiz, jstring host, jint port,
    jstring username, jstring password, jint timeoutMs);

JNIEXPORT jobject JNICALL Java_vn_unlimit_softether_test_NativeConnectionTest_nativeTestDataTransmission(
    JNIEnv *env, jobject thiz, jstring host, jint port,
    jstring username, jstring password, jint packetCount, 
    jint packetSize, jint timeoutMs);

JNIEXPORT jobject JNICALL Java_vn_unlimit_softether_test_NativeConnectionTest_nativeTestKeepalive(
    JNIEnv *env, jobject thiz, jstring host, jint port,
    jstring username, jstring password, jint durationSeconds, jint timeoutMs);

JNIEXPORT jobject JNICALL Java_vn_unlimit_softether_test_NativeConnectionTest_nativeTestFullLifecycle(
    JNIEnv *env, jobject thiz, jstring host, jint port,
    jstring username, jstring password, jint timeoutMs);

#ifdef __cplusplus
}
#endif

#endif // SOFTETHER_JNI_H

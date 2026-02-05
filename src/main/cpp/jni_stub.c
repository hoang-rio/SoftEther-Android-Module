#include <jni.h>

// Placeholder JNI entry to keep the shared library buildable.
JNIEXPORT jint JNICALL
Java_vn_unlimit_softetherclient_NativeStub_init(JNIEnv* env, jobject thiz) {
    (void)env;
    (void)thiz;
    return 0;
}
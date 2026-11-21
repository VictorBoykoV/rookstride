/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <jni.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <unistd.h>

/* No Java/API-30 libc dependency, no replace/copy/link fallback. */
JNIEXPORT jint JNICALL
Java_org_strongswan_android_rookstride_CertificatePublication_nativeRenameNoReplace(
    JNIEnv *env, jclass type, jstring source, jstring target)
{
    (void)type;
    if (!source || !target || (*env)->GetStringUTFLength(env, source) > 4096 ||
        (*env)->GetStringUTFLength(env, target) > 4096) return EINVAL;
    const char *from = (*env)->GetStringUTFChars(env, source, NULL);
    if (!from) return ENOMEM;
    const char *to = (*env)->GetStringUTFChars(env, target, NULL);
    if (!to) {
        (*env)->ReleaseStringUTFChars(env, source, from);
        return ENOMEM;
    }
    int result;
#ifdef __NR_renameat2
    result = syscall(__NR_renameat2, AT_FDCWD, from, AT_FDCWD, to, 1U) == 0 ? 0 : errno;
#else
    result = ENOSYS;
#endif
    (*env)->ReleaseStringUTFChars(env, target, to);
    (*env)->ReleaseStringUTFChars(env, source, from);
    return result;
}

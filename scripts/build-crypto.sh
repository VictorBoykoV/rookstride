#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
root="$PWD"
export ANDROID_NDK_HOME="${ANDROID_NDK_HOME:-$root/.tools/sdk/ndk/27.3.13750724}"
export ANDROID_NDK_ROOT="$ANDROID_NDK_HOME"
case "$(uname -s)" in Darwin) host=darwin-x86_64;; Linux) host=linux-x86_64;; *) echo 'Use macOS or Linux for this build'; exit 1;; esac
export PATH="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/$host/bin:$PATH"
out="$root/.tools/strongswan-source/src/frontends/android/app/src/main/jni/openssl"
mkdir -p "$out"
for abi in arm64-v8a armeabi-v7a x86_64; do
 case $abi in arm64-v8a) target=android-arm64;; armeabi-v7a) target=android-arm;; x86_64) target=android-x86_64;; esac
 if [[ -s "$out/$abi/libcrypto.a" && -s "$out/$abi/include/openssl/configuration.h" ]]; then continue; fi
 cd "$root/.tools/openssl-3.5.9"
 make distclean >/dev/null 2>&1 || true
 ./Configure "$target" no-shared no-ct no-cast no-comp no-dgram no-dsa no-gost no-idea no-rmd160 no-seed no-sm2 no-sm3 no-sm4 no-sock no-srp no-srtp no-err no-engine no-dso no-hw no-stdio no-ui-console -fPIC -DOPENSSL_PIC -O2 -D__ANDROID_API__=26
 make -j"${ROOKSTRIDE_BUILD_JOBS:-4}" build_generated
 if [[ ! -s "$out/$abi/libcrypto.a" ]]; then make -j"${ROOKSTRIDE_BUILD_JOBS:-4}" libcrypto.a; fi
 mkdir -p "$out/$abi"
 if [[ -s libcrypto.a ]]; then cp libcrypto.a "$out/$abi/"; fi
 mkdir -p "$out/$abi/include"
 cp -R include/. "$out/$abi/include/"
done
cd "$root/.tools/openssl-3.5.9"

cat > "$out/Android.mk" <<'MK'
LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)
LOCAL_MODULE := libcrypto_static
LOCAL_SRC_FILES := $(TARGET_ARCH_ABI)/libcrypto.a
LOCAL_EXPORT_C_INCLUDES := $(LOCAL_PATH)/$(TARGET_ARCH_ABI)/include
include $(PREBUILT_STATIC_LIBRARY)
MK

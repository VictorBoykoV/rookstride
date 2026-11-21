LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)
LOCAL_MODULE := rook-files
LOCAL_SRC_FILES := rook-files.c
LOCAL_CFLAGS := -std=c11 -Wall -Wextra -Werror -fvisibility=hidden
include $(BUILD_SHARED_LIBRARY)

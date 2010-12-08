LOCAL_PATH:=$(call my-dir)

include $CLEAR_VARS)
LOCAL_SRC_FILES:=masond.c
LOCAL_MODULE:=masond

LOCAL_SHARED_LIBRARIES := libc

include $(BUILD_EXECUTABLE)

ifneq ($(TARGET_SIMULATOR),true)

LOCAL_PATH:=$(call my-dir)

include $(CLEAR_VARS)
LOCAL_SRC_FILES:= masond.c
LOCAL_MODULE:= masond
LOCAL_SHARED_LIBRARIES := libc libcutils
include $(BUILD_EXECUTABLE)

endif

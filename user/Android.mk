ifneq ($(TARGET_SIMULATOR),true)

LOCAL_PATH:=$(call my-dir)

include $(CLEAR_VARS)
LOCAL_SRC_FILES:= masond.c
LOCAL_C_INCLUDES:= $(LOCAL_PATH)/../kernel/include/
LOCAL_MODULE:= masond
LOCAL_SHARED_LIBRARIES := libc libcutils
include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_SRC_FILES:= masonloopd.c
LOCAL_MODULE:= masonloopd
LOCAL_SHARED_LIBRARIES := libc libcutils
include $(BUILD_EXECUTABLE)

endif

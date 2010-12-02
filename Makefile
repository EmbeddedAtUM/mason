obj-m += mason.o

KERNEL_DIR ?= $(realpath ../../kernel/msm/)
ifeq (,$(ARCH))
  ARCH := arm
  CROSS_COMPILE := arm-eabi-
  PATH := $(PATH):../../prebuilt/linux-x86/toolchain/arm-eabi-4.4.0/bin/
endif

EXTRA_CFLAGS += -DMASON_DEBUG

all:
	@echo "KERNEL_DIR=$(KERNEL_DIR)"
	@echo "ARCH=$(ARCH)"
	@echo "CROSS_COMPILE=$(CROSS_COMPILE)"
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) modules	
clean:
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) clean

ins:
	sudo /sbin/insmod mason.ko iface=eth0
ins100:
	sudo /sbin/insmod mason.ko iface=eth0 numids=100
insinit:
	sudo /sbin/insmod mason.ko init=1 iface=eth0
rm:
	sudo /sbin/rmmod mason
push:
	adb remount
	adb push mason.ko system/lib/modules
adbins:
	adb shell 'insmod system/lib/modules/mason.ko'
adbins100:
	adb shell 'insmod system/lib/modules/mason.ko numids=100'
adbinsinit:
	adb shell 'insmod system/lib/modules/mason.ko init=1'
adbrm:
	adb shell 'rmmod mason.ko'
adbdmesg:
	adb shell 'dmesg'

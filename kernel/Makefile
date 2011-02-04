obj-m += mason.o

EXTRA_CFLAGS += -I${M}/include
EXTRA_CFLAGS += -DMASON_DEBUG
EXTRA_CFLAGS += -DMASON_LOG_SEND
EXTRA_CFLAGS += -DMASON_LOG_RECV
EXTRA_CFLAGS += -DMASON_LOG_ADDR

all:
	@echo "KERNEL_DIR=$(KERNEL_DIR)"
	@echo "ARCH=$(ARCH)"
	@echo "CROSS_COMPILE=$(CROSS_COMPILE)"
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) modules	
clean:
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) clean

ins:
	sudo /sbin/insmod mason.ko
ins100:
	sudo /sbin/insmod mason.ko numids=100
rm:
	sudo /sbin/rmmod mason
push:
	adb remount
	adb push mason.ko system/lib/modules
init:
	echo -n eth0 > /proc/net/mason_initiate
adbins:
	adb shell 'insmod system/lib/modules/mason.ko'
adbins100:
	adb shell 'insmod system/lib/modules/mason.ko numids=100'	
adbrm:	
	adb shell 'rmmod mason.ko'
adbdmesg:
	adb shell 'dmesg'
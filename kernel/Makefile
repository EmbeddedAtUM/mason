# Copyright 2010, 2011 The Regents of the University of Michigan

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or (at
# your option) any later version.

# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

obj-m += mason.o

EXTRA_CFLAGS += -I${M}/include
#EXTRA_CFLAGS += -DMASON_DEBUG
EXTRA_CFLAGS += -DMASON_LOG_SEND
EXTRA_CFLAGS += -DMASON_LOG_RECV
EXTRA_CFLAGS += -DMASON_LOG_ADDR
EXTRA_CFLAGS += -DMASON_LOG_MSG

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
adbperm:
	adb shell 'chmod 0222 /proc/net/mason_initiate'
	adb shell 'chmod 0666 /sys/module/mason/parameters/numids'

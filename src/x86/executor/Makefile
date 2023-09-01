NAME = x86_executor

ifneq ($(shell grep "Intel" /proc/cpuinfo),)
	VENDOR_ID=1
else ifneq ($(shell grep "AMD" /proc/cpuinfo),)
	VENDOR_ID=2
ifneq ($(shell grep -m1 "cpu family" /proc/cpuinfo | grep "23" ),)
	CPU_FAMILY=23
else
	CPU_FAMILY=25 # Default to 19h
endif
endif

ccflags-y += -std=gnu11 -Wno-declaration-after-statement -msse2 \
    -DL1D_ASSOCIATIVITY=$(shell cat /sys/devices/system/cpu/cpu0/cache/index0/ways_of_associativity) \
	-DVENDOR_ID=$(VENDOR_ID) \
	-DCPU_FAMILY=$(CPU_FAMILY)

obj-m += $(NAME).o
$(NAME)-objs += main.o templates.o measurement.o input.o sandbox.o test_case.o


KDIR=/lib/modules/$(shell uname -r)/build


all:
	make -C $(KDIR) M=$(PWD) modules

clean:
	make -C $(KDIR) M=$(PWD) clean

install:
	sudo insmod $(NAME).ko

uninstall:
	sudo rmmod $(NAME)

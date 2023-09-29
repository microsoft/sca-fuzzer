NAME = x86_executor
KDIR=/lib/modules/$(shell uname -r)/build

obj-m += $(NAME).o
$(NAME)-objs += main.o measurement.o input.o sandbox.o test_case.o fault_handler.o page_table.o loader.o macro.o

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

EXTRA_CFLAGS += -I$(src)/include \
	-std=gnu11 -Wno-declaration-after-statement -msse2 \
    -DL1D_ASSOCIATIVITY=$(shell cat /sys/devices/system/cpu/cpu0/cache/index0/ways_of_associativity) \
	-DVENDOR_ID=$(VENDOR_ID) \
	-DCPU_FAMILY=$(CPU_FAMILY)

EXTRA_CFLAGS += -g -DDEBUG

ifdef VMBUILD
EXTRA_CFLAGS += -DVMBUILD
endif

all:
ifeq ($(shell cat /sys/devices/virtual/dmi/id/sys_vendor), QEMU)
ifndef VMBUILD
	$(warning WARNING: VM environment detected; it's recommented to use `make VMBUILD=1`)
else
	$(eval EXTRA_CFLAGS += -DVMBUILD)
endif
endif
	make -C $(KDIR) M=$(PWD) modules

clean:
	make -C $(KDIR) M=$(PWD) clean

install:
	sudo insmod $(NAME).ko

uninstall:
	sudo rmmod $(NAME)

dbg_symbols:
	objcopy --only-keep-debug $(NAME).o $(NAME).dbg
	sudo cat /sys/module/$(NAME)/sections/.text

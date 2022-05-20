NAME = x86_executor

ccflags-y += -std=gnu11 -Wno-declaration-after-statement -DL1D_ASSOCIATIVITY=$(shell cat /sys/devices/system/cpu/cpu0/cache/index0/ways_of_associativity)

obj-m += $(NAME).o
$(NAME)-objs += main.o templates.o measurement.o


KDIR=/lib/modules/$(shell uname -r)/build
# KDIR=/home/t-oleksenkoo/kernel/linux

all:
	make -C $(KDIR) M=$(PWD) modules

clean:
	make -C $(KDIR) M=$(PWD) clean

install:
	sudo insmod $(NAME).ko

uninstall:
	sudo rmmod $(NAME)
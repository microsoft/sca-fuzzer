NAME = arm64_executor

L1D_ASSOCIATIVITY=$(shell cat /sys/devices/system/cpu/cpu0/cache/index0/ways_of_associativity)
L1D_SIZE_K=$(shell cat /sys/devices/system/cpu/cpu0/cache/index0/size | sed -e "s:K::g" )

ccflags-y += -std=gnu11 -Wno-declaration-after-statement -DL1D_ASSOCIATIVITY=$(L1D_ASSOCIATIVITY) -DL1D_SIZE_K=$(L1D_SIZE_K)

obj-m += $(NAME).o
$(NAME)-objs += main.o templates.o measurement.o


KDIR=/lib/modules/$(shell uname -r)/build

all:
	make -C $(KDIR) M=$(PWD) modules

clean:
	make -C $(KDIR) M=$(PWD) clean

install:
	sudo insmod $(NAME).ko

uninstall:
	sudo rmmod $(NAME)

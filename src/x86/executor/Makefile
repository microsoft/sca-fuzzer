NAME = x86_executor
KDIR=/lib/modules/$(shell uname -r)/build

obj-m += $(NAME).o
$(NAME)-objs += fault_handler.o perf_counters.o vmx.o \
    special_registers.o host_page_tables.o memory_guest.o \
    input_parser.o test_case_parser.o code_loader.o data_loader.o macro_loader.o \
    sandbox_manager.o measurement.o main.o
VPATH += $(src)/hw_features

# build flags
ifneq ($(shell grep "Intel" /proc/cpuinfo),)
	VENDOR_ID=1
else ifneq ($(shell grep "AMD" /proc/cpuinfo),)
	VENDOR_ID=2

# deprecated?
ifneq ($(shell grep -m1 "cpu family" /proc/cpuinfo | grep "23" ),)
	CPU_FAMILY=23
else
	CPU_FAMILY=25 # Default to 19h
endif
endif

EXTRA_CFLAGS += -I$(src)/include
EXTRA_CFLAGS += -std=gnu11 -Wno-declaration-after-statement -Wno-comment -msse2
EXTRA_CFLAGS += -g -DDEBUG
EXTRA_CFLAGS += \
    -DL1D_ASSOCIATIVITY=$(shell cat /sys/devices/system/cpu/cpu0/cache/index0/ways_of_associativity)
EXTRA_CFLAGS += -DVENDOR_ID=$(VENDOR_ID)
EXTRA_CFLAGS += -DCPU_FAMILY=$(CPU_FAMILY)
EXTRA_CFLAGS += -DFORCE_SMAP_OFF
EXTRA_CFLAGS += -DPHYSICAL_WIDTH=$(shell grep -m1 "bits physical," /proc/cpuinfo | awk '{print $$4}')

ifdef VMBUILD
EXTRA_CFLAGS += -DVMBUILD
endif

# disable objtool warnings - a lot of code in the module violates the checks intentionally,
# so it's impossible to fix
CONFIG_RETHUNK=n
CONFIG_RETPOLINE=n
CONFIG_STACK_VALIDATION=n
CONFIG_X86_KERNEL_IBT=n
CONFIG_HAVE_UACCESS_VALIDATION=n


# file-specific flags
CFLAGS_code_loader.o := -Wno-attribute-warning  # workaround for __write_overflow_field warning

# build targets
all:
ifeq ($(shell cat /sys/devices/virtual/dmi/id/sys_vendor), QEMU)
ifndef VMBUILD
	$(error ERROR: VM environment detected; use `make VMBUILD=1`)
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

# --------------- debugging crushes ---------------
dbg_symbols:
	objcopy --only-keep-debug $(NAME).o $(NAME).dbg
	sudo cat /sys/module/$(NAME)/sections/.text
# continue manually with gdb:
# (if the executor is in a VM):
#       scp vm:revizor_dir/$x86_executor.dbg .
# gdb
#   target remote localhost:1234
#   add-symbol-file x86_executor.dbg <addr>  # addr is the address printed by the cat command above
#   b run_experiment  # or any other function that you want to debug
#   (if guest VM path does not match the host path):
#       set substitute-path /home/revizor_dir /home/revizor_dir
#   c

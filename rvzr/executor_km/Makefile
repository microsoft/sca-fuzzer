NAME = rvzr_executor
KDIR=/lib/modules/$(shell uname -r)/build

# Determine CPU vendor
ifneq ($(shell grep "Intel" /proc/cpuinfo),)
VENDOR_ID = 1
else ifneq ($(shell grep "AMD" /proc/cpuinfo),)
VENDOR_ID = 2
else ifneq ($(shell lscpu | grep "aarch64"),)
VENDOR_ID = 3
else
$(error "Unknown CPU vendor")
endif

# Object files
SRC_ = input_parser.c test_case_parser.c code_loader.c data_loader.c sandbox_manager.c \
	measurement.c main.c macro_expansion.c
SRC_X86 = x86/vmx.c x86/svm.c x86/perf_counters.c x86/host_page_tables.c x86/memory_guest.c \
	x86/special_registers.c x86/fault_handler.c x86/macros.c
ASM_X86 =
SRC_ARM64 = arm64/fault_handler.c arm64/perf_counters.c arm64/special_registers.c \
	arm64/host_page_tables.c arm64/memory_guest.c arm64/macros.c
ASM_ARM64 = arm64/exception.S

ifeq ($(VENDOR_ID), 1)
SRC_ += $(SRC_X86)
ASM_ += $(ASM_X86)
else ifeq ($(VENDOR_ID), 2)
SRC_ += $(SRC_X86)
ASM_ += $(ASM_X86)
else ifeq ($(VENDOR_ID), 3)
SRC_ += $(SRC_ARM64)
ASM_ += $(ASM_ARM64)
endif

obj-m += $(NAME).o
$(NAME)-objs += $(SRC_:.c=.o) $(ASM_:.S=.o)

# Common build flags
EXTRA_CFLAGS += -I$(src)/include
EXTRA_CFLAGS += -std=gnu11 -Wno-declaration-after-statement -Wno-comment
EXTRA_CFLAGS += -g -DDEBUG
EXTRA_CFLAGS += -DVENDOR_ID=$(VENDOR_ID)
EXTRA_CFLAGS += -DFORCE_SMAP_OFF
EXTRA_CFLAGS += -DPHYSICAL_WIDTH=$(shell grep -m1 "bits physical," /proc/cpuinfo | awk '{print $$4}')
ifeq ($(shell ls /sys/devices/system/cpu/cpu0/cache/index0/ways_of_associativity 2>/dev/null),)
$(error "Cache info not found")
endif
EXTRA_CFLAGS += -DL1D_ASSOCIATIVITY=$(shell cat /sys/devices/system/cpu/cpu0/cache/index0/ways_of_associativity)

ifeq ($(VENDOR_ID), 1)
EXTRA_CFLAGS += -msse2
else ifeq ($(VENDOR_ID), 2)
EXTRA_CFLAGS += -msse2
endif

ifdef VMBUILD
EXTRA_CFLAGS += -DVMBUILD
endif

# Suppress objtool warnings - a lot of code in the module violates the checks intentionally,
# so it's impossible to fix
GREP_FILTER = "return found in RETHUNK|indirect call found in RETPOLINE|call without frame pointer|undefined stack stae|return with modified stack frame|unsupported instruction in callable|undefined stack state|ENDBR: "
OBJECT_FILES_NON_STANDARD := y

# File-specific flags
CFLAGS_code_loader.o := -Wno-attribute-warning # workaround for __write_overflow_field warning

# Check if VMBUILD is required
ifndef VMBUILD
sys_vendor = $(shell cat /sys/devices/virtual/dmi/id/sys_vendor)
is_vm_vendor = 'no'
ifeq ($(sys_vendor), QEMU)
is_vm_vendor = 'yes'
endif
ifeq ($(sys_vendor), Microsoft Corporation)
is_vm_vendor = 'yes'
endif
endif

# build targets
all:
ifndef VMBUILD
ifeq ($(is_vm_vendor), 'yes')
	$(error ERROR: VM or WSL environment detected; use `make VMBUILD=1`)
endif
endif
	make -C $(KDIR) M=$(PWD) modules 2>&1 | grep -vE $(GREP_FILTER)

clean:
	make -C $(KDIR) M=$(PWD) clean

install:
	sudo insmod $(NAME).ko

uninstall:
	sudo rmmod $(NAME) || true

# --------------- debugging crushes ---------------
dbg_symbols:
	objcopy --only-keep-debug $(NAME).o $(NAME).dbg
	sudo cat /sys/module/$(NAME)/sections/.text
# continue manually with gdb:
# (if the executor is in a VM):
#       scp vm:revizor_dir/$rvzr_executor.dbg .
# gdb -ex "target remote localhost:1234" -ex "set substitute-path /home/revizor_dir /home/revizor_dir"
#   target remote localhost:1234
#   add-symbol-file rvzr_executor.dbg <addr>  # addr is the address printed by the cat command above
#   b run_experiment  # or any other function that you want to debug
#   (if guest VM path does not match the host path):
#       set substitute-path /home/revizor_dir /home/revizor_dir
#   c

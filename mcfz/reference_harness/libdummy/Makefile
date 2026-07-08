#
# File: Makefile
#       Build the stand-in "external" library, libdummy, as a static archive.
#       This mimics building a real third-party library that the harness links
#       against; the harness itself contains no cryptographic code.
#

# Compiler. Defaults to clang but is overridden by the harness build, which
# passes the native or the AFL-instrumented compiler depending on the target.
ifeq ($(origin CC),default)
CC := clang
endif

# Output directory. The harness build uses separate directories for its native
# and AFL configurations so their objects never mix.
BUILD_DIR ?= build

# -O0 keeps the key-dependent branch a real branch (higher optimization levels
# may fold it into a branchless sequence and hide the control-flow leak).
# -g emits the DWARF info MCFuzz uses to map leaks back to source lines.
CFLAGS ?= -std=gnu11 -O0 -g -Wall -Wextra
CFLAGS += -I.

LIB := $(BUILD_DIR)/libdummy.a
OBJ := $(BUILD_DIR)/dummy_lib.o

.PHONY: all clean

all: $(LIB)

$(LIB): $(OBJ)
	$(AR) rcs $@ $^

$(OBJ): dummy_lib.c dummy_lib.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

clean:
	rm -rf $(BUILD_DIR)

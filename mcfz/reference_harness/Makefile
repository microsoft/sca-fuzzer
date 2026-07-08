#
# File: Makefile
#       Build the reference harness in two configurations:
#         * native  (reference-harness-native) — used by MCFuzz's tracing stage
#         * AFL      (reference-harness-afl)     — used by MCFuzz's fuzz_gen stage
#
# The harness contains no cryptographic code of its own: it links against the
# stand-in "external" library in libdummy/, which is built (per configuration)
# by its own Makefile.
#

# ---------------------------------------------------------------------------
# Toolchain
# ---------------------------------------------------------------------------
# Native compiler for the tracing binary. Needs debug info so MCFuzz can map
# leaks back to source lines via DWARF. Default to clang (the MCFuzz toolchain),
# but honor an explicit override from the environment or the command line.
ifeq ($(origin CC),default)
CC := clang
endif

# AFL++ installation directory. Override to point at your AFL++ location, e.g.
#   make afl AFL_ROOT=~/bin/AFLplusplus
AFL_ROOT ?= $(HOME)/.local/afl
AFL_CC := $(AFL_ROOT)/afl-clang-fast

# ---------------------------------------------------------------------------
# Sources and includes
# ---------------------------------------------------------------------------
LIBDUMMY_DIR := libdummy

# The harness is a single translation unit. The stand-in library is built and
# linked separately.
SRCS := harness.c

INCLUDES := -I$(LIBDUMMY_DIR)

# -O0 keeps the key-dependent branch a real branch (higher optimization levels
# may replace it with a branchless sequence and hide the control-flow leak).
# -g emits the DWARF info MCFuzz uses to map leaks to source lines.
CFLAGS := -std=gnu11 -O0 -g -Wall -Wextra $(INCLUDES)

# The stand-in library, built once per harness configuration into its own dir.
LIBDUMMY_NATIVE := $(LIBDUMMY_DIR)/build-native/libdummy.a
LIBDUMMY_AFL := $(LIBDUMMY_DIR)/build-afl/libdummy.a

# Output directory for the harness binaries. Defaults to the current directory;
# override to place them elsewhere (the directory is created if needed), e.g.
#   make HARNESS_BUILD_DIR=~/mcfz-quickstart
HARNESS_BUILD_DIR ?= .

NATIVE_BIN := $(HARNESS_BUILD_DIR)/harness-native
AFL_BIN := $(HARNESS_BUILD_DIR)/harness-afl

# ---------------------------------------------------------------------------
# Targets
# ---------------------------------------------------------------------------
.PHONY: all native afl clean FORCE

all: native afl

native: $(NATIVE_BIN)

$(NATIVE_BIN): $(SRCS) $(LIBDUMMY_NATIVE) | $(HARNESS_BUILD_DIR)
	$(CC) $(CFLAGS) $(SRCS) $(LIBDUMMY_NATIVE) -o $@

$(LIBDUMMY_NATIVE): FORCE
	$(MAKE) -C $(LIBDUMMY_DIR) BUILD_DIR=build-native CC="$(CC)"

afl: $(AFL_BIN)

$(AFL_BIN): $(SRCS) $(LIBDUMMY_AFL) | $(HARNESS_BUILD_DIR)
	$(AFL_CC) $(CFLAGS) $(SRCS) $(LIBDUMMY_AFL) -o $@

$(LIBDUMMY_AFL): FORCE
	@if [ ! -x "$(AFL_CC)" ]; then \
		echo "error: AFL compiler not found at $(AFL_CC)"; \
		echo "       set AFL_ROOT=<afl install dir> (e.g. AFL_ROOT=~/bin/AFLplusplus)"; \
		exit 1; \
	fi
	$(MAKE) -C $(LIBDUMMY_DIR) BUILD_DIR=build-afl CC="$(AFL_CC)"

# Create the output directory when a non-default HARNESS_BUILD_DIR is requested.
# The default '.' always exists, so this rule never runs for it.
$(HARNESS_BUILD_DIR):
	mkdir -p $@

clean:
	rm -f $(NATIVE_BIN) $(AFL_BIN)
	$(MAKE) -C $(LIBDUMMY_DIR) clean BUILD_DIR=build-native
	$(MAKE) -C $(LIBDUMMY_DIR) clean BUILD_DIR=build-afl

FORCE:

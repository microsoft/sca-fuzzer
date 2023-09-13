/// File: Main Header
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#ifndef X86_EXECUTOR
#define X86_EXECUTOR

#include <asm/traps.h>
#include <linux/types.h>
#include <linux/version.h>

#define EXECUTOR_DEBUG 0

// Executor Configuration Interface
extern bool quick_and_dirty_mode;
extern long uarch_reset_rounds;
#define UARCH_RESET_ROUNDS_DEFAULT 1
extern uint64_t ssbp_patch_control;
#define SSBP_PATH_DEFAULT SSBP_PATCH_ON
extern uint64_t prefetcher_control;
#define PREFETCHER_DEFAULT PREFETCHER_OFF
extern char pre_run_flush;
#define PRE_RUN_FLUSH_DEFAULT 1
extern uint64_t mpx_control; // MPX - unused on AMD
#define MPX_DEFAULT 0
extern char *attack_template;

// Linux Kernel compatibility
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0)
#include <linux/kallsyms.h>
extern int (*set_memory_x)(unsigned long, int);
extern int (*set_memory_nx)(unsigned long, int);
#else
#include <linux/set_memory.h>
#endif

#endif // X86_EXECUTOR

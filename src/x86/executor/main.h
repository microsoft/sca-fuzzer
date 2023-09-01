/// File: Main Header
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#ifndef X86_EXECUTOR
#define X86_EXECUTOR

#include <asm/traps.h>
#include <linux/types.h>
#include <linux/version.h>

#define DEBUG 0
#define STRINGIFY(...) #__VA_ARGS__

// HW configuration
#ifndef VENDOR_ID
#error "Undefined VENDOR_ID"
#define VENDOR_ID 0
#endif

#ifndef L1D_ASSOCIATIVITY
#error "Undefined L1D_ASSOCIATIVITY"
#define L1D_ASSOCIATIVITY 0
#elif L1D_ASSOCIATIVITY != 12 && L1D_ASSOCIATIVITY != 8
#warning "Unsupported/corrupted L1D associativity. Falling back to 8-way"
#define L1D_ASSOCIATIVITY 8
#endif

// =================================================================================================
// Model-specific constants
// =================================================================================================
#if VENDOR_ID == 1 // Intel
#define SSBP_PATCH_ON 0b111
#define SSBP_PATCH_OFF 0b011
#define PREFETCHER_ON 0
#define PREFETCHER_OFF 15

#elif VENDOR_ID == 2 // AMD
#define SSBP_PATCH_ON 0b111
#define SSBP_PATCH_OFF 0b011
#define PREFETCHER_ON 0b000000
#define PREFETCHER_OFF 0b101111
#endif

// =================================================================================================
// Executor Configuration Interface
// =================================================================================================
extern bool quick_and_dirty_mode;
extern long uarch_reset_rounds;
#define UARCH_RESET_ROUNDS_DEFAULT 1
extern uint64_t ssbp_patch_control;
#define SSBP_PATH_DEFAULT SSBP_PATCH_ON
extern uint64_t prefetcher_control;
#define PREFETCHER_DEFAULT PREFETCHER_OFF
extern char pre_run_flush;
#define PRE_RUN_FLUSH_DEFAULT 1
extern char mpx_control; // MPX - unused on AMD
#define MPX_DEFAULT 0
extern char *attack_template;

// =================================================================================================
// Measurements
// =================================================================================================
#define HTRACE_WIDTH 1
#define NUM_PFC 5

typedef struct Measurement
{
    uint64_t htrace[HTRACE_WIDTH];
    uint64_t pfc[NUM_PFC];
} measurement_t;

extern measurement_t *measurements;

int trace_test_case(void);
int alloc_measurements(void);

int init_measurements(void);
void free_measurements(void);

// =================================================================================================
// Sandbox
// =================================================================================================
#define WORKING_MEMORY_SIZE 1048576 // 256KB
#define MAIN_REGION_SIZE 4096
#define FAULTY_REGION_SIZE 4096
#define OVERFLOW_REGION_SIZE 4096
#define REG_INITIALIZATION_REGION_SIZE 64
#define REG_INITIALIZATION_REGION_SIZE_ALIGNED 4096
#define EVICT_REGION_SIZE (L1D_ASSOCIATIVITY * 4096)

typedef struct Sandbox
{
    char eviction_region[EVICT_REGION_SIZE];   // region used in Prime+Probe for priming
    char lower_overflow[OVERFLOW_REGION_SIZE]; // zero-initialized region for accidental overflows
    char main_region[MAIN_REGION_SIZE];        // first input page. does not cause faults
    char faulty_region[FAULTY_REGION_SIZE];    // second input. causes a (configurable) fault
    char upper_overflow[OVERFLOW_REGION_SIZE]; // zero-initialized region for accidental overflows
    uint64_t stored_rsp;
    measurement_t latest_measurement; // measurement results
} sandbox_t;

extern sandbox_t *sandbox;
extern void *stack_base;

#define REG_INIT_OFFSET 8192 // (MAIN_REGION_SIZE + FAULTY_REGION_SIZE)
#define EVICT_REGION_OFFSET (EVICT_REGION_SIZE + OVERFLOW_REGION_SIZE)
#define RSP_OFFSET 12288         // (MAIN_REGION_SIZE + FAULTY_REGION_SIZE + OVERFLOW_REGION_SIZE)
#define MEASUREMENT_OFFSET 12296 // RSP_OFFSET + sizeof(stored_rsp)

int alloc_and_map_sandboxes(void);

int init_sandbox(void);
void free_sandbox(void);

// =================================================================================================
// Test Case
// =================================================================================================
extern char *test_case;
#define MAX_TEST_CASE_SIZE 4096 // must be exactly 1 page to detect sysfs buffering
extern char *measurement_code;
#define MAX_MEASUREMENT_CODE_SIZE (4096 * 2)
extern char *measurement_template;

extern int loaded_tc_size;

int init_test_case_manager(void);
void free_test_case_manager(void);

// =================================================================================================
// Input management
// =================================================================================================

// =================================================================================================
// Fault handling
// =================================================================================================
#define HANDLED_FAULTS_DEFAULT                                                                     \
    ((1 << X86_TRAP_DE) + (1 << X86_TRAP_DB) + (1 << X86_TRAP_BP) + (1 << X86_TRAP_BR) +           \
     (1 << X86_TRAP_UD) + (1 << X86_TRAP_GP) + (1 << X86_TRAP_PF))

extern char *fault_handler;
extern uint32_t handled_faults;
extern gate_desc *curr_idt_table;
extern pteval_t faulty_pte_mask_set;
extern pteval_t faulty_pte_mask_clear;

// =================================================================================================
// Shared functions
// =================================================================================================
int load_template(size_t tc_size);
void template_l1d_prime_probe(void);
void template_l1d_prime_probe_fast(void);
void template_l1d_prime_probe_partial(void);
void template_l1d_prime_probe_partial_fast(void);
void template_l1d_flush_reload(void);
void template_l1d_evict_reload(void);
void template_gpr(void);

// Missing definition of set_memory_{x,nx} in newer kernels
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0)
#include <linux/kallsyms.h>
extern int (*set_memory_x)(unsigned long, int);
extern int (*set_memory_nx)(unsigned long, int);
#else
#include <linux/set_memory.h>
#endif

#define BIT_SET(a, b) ((a) |= (1ULL << (b)))
#define BIT_CLEAR(a, b) ((a) &= ~(1ULL << (b)))
#define BIT_FLIP(a, b) ((a) ^= (1ULL << (b)))
#define BIT_CHECK(a, b) (!!((a) & (1ULL << (b))))

#define xstr(s) _str(s)
#define _str(s) str(s)
#define str(s) #s

#define asm_volatile_intel(ASM)                                                                    \
    asm volatile(                                                                                  \
    "\n.intel_syntax noprefix                  \n"                                                 \
    ASM                                                                                            \
    ".att_syntax noprefix                    ")

// =================================================================================================
// Checking for internal errors
// =================================================================================================
#define PRINT_ERR(msg, ...) printk(KERN_ERR "[x86_executor] " msg, ##__VA_ARGS__);
#define PRINT_ERRS(src, msg, ...) printk(KERN_ERR "[x86_executor:" src "] " msg, ##__VA_ARGS__);

#define CHECK_ERR(msg)                                                                             \
    if (err)                                                                                       \
    {                                                                                              \
        PRINT_ERR(" Error [" msg "]\n");                                                           \
        return err;                                                                                \
    }
#define CHECK_ERR_RETURN_NULL(msg)                                                                 \
    if (err)                                                                                       \
    {                                                                                              \
        PRINT_ERR("  Error [" msg "]\n");                                                          \
        return 0;                                                                                  \
    }
#define CHECK_NONULL(ptr, msg)                                                                     \
    if (!ptr)                                                                                      \
    {                                                                                              \
        PRINT_ERR(" Null pointer [" msg "]\n");                                                    \
        return -EIO;                                                                               \
    }
#define CHECK_NONULL_RETURN_NULL(ptr, msg)                                                         \
    if (!ptr)                                                                                      \
    {                                                                                              \
        PRINT_ERR(" Null pointer [" msg "]\n");                                                    \
        return NULL;                                                                               \
    }
#define SAFE_FREE(x)                                                                               \
    if (x)                                                                                         \
    {                                                                                              \
        kfree(x);                                                                                  \
        x = NULL;                                                                                  \
    }
#define CHECKED_MALLOC(x)                                                                          \
    ({                                                                                             \
        void *ptr = kmalloc(x, GFP_KERNEL);                                                        \
        if (!ptr)                                                                                  \
        {                                                                                          \
            PRINT_ERR(" Error allocating memory\n");                                               \
            return -EIO;                                                                           \
        }                                                                                          \
        ptr;                                                                                       \
    })
#define CHECKED_ZALLOC(x)                                                                          \
    ({                                                                                             \
        void *ptr = kzalloc(x, GFP_KERNEL);                                                        \
        if (!ptr)                                                                                  \
        {                                                                                          \
            PRINT_ERR(" Error zero-allocating memory\n");                                          \
            return -EIO;                                                                           \
        }                                                                                          \
        ptr;                                                                                       \
    })
#define CHECKED_VMALLOC(x)                                                                         \
    ({                                                                                             \
        void *ptr = vmalloc(x);                                                                    \
        if (!ptr)                                                                                  \
        {                                                                                          \
            PRINT_ERR(" Error allocating memory\n");                                               \
            return -EIO;                                                                           \
        }                                                                                          \
        ptr;                                                                                       \
    })
#define SAFE_VFREE(x)                                                                              \
    if (x)                                                                                         \
    {                                                                                              \
        vfree(x);                                                                                  \
        x = NULL;                                                                                  \
    }

#endif

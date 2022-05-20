/// File: Main Header
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#ifndef X86_EXECUTOR
#define X86_EXECUTOR

#include <linux/types.h>

#define DEBUG 0

// Executor Configuration Interface
extern long uarch_reset_rounds;
#define UARCH_RESET_ROUNDS_DEFAULT 1
extern uint64_t ssbp_patch_control;
#define SSBP_PATH_DEFAULT 0b011
extern char enable_faulty_page;
#define ENABLE_FAULTY_DEFAULT 0
extern char pre_run_flush;
#define PRE_RUN_FLUSH_DEFAULT 1
extern char *attack_template;

// Attack configuration
#ifndef L1D_ASSOCIATIVITY
#error "Undefined associativity"
#elif L1D_ASSOCIATIVITY != 12 && L1D_ASSOCIATIVITY != 8
#warning "Unsupported/corrupted L1D associativity. Falling back to 8-way"
#define L1D_ASSOCIATIVITY 8
#endif

// Measurement results
#define HTRACE_WIDTH 1
#define NUM_PFC 3

typedef struct Measurement
{
    uint64_t htrace[HTRACE_WIDTH];
    uint64_t pfc[NUM_PFC];
} measurement_t;

extern measurement_t *measurements;

// Sandbox
#define WORKING_MEMORY_SIZE 1048576 // 256KB
#define MAIN_REGION_SIZE 4096
#define FAULTY_REGION_SIZE 4096
#define OVERFLOW_REGION_SIZE 4096
#define REG_INITIALIZATION_REGION_SIZE 64
#define EVICT_REGION_SIZE (L1D_ASSOCIATIVITY * 4096)

typedef struct Sandbox
{
    char eviction_region[EVICT_REGION_SIZE];  // region used in Prime+Probe for priming
    char lower_overflow[OVERFLOW_REGION_SIZE];  // zero-initialized region for accidental overflows
    char main_region[MAIN_REGION_SIZE];  // first input page. does not cause faults
    char faulty_region[FAULTY_REGION_SIZE];  // second input. causes a (configurable) fault
    char upper_overflow[OVERFLOW_REGION_SIZE];  // zero-initialized region for accidental overflows
    uint64_t stored_rsp;
    measurement_t latest_measurement;  // measurement results
} sandbox_t;

extern sandbox_t *sandbox;
extern void *stack_base;

#define REG_INIT_OFFSET 8192 // (MAIN_REGION_SIZE + FAULTY_REGION_SIZE)
#define EVICT_REGION_OFFSET (EVICT_REGION_SIZE + OVERFLOW_REGION_SIZE)
#define RSP_OFFSET 12288 // (MAIN_REGION_SIZE + FAULTY_REGION_SIZE + OVERFLOW_REGION_SIZE)
#define MEASUREMENT_OFFSET 12296 // RSP_OFFSET + sizeof(stored_rsp)

// Test Case
extern char *test_case;
#define MAX_TEST_CASE_SIZE 4096 // must be exactly 1 page to detect sysfs buffering
extern char *measurement_code;
#define MAX_MEASUREMENT_CODE_SIZE (4096 * 2)
extern char *measurement_template;

// Inputs
#define REG_INITIALIZATION_REGION_SIZE_ALIGNED 4096
#define INPUT_SIZE (MAIN_REGION_SIZE + FAULTY_REGION_SIZE + REG_INITIALIZATION_REGION_SIZE_ALIGNED)
extern uint64_t *inputs;
extern volatile size_t n_inputs;

// Shared functions
int trace_test_case(void);
int load_template(size_t tc_size);
void template_l1d_prime_probe(void);
void template_l1d_flush_reload(void);
void template_l1d_evict_reload(void);

#endif
/// File: Header for sandbox management
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#ifndef _X86_EXECUTOR_SANDBOX_H_
#define _X86_EXECUTOR_SANDBOX_H_

#include "hardware.h"
#include "measurement.h"
#include <linux/types.h>

#define WORKING_MEMORY_SIZE                    1048576 // 256KB
#define MAIN_REGION_SIZE                       4096
#define FAULTY_REGION_SIZE                     4096
#define OVERFLOW_REGION_SIZE                   4096
#define REG_INITIALIZATION_REGION_SIZE         64
#define REG_INITIALIZATION_REGION_SIZE_ALIGNED 4096
#define EVICT_REGION_SIZE                      (L1D_ASSOCIATIVITY * 4096)
#define MACRO_STACK_PADDING                    (4096 - sizeof(measurement_t) - sizeof(uint64_t))

typedef uint64_t rsp_t;

typedef struct Sandbox
{
    char eviction_region[EVICT_REGION_SIZE];   // region used in Prime+Probe for priming
    char lower_overflow[OVERFLOW_REGION_SIZE]; // zero-initialized region for accidental overflows
    char main_region[MAIN_REGION_SIZE];        // first input page. does not cause faults
    char faulty_region[FAULTY_REGION_SIZE];    // second input. causes a (configurable) fault
    char upper_overflow[OVERFLOW_REGION_SIZE]; // zero-initialized region for accidental overflows
    rsp_t rsp_before_test_case;
    measurement_t latest_measurement;  // measurement results
    char padding[MACRO_STACK_PADDING]; // ensures that macro_stack uses the first cache line
    char macro_stack[64];
} sandbox_t;

// offsets w.r.t. the base of main_region (r14 will be initialized to point there)
#define EVICT_REGION_OFFSET    (OVERFLOW_REGION_SIZE + EVICT_REGION_SIZE)
#define LOWER_OVERFLOW_OFFSET  (OVERFLOW_REGION_SIZE)
#define MAIN_REGION_OFFSET     0
#define FAULTY_REGION_OFFSET   (MAIN_REGION_SIZE)
#define REG_INIT_OFFSET        (FAULTY_REGION_OFFSET + FAULTY_REGION_SIZE)
#define RSP_OFFSET             (REG_INIT_OFFSET + OVERFLOW_REGION_SIZE)
#define MEASUREMENT_OFFSET     (RSP_OFFSET + 8)
#define MACRO_STACK_TOP_OFFSET (RSP_OFFSET + 4096 + 64)

extern sandbox_t *sandbox;
extern void *stack_base;

void write_sandbox(uint64_t *current_input);

int alloc_and_map_sandboxes(void);
int init_sandbox(void);
void free_sandbox(void);

#endif // _X86_EXECUTOR_SANDBOX_H_

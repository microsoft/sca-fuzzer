/// File: Header for sandbox management
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#ifndef _X86_EXECUTOR_SANDBOX_H_
#define _X86_EXECUTOR_SANDBOX_H_

#include <linux/types.h>
#include "measurement.h"
#include "hardware.h"

#define WORKING_MEMORY_SIZE 1048576 // 256KB
#define MAIN_REGION_SIZE 4096
#define FAULTY_REGION_SIZE 4096
#define OVERFLOW_REGION_SIZE 4096
#define REG_INITIALIZATION_REGION_SIZE 64
#define REG_INITIALIZATION_REGION_SIZE_ALIGNED 4096
#define EVICT_REGION_SIZE (L1D_ASSOCIATIVITY * 4096)

#define REG_INIT_OFFSET 8192 // (MAIN_REGION_SIZE + FAULTY_REGION_SIZE)
#define EVICT_REGION_OFFSET (EVICT_REGION_SIZE + OVERFLOW_REGION_SIZE)
#define RSP_OFFSET 12288         // (MAIN_REGION_SIZE + FAULTY_REGION_SIZE + OVERFLOW_REGION_SIZE)
#define MEASUREMENT_OFFSET 12296 // RSP_OFFSET + sizeof(stored_rsp)

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

void write_sandbox(uint64_t *current_input);

int alloc_and_map_sandboxes(void);
int init_sandbox(void);
void free_sandbox(void);

#endif // _X86_EXECUTOR_SANDBOX_H_

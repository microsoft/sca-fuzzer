/// File: Header for sandbox management
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#ifndef _X86_EXECUTOR_SANDBOX_H_
#define _X86_EXECUTOR_SANDBOX_H_

#include "hardware.h"
#include "measurement.h"
#include <linux/types.h>

#define MAIN_AREA_SIZE             4096
#define FAULTY_AREA_SIZE           4096
#define OVERFLOW_PAD_SIZE          4096
#define REG_INIT_AREA_SIZE         64
#define REG_INIT_AREA_SIZE_ALIGNED 4096
#define L1D_PRIMING_AREA_SIZE      (L1D_ASSOCIATIVITY * 4096)
#define MACRO_STACK_PADDING        (4096 - 64)

typedef uint64_t rsp_t;

typedef struct Sandbox {
    char underflow_pad[OVERFLOW_PAD_SIZE]; // zero-initialized region for accidental underflows
    char main_area[MAIN_AREA_SIZE];        // first input page; does not cause faults
    char faulty_area[FAULTY_AREA_SIZE];    // second input page; causes a (configurable) fault
    char overflow_pad[OVERFLOW_PAD_SIZE];  // zero-initialized region for accidental overflows
    char l1d_priming_area[L1D_PRIMING_AREA_SIZE]; // region used in Prime+Probe for priming
    char macro_stack[64];                         // stack for storing registers when calling macros
    char mstack_padding[MACRO_STACK_PADDING]; // ensures that next field uses the first cache line
    rsp_t stored_rsp;                 // stores the stack pointer before calling the test case
    measurement_t latest_measurement; // measurement results
} sandbox_t;

// offsets w.r.t. the base of main_area (r14 will be initialized to point there)
// note: we use these offsets to have clean immediates in the assembly code
#define UNDERFLOW_PAD_OFFSET   (OVERFLOW_PAD_SIZE)
#define MAIN_AREA_OFFSET       0
#define FAULTY_AREA_OFFSET     (MAIN_AREA_SIZE)
#define REG_INIT_OFFSET        (FAULTY_AREA_OFFSET + FAULTY_AREA_SIZE)
#define L1D_PRIMING_OFFSET     (REG_INIT_OFFSET + OVERFLOW_PAD_SIZE)
#define MACRO_STACK_TOP_OFFSET (L1D_PRIMING_OFFSET + L1D_PRIMING_AREA_SIZE + 64)
#define RSP_OFFSET             (L1D_PRIMING_OFFSET + L1D_PRIMING_AREA_SIZE + 4096)
#define MEASUREMENT_OFFSET     (RSP_OFFSET + 8)

extern sandbox_t *sandbox;
extern void *stack_base;

void write_sandbox(uint64_t *current_input);

int alloc_and_map_sandboxes(void);
int init_sandbox(void);
void free_sandbox(void);

#endif // _X86_EXECUTOR_SANDBOX_H_

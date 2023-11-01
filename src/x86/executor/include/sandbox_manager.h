/// File: Header for sandbox management
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#ifndef _SANDBOX_MANAGER_H_
#define _SANDBOX_MANAGER_H_

#include <linux/types.h>

#include "hardware_desc.h" // L1D_ASSOCIATIVITY
#include "measurement.h"   // measurement_t

// =================================================================================================
// Sandbox data layout
// =================================================================================================
#define L1D_PRIMING_AREA_SIZE (L1D_ASSOCIATIVITY * 4096)

// layout of actor_data_t
#define MACRO_STACK_SIZE   64
#define UNDERFLOW_PAD_SIZE (4096 - MACRO_STACK_SIZE)
#define MAIN_AREA_SIZE     4096
#define FAULTY_AREA_SIZE   4096
#define REG_INIT_AREA_SIZE 320 // 8 64-bit GPRs + 8 256-bit YMMs
#define OVERFLOW_PAD_SIZE  (4096 - REG_INIT_AREA_SIZE)

// offsets w.r.t. the base of util_t (r15 will be initialized to point there)
#define L1D_PRIMING_OFFSET 0
#define STORED_RSP_OFFSET  (L1D_PRIMING_AREA_SIZE)
#define MEASUREMENT_OFFSET (STORED_RSP_OFFSET + 8)

// offset of util_t w.r.t. the base of main_area of the main actor
#define UTIL_REL_TO_MAIN (L1D_PRIMING_AREA_SIZE + 4096 + UNDERFLOW_PAD_SIZE + MACRO_STACK_SIZE)

// offsets w.r.t. the base of main_area of the current actor (r14 will contain the base)
#define MACRO_STACK_TOP_OFFSET (UNDERFLOW_PAD_SIZE)
#define MAIN_AREA_OFFSET       0
#define FAULTY_AREA_OFFSET     (MAIN_AREA_SIZE)
#define REG_INIT_OFFSET        (FAULTY_AREA_OFFSET + FAULTY_AREA_SIZE)
#define OVERFLOW_PAD_OFFSET    (REG_INIT_OFFSET + REG_INIT_AREA_SIZE)
#define LOCAL_RSP_OFFSET       (FAULTY_AREA_OFFSET - 8)

/// @brief Utility data structure used by various primitives in the test case.
///        Must be allocated strictly before the main actor data as its code accesses
///        fields of util_t by using constant offsets from the base of its main_area.
typedef struct {
    uint8_t l1d_priming_area[L1D_PRIMING_AREA_SIZE];
    uint64_t stored_rsp;              // stores the stack pointer before calling the test case
    measurement_t latest_measurement; // measurement results
    uint8_t unused[4096 - 8 - sizeof(measurement_t)];
} __attribute__((packed)) util_t;

/// @brief Data structure representing the memory accessible by the actor's code
typedef struct {
    uint8_t macro_stack[MACRO_STACK_SIZE];     // stack for storing registers when calling macros
    uint8_t underflow_pad[UNDERFLOW_PAD_SIZE]; // zero-initialized region for accidental underflows
    uint8_t main_area[MAIN_AREA_SIZE];         // first input page; does not cause faults
    uint8_t faulty_area[FAULTY_AREA_SIZE];     // second input page; causes a (configurable) fault
    uint8_t reg_init_area[REG_INIT_AREA_SIZE]; // region for initializing registers
    uint8_t overflow_pad[OVERFLOW_PAD_SIZE];   // zero-initialized region for accidental overflows
} __attribute__((packed)) actor_data_t;

// =================================================================================================
// Sandbox code layout
// =================================================================================================
#define MAX_EXPANDED_SECTION_SIZE (0x1000 * 2)
#define MAX_EXPANDED_MACROS_SIZE  (0x1000)
// DBG: Uncomment the following lines to be able to see macros when using test_case_show interface
// #define MAX_EXPANDED_SECTION_SIZE (0x400)
// #define MAX_EXPANDED_MACROS_SIZE  (0x400)

typedef struct {
    uint8_t section[MAX_EXPANDED_SECTION_SIZE];
    uint8_t macros[MAX_EXPANDED_MACROS_SIZE];
} __attribute__((packed)) actor_code_t;

// =================================================================================================
// sandbox_t
// =================================================================================================
typedef struct {
    actor_data_t *data;
    actor_code_t *code;
    util_t *util;
} sandbox_t;

#define N_UTIL_PAGES (sizeof(util_t) / PAGE_SIZE)
#define N_DATA_PAGES_PER_ACTOR (sizeof(actor_data_t) / PAGE_SIZE)
#define N_CODE_PAGES_PER_ACTOR (sizeof(actor_code_t) / PAGE_SIZE)

extern sandbox_t *sandbox;

int get_n_sandbox_pages(void);

int allocate_sandbox(void);
int init_sandbox_manager(void);
void free_sandbox_manager(void);

#endif // _SANDBOX_MANAGER_H_

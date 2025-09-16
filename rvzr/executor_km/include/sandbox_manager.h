/// File: Header for sandbox management
///       See docs/sandbox.md for the description of the sandboxing mechanism.
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#ifndef _SANDBOX_MANAGER_H_
#define _SANDBOX_MANAGER_H_

#include <linux/types.h>

#include "sandbox_constants.h"

#include "hardware_desc.h" // L1D_ASSOCIATIVITY
#include "measurement.h"   // measurement_t

// =================================================================================================
// Sandbox data layout
// =================================================================================================
/// @brief Area with test-case global variables that are used to communicate with the executor
///        and store intermediate results
typedef struct {
    uint64_t stored_rsp;              // stores the stack pointer before calling the test case
    measurement_t latest_measurement; // measurement results
    uint64_t nested_fault;            // non-zero if a fault occurs during a fault handler
#if defined(ARCH_X86_64)
    uint8_t unused[UTIL_VARS_MAX - sizeof(measurement_t) - (2 * sizeof(uint64_t))];
#elif defined(ARCH_ARM)
    uint64_t k2u_target_address; // target address for k2u switches
    uint64_t u2k_target_address; // target address for u2k switches
    uint8_t unused[UTIL_VARS_MAX - sizeof(measurement_t) - (4 * sizeof(uint64_t))];
#endif // ARCH_ARM
} util_vars_t;

/// @brief Utility data structure used by various primitives in the test case.
///        Must be allocated strictly before the main actor data as its code accesses
///        fields of util_t by using constant offsets from the base of its main_area.
typedef struct {
    uint8_t l1d_priming_area[L1D_PRIMING_AREA_SIZE];
    util_vars_t vars;
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

// =================================================================================================
// Sandbox manager interface
// =================================================================================================
extern sandbox_t *sandbox;

int get_sandbox_size_pages(void);

int set_sandbox_page_tables(void);
void restore_orig_sandbox_page_tables(void);

void set_faulty_page_permissions(void);
void restore_faulty_page_permissions(void);

int allocate_sandbox(void);
void reset_code_area(void);

int init_sandbox_manager(void);
void free_sandbox_manager(void);

#endif // _SANDBOX_MANAGER_H_

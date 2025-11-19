/// File: Sandbox layout
/// (see docs/sandbox.md for layout description)
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#ifndef SANDBOX_H
#define SANDBOX_H

#include <stdint.h>

#include "rcbf.h"
#include "rdbf.h"
#include "sandbox_const.h"

// =================================================================================================
// Data sections
// =================================================================================================

// IMPORTANT! This structure must match the layout in rvzr/executor_km/include/sandbox_manager.h
typedef struct {
    uint8_t macro_stack[MACRO_STACK_SIZE];     // stack for storing registers when calling macros
    uint8_t underflow_pad[UNDERFLOW_PAD_SIZE]; // zero-initialized region for accidental underflows
    uint8_t main_area[MAIN_AREA_SIZE];         // first input page; does not cause faults
    uint8_t faulty_area[FAULTY_AREA_SIZE];     // second input page; causes a (configurable) fault
    uint8_t reg_init_area[REG_INIT_AREA_SIZE]; // region for initializing registers
    uint8_t overflow_pad[OVERFLOW_PAD_SIZE];   // zero-initialized region for accidental overflows
} __attribute__((packed)) data_section_t;

// =================================================================================================
// Code sections
// =================================================================================================

// IMPORTANT! This structure must match the layout in rvzr/executor_km/include/sandbox_manager.h
typedef struct {
    uint8_t code[MAX_EXPANDED_SECTION_SIZE];
    uint8_t unused[MACRO_AREA_SIZE]; // unused; mirrors the macro area in sandbox_manager.h
} __attribute__((packed)) code_section_t;

_Static_assert(MAX_ACTORS * sizeof(code_section_t) == (unsigned long)TEST_CASE_MAX_SIZE,
               "Invalid value of TEST_CASE_MAX_SIZE");

// =================================================================================================
// sandbox_t
// =================================================================================================
typedef struct {
    data_section_t *data;
    code_section_t *code;
} sandbox_t;

// =================================================================================================
// Functions
// =================================================================================================
int load_code_in_sandbox(rcbf_t *rcbf_data);
int load_data_in_sandbox(rdbf_t *rdbf_data, int input_id);
sandbox_t *get_sandbox();
int allocate_sandbox(uint64_t n_actors);
void free_sandbox();

#endif // SANDBOX_H

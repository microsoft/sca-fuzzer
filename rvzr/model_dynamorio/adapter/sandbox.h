/// File: Constants for the sandbox layout
/// (see docs/sandbox.md for layout description)
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#ifndef SANDBOX_H
#define SANDBOX_H

#include <stdint.h>

#include "rcbf.h"
#include "rdbf.h"

#define PAGE_SIZE 4096

// =================================================================================================
// Data sections
// =================================================================================================
// layout of code_section_t
#define MACRO_STACK_SIZE   64
#define UNDERFLOW_PAD_SIZE (PAGE_SIZE - MACRO_STACK_SIZE)
#define MAIN_AREA_SIZE     PAGE_SIZE
#define FAULTY_AREA_SIZE   PAGE_SIZE
#define REG_INIT_AREA_SIZE 320 // 8 64-bit GPRs + 8 256-bit YMMs
#define OVERFLOW_PAD_SIZE  (PAGE_SIZE - REG_INIT_AREA_SIZE)

#define REG_INIT_AREA_SIZE_ALIGNED PAGE_SIZE
#define STACK_OFFSET               (MAIN_AREA_SIZE - 8)
#define REG_INIT_OFFSET            (MAIN_AREA_SIZE + FAULTY_AREA_SIZE)
#define SIMD_INIT_OFFSET           (REG_INIT_OFFSET + 64)

#define GPR_SIZE       8
#define EFLAGS_INIT_ID 6
#define RSP_INIT_ID    7

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
#define MAX_EXPANDED_SECTION_SIZE (PAGE_SIZE * 2)
#define MACRO_AREA_SIZE           (PAGE_SIZE)

// IMPORTANT! This structure must match the layout in rvzr/executor_km/include/sandbox_manager.h
typedef struct {
    uint8_t code[MAX_EXPANDED_SECTION_SIZE];
    uint8_t unused[MACRO_AREA_SIZE]; // unused; mirrors the macro area in sandbox_manager.h
} __attribute__((packed)) code_section_t;

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

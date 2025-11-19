/// File: Constants for the sandbox layout
/// (see docs/sandbox.md for layout description)
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#ifndef SANDBOX_CONST_H
#define SANDBOX_CONST_H

#define PAGE_SIZE 4096U

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

// layout of code_section_t
#define MAX_ACTORS                16U
#define MAX_EXPANDED_SECTION_SIZE (PAGE_SIZE * 2)
#define MACRO_AREA_SIZE           (PAGE_SIZE)
#define TEST_CASE_MAX_SIZE        (MAX_ACTORS * (MAX_EXPANDED_SECTION_SIZE + MACRO_AREA_SIZE))

#endif // SANDBOX_CONST_H

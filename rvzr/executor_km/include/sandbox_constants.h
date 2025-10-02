/// File: Collection of constants that define the layout of the sandbox;
///       This file is intentionally separate from sandbox_manager.h so that
///       it can be included in assembly files as well.
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#ifndef _SANDBOX_CONSTANTS_H_
#define _SANDBOX_CONSTANTS_H_

#include "hardware_desc.h"

#define SIZE_UINT64 (8)

// layout of util_t
#define UTIL_VARS_MAX         4096
#define L1D_PRIMING_AREA_SIZE (L1D_SIZE_KB * 1024)
#define STORED_RSP_SIZE       SIZE_UINT64
#define MEASUREMENT_SIZE      56ULL  // see measurement.h
#define NESTED_FAULT_SIZE     SIZE_UINT64

// layout of actor_data_t
#define MACRO_STACK_SIZE   64
#define UNDERFLOW_PAD_SIZE (4096 - MACRO_STACK_SIZE)
#define MAIN_AREA_SIZE     4096
#define FAULTY_AREA_SIZE   4096
#define REG_INIT_AREA_SIZE 320 // 8 64-bit GPRs + 8 256-bit YMMs
#define OVERFLOW_PAD_SIZE  (4096 - REG_INIT_AREA_SIZE)

// Section sizes
#define MAX_EXPANDED_SECTION_SIZE (0x1000 * 2)
#define MAX_EXPANDED_MACROS_SIZE  (0x1000)

// offsets w.r.t. the base of util_t (r15 will be initialized to point there)
#define L1D_PRIMING_OFFSET  (0)
#define UTIL_VARS_OFFSET    (L1D_PRIMING_OFFSET + L1D_PRIMING_AREA_SIZE)
#define STORED_RSP_OFFSET   (UTIL_VARS_OFFSET + 0)
#define MEASUREMENT_OFFSET  (STORED_RSP_OFFSET + STORED_RSP_SIZE)
#define NESTED_FAULT_OFFSET (MEASUREMENT_OFFSET + MEASUREMENT_SIZE)
#define K2U_TARGET_OFFSET   (NESTED_FAULT_OFFSET + NESTED_FAULT_SIZE)
#define U2K_TARGET_OFFSET   (K2U_TARGET_OFFSET + SIZE_UINT64)

// offsets of util_t w.r.t. the base of main_area of the main actor
#define UTIL_REL_TO_MAIN                                                                           \
    (L1D_PRIMING_AREA_SIZE + UTIL_VARS_MAX + UNDERFLOW_PAD_SIZE + MACRO_STACK_SIZE)

// offsets w.r.t. the base of main_area of the current actor (r14 will contain the base)
#define MACRO_STACK_TOP_OFFSET (UNDERFLOW_PAD_SIZE)
#define MAIN_AREA_OFFSET       (0)
#define FAULTY_AREA_OFFSET     (MAIN_AREA_SIZE)
#define REG_INIT_OFFSET        (FAULTY_AREA_OFFSET + FAULTY_AREA_SIZE)
#define OVERFLOW_PAD_OFFSET    (REG_INIT_OFFSET + REG_INIT_AREA_SIZE)
#define LOCAL_RSP_OFFSET       (FAULTY_AREA_OFFSET - 8)

// area page IDs
#define MAIN_PAGE_ID   (MACRO_STACK_SIZE + UNDERFLOW_PAD_SIZE) / 4096
#define FAULTY_PAGE_ID (MACRO_STACK_SIZE + UNDERFLOW_PAD_SIZE + MAIN_AREA_SIZE) / 4096

// number of pages for each component
#define N_UTIL_PAGES           (sizeof(util_t) / 4096)
#define N_DATA_PAGES_PER_ACTOR (sizeof(actor_data_t) / 4096)
#define N_CODE_PAGES_PER_ACTOR (sizeof(actor_code_t) / 4096)

#endif // _SANDBOX_CONSTANTS_H_

/// File: Header for test case macro loader
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#ifndef _RVZR_MACRO_LOADER_H_
#define _RVZR_MACRO_LOADER_H_

#include "hardware_desc.h"

#include "asm_snippets.h"
#include "test_case_parser.h"
#include <linux/types.h>

// =================================================================================================
// Lists of possible macros
// =================================================================================================
typedef enum {
    NONMACRO_FUNCTION = 0,
    MACRO_MEASUREMENT_START = 1,
    MACRO_MEASUREMENT_END = 2,
    MACRO_FAULT_HANDLER = 3,
    MACRO_SWITCH = 4,
    MACRO_SET_K2U_TARGET = 5,
    MACRO_SWITCH_K2U = 6,
    MACRO_SET_U2K_TARGET = 7,
    MACRO_SWITCH_U2K = 8,
    MACRO_SET_H2G_TARGET = 9,
    MACRO_SWITCH_H2G = 10,
    MACRO_SET_G2H_TARGET = 11,
    MACRO_SWITCH_G2H = 12,
    MACRO_LANDING_K2U = 13,
    MACRO_LANDING_U2K = 14,
    MACRO_LANDING_H2G = 15,
    MACRO_LANDING_G2H = 16,
    MACRO_FAULT_HANDLER_WITH_MEASUREMENT = 17,
    MACRO_SET_DATA_PERMISSIONS = 18,
} macro_name_e;

typedef enum {
    TYPE_UNDEFINED,
    TYPE_PRIME,
    TYPE_FAST_PRIME,
    TYPE_PARTIAL_PRIME,
    TYPE_FAST_PARTIAL_PRIME,
    TYPE_PROBE,
    TYPE_FLUSH,
    TYPE_EVICT,
    TYPE_RELOAD,
    TYPE_TSC_START,
    TYPE_TSC_END,
    TYPE_FAULT_HANDLER,
    TYPE_FAULT_AND_PROBE,
    TYPE_FAULT_AND_RELOAD,
    TYPE_FAULT_AND_TSC_END,
    TYPE_SWITCH,
    TYPE_SET_K2U_TARGET,
    TYPE_SWITCH_K2U,
    TYPE_SET_U2K_TARGET,
    TYPE_SWITCH_U2K,
    TYPE_SET_H2G_TARGET,
    TYPE_SWITCH_H2G,
    TYPE_SET_G2H_TARGET,
    TYPE_SWITCH_G2H,
    TYPE_LANDING_K2U,
    TYPE_LANDING_U2K,
    TYPE_LANDING_H2G,
    TYPE_LANDING_G2H,
    TYPE_SET_DATA_PERMISSIONS,
} macro_subtype_e;

// =================================================================================================
// Macro descriptors
// =================================================================================================
// Arguments for a macro
typedef struct {
    uint16_t arg1;
    uint16_t arg2;
    uint16_t arg3;
    uint16_t arg4;
    uint64_t owner;
} macro_args_t;

// Descriptor of a macro
typedef struct {
    size_t (*start)(macro_args_t args, uint8_t *dest);
    void (*body)(void);
} macro_descr_t;

extern macro_descr_t macro_descriptors[];

// =================================================================================================
// Constants for parsing macro bodies
// =================================================================================================
// Code tokens
#define MACRO_START              0x0fff379000000000
#define MACRO_END                0x0fff2f9000000000
#define MACRO_START_TOKEN_LENGTH 8
#define MACRO_END_TOKEN_LENGTH   8

#if defined(ARCH_X86_64)
#define MACRO_PLACEHOLDER_SIZE 8
#elif defined(ARCH_ARM)
#define MACRO_PLACEHOLDER_SIZE 12
#endif

// =================================================================================================
// Public interface
// =================================================================================================
int expand_macro(tc_symbol_entry_t *macro, uint8_t *dest, uint8_t *macro_dest, size_t *macro_size);
void set_main_prologue_size(size_t size);
size_t get_main_prologue_size(void);

#endif // _RVZR_MACRO_LOADER_H_

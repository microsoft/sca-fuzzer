/// File: Header for test case macros
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#ifndef _MACRO_H_
#define _MACRO_H_

#include "test_case_parser.h"
#include "asm_snippets.h"
#include <linux/types.h>

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

#define MACRO_PLACEHOLDER_SIZE 8

int expand_macro(tc_symbol_entry_t *macro, uint8_t *dest, uint8_t *macro_dest, size_t *macro_size);
void set_main_prologue_size(size_t size);

int init_macros_loader(void);
void free_macros_loader(void);

#endif // _MACRO_H_

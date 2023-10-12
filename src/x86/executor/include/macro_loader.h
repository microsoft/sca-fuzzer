/// File: Header for test case macros
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#ifndef _MACRO_H_
#define _MACRO_H_

#include <linux/types.h>

typedef enum {
    NONMACRO_FUNCTION = 0,
    MACRO_MEASUREMENT_START = 1,
    MACRO_MEASUREMENT_END = 2,
    MACRO_SWITCH = 3,
} macro_name_e;

#define JMP_32BIT_RELATIVE 0xE9

int get_macro_bounds(uint64_t macro_id, uint8_t **start, uint64_t *size);
uint64_t inject_macro_arguments(uint64_t macro_type, uint64_t args, uint8_t *macro_dest,
                                size_t main_prologue_size);

int init_macros_loader(void);
void free_macros_loader(void);

#endif // _MACRO_H_

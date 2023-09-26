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
} macro_name_e;

int get_macro_bounds(uint64_t macro_id, uint8_t **start, uint64_t *size);

int init_macros_manager(void);
void free_macros_manager(void);

#endif // _MACRO_H_

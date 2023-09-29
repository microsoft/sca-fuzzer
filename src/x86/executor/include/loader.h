/// File: Header for loader.c
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#ifndef _LOADER_H_
#define _LOADER_H_

#include <linux/types.h>

// #define MAX_EXPANDED_SECTION_SIZE (0x800)
#define MAX_EXPANDED_SECTION_SIZE (0x1000 * 2)
#define MAX_EXPANDED_MACROS_SIZE  (0x1000)
#define PER_SECTION_ALLOC_SIZE    (MAX_EXPANDED_SECTION_SIZE + MAX_EXPANDED_MACROS_SIZE)

extern uint8_t *loaded_main_section;

int load_test_case(void);

int init_loader(void);
void free_loader(void);

#endif // _LOADER_H_

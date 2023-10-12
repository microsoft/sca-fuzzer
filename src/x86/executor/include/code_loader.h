/// File: Header for code_loader.c
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#ifndef _CODE_LOADER_H_
#define _CODE_LOADER_H_

#include <linux/types.h>

extern uint8_t *loaded_test_case_entry;

int load_sandbox_code(void);

int init_code_loader(void);
void free_code_loader(void);

#endif // _CODE_LOADER_H_

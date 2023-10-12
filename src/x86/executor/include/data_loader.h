/// File: Header for data_loader.c
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#ifndef _DATA_LOADER_H_
#define _DATA_LOADER_H_

#include <linux/types.h>

int load_sandbox_data(int input_id);

int init_data_loader(void);
void free_data_loader(void);

#endif // _DATA_LOADER_H_

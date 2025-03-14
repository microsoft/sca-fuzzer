/// File: Common definitions for page tables
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#ifndef _PAGE_TABLES_COMMON_H_
#define _PAGE_TABLES_COMMON_H_

#include "hardware_desc.h"

#include <linux/slab.h> // PAGE_SIZE
#include <linux/types.h>

// FIXME: under construction
typedef struct {
    uint64_t read_access : 64;
} __attribute__((packed)) pte_t_;

#endif // _PAGE_TABLES_COMMON_H_

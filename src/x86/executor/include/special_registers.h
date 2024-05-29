/// File: Header for msr.c
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#ifndef _MSR_H_
#define _MSR_H_

#include <linux/types.h>

// A few MSR definitions missing in the kernel
#define MSR_SYSCFG 0xc0010010

typedef struct {
    uint64_t cr0;
    uint64_t cr4;
    uint64_t efer;
    uint64_t lstar;
    uint64_t spec_ctrl;
    uint64_t prefetcher_ctrl;
    uint64_t mpx_ctrl;
    uint64_t syscfg;
    uint64_t gs_base;
} __attribute__((packed)) special_registers_t;

extern special_registers_t *orig_special_registers_state;

int set_special_registers(void);
void restore_special_registers(void);

int init_special_register_manager(void);
void free_special_register_manager(void);


#endif // _MSR_H_

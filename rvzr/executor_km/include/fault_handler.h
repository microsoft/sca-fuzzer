/// File: Header for fault handling
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#ifndef _FAULT_HANDLER_H_
#define _FAULT_HANDLER_H_

#include <linux/interrupt.h>
#include <linux/version.h>
#include "hardware_desc.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)
struct idt_data {
    unsigned int vector;
    unsigned int segment;
    struct idt_bits bits;
    const void *addr;
};
#endif

#ifdef ARCH_X86_64

#include <../arch/x86/include/asm/traps.h>

#define HANDLED_FAULTS_DEFAULT                                                                     \
    ((1 << X86_TRAP_DE) + (1 << X86_TRAP_DB) + (1 << X86_TRAP_BP) + (1 << X86_TRAP_BR) +           \
     (1 << X86_TRAP_UD) + (1 << X86_TRAP_GP) + (1 << X86_TRAP_PF) + (1 << X86_TRAP_AC))

#elif defined(ARCH_ARM)

// FIXME: exception handling is not implemented for ARM
#define HANDLED_FAULTS_DEFAULT 0

#endif


extern char *fault_handler;
extern uint32_t handled_faults;

// x86-only globals
extern uint64_t pre_bubble_rsp;
extern struct desc_ptr test_case_idtr;

int set_outer_fault_handlers(void);
int unset_outer_fault_handlers(void);
int set_inner_fault_handlers(void);
int unset_inner_fault_handlers(void);

int init_fault_handler(void);
void free_fault_handler(void);

#endif // _FAULT_HANDLER_H_

/// File: Header for fault handling
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#ifndef _X86_EXECUTOR_FAULT_HANDLING_H_
#define _X86_EXECUTOR_FAULT_HANDLING_H_

#include <../arch/x86/include/asm/traps.h>
#include <linux/interrupt.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)
struct idt_data {
    unsigned int vector;
    unsigned int segment;
    struct idt_bits bits;
    const void *addr;
};
#endif

#define HANDLED_FAULTS_DEFAULT                                                                     \
    ((1 << X86_TRAP_DE) + (1 << X86_TRAP_DB) + (1 << X86_TRAP_BP) + (1 << X86_TRAP_BR) +           \
     (1 << X86_TRAP_UD) + (1 << X86_TRAP_GP) + (1 << X86_TRAP_PF))

extern char *fault_handler;
extern uint32_t handled_faults;
extern gate_desc *curr_idt_table;
extern pteval_t faulty_pte_mask_set;
extern pteval_t faulty_pte_mask_clear;

void default_handler(void);

void idt_store(void);
void idt_restore(void);
void idt_set_custom_handlers(void);

int init_fault_handler(void);
void free_fault_handler(void);

#endif // _X86_EXECUTOR_FAULT_HANDLING_H_

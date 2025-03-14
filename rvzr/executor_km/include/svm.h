/// File: Header for svm.c
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#ifndef _RVZR_EXECUTOR_SVM_H_
#define _RVZR_EXECUTOR_SVM_H_

#include <asm/svm.h>
#include <linux/types.h>

#include "svm_constants.h"

// =================================================================================================
// Virtual Machine Control Block (VMCB) definitions
#define VMCB_SIZE PAGE_SIZE

typedef struct {
    uint32_t intercept_cr;
    uint32_t intercept_dr;
    uint32_t intercept_exceptions;
    uint64_t intercept;
    uint32_t intercept_ext;
    uint8_t reserved_1[36];
    uint16_t pause_filter_thresh;
    uint16_t pause_filter_count;
    uint64_t iopm_base_pa;
    uint64_t msrpm_base_pa;
    uint64_t tsc_offset;
    uint32_t asid;
    uint8_t tlb_ctl;
    uint8_t reserved_2[3];
    uint32_t int_ctl;
    uint8_t int_vector;
    uint8_t reserved_3[3];
    uint8_t int_state;
    uint8_t reserved_4[7];
    uint64_t exit_code;
    uint64_t exit_info_1;
    uint64_t exit_info_2;
    uint64_t exit_int_info;
    uint64_t nested_ctl;
    uint64_t avic_vapic_bar;
    uint8_t reserved_5[8];
    uint32_t event_inj;
    uint32_t event_inj_err;
    uint64_t nested_cr3;
    uint64_t virt_ext;
    uint32_t clean;
    uint32_t reserved_6;
    uint64_t next_rip;
    uint8_t insn_len;
    uint8_t insn_bytes[15];
    uint64_t avic_backing_page;
    uint8_t reserved_7[8];
    uint64_t avic_logical_id;
    uint64_t avic_physical_id;
    uint8_t reserved_8[768];
} __attribute__((__packed__)) vmcb_control_t;

typedef struct {
    uint16_t selector;
    uint16_t attrib;
    uint32_t limit;
    uint64_t base;
} __attribute__((__packed__)) seg_t;

typedef struct {
    seg_t es;
    seg_t cs;
    seg_t ss;
    seg_t ds;
    seg_t fs;
    seg_t gs;
    seg_t gdtr;
    seg_t ldtr;
    seg_t idtr;
    seg_t tr;
    uint8_t reserved_1[43];
    uint8_t cpl;
    uint8_t reserved_2[4];
    uint64_t efer;
    uint64_t reserved_2a;
    uint64_t perf_ctl0;
    uint64_t perf_ctr0;
    uint64_t perf_ctl1;
    uint64_t perf_ctr1;
    uint64_t perf_ctl2;
    uint64_t perf_ctr2;
    uint64_t perf_ctl3;
    uint64_t perf_ctr3;
    uint64_t perf_ctl4;
    uint64_t perf_ctr4;
    uint64_t perf_ctl5;
    uint64_t perf_ctr5;
    uint64_t reserved_3;
    // uint8_t reserved_3[112];
    uint64_t cr4;
    uint64_t cr3;
    uint64_t cr0;
    uint64_t dr7;
    uint64_t dr6;
    uint64_t rflags;
    uint64_t rip;
    uint8_t reserved_4[88];
    uint64_t rsp;
    uint8_t reserved_5[24];
    uint64_t rax;
    uint64_t star;
    uint64_t lstar;
    uint64_t cstar;
    uint64_t sfmask;
    uint64_t kernel_gs_base;
    uint64_t sysenter_cs;
    uint64_t sysenter_esp;
    uint64_t sysenter_eip;
    uint64_t cr2;
    uint8_t reserved_6[32];
    uint64_t g_pat;
    uint64_t dbgctl;
    uint64_t br_from;
    uint64_t br_to;
    uint64_t last_excp_from;
    uint64_t last_excp_to;
} __attribute__((__packed__)) vmcb_save_t;

typedef struct {
    vmcb_control_t control;
    vmcb_save_t save;
} __attribute__((packed)) vmcb_t;


// =================================================================================================
// Module interface
#define VMCB_RIP_OFFSET offsetof(vmcb_t, save.rip)

extern bool svm_is_on;
extern uint64_t *vmcb_hpas;
extern uint64_t *vmcb_hvas;

int svm_check_cpu_compatibility(void);
int start_svm_operation(void);
void stop_svm_operation(void);
int store_orig_vmcb_state(void);
void restore_orig_vmcb_state(void);
int set_vmcb_state(void);
int print_svm_exit_info(void);

int init_svm(void);
void free_svm(void);

#endif // _RVZR_EXECUTOR_SVM_H_

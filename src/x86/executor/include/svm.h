/// File: Header for svm.c
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#ifndef _X86_EXECUTOR_SVM_H_
#define _X86_EXECUTOR_SVM_H_

#include <linux/types.h>

// =================================================================================================
// Kernel compatibility


// =================================================================================================
// SVM data structures


// =================================================================================================
// Module interface
extern bool vmx_is_on;
extern uint64_t *vmcs_hpas;

int svm_check_cpu_compatibility(void);
int start_svm_operation(void);
void stop_svm_operation(void);
int store_orig_vmcb_state(void);
void restore_orig_vmcb_state(void);
int set_vmcb_state(void);
int print_svm_exit_info(void);

int init_svm(void);
void free_svm(void);

#endif // _X86_EXECUTOR_SVM_H_

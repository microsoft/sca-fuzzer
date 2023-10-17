/// File: Header for vmx.c
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#ifndef _X86_EXECUTOR_VMX_H_
#define _X86_EXECUTOR_VMX_H_

#include <linux/types.h>

// =================================================================================================
// Kernel compatibility
#ifdef FEAT_CTL_VMX_ENABLED_OUTSIDE_SMX
#define FEATURE_VMX_ENABLED_OUTSIDE_SMX FEAT_CTL_VMX_ENABLED_OUTSIDE_SMX
#elif defined(FEATURE_CONTROL_VMXON_ENABLED_OUTSIDE_SMX)
#define FEATURE_VMX_ENABLED_OUTSIDE_SMX FEATURE_CONTROL_VMXON_ENABLED_OUTSIDE_SMX
#else
#error "FEATURE_VMX_ENABLED_OUTSIDE_SMX not defined"
#endif

#ifdef FEAT_CTL_LOCKED
#define FEATURE_CTL_LOCKED FEAT_CTL_LOCKED
#elif defined(FEATURE_CONTROL_LOCKED)
#define FEATURE_CTL_LOCKED FEATURE_CONTROL_LOCKED
#else
#error "FEATURE_CTL_LOCKED not defined"
#endif

#ifdef MSR_IA32_FEAT_CTL
#define MSR_FEATURE_CONTROL MSR_IA32_FEAT_CTL
#elif defined(MSR_IA32_FEATURE_CONTROL)
#define MSR_FEATURE_CONTROL MSR_IA32_FEATURE_CONTROL
#else
#error "MSR_FEATURE_CONTROL not defined"
#endif

// =================================================================================================
// Host VMX data structures
#define VMXON_SIZE 4096 // 4KB, as defined in SDM "Enabling and Entering VMX Operation"

typedef struct {
    uint32_t revision_id : 30;
    uint32_t reserved_31 : 1;
    uint8_t data[VMXON_SIZE - 4];
} __attribute__((packed)) vmxon_region_t;

// =================================================================================================
// Module interface
extern bool vmx_is_on;

int start_vmx_operation(void);
int stop_vmx_operation(void);

int init_vmx(void);
void free_vmx(void);

#endif // _X86_EXECUTOR_VMX_H_

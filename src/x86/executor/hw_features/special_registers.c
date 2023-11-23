/// File:
///  - Management of model-specific registers (MSRs)
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <asm/msr-index.h>

#include "hw_features/fault_handler.h"
#include "hw_features/special_registers.h"
#include "shortcuts.h"
#include "test_case_parser.h"

special_registers_t *orig_special_registers_state = NULL; // global

static int store_orig_msr_state(void)
{
    orig_special_registers_state->cr0 = read_cr0();
    orig_special_registers_state->cr4 = __read_cr4();
    orig_special_registers_state->lstar = rdmsr64(MSR_LSTAR);
    return 0;
}

static int set_msrs_for_user_actors(void)
{
#ifdef FORCE_SMAP_OFF
    uint64_t cr4 = __read_cr4();
    cr4 &= ~(X86_CR4_SMAP | X86_CR4_SMEP);
    asm volatile("mov %0, %%cr4" : : "r"(cr4)); // use asm to bypass checks
#endif
    // set default syscall entry point
    wrmsr64(MSR_LSTAR, (uint64_t)fault_handler);

    return 0;
}

static int set_msrs_for_vmx(void)
{
    uint64_t cr4 = __read_cr4();
    uint64_t cr0 = read_cr0();

    // Ensure bits in CR0 and CR4 are valid in VMX operation:
    // - Bit X is 1 in _FIXED0: bit X is fixed to 1 in CRx.
    // - Bit X is 0 in _FIXED1: bit X is fixed to 0 in CRx.
    // (source: SDM, 24.8 "restrictions on VMX operation")
    cr0 &= rdmsr64(MSR_IA32_VMX_CR0_FIXED1);
    cr0 |= rdmsr64(MSR_IA32_VMX_CR0_FIXED0);
    cr4 &= rdmsr64(MSR_IA32_VMX_CR4_FIXED1);
    cr4 |= rdmsr64(MSR_IA32_VMX_CR4_FIXED0);
    write_cr0(cr0);

    // Enable VMX operation:
    // (source: SDM, 24.7 "Enabling and entering VMX operation")
    // - CR4.VMXE = 1
    cr4 |= X86_CR4_VMXE;
    __write_cr4(cr4);

    return 0;
}

int set_special_registers(void)
{
    int err = 0;

    err = store_orig_msr_state();
    CHECK_ERR("store_orig_msr_state");

    // set required features in CRs
    uint64_t cr0 = read_cr0();
    cr0 &= ~X86_CR0_CD; // enable caching; required for collecting traces
    write_cr0(cr0);

    uint64_t cr4 = __read_cr4();
    cr4 |= X86_CR4_PCE; // enable perf counters
    __write_cr4(cr4);

    if (test_case->features.includes_user_actors) {
        err = set_msrs_for_user_actors();
        CHECK_ERR("set_msrs_for_user_actors");
    }

    if (test_case->features.includes_vm_actors) {
        set_msrs_for_vmx();
    }

    return 0;
}

void restore_special_registers(void)
{
    // note: the if-zero statements are necessary because the MSR initialization might have failed
    // midway through the process, in which case the MSR state was only partially initialized

    if (orig_special_registers_state->cr0 != 0)
        write_cr0(orig_special_registers_state->cr0);

    if (orig_special_registers_state->cr4 != 0)
        __write_cr4(orig_special_registers_state->cr4);

    if (orig_special_registers_state->lstar != 0)
        wrmsr64(MSR_LSTAR, orig_special_registers_state->lstar);

    memset(orig_special_registers_state, 0, sizeof(special_registers_t));
}

// =================================================================================================
int init_special_register_manager(void)
{
    orig_special_registers_state = CHECKED_ZALLOC(sizeof(special_registers_t));
    return 0;
}

void free_special_register_manager(void) { SAFE_FREE(orig_special_registers_state); }

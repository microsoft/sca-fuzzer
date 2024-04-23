/// File:
///  - Management of model-specific registers (MSRs)
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <asm/msr-index.h>

#include "fault_handler.h"
#include "main.h"
#include "shortcuts.h"
#include "special_registers.h"
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

static int get_ssbp_patch_msr_ctrls(uint64_t *msr_id, uint64_t *msr_mask)
{
    if (cpu_has(cpuinfo, X86_FEATURE_MSR_SPEC_CTRL)) {
        *msr_id = MSR_IA32_SPEC_CTRL;
        *msr_mask = SPEC_CTRL_SSBD;
    } else if (cpu_has(cpuinfo, X86_FEATURE_VIRT_SSBD)) {
        *msr_id = MSR_AMD64_VIRT_SPEC_CTRL;
        *msr_mask = SPEC_CTRL_SSBD;
    } else if (cpu_has(cpuinfo, X86_FEATURE_LS_CFG_SSBD)) {
        *msr_id = MSR_AMD64_LS_CFG;
        switch (cpuinfo->x86) {
        case 0x15:
            *msr_mask = 1ULL << 54;
            break;
        case 0x16:
            *msr_mask = 1ULL << 33;
            break;
        case 0x17:
            *msr_mask = 1ULL << 10;
            break;
        default:
            PRINT_ERR("ERROR: Unable to patch SSBD on this CPU; unexpected CPU model\n");
            return -1;
        }
    } else {
        PRINT_ERR("ERROR: Unable to patch SSBD on this CPU; no known patch\n");
        return -1;
    }
    return 0;
}

static int get_prefetcher_msr_ctrls(uint64_t *msr_id, uint64_t *msr_mask)
{
    if (cpuinfo->x86_vendor == X86_VENDOR_INTEL) {
        *msr_id = MSR_MISC_FEATURE_CONTROL;
        switch (cpuinfo->x86_model) {
        case 0x97:
        case 0x9a:
        case 0xba:
        case 0xb7:
        case 0xbf:
            *msr_mask = 0b101111;
            break;
        default:
            *msr_mask = 0b1111;
            break;
        }
    } else if (cpuinfo->x86_vendor == X86_VENDOR_AMD) {
        switch (cpuinfo->x86) {
        case 0x19:
            *msr_id = 0xc0000108;
            *msr_mask = 0b101111;
            break;
        default:
            *msr_id = MSR_AMD64_DC_CFG;
            *msr_mask = (1 << 13) | (1 << 15);
            break;
        }
    }
    return 0;
}

static int get_mpx_msr_ctrls(uint64_t *msr_id, uint64_t *msr_mask)
{
    if (cpuinfo->x86_vendor == X86_VENDOR_INTEL) {
        if (cpu_has(cpuinfo, X86_FEATURE_MPX)) {
            *msr_id = MSR_IA32_BNDCFGS;
            *msr_mask = 1ULL;
        } else {
            PRINT_ERR("ERROR: Unable to set MPX control; MPX not supported on this CPU\n");
            return -1;
        }
    }
    return 0;
}

static int apply_msr_mask(uint64_t msr_id, uint64_t msr_mask, bool enable)
{
    uint64_t msr_value = rdmsr64(msr_id);
    if (enable) {
        msr_value |= msr_mask;
    } else {
        msr_value &= ~msr_mask;
    }
    wrmsr64(msr_id, msr_value);
    if (rdmsr64(msr_id) != msr_value) {
        PRINT_ERR("ERROR: Not able to set MSR 0x%llx\n", msr_id);
        return -1;
    }
    return 0;
}

int set_special_registers(void)
{
    int err = 0;
    uint64_t msr_id, msr_mask;

    err = store_orig_msr_state();
    CHECK_ERR("store_orig_msr_state");

    // Speculative Store Bypass (SSBP) patch
    err = get_ssbp_patch_msr_ctrls(&msr_id, &msr_mask);
    orig_special_registers_state->spec_ctrl = rdmsr64(msr_id);
    CHECK_ERR("set_enable_ssbp_patch");
    err = apply_msr_mask(msr_id, msr_mask, enable_ssbp_patch);
    CHECK_ERR("set_enable_ssbp_patch");

    // Prefetcher control
#ifndef VMBUILD
    err = get_prefetcher_msr_ctrls(&msr_id, &msr_mask);
    orig_special_registers_state->prefetcher_ctrl = rdmsr64(msr_id);
    CHECK_ERR("set_disable_prefetchers");
    err = apply_msr_mask(msr_id, msr_mask, !enable_prefetchers); // the mask is
    CHECK_ERR("set_disable_prefetchers");
#endif

    // Intel MPX control
#if VENDOR_ID == 1 // Intel
    if (enable_mpx) {
        err = get_mpx_msr_ctrls(&msr_id, &msr_mask);
        orig_special_registers_state->mpx_ctrl = rdmsr64(msr_id);
        CHECK_ERR("set_enable_mpx_state");
        err = apply_msr_mask(msr_id, msr_mask, enable_mpx);
        CHECK_ERR("set_enable_mpx_state");
    }
#endif // VENDOR_ID == 1

    // Caching in CR0; required for collecting traces
    uint64_t cr0 = read_cr0();
    cr0 &= ~X86_CR0_CD; // enable caching
    write_cr0(cr0);

    // Performance counters in CR0
    uint64_t cr4 = __read_cr4();
    cr4 |= X86_CR4_PCE;
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
    uint64_t msr_id, msr_mask;

    // note: the if-zero statements are necessary because the MSR initialization might have failed
    // midway through the process, in which case the MSR state was only partially initialized

    if (orig_special_registers_state->cr0 != 0)
        write_cr0(orig_special_registers_state->cr0);

    if (orig_special_registers_state->cr4 != 0)
        __write_cr4(orig_special_registers_state->cr4);

    if (orig_special_registers_state->lstar != 0)
        wrmsr64(MSR_LSTAR, orig_special_registers_state->lstar);

    if (orig_special_registers_state->spec_ctrl != 0) {
        get_ssbp_patch_msr_ctrls(&msr_id, &msr_mask);
        wrmsr64(msr_id, orig_special_registers_state->spec_ctrl);
    }

    if (orig_special_registers_state->prefetcher_ctrl != 0) {
        get_prefetcher_msr_ctrls(&msr_id, &msr_mask);
        wrmsr64(msr_id, orig_special_registers_state->prefetcher_ctrl);
    }

    if (orig_special_registers_state->mpx_ctrl != 0) {
        get_mpx_msr_ctrls(&msr_id, &msr_mask);
        wrmsr64(msr_id, orig_special_registers_state->mpx_ctrl);
    }

    memset(orig_special_registers_state, 0, sizeof(special_registers_t));
}

// =================================================================================================
int init_special_register_manager(void)
{
    orig_special_registers_state = CHECKED_ZALLOC(sizeof(special_registers_t));
    return 0;
}

void free_special_register_manager(void) { SAFE_FREE(orig_special_registers_state); }

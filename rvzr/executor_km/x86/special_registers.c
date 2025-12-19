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

// =================================================================================================
// Local shortcuts to read/write special registers
// =================================================================================================
/// Note: we intentionally don't use the native_read/write_cr0/4 functions here for long-term
/// stability, because their signatures may change between kernel versions

static inline unsigned long _read_cr0(void)
{
    unsigned long val = 0;
    asm volatile("mov %%cr0, %0\n" : "=r"(val));
    return val;
}

static inline void _write_cr0(unsigned long val) { asm volatile("mov %0, %%cr0\n" : : "r"(val)); }

static inline unsigned long _read_cr4(void)
{
    unsigned long val = 0;
    asm volatile("mov %%cr4, %0\n" : "=r"(val));
    return val;
}

static inline void _write_cr4(unsigned long val) { asm volatile("mov %0, %%cr4\n" : : "r"(val)); }

// =================================================================================================
// Private implementation of special register management
// =================================================================================================

static int store_orig_msr_state(void);

static int set_msrs_for_user_actors(void)
{
#ifdef FORCE_SMAP_OFF
    uint64_t cr4 = _read_cr4();
    cr4 &= ~(X86_CR4_SMAP | X86_CR4_SMEP);
    asm volatile("mov %0, %%cr4" : : "r"(cr4)); // use asm to bypass checks
#endif
    // set default syscall entry point
    wrmsr64(MSR_LSTAR, (uint64_t)fault_handler);

    return 0;
}

/// @brief Configure MSRs to enable VMX operation
/// @param void
/// @return 0 on success, -1 on failure
static int set_msrs_for_vmx(void)
{
    uint64_t cr4 = _read_cr4();
    uint64_t cr0 = _read_cr0();

    // Ensure bits in CR0 and CR4 are valid in VMX operation:
    // - Bit X is 1 in _FIXED0: bit X is fixed to 1 in CRx.
    // - Bit X is 0 in _FIXED1: bit X is fixed to 0 in CRx.
    // (source: SDM, 24.8 "restrictions on VMX operation")
    cr0 &= rdmsr64(MSR_IA32_VMX_CR0_FIXED1);
    cr0 |= rdmsr64(MSR_IA32_VMX_CR0_FIXED0);
    cr4 &= rdmsr64(MSR_IA32_VMX_CR4_FIXED1);
    cr4 |= rdmsr64(MSR_IA32_VMX_CR4_FIXED0);
    _write_cr0(cr0);

    // Enable VMX operation:
    // (source: SDM, 24.7 "Enabling and entering VMX operation")
    // - CR4.VMXE = 1
    cr4 |= X86_CR4_VMXE;
    _write_cr4(cr4);

    return 0;
}

/// @brief Configure MSRs to enable SVM operation
/// @param void
/// @return 0 on success, -1 on failure
static int set_msrs_for_svm(void)
{
    // Ensure SVM is not disabled in BIOS
    uint64_t vm_cr = rdmsr64(MSR_VM_CR);
    ASSERT((vm_cr & (1 << 4)) == 0, "set_msrs_for_svm");

    // Enable SVM operation
    uint64_t efer = rdmsr64(MSR_EFER);
    if (!(efer & EFER_SVME)) {
        efer |= EFER_SVME;
        wrmsr64(MSR_EFER, efer);
    }

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

// =================================================================================================
// Public interface to special register management
// =================================================================================================

int set_special_registers(void)
{
    int err = 0;
    uint64_t msr_id = 0, msr_mask = 0;

    err = store_orig_msr_state();
    CHECK_ERR("store_orig_msr_state");

#ifndef VMBUILD
    // Speculative Store Bypass (SSBP) patch
    err = get_ssbp_patch_msr_ctrls(&msr_id, &msr_mask);
    orig_special_registers_state->spec_ctrl = rdmsr64(msr_id);
    CHECK_ERR("set_enable_ssbp_patch");
    err = apply_msr_mask(msr_id, msr_mask, enable_ssbp_patch);
    CHECK_ERR("set_enable_ssbp_patch");

    // Prefetcher control
    err = get_prefetcher_msr_ctrls(&msr_id, &msr_mask);
    orig_special_registers_state->prefetcher_ctrl = rdmsr64(msr_id);
    CHECK_ERR("set_disable_prefetchers");
    err = apply_msr_mask(msr_id, msr_mask, !enable_prefetchers); // the mask is
    CHECK_ERR("set_disable_prefetchers");
#endif

    // CR0
    uint64_t cr0 = _read_cr0();
    cr0 &= ~X86_CR0_CD; // enable caching; required for collecting traces
    _write_cr0(cr0);

    // CR4
    uint64_t cr4 = _read_cr4();
    cr4 |= X86_CR4_PCE; // enable performance counters
    _write_cr4(cr4);

    if (test_case->features.includes_user_actors) {
        err = set_msrs_for_user_actors();
        CHECK_ERR("set_msrs_for_user_actors");
    }

    if (test_case->features.includes_vm_actors) {
        if (cpuinfo->x86_vendor == X86_VENDOR_INTEL) {
            err = set_msrs_for_vmx();
        } else if (cpuinfo->x86_vendor == X86_VENDOR_AMD) {
            err = set_msrs_for_svm();
        }
        CHECK_ERR("set_msrs_for_vm_actors");
    }

    return 0;
}

static int store_orig_msr_state(void)
{
    orig_special_registers_state->cr0 = _read_cr0();
    orig_special_registers_state->cr4 = _read_cr4();
    orig_special_registers_state->lstar = rdmsr64(MSR_LSTAR);
    orig_special_registers_state->efer = rdmsr64(MSR_EFER);
    orig_special_registers_state->fs_base = rdmsr64(MSR_FS_BASE);
    orig_special_registers_state->gs_base = rdmsr64(MSR_GS_BASE);

    struct desc_ptr gdtr;
    asm volatile("sgdt %0" : "=m"(gdtr));
    orig_special_registers_state->gdtr_base = gdtr.address;
    orig_special_registers_state->gdtr_limit = gdtr.size;

#if VENDOR_ID == VENDOR_AMD_ // AMD
    orig_special_registers_state->syscfg = rdmsr64(MSR_SYSCFG);
#endif
    return 0;
}

void restore_special_registers(void)
{
    uint64_t msr_id = 0, msr_mask = 0;

    // note: the if-zero statements are necessary because the MSR initialization might have failed
    // midway through the process, in which case the MSR state was only partially initialized

    if (orig_special_registers_state->cr0 != 0)
        _write_cr0(orig_special_registers_state->cr0);

    if (orig_special_registers_state->cr4 != 0)
        _write_cr4(orig_special_registers_state->cr4);

    if (orig_special_registers_state->efer != 0)
        wrmsr64(MSR_EFER, orig_special_registers_state->efer);

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

    if (orig_special_registers_state->fs_base != 0) {
        wrmsr64(MSR_FS_BASE, orig_special_registers_state->fs_base);
    }

    if (orig_special_registers_state->gs_base != 0) {
        wrmsr64(MSR_GS_BASE, orig_special_registers_state->gs_base);
    }

    if (orig_special_registers_state->gdtr_base != 0) {
        struct desc_ptr gdtr = {.address = orig_special_registers_state->gdtr_base,
                                .size = orig_special_registers_state->gdtr_limit};
        asm volatile("lgdt %0" : : "m"(gdtr));
    }

#if VENDOR_ID == VENDOR_AMD_ // AMD
    if (orig_special_registers_state->syscfg != 0)
        wrmsr64(MSR_SYSCFG, orig_special_registers_state->syscfg);
#endif

    memset(orig_special_registers_state, 0, sizeof(special_registers_t));
}

// =================================================================================================
int init_special_register_manager(void)
{
    orig_special_registers_state = CHECKED_ZALLOC(sizeof(special_registers_t));
    return 0;
}

void free_special_register_manager(void) { SAFE_FREE(orig_special_registers_state); }

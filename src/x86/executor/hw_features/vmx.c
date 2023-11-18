/// File: Configuration and use of performance counters
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <asm/io.h>
#include <asm/msr-index.h>
#include <asm/processor-flags.h>
#include <asm/virtext.h>
#include <linux/types.h>

#include "shortcuts.h"

#include "hw_features/vmx.h"
#include "hw_features/vmx_config.h"

#define CHECK_VMFAIL(src)                                                                          \
    ASSERT(err_inv == 0, src);                                                                     \
    ASSERT(err_val == 0, src);

bool vmx_is_on = false; // global

static bool orig_vmxon_state = false;
static unsigned long orig_cr0 = 0;
static unsigned long orig_cr4 = 0;
static uint64_t orig_vmcs_ptr = 0;

static void *vmxon_page_hva = NULL;
static uint64_t vmxon_page_hpa = 0;

// =================================================================================================
// Helper functions
// =================================================================================================
/// @brief Runs VMXON and indicates whether it failed
/// @param fail_invalid Set if VMXOFF failed due to VMfailInvalid
/// @param fail_valid Set if VMXOFF failed due to VMfailValid
static inline void vmxon(uint64_t phys, uint8_t *fail_invalid, uint8_t *fail_valid)
{
    uint8_t inv, val;
    __asm__ __volatile__("vmxon %[pa]; setc %[inval]; setz %[val]\n"
                         : [val] "=rm"(val), [inval] "=rm"(inv)
                         : [pa] "m"(phys)
                         : "cc", "memory");
    *fail_invalid = inv;
    *fail_valid = val;
}

/// @brief Runs VMXOFF and indicates whether it failed
/// @param fail_invalid Set if VMXOFF failed due to VMfailInvalid
/// @param fail_valid Set if VMXOFF failed due to VMfailValid
static inline void vmxoff(uint8_t *fail_invalid, uint8_t *fail_valid)
{
    uint8_t inv, val;
    __asm__ __volatile__("vmxoff; setc %[inval]; setz %[val]\n"
                         : [val] "=rm"(val), [inval] "=rm"(inv)
                         :
                         : "cc", "memory");
    *fail_invalid = inv;
    *fail_valid = val;
}

static inline void vmptrst(uint64_t *dest, uint8_t *fail_invalid, uint8_t *fail_valid)
{
    uint64_t tmp;
    uint8_t inv, val;
    __asm__ __volatile__("vmptrst %[tmp]; setc %[inval]; setz %[val]\n"
                         : [tmp] "=m"(tmp), [val] "=rm"(val), [inval] "=rm"(inv)
                         :
                         : "cc", "memory");
    *dest = tmp;
    *fail_invalid = inv;
    *fail_valid = val;
}

static inline void vmptrld(uint64_t vmcs_hpa, uint8_t *fail_invalid, uint8_t *fail_valid)
{
    uint8_t inv, val;
    __asm__ __volatile__("vmptrld %[pa]; setc %[inval]; setz %[val]\n"
                         : [val] "=rm"(val), [inval] "=rm"(inv)
                         : [pa] "m"(vmcs_hpa)
                         : "cc", "memory");
    *fail_invalid = inv;
    *fail_valid = val;
}

// =================================================================================================
// VMX management interface
// (functions exposed to the rest of the executor)
// =================================================================================================
/// @brief Enable VMX operation and do VMXON
/// @return 0 on success, negative error code on failure
int start_vmx_operation(void)
{
    orig_vmxon_state = ((__read_cr4() & X86_CR4_VMXE) != 0);
    unsigned long cr4 = __read_cr4();
    unsigned long cr0 = read_cr0();
    orig_cr4 = cr4;
    orig_cr0 = cr0;

    if (!orig_vmxon_state) {
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
        // - Configure IA32_FEATURE_CONTROL MSR to allow VMXON
        //   Bit 0: Lock bit. If clear, VMXON causes a #GP.
        //   Bit 2: Enables VMXON outside of SMX operation. If clear, VMXON
        //          outside of SMX causes a #GP.
        uint64_t feature_control = rdmsr64(MSR_FEATURE_CONTROL);
        uint64_t required = FEATURE_VMX_ENABLED_OUTSIDE_SMX | FEATURE_CTL_LOCKED;
        if ((feature_control & required) != required)
            wrmsr64(MSR_FEATURE_CONTROL, feature_control | required);

        // Prepare VMXON region:
        // (source: SDM, 25.11.5 VMXON Region)
        // - Write the revision identifier into bits 30:0, and clear bit 31
        memset(vmxon_page_hva, 0, VMXON_SIZE);
        ((vmxon_region_t *)vmxon_page_hva)->revision_id = rdmsr64(MSR_IA32_VMX_BASIC);
        ((vmxon_region_t *)vmxon_page_hva)->reserved_31 = 0;

        // Run VMXON
        uint8_t fail_invalid, fail_valid = 0;
        vmxon(vmxon_page_hpa, &fail_invalid, &fail_valid);
        CHECK_VMFAIL("vmx_start_operation");
    }
    // if (orig_vmxon_state)
    //     printk(KERN_INFO "VMX was already activated.\n");
    // else
    //     printk(KERN_WARNING "Activated VMXON (was off before).\n");

    vmx_is_on = true;
    return 0;
}

/// @brief Disable VMX operation and do VMXOFF
/// @return 0 on success, negative error code on failure
int stop_vmx_operation(void)
{
    // PRINT_ERR("Stopping VMX operation\n");
    ASSERT(vmx_is_on, "vmx_stop_operation");

    // Run VMXOFF
    if (!orig_vmxon_state) {
        uint8_t fail_invalid, fail_valid = 0;
        vmxoff(&fail_invalid, &fail_valid);
        CHECK_VMFAIL("vmx_stop_operation");
        orig_vmxon_state = false;
    }

    // Restore CR0 and CR4
    write_cr0(orig_cr0);
    __write_cr4(orig_cr4);

    vmx_is_on = false;
    return 0;
}

int store_orig_vmcs_state(void)
{
    if (!orig_vmxon_state)
        return 0; // VMX was not in use when we started; nothing to store

    uint8_t fail_invalid, fail_valid = 0;
    vmptrst(&orig_vmcs_ptr, &fail_invalid, &fail_valid);
    CHECK_VMFAIL("store_orig_vmcs_state");
    return 0;
}

int restore_orig_vmcs_state(void)
{
    if (!orig_vmxon_state)
        return 0; // VMX was not in use when we started; nothing to restore

    // PRINT_ERR("vmptrld(%llx)\n", orig_vmcs_ptr);
    if (orig_vmcs_ptr == 0xFFFFFFFFFFFFFFFF)
        return 0; // VMCS was not initialized; nothing to restore

    uint8_t fail_invalid, fail_valid = 0;
    vmptrld(orig_vmcs_ptr, &fail_invalid, &fail_valid);
    CHECK_VMFAIL("restore_orig_vmcs_state");
    return 0;
}


// =================================================================================================
int init_vmx(void)
{
    int err = 0;
    ASSERT_MSG(cpu_has_vmx(), "init_vmx", "VMX is not supported on this CPU");

    // check that the hw-specific region sizes match our constants
    size_t vmxon_size = (rdmsr64(MSR_IA32_VMX_BASIC) >> 32) & 0xFFF;
    ASSERT(vmxon_size <= VMXON_SIZE, "init_vmx");

    // VMX host data structures
    vmxon_page_hva = CHECKED_ZALLOC(VMXON_SIZE);
    vmxon_page_hpa = virt_to_phys(vmxon_page_hva);
    ASSERT((vmxon_page_hpa & 0xFFF) == 0, "init_vmx"); // VMXON region must be 4KB-aligned

    return err;
}

void free_vmx(void)
{
    SAFE_FREE(vmxon_page_hva);
}

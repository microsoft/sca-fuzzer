/// File: Configuration and use of performance counters
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <asm/io.h>
#include <asm/msr-index.h>
#include <asm/processor-flags.h>
#include <asm/virtext.h>
#include <linux/types.h>

#include "actor.h"
#include "shortcuts.h"

#include "hw_features/fault_handler.h"
#include "hw_features/guest_page_tables.h"
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

static vmcs_t *vmcss = NULL;

static int set_vmcs_guest_state(void);
static int set_vmcs_host_state(void);
static int set_vmcs_exec_control(void);
static int set_vmcs_exit_control(void);
static int set_vmcs_entry_control(void);

// =================================================================================================
// Error decoding
// =================================================================================================
static const char *vmx_instruction_error_to_str[] = {
    "Unknown error: 0",
    "VMXERR_VMCALL_IN_VMX_ROOT_OPERATION",
    "VMXERR_VMCLEAR_INVALID_ADDRESS",
    "VMXERR_VMCLEAR_VMXON_POINTER",
    "VMXERR_VMLAUNCH_NONCLEAR_VMCS",
    "VMXERR_VMRESUME_NONLAUNCHED_VMCS",
    "VMXERR_VMRESUME_AFTER_VMXOFF",
    "VMXERR_ENTRY_INVALID_CONTROL_FIELD",
    "VMXERR_ENTRY_INVALID_HOST_STATE_FIELD",
    "VMXERR_VMPTRLD_INVALID_ADDRESS",
    "VMXERR_VMPTRLD_VMXON_POINTER",
    "VMXERR_VMPTRLD_INCORRECT_VMCS_REVISION_ID",
    "VMXERR_UNSUPPORTED_VMCS_COMPONENT",
    "VMXERR_VMWRITE_READ_ONLY_VMCS_COMPONENT",
    "VMXERR_VMXON_IN_VMX_ROOT_OPERATION",
    "VMXERR_ENTRY_INVALID_EXECUTIVE_VMCS_POINTER",
    "VMXERR_ENTRY_NONLAUNCHED_EXECUTIVE_VMCS",
    "VMXERR_ENTRY_EXECUTIVE_VMCS_POINTER_NOT_VMXON_POINTER",
    "VMXERR_VMCALL_NONCLEAR_VMCS",
    "VMXERR_VMCALL_INVALID_VM_EXIT_CONTROL_FIELDS",
    "VMXERR_VMCALL_INCORRECT_MSEG_REVISION_ID",
    "VMXERR_VMXOFF_UNDER_DUAL_MONITOR_TREATMENT_OF_SMIS_AND_SMM",
    "VMXERR_VMCALL_INVALID_SMM_MONITOR_FEATURES",
    "VMXERR_ENTRY_INVALID_VM_EXECUTION_CONTROL_FIELDS_IN_EXECUTIVE_VMCS",
    "VMXERR_ENTRY_EVENTS_BLOCKED_BY_MOV_SS",
    "VMXERR_INVALID_OPERAND_TO_INVEPT_INVVPID",
    NULL};

typedef struct {
    uint16_t basic_exit_reason;
    const char *str;
} vmx_basic_exit_reason_t;

static vmx_basic_exit_reason_t vmx_basic_exit_reason_to_str[] = {VMX_EXIT_REASONS, {0, NULL}};

// =================================================================================================
// Helper functions
// =================================================================================================
/// @brief Runs VMXON and indicates whether it failed
/// @param err_inv Set if VMXOFF failed due to VMfailInvalid
/// @param err_val Set if VMXOFF failed due to VMfailValid
static inline void vmxon(uint64_t phys, uint8_t *err_inv, uint8_t *err_val)
{
    uint8_t inv, val;
    __asm__ __volatile__("vmxon %[pa]; setc %[inval]; setz %[val]\n"
                         : [val] "=rm"(val), [inval] "=rm"(inv)
                         : [pa] "m"(phys)
                         : "cc", "memory");
    *err_inv = inv;
    *err_val = val;
}

/// @brief Runs VMXOFF and indicates whether it failed
/// @param err_inv Set if VMXOFF failed due to VMfailInvalid
/// @param err_val Set if VMXOFF failed due to VMfailValid
static inline void vmxoff(uint8_t *err_inv, uint8_t *err_val)
{
    uint8_t inv, val;
    __asm__ __volatile__("vmxoff; setc %[inval]; setz %[val]\n"
                         : [val] "=rm"(val), [inval] "=rm"(inv)
                         :
                         : "cc", "memory");
    *err_inv = inv;
    *err_val = val;
}

static inline void vmptrst(uint64_t *dest, uint8_t *err_inv, uint8_t *err_val)
{
    uint64_t tmp;
    uint8_t inv, val;
    __asm__ __volatile__("vmptrst %[tmp]; setc %[inval]; setz %[val]\n"
                         : [tmp] "=m"(tmp), [val] "=rm"(val), [inval] "=rm"(inv)
                         :
                         : "cc", "memory");
    *dest = tmp;
    *err_inv = inv;
    *err_val = val;
}

static inline void vmptrld(uint64_t vmcs_hpa, uint8_t *err_inv, uint8_t *err_val)
{
    uint8_t inv, val;
    __asm__ __volatile__("vmptrld %[pa]; setc %[inval]; setz %[val]\n"
                         : [val] "=rm"(val), [inval] "=rm"(inv)
                         : [pa] "m"(vmcs_hpa)
                         : "cc", "memory");
    *err_inv = inv;
    *err_val = val;
}

static inline void vmclear(uint64_t vmcs_hpa, uint8_t *err_inv, uint8_t *err_val)
{
    uint8_t inv, val;
    __asm__ __volatile__("vmclear %[pa]; setc %[inval]; setz %[val]\n"
                         : [val] "=rm"(val), [inval] "=rm"(inv)
                         : [pa] "m"(vmcs_hpa)
                         : "cc", "memory");
    *err_inv = inv;
    *err_val = val;
}

static inline void vmread(uint64_t field, uint64_t *dest, uint8_t *err_inv, uint8_t *err_val)
{
    uint8_t inv, val;
    uint64_t dest_local;
    __asm__ __volatile__("vmread %[field], %[dest]; setc %[inval]; setz %[val]\n"
                         : [dest] "=rm"(dest_local), [val] "=rm"(val), [inval] "=rm"(inv)
                         : [field] "r"(field)
                         : "cc", "memory");
    *err_inv = inv;
    *err_val = val;
    *dest = dest_local;
}

static inline void vmwrite(uint64_t field, uint64_t value, uint8_t *err_inv, uint8_t *err_val)
{
    uint8_t inv, valid;
    __asm__ __volatile__("vmwrite %[value], %[field]; setc %[inval]; setz %[valid]\n"
                         : [valid] "=rm"(valid), [inval] "=rm"(inv)
                         : [field] "r"(field), [value] "rm"(value)
                         : "cc", "memory");
    *err_inv = inv;
    *err_val = valid;
}
#define CHECKED_VMWRITE(field, value)                                                              \
    {                                                                                              \
        vmwrite(field, value, &err_inv, &err_val);                                                 \
        CHECK_VMFAIL("CHECKED_VMWRITE");                                                           \
    }

static int check_vmx_controls(uint32_t options, uint32_t msr)
{
    uint64_t msr_value = rdmsr64(msr);
    uint32_t mask_low = msr_value & 0xFFFFFFFF; // 1 low bits indicate must-one
    uint32_t mask_high = msr_value >> 32;       // zero high bits indicate must-zero

    if ((~options & mask_low) || (options & ~mask_high)) {
        PRINT_ERR("VMX MSR 0x%x: bits not supported (value 0x%x, mask l-0x%x h-0x%x)\n", msr,
                  options, mask_low, mask_high);
        return -1;
    }

    return 0;
}

#define VMWRITE_GUEST_SEGMENT(segment, selector, base, limit, ar)                                  \
    {                                                                                              \
        CHECKED_VMWRITE(GUEST_##segment##_SELECTOR, selector);                                     \
        CHECKED_VMWRITE(GUEST_##segment##_BASE, base);                                             \
        CHECKED_VMWRITE(GUEST_##segment##_LIMIT, limit);                                           \
        CHECKED_VMWRITE(GUEST_##segment##_AR_BYTES, ar);                                           \
    }

// =================================================================================================
// VMX management interface
// (functions exposed to the rest of the executor)
// =================================================================================================

/// @brief Check whether the target CPU is compatible with our implementation of VMX management
/// @return 0 is compatible, -1 otherwise
int vmx_check_cpu_compatibility(void)
{
    uint64_t msr_value = 0;
    ASSERT_MSG(cpu_has_vmx(), "vmx_check_cpu_compatibility", "VMX is not supported on this CPU");

    // True controls are usable
    msr_value = rdmsr64(MSR_IA32_VMX_BASIC);
    ASSERT((msr_value & VMX_BASIC_TRUE_CTLS) != 0, "vmx_check_cpu_compatibility");

    // Pin-based controls
    msr_value = rdmsr64(MSR_IA32_VMX_TRUE_PINBASED_CTLS);
    ASSERT((msr_value & NOT_SUPPORTED_PIN_BASED_VM_EXEC_CONTROL) == 0,
           "vmx_check_cpu_compatibility");

    // Primary processor-based controls
    msr_value = rdmsr64(MSR_IA32_VMX_TRUE_PROCBASED_CTLS);
    ASSERT((msr_value & NOT_SUPPORTED_PRIMARY_VM_EXEC_CONTROL) == 0, "vmx_check_cpu_compatibility");

    // Secondary
    msr_value = rdmsr64(MSR_IA32_VMX_PROCBASED_CTLS2);
    ASSERT((msr_value & NOT_SUPPORTED_SECONDARY_VM_EXEC_CONTROL) == 0,
           "vmx_check_cpu_compatibility");

    // Exit/entry
    msr_value = rdmsr64(MSR_IA32_VMX_TRUE_EXIT_CTLS);
    ASSERT((msr_value & NOT_SUPPORTED_EXIT_CTRL) == 0, "vmx_check_cpu_compatibility");
    msr_value = rdmsr64(MSR_IA32_VMX_TRUE_ENTRY_CTLS);
    ASSERT((msr_value & NOT_SUPPORTED_ENTRY_CTRL) == 0, "vmx_check_cpu_compatibility");

    return 0;
}

/// @brief Enable VMX operation and do VMXON
/// @return 0 on success, negative error code on failure
int start_vmx_operation(void)
{
    uint8_t err_inv, err_val = 0;

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
        vmxon(vmxon_page_hpa, &err_inv, &err_val);
        CHECK_VMFAIL("vmx_start_operation");
    }

    vmx_is_on = true;
    return 0;
}

/// @brief Disable VMX operation and do VMXOFF
/// Should never fail as this function can be used in exception handlers;
/// instead, it prints warnings upon errors.
/// @return void
void stop_vmx_operation(void)
{
    // PRINT_ERR("Stopping VMX operation\n");
    uint8_t err_inv, err_val = 0;

    // Run VMXOFF
    if (vmx_is_on && !orig_vmxon_state) {
        vmxoff(&err_inv, &err_val);
        orig_vmxon_state = false;
    }

    // Restore CR0 and CR4
    write_cr0(orig_cr0);
    __write_cr4(orig_cr4);

    vmx_is_on = false;
    if (err_inv || err_val)
        PRINT_ERRS("stop_vmx_operation", "Exited with VMfailInvalid=%d, VMfailValid=%d\n", err_inv,
                   err_val);
}

/// @brief Restore the VMCS state that was active when we started
/// @param void
/// @return 0 on success, negative error code on failure
int store_orig_vmcs_state(void)
{
    if (!orig_vmxon_state)
        return 0; // VMX was not in use when we started; nothing to store

    uint8_t err_inv, err_val = 0;
    vmptrst(&orig_vmcs_ptr, &err_inv, &err_val);
    CHECK_VMFAIL("store_orig_vmcs_state");
    return 0;
}

/// @brief Restore the VMCS state that was active when we started
/// Should never fail as this function can be used in exception handlers;
/// instead, it prints warnings upon errors.
/// @return void
void restore_orig_vmcs_state(void)
{
    uint8_t err_inv, err_val = 0;
    if (!orig_vmxon_state)
        return; // VMX was not in use when we started; nothing to restore

    // PRINT_ERR("vmptrld(%llx)\n", orig_vmcs_ptr);
    if (orig_vmcs_ptr == 0xFFFFFFFFFFFFFFFF)
        return; // VMCS was not initialized; nothing to restore

    // vmclear(orig_vmcs_ptr, &err_inv, &err_val);
    vmptrld(orig_vmcs_ptr, &err_inv, &err_val);
    if (err_inv || err_val)
        PRINT_ERRS("restore_orig_vmcs_state", "Exited with VMfailInvalid=%d, VMfailValid=%d\n",
                   err_inv, err_val);
}

int set_vmcs_state(void)
{
    int err = 0;
    uint8_t err_inv, err_val = 0;

    // if necessary, allocate additional memory for VMCSs
    static int old_n_actors = 0;
    if (n_actors > old_n_actors) {
        SAFE_VFREE(vmcss);
        vmcss = CHECKED_VMALLOC(n_actors * VMCS_SIZE);
    }
    old_n_actors = n_actors;

    // initialize VMCSs for all guest actors
    for (int actor_id = 0; actor_id < n_actors; actor_id++) {
        // skip non-guest actors
        actor_metadata_t *actor = &actors[actor_id];
        if (actor->mode != MODE_GUEST)
            continue;

        vmcs_t *vmcs_hva = (vmcs_t *)(&vmcss[actor_id]);
        uint64_t vmcs_hpa = vmalloc_to_phys(vmcs_hva);

        // initialize VMCS revision identifier
        memset(vmcs_hva, 0, VMCS_SIZE);
        vmcs_hva->revision_id = rdmsr64(MSR_IA32_VMX_BASIC);
        vmcs_hva->abort_indicator = 0;

        // load VMCS
        vmclear(vmcs_hpa, &err_inv, &err_val);
        CHECK_VMFAIL("set_vmcs_state:vmclear");

        vmptrld(vmcs_hpa, &err_inv, &err_val);
        CHECK_VMFAIL("set_vmcs_state:vmptrld");

        // set VMCS fields
        err = set_vmcs_guest_state();
        CHECK_ERR("set_vmcs_guest_state");

        err = set_vmcs_host_state();
        CHECK_ERR("set_vmcs_host_state");

        err = set_vmcs_exec_control();
        CHECK_ERR("set_vmcs_exec_control");

        err = set_vmcs_exit_control();
        CHECK_ERR("set_vmcs_exit_control");

        err = set_vmcs_entry_control();
        CHECK_ERR("set_vmcs_entry_control");
    }

    // uint64_t invept_desc[2] = {0};
    // invept_desc[0] = *(uint64_t *)ept_ptr;
    // asm volatile("mov $2, %%rax; invept (%0), %%rax" ::"r"(invept_desc) : "rax");

    return 0;
}

static int set_vmcs_guest_state(void)
{
    uint8_t err_inv, err_val = 0;
    guest_memory_t *guest_v_memory = (guest_memory_t *)(GUEST_V_MEMORY_START);
    guest_memory_t *guest_p_memory = (guest_memory_t *)(GUEST_P_MEMORY_START);

    // SDM 25.4 Guest-State Area
    // - Control registers
    CHECKED_VMWRITE(GUEST_CR0, read_cr0());
    CHECKED_VMWRITE(GUEST_CR3, (uint64_t)&guest_p_memory->guest_page_tables.pml4[0]);
    CHECKED_VMWRITE(GUEST_CR4, __read_cr4());

    // - Debug register
    CHECKED_VMWRITE(GUEST_DR7, 0x400);

    // - RSP, RIP, and RFLAGS
    CHECKED_VMWRITE(GUEST_RSP, (uint64_t)&guest_v_memory->data.main_area[LOCAL_RSP_OFFSET]);
    CHECKED_VMWRITE(GUEST_RIP, (uint64_t)&guest_v_memory->code.section[0]);
    CHECKED_VMWRITE(GUEST_RFLAGS, (X86_EFLAGS_FIXED));

    // - Segments (values mainly based on https://www.sandpile.org/x86/initial.htm)
    VMWRITE_GUEST_SEGMENT(CS, 0x1, 0, 0xFFFF, 0xa09B);
    VMWRITE_GUEST_SEGMENT(SS, 0x2, 0, 0xFFFF, 0xc093);
    VMWRITE_GUEST_SEGMENT(DS, 0, 0, 0xFFFF, 0x10000); // 0xc093
    VMWRITE_GUEST_SEGMENT(ES, 0, 0, 0xFFFF, 0x10000);
    VMWRITE_GUEST_SEGMENT(FS, 0, 0, 0xFFFF, 0x10000);
    VMWRITE_GUEST_SEGMENT(GS, 0, 0, 0xFFFF, 0x10000);
    VMWRITE_GUEST_SEGMENT(LDTR, 0, 0, 0xFFFF, 0x10000); // 0xc082);
    VMWRITE_GUEST_SEGMENT(TR, 0, 0, 0xFFFF, 0x8b);

    // - GDTR and IDTR (left empty for the time being; attempt to use will cause VM exit)
    CHECKED_VMWRITE(GUEST_GDTR_BASE, (uint64_t)&guest_v_memory->gdt[0]);
    CHECKED_VMWRITE(GUEST_GDTR_LIMIT, 0xFFFF);
    CHECKED_VMWRITE(GUEST_IDTR_BASE, 0);
    CHECKED_VMWRITE(GUEST_IDTR_LIMIT, 0xFFFF);

    // - MSRs
    CHECKED_VMWRITE(GUEST_IA32_DEBUGCTL, 0);
    CHECKED_VMWRITE(GUEST_SYSENTER_CS, 0x1);
    CHECKED_VMWRITE(GUEST_SYSENTER_ESP,
                    (uint64_t)&guest_v_memory->data.main_area[LOCAL_RSP_OFFSET]);
    CHECKED_VMWRITE(GUEST_SYSENTER_EIP, (uint64_t)&guest_v_memory->code.section[0]);

    ASSERT((VM_ENTRY_LOAD_IA32_PERF_GLOBAL_CTRL & NOT_SUPPORTED_ENTRY_CTRL) != 0,
           "set_vmcs_guest_state");
    ASSERT((VM_ENTRY_LOAD_IA32_PAT & NOT_SUPPORTED_ENTRY_CTRL) != 0, "set_vmcs_guest_state");
    ASSERT((VM_ENTRY_LOAD_IA32_EFER & NOT_SUPPORTED_ENTRY_CTRL) != 0, "set_vmcs_guest_state");

    // SDM 25.4.2 Guest Non-Register State
    CHECKED_VMWRITE(GUEST_ACTIVITY_STATE, 0);
    CHECKED_VMWRITE(GUEST_INTERRUPTIBILITY_INFO, 0b1000); // block all possible interrupts
    CHECKED_VMWRITE(GUEST_PENDING_DBG_EXCEPTIONS, 0);
    CHECKED_VMWRITE(VMCS_LINK_POINTER, -1LL);
    CHECKED_VMWRITE(VMX_PREEMPTION_TIMER_VALUE, 0xFFFF); // FIXME: make configurable

    return 0;
}

static int set_vmcs_host_state(void)
{
    uint8_t err_inv, err_val = 0;

    // get TR, GDTR, IDTR and LDTR bases (will be necessary later, in several places)
    uint64_t tr;
    struct desc_ptr gdtr, idtr, ldtr;
    asm volatile("str %[tr]\n"
                 "sgdt %[gdtr]\n"
                 "sidt %[idtr]\n"
                 "sldt %[ldtr]\n"
                 : [tr] "=m"(tr), [gdtr] "=m"(gdtr), [idtr] "=m"(idtr), [ldtr] "=m"(ldtr)
                 :
                 : "memory");
    struct ldttss_desc *tr_register = (struct ldttss_desc *)(gdtr.address + tr);
    uint64_t tr_base = ((uint64_t)tr_register->base0 | ((tr_register->base1) << 16) |
                        ((tr_register->base2) << 24) | ((uint64_t)tr_register->base3 << 32));

    // SDM 25.5 Host-State Area
    // - Control registers
    CHECKED_VMWRITE(HOST_CR0, read_cr0());
    CHECKED_VMWRITE(HOST_CR3, __read_cr3());
    CHECKED_VMWRITE(HOST_CR4, __read_cr4());

    // - RSP and RIP
    CHECKED_VMWRITE(HOST_RSP, (uint64_t)&sandbox->data[0].main_area[LOCAL_RSP_OFFSET]);
    CHECKED_VMWRITE(HOST_RIP, (uint64_t)fault_handler); // FIXME

    // - Segment selectors
    CHECKED_VMWRITE(HOST_CS_SELECTOR, __KERNEL_CS);
    CHECKED_VMWRITE(HOST_SS_SELECTOR, __KERNEL_DS);
    CHECKED_VMWRITE(HOST_DS_SELECTOR, 0);
    CHECKED_VMWRITE(HOST_ES_SELECTOR, 0);
    CHECKED_VMWRITE(HOST_FS_SELECTOR, 0);
    CHECKED_VMWRITE(HOST_GS_SELECTOR, 0);
    CHECKED_VMWRITE(HOST_TR_SELECTOR, tr);

    // - Segment bases
    CHECKED_VMWRITE(HOST_FS_BASE, rdmsr64(MSR_FS_BASE));
    CHECKED_VMWRITE(HOST_GS_BASE, rdmsr64(MSR_GS_BASE));
    CHECKED_VMWRITE(HOST_TR_BASE, tr_base);
    CHECKED_VMWRITE(HOST_GDTR_BASE, gdtr.address);
    CHECKED_VMWRITE(HOST_IDTR_BASE, test_case_idtr.address);

    // - MSRs
    CHECKED_VMWRITE(HOST_IA32_SYSENTER_CS, rdmsr64(MSR_IA32_SYSENTER_CS));
    CHECKED_VMWRITE(HOST_IA32_SYSENTER_ESP, rdmsr64(MSR_IA32_SYSENTER_ESP));
    CHECKED_VMWRITE(HOST_IA32_SYSENTER_EIP, rdmsr64(MSR_IA32_SYSENTER_EIP));
    CHECKED_VMWRITE(HOST_IA32_EFER, rdmsr64(MSR_EFER));

    ASSERT((VM_EXIT_LOAD_IA32_PERF_GLOBAL_CTRL & NOT_SUPPORTED_EXIT_CTRL) != 0,
           "set_vmcs_host_state");
    ASSERT((VM_EXIT_LOAD_IA32_PAT & NOT_SUPPORTED_EXIT_CTRL) != 0, "set_vmcs_host_state");
    return 0;
}

static int set_vmcs_exec_control(void)
{
    // int err = 0;
    uint8_t err_inv, err_val = 0;
    return 0;
}

static int set_vmcs_exit_control(void)
{
    uint8_t err_inv, err_val = 0;
    return 0;
}

static int set_vmcs_entry_control(void)
{
    uint8_t err_inv, err_val = 0;

    return 0;
}

int print_vmx_exit_info(void)
{
    uint8_t err_inv, err_val = 0;
    uint64_t value = 0;

    // Abort reasons
    PRINT_ERR("VMX Abort indicators:\n");
    for (int actor_id = 0; actor_id < n_actors; actor_id++) {
        if (actors[actor_id].mode == MODE_GUEST)
            PRINT_ERR("  actor 0x%x: %d\n", actor_id, vmcss[actor_id].abort_indicator);
    }

    // VM exit reason
    PRINT_ERR("VMXC exit info:\n");
    vmread(VM_EXIT_REASON, &value, &err_inv, &err_val);
    CHECK_VMFAIL("print_vmx_exit_info:VM_EXIT_REASON");
    PRINT_ERR("  VM exit reason: 0x%llx\n", value);
    if (value != 0) {
        uint16_t basic_reason = value & 0xFFFF;
        char *exit_type;
        if (value & (1ULL << 31))
            exit_type = "entry";
        else
            exit_type = "exit";

        for (int i = 0; i < EXIT_REASON_TPAUSE; i++) {
            if (basic_reason == vmx_basic_exit_reason_to_str[i].basic_exit_reason) {
                PRINT_ERR("    decoded: %s [%s]\n", vmx_basic_exit_reason_to_str[i].str, exit_type);
                break;
            }
        }
    }

    vmread(EXIT_QUALIFICATION, &value, &err_inv, &err_val);
    CHECK_VMFAIL("print_vmx_exit_info:EXIT_QUALIFICATION");
    PRINT_ERR("  Exit qualification: 0x%llx\n", value);

    vmread(GUEST_LINEAR_ADDRESS, &value, &err_inv, &err_val);
    CHECK_VMFAIL("print_vmx_exit_info:GUEST_LINEAR_ADDRESS");
    PRINT_ERR("  Guest linear address: 0x%llx\n", value);

    vmread(GUEST_PHYSICAL_ADDRESS, &value, &err_inv, &err_val);
    CHECK_VMFAIL("print_vmx_exit_info:GUEST_PHYSICAL_ADDRESS");
    PRINT_ERR("  Guest physical address: 0x%llx\n", value);

    vmread(VM_EXIT_INTR_INFO, &value, &err_inv, &err_val);
    CHECK_VMFAIL("print_vmx_exit_info:VM_EXIT_INTR_INFO");
    PRINT_ERR("  VM exit interrupt info: 0x%llx\n", value);

    vmread(VM_EXIT_INTR_ERROR_CODE, &value, &err_inv, &err_val);
    CHECK_VMFAIL("print_vmx_exit_info:VM_EXIT_INTR_ERROR_CODE");
    PRINT_ERR("  VM exit interrupt error code: 0x%llx\n", value);

    vmread(IDT_VECTORING_INFO_FIELD, &value, &err_inv, &err_val);
    CHECK_VMFAIL("print_vmx_exit_info:IDT_VECTORING_INFO_FIELD");
    PRINT_ERR("  IDT vectoring info field: 0x%llx\n", value);

    vmread(IDT_VECTORING_ERROR_CODE, &value, &err_inv, &err_val);
    CHECK_VMFAIL("print_vmx_exit_info:IDT_VECTORING_ERROR_CODE");
    PRINT_ERR("  IDT vectoring error code: 0x%llx\n", value);

    vmread(VM_EXIT_INSTRUCTION_LEN, &value, &err_inv, &err_val);
    CHECK_VMFAIL("print_vmx_exit_info:VM_EXIT_INSTRUCTION_LEN");
    PRINT_ERR("  VM exit instruction length: 0x%llx\n", value);

    vmread(VMX_INSTRUCTION_INFO, &value, &err_inv, &err_val);
    CHECK_VMFAIL("print_vmx_exit_info:VMX_INSTRUCTION_INFO");
    PRINT_ERR("  VM exit instruction info: 0x%llx\n", value);

    vmread(VM_INSTRUCTION_ERROR, &value, &err_inv, &err_val);
    CHECK_VMFAIL("print_vmx_exit_info:VM_INSTRUCTION_ERROR");
    PRINT_ERR("  VM exit instruction error: 0x%llx\n", value);
    if (value > 0 && value < 22)
        PRINT_ERR("    decoded: %s\n", vmx_instruction_error_to_str[value]);

    return 0;
}

// =================================================================================================
int init_vmx(void)
{
    int err = 0;

    // check that the hw-specific region sizes match our constants
    size_t vmxon_size = (rdmsr64(MSR_IA32_VMX_BASIC) >> 32) & 0xFFF;
    ASSERT(vmxon_size <= VMXON_SIZE, "init_vmx");

    // VMX host data structures
    vmxon_page_hva = CHECKED_ZALLOC(VMXON_SIZE);
    vmxon_page_hpa = virt_to_phys(vmxon_page_hva);
    ASSERT((vmxon_page_hpa & 0xFFF) == 0, "init_vmx"); // VMXON region must be 4KB-aligned

    // VMCS
    vmcss = CHECKED_VMALLOC(VMCS_SIZE);

    return err;
}

void free_vmx(void)
{
    SAFE_FREE(vmxon_page_hva);
    SAFE_VFREE(vmcss);
}

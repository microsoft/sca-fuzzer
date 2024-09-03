/// File: Configuration and use of AMD SVM
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <linux/types.h>

#include "actor.h"
#include "shortcuts.h"

#include "main.h"
#include "fault_handler.h"
#include "hardware_desc.h"
#include "memory_guest.h"
#include "special_registers.h"
#include "svm.h"
#include "svm_constants.h"

bool svm_is_on = false; // global
uint64_t *vmcb_hpas;    // global
uint64_t *vmcb_hvas;    // global

static struct page *host_ssa_page = NULL;
static char *host_ssa_hva = NULL;
static uint64_t orig_host_ssa_hpa = 0;

static struct page *vmcb_pages = NULL;

static void *iopm_hva = NULL;
static uint64_t iopm_hpa = 0;

static void *msrpm_hva = NULL;
static uint64_t msrpm_hpa = 0;

static int set_vmcb_guest_state(vmcb_t *vmcb_hva);
static int set_vmcb_control(vmcb_t *vmcb_hva, uint64_t actor_id);

// =================================================================================================
// Helper functions
// =================================================================================================
#define _BITU(x) (1U << (x))

/// @brief Initialize a segment
/// See arch/x86/svm.c for original implementation
/// @param seg The segment to initialize
static void inline init_seg(seg_t *seg, uint16_t selector, uint64_t base, uint32_t limit,
                            uint16_t attrib)
{
    seg->selector = selector;
    seg->attrib = attrib;
    seg->limit = limit;
    seg->base = base;
}

/// @brief Initialize a system segment
/// See arch/x86/svm.c for original implementation
/// @param seg The segment to initialize
/// @param type Segment attributes
static void init_sys_seg(seg_t *seg, uint32_t type)
{
    seg->selector = 0;
    seg->attrib = SVM_SELECTOR_P_MASK | type;
    seg->limit = 0xffff;
    seg->base = 0;
}

// =================================================================================================
// SVM management interface
// (functions exposed to the rest of the executor)
// =================================================================================================

/// @brief Check whether the target CPU is compatible with our implementation of SVM management
/// @return 0 is compatible, -1 otherwise
int svm_check_cpu_compatibility(void)
{
    ASSERT_MSG(cpu_has(cpuinfo, X86_FEATURE_SVM), "svm_check_cpu_compatibility",
               "SVM is not supported on this CPU");

    // Control registers
    uint64_t cr0 = read_cr0();
    uint64_t cr4 = __read_cr4();
    uint64_t efer = rdmsr64(MSR_EFER);
    ASSERT((cr0 & X86_CR0_CD) == 0, "set_vmcb_guest_state");
    ASSERT((cr0 & X86_CR0_NW) == 0, "set_vmcb_guest_state");
    ASSERT((cr0 & X86_CR0_PE) != 0, "set_vmcb_guest_state");
    ASSERT((cr0 & X86_CR0_PG) != 0, "set_vmcb_guest_state");
    ASSERT((cr4 & X86_CR4_PAE) != 0, "set_vmcb_guest_state");
    ASSERT((efer & EFER_LME) != 0, "set_vmcb_guest_state");
    ASSERT((efer & EFER_LMA) != 0, "set_vmcb_guest_state");

    // SNP is not supported
    uint64_t syscfg = rdmsr64(MSR_SYSCFG);
    ASSERT((syscfg & _BITULL(24)) == 0, "set_vmcb_guest_state");

    return 0;
}

/// @brief Enable SVM operation
/// @return 0 on success, negative error code on failure
int start_svm_operation(void)
{
    // Note that EFER.SVME is already set in special_registers.c

    // Store the original Host State Save Area
    orig_host_ssa_hpa = rdmsr64(MSR_VM_HSAVE_PA);

    // Prepare Host State Save Area
    memset(host_ssa_hva, 0, PAGE_SIZE);
    wrmsr64(MSR_VM_HSAVE_PA, page_to_pfn(host_ssa_page) << PAGE_SHIFT);
    ((uint64_t *)host_ssa_hva)[0] = 0x42;

    svm_is_on = true;

    return 0;
}

/// @brief Disable SVM operation
/// Should never fail as this function can be used in exception handlers;
/// instead, it will print warning upon error.
/// @return void
void stop_svm_operation(void)
{
    // Restore the original Host State Save Area
    wrmsr64(MSR_VM_HSAVE_PA, orig_host_ssa_hpa);

    svm_is_on = false;
}

/// @brief Restore the VMCB state that was active when we started
/// @param void
/// @return 0 on success, negative error code on failure
int store_orig_vmcb_state(void) { return 0; }

/// @brief Restore the VMCB state that was active when we started
/// Should never fail as this function can be used in exception handlers;
/// instead, it prints warnings upon errors.
/// @return void
void restore_orig_vmcb_state(void) {}

/// @brief Configure VMCBs for all guest actors
/// @param void
/// @return 0 on success, negative error code on failure
int set_vmcb_state(void)
{
    int err = 0;

    // initialize VMCBs for all guest actors
    for (int actor_id = 0; actor_id < n_actors; actor_id++) {
        // skip non-guest actors
        actor_metadata_t *actor = &actors[actor_id];
        if (actor->mode != MODE_GUEST)
            continue;

        struct page *vmcb_page = &vmcb_pages[actor_id];
        vmcb_t *vmcb_hva = page_address(vmcb_page);
        vmcb_hvas[actor_id] = (uint64_t)vmcb_hva;
        vmcb_hpas[actor_id] = page_to_pfn(vmcb_page) << PAGE_SHIFT;

        ASSERT(vmcb_hpas[actor_id] != 0, "set_vmcb_state");
        ASSERT((vmcb_hpas[actor_id] & 0xFFF) == 0, "set_vmcb_state");

        // reset VMCB
        memset(vmcb_hva, 0, VMCB_SIZE);

        // set VMCB fields
        err = set_vmcb_guest_state(vmcb_hva);
        CHECK_ERR("set_vmcb_state");

        err = set_vmcb_control(vmcb_hva, actor_id);
        CHECK_ERR("set_vmcb_state");
    }

    return 0;
}

static int set_vmcb_guest_state(vmcb_t *vmcb_hva)
{
    int err = 0;
    vmcb_save_t *save = &vmcb_hva->save;
    guest_memory_t *guest_v_memory = (guest_memory_t *)(GUEST_V_MEMORY_START);
    guest_memory_t *guest_p_memory = (guest_memory_t *)(GUEST_P_MEMORY_START);

    // - Control registers
    save->cr0 = (read_cr0() | MUST_SET_BITS_CR0_SVM_GUEST) & ~MUST_CLEAR_BITS_CR0_SVM_GUEST;
    save->cr3 = (uint64_t)&guest_p_memory->guest_page_tables.l4[0];
    save->cr4 = (__read_cr4() | MUST_SET_BITS_CR4_SVM_GUEST) & ~MUST_CLEAR_BITS_CR4_SVM_GUEST;
    save->efer =
        (rdmsr64(MSR_EFER) | MUST_SET_BITS_EFER_SVM_GUEST) & ~MUST_CLEAR_BITS_EFER_SVM_GUEST;

    // - Debug registers
    save->dr7 = 0x400;
    save->dr6 = 0;

    // - GPRs
    save->rip = (uint64_t)&guest_v_memory->code.section[0];
    save->rsp = (uint64_t)&guest_v_memory->data.main_area[LOCAL_RSP_OFFSET];
    save->rflags = X86_EFLAGS_FIXED;
    save->rax = 0;

    // - Segment registers (values mainly based on https://www.sandpile.org/x86/initial.htm)
    init_seg(&save->cs, 0x10, 0, 0xffffffff, MUST_SET_BITS_CS_SVM_GUEST);
    init_seg(&save->ss, 0x20, 0, 0xffffffff, MUST_SET_BITS_SS_SVM_GUEST);
    init_seg(&save->ds, 0, 0, 0xffffffff, MUST_SET_BITS_DS_SVM_GUEST);
    init_seg(&save->es, 0, 0, 0xffffffff, 0);
    init_seg(&save->fs, 0, 0, 0xffffffff, 0);
    init_seg(&save->gs, 0, 0, 0xffffffff, 0);

    init_sys_seg(&save->ldtr, 2);
    init_sys_seg(&save->tr, 3);

    // - GDTR and IDTR (left empty for the time being; attempt to use will cause VM exit)
    save->gdtr.base = (uint64_t)&guest_v_memory->gdt;
    save->gdtr.limit = 0xffff;
    save->idtr.base = 0;
    save->idtr.limit = 0xffff;

    // MSRs
    save->dbgctl = 0;
    save->sysenter_cs = 0x10;
    // save->sysenter_cs = rdmsr64(MSR_IA32_SYSENTER_CS);
    save->sysenter_esp = (uint64_t)&guest_v_memory->data.main_area[LOCAL_RSP_OFFSET];
    // save->sysenter_esp = rdmsr64(MSR_IA32_SYSENTER_ESP);
    save->sysenter_eip = (uint64_t)&guest_v_memory->code.section[0];
    // save->sysenter_eip = rdmsr64(MSR_IA32_SYSENTER_EIP);

    save->kernel_gs_base = rdmsr64(MSR_KERNEL_GS_BASE);
    save->star = rdmsr64(MSR_STAR);
    save->lstar = rdmsr64(MSR_LSTAR);
    save->cstar = rdmsr64(MSR_CSTAR);
    save->sfmask = rdmsr64(MSR_SYSCALL_MASK);

    // Performance counters
    save->perf_ctl0 = rdmsr64(MSR_F15H_PERF_CTL0);
    save->perf_ctr0 = rdmsr64(MSR_F15H_PERF_CTR0);
    save->perf_ctl1 = rdmsr64(MSR_F15H_PERF_CTL1);
    save->perf_ctr1 = rdmsr64(MSR_F15H_PERF_CTR1);
    save->perf_ctl2 = rdmsr64(MSR_F15H_PERF_CTL2);
    save->perf_ctr2 = rdmsr64(MSR_F15H_PERF_CTR2);
    save->perf_ctl3 = rdmsr64(MSR_F15H_PERF_CTL3);
    save->perf_ctr3 = rdmsr64(MSR_F15H_PERF_CTR3);

    // Privilege level
    save->cpl = 0;

    // PAT
    uint64_t pat = 0;
    for (int i = 0; i < 8; i++) {
        pat |= (uint64_t)0x06 << (i * 8);
    }
    save->g_pat = pat;
    return err;
}

static int set_vmcb_control(vmcb_t *vmcb_hva, uint64_t actor_id)
{
    int err = 0;
    vmcb_control_t *ctrl = &vmcb_hva->control;

    ctrl->intercept_cr |= _BITU(VMCB_INTERCEPT_CR0_READ);
    ctrl->intercept_cr |= _BITU(VMCB_INTERCEPT_CR3_READ);
    ctrl->intercept_cr |= _BITU(VMCB_INTERCEPT_CR4_READ);
    ctrl->intercept_cr |= _BITU(VMCB_INTERCEPT_CR8_READ);
    ctrl->intercept_cr |= _BITU(VMCB_INTERCEPT_CR0_WRITE);
    ctrl->intercept_cr |= _BITU(VMCB_INTERCEPT_CR3_WRITE);
    ctrl->intercept_cr |= _BITU(VMCB_INTERCEPT_CR4_WRITE);
    ctrl->intercept_cr |= _BITU(VMCB_INTERCEPT_CR8_WRITE);

    ctrl->intercept_dr |= _BITU(VMCB_INTERCEPT_DR0_READ);
    ctrl->intercept_dr |= _BITU(VMCB_INTERCEPT_DR1_READ);
    ctrl->intercept_dr |= _BITU(VMCB_INTERCEPT_DR2_READ);
    ctrl->intercept_dr |= _BITU(VMCB_INTERCEPT_DR3_READ);
    ctrl->intercept_dr |= _BITU(VMCB_INTERCEPT_DR4_READ);
    ctrl->intercept_dr |= _BITU(VMCB_INTERCEPT_DR5_READ);
    ctrl->intercept_dr |= _BITU(VMCB_INTERCEPT_DR6_READ);
    ctrl->intercept_dr |= _BITU(VMCB_INTERCEPT_DR7_READ);
    ctrl->intercept_dr |= _BITU(VMCB_INTERCEPT_DR0_WRITE);
    ctrl->intercept_dr |= _BITU(VMCB_INTERCEPT_DR1_WRITE);
    ctrl->intercept_dr |= _BITU(VMCB_INTERCEPT_DR2_WRITE);
    ctrl->intercept_dr |= _BITU(VMCB_INTERCEPT_DR3_WRITE);
    ctrl->intercept_dr |= _BITU(VMCB_INTERCEPT_DR4_WRITE);
    ctrl->intercept_dr |= _BITU(VMCB_INTERCEPT_DR5_WRITE);
    ctrl->intercept_dr |= _BITU(VMCB_INTERCEPT_DR6_WRITE);
    ctrl->intercept_dr |= _BITU(VMCB_INTERCEPT_DR7_WRITE);

    ctrl->intercept_exceptions = 0XFFFFFFFF;

    ctrl->intercept |= _BITULL(VMCB_INTERCEPT_INTR);
    ctrl->intercept |= _BITULL(VMCB_INTERCEPT_NMI);
    ctrl->intercept |= _BITULL(VMCB_INTERCEPT_SMI);
    ctrl->intercept |= _BITULL(VMCB_INTERCEPT_INIT);
    ctrl->intercept |= _BITULL(VMCB_INTERCEPT_VINTR);
    ctrl->intercept |= _BITULL(VMCB_INTERCEPT_SELECTIVE_CR0);
    ctrl->intercept |= _BITULL(VMCB_INTERCEPT_STORE_IDTR);
    ctrl->intercept |= _BITULL(VMCB_INTERCEPT_STORE_GDTR);
    ctrl->intercept |= _BITULL(VMCB_INTERCEPT_STORE_LDTR);
    ctrl->intercept |= _BITULL(VMCB_INTERCEPT_STORE_TR);
    ctrl->intercept |= _BITULL(VMCB_INTERCEPT_LOAD_IDTR);
    ctrl->intercept |= _BITULL(VMCB_INTERCEPT_LOAD_GDTR);
    ctrl->intercept |= _BITULL(VMCB_INTERCEPT_LOAD_LDTR);
    ctrl->intercept |= _BITULL(VMCB_INTERCEPT_LOAD_TR);
    ctrl->intercept |= _BITULL(VMCB_INTERCEPT_CPUID);
    ctrl->intercept |= _BITULL(VMCB_INTERCEPT_RSM);
    ctrl->intercept |= _BITULL(VMCB_INTERCEPT_IRET);
    ctrl->intercept |= _BITULL(VMCB_INTERCEPT_INTn);
    ctrl->intercept |= _BITULL(VMCB_INTERCEPT_INVD);
    ctrl->intercept |= _BITULL(VMCB_INTERCEPT_PAUSE);
    ctrl->intercept |= _BITULL(VMCB_INTERCEPT_HLT);
    ctrl->intercept |= _BITULL(VMCB_INTERCEPT_INVLPG);
    ctrl->intercept |= _BITULL(VMCB_INTERCEPT_INVLPGA);
    ctrl->intercept |= _BITULL(VMCB_INTERCEPT_IOIO_PROT);
    ctrl->intercept |= _BITULL(VMCB_INTERCEPT_MSR_PROT);
    ctrl->intercept |= _BITULL(VMCB_INTERCEPT_TASK_SWITCH);
    ctrl->intercept |= _BITULL(VMCB_INTERCEPT_FERR_FREEZE);
    ctrl->intercept |= _BITULL(VMCB_INTERCEPT_SHUTDOWN);
    ctrl->intercept |= _BITULL(VMCB_INTERCEPT_VMRUN);
    ctrl->intercept |= _BITULL(VMCB_INTERCEPT_VMMCALL);
    ctrl->intercept |= _BITULL(VMCB_INTERCEPT_VMLOAD);
    ctrl->intercept |= _BITULL(VMCB_INTERCEPT_VMSAVE);
    ctrl->intercept |= _BITULL(VMCB_INTERCEPT_STGI);
    ctrl->intercept |= _BITULL(VMCB_INTERCEPT_CLGI);
    ctrl->intercept |= _BITULL(VMCB_INTERCEPT_SKINIT);
    ctrl->intercept |= _BITULL(VMCB_INTERCEPT_ICEBP);
    ctrl->intercept |= _BITULL(VMCB_INTERCEPT_WBINVD);
    ctrl->intercept |= _BITULL(VMCB_INTERCEPT_MONITOR);
    ctrl->intercept |= _BITULL(VMCB_INTERCEPT_MWAIT);
    ctrl->intercept |= _BITULL(VMCB_INTERCEPT_MWAIT_COND);
    ctrl->intercept |= _BITULL(VMCB_INTERCEPT_XSETBV);
    ctrl->intercept |= _BITULL(VMCB_INTERCEPT_RDPRU);
    ctrl->intercept |= _BITULL(VMCB_INTERCEPT_EFER_WRITE);
    // DO NOT SET the following bits! Required for htrace collection
    // ctrl->intercept |= _BITULL(VMCB_INTERCEPT_PUSHF);
    // ctrl->intercept |= _BITULL(VMCB_INTERCEPT_POPF);
    // ctrl->intercept |= _BITULL(VMCB_INTERCEPT_RDTSC);
    // ctrl->intercept |= _BITULL(VMCB_INTERCEPT_RDPMC);
    // ctrl->intercept |= _BITULL(VMCB_INTERCEPT_RDTSCP);

    ctrl->intercept_ext |= _BITULL(VMCB_INTERCEPT_ALL_INVLPGB);
    ctrl->intercept_ext |= _BITULL(VMCB_INTERCEPT_INVPCID);
    ctrl->intercept_ext |= _BITULL(VMCB_INTERCEPT_MCOMMIT);
    ctrl->intercept_ext |= _BITULL(VMCB_INTERCEPT_TLBSYNC);
    ctrl->intercept_ext |= _BITULL(VMCB_INTERCEPT_BUS_LOCK);

    ctrl->pause_filter_count = 0;
    ctrl->pause_filter_thresh = 0;

    ctrl->iopm_base_pa = iopm_hpa;
    ASSERT(ctrl->iopm_base_pa < MAX_PHYSICAL_ADDRESS, "set_vmcb_control");

    ctrl->msrpm_base_pa = msrpm_hpa;
    ASSERT(ctrl->msrpm_base_pa < MAX_PHYSICAL_ADDRESS, "set_vmcb_control");

    ctrl->tsc_offset = 0;

    ctrl->asid = (uint32_t)actor_id;

    ctrl->tlb_ctl = 0;
    ctrl->int_ctl = V_INTR_MASKING_MASK;
    ctrl->int_vector = 0;
    ctrl->int_state = 0;

    ctrl->nested_ctl |= SVM_NESTED_CTL_NP_ENABLE;
    ctrl->nested_ctl |= _BITULL(6); // Read-only guest page tables

    ctrl->nested_cr3 = (ept_ptr[actor_id].paddr << 12);
    ASSERT(ctrl->nested_cr3 < MAX_PHYSICAL_ADDRESS, "set_vmcb_control");

    ctrl->exit_code = 0x42;

    ctrl->clean = 0;

    return err;
}

/// @brief Print information about the last VM exit
/// @param void
/// @return 0 on success, negative error code on failure
int print_svm_exit_info(void)
{
    int err = 0;

    for (int actor_id = 0; actor_id < n_actors; actor_id++) {
        // skip non-guest actors
        actor_metadata_t *actor = &actors[actor_id];
        if (actor->mode != MODE_GUEST)
            continue;

        struct page *vmcb_page = &vmcb_pages[actor_id];
        vmcb_t *vmcb_hva = page_address(vmcb_page);

        uint64_t exitcode = vmcb_hva->control.exit_code;
        uint64_t exitinfo1 = vmcb_hva->control.exit_info_1;
        uint64_t exitinfo2 = vmcb_hva->control.exit_info_2;
        uint64_t exitintinfo = vmcb_hva->control.exit_int_info;

        // print exit information
        printk(
            KERN_ERR
            "VMCB[%d]: exitcode=0x%llx, exitinfo1=0x%llx, exitinfo2=0x%llx, exitintinfo=0x%llx\n",
            actor_id, exitcode, exitinfo1, exitinfo2, exitintinfo);
        printk(KERN_ERR "insn_len=0x%x, insn_bytes=0x%llx\n", vmcb_hva->control.insn_len,
               *(uint64_t *)(&vmcb_hva->control.insn_bytes[0]));
    }

    return err;
}

// =================================================================================================
int init_svm(void)
{
    int err = 0;

    // VMCBs
    vmcb_pages = CHECKED_ALLOC_PAGES(SVM_MAX_NUM_GUESTS * VMCB_SIZE);
    vmcb_hpas = CHECKED_ZALLOC(SVM_MAX_NUM_GUESTS * sizeof(uint64_t));
    vmcb_hvas = CHECKED_ZALLOC(SVM_MAX_NUM_GUESTS * sizeof(uint64_t));

    // host state save area
    host_ssa_page = alloc_page(GFP_KERNEL);
    if (!host_ssa_page)
        return -ENOMEM;
    host_ssa_hva = page_address(host_ssa_page);

    // IOPM
    struct page *iopm_pages = alloc_pages(GFP_KERNEL, 2);
    if (!iopm_pages)
        return -ENOMEM;
    iopm_hva = page_address(iopm_pages);
    memset(iopm_hva, 0xff, PAGE_SIZE * 4);
    iopm_hpa = page_to_pfn(iopm_pages) << PAGE_SHIFT;

    // MSRPM
    struct page *msrpm_pages = alloc_pages(GFP_KERNEL, 1);
    if (!msrpm_pages)
        return -ENOMEM;
    msrpm_hva = page_address(msrpm_pages);
    memset(msrpm_hva, 0xff, PAGE_SIZE * 2);
    msrpm_hpa = page_to_pfn(msrpm_pages) << PAGE_SHIFT;

    return err;
}

void free_svm(void)
{
    SAFE_PAGES_FREE(vmcb_pages, SVM_MAX_NUM_GUESTS * VMCB_SIZE);
    SAFE_FREE(vmcb_hpas);
    SAFE_FREE(vmcb_hvas);

    if (host_ssa_page) {
        __free_page(host_ssa_page);
        host_ssa_page = NULL;
        host_ssa_hva = NULL;
    }

    if (iopm_hva) {
        __free_pages(virt_to_page(iopm_hva), 2);
        iopm_hva = NULL;
        iopm_hpa = 0;
    }

    if (msrpm_hva) {
        __free_pages(virt_to_page(msrpm_hva), 1);
        msrpm_hva = NULL;
        msrpm_hpa = 0;
    }
}

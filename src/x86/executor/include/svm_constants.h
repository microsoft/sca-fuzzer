/// File: Definitions of constants used by AMD SVM (Secure Virtual Machine) technology
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <asm/msr-index.h>
#include <asm/virtext.h>

#ifndef _X86_EXECUTOR_SVM_CONSTANTS_H_
#define _X86_EXECUTOR_SVM_CONSTANTS_H_

// =================================================================================================
// Default values for configuration registers and VMCB fields

// Could be read from cpuid
#define SVM_MAX_NUM_GUESTS 64 // DO NOT INCREASE without knowing exactly what you are doing

// -------------------------------------------------------------------------------------------------
// Guest control registers
#define MUST_SET_BITS_CR0_SVM_GUEST                                                                \
    (X86_CR0_PE | X86_CR0_PG | X86_CR0_NE | X86_CR0_WP | X86_CR0_AM | X86_CR0_ET)
#define MUST_CLEAR_BITS_CR0_SVM_GUEST (X86_CR0_NW | X86_CR0_CD)

#define MUST_SET_BITS_CR4_SVM_GUEST                                                                \
    (X86_CR4_PSE | X86_CR4_PAE | X86_CR4_MCE | X86_CR4_PGE | X86_CR4_PCE | X86_CR4_OSFXSR |        \
     X86_CR4_OSXMMEXCPT)
#define MUST_CLEAR_BITS_CR4_SVM_GUEST (X86_CR4_VME)

#define MUST_SET_BITS_EFER_SVM_GUEST   (EFER_SCE | EFER_LME | EFER_LMA | EFER_NX | EFER_SVME)
#define MUST_CLEAR_BITS_EFER_SVM_GUEST (EFER_LMSLE)

// -------------------------------------------------------------------------------------------------
// Segment attributes
#define MUST_SET_BITS_CS_SVM_GUEST                                                                 \
    (SVM_SELECTOR_P_MASK | SVM_SELECTOR_L_MASK | SVM_SELECTOR_WRITE_MASK)
#define MUST_SET_BITS_DS_SVM_GUEST                                                                 \
    (SVM_SELECTOR_P_MASK | SVM_SELECTOR_L_MASK | SVM_SELECTOR_WRITE_MASK)
#define MUST_SET_BITS_SS_SVM_GUEST                                                                 \
    (SVM_SELECTOR_P_MASK | SVM_SELECTOR_L_MASK | SVM_SELECTOR_WRITE_MASK)

// -------------------------------------------------------------------------------------------------
// VMCB control fields

// =================================================================================================
// Kernel compatibility: Constant definitions that are either missing in the kernel, or are
// inconsistent between versions

// We define VMCB bits here, as the definitions within the kernel are not stable between versions
#define VMCB_INTERCEPT_CR0_READ  0
#define VMCB_INTERCEPT_CR3_READ  3
#define VMCB_INTERCEPT_CR4_READ  4
#define VMCB_INTERCEPT_CR8_READ  8
#define VMCB_INTERCEPT_CR0_WRITE (16 + 0)
#define VMCB_INTERCEPT_CR3_WRITE (16 + 3)
#define VMCB_INTERCEPT_CR4_WRITE (16 + 4)
#define VMCB_INTERCEPT_CR8_WRITE (16 + 8)

#define VMCB_INTERCEPT_DR0_READ  0
#define VMCB_INTERCEPT_DR1_READ  1
#define VMCB_INTERCEPT_DR2_READ  2
#define VMCB_INTERCEPT_DR3_READ  3
#define VMCB_INTERCEPT_DR4_READ  4
#define VMCB_INTERCEPT_DR5_READ  5
#define VMCB_INTERCEPT_DR6_READ  6
#define VMCB_INTERCEPT_DR7_READ  7
#define VMCB_INTERCEPT_DR0_WRITE (16 + 0)
#define VMCB_INTERCEPT_DR1_WRITE (16 + 1)
#define VMCB_INTERCEPT_DR2_WRITE (16 + 2)
#define VMCB_INTERCEPT_DR3_WRITE (16 + 3)
#define VMCB_INTERCEPT_DR4_WRITE (16 + 4)
#define VMCB_INTERCEPT_DR5_WRITE (16 + 5)
#define VMCB_INTERCEPT_DR6_WRITE (16 + 6)
#define VMCB_INTERCEPT_DR7_WRITE (16 + 7)

enum {
    VMCB_INTERCEPT_INTR,
    VMCB_INTERCEPT_NMI,
    VMCB_INTERCEPT_SMI,
    VMCB_INTERCEPT_INIT,
    VMCB_INTERCEPT_VINTR,
    VMCB_INTERCEPT_SELECTIVE_CR0,
    VMCB_INTERCEPT_STORE_IDTR,
    VMCB_INTERCEPT_STORE_GDTR,
    VMCB_INTERCEPT_STORE_LDTR,
    VMCB_INTERCEPT_STORE_TR,
    VMCB_INTERCEPT_LOAD_IDTR,
    VMCB_INTERCEPT_LOAD_GDTR,
    VMCB_INTERCEPT_LOAD_LDTR,
    VMCB_INTERCEPT_LOAD_TR,
    VMCB_INTERCEPT_RDTSC,
    VMCB_INTERCEPT_RDPMC,
    VMCB_INTERCEPT_PUSHF,
    VMCB_INTERCEPT_POPF,
    VMCB_INTERCEPT_CPUID,
    VMCB_INTERCEPT_RSM,
    VMCB_INTERCEPT_IRET,
    VMCB_INTERCEPT_INTn,
    VMCB_INTERCEPT_INVD,
    VMCB_INTERCEPT_PAUSE,
    VMCB_INTERCEPT_HLT,
    VMCB_INTERCEPT_INVLPG,
    VMCB_INTERCEPT_INVLPGA,
    VMCB_INTERCEPT_IOIO_PROT,
    VMCB_INTERCEPT_MSR_PROT,
    VMCB_INTERCEPT_TASK_SWITCH,
    VMCB_INTERCEPT_FERR_FREEZE,
    VMCB_INTERCEPT_SHUTDOWN,
    VMCB_INTERCEPT_VMRUN,
    VMCB_INTERCEPT_VMMCALL,
    VMCB_INTERCEPT_VMLOAD,
    VMCB_INTERCEPT_VMSAVE,
    VMCB_INTERCEPT_STGI,
    VMCB_INTERCEPT_CLGI,
    VMCB_INTERCEPT_SKINIT,
    VMCB_INTERCEPT_RDTSCP,
    VMCB_INTERCEPT_ICEBP,
    VMCB_INTERCEPT_WBINVD,
    VMCB_INTERCEPT_MONITOR,
    VMCB_INTERCEPT_MWAIT,
    VMCB_INTERCEPT_MWAIT_COND,
    VMCB_INTERCEPT_XSETBV,
    VMCB_INTERCEPT_RDPRU,
    VMCB_INTERCEPT_EFER_WRITE,
};

enum {
    VMCB_INTERCEPT_ALL_INVLPGB,
    VMCB_INTERCEPT_INVALID_INVLPGB,
    VMCB_INTERCEPT_INVPCID,
    VMCB_INTERCEPT_MCOMMIT,
    VMCB_INTERCEPT_TLBSYNC,
    VMCB_INTERCEPT_BUS_LOCK,
    VMCB_INTERCEPT_HLT_IF_NOT_VINTR,
};

#endif // _X86_EXECUTOR_SVM_CONSTANTS_H_

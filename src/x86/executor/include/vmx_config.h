/// File: Configuration constants for VMX
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#ifndef _VMX_CONFIG_H_
#define _VMX_CONFIG_H_

#include <asm/vmx.h>

// Could be read from cpuid
#define VMX_MAX_NUM_GUESTS 64 // DO NOT INCREASE without knowing exactly what you are doing

// Constants missing in (some versions of) Linux
#ifndef CPU_BASED_ACTIVATE_TERTIARY_CONTROLS
#define CPU_BASED_ACTIVATE_TERTIARY_CONTROLS (1ULL << 17)
#endif
#ifndef SECONDARY_EXEC_RDTSCP
#define SECONDARY_EXEC_RDTSCP (1ULL << 3)
#endif
#define SECONDARY_EXEC_EPT_VIOLATION_CAUSES_VE (1ULL << 18)
#define SECONDARY_EXEC_PASID_TRANSLATION       (1ULL << 21)
#define SECONDARY_EXEC_SUBPAGE_WRITE_PERM      (1ULL << 23)
#define SECONDARY_EXEC_ENABLE_PCONFIG          (1ULL << 27)
#define SECONDARY_EXEC_ENABLE_ENCLV_EXITING    (1ULL << 28)

#define VM_EXIT_UINV               (1ULL << 19)
#define VM_ENTRY_CET               (1ULL << 20)
#define VM_ENTRY_LOAD_IA32_LBR_CTL (1ULL << 21)
#define VM_ENTRY_LOAD_IA32_PKRS    (1ULL << 22)

// ----------------------------------------------------------------------------------------------
// Guest control registers
#define MUST_SET_BITS_CR0_GUEST                                                                    \
    (X86_CR0_PE | X86_CR0_PG | X86_CR0_NE | X86_CR0_WP | X86_CR0_AM | X86_CR0_ET)
#define MUST_CLEAR_BITS_CR0_GUEST (X86_CR0_NW | X86_CR0_CD)

#define MUST_SET_BITS_CR4_GUEST                                                                    \
    (X86_CR4_PSE | X86_CR4_PAE | X86_CR4_MCE | X86_CR4_PGE | X86_CR4_PCE | X86_CR4_OSFXSR |        \
     X86_CR4_OSXMMEXCPT | X86_CR4_VMXE | X86_CR4_PCIDE)
#define MUST_CLEAR_BITS_CR4_GUEST                                                                  \
    (X86_CR4_VME | X86_CR4_PVI | X86_CR4_TSD | X86_CR4_UMIP | X86_CR4_SMXE | X86_CR4_FSGSBASE |    \
     X86_CR4_OSXSAVE)

// ----------------------------------------------------------------------------------------------
// VMCS control fields

// Table 25-5. Definitions of Pin-Based VM-Execution Controls
// IMPORTANT: never combine setting of PIN_BASED_EXT_INTR_MASK and VM_EXIT_ACK_INTR_ON_EXIT
//            (i.e., at least one must be disabled); otherwise, interrupts lead to system crash
#define MUST_SET_PIN_BASED_VM_EXEC_CONTROL                                                         \
    (PIN_BASED_NMI_EXITING | PIN_BASED_VIRTUAL_NMIS | PIN_BASED_VMX_PREEMPTION_TIMER)
#define MUST_CLEAR_PIN_BASED_VM_EXEC_CONTROL (PIN_BASED_EXT_INTR_MASK | PIN_BASED_POSTED_INTR)

// Table 25-6. Definitions of Primary Processor-Based VM-Execution Controls
// DO NOT add CPU_BASED_RDPMC_EXITING because we may need it if guest primes or probes
#define MUST_SET_PRIMARY_VM_EXEC_CONTROL                                                           \
    (CPU_BASED_INTR_WINDOW_EXITING | CPU_BASED_HLT_EXITING | CPU_BASED_INVLPG_EXITING |            \
     CPU_BASED_MWAIT_EXITING | CPU_BASED_CR3_LOAD_EXITING | CPU_BASED_CR3_STORE_EXITING |          \
     CPU_BASED_CR8_LOAD_EXITING | CPU_BASED_CR8_STORE_EXITING | CPU_BASED_MOV_DR_EXITING |         \
     CPU_BASED_UNCOND_IO_EXITING | CPU_BASED_MONITOR_EXITING | CPU_BASED_PAUSE_EXITING |           \
     CPU_BASED_ACTIVATE_SECONDARY_CONTROLS | CPU_BASED_NMI_WINDOW_EXITING)
#define MUST_CLEAR_PRIMARY_VM_EXEC_CONTROL                                                         \
    (CPU_BASED_USE_TSC_OFFSETTING | CPU_BASED_RDPMC_EXITING | CPU_BASED_RDTSC_EXITING |            \
     CPU_BASED_ACTIVATE_TERTIARY_CONTROLS | CPU_BASED_TPR_SHADOW | CPU_BASED_USE_IO_BITMAPS |      \
     CPU_BASED_MONITOR_TRAP_FLAG | CPU_BASED_USE_MSR_BITMAPS)

// Table 25-7. Definitions of Secondary Processor-Based VM-Execution Controls
#define MUST_SET_SECONDARY_VM_EXEC_CONTROL                                                         \
    (SECONDARY_EXEC_ENABLE_EPT | SECONDARY_EXEC_DESC | SECONDARY_EXEC_WBINVD_EXITING |             \
     SECONDARY_EXEC_ENCLS_EXITING | SECONDARY_EXEC_ENABLE_INVPCID |                                \
     SECONDARY_EXEC_RDRAND_EXITING | SECONDARY_EXEC_RDSEED_EXITING)
#define MUST_CLEAR_SECONDARY_VM_EXEC_CONTROL                                                       \
    (SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES | SECONDARY_EXEC_RDTSCP |                             \
     SECONDARY_EXEC_VIRTUALIZE_X2APIC_MODE | SECONDARY_EXEC_ENABLE_VPID |                          \
     SECONDARY_EXEC_UNRESTRICTED_GUEST | SECONDARY_EXEC_APIC_REGISTER_VIRT |                       \
     SECONDARY_EXEC_VIRTUAL_INTR_DELIVERY | SECONDARY_EXEC_ENABLE_VMFUNC |                         \
     SECONDARY_EXEC_ENABLE_PML | SECONDARY_EXEC_EPT_VIOLATION_CAUSES_VE |                          \
     SECONDARY_EXEC_PT_CONCEAL_VMX | SECONDARY_EXEC_XSAVES | SECONDARY_EXEC_PASID_TRANSLATION |    \
     SECONDARY_EXEC_MODE_BASED_EPT_EXEC | SECONDARY_EXEC_SUBPAGE_WRITE_PERM |                      \
     SECONDARY_EXEC_PT_USE_GPA | SECONDARY_EXEC_TSC_SCALING |                                      \
     SECONDARY_EXEC_ENABLE_USR_WAIT_PAUSE | SECONDARY_EXEC_ENABLE_PCONFIG |                        \
     SECONDARY_EXEC_ENABLE_ENCLV_EXITING | SECONDARY_EXEC_SHADOW_VMCS)

#ifdef VMBUILD
#undef MUST_SET_SECONDARY_VM_EXEC_CONTROL
#define MUST_SET_SECONDARY_VM_EXEC_CONTROL                                                         \
    (SECONDARY_EXEC_ENABLE_EPT | SECONDARY_EXEC_DESC | SECONDARY_EXEC_WBINVD_EXITING |             \
     SECONDARY_EXEC_RDRAND_EXITING | SECONDARY_EXEC_RDSEED_EXITING)
#endif

// Misc.
#define DEFAULT_EXCEPTION_BITMAP 0xFFFFFFFF // all exceptions are redirected to host

// Exit/entry controls
#define MUST_SET_EXIT_CTRL (VM_EXIT_SAVE_DEBUG_CONTROLS | VM_EXIT_HOST_ADDR_SPACE_SIZE)
#define MUST_CLEAR_EXIT_CTRL                                                                       \
    (VM_EXIT_LOAD_IA32_PERF_GLOBAL_CTRL | VM_EXIT_SAVE_IA32_PAT | VM_EXIT_LOAD_IA32_PAT |          \
     VM_EXIT_SAVE_IA32_EFER | VM_EXIT_LOAD_IA32_EFER | VM_EXIT_SAVE_VMX_PREEMPTION_TIMER |         \
     VM_EXIT_CLEAR_BNDCFGS | VM_EXIT_PT_CONCEAL_PIP | VM_EXIT_CLEAR_IA32_RTIT_CTL |                \
     VM_EXIT_ACK_INTR_ON_EXIT)

#define MUST_SET_ENTRY_CTRL (VM_ENTRY_LOAD_DEBUG_CONTROLS | VM_ENTRY_IA32E_MODE)
#define MUST_CLEAR_ENTRY_CTRL                                                                      \
    (VM_ENTRY_SMM | VM_ENTRY_DEACT_DUAL_MONITOR | VM_ENTRY_LOAD_IA32_PERF_GLOBAL_CTRL |            \
     VM_ENTRY_LOAD_IA32_PAT | VM_ENTRY_LOAD_IA32_EFER | VM_ENTRY_LOAD_BNDCFGS |                    \
     VM_ENTRY_PT_CONCEAL_PIP | VM_ENTRY_LOAD_IA32_RTIT_CTL | VM_EXIT_UINV | VM_ENTRY_CET |         \
     VM_ENTRY_LOAD_IA32_LBR_CTL | VM_ENTRY_LOAD_IA32_PKRS)

#endif // _VMX_CONFIG_H_

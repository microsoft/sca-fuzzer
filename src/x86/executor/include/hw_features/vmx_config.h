/// File: Configuration constants for VMX
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#ifndef _VMX_CONFIG_H_
#define _VMX_CONFIG_H_

#include <asm/vmx.h>

// Could be read from cpuid
#define VMX_MAX_NUM_GUESTS 64 // DO NOT INCREASE without knowing exactly what you are doing

// ----------------------------------------------------------------------------------------------
// VMCS control fields

// Table 25-5. Definitions of Pin-Based VM-Execution Controls
// We set it to 0 in an attempt to not get the external interrupts
#define DEFAULT_PIN_BASED_VM_EXEC_CONTROL                                                          \
    0 // PIN_BASED_EXT_INTR_MASK | PIN_BASED_NMI_EXITING | PIN_BASED_VIRTUAL_NMIS

// Table 25-6. Definitions of Primary Processor-Based VM-Execution Controls
// DO NOT add CPU_BASED_RDPMC_EXITING because we may need it if guest primes or probes
#define DEFAULT_PRIMARY_VM_EXEC_CONTROL                                                            \
    CPU_BASED_INTR_WINDOW_EXITING | CPU_BASED_HLT_EXITING | CPU_BASED_CR8_LOAD_EXITING |           \
        CPU_BASED_CR8_STORE_EXITING | CPU_BASED_CR3_LOAD_EXITING | CPU_BASED_CR3_STORE_EXITING |   \
        CPU_BASED_UNCOND_IO_EXITING | CPU_BASED_MOV_DR_EXITING | CPU_BASED_MWAIT_EXITING |         \
        CPU_BASED_MONITOR_EXITING | CPU_BASED_INVLPG_EXITING |                                     \
        CPU_BASED_ACTIVATE_SECONDARY_CONTROLS | CPU_BASED_USE_MSR_BITMAPS

// Table 25-7. Definitions of Secondary Processor-Based VM-Execution Controls
#define DEFAULT_SECONDARY_VM_EXEC_CONTROL                                                          \
    SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES | SECONDARY_EXEC_ENABLE_EPT |                          \
        SECONDARY_EXEC_WBINVD_EXITING | SECONDARY_EXEC_RDRAND_EXITING |                            \
        SECONDARY_EXEC_RDSEED_EXITING

// 25.6.3 Exception Bitmap
#define DEFAULT_EXCEPTION_BITMAP 0xFFFFFFFF // all exceptions are redirected to host

#endif // _VMX_CONFIG_H_

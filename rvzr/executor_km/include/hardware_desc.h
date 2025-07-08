/// File: Header for hardware configuration
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#ifndef _HARDWARE_DESC_H_
#define _HARDWARE_DESC_H_

#ifndef VENDOR_ID
#error "Undefined VENDOR_ID"
#define VENDOR_ID 0
#endif

#if VENDOR_ID != 1 && VENDOR_ID != 2 && VENDOR_ID != 3
#error "Unsupported/corrupted VENDOR_ID"
#endif

#define VENDOR_INTEL_ 1
#define VENDOR_AMD_   2
#define VENDOR_ARM_  3
#undef VENDOR_INTEL
#undef VENDOR_AMD
#undef VENDOR_ARM

#if VENDOR_ID == VENDOR_INTEL_
#define ARCH_X86_64
#elif VENDOR_ID == VENDOR_AMD_
#define ARCH_X86_64
#elif VENDOR_ID == VENDOR_ARM_
#define ARCH_ARM
#endif

// =================================================================================================
// CPU identification
// =================================================================================================
#if defined(ARCH_X86_64)
typedef struct cpuinfo_x86 cpuinfo_t;
#elif defined(ARCH_ARM)
typedef struct {
    int implementer;
    int variant;
    int architecture;
    int part;
    int revision;
} cpuinfo_t;
#endif

// =================================================================================================
// Memory configuration
// =================================================================================================
#ifndef PHYSICAL_WIDTH
#define PHYSICAL_WIDTH 51 // unused in the build; used only for syntax highlighting
#error "PHYSICAL_WIDTH must be defined by the makefile"
#endif

#define MAX_PHYSICAL_ADDRESS ((1ULL << PHYSICAL_WIDTH) - 1)

// =================================================================================================
// Cache configuration
// =================================================================================================
#ifndef L1D_ASSOCIATIVITY
#error "Undefined L1D_ASSOCIATIVITY"
#define L1D_ASSOCIATIVITY 0
#elif L1D_ASSOCIATIVITY != 12 && L1D_ASSOCIATIVITY != 8 && L1D_ASSOCIATIVITY != 4 &&               \
    L1D_ASSOCIATIVITY != 2
#warning "Unsupported/corrupted L1D associativity. Falling back to 8-way"
#define L1D_ASSOCIATIVITY 8
#endif

// Definitions of MSRs missing in the kernel
#define MSR_SYSCFG 0xc0010010

#endif // _HARDWARE_DESC_H_

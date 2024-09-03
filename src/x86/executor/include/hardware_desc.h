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

#define VENDOR_INTEL_ 1
#define VENDOR_AMD_   2
#undef VENDOR_INTEL
#undef VENDOR_AMD

// Memory
#ifndef PHYSICAL_WIDTH
#define PHYSICAL_WIDTH 51 // unused in the build; used only for syntax highlighting
#error "PHYSICAL_WIDTH must be defined by the makefile"
#endif

#define MAX_PHYSICAL_ADDRESS ((1ULL << PHYSICAL_WIDTH) - 1)

// Cache configuration
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

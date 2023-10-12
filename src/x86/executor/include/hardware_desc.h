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

// Cache configuration
#ifndef L1D_ASSOCIATIVITY
#error "Undefined L1D_ASSOCIATIVITY"
#define L1D_ASSOCIATIVITY 0
#elif L1D_ASSOCIATIVITY != 12 && L1D_ASSOCIATIVITY != 8
#warning "Unsupported/corrupted L1D associativity. Falling back to 8-way"
#define L1D_ASSOCIATIVITY 8
#endif

// Model-specific constants
#if VENDOR_ID == 1 // Intel
#define SSBP_PATCH_ON  0b111
#define SSBP_PATCH_OFF 0b011
#define PREFETCHER_ON  0
#define PREFETCHER_OFF 15

#elif VENDOR_ID == 2 // AMD
#define SSBP_PATCH_ON  0b111
#define SSBP_PATCH_OFF 0b011
#define PREFETCHER_ON  0b000000
#define PREFETCHER_OFF 0b101111
#endif

#endif // _HARDWARE_DESC_H_

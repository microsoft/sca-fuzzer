/// File: Configuration constants for SVM
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#ifndef _SVM_CONFIG_H_
#define _SVM_CONFIG_H_

#include <asm/svm.h>

// Could be read from cpuid
#define SVM_MAX_NUM_GUESTS 64 // DO NOT INCREASE without knowing exactly what you are doing

// Constants missing in (some versions of) Linux

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
// VMCB control fields



#endif // _SVM_CONFIG_H_

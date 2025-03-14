/// File: AARCH64 Model-Specific Registers (MSRs) and their accessors
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#ifndef _MSR_H_
#define _MSR_H_

// =================================================================================================
// Accessor Macros
// =================================================================================================
#define WRITE_MSR(NAME, VALUE) asm volatile("msr " NAME ", %0\n isb\n" ::"r"(VALUE));
#define READ_MSR(NAME, VAR)    asm volatile("mrs %0, " NAME "\n isb\n" : "=r"(VAR));

// =================================================================================================
// MSR bits
// =================================================================================================
#define BIT_(x) (1ULL << x)

// Perf counters
#define PMCR_ENABLE           BIT_(0)
#define PMCR_EVENT_CNTR_RESET BIT_(1)
#define PMCR_CYCLE_CNTR_RESET BIT_(2)
#define PMCR_DP               BIT_(5)
#define PMCR_N_COUNTER_START  11
#define PMCR_N_COUNTER_MASK   0b11111

#define MDCR_HPME BIT_(7)
#define MDCR_HPMD BIT_(17)

#define PMCNTENSET_P0 BIT_(0)
#define PMCNTENSET_P1 BIT_(1)
#define PMCNTENSET_P2 BIT_(2)
#define PMCNTENSET_C  BIT_(31)

#define PMCCFILTR_NSH BIT_(27)

#define PMSELR_CYCLE_CNTR 0x1f

// Store bypass controls
#define ID_AA64PFR1_EL1_SSBS_START    4
#define ID_AA64PFR1_EL1_SSBS_MASK_    0b1111
#define ID_AA64PFR1_EL1_SSBS_EXPECTED 2

#endif // _MSR_H_

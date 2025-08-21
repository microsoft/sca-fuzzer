/// File: Configuration and use of performance counters
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <linux/kernel.h>
#include <linux/types.h>

#include "main.h"
#include "shortcuts.h"

#include "perf_counters.h"
#include "shortcuts.h"

#define REQUIRED_N_COUNTERS 3

// =================================================================================================
// Constants and event IDs

// Performance Monitor Events
#define EVENT_L1D_CACHE_REFILL 0x03
#define EVENT_INST_RETIRED     0x08
#define EVENT_INST_SPEC        0x1b

// Perf counter controls
#define PMCR_ENABLE           BIT_(0)
#define PMCR_EVENT_CNTR_RESET BIT_(1)
#define PMCR_CYCLE_CNTR_RESET BIT_(2)
#define PMCR_DP               BIT_(5)
#define PMCR_N_COUNTER_START  11
#define PMCR_N_COUNTER_MASK   0b11111
#define MDCR_HPME             BIT_(7)
#define MDCR_HPMD             BIT_(17)
#define PMCNTENSET_P0         BIT_(0)
#define PMCNTENSET_P1         BIT_(1)
#define PMCNTENSET_P2         BIT_(2)
#define PMCNTENSET_C          BIT_(31)
#define PMCCFILTR_NSH         BIT_(27)
#define PMSELR_CYCLE_CNTR     0x1f

// =================================================================================================
// Private module-level functions
// =================================================================================================

/// @brief Get the current exception level (EL)
/// @param void
/// @return Exception level
static inline int get_current_exception_level(void)
{
    int val = 0;
    read_msr("CurrentEL", val);
    val = (val >> 2) & 0b11;
    return val;
}

/// @brief Enable the Performance Monitoring Unit in EL2
/// @param void
/// @return 0 on success, -1 on failure
static inline int pmu_enable_el2(void)
{
    uint64_t mdcr = 0;
    read_msr("MDCR_EL2", mdcr);
    mdcr = mdcr | MDCR_HPME;    // set MDCR_EL2.HPME = 1
    mdcr = mdcr & (~MDCR_HPMD); // set MDCR_EL2.HPMD = 0
    write_msr("MDCR_EL2", mdcr);
    return 0;
}

/// @brief Enable the Performance Monitoring Unit
/// @param void
/// @return 0 on success, -1 on failure
static inline int pmu_enable(void)
{
    uint64_t pmcr = 0;
    read_msr("PMCR_EL0", pmcr);
    write_msr("PMCR_EL0", (pmcr | PMCR_ENABLE) & (~PMCR_DP));
    return 0;
}

/// @brief Reset the Performance Monitoring Unit
/// @param void
/// @return 0 on success, -1 on failure
static inline int pmu_reset(void)
{
    uint64_t pmcr = 0;
    read_msr("PMCR_EL0", pmcr);
    write_msr("PMCR_EL0", pmcr | PMCR_EVENT_CNTR_RESET | PMCR_CYCLE_CNTR_RESET);
    return 0;
}

/// @brief Enable all counters
/// @param void
/// @return 0 on success, -1 on failure
static inline int enable_all_counters(void)
{
    // Check that the number of available counters matches our expected value
    uint64_t pmcr_value = 0;
    read_msr("PMCR_EL0", pmcr_value);
    uint64_t pmcr_n = (pmcr_value >> PMCR_N_COUNTER_START) & PMCR_N_COUNTER_MASK;
    ASSERT(pmcr_n >= REQUIRED_N_COUNTERS, "pmu_enable");

    // Enable all counters
    uint64_t enable_all = PMCNTENSET_P0 | PMCNTENSET_P1 | PMCNTENSET_P2 | PMCNTENSET_C;
    write_msr("PMCNTENSET_EL0", enable_all);

    return 0;
}

/// @brief Disable all PMU filtering
/// @param void
/// @return 0 on success, -1 on failure
static inline int disable_filtering(void)
{
    write_msr("PMCCFILTR_EL0", PMCCFILTR_NSH);
    return 0;
}

/// @brief Set perf events to the expected values
/// Currently, the events are hardcoded to:
///   - counter 0: L1D_CACHE_REFILL
///   - counter 1: INST_RETIRED
///   - counter 2: INST_SPEC
/// @param void
/// @return 0 on success, -1 on failure
static inline int configure_events(void)
{
    // Configure the cycle counter
    write_msr("PMSELR_EL0", PMSELR_CYCLE_CNTR);
    write_msr("PMXEVTYPER_EL0", PMCCFILTR_NSH);

    // Configure event counters
    write_msr("PMSELR_EL0", 0);
    write_msr("PMXEVTYPER_EL0", (PMCCFILTR_NSH | EVENT_L1D_CACHE_REFILL));

    write_msr("PMSELR_EL0", 1);
    write_msr("PMXEVTYPER_EL0", (PMCCFILTR_NSH | EVENT_INST_RETIRED));

    write_msr("PMSELR_EL0", 2);
    write_msr("PMXEVTYPER_EL0", (PMCCFILTR_NSH | EVENT_INST_SPEC));

    return 0;
}

// =================================================================================================
// Public interface
// =================================================================================================
int pfc_configure(void)
{
    // NOTE: the below implementation is based on the instructions from
    // "Arm Architecture Reference Manual for A-profile architecture"
    // Section "D13.1 About the Performance Monitors"

    int err = 0;

#ifndef VMBUILD
    if (get_current_exception_level() >= 2) {
        err = pmu_enable_el2();
        CHECK_ERR("pmu_enable_el2");
    }

    err = configure_events();
    CHECK_ERR("configure_events");

    err = pmu_reset();
    CHECK_ERR("pmu_reset");

    err = disable_filtering();
    CHECK_ERR("disable_filtering");

    err = enable_all_counters();
    CHECK_ERR("enable_all_counters");

    err = pmu_enable();
    CHECK_ERR("pmu_enable");

#endif // VMBUILD

    return err;
}

// =================================================================================================
int init_perf_counters(void) { return 0; }
void free_perf_counters(void) {}

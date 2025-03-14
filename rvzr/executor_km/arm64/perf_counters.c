/// File: Configuration and use of performance counters
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <linux/kernel.h>
#include <linux/types.h>

#include "main.h"
#include "shortcuts.h"

#include "msr.h"
#include "perf_counters.h"
#include "shortcuts.h"

#define REQUIRED_N_COUNTERS 3

#define EVENT_L1D_CACHE_REFILL 0x03
#define EVENT_INST_RETIRED     0x08
#define EVENT_INST_SPEC        0x1b

// ----------------------------------------------------------------------------------------
// Private module-level functions
// ----------------------------------------------------------------------------------------

/// @brief Get the current exception level (EL)
/// @param void
/// @return Exception level
static inline int get_current_exception_level(void)
{
    int val = 0;
    READ_MSR("CurrentEL", val);
    val = (val >> 2) & 0b11;
    return val;
}

/// @brief Enable the Performance Monitoring Unit in EL2
/// @param void
/// @return 0 on success, -1 on failure
static inline int pmu_enable_el2(void)
{
    uint64_t mdcr = 0;
    READ_MSR("MDCR_EL2", mdcr);
    mdcr = mdcr | MDCR_HPME;    // set MDCR_EL2.HPME = 1
    mdcr = mdcr & (~MDCR_HPMD); // set MDCR_EL2.HPMD = 0
    WRITE_MSR("MDCR_EL2", mdcr);
    return 0;
}

/// @brief Enable the Performance Monitoring Unit
/// @param void
/// @return 0 on success, -1 on failure
static inline int pmu_enable(void)
{
    uint64_t pmcr = 0;
    READ_MSR("PMCR_EL0", pmcr);
    WRITE_MSR("PMCR_EL0", (pmcr | PMCR_ENABLE) & (~PMCR_DP));
    return 0;
}

/// @brief Reset the Performance Monitoring Unit
/// @param void
/// @return 0 on success, -1 on failure
static inline int pmu_reset(void)
{
    WRITE_MSR("PMCR_EL0", PMCR_EVENT_CNTR_RESET & PMCR_CYCLE_CNTR_RESET);
    return 0;
}

/// @brief Enable all counters
/// @param void
/// @return 0 on success, -1 on failure
static inline int enable_all_counters(void)
{
    // Check that the number of available counters matches our expected value
    uint64_t pmcr_value = 0;
    READ_MSR("PMCR_EL0", pmcr_value);
    uint64_t pmcr_n = (pmcr_value >> PMCR_N_COUNTER_START) & PMCR_N_COUNTER_MASK;
    ASSERT(pmcr_n >= REQUIRED_N_COUNTERS, "pmu_enable");

    // Enable all counters
    uint64_t enable_all = PMCNTENSET_P0 | PMCNTENSET_P1 | PMCNTENSET_P2 | PMCNTENSET_C;
    WRITE_MSR("PMCNTENSET_EL0", enable_all);

    return 0;
}

/// @brief Disable all PMU filtering
/// @param void
/// @return 0 on success, -1 on failure
static inline int disable_filtering(void)
{
    WRITE_MSR("PMCCFILTR_EL0", PMCCFILTR_NSH);
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
    WRITE_MSR("PMSELR_EL0", PMSELR_CYCLE_CNTR);
    WRITE_MSR("PMXEVTYPER_EL0", PMCCFILTR_NSH);

    // Configure event counters
    WRITE_MSR("PMSELR_EL0", 0);
    WRITE_MSR("PMXEVTYPER_EL0", (PMCCFILTR_NSH | EVENT_L1D_CACHE_REFILL));

    WRITE_MSR("PMSELR_EL0", 1);
    WRITE_MSR("PMXEVTYPER_EL0", (PMCCFILTR_NSH | EVENT_INST_RETIRED));

    WRITE_MSR("PMSELR_EL0", 2);
    WRITE_MSR("PMXEVTYPER_EL0", (PMCCFILTR_NSH | EVENT_INST_SPEC));

    return 0;
}

// ----------------------------------------------------------------------------------------
// Public interface
// ----------------------------------------------------------------------------------------
int pfc_configure(void)
{
    // NOTE: the below implementation is based on the instructions from
    // "Arm Architecture Reference Manual for A-profile architecture"
    // Section "D13.1 About the Performance Monitors"

    int err = 0;

    if (get_current_exception_level() >= 2)
    {
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

    return err;
}

// =================================================================================================
int init_perf_counters(void) { return 0; }
void free_perf_counters(void) {}

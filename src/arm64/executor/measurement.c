/// File:
///  - Test case execution
///  - Ensuring an isolated environment
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <linux/seq_file.h>
#include <linux/irqflags.h>

#include "main.h"

struct pfc_config
{
    unsigned long evt_num;
    unsigned long umask;
    unsigned long cmask;
    unsigned int any;
    unsigned int edge;
    unsigned int inv;
};

int config_pfc(void);

// =================================================================================================
// Measurement
// =================================================================================================
static inline int pre_measurement_setup(void)
{
    int err = 0;
    // TBD: configure PFC
    err = config_pfc();

    if (err)
        return err;

    // TBD: configure faulty page
    return 0;
}

void run_experiment(long rounds)
{
    get_cpu();
    unsigned long flags;
    raw_local_irq_save(flags);

    for (long i = -uarch_reset_rounds; i < rounds; i++)
    {
        // ignore "warm-up" runs (i<0)uarch_reset_rounds
        long i_ = (i < 0) ? 0 : i;

        // execute
        ((void (*)(char *))measurement_code)(&sandbox->main_region[0]);

        // store the measurement results
        measurement_t result = sandbox->latest_measurement;
        // printk(KERN_ERR "arm64_executor: measurement %llu\n", result.htrace[0]);
        measurements[i_].htrace[0] = result.htrace[0];
    }

    raw_local_irq_restore(flags);
    put_cpu();
}

int trace_test_case(void)
{
    // Ensure that all necessary objects are allocated
    if (!measurements)
    {
        printk(KERN_ERR "Did not allocate memory for measurements\n");
        return -ENOMEM;
    }
    if (!measurement_code)
        return -1;
    if (!inputs)
    {
        printk(KERN_ERR "Did not allocate memory for inputs\n");
        return -ENOMEM;
    }

    // Run the measurement
    if (pre_measurement_setup())
        return -1;
    run_experiment((long)n_inputs);

    return 0;
}

// =================================================================================================
// Helper Functions
// =================================================================================================

/// Clears the programmable performance counters and writes the
/// configurations to the corresponding MSRs.
///
int config_pfc(void)
{
    // TBD
    return 0;
}

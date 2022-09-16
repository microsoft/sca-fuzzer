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

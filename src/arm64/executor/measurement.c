/// File:
///  - Test case execution
///  - Ensuring an isolated environment
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

// clang-format off
#include <linux/seq_file.h>
#include <linux/irqflags.h>
#include <linux/kernel.h>
// clang-format on

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

    // Zero-initialize the region of memory used by Prime+Probe
    memset(&sandbox->eviction_region[0], 0, EVICT_REGION_SIZE * sizeof(char));

    for (long i = -uarch_reset_rounds; i < rounds; i++)
    {
        // ignore "warm-up" runs (i<0)uarch_reset_rounds
        long i_ = (i < 0) ? 0 : i;
        uint64_t *current_input = &inputs[i_ * INPUT_SIZE / 8];

        // Initialize memory:
        // NOTE: memset is not used intentionally! somehow, it messes up with P+P measurements
        // - overflows are initialized with zeroes
        memset(&sandbox->lower_overflow[0], 0, OVERFLOW_REGION_SIZE * sizeof(char));
        for (int j = 0; j < OVERFLOW_REGION_SIZE / 8; j += 1)
        {
            // ((uint64_t *) sandbox->lower_overflow)[j] = 0;
            ((uint64_t *)sandbox->upper_overflow)[j] = 0;
        }

        // - sandbox: main and faulty regions
        uint64_t *main_page_values = &current_input[0];
        uint64_t *main_base = (uint64_t *)&sandbox->main_region[0];
        for (int j = 0; j < MAIN_REGION_SIZE / 8; j += 1)
        {
            ((uint64_t *)main_base)[j] = main_page_values[j];
        }

        uint64_t *faulty_page_values = &current_input[MAIN_REGION_SIZE / 8];
        uint64_t *faulty_base = (uint64_t *)&sandbox->faulty_region[0];
        for (int j = 0; j < FAULTY_REGION_SIZE / 8; j += 1)
        {
            ((uint64_t *)faulty_base)[j] = faulty_page_values[j];
        }

        // Initial register values (the registers will be set to these values in template.c)
        uint64_t *register_values = &current_input[(MAIN_REGION_SIZE + FAULTY_REGION_SIZE) / 8];
        uint64_t *register_initialization_base = (uint64_t *)&sandbox->upper_overflow[0];

        // - RAX ... RDI
        for (int j = 0; j < 6; j += 1)
        {
            ((uint64_t *)register_initialization_base)[j] = register_values[j];
        }

        // - flags
        uint64_t masked_flags = register_values[6] << 28;
        ((uint64_t *)register_initialization_base)[6] = masked_flags;

        // - RSP and RBP
        ((uint64_t *)register_initialization_base)[7] = (uint64_t)stack_base;

        // flush some of the uarch state
        if (pre_run_flush == 1)
        {
            // TBD
        }

        // execute
        ((void (*)(char *))measurement_code)(&sandbox->main_region[0]);

        // store the measurement results
        measurement_t result = sandbox->latest_measurement;
        measurements[i_].htrace[0] = result.htrace[0];
        measurements[i_].pfc[0] = result.pfc[0];
        measurements[i_].pfc[1] = result.pfc[1];
        measurements[i_].pfc[2] = result.pfc[2];
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
    // disable PMU user-mode access (not necessary?)
    uint64_t val = 0;
    // asm volatile("msr pmuserenr_el0, %0" :: "r" (0x1));
    // asm volatile("isb\n");

    // disable PMU counters before selecting the event we want
    val = 0;
    asm volatile("mrs %0, pmcr_el0" : "=r" (val));
    asm volatile("msr pmcr_el0, %0" :: "r" (0x0));
    asm volatile("isb\n");

    // select events:
    // 1. L1D cache refills (0x3)
    asm volatile("msr pmevtyper0_el0, %0" :: "r" (0x3));
    asm volatile("isb\n");

    // 2. Instructions retired (0x08)
    asm volatile("msr pmevtyper1_el0, %0" :: "r" (0x08));
    asm volatile("isb\n");

    // 3. Instruction speculatively executed (0x1b)
    asm volatile("msr pmevtyper2_el0, %0" :: "r" (0x1b));
    asm volatile("isb\n");

    // enable counting
    val = 0;
    asm volatile("msr pmcntenset_el0, %0" :: "r" (0b111));
    asm volatile("isb\n");

    // enable PMU counters and reset the counters (using two bits)
    val = 0;
    asm volatile("mrs %0, pmcr_el0" : "=r" (val));
    asm volatile("msr pmcr_el0, %0" :: "r" (val | 0x3));
    asm volatile("isb\n");

    // debug prints (view via 'sudo dmesg')
    // val = 0;
    // asm volatile("mrs %0, pmuserenr_el0" : "=r" (val));
    // printk(KERN_ERR "%-24s 0x%0llx\n", "PMUSERENR_EL0:", val);
    // asm volatile("mrs %0, pmcr_el0" : "=r" (val));
    // printk(KERN_ERR "%-24s 0x%0llx\n", "PMCR_EL0:", val);
    // asm volatile("mrs %0, pmselr_el0" : "=r" (val));
    // printk(KERN_ERR "%-24s 0x%0llx\n", "PMSELR_EL0:", val);
    // asm volatile("mrs %0, pmevtyper0_el0" : "=r" (val));
    // printk(KERN_ERR "%-24s 0x%0llx\n", "PMEVTYPER0_EL0:", val);
    // asm volatile("mrs %0, pmcntenset_el0" : "=r" (val));
    // printk(KERN_ERR "%-24s 0x%0llx\n", "PMCNTENSET_EL0:", val);

    return 0;
}

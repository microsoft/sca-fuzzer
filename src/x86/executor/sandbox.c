/// File:
///  - Parsing inputs and test cases
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT
#include "main.h"

sandbox_t *sandbox = NULL; // global
void *stack_base = NULL;   // global
void *_sandbox_unaligned = NULL;


// =================================================================================================
// Allocation and Initialization
// =================================================================================================
int alloc_and_map_sandboxes()
{
    // Under construction
    return 0;
}

/// Constructor
///
int init_sandbox(void)
{
    // allocate working memory
    _sandbox_unaligned = CHECKED_VMALLOC(sizeof(sandbox_t) + 0x1000);

    // align sandbox to 2 pages (vmalloc guarantees 1 page alignment)
    if ((unsigned long)_sandbox_unaligned % 0x2000 == 0)
        sandbox = (sandbox_t *)_sandbox_unaligned;
    else
        sandbox = (sandbox_t *)((unsigned long)_sandbox_unaligned + 0x1000);

    // make sure the fields of the sandbox are aligned as we expect
    if ((&sandbox->main_region[0] - &sandbox->eviction_region[0]) != EVICT_REGION_OFFSET ||
        ((char *)&sandbox->stored_rsp - &sandbox->main_region[0]) != RSP_OFFSET ||
        ((char *)&sandbox->latest_measurement - &sandbox->main_region[0]) != MEASUREMENT_OFFSET ||
        (&sandbox->upper_overflow[0] - &sandbox->main_region[0]) != REG_INIT_OFFSET)
    {
        printk(KERN_ERR "x86_executor: Sandbox alignment error\n");
        return -1;
    }

    stack_base = &(sandbox->main_region[MAIN_REGION_SIZE - 8]);

    // zero-initialize the region of memory used by Prime+Probe
    memset(&sandbox->eviction_region[0], 0, EVICT_REGION_SIZE * sizeof(char));


    _sandbox_unaligned = CHECKED_VMALLOC(sizeof(sandbox_t) + 0x1000);
    // no alignment here because this allocation is done just in case, we won't actually use it
    sandbox = _sandbox_unaligned;
    stack_base = &(sandbox->main_region[MAIN_REGION_SIZE - 8]);
    return 0;
}

/// Destructor
///
void free_sandbox(void) { SAFE_VFREE(_sandbox_unaligned); }

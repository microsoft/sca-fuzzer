/// File:
///   - Parsing of test cases
///   - Management of TC-related data structures
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "main.h"

char *test_case = NULL;
char *measurement_code = NULL;

size_t n_actors = 1;
int loaded_tc_size = 0;

// =================================================================================================
// Allocation and Initialization
// =================================================================================================
/// Constructor
///
int init_test_case_manager(void)
{
    // allocate memory for test cases and make it executable
    test_case = CHECKED_ZALLOC(MAX_TEST_CASE_SIZE);
    measurement_code = CHECKED_ZALLOC(MAX_MEASUREMENT_CODE_SIZE);

    set_memory_x((unsigned long)measurement_code, MAX_MEASUREMENT_CODE_SIZE / PAGE_SIZE);

    loaded_tc_size = 1;
    measurement_code[0] = '\xC3'; // empty test case that just immediately returns
    return 0;
}

/// Destructor
///
void free_test_case_manager(void)
{
    if (measurement_code)
    {
        set_memory_nx((unsigned long)measurement_code, MAX_MEASUREMENT_CODE_SIZE / PAGE_SIZE);
        kfree(measurement_code);
    }

    if (test_case)
        kfree(test_case);
}

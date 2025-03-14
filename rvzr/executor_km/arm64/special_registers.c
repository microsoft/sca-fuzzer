/// File:
///  - Management of model-specific registers (MSRs)
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "special_registers.h"
#include "fault_handler.h"
#include "main.h"
#include "shortcuts.h"
#include "test_case_parser.h"

special_registers_t *orig_special_registers_state = NULL; // global

int set_special_registers(void)
{
    // FIXME: under construction;
    int err = 0;
    return err;
}

void restore_special_registers(void)
{
    memset(orig_special_registers_state, 0, sizeof(special_registers_t));
}

// =================================================================================================
int init_special_register_manager(void)
{
    orig_special_registers_state = CHECKED_ZALLOC(sizeof(special_registers_t));
    return 0;
}

void free_special_register_manager(void) { SAFE_FREE(orig_special_registers_state); }

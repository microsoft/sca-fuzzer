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

static int store_special_registers(void)
{
    ASSERT(orig_special_registers_state != NULL, "store_special_registers");
    memset(orig_special_registers_state, 0, sizeof(special_registers_t));

    read_msr("SPSR_EL1", orig_special_registers_state->spsr_el1);
    read_msr("SP_EL0", orig_special_registers_state->sp_el0);
    read_msr("SP_EL1", orig_special_registers_state->sp_el1);
    read_msr("ELR_EL1", orig_special_registers_state->elr_el1);
    return 0;
}

int set_special_registers(void)
{
    int err = store_special_registers();
    CHECK_ERR("set_special_registers");
    return err;
}

void restore_special_registers(void)
{
    if (orig_special_registers_state->spsr_el1 != 0) {
        write_msr("SPSR_EL1", orig_special_registers_state->spsr_el1);
    }
    if (orig_special_registers_state->sp_el0 != 0) {
        write_msr("SP_EL0", orig_special_registers_state->sp_el0);
    }
    if (orig_special_registers_state->sp_el1 != 0) {
        write_msr("SP_EL1", orig_special_registers_state->sp_el1);
    }
    if (orig_special_registers_state->elr_el1 != 0) {
        write_msr("ELR_EL1", orig_special_registers_state->elr_el1);
    }
    memset(orig_special_registers_state, 0, sizeof(special_registers_t));
}

// =================================================================================================
int init_special_register_manager(void)
{
    orig_special_registers_state = CHECKED_ZALLOC(sizeof(special_registers_t));
    return 0;
}

void free_special_register_manager(void) { SAFE_FREE(orig_special_registers_state); }

///
/// File: Helper functions for DR model
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <cstddef>

#include <dr_api.h> // NOLINT
#include <dr_defines.h>
#include <dr_ir_opnd.h>
#include <dr_tools.h>

#include <drreg.h>
#include <drvector.h>

#include "include/util.hpp"

void reserve_register_checked(void *drcontext, instrlist_t *ilist, instr_t *where,
                              drvector_t *permitted, OUT reg_id_t *reg)
{
    if (drreg_reserve_register(drcontext, ilist, where, permitted, reg) != DRREG_SUCCESS) {
        dr_printf("ERROR: failed to reserve a register\n");
        dr_abort();
    }
}

void unreserve_register_checked(void *drcontext, instrlist_t *ilist, instr_t *where, reg_id_t reg)
{
    if (drreg_unreserve_register(drcontext, ilist, where, reg) != DRREG_SUCCESS) {
        dr_printf("ERROR: failed to unreserve a register\n");
        dr_abort();
    }
}

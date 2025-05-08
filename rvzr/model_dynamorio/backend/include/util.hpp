///
/// File: Helper functions for DR model
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include <cstddef>

#include <dr_api.h> // NOLINT
#include <dr_defines.h>
#include <dr_ir_opnd.h>
#include <dr_ir_utils.h> // NOLINT
#include <drvector.h>

#define INSERT_BEFORE instrlist_meta_preinsert

/// @brief A wrapper around drreg_reserve_register that aborts on failure
/// @param drcontext The drcontext of the current thread
/// @param ilist Current instruction list
/// @param where Current instruction
/// @param permitted The set of registers that can be reserved
/// @param [out] reg The reserved register
/// @return void
void reserve_register_checked(void *drcontext, instrlist_t *ilist, instr_t *where,
                              drvector_t *permitted, DR_PARAM_OUT reg_id_t *reg);

/// @brief A wrapper around drreg_reserve_register that aborts on failure
/// @param drcontext The drcontext of the current thread
/// @param ilist Current instruction list
/// @param where Current instruction
/// @param reg The register to unreserve
/// @return void
void unreserve_register_checked(void *drcontext, instrlist_t *ilist, instr_t *where, reg_id_t reg);

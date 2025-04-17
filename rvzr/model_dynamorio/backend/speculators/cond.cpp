///
/// File: Implementation of the Conditional Branch (COND) Speculator
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <functional>
#include <unordered_map>

#include <dr_api.h> // NOLINT
#include <dr_ir_decode.h>
#include <dr_ir_instr.h>
#include <dr_ir_opcodes_x86.h>

#include "speculator_abc.hpp"
#include "speculators/cond.hpp"

// =================================================================================================
// Local helper functions
// =================================================================================================

// =================================================================================================
// Class implementation
// =================================================================================================

pc_t SpeculatorCond::handle_instruction(instr_obs_t instr, dr_mcontext_t *mc, void *dc)
{
    // Handling in the superclass takes priority
    const pc_t next_pc = SpeculatorABC::handle_instruction(instr, mc, dc);
    if (next_pc != 0)
        return next_pc;

    // Check if speculation should be skipped
    if (skip_speculation())
        return 0;

    // TODO: implement speculation here

    // redirect execution to the speculative next instruction
    return 0;
}

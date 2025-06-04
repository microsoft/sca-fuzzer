///
/// File: Implementation of the Conditional Branch (COND) Speculator
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <optional>

#include <dr_api.h> // NOLINT
#include <dr_defines.h>
#include <dr_ir_decode.h>
#include <dr_ir_instr.h>
#include <dr_ir_opcodes_x86.h>

#include "observables.hpp"
#include "speculator_abc.hpp"
#include "speculators/cond.hpp"

// =================================================================================================
// Local helper functions
// =================================================================================================

/// @brief Summary of the relevant information for conditional branches
typedef struct {
    pc_t target;
    pc_t fallthrough;
    bool is_loop;
    bool will_jump;
} BranchInfo;

/// @brief If the instruction is a conditional branch return its relevant information, otherwise
/// return an empty option.
static std::optional<BranchInfo> get_branch_info(instr_obs_t instr, dr_mcontext_t *mc, void *dc,
                                                 instr_noalloc_t *noalloc)
{
    // Decode the instruction
    instr_noalloc_init(dc, noalloc);
    instr_t *cur_instr = instr_from_noalloc(noalloc);
    byte *next_pc = decode(dc, (byte *)instr.pc, cur_instr);
    if (next_pc == nullptr) {
        dr_printf("[ERROR] cond_speculator: Failed to decode instruction\n");
        dr_abort();
        return {};
    }

    // Not a branch, return empty option
    if (not instr_is_cbr(cur_instr))
        return {};

    // Parse branch information
    return BranchInfo{
        .target = (pc_t)instr_get_branch_target_pc(cur_instr),
        .fallthrough = (pc_t)next_pc,
        .is_loop = instr_is_cti_loop(cur_instr),
        .will_jump = instr_jcc_taken(cur_instr, mc->xflags),
    };
}

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

    // Decode the instruction
    instr_noalloc_t noalloc;
    const auto &branch_info = get_branch_info(instr, mc, dc, &noalloc);

    // Skip if not a branch
    if (not branch_info)
        return 0;

    // LOOP instructions must also decrement RCX
    if (branch_info->is_loop)
        mc->rcx -= 1;

    // Simulate misprediction: checkpoint the correct path, speculate the opposite one
    pc_t speculated_pc = 0;
    if (branch_info->will_jump) {
        checkpoint(mc, branch_info->target);
        speculated_pc = branch_info->fallthrough;
    } else {
        checkpoint(mc, branch_info->fallthrough);
        speculated_pc = branch_info->target;
    }

    // Redirect execution to the next speculative instruction
    return speculated_pc;
}

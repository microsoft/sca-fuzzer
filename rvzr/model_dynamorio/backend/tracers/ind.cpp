///
/// File: Indirect Call Tracer implementation
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <optional>

#include <dr_api.h> // NOLINT
#include <dr_defines.h>
#include <dr_ir_macros.h>
#include <dr_ir_macros_x86.h>
#include <dr_ir_opnd.h>
#include <dr_ir_utils.h>
#include <drutil.h>

#include "dr_tools.h"
#include "tracers/ind.hpp"

// =================================================================================================
// Local helper functions
// =================================================================================================

/// @brief Summary of the relevant information for indirect branches
typedef struct {
    pc_t src;
    pc_t target;
} mbr_info_t;

/// @brief If the instruction is a multi-branch instruction, get the source and target,
/// otherwise return an empty option.
static std::optional<mbr_info_t> get_mbr_info(instr_obs_t instr, dr_mcontext_t *mc, void *dc,
                                              instr_noalloc_t *noalloc)
{
    // Decode the instruction
    instr_noalloc_init(dc, noalloc);
    instr_t *cur_instr = instr_from_noalloc(noalloc);
    byte *next_pc = decode(dc, (byte *)instr.pc, cur_instr);
    DR_ASSERT_MSG(next_pc != nullptr, "[ERROR] ind_tracer: Failed to decode instruction\n");

    // Check if it's an indirect jump or ret (a.k.a. multi-way branch).
    if (not instr_is_mbr(cur_instr))
        return {}; // ignore

    const opnd_t target = instr_get_target(cur_instr);
    app_pc target_addr = nullptr;
    bool is_target_in_memory = false;

    // Get the target, depending on the type of instruction
    if (instr_is_return(cur_instr)) {
        target_addr = (app_pc)mc->xsp;
        is_target_in_memory = true;
    } else if (opnd_is_reg(target)) {
        const reg_id_t reg = opnd_get_reg(target);
        target_addr = (app_pc)reg_get_value(reg, mc);
        is_target_in_memory = false;
    } else if (opnd_is_memory_reference(target)) {
        target_addr = opnd_compute_address(target, mc);
        is_target_in_memory = true;
    } else {
        dr_printf("[ERROR] ind_tracer: Unknown target operand type\n");
        dr_abort();
        return {}; // unreachable
    }

    // Load the target if it's in memory
    if (is_target_in_memory) {
        uint64_t loaded_val = 0;
        if (dr_safe_read(target_addr, sizeof(uint64_t), &loaded_val, nullptr)) {
            target_addr = (app_pc)loaded_val;
        } else {
            dr_printf("[ERROR] ind_tracer: Failed to read the target from memory\n");
            dr_abort();
            return {}; // unreachable
        }
    }

    return mbr_info_t{.src = instr.pc, .target = (uint64_t)target_addr};
}

// =================================================================================================
// Class implementation
// =================================================================================================

void TracerInd::observe_instruction(instr_obs_t instr, dr_mcontext_t *mc, void *dc)
{
    TracerABC::observe_instruction(instr, mc, dc);

    // Nothing to do if tracing is off
    if (not tracing_on) {
        return;
    }

    // Decode the instruction
    instr_noalloc_t noalloc;
    const auto &mbr_info = get_mbr_info(instr, mc, dc, &noalloc);

    // Skip if not a branch
    if (not mbr_info)
        return;

    // Log source
    trace.push_back({
        .addr = mbr_info->src,
        .size = 0,
        .type = trace_entry_type_t::ENTRY_PC,
    });
    // Log destination
    trace.push_back({
        .addr = mbr_info->target,
        .size = 0,
        .type = trace_entry_type_t::ENTRY_IND,
    });
}

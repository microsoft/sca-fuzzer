///
/// File: Helper functions for DR model
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <cstddef>

#include <cstdint>
#include <dr_api.h> // NOLINT
#include <dr_defines.h>
#include <dr_ir_opnd.h>
#include <dr_tools.h>

#include <drreg.h>
#include <drvector.h>

#include "observables.hpp"
#include "util.hpp"

void reserve_register_checked(void *drcontext, instrlist_t *ilist, instr_t *where,
                              drvector_t *permitted, DR_PARAM_OUT reg_id_t *reg)
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

bool force_write(byte *addr, size_t size, const uint64_t *val, size_t *w_size)
{
    // Read page protections
    uint prot = -1;
    dr_query_memory(addr, nullptr, nullptr, &prot);

    // Make page writable
    dr_memory_protect(addr, size, DR_MEMPROT_READ | DR_MEMPROT_WRITE | DR_MEMPROT_EXEC);
    const bool success = dr_safe_write(addr, size, val, w_size);
    // Restore previous protections
    dr_memory_protect(addr, size, prot);

    return success;
}

bool is_illegal_jump(instr_obs_t instr, dr_mcontext_t *mc, void *dc)
{
    // Decode the instruction
    // FIXME: we should avoid decoding the same instruction many times.
    // At the moment, we decode both in the COND speculator (to get branch information) and when
    // handling memory operations.
    instr_noalloc_t noalloc;
    instr_noalloc_init(dc, &noalloc);
    instr_t *cur_instr = instr_from_noalloc(&noalloc);
    byte *next_pc = decode(dc, (byte *)instr.pc, cur_instr);
    if (next_pc == nullptr) {
        dr_printf("[ERROR] is_illegal_jump: Failed to decode instruction\n");
        dr_abort();
        return false; // unreachable
    }

    // Check if it's an indirect jump or ret (a.k.a. multi-way branch).
    if (not instr_is_mbr(cur_instr))
        return false; // ignore

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
        return false; // ignore
    }

    // Load the target if it's in memory
    if (is_target_in_memory) {
        uint64_t loaded_val = 0;
        if (dr_safe_read(target_addr, sizeof(uint64_t), &loaded_val, nullptr)) {
            target_addr = (app_pc)loaded_val;
        } else {
            return true; // invalid target
        }
    }

    // Check the permissions of the target address
    uint prot = 0;
    const bool target_exists = dr_query_memory(target_addr, nullptr, nullptr, &prot);
    const bool target_is_executable = (prot & DR_MEMPROT_EXEC) != 0;

    // Target can be followed only if it's a valid executable address
    const bool target_is_valid = target_exists and target_is_executable;
    return not target_is_valid;
}

void flush_bb_cache()
{
    const uint64_t flush_begin = 0;
    const size_t flush_size = -1;

    // NOTE: This is very conservative, but avoids any potentially expensive analysis of
    // the target function
    dr_delay_flush_region((byte *)flush_begin, flush_size, /*flush_id*/ 0, /*callback*/ nullptr);
}

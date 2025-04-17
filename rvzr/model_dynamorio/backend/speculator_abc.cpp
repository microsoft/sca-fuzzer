///
/// File: Abstract interface to be implemented by all speculators.
///       For implementations of concrete speculators, see speculators/*.cpp files.
///
///      A speculator is a component that modifies the execution process of a test case when it
///      runs on the contract model (e.g., it can emulate misprediction of branches).
///      As such, speculators implement execution clauses of different contracts.
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <dr_api.h>

#include "observables.hpp"
#include "speculator_abc.hpp"
#include "util.hpp"

// =================================================================================================
// Local helper functions
// =================================================================================================
static bool is_speculation_barrier(opcode_t opcode)
{
    return opcode == OP_lfence || opcode == OP_mfence || opcode == OP_sfence;
}

// =================================================================================================
// Public Methods
// =================================================================================================
void SpeculatorABC::enable() { enabled = true; }

void SpeculatorABC::disable() { enabled = false; }

bool SpeculatorABC::skip_speculation() const
{
    if (not enabled)
        return true;
    if (nesting >= max_nesting)
        return true;
    if (spec_window >= max_spec_window)
        return true;
    return false;
}

void SpeculatorABC::checkpoint(dr_mcontext_t *mc, pc_t pc)
{
    // dr_printf("[INFO] SpeculatorABC::checkpoint: checkpointing at %llx\n", (long long)pc);

    // store the register state and the rollback address
    checkpoints.push_back({.rollback_pc = pc, .spec_window = spec_window, .mc = *mc});

    // update the state machine that tracks the speculation proces
    in_speculation = true;
    nesting += 1;
}

pc_t SpeculatorABC::rollback(dr_mcontext_t *mc)
{
    // restore the last checkpoint
    if (checkpoints.empty()) {
        dr_printf("[ERROR] SpeculatorABC::rollback: no checkpoints to rollback");
        dr_abort();
    }
    const checkpoint_t checkpoint = checkpoints.back();
    *mc = checkpoint.mc;
    spec_window = checkpoint.spec_window;

    // undo all store operations performed during speculation
    for (auto it = store_log.rbegin(); it != store_log.rend(); ++it) {
        if (it->nesting_level < nesting)
            break;

        // NOTE: same as in handle_mem_access, we should use dr_safe_write here
        *(uint64_t *)it->addr = it->val;
    }

    // update the state machine that tracks the speculation process
    nesting -= 1;
    if (nesting <= 0) {
        nesting = 0;
        in_speculation = false;
    }

    // dr_printf("[INFO] SpeculatorABC::rollback: %llx\n", (long long)checkpoint.rollback_pc);
    return checkpoint.rollback_pc;
}

pc_t SpeculatorABC::handle_instruction(instr_obs_t instr, dr_mcontext_t *mc, void * /*dc*/)
{
    // dr_printf("[INFO] handling %lx\n", (long)instr.pc);
    if (not in_speculation)
        return 0;

    // rollback if we hit a speculation barrier
    if (is_speculation_barrier(instr.opcode)) {
        return rollback(mc);
    }

    // rollback if we hit a speculation window limit
    spec_window += 1;
    if (spec_window >= max_spec_window)
        return rollback(mc);

    return 0;
}

void SpeculatorABC::handle_mem_access(bool is_write, void *address, uint64_t /*size*/)
{
    if (not in_speculation)
        return;

    // record changes made to the memory
    if (is_write) {
        // NOTE: it would be more correct to use dr_safe_read here to avoid faults;
        // However, this code is on the hot path, and dr_safe_read is slow,
        // so we just accept that horrible things may happen. Oh well.
        const uint64_t val = *(uint64_t *)address;
        store_log.push_back({.addr = (uint64_t)address, .val = val, .nesting_level = nesting});
    }
}

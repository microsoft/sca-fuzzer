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

#include <algorithm>
#include <array>
#include <cstdint>

#include <dr_api.h>
#include <dr_ir_opcodes_x86.h>
#include <dr_ir_opnd.h>
#include <dr_os_utils.h>

#include "observables.hpp"
#include "speculator_abc.hpp"
#include "util.hpp"

// =================================================================================================
// Local helper functions
// =================================================================================================

// See Intel Manual https://cdrdv2.intel.com/v1/dl/getContent/671200
// chapter 10.3 - Serializing Instructions.
static constexpr const std::array<uint64_t, 35> serializing_opcodes = {
    // Non-privileged memory-ordering instructions
    OP_lfence, OP_mfence, OP_sfence,
    // Privileged serializing instructions
    // TODO: add MOV CR (except CR8)
    OP_invd, OP_invept, OP_invlpg, OP_invvpid, OP_lgdt, OP_lidt, OP_lldt, OP_ltr, OP_wbinvd,
    OP_wrmsr,
    // Non-privileged serializing instructions
    OP_cpuid, OP_iret, OP_rsm, OP_serialize,
    // TSX/RTM instructions (not tracked by DynamoRIO).
    OP_xbegin, OP_xabort, OP_xend, OP_xtest,
    // XSAVE/XRESTORE instructions (not tracked by DynamoRIO).
    OP_xsave32, OP_xsave64, OP_xsavec32, OP_xsavec64, OP_xsaves32, OP_xsaves64, OP_xsaveopt32,
    OP_xsaveopt64, OP_xrstor32, OP_xrstor64, OP_xrstors32, OP_xrstors64,
    // Other special instructions
    OP_hlt,
    // NOTE: syscalls are not instrumented by Dynamorio, this makes sure that speculation is aborted
    // on speculative syscall instructions.
    OP_syscall};

static bool is_speculation_barrier(const uint64_t opcode)
{
    return std::any_of(serializing_opcodes.begin(), serializing_opcodes.end(),
                       [&opcode](const uint64_t barrier) { return opcode == barrier; });
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
    checkpoints.pop_back();
    *mc = checkpoint.mc;
    spec_window = checkpoint.spec_window;

    // undo all store operations performed during speculation
    while (not store_log.empty()) {
        const auto store = store_log.back();

        // Rollback only entries of the last (nested) speculative window
        if (store.nesting_level < nesting)
            break;

        // NOTE: same as in handle_mem_access, we should use dr_safe_write here
        *(uint64_t *)it->addr = it->val;
        store_log.pop_back();
    }

    // update the state machine that tracks the speculation process
    nesting -= 1;
    if (nesting <= 0) {
        nesting = 0;
        in_speculation = false;
        if (not checkpoints.empty() or not store_log.empty()) {
            dr_printf("[ERROR] Speculation ended but there are still %d checkpoints and %d "
                      "store logs to consume\n",
                      checkpoints.size(), store_log.size());
            dr_abort();
        }
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

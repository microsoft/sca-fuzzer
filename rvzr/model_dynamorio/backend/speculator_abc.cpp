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
#include <memory>

#include "dr_events.h"
#include "dr_ir_instr.h"
#include "dr_tools.h"
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
    // store the register state and the rollback address
    checkpoints.push_back({.rollback_pc = pc, .spec_window = spec_window, .mc = *mc});
    logger.log_checkpoint(pc, spec_window, store_log.size());

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

        // Try restoring the previous value in memory.
        size_t w_size = 0;
        const bool success = dr_safe_write((byte *)store.addr, store.size, &store.val, &w_size);
        logger.log_rollback_store(store.addr, store.val, w_size, store.nesting_level);

        // The rollback should always be successful.
        // NOTE: The following cases are already handled elsewhere:
        //       1. Rollback of an invalid store.
        //            - stores to non-valid memory are handled by handle_mem_access()
        //            - stores to non-writable memory cause an exception, and their
        //            corresponding entires are flushed by handle_exception()
        //       2. Rollback after faulty indirect call/ret.
        //            - should never be executed, handled by handle_instruction()
        if (not success) {
            // If ignoring permissions does not work, we cannot recover.
            dr_printf("[ERROR] Failed to rollback store -- addr: %lx  val: %lx  sx: %d\n",
                      store.addr, store.val, store.size);
            // Read page protections
            uint prot = -1;
            dr_query_memory((byte *)store.addr, nullptr, nullptr, &prot);
            dr_printf("[ERROR] Page prot 0x%x\n", prot);
            dr_abort();
            return 0; // unreachable
        }
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

    logger.log_rollback(nesting, checkpoint.rollback_pc);
    return checkpoint.rollback_pc;
}

pc_t SpeculatorABC::handle_instruction(instr_obs_t instr, dr_mcontext_t *mc, void *dc)
{
    // the last instruction committed: all entries in the store_log are valid
    store_log.update_committed();

    if (not in_speculation)
        return 0;

    // rollback if we hit a speculation barrier
    if (is_speculation_barrier(instr.opcode)) {
        return rollback(mc);
    }

    // rollback if we hit a speculation window limit
    spec_window += 1;
    if (spec_window >= max_spec_window) {
        return rollback(mc);
    }

    // rollback if we're about to jump/ret to an illegal address
    if (is_illegal_jump(instr, mc, dc)) {
        return rollback(mc);
    }

    return 0;
}

bool SpeculatorABC::handle_mem_access(bool is_write, void *address, uint64_t size)
{
    if (not in_speculation)
        return true;

    if (not is_write)
        return true;

    // record changes made to the memory
    auto cur_address = (uint64_t)address;
    size_t remaining_size = size;

    // The store might be bigger than 64 bits (e.g. vector ops): save 64 bits at a time
    while (remaining_size > 0) {
        const uint64_t cur_size = std::min(remaining_size, sizeof(uint64_t));
        // NOTE: on speculative paths, safe reads are the only way to load from memory, since
        // pointers might be invalid.
        size_t r_size = 0;
        uint64_t val = 0;
        const bool success = dr_safe_read((byte *)cur_address, cur_size, (byte *)&val, &r_size);

        if (not success) {
            // If the memory access is illegal, the store is bound to fail: rollback.
            return false;
        }

        // Save the previous memory value to be restored after speculation
        store_log.push_back({
            .addr = cur_address,
            .val = val,
            .size = cur_size,
            .nesting_level = nesting,
        });

        // Advance until all relevant memory has been saved
        cur_address += cur_size;
        remaining_size -= cur_size;
    }

    return true;
}

static bool is_supported_reg(const reg_id_t reg)
{
    // Some registers cannot be modified from the API, see DynamoRIO NYI i#3504
    return reg_is_gpr(reg) or (reg >= DR_REG_START_XMM && reg <= DR_REG_STOP_XMM) or
           (reg >= DR_REG_START_YMM && reg <= DR_REG_STOP_YMM) or
           (reg >= DR_REG_START_ZMM && reg <= DR_REG_STOP_ZMM);
}

static std::pair<instr_t *, byte *> get_load_inst(instr_noalloc_t *noalloc, void *dc,
                                                  dr_mcontext_t *mc)
{
    // Decode the instruction
    instr_noalloc_init(dc, noalloc);
    instr_t *cur_instr = instr_from_noalloc(noalloc);
    byte *next_pc = decode(dc, mc->pc, cur_instr);
    DR_ASSERT_MSG(next_pc != nullptr, "[ERROR] cond_speculator: Failed to decode instruction\n");

    // Return a nullptr if it's not a load.
    if (not instr_reads_memory(cur_instr))
        return {nullptr, nullptr};

    return {cur_instr, next_pc};
}

bool SpeculatorABC::handle_exception(void *drcontext, dr_siginfo_t *siginfo)
{
    if (not in_speculation)
        return false; // nothing to do

    // Get faulty instruction's context
    dr_mcontext_t *mc = siginfo->mcontext;

    // Check if we need to poison the destination register. If not, just rollback.
    if (poison_value.has_value()) {
        // Decode the instruction
        instr_noalloc_t noalloc;
        const auto [cur_instr, next_pc] = get_load_inst(&noalloc, drcontext, mc);

        // Forward poison value
        if (cur_instr != nullptr and instr_num_dsts(cur_instr) > 0) {
            // Get the first destination register
            // TODO: what if the instruction has more than one destination register?
            const opnd_t dst = instr_get_dst(cur_instr, 0);
            // TODO: what if the destination is memory?
            if (opnd_is_reg(dst)) {
                reg_id_t reg = opnd_get_reg(dst);
                reg = reg_to_pointer_sized(reg);
                // Not all registers can be written from the API
                if (is_supported_reg(reg)) {
                    // Create a buffer with the repeated poison value
                    constexpr int max_reg_size = 64;
                    constexpr int n_elems = max_reg_size / sizeof(uint64_t);
                    std::array<uint64_t, n_elems> poison_buf = {};
                    std::fill(poison_buf.begin(), poison_buf.end(), poison_value.value());

                    // Set the destination register to the poison value
                    reg_set_value_ex(reg, mc, (uint8_t *)(poison_buf.data()));
                    // Skip to the next instruction
                    // TODO: what if the instruction is supposed to have other side effects?
                    mc->pc = next_pc;
                    return true; // execution was redirected
                }
            }
        }
    }

    // Flush stores that are in-flight (i.e. were performed by the failing instruction)
    store_log.flush_uncommitted();
    // Perform rollback
    const pc_t newpc = rollback(mc);
    mc->pc = (byte *)newpc;

    return true; // execution was redirected
}

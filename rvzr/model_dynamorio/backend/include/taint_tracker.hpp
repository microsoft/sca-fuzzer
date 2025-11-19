///
/// File: Header for Taint Tracker class,
///       which performs backward taint analysis to identify parts of the input that influence
///       contract traces.
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include <cstdint>
#include <fstream>
#include <iostream>
#include <map>
#include <memory>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include <dr_api.h> // NOLINT
#include <dr_ir_opnd.h>

#include "logger.hpp"
#include "observables.hpp"
#include "types/decoder.hpp"
#include "types/input_taint.hpp"

// =================================================================================================
// Constants and Types
// =================================================================================================
typedef reg_id_t tracker_reg_label_t;
typedef uint64_t tracked_mem_label_t;
typedef uint64_t tracked_label_t;

// Extra register IDs for those registers that do not have a direct mapping in DynamoRIO
// We use here the values that are guaranteed to be unused by other registers
// in our logic (this defined in taint_tracer.cpp:normalize_reg) and thus are safe to re-use.
#define DR_REG_RIP DR_REG_NULL
#define DR_FLAG_CF DR_REG_AX // all GPRs are normalized to 64-bit, so AX and others are free
#define DR_FLAG_PF DR_REG_BX
#define DR_FLAG_AF DR_REG_CX
#define DR_FLAG_ZF DR_REG_DX
#define DR_FLAG_SF DR_REG_SI
#define DR_FLAG_OF DR_REG_DI
#define DR_FLAG_DF DR_REG_R8W

/// @brief Register IDs used by RVZR code
/// must match the register offsets defined in the rvzr/sandbox.py
enum class RVZRRegId : uint64_t {
    RVZR_REG_RAX = 0x2000,
    RVZR_REG_RBX = 0x2008,
    RVZR_REG_RCX = 0x2010,
    RVZR_REG_RDX = 0x2018,
    RVZR_REG_RSI = 0x2020,
    RVZR_REG_RDI = 0x2028,
    RVZR_REG_FLAGS = 0x2030,
    RVZR_REG_XMM0 = 0x2040,
    RVZR_REG_XMM1 = 0x2060,
    RVZR_REG_XMM2 = 0x2080,
    RVZR_REG_XMM3 = 0x20A0,
    RVZR_REG_XMM4 = 0x20C0,
    RVZR_REG_XMM5 = 0x20E0,
    RVZR_REG_XMM6 = 0x2100,
    RVZR_REG_XMM7 = 0x2120,
    RVZR_REG_IGNORED = 0x2FFF,
};

/// @brief Structure holding source and destination operands of the tracked instruction
struct TrackedInstruction {
    instr_obs_t instr_obs;
    // dr_mcontext_t *mc;
    void *dc;

    std::set<tracker_reg_label_t> src_regs;
    std::set<tracker_reg_label_t> dest_regs;
    std::set<tracked_mem_label_t> src_mems;
    std::set<tracked_mem_label_t> dest_mems;
    std::set<tracker_reg_label_t> mem_address_regs;
};

/// @brief Structure tracking all dependencies collected by TaintTracker
struct Dependencies {
    std::map<tracker_reg_label_t, std::set<tracked_label_t>> reg;
    std::map<tracked_mem_label_t, std::set<tracked_label_t>> mem;
};

// =================================================================================================
// Class Definitions
// =================================================================================================

/// @brief Tracking of the input data that impacts contract traces.
///  The algorithm is as follows:
///  - start_instruction: get the static source and destination operands of the instruction
///  - track_memory_access: get dynamic source and destination memory addresses
///  - taint: collect the labels (register names or mem. addresses) that are
///    exposed by this instruction in the contract trace
///  - finalize_instruction:
///    1. propagate the dependencies of the source operands to the destination operands
///    2. update the list of tainted labels with the dependencies of the labels
///       collected by taint_* methods
///  - get_taint: produce an InputTaint object based on the all tainted labels
class TaintTracker
{
  public:
    TaintTracker(const std::string &out_path_, Logger &logger_, Decoder &decode_cache_)
        : logger(logger_), decoder(decode_cache_)
    {
        stream.open(out_path_, std::ios::binary | std::ios::out);
    }
    virtual ~TaintTracker()
    {
        if (stream.is_open())
            stream.close();
    }
    TaintTracker(const TaintTracker &) = delete;
    TaintTracker &operator=(const TaintTracker &) = delete;
    TaintTracker(TaintTracker &&) = delete;
    TaintTracker &operator=(TaintTracker &&) = delete;

    // ---------------------------------------------------------------------------------------------
    // Public Attributes
    bool enabled = false;
    bool tracking_in_progress = false;

    // ---------------------------------------------------------------------------------------------
    // Public Methods (state management)

    /// @brief Enable the taint tracker
    virtual void enable();

    /// @brief Disable the taint tracker and store the collected taints to out_path file
    virtual void finalize();

    /// @brief Save the current state of the taint tracker
    /// @param include_current_inst Whether to include the currently-tracked instruction in the
    ///        checkpoint. (This is currently unused; will be necessary in the future, when
    ///        implementing more complex contracts)
    /// @return void
    virtual void checkpoint(bool include_current_inst);

    /// @brief Restore the state of the taint tracker from the top-most checkpoint
    /// @return void
    virtual void rollback();

    // ---------------------------------------------------------------------------------------------
    // Public Methods (dependency propagation)

    /// @brief Parse instruction and record its static source and destination operands.
    ///        Static means the operands that we can identify without executing the instruction.
    ///        The remaining dynamic operands are collected by track_* methods.
    /// @return void
    virtual void track_instruction(instr_obs_t instr, dr_mcontext_t *mc, void *dc);

    /// @brief Add the address of the memory access to the list of current instruction dependencies
    virtual void track_memory_access(bool is_write, void *address, uint64_t size);

    // ---------------------------------------------------------------------------------------------
    // Public Methods (tainting)

    /// @brief Taint the operands of a given type for the tracked instruction
    ///        (tracked instruction is the last instruction on which track_instruction was called)
    /// @param value_type The type of the value to taint
    virtual void taint(taint_entry_type_t value_type);

  private:
    // ---------------------------------------------------------------------------------------------
    // Private Attributes

    /// @param stream Output stream for taint entries
    std::ofstream stream;

    /// @param logger Used to log checkpoint and rollback events
    Logger &logger;

    /// @param sandbox_base Base address of the sandbox (stored in R14)
    uint64_t sandbox_base = 0;

    /// @param checkpoints Stack of dependency states for speculation support
    std::vector<Dependencies> checkpoints;

    /// @param tainted_labels Set of labels (register IDs or memory addresses) that are tainted
    std::set<tracked_label_t> tainted_labels;

    /// @param pending_taint Set of labels to be tainted when `finalize` is called
    std::set<tracked_label_t> pending_taint;

    /// @param current_instruction The instruction currently being tracked
    std::unique_ptr<TrackedInstruction> current_instruction;

    /// @param dependencies Current dependency state
    Dependencies dependencies;

    /// @param decoder Shared cache for decoded instructions (reference)
    Decoder &decoder;

    // ---------------------------------------------------------------------------------------------
    // Private Methods

    /// @brief Store all collected taints to the output file
    void store_taints();

    /// @brief Parse instruction operands and populate TrackedInstruction structure
    void parse_instruction_operands(TrackedInstruction *tracked_inst);

    /// @brief Add dependencies from tracked instruction to the global dependency state
    void add_dependencies(const TrackedInstruction *tracked_inst);

    /// @brief Remove overwritten dependencies (for MOV/LEA-like instructions)
    void remove_overwritten_dependencies(const TrackedInstruction *tracked_inst);

    /// @brief Collect all source dependencies from a tracked instruction
    /// @param tracked_inst The instruction to collect dependencies from
    /// @return Set of all labels that the instruction's sources depend on
    std::set<tracked_label_t> collect_source_dependencies(
        const TrackedInstruction *tracked_inst) const;

    /// @brief Propagate source dependencies to a destination in the dependency map
    /// @tparam LabelT The type of label (register or memory)
    /// @param dest_label The destination label to update
    /// @param src_dependencies The source dependencies to propagate
    /// @param dep_map The dependency map to update (either reg or mem)
    template <typename LabelT>
    void propagate_dependencies_to_dest(LabelT dest_label,
                                        const std::set<tracked_label_t> &src_dependencies,
                                        std::map<LabelT, std::set<tracked_label_t>> &dep_map);

    /// @brief Debug: Print the current tainted labels. Should be unused in release builds.
    void dbg_print_taints();

    /// @brief Debug: Print the current dependencies. Should be unused in release builds.
    void dbg_print_dependencies();

    // ---------------------------------------------------------------------------------------------
    // Protected Methods

    /// @brief Propagate dependencies and record the taints of the tracked instruction
    /// @throw dr_abort if called when tracking is not in progress
    void finalize_instruction();
};

/// @brief A no-op implementation of TaintTracker; Used when taint tracking is disabled
class NoneTaintTracker : public TaintTracker
{
  public:
    NoneTaintTracker(const std::string &out_path_, Logger &logger_, Decoder &decode_cache_)
        : TaintTracker(out_path_, logger_, decode_cache_)
    {
    }
    ~NoneTaintTracker() override = default;
    NoneTaintTracker(const NoneTaintTracker &) = delete;
    NoneTaintTracker &operator=(const NoneTaintTracker &) = delete;
    NoneTaintTracker(NoneTaintTracker &&) = delete;
    NoneTaintTracker &operator=(NoneTaintTracker &&) = delete;

    void enable() override {}

    void finalize() override {}

    void checkpoint(bool include_current_inst) override {}

    void rollback() override {}

    void track_instruction(instr_obs_t instr, dr_mcontext_t *mc, void *dc) override {}

    void track_memory_access(bool is_write, void *address, uint64_t size) override {}

    void taint(taint_entry_type_t value_type) override {}
};

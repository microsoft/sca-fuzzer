///
/// File: Header for speculator_abc.cpp
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include <cstdint>
#include <vector>

#include <dr_api.h> // NOLINT

#include "observables.hpp"

using std::uint64_t;

// =================================================================================================
// Constants and Types
// =================================================================================================

typedef struct {
    pc_t rollback_pc;
    uint64_t spec_window;
    dr_mcontext_t mc;
} checkpoint_t;

typedef struct {
    uint64_t addr;
    uint64_t val;
    unsigned int nesting_level;
} store_log_entry_t;

// =================================================================================================
// Class Definition
// =================================================================================================

/// @brief Abstract base class for all speculators
class SpeculatorABC
{
  public:
    SpeculatorABC(int max_nesting_, int max_spec_window_)
        : max_nesting(max_nesting_), max_spec_window(max_spec_window_)
    {
    }
    virtual ~SpeculatorABC() = default;
    SpeculatorABC(const SpeculatorABC &) = delete;
    SpeculatorABC &operator=(const SpeculatorABC &) = delete;
    SpeculatorABC(SpeculatorABC &&) = delete;
    SpeculatorABC &operator=(SpeculatorABC &&) = delete;

    // ---------------------------------------------------------------------------------------------
    // Public Attributes

    /// @param Boolean flag indicating whether the speculator is currently active
    bool in_speculation = false;

    // ---------------------------------------------------------------------------------------------
    // Public Methods

    void enable(void);
    void disable(void);

    /// @brief Rollback to the last checkpoint, thus undoing all speculative changes to the process
    ///        state.
    ///
    ///        NOTE: The `rollback` method is public, because it a rollback could be caused
    ///        by external events, such exceptions. The `checkpoint` method, however, is protected
    ///        because it should never be called externally; instead, the `handle_instruction`
    ///        and `handle_mem_access` methods will call it internally as a part of
    ///        the speculation process.
    ///
    /// @param mc The machine context of the current instruction
    /// @return The PC of the next instruction to be executed
    virtual pc_t rollback(dr_mcontext_t *mc);

    /// @brief Check if the speculation should be skipped (e.g., due to exceeding the maximum
    ///        nesting, speculation window, or other conditions).
    /// @param void
    /// @return true if speculation should be skipped, false otherwise
    bool skip_speculation(void) const;

    /// @brief Emulates speculation for the given instruction according to the target contract.
    ///        Each subclass implements a different contract, hence the implementation
    ///        of this method is different for each subclass.
    /// @param opcode The opcode of the instruction
    /// @param pc The program counter (address) of the instruction
    /// @param mc The machine context of the instruction
    /// @param dc The current DR context
    /// @return 0 if no speculation was triggered or no redirection is needed;
    ///         otherwise, the PC of the instruction to which the execution should be redirected
    virtual pc_t handle_instruction(instr_obs_t instr, dr_mcontext_t *mc, void *dc);

    /// @brief Emulates speculation for the memory access according to the target contract.
    ///        Each subclass implements a different contract, hence the implementation
    ///        of this method is different for each subclass.
    /// @param type The type of the memory access (read or write)
    /// @param address The address of the memory access
    /// @param size The size of the memory access
    /// @return void
    virtual void handle_mem_access(bool is_write, void *address, uint64_t size);

  protected:
    // ---------------------------------------------------------------------------------------------
    // Protected Attributes

    /// @brief Boolean flag indicating whether the speculation is enabled
    bool enabled = false;

    /// @param Stack of program state checkpoints (one checkpoint per nested speculation level)
    std::vector<checkpoint_t> checkpoints;

    /// @param Log of store operations performed during speculation; used to undo the operations
    ///        during rollback
    std::vector<store_log_entry_t> store_log;

    /// @param Maximum number of nested speculations
    unsigned int max_nesting = 0;

    /// @param Current speculation nesting level
    unsigned int nesting = 0;

    /// @param Maximum speculation window size
    unsigned int max_spec_window = 0;

    /// @param Current speculation window
    unsigned int spec_window = 0;

    // ---------------------------------------------------------------------------------------------
    // Protected Methods

    /// @brief Record a checkpoint of the current state and store it in the `checkpoints` stack
    /// @param mc The machine context of the current instruction
    /// @param pc The program counter (address) of the instruction
    /// @return void
    virtual void checkpoint(dr_mcontext_t *mc, pc_t pc);
};

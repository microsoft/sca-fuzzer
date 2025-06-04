///
/// File: Header for speculator_abc.cpp
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include <cstdint>
#include <vector>

#include <dr_api.h> // NOLINT

#include "dr_events.h"
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
    size_t size;
    unsigned int nesting_level;
} store_log_entry_t;

/// @brief The StoreLog is a wrapper around an std::vector of store_log_entries that keeps track of
/// which entries have been committed and which entries are in-flight. This is needed since we
/// populate the store_log before actually executing the instruction, which might fail.
class StoreLog
{
  public:
    StoreLog() = default;
    ~StoreLog() = default;
    StoreLog(const StoreLog &) = delete;
    StoreLog(StoreLog &&) = delete;
    StoreLog &operator=(const StoreLog &) = delete;
    StoreLog &operator=(StoreLog &&) = delete;

    /// @brief Implement std::vector::back
    [[nodiscard]] const store_log_entry_t &back() const { return entries.back(); }
    /// @brief Implement std::vector::pop_back. This will also update the committed state.
    void pop_back()
    {
        const bool was_committed_entry = (entries.size() == last_committed);
        entries.pop_back();

        if (was_committed_entry)
            last_committed -= 1;
    }
    /// @brief Implement std::vector::push_back
    void push_back(const store_log_entry_t &entry) { entries.push_back(entry); }
    /// @brief Implement std::vector::size
    [[nodiscard]] size_t size() const { return entries.size(); }
    /// @brief Implement std::vector::empty
    [[nodiscard]] bool empty() const { return entries.empty(); }

    /// @brief The last instruction actually committed: mark all entries as committed.
    void update_committed() { last_committed = entries.size(); }
    /// @brief Check if the instruction has any in-flight entries.
    [[nodiscard]] bool has_uncommitted() const { return entries.size() > last_committed; }
    /// @brief Remove all uncommitted entries from the store_log.
    void flush_uncommitted()
    {
        while (has_uncommitted())
            pop_back();
    }

  private:
    std::vector<store_log_entry_t> entries;
    size_t last_committed = 0;
};

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

    void enable();
    void disable();

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
    [[nodiscard]] bool skip_speculation() const;

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
    /// @return false if the memory access is invalid and is going to produce an exception
    virtual bool handle_mem_access(bool is_write, void *address, uint64_t size);

    /// @brief Notifies the speculator of an exception, needed to possibly reset internal state.
    virtual void handle_exception(dr_siginfo_t *siginfo);

  protected:
    // ---------------------------------------------------------------------------------------------
    // Protected Attributes

    /// @brief Boolean flag indicating whether the speculation is enabled
    bool enabled = false;

    /// @param Stack of program state checkpoints (one checkpoint per nested speculation level)
    std::vector<checkpoint_t> checkpoints;

    /// @param Log of store operations performed during speculation; used to undo the operations
    ///        during rollback
    StoreLog store_log;

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

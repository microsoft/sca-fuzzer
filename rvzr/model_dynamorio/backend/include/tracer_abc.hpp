///
/// File: Header for the Tracer abstract base class
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include <dr_api.h> // NOLINT
#include <dr_defines.h>
#include <dr_events.h>
#include <drvector.h>

#include "observables.hpp"
#include "types/debug_trace.hpp"
#include "types/trace.hpp"

using std::uint64_t;

// =================================================================================================
// Class Definition
// =================================================================================================

/// @brief Abstract base class for all tracers
class TracerABC
{
  public:
    TracerABC(bool enable_dbg_trace_, bool enable_bin_output_);
    virtual ~TracerABC() = default;
    TracerABC(const TracerABC &) = delete;
    TracerABC &operator=(const TracerABC &) = delete;
    TracerABC(TracerABC &&) = delete;
    TracerABC &operator=(TracerABC &&) = delete;

    /// @param Buffer containing collected trace entries
    std::vector<trace_entry_t> trace;

    /// @param Buffer containing collected debug trace entries
    std::vector<debug_trace_entry_t> dbg_trace;

    // ---------------------------------------------------------------------------------------------
    // Public Methods

    /// @brief Starts the tracing process for a wrapped functions
    /// @param wrapctx The machine context of the wrapped function
    /// @param user_data Unused
    /// @return void
    virtual void tracing_start(void *, DR_PARAM_OUT void **);

    /// @brief Finalizes the tracing process for a wrapped function
    /// @param wrapctx The machine context of the wrapped function
    /// @param user_data Unused
    /// @return void
    virtual void tracing_finalize(void *, DR_PARAM_OUT void *);

    /// @brief Record per-instruction information on the trace (e.g., its address) as defined
    ///        by the target contract.
    ///        Note: some subclasses may not record any information as the corresponding
    ///        contract may not require it. For such subclasses, this method should be a no-op.
    /// @param opcode The opcode of the instruction
    /// @param pc The program counter (address) of the instruction
    /// @param mc The machine context of the instruction
    /// @return void
    virtual void observe_instruction(instr_obs_t instr, dr_mcontext_t *mc);

    /// @brief Record per-memory access information on the trace (e.g., its address and value)
    ///        as defined by the target contract.
    ///        Note: some subclasses may not record any information as the corresponding
    ///        contract may not require it. For such subclasses, this method should be a no-op.
    /// @param type The type of the memory access (read or write)
    /// @param address The address of the memory access
    /// @param size The size of the memory access
    /// @return void
    virtual void observe_mem_access(bool is_write, void *address, uint64_t size);

  protected:
    // ---------------------------------------------------------------------------------------------
    // Protected Fields

    /// @param If true, outputs the trace entries in raw binary format
    bool enable_bin_output = false;

    /// @param If true, the tracer will collect data for Revizor's model debug mode
    bool enable_dbg_trace = false;

    /// @param If true, the tracer will instrument the instructions in the traced function
    bool tracing_on = false;

    /// @param If true, tracing has been finalized; no more tracing is allowed
    bool tracing_finalized = false;
};

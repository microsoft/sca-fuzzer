///
/// File: Header for the Tracer abstract base class
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include <cstdint>
#include <string>

#include <dr_api.h> // NOLINT
#include <dr_defines.h>
#include <dr_events.h>
#include <drvector.h>

#include "logger.hpp"
#include "observables.hpp"
#include "types/file_buffer.hpp"
#include "types/trace.hpp"

using std::uint64_t;

// =================================================================================================
// Class Definition
// =================================================================================================

/// @brief Abstract base class for all tracers
class TracerABC
{
  public:
    TracerABC(const std::string &out_path, Logger &logger, bool print);
    virtual ~TracerABC() = default;
    TracerABC(const TracerABC &) = delete;
    TracerABC &operator=(const TracerABC &) = delete;
    TracerABC(TracerABC &&) = delete;
    TracerABC &operator=(TracerABC &&) = delete;

    static constexpr const unsigned buf_sz = 8 * 1024;
    /// @param  Buffer containing collected trace entries
    FileBackedBuf<trace_entry_t, buf_sz> trace;

    // ---------------------------------------------------------------------------------------------
    // Public Methods

    /// @brief Starts the tracing process for a wrapped functions
    /// @return void
    virtual void tracing_start();

    /// @brief Finalizes the tracing process for a wrapped function
    /// @return void
    virtual void tracing_finalize();

    /// @brief Record per-instruction information on the trace (e.g., its address) as defined
    ///        by the target contract.
    ///        Note: some subclasses may not record any information as the corresponding
    ///        contract may not require it. For such subclasses, this method should be a no-op.
    /// @param instr the observed instruction
    /// @param mc The machine context of the instruction
    /// @param dc The DR context of the instruction
    /// @return void
    virtual void observe_instruction(instr_obs_t instr, dr_mcontext_t *mc, void *dc);

    /// @brief Record per-memory access information on the trace (e.g., its address and value)
    ///        as defined by the target contract.
    ///        Note: some subclasses may not record any information as the corresponding
    ///        contract may not require it. For such subclasses, this method should be a no-op.
    /// @param type The type of the memory access (read or write)
    /// @param address The address of the memory access
    /// @param size The size of the memory access
    /// @return void
    virtual void observe_mem_access(bool is_write, void *address, uint64_t size);

    /// @brief Record an architectural exception with a special marker in the trace.
    /// @param siginfo Information about the exception coming from DynamoRIO.
    void observe_exception(dr_siginfo_t *siginfo);

  protected:
    // ---------------------------------------------------------------------------------------------
    // Protected Fields
    /// @param If true, the tracer will instrument the instructions in the traced function
    bool tracing_on = false;

    /// @param If true, tracing has been finalized; no more tracing is allowed
    bool tracing_finalized = false;

    /// @param Where to log events for debugging
    Logger &logger;
};

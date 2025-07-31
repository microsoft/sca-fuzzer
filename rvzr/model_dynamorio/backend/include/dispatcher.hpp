///
/// File: Header for the Dispatcher class,
///       responsible for instrumenting the target application with calls to service classes
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include <memory>

#include <dr_api.h> // NOLINT

#include "cli.hpp"
#include "logger.hpp"
#include "speculator_abc.hpp"
#include "tracer_abc.hpp"

/// @brief Dispatcher class responsible for adding instrumentation to instructions
///        in the target application and calling the appropriate
///        service classes (e.g., Tracer, Speculator, etc)
class Dispatcher
{
  public:
    Dispatcher(cli_args_t *cli_args);
    virtual ~Dispatcher();
    Dispatcher(const Dispatcher &) = delete;
    Dispatcher &operator=(const Dispatcher &) = delete;
    Dispatcher(Dispatcher &&) = delete;
    Dispatcher &operator=(Dispatcher &&) = delete;

    // ---------------------------------------------------------------------------------------------
    // Public Methods

    /// @brief Starts the instrumentation process for a wrapped function
    /// @param wrapctx The machine context of the wrapped function
    /// @param user_data Unused
    /// @return void
    void start(void *wrapctx, void **user_data);

    /// @brief Restarts the instrumentation process for a wrapped function
    /// @param wrapctx The machine context of the wrapped function
    /// @param user_data Unused
    /// @return void
    void restart(void *wrapctx, void **user_data);

    /// @brief Finalizes the instrumentation process
    /// @return void
    void finalize();

    /// @brief Check if the instrumentation has started and is not finalized.
    [[nodiscard]] bool is_instrumentation_on() const { return instrumentation_on; };

    /// @brief Instruments the instruction \p instr with calls to callback functions of the
    /// corresponding type
    /// @param drcontext The drcontext of the current thread
    /// @param bb The basic block to be instrumented
    /// @param instr The instruction to instrument
    /// @return Flags to be consumed by DynamoRIO instrumentation callbacks
    dr_emit_flags_t instrument_instruction(void *drcontext, instrlist_t *bb, instr_t *instr) const;

    /// @brief Instruments the exit instruction with the finalization callback
    /// @param drcontext The drcontext of the current thread
    /// @param bb The basic block to be instrumented
    /// @param instr The instruction to instrument
    /// @return Flags to be consumed by DynamoRIO instrumentation callbacks
    dr_emit_flags_t instrument_exit(void *drcontext, instrlist_t *bb, instr_t *instr) const;

    /// @brief Passes the exception down to service modules for handling
    /// @param drcontext The drcontext of the current thread
    /// @param excpt Pointer to the exception data
    /// @return True if the exception has been handled (control-flow should be redirected)
    bool handle_exception(void *drcontext, dr_siginfo_t *siginfo) const;

    /// @param logger: shared logger for event tracing
    std::unique_ptr<Logger> logger = nullptr;
    /// @param tracer: implements observation clause
    std::unique_ptr<TracerABC> tracer = nullptr;
    /// @param speculator: implements execution clause
    std::unique_ptr<SpeculatorABC> speculator = nullptr;

    /// @param initialized: true if the dispatcher has been already initialized (start was called)
    bool is_initialized = false;

  private:
    bool instrumentation_on;
};

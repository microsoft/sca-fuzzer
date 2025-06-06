///
/// File: Header for the Dispatcher class,
///       responsible for instrumenting the target application with calls to service classes
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include <memory>
#include <string>
#include <vector>

#include <dr_api.h> // NOLINT

#include "cli.hpp"
#include "logger.hpp"
#include "speculator_abc.hpp"
#include "tracer_abc.hpp"

struct module_bundle_t {
    std::unique_ptr<Logger> logger = nullptr;
    std::unique_ptr<TracerABC> tracer = nullptr;
    std::unique_ptr<SpeculatorABC> speculator = nullptr;
};

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

    /// @brief Starts the instrumentation process for a wrapped functions
    /// @param wrapctx The machine context of the wrapped function
    /// @param user_data Unused
    /// @return void
    void start(void *, DR_PARAM_OUT void **);

    /// @brief Finalizes the instrumentation process for a wrapped function
    /// @param wrapctx The machine context of the wrapped function
    /// @param user_data Unused
    /// @return void
    void finalize(void *, DR_PARAM_OUT void *);

    /// @brief Instruments the instruction \p instr with calls to callback functions of the
    /// corresponding type
    /// @param drcontext The drcontext of the current thread
    /// @param bb The basic block to be instrumented
    /// @param instr The instruction to instrument
    /// @return Flags to be consumed by DynamoRIO instrumentation callbacks
    dr_emit_flags_t instrument_instruction(void *drcontext, instrlist_t *bb, instr_t *instr) const;

    /// @brief Passes the exception down to service modules for handling
    /// @param drcontext The drcontext of the current thread
    /// @param excpt Pointer to the exception data
    /// @return True if the exception has been handled (control-flow should be redirected)
    bool handle_exception(void *drcontext, dr_siginfo_t *siginfo);

  protected:
    // ---------------------------------------------------------------------------------------------
    // Protected Fields

    /// @param instrumentation_on: If true, the dispatcher will apply instrumentation to the target
    bool instrumentation_on = false;

    /// @param module_bundle: A bundle of service modules to call from the instrumentation
    std::unique_ptr<module_bundle_t> module_bundle = nullptr;

  private:
    /// @param The name of the function to instrument
    std::string instrumented_func;
};

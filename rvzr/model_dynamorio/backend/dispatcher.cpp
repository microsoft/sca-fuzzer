///
/// File: Class responsible for instrumenting instructions
///       in the target application with a call to a dispatch function.
///       The function, in turn, calls service classes (e.g., Tracer, Speculator, etc)
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <cstdint>
#include <memory>
#include <string>

#include <dr_api.h> // NOLINT
#include <dr_defines.h>
#include <dr_tools.h>
#include <drmgr.h>
#include <drwrap.h>

#include "cli.hpp"
#include "dispatcher.hpp"
#include "factory.hpp"
#include "observables.hpp"
#include "util.hpp"

using std::string;

/// Defined by model.cpp
extern std::unique_ptr<Dispatcher> glob_dispatcher; // NOLINT

// =================================================================================================
// Runtime functions
// =================================================================================================

/// @brief Dispatch function that calls the per-instruction functions in the service modules
/// @param mc Machine context of the current instruction
/// @param bundle The bundle of service modules to be called
/// @param instr Observables of the current instruction
/// @return The PC of the next instruction to be executed (if redirection is necessary);
///         otherwise, 0 (zero)
static pc_t instruction_dispatch(dr_mcontext_t *mc, void *dc, const Dispatcher *dispatcher,
                                 instr_obs_t instr)
{
    dispatcher->logger->log_instruction(instr, mc, dispatcher->speculator->get_nesting_level());
    dispatcher->taint_tracker->track_instruction(instr, mc, dc);
    dispatcher->tracer->observe_instruction(instr, mc, dc);
    const pc_t next_pc = dispatcher->speculator->handle_instruction(instr, mc, dc);
    return next_pc;
}

/// @brief Dispatch function that calls the per-memory-access functions in the service modules
/// @param drcontext
/// @param mc
/// @param bundle
/// @param pc
/// @return The PC of the next instruction to be executed (if redirection is necessary);
///         otherwise, 0 (zero)
static pc_t mem_access_dispatch(void *dc, dr_mcontext_t *mc, const Dispatcher *dispatcher, pc_t pc)
{
    // Decode the instruction using the shared cache to extract its memory references
    instr_t *instr = dispatcher->decoder->get_decoded_instr(dc, (byte *)pc);

    // Identify the size of the memory reference
    // (assumed that all memory references for the instruction are of the same size)
    const uint64_t size = instr_memory_reference_size(instr);

    // Loop over all memory operands and call service modules for each
    uint index = 0;
    bool is_write = false;
    app_pc addr = nullptr;
    while (instr_compute_address_ex(instr, mc, index, &addr, &is_write)) {
        dispatcher->logger->log_mem_access(is_write, addr, size);
        dispatcher->taint_tracker->track_memory_access(is_write, (void *)addr, size);
        dispatcher->tracer->observe_mem_access(is_write, addr, size);
        if (not dispatcher->speculator->handle_mem_access(is_write, (void *)addr, size)) {
            return dispatcher->speculator->rollback(mc);
        }

        index++;
    }

    return 0;
}

/// @brief Callback function called for every instruction in the instrumented function
/// @param bundle The bundle of service modules to be called
/// @param opcode The opcode of the instruction
/// @param pc The program counter (address) of the instruction
/// @param has_mem_ref Flag indicating whether the instruction has a memory reference
static void dispatch_callback(uint64_t opcode, uint64_t pc, uint64_t has_mem_ref)
{
    // Get the global dispatcher
    const Dispatcher *dispatcher = glob_dispatcher.get();
    DR_ASSERT_MSG(dispatcher != nullptr, "[ERROR] glob_dispatcher is null\n");

    // Nothing to do if we're outside of the instrumented function
    if (not dispatcher->is_instrumentation_on()) {
        return;
    }

    // get current context
    void *drcontext = dr_get_current_drcontext();
    dr_mcontext_t mc = {sizeof(mc), DR_MC_ALL};
    dr_get_mcontext(drcontext, &mc);

    // create an instruction instance for the current instruction
    const instr_obs_t instr = {
        .opcode = opcode,
        .pc = (pc_t)pc,
        .has_mem_access = (bool)has_mem_ref,
    };

    // pass down to instruction dispatch functions and redirect execution if needed
    pc_t next_pc = instruction_dispatch(&mc, drcontext, dispatcher, instr);
    if (next_pc != 0) {
        mc.pc = (byte *)next_pc;
        dr_redirect_execution(&mc);
        return; // unreachable
    }
    dr_set_mcontext(drcontext, &mc);
    if (has_mem_ref == 0) {
        return;
    }

    // pass down to memory access dispatch functions and redirect execution if needed
    next_pc = mem_access_dispatch(drcontext, &mc, dispatcher, instr.pc);
    if (next_pc != 0) {
        mc.pc = (byte *)next_pc;
        dr_redirect_execution(&mc);
        return; // unreachable
    }
    dr_set_mcontext(drcontext, &mc);
}

/// @brief Callback function called upon return from the instrumented function
static void exit_callback()
{
    // Get the global dispatcher
    Dispatcher *dispatcher = glob_dispatcher.get();
    DR_ASSERT_MSG(dispatcher != nullptr, "[ERROR] glob_dispatcher is null\n");
    DR_ASSERT_MSG(dispatcher->is_instrumentation_on(),
                  "[ERROR] Instrumentation disabled when exiting instrumented function");

    // get current context
    void *drcontext = dr_get_current_drcontext();
    dr_mcontext_t mc = {sizeof(mc), DR_MC_ALL};
    dr_get_mcontext(drcontext, &mc);

    // Rollback speculation if we're speculatively exiting the target function
    if (dispatcher->speculator->in_speculation) {
        // Perform rollback
        const pc_t newpc = dispatcher->speculator->rollback(&mc);
        mc.pc = (byte *)newpc;
        dr_redirect_execution(&mc);
        return; // unreachable
    }

    // Architectural exit: stop the instrumentation
    flush_bb_cache();
    dispatcher->finalize();
    dr_set_mcontext(drcontext, &mc);
}

bool Dispatcher::handle_exception(void *drcontext, dr_siginfo_t *siginfo) const
{
    logger->log_exception(siginfo);
    // Exceptions on speculative paths are handled by the speculator.
    const bool redirected = speculator->handle_exception(drcontext, siginfo);
    if (redirected)
        return true; // intercepted

    // Architectural exceptions are forwarded to the program
    dr_printf("[XCPT] Dispatcher::handle_exception: exception on a non-speculative path\n");
    tracer->observe_exception(siginfo);
    return false; // not intercepted
}

// =================================================================================================
// Instrumentation-time Methods
// =================================================================================================
void Dispatcher::start()
{
    DR_ASSERT_MSG(not is_initialized,
                  "[ERROR] Attempting to initialize Dispatcher multiple times.");

    instrumentation_on = true;
    is_initialized = true;

    // Turn service modules on
    taint_tracker->enable();
    tracer->enable();
    speculator->enable();
}

void Dispatcher::restart()
{
    DR_ASSERT_MSG(is_initialized,
                  "[ERROR] Attempting to restart Dispatcher without initialization.");

    instrumentation_on = true;

    // Turn service modules on
    taint_tracker->enable();
    tracer->enable();
    speculator->enable();
}

void Dispatcher::finalize()
{
    if (not instrumentation_on)
        return;

    // Turn service modules off
    taint_tracker->finalize();
    tracer->finalize();
    speculator->disable();

    instrumentation_on = false;
}

dr_emit_flags_t Dispatcher::instrument_instruction(void *drcontext, instrlist_t *bb,
                                                   instr_t *instr) const
{
    // Nothing to do if we're outside of the instrumented function
    if (not instrumentation_on) {
        return DR_EMIT_DEFAULT;
    }

    // Get a pointer to the instruction's original form (pre event_bb_app2app call)
    instr_t *org_instr = drmgr_orig_app_instr_for_fetch(drcontext);
    if (org_instr == nullptr) { // DR tell us that this instruction should be skipped
        return DR_EMIT_DEFAULT;
    }

    // Get instruction parameters
    const opnd_t opcode = OPND_CREATE_INT64(instr_get_opcode(org_instr));
    const opnd_t pc_op = OPND_CREATE_INTPTR(instr_get_app_pc(org_instr));
    const opnd_t has_mem_ref =
        OPND_CREATE_INT64(instr_reads_memory(org_instr) or instr_writes_memory(org_instr));

    // Add a clean call to the dispatch callback, which will forward the call to the service
    // modules
    const int dispatch_callback_nargs = 3;
    dr_insert_clean_call(drcontext, bb, instr, (void *)dispatch_callback, false,
                         dispatch_callback_nargs, opcode, pc_op, has_mem_ref);

    return DR_EMIT_DEFAULT;
}

void Dispatcher::instrument_exit(void *drcontext, instrlist_t *bb, instr_t *instr) const
{
    dr_insert_clean_call(drcontext, bb, instr, (void *)exit_callback, false, 0);
}

// =================================================================================================
// Constructors and Destructors
// =================================================================================================
Dispatcher::Dispatcher(cli_args_t *cli_args) : instrumentation_on(false)
{
    // Create service modules
    logger = create_logger(cli_args->debug_output, cli_args->log_level, cli_args->print_dbg_trace);
    decoder = std::make_unique<Decoder>();
    taint_tracker = create_taint_tracker(cli_args->enable_taint_tracker, cli_args->taint_output,
                                         *logger, *decoder);
    tracer = create_tracer(cli_args->tracer_type, cli_args->trace_output, *logger, *taint_tracker,
                           *decoder, cli_args->print_trace);
    speculator = create_speculator(cli_args->speculator_type, cli_args->max_nesting,
                                   cli_args->max_spec_window, *logger, *taint_tracker, *decoder,
                                   cli_args->poison_value);
}

Dispatcher::~Dispatcher()
{
    logger.reset();
    decoder.reset();
    tracer.reset();
    speculator.reset();
    taint_tracker.reset();
}

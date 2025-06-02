///
/// File: Class responsible for instrumenting instructions
///       in the target application with a call to a dispatch function.
///       The function, in turn, calls service classes (e.g., Tracer, Speculator, etc)
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <string>
#include <vector>

#include <dr_api.h> // NOLINT
#include <dr_tools.h>
#include <drmgr.h>

#include "cli.hpp"
#include "dispatcher.hpp"
#include "factory.hpp"
#include "observables.hpp"

using std::string;

// =================================================================================================
// Runtime functions
// =================================================================================================

/// glob_module_bundle: Callback functions do not have access to the class instance,
/// so we pass the module bundle as a static variable.
static module_bundle_t *glob_module_bundle = nullptr; // NOLINT

/// @brief Dispatch function that calls the per-instruction functions in the service modules
/// @param mc Machine context of the current instruction
/// @param bundle The bundle of service modules to be called
/// @param instr Observables of the current instruction
/// @return The PC of the next instruction to be executed (if redirection is necessary);
///         otherwise, 0 (zero)
static pc_t instruction_dispatch(dr_mcontext_t *mc, void *dc, const module_bundle_t *bundle,
                                 instr_obs_t instr)
{
    bundle->tracer->observe_instruction(instr, mc);
    const pc_t next_pc = bundle->speculator->handle_instruction(instr, mc, dc);
    return next_pc;
}

/// @brief Dispatch function that calls the per-memory-access functions in the service modules
/// @param drcontext
/// @param mc
/// @param bundle
/// @param pc
static void mem_access_dispatch(void *dc, dr_mcontext_t *mc, const module_bundle_t *bundle, pc_t pc)
{
    // decode the instruction to extract its memory references
    instr_noalloc_t noalloc;
    instr_noalloc_init(dc, &noalloc);
    instr_t *instr = instr_from_noalloc(&noalloc);
    byte *next_pc = decode(dc, (byte *)pc, instr);
    if (next_pc == nullptr) {
        dr_printf("[ERROR] mem_access_dispatch: Failed to decode instruction\n");
        dr_abort();
        return;
    }

    // Identify the size of the memory reference
    // (assumed that all memory references for the instruction are of the same size)
    const uint64_t size = instr_memory_reference_size(instr);

    // Loop over all memory operands and call service modules for each
    uint index = 0;
    bool is_write = false;
    app_pc addr = nullptr;
    while (instr_compute_address_ex(instr, mc, index, &addr, &is_write)) {
        bundle->tracer->observe_mem_access(is_write, addr, size);
        bundle->speculator->handle_mem_access(is_write, (void *)addr, size);
        index++;
    }
}

/// @brief Callback function called for every instruction in the instrumented function
/// @param bundle The bundle of service modules to be called
/// @param opcode The opcode of the instruction
/// @param pc The program counter (address) of the instruction
/// @param has_mem_ref Flag indicating whether the instruction has a memory reference
static void dispatch_callback(uint64_t opcode, uint64_t pc, uint64_t has_mem_ref)
{
    const module_bundle_t *bundle = glob_module_bundle;
    if (bundle == nullptr) {
        dr_printf("[ERROR] dispatch_callback: module bundle is null\n");
        dr_abort();
        return; // unreachable
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
    const pc_t next_pc = instruction_dispatch(&mc, drcontext, bundle, instr);
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
    mem_access_dispatch(drcontext, &mc, bundle, instr.pc);
    dr_set_mcontext(drcontext, &mc);
}

bool Dispatcher::handle_exception(void * /*drcontext*/, dr_siginfo_t *siginfo)
{
    // dr_printf("[INFO] Dispatcher::handle_exception: exception %d\n", siginfo->sig);
    if (!module_bundle->speculator->in_speculation) {
        // dr_printf("[ERROR] Dispatcher::handle_exception: exception %d on a non-speculative
        // path\n",
        //   siginfo->sig);
        return false;
    }
    // dr_printf("[INFO] Dispatcher::handle_exception: is speculative\n");

    // Exceptions on speculative paths cause speculation to be aborted
    dr_mcontext_t *mc = siginfo->mcontext;
    const pc_t next_pc = module_bundle->speculator->rollback(mc);
    mc->pc = (byte *)next_pc;
    return true;
}

// =================================================================================================
// Instrumentation-time Methods
// =================================================================================================
void Dispatcher::start(void *wrapctx, DR_PARAM_OUT void **user_data)
{
    instrumentation_on = true;

    // Turn service modules on
    module_bundle->tracer->tracing_start(wrapctx, user_data);
    module_bundle->speculator->enable();
}

void Dispatcher::finalize(void *wrapctx, DR_PARAM_OUT void *user_data)
{
    // Turn service modules off
    module_bundle->tracer->tracing_finalize(wrapctx, user_data);
    module_bundle->speculator->disable();

    instrumentation_on = false;
}

dr_emit_flags_t Dispatcher::instrument_instruction(void *drcontext, instrlist_t *bb,
                                                   instr_t *instr) const
{
    // Nothing to do if we're outside of the instrumentation function
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
    const opnd_t pc = OPND_CREATE_INTPTR(instr_get_app_pc(org_instr));
    const opnd_t has_mem_ref =
        OPND_CREATE_INT64(instr_reads_memory(org_instr) or instr_writes_memory(org_instr));

    // Add a clean call to the dispatch callback, which will forward the call to the service modules
    dr_insert_clean_call(drcontext, bb, instr, (void *)dispatch_callback, false, 3, opcode, pc,
                         has_mem_ref);

    return DR_EMIT_DEFAULT;
}

// =================================================================================================
// Constructors and Destructors
// =================================================================================================
Dispatcher::Dispatcher(cli_args_t *cli_args)
{
    // Create service modules
    module_bundle = std::make_unique<module_bundle_t>();
    module_bundle->tracer = create_tracer(cli_args->tracer_type, cli_args->enable_debug_trace,
                                          cli_args->enable_bin_output);
    module_bundle->speculator = create_speculator(cli_args->speculator_type, cli_args->max_nesting,
                                                  cli_args->max_spec_window);

    // Make the bundle available to the dispatch callback
    glob_module_bundle = module_bundle.get();
}

Dispatcher::~Dispatcher()
{
    module_bundle->tracer.reset();
    module_bundle->speculator.reset();
    module_bundle.reset();
}

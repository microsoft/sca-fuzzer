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
#include <drmgr.h>

#include "dispatcher.hpp"
#include "factory.hpp"

using std::string;

// =================================================================================================
// Callback functions that dispatch the instrumentation calls to service classes
// =================================================================================================

/// @brief Dispatch function that calls the per-instruction functions in the service modules
/// @param drcontext
/// @param mc
/// @param bundle The bundle of service modules to be called
/// @param opcode The opcode of the instruction
/// @param pc The program counter (address) of the instruction
static void instruction_dispatch(dr_mcontext_t *mc, const module_bundle_t *bundle, uint64_t opcode,
                                 uint64_t pc)
{
    bundle->tracer->observe_instruction(opcode, pc, mc);
}

/// @brief Dispatch function that calls the per-memory-access functions in the service modules
/// @param drcontext
/// @param mc
/// @param bundle
/// @param pc
static void mem_access_dispatch(void *drcontext, dr_mcontext_t *mc, const module_bundle_t *bundle,
                                uint64_t pc)
{
    // create an instruction instance for the current memory access
    instr_t *instr = instr_create(drcontext);
    byte *err = decode(drcontext, (byte *)pc, instr);
    if (err == nullptr) {
        instr_destroy(drcontext, instr);
        return;
    }

    // Identify the size of the memory reference
    // (assumed that all memory references for the instruction are of the same size)
    uint64_t size = instr_memory_reference_size(instr);

    // Loop over all memory operands and call service modules for each
    uint index = 0;
    bool is_write = false;
    app_pc addr = 0;
    while (instr_compute_address_ex(instr, mc, index, &addr, &is_write)) {
        bundle->tracer->observe_mem_access(is_write, addr, size);
        index++;
    }

    instr_destroy(drcontext, instr);
}

/// @brief Callback function called for every instruction in the instrumented function
/// @param bundle The bundle of service modules to be called
/// @param opcode The opcode of the instruction
/// @param pc The program counter (address) of the instruction
/// @param has_mem_ref Flag indicating whether the instruction has a memory reference
static void dispatch_callback(const module_bundle_t *bundle, uint64_t opcode, uint64_t pc,
                              uint64_t has_mem_ref)
{
    // get current context
    void *drcontext = dr_get_current_drcontext();
    dr_mcontext_t mc = {sizeof(mc), DR_MC_ALL};
    dr_get_mcontext(drcontext, &mc);

    // pass down to dispatch functions
    instruction_dispatch(&mc, bundle, opcode, pc);
    if (has_mem_ref) {
        mem_access_dispatch(drcontext, &mc, bundle, pc);
    }
}

// =================================================================================================
// Constructors and Destructors
// =================================================================================================
Dispatcher::Dispatcher(bool enable_dbg_trace_, bool enable_bin_output_, const string &tracer_type,
                       const string &speculator_type)
{
    // Create service modules
    module_bundle = std::make_unique<module_bundle_t>();
    module_bundle->tracer = create_tracer(tracer_type, enable_dbg_trace_, enable_bin_output_);
    // module_bundle->speculator = create_speculator(speculator_type);
}

Dispatcher::~Dispatcher()
{
    module_bundle->tracer.reset();
    // module_bundle->speculator.reset();
    module_bundle.reset();
}

// =================================================================================================
// Public Methods
// =================================================================================================
void Dispatcher::start(void *wrapcxt, OUT void **user_data)
{
    instrumentation_on = true;

    // Turn service modules on
    module_bundle->tracer->tracing_start(wrapcxt, user_data);
}

void Dispatcher::finalize(void *wrapcxt, OUT void *user_data)
{
    // Turn service modules off
    module_bundle->tracer->tracing_finalize(wrapcxt, user_data);

    instrumentation_on = false;
}

dr_emit_flags_t Dispatcher::instrument_instruction(void *drcontext, instrlist_t *bb, instr_t *instr)
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

    // Create an opnd_t for the module bundle to pass it down to clean calls
    const opnd_t bundle_arg = OPND_CREATE_INTPTR(module_bundle.get());

    // Get instruction parameters
    const opnd_t opcode = OPND_CREATE_INT64(instr_get_opcode(org_instr));
    const opnd_t pc = OPND_CREATE_INTPTR(instr_get_app_pc(org_instr));
    const opnd_t has_mem_ref =
        OPND_CREATE_INT64(instr_reads_memory(instr) or instr_writes_memory(instr));

    // Add a clean call to the dispatch callback, which will forward the call to the service modules
    dr_insert_clean_call(drcontext, bb, instr, (void *)dispatch_callback, false, 4, bundle_arg,
                         opcode, pc, has_mem_ref);

    return DR_EMIT_DEFAULT;
}

///
/// File: Interface between the model and the DynamoRIO API
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <stdexcept>
#include <string>

#include <dr_api.h> // NOLINT
#include <dr_defines.h>
#include <dr_events.h>
#include <dr_tools.h>
#include <drmgr.h>
#include <drsyms.h>
#include <drutil.h>
#include <drwrap.h>
#include <drx.h>

#include "cli.hpp"
#include "dispatcher.hpp"
#include "factory.hpp"
#include "speculator_abc.hpp"
#include "tracer_abc.hpp"

using std::size_t;
using std::string;

namespace dr_model
{

/// @brief Pointer to the dispatcher instance;
/// @note We have to use a local pointer because DynamoRIO API relies on callback functions,
///       and there is no other way to pass the tracer instance to the callbacks;
std::unique_ptr<Dispatcher> dispatcher = nullptr; // NOLINT

/// @brief Name of the function to instrument
std::string instrumented_func_name; // NOLINT

void event_instrumentation_start(void *wrapctx, DR_PARAM_OUT void **user_data);
void event_instrumentation_end(void *wrapctx, void *user_data);
void dr_model_del() noexcept;

/// @brief Flush dynamorio's basic-block cache. This is needed when transitioning from
/// non-instrumented code to instrumented code, as any shared code (e.g. libc) might be cached and
/// therefore inaccessible for instrumentation.
static void flush_bb_cache()
{
    const uint64_t flush_begin = 0;
    const size_t flush_size = -1;

    // NOTE: This is very conservative, but avoids any potentially expensive analysis of
    // the target function
    dr_delay_flush_region((byte *)flush_begin, flush_size, /*flush_id*/ 0, /*callback*/ nullptr);
}

// =================================================================================================
// Event callbacks
// =================================================================================================

/// @brief Callback executed before loading a module.
///        The implementation wraps a function called `instrumented_func_name`
///        with calls to `event_instrumentation_start` and `event_instrumentation_end`
/// @param unused
/// @param module_ Pointer to the module data
/// @param unused
/// @return void
void event_module_load(void * /*drcontext*/, const module_data_t *module_, bool /*loaded*/)
{
    size_t offset = 0;
    const drsym_error_t sym_res = drsym_lookup_symbol(
        module_->full_path, instrumented_func_name.c_str(), &offset, DRSYM_DEMANGLE);
    if (sym_res == DRSYM_SUCCESS) {
        app_pc to_wrap = module_->start + offset;
        drwrap_wrap(to_wrap, event_instrumentation_start, event_instrumentation_end);
    }
}

/// @brief Callback executed at the first instrumentation stage:
///        application-to-application transformation.
///        The implementation expands string ops and scatter/gather
///        into a sequence of normal memory references.
/// @param drcontext The drcontext of the current thread
/// @param unused
/// @param bb The basic block to be transformed
/// @param unused
/// @param unused
/// @return BB emitted state (dr_emit_flags_t)
dr_emit_flags_t event_bb_app2app(void *drcontext, void * /*tag*/, instrlist_t *bb,
                                 bool /*for_trace*/, bool /*translating*/)
{
    bool err = false;
    err |= !drutil_expand_rep_string(drcontext, bb);
    err |= !drx_expand_scatter_gather(drcontext, bb, nullptr);
    if (err) {
        dr_printf("ERROR: failed to expand string ops or scatter/gather\n");
        dr_abort();
    }
    return DR_EMIT_DEFAULT;
}

/// @brief Callback executed at the third instrumentation stage: instrumentation insertion.
///        The implementation invokes the Dispatcher::instrument_instruction method for every
///        (post-expanded) instruction in the basic block.
/// @param drcontext The drcontext of the current thread
/// @param unused
/// @param bb Parent basic block
/// @param instr The instruction to instrument
/// @param unused
/// @param unused
/// @param unused
/// @return BB emitted state (dr_emit_flags_t)
dr_emit_flags_t event_bb_instrumentation(void *drcontext, void * /*tag*/, instrlist_t *bb,
                                         instr_t *instr, bool /*for_trace*/, bool /*translating*/,
                                         void * /*user_data*/)
{
    const dr_emit_flags_t emit_flags = dispatcher->instrument_instruction(drcontext, bb, instr);
    return emit_flags;
}

/// @brief Callback executed before calling the `instrumented_func_name` function.
/// @param wrapctx The wrap context
/// @param user_data
/// @return void
void event_instrumentation_start(void *wrapctx, DR_PARAM_OUT void **user_data)
{
    flush_bb_cache();
    dispatcher->start(wrapctx, user_data);
}

/// @brief Callback executed after returning from the `instrumented_func_name` function.
/// @param wrapctx The wrap context
/// @param user_data
/// @return void
void event_instrumentation_end(void *wrapctx, void *user_data)
{
    dispatcher->finalize(wrapctx, user_data);
    flush_bb_cache();
}

/// @brief Callback executed upon exceptions
/// @param drcontext The drcontext of the current thread
/// @param excpt Pointer to the exception data
/// @return if the exception is handled, this function does not return
/// (dr_redirect_execution is called by handlers); otherwise, it returns true so that DR will
/// continue with the default exception handling
dr_signal_action_t event_exception(void *drcontext, dr_siginfo_t *siginfo)
{
    dispatcher->handle_exception(drcontext, siginfo);

    // Continue with the default exception handling if no redirection happened
    return DR_SIGNAL_DELIVER;
}

/// @brief Callback executed before exiting the application.
/// @return void
void event_exit()
{
    // There is a possibility that the tracing process has not been finalized
    // because the traced function has not been called
    dispatcher->finalize(nullptr, nullptr);

    // Make sure we've sent all the collected data
    fflush(stdout);

    // Delete the dispatcher
    dispatcher.reset();

    // Close the DR extensions
    dr_model_del();
}

// =================================================================================================
// Model constructor and destructor
// =================================================================================================

/// @brief Constructor of the DR model.
///        The function initializes the DR extensions and registers callbacks.
/// @return void
/// @throw std::runtime_error if any of the DR extensions fails to start
void dr_model_init()
{
    // Start DR extensions
    if (!drmgr_init())
        throw std::runtime_error("ERROR: failed to start drmgr\n");
    if (!drutil_init())
        throw std::runtime_error("ERROR: failed to start drutil\n");
    if (!drx_init())
        throw std::runtime_error("ERROR: failed to start drx\n");
    if (!drwrap_init())
        throw std::runtime_error("ERROR: failed to start drwrap\n");
    if (drsym_init(0) != DRSYM_SUCCESS)
        throw std::runtime_error("ERROR: failed to start drsym\n");

    // Register callbacks
    if (!drmgr_register_module_load_event(event_module_load))
        throw std::runtime_error("ERROR: failed to register a callback\n");
    if (!drmgr_register_bb_app2app_event(event_bb_app2app, nullptr))
        throw std::runtime_error("ERROR: failed to register a callback\n");
    if (!drmgr_register_bb_instrumentation_event(nullptr, event_bb_instrumentation, nullptr))
        throw std::runtime_error("ERROR: failed to register a callback\n");

    drmgr_register_signal_event(event_exception);
    dr_register_exit_event(event_exit);
}

/// @brief Destructor of the DR model.
///        The function unregisters callbacks and closes the DR extensions.
/// @return void
void dr_model_del() noexcept
{
    drmgr_unregister_module_load_event(event_module_load);
    drmgr_unregister_bb_app2app_event(event_bb_app2app);
    drmgr_unregister_bb_insertion_event(event_bb_instrumentation);

    drsym_exit();
    drwrap_exit();
    drx_exit();
    drutil_exit();
    drmgr_exit();
}

} // namespace dr_model

// =================================================================================================
// Model entry point
// =================================================================================================

/// @brief Entry point of the DR model.
///        The function initializes the dispatcher, registers callbacks,
///        and starts the DR extensions.
/// @param _ Unused
/// @param argc Number of CLI arguments
/// @param argv CLI arguments
/// @return void
DR_EXPORT void dr_client_main(client_id_t _, int argc, const char **argv) // NOLINT
{
    // Parse CLI arguments
    cli_args_t parsed_args = {};
    parse_cli(argc, argv, parsed_args);

    // Special cases:
    if (parsed_args.list_tracers) {
        for (const auto &tracer_name : get_tracer_list()) {
            dr_printf("%s\n", tracer_name.c_str());
        }
        return;
    }
    if (parsed_args.list_speculators) {
        for (const auto &speculator_name : get_speculator_list()) {
            dr_printf("%s\n", speculator_name.c_str());
        }
        return;
    }

    // Create a dispatcher instance
    dr_model::dispatcher = std::make_unique<Dispatcher>(&parsed_args);

    // Set the target function
    dr_model::instrumented_func_name = parsed_args.instrumented_func;

    // Initialize the DR model
    dr_model::dr_model_init();
}

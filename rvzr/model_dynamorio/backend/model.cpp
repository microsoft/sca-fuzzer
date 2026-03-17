///
/// File: DynamoRIO client entry point and instrumentation orchestrator
///
/// This file implements the main DynamoRIO client (dr_client_main) and coordinates
/// the instrumentation lifecycle. The file is responsible for detecting when to start/stop
/// instrumentation of the target function based on its name. It also registers event callbacks
/// for module loading, basic block transformation, and instruction-level instrumentation.
/// The callbacks transfer control to the Dispatcher class, which manages the rest of
/// the model's logic.
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

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
#include "include/dispatcher.hpp"
#include "util.hpp"

using std::size_t;
using std::string;

/// @brief Pointer to the dispatcher instance;
/// @note We have to use a global pointer to share state (tracer, speculator, state of the
///       instrumentation) with the callbacks. This is the reason for NOLINT as well.
std::unique_ptr<Dispatcher> glob_dispatcher = nullptr; // NOLINT

namespace dr_model
{

static void dr_model_del() noexcept;

/// @brief Struct holding information about the symbols to instrument.
struct syms_to_instrument_t {
    std::string entry_sym;
    std::vector<std::string> ignored_syms;
    bool use_inst_markers = false;
} syms_to_instrument; // NOLINT

static constexpr const char *entry_marker = "_mcfz_start_inst";
static constexpr const char *exit_marker = "_mcfz_stop_inst";

// =================================================================================================
// Memory layout tracking
// =================================================================================================
class MemoryLayout
{
  public:
    MemoryLayout(std::string mappings_file_) : mappings_file(std::move(mappings_file_))
    {
        // Ensure the file is empty at the beginning
        std::ofstream stream;
        stream.open(mappings_file, std::ios::out | std::ios::trunc);
        stream.close();
    }
    ~MemoryLayout() = default;
    MemoryLayout(const MemoryLayout &) = delete;
    MemoryLayout &operator=(const MemoryLayout &) = delete;
    MemoryLayout(MemoryLayout &&) = delete;
    MemoryLayout &operator=(MemoryLayout &&) = delete;

    /// @brief Records the mapping of a module.
    void record_module_mapping(const char *module_name, app_pc start_address)
    {
        module_mappings.emplace_back(module_name, reinterpret_cast<std::uintptr_t>(start_address));
    }

    /// @brief Store the recorded module mappings to file.
    void store_mappings() const
    {
        std::ofstream stream;
        stream.open(mappings_file, std::ios::out);
        for (const auto &mapping : module_mappings) {
            stream << mapping.first << " 0x" << std::hex << mapping.second << std::dec << "\n";
        }
        stream.close();
    }

  private:
    /// @brief Storage for module mappings when --store-mappings is enabled.
    /// @note Stores pairs of (module_name, start_address).
    std::vector<std::pair<std::string, std::uintptr_t>> module_mappings;
    /// @brief Output file path for module mappings. Empty if not enabled.
    std::string mappings_file;
};

/// @brief Global instance of MemoryLayout to manage memory layout information during tracing.
static std::unique_ptr<MemoryLayout> memory_layout = nullptr;

// =================================================================================================
// Event callbacks
// =================================================================================================

/// @brief Callback executed before loading a module.
///        This callback is responsible for detecting the presence of the function to instrument.
///        It checks if the module being loaded contains the function to instrument, and if so,
///        communicates its address to Dispatcher, so that is knows when
///        to start the instrumentation (see `event_instrumentation_start`).
/// @param unused
/// @param module_ Pointer to the module data
/// @param unused
/// @return void
static void event_module_load(void * /*drcontext*/, const module_data_t *module_, bool /*loaded*/)
{
    // Record module mapping if store-mappings is enabled
    if (memory_layout != nullptr) {
        memory_layout->record_module_mapping(module_->full_path, module_->start);
    }

    // Helper used to check if a symbol is present in the currently loaded module.
    auto find_symbol_pc = [&module_](const char *sym, size_t *offset) -> bool {
        const auto result = drsym_lookup_symbol(module_->full_path, sym, offset, DRSYM_DEMANGLE);
        return result == DRSYM_SUCCESS;
    };

    size_t offset = 0;
    if (syms_to_instrument.use_inst_markers) {
        // Check the presence of instrumentation markers
        if (find_symbol_pc(entry_marker, &offset))
            glob_dispatcher->register_entry_pc(module_->start + offset);
        if (find_symbol_pc(exit_marker, &offset))
            glob_dispatcher->register_exit_pc(module_->start + offset);
    } else {
        // Check if the module contains the function to instrument.
        const char *target_func = syms_to_instrument.entry_sym.c_str();
        if (find_symbol_pc(target_func, &offset)) {
            // dr_printf("[MODULE_LOAD] Found ENTRY %s in module %s (pc: %p)\n", target_func,
            //           module_->full_path, module_->start + offset);
            glob_dispatcher->register_entry_pc(module_->start + offset);
        }
    }

    // Check if the module contains aby of the ignored functions.
    for (const auto &sym : syms_to_instrument.ignored_syms) {
        if (find_symbol_pc(sym.c_str(), &offset)) {
            //     dr_printf("[MODULE_LOAD] Found PAUSE %s in module %s (pc: %p)\n", sym,
            //               module_->full_path, module_->start + offset);
            glob_dispatcher->register_pause_pc(module_->start + offset);
        }
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
static dr_emit_flags_t event_bb_app2app(void *drcontext, void * /*tag*/, instrlist_t *bb,
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
static dr_emit_flags_t event_bb_instrumentation(void *drcontext, void * /*tag*/, instrlist_t *bb,
                                                instr_t *instr, bool /*for_trace*/,
                                                bool /*translating*/, void * /*user_data*/)
{
    glob_dispatcher->instrument(drcontext, bb, instr);
    return DR_EMIT_DEFAULT;
}

/// @brief Callback executed upon exceptions
/// @param drcontext The drcontext of the current thread
/// @param excpt Pointer to the exception data
/// @return whether the signal should be redirected or delivered to the application
static dr_signal_action_t event_signal(void *drcontext, dr_siginfo_t *siginfo)
{
    if (glob_dispatcher->handle_exception(drcontext, siginfo)) {
        return DR_SIGNAL_REDIRECT;
    }

    // Continue with the default exception handling if no redirection happened
    return DR_SIGNAL_DELIVER;
}

/// @brief Callback executed before exiting the application.
/// @return void
static void event_exit()
{
    if (glob_dispatcher->is_instrumentation_on())
        glob_dispatcher->handle_event(dispatcher_event_t::EV_EXIT);
    // There is a possibility that the tracing process has not been finalized
    // because the traced function has not been called
    glob_dispatcher->finalize();

    // Make sure we've sent all the collected data
    fflush(stdout);

    // Write module mappings to file if enabled
    if (memory_layout != nullptr) {
        memory_layout->store_mappings();
    }

    // Delete the dispatcher
    glob_dispatcher.reset();

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
static void dr_model_init()
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

    drmgr_register_signal_event(event_signal);
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

///@brief Parse ignorelist (one symbol for each line).
static std::vector<std::string> parse_ignore_list(const std::string &filename)
{
    std::vector<std::string> lines;
    std::ifstream file(filename);

    if (!file.is_open()) {
        dr_printf("WARNING: Could not open ignore list file: %s\n", filename.c_str());
        return lines;
    }

    std::string line;
    while (std::getline(file, line)) {
        lines.push_back(line);
    }

    return lines;
}

/// @brief Entry point of the DR model.
///        The function initializes the dispatcher, registers callbacks,
///        and starts the DR extensions.
/// @param _ Unused
/// @param argc Number of CLI arguments
/// @param argv CLI arguments
/// @return void
DR_EXPORT void dr_client_main(client_id_t /* client_id */, int argc, const char **argv)
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

    // Save symbols to instrument
    dr_model::syms_to_instrument.entry_sym = parsed_args.instrumented_func;
    dr_model::syms_to_instrument.ignored_syms = parse_ignore_list(parsed_args.ignore_list_path);
    dr_model::syms_to_instrument.use_inst_markers = parsed_args.use_inst_markers;

    // Create a dispatcher instance
    glob_dispatcher = std::make_unique<Dispatcher>(&parsed_args);

    // Set up memory layout tracking if --store-mappings is enabled
    if (not parsed_args.mappings_file.empty()) {
        dr_model::memory_layout =
            std::make_unique<dr_model::MemoryLayout>(parsed_args.mappings_file);
    }

    // Initialize the DR model
    dr_model::dr_model_init();
}

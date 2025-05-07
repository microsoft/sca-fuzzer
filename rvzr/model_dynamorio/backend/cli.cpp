///
/// File: Dr. Model Command Line Interface
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <algorithm>
#include <string>

#include <dr_api.h> // NOLINT
#include <dr_defines.h>
#include <dr_tools.h>
#include <droption.h>

#include "cli.hpp"
#include "factory.hpp"

using std::string;

using dynamorio::droption::DROPTION_SCOPE_CLIENT;
using dynamorio::droption::droption_t;

static bool validate_tracer(cli_args_t *parsed_args);
static bool validate_speculator(cli_args_t *parsed_args);

static const int max_reasonable_nesting = 100;
static const int max_reasonable_spec_window = 1000;

// =================================================================================================
// List of options
// =================================================================================================
namespace
{

// General Configuration

// Tracer Configuration
const droption_t<string>
    op_tracer_name(DROPTION_SCOPE_CLIENT, "tracer", "ct",
                   "Type of the tracer; equivalent to the observation clause of a contract",
                   "Type of the tracer; equivalent to the observation clause of a contract");
const droption_t<string> op_instrumented_func(DROPTION_SCOPE_CLIENT, "instrumented-func",
                                              "__libc_start_main",
                                              "Name of the function to instrument.",
                                              "Name of the function to instrument.");
const droption_t<bool> op_debug_trace(DROPTION_SCOPE_CLIENT, "enable-debug-trace", false,
                                      "Collect detailed trace for debugging with Revizor",
                                      "Collect detailed trace for debugging with Revizor");
const droption_t<bool> op_bin_output(DROPTION_SCOPE_CLIENT, "enable-bin-output", false,
                                     "Print results in raw binary format.",
                                     "Print results in raw binary format.");

// Speculator Configuration
const droption_t<string>
    op_speculator_name(DROPTION_SCOPE_CLIENT, "speculator", "seq",
                       "Type of the speculator; equivalent to the execution clause of a contract",
                       "Type of the speculator; equivalent to the execution clause of a contract");
const droption_t<int> op_max_nesting(DROPTION_SCOPE_CLIENT, "max-nesting", 1,
                                     "Maximum number of nested speculations.",
                                     "Maximum number of nested speculations.");
const droption_t<int> op_max_spec_window(DROPTION_SCOPE_CLIENT, "max-spec-window", 250,
                                         "Maximum number of speculative instructions.",
                                         "Maximum number of speculative instructions.");

// Listing Options
const droption_t<bool> op_list_tracers(DROPTION_SCOPE_CLIENT, "list-tracers", false,
                                       "List all available tracers (aka, observation clauses).",
                                       "List all available tracers (aka, observation clauses).");
const droption_t<bool>
    op_list_speculators(DROPTION_SCOPE_CLIENT, "list-speculators", false,
                        "List all available speculators (aka execution clauses).",
                        "List all available speculators (aka execution clauses).");

} // namespace

// =================================================================================================
// CLI parser
// =================================================================================================
void parse_cli(int argc, const char **argv, DR_PARAM_OUT cli_args_t &parsed_args)
{
    // Parse the arguments using DynamoRIO's droption parser
    string err_msg;
    const bool parsed = dynamorio::droption::droption_parser_t::parse_argv(
        DROPTION_SCOPE_CLIENT, argc, argv, &err_msg, nullptr);

    // Print error message and abort if the arguments cannot be parsed
    if (not parsed) {
        dr_printf("Error parsing arguments: %s\n", err_msg.c_str());
        dr_printf(
            "Usage: %s\n",
            dynamorio::droption::droption_parser_t::usage_long(DROPTION_SCOPE_CLIENT).c_str());
        dr_abort();
    }

    // Set the parsed arguments
    parsed_args.tracer_type = op_tracer_name.get_value();
    parsed_args.instrumented_func = op_instrumented_func.get_value();
    parsed_args.enable_debug_trace = op_debug_trace.get_value();
    parsed_args.enable_bin_output = op_bin_output.get_value();
    parsed_args.speculator_type = op_speculator_name.get_value();
    parsed_args.max_nesting = op_max_nesting.get_value();
    parsed_args.max_spec_window = op_max_spec_window.get_value();
    parsed_args.list_tracers = op_list_tracers.get_value();
    parsed_args.list_speculators = op_list_speculators.get_value();

    // Check values
    if (not validate_tracer(&parsed_args)) {
        dr_abort();
    }
    if (not validate_speculator(&parsed_args)) {
        dr_abort();
    }
}

// =================================================================================================
// Validators
// =================================================================================================
bool validate_tracer(cli_args_t *parsed_args)
{
    // Check if the tracer type is supported
    auto tracer_names = get_tracer_list();
    auto match = std::find(tracer_names.begin(), tracer_names.end(), parsed_args->tracer_type);
    if (match == tracer_names.end()) {
        dr_printf("Invalid tracer type: %s\n", parsed_args->tracer_type.c_str());
        dr_printf("Available tracers: [ ");
        for (const auto &tracer : tracer_names) {
            dr_printf("%s, ", tracer.c_str());
        }
        dr_printf("]\n");
        return false;
    }

    return true;
}

bool validate_speculator(cli_args_t *parsed_args)
{
    // Check if the speculator type is supported
    auto speculator_names = get_speculator_list();
    auto match =
        std::find(speculator_names.begin(), speculator_names.end(), parsed_args->speculator_type);
    if (match == speculator_names.end()) {
        dr_printf("Invalid speculator type: %s\n", parsed_args->speculator_type.c_str());
        dr_printf("Available speculators: [ ");
        for (const auto &spec : speculator_names) {
            dr_printf("%s, ", spec.c_str());
        }
        dr_printf("]\n");
        return false;
    }

    // Check if the maximum nesting level is valid
    // - Negative or zero values have no meaning;
    // - Anything greater than 100 is unrealistic on modern hardware
    if (parsed_args->max_nesting <= 0) {
        dr_printf("Invalid maximum nesting level: %d\n", parsed_args->max_nesting);
        dr_printf("Maximum nesting level must be greater than 0.\n");
        return false;
    }
    if (parsed_args->max_nesting > max_reasonable_nesting) {
        dr_printf("Invalid maximum nesting level: %d\n", parsed_args->max_nesting);
        dr_printf("Maximum nesting level must be less than or equal to 100.\n");
        return false;
    }

    // Check if the maximum speculation window is valid
    // - Negative or zero values have no meaning;
    // - Anything greater than 1000 is unrealistic on modern hardware
    if (parsed_args->max_spec_window <= 0) {
        dr_printf("Invalid maximum speculation window: %d\n", parsed_args->max_spec_window);
        dr_printf("Maximum speculation window must be greater than 0.\n");
        return false;
    }
    if (parsed_args->max_spec_window > max_reasonable_spec_window) {
        dr_printf("Invalid maximum speculation window: %d\n", parsed_args->max_spec_window);
        dr_printf("Maximum speculation window must be less than or equal to 1000.\n");
        return false;
    }

    return true;
}

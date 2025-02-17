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

// =================================================================================================
// List of options
// =================================================================================================
namespace
{

const droption_t<string>
    op_tracer_name(DROPTION_SCOPE_CLIENT, "tracer", "ct",
                   "Type of the tracer; equivalent to the observation clause of a contract",
                   "Type of the tracer; equivalent to the observation clause of a contract");
const droption_t<string>
    op_speculator_name(DROPTION_SCOPE_CLIENT, "speculator", "seq",
                       "Type of the speculator; equivalent to the execution clause of a contract",
                       "Type of the speculator; equivalent to the execution clause of a contract");
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
const droption_t<bool>
    op_list_obs_clauses(DROPTION_SCOPE_CLIENT, "list-obs-clauses", false,
                        "List all available tracers (aka, observation clauses).",
                        "List all available tracers (aka, observation clauses).");
const droption_t<bool> op_list_exec_clauses(DROPTION_SCOPE_CLIENT, "list-exec-clauses", false,
                                            "List all available execution clauses.",
                                            "List all available execution clauses.");

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

    // Check values
    auto tracer_names = get_tracer_list();
    auto match = std::find(tracer_names.begin(), tracer_names.end(), op_tracer_name.get_value());
    if (match == tracer_names.end()) {
        dr_printf("Invalid tracer type: %s\n", op_tracer_name.get_value().c_str());
        dr_printf("Available tracers: [ ");
        for (const auto &tracer : tracer_names) {
            dr_printf("%s, ", tracer.c_str());
        }
        dr_printf("]\n");
        dr_abort();
    }

    // Set the parsed arguments
    parsed_args.tracer_type = op_tracer_name.get_value();
    parsed_args.speculator_type = op_speculator_name.get_value();
    parsed_args.instrumented_func = op_instrumented_func.get_value();
    parsed_args.enable_debug_trace = op_debug_trace.get_value();
    parsed_args.enable_bin_output = op_bin_output.get_value();
    parsed_args.list_obs_clauses = op_list_obs_clauses.get_value();
    parsed_args.list_exec_clauses = op_list_exec_clauses.get_value();
}

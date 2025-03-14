///
/// File: Header for the Command Line Interface (cli.cpp)
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include <dr_defines.h> // DR_PARAM_OUT
#include <string>

struct cli_args_t {
    std::string tracer_type;
    std::string speculator_type;
    std::string instrumented_func;
    bool enable_debug_trace;
    bool enable_bin_output;
    bool list_obs_clauses;
    bool list_exec_clauses;
};

/// @brief Parse the command line arguments
/// @param argc Standard argument count
/// @param argv Standard argument vector
/// @param parsed_args Output structure with the parsed arguments
/// @return void
/// @exception dr_abort() if the arguments cannot be parsed
void parse_cli(int argc, const char **argv, DR_PARAM_OUT cli_args_t &parsed_args);

///
/// File: Implementation of the Factory Function pattern to create instances
/// of core classes in the DR Model
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include <memory>
#include <string>
#include <vector>

#include "speculator_abc.hpp"
#include "tracer_abc.hpp"

/// @brief Create a tracer instance based on the tracer name
/// @param tracer_name The name of the tracer to create
/// @return A unique pointer to the created tracer instance
/// @throw std::invalid_argument if the tracer name is unknown
std::unique_ptr<TracerABC> create_tracer(const std::string &tracer_type, bool enable_dbg_trace,
                                         bool enable_bin_output);

/// @brief Get a list of all available tracers
/// @return A list of all available tracers
std::vector<std::string> get_tracer_list();

/// @brief Create a speculator instance based on the speculator name
/// @param speculator_name The name of the speculator to create
/// @param max_nesting_ The maximum nesting level for the speculator
/// @param max_spec_window_ The maximum size of the speculation window
/// @return A unique pointer to the created speculator instance
/// @throw std::invalid_argument if the speculator name is unknown
std::unique_ptr<SpeculatorABC> create_speculator(const std::string &speculator_type,
                                                 int max_nesting_, int max_spec_window_);

/// @brief Get a list of all available speculators
/// @return A list of all available speculators
std::vector<std::string> get_speculator_list();

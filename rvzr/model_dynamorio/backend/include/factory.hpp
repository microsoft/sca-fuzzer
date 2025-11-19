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
#include "taint_tracker.hpp"
#include "tracer_abc.hpp"
#include "types/decoder.hpp"

/// @brief Create a tracer instance based on the tracer name
/// @param tracer_name The name of the tracer to create
/// @param out_path The path of the trace output file
/// @param logger Where to log events for debugging
/// @param taint_tracker Taint tracker for input boosting
/// @param decoder Shared instruction decode cache
/// @param print Print every trace entry to STDOUT during tracing (slow)
/// @return A unique pointer to the created tracer instance
/// @throw std::invalid_argument if the tracer name is unknown
std::unique_ptr<TracerABC> create_tracer(const std::string &tracer_type,
                                         const std::string &out_path, Logger &logger,
                                         TaintTracker &taint_tracker, Decoder &decoder, bool print);

/// @brief Get a list of all available tracers
/// @return A list of all available tracers
std::vector<std::string> get_tracer_list();

/// @brief Create a speculator instance based on the speculator name
/// @param speculator_name The name of the speculator to create
/// @param max_nesting_ The maximum nesting level for the speculator
/// @param max_spec_window_ The maximum size of the speculation window
/// @param logger Where to log events for debugging
/// @param taint_tracker Taint tracker for input boosting
/// @param decoder Shared instruction decode cache
/// @param poison_value If not empty, this value will be forwarded on speculative faulty loads
/// @return A unique pointer to the created speculator instance
/// @throw std::invalid_argument if the speculator name is unknown
std::unique_ptr<SpeculatorABC> create_speculator(const std::string &speculator_type,
                                                 int max_nesting_, int max_spec_window_,
                                                 Logger &logger, TaintTracker &taint_tracker,
                                                 Decoder &decoder,
                                                 std::optional<uint64_t> poison_value);

/// @brief Get a list of all available speculators
/// @return A list of all available speculators
std::vector<std::string> get_speculator_list();

/// @brief Create the shared logger to log debug events
/// @param out_path Where the logger should log
/// @param level Verbosity level of the logger
std::unique_ptr<Logger> create_logger(const std::string &out_path, int level, bool print);

/// @brief Create the taint tracker instance
/// @param enable Whether to enable taint tracking
/// @param out_path Where to write taint tracking output
/// @param logger Where to log events for debugging
/// @param decoder Shared instruction decode cache
/// @return A unique ptr to the created taint tracker instance
std::unique_ptr<TaintTracker> create_taint_tracker(bool enable, const std::string &out_path,
                                                   Logger &logger, Decoder &decoder);

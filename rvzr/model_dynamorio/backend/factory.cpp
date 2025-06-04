///
/// File: Implementation factory functions defined in factory.hpp
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <functional>
#include <memory>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

#include "factory.hpp"
#include "speculator_abc.hpp"
#include "speculators/cond.hpp"
#include "speculators/seq.hpp"
#include "tracer_abc.hpp"
#include "tracers/ct.hpp"
#include "tracers/pc.hpp"

using std::function;
using std::string;
using std::unique_ptr;
using std::vector;

namespace
{

const std::unordered_map<
    string, function<unique_ptr<TracerABC>(const string &, bool, bool, const string &, bool)>>
    tracer_factories = {
        {
            "ct",
            [](const std::string &out_path, bool print_trace_, bool enable_dbg_trace_,
               const std::string &dbg_out_path, bool print_dbg_trace_) {
                return std::make_unique<TracerCT>(out_path, print_trace_, enable_dbg_trace_,
                                                  dbg_out_path, print_dbg_trace_);
            },
        },
        {
            "pc",
            [](const std::string &out_path, bool print_trace_, bool enable_dbg_trace_,
               const std::string &dbg_out_path, bool print_dbg_trace_) {
                return std::make_unique<TracerPC>(out_path, print_trace_, enable_dbg_trace_,
                                                  dbg_out_path, print_dbg_trace_);
            },
        }};

const std::unordered_map<string, function<unique_ptr<SpeculatorABC>(int, int)>>
    speculator_factories = {
        {
            "seq",
            [](int max_nesting_, int max_spec_window_) {
                return std::make_unique<SpeculatorSeq>(max_nesting_, max_spec_window_);
            },
        },
        {
            "cond",
            [](int max_nesting_, int max_spec_window_) {
                return std::make_unique<SpeculatorCond>(max_nesting_, max_spec_window_);
            },
        }};

} // namespace

unique_ptr<TracerABC> create_tracer(const string &tracer_type, const std::string &out_path,
                                    bool print_trace_, bool enable_dbg_trace_,
                                    const std::string &dbg_out_path, bool print_dbg_trace_)
{
    try {
        return tracer_factories.at(tracer_type)(out_path, print_trace_, enable_dbg_trace_,
                                                dbg_out_path, print_dbg_trace_);
    } catch (const std::out_of_range &e) {
        throw std::invalid_argument("Unexpected tracer type: " + tracer_type);
    }
}

vector<string> get_tracer_list()
{
    vector<string> tracer_list;
    tracer_list.reserve(tracer_factories.size());
    for (const auto &tracer : tracer_factories) {
        tracer_list.push_back(tracer.first);
    }
    return tracer_list;
}

std::unique_ptr<SpeculatorABC> create_speculator(const string &speculator_type, int max_nesting_,
                                                 int max_spec_window_)
{
    try {
        return speculator_factories.at(speculator_type)(max_nesting_, max_spec_window_);
    } catch (const std::out_of_range &e) {
        throw std::invalid_argument("Unexpected speculator type: " + speculator_type);
    }
}

vector<string> get_speculator_list()
{
    vector<string> speculator_list;
    speculator_list.reserve(speculator_factories.size());
    for (const auto &speculator : speculator_factories) {
        speculator_list.push_back(speculator.first);
    }
    return speculator_list;
}

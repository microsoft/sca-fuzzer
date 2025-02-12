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
#include "tracer_abc.hpp"
#include "tracer_ct.hpp"

using std::function;
using std::string;
using std::unique_ptr;
using std::vector;

namespace
{

const std::unordered_map<string, function<unique_ptr<TracerABC>(bool, bool)>> tracer_factories = {
    {"ct",
     [](bool enable_dbg_trace, bool enable_bin_output) {
         return std::make_unique<TracerCT>(enable_dbg_trace, enable_bin_output);
     }},
};

} // namespace

unique_ptr<TracerABC> create_tracer(const string &tracer_type, bool enable_dbg_trace,
                                    bool enable_bin_output)
{
    try {
        return tracer_factories.at(tracer_type)(enable_dbg_trace, enable_bin_output);
    } catch (const std::out_of_range &e) {
        throw std::invalid_argument("Unexpected tracer type: " + tracer_type);
    }
}

vector<string> get_tracer_list()
{
    vector<string> tracer_list;
    for (const auto &tracer : tracer_factories) {
        tracer_list.push_back(tracer.first);
    }
    return tracer_list;
}

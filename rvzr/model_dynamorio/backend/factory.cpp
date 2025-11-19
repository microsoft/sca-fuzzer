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
#include "logger.hpp"
#include "speculator_abc.hpp"
#include "speculators/cond.hpp"
#include "speculators/seq.hpp"
#include "taint_tracker.hpp"
#include "tracer_abc.hpp"
#include "tracers/ct.hpp"
#include "tracers/ind.hpp"
#include "tracers/pc.hpp"
#include "types/decoder.hpp"

using std::function;
using std::string;
using std::unique_ptr;
using std::vector;

namespace
{

const std::unordered_map<string, function<unique_ptr<TracerABC>(const string &, Logger &,
                                                                TaintTracker &, Decoder &, bool)>>
    tracer_factories = {
        {
            "ct",
            [](const string &out_path, Logger &logger, TaintTracker &taint_tracker,
               Decoder &decoder, bool print) {
                return std::make_unique<TracerCT>(out_path, logger, taint_tracker, decoder, print);
            },
        },
        {
            "pc",
            [](const string &out_path, Logger &logger, TaintTracker &taint_tracker,
               Decoder &decoder, bool print) {
                return std::make_unique<TracerPC>(out_path, logger, taint_tracker, decoder, print);
            },
        },
        {
            "ind",
            [](const string &out_path, Logger &logger, TaintTracker &taint_tracker,
               Decoder &decoder, bool print) {
                return std::make_unique<TracerInd>(out_path, logger, taint_tracker, decoder, print);
            },
        }};

const std::unordered_map<string,
                         function<unique_ptr<SpeculatorABC>(int, int, Logger &, TaintTracker &,
                                                            Decoder &, std::optional<uint64_t>)>>
    speculator_factories = {
        {
            "seq",
            [](int max_nesting_, int max_spec_window_, Logger &logger, TaintTracker &taint_tracker,
               Decoder &decoder, std::optional<uint64_t> poison_value) {
                return std::make_unique<SpeculatorSeq>(max_nesting_, max_spec_window_, logger,
                                                       taint_tracker, decoder, poison_value);
            },
        },
        {
            "cond",
            [](int max_nesting_, int max_spec_window_, Logger &logger, TaintTracker &taint_tracker,
               Decoder &decoder, std::optional<uint64_t> poison_value) {
                return std::make_unique<SpeculatorCond>(max_nesting_, max_spec_window_, logger,
                                                        taint_tracker, decoder, poison_value);
            },
        }};

} // namespace

unique_ptr<TracerABC> create_tracer(const string &tracer_type, const string &out_path,
                                    Logger &logger, TaintTracker &taint_tracker, Decoder &decoder,
                                    bool print)
{
    try {
        return tracer_factories.at(tracer_type)(out_path, logger, taint_tracker, decoder, print);
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
                                                 int max_spec_window_, Logger &logger,
                                                 TaintTracker &taint_tracker, Decoder &decoder,
                                                 std::optional<uint64_t> poison_value)
{
    try {
        return speculator_factories.at(speculator_type)(max_nesting_, max_spec_window_, logger,
                                                        taint_tracker, decoder, poison_value);
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

unique_ptr<Logger> create_logger(const string &out_path, int level, bool print)
{
    // Sanitize log level
    if (level >= Logger::log_level_t::LOG_MAX) {
        level = Logger::log_level_t::LOG_MAX - 1;
    } else if (level < 0) {
        level = 0;
    }

    return std::make_unique<Logger>(out_path, (Logger::log_level_t)level, print);
}

std::unique_ptr<TaintTracker> create_taint_tracker(bool enable, const std::string &out_path,
                                                   Logger &logger, Decoder &decoder)
{
    if (enable) {
        return std::make_unique<TaintTracker>(out_path, logger, decoder);
    }
    return std::make_unique<NoneTaintTracker>(out_path, logger, decoder);
}

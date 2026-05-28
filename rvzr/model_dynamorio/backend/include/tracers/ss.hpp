///
/// File: Header for the Silent-Store Tracer
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include <optional>

#include <dr_api.h> // NOLINT
#include <dr_defines.h>

#include "tracer_abc.hpp"

struct in_flight_store_t {
    void *address = nullptr;
    uint64_t size = 0;
    std::vector<uint64_t> value = {};

    void reset()
    {
        address = nullptr;
        value.clear();
        size = 0;
    }
};

/// @brief Silent-Store Tracer;
/// This tracer collects addresses of silent stores
/// Silent stores are defined as memory writes to a memory location that already
/// contains the same value.
class TracerSilentStore : public TracerABC
{
  public:
    TracerSilentStore(const std::string &out_path, Logger &logger, TaintTracker &taint_tracker,
                      Decoder &decoder, bool print, std::optional<uint64_t> value_to_observe)
        : TracerABC(out_path, logger, taint_tracker, decoder, print),
          value_to_observe(value_to_observe)
    {
    }
    ~TracerSilentStore() = default;
    TracerSilentStore(const TracerSilentStore &) = delete;
    TracerSilentStore &operator=(const TracerSilentStore &) = delete;
    TracerSilentStore(TracerSilentStore &&) = delete;
    TracerSilentStore &operator=(TracerSilentStore &&) = delete;

    /// @brief Check if the in-flight store was silent and, if so, record its address in the trace.
    /// @param instr The current instruction being observed -- unused
    /// @param mc The machine context of the instruction
    /// @param dc The DR context of the instruction
    /// @param spec_level The speculation level at which the instruction was observed
    /// @return void
    void observe_instruction(instr_obs_t instr, dr_mcontext_t *mc, void *dc,
                             unsigned int spec_level) override;

    /// @brief Record an in-flight store.
    /// @param type The type of the memory access (read or write)
    /// @param address The address of the memory access
    /// @param size The size of the memory access
    /// @return void
    void observe_mem_access(bool is_write, void *address, uint64_t size) override;

    /// @brief Record an architectural exception with a special marker in the trace.
    /// @param siginfo Information about the exception coming from DynamoRIO.
    void observe_exception(dr_siginfo_t *siginfo) override;

  protected:
    in_flight_store_t in_flight_store;
    std::optional<uint64_t> value_to_observe;
};

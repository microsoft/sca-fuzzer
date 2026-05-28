///
/// File: Silent-Store Tracer implementation
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <dr_api.h> // NOLINT
#include <dr_defines.h>
#include <dr_ir_macros.h>
#include <dr_ir_macros_x86.h>
#include <dr_ir_opnd.h>
#include <dr_ir_utils.h>
#include <drutil.h>

#include "dr_tools.h"
#include "tracers/ss.hpp"
#include "types/decoder.hpp"

using std::optional;

static std::vector<uint64_t> get_mem_contents(void *address, uint64_t size,
                                              optional<uint64_t> val_to_observe = std::nullopt)
{
    std::vector<uint64_t> contents;
    auto cur_address = (uint64_t)address;
    size_t remaining_size = size;

    // The store might be bigger than 64 bits (e.g. vector ops): read 64 bits at a time
    while (remaining_size > 0) {
        const uint64_t cur_size = std::min(remaining_size, sizeof(uint64_t));
        size_t r_size = 0;
        uint64_t val = 0;
        const bool success = dr_safe_read((byte *)cur_address, cur_size, (byte *)&val, &r_size);

        // If the memory access is illegal, the store is bound to fail.
        if (not success)
            return {};

        // Check against the value to observe, if specified
        if (val_to_observe.has_value() && val != val_to_observe.value())
            return {};

        contents.push_back(val);

        // Advance until all relevant memory has been saved
        cur_address += cur_size;
        remaining_size -= cur_size;
    }

    return contents;
}

void TracerSilentStore::observe_instruction(instr_obs_t instr, dr_mcontext_t *mc, void *dc,
                                            unsigned int spec_level)
{
    TracerABC::observe_instruction(instr, mc, dc, spec_level);

    if (not tracing_on) {
        return; // Nothing to do if tracing is off
    }

    // First, check if the in-flight store was redundant (i.e., memory value didn't change)
    if (in_flight_store.address != nullptr) {
        const auto cur_val = get_mem_contents(in_flight_store.address, in_flight_store.size);
        if (cur_val == in_flight_store.value) {
            record_mem_access(/*is_write=*/true, in_flight_store.address, in_flight_store.size);
        }
    }

    // Record every PC
    record_pc(instr, spec_level);
    in_flight_store.reset();
}

void TracerSilentStore::observe_mem_access(bool is_write, void *address, uint64_t size)
{
    TracerABC::observe_mem_access(is_write, address, size);

    if (not tracing_on) {
        return;
    }

    if (not is_write) {
        return;
    }

    // Get the value of the targeted memory location before the store commits
    auto contents = get_mem_contents(address, size, value_to_observe);

    // Don't record the store if we couldn't read its target memory (e.g., due to an illegal
    // access)
    if (contents.empty())
        return;

    in_flight_store.address = address;
    in_flight_store.size = size;
    in_flight_store.value = std::move(contents);
}

void TracerSilentStore::observe_exception(dr_siginfo_t *siginfo)
{
    TracerABC::observe_exception(siginfo);

    if (not tracing_on) {
        return;
    }

    // If there's an in-flight store, it will not commit, so don't record it.
    in_flight_store.reset();
}

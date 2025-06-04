///
/// File: Constant-time (CT) Tracer implementation and its variants
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <cstddef>

#include <dr_api.h> // NOLINT
#include <dr_defines.h>
#include <dr_ir_macros.h>
#include <dr_ir_macros_x86.h>
#include <dr_ir_opnd.h>
#include <dr_ir_utils.h>
#include <drutil.h>

#include "tracers/ct.hpp"
#include "util.hpp"

void TracerCT::observe_instruction(instr_obs_t instr, dr_mcontext_t *mc)
{
    TracerABC::observe_instruction(instr, mc);

    // Nothing to do if tracing is off
    if (not tracing_on) {
        return;
    }

    // Create an new entry and push it on the trace buffer
    const trace_entry_t entry = {
        .addr = instr.pc,
        .size = 0,
        .type = trace_entry_type_t::ENTRY_PC,
    };
    trace.push_back(entry);
}

void TracerCT::observe_mem_access(bool is_write, void *address, uint64_t size)
{
    TracerABC::observe_mem_access(is_write, address, size);

    // Nothing to do if tracing is off
    if (not tracing_on) {
        return;
    }

    // Create an new entry and push it on the trace buffer
    const trace_entry_t entry = {
        .addr = reinterpret_cast<uint64_t>(address),
        .size = (uint32_t)size,
        .type = (is_write) ? trace_entry_type_t::ENTRY_WRITE : trace_entry_type_t::ENTRY_READ,
    };
    trace.push_back(entry);
}

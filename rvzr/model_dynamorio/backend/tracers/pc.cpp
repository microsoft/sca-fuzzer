///
/// File: Program Counter (PC) Tracer implementation
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

#include "tracers/pc.hpp"
#include "util.hpp"

void TracerPC::observe_instruction(instr_obs_t instr, dr_mcontext_t *mc)
{
    TracerABC::observe_instruction(instr, mc);

    // Nothing to do if tracing is off
    if (not tracing_on) {
        return;
    }

    // Create an new entry and push it on the trace buffer
    const trace_entry_t entry = {
        .type = trace_entry_type_t::ENTRY_PC,
        .addr = instr.pc,
        .size = 0,
    };
    trace.push_back(entry);
}

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

void TracerCT::observe_instruction(instr_obs_t instr, dr_mcontext_t *mc, void *dc)
{
    TracerABC::observe_instruction(instr, mc, dc);

    // Nothing to do if tracing is off
    if (not tracing_on) {
        return;
    }

    record_pc(instr);
}

void TracerCT::observe_mem_access(bool is_write, void *address, uint64_t size)
{
    TracerABC::observe_mem_access(is_write, address, size);

    // Nothing to do if tracing is off
    if (not tracing_on) {
        return;
    }

    record_mem_access(is_write, address, size);
}

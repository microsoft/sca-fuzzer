///
/// File: Abstract Model TracerABC
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>

#include <dr_api.h> // NOLINT
#include <dr_defines.h>
#include <dr_events.h>
#include <dr_ir_instr.h>
#include <dr_ir_opnd.h>
#include <dr_ir_utils.h>
#include <dr_tools.h>

#include <drmgr.h>
#include <drreg.h>
#include <drvector.h>

#include "observables.hpp"
#include "tracer_abc.hpp"
#include "types/debug_trace.hpp"
#include "types/trace.hpp"

using std::string;

// =================================================================================================
// Constructors and Destructors
// =================================================================================================
TracerABC::TracerABC(const std::string &out_path, bool print_trace_, bool enable_dbg_trace_,
                     const std::string &dbg_out_path, bool print_dbg_trace_)
    : enable_dbg_trace(enable_dbg_trace_), trace(print_trace_), dbg_trace(print_dbg_trace_)
{
    // Initialize trace buffers
    trace.open(out_path);
    dbg_trace.open(dbg_out_path);
}

// =================================================================================================
// Public Methods
// =================================================================================================
void TracerABC::tracing_start(void * /*wrapctx*/, DR_PARAM_OUT void ** /*user_data*/)
{
    tracing_on = true;
    tracing_finalized = false;
}

void TracerABC::tracing_finalize(void * /*wrapctx*/, DR_PARAM_OUT void * /*user_data*/)
{
    if (tracing_finalized) {
        return;
    }

    dr_printf("Done Tracing!\n");

    // Push the end-of-trace marker and flush the remaining entries.
    trace.push_back({.type = trace_entry_type_t::ENTRY_EOT});
    trace.clear();
    // Tell the user where to find the trace
    dr_printf("Trace saved to %s\n", trace.get_filename().c_str());

    // Print the trace buffers
    if (enable_dbg_trace) {
        dbg_trace.push_back({.type = debug_trace_entry_type_t::ENTRY_EOT});
        dbg_trace.clear();
        // Tell the user where to find the debug trace
        dr_printf("Debug trace saved to %s\n", dbg_trace.get_filename().c_str());
    }

    // Reset tracing flags
    tracing_on = false;
    tracing_finalized = true;
}

void TracerABC::observe_instruction(instr_obs_t instr, dr_mcontext_t *mc)
{
    // Nothing to do if tracing is off
    if (not tracing_on) {
        return;
    }

    // In debug mode, print all registers at every instruction
    if (enable_dbg_trace) {
        dbg_trace.push_back({.type = debug_trace_entry_type_t::ENTRY_REG_DUMP,
                             .regs{
                                 .xax = mc->xax,
                                 .xbx = mc->xbx,
                                 .xcx = mc->xcx,
                                 .xdx = mc->xdx,
                                 .xsi = mc->xsi,
                                 .xdi = mc->xdi,
                                 .pc = instr.pc,
                             }});
    }

    // The rest of the functionality - if any - is implemented by subclasses
}

void TracerABC::observe_mem_access(bool is_write, void *address, uint64_t size)
{
    // Nothing to do if tracing is off
    if (not tracing_on) {
        return;
    }

    // In debug mode, record all stores and loads (and the corresponding value as well)
    if (enable_dbg_trace) {
        size_t r_size = 0;
        uint64_t val = 0;
        dr_safe_read(address, size, &val, &r_size);

        dbg_trace.push_back({.type = is_write ? debug_trace_entry_type_t::ENTRY_WRITE
                                              : debug_trace_entry_type_t::ENTRY_READ,
                             .mem{
                                 .address = (uint64_t)address,
                                 .value = val,
                                 .size = r_size,
                             }});
    }
    // The rest of the functionality - if any - is implemented by subclasses
}

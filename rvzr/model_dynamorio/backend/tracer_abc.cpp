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
#include "types/trace.hpp"

using std::string;

// =================================================================================================
// Constructors and Destructors
// =================================================================================================
TracerABC::TracerABC(const std::string &out_path, Logger &logger, bool print)
    : logger(logger), trace(print)
{
    // Initialize trace buffers
    trace.open(out_path);
}

// =================================================================================================
// Public Methods
// =================================================================================================
void TracerABC::tracing_start()
{
    tracing_on = true;
    tracing_finalized = false;
}

void TracerABC::tracing_finalize()
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
    if (logger.is_enabled()) {
        logger.log_eot();
        logger.close();
        // Tell the user where to find the debug trace
        dr_printf("Debug trace saved to %s\n", logger.get_filename().c_str());
    }

    // Reset tracing flags
    tracing_on = false;
    tracing_finalized = true;
}

void TracerABC::observe_instruction(instr_obs_t /*instr*/, dr_mcontext_t * /*mc*/, void * /*dc*/)
{
    // The rest of the functionality - if any - is implemented by subclasses
}

void TracerABC::observe_mem_access(bool /*is_write*/, void * /*address*/, uint64_t /*size*/)
{
    // The rest of the functionality - if any - is implemented by subclasses
}

void TracerABC::observe_exception(dr_siginfo_t *siginfo)
{
    if (not tracing_on) {
        return;
    }

    trace.push_back({.addr = (pc_t)siginfo->access_address,
                     .size = (uint32_t)siginfo->sig,
                     .type = trace_entry_type_t::ENTRY_EXCEPTION});
}

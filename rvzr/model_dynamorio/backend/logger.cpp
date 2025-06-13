///
/// File: Implementation for logger
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <cassert>
#include <cstdint>
#include <cstring>
#include <string>

#include <dr_api.h> // NOLINT
#include <dr_defines.h>
#include <dr_events.h>
#include <dr_ir_instr.h>
#include <dr_ir_opnd.h>
#include <dr_ir_utils.h>
#include <dr_tools.h>

#include "logger.hpp"

// =================================================================================================
// Local helper functions
// =================================================================================================

static std::pair<std::string, size_t> get_module(uint64_t pc)
{
    module_data_t *mod = dr_lookup_module((byte *)pc);
    if (mod == nullptr)
        return {"Unknown Module", 0};

    // Calculate the offset from the beginning of the module.
    auto offset = (size_t)(pc - (pc_t)mod->start);

    // Get the name of the current module.
    std::string module_name(mod->full_path);

    // If the name is too long, get only the last part.
    const size_t max_path_size = sizeof(debug_trace_entry_t::loc.module_name) - 1;
    if (module_name.size() > max_path_size)
        module_name = module_name.substr(module_name.size() - max_path_size - 1, max_path_size);

    dr_free_module_data(mod);
    return {module_name, offset};
}

/// @brief convert an integer of src_type into a smaller dst_type, saturating the value if needed.
template <typename dst_type, typename src_type>
static constexpr dst_type saturate_cast(const src_type &val)
{
    if (val > std::numeric_limits<dst_type>::max())
        return std::numeric_limits<dst_type>::max();

    return (dst_type)val;
}

// =================================================================================================
// Constructors and Destructors
// =================================================================================================

Logger::Logger(const std::string &logs_path, log_level_t log_level, bool print)
    : log_level(log_level), log(print), cur_nesting_level(0)
{
    if (is_enabled())
        log.open(logs_path);
}

Logger::~Logger() { log.clear(); }

// =================================================================================================
// Public methods
// =================================================================================================

const std::string &Logger::get_filename() const { return log.get_filename(); }

void Logger::close() { log.clear(); }

// =================================================================================================
// Logging methods
// =================================================================================================

void Logger::log_instruction(instr_obs_t instr, dr_mcontext_t *mc, unsigned int nesting_level)
{
    if (not is_enabled())
        return;

    // Set the nesting level for all the entries until the next instruction
    cur_nesting_level = saturate_cast<uint8_t>(nesting_level);
    // Log PC and registers
    log.push_back({.type = debug_trace_entry_type_t::ENTRY_REG_DUMP,
                   .nesting_level = cur_nesting_level,
                   .regs{
                       .xax = mc->xax,
                       .xbx = mc->xbx,
                       .xcx = mc->xcx,
                       .xdx = mc->xdx,
                       .xsi = mc->xsi,
                       .xdi = mc->xdi,
                       .pc = instr.pc,
                   }});
    // Log more registers
    log.push_back({.type = debug_trace_entry_type_t::ENTRY_REG_DUMP_EXTENDED,
                   .nesting_level = cur_nesting_level,
                   .regs_2{
                       .rsp = mc->rsp,
                       .rbp = mc->rbp,
                       .flags = mc->xflags,
                       .r8 = mc->r8,
                       .r9 = mc->r9,
                       .r10 = mc->r10,
                       .r11 = mc->r11,
                   }});
    // Optionally, output each instruction's module and location to aid disassembly
    if (log_level >= LOG_DISASM) {
        // Recover module name from DynamoRIO
        const auto &[module_name, offset] = get_module(instr.pc);
        assert(module_name.size() <= sizeof(debug_trace_entry_t::loc.module_name));

        debug_trace_entry_t loc_entry = {.type = debug_trace_entry_type_t::ENTRY_LOC,
                                         .nesting_level = cur_nesting_level,
                                         .loc{
                                             .offset = offset,
                                             .module_name = {'\0'},
                                         }};
        // Move the recovered module name into the corresponding member of the entry
        std::move(module_name.begin(), module_name.end(), loc_entry.loc.module_name.begin());
        log.push_back(loc_entry);
    }
}

void Logger::log_mem_access(bool is_write, void *address, uint64_t size)
{
    if (not is_enabled())
        return;

    auto cur_address = (uint64_t)address;
    uint64_t remaining_size = size;

    // Vector instructions can read/write more that 64-bits: translate these cases into multiple
    // 64-bit entries.
    while (remaining_size > 0) {
        const uint64_t cur_size = std::min(remaining_size, sizeof(uint64_t));

        // Magic value that marks failed reads in the log.
        const uint64_t marker = 0xDEADBEEFDEADBEEF;
        // Read current memory value.
        uint64_t val = marker;
        size_t r_size = marker;
        const bool success = dr_safe_read((byte *)cur_address, cur_size, &val, &r_size);

        log.push_back({.type = is_write ? debug_trace_entry_type_t::ENTRY_WRITE
                                        : debug_trace_entry_type_t::ENTRY_READ,
                       .nesting_level = cur_nesting_level,
                       .mem{
                           .address = cur_address,
                           .value = val,
                           .size = size,
                       }});

        cur_address += cur_size;
        remaining_size -= cur_size;
    }
}

void Logger::log_exception(dr_siginfo_t *siginfo)
{
    if (not is_enabled())
        return;

    log.push_back({.type = debug_trace_entry_type_t::ENTRY_EXCEPTION,
                   .nesting_level = cur_nesting_level,
                   .xcpt{
                       .signal = siginfo->sig,
                       .address = (uint64_t)siginfo->access_address,
                   }});
}

void Logger::log_checkpoint(pc_t rollback_pc, uint64_t cur_window_size, size_t cur_store_log_size)
{
    if (log_level < LOG_SPEC)
        return;

    log.push_back({.type = debug_trace_entry_type_t::ENTRY_CHECKPOINT,
                   .nesting_level = cur_nesting_level,
                   .checkpoint{
                       .rollback_pc = rollback_pc,
                       .cur_window_size = cur_window_size,
                       .cur_store_log_size = cur_store_log_size,
                   }});
}

void Logger::log_rollback(unsigned nesting, pc_t rollback_pc)
{
    if (log_level < LOG_SPEC)
        return;

    log.push_back({.type = debug_trace_entry_type_t::ENTRY_ROLLBACK,
                   .nesting_level = cur_nesting_level,
                   .rollback{
                       .nesting = nesting,
                       .rollback_pc = rollback_pc,
                   }});
}

void Logger::log_rollback_store(uint64_t addr, uint64_t val, size_t size, uint64_t nesting_level)
{
    if (log_level < LOG_SPEC)
        return;

    log.push_back({.type = debug_trace_entry_type_t::ENTRY_ROLLBACK_STORE,
                   .nesting_level = cur_nesting_level,
                   .rollback_store{
                       .addr = addr,
                       .val = val,
                       .size = size,
                       .nesting_level = nesting_level,
                   }});
}

void Logger::log_eot()
{
    if (not is_enabled())
        return;

    log.push_back({.type = debug_trace_entry_type_t::ENTRY_EOT});
}

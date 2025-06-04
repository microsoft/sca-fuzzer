///
/// File: Debug trace entries produced when debugging
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include <cstdint>
#include <ostream>

/// @brief Type of entry (single element of a trace)
enum class debug_trace_entry_type_t : uint8_t {
    ENTRY_EOT = 0, // end of trace
    ENTRY_REG_DUMP = 1,
    ENTRY_READ = 2,
    ENTRY_WRITE = 3,
};

/// @brief Pretty-printer for trace_entry_type_t
static constexpr const char *to_string(const debug_trace_entry_type_t &type)
{
    switch (type) {
    case debug_trace_entry_type_t::ENTRY_EOT:
        return "EOT";
    case debug_trace_entry_type_t::ENTRY_REG_DUMP:
        return "REG_DUMP";
    case debug_trace_entry_type_t::ENTRY_READ:
        return "READ";
    case debug_trace_entry_type_t::ENTRY_WRITE:
        return "WRITE";
    }

    return "UNKNOWN";
}

struct debug_trace_entry_t {
    // What does this entry contain
    debug_trace_entry_type_t type;
    // Unused for now
    uint8_t padding[7]; // NOLINT

    // Union of all possible entry types
    union {
        // ENTRY_REG_DUMP
        struct {
            uint64_t xax;
            uint64_t xbx;
            uint64_t xcx;
            uint64_t xdx;
            uint64_t xsi;
            uint64_t xdi;
            uint64_t pc;
        } regs;
        // ENTRY_MEM (read or write)
        struct {
            uint64_t address;
            uint64_t value;
            uint64_t size;
        } mem;
    };

    /// @param Declare a marker to identify traces of this type
    static constexpr char marker = 'D';

    /// @brief Pretty-printer for debug_trace_entry_t
    void dump(std::ostream &out) const
    {
        out << "[" << to_string(type) << "] ";

        switch (type) {
        case debug_trace_entry_type_t::ENTRY_REG_DUMP:
            out << " pc: " << std::hex << regs.pc;
            out << "  (rax: 0x" << std::hex << regs.xax;
            out << " rbx: 0x" << std::hex << regs.xbx;
            out << " rcx: 0x" << std::hex << regs.xcx;
            out << " rdx: 0x" << std::hex << regs.xdx;
            out << " rsi: 0x" << std::hex << regs.xsi;
            out << " rdi: 0x" << std::hex << regs.xdi << ")";
            break;

        case debug_trace_entry_type_t::ENTRY_READ:
        case debug_trace_entry_type_t::ENTRY_WRITE:
            out << " addr: " << std::hex << mem.address;
            out << "  val: " << std::hex << mem.value;
            out << "  (sz: " << std::dec << mem.size << ")";
            break;

        case debug_trace_entry_type_t::ENTRY_EOT:
            out << "---- END OF TRACE ----\n";
            break;
        }

        out << "\n";
    }
};

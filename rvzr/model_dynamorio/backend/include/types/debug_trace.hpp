///
/// File: Debug trace entries produced when debugging
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include <array>
#include <cstdint>
#include <ostream>

/// @brief Type of entry (single element of a trace)
enum class debug_trace_entry_type_t : uint8_t {
    ENTRY_EOT = 0, // end of trace
    ENTRY_REG_DUMP = 1,
    ENTRY_READ = 2,
    ENTRY_WRITE = 3,
    ENTRY_LOC = 4,
    ENTRY_EXCEPTION = 5,
    ENTRY_CHECKPOINT = 6,
    ENTRY_ROLLBACK = 7,
    ENTRY_ROLLBACK_STORE = 8,
    ENTRY_REG_DUMP_EXTENDED = 9,
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
    case debug_trace_entry_type_t::ENTRY_LOC:
        return "LOC";
    case debug_trace_entry_type_t::ENTRY_EXCEPTION:
        return "XCPT";
    case debug_trace_entry_type_t::ENTRY_CHECKPOINT:
        return "CHECKPOINT";
    case debug_trace_entry_type_t::ENTRY_ROLLBACK_STORE:
        return "ROLLBACK_STR";
    case debug_trace_entry_type_t::ENTRY_ROLLBACK:
        return "ROLLBACK";
    case debug_trace_entry_type_t::ENTRY_REG_DUMP_EXTENDED:
        return "REG_DUMP2";
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
        // ENTRY_REG_DUMP_EXTENDED
        struct {
            uint64_t rsp;
            uint64_t rbp;
            uint64_t flags;
            uint64_t r8;
            uint64_t r9;
            uint64_t r10;
            uint64_t r11;
        } regs_2;
        // ENTRY_MEM (read or write)
        struct {
            uint64_t address;
            uint64_t value;
            uint64_t size;
        } mem;
        // ENTRY_LOC (module name and offset, for disassembly)
        struct {
            uint64_t offset;
            std::array<char, 48> module_name; // NOLINT
        } loc;
        // ENTRY_EXCEPTION
        struct {
            int signal;
            uint64_t address;
        } xcpt;
        // ENTRY_CHECKPOINT
        struct {
            uint64_t rollback_pc;
            uint64_t cur_window_size;
            size_t cur_store_log_size;
        } checkpoint;
        // ENTRY_ROLLBACK
        struct {
            unsigned nesting;
            uint64_t rollback_pc;
        } rollback;
        // ENTRY_ROLLBACK_STORE
        struct {
            uint64_t addr;
            uint64_t val;
            size_t size;
            uint64_t nesting_level;
        } rollback_store;
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

        case debug_trace_entry_type_t::ENTRY_LOC:
            for (const char name_char : loc.module_name) {
                if (name_char == '\0')
                    break;
                out << name_char;
            }
            out << "+0x" << std::hex << loc.offset;
            break;

        case debug_trace_entry_type_t::ENTRY_READ:
        case debug_trace_entry_type_t::ENTRY_WRITE:
            out << " addr: " << std::hex << mem.address;
            out << "  val: " << std::hex << mem.value;
            out << "  (sz: " << std::dec << mem.size << ")";
            break;

        case debug_trace_entry_type_t::ENTRY_EXCEPTION:
            out << " sig: " << std::dec << xcpt.signal;
            out << "  addr: " << std::hex << xcpt.address;
            break;

        case debug_trace_entry_type_t::ENTRY_EOT:
            out << "---- END OF TRACE ----\n";
            break;
        case debug_trace_entry_type_t::ENTRY_CHECKPOINT:
            out << " rollback_pc: " << std::hex << checkpoint.rollback_pc;
            out << " (storelog_sz: " << std::dec << checkpoint.cur_store_log_size;
            out << " window_sz: " << std::dec << checkpoint.cur_window_size << ")";
            break;
        case debug_trace_entry_type_t::ENTRY_ROLLBACK:
            out << " rollback_pc: " << std::hex << rollback.rollback_pc;
            out << " (nesting: " << std::dec << rollback.nesting << ")";
            break;

        case debug_trace_entry_type_t::ENTRY_ROLLBACK_STORE:
            out << " addr: 0x" << std::hex << rollback_store.addr;
            out << " val: 0x" << std::hex << rollback_store.val;
            out << " (sz: " << std::dec << rollback_store.size;
            out << " nesting: " << std::dec << rollback_store.nesting_level << ")";
            break;
        case debug_trace_entry_type_t::ENTRY_REG_DUMP_EXTENDED:
            out << " rsp: 0x" << std::hex << regs_2.rsp;
            out << " rbp: 0x" << std::hex << regs_2.rbp;
            out << " flags: 0x" << std::hex << regs_2.flags;
            out << " r8: 0x" << std::hex << regs_2.r8;
            out << " r9: 0x" << std::hex << regs_2.r9;
            out << " r10: 0x" << std::hex << regs_2.r10;
            out << " r11: 0x" << std::hex << regs_2.r11;
            break;
        }

        out << "\n";
    }
};

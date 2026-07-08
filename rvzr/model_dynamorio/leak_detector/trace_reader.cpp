#include "trace_reader.h"

#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <optional>
#include <sys/mman.h>
#include <sys/stat.h>
#include <tuple>
#include <unistd.h>

TraceReader::TraceReader(const char *path)
{
    // Open file
    const int fd = open(path, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "File not found");
        exit(1);
    }

    // Read size
    struct stat file_stat{};
    if (fstat(fd, &file_stat) < 0) {
        fprintf(stderr, "Cannot stat file");
        exit(1);
    }
    file_size = (size_t)file_stat.st_size;
    if (file_size < MARKER_SIZE) {
        fprintf(stderr, "error: file too small: %s\n", path);
        exit(1);
    }
    num_entries = (file_size - MARKER_SIZE) / sizeof(trace_entry_t);

    // Get raw pointer to data
    raw_data = mmap(nullptr, file_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (raw_data == MAP_FAILED) {
        fprintf(stderr, "MMAP failed");
        exit(1);
    }
    close(fd);
    madvise(raw_data, file_size, MADV_SEQUENTIAL);

    // Reinterpret as array of trace entry
    entries =
        reinterpret_cast<const trace_entry_t *>(static_cast<const char *>(raw_data) + MARKER_SIZE);
}

TraceReader::~TraceReader() { munmap(raw_data, file_size); }

std::optional<TracedInst> TraceReader::next()
{
    // Groups the flat DR trace into one record per instruction. A Python (numpy) reimplementation
    // of this same grouping lives in `_Trace` in `mcfz/driller.py`; the authoritative on-disk
    // format is `../backend/include/types/trace.hpp`. Changes to that format must be mirrored in
    // both parsers.

    // Check if the cursor is out of bounds
    if (cursor >= num_entries)
        return std::nullopt;
    if (entries[cursor].type == trace_entry_type_t::ENTRY_EOT)
        return std::nullopt;
    // Check that the cursor points to an instruction
    assert(entries[cursor].type == trace_entry_type_t::ENTRY_PC);

    // Get PC
    TracedInst inst;
    inst.pc = entries[cursor].addr;
    inst.spec_level = entries[cursor].spec_level;
    inst.trace_idx = cursor;
    cursor++;

    // Gather accesses occuring before next PC, if any
    while (cursor < num_entries) {
        const auto &entry = entries[cursor];
        if (entry.type == trace_entry_type_t::ENTRY_PC or
            entry.type == trace_entry_type_t::ENTRY_EOT)
            break;

        cursor++;

        // Check that we never change speculation level mid-instruction.
        assert(entry.spec_level == inst.spec_level);

        if (entry.type == trace_entry_type_t::ENTRY_READ) {
            inst.reads.push_back({.address = entry.addr, .size = entry.size});
        } else if (entry.type == trace_entry_type_t::ENTRY_WRITE) {
            inst.writes.push_back({.address = entry.addr, .size = entry.size});
        } else {
            // Other entries are ignored
        }
    }

    return inst;
}

std::optional<TracedInst> TraceReader::skip_spec_window(uint8_t cur_level)
{
    if (cur_level == 0)
        return std::nullopt;
    if (cursor >= num_entries)
        return std::nullopt;

    while (cursor < num_entries and entries[cursor].spec_level >= cur_level)
        cursor++;

    return next();
}

std::tuple<TraceReader::pc_t, TraceReader::spec_level_t, TraceReader::trace_idx_t>
TraceReader::get_prev(trace_idx_t idx) const
{
    if (idx == 0)
        return {0, 0, 0}; // Reached start of trace

    // Go back until you find a PC entry at the same speculation level
    const uint8_t cur_level = entries[idx].spec_level;
    uint64_t prev_idx = idx;
    while (prev_idx > 0) {
        prev_idx--;
        if (entries[prev_idx].type == trace_entry_type_t::ENTRY_PC and
            entries[prev_idx].spec_level <= cur_level)
            return {entries[prev_idx].addr, entries[prev_idx].spec_level, prev_idx};
    }

    return {0, 0, 0}; // Reached start of trace
}

#pragma once

#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <iostream>
#include <optional>
#include <sys/mman.h>
#include <sys/stat.h>
#include <tuple>
#include <unistd.h>
#include <vector>

// Import the DR trace format.
// TODO: Avoid hardcoding this path
#include "../../rvzr/model_dynamorio/backend/include/types/trace.hpp"

static constexpr size_t MARKER_SIZE = 8;

/// @brief Represents a READ/WRITE entry of the trace
struct MemAccess {
    uint64_t address = 0;
    uint8_t size = 0;
};

/// @brief Bundles each instruction in the trace with its reads/writes
struct TracedInst {
    uint64_t pc = 0;
    uint8_t spec_level = 0;
    uint64_t trace_idx = 0;
    std::vector<MemAccess> reads = {};
    std::vector<MemAccess> writes = {};

    void dump() const
    {
        printf("PC: 0x%lx, SPEC_LEVEL: %d, TRACE_ID: %ld, READS: %ld, WRITES:%ld\n", pc, spec_level,
               trace_idx, reads.size(), writes.size());
    }
};

/// @brief Buffered reader for Revizor DR Traces.
class TraceReader
{
  public:
    TraceReader(const char *path);
    ~TraceReader();

    /// @brief Advance the cursor by one instruction
    std::optional<TracedInst> next();
    /// @brief Advance the cursor until the current speculation window has ended
    std::optional<TracedInst> skip_spec_window(uint8_t cur_level);

    /// @brief Get info about the previous instruction of a given instruction.
    using pc_t = uint64_t;
    using trace_idx_t = uint64_t;
    using spec_level_t = uint8_t;
    std::tuple<pc_t, spec_level_t, trace_idx_t> get_prev(trace_idx_t idx) const;

  private:
    const trace_entry_t *entries;
    uint64_t cursor = 0;

    void *raw_data;
    size_t file_size;
    size_t num_entries;
};

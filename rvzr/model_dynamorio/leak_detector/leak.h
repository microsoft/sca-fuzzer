#pragma once

#include <cstdint>
#include <cstdio>

// ===================================================================
// Output format
// ===================================================================

/// @brief Type of mismatch found
enum leak_type_t : uint8_t {
    I_LEAK = 0, ///< PC mismatch
    D_LEAK = 1, ///< Load/Store address mismatch
};

/// @brief Entry corresponding to a single trace mismatch.
struct __attribute__((packed)) leak_t {
    uint64_t pc;        ///< Offending PC
    leak_type_t type;   ///< type of leak
    uint8_t spec_level; ///< speculation level
    uint64_t ref_idx;   ///< 0-based index of the differing entry in the reference trace
    uint64_t tgt_idx;   ///< 0-based index of the differing entry in the target trace

    void dump() const
    {
        printf("PC: %lx, type: %s, spec_lvl: %d, ref_idx: %ld, tgt_idx: %ld\n", pc,
               type == leak_type_t::D_LEAK ? "D" : "I", spec_level, ref_idx, tgt_idx);
    }
};

///
/// File: Class representing the taints collected by TaintTracker class
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include <cstdint>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <vector>

/// @brief Type of trace entries that can be observed
enum class taint_entry_type_t : uint8_t {
    TAINT_ENTRY_EOT = 0, // end of trace
    TAINT_ENTRY_PC = 1,
    TAINT_ENTRY_MEM = 2,
};

/// @brief An entry of an observed taint trace
typedef struct taint_entry_t {
    taint_entry_type_t type;
    uint64_t value;
} taint_entry_t;

/// @brief Class that acts as a container for taint info collected by TaintTracker class.
///        Partially implements std::vector interface
class InputTaint
{
  public:
    InputTaint() = default;
    ~InputTaint() = default;
    InputTaint(const InputTaint &) = delete;
    InputTaint &operator=(const InputTaint &) = delete;
    InputTaint(InputTaint &&) = delete;
    InputTaint &operator=(InputTaint &&) = delete;

    // ---------------------------------------------------------------------------------------------
    // Public Methods

    /// @brief Implement std::vector::push_back
    void push_back(const taint_entry_t &entry) { entries.push_back(entry); }
    /// @brief Implement std::vector::size
    [[nodiscard]] size_t size() const { return entries.size(); }
    /// @brief Implement std::vector::empty
    [[nodiscard]] bool empty() const { return entries.empty(); }

    /// @brief Iterator access operator
    taint_entry_t operator[](size_t index) const { return entries[index]; }

    /// @brief [Non-vector method] Store input taints into a file
    /// @param file_path Path to the output file
    void store_to_file(const char *file_path)
    {
        std::ofstream stream;
        stream.open(file_path, std::ios::binary | std::ios::out);

        // Write all collected entries
        for (const auto &entry : entries) {
            stream.write(reinterpret_cast<const char *>(&entry.type), sizeof(uint8_t));
            stream.write(reinterpret_cast<const char *>(&entry.value), sizeof(uint64_t));
        }

        // Write end-of-trace marker
        auto eot = static_cast<uint8_t>(taint_entry_type_t::TAINT_ENTRY_EOT);
        auto eot_value = 0ULL;
        stream.write(reinterpret_cast<const char *>(&eot), sizeof(uint8_t));
        stream.write(reinterpret_cast<const char *>(&eot_value), sizeof(uint64_t));

        stream.close();
    };

  private:
    // ---------------------------------------------------------------------------------------------
    // Private Attributes
    std::vector<taint_entry_t> entries;
};

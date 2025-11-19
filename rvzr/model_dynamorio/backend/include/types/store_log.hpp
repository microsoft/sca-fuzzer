
///
/// File: Class representing a log of store operations performed during speculation.
///       Used to be able to undo memory writes upon rollback.
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

typedef struct {
    uint64_t addr;
    uint64_t val;
    size_t size;
    unsigned int nesting_level;
} store_log_entry_t;

/// @brief The StoreLog is a wrapper around an std::vector of store_log_entries that keeps track of
/// which entries have been committed and which entries are in-flight. This is needed since we
/// populate the store_log before actually executing the instruction, which might fail.
class StoreLog
{
  public:
    StoreLog() = default;
    ~StoreLog() = default;
    StoreLog(const StoreLog &) = delete;
    StoreLog(StoreLog &&) = delete;
    StoreLog &operator=(const StoreLog &) = delete;
    StoreLog &operator=(StoreLog &&) = delete;

    /// @brief Implement std::vector::back
    [[nodiscard]] const store_log_entry_t &back() const { return entries.back(); }
    /// @brief Implement std::vector::pop_back. This will also update the committed state.
    void pop_back()
    {
        const bool was_committed_entry = (entries.size() == last_committed);
        entries.pop_back();

        if (was_committed_entry)
            last_committed -= 1;
    }
    /// @brief Implement std::vector::push_back
    void push_back(const store_log_entry_t &entry) { entries.push_back(entry); }
    /// @brief Implement std::vector::size
    [[nodiscard]] size_t size() const { return entries.size(); }
    /// @brief Implement std::vector::empty
    [[nodiscard]] bool empty() const { return entries.empty(); }

    /// @brief The last instruction actually committed: mark all entries as committed.
    void update_committed() { last_committed = entries.size(); }
    /// @brief Check if the instruction has any in-flight entries.
    [[nodiscard]] bool has_uncommitted() const { return entries.size() > last_committed; }
    /// @brief Remove all uncommitted entries from the store_log.
    void flush_uncommitted()
    {
        while (has_uncommitted())
            pop_back();
    }

  private:
    std::vector<store_log_entry_t> entries;
    size_t last_committed = 0;
};

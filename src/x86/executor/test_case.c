/// File:
///   - Parsing of test cases
///   - Management of TC-related data structures
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "main.h"

char *test_case_main = NULL;   // global
char *measurement_code = NULL; // global
test_case_t *test_case = NULL; // global

int loaded_tc_size = 0;

size_t n_actors;
size_t n_symbols;

// =================================================================================================
// State machine for test case loading
// =================================================================================================
static bool _is_receiving_test_case = false;
static uint64_t _cursor = 0;
static size_t highest_n_actors = 0;
static size_t highest_n_symbols = 0;
static tc_symbol_entry_t *_allocated_symbol_table;
static tc_section_metadata_entry_t *_allocated_metadata;
static tc_section_t *_allocated_data;

/// Initialize the state machine
///
static int __batch_tc_parsing_start(const char *buf)
{
    int ret = 0;

    // Restart parsing
    _cursor = 0;

    // Create a new batch
    SAFE_FREE(test_case);
    test_case = CHECKED_MALLOC(sizeof(test_case_t));

    // Get the number the number of actors
    uint64_t new_n_actors = ((uint64_t *)buf)[0];
    ASSERT(new_n_actors > 0, "__batch_tc_parsing_start");
    ASSERT_MSG(new_n_actors == 1, "__batch_tc_parsing_start",
               "n_actors (%llu) > 1 (not supported)\n", new_n_actors);
    ret += 8;

    // Get the number of symbols
    uint64_t new_n_symbols = ((uint64_t *)buf)[1];
    ASSERT_MSG(new_n_symbols <= MAX_SYMBOLS, "__batch_tc_parsing_start",
               "n_symbols (%llu) > MAX_SYMBOLS (%u)\n", new_n_symbols, MAX_SYMBOLS);
    ret += 8;

    // Store object sizes
    test_case->symbol_table_size = new_n_symbols * sizeof(tc_symbol_entry_t);
    test_case->metadata_size = new_n_actors * sizeof(tc_section_metadata_entry_t);
    test_case->sections_size = new_n_actors * sizeof(tc_section_t);

    // Allocate memory for the test case
    if (new_n_symbols > highest_n_symbols || !_allocated_symbol_table)
    {
        SAFE_FREE(_allocated_symbol_table);
        // +1 to have a valid allocation for test cases without symbols
        _allocated_symbol_table = CHECKED_MALLOC(test_case->symbol_table_size + 1);
        highest_n_symbols = new_n_symbols;
    }
    if (new_n_actors > highest_n_actors || !_allocated_data)
    {
        SAFE_FREE(_allocated_metadata);
        SAFE_VFREE(_allocated_data);
        _allocated_metadata = CHECKED_MALLOC(test_case->metadata_size);
        _allocated_data = CHECKED_VMALLOC(test_case->sections_size);
        highest_n_actors = new_n_actors;
    }

    test_case->symbol_table = _allocated_symbol_table;
    test_case->metadata = _allocated_metadata;
    test_case->sections = _allocated_data;
    n_actors = new_n_actors;
    n_symbols = new_n_symbols;

    // TEMPORARY
    test_case_main = test_case->sections[0].code;

    ASSERT(ret < PAGE_SIZE, "__batch_tc_parsing_start");
    return ret;
}

/// Parse the test case sent via sysfs, according to the following format:
///
///     |-------------------------------------|
///     | n_actors (uint64_t)                 | HEADER
///     | n_symbols (uint64_t)                |
///     |-------------------------------------|
///     | tc_symbol_entry_t:                  | SYMBOL TABLE
///     |   - owner_id (uint64_t)             |
///     |   - offset (uint64_t)               |
///     |   - id (uint64_t)                   |
///     | x n_symbols                         |
///     |-------------------------------------|
///     | tc_section_metadata_entry_t:        | METADATA
///     |   - owner_id (uint64_t)             |
///     |   - size (uint64_t)                 |
///     |   - reserved (uint64_t)             |
///     | x n_actors                          |
///     |-------------------------------------|
///     | tc_section_t:                       | DATA
///     |   - code (char *)                   |
///     | x n_actors                          |
///     |-------------------------------------|
///
ssize_t parse_test_case_buffer(const char *buf, size_t count, bool *finished)
{
    ASSERT(*finished == false, "parse_test_case_buffer");

    static size_t curr_section_id = 0;
    static size_t curr_section_start = 0;
    static size_t curr_section_end = 0;
    ssize_t consumed_bytes = 0;
    ssize_t byte_id = 0;

    int symbol_table_end = TC_HEADER_SIZE + test_case->symbol_table_size;
    int metadata_end = symbol_table_end + test_case->metadata_size;

    if (!_is_receiving_test_case) // Starting a a new batch
    {
        consumed_bytes = __batch_tc_parsing_start(buf);
        if (consumed_bytes != TC_HEADER_SIZE)
        {
            PRINT_ERRS("parse_test_case_buffer", "Error parsing header\n");
            return -1;
        }

        _cursor += consumed_bytes;
        _is_receiving_test_case = true;
    }
    else if (_cursor < symbol_table_end) // Parsing symbol table
    {
        size_t st_cursor = _cursor - TC_HEADER_SIZE;
        for (; st_cursor < test_case->symbol_table_size && byte_id < count;)
        {
            ((char *)test_case->symbol_table)[st_cursor] = buf[byte_id];
            byte_id++;
            st_cursor++;
        }
        _cursor = st_cursor + TC_HEADER_SIZE;
        consumed_bytes = byte_id;
    }
    else if (_cursor < metadata_end) // Parsing metadata
    {
        size_t metadata_cursor = _cursor - symbol_table_end;
        for (; metadata_cursor < test_case->metadata_size && byte_id < count;)
        {
            ((char *)test_case->metadata)[metadata_cursor] = buf[byte_id];
            byte_id++;
            metadata_cursor++;
        }
        _cursor = metadata_cursor + symbol_table_end;
        consumed_bytes = byte_id;
    }
    else // Parsing data
    {
        if (curr_section_id == 0)
        {
            curr_section_start = metadata_end;
            curr_section_end = metadata_end + test_case->metadata[0].size;
        }
        // printk(KERN_ERR "parse_test_case_buffer: curr_section_start = %lu; curr_section_end = "
        //                 "%lu; curr_section_id = %lu\n",
        //        curr_section_start, curr_section_end, curr_section_id);

        size_t func_cursor = _cursor - curr_section_start;
        bool func_finished = false;
        for (; byte_id < count;)
        {
            test_case->sections[curr_section_id].code[func_cursor] = buf[byte_id];
            byte_id++;
            func_cursor++;
            if (func_cursor >= test_case->metadata[curr_section_id].size)
            {
                func_finished = true;
                break;
            }
        }
        _cursor = func_cursor + curr_section_start;
        consumed_bytes = byte_id;

        if (func_finished)
        {
            curr_section_id++;
            curr_section_start = curr_section_end;
            curr_section_end = curr_section_end + test_case->metadata[curr_section_id].size;
        }
    }

    printk(KERN_ERR "parse_test_case_buffer: consumed_bytes = %lu; count = %lu; _cursor = %llu, "
                    "fid: %ld, finished: %d\n",
           consumed_bytes, count, _cursor, curr_section_id, *finished);

    // Check whether we are done
    if (curr_section_id >= n_actors)
    {
        curr_section_id = 0;
        curr_section_start = 0;
        curr_section_end = 0;

        _is_receiving_test_case = false;
        *finished = true;

        ASSERT_MSG(consumed_bytes == count, "parse_test_case_buffer",
                   "consumed_bytes (%lu) != count (%lu)\n", consumed_bytes, count);
    }
    // printk(KERN_ERR "parse_test_case_buffer: consumed_bytes = %lu; count = %lu; _cursor = %llu, "
    // "fid: %ld, finished: %d\n",
    //    consumed_bytes, count, _cursor, curr_section_id, *finished);

    return consumed_bytes;
}

/// Getter for _is_receiving_test_case
///
bool tc_parsing_completed(void) { return !_is_receiving_test_case; }

// =================================================================================================
// Allocation and Initialization
// =================================================================================================
/// Constructor
///
int init_test_case_manager(void)
{
    // sanity checks
    if (sizeof(test_case_t) >= MAX_EXPANDED_SECTION_SIZE)
    {
        PRINT_ERRS(
            "test_case_store:", "sizeof(test_case_t) (%lu) >= MAX_EXPANDED_FUNCTION_SIZE (%u)\n",
            sizeof(test_case_t), MAX_EXPANDED_SECTION_SIZE);
        return -1;
    }

    // globals
    n_actors = 1;
    n_symbols = 0;

    // locals
    _is_receiving_test_case = false;
    _cursor = 0;
    _allocated_symbol_table = CHECKED_MALLOC(1);
    _allocated_metadata = CHECKED_MALLOC(sizeof(tc_section_metadata_entry_t));
    _allocated_data = CHECKED_VMALLOC(sizeof(tc_section_t));

    // Dummy test case
    test_case = CHECKED_MALLOC(sizeof(test_case_t));
    test_case->symbol_table_size = 0;
    test_case->metadata_size = sizeof(tc_section_metadata_entry_t);
    test_case->sections_size = sizeof(tc_section_t);
    test_case->symbol_table = _allocated_symbol_table;
    test_case->metadata = _allocated_metadata;
    test_case->sections = _allocated_data;

    // backwards compatibility
    test_case_main = test_case->sections[0].code;

    measurement_code = CHECKED_ZALLOC(MAX_MEASUREMENT_CODE_SIZE);
    measurement_code[0] = '\xC3'; // empty test case that just immediately returns
    set_memory_x((unsigned long)measurement_code, MAX_MEASUREMENT_CODE_SIZE / PAGE_SIZE);

    loaded_tc_size = 1;
    return 0;
}

/// Destructor
///
void free_test_case_manager(void)
{
    if (measurement_code)
    {
        set_memory_nx((unsigned long)measurement_code, MAX_MEASUREMENT_CODE_SIZE / PAGE_SIZE);
        kfree(measurement_code);
    }

    SAFE_FREE(test_case);
    SAFE_FREE(_allocated_symbol_table);
    SAFE_FREE(_allocated_metadata);
    SAFE_VFREE(_allocated_data);
}
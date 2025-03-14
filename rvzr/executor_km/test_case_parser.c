/// File:
///   - Parsing of test cases in RCBF format (see docs/devel/binary-formats.md)
///   - Management of TC-related data structures
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "test_case_parser.h"
#include "macro_expansion.h"
#include "main.h"
#include "shortcuts.h"

test_case_t *test_case = NULL;   // global
actor_metadata_t *actors = NULL; // global
size_t n_actors = 1;             // global

static size_t n_symbols;

// =================================================================================================
// State machine for test case loading
// =================================================================================================
static bool _is_receiving_test_case = false;
static uint64_t _cursor = 0;
static size_t highest_n_actors = 0;
static size_t highest_n_symbols = 0;
static actor_metadata_t *_allocated_actor_table;
static tc_symbol_entry_t *_allocated_symbol_table;
static tc_section_metadata_entry_t *_allocated_metadata;
static tc_section_t *_allocated_data;

/// @brief Initialize the state machine
/// @param buf A pointer to the buffer containing (a portion of) the test case
/// @return Error code; 0 if successful
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
    ret += 8;

    // Get the number of symbols
    uint64_t new_n_symbols = ((uint64_t *)buf)[1];
    ASSERT_MSG(new_n_symbols <= MAX_SYMBOLS, "__batch_tc_parsing_start",
               "n_symbols (%llu) > MAX_SYMBOLS (%u)\n", new_n_symbols, MAX_SYMBOLS);
    ret += 8;

    // Store object sizes
    test_case->actor_table_size = new_n_actors * sizeof(actor_metadata_t);
    test_case->symbol_table_size = new_n_symbols * sizeof(tc_symbol_entry_t);
    test_case->metadata_size = new_n_actors * sizeof(tc_section_metadata_entry_t);
    test_case->sections_size = new_n_actors * sizeof(tc_section_t);

    // Allocate memory for the test case
    if (new_n_symbols > highest_n_symbols || !_allocated_symbol_table) {
        SAFE_FREE(_allocated_symbol_table);
        // +1 to have a valid allocation if the test case is empty
        _allocated_symbol_table = CHECKED_MALLOC(test_case->symbol_table_size + 1);
        highest_n_symbols = new_n_symbols;
    }
    if (new_n_actors > highest_n_actors || !_allocated_data) {
        SAFE_FREE(_allocated_actor_table);
        SAFE_FREE(_allocated_metadata);
        SAFE_VFREE(_allocated_data);
        _allocated_actor_table = CHECKED_MALLOC(test_case->actor_table_size);
        _allocated_metadata = CHECKED_MALLOC(test_case->metadata_size);
        _allocated_data = CHECKED_VMALLOC(test_case->sections_size);
        highest_n_actors = new_n_actors;
    }

    // Reset the allocated memory
    memset(_allocated_actor_table, 0, highest_n_actors * sizeof(actor_metadata_t));
    memset(_allocated_symbol_table, 0, highest_n_symbols * sizeof(tc_symbol_entry_t));
    memset(_allocated_metadata, 0, highest_n_actors * sizeof(tc_section_metadata_entry_t));
    memset(_allocated_data, 0, highest_n_actors * sizeof(tc_section_t));

    test_case->actor_table = _allocated_actor_table;
    test_case->symbol_table = _allocated_symbol_table;
    test_case->metadata = _allocated_metadata;
    test_case->sections = _allocated_data;

    // set globals
    n_symbols = new_n_symbols;
    n_actors = new_n_actors;
    actors = test_case->actor_table;

    ASSERT(ret < PAGE_SIZE, "__batch_tc_parsing_start");
    return ret;
}

/// @brief Finalize parsing:
///        - do sanity checks
///        - set test case features
///        - type-check actor switch targets
/// @param void
/// @return Error code; 0 if successful
static int __batch_tc_parsing_end(void)
{
    // Make sure that macros in the symbol table are ordered by owner and offset;
    // the symbol table contains measurement start/end; and contains the main function at offset 0
    bool macros_ordered = true;
    bool has_start, has_end = false;
    bool has_main = false;
    tc_symbol_entry_t *prev_e = NULL;
    for (tc_symbol_entry_t *e = test_case->symbol_table; e < test_case->symbol_table + n_symbols;
         e++) {
        // check for start, end, and main
        if (e->id == MACRO_MEASUREMENT_START)
            has_start = true;
        if (e->id == MACRO_MEASUREMENT_END)
            has_end = true;
        if (e->owner == 0 && e->offset == 0)
            has_main = true;

        // check ordering
        if (prev_e && e->id != NONMACRO_FUNCTION && prev_e->id != NONMACRO_FUNCTION) {
            if (e->owner < prev_e->owner)
                macros_ordered = false;
            if (e->owner == prev_e->owner && e->offset < prev_e->offset)
                macros_ordered = false;
        }

        // check targets
        if (e->id == MACRO_SET_K2U_TARGET)
            ASSERT((actors[e->args & 0xFF].pl == PL_USER), "__batch_tc_parsing_end");
        if (e->id == MACRO_SET_U2K_TARGET)
            ASSERT((actors[e->args & 0xFF].pl == PL_KERNEL), "__batch_tc_parsing_end");
        if (e->id == MACRO_SET_H2G_TARGET)
            ASSERT((actors[e->args & 0xFF].mode == MODE_GUEST), "__batch_tc_parsing_end");
        if (e->id == MACRO_SET_G2H_TARGET)
            ASSERT((actors[e->args & 0xFF].mode == MODE_HOST), "__batch_tc_parsing_end");

        prev_e = e;
    }
    if (!macros_ordered) {
        PRINT_ERRS("__batch_tc_parsing_end", "Macros in the symbol table are not ordered\n");
        return -1;
    }
    if (!has_start || !has_end) {
        PRINT_ERRS("__batch_tc_parsing_end", "Symbol table does not contain measurement "
                                             "start/end\n");
        return -1;
    }
    if (!has_main) {
        PRINT_ERRS("__batch_tc_parsing_end", "Symbol table does not contain main function\n");
        return -1;
    }

    // Set test case features
    for (int i = 0; i < n_actors; i++) {
        if (actors[i].mode == MODE_GUEST) {
            test_case->features.includes_vm_actors = true;
            break;
        }
        if (actors[i].pl == PL_USER) {
            test_case->features.includes_user_actors = true;
            break;
        }
    }

    bool fault_handler_found = false;
    for (tc_symbol_entry_t *e = test_case->symbol_table; e < test_case->symbol_table + n_symbols;
         e++) {
        if (e->id == MACRO_FAULT_HANDLER) {
            fault_handler_found = true;
            break;
        }
    }
    test_case->features.has_explicit_fault_handler = fault_handler_found;
    return 0;
}

/// Parse the test case sent via sysfs in the RCBF format
/// (see docs/devel/binary-formats.md for details)
///
ssize_t parse_test_case_buffer(const char *buf, size_t count, bool *finished)
{
    ASSERT(*finished == false, "parse_test_case_buffer");

    static size_t curr_section_id = 0;
    static size_t curr_section_start = 0;
    static size_t curr_section_end = 0;
    ssize_t consumed_bytes = 0;
    ssize_t byte_id = 0;

    int actor_table_end = TC_HEADER_SIZE + test_case->actor_table_size;
    int symbol_table_end = actor_table_end + test_case->symbol_table_size;
    int metadata_end = symbol_table_end + test_case->metadata_size;

    if (!_is_receiving_test_case) // Starting a a new batch
    {
        consumed_bytes = __batch_tc_parsing_start(buf);
        if (consumed_bytes != TC_HEADER_SIZE) {
            PRINT_ERRS("parse_test_case_buffer", "Error parsing header\n");
            return -1;
        }

        _cursor += consumed_bytes;
        _is_receiving_test_case = true;
    } else if (_cursor < actor_table_end) // Parsing actor table
    {
        size_t at_cursor = _cursor - TC_HEADER_SIZE;
        for (; at_cursor < test_case->actor_table_size && byte_id < count;) {
            ((char *)test_case->actor_table)[at_cursor] = buf[byte_id];
            byte_id++;
            at_cursor++;
        }
        _cursor = at_cursor + TC_HEADER_SIZE;
        consumed_bytes = byte_id;
    } else if (_cursor < symbol_table_end) // Parsing symbol table
    {
        size_t st_cursor = _cursor - actor_table_end;
        for (; st_cursor < test_case->symbol_table_size && byte_id < count;) {
            ((char *)test_case->symbol_table)[st_cursor] = buf[byte_id];
            byte_id++;
            st_cursor++;
        }
        _cursor = st_cursor + actor_table_end;
        consumed_bytes = byte_id;
    } else if (_cursor < metadata_end) // Parsing metadata
    {
        size_t metadata_cursor = _cursor - symbol_table_end;
        for (; metadata_cursor < test_case->metadata_size && byte_id < count;) {
            ((char *)test_case->metadata)[metadata_cursor] = buf[byte_id];
            byte_id++;
            metadata_cursor++;
        }
        _cursor = metadata_cursor + symbol_table_end;
        consumed_bytes = byte_id;
    } else // Parsing data
    {
        if (curr_section_id == 0) {
            curr_section_start = metadata_end;
            curr_section_end = metadata_end + test_case->metadata[0].size;
        }
        // Check that the section is not too large
        if (test_case->metadata[curr_section_id].size > MAX_SECTION_SIZE) {
            PRINT_ERRS("parse_test_case_buffer", "Section size exceeds MAX_SECTION_SIZE\n");
            _is_receiving_test_case = false;
            return -1;
        }
        // printk(KERN_ERR "parse_test_case_buffer: curr_section_start = %lu; curr_section_end =
        // "
        //                 "%lu; curr_section_id = %lu\n",
        //        curr_section_start, curr_section_end, curr_section_id);

        size_t func_cursor = _cursor - curr_section_start;
        bool func_finished = false;
        for (; byte_id < count;) {
            test_case->sections[curr_section_id].code[func_cursor] = buf[byte_id];
            byte_id++;
            func_cursor++;
            if (func_cursor >= test_case->metadata[curr_section_id].size) {
                func_finished = true;
                break;
            }
        }
        _cursor = func_cursor + curr_section_start;
        consumed_bytes = byte_id;

        if (func_finished) {
            curr_section_id++;
            curr_section_start = curr_section_end;
            curr_section_end = curr_section_end + test_case->metadata[curr_section_id].size;
        }
    }

    // Check whether we are done
    if (curr_section_id >= n_actors) {
        curr_section_id = 0;
        curr_section_start = 0;
        curr_section_end = 0;

        _is_receiving_test_case = false;
        *finished = true;

        if (__batch_tc_parsing_end())
            return -1;

        ASSERT_MSG(consumed_bytes == count, "parse_test_case_buffer",
                   "consumed_bytes (%lu) != count (%lu)\n", consumed_bytes, count);
    }
    // printk(KERN_ERR "parse_test_case_buffer: consumed_bytes = %lu; count = %lu; _cursor =
    // %llu, " "fid: %ld, finished: %d\n",
    //    consumed_bytes, count, _cursor, curr_section_id, *finished);

    return consumed_bytes;
}

/// Getter for _is_receiving_test_case
///
bool tc_parsing_completed(void) { return !_is_receiving_test_case; }

// =================================================================================================
int init_test_case_parser(void)
{
    // locals
    n_symbols = 0;
    _is_receiving_test_case = false;
    _cursor = 0;
    _allocated_actor_table = CHECKED_MALLOC(sizeof(actor_metadata_t));
    _allocated_symbol_table = CHECKED_MALLOC(1);
    _allocated_metadata = CHECKED_MALLOC(sizeof(tc_section_metadata_entry_t));
    _allocated_data = CHECKED_VMALLOC(sizeof(tc_section_t));

    // Dummy test case
    test_case = CHECKED_MALLOC(sizeof(test_case_t));
    test_case->actor_table_size = sizeof(actor_metadata_t);
    test_case->symbol_table_size = 0;
    test_case->metadata_size = sizeof(tc_section_metadata_entry_t);
    test_case->sections_size = sizeof(tc_section_t);
    test_case->actor_table = _allocated_actor_table;
    test_case->symbol_table = _allocated_symbol_table;
    test_case->metadata = _allocated_metadata;
    test_case->sections = _allocated_data;

    actors = test_case->actor_table;
    return 0;
}

void free_test_case_parser(void)
{
    SAFE_FREE(test_case);
    SAFE_FREE(_allocated_actor_table);
    SAFE_FREE(_allocated_symbol_table);
    SAFE_FREE(_allocated_metadata);
    SAFE_VFREE(_allocated_data);
    actors = NULL;
}

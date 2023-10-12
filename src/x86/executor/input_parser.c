/// File:
///   - Parsing inputs
///   - Management of input-related data structures
///   - Accessors to the input data
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <linux/slab.h> // PAGE_SIZE

#include "actor_manager.h"
#include "input_parser.h"
#include "sandbox_manager.h"
#include "shortcuts.h"

input_batch_t *inputs = NULL; // global
size_t n_inputs = 0;          // global

// =================================================================================================
// State machine for input acquisition
// =================================================================================================
static bool _is_receiving_inputs = false;
static uint64_t _cursor = 0;
static size_t highest_n_actors = 0;
static size_t highest_n_inputs = 0;
static input_fragment_metadata_entry_t *_allocated_metadata;
static input_fragment_t *_allocated_data;

/// Initialize the state machine
///
static int __batch_input_parsing_start(const char *buf)
{
    int ret = 0;

    // Restart parsing
    _cursor = 0;

    // Create a new batch
    SAFE_FREE(inputs);
    inputs = CHECKED_MALLOC(sizeof(input_batch_t));

    // Get the number the number of actors
    // (here, we just check that it matches the previous value from test_case.c)
    uint64_t new_n_actors = ((uint64_t *)buf)[0];
    ASSERT_MSG(new_n_actors == n_actors, "__batch_input_parsing_start",
               "Mismatch in n_actors;"
               " Either inputs were loaded befor the test case,\n"
               "or the declared n_actors does not match "
               "(n_actors = %lu, new_n_actors = %llu)\n",
               n_actors, new_n_actors);
    ret += 8;

    // Get the number of inputs
    uint64_t new_n_inputs = ((uint64_t *)buf)[1];
    ASSERT(new_n_inputs != 0, "__batch_input_parsing_start");
    ASSERT_MSG(new_n_inputs <= MAX_INPUTS, "__batch_input_parsing_start",
               "n_inputs (%llu) > MAX_INPUTS (%u)\n", new_n_inputs, MAX_INPUTS);
    ret += 8;

    // Store object sizes
    //       Note: do not multiply by the number of inputs per actor for metadata,
    //       because we keep the same metadata for each run
    inputs->metadata_size = new_n_actors * sizeof(input_fragment_metadata_entry_t);
    inputs->data_size = new_n_actors * new_n_inputs * sizeof(input_fragment_t);

    // If the number of actors or the number of inputs has increased, we need to re-allocate
    if (new_n_actors > highest_n_actors || new_n_inputs > highest_n_inputs ||
        !_allocated_metadata || !_allocated_data) {
        SAFE_FREE(_allocated_metadata);
        SAFE_VFREE(_allocated_data);
        _allocated_metadata = CHECKED_MALLOC(inputs->metadata_size);
        _allocated_data = CHECKED_VMALLOC(inputs->data_size);
        highest_n_actors = new_n_actors;
        highest_n_inputs = new_n_inputs;
    }

    // Update globals
    inputs->metadata = _allocated_metadata;
    inputs->data = _allocated_data;
    n_inputs = new_n_inputs;
    // note: n_actors is not updated here; test_case.c is responsible for that

    ASSERT(ret < PAGE_SIZE, "__batch_input_parsing_start");
    return ret;
}

/// Parse the inputs sent via sysfs, according to the following format:
///
///     |-------------------------------------|
///     | n_actors (uint64_t)                 | HEADER
///     | n_inputs (uint64_t)                 |
///     |-------------------------------------|
///     | input_fragment_metadata_entry_t:    | METADATA
///     |   - fragment_size (uint64_t)        |
///     |   - permissions (uint64_t)          |
///     |   - reserved (uint64_t)             |
///     | x (n_actors * n_inputs)             |
///     |-------------------------------------|
///     | input:                              | DATA
///     |   input_fragment_t:                 |
///     |     - main_area (char *)            |
///     |     - faulty_area (char *)          |
///     |     - reg_init_region (char *)      |
///     |   x n_actors                        |
///     | x n_inputs                          |
///     |-------------------------------------|
///
ssize_t parse_input_buffer(const char *buf, size_t count, bool *finished)
{
    ssize_t consumed_bytes = 0;
    ssize_t byte_id = 0;

    if (!_is_receiving_inputs) // Starting a a new batch
    {
        // Consume the fixed-size part of the batch
        // We assume that this part is small enough to fit into the minimum buffer size,
        // thus it does not require multiple calls to this function
        consumed_bytes = __batch_input_parsing_start(buf);
        _cursor += consumed_bytes;
        if (consumed_bytes <= 0)
            return -1;

        _is_receiving_inputs = true;
    } else if (_cursor < BATCH_HEADER_SIZE + inputs->metadata_size) // Parsing metadata
    {
        size_t metadata_cursor = _cursor - BATCH_HEADER_SIZE;
        size_t end = inputs->metadata_size;
        for (; metadata_cursor < end && byte_id < count;) {
            ((char *)inputs->metadata)[metadata_cursor] = buf[byte_id];
            byte_id++;
            metadata_cursor++;
        }
        _cursor = metadata_cursor + BATCH_HEADER_SIZE;
        consumed_bytes = byte_id;
    } else // Parsing data
    {
        // FIXME: this implementation is not optimal performance-wise,
        // because it will copy the unused data between fragment_size and FRAGMENT_SIZE_ALIGNED
        // See Flavien's implementation for a better one.
        size_t data_cursor = _cursor - inputs->metadata_size - BATCH_HEADER_SIZE;
        size_t end = inputs->data_size;
        for (; data_cursor < end && byte_id < count;) {
            ((char *)inputs->data)[data_cursor] = buf[byte_id];
            byte_id++;
            data_cursor++;
        }
        _cursor = data_cursor + inputs->metadata_size + BATCH_HEADER_SIZE;
        consumed_bytes = byte_id;
    }

    // Check whether we are done
    size_t data_end = BATCH_HEADER_SIZE + inputs->metadata_size + inputs->data_size;
    if (_cursor >= data_end) {
        _is_receiving_inputs = false;
        *finished = true;
    }
    // printk(KERN_ERR "parse_input_buffer: consumed_bytes = %lu; count = %lu; _cursor = %llu; end =
    // "
    //                 "%lu; finished = %d\n",
    //        consumed_bytes, count, _cursor, data_end, *finished);
    return consumed_bytes;
}

// =================================================================================================
// Misc. functions
// =================================================================================================

/// @brief Get the input fragment from the dynamic array
/// @param actor_id: 0 is guest 0, 1 is guest 1, and host is last
/// @param input_id
/// @return The input fragment for input_id of actor_id
input_fragment_t *get_input_fragment(uint64_t input_id, uint64_t actor_id)
{
    ASSERT_ENULL(inputs != NULL, "get_input_fragment");
    if (actor_id >= n_actors) {
        PRINT_ERRS("get_input_fragment", "actor_id (%llu) >= n_actors (%lu)\n", actor_id, n_actors);
        return NULL;
    } else if (input_id >= n_inputs) {
        PRINT_ERRS("get_input_fragment", "input_id (%llu) >= n_inputs (%lu)\n", input_id, n_inputs);
        return NULL;
    }

    return &inputs->data[actor_id * n_inputs + input_id];
}

/// @brief Unsafe version of get_input_fragment
/// @param input_id
/// @param actor_id
/// @return
input_fragment_t *get_input_fragment_unsafe(uint64_t input_id, uint64_t actor_id)
{
    return &inputs->data[input_id * n_actors + actor_id];
}

/// Getter for _is_receiving_inputs
///
bool input_parsing_completed(void) { return !_is_receiving_inputs; }

// =================================================================================================
int init_input_parser(void)
{
    _is_receiving_inputs = false;
    _cursor = 0;
    n_inputs = 0;
    inputs = CHECKED_MALLOC(sizeof(input_batch_t));
    _allocated_data = CHECKED_VMALLOC(sizeof(input_fragment_t));
    _allocated_metadata = CHECKED_MALLOC(sizeof(input_fragment_metadata_entry_t));
    inputs->data_size = 0;
    inputs->metadata_size = 0;
    inputs->data = _allocated_data;
    inputs->metadata = _allocated_metadata;
    return 0;
}

void free_input_parser(void)
{
    SAFE_FREE(inputs);
    SAFE_FREE(_allocated_metadata);
    SAFE_VFREE(_allocated_data);
}

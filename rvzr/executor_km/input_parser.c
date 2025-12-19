/// File:
///   - Parsing inputs
///   - Management of input-related data structures
///   - Accessors to the input data
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <linux/slab.h> // PAGE_SIZE

#include "actor.h"
#include "input_parser.h"
#include "sandbox_manager.h"
#include "shortcuts.h"

input_batch_t *inputs = NULL; // global
size_t n_inputs = 0;          // global

// =================================================================================================
// State machine for input acquisition
// =================================================================================================
static bool is_receiving_inputs = false;
static uint64_t cursor = 0;
static size_t highest_n_actors = 0;
static size_t highest_n_inputs = 0;
static input_fragment_metadata_entry_t *allocated_metadata;
static input_fragment_t *allocated_data;

/// Initialize the state machine
///
static int start_batch_input_parsing(const char *buf)
{
    int ret = 0;

    // Restart parsing
    cursor = 0;

    // Create a new batch
    SAFE_FREE(inputs);
    inputs = CHECKED_MALLOC(sizeof(input_batch_t));

    // Get the number the number of actors
    // (here, we just check that it matches the previous value from test_case.c)
    uint64_t new_n_actors = ((uint64_t *)buf)[0];
    ASSERT_MSG(new_n_actors == n_actors, "start_batch_input_parsing",
               "Mismatch in n_actors;"
               " Either inputs were loaded befor the test case,\n"
               "or the declared n_actors does not match "
               "(n_actors = %lu, new_n_actors = %llu)\n",
               n_actors, new_n_actors);
    ret += 8;

    // Get the number of inputs
    uint64_t new_n_inputs = ((uint64_t *)buf)[1];
    ASSERT(new_n_inputs != 0, "start_batch_input_parsing");
    ASSERT_MSG((int)new_n_inputs <= MAX_INPUTS, "start_batch_input_parsing",
               "n_inputs (%llu) > MAX_INPUTS (%u)\n", new_n_inputs, MAX_INPUTS);
    ret += 8;

    // Store object sizes
    //       Note: do not multiply by the number of inputs per actor for metadata,
    //       because we keep the same metadata for each run
    inputs->metadata_size = new_n_actors * sizeof(input_fragment_metadata_entry_t);
    inputs->data_size = new_n_actors * new_n_inputs * sizeof(input_fragment_t);

    // If the number of actors or the number of inputs has increased, we need to re-allocate
    if (new_n_actors > highest_n_actors || new_n_inputs > highest_n_inputs || !allocated_metadata ||
        !allocated_data) {
        SAFE_FREE(allocated_metadata);
        SAFE_VFREE(allocated_data);
        allocated_metadata = CHECKED_MALLOC(inputs->metadata_size);
        allocated_data = CHECKED_VMALLOC(inputs->data_size);
        highest_n_actors = new_n_actors;
        highest_n_inputs = new_n_inputs;
    }

    // Update globals
    inputs->metadata = allocated_metadata;
    inputs->data = allocated_data;
    n_inputs = new_n_inputs;
    // note: n_actors is not updated here; test_case.c is responsible for that

    ASSERT(ret < PAGE_SIZE, "start_batch_input_parsing");
    return ret;
}

/// Parse the inputs sent via sysfs in RDBF format
/// (see docs/devel/binary-formats.md for the format description)
///
ssize_t parse_input_buffer(const char *buf, size_t count, bool *finished)
{
    ssize_t consumed_bytes = 0;
    ssize_t byte_id = 0;

    if (!is_receiving_inputs) // Starting a a new batch
    {
        // Consume the fixed-size part of the batch
        // We assume that this part is small enough to fit into the minimum buffer size,
        // thus it does not require multiple calls to this function
        consumed_bytes = start_batch_input_parsing(buf);
        cursor += consumed_bytes;
        if (consumed_bytes <= 0)
            return -1;

        is_receiving_inputs = true;
    } else if (cursor < BATCH_HEADER_SIZE + inputs->metadata_size) // Parsing metadata
    {
        size_t metadata_cursor = cursor - BATCH_HEADER_SIZE;
        size_t end = inputs->metadata_size;
        for (; metadata_cursor < end && byte_id < count;) {
            ((char *)inputs->metadata)[metadata_cursor] = buf[byte_id];
            byte_id++;
            metadata_cursor++;
        }
        cursor = metadata_cursor + BATCH_HEADER_SIZE;
        consumed_bytes = byte_id;
    } else // Parsing data
    {
        // FIXME: this implementation is not optimal performance-wise,
        // because it will copy the unused data between fragment_size and FRAGMENT_SIZE_ALIGNED
        // See Flavien's implementation for a better one.
        size_t data_cursor = cursor - inputs->metadata_size - BATCH_HEADER_SIZE;
        size_t end = inputs->data_size;
        for (; data_cursor < end && byte_id < count;) {
            ((char *)inputs->data)[data_cursor] = buf[byte_id];
            byte_id++;
            data_cursor++;
        }
        cursor = data_cursor + inputs->metadata_size + BATCH_HEADER_SIZE;
        consumed_bytes = byte_id;
    }

    // Check whether we are done
    size_t data_end = BATCH_HEADER_SIZE + inputs->metadata_size + inputs->data_size;
    if (cursor >= data_end) {
        is_receiving_inputs = false;
        *finished = true;
    }
    // printk(KERN_ERR "parse_input_buffer: consumed_bytes = %lu; count = %lu; cursor = %llu; end =
    // "
    //                 "%lu; finished = %d\n",
    //        consumed_bytes, count, cursor, data_end, *finished);
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
    }
    if (input_id >= n_inputs) {
        PRINT_ERRS("get_input_fragment", "input_id (%llu) >= n_inputs (%lu)\n", input_id, n_inputs);
        return NULL;
    }

    return &inputs->data[(actor_id * n_inputs) + input_id];
}

/// @brief Unsafe version of get_input_fragment
/// @param input_id
/// @param actor_id
/// @return
input_fragment_t *get_input_fragment_unsafe(uint64_t input_id, uint64_t actor_id)
{
    return &inputs->data[(input_id * n_actors) + actor_id];
}

/// Getter for is_receiving_inputs
///
bool input_parsing_completed(void) { return !is_receiving_inputs; }

// =================================================================================================
int init_input_parser(void)
{
    is_receiving_inputs = false;
    cursor = 0;
    n_inputs = 0;
    inputs = CHECKED_MALLOC(sizeof(input_batch_t));
    allocated_data = CHECKED_VMALLOC(sizeof(input_fragment_t));
    allocated_metadata = CHECKED_MALLOC(sizeof(input_fragment_metadata_entry_t));
    inputs->data_size = 0;
    inputs->metadata_size = 0;
    inputs->data = allocated_data;
    inputs->metadata = allocated_metadata;
    return 0;
}

void free_input_parser(void)
{
    SAFE_FREE(inputs);
    SAFE_FREE(allocated_metadata);
    SAFE_VFREE(allocated_data);
}

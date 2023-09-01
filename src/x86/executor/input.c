/// File:
///   - Parsing inputs
///   - Management of input-related data structures
///   - Accessors to the input data
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "main.h"

input_batch_t *inputs = NULL; // global
size_t n_inputs = 0;          // global

// =================================================================================================
// State machine for input acquisition
// =================================================================================================
bool _is_receiving_inputs = false;
uint64_t _cursor = 0;
input_fragment_metadata_entry_t *_allocated_metadata;
input_fragment_t *_allocated_data;

/// Initialize the state machine
///
static int __batch_parsing_start(const char *buf)
{
    int ret = 0;

    // Restart parsing
    _cursor = 0;

    // Create a new batch
    SAFE_FREE(inputs);
    inputs = CHECKED_MALLOC(sizeof(input_batch_t));

    // Get the number the number of actors
    uint64_t new_n_actors = ((uint64_t *)buf)[0];
    ret += 8;
    if (new_n_actors == 0)
    {
        PRINT_ERRS("__batch_parsing_start", "n_actors == 0\n");
        return -1;
    }
    if (new_n_actors > 1)
    {
        PRINT_ERRS("__batch_parsing_start", "n_actors (%llu) > 1 (not supported)\n", new_n_actors);
        return -1;
    }

    // Get the number of inputs
    uint64_t new_n_inputs = ((uint64_t *)buf)[1];
    ret += 8;
    if (new_n_inputs == 0)
    {
        PRINT_ERRS("__batch_parsing_start", "n_inputs == 0\n");
        return -1;
    }
    if (new_n_inputs > MAX_INPUTS)
    {
        PRINT_ERRS("__batch_parsing_start", "n_inputs (%llu) > MAX_INPUTS (%u)\n", new_n_inputs,
                   MAX_INPUTS);
        return -1;
    }

    // Store object sizes
    //       Note: do not multiply by the number of inputs per actor for metadata,
    //       because we keep the same metadata for each run
    inputs->metadata_size = new_n_actors * sizeof(input_fragment_metadata_entry_t);
    inputs->data_size = new_n_actors * new_n_inputs * sizeof(input_fragment_t);

    // If the number of actors or the number of inputs has increased, we need to re-allocate
    if (new_n_actors > n_actors || new_n_inputs > n_inputs || !_allocated_metadata ||
        !_allocated_data)
    {
        SAFE_FREE(_allocated_metadata);
        SAFE_VFREE(_allocated_data);
        _allocated_metadata = CHECKED_MALLOC(inputs->metadata_size);
        _allocated_data = CHECKED_VMALLOC(inputs->data_size);
    }

    // // Print the size of each input fragment
    // printk(KERN_INFO "inputs_store: Input fragment sizes:\n");
    // for (size_t actor_id = 0; actor_id < declared_num_actors; actor_id++) {
    //     printk(KERN_INFO "inputs_store:   Actor %llu: %llu bytes\n", actor_id,
    //     inputs->metadata[actor_id].size);
    // }

    inputs->metadata = _allocated_metadata;
    inputs->data = _allocated_data;
    n_actors = new_n_actors;
    n_inputs = new_n_inputs;

    // IMPORTANT: ret must always be less than PAGE_SIZE
    return ret;
}

/// Parse the inputs sent via sysfs, according to the following format:
//   - n_fragments: 8 bytes
//   - n_inputs: 8 bytes
//   - -- metadata -- the same size is used for each run
//   - size_of_input_fragment_g0: 8 bytes
//   - size_of_input_fragment_gN-1: 8 bytes, where N is the number of guests
//   - size_of_input_fragment_h0: 8 bytes
//   - -- data --
//   - Corresponding to the first experiment run:
//   -  input_fragment_g0_0
//   -  input_fragment_gN-1_0, where N is the number of guests
//   -  input_fragment_h0_0
//   - Corresponding to the second experiment run:
//   -  input_fragment_g0_1
//   - ..
//   - Corresponding to the last experiment run:
//   -  ..
//   -  input_fragment_gN-1_n
//   -  input_fragment_h_n, where N is the number of guests and n is n_inputs_per_actor
///
ssize_t parse_input_buffer(const char *buf, size_t count, bool *finished)
{
    ssize_t consumed_bytes = 0;

    if (!_is_receiving_inputs) // Starting a a new batch
    {
        // Consume the fixed-size part of the batch
        // We assume that this part is small enough to fit into the minimum buffer size,
        // thus it does not require multiple calls to this function
        consumed_bytes = __batch_parsing_start(buf);
        _cursor += consumed_bytes;
        if (consumed_bytes <= 0)
            return -1;

        _is_receiving_inputs = true;
    }
    else if (_cursor < inputs->metadata_size + BATCH_HEADER_SIZE) // Parsing metadata
    {
        ssize_t byte_id = 0;
        size_t metadata_cursor = _cursor - BATCH_HEADER_SIZE;
        size_t end = inputs->metadata_size;
        for (; metadata_cursor < end && byte_id < count;)
        {
            ((char *)inputs->metadata)[metadata_cursor] = buf[byte_id];
            byte_id++;
            metadata_cursor++;
        }
        _cursor = metadata_cursor + BATCH_HEADER_SIZE;
        consumed_bytes = byte_id;
    }
    else // Parsing data
    {
        // FIXME: this implementation is not optimal performance-wise,
        // because it will copy the unused data between fragment_size and FRAGMENT_SIZE_ALIGNED
        // See Flavien's implementation for a better one.
        size_t byte_id = 0;
        size_t data_cursor = _cursor - inputs->metadata_size - BATCH_HEADER_SIZE;
        size_t end = inputs->data_size;
        for (; data_cursor < end && byte_id < count;)
        {
            ((char *)inputs->data)[data_cursor] = buf[byte_id];
            byte_id++;
            data_cursor++;
        }
        _cursor = data_cursor + inputs->metadata_size + BATCH_HEADER_SIZE;
        consumed_bytes = byte_id;
    }

    // Check whether we are done
    if (_cursor >= BATCH_HEADER_SIZE + inputs->metadata_size + inputs->data_size)
    {
        _is_receiving_inputs = false;
        *finished = true;
    }
    // printk(KERN_ERR
        //    "parse_input_buffer: consumed_bytes = %lu; count = %lu; _cursor = %llu; end = %lu\n",
        //    consumed_bytes, count, _cursor,
        //    BATCH_HEADER_SIZE + inputs->metadata_size + inputs->data_size);
    return consumed_bytes;
}

// =================================================================================================
// Misc. functions
// =================================================================================================

/// @brief Get the input fragment from the dynamic array
/// @param actor_id: 0 is guest 0, 1 is guest 1, and host is last
/// @param input_id
/// @return The input fragment for input_id of actor_id
char *get_input_fragment(uint64_t input_id, uint64_t actor_id)
{
    CHECK_NONULL_RETURN_NULL(inputs, "get_input_fragment: inputs is NULL");
    if (actor_id >= n_actors)
    {
        PRINT_ERRS("get_input_fragment", "actor_id (%llu) >= n_actors (%lu)\n", actor_id, n_actors);
        return NULL;
    }
    else if (input_id >= n_inputs)
    {
        PRINT_ERRS("get_input_fragment", "input_id (%llu) >= n_inputs (%lu)\n", input_id, n_inputs);
        return NULL;
    }

    return inputs->data[actor_id * n_inputs + input_id].main_region;
}

/// @brief Unsafe version of get_input_fragment
/// @param input_id
/// @param actor_id
/// @return
char *get_input_fragment_unsafe(uint64_t input_id, uint64_t actor_id)
{
    return inputs->data[actor_id * n_inputs + input_id].main_region;
}

/// Getter for _is_receiving_inputs
///
bool input_parsing_completed(void) { return !_is_receiving_inputs; }

// =================================================================================================
// Allocation and Initialization
// =================================================================================================
/// Constructor
int init_input_manager(void)
{
    _is_receiving_inputs = false;
    _cursor = 0;
    n_inputs = 0;
    n_actors = 0;
    inputs = CHECKED_MALLOC(sizeof(input_batch_t));
    _allocated_data = CHECKED_VMALLOC(sizeof(input_fragment_t));
    _allocated_metadata = CHECKED_MALLOC(sizeof(input_fragment_metadata_entry_t));
    inputs->data_size = 0;
    inputs->metadata_size = 0;
    inputs->data = _allocated_data;
    inputs->metadata = _allocated_metadata;
    return 0;
}

/// Destructor
///
void free_input_parser(void)
{
    SAFE_FREE(inputs);
    SAFE_FREE(_allocated_metadata);
    SAFE_VFREE(_allocated_data);
}

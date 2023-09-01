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

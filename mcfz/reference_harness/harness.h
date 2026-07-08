///
/// File: harness.h
///       Public data types and entry point of the single-file reference
///       harness. The implementation lives in harness.c.
///

#ifndef HARNESS_H
#define HARNESS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// =================================================================================================
// Secrecy policy
// =================================================================================================
/// @brief Classification of each input field as public or private (secret),
///        parsed from the policy file passed via `-p`.
typedef struct {
    bool key_is_public;
    bool iv_is_public;
    bool plaintext_is_public;
} policy_t;

// =================================================================================================
// Raw input blob
// =================================================================================================
/// @brief Descriptor for a contiguous region of input bytes.
typedef struct {
    const uint8_t *data;
    size_t size;
} input_t;

// =================================================================================================
// Configuration header
// =================================================================================================
/// @brief Fixed 16-byte header at the start of every input blob.
///
/// The layout is shared with MCFuzz's boosting stage, which reads byte 2
/// (`priv_ratio`) to learn how the data section splits into private and public
/// regions. Keep this struct exactly 16 bytes with `priv_ratio` at offset 2.
typedef struct {
    uint8_t operation;         ///< byte 0:    selects the dummy operation (reserved)
    uint8_t variant;           ///< byte 1:    reserved operation variant
    uint8_t priv_ratio;        ///< byte 2:    private/public split (read by MCFuzz boosting)
    uint8_t reserved[5];       ///< bytes 3-7: reserved for future use
    uint64_t operation_config; ///< bytes 8-15: operation-specific parameters
} __attribute__((packed)) harness_config_t;

// =================================================================================================
// Entry point
// =================================================================================================
/// @brief Target entry point, and the function where MCFuzz begins tracing (see
///        `tracing_entrypoint` in the config, default `start_driver`; set it to
///        `start_harness` for this harness).
/// @param policy Data-classification policy.
/// @param data   Raw input blob.
/// @return 0 on success, non-zero on failure.
int start_harness(policy_t *policy, input_t *data);

#endif // HARNESS_H

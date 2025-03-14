/// File: Expansion of macros in the test case; used primarily by code_loader.c
///       This file contains architecture-independent code for expanding macros in the test case.
///       For concrete architecture-specific implementations of macros, see <arch>/macros.c.
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "hardware_desc.h"

#include "asm_snippets.h"
#include "fault_handler.h"
#include "macro_expansion.h"
#include "main.h"
#include "sandbox_manager.h"
#include "shortcuts.h"
#include "test_case_parser.h"

// Max sizes for sanity checks
#define MAX_MACRO_START_OFFSET 0x100
#define MAX_MACRO_LENGTH       0x800

static size_t main_prologue_size = 0;

// =================================================================================================
// Helper functions
// =================================================================================================
/// @brief Setter/getter for the module variable main_prologue_size
///        This interface is necessary because the main section does not set from offset zero,
///        and instead starts from a hardcoded prologue. To take this offset into account,
///        Code Loader passes the size of the prologue to the Macros Loader, and then
///        arch-specific macros can query this size to calculate the correct function address.
/// @param size
void set_main_prologue_size(size_t size) { main_prologue_size = size; }
size_t get_main_prologue_size(void) { return main_prologue_size; }

/// @brief Determine the macro subtype from the macro ID and current configuration
/// @param macro_id ID of the macro
/// @return Pointer to the macro descriptor
static macro_descr_t *get_macro_subtype_from_id(uint64_t macro_id)
{
    // determine macro subtype
    macro_subtype_e macro_subtype = TYPE_UNDEFINED;
    switch (macro_id) {
    case MACRO_MEASUREMENT_START:
        switch (measurement_mode) {
        case PRIME_PROBE:
            macro_subtype = TYPE_PRIME;
            break;
        case FAST_PRIME_PROBE:
            macro_subtype = TYPE_FAST_PRIME;
            break;
        case PARTIAL_PRIME_PROBE:
            macro_subtype = TYPE_PARTIAL_PRIME;
            break;
        case FAST_PARTIAL_PRIME_PROBE:
            macro_subtype = TYPE_FAST_PARTIAL_PRIME;
            break;
        case FLUSH_RELOAD:
            macro_subtype = TYPE_FLUSH;
            break;
        case EVICT_RELOAD:
            macro_subtype = TYPE_EVICT;
            break;
        case TSC:
            macro_subtype = TYPE_TSC_START;
            break;
        default:
            PRINT_ERRS("get_macro_subtype_from_id", "misconfigured measurement_mode\n");
            return NULL;
        }
        break;
    case MACRO_FAULT_HANDLER_WITH_MEASUREMENT:
        switch (measurement_mode) {
        case PRIME_PROBE:
        case FAST_PRIME_PROBE:
        case PARTIAL_PRIME_PROBE:
        case FAST_PARTIAL_PRIME_PROBE:
            macro_subtype = TYPE_FAULT_AND_PROBE;
            break;
        case FLUSH_RELOAD:
        case EVICT_RELOAD:
            macro_subtype = TYPE_FAULT_AND_RELOAD;
            break;
        case TSC:
            macro_subtype = TYPE_FAULT_AND_TSC_END;
            break;
        default:
            PRINT_ERRS("get_macro_subtype_from_id", "misconfigured measurement_mode\n");
            return NULL;
        }
        break;
    case MACRO_MEASUREMENT_END:
        switch (measurement_mode) {
        case PRIME_PROBE:
        case FAST_PRIME_PROBE:
        case PARTIAL_PRIME_PROBE:
        case FAST_PARTIAL_PRIME_PROBE:
            macro_subtype = TYPE_PROBE;
            break;
        case FLUSH_RELOAD:
        case EVICT_RELOAD:
            macro_subtype = TYPE_RELOAD;
            break;
        case TSC:
            macro_subtype = TYPE_TSC_END;
            break;
        default:
            PRINT_ERRS("get_macro_subtype_from_id", "misconfigured measurement_mode\n");
            return NULL;
        }
        break;
    case MACRO_SWITCH_K2U:
        macro_subtype = TYPE_SWITCH_K2U;
        break;
    case MACRO_SWITCH_U2K:
        macro_subtype = TYPE_SWITCH_U2K;
        break;
    case MACRO_SWITCH_H2G:
        macro_subtype = TYPE_SWITCH_H2G;
        break;
    case MACRO_SWITCH_G2H:
        macro_subtype = TYPE_SWITCH_G2H;
        break;
    case MACRO_SET_H2G_TARGET:
        macro_subtype = TYPE_SET_H2G_TARGET;
        break;
    case MACRO_SET_G2H_TARGET:
        macro_subtype = TYPE_SET_G2H_TARGET;
        break;
    case MACRO_FAULT_HANDLER:
        macro_subtype = TYPE_FAULT_HANDLER;
        break;
    case MACRO_SWITCH:
        macro_subtype = TYPE_SWITCH;
        break;
    case MACRO_SET_K2U_TARGET:
        macro_subtype = TYPE_SET_K2U_TARGET;
        break;
    case MACRO_SET_U2K_TARGET:
        macro_subtype = TYPE_SET_U2K_TARGET;
        break;
    case MACRO_LANDING_K2U:
        macro_subtype = TYPE_LANDING_K2U;
        break;
    case MACRO_LANDING_U2K:
        macro_subtype = TYPE_LANDING_U2K;
        break;
    case MACRO_LANDING_H2G:
        macro_subtype = TYPE_LANDING_H2G;
        break;
    case MACRO_LANDING_G2H:
        macro_subtype = TYPE_LANDING_G2H;
        break;
    case MACRO_SET_DATA_PERMISSIONS:
        macro_subtype = TYPE_SET_DATA_PERMISSIONS;
        break;
    default:
        PRINT_ERRS("get_macro_subtype_from_id", "macro_id %llu is not valid\n", macro_id);
        return NULL;
    }

    macro_descr_t *descr = &macro_descriptors[macro_subtype];
    if (descr->start == NULL && descr->body == NULL) {
        PRINT_ERRS("get_macro_subtype_from_id", "macro_id %llu is not implemented\n", macro_id);
        return NULL;
    }
    return descr;
}

/// @brief Check if the given pointer points to a token marking the start of a macro
/// @param ptr
/// @return True if the pointer points to the start of a macro, false otherwise
static inline bool is_macro_start(uint8_t *ptr)
{
    return (ptr)[7] == ((MACRO_START >> 56) & 0xFF) && (ptr)[6] == ((MACRO_START >> 48) & 0xFF) &&
           (ptr)[5] == ((MACRO_START >> 40) & 0xFF) && (ptr)[4] == ((MACRO_START >> 32) & 0xFF) &&
           (ptr)[3] == ((MACRO_START >> 24) & 0xFF) && (ptr)[2] == ((MACRO_START >> 16) & 0xFF) &&
           (ptr)[1] == ((MACRO_START >> 8) & 0xFF) && (ptr)[0] == ((MACRO_START) & 0xFF);
}

/// @brief Check if the given pointer points to a token marking the end of a macro
/// @param ptr
/// @return True if the pointer points to the end of a macro, false otherwise
static inline bool is_macro_end(uint8_t *ptr)
{
    return (ptr)[7] == ((MACRO_END >> 56) & 0xFF) && (ptr)[6] == ((MACRO_END >> 48) & 0xFF) &&
           (ptr)[5] == ((MACRO_END >> 40) & 0xFF) && (ptr)[4] == ((MACRO_END >> 32) & 0xFF) &&
           (ptr)[3] == ((MACRO_END >> 24) & 0xFF) && (ptr)[2] == ((MACRO_END >> 16) & 0xFF) &&
           (ptr)[1] == ((MACRO_END >> 8) & 0xFF) && (ptr)[0] == ((MACRO_END) & 0xFF);
}

/// @brief Replace the NOP at the given location with a relative jump to the expanded macro
///        and add a fence after the jump to prevent straight-line speculation
/// @param dest Destination buffer
/// @param target Target address for the jump
/// @return Size of the added code, in bytes
static inline uint64_t insert_relative_jmp_n_fence(uint8_t *dest, int32_t target)
{
    uint64_t cursor = 0;

#if defined(ARCH_X86_64)
    const int jmp_opcode_size = 5;
    target -= jmp_opcode_size;

    // jmp *target
    dest[cursor++] = 0xe9; // start of the jump opcode
    *((uint32_t *)&dest[cursor]) = target;
    cursor += 4;

    // lfence
    dest[cursor++] = 0x0f;
    dest[cursor++] = 0xae;
    dest[cursor++] = 0xe8;
#elif defined(ARCH_ARM)
    // offsets in ARM are in dwords
    target = target / 4;

    // the target for a jump is a 26-bit signed offset from the current PC
    int target_sign = target < 0 ? 1 : 0;
    ASSERT(target < 0x02000000 && target >= -0x02000000, "insert_relative_jmp_n_fence");
    target = (target & 0x3FFFFFF) | (target_sign << 25);

    // b *target
    *((uint32_t *)&dest[cursor]) = 0x14000000; // start of the jump opcode
    *((uint32_t *)&dest[cursor]) |= target;
    cursor += 4;

    // isb
    *((uint32_t *)&dest[cursor]) = 0xd5033fdf;
    cursor += 4;

    // dsb SY
    *((uint32_t *)&dest[cursor]) = 0xd5033f9f;
    cursor += 4;

#endif

    return cursor;
}

// =================================================================================================
// Macro expansion logic
// =================================================================================================

/// @brief Dynamically generate the configurable part of the macro
/// @param[in] descr Pointer to the macro descriptor
/// @param[in] args Compressed representation of the macro arguments, as received from the test case
///            symbol table
/// @param[in] owner ID of the actor owning the macro
/// @param[out] dest Pointer to the destination buffer
/// @return Size of the added code, in bytes
static uint64_t inject_macro_configurable_part(macro_descr_t *descr, uint64_t args, uint64_t owner,
                                               uint8_t *dest)
{
    // Extract the macro arguments
    macro_args_t args_struct = {
        .arg1 = (args >> 0x00) & 0xFFFF,
        .arg2 = (args >> 0x10) & 0xFFFF,
        .arg3 = (args >> 0x20) & 0xFFFF,
        .arg4 = (args >> 0x30) & 0xFFFF,
        .owner = owner,
    };

    // Generate the macro start code
    size_t cursor = descr->start(args_struct, dest);
    return cursor;
}

/// @brief Inject the static part of the macro into destination
/// @param[in] descr Pointer to the macro descriptor
/// @param[out] dest Pointer to the destination buffer
/// @return Size of the added code, in bytes
static uint64_t inject_macro_static_part(macro_descr_t *descr, uint8_t *dest)
{
    // Get pointers to the start and the end of the static part of the macro
    uint8_t *macro_wrapper_start = (uint8_t *)descr->body;
    uint8_t *macro_start = macro_wrapper_start;
    while (!is_macro_start(macro_start)) {
        macro_start++;
        ASSERT(macro_start - macro_wrapper_start < MAX_MACRO_START_OFFSET, "get_macro_ptr");
    }
    macro_start += MACRO_START_TOKEN_LENGTH;

    uint8_t *macro_end = macro_start;
    while (!is_macro_end(macro_end)) {
        macro_end++;
        ASSERT(macro_end - macro_start < MAX_MACRO_LENGTH, "get_macro_ptr");
    }
    if (macro_end - macro_start == 0)
        return 0;

    // Copy the static part of the macro
    size_t size = macro_end - macro_start;
    memcpy(dest, macro_start, size);
    return size;
}

/// @brief Expand a macro into the destination buffer (macro_dest) and replace the nop at
///        jmp_location with a relative jump to the expanded macro
/// @param macro Macro to expand
/// @param[in] dest Destination address for placing the JMP instruction
/// @param[in] macro_dest Destination buffer for the expanded macro
/// @param[out] macro_size Size of the expanded macro
/// @return 0 on success, -1 on failure
int expand_macro(tc_symbol_entry_t *macro, uint8_t *code_dest, uint8_t *macro_dest,
                 size_t *macro_size)
{
    uint64_t code_cursor = 0;
    uint64_t macro_cursor = 0;

    // Get the macro type
    symbol_id_t type_id = macro->id;
    ASSERT(type_id != 0, "expand_macro");

    // Get the macro descriptor
    macro_descr_t *descr = get_macro_subtype_from_id(type_id);
    ASSERT(descr != NULL, "expand_macro");

    // Code area: Replace the NOP with a relative jump to the expanded macro + fence
    int32_t target = (int32_t)(&macro_dest[macro_cursor] - code_dest);
    code_cursor += insert_relative_jmp_n_fence(&code_dest[code_cursor], target);

    // Macro area: Inject the configurable part of the macro
    if (descr->start != NULL) {
        macro_cursor += inject_macro_configurable_part(descr, macro->args, macro->owner,
                                                       &macro_dest[macro_cursor]);
    }
    ASSERT(macro_cursor >= 0, "expand_macro");

    // Macro area: Inject the static part of the macro
    if (descr->body != NULL) {
        macro_cursor += inject_macro_static_part(descr, &macro_dest[macro_cursor]);
    }
    ASSERT(macro_cursor >= 0, "expand_macro");

    // Macro area: Insert a relative jump backwards
    target = (int32_t)(&code_dest[code_cursor] - &macro_dest[macro_cursor]);
    macro_cursor += insert_relative_jmp_n_fence(&macro_dest[macro_cursor], target);

    *macro_size = macro_cursor;
    return 0;
}

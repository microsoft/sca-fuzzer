/// File: Management of test case macros
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "asm_snippets.h"
#include "fault_handler.h"
#include "macro_expansion.h"
#include "main.h"
#include "sandbox_manager.h"
#include "shortcuts.h"

// =================================================================================================
// Convenience shortcuts for writing constants to memory
// =================================================================================================
#define APPEND_U8_TO_DEST(value) dest[cursor++] = value;

#define APPEND_U16_TO_DEST(value)                                                                  \
    {                                                                                              \
        *((uint16_t *)(dest + cursor)) = value;                                                    \
        cursor += 2;                                                                               \
    }

#define APPEND_U32_TO_DEST(value)                                                                  \
    {                                                                                              \
        *((uint32_t *)(dest + cursor)) = value;                                                    \
        cursor += 4;                                                                               \
    }

#define APPEND_U64_TO_DEST(value)                                                                  \
    {                                                                                              \
        *((uint64_t *)(dest + cursor)) = value;                                                    \
        cursor += 8;                                                                               \
    }

#define APPEND_BYTES_TO_DEST(...)                                                                  \
    {                                                                                              \
        static const uint8_t bytes[] = {__VA_ARGS__};                                              \
        for (size_t i = 0; i < sizeof(bytes); i++) {                                               \
            dest[cursor++] = bytes[i];                                                             \
        }                                                                                          \
    }

// =================================================================================================
// Instruction opcodes
// =================================================================================================
static inline uint32_t movz(uint8_t rd, uint16_t imm16, uint8_t shift)
{
    uint32_t opcode = 0xd2800000;
    opcode |= rd;                    // set destination register
    opcode |= (imm16 & 0xffff) << 5; // set immediate
    opcode |= shift << 21;           // set shift
    return opcode;
}

static inline uint32_t movk(uint8_t rd, uint16_t imm16, uint8_t shift)
{
    uint32_t opcode = 0xf2800000;
    opcode |= rd;                    // set destination register
    opcode |= (imm16 & 0xffff) << 5; // set immediate
    opcode |= shift << 21;           // set shift
    return opcode;
}

static inline uint32_t mov_to_sp(uint8_t rd) { return 0x9100001f | (rd << 5); }

static inline uint32_t b_imm(uint32_t offset)
{
    // offsets in ARM are in dwords
    offset = offset / 4;

    // the target for a jump is a 26-bit signed offset from the current PC
    int sign = offset < 0 ? 1 : 0;
    offset = (offset & 0x3FFFFFF) | (sign << 25);

    return 0x14000000 | offset;
}

// =================================================================================================
// Helper functions
// =================================================================================================
/// @brief Get the address of a function within a section
/// @param section_id ID of the section
/// @param function_id ID of the function
/// @return Virtual address of the function
static uint64_t get_function_addr(int section_id, int function_id)
{
    uint64_t section_base = 0;
    section_base = (uint64_t)sandbox->code[section_id].section;

    // The code section of the main actor begins after a hardcoded prologue,
    // which we need to take into account when calculating the function address
    if (section_id == 0)
        section_base += get_main_prologue_size();

    return section_base + test_case->symbol_table[function_id].offset;
}

/// @brief Insert a sequence of instructions into dest that updates x30 (memory base register)
///        to point to the base address of the memory owned by actor with `section_id`
/// @param section_id ID of the section
/// @param dest Pointer to the destination of the code sequence
/// @param cursor Current position in the destination buffer
/// @return Number of bytes written to the destination buffer
static uint64_t update_memory_base_reg(int section_id, uint8_t *dest, uint64_t cursor)
{
    int old_cursor = cursor;

    // calculate the new x30 value
    uint64_t new_val = 0;
    new_val = (uint64_t)sandbox->data[section_id].main_area;
    uint8_t rd = MEMORY_BASE_REGISTER_ID;

    uint32_t opcode = movz(rd, new_val & 0xffff, 0);
    APPEND_U32_TO_DEST(opcode);

    opcode = movk(rd, new_val >> 16 & 0xffff, 1);
    APPEND_U32_TO_DEST(opcode);

    opcode = movk(rd, new_val >> 32 & 0xffff, 2);
    APPEND_U32_TO_DEST(opcode);

    opcode = movk(rd, new_val >> 48 & 0xffff, 3);
    APPEND_U32_TO_DEST(opcode);

    return cursor - old_cursor;
}

/// @brief Insert a sequence of instructions into dest that updates x30 and sp to match
///        the actor owning section_id
/// @param section_id ID of the section
/// @param dest Pointer to the destination of the code sequence
/// @param cursor Current position in the destination buffer
/// @return Number of bytes written to the destination buffer
static uint64_t update_mem_base_and_sp(int section_id, uint8_t *dest, uint64_t cursor)
{
    int old_cursor = cursor;
    cursor += update_memory_base_reg(section_id, dest, cursor);

    // calculate the new sp value
    uint64_t new_sp = 0;
    new_sp = (uint64_t)sandbox->data[section_id].main_area + LOCAL_RSP_OFFSET;

    uint32_t opcode = movz(TMP_REG1_ID, new_sp & 0xffff, 0);
    APPEND_U32_TO_DEST(opcode);

    opcode = movk(TMP_REG1_ID, new_sp >> 16 & 0xffff, 1);
    APPEND_U32_TO_DEST(opcode);

    opcode = movk(TMP_REG1_ID, new_sp >> 32 & 0xffff, 2);
    APPEND_U32_TO_DEST(opcode);

    opcode = movk(TMP_REG1_ID, new_sp >> 48 & 0xffff, 3);
    APPEND_U32_TO_DEST(opcode);

    // ASM: mov sp, SCRATCH_REG
    opcode = mov_to_sp(TMP_REG1_ID);
    APPEND_U32_TO_DEST(opcode);

    return cursor - old_cursor;
}

/// @brief Insert a sequence of instructions into dest that updates x29 (util base register)
///        to point to the base address of the util region
/// @param section_id ID of the section
/// @param dest Pointer to the destination of the code sequence
/// @param cursor Current position in the destination buffer
/// @return Number of bytes written to the destination buffer
static uint64_t update_util_base_reg(int section_id, uint8_t *dest, uint64_t cursor)
{
    int old_cursor = cursor;

    // calculate the new x29 value
    uint64_t new_val = 0;
    new_val = (uint64_t)sandbox->util;
    uint8_t rd = UTIL_BASE_REGISTER_ID;

    uint32_t opcode = movz(rd, new_val & 0xffff, 0);
    APPEND_U32_TO_DEST(opcode);

    opcode = movk(rd, new_val >> 16 & 0xffff, 1);
    APPEND_U32_TO_DEST(opcode);

    opcode = movk(rd, new_val >> 32 & 0xffff, 2);
    APPEND_U32_TO_DEST(opcode);

    opcode = movk(rd, new_val >> 48 & 0xffff, 3);
    APPEND_U32_TO_DEST(opcode);

    return cursor - old_cursor;
}

// =================================================================================================
// Macro implementations
//
// Note: A macro consists of two parts: it starts with the dynamically-generated part,
// and the main body is static.
// The dynamic part is generated by the start_macro* functions, and the generated code
// can be configured according to the macro arguments.
// The body_macro* functions are not configurable, and are copied directly into the test case
// macro memory.
// =================================================================================================

// MEASUREMENT_START and MEASUREMENT_END -----------------------------------------------------------
// Prime+Probe variants
static void __attribute__((noipa)) body_macro_prime(void)
{
    asm volatile(".quad " xstr(MACRO_START));
    asm volatile(""                                                               //
                 "mrs " TMP_REG6 ", nzcv \n"                                      //
                 "mov " TMP_REG1 ", " UTIL_BASE_REGISTER "\n"                     //
                 "add " TMP_REG1 ", " TMP_REG1 ", " xstr(L1D_PRIMING_OFFSET) "\n" //
                 PRIME(TMP_REG1, TMP_REG2, TMP_REG3, TMP_REG4, TMP_REG5, "8")     //
                 READ_PFC_START()                                                 //
                 SET_SR_STARTED()                                                 //
                 "msr nzcv, " TMP_REG6 "\n"                                       //
                 "isb\n"                                                          //
                 "dsb SY \n"                                                      //
    );
    asm volatile(".quad " xstr(MACRO_END));
}

static void __attribute__((noipa)) body_macro_fast_prime(void)
{
    asm volatile(".quad " xstr(MACRO_START));
    asm volatile(""                                                               //
                 "mrs " TMP_REG6 ", nzcv \n"                                      //
                 "mov " TMP_REG1 ", " UTIL_BASE_REGISTER "\n"                     //
                 "add " TMP_REG1 ", " TMP_REG1 ", " xstr(L1D_PRIMING_OFFSET) "\n" //
                 PRIME(TMP_REG1, TMP_REG2, TMP_REG3, TMP_REG4, TMP_REG5, "1")     //
                 READ_PFC_START()                                                 //
                 SET_SR_STARTED()                                                 //
                 "msr nzcv, " TMP_REG6 "\n"                                       //
                 "isb\n"                                                          //
                 "dsb SY \n"                                                      //
    );
    asm volatile(".quad " xstr(MACRO_END));
}

static void __attribute__((noipa)) body_macro_probe(void)
{
    asm volatile(".quad " xstr(MACRO_START));
    asm volatile(""                          //
                 "mrs " TMP_REG6 ", nzcv \n" //
                 READ_PFC_END()              //
                 PROBE()                     //
                 SET_SR_ENDED()              //
                 "msr nzcv, " TMP_REG6 "\n"  //
                 "isb\n"                     //
                 "dsb SY \n"                 //
    );
    asm volatile(".quad " xstr(MACRO_END));
}

// FAULT_HANDLER -------------------------------------------------------------------------------
static inline size_t start_macro_fault_handler(macro_args_t args, uint8_t *dest)
{
    size_t cursor = 0;

    // The fault handler must be owned by the main actor
    ASSERT(args.owner == 0, "inject_macro_configurable_part");

    // Set new global address to the fault handler
    fault_handler = (char *)((uint64_t)dest + cursor);

    // Ensure that SP, memory base, and util base
    // are set to correct values after (potential) actor switch
    cursor += update_mem_base_and_sp(0, dest, cursor);
    cursor += update_util_base_reg(0, dest, cursor);

    return cursor;
}

// MACRO_SWITCH ------------------------------------------------------------------------------------
static inline size_t start_macro_switch(macro_args_t args, uint8_t *dest)
{
    size_t cursor = 0;
    // Update sp and x30 to the addresses within the new actor's memory
    cursor += update_mem_base_and_sp(args.arg1, dest, cursor);

    // Determine the target address for the switch
    uint64_t switch_target = get_function_addr(args.arg1, args.arg2);
    uint32_t relative_offset = switch_target - (uint64_t)dest - cursor;

    // Jump to the target address (in a different actor) via a relative offset
    uint32_t opcode = b_imm(relative_offset);
    APPEND_U32_TO_DEST(opcode);

    return cursor;
}

// =================================================================================================
// Macro descriptors
// =================================================================================================
macro_descr_t macro_descriptors[] = {
    [TYPE_UNDEFINED] = {.start = NULL, .body = NULL},
    [TYPE_PRIME] = {.start = NULL, .body = body_macro_prime},
    [TYPE_FAST_PRIME] = {.start = NULL, .body = body_macro_fast_prime},
    [TYPE_PARTIAL_PRIME] = {.start = NULL, .body = NULL},
    [TYPE_FAST_PARTIAL_PRIME] = {.start = NULL, .body = NULL},
    [TYPE_PROBE] = {.start = NULL, .body = body_macro_probe},
    [TYPE_FLUSH] = {.start = NULL, .body = NULL},
    [TYPE_EVICT] = {.start = NULL, .body = body_macro_prime},
    [TYPE_RELOAD] = {.start = NULL, .body = NULL},
    [TYPE_TSC_START] = {.start = NULL, .body = NULL},
    [TYPE_TSC_END] = {.start = NULL, .body = NULL},
    [TYPE_FAULT_HANDLER] = {.start = start_macro_fault_handler, .body = NULL},
    [TYPE_FAULT_AND_PROBE] = {.start = start_macro_fault_handler, .body = body_macro_probe},
    [TYPE_FAULT_AND_RELOAD] = {.start = NULL, .body = NULL},
    [TYPE_FAULT_AND_TSC_END] = {.start = NULL, .body = NULL},
    [TYPE_SWITCH] = {.start = start_macro_switch, .body = NULL},
    [TYPE_SET_K2U_TARGET] = {.start = NULL, .body = NULL},
    [TYPE_SWITCH_K2U] = {.start = NULL, .body = NULL},
    [TYPE_SET_U2K_TARGET] = {.start = NULL, .body = NULL},
    [TYPE_SWITCH_U2K] = {.start = NULL, .body = NULL},
    [TYPE_SET_H2G_TARGET] = {.start = NULL, .body = NULL},
    [TYPE_SWITCH_H2G] = {.start = NULL, .body = NULL},
    [TYPE_SET_G2H_TARGET] = {.start = NULL, .body = NULL},
    [TYPE_SWITCH_G2H] = {.start = NULL, .body = NULL},
    [TYPE_LANDING_K2U] = {.start = NULL, .body = NULL},
    [TYPE_LANDING_U2K] = {.start = NULL, .body = NULL},
    [TYPE_LANDING_H2G] = {.start = NULL, .body = NULL},
    [TYPE_LANDING_G2H] = {.start = NULL, .body = NULL},
    [TYPE_SET_DATA_PERMISSIONS] = {.start = NULL, .body = NULL},
};

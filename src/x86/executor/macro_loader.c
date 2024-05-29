/// File: Management of test case macros
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "macro_loader.h"
#include "asm_snippets.h"
#include "fault_handler.h"
#include "host_page_tables.h"
#include "main.h"
#include "memory_guest.h"
#include "sandbox_manager.h"
#include "shortcuts.h"
#include "svm.h"
#include "test_case_parser.h"
#include "vmx.h"

// Max sizes for sanity checks
#define MAX_MACRO_START_OFFSET 0x100
#define MAX_MACRO_LENGTH       0x800

// Code tokens
#define MACRO_START              0x0fff379000000000
#define MACRO_END                0x0fff2f9000000000
#define MACRO_START_TOKEN_LENGTH 8
#define MACRO_END_TOKEN_LENGTH   8

#define MATCHES_MACRO_START(ptr)                                                                   \
    ((ptr)[7] == ((MACRO_START >> 56) & 0xFF) && (ptr)[6] == ((MACRO_START >> 48) & 0xFF) &&       \
     (ptr)[5] == ((MACRO_START >> 40) & 0xFF) && (ptr)[4] == ((MACRO_START >> 32) & 0xFF) &&       \
     (ptr)[3] == ((MACRO_START >> 24) & 0xFF) && (ptr)[2] == ((MACRO_START >> 16) & 0xFF) &&       \
     (ptr)[1] == ((MACRO_START >> 8) & 0xFF) && (ptr)[0] == ((MACRO_START) & 0xFF))

#define MATCHES_MACRO_END(ptr)                                                                     \
    ((ptr)[7] == ((MACRO_END >> 56) & 0xFF) && (ptr)[6] == ((MACRO_END >> 48) & 0xFF) &&           \
     (ptr)[5] == ((MACRO_END >> 40) & 0xFF) && (ptr)[4] == ((MACRO_END >> 32) & 0xFF) &&           \
     (ptr)[3] == ((MACRO_END >> 24) & 0xFF) && (ptr)[2] == ((MACRO_END >> 16) & 0xFF) &&           \
     (ptr)[1] == ((MACRO_END >> 8) & 0xFF) && (ptr)[0] == ((MACRO_END) & 0xFF))

void macro_measurement_start_prime(void);
void macro_measurement_start_fast_prime(void);
void macro_measurement_start_partial_prime(void);
void macro_measurement_start_fast_partial_prime(void);
void macro_measurement_end_probe(void);
void macro_measurement_start_flush(void);
void macro_measurement_end_reload(void);
void macro_measurement_start_tsc(void);
void macro_measurement_end_tsc(void);

void macro_switch_k2u(void);
void macro_switch_u2k(void);
void macro_switch_h2g(void);
void macro_switch_g2h(void);
void macro_set_h2g_target(void);
void macro_set_g2h_target(void);
void macro_empty(void);

// =================================================================================================
// Helper functions
// =================================================================================================
static uint64_t get_function_addr(int section_id, int function_id, uint64_t main_prologue_size)
{
    uint64_t section_base = 0;
    if (actors[section_id].mode == MODE_HOST)
        section_base = (uint64_t)sandbox->code[section_id].section;
    else { // MODE_GUEST
        guest_memory_t *guest_memory = (guest_memory_t *)GUEST_V_MEMORY_START;
        section_base = (uint64_t)guest_memory->code.section;
    }

    if (section_id == 0)
        section_base += main_prologue_size;
    return section_base + test_case->symbol_table[function_id].offset;
}

static uint64_t update_r14(int section_id, uint8_t *macro_dest, uint64_t cursor)
{
    int old_cursor = cursor;

    // calculate the new R14 value
    uint64_t new_r14 = 0;
    if (actors[section_id].mode == MODE_HOST)
        new_r14 = (uint64_t)sandbox->data[section_id].main_area;
    else { // MODE_GUEST
        guest_memory_t *guest_memory = (guest_memory_t *)GUEST_V_MEMORY_START;
        new_r14 = (uint64_t)guest_memory->data.main_area;
    }

    // movabs r14, new_r14
    macro_dest[cursor] = 0x49;
    cursor++;
    macro_dest[cursor] = 0xbe;
    cursor++;
    *((uint64_t *)(macro_dest + cursor)) = new_r14;
    cursor += 8;
    return cursor - old_cursor;
}

static uint64_t update_r14_rsp(int section_id, uint8_t *macro_dest, uint64_t cursor)
{
    int old_cursor = cursor;
    cursor += update_r14(section_id, macro_dest, cursor);

    uint64_t new_rsp = 0;
    if (actors[section_id].mode == MODE_HOST)
        new_rsp = (uint64_t)sandbox->data[section_id].main_area + LOCAL_RSP_OFFSET;
    else { // MODE_GUEST
        guest_memory_t *guest_memory = (guest_memory_t *)GUEST_V_MEMORY_START;
        new_rsp = (uint64_t)guest_memory->data.main_area + LOCAL_RSP_OFFSET;
    }

    // movabs rsp, new_rsp
    macro_dest[cursor] = 0x48;
    cursor++;
    macro_dest[cursor] = 0xbc;
    cursor++;
    *((uint64_t *)(macro_dest + cursor)) = new_rsp;
    cursor += 8;
    return cursor - old_cursor;
}

static uint64_t update_r15(int section_id, uint8_t *macro_dest, uint64_t cursor)
{
    int old_cursor = cursor;

    // calculate the new R15 value
    uint64_t new_r15 = 0;
    if (actors[section_id].mode == MODE_HOST)
        new_r15 = (uint64_t)sandbox->util;
    else { // MODE_GUEST
        guest_memory_t *guest_memory = (guest_memory_t *)GUEST_V_MEMORY_START;
        new_r15 = (uint64_t)&guest_memory->util;
    }

    // movabs r15, new_r15
    macro_dest[cursor] = 0x49;
    cursor++;
    macro_dest[cursor] = 0xbf;
    cursor++;
    *((uint64_t *)(macro_dest + cursor)) = new_r15;
    cursor += 8;
    return cursor - old_cursor;
}

#define SET_MACRO_BYTE(x)                                                                          \
    {                                                                                              \
        macro_dest[cursor] = x;                                                                    \
        cursor++;                                                                                  \
    }

// =================================================================================================
// Macro management
// =================================================================================================
/// @brief Get a pointer to the start of the macro wrapper
/// @param macro_id
/// @return Pointer to the start of the macro wrapper
static uint8_t *get_macro_wrapper_ptr(uint64_t macro_id)
{
    switch (macro_id) {
    case MACRO_MEASUREMENT_START:
        switch (measurement_mode) {
        case PRIME_PROBE:
            return (uint8_t *)macro_measurement_start_prime;
        case FAST_PRIME_PROBE:
            return (uint8_t *)macro_measurement_start_fast_prime;
        case PARTIAL_PRIME_PROBE:
            return (uint8_t *)macro_measurement_start_partial_prime;
        case FAST_PARTIAL_PRIME_PROBE:
            return (uint8_t *)macro_measurement_start_fast_partial_prime;
        case FLUSH_RELOAD:
            return (uint8_t *)macro_measurement_start_flush;
        case EVICT_RELOAD:
            return (uint8_t *)macro_measurement_start_flush;
        case TSC:
            return (uint8_t *)macro_measurement_start_tsc;
        default:
            PRINT_ERRS("get_macro_wrapper_ptr", "misconfigured measurement_mode\n");
            return NULL;
        }
    case MACRO_FAULT_HANDLER_WITH_MEASUREMENT:
    case MACRO_MEASUREMENT_END:
        switch (measurement_mode) {
        case PRIME_PROBE:
        case FAST_PRIME_PROBE:
        case PARTIAL_PRIME_PROBE:
        case FAST_PARTIAL_PRIME_PROBE:
            return (uint8_t *)macro_measurement_end_probe;
        case FLUSH_RELOAD:
        case EVICT_RELOAD:
            return (uint8_t *)macro_measurement_end_reload;
        case TSC:
            return (uint8_t *)macro_measurement_end_tsc;
        default:
            PRINT_ERRS("get_macro_wrapper_ptr", "misconfigured measurement_mode\n");
            return NULL;
        }
    case MACRO_SWITCH_K2U:
        return (uint8_t *)macro_switch_k2u;
    case MACRO_SWITCH_U2K:
        return (uint8_t *)macro_switch_u2k;
    case MACRO_SWITCH_H2G:
        return (uint8_t *)macro_switch_h2g;
    case MACRO_SWITCH_G2H:
        return (uint8_t *)macro_switch_g2h;
    case MACRO_SET_H2G_TARGET:
        return (uint8_t *)macro_set_h2g_target;
    case MACRO_SET_G2H_TARGET:
        return (uint8_t *)macro_set_g2h_target;
    case MACRO_FAULT_HANDLER:
    case MACRO_SWITCH:
    case MACRO_SET_K2U_TARGET:
    case MACRO_SET_U2K_TARGET:
    case MACRO_LANDING_K2U:
    case MACRO_LANDING_U2K:
    case MACRO_LANDING_H2G:
    case MACRO_LANDING_G2H:
    case MACRO_SET_DATA_PERMISSIONS:
        return (uint8_t *)macro_empty;
    default:
        PRINT_ERRS("get_macro_wrapper_ptr", "macro_id %llu is not valid\n", macro_id);
        return NULL;
    }
}

/// @brief Get pointers to the start and the end of the static part of the macro
/// @param[in] macro_id ID of the macro in the macro table
/// @param[out] start Pointer to the start of the macro
/// @param[out] size Size of the macro, in bytes
/// @return -1 on error, 0 otherwise
int get_static_macro_bounds(uint64_t macro_id, uint8_t **start, uint64_t *size)
{
    uint8_t *macro_wrapper_start = get_macro_wrapper_ptr(macro_id);
    ASSERT(macro_wrapper_start != NULL, "get_macro_ptr");

    uint8_t *macro_start = macro_wrapper_start;
    while (!MATCHES_MACRO_START(macro_start)) {
        macro_start++;
        ASSERT(macro_start - macro_wrapper_start < MAX_MACRO_START_OFFSET, "get_macro_ptr");
    }
    macro_start += MACRO_START_TOKEN_LENGTH;

    uint8_t *macro_end = macro_start;
    while (!MATCHES_MACRO_END(macro_end)) {
        macro_end++;
        ASSERT(macro_end - macro_start < MAX_MACRO_LENGTH, "get_macro_ptr");
    }

    *start = macro_start;
    *size = macro_end - macro_start;
    return 0;
}

/// @brief Dynamically generate the configurable part of the macro;
///        This code may pass data to the static part via R11 register
/// @param args Compressed representation of the macro arguments, as received from the test case
/// symbol table
/// @return Size of the generated code, in bytes
uint64_t inject_macro_configurable_part(uint64_t macro_type, uint64_t args, uint64_t owner,
                                        uint8_t *macro_dest, size_t main_prologue_size)
{
    size_t cursor = 0;
    uint16_t arg1 = args & 0xFFFF;
    uint16_t arg2 = (args >> 16) & 0xFFFF;
    uint16_t arg3 = (args >> 32) & 0xFFFF;
    // uint16_t arg4 = (args >> 48) & 0xFFFF;

    uint32_t macro_stack_offset = 0;

    switch (macro_type) {
    case MACRO_MEASUREMENT_START:
    case MACRO_MEASUREMENT_END:
        break;
    case MACRO_FAULT_HANDLER_WITH_MEASUREMENT: {
        cursor += update_r14(arg1, macro_dest, cursor);
        cursor += update_r15(arg1, macro_dest, cursor);
        break;
    }
    case MACRO_FAULT_HANDLER: {
        ASSERT(NESTED_FAULT_OFFSET < (1 << 16), "inject_macro_configurable_part");
        ASSERT(owner == 0, "inject_macro_configurable_part");

        fault_handler = (char *)((uint64_t)macro_dest + cursor);
        cursor += update_r14_rsp(0, macro_dest, cursor);
        cursor += update_r15(0, macro_dest, cursor);

        // Crash on nested fault:
        // cmp byte ptr [r15 + NESTED_FAULT_OFFSET], 0
        SET_MACRO_BYTE(0x49);
        SET_MACRO_BYTE(0x83);
        SET_MACRO_BYTE(0xbf);
        SET_MACRO_BYTE(NESTED_FAULT_OFFSET & 0xFF);
        SET_MACRO_BYTE(NESTED_FAULT_OFFSET >> 8);
        SET_MACRO_BYTE(0x00);
        SET_MACRO_BYTE(0x00);
        SET_MACRO_BYTE(0x00);
        // je [RIP + 9]
        SET_MACRO_BYTE(0x74);
        SET_MACRO_BYTE(0x09);
        // dec byte ptr [r15 + NESTED_FAULT_OFFSET]
        SET_MACRO_BYTE(0x49);
        SET_MACRO_BYTE(0xff);
        SET_MACRO_BYTE(0x8f);
        SET_MACRO_BYTE(NESTED_FAULT_OFFSET & 0xFF);
        SET_MACRO_BYTE(NESTED_FAULT_OFFSET >> 8);
        SET_MACRO_BYTE(0x00);
        SET_MACRO_BYTE(0x00);
        // int 0x20
        SET_MACRO_BYTE(0xcd);
        SET_MACRO_BYTE(0x20);
        // inc byte ptr [r15 + NESTED_FAULT_OFFSET]
        SET_MACRO_BYTE(0x49);
        SET_MACRO_BYTE(0xff);
        SET_MACRO_BYTE(0x87);
        SET_MACRO_BYTE(NESTED_FAULT_OFFSET & 0xFF);
        SET_MACRO_BYTE(NESTED_FAULT_OFFSET >> 8);
        SET_MACRO_BYTE(0x00);
        SET_MACRO_BYTE(0x00);

        break;
    }
    case MACRO_SWITCH: {
        cursor += update_r14_rsp(arg1, macro_dest, cursor);

        // determine the jump target
        uint64_t function_addr = get_function_addr(arg1, arg2, main_prologue_size);

        // jmp [RIP + relative_offset]
        uint32_t relative_offset = function_addr - (uint64_t)macro_dest - cursor - 5;
        macro_dest[cursor] = JMP_32BIT_RELATIVE;
        cursor++;
        *((uint32_t *)(macro_dest + cursor)) = relative_offset;
        cursor += 4;
        break;
    }
    case MACRO_SWITCH_K2U:
        break;
    case MACRO_SWITCH_U2K:
        break;
    case MACRO_SET_K2U_TARGET: {
        // movabs r11, function_addr
        uint64_t function_addr = get_function_addr(arg1, arg2, main_prologue_size);
        SET_MACRO_BYTE(0x49);
        SET_MACRO_BYTE(0xbb);
        *((uint64_t *)(macro_dest + cursor)) = function_addr;
        cursor += 8;
        break;
    }
    case MACRO_SET_H2G_TARGET: {
        if (cpuinfo->x86_vendor == X86_VENDOR_INTEL) {
            // movabs r11, &vmcs_hpa
            SET_MACRO_BYTE(0x49);
            SET_MACRO_BYTE(0xbb);
            *((uint64_t **)(macro_dest + cursor)) = &vmcs_hpas[arg1];
            cursor += 8;

            // vmptrld [r11]
            SET_MACRO_BYTE(0x41);
            SET_MACRO_BYTE(0x0f);
            SET_MACRO_BYTE(0xc7);
            SET_MACRO_BYTE(0x33);

            // movabs r11, function_addr
            uint64_t function_addr = get_function_addr(arg1, arg2, main_prologue_size);
            SET_MACRO_BYTE(0x49);
            SET_MACRO_BYTE(0xbb);
            *((uint64_t *)(macro_dest + cursor)) = function_addr;
            cursor += 8;
        } else {
            // movabs r11, &vmcb_hva
            SET_MACRO_BYTE(0x49);
            SET_MACRO_BYTE(0xbb);
            *((uint64_t **)(macro_dest + cursor)) = &vmcb_hvas[arg1];
            cursor += 8;

            // mov r11, [r11]
            SET_MACRO_BYTE(0x4d);
            SET_MACRO_BYTE(0x8b);
            SET_MACRO_BYTE(0x1b);

            // add r11, VMCB_RIP_OFFSET
            SET_MACRO_BYTE(0x49);
            SET_MACRO_BYTE(0x81);
            SET_MACRO_BYTE(0xc3);
            *((uint32_t *)(macro_dest + cursor)) = VMCB_RIP_OFFSET;
            cursor += 4;

            // mov qword ptr [r11], function_addr
            uint64_t function_addr = get_function_addr(arg1, arg2, main_prologue_size);
            SET_MACRO_BYTE(0x49);
            SET_MACRO_BYTE(0xc7);
            SET_MACRO_BYTE(0x03);
            *((uint32_t *)(macro_dest + cursor)) = function_addr & 0xFFFFFFFF;
            cursor += 4;

            // add r11, 4
            SET_MACRO_BYTE(0x49);
            SET_MACRO_BYTE(0x83);
            SET_MACRO_BYTE(0xc3);
            SET_MACRO_BYTE(0x04);

            SET_MACRO_BYTE(0x49);
            SET_MACRO_BYTE(0xc7);
            SET_MACRO_BYTE(0x03);
            *((uint32_t *)(macro_dest + cursor)) = (function_addr >> 32) & 0xFFFFFFFF;
            cursor += 4;

        }
        break;
    }
    case MACRO_SET_U2K_TARGET: {
        uint64_t function_addr = get_function_addr(arg1, arg2, main_prologue_size);

        // 49 89 a6 38 f0 ff ff    mov    QWORD PTR [r14 - MACRO_STACK_TOP_OFFSET - 8],rsp
        SET_MACRO_BYTE(0x49);
        SET_MACRO_BYTE(0x89);
        SET_MACRO_BYTE(0xa6);
        macro_stack_offset = -MACRO_STACK_TOP_OFFSET - 8;
        *((uint32_t *)(macro_dest + cursor)) = macro_stack_offset;
        cursor += 4;
        // 49 8d a6 38 f0 ff ff    lea    rsp,[r14 - MACRO_STACK_TOP_OFFSET - 8]
        SET_MACRO_BYTE(0x49);
        SET_MACRO_BYTE(0x8d);
        SET_MACRO_BYTE(0xa6);
        *((uint32_t *)(macro_dest + cursor)) = macro_stack_offset;
        cursor += 4;
        // 50                      push   rax
        SET_MACRO_BYTE(0x50);
        // 51                      push   rcx
        SET_MACRO_BYTE(0x51);
        // 52                      push   rdx
        SET_MACRO_BYTE(0x52);
        // 9c                      pushf
        SET_MACRO_BYTE(0x9c);
        // 48 b8                   movabs rax, function_addr
        SET_MACRO_BYTE(0x48);
        SET_MACRO_BYTE(0xb8);
        *((uint64_t *)(macro_dest + cursor)) = function_addr;
        cursor += 8;
        // 48 89 c2                mov    rdx,rax
        SET_MACRO_BYTE(0x48);
        SET_MACRO_BYTE(0x89);
        SET_MACRO_BYTE(0xc2);
        // 48 c1 ea 20             shr    rdx,0x20
        SET_MACRO_BYTE(0x48);
        SET_MACRO_BYTE(0xc1);
        SET_MACRO_BYTE(0xea);
        SET_MACRO_BYTE(0x20);
        // 48 b9 82 00 00 c0 00    movabs rcx,0xc0000082
        SET_MACRO_BYTE(0x48);
        SET_MACRO_BYTE(0xb9);
        *((uint64_t *)(macro_dest + cursor)) = 0xc0000082;
        cursor += 8;
        // 0f 30                   wrmsr
        SET_MACRO_BYTE(0x0f);
        SET_MACRO_BYTE(0x30);
        // 9d                      popf
        SET_MACRO_BYTE(0x9d);
        // mov qword ptr [rsp - 0x08], 0
        SET_MACRO_BYTE(0x48);
        SET_MACRO_BYTE(0xc7);
        SET_MACRO_BYTE(0x44);
        SET_MACRO_BYTE(0x24);
        SET_MACRO_BYTE(0xf8);
        SET_MACRO_BYTE(0x00);
        SET_MACRO_BYTE(0x00);
        SET_MACRO_BYTE(0x00);
        SET_MACRO_BYTE(0x00);
        // 5a                      pop    rdx
        SET_MACRO_BYTE(0x5a);
        // mov qword ptr [rsp - 0x08], 0
        SET_MACRO_BYTE(0x48);
        SET_MACRO_BYTE(0xc7);
        SET_MACRO_BYTE(0x44);
        SET_MACRO_BYTE(0x24);
        SET_MACRO_BYTE(0xf8);
        SET_MACRO_BYTE(0x00);
        SET_MACRO_BYTE(0x00);
        SET_MACRO_BYTE(0x00);
        SET_MACRO_BYTE(0x00);
        // 59                      pop    rcx
        SET_MACRO_BYTE(0x59);
        // mov qword ptr [rsp - 0x08], 0
        SET_MACRO_BYTE(0x48);
        SET_MACRO_BYTE(0xc7);
        SET_MACRO_BYTE(0x44);
        SET_MACRO_BYTE(0x24);
        SET_MACRO_BYTE(0xf8);
        SET_MACRO_BYTE(0x00);
        SET_MACRO_BYTE(0x00);
        SET_MACRO_BYTE(0x00);
        SET_MACRO_BYTE(0x00);
        // 58                      pop    rax
        SET_MACRO_BYTE(0x58);
        // mov qword ptr [rsp - 0x08], 0
        SET_MACRO_BYTE(0x48);
        SET_MACRO_BYTE(0xc7);
        SET_MACRO_BYTE(0x44);
        SET_MACRO_BYTE(0x24);
        SET_MACRO_BYTE(0xf8);
        SET_MACRO_BYTE(0x00);
        SET_MACRO_BYTE(0x00);
        SET_MACRO_BYTE(0x00);
        SET_MACRO_BYTE(0x00);
        // 5c                      pop    rsp
        SET_MACRO_BYTE(0x5c);

        break;
    }
    case MACRO_SET_G2H_TARGET: {
        if (cpuinfo->x86_vendor == X86_VENDOR_INTEL) {
            // movabs r11, function_addr
            uint64_t function_addr = get_function_addr(arg1, arg2, main_prologue_size);
            SET_MACRO_BYTE(0x49);
            SET_MACRO_BYTE(0xbb);
            *((uint64_t *)(macro_dest + cursor)) = function_addr;
            cursor += 8;
        } else {
            // Nothing for AMD
        }
        break;
    }
    case MACRO_SWITCH_H2G:
        if (cpuinfo->x86_vendor == X86_VENDOR_INTEL) {
            // Nothing for Intel
        } else { // AMD
            // movabs rax, &vmcb_hpa
            SET_MACRO_BYTE(0x48);
            SET_MACRO_BYTE(0xb8);
            *((uint64_t *)(macro_dest + cursor)) = (uint64_t)&vmcb_hpas[arg1];
            cursor += 8;
        }
        break;
    case MACRO_SWITCH_G2H:
        break;
    case MACRO_LANDING_K2U: {
        cursor += update_r14_rsp(owner, macro_dest, cursor);
        // movabs rcx, 0  # rcx was corrupted during context switch; set to zero
        SET_MACRO_BYTE(0x48);
        SET_MACRO_BYTE(0xb9);
        *((uint64_t *)(macro_dest + cursor)) = 0;
        cursor += 8;
        break;
    }
    case MACRO_LANDING_U2K: {
        cursor += update_r14(owner, macro_dest, cursor);
        // rsp is automatically restored by syscall instruction

        // movabs rcx, 0  # rcx was corrupted during context switch; set to zero
        SET_MACRO_BYTE(0x48);
        SET_MACRO_BYTE(0xb9);
        *((uint64_t *)(macro_dest + cursor)) = 0;
        cursor += 8;
        break;
    }
    case MACRO_LANDING_H2G:
    case MACRO_LANDING_G2H: {
        cursor += update_r14(owner, macro_dest, cursor);
        cursor += update_r15(owner, macro_dest, cursor);

        if (cpuinfo->x86_vendor == X86_VENDOR_AMD) {
            // mov rax, 0
            SET_MACRO_BYTE(0x48);
            SET_MACRO_BYTE(0xc7);
            SET_MACRO_BYTE(0xc0);
            SET_MACRO_BYTE(0x00);
            SET_MACRO_BYTE(0x00);
            SET_MACRO_BYTE(0x00);
            SET_MACRO_BYTE(0x00);
        }

        break;
    }
    case MACRO_SET_DATA_PERMISSIONS: {
        // get safe bits to set/clear
        uint16_t mask_set = arg2;
        uint16_t mask_clear = arg3;

        // get the target PTE
        int page_id = arg1 * N_DATA_PAGES_PER_ACTOR + FAULTY_PAGE_ID;
        pte_t_ *ptep = sandbox_pteps->data_pteps[page_id];
        ASSERT(ptep != NULL, "inject_macro_configurable_part");

        // Switch stack
        // mov    QWORD PTR [r14 - MACRO_STACK_TOP_OFFSET - 8],rsp
        SET_MACRO_BYTE(0x49);
        SET_MACRO_BYTE(0x89);
        SET_MACRO_BYTE(0xa6);
        macro_stack_offset = -MACRO_STACK_TOP_OFFSET - 8;
        *((uint32_t *)(macro_dest + cursor)) = macro_stack_offset;
        cursor += 4;
        // lea    rsp,[r14 - MACRO_STACK_TOP_OFFSET - 8]
        SET_MACRO_BYTE(0x49);
        SET_MACRO_BYTE(0x8d);
        SET_MACRO_BYTE(0xa6);
        *((uint32_t *)(macro_dest + cursor)) = macro_stack_offset;
        cursor += 4;

        // push rax
        SET_MACRO_BYTE(0x50);

        // Get pointer to PTE
        // mov rax, ptep
        SET_MACRO_BYTE(0x48);
        SET_MACRO_BYTE(0xb8);
        *((uint64_t *)(macro_dest + cursor)) = (uint64_t)ptep;
        cursor += 8;

        // Apply the set and clear masks to the lowest 16 bits of the PTE
        // note that we leave the remaining bits unchanged because arg2 and arg3 are 16-bit values
        //   or qword ptr [r11], mask_set
        SET_MACRO_BYTE(0x66);
        SET_MACRO_BYTE(0x81);
        SET_MACRO_BYTE(0x08);
        *((uint16_t *)(macro_dest + cursor)) = mask_set;
        cursor += 2;

        //   and qword ptr [r11], mask_clear
        SET_MACRO_BYTE(0x66);
        SET_MACRO_BYTE(0x81);
        SET_MACRO_BYTE(0x20);
        *((uint16_t *)(macro_dest + cursor)) = mask_clear;
        cursor += 2;

        // Restore stack
        // pop    rax
        SET_MACRO_BYTE(0x58);
        // mov qword ptr [rsp - 0x08], 0
        SET_MACRO_BYTE(0x48);
        SET_MACRO_BYTE(0xc7);
        SET_MACRO_BYTE(0x44);
        SET_MACRO_BYTE(0x24);
        SET_MACRO_BYTE(0xf8);
        SET_MACRO_BYTE(0x00);
        SET_MACRO_BYTE(0x00);
        SET_MACRO_BYTE(0x00);
        SET_MACRO_BYTE(0x00);
        // pop    rsp
        SET_MACRO_BYTE(0x5c);

        break;
    }
    default:
        PRINT_ERRS("inject_macro_configurable_part", "macro_type %llu is not valid\n", macro_type);
        return -1;
    }

    return cursor;
}

// =================================================================================================
// Macros: Uarch measurements
// =================================================================================================
// clang-format off
#define PUSH_ABCDF()                                                                               \
    "mov qword ptr [r14 - " xstr(MACRO_STACK_TOP_OFFSET) " - 8], rsp\n"                            \
    "lea rsp, [r14 - " xstr(MACRO_STACK_TOP_OFFSET) " - 8]\n"                                      \
    "push rax\n"                                                                                   \
    "push rbx\n"                                                                                   \
    "push rcx\n"                                                                                   \
    "push rdx\n"                                                                                   \
    "pushf\n"

#define POP_ABCDF()                                                                                \
    "popf\n"                                                                                       \
    "pop rdx\n"                                                                                    \
    "pop rcx\n"                                                                                    \
    "pop rbx\n"                                                                                    \
    "pop rax\n"                                                                                    \
    "mov qword ptr [rsp - 0x08], 0 \n"                                                             \
    "mov qword ptr [rsp - 0x10], 0 \n"                                                             \
    "mov qword ptr [rsp - 0x18], 0 \n"                                                             \
    "mov qword ptr [rsp - 0x20], 0 \n"                                                             \
    "mov qword ptr [rsp - 0x28], 0 \n"                                                             \
    "pop rsp\n"
// clang-format on

#define HTRACE_REGISTER "r13"

// Prime + Probe and variants -----------------------
void __attribute__((noipa)) macro_measurement_start_prime(void)
{
    asm volatile(".quad " xstr(MACRO_START));
    asm_volatile_intel(""                                                //
                       PUSH_ABCDF()                                      //
                       "lea rax, [r15 + " xstr(L1D_PRIMING_OFFSET) "]\n" //
                       PRIME("rax", "rbx", "rcx", "rdx", "32")           //
                       "xor " HTRACE_REGISTER ", " HTRACE_REGISTER "\n"  //
                       READ_PFC_START()                                  //
                       POP_ABCDF()                                       //
                       "lfence\n"                                        //
    );
    asm volatile(".quad " xstr(MACRO_END));
}

void __attribute__((noipa)) macro_measurement_start_fast_prime(void)
{
    asm volatile(".quad " xstr(MACRO_START));
    asm_volatile_intel(""                                                //
                       PUSH_ABCDF()                                      //
                       "lea rax, [r15 + " xstr(L1D_PRIMING_OFFSET) "]\n" //
                       PRIME("rax", "rbx", "rcx", "rdx", "1")            //
                       "xor " HTRACE_REGISTER ", " HTRACE_REGISTER "\n"  //
                       READ_PFC_START()                                  //
                       POP_ABCDF()                                       //
                       "lfence\n"                                        //
    );
    asm volatile(".quad " xstr(MACRO_END));
}

void __attribute__((noipa)) macro_measurement_start_partial_prime(void)
{
    asm volatile(".quad " xstr(MACRO_START));
    asm_volatile_intel(""                                                //
                       PUSH_ABCDF()                                      //
                       "lea rax, [r15 + " xstr(L1D_PRIMING_OFFSET) "]\n" //
                       PRIME_PARTIAL("rax", "rbx", "rcx", "rdx", "32")   //
                       "xor " HTRACE_REGISTER ", " HTRACE_REGISTER "\n"  //
                       READ_PFC_START()                                  //
                       POP_ABCDF()                                       //
                       "lfence\n"                                        //
    );
    asm volatile(".quad " xstr(MACRO_END));
}

void __attribute__((noipa)) macro_measurement_start_fast_partial_prime(void)
{
    asm volatile(".quad " xstr(MACRO_START));
    asm_volatile_intel(""                                                //
                       PUSH_ABCDF()                                      //
                       "lea rax, [r15 + " xstr(L1D_PRIMING_OFFSET) "]\n" //
                       PRIME_PARTIAL("rax", "rbx", "rcx", "rdx", "1")    //
                       "xor " HTRACE_REGISTER ", " HTRACE_REGISTER "\n"  //
                       READ_PFC_START()                                  //
                       POP_ABCDF()                                       //
                       "lfence\n"                                        //
    );
    asm volatile(".quad " xstr(MACRO_END));
}

void __attribute__((noipa)) macro_measurement_end_probe(void)
{
    asm volatile(".quad " xstr(MACRO_START));
    asm_volatile_intel(""                                                //
                       "cmp " HTRACE_REGISTER ", 0\n"                    // skip if already called
                       "jnz 99f\n"                                       //
                       PUSH_ABCDF()                                      //
                       "push r15\n"                                      //
                       "lfence\n"                                        //
                       READ_PFC_END()                                    //
                       "lea r15, [r15 + " xstr(L1D_PRIMING_OFFSET) "]\n" //
                       PROBE("r15", "rbx", "r11", HTRACE_REGISTER)       //
                       "pop r15\n"                                       //
                       "mov qword ptr [rsp - 8], 0 \n"                   //
                       POP_ABCDF()                                       //
                       "99:\n"                                           //
    );
    asm volatile(".quad " xstr(MACRO_END));
}

// Flush + Reload and variants ----------------------
void __attribute__((noipa)) macro_measurement_start_flush(void)
{
    asm volatile(".quad " xstr(MACRO_START));
    asm_volatile_intel(""                  //
                       PUSH_ABCDF()        //
                       "lea rbx, [r14]\n"  //
                       FLUSH("rbx", "rax") //
                       READ_PFC_START()    //
                       POP_ABCDF()         //
                       "lfence\n"          //
    );
    asm volatile(".quad " xstr(MACRO_END));
}

void __attribute__((noipa)) macro_measurement_end_reload(void)
{
    asm volatile(".quad " xstr(MACRO_START));
    asm_volatile_intel(""                                           //
                       "cmp " HTRACE_REGISTER ", 0\n"               // skip if already called
                       "jnz 98f\n"                                  //
                       PUSH_ABCDF()                                 //
                       "lfence\n"                                   //
                       READ_PFC_END()                               //
                       RELOAD("r14", "rbx", "r11", HTRACE_REGISTER) //
                       "mov rax, 1\n"                               //
                       "shl rax, 63\n"                              //
                       "or " HTRACE_REGISTER ", rax\n"              //
                       POP_ABCDF()                                  //
                       "98:\n"                                      //
    );
    asm volatile(".quad " xstr(MACRO_END));
}

// Time stamp counter -------------------------------
void __attribute__((noipa)) macro_measurement_start_tsc(void)
{
    asm volatile(".quad " xstr(MACRO_START));
    asm_volatile_intel(""                                               //
                       PUSH_ABCDF()                                     //
                       "lfence; rdtsc; lfence\n"                        //
                       "shl rdx, 32\n"                                  //
                       "or rdx, rax\n"                                  //
                       "xor " HTRACE_REGISTER ", " HTRACE_REGISTER "\n" //
                       "sub " HTRACE_REGISTER ", rdx\n"                 //
                       "lfence\n"                                       //
                       READ_PFC_START()                                 //
                       POP_ABCDF()                                      //
                       "lfence\n"                                       //
    );
    asm volatile(".quad " xstr(MACRO_END));
}

void __attribute__((noipa)) macro_measurement_end_tsc(void)
{
    asm volatile(".quad " xstr(MACRO_START));
    asm_volatile_intel(""                               //
                       "cmp " HTRACE_REGISTER ", 0\n"   // skip if already called
                       "jg 97f\n"                       //
                       PUSH_ABCDF()                     //
                       READ_PFC_END()                   //
                       "lfence; rdtsc; lfence\n"        //
                       "shl rdx, 32\n"                  //
                       "or rdx, rax\n"                  //
                       "add " HTRACE_REGISTER ", rdx\n" //
                       POP_ABCDF()                      //
                       "97:\n"                          //
    );
    asm volatile(".quad " xstr(MACRO_END));
}

// =================================================================================================
// Macros: Context switches
// =================================================================================================

/// @brief Macro to switch host -> user actor
void __attribute__((noipa)) macro_switch_k2u(void)
{
    asm volatile(".quad " xstr(MACRO_START));
    // clang-format off
    asm_volatile_intel(""
                       "mov rcx, r11\n"
                       "mov qword ptr [r14 - " xstr(MACRO_STACK_TOP_OFFSET) " - 8], rsp\n"
                       "lea rsp, [r14 - " xstr(MACRO_STACK_TOP_OFFSET) " - 8]\n"
                       "pushfq\n"
                       "pop r11\n"
                       "pop rsp\n"
                       "sysretq\n");
    // clang-format on
    asm volatile(".quad " xstr(MACRO_END));
}

/// @brief Macro to switch user -> host actor
void __attribute__((noipa)) macro_switch_u2k(void)
{
    asm volatile(".quad " xstr(MACRO_START));
    asm_volatile_intel("syscall\n");
    asm volatile(".quad " xstr(MACRO_END));
}

void __attribute__((noipa)) macro_switch_h2g(void)
{
    asm volatile(".quad " xstr(MACRO_START));
#if VENDOR_ID == 1
    asm_volatile_intel("vmresume\n");
#else
    asm_volatile_intel("" // rax contains the current VMCB pointer
                       "clgi\n"
                       "mov rax, qword ptr [rax]\n" //
                       "vmsave rax\n" //
                       "vmrun rax\n"  //
                       "vmload rax\n"
                       "mov rax, 0\n" //
                       "stgi\n"       //
                       "");
#endif
    asm volatile(".quad " xstr(MACRO_END));
}

void __attribute__((noipa)) macro_switch_g2h(void)
{
    asm volatile(".quad " xstr(MACRO_START));
#if VENDOR_ID == 1
    asm_volatile_intel("vmcall\n");
#else
    asm_volatile_intel("vmmcall\n");
#endif
    asm volatile(".quad " xstr(MACRO_END));
}

void __attribute__((noipa)) macro_set_h2g_target(void)
{
    asm volatile(".quad " xstr(MACRO_START));
#if VENDOR_ID == 1
    asm_volatile_intel(""                      // r11 contains the target address
                       PUSH_ABCDF()            //
                       "mov rcx, 0x0000681e\n" // GUEST_RIP
                       "vmwrite rcx, r11 \n"   //
                       POP_ABCDF()             //
    );
#else
    // Nothing on AMD
#endif
    asm volatile(".quad " xstr(MACRO_END));
}

void __attribute__((noipa)) macro_set_g2h_target(void)
{
    asm volatile(".quad " xstr(MACRO_START));
#if VENDOR_ID == 1
    asm_volatile_intel(""                      // r11 contains the target address
                       PUSH_ABCDF()            //
                       "mov rcx, 0x00006c16\n" // HOST_RIP
                       "vmwrite rcx, r11 \n"   //
                       POP_ABCDF()             //
    );
#else
    // Nothing on AMD
#endif
    asm volatile(".quad " xstr(MACRO_END));
}

void __attribute__((noipa)) macro_empty(void)
{
    asm volatile(".quad " xstr(MACRO_START));
    asm volatile(".quad " xstr(MACRO_END));
}

// =================================================================================================
// Macros: VMX
// =================================================================================================

// Under construction

// =================================================================================================
int init_macros_loader(void) { return 0; }

void free_macros_loader(void) {}

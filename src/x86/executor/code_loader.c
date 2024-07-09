/// File:
///    - Loader for test case code
///    - Definition of the test case entry- and exit-points
///    - Insertion of macros
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

// -----------------------------------------------------------------------------------------------
// Note on registers.
// Some of the registers are reserved for a specific purpose and should never be overwritten.
// These include:
//   R8 - performance counter #3
//   R9 - performance counter #2
//   R10 - performance counter #1
//   R11 - temporary data for macros
//   R12 - SMI counter
//   R13 - hardware trace
//   R14 - base address of the current actor's main data area
//   R15 - base address of the utility area

#include "code_loader.h"
#include "asm_snippets.h"
#include "macro_loader.h"
#include "main.h"
#include "sandbox_manager.h"
#include "shortcuts.h"
#include "test_case_parser.h"

#include "fault_handler.h"

#define PER_SECTION_ALLOC_SIZE (MAX_EXPANDED_SECTION_SIZE + MAX_EXPANDED_MACROS_SIZE)
#define MAX_TEMPLATE_SIZE      0x1000 // for sanity checking

#define TEMPLATE_START                     0x0fff379000000000
#define TEMPLATE_INSERT_TC                 0x0fff2f9000000000
#define TEMPLATE_DEFAULT_EXCEPTION_LANDING 0x0fff479000000000
#define TEMPLATE_END                       0x0fff279000000000
#define TEMPLATE_MARKER_SIZE               8

uint8_t *loaded_test_case_entry = NULL; // global

static int load_section_main(void);
static int load_section(int segment_id);
static tc_symbol_entry_t *get_section_macros_start(uint64_t section_id);
static int64_t expand_section(uint64_t section_id, uint8_t *dest, uint8_t *macros_dest,
                              size_t *size_section, size_t *size_macros);

static inline void prologue(void);
static inline void epilogue(void);
static void main_segment_template(void);
static void main_segment_template_dbg_gpr(void);

// =================================================================================================
// Code Loader
// =================================================================================================
int load_sandbox_code(void)
{
    int err = 0;
    ASSERT(sandbox->code != NULL, "load_sandbox_code");

    // reset the code
    memset(sandbox->code, 0x90, sizeof(actor_code_t) * n_actors);

    for (int section_id = 0; section_id < n_actors; section_id++) {
        if (section_id == 0)
            err |= load_section_main();
        else
            err |= load_section(section_id);
    }
    return err;
}

static int load_section(int section_id)
{
    uint8_t *section = sandbox->code[section_id].section;
    uint8_t *macros = sandbox->code[section_id].macros;
    size_t size_section, size_macros = 0;
    int err = expand_section(section_id, section, macros, &size_section, &size_macros);
    CHECK_ERR("load_section");

    return 0;
}

static int load_section_main(void)
{
    int err = 0;

    ASSERT(test_case->metadata[0].owner == 0, "load_section_main");
    uint8_t *dest = (uint8_t *)&sandbox->code[0].section;
    uint8_t *macro_dest = sandbox->code[0].macros;

    uint64_t src_cursor = 0;
    uint64_t dest_cursor = 0;
    uint64_t macros_cursor = 0;

    // reset globals
    fault_handler = NULL;
    loaded_test_case_entry = NULL;

    // select a template based on the debug mode
    uint8_t *src = (dbg_gpr_mode) ? (uint8_t *)main_segment_template_dbg_gpr
                                  : (uint8_t *)main_segment_template;

    // skip instructions inserted by the compiler and start at the TEMPLATE_START marker
    for (;; src_cursor++) {
        ASSERT(src_cursor < MAX_TEMPLATE_SIZE, "load_section_main; TEMPLATE_START");
        if (*(uint64_t *)&src[src_cursor] == TEMPLATE_START)
            break;
    }
    src_cursor += TEMPLATE_MARKER_SIZE;

    // copy the first part of the template
    for (;; src_cursor++, dest_cursor++) {
        ASSERT(src_cursor < MAX_TEMPLATE_SIZE, "load_section_main; TEMPLATE_INSERT_TC");
        if (*(uint64_t *)&src[src_cursor] == TEMPLATE_INSERT_TC)
            break;
        dest[dest_cursor] = src[src_cursor];
    }
    src_cursor += TEMPLATE_MARKER_SIZE;

    // notify Macro Loader about the prologue size of the main section
    set_main_prologue_size(dest_cursor);

    // copy the test case into the template and expand macros
    size_t size_section, size_macros = 0;
    err = expand_section(0, &dest[dest_cursor], macro_dest, &size_section, &size_macros);
    CHECK_ERR("load_section_main");
    dest_cursor += size_section;
    macros_cursor += size_macros;

    // set fault handler if the test case does not already declare an explicit one
    for (;; src_cursor++, dest_cursor++) {
        ASSERT(src_cursor < MAX_TEMPLATE_SIZE, "load_section_main; EXCEPTION_LANDING");
        if (*(uint64_t *)&src[src_cursor] == TEMPLATE_DEFAULT_EXCEPTION_LANDING) {

            // if the test case has an explicit fault handler, we just skip the macro
            // and leave the 8 NOP bytes for compatibility
            if (test_case->features.has_explicit_fault_handler) {
                dest_cursor += 5; // leave 5 NOP bytes for compatibility
                break;
            }

            // set the fault handler to the default one (end of the main actor)
            fault_handler = (char *)&dest[dest_cursor];

            // expand the macro for the default fault handler
            tc_symbol_entry_t measurement_end = (tc_symbol_entry_t){
                .id = MACRO_FAULT_HANDLER_WITH_MEASUREMENT, .offset = 0, .owner = 0, .args = 0};
            size_macros = 0;
            err = expand_macro(&measurement_end, &dest[dest_cursor], &macro_dest[macros_cursor],
                               &size_macros);
            CHECK_ERR("load_section_main");

            macros_cursor += size_macros;
            dest_cursor += MACRO_PLACEHOLDER_SIZE;
            break;
        }
        dest[dest_cursor] = src[src_cursor];
    }
    src_cursor += TEMPLATE_MARKER_SIZE;

    // write the rest of the template
    for (;; src_cursor++, dest_cursor++) {
        ASSERT(src_cursor < MAX_TEMPLATE_SIZE, "load_section_main: TEMPLATE_END");
        if (*(uint64_t *)&src[src_cursor] == TEMPLATE_END)
            break;
        dest[dest_cursor] = src[src_cursor];
    }
    ASSERT(dest_cursor < MAX_EXPANDED_SECTION_SIZE, "load_section_main");

    loaded_test_case_entry = dest;
    return 0;
}

/// @brief Get the first macro in a section
/// @param section_id ID of the section
/// @return Pointer to the first macro in the section, or NULL if there are no macros
static tc_symbol_entry_t *get_section_macros_start(uint64_t section_id)
{
    tc_symbol_entry_t *entry = test_case->symbol_table;
    tc_symbol_entry_t *end = entry + test_case->symbol_table_size / sizeof(*entry);
    while (entry->owner != section_id || entry->id == 0) {
        entry++;
        if (entry >= end)
            return NULL;
    }
    return entry;
}

/// @brief Expand a section and its macros into destination buffers
/// @param[in] section_id ID of the section to expand
/// @param[in] dest Destination address for the expanded section code
/// @param[in] macros_dest Destination address for the expanded macros
/// @param[out] size_section Size of the expanded section
/// @param[out] size_macros Size of the expanded macros
/// @return 0 on success, -1 on failure
static int64_t expand_section(uint64_t section_id, uint8_t *dest, uint8_t *macros_dest,
                              size_t *size_section, size_t *size_macros)
{
    int err = 0;
    uint64_t src_cursor = 0;
    uint64_t dest_cursor = 0;
    uint64_t macros_cursor = 0;

    // get the unexpanded section
    uint8_t *section = test_case->sections[section_id].code;
    size_t section_size = test_case->metadata[section_id].size;
    ASSERT(section_size <= MAX_SECTION_SIZE, "expand_section");

    // get the first macro in the section
    tc_symbol_entry_t *macro = get_section_macros_start(section_id);

    // If there are no macros to expand, just copy the code
    if (macro == NULL) {
        memcpy(dest, section, section_size);
        *size_section = section_size;
        *size_macros = 0;
        return 0;
    }

    // Otherwise, expand macros by iterating over the section and calling expand_macro
    // whenever we encounter a macro placeholder
    for (src_cursor = 0; src_cursor < section_size; src_cursor++, dest_cursor++) {
        // if a byte is *not* a macro placeholder, just copy it
        if (macro == NULL || src_cursor != macro->offset) {
            dest[dest_cursor] = section[src_cursor];
            continue;
        }

        // if we're here, we have a macro placeholder
        ASSERT(macro->owner == section_id, "expand_section");
        ASSERT(macro->id != 0, "expand_section");

        // expand the macro into the destination buffers
        size_t macro_size = 0;
        err = expand_macro(macro, &dest[dest_cursor], &macros_dest[macros_cursor], &macro_size);
        CHECK_ERR("expand_section");

        // move the cursors
        dest_cursor += 4;
        src_cursor += 4; // skip the remaining bytes of the current macro placeholder
        macro++;         // move to next macro
        macros_cursor += macro_size;

        // if we're done with macros in this section, set the macro pointer to NULL
        if (macro->owner != section_id)
            macro = NULL;
    }

    // ensure that we did not have an overrun
    ASSERT(src_cursor == section_size, "expand_section");

    *size_section = dest_cursor;
    *size_macros = macros_cursor;
    return 0;
}

// =================================================================================================
// Entry and exit points
// =================================================================================================
// clang-format off
static inline void prologue(void)
{
    // As we don't use a compiler to track clobbering,
    // we have to save the callee-saved regs
    asm_volatile_intel(
        "push rbx\n"
        "push rbp\n"
        "push r10\n"
        "push r11\n"
        "push r12\n"
        "push r13\n"
        "push r14\n"
        "push r15\n"
        "pushfq\n"

        // r14 = main_area of actor 0 (passed in rdi, the first argument of measurement_code)
        "mov r14, rdi\n"

        // r15 = sandbox->util
        "lea r15, [r14 - "xstr(UTIL_REL_TO_MAIN)"]\n"

        // sandbox->util->stored_rsp = rsp
        "mov qword ptr [r15 + "xstr(STORED_RSP_OFFSET)"], rsp\n"

        // clear the rest of the registers
        "mov rax, 0\n"
        "mov rbx, 0\n"
        "mov rcx, 0\n"
        "mov rdx, 0\n"
        "mov rsi, 0\n"
        "mov rdi, 0\n"
        "mov r8,  0\n"
        "mov r9,  0\n"
        "mov r10, 0\n"
        "mov r11, 0\n"
        "mov r12, 0\n"
        "mov r13, 0\n"

        "mov rbp, rsp\n"
        "sub rsp, 0x1000\n"

        // start monitoring interrupts
        READ_SMI_START("r12")
    );
}

static inline void epilogue(void)
{
    asm_volatile_intel(
        READ_SMI_END("r12")

        // rax <- &latest_measurement
        "lea rax, [r15 + "xstr(MEASUREMENT_OFFSET)"]\n"

        // if we see no interrupts, store the hardware trace (r13)
        // otherwise, store zero
        "cmp r12, 0; jne 1f \n"
        "   mov qword ptr [rax + 0x00], r13 \n"
        "   mov qword ptr [rax + 0x08], r10 \n"
        "   mov qword ptr [rax + 0x10], r9 \n"
        "   mov qword ptr [rax + 0x18], r8 \n"

            // to show that the measurement is valid, we set the last byte to 0x01
        "   or byte ptr [rax + 0x07], 0x80 \n"
        "   jmp 2f \n"
        "1: \n"
        "   mov qword ptr [rax + 0x00], 0 \n"
        "   mov qword ptr [rax + 0x08], 0 \n"
        "   mov qword ptr [rax + 0x10], 0 \n"
        "   mov qword ptr [rax + 0x18], 0 \n"
        "2: \n"

        // rsp = sandbox->util->stored_rsp
        "mov rsp, qword ptr [r15 + "xstr(STORED_RSP_OFFSET)"]\n"

        // restore registers
        "popfq\n"
        "pop r15\n"
        "pop r14\n"
        "pop r13\n"
        "pop r12\n"
        "pop r11\n"
        "pop r10\n"
        "pop rbp\n"
        "pop rbx\n"

        // return 0
        "mov rax, 0\n"
        "ret\n"
        "int3\n" // Silences objtool warnings about no int3 after ret
    );
}

static inline void epilogue_dbg_gpr(void)
{
    asm_volatile_intel(
        // clobber r14; not in use anymore
        "lea r14, [r15 + "xstr(MEASUREMENT_OFFSET)"]\n"
        "mov qword ptr [r14 + 0x00], rax\n"
        "mov qword ptr [r14 + 0x08], rbx\n"
        "mov qword ptr [r14 + 0x10], rcx\n"
        "mov qword ptr [r14 + 0x18], rdx\n"
        "mov qword ptr [r14 + 0x20], rsi\n"
        "mov qword ptr [r14 + 0x28], rdi\n"

        // rsp = sandbox->util->stored_rsp
        "mov rsp, qword ptr [r15 + "xstr(STORED_RSP_OFFSET)"]\n"

        // restore registers
        "popfq\n"
        "pop r15\n"
        "pop r14\n"
        "pop r13\n"
        "pop r12\n"
        "pop r11\n"
        "pop r10\n"
        "pop rbp\n"
        "pop rbx\n"

        // return 0
        "mov rax, 0\n"
        "ret\n"
        "int3\n" // Silences objtool warnings about no int3 after ret
    );
}
// clang-format on

static void main_segment_template(void)
{
    asm volatile(".quad " xstr(TEMPLATE_START));
    prologue();

    SET_REGISTER_FROM_INPUT();
    PIPELINE_RESET();

    // test case placeholder
    asm volatile("\nlfence\n");
    asm volatile(".quad " xstr(TEMPLATE_INSERT_TC) "\n");
    asm volatile("\nmfence\n");

    // fault handler
    asm_volatile_intel(""
                       "jmp 1f\n"
                       ".quad " xstr(TEMPLATE_DEFAULT_EXCEPTION_LANDING) "\n"
                                                                         "1:nop; nop; nop\n");

    epilogue();
    asm volatile(".quad " xstr(TEMPLATE_END));
}

static void main_segment_template_dbg_gpr(void)
{
    asm volatile(".quad " xstr(TEMPLATE_START));
    prologue();

    SET_REGISTER_FROM_INPUT();
    PIPELINE_RESET();

    // test case placeholder
    asm volatile("\nlfence\n");
    asm volatile(".quad " xstr(TEMPLATE_INSERT_TC) "\n");
    asm volatile("\nmfence\n");

    asm_volatile_intel(""
                       "jmp 1f\n"
                       ".quad " xstr(TEMPLATE_DEFAULT_EXCEPTION_LANDING) "\n"
                                                                         "1:nop; nop; nop\n");

    epilogue_dbg_gpr();
    asm volatile(".quad " xstr(TEMPLATE_END));
}

// =================================================================================================
int init_code_loader(void)
{
    // NOTE: we assume the sandbox is already allocated by sandbox_manager
    return 0;
}

void free_code_loader(void) {}

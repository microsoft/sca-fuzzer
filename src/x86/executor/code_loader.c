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
//   R11 - hardware trace
//   R12 - SMI counter
//   R13 - temporary data for macros
//   R14 - sandbox base address
//

#include "code_loader.h"
#include "asm_snippets.h"
#include "macro_loader.h"
#include "main.h"
#include "sandbox_manager.h"
#include "shortcuts.h"
#include "test_case_parser.h"

#include "hw_features/fault_handler.h"

#define PER_SECTION_ALLOC_SIZE (MAX_EXPANDED_SECTION_SIZE + MAX_EXPANDED_MACROS_SIZE)
#define MAX_TEMPLATE_SIZE 0x1000 // for sanity checking

#define TEMPLATE_START                     0x0fff379000000000
#define TEMPLATE_INSERT_TC                 0x0fff2f9000000000
#define TEMPLATE_DEFAULT_EXCEPTION_LANDING 0x0fff479000000000
#define TEMPLATE_END                       0x0fff279000000000

#define JMP_32BIT_RELATIVE 0xE9

uint8_t *loaded_test_case_entry = NULL; // global

static uint8_t *main_actor_code = NULL;
static size_t main_macros_cursor = 0;
static size_t main_prologue_size = 0;

static int load_section_main(void);
static int load_section(int segment_id);
static tc_symbol_entry_t *get_section_macros_start(uint64_t section_id);
static uint64_t expand_macro(tc_symbol_entry_t *macro, uint8_t *jmp_location, uint8_t *macro_dest);
static uint64_t expand_section(uint64_t section_id, uint8_t *dest);

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
    int bytes_written = expand_section(section_id, (uint8_t *)&sandbox->code[section_id].section);
    if (bytes_written < 0)
        return -1;
    return 0;
}

static int load_section_main(void)
{
    uint64_t dest_cursor = 0;
    uint64_t main_template_cursor = 0;
    main_macros_cursor = 0;
    main_actor_code = (uint8_t *)&sandbox->code[0].section;

    // reset the code
    memset(&main_actor_code[0], 0x90, PER_SECTION_ALLOC_SIZE);

    // get the template
    uint8_t *template;
    if (dbg_gpr_mode)
        template = (uint8_t *)main_segment_template_dbg_gpr;
    else
        template = (uint8_t *)main_segment_template;

    // reset the fault handler
    fault_handler = NULL;

    // skip until the beginning of the template
    for (;; main_template_cursor++) {
        ASSERT(main_template_cursor < MAX_TEMPLATE_SIZE, "load_section_main; TEMPLATE_START");
        if (*(uint64_t *)&template[main_template_cursor] == TEMPLATE_START)
            break;
    }
    main_template_cursor += 8;

    // copy the first part of the template
    for (;; main_template_cursor++, dest_cursor++) {
        ASSERT(main_template_cursor < MAX_TEMPLATE_SIZE, "load_section_main; TEMPLATE_INSERT_TC");
        if (*(uint64_t *)&template[main_template_cursor] == TEMPLATE_INSERT_TC)
            break;
        main_actor_code[dest_cursor] = template[main_template_cursor];
    }
    main_template_cursor += 8;
    main_prologue_size = dest_cursor;

    // copy the test case into the template and expand macros
    ASSERT(test_case->metadata[0].owner == 0, "load_section_main");
    dest_cursor += expand_section(0, &main_actor_code[dest_cursor]);

    // write the handler
    for (;; main_template_cursor++, dest_cursor++) {
        ASSERT(main_template_cursor < MAX_TEMPLATE_SIZE, "load_section_main; EXCEPTION_LANDING");
        if (*(uint64_t *)&template[main_template_cursor] == TEMPLATE_DEFAULT_EXCEPTION_LANDING) {
            fault_handler = (char *)&main_actor_code[dest_cursor];

            // expand the macro that would collect htrace after the exception
            tc_symbol_entry_t measurement_end =
                (tc_symbol_entry_t){.id = MACRO_MEASUREMENT_END, .offset = 0, .owner = 0};
            uint8_t *macro_dest = &main_actor_code[MAX_EXPANDED_SECTION_SIZE + main_macros_cursor];

            main_macros_cursor += expand_macro(&measurement_end, fault_handler, macro_dest);
            dest_cursor += 5;
            break;
        }
        main_actor_code[dest_cursor] = template[main_template_cursor];
    }
    main_template_cursor += 8;

    // write the rest of the template
    for (;; main_template_cursor++, dest_cursor++) {
        ASSERT(main_template_cursor < MAX_TEMPLATE_SIZE, "load_section_main: TEMPLATE_END");
        if (*(uint64_t *)&template[main_template_cursor] == TEMPLATE_END)
            break;
        main_actor_code[dest_cursor] = template[main_template_cursor];
    }

    // sanity check
    ASSERT(dest_cursor < MAX_EXPANDED_SECTION_SIZE, "load_section_main");

    loaded_test_case_entry = main_actor_code;
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

/// @brief Expand a section into the destination buffer
/// @param section_id ID of the section to expand
/// @param dest Destination address
/// @return Number of bytes written to the destination buffer
static uint64_t expand_section(uint64_t section_id, uint8_t *dest)
{
    uint64_t src_cursor = 0;
    uint64_t dest_cursor = 0;
    uint64_t macros_dest_cursor = 0;
    uint8_t *macros_dest = sandbox->code[section_id].macros;

    // get the unexpanded section
    uint8_t *section = test_case->sections[section_id].code;
    size_t section_size = test_case->metadata[section_id].size;
    ASSERT(section_size <= MAX_SECTION_SIZE, "expand_section");

    tc_symbol_entry_t *macro = get_section_macros_start(section_id);
    if (macro == NULL) {
        // no macros to expand; just copy the code
        memcpy(dest, section, section_size);
        return section_size;
    }

    // otherwise, expand the macros
    for (src_cursor = 0; src_cursor < section_size; src_cursor++, dest_cursor++) {
        // PRINT_ERR("macro id: %lu, offset: %lu\n", macro->id, macro->offset);
        // PRINT_ERR("dest_cursor: 0x%lx, src_cursor: %lu, %lx\n", dest_cursor, src_cursor,
        //   section[src_cursor]);
        if (src_cursor == macro->offset) {
            // if we found a macro -> expand it
            ASSERT(macro->owner == section_id, "expand_section");
            ASSERT(macro->id != 0, "expand_section");
            macros_dest_cursor +=
                expand_macro(macro, &dest[dest_cursor], &macros_dest[macros_dest_cursor]);
            dest_cursor += 4;
            src_cursor += 4; // skip the remaining bytes of the current macro placeholder
            macro++;         // move to next macro

        } else {
            // otherwise -> just copy the code from the section
            dest[dest_cursor] = section[src_cursor];
        }
    }
    if (section_id == 0)
        main_macros_cursor = macros_dest_cursor;

    // ensure that we did not have an overrun
    ASSERT(src_cursor == section_size, "expand_section");
    ASSERT(macro - test_case->symbol_table <= test_case->symbol_table_size / sizeof(*macro) ||
               macro->owner != section_id,
           "expand_section");

    return dest_cursor;
}

/// @brief Expand a macro into the destination buffer (macro_dest) and replace the nop at
///        jmp_location with a relative jump to the expanded macro
/// @param macro Macro to expand
/// @param jmp_location Location of the nop that will be replaced with a relative jump
/// @param macro_dest Destination buffer for the expanded macro
/// @return Number of bytes written to the destination buffer
static uint64_t expand_macro(tc_symbol_entry_t *macro, uint8_t *jmp_location, uint8_t *macro_dest)
{
    ASSERT(macro->id != 0, "expand_macro");
    uint64_t dest_cursor = 0;

    // replace the nop with a relative 32-bit jump to the expanded macro
    uint32_t target = (uint32_t)(&macro_dest[dest_cursor] - jmp_location - 5);
    jmp_location[0] = JMP_32BIT_RELATIVE; // opcode of the jump
    *((uint32_t *)&jmp_location[1]) = target;

    // copy the macro into the destination
    uint8_t *macro_start;
    uint64_t macro_size;
    int err = get_macro_bounds(macro->id, &macro_start, &macro_size);
    CHECK_ERR("get_macro_bounds");

    dest_cursor += inject_macro_arguments(macro->id, macro->args, &macro_dest[dest_cursor]);
    memcpy(&macro_dest[dest_cursor], macro_start, macro_size);
    dest_cursor += macro_size;

    // insert a relative jump backwards
    target = (int32_t)(&jmp_location[5] - &macro_dest[dest_cursor] - 5);
    macro_dest[dest_cursor] = JMP_32BIT_RELATIVE; // opcode of the jump
    *((uint32_t *)&macro_dest[dest_cursor + 1]) = target;
    dest_cursor += 5;

    return dest_cursor;
}

/// @brief Dynamically generate code that passes arguments to a macro; the macros receive the
/// arguments in the R13 register
/// @param args Compressed representation of the arguments, as received from the test case
/// symbol table
/// @return Size of the generated code, in bytes
uint64_t inject_macro_arguments(uint64_t macro_type, uint64_t args, uint8_t *macro_dest)
{
    switch (macro_type) {
    case MACRO_MEASUREMENT_START:
    case MACRO_MEASUREMENT_END:
        return 0;
    case MACRO_SWITCH: {
        uint16_t section_id = args & 0xFFFF;
        uint16_t function_id = (args >> 16) & 0xFFFF;

        uint64_t actor_addr = (uint64_t)sandbox->code[section_id].section;
        if (section_id == 0)
            actor_addr += main_prologue_size;
        uint64_t function_addr = actor_addr + test_case->symbol_table[function_id].offset;

        // // movabs r13, function_addr
        // macro_dest[0] = 0x49;
        // macro_dest[1] = 0xbd;
        // *((uint64_t *)(macro_dest + 2)) = function_addr;
        uint32_t relative_offset = function_addr - (uint64_t)macro_dest - 5;
        // jmp offset
        macro_dest[0] = JMP_32BIT_RELATIVE;
        *((uint32_t *)(macro_dest + 1)) = relative_offset;

        return 5;
    }
    default:
        PRINT_ERRS("inject_macro_arguments", "macro_type %llu is not valid\n", macro_type);
        return 0;
    }
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

        // r14 <- input base address (stored in rdi, the first argument of measurement_code)
        "mov r14, rdi\n"

        // stored_rsp <- rsp
        "mov qword ptr [r14 - "xstr(STORED_RSP_OFFSET)"], rsp\n"

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
        "mov r15, 0\n"

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
        "lea rax, [r14 - "xstr(MEASUREMENT_OFFSET)"]\n"

        // if we see no interrupts, store the hardware trace (r11)
        // otherwise, store zero
        "cmp r12, 0; jne 1f \n"
        "   mov qword ptr [rax + 0x00], r11 \n"
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

        // rsp <- stored_rsp
        "mov rsp, qword ptr [r14 - "xstr(STORED_RSP_OFFSET)"]\n"

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

        // return
        "ret\n"
    );
}

static inline void epilogue_dbg_gpr(void)
{
    asm_volatile_intel(
        "lea r15, [r14 - "xstr(MEASUREMENT_OFFSET)"]\n"
        "mov qword ptr [r15 + 0x00], rax\n"
        "mov qword ptr [r15 + 0x08], rbx\n"
        "mov qword ptr [r15 + 0x10], rcx\n"
        "mov qword ptr [r15 + 0x18], rdx\n"
        "mov qword ptr [r15 + 0x20], rsi\n"
        "mov qword ptr [r15 + 0x28], rdi\n"

        // rsp <- stored_rsp
        "mov rsp, qword ptr [r14 - "xstr(STORED_RSP_OFFSET)"]\n"

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

        // return
        "ret\n"
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

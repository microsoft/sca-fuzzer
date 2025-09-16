/// File: x86 implementation of various macros as well as x86-specific code for
///       the macro loader (macro_expansion.c)
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "asm_snippets.h"
#include "fault_handler.h"
#include "page_tables_host.h"
#include "macro_expansion.h"
#include "main.h"
#include "page_tables_guest.h"
#include "sandbox_manager.h"
#include "shortcuts.h"
#include "svm.h"
#include "vmx.h"

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
// Helper functions
// =================================================================================================

/// @brief Get the address of a function within a section
/// @param section_id ID of the section
/// @param function_id ID of the function
/// @return Virtual address of the function
static uint64_t get_function_addr(int section_id, int function_id)
{
    uint64_t section_base = 0;

    if (actors[section_id].mode == MODE_HOST) {
        section_base = (uint64_t)sandbox->code[section_id].section;
    } else if (actors[section_id].mode == MODE_GUEST) {
        guest_memory_t *guest_memory = (guest_memory_t *)GUEST_V_MEMORY_START;
        section_base = (uint64_t)guest_memory->code.section;
    }

    // The code section of the main actor begins after a hardcoded prologue,
    // which we need to take into account when calculating the function address
    if (section_id == 0)
        section_base += get_main_prologue_size();

    return section_base + test_case->symbol_table[function_id].offset;
}

/// @brief Insert a sequence of instructions into dest that updates R14 to match
///        the actor owning section_id
/// @param section_id ID of the section
/// @param dest Pointer to the destination of the code sequence
/// @param cursor Current position in the destination buffer
/// @return Number of bytes written to the destination buffer
static uint64_t update_r14(int section_id, uint8_t *dest, uint64_t cursor)
{
    int old_cursor = cursor;

    // calculate the new R14 value
    uint64_t new_r14 = 0;
    if (actors[section_id].mode == MODE_HOST) {
        new_r14 = (uint64_t)sandbox->data[section_id].main_area;
    } else if (actors[section_id].mode == MODE_GUEST) {
        guest_memory_t *guest_memory = (guest_memory_t *)GUEST_V_MEMORY_START;
        new_r14 = (uint64_t)guest_memory->data.main_area;
    }

    // ASM: movabs r14, new_r14
    APPEND_BYTES_TO_DEST(0x49, 0xbe);
    APPEND_U64_TO_DEST(new_r14);
    return cursor - old_cursor;
}

/// @brief Insert a sequence of instructions into dest that updates R14 and RSP to match
///        the actor owning section_id
/// @param section_id ID of the section
/// @param dest Pointer to the destination of the code sequence
/// @param cursor Current position in the destination buffer
/// @return Number of bytes written to the destination buffer
static uint64_t update_mem_base_and_sp(int section_id, uint8_t *dest, uint64_t cursor)
{
    int old_cursor = cursor;
    cursor += update_r14(section_id, dest, cursor);

    // calculate the new RSP value
    uint64_t new_rsp = 0;
    if (actors[section_id].mode == MODE_HOST) {
        new_rsp = (uint64_t)sandbox->data[section_id].main_area + LOCAL_RSP_OFFSET;
    } else if (actors[section_id].mode == MODE_GUEST) {
        guest_memory_t *guest_memory = (guest_memory_t *)GUEST_V_MEMORY_START;
        new_rsp = (uint64_t)guest_memory->data.main_area + LOCAL_RSP_OFFSET;
    }

    // ASM: movabs rsp, new_rsp
    APPEND_BYTES_TO_DEST(0x48, 0xbc);
    APPEND_U64_TO_DEST(new_rsp);
    return cursor - old_cursor;
}

/// @brief Insert a sequence of instructions into dest that updates R15 to match the actor
///        owning section_id
/// @param section_id ID of the section
/// @param dest Pointer to the destination of the code sequence
/// @param cursor Current position in the destination buffer
/// @return Number of bytes written to the destination buffer
static uint64_t update_r15(int section_id, uint8_t *dest, uint64_t cursor)
{
    int old_cursor = cursor;

    // calculate the new R15 value
    uint64_t new_r15 = 0;
    if (actors[section_id].mode == MODE_HOST) {
        new_r15 = (uint64_t)sandbox->util;
    } else if (actors[section_id].mode == MODE_GUEST) {
        guest_memory_t *guest_memory = (guest_memory_t *)GUEST_V_MEMORY_START;
        new_r15 = (uint64_t)&guest_memory->util;
    }

    // ASM: movabs r15, new_r15
    APPEND_BYTES_TO_DEST(0x49, 0xbf);
    APPEND_U64_TO_DEST(new_r15);
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
    asm_volatile_intel(""                                                //
                       MACRO_PROLOGUE()                                  //
                       "lea rax, [r15 + " xstr(L1D_PRIMING_OFFSET) "]\n" //
                       PRIME("rax", "rbx", "rcx", "rdx", "32")           //
                       READ_PFC_START()                                  //
                       SET_SR_STARTED()                                  //
                       MACRO_EPILOGUE()                                  //
                       "lfence\n"                                        //
    );
    asm volatile(".quad " xstr(MACRO_END));
}

static void __attribute__((noipa)) body_macro_fast_prime(void)
{
    asm volatile(".quad " xstr(MACRO_START));
    asm_volatile_intel(""                                                //
                       MACRO_PROLOGUE()                                  //
                       "lea rax, [r15 + " xstr(L1D_PRIMING_OFFSET) "]\n" //
                       PRIME("rax", "rbx", "rcx", "rdx", "1")            //
                       READ_PFC_START()                                  //
                       SET_SR_STARTED()                                  //
                       MACRO_EPILOGUE()                                  //
                       "lfence\n"                                        //
    );
    asm volatile(".quad " xstr(MACRO_END));
}

static void __attribute__((noipa)) body_macro_partial_prime(void)
{
    asm volatile(".quad " xstr(MACRO_START));
    asm_volatile_intel(""                                                //
                       MACRO_PROLOGUE()                                  //
                       "lea rax, [r15 + " xstr(L1D_PRIMING_OFFSET) "]\n" //
                       PRIME_PARTIAL("rax", "rbx", "rcx", "rdx", "32")   //
                       READ_PFC_START()                                  //
                       SET_SR_STARTED()                                  //
                       MACRO_EPILOGUE()                                  //
                       "lfence\n"                                        //
    );
    asm volatile(".quad " xstr(MACRO_END));
}

static void __attribute__((noipa)) body_macro_fast_partial_prime(void)
{
    asm volatile(".quad " xstr(MACRO_START));
    asm_volatile_intel(""                                                //
                       MACRO_PROLOGUE()                                  //
                       "lea rax, [r15 + " xstr(L1D_PRIMING_OFFSET) "]\n" //
                       PRIME_PARTIAL("rax", "rbx", "rcx", "rdx", "1")    //
                       READ_PFC_START()                                  //
                       SET_SR_STARTED()                                  //
                       MACRO_EPILOGUE()                                  //
                       "lfence\n"                                        //
    );
    asm volatile(".quad " xstr(MACRO_END));
}

static void __attribute__((noipa)) body_macro_probe(void)
{
    asm volatile(".quad " xstr(MACRO_START));
    // clang-format off
    asm_volatile_intel(""
                       "cmp " STATUS_REGISTER_8 ", "xstr(STATUS_STARTED)"\n"
                       "jne 99f\n"
                       MACRO_PROLOGUE()
                       "push r15\n"
                       "lfence\n"
                       READ_PFC_END()
                       "lea r15, [r15 + " xstr(L1D_PRIMING_OFFSET) "]\n"
                       PROBE("r15", "rbx", "r11", HTRACE_REGISTER)
                       "pop r15\n"
                       "mov qword ptr [rsp - 8], 0 \n"
                       SET_SR_ENDED()
                       MACRO_EPILOGUE()
                       "99:\n"
    );
    // clang-format on
    asm volatile(".quad " xstr(MACRO_END));
}

// Flush + Reload and variants
static void __attribute__((noipa)) body_macro_flush(void)
{
    asm volatile(".quad " xstr(MACRO_START));
    asm_volatile_intel(""                  //
                       MACRO_PROLOGUE()    //
                       "lea rbx, [r14]\n"  //
                       FLUSH("rbx", "rax") //
                       READ_PFC_START()    //
                       SET_SR_STARTED()    //
                       MACRO_EPILOGUE()    //
                       "lfence\n"          //
    );
    asm volatile(".quad " xstr(MACRO_END));
}

static void __attribute__((noipa)) body_macro_reload(void)
{
    asm volatile(".quad " xstr(MACRO_START));
    // clang-format off
    asm_volatile_intel(""
                       "cmp " STATUS_REGISTER_8 ", "xstr(STATUS_STARTED)"\n"
                       "jne 98f\n"
                       MACRO_PROLOGUE()
                       "lfence\n"
                       READ_PFC_END()
                       RELOAD("r14", "rbx", "r11", HTRACE_REGISTER)
                       "mov rax, 1\n"
                       "shl rax, 63\n"
                       "or " HTRACE_REGISTER ", rax\n"
                       SET_SR_ENDED()
                       MACRO_EPILOGUE()
                       "98:\n"
    );
    // clang-format on
    asm volatile(".quad " xstr(MACRO_END));
}

// Time stamp counter
static void __attribute__((noipa)) body_macro_tsc_start(void)
{
    asm volatile(".quad " xstr(MACRO_START));
    asm_volatile_intel(""                                               //
                       MACRO_PROLOGUE()                                 //
                       "lfence; rdtsc; lfence\n"                        //
                       "shl rdx, 32\n"                                  //
                       "or rdx, rax\n"                                  //
                       "xor " HTRACE_REGISTER ", " HTRACE_REGISTER "\n" //
                       "sub " HTRACE_REGISTER ", rdx\n"                 //
                       "lfence\n"                                       //
                       READ_PFC_START()                                 //
                       SET_SR_STARTED()                                 //
                       MACRO_EPILOGUE()                                 //
                       "lfence\n"                                       //
    );
    asm volatile(".quad " xstr(MACRO_END));
}

static void __attribute__((noipa)) body_macro_tsc_end(void)
{
    asm volatile(".quad " xstr(MACRO_START));
    // clang-format off
    asm_volatile_intel(""
                       "cmp " STATUS_REGISTER_8 ", "xstr(STATUS_STARTED)"\n"
                       "jne 97f\n"
                       MACRO_PROLOGUE()
                       READ_PFC_END()
                       "lfence; rdtsc; lfence\n"
                       "shl rdx, 32\n"
                       "or rdx, rax\n"
                       "add " HTRACE_REGISTER ", rdx\n"
                       SET_SR_ENDED()
                       MACRO_EPILOGUE()
                       "97:\n"
    );
    // clang-format on
    asm volatile(".quad " xstr(MACRO_END));
}

// FAULT_HANDLER -------------------------------------------------------------------------------
static inline size_t start_macro_fault_handler(macro_args_t args, uint8_t *dest)
{
    size_t cursor = 0;

    ASSERT(NESTED_FAULT_OFFSET < (1 << 16), "inject_macro_configurable_part");
    ASSERT(args.owner == 0, "inject_macro_configurable_part");

    // Set new global address to the fault handler
    fault_handler = (char *)((uint64_t)dest + cursor);

    // Ensure that RSP, R14, and R15 are set to correct values after (potential) actor switch
    cursor += update_mem_base_and_sp(0, dest, cursor);
    cursor += update_r15(0, dest, cursor);

    // Check for nested faults; if so, explicitly crash the executor by calling INT 0x20
    //   ASM: cmp byte ptr [r15 + NESTED_FAULT_OFFSET], 0
    APPEND_BYTES_TO_DEST(0x49, 0x83, 0xbf);
    APPEND_U16_TO_DEST(NESTED_FAULT_OFFSET);
    APPEND_BYTES_TO_DEST(0x0, 0x0, 0x0);
    //   ASM: je [RIP + 9]
    APPEND_BYTES_TO_DEST(0x74, 0x09);
    //   ASM: dec byte ptr [r15 + NESTED_FAULT_OFFSET]
    APPEND_BYTES_TO_DEST(0x49, 0xff, 0x8f);
    APPEND_BYTES_TO_DEST(NESTED_FAULT_OFFSET & 0xFF, NESTED_FAULT_OFFSET >> 8, 0x00, 0x00);
    //   ASM: int 0x20
    APPEND_BYTES_TO_DEST(0xcd, 0x20);
    //   ASM: inc byte ptr [r15 + NESTED_FAULT_OFFSET]
    APPEND_BYTES_TO_DEST(0x49, 0xff, 0x87);
    APPEND_BYTES_TO_DEST(NESTED_FAULT_OFFSET & 0xFF, NESTED_FAULT_OFFSET >> 8, 0x00, 0x00);
    return cursor;
}

// FAULT_HANDLER_WITH_MEASUREMENT ------------------------------------------------------------------
static inline size_t start_macro_fault_handler_with_measurement(macro_args_t args, uint8_t *dest)
{
    size_t cursor = 0;
    cursor += update_r14(args.arg1, dest, cursor);
    cursor += update_r15(args.arg1, dest, cursor);
    return cursor;
}

// MACRO_SWITCH ------------------------------------------------------------------------------------
static inline size_t start_macro_switch(macro_args_t args, uint8_t *dest)
{
    size_t cursor = 0;
    // Update RSP and R14 to the addresses within the new actor's memory
    cursor += update_mem_base_and_sp(args.arg1, dest, cursor);

    // Determine the target address for the switch
    uint64_t switch_target = get_function_addr(args.arg1, args.arg2);
    uint32_t relative_offset = switch_target - (uint64_t)dest - cursor - 5;

    // Jump to the target address (in a different actor) via a relative offset
    // ASM: jmp [RIP + relative_offset]
    APPEND_BYTES_TO_DEST(0xe9);
    APPEND_U32_TO_DEST(relative_offset);
    return cursor;
}

// MACRO_SET_K2U_TARGET ----------------------------------------------------------------------------
static inline size_t start_macro_set_k2u_target(macro_args_t args, uint8_t *dest)
{
    size_t cursor = 0;

    // ASM: movabs r11, function_addr
    uint64_t function_addr = get_function_addr(args.arg1, args.arg2);
    APPEND_BYTES_TO_DEST(0x49, 0xbb);
    APPEND_U64_TO_DEST(function_addr);

    return cursor;
}

// MACRO_SWITCH_K2U --------------------------------------------------------------------------------
static inline size_t start_macro_switch_k2u(macro_args_t args, uint8_t *dest) { return 0; }

static void __attribute__((noipa)) body_macro_switch_k2u(void)
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

// MACRO_SET_U2K_TARGET ----------------------------------------------------------------------------
static inline size_t start_macro_set_u2k_target(macro_args_t args, uint8_t *dest)
{
    size_t cursor = 0;
    uint64_t function_addr = get_function_addr(args.arg1, args.arg2);
    uint32_t macro_stack_offset = -MACRO_STACK_TOP_OFFSET - 8;

    // ASM: mov [r14 - MACRO_STACK_TOP_OFFSET - 8],rsp
    APPEND_BYTES_TO_DEST(0x49, 0x89, 0xa6);
    APPEND_U32_TO_DEST(macro_stack_offset);
    // ASM: lea rsp,[r14 - MACRO_STACK_TOP_OFFSET - 8]
    APPEND_BYTES_TO_DEST(0x49, 0x8d, 0xa6);
    APPEND_U32_TO_DEST(macro_stack_offset);
    // ASM: push rax
    APPEND_U8_TO_DEST(0x50);
    // ASM: push rcx
    APPEND_U8_TO_DEST(0x51);
    // ASM: push rdx
    APPEND_U8_TO_DEST(0x52);
    // ASM: pushf
    APPEND_U8_TO_DEST(0x9c);
    // ASM: movabs rax, function_addr
    APPEND_BYTES_TO_DEST(0x48, 0xb8);
    APPEND_U64_TO_DEST(function_addr);
    // ASM: mov rdx, rax
    APPEND_BYTES_TO_DEST(0x48, 0x89, 0xc2);
    // ASM: shr rdx, 0x20
    APPEND_BYTES_TO_DEST(0x48, 0xc1, 0xea, 0x20);
    // ASM: movabs rcx, 0xc0000082
    APPEND_BYTES_TO_DEST(0x48, 0xb9);
    APPEND_U64_TO_DEST(0xc0000082);
    // ASM: wrmsr
    APPEND_BYTES_TO_DEST(0x0f, 0x30);
    // ASM: popf
    APPEND_U8_TO_DEST(0x9d);
    // ASM: mov qword ptr [rsp - 0x08], 0
    APPEND_BYTES_TO_DEST(0x48, 0xc7, 0x44, 0x24, 0xf8, 0x00, 0x00, 0x00, 0x00);
    // ASM: pop    rdx
    APPEND_U8_TO_DEST(0x5a);
    // ASM: mov qword ptr [rsp - 0x08], 0
    APPEND_BYTES_TO_DEST(0x48, 0xc7, 0x44, 0x24, 0xf8, 0x00, 0x00, 0x00, 0x00);
    // ASM: pop    rcx
    APPEND_U8_TO_DEST(0x59);
    // ASM: mov qword ptr [rsp - 0x08], 0
    APPEND_BYTES_TO_DEST(0x48, 0xc7, 0x44, 0x24, 0xf8, 0x00, 0x00, 0x00, 0x00);
    // ASM: pop    rax
    APPEND_U8_TO_DEST(0x58);
    // ASM: mov qword ptr [rsp - 0x08], 0
    APPEND_BYTES_TO_DEST(0x48, 0xc7, 0x44, 0x24, 0xf8, 0x00, 0x00, 0x00, 0x00);
    // ASM: pop    rsp
    APPEND_U8_TO_DEST(0x5c);

    return cursor;
}

// MACRO_SWITCH_U2K --------------------------------------------------------------------------------
static void __attribute__((noipa)) body_macro_switch_u2k(void)
{
    asm volatile(".quad " xstr(MACRO_START));
    asm_volatile_intel("syscall\n");
    asm volatile(".quad " xstr(MACRO_END));
}

// MACRO_SET_H2G_TARGET ----------------------------------------------------------------------------
static inline size_t start_macro_set_h2g_target(macro_args_t args, uint8_t *dest)
{
    size_t cursor = 0;

    if (cpuinfo->x86_vendor == X86_VENDOR_INTEL) {
        uint64_t function_addr = get_function_addr(args.arg1, args.arg2);
        uint64_t vmcs_hpa_addr = (uint64_t)&vmcs_hpas[args.arg1];

        // ASM: movabs r11, &vmcs_hpa
        APPEND_BYTES_TO_DEST(0x49, 0xbb);
        APPEND_U64_TO_DEST(vmcs_hpa_addr);
        // ASM: vmptrld [r11]
        APPEND_BYTES_TO_DEST(0x41, 0x0f, 0xc7, 0x33);
        // ASM: movabs r11, function_addr
        APPEND_BYTES_TO_DEST(0x49, 0xbb);
        APPEND_U64_TO_DEST(function_addr);

    } else if (cpuinfo->x86_vendor == X86_VENDOR_AMD) {
        uint64_t function_addr = get_function_addr(args.arg1, args.arg2);
        uint64_t vmcb_hva_addr = (uint64_t)&vmcb_hvas[args.arg1];

        // ASM: movabs r11, &vmcb_hva
        APPEND_BYTES_TO_DEST(0x49, 0xbb);
        APPEND_U64_TO_DEST(vmcb_hva_addr);
        // ASM: mov r11, [r11]
        APPEND_BYTES_TO_DEST(0x4d, 0x8b, 0x1b);
        // ASM: add r11, VMCB_RIP_OFFSET
        APPEND_BYTES_TO_DEST(0x49, 0x81, 0xc3);
        APPEND_U32_TO_DEST(VMCB_RIP_OFFSET);
        // ASM: mov dword ptr [r11], function_addr[0:31]
        APPEND_BYTES_TO_DEST(0x49, 0xc7, 0x03);
        APPEND_U32_TO_DEST(function_addr & 0xFFFFFFFF);
        // ASM: add r11, 4
        APPEND_BYTES_TO_DEST(0x49, 0x83, 0xc3, 0x04);
        // ASM: mov dword ptr [r11], function_addr[32:63]
        APPEND_BYTES_TO_DEST(0x49, 0xc7, 0x03);
        APPEND_U32_TO_DEST((function_addr >> 32) & 0xFFFFFFFF);
    }

    return cursor;
}

static void __attribute__((noipa)) body_macro_set_h2g_target(void)
{
    asm volatile(".quad " xstr(MACRO_START));
#if VENDOR_ID == 1
    asm_volatile_intel(""                      // r11 contains the target address
                       MACRO_PROLOGUE()        //
                       "mov rcx, 0x0000681e\n" // GUEST_RIP
                       "vmwrite rcx, r11 \n"   //
                       MACRO_EPILOGUE()        //
    );
#else
    // Nothing on AMD
#endif
    asm volatile(".quad " xstr(MACRO_END));
}

// MACRO_SWITCH_H2G --------------------------------------------------------------------------------
static inline size_t start_macro_switch_h2g(macro_args_t args, uint8_t *dest)
{
    size_t cursor = 0;
    if (cpuinfo->x86_vendor == X86_VENDOR_INTEL) {
        // Nothing for Intel
    } else if (cpuinfo->x86_vendor == X86_VENDOR_AMD) {
        // ASM: movabs rax, &vmcb_hpa
        APPEND_BYTES_TO_DEST(0x48, 0xb8);
        APPEND_U64_TO_DEST((uint64_t)&vmcb_hpas[args.arg1]);
    }
    return cursor;
}

static void __attribute__((noipa)) body_macro_switch_h2g(void)
{
    asm volatile(".quad " xstr(MACRO_START));
#if VENDOR_ID == 1
    asm_volatile_intel("vmresume\n");
#else
    asm_volatile_intel("" // rax contains the current VMCB pointer
                       "clgi\n"
                       "mov rax, qword ptr [rax]\n" //
                       "vmsave rax\n"               //
                       "vmrun rax\n"                //
                       "vmload rax\n"
                       "mov rax, 0\n" //
                       "stgi\n"       //
                       "");
#endif
    asm volatile(".quad " xstr(MACRO_END));
}

// MACRO_SET_G2H_TARGET ----------------------------------------------------------------------------
static inline size_t start_macro_set_g2h_target(macro_args_t args, uint8_t *dest)
{
    size_t cursor = 0;
    if (cpuinfo->x86_vendor == X86_VENDOR_INTEL) {
        // ASM: movabs r11, function_addr
        uint64_t function_addr = get_function_addr(args.arg1, args.arg2);
        APPEND_BYTES_TO_DEST(0x49, 0xbb);
        APPEND_U64_TO_DEST(function_addr);
    } else {
        // Nothing for AMD
    }
    return cursor;
}

static void __attribute__((noipa)) body_macro_set_g2h_target(void)
{
    asm volatile(".quad " xstr(MACRO_START));
#if VENDOR_ID == VENDOR_INTEL_
    asm_volatile_intel(""                      // r11 contains the target address
                       MACRO_PROLOGUE()        //
                       "mov rcx, 0x00006c16\n" // HOST_RIP
                       "vmwrite rcx, r11 \n"   //
                       MACRO_EPILOGUE()        //
    );
#else
    // Nothing on AMD
#endif
    asm volatile(".quad " xstr(MACRO_END));
}

// MACRO_SWITCH_G2H --------------------------------------------------------------------------------
static void __attribute__((noipa)) body_macro_switch_g2h(void)
{
    asm volatile(".quad " xstr(MACRO_START));
#if VENDOR_ID == 1
    asm_volatile_intel("vmcall\n");
#else
    asm_volatile_intel("vmmcall\n");
#endif
    asm volatile(".quad " xstr(MACRO_END));
}

// MACRO_LANDING_K2U -------------------------------------------------------------------------------
static inline size_t start_macro_landing_k2u(macro_args_t args, uint8_t *dest)
{
    size_t cursor = 0;
    cursor += update_mem_base_and_sp(args.owner, dest, cursor);
    // ASM: movabs rcx, 0  # rcx was corrupted during context switch; set to zero
    APPEND_BYTES_TO_DEST(0x48, 0xb9);
    APPEND_U64_TO_DEST(0);
    return cursor;
}

// MACRO_LANDING_U2K -------------------------------------------------------------------------------
static inline size_t start_macro_landing_u2k(macro_args_t args, uint8_t *dest)
{
    size_t cursor = 0;
    cursor += update_r14(args.owner, dest, cursor);
    // rsp is automatically restored by syscall instruction

    // ASM: movabs rcx, 0  # rcx was corrupted during context switch; set to zero
    APPEND_BYTES_TO_DEST(0x48, 0xb9);
    APPEND_U64_TO_DEST(0);

    return cursor;
}

// MACRO_LANDING_H2G -------------------------------------------------------------------------------
static inline size_t start_macro_landing_h2g(macro_args_t args, uint8_t *dest)
{
    size_t cursor = 0;
    cursor += update_r14(args.owner, dest, cursor);
    cursor += update_r15(args.owner, dest, cursor);

    if (cpuinfo->x86_vendor == X86_VENDOR_AMD) {
        // ASM: mov rax, 0
        APPEND_BYTES_TO_DEST(0x48, 0xc7, 0xc0, 0x00, 0x00, 0x00, 0x00);
    }
    return cursor;
}

// MACRO_LANDING_G2H -------------------------------------------------------------------------------
static inline size_t start_macro_landing_g2h(macro_args_t args, uint8_t *dest)
{
    size_t cursor = 0;
    cursor += update_r14(args.owner, dest, cursor);
    cursor += update_r15(args.owner, dest, cursor);

    if (cpuinfo->x86_vendor == X86_VENDOR_AMD) {
        // ASM: mov rax, 0
        APPEND_BYTES_TO_DEST(0x48, 0xc7, 0xc0, 0x00, 0x00, 0x00, 0x00);
    }

    return cursor;
}

// MACRO_SET_DATA_PERMISSIONS ----------------------------------------------------------------------
static inline size_t start_macro_set_data_permissions(macro_args_t args, uint8_t *dest)
{
    size_t cursor = 0;
    // get safe bits to set/clear
    uint16_t mask_set = args.arg2;
    uint16_t mask_clear = args.arg3;

    // get the target PTE
    int page_id = args.arg1 * N_DATA_PAGES_PER_ACTOR + FAULTY_PAGE_ID;
    pte_t_ *ptep = sandbox_pteps->data_pteps[page_id];
    ASSERT(ptep != NULL, "start_macro_set_data_permissions");

    uint32_t macro_stack_offset = -MACRO_STACK_TOP_OFFSET - 8;

    // Switch stack
    // ASM: mov [r14 - MACRO_STACK_TOP_OFFSET - 8],rsp
    APPEND_BYTES_TO_DEST(0x49, 0x89, 0xa6);
    APPEND_U32_TO_DEST(macro_stack_offset);
    // ASM: lea rsp,[r14 - MACRO_STACK_TOP_OFFSET - 8]
    APPEND_BYTES_TO_DEST(0x49, 0x8d, 0xa6);
    APPEND_U32_TO_DEST(macro_stack_offset);
    // ASM: push rax
    APPEND_U8_TO_DEST(0x50);

    // Get pointer to PTE
    // ASM: mov rax, ptep
    APPEND_BYTES_TO_DEST(0x48, 0xb8);
    APPEND_U64_TO_DEST((uint64_t)ptep);

    // Apply the set and clear masks to the lowest 16 bits of the PTE
    // note that we leave the remaining bits unchanged because arg2 and arg3 are 16-bit values
    //   ASM: or qword ptr [r11], mask_set
    APPEND_BYTES_TO_DEST(0x66, 0x81, 0x08);
    APPEND_U16_TO_DEST(mask_set);
    //   ASM: and qword ptr [r11], mask_clear
    APPEND_BYTES_TO_DEST(0x66, 0x81, 0x20);
    APPEND_U16_TO_DEST(mask_clear);

    // Restore stack
    // ASM: pop rax
    APPEND_U8_TO_DEST(0x58);
    // ASM: mov qword ptr [rsp - 0x08], 0
    APPEND_BYTES_TO_DEST(0x48, 0xc7, 0x44, 0x24, 0xf8, 0x00, 0x00, 0x00, 0x00);
    // ASM: pop rsp
    APPEND_U8_TO_DEST(0x5c);
    return cursor;
}

// =================================================================================================
// Macro descriptors
// =================================================================================================
macro_descr_t macro_descriptors[] = {
    [TYPE_UNDEFINED] = {.start = NULL, .body = NULL},
    [TYPE_PRIME] = {.start = NULL, .body = body_macro_prime},
    [TYPE_FAST_PRIME] = {.start = NULL, .body = body_macro_fast_prime},
    [TYPE_PARTIAL_PRIME] = {.start = NULL, .body = body_macro_partial_prime},
    [TYPE_FAST_PARTIAL_PRIME] = {.start = NULL, .body = body_macro_fast_partial_prime},
    [TYPE_PROBE] = {.start = NULL, .body = body_macro_probe},
    [TYPE_FLUSH] = {.start = NULL, .body = body_macro_flush},
    [TYPE_EVICT] = {.start = NULL, .body = body_macro_prime},
    [TYPE_RELOAD] = {.start = NULL, .body = body_macro_reload},
    [TYPE_TSC_START] = {.start = NULL, .body = body_macro_tsc_start},
    [TYPE_TSC_END] = {.start = NULL, .body = body_macro_tsc_end},
    [TYPE_FAULT_HANDLER] = {.start = start_macro_fault_handler, .body = NULL},
    [TYPE_FAULT_AND_PROBE] = {.start = start_macro_fault_handler_with_measurement,
                              .body = body_macro_probe},
    [TYPE_FAULT_AND_RELOAD] = {.start = start_macro_fault_handler_with_measurement,
                               .body = body_macro_reload},
    [TYPE_FAULT_AND_TSC_END] = {.start = start_macro_fault_handler_with_measurement,
                                .body = body_macro_tsc_end},
    [TYPE_SWITCH] = {.start = start_macro_switch, .body = NULL},
    [TYPE_SET_K2U_TARGET] = {.start = start_macro_set_k2u_target, .body = NULL},
    [TYPE_SWITCH_K2U] = {.start = start_macro_switch_k2u, .body = body_macro_switch_k2u},
    [TYPE_SET_U2K_TARGET] = {.start = start_macro_set_u2k_target, .body = NULL},
    [TYPE_SWITCH_U2K] = {.start = NULL, .body = body_macro_switch_u2k},
    [TYPE_SET_H2G_TARGET] = {.start = start_macro_set_h2g_target,
                             .body = body_macro_set_h2g_target},
    [TYPE_SWITCH_H2G] = {.start = start_macro_switch_h2g, .body = body_macro_switch_h2g},
    [TYPE_SET_G2H_TARGET] = {.start = start_macro_set_g2h_target,
                             .body = body_macro_set_g2h_target},
    [TYPE_SWITCH_G2H] = {.start = NULL, .body = body_macro_switch_g2h},
    [TYPE_LANDING_K2U] = {.start = start_macro_landing_k2u, .body = NULL},
    [TYPE_LANDING_U2K] = {.start = start_macro_landing_u2k, .body = NULL},
    [TYPE_LANDING_H2G] = {.start = start_macro_landing_h2g, .body = NULL},
    [TYPE_LANDING_G2H] = {.start = start_macro_landing_g2h, .body = NULL},
    [TYPE_SET_DATA_PERMISSIONS] = {.start = start_macro_set_data_permissions, .body = NULL},
};

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

// Types of macros
typedef enum {
    TYPE_UNDEFINED,
    TYPE_PRIME,
    TYPE_FAST_PRIME,
    TYPE_PARTIAL_PRIME,
    TYPE_FAST_PARTIAL_PRIME,
    TYPE_PROBE,
    TYPE_FLUSH,
    TYPE_EVICT,
    TYPE_RELOAD,
    TYPE_TSC_START,
    TYPE_TSC_END,
    TYPE_FAULT_HANDLER,
    TYPE_FAULT_AND_PROBE,
    TYPE_FAULT_AND_RELOAD,
    TYPE_FAULT_AND_TSC_END,
    TYPE_SWITCH,
    TYPE_SET_K2U_TARGET,
    TYPE_SWITCH_K2U,
    TYPE_SET_U2K_TARGET,
    TYPE_SWITCH_U2K,
    TYPE_SET_H2G_TARGET,
    TYPE_SWITCH_H2G,
    TYPE_SET_G2H_TARGET,
    TYPE_SWITCH_G2H,
    TYPE_LANDING_K2U,
    TYPE_LANDING_U2K,
    TYPE_LANDING_H2G,
    TYPE_LANDING_G2H,
    TYPE_SET_DATA_PERMISSIONS,
} macro_subtype_e;

// Descriptor of a macro
typedef struct {
    uint16_t arg1;
    uint16_t arg2;
    uint16_t arg3;
    uint16_t arg4;
    uint64_t owner;
} macro_args_t;

typedef struct {
    size_t (*start)(macro_args_t args, uint8_t *dest);
    void (*body)(void);
} macro_descr_t;

static size_t main_prologue_size = 0;

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
        section_base += main_prologue_size;

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
static uint64_t update_r14_rsp(int section_id, uint8_t *dest, uint64_t cursor)
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
void __attribute__((noipa)) body_macro_prime(void)
{
    asm volatile(".quad " xstr(MACRO_START));
    asm_volatile_intel(""                                                //
                       MACRO_PROLOGUE()                                  //
                       "lea rax, [r15 + " xstr(L1D_PRIMING_OFFSET) "]\n" //
                       PRIME("rax", "rbx", "rcx", "rdx", "32")           //
                       "xor " HTRACE_REGISTER ", " HTRACE_REGISTER "\n"  //
                       READ_PFC_START()                                  //
                       MACRO_EPILOGUE()                                  //
                       "lfence\n"                                        //
    );
    asm volatile(".quad " xstr(MACRO_END));
}

void __attribute__((noipa)) body_macro_fast_prime(void)
{
    asm volatile(".quad " xstr(MACRO_START));
    asm_volatile_intel(""                                                //
                       MACRO_PROLOGUE()                                  //
                       "lea rax, [r15 + " xstr(L1D_PRIMING_OFFSET) "]\n" //
                       PRIME("rax", "rbx", "rcx", "rdx", "1")            //
                       "xor " HTRACE_REGISTER ", " HTRACE_REGISTER "\n"  //
                       READ_PFC_START()                                  //
                       MACRO_EPILOGUE()                                  //
                       "lfence\n"                                        //
    );
    asm volatile(".quad " xstr(MACRO_END));
}

void __attribute__((noipa)) body_macro_partial_prime(void)
{
    asm volatile(".quad " xstr(MACRO_START));
    asm_volatile_intel(""                                                //
                       MACRO_PROLOGUE()                                  //
                       "lea rax, [r15 + " xstr(L1D_PRIMING_OFFSET) "]\n" //
                       PRIME_PARTIAL("rax", "rbx", "rcx", "rdx", "32")   //
                       "xor " HTRACE_REGISTER ", " HTRACE_REGISTER "\n"  //
                       READ_PFC_START()                                  //
                       MACRO_EPILOGUE()                                  //
                       "lfence\n"                                        //
    );
    asm volatile(".quad " xstr(MACRO_END));
}

void __attribute__((noipa)) body_macro_fast_partial_prime(void)
{
    asm volatile(".quad " xstr(MACRO_START));
    asm_volatile_intel(""                                                //
                       MACRO_PROLOGUE()                                  //
                       "lea rax, [r15 + " xstr(L1D_PRIMING_OFFSET) "]\n" //
                       PRIME_PARTIAL("rax", "rbx", "rcx", "rdx", "1")    //
                       "xor " HTRACE_REGISTER ", " HTRACE_REGISTER "\n"  //
                       READ_PFC_START()                                  //
                       MACRO_EPILOGUE()                                  //
                       "lfence\n"                                        //
    );
    asm volatile(".quad " xstr(MACRO_END));
}

void __attribute__((noipa)) body_macro_probe(void)
{
    asm volatile(".quad " xstr(MACRO_START));
    asm_volatile_intel(""                                                //
                       "cmp " HTRACE_REGISTER ", 0\n"                    // skip if already called
                       "jnz 99f\n"                                       //
                       "cmp " HTRACE_REGISTER ", -1\n"                   // skip if uninitialized
                       "je 99f\n"                                        //
                       MACRO_PROLOGUE()                                  //
                       "push r15\n"                                      //
                       "lfence\n"                                        //
                       READ_PFC_END()                                    //
                       "lea r15, [r15 + " xstr(L1D_PRIMING_OFFSET) "]\n" //
                       PROBE("r15", "rbx", "r11", HTRACE_REGISTER)       //
                       "pop r15\n"                                       //
                       "mov qword ptr [rsp - 8], 0 \n"                   //
                       MACRO_EPILOGUE()                                  //
                       "99:\n"                                           //
    );
    asm volatile(".quad " xstr(MACRO_END));
}

// Flush + Reload and variants
void __attribute__((noipa)) body_macro_flush(void)
{
    asm volatile(".quad " xstr(MACRO_START));
    asm_volatile_intel(""                  //
                       MACRO_PROLOGUE()    //
                       "lea rbx, [r14]\n"  //
                       FLUSH("rbx", "rax") //
                       READ_PFC_START()    //
                       MACRO_EPILOGUE()    //
                       "lfence\n"          //
    );
    asm volatile(".quad " xstr(MACRO_END));
}

void __attribute__((noipa)) body_macro_reload(void)
{
    asm volatile(".quad " xstr(MACRO_START));
    asm_volatile_intel(""                                           //
                       "cmp " HTRACE_REGISTER ", 0\n"               // skip if already called
                       "jnz 98f\n"                                  //
                       "cmp " HTRACE_REGISTER ", -1\n"              // skip if uninitialized
                       "je 98f\n"                                   //
                       MACRO_PROLOGUE()                             //
                       "lfence\n"                                   //
                       READ_PFC_END()                               //
                       RELOAD("r14", "rbx", "r11", HTRACE_REGISTER) //
                       "mov rax, 1\n"                               //
                       "shl rax, 63\n"                              //
                       "or " HTRACE_REGISTER ", rax\n"              //
                       MACRO_EPILOGUE()                             //
                       "98:\n"                                      //
    );
    asm volatile(".quad " xstr(MACRO_END));
}

// Time stamp counter
void __attribute__((noipa)) body_macro_tsc_start(void)
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
                       MACRO_EPILOGUE()                                 //
                       "lfence\n"                                       //
    );
    asm volatile(".quad " xstr(MACRO_END));
}

void __attribute__((noipa)) body_macro_tsc_end(void)
{
    asm volatile(".quad " xstr(MACRO_START));
    asm_volatile_intel(""                               //
                       "cmp " HTRACE_REGISTER ", 0\n"   // skip if already called
                       "jg 97f\n"                       //
                       "cmp " HTRACE_REGISTER ", -1\n"  // skip if uninitialized
                       "je 97f\n"                       //
                       MACRO_PROLOGUE()                 //
                       READ_PFC_END()                   //
                       "lfence; rdtsc; lfence\n"        //
                       "shl rdx, 32\n"                  //
                       "or rdx, rax\n"                  //
                       "add " HTRACE_REGISTER ", rdx\n" //
                       MACRO_EPILOGUE()                 //
                       "97:\n"                          //
    );
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
    cursor += update_r14_rsp(0, dest, cursor);
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
static inline size_t start_macro_fault_switch(macro_args_t args, uint8_t *dest)
{
    size_t cursor = 0;
    // Update RSP and R14 to the addresses within the new actor's memory
    cursor += update_r14_rsp(args.arg1, dest, cursor);

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

void __attribute__((noipa)) body_macro_switch_k2u(void)
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
void __attribute__((noipa)) body_macro_switch_u2k(void)
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
        APPEND_BYTES_TO_DEST(0x49, 0x8b, 0x1b);
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

void __attribute__((noipa)) body_macro_set_h2g_target(void)
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

void __attribute__((noipa)) body_macro_switch_h2g(void)
{
    asm volatile(".quad " xstr(MACRO_START));
#if VENDOR_ID == 1
    asm_volatile_intel("vmresume\n");
#else
    asm_volatile_intel("" // rax contains the current VMCB pointer
                       "clgi\n"
                       "mov rax, qword ptr [rax]\n" //
                       //    "vmload rax\n"               //  FIXME: causes a hang
                       "vmrun rax\n"  //
                       "vmsave rax\n" //
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

void __attribute__((noipa)) body_macro_set_g2h_target(void)
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
void __attribute__((noipa)) body_macro_switch_g2h(void)
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
    cursor += update_r14_rsp(args.owner, dest, cursor);
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
// Determining the macro subtype from the macro ID and current configuration
// =================================================================================================
// Lookup table for macro descriptors
static macro_descr_t macro_descriptors[] = {
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
    [TYPE_SWITCH] = {.start = start_macro_fault_switch, .body = NULL},
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

    return &macro_descriptors[macro_subtype];
}

// =================================================================================================
// Macro Loader
// =================================================================================================

/// @brief Dynamically generate the configurable part of the macro
/// @param[in] descr Pointer to the macro descriptor
/// @param[in] args Compressed representation of the macro arguments, as received from the test case
///            symbol table
/// @param[in] owner ID of the actor owning the macro
/// @param[out] dest Pointer to the destination buffer
/// @return Size of the added code, in bytes
uint64_t inject_macro_configurable_part(macro_descr_t *descr, uint64_t args, uint64_t owner,
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
uint64_t inject_macro_static_part(macro_descr_t *descr, uint8_t *dest)
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
    const int jmp_opcode_size = 5;

    // Get the macro type
    symbol_id_t type_id = macro->id;
    ASSERT(type_id != 0, "expand_macro");

    // Get the macro descriptor
    macro_descr_t *descr = get_macro_subtype_from_id(type_id);
    ASSERT(descr != NULL, "expand_macro");

    // Code area: Replace the NOP with a relative 32-bit jump to the expanded macro
    uint32_t target = (uint32_t)(&macro_dest[macro_cursor] - code_dest - jmp_opcode_size);
    code_dest[code_cursor++] = 0xe9; // start of the jump opcode
    *((uint32_t *)&code_dest[code_cursor]) = target;
    code_dest += 4;

    // Code area: Add a fence after the jump to prevent straight-line speculation
    code_dest[code_cursor++] = 0x0f;
    code_dest[code_cursor++] = 0xae;
    code_dest[code_cursor++] = 0xe8;

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
    target = (int32_t)(&code_dest[code_cursor] - &macro_dest[macro_cursor] - jmp_opcode_size);
    macro_dest[macro_cursor++] = 0xe9; // start of the jump opcode
    *((uint32_t *)&macro_dest[macro_cursor]) = target;
    macro_cursor += 4;

    // Macro area: Add a fence after this jump as well, also to prevent straight-line speculation
    macro_dest[macro_cursor++] = 0x0f;
    macro_dest[macro_cursor++] = 0xae;
    macro_dest[macro_cursor++] = 0xe8;

    *macro_size = macro_cursor;
    return 0;
}

/// @brief Setter for the module variable main_prologue_size
///        This interface is necessary because the main section does not set from offset zero,
///        and instead starts from a hardcoded prologue. To take this offset into account,
///        Code Loader passes the size of the prologue to the Macros Loader.
/// @param size
void set_main_prologue_size(size_t size) { main_prologue_size = size; }

// =================================================================================================
int init_macros_loader(void) { return 0; }

void free_macros_loader(void) {}

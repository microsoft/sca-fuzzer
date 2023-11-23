/// File: Management of test case macros
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "macro_loader.h"
#include "asm_snippets.h"
#include "hw_features/guest_memory.h"
#include "hw_features/vmx.h"
#include "main.h"
#include "sandbox_manager.h"
#include "shortcuts.h"
#include "test_case_parser.h"

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

void macro_same_context_switch(void);
void macro_switch_k2u(void);
void macro_switch_u2k(void);
void macro_set_k2u_target(void);
void macro_set_u2k_target(void);
void macro_switch_h2g(void);
void macro_switch_g2h(void);
void macro_set_h2g_target(void);
void macro_set_g2h_target(void);

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
    case MACRO_FAULT_HANDLER:
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
    case MACRO_SWITCH:
        return (uint8_t *)macro_same_context_switch;
    case MACRO_SWITCH_K2U:
        return (uint8_t *)macro_switch_k2u;
    case MACRO_SWITCH_U2K:
        return (uint8_t *)macro_switch_u2k;
    case MACRO_SET_K2U_TARGET:
        return (uint8_t *)macro_set_k2u_target;
    case MACRO_SET_U2K_TARGET:
        return (uint8_t *)macro_set_u2k_target;
    case MACRO_SWITCH_H2G:
        return (uint8_t *)macro_switch_h2g;
    case MACRO_SWITCH_G2H:
        return (uint8_t *)macro_switch_g2h;
    case MACRO_SET_H2G_TARGET:
        return (uint8_t *)macro_set_h2g_target;
    case MACRO_SET_G2H_TARGET:
        return (uint8_t *)macro_set_g2h_target;
    default:
        PRINT_ERRS("get_macro_wrapper_ptr", "macro_id %llu is not valid\n", macro_id);
        return NULL;
    }
}

/// @brief Get pointers to the start and the end of the macro
/// @param[in] macro_id ID of the macro in the macro table
/// @param[out] start Pointer to the start of the macro
/// @param[out] size Size of the macro, in bytes
/// @return -1 on error, 0 otherwise
int get_macro_bounds(uint64_t macro_id, uint8_t **start, uint64_t *size)
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

/// @brief Dynamically generate code that passes arguments to a macro; the macros receive the
/// arguments in the R11 register
/// @param args Compressed representation of the arguments, as received from the test case
/// symbol table
/// @return Size of the generated code, in bytes
uint64_t inject_macro_arguments(uint64_t macro_type, uint64_t args, uint8_t *macro_dest,
                                size_t main_prologue_size)
{
    size_t cursor = 0;
    uint16_t arg1 = args & 0xFFFF;
    uint16_t arg2 = (args >> 16) & 0xFFFF;
    // uint16_t arg3 = (args >> 32) & 0xFFFF;
    // uint16_t arg4 = (args >> 48) & 0xFFFF;

    switch (macro_type) {
    case MACRO_MEASUREMENT_START:
    case MACRO_MEASUREMENT_END:
        break;
    case MACRO_FAULT_HANDLER: {
        cursor += update_r14(arg1, macro_dest, cursor);
        cursor += update_r15(arg1, macro_dest, cursor);
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
    case MACRO_SWITCH_K2U: {
        cursor += update_r14_rsp(arg1, macro_dest, cursor);
        break;
    }
    case MACRO_SWITCH_U2K: {
        cursor += update_r14_rsp(arg1, macro_dest, cursor);
        break;
    }
    case MACRO_SET_K2U_TARGET: {
        // movabs rcx, function_addr
        uint64_t function_addr = get_function_addr(arg1, arg2, main_prologue_size);
        macro_dest[cursor] = 0x48;
        cursor++;
        macro_dest[cursor] = 0xb9;
        cursor++;
        *((uint64_t *)(macro_dest + cursor)) = function_addr;
        cursor += 8;
        break;
    }
    case MACRO_SET_H2G_TARGET: {
        // movabs r11, &vmcs_hpa
        macro_dest[cursor] = 0x49;
        cursor++;
        macro_dest[cursor] = 0xbb;
        cursor++;
        *((uint64_t **)(macro_dest + cursor)) = &vmcs_hpas[arg1];
        cursor += 8;

        // vmptrld [r11]
        macro_dest[cursor] = 0x41;
        cursor++;
        macro_dest[cursor] = 0x0f;
        cursor++;
        macro_dest[cursor] = 0xc7;
        cursor++;
        macro_dest[cursor] = 0x33;
        cursor++;

        // movabs r11, function_addr
        uint64_t function_addr = get_function_addr(arg1, arg2, main_prologue_size);
        macro_dest[cursor] = 0x49;
        cursor++;
        macro_dest[cursor] = 0xbb;
        cursor++;
        *((uint64_t *)(macro_dest + cursor)) = function_addr;
        cursor += 8;
        break;
    }
    case MACRO_SET_U2K_TARGET:
    case MACRO_SET_G2H_TARGET: {
        // movabs r11, function_addr
        uint64_t function_addr = get_function_addr(arg1, arg2, main_prologue_size);
        macro_dest[cursor] = 0x49;
        cursor++;
        macro_dest[cursor] = 0xbb;
        cursor++;
        *((uint64_t *)(macro_dest + cursor)) = function_addr;
        cursor += 8;
        break;
    }
    case MACRO_SWITCH_H2G: {
        cursor += update_r14(arg1, macro_dest, cursor);
        cursor += update_r15(arg1, macro_dest, cursor);
        // vmresume
        macro_dest[cursor] = 0x0f;
        cursor++;
        macro_dest[cursor] = 0x01;
        cursor++;
        macro_dest[cursor] = 0xc3;
        cursor++;
        // vmlaunch can fall through to the next instruction, so we need to restore R14
        cursor += update_r14(0, macro_dest, cursor);
        cursor += update_r15(0, macro_dest, cursor);
        break;
    }
    case MACRO_SWITCH_G2H: {
        cursor += update_r14(arg1, macro_dest, cursor);
        cursor += update_r15(arg1, macro_dest, cursor);
        break;
    }
    default:
        PRINT_ERRS("inject_macro_arguments", "macro_type %llu is not valid\n", macro_type);
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
                       PUSH_ABCDF()                                 //
                       "lfence\n"                                   //
                       READ_PFC_END()                               //
                       RELOAD("r14", "rbx", "r11", HTRACE_REGISTER) //
                       "mov rax, 1\n"                               //
                       "shl rax, 63\n"                              //
                       "or " HTRACE_REGISTER ", rax\n"              //
                       POP_ABCDF()                                  //
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
                       PUSH_ABCDF()                     //
                       READ_PFC_END()                   //
                       "lfence; rdtsc; lfence\n"        //
                       "shl rdx, 32\n"                  //
                       "or rdx, rax\n"                  //
                       "add " HTRACE_REGISTER ", rdx\n" //
                       POP_ABCDF()                      //
    );
    asm volatile(".quad " xstr(MACRO_END));
}

// =================================================================================================
// Macros: Context switches
// =================================================================================================

void __attribute__((noipa)) macro_same_context_switch(void)
{
    asm volatile(".quad " xstr(MACRO_START));
    // Nothing here; everything is implemented in inject_macro_arguments->MACRO_SWITCH
    asm volatile(".quad " xstr(MACRO_END));
}

void __attribute__((noipa)) macro_set_k2u_target(void)
{
    asm volatile(".quad " xstr(MACRO_START));
    // Nothing here: implementation in inject_macro_arguments->MACRO_SET_K2U_TARGET
    asm volatile(".quad " xstr(MACRO_END));
}

/// @brief Macro to switch host -> user actor
void __attribute__((noipa)) macro_switch_k2u(void)
{
    asm volatile(".quad " xstr(MACRO_START));
    asm_volatile_intel(""
                       "pushfq\n"
                       "pop r11\n"
                       "sysretq\n");
    asm volatile(".quad " xstr(MACRO_END));
}

void __attribute__((noipa)) macro_set_u2k_target(void)
{
    asm volatile(".quad " xstr(MACRO_START));
    asm_volatile_intel(""                      // r11 contains the target address
                       PUSH_ABCDF()            //
                       "mov rax, r11\n"        //
                       "mov rdx, r11\n"        //
                       "shr rdx, 32\n"         //
                       "mov rcx, 0xc0000082\n" //
                       "wrmsr\n"               //
                       POP_ABCDF()             //
    );
    asm volatile(".quad " xstr(MACRO_END));
}

/// @brief Macro to switch user -> host actor
void __attribute__((noipa)) macro_switch_u2k(void)
{
    asm volatile(".quad " xstr(MACRO_START));
    asm_volatile_intel(""
                       "syscall\n"
                       "");
    asm volatile(".quad " xstr(MACRO_END));
}

void __attribute__((noipa)) macro_switch_h2g(void)
{
    asm volatile(".quad " xstr(MACRO_START));
    // Nothing here: implementation in inject_macro_arguments->MACRO_SWITCH_H2G
    asm volatile(".quad " xstr(MACRO_END));
}

void __attribute__((noipa)) macro_switch_g2h(void)
{
    asm volatile(".quad " xstr(MACRO_START));
    asm_volatile_intel("vmcall\n");
    asm volatile(".quad " xstr(MACRO_END));
}

void __attribute__((noipa)) macro_set_h2g_target(void)
{
    asm volatile(".quad " xstr(MACRO_START));
    asm_volatile_intel(""                      // r11 contains the target address
                       PUSH_ABCDF()            //
                       "mov rcx, 0x0000681e\n" // GUEST_RIP
                       "vmwrite rcx, r11 \n"   //
                       POP_ABCDF()             //
    );
    asm volatile(".quad " xstr(MACRO_END));
}

void __attribute__((noipa)) macro_set_g2h_target(void)
{
    asm volatile(".quad " xstr(MACRO_START));
    asm_volatile_intel(""                      // r11 contains the target address
                       PUSH_ABCDF()            //
                       "mov rcx, 0x00006c16\n" // HOST_RIP
                       "vmwrite rcx, r11 \n"   //
                       POP_ABCDF()             //
    );
    asm volatile(".quad " xstr(MACRO_END));
}

// =================================================================================================
// Macros: VMX
// =================================================================================================

// Under construction

// =================================================================================================
int init_macros_loader(void) { return 0; }

void free_macros_loader(void) {}

/// File: Management of test case macros
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "macro.h"
#include "asm_snippets.h"
#include "main.h"
#include "sandbox.h"
#include "shortcuts.h"

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
        default:
            PRINT_ERRS("get_macro_wrapper_ptr", "misconfigured measurement_mode\n");
            return NULL;
        }
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
        default:
            PRINT_ERRS("get_macro_wrapper_ptr", "misconfigured measurement_mode\n");
            return NULL;
        }
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

// =================================================================================================
// Macros: Uarch measurements
// =================================================================================================
// clang-format off
#define PUSH_ABCDF()                                                                              \
    "mov r13, rsp\n"                                                                               \
    "lea rsp, [r14 + " xstr(MACRO_STACK_TOP_OFFSET) "]\n"                                          \
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
    "mov rsp, r13\n"
// clang-format on

#define HTRACE_REGISTER "r11"

void macro_measurement_start_prime(void)
{
    asm volatile(".quad " xstr(MACRO_START));
    asm_volatile_intel(""                                                 //
                       PUSH_ABCDF()                                       //
                       "lea rax, [r14 - " xstr(EVICT_REGION_OFFSET) "]\n" //
                       PRIME("rax", "rbx", "rcx", "rdx", "32")            //
                       READ_PFC_START()                                   //
                       POP_ABCDF()                                        //
                       "lfence\n"                                         //
    );
    asm volatile(".quad " xstr(MACRO_END));
}

void macro_measurement_start_fast_prime(void)
{
    asm volatile(".quad " xstr(MACRO_START));
    asm_volatile_intel(""                                                 //
                       PUSH_ABCDF()                                       //
                       "lea rax, [r14 - " xstr(EVICT_REGION_OFFSET) "]\n" //
                       PRIME("rax", "rbx", "rcx", "rdx", "1")             //
                       READ_PFC_START()                                   //
                       POP_ABCDF()                                        //
                       "lfence\n"                                         //
    );
    asm volatile(".quad " xstr(MACRO_END));
}

void macro_measurement_start_partial_prime(void)
{
    asm volatile(".quad " xstr(MACRO_START));
    asm_volatile_intel(""                                                 //
                       PUSH_ABCDF()                                       //
                       "lea rax, [r14 - " xstr(EVICT_REGION_OFFSET) "]\n" //
                       PRIME_PARTIAL("rax", "rbx", "rcx", "rdx", "32")    //
                       READ_PFC_START()                                   //
                       POP_ABCDF()                                        //
                       "lfence\n"                                         //
    );
    asm volatile(".quad " xstr(MACRO_END));
}

void macro_measurement_start_fast_partial_prime(void)
{
    asm volatile(".quad " xstr(MACRO_START));
    asm_volatile_intel(""                                                 //
                       PUSH_ABCDF()                                       //
                       "lea rax, [r14 - " xstr(EVICT_REGION_OFFSET) "]\n" //
                       PRIME_PARTIAL("rax", "rbx", "rcx", "rdx", "1")     //
                       READ_PFC_START()                                   //
                       POP_ABCDF()                                        //
                       "lfence\n"                                         //
    );
    asm volatile(".quad " xstr(MACRO_END));
}

void macro_measurement_end_probe(void)
{
    asm volatile(".quad " xstr(MACRO_START));
    asm_volatile_intel(""                                                 //
                       PUSH_ABCDF()                                       //
                       "push r15\n"                                       //
                       "push r13\n"                                       //
                       "lfence\n"                                         //
                       READ_PFC_END()                                     //
                       "lea r15, [r14 - " xstr(EVICT_REGION_OFFSET) "]\n" //
                       PROBE("r15", "rbx", "r13", HTRACE_REGISTER)        //
                       "pop r13\n"                                        //
                       "pop r15\n"                                        //
                       POP_ABCDF()                                        //
    );
    asm volatile(".quad " xstr(MACRO_END));
}

void macro_measurement_start_flush(void)
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

void macro_measurement_end_reload(void)
{
    asm volatile(".quad " xstr(MACRO_START));
    asm_volatile_intel(""                                           //
                       PUSH_ABCDF()                                 //
                       "push r15\n"                                 //
                       "push r13\n"                                 //
                       "lfence\n"                                   //
                       READ_PFC_END()                               //
                       "lea r15, [r14]\n"                           //
                       RELOAD("r15", "rbx", "r13", HTRACE_REGISTER) //
                       "mov rax, 1\n"                               //
                       "shl rax, 63\n"                              //
                       "or " HTRACE_REGISTER ", rax\n"              //
                       "pop r13\n"                                  //
                       "pop r15\n"                                  //
                       POP_ABCDF()                                  //
    );
    asm volatile(".quad " xstr(MACRO_END));
}

// =================================================================================================
// Macros: VMX
// =================================================================================================

// Under construction

// =================================================================================================
// Allocation and Initialization
// =================================================================================================
/// Constructor
int init_macros_manager(void) { return 0; }

/// Destructor
///
void free_macros_manager(void) {}

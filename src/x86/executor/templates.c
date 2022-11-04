/// File: Measurement templates for various threat models
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
//   R14 - sandbox base address
//

#include "main.h"
#include <linux/string.h>

#define TEMPLATE_ENTER 0x0fff379000000000
#define TEMPLATE_INSERT_TC 0x0fff2f9000000000
#define TEMPLATE_RETURN 0x0fff279000000000

#define xstr(s) _str(s)
#define _str(s) str(s)
#define str(s) #s

int load_template(size_t tc_size)
{
    unsigned template_pos = 0;
    unsigned code_pos = 0;

    // skip until the beginning of the template
    for (;; template_pos++)
    {
        if (template_pos >= MAX_MEASUREMENT_CODE_SIZE)
            return -1;

        if (*(uint64_t *)&measurement_template[template_pos] == TEMPLATE_ENTER)
        {
            template_pos += 8;
            break;
        }
    }

    // copy the first part of the template
    for (;; template_pos++, code_pos++)
    {
        if (template_pos >= MAX_MEASUREMENT_CODE_SIZE)
            return -1;

        if (*(uint64_t *)&measurement_template[template_pos] == TEMPLATE_INSERT_TC)
        {
            template_pos += 8;
            break;
        }

        measurement_code[code_pos] = measurement_template[template_pos];
    }

    // copy the test case into the template
    memcpy(&measurement_code[code_pos], test_case, tc_size);
    code_pos += tc_size;

    // write the rest of the template
    for (;; template_pos++, code_pos++)
    {
        if (template_pos >= MAX_MEASUREMENT_CODE_SIZE)
            return -2;

        if (*(uint64_t *)&measurement_template[template_pos] == TEMPLATE_INSERT_TC)
            return -3;

        if (*(uint64_t *)&measurement_template[template_pos] == TEMPLATE_RETURN)
            break;

        measurement_code[code_pos] = measurement_template[template_pos];
    }
    measurement_code[code_pos] = '\xC3'; // RET
    return code_pos;
}

// =================================================================================================
// Template building blocks
// =================================================================================================
// clang-format off
#define asm_volatile_intel(ASM) \
    asm volatile( \
    "\n.intel_syntax noprefix                  \n" \
    ASM \
    ".att_syntax noprefix                    ") \

// clobber: rax, rcx, rdx
#define READ_MSR_START(ID, DEST)                          \
        "mov rcx, "ID"                           \n"      \
        "lfence; rdmsr; lfence                   \n"      \
        "shl rdx, 32; or rdx, rax                \n"      \
        "sub "DEST", rdx                         \n"

// clobber: rax, rcx, rdx
#define READ_MSR_END(ID, DEST)                            \
        "mov rcx, "ID"                           \n"      \
        "lfence; rdmsr; lfence                   \n"      \
        "shl rdx, 32; or rdx, rax                \n"      \
        "add "DEST", rdx                         \n"

#define READ_SMI_START(DEST) READ_MSR_START("0x00000034", DEST)
#define READ_SMI_END(DEST) READ_MSR_END("0x00000034", DEST)

// clobber: rax, rcx, rdx
#define READ_PFC_ONE(ID) \
        "mov rcx, "ID" \n"      \
        "lfence; rdpmc; lfence \n" \
        "shl rdx, 32; or rdx, rax \n"

// clobber: rax, rcx, rdx
#define READ_PFC_START() \
        READ_PFC_ONE("1") \
        "sub r10, rdx \n" \
        READ_PFC_ONE("2") \
        "sub r9, rdx \n" \
        READ_PFC_ONE("3") \
        "sub r8, rdx \n"

// clobber: rax, rcx, rdx
#define READ_PFC_END() \
        READ_PFC_ONE("1") \
        "add r10, rdx \n" \
        READ_PFC_ONE("2") \
        "add r9, rdx \n" \
        READ_PFC_ONE("3") \
        "add r8, rdx \n"

// clobber: none
#define SB_FLUSH(TMP, REPS)                          \
        "mov "TMP", "REPS"                          \n" \
        "1: sfence                                  \n" \
        "dec "TMP"; jnz 1b                          \n"


#define SET_REGISTER_FROM_INPUT()\
    asm volatile("\n.intel_syntax noprefix\n" \
    "lea rsp, [r14 + "xstr(REG_INIT_OFFSET)"]\n" \
    "popq rax \n" \
    "popq rbx \n" \
    "popq rcx \n" \
    "popq rdx \n" \
    "popq rsi \n" \
    "popq rdi \n" \
    "popfq \n" \
    "popq rsp \n" \
    "mov rbp, rsp \n" \
    ".att_syntax noprefix");

inline void prologue(void)
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
        "mov qword ptr [r14 + "xstr(RSP_OFFSET)"], rsp\n"

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

        // start monitoring SMIs
        READ_SMI_START("r12"));
}

inline void epilogue(void)
{
    asm_volatile_intel(
        READ_SMI_END("r12")

        // rax <- &latest_measurement
        "lea rax, [r14 + "xstr(MEASUREMENT_OFFSET)"]\n"

        // if we see no SMI interrupts, store the hardware trace (r11)
        // otherwise, store zero
        "cmp r12, 0; jne 1f \n"
        "   mov qword ptr [rax], r11 \n"
        "   mov qword ptr [rax + 8], r10 \n"
        "   mov qword ptr [rax + 16], r9 \n"
        "   mov qword ptr [rax + 24], r8 \n"
        "   jmp 2f \n"
        "1: \n"
        "   mov qword ptr [rax], 0 \n"
        "2: \n"

        // rsp <- stored_rsp
        "mov rsp, qword ptr [r14 + "xstr(RSP_OFFSET)"]\n"

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
    );
}

// =================================================================================================
// L1D Prime+Probe
// =================================================================================================
// TODO: generate this code dynamically
#if L1D_ASSOCIATIVITY == 8
// clobber: none
#define PRIME(BASE, OFFSET, TMP, COUNTER, REPS)                 \
        "mfence                                             \n" \
        "mov "COUNTER", "REPS"                              \n" \
        "   1: mov "OFFSET", 0                              \n" \
        "       2: lfence                                   \n" \
        "       mov "TMP", "OFFSET"                ; mfence \n" \
        "       add "TMP", ["BASE" + "TMP"]        ; mfence \n" \
        "       add "TMP", ["BASE" + "TMP" + 4096] ; mfence \n" \
        "       add "TMP", ["BASE" + "TMP" + 8192] ; mfence \n" \
        "       add "TMP", ["BASE" + "TMP" + 12288]; mfence \n" \
        "       add "TMP", ["BASE" + "TMP" + 16384]; mfence \n" \
        "       add "TMP", ["BASE" + "TMP" + 20480]; mfence \n" \
        "       add "TMP", ["BASE" + "TMP" + 24576]; mfence \n" \
        "       add "TMP", ["BASE" + "TMP" + 28672]; mfence \n" \
        "       add "OFFSET", 64                            \n" \
        "   cmp "OFFSET", 4096; jl 2b                       \n" \
        "dec "COUNTER"; jnz 1b                              \n" \
        "mfence;                                            \n"

// clobber: rax, rcx, rdx
#define PROBE(BASE, OFFSET, TMP, DEST)                  \
        "xor "DEST", "DEST"                         \n" \
        "xor "OFFSET", "OFFSET"                     \n" \
        "1: lfence                                  \n" \
        "   xor "TMP", "TMP"                        \n" \
        "   mov rcx, 0                              \n" \
        "   mfence; rdpmc; mfence                   \n" \
        "   shl rdx, 32; or rdx, rax                \n" \
        "   sub "TMP", rdx                          \n" \
        "   mov rax, "OFFSET"                       \n" \
        "   add rax, ["BASE" + rax]        ; mfence \n" \
        "   add rax, ["BASE" + rax + 4096] ; mfence \n" \
        "   add rax, ["BASE" + rax + 8192] ; mfence \n" \
        "   add rax, ["BASE" + rax + 12288]; mfence \n" \
        "   add rax, ["BASE" + rax + 16384]; mfence \n" \
        "   add rax, ["BASE" + rax + 20480]; mfence \n" \
        "   add rax, ["BASE" + rax + 24576]; mfence \n" \
        "   add rax, ["BASE" + rax + 28672]; mfence \n" \
        "   mov rcx, 0                              \n" \
        "   mfence; rdpmc; mfence                   \n" \
        "   shl rdx, 32; or rdx, rax                \n" \
        "   add "TMP", rdx                          \n" \
        "   cmp "TMP", 8; jl 2f                     \n" \
        "      shl "DEST", 1                        \n" \
        "      jmp 3f                               \n" \
        "   2:                                      \n" \
        "      shl "DEST", 1                        \n" \
        "      or "DEST", 1                         \n" \
        "   3:                                      \n" \
        "   add "OFFSET", 64                        \n" \
        "cmp "OFFSET", 4096; jl 1b                  \n"
#elif L1D_ASSOCIATIVITY == 12
#define PRIME(BASE, OFFSET, TMP, COUNTER, REPS)                 \
        "mfence                                             \n" \
        "mov "COUNTER", "REPS"                              \n" \
        "   1: mov "OFFSET", 0                              \n" \
        "       2: lfence                                   \n" \
        "       mov "TMP", "OFFSET"                         \n" \
        "       add "TMP", ["BASE" + "TMP"]                 \n" \
        "       add "TMP", ["BASE" + "TMP" + 4096]          \n" \
        "       add "TMP", ["BASE" + "TMP" + 8192]          \n" \
        "       add "TMP", ["BASE" + "TMP" + 12288]         \n" \
        "       add "TMP", ["BASE" + "TMP" + 16384]         \n" \
        "       add "TMP", ["BASE" + "TMP" + 20480]         \n" \
        "       add "TMP", ["BASE" + "TMP" + 24576]         \n" \
        "       add "TMP", ["BASE" + "TMP" + 28672]         \n" \
        "       add "TMP", ["BASE" + "TMP" + 32768]         \n" \
        "       add "TMP", ["BASE" + "TMP" + 36864]         \n" \
        "       add "TMP", ["BASE" + "TMP" + 40960]         \n" \
        "       add "TMP", ["BASE" + "TMP" + 45056]         \n" \
        "       add "OFFSET", 64                            \n" \
        "   cmp "OFFSET", 4096; jl 2b                       \n" \
        "dec "COUNTER"; jnz 1b                              \n" \
        "mfence;                                            \n"

#define PROBE(BASE, OFFSET, TMP, DEST)                  \
        "xor "DEST", "DEST"                         \n" \
        "xor "OFFSET", "OFFSET"                     \n" \
        "1:                                         \n" \
        "   xor "TMP", "TMP"                        \n" \
        "   mov rcx, 0                              \n" \
        "   mfence; rdpmc; lfence                   \n" \
        "   shl rdx, 32; or rdx, rax                \n" \
        "   sub "TMP", rdx                          \n" \
        "   mov rax, "OFFSET"                       \n" \
        "   add rax, ["BASE" + rax]                 \n" \
        "   add rax, ["BASE" + rax + 4096]          \n" \
        "   add rax, ["BASE" + rax + 8192]          \n" \
        "   add rax, ["BASE" + rax + 12288]         \n" \
        "   add rax, ["BASE" + rax + 16384]         \n" \
        "   add rax, ["BASE" + rax + 20480]         \n" \
        "   add rax, ["BASE" + rax + 24576]         \n" \
        "   add rax, ["BASE" + rax + 28672]         \n" \
        "   add rax, ["BASE" + rax + 32768]         \n" \
        "   add rax, ["BASE" + rax + 36864]         \n" \
        "   add rax, ["BASE" + rax + 40960]         \n" \
        "   add rax, ["BASE" + rax + 45056]         \n" \
        "   mov rcx, 0                              \n" \
        "   lfence; rdpmc; mfence                   \n" \
        "   shl rdx, 32; or rdx, rax                \n" \
        "   add "TMP", rdx                          \n" \
        "   cmp "TMP", 12; jne 2f                    \n" \
        "      shl "DEST", 1                        \n" \
        "      jmp 3f                               \n" \
        "   2:                                      \n" \
        "      shl "DEST", 1                        \n" \
        "      or "DEST", 1                         \n" \
        "   3:                                      \n" \
        "   add "OFFSET", 64                        \n" \
        "cmp "OFFSET", 4096; jl 1b                  \n"
#endif

void template_l1d_prime_probe(void) {
    asm volatile(".quad "xstr(TEMPLATE_ENTER));
    prologue();

    // Prime
    // clobber: rax, rbx, rcx, rdx
    asm_volatile_intel(""\
        "lea rax, [r14 - "xstr(EVICT_REGION_OFFSET)"]\n"
        PRIME("rax", "rbx", "rcx", "rdx", "32"));

    // Deprecated?
    // Push empty values into the store buffer (just in case)
    // clobber: rax
    // asm_volatile_intel(SB_FLUSH("rax", "60"));

    // PFC
    // clobber: rax, rcx, rdx
    asm_volatile_intel(READ_PFC_START());

    // // Initialize registers
    SET_REGISTER_FROM_INPUT();

    // Execute the test case
    asm("\nlfence\n"
        ".quad "xstr(TEMPLATE_INSERT_TC)" \n"
        "mfence\n");

    // PFC
    asm_volatile_intel(READ_PFC_END());

    // Probe and store the resulting eviction bitmap map into r11
    // Note: it internally clobbers rcx, rdx, rax
    asm_volatile_intel(""\
        "lea r15, [r14 - "xstr(EVICT_REGION_OFFSET)"]\n"
        PROBE("r15", "rbx", "r13", "r11"));

    epilogue();
    asm volatile(".quad "xstr(TEMPLATE_RETURN));
}

// =================================================================================================
// L1D Flush+Reload
// =================================================================================================
#define FLUSH(BASE, OFFSET) \
        "mfence                                     \n" \
        "mov "OFFSET", 0                            \n" \
        "1: lfence                                  \n" \
        "   clflush qword ptr ["BASE" + "OFFSET"]   \n" \
        "   add "OFFSET", 64                        \n" \
        "cmp "OFFSET", 4096; jl 1b                  \n" \
        "mfence                                     \n"

#define RELOAD(BASE, OFFSET, TMP, DEST)                 \
        "xor "DEST", "DEST"                         \n" \
        "xor "OFFSET", "OFFSET"                     \n" \
        "1:                                         \n" \
        "   xor "TMP", "TMP"                        \n" \
        "   mov rcx, 0                              \n" \
        "   mfence; rdpmc; lfence                   \n" \
        "   shl rdx, 32; or rdx, rax                \n" \
        "   sub "TMP", rdx                          \n" \
        "   mov rax, qword ptr ["BASE" + "OFFSET"]  \n" \
        "   mov rcx, 0                              \n" \
        "   lfence; rdpmc; mfence                   \n" \
        "   shl rdx, 32; or rdx, rax                \n" \
        "   add "TMP", rdx                          \n" \
        "   cmp "TMP", 0; jne 2f                    \n" \
        "      shl "DEST", 1                        \n" \
        "      jmp 3f                               \n" \
        "   2:                                      \n" \
        "      shl "DEST", 1                        \n" \
        "      or "DEST", 1                         \n" \
        "   3:                                      \n" \
        "   add "OFFSET", 64                        \n" \
        "cmp "OFFSET", 4096; jl 1b                  \n"

void template_l1d_flush_reload(void) {
    asm volatile(".quad "xstr(TEMPLATE_ENTER));
    prologue();

    // Flush
    asm_volatile_intel(
        "mov rbx, r14\n" \
        FLUSH("rbx", "rax"));

    // Deprecated?
    // Push empty values into the store buffer (just in case)
    // asm_volatile_intel(SB_FLUSH("rax", "60"));

    // PFC
    asm_volatile_intel(READ_PFC_START());

    // Initialize registers
    SET_REGISTER_FROM_INPUT();

    // Execute the test case
    asm("lfence\n"
        ".quad "xstr(TEMPLATE_INSERT_TC)"\n"
        "mfence\n");

    // PFC
    asm_volatile_intel(READ_PFC_END());

    // Reload
    // Note: it internally clobbers rcx, rdx, rax
    asm_volatile_intel(
        "mov r15, r14\n" \
        RELOAD("r15", "rbx", "r13", "r11"));

    epilogue();
    asm volatile(".quad "xstr(TEMPLATE_RETURN));
}

void template_l1d_evict_reload(void) {
    asm volatile(".quad "xstr(TEMPLATE_ENTER));
    prologue();

    // Prime
    asm_volatile_intel(""\
        "lea rax, [r14 - "xstr(EVICT_REGION_OFFSET)"]\n"
        PRIME("rax", "rbx", "rcx", "rdx", "32"));

    // Deprecated?
    // Push empty values into the store buffer (just in case)
    // asm_volatile_intel(SB_FLUSH("rax", "60"));

    // PFC
    asm_volatile_intel(READ_PFC_START());

    // Initialize registers
    SET_REGISTER_FROM_INPUT();

    // Execute the test case
    asm("lfence\n"
        ".quad "xstr(TEMPLATE_INSERT_TC)" \n"
        "mfence\n");

    // PFC
    asm_volatile_intel(READ_PFC_END());

    // Reload
    // Note: it internally clobbers rcx, rdx, rax
    asm_volatile_intel(
        "mov r15, r14\n" \
        RELOAD("r15", "rbx", "r13", "r11"));

    epilogue();
    asm volatile(".quad "xstr(TEMPLATE_RETURN));
}

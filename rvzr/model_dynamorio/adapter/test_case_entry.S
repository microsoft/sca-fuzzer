.intel_syntax noprefix

#include "sandbox_const.h"
#define xstr(s) _str(s)
#define _str(s) str(s)
#define str(s)  #s

// =================================================================================================
.text

/// @brief Placeholder for the test case code; This will be dynamically populated at runtime
///        by sandbox.c
///        At compile time, a zero-filled area of size TEST_CASE_MAX_SIZE is reserved here.
/// r15: Address of test case code
.global test_case_entry
.align PAGE_SIZE
test_case_entry:
    .rept TEST_CASE_MAX_SIZE
    .byte 0
    .endr


/// @brief Outer wrapper to set up registers and FLAGS
///        See docs/devel/registers.md for the explanation of the initialized registers
/// rdi: Base address of sandbox main_area
/// rsi: Base address of test case code
.global test_case_entry_outer
.align PAGE_SIZE
test_case_entry_outer:
    pushfq
    push rbx
    push rcx
    push rdx
    push r14
    push r15
    push rsp

    // Save arguments
    mov r14, rdi
    mov r15, rsi

    // Initialize FLAGS
    mov rax, qword ptr [r14 + REG_INIT_OFFSET + EFLAGS_INIT_ID * GPR_SIZE]
    push rax
    popfq

    // Stack pointer
    // push rsp
    // mov rax, qword ptr [r14 + xstr(REG_INIT_OFFSET + RSP_INIT_ID * GPR_SIZE)]
    // mov rsp, rax

    // Initialize registers
    mov rax, qword ptr [r14 + REG_INIT_OFFSET + 0x00]
    mov rbx, qword ptr [r14 + REG_INIT_OFFSET + 0x08]
    mov rcx, qword ptr [r14 + REG_INIT_OFFSET + 0x10]
    mov rdx, qword ptr [r14 + REG_INIT_OFFSET + 0x18]
    mov rsi, qword ptr [r14 + REG_INIT_OFFSET + 0x20]
    mov rdi, qword ptr [r14 + REG_INIT_OFFSET + 0x28]

    // Initialize MMX registers
    movq mm0, qword ptr [r14 + SIMD_INIT_OFFSET + 0x00]
    movq mm1, qword ptr [r14 + SIMD_INIT_OFFSET + 0x08]
    movq mm2, qword ptr [r14 + SIMD_INIT_OFFSET + 0x10]
    movq mm3, qword ptr [r14 + SIMD_INIT_OFFSET + 0x18]
    movq mm4, qword ptr [r14 + SIMD_INIT_OFFSET + 0x20]
    movq mm5, qword ptr [r14 + SIMD_INIT_OFFSET + 0x28]
    movq mm6, qword ptr [r14 + SIMD_INIT_OFFSET + 0x30]
    movq mm7, qword ptr [r14 + SIMD_INIT_OFFSET + 0x38]

    // Initialize YMM registers (overlap with MMX init values is intentional)
    vmovdqa ymm0, ymmword ptr [r14 + SIMD_INIT_OFFSET + 0x00]
    vmovdqa ymm1, ymmword ptr [r14 + SIMD_INIT_OFFSET + 0x20]
    vmovdqa ymm2, ymmword ptr [r14 + SIMD_INIT_OFFSET + 0x40]
    vmovdqa ymm3, ymmword ptr [r14 + SIMD_INIT_OFFSET + 0x60]
    vmovdqa ymm4, ymmword ptr [r14 + SIMD_INIT_OFFSET + 0x80]
    vmovdqa ymm5, ymmword ptr [r14 + SIMD_INIT_OFFSET + 0xa0]
    vmovdqa ymm6, ymmword ptr [r14 + SIMD_INIT_OFFSET + 0xc0]
    vmovdqa ymm7, ymmword ptr [r14 + SIMD_INIT_OFFSET + 0xe0]

    call r15

    pop rsp
    pop r15
    pop r14
    pop rdx
    pop rcx
    pop rbx
    popfq

    ret




.intel_syntax noprefix
.test_case_enter:
.section .data.main

.function_start:
    # delay on rbx
    lea rbx, qword ptr [rbx + rcx + 1]
    lea rbx, qword ptr [rbx + rcx + 1]
    lea rbx, qword ptr [rbx + rcx + 1]
    lea rbx, qword ptr [rbx + rcx + 1]
    lea rbx, qword ptr [rbx + rcx + 1]
    lea rbx, qword ptr [rbx + rcx + 1]
    lea rbx, qword ptr [rbx + rcx + 1]
    lea rbx, qword ptr [rbx + rcx + 1]
    lea rbx, qword ptr [rbx + rcx + 1]
    lea rbx, qword ptr [rbx + rcx + 1]
    and rbx, 0b1

    .macro.switch.actor2.function_1:
# end of function_start
# --------------------------------------------------------------------------------------------------

.function_fin:
    .bb0:
    nop
# end of function_fin
# --------------------------------------------------------------------------------------------------

.section .data.actor2
.function_1:
    # a typical spectre v1 gadget
    jz .l3
    .l1:
        # mask the memory access
        and rax, 0b111111000000
        mov rax, qword ptr [r14 + rax]
    jmp .l3
    .l2:
        # mov rax, qword ptr [r14 + 0x100]
    .l3:

    and rdx, 0b111111000000
    mov rax, qword ptr [r14 + rdx]
    mov rsi, 0x42

    .macro.switch.main.function_fin:
# end of function_1
# --------------------------------------------------------------------------------------------------

.test_case_exit:

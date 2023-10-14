.intel_syntax noprefix
.test_case_enter:
.section .data.main

.function_start:
    # delay on rbx
    LEA rbx, qword ptr [rbx + rcx + 1]
    LEA rbx, qword ptr [rbx + rcx + 1]
    LEA rbx, qword ptr [rbx + rcx + 1]
    LEA rbx, qword ptr [rbx + rcx + 1]
    LEA rbx, qword ptr [rbx + rcx + 1]
    LEA rbx, qword ptr [rbx + rcx + 1]
    LEA rbx, qword ptr [rbx + rcx + 1]
    LEA rbx, qword ptr [rbx + rcx + 1]
    LEA rbx, qword ptr [rbx + rcx + 1]
    LEA rbx, qword ptr [rbx + rcx + 1]
    AND rbx, 0b1

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
    JZ .l3
    .l1:
        # mask the memory access
        AND rax, 0b111111000000
        MOV rax, qword ptr [r14 + rax]
    JMP .l3
    .l2:
        # MOV rax, qword ptr [r14 + 0x100]
    .l3:

    AND rdx, 0b111111000000
    MOV rax, qword ptr [r14 + rdx]
    MOV rsi, 0x42

    .macro.switch.main.function_fin:
# end of function_1
# --------------------------------------------------------------------------------------------------

.test_case_exit:

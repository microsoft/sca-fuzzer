.intel_syntax noprefix
.test_case_enter:
.section .data.main
.function_main:
.macro.measurement_start: nop dword ptr [rax + rax * 1 + 1]
AND RAX, 0b1111111111111 # instrumentation
OR EBX, dword ptr [R14 + RAX]  # speculation source ?
MOV AL, BL
XOR AX, -2067
TEST AL, -117 # instrumentation
AND RAX, 0b1111111111111 # instrumentation
MOV qword ptr [R14 + RAX], RCX  # speculation sink ?
.section .data.main
.function_end:
.macro.measurement_end: nop dword ptr [rax + rax * 1 + 1]
.section .data.main
.test_case_exit:nop

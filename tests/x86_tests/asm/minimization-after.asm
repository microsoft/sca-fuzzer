.intel_syntax noprefix
.test_case_enter:
.section .data.main
.function_main:
.macro.measurement_start: nop dword ptr [rax + rax * 1 + 1]
and rax, 0b1111111111111 # instrumentation
or ebx, dword ptr [r14 + rax]  # speculation source ?
mov al, bl
xor ax, -2067
test al, -117 # instrumentation
and rax, 0b1111111111111 # instrumentation
mov qword ptr [r14 + rax], rcx  # speculation sink ?
.section .data.main
.function_end:
.macro.measurement_end: nop dword ptr [rax + rax * 1 + 1]
.section .data.main
.test_case_exit:nop

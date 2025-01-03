.intel_syntax noprefix
.section .data.main
.function_main:
.macro.measurement_start: nop qword ptr [rax + 0xff]
and rax, 0b1111111111111 # instrumentation
or ebx, dword ptr [r14 + rax]  # speculation source ?
mov al, bl
xor ax, -2067
test al, -117 # instrumentation
and rax, 0b1111111111111 # instrumentation
mov qword ptr [r14 + rax], rcx  # speculation sink ?
.section .data.main
.function_end:
.macro.measurement_end: nop qword ptr [rax + 0xff]
.section .data.main
.test_case_exit:nop

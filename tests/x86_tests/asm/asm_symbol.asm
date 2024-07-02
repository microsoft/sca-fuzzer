.intel_syntax noprefix
.test_case_enter:
.section .data.main

.macro.measurement_start: nop dword ptr [rax + 1*rax + 1]

nop

.macro.measurement_end: nop dword ptr [rax + 1*rax + 1]

and rax, rax

.function_1:

nop

.section .data.guest_1
.function_2:
nop


.test_case_exit:

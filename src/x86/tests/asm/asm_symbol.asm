.intel_syntax noprefix
.test_case_enter:
.section .data.0_host

.macro.measurement_start: nop

nop

.macro.measurement_end: nop

.macro.vmenter: nop

.macro.vmcall: nop

and rax, rax

.function_1:

nop

.section .data.1_guest
.function_2:
nop


.test_case_exit:

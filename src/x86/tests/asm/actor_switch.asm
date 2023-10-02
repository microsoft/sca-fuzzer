.intel_syntax noprefix
.test_case_enter:
.section .data.0_host

.function_main:
NOP
NOP
AND rax, 0b11000000
AND rbx, 0b1


.macro.switch.3_host.function_1:

.section .data.3_host
.function_1:

# a typical spectre v1 gadget
JZ .l3
.l1:
MOV rax, qword ptr [r14 + rax]
JMP .l3
.l2:
MOV rax, qword ptr [r14 + 0x100]
.l3:

.macro.switch.0_host.function_fin:

.section .data.0_host
.function_fin:
.bb0:
nop

.test_case_exit:

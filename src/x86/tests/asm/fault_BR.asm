.intel_syntax noprefix
.test_case_enter:
.section .data.0_host
AND rax, 0b011111111111
ADD rax, 0x1000
BNDCU BND1, qword ptr [r14 + rax]
MOV rax, qword ptr [r14 + rax]
.test_case_exit:

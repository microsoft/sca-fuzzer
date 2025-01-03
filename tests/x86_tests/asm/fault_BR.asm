.intel_syntax noprefix
.section .data.main
and rax, 0b011111111111
add rax, 0x1000
bndcu bnd1, qword ptr [r14 + rax]
mov rax, qword ptr [r14 + rax]
.test_case_exit:

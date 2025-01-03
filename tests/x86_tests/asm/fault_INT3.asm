.intel_syntax noprefix
.section .data.main
int3
mov rax, qword ptr [r14 + 256]
.test_case_exit:

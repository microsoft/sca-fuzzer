.intel_syntax noprefix
.test_case_enter:
.section .data.main
INT3
MOV rax, qword ptr [r14 + 256]
.test_case_exit:

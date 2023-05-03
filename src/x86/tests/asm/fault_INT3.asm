.intel_syntax noprefix
.test_case_enter:
INT3
MOV rax, qword ptr [r14 + 256]
.test_case_exit:

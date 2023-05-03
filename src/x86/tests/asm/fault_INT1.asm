.intel_syntax noprefix
.test_case_enter:
.byte 0xf1  # INT1
MOV rax, qword ptr [r14 + 256]
.test_case_exit:

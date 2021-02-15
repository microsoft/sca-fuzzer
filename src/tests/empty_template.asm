.intel_syntax noprefix
.test_case_enter:
CALL test_case_main
JMP .test_case_exit
    test_case_main:
        .test_case_main.entry:
        MOV rax, 1
        MOV rbx, 1
        MOV rcx, 1
        MOV rdx, 1
        MOV rsi, 1
        MOV rdi, 1
        MOV r13, 1
        LFENCE
        .main.generated:
        JMP .test_case_main.exit
        .test_case_main.exit:
        RET
.test_case_exit:
MFENCE

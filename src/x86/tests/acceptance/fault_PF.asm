.intel_syntax noprefix
.test_case_enter:
MOV rax, qword ptr [r14 + 4096 + 128]
AND rax, 0b111111111111 # instrumentation
MOV rax, qword ptr [r14 + rax]
.test_case_exit:
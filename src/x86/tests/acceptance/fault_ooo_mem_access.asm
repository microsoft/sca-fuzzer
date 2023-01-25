.intel_syntax noprefix
.test_case_enter:
MOV rax, qword ptr [r14 + 4096 + 64]

# dependent memory access
AND rbx, 0b111111111000 # instrumentation
MOV rax, qword ptr [r14 + rbx]

# independent memory access
AND rbx, 0b111111111000 # instrumentation
MOV rax, qword ptr [r14 + rbx]
.test_case_exit:

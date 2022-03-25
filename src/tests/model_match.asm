.intel_syntax noprefix
.test_case_enter:

# test register values
AND rax, 0b111111000000
MOV rax, qword ptr [r14 + rax]

AND rbx, 0b111111000000
MOV rbx, qword ptr [r14 + rbx]

AND rcx, 0b111111000000
MOV rcx, qword ptr [r14 + rcx]

AND rdx, 0b111111000000
MOV rdx, qword ptr [r14 + rdx]

AND rsi, 0b111111000000
MOV rsi, qword ptr [r14 + rsi]

AND rdi, 0b111111000000
MOV rdi, qword ptr [r14 + rdi]

MOV rax, rsp
AND rax, 0b111111000000
MOV rax, qword ptr [r14 + rax]

# test values in memory
MOV rax, qword ptr [r14]
AND rax, 0b111111000000
MOV rax, qword ptr [r14 + rax]

MOV rax, qword ptr [r14 + 1024]
AND rax, 0b111111000000
MOV rax, qword ptr [r14 + rax]

MOV rax, qword ptr [r14 + 4096 - 8]
AND rax, 0b111111000000
MOV rax, qword ptr [r14 + rax]

MFENCE

.intel_syntax noprefix

# test register values
AND rax, 0b111111000000
MOV rax, [r14 + rax]

AND rbx, 0b111111000000
MOV rbx, [r14 + rbx]

AND rcx, 0b111111000000
MOV rcx, [r14 + rcx]

AND rdx, 0b111111000000
MOV rdx, [r14 + rdx]

AND rsi, 0b111111000000
MOV rsi, [r14 + rsi]

AND rdi, 0b111111000000
MOV rdi, [r14 + rdi]

MOV rax, rsp
AND rax, 0b111111000000
MOV rax, [r14 + rax]

# test values in memory
MOV rax, [r14]
AND rax, 0b111111000000
MOV rax, [r14 + rax]

MOV rax, [r14 + 1024]
AND rax, 0b111111000000
MOV rax, [r14 + rax]

MOV rax, [r14 + 4096 - 8]
AND rax, 0b111111000000
MOV rax, [r14 + rax]

MFENCE

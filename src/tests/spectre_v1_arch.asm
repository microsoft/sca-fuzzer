.intel_syntax noprefix
LFENCE

# delay the cond. jump
LEA rbx, [rbx + rax + 1]
LEA rbx, [rbx + rax + 1]
LEA rbx, [rbx + rax + 1]
LEA rbx, [rbx + rax + 1]
LEA rbx, [rbx + rax + 1]
LEA rbx, [rbx + rax + 1]
LEA rbx, [rbx + rax + 1]
LEA rbx, [rbx + rax + 1]
LEA rbx, [rbx + rax + 1]
LEA rbx, [rbx + rax + 1]

# reduce the entropy in rbx
AND rbx, 0b1

CMP rbx, 0
JE .l1  # misprediction
    # rbx != 0
    MOV rax, [r14]
JMP .l2
.l1:
    # rbx == 0
    MOV rax, [r14 + 64]
    LFENCE
.l2:

SHL rax, 8
AND rax, 0b111111000000
MOV rax, [r14 + rax + 512] # leakage happens here

MFENCE
